defmodule BeamAudit.Evidence do
  @moduledoc """
  Reach-backed source evidence and bounded, scope-checked review excerpts.

  A reported path is evidence of the analyzer's model, not proof of exploitability.
  A missing path is never a proof of safety.
  """
  alias BeamAudit.{Scope, Store}
  @max_excerpt_lines 120
  @max_excerpt_bytes 32_000
  @max_flows 2_000

  @doc false
  def analyze(run, repo, files, catalogue, candidate_hits) do
    # Reach's Erlang frontend uses EPP, which can read includes outside the snapshot.
    source_files = Enum.filter(files, &(Path.extname(&1["path"]) in ~w(.ex .exs)))
    root = Scope.snapshot_dir(run, repo)
    paths = Enum.map(source_files, &Path.join(root, &1["path"]))

    if paths == [] do
      {[], %{"tool" => "reach", "status" => "partial", "reason" => "No supported source files"}}
    else
      case Store.safe(fn -> project_flows(paths, root, files, catalogue, candidate_hits) end) do
        {:ok, {flows, represented, count, symbols, slices, slice_errors}} ->
          Store.write_lines(Path.join([run, repo, "symbols.jsonl"]), symbols)
          Store.write_lines(Path.join([run, repo, "slices.jsonl"]), slices)
          missing = Enum.map(source_files, & &1["path"]) -- represented
          unmodeled = Enum.map(files -- source_files, & &1["path"])

          status =
            if missing == [] and count <= @max_flows and unmodeled == [] and slice_errors == [],
              do: "completed",
              else: "partial"

          {flows,
           %{
             "tool" => "reach",
             "status" => status,
             "submitted" => length(paths),
             "represented" => length(represented),
             "unrepresented_files" => missing,
             "unmodeled_extensions" => unmodeled,
             "paths_reported" => length(flows),
             "nontrivial_paths_reported" => Enum.count(flows, &nontrivial_flow?/1),
             "zero_length_paths_reported" => Enum.count(flows, &(not nontrivial_flow?(&1))),
             "paths_total" => count,
             "slice_errors" => slice_errors,
             "symbol_count" => length(symbols),
             "slice_count" => length(slices),
             "scope" =>
               "Elixir source graph only; Erlang includes, target dependency summaries and macro expansion are outside scope"
           }}

        {:error, reason} ->
          {[], %{"tool" => "reach", "status" => "failed", "reason" => reason}}
      end
    end
  end

  defp project_flows(paths, root, inventory, catalogue, candidate_hits) do
    {:ok, _} = Application.ensure_all_started(:reach)
    project = Reach.Project.from_sources(paths, summaries: %{}, retain_module_sdgs: false)
    nodes = project.nodes

    locations = Map.new(nodes, fn {id, node} -> {id, location(node, root, inventory)} end)

    represented =
      locations
      |> Map.values()
      |> Enum.reject(&is_nil/1)
      |> Enum.map(& &1["path"])
      |> Enum.uniq()
      |> Enum.sort()

    symbols =
      locations
      |> Map.values()
      |> Enum.reject(&is_nil/1)
      |> Enum.filter(&(&1["type"] in ~w(function_def call)))
      |> Enum.uniq()
      |> Enum.sort_by(&JSON.encode!/1)

    profiles = catalogue["flow_profiles"] || []
    sources = catalogue["flow_sources"] || %{}

    # One graph, one native taint query per source family, not per candidate.
    flows =
      profiles
      |> Enum.group_by(& &1["source"])
      |> Enum.sort()
      |> Enum.flat_map(fn {family, specs} ->
        source_calls = Map.fetch!(sources, family)
        sink_calls = Enum.flat_map(specs, & &1["sinks"]) |> Enum.uniq()

        results =
          Reach.Project.taint_analysis(project,
            sources: fn n -> matches_call?(n, source_calls) end,
            sinks: fn n -> matches_call?(n, sink_calls) end
          )

        Enum.flat_map(results, fn flow ->
          specs
          |> Enum.filter(&matches_call?(flow.sink, &1["sinks"]))
          |> Enum.map(fn spec ->
            %{
              "rule" => spec["rule"],
              "source" => location(flow.source, root, inventory),
              "sink" => location(flow.sink, root, inventory),
              "path" => Enum.take(flow.path, 120) |> Enum.map(&Map.get(locations, &1)),
              "path_truncated" => length(flow.path) > 120,
              "kind" =>
                if(flow.path == [],
                  do: "coincident_source_sink",
                  else: "modeled_data_flow"
                )
            }
          end)
        end)
      end)
      |> Enum.uniq()
      |> Enum.sort_by(&JSON.encode!/1)

    {nontrivial, coincident} = Enum.split_with(flows, &nontrivial_flow?/1)
    selected = Enum.take(nontrivial ++ coincident, @max_flows)
    # Persist native slices around candidate locations while the graph exists.
    # Later evidence requests never rebuild the project or run arbitrary tools.
    anchors =
      candidate_hits
      |> Enum.filter(&(&1["bucket"] == "candidate"))
      |> Enum.map(&{&1["path"], &1["line"]})

    anchors =
      MapSet.new(
        anchors ++
          Enum.flat_map(Enum.filter(selected, &nontrivial_flow?/1), fn f ->
            case f["sink"] do
              %{"path" => path, "line" => line} -> [{path, line}]
              _ -> []
            end
          end)
      )

    targets =
      nodes
      |> Enum.filter(fn {id, node} ->
        case Map.get(locations, id) do
          %{"path" => path, "line" => line} ->
            node.type == :call and MapSet.member?(anchors, {path, line})

          _ ->
            false
        end
      end)
      |> Enum.sort_by(fn {id, _} -> JSON.encode!(Map.fetch!(locations, id)) end)

    sdg = %Reach.SystemDependence{
      graph: project.graph,
      nodes: nodes,
      call_graph: project.call_graph,
      function_pdgs: %{}
    }

    {slices, errors} =
      targets
      |> Enum.take(500)
      |> Enum.reduce({[], []}, fn {id, _node}, {slices, errors} ->
        target = Map.fetch!(locations, id)

        case Store.safe(fn -> Reach.context_sensitive_slice(sdg, id) end) do
          {:ok, ids} ->
            locs =
              ids
              |> Enum.map(&Map.get(locations, &1))
              |> Enum.reject(&is_nil/1)
              |> Enum.uniq()
              |> Enum.sort_by(&JSON.encode!/1)

            {[
               %{
                 "target" => target,
                 "locations" => Enum.take(locs, 100),
                 "truncated" => length(locs) > 100
               }
               | slices
             ], errors}

          {:error, reason} ->
            {slices, [%{"target" => target, "reason" => reason} | errors]}
        end
      end)

    errors =
      if length(targets) > 500,
        do: [
          %{"reason" => "Slice target cap reached", "omitted" => length(targets) - 500} | errors
        ],
        else: errors

    {selected, represented, length(flows), symbols, Enum.reverse(slices), Enum.reverse(errors)}
  end

  defp matches_call?(nil, _), do: false

  defp matches_call?(node, selectors) do
    mod = name(node.meta[:module])
    fun = name(node.meta[:function])

    node.type == :call and
      Enum.any?(selectors, fn selector ->
        selector in [mod <> "." <> fun, "*." <> fun, mod <> ".*"]
      end)
  end

  @doc false
  def flow_hits(flows) do
    Enum.map(flows, fn flow ->
      sink = flow["sink"] || %{}

      hit = %{
        "tool" => "reach",
        "rule" => flow["rule"],
        "path" => sink["path"],
        "line" => sink["line"],
        "column" => 1,
        "flow" => flow
      }

      if nontrivial_flow?(flow) do
        Map.merge(hit, %{
          "bucket" => "candidate",
          "snippet" => "Modeled flow to #{sink["module"]}.#{sink["function"]}"
        })
      else
        Map.merge(hit, %{
          "bucket" => "context",
          "reason" => "zero_length_flow",
          "snippet" => "Coincident source and sink; no traversed flow"
        })
      end
    end)
  end

  defp nontrivial_flow?(%{"path" => [_ | _]}), do: true
  defp nontrivial_flow?(_), do: false

  defp name(x) when is_atom(x), do: Atom.to_string(x)
  defp name(x) when is_binary(x), do: x
  defp name(_), do: ""

  defp location(%{source_span: %{file: file, start_line: first}} = node, root, inventory)
       when is_binary(file) and is_integer(first) do
    path = file |> Path.expand(root) |> Path.relative_to(root)

    if Scope.location_valid?(inventory, path, first, first) do
      %{
        "path" => path,
        "line" => first,
        "type" => name(node.type),
        "module" => name(node.meta[:module]),
        "function" => name(node.meta[:function] || node.meta[:name]),
        "arity" => if(is_integer(node.meta[:arity]), do: node.meta[:arity], else: nil)
      }
    end
  end

  defp location(_, _, _), do: nil

  @doc false
  def packet(run, group, inventory, rules, flows) do
    path = group["path"]
    entry = Scope.lookup(inventory, path) || raise("Candidate outside inventory")
    first = max(1, group["first"] - 12)
    last = min(entry["lines"], group["last"] + 12)
    # Large functions are split at grouping time; this is a final size guard.
    last = min(last, first + @max_excerpt_lines - 1)

    unless Enum.all?(group["lines"], &(&1 >= first and &1 <= last)),
      do: raise("Candidate group exceeds source packet range")

    main = excerpt(run, group["repo"], inventory, path, first, last)

    relevant =
      flows
      |> Enum.filter(&nontrivial_flow?/1)
      |> Enum.filter(fn flow ->
        Enum.any?([flow["source"], flow["sink"] | flow["path"]], fn
          %{"path" => ^path, "line" => line} -> line >= group["first"] and line <= group["last"]
          _ -> false
        end)
      end)

    selected = Enum.take(relevant, 12)

    extra =
      selected
      |> Enum.flat_map(fn flow -> [flow["source"], flow["sink"]] end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()
      |> Enum.take(8)
      |> Enum.flat_map(fn loc ->
        case Scope.lookup(inventory, loc["path"]) do
          nil ->
            []

          entry ->
            case Store.safe(fn ->
                   excerpt(
                     run,
                     group["repo"],
                     inventory,
                     loc["path"],
                     max(1, loc["line"] - 5),
                     min(entry["lines"], loc["line"] + 5)
                   )
                 end) do
              {:ok, item} -> [item]
              {:error, _} -> []
            end
        end
      end)

    properties = group["properties"] || [group["rule"]]

    properties =
      if group["rule"] in ~w(P01 P02), do: Enum.uniq(properties ++ ~w(P03 P04)), else: properties

    slices =
      facts(run, group["repo"], "slices")
      |> Enum.filter(fn slice ->
        in_group?(slice["target"], group)
      end)
      |> Enum.take(4)

    related =
      slices
      |> Enum.flat_map(& &1["locations"])
      |> Enum.reject(&in_group?(&1, group))
      |> Enum.uniq_by(&{&1["path"], &1["line"]})
      |> Enum.take(4)

    extra = extra ++ excerpts_for(run, group["repo"], inventory, related)

    questions = Enum.filter(rules, &(&1["id"] in properties))

    questions =
      if questions == [],
        do: [
          %{
            "id" => group["rule"],
            "invariant" =>
              "Evaluate the native Sobelow security finding against actual input provenance, guard conditions and effects."
          }
        ],
        else: questions

    %{
      "candidate" => group,
      "rules" => questions,
      "excerpts" => Enum.uniq_by([main | extra], & &1["id"]),
      "reach" => selected,
      "slices" => slices,
      "reach_paths_available" => length(relevant),
      "context_note" =>
        "Only supplied excerpts are citable. Reach may omit paths, macros, implicit dispatch or validation. No-path is not safety."
    }
  end

  @doc false
  def excerpt(run, repo, inventory, path, first, last) do
    unless Scope.location_valid?(inventory, path, first, last) and
             last - first + 1 <= @max_excerpt_lines,
           do: raise("Invalid or excessive evidence range")

    entry = Scope.lookup(inventory, path)
    source = Scope.source!(run, repo, entry)

    text =
      source |> String.split("\n") |> Enum.slice(first - 1, last - first + 1) |> Enum.join("\n")

    if byte_size(text) > @max_excerpt_bytes, do: raise("Source excerpt exceeds byte limit")
    id = Store.id([repo, path, first, last, entry["sha256"]])

    %{
      "id" => id,
      "repo" => repo,
      "path" => path,
      "first" => first,
      "last" => last,
      "source_sha256" => entry["sha256"],
      "text" => text
    }
  end

  @doc false
  def fulfill(run, packet, inventory, requests) when is_list(requests) do
    if length(requests) > 3, do: raise("Too many evidence requests")
    repo = packet["candidate"]["repo"]

    answers =
      Enum.map(requests, fn request ->
        case request do
          %{"operation" => "read_source", "path" => path, "first" => first, "last" => last} ->
            %{
              "request" => request,
              "excerpts" => [excerpt(run, repo, inventory, path, first, last)],
              "truncated" => false
            }

          %{"operation" => "find_symbol", "symbol" => symbol} when is_binary(symbol) ->
            unless byte_size(symbol) in 2..160 and
                     not String.contains?(symbol, ["\n", "\r", <<0>>]),
                   do: raise("Invalid literal symbol")

            matches =
              Scope.included(inventory)
              |> Enum.flat_map(fn entry ->
                Scope.source!(run, repo, entry)
                |> String.split("\n")
                |> Enum.with_index(1)
                |> Enum.filter(fn {line, _} -> String.contains?(line, symbol) end)
                |> Enum.map(fn {_, line} -> {entry, line} end)
              end)

            items =
              Enum.take(matches, 8)
              |> Enum.map(fn {entry, line} ->
                excerpt(
                  run,
                  repo,
                  inventory,
                  entry["path"],
                  max(1, line - 4),
                  min(entry["lines"], line + 4)
                )
              end)

            %{"request" => request, "excerpts" => items, "truncated" => length(matches) > 8}

          %{"operation" => op, "symbol" => symbol}
          when op in ~w(find_definition find_references find_callers) and is_binary(symbol) ->
            unless byte_size(symbol) in 1..160 and
                     not String.contains?(symbol, ["\n", "\r", <<0>>]),
                   do: raise("Invalid symbol")

            records = symbol_records(run, repo, op, symbol)

            %{
              "request" => request,
              "excerpts" => excerpts_for(run, repo, inventory, Enum.take(records, 8)),
              "modeled_matches" => Enum.take(records, 8),
              "truncated" => length(records) > 8,
              "note" =>
                "Definitions and modeled call sites only; absence is not proof of no callers."
            }

          %{"operation" => op, "path" => path, "first" => line} when op in ~w(trace_flow slice) ->
            unless Scope.location_valid?(inventory, path, line, line),
              do: raise("Invalid evidence anchor")

            {file, key} = if op == "slice", do: {"slices", "target"}, else: {"flows", "sink"}

            records =
              facts(run, repo, file)
              |> Enum.filter(fn row ->
                loc = row[key] || %{}
                loc["path"] == path and loc["line"] == line
              end)

            records =
              if op == "trace_flow",
                do: Enum.filter(records, &nontrivial_flow?/1),
                else: records

            selected = Enum.take(records, 4)

            locs =
              Enum.flat_map(selected, fn row ->
                if op == "slice",
                  do: row["locations"],
                  else: [row["source"], row["sink"] | row["path"]]
              end)
              |> Enum.reject(&is_nil/1)
              |> Enum.uniq_by(&{&1["path"], &1["line"]})
              |> Enum.take(8)

            %{
              "request" => request,
              "excerpts" => excerpts_for(run, repo, inventory, locs),
              "modeled_matches" => selected,
              "truncated" => length(records) > 4,
              "note" =>
                "Frozen native evidence at this anchor; no matching record is not proof of safety."
            }

          _ ->
            raise "Unsupported evidence request; no shell, external repository or dependency access"
        end
      end)

    existing = packet["excerpts"] ++ Enum.flat_map(answers, & &1["excerpts"])

    packet
    |> Map.put("excerpts", Enum.uniq_by(existing, & &1["id"]))
    |> Map.update(
      "answers",
      Enum.map(answers, &Map.delete(&1, "excerpts")),
      &(&1 ++ Enum.map(answers, fn answer -> Map.delete(answer, "excerpts") end))
    )
  end

  @doc false
  def facts(run, repo, name) when name in ~w(definitions symbols slices flows) do
    path = Path.join([run, repo, name <> ".jsonl"])
    if File.regular?(path), do: Store.read_lines(path), else: []
  end

  defp in_group?(%{"path" => path, "line" => line}, group),
    do: path == group["path"] and line >= group["first"] and line <= group["last"]

  defp in_group?(_, _), do: false

  defp excerpts_for(run, repo, inventory, locations) do
    locations
    |> Enum.uniq_by(&{&1["path"], &1["line"] || &1["first"]})
    |> Enum.flat_map(fn loc ->
      path = loc["path"]
      line = loc["line"] || loc["first"]

      case Scope.lookup(inventory, path) do
        nil ->
          []

        entry ->
          case Store.safe(fn ->
                 excerpt(
                   run,
                   repo,
                   inventory,
                   path,
                   max(1, line - 6),
                   min(entry["lines"], line + 10)
                 )
               end) do
            {:ok, item} -> [item]
            {:error, _} -> []
          end
      end
    end)
  end

  defp symbol_records(run, repo, op, symbol) do
    definitions = facts(run, repo, "definitions")
    calls = facts(run, repo, "symbols") |> Enum.filter(&(&1["type"] == "call"))

    records =
      case op do
        "find_definition" -> definitions
        "find_references" -> definitions ++ calls
        "find_callers" -> calls
      end

    Enum.filter(records, fn row ->
      fun = row["function"] || ""
      mod = String.trim_leading(row["module"] || "", "Elixir.")
      mfa = mod <> "." <> fun
      arity = if is_integer(row["arity"]), do: "/#{row["arity"]}", else: ""
      symbol in [fun, mod, mfa, mfa <> arity, "Elixir." <> mfa <> arity]
    end)
  end
end
