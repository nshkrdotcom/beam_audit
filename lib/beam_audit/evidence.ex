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
  def analyze(run, repo, files, _groups) do
    source_files = Enum.filter(files, &(Path.extname(&1["path"]) in ~w(.ex .exs .erl .hrl)))
    root = Scope.snapshot_dir(run, repo)
    paths = Enum.map(source_files, &Path.join(root, &1["path"]))

    if paths == [] do
      {[], %{"tool" => "reach", "status" => "partial", "reason" => "No supported source files"}}
    else
      case Store.safe(fn -> project_flows(paths, root, files) end) do
        {:ok, {flows, represented, count}} ->
          missing = Enum.map(source_files, & &1["path"]) -- represented
          unmodeled = Enum.map(files -- source_files, & &1["path"])

          status =
            if missing == [] and count <= @max_flows and unmodeled == [],
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
             "paths_total" => count,
             "scope" => "source graph only; no target dependency summaries or macro expansion"
           }}

        {:error, reason} ->
          {[], %{"tool" => "reach", "status" => "failed", "reason" => reason}}
      end
    end
  end

  defp project_flows(paths, root, inventory) do
    {:ok, _} = Application.ensure_all_started(:reach)
    project = Reach.Project.from_sources(paths, summaries: %{}, retain_module_sdgs: false)
    nodes = project.nodes

    represented =
      nodes
      |> Map.values()
      |> Enum.flat_map(fn n ->
        case location(n, root, inventory) do
          nil -> []
          loc -> [loc["path"]]
        end
      end)
      |> Enum.uniq()
      |> Enum.sort()

    # These predicates deliberately select signal families, not trust judgments.
    # Do not install guessed sanitizer summaries or claim that a path is feasible.
    sources = fn n ->
      n.type == :call and
        name(n.meta[:function]) in ~w(binary_to_term non_executable_binary_to_term decode decode! decode_cursor decode_keyset params body_params get_param)
    end

    sinks = fn n ->
      mod = name(n.meta[:module])
      fun = name(n.meta[:function])

      n.type == :call and
        (mod in ~w(Elixir.Enum Elixir.Inspect Elixir.Enumerable Elixir.String.Chars Elixir.Logger Elixir.Jason.Encoder Elixir.Ash.Expr Elixir.Ash.Filter) or
           fun in ~w(inspect to_string apply eval_string eval_quoted eval_file compile_string compile_quoted compile_file cmd shell fragment unsafe_fragment query query! to_atom binary_to_atom list_to_atom concat struct struct!))
    end

    results = Reach.Project.taint_analysis(project, sources: sources, sinks: sinks)

    flows =
      results
      |> Enum.map(fn flow ->
        %{
          "source" => location(flow.source, root, inventory),
          "sink" => location(flow.sink, root, inventory),
          "path" => Enum.map(flow.path, &location(Map.get(nodes, &1), root, inventory)),
          "kind" => "modeled_data_flow"
        }
      end)
      |> Enum.sort_by(&JSON.encode!/1)

    # Keep invalid/unlocated path nodes visible as null; do not fabricate citations.
    {Enum.take(flows, @max_flows), represented, length(flows)}
  end

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
        "function" => name(node.meta[:function])
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

    properties =
      if group["rule"] in ~w(P01 P02), do: [group["rule"], "P03", "P04"], else: [group["rule"]]

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

          _ ->
            raise "Unsupported evidence request; no shell, external repository or dependency access"
        end
      end)

    existing = packet["excerpts"] ++ Enum.flat_map(answers, & &1["excerpts"])

    packet
    |> Map.put("excerpts", Enum.uniq_by(existing, & &1["id"]))
    |> Map.update("answers", answers, &(&1 ++ answers))
  end
end
