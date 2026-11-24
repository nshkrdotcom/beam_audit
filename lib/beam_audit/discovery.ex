defmodule BeamAudit.Discovery do
  @moduledoc """
  Executes native textual, structural and security checks; accounts for every
  emitted hit under a versioned selection policy. A hit is never a verdict.
  """
  alias BeamAudit.{Evidence, Scope, Store}

  @doc false
  def run(run, repo) do
    dir = Path.join(run, repo)
    expression = "[run, repo] = System.argv(); BeamAudit.Discovery.worker(run, repo)"
    {output, status} = Store.worker(expression, [run, repo], run)
    Store.atomic(Path.join(dir, "worker.log"), output)

    if status != 0 or not File.regular?(Path.join(dir, "discovery.json")) do
      Store.write(Path.join(dir, "discovery_failure.json"), %{
        "status" => "failed",
        "exit_status" => status,
        "reason" => "Discovery worker did not complete"
      })
    end
  end

  @doc false
  def skip(run, repo) do
    dir = Path.join(run, repo)

    for name <- ~w(ledger candidates flows),
        do: Store.write_lines(Path.join(dir, name <> ".jsonl"), [])

    Store.write(Path.join(dir, "discovery.json"), %{
      "coverage" => [%{"tool" => "source", "status" => "not_requested"}],
      "scope_errors" => [],
      "ledger_sha256" => Store.digest(""),
      "candidates_sha256" => Store.digest(""),
      "flows_sha256" => Store.digest("")
    })
  end

  @doc false
  def worker(run, repo) do
    dir = Path.join(run, repo)
    inventory = Scope.inventory(run, repo)
    files = Scope.included(inventory)
    catalogue = Store.read(Path.join(run, "rules.json"))
    rules = catalogue["rules"]

    identity =
      Store.read(Path.join(run, "manifest.json"))["repositories"]
      |> Enum.find(&(&1["id"] == repo))

    File.mkdir_p!(Path.join(dir, "raw"))

    # Separate jobs; no application source or target configuration is evaluated.
    git_task = Task.async(fn -> text(run, repo, rules) end)
    sobelow_task = Task.async(fn -> sobelow(run, repo, inventory) end)
    {ast_hits, spans, definitions, ast_status} = structural(run, repo, files, rules)
    {git_hits, git_status} = Task.await(git_task, :infinity)
    {sobelow_hits, sobelow_status} = Task.await(sobelow_task, :infinity)

    native = git_hits ++ ast_hits ++ sobelow_hits
    boundary_hits = boundary_hits(native, definitions, identity)
    Store.write_lines(Path.join(dir, "definitions.jsonl"), definitions)
    {flows, reach_status} = Evidence.analyze(run, repo, files, catalogue, native ++ boundary_hits)
    Store.write_lines(Path.join(dir, "flows.jsonl"), flows)

    {ledger, groups, scope_errors} =
      account(
        repo,
        native ++ boundary_hits ++ Evidence.flow_hits(flows),
        spans,
        inventory,
        identity,
        definitions,
        rules
      )

    Store.write_lines(Path.join(dir, "ledger.jsonl"), ledger)
    Store.write_lines(Path.join(dir, "candidates.jsonl"), groups)

    Store.write(Path.join(dir, "discovery.json"), %{
      "coverage" => git_status ++ [ast_status] ++ sobelow_status ++ [reach_status],
      "scope_errors" => scope_errors,
      "ledger_sha256" => Store.digest(File.read!(Path.join(dir, "ledger.jsonl"))),
      "candidates_sha256" => Store.digest(File.read!(Path.join(dir, "candidates.jsonl"))),
      "flows_sha256" => Store.digest(File.read!(Path.join(dir, "flows.jsonl"))),
      "evidence_hashes" =>
        Map.new(~w(definitions symbols slices), fn name ->
          path = Path.join(dir, name <> ".jsonl")
          unless File.regular?(path), do: Store.write_lines(path, [])
          {name, Store.digest(File.read!(path))}
        end)
    })
  end

  defp text(run, repo, rules) do
    rules
    |> Enum.reject(&(&1["grep"] == ""))
    |> Enum.map(fn rule ->
      args = [
        "grep",
        "--no-index",
        "--no-color",
        "--no-textconv",
        "--no-exclude-standard",
        "-n",
        "-z",
        "-I",
        "-E",
        "-e",
        rule["grep"],
        "--"
      ]

      {out, status} = Scope.git(Scope.snapshot_dir(run, repo), args)
      path = Path.join([run, repo, "raw", "git-#{rule["id"]}.txt"])
      Store.atomic(path, out)

      result =
        if status in [0, 1] do
          Store.safe(fn ->
            out
            |> String.split("\n", trim: true)
            |> Enum.map(fn row ->
              [file, line, snippet] = :binary.split(row, <<0>>, [:global])
              hit("git", rule["id"], file, String.to_integer(line), 1, snippet, rule["bucket"])
            end)
          end)
        else
          {:error, "Git grep exit #{status}"}
        end

      case result do
        {:ok, hits} ->
          {hits,
           status("git:#{rule["id"]}", "completed", %{
             "matches" => length(hits),
             "exit" => status,
             "args" => args
           })}

        {:error, reason} ->
          {[],
           status("git:#{rule["id"]}", "failed", %{
             "reason" => reason,
             "exit" => status,
             "args" => args
           })}
      end
    end)
    |> Enum.reduce({[], []}, fn {hits, state}, {all, states} ->
      {all ++ hits, states ++ [state]}
    end)
  end

  defp structural(run, repo, files, rules) do
    {:ok, _} = Application.ensure_all_started(:ex_ast)

    patterns =
      for rule <- rules, {pattern, index} <- Enum.with_index(rule["patterns"]), into: %{} do
        {"#{rule["id"]}:#{index}", pattern}
      end

    patterns =
      Map.merge(patterns, %{
        "context:def" => "def _ do ... end",
        "context:defp" => "defp _ do ... end",
        "context:module" => "defmodule _ do ... end"
      })

    {valid, invalid} =
      patterns
      |> Enum.sort()
      |> Enum.split_with(fn {_id, pattern} ->
        match?({:ok, _}, Store.safe(fn -> ExAST.Pattern.compile(pattern) end))
      end)

    patterns = Map.new(valid)

    elixir_files = Enum.filter(files, &(Path.extname(&1["path"]) in [".ex", ".exs"]))

    {hits, spans, definitions, errors} =
      Enum.reduce(elixir_files, {[], %{}, [], []}, fn file, {hits, spans, definitions, errors} ->
        result =
          Store.safe(fn ->
            source = Scope.source!(run, repo, file)

            ExAST.Patcher.find_many(source, patterns, expand_imports: false)
            |> Enum.map(fn match ->
              range = match.range || raise("ExAST match has no source range")
              first = Keyword.fetch!(range.start, :line)
              last = Keyword.fetch!(range.end, :line)
              column = Keyword.get(range.start, :column, 1)
              {to_string(match.pattern), first, last, column, match.source || "", match.node}
            end)
          end)

        case result do
          {:ok, matches} ->
            {contexts, findings} =
              Enum.split_with(matches, &String.starts_with?(elem(&1, 0), "context:"))

            defs = definitions(contexts, file["path"])
            ranges = Enum.map(defs, &{&1["first"], &1["last"]})

            current =
              Enum.map(findings, fn {pattern, first, _last, col, snippet, _node} ->
                [rule, _] = String.split(pattern, ":", parts: 2)

                hit(
                  "ex_ast",
                  rule,
                  file["path"],
                  first,
                  col,
                  snippet,
                  Enum.find(rules, &(&1["id"] == rule))["bucket"]
                )
                |> Map.put("query", pattern)
              end)

            {current ++ hits, Map.put(spans, file["path"], ranges), definitions ++ defs, errors}

          {:error, reason} ->
            {hits, spans, definitions, [%{"path" => file["path"], "reason" => reason} | errors]}
        end
      end)

    Store.write_lines(Path.join([run, repo, "raw", "ex_ast.jsonl"]), Enum.reverse(hits))

    {hits, spans, definitions,
     status("ex_ast", if(errors == [] and invalid == [], do: "completed", else: "partial"), %{
       "submitted" => length(elixir_files),
       "failed_files" => Enum.reverse(errors),
       "unmodeled_extensions" =>
         files |> Enum.reject(&(&1 in elixir_files)) |> Enum.map(& &1["path"]),
       "patterns" => patterns,
       "invalid_patterns" => Map.new(invalid)
     })}
  end

  # Native match ranges and AST nodes, not a new source parser. Module names are
  # lexical source names (not guaranteed resolved MFAs for generated modules).
  defp definitions(contexts, path) do
    modules = Enum.filter(contexts, &(elem(&1, 0) == "context:module"))

    contexts
    |> Enum.reject(&(elem(&1, 0) == "context:module"))
    |> Enum.map(fn {kind, first, last, _, snippet, node} ->
      head =
        case node do
          {form, _, [head | _]} when form in [:def, :defp] -> head
          _ -> nil
        end

      head =
        case head do
          {:when, _, [call | _]} -> call
          other -> other
        end

      {name, arity} =
        case head do
          {name, _, args} when is_atom(name) and is_list(args) ->
            {Atom.to_string(name), length(args)}

          {name, _, nil} when is_atom(name) ->
            {Atom.to_string(name), 0}

          _ ->
            {nil, nil}
        end

      mod =
        modules
        |> Enum.filter(fn {_, a, b, _, _, _} -> a <= first and b >= last end)
        |> Enum.sort_by(&elem(&1, 1))
        |> Enum.map(fn
          {_, _, _, _, _, {:defmodule, _, [module | _]}} -> Macro.to_string(module)
          _ -> "?"
        end)
        |> Enum.join(".")

      %{
        "path" => path,
        "first" => first,
        "last" => last,
        "function" => name,
        "arity" => arity,
        "module" => mod,
        "visibility" => if(kind == "context:def", do: "public", else: "private"),
        "signature" => if(head, do: Macro.to_string(head), else: String.slice(snippet, 0, 120))
      }
    end)
    |> Enum.uniq()
    |> Enum.sort_by(&{&1["path"], &1["first"], &1["last"]})
  end

  @doc false
  def boundary_hits(native, definitions, identity) do
    context_rules = ~w(P08 P09 P10 P11 P12)
    sensitive_rules = ~w(P09 P10 P11)

    callbacks =
      ~w(handle_call handle_cast handle_info handle_event handle_in handle_continue handle_params perform)

    entrypoints = ~w(dispatch execute invoke request connect resume)
    authority = ~w(approve approve! authorize authorize!)

    context =
      native
      |> Enum.filter(&(&1["rule"] in context_rules))
      |> Enum.group_by(& &1["path"])

    generated =
      definitions
      |> Enum.filter(&(&1["visibility"] == "public"))
      |> Enum.flat_map(fn defn ->
        sites =
          Map.get(context, defn["path"], [])
          |> Enum.filter(fn site ->
            site["line"] >= defn["first"] and site["line"] <= defn["last"]
          end)

        properties = sites |> Enum.map(& &1["rule"]) |> Enum.uniq() |> Enum.sort()
        name = defn["function"]

        sensitive =
          sites
          |> Enum.filter(&(&1["rule"] in sensitive_rules))
          |> Enum.group_by(& &1["rule"])
          |> Enum.sort()
          |> Enum.map(fn {rule, matches} ->
            site = Enum.min_by(matches, &{&1["line"], &1["column"], &1["tool"]})

            hit(
              "boundary",
              rule,
              defn["path"],
              site["line"],
              site["column"],
              site["snippet"],
              "candidate"
            )
            |> Map.merge(%{
              "boundary" => true,
              "related_rules" => [rule],
              "definition" => defn,
              "question" =>
                "Assess the sensitive operation, caller contract, validation and authority at this public boundary."
            })
          end)

        inventory =
          if name in callbacks or name in entrypoints or
               name in authority or "P12" in properties do
            explicit_authority = name in authority

            row =
              hit(
                "boundary",
                "P12",
                defn["path"],
                defn["first"],
                1,
                defn["signature"],
                if(explicit_authority, do: "candidate", else: "context")
              )
              |> Map.merge(%{
                "boundary" => true,
                "related_rules" => Enum.uniq(["P12" | properties]),
                "definition" => defn,
                "question" =>
                  "Assess the actual entrypoint, caller trust, state transition and authority contract."
              })

            if explicit_authority do
              [row]
            else
              [Map.put(row, "reason", "entrypoint_inventory")]
            end
          else
            []
          end

        sensitive ++ inventory
      end)

    requested =
      Enum.map(identity["boundaries"] || [], fn spec ->
        hit(
          "owner_boundary",
          "P12",
          spec["path"],
          spec["line"],
          1,
          spec["question"],
          "candidate"
        )
        |> Map.merge(%{
          "boundary" => true,
          "related_rules" => ["P12"],
          "question" => spec["question"]
        })
      end)

    generated ++ requested
  end

  defp sobelow(run, repo, inventory) do
    root = Scope.snapshot_dir(run, repo)
    paths = Scope.included(inventory) |> Enum.map(& &1["path"])

    app_roots =
      paths |> Enum.filter(&(Path.basename(&1) == "mix.exs")) |> Enum.map(&Path.dirname/1)

    app_roots = if app_roots == [], do: ["."], else: Enum.sort(Enum.uniq(app_roots))
    # Exclude the dependency advisory category. Do not load target .sobelow-conf.
    app_roots
    |> Enum.with_index(1)
    |> Enum.map(fn {app, index} ->
      target = Path.expand(app, root)

      args = [
        "--root",
        target,
        "--private",
        "--no-config",
        "--no-router",
        "--strict",
        "--summary",
        "--format",
        "sarif",
        "--include-mix-tasks",
        "--include-scripts",
        "--ignore",
        "Vuln"
      ]

      if not Enum.any?(paths, fn path ->
           String.starts_with?(path, if(app == ".", do: "lib/", else: app <> "/lib/"))
         end) do
        {[],
         status("sobelow:#{app}", "partial", %{
           "reason" => "No lib source; not a supported application layout",
           "args" => args
         })}
      else
        stderr_path = Path.join([run, repo, "raw", "sobelow-#{index}.stderr.log"])

        result =
          Store.safe(fn ->
            expression =
              "Mix.start(); {:ok, _} = Application.ensure_all_started(:sobelow); Mix.Tasks.Sobelow.main(System.argv())"

            Store.worker(expression, args, run, stderr_path)
          end)

        case result do
          {:ok, {out, exit_code}} ->
            Store.atomic(Path.join([run, repo, "raw", "sobelow-#{index}.sarif.log"]), out)
            diagnostics = File.read!(stderr_path)

            decoded =
              if exit_code == 0,
                do: Store.safe(fn -> sarif(out, target, root) end),
                else: {:error, "exit #{exit_code}; see #{Path.basename(stderr_path)}"}

            case decoded do
              {:ok, hits} ->
                {hits,
                 status("sobelow:#{app}", "completed", %{
                   "matches" => length(hits),
                   "args" => args,
                   "exit" => exit_code,
                   "scan_summary" =>
                     diagnostics
                     |> String.split("\n")
                     |> Enum.find(&String.starts_with?(&1, "Scan summary: ")),
                   "scope" => "Sobelow-supported paths only; Vuln category excluded"
                 })}

              {:error, reason} ->
                {[],
                 status("sobelow:#{app}", "failed", %{
                   "reason" => reason,
                   "args" => args,
                   "exit" => exit_code
                 })}
            end

          {:error, reason} ->
            {[], status("sobelow:#{app}", "unavailable", %{"reason" => reason})}
        end
      end
    end)
    |> Enum.reduce({[], []}, fn {hits, state}, {all, states} ->
      {all ++ hits, states ++ [state]}
    end)
  end

  @doc false
  def sarif(out, app, root) do
    %{"runs" => runs} = JSON.decode!(out)

    for run <- runs, result <- Map.fetch!(run, "results"), location <- locations(result) do
      physical = Map.get(location, "physicalLocation", %{})
      artifact = Map.get(physical, "artifactLocation", %{})
      region = Map.get(physical, "region", %{})
      uri = Map.get(artifact, "uri", "")
      file = if String.starts_with?(uri, "file://"), do: URI.parse(uri).path || "", else: uri
      full = Path.expand(URI.decode(file), app)
      relative = Path.relative_to(full, root)

      hit(
        "sobelow",
        "SOBELOW:" <> Map.get(result, "ruleId", "unknown"),
        relative,
        Map.get(region, "startLine", 0),
        Map.get(region, "startColumn", 1),
        get_in(result, ["message", "text"]) || "",
        "candidate"
      )
      |> Map.put("native", result)
      |> Map.put(
        "native_rule_name",
        Enum.find_value(
          get_in(run, ["tool", "driver", "rules"]) || [],
          fn rule ->
            if rule["id"] == result["ruleId"], do: rule["name"]
          end
        )
      )
    end
  end

  defp locations(result) do
    case Map.get(result, "locations", []) do
      [] -> [%{}]
      list when is_list(list) -> list
    end
  end

  defp hit(tool, rule, path, line, col, snippet, bucket) do
    %{
      "tool" => tool,
      "rule" => rule,
      "path" => path,
      "line" => line,
      "column" => col,
      "snippet" => snippet,
      "bucket" => bucket
    }
  end

  defp status(tool, value, details), do: Map.merge(%{"tool" => tool, "status" => value}, details)

  # Native IDs are retained on every row. Only exact known equivalent rules
  # share a property group; unrelated findings in a function stay separate.
  defp canonical_rule(%{"tool" => "sobelow", "rule" => rule} = row) do
    name = row["native_rule_name"] || String.replace_prefix(rule, "SOBELOW:", "")

    case name do
      "Misc.BinToTerm" -> "P01"
      "DOS.BinToAtom" -> "P07"
      "DOS.StringToAtom" -> "P07"
      "DOS.ModuleConcat" -> "P07"
      "RCE.CodeModule" -> "P05"
      "RCE.EEx" -> "P05"
      "RCE.System" -> "P05"
      "CI.System" -> "P05"
      "SQL.Query" -> "P06"
      "Traversal.FileModule" -> "P09"
      _ -> rule
    end
  end

  defp canonical_rule(row), do: row["rule"]

  @doc false
  def account(repo, hits, spans, inventory, identity, definitions \\ [], rules \\ []) do
    rows =
      hits
      |> Enum.sort_by(
        &{&1["path"], &1["line"], &1["rule"], &1["tool"], &1["column"], &1["snippet"]}
      )
      |> Enum.with_index(1)
      |> Enum.map(fn {hit, index} ->
        row = Map.put(hit, "raw_id", "#{repo}:#{index}")

        cond do
          not Scope.location_valid?(inventory, row["path"], row["line"], row["line"]) ->
            Map.merge(row, %{
              "bucket" => "excluded",
              "reason" => "out_of_scope_or_invalid_location"
            })

          row["bucket"] == "context" ->
            Map.put_new(row, "reason", "context_only_policy")

          true ->
            {first, last} =
              Map.get(spans, row["path"], [])
              |> Enum.filter(fn {first, last} ->
                first <= row["line"] and row["line"] <= last and last - first <= 90 and
                  Scope.location_valid?(inventory, row["path"], first, last)
              end)
              |> Enum.min_by(fn {first, last} -> last - first end, fn ->
                {row["line"], row["line"]}
              end)

            family = canonical_rule(row)

            group =
              Store.id([
                identity["root"],
                identity["commit"],
                row["path"],
                family,
                first,
                last
              ])

            Map.merge(row, %{
              "bucket" => "queued",
              "candidate_id" => group,
              "family" => family,
              "first" => first,
              "last" => last
            })
        end
      end)

    groups =
      rows
      |> Enum.filter(&(&1["bucket"] == "queued"))
      |> Enum.group_by(& &1["candidate_id"])
      |> Enum.map(fn {id, matches} ->
        first = hd(matches)

        defn =
          definitions
          |> Enum.filter(
            &(&1["path"] == first["path"] and &1["first"] <= first["line"] and
                &1["last"] >= first["line"])
          )
          |> Enum.min_by(&(&1["last"] - &1["first"]), fn -> nil end)

        family = first["family"]

        properties =
          matches
          |> Enum.flat_map(&(&1["related_rules"] || [&1["rule"]]))
          |> Enum.uniq()
          |> Enum.sort()

        rule = Enum.find(rules, &(&1["id"] == family)) || %{}

        %{
          "id" => id,
          "repo" => repo,
          "path" => first["path"],
          "rule" => family,
          "properties" => Enum.uniq([family | properties]),
          "boundary" => Enum.any?(matches, &(&1["boundary"] == true)),
          "risk" =>
            if(Enum.all?(matches, &(&1["tool"] == "boundary")),
              do: "medium",
              else: rule["risk"] || "medium"
            ),
          "definition" => defn,
          "first" => first["first"],
          "last" => first["last"],
          "raw_ids" => Enum.map(matches, & &1["raw_id"]),
          "lines" => matches |> Enum.map(& &1["line"]) |> Enum.uniq() |> Enum.sort(),
          "tools" => matches |> Enum.map(& &1["tool"]) |> Enum.uniq() |> Enum.sort()
        }
      end)
      |> Enum.sort_by(&{&1["path"], &1["first"], &1["rule"], &1["id"]})

    {rows, groups, Enum.filter(rows, &(&1["bucket"] == "excluded")) |> Enum.map(& &1["raw_id"])}
  end
end
