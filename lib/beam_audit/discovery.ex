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
  def worker(run, repo) do
    dir = Path.join(run, repo)
    inventory = Scope.inventory(run, repo)
    files = Scope.included(inventory)
    rules = Store.read(Path.join(run, "rules.json"))["rules"]

    identity =
      Store.read(Path.join(run, "manifest.json"))["repositories"]
      |> Enum.find(&(&1["id"] == repo))

    File.mkdir_p!(Path.join(dir, "raw"))

    # Separate jobs; no application source or target configuration is evaluated.
    git_task = Task.async(fn -> text(run, repo, rules) end)
    sobelow_task = Task.async(fn -> sobelow(run, repo, inventory) end)
    {ast_hits, spans, ast_status} = structural(run, repo, files, rules)
    {git_hits, git_status} = Task.await(git_task, :infinity)
    {sobelow_hits, sobelow_status} = Task.await(sobelow_task, :infinity)

    {ledger, groups, scope_errors} =
      account(repo, git_hits ++ ast_hits ++ sobelow_hits, spans, inventory, identity)

    Store.write_lines(Path.join(dir, "ledger.jsonl"), ledger)
    Store.write_lines(Path.join(dir, "candidates.jsonl"), groups)
    {flows, reach_status} = Evidence.analyze(run, repo, files, groups)
    Store.write_lines(Path.join(dir, "flows.jsonl"), flows)

    Store.write(Path.join(dir, "discovery.json"), %{
      "coverage" => git_status ++ [ast_status] ++ sobelow_status ++ [reach_status],
      "scope_errors" => scope_errors,
      "ledger_sha256" => Store.digest(File.read!(Path.join(dir, "ledger.jsonl"))),
      "candidates_sha256" => Store.digest(File.read!(Path.join(dir, "candidates.jsonl"))),
      "flows_sha256" => Store.digest(File.read!(Path.join(dir, "flows.jsonl")))
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
        "context:defp" => "defp _ do ... end"
      })

    elixir_files = Enum.filter(files, &(Path.extname(&1["path"]) in [".ex", ".exs"]))

    {hits, spans, errors} =
      Enum.reduce(elixir_files, {[], %{}, []}, fn file, {hits, spans, errors} ->
        result =
          Store.safe(fn ->
            source = Scope.source!(run, repo, file)

            ExAST.Patcher.find_many(source, patterns, expand_imports: false)
            |> Enum.map(fn match ->
              range = match.range || raise("ExAST match has no source range")
              first = Keyword.fetch!(range.start, :line)
              last = Keyword.fetch!(range.end, :line)
              column = Keyword.get(range.start, :column, 1)
              {to_string(match.pattern), first, last, column, match.source || ""}
            end)
          end)

        case result do
          {:ok, matches} ->
            {contexts, findings} =
              Enum.split_with(matches, &String.starts_with?(elem(&1, 0), "context:"))

            ranges = Enum.map(contexts, fn {_, first, last, _, _} -> {first, last} end)

            current =
              Enum.map(findings, fn {pattern, first, _last, col, snippet} ->
                [rule, _] = String.split(pattern, ":", parts: 2)

                hit("ex_ast", rule, file["path"], first, col, snippet, "candidate")
                |> Map.put("query", pattern)
              end)

            {current ++ hits, Map.put(spans, file["path"], ranges), errors}

          {:error, reason} ->
            {hits, spans, [%{"path" => file["path"], "reason" => reason} | errors]}
        end
      end)

    Store.write_lines(Path.join([run, repo, "raw", "ex_ast.jsonl"]), Enum.reverse(hits))

    {hits, spans,
     status("ex_ast", if(errors == [], do: "completed", else: "partial"), %{
       "submitted" => length(elixir_files),
       "failed_files" => Enum.reverse(errors),
       "unmodeled_extensions" =>
         files |> Enum.reject(&(&1 in elixir_files)) |> Enum.map(& &1["path"]),
       "patterns" => patterns
     })}
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
        "--strict",
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
        result =
          Store.safe(fn ->
            expression =
              "Mix.start(); {:ok, _} = Application.ensure_all_started(:sobelow); Mix.Tasks.Sobelow.main(System.argv())"

            Store.worker(expression, args, run)
          end)

        case result do
          {:ok, {out, exit_code}} ->
            Store.atomic(Path.join([run, repo, "raw", "sobelow-#{index}.sarif.log"]), out)

            decoded =
              if exit_code == 0,
                do: Store.safe(fn -> sarif(out, target, root) end),
                else: {:error, "exit #{exit_code}"}

            case decoded do
              {:ok, hits} ->
                {hits,
                 status("sobelow:#{app}", "completed", %{
                   "matches" => length(hits),
                   "args" => args,
                   "exit" => exit_code,
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

  @doc false
  def account(repo, hits, spans, inventory, identity) do
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
            Map.put(row, "reason", "context_only_policy")

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

            group =
              Store.id([
                identity["root"],
                identity["commit"],
                row["path"],
                row["rule"],
                first,
                last
              ])

            Map.merge(row, %{
              "bucket" => "queued",
              "candidate_id" => group,
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

        %{
          "id" => id,
          "repo" => repo,
          "path" => first["path"],
          "rule" => first["rule"],
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
