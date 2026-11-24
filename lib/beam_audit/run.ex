defmodule BeamAudit.Run do
  @moduledoc """
  Run creation, immutable input accounting, finite review budgets and resume.
  A single coordinating writer owns a run; independent runs can execute in parallel.
  """
  alias BeamAudit.{Discovery, Report, Review, Scope, Store}

  @defaults %{
    "provider" => "codex",
    "model" => nil,
    "jobs" => 4,
    "batch_size" => 6,
    "max_calls" => 80,
    "evidence_rounds" => 2,
    "deadline_ms" => 300_000,
    "max_file_bytes" => 1_048_576,
    "include_tests" => false
  }

  @option_keys ~w(provider model jobs batch_size max_calls evidence_rounds deadline_ms max_file_bytes include_tests)a

  @doc false
  def default_out, do: Path.expand("~/.beam_audit/runs")

  @doc false
  def doctor do
    %{
      "elixir" => System.version(),
      "otp" => System.otp_release(),
      "git" => System.find_executable("git"),
      "git_version" => git_version(),
      "elixir_executable" => System.find_executable("elixir"),
      "codex" => System.find_executable("codex"),
      "antigravity" => System.find_executable("agy"),
      "libraries" => Store.versions(),
      "provider_boundary" => Store.read(Store.priv("asm_boundary.json"))
    }
  end

  defp git_version do
    case System.find_executable("git") do
      nil ->
        nil

      executable ->
        case System.cmd(executable, ["--version"], stderr_to_stdout: true) do
          {text, 0} -> String.trim(text)
          _ -> nil
        end
    end
  end

  @doc false
  def discover(repositories, opts) do
    Store.safe(fn ->
      if repositories == [], do: raise("Select at least one repository")
      settings = settings(@defaults, opts)

      repos =
        repositories
        |> Enum.with_index(1)
        |> Enum.map(fn {spec, i} ->
          spec = if is_binary(spec), do: %{"path" => spec}, else: spec
          spec = Map.put_new(spec, "include_tests", settings["include_tests"])
          Scope.resolve(spec, i)
        end)

      if length(Enum.uniq_by(repos, &{&1["root"], &1["commit"]})) != length(repos),
        do: raise("Duplicate repository/revision")

      parent = opts |> Keyword.get(:out, default_out()) |> Path.expand()

      if Enum.any?(
           repos,
           &(parent == &1["root"] or String.starts_with?(parent, &1["root"] <> "/"))
         ),
         do: raise("Output must be outside the audited repositories")

      File.mkdir_p!(parent)
      run = Path.join(parent, "#{System.os_time(:second)}-#{Store.nonce()}")
      File.mkdir!(run)
      File.chmod!(run, 0o700)
      rules = File.read!(Store.priv("rules.json"))
      Store.atomic(Path.join(run, "rules.json"), rules)

      prompts =
        Map.new(~w(adjudicate.md challenge.md), fn name ->
          text = File.read!(Store.priv("prompts/" <> name))
          Store.atomic(Path.join([run, "prompts", name]), text)
          {name, Store.digest(text)}
        end)

      repos =
        Enum.map(repos, fn repo ->
          case Store.safe(fn -> Scope.snapshot(run, repo, settings["max_file_bytes"]) end) do
            {:ok, _} ->
              Map.put(
                repo,
                "inventory_sha256",
                Store.digest(File.read!(Path.join([run, repo["id"], "inventory.jsonl"])))
              )

            {:error, reason} ->
              Map.put(repo, "snapshot_error", reason)
          end
        end)

      Store.write(Path.join(run, "manifest.json"), %{
        "schema" => 1,
        "id" => Path.basename(run),
        "created_at" => Store.now(),
        "settings" => settings,
        "repositories" => repos,
        "tools" => doctor(),
        "rules_sha256" => Store.digest(rules),
        "prompts_sha256" => prompts
      })

      repos
      |> Enum.reject(& &1["snapshot_error"])
      |> Task.async_stream(
        fn repo ->
          case Store.safe(fn -> Discovery.run(run, repo["id"]) end) do
            {:ok, _} ->
              :ok

            {:error, reason} ->
              Store.write(Path.join([run, repo["id"], "discovery_failure.json"]), %{
                "status" => "failed",
                "reason" => reason
              })
          end
        end,
        max_concurrency: min(settings["jobs"], 2),
        timeout: :infinity,
        ordered: false
      )
      |> Stream.run()

      Report.render(run)
    end)
  end

  @doc false
  def resume(id, opts) do
    Store.safe(fn ->
      run = resolve_run(id, opts)
      manifest = verify!(run)
      config = settings(manifest["settings"], opts)
      # Only the review scheduling/provider choices may change at resume.
      config = Map.put(config, "max_file_bytes", manifest["settings"]["max_file_bytes"])
      counter = :atomics.new(1, signed: false)
      :atomics.put(counter, 1, call_count(run))

      case Review.provider_check(config["provider"]) do
        :ok ->
          Store.write(Path.join(run, "review_status.json"), %{
            "status" => "reviewing",
            "settings" => config
          })

          Enum.each(manifest["repositories"], fn repo ->
            if ready?(run, repo) do
              Review.execute(run, repo["id"], config, counter)
            end
          end)

          Store.write(Path.join(run, "review_status.json"), %{
            "status" => "review_pass_finished",
            "settings" => config
          })

        {:error, reason} ->
          Store.write(Path.join(run, "review_status.json"), %{
            "status" => "provider_blocked",
            "reason" => reason,
            "settings" => config
          })
      end

      Report.render(run)
    end)
  end

  @doc false
  def report(id, opts), do: Store.safe(fn -> id |> resolve_run(opts) |> Report.render() end)

  @doc false
  def resolve_run(id, opts) do
    cond do
      File.regular?(Path.join(id, "manifest.json")) ->
        Path.expand(id)

      Regex.match?(~r/\A[0-9]+-[0-9a-f]+\z/, id) ->
        Path.join(Keyword.get(opts, :out, default_out()) |> Path.expand(), id)

      true ->
        raise "Pass a run ID or its directory"
    end
  end

  @doc false
  def ready?(run, repo),
    do:
      is_nil(repo["snapshot_error"]) and
        File.regular?(Path.join([run, repo["id"], "discovery.json"])) and
        not File.exists?(Path.join([run, repo["id"], "discovery_failure.json"]))

  @doc false
  def verify!(run) do
    manifest = Store.read(Path.join(run, "manifest.json"))
    if manifest["schema"] != 1, do: raise("Unsupported run format")
    check_hash(Path.join(run, "rules.json"), manifest["rules_sha256"])

    Enum.each(manifest["prompts_sha256"], fn {name, hash} ->
      check_hash(Path.join([run, "prompts", name]), hash)
    end)

    Enum.each(manifest["repositories"], fn repo ->
      if is_nil(repo["snapshot_error"]) do
        dir = Path.join(run, repo["id"])
        check_hash(Path.join(dir, "inventory.jsonl"), repo["inventory_sha256"])
        inventory = Scope.inventory(run, repo["id"])
        Enum.each(Scope.included(inventory), &Scope.source!(run, repo["id"], &1))

        if ready?(run, repo) do
          data = Store.read(Path.join(dir, "discovery.json"))

          Enum.each(~w(ledger candidates flows), fn file ->
            check_hash(Path.join(dir, file <> ".jsonl"), data[file <> "_sha256"])
          end)

          verify_ledger!(dir, repo, inventory)
        end
      end
    end)

    manifest
  end

  defp check_hash(path, hash) do
    unless Store.digest(File.read!(path)) == hash, do: raise("Recorded input changed: #{path}")
  end

  defp verify_ledger!(dir, repo, inventory) do
    rows = Store.read_lines(Path.join(dir, "ledger.jsonl"))
    groups = Store.read_lines(Path.join(dir, "candidates.jsonl"))
    ids = Enum.map(rows, & &1["raw_id"])
    group_ids = Enum.map(groups, & &1["id"])
    queued = Enum.filter(rows, &(&1["bucket"] == "queued"))
    expected = Enum.sort(Enum.map(queued, &{&1["raw_id"], &1["candidate_id"]}))

    actual =
      Enum.flat_map(groups, fn group -> Enum.map(group["raw_ids"], &{&1, group["id"]}) end)
      |> Enum.sort()

    unless Enum.uniq(ids) == ids and Enum.uniq(group_ids) == group_ids and expected == actual and
             Enum.all?(rows, &(&1["bucket"] in ~w(queued context excluded))) and
             Enum.all?(
               groups,
               &(&1["repo"] == repo["id"] and
                   Scope.location_valid?(inventory, &1["path"], &1["first"], &1["last"]))
             ),
           do: raise("Candidate ledger does not reconcile")

    Enum.each(~w(decisions challenges), fn phase ->
      for path <- Path.wildcard(Path.join([dir, phase, "*.json"])) do
        id = Path.basename(path, ".json")
        unless id in group_ids, do: raise("Unexpected decision file: #{path}")
        rec = Store.read(path)
        group = Enum.find(groups, &(&1["id"] == id))

        if phase == "challenges" do
          primary = Review.record(Path.dirname(dir), repo["id"], "decisions", id)

          unless primary && Review.challenge_required?(primary["decision"], group),
            do: raise("Challenge without required primary review: #{path}")
        end

        unless rec["packet"]["candidate"] == group and
                 Review.validate(rec["decision"], rec["packet"]) == :ok and
                 rec["decision"]["requests"] == [],
               do: raise("Invalid persisted decision: #{path}")

        Enum.each(rec["packet"]["excerpts"], fn excerpt ->
          expected =
            BeamAudit.Evidence.excerpt(
              Path.dirname(dir),
              repo["id"],
              inventory,
              excerpt["path"],
              excerpt["first"],
              excerpt["last"]
            )

          unless excerpt == expected, do: raise("Invalid persisted evidence: #{path}")
        end)
      end
    end)
  end

  @doc false
  def call_count(run) do
    Path.wildcard(Path.join([run, "calls", "*.json"]))
    |> Enum.map(fn path -> path |> Path.basename(".json") |> String.to_integer() end)
    |> Enum.max(fn -> 0 end)
  end

  defp settings(base, opts) do
    result =
      Enum.reduce(@option_keys, base, fn key, acc ->
        case Keyword.fetch(opts, key) do
          {:ok, value} -> Map.put(acc, Atom.to_string(key), value)
          :error -> acc
        end
      end)

    if result["provider"] not in ~w(codex antigravity), do: raise("Unsupported provider")

    for {key, range} <- [
          {"jobs", 1..16},
          {"batch_size", 1..12},
          {"max_calls", 0..10_000},
          {"evidence_rounds", 0..4},
          {"deadline_ms", 1_000..900_000},
          {"max_file_bytes", 1_024..8_388_608}
        ] do
      unless is_integer(result[key]) and result[key] in range, do: raise("Invalid #{key}")
    end

    unless is_nil(result["model"]) or is_binary(result["model"]), do: raise("Invalid model")
    unless is_boolean(result["include_tests"]), do: raise("Invalid include_tests")
    result
  end
end
