defmodule Mix.Tasks.BeamAudit do
  use Mix.Task

  @shortdoc "Audit explicitly selected BEAM repositories at pinned Git revisions"
  @moduledoc """
  Run from the BeamAudit checkout or a trusted Mix project depending on it.

      mix beam_audit ~/projects/weld
      mix beam_audit ~/projects/weld ~/projects/codex_sdk
      mix beam_audit ~/projects/weld --discover-only
      mix beam_audit resume RUN_ID
      mix beam_audit report RUN_ID
      mix beam_audit runs
      mix beam_audit delete RUN_ID --yes
      mix beam_audit prune --older-than 30 --keep 5
      mix beam_audit doctor

  Run directories default to `$XDG_STATE_HOME/beam_audit/runs` (or
  `~/.local/state/beam_audit/runs`). See `--help` for options.
  No target compilation, required environment variables, or separate scanner installation.
  """

  @switches [
    help: :boolean,
    discover_only: :boolean,
    profile: :string,
    compiled: :boolean,
    offline: :boolean,
    reconsider: :boolean,
    provider: :string,
    model: :string,
    out: :string,
    config: :string,
    rev: :string,
    include_tests: :boolean,
    jobs: :integer,
    batch_size: :integer,
    max_calls: :integer,
    evidence_rounds: :integer,
    deadline_ms: :integer,
    max_file_bytes: :integer,
    older_than: :integer,
    keep: :integer,
    include_partial: :boolean,
    yes: :boolean
  ]
  @config_keys ~w(provider model out include_tests jobs batch_size max_calls evidence_rounds deadline_ms max_file_bytes profile compiled offline)a

  @impl Mix.Task
  def run(argv) do
    {opts, args, invalid} = OptionParser.parse(argv, strict: @switches)
    if invalid != [], do: Mix.raise("Unknown or invalid options: #{inspect(invalid)}")

    if opts[:help] do
      Mix.shell().info("""
      Usage: mix beam_audit REPO [REPO ...] [options]
             mix beam_audit --config audit.json
             mix beam_audit resume RUN_ID [options]
             mix beam_audit report RUN_ID [--out DIRECTORY]
             mix beam_audit compare OLD_RUN NEW_RUN [--out DIRECTORY]
             mix beam_audit runs [--out DIRECTORY]
             mix beam_audit delete RUN_ID [--out DIRECTORY] [--yes]
             mix beam_audit prune [--out DIRECTORY] [--older-than DAYS] [--keep N] [--include-partial] [--yes]
             mix beam_audit doctor

      --discover-only  Skip agentic review (source and dependency analysis)
      --profile NAME   full (default), source, or dependencies
      --compiled       Include existing local compiled dependency evidence
      --offline        Use cached advisory data without network requests
      --reconsider     Explicitly retry unresolved reviews on resume
      --rev REF        Pin a single positional repository (default HEAD)
      --include-tests  Include tests/examples in selected source
      --provider NAME  codex (default) or antigravity
      --model NAME     Optional ASM model override
      --jobs N         Review concurrency (default 1)
      --batch-size N   Candidate groups per call (default 6)
      --max-calls N    Cumulative call budget (default 24; increase on resume)
      --evidence-rounds N  Extra evidence rounds (default 2)
      --deadline-ms N  ASM run deadline (default 300000)
      --max-file-bytes N  Source file limit (default 1048576)
      --out DIRECTORY  Results root (overrides BEAM_AUDIT_OUT and application config)
      --older-than DAYS  Prune runs created more than DAYS ago (positive integer)
      --keep N         Preserve N newest recognized runs in prune (nonnegative integer)
      --include-partial  Allow prune to select partial or unreported runs
      --yes            Apply delete/prune; otherwise preview only
      --config FILE    JSON repository list and optional settings
      """)
    else
      if Enum.any?(Keyword.keys(opts), &(&1 in [:older_than, :keep, :include_partial, :yes])) and
           List.first(args) not in ["delete", "prune"],
         do: Mix.raise("Retention options require delete or prune")

      Mix.Task.run("app.start")
      dispatch(args, Keyword.put(opts, :on_progress, &progress/1))
    end
  end

  defp dispatch(["doctor"], _), do: Mix.shell().info(JSON.encode!(BeamAudit.doctor()))
  defp dispatch(["resume", id], opts), do: finish(BeamAudit.resume(id, opts), false)
  defp dispatch(["report", id], opts), do: finish(BeamAudit.report(id, opts), true)

  defp dispatch(["compare", old, new], opts) do
    case BeamAudit.compare(old, new, opts) do
      {:ok, comparison} -> Mix.shell().info(JSON.encode!(comparison))
      {:error, reason} -> Mix.raise(reason)
    end
  end

  defp dispatch(["runs"], opts) do
    lifecycle_options!(opts, [:out])
    lifecycle(BeamAudit.list_runs(opts))
  end

  defp dispatch(["delete", id], opts) do
    lifecycle_options!(opts, [:out, :yes])
    lifecycle(BeamAudit.delete_run(id, Keyword.put(opts, :confirm, opts[:yes] == true)))
  end

  defp dispatch(["prune"], opts) do
    lifecycle_options!(opts, [:out, :older_than, :keep, :include_partial, :yes])
    lifecycle(BeamAudit.prune_runs(Keyword.put(opts, :confirm, opts[:yes] == true)))
  end

  defp dispatch([command | _], _) when command in ["runs", "delete", "prune"],
    do: Mix.raise("Invalid lifecycle command arguments; see --help")

  defp dispatch(args, opts) do
    {repositories, opts} = config(args, opts)

    repositories =
      case {repositories, opts[:rev]} do
        {[path], rev} when is_binary(path) and is_binary(rev) ->
          [%{"path" => path, "revision" => rev}]

        {repos, nil} ->
          repos

        _ ->
          Mix.raise("--rev requires exactly one positional repository")
      end

    if repositories == [], do: Mix.raise("Select repositories or use --config; see --help")

    if opts[:discover_only] do
      finish(BeamAudit.discover(repositories, opts), true)
    else
      finish(BeamAudit.audit(repositories, opts), false)
    end
  end

  defp lifecycle_options!(opts, allowed) do
    unknown = Keyword.keys(opts) -- [:help, :on_progress | allowed]
    if unknown != [], do: Mix.raise("Invalid lifecycle options: #{inspect(unknown)}")
  end

  defp lifecycle({:error, reason}), do: Mix.raise(reason)

  defp lifecycle({:ok, result}) do
    Mix.shell().info(JSON.encode!(result))

    if Map.get(result, :errors, []) != [],
      do: Mix.raise("Some selected runs could not be deleted; inspect the result")
  end

  defp config(args, opts) do
    case opts[:config] do
      nil ->
        {args, opts}

      path ->
        if args != [],
          do: Mix.raise("Select repositories by arguments OR configuration, not both")

        config = path |> File.read!() |> JSON.decode!()

        configured =
          Enum.flat_map(@config_keys, &configured_option(config, &1))

        {Map.fetch!(config, "repositories"), Keyword.merge(configured, opts)}
    end
  end

  defp configured_option(config, key) do
    case Map.fetch(config, Atom.to_string(key)) do
      {:ok, value} -> [{key, value}]
      :error -> []
    end
  end

  defp progress(event) do
    message =
      event
      |> Map.drop([:run])
      |> Map.to_list()
      |> Enum.sort()
      |> Enum.map_join(" ", fn {key, value} -> "#{key}=#{value}" end)

    IO.puts(:stderr, "BeamAudit: " <> message)
  end

  defp finish({:error, reason}, _), do: Mix.raise(reason)

  defp finish({:ok, result}, allow_partial) do
    Mix.shell().info(
      "Run: #{result.id}\nReport: #{result.report}\nStatus: #{result.status}\nPending: #{result.pending}; unresolved: #{result.unresolved}; gaps: #{result.coverage_gaps}"
    )

    if not allow_partial and result.status != "accounted_within_declared_policy",
      do:
        Mix.raise(
          "Audit incomplete or unresolved; inspect the saved report and resume when applicable"
        )
  end
end
