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
      mix beam_audit doctor

  Run directories default to `~/.beam_audit/runs`. See `--help` for options.
  No target compilation, environment variables, or separate scanner installation.
  """

  @switches [
    help: :boolean,
    discover_only: :boolean,
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
    max_file_bytes: :integer
  ]
  @config_keys ~w(provider model out include_tests jobs batch_size max_calls evidence_rounds deadline_ms max_file_bytes)a

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
             mix beam_audit doctor

      --discover-only  Skip agentic review
      --rev REF        Pin a single positional repository (default HEAD)
      --include-tests  Include tests/examples in selected source
      --provider NAME  codex (default) or antigravity
      --model NAME     Optional ASM model override
      --jobs N         Review concurrency (default 4)
      --batch-size N   Candidate groups per call (default 6)
      --max-calls N    Cumulative call budget (default 80; increase on resume)
      --evidence-rounds N  Extra evidence rounds (default 2)
      --deadline-ms N  ASM run deadline (default 300000)
      --max-file-bytes N  Source file limit (default 1048576)
      --out DIRECTORY  Results root (default ~/.beam_audit/runs)
      --config FILE    JSON repository list and optional settings
      """)
    else
      Mix.Task.run("app.start")
      dispatch(args, opts)
    end
  end

  defp dispatch(["doctor"], _), do: Mix.shell().info(JSON.encode!(BeamAudit.doctor()))
  defp dispatch(["resume", id], opts), do: finish(BeamAudit.resume(id, opts), false)
  defp dispatch(["report", id], opts), do: finish(BeamAudit.report(id, opts), true)

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

  defp config(args, opts) do
    case opts[:config] do
      nil ->
        {args, opts}

      path ->
        if args != [],
          do: Mix.raise("Select repositories by arguments OR configuration, not both")

        config = path |> File.read!() |> JSON.decode!()

        configured =
          Enum.flat_map(@config_keys, fn key ->
            case Map.fetch(config, Atom.to_string(key)) do
              {:ok, value} -> [{key, value}]
              :error -> []
            end
          end)

        {Map.fetch!(config, "repositories"), Keyword.merge(configured, opts)}
    end
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
