defmodule BeamAudit do
  @moduledoc """
  Source and dependency security audits of explicitly selected Git repositories.

  Discovery never builds the target. Review is a bounded evidence-based workflow, not
  autonomous repository scanning. Results are kept on disk and can be resumed.
  See the guides for coverage limits and review behavior.
  """
  alias BeamAudit.{Run, RunStorage}

  @doc "Discover, review, and report. Returns a run summary, even for partial review."
  def audit(repositories, opts \\ []) do
    with {:ok, run} <- discover(repositories, opts) do
      resume(run.path, opts)
    end
  end

  @doc "Perform deterministic discovery and render the initial report without an LLM."
  def discover(repositories, opts \\ []), do: Run.discover(List.wrap(repositories), opts)

  @doc "Review only outstanding work in an existing run."
  def resume(run, opts \\ []), do: Run.resume(run, opts)

  @doc "Render a report from persisted results without invoking analyzers or providers."
  def report(run, opts \\ []), do: Run.report(run, opts)

  @doc "Compare accepted source and dependency findings in two persisted runs."
  def compare(old_run, new_run, opts \\ []), do: Run.compare(old_run, new_run, opts)

  @doc "List saved runs in the selected results root, without regenerating reports."
  def list_runs(opts \\ []), do: RunStorage.list(opts)

  @doc "Preview deletion of a run ID in the selected root; `confirm: true` removes it."
  def delete_run(id, opts \\ []), do: RunStorage.delete(id, opts)

  @doc "Preview retention by `older_than` days and/or `keep` newest runs; opt in to deletion."
  def prune_runs(opts \\ []), do: RunStorage.prune(opts)

  @doc "Inspect local prerequisites without executing a target repository or spending tokens."
  def doctor, do: Run.doctor()
end
