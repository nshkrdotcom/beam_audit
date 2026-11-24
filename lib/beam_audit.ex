defmodule BeamAudit do
  @moduledoc """
  First-party security audits of explicitly selected Git repositories.

  Discovery is source-only. Review is a bounded evidence-based workflow, not
  autonomous repository scanning. Results are kept on disk and can be resumed.
  See the guides for coverage limits and the provider qualification gate.
  """
  alias BeamAudit.Run

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

  @doc "Inspect local prerequisites without executing a target repository or spending tokens."
  def doctor, do: Run.doctor()
end
