# Library integration

Use the same library from the ecosystem manager. Do not wrap another copy of the
scanner or build an agent integration layer. All public operations return
`{:ok, summary}` or `{:error, reason}`. A successful return means the requested
workflow operation produced records; inspect `status`, `pending`, `unresolved`
and `coverage_gaps` before interpreting the results.

```elixir
repositories = [
  %{"path" => "/workspace/weld", "revision" => "HEAD"},
  %{"path" => "/workspace/codex_sdk", "exclude" => ["third_party"]}
]

{:ok, discovery} = BeamAudit.discover(repositories, out: "/audit/runs")
{:ok, result} = BeamAudit.resume(discovery.path, max_calls: 120, jobs: 4)
{:ok, report} = BeamAudit.report(result.path)
```

`BeamAudit.audit/2` combines both phases. `BeamAudit.doctor/0` returns local
prerequisite and qualification information. Options are ordinary Elixir keyword
lists, with string repository map keys and provider/model values. The Mix task
calls this API, not an external service.

| Field | Meaning |
| --- | --- |
| `id` / `path` | Run identity and absolute directory |
| `report` | Absolute Markdown report path |
| `status` | Accounting under the declared policy, or partial/unresolved |
| `review_status` | Review state or provider blocker |
| `pending` | Outstanding primary and challenge records |
| `unresolved` | Accepted uncertainty or material disagreement |
| `coverage_gaps` | Scanner/source omissions and failure indicators |
| `findings` | Effective confirmed/potential candidate groups |
| `repository_count` | Number of explicit repository/revision entries |

The current API is synchronous. The caller may run independent audits in tasks
or its existing job orchestration. Use a single writer per run directory; do not
invoke concurrent resume operations for the same run. No service, GenServer tree,
external storage or framework is introduced by BeamAudit itself. ASM owns its
own sessions and subprocess lifecycle. The source worker needs the trusted
installed Elixir executable and current release code paths, so validate packaged
release use separately from the Mix path before promising a release deployment.

Reports can be regenerated from a saved run with the same schema. Treat run
records as sensitive audit artifacts. Do not make cross-run waiver decisions
from line numbers alone: a changed commit, caller, validator or configuration
may invalidate an otherwise identical function's earlier conclusion.
