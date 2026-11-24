# Library integration

Use the library API from the ecosystem manager, not a second scanner or agent
integration layer. Calls return `{:ok, result}` or `{:error, reason}`. Successful
operation does not certify security: inspect status, pending, unresolved and gaps.

```elixir
repositories = [
  %{"path" => "/workspace/weld", "revision" => "HEAD"},
  %{"path" => "/workspace/codex_sdk", "exclude" => ["third_party"]}
]
{:ok, discovery} = BeamAudit.discover(repositories, profile: "full")
{:ok, result} = BeamAudit.resume(discovery.path, max_calls: 12,
  on_progress: fn event -> IO.inspect(event) end)
{:ok, report} = BeamAudit.report(result.path)
{:ok, changes} = BeamAudit.compare(previous_run, result.path)
```

`audit/2` combines discovery and review; `doctor/0` inspects local prerequisites.
Options are Elixir keywords; repository specifications use string keys. Profiles
are `full`, `source`, `dependencies`. Progress callbacks receive stage metadata,
not source. Observer failures do not fail the audit. Summary fields include run
identity/path, report, status, pending, unresolved, coverage_gaps, source_findings,
dependency_findings, combined findings count, usage and repository_count.
`findings.jsonl` contains structured source and dependency findings.

Run API operations are synchronous. Use one writer per run directory; callers
must coordinate any independent runs and provider quotas. No database, service,
custom agent runtime or application supervision tree is added. Packaged release
operation should be validated separately if needed; the source worker uses the
installed Elixir executable and trusted code paths.
