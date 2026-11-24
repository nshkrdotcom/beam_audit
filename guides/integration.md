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

Configure a results root for the ecosystem manager, or pass `out:` explicitly:

```elixir
# In the calling project's config/config.exs
config :beam_audit, out: "/var/lib/ecosystem/beam-audit/runs"
```

```elixir
{:ok, inventory} = BeamAudit.list_runs(out: root)
{:ok, preview} = BeamAudit.delete_run(run_id, out: root)
{:ok, plan} = BeamAudit.prune_runs(out: root, older_than: 30, keep: 5,
  include_partial: true)
# Only after reviewing the intended deletion:
{:ok, result} = BeamAudit.prune_runs(out: root, older_than: 30, keep: 5,
  include_partial: true, confirm: true)
```

`out:` takes precedence over `BEAM_AUDIT_OUT`, application configuration and
XDG state defaults. Deletion accepts a run ID in that root, not a path. API
maps use atom keys for lifecycle metadata (`runs`, `total_bytes`, `selected`,
`deleted`, `skipped`, `errors`, etc.). Inspect `errors` after an applied prune;
removal is per run rather than an all-or-nothing transaction. No provider is
used by these commands.

Run API operations are synchronous. Public run operations use a directory
guard; callers still coordinate independent runs and provider quotas. No database, service,
custom agent runtime or application supervision tree is added. Packaged release
operation should be validated separately if needed; the source worker uses the
installed Elixir executable and trusted code paths.
