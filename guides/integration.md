# Library integration

Use the library API from a trusted calling Mix project or host application.
Add the published package to the caller's Mix dependencies:

```elixir
{:beam_audit, "~> 0.1.0"}
```

The audit operations are synchronous and return `{:ok, result}` or
`{:error, reason}`. `doctor/0` returns its prerequisite map directly. Successful
operation does not certify security: inspect status, pending, unresolved and
coverage gaps.

## Audit API

```elixir
repositories = [
  %{"path" => "/path/to/app_a", "revision" => "HEAD"},
  %{"path" => "/path/to/app_b", "exclude" => ["third_party"]}
]
{:ok, discovery} = BeamAudit.discover(repositories, profile: "full")
{:ok, result} = BeamAudit.resume(discovery.path, max_calls: 12,
  on_progress: fn event -> IO.inspect(event) end)
{:ok, report} = BeamAudit.report(result.path)
# Compare with a separately captured earlier run when available:
# {:ok, changes} = BeamAudit.compare(previous_run, result.path)
```

`audit/2` combines discovery and review; `doctor/0` inspects local prerequisites.
Both `discover/2` and `audit/2` accept a repository path or specification, or a
list of paths/specifications. Run options are Elixir keywords. Repository
specifications use string keys:

| Key | Meaning |
| --- | --- |
| `"path"` | Required Git repository root |
| `"revision"` | Git reference, default `HEAD` |
| `"exclude"` | Repository-relative paths or directory prefixes |
| `"include_tests"` | Override the run's test/example inclusion policy |
| `"boundaries"` | List of audit questions with `"path"`, `"line"` and `"question"` |

Boundary paths must be relative, lines positive integers, and question strings
1–1,000 bytes. Use actual in-scope source anchors. Duplicate repository/commit
pairs are rejected within a run.

Profiles and option ranges are documented in [Getting started](getting-started.md).
`resume/2` accepts review tuning options without repeating discovery; pass
`reconsider: true` to explicitly reopen unresolved or disputed decisions when
budget remains. The optional `on_progress:` callback receives atom-keyed stage
metadata, not source. Event stages are `:discovery`, `:dependencies`, `:review`,
`:provider_call` and `:provider_return`. Observer failures do not fail the audit.

## Return values

`discover/2`, `audit/2`, `resume/2` and `report/2` return atom-keyed summary maps
inside `{:ok, summary}`. Fields include `id`, `path`, `report`, `status`,
`review_status`, `pending`, `unresolved`, `coverage_gaps`, `source_findings`,
`dependency_findings`, `findings` (combined count), `usage` and
`repository_count`. `list_runs/1`, `delete_run/2` and `prune_runs/1` likewise
return atom-keyed lifecycle maps inside `{:ok, result}`. `compare/3` returns
`{:ok, comparison}` with string keys, and `doctor/0` returns a string-keyed map
directly. Stored JSON and JSONL use JSON string keys; `findings.jsonl` contains
structured source and dependency findings.

## Storage and retention

Configure a results root in the calling application, or pass `out:` explicitly:

```elixir
# In the calling project's config/config.exs
config :beam_audit, out: "/path/to/audit-runs"
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

## Operational considerations

Public run operations use a directory guard. Callers still coordinate independent
runs and shared provider quotas. No database or background service is required.
If deploying BeamAudit in a packaged release, validate that environment
separately: the source worker uses the installed Elixir executable and trusted
code paths.
