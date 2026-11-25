# Getting started

Run from BeamAudit's own checkout or a separate, trusted Mix project that
uses it. Target repositories are data inputs, not the Mix project executing
BeamAudit. Discovery does not need a target build or installed target dependencies.

## Setup

BeamAudit requires Elixir `~> 1.20`, compatible OTP, and Git. Add the published
Hex package to the calling project's dependency list:

```elixir
{:beam_audit, "~> 0.1.0"}
```

Alternatively, use a standalone checkout:

```sh
git clone https://github.com/nshkrdotcom/beam_audit.git
cd beam_audit
```

In either host project, run:

```sh
mix deps.get
mix beam_audit doctor
mix beam_audit ~/projects/my_app --discover-only
```

`doctor` reports the Elixir and OTP versions, Git path and version, the
`elixir` executable, the `codex` and `agy` executables, and installed BeamAudit
and analyzer library versions. It does not authenticate a provider or make a
live model request. Authenticate the selected ASM provider before AI review;
provider credentials are not needed for discovery-only operation.

## Analysis profiles

The default `full` profile covers both source and dependencies. `source` skips
advisory feeds; `dependencies` skips source analyzers and has no review queue.
`--discover-only` skips all provider calls. `--offline` uses VulnCheck's cached
feed data; missing or stale inputs are visible. `--compiled` is opt-in and
reads existing build artifacts only. Nothing compiles the target.

## Repository selection

Pin a single positional repository with `--rev REF` (default `HEAD`). Multiple
repositories can be supplied as positional roots. Use a JSON config for
per-repository revisions, exclusions, test inclusion or audit questions:

```json
{
  "repositories": [
    {"path": "~/projects/my_app", "revision": "HEAD", "exclude": ["third_party"]},
    {"path": "~/projects/my_lib", "boundaries": [
      {"path": "lib/example.ex", "line": 12, "question": "Can untrusted input choose executable authority?"}
    ]}
  ],
  "profile": "full",
  "jobs": 1,
  "max_calls": 24
}
```

Replace example boundary locations with real in-scope source anchors. Repository
roots are resolved from the caller's working directory, not the config file's
location. Exclusion paths and boundary paths are repository-relative. Positional
roots and `--config` are mutually exclusive; CLI flags override top-level config
values. Repository-specific `include_tests` overrides the run default. Use
`--rev` only with a single positional repository; put `revision` in each JSON
repository specification instead.

## Options

CLI flags use kebab-case; Elixir keyword options and JSON configuration keys use
snake_case. Boolean analysis flags default to `false` unless stated otherwise.

| Elixir / JSON key | CLI flag | Default | Meaning / valid range |
| --- | --- | --- | --- |
| `profile` | `--profile` | `full` | `full`, `source`, `dependencies` |
| `compiled` | `--compiled` | `false` | Capture existing local build artifacts |
| `offline` | `--offline` | `false` | Cached advisory data only |
| `provider` | `--provider` | `codex` | `codex` or `antigravity` |
| `model` | `--model` | Provider default | Optional model string |
| `jobs` | `--jobs` | 1 | Review concurrency, 1–16 |
| `batch_size` | `--batch-size` | 6 | Groups per call, 1–12; large batches split |
| `max_calls` | `--max-calls` | 24 | Cumulative reservations, 0–10,000 |
| `evidence_rounds` | `--evidence-rounds` | 2 | Additional evidence rounds, 0–4 |
| `deadline_ms` | `--deadline-ms` | 300,000 | Each provider queue, stream and run timeout, 1,000–900,000 ms |
| `max_file_bytes` | `--max-file-bytes` | 1,048,576 | Source/metadata file limit, 1,024–8,388,608 bytes |
| `include_tests` | `--include-tests` | `false` | Include tests, fixtures and examples |
| `out` | `--out` | XDG state root | Results directory |

Discovery workers are capped at `min(jobs, 2)`. Dependency scans are serial
within a run. The review budget includes primary, challenge and follow-up calls;
`--max-calls 0` permits no new provider calls.

Other CLI controls:

- `--discover-only` runs deterministic discovery without review (library:
  `BeamAudit.discover/2`).
- `--rev REF` selects one positional repository revision.
- `--config FILE` supplies a JSON `repositories` list and optional run settings.
- `--reconsider` on `resume` reopens unresolved or disputed decisions when
  budget remains (library: `reconsider: true`).

Use `mix beam_audit --help` for the complete command list, including retention.

## Storage

If `XDG_STATE_HOME` is unset, empty or relative, the default root is
`~/.local/state/beam_audit/runs`. An explicit `out` takes precedence over
`BEAM_AUDIT_OUT`, then `config :beam_audit, out: ...`, then that default.
The root is created only when discovering an audit; listing an absent root
returns an empty inventory. Use `runs`, `delete` and `prune` to manage saved
runs. See [Results and recovery](results-and-recovery.md).

## Output and exit status

Audits, discovery-only runs, `resume` and `report` print a four-line text summary
to stdout: `Run`, `Report`, `Status`, and counts of pending, unresolved and
coverage gaps. BeamAudit's progress events go to stderr. The `doctor`, `compare`,
`runs`, `delete` and `prune` commands print JSON to stdout.

An audit without `--discover-only`, or a `resume`, exits nonzero if the result
is `partial_or_unresolved`. The saved report remains available. Discovery-only
and `report` can succeed with partial results; execution errors still fail the
command. `accounted_within_declared_policy` means that there are no pending
reviews, unresolved decisions or recorded coverage gaps. It does not mean no
findings or a security certification.
