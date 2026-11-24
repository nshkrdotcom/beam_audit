# Getting started

Run from BeamAudit's own checkout or a trusted Mix project depending on it.
Never run Mix inside an audited project to make discovery work.

```sh
mix deps.get
mix beam_audit ~/projects/weld --discover-only
mix beam_audit doctor
```

The default `full` profile covers both source and dependencies. `source` skips
advisory feeds; `dependencies` skips source analyzers and has no review queue.
`--discover-only` skips all provider calls. `--offline` uses VulnCheck's cached
feed data; missing or stale inputs are visible. `--compiled` is opt-in and
reads existing build artifacts only. Nothing compiles the target.

Pin one repository with `--rev SHA`. Select many with positional roots, or use
a JSON config when per-repository settings are needed:

```json
{
  "repositories": [
    {"path": "~/projects/weld", "revision": "HEAD", "exclude": ["third_party"]},
    {"path": "~/projects/codex_sdk", "boundaries": [
      {"path": "lib/example.ex", "line": 12, "question": "Can untrusted input choose executable authority?"}
    ]}
  ],
  "profile": "full",
  "jobs": 1,
  "max_calls": 24
}
```

Replace example boundary locations with real in-scope source anchors. Paths are
resolved from the caller's working directory. Positional roots and `--config`
are mutually exclusive. CLI flags override config values.

| Option | Default | Meaning |
| --- | --- | --- |
| profile | full | source, dependency, or combined analysis |
| compiled | false | use existing local artifact evidence |
| offline | false | cached advisory data only |
| provider | codex | ASM provider; alternative antigravity |
| model | provider default | optional explicit model |
| jobs | 1 | concurrent calls within one run |
| batch_size | 6 | maximum groups per call; large packets split |
| max_calls | 24 | cumulative reservations across all repositories |
| evidence_rounds | 2 | additional evidence rounds |
| deadline_ms | 300000 | provider run, queue and stream timeouts |
| max_file_bytes | 1048576 | snapshot file limit |
| include_tests | false | include tests, fixtures and examples |
| out | $XDG_STATE_HOME/beam_audit/runs | results root; see below |

If `XDG_STATE_HOME` is unset, empty or relative, the default root is
`~/.local/state/beam_audit/runs`. An explicit `out` takes precedence over
`BEAM_AUDIT_OUT`, then `config :beam_audit, out: ...`, then that default.
The root is created only when discovering an audit; listing an absent root
returns an empty inventory. Use `runs`, `delete` and `prune` to manage saved
runs. See [Results and recovery](results-and-recovery.md).

Use `--help` for CLI options. No mandatory provider call is needed for discovery,
reporting, or comparison. The CLI writes progress to stderr and the saved report
path to stdout. Partial results remain available after a nonzero full-audit exit.
A complete accounting status is not a security certification.
