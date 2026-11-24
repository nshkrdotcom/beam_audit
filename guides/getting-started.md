# Getting started

BeamAudit operates from its own checkout, or a trusted Mix project that has it
as a dependency. Do not run Mix inside an audited project to make the audit work.

## Install and audit

```sh
mix deps.get
mix beam_audit /path/to/repository --discover-only
```

This is the source-only command and needs no provider login. The ordinary
`mix beam_audit /path/to/repository` command also reviews evidence through ASM
with an authenticated provider. Use `mix beam_audit doctor` to inspect local prerequisites.

Pass multiple repository roots as positional arguments. HEAD is resolved once
per repository. To pin one historical revision use `--rev SHA`.

```sh
mix beam_audit ~/projects/weld --rev 0f10cbd70ca6d20e8ba1a8b43b09b4fcba3db9c3 --discover-only
```

## Optional configuration

Use JSON only when repeatable scope or nondefault limits are useful:

```json
{
  "repositories": [
    {"path": "~/projects/weld", "revision": "HEAD", "exclude": ["third_party"]},
    {"path": "~/projects/codex_sdk", "revision": "HEAD", "include_tests": true}
  ],
  "provider": "codex",
  "jobs": 4,
  "batch_size": 6,
  "max_calls": 80
}
```

```sh
mix beam_audit --config audit.json --discover-only
```

Repositories are root paths or objects containing `path`, optional `revision`,
relative directory/file `exclude` entries, and `include_tests`. Config file
paths are resolved from the caller's working directory, not from the JSON file.
CLI options override configuration defaults; positional repository arguments
and `--config` are mutually exclusive. `--rev` applies to one positional root.

| Setting | Default | Meaning |
| --- | --- | --- |
| `provider` | `codex` | ASM provider; select Antigravity as an alternative |
| `model` | ASM default | Explicit model override only if requested |
| `jobs` | 4 | Maximum concurrent review batches; discovery uses at most 2 repository workers |
| `batch_size` | 6 | Maximum groups in a review call; large packets split further |
| `max_calls` | 80 | Cumulative reservation budget, including evidence and challenge calls |
| `evidence_rounds` | 2 | Additional bounded retrieval rounds per batch |
| `deadline_ms` | 300000 | ASM run deadline in milliseconds |
| `max_file_bytes` | 1048576 | Individual source snapshot byte limit |
| `include_tests` | false | Include tests, fixtures and examples |
| `out` | `~/.beam_audit/runs` | Output root outside selected repositories |

Use `--help` for option names. CLI flags use hyphens. There is no mandatory setup
script, `.env` file, or per-target dependency installation. `doctor` inspects
local prerequisites and library versions without querying a model.

## Result status

The CLI prints the saved report path before returning. Full audit/resume returns
an error status when review or coverage is incomplete. `--discover-only` and
`report` permit partial results because no review is expected. A complete status
means accounting under the declared policy; it is not a security certification.
