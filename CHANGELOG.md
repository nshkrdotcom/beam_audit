# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-24

### Added

- `BeamAudit` Elixir API (`audit/2`, `discover/2`, `resume/2`, `report/2`,
  `compare/3`, `list_runs/1`, `delete_run/2`, `prune_runs/1`, `doctor/0`) and
  `mix beam_audit` CLI with `full`, `source`, and `dependencies` profiles and
  JSON configuration support.
- Pinned Git repository scoping and read-only, SHA-256-verified source
  snapshots captured directly from Git blobs without compiling or executing
  target code.
- Deterministic source discovery in an isolated worker combining `git grep`,
  ExAST structural patterns and lexical definitions, Sobelow SARIF
  diagnostics, Reach taint flows and slices, public/owner security boundaries,
  and a versioned ruleset (`P01`-`P13`, `CTX`) with full hit accounting.
- Native dependency advisory assessment via VulnCheck over committed Mix,
  Rebar, and Gleam metadata with conservative lock-only fallback, `--offline`
  cache mode, and opt-in `.beam`/`.app` artifact capture (`--compiled`).
- Bounded, resumable AI-assisted review and selective challenge adjudication
  via Agent Session Manager (Codex default, Antigravity optional) with
  mechanical citation validation, stored-evidence follow-up rounds, shared
  cumulative call budgets, provider-error pausing, and `--reconsider` retries.
- Deterministic Markdown reports (`report.md`), structured run projections
  (`summary.json`, `findings.jsonl`, `dispositions.jsonl`), and
  exact-fingerprint cross-run comparison without claiming remediation.
- Durable run storage in `$XDG_STATE_HOME/beam_audit/runs` (overridable via
  `--out`, `BEAM_AUDIT_OUT`, or app config), per-run filesystem guards, and
  dry-run-first `runs`, `delete`, and `prune` retention commands.

[0.1.0]: https://github.com/nshkrdotcom/beam_audit/releases/tag/v0.1.0
