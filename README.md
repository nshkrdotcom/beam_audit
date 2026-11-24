<p align="center">
  <img src="assets/beam_audit.svg" alt="BeamAudit" width="200" />
</p>
<p align="center">
  <a href="https://github.com/nshkrdotcom/beam_audit"><img src="https://img.shields.io/badge/github-nshkrdotcom%2Fbeam__audit-24292e.svg" alt="GitHub" /></a>
  <a href="https://github.com/nshkrdotcom/beam_audit/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>
</p>

# BeamAudit

Reproducible first-party security auditing for Elixir and the BEAM. Discover
candidate vulnerability patterns with existing analyzers, gather evidence,
review with a bounded AI adjudicator, and produce a reconciled report.

BeamAudit is a library and a Mix task. It is not a new static analysis engine,
dependency scanner, agent framework, or application runtime. It does not modify
or compile the audited repositories.

> Unreleased. Discovery and reporting work independently of review. Live review
> is blocked until ASM can enforce read containment and restrict tool access.

## Getting started

Requirements: Elixir 1.20, compatible OTP, and Git. The four analysis/review
libraries are normal Mix dependencies. ExDoc is a development-only dependency.
For AI review, use an installed, authenticated ASM-supported provider (Codex by
preference). No extra scanner installation, target dependencies, environment
variables, containers, or service configuration.

```sh
git clone https://github.com/nshkrdotcom/beam_audit.git
cd beam_audit
mix deps.get
mix beam_audit ~/projects/weld --discover-only
```

After provider qualification:

```sh
mix beam_audit ~/projects/weld ~/projects/codex_sdk ~/projects/gemini_ex
```

The command pins HEAD of each selected repository, snapshots the authorized
tracked source, runs deterministic checks, and (when qualified) reviews pending
candidate groups through ASM. It prints the run ID and report location.
Results default to `~/.beam_audit/runs/`; `--out` selects another results root
outside the targets.

```sh
mix beam_audit resume RUN_ID
mix beam_audit report RUN_ID
mix beam_audit doctor
mix beam_audit --help
```

Use `--config audit.json` for explicitly pinned repository lists or exclusions.
Ordinary use needs no configuration. Only committed source is audited; tests and
examples are separate, opt-in scope. See [Scope and safety](guides/scope-and-safety.md).

## Library usage

Before publication, depend on the Git repository:

```elixir
{:beam_audit, github: "nshkrdotcom/beam_audit"}
```

After an actual Hex release, use `{:beam_audit, "~> 0.1.0"}` instead.

```elixir
{:ok, run} = BeamAudit.discover(["/path/to/weld"])
{:ok, result} = BeamAudit.resume(run.path)
{:ok, report} = BeamAudit.report(result.path)
```

`BeamAudit.audit/2` combines discovery and review. The same library drives the
Mix task; no standalone agent runtime or server is required.

## Execution contract

| Stage | Owner |
| --- | --- |
| Scope, Git snapshots, inventory | BeamAudit / Git |
| Textual and structural discovery | Git grep / ExAST |
| Established first-party checks | Sobelow |
| Source data-flow evidence | Reach |
| Candidate grouping, review queue, reconciliation | BeamAudit |
| Security-property judgment and independent challenge | ASM-backed provider |
| Remediation and regression execution | Repository owner, outside this audit |

Every raw finding is queued, retained as context, or explicitly excluded under
the captured policy. Failed or unsupported scans stay visible. Accepted review
records are written individually; a resume does not re-review them. A report
can be regenerated without running scanners or consuming LLM tokens.

The initial policy targets unsafe representation reconstruction, struct trust,
nested validation, implicit protocol dispatch, executable authority, interpreted
query expressions and atom creation. Sobelow provides additional existing checks.
This is not a comprehensive BEAM vulnerability catalogue. Static matching,
call reachability and semantic evidence are not interchangeable with proof.

## Documentation

**Getting started**
- [Installation, commands and configuration](guides/getting-started.md)

**Audit workflow**
- [Scope and safety](guides/scope-and-safety.md)
- [Execution graph](guides/workflow.md)
- [Security rules and coverage](guides/security-rules.md)
- [Agentic review and evidence](guides/review-and-evidence.md)

**Operations and integration**
- [Library integration](guides/integration.md)
- [Results and recovery](guides/results-and-recovery.md)
- [Verification and release gates](guides/validation.md)

**Project**
- [Changelog](CHANGELOG.md)
- [MIT license](LICENSE)

## Development

```sh
mix deps.get
mix format
mix compile --warnings-as-errors
mix test
mix docs
mix hex.build
```

The tests include pinned-source scope, native analyzer contracts, reconciliation,
and review recovery with a deterministic test reviewer. They do not substitute
for a live analyzer or provider evaluation. The initial delivery could not run
these BEAM commands; see the validation guide and Phase 2 handoff.

## License

MIT. Copyright (c) 2026 nshkrdotcom.
