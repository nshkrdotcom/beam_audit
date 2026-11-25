<p align="center">
  <img src="assets/beam_audit.svg" alt="BeamAudit" width="200" />
</p>
<p align="center">
  <a href="https://github.com/nshkrdotcom/beam_audit"><img src="https://img.shields.io/badge/github-nshkrdotcom%2Fbeam__audit-24292e.svg" alt="GitHub" /></a>
  <a href="https://github.com/nshkrdotcom/beam_audit/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>
</p>

# BeamAudit

Reproducible source and dependency security auditing for Elixir and the BEAM.
Combine native structural and semantic analysis, dependency advisory matching,
and bounded AI-assisted investigation in a single evidence-backed report.

BeamAudit is a library and a Mix task. It does not compile, execute, or modify
its target projects. It does not replace the underlying analyzers or ASM.

## Getting started

Requires Elixir `~> 1.20`, compatible OTP, and Git. The analyzer libraries are
ordinary Mix dependencies. AI review also requires an authenticated ASM provider;
Codex is the default. There are no required environment variables or additional
scanner binaries.

### Installation

To use BeamAudit from a separate, trusted Mix project, add the published Hex
package to its dependencies:

```elixir
{:beam_audit, "~> 0.1.0"}
```

Run `mix deps.get` in that project. To work from a standalone source checkout
(including before the package is published), use:

```sh
git clone https://github.com/nshkrdotcom/beam_audit.git
cd beam_audit
mix deps.get
```

Check the local prerequisites and start with deterministic discovery:

```sh
mix beam_audit doctor
mix beam_audit ~/projects/my_app --discover-only
```

The default full profile captures committed source and dependency metadata.
Discovery-only does not call a model. Advisory data may be fetched through
VulnCheck's native feed cache. Inspect the saved report before spending tokens.

```sh
mix beam_audit ~/projects/my_app ~/projects/my_lib
mix beam_audit ~/projects/my_app --profile source --discover-only
mix beam_audit ~/projects/my_app --profile dependencies
mix beam_audit resume RUN_ID --max-calls 25
mix beam_audit report RUN_ID
mix beam_audit compare OLD_RUN NEW_RUN
```

New runs default to one concurrent provider call and at most 24 reserved calls
across all repositories in that run. A provider failure pauses new launches.
Resume does not repeat discovery or accepted decisions unless reconsideration is
explicitly requested for unresolved or disputed work. The call budget is
cumulative; increase it deliberately. Separate runs have independent budgets
but can consume the same provider account quota.
Full audits and resume exit nonzero when accounting remains incomplete or
unresolved, but preserve the saved report and available recovery records.
Use `--compiled` only when existing build artifacts are wanted as additional
reachability evidence. No target build is performed.

## Saved runs and cleanup

Runs are stored under `$XDG_STATE_HOME/beam_audit/runs`, defaulting to
`~/.local/state/beam_audit/runs`. Override the root with `--out`, the optional
`BEAM_AUDIT_OUT` environment variable, or application configuration.

```sh
mix beam_audit runs
mix beam_audit delete RUN_ID          # preview
mix beam_audit delete RUN_ID --yes    # remove that run
mix beam_audit prune --older-than 30 --keep 5
mix beam_audit prune --older-than 30 --keep 5 --yes
```

Prune combines age and count criteria. Partial/unreported runs are protected
unless `--include-partial` is explicit. Preview first; `--yes` permanently
removes the selected run records. Guarded runs and unrecognized entries are
excluded. No automatic deletion or background service.
See [Results and recovery](guides/results-and-recovery.md) for details.

## Analysis

| Component | Responsibility |
| --- | --- |
| Git | Pinned source and metadata; conservative text signals |
| ExAST | Structural queries, lexical definitions and source locations |
| Sobelow | Native security rules and diagnostics |
| Reach | Rule-directed modeled data flow, call sites and slices |
| VulnCheck | Resolved dependency advisories and optional compiled reachability |
| Agent Session Manager | Bounded semantic adjudication and challenge review |

Nontrivial Reach paths can independently generate candidates. Public security-sensitive
boundaries and explicit audit questions can also enter the queue. Native hits,
context, exclusions, review records, and coverage gaps remain traceable.
Dependency advisories are deterministic results, not model judgments.

## Integration

Use the same API from a trusted Mix project that depends on BeamAudit:

```elixir
{:ok, run} = BeamAudit.discover(["/path/to/repository"], profile: "full")
{:ok, summary} = BeamAudit.resume(run.path, max_calls: 12)
{:ok, report} = BeamAudit.report(summary.path)

# Once an earlier run is available:
# {:ok, changes} = BeamAudit.compare(old_run, summary.path)
```

The report separates source findings from dependency advisory matches. A native
reachability verdict is not a waiver, and a missing or unresolved result is not
proof of safety. Exact-fingerprint comparison helps review changes but never
claims an unobserved finding is fixed. Language and policy limitations are
reported rather than hidden. Elixir is the primary semantic target; Erlang,
Gleam and templates have limited coverage.

## Guides

- [Getting started](guides/getting-started.md)
- [Scope and safety](guides/scope-and-safety.md)
- [Workflow](guides/workflow.md)
- [Security rules](guides/security-rules.md)
- [Dependency security](guides/dependencies.md)
- [Review and evidence](guides/review-and-evidence.md)
- [Integration](guides/integration.md)
- [Results and recovery](guides/results-and-recovery.md)
- [Validation](guides/validation.md)

## License

MIT. See [LICENSE](LICENSE).
