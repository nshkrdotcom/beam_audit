# Validation

## Local quality checks

Run the following from the BeamAudit checkout to verify resolved tool APIs,
analysis behavior, documentation and package contents:

```sh
mix deps.get
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix docs
mix hex.build
```

Normal tests must not execute fixture projects, contact a provider or require
live advisories. Use a synthetic offline native feed for version matching and
source-only fixtures for source analysis. Verify direct, piped, aliased and
imported decoder candidates, benign context, flow-derived candidates, native
failure visibility, evidence rejection, recovery and report reproduction.
Test source/dependency profile behavior and pinned dependency provenance. Mock
reviewers validate accounting and persistence only, not security judgment.
Use disposable results roots for all lifecycle tests. Verify root precedence,
read-only listing, age/count retention, partial protection, explicit deletion,
unknown/symlink entry refusal, guard contention, release on failure and
zero-call resume. Do not point destructive QC at real saved runs.

## Historical source controls

The source policy references the following incident-related advisories from the
Erlang Ecosystem Foundation (EEF) CNA:

| Advisory | Affected project |
| --- | --- |
| [CVE-2026-129514](https://cna.erlef.org/cves/CVE-2026-129514.html) | Hex |
| [CVE-2026-67579](https://cna.erlef.org/cves/CVE-2026-67579.html) | Ash |
| [CVE-2026-124283](https://cna.erlef.org/cves/CVE-2026-124283.html) | Ash |
| [CVE-2026-133555](https://cna.erlef.org/cves/CVE-2026-133555.html) | DBConnection |
| [CVE-2026-130411](https://cna.erlef.org/cves/CVE-2026-130411.html) | Flop |

Use pinned vulnerable/fixed source pairs and legitimate variants to assess the
relevant properties. Small faithful extracts are useful for L1 candidate
discovery; broader context is needed for L2 grounded violations and L3 impact
evidence. A fixed case may still trigger the original rule. See
[Security rules and coverage](security-rules.md) for the validation levels.
Candidate counts alone are not vulnerability detection rates. Use harmless
regression controls rather than live exploits.

## Live review checks

Live review consumes provider quota. Use a single bounded Codex call when a
transport check is needed, after deterministic validation. Stop on quota
exhaustion; do not automatically retry or launch bulk target reviews as part
of ordinary QA. Full audits are user-controlled operations distinct from
software development. Antigravity is optional. Mock reviewers and JSON smoke
tests do not establish the quality of security judgments.

## 0.1.0 validation baseline

Local verification used Elixir 1.20.5 and OTP 29 with ExAST 0.12.10,
Reach 2.8.4, Sobelow 0.19.0, VulnCheck 1.0.2 and ASM 0.17.6. The release
candidate passed 16 regression tests, compilation with warnings treated as
errors, formatting, documentation generation and Hex package inventory checks.
Storage CLI checks covered root precedence, read-only listing, deletion and
pruning, guard protection, zero-call resume, and report reproduction.

Deterministic discovery was exercised on three pinned internal pre-release
repository snapshots using the combined profile. These measurements describe those inputs,
not a public benchmark or a representative population of BEAM applications.

| Target snapshot | Review groups | Nonempty modeled paths |
| --- | ---: | ---: |
| A | 76 | 6 |
| B | 110 | 0 |
| C | 120 | 10 |
| Total | 306 | 16 |

All queued raw hits reconciled, and repeated report rendering was byte-identical.
Thirty-seven zero-length source/sink coincidences were retained as context.
Every queued group passed source-packet construction and anchor-coverage checks.

No dependency advisories matched the three captured inventories. This is
not a guarantee that their dependencies are secure. A separate real cached
feed control reported CVE-2026-133555 for DBConnection 2.10.2 but not
2.10.3. Comparison correctly classified the earlier advisory as not
observed in the later run, rather than declaring a verified remediation.

Four coverage gaps remained: three partial Reach source models and incomplete
dependency-scope classification for dynamic declarations in target B. Native
warnings and limitations remain in the run records.

Ten saved source extracts covering the five advisory-related vulnerable/fixed
pairs listed above were replayed after verifying their saved source hashes. All
completed deterministic discovery, yielding 156 review groups. These are L1
candidate-discovery controls, not full upstream project scans or independently
reverified upstream provenance. They do not establish L2/L3 security judgments
or vulnerability detection rates.

Optional artifact capture selected an existing `dev` build, recording 1033
files and 0 omissions. Dependency status was `partial`. Captured artifact
hashes and sizes were checked. The native assessment requests production scope.
No applicable advisory required native graph analysis in that run. Artifact
capture does not establish build-to-revision correspondence or affected-function
reachability accuracy.

Review and recovery were exercised with deterministic reviewer fixtures,
including provider-error pause, budget recovery, interruption recovery, challenge
disagreement and explicit reconsideration. A live Codex transport check was
performed during pre-release development, but not repeated during this
validation. Live adjudication quality under the current policy remains unmeasured.

Remaining limitations include textual documentation/type matches, incomplete
dynamic and implicit execution modeling, and application-specific security
properties requiring explicit investigation. These limitations must not
be interpreted as verified-safe decisions.
