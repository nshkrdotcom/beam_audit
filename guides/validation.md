# Validation

## Local quality checks

Run the following from the BeamAudit checkout to verify resolved tool APIs,
analysis behavior, documentation and package contents:

```sh
mix deps.get --check-locked
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix credo --strict --all
mix dialyzer
mix docs
git diff --check
package_dir=$(mktemp -d)
mix hex.build --output "$package_dir/beam_audit.tar"
```

The final v0.1.0 checks passed all 17 tests on Elixir 1.20.5 and OTP 29.
Credo 1.7.19 ran 69 checks in strict mode and reported zero issues. Dialyxir
1.4.9 reported zero Dialyzer errors and zero skips using the existing PLT.
Locked dependency resolution, formatting, compilation with warnings treated as
errors, ExDoc generation, the Git diff check and the Hex package inventory check
also passed.

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

Ten saved vulnerable/fixed source extracts completed deterministic discovery
and yielded 156 review candidates. The replayed file hashes matched the
original saved extracts. The counts describe L1 candidate discovery on these
extracts. A fixed case may still trigger the original rule. L2 grounded
violations and L3 impact evidence require broader context. See
[Security rules and coverage](security-rules.md) for the validation levels.

| Source control | Vulnerable extract candidates | Fixed extract candidates |
| --- | ---: | ---: |
| Hex (CVE-2026-129514) | 3 | 6 |
| Ash (CVE-2026-67579) | 11 | 12 |
| Ash (CVE-2026-124283) | 49 | 55 |
| DBConnection (CVE-2026-133555) | 5 | 6 |
| Flop (CVE-2026-130411) | 4 | 5 |
| **Total** | **72** | **84** |

## Live review checks

Live review consumes provider quota. Use a single bounded Codex call when a
transport check is needed, after deterministic validation. Stop on quota
exhaustion; do not automatically retry or launch bulk target reviews as part
of ordinary QA. Full audits are user-controlled operations distinct from
software development. Antigravity is optional. Mock reviewers and JSON smoke
tests do not establish the quality of security judgments.

### Current release candidate

The v0.1.0 CLI captured a two-file source-only extract of the fixed Hex decoder.
Its local extract revision was `6dfc68fbfc994b89bce5de28d3e7230ca6c68105`.
The decoder file matched upstream fix revision
`379b0a29bcc95164249f38ad7d772a37a8ff9533` byte for byte.
[Hex fix commit](https://github.com/hexpm/hexpm/commit/379b0a29bcc95164249f38ad7d772a37a8ff9533)

Separate discovery and resume invocations produced 14 native hits, six
candidates and six accepted primary decisions through ASM with Codex. The
first resume reserved three calls with one candidate per batch. The second
resumed at call four, kept concurrency at one, and used a batch of three to
leave room for follow-up and challenge work. It reached the cumulative cap of
six calls.

- Accepted primary dispositions were two `not_applicable`, one
  `verified_safe` and three `unresolved`. All six source citations matched
  the saved file, hash and cited line range.
- One candidate used two fulfilled evidence rounds and cited the retrieved
  source. Two other requests were rejected for invalid ranges.
- One required challenge remained pending at the cap. The report retained
  three unresolved candidates and recorded zero declared coverage gaps for
  the extract. A fresh CLI invocation regenerated the same report byte for
  byte with the same six call records. The initial calls and accepted
  decisions also retained their hashes across resume.

Acceptance means BeamAudit validated the structured decision and its evidence
references. The dispositions reflect the model's assessment within the
captured scope. See the [curated example report](example-report.md) for a
source-level walkthrough.

### Earlier implementation

Earlier ASM-backed Codex review of Weld, Codex SDK and Gemini Ex produced
28 accepted primary decisions across all three runs. The saved dispositions
include three `confirmed`, four `verified_safe` and 21 `unresolved`.
Nine accepted decisions used additional retrieved evidence. No challenge
decisions were accepted. Provider quota failures and timeouts left those
pre-release audits incomplete.

## 0.1.0 validation baseline

Local verification used Elixir 1.20.5 and OTP 29 with ExAST 0.12.10,
Reach 2.8.4, Sobelow 0.19.0, VulnCheck 1.0.2 and ASM 0.17.6.

The saved deterministic discovery runs used the full profile on three pinned
public repository snapshots.

| Target snapshot | Captured source files | Raw hits | Review candidates | Nonempty modeled flows | Dependency packages |
| --- | ---: | ---: | ---: | ---: | ---: |
| [Weld](https://github.com/nshkrdotcom/weld) `0f10cbd70ca6d20e8ba1a8b43b09b4fcba3db9c3` | 50 | 829 | 76 | 6 | 16 |
| [Codex SDK](https://github.com/nshkrdotcom/codex_sdk) `194b7cabc1e80ff9772a63fd83ca01ad1c2abe8f` | 190 | 1,623 | 110 | 0 | 56 |
| [Gemini Ex](https://github.com/nshkrdotcom/gemini_ex) `a284a41f53c8665f17f82d46376a4de548d5982d` | 139 | 1,155 | 120 | 10 | 36 |
| **Total** | **379** | **3,607** | **306** | **16** | **108** |

All captured source hashes matched the inventories, raw hits reconciled
against the candidate ledger, and report regeneration was byte-identical.
Thirty-seven zero-length source/sink coincidences were retained as context.
Every queued group passed source-packet construction and anchor-coverage checks.

No dependency advisories matched the three captured inventories. In a separate
control using the real cached feed, DBConnection 2.10.2 matched CVE-2026-133555
and 2.10.3 had zero matches. Comparison classified the earlier advisory as
`not_observed` in the later run. A comparison result describes how the saved
evidence changed. Remediation requires independent verification.

## Coverage limits

Four gaps remained in the three-repository runs. Reach partially modeled
source in each repository, and dynamic dependency declarations limited scope
classification in Codex SDK. Text signals can match comments and types.
Dynamic and implicit execution modeling is incomplete, and
application-specific security properties may require explicit investigation.
Candidate counts and accepted model dispositions measure workflow activity.
Detection accuracy and security conclusions require independent evidence.

Optional artifact capture selected an existing `dev` build, recording 1033
files and 0 omissions. Dependency status was `partial`. Captured artifact
hashes and sizes were checked. The native assessment requests production scope.
No applicable advisory required native graph analysis in that run. Artifact
capture does not establish build-to-revision correspondence or affected-function
reachability accuracy.

Review and recovery tests use deterministic reviewer fixtures for provider-error
pause, budget recovery, interruption recovery, challenge disagreement and
explicit reconsideration.
