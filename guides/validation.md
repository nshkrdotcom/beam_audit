# Validation

Verify the resolved tool APIs and behavior, not merely that dependency names
appear in the project. Normal local QA:

```sh
mix deps.get
mix format
mix compile --warnings-as-errors
mix test
mix docs
mix hex.build
```

Tests must not execute fixture projects, contact a provider, or require live
advisories. Use a synthetic offline native feed for version matching and
source-only fixtures for source analysis. Verify direct, piped, aliased and
imported decoder candidates, benign context, flow-derived candidates, native
failure visibility, evidence rejection, recovery and report reproduction.
Test source/dependency profile behavior and pinned dependency provenance. Mock
reviewers validate accounting and persistence only, not security judgment.

Use the five incident-related historical vulnerable/fixed source pairs from the
research to check the original security properties. Small faithful source
extracts are appropriate for L1 controls; broader context is needed for L2/L3.
Check legitimate variants as well. Avoid live exploits, target compilation,
large research benchmarks or additional analyzer integration unless a concrete
missing capability justifies it.

Live review consumes provider quota. Existing real Codex records can establish
that the transport worked. Do not start all target reviews as part of ordinary
QA. If necessary, use one bounded Codex call after deterministic validation;
never retry automatically on quota exhaustion. Full audits are owner-controlled
operations distinct from software development. Antigravity is not required for
release QA. Do not infer provider quality from a mock or a JSON smoke test.

## Initial implementation validation

Development verification used Elixir 1.20.5 and OTP 29 with ExAST 0.12.10,
Reach 2.8.4, Sobelow 0.19.0, VulnCheck 1.0.2 and ASM 0.17.6.

Three explicitly pinned repositories were scanned with the combined profile:

| Repository | Review groups | Nonempty modeled paths |
| --- | ---: | ---: |
| weld | 76 | 6 |
| codex_sdk | 110 | 0 |
| gemini_ex | 120 | 10 |

The revised selection policy reduced the combined queue from 616 to 306
groups. All queued raw hits reconciled, and repeated report rendering was
byte-identical. Thirty-seven zero-length source/sink coincidences were
retained as context. Every queued group passed source-packet construction
and anchor-coverage checks.

No dependency advisories matched the three captured inventories. This is
not a guarantee that their dependencies are secure. A separate real cached
feed control reported CVE-2026-133555 for DBConnection 2.10.2 but not
2.10.3. Comparison correctly classified the earlier advisory as not
observed in the later run, rather than declaring a verified remediation.

Four coverage gaps remained: three partial Reach source models and
incomplete dependency-scope classification for the dynamic declarations
in codex_sdk. Native warnings and limitations remain in the run records.

Ten previously saved source extracts covering the five incident-related
vulnerable/fixed pairs were replayed after verifying their saved source
hashes. All completed deterministic discovery, yielding 156 review groups.
These are L1 candidate-discovery controls, not full upstream project scans
or independently reverified upstream provenance. No L2/L3 security
judgment or vulnerability detection rate is established by this experiment.

Optional artifact capture selected an existing `dev` build, recording 1033 files and 0 omissions. Dependency status was `partial`. Captured artifact hashes and sizes were checked. The native assessment requests production scope. Artifact capture does not establish build-to-revision correspondence or affected-function reachability accuracy.

Twenty-eight previously accepted primary review records remained readable.
The revised review and recovery machinery was exercised with deterministic
reviewer fixtures, including provider-error pause, budget recovery,
interruption recovery, challenge disagreement and explicit reconsideration.

No additional live provider calls were made during this validation.
The expanded security policy's live adjudication quality remains unmeasured.

Remaining limitations include textual documentation/type matches, incomplete
dynamic and implicit execution modeling, and application-specific security
properties requiring explicit investigation. These limitations must not
be interpreted as verified-safe decisions.
