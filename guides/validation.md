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
