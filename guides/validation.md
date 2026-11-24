# Verification and release gates

## Verification sequence

```sh
mix deps.get --check-locked
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix docs
mix hex.build
```

Do not treat passing a synthetic review test as a measurement of provider
security judgment. The tests exercise actual Git snapshots and analyzer
contracts plus a deterministic reviewer fixture for persistence and scope. Run
real positive and benign controls through native analyzers before trusting
candidate selection or semantic enrichment. Verify parse failure and unavailable
scanner handling, native result parsing and umbrella application behavior. Confirm
that no target code executes, including target `mix.exs` and macros.

Reach analyzes the pinned Elixir inputs. Erlang inputs remain visible in
coverage because the upstream Erlang preprocessor can follow external includes.

## Provider gate

Qualify the exact ASM/provider version using its supported containment and
completion interface. On a harmless synthetic workspace, establish that a
reviewer cannot read a neighboring repository, invoke arbitrary tools or write
source, not just that it promises not to. Verify strict structured output,
finite deadlines and actual evidence-reference validation. Codex completion-only
as documented is read-only; it does not prove read containment. If ASM cannot
provide the needed boundary, stop that integration and retain the deterministic
pipeline. No fallback to a raw CLI, extra agent SDK, general agent framework or
new sandbox infrastructure. Antigravity requires its own qualified equivalent.

## Operational evaluation

Run against Weld first at the recorded commit. Preserve the old textual scan as
a baseline. Deliberately interrupt after a saved batch; verify resume, no
re-review of accepted IDs, and byte-identical report regeneration from unchanged
records. Then run the same workflow against codex_sdk and gemini_ex. Record
raw hit counts, queued groups, accepted decisions, pending and unresolved counts,
scanner gaps, token/cost metadata and human review effort. Judge utility by
actual grounded findings and remediation decisions, not number of generated
reports. Historic pre/post CVE pairs are separate validation fixtures; they are
not extra targets in an operational audit.

The separate Phase 2 handoff contains exact acceptance criteria, known interface
uncertainties, historical revision references and the GitHub setup instructions.
