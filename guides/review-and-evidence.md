# Agentic review and evidence

BeamAudit delegates semantic security judgment only. Deterministic discovery,
file classification, source extraction, analyzer invocation, batching, candidate
identity, coverage accounting and report rendering do not use a model.

## Provider contract

Live review is blocked. ASM 0.17.6 and CLI Subprocess Core 0.10.1 support Codex
completion-only and structured output. The generated Codex invocation uses a
read-only sandbox, and its core profile lacks a host-read allowlist and a shell
tool prohibition. Antigravity lacks equivalent completion-only and structured
output support on the checked profile. The local check built a synthetic Codex
core invocation without launching a provider. Other execution surfaces and
live containment remain unverified. While the qualification list is empty,
`resume` records the blocker and renders the stored run.

The review code calls `ASM.query/3` after the provider gate passes. It requests
structured output and a finite deadline and uses the cumulative call budget.
Before adding a qualification entry to `priv/asm_boundary.json`, bind verified
containment to the invocation and verify the exact provider stack. The current
gate matches provider and ASM version and is insufficient on its own to
establish containment.

## Adjudication input and output

Each candidate packet contains the rule, all originating signals, bounded source
ranges with immutable evidence IDs, and selected modeled Reach flows. The model
returns exactly one result per submitted candidate. Invalid, duplicate or missing
IDs reject the response; unknown evidence references reject the corresponding
decision. Every non-unresolved verdict must cite source evidence covering its
candidate anchor(s). References identify supplied excerpts rather than arbitrary
strings that happen to look like `file:line`.

| Disposition | Meaning |
| --- | --- |
| `confirmed` | Grounded first-party invariant violation with trace, proposed fix and harmless regression check |
| `potential` | Plausible security issue with stated uncertainty |
| `verified_safe` | Evidence-backed safe conclusion for the candidate and stated boundary; not a proof of entire repository safety |
| `unresolved` | Insufficient or contradictory evidence |
| `pending` | No accepted primary review; never a safety conclusion |
| `pending_challenge` | Primary review saved; consequential conclusion not yet accepted as final |

Schema validation verifies the shape and provenance, not the truth of the
reasoning. A safe-basis enum is not itself a proof. Challenge review is required
for safe conclusions on the incident-family rules and high/critical confirmed or
potential findings. Material disposition/severity disagreement remains unresolved.
The challenge prompt asks for an independent analysis before comparing the prior
conclusion; it is not a statistically independent benchmark.

## Bounded evidence feedback

Only an unresolved response may request further evidence. The host supports:

- `read_source`: relative file path plus bounded first/last lines from the same
  pinned inventory.
- `find_symbol`: literal string lookup within that inventory, with a bounded
  number of returned excerpts and explicit truncation.

No model-supplied shell, regex program, external path, dependency checkout,
network operation, compiler call, or new audit target is accepted. At most three
requests per candidate response are allowed. More than the configured evidence
round limit yields an unresolved disposition. Rejected requests are recorded.
The next ASM call receives only the affected groups and additional evidence.

The run budget counts calls, not promised dollar cost. Actual provider token and
cost metadata are stored where exposed. Model outputs vary between executions.
Reproducibility means frozen inputs, replayable evidence and stored decisions,
not identical new model judgments.
