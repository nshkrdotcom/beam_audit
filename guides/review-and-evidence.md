# Review and evidence

## Providers and execution

The review engine calls `ASM.query/3` using `lane: :core` and a newly created,
empty working directory inside the run, with Unix mode `0o700`. Codex is the
default and uses the completion-only structured response; Antigravity is an
alternative with locally validated JSON. An optional model override is passed
to ASM. Queue, stream and run timeouts use `deadline_ms`. The working directory
and review protocol do not constitute OS-level provider containment.

## Review packets and scheduling

A review packet contains a stable candidate, relevant security properties,
source excerpts with citable IDs, original native signals and context, and
selected Reach paths and slices. A review can investigate a native finding, a
public security-sensitive boundary or an explicit audit question. An agent does not choose the repository
set, run scanners, edit source, or establish accounting status.

New primary candidates are prioritized within each repository as follows:

1. Explicit audit questions (`owner_boundary`).
2. High-risk groups with Reach evidence.
3. Other high-risk groups.
4. Groups with native Sobelow findings.
5. Remaining candidates.

Within each tier, ordering uses path, location and candidate ID. Pending packets
with additional evidence are scheduled ahead of fresh packets. Concurrency may
change completion order. Challenge review follows the primary phase for the
repository.

## Dispositions

| Disposition | Meaning |
| --- | --- |
| confirmed | Grounded violation, trace, minimal fix and regression |
| potential | Plausible violation with stated uncertainty |
| verified_safe | Evidence-backed invariant under stated scope |
| not_applicable | Concrete explanation why the rule does not apply |
| unresolved | Insufficient or conflicting evidence |
| pending | No accepted decision yet |
| pending_challenge | Primary conclusion needs a separate challenge review |

The first five are reviewer dispositions. `pending` and `pending_challenge`
are effective report states, not values a provider can return.

## Validation and challenge review

A batch response must contain exactly the requested candidate IDs. Mechanical
validation checks the required fields and types, allowed disposition, severity
and safety-basis values, nonempty reasoning, and unique references to supplied
excerpt IDs. All conclusions except `unresolved` need citations covering every
candidate anchor. Further requirements are:

- `confirmed`: nonempty trace, remediation and regression check.
- `potential`: cited evidence and nonempty reasoning; the review prompt also
  requires an explanation of plausible exposure and uncertainty.
- `verified_safe`: nonempty trace and an allowed safety basis other than
  `not_applicable`.
- `not_applicable`: nonempty boundary explanation and safety basis
  `not_applicable`.
- `unresolved`: may request additional evidence; other dispositions may not.

These checks enforce response structure and grounding, not the truth of the
security reasoning. Severity assesses impact, not analyzer confidence.

Challenge review is required for `confirmed` or `potential` findings with
`critical` or `high` severity, and for `verified_safe` or `not_applicable`
conclusions on a high-risk group or a group with `reach` or `owner_boundary`
signals. The separate challenge call receives the recorded evidence and prior
conclusion. A disposition mismatch, or a severity mismatch on a `confirmed` or
`potential` finding, leaves the effective result unresolved.

## Evidence operations

Supported evidence requests: `read_source` (bounded path/line range),
`find_symbol` (literal fallback), `find_definition`, `find_references`,
`find_callers` (modeled call sites), `trace_flow` and `slice` (stored evidence at
an anchor). The evidence protocol does not offer arbitrary shell commands,
external paths, network requests, compilation or new audit targets. Empty native evidence is
not proof of absence. Each source excerpt is limited to 120 lines and 32,000
bytes. A review response can request at most three evidence operations; the
number of additional evidence rounds is configurable from 0 to 4 (default 2).
Batches are split when their encoded evidence JSON exceeds 120,000 bytes. An
oversized individual packet cannot be sent; this is recorded as outstanding
review work. The limit applies to evidence JSON, not the full provider prompt
or a token budget.

Additional evidence is persisted before a follow-up call; accepted decisions
are persisted independently. Provider errors halt new launches, but already
running calls may finish.

## Budgets and reconsideration

One cumulative call reservation budget is shared across repositories within a
run, including challenges and follow-up calls. Default concurrency is one. The
budget is not a dollar/token guarantee. Observed usage is reported only when
provided by ASM; missing values remain unknown. Separate runs have independent
reservation budgets but may consume the same provider quota.

`--reconsider` explicitly archives and reopens unresolved or disputed decisions
when budget remains. Accepted decisions are otherwise retained.
