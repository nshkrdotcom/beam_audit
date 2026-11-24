# Review and evidence

The review engine calls `ASM.query/3`. Codex uses the supported completion-only
structured response; Antigravity remains an alternative with locally validated
JSON. Provider/model selection is explicit. Queue, stream and run timeouts use
the configured deadline. No artificial provider qualification gate is used.

A review packet contains a stable candidate, relevant security properties,
source excerpts with citable IDs, original native signals and context, and
selected Reach paths/slices. Review can ask about a deterministic finding or a
public/owner-specified security boundary. An agent does not choose the repository
set, run scanners, edit source, or establish accounting status.

| Disposition | Meaning |
| --- | --- |
| confirmed | Grounded violation, trace, minimal fix and regression |
| potential | Plausible violation with stated uncertainty |
| verified_safe | Evidence-backed invariant under stated scope |
| not_applicable | Concrete explanation why the rule does not apply |
| unresolved | Insufficient or conflicting evidence |
| pending | No accepted decision yet |
| pending_challenge | Primary conclusion needs independent challenge |

Mechanical validation checks IDs, citations and decision fields. It cannot
prove security reasoning. High-impact findings and consequential safe or
non-applicable dismissals get a challenge. Material disagreement remains
unresolved.

Supported evidence requests: `read_source` (bounded path/line range),
`find_symbol` (literal fallback), `find_definition`, `find_references`,
`find_callers` (modeled call sites), `trace_flow` and `slice` (stored evidence at
an anchor). No arbitrary shell, external paths, network, compiler, or new audit
target. Empty native evidence is not proof of absence. The host caps excerpts,
rounds, and packet size. Evidence is persisted before a follow-up; accepted
decisions are persisted independently. Provider errors halt new launches.

One cumulative call reservation budget is shared across repositories within a
run, including challenges and follow-up calls. Default concurrency is one. The
budget is not a dollar/token guarantee. Observed usage is reported only when
provided by ASM; missing values remain unknown. Do not start several independent
runs to get around quotas. `--reconsider` explicitly archives and reopens
unresolved or disputed decisions, subject to the remaining call budget.
