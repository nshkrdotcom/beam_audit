# Security rules and coverage

`priv/rules.json` contains the versioned source policy. Preserve the original
incident-family controls and reuse native Sobelow rules. L1 signals are review
obligations, not proven vulnerabilities. Source and sink names are hypotheses,
not declarations that values are hostile or that operations are vulnerable.

| Property | Investigation |
| --- | --- |
| P01 | External term decoding and internal representations |
| P02 | Struct identity versus actual field invariants |
| P03 | Recursive validation of keys, values, tails, fields and tuples |
| P04 | Implicit protocol dispatch and rejection/error paths |
| P05 | Dynamic executable authority, evaluation and commands |
| P06 | Values versus executable query/DSL expressions |
| P07 | Unbounded atom creation |
| P08 | Resource and decompression bounds |
| P09 | Filesystem authority and externally selected paths |
| P10 | Network destination control |
| P11 | Sensitive information disclosure |
| P12 | Public entrypoints, callbacks and authority boundaries |
| P13 | Insecure transport and randomness choices |

Direct high-risk signals become candidates. Ordinary decode, logging, file,
network and state operations may remain context; modeled flows or sensitive
public entrypoints can promote them into review. Explicit owner questions cover
application-specific authorization and business invariants without a new DSL.

Generic OTP callbacks and broad entrypoint names are retained as context,
not automatically treated as separate security investigations. Sensitive
operations at public boundaries are grouped under their relevant properties.
Explicit approval/authorization entrypoints, owner questions and nontrivial
modeled flows can independently create candidates. Context-only classification
is a review-selection decision, never a verified-safe conclusion.

Known equivalent Sobelow rules are normalized using their native SARIF rule
names. Original rule IDs and messages remain in the raw ledger. Ordinary
filesystem signals have medium review priority; this does not limit the
severity of an established filesystem vulnerability.
`[:safe]`, non-executable decoding and struct checks cannot independently
establish application safety. Missing paths cannot establish safety.

ExAST uses native structural matching with host import expansion disabled; bare
imports, captures and other unresolved spellings may rely on textual signals.
Definition and module names are lexical; generated code and dynamic dispatch
are not exhaustively modeled. Reach provides source graph paths and bounded
slices, not feasible-path proof. Zero-length source/sink coincidences
remain context rather than evidence of traversed data flow. Native Erlang semantic analysis is not enabled
because includes could follow paths outside the snapshot. Erlang, Gleam and
templates therefore have limited textual coverage. Caps, unsupported files,
parse failures and other coverage gaps remain visible. The catalogue is not an
exhaustive CWE or EEF advisory mapping.

Add or change a rule only with a concrete invariant, relevant existing native
checks, a representative vulnerable and legitimate input, and a measurable
improvement. No generic regex just to increase counts. For historical controls,
measure candidate discovery (L1), grounded violation (L2), and impact evidence
(L3) separately. A fixed case may retain its L1 hit.

References: [EEF CNA](https://cna.erlef.org/cves/),
[EEF serialization guidance](https://security.erlef.org/secure_coding_and_deployment_hardening/serialisation.html),
[ExAST](https://ex-ast.hexdocs.pm/), [Reach](https://reach.hexdocs.pm/),
[Sobelow](https://sobelow.hexdocs.pm/).
