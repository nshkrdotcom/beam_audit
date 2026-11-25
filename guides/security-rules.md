# Security rules and coverage

`priv/rules.json` contains the versioned source policy, combining BEAM-specific
security properties with native Sobelow rules. Source and sink names are
hypotheses, not declarations that values are hostile or operations vulnerable.

The validation levels used in these guides distinguish:

- **L1 — Candidate discovery:** locate a relevant signal or investigation anchor.
- **L2 — Grounded violation:** establish the broken invariant and affected path.
- **L3 — Impact evidence:** substantiate the security consequence under a
  realistic input and authority model.

Queued L1 signals are review obligations, not proven vulnerabilities. These levels are
validation concepts, not additional runtime dispositions.

## Security properties

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

## Candidate selection

Direct candidate rules enter review. `P03` is a derived recursive-validation
property, not a standalone text query; review packets for `P01` and `P02`
include the `P03` and `P04` invariants. `CTX` records ordinary textual signals
such as enumeration, inspection, logging, decoding and query terms as context,
not independent vulnerability predicates.

The Reach `flow_profiles` associate `P04`–`P12` with three source families:

| Source family | Properties | Example source hypotheses |
| --- | --- | --- |
| `representation` | P04 | External term and cursor decoding |
| `external` | P05–P10, P12 | Decoding, request input, file reads, environment values |
| `sensitive` | P11 | Environment, token, secret and password access |

Nontrivial modeled flows can generate their own candidates. Sensitive `P09`,
`P10` and `P11` operations at public function boundaries enter review under
their respective properties. Public `approve`, `approve!`, `authorize` and
`authorize!` functions can independently queue `P12` investigations. Generic
OTP callbacks, broad entrypoint names and other selected boundary signals are
retained as `entrypoint_inventory` context unless independently promoted.
Explicit audit questions can queue `P12` investigations for application-specific
authorization and business invariants. Context-only classification is a
review-selection decision, never a verified-safe conclusion.

## Native rule consolidation

Known equivalent Sobelow rules are normalized using native SARIF rule names.
Original rule IDs and messages remain in the raw ledger; equivalent signals at
the same investigation scope can share a group.

| Native Sobelow rule names | Property |
| --- | --- |
| `Misc.BinToTerm` | P01 |
| `RCE.CodeModule`, `RCE.EEx`, `RCE.System`, `CI.System` | P05 |
| `SQL.Query` | P06 |
| `DOS.BinToAtom`, `DOS.StringToAtom`, `DOS.ModuleConcat` | P07 |
| `Traversal.FileModule` | P09 |

Other rules retain their `SOBELOW:<id>` identity. Ordinary filesystem signals
have medium review priority; this does not limit the severity of an established
filesystem vulnerability.

## Coverage limits

`[:safe]`, non-executable decoding and struct checks cannot independently
establish application safety. Missing paths cannot establish safety.

ExAST uses native structural matching with host import expansion disabled; bare
imports, captures and other unresolved spellings may rely on textual signals.
Definition and module names are lexical; generated code and dynamic dispatch
are not exhaustively modeled. Reach provides source graph paths and bounded
slices, not feasible-path proof. Zero-length source/sink coincidences
remain context rather than evidence of traversed data flow. Native Erlang
semantic analysis is not enabled because includes could follow paths outside
the snapshot. Erlang, Gleam and templates therefore have limited textual
coverage. Caps, unsupported files, parse failures and other coverage gaps
remain visible. The catalogue is not an
exhaustive CWE or EEF advisory mapping.

## Rule development

Rule changes should identify a concrete invariant, relevant native checks,
representative vulnerable and legitimate inputs, and a measurable improvement.
For historical controls, evaluate L1, L2 and L3 separately. A fixed case may
retain its L1 hit; candidate counts alone do not measure detection accuracy.

References: [EEF CNA](https://cna.erlef.org/cves/),
[EEF serialization guidance](https://security.erlef.org/secure_coding_and_deployment_hardening/serialisation.html),
[ExAST](https://ex-ast.hexdocs.pm/), [Reach](https://reach.hexdocs.pm/),
[Sobelow](https://sobelow.hexdocs.pm/).
