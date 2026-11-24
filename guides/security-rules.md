# Security rules and coverage

The initial version implements a small incident-family rule catalogue in
`priv/rules.json`. It is a first-party candidate policy, not a complete CWE or
CVE catalogue. The rule metadata includes upstream advisory/guidance links as
research provenance. These rules require semantic assessment before findings
are accepted. Historical pre/post patch validation is a release gate.

| ID | Invariant | Discovery |
| --- | --- | --- |
| P01 | External data must not reconstruct unvalidated internal terms | ETF decoders, cursor/keyset-related calls |
| P02 | A struct tag is not a field invariant | Construction, struct tags, casts, custom type signals |
| P03 | Recursive validation must cover nested keys and values, lists, tuples and fields | Attached to P01/P02 producer/consumer reviews; not a separate regex |
| P04 | External representation must not select unexpected protocol behavior | Explicit protocol implementations and consumers; rejection paths considered in review |
| P05 | Data must not choose executable authority without trusted resolution | Dynamic apply, eval/compile, callbacks and command execution signals |
| P06 | Untrusted input must remain a literal, not an executable query expression | Fragments, SQL query entrypoints, Ash expression/filter signals |
| P07 | Input must not cause unbounded permanent atom creation | Atom-creating APIs and module concatenation |
| CTX | Context, not an independent security assertion | Ordinary decode, enumerate, inspect, logging, query and dynamic words |
| SOBELOW:* | Existing first-party security rules | Native Sobelow findings, without the historical dependency advisory category |

`[:safe]` constrains some ETF features but does not enforce application-level
schema invariants. Plug.Crypto's non-executable decoding cannot by itself
establish safe downstream protocol dispatch. Both are always reviewable
representation boundaries. A fixed implementation may legitimately retain the
same L1 hit as its vulnerable predecessor. `Module.safe_concat/1,2` is not
included as an atom-creation predicate. Literal JSON parsing is not treated as
ETF decoding or code execution merely because the function is named `decode`.

## How matching works

The Git pass searches textual API spellings, including references in comments
and strings. ExAST matches native structural patterns and supplies function
ranges where available. It does not evaluate macros or load target imports.
No claim is made that captures, all dynamic aliases, arbitrary wrappers,
framework DSLs, all protocol consumers or recursive validation are exhaustively
resolved. Reach contributes modeled flow paths, including decoder-to-consumer
signals; it does not prove a source is hostile or a path feasible. There is no
automatic sanitizer whitelist. `CTX` rows are retained but not agent tasks.

Do not add generic regexes merely to enlarge hit counts. Add a rule only with a
specific invariant, representative vulnerable and legitimate inputs, a known
coverage limitation, and evidence that existing checks do not already cover the
requirement. Verify native query syntax and alias/pipeline variants against the
installed tool versions. Do not penalize a safe pair for retaining an L1 match.

## Reference material

- [EEF vulnerability index](https://cna.erlef.org/cves/)
- [EEF serialization guidance](https://security.erlef.org/secure_coding_and_deployment_hardening/serialisation.html)
- [ExAST pattern and querying documentation](https://ex-ast.hexdocs.pm/)
- [Reach source and project analysis](https://reach.hexdocs.pm/)
- [Sobelow checks and options](https://sobelow.hexdocs.pm/)

The handoff lists the five historical incident-family cases and paired-revision
validation. Do not report those cases as executed in this initial delivery.
