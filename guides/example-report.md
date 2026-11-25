# Example report

## Hex decoder source review

This excerpt summarizes a saved BeamAudit v0.1.0 run against two files from a
pinned Hex source extract. The decoder matched the upstream fix for
CVE-2026-129514 byte for byte. The upstream incident report establishes the
historical vulnerability. This run examined the fixed decoder within the
captured scope.
[Hex incident report](https://hex.pm/blog/security-incident-on-hexpm) ·
[Pinned decoder source](https://github.com/hexpm/hexpm/blob/379b0a29bcc95164249f38ad7d772a37a8ff9533/lib/hexpm_web/erlang_format.ex)

Discovery recorded 14 native hits and six candidates. Codex via ASM used six
calls and produced six accepted primary decisions with verified source
references. Three candidates remained unresolved and one awaited challenge
review. The table summarizes four of the recorded decisions.

| Discovery signal | Candidate and security property | Cited source and accepted primary decision |
| --- | --- | --- |
| Git text match at line 14 | P01, external term validation | Lines 1–27 show that the flagged clause returns a fixed error before the decoding clause can run. `not_applicable` for that clause. A challenge was required and remained pending. |
| ExAST structural match and Git text match at line 18 | P01, external term validation | Lines 6–30 show the decode call and its entry and return branches. The initial packet lacks the recursive helper and downstream caller context. `unresolved`. |
| Git text match on the rescue message at line 27 | P01, external term validation | The retrieved file shows the recursive struct-marker check and the fixed error on `ArgumentError`. The caller search yielded zero modeled matches within the extract. Input authority, upstream limits and downstream use remained uncertain. `unresolved`. |
| Git text match on the struct-marker check at line 34 | P02, reconstructed struct identity | Lines 21–42 show that the check rejects tagged maps before enumeration and recurses into map keys and values, list heads and tails, and tuple elements. The reviewer recorded `verified_safe` for this scoped check. |

Line references point to `lib/hexpm_web/erlang_format.ex` in the saved snapshot.
BeamAudit verified each cited excerpt against the captured file and its
SHA-256 digest.

## Evidence retrieval

For the line 27 candidate, the first request looked for modeled callers of
`HexpmWeb.ErlangFormat.decode/1`. BeamAudit returned an empty modeled result
with a coverage note. A follow-up asked for a symbol search and the complete
decoder file. The next response cited that file, including the recursive
helper, and remained unresolved at the configured evidence-round limit.
Two other candidates requested line ranges outside the snapshot. BeamAudit
rejected those requests and recorded the decisions as unresolved.

## Scope and follow-up

The run covered the pinned decoder extract in the source profile. HTTP routing,
request limits, callers outside the extract, dependency internals and advisory
matching were outside scope. The report made no new source findings. The
remaining caller question would require pinned endpoint and parser context.

A regression check for the public fix could verify that the decoder rejects
plain nested maps containing a struct marker and still accepts ordinary nested
terms. This run recorded source evidence and performed no target execution.

See the [validation guide](validation.md) for the run-level results.
