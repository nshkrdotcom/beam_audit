# Dependency security

The default `full` profile includes native VulnCheck assessment. The independent
`dependencies` profile omits source discovery and model calls.

```sh
mix beam_audit ~/projects/weld --profile dependencies
mix beam_audit ~/projects/weld --profile dependencies --offline
mix beam_audit ~/projects/weld --profile dependencies --compiled
```

BeamAudit captures committed Mix, Rebar and Gleam metadata separately from
source. VulnCheck reads the captured workspace and performs native advisory
matching, package scope classification, and optional compiled reachability.
The lock-only fallback for unresolved or external Mix path references reuses
VulnCheck's native lock parser, feed matcher and solver; it does not inspect the
external dependency source. Production scope is conservative in that fallback.
No target config is evaluated and no dependency is fetched or compiled.

A missing lockfile is a coverage gap, not evidence of safe requirements. Mix
requirements are inventoried where statically parsed, not exhaustively checked
against every permissible consumer version. Library consumers can resolve
versions different from the library's own lockfile. Unsupported or non-Hex
sources, feed failures, retirement-cache warnings, and unresolved path references
remain visible. Advisory matching is a known-vulnerability check, independent
from source review. Native reachability classifications do not hide advisories.

`--compiled` copies selected existing regular `.beam` and `.app` artifacts from
usual build layouts, records hashes and omissions, and permits native scanner
reachability analysis when applicable. A local artifact is not proven to
correspond to the pinned commit, lockfile or deployed build. Do not claim it is.
Without artifacts the version matching still runs and missing reachability is
explicit. Native OTP information describes the scanner host unless otherwise
configured upstream; deployment inventory is a separate question.

The native JSON document, feed provenance, package inventory, declarations and
capture hashes are retained in `rNNN/dependencies.json`. No auto-suppression or
model calls are involved. Existing feed caches are managed by VulnCheck, not
another downloader or database. See [VulnCheck](https://github.com/Voskan/vulncheck).
