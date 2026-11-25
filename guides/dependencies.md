# Dependency security

## Profiles and modes

The default `full` profile includes native VulnCheck assessment. The independent
`dependencies` profile omits source discovery and model calls.

```sh
mix beam_audit ~/projects/my_app --profile dependencies
mix beam_audit ~/projects/my_app --profile dependencies --offline
mix beam_audit ~/projects/my_app --profile dependencies --compiled
```

## Metadata capture and advisory matching

BeamAudit captures committed metadata separately from source: `mix.exs`,
`rebar.config`, `gleam.toml`, `mix.lock`, `rebar.lock`, `manifest.toml`,
`*.app.src`, and `.exs` files under a `config/` path component (including
nested applications). Repository scope, encoding and file-size limits apply.
Project roots are inferred from captured manifests and lockfiles. Conventional
Mix umbrella children under `apps/*` without their own lockfile belong to the
enclosing locked workspace; independently locked nested projects are assessed
separately.

VulnCheck reads the captured workspace and performs native advisory matching,
package scope classification and optional compiled reachability. The normal
native scan requests `env: :prod`, `show_unreachable: true`, `fail_on: :none`
and `ignore: false`. Matching advisories are retained even when native
reachability is negative or uncertain.

## Fallbacks and coverage limits

The lock-only fallback for unresolved or external Mix path references reuses
VulnCheck's native lock parser, feed matcher and solver; it does not inspect the
external dependency source. Production scope is conservative in that fallback.
No target config is evaluated and no dependency is fetched or compiled.

Dynamic Mix declarations can limit dependency-scope classification. The native
scanner may conservatively treat locked packages as production dependencies.
A missing lockfile is a coverage gap, not evidence of safe requirements. Mix
requirements are inventoried where statically parsed, not exhaustively checked
against every permissible consumer version. Library consumers can resolve
versions different from the library's own lockfile. Unsupported or non-Hex
sources, feed failures, retirement-cache warnings, and unresolved path references
remain visible. Advisory matching is a known-vulnerability check, independent
from source review. Native reachability classifications do not hide advisories.

## Existing compiled artifacts

`--compiled` copies selected existing regular `.beam` and `.app` artifacts from
these build layouts relative to each selected project root:

- `_build/*/lib/*/ebin/*`
- `_build/*/lib/*/consolidated/*`
- `build/*/erlang/*/ebin/*`

Files with symlinked path components are not copied. Per-repository limits are
64 MiB per file, 512 MiB in total and 20,000 files. Hashes and omissions are
recorded. Native reachability analysis runs when applicable; capturing artifacts
alone does not establish that the native graph analysis ran. Local artifacts
are not proven to correspond to the pinned commit, lockfile or deployed build.
Without artifacts the version matching still runs and missing reachability is
explicit. Native OTP information describes the scanner host unless otherwise
configured upstream; deployment inventory is a separate question.

## Stored results

| Status | Meaning |
| --- | --- |
| `completed` | Assessment completed under the captured scope; not a safety verdict |
| `partial` | Incomplete inputs, applicable warnings, failed projects or artifact coverage limits |
| `not_applicable` | No supported project roots found |
| `not_requested` | Source-only profile |
| `failed` | Dependency stage or individual project failed |

A missing dependency record is reported as `not_captured` and counted as a
coverage gap. Inspect project-level statuses and native diagnostics as well as
the repository-level result.

The native JSON document, feed provenance, package inventory, declarations and
capture hashes are retained in `rNNN/dependencies.json`. No auto-suppression or
model calls are involved. Existing feed caches are managed by VulnCheck, not
another downloader or database. See [VulnCheck](https://github.com/Voskan/vulncheck).
