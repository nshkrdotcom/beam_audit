# Scope and safety

## Repository and snapshot scope

Each target must be the Git repository root, not a subdirectory. BeamAudit
resolves the requested revision (default `HEAD`) to a commit once. Uncommitted
and untracked files are not included. Place the results root outside all audited
repositories. Git blob reads avoid worktree symlinks and filters; the scanner
does not execute target Mix configuration, macros, tests or application startup.
The tools and repository metadata are assumed to be trusted local inputs, not
a hostile OS environment.

The source inventory includes regular tracked files with these extensions:

- Elixir: `.ex`, `.exs`; templates: `.eex`, `.heex`, `.leex`.
- Erlang: `.erl`, `.hrl`; Gleam: `.gleam`.

Path components named `.git`, `deps`, `_build`, `vendor`, `vendored`,
`node_modules` or `.beam_audit` are outside source scope. By default, `test`,
`tests`, `test_support`, `fixtures`, `example`, `examples`, `bench` and
`benchmarks` are also excluded. Use `--include-tests` or repository-specific
`include_tests` to include the latter group. Symlink and gitlink entries are
not materialized. Use repository-specific `exclude` for other vendored or
out-of-scope paths.

Files exceeding `max_file_bytes`, unsupported source encodings and other
omissions are recorded in the inventory. On Unix, run directories are created
with mode `0o700` and captured source files with mode `0o400`. BeamAudit verifies
SHA-256 digests when reading source through its snapshot interface and when
validating stored runs. These checks do not make a hostile host trustworthy.

## Dependencies and compiled artifacts

Dependency metadata is captured separately from the source tree. The native
scanner uses committed lockfiles and static declarations. External/unavailable
Mix path references trigger conservative lock-only assessment rather than
following a neighboring checkout. Path/git packages may lack applicable feed
coverage; do not confuse lack of matches with safety. Existing build artifact
capture is explicit (`--compiled`) and limited to regular `.beam` and `.app`
files in supported build layouts. Symlinked artifacts and path components are
excluded. Capture is capped
at 64 MiB per file, 512 MiB total and 20,000 files per repository. It never
compiles a target. Artifact provenance is weaker than pinned source. See
[Dependency security](dependencies.md) for metadata and artifact details.

## Review boundary

Review receives bounded packets of source evidence. Its allowed evidence
operations read only recorded source and analysis facts. The runner validates
locations, citations and decisions and rejects requests for other repositories.
ASM manages trusted local provider execution and provider permissions. The
bounded evidence interface constrains BeamAudit's review requests; it does not
provide OS-level containment of provider processes.

## Confidentiality and remediation

Reports, prompts, provider output and snapshots may contain confidential code.
Use only authorized providers and repositories. Deleting a local run does not
control provider retention. The results root is configurable; explicit deletion
and pruning remove whole local runs. Do not perform direct filesystem cleanup
of active runs. Source and native analyzer output are untrusted model
input. Mechanical evidence validation does not prove semantic correctness.
BeamAudit makes no source changes. Remediation is a separate owner-approved task.
