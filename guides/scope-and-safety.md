# Scope and safety

The target is an explicit repository root and immutable Git commit. HEAD is
resolved once. Uncommitted and untracked files are not included. Git blob reads
avoid worktree symlinks and filters; the scanner does not execute target Mix
configuration, macros, tests, or application startup. The tools and repository
metadata are assumed to be trusted local inputs, not a hostile OS environment.

Source snapshots include regular Elixir, Erlang, Gleam and template files
selected by policy. Test/example trees are excluded by default; dependency,
build, vendor, symlink and gitlink entries are excluded. Other vendored source
requires explicit exclusion. The inventory records omissions and reasons.

Dependency metadata is captured separately from the source tree. The native
scanner uses committed lockfiles and static declarations. External/unavailable
Mix path references trigger conservative lock-only assessment rather than
following a neighboring checkout. Path/git packages may lack applicable feed
coverage; do not confuse lack of matches with safety. Existing build artifact
capture is explicit and limited to regular files in usual build layouts; it
never compiles a target. Artifact provenance is weaker than pinned source.

Review receives bounded packets of source evidence. Its allowed evidence
operations read only recorded source and analysis facts. The runner validates
locations, citations and decisions and rejects requests for other repositories.
ASM owns normal trusted local execution and provider permissions. These controls
are not OS-level containment. No artificial qualification mechanism is used.

Reports, prompts, provider output and snapshots may contain confidential code.
Use only authorized providers and repositories. Deleting a local run does not
control provider retention. The results root is configurable; explicit deletion
and pruning remove whole local runs. Do not perform direct filesystem cleanup
of active runs. Source and native analyzer output are untrusted model
input. Mechanical evidence validation does not prove semantic correctness.
BeamAudit makes no source changes. Remediation is a separate owner-approved task.
