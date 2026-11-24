# Scope and safety

The audit target is an explicit pair of repository root and immutable Git
commit. BeamAudit does not recursively discover repositories or follow path
dependencies, even when they share an owner. No target `mix.exs`, configuration,
macro, test, application startup, or build hook is evaluated intentionally.

## Source policy

Git tree enumeration records all tracked entries. Only regular source blobs
with `.ex`, `.exs`, `.eex`, `.heex`, `.leex`, `.erl`, `.hrl`, or `.gleam` suffixes
are materialized. Tests, examples and benchmark/fixture trees are excluded by
default. Dependency/build/vendor directories, explicit exclusions, symlinks,
gitlinks and non-source formats are recorded as excluded. A source size or
encoding failure is a coverage gap. Uncommitted and untracked changes are not
included. A new revision or scope policy requires a new discovery run.

The automatic directory exclusions are conventions, not a proof of ownership.
Supply explicit exclusions for other vendored or generated source. The target
inventory is the contract; the name of a repository does not establish which
code is first party. Templates and non-Elixir syntax have textual coverage only
unless a native analyzer models them. Sobelow coverage is limited to supported
application layouts. Its historical dependency advisory category is excluded.

## Execution boundary

Git reads blobs rather than following checked-out symlinks or invoking filters.
A source snapshot contains selected regular files, not the full worktree or `.git`
metadata. Separate Elixir worker VMs analyze each repository to avoid carrying
arbitrary source atoms across a whole ecosystem audit. Sobelow is called outside
the target Mix project. This is process and input isolation, not a general OS
sandbox. Use trusted local repositories, Git metadata and installed analyzers.
Analyzer resource limits and source modeling are not guaranteed for hostile code.

Source ranges are accepted only from the recorded inventory, checked against
snapshot bytes, and sent as evidence packets. Agent output cannot add a target,
execute a requested command or register a new tool. Provider execution uses an
empty working directory and ASM completion-only and structured-output intent.
The default qualification list is intentionally empty until a provider-side
read boundary is verified. A read-only sandbox does not by itself prevent reads
of adjacent repositories or secrets. ASM's actual boundary must be established
in Phase 2; do not remove the gate or downgrade to normal coding-agent mode.

## Data handling

Reports, raw scanner output, prompts and source snapshots can contain sensitive
code and credentials. Run directories are created private to the local owner;
retain them locally and avoid publishing them with the tool. The provider will
receive source excerpts when review is enabled. Use only repositories and
providers authorized for that disclosure. Source comments are untrusted model
input; response validation cannot solve all prompt-injection attacks or prove
semantic correctness. No secrets, credentials or actual target code are bundled
with this project.

The tool makes no source changes. Remediation is a separate owner-approved task.
No dependency suppression, network scanning, live exploit, or automatic fix is
part of discovery or adjudication.
