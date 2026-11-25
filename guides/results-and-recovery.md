# Results and recovery

## Storage location

By default, run records live under `$XDG_STATE_HOME/beam_audit/runs/RUN_ID`.
If the state variable is unset, empty or relative, the location falls back to
`~/.local/state/beam_audit/runs/RUN_ID`. This is durable user state, not a
cache that may be silently discarded. The results root is selected in order:

1. Explicit `--out DIRECTORY` or `out: directory`.
2. Optional `BEAM_AUDIT_OUT` environment variable.
3. `config :beam_audit, out: directory` in the calling application.
4. The XDG state default above.

The selected root is outside the audited repositories. It is created on the
first discovery, not on listing or retention preview. Only the current run
schema is supported; run records are not automatically migrated.
An explicit run directory may be passed to resume, report and compare; run IDs
are resolved within the selected root. Do not rename run directories.
A new policy or revision needs a new discovery run. Resume keeps the discovery
settings frozen in `manifest.json` and permits review-stage overrides only:
provider, model, jobs, batch size, cumulative call budget, evidence rounds and
deadline. The results root selects the run; it does not change its captured scope.

## Run records

```text
RUN_ID/
  manifest.json, rules.json, prompts/
  r001/
    inventory.jsonl, source/, raw/
    discovery.json, ledger.jsonl, candidates.jsonl
    flows.jsonl, definitions.jsonl, symbols.jsonl, slices.jsonl
    dependency-input/, dependencies.json, dependencies.sha256
    decisions/, challenges/, pending_decisions/, pending_challenges/
    history/, review_errors/, dispositions.jsonl, findings.jsonl
  calls/, review_status.json, summary.json, report.md
```

The report projections are regenerated from stored records:

| File | Purpose |
| --- | --- |
| `report.md` | Human-readable findings, evidence, coverage and outstanding work |
| `summary.json` | Run identity, status, counts and observed provider usage |
| `rNNN/findings.jsonl` | Consolidated accepted source findings and dependency advisory matches |
| `rNNN/dispositions.jsonl` | Effective review status for every candidate, including unresolved and pending groups |

The `accounted_within_declared_policy` status requires zero pending reviews,
unresolved decisions and recorded coverage gaps. Confirmed findings may still
be present. `partial_or_unresolved` indicates incomplete accounting, not a
judgment that the target is unsafe or safe. Some files may be absent if a stage
never completed.

Manifest and evidence digests freeze the discovery inputs. Records use synced
temporary files and atomic replacement. This supports process interruption,
not malicious tampering or guaranteed survival of power loss. New run
contents are protected by a private run directory on Unix. Discovery, resume,
report rendering, comparison and deletion coordinate through an atomic sibling
directory named `.beam-audit-lock-RUN_ID`. Independent runs can execute in
parallel. This is a local filesystem guard, not a security boundary or
coordination with arbitrary manual file operations.

Unaccepted calls may be repeated, but their reservations still count. A
provider failure pauses further launches; resume only after addressing it.
Resume invalidates the previous summary before changing review records, so an
interrupted review is not mistaken for a completed run by retention. An old
Markdown report may remain; regenerate it before relying on its status.

A hard process kill or host failure can leave an empty guard directory. It is
reported by `runs` and blocks access/deletion until removed. Verify that the
coordinator and any worker processes have stopped, then remove only that
specific empty guard with `rmdir`:

```sh
rmdir "$RESULTS_ROOT/.beam-audit-lock-$RUN_ID"
```

Do not remove guards just because they are old. An interrupted discovery may
also leave a run without a recognizable manifest. Inspect such a directory
manually before discarding it. An incomplete dependency stage is a coverage
gap even under the source profile; a finished source-only stage records
`not_requested`.

```sh
mix beam_audit report RUN_ID
mix beam_audit resume RUN_ID --max-calls 25
mix beam_audit resume RUN_ID --reconsider --max-calls 30
mix beam_audit compare OLD_RUN NEW_RUN
```

`report` and `compare` use stored records and invoke no provider or scanner.
Comparison regenerates both reports from their persisted inputs.
Pending evidence packets preserve work across budget pauses. Reconsideration
archives unresolved/disputed records before reopening; no silent change to
accepted safe or confirmed decisions. Byte equality is expected for identical
stored inputs and renderer, not across releases.

Source finding fingerprints combine repository, path, property, definition and
anchor content. Dependency fingerprints combine repository, project, package
and advisory. Comparison uses exact matches and reports new, still reported
and not observed. It does not transfer waivers or prove remediation; changed
policy, feed, review or scope may explain differences. Use one revision per
repository in each compared run. Inspect underlying evidence after changes.

## Retention

```sh
mix beam_audit runs
mix beam_audit runs --out /path/to/runs
mix beam_audit delete RUN_ID
mix beam_audit delete RUN_ID --yes
mix beam_audit prune --keep 10 --older-than 30
mix beam_audit prune --keep 10 --older-than 30 --include-partial
mix beam_audit prune --keep 10 --older-than 30 --include-partial --yes
```

All lifecycle commands accept `--out DIRECTORY`. They print JSON and make no
provider or scanner calls. `runs` inventories immediate run-shaped children,
including any malformed ones, and reports logical regular-file bytes rather
than physical filesystem allocation. It does not follow symlinks. Sizes for
active/unreadable runs may be incomplete; ignored entries and guards are
listed separately and are not included in the total. This is a read-only
inventory, not a transactional snapshot of concurrent operations.

`delete` accepts exactly one recognized run ID in the selected root. It
previews even a partial run; add `--yes` only to intentionally discard that
run, including source, reports, review history and recovery records.

`prune` requires `--keep N` (nonnegative) or `--older-than DAYS` (positive).
`--keep N` protects the newest N recognized runs at selection time, including
partial runs. Age is measured from creation, in 24-hour days, not last access.
When both options are supplied, runs must satisfy both criteria. By default
only fully accounted runs are eligible; use `--include-partial` to include
partial or unreported runs, for example after deciding not to resume them.
Unknown entries, symlinked run directories, and guarded runs are excluded.
Deletion rechecks identity and status after acquiring the per-run guard.

Both deletion commands are dry runs unless `--yes` is supplied (library:
`confirm: true`). The result includes selected IDs/sizes, skipped reasons,
actual deleted IDs and any errors. Prune continues across individual failures;
there is no rollback. Preview is not a reservation: an applied prune computes
a fresh selection. Inspect the results, especially if other processes are
running. There is no automatic retention, hard size quota, scheduler or global
index. Use explicit pruning or a caller-chosen temporary results root for
disposable work. VulnCheck's own advisory cache is outside this lifecycle;
provider retention is also separate. Deleting run files is not secure erasure.
