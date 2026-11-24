# Results and recovery

A run is a local directory, identified by a time-derived prefix and random ID.
It is not a Git checkout of the target and it is never installed in the target.

```text
RUN_ID/
  manifest.json
  rules.json
  prompts/
  r001/
    inventory.jsonl
    source/
    raw/
    worker.log
    discovery.json
    ledger.jsonl
    candidates.jsonl
    flows.jsonl
    decisions/<candidate-id>.json
    challenges/<candidate-id>.json
    review_errors/
    dispositions.jsonl
  calls/<call-id>.json
  review_status.json
  summary.json
  report.md
```

`manifest.json` records selected roots and resolved revisions, settings, rule
and prompt hashes, analyzer versions and snapshot inventory digests. Each
repository's `discovery.json` records coverage, scope errors and the frozen
ledger, candidate and flow hashes. Raw tool results and errors remain visible.
A worker failure gets its own record rather than a synthetic empty scan.

`ledger.jsonl` accounts for every normalized native hit by raw ID, tool, rule,
location and bucket. `candidates.jsonl` maps stable group IDs to raw IDs. Both
are immutable inputs to review. `calls/` records attempts and responses,
including those that failed. Individual accepted decisions and challenges are
written using synced temporary files and atomic renames. This supports process
interruption recovery, not a guarantee against machine power loss or malicious
modification of every run record.

## Resume

```sh
mix beam_audit resume RUN_ID
mix beam_audit resume RUN_ID --max-calls 160
```

Resume validates snapshots, frozen ledgers, accepted IDs and evidence ranges,
then processes only outstanding primary/challenge work. Interrupted unaccepted
calls may be repeated; existing accepted work is not. A rejected or exhausted
feedback request is unresolved. A call-budget pause leaves unaccepted groups
pending. The cumulative budget counts reservations even if the provider fails.
Changing review provider/model is allowed only through explicit options and is
recorded per call; it cannot change the repository scope or rule policy.

Discovery failures require a fresh discovery run after diagnosing the tool or
scope failure; resume is for review, not rebuilding a partially captured tree.
A single coordinating writer is supported per run. Do not edit ledgers,
qualification records, decisions or hashes to make a run look complete.

```sh
mix beam_audit report RUN_ID
```

Rendering verifies the frozen inputs and writes an aggregate Markdown report,
JSON summary and per-repository disposition projections. The renderer never
calls a model. Given identical stored records it renders the same Markdown;
coverage or review gaps remain explicit even when no findings are accepted.

A run directory is private source evidence. Keep it out of Git and published
Hex packages. Delete it when retention is no longer needed. Do not assume that
provider-side retention is governed by deleting the local directory.
