# Results and recovery

Run records are kept in `~/.beam_audit/runs/RUN_ID` by default. Schema 2 adds
native dependency results, frozen definitions/symbols/slices, pending evidence
packets, review history, and finding projections. Schema 1 inputs and challenge
rules remain readable; do not rewrite old ledgers to add new rule coverage.
A new policy or revision needs a new discovery run.

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

Manifest and evidence digests freeze the discovery inputs. Records use synced
temporary files and atomic replacement. This supports process interruption,
not malicious tampering or guaranteed survival of power loss. Use one writer
per run. Unaccepted calls may be repeated, but their reservations still count.
A provider failure pauses further launches; resume only after addressing it.

```sh
mix beam_audit report RUN_ID
mix beam_audit resume RUN_ID --max-calls 25
mix beam_audit resume RUN_ID --reconsider --max-calls 30
mix beam_audit compare OLD_RUN NEW_RUN
```

`report` and `compare` use stored records and invoke no provider or scanner.
Pending evidence packets preserve work across budget pauses. Reconsideration
archives unresolved/disputed records before reopening; no silent change to
accepted safe or confirmed decisions. Legacy runs have the old frozen policy
and no dependency result; their reports label it not captured. Byte equality is
expected for identical stored inputs and renderer, not across releases.

Source finding fingerprints combine repository, path, property, definition and
anchor content. Dependency fingerprints combine repository, project, package
and advisory. Comparison uses exact matches and reports new, still reported
and not observed. It does not transfer waivers or prove remediation; changed
policy, feed, review or scope may explain differences. Use one revision per
repository in each compared run. Inspect underlying evidence after changes.
