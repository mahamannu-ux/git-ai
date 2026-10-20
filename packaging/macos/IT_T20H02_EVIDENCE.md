# IT-T20h-02 — Endpoint inventory and day-one scan, Intel Mac

**Result:** passed for the Task20h-b merge on one disposable Intel Mac account,
`trackaimdmtest`, on 2026-10-20 UTC. This is a bounded debug-package test, not
a signed release, second-Mac, or live reinstall test.

## Packages and setup

| Item | SHA-256 / result |
|---|---|
| Initial debug PKG, `trackai-endpoint-task20h-b-debug-x64.pkg` | `aa9dcdbefa4e6cc78a4e482c15f025269f766e9cc656dc33fce62038f40f9d0f` |
| Corrected scan debug PKG, `trackai-endpoint-task20h-b-debug-x64-fix1.pkg` | `8bb9b7d93b97eb558d267dc874c1af111c97a9a3cb3ff224d44c6120d377e867` |
| Pinned Numbat binary, `v0.2.0-trackai.1` | `b80672486b0e05b4eb13033b0546fddddde71c7792a6e1cceb9cd19240771667` |

The founder installed both packages with macOS `installer -pkg ... -target /`.
The disposable TrackAI API used `scripts/it-db.sh` database
`trackai_task20h_founder` and port 8080. The guest had five managed hooks.
The final debug binary was ad hoc signed **after installation**, solely to
diagnose the Keychain prompt, then the disposable machine credential was
reinstalled. Neither package included that signature. No private key,
credential, raw record or customer content is included here.

## Observed server and guest results

| Gate | Observation |
|---|---|
| Inventory S19 | One snapshot with all 27 Numbat `--all` rows applied; managed names mapped to `claude-code`, `codex`, `cursor`, `gemini-cli`, `copilot`. |
| Day-one S20 | Five summaries delivered: four `complete`, one zero-artifact `error` for the approved no-artifacts case. Seven `found_at_rest` findings arrived, including three `secrets.agent_read_env` findings. |
| Policy and local state | The newest acknowledgement was `applied`, `rules/current` pointed at `1-f51ace7d9b21`, `day-one-scan-done` existed, `scan-tmp` was mode 0700 and held zero files. |
| Off/on once rule | Guest applied off and returned to `placeholder`; marker remained. Guest applied on again and returned to the signed rules. Server summary count stayed five. |
| Cleanup | Guest daemon stopped; guest-session Keychain credential deletion returned `ok`; root cleanup removed all five managed hooks, Numbat and guest security state while preserving `.numbat`. Disposable API/database stopped; saved private signing keys and credential transfer were removed. |

The core verification commands were:

```sh
# Main account in the throwaway database shell, with TENANT_ID from the test fixture:
npm run security:settings -w apps/api -- --tenant "$TENANT_ID" --operator task20h-founder-test --change "$LIVE_DIR/settings-monitor.json" --confirm
npm run security:settings -w apps/api -- --tenant "$TENANT_ID" --operator task20h-founder-test --change "$LIVE_DIR/settings-day-one-on.json" --confirm
psql "$DATABASE_URL" -c "SELECT count(*) FROM security_agent_inventory_snapshots WHERE tenant_id = '$TENANT_ID'"
psql "$DATABASE_URL" -c "SELECT status, artifacts_scanned, findings_emitted FROM security_scan_summaries WHERE tenant_id = '$TENANT_ID' ORDER BY received_at"
# Guest account after each settings change:
"$HOME/.git-ai/bin/git-ai" bg restart --hard
readlink "$HOME/.git-ai/internal/security/rules/current"
```

The founder used dry runs before each settings publish, queried the inventory
rows and acknowledgements, and repeated the off/on publish to test scan
idempotence. The commands above are evidence context; the disposable tenant,
database and private fixture have been removed.

## Repairs and follow-ups

- Pinned Numbat writes the no-artifacts diagnostic to stderr and one `error`
  summary to the output file. Task20h-b queues that summary once; any other
  nonzero exit leaves the marker unwritten for retry. The diagnostic wording
  and output channels are now listed in `packaging/numbat/SYNC.md`.
- A prior postinstall `mv -f` followed the `current` symlink into the cached
  bundle directory, leaving an extra `current.next`; the founder removed that
  exact link for this run. The source repair uses BSD `mv -fh` and has a macOS
  regression test. The repaired installer was **not** reinstalled live; Task9f
  update/reinstall checks own that gate.
- A permanently failing agent currently retries all five scans hourly.
  Task20j should cap attempts (for example, 24) and record a partial marker.
- The zero-artifact summary has machine status `error`; Task19/S20 answers
  should explain it as “no session files found for this agent.”
- Ad hoc signing was diagnostic only. Stable Endpoint signing and package
  update Keychain behavior remain Task9f/Task14 work.
