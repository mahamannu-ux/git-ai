# Task17d attribution and metrics handoff — 2026-10-25

**Branch:** `task/Task17-upstream-sync-gitai`, fork `mahamannu-ux/git-ai`.
**Start:** Task17b/c through `62e1e6a03`; fork `origin/main` `83f367366`
merged locally at `ac6dbe022`. Initial code end `7e3f2d0d7`; review fix
`a100bfcba`. Review through branch `HEAD`.
All source commits below are Git AI Apache-2.0. No push, PR, upstream-main
merge, package install, TrackAI schema change or Task17f run occurred.
Reuse search: none; these are narrow GitAI upstream adaptations, not agent-kit
or SushiCorp reusable components. **Effort:** about 0.4× T6 against the
0.38× estimate; disposable-Lab validation and Rust rebuilds account for the
small overrun.

## Decision table for the Task17 lead

| Source row | Decision and evidence | Implementation |
|---|---|---|
| `17a402e12b` | **Adapt.** Startup called the process-local metadata backfill on every daemon start. A persisted completion marker now stops rescanning after the last batch; an interrupted scan resumes safely. Event IDs, timestamps, retention and upload shape are unchanged. | `e7e403363` |
| `7b0eead750` | **Reject.** Upstream's bounded intermediate queue drops metrics on full/closed. Task17b already addressed the cited ingest stall; Task4's durable queue must remain the first metric boundary. No contention evidence justified optional `busy_timeout`. | None |
| `7e71f693cb` | **Narrow adapt.** Control peer EOF/reset/timeout is contained at WARN; unexpected errors remain ERROR. Trace queue-full and reader-spawn losses are counted in local `bg status`. The queue-full path still requests shutdown. No root/session/path is added to uploaded logs. No event ID 8, `stats.ingest`, periodic counter log or uploaded counter. | `b1704c264` |
| L17-M1 `d0f864c570` | **Reject for Task17.** The upstream 10,000-entry in-memory limiter can re-emit inside 150 seconds after capacity eviction or a poisoned lock, as well as after restart. This exceeds Task20's condition of at most one extra event per restart and changes usage counts. The fork's SQLite throttle survives reopen (`agent_usage_throttle_survives_database_reopen`). No Task2-owner approval is needed to reject it. A future performance proposal would need a durable, meaning-preserving design and its own owner decision. | Test guard `7e3f2d0d7`; no limiter port |
| L17-M2 `6210ebff3b`, `0a1afdd26c`, `98c27b210d`, `2be4851036`, `e11298f8d0`, `0389b48c53`, `65e22252ab`, `28cc324c2f`, `898567e747`, `879a39233e` | **Reject for Task17**, per Task20. High conflict with Task4 delivery/dedup and no named fork failure. If a real reingest defect appears, the Task17 lead should open a separately named proposal with pending/delivered replay scenarios; this is not a deferral to finished Task4. | None |
| L17-A1 `1e400d552a` | **Reject.** Relabels unobserved gaps as human; unknown must remain unknown. | None |
| L17-A2 `4dc3b1ccf1` | **Adapt, then review fix.** The before fixture reported an observed human addition as `human=0, unknown=1`; after the fix it reports `human=1, unknown=0`, with AI additions and total diff unchanged. A separate unobserved addition remains `unknown=1`. The review fix excludes blame-confirmed AI lines from `h_` counting and warns with counts only if totals exceed added lines. No note, event, lifecycle definition or evidence pointer is rewritten. | `8097f5e4f`, `a100bfcba` |
| L17-A3 `120bcf25cf` | **Reject current upstream patch.** `recover_adjacent_edges` derives `source_session` from `recovery.source_author`, selected from an adjacent line; the synthetic edge has no checkpoint carrying its own exact session ID. Copying that neighbor's tool/model/session would violate Task20's exact-join condition. The upstream fixture itself labels its unknown gap as AI. A future exact-join implementation requires an edge checkpoint with the recorded session ID and an adjacent-unknown guard. | None |
| `3e2746c8f7` + `069981d3dc` | **Adapt.** Local `usage --period`; five integration cases passed. Excluded upstream pricing-cache refresh, which belongs to Task13. No upload change. | `6bc803221` |
| `6f7ee5cabe` | **Adapt.** `core.abbrev=no` is supplied to parsed `range-diff`; existing synthetic pull/rebase note and AI-line fixtures passed before and after (2/2 each). | `1b94af533` |
| `4f3586c606` | **Narrow adapt.** C locale only for internally parsed Git output. The fork already decoded C-quoted status paths; added unescape/NFC for range numstat paths. A French-host-locale non-ASCII ignore fixture and the same rebase note/AI-line fixtures passed. No user-facing Git passthrough locale change. | `0cfa1b434` |

The seven rejected lite-mode rows remain rejected per `TASK17.md` §3. No
synthetic reflog attribution or inference of unknown provenance was added.
Task17 lead owns the TrackAI ledger/tracker update and any future proposal.

## Disposable Lab and meaning boundary

Task14a's handoff records migration 0010–0028, post-step dry runs, API smoke
and Company A/B isolation. Its standing recovery copies on ports 55433–55435
contain restored accounts and were not used. On 2026-10-25,
`IT_PG_IMAGE=pgvector/pgvector:pg17 IT_PG_VERSION=17 scripts/it-db.sh npm run
verify:task19b-qa-live -w apps/api` passed on a new random-port PostgreSQL 17
database. The wrapper applied all 29 migration ledger entries, seeded only
synthetic Company A/B lifecycle rows, checked Q3/Q9/Q13/Q19/Q20 and tenant
isolation, and removed the database on exit. Its first sandboxed attempt
failed at `initdb` shared-memory allocation; the identical command passed
outside the sandbox. This verifies a repeatable migrated reset path and the
TrackAI lifecycle read model, not live delivery from GitAI.

GitAI's synthetic `TestRepo` fixtures provided before/after source evidence
for A2 and wave-4 note behavior. These are separate isolated test repos, not
one captured PostgreSQL snapshot replayed through a server. Since M1 and A3
were rejected, no changed GitAI metric payload needs a TrackAI ingestion
comparison. The precise end-to-end GitAI→TrackAI Lab replay from the prompt
remains **unrun**; do not describe this as a live or complete lifecycle Lab
pass. No customer data or live Supabase database was queried for Task17d.

Task17c's Copilot selected/Auto/default-to-unknown model behavior remains
the before state. Task17d makes no per-model change. A2 can change local
`stats <range>` human/unknown totals where a known-human attestation existed;
the Task19 answer owners should receive that note through the founder.

## Checks run

- Usage period: five integration tests passed. One-time backfill: restart,
  interrupted-batch and completion test passed; Task4 offline daemon-restart
  commit binding passed 1/1.
- Local diagnostics: peer classification, local status counters, full trace
  queue loss and checkpoint-body EOF tests passed. Heartbeat upload-shape
  fixture and six-action two-second security tick passed.
- A2: 30 range-authorship fixtures passed after review fix. The original
  corrected assertion failed before the source change and passed after.
  Unobserved addition remains unknown. A synthetic conflicting-source unit
  fixture passed: AI by blame plus `h_` by attestation on one added line
  yields `ai=1, human=0, unknown=1` for two added lines. Nine
  `diff_ai_accepted` unit tests passed.
- Wave 4: non-ASCII range ignore under `fr_FR.UTF-8` passed; two rebase
  note/AI-line fixtures passed before and after `core.abbrev=no`, then passed
  under `fr_FR.UTF-8` after C-locale adaptation. C-quoted/decomposed path and
  internal-versus-passthrough locale unit tests passed.
- Task4 queue: offline retry stays pending, successful upload marks delivered,
  retry exhaustion quarantines, and bound delivery identity round-trips;
  focused tests passed. Security v2 contract: 5/5 passed. The real Numbat
  shipper integration test stayed ignored because it needs a built package.
- `cargo fmt --check`, `git diff --check`, and `task build` passed at the last
  source slice. `cargo clippy --all-targets -- -D warnings` failed on 11
  unchanged-line findings under installed Homebrew Rust 1.97.1 (including
  existing daemon delimiter syntax); the requested Rust 1.93.0/rustup is not
  installed. No finding points to a Task17d added line. No full `cargo test`
  was run; Task17f owns the combined gate.

Task17b's two-second security worker still calls policy refresh, shipper
poll, status, inventory, flush and day-one scan in order. The exact only
Task17d change to shared `src/daemon/telemetry_worker.rs` is:

```diff
- db_lock.backfill_event_metadata_batch_after(after_id, METADATA_BACKFILL_BATCH_SIZE)?
+ db_lock.backfill_event_metadata_batch_once(after_id, METADATA_BACKFILL_BATCH_SIZE)?
```

No `src/security/` file changed. This diff was supplied for founder relay to
the Task20 lead. `bg status` stopped-shape top-level `"daemon_running": false`
was not changed. The only new uploadable daemon log fields are queue capacity
and queued payload count on an error line when a trace payload is lost; no
counter, root, session or path is uploaded. No new metric/security event kind,
retention rule or privacy field was added. The A2 mismatch warning contains
only added/AI/human counts, no file path, repository, session or content.

## Remaining gates and review request

The founder relayed a **fix first** review on 2026-10-25 for
one A2 overlap defect and confirmed the shared-worker diff and all other
reviewed areas. The overlap fix above is committed; its focused tests and
build passed. **FOUNDER REVIEW:** request read-only re-review of the new
`HEAD` before **ready to push**. The local
`codex review --base ac6dbe022` attempt failed in the sandbox because its
runtime could not write its state database. The escalated attempt was rejected
by automatic approval review: it may transmit the private diff and handoff to
an external backend without specific authorization for that destination. No
indirect review attempt was made. Relay the request below to the standing
TrackAI-Orchestrator Claude chat, as `AGENTS.md` §12.6 directs.
The founder can paste this request to the reviewer:

> Re-review Task17d on `task/Task17-upstream-sync-gitai` at its final `HEAD` in
> `/Users/manishmahajan/AIProjects/TrackAI-wt/Task17-upstream-sync-gitai`,
> against fork-main integration base `ac6dbe022`. Read the Task17d prompt,
> verdict and the exact `src/daemon/telemetry_worker.rs` diff above. The
> previous review found one A2 overlap defect: blame-confirmed AI and `h_`
> could count the same line. Inspect the committed exclusion, conflicting-
> source fixture, and counts-only warning, then return numbered fixes or
> `ready to push`; do not edit the branch.

**FOUNDER TASK19:** tell answer owners that observed local `stats <range>` human/unknown counts
can move. **FOUNDER TASK17f:** run full Cargo/combined suites, real Endpoint
shipper/server gates,
E20/Intel timing, real long hook, separate-account live agent routes, and the
one combined GitAI PR. Do not push or open that PR from this session.
