# Task17d pre-port Task20 review packet — 2026-10-24

**State:** decision request only. No Task17d source row has been ported. The
existing integration branch contains Task17b/c through `62e1e6a03` and a
fork-main merge at `ac6dbe022` (fork main `83f367366`). The merge resolved
only `src/daemon.rs` imports; it added no telemetry or attribution behavior.

Task14a's live migrations 0010–0028, three post-step dry runs, API smoke and
Company A/B audit isolation are recorded in its handoff. Task14a checked its
standing local recovery databases on 55433–55435: they contain copied tenants
or accounts and are unsuitable for the synthetic Lab. It verified the TrackAI
`scripts/it-db.sh` wrapper with PostgreSQL 17: a new random-port database
reached 29 Drizzle ledger entries and zero tenants, then was removed on exit.
That is a safe reset mechanism, but the synthetic L17 scenario seed and
repeatability check have **not yet been established**. Thus L17 before values
are unknown and all rows below remain unported.

Baseline checks after the fork-main merge: `cargo fmt --check` passed;
`cargo test --lib task17_security_tick_wires_all_six_actions_in_order_without_timer_or_server`
passed 1/1; `task build` passed. These ran with the installed Homebrew Rust
1.97.1 because `rustup`/the requested 1.93.0 toolchain are unavailable here.
The merge also brought CI, Git 2.56 blame expectations, Task4 test, fleet and
security fixes from fork main; Task17f still owns the combined final gates.

## Verdict requested from the Task20 lead before implementation

Please give a take, narrow, or reject verdict for the following groups. In
particular, confirm the durable no-loss queue boundary, whether any proposed
local counter may enter an uploaded payload, and whether any Trace2-only
authorship/metric meaning change is acceptable. No new upload field, event
kind, retention rule, or privacy surface will be implemented without its
TrackAI contract owner review. A shared security-file diff will be sent once
after any approved wave-3 implementation.

| Source (Apache-2.0) | Upstream behavior and fork collision | Proposed Task17d treatment; files and fixture |
|---|---|---|
| `17a402e12b` | Makes the local metric metadata backfill one-time with a `schema_metadata` completion marker. Touches `src/daemon/telemetry_worker.rs`, `src/metrics/db.rs`. | Consider only if repeated scans exist on the fork. Preserve existing event identity/time and retention. Test interruption and restart at batch boundaries, then future normal inserts. No new payload. |
| `7b0eead750` | Isolates telemetry on a dedicated runtime, but its bounded persistence queue **drops metric batches on full/closed** and its recovery lookup can time out. Touches `src/daemon.rs`, `src/daemon/telemetry_worker.rs`, `src/sqlite.rs`, `src/tokio_runtime.rs`, `src/authorship/attribution_recovery.rs`. | Reject the drop-on-full and best-effort metric semantics. If isolation is still useful, adapt with durable persistence/backpressure outside the Trace2 critical path. Prove queue pressure, offline/restart, dedup and Task4 `commit_metric_metadata` gate. Keep the two-second six-action security tick and local-only daemon health. |
| `7e71f693cb` | Adds peer error containment and loss counters, including new `DaemonIngestAnomaly` event ID 8 and `stats.ingest` control API. Touches `src/daemon.rs`, `src/daemon/control_api.rs`, `src/daemon/telemetry_worker.rs`, `src/metrics/events.rs`, `src/metrics/types.rs`. | Consider local-only peer error and counter diagnostics. Do **not** adopt event ID 8 or upload counters without separate TrackAI wire/privacy contract approval. Test peer disconnects, saturated ingest, exact local counter, no uploaded shape change and unchanged security tick. |
| L17-M1 `d0f864c570` | Replaces a SQLite rate-limit transaction on each AI checkpoint with an in-memory 150-second limiter in `src/daemon/checkpoint.rs`. Restart could change `agent_usage` count and timestamp. | Wait for same-snapshot Lab burst before/after. Decide whether usage meaning may change; preserve tool/model/cost and durable identities. Test bursts within/across 150 seconds plus restart and checkpoint latency. |
| L17-M2 `6210ebff3b`, `0a1afdd26c`, `98c27b210d`, `2be4851036`, `e11298f8d0`, `0389b48c53`, `65e22252ab`, `28cc324c2f`, `898567e747`, `879a39233e` | Reingest/replay and metadata/daemon changes in `src/metrics/db.rs`, `src/daemon.rs`, `src/daemon/telemetry_worker.rs`, `src/commands/reingest.rs` and tests. Potential conflict with Task4's durable queue and dedup contract. | Wait for Lab delivered+pending, offline/restart, two reingests and server reconciliation. Preserve event time/model, Generated/Committed, retention and stable delivery IDs; decide each row after comparison. Formatting/test commits are dependencies only. |
| L17-A1 `1e400d552a` | Recovers remaining unattributed lines as human in `src/authorship/attribution_recovery.rs` and integration tests. Collides with TrackAI's explicit unknown/untraced meaning. | Recommend reject unless controlled Lab evidence demonstrates genuinely observed human action. Never fill an unknown gap merely to reduce unknown share. Test adjacent known human, AI and untraced lines and evidence pointers. |
| L17-A2 `4dc3b1ccf1` | Corrects human additions in range stats via `src/authorship/diff_ai_accepted.rs` and `src/authorship/range_authorship.rs`. Could change range human/AI totals. | Wait for Lab two-commit human-addition/AI-deletion comparison and note/evidence checks; adopt only observed correction. |
| L17-A3 `120bcf25cf` | Copies tool/model/session onto a recovered-edge checkpoint metric from a neighboring AI session in `src/authorship/attribution_recovery.rs`. Could turn unknown model into known. | Wait for Lab proof that the edge belongs to the observed session, while adjacent unknown stays unknown. Test Bash edge fixture and source pointers. |

Wave 3 also has `3e2746c8f7`/`069981d3dc` (`usage --period`) in
`src/commands/usage.rs` and focused integration fixtures. They have no planned
shared security file or upload contract change. Wave 4 has `6f7ee5cabe`
(range-diff SHA abbreviation) and `4f3586c606` (C locale for internal Git);
their attribution and note effects will be checked against the same Lab
snapshot before choosing any adaptation.

**Before-state / privacy:** L17-M1/M2/A1/A2/A3 event IDs, timestamps,
tool/model, queue positions, lifecycle totals and evidence pointers are not
yet observed. The Lab will use synthetic identifiers only. No raw prompt,
response, tool content, repository path, family name, secret or customer row
will enter an uploadable log/event or this packet. Copilot selected/Auto versus
availability-default-to-unknown semantics from Task17c are part of the
baseline; any per-model total change is to be relayed to Task19 answer owners.

The expected scope exceeds the original `0.38× T6` estimate if the two large
upstream telemetry commits and all 14 Lab rows are taken. Keep wave 3
(telemetry/metrics) and wave 4 (attribution/notes) separate for review; narrow
or reject candidates before widening the code diff.
