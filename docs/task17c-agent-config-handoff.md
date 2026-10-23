# Task17c agent identity and config handoff

Date: 2026-10-23. GitAI branch: `task/Task17-upstream-sync-gitai`. Base for exact Task17c review: `3552d4640` (fork `origin/main` `3b42f8fbe` integrated after Task17b `1c219f538`; public upstream was not merged). The founder owns push, PR and merge. Task17f owns the combined full Cargo and live gates. No TrackAI server contract, release, MDM, fleet, security module or telemetry worker source was changed. **Recommendation: ready for Task17 lead review; founder-run Task4 restart and live route checks remain pending before any stronger release claim.**

## Source decisions

All 16 selected rows were adapted from the Apache-2.0 upstream Git AI source. The fork had partial Copilot, Codex and Unicode behavior but not these fixes. Reuse search: none; these are narrow GitAI upstream adaptations, not agent-kit or SushiCorp components.

| Upstream SHA | Feature or fix and user benefit | Fork before / adaptation risk | Commit |
| --- | --- | --- | --- |
| `2b7dc3b18b` | Case-insensitive Claude tool names preserve hook attribution. | Fork required exact casing; limited to Claude preset. | `9c794f556` |
| `16655f8fbc` | Normal config output uses stdout, allowing shell capture. | Fork used stderr; error output retains its route. | `2d7aa98e5` |
| `2c321c143f` | Lowercase `head` resolves in linked worktrees. | Fork had a case-sensitive path; revision scope only. | `46f44e5fb` |
| `9dd155d9fa` | UTF-8 revision bytes are handled safely. | Fork conversion could mis-handle non-ASCII names; no Git route expansion. | `46f44e5fb` |
| `b835f97236` | Case-insensitive revision fixture pins behavior. | Test-only dependency of the revision pair. | `46f44e5fb` |
| `878775205b` | Stored pathspecs normalize to NFC so Unicode paths match. | Fork lacked path normalization; may shift counts for decomposed names. | `e4c3e6632` |
| `656ede16d5` | Non-ASCII numstat postfilter unescapes Git paths. | Fork could omit Unicode files; test placement fixed in `194bd5b0c`. | `e4c3e6632` |
| `f17bf9177e` | Codex model comes from rollout or local selected profile when hook omits it. | Fork left it unknown; bounded local reads, no availability default. | `ce6ac1cb3` |
| `d63e091240` | Latest turn/profile precedence and missing-evidence tests. | Refines the preceding extraction; no new route. | `ce6ac1cb3` |
| `79cb2e83a2` | Copilot VS Code selected model is resolved in daemon checkpoint work; Bash metadata is enriched only for matched checkpoints. | Fork read in every hook and used availability defaults; privacy and hook latency required adaptation. | `896266547` |
| `2b26f1ca17` | Auto uses observed resolved model; absent selection stays unknown. | Fork could report default as selected; per-model counts change. | `896266547` |
| `3bf8bbfebe` | Buffered JSON parsing reduces local read overhead. | Applied within bounded typed parsing. | `896266547` |
| `b1bbb7650e` | Session scans have byte limits. | 1 MiB JSONL tail; evidence outside bound stays unknown. | `896266547` |
| `355b95e088` | Large session JSON is streamed without retaining prompt/response fields. | Adapted with an 8 MiB bound; larger states remain unknown. | `896266547` |
| `7ace11b091` | Codex hook and sweep key a fork rollout by filename and retain parent metadata. | Fork could double ingest; added atomic old-key cursor reconciliation. | `7b5d62aab` |
| `9af568ff1e` | Canonical macOS path fixture pins one row for `/var` and `/private/var`. | Test-only dependency of the stream-key fix. | `7b5d62aab` |

All source SHAs are Apache-2.0; no new dependency was added. Reject and `defer:Task13` agent/config ledger rows remain out of this wave. The Task17 lead owns ledger edits.
## Task20 owner conditions and contract

Task20 lead (Claude) verdict supplied by founder: **accept with changes** for the Copilot chain and Codex stream pair. The adaptation keeps VS Code prompt content local and out of model records/events/logs; the native hook records unknown without lookup or retry, while daemon checkpoint work runs via `spawn_blocking` outside trace ingestion. Bash enrichment is only reached after an existing matching checkpoint candidate, and an untraced edit stays unattributed. Codex stream reconciliation atomically retains the greatest existing byte cursor for the same canonical path before the new key is registered. No wire schema, security worker, Numbat hook or Numbat-managed agent route changed. Copilot CLI is unaffected.

The privacy fixture places `PRIVATE_PROMPT_SENTINEL_do_not_upload` in VS Code session state and checks the authorship record, daemon stderr log, and stored daemon state for absence. Only a short model id may leave as existing model evidence. Parse failures and session-state paths are not logged by the new lookup. The 1 MiB JSONL/8 MiB JSON limits may leave very large states unknown. Replacing the old availability default with unknown will shift per-model counts: Task19 answer owners and Task17d Lab before/after should expect this meaning change. The Codex upgrade fixture seeds an old cursor, appends a token event, and verifies one canonical stream row with exactly one locally queued token event (`39432ca6b`); it does not claim live server delivery evidence.

## Verification observed locally

- Config TestRepo 1/1; revision TestRepo 4/4; Claude preset/integration 1/1 each; Unicode status unit 1/1.
- Codex model units 3/3, preset 1/1, config route 1/1, Codex integration group 43/43.
- `cargo check --all-targets` passed; `cargo test --lib copilot -- --test-threads=1` passed 130/130.
- Copilot selected/Auto/cache TestRepo group 6/6 including linked-worktree variants; sentinel privacy assertion passed. Bash selected-model recovery and no-checkpoint negative fixtures passed 2/2.
- Codex fork/subagent pre-upgrade cursor e2e passed 1/1; cursor reconciliation unit passed 1/1. Large JSON bounded read 1/1 and JSONL oversized/UTF-8 tail 2/2 passed. Task17 security six-action worker wiring unit passed 1/1.
- Codex fork and plain rollout preset identities passed 1/1 each; Copilot hook-without-daemon unknown unit passed 1/1.
- `cargo fmt --check` and `git diff --check` passed on the committed code.
- `task build` passed. Independent read-only `codex review --base 3552d4640` reported no actionable regression. Supplemental `codex review --commit 39432ca6b` found no actionable defect in the final queue-count assertion; that review's own sandboxed test was interrupted, while the same fixture passed separately with local daemon sockets enabled.
- `task lint` under host Rust/Clippy 1.97.1 stopped on 12 unchanged-line warnings inherited from fork main/Task17b (the project CI toolchain is pinned to 1.93.0); none was in a new Task17c line. `cargo clippy --all-targets -- -D warnings` passed after suppressing only those seven inherited warning categories: `useless_borrows_in_formatting`, `for_kv_map`, `question_mark`, `manual_filter`, `byte_char_slices`, `needless_borrow`, `unnecessary_to_owned`.

## Remaining gates

The founder can run the heavier Task4 durability restart fixture locally:

```sh
cd /Users/manishmahajan/AIProjects/TrackAI-wt/Task17-upstream-sync-gitai
task build
task test TEST_FILTER=codex_commit_is_durably_bound_before_daemon_restart_when_delivery_is_offline
```

This harness requires local daemon sockets. In Codex's sandbox it needed `env -u CODEX_SANDBOX_NETWORK_DISABLED` and a `test-support` binary; a normal local shell should use the repo's task/test setup. Expected result: one passed fixture, no duplicate delivery after restart. Task17f retains the combined full suite and Task20 security/contract gates. Live agent checks remain pending in a separate macOS account: Claude Code mixed-case hook, Codex actual rollout model plus fork/subagent, and Copilot VS Code selected/Auto with actual agent version, host, capture channel and observed/unknown result. Prove that account's daemon/database before each check. No package was installed on the founder's everyday account.
