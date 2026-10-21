# Task9f phase 1 handoff

Date: 2026-10-21
Branch: `task/Task9f-macos-conformance-gitai`

## Completed scope

- Refreshed the worktree to merged Task20h-b (`origin/main` at `e6dea1cca`)
  through merge commit `cad52d804`.
- Ported the bounded offline-durability fix as `12d231781`. Commit-triggered
  metrics now complete durable queue insertion before command completion;
  diagnostic submission remains asynchronous.
- Ported the regression that proves the allowlisted metric is bound to its
  tenant/repository/credential key, records an offline retry, retains no
  reusable credential in SQLite, and survives an isolated daemon restart.
- Added the canonical [TrackAI Endpoint package flavour
  registry](task9-endpoint-package-flavours.md). It distinguishes public
  package names from the internal `git-ai` and `numbat` executables and from
  the current `git-ai-*` workflow filenames.

## Verification

| Gate | Result |
|---|---|
| `task fmt` | passed |
| `task test CARGO_TEST_ARGS="--test task9_macos_conformance"` | 5 passed, 0 failed |
| Focused `integration` test `commit_metric_metadata::codex_commit_is_durably_bound_before_daemon_restart_when_delivery_is_offline` with a prebuilt `test-support` binary and isolated daemon | 1 passed, 0 failed; 3,357 filtered out |

The first focused-test attempt used the module name as a Cargo test target and
was corrected to the repository's `integration` target. A second attempt
exposed the known nested-Cargo target lock and was stopped. The sandboxed
attempt then failed closed because the daemon rejects Codex sandbox marker
variables. The final run removed only those markers under the approved
isolated-test boundary and passed. These were invocation/environment failures,
not product failures.

## Boundaries and next step

- No package was installed, signed, notarized, uploaded, or sent through Jamf
  in phase 1. No normal user GitAI state was touched.
- The prior founder run remains bounded unsigned Intel development evidence.
  The exact post-Task20h-b combined package still needs reinstall/update
  validation before the local lifecycle row is complete.
- Phase 2 should coordinate the public artifact rename to
  `trackai-endpoint-macos-{x64,arm64}.pkg` across the release workflow,
  checksums, scripts, tests and docs, while keeping internal executable names
  stable. It must not label the current GitAI-only Windows MSI as a combined
  TrackAI Endpoint package.
- Push, pull request, signed-release execution, Jamf/APNs work and founder-live
  commands remain founder-owned follow-ups.
