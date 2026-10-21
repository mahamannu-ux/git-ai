# Task20h-a handoff: macOS Endpoint package and managed hooks

## Scope and behavior

- The macOS package carries the pinned Numbat binary, its notices and provenance, checksum and TrackAI trust documents. It builds separate `x64` and `arm64` PKGs. The release workflow verifies the reproducible unsigned Numbat digest, signs the copied binary with Developer ID and records both unsigned and signed digests. A non-dry-run release requires signing inputs and the `TRACKAI_SECURITY_TRUST_DOCUMENTS_B64` release environment secret; the first such release has not run.
- Numbat's root-owned admin path is `/Library/Application Support/TrackAI/Endpoint/bin/numbat`. The postinstall checks its package SHA-256 and pinned 51 built-in rule IDs before installing hooks.
- `rules/current` starts at `placeholder` and returns there on off or expiry. Each agent folder has the enabled `trackai.placeholder.never_matches` rule (`expr: 'false'`) and disabled overrides for all pinned built-in IDs. This compiles one rule and cannot find anything. A verified compact bundle supplies the active overrides; the founder's monitor bundle compiled 45 rules.
- Managed hooks append preview records to `$HOME/.numbat/records.ndjson`. The Endpoint uploads allowed minimized records only under a valid monitored lease. Off stops uploads, but Numbat continues writing local previews. Task20e rotates the file daily and removes rotations after seven days; it does not truncate the active file as it is consumed.

## Exact managed hook installation

All five are installed by root with this common path and flags (no `--enforce` and no `--no-builtin-rules`):

```sh
NUMBAT='/Library/Application Support/TrackAI/Endpoint/bin/numbat'
"$NUMBAT" hook install --agent claude  --managed --emit all --content preview --output file --rules-dir '$HOME/.git-ai/internal/security/rules/current/claude-code' --output-file '$HOME/.numbat/records.ndjson'
"$NUMBAT" hook install --agent codex   --managed --emit all --content preview --output file --rules-dir '$HOME/.git-ai/internal/security/rules/current/codex'       --output-file '$HOME/.numbat/records.ndjson'
"$NUMBAT" hook install --agent cursor  --managed --emit all --content preview --output file --rules-dir '$HOME/.git-ai/internal/security/rules/current/cursor'      --output-file '$HOME/.numbat/records.ndjson'
"$NUMBAT" hook install --agent gemini  --managed --emit all --content preview --output file --rules-dir '$HOME/.git-ai/internal/security/rules/current/gemini-cli'  --output-file '$HOME/.numbat/records.ndjson'
"$NUMBAT" hook install --agent copilot --managed --emit all --content preview --output file --rules-dir '$HOME/.git-ai/internal/security/rules/current/copilot'     --output-file '$HOME/.numbat/records.ndjson'
```

## Health, live check and remaining gates

- The hourly and post-apply Endpoint status includes Numbat version, five managed hook states, lease ID, active bundle digest, local record time, and `hook_status`, `agent_effective_view`, `local_record`, `forwarder_ack`. It reports `unavailable` rather than inventing an effective view. The latest founder monitor status had `hook_status=ok`, `local_record=ok`, `forwarder_ack=ok`, a non-null digest and `agent_effective_view=unavailable`.
- [IT-T20h-01 evidence](IT_T20H01_EVIDENCE.md) records the Intel Mac debug PKG run. Copilot and Claude actions passed on placeholder; a signed development bundle applied and produced one dummy `.env` finding; off returned to placeholder and kept the server finding count unchanged; all five managed hooks and Numbat were removed. Claude and Cursor did not display Numbat in their hook lists, but startup/debug and Cursor-specific record counts proved execution. Gemini displayed enabled hooks. Codex CLI was absent in the guest.
- Root offboard from the main console could not delete the guest Keychain item (`locked`), exited nonzero and retained the bootstrap file. A guest-console `fleet cleanup --apply` retry completed. Unattended MDM cleanup with a locked guest Keychain is not proven.
- Hook latency on the Intel Mac, 200 runs each: Numbat benign median/p95 20.1/27.0 ms; Numbat matching 19.7/25.4 ms; Endpoint hook 18.1/27.0 ms. TASK20 §6 budgets remain unset.
- Build, 56 security tests, 39 fleet tests, format and scoped all-target Clippy passed after merging refreshed `origin/main`. Exact `task lint` fails on 12 warnings in unchanged `origin/main` files; the scoped run allows only those six inherited lint categories.
- The separate TrackAI docs branch `task/Task20h-task9-resume` records architecture-specific packages and defers IT-T9-02/03/07 until the Task20h package has merged. Signed package, update, rollback, offline queue, credential rotation/revocation, Jamf, Apple Silicon and another Mac are still pending. Production trust and first non-dry-run signed/notarized release remain post-merge.

Effort: about 0.45× T6 against the prompt's 0.25× estimate; live trust, built-in catalogue compatibility and guest Keychain diagnosis extended the run.
