# Git AI Task2 Command Guide

This guide distinguishes source development, local installation, background-service
control, controlled TrackAI experiments, diagnostics, and final verification.

## Important directories

| Purpose | Directory |
|---|---|
| Patched Git AI OSS source | `/Users/manishmahajan/Documents/Codex/2026-07-21/hi/outputs/Task2/git-ai-task2` |
| Controlled lab repository | `/Users/manishmahajan/Documents/Codex/2026-07-21/hi/outputs/git-ai-teamz-lab-vscode` |
| TrackAI Task2 application | `/Users/manishmahajan/Documents/Codex/2026-07-21/hi/outputs/Task1/TrackAI-v1-task1` |
| Installed Git AI binary | `~/.git-ai/bin/git-ai` |
| Local metrics queue | `~/.git-ai/internal/metrics-db` |
| Transcript watermarks | `~/.git-ai/internal/transcripts-db` |

## 1. After changing Git AI source

Run these from the patched Git AI source directory:

```bash
cd /Users/manishmahajan/Documents/Codex/2026-07-21/hi/outputs/Task2/git-ai-task2

cargo fmt --check
cargo test test_model_session_id_splits_models_but_preserves_conversation_input
cargo test provider_reader_uses_external_id_for_non_shared_streams
cargo test opencode_wrapped_session_events_contribute_tokens_and_model
cargo test test_revert_restores_ai_attribution_inherited_from_multiple_notes
```

The revert test launches a real isolated Git/daemon fixture. In a restricted
sandbox it may stall because local socket/process communication is blocked; run
it from a normal Terminal session when that occurs.

Run only the tests relevant to the change during development. Run the complete
suite before a final PR or merge:

```bash
cargo test
```

If formatting fails, apply formatting and inspect the resulting diff:

```bash
cargo fmt
git diff --check
git diff
```

## 2. Build and install the patched binary

`task dev` builds the debug binary, installs it into `~/.git-ai/bin`, and refreshes
supported hooks/extensions. Stop the old daemon first so the next launch definitely
uses the new binary.

```bash
cd /Users/manishmahajan/Documents/Codex/2026-07-21/hi/outputs/Task2/git-ai-task2

git-ai bg shutdown --hard
task dev

which git-ai
git-ai --version
~/.git-ai/bin/git-ai --version
```

Use `cargo build` only when a build without installation is wanted. It is not
necessary immediately before `task dev`, because `task dev` builds again.

## 3. Configure a controlled TrackAI experiment

Run the repository enrollment command from the lab repository so `.` resolves to
the correct Git remote. Never print or paste the API key.

```bash
cd /Users/manishmahajan/Documents/Codex/2026-07-21/hi/outputs/git-ai-teamz-lab-vscode

git-ai config set allow_repositories .
git-ai config --add feature_flags.transcript_streaming true
git-ai config --add feature_flags.transcript_sweep false
git-ai config set transcript_streaming_lookback_days 1
```

Why these settings:

- `allow_repositories`: prevents unrelated repositories on the machine from producing telemetry.
- `transcript_streaming=true`: processes the transcript associated with a checkpoint.
- `transcript_sweep=false`: prevents broad historical scanning of Codex, Gemini, and other agents.
- The API base URL and API key should remain configured for the local TrackAI API; do not display the key.

Safe verification:

```bash
git-ai config allow_repositories
git-ai config api_base_url
git-ai config feature_flags
```

## 4. Launch or restart the Git AI background service

Most repository commands start the daemon automatically. After installing a new
binary or changing feature flags, force a clean restart:

```bash
cd /Users/manishmahajan/Documents/Codex/2026-07-21/hi/outputs/git-ai-teamz-lab-vscode

git-ai bg shutdown --hard
git-ai status --json
git-ai bg status
```

Routine background-service commands:

```bash
git-ai bg status
git-ai bg shutdown --hard
git-ai await --timeout 60
```

`git-ai await` drains checkpoint/transcript work and attempts to upload pending
metrics. It does not prove that a particular agent supplied token evidence.

## 5. Inspect a controlled experiment

Before the AI edit, record the current maximum metric ID:

```bash
sqlite3 -readonly ~/.git-ai/internal/metrics-db \
  "SELECT COALESCE(MAX(id), 0) FROM metrics;"
```

After the edit:

```bash
git-ai status --json
git-ai await --timeout 60
```

Replace `BASELINE_ID` with the recorded number:

```bash
sqlite3 -readonly ~/.git-ai/internal/metrics-db \
  "SELECT event_kind,
          tool,
          SUM(delivered_ts IS NULL) AS pending,
          SUM(delivered_ts IS NOT NULL) AS delivered,
          COUNT(*) AS total
     FROM metrics
    WHERE id > BASELINE_ID
    GROUP BY event_kind, tool
    ORDER BY event_kind, tool;"
```

Relevant event kinds:

| Kind | Meaning |
|---:|---|
| 1 | Commit |
| 2 | Agent/session usage marker |
| 4 | Checkpoint and line attribution |
| 5 | Provider transcript/session event, used by OpenCode usage |
| 6 | OTEL trace, used by VS Code GitHub Copilot usage |
| 7 | Commit rewrite |

`git-ai usage --json` aggregates the entire local metrics database. Do not use its
global total as the controlled experiment result while historical Codex/Gemini
events remain in that database.

## 6. Temporary diagnostics only

Checkpoint debug logs may contain hook metadata. Enable them only while diagnosing
a hook, then disable them again:

```bash
git-ai config --add feature_flags.checkpoint_debug_log true
git-ai bg shutdown --hard
git-ai status --json
```

After the diagnostic:

```bash
git-ai config --add feature_flags.checkpoint_debug_log false
git-ai bg shutdown --hard
git-ai status --json
```

Do not enable `transcript_sweep` for a controlled tenant experiment. It can discover
historical sessions from unrelated agents and repositories.

## 7. Restore/disconnect after local TrackAI testing

When local ingestion should stop:

```bash
git-ai bg shutdown --hard
git-ai config unset api_base_url
git-ai config unset api_key
git-ai config unset allow_repositories
git-ai config --add feature_flags.transcript_streaming false
git-ai config --add feature_flags.transcript_sweep false
git-ai config --add feature_flags.checkpoint_debug_log false
```

Do this only after all pending controlled events have been inspected or delivered.

## 8. Final pre-PR verification

From the Git AI source directory:

```bash
cargo fmt --check
cargo test
git diff --check
git status --short --branch
```

Review and commit only intentional source/test/runbook changes. Local databases,
provider transcripts, API keys, debug logs, and lab experiment files must not be
committed to the Git AI OSS branch.
