# Git AI login-start helpers (Task9b)

Per-user scripts for managed rollouts that start the Git AI background service
when the user logs in. Without them, the daemon only starts on the first
checkpoint or `git-ai` subcommand, so trace2 events from git commands run
before that point are lost.

| Platform | Script | Mechanism | Release asset |
|---|---|---|---|
| macOS | `macos/install-login-start.sh` | LaunchAgent `com.usegitai.bg` | `git-ai-login-start-macos.sh` |
| Windows | `windows/install-login-start.ps1` | Scheduled Task `\GitAI\Start bg at logon` | `git-ai-login-start-windows.ps1` |

Each release publishes the scripts at
`https://github.com/mahamannu-ux/git-ai/releases/latest/download/<asset>`.
Run them **after** `git-ai` is installed and `git-ai install` has run for the
user (that step writes the per-user trace2 config the daemon depends on).

## Why the scripts only start the daemon

Every script registers the idempotent `git-ai bg start --retry-secs 10` and
nothing else. The retry window covers a previous daemon that is still
releasing its lock at login (fast logout/login, self-update in progress); the
daemon itself supervises everything after that:

- It exits 0 immediately if a daemon is already up, and refuses to start a
  second instance while the daemon **lock** is held.
- It restarts itself after 24.5 hours of uptime and after installing a
  self-update; the exiting process spawns its successor.

A launchd `KeepAlive`, or task-scheduler retry would see the launcher exit,
relaunch it, hit the held lock, and loop. So the launch definitions must never
supervise the daemon, and they must not tear down the processes left behind
when `bg start` exits. `tests/mdm_scripts.rs` pins these invariants:

- **macOS**: `AbandonProcessGroup` is `true` (launchd otherwise kills the
  daemon when `bg start` exits), `KeepAlive` is `false`, `RunAtLoad` is `true`.
  The agent runs the `git-ai` binary directly, so Login Items & Extensions and
  the "can run in the background" notice name `git-ai`, not `sh`.
- **Windows**: `-MultipleInstances IgnoreNew` so a second logon trigger cannot
  race the daemon, and the execution time limit is disabled so Task Scheduler
  never ends the instance.

## Usage

Both scripts share one contract:

```
install-login-start [install] [--bin PATH] [--no-start]
install-login-start --uninstall
```

- `--bin PATH` points at a non-default `git-ai` binary. The path must be
  absolute, must resolve to an executable file, and must not contain a newline
  or carriage return. On macOS it is quoted into the plist; on Windows it is
  quoted into the launcher file.
- `--no-start` registers without starting now; the daemon starts at next login.
- `--uninstall` removes the registration and leaves the running daemon alone.

Both scripts are per-user and idempotent: re-running `install` re-registers
the same definition, and `--no-start` skips the immediate start for imaging
flows. They never enroll a device, fetch policy, transport a credential, prove
MDM enrollment, or grant TrackAI authority — they only arrange a per-user
login start for an already-installed client.

### macOS

Run as the console user:

```sh
su - "$(/usr/bin/stat -f%Su /dev/console)" -c \
  'curl -fsSL https://github.com/mahamannu-ux/git-ai/releases/latest/download/git-ai-login-start-macos.sh | sh'
```

The agent's `PATH` is fixed inside the script because launchd does not load
the user's shell profile. `bg start` output goes to
`~/.git-ai/internal/daemon/logs/login-start.log`.

### Windows

Run in the user's context from a non-elevated shell:

```powershell
irm https://github.com/mahamannu-ux/git-ai/releases/latest/download/git-ai-login-start-windows.ps1 | iex
```

Piped installs use the defaults. To pass flags, download the file and run it.
The task runs a small launcher at `%USERPROFILE%\.git-ai\login\start-bg.ps1`
that calls `bg start` directly.

## Boundaries

- Per-user only. There is no all-users install mode in these scripts.
- No environment or configuration passthrough. Managed configuration and OS
  secret-store bootstrap resume in Task9c.
- Jamf and Intune remain delivery systems, not TrackAI authorities:
  documentation may describe uploading the release PKG/MSI and post-login
  installation, but enrollment and configuration resume in Task9c and live
  tenant evidence remains pending.

## Verifying

Log in, then run `git-ai bg status` from inside any git repository before
issuing other git commands. It should report a healthy daemon. Platform state:

- macOS: `launchctl print gui/$(id -u)/com.usegitai.bg`
- Windows: `Get-ScheduledTaskInfo -TaskPath '\GitAI\' -TaskName 'Start bg at logon'`

## Tests

- `tests/mdm_scripts.rs`: static invariants above (`task test CARGO_TEST_ARGS="--test mdm_scripts"`).
- `scripts/mdm/test-login-start.{sh,ps1}`: end-to-end lifecycle on each OS.
  Run per PR by `.github/workflows/mdm-login-start.yml` on macOS and Windows
  with a locally built binary.

Ported from upstream snapshot `0670e7ef27590af0e8ff5409267f3f4b09b8fcb4`
(same Apache-2.0 project): per-user subset with the Linux, nightly, and
configuration-transport surface excluded.
