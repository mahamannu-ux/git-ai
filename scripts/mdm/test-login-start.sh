#!/usr/bin/env bash
# End-to-end lifecycle test for mdm/macos/install-login-start.sh.
#
# Installs git-ai into $HOME, registers the login start, simulates the login
# trigger, and checks that the daemon (a) comes up, (b) survives the launcher
# exiting, and (c) the login mechanism stays healthy throughout, including a
# re-trigger (idempotency), an unusual --bin path, and the login-time lock race
# covered by `bg start --retry-secs`.
#
# Usage: test-login-start.sh lifecycle
#
# Environment:
#   BINARY_SOURCE          local (default) | release
#   GIT_AI_LOCAL_BINARY    binary to install when BINARY_SOURCE=local
#   GIT_AI_RELEASE_TAG     release tag to install when BINARY_SOURCE=release
#                          (empty = latest)
#   MDM_TEST_LOG_DIR       where daemon logs are copied (default $RUNNER_TEMP/mdm-logs)
#
# Task9b scope: macOS lifecycle only. There is no auto-update scenario, no
# --env tuning surface (the launchers carry no configuration; Task9c owns it),
# and no Linux coverage. Ported from upstream snapshot
# 0670e7ef27590af0e8ff5409267f3f4b09b8fcb4 (same Apache-2.0 project) with the
# Linux, auto-update, and configuration-transport surface removed.
set -euo pipefail

SCENARIO="${1:-lifecycle}"
BINARY_SOURCE="${BINARY_SOURCE:-local}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_OUT="${MDM_TEST_LOG_DIR:-${RUNNER_TEMP:-/tmp}/mdm-logs}"
BIN="$HOME/.git-ai/bin/git-ai"
DAEMON_DIR="$HOME/.git-ai/internal/daemon"
LABEL="com.usegitai.bg"

[ "$SCENARIO" = "lifecycle" ] || { echo "unsupported scenario: $SCENARIO (Task9b runs lifecycle only)" >&2; exit 1; }
case "$(uname -s)" in
  Darwin) ;;
  *) echo "unsupported OS: $(uname -s) (Task9b covers macOS here; see test-login-start.ps1 for Windows)" >&2; exit 1 ;;
esac
MDM_SCRIPT="$REPO_ROOT/mdm/macos/install-login-start.sh"

log() { printf '[mdm-test] %s\n' "$*"; }
fail() { printf '[mdm-test] FAIL: %s\n' "$*" >&2; exit 1; }

# --- helpers -----------------------------------------------------------------

install_binary() {
  case "$BINARY_SOURCE" in
    local)
      [ -x "${GIT_AI_LOCAL_BINARY:-}" ] || fail "GIT_AI_LOCAL_BINARY must point at a built git-ai"
      GIT_AI_LOCAL_BINARY="$GIT_AI_LOCAL_BINARY" bash "$REPO_ROOT/install.sh"
      ;;
    release)
      if [ -n "${GIT_AI_RELEASE_TAG:-}" ]; then
        GIT_AI_RELEASE_TAG="$GIT_AI_RELEASE_TAG" bash "$REPO_ROOT/install.sh"
      else
        bash "$REPO_ROOT/install.sh"
      fi
      ;;
    *) fail "BINARY_SOURCE must be local or release" ;;
  esac
  [ -x "$BIN" ] || fail "$BIN missing after install"
  log "installed $("$BIN" --version | head -1)"
}

daemon_pid() {
  jq -r '.pid // empty' "$DAEMON_DIR/daemon.pid.json" 2>/dev/null || true
}

pid_alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }

STATUS_REPO="$(mktemp -d)"
git -C "$STATUS_REPO" init -q

daemon_up() {
  local pid
  pid="$(daemon_pid)"
  pid_alive "$pid" && (cd "$STATUS_REPO" && "$BIN" bg status >/dev/null 2>&1)
}

# wait_for <seconds> <description> <command...>
wait_for() {
  local secs="$1" what="$2"; shift 2
  local deadline=$((SECONDS + secs))
  until "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || fail "timed out after ${secs}s waiting for $what"
    sleep 1
  done
  log "$what"
}

# Only daemons under this HOME: a developer box may run its own git-ai daemon.
no_daemon_process() { ! pgrep -f "^$HOME/.*git-ai bg run" >/dev/null; }

# `bg shutdown` returns before the old process has released the daemon lock;
# a login start racing that window would have to retry.
stop_daemon() {
  "$BIN" bg shutdown >/dev/null 2>&1 || true
  wait_for 30 "previous daemon exited" no_daemon_process
}

daemon_command_line() { ps -p "$(daemon_pid)" -o args= 2>/dev/null || true; }

run_mdm_script() {
  sh "$MDM_SCRIPT" "$@"
}

registered() {
  [ -f "$HOME/Library/LaunchAgents/$LABEL.plist" ] && launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1
}

# Re-fires the login trigger while the daemon is up; must be a no-op.
trigger_login() {
  launchctl kickstart "gui/$(id -u)/$LABEL"
}

launcher_exited() { launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | grep -q "state = not running"; }

mechanism_sane() {
  launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || fail "launchd job missing"
  # The daemon answers before `bg start` returns and launchd notices; give
  # the launcher a moment to exit rather than asserting instantly.
  wait_for 20 "launcher exited" launcher_exited
  if launchctl print "gui/$(id -u)/$LABEL" | grep -E "last exit code = [1-9]"; then
    fail "launchd job exited non-zero"
  fi
  log "login mechanism healthy"
}

lint_definition() {
  plutil -lint "$HOME/Library/LaunchAgents/$LABEL.plist"
}

cleanup() {
  local rc=$?
  set +e
  mkdir -p "$LOG_OUT"
  cp -R "$DAEMON_DIR/logs" "$LOG_OUT/daemon-logs" 2>/dev/null
  launchctl print "gui/$(id -u)/$LABEL" >"$LOG_OUT/launchctl-print.txt" 2>&1
  run_mdm_script --uninstall >/dev/null 2>&1
  [ -x "$BIN" ] && "$BIN" bg shutdown >/dev/null 2>&1
  rm -rf "$STATUS_REPO"
  exit "$rc"
}
trap cleanup EXIT

# --- scenarios ---------------------------------------------------------------

register_and_wait_for_daemon() {
  run_mdm_script "$@"
  registered || fail "login start not registered after install"
  wait_for 30 "daemon up after login trigger" daemon_up
}

scenario_lifecycle() {
  install_binary
  # Keep the uptime restart deterministic: no network update checks.
  "$BIN" config set disable_auto_updates true
  stop_daemon

  register_and_wait_for_daemon
  local pid1; pid1="$(daemon_pid)"

  sleep 10
  pid_alive "$pid1" || fail "daemon $pid1 died after the launcher exited (process group torn down?)"
  daemon_up || fail "daemon not answering after launcher exit"
  log "daemon survived launcher exit"

  trigger_login
  sleep 3
  daemon_up || fail "daemon unhealthy after re-trigger"
  [ "$(daemon_pid)" = "$pid1" ] || fail "re-triggering login restarted the daemon (pid $pid1 -> $(daemon_pid))"
  mechanism_sane
  log "re-triggered login start was a no-op"

  lint_definition

  run_mdm_script --uninstall
  ! registered || fail "login start still registered after --uninstall"
  log "uninstall clean"

  stop_daemon
  scenario_unusual_binary_path
  scenario_launcher_retry
}

# --bin must cope with every path an admin might install to: spaces, quotes,
# parentheses, percent signs, non-ASCII.
scenario_unusual_binary_path() {
  local dir="$HOME/mdm test (weird) 100% 'quoted' ünïcode"
  mkdir -p "$dir"
  cp "$BIN" "$dir/git-ai"

  run_mdm_script --bin "$dir/git-ai"
  registered || fail "login start not registered with unusual --bin"
  wait_for 30 "daemon up from unusual binary path" daemon_up
  case "$(daemon_command_line)" in
    *"$dir/git-ai"*) log "daemon runs from the unusual path" ;;
    *) fail "daemon command line does not reference $dir: $(daemon_command_line)" ;;
  esac
  mechanism_sane

  run_mdm_script --uninstall
  stop_daemon
}

# Writes a fake git-ai that always fails and counts its invocations in $2.
write_failing_binary() {
  local path="$1" attempts="$2"
  cat >"$path" <<EOF
#!/bin/sh
n=\$(cat "$attempts" 2>/dev/null || echo 0); echo "\$((n + 1))" >"$attempts"
exit 1
EOF
  chmod +x "$path"
}

# Holds the daemon lock for $1 seconds in the background, the state a login
# start sees while a previous daemon is still shutting down.
hold_daemon_lock() {
  mkdir -p "$DAEMON_DIR"
  python3 - "$DAEMON_DIR/daemon.lock" "$1" <<'PY' &
import fcntl, sys, time
handle = open(sys.argv[1], "w")
fcntl.flock(handle, fcntl.LOCK_EX)
time.sleep(float(sys.argv[2]))
PY
}

mechanism_failed() {
  launchctl print "gui/$(id -u)/$LABEL" | grep -Eq "last exit code = [1-9]"
}

# Runs the registered launcher once; the login mechanism itself must report failure.
trigger_login_expect_failure() {
  launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$LABEL.plist"
}

# `bg start --retry-secs` must ride out a lock held at login, and a binary that
# keeps failing must surface as a failed login start.
supports_retry() { "$BIN" bg --help 2>&1 | grep -q -- --retry-secs; }

scenario_launcher_retry() {
  if supports_retry; then
    hold_daemon_lock 4
    local holder=$!
    sleep 1
    run_mdm_script
    wait_for 45 "daemon up despite a lock held at login" daemon_up
    wait "$holder" || true
    mechanism_sane
    run_mdm_script --uninstall
    stop_daemon
  else
    # Published releases without --retry-secs cannot ride out the lock race.
    log "SKIP held-lock phase: installed version predates bg start --retry-secs"
  fi

  local fake_dir="$HOME/mdm-fake" attempts="$HOME/mdm-fake/attempts"
  mkdir -p "$fake_dir"
  rm -f "$attempts"
  write_failing_binary "$fake_dir/git-ai" "$attempts"
  run_mdm_script --bin "$fake_dir/git-ai" --no-start
  trigger_login_expect_failure
  wait_for 45 "persistent launcher failure reported by the login mechanism" mechanism_failed
  [ "$(cat "$attempts")" = 1 ] || fail "launcher should invoke the binary once, got $(cat "$attempts")"
  daemon_up && fail "no daemon should be running after persistent failure"
  run_mdm_script --uninstall
  log "launcher retry semantics verified"
}

scenario_lifecycle
log "PASS lifecycle on macos"
