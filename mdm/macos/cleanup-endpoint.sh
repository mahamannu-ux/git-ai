#!/bin/sh
# Explicit, dry-run-first TrackAI endpoint cleanup for one macOS user.
#
# Usage:
#   cleanup-endpoint.sh [--dry-run] [--apply] [--bin PATH]
#
# The default is --dry-run: print the bounded cleanup plan and change nothing.
# --apply first removes the login-start registration via install-login-start.sh
# --uninstall (best effort), then runs `git-ai fleet cleanup --apply`, which
# removes only Task9-owned state: the TrackAI machine credential, managed
# bootstrap/configuration state and login-start registration.
#
# Preserved: evidence queue, authorship notes, repositories, user login
# credentials, ordinary GitAI data and the GitAI binary. This script never
# erases ~/.git-ai wholesale and never uninstalls git-ai. Run as the logged-in
# user, not as root (per-user only). MDM transports this command; MDM state
# itself is not authority. There is no Linux support.
set -eu

MODE="dry-run"
BIN=""

usage() {
  cat <<'USAGE'
Usage:
  cleanup-endpoint.sh [--dry-run] [--apply] [--bin PATH]

Explicit TrackAI endpoint cleanup (default --dry-run). Run as the logged-in
user, not as root.
USAGE
}

fail() {
  echo "git-ai cleanup-endpoint: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --apply) MODE="apply" ;;
    --bin) shift; [ $# -gt 0 ] || fail "--bin requires a path"; BIN="$1" ;;
    --bin=*) BIN="${1#--bin=}" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
  shift
done

[ "$(id -u)" -ne 0 ] || fail "run this as the logged-in user, not as root (per-user only)"

if [ -n "$BIN" ]; then
  case "$BIN" in
    /*) ;;
    *) fail "--bin must be an absolute path" ;;
  esac
  [ -x "$BIN" ] || fail "$BIN is not an executable git-ai binary"
  case "$BIN" in
    *"
"*) fail "--bin path must not contain a newline or carriage return" ;;
  esac
else
  BIN="$HOME/.git-ai/bin/git-ai"
  [ -x "$BIN" ] || fail "$BIN not found; install git-ai first or pass --bin"
fi

if [ "$MODE" = "dry-run" ]; then
  exec "$BIN" fleet cleanup --dry-run
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# Propagate uninstall failure instead of masking it: a remaining LaunchAgent
# with a successful cleanup report would be a false success. Cleanup still
# runs so one failing half never blocks the other, and the exit code tells
# MDM to retry.
UNINSTALL_STATUS=0
CLEANUP_STATUS=0
if [ -x "$SCRIPT_DIR/install-login-start.sh" ]; then
  "$SCRIPT_DIR/install-login-start.sh" --uninstall 2>/dev/null || UNINSTALL_STATUS=$?
fi
"$BIN" fleet cleanup --apply || CLEANUP_STATUS=$?
if [ "$UNINSTALL_STATUS" -ne 0 ] || [ "$CLEANUP_STATUS" -ne 0 ]; then
  echo "git-ai cleanup-endpoint: incomplete (uninstall=$UNINSTALL_STATUS cleanup=$CLEANUP_STATUS)" >&2
  exit 1
fi
exit 0
