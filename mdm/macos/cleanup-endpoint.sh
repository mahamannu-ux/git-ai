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
if [ -x "$SCRIPT_DIR/install-login-start.sh" ]; then
  "$SCRIPT_DIR/install-login-start.sh" --uninstall 2>/dev/null || true
fi
exec "$BIN" fleet cleanup --apply
