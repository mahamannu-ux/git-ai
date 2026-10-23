#!/bin/sh
# Explicit, dry-run-first TrackAI endpoint cleanup for one macOS user.
#
# Usage:
#   cleanup-endpoint.sh [--dry-run] [--apply] [--bin PATH] [--user NAME]
#
# The default is --dry-run: print the bounded cleanup plan and change nothing.
# --apply removes security hooks and files when run as root, then removes the
# login-start registration and runs `git-ai fleet cleanup --apply` for the user.
#
# Root apply removes managed Numbat hooks before its binary and the selected
# user's security state. The user's ~/.numbat remains theirs. Non-root apply
# retains the legacy Task9 cleanup route when no managed Numbat is installed.
set -eu

MODE="dry-run"
BIN=""
TARGET_USER=""
NUMBAT_ADMIN_DIR="/Library/Application Support/TrackAI/Endpoint"
NUMBAT_BIN="$NUMBAT_ADMIN_DIR/bin/numbat"
RECEIPT_ID="com.git-ai.git-ai"

usage() {
  cat <<'USAGE'
Usage:
  cleanup-endpoint.sh [--dry-run] [--apply] [--bin PATH] [--user NAME]

Explicit TrackAI endpoint cleanup (default --dry-run). MDM runs --apply as
root for managed hooks; --user selects the target account.
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
    --user) shift; [ $# -gt 0 ] || fail "--user requires a name"; TARGET_USER="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
  shift
done

if [ "$(id -u)" -eq 0 ]; then
  if [ -z "$TARGET_USER" ]; then
    TARGET_USER="$(/usr/bin/stat -f%Su /dev/console)"
  fi
  case "$TARGET_USER" in
    ""|root|loginwindow|_mbsetupuser) fail "select a logged-in user with --user" ;;
  esac
  /usr/bin/id "$TARGET_USER" >/dev/null 2>&1 || fail "unknown user $TARGET_USER"
  TARGET_HOME="$(/usr/bin/dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory | /usr/bin/awk 'NR == 1 { print $2 }')"
  case "$TARGET_HOME" in /*) ;; *) fail "could not resolve user home" ;; esac
else
  [ -z "$TARGET_USER" ] || fail "--user requires root"
  TARGET_HOME="$HOME"
fi

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
  BIN="$TARGET_HOME/.git-ai/bin/git-ai"
  [ -x "$BIN" ] || fail "$BIN not found; install git-ai first or pass --bin"
fi

if [ "$MODE" = "dry-run" ]; then
  echo "git-ai cleanup-endpoint: managed hooks=claude,codex,cursor,gemini,copilot"
  echo "git-ai cleanup-endpoint: binary=$NUMBAT_BIN"
  echo "git-ai cleanup-endpoint: security=$TARGET_HOME/.git-ai/internal/security"
  echo "git-ai cleanup-endpoint: preserved=$TARGET_HOME/.numbat"
  echo "git-ai cleanup-endpoint: receipt=$RECEIPT_ID action=forget-after-successful-root-apply"
  if [ "$(id -u)" -eq 0 ]; then
    /usr/bin/sudo -H -u "$TARGET_USER" "$BIN" fleet cleanup --dry-run
  else
    "$BIN" fleet cleanup --dry-run
  fi
  exit $?
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ "$(id -u)" -eq 0 ]; then
  if [ -x "$SCRIPT_DIR/install-login-start.sh" ]; then
    /usr/bin/sudo -H -u "$TARGET_USER" "$SCRIPT_DIR/install-login-start.sh" --uninstall
  fi
  SHUTDOWN_STATUS=0
  /usr/bin/sudo -H -u "$TARGET_USER" "$BIN" bg shutdown 2>/dev/null || SHUTDOWN_STATUS=$?
  DAEMON_STATUS="$(/usr/bin/sudo -H -u "$TARGET_USER" "$BIN" bg status --repo /)" || fail "could not check daemon shutdown"
  printf '%s\n' "$DAEMON_STATUS" | /usr/bin/grep -q '"daemon_running": false' || fail "daemon still running (shutdown=$SHUTDOWN_STATUS); security state retained"
  if [ -x "$NUMBAT_BIN" ]; then
    [ -f "$NUMBAT_ADMIN_DIR/agents.tsv" ] || fail "managed agent map missing; inspect hooks before removing Numbat"
    UNINSTALL_STATUS=0
    while read -r agent source; do
      [ -n "$agent" ] || continue
      "$NUMBAT_BIN" hook uninstall --agent "$agent" --managed || UNINSTALL_STATUS=1
    done < "$NUMBAT_ADMIN_DIR/agents.tsv"
    [ "$UNINSTALL_STATUS" -eq 0 ] || fail "one or more managed hooks remain; Numbat binary and rules retained"
    /bin/rm -rf "$NUMBAT_ADMIN_DIR"
    /bin/rm -rf "$TARGET_HOME/.git-ai/internal/security"
    echo "git-ai cleanup-endpoint: removed managed hooks, $NUMBAT_ADMIN_DIR, $TARGET_HOME/.git-ai/internal/security"
  else
    [ ! -e "$TARGET_HOME/.git-ai/internal/security" ] || fail "Numbat binary missing while security state remains; inspect managed hooks"
    echo "git-ai cleanup-endpoint: managed Numbat already removed"
  fi
  echo "git-ai cleanup-endpoint: preserved $TARGET_HOME/.numbat"
  CLEANUP_STATUS=0
  /usr/bin/sudo -H -u "$TARGET_USER" "$BIN" fleet cleanup --apply || CLEANUP_STATUS=$?
  [ "$CLEANUP_STATUS" -eq 0 ] || exit "$CLEANUP_STATUS"
  if /usr/sbin/pkgutil --pkg-info "$RECEIPT_ID" >/dev/null 2>&1; then
    /usr/sbin/pkgutil --forget "$RECEIPT_ID" >/dev/null || fail "could not forget receipt $RECEIPT_ID"
    echo "git-ai cleanup-endpoint: forgot receipt $RECEIPT_ID"
  else
    echo "git-ai cleanup-endpoint: receipt $RECEIPT_ID already absent"
  fi
  exit 0
fi
[ ! -e "$NUMBAT_BIN" ] || fail "managed Numbat is installed; run cleanup as root for complete offboarding"
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
echo "receipt $RECEIPT_ID retained; rerun as root to forget it"
if [ "$UNINSTALL_STATUS" -ne 0 ] || [ "$CLEANUP_STATUS" -ne 0 ]; then
  echo "git-ai cleanup-endpoint: incomplete (uninstall=$UNINSTALL_STATUS cleanup=$CLEANUP_STATUS)" >&2
  [ "$CLEANUP_STATUS" -eq 0 ] || exit "$CLEANUP_STATUS"
  exit "$UNINSTALL_STATUS"
fi
exit 0
