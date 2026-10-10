#!/bin/sh
# Register a per-user launchd LaunchAgent that runs `git-ai bg start` when the
# user logs in, so the Git AI background service is up before the first git
# command.
#
# Usage:
#   install-login-start.sh [install] [--bin PATH] [--no-start]
#   install-login-start.sh --uninstall
#
# The agent only *starts* the daemon. It never supervises it: the daemon
# restarts and updates itself, and a second instance exits because the daemon
# lock is held. See mdm/README.md for the invariants this file must keep.
#
# Task9b scope: per-user only. There is no all-users mode and no configuration
# passthrough; managed configuration belongs to Task9c. Ported from upstream
# snapshot 0670e7ef27590af0e8ff5409267f3f4b09b8fcb4 (same Apache-2.0 project)
# with the configuration-transport, all-users, and Linux surface removed.
set -eu

LABEL="com.usegitai.bg"
DEFAULT_PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
# `bg start --retry-secs` keeps retrying for this long if a previous daemon is
# releasing its lock at login (fast logout/login, self-update in progress).
RETRY_SECS=10

MODE="install"
START=1
BIN=""

usage() {
  cat <<'USAGE'
Usage:
  install-login-start.sh [install] [--bin PATH] [--no-start]
  install-login-start.sh --uninstall

Registers a per-user launchd LaunchAgent (com.usegitai.bg) that runs
`git-ai bg start` at login. Run as the logged-in user.
USAGE
}

fail() {
  echo "git-ai login-start: $*" >&2
  exit 1
}

xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# One indented plist <string> element.
xml_string() {
  printf '        <string>%s</string>\n' "$(xml_escape "$1")"
}

while [ $# -gt 0 ]; do
  case "$1" in
    install) ;;
    --uninstall) MODE="uninstall" ;;
    --no-start) START=0 ;;
    --bin) shift; [ $# -gt 0 ] || fail "--bin requires a path"; BIN="$1" ;;
    --bin=*) BIN="${1#--bin=}" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
  shift
done

[ "$(id -u)" -ne 0 ] || fail "run this as the logged-in user, not as root (per-user only)"

PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
TARGET_USER="$(id -un)"
DOMAIN="gui/$(id -u)"

if [ "$MODE" = "uninstall" ]; then
  if [ -n "$DOMAIN" ]; then
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  fi
  rm -f "$PLIST"
  echo "git-ai login-start: removed $PLIST"
  exit 0
fi

if [ -n "$BIN" ]; then
  case "$BIN" in
    /*) ;;
    *) fail "--bin must be an absolute path" ;;
  esac
  [ -x "$BIN" ] || fail "$BIN is not an executable git-ai binary"
  case "$BIN" in
    *"
"*|*"$(printf '\r')"*) fail "--bin path must not contain a newline or carriage return" ;;
  esac
else
  BIN="$HOME/.git-ai/bin/git-ai"
  [ -x "$BIN" ] || fail "$BIN not found; install git-ai first or pass --bin"
fi

# Run the binary directly so macOS names the login item "git-ai".
PROGRAM_XML="$(xml_string "$BIN")
$(xml_string bg)
$(xml_string start)
$(xml_string --retry-secs)
$(xml_string "$RETRY_SECS")"

# The agent logs `bg start` output. launchd does not load the user's shell
# profile, so the agent carries a fixed safe PATH.
LOG_DIR="$HOME/.git-ai/internal/daemon/logs"
mkdir -p "$LOG_DIR"
LOG_FILE_XML="$(xml_string "$LOG_DIR/login-start.log" | sed 's/^    //')"
LOG_XML="    <key>StandardOutPath</key>
$LOG_FILE_XML
    <key>StandardErrorPath</key>
$LOG_FILE_XML"

ENV_XML="        <key>PATH</key>
$(xml_string "$DEFAULT_PATH")
"

mkdir -p "$(dirname "$PLIST")"
cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
$PROGRAM_XML
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
$LOG_XML
    <key>EnvironmentVariables</key>
    <dict>
${ENV_XML}    </dict>
</dict>
</plist>
EOF

chmod 0644 "$PLIST"

if command -v plutil >/dev/null 2>&1; then
  plutil -lint -s "$PLIST" || fail "generated plist failed validation"
fi

if [ -n "$DOMAIN" ]; then
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  if [ "$START" -eq 1 ]; then
    launchctl bootstrap "$DOMAIN" "$PLIST" || fail "launchctl bootstrap $DOMAIN failed"
  fi
fi

echo "git-ai login-start: installed $PLIST"
