#!/usr/bin/env bash
# Read-only Task9f macOS conformance planning and artifact inspection.
#
# Usage:
#   macos-conformance.sh [plan]
#   macos-conformance.sh binary --binary /absolute/path/to/git-ai
#   macos-conformance.sh package --package /absolute/path/to/file.pkg \
#     --checksum-file /absolute/path/to/PKG-SHA256SUMS
#
# The script never installs an artifact, accesses native credentials, touches
# launchd, downloads a release, or reads normal GitAI state. Its persistent
# output is bounded metadata under the gitignored target/task9-evidence tree.
set -euo pipefail
umask 077

MODE="plan"
BINARY=""
PACKAGE=""
CHECKSUM_FILE=""

usage() {
  cat >&2 <<'USAGE'
Usage:
  macos-conformance.sh [plan]
  macos-conformance.sh binary --binary /absolute/path/to/git-ai
  macos-conformance.sh package --package /absolute/path/to/file.pkg --checksum-file /absolute/path/to/PKG-SHA256SUMS
USAGE
}

fail_usage() {
  usage
  exit 2
}

if [ "$#" -gt 0 ]; then
  MODE="$1"
  shift
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary)
      [ "$#" -ge 2 ] || fail_usage
      BINARY="$2"
      shift 2
      ;;
    --package)
      [ "$#" -ge 2 ] || fail_usage
      PACKAGE="$2"
      shift 2
      ;;
    --checksum-file)
      [ "$#" -ge 2 ] || fail_usage
      CHECKSUM_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail_usage ;;
  esac
done

case "$MODE" in
  plan)
    [ -z "$BINARY$PACKAGE$CHECKSUM_FILE" ] || fail_usage
    ;;
  binary)
    [ -n "$BINARY" ] && [ -z "$PACKAGE$CHECKSUM_FILE" ] || fail_usage
    ;;
  package)
    [ -z "$BINARY" ] && [ -n "$PACKAGE" ] && [ -n "$CHECKSUM_FILE" ] || fail_usage
    ;;
  *) fail_usage ;;
esac

if [ "$(uname -s)" != "Darwin" ]; then
  echo "task9_conformance status=failed classification=unsupported_host"
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVIDENCE_ROOT="$REPO_ROOT/target/task9-evidence"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
REPORT="$EVIDENCE_ROOT/$RUN_ID.txt"
mkdir -p "$EVIDENCE_ROOT"
WORKSPACE="$(mktemp -d "${TMPDIR:-/tmp}/git-ai-task9f.XXXXXX")"

cleanup() {
  case "$WORKSPACE" in
    "${TMPDIR:-/tmp}"/git-ai-task9f.*) rm -rf "$WORKSPACE" ;;
  esac
}
trap cleanup EXIT

record() {
  printf '%s\n' "$1" >>"$REPORT"
  printf 'task9_conformance %s\n' "$1"
}

command_status() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    record "check=$label status=passed classification=product"
    return 0
  fi
  record "check=$label status=pending_prerequisite classification=artifact_or_tooling"
  return 1
}

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|arm64) ;;
  *)
    record "check=host_architecture status=failed classification=unsupported_architecture"
    exit 2
    ;;
esac
MACOS_VERSION="$(sw_vers -productVersion)"
case "$MACOS_VERSION" in
  *[!0-9.]*)
    record "check=macos_version status=failed classification=environment"
    exit 2
    ;;
esac

record "mode=$MODE status=passed classification=planning"
record "host_os=macos status=passed classification=environment"
record "host_architecture=$ARCH status=passed classification=environment"
record "macos_version=$MACOS_VERSION status=passed classification=environment"

run_plan() {
  local missing=0
  local tool
  for tool in pkgutil codesign spctl xcrun shasum lipo; do
    if command -v "$tool" >/dev/null 2>&1; then
      record "tool=$tool status=passed classification=environment"
    else
      record "tool=$tool status=pending_prerequisite classification=missing_tool"
      missing=1
    fi
  done
  if [ "$missing" -eq 0 ]; then
    record "summary=plan status=passed classification=read_only"
  else
    record "summary=plan status=pending_prerequisite classification=missing_tool"
  fi
}

absolute_file() {
  case "$1" in
    /*) [ -f "$1" ] ;;
    *) return 1 ;;
  esac
}

safe_basename() {
  case "$1" in
    ""|*[!A-Za-z0-9._-]*) return 1 ;;
    *) return 0 ;;
  esac
}

run_binary() {
  if ! absolute_file "$BINARY" || [ ! -x "$BINARY" ]; then
    record "check=binary_input status=failed classification=invalid_input"
    exit 2
  fi

  local name digest architectures isolated_output version
  name="$(basename "$BINARY")"
  safe_basename "$name" || {
    record "check=binary_name status=failed classification=invalid_input"
    exit 2
  }
  digest="$(LC_ALL=C LANG=C shasum -a 256 "$BINARY" | awk '{print $1}')"
  case "$digest" in
    [0-9a-f][0-9a-f]*) ;;
    *)
      record "check=binary_digest status=failed classification=tooling"
      exit 1
      ;;
  esac
  record "artifact=binary sha256=$digest status=passed classification=read_only"

  if architectures="$(lipo -archs "$BINARY" 2>/dev/null)"; then
    case "$architectures" in
      x86_64|arm64|"x86_64 arm64"|"arm64 x86_64")
        record "binary_architectures=${architectures// /,} status=passed classification=artifact"
        ;;
      *)
        record "check=binary_architecture status=failed classification=artifact"
        exit 1
        ;;
    esac
  else
    record "check=binary_architecture status=failed classification=artifact"
    exit 1
  fi

  mkdir -p "$WORKSPACE/bin" "$WORKSPACE/home" "$WORKSPACE/tmp"
  local ISOLATED_BINARY="$WORKSPACE/bin/git-ai"
  cp "$BINARY" "$ISOLATED_BINARY"
  chmod 0755 "$ISOLATED_BINARY"
  isolated_output="$(
    env -i \
      HOME="$WORKSPACE/home" \
      PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
      TMPDIR="$WORKSPACE/tmp" \
      GIT_AI_TEST_DB_PATH="$WORKSPACE/git-ai.db" \
      "$ISOLATED_BINARY" --version 2>/dev/null | head -n 1
  )"
  if [[ "$isolated_output" =~ ^(git-ai[[:space:]])?([0-9]+\.[0-9]+\.[0-9]+)([[:space:]]\((debug|release)\))?$ ]]; then
    version="${BASH_REMATCH[2]}"
    record "binary_version=$version status=passed classification=isolated_execution"
  else
    record "check=binary_version status=failed classification=artifact"
    exit 1
  fi

  command_status binary_signature codesign --verify --strict "$BINARY" || true
  record "summary=binary status=passed classification=read_only"
}

run_package() {
  if ! absolute_file "$PACKAGE" || ! absolute_file "$CHECKSUM_FILE"; then
    record "check=package_input status=failed classification=invalid_input"
    exit 2
  fi

  local name digest expected signature_ok=0 gatekeeper_ok=0 staple_ok=0
  name="$(basename "$PACKAGE")"
  safe_basename "$name" || {
    record "check=package_name status=failed classification=invalid_input"
    exit 2
  }
  case "$name" in
    *.pkg) ;;
    *)
      record "check=package_extension status=failed classification=invalid_input"
      exit 2
      ;;
  esac

  digest="$(LC_ALL=C LANG=C shasum -a 256 "$PACKAGE" | awk '{print $1}')"
  expected="$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1; exit }' "$CHECKSUM_FILE")"
  if [ -z "$expected" ] || [ "$digest" != "$expected" ]; then
    record "check=package_checksum status=failed classification=artifact"
    exit 1
  fi
  record "artifact=package sha256=$digest status=passed classification=read_only"
  record "check=package_checksum status=passed classification=artifact"

  command_status package_signature pkgutil --check-signature "$PACKAGE" && signature_ok=1 || true
  command_status package_gatekeeper spctl -a -t install "$PACKAGE" && gatekeeper_ok=1 || true
  command_status package_staple xcrun stapler validate "$PACKAGE" && staple_ok=1 || true

  if [ "$signature_ok" -eq 1 ] && [ "$gatekeeper_ok" -eq 1 ] && [ "$staple_ok" -eq 1 ]; then
    record "summary=package status=passed classification=signed_notarized"
  else
    record "summary=package status=pending_prerequisite classification=unsigned_or_unnotarized"
  fi
}

case "$MODE" in
  plan) run_plan ;;
  binary) run_binary ;;
  package) run_package ;;
esac

record "workspace_cleanup=scheduled status=passed classification=isolated"
