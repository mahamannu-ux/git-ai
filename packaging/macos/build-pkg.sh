#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: build-pkg.sh --binary <path> --numbat-dir <Task20b target dir> --trust-dir <path> --arch <x64|arm64> --version <version> --output <path> [--debug-dev-pins]
USAGE
}

BINARY=""
ARCH=""
VERSION=""
OUTPUT=""
NUMBAT_DIR=""
TRUST_DIR=""
DEBUG_DEV_PINS=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --arch) ARCH="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --numbat-dir) NUMBAT_DIR="${2:-}"; shift 2 ;;
    --trust-dir) TRUST_DIR="${2:-}"; shift 2 ;;
    --debug-dev-pins) DEBUG_DEV_PINS=1; shift ;;
    *) usage; exit 2 ;;
  esac
done

[ -n "$BINARY" ] && [ -n "$NUMBAT_DIR" ] && [ -n "$TRUST_DIR" ] && [ -n "$ARCH" ] && [ -n "$VERSION" ] && [ -n "$OUTPUT" ] || { usage; exit 2; }
[ -f "$BINARY" ] || { echo "binary not found: $BINARY" >&2; exit 1; }
[ -f "$NUMBAT_DIR/numbat" ] && [ -f "$NUMBAT_DIR/LICENSE" ] && [ -f "$NUMBAT_DIR/THIRD_PARTY_LICENSES.txt" ] && [ -f "$NUMBAT_DIR/PROVENANCE.txt" ] || { echo "incomplete Numbat build: $NUMBAT_DIR" >&2; exit 1; }
[ -f "$(dirname "$NUMBAT_DIR")/SHA256SUMS" ] || { echo "missing Numbat SHA256SUMS" >&2; exit 1; }
[ -f "$TRUST_DIR/root.json" ] || { echo "missing trust root.json" >&2; exit 1; }
if [ "$DEBUG_DEV_PINS" -eq 1 ]; then
  [ -f "$TRUST_DIR/dev-pins.json" ] || { echo "missing debug dev-pins.json" >&2; exit 1; }
fi

case "$ARCH" in
  x64|arm64) ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 2 ;;
esac
case "$ARCH:$(basename "$NUMBAT_DIR")" in
  x64:numbat_*_darwin_amd64|arm64:numbat_*_darwin_arm64) ;;
  *) echo "Numbat target does not match macOS package architecture" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$ROOT/target/package/pkg-$ARCH"
SCRIPTS="$WORK_DIR/scripts"
COMPONENT_PKG="$WORK_DIR/git-ai-component.pkg"
OUTPUT_ABS="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUTPUT")"

rm -rf "$WORK_DIR"
mkdir -p "$SCRIPTS" "$(dirname "$OUTPUT_ABS")"
install -m 0755 "$BINARY" "$SCRIPTS/git-ai"
install -m 0755 "$NUMBAT_DIR/numbat" "$SCRIPTS/numbat"
for notice in LICENSE THIRD_PARTY_LICENSES.txt PROVENANCE.txt; do
  install -m 0644 "$NUMBAT_DIR/$notice" "$SCRIPTS/$notice"
done
SUM_ENTRY="$(awk -v name="$(basename "$NUMBAT_DIR")/numbat" '$2 == name { print; count++ } END { if (count != 1) exit 1 }' "$(dirname "$NUMBAT_DIR")/SHA256SUMS")" || { echo "Numbat checksum entry missing or duplicated" >&2; exit 1; }
ACTUAL_SHA="$(shasum -a 256 "$NUMBAT_DIR/numbat" | awk '{print $1}')"
[ "${SUM_ENTRY%% *}" = "$ACTUAL_SHA" ] || { echo "Numbat checksum mismatch" >&2; exit 1; }
printf '%s\n' "$SUM_ENTRY" > "$SCRIPTS/SHA256SUMS"
install -m 0644 "$ROOT/packaging/macos/placeholder.yaml" "$SCRIPTS/placeholder.yaml"
install -m 0644 "$ROOT/packaging/macos/agents.tsv" "$SCRIPTS/agents.tsv"
mkdir -p "$SCRIPTS/trust"
install -m 0644 "$TRUST_DIR/root.json" "$SCRIPTS/trust/root.json"
for document in "$TRUST_DIR"/keyset-*.json; do
  [ -f "$document" ] || continue
  install -m 0644 "$document" "$SCRIPTS/trust/$(basename "$document")"
done
if [ "$DEBUG_DEV_PINS" -eq 1 ]; then
  install -m 0644 "$TRUST_DIR/dev-pins.json" "$SCRIPTS/dev-pins.json"
fi
install -m 0755 "$ROOT/packaging/macos/scripts/preinstall" "$SCRIPTS/preinstall"
install -m 0755 "$ROOT/packaging/macos/scripts/postinstall" "$SCRIPTS/postinstall"
xattr -cr "$SCRIPTS" 2>/dev/null || true

pkgbuild \
  --nopayload \
  --scripts "$SCRIPTS" \
  --identifier "com.git-ai.git-ai" \
  --version "$VERSION" \
  --install-location "/" \
  "$COMPONENT_PKG"

if [ -n "${APPLE_DEVELOPER_ID_INSTALLER_IDENTITY:-}" ]; then
  productsign \
    --sign "$APPLE_DEVELOPER_ID_INSTALLER_IDENTITY" \
    "$COMPONENT_PKG" \
    "$OUTPUT_ABS"
else
  cp "$COMPONENT_PKG" "$OUTPUT_ABS"
fi

echo "Built PKG: $OUTPUT_ABS"
