#!/bin/sh
# Task20b: prove the pin builds bit-for-bit reproducibly twice (IT-T20b-01).
#
# Usage: reproduce.sh <goos> <goarch>
#
# Builds the pin twice into two fresh directories with build.sh and exits 0
# only if both binaries have the same SHA-256. Prints digest and byte size.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <goos> <goarch>" >&2
    exit 2
fi

goos=$1
goarch=$2
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Sources this folder's pin.env; follow requires -x run from this directory.
# shellcheck disable=SC1091
. "$script_dir/pin.env"

repro_root=$(mktemp -d "${TMPDIR:-/tmp}/numbat-repro.XXXXXX")
trap 'rm -rf "$repro_root"' EXIT INT TERM

"$script_dir/build.sh" "$goos" "$goarch" "$repro_root/a" >/dev/null
"$script_dir/build.sh" "$goos" "$goarch" "$repro_root/b" >/dev/null

bin_name=numbat
if [ "$goos" = "windows" ]; then
    bin_name=numbat.exe
fi
pkg="numbat_${NUMBAT_VERSION}_${goos}_${goarch}"
bin_a="$repro_root/a/$pkg/$bin_name"
bin_b="$repro_root/b/$pkg/$bin_name"

for f in "$bin_a" "$bin_b"; do
    if [ ! -x "$f" ]; then
        echo "reproduce.sh: missing build output: $f" >&2
        exit 1
    fi
done

if command -v sha256sum >/dev/null 2>&1; then
    digest_a=$(sha256sum "$bin_a" | awk '{print $1}')
    digest_b=$(sha256sum "$bin_b" | awk '{print $1}')
else
    digest_a=$(shasum -a 256 "$bin_a" | awk '{print $1}')
    digest_b=$(shasum -a 256 "$bin_b" | awk '{print $1}')
fi

echo "digest:  $digest_a"
echo "size:    $(wc -c <"$bin_a") bytes"

if [ "$digest_a" != "$digest_b" ]; then
    echo "reproduce.sh: FAIL digests differ a=$digest_a b=$digest_b" >&2
    exit 1
fi

echo "reproduce: ok ($goos/$goarch identical bytes across two fresh builds)"
