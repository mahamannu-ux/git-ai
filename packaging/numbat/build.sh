#!/bin/sh
# Task20b: build the TrackAI audited Numbat pin reproducibly.
#
# Usage: build.sh <goos> <goarch> <out-dir>
#
# Behaviour contract: upstream goreleaser flags at the pin
# (source: perplexityai/numbat@20a5a52 .goreleaser.yaml, CGO_ENABLED=0,
# -trimpath, -s -w, the internal/version -X flag), plus empty -buildid=
# and -buildvcs=false for bit-for-bit reproducibility on this machine.
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <goos> <goarch> <out-dir>" >&2
    exit 2
fi

goos=$1
goarch=$2
out_dir=$3

case "$goos" in
darwin | linux | windows) ;;
*)
    echo "build.sh: unsupported goos '$goos' (darwin, linux, windows)" >&2
    exit 2
    ;;
esac

case "$goarch" in
amd64 | arm64) ;;
*)
    echo "build.sh: unsupported goarch '$goarch' (amd64, arm64)" >&2
    exit 2
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Sources this folder's pin.env; follow requires -x run from this directory.
# shellcheck disable=SC1091
. "$script_dir/pin.env"

if [ -z "$NUMBAT_MIRROR" ] || [ -z "$NUMBAT_TAG" ] || [ -z "$NUMBAT_COMMIT" ]; then
    echo "build.sh: pin.env is incomplete" >&2
    exit 1
fi

if ! command -v go >/dev/null 2>&1; then
    echo "build.sh: go is not on PATH (need $NUMBAT_GO_VERSION)" >&2
    exit 1
fi

# Refuse unless go reports exactly the pinned toolchain version.
# GOVERSION is the toolchain go itself selects (real, even under 'auto').
got_go=$(go env GOVERSION)
raw_go_version=$(go version 2>/dev/null | awk '{print $3}')
if [ "$got_go" != "$raw_go_version" ]; then
    echo "build.sh: toolchain selection ($got_go) != installed go ($raw_go_version); run with GOTOOLCHAIN=local" >&2
    exit 1
fi
if [ "$got_go" != "$NUMBAT_GO_VERSION" ]; then
    echo "build.sh: go version mismatch (got '$got_go', want '$NUMBAT_GO_VERSION')" >&2
    exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/numbat-build.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT INT TERM
src_dir="$work_dir/numbat"

# Clone the mirror at the pinned tag into a fresh checkout.
git clone --quiet --no-checkout "$NUMBAT_MIRROR" "$src_dir"
git -C "$src_dir" checkout --quiet --detach "$NUMBAT_TAG"

# Refuse unless the checked-out tree is exactly the audited commit.
got_commit=$(git -C "$src_dir" rev-parse HEAD)
if [ "$got_commit" != "$NUMBAT_COMMIT" ]; then
    echo "build.sh: pin mismatch at '$NUMBAT_TAG': HEAD $got_commit, want $NUMBAT_COMMIT" >&2
    exit 1
fi

mkdir -p "$out_dir"
out_dir=$(CDPATH='' cd -- "$out_dir" && pwd)
out_pkg="$out_dir/numbat_${NUMBAT_VERSION}_${goos}_${goarch}"
bin_name=numbat
if [ "$goos" = "windows" ]; then
    bin_name=numbat.exe
fi
binary_src="$out_pkg/numbat_built"

mkdir -p "$out_pkg"
(
    cd "$src_dir"
    CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local \
        GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath -buildvcs=false \
        -o "$binary_src" \
        -ldflags "-s -w -buildid= -X github.com/perplexityai/numbat/internal/version.Version=$NUMBAT_VERSION" \
        ./cmd/numbat
)

mv "$binary_src" "$out_pkg/$bin_name"
out_bin="$out_pkg/$bin_name"

cp "$src_dir/LICENSE" "$out_pkg/LICENSE"
cp "$src_dir/THIRD_PARTY_LICENSES.txt" "$out_pkg/THIRD_PARTY_LICENSES.txt"

build_time=$(TZ=UTC date '+%Y-%m-%dT%H:%M:%SZ')
{
    echo "mirror: $NUMBAT_MIRROR"
    echo "tag: $NUMBAT_TAG"
    echo "commit: $NUMBAT_COMMIT"
    echo "go version: $got_go"
    echo "GOOS: $goos"
    echo "GOARCH: $goarch"
    echo "flags: CGO_ENABLED=0 GOFLAGS=-mod=readonly -trimpath -buildvcs=false -ldflags \"-s -w -buildid= -X github.com/perplexityai/numbat/internal/version.Version=$NUMBAT_VERSION\""
    echo "built at (UTC): $build_time"
} >"$out_pkg/PROVENANCE.txt"

if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$out_bin" | awk '{print $1}')
else
    digest=$(shasum -a 256 "$out_bin" | awk '{print $1}')
fi

sums_file="$out_dir/SHA256SUMS"
touch "$sums_file"
grep -v "numbat_${NUMBAT_VERSION}_${goos}_${goarch}/$bin_name" "$sums_file" >"$sums_file.tmp" || true
mv "$sums_file.tmp" "$sums_file"
printf '%s  numbat_%s_%s_%s/%s\n' "$digest" "$NUMBAT_VERSION" "$goos" "$goarch" "$bin_name" >>"$sums_file"

echo "built: $out_pkg/$bin_name"
echo "sha256: $digest"
echo "size: $(wc -c <"$out_pkg/$bin_name") bytes"
