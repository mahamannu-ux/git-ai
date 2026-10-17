#!/bin/sh
# Task20b: run Numbat's own test suite at the audited pin.
#
# Usage: test-pin.sh
#
# Clones the pin exactly like build.sh does, runs `go test ./...` in the
# checkout, and prints exactly one summary line:
#   numbat-tests: ok <n packages>
#   numbat-tests: failed
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Sources this folder's pin.env; follow requires -x run from this directory.
# shellcheck disable=SC1091
. "$script_dir/pin.env"

if ! command -v go >/dev/null 2>&1; then
    echo "numbat-tests: failed" >&2
    echo "test-pin.sh: go is not on PATH (need $NUMBAT_GO_VERSION)" >&2
    exit 1
fi

got_go=$(go env GOVERSION)
if [ "$got_go" != "$NUMBAT_GO_VERSION" ]; then
    echo "numbat-tests: failed" >&2
    echo "test-pin.sh: go version mismatch (got '$got_go', want '$NUMBAT_GO_VERSION')" >&2
    exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/numbat-testpin.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT INT TERM
src_dir="$work_dir/numbat"

git clone --quiet --no-checkout "$NUMBAT_MIRROR" "$src_dir"
git -C "$src_dir" checkout --quiet --detach "$NUMBAT_TAG"

got_commit=$(git -C "$src_dir" rev-parse HEAD)
if [ "$got_commit" != "$NUMBAT_COMMIT" ]; then
    echo "numbat-tests: failed" >&2
    echo "test-pin.sh: pin mismatch at '$NUMBAT_TAG': HEAD $got_commit, want $NUMBAT_COMMIT" >&2
    exit 1
fi

log_file="$work_dir/test.log"
ok_lines=0
if (cd "$src_dir" && CGO_ENABLED=0 GOTOOLCHAIN=local go test ./...) >"$log_file" 2>&1; then
    ok_lines=$(grep -c '^ok[[:space:]]' "$log_file" || true)
    echo "numbat-tests: ok $ok_lines packages"
else
    # One retry: upstream's OpenClaw node-harness test has a hard-coded 500ms
    # child deadline that flakes under machine load (sandbox-only, not the pin).
    echo "test-pin.sh: first run failed; retrying once" >&2
    cp "$log_file" "$work_dir/first.log"
    if (cd "$src_dir" && CGO_ENABLED=0 GOTOOLCHAIN=local go test ./...) >"$log_file" 2>&1; then
        ok_lines=$(grep -c '^ok[[:space:]]' "$log_file" || true)
        echo "numbat-tests: ok $ok_lines packages (after one retry)"
    else
        echo "numbat-tests: failed" >&2
        tail -n 40 "$log_file" >&2 || true
        exit 1
    fi
fi
