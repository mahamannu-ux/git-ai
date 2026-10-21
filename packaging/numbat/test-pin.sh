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

# The installer and Endpoint placeholder compile this exact built-in ID list.
# Catch catalogue drift at the pin, before building a package that would fail
# postinstall (or leave the placeholder out of sync with Numbat).
builtin_ids="$work_dir/builtin-rule-ids.txt"
if ! (cd "$src_dir" && CGO_ENABLED=0 GOTOOLCHAIN=local \
        go run ./cmd/numbat rules list) >"$builtin_ids" 2>"$work_dir/rules-list.log"; then
    echo "numbat-tests: failed" >&2
    echo "test-pin.sh: cannot list built-in rules at '$NUMBAT_TAG'" >&2
    cat "$work_dir/rules-list.log" >&2
    exit 1
fi
if ! cmp -s "$builtin_ids" "$script_dir/../macos/builtin-rule-ids.txt"; then
    echo "numbat-tests: failed" >&2
    echo "test-pin.sh: packaging/macos/builtin-rule-ids.txt differs from Numbat at '$NUMBAT_TAG'" >&2
    diff -u "$script_dir/../macos/builtin-rule-ids.txt" "$builtin_ids" >&2 || true
    exit 1
fi

log_file="$work_dir/test.log"
if (cd "$src_dir" && CGO_ENABLED=0 GOTOOLCHAIN=local go test ./...) >"$log_file" 2>&1; then
    echo "numbat-tests: ok $(grep -c '^ok[[:space:]]' "$log_file" || true) packages"
else
    # Targeted retry, and only this: upstream's OpenClaw node-harness test has
    # a hard-coded 500ms child deadline that flakes under machine load
    # (openclaw_runtime_test.go:71-80 at the pin; the failure is a timing
    # artifact of the test harness, not the pin). Retry is allowed only when
    # the first run's failures are exactly that one test — anything else
    # (another test, a panic, a build failure) fails the gate without retry.
    tail -n 40 "$log_file" >&2 || true
    failed_tests=$(grep -c '^--- FAIL:' "$log_file" || true)
    openclaw_fails=$(grep -c '^--- FAIL: TestOpenClawGeneratedPluginRuntime' "$log_file" || true)
    if [ "$failed_tests" -gt "1" ] || [ "$openclaw_fails" -ne "1" ] || grep -q '^panic:' "$log_file"; then
        echo "numbat-tests: failed" >&2
        exit 1
    fi
    echo "test-pin.sh: retrying only TestOpenClawGeneratedPluginRuntime (classified timing flake)" >&2
    if (cd "$src_dir" && CGO_ENABLED=0 GOTOOLCHAIN=local \
            go test ./internal/hook -run 'TestOpenClawGeneratedPluginRuntime') \
        >"$work_dir/retry.log" 2>&1; then
        ok_lines=$(( $(grep -c '^ok[[:space:]]' "$log_file" || true) \
            + $(grep -c '^ok[[:space:]]' "$work_dir/retry.log" || true) ))
        echo "numbat-tests: ok $ok_lines packages (after targeted retry of the upstream timing-flaky OpenClaw node-harness test)"
    else
        tail -n 40 "$work_dir/retry.log" >&2 || true
        echo "numbat-tests: failed" >&2
        exit 1
    fi
fi
