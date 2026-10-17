#!/bin/sh
# Task20b: extract Numbat's agent-coverage table verbatim for TrackAI's
# server-side coverage data (TASK20 section 1 item 9 licence plan).
#
# Usage: extract-coverage.sh <numbat-checkout> <out-file>
#
# Copies the "Matrix", "Permission and decision telemetry" and "Managed hooks"
# sections of docs/agent-coverage.md verbatim. Prepends a header naming the
# source, commit and Apache-2.0. Commit one output per pin as
# packaging/numbat/coverage/<version>.md.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <numbat-checkout> <out-file>" >&2
    exit 2
fi

checkout=$1
out_file=$2

src="$checkout/docs/agent-coverage.md"
if [ ! -f "$src" ]; then
    echo "extract-coverage.sh: $src not found (is this the numbat checkout?)" >&2
    exit 1
fi

# Sources this folder's pin.env; follow requires -x run from this directory.
# But the checkout may be a different pin than packaging/numbat/pin.env, so the
# header commit is taken from what the checkout actually is.
commit=$(git -C "$checkout" rev-parse HEAD)
branch_name=$(git -C "$checkout" describe --tags --exact-match HEAD 2>/dev/null || echo "unknown")

tmp=$(mktemp -d "${TMPDIR:-/tmp}/numbat-coverage.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

# Extract the three wanted sections with awk: from a "## <name>" heading to
# the next "## " heading, for: Matrix, Permission and decision telemetry,
# Managed hooks.
for section in "Matrix" "Permission and decision telemetry" "Managed hooks"; do
    awk -v want="$section" '
        /^## / {
            keep = (substr($0, 4) == want)
        }
        keep { print }
    ' "$src" >>"$tmp/body.md"
done

if [ ! -s "$tmp/body.md" ]; then
    echo "extract-coverage.sh: no wanted sections found" >&2
    exit 1
fi

{
    echo "<!-- Extracted by TrackAI packaging/numbat/extract-coverage.sh. -->"
    echo "<!-- Source sections copied verbatim; do not edit the copied body here. -->"
    echo "Source: perplexityai/numbat @$commit (tag: $branch_name)"
    echo "Licence: Apache-2.0 (see the Numbat LICENSE and"
    echo "THIRD_PARTY_LICENSES.txt shipped next to the built numbat binary)."
    echo "Sections: Matrix, Permission and decision telemetry, Managed hooks"
    echo "of docs/agent-coverage.md."
    echo
    cat "$tmp/body.md"
} >"$out_file"

echo "extracted: $out_file"
