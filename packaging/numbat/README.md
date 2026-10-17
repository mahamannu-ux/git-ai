# packaging/numbat — TrackAI's reproducible Numbat build (Task20b)

TrackAI ships [Numbat](https://github.com/perplexityai/numbat) (Apache-2.0) **unchanged** inside the TrackAI Endpoint: the binary is built from our audited mirror fork at a pinned commit, with no product changes (TrackAI `docs/plan/TASK20.md` §1 item 1).

**Powered by Numbat (Apache-2.0).** The built binary is redistributed with Numbat's own `LICENSE` and `THIRD_PARTY_LICENSES.txt` (copied byte-for-byte from the checkout at the pin). Numbat's per-dependency notices travel with it because they are compiled into the binary (see TrackAI `docs/TASK6_SECURITY_NUMBAT_LICENSE_PLAN.md`, section "Task20: binary redistribution").

The binaries produced by these scripts are **not code-signed**: checks are recorded here, and Task20h (package and install) and Task14 apply package-level signing and notarization later.

Source of the behaviour contract: `perplexityai/numbat@20a5a52 .goreleaser.yaml` (build flags: `CGO_ENABLED=0`, `-trimpath`, `-s -w`, the internal/version `-X` flag; recorded here per agreements), plus audit-required exact-commit and toolchain-version checks added in build.sh.

## The pin

`pin.env` defines the audited pin read by every script:

| Variable | Value |
|---|---|
| `NUMBAT_MIRROR` | `https://github.com/mahamannu-ux/numbat.git` |
| `NUMBAT_TAG` | `v0.2.0-trackai.1` |
| `NUMBAT_COMMIT` | `20a5a52bab41c9bf6ee857efd43c7b198b055de5` |
| `NUMBAT_VERSION` | `v0.2.0-trackai.1` (stamped in the binary via `-X internal/version.Version`) |
| `NUMBAT_GO_VERSION` | `go1.26.9` (exactly what `go.mod` at the pin requires) |

build.sh refuses unless the mirrored checkout's HEAD equals `NUMBAT_COMMIT` and the installed Go toolchain equals `NUMBAT_GO_VERSION`.

## Scripts

### `build.sh <goos> <goarch> <out-dir>`

Clones the mirror at `NUMBAT_TAG` into a fresh temporary checkout, verifies HEAD == `NUMBAT_COMMIT`, then builds `./cmd/numbat` with the exact upstream `.goreleaser.yaml` flags at the pin (`CGO_ENABLED=0`, `-trimpath`, `-s -w`, the internal/version `-X` flag) plus `-buildvcs=false` and an empty `-buildid=` so two builds on this machine produce identical bytes. Output is:

```
<out-dir>/numbat_<version>_<goos>_<goarch>/{numbat* (numbat.exe on Windows), LICENSE, THIRD_PARTY_LICENSES.txt, PROVENANCE.txt}
<out-dir>/SHA256SUMS
```

`PROVENANCE.txt` records the mirror, tag, exact commit, Go version, full flag string, and build time in UTC. Rebuilding into the same `out-dir` replaces that target's own SHA256SUMS line (multiple targets coexist). Required targets: `darwin/amd64`, `darwin/arm64`; `linux/{amd64,arm64}` and `windows/amd64` build here but carry **no support claim** (they are used for cross-checks only).

Network use: clone/fetch from the pinned mirror, plus Go module downloads (go.sum-verified at the pin, `GOFLAGS=-mod=readonly`; nothing else is fetched). No network access in `reproduce.sh`.

### `reproduce.sh <goos> <goarch>`

Builds the pin **twice** into two fresh directories with build.sh and exits 0 only if both binaries hash identical SHA-256 (gates IT-T20b-01). Prints the digest and byte size.

### `test-pin.sh`

Clones the pin like build.sh does, then runs Numbat's own suite (`go test ./...`) inside it. On success prints exactly `numbat-tests: ok <n> packages`. On failure prints `numbat-tests: failed` plus the tail of the test log. Retries once automatically: upstream's OpenClaw node-harness test (`openclaw_runtime_test.go:71-80` at the pin) has a hard-coded 500 ms child deadline that flakes under machine load — this is a sandbox quirk of the test, not the pin (verified: passes in isolation).

### `measure.sh <numbat-binary> [<git-ai-binary>]`

- **Sizes** of numbat (and, if configured, git-ai — default `~/.git-ai/bin/git-ai`), each marked stripped / not stripped (`nm`‑based).
- **Latency**: 200 timed runs per case after 10 warm-up runs; each timed sample is one fork/exec of the target binary (a fresh process per sample), stdin from a fixture, output and stderr parked in the throwaway directory; median / p95 / max printed in ms. Cases:
  1. Numbat hook, benign Claude Code `PreToolUse` Bash payload (emits no rule finding);
  2. Numbat hook, the same payload running `cat .env` (matched by `secrets.agent_read_env` — rule version `1.3`, severity `medium` at the pin);
  3. `git-ai checkpoint claude --hook-input stdin` with the benign payload — **only with `GIT_AI_MEASURE=1`** set. Note: the benign synthetic payload carries no `transcript_path`, so the claude preset skips attribution processing — case (3) measures the CLI startup/entry path only, which is exactly what a cross-hook latency budget compares.
- **Isolation (TrackAI AGENTS.md §9 item 6)**: every run uses a throwaway `HOME` and a throwaway `git init` repository as the working directory, so the developer's own Git AI daemon or configuration is never started, stopped or contacted. If the git-ai probe fails, it prints `git-ai-hook: unavailable (<reason>)` and stops (exit-code or reason-class only). No payload contents, record contents, or paths outside the throwaway directory are printed. For Numbat's `--output-file`, each timed run truncates the throwaway records file first so late runs don't pay an append cost.
- Requires `perl -MTime::HiRes` (macOS default); Linux ships it too.

Fixtures: `fixtures/*.json`, synthetic payloads in the Claude Code PreToolUse shape used by Numbat's own `cmd/numbat/hook_test.go` (shape copied from the claude payload in `TestHookPrintsPassthroughAndExitsZero`, `cmd/numbat/hook_test.go:129-131`; verified live at the pin: benign `ls -la` yields zero records, `cat .env` matches `secrets.agent_read_env`). No real paths, users, or secrets.

### `extract-coverage.sh <numbat-checkout> <out-file>`

Copies the "Matrix", "Permission and decision telemetry" and "Managed hooks" sections of the checkout's `docs/agent-coverage.md` **verbatim**, with a header naming the source commit and Apache-2.0. One committed output per pin: `coverage/<version>.md`.

### `SYNC.md`

The monthly-sync runbook: fetch upstream into the mirror, choose the first upstream release containing the current pin (TASK20.md §1 item 1), re-tag as `v<upstream>-trackai.<n>`, update `pin.env`, re-run the pin checks and TrackAI's contract tests, re-extract coverage, re-check the licence (`NOTICE` existence, `THIRD_PARTY_LICENSES.txt` diff), diff the rule files, and hand the record to the Task20 lead.

## Outputs in this repository

- `coverage/v0.2.0-trackai.1.md` — verbatim coverage sections extracted from the pinned checkout.
- `out/` — git-ignored build outputs (put your build outputs here when using the default `<out-dir>` named in the Task20b founder bash block).

Nothing in this folder runs on the ingestion path, spawns git regularly, or changes package layout: it builds and measures; the package wiring is Task20h's.
