# Task9 macOS conformance and evidence

This runbook records the bounded Task9f evidence for macOS. It deliberately
separates automated contracts, one Intel Mac, signed release artifacts, Jamf,
a second Mac, and Task15-dependent execution. A result in one row never
promotes another row.

## Evidence rules

- Record only `passed`, `failed`, `pending prerequisite`, or `not applicable`.
- Store harness output only under the gitignored `target/task9-evidence/` tree.
- Record architecture, macOS version, artifact digest, command result, and
  bounded state/result codes only.
- Never record a hostname, username, serial number, Apple Account, tenant URL,
  credential, token, certificate, private key, raw configuration, raw
  telemetry, customer source, or full local path.
- A dry run, unsigned package, CI run, simulation, or single-device result is
  not signed/notarized, Jamf, or two-device evidence.
- Environment, tooling, sandbox, and external-service failures stay distinct
  from product failures.

## Evidence matrix

| Row | Prerequisites | Exact procedure | Safe expected result | Evidence captured | Status | Customer claim permitted |
|---|---|---|---|---|---|---|
| Automated/static contract evidence | Rust 1.93 toolchain and repository dependencies | Run the focused gates in [Automated gates](#automated-gates), then `scripts/task9/macos-conformance.sh` in `plan`, `binary`, and `package` modes | Focused Task9 contracts pass; workflow asserts Intel PKG, signing/notarization gates and checksums; harness remains read-only | Test counts, commit, architecture, macOS version, artifact SHA-256, bounded result codes | passed — Task9-owned focused gates; inherited lint baseline recorded below | Engineering contracts exist for the macOS package, login start, managed state, native credential adapter, update and cleanup; no native support claim |
| Current Intel-Mac local evidence (`IT-T9-02`) | Founder-approved checkpoints; exact Intel or universal PKG; disposable non-customer identifiers/runtime; Task9f automated gates | Follow [Founder-assisted Intel-Mac lifecycle](#founder-assisted-intel-mac-lifecycle-it-t9-02) | Per-user install and hooks, login start, Keychain behavior, isolated bootstrap/offline evidence, fail-closed update, and explicit idempotent cleanup behave as documented | Safe pass/fail codes only; no machine identity or content | not passed — install, login start, Keychain, bootstrap and cleanup passed; offline delivery produced no managed queue row | No complete local-lifecycle or offline-delivery claim; bounded passed sub-checks may be reported only as development evidence |
| Signed/notarized artifact evidence | Exact production PKG, its published checksum, Developer ID signature and stapled notarization ticket | Run read-only package inspection in checkpoint 1 and harness `package` mode | Checksum matches; `pkgutil`, `spctl`, and stapler checks succeed | Artifact basename class, SHA-256 and pass/fail codes; never certificate output | pending prerequisite — signed/notarized PKG unavailable | None; unsigned development mechanics must remain labelled unsigned |
| Jamf-managed evidence (`IT-T9-03`) | Jamf Pro trial with package/policy/inventory features; active APNs certificate from an organization-controlled Apple Account; manually enrolled test Mac; signed/notarized PKG for a production package claim | Follow [Jamf phase 1](#jamf-phase-1-it-t9-03) after all prerequisites are confirmed | Post-login package/login-start/bootstrap delivery succeeds without transporting credentials; TrackAI authority remains independent; cleanup is separately delivered | Redacted/opaque policy and inventory result identifiers only | pending prerequisite — Jamf/APNs/enrollment not confirmed | No Jamf-managed macOS claim |
| Second-Mac/Apple-Silicon evidence (`IT-T9-07`) | Second Mac, preferably Apple Silicon; bounded two-device rollout ring | Repeat the signed artifact and lifecycle procedure on the second Mac, then exercise the two-device ring | Both devices report separate bounded results; architecture is recorded honestly | Architecture, OS version and opaque rollout result only | pending prerequisite — second Mac unavailable | No two-device rollout-ring or Apple-Silicon claim |
| Task15-signed configuration/update execution (`IT-M9-01`) | Production Task15 verifier and trust interface; signed machine-bound schema-v2 configuration | Run tamper, replay, revocation, N/N-1 update and rollback checks | Valid signatures authorize exact pinned releases; invalid/unavailable verification causes zero download/install side effects and preserves last-known-good | Closed verification/update result codes and artifact digests only | pending prerequisite — production verifier unavailable | No successful managed update/rollback or signed-configuration claim; fail-closed engineering behavior may be claimed after focused tests pass |

## Automated gates

Run focused checks before any native checkpoint. Do not repeatedly run the
complete Cargo suite on this Intel Mac.

```bash
task fmt
task lint
task test CARGO_TEST_ARGS="--test mdm_scripts"
task test CARGO_TEST_ARGS="--test packaging_contract"
task test CARGO_TEST_ARGS="--test task9_macos_conformance"
task test CARGO_TEST_ARGS="--lib" TEST_FILTER="fleet::"
task test CARGO_TEST_ARGS="--lib" TEST_FILTER="machine_credentials"
task test CARGO_TEST_ARGS="--lib" TEST_FILTER="metrics::delivery"
git diff --check d1838619c5555a47ea0ffb77ecd6d1cc07cf4859..HEAD
```

The full Cargo suite is skipped unless a focused failure demonstrates a
cross-cutting risk. Inherited Clippy findings and daemon timing flakes are
reported separately from Task9f regressions.

### Task9f automated results — 2026-10-13

| Gate | Result | Classification |
|---|---|---|
| `task build` | passed | Local debug binary built as GitAI 1.6.19 for x86_64 |
| `task fmt` | passed | Task9f Rust test formatted |
| `task test CARGO_TEST_ARGS="--test mdm_scripts"` | 11 passed, 0 failed | Packaging/MDM static and cleanup-wrapper contracts |
| `task test CARGO_TEST_ARGS="--test packaging_contract"` | 4 passed, 0 failed | Secret-free per-user PKG/MSI contracts |
| `task test CARGO_TEST_ARGS="--test task9_macos_conformance"` | 4 passed, 0 failed | Harness, runbook and release-workflow assertions |
| `task test CARGO_TEST_ARGS="--lib" TEST_FILTER="fleet::"` | 36 passed, 0 failed | Configuration, update, fail-closed execution and cleanup |
| `task test CARGO_TEST_ARGS="--lib" TEST_FILTER="machine_credentials"` | 2 passed, 0 failed | Native-store input and safe memory-adapter behavior; not live Keychain evidence |
| `task test CARGO_TEST_ARGS="--lib" TEST_FILTER="metrics::delivery"` | 12 passed, 0 failed | Managed binding, credential selection and durable delivery policy |
| `task lint` | 11 findings, all in untouched non-Task9 files | Inherited Rust 1.97.1 Clippy baseline; repository target is Rust 1.93.0, which is not locally available; no unrelated fix attempted |
| `shellcheck` | not run | Optional tool unavailable locally; `bash -n` passed |
| Complete Cargo suite | not run | No focused result exposed a cross-cutting risk |
| Native login-start lifecycle script | not run automatically | Its `com.usegitai.bg` launchd label shares the founder's user domain; running it would touch the normal daemon boundary without checkpoint approval |

The planning harness passed on macOS 15.0.1 x86_64. The isolated binary mode
passed architecture and version checks for the local debug build. A locally
built x86_64 development PKG passed its generated SHA-256 check; package
signature, Gatekeeper and stapler checks returned `pending_prerequisite`, so it
is evidence of unsigned mechanics only. No PKG was installed.

## Harness

The harness defaults to read-only planning and accepts no credential or
configuration input:

```bash
scripts/task9/macos-conformance.sh
scripts/task9/macos-conformance.sh plan
scripts/task9/macos-conformance.sh binary --binary /absolute/path/to/git-ai
scripts/task9/macos-conformance.sh package --package /absolute/path/to/git-ai-macos-x64.pkg --checksum-file /absolute/path/to/PKG-SHA256SUMS
```

It refuses non-macOS hosts, creates an isolated temporary workspace, records
only bounded metadata under `target/task9-evidence/`, and removes its workspace
on success or failure. It never invokes `sudo`, installs a package, registers
login start, accesses normal GitAI state, opens Keychain entries, enrolls MDM,
or runs cleanup.

## Founder-assisted Intel-Mac lifecycle (`IT-T9-02`)

Run each checkpoint separately and inspect its safe output before continuing.
The paths below are placeholders for the exact reviewed artifact. Checkpoint 2
is privileged and must be run by the founder, never by Codex.

### Checkpoint 1 — inspect the exact artifact, read-only

```bash
set -euo pipefail
REPO=/Users/manishmahajan/AIProjects/TrackAI-wt/Task9f-macos-conformance-gitai
PKG=/absolute/path/to/git-ai-macos-x64.pkg
PKG_SUMS=/absolute/path/to/PKG-SHA256SUMS

cd "$REPO"
scripts/task9/macos-conformance.sh package --package "$PKG" --checksum-file "$PKG_SUMS"
pkgutil --payload-files "$PKG"
```

Proceed as signed/notarized only when the harness reports successful checksum,
package signature, Gatekeeper, and stapler results. Otherwise label the package
`unsigned development mechanics only` and leave the signed row pending.

### Checkpoint 2 — install the reviewed PKG, founder approval required

Pre-install baseline recorded 2026-10-13:

- existing binary: GitAI 1.6.16 debug, x86_64,
  SHA-256 `b8efed65e4424a8cc72d721709e945bd765543845fc3b9bde0ab7b1555786bb4`;
- rollback copy (gitignored): `target/task9-native-backup/1.6.16/git-ai`;
- candidate binary: GitAI 1.6.19 debug, x86_64, built from Task9d merge
  `d1838619c` plus Task9f's docs/tests-only commit `e155f5eea`, SHA-256
  `dce25adcc749af4ce810eec3bc1a3f35f9816fbfaec0bfe432a4a01f7a19ce1c`;
- unsigned development PKG SHA-256:
  `405e2f9fd313e16d42e709ae0ea79f9c175daedc8f881a7a211b7fe4688dc060`;
- founder decision: keep 1.6.19 after this walkthrough. The rollback copy is
  retained only for a later explicit rollback walkthrough or forensic check.

Founder result, 2026-10-13: **passed for unsigned development mechanics**.
The PKG installed successfully; the installed binary reported GitAI 1.6.19
debug, x86_64, with the expected binary SHA-256; ownership and trace2 hook
checks passed; `/opt/git-ai` and `/usr/local/bin/git-ai` remained absent. This
does not change the signed/notarized artifact row, which remains pending.

```bash
set -euo pipefail
PKG=/absolute/path/to/git-ai-macos-x64.pkg
sudo installer -pkg "$PKG" -target /

GIT_AI_BIN="$HOME/.git-ai/bin/git-ai"
test -x "$GIT_AI_BIN"
"$GIT_AI_BIN" --version
test "$(stat -f%Su "$GIT_AI_BIN")" = "$(id -un)"
test ! -e /opt/git-ai
test ! -e /usr/local/bin/git-ai
git config --global --get-regexp '^trace2\.'
```

### Checkpoint 3 — login start and idempotency, unprivileged

This touches the real per-user LaunchAgent and daemon, so run only after the
founder explicitly approves using the test Mac's normal user session.

```bash
set -euo pipefail
REPO=/Users/manishmahajan/AIProjects/TrackAI-wt/Task9f-macos-conformance-gitai
GIT_AI_BIN="$HOME/.git-ai/bin/git-ai"

sh "$REPO/mdm/macos/install-login-start.sh" --bin "$GIT_AI_BIN"
launchctl print "gui/$(id -u)/com.usegitai.bg" >/dev/null
sh "$REPO/mdm/macos/install-login-start.sh" --bin "$GIT_AI_BIN"
launchctl print "gui/$(id -u)/com.usegitai.bg" >/dev/null
```

Confirm only that the daemon is healthy, the launcher exits successfully, and
re-registration is idempotent. Do not paste `launchctl print` or daemon logs.

Founder result, 2026-10-13: **passed**. macOS emitted two expected
“Background Items Added” notifications because the LaunchAgent was registered
and then re-registered for the idempotency check. The registration existed,
the launcher exited, the daemon was healthy and survived launcher exit, and
the second registration retained the same daemon process.

### Checkpoint 4 — native Keychain and non-secret bootstrap

Founder result, 2026-10-13, native credential-store sub-checkpoint:
**passed** using a generated synthetic credential. The store reported
available; native Keychain store, load, and delete all succeeded; and the
legacy plaintext fallback file remained absent. No credential value, account
identifier, or device identifier was retained as evidence.

Founder result, 2026-10-13, non-secret bootstrap sub-checkpoint: **passed**.
One synthetic repository route targeting a loopback-only unavailable endpoint
was installed with mode `0600`; the closed policy contained no plaintext
credential. This proves local bootstrap installation only, not delivery or a
live TrackAI integration.

Founder result, 2026-10-13, offline delivery sub-checkpoint: **did not pass**.
The configured repository allowlist first rejected an unlisted synthetic
remote, which is the expected privacy behavior and was not weakened. A fully
isolated-home attempt was discarded because that artificial home could not
access the login Keychain. Under the normal daemon, an allowlisted local lab
accepted a synthetic Codex checkpoint, produced two synthetic commits and an
authorship note, and the daemon loaded the synthetic Keychain credential and
failed safely against the loopback-only unavailable endpoint. However, no new
metrics row with a managed delivery binding was created, so queue durability
across restart was not exercised. No customer content or plaintext credential
was used. This sub-checkpoint remains open and permits no offline-delivery
claim.

The credential is pasted into a silent shell read and piped over stdin. It is
never placed in an argument, environment variable, fixture, file, or log.

```bash
set -euo pipefail
GIT_AI_BIN="$HOME/.git-ai/bin/git-ai"

"$GIT_AI_BIN" fleet credential status
IFS= read -r -s -p 'One-time TrackAI machine credential: ' TRACKAI_INPUT; printf '\n'
printf '%s\n' "$TRACKAI_INPUT" | "$GIT_AI_BIN" fleet credential install
unset TRACKAI_INPUT
"$GIT_AI_BIN" fleet credential status

# Supply a reviewed synthetic bootstrap document through stdin; never paste
# its contents or resulting policy file into evidence.
"$GIT_AI_BIN" fleet bootstrap install < /absolute/path/to/synthetic-bootstrap.json
test "$(stat -f%Lp "$HOME/.git-ai/trackai-delivery-policy.json")" = 600
```

Use only synthetic repositories and a disposable TrackAI runtime. Work offline
to enqueue synthetic evidence, restart the daemon, and record bounded queue
counts only. With `UnavailableVerifier`, record `verification_unavailable` and
confirm no staged installer was downloaded or executed. Successful managed
update/rollback remains pending until Task15.

### Checkpoint 5 — cleanup scope, apply, and idempotency

Cleanup preserves the durable queue, authorship notes, repositories, normal
user login, GitAI binary, and ordinary GitAI data.

Founder result, 2026-10-13: **passed**. The bounded dry-run contained exactly
the expected credential, managed-file, staging-directory and login-start
actions. First apply returned only successful or already-missing results;
the existing durable queue, synthetic authorship note and installed binary
remained available while managed policy, synthetic Keychain credential and
login-start registration were absent. The second dry-run contained no
credential action, and the second apply was successful and idempotent. The two
disposable synthetic repositories were then removed; the 1.6.19 binary and
the retained 1.6.16 rollback copy were not removed.

```bash
set -euo pipefail
REPO=/Users/manishmahajan/AIProjects/TrackAI-wt/Task9f-macos-conformance-gitai
GIT_AI_BIN="$HOME/.git-ai/bin/git-ai"
WRAPPER="$REPO/mdm/macos/cleanup-endpoint.sh"

sh "$WRAPPER" --dry-run --bin "$GIT_AI_BIN"
sh "$WRAPPER" --apply --bin "$GIT_AI_BIN"
sh "$WRAPPER" --dry-run --bin "$GIT_AI_BIN"
sh "$WRAPPER" --apply --bin "$GIT_AI_BIN"
test -x "$GIT_AI_BIN"
```

Record only action/result codes. Never paste paths containing a username,
credential key IDs, policy contents, queue contents, or daemon logs.

## Jamf phase 1 (`IT-T9-03`)

Do not start this lane until the Jamf trial, APNs certificate, and manual test
enrollment are all confirmed. ADE, Apple Business Manager, OOBE, wipe testing,
and production rollout are excluded.

1. Upload the exact signed/notarized PKG. If it is unsigned, keep the production
   package row pending.
2. Create post-login policies for the package, `install-login-start.sh`, and a
   non-secret bootstrap document. Do not transport a TrackAI credential.
3. Enter the one-time credential locally through stdin as in checkpoint 4.
4. Record only opaque/redacted policy and inventory result identifiers. Jamf
   evidence never grants TrackAI authority.
5. Until Task15 exists, verify the fail-closed update result only; do not claim
   successful managed update or rollback.
6. Revoke TrackAI server authority first. Then explicitly deliver
   `cleanup-endpoint.sh --apply` and verify its separate bounded result.
7. Remove the Mac from the test scope and tenant without wiping it.

## Support wording

Until all live rows change status, the safe statement is:

> Task9 has automated macOS packaging, per-user login-start, managed-state,
> native-credential, fail-closed update, and bounded-cleanup engineering
> evidence. Native Intel-Mac, signed/notarized PKG, Jamf, two-device,
> Apple-Silicon, and Task15-signed execution claims remain pending their named
> prerequisites and live runs.

## Founder integration commands

Run these only after TrackAI-Orchestrator independently reviews the final
Task9f commits and replies `ready to push`.

```bash
# after cross-agent review
cd /Users/manishmahajan/AIProjects/TrackAI-wt/Task9f-macos-conformance-gitai
git push -u origin task/Task9f-macos-conformance-gitai
gh pr create \
  --base main \
  --head task/Task9f-macos-conformance-gitai \
  --title "Task9f: add macOS conformance evidence harness" \
  --body "Task9f adds a read-only, isolated macOS artifact conformance harness and an evidence runbook. Native Intel-Mac, signed/notarized, Jamf, second-Mac and Task15-dependent rows remain explicitly conditional on their live prerequisites."
```
