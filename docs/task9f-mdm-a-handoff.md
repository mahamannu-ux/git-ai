# Task9f MDM-a handoff

Date: 2026-10-22

## At a glance

- Branch: `task/Task9f-mdm-a-gitai`, based on fork `main` at `980ef3ef3`.
- Adapted upstream `acbac7ef861819306eec1f8cf830e4489f30937b`
  and `5b25b11a6bf1a0fa8bd37e5c634edeb04b680d0e`.
- Task20 lead verdict: accept with changes. The package must prove its empty
  payload does not alter `/`, and receipt cleanup moves to Task9f MDM-b.

## Implementation

- The macOS builder now gives `pkgbuild` an empty payload root at mode `0755`
  instead of using `--nopayload`, so the installed package has versioned receipt
  metadata. Endpoint binaries, Numbat, trust documents and hooks remain in the
  existing package scripts.
- The release package test runs on Apple Silicon and Intel runners. Each job
  expands both architecture packages and requires `lsbom` to list only `.`.
  It fails rather than skipping when no eligible console user is available,
  then installs the runner-matching package and verifies:
  - `/` owner, group and mode are unchanged;
  - receipt `com.git-ai.git-ai` reports the installed binary version;
  - `pkgutil --files` reports no installed payload files.
- A packaging contract test pins these guarantees and keeps `--nopayload` out.

## Test coverage

- Focused local suites: `packaging_contract` (5 passed),
  `task9_macos_conformance` (6 passed), and `mdm_scripts` (13 passed).
- Both x64 and arm64 package containers were built and expanded locally with
  their audited Numbat binaries. Each payload BOM contained only `.` and each
  package reported identifier `com.git-ai.git-ai`, version `1.6.19`, and
  install location `/`.
- The local arm64 package used the x64 GitAI executable only as a packaging
  fixture because the arm64 Rust target is unavailable in this worktree.
  Architecture-correct installation and receipt checks therefore remain CI
  evidence, not local evidence.
- `cargo fmt --check`, `task build`, shell syntax, release YAML parsing, and
  `git diff --check` passed. Local `task lint` on Rust 1.97.1 reports 11
  pre-existing diagnostics in untouched files; CI's pinned Rust 1.93.0 is the
  authoritative lint gate.

The change adds a packaging contract test but no new product integration-test
identifier. A full local `task test` may be deferred until MDM-b, provided this
MDM-a PR's CI runs the full suite on the exact commit being merged.

## Known limitation and MDM-b dependency

The versioned package receipt remains after the existing Endpoint cleanup.
Until Task9f MDM-b merges, a successfully offboarded Mac can still appear in
Jamf inventory as having this package installed. MDM-b must list
`pkgutil --forget com.git-ai.git-ai` in cleanup dry-run output and execute it
only after a successful `cleanup-endpoint.sh --apply`; it must not forget the
receipt when cleanup is deferred or fails, including when the daemon remains
running.

## Evidence boundaries

Automated and unsigned build evidence does not establish signing,
notarization, Jamf/APNs behavior, Intel IT-T9-02/03 or Apple Silicon IT-T9-07.
After this PR merges and Task20j stabilizes, use one exact post-MDM-a Intel
package and digest for IT-T9-02 and Jamf. Task15n production trust creates a
distinct signed artifact for the later production and Apple Silicon gates.

The change adds no credential input, network request, customer-content path,
telemetry, Numbat behavior, trust-policy change or MDM install/cleanup mutation.
