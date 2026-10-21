# Task9f phase 2 handoff

Date: 2026-10-21

## Completed scope

- Renamed the two combined macOS installer outputs to
  `trackai-endpoint-macos-x64.pkg` and
  `trackai-endpoint-macos-arm64.pkg`.
- Updated the release workflow's build outputs, checksum input, CI artifact
  name, hosted package test, release notes, provenance attestation and release
  upload glob as one contract.
- Updated the Task9f runbook examples and static contract assertions.
- Added a persistent tracking column to the [package flavour
  registry](task9-endpoint-package-flavours.md): `✅` means implemented and
  automatically checked, `⏳` means pending, and `➖` means build-only or outside
  the current support target.

## Deliberately unchanged

- The executables inside the package remain `git-ai` and `numbat`.
- Standalone component artifacts remain `git-ai-macos-x64` and
  `git-ai-macos-arm64`.
- The current Windows MSI remains `git-ai-windows-x64.msi` because it contains
  only GitAI. It must not be renamed to TrackAI Endpoint until Windows Numbat
  packaging exists.
- Package identifier, installed paths and update identity are unchanged; this
  is an artifact/product-name change, not an installer migration.

## Verification

| Gate | Result |
|---|---|
| `task fmt` | passed |
| `task test CARGO_TEST_ARGS="--test task9_macos_conformance"` | 5 passed, 0 failed |
| `task test CARGO_TEST_ARGS="--test packaging_contract"` | 4 passed, 0 failed |
| Parse `.github/workflows/release.yml` with the macOS Ruby YAML parser | passed |
| `git diff --check` | passed before commit |

No founder/manual validation is required for the naming-contract change itself.
The newly named Intel package must still be built and used by the next native
reinstall/update checkpoint; signed/notarized, Jamf and Apple Silicon evidence
remain separate pending gates.
