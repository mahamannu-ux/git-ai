# Task9f MDM-b handoff

Date: 2026-10-23

## At a glance

- Branch: `task/Task9f-mdm-b-gitai`, based on fork `main` at `3b42f8fbe`.
- Adapted upstream `0cd8ede139e5cb5287cd09563ce677525d703547`
  and `97074e657785cb54b5140180e77d867315961feb`.
- Task20 lead verdict: accept with changes. Published validation is fork-only,
  production-trust-gated and fail-closed; package-receipt removal is part of
  successful root offboarding.

## Implementation

- The macOS cleanup dry run lists the `com.git-ai.git-ai` receipt. A root
  `--apply` forgets it only after daemon shutdown, hook removal and fleet
  cleanup succeed. Non-root cleanup preserves its original result and prints
  `receipt com.git-ai.git-ai retained; rerun as root to forget it`.
- The nightly workflow deterministically selects the immediate N-1/N semantic
  versions from this fork. Both releases must be non-draft, non-prerelease,
  contain the complete macOS/Windows package, installer, MDM and hash-manifest
  asset set, and have a production trust pin in that tag's source.
- Selected assets are downloaded by exact tag from the fork. MDM assets must
  equal their same-tag source bytes, hashes must match the release manifests,
  and GitHub attestations must match this repository, the tag-resolved commit
  digest and the pinned release workflow. Lifecycle jobs cannot start until
  every asset-verification matrix leg succeeds, then each runner re-verifies
  the hash and provenance of the exact installer copy it will execute.
- Separate macOS and Windows jobs run lifecycle and N-1 to N auto-update
  scenarios while checking daemon health and login-start registration. The
  temporary shortened update interval is test-only and does not change the
  managed-launcher contract or restore a product `--env` surface.
- Artifact upload is an allow-list of `${{ runner.temp }}/mdm-logs` only. The
  Windows summary states `security: not monitored on Windows`.

## Honest availability and evidence

The fork currently has fewer than two eligible releases because release builds
remain disabled until Task15n populates production trust pins. In that state,
the live lifecycle, update and asset jobs are skipped, the selection job says
`no eligible release pair`, and only the isolated synthetic selector fixtures
may pass. That is not published-release validation evidence.

PowerShell syntax and the Windows lifecycle remain CI evidence because this
macOS worktree has no PowerShell parser. Signed/notarized packages, Jamf/APNs,
Intel IT-T9-02/03 and Apple Silicon IT-T9-07 remain separate founder-live gates.
During the Task20j week, verify that the installed receipt version equals the
binary version and that final successful root offboarding removes the receipt.

## Test coverage

- `mdm_scripts` passed 18/18 and covers deterministic eligibility, workflow boundaries,
  receipt dry-run/root/non-root/daemon-running behavior and the published
  update harness contracts.
- The selector self-test covers zero and one eligible release, ordering,
  drafts, prereleases, missing assets and absent production trust pins.
- Task9 macOS conformance passed 6/6 and the packaging contract passed 5/5.
- Rust format, shell syntax, workflow YAML parsing and diff hygiene passed.
- Independent read-only review returned `ready to commit` after the workflow
  was hardened to verify assets before use, bind provenance to the tag commit
  and release workflow, and re-verify the exact installer each runner executes.
- The exact final SHA still requires the normal full build, format, lint and
  test gates before merge; these are intentionally founder-run for this round.

No new product integration-test identifier is added. This is release/MDM
regression infrastructure and bounded cleanup behavior, not ingestion-path or
customer-data behavior.

## Scope and follow-ups

Numbat binaries, catalogues and state, security leases/queues, trust semantics,
hooks and telemetry are unchanged. Uploaded logs exclude home/config/database
trees, `~/.numbat/`, `~/.git-ai/internal/security/` and
`/Library/Application Support/TrackAI/Endpoint/` by never including them.

After merge, update the Task9 status/roadmap and Task17 upstream ledger with the
final commit and PR. Task20j should build its package from `main` after this
change lands. E20 and Task20j behavior are otherwise unaffected.

## Effort

Estimated effort was 0.35–0.40 x T6. Actual implementation remained within
that range; the additional work was focused on receipt sequencing, fail-closed
release eligibility and provenance/privacy gates rather than product code.
