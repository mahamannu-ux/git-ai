# Monthly Numbat sync runbook (Task20b)

Run once a month (or before the first customer build) to move TrackAI's Numbat
pin to a newer upstream release. Owner: TrackAI founder / lead. The audited
pin lives in `packaging/numbat/pin.env`, synced monthly per
TrackAI `docs/plan/TASK20.md` §1 item 1.

All work happens in `~/AIProjects/numbat` (the local Numbat checkout with the
`trackai` mirror remote) and this repository.

1. **Fetch upstream into the mirror.** In `~/AIProjects/numbat`:
   `git fetch origin` (upstream `perplexityai/numbat`), then
   `git fetch trackai` so the mirror stays consistent.

2. **Choose the upstream release, preferring the first upstream release that
   contains the current pin.** Check with
   `git tag --contains 20a5a52bab41c9bf6ee857efd43c7b198b055de5` against
   upstream's releases. If no such release exists, the mirror tag ships
   unchanged (TASK20.md §1 item 1). Record which one you chose and why.

3. **Tag it** `v<upstream>-trackai.<n>` (n = next integer) on the exact
   upstream commit, then push the tag:
   `git tag -a v1.0.0-trackai.1 <commit> -m "TrackAI audited pin (Task20)"`;
   `git push trackai v1.0.0-trackai.1`.

4. **Update `pin.env`** in this repository: `NUMBAT_TAG`, `NUMBAT_COMMIT`
   (the exact SHA), `NUMBAT_VERSION` (same as the tag) and `NUMBAT_GO_VERSION`
   if Numbat's `go.mod` moved. Commit this change with a `Task20b:` commit.

5. **Sync the built-in catalogue at the new pin.** In the Numbat checkout at
   `NUMBAT_COMMIT`, regenerate `packaging/macos/builtin-rule-ids.txt` in this
   repository from `numbat rules list` (for example,
   `go run ./cmd/numbat rules list > <gitai-worktree>/packaging/macos/builtin-rule-ids.txt`).
   Review the added and removed IDs, then release this file in the **same
   Endpoint build** as the new Numbat binary. Re-import TrackAI Task20f's
   `catalogue/` from that same pin: the server compiles compact bundles against
   it, while the Endpoint loads the binary's embedded catalogue. Include the
   catalogue update in the corresponding TrackAI pin change.

6. **Run the pin checks** for both macOS architectures:
   - `sh packaging/numbat/test-pin.sh` (expect `numbat-tests: ok <n> packages`);
   - `sh packaging/numbat/reproduce.sh darwin amd64` and
     `sh packaging/numbat/reproduce.sh darwin arm64`
     (expect identical digests across two fresh builds).

7. **Run TrackAI's contract tests with Numbat checked out beside the TrackAI
   worktree** (`npm test` in TrackAI). The pinned-source assertions in
   `v2-contract.test.ts` must not be skipped.

8. **Extract the coverage table**:
   `sh packaging/numbat/extract-coverage.sh <numbat-checkout> \
      packaging/numbat/coverage/<new-tag>.md`
   and commit the new file.

9. **Check the licence**: does a `NOTICE` file exist at the new pin now
   (there is none at `20a5a52`)? Has `THIRD_PARTY_LICENSES.txt` changed
   (`git diff <old-pin> <new-pin> -- THIRD_PARTY_LICENSES.txt`)? Record both
   answers; notice-bearing dependencies inside the binary change the package's
   notices (TASK6 security/numbat licence plan, "Task20: binary redistribution").

10. **Diff the rule files against the previous pin** (adapted-material
   provenance for Task20f; 51 `.yaml` rule files at `20a5a52`, re-count at the
   new pin):
   `git diff --numstat <old-pin> <new-pin> -- rules/`
   and `git diff <old-pin> <new-pin> -- rules/` for the full review. Changed
   rule files update TrackAI's catalogue provenance.

11. **Hand the record to the Task20 lead**: chosen release, new tag, test and
    reproducibility results, the coverage file, the licence answers and the
    rule diff summary, so §1 item 1's pin move can be recorded.
