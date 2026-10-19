# TrackAI Endpoint macOS package

`build-pkg.sh` packages a GitAI binary and one Task20b `darwin` Numbat build for the selected architecture. It needs the Task20b output directory containing `numbat`, `LICENSE`, `THIRD_PARTY_LICENSES.txt`, and `PROVENANCE.txt`; the parent directory must contain `SHA256SUMS`. It also needs a trust directory containing `root.json` and any `keyset-<scope>.json` files. The build copies these documents; it does not fetch or generate keys.

```sh
packaging/macos/build-pkg.sh \
  --binary target/debug/git-ai \
  --numbat-dir packaging/numbat/out/numbat_v0.2.0-trackai.1_darwin_amd64 \
  --trust-dir /path/to/trust-documents \
  --arch x64 --version 1.6.19 --output /path/to/trackai-endpoint.pkg
```

For the disposable Task20h Intel Mac run, add `--debug-dev-pins` and put Task20g's `dev-pins.json` in the trust directory. That file is deliberately absent from normal release packages. The release code has no production trust-root pins until Task15n supplies them, so a release package stays off even if trust documents are present.

Postinstall verifies the bundled Numbat binary against its Task20b SHA-256 entry before installing hooks. It installs Numbat root-owned at `/Library/Application Support/TrackAI/Endpoint/bin/numbat`, with the license and provenance files alongside it. Trust documents go in the logged-in user's `~/.git-ai/internal/security/trust/` before the first policy refresh. The package writes the same never-matching `placeholder.yaml` into each of the five source-agent folders, then points `rules/current` at the placeholder until a verified bundle is applied. `agents.tsv` is the single Numbat-to-bundle name map used by the installer and Endpoint.

Managed hooks monitor Claude Code, Codex, Cursor, Gemini CLI, and Copilot CLI. They use `--emit all --content preview --output file --no-builtin-rules`, load `$HOME/.git-ai/internal/security/rules/current/<source-agent>`, and append to `$HOME/.numbat/records.ndjson`. The Endpoint shipper reads that same file. When TrackAI monitoring is off, Numbat **continues writing local action previews** to the developer's file; the Endpoint drops them from upload. Task20e rotates that file daily and deletes old rotations after seven days. It does not truncate the active file as records are consumed, so a busy day can make it large.

For complete offboarding, MDM runs `mdm/macos/cleanup-endpoint.sh --dry-run --user NAME` and then `--apply --user NAME` as root. Cleanup uninstalls all five managed hooks before removing Numbat and `~/.git-ai/internal/security/`; if any hook cannot be removed, it retains the binary and rules and reports an incomplete cleanup. The developer's `~/.numbat/` stays in place and is named in the output.

The Endpoint's hourly status records report Numbat version, configured managed hooks, active bundle digest and lease, and the last local file-write time. A hook is marked wired only when Numbat's managed `hook status` reports `installed`. The effective agent view, known-action local record, and matching forwarder acknowledgement are `unavailable` until they can be observed; the host walkthrough supplies those checks. Monitor evidence does not prove prevention.
