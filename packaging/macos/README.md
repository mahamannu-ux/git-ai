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

The release workflow builds the audited Numbat pin for `darwin/arm64` and `darwin/amd64`, then produces separate Apple Silicon and Intel PKGs. It checks the unsigned reproducible SHA-256, signs the copied Numbat binary with Developer ID Application, records the unsigned digest in packaged `PROVENANCE.txt`, and writes the signed digest to the package `SHA256SUMS`. The `release` GitHub environment must provide `TRACKAI_SECURITY_TRUST_DOCUMENTS_B64`: single-line base64 of a gzip tar archive with flat `root.json` and optional `keyset-<scope>.json` entries. The workflow rejects missing or malformed documents and never adds `dev-pins.json` to a release package. The founder supplies this environment secret; the archive contents are never printed by the workflow. The hosted macOS runner checks both package payloads and installs the Apple Silicon one only when a normal console user exists. The live install and agent checks remain IT-T20h-01 on the founder's Mac.

Postinstall verifies the bundled Numbat binary against the package SHA-256 entry before installing hooks. It installs Numbat root-owned at `/Library/Application Support/TrackAI/Endpoint/bin/numbat`, with the license and provenance files alongside it. Trust documents go in the logged-in user's `~/.git-ai/internal/security/trust/` before the first policy refresh. The package writes the same never-matching `placeholder.yaml` into each of the five source-agent folders, then points `rules/current` at the placeholder until a verified bundle is applied. `agents.tsv` is the single Numbat-to-bundle name map used by the installer and Endpoint.

Managed hooks monitor Claude Code, Codex, Cursor, Gemini CLI, and Copilot CLI. They use `--emit all --content preview --output file --no-builtin-rules`, load `$HOME/.git-ai/internal/security/rules/current/<source-agent>`, and append to `$HOME/.numbat/records.ndjson`. The Endpoint shipper reads that same file. When TrackAI monitoring is off, Numbat **continues writing local action previews** to the developer's file; the Endpoint drops them from upload. Task20e rotates that file daily and deletes old rotations after seven days. It does not truncate the active file as records are consumed, so a busy day can make it large.

Managed hooks apply to every account on the Mac. An account without TrackAI enrollment has no rules folder: Numbat fails open (exit 0), and its `~/.numbat` file may appear in that account. Trust documents from an earlier install remain after an upgrade in this phase.

For complete offboarding, MDM runs `mdm/macos/cleanup-endpoint.sh --dry-run --user NAME` and then `--apply --user NAME` as root. Cleanup uninstalls all five managed hooks before removing Numbat and `~/.git-ai/internal/security/`; if any hook cannot be removed, it retains the binary and rules and reports an incomplete cleanup. The developer's `~/.numbat/` stays in place and is named in the output.

The Endpoint's hourly status records report Numbat version, configured managed hooks, active bundle digest and lease, and the last local file-write time. A hook is marked wired only when Numbat's managed `hook status` reports `installed`. The effective agent view remains `unavailable` in phase 1 and is checked by hand. `local_record` is `ok` after the tail commits a well-formed Numbat record timestamped after hook installation within 24 hours; it is `failed` when recent lines were rejected and no such valid record exists, otherwise `unavailable`. `forwarder_ack` is `ok` after a recent valid 2xx response for an upload holding Numbat-derived records; a terminal refusal or a Numbat queue row older than 24 hours makes it `failed`, otherwise it is `unavailable`. The queue retains only timestamps and a refusal code for these checks. Monitor evidence does not prove prevention.
