# Task20j / Task9f coordination note

Run Task20j's E20 acceptance walkthrough and Task19 `T19.9` in one founder
session, but record their verdicts separately: E20 controls per-agent
**monitored/not monitored** claims; T19.9 covers the ten top-ranked questions
as admin and auditor plus Company A/B isolation.

Sequence: `((1 => 2) || 20j) => 3 (Intel + Jamf); (3 || 15n) => 4 => (5 || 6/Task9g)`

1. ✅ Task9f durable-offline port.
2. ✅ TrackAI Endpoint macOS package naming/contracts.
3. ⏳ Exact rebuilt Intel package lifecycle plus Jamf/APNs evidence.
4. ⏳ Production signed/notarized package with Task15n trust activation.
5. ⏳ Apple Silicon/second-Mac validation.
6. ⏳ Windows x64 validation in Task9g; Windows ARM64 remains build-only.

Task20j should use the Intel TrackAI Endpoint package name
`trackai-endpoint-macos-x64.pkg`, record the exact digest/version, and must not
promote unsigned, non-Jamf or single-device results into later Task9 claims.
The canonical names, contents and live status are in the [package flavour
registry](https://github.com/mahamannu-ux/git-ai/blob/main/docs/task9-endpoint-package-flavours.md).
This link becomes authoritative after the Task9f GitAI branch is merged.
