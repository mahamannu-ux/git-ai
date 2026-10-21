# TrackAI Endpoint package flavours

Use **TrackAI Endpoint package** for the customer-facing installer. `git-ai`
and `numbat` are the executables inside that package; neither component name
should be used as the name of the combined product installer.

The names below are the public package names. Tracking uses `✅` for an
implemented and automatically checked item, `⏳` for pending validation or
implementation, and `➖` for a build-only/non-target item.

| Tracking | Platform / flavour | Public/current package name | Installed components | Signing and validation state | Dependency / boundary |
|---|---|---|---|---|---|
| ✅ naming/build; ⏳ rebuilt-package native check | macOS Intel development | `trackai-endpoint-macos-x64-debug.pkg` for ad-hoc builds; release workflow emits `trackai-endpoint-macos-x64.pkg` | `git-ai` x86_64 + Numbat amd64 | Unsigned. Bounded Intel install, hooks, lifecycle, offline queue and manual cleanup have development evidence; the exact post-Task20h-b rebuilt package still needs reinstall/update validation. | Task9f package rebuild/reinstall checkpoint; never a production signing claim. |
| ✅ naming/build; ⏳ signing/Jamf | macOS Intel production | `trackai-endpoint-macos-x64.pkg` | `git-ai` x86_64 + Numbat amd64 | Signed/notarized release and Jamf validation pending. | Apple signing/notarization inputs + Task15n production trust documents + Task9f `IT-T9-02`/`IT-T9-03`. |
| ✅ naming/build; ⏳ native check | macOS Apple Silicon development | `trackai-endpoint-macos-arm64-debug.pkg` for ad-hoc builds; release workflow emits `trackai-endpoint-macos-arm64.pkg` | `git-ai` arm64 + Numbat arm64 | Unsigned build/static contract only; native validation pending. | New Apple Silicon Mac + Task9f `IT-T9-07`. |
| ✅ naming/build; ⏳ signing/native check | macOS Apple Silicon production | `trackai-endpoint-macos-arm64.pkg` | `git-ai` arm64 + Numbat arm64 | Signed/notarized and native validation pending. | Apple signing/notarization inputs + Task15n production trust documents + Apple Silicon `IT-T9-07`. |
| ✅ current GitAI-only build; ⏳ native check | Windows x64 current installer | Not a TrackAI Endpoint package: `git-ai-windows-x64.msi` | `git-ai.exe` x64 only | Azure-signing path exists; production signing and native validation are pending. | Task9g `IT-T9-04`/`IT-T9-05`; do not describe this GitAI-only MSI as the combined Endpoint. |
| ⏳ packaging/signing/native check | Windows x64 combined target | `trackai-endpoint-windows-x64.msi` (not emitted today) | Target: `git-ai.exe` x64 + Numbat amd64 | Packaging, signing and validation pending. | Task9g plus the Windows Task20 packaging/security wave and rental Windows host. |
| ➖ build-only | Windows ARM64 | No TrackAI Endpoint product name assigned; `git-ai-windows-arm64.exe` and `git-ai-windows-arm64.msi` are GitAI-only artifacts | `git-ai.exe` arm64 only | Build artifact only; no native or support claim. | Outside the initial Task9 support target; requires an explicit future platform decision. |

Standalone `git-ai-*` binaries and pinned Numbat builds are component/build
artifacts, not TrackAI Endpoint packages. A signed package means its platform
installer and bundled executables passed the applicable signing pipeline; it
does not imply APNs enrollment, Jamf validation, Task15n trust activation, or
native lifecycle validation.
