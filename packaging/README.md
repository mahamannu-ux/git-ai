# Git AI packaging

This directory contains MSI and PKG installer scaffolding for Git AI.

Package outputs install `git-ai` and, on macOS, the TrackAI-managed Numbat
binary. They must not install a `git`
wrapper, `git.exe` shim, `git-og`, or any other executable that changes Git
command routing. Per-user trace2 and editor/agent setup remains the
responsibility of `git-ai install-hooks`.

The release workflow builds signed/notarized production packages when the
required Apple and Azure signing secrets are configured. Dry-run releases can
build unsigned packages for validation. macOS releases include separate Intel
and Apple Silicon PKGs; the universal PKG was removed in Task20h-a.

The Windows MSI is per-user: it installs under
`%USERPROFILE%\\.git-ai\\bin` and changes only that user's `PATH`. It has no
all-users or Administrator install mode. The macOS PKG copies its bundled
binary into the active console user's `~/.git-ai/bin`, then runs setup as that
user. It fails if no valid console user is logged in or per-user setup fails.

For a managed rollout, upload the release PKG/MSI from your endpoint-management
system and install it post-login for the target user. Enrollment and
configuration resume in Task9c: the packages never receive, exchange, write,
or log a TrackAI machine credential, and live tenant evidence remains pending.
Managed configuration and OS secret-store bootstrap belong to Task9c.
