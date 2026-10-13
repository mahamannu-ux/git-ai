//! Static contract for the bounded Task9f macOS conformance harness and
//! evidence runbook. Native PKG installation, launchd, Keychain and Jamf are
//! founder-assisted gates and must never be performed by this test.

use std::fs;
use std::path::PathBuf;

fn repo_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn harness_is_read_only_isolated_and_redacted() {
    let harness = repo_file("scripts/task9/macos-conformance.sh");

    for required in [
        "MODE=\"plan\"",
        "Darwin",
        "target/task9-evidence",
        "mktemp -d",
        "umask 077",
        "trap cleanup EXIT",
        "HOME=\"$WORKSPACE/home\"",
        "GIT_AI_TEST_DB_PATH=\"$WORKSPACE/git-ai.db\"",
        "status=",
        "classification=",
    ] {
        assert!(
            harness.contains(required),
            "harness must retain the bounded safety marker {required}"
        );
    }

    for forbidden in [
        "sudo",
        "installer -pkg",
        "launchctl",
        "security ",
        "trk_v1",
        "API_KEY",
        "TRACKAI_MACHINE_CREDENTIAL",
        "hostname",
        "whoami",
        "ioreg",
        "system_profiler",
    ] {
        assert!(
            !harness.contains(forbidden),
            "harness must not contain privileged, secret, or device-identity surface {forbidden}"
        );
    }
}

#[test]
fn harness_inspects_only_explicit_artifacts() {
    let harness = repo_file("scripts/task9/macos-conformance.sh");

    for required in [
        "binary --binary",
        "package --package",
        "--checksum-file",
        "pkgutil --check-signature",
        "spctl -a -t install",
        "xcrun stapler validate",
        "LC_ALL=C LANG=C shasum -a 256",
        "lipo -archs",
        "codesign --verify --strict",
        "cp \"$BINARY\" \"$ISOLATED_BINARY\"",
        "\"$ISOLATED_BINARY\" --version",
        "version=\"${BASH_REMATCH[2]}\"",
    ] {
        assert!(
            harness.contains(required),
            "harness must retain explicit read-only inspection marker {required}"
        );
    }

    assert!(
        !harness.contains("$HOME/.git-ai"),
        "harness must not reference the founder's normal GitAI home"
    );
    assert!(
        !harness.contains("releases/latest"),
        "harness must never discover or fetch a mutable release"
    );
    assert!(
        !harness.contains("curl ") && !harness.contains("wget "),
        "harness must perform no network download"
    );
}

#[test]
fn release_workflow_pins_intel_signing_notarization_and_checksums() {
    let workflow = repo_file(".github/workflows/release.yml");

    for required in [
        "runs-on: macos-15-intel",
        "targets: x86_64-apple-darwin",
        "git-ai-macos-x64.pkg",
        "productsign",
        "codesign --verify --strict",
        "xcrun notarytool submit",
        "xcrun stapler staple",
        "xcrun stapler validate",
        "shasum -a 256 git-ai-macos-*.pkg",
        "PKG-SHA256SUMS",
    ] {
        assert!(
            workflow.contains(required),
            "release workflow must retain conformance gate {required}"
        );
    }
}

#[test]
fn runbook_keeps_all_live_claims_separate_and_pending() {
    let runbook = repo_file("docs/task9-macos-conformance.md");

    for row in [
        "Automated/static contract evidence",
        "Current Intel-Mac local evidence (`IT-T9-02`)",
        "Signed/notarized artifact evidence",
        "Jamf-managed evidence (`IT-T9-03`)",
        "Second-Mac/Apple-Silicon evidence (`IT-T9-07`)",
        "Task15-signed configuration/update execution (`IT-M9-01`)",
    ] {
        assert!(runbook.contains(row), "runbook must retain row {row}");
    }

    for boundary in [
        "unsigned development mechanics only",
        "No Jamf-managed macOS claim",
        "No two-device rollout-ring or Apple-Silicon claim",
        "zero download/install side effects",
        "pending prerequisite",
        "# after cross-agent review",
    ] {
        assert!(
            runbook.contains(boundary),
            "runbook must retain honest support boundary {boundary}"
        );
    }
}
