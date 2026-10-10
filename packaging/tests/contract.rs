//! Task9b package contract: the PKG/MSI install only the GitAI binary and the
//! existing per-user setup. They never receive, exchange, write, or log a
//! TrackAI machine credential; managed configuration and OS secret-store
//! bootstrap belong to Task9c.
//!
//! Dependency-free (std only). Ported provenance: upstream MSI hardening and
//! smoke fixes at snapshot 0670e7ef27590af0e8ff5409267f3f4b09b8fcb4 (same
//! Apache-2.0 project), adapted to remove — not replace — the secret-bearing
//! MSI surface. Run with `task test CARGO_TEST_ARGS="--test packaging_contract"`.

use std::fs;
use std::path::PathBuf;

fn repo_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn packaging_file(relative: &str) -> String {
    repo_file(&format!("packaging/{relative}"))
}

fn wxs() -> String {
    packaging_file("windows/git-ai.wxs")
}

fn build_msi() -> String {
    packaging_file("windows/build-msi.ps1")
}

fn postinstall() -> String {
    packaging_file("macos/scripts/postinstall")
}

fn build_pkg() -> String {
    packaging_file("macos/build-pkg.sh")
}

fn packaging_readme() -> String {
    packaging_file("README.md")
}

#[test]
fn msi_accepts_no_credential_input() {
    for (name, contents) in [("git-ai.wxs", wxs()), ("build-msi.ps1", build_msi())] {
        for forbidden in ["API_KEY", "API_BASE", "trk_v1", "api-key"] {
            assert!(
                !contents.contains(forbidden),
                "{name} must not accept credential input ({forbidden})"
            );
        }
    }
    assert!(
        !wxs().contains("ConfigureGitAi"),
        "git-ai.wxs must not keep the ConfigureGitAi property/custom action"
    );
    assert!(
        !wxs().contains("install-hooks"),
        "the MSI must not invoke install-hooks with (or without) credential arguments"
    );
}

#[test]
fn msi_remains_per_user_with_clean_uninstall() {
    let wxs = wxs();
    assert!(
        wxs.contains(r#"Scope="perUser""#),
        "MSI must remain per-user"
    );
    assert!(
        wxs.contains(r"[WIX_DIR_PROFILE]\.git-ai\bin"),
        "MSI must install under the installing user's profile"
    );
    assert!(
        wxs.contains(r#"Name="git-ai.exe""#),
        "MSI must install git-ai.exe"
    );
    assert!(
        wxs.contains("<MajorUpgrade"),
        "MSI must keep major-upgrade handling"
    );
    // The MSI owns exactly one user PATH entry and removes it on uninstall.
    assert_eq!(
        wxs.matches("<Environment").count(),
        1,
        "MSI must own only its user PATH entry"
    );
    assert!(
        wxs.contains(r#"Name="PATH""#)
            && wxs.contains(r#"Part="first""#)
            && wxs.contains(r#"System="no""#)
            && wxs.contains(r#"Permanent="no""#),
        "MSI PATH entry must be per-user, first in order, and removed on uninstall"
    );
    for forbidden in [
        "ALLUSERS",
        "ProgramFiles",
        "ProgramFiles64",
        r#"Scope="perMachine""#,
    ] {
        assert!(
            !wxs.contains(forbidden),
            "MSI must not gain an all-users/System install mode ({forbidden})"
        );
    }
}

#[test]
fn macos_postinstall_carries_no_credential() {
    let postinstall = postinstall();
    for forbidden in [
        "API_KEY",
        "API_BASE",
        "trk_v1",
        "api-key",
        "--api-key",
        "--api-base",
    ] {
        assert!(
            !postinstall.contains(forbidden),
            "macOS postinstall must contain no credential/config argument ({forbidden})"
        );
    }
    assert!(
        postinstall.contains("no valid console user"),
        "macOS postinstall must still reject invalid console users"
    );
    assert!(
        postinstall.contains("install-hooks"),
        "macOS postinstall must keep the existing per-user hook setup"
    );
    for (name, contents) in [
        ("build-pkg.sh", build_pkg()),
        ("build-msi.ps1", build_msi()),
    ] {
        for forbidden in ["API_KEY", "trk_v1", "api-key"] {
            assert!(
                !contents.contains(forbidden),
                "{name} must not handle credential material ({forbidden})"
            );
        }
    }
}

#[test]
fn managed_docs_point_secure_enrollment_to_task9c() {
    let readme = packaging_readme();
    for forbidden in ["API_KEY", "API_BASE", "trk_v1", "api-key", "your-api-key"] {
        assert!(
            !readme.contains(forbidden),
            "packaging/README.md must contain no example secret ({forbidden})"
        );
    }
    assert!(
        readme.contains("Task9c"),
        "packaging/README.md must point secure enrollment to Task9c"
    );
    assert!(
        readme.contains("per-user") || readme.contains("per-user"),
        "packaging/README.md must keep the per-user install model front and center"
    );
}
