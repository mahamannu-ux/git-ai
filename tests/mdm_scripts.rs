//! Static checks on the Task9b MDM login-start scripts in `mdm/`.
//!
//! These scripts register the per-user `git-ai bg start --retry-secs` to run
//! at login. The daemon supervises itself (uptime restart, self-update,
//! lock-guarded single instance), so the launch definitions must never
//! supervise it and must never tear down the process group the daemon is left
//! in once `bg start` exits. The platform-specific behaviour is exercised in
//! CI by `scripts/mdm/test-login-start.{sh,ps1}`; these tests pin the
//! invariants that make those runs pass.
//!
//! Task9b scope: macOS and Windows only. There is no Linux script, no
//! `--env`/`--system` surface, and no credential/config transport — managed
//! configuration and secret-store bootstrap belong to Task9c. Ported from
//! upstream snapshot 0670e7ef27590af0e8ff5409267f3f4b09b8fcb4 (same Apache-2.0
//! project; per-user subset with `--env`/`--system`/Linux removed).

use std::fs;
use std::path::PathBuf;

fn repo_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn mdm_file(relative: &str) -> String {
    repo_file(&format!("mdm/{relative}"))
}

fn macos_script() -> String {
    mdm_file("macos/install-login-start.sh")
}

fn windows_script() -> String {
    mdm_file("windows/install-login-start.ps1")
}

fn macos_cleanup_script() -> String {
    mdm_file("macos/cleanup-endpoint.sh")
}

fn windows_cleanup_script() -> String {
    mdm_file("windows/cleanup-endpoint.ps1")
}

#[test]
fn macos_package_installs_monitor_hooks_to_the_shipper_file() {
    let postinstall = repo_file("packaging/macos/scripts/postinstall");
    for flag in [
        "hook install --agent \"$numbat_agent\" --managed --emit all",
        "--content preview --output file",
        "--rules-dir \"\\$HOME/.git-ai/internal/security/rules/current/$source_agent\"",
        "--output-file '$HOME/.numbat/records.ndjson'",
    ] {
        assert!(
            postinstall.contains(flag),
            "missing managed hook argument: {flag}"
        );
    }
    assert!(!postinstall.contains("--enforce"));
    assert!(!postinstall.contains("--no-builtin-rules"));
    assert!(postinstall.contains("builtin-rule-ids.txt"));
    assert_eq!(repo_file("packaging/macos/agents.tsv").lines().count(), 5);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_package_replaces_current_symlink_without_touching_bundle_directory() {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let postinstall = repo_file("packaging/macos/scripts/postinstall");
    assert!(postinstall.contains("/bin/mv -fh \"$RULES_DIR/current.next\" \"$RULES_DIR/current\""));

    let temp = tempfile::tempdir().unwrap();
    let rules = temp.path();
    fs::create_dir(rules.join("version")).unwrap();
    symlink("version", rules.join("current")).unwrap();
    symlink("placeholder", rules.join("current.next")).unwrap();
    let status = Command::new("/bin/mv")
        .args(["-fh"])
        .arg(rules.join("current.next"))
        .arg(rules.join("current"))
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::read_link(rules.join("current")).unwrap(),
        PathBuf::from("placeholder")
    );
    assert!(
        rules
            .join("version/current.next")
            .symlink_metadata()
            .is_err()
    );
}

/// Asserts that the plist `<key>` is immediately followed by `<value/>`,
/// ignoring the whitespace between them.
fn plist_key_has_value(plist: &str, key: &str, value: &str) -> bool {
    let key_tag = format!("<key>{key}</key>");
    plist
        .split(&key_tag)
        .skip(1)
        .any(|rest| rest.trim_start().starts_with(&format!("<{value}/>")))
}

#[test]
fn macos_launch_agent_abandons_process_group_and_never_keeps_alive() {
    let script = macos_script();

    assert!(
        plist_key_has_value(&script, "AbandonProcessGroup", "true"),
        "launchd kills the daemon left behind by `bg start` unless AbandonProcessGroup is true"
    );
    assert!(
        plist_key_has_value(&script, "KeepAlive", "false"),
        "KeepAlive would fight the daemon's own lock-guarded self-restart"
    );
    assert!(
        plist_key_has_value(&script, "RunAtLoad", "true"),
        "RunAtLoad is what makes the agent fire at login"
    );
    assert!(
        script.contains("com.usegitai.bg"),
        "launch agent label should be stable so MDM tooling can reference it"
    );
    assert!(
        script.contains("bg start") && !script.contains("bg run"),
        "the agent must invoke the idempotent `bg start`, never the foreground `bg run`"
    );
    assert!(
        script.contains(r#"$(xml_string "$BIN")"#),
        "per-user agents must run the git-ai binary directly so macOS shows \"git-ai\", not \"sh\", as the login item"
    );
}

#[test]
fn windows_task_runs_once_per_logon_as_the_current_user_without_time_limit() {
    let script = windows_script();

    assert!(
        script.contains("-MultipleInstances IgnoreNew"),
        "a second task instance must not race the running daemon"
    );
    assert!(
        script.contains("-LogonType Interactive"),
        "task must run in the logged-on user's own session"
    );
    assert!(
        script.contains("-ExecutionTimeLimit"),
        "task must disable the execution time limit so Task Scheduler never ends the instance"
    );
    assert!(
        !script.contains(r"BUILTIN\Users") && !script.contains("-RunLevel Highest"),
        "task must be per-user and unelevated; group principals require administrator rights"
    );
    assert!(
        script.contains("bg start") && !script.contains("bg run"),
        "the task must invoke the idempotent `bg start`, never the foreground `bg run`"
    );
    assert!(
        !script.contains("$attempt"),
        "the launcher must not loop itself; retries live in `bg start --retry-secs`"
    );
}

#[test]
fn all_scripts_share_the_same_cli_contract() {
    for (name, script) in [("macos", macos_script()), ("windows", windows_script())] {
        for flag in ["--uninstall", "--bin", "--no-start"] {
            assert!(
                script.contains(flag),
                "{name} script must support {flag} like the other platform"
            );
        }
        assert!(
            script.contains("bg start --retry-secs"),
            "{name} launcher must let bg start retry through a login-time lock race"
        );
    }
}

#[test]
fn scripts_reject_unsafe_bin_paths() {
    let macos = macos_script();
    assert!(
        macos.contains("must be an absolute path"),
        "macOS script must require an absolute --bin path"
    );
    assert!(
        macos.contains("carriage return"),
        "macOS script must reject newline/carriage-return --bin paths"
    );
    assert!(
        macos.contains("not an executable"),
        "macOS script must verify --bin is executable"
    );

    let windows = windows_script();
    assert!(
        windows.contains("must be an absolute path"),
        "Windows script must require an absolute --bin path"
    );
    assert!(
        windows.contains("[a-zA-Z]:[\\\\/]"),
        "Windows script must require a fully-qualified --bin path: drive-relative (C:foo) and root-relative (\\foo) forms are not absolute"
    );
    assert!(
        windows.contains("not found; install git-ai first or pass --bin"),
        "Windows script must verify --bin exists"
    );
    assert!(
        windows.to_lowercase().contains("carriage return")
            || windows.contains("`r")
            || windows.contains("\\r"),
        "Windows script must reject newline/carriage-return --bin paths"
    );
}

#[test]
fn scripts_carry_no_credential_transport() {
    for (name, script) in [("macos", macos_script()), ("windows", windows_script())] {
        for forbidden in ["API_KEY", "API_BASE", "trk_v1", "api-key"] {
            assert!(
                !script.contains(forbidden),
                "{name} script must not transport credentials ({forbidden})"
            );
        }
        assert!(
            !script.contains("--env"),
            "{name} script must not take --env: managed configuration belongs to Task9c"
        );
        assert!(
            !script.contains("--system"),
            "{name} script is per-user only: no --system mode in Task9b"
        );
    }
}

#[test]
fn no_linux_drift() {
    let linux_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mdm/linux/install-login-start.sh");
    assert!(
        !linux_path.exists(),
        "Task9b ships no Linux login-start script"
    );
    let release = repo_file(".github/workflows/release.yml");
    assert!(
        !release.contains("git-ai-login-start-linux.sh"),
        "release.yml must not publish a Linux login-start asset in Task9b"
    );
    let readme = mdm_file("README.md");
    assert!(
        !readme.contains("git-ai-login-start-linux.sh"),
        "mdm/README.md must not document a Linux login-start asset in Task9b"
    );
}

#[test]
fn readme_documents_the_launch_invariants() {
    let readme = mdm_file("README.md");

    for keyword in [
        "AbandonProcessGroup",
        "IgnoreNew",
        "lock",
        "--retry-secs",
        "--uninstall",
        "--bin",
        "--no-start",
        "Task9c",
    ] {
        assert!(
            readme.contains(keyword),
            "mdm/README.md must explain {keyword}"
        );
    }
    assert!(
        !readme.contains("--system"),
        "mdm/README.md must not offer --system in Task9b (per-user only)"
    );
}

#[test]
fn release_workflow_publishes_the_scripts_as_assets() {
    let release = repo_file(".github/workflows/release.yml");
    let readme = mdm_file("README.md");

    for asset in [
        "git-ai-login-start-macos.sh",
        "git-ai-login-start-windows.ps1",
    ] {
        assert!(
            release.contains(asset),
            "release.yml must copy {asset} into the release assets"
        );
        assert!(
            readme.contains(asset),
            "mdm/README.md must document the {asset} download"
        );
    }
    assert!(
        release.contains("sha256sum install.sh install.ps1 git-ai-login-start-*"),
        "login-start assets must be covered by SHA256SUMS"
    );
}

#[test]
fn published_release_selector_fixtures_are_deterministic_and_fail_closed() {
    let selector = repo_file("scripts/mdm/select-release-pair.py");
    for required in [
        "no eligible release pair",
        "trackai-endpoint-macos-arm64.pkg",
        "trackai-endpoint-macos-x64.pkg",
        "git-ai-windows-x64.msi",
        "git-ai-login-start-macos.sh",
        "git-ai-login-start-windows.ps1",
        "install.sh",
        "install.ps1",
        "PKG-SHA256SUMS",
        "SHA256SUMS",
        "production_trust_pinned",
    ] {
        assert!(
            selector.contains(required),
            "published-release selector must retain eligibility marker {required}"
        );
    }

    let output = std::process::Command::new("python3")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/mdm/select-release-pair.py"))
        .arg("--self-test")
        .output()
        .expect("run published-release selector fixture tests");
    assert!(
        output.status.success(),
        "selector fixture tests failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn published_release_workflow_is_immutable_bounded_and_honest() {
    let workflow = repo_file(".github/workflows/mdm-login-start-nightly.yml");
    for required in [
        "permissions:\n  contents: read",
        "no eligible release pair",
        "pair_available == 'true'",
        "scripts/mdm/select-release-pair.py --self-test",
        "https://api.github.com/repos/${GITHUB_REPOSITORY}/releases",
        "gh release download \"$tag\"",
        "diff --no-dereference --brief",
        "SHA256SUMS",
        "gh attestation verify",
        "attestations: read",
        "needs: [select-releases, published-assets]",
        "Download and verify selected fork installer",
        "test -n \"$expected\" && test \"$expected\" = \"$actual\"",
        "--source-digest \"$source_digest\"",
        "--signer-workflow \"$GITHUB_REPOSITORY/.github/workflows/release.yml\"",
        "path: ${{ runner.temp }}/mdm-logs",
        "retention-days: 7",
        "security: not monitored on Windows",
    ] {
        assert!(
            workflow.contains(required),
            "published-release workflow must retain safeguard {required}"
        );
    }
    for forbidden in [
        "api.github.com/repos/git-ai-project/git-ai",
        "github.com/git-ai-project/git-ai/releases",
        "releases/latest",
        "continue-on-error: true",
        "mdm/linux",
        "~/.numbat",
        "~/.git-ai/internal/security",
        "/Library/Application Support/TrackAI/Endpoint",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "published-release workflow must exclude {forbidden}"
        );
    }
}

#[test]
fn published_update_harnesses_keep_registration_and_fork_identity() {
    let macos = repo_file("scripts/mdm/test-login-start.sh");
    for required in [
        "lifecycle|auto-update",
        "GIT_AI_INSTALL_SCRIPT",
        "GIT_AI_DAEMON_UPDATE_CHECK_INTERVAL",
        "binary updated to $latest",
        "daemon restarted after update",
        "login start registration missing after update",
    ] {
        assert!(
            macos.contains(required),
            "macOS published update harness must retain {required}"
        );
    }

    let windows = repo_file("scripts/mdm/test-login-start.ps1");
    for required in [
        "'lifecycle', 'auto-update'",
        "GIT_AI_INSTALL_SCRIPT",
        "GIT_AI_DAEMON_UPDATE_CHECK_INTERVAL",
        "binary updated to $latest",
        "daemon restarted after update",
        "login start registration missing after update",
    ] {
        assert!(
            windows.contains(required),
            "Windows published update harness must retain {required}"
        );
    }
    assert!(!macos.contains("--env") && !windows.contains("--env"));
}

#[test]
fn cleanup_wrappers_are_dry_run_first_and_explicit() {
    for (name, script) in [
        ("macos", macos_cleanup_script()),
        ("windows", windows_cleanup_script()),
    ] {
        assert!(
            script.contains("--dry-run") && script.contains("--apply"),
            "{name} cleanup wrapper must support --dry-run and --apply"
        );
        assert!(
            script.contains("--bin"),
            "{name} cleanup wrapper must support --bin like the login-start scripts"
        );
        assert!(
            script.contains("fleet cleanup"),
            "{name} cleanup wrapper must reuse the fleet cleanup command surface"
        );
        assert!(
            script.contains("--uninstall"),
            "{name} cleanup wrapper must deregister login-start via the existing --uninstall scripts"
        );
        assert!(
            !script.contains("rm -rf \"$HOME/.git-ai\"")
                && !script.contains("Remove-Item -Recurse"),
            "{name} cleanup wrapper must never erase ~/.git-ai wholesale"
        );
        for forbidden in ["trk_v1", "API_KEY", "API_BASE", "api-key"] {
            assert!(
                !script.contains(forbidden),
                "{name} cleanup wrapper must not transport credentials ({forbidden})"
            );
        }
        assert!(
            !script.contains("--env") && !script.contains("--system"),
            "{name} cleanup wrapper is per-user only with no config transport"
        );
    }
    assert!(
        macos_cleanup_script().contains("MODE=\"dry-run\""),
        "macOS cleanup wrapper must default to dry-run"
    );
    assert!(
        windows_cleanup_script().contains("$Mode = 'dry-run'"),
        "Windows cleanup wrapper must default to dry-run"
    );
    assert!(
        macos_cleanup_script().contains("--user")
            && macos_cleanup_script().contains("hook uninstall")
            && macos_cleanup_script().contains("--managed")
            && macos_cleanup_script().contains("run cleanup as root"),
        "macOS cleanup must remove managed hooks as root and retain its user-scoped Task9 path"
    );
    assert!(
        !windows_cleanup_script().contains("-RunLevel Highest"),
        "Windows cleanup wrapper must stay unelevated"
    );
    assert!(
        macos_cleanup_script().contains("must be an absolute path")
            && macos_cleanup_script().contains("carriage return"),
        "macOS cleanup wrapper must validate --bin paths"
    );
    assert!(
        windows_cleanup_script().contains("must be an absolute path")
            && windows_cleanup_script().contains("[a-zA-Z]:[\\\\/]"),
        "Windows cleanup wrapper must require fully-qualified --bin paths"
    );
    let linux_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mdm/linux/cleanup-endpoint.sh");
    assert!(
        !linux_path.exists(),
        "Task9d ships no Linux cleanup wrapper"
    );
}

#[test]
fn cleanup_wrappers_propagate_uninstall_failure() {
    let macos = macos_cleanup_script();
    assert!(
        !macos.contains("|| true"),
        "macOS cleanup wrapper must not silence the uninstall step"
    );
    for marker in ["UNINSTALL_STATUS", "CLEANUP_STATUS", "exit 1"] {
        assert!(
            macos.contains(marker),
            "macOS cleanup wrapper must propagate uninstall/cleanup failure ({marker})"
        );
    }

    let windows = windows_cleanup_script();
    assert!(
        !windows.contains("catch { }"),
        "Windows cleanup wrapper must not swallow uninstall failure"
    );
    for marker in ["$uninstallFailed", "$cleanupOk", "exit 1"] {
        assert!(
            windows.contains(marker),
            "Windows cleanup wrapper must propagate uninstall/cleanup failure ({marker})"
        );
    }
}

#[test]
fn macos_cleanup_receipt_contract_is_explicit_and_root_only() {
    let macos = macos_cleanup_script();
    for required in [
        "RECEIPT_ID=\"com.git-ai.git-ai\"",
        "receipt $RECEIPT_ID retained; rerun as root to forget it",
        "pkgutil --forget \"$RECEIPT_ID\"",
        "receipt=$RECEIPT_ID",
    ] {
        assert!(
            macos.contains(required),
            "macOS cleanup must retain receipt safeguard {required}"
        );
    }
}

/// Exercise the macOS cleanup wrapper end to end with stubbed siblings: the
/// wrapper must still run `fleet cleanup --apply` when uninstall fails, and
/// must exit nonzero when either half fails.
#[cfg(unix)]
#[test]
fn macos_cleanup_wrapper_runs_cleanup_and_reports_each_half() {
    use std::os::unix::fs::PermissionsExt;

    fn write_executable(path: &std::path::Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    std::fs::copy(
        manifest.join("mdm/macos/cleanup-endpoint.sh"),
        dir.join("cleanup-endpoint.sh"),
    )
    .unwrap();
    // Fake git-ai: records its arguments and exits as directed.
    write_executable(
        &dir.join("git-ai"),
        "#!/bin/sh\necho \"$@\" >> \"$FAKE_LOG\"\nexit \"${FAKE_GIT_AI_EXIT:-0}\"\n",
    );

    for (uninstall_exit, cleanup_exit, expected) in [(1, 0, 1), (0, 1, 1), (0, 0, 0)] {
        write_executable(
            &dir.join("install-login-start.sh"),
            &format!("#!/bin/sh\nexit {uninstall_exit}\n"),
        );
        let _ = std::fs::remove_file(dir.join("calls.log"));
        let output = std::process::Command::new("sh")
            .arg(dir.join("cleanup-endpoint.sh"))
            .arg("--apply")
            .arg("--bin")
            .arg(dir.join("git-ai"))
            .env("HOME", dir)
            .env("FAKE_LOG", dir.join("calls.log"))
            .env("FAKE_GIT_AI_EXIT", cleanup_exit.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "uninstall={uninstall_exit} cleanup={cleanup_exit}"
        );
        // Cleanup always runs, even when uninstall fails.
        let calls = std::fs::read_to_string(dir.join("calls.log")).unwrap();
        assert!(
            calls.contains("fleet cleanup --apply"),
            "cleanup must run despite uninstall failure: {calls}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).lines().any(
                |line| line == "receipt com.git-ai.git-ai retained; rerun as root to forget it"
            ),
            "non-root cleanup must disclose that the package receipt remains"
        );
    }
}

/// Exercise the root-only receipt path without privileges by rewriting only
/// absolute system command paths in a disposable copy. This preserves the
/// production control flow while keeping pkgutil and filesystem mutation fake.
#[cfg(target_os = "macos")]
#[test]
fn macos_cleanup_forgets_receipt_only_after_root_cleanup_and_stopped_daemon() {
    use std::os::unix::fs::PermissionsExt;

    fn write_executable(path: &std::path::Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let fake_home = dir.join("home");
    std::fs::create_dir(&fake_home).unwrap();
    let git_ai = dir.join("git-ai");
    let dscl = dir.join("dscl");
    let pkgutil = dir.join("pkgutil");
    let calls = dir.join("calls.log");
    let receipts = dir.join("receipts.log");

    write_executable(
        &git_ai,
        "#!/bin/sh\necho \"$@\" >> \"$FAKE_LOG\"\ncase \"$*\" in\n  *'bg status'*)\n    if [ \"${FAKE_DAEMON_RUNNING:-0}\" = 1 ]; then echo '{\"daemon_running\": true}'; else echo '{\"daemon_running\": false}'; fi\n    ;;\n  *'fleet cleanup --apply'*) exit \"${FAKE_CLEANUP_EXIT:-0}\" ;;\nesac\nexit 0\n",
    );
    write_executable(
        &dscl,
        "#!/bin/sh\nprintf 'NFSHomeDirectory: %s\\n' \"$FAKE_HOME\"\n",
    );
    write_executable(
        &pkgutil,
        "#!/bin/sh\necho \"$@\" >> \"$FAKE_RECEIPTS\"\nexit 0\n",
    );

    let original = macos_cleanup_script();
    let transformed = original
        .replace(
            "if [ \"$(id -u)\" -eq 0 ]; then",
            "if [ \"${FAKE_UID:-$(id -u)}\" -eq 0 ]; then",
        )
        .replace("/usr/bin/sudo -H -u \"$TARGET_USER\" ", "")
        .replace("/usr/bin/dscl", &dscl.display().to_string())
        .replace("/usr/sbin/pkgutil", &pkgutil.display().to_string())
        .replace(
            "NUMBAT_ADMIN_DIR=\"/Library/Application Support/TrackAI/Endpoint\"",
            &format!("NUMBAT_ADMIN_DIR=\"{}\"", dir.join("endpoint").display()),
        );
    let cleanup = dir.join("cleanup-endpoint.sh");
    write_executable(&cleanup, &transformed);
    let user = std::env::var("USER").expect("USER is set on macOS");

    let run = |daemon_running: bool| {
        let _ = std::fs::remove_file(&receipts);
        std::process::Command::new("sh")
            .arg(&cleanup)
            .arg("--apply")
            .arg("--user")
            .arg(&user)
            .arg("--bin")
            .arg(&git_ai)
            .env("FAKE_UID", "0")
            .env("FAKE_HOME", &fake_home)
            .env("FAKE_LOG", &calls)
            .env("FAKE_RECEIPTS", &receipts)
            .env(
                "FAKE_DAEMON_RUNNING",
                if daemon_running { "1" } else { "0" },
            )
            .output()
            .unwrap()
    };

    let success = run(false);
    assert!(
        success.status.success(),
        "root cleanup failed: {}",
        String::from_utf8_lossy(&success.stderr)
    );
    let receipt_calls = std::fs::read_to_string(&receipts).unwrap();
    assert!(receipt_calls.contains("--pkg-info com.git-ai.git-ai"));
    assert!(receipt_calls.contains("--forget com.git-ai.git-ai"));

    let daemon_running = run(true);
    assert!(!daemon_running.status.success());
    assert!(String::from_utf8_lossy(&daemon_running.stderr).contains("daemon still running"));
    assert!(
        !receipts.exists(),
        "receipt must remain when daemon shutdown did not complete"
    );
}
