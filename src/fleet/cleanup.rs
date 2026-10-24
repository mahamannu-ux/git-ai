//! Explicit, dry-run-first local endpoint cleanup for Task9d.
//!
//! TrackAI offboarding revokes server authority first and deliberately returns
//! `localCleanup: best_effort_not_requested_by_server`. Cleanup is therefore
//! never inferred from a 401, 403, network error, missing configuration or any
//! other transient failure: it runs only when a local administrator (or MDM via
//! the bounded `mdm/*/cleanup-endpoint` wrappers) explicitly invokes
//! `git-ai fleet cleanup --apply`.
//!
//! Dry-run prints only bounded safe metadata (planned actions, paths and
//! credential key IDs, which are already non-secret) and performs no mutation.
//! Apply removes only Task9-owned endpoint state: the TrackAI machine
//! credential, managed bootstrap/configuration state and login-start
//! registration. It preserves the durable evidence queue, authorship notes,
//! repositories, user login credentials and ordinary GitAI data: it never
//! erases `~/.git-ai` wholesale and never uninstalls the GitAI binary.

use crate::auth::machine_credentials::{MachineCredentialStore, MachineCredentialStoreCode};
use std::path::{Path, PathBuf};

/// Managed bootstrap file written by `fleet bootstrap install`, relative to
/// `~/.git-ai`.
pub const MANAGED_POLICY_FILE: &str = "trackai-delivery-policy.json";
/// Managed fleet state file, relative to `~/.git-ai`.
pub const MANAGED_STATE_REL: &str = "fleet/state.json";
/// macOS login-start registration, relative to `$HOME`.
pub const LOGIN_PLIST_REL: &str = "Library/LaunchAgents/com.usegitai.bg.plist";
/// Windows login-start launcher, relative to `$HOME`.
pub const LOGIN_LAUNCHER_REL: &str = ".git-ai/login/start-bg.ps1";

const MAX_KEY_IDS: usize = 64;

/// Bounded, printable cleanup plan. Contains only actions, paths and key IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPlan {
    pub credential_key_ids: Vec<String>,
    pub remove_files: Vec<PathBuf>,
    pub remove_dirs: Vec<PathBuf>,
    pub deregister_login_start: bool,
}

/// Per-step apply result. Missing items are successful idempotent outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupStep {
    pub action: &'static str,
    pub target: String,
    pub result: StepResult,
}

/// Step results carry only fixed codes, never secrets or file contents.
/// Deferred marks work intentionally retained for a later retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    Ok,
    Missing,
    Deferred(&'static str),
    Failed(&'static str),
}

impl StepResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Deferred(code) | Self::Failed(code) => code,
        }
    }

    fn succeeded(self) -> bool {
        matches!(self, Self::Ok | Self::Missing)
    }
}

/// Exit code for `fleet cleanup --apply`: nonzero when any step failed or was
/// deferred, so MDM and scripts can retry.
pub fn cleanup_apply_exit_code(steps: &[CleanupStep]) -> i32 {
    if steps.iter().all(|step| step.result.succeeded()) {
        0
    } else {
        1
    }
}

fn valid_key_id(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn policy_path(home: &Path) -> PathBuf {
    home.join(".git-ai").join(MANAGED_POLICY_FILE)
}

fn state_path(home: &Path) -> PathBuf {
    home.join(".git-ai").join(MANAGED_STATE_REL)
}

/// Platform login-start registration owned by Task9 login-start setup.
/// macOS and Windows only; there is no Linux support.
pub fn login_start_path(home: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(home.join(LOGIN_PLIST_REL))
    }
    #[cfg(windows)]
    {
        Some(home.join(LOGIN_LAUNCHER_REL))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = home;
        None
    }
}

fn read_key_ids(policy_path: &Path) -> Vec<String> {
    let raw = std::fs::read(policy_path).unwrap_or_default();
    if raw.is_empty() {
        return Vec::new();
    }
    let value: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let mut ids = Vec::new();
    if let Some(entries) = value.get("repositories").and_then(|value| value.as_array()) {
        for entry in entries {
            if let Some(key_id) = entry
                .get("credential_key_id")
                .and_then(|value| value.as_str())
                .filter(|key_id| valid_key_id(key_id))
                && !ids.contains(&key_id.to_string())
            {
                ids.push(key_id.to_string());
            }
            if ids.len() >= MAX_KEY_IDS {
                break;
            }
        }
    }
    ids
}

/// Build the bounded cleanup plan. Reads at most the small bootstrap file;
/// performs no mutation. The staged-update directory is included so a
/// superseded staged bundle can never install after offboarding.
pub fn plan_cleanup(home: &Path) -> CleanupPlan {
    CleanupPlan {
        credential_key_ids: read_key_ids(&policy_path(home)),
        remove_files: vec![policy_path(home), state_path(home)],
        remove_dirs: vec![crate::fleet::managed_update::staging_dir_for_home(home)],
        deregister_login_start: true,
    }
}

fn store_code(code: MachineCredentialStoreCode) -> &'static str {
    match code {
        MachineCredentialStoreCode::Available => "available",
        MachineCredentialStoreCode::Missing => "missing",
        MachineCredentialStoreCode::Locked => "locked",
        MachineCredentialStoreCode::Unsupported => "unsupported",
        MachineCredentialStoreCode::Corrupt => "corrupt",
    }
}

/// Login-start deregistration seam. The production implementation removes the
/// registration file, unloads the platform registration best-effort, and then
/// verifies absence; tests inject fakes.
pub trait LoginStartDeregistrar {
    fn deregister(&self, home: &Path) -> StepResult;
    fn registration_absent(&self, home: &Path) -> bool;
}

/// Production login-start deregistration (macOS and Windows only).
pub struct PlatformLoginStart;

impl LoginStartDeregistrar for PlatformLoginStart {
    fn deregister(&self, home: &Path) -> StepResult {
        let Some(path) = login_start_path(home) else {
            return StepResult::Missing;
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return StepResult::Missing;
            }
            Err(_) => return StepResult::Failed("remove_failed"),
        }
        // Best-effort platform unload; `registration_absent` below decides the
        // step, so a no-op unload (nothing registered) is not a failure.
        unload_login_start();
        StepResult::Ok
    }

    fn registration_absent(&self, home: &Path) -> bool {
        if login_start_path(home).is_some_and(|path| path.exists()) {
            return false;
        }
        platform_registration_absent()
    }
}

fn unload_login_start() {
    #[cfg(target_os = "macos")]
    {
        let uid = std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|uid| uid.trim().to_string())
            .unwrap_or_default();
        if uid.is_empty() {
            return;
        }
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("gui/{uid}/com.usegitai.bg")])
            .output();
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("schtasks")
            .args(["/Delete", "/TN", r"\GitAI\Start bg at logon", "/F"])
            .creation_flags(crate::utils::CREATE_NO_WINDOW)
            .output();
    }
}

/// Bounded process-runner seam for platform registration queries. Tests inject
/// scripted runners; production spawns the real tools.
#[derive(Clone)]
pub struct CommandResult {
    pub success: bool,
    pub output: String,
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandResult, &'static str>;
}

/// Production runner: at most 4 KiB of combined output, never logged.
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandResult, &'static str> {
        let mut command = std::process::Command::new(program);
        command.args(args);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(crate::utils::CREATE_NO_WINDOW);
        }
        let output = command.output().map_err(|_| "command_unavailable")?;
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        combined.truncate(4096);
        Ok(CommandResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&combined).into_owned(),
        })
    }
}

#[cfg(target_os = "macos")]
fn current_uid(runner: &dyn CommandRunner) -> String {
    runner
        .run("id", &["-u"])
        .ok()
        .filter(|result| result.success)
        .map(|result| result.output.trim().to_string())
        .unwrap_or_default()
}

/// True only on a recognized "not registered" result: launchctl reports the
/// service as unfound. Tool, query and unexpected failures are not absence.
#[cfg(any(test, target_os = "macos"))]
fn macos_registration_absent(runner: &dyn CommandRunner, uid: &str) -> bool {
    if uid.is_empty() {
        return false;
    }
    match runner.run(
        "launchctl",
        &["print", &format!("gui/{uid}/com.usegitai.bg")],
    ) {
        Ok(result) if result.success => false,
        Ok(result) if result.output.contains("Could not find service") => true,
        _ => false,
    }
}

/// True only on a recognized "not found" result: schtasks reports the task
/// file as missing. Tool, query and unexpected failures are not absence.
#[cfg(any(test, windows))]
fn windows_registration_absent(runner: &dyn CommandRunner) -> bool {
    match runner.run("schtasks", &["/Query", "/TN", r"\GitAI\Start bg at logon"]) {
        Ok(result) if result.success => false,
        Ok(result)
            if result
                .output
                .to_lowercase()
                .contains("cannot find the file") =>
        {
            true
        }
        _ => false,
    }
}

/// True only when no platform registration remains. An unverifiable
/// registration counts as present so cleanup reports failure instead of a
/// false success.
fn platform_registration_absent() -> bool {
    #[cfg(target_os = "macos")]
    {
        let runner = SystemRunner;
        macos_registration_absent(&runner, &current_uid(&runner))
    }
    #[cfg(windows)]
    {
        windows_registration_absent(&SystemRunner)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        true
    }
}

/// Apply a plan built by [`plan_cleanup`]. Continues past missing items and
/// per-step failures so partial cleanup still reports every safe step result,
/// but a failed credential deletion retains the policy file: it holds the key
/// IDs required to find the orphaned secret on retry.
pub fn apply_cleanup(
    plan: &CleanupPlan,
    home: &Path,
    store: &dyn MachineCredentialStore,
    registrar: &dyn LoginStartDeregistrar,
) -> Vec<CleanupStep> {
    let mut steps = Vec::new();
    let mut credential_failed = false;
    for key_id in &plan.credential_key_ids {
        let result = match store.delete(key_id) {
            Ok(()) => StepResult::Ok,
            Err(error) if error.code == MachineCredentialStoreCode::Missing => StepResult::Missing,
            Err(error) => {
                credential_failed = true;
                StepResult::Failed(store_code(error.code))
            }
        };
        steps.push(CleanupStep {
            action: "delete-credential",
            target: format!("key_id={key_id}"),
            result,
        });
    }
    let policy = policy_path(home);
    for path in &plan.remove_files {
        if credential_failed && *path == policy {
            steps.push(CleanupStep {
                action: "remove-file",
                target: path.to_string_lossy().into_owned(),
                result: StepResult::Deferred("deferred_credential_cleanup"),
            });
            continue;
        }
        let result = match std::fs::remove_file(path) {
            Ok(()) => StepResult::Ok,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => StepResult::Missing,
            Err(_) => StepResult::Failed("remove_failed"),
        };
        steps.push(CleanupStep {
            action: "remove-file",
            target: path.to_string_lossy().into_owned(),
            result,
        });
    }
    for dir in &plan.remove_dirs {
        let result = match std::fs::remove_dir_all(dir) {
            Ok(()) => StepResult::Ok,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => StepResult::Missing,
            Err(_) => StepResult::Failed("remove_failed"),
        };
        steps.push(CleanupStep {
            action: "remove-dir",
            target: dir.to_string_lossy().into_owned(),
            result,
        });
    }
    if plan.deregister_login_start {
        let removed = registrar.deregister(home);
        let result = if registrar.registration_absent(home) {
            removed
        } else {
            StepResult::Failed("deregistration_failed")
        };
        let target = match removed {
            StepResult::Missing if result == StepResult::Missing => {
                "login-start-registration".to_string()
            }
            _ => login_start_path(home)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|| "login-start-registration".to_string()),
        };
        steps.push(CleanupStep {
            action: "deregister-login-start",
            target,
            result,
        });
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::machine_credentials::{
        MachineCredentialError, MachineCredentialStore, MemoryMachineCredentialStore,
    };
    use crate::fleet::{ConfigurationResponse, classify_configuration_response};
    use std::cell::RefCell;

    fn home_with_policy(key_ids: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join(".git-ai/fleet")).unwrap();
        let repositories: Vec<serde_json::Value> = key_ids
            .iter()
            .map(|key_id| {
                serde_json::json!({
                    "repository_url": "https://github.com/example/repo",
                    "repository_id": "11111111-1111-4111-8111-111111111111",
                    "tenant_id": "22222222-2222-4222-8222-222222222222",
                    "api_base_url": "https://trackai.example/api/gitai",
                    "credential_key_id": key_id,
                })
            })
            .collect();
        let policy = serde_json::json!({"version": 1, "repositories": repositories});
        std::fs::write(policy_path(&home), serde_json::to_vec(&policy).unwrap()).unwrap();
        std::fs::write(state_path(&home), b"{}").unwrap();
        (temp, home)
    }

    /// Fake registrar for engineering-evidence unit tests only.
    struct FakeRegistrar {
        remove: StepResult,
        absent: bool,
        calls: RefCell<u32>,
    }

    impl FakeRegistrar {
        fn success() -> Self {
            Self {
                remove: StepResult::Ok,
                absent: true,
                calls: RefCell::new(0),
            }
        }
    }

    impl LoginStartDeregistrar for FakeRegistrar {
        fn deregister(&self, home: &Path) -> StepResult {
            *self.calls.borrow_mut() += 1;
            if login_start_path(home).is_none() {
                return StepResult::Missing;
            }
            self.remove
        }

        fn registration_absent(&self, _home: &Path) -> bool {
            self.absent
        }
    }

    /// Store that always fails deletion, to prove recovery metadata survives.
    struct LockedStore;

    impl MachineCredentialStore for LockedStore {
        fn store(
            &self,
            _credential: crate::auth::machine_credentials::MachineCredential,
        ) -> Result<(), MachineCredentialError> {
            Err(MachineCredentialError {
                code: MachineCredentialStoreCode::Locked,
            })
        }

        fn load(
            &self,
            _key_id: &str,
        ) -> Result<crate::auth::machine_credentials::MachineCredential, MachineCredentialError>
        {
            Err(MachineCredentialError {
                code: MachineCredentialStoreCode::Locked,
            })
        }

        fn delete(&self, _key_id: &str) -> Result<(), MachineCredentialError> {
            Err(MachineCredentialError {
                code: MachineCredentialStoreCode::Locked,
            })
        }

        fn status(&self) -> MachineCredentialStoreCode {
            MachineCredentialStoreCode::Locked
        }
    }

    #[test]
    fn dry_run_mutates_nothing_and_lists_only_task9_owned_state() {
        let (_temp, home) = home_with_policy(&["ABCDEFGHIJKLMNOP"]);
        let plan = plan_cleanup(&home);
        assert_eq!(plan.credential_key_ids, vec!["ABCDEFGHIJKLMNOP"]);
        assert_eq!(
            plan.remove_files,
            vec![policy_path(&home), state_path(&home)]
        );
        assert_eq!(
            plan.remove_dirs,
            vec![crate::fleet::managed_update::staging_dir_for_home(&home)]
        );
        assert!(plan.deregister_login_start);
        // Planning is read-only: everything is still on disk.
        assert!(policy_path(&home).exists());
        assert!(state_path(&home).exists());
    }

    #[test]
    fn apply_deletes_only_task9_state_and_preserves_queue_notes_and_user_data() {
        let (_temp, home) = home_with_policy(&["ABCDEFGHIJKLMNOP", "ABCDEFGHIJKLMNOP"]);
        // Evidence queue, notes DB, user credential stand-ins and the binary
        // must survive endpoint cleanup.
        let preserved = [
            home.join(".git-ai/internal/metrics-db"),
            home.join(".git-ai/internal/notes-db"),
            home.join(".git-ai/config.json"),
            home.join(".git-ai/bin/git-ai"),
            home.join("repo/.git/refs/notes/ai"),
        ];
        for path in &preserved {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"precious").unwrap();
        }
        // Login-start registration present on this platform is removed;
        // elsewhere the step reports a successful idempotent outcome.
        if let Some(path) = login_start_path(&home) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"registration").unwrap();
        }

        let store = MemoryMachineCredentialStore::default();
        let credential = "trk_v1.ABCDEFGHIJKLMNOP.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store
            .store(
                crate::auth::machine_credentials::MachineCredential::parse(credential.to_string())
                    .unwrap(),
            )
            .unwrap();

        let plan = plan_cleanup(&home);
        let registrar = FakeRegistrar::success();
        let steps = apply_cleanup(&plan, &home, &store, &registrar);
        assert!(
            steps
                .iter()
                .any(|step| step.action == "delete-credential" && step.result == StepResult::Ok)
        );
        assert!(
            steps
                .iter()
                .any(|step| step.action == "deregister-login-start"
                    && matches!(step.result, StepResult::Ok | StepResult::Missing))
        );
        assert_eq!(*registrar.calls.borrow(), 1);
        assert_eq!(cleanup_apply_exit_code(&steps), 0);
        assert!(!policy_path(&home).exists());
        assert!(!state_path(&home).exists());
        for path in &preserved {
            assert!(path.exists(), "cleanup must preserve {}", path.display());
        }
        assert_eq!(
            store.load("ABCDEFGHIJKLMNOP").err().unwrap().code,
            MachineCredentialStoreCode::Missing
        );

        // Idempotent second apply: missing items succeed.
        let again = apply_cleanup(&plan_cleanup(&home), &home, &store, &registrar);
        assert!(!again.is_empty());
        assert!(
            again
                .iter()
                .all(|step| matches!(step.result, StepResult::Ok | StepResult::Missing))
        );
        assert_eq!(cleanup_apply_exit_code(&again), 0);
    }

    #[test]
    fn credential_delete_failure_retains_policy_and_fails_the_command() {
        let (_temp, home) = home_with_policy(&["ABCDEFGHIJKLMNOP"]);
        let plan = plan_cleanup(&home);
        let registrar = FakeRegistrar::success();
        let steps = apply_cleanup(&plan, &home, &LockedStore, &registrar);
        let delete = steps
            .iter()
            .find(|step| step.action == "delete-credential")
            .unwrap();
        assert_eq!(delete.result, StepResult::Failed("locked"));
        // Recovery metadata survives: the policy file holding the key ID is
        // retained and marked deferred, while unrelated state still cleans up.
        assert!(policy_path(&home).exists());
        assert!(!state_path(&home).exists());
        let policy_step = steps
            .iter()
            .find(|step| {
                step.action == "remove-file" && step.target == policy_path(&home).to_string_lossy()
            })
            .unwrap();
        assert_eq!(
            policy_step.result,
            StepResult::Deferred("deferred_credential_cleanup")
        );
        assert_eq!(cleanup_apply_exit_code(&steps), 1);

        // Retry after the store recovers completes and exits zero.
        let store = MemoryMachineCredentialStore::default();
        let retry = apply_cleanup(&plan_cleanup(&home), &home, &store, &registrar);
        assert_eq!(cleanup_apply_exit_code(&retry), 0);
        assert!(!policy_path(&home).exists());
    }

    #[test]
    fn deregistration_failure_is_reported_and_fails_the_command() {
        let (_temp, home) = home_with_policy(&["ABCDEFGHIJKLMNOP"]);
        let plan = plan_cleanup(&home);
        let store = MemoryMachineCredentialStore::default();
        // Files removed but the platform registration remains: must fail.
        let registrar = FakeRegistrar {
            remove: StepResult::Ok,
            absent: false,
            calls: RefCell::new(0),
        };
        let steps = apply_cleanup(&plan, &home, &store, &registrar);
        let deregister = steps
            .iter()
            .find(|step| step.action == "deregister-login-start")
            .unwrap();
        assert_eq!(
            deregister.result,
            StepResult::Failed("deregistration_failed")
        );
        assert_eq!(cleanup_apply_exit_code(&steps), 1);

        // Registrar errors propagate the same way.
        let failing = FakeRegistrar {
            remove: StepResult::Failed("remove_failed"),
            absent: false,
            calls: RefCell::new(0),
        };
        let steps = apply_cleanup(&plan_cleanup(&home), &home, &store, &failing);
        assert!(
            steps
                .iter()
                .any(|step| step.action == "deregister-login-start"
                    && step.result == StepResult::Failed("deregistration_failed"))
        );
        assert_eq!(cleanup_apply_exit_code(&steps), 1);
    }

    #[test]
    fn cleanup_apply_exit_code_maps_results() {
        let step = |result| CleanupStep {
            action: "remove-file",
            target: "target".to_string(),
            result,
        };
        assert_eq!(
            cleanup_apply_exit_code(&[step(StepResult::Ok), step(StepResult::Missing)]),
            0
        );
        assert_eq!(cleanup_apply_exit_code(&[step(StepResult::Failed("x"))]), 1);
        assert_eq!(
            cleanup_apply_exit_code(&[step(StepResult::Deferred("x"))]),
            1
        );
    }

    #[test]
    fn apply_removes_staged_updates() {
        let (_temp, home) = home_with_policy(&[]);
        let staging = crate::fleet::managed_update::staging_dir_for_home(&home);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("tag"), b"v9.8.7").unwrap();
        let plan = plan_cleanup(&home);
        let store = MemoryMachineCredentialStore::default();
        let registrar = FakeRegistrar::success();
        let steps = apply_cleanup(&plan, &home, &store, &registrar);
        assert!(
            steps
                .iter()
                .any(|step| step.action == "remove-dir" && step.result == StepResult::Ok)
        );
        assert!(!staging.exists());
        assert_eq!(cleanup_apply_exit_code(&steps), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_registrar_verifies_real_absence() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let registrar = PlatformLoginStart;
        // Nothing registered under an empty home: absent.
        assert!(registrar.registration_absent(&home));
        // A leftover plist file counts as present until deregistered.
        let plist = login_start_path(&home).unwrap();
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, b"stale").unwrap();
        assert!(!registrar.registration_absent(&home));
        assert_eq!(registrar.deregister(&home), StepResult::Ok);
        assert!(!plist.exists());
        assert!(registrar.registration_absent(&home));
    }

    #[test]
    fn missing_items_are_successful_idempotent_outcomes() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("empty-home");
        std::fs::create_dir_all(&home).unwrap();
        let plan = plan_cleanup(&home);
        assert!(plan.credential_key_ids.is_empty());
        let store = MemoryMachineCredentialStore::default();
        let registrar = FakeRegistrar::success();
        let steps = apply_cleanup(&plan, &home, &store, &registrar);
        assert!(!steps.is_empty());
        assert!(
            steps
                .iter()
                .all(|step| matches!(step.result, StepResult::Ok | StepResult::Missing))
        );
        assert_eq!(cleanup_apply_exit_code(&steps), 0);
    }

    #[test]
    fn http_and_auth_failures_never_trigger_cleanup() {
        // 401/403, network-level 503 and empty 204 responses all classify as
        // unavailable/no-change, never as a candidate, so the managed refresh
        // path that consumes this classification cannot reach cleanup. Cleanup
        // is reachable only through the explicit `fleet cleanup` command.
        for status in [401u16, 403, 500, 503] {
            assert_eq!(
                classify_configuration_response(status, b""),
                ConfigurationResponse::Unavailable,
                "status {status} must never trigger cleanup"
            );
        }
        assert_eq!(
            classify_configuration_response(204, b"ignored"),
            ConfigurationResponse::NoChange
        );
    }

    #[test]
    fn cleanup_reports_carry_no_secrets() {
        let (_temp, home) = home_with_policy(&["ABCDEFGHIJKLMNOP"]);
        let plan = plan_cleanup(&home);
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("trk_v1"));
        assert!(!rendered.contains("aaaaaaa"));
        let store = MemoryMachineCredentialStore::default();
        let registrar = FakeRegistrar::success();
        for step in apply_cleanup(&plan, &home, &store, &registrar) {
            let rendered = format!("{step:?} {}", step.result.as_str());
            assert!(!rendered.contains("trk_v1"));
            assert!(!rendered.contains("aaaaaaa"));
        }
    }

    /// Scripted runner for verification strictness tests.
    struct ScriptedRunner {
        result: Result<CommandResult, &'static str>,
    }

    impl CommandRunner for ScriptedRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<CommandResult, &'static str> {
            self.result.clone()
        }
    }

    fn runner(result: Result<CommandResult, &'static str>) -> ScriptedRunner {
        ScriptedRunner { result }
    }

    fn failed_output(output: &str) -> Result<CommandResult, &'static str> {
        Ok(CommandResult {
            success: false,
            output: output.to_string(),
        })
    }

    #[test]
    fn absence_requires_recognized_not_found_not_tool_failure() {
        // Present registrations are never absent.
        let present = Ok(CommandResult {
            success: true,
            output: String::new(),
        });
        assert!(!macos_registration_absent(&runner(present.clone()), "501"));
        assert!(!windows_registration_absent(&runner(present)));

        // Unavailable tools prove nothing.
        let unavailable: Result<CommandResult, &'static str> = Err("command_unavailable");
        assert!(!macos_registration_absent(&runner(unavailable), "501"));
        assert!(!windows_registration_absent(&runner(Err(
            "command_unavailable"
        ))));

        // Unexpected nonzero output (access denial, usage errors) is not
        // absence either.
        assert!(!macos_registration_absent(
            &runner(failed_output("launchctl: Access denied")),
            "501"
        ));
        assert!(!windows_registration_absent(&runner(failed_output(
            "ERROR: Access is denied."
        ))));

        // Only recognized not-found results prove absence.
        assert!(macos_registration_absent(
            &runner(failed_output(
                "Could not find service \"com.usegitai.bg\" in domain for gui/501"
            )),
            "501"
        ));
        assert!(windows_registration_absent(&runner(failed_output(
            "ERROR: The system cannot find the file specified."
        ))));

        // An unresolvable user proves nothing on macOS.
        assert!(!macos_registration_absent(
            &runner(failed_output("Could not find service \"com.usegitai.bg\"")),
            ""
        ));
    }
}
