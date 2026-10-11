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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    Ok,
    Missing,
    Failed(&'static str),
}

impl StepResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Failed(code) => code,
        }
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
/// performs no mutation.
pub fn plan_cleanup(home: &Path) -> CleanupPlan {
    CleanupPlan {
        credential_key_ids: read_key_ids(&policy_path(home)),
        remove_files: vec![policy_path(home), state_path(home)],
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

/// Apply a plan built by [`plan_cleanup`]. Continues past missing items and
/// per-step failures so partial cleanup still reports every safe step result.
pub fn apply_cleanup(
    plan: &CleanupPlan,
    home: &Path,
    store: &dyn MachineCredentialStore,
) -> Vec<CleanupStep> {
    let mut steps = Vec::new();
    for key_id in &plan.credential_key_ids {
        let result = match store.delete(key_id) {
            Ok(()) => StepResult::Ok,
            Err(error) if error.code == MachineCredentialStoreCode::Missing => StepResult::Missing,
            Err(error) => StepResult::Failed(store_code(error.code)),
        };
        steps.push(CleanupStep {
            action: "delete-credential",
            target: format!("key_id={key_id}"),
            result,
        });
    }
    for path in &plan.remove_files {
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
    if plan.deregister_login_start {
        match login_start_path(home) {
            None => steps.push(CleanupStep {
                action: "deregister-login-start",
                target: "login-start-registration".to_string(),
                result: StepResult::Missing,
            }),
            Some(path) => {
                let result = match std::fs::remove_file(&path) {
                    Ok(()) => StepResult::Ok,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        StepResult::Missing
                    }
                    Err(_) => StepResult::Failed("remove_failed"),
                };
                steps.push(CleanupStep {
                    action: "deregister-login-start",
                    target: path.to_string_lossy().into_owned(),
                    result,
                });
            }
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::machine_credentials::MemoryMachineCredentialStore;
    use crate::fleet::{ConfigurationResponse, classify_configuration_response};

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
        std::fs::write(state_path(&home), b"{}".to_vec()).unwrap();
        (temp, home)
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
        let steps = apply_cleanup(&plan, &home, &store);
        assert!(
            steps
                .iter()
                .any(|step| step.action == "delete-credential" && step.result == StepResult::Ok)
        );
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
        let again = apply_cleanup(&plan_cleanup(&home), &home, &store);
        assert!(!again.is_empty());
        assert!(
            again
                .iter()
                .all(|step| matches!(step.result, StepResult::Ok | StepResult::Missing))
        );
    }

    #[test]
    fn missing_items_are_successful_idempotent_outcomes() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("empty-home");
        std::fs::create_dir_all(&home).unwrap();
        let plan = plan_cleanup(&home);
        assert!(plan.credential_key_ids.is_empty());
        let store = MemoryMachineCredentialStore::default();
        let steps = apply_cleanup(&plan, &home, &store);
        assert!(!steps.is_empty());
        assert!(
            steps
                .iter()
                .all(|step| matches!(step.result, StepResult::Ok | StepResult::Missing))
        );
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
        for step in apply_cleanup(&plan, &home, &store) {
            let rendered = format!("{step:?} {}", step.result.as_str());
            assert!(!rendered.contains("trk_v1"));
            assert!(!rendered.contains("aaaaaaa"));
        }
    }
}
