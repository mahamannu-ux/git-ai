use crate::auth::machine_credentials::{
    MachineCredential, MachineCredentialStore, MachineCredentialStoreCode,
    default_machine_credential_store,
};
use crate::fleet::atomic_write_json;
use crate::metrics::delivery::{DeliveryPolicyCache, TRACKAI_DELIVERY_POLICY_FILE};
use serde_json::Value;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MAX_BOOTSTRAP_BYTES: usize = 256 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 1024;

pub fn handle_fleet(args: &[String]) {
    let result = match args {
        [scope, action] if scope == "bootstrap" && action == "install" => {
            if std::io::stdin().is_terminal() {
                Err("stdin_required")
            } else {
                default_policy_path()
                    .ok_or("home_unavailable")
                    .and_then(|path| install_bootstrap(std::io::stdin().lock(), &path))
                    .map(|count| println!("fleet_bootstrap_installed repositories={count}"))
            }
        }
        [scope, action] if scope == "credential" && action == "install" => {
            if std::io::stdin().is_terminal() {
                Err("stdin_required")
            } else {
                install_credential(
                    std::io::stdin().lock(),
                    default_machine_credential_store().as_ref(),
                )
                .map(|key_id| println!("fleet_credential_installed key_id={key_id}"))
            }
        }
        [scope, action] if scope == "credential" && action == "status" => {
            let code = default_machine_credential_store().status();
            println!("fleet_credential_store status={}", status_code(code));
            Ok(())
        }
        [scope, action, flag, key_id]
            if scope == "credential" && action == "delete" && flag == "--key-id" =>
        {
            default_machine_credential_store()
                .delete(key_id)
                .map_err(|error| status_code(error.code))
                .map(|()| println!("fleet_credential_deleted key_id={key_id}"))
        }
        [scope, flag] if scope == "cleanup" && flag == "--dry-run" => dirs::home_dir()
            .ok_or("home_unavailable")
            .map(|home| print_cleanup_plan(&crate::fleet::cleanup::plan_cleanup(&home))),
        [scope, flag] if scope == "cleanup" && flag == "--apply" => {
            dirs::home_dir().ok_or("home_unavailable").map(|home| {
                let plan = crate::fleet::cleanup::plan_cleanup(&home);
                let steps = crate::fleet::cleanup::apply_cleanup(
                    &plan,
                    &home,
                    default_machine_credential_store().as_ref(),
                    &crate::fleet::cleanup::PlatformLoginStart,
                );
                print_cleanup_steps(&steps);
                if crate::fleet::cleanup::cleanup_apply_exit_code(&steps) != 0 {
                    eprintln!("fleet_error code=cleanup_failed");
                    std::process::exit(1);
                }
            })
        }
        _ => Err("usage"),
    };
    if let Err(code) = result {
        eprintln!("fleet_error code={code}");
        std::process::exit(1);
    }
}

pub fn install_bootstrap(reader: impl Read, path: &Path) -> Result<usize, &'static str> {
    let raw = read_bounded(reader, MAX_BOOTSTRAP_BYTES)?;
    let raw_string = std::str::from_utf8(&raw).map_err(|_| "invalid_bootstrap")?;
    let policy = DeliveryPolicyCache::from_json(raw_string).map_err(|_| "invalid_bootstrap")?;
    let value: Value = serde_json::from_slice(&raw).map_err(|_| "invalid_bootstrap")?;
    let repositories = value
        .get("repositories")
        .and_then(Value::as_array)
        .ok_or("invalid_bootstrap")?;
    if repositories.iter().any(|entry| {
        entry
            .get("api_base_url")
            .and_then(Value::as_str)
            .is_none_or(|raw| !secure_api_base(raw))
    }) {
        return Err("insecure_transport");
    }
    if policy.repository_ids().len() != repositories.len() {
        return Err("invalid_bootstrap");
    }
    atomic_write_json(path, &value).map_err(|_| "write_failed")?;
    Ok(policy.repository_ids().len())
}

fn secure_api_base(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    if url.scheme() == "https" {
        return true;
    }
    cfg!(debug_assertions)
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

pub fn install_credential(
    reader: impl Read,
    store: &dyn MachineCredentialStore,
) -> Result<String, &'static str> {
    let raw = read_bounded(reader, MAX_CREDENTIAL_BYTES)?;
    let mut value = match String::from_utf8(raw) {
        Ok(value) => value,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err("invalid_credential");
        }
    };
    while matches!(value.as_bytes().last(), Some(b'\r' | b'\n')) {
        value.pop();
    }
    let credential = MachineCredential::parse(value).map_err(|_| "invalid_credential")?;
    let key_id = credential.key_id().to_string();
    store
        .store(credential)
        .map_err(|error| status_code(error.code))?;
    Ok(key_id)
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut raw = Vec::new();
    reader
        .by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "stdin_unavailable")?;
    if raw.is_empty() || raw.len() > maximum {
        return Err("input_size");
    }
    Ok(raw)
}

fn default_policy_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".git-ai").join(TRACKAI_DELIVERY_POLICY_FILE))
}

/// Dry-run prints only bounded safe metadata: planned actions, paths and
/// credential key IDs. It performs no mutation.
fn print_cleanup_plan(plan: &crate::fleet::cleanup::CleanupPlan) {
    for key_id in &plan.credential_key_ids {
        println!("fleet_cleanup_plan action=delete-credential target=key_id={key_id}");
    }
    for path in &plan.remove_files {
        println!(
            "fleet_cleanup_plan action=remove-file target={}",
            path.to_string_lossy()
        );
    }
    for dir in &plan.remove_dirs {
        println!(
            "fleet_cleanup_plan action=remove-dir target={}",
            dir.to_string_lossy()
        );
    }
    if plan.deregister_login_start {
        println!(
            "fleet_cleanup_plan action=deregister-login-start target=login-start-registration"
        );
    }
}

/// Apply reports safe per-step results without secrets.
fn print_cleanup_steps(steps: &[crate::fleet::cleanup::CleanupStep]) {
    for step in steps {
        println!(
            "fleet_cleanup_step action={} target={} result={}",
            step.action,
            step.target,
            step.result.as_str()
        );
    }
}

fn status_code(code: MachineCredentialStoreCode) -> &'static str {
    match code {
        MachineCredentialStoreCode::Available => "available",
        MachineCredentialStoreCode::Missing => "missing",
        MachineCredentialStoreCode::Locked => "locked",
        MachineCredentialStoreCode::Unsupported => "unsupported",
        MachineCredentialStoreCode::Corrupt => "corrupt",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::machine_credentials::MemoryMachineCredentialStore;

    #[test]
    fn credential_install_printable_result_never_contains_secret() {
        let store = MemoryMachineCredentialStore::default();
        let credential = "trk_v1.ABCDEFGHIJKLMNOP.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key_id = install_credential(credential.as_bytes(), &store).unwrap();
        assert_eq!(key_id, "ABCDEFGHIJKLMNOP");
        assert!(!key_id.contains("aaaaaaaa"));
        assert_eq!(
            install_credential(&vec![b'a'; MAX_CREDENTIAL_BYTES + 1][..], &store),
            Err("input_size")
        );
    }

    #[test]
    fn bootstrap_install_is_closed_and_atomic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trackai-delivery-policy.json");
        let valid = br#"{"version":1,"repositories":[{"repository_url":"https://github.com/example/repo","repository_id":"11111111-1111-4111-8111-111111111111","tenant_id":"22222222-2222-4222-8222-222222222222","api_base_url":"https://trackai.example/api/gitai","credential_key_id":"ABCDEFGHIJKLMNOP"}]}"#;
        assert_eq!(install_bootstrap(&valid[..], &path), Ok(1));
        let written = std::fs::read_to_string(path).unwrap();
        assert!(!written.contains("github.com/example/repo\n"));
        let invalid = br#"{"version":1,"unknown":true,"repositories":[]}"#;
        assert_eq!(
            install_bootstrap(&invalid[..], &temp.path().join("bad.json")),
            Err("invalid_bootstrap")
        );
        let insecure = std::str::from_utf8(valid)
            .unwrap()
            .replace("https://trackai.example", "http://trackai.example");
        assert_eq!(
            install_bootstrap(insecure.as_bytes(), &temp.path().join("insecure.json")),
            Err("insecure_transport")
        );
        let missing_repository_id = std::str::from_utf8(valid).unwrap().replace(
            "\"repository_id\":\"11111111-1111-4111-8111-111111111111\",",
            "",
        );
        assert_eq!(
            install_bootstrap(
                missing_repository_id.as_bytes(),
                &temp.path().join("missing-id.json")
            ),
            Err("invalid_bootstrap")
        );
    }
}
