//! Lease-gated, privacy-reduced Numbat agent inventory.

use crate::error::GitAiError;
use crate::metrics::delivery::MetricDeliveryHealthBinding;
use crate::security::activation::{SecurityLeaseContext, configured_lease_context};
use crate::security::delivery_queue::SecurityRecordQueue;
use crate::security::lease_state::LeaseStateStore;
use crate::security::policy_apply::{MANAGED_AGENT_MAP, NUMBAT_ADMIN_BINARY};
use crate::security::records::{ProjectedRecord, project_agent_inventory};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

const INTERVAL_SECONDS: i64 = 86_400;
const MAX_AGENTS: usize = 64;
static LAST_RUN_AT: Mutex<Option<LastRun>> = Mutex::new(None);

// Numbat JSON display name to its managed CLI name. The bundle source name
// comes from MANAGED_AGENT_MAP; unmapped Numbat rows retain their display name.
const MANAGED_NAMES: &[(&str, &str)] = &[
    ("Claude Code", "claude"),
    ("Codex", "codex"),
    ("Cursor", "cursor"),
    ("Gemini CLI", "gemini"),
    ("GitHub Copilot CLI", "copilot"),
];

#[derive(Clone, Serialize, Deserialize)]
struct LastRun {
    tenant_id: String,
    machine_id: String,
    at: i64,
}

fn map_row(row: &Value) -> Option<Value> {
    let name = row.get("agent")?.as_str()?;
    let managed_cli = MANAGED_NAMES
        .iter()
        .find(|(display, _)| *display == name)
        .map(|(_, cli)| *cli);
    let name = managed_cli
        .and_then(|cli| {
            MANAGED_AGENT_MAP.lines().find_map(|line| {
                let mut fields = line.split_whitespace();
                let mapped_cli = fields.next()?;
                let source = fields.next()?;
                (mapped_cli == cli).then_some(source)
            })
        })
        .unwrap_or(name);
    let config = match row.get("detected").and_then(Value::as_bool) {
        Some(true) => "present",
        Some(false) => "absent",
        None => "unavailable",
    };
    let artifacts = if row.get("at_rest_scan_incomplete").and_then(Value::as_bool) != Some(false) {
        "unavailable"
    } else {
        match row.get("at_rest").and_then(Value::as_str) {
            Some(value) if value.starts_with("found") => "present",
            Some("none found") => "absent",
            Some(value) if value.starts_with("n/a") => "not_supported",
            _ => "unavailable",
        }
    };
    let wired = match row.get("wired").and_then(Value::as_str) {
        Some("yes") => "yes",
        Some("no") => "no",
        Some("n/a") => "not_supported",
        _ => "unavailable",
    };
    Some(json!({
        "agent": name, "version": null, "config": config,
        "artifacts": artifacts, "wired": wired
    }))
}

fn map_rows(raw: &[u8]) -> Result<(Vec<Value>, usize), GitAiError> {
    let rows: Vec<Value> = serde_json::from_slice(raw)?;
    let mut signalled = Vec::new();
    let mut absent = Vec::new();
    for row in &rows {
        if row.get("present").and_then(Value::as_bool) == Some(true) {
            signalled.push(row);
        } else {
            absent.push(row);
        }
    }
    let dropped = rows.len().saturating_sub(MAX_AGENTS);
    let mapped = signalled
        .into_iter()
        .chain(absent)
        .take(MAX_AGENTS)
        .filter_map(map_row)
        .collect();
    Ok((mapped, dropped))
}

pub fn project_inventory(
    raw: &[u8],
    now: DateTime<Utc>,
) -> Result<(ProjectedRecord, usize), GitAiError> {
    let (agents, dropped) = map_rows(raw)?;
    if agents.is_empty() {
        return Err(GitAiError::Generic("Numbat inventory is empty".into()));
    }
    let fields = json!({
        "observed_at": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "agents": agents
    });
    let record = project_agent_inventory(fields.as_object().cloned().unwrap_or_else(Map::new))
        .ok_or_else(|| GitAiError::Generic("inventory projection failed".into()))?;
    Ok((record, dropped))
}

fn last_run(path: &Path, tenant_id: &str, machine_id: &str) -> i64 {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<LastRun>(&bytes).ok())
        .filter(|value| value.tenant_id == tenant_id && value.machine_id == machine_id)
        .map_or(0, |value| value.at)
}

fn write_last_run(path: &Path, value: &LastRun) -> Result<(), GitAiError> {
    let tmp = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn active_identity(
    context: &LeaseStateStore,
    now: DateTime<Utc>,
    binding: &MetricDeliveryHealthBinding,
) -> Option<(String, String)> {
    context.lease_at(now)?;
    let state = context.snapshot();
    let tenant_id = state.enrolled_tenant_id?;
    let machine_id = state.enrolled_machine_id?;
    (binding.tenant_id == tenant_id).then_some((tenant_id, machine_id))
}

pub fn queue_configured_inventory(
    now: DateTime<Utc>,
    binding: Option<&MetricDeliveryHealthBinding>,
) -> Result<(), GitAiError> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let context = configured_lease_context();
    let Some((tenant_id, machine_id)) = active_identity(context, now, binding) else {
        return Ok(());
    };
    let mut last = LAST_RUN_AT
        .lock()
        .map_err(|_| GitAiError::Generic("inventory lock poisoned".into()))?;
    let config = crate::daemon::DaemonConfig::from_env_or_default_paths()?;
    let security_dir = config.internal_dir.join("security");
    let stamp = security_dir.join("agent-inventory-last-run");
    let in_memory = last
        .as_ref()
        .filter(|value| value.tenant_id == tenant_id && value.machine_id == machine_id)
        .map_or(0, |value| value.at);
    if now.timestamp()
        < in_memory
            .max(last_run(&stamp, &tenant_id, &machine_id))
            .saturating_add(INTERVAL_SECONDS)
    {
        return Ok(());
    }
    let output = Command::new(NUMBAT_ADMIN_BINARY)
        .args(["agents", "--all", "--format", "json"])
        .output()?;
    if !output.status.success() {
        return Err(GitAiError::Generic("Numbat agent inventory failed".into()));
    }
    let observed = Utc::now();
    let (record, dropped) = project_inventory(&output.stdout, observed)?;
    if dropped > 0 {
        tracing::warn!(dropped, "Numbat inventory exceeded 64 rows");
    }
    if active_identity(context, observed, binding).as_ref()
        != Some(&(tenant_id.clone(), machine_id.clone()))
    {
        return Ok(());
    }
    fs::create_dir_all(&security_dir)?;
    let queue =
        SecurityRecordQueue::open_at_path(&config.internal_dir.join("security-findings.db"))?;
    queue.enqueue_generated(&record, binding, observed.timestamp().max(0) as u64)?;
    let completed = LastRun {
        tenant_id,
        machine_id,
        at: observed.timestamp(),
    };
    write_last_run(&stamp, &completed)?;
    *last = Some(completed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::lease_state::{AcceptedLease, DurableSecurityState, LeaseMode};
    use crate::security::records::SecurityDataSettings;

    #[test]
    fn captured_all_rows_are_private_and_conservative() {
        let raw = include_bytes!("../../tests/fixtures/numbat/agents-all.json");
        let (rows, dropped) = map_rows(raw).unwrap();
        assert_eq!(rows.len(), 27);
        assert_eq!(dropped, 0);
        for row in &rows {
            let encoded = row.to_string();
            assert!(!encoded.contains("setup_hint"));
            assert!(!encoded.contains("/repo") && !encoded.contains('~'));
            assert_eq!(row["version"], Value::Null);
        }
        for name in ["claude-code", "codex", "cursor", "gemini-cli", "copilot"] {
            assert!(rows.iter().any(|row| row["agent"] == name));
        }
        let find = |name| rows.iter().find(|row| row["agent"] == name).unwrap();
        assert_eq!(find("cursor")["artifacts"], "unavailable");
        assert_eq!(find("copilot")["artifacts"], "present");
        assert_eq!(find("OpenHands")["wired"], "not_supported");
        assert_eq!(find("Devin CLI")["config"], "absent");
    }

    #[test]
    fn incomplete_and_future_rows_fail_closed_and_cap_prefers_signals() {
        let mut incomplete = json!({"agent":"X", "detected":false,"at_rest":"found transcripts","at_rest_scan_incomplete":true,"wired":"error: unreadable"});
        assert_eq!(map_row(&incomplete).unwrap()["artifacts"], "unavailable");
        assert_eq!(map_row(&incomplete).unwrap()["wired"], "unavailable");
        incomplete["at_rest_scan_incomplete"] = json!(false);
        incomplete["at_rest"] = json!("new wording");
        assert_eq!(map_row(&incomplete).unwrap()["artifacts"], "unavailable");
        let mut rows = vec![
            json!({"agent":"absent","present":false,"detected":false,"at_rest":"none found","at_rest_scan_incomplete":false,"wired":"no"});
            65
        ];
        rows.push(json!({"agent":"important","present":true,"detected":true,"at_rest":"found transcripts","at_rest_scan_incomplete":false,"wired":"yes"}));
        let (selected, dropped) = map_rows(&serde_json::to_vec(&rows).unwrap()).unwrap();
        assert_eq!(selected.len(), 64);
        assert_eq!(dropped, 2);
        assert_eq!(selected[0]["agent"], "important");
    }

    #[test]
    fn inventory_requires_active_lease_and_matching_tenant() {
        let tmp = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let mut state = DurableSecurityState {
            enrolled_tenant_id: Some("tenant-a".into()),
            enrolled_machine_id: Some("machine-a".into()),
            accepted_leases: vec![AcceptedLease {
                lease_id: "lease-a".into(),
                bundle_digest: "a".repeat(64),
                issued_at: now - chrono::Duration::minutes(1),
                expires_at: now + chrono::Duration::hours(1),
                data_settings: SecurityDataSettings::ALL_OFF,
                mode: LeaseMode::Monitor,
                agents: vec![],
                day_one_scan: false,
                signed_bytes: vec![],
            }],
            ..Default::default()
        };
        let binding = MetricDeliveryHealthBinding {
            tenant_id: "tenant-a".into(),
            api_base_url: "https://trackai.example".into(),
            credential_key_id: "credential".into(),
        };
        let context = LeaseStateStore::from_state(tmp.path(), state.clone());
        assert_eq!(
            active_identity(&context, now, &binding),
            Some(("tenant-a".into(), "machine-a".into()))
        );
        assert!(
            active_identity(
                &context,
                now,
                &MetricDeliveryHealthBinding {
                    tenant_id: "other".into(),
                    ..binding.clone()
                }
            )
            .is_none()
        );
        state.accepted_leases[0].mode = LeaseMode::Off;
        assert!(
            active_identity(
                &LeaseStateStore::from_state(tmp.path(), state.clone()),
                now,
                &binding
            )
            .is_none()
        );
        state.accepted_leases[0].mode = LeaseMode::Monitor;
        state.accepted_leases[0].expires_at = now - chrono::Duration::seconds(1);
        assert!(
            active_identity(
                &LeaseStateStore::from_state(tmp.path(), state),
                now,
                &binding
            )
            .is_none()
        );
        assert!(
            active_identity(
                &LeaseStateStore::from_state(tmp.path(), DurableSecurityState::default()),
                now,
                &binding
            )
            .is_none()
        );
    }
}
