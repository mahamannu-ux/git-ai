//! Conservative Endpoint security posture snapshots.

use crate::error::GitAiError;
use crate::metrics::delivery::MetricDeliveryHealthBinding;
use crate::security::activation::{SecurityLeaseContext, configured_lease_context};
use crate::security::delivery_queue::{SecurityHealthEvidence, SecurityRecordQueue};
use crate::security::policy_apply::{MANAGED_AGENT_MAP, NUMBAT_ADMIN_BINARY};
use crate::security::records::project_security_status;
use crate::security::shipper::configured_records_path;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

const STATUS_INTERVAL_SECONDS: i64 = 3_600;
static LAST_STATUS_AT: Mutex<i64> = Mutex::new(0);

fn managed_agents() -> impl Iterator<Item = (&'static str, &'static str)> {
    MANAGED_AGENT_MAP.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        Some((fields.next()?, fields.next()?))
    })
}

fn hook_status(binary: &Path, agent: &str) -> Option<bool> {
    let output = Command::new(binary)
        .args(["hook", "status", "--agent", agent, "--managed"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let status = String::from_utf8(output.stdout).ok()?;
    match status.split_whitespace().nth(1) {
        Some("installed") => Some(true),
        Some("not-installed" | "drifted") => Some(false),
        _ => None,
    }
}

fn numbat_version(binary: &Path) -> String {
    Command::new(binary)
        .arg("version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().chars().take(64).collect())
        .filter(|value: &String| !value.is_empty())
        .unwrap_or_else(|| "unavailable".into())
}

fn last_record_at(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() == 0 {
        return None;
    }
    let written = DateTime::<Utc>::from(metadata.modified().ok()?);
    Some(written.to_rfc3339_opts(SecondsFormat::Secs, true))
}

pub fn build_security_status(
    now: DateTime<Utc>,
    binary: &Path,
    records: &Path,
    lease_id: &str,
    active_bundle_digest: Option<&str>,
    installed_at: Option<i64>,
    evidence: &SecurityHealthEvidence,
) -> Map<String, Value> {
    let statuses = managed_agents()
        .map(|(agent, source)| (source, hook_status(binary, agent)))
        .collect::<Vec<_>>();
    let wired = statuses
        .iter()
        .filter_map(|(source, status)| (*status == Some(true)).then_some(*source))
        .collect::<Vec<_>>();
    let hook_layer = if statuses.iter().any(|(_, status)| *status == Some(false)) {
        "failed"
    } else if statuses.iter().all(|(_, status)| *status == Some(true)) {
        "ok"
    } else {
        "unavailable"
    };
    let active_digest = active_bundle_digest
        .filter(|digest| digest.len() == 64)
        .map_or(Value::Null, |digest| json!(digest));
    let recent = |timestamp: i64| {
        timestamp >= now.timestamp().saturating_sub(86_400) && timestamp <= now.timestamp()
    };
    let file_modified_at = fs::metadata(records)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .map(|modified| DateTime::<Utc>::from(modified).timestamp());
    let local_record = if evidence
        .last_valid_record_at
        .is_some_and(|at| recent(at) && installed_at.is_some_and(|installed| at >= installed))
    {
        "ok"
    } else if evidence.last_rejected_record_at.is_some_and(|at| {
        recent(at)
            && installed_at.is_some_and(|installed| {
                at >= installed && file_modified_at.is_some_and(|modified| modified >= installed)
            })
    }) {
        "failed"
    } else {
        "unavailable"
    };
    let forwarder_ack = if evidence.last_refusal_at.is_some_and(|refused| {
        evidence.last_refusal_code.is_some()
            && evidence.last_acked_at.is_none_or(|acked| refused > acked)
    }) || evidence
        .oldest_numbat_queued_at
        .is_some_and(|queued| now.timestamp().saturating_sub(queued) > 86_400)
    {
        "failed"
    } else if evidence.last_acked_at.is_some_and(recent) {
        "ok"
    } else {
        "unavailable"
    };
    let fields = json!({
        "observed_at": now.to_rfc3339_opts(SecondsFormat::Millis, true),
        "numbat_version": numbat_version(binary),
        "wired_agents": wired,
        "active_bundle_digest": active_digest,
        "lease_id": lease_id,
        "last_record_at": last_record_at(records),
        "health": {
            "hook_status": hook_layer,
            // No agent-independent API proves an installed hook is effective.
            "agent_effective_view": "unavailable",
            "local_record": local_record,
            "forwarder_ack": forwarder_ack
        }
    });
    fields.as_object().cloned().expect("status fields object")
}

pub fn queue_configured_security_status(
    now: DateTime<Utc>,
    after_apply: bool,
    binding: Option<&MetricDeliveryHealthBinding>,
) -> Result<(), GitAiError> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let Some(lease) = configured_lease_context().lease_at(now) else {
        return Ok(());
    };
    let mut last = LAST_STATUS_AT
        .lock()
        .map_err(|_| GitAiError::Generic("security status lock poisoned".into()))?;
    if !after_apply && now.timestamp() < last.saturating_add(STATUS_INTERVAL_SECONDS) {
        return Ok(());
    }
    let config = crate::daemon::DaemonConfig::from_env_or_default_paths()?;
    fs::create_dir_all(&config.internal_dir)?;
    let queue =
        SecurityRecordQueue::open_at_path(&config.internal_dir.join("security-findings.db"))?;
    let active_digest = lease.bundle_digest.get(..12).and_then(|prefix| {
        fs::read_link(config.internal_dir.join("security/rules/current"))
            .ok()
            .and_then(|target| {
                target
                    .file_name()
                    .and_then(|name| name.to_str())
                    .filter(|name| name.ends_with(prefix))
                    .map(|_| lease.bundle_digest.as_str())
            })
    });
    let fields = build_security_status(
        now,
        Path::new(NUMBAT_ADMIN_BINARY),
        &configured_records_path()?,
        &lease.lease_id,
        active_digest,
        fs::read_to_string(config.internal_dir.join("security/hooks-installed-at"))
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok()),
        &queue.health_evidence()?,
    );
    let record = project_security_status(fields)
        .ok_or_else(|| GitAiError::Generic("security status projection failed".into()))?;
    queue.enqueue_generated(&record, binding, now.timestamp().max(0) as u64)?;
    *last = now.timestamp();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_map_is_unique_and_matches_bundle_sources() {
        let pairs = managed_agents().collect::<Vec<_>>();
        assert_eq!(
            pairs,
            vec![
                ("claude", "claude-code"),
                ("codex", "codex"),
                ("cursor", "cursor"),
                ("gemini", "gemini-cli"),
                ("copilot", "copilot"),
            ]
        );
    }

    #[test]
    fn unknown_layers_are_not_reported_healthy() {
        let temp = tempfile::tempdir().unwrap();
        let fields = build_security_status(
            Utc::now(),
            &temp.path().join("missing-numbat"),
            &temp.path().join("missing-records"),
            "lease",
            Some(&"a".repeat(64)),
            None,
            &SecurityHealthEvidence::default(),
        );
        let health = &fields["health"];
        assert_eq!(health["hook_status"], "unavailable");
        assert_eq!(health["agent_effective_view"], "unavailable");
        assert_eq!(health["local_record"], "unavailable");
        assert_eq!(health["forwarder_ack"], "unavailable");
        assert!(project_security_status(fields).is_some());

        let placeholder = build_security_status(
            Utc::now(),
            &temp.path().join("missing-numbat"),
            &temp.path().join("missing-records"),
            "lease",
            None,
            None,
            &SecurityHealthEvidence::default(),
        );
        assert!(placeholder["active_bundle_digest"].is_null());
    }

    #[test]
    fn recent_tail_and_remote_evidence_distinguish_ok_failed_and_idle() {
        let temp = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let timestamp = now.timestamp();
        let records = temp.path().join("records.ndjson");
        fs::write(&records, b"rejected line\n").unwrap();
        let status = |evidence: &SecurityHealthEvidence| {
            build_security_status(
                now,
                &temp.path().join("missing-numbat"),
                &records,
                "lease",
                None,
                Some(timestamp - 60),
                evidence,
            )
        };
        let green = status(&SecurityHealthEvidence {
            last_valid_record_at: Some(timestamp - 10),
            last_acked_at: Some(timestamp),
            ..Default::default()
        });
        assert_eq!(green["health"]["local_record"], "ok");
        assert_eq!(green["health"]["forwarder_ack"], "ok");

        let rejected = status(&SecurityHealthEvidence {
            last_rejected_record_at: Some(timestamp - 10),
            last_refusal_at: Some(timestamp),
            last_refusal_code: Some("SECURITY_V2_RECORD_CONFLICT".into()),
            ..Default::default()
        });
        assert_eq!(rejected["health"]["local_record"], "failed");
        assert_eq!(rejected["health"]["forwarder_ack"], "failed");

        let idle = status(&SecurityHealthEvidence {
            last_valid_record_at: Some(timestamp - 100),
            last_acked_at: Some(timestamp - 86_401),
            ..Default::default()
        });
        assert_eq!(idle["health"]["local_record"], "unavailable");
        assert_eq!(idle["health"]["forwarder_ack"], "unavailable");
        let stuck = status(&SecurityHealthEvidence {
            oldest_numbat_queued_at: Some(timestamp - 86_401),
            ..Default::default()
        });
        assert_eq!(stuck["health"]["forwarder_ack"], "failed");
    }
}
