//! One polling pass from Numbat's local record stream into the durable queue.

use crate::error::GitAiError;
use crate::metrics::delivery::MetricDeliveryHealthBinding;
use crate::security::activation::SecurityLeaseContext;
use crate::security::delivery_queue::{SecurityRecordQueue, TailHealthObservation};
use crate::security::records::{PermissionJoinTracker, project_numbat_record};
use crate::security::tail::{
    DEFAULT_MAX_ENTRIES_PER_POLL, TailEntryKind, delete_expired_rotations_except, read_available,
    rotate_if_due,
};
use chrono::{DateTime, Local, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub const NUMBAT_RECORDS_PATH_ENV: &str = "GIT_AI_NUMBAT_RECORDS_PATH";

pub fn configured_records_path() -> Result<PathBuf, GitAiError> {
    if let Some(path) = std::env::var_os(NUMBAT_RECORDS_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }
    dirs::home_dir()
        .map(|home| home.join(".numbat/records.ndjson"))
        .ok_or_else(|| {
            GitAiError::Generic("home directory unavailable for Numbat records".to_string())
        })
}

pub fn poll_security_records(
    path: &Path,
    queue: &mut SecurityRecordQueue,
    leases: &dyn SecurityLeaseContext,
    binding: Option<&MetricDeliveryHealthBinding>,
    repositories: &HashMap<String, String>,
    joins: &mut PermissionJoinTracker,
    now: u64,
) -> Result<(), GitAiError> {
    if !path.try_exists()? {
        return Ok(());
    }
    let checkpoint = queue.checkpoint()?;
    let read = read_available(path, &checkpoint, DEFAULT_MAX_ENTRIES_PER_POLL)?;
    let current_lease = leases.current();
    let mut projected = Vec::new();
    let mut counters = BTreeMap::<String, u64>::new();
    let mut last_valid_record_at: Option<i64> = None;
    let mut rejected_record = false;
    for entry in &read.entries {
        match &entry.kind {
            TailEntryKind::Oversized => {
                increment(&mut counters, "oversized_line");
                rejected_record = true;
            }
            TailEntryKind::Record(raw) => {
                let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(raw) else {
                    increment(&mut counters, "parse_error");
                    rejected_record = true;
                    continue;
                };
                let timestamp = parsed
                    .get("timestamp")
                    .or_else(|| parsed.get("detected_at"))
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<DateTime<Utc>>().ok());
                if parsed.get("schema_version").and_then(Value::as_str) == Some("0.5.0")
                    && matches!(
                        parsed.get("record_type").and_then(Value::as_str),
                        Some("finding" | "enforcement" | "indicator" | "scan_summary" | "event")
                    )
                    && parsed
                        .get("source_agent")
                        .and_then(Value::as_str)
                        .is_some_and(|agent| !agent.is_empty())
                    && let Some(timestamp) = timestamp
                {
                    last_valid_record_at = Some(
                        last_valid_record_at.map_or(timestamp.timestamp(), |previous| {
                            previous.max(timestamp.timestamp())
                        }),
                    );
                } else {
                    rejected_record = true;
                }
                match parsed
                    .get("schema_version")
                    .and_then(serde_json::Value::as_str)
                {
                    Some("0.5.0") => {}
                    Some(version) => {
                        increment(&mut counters, &format!("schema_version:{version}"));
                        continue;
                    }
                    None => {
                        increment(&mut counters, "schema_version:missing");
                        continue;
                    }
                }
                if parsed.get("record_type")
                    == Some(&serde_json::Value::String("diagnostic".to_string()))
                {
                    increment(&mut counters, "diagnostic");
                    continue;
                }
                let security_kind = match parsed.get("record_type").and_then(Value::as_str) {
                    Some("finding" | "enforcement" | "indicator" | "scan_summary") => true,
                    Some("event") => matches!(
                        parsed.get("event_type").and_then(Value::as_str),
                        Some("permission.requested" | "permission.approved" | "permission.denied")
                    ),
                    _ => false,
                };
                if !security_kind {
                    increment(&mut counters, "not_security_v2");
                    continue;
                }
                let Some(current_lease) = current_lease.as_ref() else {
                    increment(&mut counters, "lease_absent");
                    continue;
                };
                let Some(binding) = binding else {
                    increment(&mut counters, "delivery_binding_absent");
                    continue;
                };
                let lease = if parsed.get("record_type").and_then(Value::as_str) == Some("finding")
                {
                    parsed
                        .get("detected_at")
                        .and_then(Value::as_str)
                        .and_then(|at| at.parse::<DateTime<Utc>>().ok())
                        .and_then(|at| leases.lease_at(at))
                } else {
                    Some(current_lease.clone())
                };
                let Some(lease) = lease else {
                    increment(&mut counters, "lease_at_detection_absent");
                    continue;
                };
                if let Some(record) = project_numbat_record(raw, &lease, repositories, joins, false)
                {
                    projected.push((record, binding));
                } else {
                    increment(&mut counters, "not_projected");
                }
            }
        }
    }
    let local_date = Local::now().date_naive();
    let refs = projected
        .iter()
        .map(|(record, binding)| (record, *binding))
        .collect::<Vec<_>>();
    queue.commit_poll(
        &read,
        local_date,
        &refs,
        &counters,
        now,
        TailHealthObservation {
            valid_at: last_valid_record_at,
            rejected: rejected_record,
        },
    )?;
    let saved = queue.checkpoint()?;
    let mut rotation_checkpoint = saved.clone();
    // The transaction records today's poll date. Rotation must compare
    // against the date that was durable before this poll, otherwise updating
    // the checkpoint would erase the midnight transition before the rename.
    rotation_checkpoint.last_rotation_local_date = checkpoint.last_rotation_local_date;
    let _ = rotate_if_due(
        path,
        &rotation_checkpoint,
        local_date,
        Utc::now().date_naive(),
    )?;
    let _ = delete_expired_rotations_except(
        path,
        Utc::now().date_naive(),
        queue.checkpoint()?.identity,
    )?;
    Ok(())
}

fn increment(counters: &mut BTreeMap<String, u64>, name: &str) {
    *counters.entry(name.to_string()).or_default() += 1;
}

pub fn poll_configured_security_records(
    leases: &dyn SecurityLeaseContext,
    binding: Option<&MetricDeliveryHealthBinding>,
    repositories: &HashMap<String, String>,
    joins: &mut PermissionJoinTracker,
    now: u64,
) -> Result<(), GitAiError> {
    let config = crate::daemon::DaemonConfig::from_env_or_default_paths()?;
    std::fs::create_dir_all(&config.internal_dir)?;
    let mut queue =
        SecurityRecordQueue::open_at_path(&config.internal_dir.join("security-findings.db"))?;
    if queue.legacy_rows_dropped() > 0 {
        tracing::info!(
            count = queue.legacy_rows_dropped(),
            "retired Task6 security rows dropped"
        );
    }
    poll_security_records(
        &configured_records_path()?,
        &mut queue,
        leases,
        binding,
        repositories,
        joins,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::activation::{LeaseSnapshot, UnavailableLeaseContext};
    use crate::security::records::SecurityDataSettings;
    use chrono::{TimeZone, Utc};

    struct Lease;
    impl SecurityLeaseContext for Lease {
        fn current(&self) -> Option<LeaseSnapshot> {
            Some(LeaseSnapshot {
                lease_id: "lease".into(),
                bundle_digest: "a".repeat(64),
                issued_at: Utc.timestamp_opt(0, 0).unwrap(),
                expires_at: Utc.timestamp_opt(4_000_000_000, 0).unwrap(),
                data_settings: SecurityDataSettings::ALL_OFF,
            })
        }
        fn lease_at(&self, at: DateTime<Utc>) -> Option<LeaseSnapshot> {
            self.current()
                .filter(|lease| lease.issued_at <= at && at < lease.expires_at)
        }
        fn issued(&self, _: &str) -> Option<LeaseSnapshot> {
            self.current()
        }
    }

    fn finding() -> String {
        serde_json::json!({
            "schema_version":"0.5.0","record_type":"finding","finding_id":"f1",
            "rule_id":"r","rule_version":"1","severity":"low","title":"safe",
            "source_agent":"claude-code","source_type":"hook","confidence":"high",
            "detected_at":"2026-10-17T10:00:00Z","tool_input":"never-store"
        })
        .to_string()
            + "\n"
    }

    #[test]
    fn absent_lease_drops_but_checkpoints() {
        let temp = tempfile::TempDir::new().unwrap();
        let records = temp.path().join("records.ndjson");
        std::fs::write(&records, finding()).unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        poll_security_records(
            &records,
            &mut queue,
            &UnavailableLeaseContext,
            None,
            &HashMap::new(),
            &mut PermissionJoinTracker::default(),
            10,
        )
        .unwrap();
        assert_eq!(
            queue.checkpoint().unwrap().offset,
            std::fs::metadata(records).unwrap().len()
        );
        assert!(queue.dequeue_pending(500, 10).unwrap().is_empty());
    }

    #[test]
    fn queued_json_contains_only_minimized_projection() {
        let temp = tempfile::TempDir::new().unwrap();
        let records = temp.path().join("records.ndjson");
        std::fs::write(&records, finding()).unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        let binding = MetricDeliveryHealthBinding {
            tenant_id: "tenant".into(),
            api_base_url: "https://trackai.example".into(),
            credential_key_id: "ABCDEFGHIJKLMNOP".into(),
        };
        poll_security_records(
            &records,
            &mut queue,
            &Lease,
            Some(&binding),
            &HashMap::new(),
            &mut PermissionJoinTracker::default(),
            10,
        )
        .unwrap();
        let rows = queue.dequeue_pending(500, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].projection_json.contains("tool_input"));
        assert_eq!(
            queue.health_evidence().unwrap().last_valid_record_at,
            Some(
                chrono::DateTime::parse_from_rfc3339("2026-10-17T10:00:00Z")
                    .unwrap()
                    .timestamp()
            )
        );
    }

    #[test]
    fn rejected_tail_line_is_committed_as_health_evidence() {
        let temp = tempfile::TempDir::new().unwrap();
        let records = temp.path().join("records.ndjson");
        std::fs::write(&records, b"{\"schema_version\":\"wrong\"}\n").unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        poll_security_records(
            &records,
            &mut queue,
            &UnavailableLeaseContext,
            None,
            &HashMap::new(),
            &mut PermissionJoinTracker::default(),
            100,
        )
        .unwrap();
        let evidence = queue.health_evidence().unwrap();
        assert_eq!(evidence.last_rejected_record_at, Some(100));
        assert_eq!(evidence.last_valid_record_at, None);
    }

    #[test]
    fn finding_uses_lease_current_at_detection_after_refresh() {
        struct LeaseHistory;
        impl LeaseHistory {
            fn lease(
                id: &str,
                issued_at: DateTime<Utc>,
                expires_at: DateTime<Utc>,
            ) -> LeaseSnapshot {
                LeaseSnapshot {
                    lease_id: id.into(),
                    bundle_digest: if id == "older" {
                        "a".repeat(64)
                    } else {
                        "b".repeat(64)
                    },
                    issued_at,
                    expires_at,
                    data_settings: SecurityDataSettings::ALL_OFF,
                }
            }

            fn history() -> [LeaseSnapshot; 2] {
                [
                    Self::lease(
                        "older",
                        Utc.with_ymd_and_hms(2026, 10, 17, 0, 0, 0).unwrap(),
                        Utc.with_ymd_and_hms(2026, 10, 17, 11, 0, 0).unwrap(),
                    ),
                    Self::lease(
                        "newer",
                        Utc.with_ymd_and_hms(2026, 10, 17, 11, 0, 0).unwrap(),
                        Utc.with_ymd_and_hms(2026, 10, 18, 0, 0, 0).unwrap(),
                    ),
                ]
            }
        }
        impl SecurityLeaseContext for LeaseHistory {
            fn current(&self) -> Option<LeaseSnapshot> {
                Self::history().into_iter().last()
            }

            fn lease_at(&self, at: DateTime<Utc>) -> Option<LeaseSnapshot> {
                Self::history()
                    .into_iter()
                    .find(|lease| lease.issued_at <= at && at < lease.expires_at)
            }

            fn issued(&self, lease_id: &str) -> Option<LeaseSnapshot> {
                Self::history()
                    .into_iter()
                    .find(|lease| lease.lease_id == lease_id)
            }
        }

        let temp = tempfile::TempDir::new().unwrap();
        let records = temp.path().join("records.ndjson");
        std::fs::write(&records, finding()).unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        let binding = MetricDeliveryHealthBinding {
            tenant_id: "tenant".into(),
            api_base_url: "https://trackai.example".into(),
            credential_key_id: "ABCDEFGHIJKLMNOP".into(),
        };

        poll_security_records(
            &records,
            &mut queue,
            &LeaseHistory,
            Some(&binding),
            &HashMap::new(),
            &mut PermissionJoinTracker::default(),
            10,
        )
        .unwrap();

        let rows = queue.dequeue_pending(500, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].lease_id, "older");
        let projection: Value = serde_json::from_str(&rows[0].projection_json).unwrap();
        assert_eq!(projection["lease_id"], "older");
        assert_eq!(projection["bundle_digest"], "a".repeat(64));
    }
}
