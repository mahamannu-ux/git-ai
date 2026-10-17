//! Privacy-minimized TrackAI security-v2 projections from Numbat 0.5.0.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};

const RECORD_DOMAIN: &str = "trackai.security-record/2";
const JOIN_WINDOW_SECONDS: i64 = 5 * 60;
const MAX_JOIN_OBSERVATIONS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityDataSettings {
    pub command_previews: bool,
    pub file_paths: bool,
    pub urls: bool,
    pub host_identity: bool,
    pub user_identity: bool,
}

impl SecurityDataSettings {
    pub const ALL_OFF: Self = Self {
        command_previews: false,
        file_paths: false,
        urls: false,
        host_identity: false,
        user_identity: false,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionLease {
    pub lease_id: String,
    pub bundle_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub data_settings: SecurityDataSettings,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedRecord {
    pub kind: String,
    pub record_id: String,
    pub lease_id: String,
    pub json: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JoinObservation {
    timestamp: DateTime<Utc>,
    session_id: Option<String>,
    tool_call_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct PermissionJoinTracker {
    recent: VecDeque<JoinObservation>,
}

impl PermissionJoinTracker {
    fn observe(&mut self, record: &Map<String, Value>) {
        let Some(timestamp) = string(record, "timestamp")
            .or_else(|| string(record, "detected_at"))
            .and_then(parse_time)
        else {
            return;
        };
        self.expire(timestamp);
        self.recent.push_back(JoinObservation {
            timestamp,
            session_id: string(record, "session_id").map(str::to_owned),
            tool_call_id: string(record, "tool_call_id").map(str::to_owned),
        });
        while self.recent.len() > MAX_JOIN_OBSERVATIONS {
            self.recent.pop_front();
        }
    }

    fn join_for(&mut self, record: &Map<String, Value>) -> Value {
        let Some(timestamp) = string(record, "timestamp").and_then(parse_time) else {
            return json!({"join": "unavailable"});
        };
        self.expire(timestamp);
        let session_id = string(record, "session_id");
        let tool_call_id = string(record, "tool_call_id");
        if let (Some(session_id), Some(tool_call_id)) = (session_id, tool_call_id)
            && self.recent.iter().any(|seen| {
                seen.session_id.as_deref() == Some(session_id)
                    && seen.tool_call_id.as_deref() == Some(tool_call_id)
                    && seen.timestamp <= timestamp
            })
        {
            return json!({"join": "exact", "tool_call_id": tool_call_id});
        }
        if let Some(session_id) = session_id
            && self.recent.iter().any(|seen| {
                seen.session_id.as_deref() == Some(session_id) && seen.timestamp <= timestamp
            })
        {
            return json!({"join": "same_session_window", "session_id": session_id});
        }
        json!({"join": "unavailable"})
    }

    fn expire(&mut self, now: DateTime<Utc>) {
        while self.recent.front().is_some_and(|seen| {
            now.signed_duration_since(seen.timestamp).num_seconds() > JOIN_WINDOW_SECONDS
        }) {
            self.recent.pop_front();
        }
    }
}

pub fn record_id(kind: &str, source_parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(RECORD_DOMAIN.as_bytes());
    digest.update([0]);
    digest.update(kind.as_bytes());
    for part in source_parts {
        digest.update([0]);
        digest.update(part.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

/// Reproduces `numbat@20a5a52:internal/model/event.go:543-564` without
/// resolving symlinks: trim, slash-normalize, POSIX-clean, SHA-256.
pub fn hash_project_path(path: &str) -> String {
    let normalized = clean_posix_path(path.trim().replace('\\', "/"));
    if normalized.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(normalized.as_bytes());
    format!("sha256:{digest:x}")
}

fn clean_posix_path(path: String) -> String {
    if path.is_empty() {
        return path;
    }
    let absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|part| *part != "..") => {
                parts.pop();
            }
            ".." if !absolute => parts.push(part),
            ".." => {}
            _ => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

pub fn repository_hashes<'a>(
    repositories: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> HashMap<String, String> {
    repositories
        .into_iter()
        .map(|(root, id)| (hash_project_path(root), id.to_string()))
        .collect()
}

pub fn project_numbat_record(
    raw: &[u8],
    lease: &ProjectionLease,
    repositories: &HashMap<String, String>,
    joins: &mut PermissionJoinTracker,
    found_at_rest: bool,
) -> Option<ProjectedRecord> {
    let source: Value = serde_json::from_slice(raw).ok()?;
    let source = source.as_object()?;
    if string(source, "schema_version") != Some("0.5.0") {
        return None;
    }
    let kind = match string(source, "record_type")? {
        "finding" => "finding",
        "enforcement" => "enforcement",
        "indicator" => "indicator",
        "scan_summary" => "scan_summary",
        "event"
            if matches!(
                string(source, "event_type"),
                Some("permission.requested" | "permission.approved" | "permission.denied")
            ) =>
        {
            "permission_event"
        }
        _ => return None,
    };
    let json = match kind {
        "finding" => project_finding(source, lease, repositories, found_at_rest)?,
        "enforcement" => project_enforcement(source)?,
        "indicator" => project_indicator(source, &lease.data_settings)?,
        "scan_summary" => project_scan_summary(source)?,
        "permission_event" => project_permission(source, joins)?,
        _ => return None,
    };
    if matches!(kind, "finding" | "enforcement") {
        joins.observe(source);
    }
    Some(ProjectedRecord {
        kind: kind.to_string(),
        record_id: string(json.as_object()?, "record_id")?.to_string(),
        lease_id: lease.lease_id.clone(),
        json,
    })
}

fn project_finding(
    source: &Map<String, Value>,
    lease: &ProjectionLease,
    repositories: &HashMap<String, String>,
    found_at_rest: bool,
) -> Option<Value> {
    let detected_at = string(source, "detected_at")?;
    let detected = parse_time(detected_at)?;
    if detected < lease.issued_at || detected >= lease.expires_at {
        return None;
    }
    let mut out = Map::new();
    insert(&mut out, "kind", json!("finding"));
    insert(
        &mut out,
        "record_id",
        json!(record_id("finding", &[string(source, "finding_id")?])),
    );
    copy_required(
        source,
        &mut out,
        &[
            "rule_id",
            "rule_version",
            "severity",
            "title",
            "source_agent",
            "source_type",
            "confidence",
            "detected_at",
        ],
    )?;
    copy_optional(
        source,
        &mut out,
        &[
            "model",
            "model_provider",
            "session_id",
            "parent_session_id",
            "sub_agent_id",
            "tags",
        ],
    );
    insert(&mut out, "numbat_schema_version", json!("0.5.0"));
    insert(&mut out, "bundle_digest", json!(lease.bundle_digest));
    insert(&mut out, "lease_id", json!(lease.lease_id));
    insert(&mut out, "found_at_rest", json!(found_at_rest));
    let repository = string(source, "project_path_hash")
        .and_then(|hash| repositories.get(hash))
        .map_or_else(
            || json!({"kind": "not_enrolled"}),
            |id| json!({"kind": "enrolled", "id": id}),
        );
    insert(&mut out, "repository", repository);
    for (enabled, key) in [
        (lease.data_settings.command_previews, "observed_command"),
        (lease.data_settings.file_paths, "observed_file_path"),
        (lease.data_settings.urls, "observed_url"),
    ] {
        if enabled {
            copy_optional(source, &mut out, &[key]);
        }
    }
    let endpoint = source.get("endpoint").and_then(Value::as_object);
    let mut projected_endpoint = Map::new();
    if lease.data_settings.host_identity
        && let Some(value) = endpoint.and_then(|map| map.get("hostname"))
    {
        insert(&mut projected_endpoint, "hostname", value.clone());
    }
    if lease.data_settings.user_identity
        && let Some(value) = endpoint.and_then(|map| map.get("username"))
    {
        insert(&mut projected_endpoint, "username", value.clone());
    }
    if !projected_endpoint.is_empty() {
        insert(&mut out, "endpoint", Value::Object(projected_endpoint));
    }
    Some(Value::Object(out))
}

fn project_enforcement(source: &Map<String, Value>) -> Option<Value> {
    let mut out = Map::new();
    insert(&mut out, "kind", json!("enforcement"));
    insert(
        &mut out,
        "record_id",
        json!(record_id("enforcement", &[string(source, "decision_id")?])),
    );
    copy_required(
        source,
        &mut out,
        &["decision", "mode", "rule_ids", "source_agent", "timestamp"],
    )?;
    copy_optional(
        source,
        &mut out,
        &[
            "deny_rule_id",
            "deny_rule_version",
            "tool_name",
            "tool_call_id",
            "session_id",
        ],
    );
    let ids = source.get("finding_ids")?.as_array()?;
    insert(
        &mut out,
        "finding_record_ids",
        Value::Array(
            ids.iter()
                .map(|id| Some(json!(record_id("finding", &[id.as_str()?]))))
                .collect::<Option<Vec<_>>>()?,
        ),
    );
    Some(Value::Object(out))
}

fn project_indicator(
    source: &Map<String, Value>,
    settings: &SecurityDataSettings,
) -> Option<Value> {
    if !settings.urls {
        return None;
    }
    let run_id = string(source, "run_id")?;
    let indicator_type = string(source, "type")?;
    let value = string(source, "value")?;
    let mut out = Map::new();
    insert(&mut out, "kind", json!("indicator"));
    insert(
        &mut out,
        "record_id",
        json!(record_id("indicator", &[run_id, indicator_type, value])),
    );
    copy_required(
        source,
        &mut out,
        &[
            "type",
            "value",
            "count",
            "first_seen",
            "last_seen",
            "source_agent",
        ],
    )?;
    Some(Value::Object(out))
}

fn project_scan_summary(source: &Map<String, Value>) -> Option<Value> {
    let mut out = Map::new();
    insert(&mut out, "kind", json!("scan_summary"));
    insert(
        &mut out,
        "record_id",
        json!(record_id("scan_summary", &[string(source, "run_id")?])),
    );
    copy_required(
        source,
        &mut out,
        &[
            "status",
            "artifacts_scanned",
            "events_emitted",
            "findings_emitted",
            "indicators_emitted",
            "diagnostics",
        ],
    )?;
    Some(Value::Object(out))
}

fn project_permission(
    source: &Map<String, Value>,
    joins: &mut PermissionJoinTracker,
) -> Option<Value> {
    let outcome = match string(source, "event_type")? {
        "permission.requested" => "requested",
        "permission.approved" => "approved",
        "permission.denied" => "denied",
        _ => return None,
    };
    let mut out = Map::new();
    insert(&mut out, "kind", json!("permission_event"));
    insert(
        &mut out,
        "record_id",
        json!(record_id(
            "permission_event",
            &[string(source, "event_id")?]
        )),
    );
    insert(&mut out, "outcome", json!(outcome));
    copy_required(source, &mut out, &["source_agent", "timestamp"])?;
    copy_optional(
        source,
        &mut out,
        &["tool_name", "tool_call_id", "session_id"],
    );
    let join = joins.join_for(source);
    for (key, value) in join.as_object()? {
        insert(&mut out, key, value.clone());
    }
    Some(Value::Object(out))
}

pub fn project_security_status(fields: Map<String, Value>) -> Option<ProjectedRecord> {
    let observed_at = string(&fields, "observed_at")?;
    let mut projected = Map::new();
    insert(&mut projected, "kind", json!("security_status"));
    insert(
        &mut projected,
        "record_id",
        json!(record_id("security_status", &[observed_at])),
    );
    copy_required(
        &fields,
        &mut projected,
        &[
            "observed_at",
            "numbat_version",
            "wired_agents",
            "active_bundle_digest",
            "lease_id",
            "last_record_at",
            "health",
        ],
    )?;
    let record_id = string(&projected, "record_id")?.to_string();
    let lease_id = string(&projected, "lease_id")
        .unwrap_or_default()
        .to_string();
    Some(ProjectedRecord {
        kind: "security_status".to_string(),
        record_id,
        lease_id,
        json: Value::Object(projected),
    })
}

pub fn project_agent_inventory(fields: Map<String, Value>) -> Option<ProjectedRecord> {
    let observed_at = string(&fields, "observed_at")?;
    let mut projected = Map::new();
    insert(&mut projected, "kind", json!("agent_inventory"));
    insert(
        &mut projected,
        "record_id",
        json!(record_id("agent_inventory", &[observed_at])),
    );
    copy_required(&fields, &mut projected, &["observed_at", "agents"])?;
    let record_id = string(&projected, "record_id")?.to_string();
    Some(ProjectedRecord {
        kind: "agent_inventory".to_string(),
        record_id,
        lease_id: String::new(),
        json: Value::Object(projected),
    })
}

/// Re-minimization is deletion-only. It never restores data that was not
/// permitted when the row entered the durable queue.
pub fn minimize_queued(record: &Value, settings: &SecurityDataSettings) -> Option<Value> {
    let mut record = record.as_object()?.clone();
    if string(&record, "kind") == Some("indicator") && !settings.urls {
        return None;
    }
    if string(&record, "kind") == Some("finding") {
        for (enabled, key) in [
            (settings.command_previews, "observed_command"),
            (settings.file_paths, "observed_file_path"),
            (settings.urls, "observed_url"),
        ] {
            if !enabled {
                record.remove(key);
            }
        }
        if let Some(endpoint) = record.get_mut("endpoint").and_then(Value::as_object_mut) {
            if !settings.host_identity {
                endpoint.remove("hostname");
            }
            if !settings.user_identity {
                endpoint.remove("username");
            }
            if endpoint.is_empty() {
                record.remove("endpoint");
            }
        }
    }
    Some(Value::Object(record))
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn string<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)?.as_str()
}

fn insert(map: &mut Map<String, Value>, key: &str, value: Value) {
    map.insert(key.to_string(), value);
}

fn copy_required(
    source: &Map<String, Value>,
    out: &mut Map<String, Value>,
    keys: &[&str],
) -> Option<()> {
    for key in keys {
        insert(out, key, source.get(*key)?.clone());
    }
    Some(())
}

fn copy_optional(source: &Map<String, Value>, out: &mut Map<String, Value>, keys: &[&str]) {
    for key in keys {
        if let Some(value) = source.get(*key) {
            insert(out, key, value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn lease(settings: SecurityDataSettings) -> ProjectionLease {
        ProjectionLease {
            lease_id: "lease-placeholder".to_string(),
            bundle_digest: "a".repeat(64),
            issued_at: parse_time("2026-01-01T00:00:00Z").unwrap(),
            expires_at: parse_time("2027-01-01T00:00:00Z").unwrap(),
            data_settings: settings,
        }
    }

    #[test]
    fn record_id_uses_the_frozen_nul_delimited_preimage() {
        for (kind, parts, expected) in [
            (
                "finding",
                vec!["fnd-49e7e870ff96953b2b8e5dd3"],
                "sha256:3600c333faf7fddf87d4508d3d9e308f05f53cf70b3735c8575fadf0488a8338",
            ),
            (
                "enforcement",
                vec!["enf-8f62f739638bc81b28547bc9"],
                "sha256:e30e4c26c44c18fc4627ab16cf08d16b40c4cde7b6d66cfe5db1ca87cb4b2bc1",
            ),
            (
                "indicator",
                vec!["run-placeholder", "domain", "example.invalid"],
                "sha256:679b83b6728e080b15b3ec16486fba76a9c6e9c737919d00013d6e99bd2fef4b",
            ),
            (
                "scan_summary",
                vec!["scan-placeholder"],
                "sha256:e69cd3a4af4f20d0e39260d7a709ea29bc1e9f1f5444f57649075f76856d1fde",
            ),
            (
                "permission_event",
                vec!["permission-placeholder"],
                "sha256:15907aea1fc2023f7059b0a62f5a145d4449107058b66591282db14a2d7def60",
            ),
            (
                "security_status",
                vec!["2026-10-17T10:00:00Z"],
                "sha256:3b85d236fdca28674a6762d420852b6e4e78541e02cff09149eec586a2230f13",
            ),
            (
                "agent_inventory",
                vec!["2026-10-17T10:00:00Z"],
                "sha256:a422f340f1abbd7d715d7285774273b6d04693375cf44bd473e9d3db971385fe",
            ),
        ] {
            assert_eq!(record_id(kind, &parts), expected, "{kind}");
        }
    }

    #[test]
    fn finding_projection_is_closed_and_respects_every_switch() {
        let raw = json!({
            "schema_version":"0.5.0", "record_type":"finding",
            "finding_id":"fnd-49e7e870ff96953b2b8e5dd3", "rule_id":"secrets.agent_read_env",
            "rule_version":"1.3", "severity":"medium", "title":".env file access",
            "source_agent":"codex", "source_type":"hook", "model":"gpt-5.5-codex",
            "session_id":"session-placeholder", "confidence":"high",
            "detected_at":"2026-10-17T10:00:00Z", "project_path_hash":"sha256:unknown",
            "observed_command":"cat [REDACTED_PATH]", "observed_file_path":"[REDACTED_PATH]",
            "observed_url":"https://example.invalid", "tool_input":"forbidden",
            "endpoint":{"hostname":"host", "username":"user", "uid":"501", "device_id":"bad"}
        });
        let settings = SecurityDataSettings {
            command_previews: true,
            file_paths: false,
            urls: false,
            host_identity: true,
            user_identity: false,
        };
        let projected = project_numbat_record(
            raw.to_string().as_bytes(),
            &lease(settings),
            &HashMap::new(),
            &mut PermissionJoinTracker::default(),
            false,
        )
        .unwrap();
        assert_eq!(projected.json["observed_command"], "cat [REDACTED_PATH]");
        assert!(projected.json.get("observed_file_path").is_none());
        assert!(projected.json.get("observed_url").is_none());
        assert_eq!(projected.json["endpoint"], json!({"hostname":"host"}));
        for forbidden in ["tool_input", "uid", "device_id", "project_path_hash"] {
            assert!(!projected.json.to_string().contains(forbidden));
        }
    }

    #[test]
    fn finding_projection_tests_each_data_setting_independently() {
        let raw = json!({
            "schema_version":"0.5.0", "record_type":"finding", "finding_id":"f1",
            "rule_id":"rule", "rule_version":"1", "severity":"low", "title":"title",
            "source_agent":"codex", "source_type":"hook", "confidence":"high",
            "detected_at":"2026-10-17T10:00:00Z", "observed_command":"command",
            "observed_file_path":"path", "observed_url":"https://example.invalid",
            "endpoint":{"hostname":"host", "username":"user"}
        });
        let cases = [
            ("command_previews", "observed_command", None),
            ("file_paths", "observed_file_path", None),
            ("urls", "observed_url", None),
            ("host_identity", "hostname", Some("endpoint")),
            ("user_identity", "username", Some("endpoint")),
        ];
        for (setting, field, parent) in cases {
            let mut settings = SecurityDataSettings::ALL_OFF;
            match setting {
                "command_previews" => settings.command_previews = true,
                "file_paths" => settings.file_paths = true,
                "urls" => settings.urls = true,
                "host_identity" => settings.host_identity = true,
                "user_identity" => settings.user_identity = true,
                _ => unreachable!(),
            }
            let projected = project_numbat_record(
                raw.to_string().as_bytes(),
                &lease(settings),
                &HashMap::new(),
                &mut PermissionJoinTracker::default(),
                false,
            )
            .unwrap();
            if let Some(parent) = parent {
                assert!(projected.json[parent].get(field).is_some(), "{setting}");
            } else {
                assert!(projected.json.get(field).is_some(), "{setting}");
            }
        }
    }

    #[test]
    fn repository_hash_matches_numbat_without_symlink_resolution() {
        assert_eq!(
            hash_project_path(" /var/repo/./a/../b "),
            hash_project_path("/var/repo/b")
        );
        assert_ne!(
            hash_project_path("/private/var/repo"),
            hash_project_path("/var/repo")
        );
        assert_eq!(
            hash_project_path(r"C:\repo\a"),
            hash_project_path("C:/repo/a")
        );
    }

    #[test]
    fn permission_join_is_ordered_bounded_and_not_buffered() {
        let lease = lease(SecurityDataSettings::ALL_OFF);
        let mut joins = PermissionJoinTracker::default();
        let permission = |id: &str, timestamp: &str| {
            json!({
                "schema_version":"0.5.0", "record_type":"event", "event_id":id,
                "event_type":"permission.approved", "source_agent":"claude-code",
                "timestamp":timestamp, "session_id":"s1", "tool_call_id":"t1"
            })
        };
        let before = project_numbat_record(
            permission("before", "2026-10-17T10:00:00Z")
                .to_string()
                .as_bytes(),
            &lease,
            &HashMap::new(),
            &mut joins,
            false,
        )
        .unwrap();
        assert_eq!(before.json["join"], "unavailable");

        let finding = json!({
            "schema_version":"0.5.0", "record_type":"finding", "finding_id":"f1",
            "rule_id":"r", "rule_version":"1", "severity":"low", "title":"t",
            "source_agent":"claude-code", "source_type":"hook", "confidence":"high",
            "detected_at":"2026-10-17T10:00:01Z", "session_id":"s1", "tool_call_id":"t1"
        });
        project_numbat_record(
            finding.to_string().as_bytes(),
            &lease,
            &HashMap::new(),
            &mut joins,
            false,
        )
        .unwrap();
        let exact = project_numbat_record(
            permission("after", "2026-10-17T10:00:02Z")
                .to_string()
                .as_bytes(),
            &lease,
            &HashMap::new(),
            &mut joins,
            false,
        )
        .unwrap();
        assert_eq!(exact.json["join"], "exact");
        assert_eq!(exact.json["tool_call_id"], "t1");

        let same_session = json!({
            "schema_version":"0.5.0", "record_type":"event", "event_id":"session",
            "event_type":"permission.requested", "source_agent":"claude-code",
            "timestamp":"2026-10-17T10:00:03Z", "session_id":"s1",
            "tool_call_id":"different"
        });
        let same_session = project_numbat_record(
            same_session.to_string().as_bytes(),
            &lease,
            &HashMap::new(),
            &mut joins,
            false,
        )
        .unwrap();
        assert_eq!(same_session.json["join"], "same_session_window");
        assert_eq!(same_session.json["session_id"], "s1");

        let restarted = project_numbat_record(
            permission("restart", "2026-10-17T10:00:04Z")
                .to_string()
                .as_bytes(),
            &lease,
            &HashMap::new(),
            &mut PermissionJoinTracker::default(),
            false,
        )
        .unwrap();
        assert_eq!(restarted.json["join"], "unavailable");
    }

    #[test]
    fn indicator_is_dropped_when_urls_turn_off_and_reminimization_only_deletes() {
        let source = json!({
            "schema_version":"0.5.0", "record_type":"indicator", "run_id":"run-1",
            "type":"domain", "value":"example.invalid", "count":2,
            "first_seen":"2026-06-02T10:00:00Z", "last_seen":"2026-06-02T10:05:00Z",
            "source_agent":"claude-code"
        });
        assert!(
            project_numbat_record(
                source.to_string().as_bytes(),
                &lease(SecurityDataSettings::ALL_OFF),
                &HashMap::new(),
                &mut PermissionJoinTracker::default(),
                false
            )
            .is_none()
        );
        let mut on = SecurityDataSettings::ALL_OFF;
        on.urls = true;
        let projected = project_numbat_record(
            source.to_string().as_bytes(),
            &lease(on),
            &HashMap::new(),
            &mut PermissionJoinTracker::default(),
            false,
        )
        .unwrap();
        assert!(minimize_queued(&projected.json, &SecurityDataSettings::ALL_OFF).is_none());
    }

    #[test]
    fn endpoint_generated_projections_are_closed() {
        let mut status = fixture("valid-security-status.json")["records"][0]
            .as_object()
            .unwrap()
            .clone();
        status.remove("kind");
        status.remove("record_id");
        status.insert("endpoint".into(), json!({"device_id":"forbidden"}));
        assert!(
            project_security_status(status)
                .unwrap()
                .json
                .get("endpoint")
                .is_none()
        );

        let mut inventory = fixture("valid-agent-inventory.json")["records"][0]
            .as_object()
            .unwrap()
            .clone();
        inventory.remove("kind");
        inventory.remove("record_id");
        inventory.insert("content_preview".into(), json!("forbidden"));
        assert!(
            project_agent_inventory(inventory)
                .unwrap()
                .json
                .get("content_preview")
                .is_none()
        );
    }

    #[test]
    fn diagnostic_wrong_schema_and_unrelated_events_are_never_projected() {
        let lease = lease(SecurityDataSettings::ALL_OFF);
        for source in [
            json!({"schema_version":"0.5.0","record_type":"diagnostic"}),
            json!({"schema_version":"0.4.0","record_type":"finding"}),
            json!({"schema_version":"0.5.0","record_type":"event","event_type":"command.exec"}),
        ] {
            assert!(
                project_numbat_record(
                    source.to_string().as_bytes(),
                    &lease,
                    &HashMap::new(),
                    &mut PermissionJoinTracker::default(),
                    false
                )
                .is_none()
            );
        }
    }

    fn fixture(name: &str) -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/security_v2")
            .join(name);
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn local_ref<'a>(schema: &'a Value, reference: &str) -> Option<&'a Value> {
        reference
            .strip_prefix("#/")?
            .split('/')
            .try_fold(schema, |node, part| node.get(part))
    }

    fn validates(schema: &Value, root: &Value, value: &Value) -> bool {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            return local_ref(root, reference).is_some_and(|target| validates(target, root, value));
        }
        if let Some(constant) = schema.get("const")
            && value != constant
        {
            return false;
        }
        if let Some(values) = schema.get("enum").and_then(Value::as_array)
            && !values.contains(value)
        {
            return false;
        }
        if let Some(branches) = schema.get("oneOf").and_then(Value::as_array)
            && branches
                .iter()
                .filter(|branch| validates(branch, root, value))
                .count()
                != 1
        {
            return false;
        }
        match schema.get("type").and_then(Value::as_str) {
            Some("object") => {
                let Some(object) = value.as_object() else {
                    return false;
                };
                if let Some(required) = schema.get("required").and_then(Value::as_array)
                    && required
                        .iter()
                        .any(|key| key.as_str().is_none_or(|key| !object.contains_key(key)))
                {
                    return false;
                }
                let properties = schema.get("properties").and_then(Value::as_object);
                if schema.get("additionalProperties") == Some(&Value::Bool(false))
                    && object
                        .keys()
                        .any(|key| properties.is_none_or(|map| !map.contains_key(key)))
                {
                    return false;
                }
                if let Some(properties) = properties {
                    for (key, value) in object {
                        if let Some(property) = properties.get(key)
                            && !validates(property, root, value)
                        {
                            return false;
                        }
                    }
                }
            }
            Some("array") => {
                let Some(array) = value.as_array() else {
                    return false;
                };
                if let Some(items) = schema.get("items")
                    && array.iter().any(|value| !validates(items, root, value))
                {
                    return false;
                }
            }
            Some("string") if !value.is_string() => return false,
            Some("integer") if !value.is_i64() && !value.is_u64() => return false,
            Some("boolean") if !value.is_boolean() => return false,
            Some("null") if !value.is_null() => return false,
            _ => {}
        }
        true
    }

    fn validates_upload_fixture(schema: &Value, fixture: &Value) -> bool {
        let Some(records) = fixture.get("records").and_then(Value::as_array) else {
            return false;
        };
        let names = [
            ("finding", "finding"),
            ("enforcement", "enforcement"),
            ("indicator", "indicator"),
            ("scan_summary", "scanSummary"),
            ("permission_event", "permissionEvent"),
            ("security_status", "securityStatus"),
            ("agent_inventory", "agentInventory"),
        ];
        records.iter().all(|record| {
            let Some(kind) = record.get("kind").and_then(Value::as_str) else {
                return false;
            };
            let Some((_, definition)) = names.iter().find(|(name, _)| *name == kind) else {
                return false;
            };
            schema
                .get("definitions")
                .and_then(|definitions| definitions.get(*definition))
                .is_some_and(|record_schema| validates(record_schema, schema, record))
        })
    }

    #[test]
    fn copied_upload_schema_accepts_every_valid_and_refuses_every_invalid_record_fixture() {
        let schema = fixture("security-upload-v2.schema.json");
        let valid = [
            "valid-finding.json",
            "valid-enforcement.json",
            "valid-indicator.json",
            "valid-scan-summary.json",
            "valid-permission-event.json",
            "valid-security-status.json",
            "valid-agent-inventory.json",
        ];
        let invalid = [
            "invalid-finding-tool-input.json",
            "invalid-finding-evidence-refs.json",
            "invalid-finding-project-path-hash.json",
            "invalid-finding-endpoint-uid.json",
            "invalid-enforcement-tool-result.json",
            "invalid-indicator-sample-project-path-hash.json",
            "invalid-scan-summary-project-path.json",
            "invalid-permission-event-content.json",
            "invalid-security-status-endpoint-device-id.json",
            "invalid-agent-inventory-content-preview.json",
        ];
        for name in valid {
            assert!(validates_upload_fixture(&schema, &fixture(name)), "{name}");
        }
        for name in invalid {
            assert!(!validates_upload_fixture(&schema, &fixture(name)), "{name}");
        }
    }

    #[test]
    fn every_projection_validates_against_the_copied_upload_schema() {
        let schema = fixture("security-upload-v2.schema.json");
        let mut settings = SecurityDataSettings::ALL_OFF;
        settings.urls = true;
        let lease = lease(settings);
        let sources = [
            json!({
                "schema_version":"0.5.0","record_type":"finding","finding_id":"f1",
                "rule_id":"rule","rule_version":"1","severity":"low","title":"title",
                "source_agent":"codex","source_type":"hook","confidence":"high",
                "detected_at":"2026-10-17T10:00:00Z"
            }),
            json!({
                "schema_version":"0.5.0","record_type":"enforcement","decision_id":"d1",
                "decision":"no_override","mode":"monitor","rule_ids":["rule"],
                "finding_ids":["f1"],"source_agent":"codex",
                "timestamp":"2026-10-17T10:00:01Z"
            }),
            json!({
                "schema_version":"0.5.0","record_type":"indicator","run_id":"run1",
                "type":"domain","value":"example.invalid","count":1,
                "first_seen":"2026-10-17T10:00:00Z","last_seen":"2026-10-17T10:00:01Z",
                "source_agent":"codex"
            }),
            json!({
                "schema_version":"0.5.0","record_type":"scan_summary","run_id":"run1",
                "status":"complete","artifacts_scanned":1,"events_emitted":1,
                "findings_emitted":1,"indicators_emitted":1,"diagnostics":0
            }),
            json!({
                "schema_version":"0.5.0","record_type":"event","event_id":"event1",
                "event_type":"permission.approved","source_agent":"codex",
                "timestamp":"2026-10-17T10:00:02Z"
            }),
        ];
        let mut joins = PermissionJoinTracker::default();
        let mut projected = sources
            .iter()
            .map(|source| {
                project_numbat_record(
                    source.to_string().as_bytes(),
                    &lease,
                    &HashMap::new(),
                    &mut joins,
                    false,
                )
                .unwrap()
                .json
            })
            .collect::<Vec<_>>();

        for (fixture_name, projector) in [
            (
                "valid-security-status.json",
                project_security_status as fn(Map<String, Value>) -> Option<ProjectedRecord>,
            ),
            ("valid-agent-inventory.json", project_agent_inventory),
        ] {
            let mut fields = fixture(fixture_name)["records"][0]
                .as_object()
                .unwrap()
                .clone();
            fields.remove("kind");
            fields.remove("record_id");
            projected.push(projector(fields).unwrap().json);
        }

        for record in projected {
            assert!(
                validates_upload_fixture(
                    &schema,
                    &json!({"schema_version":"trackai.security-upload/2","records":[record]})
                ),
                "projection did not match frozen upload schema"
            );
        }
    }
}
