#[path = "support/security_v2_schema.rs"]
mod security_v2_schema;

use chrono::{TimeZone, Utc};
use git_ai::security::records::{
    PermissionJoinTracker, ProjectedRecord, ProjectionLease, SecurityDataSettings,
    project_agent_inventory, project_numbat_record, project_security_status,
};
use security_v2_schema::{fixture, validates};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

fn lease() -> ProjectionLease {
    let mut data_settings = SecurityDataSettings::ALL_OFF;
    data_settings.urls = true;
    ProjectionLease {
        lease_id: "lease-placeholder".into(),
        bundle_digest: "a".repeat(64),
        issued_at: Utc.timestamp_opt(0, 0).unwrap(),
        expires_at: Utc.timestamp_opt(4_102_444_800, 0).unwrap(),
        data_settings,
    }
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
        assert!(validates(&schema, &fixture(name)), "{name}");
    }
    for name in invalid {
        assert!(!validates(&schema, &fixture(name)), "{name}");
    }
}

#[test]
fn schema_validator_enforces_bounds_patterns_uniqueness_conditionals_and_time() {
    let schema = fixture("security-upload-v2.schema.json");
    let valid = fixture("valid-enforcement.json");
    for invalid in [
        json!({"schema_version":"trackai.security-upload/2","records":[]}),
        {
            let mut value = valid.clone();
            value["records"][0]["record_id"] = json!("not-a-record-id");
            value
        },
        {
            let mut value = valid.clone();
            value["records"][0]["rule_ids"] = json!(["rule", "rule"]);
            value
        },
        {
            let mut value = valid.clone();
            value["records"][0]["timestamp"] = json!("not-a-time");
            value
        },
        {
            let mut value = valid.clone();
            value["records"][0]["decision"] = json!("deny");
            value["records"][0]["mode"] = json!("enforce");
            value
        },
        {
            let mut value = fixture("valid-scan-summary.json");
            value["records"][0]["events_emitted"] = json!(9_007_199_254_740_992_u64);
            value
        },
        {
            let mut value = fixture("valid-finding.json");
            value["records"][0]["observed_command"] = json!("x".repeat(201));
            value
        },
    ] {
        assert!(!validates(&schema, &invalid));
    }
}

#[test]
fn every_endpoint_projection_validates_against_the_exact_copied_schema() {
    let schema = fixture("security-upload-v2.schema.json");
    let lease = lease();
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
        let upload = json!({
            "schema_version":"trackai.security-upload/2",
            "records":[record]
        });
        assert!(validates(&schema, &upload), "{upload}");
    }
}
