use git_ai::metrics::delivery::EvidenceDeliveryBinding;
use git_ai::security::delivery_queue::SecurityFindingQueue;
use git_ai::security::{
    DeleteInput, EvaluationInput, FindingOperatingSystem, FindingUploadContext, MonitorMode,
    SecurityFindingUploadBatch, ShellDialect, TargetClass, evaluate,
};

fn binding(tenant: &str, repository: &str, key: &str) -> EvidenceDeliveryBinding {
    EvidenceDeliveryBinding {
        repository_id: repository.to_string(),
        tenant_id: tenant.to_string(),
        repository_url: format!("https://github.com/example/{repository}"),
        api_base_url: "https://trackai.example/api/gitai".to_string(),
        credential_key_id: key.to_string(),
    }
}

fn batch(suffix: &str) -> SecurityFindingUploadBatch {
    let finding = evaluate(
        MonitorMode::Monitor,
        &EvaluationInput::Delete(DeleteInput::new(
            ShellDialect::Posix,
            TargetClass::FilesystemRoot,
        )),
    )
    .finding
    .expect("approved input should match");
    SecurityFindingUploadBatch::from_safe_finding(
        finding,
        FindingUploadContext {
            finding_id: format!("finding-{suffix}"),
            delivery_id: format!("delivery-{suffix}"),
            repository_id: format!("repository-{suffix}"),
            session_id: format!("session-{suffix}"),
            source_event_id: format!("event-{suffix}"),
            correlation_id: None,
            operating_system: FindingOperatingSystem::Linux,
            occurred_at: "2026-09-30T08:00:00Z".to_string(),
            client_version: "0.1.0-test".to_string(),
            rule_pack_version: "0.1.0-test".to_string(),
        },
    )
    .expect("safe metadata should project")
}

#[test]
fn queued_safe_finding_survives_restart_with_immutable_binding() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("security-findings.db");
    let expected_batch = batch("a");
    let expected_binding = binding("tenant-a", "repository-a", "key-a");

    {
        let mut queue = SecurityFindingQueue::open_at_path(&path).unwrap();
        queue
            .enqueue(&expected_batch, &expected_binding, 1_700_000_000)
            .unwrap();
    }

    let mut reopened = SecurityFindingQueue::open_at_path(&path).unwrap();
    let records = reopened
        .dequeue_pending(10, 1_700_000_001)
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].delivery_binding, expected_binding);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&records[0].finding_json).unwrap(),
        serde_json::to_value(expected_batch).unwrap()
    );
    assert!(!records[0].finding_json.contains("command"));
    assert!(!records[0].finding_json.contains("tenantId"));
    assert!(!records[0].finding_json.contains("machineId"));
}

#[test]
fn queued_findings_keep_two_tenant_routes_separate() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("security-findings.db");
    let mut queue = SecurityFindingQueue::open_at_path(&path).unwrap();
    queue
        .enqueue(
            &batch("a"),
            &binding("tenant-a", "repository-a", "key-a"),
            1_700_000_000,
        )
        .unwrap();
    queue
        .enqueue(
            &batch("b"),
            &binding("tenant-b", "repository-b", "key-b"),
            1_700_000_000,
        )
        .unwrap();

    let records = queue.dequeue_pending(10, 1_700_000_001).unwrap();
    assert_eq!(records.len(), 2);
    assert_ne!(
        records[0].delivery_binding.tenant_id,
        records[1].delivery_binding.tenant_id
    );
    assert_ne!(
        records[0].delivery_binding.credential_key_id,
        records[1].delivery_binding.credential_key_id
    );
    assert_ne!(
        records[0].delivery_binding.repository_id,
        records[1].delivery_binding.repository_id
    );
}

#[test]
fn partial_acknowledgement_delivers_success_and_retries_only_failure() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("security-findings.db");
    let mut queue = SecurityFindingQueue::open_at_path(&path).unwrap();
    let route = binding("tenant-a", "repository-a", "key-a");
    queue.enqueue(&batch("one"), &route, 1_700_000_000).unwrap();
    queue.enqueue(&batch("two"), &route, 1_700_000_000).unwrap();

    let records = queue.dequeue_pending(10, 1_700_000_001).unwrap();
    assert_eq!(records.len(), 2);
    queue
        .mark_delivered(&[records[0].id], 1_700_000_002)
        .unwrap();
    queue
        .mark_failed(&[records[1].id], "temporary_transport_error", 1_700_000_002)
        .unwrap();

    assert!(queue.dequeue_pending(10, 1_700_000_003).unwrap().is_empty());
    let retry = queue.dequeue_pending(10, 1_700_000_062).unwrap();
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].id, records[1].id);
    assert_eq!(retry[0].attempts, 1);
}
