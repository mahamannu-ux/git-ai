use git_ai::error::GitAiError;
use git_ai::metrics::delivery::EvidenceDeliveryBinding;
use git_ai::security::delivery::{
    SecurityFindingUploadError, SecurityFindingUploadResponse, flush_security_findings_with,
    upload_security_findings,
};
use git_ai::security::delivery_queue::SecurityFindingQueue;
use git_ai::security::{
    DeleteInput, EvaluationInput, FindingOperatingSystem, FindingUploadContext, MonitorMode,
    SecurityFindingUploadBatch, ShellDialect, TargetClass, evaluate,
};

fn route() -> EvidenceDeliveryBinding {
    EvidenceDeliveryBinding {
        repository_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
        tenant_id: "11111111-1111-4111-8111-111111111111".to_string(),
        repository_url: "https://github.com/example/repository-a".to_string(),
        api_base_url: "https://trackai.example/api/gitai".to_string(),
        credential_key_id: "credential-key-a".to_string(),
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
    .unwrap();
    SecurityFindingUploadBatch::from_safe_finding(
        finding,
        FindingUploadContext {
            finding_id: format!("finding-{suffix}"),
            delivery_id: format!("delivery-{suffix}"),
            repository_id: route().repository_id,
            session_id: format!("session-{suffix}"),
            source_event_id: format!("event-{suffix}"),
            correlation_id: None,
            operating_system: FindingOperatingSystem::Linux,
            occurred_at: "2026-09-30T09:00:00Z".to_string(),
            client_version: "0.1.0-test".to_string(),
            rule_pack_version: "0.1.0-test".to_string(),
        },
    )
    .unwrap()
}

#[test]
fn delivery_batches_one_route_and_honors_partial_acknowledgement() {
    let directory = tempfile::tempdir().unwrap();
    let mut queue = SecurityFindingQueue::open_at_path(&directory.path().join("queue.db")).unwrap();
    queue
        .enqueue(&batch("one"), &route(), 1_700_000_000)
        .unwrap();
    queue
        .enqueue(&batch("two"), &route(), 1_700_000_000)
        .unwrap();
    let mut uploads = 0;

    let result = flush_security_findings_with(
        &mut queue,
        1_700_000_001,
        100,
        |binding| {
            assert_eq!(binding.credential_key_id, "credential-key-a");
            Some("reusable-secret-never-stored".to_string())
        },
        |context, body| {
            uploads += 1;
            assert_eq!(context.base_url, "https://trackai.example/api/gitai");
            assert_eq!(
                context.api_key.as_deref(),
                Some("reusable-secret-never-stored")
            );
            assert_eq!(body["findings"].as_array().unwrap().len(), 2);
            assert!(!body.to_string().contains("reusable-secret-never-stored"));
            Ok(SecurityFindingUploadResponse {
                errors: vec![SecurityFindingUploadError {
                    index: 1,
                    error: "repository_not_authorized".to_string(),
                }],
            })
        },
    )
    .unwrap();

    assert_eq!(uploads, 1);
    assert_eq!(result.delivered, 1);
    assert_eq!(result.terminal, 1);
    assert_eq!(result.retrying, 0);
    assert!(queue.dequeue_pending(10, 1_800_000_000).unwrap().is_empty());
}

#[test]
fn unavailable_exact_credential_stops_without_upload_or_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let mut queue = SecurityFindingQueue::open_at_path(&directory.path().join("queue.db")).unwrap();
    queue
        .enqueue(&batch("revoked"), &route(), 1_700_000_000)
        .unwrap();
    let mut uploads = 0;

    let result = flush_security_findings_with(
        &mut queue,
        1_700_000_001,
        100,
        |_binding| None,
        |_context, _body| {
            uploads += 1;
            Ok(SecurityFindingUploadResponse { errors: vec![] })
        },
    )
    .unwrap();

    assert_eq!(uploads, 0);
    assert_eq!(result.terminal, 1);
    assert!(queue.dequeue_pending(10, 1_800_000_000).unwrap().is_empty());
}

#[test]
fn transport_failure_retries_without_storing_error_content() {
    let directory = tempfile::tempdir().unwrap();
    let mut queue = SecurityFindingQueue::open_at_path(&directory.path().join("queue.db")).unwrap();
    queue
        .enqueue(&batch("retry"), &route(), 1_700_000_000)
        .unwrap();

    let result = flush_security_findings_with(
        &mut queue,
        1_700_000_001,
        100,
        |_binding| Some("secret".to_string()),
        |_context, _body| Err(GitAiError::Generic("raw upstream response".to_string())),
    )
    .unwrap();

    assert_eq!(result.retrying, 1);
    assert!(queue.dequeue_pending(10, 1_700_000_060).unwrap().is_empty());
    assert_eq!(queue.dequeue_pending(10, 1_700_000_061).unwrap().len(), 1);
}

#[test]
fn http_uploader_uses_managed_credential_and_safe_endpoint() {
    let mut server = mockito::Server::new();
    let request = batch("http");
    let body = serde_json::to_value(&request).unwrap();
    let mock = server
        .mock("POST", "/worker/security/findings")
        .match_header("x-api-key", "managed-machine-secret")
        .match_header("content-type", "application/json")
        .match_body(mockito::Matcher::Json(body.clone()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"errors":[]}"#)
        .create();
    let context = git_ai::api::ApiContext {
        base_url: server.url(),
        auth_token: None,
        api_key: Some("managed-machine-secret".to_string()),
        author_identity: None,
        timeout_secs: Some(5),
    };

    let response = upload_security_findings(&context, &body).unwrap();

    mock.assert();
    assert!(response.errors.is_empty());
}

#[test]
fn http_uploader_does_not_copy_server_body_into_error() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("POST", "/worker/security/findings")
        .with_status(503)
        .with_body("raw-server-secret-must-not-be-retained")
        .create();
    let context = git_ai::api::ApiContext {
        base_url: server.url(),
        auth_token: None,
        api_key: Some("managed-machine-secret".to_string()),
        author_identity: None,
        timeout_secs: Some(5),
    };

    let error = upload_security_findings(&context, &serde_json::json!({})).unwrap_err();

    mock.assert();
    assert!(error.to_string().contains("HTTP 503"));
    assert!(!error.to_string().contains("raw-server-secret-must-not-be-retained"));
}
