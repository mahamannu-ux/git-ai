use git_ai::api::ApiContext;
use git_ai::daemon::control_api::{ControlRequest, ControlResponse};
use git_ai::metrics::delivery::MetricDeliveryHealthBinding;
use git_ai::metrics::delivery::MetricDeliveryRuntime;
use git_ai::security::MonitorMode;
use git_ai::security::activation::{
    SecurityActivationCache, SecurityActivationRegistry, configured_security_monitor_mode,
    fetch_security_activation, query_daemon_security_monitor_mode_with,
    refresh_security_activation_with, refresh_security_activations,
};

fn context(base_url: String) -> ApiContext {
    ApiContext {
        base_url,
        auth_token: None,
        api_key: Some("managed-machine-secret".to_string()),
        author_identity: None,
        timeout_secs: Some(5),
    }
}

fn binding(tenant_id: &str, credential_key_id: &str) -> MetricDeliveryHealthBinding {
    MetricDeliveryHealthBinding {
        tenant_id: tenant_id.to_string(),
        api_base_url: "https://trackai.example".to_string(),
        credential_key_id: credential_key_id.to_string(),
    }
}

#[test]
fn activation_cache_starts_off_and_expires_without_persistence() {
    let mut cache = SecurityActivationCache::default();
    assert_eq!(cache.mode_at(1_790_762_400), MonitorMode::Off);

    cache
        .replace_from_json(
            r#"{
                "schemaVersion":"trackai.security-activation/0.1",
                "mode":"monitor",
                "version":3,
                "issuedAt":"2026-09-30T10:00:00Z",
                "refreshAfter":"2026-09-30T10:01:00Z",
                "expiresAt":"2026-09-30T10:05:00Z"
            }"#,
            1_790_762_400,
        )
        .unwrap();

    assert_eq!(cache.mode_at(1_790_762_401), MonitorMode::Monitor);
    assert_eq!(cache.mode_at(1_790_762_700), MonitorMode::Off);
    assert_eq!(
        SecurityActivationCache::default().mode_at(1_790_762_401),
        MonitorMode::Off
    );
}

#[test]
fn activation_cache_rejects_invalid_or_stale_server_values() {
    let now = 1_790_762_400;
    for raw in [
        r#"{"schemaVersion":"unknown","mode":"monitor","version":1,"issuedAt":"2026-09-30T10:00:00Z","refreshAfter":"2026-09-30T10:01:00Z","expiresAt":"2026-09-30T10:05:00Z"}"#,
        r#"{"schemaVersion":"trackai.security-activation/0.1","mode":"monitor","version":1,"issuedAt":"2026-09-30T10:00:00Z","refreshAfter":"2026-09-30T10:01:00Z","expiresAt":"2026-09-30T10:00:00Z"}"#,
        r#"{"schemaVersion":"trackai.security-activation/0.1","mode":"monitor","version":1,"issuedAt":"2026-09-30T10:00:00Z","refreshAfter":"2026-09-30T10:01:00Z","expiresAt":"2026-09-30T10:05:00Z","localOverride":true}"#,
    ] {
        let mut cache = SecurityActivationCache::default();
        assert!(cache.replace_from_json(raw, now).is_err());
        assert_eq!(cache.mode_at(now), MonitorMode::Off);
    }
}

#[test]
fn activation_http_fetch_uses_managed_credential_and_safe_endpoint() {
    let mut server = mockito::Server::new();
    let response = r#"{"schemaVersion":"trackai.security-activation/0.1","mode":"monitor","version":2,"issuedAt":"2026-09-30T10:00:00Z","refreshAfter":"2026-09-30T10:01:00Z","expiresAt":"2026-09-30T10:05:00Z"}"#;
    let mock = server
        .mock("GET", "/worker/security/activation")
        .match_header("x-api-key", "managed-machine-secret")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(response)
        .create();

    let lease = fetch_security_activation(&context(server.url())).unwrap();

    mock.assert();
    assert_eq!(lease.version(), 2);
}

#[test]
fn refresh_failure_clears_an_existing_monitor_value() {
    let now = 1_790_762_400;
    let mut cache = SecurityActivationCache::default();
    cache
        .replace_from_json(
            r#"{"schemaVersion":"trackai.security-activation/0.1","mode":"monitor","version":1,"issuedAt":"2026-09-30T10:00:00Z","refreshAfter":"2026-09-30T10:01:00Z","expiresAt":"2026-09-30T10:05:00Z"}"#,
            now,
        )
        .unwrap();

    let result = refresh_security_activation_with(&mut cache, now + 30, || {
        Err(git_ai::error::GitAiError::Generic("offline".to_string()))
    });

    assert!(result.is_err());
    assert_eq!(cache.mode_at(now + 30), MonitorMode::Off);
}

#[test]
fn activation_registry_keeps_company_routes_separate() {
    let now = 1_790_762_400;
    let company_a = binding("11111111-1111-4111-8111-111111111111", "credential-a");
    let company_b = binding("22222222-2222-4222-8222-222222222222", "credential-b");
    let mut registry = SecurityActivationRegistry::default();
    registry
        .replace_from_json(
            &company_a,
            r#"{"schemaVersion":"trackai.security-activation/0.1","mode":"monitor","version":1,"issuedAt":"2026-09-30T10:00:00Z","refreshAfter":"2026-09-30T10:01:00Z","expiresAt":"2026-09-30T10:05:00Z"}"#,
            now,
        )
        .unwrap();
    registry.replace_repository_bindings([
        (
            "https://github.com/example/company-a".to_string(),
            company_a.clone(),
        ),
        (
            "https://github.com/example/company-b".to_string(),
            company_b.clone(),
        ),
    ]);

    assert_eq!(registry.mode_for(&company_a, now), MonitorMode::Monitor);
    assert_eq!(registry.mode_for(&company_b, now), MonitorMode::Off);
    assert_eq!(
        registry.mode_for_repository("git@github.com:example/company-a.git", now),
        MonitorMode::Monitor
    );
    assert_eq!(
        registry.mode_for_repository("https://github.com/example/company-b", now),
        MonitorMode::Off
    );
    assert_eq!(
        registry.mode_for_repository("not-a-repository", now),
        MonitorMode::Off
    );
    assert!(!registry.refresh_due_for(&company_a, now + 59));
    assert!(registry.refresh_due_for(&company_a, now + 60));

    let due = registry.prepare_refresh([company_a.clone(), company_b.clone()], now + 60);
    assert_eq!(due, vec![company_a.clone(), company_b.clone()]);
    assert_eq!(registry.mode_for(&company_a, now + 60), MonitorMode::Off);
    assert_eq!(registry.mode_for(&company_b, now + 60), MonitorMode::Off);

    registry.retain_routes([&company_b]);
    assert_eq!(registry.mode_for(&company_a, now + 1), MonitorMode::Off);
}

#[cfg(unix)]
#[test]
fn background_refresh_uses_exact_task4_route_and_fails_offline_to_off() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::RwLock;

    let now = 1_790_762_400;
    let mut server = mockito::Server::new();
    let directory = tempfile::tempdir().unwrap();
    let policy_path = directory.path().join("trackai-delivery-policy.json");
    let keyring_path = directory.path().join("trackai-machine-credentials.json");
    let key_id = "abcdefghijklmnop";
    let credential = format!("trk_v1.{key_id}.{}", "A".repeat(43));
    std::fs::write(
        &policy_path,
        serde_json::json!({
            "version": 1,
            "repositories": [{
                "repository_url": "https://github.com/example/repository-a",
                "repository_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "tenant_id": "11111111-1111-4111-8111-111111111111",
                "api_base_url": server.url(),
                "credential_key_id": key_id,
            }],
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        &keyring_path,
        serde_json::json!({ "version": 1, "credentials": [credential] }).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&keyring_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = MetricDeliveryRuntime::load_from_paths(&policy_path, &keyring_path).unwrap();
    let binding = runtime.health_bindings().remove(0);
    let mock = server
        .mock("GET", "/worker/security/activation")
        .match_header("x-api-key", mockito::Matcher::Regex("^trk_v1\\.".to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"schemaVersion":"trackai.security-activation/0.1","mode":"monitor","version":1,"issuedAt":"2026-09-30T10:00:00Z","refreshAfter":"2026-09-30T10:01:00Z","expiresAt":"2026-09-30T10:05:00Z"}"#)
        .expect(1)
        .create();
    let registry = RwLock::new(SecurityActivationRegistry::default());

    refresh_security_activations(&registry, &runtime, now);
    assert_eq!(
        registry.read().unwrap().mode_for(&binding, now),
        MonitorMode::Monitor
    );
    assert_eq!(
        registry
            .read()
            .unwrap()
            .mode_for_repository("git@github.com:example/repository-a.git", now),
        MonitorMode::Monitor
    );
    refresh_security_activations(&registry, &runtime, now + 30);
    assert_eq!(
        registry.read().unwrap().mode_for(&binding, now + 30),
        MonitorMode::Monitor
    );
    mock.assert();
    mock.remove();
    refresh_security_activations(&registry, &runtime, now + 60);
    assert_eq!(
        registry.read().unwrap().mode_for(&binding, now + 60),
        MonitorMode::Off
    );
}

#[test]
fn daemon_schedules_activation_refresh_outside_the_git_event_path() {
    let unknown = binding("33333333-3333-4333-8333-333333333333", "credential-c");
    assert_eq!(
        configured_security_monitor_mode(&unknown, 1_790_762_400),
        MonitorMode::Off
    );

    let worker = std::fs::read_to_string("src/daemon/telemetry_worker.rs").unwrap();
    assert!(worker.contains("spawn_security_activation_refresh_worker();"));
    assert!(worker.contains("refresh_configured_security_activations();"));
    assert!(worker.contains("flush_configured_security_findings"));
}

#[test]
fn local_daemon_activation_query_carries_only_repository_identity() {
    let repository_url = "https://github.com/example/repository-a";
    let mode = query_daemon_security_monitor_mode_with(repository_url, |request| {
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({
                "method": "security.activation.query",
                "params": { "repository_url": repository_url },
            })
        );
        assert!(matches!(
            request,
            ControlRequest::SecurityActivationQuery { .. }
        ));
        Ok(ControlResponse::ok(
            None,
            Some(serde_json::json!({ "mode": "monitor" })),
        ))
    });
    assert_eq!(mode, MonitorMode::Monitor);

    for response in [
        Ok(ControlResponse::ok(
            None,
            Some(serde_json::json!({ "mode": "unexpected" })),
        )),
        Err("daemon unavailable".to_string()),
    ] {
        assert_eq!(
            query_daemon_security_monitor_mode_with(repository_url, |_| response),
            MonitorMode::Off
        );
    }
}
