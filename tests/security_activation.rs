use git_ai::api::ApiContext;
use git_ai::metrics::delivery::MetricDeliveryHealthBinding;
use git_ai::security::MonitorMode;
use git_ai::security::activation::{
    SecurityActivationCache, SecurityActivationRegistry, fetch_security_activation,
    refresh_security_activation_with,
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

    assert_eq!(registry.mode_for(&company_a, now), MonitorMode::Monitor);
    assert_eq!(registry.mode_for(&company_b, now), MonitorMode::Off);
    assert!(!registry.refresh_due_for(&company_a, now + 59));
    assert!(registry.refresh_due_for(&company_a, now + 60));

    let due = registry.prepare_refresh([company_a.clone(), company_b.clone()], now + 60);
    assert_eq!(due, vec![company_a.clone(), company_b.clone()]);
    assert_eq!(registry.mode_for(&company_a, now + 60), MonitorMode::Off);
    assert_eq!(registry.mode_for(&company_b, now + 60), MonitorMode::Off);

    registry.retain_routes([&company_b]);
    assert_eq!(registry.mode_for(&company_a, now + 1), MonitorMode::Off);
}
