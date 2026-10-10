use crate::repos::test_repo::TestRepo;

#[test]
fn fleet_bootstrap_installs_closed_non_secret_policy() {
    let repo = TestRepo::new();
    let policy = r#"{"version":1,"repositories":[{"repository_url":"https://github.com/example/repo","repository_id":"11111111-1111-4111-8111-111111111111","tenant_id":"22222222-2222-4222-8222-222222222222","api_base_url":"https://trackai.example/api/gitai","credential_key_id":"ABCDEFGHIJKLMNOP"}]}"#;
    let output = repo
        .git_ai_with_stdin(&["fleet", "bootstrap", "install"], policy.as_bytes())
        .unwrap();
    assert_eq!(output.trim(), "fleet_bootstrap_installed repositories=1");
    let installed = std::fs::read_to_string(
        repo.test_home_path()
            .join(".git-ai/trackai-delivery-policy.json"),
    )
    .unwrap();
    assert!(installed.contains("11111111-1111-4111-8111-111111111111"));
    assert!(!output.contains("github.com"));
    assert!(!output.contains("trackai.example"));
}

#[test]
fn fleet_credential_install_rejects_malformed_input_without_echoing_it() {
    let repo = TestRepo::new();
    let credential = "trk_v1.ABCDEFGHIJKLMNOP.not-a-complete-secret";
    let error = repo
        .git_ai_with_stdin(&["fleet", "credential", "install"], credential.as_bytes())
        .unwrap_err();
    assert!(error.contains("fleet_error code=invalid_credential"));
    assert!(!error.contains(credential));
    assert!(!error.contains("not-a-complete-secret"));
}
