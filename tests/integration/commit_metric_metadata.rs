use crate::repos::test_file::ExpectedLineExt;
use crate::repos::test_repo::TestRepo;
use git_ai::metrics::MetricEvent;
use git_ai::metrics::attrs::attr_pos;
use git_ai::metrics::db::MetricsDatabase;
use git_ai::metrics::events::{committed_pos, rewrite_committed_pos};
use git_ai::metrics::types::{MetricEventId, SparseArray};
use serde_json::json;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

fn isolated_metrics_db_path() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("failed to create isolated metrics db dir");
    let path = dir.path().join("metrics.db");
    (dir, path.to_string_lossy().to_string())
}

fn codex_checkpoint(
    repo: &TestRepo,
    file_path: &Path,
    session_id: &str,
    hook_event_name: &str,
    tool_use_id: &str,
) {
    let hook_input = json!({
        "session_id": session_id,
        "cwd": repo.canonical_path().to_string_lossy().to_string(),
        "hook_event_name": hook_event_name,
        "tool_name": "apply_patch",
        "tool_use_id": tool_use_id,
        "model": "gpt-5",
        "tool_input": {
            "patch": format!("*** Update File: {}\n", file_path.to_string_lossy())
        },
    })
    .to_string();

    repo.git_ai(&["checkpoint", "codex", "--hook-input", &hook_input])
        .expect("codex checkpoint should succeed");
}

fn sparse_str(values: &SparseArray, pos: usize) -> Option<&str> {
    values
        .get(&pos.to_string())
        .and_then(|value| value.as_str())
}

fn sparse_u64(values: &SparseArray, pos: usize) -> Option<u64> {
    values
        .get(&pos.to_string())
        .and_then(|value| value.as_u64())
}

fn committed_metric_for_commit(db_path: &str, commit_sha: &str) -> MetricEvent {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let db = MetricsDatabase::open_at_path(Path::new(db_path))
            .expect("metrics db should open at isolated path");
        let records = db
            .get_metric_history(0, None, &[MetricEventId::Committed as u16])
            .expect("metric history should load");
        if let Some(record) = records.into_iter().find(|record| {
            sparse_str(&record.event.attrs, attr_pos::COMMIT_SHA) == Some(commit_sha)
        }) {
            return record.event;
        }

        if Instant::now() >= deadline {
            panic!("committed metric for {commit_sha} was not persisted");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn rewrite_metric_diagnostics(repo: &TestRepo, db_path: &str) -> String {
    let db = MetricsDatabase::open_at_path(Path::new(db_path))
        .expect("metrics db should open for diagnostics");
    let mut persisted = Vec::new();
    for event_id in 1..=MetricEventId::RewriteCommitted as u16 {
        let records = db
            .get_metric_history(0, None, &[event_id])
            .expect("metric diagnostics should load");
        for record in records {
            persisted.push((
                record.event.event_id,
                sparse_str(&record.event.attrs, attr_pos::COMMIT_SHA)
                    .unwrap_or("")
                    .to_string(),
            ));
        }
    }

    let daemon_dir = repo.daemon_home_path().join(".git-ai/internal/daemon");
    let stderr = fs::read_to_string(daemon_dir.join("daemon.test.stderr.log"))
        .unwrap_or_else(|_| "<no daemon stderr>".to_string());
    let mut logs = String::new();
    if let Ok(entries) = fs::read_dir(daemon_dir.join("logs")) {
        for entry in entries.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                logs.push_str(&format!("\n--- {} ---\n{content}", entry.path().display()));
            }
        }
    }
    format!(
        "persisted={persisted:?}\ncompletions={:?}\nstderr={stderr}\nlogs={logs}",
        repo.daemon_completion_entries()
    )
}

fn rewrite_metric_for_commit(repo: &TestRepo, db_path: &str, commit_sha: &str) -> MetricEvent {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let db = MetricsDatabase::open_at_path(Path::new(db_path))
            .expect("metrics db should open at isolated path");
        let records = db
            .get_metric_history(0, None, &[MetricEventId::RewriteCommitted as u16])
            .expect("rewrite metric history should load");
        if let Some(record) = records.into_iter().find(|record| {
            sparse_str(&record.event.attrs, attr_pos::COMMIT_SHA) == Some(commit_sha)
        }) {
            return record.event;
        }

        if Instant::now() >= deadline {
            panic!(
                "rewrite metric for {commit_sha} was not persisted\n{}",
                rewrite_metric_diagnostics(repo, db_path)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn looks_like_patch_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[test]
fn committed_metric_includes_git_author_commit_timestamps_and_patch_id() {
    let (_metrics_db_dir, metrics_db_path) = isolated_metrics_db_path();
    let repo =
        TestRepo::new_with_daemon_env(&[("GIT_AI_TEST_METRICS_DB_PATH", metrics_db_path.as_str())]);

    let file_path = repo.path().join("generated.txt");
    fs::write(&file_path, "base\n").unwrap();
    repo.stage_all_and_commit("Initial commit")
        .expect("initial commit should succeed");

    codex_checkpoint(
        &repo,
        &file_path,
        "metric-metadata-session",
        "PreToolUse",
        "tool-use-metric-metadata",
    );
    fs::write(&file_path, "base\nai line\n").unwrap();
    codex_checkpoint(
        &repo,
        &file_path,
        "metric-metadata-session",
        "PostToolUse",
        "tool-use-metric-metadata",
    );

    let commit = repo
        .stage_all_and_commit_with_env(
            "AI commit with deterministic dates",
            &[
                ("GIT_AUTHOR_DATE", "2030-01-03T00:00:00Z"),
                ("GIT_COMMITTER_DATE", "2030-01-03T00:00:42Z"),
            ],
        )
        .expect("AI commit should succeed");

    let expected_times = repo
        .git(&["show", "-s", "--format=%at%x00%ct", &commit.commit_sha])
        .expect("commit timestamps should be readable");
    let mut parts = expected_times.trim().split('\0');
    let expected_author_ts = parts
        .next()
        .expect("author ts")
        .parse::<u64>()
        .expect("author ts should parse");
    let expected_commit_ts = parts
        .next()
        .expect("commit ts")
        .parse::<u64>()
        .expect("commit ts should parse");

    let event = committed_metric_for_commit(&metrics_db_path, &commit.commit_sha);
    assert_eq!(
        sparse_u64(&event.values, committed_pos::AUTHOR_TS),
        Some(expected_author_ts)
    );
    assert_eq!(
        sparse_u64(&event.values, committed_pos::COMMIT_TS),
        Some(expected_commit_ts)
    );
    let patch_id = sparse_str(&event.values, committed_pos::PATCH_ID).expect("patch id");
    assert!(looks_like_patch_id(patch_id), "patch_id={patch_id}");

    let mut file = repo.filename("generated.txt");
    file.assert_committed_lines(lines!["base".unattributed_human(), "ai line".ai()]);
}

#[cfg(unix)]
#[test]
fn codex_commit_is_durably_bound_before_daemon_restart_when_delivery_is_offline() {
    let (_metrics_db_dir, metrics_db_path) = isolated_metrics_db_path();
    let delivery_dir = tempfile::tempdir().expect("failed to create delivery config dir");
    let policy_path = delivery_dir.path().join("trackai-delivery-policy.json");
    let keyring_path = delivery_dir.path().join("trackai-machine-credentials.json");
    let repository_url = "https://github.com/example/task9f-offline-delivery";
    let tenant_id = "11111111-1111-4111-8111-111111111111";
    let key_id = "abcdefghijklmnop";
    let synthetic_credential = format!("trk_v1.{key_id}.{}", "A".repeat(43));
    let api_base_url = "http://127.0.0.1:1".to_string();

    fs::write(
        &policy_path,
        json!({
            "version": 1,
            "repositories": [{
                "repository_url": repository_url,
                "tenant_id": tenant_id,
                "api_base_url": api_base_url,
                "credential_key_id": key_id,
            }],
        })
        .to_string(),
    )
    .expect("failed to write delivery policy");
    fs::write(
        &keyring_path,
        json!({
            "version": 1,
            "credentials": [synthetic_credential],
        })
        .to_string(),
    )
    .expect("failed to write synthetic credential adapter");
    fs::set_permissions(&keyring_path, fs::Permissions::from_mode(0o600))
        .expect("failed to restrict synthetic credential adapter");

    let policy_path_string = policy_path.to_string_lossy().into_owned();
    let keyring_path_string = keyring_path.to_string_lossy().into_owned();
    let daemon_env = [
        ("GIT_AI_TEST_METRICS_DB_PATH", metrics_db_path.as_str()),
        (
            "GIT_AI_TRACKAI_DELIVERY_POLICY_PATH",
            policy_path_string.as_str(),
        ),
        (
            "GIT_AI_TRACKAI_CREDENTIAL_KEYRING_PATH",
            keyring_path_string.as_str(),
        ),
    ];
    let mut repo = TestRepo::new_with_daemon_env(&daemon_env);
    repo.git(&["remote", "add", "origin", repository_url])
        .expect("synthetic allowlisted remote should be configured");

    let file_path = repo.path().join("generated.txt");
    fs::write(&file_path, "base\n").expect("failed to write baseline");
    repo.stage_all_and_commit("Initial commit")
        .expect("initial commit should succeed while delivery is offline");

    codex_checkpoint(
        &repo,
        &file_path,
        "task9f-offline-session",
        "PreToolUse",
        "task9f-offline-tool",
    );
    fs::write(&file_path, "base\nai line\n").expect("failed to write AI edit");
    codex_checkpoint(
        &repo,
        &file_path,
        "task9f-offline-session",
        "PostToolUse",
        "task9f-offline-tool",
    );

    let commit = repo
        .stage_all_and_commit("AI commit while TrackAI is offline")
        .expect("Git activity must not be blocked by delivery failure");
    assert!(
        repo.read_authorship_note(&commit.commit_sha).is_some(),
        "Codex-attributed commit should retain its authorship note"
    );

    let row = || {
        let connection =
            rusqlite::Connection::open(&metrics_db_path).expect("metrics database should reopen");
        connection
            .query_row(
                "SELECT id, delivery_tenant_id, delivery_repository_url, delivery_api_base_url, \
                        delivery_credential_key_id, attempts, delivered_ts, quarantined_at, \
                        last_sync_error \
                 FROM metrics \
                 WHERE event_kind = 1 AND event_json LIKE ?1 \
                 ORDER BY id DESC LIMIT 1",
                [format!("%{}%", commit.commit_sha)],
                |record| {
                    Ok((
                        record.get::<_, i64>(0)?,
                        record.get::<_, Option<String>>(1)?,
                        record.get::<_, Option<String>>(2)?,
                        record.get::<_, Option<String>>(3)?,
                        record.get::<_, Option<String>>(4)?,
                        record.get::<_, u32>(5)?,
                        record.get::<_, Option<u64>>(6)?,
                        record.get::<_, Option<u64>>(7)?,
                        record.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .ok()
    };

    let failure_deadline = Instant::now() + Duration::from_secs(10);
    let before_restart = loop {
        if let Some(record) = row()
            && record.8.is_some()
        {
            break record;
        }
        assert!(
            Instant::now() < failure_deadline,
            "committed metric should be inserted and record the offline retry"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(before_restart.1.as_deref(), Some(tenant_id));
    assert_eq!(before_restart.2.as_deref(), Some(repository_url));
    assert_eq!(before_restart.3.as_deref(), Some(api_base_url.as_str()));
    assert_eq!(before_restart.4.as_deref(), Some(key_id));
    assert!(before_restart.5 < 6, "offline row must remain retryable");
    assert_eq!(
        before_restart.6, None,
        "offline row must remain undelivered"
    );
    assert_eq!(
        before_restart.7, None,
        "offline row must not be quarantined"
    );

    for sqlite_path in [
        metrics_db_path.clone(),
        format!("{metrics_db_path}-wal"),
        format!("{metrics_db_path}-shm"),
    ] {
        if let Ok(bytes) = fs::read(sqlite_path) {
            assert!(
                !bytes
                    .windows(synthetic_credential.len())
                    .any(|window| window == synthetic_credential.as_bytes()),
                "SQLite must never contain the reusable credential"
            );
        }
    }

    repo.restart_dedicated_daemon_with_env_for_test(&daemon_env);
    let after_restart = row().expect("queued committed metric should survive daemon restart");
    assert_eq!(after_restart.0, before_restart.0);
    assert_eq!(after_restart.1, before_restart.1);
    assert_eq!(after_restart.2, before_restart.2);
    assert_eq!(after_restart.3, before_restart.3);
    assert_eq!(after_restart.4, before_restart.4);
    assert_eq!(after_restart.6, None);
    assert_eq!(after_restart.7, None);
}

#[test]
fn deletion_only_git_revert_emits_rewrite_metric_without_authorship_note() {
    let (_metrics_db_dir, metrics_db_path) = isolated_metrics_db_path();
    let repo = TestRepo::new_with_daemon_env(&[
        ("GIT_AI_TEST_METRICS_DB_PATH", metrics_db_path.as_str()),
        ("GIT_AI_REWRITE_METRICS_EVENTS", "true"),
        ("GIT_AI_DEBUG_DAEMON_TRACE", "1"),
    ]);

    let file_path = repo.path().join("revert-delete-only.txt");
    fs::write(&file_path, "base\n").unwrap();
    repo.stage_all_and_commit("base commit")
        .expect("base commit should succeed");

    fs::write(&file_path, "base\nai line removed by revert\n").unwrap();
    repo.git_ai(&["checkpoint", "mock_ai", "revert-delete-only.txt"])
        .expect("AI checkpoint should succeed");
    let source = repo
        .stage_all_and_commit("add AI line")
        .expect("AI source commit should succeed")
        .commit_sha;

    repo.git(&["revert", "--no-edit", &source])
        .expect("deletion-only revert should succeed");
    repo.sync_daemon_force();
    let revert = repo
        .git(&["rev-parse", "HEAD"])
        .expect("revert HEAD should resolve")
        .trim()
        .to_string();

    let event = rewrite_metric_for_commit(&repo, &metrics_db_path, &revert);
    assert_eq!(
        sparse_str(&event.values, rewrite_committed_pos::OPERATION_KIND),
        Some("revert")
    );
    assert_eq!(
        sparse_u64(&event.values, rewrite_committed_pos::GIT_DIFF_ADDED_LINES),
        Some(0)
    );
    assert_eq!(
        sparse_u64(&event.values, rewrite_committed_pos::GIT_DIFF_DELETED_LINES),
        Some(1)
    );
}
