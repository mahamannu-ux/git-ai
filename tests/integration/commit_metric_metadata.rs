use crate::repos::test_file::ExpectedLineExt;
use crate::repos::test_repo::TestRepo;
use git_ai::metrics::MetricEvent;
use git_ai::metrics::attrs::attr_pos;
use git_ai::metrics::db::MetricsDatabase;
use git_ai::metrics::events::{committed_pos, rewrite_committed_pos};
use git_ai::metrics::types::{MetricEventId, SparseArray};
use serde_json::json;
use std::fs;
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
