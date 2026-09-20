use crate::api::ApiContext;
use crate::authorship::authorship_log_serialization::generate_session_id;
use crate::error::GitAiError;
use crate::evidence::OpenCodeEvidenceBatch;
use crate::metrics::delivery::MetricDeliveryRuntime;
use crate::streams::agent::get_agent;
use crate::streams::watermark::{TimestampWatermark, WatermarkStrategy};
use chrono::{DateTime, Utc};
use std::path::PathBuf;

struct SyncArguments {
    database: PathBuf,
    external_session_id: String,
    repository_url: String,
}

pub fn handle_evidence(args: &[String]) {
    if matches!(
        args.first().map(String::as_str),
        None | Some("help" | "--help" | "-h")
    ) {
        print_help();
        return;
    }
    if args.first().map(String::as_str) != Some("sync-opencode") {
        eprintln!("error: expected `git-ai evidence sync-opencode`");
        std::process::exit(2);
    }
    let arguments = match parse_sync_arguments(&args[1..]) {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    match sync_opencode(arguments) {
        Ok((batches, events)) => {
            println!(
                "OpenCode evidence sync completed: {batches} batches, {events} events accepted for delivery"
            );
        }
        Err(error) => {
            eprintln!("OpenCode evidence sync failed: {error}");
            std::process::exit(1);
        }
    }
}

fn print_help() {
    eprintln!("git-ai evidence - Upload consent-gated OpenCode evidence to TrackAI");
    eprintln!();
    eprintln!("Usage:");
    eprintln!(
        "  git-ai evidence sync-opencode --database <path> --session <id> --repository-url <url>"
    );
    eprintln!();
    eprintln!(
        "Raw prompt/tool content is read from OpenCode, redacted locally, and never printed."
    );
}

fn parse_sync_arguments(args: &[String]) -> Result<SyncArguments, &'static str> {
    let mut database = None;
    let mut external_session_id = None;
    let mut repository_url = None;
    let mut index = 0;
    while index < args.len() {
        let target = match args[index].as_str() {
            "--database" => &mut database,
            "--session" => &mut external_session_id,
            "--repository-url" => &mut repository_url,
            _ => return Err("unsupported evidence sync argument"),
        };
        let Some(value) = args.get(index + 1).filter(|value| !value.trim().is_empty()) else {
            return Err("each evidence sync option requires a value");
        };
        if target.replace(value.clone()).is_some() {
            return Err("evidence sync options may be supplied only once");
        }
        index += 2;
    }
    Ok(SyncArguments {
        database: database
            .map(PathBuf::from)
            .ok_or("--database is required")?,
        external_session_id: external_session_id.ok_or("--session is required")?,
        repository_url: repository_url.ok_or("--repository-url is required")?,
    })
}

fn sync_opencode(arguments: SyncArguments) -> Result<(usize, usize), GitAiError> {
    let runtime = MetricDeliveryRuntime::load_optional_default()
        .map_err(|error| {
            GitAiError::Generic(format!(
                "TrackAI delivery configuration is unavailable: {error}"
            ))
        })?
        .ok_or_else(|| {
            GitAiError::Generic("TrackAI delivery policy is not installed".to_string())
        })?;
    sync_opencode_with_runtime(arguments, &runtime)
}

fn sync_opencode_with_runtime(
    arguments: SyncArguments,
    runtime: &MetricDeliveryRuntime,
) -> Result<(usize, usize), GitAiError> {
    sync_opencode_with_runtime_and_upload(arguments, runtime, |context, batch| {
        context
            .post_json("/worker/evidence/opencode/batches", batch)
            .map(|response| response.status_code)
    })
}

fn sync_opencode_with_runtime_and_upload<Upload>(
    arguments: SyncArguments,
    runtime: &MetricDeliveryRuntime,
    mut upload: Upload,
) -> Result<(usize, usize), GitAiError>
where
    Upload: FnMut(&ApiContext, &OpenCodeEvidenceBatch) -> Result<u16, GitAiError>,
{
    let binding = runtime
        .bind_evidence_repository(&arguments.repository_url)
        .map_err(|error| {
            GitAiError::Generic(format!(
                "TrackAI repository binding is unavailable: {error}"
            ))
        })?;
    let credential = runtime
        .credential_for_evidence_binding(&binding)
        .map_err(|error| {
            GitAiError::Generic(format!(
                "TrackAI machine credential is unavailable: {error}"
            ))
        })?
        .to_string();
    let context = ApiContext {
        base_url: binding.api_base_url.clone(),
        auth_token: None,
        api_key: Some(credential),
        author_identity: None,
        timeout_secs: Some(30),
    };
    let agent = get_agent("opencode")
        .ok_or_else(|| GitAiError::Generic("OpenCode reader is unavailable".to_string()))?;
    let git_ai_session_id = generate_session_id(&arguments.external_session_id, "opencode");
    let mut watermark: Box<dyn WatermarkStrategy> =
        Box::new(TimestampWatermark::new(DateTime::<Utc>::UNIX_EPOCH));
    let mut uploaded_batches = 0;
    let mut uploaded_events = 0;
    loop {
        let stream_batch = agent
            .read_incremental(
                &arguments.database,
                watermark,
                &arguments.external_session_id,
            )
            .map_err(|error| {
                GitAiError::Generic(format!("OpenCode evidence read failed: {error}"))
            })?;
        watermark = stream_batch.new_watermark;
        if stream_batch.events.is_empty() {
            break;
        }
        let batches = OpenCodeEvidenceBatch::from_stream_events(
            &binding.repository_id,
            &arguments.external_session_id,
            &git_ai_session_id,
            stream_batch.events,
        );
        for batch in batches {
            let event_count = batch.event_count();
            match upload(&context, &batch)? {
                202 => {
                    uploaded_batches += 1;
                    uploaded_events += event_count;
                }
                401 => {
                    return Err(GitAiError::Generic(
                        "machine credential was rejected".to_string(),
                    ));
                }
                403 => {
                    return Err(GitAiError::Generic(
                        "tenant consent or repository authorization is not active".to_string(),
                    ));
                }
                400 => {
                    return Err(GitAiError::Generic(
                        "evidence batch was rejected".to_string(),
                    ));
                }
                _ => {
                    return Err(GitAiError::Generic(
                        "evidence service is temporarily unavailable".to_string(),
                    ));
                }
            }
        }
    }
    Ok((uploaded_batches, uploaded_events))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_sync_requires_explicit_non_content_arguments() {
        let args = [
            "--database".to_string(),
            "/tmp/opencode.db".to_string(),
            "--session".to_string(),
            "session-one".to_string(),
            "--repository-url".to_string(),
            "https://github.com/example/repo".to_string(),
        ];
        let parsed = parse_sync_arguments(&args).unwrap();
        assert_eq!(parsed.external_session_id, "session-one");
        assert_eq!(parsed.repository_url, "https://github.com/example/repo");
        assert!(parse_sync_arguments(&args[..4]).is_err());
    }

    #[test]
    fn evidence_sync_reads_opencode_and_uploads_redacted_tenant_bound_batch() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("opencode.db");
        let connection = crate::sqlite::open_with_memory_limits(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE message (
                id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL
            );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO message VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    "message-one",
                    "session-one",
                    1_750_000_000_000_i64,
                    1_750_000_000_000_i64,
                    r#"{"role":"user","modelID":"model-a"}"#,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO part VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    "part-one",
                    "message-one",
                    "session-one",
                    1_750_000_000_000_i64,
                    1_750_000_000_000_i64,
                    r#"{"type":"text","text":"use sk_test_4eC39HqLyjWDarjtT1zdp7dc"}"#,
                ],
            )
            .unwrap();
        drop(connection);

        let policy_path = temp.path().join("policy.json");
        let keyring_path = temp.path().join("keyring.json");
        std::fs::write(
            &policy_path,
            serde_json::json!({
                "version": 1,
                "repositories": [{
                    "repository_url": "https://github.com/example/repo",
                    "repository_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "tenant_id": "11111111-1111-4111-8111-111111111111",
                    "api_base_url": "http://127.0.0.1:1",
                    "credential_key_id": "abcdefghijklmnop"
                }]
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(&keyring_path, serde_json::json!({
            "version": 1,
            "credentials": ["trk_v1.abcdefghijklmnop.abcdefghijklmnopqrstuvwxyzABCDEFGH123456789"]
        }).to_string()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keyring_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let runtime = MetricDeliveryRuntime::load_from_paths(&policy_path, &keyring_path).unwrap();
        let mut uploaded = Vec::new();
        let result = sync_opencode_with_runtime_and_upload(
            SyncArguments {
                database,
                external_session_id: "session-one".to_string(),
                repository_url: "https://github.com/example/repo".to_string(),
            },
            &runtime,
            |context, batch| {
                assert_eq!(context.base_url, "http://127.0.0.1:1");
                assert_eq!(
                    context.api_key.as_deref(),
                    Some("trk_v1.abcdefghijklmnop.abcdefghijklmnopqrstuvwxyzABCDEFGH123456789")
                );
                let serialized = serde_json::to_string(batch).unwrap();
                assert!(serialized.contains("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
                assert!(serialized.contains("part-one"));
                assert!(serialized.contains("********"));
                assert!(!serialized.contains("sk_test_4eC39HqLyjWDarjtT1zdp7dc"));
                uploaded.push(serialized);
                Ok(202)
            },
        )
        .unwrap();
        assert_eq!(result, (1, 1));
        assert_eq!(uploaded.len(), 1);

        let replay = sync_opencode_with_runtime_and_upload(
            SyncArguments {
                database: temp.path().join("opencode.db"),
                external_session_id: "session-one".to_string(),
                repository_url: "https://github.com/example/repo".to_string(),
            },
            &runtime,
            |_, batch| {
                let serialized = serde_json::to_string(batch).unwrap();
                assert_eq!(serialized, uploaded[0]);
                Ok(202)
            },
        )
        .unwrap();
        assert_eq!(replay, result);
    }
}
