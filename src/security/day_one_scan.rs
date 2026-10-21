//! Once-per-enrolment, lease-gated Numbat scan of managed agent artifacts.

use crate::error::GitAiError;
use crate::metrics::delivery::MetricDeliveryHealthBinding;
use crate::security::activation::{SecurityLeaseContext, configured_lease_context};
use crate::security::delivery_queue::SecurityRecordQueue;
use crate::security::lease_state::LeaseStateStore;
use crate::security::policy_apply::{MANAGED_AGENT_MAP, NUMBAT_ADMIN_BINARY};
use crate::security::records::{PermissionJoinTracker, project_numbat_record, record_id};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant};

const RETRY_SECONDS: i64 = 3_600;
const AGENT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
static RUNNING: AtomicBool = AtomicBool::new(false);
static NEXT_ATTEMPT_AT: AtomicI64 = AtomicI64::new(0);

#[derive(Serialize, Deserialize)]
struct DoneMarker {
    tenant_id: String,
    machine_id: String,
    bundle_digest: String,
    at: DateTime<Utc>,
}

fn managed_agents() -> impl Iterator<Item = (&'static str, &'static str)> {
    MANAGED_AGENT_MAP.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        Some((fields.next()?, fields.next()?))
    })
}

fn applied_rules(security_dir: &Path, digest: &str) -> bool {
    let Some(prefix) = digest.get(..12) else {
        return false;
    };
    fs::read_link(security_dir.join("rules/current"))
        .ok()
        .and_then(|target| {
            target
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .is_some_and(|name| name != "placeholder" && name.ends_with(prefix))
}

fn done_for(path: &Path, tenant_id: &str, machine_id: &str) -> bool {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<DoneMarker>(&bytes).ok())
        .is_some_and(|marker| marker.tenant_id == tenant_id && marker.machine_id == machine_id)
}

fn write_done(path: &Path, marker: &DoneMarker) -> Result<(), GitAiError> {
    let tmp = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(&serde_json::to_vec(marker)?)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn scan_command(
    binary: &Path,
    security_dir: &Path,
    agent: &str,
    source: &str,
    output: &Path,
) -> Command {
    let mut command = Command::new(binary);
    command
        .args([
            "scan",
            "--agent",
            agent,
            "--emit",
            "findings",
            "--rules-dir",
        ])
        .arg(security_dir.join("rules/current").join(source))
        .args(["--output", "file", "--output-file"])
        .arg(output)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

enum AgentRun {
    Success,
    Nonzero,
    Interrupted,
}

fn run_agent(
    binary: &Path,
    security_dir: &Path,
    agent: (&str, &str),
    output: &Path,
    timeout: Duration,
    context: &LeaseStateStore,
    lease_id: &str,
) -> Result<AgentRun, GitAiError> {
    let diagnostics = output.with_extension("stderr.ndjson");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let stderr = options.open(&diagnostics)?;
    let mut command = scan_command(binary, security_dir, agent.0, agent.1, output);
    let mut child = command.stderr(Stdio::from(stderr)).spawn()?;
    let started = Instant::now();
    loop {
        if context
            .lease_at(Utc::now())
            .as_ref()
            .map(|lease| lease.lease_id.as_str())
            != Some(lease_id)
            || started.elapsed() >= timeout
        {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(AgentRun::Interrupted);
        }
        if let Some(status) = child.try_wait()? {
            return Ok(if status.success() {
                AgentRun::Success
            } else {
                AgentRun::Nonzero
            });
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn no_artifacts_summary(output: &Path, diagnostics: &Path, agent: &str) -> bool {
    let Ok(file) = fs::File::open(output) else {
        return false;
    };
    let mut lines = BufReader::new(file).lines();
    let Some(Ok(line)) = lines.next() else {
        return false;
    };
    let Ok(summary) = serde_json::from_str::<Value>(&line) else {
        return false;
    };
    if lines.next().is_some()
        || summary.get("record_type").and_then(Value::as_str) != Some("scan_summary")
        || summary.get("status").and_then(Value::as_str) != Some("error")
        || summary.get("artifacts_scanned").and_then(Value::as_u64) != Some(0)
        || summary.get("findings_emitted").and_then(Value::as_u64) != Some(0)
    {
        return false;
    }

    // Numbat@20a5a52:internal/output/output.go:228-242 sends file-sink
    // diagnostics to stderr, separately from the scan_summary file record.
    let Ok(file) = fs::File::open(diagnostics) else {
        return false;
    };
    let mut lines = BufReader::new(file).lines();
    let Some(Ok(line)) = lines.next() else {
        return false;
    };
    let Ok(diagnostic) = serde_json::from_str::<Value>(&line) else {
        return false;
    };
    lines.next().is_none()
        && diagnostic.get("record_type").and_then(Value::as_str) == Some("diagnostic")
        && diagnostic
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| {
                message.starts_with(&format!("no agent artifacts found for --agent {agent} "))
            })
}

fn queue_scan_file(
    path: &Path,
    queue: &SecurityRecordQueue,
    binding: &MetricDeliveryHealthBinding,
    context: &LeaseStateStore,
    lease_id: &str,
    identity: (&str, &str, &str),
) -> Result<bool, GitAiError> {
    let file = fs::File::open(path)?;
    let mut saw_summary = false;
    let mut joins = PermissionJoinTracker::default();
    for line in BufReader::new(file).lines() {
        let line = line?;
        let raw: Value = serde_json::from_str(&line)?;
        let kind = raw.get("record_type").and_then(Value::as_str);
        if !matches!(kind, Some("finding" | "scan_summary")) {
            continue;
        }
        let Some(lease) = context.lease_at(Utc::now()) else {
            return Ok(false);
        };
        if lease.lease_id != lease_id {
            return Ok(false);
        }
        let Some(mut projected) = project_numbat_record(
            line.as_bytes(),
            &lease,
            &Default::default(),
            &mut joins,
            true,
        ) else {
            continue;
        };
        if kind == Some("scan_summary") {
            saw_summary = true;
            // Numbat creates a fresh run_id on retry. This key keeps the summary
            // idempotent if another agent fails after this one was queued.
            let id = record_id("scan_summary", &[identity.0, identity.1, identity.2]);
            projected.record_id = id.clone();
            projected.json["record_id"] = Value::String(id);
        }
        queue.enqueue_generated(&projected, binding, Utc::now().timestamp().max(0) as u64)?;
    }
    Ok(saw_summary)
}

fn run_once(
    binary: &Path,
    internal_dir: &Path,
    context: &LeaseStateStore,
    binding: &MetricDeliveryHealthBinding,
    timeout: Duration,
) -> Result<(), GitAiError> {
    let now = Utc::now();
    let Some(lease) = context.lease_at(now) else {
        return Ok(());
    };
    let state = context.snapshot();
    let (Some(tenant_id), Some(machine_id)) = (state.enrolled_tenant_id, state.enrolled_machine_id)
    else {
        return Ok(());
    };
    if binding.tenant_id != tenant_id
        || !state
            .accepted_leases
            .iter()
            .any(|accepted| accepted.lease_id == lease.lease_id && accepted.day_one_scan)
    {
        return Ok(());
    }
    let security_dir = internal_dir.join("security");
    let marker = security_dir.join("day-one-scan-done");
    if done_for(&marker, &tenant_id, &machine_id)
        || !applied_rules(&security_dir, &lease.bundle_digest)
    {
        return Ok(());
    }
    let tmp_dir = security_dir.join("scan-tmp");
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(&tmp_dir)?;
    #[cfg(unix)]
    fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o700))?;
    let queue = SecurityRecordQueue::open_at_path(&internal_dir.join("security-findings.db"))?;
    let mut all_ok = true;
    for (agent, source) in managed_agents() {
        let output = tmp_dir.join(format!("{agent}.ndjson"));
        let diagnostics = output.with_extension("stderr.ndjson");
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&diagnostics);
        let result = run_agent(
            binary,
            &security_dir,
            (agent, source),
            &output,
            timeout,
            context,
            &lease.lease_id,
        )
        .and_then(|result| {
            if matches!(result, AgentRun::Success)
                || matches!(result, AgentRun::Nonzero)
                    && no_artifacts_summary(&output, &diagnostics, agent)
            {
                queue_scan_file(
                    &output,
                    &queue,
                    binding,
                    context,
                    &lease.lease_id,
                    (&tenant_id, &machine_id, agent),
                )
            } else {
                Ok(false)
            }
        });
        let _ = fs::remove_file(&output);
        let _ = fs::remove_file(&diagnostics);
        match result {
            Ok(true) => {}
            Ok(false) => all_ok = false,
            Err(error) => {
                tracing::warn!(%error, agent, "day-one agent scan failed");
                all_ok = false;
            }
        }
        if context
            .lease_at(Utc::now())
            .as_ref()
            .map(|active| active.lease_id.as_str())
            != Some(&lease.lease_id)
        {
            return Ok(());
        }
    }
    if all_ok
        && context
            .lease_at(Utc::now())
            .as_ref()
            .map(|active| active.lease_id.as_str())
            == Some(&lease.lease_id)
    {
        write_done(
            &marker,
            &DoneMarker {
                tenant_id,
                machine_id,
                bundle_digest: lease.bundle_digest,
                at: Utc::now(),
            },
        )?;
    }
    Ok(())
}

pub fn spawn_if_due() {
    let now = Utc::now();
    let context = configured_lease_context();
    let Some(lease) = context.lease_at(now) else {
        return;
    };
    if !context
        .snapshot()
        .accepted_leases
        .iter()
        .any(|accepted| accepted.lease_id == lease.lease_id && accepted.day_one_scan)
        || now.timestamp() < NEXT_ATTEMPT_AT.load(Ordering::Relaxed)
        || RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    NEXT_ATTEMPT_AT.store(
        now.timestamp().saturating_add(RETRY_SECONDS),
        Ordering::Relaxed,
    );
    std::mem::drop(tokio::task::spawn_blocking(|| {
        let result = (|| {
            let binding = crate::metrics::delivery::MetricDeliveryRuntime::load_optional_default()
                .ok()
                .flatten()
                .and_then(|runtime| runtime.fleet_binding().ok());
            let Some(binding) = binding else {
                return Ok(());
            };
            let config = crate::daemon::DaemonConfig::from_env_or_default_paths()?;
            run_once(
                Path::new(NUMBAT_ADMIN_BINARY),
                &config.internal_dir,
                configured_lease_context(),
                &binding,
                AGENT_TIMEOUT,
            )
        })();
        if let Err(error) = result {
            tracing::warn!(%error, "day-one scan failed");
        }
        RUNNING.store(false, Ordering::Release);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::lease_state::{AcceptedLease, DurableSecurityState, LeaseMode};
    use crate::security::records::SecurityDataSettings;
    use chrono::TimeZone;

    fn state(now: DateTime<Utc>, mode: LeaseMode, opt_in: bool) -> DurableSecurityState {
        DurableSecurityState {
            enrolled_tenant_id: Some("tenant-a".into()),
            enrolled_machine_id: Some("machine-a".into()),
            accepted_leases: vec![AcceptedLease {
                lease_id: "lease-a".into(),
                bundle_digest: "a".repeat(64),
                issued_at: now - chrono::Duration::minutes(1),
                expires_at: now + chrono::Duration::hours(1),
                data_settings: SecurityDataSettings::ALL_OFF,
                mode,
                agents: vec!["codex".into()],
                day_one_scan: opt_in,
                signed_bytes: Vec::new(),
            }],
            ..Default::default()
        }
    }

    fn binding() -> MetricDeliveryHealthBinding {
        MetricDeliveryHealthBinding {
            tenant_id: "tenant-a".into(),
            api_base_url: "https://trackai.example".into(),
            credential_key_id: "credential".into(),
        }
    }

    #[test]
    fn marker_is_tenant_machine_scoped_and_placeholder_is_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let security = tmp.path();
        fs::create_dir_all(security.join("rules")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("placeholder", security.join("rules/current")).unwrap();
        assert!(!applied_rules(security, &"a".repeat(64)));
        let marker = security.join("day-one-scan-done");
        assert!(!done_for(&marker, "tenant-a", "machine-a"));
        write_done(
            &marker,
            &DoneMarker {
                tenant_id: "tenant-a".into(),
                machine_id: "machine-a".into(),
                bundle_digest: "a".repeat(64),
                at: Utc.timestamp_opt(1, 0).unwrap(),
            },
        )
        .unwrap();
        assert!(done_for(&marker, "tenant-a", "machine-a"));
        assert!(!done_for(&marker, "tenant-b", "machine-a"));
        assert!(!done_for(&marker, "tenant-a", "machine-b"));
    }

    #[test]
    fn no_lease_off_lease_and_placeholder_never_start_a_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let security = tmp.path().join("security");
        fs::create_dir_all(security.join("rules")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("placeholder", security.join("rules/current")).unwrap();
        let now = Utc::now();
        for snapshot in [
            DurableSecurityState::default(),
            state(now, LeaseMode::Off, true),
            state(now, LeaseMode::Monitor, true),
        ] {
            let context = LeaseStateStore::from_state(&security, snapshot);
            run_once(
                Path::new("/nonexistent/numbat"),
                tmp.path(),
                &context,
                &binding(),
                Duration::from_millis(1),
            )
            .unwrap();
            assert!(!security.join("day-one-scan-done").exists());
            assert!(!security.join("scan-tmp").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn marker_follows_all_queued_summaries_and_prevents_a_second_run() {
        let tmp = tempfile::tempdir().unwrap();
        let security = tmp.path().join("security");
        let rules = security.join("rules");
        fs::create_dir_all(rules.join("1-aaaaaaaaaaaa")).unwrap();
        std::os::unix::fs::symlink("1-aaaaaaaaaaaa", rules.join("current")).unwrap();
        let fake = tmp.path().join("fake-numbat");
        fs::write(&fake, "#!/bin/sh\nfor arg do output=$arg; done\nprintf '%s\\n' '{\"schema_version\":\"0.5.0\",\"record_type\":\"scan_summary\",\"run_id\":\"run-test\",\"status\":\"complete\",\"artifacts_scanned\":1,\"events_emitted\":0,\"findings_emitted\":0,\"indicators_emitted\":0,\"diagnostics\":0}' > \"$output\"\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let context =
            LeaseStateStore::from_state(&security, state(Utc::now(), LeaseMode::Monitor, true));
        run_once(
            &fake,
            tmp.path(),
            &context,
            &binding(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(security.join("day-one-scan-done").exists());
        let database = rusqlite::Connection::open(tmp.path().join("security-findings.db")).unwrap();
        let count: i64 = database
            .query_row("SELECT count(*) FROM security_record_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 5);
        run_once(
            Path::new("/nonexistent/numbat"),
            tmp.path(),
            &context,
            &binding(),
            Duration::from_secs(1),
        )
        .unwrap();
        let count_after: i64 = database
            .query_row("SELECT count(*) FROM security_record_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count_after, 5);
        assert_eq!(fs::read_dir(security.join("scan-tmp")).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn failed_agent_leaves_marker_unwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let security = tmp.path().join("security");
        let rules = security.join("rules");
        fs::create_dir_all(rules.join("1-aaaaaaaaaaaa")).unwrap();
        std::os::unix::fs::symlink("1-aaaaaaaaaaaa", rules.join("current")).unwrap();
        let fake = tmp.path().join("fake-numbat");
        fs::write(&fake, "#!/bin/sh\n[ \"$3\" = codex ] && exit 2\nfor arg do output=$arg; done\nprintf '%s\\n' '{\"schema_version\":\"0.5.0\",\"record_type\":\"scan_summary\",\"run_id\":\"run-test\",\"status\":\"complete\",\"artifacts_scanned\":1,\"events_emitted\":0,\"findings_emitted\":0,\"indicators_emitted\":0,\"diagnostics\":0}' > \"$output\"\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let context =
            LeaseStateStore::from_state(&security, state(Utc::now(), LeaseMode::Monitor, true));
        run_once(
            &fake,
            tmp.path(),
            &context,
            &binding(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(!security.join("day-one-scan-done").exists());
        assert_eq!(fs::read_dir(security.join("scan-tmp")).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn no_artifacts_exit_queues_error_summary_and_completes() {
        let tmp = tempfile::tempdir().unwrap();
        let security = tmp.path().join("security");
        let rules = security.join("rules");
        fs::create_dir_all(rules.join("1-aaaaaaaaaaaa")).unwrap();
        std::os::unix::fs::symlink("1-aaaaaaaaaaaa", rules.join("current")).unwrap();
        let fake = tmp.path().join("fake-numbat");
        fs::write(&fake, concat!(
            "#!/bin/sh\n",
            "for arg do output=$arg; done\n",
            "if [ \"$3\" = codex ]; then\n",
            "  printf '%s\\n' '{\"record_type\":\"diagnostic\",\"message\":\"no agent artifacts found for --agent codex under home\"}' >&2\n",
            "  printf '%s\\n' '{\"schema_version\":\"0.5.0\",\"record_type\":\"scan_summary\",\"run_id\":\"run-empty\",\"status\":\"error\",\"artifacts_scanned\":0,\"events_emitted\":0,\"findings_emitted\":0,\"indicators_emitted\":0,\"diagnostics\":1}' > \"$output\"\n",
            "  exit 1\n",
            "fi\n",
            "printf '%s\\n' '{\"schema_version\":\"0.5.0\",\"record_type\":\"scan_summary\",\"run_id\":\"run-test\",\"status\":\"complete\",\"artifacts_scanned\":1,\"events_emitted\":0,\"findings_emitted\":0,\"indicators_emitted\":0,\"diagnostics\":0}' > \"$output\"\n"
        )).unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let context =
            LeaseStateStore::from_state(&security, state(Utc::now(), LeaseMode::Monitor, true));
        run_once(
            &fake,
            tmp.path(),
            &context,
            &binding(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(security.join("day-one-scan-done").exists());
        assert_eq!(fs::read_dir(security.join("scan-tmp")).unwrap().count(), 0);
        let database = rusqlite::Connection::open(tmp.path().join("security-findings.db")).unwrap();
        let count: i64 = database
            .query_row("SELECT count(*) FROM security_record_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 5);
    }

    #[cfg(unix)]
    #[test]
    fn timed_out_agent_is_interrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let fake = tmp.path().join("slow-numbat");
        fs::write(&fake, "#!/bin/sh\nsleep 2\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let security = tmp.path().join("security");
        fs::create_dir_all(&security).unwrap();
        let context =
            LeaseStateStore::from_state(&security, state(Utc::now(), LeaseMode::Monitor, true));
        let result = run_agent(
            &fake,
            &security,
            ("codex", "codex"),
            &security.join("scan.ndjson"),
            Duration::from_millis(1),
            &context,
            "lease-a",
        )
        .unwrap();
        assert!(matches!(result, AgentRun::Interrupted));
        assert!(!security.join("scan.ndjson").exists());
    }

    #[test]
    fn commands_use_only_managed_parser_agents_and_builtin_rules() {
        let agents = managed_agents().collect::<Vec<_>>();
        assert_eq!(
            agents,
            vec![
                ("claude", "claude-code"),
                ("codex", "codex"),
                ("cursor", "cursor"),
                ("gemini", "gemini-cli"),
                ("copilot", "copilot")
            ]
        );
        for (agent, source) in agents {
            let command = scan_command(
                Path::new("numbat"),
                Path::new("security"),
                agent,
                source,
                Path::new("scan.ndjson"),
            );
            let args = command
                .get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(args.contains(&"findings".to_string()));
            assert!(!args.contains(&"--no-builtin-rules".to_string()));
            assert!(!args.contains(&"events".to_string()));
        }
    }

    #[test]
    fn only_no_artifacts_nonzero_result_can_queue_its_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let output = tmp.path().join("scan.ndjson");
        let diagnostics = tmp.path().join("scan.stderr.ndjson");
        fs::write(&output, "{\"record_type\":\"scan_summary\",\"status\":\"error\",\"artifacts_scanned\":0,\"findings_emitted\":0}\n").unwrap();
        fs::write(&diagnostics, "{\"record_type\":\"diagnostic\",\"message\":\"no agent artifacts found for --agent cursor under home\"}\n").unwrap();
        assert!(no_artifacts_summary(&output, &diagnostics, "cursor"));
        assert!(!no_artifacts_summary(&output, &diagnostics, "codex"));
        fs::write(
            &diagnostics,
            "{\"record_type\":\"diagnostic\",\"message\":\"rule engine failed\"}\n",
        )
        .unwrap();
        assert!(!no_artifacts_summary(&output, &diagnostics, "cursor"));
        fs::write(&output, "{\"record_type\":\"finding\"}\n{\"record_type\":\"scan_summary\",\"status\":\"error\",\"artifacts_scanned\":0,\"findings_emitted\":0}\n").unwrap();
        assert!(!no_artifacts_summary(&output, &diagnostics, "cursor"));
    }
}
