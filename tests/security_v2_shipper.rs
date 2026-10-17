//! IT-T20e-01: real pinned Numbat -> Endpoint queue -> local v2 receiver.
//!
//! This is ignored by default because the caller must first build the pinned
//! Numbat binary and provide its absolute path in `TRACKAI_NUMBAT_BIN`.

#[path = "support/security_v2_schema.rs"]
mod security_v2_schema;

use chrono::{NaiveDate, TimeZone, Utc};
use git_ai::metrics::delivery::MetricDeliveryHealthBinding;
use git_ai::security::activation::{LeaseSnapshot, SecurityLeaseContext};
use git_ai::security::delivery::flush_security_records_with;
use git_ai::security::delivery_queue::SecurityRecordQueue;
use git_ai::security::records::{PermissionJoinTracker, SecurityDataSettings};
use git_ai::security::shipper::poll_security_records;
use git_ai::security::tail::rotate_if_due;
use security_v2_schema::validates;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

struct Lease;

impl SecurityLeaseContext for Lease {
    fn current(&self) -> Option<LeaseSnapshot> {
        Some(LeaseSnapshot {
            lease_id: "lease-it-t20e-01".into(),
            bundle_digest: "a".repeat(64),
            issued_at: Utc.timestamp_opt(0, 0).unwrap(),
            expires_at: Utc.timestamp_opt(4_102_444_800, 0).unwrap(),
            data_settings: SecurityDataSettings {
                command_previews: true,
                file_paths: true,
                urls: true,
                host_identity: false,
                user_identity: false,
            },
        })
    }

    fn issued(&self, _lease_id: &str) -> Option<LeaseSnapshot> {
        self.current()
    }
}

fn run_hook(binary: &Path, home: &Path, records: &Path, fixture: &Path) {
    let mut child = Command::new(binary)
        .args([
            "hook",
            "PreToolUse",
            "--agent",
            "claude",
            "--emit",
            "all",
            "--output",
            "file",
            "--output-file",
        ])
        .arg(records)
        .current_dir(home)
        .env_clear()
        .env("HOME", home)
        .env("TMPDIR", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(fixture).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "pinned Numbat hook failed with status {:?}",
        output.status.code()
    );
    assert!(records.is_file(), "pinned Numbat file sink was not created");
}

fn receive(listener: &TcpListener, schema: &Value) -> Vec<String> {
    let (mut stream, _) = listener.accept().unwrap();
    let body = read_http_body(&stream);
    let upload: Value = serde_json::from_slice(&body).unwrap();
    assert!(validates(schema, &upload));
    let records = upload["records"].as_array().unwrap();
    let record_ids = records
        .iter()
        .map(|record| record["record_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let results = records
        .iter()
        .map(|record| {
            serde_json::json!({
                "record_id": record["record_id"],
                "result": "accepted"
            })
        })
        .collect::<Vec<_>>();
    let response_body = serde_json::json!({
        "schema_version":"trackai.security-upload-result/2",
        "results": results
    })
    .to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
    .unwrap();
    record_ids
}

fn read_http_body(stream: &TcpStream) -> Vec<u8> {
    let mut reader = BufReader::new(stream);
    let mut content_length = None;
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    assert_eq!(
        request_line,
        "POST /worker/security/v2/records HTTP/1.1\r\n"
    );
    let mut has_machine_credential = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = Some(value.trim().parse::<usize>().unwrap());
        }
        if line.to_ascii_lowercase().starts_with("x-api-key:") {
            has_machine_credential = true;
        }
    }
    assert!(has_machine_credential);
    let mut body = vec![0; content_length.unwrap()];
    reader.read_exact(&mut body).unwrap();
    body
}

#[test]
#[ignore = "requires TRACKAI_NUMBAT_BIN built from packaging/numbat/build.sh"]
fn it_t20e_01_real_numbat_restart_rotation_and_local_receiver() {
    let binary = std::env::var_os("TRACKAI_NUMBAT_BIN")
        .map(std::path::PathBuf::from)
        .expect("set TRACKAI_NUMBAT_BIN to the pinned Numbat binary");
    assert!(binary.is_absolute() && binary.is_file());

    let temp = tempfile::TempDir::new().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let records = temp.path().join("records.ndjson");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    run_hook(
        &binary,
        &home,
        &records,
        &manifest.join("packaging/numbat/fixtures/claude-pretooluse-benign.json"),
    );
    run_hook(
        &binary,
        &home,
        &records,
        &manifest.join("packaging/numbat/fixtures/claude-pretooluse-match.json"),
    );

    let schema: Value = serde_json::from_slice(
        &std::fs::read(manifest.join("tests/fixtures/security_v2/security-upload-v2.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_base_url = format!("http://{}", listener.local_addr().unwrap());
    let receiver = thread::spawn(move || {
        let first = receive(&listener, &schema);
        let second = receive(&listener, &schema);
        let mut unique = std::collections::HashSet::new();
        assert!(
            first
                .iter()
                .chain(&second)
                .all(|id| unique.insert(id.clone()))
        );
        (first.len(), second.len())
    });
    let binding = MetricDeliveryHealthBinding {
        tenant_id: "tenant-it-t20e-01".into(),
        api_base_url,
        credential_key_id: "ABCDEFGHIJKLMNOP".into(),
    };
    let database = temp.path().join("security.db");
    let mut queue = SecurityRecordQueue::open_at_path(&database).unwrap();
    poll_security_records(
        &records,
        &mut queue,
        &Lease,
        Some(&binding),
        &HashMap::new(),
        &mut PermissionJoinTracker::default(),
        1,
    )
    .unwrap();
    let first = flush_security_records_with(
        &mut queue,
        &Lease,
        1,
        |_| Some("local-test-credential".into()),
        git_ai::security::delivery::upload_security_records,
    )
    .unwrap();
    assert!(first.delivered > 0);

    let checkpoint = queue.checkpoint().unwrap();
    let rotated = rotate_if_due(
        &records,
        &git_ai::security::tail::TailCheckpoint {
            last_rotation_local_date: Some(NaiveDate::from_ymd_opt(2026, 10, 16).unwrap()),
            ..checkpoint
        },
        NaiveDate::from_ymd_opt(2026, 10, 17).unwrap(),
        NaiveDate::from_ymd_opt(2026, 10, 17).unwrap(),
    )
    .unwrap();
    assert!(rotated.is_some());
    run_hook(
        &binary,
        &home,
        &records,
        &manifest.join("packaging/numbat/fixtures/claude-pretooluse-match.json"),
    );

    drop(queue);
    let mut restarted = SecurityRecordQueue::open_at_path(&database).unwrap();
    poll_security_records(
        &records,
        &mut restarted,
        &Lease,
        Some(&binding),
        &HashMap::new(),
        &mut PermissionJoinTracker::default(),
        2,
    )
    .unwrap();
    let second = flush_security_records_with(
        &mut restarted,
        &Lease,
        2,
        |_| Some("local-test-credential".into()),
        git_ai::security::delivery::upload_security_records,
    )
    .unwrap();
    assert!(second.delivered > 0);

    poll_security_records(
        &records,
        &mut restarted,
        &Lease,
        Some(&binding),
        &HashMap::new(),
        &mut PermissionJoinTracker::default(),
        3,
    )
    .unwrap();
    assert_eq!(
        flush_security_records_with(
            &mut restarted,
            &Lease,
            3,
            |_| Some("local-test-credential".into()),
            git_ai::security::delivery::upload_security_records,
        )
        .unwrap()
        .delivered,
        0
    );

    let (received_first, received_second) = receiver.join().unwrap();
    assert_eq!(received_first, first.delivered);
    assert_eq!(received_second, second.delivered);
}
