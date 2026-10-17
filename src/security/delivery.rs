//! Security-v2 queue delivery using the existing machine credential.

use crate::api::client::ApiContext;
use crate::error::GitAiError;
use crate::metrics::delivery::{MetricDeliveryHealthBinding, MetricDeliveryRuntime};
use crate::security::activation::{SecurityLeaseContext, UNAVAILABLE_LEASE_CONTEXT};
use crate::security::delivery_queue::{QueuedSecurityRecord, SecurityRecordQueue};
use crate::security::records::minimize_queued;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MAX_RECORDS: usize = 500;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadHttpResponse {
    pub status: u16,
    pub retry_after_seconds: Option<u64>,
    pub body: String,
}

#[derive(Debug, Deserialize)]
struct ResultEnvelope {
    results: Vec<RecordResult>,
}

#[derive(Debug, Deserialize)]
struct RecordResult {
    record_id: String,
    result: String,
    code: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SecurityFlushResult {
    pub delivered: usize,
    pub dropped: usize,
    pub retrying: usize,
    pub reprojected: usize,
}

type RouteKey = (String, String, String);
type ParsedQueuedRecord = (QueuedSecurityRecord, Value);
type SecurityBatch = Vec<ParsedQueuedRecord>;

pub fn flush_security_records_with<Resolve, Upload>(
    queue: &mut SecurityRecordQueue,
    leases: &dyn SecurityLeaseContext,
    now: u64,
    mut resolve: Resolve,
    mut upload: Upload,
) -> Result<SecurityFlushResult, GitAiError>
where
    Resolve: FnMut(&MetricDeliveryHealthBinding) -> Option<String>,
    Upload:
        FnMut(&MetricDeliveryHealthBinding, &str, &Value) -> Result<UploadHttpResponse, GitAiError>,
{
    let records = queue.dequeue_pending(MAX_RECORDS, now)?;
    let mut routes = BTreeMap::<RouteKey, Vec<QueuedSecurityRecord>>::new();
    for record in records {
        let binding = &record.delivery_binding;
        routes
            .entry((
                binding.tenant_id.clone(),
                binding.api_base_url.clone(),
                binding.credential_key_id.clone(),
            ))
            .or_default()
            .push(record);
    }
    let mut summary = SecurityFlushResult::default();
    for records in routes.into_values() {
        let binding = records[0].delivery_binding.clone();
        let Some(credential) = resolve(&binding) else {
            queue.delete_counted(
                &records.iter().map(|record| record.id).collect::<Vec<_>>(),
                "credential_unavailable",
            )?;
            summary.dropped += records.len();
            continue;
        };
        let (batches, invalid_ids) = split_batches(records)?;
        if !invalid_ids.is_empty() {
            queue.delete_counted(&invalid_ids, "invalid_local_record")?;
            summary.dropped += invalid_ids.len();
        }
        for batch in batches {
            let values = batch
                .iter()
                .map(|(_, value)| value.clone())
                .collect::<Vec<_>>();
            let body = json!({"schema_version":"trackai.security-upload/2","records":values});
            let response = match upload(&binding, &credential, &body) {
                Ok(response) => response,
                Err(_) => {
                    let ids = batch
                        .iter()
                        .map(|(record, _)| record.id)
                        .collect::<Vec<_>>();
                    queue.mark_retry(&ids, "transport", now, None)?;
                    summary.retrying += ids.len();
                    continue;
                }
            };
            let problem_code = problem_code(&response.body);
            if response.status == 429 {
                let ids = batch
                    .iter()
                    .map(|(record, _)| record.id)
                    .collect::<Vec<_>>();
                queue.mark_retry(
                    &ids,
                    "SECURITY_V2_RATE_LIMITED",
                    now,
                    response.retry_after_seconds,
                )?;
                summary.retrying += ids.len();
                continue;
            }
            if response.status >= 500
                || problem_code.as_deref() == Some("SECURITY_V2_LEASE_REQUIRED")
            {
                let ids = batch
                    .iter()
                    .map(|(record, _)| record.id)
                    .collect::<Vec<_>>();
                queue.mark_retry(&ids, "SECURITY_V2_LEASE_REQUIRED", now, None)?;
                summary.retrying += ids.len();
                continue;
            }
            if response.status != 200
                && matches!(
                    problem_code.as_deref(),
                    Some(
                        "SECURITY_V2_LEASE_MISMATCH"
                            | "SECURITY_V2_RECORD_CONFLICT"
                            | "SECURITY_V2_INVALID_BODY"
                            | "SECURITY_V2_UNKNOWN_FIELD"
                    )
                )
            {
                let ids = batch
                    .iter()
                    .map(|(record, _)| record.id)
                    .collect::<Vec<_>>();
                queue.delete_counted(&ids, problem_code.as_deref().unwrap_or("terminal"))?;
                summary.dropped += ids.len();
                continue;
            }
            if response.status != 200 {
                let ids = batch
                    .iter()
                    .map(|(record, _)| record.id)
                    .collect::<Vec<_>>();
                queue.mark_retry(&ids, "invalid_response", now, None)?;
                summary.retrying += ids.len();
                continue;
            }
            let Ok(envelope) = serde_json::from_str::<ResultEnvelope>(&response.body) else {
                let ids = batch
                    .iter()
                    .map(|(record, _)| record.id)
                    .collect::<Vec<_>>();
                queue.mark_retry(&ids, "invalid_response", now, None)?;
                summary.retrying += ids.len();
                continue;
            };
            if envelope.results.len() != batch.len()
                || envelope
                    .results
                    .iter()
                    .zip(&batch)
                    .any(|(result, (record, _))| result.record_id != record.record_id)
            {
                let ids = batch
                    .iter()
                    .map(|(record, _)| record.id)
                    .collect::<Vec<_>>();
                queue.mark_retry(&ids, "invalid_response", now, None)?;
                summary.retrying += ids.len();
                continue;
            }
            for (result, (record, value)) in envelope.results.iter().zip(batch.iter()) {
                match (result.result.as_str(), result.code.as_deref()) {
                    ("accepted" | "duplicate", None) => {
                        queue.delete(&[record.id])?;
                        summary.delivered += 1;
                    }
                    ("rejected", Some("SECURITY_V2_FIELD_NOT_PERMITTED")) => {
                        let Some(current) = leases.current() else {
                            queue.mark_retry(
                                &[record.id],
                                "SECURITY_V2_LEASE_REQUIRED",
                                now,
                                None,
                            )?;
                            summary.retrying += 1;
                            continue;
                        };
                        if let Some(minimized) = minimize_queued(value, &current.data_settings) {
                            queue.replace_projection(record.id, &minimized)?;
                            summary.reprojected += 1;
                        } else {
                            queue
                                .delete_counted(&[record.id], "SECURITY_V2_FIELD_NOT_PERMITTED")?;
                            summary.dropped += 1;
                        }
                    }
                    (
                        "rejected",
                        Some(
                            "SECURITY_V2_LEASE_MISMATCH"
                            | "SECURITY_V2_RECORD_CONFLICT"
                            | "SECURITY_V2_INVALID_BODY"
                            | "SECURITY_V2_UNKNOWN_FIELD",
                        ),
                    ) => {
                        queue.delete_counted(&[record.id], result.code.as_deref().unwrap())?;
                        summary.dropped += 1;
                    }
                    _ => {
                        queue.mark_retry(&[record.id], "invalid_response", now, None)?;
                        summary.retrying += 1;
                    }
                }
            }
        }
    }
    Ok(summary)
}

fn split_batches(
    records: Vec<QueuedSecurityRecord>,
) -> Result<(Vec<SecurityBatch>, Vec<i64>), GitAiError> {
    let mut batches = Vec::new();
    let mut current = SecurityBatch::new();
    let mut invalid_ids = Vec::new();
    for record in records {
        let Ok(value) = serde_json::from_str::<Value>(&record.projection_json) else {
            invalid_ids.push(record.id);
            continue;
        };
        let mut candidate = current
            .iter()
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        candidate.push(value.clone());
        let bytes = serde_json::to_vec(
            &json!({"schema_version":"trackai.security-upload/2","records":candidate}),
        )?
        .len();
        if (!current.is_empty() && bytes > MAX_BODY_BYTES) || current.len() == MAX_RECORDS {
            batches.push(std::mem::take(&mut current));
        }
        let single_bytes = serde_json::to_vec(
            &json!({"schema_version":"trackai.security-upload/2","records":[&value]}),
        )?
        .len();
        if single_bytes > MAX_BODY_BYTES {
            invalid_ids.push(record.id);
            continue;
        }
        current.push((record, value));
    }
    if !current.is_empty() {
        batches.push(current);
    }
    Ok((batches, invalid_ids))
}

fn problem_code(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body)
        .ok()?
        .get("code")?
        .as_str()
        .map(str::to_owned)
}

pub fn upload_security_records(
    binding: &MetricDeliveryHealthBinding,
    credential: &str,
    body: &Value,
) -> Result<UploadHttpResponse, GitAiError> {
    let url = format!(
        "{}/worker/security/v2/records",
        binding.api_base_url.trim_end_matches('/')
    );
    let body = serde_json::to_string(body)?;
    let (_agent, request) = ApiContext::http_post(&url, Some(30));
    let response = request
        .header("Content-Type", "application/json")
        .header("X-API-Key", credential)
        .send(&body)
        .map_err(|error| GitAiError::Generic(format!("security upload failed: {error}")))?;
    let status = response.status().as_u16();
    let retry_after_seconds = response
        .headers()
        .get("Retry-After")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    let mut body = response.into_body();
    let body = body
        .read_to_string()
        .map_err(|error| GitAiError::Generic(format!("security response failed: {error}")))?;
    Ok(UploadHttpResponse {
        status,
        retry_after_seconds,
        body,
    })
}

pub fn flush_configured_security_records(now: u64) -> Result<SecurityFlushResult, GitAiError> {
    let Some(runtime) = MetricDeliveryRuntime::load_optional_default()
        .map_err(|error| GitAiError::Generic(error.to_string()))?
    else {
        return Ok(SecurityFlushResult::default());
    };
    let config = crate::daemon::DaemonConfig::from_env_or_default_paths()?;
    let path = config.internal_dir.join("security-findings.db");
    if !path.try_exists()? {
        return Ok(SecurityFlushResult::default());
    }
    let mut queue = SecurityRecordQueue::open_at_path(&path)?;
    flush_security_records_with(
        &mut queue,
        &UNAVAILABLE_LEASE_CONTEXT,
        now,
        |binding| runtime.credential_for_health_binding(binding).ok(),
        upload_security_records,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::activation::LeaseSnapshot;
    use crate::security::records::{ProjectedRecord, SecurityDataSettings};
    use crate::security::tail::{FileIdentity, TailRead};
    use chrono::{NaiveDate, TimeZone, Utc};
    use std::collections::BTreeMap;

    struct Lease(SecurityDataSettings);
    impl SecurityLeaseContext for Lease {
        fn current(&self) -> Option<LeaseSnapshot> {
            Some(LeaseSnapshot {
                lease_id: "lease".into(),
                bundle_digest: "a".repeat(64),
                issued_at: Utc.timestamp_opt(0, 0).unwrap(),
                expires_at: Utc.timestamp_opt(4_000_000_000, 0).unwrap(),
                data_settings: self.0.clone(),
            })
        }
        fn issued(&self, _lease_id: &str) -> Option<LeaseSnapshot> {
            self.current()
        }
    }

    fn binding() -> MetricDeliveryHealthBinding {
        MetricDeliveryHealthBinding {
            tenant_id: "tenant".into(),
            api_base_url: "https://trackai.example".into(),
            credential_key_id: "ABCDEFGHIJKLMNOP".into(),
        }
    }

    fn queue_with(values: Vec<Value>) -> (tempfile::TempDir, SecurityRecordQueue) {
        let temp = tempfile::TempDir::new().unwrap();
        let mut queue = SecurityRecordQueue::open_at_path(&temp.path().join("queue.db")).unwrap();
        let records = values
            .into_iter()
            .enumerate()
            .map(|(index, mut json)| {
                let record_id = format!("sha256:{index:064x}");
                json.as_object_mut()
                    .unwrap()
                    .insert("record_id".into(), json!(record_id));
                ProjectedRecord {
                    kind: json["kind"].as_str().unwrap().into(),
                    record_id,
                    lease_id: "lease".into(),
                    json,
                }
            })
            .collect::<Vec<_>>();
        let binding = binding();
        let refs = records
            .iter()
            .map(|record| (record, &binding))
            .collect::<Vec<_>>();
        queue
            .commit_poll(
                &TailRead {
                    identity: FileIdentity {
                        device: 1,
                        inode: 1,
                    },
                    reset: false,
                    start_offset: 0,
                    next_offset: 1,
                    partial_len: 0,
                    file_len: 1,
                    reached_eof: true,
                    entries: vec![],
                },
                NaiveDate::from_ymd_opt(2026, 10, 17).unwrap(),
                &refs,
                &BTreeMap::new(),
                10,
            )
            .unwrap();
        (temp, queue)
    }

    #[test]
    fn accepted_duplicate_and_every_terminal_code_delete_rows() {
        let (_temp, mut queue) = queue_with(vec![
            json!({"kind":"finding"}),
            json!({"kind":"scan_summary"}),
            json!({"kind":"permission_event"}),
            json!({"kind":"enforcement"}),
            json!({"kind":"security_status"}),
            json!({"kind":"agent_inventory"}),
        ]);
        let result=flush_security_records_with(
            &mut queue,&Lease(SecurityDataSettings::ALL_OFF),10,|_|Some("credential".into()),
            |_,_,body| Ok(UploadHttpResponse { status:200,retry_after_seconds:None,body:json!({"results":[
                {"record_id":body["records"][0]["record_id"],"result":"accepted"},
                {"record_id":body["records"][1]["record_id"],"result":"duplicate"},
                {"record_id":body["records"][2]["record_id"],"result":"rejected","code":"SECURITY_V2_LEASE_MISMATCH"},
                {"record_id":body["records"][3]["record_id"],"result":"rejected","code":"SECURITY_V2_RECORD_CONFLICT"},
                {"record_id":body["records"][4]["record_id"],"result":"rejected","code":"SECURITY_V2_INVALID_BODY"},
                {"record_id":body["records"][5]["record_id"],"result":"rejected","code":"SECURITY_V2_UNKNOWN_FIELD"}
            ]}).to_string() })
        ).unwrap();
        assert_eq!(result.delivered, 2);
        assert_eq!(result.dropped, 4);
        assert!(queue.dequeue_pending(500, 10_000).unwrap().is_empty());
    }

    #[test]
    fn field_not_permitted_only_deletes_from_minimized_projection() {
        let record_id = format!("sha256:{:064x}", 0);
        let (_temp, mut queue) = queue_with(vec![json!({
            "kind":"finding","record_id":record_id,
            "observed_command":"redacted","observed_url":"https://example.invalid",
            "endpoint":{"hostname":"host","username":"user"}
        })]);
        let result=flush_security_records_with(
            &mut queue,&Lease(SecurityDataSettings::ALL_OFF),10,|_|Some("credential".into()),
            |_,_,body| Ok(UploadHttpResponse { status:200,retry_after_seconds:None,body:json!({"results":[{
                "record_id":body["records"][0]["record_id"],"result":"rejected","code":"SECURITY_V2_FIELD_NOT_PERMITTED"
            }]}).to_string() })
        ).unwrap();
        assert_eq!(result.reprojected, 1);
        let rows = queue.dequeue_pending(500, 10).unwrap();
        let value: Value = serde_json::from_str(&rows[0].projection_json).unwrap();
        assert_eq!(value["record_id"], record_id);
        for key in ["observed_command", "observed_url", "endpoint"] {
            assert!(value.get(key).is_none());
        }
    }

    #[test]
    fn lease_required_server_error_and_rate_limit_retry() {
        for (status, retry_after) in [(403, None), (503, None), (429, Some(17))] {
            let (_temp, mut queue) = queue_with(vec![json!({"kind":"scan_summary"})]);
            let result = flush_security_records_with(
                &mut queue,
                &Lease(SecurityDataSettings::ALL_OFF),
                10,
                |_| Some("credential".into()),
                |_, _, _| {
                    Ok(UploadHttpResponse {
                        status,
                        retry_after_seconds: retry_after,
                        body: if status == 403 {
                            json!({"code":"SECURITY_V2_LEASE_REQUIRED"}).to_string()
                        } else {
                            "{}".into()
                        },
                    })
                },
            )
            .unwrap();
            assert_eq!(result.retrying, 1);
            assert_eq!(queue.dequeue_pending(500, 1000).unwrap().len(), 1);
        }
    }

    #[test]
    fn field_not_permitted_drops_indicator_when_urls_are_off() {
        let (_temp, mut queue) = queue_with(vec![json!({
            "kind":"indicator","type":"domain","value":"example.invalid"
        })]);
        let result = flush_security_records_with(
            &mut queue,
            &Lease(SecurityDataSettings::ALL_OFF),
            10,
            |_| Some("credential".into()),
            |_, _, body| {
                Ok(UploadHttpResponse {
                    status: 200,
                    retry_after_seconds: None,
                    body: json!({"results":[{
                        "record_id":body["records"][0]["record_id"],
                        "result":"rejected","code":"SECURITY_V2_FIELD_NOT_PERMITTED"
                    }]})
                    .to_string(),
                })
            },
        )
        .unwrap();
        assert_eq!(result.dropped, 1);
        assert!(queue.dequeue_pending(500, 10).unwrap().is_empty());
    }
}
