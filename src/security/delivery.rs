//! Disconnected delivery adapter for queued Task6 security findings.
//!
//! The caller supplies credential resolution and upload functions. This keeps
//! the adapter testable and prevents a live route from being enabled before
//! TrackAI has approved durable storage.

use crate::api::client::ApiContext;
use crate::error::GitAiError;
use crate::metrics::delivery::EvidenceDeliveryBinding;
use crate::security::delivery_queue::{
    QueuedSecurityFinding, SecurityFindingFailureClass, SecurityFindingQueue,
    SecurityFindingTerminalClass,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFindingUploadError {
    pub index: usize,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFindingUploadResponse {
    pub errors: Vec<SecurityFindingUploadError>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SecurityFindingFlushResult {
    pub delivered: usize,
    pub terminal: usize,
    pub retrying: usize,
}

type RouteKey = (String, String, String);

pub fn upload_security_findings(
    context: &ApiContext,
    body: &Value,
) -> Result<SecurityFindingUploadResponse, GitAiError> {
    let response = context.post_json("/worker/security/findings", body)?;
    if response.status_code != 200 {
        return Err(GitAiError::Generic(format!(
            "security finding upload returned HTTP {}",
            response.status_code
        )));
    }
    let response_body = response.as_str().map_err(|_| {
        GitAiError::Generic("security finding upload response was not valid UTF-8".to_string())
    })?;
    serde_json::from_str(response_body).map_err(|_| {
        GitAiError::Generic("security finding upload response was invalid".to_string())
    })
}

pub fn flush_security_findings_with<ResolveCredential, Upload>(
    queue: &mut SecurityFindingQueue,
    now: u64,
    limit: usize,
    mut resolve_credential: ResolveCredential,
    mut upload: Upload,
) -> Result<SecurityFindingFlushResult, GitAiError>
where
    ResolveCredential: FnMut(&EvidenceDeliveryBinding) -> Option<String>,
    Upload: FnMut(&ApiContext, &Value) -> Result<SecurityFindingUploadResponse, GitAiError>,
{
    let records = queue.dequeue_pending(limit, now)?;
    let mut routes = BTreeMap::<RouteKey, Vec<QueuedSecurityFinding>>::new();
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

    let mut result = SecurityFindingFlushResult::default();
    for records in routes.into_values() {
        let binding = &records[0].delivery_binding;
        let ids = records.iter().map(|record| record.id).collect::<Vec<_>>();
        let Some(credential) = resolve_credential(binding) else {
            queue.mark_terminal(
                &ids,
                SecurityFindingTerminalClass::CredentialUnavailable,
                now,
            )?;
            result.terminal += ids.len();
            continue;
        };

        let mut findings = Vec::with_capacity(records.len());
        let mut valid_ids = Vec::with_capacity(records.len());
        for record in &records {
            let finding = serde_json::from_str::<Value>(&record.finding_json)
                .ok()
                .and_then(|body| body.get("findings")?.as_array()?.first().cloned());
            if let Some(finding) = finding {
                findings.push(finding);
                valid_ids.push(record.id);
            } else {
                queue.mark_terminal(
                    &[record.id],
                    SecurityFindingTerminalClass::InvalidLocalRecord,
                    now,
                )?;
                result.terminal += 1;
            }
        }
        if findings.is_empty() {
            continue;
        }

        let context = ApiContext {
            base_url: binding.api_base_url.clone(),
            auth_token: None,
            api_key: Some(credential),
            author_identity: None,
            timeout_secs: Some(30),
        };
        let body = json!({
            "schemaVersion": "trackai.security-finding-upload/0.1",
            "findings": findings,
        });
        let response = match upload(&context, &body) {
            Ok(response) => response,
            Err(_) => {
                queue.mark_failed(
                    &valid_ids,
                    SecurityFindingFailureClass::TemporaryTransport,
                    now,
                )?;
                result.retrying += valid_ids.len();
                continue;
            }
        };

        let mut failed = HashSet::new();
        let valid_response = response
            .errors
            .iter()
            .all(|error| error.index < valid_ids.len() && failed.insert(error.index));
        if !valid_response {
            queue.mark_failed(
                &valid_ids,
                SecurityFindingFailureClass::ServerUnavailable,
                now,
            )?;
            result.retrying += valid_ids.len();
            continue;
        }

        let delivered_ids = valid_ids
            .iter()
            .enumerate()
            .filter(|(index, _)| !failed.contains(index))
            .map(|(_, id)| *id)
            .collect::<Vec<_>>();
        let terminal_ids = valid_ids
            .iter()
            .enumerate()
            .filter(|(index, _)| failed.contains(index))
            .map(|(_, id)| *id)
            .collect::<Vec<_>>();
        queue.mark_delivered(&delivered_ids, now)?;
        queue.mark_terminal(
            &terminal_ids,
            SecurityFindingTerminalClass::ServerRejected,
            now,
        )?;
        result.delivered += delivered_ids.len();
        result.terminal += terminal_ids.len();
    }
    Ok(result)
}
