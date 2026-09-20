//! Tenant-bound OpenCode evidence batches for TrackAI.
//!
//! This module deliberately sits outside Git trace/checkpoint ingestion. Raw
//! provider values are redacted before they enter a request body and are never
//! included in logs, command arguments, or error messages.

use crate::daemon::transcript_redaction::redact_json_secrets;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const SOURCE_VERSION: &str = "git-ai/opencode-evidence/1";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenCodeEvidenceBatch {
    provider: &'static str,
    batch_id: String,
    source_version: &'static str,
    repository_id: String,
    external_session_id: String,
    git_ai_session_id: String,
    events: Vec<OpenCodeEvidenceEvent>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenCodeEvidenceEvent {
    provider_event_id: String,
    #[serde(rename = "type")]
    event_type: &'static str,
    occurred_at: String,
    trace_id: Option<String>,
    model: Option<String>,
    tool_name: Option<String>,
    content: Value,
    metadata: Map<String, Value>,
}

impl OpenCodeEvidenceBatch {
    pub fn from_stream_events(
        repository_id: &str,
        external_session_id: &str,
        git_ai_session_id: &str,
        raw_events: Vec<Value>,
    ) -> Vec<Self> {
        let mut events = Vec::new();
        for raw in raw_events {
            events.extend(map_message(redact_json_secrets(raw)));
        }
        events
            .chunks(500)
            .map(|chunk| {
                let event_ids = chunk
                    .iter()
                    .map(|event| event.provider_event_id.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                let batch_id = stable_batch_id(external_session_id, &event_ids);
                Self {
                    provider: "opencode",
                    batch_id,
                    source_version: SOURCE_VERSION,
                    repository_id: repository_id.to_string(),
                    external_session_id: external_session_id.to_string(),
                    git_ai_session_id: git_ai_session_id.to_string(),
                    events: chunk.to_vec(),
                }
            })
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

fn stable_batch_id(session_id: &str, event_ids: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(SOURCE_VERSION.as_bytes());
    digest.update(b"\0");
    digest.update(session_id.as_bytes());
    digest.update(b"\0");
    digest.update(event_ids.as_bytes());
    format!("opencode-{:x}", digest.finalize())
}

fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn millis(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64).filter(|value| *value >= 0)
}

fn occurred_at(message: &Map<String, Value>, part: &Map<String, Value>) -> String {
    let data = part.get("data").and_then(object);
    let state = data.and_then(|value| value.get("state")).and_then(object);
    let state_time = state.and_then(|value| value.get("time")).and_then(object);
    let part_time = data.and_then(|value| value.get("time")).and_then(object);
    let milliseconds = millis(state_time.and_then(|value| value.get("start")))
        .or_else(|| millis(part_time.and_then(|value| value.get("start"))))
        .or_else(|| millis(part.get("time_created")))
        .or_else(|| millis(message.get("time_created")))
        .unwrap_or(0);
    DateTime::<Utc>::from_timestamp_millis(milliseconds)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn model(message_data: &Map<String, Value>) -> Option<String> {
    text(message_data.get("modelID")).or_else(|| {
        message_data
            .get("model")
            .and_then(object)
            .and_then(|value| text(value.get("modelID")))
    })
}

fn metadata(part_data: &Map<String, Value>) -> Map<String, Value> {
    let mut metadata = Map::new();
    let Some(state) = part_data.get("state").and_then(object) else {
        return metadata;
    };
    if let Some(status) = text(state.get("status")) {
        metadata.insert("status".to_string(), Value::String(status));
    }
    let state_time = state.get("time").and_then(object);
    let start = millis(state_time.and_then(|value| value.get("start")));
    let end = millis(state_time.and_then(|value| value.get("end")));
    if let (Some(start), Some(end)) = (start, end)
        && end >= start
    {
        metadata.insert("durationMs".to_string(), json!(end - start));
    }
    metadata
}

fn event(
    provider_event_id: String,
    event_type: &'static str,
    timestamp: &str,
    model: &Option<String>,
    tool_name: Option<String>,
    content: Value,
    metadata: Map<String, Value>,
) -> OpenCodeEvidenceEvent {
    OpenCodeEvidenceEvent {
        provider_event_id,
        event_type,
        occurred_at: timestamp.to_string(),
        trace_id: None,
        model: model.clone(),
        tool_name,
        content,
        metadata,
    }
}

fn map_message(raw: Value) -> Vec<OpenCodeEvidenceEvent> {
    let Some(message) = raw.get("message").and_then(object) else {
        return Vec::new();
    };
    let Some(message_data) = message.get("data").and_then(object) else {
        return Vec::new();
    };
    let role = text(message_data.get("role"));
    let message_id = text(message.get("id"));
    let model = model(message_data);
    let parts = raw
        .get("parts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_reasoning = parts.iter().any(|part| {
        part.get("data")
            .and_then(object)
            .and_then(|data| text(data.get("type")))
            .as_deref()
            == Some("reasoning")
    });
    let mut events = Vec::new();
    for part in parts {
        let Some(part_row) = object(&part) else {
            continue;
        };
        let Some(part_id) = text(part_row.get("id")) else {
            continue;
        };
        let Some(data) = part_row.get("data").and_then(object) else {
            continue;
        };
        let Some(part_type) = text(data.get("type")) else {
            continue;
        };
        let timestamp = occurred_at(message, part_row);
        let base_metadata = metadata(data);
        match (role.as_deref(), part_type.as_str()) {
            (Some("user"), "text") => events.push(event(
                part_id,
                "prompt",
                &timestamp,
                &model,
                None,
                data.get("text").cloned().unwrap_or(Value::Null),
                base_metadata,
            )),
            (Some("assistant"), "reasoning") => events.push(event(
                part_id,
                "reasoning",
                &timestamp,
                &model,
                None,
                data.get("text").cloned().unwrap_or(Value::Null),
                base_metadata,
            )),
            (Some("assistant"), "text") => events.push(event(
                part_id,
                "response",
                &timestamp,
                &model,
                None,
                data.get("text").cloned().unwrap_or(Value::Null),
                base_metadata,
            )),
            (Some("assistant"), "tool") => {
                let tool_name = text(data.get("tool"));
                let state = data.get("state").and_then(object);
                events.push(event(
                    format!("{part_id}:call"),
                    "tool_call",
                    &timestamp,
                    &model,
                    tool_name.clone(),
                    state
                        .and_then(|value| value.get("input"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    base_metadata.clone(),
                ));
                if let Some(state) = state
                    && (state.contains_key("output") || state.contains_key("error"))
                {
                    let mut result_metadata = base_metadata;
                    if state.contains_key("error") {
                        result_metadata
                            .insert("status".to_string(), Value::String("failed".to_string()));
                        result_metadata.insert(
                            "errorCode".to_string(),
                            Value::String("provider_tool_error".to_string()),
                        );
                    }
                    events.push(event(
                        format!("{part_id}:result"),
                        "tool_result",
                        &timestamp,
                        &model,
                        tool_name,
                        state
                            .get("output")
                            .or_else(|| state.get("error"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        result_metadata,
                    ));
                }
            }
            _ => {}
        }
    }
    if role.as_deref() == Some("assistant")
        && !has_reasoning
        && let Some(message_id) = message_id
    {
        events.push(event(
            format!("{message_id}:reasoning-unavailable"),
            "reasoning",
            &occurred_at(message, message),
            &model,
            None,
            Value::Null,
            Map::new(),
        ));
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_mapping_separates_prompt_tool_result_and_unavailable_reasoning() {
        let batches = OpenCodeEvidenceBatch::from_stream_events(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "session-one",
            "s_1234567890abcd",
            vec![json!({
                "message": {
                    "id": "message-one",
                    "time_created": 1750000000000_i64,
                    "data": { "role": "assistant", "modelID": "model-a" }
                },
                "parts": [{
                    "id": "part-tool",
                    "time_created": 1750000000000_i64,
                    "data": {
                        "type": "tool", "tool": "shell",
                        "state": {
                            "status": "completed", "input": { "command": "task test" },
                            "output": "passed", "time": { "start": 1750000000000_i64, "end": 1750000000012_i64 }
                        }
                    }
                }]
            })],
        );
        let value = serde_json::to_value(&batches[0]).unwrap();
        assert_eq!(value["events"].as_array().unwrap().len(), 3);
        assert_eq!(value["events"][0]["type"], "tool_call");
        assert_eq!(value["events"][1]["type"], "tool_result");
        assert_eq!(value["events"][2]["type"], "reasoning");
        assert!(value["events"][2]["content"].is_null());
        assert_eq!(value["events"][0]["metadata"]["durationMs"], 12);
    }

    #[test]
    fn opencode_mapping_redacts_secrets_before_serialization() {
        let batches = OpenCodeEvidenceBatch::from_stream_events(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "session-one",
            "s_1234567890abcd",
            vec![json!({
                "message": {
                    "id": "message-one", "time_created": 1750000000000_i64,
                    "data": { "role": "user" }
                },
                "parts": [{
                    "id": "part-one", "time_created": 1750000000000_i64,
                    "data": { "type": "text", "text": "token sk_test_4eC39HqLyjWDarjtT1zdp7dc" }
                }]
            })],
        );
        let serialized = serde_json::to_string(&batches).unwrap();
        assert!(!serialized.contains("sk_test_4eC39HqLyjWDarjtT1zdp7dc"));
        assert!(serialized.contains("********"));
    }

    #[test]
    fn opencode_batch_is_replay_stable_and_matches_trackai_contract() {
        let input = vec![json!({
            "message": {
                "id": "message-contract", "time_created": 1750000000000_i64,
                "data": { "role": "assistant", "modelID": "model-contract" }
            },
            "parts": [{
                "id": "part-contract", "time_created": 1750000000000_i64,
                "data": {
                    "type": "tool", "tool": "shell",
                    "state": {
                        "status": "completed", "input": { "command": "task test" },
                        "output": "passed",
                        "time": { "start": 1750000000000_i64, "end": 1750000000042_i64 }
                    }
                }
            }]
        })];
        let make = || {
            OpenCodeEvidenceBatch::from_stream_events(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "session-contract",
                "s_1234567890abcd",
                input.clone(),
            )
        };
        let first = serde_json::to_value(make()).unwrap();
        let replay = serde_json::to_value(make()).unwrap();
        assert_eq!(
            first, replay,
            "the same provider rows must create the same replay body"
        );

        let batch = &first[0];
        assert_eq!(batch["provider"], "opencode");
        assert_eq!(batch["sourceVersion"], SOURCE_VERSION);
        assert_eq!(
            batch["repositoryId"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(batch["externalSessionId"], "session-contract");
        assert_eq!(batch["gitAiSessionId"], "s_1234567890abcd");
        assert!(
            batch.get("intention").is_none(),
            "prompt and intention remain separate"
        );
        let events = batch["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["providerEventId"], "part-contract:call");
        assert_eq!(events[1]["providerEventId"], "part-contract:result");
        assert_eq!(
            events[2]["providerEventId"],
            "message-contract:reasoning-unavailable"
        );
        assert!(events[2]["content"].is_null());
        assert!(
            events[2]["traceId"].is_null(),
            "missing trace evidence must stay unavailable"
        );

        let allowed_event_fields = [
            "providerEventId",
            "type",
            "occurredAt",
            "traceId",
            "model",
            "toolName",
            "content",
            "metadata",
        ];
        let allowed_metadata_fields = [
            "status",
            "durationMs",
            "attempt",
            "errorCode",
            "exitCode",
            "abandoned",
        ];
        for event in events {
            let row = event.as_object().unwrap();
            assert!(
                row.keys()
                    .all(|key| allowed_event_fields.contains(&key.as_str()))
            );
            let metadata = row["metadata"].as_object().unwrap();
            assert!(
                metadata
                    .keys()
                    .all(|key| allowed_metadata_fields.contains(&key.as_str()))
            );
        }
    }
}
