use super::{AgentPreset, ParsedHookEvent, PostFileEdit, PresetContext};
use crate::authorship::working_log::AgentId;
use crate::error::GitAiError;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct AntigravityPreset;

impl AgentPreset for AntigravityPreset {
    fn parse(&self, hook_input: &str, trace_id: &str) -> Result<Vec<ParsedHookEvent>, GitAiError> {
        let data: Value = serde_json::from_str(hook_input)
            .map_err(|e| GitAiError::PresetError(format!("Invalid Antigravity hook JSON: {e}")))?;
        let cwd = required_string(&data, "cwd")?;
        let conversation_id = required_string(&data, "conversation_id")?;
        let model = data
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("unknown")
            .to_string();
        let transcript_path = required_string(&data, "transcript_path")?;
        let file_paths = data
            .get("edited_filepaths")
            .and_then(Value::as_array)
            .ok_or_else(|| GitAiError::PresetError("edited_filepaths is required".to_string()))?
            .iter()
            .filter_map(Value::as_str)
            .map(|value| resolve_path(value, &cwd))
            .collect::<Vec<_>>();
        if file_paths.is_empty() {
            return Err(GitAiError::PresetError(
                "edited_filepaths cannot be empty".to_string(),
            ));
        }

        let dirty_files = data
            .get("dirty_files")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(key, value)| {
                        value
                            .as_str()
                            .map(|content| (resolve_path(key, &cwd), content.to_string()))
                    })
                    .collect::<HashMap<_, _>>()
            });

        let context = PresetContext {
            agent_id: AgentId {
                tool: "antigravity".to_string(),
                id: conversation_id.clone(),
                model,
            },
            external_session_id: conversation_id,
            trace_id: trace_id.to_string(),
            cwd: PathBuf::from(&cwd),
            metadata: HashMap::from([("transcript_path".to_string(), transcript_path)]),
        };

        Ok(vec![ParsedHookEvent::PostFileEdit(PostFileEdit {
            context,
            file_paths,
            dirty_files,
            // Antigravity's exported transcript is evidence metadata for now.
            // Its token stream is not Gemini CLI JSONL and must not be parsed as one.
            stream_source: None,
            tool_use_id: data
                .get("tool_use_id")
                .and_then(Value::as_str)
                .map(str::to_string),
        })])
    }
}

fn required_string(data: &Value, key: &str) -> Result<String, GitAiError> {
    data.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| GitAiError::PresetError(format!("{key} is required")))
}

fn resolve_path(value: &str, cwd: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(cwd).join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_post_edit_with_conversation_and_model() {
        let input = json!({
            "cwd": "/repo",
            "conversation_id": "conversation-123",
            "model": "Gemini 3.5 Flash (Low)",
            "transcript_path": "/home/user/.gemini/antigravity-ide/brain/conversation-123/.system_generated/logs/transcript.jsonl",
            "edited_filepaths": ["src/example.py"],
            "dirty_files": {"/repo/src/example.py": "def example():\n    return 1\n"},
            "tool_use_id": "step-8"
        })
        .to_string();

        let events = AntigravityPreset.parse(&input, "trace-1").unwrap();
        let ParsedHookEvent::PostFileEdit(event) = &events[0] else {
            panic!("expected PostFileEdit");
        };
        assert_eq!(event.context.agent_id.tool, "antigravity");
        assert_eq!(event.context.agent_id.id, "conversation-123");
        assert_eq!(event.context.agent_id.model, "Gemini 3.5 Flash (Low)");
        assert_eq!(event.context.external_session_id, "conversation-123");
        assert_eq!(
            event.file_paths,
            vec![PathBuf::from("/repo/src/example.py")]
        );
        assert_eq!(event.tool_use_id.as_deref(), Some("step-8"));
        assert!(event.stream_source.is_none());
    }

    #[test]
    fn rejects_empty_file_list() {
        let input = json!({
            "cwd": "/repo",
            "conversation_id": "conversation-123",
            "transcript_path": "/tmp/transcript.jsonl",
            "edited_filepaths": []
        })
        .to_string();
        assert!(AntigravityPreset.parse(&input, "trace-1").is_err());
    }
}
