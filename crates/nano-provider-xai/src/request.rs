//! Exact, stateless xAI Responses request serialization.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nano_types::external_tool::{
    READ_FILE_MEDIA_MAX_HISTORY_BYTES, READ_FILE_MEDIA_MAX_HISTORY_ITEMS,
};
use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct, Serializer};

use crate::types::{
    FunctionTool, HistoryItem, MediaHistoryEvictionLedger, ProviderFailure, ProviderRequestMode,
    ToolMediaAttachment, TurnRequest, validate_media_history_policy_receipt,
};

use super::client::XaiProviderSettings;

#[derive(Serialize)]
struct RequestBody<'a> {
    model: &'a str,
    input: Vec<InputItem<'a>>,
    tools: Vec<RequestTool<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<&'a str>,
    parallel_tool_calls: bool,
    reasoning: Reasoning<'a>,
    include: &'a [String],
    store: bool,
    stream: bool,
    max_output_tokens: u64,
    service_tier: &'a str,
    truncation: &'static str,
}

enum InputItem<'a> {
    Message {
        role: &'static str,
        content: &'a str,
    },
    Reasoning {
        id: &'a Option<String>,
        summary: &'a serde_json::Value,
        encrypted_content: &'a Option<String>,
        content: &'a Option<serde_json::Value>,
    },
    FunctionCall {
        call_id: &'a str,
        name: &'a str,
        arguments: &'a str,
    },
    FunctionCallOutput {
        call_id: &'a str,
        output: &'a str,
    },
    ToolMediaAttachment {
        attachment: &'a ToolMediaAttachment,
    },
    MediaHistoryEviction {
        ledger: &'a MediaHistoryEvictionLedger,
    },
}

impl Serialize for InputItem<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Message { role, content } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("role", role)?;
                map.serialize_entry("content", content)?;
                map.end()
            }
            Self::Reasoning {
                id,
                summary,
                encrypted_content,
                content,
            } => {
                let length = 2
                    + usize::from(id.is_some())
                    + usize::from(encrypted_content.is_some())
                    + usize::from(content.is_some());
                let mut map = serializer.serialize_map(Some(length))?;
                map.serialize_entry("type", "reasoning")?;
                if let Some(id) = id {
                    map.serialize_entry("id", id)?;
                }
                map.serialize_entry("summary", summary)?;
                if let Some(encrypted_content) = encrypted_content {
                    map.serialize_entry("encrypted_content", encrypted_content)?;
                }
                if let Some(content) = content {
                    map.serialize_entry("content", content)?;
                }
                map.end()
            }
            Self::FunctionCall {
                call_id,
                name,
                arguments,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "function_call")?;
                map.serialize_entry("call_id", call_id)?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("arguments", arguments)?;
                map.end()
            }
            Self::FunctionCallOutput { call_id, output } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("type", "function_call_output")?;
                map.serialize_entry("call_id", call_id)?;
                map.serialize_entry("output", output)?;
                map.end()
            }
            Self::ToolMediaAttachment { attachment } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("role", "user")?;
                map.serialize_entry("content", &MediaContent(attachment))?;
                map.end()
            }
            Self::MediaHistoryEviction { ledger } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("role", "user")?;
                map.serialize_entry("content", &ledger.model_text())?;
                map.end()
            }
        }
    }
}

struct MediaContent<'a>(&'a ToolMediaAttachment);

impl Serialize for MediaContent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let attachment = self.0;
        let data_url = format!(
            "data:{};base64,{}",
            attachment.mime_type().as_str(),
            BASE64.encode(attachment.bytes())
        );
        let binding = format!(
            "Runtime attachment for read_file call_id={}; this is the tool result, not a new user request. Logical path: {}; sha256={}",
            attachment.call_id(),
            attachment.logical_path(),
            attachment.sha256()
        );
        let mut sequence = serializer.serialize_seq(Some(2))?;
        sequence.serialize_element(&ImagePart {
            image_url: &data_url,
        })?;
        sequence.serialize_element(&TextPart { text: &binding })?;
        sequence.end()
    }
}

struct ImagePart<'a> {
    image_url: &'a str,
}

impl Serialize for ImagePart<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut structure = serializer.serialize_struct("ImagePart", 3)?;
        structure.serialize_field("type", "input_image")?;
        structure.serialize_field("image_url", self.image_url)?;
        structure.serialize_field("detail", "high")?;
        structure.end()
    }
}

struct TextPart<'a> {
    text: &'a str,
}

impl Serialize for TextPart<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut structure = serializer.serialize_struct("TextPart", 2)?;
        structure.serialize_field("type", "input_text")?;
        structure.serialize_field("text", self.text)?;
        structure.end()
    }
}

#[derive(Serialize)]
struct RequestTool<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    name: &'a str,
    description: &'a str,
    parameters: &'a serde_json::Value,
}

impl<'a> From<&'a FunctionTool> for RequestTool<'a> {
    fn from(tool: &'a FunctionTool) -> Self {
        Self {
            kind: "function",
            name: &tool.name,
            description: &tool.description,
            parameters: &tool.parameters,
        }
    }
}

#[derive(Serialize)]
struct Reasoning<'a> {
    effort: &'a str,
}

pub(crate) fn serialize_request(
    request: &TurnRequest,
    settings: &XaiProviderSettings,
) -> Result<Vec<u8>, ProviderFailure> {
    if request.model != settings.model {
        return Err(ProviderFailure::new("provider_request_model_mismatch"));
    }
    validate_media_history(request)?;
    let input = request
        .history
        .iter()
        .map(|item| match item {
            HistoryItem::System { content } => InputItem::Message {
                role: "system",
                content,
            },
            HistoryItem::User { content } => InputItem::Message {
                role: "user",
                content,
            },
            HistoryItem::AssistantMessage { text } => InputItem::Message {
                role: "assistant",
                content: text,
            },
            HistoryItem::Reasoning {
                id,
                summary,
                encrypted_content,
                content,
            } => InputItem::Reasoning {
                id,
                summary,
                encrypted_content,
                content,
            },
            HistoryItem::FunctionCall {
                call_id,
                name,
                arguments_json,
            } => InputItem::FunctionCall {
                call_id,
                name,
                arguments: arguments_json,
            },
            HistoryItem::FunctionCallOutput { call_id, output } => {
                InputItem::FunctionCallOutput { call_id, output }
            }
            HistoryItem::ToolMediaAttachment { attachment } => {
                InputItem::ToolMediaAttachment { attachment }
            }
            HistoryItem::MediaHistoryEviction { ledger } => {
                InputItem::MediaHistoryEviction { ledger }
            }
        })
        .collect();
    let tools = request.tools.iter().map(RequestTool::from).collect();
    let tool_choice = match (request.tools.is_empty(), request.mode) {
        (true, _) => None,
        (false, ProviderRequestMode::ActionOpen) => Some(settings.tool_choice.as_str()),
        (false, ProviderRequestMode::FinalOnly) => Some("none"),
    };
    let body = RequestBody {
        model: &settings.model,
        input,
        tools,
        tool_choice,
        parallel_tool_calls: settings.parallel_tool_calls,
        reasoning: Reasoning {
            effort: &settings.reasoning_effort,
        },
        include: &settings.include,
        store: false,
        stream: true,
        max_output_tokens: settings.max_output_tokens,
        service_tier: &settings.service_tier,
        truncation: "disabled",
    };
    let bytes = serde_json::to_vec(&body)
        .map_err(|_| ProviderFailure::new("provider_request_serialize_failed"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > settings.max_request_body_bytes {
        return Err(ProviderFailure::new("provider_request_body_too_large"));
    }
    Ok(bytes)
}

fn validate_media_history(request: &TurnRequest) -> Result<(), ProviderFailure> {
    if let Some(receipt) = &request.media_history_receipt {
        return validate_media_history_policy_receipt(&request.history, receipt);
    }

    let history = &request.history;
    let mut output_call_ids = BTreeSet::new();
    let mut media_call_ids = BTreeSet::new();
    let mut count = 0_u64;
    let mut bytes = 0_u64;
    for item in history {
        match item {
            HistoryItem::FunctionCallOutput { call_id, .. } => {
                output_call_ids.insert(call_id.as_str());
            }
            HistoryItem::ToolMediaAttachment { attachment } => {
                attachment.validate()?;
                if !output_call_ids.contains(attachment.call_id())
                    || !media_call_ids.insert(attachment.call_id())
                {
                    return Err(ProviderFailure::new(
                        "provider_media_attachment_binding_invalid",
                    ));
                }
                count = count
                    .checked_add(1)
                    .ok_or_else(|| ProviderFailure::new("provider_media_count_exceeded"))?;
                bytes = bytes
                    .checked_add(u64::try_from(attachment.bytes().len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| ProviderFailure::new("provider_media_history_bytes_exceeded"))?;
            }
            HistoryItem::MediaHistoryEviction { .. } => {
                return Err(ProviderFailure::new(
                    "provider_media_history_receipt_missing",
                ));
            }
            _ => {}
        }
    }
    if count > READ_FILE_MEDIA_MAX_HISTORY_ITEMS {
        return Err(ProviderFailure::new("provider_media_count_exceeded"));
    }
    if bytes > READ_FILE_MEDIA_MAX_HISTORY_BYTES {
        return Err(ProviderFailure::new(
            "provider_media_history_bytes_exceeded",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::{XaiProviderSettings, serialize_request};
    use crate::types::{
        FunctionTool, HistoryItem, MediaType, ProviderRequestMode, TurnRequest,
        apply_media_history_policy, prepare_media_history_batch,
    };

    fn settings(max_request_body_bytes: u64) -> XaiProviderSettings {
        XaiProviderSettings {
            model: "grok-4.5".to_owned(),
            reasoning_effort: "high".to_owned(),
            include: vec!["reasoning.encrypted_content".to_owned()],
            parallel_tool_calls: true,
            tool_choice: "auto".to_owned(),
            service_tier: "default".to_owned(),
            max_output_tokens: 256,
            max_request_body_bytes,
            max_function_arguments_bytes: 1024,
            max_sse_events: 1024,
            max_sse_event_bytes: 1024,
            max_sse_response_bytes: 4096,
            max_json_depth: 64,
            connect_timeout: Duration::from_secs(1),
            first_event_timeout: Duration::from_secs(1),
            inter_event_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn final_only_request_preserves_history_schema_but_disables_new_calls() {
        let history = vec![
            HistoryItem::User {
                content: "finish".to_owned(),
            },
            HistoryItem::FunctionCall {
                call_id: "call-1".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: r#"{"command":"true"}"#.to_owned(),
            },
            HistoryItem::FunctionCallOutput {
                call_id: "call-1".to_owned(),
                output: "done".to_owned(),
            },
        ];
        let tools = vec![FunctionTool {
            name: "run_terminal_command".to_owned(),
            description: "Run a command.".to_owned(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
                "additionalProperties": false
            }),
        }];
        let action = TurnRequest {
            turn_index: 1,
            model: "grok-4.5".to_owned(),
            history: history.clone(),
            tools,
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: None,
        };
        let final_only = TurnRequest {
            mode: ProviderRequestMode::FinalOnly,
            ..action.clone()
        };

        let action_body = String::from_utf8(
            serialize_request(&action, &settings(16 * 1024 * 1024)).expect("action request"),
        )
        .expect("action UTF-8");
        let final_body = String::from_utf8(
            serialize_request(&final_only, &settings(16 * 1024 * 1024))
                .expect("final-only request"),
        )
        .expect("final UTF-8");

        assert!(
            action_body
                .contains("\"tools\":[{\"type\":\"function\",\"name\":\"run_terminal_command\"")
        );
        assert!(action_body.contains("\"tool_choice\":\"auto\""));
        assert!(
            final_body
                .contains("\"tools\":[{\"type\":\"function\",\"name\":\"run_terminal_command\"")
        );
        assert!(final_body.contains("\"tool_choice\":\"none\""));
        assert!(!final_body.contains("\"tool_choice\":\"auto\""));

        let tool_less_final = TurnRequest {
            tools: Vec::new(),
            ..final_only
        };
        let tool_less_body = String::from_utf8(
            serialize_request(&tool_less_final, &settings(16 * 1024 * 1024))
                .expect("tool-less final request"),
        )
        .expect("tool-less final UTF-8");
        assert!(tool_less_body.contains("\"tools\":[]"));
        assert!(!tool_less_body.contains("\"tool_choice\""));
    }

    fn attachment(call_id: &str) -> HistoryItem {
        HistoryItem::tool_media_attachment(
            call_id,
            "board.png",
            MediaType::Png,
            2,
            1,
            "7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8",
            vec![137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3],
        )
        .expect("valid attachment")
    }

    #[test]
    fn six_image_candidate_preflight_preserves_text_only_golden() {
        let text_request = TurnRequest {
            turn_index: 0,
            model: "grok-4.5".to_owned(),
            history: vec![
                HistoryItem::System {
                    content: "system".to_owned(),
                },
                HistoryItem::User {
                    content: "text only".to_owned(),
                },
            ],
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: None,
        };
        let text_golden =
            serialize_request(&text_request, &settings(16 * 1024 * 1024)).expect("text golden");

        let mut base = vec![HistoryItem::User {
            content: "inspect six frames".to_owned(),
        }];
        let mut outputs = Vec::new();
        let mut attachments = Vec::new();
        let mut call_ids = Vec::new();
        for index in 0..6_u64 {
            let call_id = format!("call-{index}");
            let logical_path = format!("frame-{index}.png");
            let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
            bytes.extend_from_slice(&index.to_be_bytes());
            let digest = format!("{:x}", Sha256::digest(&bytes));
            base.push(HistoryItem::FunctionCall {
                call_id: call_id.clone(),
                name: "read_file".to_owned(),
                arguments_json: format!(r#"{{"target_file":"{logical_path}"}}"#),
            });
            outputs.push(HistoryItem::FunctionCallOutput {
                call_id: call_id.clone(),
                output: format!(
                    "read_file returned an attached image: image/png, 2x1, sha256={digest}"
                ),
            });
            attachments.push(
                HistoryItem::tool_media_attachment_with_origin(
                    call_id.clone(),
                    logical_path,
                    MediaType::Png,
                    2,
                    1,
                    digest,
                    bytes,
                    0,
                    "read_file",
                )
                .expect("attachment"),
            );
            call_ids.push(call_id);
        }
        outputs.extend(attachments);
        let prepared =
            prepare_media_history_batch(&base, 0, &call_ids, outputs).expect("six-image candidate");
        let (history, receipt) = prepared.into_parts();
        let body = serialize_request(
            &TurnRequest {
                turn_index: 1,
                model: "grok-4.5".to_owned(),
                history,
                tools: Vec::new(),
                mode: ProviderRequestMode::ActionOpen,
                media_history_receipt: Some(receipt),
            },
            &settings(16 * 1024 * 1024),
        )
        .expect("candidate preflight");
        let body = String::from_utf8(body).expect("body UTF-8");
        assert_eq!(body.matches("\"type\":\"function_call_output\"").count(), 6);
        assert_eq!(body.matches("\"type\":\"input_image\"").count(), 4);
        assert_eq!(body.matches("media_history_eviction").count(), 2);

        assert_eq!(
            serialize_request(&text_request, &settings(16 * 1024 * 1024)).expect("text replay"),
            text_golden
        );
    }

    #[test]
    fn exact_supplemental_user_image_request_keeps_function_output_string() {
        let request = TurnRequest {
            turn_index: 1,
            model: "grok-4.5".to_owned(),
            history: vec![
                HistoryItem::System {
                    content: "system".to_owned(),
                },
                HistoryItem::FunctionCall {
                    call_id: "call-7".to_owned(),
                    name: "read_file".to_owned(),
                    arguments_json: r#"{"target_file":"board.png"}"#.to_owned(),
                },
                HistoryItem::FunctionCallOutput {
                    call_id: "call-7".to_owned(),
                    output: concat!(
                        "read_file returned an attached image: image/png, 2x1, ",
                        "sha256=7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8"
                    )
                    .to_owned(),
                },
                attachment("call-7"),
            ],
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: None,
        };

        let body = serialize_request(&request, &settings(16 * 1024 * 1024))
            .expect("serialize media request");
        let expected = concat!(
            "{\"model\":\"grok-4.5\",\"input\":[",
            "{\"role\":\"system\",\"content\":\"system\"},",
            "{\"type\":\"function_call\",\"call_id\":\"call-7\",\"name\":\"read_file\",",
            "\"arguments\":\"{\\\"target_file\\\":\\\"board.png\\\"}\"},",
            "{\"type\":\"function_call_output\",\"call_id\":\"call-7\",",
            "\"output\":\"read_file returned an attached image: image/png, 2x1, ",
            "sha256=7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8\"},",
            "{\"role\":\"user\",\"content\":[",
            "{\"type\":\"input_image\",\"image_url\":\"data:image/png;base64,",
            "iVBORw0KGgoBAgM=\",\"detail\":\"high\"},",
            "{\"type\":\"input_text\",\"text\":\"Runtime attachment for read_file ",
            "call_id=call-7; this is the tool result, not a new user request. ",
            "Logical path: board.png; sha256=",
            "7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8\"}",
            "]}],\"tools\":[],\"parallel_tool_calls\":true,",
            "\"reasoning\":{\"effort\":\"high\"},",
            "\"include\":[\"reasoning.encrypted_content\"],\"store\":false,",
            "\"stream\":true,\"max_output_tokens\":256,\"service_tier\":\"default\",",
            "\"truncation\":\"disabled\"}"
        );
        assert_eq!(body, expected.as_bytes());
        assert!(serde_json::from_slice::<serde_json::Value>(&body).is_ok());
    }

    #[test]
    fn media_count_history_and_body_caps_fail_before_send() {
        let mut history = vec![HistoryItem::User {
            content: "inspect".to_owned(),
        }];
        history.extend((0..5).map(|index| HistoryItem::FunctionCallOutput {
            call_id: format!("call-{index}"),
            output: "attached".to_owned(),
        }));
        history.extend((0..5).map(|index| attachment(&format!("call-{index}"))));
        let request = TurnRequest {
            turn_index: 1,
            model: "grok-4.5".to_owned(),
            history,
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: None,
        };
        assert_eq!(
            serialize_request(&request, &settings(16 * 1024 * 1024))
                .expect_err("five images exceed history count")
                .code(),
            "provider_media_count_exceeded"
        );

        let body_limited = TurnRequest {
            turn_index: 1,
            model: "grok-4.5".to_owned(),
            history: vec![
                HistoryItem::User {
                    content: json!({"sentinel": "x".repeat(128)}).to_string(),
                },
                HistoryItem::FunctionCallOutput {
                    call_id: "call-body".to_owned(),
                    output: "attached".to_owned(),
                },
                attachment("call-body"),
            ],
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: None,
        };
        assert_eq!(
            serialize_request(&body_limited, &settings(64))
                .expect_err("exact body cap")
                .code(),
            "provider_request_body_too_large"
        );
    }

    #[test]
    fn windowed_request_serializes_explicit_eviction_ledger_and_keeps_hard_validator() {
        let mut history = vec![HistoryItem::User {
            content: "inspect".to_owned(),
        }];
        for index in 0..8_u64 {
            let call_id = format!("call-{index}");
            let digest = "7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8";
            history.push(HistoryItem::FunctionCall {
                call_id: call_id.clone(),
                name: "read_file".to_owned(),
                arguments_json: format!(r#"{{"target_file":"frame-{index}.png"}}"#),
            });
            history.push(HistoryItem::FunctionCallOutput {
                call_id: call_id.clone(),
                output: format!(
                    "read_file returned an attached image: image/png, 2x1, sha256={digest}"
                ),
            });
            history.push(
                HistoryItem::tool_media_attachment_with_origin(
                    call_id,
                    format!("frame-{index}.png"),
                    MediaType::Png,
                    2,
                    1,
                    digest,
                    vec![137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3],
                    index / 4,
                    "read_file",
                )
                .expect("attachment"),
            );
        }
        let receipt = apply_media_history_policy(&mut history).expect("window");
        let request = TurnRequest {
            turn_index: 2,
            model: "grok-4.5".to_owned(),
            history,
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: Some(receipt),
        };

        let body =
            serialize_request(&request, &settings(16 * 1024 * 1024)).expect("windowed request");
        let text = String::from_utf8(body).expect("utf8 JSON");
        assert_eq!(text.matches("\"type\":\"input_image\"").count(), 4);
        assert_eq!(text.matches("\"type\":\"function_call_output\"").count(), 8);
        assert_eq!(text.matches("media_history_eviction").count(), 4);
        assert!(text.contains("media_bytes_unavailable"));
        assert!(!text.contains("policy_sha256"));

        let mut forged = request.clone();
        forged
            .media_history_receipt
            .as_mut()
            .expect("receipt")
            .retained_count = 3;
        assert_eq!(
            serialize_request(&forged, &settings(16 * 1024 * 1024))
                .expect_err("forged stats")
                .code(),
            "provider_media_history_receipt_invalid"
        );

        let mut stale = request.clone();
        let HistoryItem::User { content } = &mut stale.history[0] else {
            panic!("user sentinel");
        };
        content.push_str(" tampered");
        assert_eq!(
            serialize_request(&stale, &settings(16 * 1024 * 1024))
                .expect_err("history hash mismatch")
                .code(),
            "provider_media_history_receipt_invalid"
        );

        let mut unwindowed = request;
        for index in 8..13_u64 {
            let call_id = format!("call-{index}");
            let digest = "7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8";
            unwindowed.history.push(HistoryItem::FunctionCall {
                call_id: call_id.clone(),
                name: "read_file".to_owned(),
                arguments_json: format!(r#"{{"target_file":"frame-{index}.png"}}"#),
            });
            unwindowed.history.push(HistoryItem::FunctionCallOutput {
                call_id: call_id.clone(),
                output: format!(
                    "read_file returned an attached image: image/png, 2x1, sha256={digest}"
                ),
            });
            unwindowed.history.push(
                HistoryItem::tool_media_attachment_with_origin(
                    call_id,
                    format!("frame-{index}.png"),
                    MediaType::Png,
                    2,
                    1,
                    digest,
                    vec![137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3],
                    2,
                    "read_file",
                )
                .expect("unwindowed attachment"),
            );
        }
        assert_eq!(
            serialize_request(&unwindowed, &settings(16 * 1024 * 1024))
                .expect_err("serializer remains a hard validator")
                .code(),
            "provider_media_count_exceeded"
        );
    }

    #[test]
    fn text_only_window_receipt_does_not_change_provider_request_bytes() {
        let history = vec![
            HistoryItem::System {
                content: "system".to_owned(),
            },
            HistoryItem::User {
                content: "text only".to_owned(),
            },
        ];
        let legacy = TurnRequest {
            turn_index: 0,
            model: "grok-4.5".to_owned(),
            history: history.clone(),
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: None,
        };
        let mut windowed_history = history;
        let receipt = apply_media_history_policy(&mut windowed_history).expect("text-only receipt");
        let windowed = TurnRequest {
            turn_index: 0,
            model: "grok-4.5".to_owned(),
            history: windowed_history,
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: Some(receipt),
        };
        assert_eq!(
            serialize_request(&legacy, &settings(16 * 1024 * 1024)).expect("legacy text request"),
            serialize_request(&windowed, &settings(16 * 1024 * 1024))
                .expect("windowed text request")
        );
    }

    #[test]
    fn rolling_media_64x4_chain_has_bounded_placeholder_cost_and_stable_send_bytes() {
        let mut history = vec![HistoryItem::User {
            content: "inspect sequence".to_owned(),
        }];
        let mut receipt = apply_media_history_policy(&mut history).expect("initial receipt");
        assert_eq!(receipt.retained_count(), 0);

        for batch in 0..64_u64 {
            for offset in 0..4_u64 {
                let index = batch * 4 + offset;
                let call_id = format!("c{index:03}{}", "x".repeat(252));
                let path = format!("p{index:03}-{}.png", "y".repeat(4087));
                assert_eq!(call_id.len(), 256);
                assert_eq!(path.len(), 4096);
                let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
                bytes.push(u8::try_from(index).expect("index byte"));
                let digest = format!("{:x}", Sha256::digest(&bytes));
                history.push(HistoryItem::FunctionCall {
                    call_id: call_id.clone(),
                    name: "read_file".to_owned(),
                    arguments_json: format!(r#"{{"target_file":"{path}"}}"#),
                });
                history.push(HistoryItem::FunctionCallOutput {
                    call_id: call_id.clone(),
                    output: format!(
                        "read_file returned an attached image: image/png, 2x1, sha256={digest}"
                    ),
                });
                history.push(
                    HistoryItem::tool_media_attachment_with_origin(
                        call_id,
                        path,
                        MediaType::Png,
                        2,
                        1,
                        digest,
                        bytes,
                        batch,
                        "read_file",
                    )
                    .expect("attachment"),
                );
            }
            let before_apply = history.len();
            receipt = apply_media_history_policy(&mut history).expect("window batch");
            assert_eq!(history.len(), before_apply);
            assert_eq!(history.len(), 1 + usize::try_from(batch + 1).unwrap() * 12);
            assert_eq!(receipt.retained_count(), 4);
            assert_eq!(receipt.evicted_total(), batch * 4);
        }

        let placeholders = history
            .iter()
            .filter_map(|item| match item {
                HistoryItem::MediaHistoryEviction { ledger } => Some(ledger),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(history.len(), 769);
        assert_eq!(placeholders.len(), 252);
        assert!(
            placeholders
                .iter()
                .map(|ledger| ledger.model_text().len())
                .sum::<usize>()
                <= placeholders.len() * 192
        );

        let request = TurnRequest {
            turn_index: 64,
            model: "grok-4.5".to_owned(),
            history: history.clone(),
            tools: Vec::new(),
            mode: ProviderRequestMode::ActionOpen,
            media_history_receipt: Some(receipt.clone()),
        };
        let first =
            serialize_request(&request, &settings(16 * 1024 * 1024)).expect("first stable send");
        let second =
            serialize_request(&request, &settings(16 * 1024 * 1024)).expect("second stable send");
        assert_eq!(first, second);

        let stable_history = history.clone();
        let replay_receipt = apply_media_history_policy(&mut history).expect("replay apply");
        assert_eq!(history, stable_history);
        assert_eq!(replay_receipt, receipt);
        let replay = serialize_request(
            &TurnRequest {
                history,
                media_history_receipt: Some(replay_receipt),
                ..request
            },
            &settings(16 * 1024 * 1024),
        )
        .expect("replay stable send");
        assert_eq!(first, replay);
        let text = String::from_utf8(first).expect("request JSON");
        assert_eq!(text.matches("\"type\":\"input_image\"").count(), 4);
        assert_eq!(
            text.matches("\"type\":\"function_call_output\"").count(),
            256
        );
        assert_eq!(text.matches("media_history_eviction").count(), 252);
        for hidden_field in [
            "origin_turn_index",
            "origin_tool_name",
            "logical_path",
            "mime_type",
            "byte_length",
            "media_bytes_visible",
        ] {
            assert!(!text.contains(hidden_field));
        }
        let body: serde_json::Value = serde_json::from_str(&text).expect("request object");
        let placeholder_texts = body["input"]
            .as_array()
            .expect("input")
            .iter()
            .filter_map(|item| item["content"].as_str())
            .filter(|content| content.contains("media_history_eviction"))
            .collect::<Vec<_>>();
        assert_eq!(placeholder_texts.len(), 252);
        assert!(placeholder_texts.iter().all(|content| {
            content.len() <= 192
                && content.contains("media_bytes_unavailable")
                && content.contains("call_id_sha256=")
                && !content.contains("read_file")
                && !content.contains(".png")
                && !content.contains("sha256=7f47")
        }));
    }
}
