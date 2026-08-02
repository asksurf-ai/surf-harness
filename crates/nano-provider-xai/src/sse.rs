//! Bounded incremental SSE decoding with terminal-only dispatch authority.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::types::{CompletedTurn, OutputItem, ProviderFailure};

use super::client::XaiProviderSettings;

pub(crate) struct ResponseStream {
    decoder: SseDecoder,
    expected_model: String,
    max_function_arguments_bytes: u64,
    max_json_depth: u64,
    next_sequence: Option<u64>,
    partial_calls: BTreeMap<u64, PartialCall>,
    completed: Option<CompletedTurn>,
    done: bool,
}

impl ResponseStream {
    pub(crate) fn new(settings: &XaiProviderSettings) -> Self {
        Self {
            decoder: SseDecoder::new(
                settings.max_sse_events,
                settings.max_sse_event_bytes,
                settings.max_sse_response_bytes,
            ),
            expected_model: settings.model.clone(),
            max_function_arguments_bytes: settings.max_function_arguments_bytes,
            max_json_depth: settings.max_json_depth,
            next_sequence: None,
            partial_calls: BTreeMap::new(),
            completed: None,
            done: false,
        }
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<(), ProviderFailure> {
        let frames = self.decoder.feed(bytes)?;
        for frame in frames {
            self.consume_frame(&frame)?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<CompletedTurn, ProviderFailure> {
        let frames = self.decoder.finish()?;
        for frame in frames {
            self.consume_frame(&frame)?;
        }
        self.completed
            .ok_or_else(|| ProviderFailure::new("provider_stream_incomplete"))
    }

    fn consume_frame(&mut self, frame: &[u8]) -> Result<(), ProviderFailure> {
        if frame == b"[DONE]" {
            if self.completed.is_none() {
                return Err(ProviderFailure::new("provider_done_before_completed"));
            }
            if self.done {
                return Err(ProviderFailure::new("provider_done_duplicate"));
            }
            self.done = true;
            return Ok(());
        }
        if self.completed.is_some() {
            return Err(ProviderFailure::new("provider_event_after_completed"));
        }
        let value: Value = serde_json::from_slice(frame)
            .map_err(|_| ProviderFailure::new("provider_event_json_invalid"))?;
        if value_depth(&value) > self.max_json_depth {
            return Err(ProviderFailure::new("provider_event_json_too_deep"));
        }
        if value.get("error").is_some() && value.get("type").is_none() {
            return Err(ProviderFailure::new("provider_error_envelope"));
        }
        self.observe_sequence(&value)?;
        let event_type = required_string(&value, "type", "provider_event_type_missing")?;
        match event_type {
            "response.completed" => self.consume_completed(&value),
            "response.incomplete" => Err(ProviderFailure::new("provider_response_incomplete")),
            "response.failed" => Err(ProviderFailure::new("provider_response_failed")),
            "error" | "response.error" => Err(ProviderFailure::new("provider_response_error")),
            "response.output_item.added" => self.observe_output_item(&value, true),
            "response.output_item.done" => self.observe_output_item(&value, false),
            "response.function_call_arguments.delta" => self.observe_arguments_delta(&value),
            "response.function_call_arguments.done" => self.observe_arguments_done(&value),
            event if is_allowed_intermediate(event) => self.validate_intermediate_model(&value),
            event if is_hosted_tool_event(event) => {
                Err(ProviderFailure::new("unsupported_server_tool"))
            }
            _ => Err(ProviderFailure::new("provider_protocol_unknown")),
        }
    }

    fn observe_sequence(&mut self, value: &Value) -> Result<(), ProviderFailure> {
        let Some(sequence) = value.get("sequence_number") else {
            return Ok(());
        };
        let sequence = sequence
            .as_u64()
            .ok_or_else(|| ProviderFailure::new("provider_sequence_invalid"))?;
        match self.next_sequence {
            None => {
                self.next_sequence = sequence.checked_add(1);
                if self.next_sequence.is_none() {
                    return Err(ProviderFailure::new("provider_sequence_invalid"));
                }
            }
            Some(expected) if sequence == expected => {
                self.next_sequence = sequence.checked_add(1);
                if self.next_sequence.is_none() {
                    return Err(ProviderFailure::new("provider_sequence_invalid"));
                }
            }
            Some(_) => return Err(ProviderFailure::new("provider_sequence_mismatch")),
        }
        Ok(())
    }

    fn validate_intermediate_model(&self, event: &Value) -> Result<(), ProviderFailure> {
        if let Some(model) = event.pointer("/response/model").and_then(Value::as_str)
            && model != self.expected_model
        {
            return Err(ProviderFailure::new("provider_model_drift"));
        }
        Ok(())
    }

    fn observe_output_item(&mut self, event: &Value, added: bool) -> Result<(), ProviderFailure> {
        let output_index = required_u64(event, "output_index", "provider_output_index_missing")?;
        let item = event
            .get("item")
            .and_then(Value::as_object)
            .ok_or_else(|| ProviderFailure::new("provider_output_item_invalid"))?;
        let item_type = item
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderFailure::new("provider_output_item_invalid"))?;
        if is_hosted_output_item(item_type) {
            return Err(ProviderFailure::new("unsupported_server_tool"));
        }
        if item_type != "function_call" {
            return Ok(());
        }
        let candidate = PartialCall {
            call_id: optional_string(item.get("call_id"))?,
            name: optional_string(item.get("name"))?,
            item_id: optional_string(item.get("id"))?,
            arguments: item
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            saw_delta: false,
        };
        if u64::try_from(candidate.arguments.len()).unwrap_or(u64::MAX)
            > self.max_function_arguments_bytes
        {
            return Err(ProviderFailure::new(
                "provider_function_arguments_too_large",
            ));
        }
        match self.partial_calls.get_mut(&output_index) {
            None => {
                self.partial_calls.insert(output_index, candidate);
            }
            Some(_) if added => {
                return Err(ProviderFailure::new("provider_output_index_duplicate"));
            }
            Some(existing) => {
                reconcile_optional(&existing.call_id, &candidate.call_id)?;
                reconcile_optional(&existing.name, &candidate.name)?;
                reconcile_optional(&existing.item_id, &candidate.item_id)?;
                if !candidate.arguments.is_empty()
                    && existing.arguments != candidate.arguments
                    && (existing.saw_delta || !existing.arguments.is_empty())
                {
                    return Err(ProviderFailure::new("provider_function_arguments_mismatch"));
                }
                if existing.call_id.is_none() {
                    existing.call_id = candidate.call_id;
                }
                if existing.name.is_none() {
                    existing.name = candidate.name;
                }
                if existing.item_id.is_none() {
                    existing.item_id = candidate.item_id;
                }
                if !candidate.arguments.is_empty() {
                    existing.arguments = candidate.arguments;
                }
            }
        }
        Ok(())
    }

    fn observe_arguments_delta(&mut self, event: &Value) -> Result<(), ProviderFailure> {
        let output_index = required_u64(event, "output_index", "provider_output_index_missing")?;
        let delta = required_string(event, "delta", "provider_arguments_delta_missing")?;
        let call = self
            .partial_calls
            .get_mut(&output_index)
            .ok_or_else(|| ProviderFailure::new("provider_arguments_without_call"))?;
        if let Some(item_id) = event.get("item_id").and_then(Value::as_str)
            && call.item_id.as_deref().is_some_and(|id| id != item_id)
        {
            return Err(ProviderFailure::new("provider_call_item_mismatch"));
        }
        call.arguments.push_str(delta);
        call.saw_delta = true;
        if u64::try_from(call.arguments.len()).unwrap_or(u64::MAX)
            > self.max_function_arguments_bytes
        {
            return Err(ProviderFailure::new(
                "provider_function_arguments_too_large",
            ));
        }
        Ok(())
    }

    fn observe_arguments_done(&mut self, event: &Value) -> Result<(), ProviderFailure> {
        let output_index = required_u64(event, "output_index", "provider_output_index_missing")?;
        let call = self
            .partial_calls
            .get_mut(&output_index)
            .ok_or_else(|| ProviderFailure::new("provider_arguments_without_call"))?;
        if let Some(item_id) = event.get("item_id").and_then(Value::as_str)
            && call.item_id.as_deref().is_some_and(|id| id != item_id)
        {
            return Err(ProviderFailure::new("provider_call_item_mismatch"));
        }
        if let Some(arguments) = event.get("arguments").and_then(Value::as_str) {
            if call.saw_delta && call.arguments != arguments {
                return Err(ProviderFailure::new("provider_function_arguments_mismatch"));
            }
            call.arguments = arguments.to_owned();
        }
        Ok(())
    }

    fn consume_completed(&mut self, event: &Value) -> Result<(), ProviderFailure> {
        let response = event
            .get("response")
            .and_then(Value::as_object)
            .ok_or_else(|| ProviderFailure::new("provider_completed_invalid"))?;
        if response.get("object").and_then(Value::as_str) != Some("response")
            || response.get("status").and_then(Value::as_str) != Some("completed")
        {
            return Err(ProviderFailure::new("provider_completed_invalid"));
        }
        let response_id = response
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ProviderFailure::new("provider_response_id_missing"))?
            .to_owned();
        let model = response
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderFailure::new("provider_model_missing"))?;
        if model != self.expected_model {
            return Err(ProviderFailure::new("provider_model_drift"));
        }
        let raw_output = response
            .get("output")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderFailure::new("provider_output_missing"))?;
        let mut output = Vec::with_capacity(raw_output.len());
        for (index, item) in raw_output.iter().enumerate() {
            output.push(parse_output_item(item)?);
            if let Some(partial) = self.partial_calls.get(&(index as u64)) {
                let OutputItem::FunctionCall {
                    call_id,
                    name,
                    arguments_json,
                } = output.last().expect("just pushed output")
                else {
                    return Err(ProviderFailure::new("provider_call_reconciliation_failed"));
                };
                if partial.call_id.as_deref().is_some_and(|id| id != call_id)
                    || partial.name.as_deref().is_some_and(|value| value != name)
                {
                    return Err(ProviderFailure::new("provider_call_reconciliation_failed"));
                }
                if (partial.saw_delta || !partial.arguments.is_empty())
                    && partial.arguments != *arguments_json
                {
                    return Err(ProviderFailure::new("provider_function_arguments_mismatch"));
                }
            }
        }
        if self
            .partial_calls
            .keys()
            .any(|index| usize::try_from(*index).map_or(true, |index| index >= output.len()))
        {
            return Err(ProviderFailure::new("provider_call_reconciliation_failed"));
        }
        let usage = response
            .get("usage")
            .cloned()
            .filter(|value| !value.is_null())
            .map(normalize_usage_cost_alias)
            .transpose()?;
        let service_tier = response
            .get("service_tier")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let system_fingerprint = response
            .get("system_fingerprint")
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.completed = Some(CompletedTurn {
            response_id,
            model: model.to_owned(),
            output,
            usage,
            service_tier,
            system_fingerprint,
        });
        Ok(())
    }
}

fn normalize_usage_cost_alias(mut usage: Value) -> Result<Value, ProviderFailure> {
    if let Some(fields) = usage.as_object_mut()
        && let Some(canonical) = fields.get("cost_in_usd_ticks").cloned()
    {
        match fields.get("provider_cost_ticks") {
            Some(alias) if alias != &canonical => {
                return Err(ProviderFailure::new("provider_usage_cost_conflict"));
            }
            None => {
                fields.insert("provider_cost_ticks".to_owned(), canonical);
            }
            _ => {}
        }
    }
    Ok(usage)
}

#[derive(Default)]
struct PartialCall {
    call_id: Option<String>,
    name: Option<String>,
    item_id: Option<String>,
    arguments: String,
    saw_delta: bool,
}

fn parse_output_item(value: &Value) -> Result<OutputItem, ProviderFailure> {
    let object = value
        .as_object()
        .ok_or_else(|| ProviderFailure::new("provider_output_item_invalid"))?;
    let item_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderFailure::new("provider_output_item_invalid"))?;
    if is_hosted_output_item(item_type) {
        return Err(ProviderFailure::new("unsupported_server_tool"));
    }
    match item_type {
        "reasoning" => Ok(OutputItem::Reasoning {
            id: optional_string(object.get("id"))?,
            summary: object
                .get("summary")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
            encrypted_content: optional_string(object.get("encrypted_content"))?,
            content: object
                .get("content")
                .cloned()
                .filter(|value| !value.is_null()),
        }),
        "function_call" => Ok(OutputItem::FunctionCall {
            call_id: required_object_string(object, "call_id", "provider_call_id_invalid")?
                .to_owned(),
            name: required_object_string(object, "name", "provider_tool_unknown")?.to_owned(),
            arguments_json: required_object_string(
                object,
                "arguments",
                "provider_function_arguments_invalid",
            )?
            .to_owned(),
        }),
        "message" => {
            if object.get("role").and_then(Value::as_str) != Some("assistant") {
                return Err(ProviderFailure::new("provider_message_role_invalid"));
            }
            let content = object
                .get("content")
                .and_then(Value::as_array)
                .ok_or_else(|| ProviderFailure::new("provider_message_content_invalid"))?;
            let mut text = String::new();
            for part in content {
                match part.get("type").and_then(Value::as_str) {
                    Some("output_text") => {
                        text.push_str(part.get("text").and_then(Value::as_str).ok_or_else(
                            || ProviderFailure::new("provider_message_content_invalid"),
                        )?);
                    }
                    Some("refusal") => {
                        return Err(ProviderFailure::new("provider_refusal"));
                    }
                    _ => {
                        return Err(ProviderFailure::new("provider_message_content_unknown"));
                    }
                }
            }
            Ok(OutputItem::AssistantMessage { text })
        }
        _ => Err(ProviderFailure::new("provider_output_item_unknown")),
    }
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, ProviderFailure> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ProviderFailure::new("provider_string_field_invalid")),
    }
}

fn required_string<'a>(
    value: &'a Value,
    field: &str,
    code: &'static str,
) -> Result<&'a str, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderFailure::new(code))
}

fn required_object_string<'a>(
    value: &'a serde_json::Map<String, Value>,
    field: &str,
    code: &'static str,
) -> Result<&'a str, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProviderFailure::new(code))
}

fn required_u64(value: &Value, field: &str, code: &'static str) -> Result<u64, ProviderFailure> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ProviderFailure::new(code))
}

fn reconcile_optional(
    left: &Option<String>,
    right: &Option<String>,
) -> Result<(), ProviderFailure> {
    if left
        .as_deref()
        .zip(right.as_deref())
        .is_some_and(|(left, right)| left != right)
    {
        return Err(ProviderFailure::new("provider_call_reconciliation_failed"));
    }
    Ok(())
}

fn is_allowed_intermediate(event: &str) -> bool {
    matches!(
        event,
        "response.created"
            | "response.in_progress"
            | "response.queued"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.output_text.delta"
            | "response.output_text.done"
            | "response.refusal.delta"
            | "response.refusal.done"
            | "response.reasoning_summary_part.added"
            | "response.reasoning_summary_part.done"
            | "response.reasoning_summary_text.delta"
            | "response.reasoning_summary_text.done"
            | "response.reasoning_text.delta"
            | "response.reasoning_text.done"
            | "response.output_text.annotation.added"
    )
}

fn is_hosted_tool_event(event: &str) -> bool {
    [
        "web_search",
        "file_search",
        "computer",
        "code_interpreter",
        "image_generation",
        "mcp_",
        "local_shell",
        "custom_tool",
    ]
    .iter()
    .any(|needle| event.contains(needle))
}

fn is_hosted_output_item(item_type: &str) -> bool {
    item_type != "reasoning"
        && item_type != "function_call"
        && item_type != "message"
        && [
            "search",
            "computer",
            "code_interpreter",
            "image_generation",
            "mcp",
            "shell",
            "custom_tool",
        ]
        .iter()
        .any(|needle| item_type.contains(needle))
}

fn value_depth(value: &Value) -> u64 {
    match value {
        Value::Array(values) => 1 + values.iter().map(value_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(value_depth).max().unwrap_or(0),
        _ => 1,
    }
}

struct SseDecoder {
    pending: Vec<u8>,
    data_lines: Vec<Vec<u8>>,
    first_line: bool,
    emitted_events: u64,
    received_bytes: u64,
    max_events: u64,
    max_event_bytes: u64,
    max_response_bytes: u64,
}

impl SseDecoder {
    fn new(max_events: u64, max_event_bytes: u64, max_response_bytes: u64) -> Self {
        Self {
            pending: Vec::new(),
            data_lines: Vec::new(),
            first_line: true,
            emitted_events: 0,
            received_bytes: 0,
            max_events,
            max_event_bytes,
            max_response_bytes,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProviderFailure> {
        self.received_bytes = self
            .received_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| ProviderFailure::new("provider_stream_too_large"))?;
        if self.received_bytes > self.max_response_bytes {
            return Err(ProviderFailure::new("provider_stream_too_large"));
        }
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(position) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line = self.pending.drain(..=position).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.consume_line(line, &mut frames)?;
        }
        if u64::try_from(self.pending.len()).unwrap_or(u64::MAX) > self.max_event_bytes {
            return Err(ProviderFailure::new("provider_sse_event_too_large"));
        }
        Ok(frames)
    }

    fn finish(&mut self) -> Result<Vec<Vec<u8>>, ProviderFailure> {
        let mut frames = Vec::new();
        if !self.pending.is_empty() {
            let mut line = std::mem::take(&mut self.pending);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.consume_line(line, &mut frames)?;
        }
        self.emit_frame(&mut frames)?;
        Ok(frames)
    }

    fn consume_line(
        &mut self,
        mut line: Vec<u8>,
        frames: &mut Vec<Vec<u8>>,
    ) -> Result<(), ProviderFailure> {
        if self.first_line {
            self.first_line = false;
            if line.starts_with(&[0xef, 0xbb, 0xbf]) {
                line.drain(..3);
            }
        }
        if line.is_empty() {
            return self.emit_frame(frames);
        }
        if line[0] == b':' {
            return Ok(());
        }
        let separator = line.iter().position(|byte| *byte == b':');
        let (field, mut value) = match separator {
            Some(position) => (&line[..position], &line[position + 1..]),
            None => (line.as_slice(), &[][..]),
        };
        if value.first() == Some(&b' ') {
            value = &value[1..];
        }
        if field == b"data" {
            let projected = self
                .data_lines
                .iter()
                .map(Vec::len)
                .sum::<usize>()
                .saturating_add(value.len())
                .saturating_add(self.data_lines.len());
            if u64::try_from(projected).unwrap_or(u64::MAX) > self.max_event_bytes {
                return Err(ProviderFailure::new("provider_sse_event_too_large"));
            }
            self.data_lines.push(value.to_vec());
        }
        Ok(())
    }

    fn emit_frame(&mut self, frames: &mut Vec<Vec<u8>>) -> Result<(), ProviderFailure> {
        if self.data_lines.is_empty() {
            return Ok(());
        }
        if self.emitted_events >= self.max_events {
            return Err(ProviderFailure::new("provider_sse_event_limit_exceeded"));
        }
        self.emitted_events += 1;
        frames.push(self.data_lines.join(&b'\n'));
        self.data_lines.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::{ResponseStream, SseDecoder};
    use crate::client::XaiProviderSettings;

    fn settings() -> XaiProviderSettings {
        XaiProviderSettings {
            model: "grok-4.5".to_owned(),
            reasoning_effort: "high".to_owned(),
            include: vec![],
            parallel_tool_calls: true,
            tool_choice: "auto".to_owned(),
            service_tier: "default".to_owned(),
            max_output_tokens: 64,
            max_request_body_bytes: 1024,
            max_function_arguments_bytes: 1024,
            max_sse_events: 32,
            max_sse_event_bytes: 4096,
            max_sse_response_bytes: 8192,
            max_json_depth: 32,
            connect_timeout: Duration::from_secs(1),
            first_event_timeout: Duration::from_secs(1),
            inter_event_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(1),
        }
    }

    fn completed_event(usage: Value) -> String {
        format!(
            "data: {}\n\n",
            json!({
                "type": "response.completed",
                "sequence_number": 0,
                "response": {
                    "id": "resp",
                    "object": "response",
                    "model": "grok-4.5",
                    "status": "completed",
                    "output": [],
                    "usage": usage
                }
            })
        )
    }

    #[test]
    fn decoder_handles_bom_comments_multidata_and_arbitrary_splits() {
        let bytes = b"\xef\xbb\xbf: comment\r\ndata: {\"type\":\"response.created\",\r\ndata: \"sequence_number\":0}\r\n\r\n";
        let mut decoder = SseDecoder::new(4, 1024, 2048);
        let mut frames = Vec::new();
        for byte in bytes {
            frames.extend(decoder.feed(&[*byte]).expect("decode split byte"));
        }
        frames.extend(decoder.finish().expect("finish"));
        assert_eq!(
            frames,
            [b"{\"type\":\"response.created\",\n\"sequence_number\":0}".to_vec()]
        );
    }

    #[test]
    fn terminal_call_must_match_streamed_arguments() {
        let stream = concat!(
            "data: {\"type\":\"response.output_item.added\",\"sequence_number\":0,\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc-1\",\"call_id\":\"call-1\",\"name\":\"run_terminal_command\",\"arguments\":\"\"}}\n\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"sequence_number\":1,\"item_id\":\"fc-1\",\"output_index\":0,\"delta\":\"{\\\"command\\\":\\\"pwd\\\"}\"}\n\n",
            "data: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"resp\",\"object\":\"response\",\"model\":\"grok-4.5\",\"status\":\"completed\",\"output\":[{\"type\":\"function_call\",\"call_id\":\"call-1\",\"name\":\"run_terminal_command\",\"arguments\":\"{}\"}]}}\n\n"
        );
        let mut response = ResponseStream::new(&settings());
        let error = response.feed(stream.as_bytes()).expect_err("mismatch");
        assert_eq!(error.code(), "provider_function_arguments_mismatch");
    }

    #[test]
    fn terminal_call_identity_must_match_streamed_item() {
        let stream = concat!(
            "data: {\"type\":\"response.output_item.added\",\"sequence_number\":0,\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc-1\",\"call_id\":\"call-1\",\"name\":\"run_terminal_command\",\"arguments\":\"\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"id\":\"resp\",\"object\":\"response\",\"model\":\"grok-4.5\",\"status\":\"completed\",\"output\":[{\"type\":\"function_call\",\"call_id\":\"call-2\",\"name\":\"run_terminal_command\",\"arguments\":\"{}\"}]}}\n\n"
        );
        let mut response = ResponseStream::new(&settings());
        let error = response
            .feed(stream.as_bytes())
            .expect_err("identity mismatch");
        assert_eq!(error.code(), "provider_call_reconciliation_failed");
    }

    #[test]
    fn native_cost_ticks_are_mirrored_without_replacing_canonical_usage() {
        let event = completed_event(json!({
            "input_tokens": 10,
            "output_tokens": 3,
            "cost_in_usd_ticks": 123_000_000,
            "future_usage_field": {"preserved": true}
        }));
        let mut response = ResponseStream::new(&settings());
        response.feed(event.as_bytes()).expect("completed event");
        let completed = response.finish().expect("completed response");

        assert_eq!(
            completed.usage,
            Some(json!({
                "input_tokens": 10,
                "output_tokens": 3,
                "cost_in_usd_ticks": 123_000_000,
                "provider_cost_ticks": 123_000_000,
                "future_usage_field": {"preserved": true}
            }))
        );
    }

    #[test]
    fn conflicting_native_and_runtime_cost_ticks_fail_closed() {
        let event = completed_event(json!({
            "input_tokens": 10,
            "output_tokens": 3,
            "cost_in_usd_ticks": 123,
            "provider_cost_ticks": 124
        }));
        let mut response = ResponseStream::new(&settings());

        let error = response
            .feed(event.as_bytes())
            .expect_err("conflicting cost aliases");
        assert_eq!(error.code(), "provider_usage_cost_conflict");
    }
}
