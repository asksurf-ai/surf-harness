//! Provider-completed turn and stateless-history types.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use nano_types::external_tool::{
    MEDIA_HISTORY_POLICY_SHA256, MEDIA_HISTORY_POLICY_VERSION, READ_FILE_MEDIA_MAX_BYTES,
    READ_FILE_MEDIA_MAX_DIMENSION, READ_FILE_MEDIA_MAX_HISTORY_BYTES,
    READ_FILE_MEDIA_MAX_HISTORY_ITEMS, READ_FILE_MEDIA_MAX_PIXELS,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnRequest {
    pub turn_index: u64,
    pub model: String,
    pub history: Vec<HistoryItem>,
    pub tools: Vec<FunctionTool>,
    #[serde(default)]
    pub mode: ProviderRequestMode,
    /// `None` is the explicit legacy/no-window mode. Live R4 requests use a
    /// hash-bound receipt produced after the canonical history commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_history_receipt: Option<MediaHistoryPolicyReceiptV1>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRequestMode {
    #[default]
    ActionOpen,
    /// Preserve the request's tool definitions so function-call history remains
    /// schema-closed, but ask the provider not to emit any new tool calls.
    FinalOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub enum HistoryItem {
    System {
        content: String,
    },
    User {
        content: String,
    },
    AssistantMessage {
        text: String,
    },
    Reasoning {
        id: Option<String>,
        summary: Value,
        encrypted_content: Option<String>,
        content: Option<Value>,
    },
    FunctionCall {
        call_id: String,
        name: String,
        arguments_json: String,
    },
    FunctionCallOutput {
        call_id: String,
        output: String,
    },
    ToolMediaAttachment {
        attachment: ToolMediaAttachment,
    },
    MediaHistoryEviction {
        ledger: MediaHistoryEvictionLedger,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
}

impl MediaType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }

    fn magic(self) -> &'static [u8] {
        match self {
            Self::Png => b"\x89PNG\r\n\x1a\n",
            Self::Jpeg => b"\xff\xd8\xff",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolMediaAttachment {
    call_id: String,
    logical_path: String,
    mime_type: MediaType,
    width: u64,
    height: u64,
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<ToolMediaOrigin>,
    #[serde(skip, default)]
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolMediaOrigin {
    turn_index: u64,
    tool_name: String,
}

impl fmt::Debug for ToolMediaAttachment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolMediaAttachment")
            .field("call_id", &self.call_id)
            .field("logical_path", &self.logical_path)
            .field("mime_type", &self.mime_type)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("byte_length", &self.bytes.len())
            .field("sha256", &self.sha256)
            .field("origin", &self.origin)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl ToolMediaAttachment {
    #[allow(clippy::too_many_arguments)]
    fn new(
        call_id: impl Into<String>,
        logical_path: impl Into<String>,
        mime_type: MediaType,
        width: u64,
        height: u64,
        sha256: impl Into<String>,
        bytes: Vec<u8>,
        origin: Option<ToolMediaOrigin>,
    ) -> Result<Self, ProviderFailure> {
        let attachment = Self {
            call_id: call_id.into(),
            logical_path: logical_path.into(),
            mime_type,
            width,
            height,
            sha256: sha256.into(),
            origin,
            bytes,
        };
        attachment.validate()?;
        Ok(attachment)
    }

    pub(crate) fn validate(&self) -> Result<(), ProviderFailure> {
        let valid_path = !self.logical_path.is_empty()
            && !self.logical_path.starts_with('/')
            && self.logical_path.len() <= 4096
            && !self.logical_path.chars().any(char::is_control)
            && self
                .logical_path
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | ".."));
        let valid_hash = self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && format!("{:x}", Sha256::digest(&self.bytes)) == self.sha256;
        let valid_origin = self.origin.as_ref().is_none_or(|origin| {
            !origin.tool_name.is_empty()
                && origin.tool_name.len() <= 256
                && !origin.tool_name.chars().any(char::is_control)
        });
        if self.call_id.is_empty()
            || self.call_id.len() > 256
            || self.call_id.chars().any(char::is_control)
            || !valid_path
            || self.width == 0
            || self.width > READ_FILE_MEDIA_MAX_DIMENSION
            || self.height == 0
            || self.height > READ_FILE_MEDIA_MAX_DIMENSION
            || self
                .width
                .checked_mul(self.height)
                .is_none_or(|pixels| pixels > READ_FILE_MEDIA_MAX_PIXELS)
            || self.bytes.is_empty()
            || u64::try_from(self.bytes.len()).unwrap_or(u64::MAX) > READ_FILE_MEDIA_MAX_BYTES
            || !self.bytes.starts_with(self.mime_type.magic())
            || !valid_hash
            || !valid_origin
        {
            return Err(ProviderFailure::new("provider_media_attachment_invalid"));
        }
        Ok(())
    }

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    pub fn mime_type(&self) -> MediaType {
        self.mime_type
    }

    pub fn width(&self) -> u64 {
        self.width
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn origin(&self) -> Option<&ToolMediaOrigin> {
        self.origin.as_ref()
    }
}

impl HistoryItem {
    #[allow(clippy::too_many_arguments)]
    pub fn tool_media_attachment(
        call_id: impl Into<String>,
        logical_path: impl Into<String>,
        mime_type: MediaType,
        width: u64,
        height: u64,
        sha256: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, ProviderFailure> {
        Ok(Self::ToolMediaAttachment {
            attachment: ToolMediaAttachment::new(
                call_id,
                logical_path,
                mime_type,
                width,
                height,
                sha256,
                bytes,
                None,
            )?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tool_media_attachment_with_origin(
        call_id: impl Into<String>,
        logical_path: impl Into<String>,
        mime_type: MediaType,
        width: u64,
        height: u64,
        sha256: impl Into<String>,
        bytes: Vec<u8>,
        turn_index: u64,
        tool_name: impl Into<String>,
    ) -> Result<Self, ProviderFailure> {
        Ok(Self::ToolMediaAttachment {
            attachment: ToolMediaAttachment::new(
                call_id,
                logical_path,
                mime_type,
                width,
                height,
                sha256,
                bytes,
                Some(ToolMediaOrigin {
                    turn_index,
                    tool_name: tool_name.into(),
                }),
            )?,
        })
    }
}

/// Model-visible, byte-free provenance left at the exact history position of
/// an attachment evicted from future provider context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaHistoryEvictionLedger {
    origin_turn_index: u64,
    origin_tool_name: String,
    call_id: String,
    logical_path: String,
    mime_type: MediaType,
    width: u64,
    height: u64,
    byte_length: u64,
    sha256: String,
    media_bytes_visible: bool,
}

impl MediaHistoryEvictionLedger {
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn media_bytes_visible(&self) -> bool {
        self.media_bytes_visible
    }

    pub(crate) fn model_text(&self) -> String {
        let call_id_sha256 = format!("{:x}", Sha256::digest(self.call_id.as_bytes()));
        format!("[media_history_eviction media_bytes_unavailable call_id_sha256={call_id_sha256}]")
    }

    fn validate(&self) -> Result<(), ProviderFailure> {
        let valid_hash = self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if self.origin_tool_name.is_empty()
            || self.origin_tool_name.len() > 256
            || self.origin_tool_name.chars().any(char::is_control)
            || self.call_id.is_empty()
            || self.call_id.len() > 256
            || self.call_id.chars().any(char::is_control)
            || self.logical_path.is_empty()
            || self.logical_path.starts_with('/')
            || self.logical_path.len() > 4096
            || self.logical_path.chars().any(char::is_control)
            || self
                .logical_path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || self.width == 0
            || self.width > READ_FILE_MEDIA_MAX_DIMENSION
            || self.height == 0
            || self.height > READ_FILE_MEDIA_MAX_DIMENSION
            || self
                .width
                .checked_mul(self.height)
                .is_none_or(|pixels| pixels > READ_FILE_MEDIA_MAX_PIXELS)
            || self.byte_length == 0
            || self.byte_length > READ_FILE_MEDIA_MAX_BYTES
            || !valid_hash
            || self.media_bytes_visible
        {
            return Err(ProviderFailure::new(
                "provider_media_history_ledger_invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct MediaHistoryPolicyBindingBody<'a> {
    policy_version: &'a str,
    max_items: u64,
    max_bytes: u64,
}

pub fn media_history_policy_sha256() -> Result<String, ProviderFailure> {
    let body = MediaHistoryPolicyBindingBody {
        policy_version: MEDIA_HISTORY_POLICY_VERSION,
        max_items: READ_FILE_MEDIA_MAX_HISTORY_ITEMS,
        max_bytes: READ_FILE_MEDIA_MAX_HISTORY_BYTES,
    };
    let bytes = serde_json::to_vec(&body)
        .map_err(|_| ProviderFailure::new("provider_media_history_policy_invalid"))?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest != MEDIA_HISTORY_POLICY_SHA256 {
        return Err(ProviderFailure::new(
            "provider_media_history_policy_invalid",
        ));
    }
    Ok(digest)
}

/// Dynamic receipt for the one compiled rolling-media policy. The V1 Rust type
/// carries the version; fixed policy identity and caps are not repeated per
/// request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaHistoryPolicyReceiptV1 {
    history_sha256: String,
    pub(crate) retained_count: u64,
    retained_bytes: u64,
    evicted_total: u64,
}

impl MediaHistoryPolicyReceiptV1 {
    pub const POLICY_VERSION: &'static str = MEDIA_HISTORY_POLICY_VERSION;

    pub fn history_sha256(&self) -> &str {
        &self.history_sha256
    }

    pub fn retained_count(&self) -> u64 {
        self.retained_count
    }

    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }

    pub fn evicted_total(&self) -> u64 {
        self.evicted_total
    }
}

/// A fully validated next-history candidate. Construction never mutates the
/// completed history boundary supplied by the caller.
#[derive(Debug)]
pub struct PreparedMediaHistoryBatch {
    history: Vec<HistoryItem>,
    receipt: MediaHistoryPolicyReceiptV1,
}

impl PreparedMediaHistoryBatch {
    pub fn into_parts(self) -> (Vec<HistoryItem>, MediaHistoryPolicyReceiptV1) {
        (self.history, self.receipt)
    }
}

/// Prepare one tool turn as an indivisible history batch.
///
/// `additions` has one closed order: every function output in `expected_call_ids`
/// order, followed by an optional media attachment subset in that same order.
/// Validation and rolling eviction happen only on an owned clone.
pub fn prepare_media_history_batch(
    base: &[HistoryItem],
    turn_index: u64,
    expected_call_ids: &[String],
    additions: Vec<HistoryItem>,
) -> Result<PreparedMediaHistoryBatch, ProviderFailure> {
    if expected_call_ids.is_empty()
        || additions.len() < expected_call_ids.len()
        || additions.len() > expected_call_ids.len().saturating_mul(2)
    {
        return Err(ProviderFailure::new("provider_media_batch_invalid"));
    }

    let mut expected = BTreeMap::<&str, (&str, usize)>::new();
    for (position, call_id) in expected_call_ids.iter().enumerate() {
        if call_id.is_empty() || expected.insert(call_id.as_str(), ("", position)).is_some() {
            return Err(ProviderFailure::new("provider_media_batch_invalid"));
        }
    }
    for item in base {
        if let HistoryItem::FunctionCall { call_id, name, .. } = item
            && let Some(entry) = expected.get_mut(call_id.as_str())
        {
            if !entry.0.is_empty() {
                return Err(ProviderFailure::new("provider_media_batch_invalid"));
            }
            entry.0 = name;
        }
    }
    if expected.values().any(|(tool_name, _)| tool_name.is_empty()) {
        return Err(ProviderFailure::new("provider_media_batch_invalid"));
    }

    for (position, expected_call_id) in expected_call_ids.iter().enumerate() {
        if !matches!(
            &additions[position],
            HistoryItem::FunctionCallOutput { call_id, .. } if call_id == expected_call_id
        ) {
            return Err(ProviderFailure::new("provider_media_batch_invalid"));
        }
    }

    let mut previous_attachment_position = None;
    let mut batch_media_bytes = 0_u64;
    for item in &additions[expected_call_ids.len()..] {
        let HistoryItem::ToolMediaAttachment { attachment } = item else {
            return Err(ProviderFailure::new("provider_media_batch_invalid"));
        };
        attachment.validate()?;
        let Some((expected_tool_name, position)) = expected.get(attachment.call_id()).copied()
        else {
            return Err(ProviderFailure::new("provider_media_batch_invalid"));
        };
        if previous_attachment_position.is_some_and(|previous| previous >= position) {
            return Err(ProviderFailure::new("provider_media_batch_invalid"));
        }
        let Some(origin) = attachment.origin() else {
            return Err(ProviderFailure::new(
                "provider_media_history_origin_invalid",
            ));
        };
        if origin.turn_index != turn_index || origin.tool_name != expected_tool_name {
            return Err(ProviderFailure::new(
                "provider_media_history_origin_invalid",
            ));
        }
        batch_media_bytes = batch_media_bytes
            .checked_add(u64::try_from(attachment.bytes().len()).unwrap_or(u64::MAX))
            .ok_or_else(|| ProviderFailure::new("provider_media_history_bytes_exceeded"))?;
        previous_attachment_position = Some(position);
    }
    if batch_media_bytes > READ_FILE_MEDIA_MAX_HISTORY_BYTES {
        return Err(ProviderFailure::new(
            "provider_media_history_bytes_exceeded",
        ));
    }

    let mut history = base.to_vec();
    history.extend(additions);
    let receipt = apply_media_history_policy(&mut history)?;
    Ok(PreparedMediaHistoryBatch { history, receipt })
}

#[derive(Default)]
struct MediaHistoryStats {
    retained_count: u64,
    retained_bytes: u64,
    evicted_total: u64,
}

struct MediaHistoryInspection {
    stats: MediaHistoryStats,
    attachment_indices: Vec<usize>,
}

/// Apply the one live policy. Limits are imported from the provider capability
/// constants; callers cannot negotiate a second runtime copy.
pub fn apply_media_history_policy(
    history: &mut [HistoryItem],
) -> Result<MediaHistoryPolicyReceiptV1, ProviderFailure> {
    apply_media_history_policy_with_limits(
        history,
        READ_FILE_MEDIA_MAX_HISTORY_ITEMS,
        READ_FILE_MEDIA_MAX_HISTORY_BYTES,
    )
}

fn apply_media_history_policy_with_limits(
    history: &mut [HistoryItem],
    max_items: u64,
    max_bytes: u64,
) -> Result<MediaHistoryPolicyReceiptV1, ProviderFailure> {
    let inspection = inspect_media_history(history)?;
    let attachment_indices = inspection.attachment_indices;
    let mut retained_count = 0_u64;
    let mut retained_bytes = 0_u64;
    let mut retain_from = attachment_indices.len();
    for (position, index) in attachment_indices.iter().enumerate().rev() {
        let HistoryItem::ToolMediaAttachment { attachment } = &history[*index] else {
            unreachable!("attachment index");
        };
        let next_count = retained_count.saturating_add(1);
        let next_bytes =
            retained_bytes.checked_add(u64::try_from(attachment.bytes().len()).unwrap_or(u64::MAX));
        if next_count > max_items || next_bytes.is_none_or(|bytes| bytes > max_bytes) {
            break;
        }
        retained_count = next_count;
        retained_bytes = next_bytes.unwrap_or(u64::MAX);
        retain_from = position;
    }

    let evicted_indices = &attachment_indices[..retain_from];
    for index in evicted_indices {
        let HistoryItem::ToolMediaAttachment { attachment } = &history[*index] else {
            unreachable!("attachment index");
        };
        let origin = attachment
            .origin()
            .ok_or_else(|| ProviderFailure::new("provider_media_history_origin_invalid"))?;
        let ledger = MediaHistoryEvictionLedger {
            origin_turn_index: origin.turn_index,
            origin_tool_name: origin.tool_name.clone(),
            call_id: attachment.call_id.clone(),
            logical_path: attachment.logical_path.clone(),
            mime_type: attachment.mime_type,
            width: attachment.width,
            height: attachment.height,
            byte_length: u64::try_from(attachment.bytes.len()).unwrap_or(u64::MAX),
            sha256: attachment.sha256.clone(),
            media_bytes_visible: false,
        };
        history[*index] = HistoryItem::MediaHistoryEviction { ledger };
    }
    let stats = MediaHistoryStats {
        retained_count,
        retained_bytes,
        evicted_total: inspection
            .stats
            .evicted_total
            .saturating_add(u64::try_from(evicted_indices.len()).unwrap_or(u64::MAX)),
    };
    build_media_history_receipt(history, stats)
}

pub(crate) fn validate_media_history_policy_receipt(
    history: &[HistoryItem],
    receipt: &MediaHistoryPolicyReceiptV1,
) -> Result<(), ProviderFailure> {
    let inspection = inspect_media_history(history)?;
    if inspection.stats.retained_count > READ_FILE_MEDIA_MAX_HISTORY_ITEMS {
        return Err(ProviderFailure::new("provider_media_count_exceeded"));
    }
    if inspection.stats.retained_bytes > READ_FILE_MEDIA_MAX_HISTORY_BYTES {
        return Err(ProviderFailure::new(
            "provider_media_history_bytes_exceeded",
        ));
    }
    let expected = build_media_history_receipt(history, inspection.stats)?;
    if receipt != &expected {
        return Err(ProviderFailure::new(
            "provider_media_history_receipt_invalid",
        ));
    }
    Ok(())
}

fn build_media_history_receipt(
    history: &[HistoryItem],
    stats: MediaHistoryStats,
) -> Result<MediaHistoryPolicyReceiptV1, ProviderFailure> {
    let history_bytes = serde_json::to_vec(history)
        .map_err(|_| ProviderFailure::new("provider_media_history_receipt_invalid"))?;
    Ok(MediaHistoryPolicyReceiptV1 {
        history_sha256: format!("{:x}", Sha256::digest(history_bytes)),
        retained_count: stats.retained_count,
        retained_bytes: stats.retained_bytes,
        evicted_total: stats.evicted_total,
    })
}

fn inspect_media_history(
    history: &[HistoryItem],
) -> Result<MediaHistoryInspection, ProviderFailure> {
    let mut calls = BTreeMap::<&str, &str>::new();
    let mut outputs = BTreeMap::<&str, &str>::new();
    let mut media_bindings = BTreeSet::<&str>::new();
    let mut stats = MediaHistoryStats::default();
    let mut attachment_indices = Vec::new();
    for (index, item) in history.iter().enumerate() {
        match item {
            HistoryItem::FunctionCall { call_id, name, .. } => {
                if calls.insert(call_id, name).is_some() {
                    return Err(ProviderFailure::new(
                        "provider_media_history_origin_invalid",
                    ));
                }
            }
            HistoryItem::FunctionCallOutput { call_id, output } => {
                if outputs.insert(call_id, output).is_some() {
                    return Err(ProviderFailure::new(
                        "provider_media_attachment_binding_invalid",
                    ));
                }
            }
            HistoryItem::ToolMediaAttachment { attachment } => {
                attachment.validate()?;
                let origin = attachment
                    .origin()
                    .ok_or_else(|| ProviderFailure::new("provider_media_history_origin_invalid"))?;
                let expected_output = format!(
                    "read_file returned an attached image: {}, {}x{}, sha256={}",
                    attachment.mime_type.as_str(),
                    attachment.width,
                    attachment.height,
                    attachment.sha256
                );
                if calls.get(attachment.call_id()).copied() != Some(origin.tool_name.as_str())
                    || origin.tool_name != "read_file"
                    || outputs.get(attachment.call_id()).copied() != Some(expected_output.as_str())
                    || !media_bindings.insert(attachment.call_id())
                {
                    return Err(ProviderFailure::new(
                        "provider_media_attachment_binding_invalid",
                    ));
                }
                attachment_indices.push(index);
                stats.retained_count = stats.retained_count.saturating_add(1);
                stats.retained_bytes = stats
                    .retained_bytes
                    .checked_add(u64::try_from(attachment.bytes.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| ProviderFailure::new("provider_media_history_bytes_exceeded"))?;
            }
            HistoryItem::MediaHistoryEviction { ledger } => {
                ledger.validate()?;
                let expected_output = format!(
                    "read_file returned an attached image: {}, {}x{}, sha256={}",
                    ledger.mime_type.as_str(),
                    ledger.width,
                    ledger.height,
                    ledger.sha256
                );
                if calls.get(ledger.call_id()).copied() != Some(ledger.origin_tool_name.as_str())
                    || ledger.origin_tool_name != "read_file"
                    || outputs.get(ledger.call_id()).copied() != Some(expected_output.as_str())
                    || !media_bindings.insert(ledger.call_id())
                {
                    return Err(ProviderFailure::new(
                        "provider_media_attachment_binding_invalid",
                    ));
                }
                stats.evicted_total = stats.evicted_total.saturating_add(1);
            }
            _ => {}
        }
    }
    Ok(MediaHistoryInspection {
        stats,
        attachment_indices,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionTool {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedTurn {
    pub response_id: String,
    pub model: String,
    pub output: Vec<OutputItem>,
    pub usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub enum OutputItem {
    AssistantMessage {
        text: String,
    },
    Reasoning {
        id: Option<String>,
        summary: Value,
        encrypted_content: Option<String>,
        content: Option<Value>,
    },
    FunctionCall {
        call_id: String,
        name: String,
        arguments_json: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCall {
    pub call_id: String,
    pub name: String,
    pub arguments_json: String,
}

impl CompletedTurn {
    /// Validate the complete, dispatch-authoritative response before exposing
    /// any call.
    pub fn validate_authoritative(
        &self,
        expected_model: &str,
        known_tools: &BTreeSet<&str>,
        max_calls: u64,
        max_arguments_bytes: u64,
    ) -> Result<(), ProviderFailure> {
        if self.response_id.is_empty() {
            return Err(ProviderFailure::new("provider_response_id_missing"));
        }
        if self.model != expected_model {
            return Err(ProviderFailure::new("provider_model_drift"));
        }
        if self.output.is_empty() {
            return Err(ProviderFailure::new("provider_output_empty"));
        }
        let calls = self.function_calls().collect::<Vec<_>>();
        if u64::try_from(calls.len()).unwrap_or(u64::MAX) > max_calls {
            return Err(ProviderFailure::new("provider_call_limit_exceeded"));
        }
        let mut ids = BTreeSet::new();
        for call in calls {
            if call.call_id.is_empty() || !ids.insert(call.call_id.clone()) {
                return Err(ProviderFailure::new("provider_call_id_invalid"));
            }
            if call.name.is_empty() || !known_tools.contains(call.name.as_str()) {
                return Err(ProviderFailure::new("provider_tool_unknown"));
            }
            if u64::try_from(call.arguments_json.len()).unwrap_or(u64::MAX) > max_arguments_bytes {
                return Err(ProviderFailure::new(
                    "provider_function_arguments_too_large",
                ));
            }
            let arguments: Value = serde_json::from_str(&call.arguments_json)
                .map_err(|_| ProviderFailure::new("provider_function_arguments_invalid"))?;
            if !arguments.is_object() {
                return Err(ProviderFailure::new(
                    "provider_function_arguments_not_object",
                ));
            }
        }
        if self
            .output
            .iter()
            .filter(|item| matches!(item, OutputItem::AssistantMessage { .. }))
            .count()
            > 1
        {
            return Err(ProviderFailure::new("provider_final_text_duplicate"));
        }
        Ok(())
    }

    pub fn function_calls(&self) -> impl Iterator<Item = FunctionCall> + '_ {
        self.output.iter().filter_map(|item| match item {
            OutputItem::FunctionCall {
                call_id,
                name,
                arguments_json,
            } => Some(FunctionCall {
                call_id: call_id.clone(),
                name: name.clone(),
                arguments_json: arguments_json.clone(),
            }),
            _ => None,
        })
    }

    pub fn final_text(&self) -> Option<&str> {
        self.output.iter().find_map(|item| match item {
            OutputItem::AssistantMessage { text } => Some(text.as_str()),
            _ => None,
        })
    }

    pub fn append_output_to(&self, history: &mut Vec<HistoryItem>) {
        history.extend(self.output.iter().map(|item| match item {
            OutputItem::AssistantMessage { text } => {
                HistoryItem::AssistantMessage { text: text.clone() }
            }
            OutputItem::Reasoning {
                id,
                summary,
                encrypted_content,
                content,
            } => HistoryItem::Reasoning {
                id: id.clone(),
                summary: summary.clone(),
                encrypted_content: encrypted_content.clone(),
                content: content.clone(),
            },
            OutputItem::FunctionCall {
                call_id,
                name,
                arguments_json,
            } => HistoryItem::FunctionCall {
                call_id: call_id.clone(),
                name: name.clone(),
                arguments_json: arguments_json.clone(),
            },
        }));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFailure {
    code: String,
}

impl ProviderFailure {
    pub fn new(code: impl Into<String>) -> Self {
        let code = code.into();
        let code = if code.is_empty()
            || code.len() > 128
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            "provider_failure_invalid_code".to_owned()
        } else {
            code
        };
        Self { code }
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

impl Display for ProviderFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "provider failed: {}", self.code)
    }
}

impl Error for ProviderFailure {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSendTelemetry {
    pub attempt_count: u64,
    pub retry_code: Option<String>,
    pub retry_stage: Option<String>,
}

impl Default for ProviderSendTelemetry {
    fn default() -> Self {
        Self {
            attempt_count: 1,
            retry_code: None,
            retry_stage: None,
        }
    }
}

pub struct PreparedTurnRequest(Result<Vec<u8>, TurnRequest>);

impl PreparedTurnRequest {
    fn raw(request: TurnRequest) -> Self {
        Self(Err(request))
    }

    pub(crate) fn serialized(body: Vec<u8>) -> Self {
        Self(Ok(body))
    }

    pub fn into_request(self) -> Result<TurnRequest, ProviderFailure> {
        self.0
            .err()
            .ok_or_else(|| ProviderFailure::new("provider_preflight_payload_invalid"))
    }

    pub(crate) fn into_serialized_body(self) -> Result<Vec<u8>, ProviderFailure> {
        self.0
            .ok()
            .ok_or_else(|| ProviderFailure::new("provider_preflight_payload_invalid"))
    }
}

pub trait Provider {
    fn preflight(&self, request: TurnRequest) -> Result<PreparedTurnRequest, ProviderFailure> {
        Ok(PreparedTurnRequest::raw(request))
    }

    async fn send(
        &mut self,
        request: PreparedTurnRequest,
    ) -> Result<CompletedTurn, ProviderFailure>;

    /// Return telemetry for the most recently started send. Providers that do
    /// not replay transport attempts retain the one-attempt default.
    fn send_telemetry(&self) -> ProviderSendTelemetry {
        ProviderSendTelemetry::default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::{
        CompletedTurn, HistoryItem, MediaHistoryEvictionLedger, MediaType, OutputItem,
        READ_FILE_MEDIA_MAX_BYTES, apply_media_history_policy,
        apply_media_history_policy_with_limits, media_history_policy_sha256,
        prepare_media_history_batch,
    };

    fn completed(call_id: &str) -> CompletedTurn {
        CompletedTurn {
            response_id: "response-1".to_owned(),
            model: "synthetic-model".to_owned(),
            output: vec![OutputItem::FunctionCall {
                call_id: call_id.to_owned(),
                name: "echo".to_owned(),
                arguments_json: "{\"text\":\"ok\"}".to_owned(),
            }],
            usage: Some(json!({"input_tokens": 1})),
            service_tier: None,
            system_fingerprint: None,
        }
    }

    #[test]
    fn rejects_duplicate_calls_before_exposing_authority() {
        let mut turn = completed("call-1");
        turn.output.extend(completed("call-1").output);
        let tools = BTreeSet::from(["echo"]);
        let error = turn
            .validate_authoritative("synthetic-model", &tools, 16, 1024)
            .expect_err("duplicate must fail");
        assert_eq!(error.code(), "provider_call_id_invalid");
    }

    fn media_item(call_index: u64, turn_index: u64, byte_length: usize) -> [HistoryItem; 3] {
        let call_id = format!("call-{call_index}");
        let logical_path = format!("frame-{call_index}.png");
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.resize(
            byte_length.max(bytes.len()),
            u8::try_from(call_index).unwrap_or(255),
        );
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        [
            HistoryItem::FunctionCall {
                call_id: call_id.clone(),
                name: "read_file".to_owned(),
                arguments_json: format!(r#"{{"target_file":"{logical_path}"}}"#),
            },
            HistoryItem::FunctionCallOutput {
                call_id: call_id.clone(),
                output: format!(
                    "read_file returned an attached image: image/png, 2x1, sha256={sha256}"
                ),
            },
            HistoryItem::tool_media_attachment_with_origin(
                call_id,
                logical_path,
                MediaType::Png,
                2,
                1,
                sha256,
                bytes,
                turn_index,
                "read_file",
            )
            .expect("valid attachment"),
        ]
    }

    fn media_call_ids(history: &[HistoryItem]) -> Vec<String> {
        history
            .iter()
            .filter_map(|item| match item {
                HistoryItem::ToolMediaAttachment { attachment } => {
                    Some(attachment.call_id().to_owned())
                }
                _ => None,
            })
            .collect()
    }

    fn ledgers(history: &[HistoryItem]) -> Vec<&MediaHistoryEvictionLedger> {
        history
            .iter()
            .filter_map(|item| match item {
                HistoryItem::MediaHistoryEviction { ledger } => Some(ledger),
                _ => None,
            })
            .collect()
    }

    fn media_batch(
        first: u64,
        count: u64,
        turn_index: u64,
        byte_length: usize,
    ) -> (Vec<HistoryItem>, Vec<String>, Vec<HistoryItem>) {
        let triples = (first..first + count)
            .map(|index| media_item(index, turn_index, byte_length))
            .collect::<Vec<_>>();
        let calls = triples
            .iter()
            .map(|items| items[0].clone())
            .collect::<Vec<_>>();
        let call_ids = (first..first + count)
            .map(|index| format!("call-{index}"))
            .collect::<Vec<_>>();
        let additions = triples
            .iter()
            .map(|items| items[1].clone())
            .chain(triples.iter().map(|items| items[2].clone()))
            .collect::<Vec<_>>();
        (calls, call_ids, additions)
    }

    #[test]
    fn prepared_media_batch_six_image_turn_is_atomic_and_retains_newest_four() {
        let (calls, call_ids, additions) = media_batch(0, 6, 7, 11);
        let mut base = vec![HistoryItem::User {
            content: "inspect six frames".to_owned(),
        }];
        base.extend(calls);
        let base_bytes = serde_json::to_vec(&base).expect("base bytes");

        let prepared = prepare_media_history_batch(&base, 7, &call_ids, additions)
            .expect("prepare six-image batch");
        assert_eq!(
            serde_json::to_vec(&base).expect("base remains serializable"),
            base_bytes
        );
        let (history, receipt) = prepared.into_parts();

        assert_eq!(receipt.retained_count(), 4);
        assert_eq!(receipt.evicted_total(), 2);
        assert_eq!(
            media_call_ids(&history),
            ["call-2", "call-3", "call-4", "call-5"]
        );
        assert_eq!(
            ledgers(&history)
                .iter()
                .map(|ledger| ledger.call_id())
                .collect::<Vec<_>>(),
            ["call-0", "call-1"]
        );
        assert_eq!(
            history
                .iter()
                .filter(|item| matches!(item, HistoryItem::FunctionCallOutput { .. }))
                .count(),
            6
        );
    }

    #[test]
    fn prepared_media_batch_negative_matrix_leaves_base_byte_identical() {
        fn assert_rejected(
            base: &[HistoryItem],
            turn_index: u64,
            call_ids: &[String],
            additions: Vec<HistoryItem>,
        ) {
            let before = serde_json::to_vec(base).expect("base before");
            prepare_media_history_batch(base, turn_index, call_ids, additions)
                .expect_err("invalid batch");
            assert_eq!(
                serde_json::to_vec(base).expect("base after"),
                before,
                "failed preparation mutated base"
            );
        }

        let (calls, call_ids, additions) = media_batch(0, 6, 7, 11);
        let mut base = vec![HistoryItem::User {
            content: "inspect six frames".to_owned(),
        }];
        base.extend(calls);

        let mut duplicate_ids = call_ids.clone();
        duplicate_ids[5] = duplicate_ids[4].clone();
        assert_rejected(&base, 7, &duplicate_ids, additions.clone());

        let mut wrong_output_order = additions.clone();
        wrong_output_order.swap(0, 1);
        assert_rejected(&base, 7, &call_ids, wrong_output_order);

        let mut wrong_origin = additions.clone();
        let HistoryItem::ToolMediaAttachment { attachment } = &mut wrong_origin[6] else {
            panic!("attachment");
        };
        attachment.origin.as_mut().expect("origin").turn_index = 8;
        assert_rejected(&base, 7, &call_ids, wrong_origin);

        let mut wrong_digest = additions.clone();
        let HistoryItem::ToolMediaAttachment { attachment } = &mut wrong_digest[6] else {
            panic!("attachment");
        };
        attachment.bytes.push(0);
        assert_rejected(&base, 7, &call_ids, wrong_digest);

        let mut oversized_item = additions.clone();
        let HistoryItem::ToolMediaAttachment { attachment } = &mut oversized_item[6] else {
            panic!("attachment");
        };
        attachment.bytes.resize(
            usize::try_from(READ_FILE_MEDIA_MAX_BYTES).expect("media cap") + 1,
            0,
        );
        assert_rejected(&base, 7, &call_ids, oversized_item);

        let (large_calls, large_ids, large_additions) = media_batch(10, 6, 9, 1_500_000);
        let mut large_base = vec![HistoryItem::User {
            content: "inspect large frames".to_owned(),
        }];
        large_base.extend(large_calls);
        assert_rejected(&large_base, 9, &large_ids, large_additions);

        let mut missing_output = additions;
        missing_output.remove(5);
        assert_rejected(&base, 7, &call_ids, missing_output);
    }

    #[test]
    fn rolling_media_four_old_plus_four_new_keeps_newest_suffix_and_provenance() {
        let mut history = vec![
            HistoryItem::System {
                content: "system".to_owned(),
            },
            HistoryItem::User {
                content: "inspect frames".to_owned(),
            },
        ];
        for index in 0..8 {
            history.extend(media_item(index, index / 4, 11));
        }

        let receipt = apply_media_history_policy(&mut history).expect("window history");

        assert_eq!(
            media_call_ids(&history),
            ["call-4", "call-5", "call-6", "call-7"]
        );
        let ledger = ledgers(&history);
        assert_eq!(ledger.len(), 4);
        assert_eq!(
            ledger.iter().map(|item| item.call_id()).collect::<Vec<_>>(),
            ["call-0", "call-1", "call-2", "call-3"]
        );
        assert!(ledger.iter().all(|item| !item.media_bytes_visible()));
        assert_eq!(receipt.evicted_total(), 4);
        assert_eq!(receipt.retained_count(), 4);
        assert_eq!(
            media_history_policy_sha256().expect("closed policy binding"),
            "b34dc9dd4f9d37c53e98fbf2fd3a3d816ba3e1071dd3e981161f23d16ffb6cd6"
        );
        assert_eq!(
            serde_json::to_value(&receipt)
                .expect("receipt")
                .as_object()
                .expect("receipt object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "evicted_total",
                "history_sha256",
                "retained_bytes",
                "retained_count",
            ])
        );
        assert_eq!(
            serde_json::to_value(ledger[0])
                .expect("ledger")
                .as_object()
                .expect("ledger object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "byte_length",
                "call_id",
                "height",
                "logical_path",
                "media_bytes_visible",
                "mime_type",
                "origin_tool_name",
                "origin_turn_index",
                "sha256",
                "width",
            ])
        );
        assert!(ledger[0].model_text().len() < 192);
        assert_eq!(
            history
                .iter()
                .filter(|item| matches!(item, HistoryItem::FunctionCallOutput { .. }))
                .count(),
            8
        );
    }

    #[test]
    fn rolling_media_is_byte_deterministic_idempotent_and_keeps_non_media_items() {
        let sentinel = vec![
            HistoryItem::System {
                content: "system".to_owned(),
            },
            HistoryItem::User {
                content: "user".to_owned(),
            },
            HistoryItem::AssistantMessage {
                text: "assistant".to_owned(),
            },
            HistoryItem::Reasoning {
                id: Some("reason-1".to_owned()),
                summary: json!([]),
                encrypted_content: Some("opaque".to_owned()),
                content: None,
            },
        ];
        let mut first = sentinel.clone();
        for index in 0..6 {
            first.extend(media_item(index, index / 3, 11));
        }
        let mut second = first.clone();

        let first_receipt = apply_media_history_policy(&mut first).expect("first window");
        let replay_receipt = apply_media_history_policy(&mut first).expect("idempotent replay");
        let second_receipt = apply_media_history_policy(&mut second).expect("second window");

        assert_eq!(first, second);
        assert_eq!(first_receipt, second_receipt);
        assert_eq!(replay_receipt, second_receipt);
        assert_eq!(&first[..sentinel.len()], sentinel.as_slice());
        assert_eq!(
            serde_json::to_vec(&first).expect("serialize"),
            serde_json::to_vec(&second).expect("serialize")
        );
    }

    #[test]
    fn rolling_media_count_byte_duplicate_and_zero_cap_matrix_is_latest_suffix() {
        for (max_items, max_bytes, expected) in [
            (0, 1_000, Vec::<&str>::new()),
            (1, 1_000, vec!["call-4"]),
            (4, 22, vec!["call-3", "call-4"]),
            (4, 44, vec!["call-1", "call-2", "call-3", "call-4"]),
        ] {
            let mut history = Vec::new();
            for index in 0..5 {
                history.extend(media_item(index, 0, 11));
            }
            apply_media_history_policy_with_limits(&mut history, max_items, max_bytes)
                .expect("window");
            assert_eq!(media_call_ids(&history), expected);
        }

        let mut duplicate_digest = Vec::new();
        duplicate_digest.extend(media_item(0, 0, 11));
        duplicate_digest.extend(media_item(0, 0, 11).map(|item| match item {
            HistoryItem::FunctionCall {
                name,
                arguments_json,
                ..
            } => HistoryItem::FunctionCall {
                call_id: "call-1".to_owned(),
                name,
                arguments_json,
            },
            HistoryItem::FunctionCallOutput { output, .. } => HistoryItem::FunctionCallOutput {
                call_id: "call-1".to_owned(),
                output,
            },
            HistoryItem::ToolMediaAttachment { mut attachment } => {
                attachment.call_id = "call-1".to_owned();
                HistoryItem::ToolMediaAttachment { attachment }
            }
            other => other,
        }));
        apply_media_history_policy_with_limits(&mut duplicate_digest, 4, 44)
            .expect("duplicate digest is not deduplicated");
        assert_eq!(media_call_ids(&duplicate_digest), ["call-0", "call-1"]);
    }

    #[test]
    fn rolling_media_missing_origin_and_invalid_attachment_fail_without_mutation() {
        let bytes = b"\x89PNG\r\n\x1a\nabc".to_vec();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let legacy = HistoryItem::tool_media_attachment(
            "call-legacy",
            "legacy.png",
            MediaType::Png,
            2,
            1,
            digest,
            bytes,
        )
        .expect("legacy attachment");
        let mut missing_origin = vec![
            HistoryItem::FunctionCallOutput {
                call_id: "call-legacy".to_owned(),
                output: "attached".to_owned(),
            },
            legacy,
        ];
        let before = missing_origin.clone();
        assert_eq!(
            apply_media_history_policy(&mut missing_origin)
                .expect_err("origin is required")
                .code(),
            "provider_media_history_origin_invalid"
        );
        assert_eq!(missing_origin, before);

        let mut invalid = media_item(0, 0, 11).to_vec();
        let HistoryItem::ToolMediaAttachment { attachment } = &mut invalid[2] else {
            panic!("attachment");
        };
        attachment.bytes.push(99);
        let before = invalid.clone();
        assert_eq!(
            apply_media_history_policy(&mut invalid)
                .expect_err("invalid attachment")
                .code(),
            "provider_media_attachment_invalid"
        );
        assert_eq!(invalid, before);
    }

    #[test]
    fn rolling_media_long_chain_is_linear_compact_and_apply_stable() {
        let mut history = vec![HistoryItem::User {
            content: "inspect the sequence".to_owned(),
        }];
        let mut receipt = apply_media_history_policy(&mut history).expect("initial receipt");
        for batch_index in 0..64_u64 {
            for offset in 0..4_u64 {
                history.extend(media_item(batch_index * 4 + offset, batch_index, 11));
            }
            let before_apply_items = history.len();
            receipt = apply_media_history_policy(&mut history).expect("window batch");
            assert_eq!(history.len(), before_apply_items);
            assert_eq!(receipt.retained_count(), 4);
            assert_eq!(receipt.evicted_total(), batch_index.saturating_mul(4));
        }

        let placeholders = ledgers(&history);
        assert_eq!(placeholders.len(), 252);
        let total_placeholder_bytes = placeholders
            .iter()
            .map(|ledger| ledger.model_text().len())
            .sum::<usize>();
        assert!(total_placeholder_bytes <= placeholders.len() * 192);

        let stable_history = serde_json::to_vec(&history).expect("stable history");
        let stable_receipt = receipt.clone();
        assert_eq!(
            apply_media_history_policy(&mut history).expect("stable replay"),
            stable_receipt
        );
        assert_eq!(
            serde_json::to_vec(&history).expect("stable history replay"),
            stable_history
        );
    }
}
