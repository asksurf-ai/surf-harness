//! Minimal tool-execution seam and first-party synthetic echo executor.

use std::fmt::{self, Formatter};
use std::path::Path;
use std::time::Instant;

use nano_provider_xai::{FunctionCall, HistoryItem, MediaType, ProviderFailure};
use nano_types::event::ToolOutcome;
use nano_types::external_tool::ExternalTerminalActorReceiptV1;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceMode {
    LocalDirectory,
    RemoteLogical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolWaitReason {
    RuntimeBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolRuntimeBudget {
    pub wait_clamped: bool,
    pub wait_reason: Option<ToolWaitReason>,
}

impl ToolRuntimeBudget {
    pub fn wait_clamped() -> Self {
        Self {
            wait_clamped: true,
            wait_reason: Some(ToolWaitReason::RuntimeBudget),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolExecutionFailureClass {
    Tool,
    Bridge,
    Deadline,
    Cleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionError {
    code: &'static str,
    class: ToolExecutionFailureClass,
    execution_may_have_started: bool,
    cleanup_verified: Option<bool>,
    census_verified: Option<bool>,
    actor_receipt: Option<ExternalTerminalActorReceiptV1>,
}

impl ToolExecutionError {
    pub fn incomplete(code: &'static str) -> Self {
        Self {
            code,
            class: ToolExecutionFailureClass::Tool,
            execution_may_have_started: true,
            cleanup_verified: None,
            census_verified: None,
            actor_receipt: None,
        }
    }

    pub fn fatal(
        code: &'static str,
        execution_may_have_started: bool,
        cleanup_verified: Option<bool>,
        census_verified: Option<bool>,
    ) -> Self {
        Self {
            code,
            class: ToolExecutionFailureClass::Tool,
            execution_may_have_started,
            cleanup_verified,
            census_verified,
            actor_receipt: None,
        }
    }

    pub fn fatal_classified(
        code: &'static str,
        class: ToolExecutionFailureClass,
        execution_may_have_started: bool,
        cleanup_verified: Option<bool>,
        census_verified: Option<bool>,
    ) -> Self {
        Self {
            code,
            class,
            execution_may_have_started,
            cleanup_verified,
            census_verified,
            actor_receipt: None,
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn bridge(code: &'static str) -> Self {
        Self {
            code,
            class: ToolExecutionFailureClass::Bridge,
            execution_may_have_started: true,
            cleanup_verified: None,
            census_verified: None,
            actor_receipt: None,
        }
    }

    pub fn deadline(code: &'static str) -> Self {
        Self {
            code,
            class: ToolExecutionFailureClass::Deadline,
            execution_may_have_started: true,
            cleanup_verified: None,
            census_verified: None,
            actor_receipt: None,
        }
    }

    pub fn cleanup(
        code: &'static str,
        execution_may_have_started: bool,
        cleanup_verified: Option<bool>,
        census_verified: Option<bool>,
    ) -> Self {
        Self {
            code,
            class: ToolExecutionFailureClass::Cleanup,
            execution_may_have_started,
            cleanup_verified,
            census_verified,
            actor_receipt: None,
        }
    }

    pub fn class(&self) -> ToolExecutionFailureClass {
        self.class
    }

    pub fn execution_may_have_started(&self) -> bool {
        self.execution_may_have_started
    }

    pub fn cleanup_verified(&self) -> Option<bool> {
        self.cleanup_verified
    }

    pub fn census_verified(&self) -> Option<bool> {
        self.census_verified
    }

    pub(crate) fn with_actor_receipt(
        mut self,
        actor_receipt: Option<ExternalTerminalActorReceiptV1>,
    ) -> Self {
        self.actor_receipt = actor_receipt;
        self
    }

    pub fn actor_receipt(&self) -> Option<&ExternalTerminalActorReceiptV1> {
        self.actor_receipt.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub execution_attempted: bool,
    pub outcome: ToolOutcome,
    pub output: String,
    pub media: Option<Box<ToolMedia>>,
    /// Present only when a shared runtime budget changed tool wait semantics.
    pub runtime_budget: Option<ToolRuntimeBudget>,
    /// Present only for a validated v3 foreground terminal actor settlement.
    pub actor_receipt: Option<ExternalTerminalActorReceiptV1>,
}

impl ToolResult {
    pub fn succeeded(output: impl Into<String>) -> Self {
        Self {
            execution_attempted: true,
            outcome: ToolOutcome::Succeeded,
            output: output.into(),
            media: None,
            runtime_budget: None,
            actor_receipt: None,
        }
    }

    pub fn rejected(output: impl Into<String>) -> Self {
        Self {
            execution_attempted: false,
            outcome: ToolOutcome::Rejected,
            output: output.into(),
            media: None,
            runtime_budget: None,
            actor_receipt: None,
        }
    }

    pub fn timed_out(output: impl Into<String>) -> Self {
        Self {
            execution_attempted: true,
            outcome: ToolOutcome::TimedOut,
            output: output.into(),
            media: None,
            runtime_budget: None,
            actor_receipt: None,
        }
    }

    pub(crate) fn with_actor_receipt(
        mut self,
        actor_receipt: Option<ExternalTerminalActorReceiptV1>,
    ) -> Self {
        self.actor_receipt = actor_receipt;
        self
    }

    pub fn actor_receipt(&self) -> Option<&ExternalTerminalActorReceiptV1> {
        self.actor_receipt.as_ref()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ToolMedia {
    logical_path: String,
    mime_type: MediaType,
    width: u64,
    height: u64,
    source_byte_length: u64,
    source_sha256: String,
    canonical_sha256: String,
    bytes: Vec<u8>,
}

impl fmt::Debug for ToolMedia {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolMedia")
            .field("logical_path", &self.logical_path)
            .field("mime_type", &self.mime_type)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("source_byte_length", &self.source_byte_length)
            .field("source_sha256", &self.source_sha256)
            .field("canonical_byte_length", &self.bytes.len())
            .field("canonical_sha256", &self.canonical_sha256)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl ToolMedia {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        logical_path: String,
        mime_type: MediaType,
        width: u64,
        height: u64,
        source_byte_length: u64,
        source_sha256: String,
        canonical_sha256: String,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            logical_path,
            mime_type,
            width,
            height,
            source_byte_length,
            source_sha256,
            canonical_sha256,
            bytes,
        }
    }

    pub(crate) fn into_history_item(
        self,
        call_id: String,
        origin_turn_index: u64,
        origin_tool_name: String,
    ) -> Result<HistoryItem, ProviderFailure> {
        HistoryItem::tool_media_attachment_with_origin(
            call_id,
            self.logical_path,
            self.mime_type,
            self.width,
            self.height,
            self.canonical_sha256,
            self.bytes,
            origin_turn_index,
            origin_tool_name,
        )
    }

    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub trait ToolExecutor {
    fn workspace_mode(&self) -> WorkspaceMode {
        WorkspaceMode::LocalDirectory
    }

    /// Reject invalid or unsupported calls before a dispatch event.
    fn validate(&self, call: &FunctionCall) -> Result<(), ToolResult>;

    /// Execute only a call that passed `validate`.
    async fn execute(
        &mut self,
        call: &FunctionCall,
        workspace: &Path,
        deadline: Instant,
    ) -> Result<ToolResult, ToolExecutionError>;
}

/// Synthetic executor used by deterministic scripted runs.
pub struct EchoExecutor {
    provider_name: String,
}

impl EchoExecutor {
    pub fn new(provider_name: impl Into<String>) -> Self {
        Self {
            provider_name: provider_name.into(),
        }
    }
}

impl ToolExecutor for EchoExecutor {
    fn validate(&self, call: &FunctionCall) -> Result<(), ToolResult> {
        if call.name != self.provider_name {
            return Err(ToolResult::rejected("unsupported_in_alpha"));
        }
        serde_json::from_str::<EchoArguments>(&call.arguments_json)
            .map(|_| ())
            .map_err(|_| ToolResult::rejected("invalid_arguments"))
    }

    async fn execute(
        &mut self,
        call: &FunctionCall,
        _workspace: &Path,
        _deadline: Instant,
    ) -> Result<ToolResult, ToolExecutionError> {
        Ok(
            match serde_json::from_str::<EchoArguments>(&call.arguments_json) {
                Ok(arguments) => ToolResult::succeeded(arguments.text),
                Err(_) => ToolResult::rejected("invalid_arguments"),
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EchoArguments {
    text: String,
}

#[cfg(test)]
mod tests {
    use nano_provider_xai::FunctionCall;
    use nano_types::external_tool::{
        ExternalTerminalActorOriginV1, ExternalTerminalActorPhaseV1,
        ExternalTerminalActorReceiptV1, ExternalTerminalActorSubtypeV1,
        TERMINAL_ACTOR_RECEIPT_V1_SCHEMA,
    };
    use sha2::{Digest, Sha256};

    use super::{EchoExecutor, ToolExecutor, ToolResult};

    fn validated_actor_receipt() -> ExternalTerminalActorReceiptV1 {
        let mut receipt = ExternalTerminalActorReceiptV1 {
            schema_version: TERMINAL_ACTOR_RECEIPT_V1_SCHEMA.to_owned(),
            phase: ExternalTerminalActorPhaseV1::MetaValidate,
            origin: ExternalTerminalActorOriginV1::Actor,
            primary_subtype: ExternalTerminalActorSubtypeV1::Completed,
            recovery_subtype: None,
            execution_may_have_started: true,
            effective_cutoff_monotonic_ns: 42,
            cleanup_verified: Some(true),
            census_verified: Some(true),
            diagnostic_digest_sha256: String::new(),
        };
        let digest_input = serde_json::json!({
            "schema_version": receipt.schema_version,
            "phase": receipt.phase,
            "origin": receipt.origin,
            "primary_subtype": receipt.primary_subtype,
            "recovery_subtype": receipt.recovery_subtype,
            "execution_may_have_started": receipt.execution_may_have_started,
            "effective_cutoff_monotonic_ns": receipt.effective_cutoff_monotonic_ns,
            "cleanup_verified": receipt.cleanup_verified,
            "census_verified": receipt.census_verified,
        });
        receipt.diagnostic_digest_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&digest_input).expect("encode"))
        );
        receipt.validate().expect("valid PR5 actor receipt");
        receipt
    }

    #[test]
    fn validated_actor_receipt_survives_tool_result_transport() {
        let receipt = validated_actor_receipt();
        let result = ToolResult::succeeded("ok").with_actor_receipt(Some(receipt.clone()));

        assert_eq!(result.actor_receipt(), Some(&receipt));
    }

    #[test]
    fn unsupported_and_invalid_calls_settle_without_dispatch() {
        let executor = EchoExecutor::new("echo");
        let unsupported = FunctionCall {
            call_id: "call-1".to_owned(),
            name: "other".to_owned(),
            arguments_json: "{}".to_owned(),
        };
        assert!(
            !executor
                .validate(&unsupported)
                .expect_err("unsupported")
                .execution_attempted
        );

        let invalid = FunctionCall {
            call_id: "call-2".to_owned(),
            name: "echo".to_owned(),
            arguments_json: "{\"extra\":true}".to_owned(),
        };
        assert!(
            !executor
                .validate(&invalid)
                .expect_err("invalid")
                .execution_attempted
        );
    }
}
