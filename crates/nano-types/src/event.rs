//! Typed append-only event and committed run-record grammar.

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::external_tool::{
    ExternalTerminalActorOriginV1, ExternalTerminalActorPhaseV1, ExternalTerminalActorSubtypeV1,
    MEDIA_HISTORY_POLICY_SHA256, MEDIA_HISTORY_POLICY_VERSION,
};

/// Writers emit v3. Historic event compatibility belongs to integration readers.
pub const EVENT_SCHEMA: &str = "event-v3";
pub const LEGACY_EVENT_SCHEMA: &str = "event-v1";
pub const RUN_RECORD_SCHEMA: &str = "nano-run-record-v2";
pub const RUN_RECORD_V3_SCHEMA: &str = "nano-run-record-v3";
pub const LEGACY_RUN_RECORD_SCHEMA: &str = "nano-run-record-alpha-1";
pub const TOOL_RECEIPT_V1_SCHEMA: &str = "nano-tool-receipt-v1";

const MAX_IDENTITY_BYTES: usize = 256;
const MAX_TERMINAL_CODE_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema_version: String,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub seq: u64,
    pub elapsed_ms: u64,
    #[serde(flatten)]
    pub body: EventBody,
}

impl Event {
    /// Validate invariants which JSON shape alone cannot express.
    pub fn validate(&self) -> Result<(), EventValidationError> {
        if !matches!(
            self.schema_version.as_str(),
            EVENT_SCHEMA | LEGACY_EVENT_SCHEMA
        ) {
            return Err(EventValidationError::new("event_schema_unsupported"));
        }
        validate_identity(&self.run_id)?;
        validate_identity(&self.trial_id)?;
        validate_identity(&self.attempt_id)?;
        if self.schema_version == LEGACY_EVENT_SCHEMA {
            if matches!(self.body, EventBody::ToolFailed(_)) {
                return Err(EventValidationError::new(
                    "event_v1_tool_failed_unsupported",
                ));
            }
            if matches!(self.body, EventBody::ToolReceipt(_)) {
                return Err(EventValidationError::new(
                    "event_v1_tool_receipt_unsupported",
                ));
            }
            if matches!(
                self.body,
                EventBody::ContextCheckpointed(_) | EventBody::ContextCheckpointRejected(_)
            ) {
                return Err(EventValidationError::new(
                    "event_v1_context_checkpoint_unsupported",
                ));
            }
        }
        match &self.body {
            EventBody::RunStarted(started) => {
                if let Some(digest) = &started.deadline_receipt_sha256 {
                    validate_sha256(digest)?;
                }
                validate_media_history_policy_binding(
                    started.media_history_policy_version.as_deref(),
                    started.media_history_policy_sha256.as_deref(),
                )?;
                validate_completion_review_policy_binding(
                    started.completion_review_policy.as_deref(),
                    started.context_checkpoint_policy_version.as_deref(),
                    started.checkpoint_capsule_schema_version.as_deref(),
                )?;
            }
            EventBody::ProviderRequested(requested) => {
                if let Some(receipt) = &requested.media_history_receipt {
                    receipt.validate()?;
                }
                requested.validate_checkpoint_binding()?;
            }
            EventBody::ProviderCompleted(completed) => validate_provider_attempts(
                completed.attempt_count,
                completed.retry_code.as_deref(),
                completed.retry_stage.as_deref(),
            )?,
            EventBody::ProviderFailed(failure) => {
                validate_code(&failure.code)?;
                validate_provider_attempts(
                    failure.attempt_count,
                    failure.retry_code.as_deref(),
                    failure.retry_stage.as_deref(),
                )?;
                if let Some(count) = failure.rejected_call_count
                    && (count == 0
                        || !matches!(
                            failure.code.as_str(),
                            "provider_call_limit_exceeded" | "provider_run_call_limit_exceeded"
                        ))
                {
                    return Err(EventValidationError::new(
                        "provider_rejected_response_invalid",
                    ));
                }
            }
            EventBody::ContextCheckpointed(checkpoint) => checkpoint.validate()?,
            EventBody::ContextCheckpointRejected(rejection) => rejection.validate()?,
            EventBody::ToolRegistered(tool) => {
                validate_identity(&tool.call_id)?;
                validate_identity(&tool.provider_name)?;
            }
            EventBody::ToolDispatched(tool) => {
                validate_identity(&tool.call_id)?;
                validate_identity(&tool.provider_name)?;
            }
            EventBody::ToolCompleted(tool) => {
                validate_identity(&tool.call_id)?;
                validate_identity(&tool.provider_name)?;
            }
            EventBody::ToolFailed(tool) => {
                validate_identity(&tool.call_id)?;
                validate_identity(&tool.provider_name)?;
                validate_code(&tool.code)?;
            }
            EventBody::ToolReceipt(receipt) => receipt.validate()?,
            EventBody::RunCompleted(terminal) => validate_code(&terminal.code)?,
            EventBody::RunFailed(terminal) => validate_code(&terminal.code)?,
            EventBody::AssistantFinal(_) => {}
        }
        Ok(())
    }
}

fn validate_provider_attempts(
    attempt_count: Option<u64>,
    retry_code: Option<&str>,
    retry_stage: Option<&str>,
) -> Result<(), EventValidationError> {
    if let Some(count) = attempt_count
        && count == 0
    {
        return Err(EventValidationError::new(
            "provider_attempt_telemetry_invalid",
        ));
    }
    match (retry_code, retry_stage) {
        (None, None) => Ok(()),
        (Some(code), Some(stage))
            if attempt_count.is_some_and(|count| count >= 2)
                && matches!(stage, "request" | "response_stream") =>
        {
            validate_code(code)
        }
        _ => Err(EventValidationError::new(
            "provider_attempt_telemetry_invalid",
        )),
    }
}

fn validate_completion_review_policy_binding(
    review_policy: Option<&str>,
    checkpoint_policy: Option<&str>,
    capsule_schema: Option<&str>,
) -> Result<(), EventValidationError> {
    let valid = match review_policy {
        None => checkpoint_policy.is_none() && capsule_schema.is_none(),
        Some(
            "disabled"
            | "independent-falsification-v1"
            | "evidence-debt-v2"
            | "fresh-evidence-debt-v3",
        ) => checkpoint_policy.is_none() && capsule_schema.is_none(),
        Some("fresh-checkpoint-v4") => {
            checkpoint_policy == Some("fresh-context-checkpoint-v1") && capsule_schema.is_none()
        }
        Some("semantic-checkpoint-v5") => {
            checkpoint_policy == Some("semantic-context-checkpoint-v1")
                && capsule_schema == Some("semantic-checkpoint-capsule-v1")
        }
        Some(_) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(EventValidationError::new(
            "completion_review_policy_binding_invalid",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventBody {
    #[serde(rename = "run.started")]
    RunStarted(RunStarted),
    #[serde(rename = "provider.requested")]
    ProviderRequested(ProviderRequested),
    #[serde(rename = "provider.completed")]
    ProviderCompleted(ProviderCompleted),
    #[serde(rename = "provider.failed")]
    ProviderFailed(ProviderFailed),
    #[serde(rename = "context.checkpointed")]
    ContextCheckpointed(ContextCheckpointedV1),
    #[serde(rename = "context.checkpoint_rejected")]
    ContextCheckpointRejected(ContextCheckpointRejectedV1),
    #[serde(rename = "tool.registered")]
    ToolRegistered(ToolRegistered),
    #[serde(rename = "tool.dispatched")]
    ToolDispatched(ToolDispatched),
    #[serde(rename = "tool.completed")]
    ToolCompleted(ToolCompleted),
    #[serde(rename = "tool.failed")]
    ToolFailed(ToolFailed),
    #[serde(rename = "tool.receipt")]
    ToolReceipt(ToolReceiptV1),
    #[serde(rename = "assistant.final")]
    AssistantFinal(AssistantFinal),
    #[serde(rename = "run.completed")]
    RunCompleted(RunCompleted),
    #[serde(rename = "run.failed")]
    RunFailed(RunFailed),
}

impl EventBody {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::RunCompleted(_) | Self::RunFailed(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunStarted {
    pub task_id: String,
    pub contract_id: String,
    pub profile_id: String,
    pub contract_set_sha256: String,
    pub model: String,
    pub run_spec_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_history_policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_history_policy_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_review_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_checkpoint_policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_capsule_schema_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequested {
    pub turn_index: u64,
    pub history_item_count: u64,
    pub tool_count: u64,
    pub function_output_call_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_history_receipt: Option<MediaHistoryRequestReceiptV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_observation: Option<ProviderBudgetObservationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_source_history_sha256: Option<String>,
}

impl ProviderRequested {
    fn validate_checkpoint_binding(&self) -> Result<(), EventValidationError> {
        let checkpoint_prepare = self.budget_observation.as_ref().is_some_and(|observation| {
            observation.phase == ProviderBudgetPhaseV1::CheckpointPrepare
        });
        if checkpoint_prepare != self.checkpoint_source_history_sha256.is_some()
            || (checkpoint_prepare && self.tool_count != 0)
        {
            return Err(EventValidationError::new(
                "provider_checkpoint_binding_invalid",
            ));
        }
        if let Some(digest) = &self.checkpoint_source_history_sha256 {
            validate_sha256(digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBudgetObservationV1 {
    pub phase: ProviderBudgetPhaseV1,
    pub budget_notice_visible: bool,
    pub action_remaining_ms: u64,
    pub settlement_remaining_ms: u64,
    pub last_send_remaining_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderBudgetPhaseV1 {
    ActionOpen,
    FinalOnly,
    CompletionCritic,
    CheckpointPrepare,
    CheckpointProvisional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaHistoryRequestReceiptV1 {
    pub history_sha256: String,
    pub retained_count: u64,
    pub retained_bytes: u64,
    pub evicted_total: u64,
}

impl MediaHistoryRequestReceiptV1 {
    fn validate(&self) -> Result<(), EventValidationError> {
        validate_sha256(&self.history_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCompleted {
    pub turn_index: u64,
    pub response_id: String,
    pub model: String,
    pub call_ids: Vec<String>,
    pub has_final_text: bool,
    pub usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_stage: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFailed {
    pub turn_index: u64,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_call_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_usage: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_stage: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCheckpointedV1 {
    pub policy_version: String,
    pub source_history_sha256: String,
    pub checkpoint_history_sha256: String,
    pub source_history_items: u64,
    pub checkpoint_history_items: u64,
    pub provider_turn_count: u64,
    pub tool_call_count: u64,
    pub observed_input_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_schema_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare_turn_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare_history_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_turn_cutoff: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_lease_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail_reserve_ms: Option<u64>,
}

impl ContextCheckpointedV1 {
    fn validate(&self) -> Result<(), EventValidationError> {
        if !matches!(
            self.policy_version.as_str(),
            "fresh-context-checkpoint-v1" | "semantic-context-checkpoint-v1"
        ) || self.source_history_items == 0
            || self.checkpoint_history_items == 0
            || self.checkpoint_history_items >= self.source_history_items
            || self.provider_turn_count == 0
            || self.observed_input_tokens == 0
        {
            return Err(EventValidationError::new(
                "context_checkpoint_receipt_invalid",
            ));
        }
        validate_sha256(&self.source_history_sha256)?;
        validate_sha256(&self.checkpoint_history_sha256)?;
        if self.policy_version == "fresh-context-checkpoint-v1" {
            if self.capsule_schema_version.is_some()
                || self.capsule_sha256.is_some()
                || self.capsule_bytes.is_some()
                || self.prepare_turn_index.is_some()
                || self.prepare_history_sha256.is_some()
                || self.action_turn_cutoff.is_some()
                || self.action_lease_ms.is_some()
                || self.tail_reserve_ms.is_some()
            {
                return Err(EventValidationError::new(
                    "context_checkpoint_receipt_invalid",
                ));
            }
            return Ok(());
        }
        if self.capsule_schema_version.as_deref() != Some("semantic-checkpoint-capsule-v1")
            || self
                .capsule_bytes
                .is_none_or(|value| value == 0 || value > 8192)
            || self
                .prepare_turn_index
                .is_none_or(|value| value >= self.provider_turn_count)
            || self
                .action_turn_cutoff
                .is_none_or(|value| value <= self.provider_turn_count)
            || self.action_lease_ms.is_none_or(|value| value == 0)
            || self.tail_reserve_ms != Some(900_000)
        {
            return Err(EventValidationError::new(
                "context_checkpoint_receipt_invalid",
            ));
        }
        validate_sha256(
            self.capsule_sha256
                .as_deref()
                .ok_or_else(|| EventValidationError::new("context_checkpoint_receipt_invalid"))?,
        )?;
        validate_sha256(
            self.prepare_history_sha256
                .as_deref()
                .ok_or_else(|| EventValidationError::new("context_checkpoint_receipt_invalid"))?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCheckpointRejectedV1 {
    pub policy_version: String,
    pub source_history_sha256: String,
    pub prepare_history_sha256: String,
    pub prepare_turn_index: u64,
    pub provider_turn_count: u64,
    pub reason: String,
    pub request_emitted: bool,
    pub response_received: bool,
}

impl ContextCheckpointRejectedV1 {
    fn validate(&self) -> Result<(), EventValidationError> {
        let turn_relation_valid = if self.request_emitted {
            self.prepare_turn_index < self.provider_turn_count
        } else {
            self.prepare_turn_index == self.provider_turn_count && !self.response_received
        };
        if self.policy_version != "semantic-context-checkpoint-v1" || !turn_relation_valid {
            return Err(EventValidationError::new(
                "context_checkpoint_rejection_invalid",
            ));
        }
        validate_sha256(&self.source_history_sha256)?;
        validate_sha256(&self.prepare_history_sha256)?;
        validate_code(&self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRegistered {
    pub call_id: String,
    pub provider_name: String,
    pub known: bool,
    pub arguments_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_observation: Option<ToolBudgetObservationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBudgetObservationV1 {
    pub dispatch_open_at_registration: bool,
    pub action_remaining_ms: u64,
    pub settlement_remaining_ms: u64,
    pub last_send_remaining_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDispatched {
    pub call_id: String,
    pub provider_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCompleted {
    pub call_id: String,
    pub provider_name: String,
    pub execution_attempted: bool,
    pub outcome: ToolOutcome,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFailed {
    pub call_id: String,
    pub provider_name: String,
    pub code: String,
    pub execution_may_have_started: bool,
    pub cleanup_verified: Option<bool>,
    pub census_verified: Option<bool>,
    pub recoverability: ToolFailureRecoverability,
}

/// Compact durable binding of a validated actor receipt to one tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolReceiptV1 {
    pub schema_version: String,
    pub phase: ExternalTerminalActorPhaseV1,
    pub origin: ExternalTerminalActorOriginV1,
    pub primary_subtype: ExternalTerminalActorSubtypeV1,
    pub recovery_subtype: Option<ExternalTerminalActorSubtypeV1>,
    pub receipt_digest_sha256: String,
    pub tool_identity_sha256: String,
    pub tool_call_ordinal: u64,
}

impl ToolReceiptV1 {
    pub fn validate(&self) -> Result<(), EventValidationError> {
        if self.schema_version != TOOL_RECEIPT_V1_SCHEMA {
            return Err(EventValidationError::new("tool_receipt_schema_unsupported"));
        }
        if self.tool_call_ordinal == 0 {
            return Err(EventValidationError::new("tool_receipt_ordinal_invalid"));
        }
        validate_sha256(&self.receipt_digest_sha256)?;
        validate_sha256(&self.tool_identity_sha256)
    }
}

#[derive(Serialize)]
struct ToolReceiptIdentity<'a> {
    call_id: &'a str,
    provider_name: &'a str,
}

pub fn tool_receipt_identity_sha256(
    call_id: &str,
    provider_name: &str,
) -> Result<String, EventValidationError> {
    validate_identity(call_id)?;
    validate_identity(provider_name)?;
    let identity = ToolReceiptIdentity {
        call_id,
        provider_name,
    };
    let encoded = serde_json::to_vec(&identity)
        .map_err(|_| EventValidationError::new("tool_receipt_identity_serialize_failed"))?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailureRecoverability {
    Recoverable,
    Fatal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolOutcome {
    Succeeded,
    TimedOut,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistantFinal {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCompleted {
    pub code: String,
    #[serde(
        default,
        deserialize_with = "deserialize_positive_u64",
        skip_serializing_if = "is_zero"
    )]
    pub tool_receipt_omitted_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunFailed {
    pub code: String,
    #[serde(
        default,
        deserialize_with = "deserialize_positive_u64",
        skip_serializing_if = "is_zero"
    )]
    pub tool_receipt_omitted_count: u64,
}

/// The atomic marker for a settled v2 run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub schema_version: String,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub run_spec_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_receipt_sha256: Option<String>,
    pub contract_id: String,
    pub contract_set_sha256: String,
    pub profile_id: String,
    pub terminal_status: TerminalStatus,
    pub terminal_phase: Option<TerminalPhase>,
    pub terminal_code: String,
    pub final_event_seq: u64,
    pub provider_turn_count: u64,
    pub tool_call_count: u64,
    pub provider_call_coverage: ProviderCallCoverage,
    pub usage_totals: UsageTotals,
    pub start_elapsed_ms: u64,
    pub end_elapsed_ms: u64,
    pub events_sha256: String,
}

impl RunRecord {
    pub fn validate(&self) -> Result<(), EventValidationError> {
        validate_modern_run_record(
            &self.schema_version,
            RUN_RECORD_SCHEMA,
            [
                &self.run_id,
                &self.trial_id,
                &self.attempt_id,
                &self.contract_id,
                &self.profile_id,
            ],
            [
                &self.run_spec_sha256,
                &self.contract_set_sha256,
                &self.events_sha256,
            ],
            self.deadline_receipt_sha256.as_deref(),
            self.terminal_status,
            self.terminal_phase,
            &self.terminal_code,
            self.provider_turn_count,
            &self.provider_call_coverage,
            self.start_elapsed_ms,
            self.end_elapsed_ms,
        )
    }
}

/// The committed v3 run record. Its deadline receipt binding is mandatory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecordV3 {
    pub schema_version: String,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub run_spec_sha256: String,
    pub deadline_receipt_sha256: String,
    pub contract_id: String,
    pub contract_set_sha256: String,
    pub profile_id: String,
    pub terminal_status: TerminalStatus,
    pub terminal_phase: Option<TerminalPhase>,
    pub terminal_code: String,
    pub final_event_seq: u64,
    pub provider_turn_count: u64,
    pub tool_call_count: u64,
    pub provider_call_coverage: ProviderCallCoverage,
    pub usage_totals: UsageTotals,
    pub start_elapsed_ms: u64,
    pub end_elapsed_ms: u64,
    pub events_sha256: String,
}

impl RunRecordV3 {
    pub fn from_v2_compatibility_view(record: &RunRecord, deadline_receipt_sha256: String) -> Self {
        Self {
            schema_version: RUN_RECORD_V3_SCHEMA.to_owned(),
            run_id: record.run_id.clone(),
            trial_id: record.trial_id.clone(),
            attempt_id: record.attempt_id.clone(),
            run_spec_sha256: record.run_spec_sha256.clone(),
            deadline_receipt_sha256,
            contract_id: record.contract_id.clone(),
            contract_set_sha256: record.contract_set_sha256.clone(),
            profile_id: record.profile_id.clone(),
            terminal_status: record.terminal_status,
            terminal_phase: record.terminal_phase,
            terminal_code: record.terminal_code.clone(),
            final_event_seq: record.final_event_seq,
            provider_turn_count: record.provider_turn_count,
            tool_call_count: record.tool_call_count,
            provider_call_coverage: record.provider_call_coverage.clone(),
            usage_totals: record.usage_totals.clone(),
            start_elapsed_ms: record.start_elapsed_ms,
            end_elapsed_ms: record.end_elapsed_ms,
            events_sha256: record.events_sha256.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), EventValidationError> {
        validate_modern_run_record(
            &self.schema_version,
            RUN_RECORD_V3_SCHEMA,
            [
                &self.run_id,
                &self.trial_id,
                &self.attempt_id,
                &self.contract_id,
                &self.profile_id,
            ],
            [
                &self.run_spec_sha256,
                &self.contract_set_sha256,
                &self.events_sha256,
            ],
            Some(&self.deadline_receipt_sha256),
            self.terminal_status,
            self.terminal_phase,
            &self.terminal_code,
            self.provider_turn_count,
            &self.provider_call_coverage,
            self.start_elapsed_ms,
            self.end_elapsed_ms,
        )
    }

    /// Stable in-memory view for existing direct `AgentRunOutcome.record` users.
    /// This compatibility value is never written as the terminal record.
    pub fn v2_compatibility_view(&self) -> RunRecord {
        RunRecord {
            schema_version: RUN_RECORD_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            trial_id: self.trial_id.clone(),
            attempt_id: self.attempt_id.clone(),
            run_spec_sha256: self.run_spec_sha256.clone(),
            deadline_receipt_sha256: Some(self.deadline_receipt_sha256.clone()),
            contract_id: self.contract_id.clone(),
            contract_set_sha256: self.contract_set_sha256.clone(),
            profile_id: self.profile_id.clone(),
            terminal_status: self.terminal_status,
            terminal_phase: self.terminal_phase,
            terminal_code: self.terminal_code.clone(),
            final_event_seq: self.final_event_seq,
            provider_turn_count: self.provider_turn_count,
            tool_call_count: self.tool_call_count,
            provider_call_coverage: self.provider_call_coverage.clone(),
            usage_totals: self.usage_totals.clone(),
            start_elapsed_ms: self.start_elapsed_ms,
            end_elapsed_ms: self.end_elapsed_ms,
            events_sha256: self.events_sha256.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_modern_run_record(
    schema_version: &str,
    expected_schema: &str,
    identities: [&str; 5],
    digests: [&str; 3],
    deadline_receipt_sha256: Option<&str>,
    terminal_status: TerminalStatus,
    terminal_phase: Option<TerminalPhase>,
    terminal_code: &str,
    provider_turn_count: u64,
    provider_call_coverage: &ProviderCallCoverage,
    start_elapsed_ms: u64,
    end_elapsed_ms: u64,
) -> Result<(), EventValidationError> {
    if schema_version != expected_schema {
        return Err(EventValidationError::new("run_record_schema_unsupported"));
    }
    for identity in identities {
        validate_identity(identity)?;
    }
    for digest in digests {
        validate_sha256(digest)?;
    }
    if let Some(digest) = deadline_receipt_sha256 {
        validate_sha256(digest)?;
    }
    validate_code(terminal_code)?;
    if end_elapsed_ms < start_elapsed_ms {
        return Err(EventValidationError::new(
            "run_record_elapsed_order_invalid",
        ));
    }
    match (terminal_status, terminal_phase) {
        (TerminalStatus::Success, None) => {}
        (TerminalStatus::Success, Some(_)) | (_, None) => {
            return Err(EventValidationError::new(
                "run_record_terminal_phase_invalid",
            ));
        }
        (TerminalStatus::ProviderFailure, Some(TerminalPhase::Provider))
        | (TerminalStatus::ToolFailure, Some(TerminalPhase::Tool | TerminalPhase::Bridge))
        | (TerminalStatus::DeadlineFailure, Some(TerminalPhase::Deadline))
        | (TerminalStatus::Cancelled, Some(TerminalPhase::Cancellation))
        | (
            TerminalStatus::RuntimeFailure,
            Some(TerminalPhase::Runtime | TerminalPhase::Artifact),
        ) => {}
        _ => {
            return Err(EventValidationError::new(
                "run_record_terminal_phase_invalid",
            ));
        }
    }
    provider_call_coverage.validate()?;
    if provider_turn_count != provider_call_coverage.requested {
        return Err(EventValidationError::new(
            "run_record_provider_turn_count_mismatch",
        ));
    }
    Ok(())
}

fn validate_media_history_policy_binding(
    version: Option<&str>,
    sha256: Option<&str>,
) -> Result<(), EventValidationError> {
    match (version, sha256) {
        (None, None) => Ok(()),
        (Some(version), Some(sha256))
            if version == MEDIA_HISTORY_POLICY_VERSION && sha256 == MEDIA_HISTORY_POLICY_SHA256 =>
        {
            Ok(())
        }
        _ => Err(EventValidationError::new(
            "media_history_policy_binding_invalid",
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalStatus {
    Success,
    ProviderFailure,
    ToolFailure,
    DeadlineFailure,
    Cancelled,
    RuntimeFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalPhase {
    Provider,
    Tool,
    Bridge,
    Deadline,
    Cancellation,
    Artifact,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCallCoverage {
    pub requested: u64,
    pub completed: u64,
    pub failed: u64,
    pub in_flight: u64,
    pub usage_present: u64,
    pub usage_absent: u64,
    pub usage_covered: u64,
    pub cost_present: u64,
    pub cost_absent: u64,
    pub state: UsageState,
}

impl ProviderCallCoverage {
    pub fn validate(&self) -> Result<(), EventValidationError> {
        let settled = self
            .completed
            .checked_add(self.failed)
            .ok_or_else(|| EventValidationError::new("provider_coverage_overflow"))?;
        let accounted = settled
            .checked_add(self.in_flight)
            .ok_or_else(|| EventValidationError::new("provider_coverage_overflow"))?;
        let usage_observed = self.usage_present.checked_add(self.usage_absent);
        let cost_observed = self.cost_present.checked_add(self.cost_absent);
        let legacy_shape =
            usage_observed == Some(self.completed) && cost_observed == Some(self.completed);
        let settled_shape = usage_observed == Some(settled) && cost_observed == Some(settled);
        if accounted != self.requested
            || !(legacy_shape || settled_shape)
            || self.usage_covered > self.requested
        {
            return Err(EventValidationError::new(
                "provider_coverage_arithmetic_invalid",
            ));
        }
        if self.state == UsageState::Complete
            && (self.in_flight != 0 || self.usage_covered != self.requested)
        {
            return Err(EventValidationError::new(
                "provider_coverage_complete_invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageState {
    Complete,
    Partial,
    Unavailable,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageTotals {
    pub input_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub provider_cost_ticks: Option<u64>,
}

/// Historic marker retained for explicit read-only compatibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyRunRecord {
    pub schema_version: String,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub run_spec_sha256: String,
    pub contract_id: String,
    pub contract_set_sha256: String,
    pub profile_id: String,
    pub terminal_status: LegacyTerminalStatus,
    pub terminal_code: String,
    pub final_event_seq: u64,
    pub provider_turn_count: u64,
    pub tool_call_count: u64,
    pub raw_usage: Vec<Option<Value>>,
    pub start_elapsed_ms: u64,
    pub end_elapsed_ms: u64,
    pub events_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyTerminalStatus {
    Success,
    ProviderFailure,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum VersionedRunRecord {
    V3(RunRecordV3),
    V2(RunRecord),
    V1(LegacyRunRecord),
}

impl VersionedRunRecord {
    pub fn validate(&self) -> Result<(), EventValidationError> {
        match self {
            Self::V3(record) => record.validate(),
            Self::V2(record) => record.validate(),
            Self::V1(record) => {
                if record.schema_version != LEGACY_RUN_RECORD_SCHEMA {
                    return Err(EventValidationError::new("run_record_schema_unsupported"));
                }
                Ok(())
            }
        }
    }

    pub fn v2_compatibility_view(&self) -> Option<RunRecord> {
        match self {
            Self::V3(record) => Some(record.v2_compatibility_view()),
            Self::V2(record) => Some(record.clone()),
            Self::V1(_) => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum RunRecordField {
    SchemaVersion,
    RunId,
    TrialId,
    AttemptId,
    RunSpecSha256,
    DeadlineReceiptSha256,
    ContractId,
    ContractSetSha256,
    ProfileId,
    TerminalStatus,
    TerminalPhase,
    TerminalCode,
    FinalEventSeq,
    ProviderTurnCount,
    ToolCallCount,
    ProviderCallCoverage,
    UsageTotals,
    RawUsage,
    StartElapsedMs,
    EndElapsedMs,
    EventsSha256,
}

#[derive(Default)]
struct RunRecordWire {
    schema_version: Option<String>,
    run_id: Option<String>,
    trial_id: Option<String>,
    attempt_id: Option<String>,
    run_spec_sha256: Option<String>,
    deadline_receipt_sha256: Option<String>,
    contract_id: Option<String>,
    contract_set_sha256: Option<String>,
    profile_id: Option<String>,
    terminal_status: Option<TerminalStatus>,
    terminal_phase: Option<Option<TerminalPhase>>,
    terminal_code: Option<String>,
    final_event_seq: Option<u64>,
    provider_turn_count: Option<u64>,
    tool_call_count: Option<u64>,
    provider_call_coverage: Option<ProviderCallCoverage>,
    usage_totals: Option<UsageTotals>,
    raw_usage: Option<Vec<Option<Value>>>,
    start_elapsed_ms: Option<u64>,
    end_elapsed_ms: Option<u64>,
    events_sha256: Option<String>,
}

struct VersionedRunRecordVisitor;

impl<'de> Visitor<'de> for VersionedRunRecordVisitor {
    type Value = VersionedRunRecord;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an exact versioned run record object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut wire = RunRecordWire::default();
        macro_rules! read_once {
            ($slot:expr, $name:literal) => {{
                if $slot.is_some() {
                    return Err(de::Error::duplicate_field($name));
                }
                $slot = Some(map.next_value()?);
            }};
        }
        while let Some(field) = map.next_key::<RunRecordField>()? {
            match field {
                RunRecordField::SchemaVersion => {
                    read_once!(wire.schema_version, "schema_version")
                }
                RunRecordField::RunId => read_once!(wire.run_id, "run_id"),
                RunRecordField::TrialId => read_once!(wire.trial_id, "trial_id"),
                RunRecordField::AttemptId => read_once!(wire.attempt_id, "attempt_id"),
                RunRecordField::RunSpecSha256 => {
                    read_once!(wire.run_spec_sha256, "run_spec_sha256")
                }
                RunRecordField::DeadlineReceiptSha256 => {
                    read_once!(wire.deadline_receipt_sha256, "deadline_receipt_sha256")
                }
                RunRecordField::ContractId => read_once!(wire.contract_id, "contract_id"),
                RunRecordField::ContractSetSha256 => {
                    read_once!(wire.contract_set_sha256, "contract_set_sha256")
                }
                RunRecordField::ProfileId => read_once!(wire.profile_id, "profile_id"),
                RunRecordField::TerminalStatus => {
                    read_once!(wire.terminal_status, "terminal_status")
                }
                RunRecordField::TerminalPhase => {
                    read_once!(wire.terminal_phase, "terminal_phase")
                }
                RunRecordField::TerminalCode => {
                    read_once!(wire.terminal_code, "terminal_code")
                }
                RunRecordField::FinalEventSeq => {
                    read_once!(wire.final_event_seq, "final_event_seq")
                }
                RunRecordField::ProviderTurnCount => {
                    read_once!(wire.provider_turn_count, "provider_turn_count")
                }
                RunRecordField::ToolCallCount => {
                    read_once!(wire.tool_call_count, "tool_call_count")
                }
                RunRecordField::ProviderCallCoverage => {
                    read_once!(wire.provider_call_coverage, "provider_call_coverage")
                }
                RunRecordField::UsageTotals => {
                    read_once!(wire.usage_totals, "usage_totals")
                }
                RunRecordField::RawUsage => read_once!(wire.raw_usage, "raw_usage"),
                RunRecordField::StartElapsedMs => {
                    read_once!(wire.start_elapsed_ms, "start_elapsed_ms")
                }
                RunRecordField::EndElapsedMs => {
                    read_once!(wire.end_elapsed_ms, "end_elapsed_ms")
                }
                RunRecordField::EventsSha256 => {
                    read_once!(wire.events_sha256, "events_sha256")
                }
            }
        }

        macro_rules! required {
            ($slot:expr, $name:literal) => {
                $slot.ok_or_else(|| de::Error::missing_field($name))?
            };
        }
        let schema_version = required!(wire.schema_version, "schema_version");
        let modern_shape = wire.raw_usage.is_none()
            && wire.terminal_phase.is_some()
            && wire.provider_call_coverage.is_some()
            && wire.usage_totals.is_some();
        let legacy_shape = wire.deadline_receipt_sha256.is_none()
            && wire.terminal_phase.is_none()
            && wire.provider_call_coverage.is_none()
            && wire.usage_totals.is_none()
            && wire.raw_usage.is_some();

        if schema_version == LEGACY_RUN_RECORD_SCHEMA {
            if !legacy_shape {
                return Err(de::Error::custom("run_record_shape_invalid"));
            }
            let terminal_status = match required!(wire.terminal_status, "terminal_status") {
                TerminalStatus::Success => LegacyTerminalStatus::Success,
                TerminalStatus::ProviderFailure => LegacyTerminalStatus::ProviderFailure,
                _ => return Err(de::Error::custom("legacy_terminal_status_invalid")),
            };
            return Ok(VersionedRunRecord::V1(LegacyRunRecord {
                schema_version,
                run_id: required!(wire.run_id, "run_id"),
                trial_id: required!(wire.trial_id, "trial_id"),
                attempt_id: required!(wire.attempt_id, "attempt_id"),
                run_spec_sha256: required!(wire.run_spec_sha256, "run_spec_sha256"),
                contract_id: required!(wire.contract_id, "contract_id"),
                contract_set_sha256: required!(wire.contract_set_sha256, "contract_set_sha256"),
                profile_id: required!(wire.profile_id, "profile_id"),
                terminal_status,
                terminal_code: required!(wire.terminal_code, "terminal_code"),
                final_event_seq: required!(wire.final_event_seq, "final_event_seq"),
                provider_turn_count: required!(wire.provider_turn_count, "provider_turn_count"),
                tool_call_count: required!(wire.tool_call_count, "tool_call_count"),
                raw_usage: required!(wire.raw_usage, "raw_usage"),
                start_elapsed_ms: required!(wire.start_elapsed_ms, "start_elapsed_ms"),
                end_elapsed_ms: required!(wire.end_elapsed_ms, "end_elapsed_ms"),
                events_sha256: required!(wire.events_sha256, "events_sha256"),
            }));
        }
        if !modern_shape {
            return Err(de::Error::custom("run_record_shape_invalid"));
        }
        if schema_version == RUN_RECORD_SCHEMA {
            return Ok(VersionedRunRecord::V2(RunRecord {
                schema_version,
                run_id: required!(wire.run_id, "run_id"),
                trial_id: required!(wire.trial_id, "trial_id"),
                attempt_id: required!(wire.attempt_id, "attempt_id"),
                run_spec_sha256: required!(wire.run_spec_sha256, "run_spec_sha256"),
                deadline_receipt_sha256: wire.deadline_receipt_sha256,
                contract_id: required!(wire.contract_id, "contract_id"),
                contract_set_sha256: required!(wire.contract_set_sha256, "contract_set_sha256"),
                profile_id: required!(wire.profile_id, "profile_id"),
                terminal_status: required!(wire.terminal_status, "terminal_status"),
                terminal_phase: required!(wire.terminal_phase, "terminal_phase"),
                terminal_code: required!(wire.terminal_code, "terminal_code"),
                final_event_seq: required!(wire.final_event_seq, "final_event_seq"),
                provider_turn_count: required!(wire.provider_turn_count, "provider_turn_count"),
                tool_call_count: required!(wire.tool_call_count, "tool_call_count"),
                provider_call_coverage: required!(
                    wire.provider_call_coverage,
                    "provider_call_coverage"
                ),
                usage_totals: required!(wire.usage_totals, "usage_totals"),
                start_elapsed_ms: required!(wire.start_elapsed_ms, "start_elapsed_ms"),
                end_elapsed_ms: required!(wire.end_elapsed_ms, "end_elapsed_ms"),
                events_sha256: required!(wire.events_sha256, "events_sha256"),
            }));
        }
        if schema_version == RUN_RECORD_V3_SCHEMA {
            return Ok(VersionedRunRecord::V3(RunRecordV3 {
                schema_version,
                run_id: required!(wire.run_id, "run_id"),
                trial_id: required!(wire.trial_id, "trial_id"),
                attempt_id: required!(wire.attempt_id, "attempt_id"),
                run_spec_sha256: required!(wire.run_spec_sha256, "run_spec_sha256"),
                deadline_receipt_sha256: required!(
                    wire.deadline_receipt_sha256,
                    "deadline_receipt_sha256"
                ),
                contract_id: required!(wire.contract_id, "contract_id"),
                contract_set_sha256: required!(wire.contract_set_sha256, "contract_set_sha256"),
                profile_id: required!(wire.profile_id, "profile_id"),
                terminal_status: required!(wire.terminal_status, "terminal_status"),
                terminal_phase: required!(wire.terminal_phase, "terminal_phase"),
                terminal_code: required!(wire.terminal_code, "terminal_code"),
                final_event_seq: required!(wire.final_event_seq, "final_event_seq"),
                provider_turn_count: required!(wire.provider_turn_count, "provider_turn_count"),
                tool_call_count: required!(wire.tool_call_count, "tool_call_count"),
                provider_call_coverage: required!(
                    wire.provider_call_coverage,
                    "provider_call_coverage"
                ),
                usage_totals: required!(wire.usage_totals, "usage_totals"),
                start_elapsed_ms: required!(wire.start_elapsed_ms, "start_elapsed_ms"),
                end_elapsed_ms: required!(wire.end_elapsed_ms, "end_elapsed_ms"),
                events_sha256: required!(wire.events_sha256, "events_sha256"),
            }));
        }
        Err(de::Error::custom("run_record_schema_unsupported"))
    }
}

impl<'de> Deserialize<'de> for VersionedRunRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(VersionedRunRecordVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventValidationError {
    code: &'static str,
}

impl EventValidationError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

fn validate_identity(value: &str) -> Result<(), EventValidationError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES || value.chars().any(char::is_control) {
        return Err(EventValidationError::new("event_identity_invalid"));
    }
    Ok(())
}

fn validate_code(value: &str) -> Result<(), EventValidationError> {
    if value.is_empty()
        || value.len() > MAX_TERMINAL_CODE_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
    {
        return Err(EventValidationError::new("event_code_invalid"));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), EventValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EventValidationError::new("event_sha256_invalid"));
    }
    Ok(())
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn deserialize_positive_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if value == 0 {
        return Err(de::Error::custom("optional count must be positive"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use crate::external_tool::{
        ExternalTerminalActorOriginV1, ExternalTerminalActorPhaseV1, ExternalTerminalActorSubtypeV1,
    };
    use serde_json::json;

    use super::{
        ContextCheckpointRejectedV1, ContextCheckpointedV1, EVENT_SCHEMA, Event, EventBody,
        LEGACY_EVENT_SCHEMA, LEGACY_RUN_RECORD_SCHEMA, LegacyTerminalStatus,
        MEDIA_HISTORY_POLICY_SHA256, MEDIA_HISTORY_POLICY_VERSION, MediaHistoryRequestReceiptV1,
        ProviderBudgetObservationV1, ProviderBudgetPhaseV1, ProviderCallCoverage, ProviderFailed,
        ProviderRequested, RUN_RECORD_SCHEMA, RUN_RECORD_V3_SCHEMA, RunCompleted, RunRecord,
        RunRecordV3, RunStarted, TOOL_RECEIPT_V1_SCHEMA, TerminalPhase, TerminalStatus, ToolFailed,
        ToolFailureRecoverability, ToolReceiptV1, UsageState, UsageTotals, VersionedRunRecord,
        tool_receipt_identity_sha256,
    };

    fn base_event(body: EventBody) -> Event {
        Event {
            schema_version: EVENT_SCHEMA.to_owned(),
            run_id: "run-1".to_owned(),
            trial_id: "trial-1".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            seq: 0,
            elapsed_ms: 0,
            body,
        }
    }

    fn v2_record() -> RunRecord {
        RunRecord {
            schema_version: RUN_RECORD_SCHEMA.to_owned(),
            run_id: "run-1".to_owned(),
            trial_id: "trial-1".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            run_spec_sha256: "a".repeat(64),
            deadline_receipt_sha256: None,
            contract_id: "nano-v1".to_owned(),
            contract_set_sha256: "b".repeat(64),
            profile_id: "nano-profile".to_owned(),
            terminal_status: TerminalStatus::ToolFailure,
            terminal_phase: Some(TerminalPhase::Bridge),
            terminal_code: "external_stdio_response_eof".to_owned(),
            final_event_seq: 4,
            provider_turn_count: 1,
            tool_call_count: 0,
            provider_call_coverage: ProviderCallCoverage {
                requested: 1,
                completed: 1,
                failed: 0,
                in_flight: 0,
                usage_present: 0,
                usage_absent: 1,
                usage_covered: 0,
                cost_present: 0,
                cost_absent: 1,
                state: UsageState::Partial,
            },
            usage_totals: UsageTotals {
                input_tokens: None,
                cached_input_tokens: None,
                output_tokens: None,
                provider_cost_ticks: None,
            },
            start_elapsed_ms: 0,
            end_elapsed_ms: 10,
            events_sha256: "c".repeat(64),
        }
    }

    fn v3_record() -> RunRecordV3 {
        let record = v2_record();
        RunRecordV3 {
            schema_version: RUN_RECORD_V3_SCHEMA.to_owned(),
            run_id: record.run_id,
            trial_id: record.trial_id,
            attempt_id: record.attempt_id,
            run_spec_sha256: record.run_spec_sha256,
            deadline_receipt_sha256: "d".repeat(64),
            contract_id: record.contract_id,
            contract_set_sha256: record.contract_set_sha256,
            profile_id: record.profile_id,
            terminal_status: record.terminal_status,
            terminal_phase: record.terminal_phase,
            terminal_code: record.terminal_code,
            final_event_seq: record.final_event_seq,
            provider_turn_count: record.provider_turn_count,
            tool_call_count: record.tool_call_count,
            provider_call_coverage: record.provider_call_coverage,
            usage_totals: record.usage_totals,
            start_elapsed_ms: record.start_elapsed_ms,
            end_elapsed_ms: record.end_elapsed_ms,
            events_sha256: record.events_sha256,
        }
    }

    #[test]
    fn tool_receipt_is_closed_typed_and_ordinal_bound() {
        let event = base_event(EventBody::ToolReceipt(ToolReceiptV1 {
            schema_version: TOOL_RECEIPT_V1_SCHEMA.to_owned(),
            phase: ExternalTerminalActorPhaseV1::MetaValidate,
            origin: ExternalTerminalActorOriginV1::Actor,
            primary_subtype: ExternalTerminalActorSubtypeV1::Completed,
            recovery_subtype: None,
            receipt_digest_sha256: "d".repeat(64),
            tool_identity_sha256: tool_receipt_identity_sha256("call-1", "run_terminal_command")
                .expect("identity digest"),
            tool_call_ordinal: 1,
        }));
        event.validate().expect("valid receipt");
        let value = serde_json::to_value(&event).expect("receipt event");
        assert_eq!(value["type"], "tool.receipt");
        assert_eq!(value["data"]["tool_call_ordinal"], 1);
        assert_eq!(value["data"]["phase"], "meta_validate");
        assert_eq!(value["data"]["origin"], "actor");
        assert_eq!(value["data"]["primary_subtype"], "completed");
        assert_eq!(value["data"]["recovery_subtype"], json!(null));
        assert!(value["data"]["receipt_digest_sha256"].is_string());
        assert!(value["data"]["tool_identity_sha256"].is_string());
        assert!(value["data"].get("actor_receipt").is_none());
        assert!(value["data"].get("call_id").is_none());
        assert!(value["data"].get("provider_name").is_none());

        let valid_value = value;
        for (field, invalid_value) in [
            ("phase", json!("unknown")),
            ("origin", json!("unknown")),
            ("primary_subtype", json!("unknown")),
            ("recovery_subtype", json!("unknown")),
        ] {
            let mut invalid = valid_value.clone();
            invalid["data"][field] = invalid_value;
            assert!(
                serde_json::from_value::<Event>(invalid).is_err(),
                "{field} must stay closed"
            );
        }
        for field in ["receipt_digest_sha256", "tool_identity_sha256"] {
            let mut invalid = valid_value.clone();
            invalid["data"][field] = json!("D".repeat(64));
            let decoded = serde_json::from_value::<Event>(invalid).expect("typed digest");
            assert!(decoded.validate().is_err(), "{field} must be canonical");
        }
        let mut nested = valid_value.clone();
        nested["data"]["actor_receipt"] = json!({"phase": "cleanup"});
        assert!(serde_json::from_value::<Event>(nested).is_err());

        let mut invalid = event;
        if let EventBody::ToolReceipt(telemetry) = &mut invalid.body {
            telemetry.tool_call_ordinal = 0;
        } else {
            panic!("tool receipt");
        }
        assert_eq!(
            invalid.validate().expect_err("zero ordinal").code(),
            "tool_receipt_ordinal_invalid"
        );
    }

    #[test]
    fn context_checkpoint_is_v3_only_hash_bound_and_monotonic() {
        let event = base_event(EventBody::ContextCheckpointed(ContextCheckpointedV1 {
            policy_version: "fresh-context-checkpoint-v1".to_owned(),
            source_history_sha256: "a".repeat(64),
            checkpoint_history_sha256: "b".repeat(64),
            source_history_items: 40,
            checkpoint_history_items: 3,
            provider_turn_count: 12,
            tool_call_count: 9,
            observed_input_tokens: 250_000,
            capsule_schema_version: None,
            capsule_sha256: None,
            capsule_bytes: None,
            prepare_turn_index: None,
            prepare_history_sha256: None,
            action_turn_cutoff: None,
            action_lease_ms: None,
            tail_reserve_ms: None,
        }));
        event.validate().expect("valid checkpoint receipt");
        let value = serde_json::to_value(&event).expect("checkpoint event");
        assert_eq!(value["type"], "context.checkpointed");
        assert_eq!(value["data"]["checkpoint_history_items"], 3);

        let mut legacy = event.clone();
        legacy.schema_version = LEGACY_EVENT_SCHEMA.to_owned();
        assert_eq!(
            legacy
                .validate()
                .expect_err("checkpoint requires v3")
                .code(),
            "event_v1_context_checkpoint_unsupported"
        );

        let mut non_compacting = event.clone();
        let EventBody::ContextCheckpointed(checkpoint) = &mut non_compacting.body else {
            panic!("context checkpoint");
        };
        checkpoint.checkpoint_history_items = checkpoint.source_history_items;
        assert_eq!(
            non_compacting
                .validate()
                .expect_err("checkpoint must reduce history")
                .code(),
            "context_checkpoint_receipt_invalid"
        );

        let mut unversioned = event;
        let EventBody::ContextCheckpointed(checkpoint) = &mut unversioned.body else {
            panic!("context checkpoint");
        };
        checkpoint.policy_version = "fresh-context-checkpoint-v2".to_owned();
        assert_eq!(
            unversioned
                .validate()
                .expect_err("policy version is closed")
                .code(),
            "context_checkpoint_receipt_invalid"
        );
    }

    #[test]
    fn semantic_checkpoint_receipt_and_rejection_are_closed_and_hash_bound() {
        let event = base_event(EventBody::ContextCheckpointed(ContextCheckpointedV1 {
            policy_version: "semantic-context-checkpoint-v1".to_owned(),
            source_history_sha256: "a".repeat(64),
            checkpoint_history_sha256: "b".repeat(64),
            source_history_items: 40,
            checkpoint_history_items: 4,
            provider_turn_count: 13,
            tool_call_count: 9,
            observed_input_tokens: 250_000,
            capsule_schema_version: Some("semantic-checkpoint-capsule-v1".to_owned()),
            capsule_sha256: Some("c".repeat(64)),
            capsule_bytes: Some(1_024),
            prepare_turn_index: Some(12),
            prepare_history_sha256: Some("d".repeat(64)),
            action_turn_cutoff: Some(20),
            action_lease_ms: Some(299_000),
            tail_reserve_ms: Some(900_000),
        }));
        event.validate().expect("semantic checkpoint receipt");

        let mut missing_lease = event.clone();
        let EventBody::ContextCheckpointed(checkpoint) = &mut missing_lease.body else {
            panic!("checkpoint");
        };
        checkpoint.action_lease_ms = None;
        assert_eq!(
            missing_lease
                .validate()
                .expect_err("lease is mandatory")
                .code(),
            "context_checkpoint_receipt_invalid"
        );

        let rejection = base_event(EventBody::ContextCheckpointRejected(
            ContextCheckpointRejectedV1 {
                policy_version: "semantic-context-checkpoint-v1".to_owned(),
                source_history_sha256: "a".repeat(64),
                prepare_history_sha256: "d".repeat(64),
                prepare_turn_index: 12,
                provider_turn_count: 13,
                reason: "semantic_checkpoint_capsule_json_invalid".to_owned(),
                request_emitted: true,
                response_received: true,
            },
        ));
        rejection.validate().expect("typed rejection receipt");
        let mut impossible = rejection;
        let EventBody::ContextCheckpointRejected(rejection) = &mut impossible.body else {
            panic!("checkpoint rejection");
        };
        rejection.prepare_turn_index = rejection.provider_turn_count;
        assert_eq!(
            impossible
                .validate()
                .expect_err("emitted request consumes a turn")
                .code(),
            "context_checkpoint_rejection_invalid"
        );
    }

    #[test]
    fn event_body_serializes_to_type_and_data() {
        let event = base_event(EventBody::RunCompleted(RunCompleted {
            code: "completed".to_owned(),
            tool_receipt_omitted_count: 0,
        }));
        event.validate().expect("valid v2 event");
        let value = serde_json::to_value(event).expect("serialize event");
        assert_eq!(value["schema_version"], "event-v3");
        assert_eq!(value["type"], "run.completed");
        assert_eq!(value["data"]["code"], "completed");
        assert!(value["data"].get("tool_receipt_omitted_count").is_none());
        let mut explicit_zero = value.clone();
        explicit_zero["data"]["tool_receipt_omitted_count"] = json!(0);
        assert!(serde_json::from_value::<Event>(explicit_zero).is_err());
        let mut positive = value;
        positive["data"]["tool_receipt_omitted_count"] = json!(1);
        let decoded = serde_json::from_value::<Event>(positive).expect("positive omission");
        let EventBody::RunCompleted(terminal) = decoded.body else {
            panic!("run.completed");
        };
        assert_eq!(terminal.tool_receipt_omitted_count, 1);
    }

    #[test]
    fn provider_failure_binds_usage_to_any_rejected_response() {
        let mut event = base_event(EventBody::ProviderFailed(ProviderFailed {
            turn_index: 2,
            code: "provider_model_drift".to_owned(),
            attempt_count: None,
            retry_code: None,
            retry_stage: None,
            rejected_call_count: None,
            response_usage: Some(json!({"input_tokens": 7, "output_tokens": 3})),
        }));
        event
            .validate()
            .expect("semantic rejection may retain response usage");

        let EventBody::ProviderFailed(failure) = &mut event.body else {
            panic!("provider failure");
        };
        failure.rejected_call_count = Some(1);
        assert_eq!(
            event
                .validate()
                .expect_err("call count belongs only to call-limit rejection")
                .code(),
            "provider_rejected_response_invalid"
        );

        let EventBody::ProviderFailed(failure) = &mut event.body else {
            panic!("provider failure");
        };
        failure.code = "provider_call_limit_exceeded".to_owned();
        event
            .validate()
            .expect("call-limit rejection binds count and usage");
    }

    #[test]
    fn deadline_receipt_binding_is_optional_but_sha256_typed() {
        let mut event = base_event(EventBody::RunStarted(RunStarted {
            task_id: "task-1".to_owned(),
            contract_id: "nano-v1".to_owned(),
            profile_id: "nano-profile".to_owned(),
            contract_set_sha256: "a".repeat(64),
            model: "model".to_owned(),
            run_spec_sha256: "b".repeat(64),
            deadline_receipt_sha256: None,
            media_history_policy_version: None,
            media_history_policy_sha256: None,
            completion_review_policy: None,
            context_checkpoint_policy_version: None,
            checkpoint_capsule_schema_version: None,
        }));
        event.validate().expect("legacy-compatible unbound event");
        let unbound = serde_json::to_value(&event).expect("serialize unbound event");
        assert!(unbound["data"].get("deadline_receipt_sha256").is_none());

        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.deadline_receipt_sha256 = Some("c".repeat(64));
        event.validate().expect("valid deadline receipt binding");
        let bound = serde_json::to_value(&event).expect("serialize bound event");
        assert_eq!(bound["data"]["deadline_receipt_sha256"], "c".repeat(64));

        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.deadline_receipt_sha256 = Some("not-a-sha".to_owned());
        assert_eq!(
            event
                .validate()
                .expect_err("reject invalid deadline receipt digest")
                .code(),
            "event_sha256_invalid"
        );
    }

    #[test]
    fn media_history_policy_binding_is_paired_versioned_and_legacy_optional() {
        let mut event = base_event(EventBody::RunStarted(RunStarted {
            task_id: "task-1".to_owned(),
            contract_id: "nano-v1".to_owned(),
            profile_id: "nano-profile".to_owned(),
            contract_set_sha256: "a".repeat(64),
            model: "model".to_owned(),
            run_spec_sha256: "b".repeat(64),
            deadline_receipt_sha256: None,
            media_history_policy_version: None,
            media_history_policy_sha256: None,
            completion_review_policy: None,
            context_checkpoint_policy_version: None,
            checkpoint_capsule_schema_version: None,
        }));
        event.validate().expect("legacy policy-unbound event");
        let legacy = serde_json::to_value(&event).expect("legacy event bytes");
        assert!(legacy["data"].get("media_history_policy_version").is_none());
        assert!(legacy["data"].get("media_history_policy_sha256").is_none());

        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.media_history_policy_version = Some(MEDIA_HISTORY_POLICY_VERSION.to_owned());
        assert_eq!(
            event.validate().expect_err("unpaired binding").code(),
            "media_history_policy_binding_invalid"
        );
        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.media_history_policy_sha256 = Some(MEDIA_HISTORY_POLICY_SHA256.to_owned());
        event.validate().expect("paired active policy binding");

        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.media_history_policy_sha256 = Some("c".repeat(64));
        assert_eq!(
            event.validate().expect_err("wrong config digest").code(),
            "media_history_policy_binding_invalid"
        );
        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.media_history_policy_sha256 = Some(MEDIA_HISTORY_POLICY_SHA256.to_owned());
        started.media_history_policy_version = Some("unknown-policy".to_owned());
        assert_eq!(
            event.validate().expect_err("unknown policy").code(),
            "media_history_policy_binding_invalid"
        );
    }

    #[test]
    fn completion_review_policy_binding_is_closed_and_semantic_schema_is_mandatory() {
        let mut event = base_event(EventBody::RunStarted(RunStarted {
            task_id: "task-1".to_owned(),
            contract_id: "nano-v1".to_owned(),
            profile_id: "nano-profile".to_owned(),
            contract_set_sha256: "a".repeat(64),
            model: "model".to_owned(),
            run_spec_sha256: "b".repeat(64),
            deadline_receipt_sha256: None,
            media_history_policy_version: None,
            media_history_policy_sha256: None,
            completion_review_policy: Some("semantic-checkpoint-v5".to_owned()),
            context_checkpoint_policy_version: Some("semantic-context-checkpoint-v1".to_owned()),
            checkpoint_capsule_schema_version: Some("semantic-checkpoint-capsule-v1".to_owned()),
        }));
        event.validate().expect("semantic policy provenance");

        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.checkpoint_capsule_schema_version = None;
        assert_eq!(
            event
                .validate()
                .expect_err("semantic capsule schema is mandatory")
                .code(),
            "completion_review_policy_binding_invalid"
        );

        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.completion_review_policy = Some("fresh-checkpoint-v4".to_owned());
        started.context_checkpoint_policy_version = Some("fresh-context-checkpoint-v1".to_owned());
        event.validate().expect("v4 policy provenance");

        let EventBody::RunStarted(started) = &mut event.body else {
            panic!("run.started");
        };
        started.completion_review_policy = Some("task-special-policy".to_owned());
        assert_eq!(
            event.validate().expect_err("policy label is closed").code(),
            "completion_review_policy_binding_invalid"
        );
    }

    #[test]
    fn provider_request_media_receipt_v1_is_compact_and_typed() {
        let receipt = MediaHistoryRequestReceiptV1 {
            history_sha256: "b".repeat(64),
            retained_count: 4,
            retained_bytes: 1024,
            evicted_total: 4,
        };
        let event = base_event(EventBody::ProviderRequested(ProviderRequested {
            turn_index: 2,
            history_item_count: 26,
            tool_count: 8,
            function_output_call_ids: (0..8).map(|index| format!("call-{index}")).collect(),
            media_history_receipt: Some(receipt),
            budget_observation: None,
            checkpoint_source_history_sha256: None,
        }));
        event.validate().expect("valid request receipt");
        let value = serde_json::to_value(&event).expect("request event");
        assert_eq!(value["data"]["media_history_receipt"]["retained_count"], 4);
        assert_eq!(
            value["data"]["media_history_receipt"]
                .as_object()
                .expect("receipt object")
                .len(),
            4
        );
    }

    #[test]
    fn provider_budget_observation_is_typed_and_legacy_optional() {
        let event = base_event(EventBody::ProviderRequested(ProviderRequested {
            turn_index: 2,
            history_item_count: 3,
            tool_count: 8,
            function_output_call_ids: Vec::new(),
            media_history_receipt: None,
            budget_observation: Some(ProviderBudgetObservationV1 {
                phase: ProviderBudgetPhaseV1::ActionOpen,
                budget_notice_visible: true,
                action_remaining_ms: 1_000,
                settlement_remaining_ms: 2_000,
                last_send_remaining_ms: 3_000,
            }),
            checkpoint_source_history_sha256: None,
        }));
        event.validate().expect("typed budget observation");
        let value = serde_json::to_value(&event).expect("request event");
        assert_eq!(value["data"]["budget_observation"]["phase"], "action_open");
    }

    #[test]
    fn checkpoint_prepare_request_binds_the_uncompacted_source_history() {
        let mut event = base_event(EventBody::ProviderRequested(ProviderRequested {
            turn_index: 12,
            history_item_count: 41,
            tool_count: 0,
            function_output_call_ids: vec!["call-8".to_owned()],
            media_history_receipt: Some(MediaHistoryRequestReceiptV1 {
                history_sha256: "b".repeat(64),
                retained_count: 41,
                retained_bytes: 120_000,
                evicted_total: 0,
            }),
            budget_observation: Some(ProviderBudgetObservationV1 {
                phase: ProviderBudgetPhaseV1::CheckpointPrepare,
                budget_notice_visible: false,
                action_remaining_ms: 1_200_000,
                settlement_remaining_ms: 1_100_000,
                last_send_remaining_ms: 1_000_000,
            }),
            checkpoint_source_history_sha256: Some("a".repeat(64)),
        }));
        event.validate().expect("prepare source binding");

        let EventBody::ProviderRequested(requested) = &mut event.body else {
            panic!("provider.requested");
        };
        requested.checkpoint_source_history_sha256 = None;
        assert_eq!(
            event
                .validate()
                .expect_err("prepare source digest is mandatory")
                .code(),
            "provider_checkpoint_binding_invalid"
        );

        let EventBody::ProviderRequested(requested) = &mut event.body else {
            panic!("provider.requested");
        };
        requested.budget_observation.as_mut().expect("budget").phase =
            ProviderBudgetPhaseV1::ActionOpen;
        requested.checkpoint_source_history_sha256 = Some("a".repeat(64));
        assert_eq!(
            event
                .validate()
                .expect_err("source digest is prepare-only")
                .code(),
            "provider_checkpoint_binding_invalid"
        );
    }

    #[test]
    fn provider_coverage_accepts_settled_failure_usage_with_in_flight_request() {
        let coverage = ProviderCallCoverage {
            requested: 2,
            completed: 0,
            failed: 1,
            in_flight: 1,
            usage_present: 1,
            usage_absent: 0,
            usage_covered: 1,
            cost_present: 0,
            cost_absent: 1,
            state: UsageState::Partial,
        };
        coverage
            .validate()
            .expect("failed response usage is settled while one request remains in flight");

        let mut mixed_shape = coverage;
        mixed_shape.cost_absent = 0;
        assert_eq!(
            mixed_shape
                .validate()
                .expect_err("usage and cost coverage must use the same generation")
                .code(),
            "provider_coverage_arithmetic_invalid"
        );
    }

    #[test]
    fn tool_failure_is_typed_and_v1_rejects_the_new_variant() {
        let mut event = base_event(EventBody::ToolFailed(ToolFailed {
            call_id: "call-1".to_owned(),
            provider_name: "run_terminal_command".to_owned(),
            code: "external_stdio_response_eof".to_owned(),
            execution_may_have_started: true,
            cleanup_verified: None,
            census_verified: None,
            recoverability: ToolFailureRecoverability::Fatal,
        }));
        event.validate().expect("valid v2 tool failure");
        event.schema_version = LEGACY_EVENT_SCHEMA.to_owned();
        assert_eq!(
            event
                .validate()
                .expect_err("v1 cannot claim tool.failed")
                .code(),
            "event_v1_tool_failed_unsupported"
        );
    }

    #[test]
    fn v2_record_is_strict_and_legacy_record_remains_readable() {
        let record = v2_record();
        record.validate().expect("valid v2 record");
        let mut value = serde_json::to_value(&record).expect("record value");
        assert!(value.get("deadline_receipt_sha256").is_none());
        value["unknown"] = json!(true);
        assert!(serde_json::from_value::<RunRecord>(value).is_err());

        let mut bound_record = record.clone();
        bound_record.deadline_receipt_sha256 = Some("d".repeat(64));
        bound_record.validate().expect("valid receipt-bound record");
        bound_record.deadline_receipt_sha256 = Some("not-a-sha".to_owned());
        assert_eq!(
            bound_record
                .validate()
                .expect_err("reject invalid deadline receipt digest")
                .code(),
            "event_sha256_invalid"
        );

        let legacy = json!({
            "schema_version": LEGACY_RUN_RECORD_SCHEMA,
            "run_id": "run-1",
            "trial_id": "trial-1",
            "attempt_id": "attempt-0",
            "run_spec_sha256": "a".repeat(64),
            "contract_id": "nano-v1",
            "contract_set_sha256": "b".repeat(64),
            "profile_id": "nano-profile",
            "terminal_status": "provider_failure",
            "terminal_code": "provider_failed",
            "final_event_seq": 3,
            "provider_turn_count": 1,
            "tool_call_count": 0,
            "raw_usage": [null],
            "start_elapsed_ms": 0,
            "end_elapsed_ms": 10,
            "events_sha256": "c".repeat(64)
        });
        let parsed: VersionedRunRecord =
            serde_json::from_value(legacy).expect("parse historic record");
        parsed.validate().expect("valid historic record");
        assert!(matches!(
            parsed,
            VersionedRunRecord::V1(super::LegacyRunRecord {
                terminal_status: LegacyTerminalStatus::ProviderFailure,
                ..
            })
        ));
    }

    #[test]
    fn v2_no_deadline_run_wire_golden_is_unchanged() {
        let bytes = serde_json::to_vec(&v2_record()).expect("serialize v2");
        let expected = concat!(
            "{\"schema_version\":\"nano-run-record-v2\",\"run_id\":\"run-1\",",
            "\"trial_id\":\"trial-1\",\"attempt_id\":\"attempt-0\",",
            "\"run_spec_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
            "\"contract_id\":\"nano-v1\",",
            "\"contract_set_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
            "\"profile_id\":\"nano-profile\",\"terminal_status\":\"tool_failure\",",
            "\"terminal_phase\":\"bridge\",\"terminal_code\":\"external_stdio_response_eof\",",
            "\"final_event_seq\":4,\"provider_turn_count\":1,\"tool_call_count\":0,",
            "\"provider_call_coverage\":{\"requested\":1,\"completed\":1,\"failed\":0,",
            "\"in_flight\":0,\"usage_present\":0,\"usage_absent\":1,\"usage_covered\":0,",
            "\"cost_present\":0,\"cost_absent\":1,\"state\":\"partial\"},",
            "\"usage_totals\":{\"input_tokens\":null,\"cached_input_tokens\":null,",
            "\"output_tokens\":null,\"provider_cost_ticks\":null},",
            "\"start_elapsed_ms\":0,\"end_elapsed_ms\":10,",
            "\"events_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}"
        )
        .as_bytes();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn versioned_run_record_from_slice_dispatches_all_four_exact_shapes() {
        let legacy = serde_json::json!({
            "schema_version": LEGACY_RUN_RECORD_SCHEMA,
            "run_id": "run-1",
            "trial_id": "trial-1",
            "attempt_id": "attempt-0",
            "run_spec_sha256": "a".repeat(64),
            "contract_id": "nano-v1",
            "contract_set_sha256": "b".repeat(64),
            "profile_id": "nano-profile",
            "terminal_status": "provider_failure",
            "terminal_code": "provider_failed",
            "final_event_seq": 3,
            "provider_turn_count": 1,
            "tool_call_count": 0,
            "raw_usage": [null],
            "start_elapsed_ms": 0,
            "end_elapsed_ms": 10,
            "events_sha256": "c".repeat(64)
        });
        let parsed: VersionedRunRecord =
            serde_json::from_slice(&serde_json::to_vec(&legacy).expect("legacy bytes"))
                .expect("v1");
        assert!(matches!(parsed, VersionedRunRecord::V1(_)));

        let record = v2_record();
        let bytes = serde_json::to_vec(&record).expect("v2 bytes");
        let parsed: VersionedRunRecord = serde_json::from_slice(&bytes).expect("v2");
        assert!(matches!(parsed, VersionedRunRecord::V2(_)));

        let mut compatibility = record;
        compatibility.deadline_receipt_sha256 = Some("d".repeat(64));
        let bytes = serde_json::to_vec(&compatibility).expect("v2 compat bytes");
        let parsed: VersionedRunRecord = serde_json::from_slice(&bytes).expect("v2 compat");
        assert!(matches!(parsed, VersionedRunRecord::V2(_)));

        let bytes = serde_json::to_vec(&v3_record()).expect("v3 bytes");
        let parsed: VersionedRunRecord = serde_json::from_slice(&bytes).expect("v3");
        assert!(matches!(parsed, VersionedRunRecord::V3(_)));
    }

    #[test]
    fn versioned_run_record_byte_dispatch_rejects_ambiguous_documents() {
        let bytes = serde_json::to_string(&v2_record()).expect("v2 text");
        let duplicate_schema = format!(
            "{{\"schema_version\":\"nano-run-record-v2\",{}",
            &bytes[1..]
        );
        assert!(serde_json::from_slice::<VersionedRunRecord>(duplicate_schema.as_bytes()).is_err());
        let duplicate_run_id = format!("{{\"run_id\":\"other\",{}", &bytes[1..]);
        assert!(serde_json::from_slice::<VersionedRunRecord>(duplicate_run_id.as_bytes()).is_err());
        assert!(
            serde_json::from_slice::<VersionedRunRecord>(format!("{bytes}{{}}").as_bytes())
                .is_err()
        );
        let unknown = bytes.replacen(
            "\"run_id\":\"run-1\"",
            "\"unknown\":true,\"run_id\":\"run-1\"",
            1,
        );
        assert!(serde_json::from_slice::<VersionedRunRecord>(unknown.as_bytes()).is_err());
        let missing = bytes.replacen("\"run_id\":\"run-1\",", "", 1);
        assert!(serde_json::from_slice::<VersionedRunRecord>(missing.as_bytes()).is_err());
        let mismatched = bytes.replacen(RUN_RECORD_SCHEMA, RUN_RECORD_V3_SCHEMA, 1);
        assert!(serde_json::from_slice::<VersionedRunRecord>(mismatched.as_bytes()).is_err());
        assert!(serde_json::from_slice::<VersionedRunRecord>(b"{\"schema_version\":NaN}").is_err());
    }

    #[test]
    fn versioned_run_record_accepts_arbitrary_field_order_and_v3_requires_digest() {
        let bytes = serde_json::to_string(&v2_record()).expect("v2 text");
        let prefix = format!("{{\"schema_version\":\"{RUN_RECORD_SCHEMA}\",");
        let rest = bytes.strip_prefix(&prefix).expect("schema first");
        let reordered = format!(
            "{{{},\"schema_version\":\"{RUN_RECORD_SCHEMA}\"}}",
            rest.strip_suffix('}').expect("object")
        );
        let parsed: VersionedRunRecord =
            serde_json::from_slice(reordered.as_bytes()).expect("field order");
        assert!(matches!(parsed, VersionedRunRecord::V2(_)));

        let v3 = serde_json::to_string(&v3_record()).expect("v3 text");
        let missing = v3.replacen(
            &format!("\"deadline_receipt_sha256\":\"{}\",", "d".repeat(64)),
            "",
            1,
        );
        assert!(serde_json::from_slice::<VersionedRunRecord>(missing.as_bytes()).is_err());
        let invalid = v3.replacen(&"d".repeat(64), "not-a-sha", 1);
        let parsed: VersionedRunRecord =
            serde_json::from_slice(invalid.as_bytes()).expect("shape parses");
        assert_eq!(
            parsed.validate().expect_err("digest validation").code(),
            "event_sha256_invalid"
        );
    }
}
