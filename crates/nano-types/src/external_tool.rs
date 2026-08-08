//! Strict host-runtime to sandbox-tool JSONL protocol.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::contract::AgentProfile;
use crate::run_spec::RunSpec;

/// The read-only legacy external tool bridge schema.
pub const EXTERNAL_TOOL_STDIO_SCHEMA: &str = "external-tool-stdio-v2";
/// The live, absolute-deadline external tool bridge schema.
pub const EXTERNAL_TOOL_STDIO_V3_SCHEMA: &str = "external-tool-stdio-v3";
pub const TERMINAL_ACTOR_RECEIPT_V1_SCHEMA: &str = "terminal-actor-receipt-v1";
pub const EXTERNAL_BACKGROUND_START_PROOF_VERSION: &str = "background-start-no-id-proof-v1";
pub const MEDIA_HISTORY_POLICY_VERSION: &str = "rolling-media-history-latest-suffix-v1";
pub const MEDIA_HISTORY_POLICY_SHA256: &str =
    "b34dc9dd4f9d37c53e98fbf2fd3a3d816ba3e1071dd3e981161f23d16ffb6cd6";
pub const READ_FILE_MEDIA_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const READ_FILE_MEDIA_MAX_DIMENSION: u64 = 8_192;
pub const READ_FILE_MEDIA_MAX_PIXELS: u64 = 25_000_000;
pub const READ_FILE_MEDIA_MAX_HISTORY_BYTES: u64 = 8 * 1024 * 1024;
pub const READ_FILE_MEDIA_MAX_HISTORY_ITEMS: u64 = 4;

/// Direction and message kind on the reserved JSONL channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalToolMessageType {
    #[serde(rename = "tool.request")]
    Request,
    #[serde(rename = "tool.response")]
    Response,
}

/// How this operation changed the actor-owned process lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProcessDisposition {
    NoProcess,
    ForegroundCleaned,
    BackgroundRetained,
    BackgroundTerminated,
}

/// Closed, model-visible outcomes for a background start that published no ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalBackgroundStartKind {
    NotStarted,
    QuickExit,
}

/// Versioned proof facts consumed with the bound request and lifecycle evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalBackgroundStartObservation {
    pub proof_version: String,
    pub kind: ExternalBackgroundStartKind,
    pub task_id_published: bool,
    pub child_exit_code: Option<i32>,
}

/// The remote process environment policy. Values are resolved in the sandbox,
/// never copied from the host runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEnvironmentPolicy {
    pub clear: bool,
    pub inherit_remote: Vec<String>,
}

impl ExternalEnvironmentPolicy {
    pub fn minimal_remote() -> Self {
        Self {
            clear: true,
            inherit_remote: ["HOME", "LANG", "LC_ALL", "PATH", "TERM", "TMPDIR", "USER"]
                .map(str::to_owned)
                .to_vec(),
        }
    }
}

/// Profile bounds needed by the sandbox-resident foreground actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolLimits {
    pub arguments_cap_bytes: u64,
    pub max_path_bytes: u64,
    pub max_read_or_write_bytes: u64,
    pub max_directory_entries: u64,
    pub max_grep_matches: u64,
    pub max_replacements: u64,
    pub max_background_processes: u64,
    pub process_spool_bytes_per_process: u64,
    pub process_spool_bytes_per_run: u64,
    pub background_output_wait_max_ms: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub read_file_media_enabled: bool,
}

/// One foreground execution request. The exact serialized bytes (without LF)
/// are committed by the corresponding response's `request_sha256`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolRequest {
    pub schema_version: String,
    pub message_type: ExternalToolMessageType,
    pub seq: u64,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub arguments_json: String,
    pub logical_cwd: String,
    pub timeout_ms: u64,
    pub term_grace_ms: u64,
    pub kill_confirmation_timeout_ms: u64,
    pub stdout_cap_bytes: u64,
    pub stderr_cap_bytes: u64,
    pub environment: ExternalEnvironmentPolicy,
    pub limits: ExternalToolLimits,
}

impl ExternalToolRequest {
    pub fn for_call(
        seq: u64,
        spec: &RunSpec,
        profile: &AgentProfile,
        call_id: String,
        tool_name: String,
        arguments_json: String,
        timeout_ms: u64,
    ) -> Result<Self, ExternalToolProtocolError> {
        let logical_cwd = spec
            .workspace_dir
            .to_str()
            .ok_or(ExternalToolProtocolError::NonUtf8LogicalCwd)?
            .to_owned();
        let per_stream = profile.process.process_spool_bytes_per_process.div_ceil(2);
        let stdout_cap_bytes = if tool_name == "run_terminal_command" {
            per_stream
        } else {
            per_stream.min(profile.tools.model_tool_output_bytes_per_call)
        };
        Ok(Self {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Request,
            seq,
            run_id: spec.run_id.clone(),
            trial_id: spec.trial_id.clone(),
            attempt_id: spec.attempt_id.clone(),
            call_id,
            tool_name,
            arguments_json,
            logical_cwd,
            timeout_ms,
            term_grace_ms: profile.process.term_grace_ms,
            kill_confirmation_timeout_ms: profile.process.kill_confirmation_timeout_ms,
            stdout_cap_bytes,
            stderr_cap_bytes: per_stream,
            environment: ExternalEnvironmentPolicy::minimal_remote(),
            limits: ExternalToolLimits {
                arguments_cap_bytes: profile.transport.max_function_arguments_bytes,
                max_path_bytes: profile.tools.max_path_bytes,
                max_read_or_write_bytes: profile.tools.max_read_or_write_bytes,
                max_directory_entries: profile.tools.max_directory_entries,
                max_grep_matches: profile.tools.max_grep_matches,
                max_replacements: profile.tools.max_replacements,
                max_background_processes: profile.process.max_background_processes,
                process_spool_bytes_per_process: profile.process.process_spool_bytes_per_process,
                process_spool_bytes_per_run: profile.process.process_spool_bytes_per_run,
                background_output_wait_max_ms: profile.tools.background_output_wait_max_ms,
                read_file_media_enabled: profile.tools.read_file_media_enabled,
            },
        })
    }

    /// Hash the exact deterministic JSON object, excluding JSONL framing.
    pub fn sha256(&self) -> Result<String, ExternalToolProtocolError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| ExternalToolProtocolError::SerializationFailed)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

/// Absolute cutoffs and frozen reserves copied from the bound run deadline.
///
/// This helper is not itself serialized: [`ExternalToolRequestV3`] keeps the
/// wire fields flat so strict readers can reject every missing/unknown field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalToolDeadlineFields {
    pub actor_done_monotonic_ns: u64,
    pub tool_settled_monotonic_ns: u64,
    pub last_send_monotonic_ns: u64,
    pub runtime_final_monotonic_ns: u64,
    pub cleanup_start_monotonic_ns: u64,
    pub hard_deadline_monotonic_ns: u64,
    pub cleanup_reserve_ms: u64,
    pub terminalization_reserve_ms: u64,
    pub provider_send_reserve_ms: u64,
    pub process_settlement_reserve_ms: u64,
    pub deadline_receipt_sha256: String,
}

impl ExternalToolDeadlineFields {
    pub fn validate(&self) -> Result<(), ExternalToolProtocolError> {
        validate_sha256(&self.deadline_receipt_sha256)?;
        if [
            self.actor_done_monotonic_ns,
            self.tool_settled_monotonic_ns,
            self.last_send_monotonic_ns,
            self.runtime_final_monotonic_ns,
            self.cleanup_start_monotonic_ns,
            self.hard_deadline_monotonic_ns,
            self.cleanup_reserve_ms,
            self.terminalization_reserve_ms,
            self.provider_send_reserve_ms,
            self.process_settlement_reserve_ms,
        ]
        .contains(&0)
        {
            return Err(ExternalToolProtocolError::InvalidDeadline);
        }
        if self.last_send_monotonic_ns != self.runtime_final_monotonic_ns {
            return Err(ExternalToolProtocolError::InvalidDeadline);
        }
        for (earlier, later) in [
            (self.actor_done_monotonic_ns, self.tool_settled_monotonic_ns),
            (self.tool_settled_monotonic_ns, self.last_send_monotonic_ns),
            (
                self.runtime_final_monotonic_ns,
                self.cleanup_start_monotonic_ns,
            ),
            (
                self.cleanup_start_monotonic_ns,
                self.hard_deadline_monotonic_ns,
            ),
        ] {
            if earlier >= later {
                return Err(ExternalToolProtocolError::InvalidDeadline);
            }
        }
        for (earlier, later, reserve_ms) in [
            (
                self.actor_done_monotonic_ns,
                self.tool_settled_monotonic_ns,
                self.process_settlement_reserve_ms,
            ),
            (
                self.tool_settled_monotonic_ns,
                self.last_send_monotonic_ns,
                self.provider_send_reserve_ms,
            ),
            (
                self.runtime_final_monotonic_ns,
                self.cleanup_start_monotonic_ns,
                self.terminalization_reserve_ms,
            ),
            (
                self.cleanup_start_monotonic_ns,
                self.hard_deadline_monotonic_ns,
                self.cleanup_reserve_ms,
            ),
        ] {
            let expected_ns = reserve_ms
                .checked_mul(1_000_000)
                .ok_or(ExternalToolProtocolError::InvalidDeadline)?;
            if later.checked_sub(earlier) != Some(expected_ns) {
                return Err(ExternalToolProtocolError::InvalidDeadline);
            }
        }
        Ok(())
    }
}

/// One live v3 request. `operation_timeout_ms` is only the semantic operation
/// cap; the absolute actor/settlement cutoffs own transport cancellation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolRequestV3 {
    pub schema_version: String,
    pub message_type: ExternalToolMessageType,
    pub seq: u64,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub arguments_json: String,
    pub logical_cwd: String,
    pub operation_timeout_ms: u64,
    pub term_grace_ms: u64,
    pub kill_confirmation_timeout_ms: u64,
    pub stdout_cap_bytes: u64,
    pub stderr_cap_bytes: u64,
    pub environment: ExternalEnvironmentPolicy,
    pub limits: ExternalToolLimits,
    pub actor_done_monotonic_ns: u64,
    pub tool_settled_monotonic_ns: u64,
    pub last_send_monotonic_ns: u64,
    pub runtime_final_monotonic_ns: u64,
    pub cleanup_start_monotonic_ns: u64,
    pub hard_deadline_monotonic_ns: u64,
    pub cleanup_reserve_ms: u64,
    pub terminalization_reserve_ms: u64,
    pub provider_send_reserve_ms: u64,
    pub process_settlement_reserve_ms: u64,
    pub deadline_receipt_sha256: String,
}

impl ExternalToolRequestV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn for_call(
        seq: u64,
        spec: &RunSpec,
        profile: &AgentProfile,
        call_id: String,
        tool_name: String,
        arguments_json: String,
        operation_timeout_ms: u64,
        deadline: &ExternalToolDeadlineFields,
    ) -> Result<Self, ExternalToolProtocolError> {
        if operation_timeout_ms == 0 {
            return Err(ExternalToolProtocolError::InvalidDeadline);
        }
        deadline.validate()?;
        let legacy = ExternalToolRequest::for_call(
            seq,
            spec,
            profile,
            call_id,
            tool_name,
            arguments_json,
            operation_timeout_ms,
        )?;
        Ok(Self {
            schema_version: EXTERNAL_TOOL_STDIO_V3_SCHEMA.to_owned(),
            message_type: legacy.message_type,
            seq: legacy.seq,
            run_id: legacy.run_id,
            trial_id: legacy.trial_id,
            attempt_id: legacy.attempt_id,
            call_id: legacy.call_id,
            tool_name: legacy.tool_name,
            arguments_json: legacy.arguments_json,
            logical_cwd: legacy.logical_cwd,
            operation_timeout_ms,
            term_grace_ms: legacy.term_grace_ms,
            kill_confirmation_timeout_ms: legacy.kill_confirmation_timeout_ms,
            stdout_cap_bytes: legacy.stdout_cap_bytes,
            stderr_cap_bytes: legacy.stderr_cap_bytes,
            environment: legacy.environment,
            limits: legacy.limits,
            actor_done_monotonic_ns: deadline.actor_done_monotonic_ns,
            tool_settled_monotonic_ns: deadline.tool_settled_monotonic_ns,
            last_send_monotonic_ns: deadline.last_send_monotonic_ns,
            runtime_final_monotonic_ns: deadline.runtime_final_monotonic_ns,
            cleanup_start_monotonic_ns: deadline.cleanup_start_monotonic_ns,
            hard_deadline_monotonic_ns: deadline.hard_deadline_monotonic_ns,
            cleanup_reserve_ms: deadline.cleanup_reserve_ms,
            terminalization_reserve_ms: deadline.terminalization_reserve_ms,
            provider_send_reserve_ms: deadline.provider_send_reserve_ms,
            process_settlement_reserve_ms: deadline.process_settlement_reserve_ms,
            deadline_receipt_sha256: deadline.deadline_receipt_sha256.clone(),
        })
    }

    pub fn deadline_fields(&self) -> ExternalToolDeadlineFields {
        ExternalToolDeadlineFields {
            actor_done_monotonic_ns: self.actor_done_monotonic_ns,
            tool_settled_monotonic_ns: self.tool_settled_monotonic_ns,
            last_send_monotonic_ns: self.last_send_monotonic_ns,
            runtime_final_monotonic_ns: self.runtime_final_monotonic_ns,
            cleanup_start_monotonic_ns: self.cleanup_start_monotonic_ns,
            hard_deadline_monotonic_ns: self.hard_deadline_monotonic_ns,
            cleanup_reserve_ms: self.cleanup_reserve_ms,
            terminalization_reserve_ms: self.terminalization_reserve_ms,
            provider_send_reserve_ms: self.provider_send_reserve_ms,
            process_settlement_reserve_ms: self.process_settlement_reserve_ms,
            deadline_receipt_sha256: self.deadline_receipt_sha256.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), ExternalToolProtocolError> {
        if self.schema_version != EXTERNAL_TOOL_STDIO_V3_SCHEMA
            || self.message_type != ExternalToolMessageType::Request
            || self.operation_timeout_ms == 0
        {
            return Err(ExternalToolProtocolError::InvalidSettlement);
        }
        for identity in [
            &self.run_id,
            &self.trial_id,
            &self.attempt_id,
            &self.call_id,
            &self.tool_name,
        ] {
            validate_identity(identity)?;
        }
        self.deadline_fields().validate()
    }

    /// Hash the exact deterministic JSON object, excluding JSONL framing.
    pub fn sha256(&self) -> Result<String, ExternalToolProtocolError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| ExternalToolProtocolError::SerializationFailed)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

/// Cleanup proof produced by the sandbox actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCleanupEvidence {
    pub attempted: bool,
    pub term_sent: bool,
    pub kill_sent: bool,
    pub verified: bool,
}

/// Post-cleanup census of the actor-owned process group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalProcessCensus {
    pub verified: bool,
    pub owned_processes_alive: u64,
}

/// One strict response. Output streams are RFC 4648 standard base64.
///
/// This flat shape is retained as a read-only compatibility form for the
/// original external-tool-stdio-v2 bridge. New bridges emit
/// [`ExternalToolSettlement`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolResponse {
    pub schema_version: String,
    pub message_type: ExternalToolMessageType,
    pub seq: u64,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub call_id: String,
    pub tool_name: String,
    pub request_sha256: String,
    pub return_code: i32,
    pub timed_out: bool,
    pub stdout_base64: String,
    pub stderr_base64: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub process_disposition: ExternalProcessDisposition,
    pub target_task_id: Option<String>,
    pub cleanup: ExternalCleanupEvidence,
    pub census: ExternalProcessCensus,
}

/// A v2 response with an explicit completed/fatal settlement discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "settlement", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalToolSettlement {
    Completed {
        schema_version: String,
        message_type: ExternalToolMessageType,
        seq: u64,
        run_id: String,
        trial_id: String,
        attempt_id: String,
        call_id: String,
        tool_name: String,
        request_sha256: String,
        result: ExternalToolCompletedResult,
    },
    Fatal {
        schema_version: String,
        message_type: ExternalToolMessageType,
        seq: u64,
        run_id: String,
        trial_id: String,
        attempt_id: String,
        call_id: String,
        tool_name: String,
        request_sha256: String,
        failure: ExternalToolFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolCompletedResult {
    pub return_code: i32,
    pub timed_out: bool,
    pub stdout_base64: String,
    pub stderr_base64: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub process_disposition: ExternalProcessDisposition,
    pub target_task_id: Option<String>,
    pub cleanup: ExternalCleanupEvidence,
    pub census: ExternalProcessCensus,
    pub media: Option<Box<ExternalMediaPayload>>,
}

/// The only non-null wait clamp reason accepted on the v3 wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalToolWaitReasonCode {
    RuntimeBudget,
}

/// Required nullable v3 wire field. Unlike `Option`, a missing field is
/// rejected by Serde because this enum itself has no default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExternalToolWaitReason {
    Reason(ExternalToolWaitReasonCode),
    None(()),
}

impl ExternalToolWaitReason {
    pub fn runtime_budget() -> Self {
        Self::Reason(ExternalToolWaitReasonCode::RuntimeBudget)
    }

    pub fn is_runtime_budget(self) -> bool {
        matches!(
            self,
            Self::Reason(ExternalToolWaitReasonCode::RuntimeBudget)
        )
    }
}

/// Closed terminal-actor phase at which one foreground outcome became authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTerminalActorPhaseV1 {
    MappingPreflight,
    RemoteSetup,
    CommandUpload,
    RemoteExec,
    RecoveryDownload,
    ResultDownload,
    MetaValidate,
    Cleanup,
    Census,
    ActorDone,
}

/// Closed provenance for one terminal-actor primary outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTerminalActorOriginV1 {
    Semantic,
    Transport,
    Protocol,
    Actor,
}

/// Closed, secret-free terminal-actor outcome discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTerminalActorSubtypeV1 {
    Completed,
    SemanticExecutionTimedOut,
    ActorDeadlineExceeded,
    WorkspaceMappingCheckTimeout,
    WorkspaceMappingChanged,
    RequestSetupFailed,
    CommandUploadFailed,
    RunTransportTimeout,
    RunTransportFailed,
    RunResponseNonzero,
    RecoveredSettled,
    RecoveryDownloadFailed,
    MetaInvalid,
    OutputDownloadFailed,
    OutputLimitExceeded,
    CleanupUnverified,
    Cancelled,
    UnexpectedFailure,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Immutable typed evidence for one v3 foreground terminal actor settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalTerminalActorReceiptV1 {
    pub schema_version: String,
    pub phase: ExternalTerminalActorPhaseV1,
    pub origin: ExternalTerminalActorOriginV1,
    pub primary_subtype: ExternalTerminalActorSubtypeV1,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub recovery_subtype: Option<ExternalTerminalActorSubtypeV1>,
    pub execution_may_have_started: bool,
    pub effective_cutoff_monotonic_ns: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cleanup_verified: Option<bool>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub census_verified: Option<bool>,
    pub diagnostic_digest_sha256: String,
}

impl ExternalTerminalActorReceiptV1 {
    pub fn validate(&self) -> Result<(), ExternalToolProtocolError> {
        if self.schema_version != TERMINAL_ACTOR_RECEIPT_V1_SCHEMA
            || self.effective_cutoff_monotonic_ns == 0
            || !self.valid_primary_phase_origin()
            || !valid_recovery_subtype(self.recovery_subtype)
            || is_recovery_primary(self.primary_subtype) != self.recovery_subtype.is_some()
            || !self.execution_may_have_started
                && (self.cleanup_verified.is_some() || self.census_verified.is_some())
            || self.phase == ExternalTerminalActorPhaseV1::RecoveryDownload
                && self.recovery_subtype.is_none()
            || self.phase == ExternalTerminalActorPhaseV1::Cleanup
                && self.cleanup_verified == Some(true)
            || self.phase == ExternalTerminalActorPhaseV1::ActorDone
                && (!matches!(
                    self.primary_subtype,
                    ExternalTerminalActorSubtypeV1::ActorDeadlineExceeded
                        | ExternalTerminalActorSubtypeV1::Cancelled
                        | ExternalTerminalActorSubtypeV1::UnexpectedFailure
                ) || self.recovery_subtype.is_some())
        {
            return Err(ExternalToolProtocolError::InvalidActorReceipt);
        }
        validate_sha256(&self.diagnostic_digest_sha256)
            .map_err(|_| ExternalToolProtocolError::InvalidActorReceipt)?;
        let value = serde_json::json!({
            "schema_version": self.schema_version,
            "phase": self.phase,
            "origin": self.origin,
            "primary_subtype": self.primary_subtype,
            "recovery_subtype": self.recovery_subtype,
            "execution_may_have_started": self.execution_may_have_started,
            "effective_cutoff_monotonic_ns": self.effective_cutoff_monotonic_ns,
            "cleanup_verified": self.cleanup_verified,
            "census_verified": self.census_verified,
        });
        let encoded = serde_json::to_vec(&value)
            .map_err(|_| ExternalToolProtocolError::InvalidActorReceipt)?;
        let digest = format!("{:x}", Sha256::digest(encoded));
        if digest != self.diagnostic_digest_sha256 {
            return Err(ExternalToolProtocolError::InvalidActorReceipt);
        }
        Ok(())
    }

    fn valid_primary_phase_origin(&self) -> bool {
        use ExternalTerminalActorOriginV1::{Actor, Protocol, Semantic, Transport};
        use ExternalTerminalActorPhaseV1::{
            ActorDone, Census, Cleanup, CommandUpload, MappingPreflight, MetaValidate,
            RecoveryDownload, RemoteSetup, ResultDownload,
        };
        use ExternalTerminalActorSubtypeV1::{
            ActorDeadlineExceeded, Cancelled, CleanupUnverified, CommandUploadFailed, Completed,
            MetaInvalid, OutputDownloadFailed, OutputLimitExceeded, RecoveryDownloadFailed,
            RequestSetupFailed, RunResponseNonzero, RunTransportFailed, RunTransportTimeout,
            SemanticExecutionTimedOut, UnexpectedFailure, WorkspaceMappingChanged,
            WorkspaceMappingCheckTimeout,
        };
        match self.primary_subtype {
            Completed => self.phase == MetaValidate && self.origin == Actor,
            SemanticExecutionTimedOut => self.phase == MetaValidate && self.origin == Semantic,
            ActorDeadlineExceeded | UnexpectedFailure => self.origin == Actor,
            WorkspaceMappingCheckTimeout => {
                self.phase == MappingPreflight && self.origin == Transport
            }
            WorkspaceMappingChanged => self.phase == MappingPreflight && self.origin == Protocol,
            RequestSetupFailed => {
                matches!(self.phase, RemoteSetup | Cleanup)
                    && matches!(self.origin, Protocol | Transport)
            }
            CommandUploadFailed => {
                matches!(self.phase, CommandUpload | Cleanup) && self.origin == Transport
            }
            RunTransportTimeout | RunTransportFailed => {
                matches!(self.phase, RecoveryDownload | MetaValidate | Cleanup)
                    && self.origin == Transport
            }
            RunResponseNonzero => {
                matches!(self.phase, RecoveryDownload | MetaValidate | Cleanup)
                    && self.origin == Protocol
            }
            OutputDownloadFailed => {
                matches!(self.phase, ResultDownload | Cleanup) && self.origin == Transport
            }
            MetaInvalid | OutputLimitExceeded => {
                matches!(self.phase, MetaValidate | Cleanup) && self.origin == Protocol
            }
            CleanupUnverified => matches!(self.phase, Cleanup | Census) && self.origin == Actor,
            Cancelled => matches!(self.phase, Cleanup | ActorDone) && self.origin == Actor,
            ExternalTerminalActorSubtypeV1::RecoveredSettled | RecoveryDownloadFailed => false,
        }
    }
}

fn is_recovery_primary(value: ExternalTerminalActorSubtypeV1) -> bool {
    matches!(
        value,
        ExternalTerminalActorSubtypeV1::RunTransportTimeout
            | ExternalTerminalActorSubtypeV1::RunTransportFailed
            | ExternalTerminalActorSubtypeV1::RunResponseNonzero
    )
}

fn valid_recovery_subtype(value: Option<ExternalTerminalActorSubtypeV1>) -> bool {
    value.is_none_or(|subtype| {
        matches!(
            subtype,
            ExternalTerminalActorSubtypeV1::RecoveredSettled
                | ExternalTerminalActorSubtypeV1::RecoveryDownloadFailed
                | ExternalTerminalActorSubtypeV1::MetaInvalid
                | ExternalTerminalActorSubtypeV1::OutputDownloadFailed
                | ExternalTerminalActorSubtypeV1::OutputLimitExceeded
                | ExternalTerminalActorSubtypeV1::CleanupUnverified
                | ExternalTerminalActorSubtypeV1::ActorDeadlineExceeded
        )
    })
}

/// A v3 completed result. The required wait fields distinguish a semantic
/// actor wait clamp from a transport or process timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolCompletedResultV3 {
    pub return_code: i32,
    pub timed_out: bool,
    pub stdout_base64: String,
    pub stderr_base64: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub process_disposition: ExternalProcessDisposition,
    pub target_task_id: Option<String>,
    pub cleanup: ExternalCleanupEvidence,
    pub census: ExternalProcessCensus,
    pub media: Option<Box<ExternalMediaPayload>>,
    pub wait_clamped: bool,
    pub wait_reason: ExternalToolWaitReason,
    pub background_start_observation: Option<ExternalBackgroundStartObservation>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub actor_receipt: Option<ExternalTerminalActorReceiptV1>,
}

/// A v3 fatal settlement with a required nullable terminal-actor receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolFailureV3 {
    pub code: String,
    pub execution_may_have_started: bool,
    pub cleanup_verified: Option<bool>,
    pub census_verified: Option<bool>,
    pub recoverability: ExternalToolRecoverability,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub actor_receipt: Option<ExternalTerminalActorReceiptV1>,
}

/// The only response document accepted by a live v3 executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "settlement", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalToolSettlementV3 {
    Completed {
        schema_version: String,
        message_type: ExternalToolMessageType,
        seq: u64,
        run_id: String,
        trial_id: String,
        attempt_id: String,
        call_id: String,
        tool_name: String,
        request_sha256: String,
        result: ExternalToolCompletedResultV3,
    },
    Fatal {
        schema_version: String,
        message_type: ExternalToolMessageType,
        seq: u64,
        run_id: String,
        trial_id: String,
        attempt_id: String,
        call_id: String,
        tool_name: String,
        request_sha256: String,
        failure: ExternalToolFailureV3,
    },
}

impl ExternalToolSettlementV3 {
    pub fn validate(&self) -> Result<(), ExternalToolProtocolError> {
        let (
            schema_version,
            message_type,
            run_id,
            trial_id,
            attempt_id,
            call_id,
            tool_name,
            request_sha256,
        ) = match self {
            Self::Completed {
                schema_version,
                message_type,
                run_id,
                trial_id,
                attempt_id,
                call_id,
                tool_name,
                request_sha256,
                result,
                ..
            } => {
                if result.wait_clamped != result.wait_reason.is_runtime_budget() {
                    return Err(ExternalToolProtocolError::InvalidWaitMetadata);
                }
                if let Some(receipt) = &result.actor_receipt {
                    receipt.validate()?;
                    if receipt.recovery_subtype.is_some()
                        && (receipt.recovery_subtype
                            != Some(ExternalTerminalActorSubtypeV1::RecoveredSettled)
                            || receipt.phase != ExternalTerminalActorPhaseV1::MetaValidate
                            || !receipt.execution_may_have_started
                            || receipt.cleanup_verified != Some(true)
                            || receipt.census_verified != Some(true))
                    {
                        return Err(ExternalToolProtocolError::InvalidActorReceipt);
                    }
                }
                if result
                    .background_start_observation
                    .as_ref()
                    .is_some_and(|observation| {
                        observation.proof_version != EXTERNAL_BACKGROUND_START_PROOF_VERSION
                    })
                {
                    return Err(ExternalToolProtocolError::InvalidSettlement);
                }
                if let Some(media) = &result.media {
                    validate_sha256(&media.source_sha256)?;
                    validate_sha256(&media.canonical_sha256)?;
                    if !valid_logical_path(&media.logical_path)
                        || media.source_byte_length == 0
                        || media.source_byte_length > READ_FILE_MEDIA_MAX_BYTES
                        || media.canonical_byte_length == 0
                        || media.canonical_byte_length > READ_FILE_MEDIA_MAX_BYTES
                        || media.width == 0
                        || media.width > READ_FILE_MEDIA_MAX_DIMENSION
                        || media.height == 0
                        || media.height > READ_FILE_MEDIA_MAX_DIMENSION
                        || media
                            .width
                            .checked_mul(media.height)
                            .is_none_or(|pixels| pixels > READ_FILE_MEDIA_MAX_PIXELS)
                        || !valid_base64_shape(&media.content_base64, media.canonical_byte_length)
                    {
                        return Err(ExternalToolProtocolError::InvalidMedia);
                    }
                }
                (
                    schema_version,
                    message_type,
                    run_id,
                    trial_id,
                    attempt_id,
                    call_id,
                    tool_name,
                    request_sha256,
                )
            }
            Self::Fatal {
                schema_version,
                message_type,
                run_id,
                trial_id,
                attempt_id,
                call_id,
                tool_name,
                request_sha256,
                failure,
                ..
            } => {
                validate_code(&failure.code)?;
                if let Some(receipt) = &failure.actor_receipt {
                    receipt.validate()?;
                    if receipt.recovery_subtype
                        == Some(ExternalTerminalActorSubtypeV1::RecoveredSettled)
                        || matches!(
                            receipt.primary_subtype,
                            ExternalTerminalActorSubtypeV1::Completed
                                | ExternalTerminalActorSubtypeV1::SemanticExecutionTimedOut
                        )
                    {
                        return Err(ExternalToolProtocolError::InvalidActorReceipt);
                    }
                }
                (
                    schema_version,
                    message_type,
                    run_id,
                    trial_id,
                    attempt_id,
                    call_id,
                    tool_name,
                    request_sha256,
                )
            }
        };
        if schema_version != EXTERNAL_TOOL_STDIO_V3_SCHEMA
            || *message_type != ExternalToolMessageType::Response
        {
            return Err(ExternalToolProtocolError::InvalidSettlement);
        }
        for identity in [run_id, trial_id, attempt_id, call_id, tool_name] {
            validate_identity(identity)?;
        }
        validate_sha256(request_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolFailure {
    pub code: String,
    pub execution_may_have_started: bool,
    pub cleanup_verified: Option<bool>,
    pub census_verified: Option<bool>,
    pub recoverability: ExternalToolRecoverability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalToolRecoverability {
    Fatal,
}

/// Media bytes stay structured on the protocol and must not be rendered into
/// model-visible text by the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMediaPayload {
    pub logical_path: String,
    pub mime_type: ExternalMediaType,
    pub width: u64,
    pub height: u64,
    pub source_byte_length: u64,
    pub source_sha256: String,
    pub canonical_byte_length: u64,
    pub canonical_sha256: String,
    pub content_base64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalMediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
}

/// New tagged settlements plus the original flat completed-response reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExternalToolResponseDocument {
    Settled(ExternalToolSettlement),
    LegacyCompleted(ExternalToolResponse),
}

impl ExternalToolSettlement {
    pub fn validate(&self) -> Result<(), ExternalToolProtocolError> {
        let (
            schema_version,
            message_type,
            run_id,
            trial_id,
            attempt_id,
            call_id,
            tool_name,
            request_sha256,
        ) = match self {
            Self::Completed {
                schema_version,
                message_type,
                run_id,
                trial_id,
                attempt_id,
                call_id,
                tool_name,
                request_sha256,
                result,
                ..
            } => {
                if let Some(media) = &result.media {
                    validate_sha256(&media.source_sha256)?;
                    validate_sha256(&media.canonical_sha256)?;
                    if !valid_logical_path(&media.logical_path)
                        || media.source_byte_length == 0
                        || media.source_byte_length > READ_FILE_MEDIA_MAX_BYTES
                        || media.canonical_byte_length == 0
                        || media.canonical_byte_length > READ_FILE_MEDIA_MAX_BYTES
                        || media.width == 0
                        || media.width > READ_FILE_MEDIA_MAX_DIMENSION
                        || media.height == 0
                        || media.height > READ_FILE_MEDIA_MAX_DIMENSION
                        || media
                            .width
                            .checked_mul(media.height)
                            .is_none_or(|pixels| pixels > READ_FILE_MEDIA_MAX_PIXELS)
                        || !valid_base64_shape(&media.content_base64, media.canonical_byte_length)
                    {
                        return Err(ExternalToolProtocolError::InvalidMedia);
                    }
                }
                (
                    schema_version,
                    message_type,
                    run_id,
                    trial_id,
                    attempt_id,
                    call_id,
                    tool_name,
                    request_sha256,
                )
            }
            Self::Fatal {
                schema_version,
                message_type,
                run_id,
                trial_id,
                attempt_id,
                call_id,
                tool_name,
                request_sha256,
                failure,
                ..
            } => {
                validate_code(&failure.code)?;
                (
                    schema_version,
                    message_type,
                    run_id,
                    trial_id,
                    attempt_id,
                    call_id,
                    tool_name,
                    request_sha256,
                )
            }
        };
        if schema_version != EXTERNAL_TOOL_STDIO_SCHEMA
            || *message_type != ExternalToolMessageType::Response
        {
            return Err(ExternalToolProtocolError::InvalidSettlement);
        }
        for identity in [run_id, trial_id, attempt_id, call_id, tool_name] {
            validate_identity(identity)?;
        }
        validate_sha256(request_sha256)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalToolProtocolError {
    NonUtf8LogicalCwd,
    SerializationFailed,
    InvalidSettlement,
    InvalidIdentity,
    InvalidCode,
    InvalidSha256,
    InvalidMedia,
    InvalidDeadline,
    InvalidWaitMetadata,
    InvalidActorReceipt,
}

impl Display for ExternalToolProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8LogicalCwd => formatter.write_str("logical cwd is not UTF-8"),
            Self::SerializationFailed => formatter.write_str("protocol serialization failed"),
            Self::InvalidSettlement => formatter.write_str("invalid tool settlement"),
            Self::InvalidIdentity => formatter.write_str("invalid protocol identity"),
            Self::InvalidCode => formatter.write_str("invalid protocol failure code"),
            Self::InvalidSha256 => formatter.write_str("invalid protocol SHA-256"),
            Self::InvalidMedia => formatter.write_str("invalid protocol media payload"),
            Self::InvalidDeadline => formatter.write_str("invalid protocol deadline"),
            Self::InvalidWaitMetadata => formatter.write_str("invalid wait metadata"),
            Self::InvalidActorReceipt => formatter.write_str("invalid terminal actor receipt"),
        }
    }
}

impl Error for ExternalToolProtocolError {}

fn validate_identity(value: &str) -> Result<(), ExternalToolProtocolError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(ExternalToolProtocolError::InvalidIdentity);
    }
    Ok(())
}

fn validate_code(value: &str) -> Result<(), ExternalToolProtocolError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
    {
        return Err(ExternalToolProtocolError::InvalidCode);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ExternalToolProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ExternalToolProtocolError::InvalidSha256);
    }
    Ok(())
}

fn valid_logical_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn valid_base64_shape(value: &str, decoded_length: u64) -> bool {
    let Some(expected_length) = decoded_length
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|length| length.checked_mul(4))
        .and_then(|length| usize::try_from(length).ok())
    else {
        return false;
    };
    if value.len() != expected_length || value.is_empty() {
        return false;
    }
    let padding = match decoded_length % 3 {
        0 => 0,
        1 => 2,
        2 => 1,
        _ => unreachable!(),
    };
    let split = value.len() - padding;
    value.as_bytes()[..split]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        && value.as_bytes()[split..].iter().all(|byte| *byte == b'=')
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::{
        EXTERNAL_TOOL_STDIO_SCHEMA, EXTERNAL_TOOL_STDIO_V3_SCHEMA, ExternalCleanupEvidence,
        ExternalEnvironmentPolicy, ExternalMediaPayload, ExternalMediaType, ExternalProcessCensus,
        ExternalProcessDisposition, ExternalToolCompletedResult, ExternalToolCompletedResultV3,
        ExternalToolFailure, ExternalToolLimits, ExternalToolMessageType,
        ExternalToolRecoverability, ExternalToolRequest, ExternalToolRequestV3,
        ExternalToolResponse, ExternalToolResponseDocument, ExternalToolSettlement,
        ExternalToolSettlementV3, ExternalToolWaitReason,
    };
    use crate::contract::TOOL_ORDER;

    #[test]
    fn message_type_and_environment_are_stable() {
        assert_eq!(
            serde_json::to_string(&ExternalToolMessageType::Request).expect("serialize"),
            "\"tool.request\""
        );
        assert_eq!(
            ExternalEnvironmentPolicy::minimal_remote().inherit_remote,
            ["HOME", "LANG", "LC_ALL", "PATH", "TERM", "TMPDIR", "USER"]
        );
    }

    #[test]
    fn process_dispositions_are_stable_wire_values() {
        for (value, expected) in [
            (ExternalProcessDisposition::NoProcess, "\"no_process\""),
            (
                ExternalProcessDisposition::ForegroundCleaned,
                "\"foreground_cleaned\"",
            ),
            (
                ExternalProcessDisposition::BackgroundRetained,
                "\"background_retained\"",
            ),
            (
                ExternalProcessDisposition::BackgroundTerminated,
                "\"background_terminated\"",
            ),
        ] {
            assert_eq!(serde_json::to_string(&value).expect("serialize"), expected);
        }
    }

    #[test]
    fn rust_envelopes_match_the_committed_v2_schema() {
        let request = ExternalToolRequest {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Request,
            seq: 0,
            run_id: "run-1".to_owned(),
            trial_id: "trial-1".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            call_id: "call-1".to_owned(),
            tool_name: TOOL_ORDER[0].to_owned(),
            arguments_json: "{}".to_owned(),
            logical_cwd: "/workspace".to_owned(),
            timeout_ms: 1,
            term_grace_ms: 1,
            kill_confirmation_timeout_ms: 1,
            stdout_cap_bytes: 1,
            stderr_cap_bytes: 1,
            environment: ExternalEnvironmentPolicy::minimal_remote(),
            limits: ExternalToolLimits {
                arguments_cap_bytes: 2,
                max_path_bytes: 1,
                max_read_or_write_bytes: 1,
                max_directory_entries: 1,
                max_grep_matches: 1,
                max_replacements: 1,
                max_background_processes: 1,
                process_spool_bytes_per_process: 1,
                process_spool_bytes_per_run: 1,
                background_output_wait_max_ms: 1,
                read_file_media_enabled: false,
            },
        };
        let response = ExternalToolResponse {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: request.seq,
            run_id: request.run_id.clone(),
            trial_id: request.trial_id.clone(),
            attempt_id: request.attempt_id.clone(),
            call_id: request.call_id.clone(),
            tool_name: request.tool_name.clone(),
            request_sha256: "0".repeat(64),
            return_code: 0,
            timed_out: false,
            stdout_base64: String::new(),
            stderr_base64: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            process_disposition: ExternalProcessDisposition::NoProcess,
            target_task_id: None,
            cleanup: ExternalCleanupEvidence {
                attempted: false,
                term_sent: false,
                kill_sent: false,
                verified: true,
            },
            census: ExternalProcessCensus {
                verified: true,
                owned_processes_alive: 0,
            },
        };
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/external-tool-stdio-v2.json"))
                .expect("parse committed schema");
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/external-tool-stdio-v2-rust.json"
        ))
        .expect("parse Rust envelope fixture");
        let request_value = serde_json::to_value(&request).expect("serialize request");
        let response_value = serde_json::to_value(&response).expect("serialize response");

        assert_eq!(request.schema_version, EXTERNAL_TOOL_STDIO_SCHEMA);
        assert_eq!(request_value, fixture["request"]);
        assert_eq!(response_value, fixture["response"]);
        assert_eq!(
            object_keys(&request_value),
            schema_required_keys(&schema, "request")
        );
        assert_eq!(
            object_keys(&response_value),
            schema_required_keys(&schema, "response")
        );
        let schema_tools = schema
            .pointer("/$defs/tool_name/enum")
            .and_then(Value::as_array)
            .expect("schema tool enum")
            .iter()
            .map(|value| value.as_str().expect("string tool name"))
            .collect::<Vec<_>>();
        assert_eq!(schema_tools, TOOL_ORDER);
    }

    #[test]
    fn tagged_fatal_and_media_settlements_are_strict_and_legacy_response_is_readable() {
        let fatal = ExternalToolSettlement::Fatal {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: 7,
            run_id: "run-1".to_owned(),
            trial_id: "trial-1".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            call_id: "call-1".to_owned(),
            tool_name: "read_file".to_owned(),
            request_sha256: "a".repeat(64),
            failure: ExternalToolFailure {
                code: "terminal_actor_cleanup_unverified".to_owned(),
                execution_may_have_started: true,
                cleanup_verified: Some(false),
                census_verified: None,
                recoverability: ExternalToolRecoverability::Fatal,
            },
        };
        fatal.validate().expect("valid fatal settlement");
        let value = serde_json::to_value(&fatal).expect("fatal value");
        assert_eq!(value["settlement"], "fatal");
        assert_eq!(value["failure"]["recoverability"], "fatal");
        assert!(serde_json::from_value::<ExternalToolResponseDocument>(value).is_ok());

        let completed = ExternalToolSettlement::Completed {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: 7,
            run_id: "run-1".to_owned(),
            trial_id: "trial-1".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            call_id: "call-1".to_owned(),
            tool_name: "read_file".to_owned(),
            request_sha256: "a".repeat(64),
            result: ExternalToolCompletedResult {
                return_code: 0,
                timed_out: false,
                stdout_base64: String::new(),
                stderr_base64: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                process_disposition: ExternalProcessDisposition::NoProcess,
                target_task_id: None,
                cleanup: ExternalCleanupEvidence {
                    attempted: false,
                    term_sent: false,
                    kill_sent: false,
                    verified: true,
                },
                census: ExternalProcessCensus {
                    verified: true,
                    owned_processes_alive: 0,
                },
                media: Some(Box::new(ExternalMediaPayload {
                    logical_path: "image.png".to_owned(),
                    mime_type: ExternalMediaType::Png,
                    width: 1,
                    height: 1,
                    source_byte_length: 1,
                    source_sha256: "b".repeat(64),
                    canonical_byte_length: 1,
                    canonical_sha256: "b".repeat(64),
                    content_base64: "AA==".to_owned(),
                })),
            },
        };
        completed.validate().expect("valid media settlement");
        for invalid_media in [
            ExternalMediaPayload {
                logical_path: "../image.png".to_owned(),
                ..match &completed {
                    ExternalToolSettlement::Completed { result, .. } => {
                        *result.media.clone().expect("media")
                    }
                    ExternalToolSettlement::Fatal { .. } => unreachable!(),
                }
            },
            ExternalMediaPayload {
                width: 8_193,
                ..match &completed {
                    ExternalToolSettlement::Completed { result, .. } => {
                        *result.media.clone().expect("media")
                    }
                    ExternalToolSettlement::Fatal { .. } => unreachable!(),
                }
            },
            ExternalMediaPayload {
                width: 5_001,
                height: 5_000,
                ..match &completed {
                    ExternalToolSettlement::Completed { result, .. } => {
                        *result.media.clone().expect("media")
                    }
                    ExternalToolSettlement::Fatal { .. } => unreachable!(),
                }
            },
            ExternalMediaPayload {
                canonical_byte_length: 2,
                ..match &completed {
                    ExternalToolSettlement::Completed { result, .. } => {
                        *result.media.clone().expect("media")
                    }
                    ExternalToolSettlement::Fatal { .. } => unreachable!(),
                }
            },
        ] {
            let mut invalid = completed.clone();
            match &mut invalid {
                ExternalToolSettlement::Completed { result, .. } => {
                    result.media = Some(Box::new(invalid_media));
                }
                ExternalToolSettlement::Fatal { .. } => unreachable!(),
            }
            assert!(invalid.validate().is_err());
        }
        assert_eq!(
            serde_json::to_value(completed).expect("completed value")["result"]["media"]["mime_type"],
            "image/png"
        );

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/external-tool-stdio-v2-rust.json"
        ))
        .expect("legacy fixture");
        let legacy: ExternalToolResponseDocument =
            serde_json::from_value(fixture["response"].clone()).expect("legacy flat response");
        assert!(matches!(
            legacy,
            ExternalToolResponseDocument::LegacyCompleted(_)
        ));
    }

    #[test]
    fn v3_request_matches_schema_and_rejects_missing_or_unknown_fields() {
        let request = v3_request();
        request.validate().expect("valid v3 request");
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/external-tool-stdio-v3.json"))
                .expect("parse committed v3 schema");
        let value = serde_json::to_value(&request).expect("request value");
        assert_eq!(request.schema_version, EXTERNAL_TOOL_STDIO_V3_SCHEMA);
        assert_eq!(
            object_keys(&value),
            schema_required_keys(&schema, "request")
        );
        assert_eq!(value["operation_timeout_ms"], 300_000);
        assert!(value.get("timeout_ms").is_none());

        let mut missing = value.clone();
        missing
            .as_object_mut()
            .expect("request object")
            .remove("actor_done_monotonic_ns");
        assert!(serde_json::from_value::<ExternalToolRequestV3>(missing).is_err());

        let mut unknown = value;
        unknown["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<ExternalToolRequestV3>(unknown).is_err());
    }

    #[test]
    fn v3_completed_wait_metadata_is_required_correlated_and_no_v2_downgrade_exists() {
        let request = v3_request();
        let settlement = ExternalToolSettlementV3::Completed {
            schema_version: EXTERNAL_TOOL_STDIO_V3_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: request.seq,
            run_id: request.run_id.clone(),
            trial_id: request.trial_id.clone(),
            attempt_id: request.attempt_id.clone(),
            call_id: request.call_id.clone(),
            tool_name: request.tool_name.clone(),
            request_sha256: request.sha256().expect("request hash"),
            result: ExternalToolCompletedResultV3 {
                return_code: 0,
                timed_out: false,
                stdout_base64: String::new(),
                stderr_base64: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                process_disposition: ExternalProcessDisposition::ForegroundCleaned,
                target_task_id: None,
                cleanup: ExternalCleanupEvidence {
                    attempted: true,
                    term_sent: false,
                    kill_sent: false,
                    verified: true,
                },
                census: ExternalProcessCensus {
                    verified: true,
                    owned_processes_alive: 0,
                },
                media: None,
                wait_clamped: true,
                wait_reason: ExternalToolWaitReason::runtime_budget(),
                background_start_observation: None,
                actor_receipt: None,
            },
        };
        settlement.validate().expect("valid v3 settlement");
        let mut value = serde_json::to_value(&settlement).expect("settlement value");
        assert_eq!(value["result"]["wait_reason"], "runtime_budget");

        let mut missing = value.clone();
        missing["result"]
            .as_object_mut()
            .expect("result object")
            .remove("wait_reason");
        assert!(serde_json::from_value::<ExternalToolSettlementV3>(missing).is_err());

        value["result"]["unknown"] = Value::Bool(true);
        assert!(serde_json::from_value::<ExternalToolSettlementV3>(value).is_err());

        let mut inconsistent = settlement.clone();
        let ExternalToolSettlementV3::Completed { result, .. } = &mut inconsistent else {
            unreachable!("completed")
        };
        result.wait_clamped = false;
        assert!(inconsistent.validate().is_err());

        let legacy = ExternalToolSettlement::Fatal {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: request.seq,
            run_id: request.run_id,
            trial_id: request.trial_id,
            attempt_id: request.attempt_id,
            call_id: request.call_id,
            tool_name: request.tool_name,
            request_sha256: "a".repeat(64),
            failure: ExternalToolFailure {
                code: "legacy_only".to_owned(),
                execution_may_have_started: false,
                cleanup_verified: None,
                census_verified: None,
                recoverability: ExternalToolRecoverability::Fatal,
            },
        };
        assert!(
            serde_json::from_value::<ExternalToolSettlementV3>(
                serde_json::to_value(legacy).expect("legacy value")
            )
            .is_err(),
            "v3 must require its nullable actor receipt field"
        );
    }

    fn v3_request() -> ExternalToolRequestV3 {
        ExternalToolRequestV3 {
            schema_version: EXTERNAL_TOOL_STDIO_V3_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Request,
            seq: 3,
            run_id: "run-1".to_owned(),
            trial_id: "trial-1".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            call_id: "call-1".to_owned(),
            tool_name: "get_terminal_command_output".to_owned(),
            arguments_json: concat!(
                "{\"task_ids\":[\"018f22d6-9f04-7cc0-8000-000000000001\"],",
                "\"timeout_ms\":300000}"
            )
            .to_owned(),
            logical_cwd: "/workspace".to_owned(),
            operation_timeout_ms: 300_000,
            term_grace_ms: 5_000,
            kill_confirmation_timeout_ms: 5_000,
            stdout_cap_bytes: 1,
            stderr_cap_bytes: 1,
            environment: ExternalEnvironmentPolicy::minimal_remote(),
            limits: ExternalToolLimits {
                arguments_cap_bytes: 2,
                max_path_bytes: 1,
                max_read_or_write_bytes: 1,
                max_directory_entries: 1,
                max_grep_matches: 1,
                max_replacements: 1,
                max_background_processes: 1,
                process_spool_bytes_per_process: 1,
                process_spool_bytes_per_run: 1,
                background_output_wait_max_ms: 600_000,
                read_file_media_enabled: false,
            },
            actor_done_monotonic_ns: 1_000_000_000,
            tool_settled_monotonic_ns: 1_010_000_000,
            last_send_monotonic_ns: 1_040_000_000,
            runtime_final_monotonic_ns: 1_040_000_000,
            cleanup_start_monotonic_ns: 1_055_000_000,
            hard_deadline_monotonic_ns: 1_075_000_000,
            cleanup_reserve_ms: 20,
            terminalization_reserve_ms: 15,
            provider_send_reserve_ms: 30,
            process_settlement_reserve_ms: 10,
            deadline_receipt_sha256: "d".repeat(64),
        }
    }

    fn object_keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("serialized envelope object")
            .keys()
            .cloned()
            .collect()
    }

    fn schema_required_keys(schema: &Value, definition: &str) -> BTreeSet<String> {
        schema["$defs"][definition]["required"]
            .as_array()
            .expect("required keys")
            .iter()
            .map(|value| value.as_str().expect("required key").to_owned())
            .collect()
    }
}
