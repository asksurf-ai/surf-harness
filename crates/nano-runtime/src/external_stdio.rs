//! Fail-closed JSONL bridge to a remote logical terminal executor.

use std::path::Path;
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nano_provider_xai::{FunctionCall, MediaType};
use nano_types::contract::AgentProfile;
use nano_types::event::ToolOutcome;
use nano_types::external_tool::{
    EXTERNAL_BACKGROUND_START_PROOF_VERSION, EXTERNAL_TOOL_STDIO_SCHEMA,
    EXTERNAL_TOOL_STDIO_V3_SCHEMA, ExternalBackgroundStartKind, ExternalBackgroundStartObservation,
    ExternalEffectObservationStatusV1, ExternalEffectObservationV1, ExternalMediaPayload,
    ExternalMediaType, ExternalProcessDisposition, ExternalTerminalActorOriginV1,
    ExternalTerminalActorReceiptV1, ExternalTerminalActorSubtypeV1, ExternalToolDeadlineFields,
    ExternalToolMessageType, ExternalToolProtocolError, ExternalToolRequest, ExternalToolRequestV3,
    ExternalToolResponse, ExternalToolResponseDocument, ExternalToolSettlement,
    ExternalToolSettlementV3, READ_FILE_MEDIA_MAX_BYTES,
};
use nano_types::run_spec::RunSpec;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::io::{Interest, ReadBuf, unix::AsyncFd};

use crate::deadline::DeadlineContext;
use crate::foreground::{
    FROZEN_RESULT_MAX_BYTES, ForegroundOperation, truncate_utf8, validate_foreground_call,
};
use crate::terminal::render_external_result;
use crate::tool::{
    CommandVerdictV1, EffectObservationV1, ExecutionEvidenceV1, ToolExecutionError,
    ToolExecutionFailureClass, ToolExecutor, ToolMedia, ToolResult, ToolRuntimeBudget,
    WorkspaceMode,
};
use sha2::{Digest, Sha256};

const PROTOCOL_OVERHEAD_BYTES: u64 = 32 * 1024;
const SETTLEMENT_STAGE_COUNT: u64 = 6;
const MIN_SETTLEMENT_STAGE_MS: u64 = 1;

/// The v1, non-borrowable subdivision of the one wire settlement reserve.
///
/// Cutoffs are `actor_done + floor(S * i / 6)` for probe, output, encode,
/// drain, parse, and history commit. The final cutoff is exactly
/// `tool_settled`; equality at every cutoff is expired.
#[derive(Debug, Clone, Copy)]
pub struct SettlementStageCutoffsV1<T> {
    cutoffs: [T; SETTLEMENT_STAGE_COUNT as usize],
}

impl SettlementStageCutoffsV1<u64> {
    pub fn derive_raw(
        actor_done: u64,
        tool_settled: u64,
        process_settlement_reserve_ms: u64,
    ) -> Result<Self, ToolExecutionError> {
        let span = tool_settled
            .checked_sub(actor_done)
            .ok_or_else(settlement_budget_invalid)?;
        let expected = process_settlement_reserve_ms
            .checked_mul(1_000_000)
            .ok_or_else(settlement_budget_invalid)?;
        if process_settlement_reserve_ms
            < SETTLEMENT_STAGE_COUNT.saturating_mul(MIN_SETTLEMENT_STAGE_MS)
            || span != expected
        {
            return Err(settlement_budget_invalid());
        }
        let quotient = span / SETTLEMENT_STAGE_COUNT;
        let remainder = span % SETTLEMENT_STAGE_COUNT;
        let cutoffs = std::array::from_fn(|index| {
            let stage = u64::try_from(index + 1).unwrap_or(SETTLEMENT_STAGE_COUNT);
            actor_done
                .saturating_add(quotient.saturating_mul(stage))
                .saturating_add(remainder.saturating_mul(stage) / SETTLEMENT_STAGE_COUNT)
        });
        if cutoffs.windows(2).any(|pair| pair[0] >= pair[1]) || cutoffs[5] != tool_settled {
            return Err(settlement_budget_invalid());
        }
        Ok(Self { cutoffs })
    }

    pub fn raw_cutoffs(self) -> [u64; SETTLEMENT_STAGE_COUNT as usize] {
        self.cutoffs
    }
}

impl SettlementStageCutoffsV1<Instant> {
    pub fn derive_instants(
        actor_done: Instant,
        tool_settled: Instant,
        process_settlement_reserve_ms: u64,
    ) -> Result<Self, ToolExecutionError> {
        let span = tool_settled
            .checked_duration_since(actor_done)
            .ok_or_else(settlement_budget_invalid)?;
        let span_ns = u64::try_from(span.as_nanos()).map_err(|_| settlement_budget_invalid())?;
        let raw = SettlementStageCutoffsV1::derive_raw(
            1,
            1_u64
                .checked_add(span_ns)
                .ok_or_else(settlement_budget_invalid)?,
            process_settlement_reserve_ms,
        )?
        .raw_cutoffs();
        let cutoffs = std::array::from_fn(|index| {
            actor_done
                .checked_add(Duration::from_nanos(raw[index].saturating_sub(1)))
                .unwrap_or(tool_settled)
        });
        if cutoffs[5] != tool_settled {
            return Err(settlement_budget_invalid());
        }
        Ok(Self { cutoffs })
    }

    pub fn instant_cutoffs(self) -> [Instant; SETTLEMENT_STAGE_COUNT as usize] {
        self.cutoffs
    }

    pub fn strictly_before(now: Instant, cutoff: Instant) -> bool {
        now < cutoff
    }

    fn drain(self) -> Instant {
        self.cutoffs[3]
    }

    fn encode(self) -> Instant {
        self.cutoffs[2]
    }

    fn parse(self) -> Instant {
        self.cutoffs[4]
    }

    pub(crate) fn history_commit(self) -> Instant {
        self.cutoffs[5]
    }
}

fn settlement_budget_invalid() -> ToolExecutionError {
    ToolExecutionError::deadline("external_stdio_settlement_budget_invalid")
}

/// Wire cutoffs plus local `Instant` anchors derived from the same bound root.
/// The raw nanoseconds are forwarded unchanged; the local instants only bound
/// this process's async operations and must not be reconstructed from a full
/// relative timeout.
#[derive(Debug, Clone)]
pub struct ExternalStdioDeadlineEnvelope {
    wire: ExternalToolDeadlineFields,
    actor_done: Instant,
    tool_settled: Instant,
}

impl ExternalStdioDeadlineEnvelope {
    pub fn from_context(context: &DeadlineContext) -> Result<Self, ToolExecutionError> {
        let cutoffs = context.cutoffs;
        let reserves = context.reserves;
        Self::new(
            ExternalToolDeadlineFields {
                actor_done_monotonic_ns: cutoffs.actor_done_monotonic_ns,
                tool_settled_monotonic_ns: cutoffs.tool_settled_monotonic_ns,
                last_send_monotonic_ns: cutoffs.last_send_monotonic_ns,
                runtime_final_monotonic_ns: cutoffs.runtime_final_monotonic_ns,
                cleanup_start_monotonic_ns: cutoffs.cleanup_start_monotonic_ns,
                hard_deadline_monotonic_ns: cutoffs.hard_deadline_monotonic_ns,
                cleanup_reserve_ms: reserves.cleanup_ms,
                terminalization_reserve_ms: reserves.terminalization_ms,
                provider_send_reserve_ms: reserves.provider_send_ms,
                process_settlement_reserve_ms: reserves.process_settlement_ms,
                deadline_receipt_sha256: context.receipt_sha256.clone(),
            },
            context.instants.actor_done,
            context.instants.tool_settled,
        )
    }

    pub fn new(
        wire: ExternalToolDeadlineFields,
        actor_done: Instant,
        tool_settled: Instant,
    ) -> Result<Self, ToolExecutionError> {
        wire.validate()
            .map_err(|_| incomplete("external_stdio_deadline_invalid"))?;
        if actor_done >= tool_settled {
            return Err(incomplete("external_stdio_deadline_invalid"));
        }
        SettlementStageCutoffsV1::derive_raw(
            wire.actor_done_monotonic_ns,
            wire.tool_settled_monotonic_ns,
            wire.process_settlement_reserve_ms,
        )?;
        SettlementStageCutoffsV1::derive_instants(
            actor_done,
            tool_settled,
            wire.process_settlement_reserve_ms,
        )?;
        Ok(Self {
            wire,
            actor_done,
            tool_settled,
        })
    }

    pub fn wire(&self) -> &ExternalToolDeadlineFields {
        &self.wire
    }

    pub fn actor_done(&self) -> Instant {
        self.actor_done
    }

    pub fn tool_settled(&self) -> Instant {
        self.tool_settled
    }

    pub fn settlement_stages(
        &self,
    ) -> Result<SettlementStageCutoffsV1<Instant>, ToolExecutionError> {
        SettlementStageCutoffsV1::derive_instants(
            self.actor_done,
            self.tool_settled,
            self.wire.process_settlement_reserve_ms,
        )
    }
}

#[derive(Debug, Clone)]
enum ExternalStdioProtocol {
    LegacyV2,
    LiveV3(ExternalStdioDeadlineEnvelope),
}

pub struct ExternalStdioExecutor<R, W> {
    reader: BufReader<R>,
    writer: W,
    spec: RunSpec,
    profile: AgentProfile,
    next_seq: u64,
    response_line_limit: usize,
    background_enabled: bool,
    protocol: ExternalStdioProtocol,
}

impl<R, W> ExternalStdioExecutor<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn from_io(
        reader: R,
        writer: W,
        spec: &RunSpec,
        profile: &AgentProfile,
    ) -> Result<Self, ToolExecutionError> {
        Self::from_io_with_protocol(
            reader,
            writer,
            spec,
            profile,
            ExternalStdioProtocol::LegacyV2,
        )
    }

    /// Construct the live v3 bridge. This path accepts v3 responses only and
    /// never falls back to the legacy v2 response reader.
    pub fn from_io_v3(
        reader: R,
        writer: W,
        spec: &RunSpec,
        profile: &AgentProfile,
        deadline: ExternalStdioDeadlineEnvelope,
    ) -> Result<Self, ToolExecutionError> {
        Self::from_io_with_protocol(
            reader,
            writer,
            spec,
            profile,
            ExternalStdioProtocol::LiveV3(deadline),
        )
    }

    fn from_io_with_protocol(
        reader: R,
        writer: W,
        spec: &RunSpec,
        profile: &AgentProfile,
        protocol: ExternalStdioProtocol,
    ) -> Result<Self, ToolExecutionError> {
        let per_stream = profile.process.process_spool_bytes_per_process.div_ceil(2);
        let encoded_stream = base64_encoded_len(per_stream)
            .ok_or_else(|| incomplete("external_stdio_limit_overflow"))?;
        let encoded_media = if profile.tools.read_file_media_enabled {
            base64_encoded_len(READ_FILE_MEDIA_MAX_BYTES)
                .ok_or_else(|| incomplete("external_stdio_limit_overflow"))?
        } else {
            0
        };
        let response_line_limit = encoded_stream
            .checked_mul(2)
            .and_then(|value| value.checked_add(encoded_media))
            .and_then(|value| value.checked_add(PROTOCOL_OVERHEAD_BYTES))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| incomplete("external_stdio_limit_overflow"))?;
        spec.workspace_dir
            .to_str()
            .ok_or_else(|| incomplete("external_stdio_logical_cwd_not_utf8"))?;
        let selected = spec
            .selected_tool_names()
            .map_err(|_| incomplete("external_stdio_active_tools_invalid"))?;
        let background_enabled = ["kill_terminal_command", "get_terminal_command_output"]
            .iter()
            .all(|name| selected.contains(name));
        Ok(Self {
            reader: BufReader::new(reader),
            writer,
            spec: spec.clone(),
            profile: profile.clone(),
            next_seq: 0,
            response_line_limit,
            background_enabled,
            protocol,
        })
    }

    async fn execute_foreground(
        &mut self,
        call: &FunctionCall,
        workspace: &Path,
        deadline: Instant,
    ) -> Result<ToolResult, ToolExecutionError> {
        if workspace != self.spec.workspace_dir {
            return Err(incomplete("external_stdio_workspace_mismatch"));
        }
        if let ExternalStdioProtocol::LiveV3(envelope) = self.protocol.clone() {
            return self.execute_foreground_v3(call, envelope).await;
        }
        let operation =
            validate_foreground_call(call, &self.profile.tools, self.background_enabled)
                .map_err(|_| incomplete("external_stdio_validated_call_changed"))?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| incomplete("external_stdio_response_timeout"))?;
        let requested_timeout = match operation {
            ForegroundOperation::Terminal {
                requested_timeout_ms,
                background: false,
            } => {
                let command_window = remaining.saturating_sub(Duration::from_secs(
                    self.profile.deadlines.terminalization_reserve_sec,
                ));
                Duration::from_millis(
                    requested_timeout_ms.unwrap_or(self.profile.tools.terminal_default_timeout_ms),
                )
                .min(Duration::from_millis(
                    self.profile.tools.terminal_max_timeout_ms.min(300_000),
                ))
                .min(command_window)
            }
            ForegroundOperation::Terminal {
                background: true, ..
            } => remaining.min(Duration::from_secs(
                self.profile.deadlines.process_control_timeout_sec,
            )),
            ForegroundOperation::Filesystem => remaining.min(Duration::from_secs(
                self.profile.deadlines.filesystem_operation_timeout_sec,
            )),
            ForegroundOperation::Search => remaining.min(Duration::from_secs(
                self.profile.deadlines.search_operation_timeout_sec,
            )),
            ForegroundOperation::BackgroundOutput { wait_timeout_ms } => {
                let wait = Duration::from_millis(wait_timeout_ms);
                remaining.min(wait.saturating_add(Duration::from_secs(
                    self.profile.deadlines.process_control_timeout_sec,
                )))
            }
            ForegroundOperation::BackgroundKill => remaining.min(
                Duration::from_millis(self.profile.process.term_grace_ms)
                    .saturating_add(Duration::from_millis(
                        self.profile.process.kill_confirmation_timeout_ms,
                    ))
                    .saturating_add(Duration::from_secs(
                        self.profile.deadlines.process_control_timeout_sec,
                    )),
            ),
        };
        if requested_timeout.is_zero() {
            return Ok(attempted_rejection("tool_deadline_exceeded"));
        }
        let timeout_ms = u64::try_from(requested_timeout.as_millis())
            .map_err(|_| incomplete("external_stdio_timeout_overflow"))?;
        if timeout_ms == 0 {
            return Ok(attempted_rejection("terminal_deadline_exceeded"));
        }
        let seq = self.next_seq;
        let request = ExternalToolRequest::for_call(
            seq,
            &self.spec,
            &self.profile,
            call.call_id.clone(),
            call.name.clone(),
            call.arguments_json.clone(),
            timeout_ms,
        )
        .map_err(|_| incomplete("external_stdio_request_invalid"))?;
        let request_sha256 = request
            .sha256()
            .map_err(|_| incomplete("external_stdio_request_serialize_failed"))?;
        let mut line = serde_json::to_vec(&request)
            .map_err(|_| incomplete("external_stdio_request_serialize_failed"))?;
        line.push(b'\n');
        let request_limit = self
            .profile
            .transport
            .max_function_arguments_bytes
            .checked_mul(6)
            .and_then(|value| value.checked_add(PROTOCOL_OVERHEAD_BYTES))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| incomplete("external_stdio_limit_overflow"))?;
        if line.len() > request_limit {
            return Err(incomplete("external_stdio_request_line_limit_exceeded"));
        }
        self.writer
            .write_all(&line)
            .await
            .map_err(|_| incomplete("external_stdio_request_write_failed"))?;
        self.writer
            .flush()
            .await
            .map_err(|_| incomplete("external_stdio_request_flush_failed"))?;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| incomplete("external_stdio_sequence_overflow"))?;

        let response_bytes = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            read_bounded_line(&mut self.reader, self.response_line_limit),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(code)) => return Err(incomplete(code)),
            Err(_) => return Err(incomplete("external_stdio_response_timeout")),
        };
        let response_document =
            serde_json::from_slice::<ExternalToolResponseDocument>(&response_bytes)
                .map_err(|_| incomplete("external_stdio_response_invalid"))?;
        let (response, media_payload) = match response_document {
            ExternalToolResponseDocument::LegacyCompleted(response) => (response, None),
            ExternalToolResponseDocument::Settled(settlement) => {
                settlement
                    .validate()
                    .map_err(|_| incomplete("external_stdio_response_invalid"))?;
                match settlement {
                    ExternalToolSettlement::Completed {
                        schema_version,
                        message_type,
                        seq,
                        run_id,
                        trial_id,
                        attempt_id,
                        call_id,
                        tool_name,
                        request_sha256: response_request_sha256,
                        result,
                    } => (
                        ExternalToolResponse {
                            schema_version,
                            message_type,
                            seq,
                            run_id,
                            trial_id,
                            attempt_id,
                            call_id,
                            tool_name,
                            request_sha256: response_request_sha256,
                            return_code: result.return_code,
                            timed_out: result.timed_out,
                            stdout_base64: result.stdout_base64,
                            stderr_base64: result.stderr_base64,
                            stdout_truncated: result.stdout_truncated,
                            stderr_truncated: result.stderr_truncated,
                            process_disposition: result.process_disposition,
                            target_task_id: result.target_task_id,
                            cleanup: result.cleanup,
                            census: result.census,
                        },
                        result.media,
                    ),
                    ExternalToolSettlement::Fatal {
                        schema_version,
                        message_type,
                        seq,
                        run_id,
                        trial_id,
                        attempt_id,
                        call_id,
                        tool_name,
                        request_sha256: response_request_sha256,
                        failure,
                    } => {
                        validate_response_identity(
                            &request,
                            &request_sha256,
                            &schema_version,
                            message_type,
                            seq,
                            &run_id,
                            &trial_id,
                            &attempt_id,
                            &call_id,
                            &tool_name,
                            &response_request_sha256,
                        )?;
                        let code = remote_fatal_code(&failure.code);
                        return Err(ToolExecutionError::fatal_classified(
                            code,
                            failure_class(code),
                            failure.execution_may_have_started,
                            failure.cleanup_verified,
                            failure.census_verified,
                        ));
                    }
                }
            }
        };
        validate_response(&request, &request_sha256, &response, operation)?;
        finish_response(
            ResponseProjectionMode::LegacyV2,
            &self.profile,
            call,
            response,
            media_payload.map(|payload| *payload),
            request.stdout_cap_bytes,
            request.stderr_cap_bytes,
            None,
            None,
        )
    }

    async fn execute_foreground_v3(
        &mut self,
        call: &FunctionCall,
        envelope: ExternalStdioDeadlineEnvelope,
    ) -> Result<ToolResult, ToolExecutionError> {
        let operation =
            validate_foreground_call(call, &self.profile.tools, self.background_enabled)
                .map_err(|_| incomplete("external_stdio_validated_call_changed"))?;
        if Instant::now() >= envelope.actor_done() {
            return Ok(ToolResult::rejected("deadline_before_dispatch"));
        }
        let semantic_timeout_ms = semantic_operation_timeout_ms(operation, &self.profile)?;
        let operation_timeout_ms = if matches!(
            operation,
            ForegroundOperation::Terminal {
                background: false,
                ..
            }
        ) {
            let remaining_action = envelope
                .actor_done()
                .saturating_duration_since(Instant::now());
            let Some(timeout_ms) =
                clamp_foreground_timeout_ms(semantic_timeout_ms, remaining_action)?
            else {
                return Ok(ToolResult::rejected("deadline_before_dispatch"));
            };
            timeout_ms
        } else {
            semantic_timeout_ms
        };
        let seq = self.next_seq;
        let request = ExternalToolRequestV3::for_call(
            seq,
            &self.spec,
            &self.profile,
            call.call_id.clone(),
            call.name.clone(),
            call.arguments_json.clone(),
            operation_timeout_ms,
            envelope.wire(),
        )
        .map_err(|_| incomplete("external_stdio_request_invalid"))?;
        let stages = envelope.settlement_stages()?;

        ensure_before(envelope.actor_done(), "deadline_before_dispatch")?;
        let request_sha256 = request
            .sha256()
            .map_err(|_| incomplete("external_stdio_request_serialize_failed"))?;
        let mut line = serde_json::to_vec(&request)
            .map_err(|_| incomplete("external_stdio_request_serialize_failed"))?;
        line.push(b'\n');
        ensure_before(envelope.actor_done(), "deadline_before_dispatch")?;
        let request_limit = self
            .profile
            .transport
            .max_function_arguments_bytes
            .checked_mul(6)
            .and_then(|value| value.checked_add(PROTOCOL_OVERHEAD_BYTES))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| incomplete("external_stdio_limit_overflow"))?;
        if line.len() > request_limit {
            return Err(incomplete("external_stdio_request_line_limit_exceeded"));
        }
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(envelope.actor_done()),
            self.writer.write_all(&line),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(incomplete("external_stdio_request_write_failed")),
            Err(_) => return Err(incomplete("tool_settlement_deadline_exceeded")),
        }
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(envelope.actor_done()),
            self.writer.flush(),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(incomplete("external_stdio_request_flush_failed")),
            Err(_) => return Err(incomplete("tool_settlement_deadline_exceeded")),
        }
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| incomplete("external_stdio_sequence_overflow"))?;

        let response_bytes = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(stages.drain()),
            read_bounded_line(&mut self.reader, self.response_line_limit),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err("external_stdio_response_eof")) if Instant::now() >= stages.encode() => {
                return Err(ToolExecutionError::deadline(
                    "response_serialization_deadline_exceeded",
                ));
            }
            Ok(Err(code)) => return Err(incomplete(code)),
            Err(_) => return Err(incomplete("tool_settlement_deadline_exceeded")),
        };
        ensure_before(stages.parse(), "tool_settlement_parse_deadline_exceeded")?;
        validate_v3_response_keyset(&response_bytes)
            .map_err(|_| incomplete("external_stdio_response_invalid"))?;
        let settlement = serde_json::from_slice::<ExternalToolSettlementV3>(&response_bytes)
            .map_err(|_| incomplete("external_stdio_response_invalid"))?;
        settlement.validate().map_err(|error| {
            incomplete(if error == ExternalToolProtocolError::InvalidActorReceipt {
                "external_stdio_actor_receipt_invalid"
            } else {
                "external_stdio_response_invalid"
            })
        })?;
        ensure_before(stages.parse(), "tool_settlement_parse_deadline_exceeded")?;

        let (response, media_payload, runtime_budget, background_start_observation, actor_evidence) =
            match settlement {
                ExternalToolSettlementV3::Completed {
                    schema_version,
                    message_type,
                    seq,
                    run_id,
                    trial_id,
                    attempt_id,
                    call_id,
                    tool_name,
                    request_sha256: response_request_sha256,
                    result,
                } => {
                    validate_response_identity_v3(
                        &request,
                        &request_sha256,
                        &schema_version,
                        message_type,
                        seq,
                        &run_id,
                        &trial_id,
                        &attempt_id,
                        &call_id,
                        &tool_name,
                        &response_request_sha256,
                    )?;
                    validate_completed_actor_receipt(&request, operation, &result)?;
                    let actor_receipt = result.actor_receipt.clone();
                    let runtime_budget = result
                        .wait_clamped
                        .then_some(ToolRuntimeBudget::wait_clamped());
                    (
                        ExternalToolResponse {
                            schema_version,
                            message_type,
                            seq,
                            run_id,
                            trial_id,
                            attempt_id,
                            call_id,
                            tool_name,
                            request_sha256: response_request_sha256,
                            return_code: result.return_code,
                            timed_out: result.timed_out,
                            stdout_base64: result.stdout_base64,
                            stderr_base64: result.stderr_base64,
                            stdout_truncated: result.stdout_truncated,
                            stderr_truncated: result.stderr_truncated,
                            process_disposition: result.process_disposition,
                            target_task_id: result.target_task_id,
                            cleanup: result.cleanup,
                            census: result.census,
                        },
                        result.media.map(|payload| *payload),
                        runtime_budget,
                        result.background_start_observation,
                        (actor_receipt, result.effect_observation_v1),
                    )
                }
                ExternalToolSettlementV3::Fatal {
                    schema_version,
                    message_type,
                    seq,
                    run_id,
                    trial_id,
                    attempt_id,
                    call_id,
                    tool_name,
                    request_sha256: response_request_sha256,
                    failure,
                } => {
                    validate_response_identity_v3(
                        &request,
                        &request_sha256,
                        &schema_version,
                        message_type,
                        seq,
                        &run_id,
                        &trial_id,
                        &attempt_id,
                        &call_id,
                        &tool_name,
                        &response_request_sha256,
                    )?;
                    validate_fatal_actor_receipt(&request, operation, &failure)?;
                    let code = remote_fatal_code(&failure.code);
                    let actor_receipt = failure.actor_receipt;
                    return Err(ToolExecutionError::fatal_classified(
                        code,
                        failure_class(code),
                        failure.execution_may_have_started,
                        failure.cleanup_verified,
                        failure.census_verified,
                    )
                    .with_actor_receipt(actor_receipt));
                }
            };
        let (actor_receipt, effect_observation) = actor_evidence;
        validate_response_process(
            &response,
            operation,
            background_start_observation.as_ref(),
            true,
        )
        .map_err(|error| error.with_actor_receipt(actor_receipt.clone()))?;
        ensure_before(stages.parse(), "tool_settlement_parse_deadline_exceeded")
            .map_err(|error| error.with_actor_receipt(actor_receipt.clone()))?;
        let result = finish_response(
            ResponseProjectionMode::LiveV3,
            &self.profile,
            call,
            response,
            media_payload,
            request.stdout_cap_bytes,
            request.stderr_cap_bytes,
            runtime_budget,
            effect_observation,
        )
        .map_err(|error| error.with_actor_receipt(actor_receipt.clone()))?
        .with_actor_receipt(actor_receipt);
        ensure_before(stages.parse(), "tool_settlement_parse_deadline_exceeded")
            .map_err(|error| error.with_actor_receipt(result.actor_receipt().cloned()))?;
        Ok(result)
    }
}

impl ExternalStdioExecutor<ProcessStdinReader, tokio::io::Stdout> {
    pub fn from_process_stdio(
        spec: &RunSpec,
        profile: &AgentProfile,
    ) -> Result<Self, ToolExecutionError> {
        let reader = ProcessStdinReader::open()
            .map_err(|_| incomplete("external_stdio_process_stdin_failed"))?;
        Self::from_io(reader, tokio::io::stdout(), spec, profile)
    }

    pub fn from_process_stdio_v3(
        spec: &RunSpec,
        profile: &AgentProfile,
        deadline: ExternalStdioDeadlineEnvelope,
    ) -> Result<Self, ToolExecutionError> {
        let reader = ProcessStdinReader::open()
            .map_err(|_| incomplete("external_stdio_process_stdin_failed"))?;
        Self::from_io_v3(reader, tokio::io::stdout(), spec, profile, deadline)
    }
}

/// Process stdin backed by a nonblocking Unix descriptor registered directly
/// with the Tokio reactor. Dropping a timed-out read therefore leaves no
/// blocking-pool task for runtime shutdown to wait on.
#[cfg(unix)]
pub struct ProcessStdinReader {
    inner: AsyncFd<std::io::Stdin>,
    original_flags: rustix::fs::OFlags,
}

#[cfg(unix)]
impl ProcessStdinReader {
    fn open() -> std::io::Result<Self> {
        let stdin = std::io::stdin();
        let original_flags = rustix::fs::fcntl_getfl(&stdin).map_err(std::io::Error::from)?;
        rustix::fs::fcntl_setfl(&stdin, original_flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(std::io::Error::from)?;
        let inner = match AsyncFd::try_with_interest(stdin, Interest::READABLE) {
            Ok(inner) => inner,
            Err(error) => {
                let (stdin, cause) = error.into_parts();
                let _ = rustix::fs::fcntl_setfl(&stdin, original_flags);
                return Err(cause);
            }
        };
        Ok(Self {
            inner,
            original_flags,
        })
    }
}

#[cfg(unix)]
impl AsyncRead for ProcessStdinReader {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut ready_guard = ready!(this.inner.poll_read_ready(context))?;
            match ready_guard.try_io(|inner| {
                let count = rustix::io::read(inner.get_ref(), buffer.initialize_unfilled())
                    .map_err(std::io::Error::from)?;
                buffer.advance(count);
                Ok(())
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessStdinReader {
    fn drop(&mut self) {
        let _ = rustix::fs::fcntl_setfl(self.inner.get_ref(), self.original_flags);
    }
}

#[cfg(not(unix))]
pub struct ProcessStdinReader;

#[cfg(not(unix))]
impl ProcessStdinReader {
    fn open() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "external stdio requires cancellable Unix stdin",
        ))
    }
}

#[cfg(not(unix))]
impl AsyncRead for ProcessStdinReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        _buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "external stdio requires cancellable Unix stdin",
        )))
    }
}

impl<R, W> ToolExecutor for ExternalStdioExecutor<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn workspace_mode(&self) -> WorkspaceMode {
        WorkspaceMode::RemoteLogical
    }

    fn validate(&self, call: &FunctionCall) -> Result<(), ToolResult> {
        validate_foreground_call(call, &self.profile.tools, self.background_enabled).map(|_| ())
    }

    async fn execute(
        &mut self,
        call: &FunctionCall,
        workspace: &Path,
        deadline: Instant,
    ) -> Result<ToolResult, ToolExecutionError> {
        self.execute_foreground(call, workspace, deadline).await
    }
}

fn semantic_operation_timeout_ms(
    operation: ForegroundOperation,
    profile: &AgentProfile,
) -> Result<u64, ToolExecutionError> {
    let timeout_ms = match operation {
        ForegroundOperation::Terminal {
            requested_timeout_ms,
            background: false,
        } => Some(
            requested_timeout_ms
                .unwrap_or(profile.tools.terminal_default_timeout_ms)
                .min(profile.tools.terminal_max_timeout_ms.min(300_000)),
        ),
        ForegroundOperation::Terminal {
            background: true, ..
        } => profile
            .deadlines
            .process_control_timeout_sec
            .checked_mul(1_000),
        ForegroundOperation::Filesystem => profile
            .deadlines
            .filesystem_operation_timeout_sec
            .checked_mul(1_000),
        ForegroundOperation::Search => profile
            .deadlines
            .search_operation_timeout_sec
            .checked_mul(1_000),
        ForegroundOperation::BackgroundOutput { wait_timeout_ms } => {
            if wait_timeout_ms == 0 {
                profile
                    .deadlines
                    .process_control_timeout_sec
                    .checked_mul(1_000)
            } else {
                Some(wait_timeout_ms)
            }
        }
        ForegroundOperation::BackgroundKill => profile
            .deadlines
            .process_control_timeout_sec
            .checked_mul(1_000)
            .and_then(|control| control.checked_add(profile.process.term_grace_ms))
            .and_then(|total| total.checked_add(profile.process.kill_confirmation_timeout_ms)),
    }
    .ok_or_else(|| incomplete("external_stdio_timeout_overflow"))?;
    if timeout_ms == 0 {
        return Err(incomplete("external_stdio_timeout_invalid"));
    }
    Ok(timeout_ms)
}

fn clamp_foreground_timeout_ms(
    semantic_timeout_ms: u64,
    remaining_action: Duration,
) -> Result<Option<u64>, ToolExecutionError> {
    let remaining_action_ms = u64::try_from(remaining_action.as_millis())
        .map_err(|_| incomplete("external_stdio_timeout_overflow"))?;
    Ok((remaining_action_ms > 0).then_some(semantic_timeout_ms.min(remaining_action_ms)))
}

fn ensure_before(deadline: Instant, code: &'static str) -> Result<(), ToolExecutionError> {
    if Instant::now() >= deadline {
        Err(ToolExecutionError::deadline(code))
    } else {
        Ok(())
    }
}

const FOREGROUND_OWNED_PROCESSES_TERMINATED_PREFIX: &str = concat!(
    "FG_CHILDREN_KILLED;START_INTENDED_BG;VERIFY_HANDLE\n",
    "<observation>foreground_owned_processes_terminated</observation>\n",
    "<status>execution_attempted=true outcome=rejected cleanup_verified=true ",
    "census_verified=true survivors=0</status>\n",
    "<next-step>If a long-lived process was intended, start only that process in a fresh managed ",
    "background call and verify the returned handle. Otherwise continue.</next-step>\n",
);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseProjectionMode {
    LegacyV2,
    LiveV3,
}

fn foreground_owned_processes_terminated(
    mode: ResponseProjectionMode,
    call: &FunctionCall,
    response: &ExternalToolResponse,
) -> bool {
    mode == ResponseProjectionMode::LiveV3
        && call.name == "run_terminal_command"
        && response.process_disposition == ExternalProcessDisposition::ForegroundCleaned
        && !response.timed_out
        && response.cleanup.attempted
        && (response.cleanup.term_sent || response.cleanup.kill_sent)
        && response.cleanup.verified
        && response.census.verified
        && response.census.owned_processes_alive == 0
        && response.target_task_id.is_none()
}

#[allow(clippy::too_many_arguments)]
fn render_foreground_owned_processes_terminated(
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    return_code: i32,
    timed_out: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    max_bytes: usize,
) -> String {
    let original_max_bytes =
        max_bytes.saturating_sub(FOREGROUND_OWNED_PROCESSES_TERMINATED_PREFIX.len());
    let original = render_external_result(
        stdout,
        stderr,
        return_code,
        timed_out,
        stdout_truncated,
        stderr_truncated,
        original_max_bytes,
    );
    let mut output =
        String::with_capacity(FOREGROUND_OWNED_PROCESSES_TERMINATED_PREFIX.len() + original.len());
    output.push_str(FOREGROUND_OWNED_PROCESSES_TERMINATED_PREFIX);
    output.push_str(&original);
    truncate_utf8(&output, max_bytes)
}

#[allow(clippy::too_many_arguments)]
fn finish_response(
    projection_mode: ResponseProjectionMode,
    profile: &AgentProfile,
    call: &FunctionCall,
    response: ExternalToolResponse,
    media_payload: Option<ExternalMediaPayload>,
    stdout_cap_bytes: u64,
    stderr_cap_bytes: u64,
    runtime_budget: Option<ToolRuntimeBudget>,
    effect_observation: Option<ExternalEffectObservationV1>,
) -> Result<ToolResult, ToolExecutionError> {
    let stdout = BASE64
        .decode(response.stdout_base64.as_bytes())
        .map_err(|_| incomplete("external_stdio_response_base64_invalid"))?;
    let stderr = BASE64
        .decode(response.stderr_base64.as_bytes())
        .map_err(|_| incomplete("external_stdio_response_base64_invalid"))?;
    if u64::try_from(stdout.len()).unwrap_or(u64::MAX) > stdout_cap_bytes
        || u64::try_from(stderr.len()).unwrap_or(u64::MAX) > stderr_cap_bytes
    {
        return Err(incomplete("external_stdio_response_output_limit_exceeded"));
    }
    let max_model_bytes = usize::try_from(profile.tools.model_tool_output_bytes_per_call)
        .unwrap_or(usize::MAX)
        .min(FROZEN_RESULT_MAX_BYTES);
    let media = media_payload
        .map(|payload| {
            decode_media(
                &payload,
                call,
                &response,
                &stdout,
                &stderr,
                profile.tools.read_file_media_enabled,
            )
        })
        .transpose()?;
    let execution_evidence = (projection_mode == ResponseProjectionMode::LiveV3)
        .then(|| external_execution_evidence(call, &response, effect_observation));
    let render_evidence = |body: String| match execution_evidence {
        Some(evidence) => evidence.render_before(&body, max_model_bytes),
        None => body,
    };
    if foreground_owned_processes_terminated(projection_mode, call, &response) {
        return Ok(ToolResult {
            execution_attempted: true,
            outcome: ToolOutcome::Rejected,
            output: render_evidence(render_foreground_owned_processes_terminated(
                stdout,
                stderr,
                response.return_code,
                response.timed_out,
                response.stdout_truncated,
                response.stderr_truncated,
                max_model_bytes,
            )),
            media: None,
            runtime_budget,
            actor_receipt: None,
        });
    }
    if call.name == "run_terminal_command"
        && response.process_disposition == ExternalProcessDisposition::ForegroundCleaned
    {
        let output = render_evidence(render_external_result(
            stdout,
            stderr,
            response.return_code,
            response.timed_out,
            response.stdout_truncated,
            response.stderr_truncated,
            max_model_bytes,
        ));
        let mut result = if response.timed_out {
            ToolResult::timed_out(output)
        } else {
            ToolResult::succeeded(output)
        };
        result.runtime_budget = runtime_budget;
        return Ok(result);
    }
    if matches!(
        call.name.as_str(),
        "run_terminal_command" | "kill_terminal_command" | "get_terminal_command_output"
    ) {
        if response.timed_out || !stderr.is_empty() || response.stderr_truncated {
            return Err(incomplete("external_stdio_response_invalid"));
        }
        let output = String::from_utf8(stdout)
            .map_err(|_| incomplete("external_stdio_response_output_not_utf8"))?;
        return match response.return_code {
            0 => {
                let mut result =
                    ToolResult::succeeded(render_evidence(truncate_utf8(&output, max_model_bytes)));
                result.runtime_budget = runtime_budget;
                Ok(result)
            }
            2 => Ok(ToolResult {
                execution_attempted: true,
                outcome: ToolOutcome::Rejected,
                output: render_evidence(truncate_utf8(&output, max_model_bytes)),
                media: None,
                runtime_budget,
                actor_receipt: None,
            }),
            _ => Err(incomplete("external_stdio_response_return_code_invalid")),
        };
    }
    if response.timed_out || !stderr.is_empty() || response.stderr_truncated {
        return Err(incomplete("external_stdio_response_invalid"));
    }
    let output = String::from_utf8(stdout)
        .map_err(|_| incomplete("external_stdio_response_output_not_utf8"))?;
    let output = render_evidence(truncate_utf8(&output, max_model_bytes));
    match response.return_code {
        0 => {
            let mut result = ToolResult::succeeded(output);
            result.media = media.map(Box::new);
            result.runtime_budget = runtime_budget;
            Ok(result)
        }
        2 => Ok(ToolResult {
            execution_attempted: true,
            outcome: ToolOutcome::Rejected,
            output,
            media: None,
            runtime_budget,
            actor_receipt: None,
        }),
        _ => Err(incomplete("external_stdio_response_return_code_invalid")),
    }
}

fn external_execution_evidence(
    call: &FunctionCall,
    response: &ExternalToolResponse,
    effect_observation: Option<ExternalEffectObservationV1>,
) -> ExecutionEvidenceV1 {
    let command = if call.name == "run_terminal_command"
        && response.process_disposition == ExternalProcessDisposition::ForegroundCleaned
    {
        if response.timed_out {
            CommandVerdictV1::Timeout
        } else {
            CommandVerdictV1::Exit(response.return_code)
        }
    } else {
        CommandVerdictV1::NotApplicable
    };
    let effect = match effect_observation.map(|observation| observation.status) {
        Some(ExternalEffectObservationStatusV1::Changed) => EffectObservationV1::Changed,
        Some(ExternalEffectObservationStatusV1::Unchanged) => EffectObservationV1::Unchanged,
        Some(ExternalEffectObservationStatusV1::NotApplicable) => {
            EffectObservationV1::NotApplicable
        }
        None => EffectObservationV1::Unobserved,
    };
    ExecutionEvidenceV1 {
        command,
        timed_out: response.timed_out,
        stdout_truncated: response.stdout_truncated,
        stderr_truncated: response.stderr_truncated,
        effect,
    }
}

fn validate_response(
    request: &ExternalToolRequest,
    request_sha256: &str,
    response: &ExternalToolResponse,
    operation: ForegroundOperation,
) -> Result<(), ToolExecutionError> {
    validate_response_identity(
        request,
        request_sha256,
        &response.schema_version,
        response.message_type,
        response.seq,
        &response.run_id,
        &response.trial_id,
        &response.attempt_id,
        &response.call_id,
        &response.tool_name,
        &response.request_sha256,
    )?;
    validate_response_process(response, operation, None, false)
}

fn valid_background_start_observation(
    response: &ExternalToolResponse,
    operation: ForegroundOperation,
    observation: &ExternalBackgroundStartObservation,
) -> bool {
    if !matches!(
        operation,
        ForegroundOperation::Terminal {
            background: true,
            ..
        }
    ) || observation.proof_version != EXTERNAL_BACKGROUND_START_PROOF_VERSION
        || observation.task_id_published
        || response.process_disposition != ExternalProcessDisposition::NoProcess
        || response.target_task_id.is_some()
        || response.timed_out
        || !response.cleanup.verified
        || !response.census.verified
        || response.census.owned_processes_alive != 0
        || response.cleanup.term_sent
        || response.cleanup.kill_sent
    {
        return false;
    }
    match observation.kind {
        ExternalBackgroundStartKind::NotStarted => {
            observation.child_exit_code.is_none()
                && response.return_code == 2
                && !response.cleanup.attempted
        }
        ExternalBackgroundStartKind::QuickExit => observation.child_exit_code.is_some_and(|code| {
            response.return_code == if code == 0 { 0 } else { 2 } && response.cleanup.attempted
        }),
    }
}

fn validate_response_process(
    response: &ExternalToolResponse,
    operation: ForegroundOperation,
    background_start_observation: Option<&ExternalBackgroundStartObservation>,
    require_background_start_proof: bool,
) -> Result<(), ToolExecutionError> {
    let target_valid = response.target_task_id.as_ref().is_some_and(|task_id| {
        !task_id.is_empty() && task_id.len() <= 256 && !task_id.chars().any(char::is_control)
    });
    if !response.cleanup.verified {
        return Err(incomplete("external_stdio_cleanup_unverified"));
    }
    if !response.census.verified {
        return Err(incomplete("external_stdio_census_unverified"));
    }
    let survivor_count_valid = match response.process_disposition {
        ExternalProcessDisposition::BackgroundRetained => response.census.owned_processes_alive > 0,
        ExternalProcessDisposition::NoProcess
        | ExternalProcessDisposition::ForegroundCleaned
        | ExternalProcessDisposition::BackgroundTerminated => {
            response.census.owned_processes_alive == 0
        }
    };
    if !survivor_count_valid {
        return Err(incomplete("external_stdio_census_unverified"));
    }
    let common_verified = response.cleanup.verified && response.census.verified;
    let process_valid = match response.process_disposition {
        ExternalProcessDisposition::NoProcess => {
            response.target_task_id.is_none()
                && common_verified
                && response.census.owned_processes_alive == 0
                && (matches!(
                    operation,
                    ForegroundOperation::Filesystem
                        | ForegroundOperation::Search
                        | ForegroundOperation::BackgroundOutput { .. }
                        | ForegroundOperation::BackgroundKill
                ) && background_start_observation.is_none()
                    || matches!(
                        operation,
                        ForegroundOperation::Terminal {
                            background: true,
                            ..
                        }
                    ) && if require_background_start_proof {
                        background_start_observation.is_some_and(|observation| {
                            valid_background_start_observation(response, operation, observation)
                        })
                    } else {
                        background_start_observation.is_none() && response.return_code == 2
                    })
        }
        ExternalProcessDisposition::ForegroundCleaned => {
            matches!(
                operation,
                ForegroundOperation::Terminal {
                    background: false,
                    ..
                }
            ) && response.target_task_id.is_none()
                && response.cleanup.attempted
                && common_verified
                && response.census.owned_processes_alive == 0
        }
        ExternalProcessDisposition::BackgroundRetained => {
            matches!(
                operation,
                ForegroundOperation::Terminal {
                    background: true,
                    ..
                }
            ) && target_valid
                && !response.cleanup.attempted
                && common_verified
                && response.census.owned_processes_alive > 0
        }
        ExternalProcessDisposition::BackgroundTerminated => {
            matches!(operation, ForegroundOperation::BackgroundKill)
                && target_valid
                && response.cleanup.attempted
                && common_verified
                && response.census.owned_processes_alive == 0
        }
    };
    if !process_valid
        || background_start_observation.is_some()
            && response.process_disposition != ExternalProcessDisposition::NoProcess
    {
        return Err(incomplete("external_stdio_process_disposition_invalid"));
    }
    if response.process_disposition == ExternalProcessDisposition::ForegroundCleaned
        && response.timed_out
        && !response.cleanup.term_sent
        && !response.cleanup.kill_sent
    {
        return Err(incomplete("external_stdio_cleanup_unverified"));
    }
    Ok(())
}

fn decode_media(
    payload: &ExternalMediaPayload,
    call: &FunctionCall,
    response: &ExternalToolResponse,
    stdout: &[u8],
    stderr: &[u8],
    media_enabled: bool,
) -> Result<ToolMedia, ToolExecutionError> {
    if !media_enabled {
        return Err(incomplete("external_stdio_media_not_enabled"));
    }
    if call.name != "read_file"
        || response.return_code != 0
        || response.timed_out
        || response.stdout_truncated
        || response.stderr_truncated
        || !stderr.is_empty()
        || response.process_disposition != ExternalProcessDisposition::NoProcess
        || response.target_task_id.is_some()
    {
        return Err(incomplete("external_stdio_media_invalid"));
    }
    let bytes = BASE64
        .decode(payload.content_base64.as_bytes())
        .map_err(|_| incomplete("external_stdio_media_base64_invalid"))?;
    if BASE64.encode(&bytes) != payload.content_base64
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != payload.canonical_byte_length
        || format!("{:x}", Sha256::digest(&bytes)) != payload.canonical_sha256
    {
        return Err(incomplete("external_stdio_media_hash_mismatch"));
    }
    let mime_type = match payload.mime_type {
        ExternalMediaType::Png if bytes.starts_with(b"\x89PNG\r\n\x1a\n") => MediaType::Png,
        ExternalMediaType::Jpeg if bytes.starts_with(b"\xff\xd8\xff") => MediaType::Jpeg,
        _ => return Err(incomplete("external_stdio_media_type_mismatch")),
    };
    let expected_output = format!(
        "read_file returned an attached image: {}, {}x{}, sha256={}",
        mime_type.as_str(),
        payload.width,
        payload.height,
        payload.canonical_sha256
    );
    if stdout != expected_output.as_bytes() {
        return Err(incomplete("external_stdio_media_output_mismatch"));
    }
    Ok(ToolMedia::new(
        payload.logical_path.clone(),
        mime_type,
        payload.width,
        payload.height,
        payload.source_byte_length,
        payload.source_sha256.clone(),
        payload.canonical_sha256.clone(),
        bytes,
    ))
}

#[allow(clippy::too_many_arguments)]
fn validate_response_identity(
    request: &ExternalToolRequest,
    request_sha256: &str,
    schema_version: &str,
    message_type: ExternalToolMessageType,
    seq: u64,
    run_id: &str,
    trial_id: &str,
    attempt_id: &str,
    call_id: &str,
    tool_name: &str,
    response_request_sha256: &str,
) -> Result<(), ToolExecutionError> {
    if schema_version != EXTERNAL_TOOL_STDIO_SCHEMA
        || message_type != ExternalToolMessageType::Response
    {
        return Err(incomplete("external_stdio_response_schema_mismatch"));
    }
    if seq != request.seq {
        return Err(incomplete("external_stdio_response_sequence_mismatch"));
    }
    if run_id != request.run_id
        || trial_id != request.trial_id
        || attempt_id != request.attempt_id
        || call_id != request.call_id
        || tool_name != request.tool_name
        || response_request_sha256 != request_sha256
    {
        return Err(incomplete("external_stdio_response_identity_mismatch"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_response_identity_v3(
    request: &ExternalToolRequestV3,
    request_sha256: &str,
    schema_version: &str,
    message_type: ExternalToolMessageType,
    seq: u64,
    run_id: &str,
    trial_id: &str,
    attempt_id: &str,
    call_id: &str,
    tool_name: &str,
    response_request_sha256: &str,
) -> Result<(), ToolExecutionError> {
    if schema_version != EXTERNAL_TOOL_STDIO_V3_SCHEMA
        || message_type != ExternalToolMessageType::Response
    {
        return Err(incomplete("external_stdio_response_schema_mismatch"));
    }
    if seq != request.seq {
        return Err(incomplete("external_stdio_response_sequence_mismatch"));
    }
    if run_id != request.run_id
        || trial_id != request.trial_id
        || attempt_id != request.attempt_id
        || call_id != request.call_id
        || tool_name != request.tool_name
        || response_request_sha256 != request_sha256
    {
        return Err(incomplete("external_stdio_response_identity_mismatch"));
    }
    Ok(())
}

fn validate_v3_response_keyset(bytes: &[u8]) -> Result<(), ()> {
    fn exact(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> bool {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    }

    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let outer = value.as_object().ok_or(())?;
    let common = [
        "schema_version",
        "message_type",
        "seq",
        "run_id",
        "trial_id",
        "attempt_id",
        "call_id",
        "tool_name",
        "request_sha256",
        "settlement",
    ];
    match outer.get("settlement").and_then(serde_json::Value::as_str) {
        Some("completed") => {
            let mut keys = common.to_vec();
            keys.push("result");
            if !exact(outer, &keys) {
                return Err(());
            }
            let result = outer
                .get("result")
                .and_then(serde_json::Value::as_object)
                .ok_or(())?;
            if !exact(
                result,
                &[
                    "return_code",
                    "timed_out",
                    "stdout_base64",
                    "stderr_base64",
                    "stdout_truncated",
                    "stderr_truncated",
                    "process_disposition",
                    "target_task_id",
                    "cleanup",
                    "census",
                    "effect_observation_v1",
                    "media",
                    "wait_clamped",
                    "wait_reason",
                    "background_start_observation",
                    "actor_receipt",
                ],
            ) {
                return Err(());
            }
            let cleanup = result
                .get("cleanup")
                .and_then(serde_json::Value::as_object)
                .ok_or(())?;
            let census = result
                .get("census")
                .and_then(serde_json::Value::as_object)
                .ok_or(())?;
            if !exact(
                cleanup,
                &["attempted", "term_sent", "kill_sent", "verified"],
            ) || !exact(census, &["verified", "owned_processes_alive"])
            {
                return Err(());
            }
            if let Some(media) = result.get("media").and_then(serde_json::Value::as_object)
                && !exact(
                    media,
                    &[
                        "logical_path",
                        "mime_type",
                        "width",
                        "height",
                        "source_byte_length",
                        "source_sha256",
                        "canonical_byte_length",
                        "canonical_sha256",
                        "content_base64",
                    ],
                )
            {
                return Err(());
            }
            if !valid_actor_receipt_keyset(result.get("actor_receipt").ok_or(())?) {
                return Err(());
            }
        }
        Some("fatal") => {
            let mut keys = common.to_vec();
            keys.push("failure");
            if !exact(outer, &keys) {
                return Err(());
            }
            let failure = outer
                .get("failure")
                .and_then(serde_json::Value::as_object)
                .ok_or(())?;
            if !exact(
                failure,
                &[
                    "code",
                    "execution_may_have_started",
                    "cleanup_verified",
                    "census_verified",
                    "recoverability",
                    "actor_receipt",
                ],
            ) {
                return Err(());
            }
            if !valid_actor_receipt_keyset(failure.get("actor_receipt").ok_or(())?) {
                return Err(());
            }
        }
        _ => return Err(()),
    }
    Ok(())
}

fn valid_actor_receipt_keyset(value: &serde_json::Value) -> bool {
    if value.is_null() {
        return true;
    }
    let Some(receipt) = value.as_object() else {
        return false;
    };
    let keys = [
        "schema_version",
        "phase",
        "origin",
        "primary_subtype",
        "recovery_subtype",
        "execution_may_have_started",
        "effective_cutoff_monotonic_ns",
        "cleanup_verified",
        "census_verified",
        "diagnostic_digest_sha256",
    ];
    receipt.len() == keys.len() && keys.iter().all(|key| receipt.contains_key(*key))
}

fn foreground_actor_receipt(
    operation: ForegroundOperation,
    receipt: Option<&ExternalTerminalActorReceiptV1>,
) -> Result<Option<&ExternalTerminalActorReceiptV1>, ToolExecutionError> {
    let required = matches!(
        operation,
        ForegroundOperation::Terminal {
            background: false,
            ..
        }
    );
    if required != receipt.is_some() {
        return Err(incomplete("external_stdio_actor_receipt_invalid"));
    }
    Ok(receipt)
}

fn validate_actor_receipt_root(
    request: &ExternalToolRequestV3,
    receipt: &ExternalTerminalActorReceiptV1,
) -> Result<(), ToolExecutionError> {
    if receipt.effective_cutoff_monotonic_ns > request.actor_done_monotonic_ns {
        return Err(incomplete("external_stdio_actor_receipt_invalid"));
    }
    Ok(())
}

fn validate_completed_actor_receipt(
    request: &ExternalToolRequestV3,
    operation: ForegroundOperation,
    result: &nano_types::external_tool::ExternalToolCompletedResultV3,
) -> Result<(), ToolExecutionError> {
    let Some(receipt) = foreground_actor_receipt(operation, result.actor_receipt.as_ref())? else {
        return Ok(());
    };
    validate_actor_receipt_root(request, receipt)?;
    let recovered = receipt.recovery_subtype.is_some();
    if !receipt.execution_may_have_started
        || receipt.cleanup_verified != Some(result.cleanup.verified)
        || receipt.census_verified != Some(result.census.verified)
        || result.timed_out
            && !recovered
            && (receipt.origin != ExternalTerminalActorOriginV1::Semantic
                || receipt.primary_subtype
                    != ExternalTerminalActorSubtypeV1::SemanticExecutionTimedOut)
        || !result.timed_out
            && !recovered
            && (receipt.origin != ExternalTerminalActorOriginV1::Actor
                || receipt.primary_subtype != ExternalTerminalActorSubtypeV1::Completed)
        || recovered
            && (receipt.recovery_subtype != Some(ExternalTerminalActorSubtypeV1::RecoveredSettled)
                || !matches!(
                    receipt.primary_subtype,
                    ExternalTerminalActorSubtypeV1::RunTransportTimeout
                        | ExternalTerminalActorSubtypeV1::RunTransportFailed
                        | ExternalTerminalActorSubtypeV1::RunResponseNonzero
                ))
    {
        return Err(incomplete("external_stdio_actor_receipt_invalid"));
    }
    Ok(())
}

fn validate_fatal_actor_receipt(
    request: &ExternalToolRequestV3,
    operation: ForegroundOperation,
    failure: &nano_types::external_tool::ExternalToolFailureV3,
) -> Result<(), ToolExecutionError> {
    let Some(receipt) = foreground_actor_receipt(operation, failure.actor_receipt.as_ref())? else {
        return Ok(());
    };
    validate_actor_receipt_root(request, receipt)?;
    if receipt.execution_may_have_started != failure.execution_may_have_started
        || receipt.cleanup_verified != failure.cleanup_verified
        || receipt.census_verified != failure.census_verified
    {
        return Err(incomplete("external_stdio_actor_receipt_invalid"));
    }
    Ok(())
}

fn remote_fatal_code(code: &str) -> &'static str {
    match code {
        "terminal_actor_action_admission_rejected" => "terminal_actor_action_admission_rejected",
        "terminal_actor_arguments_invalid" => "terminal_actor_arguments_invalid",
        "terminal_actor_background_output_deadline_exceeded" => {
            "terminal_actor_background_output_deadline_exceeded"
        }
        "terminal_actor_background_output_failed" => "terminal_actor_background_output_failed",
        "terminal_actor_background_output_limit_exceeded" => {
            "terminal_actor_background_output_limit_exceeded"
        }
        "terminal_actor_background_registration_failed" => {
            "terminal_actor_background_registration_failed"
        }
        "terminal_actor_background_setup_failed" => "terminal_actor_background_setup_failed",
        "terminal_actor_background_start_failed" => "terminal_actor_background_start_failed",
        "terminal_actor_background_start_invalid" => "terminal_actor_background_start_invalid",
        "terminal_actor_background_status_invalid" => "terminal_actor_background_status_invalid",
        "terminal_actor_background_status_unavailable" => {
            "terminal_actor_background_status_unavailable"
        }
        "terminal_actor_cleanup_unverified" => "terminal_actor_cleanup_unverified",
        "terminal_actor_census_unverified" => "terminal_actor_census_unverified",
        "terminal_actor_transport_unknown" => "terminal_actor_transport_unknown",
        "terminal_actor_background_cleanup_unknown" => "terminal_actor_background_cleanup_unknown",
        "terminal_actor_duplicate_request" => "terminal_actor_duplicate_request",
        "terminal_actor_deadline_exceeded" => "terminal_actor_deadline_exceeded",
        "terminal_actor_failure" => "terminal_actor_failure",
        "terminal_actor_file_size_changed" => "terminal_actor_file_size_changed",
        "terminal_actor_grep_response_invalid" => "terminal_actor_grep_response_invalid",
        "terminal_actor_list_inventory_invalid" => "terminal_actor_list_inventory_invalid",
        "terminal_actor_logical_cwd_invalid" => "terminal_actor_logical_cwd_invalid",
        "terminal_actor_meta_invalid" => "terminal_actor_meta_invalid",
        "terminal_actor_not_ready" => "terminal_actor_not_ready",
        "terminal_actor_output_limit_exceeded" => "terminal_actor_output_limit_exceeded",
        "terminal_actor_path_response_invalid" => "terminal_actor_path_response_invalid",
        "terminal_actor_read_size_changed" => "terminal_actor_read_size_changed",
        "terminal_actor_request_setup_failed" => "terminal_actor_request_setup_failed",
        "terminal_actor_run_failed" => "terminal_actor_run_failed",
        "terminal_actor_setup_failed" => "terminal_actor_setup_failed",
        "terminal_actor_snapshot_duplicate_lease" => "terminal_actor_snapshot_duplicate_lease",
        "terminal_actor_snapshot_path_invalid" => "terminal_actor_snapshot_path_invalid",
        "terminal_actor_snapshot_request_invalid" => "terminal_actor_snapshot_request_invalid",
        "terminal_actor_snapshot_response_invalid" => "terminal_actor_snapshot_response_invalid",
        "terminal_actor_snapshot_status_invalid" => "terminal_actor_snapshot_status_invalid",
        "terminal_actor_snapshot_termination_unverified" => {
            "terminal_actor_snapshot_termination_unverified"
        }
        "terminal_actor_snapshot_token_invalid" => "terminal_actor_snapshot_token_invalid",
        "terminal_actor_snapshot_transport_timeout" => "terminal_actor_snapshot_transport_timeout",
        "terminal_actor_task_id_invalid" => "terminal_actor_task_id_invalid",
        "terminal_actor_tool_unsupported" => "terminal_actor_tool_unsupported",
        "terminal_actor_unexpected_failure" => "terminal_actor_unexpected_failure",
        "terminal_actor_workspace_mapping_changed" => "terminal_actor_workspace_mapping_changed",
        "terminal_actor_workspace_mapping_check_timeout" => {
            "terminal_actor_workspace_mapping_check_timeout"
        }
        "terminal_actor_workspace_not_mapped" => "terminal_actor_workspace_not_mapped",
        "terminal_actor_workspace_setup_failed" => "terminal_actor_workspace_setup_failed",
        "terminal_actor_workspace_setup_invalid" => "terminal_actor_workspace_setup_invalid",
        "tool_settlement_deadline_exceeded" => "tool_settlement_deadline_exceeded",
        "response_serialization_deadline_exceeded" => "response_serialization_deadline_exceeded",
        "response_serialization_failure" => "response_serialization_failure",
        "response_serialization_size_limit_exceeded" => {
            "response_serialization_size_limit_exceeded"
        }
        "external_response_bounds_invalid" => "external_response_bounds_invalid",
        "external_response_failure_invalid" => "external_response_failure_invalid",
        "external_response_media_invalid" => "external_response_media_invalid",
        "external_response_process_invalid" => "external_response_process_invalid",
        "external_response_return_code_invalid" => "external_response_return_code_invalid",
        "external_response_wait_invalid" => "external_response_wait_invalid",
        "external_stdio_response_timeout" => "external_stdio_response_timeout",
        "cleanup_deadline_exceeded" => "cleanup_deadline_exceeded",
        _ => "external_stdio_remote_fatal",
    }
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut line = Vec::with_capacity(max_bytes.min(8192));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| "external_stdio_response_read_failed")?;
        if available.is_empty() {
            return Err("external_stdio_response_eof");
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if line.len().saturating_add(newline) > max_bytes {
                reader.consume(newline + 1);
                return Err("external_stdio_response_line_limit_exceeded");
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            break;
        }
        if line.len().saturating_add(available.len()) > max_bytes {
            let consumed = available.len();
            reader.consume(consumed);
            return Err("external_stdio_response_line_limit_exceeded");
        }
        line.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }
    if line.is_empty() || line.last() == Some(&b'\r') {
        return Err("external_stdio_response_invalid");
    }
    Ok(line)
}

fn base64_encoded_len(bytes: u64) -> Option<u64> {
    bytes.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

fn incomplete(code: &'static str) -> ToolExecutionError {
    match failure_class(code) {
        ToolExecutionFailureClass::Deadline => ToolExecutionError::deadline(code),
        ToolExecutionFailureClass::Bridge => ToolExecutionError::bridge(code),
        ToolExecutionFailureClass::Cleanup => ToolExecutionError::cleanup(code, true, None, None),
        ToolExecutionFailureClass::Tool => ToolExecutionError::incomplete(code),
    }
}

fn failure_class(code: &str) -> ToolExecutionFailureClass {
    match code {
        "cleanup_deadline_exceeded"
        | "external_stdio_census_unverified"
        | "external_stdio_cleanup_unverified"
        | "terminal_actor_background_cleanup_unknown"
        | "terminal_actor_census_unverified"
        | "terminal_actor_cleanup_unverified"
        | "terminal_actor_snapshot_termination_unverified" => ToolExecutionFailureClass::Cleanup,
        "deadline_before_dispatch"
        | "external_stdio_deadline_invalid"
        | "external_stdio_response_timeout"
        | "external_stdio_settlement_budget_invalid"
        | "response_serialization_deadline_exceeded"
        | "terminal_actor_action_admission_rejected"
        | "terminal_actor_background_output_deadline_exceeded"
        | "terminal_actor_deadline_exceeded"
        | "terminal_actor_snapshot_transport_timeout"
        | "terminal_actor_workspace_mapping_check_timeout"
        | "tool_settlement_deadline_exceeded"
        | "tool_settlement_parse_deadline_exceeded" => ToolExecutionFailureClass::Deadline,
        "external_stdio_active_tools_invalid"
        | "external_response_bounds_invalid"
        | "external_response_failure_invalid"
        | "external_response_media_invalid"
        | "external_response_process_invalid"
        | "external_response_return_code_invalid"
        | "external_response_wait_invalid"
        | "external_stdio_limit_overflow"
        | "external_stdio_logical_cwd_not_utf8"
        | "external_stdio_media_base64_invalid"
        | "external_stdio_media_hash_mismatch"
        | "external_stdio_media_invalid"
        | "external_stdio_media_not_enabled"
        | "external_stdio_media_output_mismatch"
        | "external_stdio_media_type_mismatch"
        | "external_stdio_process_disposition_invalid"
        | "external_stdio_process_stdin_failed"
        | "external_stdio_remote_fatal"
        | "external_stdio_request_flush_failed"
        | "external_stdio_request_invalid"
        | "external_stdio_request_line_limit_exceeded"
        | "external_stdio_request_serialize_failed"
        | "external_stdio_request_write_failed"
        | "external_stdio_response_base64_invalid"
        | "external_stdio_response_eof"
        | "external_stdio_response_identity_mismatch"
        | "external_stdio_response_invalid"
        | "external_stdio_response_line_limit_exceeded"
        | "external_stdio_response_output_limit_exceeded"
        | "external_stdio_response_output_not_utf8"
        | "external_stdio_response_read_failed"
        | "external_stdio_response_return_code_invalid"
        | "external_stdio_response_schema_mismatch"
        | "external_stdio_response_sequence_mismatch"
        | "external_stdio_sequence_overflow"
        | "external_stdio_timeout_invalid"
        | "external_stdio_timeout_overflow"
        | "external_stdio_validated_call_changed"
        | "external_stdio_workspace_mismatch"
        | "response_serialization_failure"
        | "response_serialization_size_limit_exceeded"
        | "terminal_actor_arguments_invalid"
        | "terminal_actor_background_output_failed"
        | "terminal_actor_background_output_limit_exceeded"
        | "terminal_actor_background_registration_failed"
        | "terminal_actor_background_setup_failed"
        | "terminal_actor_background_start_failed"
        | "terminal_actor_background_start_invalid"
        | "terminal_actor_background_status_invalid"
        | "terminal_actor_background_status_unavailable"
        | "terminal_actor_duplicate_request"
        | "terminal_actor_failure"
        | "terminal_actor_file_size_changed"
        | "terminal_actor_grep_response_invalid"
        | "terminal_actor_list_inventory_invalid"
        | "terminal_actor_logical_cwd_invalid"
        | "terminal_actor_meta_invalid"
        | "terminal_actor_not_ready"
        | "terminal_actor_output_limit_exceeded"
        | "terminal_actor_path_response_invalid"
        | "terminal_actor_read_size_changed"
        | "terminal_actor_request_setup_failed"
        | "terminal_actor_run_failed"
        | "terminal_actor_setup_failed"
        | "terminal_actor_snapshot_duplicate_lease"
        | "terminal_actor_snapshot_path_invalid"
        | "terminal_actor_snapshot_request_invalid"
        | "terminal_actor_snapshot_response_invalid"
        | "terminal_actor_snapshot_status_invalid"
        | "terminal_actor_snapshot_token_invalid"
        | "terminal_actor_task_id_invalid"
        | "terminal_actor_tool_unsupported"
        | "terminal_actor_transport_unknown"
        | "terminal_actor_unexpected_failure"
        | "terminal_actor_workspace_mapping_changed"
        | "terminal_actor_workspace_not_mapped"
        | "terminal_actor_workspace_setup_failed"
        | "terminal_actor_workspace_setup_invalid" => ToolExecutionFailureClass::Bridge,
        _ => ToolExecutionFailureClass::Tool,
    }
}

fn attempted_rejection(output: &'static str) -> ToolResult {
    ToolResult {
        execution_attempted: true,
        outcome: nano_types::event::ToolOutcome::Rejected,
        output: output.to_owned(),
        media: None,
        runtime_budget: None,
        actor_receipt: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_timeout_clamp_uses_floored_remaining_milliseconds() {
        let cases = [
            (Duration::ZERO, None),
            (Duration::from_nanos(999_999), None),
            (Duration::from_millis(1), Some(1)),
            (Duration::from_millis(200), Some(200)),
            (Duration::from_millis(119_999), Some(119_999)),
            (Duration::from_millis(120_000), Some(120_000)),
            (Duration::from_millis(120_001), Some(120_000)),
        ];

        for (remaining, expected) in cases {
            assert_eq!(
                clamp_foreground_timeout_ms(120_000, remaining)
                    .expect("remaining duration fits u64 milliseconds"),
                expected,
            );
        }
    }
}
