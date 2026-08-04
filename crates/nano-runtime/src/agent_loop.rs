//! One serial provider/tool loop with settled success or provider failure.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nano_provider_xai::{
    FunctionCall, FunctionTool, HistoryItem, MediaHistoryPolicyReceiptV1,
    PreparedMediaHistoryBatch, PreparedTurnRequest, Provider, ProviderFailure, ProviderRequestMode,
    ProviderSendTelemetry, TurnRequest, apply_media_history_policy, media_history_policy_sha256,
    prepare_media_history_batch,
};
use nano_types::contract::{EffectClass, LocalContract};
use nano_types::event::{
    AssistantFinal, EventBody, MediaHistoryRequestReceiptV1, ProviderBudgetObservationV1,
    ProviderBudgetPhaseV1, ProviderCallCoverage, ProviderCompleted, ProviderFailed,
    ProviderRequested, RUN_RECORD_SCHEMA, RunCompleted, RunFailed, RunRecord, RunRecordV3,
    RunStarted, TOOL_RECEIPT_V1_SCHEMA, TerminalPhase, TerminalStatus, ToolBudgetObservationV1,
    ToolCompleted as ToolCompletedEvent, ToolDispatched, ToolFailed, ToolFailureRecoverability,
    ToolReceiptV1, ToolRegistered, UsageState, UsageTotals, VersionedRunRecord,
    tool_receipt_identity_sha256,
};
use nano_types::external_tool::ExternalTerminalActorReceiptV1;
use nano_types::run_spec::RunSpec;

use crate::completion_review::{
    COMPLETION_REVIEW_DECISION_PROMPT, CompletionEvidenceLedger, CompletionReviewCapacity,
    CompletionReviewPolicy, FINAL_RESPONSE_LATENCY_RESERVE_V1, REVIEW_BOUNDED_TOOL_RESERVE_V1,
    recent_terminal_evidence,
};
use crate::deadline::DeadlineContext;
use crate::event_writer::{EventWriteError, EventWriter, EventWriterLimits, RunRecordPublication};
use crate::external_stdio::SettlementStageCutoffsV1;
use crate::foreground::truncate_utf8;
use crate::protected_target::{PROTECTED_HARNESS_MATERIAL_ACCESS_BLOCKED, match_protected_target};
use crate::tool::{
    ToolExecutionError, ToolExecutionFailureClass, ToolExecutor, ToolResult, WorkspaceMode,
};

const MAX_STAGED_TOOL_RECEIPT_SAMPLES: usize = 256;
const MAX_STAGED_TOOL_RECEIPT_BYTES: usize = 256 * 1024;
const CALL_LIMIT_RECOVERY_HISTORY_CODE: &str = "call_limit_recovery_history_failed";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum CompletionReviewPhase {
    #[default]
    NotIssued,
    Validation,
    Decision,
    Correction,
    Revalidation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionReviewToolStage {
    Validation,
    Correction,
    Revalidation,
}

#[derive(Debug, Default)]
struct CompletionChallengeState {
    phase: CompletionReviewPhase,
    provisional_final: Option<String>,
    workspace_mutated: bool,
}

impl CompletionChallengeState {
    fn issue(&mut self, provisional_final: String) {
        debug_assert_eq!(self.phase, CompletionReviewPhase::NotIssued);
        self.phase = CompletionReviewPhase::Validation;
        self.provisional_final = Some(provisional_final);
        self.workspace_mutated = false;
    }

    fn admit_tool_stage(
        &self,
        effects: impl IntoIterator<Item = EffectClass>,
    ) -> Option<CompletionReviewToolStage> {
        let effects = effects.into_iter().collect::<Vec<_>>();
        if effects.is_empty() {
            return None;
        }
        match self.phase {
            CompletionReviewPhase::NotIssued => None,
            CompletionReviewPhase::Validation => Some(CompletionReviewToolStage::Validation),
            CompletionReviewPhase::Decision if effects.contains(&EffectClass::Mutating) => {
                Some(CompletionReviewToolStage::Correction)
            }
            CompletionReviewPhase::Correction
                if effects
                    .iter()
                    .all(|effect| *effect == EffectClass::ReadOnly) =>
            {
                Some(CompletionReviewToolStage::Revalidation)
            }
            CompletionReviewPhase::Decision
            | CompletionReviewPhase::Correction
            | CompletionReviewPhase::Revalidation => None,
        }
    }

    fn commit_tool_stage(
        &mut self,
        stage: CompletionReviewToolStage,
        dispatched: bool,
        mutated: bool,
    ) {
        if mutated {
            self.workspace_mutated = true;
            self.provisional_final = None;
        }
        if !dispatched {
            return;
        }
        self.phase = match (self.phase, stage) {
            (CompletionReviewPhase::Validation, CompletionReviewToolStage::Validation) => {
                CompletionReviewPhase::Decision
            }
            (CompletionReviewPhase::Decision, CompletionReviewToolStage::Correction) => {
                CompletionReviewPhase::Correction
            }
            (CompletionReviewPhase::Correction, CompletionReviewToolStage::Revalidation) => {
                CompletionReviewPhase::Revalidation
            }
            (phase, _) => phase,
        };
    }

    fn take_safe_fallback(&mut self) -> Option<String> {
        if self.workspace_mutated {
            None
        } else {
            self.provisional_final.take()
        }
    }

    fn close_review(&mut self) {
        if self.phase != CompletionReviewPhase::NotIssued {
            self.phase = CompletionReviewPhase::Revalidation;
        }
    }

    fn requires_final_only(&self) -> bool {
        self.phase == CompletionReviewPhase::Revalidation
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunOutcome {
    /// Stable v2-compatible in-memory view for existing direct field consumers.
    pub record: RunRecord,
    /// Authoritative typed terminal wire record written to `run.json`.
    pub terminal_record: VersionedRunRecord,
    pub publication: RunRecordPublication,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct V3DeadlineBinding {
    receipt_sha256: String,
}

impl V3DeadlineBinding {
    fn try_from_deadline(deadline: &DeadlineContext) -> Result<Self, AgentRunError> {
        let receipt_sha256 = deadline.receipt_sha256.clone();
        if receipt_sha256.len() != 64
            || !receipt_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AgentRunError::configuration(
                "deadline_receipt_sha256_invalid",
            ));
        }
        Ok(Self { receipt_sha256 })
    }
}

#[derive(Debug)]
enum AgentRunMode<'a> {
    V2,
    V3 {
        deadline: &'a DeadlineContext,
        binding: V3DeadlineBinding,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderPhase {
    ActionOpen,
    SettlingAccepted,
    FinalOnly,
    TerminalCommit,
}

fn provider_phase_at(
    now: Instant,
    actor_done: Instant,
    last_send: Instant,
    minimum_send_window: Duration,
    final_send_started: bool,
) -> ProviderPhase {
    if final_send_started {
        return ProviderPhase::TerminalCommit;
    }
    let Some(latency_cutoff) = last_send.checked_sub(FINAL_RESPONSE_LATENCY_RESERVE_V1) else {
        return ProviderPhase::FinalOnly;
    };
    let Some(minimum_window_cutoff) = actor_done.checked_sub(minimum_send_window) else {
        return ProviderPhase::FinalOnly;
    };
    let action_cutoff = minimum_window_cutoff.min(latency_cutoff);
    if now < action_cutoff {
        ProviderPhase::ActionOpen
    } else {
        ProviderPhase::FinalOnly
    }
}

/// Preserve exactly one action-capable provider turn when a signed run starts
/// with less capacity than the frozen final-response reserve. This does not
/// move the 90-second cutoff: equality and every later turn still use
/// `provider_phase_at`. The exceptional first turn also remains strictly
/// inside the signed actor cutoff minus the profile's minimum send window.
fn initial_provider_phase_at(
    now: Instant,
    actor_done: Instant,
    last_send: Instant,
    minimum_send_window: Duration,
) -> ProviderPhase {
    let strict_phase = provider_phase_at(now, actor_done, last_send, minimum_send_window, false);
    if strict_phase != ProviderPhase::FinalOnly {
        return strict_phase;
    }
    let launch_is_under_capacity = last_send
        .checked_duration_since(now)
        .is_some_and(|remaining| remaining < FINAL_RESPONSE_LATENCY_RESERVE_V1);
    let action_window_is_open = actor_done
        .checked_sub(minimum_send_window)
        .is_some_and(|cutoff| now < cutoff);
    if launch_is_under_capacity && action_window_is_open {
        ProviderPhase::ActionOpen
    } else {
        strict_phase
    }
}

fn completion_review_provider_deadline(now: Instant, actor_done: Instant) -> Instant {
    now.checked_add(FINAL_RESPONSE_LATENCY_RESERVE_V1)
        .map(|bounded| bounded.min(actor_done))
        .unwrap_or(now)
}

fn completion_review_tool_deadline(now: Instant, tool_settled: Instant) -> Instant {
    now.checked_add(REVIEW_BOUNDED_TOOL_RESERVE_V1)
        .map(|bounded| bounded.min(tool_settled))
        .unwrap_or(now)
}

fn tool_dispatch_open_at(now: Instant, actor_done: Instant) -> bool {
    now < actor_done
}

fn runtime_budget_notice(
    deadline: &DeadlineContext,
    terminal_max_timeout_ms: u64,
) -> Option<String> {
    let now = Instant::now();
    let action_remaining = deadline.instants.actor_done.checked_duration_since(now)?;
    let action_remaining_ms = u64::try_from(action_remaining.as_millis()).unwrap_or(u64::MAX);
    if action_remaining_ms > terminal_max_timeout_ms {
        return None;
    }
    let remaining_ms = |cutoff: Instant| {
        cutoff
            .checked_duration_since(now)
            .map(|remaining| u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    };
    Some(format!(
        "<runtime_budget_v1 action_remaining_ms=\"{action_remaining_ms}\" \
settlement_remaining_ms=\"{}\" last_send_remaining_ms=\"{}\">\n\
Preserve the strongest durable deliverable already present. Do not begin exploratory work or a \
new long-running operation. Run at most one explicitly bounded check only when its worst-case \
duration fits both the action and settlement windows; otherwise return the final now. Background \
work does not extend these deadlines.\n\
</runtime_budget_v1>",
        remaining_ms(deadline.instants.tool_settled),
        remaining_ms(deadline.instants.last_send),
    ))
}

fn remaining_milliseconds(cutoff: Instant, now: Instant) -> u64 {
    cutoff
        .checked_duration_since(now)
        .map(|remaining| u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn provider_budget_observation(
    deadline: Option<&DeadlineContext>,
    phase: ProviderBudgetPhaseV1,
    budget_notice_visible: bool,
) -> Option<ProviderBudgetObservationV1> {
    let deadline = deadline?;
    let now = Instant::now();
    Some(ProviderBudgetObservationV1 {
        phase,
        budget_notice_visible,
        action_remaining_ms: remaining_milliseconds(deadline.instants.actor_done, now),
        settlement_remaining_ms: remaining_milliseconds(deadline.instants.tool_settled, now),
        last_send_remaining_ms: remaining_milliseconds(deadline.instants.last_send, now),
    })
}

fn tool_budget_observation(
    deadline: Option<&DeadlineContext>,
    now: Instant,
    dispatch_open_at_registration: bool,
) -> Option<ToolBudgetObservationV1> {
    let deadline = deadline?;
    Some(ToolBudgetObservationV1 {
        dispatch_open_at_registration,
        action_remaining_ms: remaining_milliseconds(deadline.instants.actor_done, now),
        settlement_remaining_ms: remaining_milliseconds(deadline.instants.tool_settled, now),
        last_send_remaining_ms: remaining_milliseconds(deadline.instants.last_send, now),
    })
}

impl<'a> AgentRunMode<'a> {
    fn v3(deadline: &'a DeadlineContext) -> Result<Self, AgentRunError> {
        Ok(Self::V3 {
            deadline,
            binding: V3DeadlineBinding::try_from_deadline(deadline)?,
        })
    }

    fn deadline(&self) -> Option<&'a DeadlineContext> {
        match self {
            Self::V2 => None,
            Self::V3 { deadline, .. } => Some(*deadline),
        }
    }

    fn deadline_receipt_sha256(&self) -> Option<&str> {
        match self {
            Self::V2 => None,
            Self::V3 { binding, .. } => Some(&binding.receipt_sha256),
        }
    }

    fn into_emission(self) -> RunRecordEmission {
        match self {
            Self::V2 => RunRecordEmission::V2,
            Self::V3 { binding, .. } => RunRecordEmission::V3(binding),
        }
    }
}

#[derive(Debug, Clone)]
enum RunRecordEmission {
    V2,
    V3(V3DeadlineBinding),
}

impl RunRecordEmission {
    fn deadline_receipt_sha256(&self) -> Option<&str> {
        match self {
            Self::V2 => None,
            Self::V3(binding) => Some(&binding.receipt_sha256),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunCancellation {
    cancelled: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl Default for RunCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl RunCancellation {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

pub async fn run_agent<P: Provider, T: ToolExecutor>(
    spec: &RunSpec,
    contract: &LocalContract,
    provider: &mut P,
    executor: &mut T,
) -> Result<AgentRunOutcome, AgentRunError> {
    run_agent_bound(
        spec,
        contract,
        provider,
        executor,
        AgentRunMode::V2,
        CompletionReviewPolicy::Disabled,
    )
    .await
}

/// Run a host-integrated composition against its validated absolute deadline.
pub async fn run_agent_with_deadline<P: Provider, T: ToolExecutor>(
    spec: &RunSpec,
    contract: &LocalContract,
    provider: &mut P,
    executor: &mut T,
    deadline: &DeadlineContext,
) -> Result<AgentRunOutcome, AgentRunError> {
    run_agent_with_deadline_and_review(
        spec,
        contract,
        provider,
        executor,
        deadline,
        CompletionReviewPolicy::Disabled,
    )
    .await
}

/// Run with a caller-selected, framework-neutral completion review policy.
pub async fn run_agent_with_deadline_and_review<P: Provider, T: ToolExecutor>(
    spec: &RunSpec,
    contract: &LocalContract,
    provider: &mut P,
    executor: &mut T,
    deadline: &DeadlineContext,
    completion_review_policy: CompletionReviewPolicy,
) -> Result<AgentRunOutcome, AgentRunError> {
    run_agent_bound(
        spec,
        contract,
        provider,
        executor,
        AgentRunMode::v3(deadline)?,
        completion_review_policy,
    )
    .await
}

async fn run_agent_bound<P: Provider, T: ToolExecutor>(
    spec: &RunSpec,
    contract: &LocalContract,
    provider: &mut P,
    executor: &mut T,
    mode: AgentRunMode<'_>,
    completion_review_policy: CompletionReviewPolicy,
) -> Result<AgentRunOutcome, AgentRunError> {
    let cancellation = RunCancellation::new();
    #[cfg(unix)]
    let signal_task = {
        let cancellation = cancellation.clone();
        tokio::spawn(async move {
            if let Ok(mut signal) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                let _ = signal.recv().await;
                cancellation.cancel();
            }
        })
    };
    let outcome = run_agent_bound_with_cancellation(
        spec,
        contract,
        provider,
        executor,
        &cancellation,
        mode,
        completion_review_policy,
    )
    .await;
    #[cfg(unix)]
    signal_task.abort();
    outcome
}

pub async fn run_agent_with_cancellation<P: Provider, T: ToolExecutor>(
    spec: &RunSpec,
    contract: &LocalContract,
    provider: &mut P,
    executor: &mut T,
    cancellation: &RunCancellation,
) -> Result<AgentRunOutcome, AgentRunError> {
    run_agent_bound_with_cancellation(
        spec,
        contract,
        provider,
        executor,
        cancellation,
        AgentRunMode::V2,
        CompletionReviewPolicy::Disabled,
    )
    .await
}

async fn run_agent_bound_with_cancellation<P: Provider, T: ToolExecutor>(
    spec: &RunSpec,
    contract: &LocalContract,
    provider: &mut P,
    executor: &mut T,
    cancellation: &RunCancellation,
    mode: AgentRunMode<'_>,
    completion_review_policy: CompletionReviewPolicy,
) -> Result<AgentRunOutcome, AgentRunError> {
    let clock_origin = Instant::now();
    let deadline = mode.deadline();
    validate_runtime_bindings(spec, contract)?;
    if executor.workspace_mode() == WorkspaceMode::LocalDirectory {
        validate_workspace(spec)?;
    }
    let profile = contract.profile();
    let run_spec_sha256 = spec
        .sha256()
        .map_err(|_| AgentRunError::configuration("run_spec_hash_failed"))?;
    let legacy_action_deadline = clock_origin
        .checked_add(Duration::from_secs(spec.agent_timeout_sec))
        .and_then(|runtime_deadline| {
            runtime_deadline.checked_sub(Duration::from_secs(
                profile.deadlines.terminalization_reserve_sec,
            ))
        })
        .ok_or_else(|| AgentRunError::configuration("action_deadline_underflow"))?;
    let (actor_done, tool_settled, last_send) = match deadline {
        Some(deadline) => (
            deadline.instants.actor_done,
            deadline.instants.tool_settled,
            deadline.instants.last_send,
        ),
        None => (
            legacy_action_deadline,
            legacy_action_deadline,
            legacy_action_deadline,
        ),
    };
    let minimum_send_window = Duration::from_secs(profile.deadlines.min_provider_send_window_sec);
    let all_tools = contract
        .effective()
        .ordered_tools()
        .iter()
        .map(|tool| FunctionTool {
            name: tool.provider_name.clone(),
            description: tool.description.clone(),
            parameters: tool.input_schema.clone(),
        })
        .collect::<Vec<_>>();
    let tools = resolve_request_tools(spec, &all_tools)?;
    let mut writer = EventWriter::create(
        &spec.artifact_dir,
        &spec.run_id,
        &spec.trial_id,
        &spec.attempt_id,
        EventWriterLimits {
            max_events: profile.artifacts.max_events_per_run,
            max_line_bytes: profile.artifacts.max_event_line_bytes,
            max_log_bytes: profile.artifacts.max_event_log_bytes,
            max_run_record_bytes: profile.artifacts.max_agent_run_record_bytes,
        },
    )?;
    let mut history = vec![
        HistoryItem::System {
            content: contract.effective().system_prompt.text.clone(),
        },
        HistoryItem::User {
            content: contract.effective().wrap_user_query(&spec.task.instruction),
        },
    ];
    let mut media_history_receipt = apply_media_history_policy(&mut history)
        .map_err(|_| AgentRunError::configuration("media_history_policy_initialization_failed"))?;
    let media_history_policy_sha256 = media_history_policy_sha256()
        .map_err(|_| AgentRunError::configuration("media_history_policy_initialization_failed"))?;
    let deadline_receipt_sha256 = mode.deadline_receipt_sha256().map(str::to_owned);
    writer.append_operational(EventBody::RunStarted(RunStarted {
        task_id: spec.task.id.clone(),
        contract_id: spec.contract.id.clone(),
        profile_id: spec.contract.profile_id.clone(),
        contract_set_sha256: spec.contract.contract_set_sha256.clone(),
        model: spec.provider.model.clone(),
        run_spec_sha256: run_spec_sha256.clone(),
        deadline_receipt_sha256,
        media_history_policy_version: Some(MediaHistoryPolicyReceiptV1::POLICY_VERSION.to_owned()),
        media_history_policy_sha256: Some(media_history_policy_sha256),
    }))?;

    let known_tools = tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<BTreeSet<_>>();
    let mutating_tools = contract
        .effective()
        .ordered_tools()
        .iter()
        .filter(|tool| tool.effect_class == EffectClass::Mutating)
        .map(|tool| tool.provider_name.as_str())
        .collect::<BTreeSet<_>>();
    let mut state = RunState::new(writer, spec, run_spec_sha256, mode.into_emission());
    let phase_split_enabled = deadline.is_some();
    let mut final_send_started = false;
    let mut phase = if phase_split_enabled {
        initial_provider_phase_at(Instant::now(), actor_done, last_send, minimum_send_window)
    } else {
        ProviderPhase::ActionOpen
    };
    let mut completion_challenge = CompletionChallengeState::default();
    let mut runtime_budget_notice_issued = false;
    let mut call_limit_recovery_used = false;

    loop {
        if cancellation.is_cancelled() {
            return state.finalize_once(TerminalOutcome::failure(
                TerminalStatus::Cancelled,
                TerminalPhase::Cancellation,
                "cooperative_cancelled",
            ));
        }
        if state.provider_turn_count >= spec.provider.max_turns {
            if let Some(text) = completion_challenge.take_safe_fallback() {
                return finalize_with_text(&mut state, text);
            }
            return state.finalize_once(TerminalOutcome::failure(
                TerminalStatus::ProviderFailure,
                TerminalPhase::Provider,
                "provider_max_turns_exceeded",
            ));
        }
        if phase != ProviderPhase::ActionOpen
            && let Some(text) = completion_challenge.take_safe_fallback()
        {
            return finalize_with_text(&mut state, text);
        }
        if phase == ProviderPhase::ActionOpen {
            if phase_split_enabled {
                let now = Instant::now();
                phase = if state.provider_turn_count == 0 {
                    initial_provider_phase_at(now, actor_done, last_send, minimum_send_window)
                } else {
                    provider_phase_at(
                        now,
                        actor_done,
                        last_send,
                        minimum_send_window,
                        final_send_started,
                    )
                };
                if phase != ProviderPhase::ActionOpen
                    && let Some(text) = completion_challenge.take_safe_fallback()
                {
                    return finalize_with_text(&mut state, text);
                }
            } else {
                let remaining = match actor_done.checked_duration_since(Instant::now()) {
                    Some(remaining) => remaining,
                    None => {
                        if let Some(text) = completion_challenge.take_safe_fallback() {
                            return finalize_with_text(&mut state, text);
                        }
                        return state.finalize_once(TerminalOutcome::failure(
                            TerminalStatus::DeadlineFailure,
                            TerminalPhase::Deadline,
                            "provider_action_deadline_exceeded",
                        ));
                    }
                };
                if remaining < minimum_send_window {
                    if let Some(text) = completion_challenge.take_safe_fallback() {
                        return finalize_with_text(&mut state, text);
                    }
                    return state.finalize_once(TerminalOutcome::failure(
                        TerminalStatus::DeadlineFailure,
                        TerminalPhase::Deadline,
                        "provider_send_window_exhausted",
                    ));
                }
            }
        }
        let review_request_active = completion_challenge.phase != CompletionReviewPhase::NotIssued;
        let action_provider_deadline = if review_request_active {
            completion_review_provider_deadline(Instant::now(), actor_done)
        } else {
            actor_done
        };
        let (request_mode, request_tools, provider_deadline, timeout_code) = match phase {
            ProviderPhase::ActionOpen => (
                ProviderRequestMode::ActionOpen,
                tools.as_slice(),
                action_provider_deadline,
                if review_request_active {
                    "provider_completion_review_deadline_exceeded"
                } else {
                    "provider_action_deadline_exceeded"
                },
            ),
            ProviderPhase::FinalOnly => {
                if Instant::now() >= last_send {
                    return state.finalize_once(TerminalOutcome::failure(
                        TerminalStatus::DeadlineFailure,
                        TerminalPhase::Deadline,
                        "provider_final_deadline_exceeded",
                    ));
                }
                final_send_started = true;
                (
                    ProviderRequestMode::FinalOnly,
                    tools.as_slice(),
                    last_send,
                    "provider_final_deadline_exceeded",
                )
            }
            ProviderPhase::SettlingAccepted => {
                return Err(AgentRunError::Incomplete {
                    code: "provider_phase_settlement_leaked",
                });
            }
            ProviderPhase::TerminalCommit => {
                return state.finalize_once(TerminalOutcome::failure(
                    TerminalStatus::ProviderFailure,
                    TerminalPhase::Provider,
                    "provider_final_response_missing",
                ));
            }
        };
        if !runtime_budget_notice_issued
            && request_mode == ProviderRequestMode::ActionOpen
            && let Some(deadline) = deadline
            && let Some(notice) =
                runtime_budget_notice(deadline, profile.tools.terminal_max_timeout_ms)
        {
            history.push(HistoryItem::User { content: notice });
            media_history_receipt = match apply_media_history_policy(&mut history) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return state.finalize_once(TerminalOutcome::failure(
                        TerminalStatus::RuntimeFailure,
                        TerminalPhase::Runtime,
                        "runtime_budget_notice_history_failed",
                    ));
                }
            };
            runtime_budget_notice_issued = true;
        }
        let turn_index = state.provider_turn_count;
        if u64::try_from(history.len()).unwrap_or(u64::MAX) > profile.context.max_history_items {
            if let Some(text) = completion_challenge.take_safe_fallback() {
                return finalize_with_text(&mut state, text);
            }
            return state.finalize_once(TerminalOutcome::failure(
                TerminalStatus::ProviderFailure,
                TerminalPhase::Provider,
                "provider_history_item_limit_exceeded",
            ));
        }
        let pending = match prepare_pending_provider_request(
            provider,
            spec,
            request_tools,
            request_mode,
            turn_index,
            ProviderRequestEvidence {
                history: &history,
                media_history_receipt: &media_history_receipt,
                budget_observation: provider_budget_observation(
                    deadline,
                    match request_mode {
                        ProviderRequestMode::ActionOpen => ProviderBudgetPhaseV1::ActionOpen,
                        ProviderRequestMode::FinalOnly => ProviderBudgetPhaseV1::FinalOnly,
                    },
                    runtime_budget_notice_issued,
                ),
            },
        ) {
            Ok(pending) => pending,
            Err(failure) => {
                if let Some(outcome) = finalize_provisional(&mut state, &mut completion_challenge) {
                    return outcome;
                }
                return state.finalize_once(TerminalOutcome::failure(
                    TerminalStatus::ProviderFailure,
                    TerminalPhase::Provider,
                    failure.code(),
                ));
            }
        };
        if let Err(error) =
            state.append_operational(EventBody::ProviderRequested(pending.projection))
        {
            return state.finalize_once(TerminalOutcome::failure(
                TerminalStatus::RuntimeFailure,
                TerminalPhase::Artifact,
                error.code(),
            ));
        }
        state.provider_requested();
        let provider_result = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return state.finalize_once(TerminalOutcome::failure(
                    TerminalStatus::Cancelled,
                    TerminalPhase::Cancellation,
                    "cooperative_cancelled",
                ));
            }
            result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(provider_deadline),
                provider.send(pending.prepared),
            ) => result,
        };
        let send_telemetry = provider.send_telemetry();
        let completed = match provider_result {
            Ok(Ok(completed)) => completed,
            Ok(Err(failure)) => {
                state.provider_failed(None);
                return record_provider_failure(
                    &mut state,
                    turn_index,
                    failure,
                    &send_telemetry,
                    ProviderRejectedResponse::default(),
                );
            }
            Err(_) => {
                return state.finalize_once(TerminalOutcome::failure(
                    TerminalStatus::DeadlineFailure,
                    TerminalPhase::Deadline,
                    timeout_code,
                ));
            }
        };
        if let Err(failure) = completed.validate_authoritative(
            &spec.provider.model,
            &known_tools,
            profile.scheduler.max_function_calls_per_response,
            profile.transport.max_function_arguments_bytes,
        ) {
            let rejected = if failure.code() == "provider_call_limit_exceeded" {
                ProviderRejectedResponse {
                    call_count: Some(
                        u64::try_from(completed.function_calls().count()).unwrap_or(u64::MAX),
                    ),
                    usage: completed.usage.clone(),
                }
            } else {
                ProviderRejectedResponse {
                    call_count: None,
                    usage: completed.usage.clone(),
                }
            };
            state.provider_failed(rejected.usage.as_ref());
            if failure.code() == "provider_call_limit_exceeded"
                && request_mode == ProviderRequestMode::ActionOpen
                && !call_limit_recovery_used
                && completion_challenge.provisional_final.is_none()
            {
                if let Err(error) = append_provider_failure_event(
                    &mut state,
                    turn_index,
                    failure.code(),
                    &send_telemetry,
                    &rejected,
                ) {
                    return state.finalize_once(TerminalOutcome::failure(
                        TerminalStatus::RuntimeFailure,
                        TerminalPhase::Artifact,
                        error.code(),
                    ));
                }
                let run_remaining = profile
                    .scheduler
                    .max_function_calls_per_run
                    .saturating_sub(state.tool_call_count);
                history.push(HistoryItem::User {
                    content: call_limit_recovery_notice(
                        failure.code(),
                        rejected.call_count.unwrap_or(u64::MAX),
                        profile
                            .scheduler
                            .max_function_calls_per_response
                            .min(run_remaining),
                    ),
                });
                media_history_receipt = match apply_media_history_policy(&mut history) {
                    Ok(receipt) => receipt,
                    Err(_) => {
                        return state.finalize_once(TerminalOutcome::failure(
                            TerminalStatus::RuntimeFailure,
                            TerminalPhase::Runtime,
                            CALL_LIMIT_RECOVERY_HISTORY_CODE,
                        ));
                    }
                };
                call_limit_recovery_used = true;
                continue;
            }
            if let Some(text) = completion_challenge.take_safe_fallback() {
                return record_provider_failure_with_final(
                    &mut state,
                    turn_index,
                    failure,
                    &send_telemetry,
                    text,
                    rejected,
                );
            }
            return record_provider_failure(
                &mut state,
                turn_index,
                failure,
                &send_telemetry,
                rejected,
            );
        }
        let calls = completed.function_calls().collect::<Vec<_>>();
        if request_mode == ProviderRequestMode::ActionOpen {
            let projected_total = state
                .tool_call_count
                .saturating_add(u64::try_from(calls.len()).unwrap_or(u64::MAX));
            if projected_total > profile.scheduler.max_function_calls_per_run {
                let rejected = ProviderRejectedResponse {
                    call_count: Some(u64::try_from(calls.len()).unwrap_or(u64::MAX)),
                    usage: completed.usage.clone(),
                };
                state.provider_failed(rejected.usage.as_ref());
                if !call_limit_recovery_used && completion_challenge.provisional_final.is_none() {
                    if let Err(error) = append_provider_failure_event(
                        &mut state,
                        turn_index,
                        "provider_run_call_limit_exceeded",
                        &send_telemetry,
                        &rejected,
                    ) {
                        return state.finalize_once(TerminalOutcome::failure(
                            TerminalStatus::RuntimeFailure,
                            TerminalPhase::Artifact,
                            error.code(),
                        ));
                    }
                    let run_remaining = profile
                        .scheduler
                        .max_function_calls_per_run
                        .saturating_sub(state.tool_call_count);
                    history.push(HistoryItem::User {
                        content: call_limit_recovery_notice(
                            "provider_run_call_limit_exceeded",
                            rejected.call_count.unwrap_or(u64::MAX),
                            profile
                                .scheduler
                                .max_function_calls_per_response
                                .min(run_remaining),
                        ),
                    });
                    media_history_receipt = match apply_media_history_policy(&mut history) {
                        Ok(receipt) => receipt,
                        Err(_) => {
                            return state.finalize_once(TerminalOutcome::failure(
                                TerminalStatus::RuntimeFailure,
                                TerminalPhase::Runtime,
                                CALL_LIMIT_RECOVERY_HISTORY_CODE,
                            ));
                        }
                    };
                    call_limit_recovery_used = true;
                    continue;
                }
                if let Some(text) = completion_challenge.take_safe_fallback() {
                    return record_provider_failure_with_final(
                        &mut state,
                        turn_index,
                        ProviderFailure::new("provider_run_call_limit_exceeded"),
                        &send_telemetry,
                        text,
                        rejected,
                    );
                }
                return record_provider_failure(
                    &mut state,
                    turn_index,
                    ProviderFailure::new("provider_run_call_limit_exceeded"),
                    &send_telemetry,
                    rejected,
                );
            }
        }
        let final_text = completed.final_text().map(str::to_owned);
        state.provider_completed(completed.usage.as_ref());
        if let Err(error) =
            state.append_operational(EventBody::ProviderCompleted(ProviderCompleted {
                turn_index,
                response_id: completed.response_id.clone(),
                model: completed.model.clone(),
                call_ids: calls.iter().map(|call| call.call_id.clone()).collect(),
                has_final_text: final_text.is_some(),
                usage: completed.usage.clone(),
                attempt_count: Some(send_telemetry.attempt_count),
                retry_code: send_telemetry.retry_code.clone(),
                retry_stage: send_telemetry.retry_stage.clone(),
            }))
        {
            return state.finalize_once(TerminalOutcome::failure(
                TerminalStatus::RuntimeFailure,
                TerminalPhase::Artifact,
                error.code(),
            ));
        }
        if request_mode == ProviderRequestMode::FinalOnly {
            phase = ProviderPhase::TerminalCommit;
            debug_assert_eq!(phase, ProviderPhase::TerminalCommit);
            if !calls.is_empty() {
                return state.finalize_once(TerminalOutcome::failure(
                    TerminalStatus::ProviderFailure,
                    TerminalPhase::Provider,
                    "provider_final_only_tool_call",
                ));
            }
            completed.append_output_to(&mut history);
            if let Some(text) = final_text.filter(|text| !text.is_empty()) {
                return finalize_with_text(&mut state, text);
            }
            return state.finalize_once(TerminalOutcome::failure(
                TerminalStatus::ProviderFailure,
                TerminalPhase::Provider,
                "provider_final_output_missing",
            ));
        }
        completed.append_output_to(&mut history);

        if calls.is_empty() {
            if let Some(text) = final_text.filter(|text| !text.is_empty()) {
                if phase_split_enabled
                    && completion_challenge.phase == CompletionReviewPhase::NotIssued
                    && completion_review_policy.has_capacity(CompletionReviewCapacity {
                        now: Instant::now(),
                        last_send,
                        provider_turn_count: state.provider_turn_count,
                        max_provider_turns: spec.provider.max_turns,
                        history_items: history.len(),
                        max_history_items: profile.context.max_history_items,
                    })
                {
                    let terminal_evidence = recent_terminal_evidence(&history);
                    completion_challenge.issue(text.clone());
                    if completion_review_policy.uses_fresh_context() {
                        let Some(mut critic_history) = completion_review_policy.fresh_context(
                            &spec.task.instruction,
                            &text,
                            &terminal_evidence,
                            &state.completion_evidence,
                        ) else {
                            return state.finalize_once(TerminalOutcome::failure(
                                TerminalStatus::RuntimeFailure,
                                TerminalPhase::Runtime,
                                "completion_review_policy_inconsistent",
                            ));
                        };
                        let critic_receipt = match apply_media_history_policy(&mut critic_history) {
                            Ok(receipt) => receipt,
                            Err(_) => {
                                return finalize_with_text(&mut state, text);
                            }
                        };
                        let Some(deadline) = deadline else {
                            return state.finalize_once(TerminalOutcome::failure(
                                TerminalStatus::RuntimeFailure,
                                TerminalPhase::Runtime,
                                "completion_review_deadline_missing",
                            ));
                        };
                        let resolution = run_fresh_completion_critic(
                            &mut state,
                            provider,
                            FreshCriticRequest {
                                spec,
                                deadline,
                                cancellation,
                                history: critic_history,
                                media_history_receipt: critic_receipt,
                                candidate_final: text,
                                max_arguments_bytes: profile.transport.max_function_arguments_bytes,
                            },
                        )
                        .await?;
                        let advice = match resolution {
                            FreshCriticResolution::Advice(advice) => advice,
                            FreshCriticResolution::Terminal(outcome) => return Ok(*outcome),
                        };
                        let Some(challenge) = completion_review_policy.actor_prompt(&advice) else {
                            return state.finalize_once(TerminalOutcome::failure(
                                TerminalStatus::RuntimeFailure,
                                TerminalPhase::Runtime,
                                "completion_review_policy_inconsistent",
                            ));
                        };
                        history.push(HistoryItem::User { content: challenge });
                        media_history_receipt = match apply_media_history_policy(&mut history) {
                            Ok(receipt) => receipt,
                            Err(_) => {
                                if let Some(text) = completion_challenge.take_safe_fallback() {
                                    return finalize_with_text(&mut state, text);
                                }
                                return state.finalize_once(TerminalOutcome::failure(
                                    TerminalStatus::RuntimeFailure,
                                    TerminalPhase::Runtime,
                                    "completion_challenge_state_missing",
                                ));
                            }
                        };
                        continue;
                    }
                    let Some(challenge) = completion_review_policy.prompt(
                        &spec.task.instruction,
                        &text,
                        &terminal_evidence,
                        &state.completion_evidence,
                    ) else {
                        return state.finalize_once(TerminalOutcome::failure(
                            TerminalStatus::RuntimeFailure,
                            TerminalPhase::Runtime,
                            "completion_review_policy_inconsistent",
                        ));
                    };
                    history.push(HistoryItem::User { content: challenge });
                    media_history_receipt = match apply_media_history_policy(&mut history) {
                        Ok(receipt) => receipt,
                        Err(_) => {
                            if let Some(text) = completion_challenge.take_safe_fallback() {
                                return finalize_with_text(&mut state, text);
                            }
                            return state.finalize_once(TerminalOutcome::failure(
                                TerminalStatus::RuntimeFailure,
                                TerminalPhase::Runtime,
                                "completion_challenge_state_missing",
                            ));
                        }
                    };
                    continue;
                }
                return finalize_with_text(&mut state, text);
            }
            if let Some(text) = completion_challenge.take_safe_fallback() {
                return finalize_with_text(&mut state, text);
            }
            return state.finalize_once(TerminalOutcome::failure(
                TerminalStatus::ProviderFailure,
                TerminalPhase::Provider,
                "provider_output_without_action",
            ));
        }

        phase = ProviderPhase::SettlingAccepted;
        debug_assert_eq!(phase, ProviderPhase::SettlingAccepted);
        let review_was_active = completion_challenge.phase != CompletionReviewPhase::NotIssued;
        let review_tool_stage = completion_challenge.admit_tool_stage(calls.iter().map(|call| {
            if mutating_tools.contains(call.name.as_str()) {
                EffectClass::Mutating
            } else {
                EffectClass::ReadOnly
            }
        }));
        let admission_rejection = (review_was_active && review_tool_stage.is_none())
            .then_some("completion_review_phase_closed");
        let review_tool_deadline = if review_tool_stage.is_some() {
            completion_review_tool_deadline(Instant::now(), tool_settled)
        } else {
            tool_settled
        };
        let mut staging = TurnBatchStaging::new(state.tool_output_bytes);
        let mut review_stage_dispatched = false;
        let mut review_stage_mutated = false;
        for call in calls {
            state.tool_call_count = state.tool_call_count.saturating_add(1);
            let settlement = settle_tool_call(
                &mut state,
                executor,
                &known_tools,
                &call,
                ToolExecutionWindow {
                    workspace: &spec.workspace_dir,
                    dispatch_cutoff: actor_done,
                    settlement_deadline: review_tool_deadline,
                    admission_rejection,
                    cancellation,
                    runtime_deadline: deadline,
                    max_provider_turns: spec.provider.max_turns,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: profile.tools.model_tool_output_bytes_per_call,
                        per_run_bytes: profile.tools.model_tool_output_bytes_per_run,
                    },
                    projected_tool_output_bytes: staging.projected_tool_output_bytes,
                },
            )
            .await;
            match settlement {
                Ok(completion) => {
                    if completion.dispatched {
                        review_stage_dispatched |= review_tool_stage.is_some();
                        review_stage_mutated |= review_tool_stage.is_some()
                            && mutating_tools.contains(call.name.as_str());
                    }
                    staging.push(completion);
                }
                Err(outcome) => return state.finalize_once(outcome),
            }
        }
        let prepared_history = match prepare_turn_history_batch(&history, turn_index, &staging) {
            Ok(prepared) => prepared,
            Err(failure) => {
                return state.finalize_once(TerminalOutcome::failure(
                    TerminalStatus::RuntimeFailure,
                    TerminalPhase::Runtime,
                    failure.code(),
                ));
            }
        };
        let history_commit_cutoff = match deadline {
            Some(deadline) => match SettlementStageCutoffsV1::derive_instants(
                deadline.instants.actor_done,
                deadline.instants.tool_settled,
                deadline.reserves.process_settlement_ms,
            ) {
                Ok(stages) => Some(stages.history_commit()),
                Err(_) => {
                    return state.finalize_once(TerminalOutcome::failure(
                        TerminalStatus::DeadlineFailure,
                        TerminalPhase::Deadline,
                        "tool_settlement_budget_invalid",
                    ));
                }
            },
            None => None,
        };
        match commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut media_history_receipt,
            prepared_history,
            staging,
            history_commit_cutoff,
        ) {
            Ok(()) => {}
            Err(CommitTurnHistoryError::Deadline(outcome)) => {
                return state.finalize_once(outcome);
            }
            Err(CommitTurnHistoryError::Writer(error)) => {
                return Err(AgentRunError::Incomplete { code: error.code() });
            }
        }
        if let Some(review_tool_stage) = review_tool_stage {
            completion_challenge.commit_tool_stage(
                review_tool_stage,
                review_stage_dispatched,
                review_stage_mutated,
            );
            if !review_stage_dispatched {
                completion_challenge.close_review();
            }
        } else if review_was_active {
            completion_challenge.close_review();
        }
        if review_tool_stage == Some(CompletionReviewToolStage::Validation)
            && review_stage_dispatched
        {
            history.push(HistoryItem::User {
                content: COMPLETION_REVIEW_DECISION_PROMPT.to_owned(),
            });
            media_history_receipt = match apply_media_history_policy(&mut history) {
                Ok(receipt) => receipt,
                Err(_) => {
                    return state.finalize_once(TerminalOutcome::failure(
                        TerminalStatus::RuntimeFailure,
                        TerminalPhase::Runtime,
                        "completion_review_decision_history_failed",
                    ));
                }
            };
        }
        phase = if completion_challenge.requires_final_only() {
            ProviderPhase::FinalOnly
        } else if phase_split_enabled {
            provider_phase_at(
                Instant::now(),
                actor_done,
                last_send,
                minimum_send_window,
                final_send_started,
            )
        } else {
            ProviderPhase::ActionOpen
        };
    }
}

fn resolve_request_tools(
    spec: &RunSpec,
    all_tools: &[FunctionTool],
) -> Result<Vec<FunctionTool>, AgentRunError> {
    let selected_names = spec
        .selected_tool_names()
        .map_err(|_| AgentRunError::configuration("run_spec_active_tools_invalid"))?;
    let selected = selected_names.into_iter().collect::<BTreeSet<_>>();
    let tools = all_tools
        .iter()
        .filter(|tool| selected.contains(tool.name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if tools.len() != selected.len() {
        return Err(AgentRunError::configuration(
            "run_spec_active_tools_contract_mismatch",
        ));
    }
    Ok(tools)
}

struct PendingProviderRequest {
    prepared: PreparedTurnRequest,
    projection: ProviderRequested,
}

struct ProviderRequestEvidence<'a> {
    history: &'a [HistoryItem],
    media_history_receipt: &'a MediaHistoryPolicyReceiptV1,
    budget_observation: Option<ProviderBudgetObservationV1>,
}

fn prepare_pending_provider_request<P: Provider>(
    provider: &P,
    spec: &RunSpec,
    tools: &[FunctionTool],
    mode: ProviderRequestMode,
    turn_index: u64,
    evidence: ProviderRequestEvidence<'_>,
) -> Result<PendingProviderRequest, ProviderFailure> {
    let ProviderRequestEvidence {
        history,
        media_history_receipt: receipt,
        budget_observation,
    } = evidence;
    let prepared = provider.preflight(TurnRequest {
        turn_index,
        model: spec.provider.model.clone(),
        history: history.to_vec(),
        tools: tools.to_vec(),
        mode,
        media_history_receipt: Some(receipt.clone()),
    })?;
    Ok(PendingProviderRequest {
        prepared,
        projection: ProviderRequested {
            turn_index,
            history_item_count: u64::try_from(history.len()).unwrap_or(u64::MAX),
            tool_count: u64::try_from(tools.len()).unwrap_or(u64::MAX),
            function_output_call_ids: history
                .iter()
                .filter_map(|item| match item {
                    HistoryItem::FunctionCallOutput { call_id, .. } => Some(call_id.clone()),
                    _ => None,
                })
                .collect(),
            media_history_receipt: Some(MediaHistoryRequestReceiptV1 {
                history_sha256: receipt.history_sha256().to_owned(),
                retained_count: receipt.retained_count(),
                retained_bytes: receipt.retained_bytes(),
                evicted_total: receipt.evicted_total(),
            }),
            budget_observation,
        },
    })
}

enum FreshCriticResolution {
    Advice(String),
    Terminal(Box<AgentRunOutcome>),
}

fn fresh_critic_terminal(outcome: AgentRunOutcome) -> FreshCriticResolution {
    FreshCriticResolution::Terminal(Box::new(outcome))
}

struct FreshCriticRequest<'a> {
    spec: &'a RunSpec,
    deadline: &'a DeadlineContext,
    cancellation: &'a RunCancellation,
    history: Vec<HistoryItem>,
    media_history_receipt: MediaHistoryPolicyReceiptV1,
    candidate_final: String,
    max_arguments_bytes: u64,
}

async fn run_fresh_completion_critic<P: Provider>(
    state: &mut RunState<'_>,
    provider: &mut P,
    request: FreshCriticRequest<'_>,
) -> Result<FreshCriticResolution, AgentRunError> {
    let FreshCriticRequest {
        spec,
        deadline,
        cancellation,
        history,
        media_history_receipt,
        candidate_final,
        max_arguments_bytes,
    } = request;
    let turn_index = state.provider_turn_count;
    let pending = match prepare_pending_provider_request(
        provider,
        spec,
        &[],
        ProviderRequestMode::FinalOnly,
        turn_index,
        ProviderRequestEvidence {
            history: &history,
            media_history_receipt: &media_history_receipt,
            budget_observation: provider_budget_observation(
                Some(deadline),
                ProviderBudgetPhaseV1::CompletionCritic,
                false,
            ),
        },
    ) {
        Ok(pending) => pending,
        Err(_) => {
            return finalize_with_text(state, candidate_final).map(fresh_critic_terminal);
        }
    };
    if let Err(error) = state.append_operational(EventBody::ProviderRequested(pending.projection)) {
        return state
            .finalize_once(TerminalOutcome::failure(
                TerminalStatus::RuntimeFailure,
                TerminalPhase::Artifact,
                error.code(),
            ))
            .map(fresh_critic_terminal);
    }
    state.provider_requested();
    let provider_result = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            return state
                .finalize_once(TerminalOutcome::failure(
                    TerminalStatus::Cancelled,
                    TerminalPhase::Cancellation,
                    "cooperative_cancelled",
                ))
                .map(fresh_critic_terminal);
        }
        result = tokio::time::timeout_at(
            tokio::time::Instant::from_std(completion_review_provider_deadline(
                Instant::now(),
                deadline.instants.actor_done,
            )),
            provider.send(pending.prepared),
        ) => result,
    };
    let send_telemetry = provider.send_telemetry();
    let completed = match provider_result {
        Ok(Ok(completed)) => completed,
        Ok(Err(failure)) => {
            state.provider_failed(None);
            return record_provider_failure(
                state,
                turn_index,
                failure,
                &send_telemetry,
                ProviderRejectedResponse::default(),
            )
            .map(fresh_critic_terminal);
        }
        Err(_) => {
            return state
                .finalize_once(TerminalOutcome::failure(
                    TerminalStatus::DeadlineFailure,
                    TerminalPhase::Deadline,
                    "provider_completion_critic_deadline_exceeded",
                ))
                .map(fresh_critic_terminal);
        }
    };
    let no_tools = BTreeSet::new();
    if let Err(failure) =
        completed.validate_authoritative(&spec.provider.model, &no_tools, 0, max_arguments_bytes)
    {
        let call_count = (failure.code() == "provider_call_limit_exceeded")
            .then(|| u64::try_from(completed.function_calls().count()).unwrap_or(u64::MAX));
        let rejected = ProviderRejectedResponse {
            call_count,
            usage: completed.usage.clone(),
        };
        state.provider_failed(rejected.usage.as_ref());
        return record_provider_failure_with_final(
            state,
            turn_index,
            failure,
            &send_telemetry,
            candidate_final,
            rejected,
        )
        .map(fresh_critic_terminal);
    }
    let calls = completed.function_calls().collect::<Vec<_>>();
    debug_assert!(calls.is_empty());
    let advice = completed
        .final_text()
        .filter(|text| !text.is_empty())
        .map(str::to_owned);
    state.provider_completed(completed.usage.as_ref());
    if let Err(error) = state.append_operational(EventBody::ProviderCompleted(ProviderCompleted {
        turn_index,
        response_id: completed.response_id,
        model: completed.model,
        call_ids: Vec::new(),
        has_final_text: advice.is_some(),
        usage: completed.usage,
        attempt_count: Some(send_telemetry.attempt_count),
        retry_code: send_telemetry.retry_code,
        retry_stage: send_telemetry.retry_stage,
    })) {
        return state
            .finalize_once(TerminalOutcome::failure(
                TerminalStatus::RuntimeFailure,
                TerminalPhase::Artifact,
                error.code(),
            ))
            .map(fresh_critic_terminal);
    }
    match advice {
        Some(advice) => Ok(FreshCriticResolution::Advice(advice)),
        None => finalize_with_text(state, candidate_final).map(fresh_critic_terminal),
    }
}

#[derive(Debug)]
struct StagedToolCompletion {
    event: ToolCompletedEvent,
    arguments_json: String,
    dispatched: bool,
    history_output: HistoryItem,
    attachment: Option<HistoryItem>,
    committed_output_bytes: u64,
    tool_receipt: Option<ToolReceiptV1>,
    tool_receipt_omitted: bool,
}

#[derive(Debug)]
struct TurnBatchStaging {
    completions: Vec<StagedToolCompletion>,
    projected_tool_output_bytes: u64,
}

impl TurnBatchStaging {
    fn new(committed_tool_output_bytes: u64) -> Self {
        Self {
            completions: Vec::new(),
            projected_tool_output_bytes: committed_tool_output_bytes,
        }
    }

    fn push(&mut self, completion: StagedToolCompletion) {
        self.projected_tool_output_bytes = self
            .projected_tool_output_bytes
            .saturating_add(completion.committed_output_bytes);
        self.completions.push(completion);
    }
}

#[derive(Debug)]
struct PreparedTurnHistoryBatch {
    history: Vec<HistoryItem>,
    receipt: MediaHistoryPolicyReceiptV1,
}

fn prepare_turn_history_batch(
    history: &[HistoryItem],
    turn_index: u64,
    staging: &TurnBatchStaging,
) -> Result<PreparedTurnHistoryBatch, ProviderFailure> {
    let call_ids = staging
        .completions
        .iter()
        .map(|completion| completion.event.call_id.clone())
        .collect::<Vec<_>>();
    let mut additions = staging
        .completions
        .iter()
        .map(|completion| completion.history_output.clone())
        .collect::<Vec<_>>();
    additions.extend(
        staging
            .completions
            .iter()
            .filter_map(|completion| completion.attachment.clone()),
    );
    let prepared: PreparedMediaHistoryBatch =
        prepare_media_history_batch(history, turn_index, &call_ids, additions)?;
    let (history, receipt) = prepared.into_parts();
    Ok(PreparedTurnHistoryBatch { history, receipt })
}

#[derive(Debug)]
enum CommitTurnHistoryError {
    Deadline(TerminalOutcome),
    Writer(EventWriteError),
}

fn commit_turn_history_batch(
    state: &mut RunState<'_>,
    history: &mut Vec<HistoryItem>,
    media_history_receipt: &mut MediaHistoryPolicyReceiptV1,
    prepared: PreparedTurnHistoryBatch,
    staging: TurnBatchStaging,
    cutoff: Option<Instant>,
) -> Result<(), CommitTurnHistoryError> {
    ensure_history_commit_window(cutoff).map_err(CommitTurnHistoryError::Deadline)?;
    for completion in &staging.completions {
        state
            .append_operational(EventBody::ToolCompleted(completion.event.clone()))
            .map_err(CommitTurnHistoryError::Writer)?;
    }
    for completion in &staging.completions {
        state
            .completion_evidence
            .observe(&completion.event, &completion.arguments_json);
    }
    for completion in staging.completions {
        if completion.tool_receipt_omitted {
            state.record_tool_receipt_omissions(1);
        }
        if let Some(telemetry) = completion.tool_receipt {
            state.stage_tool_receipt(telemetry);
        }
    }
    *history = prepared.history;
    *media_history_receipt = prepared.receipt;
    state.tool_output_bytes = staging.projected_tool_output_bytes;
    Ok(())
}

async fn settle_tool_call<T: ToolExecutor>(
    state: &mut RunState<'_>,
    executor: &mut T,
    known_tools: &BTreeSet<&str>,
    call: &FunctionCall,
    window: ToolExecutionWindow<'_>,
) -> Result<StagedToolCompletion, TerminalOutcome> {
    let mut dispatched = false;
    let registration_now = Instant::now();
    let dispatch_open_at_registration =
        tool_dispatch_open_at(registration_now, window.dispatch_cutoff);
    state
        .append_operational(EventBody::ToolRegistered(ToolRegistered {
            call_id: call.call_id.clone(),
            provider_name: call.name.clone(),
            known: known_tools.contains(call.name.as_str()),
            arguments_json: call.arguments_json.clone(),
            budget_observation: tool_budget_observation(
                window.runtime_deadline,
                registration_now,
                dispatch_open_at_registration,
            ),
        }))
        .map_err(|error| {
            TerminalOutcome::failure(
                TerminalStatus::RuntimeFailure,
                TerminalPhase::Artifact,
                error.code(),
            )
        })?;
    if match_protected_target(&call.name, &call.arguments_json).is_some() {
        return Err(record_tool_failure(
            state,
            call,
            PROTECTED_HARNESS_MATERIAL_ACCESS_BLOCKED,
            ToolFailureSettlement {
                status: TerminalStatus::ToolFailure,
                phase: TerminalPhase::Tool,
                execution_may_have_started: false,
                cleanup_verified: None,
                census_verified: None,
            },
            None,
        ));
    }
    if let Some(code) = window.admission_rejection {
        return prepare_tool_completion(
            state,
            call,
            ToolResult::rejected(code),
            window.runtime_deadline,
            window.max_provider_turns,
            window.output_limits,
            window.projected_tool_output_bytes,
        );
    }
    if !dispatch_open_at_registration {
        return prepare_tool_completion(
            state,
            call,
            ToolResult::rejected("action_phase_closed"),
            window.runtime_deadline,
            window.max_provider_turns,
            window.output_limits,
            window.projected_tool_output_bytes,
        );
    }
    let result = match executor.validate(call) {
        Ok(()) => {
            if !tool_dispatch_open_at(Instant::now(), window.dispatch_cutoff) {
                ToolResult::rejected("action_phase_closed")
            } else {
                state
                    .append_operational(EventBody::ToolDispatched(ToolDispatched {
                        call_id: call.call_id.clone(),
                        provider_name: call.name.clone(),
                    }))
                    .map_err(|error| {
                        TerminalOutcome::failure(
                            TerminalStatus::RuntimeFailure,
                            TerminalPhase::Artifact,
                            error.code(),
                        )
                    })?;
                dispatched = true;
                let execution = tokio::select! {
                    biased;
                    () = window.cancellation.cancelled() => {
                        return Err(record_tool_failure(
                            state,
                            call,
                            "cooperative_cancelled",
                            ToolFailureSettlement {
                                status: TerminalStatus::Cancelled,
                                phase: TerminalPhase::Cancellation,
                                execution_may_have_started: true,
                                cleanup_verified: None,
                                census_verified: None,
                            },
                            None,
                        ));
                    }
                    result = tokio::time::timeout_at(
                        tokio::time::Instant::from_std(window.settlement_deadline),
                        executor.execute(call, window.workspace, window.settlement_deadline),
                    ) => result,
                };
                match execution {
                    Ok(Ok(result)) => result,
                    Ok(Err(error)) => {
                        let code = error.code();
                        let (status, phase) = match error.class() {
                            ToolExecutionFailureClass::Deadline => {
                                (TerminalStatus::DeadlineFailure, TerminalPhase::Deadline)
                            }
                            ToolExecutionFailureClass::Bridge
                            | ToolExecutionFailureClass::Cleanup => {
                                (TerminalStatus::ToolFailure, TerminalPhase::Bridge)
                            }
                            ToolExecutionFailureClass::Tool => {
                                (TerminalStatus::ToolFailure, TerminalPhase::Tool)
                            }
                        };
                        return Err(record_tool_failure(
                            state,
                            call,
                            code,
                            ToolFailureSettlement {
                                status,
                                phase,
                                execution_may_have_started: error.execution_may_have_started(),
                                cleanup_verified: error.cleanup_verified(),
                                census_verified: error.census_verified(),
                            },
                            error.actor_receipt().cloned(),
                        ));
                    }
                    Err(_) => {
                        return Err(record_tool_failure(
                            state,
                            call,
                            "tool_action_deadline_exceeded",
                            ToolFailureSettlement {
                                status: TerminalStatus::DeadlineFailure,
                                phase: TerminalPhase::Deadline,
                                execution_may_have_started: true,
                                cleanup_verified: None,
                                census_verified: None,
                            },
                            None,
                        ));
                    }
                }
            }
        }
        Err(rejection) => rejection,
    };
    let mut completion = prepare_tool_completion(
        state,
        call,
        result,
        window.runtime_deadline,
        window.max_provider_turns,
        window.output_limits,
        window.projected_tool_output_bytes,
    )?;
    completion.dispatched = dispatched;
    Ok(completion)
}

#[derive(Clone, Copy)]
struct ToolExecutionWindow<'a> {
    workspace: &'a std::path::Path,
    dispatch_cutoff: Instant,
    settlement_deadline: Instant,
    admission_rejection: Option<&'static str>,
    cancellation: &'a RunCancellation,
    runtime_deadline: Option<&'a DeadlineContext>,
    max_provider_turns: u64,
    output_limits: ToolOutputLimits,
    projected_tool_output_bytes: u64,
}

#[derive(Clone, Copy)]
struct ToolOutputLimits {
    per_call_bytes: u64,
    per_run_bytes: u64,
}

fn prepare_tool_completion(
    state: &RunState<'_>,
    call: &FunctionCall,
    result: ToolResult,
    runtime_deadline: Option<&DeadlineContext>,
    max_provider_turns: u64,
    output_limits: ToolOutputLimits,
    projected_tool_output_bytes: u64,
) -> Result<StagedToolCompletion, TerminalOutcome> {
    let ToolResult {
        execution_attempted,
        outcome,
        mut output,
        media,
        runtime_budget,
        actor_receipt,
    } = result;
    if let Some(deadline) = runtime_deadline {
        let wait_clamped = runtime_budget
            .as_ref()
            .is_some_and(|budget| budget.wait_clamped);
        let low_action_budget = deadline
            .instants
            .last_send
            .checked_duration_since(Instant::now())
            .is_none_or(|remaining| {
                remaining
                    < Duration::from_millis(deadline.reserves.provider_send_ms.saturating_mul(2))
            });
        if wait_clamped || low_action_budget {
            let wall_remaining_ms = deadline
                .instants
                .hard_deadline
                .checked_duration_since(Instant::now())
                .map(|remaining| u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0);
            let provider_turns_remaining =
                max_provider_turns.saturating_sub(state.provider_turn_count);
            let footer = format!(
                "[runtime_budget wall_remaining_ms={wall_remaining_ms} \
                 provider_turns_remaining={provider_turns_remaining} \
                 final_send_reserve_ms={} wait_clamped={wait_clamped}; \
                 finalize or run one bounded check]",
                deadline.reserves.provider_send_ms,
            );
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&footer);
        }
    }
    let remaining_run_bytes = output_limits
        .per_run_bytes
        .saturating_sub(projected_tool_output_bytes);
    let completion_cap = usize::try_from(output_limits.per_call_bytes.min(remaining_run_bytes))
        .unwrap_or(usize::MAX);
    output = truncate_utf8(&output, completion_cap);
    let committed_output_bytes = u64::try_from(output.len()).unwrap_or(u64::MAX);
    let attachment = media
        .map(|media| {
            (*media)
                .into_history_item(
                    call.call_id.clone(),
                    state.provider_turn_count.saturating_sub(1),
                    call.name.clone(),
                )
                .map_err(|_| {
                    TerminalOutcome::failure(
                        TerminalStatus::RuntimeFailure,
                        TerminalPhase::Runtime,
                        "runtime_media_attachment_invalid",
                    )
                })
        })
        .transpose()?;
    let event = ToolCompletedEvent {
        call_id: call.call_id.clone(),
        provider_name: call.name.clone(),
        execution_attempted,
        outcome,
        output: output.clone(),
    };
    let history_output = HistoryItem::FunctionCallOutput {
        call_id: call.call_id.clone(),
        output,
    };
    let (tool_receipt, tool_receipt_omitted) = project_tool_receipt(
        &state.record_emission,
        call,
        state.tool_call_count,
        actor_receipt,
    );
    Ok(StagedToolCompletion {
        event,
        arguments_json: call.arguments_json.clone(),
        dispatched: false,
        history_output,
        attachment,
        committed_output_bytes,
        tool_receipt,
        tool_receipt_omitted,
    })
}

fn project_tool_receipt(
    emission: &RunRecordEmission,
    call: &FunctionCall,
    tool_call_ordinal: u64,
    actor_receipt: Option<ExternalTerminalActorReceiptV1>,
) -> (Option<ToolReceiptV1>, bool) {
    let Some(actor_receipt) = actor_receipt else {
        return (None, false);
    };
    if !matches!(emission, RunRecordEmission::V3(_)) {
        return (None, false);
    }
    if actor_receipt.validate().is_err() {
        return (None, true);
    }
    let Ok(tool_identity_sha256) = tool_receipt_identity_sha256(&call.call_id, &call.name) else {
        return (None, true);
    };
    let receipt = ToolReceiptV1 {
        schema_version: TOOL_RECEIPT_V1_SCHEMA.to_owned(),
        phase: actor_receipt.phase,
        origin: actor_receipt.origin,
        primary_subtype: actor_receipt.primary_subtype,
        recovery_subtype: actor_receipt.recovery_subtype,
        receipt_digest_sha256: actor_receipt.diagnostic_digest_sha256,
        tool_identity_sha256,
        tool_call_ordinal,
    };
    if receipt.validate().is_err() {
        (None, true)
    } else {
        (Some(receipt), false)
    }
}

fn ensure_history_commit_window(deadline: Option<Instant>) -> Result<(), TerminalOutcome> {
    if deadline.is_some_and(|cutoff| Instant::now() >= cutoff) {
        Err(TerminalOutcome::failure(
            TerminalStatus::DeadlineFailure,
            TerminalPhase::Deadline,
            "tool_history_commit_deadline_exceeded",
        ))
    } else {
        Ok(())
    }
}

fn record_tool_failure(
    state: &mut RunState<'_>,
    call: &FunctionCall,
    code: &'static str,
    settlement: ToolFailureSettlement,
    actor_receipt: Option<ExternalTerminalActorReceiptV1>,
) -> TerminalOutcome {
    let diagnostic = EventBody::ToolFailed(ToolFailed {
        call_id: call.call_id.clone(),
        provider_name: call.name.clone(),
        code: code.to_owned(),
        execution_may_have_started: settlement.execution_may_have_started,
        cleanup_verified: settlement.cleanup_verified,
        census_verified: settlement.census_verified,
        recoverability: ToolFailureRecoverability::Fatal,
    });
    match state.writer.append_diagnostic_failure(diagnostic) {
        Ok(_) => {
            let (telemetry, omitted) = project_tool_receipt(
                &state.record_emission,
                call,
                state.tool_call_count,
                actor_receipt,
            );
            if omitted {
                state.record_tool_receipt_omissions(1);
            }
            if let Some(telemetry) = telemetry {
                state.stage_tool_receipt(telemetry);
            }
            TerminalOutcome::failure(settlement.status, settlement.phase, code)
        }
        Err(_) => TerminalOutcome::failure(
            TerminalStatus::RuntimeFailure,
            TerminalPhase::Artifact,
            "tool_failure_diagnostic_dropped",
        ),
    }
}

struct ToolFailureSettlement {
    status: TerminalStatus,
    phase: TerminalPhase,
    execution_may_have_started: bool,
    cleanup_verified: Option<bool>,
    census_verified: Option<bool>,
}

#[derive(Debug, Default)]
struct ProviderRejectedResponse {
    call_count: Option<u64>,
    usage: Option<serde_json::Value>,
}

fn call_limit_recovery_notice(code: &str, rejected_call_count: u64, allowed_calls: u64) -> String {
    format!(
        "The previous response was rejected atomically ({code}): it proposed \
         {rejected_call_count} tool calls, and none were executed. The workspace is \
         unchanged. Continue once from the current state. In your next response, issue at \
         most {allowed_calls} tool calls; if no call is necessary or allowed, give the best \
         grounded final answer now."
    )
}

fn append_provider_failure_event(
    state: &mut RunState<'_>,
    turn_index: u64,
    code: &str,
    telemetry: &ProviderSendTelemetry,
    rejected: &ProviderRejectedResponse,
) -> Result<(), EventWriteError> {
    state.append_operational(EventBody::ProviderFailed(ProviderFailed {
        turn_index,
        code: code.to_owned(),
        rejected_call_count: rejected.call_count,
        response_usage: rejected.usage.clone(),
        attempt_count: Some(telemetry.attempt_count),
        retry_code: telemetry.retry_code.clone(),
        retry_stage: telemetry.retry_stage.clone(),
    }))?;
    Ok(())
}

fn record_provider_failure(
    state: &mut RunState<'_>,
    turn_index: u64,
    failure: ProviderFailure,
    telemetry: &ProviderSendTelemetry,
    rejected: ProviderRejectedResponse,
) -> Result<AgentRunOutcome, AgentRunError> {
    let code = failure.code().to_owned();
    if let Err(error) =
        append_provider_failure_event(state, turn_index, &code, telemetry, &rejected)
    {
        return state.finalize_once(TerminalOutcome::failure(
            TerminalStatus::RuntimeFailure,
            TerminalPhase::Artifact,
            error.code(),
        ));
    }
    state.finalize_once(TerminalOutcome::failure(
        TerminalStatus::ProviderFailure,
        TerminalPhase::Provider,
        code,
    ))
}

fn record_provider_failure_with_final(
    state: &mut RunState<'_>,
    turn_index: u64,
    failure: ProviderFailure,
    telemetry: &ProviderSendTelemetry,
    text: String,
    rejected: ProviderRejectedResponse,
) -> Result<AgentRunOutcome, AgentRunError> {
    let code = failure.code().to_owned();
    if let Err(error) =
        append_provider_failure_event(state, turn_index, &code, telemetry, &rejected)
    {
        return state.finalize_once(TerminalOutcome::failure(
            TerminalStatus::RuntimeFailure,
            TerminalPhase::Artifact,
            error.code(),
        ));
    }
    finalize_with_text(state, text)
}

fn finalize_with_text(
    state: &mut RunState<'_>,
    text: String,
) -> Result<AgentRunOutcome, AgentRunError> {
    if let Err(error) = state.append_operational(EventBody::AssistantFinal(AssistantFinal { text }))
    {
        return state.finalize_once(TerminalOutcome::failure(
            TerminalStatus::RuntimeFailure,
            TerminalPhase::Artifact,
            error.code(),
        ));
    }
    state.finalize_once(TerminalOutcome::success())
}

fn finalize_provisional(
    state: &mut RunState<'_>,
    completion_challenge: &mut CompletionChallengeState,
) -> Option<Result<AgentRunOutcome, AgentRunError>> {
    completion_challenge
        .take_safe_fallback()
        .map(|text| finalize_with_text(state, text))
}

#[derive(Debug, Clone)]
struct TerminalOutcome {
    status: TerminalStatus,
    phase: Option<TerminalPhase>,
    code: String,
}

impl TerminalOutcome {
    fn success() -> Self {
        Self {
            status: TerminalStatus::Success,
            phase: None,
            code: "completed".to_owned(),
        }
    }

    fn failure(status: TerminalStatus, phase: TerminalPhase, code: impl Into<String>) -> Self {
        Self {
            status,
            phase: Some(phase),
            code: code.into(),
        }
    }
}

#[derive(Debug, Clone)]
struct FinalizedRun {
    outcome: AgentRunOutcome,
    success: bool,
}

struct RunState<'a> {
    writer: EventWriter,
    spec: &'a RunSpec,
    run_spec_sha256: String,
    record_emission: RunRecordEmission,
    provider_turn_count: u64,
    tool_call_count: u64,
    tool_output_bytes: u64,
    completion_evidence: CompletionEvidenceLedger,
    staged_tool_receipts: Vec<ToolReceiptV1>,
    staged_tool_receipt_bytes: usize,
    usage: UsageAccumulator,
    finalized: Option<FinalizedRun>,
}

impl<'a> RunState<'a> {
    fn new(
        writer: EventWriter,
        spec: &'a RunSpec,
        run_spec_sha256: String,
        record_emission: RunRecordEmission,
    ) -> Self {
        Self {
            writer,
            spec,
            run_spec_sha256,
            record_emission,
            provider_turn_count: 0,
            tool_call_count: 0,
            tool_output_bytes: 0,
            completion_evidence: CompletionEvidenceLedger::default(),
            staged_tool_receipts: Vec::new(),
            staged_tool_receipt_bytes: 0,
            usage: UsageAccumulator::default(),
            finalized: None,
        }
    }

    fn append_operational(&mut self, body: EventBody) -> Result<(), EventWriteError> {
        self.writer.append_operational(body).map(|_| ())
    }

    fn record_tool_receipt_omissions(&mut self, count: u64) {
        self.writer.record_tool_receipt_omissions(count);
    }

    fn stage_tool_receipt(&mut self, telemetry: ToolReceiptV1) {
        let Ok(encoded) = serde_json::to_vec(&telemetry) else {
            self.record_tool_receipt_omissions(1);
            return;
        };
        let Some(projected_bytes) = self.staged_tool_receipt_bytes.checked_add(encoded.len())
        else {
            self.record_tool_receipt_omissions(1);
            return;
        };
        if self.staged_tool_receipts.len() >= MAX_STAGED_TOOL_RECEIPT_SAMPLES
            || projected_bytes > MAX_STAGED_TOOL_RECEIPT_BYTES
        {
            self.record_tool_receipt_omissions(1);
            return;
        }
        self.staged_tool_receipt_bytes = projected_bytes;
        self.staged_tool_receipts.push(telemetry);
    }

    fn flush_staged_tool_receipts(&mut self) -> Result<(), EventWriteError> {
        let staged = std::mem::take(&mut self.staged_tool_receipts);
        self.staged_tool_receipt_bytes = 0;
        let mut remaining = u64::try_from(staged.len()).unwrap_or(u64::MAX);
        for telemetry in staged {
            match self.writer.append_tool_receipt(telemetry) {
                Ok(_) => {
                    remaining = remaining.saturating_sub(1);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn provider_requested(&mut self) {
        self.provider_turn_count = self.provider_turn_count.saturating_add(1);
        self.usage.requested = self.usage.requested.saturating_add(1);
    }

    fn provider_failed(&mut self, response_usage: Option<&serde_json::Value>) {
        self.usage.observe_failed(response_usage);
    }

    fn provider_completed(&mut self, usage: Option<&serde_json::Value>) {
        self.usage.observe_completed(usage);
    }

    fn finalize_once(
        &mut self,
        terminal_outcome: TerminalOutcome,
    ) -> Result<AgentRunOutcome, AgentRunError> {
        if let Some(finalized) = &self.finalized {
            return if finalized.success {
                Ok(finalized.outcome.clone())
            } else {
                Err(AgentRunError::TerminalFailure {
                    code: finalized.outcome.record.terminal_code.clone(),
                    publication: finalized.outcome.publication,
                })
            };
        }
        self.flush_staged_tool_receipts()
            .map_err(AgentRunError::from)?;
        let terminal = if terminal_outcome.status == TerminalStatus::Success {
            self.writer
                .append_terminal(EventBody::RunCompleted(RunCompleted {
                    code: terminal_outcome.code.clone(),
                    tool_receipt_omitted_count: 0,
                }))
        } else {
            self.writer.append_terminal(EventBody::RunFailed(RunFailed {
                code: terminal_outcome.code.clone(),
                tool_receipt_omitted_count: 0,
            }))
        }
        .map_err(AgentRunError::from)?;
        let (provider_call_coverage, usage_totals) = self.usage.snapshot();
        let deadline_receipt_sha256 = self
            .record_emission
            .deadline_receipt_sha256()
            .map(str::to_owned);
        let record = RunRecord {
            schema_version: RUN_RECORD_SCHEMA.to_owned(),
            run_id: self.spec.run_id.clone(),
            trial_id: self.spec.trial_id.clone(),
            attempt_id: self.spec.attempt_id.clone(),
            run_spec_sha256: self.run_spec_sha256.clone(),
            deadline_receipt_sha256,
            contract_id: self.spec.contract.id.clone(),
            contract_set_sha256: self.spec.contract.contract_set_sha256.clone(),
            profile_id: self.spec.contract.profile_id.clone(),
            terminal_status: terminal_outcome.status,
            terminal_phase: terminal_outcome.phase,
            terminal_code: terminal_outcome.code.clone(),
            final_event_seq: terminal.seq,
            provider_turn_count: self.provider_turn_count,
            tool_call_count: self.tool_call_count,
            provider_call_coverage,
            usage_totals,
            start_elapsed_ms: 0,
            end_elapsed_ms: terminal.elapsed_ms,
            events_sha256: self.writer.events_sha256(),
        };
        record.validate().map_err(|_| AgentRunError::Incomplete {
            code: "run_record_validation_failed",
        })?;
        let terminal_record = match &self.record_emission {
            RunRecordEmission::V2 => VersionedRunRecord::V2(record.clone()),
            RunRecordEmission::V3(binding) => VersionedRunRecord::V3(
                RunRecordV3::from_v2_compatibility_view(&record, binding.receipt_sha256.clone()),
            ),
        };
        terminal_record
            .validate()
            .map_err(|_| AgentRunError::Incomplete {
                code: "run_record_validation_failed",
            })?;
        let publication = self.writer.commit_run_record(&terminal_record)?;
        let outcome = AgentRunOutcome {
            record,
            terminal_record,
            publication,
        };
        let success = terminal_outcome.status == TerminalStatus::Success;
        self.finalized = Some(FinalizedRun {
            outcome: outcome.clone(),
            success,
        });
        if success {
            Ok(outcome)
        } else {
            Err(AgentRunError::TerminalFailure {
                code: terminal_outcome.code,
                publication,
            })
        }
    }
}

#[derive(Default)]
struct UsageAccumulator {
    requested: u64,
    completed: u64,
    failed: u64,
    usage_present: u64,
    usage_absent: u64,
    cost_present: u64,
    cost_absent: u64,
    input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    provider_cost_ticks: u64,
    invalid: bool,
}

impl UsageAccumulator {
    fn observe_completed(&mut self, usage: Option<&serde_json::Value>) {
        self.completed = self.completed.saturating_add(1);
        self.observe_settled(usage);
    }

    fn observe_failed(&mut self, response_usage: Option<&serde_json::Value>) {
        self.failed = self.failed.saturating_add(1);
        self.observe_settled(response_usage);
    }

    fn observe_settled(&mut self, usage: Option<&serde_json::Value>) {
        let Some(usage) = usage else {
            self.usage_absent = self.usage_absent.saturating_add(1);
            self.cost_absent = self.cost_absent.saturating_add(1);
            return;
        };
        let input = usage
            .get("input_tokens")
            .and_then(serde_json::Value::as_u64);
        let output = usage
            .get("output_tokens")
            .and_then(serde_json::Value::as_u64);
        match (input, output) {
            (Some(input), Some(output)) => {
                let cached = usage
                    .pointer("/input_tokens_details/cached_tokens")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                self.usage_present = self.usage_present.saturating_add(1);
                accumulate(&mut self.input_tokens, input, &mut self.invalid);
                accumulate(&mut self.cached_input_tokens, cached, &mut self.invalid);
                accumulate(&mut self.output_tokens, output, &mut self.invalid);
            }
            _ => {
                self.usage_absent = self.usage_absent.saturating_add(1);
                self.invalid = true;
            }
        }
        match usage
            .get("provider_cost_ticks")
            .or_else(|| usage.get("cost_ticks"))
        {
            Some(value) => match value.as_u64() {
                Some(cost) => {
                    self.cost_present = self.cost_present.saturating_add(1);
                    accumulate(&mut self.provider_cost_ticks, cost, &mut self.invalid);
                }
                None => {
                    self.cost_absent = self.cost_absent.saturating_add(1);
                    self.invalid = true;
                }
            },
            None => self.cost_absent = self.cost_absent.saturating_add(1),
        }
    }

    fn snapshot(&self) -> (ProviderCallCoverage, UsageTotals) {
        let settled = self.completed.saturating_add(self.failed);
        let in_flight = self.requested.saturating_sub(settled);
        let state = if self.invalid {
            UsageState::Invalid
        } else if in_flight == 0 && self.usage_present == self.requested {
            UsageState::Complete
        } else {
            UsageState::Partial
        };
        (
            ProviderCallCoverage {
                requested: self.requested,
                completed: self.completed,
                failed: self.failed,
                in_flight,
                usage_present: self.usage_present,
                usage_absent: self.usage_absent,
                usage_covered: self.usage_present,
                cost_present: self.cost_present,
                cost_absent: self.cost_absent,
                state,
            },
            UsageTotals {
                input_tokens: (self.usage_present > 0).then_some(self.input_tokens),
                cached_input_tokens: (self.usage_present > 0).then_some(self.cached_input_tokens),
                output_tokens: (self.usage_present > 0).then_some(self.output_tokens),
                provider_cost_ticks: (self.cost_present > 0).then_some(self.provider_cost_ticks),
            },
        )
    }
}

fn accumulate(target: &mut u64, value: u64, invalid: &mut bool) {
    match target.checked_add(value) {
        Some(total) => *target = total,
        None => {
            *target = u64::MAX;
            *invalid = true;
        }
    }
}

fn validate_runtime_bindings(
    spec: &RunSpec,
    contract: &LocalContract,
) -> Result<(), AgentRunError> {
    spec.validate()
        .map_err(|_| AgentRunError::configuration("run_spec_invalid"))?;
    if spec.provider.model != contract.profile().provider.model {
        return Err(AgentRunError::configuration("provider_model_mismatch"));
    }
    if spec.provider.max_turns > contract.profile().context.max_provider_turns {
        return Err(AgentRunError::configuration(
            "provider_max_turns_exceeds_profile",
        ));
    }
    if spec.agent_timeout_sec > contract.profile().deadlines.absolute_run_wall_cap_sec {
        return Err(AgentRunError::configuration(
            "agent_timeout_exceeds_profile",
        ));
    }
    Ok(())
}

fn validate_workspace(spec: &RunSpec) -> Result<(), AgentRunError> {
    let metadata = fs::symlink_metadata(&spec.workspace_dir)
        .map_err(|_| AgentRunError::configuration("workspace_metadata_failed"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AgentRunError::configuration("workspace_invalid"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRunError {
    Configuration {
        code: &'static str,
    },
    TerminalFailure {
        code: String,
        publication: RunRecordPublication,
    },
    Incomplete {
        code: &'static str,
    },
}

impl AgentRunError {
    fn configuration(code: &'static str) -> Self {
        Self::Configuration { code }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Configuration { code } | Self::Incomplete { code } => code,
            Self::TerminalFailure { code, .. } => code,
        }
    }

    pub fn publication_warning(&self) -> Option<&'static str> {
        match self {
            Self::TerminalFailure { publication, .. } => publication.warning_code(),
            Self::Configuration { .. } | Self::Incomplete { .. } => None,
        }
    }
}

impl From<EventWriteError> for AgentRunError {
    fn from(error: EventWriteError) -> Self {
        Self::Incomplete { code: error.code() }
    }
}

impl From<ToolExecutionError> for AgentRunError {
    fn from(error: ToolExecutionError) -> Self {
        Self::Incomplete { code: error.code() }
    }
}

impl Display for AgentRunError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration { code } => write!(formatter, "configuration failed: {code}"),
            Self::TerminalFailure { code, .. } => write!(formatter, "run failed: {code}"),
            Self::Incomplete { code } => write!(formatter, "run incomplete: {code}"),
        }
    }
}

impl Error for AgentRunError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use nano_provider_xai::{
        CompletedTurn, FunctionCall, FunctionTool, HistoryItem, MediaType, PreparedTurnRequest,
        Provider, ProviderFailure, ProviderRequestMode, TurnRequest,
    };
    use nano_types::contract::EffectClass;
    use nano_types::contract::TOOL_ORDER;
    use nano_types::event::{TOOL_RECEIPT_V1_SCHEMA, ToolReceiptV1, tool_receipt_identity_sha256};
    use nano_types::external_tool::{
        ExternalTerminalActorOriginV1, ExternalTerminalActorPhaseV1,
        ExternalTerminalActorReceiptV1, ExternalTerminalActorSubtypeV1,
        TERMINAL_ACTOR_RECEIPT_V1_SCHEMA,
    };
    use nano_types::run_spec::{
        ContractSpec, ProviderKind, ProviderSpec, RUN_SPEC_SCHEMA, RunSpec, TaskSpec,
    };
    use sha2::{Digest, Sha256};

    use crate::deadline::{DeadlineContext, DeadlineCutoffs, DeadlineInstants, DeadlineReserves};
    use crate::event_writer::RunRecordPublication;
    use crate::event_writer::{EventWriter, EventWriterLimits};
    use crate::tool::{
        ToolExecutionError, ToolExecutor, ToolMedia, ToolResult, ToolRuntimeBudget, WorkspaceMode,
    };

    use super::{
        AgentRunError, CommitTurnHistoryError, CompletionChallengeState, CompletionReviewPhase,
        CompletionReviewToolStage, FINAL_RESPONSE_LATENCY_RESERVE_V1, ProviderPhase,
        ProviderRequestEvidence, ToolOutputLimits, TurnBatchStaging, commit_turn_history_batch,
        completion_review_provider_deadline, completion_review_tool_deadline, finalize_provisional,
        initial_provider_phase_at, prepare_pending_provider_request, prepare_tool_completion,
        prepare_turn_history_batch, provider_phase_at, resolve_request_tools, settle_tool_call,
        tool_dispatch_open_at,
    };

    fn selected_spec(active_tools: Vec<&str>) -> RunSpec {
        RunSpec {
            schema_version: RUN_SPEC_SCHEMA.to_owned(),
            run_id: "run-selected".to_owned(),
            trial_id: "trial-selected".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            task: TaskSpec {
                id: "task".to_owned(),
                digest: "a".repeat(64),
                instruction: "Use selected tools.".to_owned(),
            },
            contract: ContractSpec {
                id: "synthetic-v1".to_owned(),
                contract_set_sha256: "b".repeat(64),
                profile_id: "synthetic-profile-v1".to_owned(),
            },
            provider: ProviderSpec {
                kind: ProviderKind::Scripted,
                model: "synthetic-model".to_owned(),
                max_turns: 4,
                retry_max: 0,
            },
            workspace_dir: PathBuf::from("/workspace"),
            artifact_dir: PathBuf::from("/logs/agent"),
            agent_timeout_sec: 60,
            active_tools: Some(active_tools.into_iter().map(str::to_owned).collect()),
        }
    }

    fn budget_context(last_send_after: Duration) -> DeadlineContext {
        let now = Instant::now();
        DeadlineContext {
            cutoffs: DeadlineCutoffs {
                actor_done_monotonic_ns: 20_000_000_000,
                tool_settled_monotonic_ns: 30_000_000_000,
                last_send_monotonic_ns: 60_000_000_000,
                runtime_final_monotonic_ns: 60_000_000_000,
                cleanup_start_monotonic_ns: 75_000_000_000,
                hard_deadline_monotonic_ns: 95_000_000_000,
            },
            instants: DeadlineInstants {
                actor_done: now + Duration::from_secs(1),
                tool_settled: now + Duration::from_secs(11),
                last_send: now + last_send_after,
                runtime_final: now + last_send_after,
                cleanup_start: now + last_send_after + Duration::from_secs(15),
                hard_deadline: now + last_send_after + Duration::from_secs(35),
            },
            reserves: DeadlineReserves::FROZEN,
            receipt_sha256: "d".repeat(64),
            observed_monotonic_ns: 10_000_000_000,
        }
    }

    fn v3_emission() -> super::RunRecordEmission {
        super::RunRecordEmission::V3(super::V3DeadlineBinding {
            receipt_sha256: "d".repeat(64),
        })
    }

    fn actor_receipt(
        phase: ExternalTerminalActorPhaseV1,
        origin: ExternalTerminalActorOriginV1,
        primary_subtype: ExternalTerminalActorSubtypeV1,
        cleanup_verified: Option<bool>,
        census_verified: Option<bool>,
    ) -> ExternalTerminalActorReceiptV1 {
        let mut receipt = ExternalTerminalActorReceiptV1 {
            schema_version: TERMINAL_ACTOR_RECEIPT_V1_SCHEMA.to_owned(),
            phase,
            origin,
            primary_subtype,
            recovery_subtype: None,
            execution_may_have_started: true,
            effective_cutoff_monotonic_ns: 42,
            cleanup_verified,
            census_verified,
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
        receipt.validate().expect("valid receipt");
        receipt
    }

    fn staged_text_completion(
        call_id: &str,
        provider_name: &str,
        output: &str,
    ) -> super::StagedToolCompletion {
        super::StagedToolCompletion {
            event: nano_types::event::ToolCompleted {
                call_id: call_id.to_owned(),
                provider_name: provider_name.to_owned(),
                execution_attempted: true,
                outcome: nano_types::event::ToolOutcome::Succeeded,
                output: output.to_owned(),
            },
            arguments_json: "{}".to_owned(),
            dispatched: false,
            history_output: HistoryItem::FunctionCallOutput {
                call_id: call_id.to_owned(),
                output: output.to_owned(),
            },
            attachment: None,
            committed_output_bytes: u64::try_from(output.len()).expect("output length"),
            tool_receipt: None,
            tool_receipt_omitted: false,
        }
    }

    #[test]
    fn selected_request_tools_use_contract_order_for_provider_and_known_set() {
        let all_tools = TOOL_ORDER
            .iter()
            .map(|name| FunctionTool {
                name: (*name).to_owned(),
                description: format!("{name} description"),
                parameters: serde_json::json!({"type": "object"}),
            })
            .collect::<Vec<_>>();
        for (input, expected) in [
            (
                vec!["write", "run_terminal_command", "read_file"],
                vec!["run_terminal_command", "read_file", "write"],
            ),
            (
                vec![
                    "grep",
                    "write",
                    "read_file",
                    "list_dir",
                    "search_replace",
                    "run_terminal_command",
                ],
                vec![
                    "run_terminal_command",
                    "read_file",
                    "search_replace",
                    "write",
                    "list_dir",
                    "grep",
                ],
            ),
        ] {
            let tools = resolve_request_tools(&selected_spec(input), &all_tools)
                .expect("resolve selected tools");
            assert_eq!(
                tools
                    .iter()
                    .map(|tool| tool.name.as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            let known_tools = tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<BTreeSet<_>>();
            assert_eq!(known_tools, expected.into_iter().collect::<BTreeSet<_>>());
        }
    }

    #[test]
    fn p0b_action_admission_and_dispatch_boundaries_are_strict() {
        let now = Instant::now();
        let last_send = now + Duration::from_secs(600);
        let final_only_cutoff = last_send - FINAL_RESPONSE_LATENCY_RESERVE_V1;
        let actor_done = last_send - Duration::from_secs(40);
        let minimum_send_window = Duration::from_secs(30);

        // Frozen, task-neutral V9 completed-turn evidence (N=2,775). Every
        // observed percentile is covered by the same absolute last_send.
        for latency_ms in [5_286_u64, 24_795, 34_563, 81_893] {
            assert!(Duration::from_millis(latency_ms) < FINAL_RESPONSE_LATENCY_RESERVE_V1);
            assert_eq!(
                provider_phase_at(
                    last_send - Duration::from_millis(latency_ms),
                    actor_done,
                    last_send,
                    minimum_send_window,
                    false,
                ),
                ProviderPhase::FinalOnly,
            );
        }

        assert_eq!(
            provider_phase_at(
                final_only_cutoff - Duration::from_millis(1),
                actor_done,
                last_send,
                minimum_send_window,
                false,
            ),
            ProviderPhase::ActionOpen
        );
        assert_eq!(
            provider_phase_at(
                final_only_cutoff,
                actor_done,
                last_send,
                minimum_send_window,
                false,
            ),
            ProviderPhase::FinalOnly
        );
        assert_eq!(
            provider_phase_at(
                final_only_cutoff + Duration::from_millis(1),
                actor_done,
                last_send,
                minimum_send_window,
                false,
            ),
            ProviderPhase::FinalOnly
        );
        assert_eq!(
            provider_phase_at(now, actor_done, last_send, minimum_send_window, true,),
            ProviderPhase::TerminalCommit
        );
        assert!(tool_dispatch_open_at(
            actor_done - Duration::from_nanos(1),
            actor_done
        ));
        assert!(!tool_dispatch_open_at(actor_done, actor_done));
        assert!(!tool_dispatch_open_at(
            actor_done + Duration::from_nanos(1),
            actor_done
        ));
        assert_ne!(ProviderPhase::SettlingAccepted, ProviderPhase::FinalOnly);
    }

    #[test]
    fn p0b_initial_under_capacity_action_is_single_turn_and_strictly_bounded() {
        let now = Instant::now();
        let actor_done = now + Duration::from_secs(45);
        let minimum_send_window = Duration::from_secs(30);

        assert_eq!(
            initial_provider_phase_at(
                now,
                actor_done,
                now + FINAL_RESPONSE_LATENCY_RESERVE_V1 - Duration::from_nanos(1),
                minimum_send_window,
            ),
            ProviderPhase::ActionOpen,
        );
        assert_eq!(
            initial_provider_phase_at(
                now,
                actor_done,
                now + FINAL_RESPONSE_LATENCY_RESERVE_V1,
                minimum_send_window,
            ),
            ProviderPhase::FinalOnly,
        );

        let action_cutoff = actor_done - minimum_send_window;
        let under_capacity_last_send = now + Duration::from_secs(85);
        assert_eq!(
            initial_provider_phase_at(
                action_cutoff - Duration::from_nanos(1),
                actor_done,
                under_capacity_last_send,
                minimum_send_window,
            ),
            ProviderPhase::ActionOpen,
        );
        assert_eq!(
            initial_provider_phase_at(
                action_cutoff,
                actor_done,
                under_capacity_last_send,
                minimum_send_window,
            ),
            ProviderPhase::FinalOnly,
        );
        assert_eq!(
            provider_phase_at(
                now,
                actor_done,
                under_capacity_last_send,
                minimum_send_window,
                false,
            ),
            ProviderPhase::FinalOnly,
            "only turn zero may use the bounded under-capacity admission",
        );
    }

    #[test]
    fn v10_review_state_allows_one_bounded_path_and_forbids_stale_fallback_after_mutation() {
        let mut read_only = CompletionChallengeState::default();
        read_only.issue("candidate".to_owned());
        assert_eq!(
            read_only.admit_tool_stage([EffectClass::ReadOnly]),
            Some(CompletionReviewToolStage::Validation)
        );
        read_only.commit_tool_stage(CompletionReviewToolStage::Validation, true, false);
        assert_eq!(read_only.phase, CompletionReviewPhase::Decision);
        assert_eq!(read_only.admit_tool_stage([EffectClass::ReadOnly]), None);
        assert_eq!(read_only.take_safe_fallback().as_deref(), Some("candidate"));

        let mut corrected = CompletionChallengeState::default();
        corrected.issue("stale-candidate".to_owned());
        corrected.commit_tool_stage(CompletionReviewToolStage::Validation, true, false);
        assert_eq!(
            corrected.admit_tool_stage([EffectClass::Mutating]),
            Some(CompletionReviewToolStage::Correction)
        );
        corrected.commit_tool_stage(CompletionReviewToolStage::Correction, true, true);
        assert_eq!(corrected.phase, CompletionReviewPhase::Correction);
        assert!(corrected.take_safe_fallback().is_none());
        assert_eq!(
            corrected.admit_tool_stage([EffectClass::ReadOnly]),
            Some(CompletionReviewToolStage::Revalidation)
        );
        corrected.commit_tool_stage(CompletionReviewToolStage::Revalidation, true, false);
        assert_eq!(corrected.phase, CompletionReviewPhase::Revalidation);
        assert_eq!(corrected.admit_tool_stage([EffectClass::ReadOnly]), None);
        assert_eq!(corrected.admit_tool_stage([EffectClass::Mutating]), None);
    }

    #[test]
    fn v10_review_stage_deadlines_are_bounded_from_one_absolute_now() {
        let now = Instant::now();
        assert_eq!(
            completion_review_provider_deadline(now, now + Duration::from_secs(200)),
            now + Duration::from_secs(90)
        );
        assert_eq!(
            completion_review_provider_deadline(now, now + Duration::from_secs(89)),
            now + Duration::from_secs(89)
        );
        assert_eq!(
            completion_review_tool_deadline(now, now + Duration::from_secs(200)),
            now + Duration::from_secs(120)
        );
        assert_eq!(
            completion_review_tool_deadline(now, now + Duration::from_secs(119)),
            now + Duration::from_secs(119)
        );
    }

    struct NeverExecute;

    impl ToolExecutor for NeverExecute {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            Ok(())
        }

        async fn execute(
            &mut self,
            _call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            panic!("closed action phase must reject before execution")
        }
    }

    struct SlowValidationNeverExecute;

    impl ToolExecutor for SlowValidationNeverExecute {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        }

        async fn execute(
            &mut self,
            _call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            panic!("boundary crossed during validation must reject before dispatch")
        }
    }

    #[derive(Default)]
    struct CrossCutoffExecutor {
        executions: u64,
    }

    impl ToolExecutor for CrossCutoffExecutor {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            Ok(())
        }

        async fn execute(
            &mut self,
            _call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            self.executions = self.executions.saturating_add(1);
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(ToolResult::succeeded("accepted"))
        }
    }

    #[tokio::test]
    async fn official_repository_commands_fail_before_validation_or_dispatch() {
        for (index, (command, background)) in [
            (
                "git clone https://github.com/harbor-framework/terminal-bench",
                false,
            ),
            (
                "git clone https://GITHUB.COM/LAUDE-INSTITUTE/TERMINAL-BENCH",
                true,
            ),
            (
                "curl https://api.github.com/repos/harbor-framework%2Fterminal-bench",
                false,
            ),
            (
                r"curl https:\/\/raw.githubusercontent.com\/laude-institute\/terminal-bench\/main",
                true,
            ),
            (
                r"curl https://github.com/harbor-framework\u002fterminal-bench",
                false,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = tempfile::tempdir().expect("event directory");
            let writer = EventWriter::create(
                directory.path(),
                "run",
                "trial",
                "attempt",
                EventWriterLimits {
                    max_events: 8,
                    max_line_bytes: 4096,
                    max_log_bytes: 16_384,
                    max_run_record_bytes: 16_384,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec!["run_terminal_command"]);
            let mut state =
                super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
            state.provider_requested();
            state.provider_completed(None);
            state.tool_call_count = 1;
            let arguments_json = serde_json::json!({
                "command": command,
                "description": "attempt official repository access",
                "background": background,
            })
            .to_string();
            let call = FunctionCall {
                call_id: format!("call-official-{index}"),
                name: "run_terminal_command".to_owned(),
                arguments_json: arguments_json.clone(),
            };
            let cancellation = super::RunCancellation::new();
            let mut executor = NeverExecute;
            let terminal = settle_tool_call(
                &mut state,
                &mut executor,
                &BTreeSet::from(["run_terminal_command"]),
                &call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 4,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes: 0,
                },
            )
            .await
            .expect_err("official benchmark repository access must be terminal");
            state
                .finalize_once(terminal)
                .expect_err("official benchmark repository access must fail the run");

            let events =
                std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
            let parsed = events
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("event JSON"))
                .collect::<Vec<_>>();
            assert_eq!(
                parsed
                    .iter()
                    .filter(|event| event["type"] == "tool.registered")
                    .count(),
                1
            );
            let registered = parsed
                .iter()
                .find(|event| event["type"] == "tool.registered")
                .expect("registered evidence");
            assert_eq!(registered["data"]["arguments_json"], arguments_json);
            assert_eq!(
                parsed
                    .iter()
                    .filter(|event| event["type"] == "tool.dispatched")
                    .count(),
                0
            );
            assert_eq!(
                parsed
                    .iter()
                    .filter(|event| event["type"] == "tool.completed")
                    .count(),
                0
            );
            let failed = parsed
                .iter()
                .find(|event| event["type"] == "tool.failed")
                .expect("tool failure evidence");
            assert_eq!(
                failed["data"]["code"],
                "protected_harness_material_access_blocked"
            );
            assert_eq!(failed["data"]["execution_may_have_started"], false);
            assert!(failed["data"]["cleanup_verified"].is_null());
            assert!(failed["data"]["census_verified"].is_null());
            assert_eq!(failed["data"]["recoverability"], "fatal");
            assert_eq!(
                parsed
                    .iter()
                    .filter(|event| event["type"] == "assistant.final")
                    .count(),
                0
            );
            let run: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.path().join("run.json")).expect("run record"),
            )
            .expect("run JSON");
            assert_eq!(run["terminal_status"], "tool_failure");
            assert_eq!(run["terminal_phase"], "tool");
            assert_eq!(
                run["terminal_code"],
                "protected_harness_material_access_blocked"
            );
        }
    }

    #[tokio::test]
    async fn protected_target_calls_fail_after_registration_and_before_validation_or_dispatch() {
        for (index, (tool_name, field, target)) in [
            (
                "run_terminal_command",
                "command",
                "cat /logs/agent/runtime/events.jsonl",
            ),
            (
                "run_terminal_command",
                "command",
                "p=/logs; cat \"$p/agent/input/run-spec.json\"",
            ),
            (
                "run_terminal_command",
                "command",
                "cat /proc/self/root/logs/agent/input/run-spec.json",
            ),
            (
                "run_terminal_command",
                "command",
                "cat /proc/123/root/logs/verifier/reward.txt",
            ),
            ("read_file", "target_file", "/logs/verifier/reward.txt"),
            ("search_replace", "file_path", "/logs/reward/result.json"),
            ("write", "file_path", "/logs/judge/result.json"),
            ("list_dir", "target_directory", "/logs/agent"),
            ("grep", "path", "/logs/verifier"),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = tempfile::tempdir().expect("event directory");
            let writer = EventWriter::create(
                directory.path(),
                "run",
                "trial",
                "attempt",
                EventWriterLimits {
                    max_events: 8,
                    max_line_bytes: 4096,
                    max_log_bytes: 16_384,
                    max_run_record_bytes: 16_384,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec![tool_name]);
            let mut state =
                super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
            state.provider_requested();
            state.provider_completed(None);
            state.tool_call_count = 1;
            let arguments_json = serde_json::json!({field: target}).to_string();
            let call = FunctionCall {
                call_id: format!("call-protected-{index}"),
                name: tool_name.to_owned(),
                arguments_json: arguments_json.clone(),
            };
            let cancellation = super::RunCancellation::new();
            let mut executor = NeverExecute;
            let terminal = settle_tool_call(
                &mut state,
                &mut executor,
                &BTreeSet::from([tool_name]),
                &call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 4,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes: 0,
                },
            )
            .await
            .expect_err("protected target access must be terminal");
            state
                .finalize_once(terminal)
                .expect_err("protected target access must fail the run");

            let events =
                std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
            let parsed = events
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("event JSON"))
                .collect::<Vec<_>>();
            assert_eq!(
                parsed
                    .iter()
                    .map(|event| event["type"].as_str().expect("event type"))
                    .collect::<Vec<_>>(),
                ["tool.registered", "tool.failed", "run.failed"]
            );
            assert_eq!(parsed[0]["data"]["arguments_json"], arguments_json);
            assert_eq!(
                parsed[1]["data"]["code"],
                "protected_harness_material_access_blocked"
            );
            assert_eq!(parsed[1]["data"]["execution_may_have_started"], false);
            assert_eq!(parsed[1]["data"]["recoverability"], "fatal");
            assert_eq!(
                parsed[2]["data"]["code"],
                "protected_harness_material_access_blocked"
            );
        }
    }

    #[tokio::test]
    async fn official_repository_guard_leaves_other_arguments_on_existing_path() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        state.provider_turn_count = 1;
        state.tool_call_count = 1;
        let call = FunctionCall {
            call_id: "call-normal-github".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: serde_json::json!({
                "command": "git clone https://github.com/rust-lang/cargo",
                "description": "compare harbor-framework/terminal-bench as plain description text",
                "background": false,
            })
            .to_string(),
        };
        let cancellation = super::RunCancellation::new();
        let mut executor = CrossCutoffExecutor::default();
        let completion = settle_tool_call(
            &mut state,
            &mut executor,
            &BTreeSet::from(["run_terminal_command"]),
            &call,
            super::ToolExecutionWindow {
                workspace: Path::new("/remote/workspace"),
                dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                settlement_deadline: Instant::now() + Duration::from_secs(1),
                admission_rejection: None,
                cancellation: &cancellation,
                runtime_deadline: None,
                max_provider_turns: 4,
                output_limits: ToolOutputLimits {
                    per_call_bytes: u64::MAX,
                    per_run_bytes: u64::MAX,
                },
                projected_tool_output_bytes: 0,
            },
        )
        .await
        .expect("normal GitHub dependency command must execute");

        assert_eq!(executor.executions, 1);
        assert!(completion.dispatched);
        assert_eq!(
            completion.event.outcome,
            nano_types::event::ToolOutcome::Succeeded
        );
    }

    #[test]
    fn official_repository_guard_defers_malformed_and_non_terminal_arguments() {
        for call in [
            FunctionCall {
                call_id: "call-malformed".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: "{".to_owned(),
            },
            FunctionCall {
                call_id: "call-missing-command".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: serde_json::json!({
                    "description": "harbor-framework/terminal-bench",
                })
                .to_string(),
            },
            FunctionCall {
                call_id: "call-other-tool".to_owned(),
                name: "read_file".to_owned(),
                arguments_json: serde_json::json!({
                    "command": "git clone https://github.com/harbor-framework/terminal-bench",
                })
                .to_string(),
            },
        ] {
            assert!(
                crate::protected_target::match_protected_target(&call.name, &call.arguments_json)
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn p0b_closed_action_call_is_registered_rejected_and_atomically_committed() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        state.provider_turn_count = 1;
        state.tool_call_count = 1;
        let call = FunctionCall {
            call_id: "call-at-actor-done".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{}".to_owned(),
        };
        let cancellation = super::RunCancellation::new();
        let mut executor = NeverExecute;
        let completion = settle_tool_call(
            &mut state,
            &mut executor,
            &BTreeSet::from(["run_terminal_command"]),
            &call,
            super::ToolExecutionWindow {
                workspace: Path::new("/remote/workspace"),
                dispatch_cutoff: Instant::now(),
                settlement_deadline: Instant::now() + Duration::from_secs(1),
                admission_rejection: None,
                cancellation: &cancellation,
                runtime_deadline: None,
                max_provider_turns: 4,
                output_limits: ToolOutputLimits {
                    per_call_bytes: u64::MAX,
                    per_run_bytes: u64::MAX,
                },
                projected_tool_output_bytes: 0,
            },
        )
        .await
        .expect("closed call is a model-visible rejection");
        assert!(!completion.event.execution_attempted);
        assert_eq!(
            completion.event.outcome,
            nano_types::event::ToolOutcome::Rejected
        );
        assert_eq!(completion.event.output, "action_phase_closed");
        assert!(completion.tool_receipt.is_none());

        let mut history = vec![HistoryItem::FunctionCall {
            call_id: call.call_id.clone(),
            name: call.name.clone(),
            arguments_json: call.arguments_json.clone(),
        }];
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
        let mut staging = TurnBatchStaging::new(0);
        staging.push(completion);
        let prepared =
            prepare_turn_history_batch(&history, 0, &staging).expect("prepared rejection");
        commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .expect("atomic rejected-output commit");

        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 1);
        assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 1);
        assert!(history.iter().any(|item| matches!(
            item,
            HistoryItem::FunctionCallOutput { call_id, output }
                if call_id == "call-at-actor-done" && output == "action_phase_closed"
        )));
    }

    #[tokio::test]
    async fn p0b_dispatch_guard_is_immediately_before_tool_dispatched() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        state.provider_turn_count = 1;
        state.tool_call_count = 1;
        let call = FunctionCall {
            call_id: "call-validation-race".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{}".to_owned(),
        };
        let cancellation = super::RunCancellation::new();
        let mut executor = SlowValidationNeverExecute;
        let completion = settle_tool_call(
            &mut state,
            &mut executor,
            &BTreeSet::from(["run_terminal_command"]),
            &call,
            super::ToolExecutionWindow {
                workspace: Path::new("/remote/workspace"),
                dispatch_cutoff: Instant::now() + Duration::from_millis(5),
                settlement_deadline: Instant::now() + Duration::from_secs(1),
                admission_rejection: None,
                cancellation: &cancellation,
                runtime_deadline: None,
                max_provider_turns: 4,
                output_limits: ToolOutputLimits {
                    per_call_bytes: u64::MAX,
                    per_run_bytes: u64::MAX,
                },
                projected_tool_output_bytes: 0,
            },
        )
        .await
        .expect("validation race is a closed rejection");

        assert!(!completion.event.execution_attempted);
        assert_eq!(completion.event.output, "action_phase_closed");
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 1);
        assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
    }

    #[tokio::test]
    async fn p0b_multi_call_cutoff_commits_accepted_prefix_and_rejected_suffix() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 12,
                max_line_bytes: 4096,
                max_log_bytes: 32_768,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        state.provider_turn_count = 1;
        let calls = ["call-accepted", "call-rejected"].map(|call_id| FunctionCall {
            call_id: call_id.to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{}".to_owned(),
        });
        let mut history = calls
            .iter()
            .map(|call| HistoryItem::FunctionCall {
                call_id: call.call_id.clone(),
                name: call.name.clone(),
                arguments_json: call.arguments_json.clone(),
            })
            .collect::<Vec<_>>();
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
        let cancellation = super::RunCancellation::new();
        let actor_done = Instant::now() + Duration::from_millis(50);
        let tool_settled = Instant::now() + Duration::from_secs(1);
        let mut executor = CrossCutoffExecutor::default();
        let mut staging = TurnBatchStaging::new(0);
        for call in &calls {
            state.tool_call_count = state.tool_call_count.saturating_add(1);
            let completion = settle_tool_call(
                &mut state,
                &mut executor,
                &BTreeSet::from(["run_terminal_command"]),
                call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: actor_done,
                    settlement_deadline: tool_settled,
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 4,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes: staging.projected_tool_output_bytes,
                },
            )
            .await
            .expect("settled prefix/suffix");
            staging.push(completion);
        }
        let prepared = prepare_turn_history_batch(&history, 0, &staging).expect("prepared batch");
        commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            Some(tool_settled),
        )
        .expect("committed prefix and suffix");

        assert_eq!(executor.executions, 1);
        let outputs = history
            .iter()
            .filter_map(|item| match item {
                HistoryItem::FunctionCallOutput { call_id, output } => {
                    Some((call_id.as_str(), output.as_str()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            outputs,
            [
                ("call-accepted", "accepted"),
                ("call-rejected", "action_phase_closed")
            ]
        );
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 2);
        assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 2);
    }

    #[derive(Default)]
    struct RejectedAfterExecutionThenSucceeded {
        call_ids: Vec<String>,
    }

    const FOREGROUND_RESIDUAL_SENTINEL: &str = "FG_CHILDREN_KILLED;START_INTENDED_BG;VERIFY_HANDLE";

    impl ToolExecutor for RejectedAfterExecutionThenSucceeded {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            Ok(())
        }

        async fn execute(
            &mut self,
            call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            self.call_ids.push(call.call_id.clone());
            if self.call_ids.len() == 1 {
                Ok(ToolResult {
                    execution_attempted: true,
                    outcome: nano_types::event::ToolOutcome::Rejected,
                    output: concat!(
                        "FG_CHILDREN_KILLED;START_INTENDED_BG;VERIFY_HANDLE\n",
                        "<observation>foreground_owned_processes_terminated</observation>\n",
                        "<status>execution_attempted=true outcome=rejected cleanup_verified=true ",
                        "census_verified=true survivors=0</status>\n",
                        "<next-step>If a long-lived process was intended, start only that process ",
                        "in a fresh managed background call and verify the returned handle. ",
                        "Otherwise continue.</next-step>\n",
                        "exit: 0\nleader-output",
                    )
                    .to_owned(),
                    media: None,
                    runtime_budget: Some(ToolRuntimeBudget::wait_clamped()),
                    actor_receipt: None,
                })
            } else {
                Ok(ToolResult::succeeded("dependent-ok"))
            }
        }
    }

    #[tokio::test]
    async fn agent_loop_rejected_after_execution_continues() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run-selected",
            "trial-selected",
            "attempt-0",
            EventWriterLimits {
                max_events: 16,
                max_line_bytes: 4096,
                max_log_bytes: 32_768,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let known_tools = BTreeSet::from(["run_terminal_command"]);
        let cancellation = super::RunCancellation::new();
        let mut executor = RejectedAfterExecutionThenSucceeded::default();
        let calls = [
            FunctionCall {
                call_id: "call-residual".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json:
                    r#"{"command":"true","description":"residual","timeout":1000,"background":false}"#
                        .to_owned(),
            },
            FunctionCall {
                call_id: "call-dependent".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json:
                    r#"{"command":"true","description":"dependent","timeout":1000,"background":false}"#
                        .to_owned(),
            },
        ];
        let mut history = Vec::new();
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("history receipt");

        for (turn_index, call) in calls.iter().enumerate() {
            state.provider_requested();
            state.provider_completed(None);
            state.tool_call_count = state.tool_call_count.saturating_add(1);
            history.push(HistoryItem::FunctionCall {
                call_id: call.call_id.clone(),
                name: call.name.clone(),
                arguments_json: call.arguments_json.clone(),
            });
            let projected_tool_output_bytes = state.tool_output_bytes;
            let completion = settle_tool_call(
                &mut state,
                &mut executor,
                &known_tools,
                call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 4,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes,
                },
            )
            .await
            .expect("nonfatal tool settlement");
            if turn_index == 0 {
                assert!(completion.event.execution_attempted);
                assert_eq!(
                    completion.event.outcome,
                    nano_types::event::ToolOutcome::Rejected
                );
            }
            let mut staging = TurnBatchStaging::new(state.tool_output_bytes);
            staging.push(completion);
            let prepared = prepare_turn_history_batch(
                &history,
                u64::try_from(turn_index).expect("turn index"),
                &staging,
            )
            .expect("prepared completion");
            commit_turn_history_batch(
                &mut state,
                &mut history,
                &mut receipt,
                prepared,
                staging,
                None,
            )
            .expect("committed completion");
        }

        let outcome = state
            .finalize_once(super::TerminalOutcome::success())
            .expect("run completes after rejected execution");
        assert_eq!(outcome.record.provider_turn_count, 2);
        assert_eq!(outcome.record.tool_call_count, 2);
        assert_eq!(executor.call_ids, ["call-residual", "call-dependent"]);
        let outputs = history
            .iter()
            .filter_map(|item| match item {
                HistoryItem::FunctionCallOutput { output, .. } => Some(output.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(outputs.len(), 2);
        assert!(outputs[0].contains("foreground_owned_processes_terminated"));
        assert!(outputs[0].contains("exit: 0\nleader-output"));
        assert_eq!(outputs[1], "dependent-ok");
        assert!(!outputs[0].contains("<task_id>"));

        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 2);
        assert_eq!(
            events
                .lines()
                .filter(|line| {
                    line.contains("\"type\":\"tool.completed\"")
                        && line.contains("\"outcome\":\"rejected\"")
                })
                .count(),
            1
        );
        assert_eq!(events.matches("\"type\":\"run.completed\"").count(), 1);
        assert!(!events.contains("\"type\":\"run.failed\""));
    }

    #[tokio::test]
    async fn agent_loop_rejected_after_execution_continues_at_cap_boundaries() {
        for (name, per_call_bytes, per_run_bytes, projected_bytes, cap) in [
            ("footer-128", 128, u64::MAX, 0, 128_usize),
            ("remaining-126", u64::MAX, 256, 130, 126),
            ("remaining-125", u64::MAX, 255, 130, 125),
            ("remaining-26", u64::MAX, 156, 130, 26),
            ("remaining-0", u64::MAX, 130, 130, 0),
        ] {
            let directory = tempfile::tempdir().expect("event directory");
            let writer = EventWriter::create(
                directory.path(),
                "run-selected",
                "trial-selected",
                "attempt-0",
                EventWriterLimits {
                    max_events: 16,
                    max_line_bytes: 4096,
                    max_log_bytes: 32_768,
                    max_run_record_bytes: 4096,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec!["run_terminal_command"]);
            let mut state =
                super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
            state.tool_output_bytes = projected_bytes;
            let known_tools = BTreeSet::from(["run_terminal_command"]);
            let cancellation = super::RunCancellation::new();
            let context = budget_context(Duration::from_secs(30));
            let limits = ToolOutputLimits {
                per_call_bytes,
                per_run_bytes,
            };
            let mut executor = RejectedAfterExecutionThenSucceeded::default();
            let calls = [
                FunctionCall {
                    call_id: format!("call-residual-{name}"),
                    name: "run_terminal_command".to_owned(),
                    arguments_json: r#"{"command":"true","description":"residual","timeout":1000,"background":false}"#
                        .to_owned(),
                },
                FunctionCall {
                    call_id: format!("call-dependent-{name}"),
                    name: "run_terminal_command".to_owned(),
                    arguments_json: r#"{"command":"true","description":"dependent","timeout":1000,"background":false}"#
                        .to_owned(),
                },
            ];
            let mut history = Vec::new();
            let mut receipt = nano_provider_xai::apply_media_history_policy(&mut history)
                .expect("history receipt");

            state.provider_requested();
            state.provider_completed(None);
            state.tool_call_count = state.tool_call_count.saturating_add(1);
            history.push(HistoryItem::FunctionCall {
                call_id: calls[0].call_id.clone(),
                name: calls[0].name.clone(),
                arguments_json: calls[0].arguments_json.clone(),
            });
            let first = settle_tool_call(
                &mut state,
                &mut executor,
                &known_tools,
                &calls[0],
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: Some(&context),
                    max_provider_turns: 4,
                    output_limits: limits,
                    projected_tool_output_bytes: projected_bytes,
                },
            )
            .await
            .expect("capped rejected settlement");
            assert!(first.event.execution_attempted);
            assert_eq!(
                first.event.outcome,
                nano_types::event::ToolOutcome::Rejected
            );
            let history_output = match &first.history_output {
                HistoryItem::FunctionCallOutput { output, .. } => output,
                other => panic!("unexpected history item: {other:?}"),
            };
            assert_eq!(first.event.output, *history_output);
            assert_eq!(history_output.len(), cap);
            assert!(std::str::from_utf8(history_output.as_bytes()).is_ok());
            match cap {
                128 | 126 => assert!(history_output.starts_with(FOREGROUND_RESIDUAL_SENTINEL)),
                125 => {
                    assert_eq!(&history_output[..49], &FOREGROUND_RESIDUAL_SENTINEL[..49]);
                    assert!(!history_output.contains(FOREGROUND_RESIDUAL_SENTINEL));
                    assert!(history_output.contains("output truncated"));
                }
                26 => assert_eq!(history_output, "\n... output truncated ...\n"),
                0 => assert!(history_output.is_empty()),
                _ => unreachable!("closed cap matrix"),
            }
            let mut first_staging = TurnBatchStaging::new(projected_bytes);
            first_staging.push(first);
            let prepared = prepare_turn_history_batch(&history, 0, &first_staging)
                .expect("prepare first completion");
            commit_turn_history_batch(
                &mut state,
                &mut history,
                &mut receipt,
                prepared,
                first_staging,
                None,
            )
            .expect("commit first completion");
            assert_eq!(
                state.tool_output_bytes,
                projected_bytes.saturating_add(u64::try_from(cap).expect("cap"))
            );

            state.provider_requested();
            state.provider_completed(None);
            state.tool_call_count = state.tool_call_count.saturating_add(1);
            history.push(HistoryItem::FunctionCall {
                call_id: calls[1].call_id.clone(),
                name: calls[1].name.clone(),
                arguments_json: calls[1].arguments_json.clone(),
            });
            let dependent_projected_bytes = state.tool_output_bytes;
            let second = settle_tool_call(
                &mut state,
                &mut executor,
                &known_tools,
                &calls[1],
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 4,
                    output_limits: limits,
                    projected_tool_output_bytes: dependent_projected_bytes,
                },
            )
            .await
            .expect("dependent call continues");
            let mut second_staging = TurnBatchStaging::new(state.tool_output_bytes);
            second_staging.push(second);
            let prepared = prepare_turn_history_batch(&history, 1, &second_staging)
                .expect("prepare dependent completion");
            commit_turn_history_batch(
                &mut state,
                &mut history,
                &mut receipt,
                prepared,
                second_staging,
                None,
            )
            .expect("commit dependent completion");
            let outcome = state
                .finalize_once(super::TerminalOutcome::success())
                .expect("run completes after capped rejection");
            assert_eq!(outcome.record.provider_turn_count, 2);
            assert_eq!(outcome.record.tool_call_count, 2);
            assert_eq!(
                executor.call_ids,
                [calls[0].call_id.clone(), calls[1].call_id.clone()]
            );
            let events =
                std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
            assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 2);
            assert_eq!(events.matches("\"type\":\"run.completed\"").count(), 1);
            assert!(!events.contains("\"type\":\"run.failed\""));
        }
    }

    #[derive(Default)]
    struct CapturingPreflightProvider {
        requests: Mutex<Vec<TurnRequest>>,
    }

    impl Provider for CapturingPreflightProvider {
        fn preflight(&self, request: TurnRequest) -> Result<PreparedTurnRequest, ProviderFailure> {
            self.requests.lock().expect("capture lock").push(request);
            Err(ProviderFailure::new("captured_preflight_request"))
        }

        async fn send(
            &mut self,
            _request: PreparedTurnRequest,
        ) -> Result<CompletedTurn, ProviderFailure> {
            panic!("captured preflight must never send")
        }
    }

    #[test]
    fn service_and_non_service_requests_project_identical_policy_and_tools() {
        let system = "test system policy".to_owned();
        let tools = TOOL_ORDER
            .iter()
            .map(|name| FunctionTool {
                name: (*name).to_owned(),
                description: format!("{name} description"),
                parameters: serde_json::json!({"type": "object"}),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            TOOL_ORDER
        );

        let mut spec = selected_spec(TOOL_ORDER.to_vec());
        spec.provider.model = "grok-4.5".to_owned();
        let provider = CapturingPreflightProvider::default();
        for query in [
            "Start a service and prove it remains ready.",
            "Read one file and report its contents.",
        ] {
            let mut history = vec![
                HistoryItem::System {
                    content: system.clone(),
                },
                HistoryItem::User {
                    content: query.to_owned(),
                },
            ];
            let receipt = nano_provider_xai::apply_media_history_policy(&mut history)
                .expect("history receipt");
            let error = prepare_pending_provider_request(
                &provider,
                &spec,
                &tools,
                ProviderRequestMode::ActionOpen,
                0,
                ProviderRequestEvidence {
                    history: &history,
                    media_history_receipt: &receipt,
                    budget_observation: None,
                },
            )
            .err()
            .expect("capturing provider rejection");
            assert_eq!(error.code(), "captured_preflight_request");
        }

        let requests = provider.requests.lock().expect("capture lock");
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            assert_eq!(request.model, "grok-4.5");
            assert_eq!(request.tools, tools);
            assert_eq!(
                request.history.first(),
                Some(&HistoryItem::System {
                    content: system.clone(),
                })
            );
        }
        assert_ne!(requests[0].history[1], requests[1].history[1]);
        assert_eq!(requests[0].history[0], requests[1].history[0]);
        assert_eq!(requests[0].tools, requests[1].tools);
    }

    #[test]
    fn published_terminal_failure_is_not_reclassified_as_incomplete() {
        let error = AgentRunError::TerminalFailure {
            code: "provider_failed".to_owned(),
            publication: RunRecordPublication::PublishedDurabilityUncertain {
                warning_code: "artifact_directory_sync_failed",
            },
        };
        assert_eq!(
            error.publication_warning(),
            Some("artifact_directory_sync_failed")
        );
        assert!(!matches!(error, AgentRunError::Incomplete { .. }));
    }

    #[test]
    fn malformed_v3_binding_is_rejected_before_artifact_creation() {
        let directory = tempfile::tempdir().expect("artifact directory");
        let mut spec = selected_spec(vec!["run_terminal_command"]);
        spec.artifact_dir = directory.path().to_owned();
        let mut deadline = budget_context(Duration::from_secs(60));
        deadline.receipt_sha256 = "not-a-sha".to_owned();

        let error = super::AgentRunMode::v3(&deadline).expect_err("invalid v3 binding");

        assert_eq!(error.code(), "deadline_receipt_sha256_invalid");
        assert!(!spec.artifact_dir.join("events.jsonl").exists());
        assert!(!spec.artifact_dir.join(".run.json.tmp").exists());
        assert!(!spec.artifact_dir.join("run.json").exists());
    }

    #[test]
    fn one_emission_binding_feeds_run_started_and_terminal_record() {
        for v3 in [false, true] {
            let directory = tempfile::tempdir().expect("artifact directory");
            let writer = EventWriter::create(
                directory.path(),
                "run-selected",
                "trial-selected",
                "attempt-0",
                EventWriterLimits {
                    max_events: 8,
                    max_line_bytes: 4096,
                    max_log_bytes: 16_384,
                    max_run_record_bytes: 4096,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec!["run_terminal_command"]);
            let emission = if v3 {
                v3_emission()
            } else {
                super::RunRecordEmission::V2
            };
            let started_digest = emission.deadline_receipt_sha256().map(str::to_owned);
            let mut state = super::RunState::new(writer, &spec, "a".repeat(64), emission);
            state
                .append_operational(nano_types::event::EventBody::RunStarted(
                    nano_types::event::RunStarted {
                        task_id: spec.task.id.clone(),
                        contract_id: spec.contract.id.clone(),
                        profile_id: spec.contract.profile_id.clone(),
                        contract_set_sha256: spec.contract.contract_set_sha256.clone(),
                        model: spec.provider.model.clone(),
                        run_spec_sha256: "a".repeat(64),
                        deadline_receipt_sha256: started_digest.clone(),
                        media_history_policy_version: None,
                        media_history_policy_sha256: None,
                    },
                ))
                .expect("run started");

            let outcome = state
                .finalize_once(super::TerminalOutcome::success())
                .expect("successful finalization");
            let run: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.path().join("run.json")).expect("run record"),
            )
            .expect("run json");
            assert_eq!(outcome.record.provider_turn_count, 0);
            assert_eq!(outcome.record.tool_call_count, 0);
            assert_eq!(outcome.record.deadline_receipt_sha256, started_digest);
            if v3 {
                assert!(matches!(
                    outcome.terminal_record,
                    nano_types::event::VersionedRunRecord::V3(_)
                ));
                assert_eq!(run["schema_version"], "nano-run-record-v3");
                assert_eq!(run["deadline_receipt_sha256"], "d".repeat(64));
            } else {
                assert!(matches!(
                    outcome.terminal_record,
                    nano_types::event::VersionedRunRecord::V2(_)
                ));
                assert_eq!(run["schema_version"], "nano-run-record-v2");
                assert!(run.get("deadline_receipt_sha256").is_none());
            }
        }
    }

    #[test]
    fn usage_snapshot_distinguishes_in_flight_and_invalid_overflow() {
        let in_flight = super::UsageAccumulator {
            requested: 1,
            ..Default::default()
        };
        let (coverage, totals) = in_flight.snapshot();
        assert_eq!(coverage.in_flight, 1);
        assert_eq!(coverage.state, nano_types::event::UsageState::Partial);
        assert_eq!(totals.input_tokens, None);

        let mut overflow = super::UsageAccumulator {
            requested: 2,
            ..Default::default()
        };
        overflow.observe_completed(Some(
            &serde_json::json!({"input_tokens": u64::MAX, "output_tokens": 1}),
        ));
        overflow.observe_completed(Some(
            &serde_json::json!({"input_tokens": 1, "output_tokens": 1}),
        ));
        let (coverage, totals) = overflow.snapshot();
        assert_eq!(coverage.state, nano_types::event::UsageState::Invalid);
        assert_eq!(totals.input_tokens, Some(u64::MAX));
    }

    #[test]
    fn runtime_budget_footer_is_conditional_and_event_history_bytes_match() {
        fn settle(
            runtime_budget: Option<ToolRuntimeBudget>,
            last_send_after: Duration,
        ) -> (String, String) {
            let directory = tempfile::tempdir().expect("event directory");
            let writer = EventWriter::create(
                directory.path(),
                "run",
                "trial",
                "attempt",
                EventWriterLimits {
                    max_events: 8,
                    max_line_bytes: 4096,
                    max_log_bytes: 16_384,
                    max_run_record_bytes: 4096,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec!["run_terminal_command"]);
            let mut state = super::RunState::new(writer, &spec, "a".repeat(64), v3_emission());
            state.provider_turn_count = 2;
            let call = FunctionCall {
                call_id: "call-budget".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: "{}".to_owned(),
            };
            let mut history = vec![HistoryItem::FunctionCall {
                call_id: call.call_id.clone(),
                name: call.name.clone(),
                arguments_json: call.arguments_json.clone(),
            }];
            let mut receipt =
                nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
            let completion = prepare_tool_completion(
                &state,
                &call,
                ToolResult {
                    execution_attempted: true,
                    outcome: nano_types::event::ToolOutcome::Succeeded,
                    output: "status: running".to_owned(),
                    media: None,
                    runtime_budget,
                    actor_receipt: None,
                },
                Some(&budget_context(last_send_after)),
                4,
                ToolOutputLimits {
                    per_call_bytes: u64::MAX,
                    per_run_bytes: u64::MAX,
                },
                state.tool_output_bytes,
            )
            .expect("prepare completion");
            let history_output = match &completion.history_output {
                HistoryItem::FunctionCallOutput { output, .. } => output.clone(),
                other => panic!("unexpected history item: {other:?}"),
            };
            let staged_event_output = completion.event.output.clone();
            let mut staging = TurnBatchStaging::new(state.tool_output_bytes);
            staging.push(completion);
            let prepared =
                prepare_turn_history_batch(&history, 1, &staging).expect("prepare history");
            commit_turn_history_batch(
                &mut state,
                &mut history,
                &mut receipt,
                prepared,
                staging,
                None,
            )
            .expect("commit completion");
            let events = std::fs::read_to_string(directory.path().join("events.jsonl"))
                .expect("read events");
            let event: serde_json::Value =
                serde_json::from_str(events.lines().last().expect("event line"))
                    .expect("event json");
            let event_output = event["data"]["output"]
                .as_str()
                .expect("event output")
                .to_owned();
            assert_eq!(event_output, staged_event_output);
            (history_output, event_output)
        }

        let (ample_history, ample_event) = settle(None, Duration::from_secs(120));
        assert_eq!(ample_history, "status: running");
        assert_eq!(ample_event, ample_history);

        let (clamped_history, clamped_event) = settle(
            Some(ToolRuntimeBudget::wait_clamped()),
            Duration::from_secs(30),
        );
        assert_eq!(clamped_event, clamped_history);
        assert!(clamped_history.contains("[runtime_budget wall_remaining_ms="));
        assert!(
            clamped_history.contains(
                "provider_turns_remaining=2 final_send_reserve_ms=30000 wait_clamped=true;"
            )
        );

        let (low_history, low_event) = settle(None, Duration::from_secs(30));
        assert_eq!(low_event, low_history);
        assert!(low_history.contains("wait_clamped=false;"));
    }

    #[test]
    fn runtime_budget_footer_counts_against_per_call_and_per_run_output_caps() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state = super::RunState::new(writer, &spec, "a".repeat(64), v3_emission());
        state.tool_output_bytes = 16;
        let call = FunctionCall {
            call_id: "call-capped-footer".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{}".to_owned(),
        };
        let mut history = vec![HistoryItem::FunctionCall {
            call_id: call.call_id.clone(),
            name: call.name.clone(),
            arguments_json: call.arguments_json.clone(),
        }];
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
        let completion = prepare_tool_completion(
            &state,
            &call,
            ToolResult {
                execution_attempted: true,
                outcome: nano_types::event::ToolOutcome::Succeeded,
                output: "x".repeat(256),
                media: None,
                runtime_budget: Some(ToolRuntimeBudget::wait_clamped()),
                actor_receipt: None,
            },
            Some(&budget_context(Duration::from_secs(30))),
            4,
            ToolOutputLimits {
                per_call_bytes: 96,
                per_run_bytes: 80,
            },
            state.tool_output_bytes,
        )
        .expect("prepare capped completion");
        let output = match &completion.history_output {
            HistoryItem::FunctionCallOutput { output, .. } => output,
            other => panic!("unexpected history item: {other:?}"),
        };
        assert_eq!(output.len(), 64);
        assert!(output.contains("output truncated"));
        assert!(output.ends_with("bounded check]"));
        assert_eq!(state.tool_output_bytes, 16);
        let mut staging = TurnBatchStaging::new(state.tool_output_bytes);
        staging.push(completion);
        let prepared =
            prepare_turn_history_batch(&history, 0, &staging).expect("prepare history batch");
        commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            None,
        )
        .expect("commit capped completion");
        assert_eq!(state.tool_output_bytes, 80);
    }

    #[test]
    fn history_commit_equality_is_typed_deadline_failure_before_next_send() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state = super::RunState::new(writer, &spec, "a".repeat(64), v3_emission());
        state.provider_turn_count = 1;
        let call = FunctionCall {
            call_id: "call-at-history-cutoff".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{}".to_owned(),
        };
        let history_cutoff = Instant::now();
        let context = budget_context(Duration::from_secs(30));
        let mut history = vec![HistoryItem::FunctionCall {
            call_id: call.call_id.clone(),
            name: call.name.clone(),
            arguments_json: call.arguments_json.clone(),
        }];
        let before = history.clone();
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
        let completion = prepare_tool_completion(
            &state,
            &call,
            ToolResult::succeeded("must-not-commit"),
            Some(&context),
            4,
            ToolOutputLimits {
                per_call_bytes: u64::MAX,
                per_run_bytes: u64::MAX,
            },
            state.tool_output_bytes,
        )
        .expect("staging before cutoff does not publish");
        let mut staging = TurnBatchStaging::new(state.tool_output_bytes);
        staging.push(completion);
        let prepared = prepare_turn_history_batch(&history, 0, &staging).expect("prepared history");
        let error = commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            Some(history_cutoff),
        )
        .expect_err("equality is expired");
        let CommitTurnHistoryError::Deadline(error) = error else {
            panic!("expected deadline");
        };
        assert_eq!(
            error.status,
            nano_types::event::TerminalStatus::DeadlineFailure
        );
        assert_eq!(
            error.phase,
            Some(nano_types::event::TerminalPhase::Deadline)
        );
        assert_eq!(error.code, "tool_history_commit_deadline_exceeded");
        assert_eq!(history, before);
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert!(!events.contains("\"type\":\"tool.completed\""));
        assert!(!events.contains("\"type\":\"provider.requested\""));
    }

    #[test]
    fn invalid_media_preparation_has_no_completion_or_history_side_effect() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["read_file"]);
        let state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let call = FunctionCall {
            call_id: "call-invalid-media".to_owned(),
            name: "read_file".to_owned(),
            arguments_json: "{}".to_owned(),
        };
        let bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        let history = Vec::<HistoryItem>::new();
        let error = prepare_tool_completion(
            &state,
            &call,
            ToolResult {
                execution_attempted: true,
                outcome: nano_types::event::ToolOutcome::Succeeded,
                output: "must-not-commit".to_owned(),
                media: Some(Box::new(ToolMedia::new(
                    String::new(),
                    MediaType::Png,
                    1,
                    1,
                    u64::try_from(bytes.len()).expect("length"),
                    format!("{:x}", sha2::Sha256::digest(&bytes)),
                    format!("{:x}", sha2::Sha256::digest(&bytes)),
                    bytes,
                ))),
                runtime_budget: None,
                actor_receipt: None,
            },
            None,
            4,
            ToolOutputLimits {
                per_call_bytes: u64::MAX,
                per_run_bytes: u64::MAX,
            },
            state.tool_output_bytes,
        )
        .expect_err("media must fail before commit");

        assert_eq!(error.code, "runtime_media_attachment_invalid");
        assert!(history.is_empty());
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert!(!events.contains("\"type\":\"tool.completed\""));
    }

    struct FailingRemoteExecutor;

    impl ToolExecutor for FailingRemoteExecutor {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            Ok(())
        }

        async fn execute(
            &mut self,
            _call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            Err(ToolExecutionError::incomplete(
                "external_stdio_response_eof",
            ))
        }
    }

    struct ClassifiedFailingExecutor(ToolExecutionError);

    impl ToolExecutor for ClassifiedFailingExecutor {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            Ok(())
        }

        async fn execute(
            &mut self,
            _call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            Err(self.0.clone())
        }
    }

    struct ReceiptExecutor(Result<ToolResult, ToolExecutionError>);

    impl ToolExecutor for ReceiptExecutor {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            Ok(())
        }

        async fn execute(
            &mut self,
            _call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn completed_and_fatal_actor_receipts_are_durable_without_result_drift() {
        for fatal in [false, true] {
            let directory = tempfile::tempdir().expect("event directory");
            let writer = EventWriter::create(
                directory.path(),
                "run-selected",
                "trial-selected",
                "attempt-0",
                EventWriterLimits {
                    max_events: 8,
                    max_line_bytes: 4096,
                    max_log_bytes: 16_384,
                    max_run_record_bytes: 4096,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec!["run_terminal_command"]);
            let mut state = super::RunState::new(writer, &spec, "a".repeat(64), v3_emission());
            state.tool_call_count = 1;
            let receipt = if fatal {
                actor_receipt(
                    ExternalTerminalActorPhaseV1::Cleanup,
                    ExternalTerminalActorOriginV1::Actor,
                    ExternalTerminalActorSubtypeV1::CleanupUnverified,
                    Some(false),
                    Some(true),
                )
            } else {
                actor_receipt(
                    ExternalTerminalActorPhaseV1::MetaValidate,
                    ExternalTerminalActorOriginV1::Actor,
                    ExternalTerminalActorSubtypeV1::Completed,
                    Some(true),
                    Some(true),
                )
            };
            let settlement = if fatal {
                Err(ToolExecutionError::cleanup(
                    "terminal_actor_cleanup_unverified",
                    true,
                    Some(false),
                    Some(true),
                )
                .with_actor_receipt(Some(receipt.clone())))
            } else {
                Ok(ToolResult::succeeded("model-visible-output")
                    .with_actor_receipt(Some(receipt.clone())))
            };
            let mut executor = ReceiptExecutor(settlement);
            let call = FunctionCall {
                call_id: "call-receipt".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: "{}".to_owned(),
            };
            let cancellation = super::RunCancellation::new();
            let observed = settle_tool_call(
                &mut state,
                &mut executor,
                &BTreeSet::from(["run_terminal_command"]),
                &call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 1,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes: 0,
                },
            )
            .await;
            let terminal = if fatal {
                Some(observed.as_ref().expect_err("fatal settlement").clone())
            } else {
                None
            };
            if fatal {
                assert!(terminal.is_some());
            } else {
                let completion = observed.expect("completed settlement");
                assert_eq!(completion.event.output, "model-visible-output");
                assert!(!completion.event.output.contains("actor_receipt"));
                let mut history = vec![HistoryItem::FunctionCall {
                    call_id: call.call_id.clone(),
                    name: call.name.clone(),
                    arguments_json: call.arguments_json.clone(),
                }];
                let mut policy_receipt =
                    nano_provider_xai::apply_media_history_policy(&mut history)
                        .expect("policy receipt");
                let mut staging = TurnBatchStaging::new(0);
                staging.push(completion);
                let prepared =
                    prepare_turn_history_batch(&history, 0, &staging).expect("prepared history");
                commit_turn_history_batch(
                    &mut state,
                    &mut history,
                    &mut policy_receipt,
                    prepared,
                    staging,
                    None,
                )
                .expect("committed completion and receipt");
            }
            let before_finalization =
                std::fs::read_to_string(directory.path().join("events.jsonl"))
                    .expect("pre-finalization events");
            assert!(
                !before_finalization.contains("\"type\":\"tool.receipt\""),
                "receipt remains in bounded memory until finalization"
            );
            if let Some(terminal) = terminal {
                let _ = state.finalize_once(terminal);
            } else {
                state
                    .finalize_once(super::TerminalOutcome::success())
                    .expect("committed success");
            }

            let event_bytes = std::fs::read(directory.path().join("events.jsonl")).expect("events");
            let receipt_event = event_bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| {
                    serde_json::from_slice::<nano_types::event::Event>(line).expect("event")
                })
                .find_map(|event| match event.body {
                    nano_types::event::EventBody::ToolReceipt(receipt) => Some(receipt),
                    _ => None,
                })
                .expect("durable receipt event");
            assert_eq!(receipt_event.phase, receipt.phase);
            assert_eq!(receipt_event.origin, receipt.origin);
            assert_eq!(receipt_event.primary_subtype, receipt.primary_subtype);
            assert_eq!(receipt_event.recovery_subtype, receipt.recovery_subtype);
            assert_eq!(
                receipt_event.receipt_digest_sha256,
                receipt.diagnostic_digest_sha256
            );
            assert_eq!(
                receipt_event.tool_identity_sha256,
                tool_receipt_identity_sha256("call-receipt", "run_terminal_command")
                    .expect("identity digest")
            );
            assert_eq!(receipt_event.tool_call_ordinal, 1);
            let event_types = event_bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| {
                    serde_json::from_slice::<serde_json::Value>(line).expect("event value")["type"]
                        .as_str()
                        .expect("event type")
                        .to_owned()
                })
                .collect::<Vec<_>>();
            assert_eq!(event_types[event_types.len() - 2], "tool.receipt");
            assert!(matches!(
                event_types.last().map(String::as_str),
                Some("run.completed" | "run.failed")
            ));
            let run: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.path().join("run.json")).expect("run record"),
            )
            .expect("run json");
            assert_eq!(
                run["events_sha256"],
                format!("{:x}", Sha256::digest(&event_bytes))
            );
        }
    }

    #[tokio::test]
    async fn saturated_receipt_telemetry_never_preempts_mandatory_tool_settlement() {
        for fatal in [false, true] {
            let directory = tempfile::tempdir().expect("event directory");
            let writer = EventWriter::create(
                directory.path(),
                "run-selected",
                "trial-selected",
                "attempt-0",
                EventWriterLimits {
                    max_events: 4,
                    max_line_bytes: 4096,
                    max_log_bytes: 16_384,
                    max_run_record_bytes: 4096,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec!["run_terminal_command"]);
            let mut state = super::RunState::new(writer, &spec, "a".repeat(64), v3_emission());
            state.tool_call_count = 1;
            let receipt = actor_receipt(
                if fatal {
                    ExternalTerminalActorPhaseV1::Cleanup
                } else {
                    ExternalTerminalActorPhaseV1::MetaValidate
                },
                ExternalTerminalActorOriginV1::Actor,
                if fatal {
                    ExternalTerminalActorSubtypeV1::CleanupUnverified
                } else {
                    ExternalTerminalActorSubtypeV1::Completed
                },
                Some(!fatal),
                Some(true),
            );
            let settlement = if fatal {
                Err(ToolExecutionError::cleanup(
                    "terminal_actor_cleanup_unverified",
                    true,
                    Some(false),
                    Some(true),
                )
                .with_actor_receipt(Some(receipt)))
            } else {
                Ok(ToolResult::succeeded("model-visible-output").with_actor_receipt(Some(receipt)))
            };
            let mut executor = ReceiptExecutor(settlement);
            let call = FunctionCall {
                call_id: "call-receipt".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: "{}".to_owned(),
            };
            let cancellation = super::RunCancellation::new();
            let observed = settle_tool_call(
                &mut state,
                &mut executor,
                &BTreeSet::from(["run_terminal_command"]),
                &call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 1,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes: 0,
                },
            )
            .await;
            if fatal {
                let terminal = observed.expect_err("fatal settlement");
                assert_eq!(terminal.code, "terminal_actor_cleanup_unverified");
                let final_error = state
                    .finalize_once(terminal)
                    .expect_err("terminal failure remains original");
                assert_eq!(final_error.code(), "terminal_actor_cleanup_unverified");
            } else {
                let completion = observed.expect("completed settlement");
                let mut history = vec![HistoryItem::FunctionCall {
                    call_id: call.call_id.clone(),
                    name: call.name.clone(),
                    arguments_json: call.arguments_json.clone(),
                }];
                let mut policy_receipt =
                    nano_provider_xai::apply_media_history_policy(&mut history)
                        .expect("policy receipt");
                let mut staging = TurnBatchStaging::new(0);
                staging.push(completion);
                let prepared =
                    prepare_turn_history_batch(&history, 0, &staging).expect("prepared history");
                commit_turn_history_batch(
                    &mut state,
                    &mut history,
                    &mut policy_receipt,
                    prepared,
                    staging,
                    None,
                )
                .expect("mandatory completion must win");
                state
                    .finalize_once(super::TerminalOutcome::success())
                    .expect("terminal success");
            }
            let events =
                std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
            assert!(events.contains(if fatal {
                "\"type\":\"tool.failed\""
            } else {
                "\"type\":\"tool.completed\""
            }));
            assert!(!events.contains("\"type\":\"tool.receipt\""));
            assert!(events.contains("\"tool_receipt_omitted_count\":1"));
        }
    }

    #[test]
    fn staged_receipt_count_overflow_is_bounded_and_preserves_terminal_outcome() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run-selected",
            "trial-selected",
            "attempt-0",
            EventWriterLimits {
                max_events: 257,
                max_line_bytes: 4096,
                max_log_bytes: 512 * 1024,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state = super::RunState::new(writer, &spec, "a".repeat(64), v3_emission());
        state.tool_call_count = 257;
        for ordinal in 1..=257 {
            state.stage_tool_receipt(ToolReceiptV1 {
                schema_version: TOOL_RECEIPT_V1_SCHEMA.to_owned(),
                phase: ExternalTerminalActorPhaseV1::MetaValidate,
                origin: ExternalTerminalActorOriginV1::Actor,
                primary_subtype: ExternalTerminalActorSubtypeV1::Completed,
                recovery_subtype: None,
                receipt_digest_sha256: "d".repeat(64),
                tool_identity_sha256: tool_receipt_identity_sha256(
                    &format!("call-{ordinal}"),
                    "run_terminal_command",
                )
                .expect("identity digest"),
                tool_call_ordinal: ordinal,
            });
        }
        assert_eq!(state.staged_tool_receipts.len(), 256);
        assert!(state.staged_tool_receipt_bytes <= super::MAX_STAGED_TOOL_RECEIPT_BYTES);
        assert_eq!(state.writer.omitted_tool_receipt_samples(), 1);
        assert!(
            std::fs::read(directory.path().join("events.jsonl"))
                .expect("pre-finalization events")
                .is_empty()
        );

        let outcome = state
            .finalize_once(super::TerminalOutcome::success())
            .expect("selected success remains authoritative");

        assert_eq!(
            outcome.record.terminal_status,
            nano_types::event::TerminalStatus::Success
        );
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains("\"type\":\"tool.receipt\""))
                .count(),
            256
        );
        let terminal: serde_json::Value =
            serde_json::from_str(events.lines().last().expect("terminal event"))
                .expect("terminal json");
        assert_eq!(terminal["type"], "run.completed");
        assert_eq!(terminal["data"]["tool_receipt_omitted_count"], 1);
    }

    #[tokio::test]
    async fn explicit_failure_classes_never_fall_back_to_generic_tool_phase() {
        for (error, expected_status, expected_phase) in [
            (
                ToolExecutionError::deadline("tool_settlement_deadline_exceeded"),
                nano_types::event::TerminalStatus::DeadlineFailure,
                nano_types::event::TerminalPhase::Deadline,
            ),
            (
                ToolExecutionError::bridge("external_stdio_response_eof"),
                nano_types::event::TerminalStatus::ToolFailure,
                nano_types::event::TerminalPhase::Bridge,
            ),
            (
                ToolExecutionError::cleanup(
                    "terminal_actor_cleanup_unverified",
                    true,
                    Some(false),
                    None,
                ),
                nano_types::event::TerminalStatus::ToolFailure,
                nano_types::event::TerminalPhase::Bridge,
            ),
        ] {
            let directory = tempfile::tempdir().expect("event directory");
            let writer = EventWriter::create(
                directory.path(),
                "run",
                "trial",
                "attempt",
                EventWriterLimits {
                    max_events: 8,
                    max_line_bytes: 4096,
                    max_log_bytes: 16_384,
                    max_run_record_bytes: 4096,
                },
            )
            .expect("event writer");
            let spec = selected_spec(vec!["run_terminal_command"]);
            let mut state =
                super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
            let mut executor = ClassifiedFailingExecutor(error);
            let known_tools = BTreeSet::from(["run_terminal_command"]);
            let call = FunctionCall {
                call_id: "call-classified".to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: "{}".to_owned(),
            };
            let cancellation = super::RunCancellation::new();
            let outcome = settle_tool_call(
                &mut state,
                &mut executor,
                &known_tools,
                &call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + Duration::from_secs(1),
                    settlement_deadline: Instant::now() + Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 1,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes: 0,
                },
            )
            .await
            .expect_err("classified failure");
            assert_eq!(outcome.status, expected_status);
            assert_eq!(outcome.phase, Some(expected_phase));
            assert_ne!(outcome.phase, Some(nano_types::event::TerminalPhase::Tool));
        }
    }

    #[tokio::test]
    async fn external_dispatch_failure_finalizes_truthful_prefix_without_tool_completion() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["run_terminal_command"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        state.tool_call_count = 1;
        let history = Vec::<HistoryItem>::new();
        let mut executor = FailingRemoteExecutor;
        let known_tools = BTreeSet::from(["run_terminal_command"]);
        let call = FunctionCall {
            call_id: "call-1".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{}".to_owned(),
        };
        let cancellation = super::RunCancellation::new();
        let error = settle_tool_call(
            &mut state,
            &mut executor,
            &known_tools,
            &call,
            super::ToolExecutionWindow {
                workspace: Path::new("/remote/workspace/does-not-exist"),
                dispatch_cutoff: Instant::now() + std::time::Duration::from_secs(1),
                settlement_deadline: Instant::now() + std::time::Duration::from_secs(1),
                admission_rejection: None,
                cancellation: &cancellation,
                runtime_deadline: None,
                max_provider_turns: 1,
                output_limits: ToolOutputLimits {
                    per_call_bytes: u64::MAX,
                    per_run_bytes: u64::MAX,
                },
                projected_tool_output_bytes: 0,
            },
        )
        .await
        .expect_err("bridge failure");
        assert_eq!(error.code, "external_stdio_response_eof");
        let final_error = state
            .finalize_once(error.clone())
            .expect_err("terminal failure");
        assert_eq!(final_error.code(), "external_stdio_response_eof");
        let repeated = state
            .finalize_once(error)
            .expect_err("same terminal failure");
        assert_eq!(repeated.code(), "external_stdio_response_eof");
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert!(events.contains("\"type\":\"tool.registered\""));
        assert!(events.contains("\"type\":\"tool.dispatched\""));
        assert!(events.contains("\"type\":\"tool.failed\""));
        assert!(events.contains("\"type\":\"run.failed\""));
        assert_eq!(events.matches("\"type\":\"run.failed\"").count(), 1);
        assert!(!events.contains("\"type\":\"tool.completed\""));
        assert!(directory.path().join("run.json").is_file());
        assert!(history.is_empty());
    }

    #[test]
    fn runtime_media_commit_reproduces_four_plus_four_without_erasing_outputs() {
        fn batch(history: &mut Vec<HistoryItem>, first: u64, turn_index: u64) -> TurnBatchStaging {
            let mut staging = TurnBatchStaging::new(0);
            for index in first..first + 4 {
                let call_id = format!("call-{index}");
                let logical_path = format!("frame-{index}.png");
                let arguments_json = format!(r#"{{"target_file":"{logical_path}"}}"#);
                let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
                bytes.extend_from_slice(&index.to_be_bytes());
                let sha256 = format!("{:x}", sha2::Sha256::digest(&bytes));
                history.push(HistoryItem::FunctionCall {
                    call_id: call_id.clone(),
                    name: "read_file".to_owned(),
                    arguments_json: arguments_json.clone(),
                });
                let output = format!(
                    "read_file returned an attached image: image/png, 2x1, sha256={sha256}"
                );
                let history_output = HistoryItem::FunctionCallOutput {
                    call_id: call_id.clone(),
                    output: output.clone(),
                };
                let attachment = HistoryItem::tool_media_attachment_with_origin(
                    call_id.clone(),
                    logical_path,
                    MediaType::Png,
                    2,
                    1,
                    sha256,
                    bytes,
                    turn_index,
                    "read_file",
                )
                .expect("valid runtime attachment");
                staging.push(super::StagedToolCompletion {
                    event: nano_types::event::ToolCompleted {
                        call_id,
                        provider_name: "read_file".to_owned(),
                        execution_attempted: true,
                        outcome: nano_types::event::ToolOutcome::Succeeded,
                        output,
                    },
                    arguments_json,
                    dispatched: false,
                    history_output,
                    attachment: Some(attachment),
                    committed_output_bytes: 0,
                    tool_receipt: None,
                    tool_receipt_omitted: false,
                });
            }
            staging
        }

        let mut history = vec![HistoryItem::User {
            content: "inspect frames".to_owned(),
        }];
        let old = batch(&mut history, 0, 0);
        let prepared =
            prepare_turn_history_batch(&history, 0, &old).expect("first four preparation");
        history = prepared.history;
        history.push(HistoryItem::AssistantMessage {
            text: "inspect the next frames".to_owned(),
        });
        let new = batch(&mut history, 4, 1);
        let prepared =
            prepare_turn_history_batch(&history, 1, &new).expect("second four preparation");
        history = prepared.history;
        let receipt = prepared.receipt;

        assert_eq!(receipt.retained_count(), 4);
        assert_eq!(receipt.evicted_total(), 4);
        assert_eq!(
            history
                .iter()
                .filter_map(|item| match item {
                    HistoryItem::ToolMediaAttachment { attachment } => {
                        Some(attachment.call_id())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ["call-4", "call-5", "call-6", "call-7"]
        );
        assert_eq!(
            history
                .iter()
                .filter(|item| matches!(item, HistoryItem::FunctionCallOutput { .. }))
                .count(),
            8
        );
        assert_eq!(
            history
                .iter()
                .filter(|item| matches!(item, HistoryItem::MediaHistoryEviction { .. }))
                .count(),
            4
        );
    }

    #[test]
    fn same_turn_six_media_commits_completion_history_and_receipt_once() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 16,
                max_line_bytes: 4096,
                max_log_bytes: 32_768,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["read_file"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let mut history = vec![HistoryItem::User {
            content: "inspect six frames".to_owned(),
        }];
        let mut staging = TurnBatchStaging::new(0);
        for index in 0..6_u64 {
            let call_id = format!("call-{index}");
            let logical_path = format!("frame-{index}.png");
            let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
            bytes.extend_from_slice(&index.to_be_bytes());
            let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
            let output =
                format!("read_file returned an attached image: image/png, 2x1, sha256={digest}");
            history.push(HistoryItem::FunctionCall {
                call_id: call_id.clone(),
                name: "read_file".to_owned(),
                arguments_json: format!(r#"{{"target_file":"{logical_path}"}}"#),
            });
            let mut completion = staged_text_completion(&call_id, "read_file", &output);
            completion.attachment = Some(
                HistoryItem::tool_media_attachment_with_origin(
                    call_id,
                    logical_path,
                    MediaType::Png,
                    2,
                    1,
                    digest,
                    bytes,
                    5,
                    "read_file",
                )
                .expect("attachment"),
            );
            staging.push(completion);
        }
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("initial receipt");
        let prepared =
            prepare_turn_history_batch(&history, 5, &staging).expect("prepare six-image turn");
        commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            None,
        )
        .expect("atomic turn commit");

        assert_eq!(receipt.retained_count(), 4);
        assert_eq!(receipt.evicted_total(), 2);
        assert_eq!(
            history
                .iter()
                .filter(|item| matches!(item, HistoryItem::FunctionCallOutput { .. }))
                .count(),
            6
        );
        assert_eq!(
            history
                .iter()
                .filter(|item| matches!(item, HistoryItem::ToolMediaAttachment { .. }))
                .count(),
            4
        );
        assert_eq!(
            history
                .iter()
                .filter(|item| matches!(item, HistoryItem::MediaHistoryEviction { .. }))
                .count(),
            2
        );
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 6);
        assert!(!events.contains("data:image"));
    }

    #[test]
    fn same_turn_media_fault_matrix_leaves_no_completion_batch() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["read_file"]);
        let state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let call_id = "call-media";
        let bytes = b"\x89PNG\r\n\x1a\nabc".to_vec();
        let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
        let history = vec![HistoryItem::FunctionCall {
            call_id: call_id.to_owned(),
            name: "read_file".to_owned(),
            arguments_json: r#"{"target_file":"frame.png"}"#.to_owned(),
        }];
        let before = serde_json::to_vec(&history).expect("base bytes");
        let mut staging = TurnBatchStaging::new(0);
        let mut completion =
            staged_text_completion(call_id, "read_file", "wrong media binding output");
        completion.attachment = Some(
            HistoryItem::tool_media_attachment_with_origin(
                call_id,
                "frame.png",
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
        staging.push(completion);

        prepare_turn_history_batch(&history, 0, &staging)
            .expect_err("wrong output/digest binding must reject whole batch");
        assert_eq!(serde_json::to_vec(&history).expect("base replay"), before);
        assert_eq!(state.tool_output_bytes, 0);
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert!(!events.contains("\"type\":\"tool.completed\""));
    }

    struct RejectingPreflightProvider;

    impl Provider for RejectingPreflightProvider {
        fn preflight(
            &self,
            _request: nano_provider_xai::TurnRequest,
        ) -> Result<PreparedTurnRequest, ProviderFailure> {
            Err(ProviderFailure::new("provider_request_body_too_large"))
        }

        async fn send(
            &mut self,
            _request: PreparedTurnRequest,
        ) -> Result<CompletedTurn, ProviderFailure> {
            panic!("rejected preflight must never send")
        }
    }

    #[test]
    fn same_turn_completion_commits_before_next_provider_preflight() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["grep"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let call_id = "call-text";
        let mut history = vec![HistoryItem::FunctionCall {
            call_id: call_id.to_owned(),
            name: "grep".to_owned(),
            arguments_json: r#"{"pattern":"x"}"#.to_owned(),
        }];
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
        let mut staging = TurnBatchStaging::new(0);
        staging.push(staged_text_completion(call_id, "grep", "result"));
        let prepared = prepare_turn_history_batch(&history, 0, &staging).expect("prepared history");
        commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            None,
        )
        .expect("truthful completion commits first");
        let tools = vec![FunctionTool {
            name: "grep".to_owned(),
            description: "grep".to_owned(),
            parameters: serde_json::json!({"type": "object"}),
        }];

        let error = prepare_pending_provider_request(
            &RejectingPreflightProvider,
            &spec,
            &tools,
            ProviderRequestMode::ActionOpen,
            1,
            ProviderRequestEvidence {
                history: &history,
                media_history_receipt: &receipt,
                budget_observation: None,
            },
        )
        .err()
        .expect("preflight reject");
        assert_eq!(error.code(), "provider_request_body_too_large");
        assert_eq!(state.tool_output_bytes, 6);
        assert_eq!(history.len(), 2);
        assert!(matches!(
            history.last(),
            Some(HistoryItem::FunctionCallOutput { call_id, output })
                if call_id == "call-text" && output == "result"
        ));
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 1);
        assert!(!directory.path().join("run.json").exists());
    }

    #[test]
    fn challenge_preflight_rejection_finalizes_the_staged_candidate() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["grep"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let mut history = vec![HistoryItem::User {
            content: "challenge".to_owned(),
        }];
        let receipt = nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
        let failure = prepare_pending_provider_request(
            &RejectingPreflightProvider,
            &spec,
            &[],
            ProviderRequestMode::ActionOpen,
            1,
            ProviderRequestEvidence {
                history: &history,
                media_history_receipt: &receipt,
                budget_observation: None,
            },
        )
        .err()
        .expect("preflight rejection");
        assert_eq!(failure.code(), "provider_request_body_too_large");

        let mut challenge = CompletionChallengeState {
            phase: CompletionReviewPhase::Validation,
            provisional_final: Some("candidate".to_owned()),
            workspace_mutated: false,
        };
        let outcome = finalize_provisional(&mut state, &mut challenge)
            .expect("staged provisional")
            .expect("successful fallback");

        assert_eq!(outcome.record.provider_call_coverage.requested, 0);
        assert_eq!(outcome.record.provider_call_coverage.failed, 0);
        assert!(challenge.provisional_final.is_none());
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"provider.requested\"").count(), 0);
        assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 0);
        assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
        assert_eq!(events.matches("\"type\":\"run.completed\"").count(), 1);
        assert!(events.contains("\"text\":\"candidate\""));
    }

    #[test]
    fn same_turn_staging_preserves_per_call_and_per_run_output_caps() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 8,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["grep"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let limits = ToolOutputLimits {
            per_call_bytes: 48,
            per_run_bytes: 80,
        };
        state.tool_output_bytes = 16;
        let mut staging = TurnBatchStaging::new(state.tool_output_bytes);
        for call_id in ["call-a", "call-b"] {
            let call = FunctionCall {
                call_id: call_id.to_owned(),
                name: "grep".to_owned(),
                arguments_json: "{}".to_owned(),
            };
            let completion = prepare_tool_completion(
                &state,
                &call,
                ToolResult::succeeded("x".repeat(256)),
                None,
                4,
                limits,
                staging.projected_tool_output_bytes,
            )
            .expect("bounded staged completion");
            staging.push(completion);
        }
        let lengths = staging
            .completions
            .iter()
            .map(|completion| usize::try_from(completion.committed_output_bytes).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(lengths, [48, 16]);
        assert_eq!(staging.projected_tool_output_bytes, 80);
        assert_eq!(state.tool_output_bytes, 16);
    }

    #[test]
    fn same_turn_completion_writer_failure_never_publishes_run_record() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 2,
                max_line_bytes: 4096,
                max_log_bytes: 16_384,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["grep"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let mut history = ["call-a", "call-b"]
            .into_iter()
            .map(|call_id| HistoryItem::FunctionCall {
                call_id: call_id.to_owned(),
                name: "grep".to_owned(),
                arguments_json: "{}".to_owned(),
            })
            .collect::<Vec<_>>();
        let before = history.clone();
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("receipt");
        let mut staging = TurnBatchStaging::new(0);
        staging.push(staged_text_completion("call-a", "grep", "a"));
        staging.push(staged_text_completion("call-b", "grep", "b"));
        let prepared =
            prepare_turn_history_batch(&history, 0, &staging).expect("prepare two completions");

        let error = commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            None,
        )
        .expect_err("second append exhausts terminal reserve");
        assert!(matches!(error, CommitTurnHistoryError::Writer(_)));
        assert_eq!(history, before);
        assert_eq!(state.tool_output_bytes, 0);
        assert!(!directory.path().join("run.json").exists());
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 1);
    }

    struct MixedMediaExecutor;

    impl ToolExecutor for MixedMediaExecutor {
        fn workspace_mode(&self) -> WorkspaceMode {
            WorkspaceMode::RemoteLogical
        }

        fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
            Ok(())
        }

        async fn execute(
            &mut self,
            call: &FunctionCall,
            _workspace: &Path,
            _deadline: Instant,
        ) -> Result<ToolResult, ToolExecutionError> {
            if call.name == "read_file" {
                let bytes = vec![137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3];
                Ok(ToolResult {
                    execution_attempted: true,
                    outcome: nano_types::event::ToolOutcome::Succeeded,
                    output: concat!(
                        "read_file returned an attached image: image/png, 2x1, ",
                        "sha256=7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8"
                    )
                    .to_owned(),
                    media: Some(Box::new(ToolMedia::new(
                        "board.png".to_owned(),
                        MediaType::Png,
                        2,
                        1,
                        11,
                        "7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8"
                            .to_owned(),
                        "7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8"
                            .to_owned(),
                        bytes,
                    ))),
                    runtime_budget: None,
                    actor_receipt: None,
                })
            } else {
                Ok(ToolResult::succeeded("text result"))
            }
        }
    }

    #[tokio::test]
    async fn mixed_turn_appends_all_function_outputs_before_media_without_blob_events() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(
            directory.path(),
            "run",
            "trial",
            "attempt",
            EventWriterLimits {
                max_events: 16,
                max_line_bytes: 4096,
                max_log_bytes: 32_768,
                max_run_record_bytes: 4096,
            },
        )
        .expect("event writer");
        let spec = selected_spec(vec!["read_file", "grep"]);
        let mut state =
            super::RunState::new(writer, &spec, "a".repeat(64), super::RunRecordEmission::V2);
        let calls = [
            FunctionCall {
                call_id: "call-image".to_owned(),
                name: "read_file".to_owned(),
                arguments_json: r#"{"target_file":"board.png"}"#.to_owned(),
            },
            FunctionCall {
                call_id: "call-text".to_owned(),
                name: "grep".to_owned(),
                arguments_json: r#"{"pattern":"x"}"#.to_owned(),
            },
        ];
        let known_tools = BTreeSet::from(["read_file", "grep"]);
        let cancellation = super::RunCancellation::new();
        let mut executor = MixedMediaExecutor;
        let mut history = calls
            .iter()
            .map(|call| HistoryItem::FunctionCall {
                call_id: call.call_id.clone(),
                name: call.name.clone(),
                arguments_json: call.arguments_json.clone(),
            })
            .collect::<Vec<_>>();
        let mut receipt =
            nano_provider_xai::apply_media_history_policy(&mut history).expect("initial receipt");
        let mut staging = TurnBatchStaging::new(state.tool_output_bytes);
        for call in &calls {
            let completion = settle_tool_call(
                &mut state,
                &mut executor,
                &known_tools,
                call,
                super::ToolExecutionWindow {
                    workspace: Path::new("/remote/workspace"),
                    dispatch_cutoff: Instant::now() + std::time::Duration::from_secs(1),
                    settlement_deadline: Instant::now() + std::time::Duration::from_secs(1),
                    admission_rejection: None,
                    cancellation: &cancellation,
                    runtime_deadline: None,
                    max_provider_turns: 1,
                    output_limits: ToolOutputLimits {
                        per_call_bytes: u64::MAX,
                        per_run_bytes: u64::MAX,
                    },
                    projected_tool_output_bytes: staging.projected_tool_output_bytes,
                },
            )
            .await
            .expect("settled tool");
            staging.push(completion);
        }
        let prepared =
            prepare_turn_history_batch(&history, 0, &staging).expect("prepare mixed batch");
        commit_turn_history_batch(
            &mut state,
            &mut history,
            &mut receipt,
            prepared,
            staging,
            None,
        )
        .expect("commit mixed batch");

        assert_eq!(
            history
                .iter()
                .filter_map(|item| match item {
                    HistoryItem::FunctionCallOutput { call_id, .. } => Some(call_id.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ["call-image", "call-text"]
        );
        assert_eq!(
            history
                .iter()
                .filter_map(|item| match item {
                    HistoryItem::ToolMediaAttachment { attachment } => {
                        Some(attachment.call_id())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ["call-image"]
        );
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        assert!(
            events.contains("7f47b756761a46e6d4a4d96f0d8a4448f8449235009d1f3ad1493f5c773c19e8")
        );
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 2);
        assert!(!events.contains("iVBORw0KGgoBAgM="));
        assert!(!events.contains("data:image"));
    }
}
