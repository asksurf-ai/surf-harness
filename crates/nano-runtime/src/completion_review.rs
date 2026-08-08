//! Optional, host-selected review of a provisional final response.

use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use nano_provider_xai::HistoryItem;
use nano_types::event::{ToolCompleted, ToolOutcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::finish_controller::FreshCriticCapacity;
use crate::finish_controller::SOFT_FINISH_PROVIDER_TURN_V1;
use crate::foreground::truncate_utf8;

const MAX_PROMPT_BYTES: usize = 2048;
const REQUEST_EXCERPT_BYTES: usize = 128;
const CANDIDATE_EXCERPT_BYTES: usize = 128;
const TERMINAL_EXCERPT_BYTES: usize = 192;
const EVIDENCE_DEBT_BYTES: usize = 512;
const FRESH_REQUEST_EXCERPT_BYTES: usize = 4096;
const FRESH_CANDIDATE_EXCERPT_BYTES: usize = 2048;
const FRESH_TERMINAL_EXCERPT_BYTES: usize = 512;
const FRESH_CRITIC_ADVICE_BYTES: usize = 1024;
const CONTEXT_CHECKPOINT_EVIDENCE_BYTES: usize = 2048;
const SEMANTIC_CHECKPOINT_CAPSULE_BYTES_V1: usize = 8192;
const SEMANTIC_CHECKPOINT_SCALAR_BYTES_V1: usize = 768;
const SEMANTIC_CHECKPOINT_ITEM_BYTES_V1: usize = 256;
const SEMANTIC_CHECKPOINT_LIST_ITEMS_V1: usize = 3;
const CONTEXT_CHECKPOINT_MIN_PROVIDER_TURNS_V1: u64 = 12;
const CONTEXT_CHECKPOINT_MIN_INPUT_TOKENS_V1: u64 = 250_000;
const CONTEXT_CHECKPOINT_MIN_HISTORY_ITEMS_V1: u64 = 32;
const CONTEXT_CHECKPOINT_MIN_REMAINING_TURNS_V1: u64 = 12;
const SEMANTIC_CHECKPOINT_MIN_REMAINING_TURNS_V1: u64 = 13;
const SEMANTIC_CHECKPOINT_POST_PREPARE_MIN_REMAINING_TURNS_V1: u64 = 12;
const CONTEXT_CHECKPOINT_POST_RESET_RESERVE_V1: Duration = Duration::from_secs(120);
const SEMANTIC_CHECKPOINT_PREPARE_RESERVE_V1: Duration = Duration::from_secs(90);
const SEMANTIC_CHECKPOINT_ACTION_PROVIDER_RESERVE_V1: Duration = Duration::from_secs(90);
const SEMANTIC_CHECKPOINT_PROVISIONAL_RESERVE_V1: Duration = Duration::from_secs(90);
const SEMANTIC_CHECKPOINT_MIN_ACTION_RESERVE_V1: Duration = Duration::from_secs(120);
const RECENT_TOOL_FACTS: usize = 6;
pub(crate) const CONTEXT_CHECKPOINT_POLICY_VERSION_V1: &str = "fresh-context-checkpoint-v1";
pub(crate) const SEMANTIC_CHECKPOINT_POLICY_VERSION_V1: &str = "semantic-context-checkpoint-v1";
pub(crate) const SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1: &str = "semantic-checkpoint-capsule-v1";
pub(crate) const SEMANTIC_CHECKPOINT_CONTROL_TOOL_V1: &str = "record_semantic_checkpoint_v1";
/// Frozen V10 final-response admission reserve.
///
/// This is task-neutral and was selected offline from 2,775 completed V9
/// provider turns: p50=5.286s, p90=24.795s, p95=34.563s, p99=81.893s.
/// Rounding the observed p99 up to 90 seconds leaves a bounded serialization
/// margin without changing the signed task or Harbor deadline.
pub(crate) const FINAL_RESPONSE_LATENCY_RESERVE_V1: Duration = Duration::from_secs(90);
/// One bounded review tool stage. The runtime does not extend this reserve
/// from task identity, reward, verifier output, or prior task outcomes.
pub(crate) const REVIEW_BOUNDED_TOOL_RESERVE_V1: Duration = Duration::from_secs(120);
const FRESH_CRITIC_SYSTEM_PROMPT: &str = "\
You are an isolated completion critic. You have no tools and no access to the actor's hidden \
reasoning. Assess only the supplied request, candidate, and bounded execution evidence. Identify \
one acceptance claim with the weakest independent evidence. Do not solve the task, propose broad \
improvements, repeat a checklist, or invent facts. Return only a concise claim, reason, and one \
high-signal falsification check; say that existing evidence is sufficient when it is.";
pub(crate) const COMPLETION_REVIEW_DECISION_PROMPT: &str = "<completion_review_decision_v2>\n\
The single validation phase is complete. Decide from that evidence now. If it shows no objective \
mismatch, return a concise final without tools. If it shows an objective mismatch, use one \
self-contained correction response. Its serialized tool batch must contain the complete safe \
replacement or change. Preserve the last known good artifact or service until the replacement is \
ready; never split teardown and replacement or restart across provider responses. After \
correction, only read-only revalidation is permitted. Do not begin another exploratory \
validation.\n\
</completion_review_decision_v2>";

/// A generic completion-review behavior selected by the composition root.
///
/// Runtime entry points default to `Disabled`; integrations must opt in
/// explicitly. The policy contains no benchmark, task, scorer, or verifier
/// concepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CompletionReviewPolicy {
    #[default]
    Disabled,
    IndependentFalsificationV1,
    EvidenceDebtV2,
    FreshEvidenceDebtV3,
    FreshCheckpointV4,
    SemanticCheckpointV6,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CompletionReviewCapacity {
    pub now: Instant,
    pub last_send: Instant,
    pub provider_turn_count: u64,
    pub max_provider_turns: u64,
    pub history_items: usize,
    pub max_history_items: u64,
}

pub(crate) fn review_required_reserve_v1(policy: CompletionReviewPolicy) -> Option<Duration> {
    let (provider_stages, tool_stages) = match policy {
        CompletionReviewPolicy::Disabled => return None,
        CompletionReviewPolicy::IndependentFalsificationV1
        | CompletionReviewPolicy::EvidenceDebtV2 => (2, 1),
        // critic + validation + correction/revalidation, followed by final-only
        CompletionReviewPolicy::FreshEvidenceDebtV3
        | CompletionReviewPolicy::FreshCheckpointV4
        | CompletionReviewPolicy::SemanticCheckpointV6 => (3, 2),
    };
    FINAL_RESPONSE_LATENCY_RESERVE_V1
        .checked_mul(provider_stages)
        .and_then(|provider| {
            REVIEW_BOUNDED_TOOL_RESERVE_V1
                .checked_mul(tool_stages)
                .and_then(|tools| provider.checked_add(tools))
        })
        .and_then(|review| review.checked_add(FINAL_RESPONSE_LATENCY_RESERVE_V1))
}

impl CompletionReviewPolicy {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::IndependentFalsificationV1 => "independent-falsification-v1",
            Self::EvidenceDebtV2 => "evidence-debt-v2",
            Self::FreshEvidenceDebtV3 => "fresh-evidence-debt-v3",
            Self::FreshCheckpointV4 => "fresh-checkpoint-v4",
            Self::SemanticCheckpointV6 => "semantic-checkpoint-v6",
        }
    }

    pub(crate) fn checkpoint_policy_version(self) -> Option<&'static str> {
        match self {
            Self::FreshCheckpointV4 => Some(CONTEXT_CHECKPOINT_POLICY_VERSION_V1),
            Self::SemanticCheckpointV6 => Some(SEMANTIC_CHECKPOINT_POLICY_VERSION_V1),
            _ => None,
        }
    }

    pub(crate) fn checkpoint_capsule_schema_version(self) -> Option<&'static str> {
        self.uses_semantic_checkpoint()
            .then_some(SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1)
    }

    pub(crate) fn has_capacity(self, capacity: CompletionReviewCapacity) -> bool {
        if self == Self::Disabled {
            return false;
        }
        let required_turns = match self {
            Self::Disabled => return false,
            Self::IndependentFalsificationV1 | Self::EvidenceDebtV2 => 2,
            Self::FreshEvidenceDebtV3 | Self::FreshCheckpointV4 | Self::SemanticCheckpointV6 => 4,
        };
        let enough_turns = capacity
            .max_provider_turns
            .saturating_sub(capacity.provider_turn_count)
            >= required_turns;
        let required_history_items = if self.uses_fresh_context() { 4 } else { 1 };
        let enough_history = u64::try_from(capacity.history_items)
            .ok()
            .is_some_and(|items| {
                capacity
                    .max_history_items
                    .checked_sub(items)
                    .is_some_and(|remaining| remaining >= required_history_items)
            });
        let enough_time = review_required_reserve_v1(self)
            .and_then(|required| {
                capacity
                    .last_send
                    .checked_duration_since(capacity.now)
                    .map(|remaining| remaining > required)
            })
            .unwrap_or(false);
        enough_turns && enough_history && enough_time
    }

    /// Strict admission for the complete fresh-critic path.
    ///
    /// W4 uses this richer check at the serial integration point. The legacy
    /// `has_capacity` entry remains available to the pre-integration loop.
    pub fn has_fresh_path_capacity(self, capacity: FreshCriticCapacity) -> bool {
        self.uses_fresh_context()
            && review_required_reserve_v1(self)
                .is_some_and(|required| capacity.has_capacity(required))
    }

    pub(crate) fn prompt(
        self,
        original_request: &str,
        candidate_final: &str,
        recent_terminal_evidence: &str,
        evidence_debt: &CompletionEvidenceLedger,
    ) -> Option<String> {
        if self == Self::Disabled || self.uses_fresh_context() {
            return None;
        }
        let prompt = match self {
            Self::Disabled => return None,
            Self::IndependentFalsificationV1 => format!(
                "<independent_falsification_review_v1>\n\
Choose one high-signal check that could falsify the candidate and does not reuse its key \
assumption. Use the latest observable tool evidence first. If that evidence already passes the \
check, return a concise final without more tools. Otherwise perform only that check. If it shows \
an objective mismatch, correct the work and revalidate; if not, stop. Do not repeat an existing \
checklist.\n\
Original request excerpt:\n{}\n\
Candidate final excerpt:\n{}\n\
Recent terminal evidence:\n{}\n\
</independent_falsification_review_v1>",
                truncate_utf8(original_request, REQUEST_EXCERPT_BYTES),
                truncate_utf8(candidate_final, CANDIDATE_EXCERPT_BYTES),
                truncate_utf8(recent_terminal_evidence, TERMINAL_EXCERPT_BYTES),
            ),
            Self::EvidenceDebtV2 => format!(
                "<evidence_debt_review_v2>\n\
Build an exact acceptance ledger from the original request: user-stated identifiers, paths, \
literal values, ports, services, and required components. Identify the acceptance claim with the \
weakest independent evidence; prefer exact schema or path, boundary or negative behavior, full \
coverage, ordering, or invariants over a familiar success case. Validation must be observational: \
preserve the required final state and the last known good artifact or service. Do not overwrite \
required files or values, kill or restart services, or mutate them merely to probe; use a \
disposable path or key when a probe needs state. A setup, parser, import, connection, timeout, or \
pre-assertion failure is missing evidence, not success. A self-test generated from the same \
misspelled schema or identifier is not independent evidence. Use the run facts as structural \
signals, not proof. Choose at most one high-signal falsification whose observation does not reuse \
the candidate's key assumption. If existing evidence settles the claim, return a concise final \
without tools. Otherwise use one tool-bearing validation response, batching only independent \
observations. Stop if it shows no objective mismatch; only a demonstrated mismatch opens \
correction and revalidation. Do not start a second exploratory check or repeat a generic \
checklist.\n\
Original request excerpt: {}\n\
Run facts: {}\n\
Recent terminal evidence: {}\n\
</evidence_debt_review_v2>",
                truncate_utf8(original_request, REQUEST_EXCERPT_BYTES),
                truncate_utf8(&evidence_debt.render(), EVIDENCE_DEBT_BYTES),
                truncate_utf8(recent_terminal_evidence, TERMINAL_EXCERPT_BYTES),
            ),
            Self::FreshEvidenceDebtV3 | Self::FreshCheckpointV4 | Self::SemanticCheckpointV6 => {
                return None;
            }
        };
        debug_assert!(prompt.len() <= MAX_PROMPT_BYTES);
        Some(prompt)
    }

    pub(crate) fn fresh_context(
        self,
        original_request: &str,
        candidate_final: &str,
        recent_terminal_evidence: &str,
        evidence_debt: &CompletionEvidenceLedger,
    ) -> Option<Vec<HistoryItem>> {
        if !self.uses_fresh_context() {
            return None;
        }
        let request = format!(
            "<fresh_completion_critic_v3>\n\
Original request:\n{}\n\
Candidate completion:\n{}\n\
Committed run facts:\n{}\n\
Most recent tool evidence:\n{}\n\
</fresh_completion_critic_v3>",
            truncate_utf8(original_request, FRESH_REQUEST_EXCERPT_BYTES),
            truncate_utf8(candidate_final, FRESH_CANDIDATE_EXCERPT_BYTES),
            truncate_utf8(&evidence_debt.render(), EVIDENCE_DEBT_BYTES),
            truncate_utf8(recent_terminal_evidence, FRESH_TERMINAL_EXCERPT_BYTES),
        );
        Some(vec![
            HistoryItem::System {
                content: FRESH_CRITIC_SYSTEM_PROMPT.to_owned(),
            },
            HistoryItem::User { content: request },
        ])
    }

    pub(crate) fn actor_prompt(self, critic_advice: &str) -> Option<String> {
        if !self.uses_fresh_context() {
            return None;
        }
        Some(format!(
            "<fresh_completion_critic_advice_v3>\n\
An isolated critic identified the following possible evidence gap:\n{}\n\
Treat this as an advisory hypothesis, not a fact. If committed evidence already settles it, \
return a concise final without tools. Otherwise perform at most one high-signal falsification \
check whose oracle does not reuse the candidate's key assumption. Correct only a demonstrated \
objective mismatch, revalidate the changed behavior, and stop.\n\
</fresh_completion_critic_advice_v3>",
            truncate_utf8(critic_advice, FRESH_CRITIC_ADVICE_BYTES),
        ))
    }

    pub(crate) fn uses_fresh_context(self) -> bool {
        matches!(
            self,
            Self::FreshEvidenceDebtV3 | Self::FreshCheckpointV4 | Self::SemanticCheckpointV6
        )
    }

    pub(crate) fn uses_context_checkpoint(self) -> bool {
        matches!(self, Self::FreshCheckpointV4 | Self::SemanticCheckpointV6)
    }

    pub(crate) fn uses_semantic_checkpoint(self) -> bool {
        self == Self::SemanticCheckpointV6
    }

    pub(crate) fn should_checkpoint(self, capacity: ContextCheckpointCapacity) -> bool {
        if !self.uses_context_checkpoint()
            || capacity.already_invoked
            || capacity.unresolved_background_count != 0
            || capacity.provider_turn_count < CONTEXT_CHECKPOINT_MIN_PROVIDER_TURNS_V1
            || capacity.observed_input_tokens < CONTEXT_CHECKPOINT_MIN_INPUT_TOKENS_V1
            || capacity.history_items < CONTEXT_CHECKPOINT_MIN_HISTORY_ITEMS_V1
        {
            return false;
        }
        let required_turns = if self.uses_semantic_checkpoint() {
            SEMANTIC_CHECKPOINT_MIN_REMAINING_TURNS_V1
        } else {
            CONTEXT_CHECKPOINT_MIN_REMAINING_TURNS_V1
        };
        let enough_turns = capacity
            .max_provider_turns
            .checked_sub(capacity.provider_turn_count)
            .is_some_and(|remaining| remaining >= required_turns);
        let required_reserve = if self.uses_semantic_checkpoint() {
            semantic_checkpoint_total_admission_reserve_v1(self)
        } else {
            review_required_reserve_v1(self)
                .and_then(|review| review.checked_add(CONTEXT_CHECKPOINT_POST_RESET_RESERVE_V1))
        };
        let enough_time = required_reserve.is_some_and(|required| capacity.remaining > required);
        enough_turns && enough_time
    }

    pub(crate) fn should_accept_semantic_checkpoint_after_prepare(
        self,
        capacity: ContextCheckpointCapacity,
    ) -> bool {
        if !self.uses_semantic_checkpoint()
            || capacity.already_invoked
            || capacity.unresolved_background_count != 0
            || capacity.provider_turn_count < CONTEXT_CHECKPOINT_MIN_PROVIDER_TURNS_V1
            || capacity.observed_input_tokens < CONTEXT_CHECKPOINT_MIN_INPUT_TOKENS_V1
            || capacity.history_items < CONTEXT_CHECKPOINT_MIN_HISTORY_ITEMS_V1
        {
            return false;
        }
        let enough_turns = capacity
            .max_provider_turns
            .checked_sub(capacity.provider_turn_count)
            .is_some_and(|remaining| {
                remaining >= SEMANTIC_CHECKPOINT_POST_PREPARE_MIN_REMAINING_TURNS_V1
            });
        let enough_time = semantic_checkpoint_tail_reserve_v1(self)
            .is_some_and(|required| capacity.remaining > required);
        enough_turns && enough_time
    }

    pub(crate) fn checkpoint_history(
        self,
        system_prompt: &str,
        wrapped_user_request: &str,
        capacity: ContextCheckpointCapacity,
        evidence_debt: &CompletionEvidenceLedger,
        recent_terminal_evidence: &str,
    ) -> Option<Vec<HistoryItem>> {
        if !self.should_checkpoint(capacity) {
            return None;
        }
        let notice = format!(
            "<fresh_context_checkpoint_v1 policy_version={}>\n\
The prior model conversation was compacted by a task-neutral budget policy after \
provider_turns={} and observed_input_tokens={}. The original request and current workspace are \
authoritative. Re-inspect the minimum current files or runtime state needed before assuming an \
earlier action persisted. Treat the bounded continuity evidence below as a locator, not proof. \
Continue with a fresh plan focused on the highest-impact unresolved acceptance gap. Do not redo \
settled work blindly, poll unchanged state, or start a broad new exploration.\n\
Committed run facts: {}\n\
Most recent tool evidence:\n{}\n\
</fresh_context_checkpoint_v1>",
            CONTEXT_CHECKPOINT_POLICY_VERSION_V1,
            capacity.provider_turn_count,
            capacity.observed_input_tokens,
            truncate_utf8(&evidence_debt.render(), EVIDENCE_DEBT_BYTES),
            truncate_utf8(recent_terminal_evidence, CONTEXT_CHECKPOINT_EVIDENCE_BYTES),
        );
        Some(vec![
            HistoryItem::System {
                content: system_prompt.to_owned(),
            },
            HistoryItem::User {
                content: wrapped_user_request.to_owned(),
            },
            HistoryItem::User { content: notice },
        ])
    }

    pub(crate) fn semantic_inline_notice(
        self,
        capacity: ContextCheckpointCapacity,
        evidence_debt: &CompletionEvidenceLedger,
        recent_terminal_evidence: &str,
    ) -> Option<String> {
        if !self.uses_semantic_checkpoint() || !self.should_checkpoint(capacity) {
            return None;
        }
        Some(format!(
            "<semantic_checkpoint_inline_v1 schema_version={} control_tool={}>\n\
In this normal action response, call the runtime-owned control tool exactly once with a concise \
continuity capsule. You may also issue the highest-value ordinary workspace tool calls in the \
same response. The capsule records the state before those ordinary calls; the runtime will bind \
their settled outputs separately before any reset. Do not claim unseen evaluation or completion \
facts. This is an untrusted continuity memo, not proof.\n\
Committed structural facts: {}\n\
Most recent tool evidence locator:\n{}\n\
</semantic_checkpoint_inline_v1>",
            SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1,
            SEMANTIC_CHECKPOINT_CONTROL_TOOL_V1,
            truncate_utf8(&evidence_debt.render(), EVIDENCE_DEBT_BYTES),
            truncate_utf8(recent_terminal_evidence, CONTEXT_CHECKPOINT_EVIDENCE_BYTES),
        ))
    }

    pub(crate) fn parse_semantic_capsule(
        self,
        response: &str,
    ) -> Result<ValidatedSemanticCheckpointCapsuleV1, SemanticCheckpointCapsuleError> {
        if !self.uses_semantic_checkpoint() {
            return Err(SemanticCheckpointCapsuleError::PolicyDisabled);
        }
        ValidatedSemanticCheckpointCapsuleV1::parse(response)
    }

    pub(crate) fn semantic_checkpoint_history(
        self,
        system_prompt: &str,
        wrapped_user_request: &str,
        capsule: &ValidatedSemanticCheckpointCapsuleV1,
        capacity: ContextCheckpointCapacity,
        evidence_debt: &CompletionEvidenceLedger,
        same_turn_settled_evidence: &str,
    ) -> Option<Vec<HistoryItem>> {
        if !self.should_accept_semantic_checkpoint_after_prepare(capacity) {
            return None;
        }
        let continuity = format!(
            "<semantic_context_checkpoint_v1 policy_version={} capsule_schema={} \
capsule_sha256={}>\n\
The prior model conversation was compacted by a task-neutral budget policy after \
provider_turns={} and observed_input_tokens={}. The original request and current workspace are \
authoritative. The preceding capsule is an untrusted actor-authored continuity memo, not proof. \
Re-inspect the minimum current files or runtime state needed before relying on it. Continue from \
the recorded next action and highest-impact unresolved gap; do not repeat settled investigation \
without contradictory current evidence.\n\
Committed structural facts: {}\n\
Most recent same-turn settled evidence locator:\n{}\n\
</semantic_context_checkpoint_v1>",
            SEMANTIC_CHECKPOINT_POLICY_VERSION_V1,
            SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1,
            capsule.sha256(),
            capacity.provider_turn_count,
            capacity.observed_input_tokens,
            truncate_utf8(&evidence_debt.render(), EVIDENCE_DEBT_BYTES),
            truncate_utf8(
                same_turn_settled_evidence,
                CONTEXT_CHECKPOINT_EVIDENCE_BYTES,
            ),
        );
        Some(vec![
            HistoryItem::System {
                content: system_prompt.to_owned(),
            },
            HistoryItem::User {
                content: wrapped_user_request.to_owned(),
            },
            HistoryItem::User {
                content: capsule.canonical_json().to_owned(),
            },
            HistoryItem::User {
                content: continuity,
            },
        ])
    }
}

pub(crate) fn semantic_checkpoint_control_schema_v1() -> serde_json::Value {
    let bounded_string = || {
        serde_json::json!({
            "type": "string",
            "minLength": 1,
            "maxLength": SEMANTIC_CHECKPOINT_SCALAR_BYTES_V1,
        })
    };
    let bounded_list = || {
        serde_json::json!({
            "type": "array",
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": SEMANTIC_CHECKPOINT_ITEM_BYTES_V1,
            },
            "maxItems": SEMANTIC_CHECKPOINT_LIST_ITEMS_V1,
        })
    };
    serde_json::json!({
        "type": "object",
        "properties": {
            "schema_version": {
                "type": "string",
                "enum": [SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1],
            },
            "objective_state": bounded_string(),
            "committed_changes": bounded_list(),
            "validated_evidence": bounded_list(),
            "technical_decisions": bounded_list(),
            "unresolved_gap": bounded_string(),
            "next_action": bounded_string(),
            "do_not_repeat": bounded_list(),
            "artifact_locators": bounded_list(),
        },
        "required": [
            "schema_version",
            "objective_state",
            "committed_changes",
            "validated_evidence",
            "technical_decisions",
            "unresolved_gap",
            "next_action",
            "do_not_repeat",
            "artifact_locators",
        ],
        "additionalProperties": false,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticCheckpointCapsuleV1 {
    schema_version: String,
    objective_state: String,
    committed_changes: Vec<String>,
    validated_evidence: Vec<String>,
    technical_decisions: Vec<String>,
    unresolved_gap: String,
    next_action: String,
    do_not_repeat: Vec<String>,
    artifact_locators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedSemanticCheckpointCapsuleV1 {
    canonical_json: String,
    sha256: String,
}

impl ValidatedSemanticCheckpointCapsuleV1 {
    fn parse(response: &str) -> Result<Self, SemanticCheckpointCapsuleError> {
        if response.is_empty() || response.len() > SEMANTIC_CHECKPOINT_CAPSULE_BYTES_V1 {
            return Err(SemanticCheckpointCapsuleError::ByteLimit);
        }
        let capsule = serde_json::from_str::<SemanticCheckpointCapsuleV1>(response)
            .map_err(|_| SemanticCheckpointCapsuleError::InvalidJson)?;
        if capsule.schema_version != SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1 {
            return Err(SemanticCheckpointCapsuleError::SchemaVersion);
        }
        for scalar in [
            &capsule.objective_state,
            &capsule.unresolved_gap,
            &capsule.next_action,
        ] {
            validate_capsule_text(scalar, SEMANTIC_CHECKPOINT_SCALAR_BYTES_V1)?;
        }
        for values in [
            &capsule.committed_changes,
            &capsule.validated_evidence,
            &capsule.technical_decisions,
            &capsule.do_not_repeat,
            &capsule.artifact_locators,
        ] {
            if values.len() > SEMANTIC_CHECKPOINT_LIST_ITEMS_V1 {
                return Err(SemanticCheckpointCapsuleError::ItemLimit);
            }
            for value in values {
                validate_capsule_text(value, SEMANTIC_CHECKPOINT_ITEM_BYTES_V1)?;
            }
        }
        let canonical_json = serde_json::to_string(&capsule)
            .map_err(|_| SemanticCheckpointCapsuleError::Canonicalization)?;
        if canonical_json.len() > SEMANTIC_CHECKPOINT_CAPSULE_BYTES_V1 {
            return Err(SemanticCheckpointCapsuleError::ByteLimit);
        }
        let sha256 = format!("{:x}", Sha256::digest(canonical_json.as_bytes()));
        Ok(Self {
            canonical_json,
            sha256,
        })
    }

    pub(crate) fn canonical_json(&self) -> &str {
        &self.canonical_json
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn bytes(&self) -> u64 {
        u64::try_from(self.canonical_json.len()).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticCheckpointCapsuleError {
    PolicyDisabled,
    InvalidJson,
    SchemaVersion,
    ByteLimit,
    ItemLimit,
    TextInvalid,
    Canonicalization,
}

impl SemanticCheckpointCapsuleError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::PolicyDisabled => "semantic_checkpoint_policy_disabled",
            Self::InvalidJson => "semantic_checkpoint_capsule_json_invalid",
            Self::SchemaVersion => "semantic_checkpoint_capsule_schema_invalid",
            Self::ByteLimit => "semantic_checkpoint_capsule_bytes_exceeded",
            Self::ItemLimit => "semantic_checkpoint_capsule_items_exceeded",
            Self::TextInvalid => "semantic_checkpoint_capsule_text_invalid",
            Self::Canonicalization => "semantic_checkpoint_capsule_canonicalization_failed",
        }
    }
}

fn validate_capsule_text(
    value: &str,
    max_bytes: usize,
) -> Result<(), SemanticCheckpointCapsuleError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(SemanticCheckpointCapsuleError::TextInvalid);
    }
    Ok(())
}

pub(crate) fn semantic_checkpoint_tail_reserve_v1(
    policy: CompletionReviewPolicy,
) -> Option<Duration> {
    if !policy.uses_semantic_checkpoint() {
        return None;
    }
    review_required_reserve_v1(policy)
        .and_then(|review| review.checked_add(SEMANTIC_CHECKPOINT_PROVISIONAL_RESERVE_V1))
        .and_then(|reserve| reserve.checked_add(SEMANTIC_CHECKPOINT_ACTION_PROVIDER_RESERVE_V1))
        .and_then(|reserve| reserve.checked_add(SEMANTIC_CHECKPOINT_MIN_ACTION_RESERVE_V1))
}

pub(crate) fn semantic_checkpoint_total_admission_reserve_v1(
    policy: CompletionReviewPolicy,
) -> Option<Duration> {
    semantic_checkpoint_tail_reserve_v1(policy)
        .and_then(|reserve| reserve.checked_add(SEMANTIC_CHECKPOINT_PREPARE_RESERVE_V1))
}

/// The soft action itself consumes one response, followed by one provisional
/// response and the four-response fresh-review worst case.
pub(crate) fn semantic_checkpoint_action_turn_cutoff_v1(max_provider_turns: u64) -> u64 {
    max_provider_turns
        .saturating_sub(6)
        .min(SOFT_FINISH_PROVIDER_TURN_V1)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ContextCheckpointCapacity {
    pub already_invoked: bool,
    pub provider_turn_count: u64,
    pub max_provider_turns: u64,
    pub observed_input_tokens: u64,
    pub history_items: u64,
    pub unresolved_background_count: u64,
    pub remaining: Duration,
}

/// Bounded structural facts from committed tool settlements.
///
/// This ledger never inspects task identity, benchmark results, commands, or
/// verifier output. It is advisory evidence for a single completion review,
/// not a completion gate.
#[derive(Debug, Default)]
pub(crate) struct CompletionEvidenceLedger {
    tool_calls: u64,
    timed_out: u64,
    rejected: u64,
    calls_after_explicit_edit: Option<u64>,
    consecutive_failure_tool: Option<String>,
    consecutive_failure_outcome: Option<ToolOutcome>,
    consecutive_failure_count: u64,
    max_consecutive_failure_count: u64,
    unresolved_background_tasks: BTreeSet<String>,
    recent: VecDeque<(String, ToolOutcome)>,
}

impl CompletionEvidenceLedger {
    pub(crate) fn observe(&mut self, event: &ToolCompleted, arguments_json: &str) {
        self.tool_calls = self.tool_calls.saturating_add(1);
        match event.outcome {
            ToolOutcome::TimedOut => self.timed_out = self.timed_out.saturating_add(1),
            ToolOutcome::Rejected => self.rejected = self.rejected.saturating_add(1),
            ToolOutcome::Succeeded => {}
        }
        if event.outcome == ToolOutcome::Succeeded
            && matches!(event.provider_name.as_str(), "write" | "search_replace")
        {
            self.calls_after_explicit_edit = Some(0);
        } else if let Some(count) = self.calls_after_explicit_edit.as_mut() {
            *count = count.saturating_add(1);
        }
        if event.outcome == ToolOutcome::Succeeded {
            self.consecutive_failure_tool = None;
            self.consecutive_failure_outcome = None;
            self.consecutive_failure_count = 0;
        } else if self.consecutive_failure_tool.as_deref() == Some(&event.provider_name)
            && self.consecutive_failure_outcome == Some(event.outcome)
        {
            self.consecutive_failure_count = self.consecutive_failure_count.saturating_add(1);
            self.max_consecutive_failure_count = self
                .max_consecutive_failure_count
                .max(self.consecutive_failure_count);
        } else {
            self.consecutive_failure_tool = Some(event.provider_name.clone());
            self.consecutive_failure_outcome = Some(event.outcome);
            self.consecutive_failure_count = 1;
            self.max_consecutive_failure_count = self
                .max_consecutive_failure_count
                .max(self.consecutive_failure_count);
        }
        self.observe_background(event, arguments_json);
        self.recent
            .push_back((event.provider_name.clone(), event.outcome));
        if self.recent.len() > RECENT_TOOL_FACTS {
            self.recent.pop_front();
        }
    }

    fn observe_background(&mut self, event: &ToolCompleted, arguments_json: &str) {
        if event.provider_name == "run_terminal_command"
            && event.output.contains("<status>running</status>")
            && let Some(task_id) = value_between(&event.output, "<task-id>", "</task-id>")
        {
            self.unresolved_background_tasks.insert(task_id.to_owned());
        }
        if event.provider_name == "get_terminal_command_output" {
            if let Some(ids) =
                value_between(&event.output, "<terminal-task-ids>", "</terminal-task-ids>")
            {
                for task_id in ids.split(',').filter(|value| !value.is_empty()) {
                    self.unresolved_background_tasks.remove(task_id);
                }
            }
            if let Some(task_id) = value_between(&event.output, "=== Task ", " ===")
                && ["Status: completed", "Status: failed", "Status: cancelled"]
                    .iter()
                    .any(|status| event.output.contains(status))
            {
                self.unresolved_background_tasks.remove(task_id);
            }
        }
        if event.provider_name == "kill_terminal_command"
            && event.outcome == ToolOutcome::Succeeded
            && let Ok(arguments) = serde_json::from_str::<serde_json::Value>(arguments_json)
            && let Some(task_id) = arguments.get("task_id").and_then(|value| value.as_str())
        {
            self.unresolved_background_tasks.remove(task_id);
        }
    }

    pub(crate) fn render(&self) -> String {
        let recent = self
            .recent
            .iter()
            .map(|(name, outcome)| format!("{name}:{}", outcome_label(*outcome)))
            .collect::<Vec<_>>()
            .join(">");
        format!(
            "tool_calls={}; timed_out={}; rejected={}; max_same_failure_streak={}; \
explicit_edit_seen={}; calls_after_last_explicit_edit={}; unresolved_background={}; recent={}",
            self.tool_calls,
            self.timed_out,
            self.rejected,
            self.max_consecutive_failure_count,
            self.calls_after_explicit_edit.is_some(),
            self.calls_after_explicit_edit.unwrap_or(0),
            self.unresolved_background_tasks.len(),
            if recent.is_empty() { "none" } else { &recent },
        )
    }

    pub(crate) fn unresolved_background_count(&self) -> u64 {
        u64::try_from(self.unresolved_background_tasks.len()).unwrap_or(u64::MAX)
    }
}

fn outcome_label(outcome: ToolOutcome) -> &'static str {
    match outcome {
        ToolOutcome::Succeeded => "ok",
        ToolOutcome::TimedOut => "timeout",
        ToolOutcome::Rejected => "rejected",
    }
}

fn value_between<'a>(value: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let offset = value.find(start)?.saturating_add(start.len());
    let tail = value.get(offset..)?;
    let length = tail.find(end)?;
    tail.get(..length)
}

pub(crate) fn recent_terminal_evidence(history: &[HistoryItem]) -> String {
    history
        .iter()
        .rev()
        .find_map(|item| match item {
            HistoryItem::FunctionCallOutput { output, .. } => {
                Some(truncate_utf8(output, TERMINAL_EXCERPT_BYTES))
            }
            _ => None,
        })
        .unwrap_or_else(|| "(no recent tool output)".to_owned())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use nano_provider_xai::HistoryItem;

    use nano_types::event::{ToolCompleted, ToolOutcome};

    use crate::finish_controller::FreshCriticCapacity;

    use super::{
        COMPLETION_REVIEW_DECISION_PROMPT, CONTEXT_CHECKPOINT_POLICY_VERSION_V1,
        CompletionEvidenceLedger, CompletionReviewCapacity, CompletionReviewPolicy,
        ContextCheckpointCapacity, FINAL_RESPONSE_LATENCY_RESERVE_V1, MAX_PROMPT_BYTES,
        REVIEW_BOUNDED_TOOL_RESERVE_V1, SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1,
        SEMANTIC_CHECKPOINT_CONTROL_TOOL_V1, SEMANTIC_CHECKPOINT_ITEM_BYTES_V1,
        SEMANTIC_CHECKPOINT_LIST_ITEMS_V1, SEMANTIC_CHECKPOINT_POLICY_VERSION_V1,
        SEMANTIC_CHECKPOINT_SCALAR_BYTES_V1, SemanticCheckpointCapsuleError,
        recent_terminal_evidence, review_required_reserve_v1,
        semantic_checkpoint_action_turn_cutoff_v1, semantic_checkpoint_control_schema_v1,
        semantic_checkpoint_tail_reserve_v1, semantic_checkpoint_total_admission_reserve_v1,
    };

    #[test]
    fn semantic_checkpoint_inline_control_schema_is_closed_and_complete() {
        let schema = semantic_checkpoint_control_schema_v1();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"].as_array().map(Vec::len), Some(9));
        assert_eq!(
            schema["properties"]["objective_state"]["maxLength"],
            SEMANTIC_CHECKPOINT_SCALAR_BYTES_V1,
        );
        assert_eq!(
            schema["properties"]["committed_changes"]["maxItems"],
            SEMANTIC_CHECKPOINT_LIST_ITEMS_V1,
        );
        assert_eq!(
            schema["properties"]["committed_changes"]["items"]["maxLength"],
            SEMANTIC_CHECKPOINT_ITEM_BYTES_V1,
        );
        assert_eq!(
            schema["properties"]["schema_version"]["enum"][0],
            SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1,
        );
        assert_eq!(
            SEMANTIC_CHECKPOINT_CONTROL_TOOL_V1,
            "record_semantic_checkpoint_v1"
        );
    }

    #[test]
    fn v10_review_capacity_covers_validation_tool_decision_and_final_reserve() {
        let policy = CompletionReviewPolicy::EvidenceDebtV2;
        let now = Instant::now();
        let required = review_required_reserve_v1(policy).expect("enabled review reserve");
        assert_eq!(FINAL_RESPONSE_LATENCY_RESERVE_V1, Duration::from_secs(90));
        assert_eq!(REVIEW_BOUNDED_TOOL_RESERVE_V1, Duration::from_secs(120));
        assert_eq!(required, Duration::from_secs(390));

        let at_cutoff = CompletionReviewCapacity {
            now,
            last_send: now + required,
            provider_turn_count: 1,
            max_provider_turns: 4,
            history_items: 7,
            max_history_items: 8,
        };
        assert!(!policy.has_capacity(at_cutoff));
        assert!(policy.has_capacity(CompletionReviewCapacity {
            last_send: now + required + Duration::from_nanos(1),
            ..at_cutoff
        }));
        assert!(!policy.has_capacity(CompletionReviewCapacity {
            last_send: now + required - Duration::from_nanos(1),
            ..at_cutoff
        }));
    }

    #[test]
    fn disabled_policy_never_consumes_an_extra_turn() {
        let now = Instant::now();
        assert!(
            !CompletionReviewPolicy::Disabled.has_capacity(CompletionReviewCapacity {
                now,
                last_send: now + Duration::from_secs(100),
                provider_turn_count: 0,
                max_provider_turns: 10,
                history_items: 2,
                max_history_items: 100,
            })
        );
        assert!(
            CompletionReviewPolicy::Disabled
                .prompt(
                    "request",
                    "candidate",
                    "evidence",
                    &CompletionEvidenceLedger::default(),
                )
                .is_none()
        );
    }

    #[test]
    fn falsification_policy_requires_two_turns_full_reserve_and_one_history_slot() {
        let policy = CompletionReviewPolicy::IndependentFalsificationV1;
        let now = Instant::now();
        let required = review_required_reserve_v1(policy).expect("enabled reserve");
        let capacity = CompletionReviewCapacity {
            now,
            last_send: now + required,
            provider_turn_count: 1,
            max_provider_turns: 3,
            history_items: 7,
            max_history_items: 8,
        };
        assert!(!policy.has_capacity(capacity));
        assert!(policy.has_capacity(CompletionReviewCapacity {
            last_send: now + required + Duration::from_nanos(1),
            ..capacity
        }));
        assert!(!policy.has_capacity(CompletionReviewCapacity {
            last_send: now + required + Duration::from_nanos(1),
            provider_turn_count: 2,
            ..capacity
        }));
        assert!(!policy.has_capacity(CompletionReviewCapacity {
            last_send: now + required + Duration::from_nanos(1),
            history_items: 8,
            ..capacity
        }));
    }

    #[test]
    fn fresh_critic_requires_four_turns_two_tool_reserves_and_full_reserve() {
        let policy = CompletionReviewPolicy::FreshEvidenceDebtV3;
        let now = Instant::now();
        let required = review_required_reserve_v1(policy).expect("enabled reserve");
        assert_eq!(required, Duration::from_secs(600));
        let capacity = CompletionReviewCapacity {
            now,
            last_send: now + required,
            provider_turn_count: 1,
            max_provider_turns: 5,
            history_items: 7,
            max_history_items: 11,
        };
        assert!(!policy.has_capacity(capacity));
        assert!(policy.has_capacity(CompletionReviewCapacity {
            last_send: now + required + Duration::from_nanos(1),
            ..capacity
        }));
        assert!(!policy.has_capacity(CompletionReviewCapacity {
            last_send: now + required + Duration::from_nanos(1),
            max_provider_turns: 4,
            ..capacity
        }));

        let full_path = FreshCriticCapacity {
            now,
            last_send: now + required + Duration::from_nanos(1),
            provisional_final_nonempty: true,
            critic_already_invoked: false,
            provider_turn_count: 10,
            max_provider_turns: 14,
            history_items: 100,
            max_history_items: 172,
            function_call_count: 20,
            max_function_calls_per_response: 16,
            max_function_calls_per_run: 52,
        };
        assert!(policy.has_fresh_path_capacity(full_path));
        assert!(!CompletionReviewPolicy::EvidenceDebtV2.has_fresh_path_capacity(full_path));
    }

    #[test]
    fn falsification_prompt_is_bounded_generic_and_uses_three_evidence_inputs() {
        let original = format!("ORIGINAL-{}", "问".repeat(200));
        let candidate = format!("CANDIDATE-{}", "答".repeat(200));
        let terminal = format!("TERMINAL-{}", "证".repeat(300));
        let prompt = CompletionReviewPolicy::IndependentFalsificationV1
            .prompt(
                &original,
                &candidate,
                &terminal,
                &CompletionEvidenceLedger::default(),
            )
            .expect("enabled prompt");

        assert!(prompt.len() <= 1024);
        assert!(prompt.contains("ORIGINAL-"));
        assert!(prompt.contains("CANDIDATE-"));
        assert!(prompt.contains("TERMINAL-"));
        assert!(prompt.contains("independent_falsification_review_v1"));
        assert!(prompt.contains("one high-signal check"));
        assert!(prompt.contains("does not reuse its key assumption"));
        assert!(prompt.contains("objective mismatch"));
        assert!(prompt.contains("without more tools"));
        for forbidden in [
            "task_id",
            "reward",
            "verifier",
            "historical answer",
            "hidden oracle",
            "/workspace/",
            "source/as-of",
            "negative cases",
        ] {
            assert!(!prompt.contains(forbidden));
        }
    }

    #[test]
    fn evidence_debt_v2_is_bounded_exact_and_has_no_runtime_injected_task_identity() {
        let mut ledger = CompletionEvidenceLedger::default();
        ledger.observe(
            &ToolCompleted {
                call_id: "edit".to_owned(),
                provider_name: "write".to_owned(),
                execution_attempted: true,
                outcome: ToolOutcome::Succeeded,
                output: "secret file contents".to_owned(),
            },
            r#"{"file_path":"/workspace/result"}"#,
        );
        for call_id in ["check-1", "check-2"] {
            ledger.observe(
                &ToolCompleted {
                    call_id: call_id.to_owned(),
                    provider_name: "run_terminal_command".to_owned(),
                    execution_attempted: true,
                    outcome: ToolOutcome::TimedOut,
                    output: "private command output".to_owned(),
                },
                r#"{"command":"private command"}"#,
            );
        }
        let original = format!("ORIGINAL-{}-REQUEST_TAIL", "x".repeat(300));
        let terminal = format!("LATEST-{}-EVIDENCE_TAIL", "z".repeat(600));
        let prompt = CompletionReviewPolicy::EvidenceDebtV2
            .prompt(&original, "private final", &terminal, &ledger)
            .expect("enabled prompt");

        assert!(prompt.len() <= MAX_PROMPT_BYTES);
        assert!(prompt.contains("evidence_debt_review_v2"));
        assert!(prompt.contains("Original request excerpt"));
        assert!(prompt.contains("ORIGINAL-"));
        assert!(prompt.contains("... output truncated ..."));
        assert!(!prompt.contains(&"x".repeat(100)));
        assert!(prompt.contains("acceptance claim"));
        for exact_requirement in [
            "identifiers",
            "paths",
            "literal values",
            "ports",
            "services",
            "required components",
        ] {
            assert!(prompt.contains(exact_requirement));
        }
        assert!(prompt.contains("exact acceptance ledger"));
        assert!(prompt.contains("observational"));
        assert!(prompt.contains("preserve the required final state"));
        assert!(prompt.contains("disposable path or key"));
        assert!(prompt.contains("setup, parser, import, connection, timeout"));
        assert!(prompt.contains("missing evidence, not success"));
        assert!(prompt.contains("same misspelled schema"));
        assert!(prompt.contains("one tool-bearing validation response"));
        assert!(prompt.contains("demonstrated mismatch opens correction"));
        assert!(prompt.contains("max_same_failure_streak=2"));
        assert!(prompt.contains("calls_after_last_explicit_edit=2"));
        assert!(prompt.contains("run_terminal_command:timeout"));
        assert!(!prompt.contains("private final"));
        assert!(!prompt.contains("private command"));
        assert!(!prompt.contains("secret file contents"));
        for forbidden in [
            "task_id",
            "benchmark",
            "reward",
            "verifier",
            "historical answer",
            "hidden oracle",
        ] {
            assert!(!prompt.contains(forbidden));
        }
    }

    #[test]
    fn completion_review_decision_v2_requires_one_complete_safe_correction() {
        assert!(COMPLETION_REVIEW_DECISION_PROMPT.contains("completion_review_decision_v2"));
        assert!(!COMPLETION_REVIEW_DECISION_PROMPT.contains("completion_review_decision_v1"));
        assert!(COMPLETION_REVIEW_DECISION_PROMPT.contains("one self-contained correction"));
        assert!(COMPLETION_REVIEW_DECISION_PROMPT.contains("serialized tool batch"));
        assert!(COMPLETION_REVIEW_DECISION_PROMPT.contains("complete safe replacement or change"));
        assert!(COMPLETION_REVIEW_DECISION_PROMPT.contains("last known good"));
        assert!(COMPLETION_REVIEW_DECISION_PROMPT.contains("never split teardown and replacement"));
        assert!(COMPLETION_REVIEW_DECISION_PROMPT.contains("only read-only revalidation"));
        for forbidden in [
            "task_id",
            "benchmark",
            "reward",
            "verifier",
            "historical answer",
            "hidden oracle",
            "transactional rollback",
        ] {
            assert!(!COMPLETION_REVIEW_DECISION_PROMPT.contains(forbidden));
        }
    }

    #[test]
    fn fresh_critic_context_is_isolated_bounded_and_task_neutral() {
        let request = format!("REQUEST-{}", "问".repeat(3000));
        let candidate = format!("CANDIDATE-{}", "答".repeat(2000));
        let terminal = format!("EVIDENCE-{}", "证".repeat(1000));
        let policy = CompletionReviewPolicy::FreshEvidenceDebtV3;
        let history = policy
            .fresh_context(
                &request,
                &candidate,
                &terminal,
                &CompletionEvidenceLedger::default(),
            )
            .expect("fresh critic context");

        assert_eq!(history.len(), 2);
        let HistoryItem::System { content: system } = &history[0] else {
            panic!("isolated system prompt");
        };
        let HistoryItem::User { content: user } = &history[1] else {
            panic!("isolated user evidence");
        };
        assert!(system.contains("isolated completion critic"));
        assert!(system.contains("no tools"));
        assert!(user.contains("REQUEST-"));
        assert!(user.contains("CANDIDATE-"));
        assert!(user.contains("EVIDENCE-"));
        assert!(user.len() < 8_000);
        for forbidden in [
            "benchmark",
            "reward",
            "verifier",
            "historical answer",
            "hidden oracle",
            "terminal-bench",
        ] {
            assert!(!system.contains(forbidden));
        }

        let actor = policy
            .actor_prompt(&format!("WEAK-{}", "x".repeat(3000)))
            .expect("actor advice");
        assert!(actor.contains("WEAK-"));
        assert!(actor.len() < 2_000);
        assert!(actor.contains("advisory hypothesis"));
        assert!(actor.contains("at most one high-signal"));
        assert!(
            CompletionReviewPolicy::EvidenceDebtV2
                .fresh_context("request", "candidate", "evidence", &Default::default())
                .is_none()
        );
    }

    #[test]
    fn fresh_critic_context_has_only_two_visible_items_and_no_hidden_runtime_inputs() {
        let history = CompletionReviewPolicy::FreshEvidenceDebtV3
            .fresh_context(
                "VISIBLE_REQUEST_CANARY",
                "VISIBLE_CANDIDATE_CANARY",
                "VISIBLE_TERMINAL_CANARY",
                &CompletionEvidenceLedger::default(),
            )
            .expect("fresh context");

        assert_eq!(history.len(), 2);
        assert!(matches!(history[0], HistoryItem::System { .. }));
        assert!(matches!(history[1], HistoryItem::User { .. }));
        let serialized = serde_json::to_string(&history).expect("history serializes");
        for visible in [
            "VISIBLE_REQUEST_CANARY",
            "VISIBLE_CANDIDATE_CANARY",
            "VISIBLE_TERMINAL_CANARY",
        ] {
            assert!(serialized.contains(visible));
        }
        for forbidden in [
            "HIDDEN_REASONING_CANARY",
            "TASK_IDENTIFIER_CANARY",
            "VERIFIER_CANARY",
            "REWARD_CANARY",
            "POSTRUN_CANARY",
            "OTHER_TRIAL_CANARY",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn fresh_checkpoint_v4_is_one_shot_bounded_and_task_neutral() {
        let capacity = ContextCheckpointCapacity {
            already_invoked: false,
            provider_turn_count: 12,
            max_provider_turns: 24,
            observed_input_tokens: 250_000,
            history_items: 32,
            unresolved_background_count: 0,
            remaining: Duration::from_secs(721),
        };
        let policy = CompletionReviewPolicy::FreshCheckpointV4;
        assert!(policy.should_checkpoint(capacity));
        assert!(!CompletionReviewPolicy::FreshEvidenceDebtV3.should_checkpoint(capacity));
        for blocked in [
            ContextCheckpointCapacity {
                already_invoked: true,
                ..capacity
            },
            ContextCheckpointCapacity {
                unresolved_background_count: 1,
                ..capacity
            },
            ContextCheckpointCapacity {
                provider_turn_count: 11,
                ..capacity
            },
            ContextCheckpointCapacity {
                observed_input_tokens: 249_999,
                ..capacity
            },
            ContextCheckpointCapacity {
                history_items: 31,
                ..capacity
            },
            ContextCheckpointCapacity {
                max_provider_turns: 23,
                ..capacity
            },
            ContextCheckpointCapacity {
                remaining: Duration::from_secs(720),
                ..capacity
            },
        ] {
            assert!(!policy.should_checkpoint(blocked));
        }

        let history = policy
            .checkpoint_history(
                "SYSTEM_CANARY",
                "<user_query>VISIBLE_REQUEST_CANARY</user_query>",
                capacity,
                &CompletionEvidenceLedger::default(),
                "VISIBLE_EVIDENCE_CANARY",
            )
            .expect("checkpoint history");
        assert_eq!(history.len(), 3);
        let encoded = serde_json::to_string(&history).expect("history JSON");
        for visible in [
            "SYSTEM_CANARY",
            "VISIBLE_REQUEST_CANARY",
            "VISIBLE_EVIDENCE_CANARY",
            CONTEXT_CHECKPOINT_POLICY_VERSION_V1,
        ] {
            assert!(encoded.contains(visible));
        }
        for forbidden in [
            "task_id",
            "reward",
            "verifier",
            "historical answer",
            "hidden oracle",
            "terminal-bench",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn semantic_checkpoint_v6_admission_reserves_inline_action_provisional_and_review() {
        let policy = CompletionReviewPolicy::SemanticCheckpointV6;
        assert_eq!(
            semantic_checkpoint_tail_reserve_v1(policy),
            Some(Duration::from_secs(900))
        );
        assert_eq!(
            semantic_checkpoint_total_admission_reserve_v1(policy),
            Some(Duration::from_secs(990))
        );
        assert_eq!(semantic_checkpoint_action_turn_cutoff_v1(64), 40);
        assert_eq!(semantic_checkpoint_action_turn_cutoff_v1(25), 19);
        assert_eq!(semantic_checkpoint_action_turn_cutoff_v1(6), 0);
        assert_eq!(
            semantic_checkpoint_tail_reserve_v1(CompletionReviewPolicy::FreshCheckpointV4),
            None
        );

        let capacity = ContextCheckpointCapacity {
            already_invoked: false,
            provider_turn_count: 12,
            max_provider_turns: 25,
            observed_input_tokens: 250_000,
            history_items: 32,
            unresolved_background_count: 0,
            remaining: Duration::from_secs(991),
        };
        assert!(policy.should_checkpoint(capacity));
        assert!(!policy.should_checkpoint(ContextCheckpointCapacity {
            max_provider_turns: 24,
            ..capacity
        }));
        assert!(!policy.should_checkpoint(ContextCheckpointCapacity {
            remaining: Duration::from_secs(990),
            ..capacity
        }));

        let post_prepare_capacity = ContextCheckpointCapacity {
            provider_turn_count: 13,
            remaining: Duration::from_secs(901),
            ..capacity
        };
        assert!(policy.should_accept_semantic_checkpoint_after_prepare(post_prepare_capacity));
        assert!(!policy.should_accept_semantic_checkpoint_after_prepare(
            ContextCheckpointCapacity {
                max_provider_turns: 24,
                ..post_prepare_capacity
            }
        ));
        assert!(!policy.should_accept_semantic_checkpoint_after_prepare(
            ContextCheckpointCapacity {
                remaining: Duration::from_secs(900),
                ..post_prepare_capacity
            }
        ));
    }

    #[test]
    fn semantic_checkpoint_v6_capsule_is_closed_canonical_bounded_and_task_neutral() {
        let policy = CompletionReviewPolicy::SemanticCheckpointV6;
        let capacity = ContextCheckpointCapacity {
            already_invoked: false,
            provider_turn_count: 12,
            max_provider_turns: 25,
            observed_input_tokens: 250_000,
            history_items: 32,
            unresolved_background_count: 0,
            remaining: Duration::from_secs(991),
        };
        let notice = policy
            .semantic_inline_notice(
                capacity,
                &CompletionEvidenceLedger::default(),
                "VISIBLE_EVIDENCE_CANARY",
            )
            .expect("inline notice");
        for visible in [
            "VISIBLE_EVIDENCE_CANARY",
            SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1,
            SEMANTIC_CHECKPOINT_CONTROL_TOOL_V1,
        ] {
            assert!(notice.contains(visible));
        }
        for forbidden in [
            "task_id",
            "reward",
            "verifier",
            "historical answer",
            "hidden oracle",
            "terminal-bench",
        ] {
            assert!(!notice.contains(forbidden));
        }

        let response = format!(
            r#"{{
                "next_action":"run the focused parser check",
                "artifact_locators":["src/parser.rs","cargo test parser"],
                "schema_version":"{}",
                "objective_state":"parser change is implemented but one edge remains",
                "unresolved_gap":"quoted empty input is not independently checked",
                "validated_evidence":["cargo test parser passed before the last edit"],
                "technical_decisions":["preserve the public parser API"],
                "committed_changes":["src/parser.rs handles escaped separators"],
                "do_not_repeat":["do not rescan unrelated modules"]
            }}"#,
            SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1
        );
        let capsule = policy
            .parse_semantic_capsule(&response)
            .expect("valid capsule");
        assert!(capsule.bytes() <= 8192);
        assert_eq!(capsule.sha256().len(), 64);
        assert!(!capsule.canonical_json().contains("\n"));

        let reparsed = policy
            .parse_semantic_capsule(capsule.canonical_json())
            .expect("canonical capsule reparses");
        assert_eq!(reparsed.canonical_json(), capsule.canonical_json());
        assert_eq!(reparsed.sha256(), capsule.sha256());

        let reset = policy
            .semantic_checkpoint_history(
                "SYSTEM_CANARY",
                "<user_query>VISIBLE_REQUEST_CANARY</user_query>",
                &capsule,
                capacity,
                &CompletionEvidenceLedger::default(),
                "same-turn tool output",
            )
            .expect("semantic checkpoint history");
        assert_eq!(reset.len(), 4);
        assert_eq!(
            reset[2],
            HistoryItem::User {
                content: capsule.canonical_json().to_owned()
            }
        );
        let reset_json = serde_json::to_string(&reset).expect("reset JSON");
        for visible in [
            "SYSTEM_CANARY",
            "VISIBLE_REQUEST_CANARY",
            SEMANTIC_CHECKPOINT_POLICY_VERSION_V1,
            capsule.sha256(),
        ] {
            assert!(reset_json.contains(visible));
        }
        assert_eq!(
            reset_json.matches("preserve the public parser API").count(),
            1
        );
    }

    #[test]
    fn semantic_checkpoint_v6_rejects_malformed_or_oversized_capsules() {
        let policy = CompletionReviewPolicy::SemanticCheckpointV6;
        let valid = format!(
            r#"{{"schema_version":"{}","objective_state":"state","committed_changes":[],"validated_evidence":[],"technical_decisions":[],"unresolved_gap":"gap","next_action":"act","do_not_repeat":[],"artifact_locators":[]}}"#,
            SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1
        );
        assert_eq!(
            CompletionReviewPolicy::FreshCheckpointV4.parse_semantic_capsule(&valid),
            Err(SemanticCheckpointCapsuleError::PolicyDisabled)
        );
        for (response, expected) in [
            (
                format!("```json\n{valid}\n```"),
                SemanticCheckpointCapsuleError::InvalidJson,
            ),
            (
                valid.replacen(
                    SEMANTIC_CHECKPOINT_CAPSULE_SCHEMA_V1,
                    "semantic-checkpoint-capsule-v0",
                    1,
                ),
                SemanticCheckpointCapsuleError::SchemaVersion,
            ),
            (
                valid.replacen(
                    "\"objective_state\":\"state\"",
                    "\"objective_state\":\"\"",
                    1,
                ),
                SemanticCheckpointCapsuleError::TextInvalid,
            ),
            (
                valid.replacen(
                    "\"artifact_locators\":[]",
                    "\"artifact_locators\":[],\"extra\":true",
                    1,
                ),
                SemanticCheckpointCapsuleError::InvalidJson,
            ),
            ("x".repeat(8193), SemanticCheckpointCapsuleError::ByteLimit),
        ] {
            assert_eq!(policy.parse_semantic_capsule(&response), Err(expected));
        }

        let too_many = (0..13)
            .map(|index| format!("\"item-{index}\""))
            .collect::<Vec<_>>()
            .join(",");
        let response = valid.replacen(
            "\"committed_changes\":[]",
            &format!("\"committed_changes\":[{too_many}]"),
            1,
        );
        assert_eq!(
            policy.parse_semantic_capsule(&response),
            Err(SemanticCheckpointCapsuleError::ItemLimit)
        );

        let response = valid.replacen(
            "\"next_action\":\"act\"",
            &format!("\"next_action\":\"{}\"", "x".repeat(769)),
            1,
        );
        assert_eq!(
            policy.parse_semantic_capsule(&response),
            Err(SemanticCheckpointCapsuleError::TextInvalid)
        );
    }

    #[test]
    fn evidence_ledger_tracks_background_completion_without_exposing_ids() {
        let mut ledger = CompletionEvidenceLedger::default();
        ledger.observe(
            &ToolCompleted {
                call_id: "start".to_owned(),
                provider_name: "run_terminal_command".to_owned(),
                execution_attempted: true,
                outcome: ToolOutcome::Succeeded,
                output: concat!(
                    "<task-id>task-secret</task-id>\n",
                    "<status>running</status>"
                )
                .to_owned(),
            },
            "{}",
        );
        assert!(ledger.render().contains("unresolved_background=1"));
        assert!(!ledger.render().contains("task-secret"));

        ledger.observe(
            &ToolCompleted {
                call_id: "wait".to_owned(),
                provider_name: "get_terminal_command_output".to_owned(),
                execution_attempted: true,
                outcome: ToolOutcome::Succeeded,
                output: concat!(
                    "<terminal-task-ids>task-secret</terminal-task-ids>\n",
                    "<running-task-ids></running-task-ids>"
                )
                .to_owned(),
            },
            "{}",
        );
        assert!(ledger.render().contains("unresolved_background=0"));
        assert!(!ledger.render().contains("task-secret"));
    }

    #[test]
    fn terminal_evidence_uses_only_recent_output_without_call_identifiers() {
        let history = vec![
            HistoryItem::FunctionCallOutput {
                call_id: "secret-old-call-id".to_owned(),
                output: "OLD-EVIDENCE".to_owned(),
            },
            HistoryItem::AssistantMessage {
                text: "intermediate".to_owned(),
            },
            HistoryItem::FunctionCallOutput {
                call_id: "secret-recent-call-id".to_owned(),
                output: format!("RECENT-EVIDENCE-{}", "x".repeat(600)),
            },
        ];
        let summary = recent_terminal_evidence(&history);
        assert!(summary.len() <= 256);
        assert!(summary.contains("RECENT-EVIDENCE-"));
        assert!(!summary.contains("OLD-EVIDENCE"));
        assert!(!summary.contains("secret-recent-call-id"));
    }
}
