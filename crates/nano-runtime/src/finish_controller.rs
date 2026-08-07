//! Pure, task-neutral admission policy for the bounded finish path.

use std::time::{Duration, Instant};

pub const SOFT_FINISH_PROVIDER_TURN_V1: u64 = 40;
pub const FINAL_ONLY_PROVIDER_TURN_V1: u64 = 48;
const FRESH_CRITIC_PROVIDER_RESPONSES_V1: u64 = 4;
const FRESH_CRITIC_TOOL_BATCHES_V1: u64 = 2;
const FRESH_CRITIC_FIXED_HISTORY_ITEMS_V1: u64 = 8;
const FRESH_CRITIC_HISTORY_ITEMS_PER_TOOL_CALL_V1: u64 = 2;
const MAX_FINISH_NOTICE_BYTES_V1: usize = 512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum FinishState {
    #[default]
    ActionOpen,
    SoftFinish,
    FinalOnly,
    TerminalCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinishTrigger {
    Time,
    Turn40,
    Turn48,
}

#[derive(Clone, Copy, Debug)]
pub struct FinishObservation {
    pub now: Instant,
    pub soft_finish_cutoff: Instant,
    pub provider_turn_count: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct FinishNoticeFacts {
    pub provider_turn_count: u64,
    pub tool_call_count: u64,
    pub timed_out_count: u64,
    pub rejected_count: u64,
    pub unresolved_background_count: u64,
    pub remaining: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionEnvelope {
    /// Deadline for useful tool work. This may be shortened in soft finish.
    pub semantic_deadline: Instant,
    /// Immutable signed/native settlement envelope supplied by the caller.
    pub settlement_deadline: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionRejection {
    ActionAlreadyAdmitted,
    CutoffReached,
    PhaseClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionAdmission {
    Admitted(ActionEnvelope),
    Rejected(ActionRejection),
}

#[derive(Debug, Default)]
pub struct FinishController {
    state: FinishState,
    notice_pending: bool,
    notice_emitted: bool,
    soft_action_admitted: bool,
}

impl FinishController {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> FinishState {
        self.state
    }

    /// Observe the task-neutral time/turn signals and return only new transitions.
    pub fn observe(&mut self, observation: FinishObservation) -> Option<FinishTrigger> {
        if self.state == FinishState::TerminalCommit {
            return None;
        }
        if observation.provider_turn_count >= FINAL_ONLY_PROVIDER_TURN_V1 {
            if self.state < FinishState::FinalOnly {
                self.state = FinishState::FinalOnly;
                self.notice_pending |= !self.notice_emitted;
                return Some(FinishTrigger::Turn48);
            }
            return None;
        }
        if self.state != FinishState::ActionOpen {
            return None;
        }
        let trigger = if observation.provider_turn_count >= SOFT_FINISH_PROVIDER_TURN_V1 {
            Some(FinishTrigger::Turn40)
        } else if observation.now >= observation.soft_finish_cutoff {
            Some(FinishTrigger::Time)
        } else {
            None
        };
        if trigger.is_some() {
            self.state = FinishState::SoftFinish;
            self.notice_pending = true;
        }
        trigger
    }

    /// Render the single bounded notice using structural counters only.
    pub fn take_notice(&mut self, facts: FinishNoticeFacts) -> Option<String> {
        if !self.notice_pending || self.notice_emitted {
            return None;
        }
        self.notice_pending = false;
        self.notice_emitted = true;
        let directive = if self.state == FinishState::SoftFinish {
            "choose one self-contained bounded repair or finalize; do not start a new exploratory branch"
        } else {
            "the action phase is closed; return the final response without tools"
        };
        let notice = format!(
            "<finish_notice_v1> provider_turns={}; tool_calls={}; timed_out={}; rejected={}; \
unresolved_background={}; remaining_ms={}; {directive}. </finish_notice_v1>",
            facts.provider_turn_count,
            facts.tool_call_count,
            facts.timed_out_count,
            facts.rejected_count,
            facts.unresolved_background_count,
            facts.remaining.as_millis(),
        );
        debug_assert!(notice.len() <= MAX_FINISH_NOTICE_BYTES_V1);
        Some(notice)
    }

    /// Admit a response's serialized action batch and derive its semantic budget.
    ///
    /// The signed settlement deadline is transported unchanged. Equality at the
    /// soft-action cutoff is closed, leaving the final send reserve intact.
    pub fn admit_action_batch(
        &mut self,
        now: Instant,
        requested_semantic_deadline: Instant,
        soft_action_cutoff: Instant,
        settlement_deadline: Instant,
    ) -> ActionAdmission {
        match self.state {
            FinishState::ActionOpen => ActionAdmission::Admitted(ActionEnvelope {
                semantic_deadline: requested_semantic_deadline,
                settlement_deadline,
            }),
            FinishState::SoftFinish if self.soft_action_admitted => {
                ActionAdmission::Rejected(ActionRejection::ActionAlreadyAdmitted)
            }
            FinishState::SoftFinish => {
                let semantic_deadline = requested_semantic_deadline.min(soft_action_cutoff);
                if now >= semantic_deadline {
                    self.state = FinishState::FinalOnly;
                    return ActionAdmission::Rejected(ActionRejection::CutoffReached);
                }
                self.soft_action_admitted = true;
                ActionAdmission::Admitted(ActionEnvelope {
                    semantic_deadline,
                    settlement_deadline,
                })
            }
            FinishState::FinalOnly | FinishState::TerminalCommit => {
                ActionAdmission::Rejected(ActionRejection::PhaseClosed)
            }
        }
    }

    pub fn settle_action_batch(&mut self) -> bool {
        if self.state == FinishState::SoftFinish && self.soft_action_admitted {
            self.state = FinishState::FinalOnly;
            return true;
        }
        false
    }

    pub fn close_actions(&mut self) -> bool {
        if self.state < FinishState::FinalOnly {
            self.state = FinishState::FinalOnly;
            return true;
        }
        false
    }

    /// Cancellation, typed fatal errors, and normal success may all commit terminally.
    pub fn commit_terminal(&mut self) -> bool {
        if self.state == FinishState::TerminalCommit {
            return false;
        }
        self.state = FinishState::TerminalCommit;
        true
    }
}

/// Capacity for the complete optional fresh-critic path.
///
/// This structure intentionally contains no task identity, reward, verifier,
/// postrun, historical-outcome, or hidden-reasoning input.
#[derive(Clone, Copy, Debug)]
pub struct FreshCriticCapacity {
    pub now: Instant,
    pub last_send: Instant,
    pub provisional_final_nonempty: bool,
    pub critic_already_invoked: bool,
    pub provider_turn_count: u64,
    pub max_provider_turns: u64,
    pub history_items: u64,
    pub max_history_items: u64,
    pub function_call_count: u64,
    pub max_function_calls_per_response: u64,
    pub max_function_calls_per_run: u64,
}

impl FreshCriticCapacity {
    pub fn has_capacity(self, required_time: Duration) -> bool {
        if !self.provisional_final_nonempty || self.critic_already_invoked {
            return false;
        }
        let enough_time = self
            .last_send
            .checked_duration_since(self.now)
            .is_some_and(|remaining| remaining > required_time);
        let enough_turns = self
            .max_provider_turns
            .checked_sub(self.provider_turn_count)
            .is_some_and(|remaining| remaining >= FRESH_CRITIC_PROVIDER_RESPONSES_V1);
        let Some(future_tool_calls) = self
            .max_function_calls_per_response
            .checked_mul(FRESH_CRITIC_TOOL_BATCHES_V1)
        else {
            return false;
        };
        let enough_function_calls = self
            .max_function_calls_per_run
            .checked_sub(self.function_call_count)
            .is_some_and(|remaining| remaining >= future_tool_calls);
        let Some(required_history_items) = future_tool_calls
            .checked_mul(FRESH_CRITIC_HISTORY_ITEMS_PER_TOOL_CALL_V1)
            .and_then(|items| items.checked_add(FRESH_CRITIC_FIXED_HISTORY_ITEMS_V1))
        else {
            return false;
        };
        let enough_history = self
            .max_history_items
            .checked_sub(self.history_items)
            .is_some_and(|remaining| remaining >= required_history_items);
        enough_time && enough_turns && enough_function_calls && enough_history
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        ActionAdmission, FINAL_ONLY_PROVIDER_TURN_V1, FinishController, FinishNoticeFacts,
        FinishObservation, FinishState, FinishTrigger, FreshCriticCapacity,
        SOFT_FINISH_PROVIDER_TURN_V1,
    };

    #[test]
    fn states_are_monotonic_and_soft_finish_allows_one_bounded_action() {
        let start = Instant::now();
        let soft_cutoff = start + Duration::from_secs(10);
        let action_cutoff = start + Duration::from_secs(30);
        let settlement_deadline = start + Duration::from_secs(60);
        let mut controller = FinishController::new();

        assert_eq!(controller.state(), FinishState::ActionOpen);
        assert_eq!(
            controller.observe(FinishObservation {
                now: soft_cutoff - Duration::from_nanos(1),
                soft_finish_cutoff: soft_cutoff,
                provider_turn_count: SOFT_FINISH_PROVIDER_TURN_V1 - 1,
            }),
            None
        );
        assert_eq!(
            controller.observe(FinishObservation {
                now: soft_cutoff,
                soft_finish_cutoff: soft_cutoff,
                provider_turn_count: SOFT_FINISH_PROVIDER_TURN_V1 - 1,
            }),
            Some(FinishTrigger::Time)
        );
        assert_eq!(controller.state(), FinishState::SoftFinish);

        let ActionAdmission::Admitted(envelope) = controller.admit_action_batch(
            soft_cutoff,
            start + Duration::from_secs(45),
            action_cutoff,
            settlement_deadline,
        ) else {
            panic!("first soft action must be admitted");
        };
        assert_eq!(envelope.semantic_deadline, action_cutoff);
        assert_eq!(envelope.settlement_deadline, settlement_deadline);
        assert!(matches!(
            controller.admit_action_batch(
                soft_cutoff,
                action_cutoff,
                action_cutoff,
                settlement_deadline,
            ),
            ActionAdmission::Rejected(_)
        ));

        assert!(controller.settle_action_batch());
        assert_eq!(controller.state(), FinishState::FinalOnly);
        assert!(!controller.settle_action_batch());
        assert!(controller.commit_terminal());
        assert_eq!(controller.state(), FinishState::TerminalCommit);
        assert_eq!(
            controller.observe(FinishObservation {
                now: start,
                soft_finish_cutoff: soft_cutoff,
                provider_turn_count: 0,
            }),
            None
        );
        assert_eq!(controller.state(), FinishState::TerminalCommit);
    }

    #[test]
    fn turn_40_notice_is_one_shot_and_turn_48_closes_actions() {
        let now = Instant::now();
        let mut controller = FinishController::new();
        let far_cutoff = now + Duration::from_secs(600);

        assert_eq!(
            controller.observe(FinishObservation {
                now,
                soft_finish_cutoff: far_cutoff,
                provider_turn_count: SOFT_FINISH_PROVIDER_TURN_V1,
            }),
            Some(FinishTrigger::Turn40)
        );
        let facts = FinishNoticeFacts {
            provider_turn_count: SOFT_FINISH_PROVIDER_TURN_V1,
            tool_call_count: 9,
            timed_out_count: 1,
            rejected_count: 2,
            unresolved_background_count: 0,
            remaining: Duration::from_secs(300),
        };
        let notice = controller.take_notice(facts).expect("one notice");
        assert!(notice.len() <= 512);
        assert!(notice.contains("provider_turns=40"));
        assert!(notice.contains("one self-contained bounded repair or finalize"));
        assert_eq!(controller.take_notice(facts), None);

        assert_eq!(
            controller.observe(FinishObservation {
                now,
                soft_finish_cutoff: far_cutoff,
                provider_turn_count: FINAL_ONLY_PROVIDER_TURN_V1,
            }),
            Some(FinishTrigger::Turn48)
        );
        assert_eq!(controller.state(), FinishState::FinalOnly);
        assert!(matches!(
            controller.admit_action_batch(now, far_cutoff, far_cutoff, far_cutoff),
            ActionAdmission::Rejected(_)
        ));
    }

    #[test]
    fn action_cutoff_equality_is_closed_but_minus_one_nanosecond_is_open() {
        let now = Instant::now();
        let soft_cutoff = now;
        let action_cutoff = now + Duration::from_secs(10);
        let settlement = now + Duration::from_secs(30);
        let mut before = FinishController::new();
        before.observe(FinishObservation {
            now,
            soft_finish_cutoff: soft_cutoff,
            provider_turn_count: 0,
        });
        assert!(matches!(
            before.admit_action_batch(
                action_cutoff - Duration::from_nanos(1),
                settlement,
                action_cutoff,
                settlement,
            ),
            ActionAdmission::Admitted(_)
        ));

        let mut equal = FinishController::new();
        equal.observe(FinishObservation {
            now,
            soft_finish_cutoff: soft_cutoff,
            provider_turn_count: 0,
        });
        assert!(matches!(
            equal.admit_action_batch(action_cutoff, settlement, action_cutoff, settlement),
            ActionAdmission::Rejected(_)
        ));
        assert_eq!(equal.state(), FinishState::FinalOnly);
    }

    #[test]
    fn fresh_critic_capacity_covers_the_complete_worst_case_path() {
        let now = Instant::now();
        let required = Duration::from_secs(600);
        let capacity = FreshCriticCapacity {
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
        assert!(capacity.has_capacity(required));
        assert!(
            !FreshCriticCapacity {
                last_send: now + required,
                ..capacity
            }
            .has_capacity(required)
        );
        assert!(
            !FreshCriticCapacity {
                max_provider_turns: 13,
                ..capacity
            }
            .has_capacity(required)
        );
        assert!(
            !FreshCriticCapacity {
                max_history_items: 171,
                ..capacity
            }
            .has_capacity(required)
        );
        assert!(
            !FreshCriticCapacity {
                max_function_calls_per_run: 51,
                ..capacity
            }
            .has_capacity(required)
        );
        assert!(
            !FreshCriticCapacity {
                critic_already_invoked: true,
                ..capacity
            }
            .has_capacity(required)
        );
        assert!(
            !FreshCriticCapacity {
                provisional_final_nonempty: false,
                ..capacity
            }
            .has_capacity(required)
        );
    }
}
