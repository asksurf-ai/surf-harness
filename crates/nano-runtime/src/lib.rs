//! Minimal serial, no-retry, no-compaction agent runtime.

#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

pub mod agent_loop;
pub mod completion_review;
pub mod deadline;
pub mod event_writer;
pub mod external_stdio;
mod foreground;
pub mod git_history_gate;
pub mod protected_target;
pub mod terminal;
pub mod tool;

pub use agent_loop::{
    AgentRunError, AgentRunOutcome, RunCancellation, run_agent, run_agent_with_cancellation,
    run_agent_with_deadline, run_agent_with_deadline_and_review,
};
pub use completion_review::CompletionReviewPolicy;
pub use deadline::{DeadlineContext, DeadlineError};
pub use event_writer::RunRecordPublication;
pub use external_stdio::{
    ExternalStdioDeadlineEnvelope, ExternalStdioExecutor, SettlementStageCutoffsV1,
};
pub use terminal::TerminalExecutor;
pub use tool::{
    EchoExecutor, ToolExecutionError, ToolExecutionFailureClass, ToolExecutor, ToolMedia,
    ToolResult, ToolRuntimeBudget, ToolWaitReason, WorkspaceMode,
};
