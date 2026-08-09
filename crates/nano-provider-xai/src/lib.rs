//! Owned provider boundary shared by scripted tests and the later xAI wire.

#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

#[cfg(feature = "http")]
pub mod client;
#[cfg(feature = "http")]
mod request;
pub mod scripted;
#[cfg(feature = "http")]
mod sse;
pub mod types;

#[cfg(feature = "http")]
pub use client::{XaiProvider, XaiProviderSettings};
pub use scripted::ScriptedProvider;
pub use types::{
    CompletedTurn, FunctionCall, FunctionTool, HistoryItem, MediaHistoryEvictionLedger,
    MediaHistoryPolicyReceiptV1, MediaType, OutputItem, PreparedMediaHistoryBatch,
    PreparedTurnRequest, Provider, ProviderFailure, ProviderRequestMode, ProviderSendTelemetry,
    ToolMediaAttachment, TurnRequest, apply_media_history_policy, media_history_policy_sha256,
    prepare_media_history_batch,
};
