use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nano_provider_xai::{
    CompletedTurn, FunctionCall, HistoryItem, OutputItem, PreparedTurnRequest, Provider,
    ProviderFailure, ProviderRequestMode, TurnRequest, XaiProvider, XaiProviderSettings,
};
use nano_runtime::deadline::{DeadlineCutoffs, DeadlineInstants, DeadlineReserves};
use nano_runtime::{
    CompletionReviewPolicy, DeadlineContext, TerminalExecutor, ToolExecutionBudget, ToolExecutor,
    ToolResult, WorkspaceMode, run_agent, run_agent_with_deadline,
    run_agent_with_deadline_and_review,
};
use nano_types::contract::{AgentProfile, LocalContract, TOOL_ORDER};
use nano_types::event::{TerminalStatus, ToolOutcome};
use nano_types::run_spec::{
    ContractSpec, GIT_HISTORY_CAPABILITY_POLICY, GIT_HISTORY_CAPABILITY_SCHEMA, GitHistoryAccess,
    GitHistoryCapability, ProviderKind, ProviderSpec, RUN_SPEC_SCHEMA, RunSpec, TaskSpec,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn json_file(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("serialize JSON");
    bytes.push(b'\n');
    bytes
}

fn terminal_profile() -> AgentProfile {
    serde_json::from_value(json!({
        "schema_version": "agent-profile-v1",
        "profile_id": "synthetic-profile-v1",
        "contract_id": "synthetic-v1",
        "provider": {
            "provider_id": "xai",
            "api": "responses-v1",
            "endpoint": "https://api.x.ai/v1/responses",
            "model": "grok-4.5",
            "reasoning_effort": "high",
            "store": false,
            "stream": true,
            "include": ["reasoning.encrypted_content"],
            "parallel_tool_calls": true,
            "tool_choice": "auto",
            "service_tier": "default",
            "retry_max": 0
        },
        "contract_bindings": {
            "effective_contract_file_sha256": "a".repeat(64),
            "system_prompt_utf8_sha256": "b".repeat(64),
            "ordered_tools_value_sha256": "c".repeat(64),
            "contract_delta_file_sha256": "d".repeat(64)
        },
        "context": {
            "policy": "fail_closed_no_compaction",
            "counting_rule": "synthetic",
            "provider_context_window_tokens": 500000,
            "request_input_upper_tokens": 199000,
            "max_output_tokens_per_request": 256,
            "max_provider_turns": 4,
            "max_input_tokens_per_run": 450000,
            "max_output_tokens_per_run": 1024,
            "max_history_items": 128,
            "max_request_body_bytes": 1048576
        },
        "transport": {
            "max_function_arguments_bytes": 1048576,
            "max_sse_events_per_response": 1024,
            "max_sse_event_bytes": 1048576,
            "max_sse_response_bytes": 4194304,
            "max_json_depth": 64
        },
        "scheduler": {
            "read_only_parallelism": 1,
            "max_function_calls_per_response": 8,
            "max_function_calls_per_run": 64,
            "mutation_batches_serialized": true
        },
        "deadlines": {
            "source": "run_spec_task_native",
            "absolute_run_wall_cap_sec": 60,
            "terminalization_reserve_sec": 1,
            "min_provider_send_window_sec": 1,
            "provider_connect_timeout_sec": 2,
            "provider_first_event_timeout_sec": 2,
            "provider_inter_event_timeout_sec": 2,
            "provider_total_timeout_sec": 5,
            "filesystem_operation_timeout_sec": 2,
            "search_operation_timeout_sec": 2,
            "process_control_timeout_sec": 2,
            "artifactization_timeout_sec": 2
        },
        "tools": {
            "terminal_default_timeout_ms": 1000,
            "terminal_max_timeout_ms": 3000,
            "background_output_wait_max_ms": 600000,
            "max_command_bytes": 4096,
            "max_path_bytes": 4096,
            "max_read_or_write_bytes": 1048576,
            "max_directory_entries": 100,
            "max_grep_matches": 100,
            "max_replacements": 100,
            "model_tool_output_bytes_per_call": 128,
            "model_tool_output_bytes_per_run": 1024
        },
        "process": {
            "max_background_processes": 8,
            "term_grace_ms": 100,
            "kill_confirmation_timeout_ms": 1000,
            "process_spool_bytes_per_process": 4096,
            "process_spool_bytes_per_run": 4096
        },
        "artifacts": {
            "max_events_per_run": 512,
            "max_event_line_bytes": 1048576,
            "max_event_log_bytes": 8388608,
            "max_blobs_per_run": 0,
            "max_blob_bytes": 1048576,
            "max_blob_bytes_per_run": 1048576,
            "max_agent_run_record_bytes": 1048576,
            "max_trajectory_bytes": 1048576,
            "max_published_agent_bytes": 8388608,
            "max_live_stdout_mirror_bytes": 1048576
        },
        "schema_versions": {
            "contract_manifest": "contract-manifest-v1",
            "effective_contract": "effective-contract-v1",
            "agent_profile": "agent-profile-v1",
            "contract_delta": "contract-delta-v1"
        }
    }))
    .expect("synthetic profile")
}

fn call(arguments: Value) -> FunctionCall {
    FunctionCall {
        call_id: "call-terminal".to_owned(),
        name: "run_terminal_command".to_owned(),
        arguments_json: serde_json::to_string(&arguments).expect("arguments JSON"),
    }
}

#[test]
fn terminal_timeout_validation_uses_the_600s_profile_limit_without_a_300s_ceiling() {
    let mut profile = terminal_profile();
    profile.tools.terminal_max_timeout_ms = 600_000;
    let executor = TerminalExecutor::from_profile(&profile);

    for timeout in [300_001_u64, 600_000] {
        executor
            .validate(&call(json!({
                "command": "true",
                "description": "prove the profile-bound timeout",
                "timeout": timeout,
            })))
            .unwrap_or_else(|_| panic!("{timeout} ms must remain valid"));
    }
    assert!(
        executor
            .validate(&call(json!({
                "command": "true",
                "description": "reject above the profile maximum",
                "timeout": 600_001,
            })))
            .is_err()
    );
}

fn write_contract(root: &Path) -> LocalContract {
    write_contract_with_max_provider_turns(root, 4)
}

fn write_contract_with_max_provider_turns(root: &Path, max_provider_turns: u64) -> LocalContract {
    let contract_dir = root.join("contract");
    fs::create_dir(&contract_dir).expect("contract directory");
    let prompt = "You are a synthetic terminal test agent.";
    let wrapper = "<user_query>\n{{USER_QUERY}}\n</user_query>";
    let tools = TOOL_ORDER
        .iter()
        .enumerate()
        .map(|(ordinal, name)| {
            let input_schema = if *name == "run_terminal_command" {
                json!({
                    "additionalProperties": false,
                    "properties": {
                        "background": {"default": false, "type": "boolean"},
                        "command": {"type": "string"},
                        "description": {"type": "string"},
                        "timeout": {
                            "default": 1000,
                            "maximum": 3000,
                            "minimum": 0,
                            "type": ["integer", "null"]
                        }
                    },
                    "required": ["command", "description"],
                    "type": "object"
                })
            } else if *name == "get_terminal_command_output" {
                json!({
                    "additionalProperties": false,
                    "properties": {
                        "timeout_ms": {"maximum": 600000, "minimum": 0, "type": "integer"}
                    },
                    "required": [],
                    "type": "object"
                })
            } else {
                json!({
                    "additionalProperties": false,
                    "properties": {},
                    "required": [],
                    "type": "object"
                })
            };
            json!({
                "ordinal": ordinal,
                "contract_tool_id": format!("synthetic:{name}"),
                "provider_name": name,
                "description": match *name {
                    "run_terminal_command" => "Synthetic terminal; timeout values default to 1000 ms and are at most 3000 ms. It owns descendants including setsid and nohup descendants and returns at most 128 bytes per call.",
                    "get_terminal_command_output" => "Synthetic background wait; omitted or zero is nonblocking and positive waits are capped at 600000 ms.",
                    "read_file" => "Read normal text files and PNG and JPEG image files only.",
                    _ => "Synthetic tool definition.",
                },
                "input_schema": input_schema,
                "effect_class": if matches!(
                    *name,
                    "read_file" | "list_dir" | "grep" | "get_terminal_command_output"
                ) {
                    "read_only"
                } else {
                    "mutating"
                },
                "compatibility_aliases": [],
                "result_policy": {
                    "renderer_contract_id": "synthetic-terminal-v1",
                    "truncation_policy": "synthetic-head-tail-v1",
                    "max_model_output_bytes": 128
                }
            })
        })
        .collect::<Vec<_>>();
    let effective_value = json!({
        "schema_version": "effective-contract-v1",
        "contract_id": "synthetic-v1",
        "prompt_context": {
            "current_date": "2026-07-23",
            "is_non_interactive": true,
            "memory_enabled": false,
            "os_name": "linux",
            "shell_path": "/bin/bash",
            "system_prompt_label": "Synthetic",
            "working_directory": "/workspace"
        },
        "system_prompt": {
            "text": prompt,
            "utf8_sha256": sha256_hex(prompt.as_bytes())
        },
        "user_wrapper": {
            "template": wrapper,
            "payload_slot": "{{USER_QUERY}}",
            "utf8_sha256": sha256_hex(wrapper.as_bytes())
        },
        "tools": tools
    });
    let effective = json_file(&effective_value);
    let delta = json_file(&json!({
        "schema_version": "contract-delta-v1",
        "contract_id": "synthetic-v1"
    }));
    let mut synthetic_profile = terminal_profile();
    synthetic_profile.context.max_provider_turns = max_provider_turns;
    let mut profile = serde_json::to_value(synthetic_profile).expect("profile value");
    profile["contract_bindings"]["effective_contract_file_sha256"] = json!(sha256_hex(&effective));
    profile["contract_bindings"]["system_prompt_utf8_sha256"] =
        json!(sha256_hex(prompt.as_bytes()));
    profile["contract_bindings"]["ordered_tools_value_sha256"] = json!(sha256_hex(
        &serde_json::to_vec(effective_value.get("tools").expect("tools")).expect("tools bytes")
    ));
    profile["contract_bindings"]["contract_delta_file_sha256"] = json!(sha256_hex(&delta));
    fs::write(contract_dir.join("effective-contract.json"), effective).expect("effective");
    fs::write(contract_dir.join("agent-profile.json"), json_file(&profile)).expect("profile");
    fs::write(contract_dir.join("contract-delta.json"), delta).expect("delta");
    LocalContract::load(&contract_dir).expect("load synthetic contract")
}

async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut received = Vec::new();
    let mut header_end = None;
    let mut body_length = None;
    loop {
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await.expect("read request");
        assert_ne!(count, 0, "request ended early");
        received.extend_from_slice(&chunk[..count]);
        if header_end.is_none()
            && let Some(position) = received.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let end = position + 4;
            let headers = String::from_utf8(received[..position].to_vec()).expect("headers");
            body_length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            });
            header_end = Some(end);
        }
        if let (Some(end), Some(length)) = (header_end, body_length)
            && received.len() >= end + length
        {
            return received[end..end + length].to_vec();
        }
    }
}

async fn start_response(stream: &mut TcpStream) {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("response headers");
}

async fn write_sse(stream: &mut TcpStream, event: &Value) {
    stream.write_all(b"data: ").await.expect("SSE prefix");
    stream
        .write_all(&serde_json::to_vec(event).expect("event JSON"))
        .await
        .expect("SSE JSON");
    stream.write_all(b"\r\n\r\n").await.expect("SSE suffix");
    stream.flush().await.expect("flush SSE");
}

async fn execute(workspace: &Path, arguments: Value) -> nano_runtime::ToolResult {
    let profile = terminal_profile();
    let mut executor = TerminalExecutor::from_profile(&profile);
    let call = call(arguments);
    executor.validate(&call).expect("valid terminal call");
    executor
        .execute(&call, workspace, Instant::now() + Duration::from_secs(5))
        .await
        .expect("local terminal execution")
}

struct PhaseProvider {
    responses: VecDeque<CompletedTurn>,
    requests: Vec<TurnRequest>,
    action_return_at: Option<Instant>,
}

impl Provider for PhaseProvider {
    async fn send(
        &mut self,
        request: PreparedTurnRequest,
    ) -> Result<CompletedTurn, ProviderFailure> {
        let request = request.into_request()?;
        if request.mode == ProviderRequestMode::ActionOpen
            && let Some(return_at) = self.action_return_at.take()
        {
            tokio::time::sleep_until(tokio::time::Instant::from_std(return_at)).await;
        }
        self.requests.push(request);
        self.responses
            .pop_front()
            .ok_or_else(|| ProviderFailure::new("phase_script_exhausted"))
    }
}

struct OneShotFailureProvider {
    responses: VecDeque<CompletedTurn>,
    requests: Vec<TurnRequest>,
    failure_at_request: usize,
    failure_code: &'static str,
    failure_emitted: bool,
}

impl Provider for OneShotFailureProvider {
    async fn send(
        &mut self,
        request: PreparedTurnRequest,
    ) -> Result<CompletedTurn, ProviderFailure> {
        let request = request.into_request()?;
        let request_index = self.requests.len();
        self.requests.push(request);
        if request_index == self.failure_at_request && !self.failure_emitted {
            self.failure_emitted = true;
            return Err(ProviderFailure::new(self.failure_code));
        }
        self.responses
            .pop_front()
            .ok_or_else(|| ProviderFailure::new("phase_script_exhausted"))
    }
}

struct HangingChallengeProvider {
    candidate: Option<CompletedTurn>,
    requests: Vec<TurnRequest>,
}

impl Provider for HangingChallengeProvider {
    async fn send(
        &mut self,
        request: PreparedTurnRequest,
    ) -> Result<CompletedTurn, ProviderFailure> {
        self.requests.push(request.into_request()?);
        if let Some(candidate) = self.candidate.take() {
            return Ok(candidate);
        }
        std::future::pending().await
    }
}

#[derive(Default)]
struct ImmediateExecutor {
    executions: u64,
    semantic_deadlines: Vec<Instant>,
    settlement_deadlines: Vec<Instant>,
    executed_call_ids: Vec<String>,
}

struct CompletionFixtureExecutor {
    executions: Vec<String>,
    workspace: PathBuf,
    active_service: Option<String>,
    replacement_ready: bool,
    service_availability: Vec<bool>,
}

impl CompletionFixtureExecutor {
    fn new(workspace: &Path) -> Self {
        Self {
            executions: Vec::new(),
            workspace: workspace.to_owned(),
            active_service: None,
            replacement_ready: false,
            service_availability: Vec::new(),
        }
    }

    fn with_working_service(workspace: &Path) -> Self {
        Self {
            active_service: Some("stable-v1".to_owned()),
            ..Self::new(workspace)
        }
    }

    fn record_service_availability(&mut self) {
        self.service_availability
            .push(self.active_service.is_some());
    }
}

impl ToolExecutor for CompletionFixtureExecutor {
    fn workspace_mode(&self) -> WorkspaceMode {
        WorkspaceMode::RemoteLogical
    }

    fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
        Ok(())
    }

    async fn execute(
        &mut self,
        call: &FunctionCall,
        workspace: &Path,
        _deadline: Instant,
    ) -> Result<ToolResult, nano_runtime::ToolExecutionError> {
        assert_eq!(workspace, self.workspace);
        self.executions.push(call.call_id.clone());
        let output = match call.call_id.as_str() {
            "call-ledger-validation" => {
                let wrong = fs::read_to_string(workspace.join("wrong.proto"))
                    .expect("mismatched schema fixture");
                assert!(!workspace.join("api.proto").exists());
                format!(
                    "acceptance_mismatch value!=SetValRequest.value \
path!=/workspace/api.proto observed={}",
                    wrong.trim()
                )
            }
            "call-ledger-stage" => {
                fs::write(
                    workspace.join("api.proto.next"),
                    "message SetValRequest { string value = 1; }\n",
                )
                .expect("stage exact schema");
                "staged exact schema without replacing current state".to_owned()
            }
            "call-ledger-activate" => {
                fs::rename(
                    workspace.join("api.proto.next"),
                    workspace.join("api.proto"),
                )
                .expect("activate exact schema");
                "activated /workspace/api.proto with SetValRequest.value".to_owned()
            }
            "call-ledger-revalidation" => fs::read_to_string(workspace.join("api.proto"))
                .expect("read exact schema during revalidation"),
            "call-service-validation" => {
                self.record_service_availability();
                format!(
                    "service={} status=available",
                    self.active_service.as_deref().expect("working service")
                )
            }
            "call-service-prepare" => {
                assert_eq!(self.active_service.as_deref(), Some("stable-v1"));
                self.replacement_ready = true;
                self.record_service_availability();
                "replacement-v2 ready; stable-v1 still available".to_owned()
            }
            "call-service-activate" => {
                assert!(self.replacement_ready, "replacement must be ready first");
                assert_eq!(self.active_service.as_deref(), Some("stable-v1"));
                self.active_service = Some("replacement-v2".to_owned());
                self.record_service_availability();
                "replacement-v2 active without service gap".to_owned()
            }
            "call-service-teardown-only" => {
                self.active_service = None;
                self.record_service_availability();
                "service stopped before a replacement".to_owned()
            }
            other => panic!("unexpected completion fixture call: {other}"),
        };
        Ok(ToolResult::succeeded(output))
    }
}

impl ToolExecutor for ImmediateExecutor {
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
        deadline: Instant,
    ) -> Result<ToolResult, nano_runtime::ToolExecutionError> {
        self.executions = self.executions.saturating_add(1);
        self.settlement_deadlines.push(deadline);
        self.executed_call_ids.push(call.call_id.clone());
        Ok(ToolResult::succeeded("settled"))
    }

    async fn execute_with_budget(
        &mut self,
        call: &FunctionCall,
        _workspace: &Path,
        budget: ToolExecutionBudget,
    ) -> Result<ToolResult, nano_runtime::ToolExecutionError> {
        self.executions = self.executions.saturating_add(1);
        self.semantic_deadlines.push(budget.semantic_deadline());
        self.settlement_deadlines.push(budget.settlement_deadline());
        self.executed_call_ids.push(call.call_id.clone());
        Ok(ToolResult::succeeded("settled"))
    }
}

struct RejectingExecutor;

impl ToolExecutor for RejectingExecutor {
    fn workspace_mode(&self) -> WorkspaceMode {
        WorkspaceMode::RemoteLogical
    }

    fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
        Err(ToolResult::rejected("challenge_validation_rejected"))
    }

    async fn execute(
        &mut self,
        _call: &FunctionCall,
        _workspace: &Path,
        _deadline: Instant,
    ) -> Result<ToolResult, nano_runtime::ToolExecutionError> {
        panic!("rejected challenge tool must not execute")
    }
}

struct DeadlineCrossingExecutor {
    dispatch_cutoff: Instant,
}

impl ToolExecutor for DeadlineCrossingExecutor {
    fn workspace_mode(&self) -> WorkspaceMode {
        WorkspaceMode::RemoteLogical
    }

    fn validate(&self, _call: &FunctionCall) -> Result<(), ToolResult> {
        if let Some(remaining) = self.dispatch_cutoff.checked_duration_since(Instant::now()) {
            std::thread::sleep(remaining + Duration::from_millis(1));
        }
        Ok(())
    }

    async fn execute(
        &mut self,
        _call: &FunctionCall,
        _workspace: &Path,
        _deadline: Instant,
    ) -> Result<ToolResult, nano_runtime::ToolExecutionError> {
        panic!("closed action-phase tool must not execute")
    }
}

struct FailingExecutor;

impl ToolExecutor for FailingExecutor {
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
    ) -> Result<ToolResult, nano_runtime::ToolExecutionError> {
        Err(nano_runtime::ToolExecutionError::fatal(
            "challenge_tool_failed",
            true,
            Some(true),
            Some(true),
        ))
    }
}

fn phase_deadline(actor_done: Instant) -> DeadlineContext {
    DeadlineContext {
        cutoffs: DeadlineCutoffs {
            actor_done_monotonic_ns: 10_000_000_000,
            tool_settled_monotonic_ns: 20_000_000_000,
            last_send_monotonic_ns: 50_000_000_000,
            runtime_final_monotonic_ns: 50_000_000_000,
            cleanup_start_monotonic_ns: 65_000_000_000,
            hard_deadline_monotonic_ns: 85_000_000_000,
        },
        instants: DeadlineInstants {
            actor_done,
            tool_settled: actor_done + Duration::from_secs(10),
            last_send: actor_done + Duration::from_secs(40),
            runtime_final: actor_done + Duration::from_secs(40),
            cleanup_start: actor_done + Duration::from_secs(55),
            hard_deadline: actor_done + Duration::from_secs(75),
        },
        reserves: DeadlineReserves::FROZEN,
        receipt_sha256: "d".repeat(64),
        observed_monotonic_ns: 1,
    }
}

fn action_open_phase_deadline(actor_done: Instant) -> DeadlineContext {
    let mut deadline = phase_deadline(actor_done);
    deadline.cutoffs.last_send_monotonic_ns = 110_000_000_000;
    deadline.cutoffs.runtime_final_monotonic_ns = 110_000_000_000;
    deadline.cutoffs.cleanup_start_monotonic_ns = 125_000_000_000;
    deadline.cutoffs.hard_deadline_monotonic_ns = 145_000_000_000;
    deadline.instants.last_send = actor_done + Duration::from_secs(100);
    deadline.instants.runtime_final = deadline.instants.last_send;
    deadline.instants.cleanup_start = deadline.instants.last_send + Duration::from_secs(15);
    deadline.instants.hard_deadline = deadline.instants.last_send + Duration::from_secs(35);
    deadline
}

/// Synthetic capacity fixture for completion-review behavior tests only.
/// Production admission remains bound to the frozen 90-second reserve and the
/// absolute signed `last_send`; this helper does not select a runtime branch.
fn review_phase_deadline(actor_done: Instant) -> DeadlineContext {
    let mut deadline = phase_deadline(actor_done);
    let review_capacity = Duration::from_secs(600);
    deadline.cutoffs.last_send_monotonic_ns = 610_000_000_000;
    deadline.cutoffs.runtime_final_monotonic_ns = 610_000_000_000;
    deadline.cutoffs.cleanup_start_monotonic_ns = 625_000_000_000;
    deadline.cutoffs.hard_deadline_monotonic_ns = 645_000_000_000;
    deadline.instants.last_send = actor_done + review_capacity;
    deadline.instants.runtime_final = deadline.instants.last_send;
    deadline.instants.cleanup_start = deadline.instants.last_send + Duration::from_secs(15);
    deadline.instants.hard_deadline = deadline.instants.last_send + Duration::from_secs(35);
    assert_eq!(deadline.reserves.provider_send_ms, 30_000);
    assert_eq!(
        deadline.instants.last_send.duration_since(actor_done),
        review_capacity
    );
    deadline
}

fn checkpoint_phase_deadline(actor_done: Instant) -> DeadlineContext {
    let mut deadline = review_phase_deadline(actor_done);
    let checkpoint_capacity = Duration::from_secs(800);
    deadline.cutoffs.last_send_monotonic_ns = 810_000_000_000;
    deadline.cutoffs.runtime_final_monotonic_ns = 810_000_000_000;
    deadline.cutoffs.cleanup_start_monotonic_ns = 825_000_000_000;
    deadline.cutoffs.hard_deadline_monotonic_ns = 845_000_000_000;
    deadline.instants.last_send = actor_done + checkpoint_capacity;
    deadline.instants.runtime_final = deadline.instants.last_send;
    deadline.instants.cleanup_start = deadline.instants.last_send + Duration::from_secs(15);
    deadline.instants.hard_deadline = deadline.instants.last_send + Duration::from_secs(35);
    deadline
}

fn semantic_checkpoint_phase_deadline(actor_done: Instant) -> DeadlineContext {
    let deadline = phase_deadline(actor_done);
    assert_eq!(
        deadline.instants.last_send.duration_since(actor_done),
        Duration::from_secs(40)
    );
    deadline
}

fn phase_spec(contract: &LocalContract, artifacts: &Path) -> RunSpec {
    RunSpec {
        schema_version: RUN_SPEC_SCHEMA.to_owned(),
        run_id: "run-p0b-phase".to_owned(),
        trial_id: "trial-p0b-phase".to_owned(),
        attempt_id: "attempt-0".to_owned(),
        task: TaskSpec {
            id: "p0b-phase".to_owned(),
            digest: "e".repeat(64),
            instruction: "Settle one action and finish.".to_owned(),
            git_history_capability: GitHistoryCapability {
                schema_version: GIT_HISTORY_CAPABILITY_SCHEMA.to_owned(),
                policy_version: GIT_HISTORY_CAPABILITY_POLICY.to_owned(),
                git_history_access: GitHistoryAccess::NotRequired,
                canonical_instruction_sha256:
                    "426a6b0332061a4cbbee9cc7d8b061226bd3a7eb975011413ca48288d7ba7ad4".to_owned(),
                trusted_manifest_sha256: "e".repeat(64),
                supporting_span_sha256: None,
            },
        },
        contract: ContractSpec {
            id: contract.effective().contract_id.clone(),
            contract_set_sha256: contract.contract_set_sha256().to_owned(),
            profile_id: contract.profile().profile_id.clone(),
        },
        provider: ProviderSpec {
            kind: ProviderKind::Xai,
            model: "grok-4.5".to_owned(),
            max_turns: 4,
            retry_max: 0,
        },
        workspace_dir: Path::new("/remote/workspace").to_owned(),
        artifact_dir: artifacts.to_owned(),
        agent_timeout_sec: 60,
        active_tools: Some(vec!["run_terminal_command".to_owned()]),
    }
}

fn phase_tool_response() -> CompletedTurn {
    CompletedTurn {
        response_id: "response-action".to_owned(),
        model: "grok-4.5".to_owned(),
        output: vec![OutputItem::FunctionCall {
            call_id: "call-phase".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{}".to_owned(),
        }],
        usage: Some(json!({"input_tokens": 2, "output_tokens": 1})),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn phase_terminal_response(response_id: &str, arguments: Value) -> CompletedTurn {
    CompletedTurn {
        response_id: response_id.to_owned(),
        model: "grok-4.5".to_owned(),
        output: vec![OutputItem::FunctionCall {
            call_id: format!("call-{response_id}"),
            name: "run_terminal_command".to_owned(),
            arguments_json: serde_json::to_string(&arguments).expect("terminal arguments"),
        }],
        usage: Some(json!({"input_tokens": 2, "output_tokens": 1})),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn phase_read_only_tool_response(response_id: &str, call_id: &str) -> CompletedTurn {
    CompletedTurn {
        response_id: response_id.to_owned(),
        model: "grok-4.5".to_owned(),
        output: vec![OutputItem::FunctionCall {
            call_id: call_id.to_owned(),
            name: "grep".to_owned(),
            arguments_json: "{}".to_owned(),
        }],
        usage: Some(json!({"input_tokens": 2, "output_tokens": 1})),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn phase_named_calls_response(response_id: &str, calls: Vec<(&str, &str, Value)>) -> CompletedTurn {
    CompletedTurn {
        response_id: response_id.to_owned(),
        model: "grok-4.5".to_owned(),
        output: calls
            .into_iter()
            .map(|(call_id, name, arguments)| OutputItem::FunctionCall {
                call_id: call_id.to_owned(),
                name: name.to_owned(),
                arguments_json: serde_json::to_string(&arguments).expect("tool arguments"),
            })
            .collect(),
        usage: Some(json!({"input_tokens": 4, "output_tokens": 2})),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn phase_complete_correction_response() -> CompletedTurn {
    CompletedTurn {
        response_id: "response-complete-correction".to_owned(),
        model: "grok-4.5".to_owned(),
        output: ["call-correction-build", "call-correction-switch"]
            .into_iter()
            .map(|call_id| OutputItem::FunctionCall {
                call_id: call_id.to_owned(),
                name: "run_terminal_command".to_owned(),
                arguments_json: "{}".to_owned(),
            })
            .collect(),
        usage: Some(json!({"input_tokens": 4, "output_tokens": 2})),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn phase_invalid_tool_response() -> CompletedTurn {
    CompletedTurn {
        response_id: "response-invalid-tool".to_owned(),
        model: "grok-4.5".to_owned(),
        output: vec![OutputItem::FunctionCall {
            call_id: "call-invalid".to_owned(),
            name: "not_a_contract_tool".to_owned(),
            arguments_json: "{}".to_owned(),
        }],
        usage: Some(json!({"input_tokens": 5, "output_tokens": 2})),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn phase_call_limit_response() -> CompletedTurn {
    CompletedTurn {
        response_id: "response-call-limit".to_owned(),
        model: "grok-4.5".to_owned(),
        output: (0..9)
            .map(|index| OutputItem::FunctionCall {
                call_id: format!("call-limit-{index}"),
                name: "run_terminal_command".to_owned(),
                arguments_json: "{}".to_owned(),
            })
            .collect(),
        usage: Some(json!({
            "input_tokens": 11,
            "output_tokens": 3,
            "provider_cost_ticks": 123_000_000
        })),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn phase_final_response() -> CompletedTurn {
    phase_message_response("response-final", "done")
}

fn phase_message_response(response_id: &str, text: &str) -> CompletedTurn {
    CompletedTurn {
        response_id: response_id.to_owned(),
        model: "grok-4.5".to_owned(),
        output: vec![OutputItem::AssistantMessage {
            text: text.to_owned(),
        }],
        usage: Some(json!({"input_tokens": 3, "output_tokens": 1})),
        service_tier: None,
        system_fingerprint: None,
    }
}

fn semantic_checkpoint_prefix_responses(label: &str) -> VecDeque<CompletedTurn> {
    (0..15)
        .map(|turn| {
            let call_id = format!("call-{label}-{turn}");
            let mut response = phase_named_calls_response(
                &format!("response-{label}-{turn}"),
                vec![(&call_id, "run_terminal_command", json!({}))],
            );
            response.usage = Some(json!({"input_tokens": 20_000, "output_tokens": 2}));
            response
        })
        .collect()
}

fn semantic_checkpoint_capsule() -> Value {
    json!({
        "schema_version": "semantic-checkpoint-capsule-v1",
        "objective_state": "the focused implementation is present",
        "committed_changes": ["workspace/result.txt was written"],
        "validated_evidence": ["the bounded command returned settled"],
        "technical_decisions": ["preserve the current interface"],
        "unresolved_gap": "one independent read remains",
        "next_action": "inspect workspace/result.txt once",
        "do_not_repeat": ["do not repeat broad discovery"],
        "artifact_locators": ["workspace/result.txt"],
    })
}

fn semantic_inline_checkpoint_response(
    response_id: &str,
    capsule: Value,
    ordinary_calls: Vec<(&str, &str, Value)>,
) -> CompletedTurn {
    let mut calls = vec![(
        "call-semantic-checkpoint-control",
        "record_semantic_checkpoint_v1",
        capsule,
    )];
    calls.extend(ordinary_calls);
    phase_named_calls_response(response_id, calls)
}

fn semantic_inline_call_limit_response() -> CompletedTurn {
    let mut output = vec![OutputItem::FunctionCall {
        call_id: "call-inline-control".to_owned(),
        name: "record_semantic_checkpoint_v1".to_owned(),
        arguments_json: serde_json::to_string(&semantic_checkpoint_capsule())
            .expect("checkpoint arguments"),
    }];
    output.extend((0..9).map(|index| OutputItem::FunctionCall {
        call_id: format!("call-inline-overflow-{index}"),
        name: "run_terminal_command".to_owned(),
        arguments_json: "{}".to_owned(),
    }));
    CompletedTurn {
        response_id: "response-inline-call-limit".to_owned(),
        model: "grok-4.5".to_owned(),
        output,
        usage: Some(json!({"input_tokens": 4, "output_tokens": 2})),
        service_tier: None,
        system_fingerprint: None,
    }
}

#[tokio::test]
async fn turn40_soft_finish_admits_one_action_batch_then_requests_final_only() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 64);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut responses = (0..41)
        .map(|turn| {
            let call_id = format!("call-action-{turn}");
            phase_named_calls_response(
                &format!("response-action-{turn}"),
                vec![(&call_id, "run_terminal_command", json!({}))],
            )
        })
        .collect::<VecDeque<_>>();
    responses.push_back(phase_final_response());
    let mut provider = PhaseProvider {
        responses,
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 64;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::Disabled,
    )
    .await
    .expect("turn40 bounded finish");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(executor.executions, 41);
    assert_eq!(provider.requests.len(), 42);
    assert_eq!(provider.requests[40].mode, ProviderRequestMode::ActionOpen);
    assert!(provider.requests[40].history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content } if content.contains("<finish_notice_v1>")
    )));
    assert_eq!(provider.requests[41].mode, ProviderRequestMode::FinalOnly);
}

#[tokio::test]
async fn protected_denial_is_model_visible_then_legal_tool_and_final_continue() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(10));
    let arguments = json!({
        "command": r"git clone https://github.com/Harbor-Framework\u002fTerminal-Bench",
        "description": "blocked direct access",
        "background": true,
    });
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_terminal_response("official", arguments.clone()),
            phase_tool_response(),
            phase_final_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome =
        run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
            .await
            .expect("pre-dispatch denial must remain nonterminal");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(executor.executions, 1);
    assert_eq!(executor.executed_call_ids, ["call-phase"]);
    assert_eq!(provider.requests.len(), 3);
    assert!(provider.requests[1].history.iter().any(|item| matches!(
        item,
        HistoryItem::FunctionCallOutput { call_id, output }
            if call_id == "call-official" && output == "permission_denied"
    )));
    assert!(provider.requests[2].history.iter().any(|item| matches!(
        item,
        HistoryItem::FunctionCallOutput { call_id, output }
            if call_id == "call-phase" && output == "settled"
    )));
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    assert_eq!(
        parsed
            .iter()
            .filter(|event| event["type"] == "tool.registered")
            .count(),
        2
    );
    assert_eq!(
        parsed
            .iter()
            .find(|event| event["type"] == "tool.registered")
            .expect("registered")["data"]["arguments_json"],
        serde_json::to_string(&arguments).expect("arguments")
    );
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"tool.failed\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"run.failed\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    let denied = parsed
        .iter()
        .find(|event| {
            event["type"] == "tool.completed" && event["data"]["call_id"] == "call-official"
        })
        .expect("denied completion evidence");
    assert_eq!(denied["data"]["execution_attempted"], false);
    assert_eq!(denied["data"]["outcome"], "rejected");
    assert_eq!(denied["data"]["output"], "permission_denied");
    assert!(
        !denied["data"]["output"]
            .as_str()
            .expect("denial output")
            .contains("terminal-bench")
    );
    let run: Value = serde_json::from_slice(&fs::read(artifacts.join("run.json")).expect("run"))
        .expect("run JSON");
    assert_eq!(run["terminal_status"], "success");
    assert_eq!(run["terminal_code"], "completed");
}

#[tokio::test]
async fn repeated_protected_path_alias_calls_are_denied_without_dispatch() {
    for (name, command) in [
        (
            "split-logs",
            "p=/logs; cat \"$p/agent/input/run-spec.json\"",
        ),
        (
            "proc-root-logs",
            "cat /proc/self/root/logs/agent/input/run-spec.json",
        ),
    ] {
        let root = tempfile::tempdir().expect("test root");
        let contract = write_contract(root.path());
        let artifacts = root.path().join("artifacts");
        let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(10));
        let arguments = json!({
            "command": command,
            "description": "blocked protected path alias",
            "background": true,
        });
        let mut provider = PhaseProvider {
            responses: VecDeque::from([
                phase_named_calls_response(
                    name,
                    vec![
                        ("call-denied-1", "run_terminal_command", arguments.clone()),
                        ("call-denied-2", "run_terminal_command", arguments.clone()),
                    ],
                ),
                phase_final_response(),
            ]),
            requests: Vec::new(),
            action_return_at: None,
        };
        let mut executor = ImmediateExecutor::default();
        let spec = phase_spec(&contract, &artifacts);

        let outcome =
            run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
                .await
                .expect("protected path aliases must be ordinary denials");

        assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
        assert_eq!(executor.executions, 0);
        assert_eq!(provider.requests.len(), 2);
        for call_id in ["call-denied-1", "call-denied-2"] {
            assert!(provider.requests[1].history.iter().any(|item| matches!(
                item,
                HistoryItem::FunctionCallOutput { call_id: observed, output }
                    if observed == call_id && output == "permission_denied"
            )));
        }
        let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
        let parsed = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
            .collect::<Vec<_>>();
        assert_eq!(
            parsed
                .iter()
                .filter(|event| event["type"] == "tool.registered")
                .count(),
            2
        );
        assert_eq!(
            parsed
                .iter()
                .find(|event| event["type"] == "tool.registered")
                .expect("registered")["data"]["arguments_json"],
            serde_json::to_string(&arguments).expect("arguments")
        );
        assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 2);
        assert_eq!(events.matches("\"type\":\"tool.failed\"").count(), 0);
        assert_eq!(events.matches("\"type\":\"run.failed\"").count(), 0);
        for denied in parsed
            .iter()
            .filter(|event| event["type"] == "tool.completed")
        {
            assert_eq!(denied["data"]["execution_attempted"], false);
            assert_eq!(denied["data"]["outcome"], "rejected");
            assert_eq!(denied["data"]["output"], "permission_denied");
            assert!(
                !denied["data"]["output"]
                    .as_str()
                    .expect("denial output")
                    .contains("/logs")
            );
        }
    }
}

#[tokio::test]
async fn ordinary_github_command_and_official_slug_outside_command_are_allowed() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_terminal_response(
                "normal-github",
                json!({
                    "command": "git clone https://github.com/rust-lang/cargo",
                    "description": "harbor-framework/terminal-bench is description only",
                    "background": false,
                }),
            ),
            phase_final_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome =
        run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
            .await
            .expect("ordinary GitHub command must remain allowed");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(executor.executions, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.failed\"").count(), 0);
}

#[test]
fn xai_settings_are_profile_bound_not_experiment_bound() {
    let mut profile = terminal_profile();
    profile.provider.model = "future-xai-model".to_owned();
    profile.provider.reasoning_effort = "medium".to_owned();
    profile.provider.include.clear();
    profile.provider.parallel_tool_calls = false;
    profile.provider.tool_choice = "required".to_owned();
    profile.provider.service_tier = "flex".to_owned();

    let settings = XaiProviderSettings::from_profile(&profile).expect("profile choices");
    assert_eq!(settings.model, "future-xai-model");
    assert_eq!(settings.reasoning_effort, "medium");
    assert!(settings.include.is_empty());
    assert!(!settings.parallel_tool_calls);
    assert_eq!(settings.tool_choice, "required");
    assert_eq!(settings.service_tier, "flex");
}

#[tokio::test]
async fn completion_challenge_revises_first_action_open_final_exactly_once() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_message_response("response-revised", "revised"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("reviewed run");

    assert_eq!(provider.requests.len(), 2);
    assert!(
        provider
            .requests
            .iter()
            .all(|request| request.mode == ProviderRequestMode::ActionOpen)
    );
    assert!(
        provider
            .requests
            .iter()
            .all(|request| !request.tools.is_empty())
    );
    assert!(provider.requests[1].history.iter().any(|item| matches!(
        item,
        nano_provider_xai::HistoryItem::AssistantMessage { text } if text == "candidate"
    )));
    assert!(provider.requests[1].history.iter().any(|item| matches!(
        item,
        nano_provider_xai::HistoryItem::User { content }
            if content.contains("independent_falsification_review_v1")
                && content.contains("candidate")
                && content.contains("Settle one action and finish.")
    )));
    assert_eq!(outcome.record.provider_turn_count, 2);
    assert_eq!(outcome.record.tool_call_count, 0);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.requested\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"provider.completed\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"revised\""));
    assert!(!events.contains("\"text\":\"candidate\""));
    let event_types = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON")["type"].clone())
        .collect::<Vec<_>>();
    let first_completed = event_types
        .iter()
        .position(|event| event == "provider.completed")
        .expect("candidate completion");
    let second_requested = event_types
        .iter()
        .rposition(|event| event == "provider.requested")
        .expect("challenge request");
    assert!(first_completed < second_requested);
}

#[tokio::test]
async fn evidence_debt_review_uses_only_committed_structural_tool_facts() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_tool_response(),
            phase_message_response("response-candidate", "candidate"),
            phase_message_response("response-revised", "revised"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect("evidence-reviewed run");

    assert_eq!(provider.requests.len(), 3);
    let review = provider.requests[2]
        .history
        .iter()
        .find_map(|item| match item {
            nano_provider_xai::HistoryItem::User { content }
                if content.contains("evidence_debt_review_v2") =>
            {
                Some(content)
            }
            _ => None,
        })
        .expect("review prompt");
    assert!(review.contains("tool_calls=1"));
    assert!(review.contains("recent=run_terminal_command:ok"));
    assert!(review.contains("unresolved_background=0"));
    assert!(!review.contains("call-phase"));
    assert!(!review.contains("\"command\""));
    assert_eq!(outcome.record.provider_turn_count, 3);
    assert_eq!(outcome.record.tool_call_count, 1);
}

#[tokio::test]
async fn read_only_review_provider_failure_preserves_safe_candidate() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_read_only_tool_response("response-validation", "call-validation"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.active_tools = Some(vec!["run_terminal_command".to_owned(), "grep".to_owned()]);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect("unmutated candidate survives review provider failure");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(outcome.record.provider_call_coverage.requested, 3);
    assert_eq!(outcome.record.provider_call_coverage.completed, 2);
    assert_eq!(outcome.record.provider_call_coverage.failed, 1);
    assert_eq!(executor.executions, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert!(events.contains("\"code\":\"phase_script_exhausted\""));
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn fresh_evidence_debt_critic_is_isolated_before_actor_validation() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 5);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_message_response(
                "response-critic",
                "claim: output exists; reason: no independent read; check: read it once",
            ),
            phase_message_response("response-revised", "revised"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 5;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::FreshEvidenceDebtV3,
    )
    .await
    .expect("fresh-context reviewed run");

    assert_eq!(provider.requests.len(), 3);
    let critic = &provider.requests[1];
    assert_eq!(critic.mode, ProviderRequestMode::FinalOnly);
    assert!(critic.tools.is_empty());
    assert_eq!(critic.history.len(), 2);
    assert!(matches!(
        &critic.history[0],
        HistoryItem::System { content } if content.contains("isolated completion critic")
    ));
    assert!(matches!(
        &critic.history[1],
        HistoryItem::User { content }
            if content.contains("Settle one action and finish.")
                && content.contains("candidate")
    ));
    assert!(!critic.history.iter().any(|item| matches!(
        item,
        HistoryItem::AssistantMessage { .. }
            | HistoryItem::FunctionCall { .. }
            | HistoryItem::FunctionCallOutput { .. }
    )));

    let actor = &provider.requests[2];
    assert_eq!(actor.mode, ProviderRequestMode::ActionOpen);
    assert!(!actor.tools.is_empty());
    assert!(actor.history.iter().any(|item| matches!(
        item,
        HistoryItem::AssistantMessage { text } if text == "candidate"
    )));
    assert!(actor.history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content }
            if content.contains("fresh_completion_critic_advice_v3")
                && content.contains("no independent read")
    )));
    assert!(!actor.history.iter().any(|item| matches!(
        item,
        HistoryItem::AssistantMessage { text } if text.contains("no independent read")
    )));
    assert_eq!(outcome.record.provider_turn_count, 3);
    assert_eq!(outcome.record.tool_call_count, 0);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let critic_request = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .filter(|event| event["type"] == "provider.requested")
        .nth(1)
        .expect("critic request event");
    assert_eq!(
        critic_request["data"]["budget_observation"]["phase"],
        "completion_critic"
    );
    assert!(events.contains("\"text\":\"revised\""));
    assert!(!events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn fresh_checkpoint_v4_resets_history_once_and_binds_the_next_request() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 64);
    let artifacts = root.path().join("artifacts");
    let deadline = checkpoint_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut responses = VecDeque::new();
    for turn in 0..15 {
        let call_id = format!("call-action-{turn}");
        let mut response = phase_named_calls_response(
            &format!("response-action-{turn}"),
            vec![(&call_id, "run_terminal_command", json!({}))],
        );
        response.usage = Some(json!({"input_tokens": 20_000, "output_tokens": 2}));
        responses.push_back(response);
    }
    responses.push_back(phase_message_response("response-candidate", "candidate"));
    responses.push_back(phase_message_response(
        "response-critic",
        "claim: current workspace state; reason: compacted history; check: inspect once",
    ));
    responses.push_back(phase_message_response("response-revised", "revised"));
    let mut provider = PhaseProvider {
        responses,
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 64;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::FreshCheckpointV4,
    )
    .await
    .expect("checkpointed run");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(executor.executions, 15);
    assert_eq!(provider.requests.len(), 18);
    let checkpoint_request = &provider.requests[15];
    assert_eq!(checkpoint_request.mode, ProviderRequestMode::ActionOpen);
    assert_eq!(checkpoint_request.history.len(), 3);
    assert!(checkpoint_request.history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content }
            if content.contains("fresh-context-checkpoint-v1")
                && content.contains("observed_input_tokens=300000")
    )));
    let checkpoint_history =
        serde_json::to_string(&checkpoint_request.history).expect("checkpoint history");
    assert!(!checkpoint_history.contains("call-action-0"));
    assert!(checkpoint_request.media_history_receipt.is_some());

    let critic_request = &provider.requests[16];
    assert_eq!(critic_request.mode, ProviderRequestMode::FinalOnly);
    assert_eq!(critic_request.history.len(), 2);
    let resumed_actor = &provider.requests[17];
    assert!(resumed_actor.history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content } if content.contains("fresh-context-checkpoint-v1")
    )));

    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    let checkpoints = parsed
        .iter()
        .filter(|event| event["type"] == "context.checkpointed")
        .collect::<Vec<_>>();
    assert_eq!(checkpoints.len(), 1);
    let checkpoint = checkpoints[0];
    assert_eq!(checkpoint["data"]["source_history_items"], 32);
    assert_eq!(checkpoint["data"]["checkpoint_history_items"], 3);
    assert_eq!(checkpoint["data"]["provider_turn_count"], 15);
    assert_eq!(checkpoint["data"]["tool_call_count"], 15);
    assert_eq!(checkpoint["data"]["observed_input_tokens"], 300_000);
    let checkpoint_index = parsed
        .iter()
        .position(|event| event["type"] == "context.checkpointed")
        .expect("checkpoint event");
    let next_request = parsed[checkpoint_index + 1]
        .get("data")
        .expect("next request data");
    assert_eq!(parsed[checkpoint_index + 1]["type"], "provider.requested");
    assert_eq!(
        next_request["media_history_receipt"]["history_sha256"],
        checkpoint["data"]["checkpoint_history_sha256"]
    );
    assert_eq!(
        events.matches("\"type\":\"context.checkpointed\"").count(),
        1
    );
    assert!(events.contains("\"text\":\"revised\""));
}

#[tokio::test]
async fn semantic_checkpoint_v6_inlines_typed_capsule_and_binds_four_item_reset() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 64);
    let artifacts = root.path().join("artifacts");
    let deadline = semantic_checkpoint_phase_deadline(Instant::now() + Duration::from_secs(1_060));
    let mut responses = VecDeque::new();
    for turn in 0..15 {
        let call_id = format!("call-semantic-{turn}");
        let mut response = phase_named_calls_response(
            &format!("response-semantic-{turn}"),
            vec![(&call_id, "run_terminal_command", json!({}))],
        );
        response.usage = Some(json!({"input_tokens": 20_000, "output_tokens": 2}));
        responses.push_back(response);
    }
    let capsule = json!({
        "schema_version": "semantic-checkpoint-capsule-v1",
        "objective_state": "the focused implementation is present",
        "committed_changes": ["workspace/result.txt was written"],
        "validated_evidence": ["the bounded command returned settled"],
        "technical_decisions": ["preserve the current interface"],
        "unresolved_gap": "one independent read remains",
        "next_action": "inspect workspace/result.txt once",
        "do_not_repeat": ["do not repeat broad discovery"],
        "artifact_locators": ["workspace/result.txt"],
    });
    responses.push_back(semantic_inline_checkpoint_response(
        "response-inline-capsule",
        capsule.clone(),
        vec![("call-semantic-same-turn", "run_terminal_command", json!({}))],
    ));
    responses.push_back(phase_message_response("response-candidate", "candidate"));
    responses.push_back(phase_message_response(
        "response-critic",
        "claim: current workspace state; reason: capsule is not proof; check: inspect once",
    ));
    responses.push_back(phase_message_response("response-revised", "revised"));
    let mut provider = PhaseProvider {
        responses,
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 64;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::SemanticCheckpointV6,
    )
    .await
    .expect("semantic checkpointed run");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(executor.executions, 16);
    assert_eq!(provider.requests.len(), 19);
    let inline = &provider.requests[15];
    assert_eq!(inline.mode, ProviderRequestMode::ActionOpen);
    let checkpoint_tool = inline
        .tools
        .iter()
        .find(|tool| tool.name == "record_semantic_checkpoint_v1")
        .expect("inline checkpoint control tool");
    assert_eq!(checkpoint_tool.parameters["additionalProperties"], false);
    assert_eq!(
        checkpoint_tool.parameters["required"]
            .as_array()
            .map(Vec::len),
        Some(9)
    );
    assert_eq!(inline.history.len(), 33);
    assert!(inline.history.iter().any(|item| matches!(
        item,
        HistoryItem::FunctionCall { call_id, .. } if call_id == "call-semantic-0"
    )));
    assert!(inline.history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content }
            if content.contains("semantic_checkpoint_inline_v1")
                && content.contains("semantic-checkpoint-capsule-v1")
    )));

    let reset = &provider.requests[16];
    assert_eq!(reset.mode, ProviderRequestMode::ActionOpen);
    assert_eq!(reset.history.len(), 4);
    let reset_json = serde_json::to_string(&reset.history).expect("reset history");
    assert!(reset_json.contains("semantic_context_checkpoint_v1"));
    assert!(reset_json.contains("workspace/result.txt"));
    assert!(reset_json.contains("settled"));
    assert!(!reset_json.contains("call-semantic-0"));
    let HistoryItem::User {
        content: canonical_capsule,
    } = &reset.history[2]
    else {
        panic!("canonical capsule item");
    };
    assert_eq!(
        serde_json::from_str::<Value>(canonical_capsule).expect("canonical capsule"),
        capsule
    );
    assert!(!canonical_capsule.contains('\n'));

    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    assert_eq!(
        parsed[0]["data"]["completion_review_policy"],
        "semantic-checkpoint-v6"
    );
    assert_eq!(
        parsed[0]["data"]["context_checkpoint_policy_version"],
        "semantic-context-checkpoint-v1"
    );
    let checkpoint_index = parsed
        .iter()
        .position(|event| event["type"] == "context.checkpointed")
        .expect("semantic checkpoint event");
    let checkpoint = &parsed[checkpoint_index];
    assert_eq!(checkpoint["data"]["source_history_items"], 32);
    assert_eq!(checkpoint["data"]["checkpoint_history_items"], 4);
    assert_eq!(checkpoint["data"]["provider_turn_count"], 16);
    assert_eq!(checkpoint["data"]["observed_input_tokens"], 300_004);
    assert_eq!(checkpoint["data"]["prepare_turn_index"], 15);
    assert_eq!(checkpoint["data"]["tail_reserve_ms"], 900_000);
    let inline_request = parsed
        .iter()
        .find(|event| event["type"] == "provider.requested" && event["data"]["turn_index"] == 15)
        .expect("inline request event");
    assert_eq!(
        inline_request["data"]["checkpoint_source_history_sha256"],
        checkpoint["data"]["source_history_sha256"]
    );
    assert_eq!(
        inline_request["data"]["media_history_receipt"]["history_sha256"],
        checkpoint["data"]["prepare_history_sha256"]
    );
    assert_eq!(parsed[checkpoint_index + 1]["type"], "provider.requested");
    assert_eq!(
        parsed[checkpoint_index + 1]["data"]["media_history_receipt"]["history_sha256"],
        checkpoint["data"]["checkpoint_history_sha256"]
    );
    assert_eq!(
        events.matches("\"type\":\"context.checkpointed\"").count(),
        1
    );
    assert_eq!(
        events
            .matches("\"type\":\"context.checkpoint_rejected\"")
            .count(),
        0
    );
    assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 16);
    assert!(!parsed.iter().any(|event| {
        event["type"] == "tool.completed"
            && event["data"]["provider_name"] == "record_semantic_checkpoint_v1"
    }));
    assert!(events.contains("\"text\":\"revised\""));
}

#[tokio::test]
async fn semantic_checkpoint_v6_invalid_capsule_rejects_once_and_preserves_source_history() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 64);
    let artifacts = root.path().join("artifacts");
    let deadline = semantic_checkpoint_phase_deadline(Instant::now() + Duration::from_secs(1_060));
    let mut responses = VecDeque::new();
    for turn in 0..15 {
        let call_id = format!("call-rejection-{turn}");
        let mut response = phase_named_calls_response(
            &format!("response-rejection-{turn}"),
            vec![(&call_id, "run_terminal_command", json!({}))],
        );
        response.usage = Some(json!({"input_tokens": 20_000, "output_tokens": 2}));
        responses.push_back(response);
    }
    responses.push_back(semantic_inline_checkpoint_response(
        "response-invalid-capsule",
        json!({"unexpected": true}),
        Vec::new(),
    ));
    responses.push_back(phase_message_response("response-candidate", "candidate"));
    responses.push_back(phase_message_response(
        "response-critic",
        "claim: current workspace state; reason: no independent read; check: inspect once",
    ));
    responses.push_back(phase_message_response("response-revised", "revised"));
    let mut provider = PhaseProvider {
        responses,
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 64;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::SemanticCheckpointV6,
    )
    .await
    .expect("invalid capsule falls back safely");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(provider.requests.len(), 19);
    assert_eq!(provider.requests[15].mode, ProviderRequestMode::ActionOpen);
    let resumed = &provider.requests[16];
    assert_eq!(resumed.mode, ProviderRequestMode::ActionOpen);
    assert_eq!(resumed.history.len(), 35);
    assert!(resumed.history.iter().any(|item| matches!(
        item,
        HistoryItem::FunctionCall { call_id, .. } if call_id == "call-rejection-0"
    )));
    assert!(!resumed.history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content } if content.contains("semantic_context_checkpoint_v1")
    )));

    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    let rejection = parsed
        .iter()
        .find(|event| event["type"] == "context.checkpoint_rejected")
        .expect("typed rejection");
    assert_eq!(
        rejection["data"]["reason"],
        "semantic_checkpoint_capsule_json_invalid"
    );
    assert_eq!(rejection["data"]["request_emitted"], true);
    assert_eq!(rejection["data"]["response_received"], true);
    assert_eq!(
        rejection["data"]["capsule_content_excerpt"],
        r#"{"unexpected":true}"#
    );
    assert_eq!(rejection["data"]["capsule_content_bytes"], 19);
    assert_eq!(
        rejection["data"]["capsule_content_sha256"],
        sha256_hex(br#"{"unexpected":true}"#),
    );
    assert_eq!(
        events
            .matches("\"type\":\"context.checkpoint_rejected\"")
            .count(),
        1
    );
    assert_eq!(
        events.matches("\"type\":\"context.checkpointed\"").count(),
        0
    );
}

#[tokio::test]
async fn semantic_checkpoint_v6_inline_rejection_matrix_preserves_source_history() {
    let mut extra_field = semantic_checkpoint_capsule();
    extra_field["unexpected"] = json!(true);
    let mut oversize = semantic_checkpoint_capsule();
    oversize["objective_state"] = json!("x".repeat(8193));
    let cases = vec![
        (
            "empty",
            semantic_inline_checkpoint_response("response-empty-capsule", json!({}), Vec::new()),
            "semantic_checkpoint_capsule_json_invalid",
            15,
        ),
        (
            "oversize",
            semantic_inline_checkpoint_response("response-oversize-capsule", oversize, Vec::new()),
            "semantic_checkpoint_capsule_bytes_exceeded",
            15,
        ),
        (
            "extra-field",
            semantic_inline_checkpoint_response(
                "response-extra-field-capsule",
                extra_field,
                Vec::new(),
            ),
            "semantic_checkpoint_capsule_json_invalid",
            15,
        ),
        (
            "missing-control",
            phase_named_calls_response(
                "response-missing-control",
                vec![("call-inline-action", "run_terminal_command", json!({}))],
            ),
            "semantic_checkpoint_control_call_missing",
            16,
        ),
        (
            "duplicate-control",
            phase_named_calls_response(
                "response-duplicate-control",
                vec![
                    (
                        "call-control-one",
                        "record_semantic_checkpoint_v1",
                        semantic_checkpoint_capsule(),
                    ),
                    (
                        "call-control-two",
                        "record_semantic_checkpoint_v1",
                        semantic_checkpoint_capsule(),
                    ),
                ],
            ),
            "semantic_checkpoint_control_call_duplicate",
            15,
        ),
    ];

    for (label, prepare_response, expected_reason, expected_executions) in cases {
        let root = tempfile::tempdir().expect("test root");
        let contract = write_contract_with_max_provider_turns(root.path(), 64);
        let artifacts = root.path().join("artifacts");
        let deadline =
            semantic_checkpoint_phase_deadline(Instant::now() + Duration::from_secs(1_060));
        let mut responses = semantic_checkpoint_prefix_responses(label);
        responses.push_back(prepare_response);
        responses.push_back(phase_message_response("response-candidate", "candidate"));
        responses.push_back(phase_message_response(
            "response-critic",
            "claim: current state; reason: prepare was rejected; check: inspect once",
        ));
        responses.push_back(phase_message_response("response-revised", "revised"));
        let mut provider = PhaseProvider {
            responses,
            requests: Vec::new(),
            action_return_at: None,
        };
        let mut executor = ImmediateExecutor::default();
        let mut spec = phase_spec(&contract, &artifacts);
        spec.provider.max_turns = 64;

        let outcome = run_agent_with_deadline_and_review(
            &spec,
            &contract,
            &mut provider,
            &mut executor,
            &deadline,
            CompletionReviewPolicy::SemanticCheckpointV6,
        )
        .await
        .unwrap_or_else(|_| panic!("{label} prepare rejection must fall back safely"));

        assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
        assert_eq!(executor.executions, expected_executions);
        assert_eq!(provider.requests[15].mode, ProviderRequestMode::ActionOpen);
        let resumed = &provider.requests[16];
        assert_eq!(resumed.mode, ProviderRequestMode::ActionOpen);
        assert!(resumed.history.len() >= 35);
        assert!(resumed.history.iter().any(|item| matches!(
            item,
            HistoryItem::FunctionCall { call_id, .. }
                if call_id == &format!("call-{label}-0")
        )));
        assert!(!resumed.history.iter().any(|item| matches!(
            item,
            HistoryItem::User { content }
                if content.contains("semantic_context_checkpoint_v1")
        )));

        let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
        let parsed = events
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
            .collect::<Vec<_>>();
        let rejection = parsed
            .iter()
            .find(|event| event["type"] == "context.checkpoint_rejected")
            .expect("typed rejection");
        assert_eq!(rejection["data"]["reason"], expected_reason, "{label}");
        assert_eq!(rejection["data"]["request_emitted"], true, "{label}");
        assert_eq!(rejection["data"]["response_received"], true, "{label}");
        assert_eq!(
            events.matches("\"type\":\"provider.failed\"").count(),
            0,
            "{label}"
        );
        assert_eq!(
            events
                .matches("\"type\":\"context.checkpoint_rejected\"")
                .count(),
            1,
            "{label}"
        );
        assert_eq!(
            events.matches("\"type\":\"context.checkpointed\"").count(),
            0,
            "{label}"
        );
    }
}

#[tokio::test]
async fn semantic_checkpoint_v6_inline_transport_failure_remains_an_action_failure() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 64);
    let artifacts = root.path().join("artifacts");
    let deadline = semantic_checkpoint_phase_deadline(Instant::now() + Duration::from_secs(1_060));
    let mut responses = semantic_checkpoint_prefix_responses("prepare-failure");
    responses.push_back(phase_message_response("response-candidate", "candidate"));
    responses.push_back(phase_message_response(
        "response-critic",
        "claim: current state; reason: prepare failed; check: inspect once",
    ));
    responses.push_back(phase_message_response("response-revised", "revised"));
    let mut provider = OneShotFailureProvider {
        responses,
        requests: Vec::new(),
        failure_at_request: 15,
        failure_code: "semantic_prepare_transport_failed",
        failure_emitted: false,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 64;

    let result = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::SemanticCheckpointV6,
    )
    .await;

    let error = result.expect_err("inline request is the ordinary action and must fail truthfully");
    assert_eq!(error.code(), "semantic_prepare_transport_failed");
    assert_eq!(provider.requests.len(), 16);
    assert_eq!(provider.requests[15].mode, ProviderRequestMode::ActionOpen);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert_eq!(
        events
            .matches("\"type\":\"context.checkpoint_rejected\"")
            .count(),
        0
    );
    assert_eq!(
        events.matches("\"type\":\"context.checkpointed\"").count(),
        0
    );
}

#[tokio::test]
async fn semantic_checkpoint_v6_inline_call_limit_recovery_closes_checkpoint_relation() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 64);
    let artifacts = root.path().join("artifacts");
    let deadline = semantic_checkpoint_phase_deadline(Instant::now() + Duration::from_secs(1_060));
    let mut responses = semantic_checkpoint_prefix_responses("inline-call-limit");
    responses.push_back(semantic_inline_call_limit_response());
    responses.push_back(phase_message_response("response-candidate", "candidate"));
    responses.push_back(phase_message_response(
        "response-critic",
        "claim: current state; reason: call-limit response was rejected; check: inspect once",
    ));
    responses.push_back(phase_message_response("response-revised", "revised"));
    let mut provider = PhaseProvider {
        responses,
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 64;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::SemanticCheckpointV6,
    )
    .await
    .expect("call-limit recovery must remain auditable and continue");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(outcome.record.provider_call_coverage.failed, 1);
    assert_eq!(executor.executions, 15);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    let rejection = parsed
        .iter()
        .find(|event| event["type"] == "context.checkpoint_rejected")
        .expect("checkpoint rejection");
    assert_eq!(rejection["data"]["reason"], "provider_call_limit_exceeded");
    let failed_index = parsed
        .iter()
        .position(|event| event["type"] == "provider.failed")
        .expect("provider failure");
    let rejected_index = parsed
        .iter()
        .position(|event| event["type"] == "context.checkpoint_rejected")
        .expect("checkpoint rejection");
    assert_eq!(rejected_index, failed_index + 1);
    assert!(events.contains("\"text\":\"revised\""));
}

#[tokio::test]
async fn semantic_checkpoint_v6_turn_lease_admits_one_soft_action_then_provisional_and_critic() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 28);
    let artifacts = root.path().join("artifacts");
    let deadline = semantic_checkpoint_phase_deadline(Instant::now() + Duration::from_secs(1_060));
    let mut responses = semantic_checkpoint_prefix_responses("lease-prefix");
    let capsule = semantic_checkpoint_capsule();
    responses.push_back(semantic_inline_checkpoint_response(
        "response-capsule",
        capsule,
        Vec::new(),
    ));
    for turn in 0..7 {
        let call_id = format!("call-lease-action-{turn}");
        responses.push_back(phase_named_calls_response(
            &format!("response-lease-action-{turn}"),
            vec![(&call_id, "run_terminal_command", json!({}))],
        ));
    }
    responses.push_back(phase_message_response("response-candidate", "candidate"));
    responses.push_back(phase_message_response(
        "response-critic",
        "claim: current state; reason: verify the final soft action; check: inspect once",
    ));
    responses.push_back(phase_message_response("response-revised", "revised"));
    let mut provider = PhaseProvider {
        responses,
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 28;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::SemanticCheckpointV6,
    )
    .await
    .expect("frozen turn lease must reach reviewed final");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(executor.executions, 22);
    assert_eq!(provider.requests.len(), 26);
    assert_eq!(provider.requests[15].mode, ProviderRequestMode::ActionOpen);
    assert_eq!(provider.requests[16].history.len(), 4);
    assert_eq!(provider.requests[22].mode, ProviderRequestMode::ActionOpen);
    assert!(provider.requests[22].history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content }
            if content.contains("choose one self-contained bounded repair or finalize")
    )));
    assert_eq!(provider.requests[23].mode, ProviderRequestMode::FinalOnly);
    assert!(provider.requests[23].tools.is_empty());
    assert_eq!(provider.requests[24].mode, ProviderRequestMode::FinalOnly);
    assert!(provider.requests[24].tools.is_empty());

    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    let checkpoint = parsed
        .iter()
        .find(|event| event["type"] == "context.checkpointed")
        .expect("checkpoint event");
    assert_eq!(checkpoint["data"]["action_turn_cutoff"], 22);
    let provisional = parsed
        .iter()
        .find(|event| {
            event["type"] == "provider.requested"
                && event["data"]["budget_observation"]["phase"] == "checkpoint_provisional"
        })
        .expect("provisional request");
    assert_eq!(provisional["data"]["turn_index"], 23);
    assert_eq!(provisional["data"]["tool_count"], 0);
    assert!(events.contains("\"text\":\"revised\""));
}

#[tokio::test]
async fn semantic_checkpoint_v6_provisional_and_critic_failures_are_phase_safe() {
    for (label, failure_at_request, preserves_candidate) in
        [("provisional", 23, false), ("critic", 24, true)]
    {
        let root = tempfile::tempdir().expect("test root");
        let contract = write_contract_with_max_provider_turns(root.path(), 28);
        let artifacts = root.path().join("artifacts");
        let deadline =
            semantic_checkpoint_phase_deadline(Instant::now() + Duration::from_secs(1_060));
        let mut responses = semantic_checkpoint_prefix_responses(label);
        responses.push_back(semantic_inline_checkpoint_response(
            "response-capsule",
            semantic_checkpoint_capsule(),
            Vec::new(),
        ));
        for turn in 0..7 {
            let call_id = format!("call-{label}-action-{turn}");
            responses.push_back(phase_named_calls_response(
                &format!("response-{label}-action-{turn}"),
                vec![(&call_id, "run_terminal_command", json!({}))],
            ));
        }
        responses.push_back(phase_message_response("response-candidate", "candidate"));
        let mut provider = OneShotFailureProvider {
            responses,
            requests: Vec::new(),
            failure_at_request,
            failure_code: "semantic_phase_transport_failed",
            failure_emitted: false,
        };
        let mut executor = ImmediateExecutor::default();
        let mut spec = phase_spec(&contract, &artifacts);
        spec.provider.max_turns = 28;

        let result = run_agent_with_deadline_and_review(
            &spec,
            &contract,
            &mut provider,
            &mut executor,
            &deadline,
            CompletionReviewPolicy::SemanticCheckpointV6,
        )
        .await;
        if preserves_candidate {
            let outcome = result.expect("critic failure must preserve the candidate");
            assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
        } else {
            let error = result.expect_err("provisional failure must fail terminally");
            assert_eq!(error.code(), "semantic_phase_transport_failed");
            let run: Value =
                serde_json::from_slice(&fs::read(artifacts.join("run.json")).expect("run record"))
                    .expect("run JSON");
            assert_eq!(run["terminal_status"], "provider_failure");
            assert_eq!(run["terminal_phase"], "provider");
        }
        let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
        assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
        assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 22);
        assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 22);
        assert_eq!(
            events.contains("\"text\":\"candidate\""),
            preserves_candidate,
            "{label}"
        );
        assert_eq!(
            events.matches("\"type\":\"assistant.final\"").count(),
            usize::from(preserves_candidate),
            "{label}"
        );
    }
}

#[tokio::test]
async fn isolated_fresh_critic_provider_failure_preserves_candidate() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 5);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_message_response("response-candidate", "candidate")]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 5;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::FreshEvidenceDebtV3,
    )
    .await
    .expect("isolated critic failure cannot invalidate an unchanged candidate");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(outcome.record.provider_call_coverage.requested, 2);
    assert_eq!(outcome.record.provider_call_coverage.completed, 1);
    assert_eq!(outcome.record.provider_call_coverage.failed, 1);
    assert_eq!(executor.executions, 0);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert!(events.contains("\"code\":\"phase_script_exhausted\""));
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn fresh_critic_tool_response_is_atomically_rejected_and_candidate_survives() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 5);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_tool_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 5;

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::FreshEvidenceDebtV3,
    )
    .await
    .expect("critic rejection falls back to candidate");

    assert_eq!(provider.requests.len(), 2);
    assert_eq!(executor.executions, 0);
    assert_eq!(outcome.record.provider_call_coverage.requested, 2);
    assert_eq!(outcome.record.provider_call_coverage.completed, 1);
    assert_eq!(outcome.record.provider_call_coverage.failed, 1);
    assert_eq!(outcome.record.provider_call_coverage.usage_present, 2);
    assert_eq!(outcome.record.provider_call_coverage.usage_absent, 0);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert!(events.contains("\"code\":\"provider_call_limit_exceeded\""));
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn completion_review_is_opt_in_for_deadline_runs() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_message_response("response-unused", "unused"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome =
        run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
            .await
            .expect("unreviewed run");

    assert_eq!(provider.requests.len(), 1);
    assert_eq!(outcome.record.provider_turn_count, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert!(events.contains("\"text\":\"candidate\""));
    assert!(!events.contains("independent_falsification_review_v1"));
}

#[tokio::test]
async fn low_action_window_is_declared_before_provider_selects_next_action() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(2));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_message_response("response-final", "done")]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
        .await
        .expect("bounded action-window run");

    assert_eq!(provider.requests.len(), 1);
    let notice = provider.requests[0]
        .history
        .iter()
        .find_map(|item| match item {
            nano_provider_xai::HistoryItem::User { content }
                if content.contains("runtime_budget_v1") =>
            {
                Some(content)
            }
            _ => None,
        })
        .expect("runtime budget notice");
    assert!(notice.contains("action_remaining_ms="));
    assert!(notice.contains("settlement_remaining_ms="));
    assert!(notice.contains("last_send_remaining_ms="));
    assert!(notice.contains("Preserve the strongest durable deliverable"));
    assert!(notice.contains("Do not begin exploratory work"));
    assert!(notice.contains("Background work does not extend these deadlines"));
    assert!(!notice.contains("benchmark"));
    assert!(!notice.contains("verifier"));
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let requested = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .find(|event| event["type"] == "provider.requested")
        .expect("provider request event");
    let observation = &requested["data"]["budget_observation"];
    assert_eq!(observation["phase"], "action_open");
    assert_eq!(observation["budget_notice_visible"], true);
    let action = observation["action_remaining_ms"]
        .as_u64()
        .expect("action remaining");
    let settlement = observation["settlement_remaining_ms"]
        .as_u64()
        .expect("settlement remaining");
    let last_send = observation["last_send_remaining_ms"]
        .as_u64()
        .expect("last send remaining");
    assert!(action <= settlement && settlement <= last_send);
}

#[tokio::test]
async fn rejected_call_limit_response_gets_one_atomic_recovery_turn() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_call_limit_response(), phase_final_response()]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome =
        run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
            .await
            .expect("one bounded recovery turn should complete");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(executor.executions, 0);
    assert_eq!(provider.requests.len(), 2);
    let recovery = provider.requests[1]
        .history
        .iter()
        .filter_map(|item| match item {
            HistoryItem::User { content } => Some(content.as_str()),
            _ => None,
        })
        .next_back()
        .expect("recovery notice");
    assert!(recovery.contains("rejected atomically"));
    assert!(recovery.contains("none were executed"));
    assert!(recovery.contains("at most 8 tool calls"));
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let failed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .find(|event| event["type"] == "provider.failed")
        .expect("provider failure event");
    assert_eq!(failed["data"]["rejected_call_count"], 9);
    assert_eq!(failed["data"]["response_usage"]["input_tokens"], 11);
    assert_eq!(
        failed["data"]["response_usage"]["provider_cost_ticks"],
        123_000_000
    );
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
    let record: Value =
        serde_json::from_slice(&fs::read(artifacts.join("run.json")).expect("terminal run record"))
            .expect("run record JSON");
    assert_eq!(record["provider_call_coverage"]["requested"], 2);
    assert_eq!(record["provider_call_coverage"]["completed"], 1);
    assert_eq!(record["provider_call_coverage"]["failed"], 1);
    assert_eq!(record["provider_call_coverage"]["usage_present"], 2);
    assert_eq!(record["provider_call_coverage"]["usage_absent"], 0);
    assert_eq!(record["provider_call_coverage"]["cost_present"], 1);
    assert_eq!(record["provider_call_coverage"]["state"], "complete");
    assert_eq!(record["usage_totals"]["input_tokens"], 14);
    assert_eq!(record["usage_totals"]["output_tokens"], 4);
    assert_eq!(record["usage_totals"]["provider_cost_ticks"], 123_000_000);
}

#[tokio::test]
async fn repeated_call_limit_response_is_terminal_without_any_dispatch() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_call_limit_response(), phase_call_limit_response()]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let error = run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
        .await
        .expect_err("the second over-limit response must terminate");

    assert_eq!(error.code(), "provider_call_limit_exceeded");
    assert_eq!(executor.executions, 0);
    assert_eq!(provider.requests.len(), 2);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
}

#[tokio::test]
async fn completion_challenge_leaves_v2_final_behavior_unchanged() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_message_response("response-final", "original")]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent(&spec, &contract, &mut provider, &mut executor)
        .await
        .expect("legacy V2 run");

    assert_eq!(provider.requests.len(), 1);
    assert_eq!(outcome.record.provider_turn_count, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.requested\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"original\""));
}

#[tokio::test]
async fn completion_challenge_skips_when_full_review_reserve_does_not_remain() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(2));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_message_response("response-candidate", "candidate")]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("unreviewed low-budget run");

    assert_eq!(provider.requests.len(), 1);
    assert_eq!(provider.requests[0].mode, ProviderRequestMode::ActionOpen);
    assert_eq!(outcome.record.provider_turn_count, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn completion_challenge_tool_call_uses_normal_settlement_without_rechallenge() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_tool_response(),
            phase_message_response("response-final", "verified"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("reviewed tool run");

    assert_eq!(provider.requests.len(), 3);
    assert_eq!(executor.executions, 1);
    assert_eq!(outcome.record.provider_turn_count, 3);
    assert_eq!(outcome.record.tool_call_count, 1);
    for request in &provider.requests[1..] {
        let challenge_count = request
            .history
            .iter()
            .filter(|item| {
                matches!(
                    item,
                    nano_provider_xai::HistoryItem::User { content }
                        if content.contains("independent_falsification_review_v1")
                )
            })
            .count();
        assert_eq!(challenge_count, 1);
    }
    assert!(!provider.requests[1].history.iter().any(|item| matches!(
        item,
        nano_provider_xai::HistoryItem::User { content }
            if content.contains("completion_review_decision_v2")
    )));
    assert!(provider.requests[2].history.iter().any(|item| matches!(
        item,
        nano_provider_xai::HistoryItem::User { content }
            if content.contains("completion_review_decision_v2")
                && content.contains("Do not begin another exploratory validation")
    )));
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"verified\""));
    let registered = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .find(|event| event["type"] == "tool.registered")
        .expect("tool registration event");
    let observation = &registered["data"]["budget_observation"];
    assert_eq!(observation["dispatch_open_at_registration"], true);
    let action = observation["action_remaining_ms"]
        .as_u64()
        .expect("action remaining");
    let settlement = observation["settlement_remaining_ms"]
        .as_u64()
        .expect("settlement remaining");
    let last_send = observation["last_send_remaining_ms"]
        .as_u64()
        .expect("last send remaining");
    assert!(action <= settlement && settlement <= last_send);
}

#[tokio::test]
async fn exact_hello_world_no_debt_review_preserves_the_existing_artifact() {
    let root = tempfile::tempdir().expect("test root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let artifact = workspace.join("result.txt");
    fs::write(&artifact, "hello world\n").expect("already-correct artifact");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response(
                "response-candidate",
                "The existing result is exactly hello world.",
            ),
            phase_message_response(
                "response-no-debt-final",
                "Verified: the already-correct hello world artifact is unchanged.",
            ),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = CompletionFixtureExecutor::new(&workspace);
    let mut spec = phase_spec(&contract, &artifacts);
    spec.workspace_dir = workspace;
    spec.task.instruction =
        "Keep /workspace/result.txt exactly `hello world`; it is already correct.".to_owned();
    spec.task
        .git_history_capability
        .canonical_instruction_sha256 = sha256_hex(spec.task.instruction.as_bytes());

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect("no-debt completion review");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(provider.requests.len(), 2);
    assert!(provider.requests[1].history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content }
            if content.contains("evidence_debt_review_v2")
                && content.contains("/workspace/result.txt")
                && content.contains("hello world")
    )));
    assert!(executor.executions.is_empty(), "review invented a mutation");
    assert_eq!(
        fs::read_to_string(&artifact).expect("preserved artifact"),
        "hello world\n"
    );
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("already-correct hello world artifact is unchanged"));
}

#[tokio::test]
async fn exact_set_val_request_ledger_corrects_path_and_value_then_revalidates_read_only() {
    let root = tempfile::tempdir().expect("test root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    fs::write(
        workspace.join("wrong.proto"),
        "message SetValRequest { string val = 1; }\n",
    )
    .expect("mismatched schema fixture");
    let contract = write_contract_with_max_provider_turns(root.path(), 5);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response(
                "response-candidate",
                "SetValRequest.val was written to /workspace/wrong.proto.",
            ),
            phase_named_calls_response(
                "response-ledger-validation",
                vec![(
                    "call-ledger-validation",
                    "grep",
                    json!({"path":"/workspace/api.proto","pattern":"SetValRequest.value"}),
                )],
            ),
            phase_named_calls_response(
                "response-ledger-correction",
                vec![
                    (
                        "call-ledger-stage",
                        "run_terminal_command",
                        json!({
                            "command":"build /workspace/api.proto.next with SetValRequest.value",
                            "description":"stage the complete exact schema"
                        }),
                    ),
                    (
                        "call-ledger-activate",
                        "run_terminal_command",
                        json!({
                            "command":"activate /workspace/api.proto.next as /workspace/api.proto",
                            "description":"atomically activate the complete schema"
                        }),
                    ),
                ],
            ),
            phase_named_calls_response(
                "response-ledger-revalidation",
                vec![(
                    "call-ledger-revalidation",
                    "grep",
                    json!({"path":"/workspace/api.proto","pattern":"SetValRequest.value"}),
                )],
            ),
            phase_message_response(
                "response-ledger-final",
                "Exact path and SetValRequest.value are verified.",
            ),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = CompletionFixtureExecutor::new(&workspace);
    let mut spec = phase_spec(&contract, &artifacts);
    spec.workspace_dir = workspace.clone();
    spec.provider.max_turns = 5;
    spec.task.instruction = "Create /workspace/api.proto containing exactly `message \
SetValRequest { string value = 1; }`."
        .to_owned();
    spec.task
        .git_history_capability
        .canonical_instruction_sha256 = sha256_hex(spec.task.instruction.as_bytes());
    spec.active_tools = Some(vec!["run_terminal_command".to_owned(), "grep".to_owned()]);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect("exact-ledger correction and revalidation");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(provider.requests.len(), 5);
    assert!(provider.requests[2].history.iter().any(|item| matches!(
        item,
        HistoryItem::FunctionCallOutput { call_id, output }
            if call_id == "call-ledger-validation"
                && output.contains("acceptance_mismatch")
                && output.contains("value!=SetValRequest.value")
                && output.contains("path!=/workspace/api.proto")
    )));
    assert!(provider.requests[2].history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content } if content.contains("completion_review_decision_v2")
    )));
    assert_eq!(
        executor.executions,
        [
            "call-ledger-validation",
            "call-ledger-stage",
            "call-ledger-activate",
            "call-ledger-revalidation",
        ]
    );
    assert_eq!(provider.requests[4].mode, ProviderRequestMode::FinalOnly);
    assert_eq!(
        fs::read_to_string(workspace.join("api.proto")).expect("exact schema"),
        "message SetValRequest { string value = 1; }\n"
    );
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    let dispatched = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .filter(|event| event["type"] == "tool.dispatched")
        .map(|event| {
            event["data"]["call_id"]
                .as_str()
                .expect("call id")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(dispatched, executor.executions);
    assert_eq!(
        dispatched
            .iter()
            .skip_while(|call_id| call_id.as_str() != "call-ledger-activate")
            .skip(1)
            .collect::<Vec<_>>(),
        [&"call-ledger-revalidation".to_owned()]
    );
    assert_eq!(events.matches("completion_review_phase_closed").count(), 0);
}

#[tokio::test]
async fn working_service_survives_complete_replacement_and_split_teardown_is_phase_closed() {
    let root = tempfile::tempdir().expect("test root");
    let workspace = root.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let contract = write_contract_with_max_provider_turns(root.path(), 5);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "stable-v1 is serving traffic."),
            phase_named_calls_response(
                "response-service-validation",
                vec![(
                    "call-service-validation",
                    "grep",
                    json!({"path":"service-status","pattern":"available"}),
                )],
            ),
            phase_named_calls_response(
                "response-complete-service-replacement",
                vec![
                    (
                        "call-service-prepare",
                        "run_terminal_command",
                        json!({
                            "command":"prepare replacement-v2 while stable-v1 stays live",
                            "description":"prepare the complete replacement"
                        }),
                    ),
                    (
                        "call-service-activate",
                        "run_terminal_command",
                        json!({
                            "command":"atomically activate ready replacement-v2",
                            "description":"switch only after replacement readiness"
                        }),
                    ),
                ],
            ),
            phase_named_calls_response(
                "response-split-teardown",
                vec![(
                    "call-service-teardown-only",
                    "run_terminal_command",
                    json!({
                        "command":"stop the active service now and restart it later",
                        "description":"invalid split teardown-only follow-up"
                    }),
                )],
            ),
            phase_message_response(
                "response-service-final",
                "replacement-v2 is active without a service gap.",
            ),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = CompletionFixtureExecutor::with_working_service(&workspace);
    let mut spec = phase_spec(&contract, &artifacts);
    spec.workspace_dir = workspace;
    spec.provider.max_turns = 5;
    spec.task.instruction = "Replace the working service without making it unavailable.".to_owned();
    spec.task
        .git_history_capability
        .canonical_instruction_sha256 = sha256_hex(spec.task.instruction.as_bytes());
    spec.active_tools = Some(vec!["run_terminal_command".to_owned(), "grep".to_owned()]);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect("complete replacement with rejected split teardown");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(provider.requests.len(), 5);
    assert_eq!(
        executor.executions,
        [
            "call-service-validation",
            "call-service-prepare",
            "call-service-activate",
        ]
    );
    assert_eq!(executor.active_service.as_deref(), Some("replacement-v2"));
    assert!(executor.replacement_ready);
    assert_eq!(executor.service_availability, [true, true, true]);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("completion_review_phase_closed").count(), 1);
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    assert!(parsed.iter().any(|event| {
        event["type"] == "tool.registered"
            && event["data"]["call_id"] == "call-service-teardown-only"
    }));
    assert!(!parsed.iter().any(|event| {
        event["type"] == "tool.dispatched"
            && event["data"]["call_id"] == "call-service-teardown-only"
    }));
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("replacement-v2 is active without a service gap"));
}

#[tokio::test]
async fn completion_correction_mutation_forbids_stale_candidate_fallback() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_read_only_tool_response("response-validation", "call-validation"),
            phase_tool_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.active_tools = Some(vec!["run_terminal_command".to_owned(), "grep".to_owned()]);

    let error = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect_err("post-correction provider failure must not reuse stale candidate");

    assert_eq!(error.code(), "phase_script_exhausted");
    assert_eq!(provider.requests.len(), 4);
    assert_eq!(executor.executions, 2);
    assert!(provider.requests[2].history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content }
            if content.contains("completion_review_decision_v2")
    )));
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"run.failed\"").count(), 1);
    assert!(!events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn completion_correction_batch_is_serial_then_revalidation_is_read_only() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 5);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_read_only_tool_response("response-validation", "call-validation"),
            phase_complete_correction_response(),
            phase_read_only_tool_response("response-revalidation", "call-revalidation"),
            phase_message_response("response-final", "verified"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 5;
    spec.active_tools = Some(vec!["run_terminal_command".to_owned(), "grep".to_owned()]);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect("complete correction and read-only revalidation");

    assert_eq!(provider.requests.len(), 5);
    assert_eq!(outcome.record.provider_turn_count, 5);
    assert_eq!(outcome.record.tool_call_count, 4);
    assert_eq!(
        executor.executed_call_ids,
        [
            "call-validation",
            "call-correction-build",
            "call-correction-switch",
            "call-revalidation",
        ]
    );
    assert_eq!(provider.requests[4].mode, ProviderRequestMode::FinalOnly);
    assert!(provider.requests[2].history.iter().any(|item| matches!(
        item,
        HistoryItem::User { content }
            if content.contains("completion_review_decision_v2")
                && content.contains("serialized tool batch")
    )));
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 4);
    assert_eq!(events.matches("completion_review_phase_closed").count(), 0);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"verified\""));
    assert!(!events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn split_second_correction_is_phase_closed_without_stale_provisional() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract_with_max_provider_turns(root.path(), 5);
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_read_only_tool_response("response-validation", "call-validation"),
            phase_terminal_response("first-correction", json!({})),
            phase_terminal_response("split-second-correction", json!({})),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 5;
    spec.active_tools = Some(vec!["run_terminal_command".to_owned(), "grep".to_owned()]);

    let error = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect_err("a split correction cannot recover through the stale provisional");

    assert_eq!(error.code(), "phase_script_exhausted");
    assert_eq!(provider.requests.len(), 5);
    assert_eq!(executor.executions, 2);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("completion_review_phase_closed").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 0);
    assert!(!events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn completion_review_turn_limit_preserves_only_unmutated_provisional() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_read_only_tool_response("response-validation", "call-validation"),
            phase_read_only_tool_response("response-extra-read", "call-extra-read"),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 3;
    spec.active_tools = Some(vec!["run_terminal_command".to_owned(), "grep".to_owned()]);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::EvidenceDebtV2,
    )
    .await
    .expect("unmutated provisional survives exact turn limit");

    assert_eq!(outcome.record.provider_turn_count, 3);
    assert_eq!(provider.requests.len(), 3);
    assert_eq!(executor.executions, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 2);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    assert!(events.contains("completion_review_phase_closed"));
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn max_turn_without_provisional_remains_typed_failure() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = action_open_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_tool_response()]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let mut spec = phase_spec(&contract, &artifacts);
    spec.provider.max_turns = 1;

    let error = run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
        .await
        .expect_err("no-provisional exhaustion must stay typed");

    assert_eq!(error.code(), "provider_max_turns_exceeded");
    assert_eq!(provider.requests.len(), 1);
    assert_eq!(executor.executions, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"run.failed\"").count(), 1);
}

#[tokio::test]
async fn completion_challenge_provider_failure_preserves_audited_candidate() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_message_response("response-candidate", "candidate")]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("a failed review cannot invalidate an unchanged candidate");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(provider.requests.len(), 2);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"run.completed\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"run.failed\"").count(), 0);
    assert!(events.contains("\"text\":\"candidate\""));
    let run: Value =
        serde_json::from_slice(&fs::read(artifacts.join("run.json")).expect("run record"))
            .expect("run JSON");
    assert_eq!(run["provider_call_coverage"]["requested"], 2);
    assert_eq!(run["provider_call_coverage"]["completed"], 1);
    assert_eq!(run["provider_call_coverage"]["failed"], 1);
    assert_eq!(run["provider_call_coverage"]["in_flight"], 0);
    assert_eq!(run["terminal_status"], "success");
    assert_eq!(run["terminal_code"], "completed");
}

#[tokio::test]
async fn completion_challenge_timeout_preserves_audited_candidate() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(3));
    let mut provider = HangingChallengeProvider {
        candidate: Some(phase_message_response("response-candidate", "candidate")),
        requests: Vec::new(),
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("a timed-out review cannot invalidate an unchanged candidate");

    assert_eq!(outcome.record.terminal_status, TerminalStatus::Success);
    assert_eq!(provider.requests.len(), 2);
    let event_bytes = fs::read(artifacts.join("events.jsonl")).expect("events");
    let events = String::from_utf8(event_bytes.clone()).expect("events UTF-8");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"run.completed\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"run.failed\"").count(), 0);
    assert!(events.contains("\"text\":\"candidate\""));
    let candidate = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .find(|event| {
            event["type"] == "provider.completed"
                && event["data"]["response_id"] == "response-candidate"
        })
        .expect("auditable provisional provider completion");
    assert_eq!(candidate["data"]["has_final_text"], true);
    let event_types = events
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).expect("event JSON")["type"]
                .as_str()
                .expect("event type")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        event_types,
        [
            "run.started",
            "provider.requested",
            "provider.completed",
            "provider.requested",
            "provider.failed",
            "assistant.final",
            "run.completed",
        ]
    );
    let run: Value =
        serde_json::from_slice(&fs::read(artifacts.join("run.json")).expect("run record"))
            .expect("run JSON");
    assert_eq!(run["terminal_status"], "success");
    assert_eq!(run["terminal_code"], "completed");
    assert_eq!(run["provider_call_coverage"]["requested"], 2);
    assert_eq!(run["provider_call_coverage"]["completed"], 1);
    assert_eq!(run["provider_call_coverage"]["failed"], 1);
    assert_eq!(run["provider_call_coverage"]["in_flight"], 0);
    assert_eq!(run["events_sha256"], sha256_hex(&event_bytes));
    let terminal: Value = serde_json::from_str(events.lines().last().expect("terminal event"))
        .expect("terminal JSON");
    assert_eq!(terminal["type"], "run.completed");
    assert_eq!(run["final_event_seq"], terminal["seq"]);
}

#[tokio::test]
async fn completion_challenge_provider_validation_rejection_preserves_fallback() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_invalid_tool_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("validation fallback");

    assert_eq!(provider.requests.len(), 2);
    assert_eq!(outcome.record.provider_call_coverage.completed, 1);
    assert_eq!(outcome.record.provider_call_coverage.failed, 1);
    assert_eq!(outcome.record.provider_call_coverage.usage_present, 2);
    assert_eq!(outcome.record.provider_call_coverage.usage_absent, 0);
    assert_eq!(outcome.record.tool_call_count, 0);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"provider.failed\"").count(), 1);
    assert!(events.contains("\"response_usage\":{\"input_tokens\":5,\"output_tokens\":2}"));
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn completion_challenge_tool_validation_rejection_preserves_fallback() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_tool_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = RejectingExecutor;
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("rejected review tool fallback");

    assert_eq!(provider.requests.len(), 2);
    assert_eq!(outcome.record.tool_call_count, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 1);
    assert!(events.contains("challenge_validation_rejected"));
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn completion_challenge_action_phase_closed_rejection_preserves_fallback() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let actor_done = Instant::now() + Duration::from_secs(3);
    let deadline = review_phase_deadline(actor_done);
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_tool_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = DeadlineCrossingExecutor {
        dispatch_cutoff: actor_done,
    };
    let spec = phase_spec(&contract, &artifacts);

    let outcome = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect("closed action-phase fallback");

    assert_eq!(provider.requests.len(), 2);
    assert_eq!(outcome.record.tool_call_count, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.registered\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 0);
    assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 1);
    assert!(events.contains("action_phase_closed"));
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
    assert!(events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn completion_challenge_never_falls_back_after_tool_dispatch() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = review_phase_deadline(Instant::now() + Duration::from_secs(10));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([
            phase_message_response("response-candidate", "candidate"),
            phase_tool_response(),
        ]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = FailingExecutor;
    let spec = phase_spec(&contract, &artifacts);

    let error = run_agent_with_deadline_and_review(
        &spec,
        &contract,
        &mut provider,
        &mut executor,
        &deadline,
        CompletionReviewPolicy::IndependentFalsificationV1,
    )
    .await
    .expect_err("dispatched review tool failure must remain terminal");

    assert_eq!(error.code(), "challenge_tool_failed");
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.failed\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 0);
    assert!(!events.contains("\"text\":\"candidate\""));
}

#[tokio::test]
async fn p0b_settled_action_commits_before_schema_closed_final_send() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let actor_done = Instant::now() + Duration::from_secs(2);
    let deadline = action_open_phase_deadline(actor_done);
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_tool_response(), phase_final_response()]),
        requests: Vec::new(),
        action_return_at: Some(actor_done - Duration::from_millis(500)),
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome =
        run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
            .await
            .expect("phase-split run");

    assert_eq!(executor.executions, 1);
    assert_eq!(
        executor.settlement_deadlines,
        [deadline.instants.tool_settled]
    );
    assert_eq!(executor.semantic_deadlines, [deadline.instants.actor_done]);
    assert_eq!(provider.requests.len(), 2);
    assert_eq!(provider.requests[0].mode, ProviderRequestMode::ActionOpen);
    assert!(!provider.requests[0].tools.is_empty());
    assert_eq!(provider.requests[1].mode, ProviderRequestMode::FinalOnly);
    assert_eq!(provider.requests[1].tools, provider.requests[0].tools);
    assert!(provider.requests[1].history.iter().any(|item| matches!(
        item,
        nano_provider_xai::HistoryItem::FunctionCallOutput { call_id, output }
            if call_id == "call-phase" && output.starts_with("settled")
    )));
    assert_eq!(outcome.record.provider_turn_count, 2);
    assert_eq!(outcome.record.tool_call_count, 1);
    assert_eq!(outcome.record.usage_totals.input_tokens, Some(5));

    let event_bytes = fs::read(artifacts.join("events.jsonl")).expect("events");
    let events = String::from_utf8(event_bytes.clone()).expect("events UTF-8");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"tool.completed\"").count(), 1);
    let event_types = events
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).expect("event JSON")["type"]
                .as_str()
                .expect("event type")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let completion_index = event_types
        .iter()
        .position(|event| event == "tool.completed")
        .expect("tool completion");
    let final_request_index = event_types
        .iter()
        .enumerate()
        .filter(|(_, event)| event.as_str() == "provider.requested")
        .nth(1)
        .map(|(index, _)| index)
        .expect("final request");
    assert!(completion_index < final_request_index);
    let run: Value =
        serde_json::from_slice(&fs::read(artifacts.join("run.json")).expect("run record"))
            .expect("run JSON");
    assert_eq!(run["events_sha256"], sha256_hex(&event_bytes));
    let terminal: Value = serde_json::from_str(events.lines().last().expect("terminal event"))
        .expect("terminal JSON");
    assert_eq!(run["final_event_seq"], terminal["seq"]);
}

#[tokio::test]
async fn p0b_final_only_tool_call_fails_closed_without_dispatch() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = phase_deadline(Instant::now() + Duration::from_millis(500));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_tool_response()]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let error = run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
        .await
        .expect_err("final-only tool call must fail");

    assert_eq!(error.code(), "provider_final_only_tool_call");
    assert_eq!(executor.executions, 0);
    assert_eq!(provider.requests.len(), 1);
    assert_eq!(provider.requests[0].mode, ProviderRequestMode::FinalOnly);
    assert!(!provider.requests[0].tools.is_empty());
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert!(!events.contains("\"type\":\"tool.registered\""));
    assert!(!events.contains("\"type\":\"tool.dispatched\""));
    assert_eq!(events.matches("\"type\":\"provider.completed\"").count(), 1);
}

#[tokio::test]
async fn p0b_launch_under_capacity_allows_one_bounded_action_then_final_only() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let deadline = phase_deadline(Instant::now() + Duration::from_secs(45));
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_tool_response(), phase_final_response()]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome =
        run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
            .await
            .expect("one bounded launch action then final");

    assert_eq!(
        outcome.record.terminal_status,
        nano_types::event::TerminalStatus::Success
    );
    assert_eq!(provider.requests.len(), 2);
    assert_eq!(provider.requests[0].mode, ProviderRequestMode::ActionOpen);
    assert_eq!(provider.requests[1].mode, ProviderRequestMode::FinalOnly);
    assert_eq!(executor.executions, 1);
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    assert_eq!(events.matches("\"type\":\"assistant.final\"").count(), 1);
}

#[tokio::test]
async fn p0b_final_send_uses_last_send_without_minimum_window_regate() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let artifacts = root.path().join("artifacts");
    let now = Instant::now();
    let mut deadline = phase_deadline(now - Duration::from_secs(1));
    deadline.instants.last_send = now + Duration::from_millis(500);
    deadline.instants.runtime_final = deadline.instants.last_send;
    let mut provider = PhaseProvider {
        responses: VecDeque::from([phase_final_response()]),
        requests: Vec::new(),
        action_return_at: None,
    };
    let mut executor = ImmediateExecutor::default();
    let spec = phase_spec(&contract, &artifacts);

    let outcome =
        run_agent_with_deadline(&spec, &contract, &mut provider, &mut executor, &deadline)
            .await
            .expect("reserved final send");

    assert_eq!(
        outcome.record.terminal_status,
        nano_types::event::TerminalStatus::Success
    );
    assert_eq!(provider.requests.len(), 1);
    assert_eq!(provider.requests[0].mode, ProviderRequestMode::FinalOnly);
    assert!(!provider.requests[0].tools.is_empty());
    assert_eq!(executor.executions, 0);
}

#[tokio::test]
async fn shell_success_nonzero_and_utf8_safe_truncation() {
    let workspace = tempfile::tempdir().expect("workspace");
    let success = execute(
        workspace.path(),
        json!({"command":"printf hello","description":"test success"}),
    )
    .await;
    assert_eq!(success.outcome, ToolOutcome::Succeeded);
    assert_eq!(success.output, "exit: 0\nhello");

    let nonzero = execute(
        workspace.path(),
        json!({"command":"printf failure >&2; exit 7","description":"test failure"}),
    )
    .await;
    assert_eq!(nonzero.outcome, ToolOutcome::Succeeded);
    assert!(nonzero.output.starts_with("exit: 7\n"));
    assert!(nonzero.output.contains("failure"));

    let truncated = execute(
        workspace.path(),
        json!({
            "command":"python3 - <<'PY'\nprint('🙂' * 100)\nPY",
            "description":"test truncation"
        }),
    )
    .await;
    assert!(truncated.output.len() <= 128);
    assert!(truncated.output.starts_with("exit: 0\n"));
    assert!(truncated.output.contains("output truncated"));
    assert!(std::str::from_utf8(truncated.output.as_bytes()).is_ok());
}

#[tokio::test]
async fn timeout_kills_owned_process_group_without_survivor() {
    let workspace = tempfile::tempdir().expect("workspace");
    let result = execute(
        workspace.path(),
        json!({
            "command":"sleep 30 & child=$!; printf \"$child\" > child.pid; wait",
            "description":"test timeout cleanup",
            "timeout":100
        }),
    )
    .await;
    assert_eq!(result.outcome, ToolOutcome::TimedOut);
    assert!(result.output.starts_with("exit: killed (timeout)\n"));
    let child_pid = fs::read_to_string(workspace.path().join("child.pid"))
        .expect("child pid")
        .parse::<u32>()
        .expect("numeric pid");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let alive = std::process::Command::new("/bin/kill")
        .args(["-0", &child_pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("probe child")
        .success();
    assert!(!alive, "background child survived timeout");
}

#[tokio::test]
async fn foreground_completion_cleans_accidentally_backgrounded_group_member() {
    let workspace = tempfile::tempdir().expect("workspace");
    let result = execute(
        workspace.path(),
        json!({
            "command":"sleep 30 >/dev/null 2>&1 & printf \"$!\" > escaped.pid",
            "description":"verify foreground ownership cleanup"
        }),
    )
    .await;
    assert_eq!(result.outcome, ToolOutcome::Succeeded);
    let child_pid = fs::read_to_string(workspace.path().join("escaped.pid"))
        .expect("escaped pid")
        .parse::<u32>()
        .expect("numeric pid");
    let alive = std::process::Command::new("/bin/kill")
        .args(["-0", &child_pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("probe escaped child")
        .success();
    assert!(!alive, "foreground call left a process-group member alive");
}

#[test]
fn rejects_background_and_invalid_but_ignores_unknown_schema_fields() {
    let mut profile = terminal_profile();
    profile.tools.terminal_max_timeout_ms = 600_000;
    let executor = TerminalExecutor::from_profile(&profile);
    let background = call(json!({
        "command":"sleep 1",
        "description":"background",
        "background":true
    }));
    assert_eq!(
        executor
            .validate(&background)
            .expect_err("background rejected")
            .output,
        "background_unsupported_in_foreground_six"
    );
    let other = FunctionCall {
        call_id: "call-other".to_owned(),
        name: "read_file".to_owned(),
        arguments_json: "{}".to_owned(),
    };
    assert_eq!(
        executor
            .validate(&other)
            .expect_err("other rejected")
            .output,
        "unsupported_in_alpha"
    );
    let invalid = call(json!({"command":"pwd","description":"x","unknown":true}));
    executor
        .validate(&invalid)
        .expect("frozen schema permits unknown fields");
    let missing = call(json!({"command":"pwd"}));
    assert_eq!(
        executor
            .validate(&missing)
            .expect_err("missing required field rejected")
            .output,
        "invalid_arguments"
    );
    let over_profile_max = call(json!({
        "command":"pwd",
        "description":"too long",
        "timeout":600001
    }));
    assert_eq!(
        executor
            .validate(&over_profile_max)
            .expect_err("profile 600000ms maximum")
            .output,
        "invalid_arguments"
    );
}

#[tokio::test]
async fn mocked_xai_completed_response_dispatches_foreground_shell_once() {
    let root = tempfile::tempdir().expect("test root");
    let contract = write_contract(root.path());
    let workspace = root.path().join("workspace");
    let artifacts = root.path().join("artifacts");
    fs::create_dir(&workspace).expect("workspace");
    let marker = workspace.join("roundtrip.txt");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider");
    let endpoint = format!(
        "http://{}/v1/responses",
        listener.local_addr().expect("provider address")
    );
    let server_marker = marker.clone();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first request");
        let first_body = read_request(&mut first).await;
        start_response(&mut first).await;
        let arguments = serde_json::to_string(&json!({
            "command":"printf roundtrip > roundtrip.txt; cat roundtrip.txt",
            "description":"prove foreground dispatch",
            "timeout":1000
        }))
        .expect("arguments");
        write_sse(
            &mut first,
            &json!({
                "type":"response.output_item.added",
                "sequence_number":0,
                "output_index":1,
                "item":{
                    "type":"function_call",
                    "id":"fc-1",
                    "call_id":"call-terminal-1",
                    "name":"run_terminal_command",
                    "arguments":""
                }
            }),
        )
        .await;
        write_sse(
            &mut first,
            &json!({
                "type":"response.function_call_arguments.delta",
                "sequence_number":1,
                "item_id":"fc-1",
                "output_index":1,
                "delta":arguments
            }),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !server_marker.exists(),
            "terminal dispatched before response.completed"
        );
        write_sse(
            &mut first,
            &json!({
                "type":"response.completed",
                "sequence_number":2,
                "response":{
                    "id":"resp-tool",
                    "object":"response",
                    "model":"grok-4.5",
                    "status":"completed",
                    "output":[
                        {
                            "type":"reasoning",
                            "id":"reason-1",
                            "summary":[],
                            "encrypted_content":"opaque-reasoning"
                        },
                        {
                            "type":"function_call",
                            "call_id":"call-terminal-1",
                            "name":"run_terminal_command",
                            "arguments":arguments
                        }
                    ],
                    "service_tier":"default",
                    "usage":{
                        "input_tokens":10,
                        "output_tokens":3,
                        "cost_in_usd_ticks":123_000_000
                    }
                }
            }),
        )
        .await;
        first
            .write_all(b"data: [DONE]\r\n\r\n")
            .await
            .expect("first DONE");
        first.shutdown().await.expect("close first");

        let (mut second, _) = listener.accept().await.expect("second request");
        let second_body = read_request(&mut second).await;
        start_response(&mut second).await;
        write_sse(
            &mut second,
            &json!({
                "type":"response.completed",
                "sequence_number":0,
                "response":{
                    "id":"resp-final",
                    "object":"response",
                    "model":"grok-4.5",
                    "status":"completed",
                    "output":[{
                        "type":"message",
                        "role":"assistant",
                        "content":[{"type":"output_text","text":"finished"}]
                    }],
                    "usage":null
                }
            }),
        )
        .await;
        second
            .write_all(b"data: [DONE]\r\n\r\n")
            .await
            .expect("second DONE");
        second.shutdown().await.expect("close second");
        [first_body, second_body]
    });

    let settings =
        XaiProviderSettings::from_profile(contract.profile()).expect("provider settings");
    let mut provider =
        XaiProvider::for_loopback_test(&endpoint, "test-only-key".to_owned(), settings)
            .expect("loopback provider");
    let mut executor = TerminalExecutor::from_profile(contract.profile());
    let spec = RunSpec {
        schema_version: RUN_SPEC_SCHEMA.to_owned(),
        run_id: "run-xai-terminal".to_owned(),
        trial_id: "trial-xai-terminal".to_owned(),
        attempt_id: "attempt-0".to_owned(),
        task: TaskSpec {
            id: "mocked-xai-terminal".to_owned(),
            digest: "e".repeat(64),
            instruction: "Create the requested marker.".to_owned(),
            git_history_capability: GitHistoryCapability {
                schema_version: GIT_HISTORY_CAPABILITY_SCHEMA.to_owned(),
                policy_version: GIT_HISTORY_CAPABILITY_POLICY.to_owned(),
                git_history_access: GitHistoryAccess::NotRequired,
                canonical_instruction_sha256:
                    "8367829a1e42d91321c384ba7b8f3c7532c87d94e0b1c6d83d28deb4082827e4".to_owned(),
                trusted_manifest_sha256: "e".repeat(64),
                supporting_span_sha256: None,
            },
        },
        contract: ContractSpec {
            id: contract.effective().contract_id.clone(),
            contract_set_sha256: contract.contract_set_sha256().to_owned(),
            profile_id: contract.profile().profile_id.clone(),
        },
        provider: ProviderSpec {
            kind: ProviderKind::Xai,
            model: "grok-4.5".to_owned(),
            max_turns: 4,
            retry_max: 0,
        },
        workspace_dir: workspace,
        artifact_dir: artifacts.clone(),
        agent_timeout_sec: 60,
        active_tools: None,
    };
    let outcome = run_agent(&spec, &contract, &mut provider, &mut executor)
        .await
        .expect("mocked round trip");
    assert_eq!(outcome.record.provider_turn_count, 2);
    assert_eq!(outcome.record.tool_call_count, 1);
    assert_eq!(fs::read_to_string(&marker).expect("marker"), "roundtrip");
    let events = fs::read_to_string(artifacts.join("events.jsonl")).expect("events");
    assert_eq!(events.matches("\"type\":\"tool.dispatched\"").count(), 1);
    let observed_usage = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .find_map(|event| {
            (event["type"] == "provider.completed" && event["data"]["usage"].is_object())
                .then(|| event["data"]["usage"].clone())
        })
        .expect("observed provider usage");
    assert_eq!(observed_usage["cost_in_usd_ticks"], 123_000_000);
    assert_eq!(observed_usage["provider_cost_ticks"], 123_000_000);

    let requests = server.await.expect("provider server");
    let first: Value = serde_json::from_slice(&requests[0]).expect("first request JSON");
    let second: Value = serde_json::from_slice(&requests[1]).expect("second request JSON");
    let tool_names = first["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(tool_names, TOOL_ORDER);
    assert_eq!(first["store"], false);
    assert_eq!(first["truncation"], "disabled");
    assert_eq!(outcome.record.usage_totals.input_tokens, Some(10));
    assert_eq!(outcome.record.usage_totals.output_tokens, Some(3));
    assert_eq!(outcome.record.provider_call_coverage.requested, 2);
    assert_eq!(outcome.record.provider_call_coverage.completed, 2);
    assert_eq!(outcome.record.provider_call_coverage.usage_present, 1);
    assert_eq!(outcome.record.provider_call_coverage.usage_absent, 1);
    assert_eq!(outcome.record.provider_call_coverage.cost_present, 1);
    assert_eq!(outcome.record.provider_call_coverage.cost_absent, 1);
    assert_eq!(
        outcome.record.usage_totals.provider_cost_ticks,
        Some(123_000_000)
    );
    let history = second["input"].as_array().expect("second history");
    assert!(history.iter().any(|item| {
        item["type"] == "reasoning"
            && item["id"] == "reason-1"
            && item["encrypted_content"] == "opaque-reasoning"
    }));
    assert!(history.iter().any(|item| {
        item["type"] == "function_call_output"
            && item["call_id"] == "call-terminal-1"
            && item["output"] == "exit: 0\nroundtrip"
    }));
}
