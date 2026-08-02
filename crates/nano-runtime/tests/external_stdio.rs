use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nano_provider_xai::FunctionCall;
use nano_runtime::{
    ExternalStdioDeadlineEnvelope, ExternalStdioExecutor, SettlementStageCutoffsV1,
    ToolExecutionError, ToolExecutionFailureClass, ToolExecutor, ToolResult, ToolWaitReason,
    WorkspaceMode,
};
use nano_types::contract::{AgentProfile, TOOL_ORDER};
use nano_types::event::ToolOutcome;
use nano_types::external_tool::{
    EXTERNAL_BACKGROUND_START_PROOF_VERSION, EXTERNAL_TOOL_STDIO_SCHEMA,
    EXTERNAL_TOOL_STDIO_V3_SCHEMA, ExternalBackgroundStartKind, ExternalBackgroundStartObservation,
    ExternalCleanupEvidence, ExternalEnvironmentPolicy, ExternalMediaPayload, ExternalMediaType,
    ExternalProcessCensus, ExternalProcessDisposition, ExternalTerminalActorOriginV1,
    ExternalTerminalActorPhaseV1, ExternalTerminalActorSubtypeV1, ExternalToolCompletedResult,
    ExternalToolCompletedResultV3, ExternalToolDeadlineFields, ExternalToolFailure,
    ExternalToolFailureV3, ExternalToolMessageType, ExternalToolRecoverability,
    ExternalToolRequest, ExternalToolRequestV3, ExternalToolResponse, ExternalToolSettlement,
    ExternalToolSettlementV3, ExternalToolWaitReason,
};
use nano_types::run_spec::{
    ContractSpec, ProviderKind, ProviderSpec, RUN_SPEC_SCHEMA, RunSpec, TaskSpec,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

fn profile() -> AgentProfile {
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
            "max_provider_turns": 8,
            "max_input_tokens_per_run": 450000,
            "max_output_tokens_per_run": 2048,
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
            "max_function_calls_per_run": 16,
            "mutation_batches_serialized": true
        },
        "deadlines": {
            "source": "run_spec_task_native",
            "absolute_run_wall_cap_sec": 120,
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
            "model_tool_output_bytes_per_call": 512,
            "model_tool_output_bytes_per_run": 4096
        },
        "process": {
            "max_background_processes": 8,
            "term_grace_ms": 100,
            "kill_confirmation_timeout_ms": 1000,
            "process_spool_bytes_per_process": 4096,
            "process_spool_bytes_per_run": 8192
        },
        "artifacts": {
            "max_events_per_run": 128,
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

fn spec(workspace: impl Into<PathBuf>) -> RunSpec {
    RunSpec {
        schema_version: RUN_SPEC_SCHEMA.to_owned(),
        run_id: "run-external-1".to_owned(),
        trial_id: "trial-external-1".to_owned(),
        attempt_id: "attempt-0".to_owned(),
        task: TaskSpec {
            id: "task-external".to_owned(),
            digest: "a".repeat(64),
            instruction: "Use the terminal once.".to_owned(),
        },
        contract: ContractSpec {
            id: "synthetic-v1".to_owned(),
            contract_set_sha256: "b".repeat(64),
            profile_id: "synthetic-profile-v1".to_owned(),
        },
        provider: ProviderSpec {
            kind: ProviderKind::Scripted,
            model: "grok-4.5".to_owned(),
            max_turns: 4,
            retry_max: 0,
        },
        workspace_dir: workspace.into(),
        artifact_dir: PathBuf::from("/logs/agent"),
        agent_timeout_sec: 60,
        active_tools: None,
    }
}

fn call(call_id: &str, command: &str) -> FunctionCall {
    FunctionCall {
        call_id: call_id.to_owned(),
        name: "run_terminal_command".to_owned(),
        arguments_json: serde_json::to_string(&json!({
            "command": command,
            "description": "external bridge test",
            "timeout": 1000,
            "background": false
        }))
        .expect("arguments"),
    }
}

fn response(request: &ExternalToolRequest, stdout: &[u8]) -> ExternalToolResponse {
    let process_disposition = if request.tool_name == "run_terminal_command" {
        ExternalProcessDisposition::ForegroundCleaned
    } else {
        ExternalProcessDisposition::NoProcess
    };
    ExternalToolResponse {
        schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
        message_type: ExternalToolMessageType::Response,
        seq: request.seq,
        run_id: request.run_id.clone(),
        trial_id: request.trial_id.clone(),
        attempt_id: request.attempt_id.clone(),
        call_id: request.call_id.clone(),
        tool_name: request.tool_name.clone(),
        request_sha256: request.sha256().expect("request hash"),
        return_code: 0,
        timed_out: false,
        stdout_base64: BASE64.encode(stdout),
        stderr_base64: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        process_disposition,
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
    }
}

fn response_v3(
    request: &ExternalToolRequestV3,
    stdout: &[u8],
    wait_clamped: bool,
) -> ExternalToolSettlementV3 {
    ExternalToolSettlementV3::Completed {
        schema_version: EXTERNAL_TOOL_STDIO_V3_SCHEMA.to_owned(),
        message_type: ExternalToolMessageType::Response,
        seq: request.seq,
        run_id: request.run_id.clone(),
        trial_id: request.trial_id.clone(),
        attempt_id: request.attempt_id.clone(),
        call_id: request.call_id.clone(),
        tool_name: request.tool_name.clone(),
        request_sha256: request.sha256().expect("v3 request hash"),
        result: ExternalToolCompletedResultV3 {
            return_code: 0,
            timed_out: false,
            stdout_base64: BASE64.encode(stdout),
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
            media: None,
            wait_clamped,
            wait_reason: if wait_clamped {
                ExternalToolWaitReason::runtime_budget()
            } else {
                ExternalToolWaitReason::None(())
            },
            background_start_observation: None,
            actor_receipt: None,
        },
    }
}

async fn read_request(reader: &mut BufReader<tokio::io::DuplexStream>) -> ExternalToolRequest {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read request");
    assert!(line.ends_with('\n'));
    serde_json::from_str(&line).expect("request JSON")
}

async fn read_request_v3(reader: &mut BufReader<tokio::io::DuplexStream>) -> ExternalToolRequestV3 {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read v3 request");
    assert!(line.ends_with('\n'));
    serde_json::from_str(&line).expect("v3 request JSON")
}

fn v3_deadline(actor_done: Instant, tool_settled: Instant) -> ExternalStdioDeadlineEnvelope {
    let actor_done_monotonic_ns = 1_000_000_000_000;
    let process_settlement_reserve_ms =
        u64::try_from(tool_settled.duration_since(actor_done).as_millis())
            .expect("settlement milliseconds");
    let tool_settled_monotonic_ns =
        actor_done_monotonic_ns + process_settlement_reserve_ms * 1_000_000;
    let last_send_monotonic_ns = tool_settled_monotonic_ns + 30_000_000_000;
    let cleanup_start_monotonic_ns = last_send_monotonic_ns + 15_000_000_000;
    let hard_deadline_monotonic_ns = cleanup_start_monotonic_ns + 20_000_000_000;
    ExternalStdioDeadlineEnvelope::new(
        ExternalToolDeadlineFields {
            actor_done_monotonic_ns,
            tool_settled_monotonic_ns,
            last_send_monotonic_ns,
            runtime_final_monotonic_ns: last_send_monotonic_ns,
            cleanup_start_monotonic_ns,
            hard_deadline_monotonic_ns,
            cleanup_reserve_ms: 20_000,
            terminalization_reserve_ms: 15_000,
            provider_send_reserve_ms: 30_000,
            process_settlement_reserve_ms,
            deadline_receipt_sha256: "d".repeat(64),
        },
        actor_done,
        tool_settled,
    )
    .expect("v3 deadline")
}

struct ActorReceiptFixture<'a> {
    phase: &'a str,
    origin: &'a str,
    primary_subtype: &'a str,
    recovery_subtype: Option<&'a str>,
    execution_may_have_started: bool,
    effective_cutoff_monotonic_ns: u64,
    cleanup_verified: Option<bool>,
    census_verified: Option<bool>,
}

fn actor_receipt_value(fixture: ActorReceiptFixture<'_>) -> Value {
    let mut value = json!({
        "schema_version": "terminal-actor-receipt-v1",
        "phase": fixture.phase,
        "origin": fixture.origin,
        "primary_subtype": fixture.primary_subtype,
        "recovery_subtype": fixture.recovery_subtype,
        "execution_may_have_started": fixture.execution_may_have_started,
        "effective_cutoff_monotonic_ns": fixture.effective_cutoff_monotonic_ns,
        "cleanup_verified": fixture.cleanup_verified,
        "census_verified": fixture.census_verified
    });
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&value).expect("receipt digest input"))
    );
    value["diagnostic_digest_sha256"] = Value::String(digest);
    value
}

fn foreground_v3_completed_value(actor_done_monotonic_ns: u64) -> Value {
    json!({
        "schema_version": EXTERNAL_TOOL_STDIO_V3_SCHEMA,
        "message_type": "tool.response",
        "seq": 0,
        "run_id": "run-external-1",
        "trial_id": "trial-external-1",
        "attempt_id": "attempt-0",
        "call_id": "call-receipt",
        "tool_name": "run_terminal_command",
        "request_sha256": "a".repeat(64),
        "settlement": "completed",
        "result": {
            "return_code": 0,
            "timed_out": false,
            "stdout_base64": "",
            "stderr_base64": "",
            "stdout_truncated": false,
            "stderr_truncated": false,
            "process_disposition": "foreground_cleaned",
            "target_task_id": null,
            "cleanup": {
                "attempted": true,
                "term_sent": false,
                "kill_sent": false,
                "verified": true
            },
            "census": {
                "verified": true,
                "owned_processes_alive": 0
            },
            "media": null,
            "wait_clamped": false,
            "wait_reason": null,
            "background_start_observation": null,
            "actor_receipt": actor_receipt_value(ActorReceiptFixture {
                phase: "meta_validate",
                origin: "actor",
                primary_subtype: "completed",
                recovery_subtype: None,
                execution_may_have_started: true,
                effective_cutoff_monotonic_ns: actor_done_monotonic_ns,
                cleanup_verified: Some(true),
                census_verified: Some(true),
            })
        }
    })
}

fn foreground_v3_fatal_value(actor_done_monotonic_ns: u64) -> Value {
    json!({
        "schema_version": EXTERNAL_TOOL_STDIO_V3_SCHEMA,
        "message_type": "tool.response",
        "seq": 0,
        "run_id": "run-external-1",
        "trial_id": "trial-external-1",
        "attempt_id": "attempt-0",
        "call_id": "call-receipt",
        "tool_name": "run_terminal_command",
        "request_sha256": "a".repeat(64),
        "settlement": "fatal",
        "failure": {
            "code": "terminal_actor_cleanup_unverified",
            "execution_may_have_started": true,
            "cleanup_verified": false,
            "census_verified": false,
            "recoverability": "fatal",
            "actor_receipt": actor_receipt_value(ActorReceiptFixture {
                phase: "cleanup",
                origin: "transport",
                primary_subtype: "run_transport_timeout",
                recovery_subtype: Some("meta_invalid"),
                execution_may_have_started: true,
                effective_cutoff_monotonic_ns: actor_done_monotonic_ns,
                cleanup_verified: Some(false),
                census_verified: Some(false),
            })
        }
    })
}

fn bind_v3_response_identity(value: &mut Value, request: &ExternalToolRequestV3) {
    value["seq"] = json!(request.seq);
    value["run_id"] = json!(request.run_id);
    value["trial_id"] = json!(request.trial_id);
    value["attempt_id"] = json!(request.attempt_id);
    value["call_id"] = json!(request.call_id);
    value["tool_name"] = json!(request.tool_name);
    value["request_sha256"] = json!(request.sha256().expect("request hash"));
}

#[test]
fn v3_foreground_completed_and_fatal_receipts_round_trip() {
    let completed = foreground_v3_completed_value(1_000_000_000_000);
    assert_eq!(
        completed["result"]["actor_receipt"]["diagnostic_digest_sha256"],
        "c3ca3fed777ea18771ab3e92ab1df052ebd3bec7ee3e314e4d4d7a00fdea89ff"
    );
    for value in [completed, foreground_v3_fatal_value(1_000_000_000_000)] {
        let settlement = serde_json::from_value::<ExternalToolSettlementV3>(value.clone())
            .expect("typed foreground actor receipt");
        settlement.validate().expect("valid typed receipt");
        assert_eq!(
            serde_json::to_value(settlement).expect("settlement value"),
            value
        );
    }
}

#[tokio::test]
async fn v3_foreground_completed_receipt_survives_to_tool_result() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile(),
        v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request_v3(&mut reader).await;
        let mut value = foreground_v3_completed_value(request.actor_done_monotonic_ns);
        bind_v3_response_identity(&mut value, &request);
        let mut bytes = serde_json::to_vec(&value).expect("completed response");
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write completed response");
    });

    let result = executor
        .execute(
            &call("call-receipt", "true"),
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await
        .expect("completed foreground result");
    let receipt = result.actor_receipt().expect("validated receipt transport");
    assert_eq!(receipt.phase, ExternalTerminalActorPhaseV1::MetaValidate);
    assert_eq!(receipt.origin, ExternalTerminalActorOriginV1::Actor);
    assert_eq!(
        receipt.primary_subtype,
        ExternalTerminalActorSubtypeV1::Completed
    );
    bridge.await.expect("completed bridge");
}

#[tokio::test]
async fn v3_large_response_round_trips_through_reader_with_truncation_metadata() {
    const RAW_STDOUT_BYTES: usize = 6_500_000;
    const PROCESS_SPOOL_BYTES: u64 = 16 * 1024 * 1024;

    let mut large_response_profile = profile();
    large_response_profile
        .process
        .process_spool_bytes_per_process = PROCESS_SPOOL_BYTES;
    large_response_profile.process.process_spool_bytes_per_run = PROCESS_SPOOL_BYTES;

    let (request_stream, bridge_request_stream) = tokio::io::duplex(64 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(64 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &large_response_profile,
        v3_deadline(now + Duration::from_secs(10), now + Duration::from_secs(30)),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request_v3(&mut reader).await;
        let mut value = foreground_v3_completed_value(request.actor_done_monotonic_ns);
        bind_v3_response_identity(&mut value, &request);
        value["result"]["stdout_base64"] = json!(BASE64.encode(vec![b'x'; RAW_STDOUT_BYTES]));
        value["result"]["stdout_truncated"] = json!(true);
        let mut bytes = serde_json::to_vec(&value).expect("large completed response");
        assert!(
            bytes.len() > 8 * 1024 * 1024,
            "the response line must exceed the historical 8 MiB request limit"
        );
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write large completed response");
    });

    let result = executor
        .execute(
            &call("call-large-response", "true"),
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await
        .expect("large bounded response must pass the Rust reader");
    bridge.await.expect("large response bridge");

    assert!(result.execution_attempted);
    assert_eq!(result.outcome, ToolOutcome::Succeeded);
    assert!(result.output.contains("[stream_capture_truncated]"));
    assert!(result.output.contains("output truncated"));
    assert!(
        u64::try_from(result.output.len()).expect("model output length fits u64")
            <= large_response_profile
                .tools
                .model_tool_output_bytes_per_call
    );
}

#[tokio::test]
async fn v3_foreground_timeout_is_clamped_before_actor_admission() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile(),
        v3_deadline(now + Duration::from_secs(2), now + Duration::from_secs(3)),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request_v3(&mut reader).await;
        assert!(request.operation_timeout_ms > 1_800);
        assert!(request.operation_timeout_ms < 2_000);
        let mut value = foreground_v3_completed_value(request.actor_done_monotonic_ns);
        bind_v3_response_identity(&mut value, &request);
        let mut bytes = serde_json::to_vec(&value).expect("completed response");
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write completed response");
    });
    let late_call = FunctionCall {
        arguments_json: serde_json::to_string(&json!({
            "command": "true",
            "description": "clamped external bridge test",
            "timeout": 3000,
            "background": false
        }))
        .expect("arguments"),
        ..call("call-clamped", "true")
    };

    executor
        .execute(
            &late_call,
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await
        .expect("clamped foreground result");
    bridge.await.expect("completed bridge");
}

#[tokio::test]
async fn v3_root_deadline_fatal_frame_stays_primary_over_eof() {
    let error = execute_foreground_v3_case(call("call-deadline", "sleep 60"), |value| {
        let actor_done = value["result"]["actor_receipt"]["effective_cutoff_monotonic_ns"]
            .as_u64()
            .expect("actor cutoff");
        *value = foreground_v3_fatal_value(actor_done);
        value["failure"]["code"] = json!("tool_settlement_deadline_exceeded");
        value["failure"]["cleanup_verified"] = Value::Null;
        value["failure"]["census_verified"] = Value::Null;
        value["failure"]["actor_receipt"] = actor_receipt_value(ActorReceiptFixture {
            phase: "actor_done",
            origin: "actor",
            primary_subtype: "actor_deadline_exceeded",
            recovery_subtype: None,
            execution_may_have_started: true,
            effective_cutoff_monotonic_ns: actor_done,
            cleanup_verified: None,
            census_verified: None,
        });
    })
    .await
    .expect_err("root deadline frame must be fatal");

    assert_code(error.clone(), "tool_settlement_deadline_exceeded");
    assert_eq!(error.class(), ToolExecutionFailureClass::Deadline);
    let receipt = error.actor_receipt().expect("deadline receipt");
    assert_eq!(
        receipt.primary_subtype,
        ExternalTerminalActorSubtypeV1::ActorDeadlineExceeded
    );
}

#[tokio::test]
async fn v3_actor_admission_backstop_remains_a_typed_deadline() {
    let error = execute_foreground_v3_case(call("call-admission", "true"), |value| {
        let actor_done = value["result"]["actor_receipt"]["effective_cutoff_monotonic_ns"]
            .as_u64()
            .expect("actor cutoff");
        *value = foreground_v3_fatal_value(actor_done);
        value["failure"]["code"] = json!("terminal_actor_action_admission_rejected");
        value["failure"]["execution_may_have_started"] = json!(false);
        value["failure"]["cleanup_verified"] = Value::Null;
        value["failure"]["census_verified"] = Value::Null;
        value["failure"]["actor_receipt"] = actor_receipt_value(ActorReceiptFixture {
            phase: "remote_setup",
            origin: "actor",
            primary_subtype: "actor_deadline_exceeded",
            recovery_subtype: None,
            execution_may_have_started: false,
            effective_cutoff_monotonic_ns: actor_done,
            cleanup_verified: None,
            census_verified: None,
        });
    })
    .await
    .expect_err("actor admission backstop must remain typed");

    assert_code(error.clone(), "terminal_actor_action_admission_rejected");
    assert_eq!(error.class(), ToolExecutionFailureClass::Deadline);
}

async fn execute_foreground_v3_case(
    call: FunctionCall,
    mutate: impl FnOnce(&mut Value) + Send + 'static,
) -> Result<ToolResult, ToolExecutionError> {
    execute_foreground_v3_case_with_profile(call, profile(), mutate).await
}

async fn execute_foreground_v3_case_with_profile(
    call: FunctionCall,
    profile: AgentProfile,
    mutate: impl FnOnce(&mut Value) + Send + 'static,
) -> Result<ToolResult, ToolExecutionError> {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile,
        v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request_v3(&mut reader).await;
        let mut value = foreground_v3_completed_value(request.actor_done_monotonic_ns);
        mutate(&mut value);
        bind_v3_response_identity(&mut value, &request);
        let mut bytes = serde_json::to_vec(&value).expect("completed response");
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write completed response");
    });
    let result = executor
        .execute(
            &call,
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await;
    bridge.await.expect("completed bridge");
    result
}

const FOREGROUND_RESIDUAL_SENTINEL: &str = "FG_CHILDREN_KILLED;START_INTENDED_BG;VERIFY_HANDLE";
const FOREGROUND_OWNED_PROCESSES_TERMINATED_PREFIX: &str = concat!(
    "FG_CHILDREN_KILLED;START_INTENDED_BG;VERIFY_HANDLE\n",
    "<observation>foreground_owned_processes_terminated</observation>\n",
    "<status>execution_attempted=true outcome=rejected cleanup_verified=true ",
    "census_verified=true survivors=0</status>\n",
    "<next-step>If a long-lived process was intended, start only that process in a fresh managed ",
    "background call and verify the returned handle. Otherwise continue.</next-step>\n",
);

#[tokio::test]
async fn foreground_owned_processes_terminated_projects_term_and_kill_evidence() {
    for (call_id, kill_sent, return_code) in [
        ("call-residual-term", false, 7),
        ("call-residual-kill", true, 0),
    ] {
        let result = execute_foreground_v3_case(call(call_id, "printf residual"), move |value| {
            value["result"]["return_code"] = json!(return_code);
            value["result"]["stdout_base64"] = json!(BASE64.encode(b"leader-out"));
            value["result"]["stderr_base64"] = json!(BASE64.encode(b"leader-err"));
            value["result"]["cleanup"]["term_sent"] = json!(true);
            value["result"]["cleanup"]["kill_sent"] = json!(kill_sent);
            value["result"]["wait_clamped"] = json!(true);
            value["result"]["wait_reason"] = json!("runtime_budget");
        })
        .await
        .expect("verified residual cleanup is a nonfatal result");

        assert!(result.execution_attempted);
        assert_eq!(result.outcome, ToolOutcome::Rejected);
        assert!(result.media.is_none());
        assert_eq!(
            result.output,
            format!(
                "{FOREGROUND_OWNED_PROCESSES_TERMINATED_PREFIX}\
                 exit: {return_code}\nleader-out\nleader-err"
            )
        );
        for line in FOREGROUND_OWNED_PROCESSES_TERMINATED_PREFIX.lines() {
            assert_eq!(result.output.matches(line).count(), 1);
        }
        assert!(!result.output.contains("task_id"));
        assert!(!result.output.contains("<handle>"));
        let budget = result.runtime_budget.expect("runtime budget survives");
        assert!(budget.wait_clamped);
        assert_eq!(budget.wait_reason, Some(ToolWaitReason::RuntimeBudget));
        assert!(
            result.actor_receipt().is_some(),
            "validated actor receipt survives"
        );
    }
}

#[tokio::test]
async fn foreground_owned_processes_terminated_keeps_prefix_inside_output_cap() {
    let mut tight_profile = profile();
    tight_profile.tools.model_tool_output_bytes_per_call = 128;
    let result = execute_foreground_v3_case_with_profile(
        call("call-residual-bounded", "printf bounded"),
        tight_profile,
        |value| {
            value["result"]["stdout_base64"] = json!(BASE64.encode("界".repeat(300)));
            value["result"]["stdout_truncated"] = json!(true);
            value["result"]["cleanup"]["term_sent"] = json!(true);
        },
    )
    .await
    .expect("verified residual cleanup is a nonfatal result");

    assert!(result.output.starts_with(FOREGROUND_RESIDUAL_SENTINEL));
    assert!(result.output.contains("output truncated"));
    assert!(result.output.len() <= 128);
    assert!(std::str::from_utf8(result.output.as_bytes()).is_ok());
}

#[tokio::test]
async fn foreground_owned_processes_terminated_is_live_v3_only() {
    let terminal_call = call("call-v2-residual", "printf legacy");
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("legacy executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request(&mut reader).await;
        let mut response = response(&request, b"legacy-out");
        response.return_code = 7;
        response.cleanup.term_sent = true;
        let mut bytes = serde_json::to_vec(&response).expect("legacy response");
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write legacy response");
    });
    let legacy = executor
        .execute(
            &terminal_call,
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("legacy residual evidence remains ordinary success");
    bridge.await.expect("legacy bridge");
    assert!(legacy.execution_attempted);
    assert_eq!(legacy.outcome, ToolOutcome::Succeeded);
    assert_eq!(legacy.output, "exit: 7\nlegacy-out");

    let live = execute_foreground_v3_case(call("call-v3-residual", "printf live"), |value| {
        value["result"]["return_code"] = json!(7);
        value["result"]["stdout_base64"] = json!(BASE64.encode(b"legacy-out"));
        value["result"]["cleanup"]["term_sent"] = json!(true);
    })
    .await
    .expect("live v3 residual evidence projects transition");
    assert_eq!(live.outcome, ToolOutcome::Rejected);
    assert!(live.output.starts_with(FOREGROUND_RESIDUAL_SENTINEL));
}

#[tokio::test]
async fn foreground_owned_processes_terminated_isolated_from_ordinary_and_timeout_results() {
    let ordinary = execute_foreground_v3_case(call("call-ordinary", "printf ordinary"), |value| {
        value["result"]["return_code"] = json!(9);
        value["result"]["stdout_base64"] = json!(BASE64.encode(b"ordinary"));
    })
    .await
    .expect("ordinary foreground completion");
    assert!(ordinary.execution_attempted);
    assert_eq!(ordinary.outcome, ToolOutcome::Succeeded);
    assert_eq!(ordinary.output, "exit: 9\nordinary");

    let timed_out = execute_foreground_v3_case(call("call-timeout", "sleep 60"), |value| {
        let cutoff = value["result"]["actor_receipt"]["effective_cutoff_monotonic_ns"]
            .as_u64()
            .expect("receipt cutoff");
        value["result"]["return_code"] = json!(124);
        value["result"]["timed_out"] = json!(true);
        value["result"]["cleanup"]["term_sent"] = json!(true);
        value["result"]["actor_receipt"] = actor_receipt_value(ActorReceiptFixture {
            phase: "meta_validate",
            origin: "semantic",
            primary_subtype: "semantic_execution_timed_out",
            recovery_subtype: None,
            execution_may_have_started: true,
            effective_cutoff_monotonic_ns: cutoff,
            cleanup_verified: Some(true),
            census_verified: Some(true),
        });
    })
    .await
    .expect("semantic timeout remains nonfatal");
    assert!(timed_out.execution_attempted);
    assert_eq!(timed_out.outcome, ToolOutcome::TimedOut);
    assert_eq!(timed_out.output, "exit: killed (timeout)\n");
    assert!(
        !timed_out
            .output
            .contains("foreground_owned_processes_terminated")
    );
}

#[tokio::test]
async fn foreground_owned_processes_terminated_requires_validated_containment() {
    for (case, expected, mutate) in [
        ("cleanup", "external_stdio_cleanup_unverified", 0_u8),
        ("census", "external_stdio_census_unverified", 1_u8),
        ("survivor", "external_stdio_census_unverified", 2_u8),
        ("target", "external_stdio_process_disposition_invalid", 3_u8),
    ] {
        let result = execute_foreground_v3_case(
            call(&format!("call-{case}"), "printf invalid"),
            move |value| {
                let cutoff = value["result"]["actor_receipt"]["effective_cutoff_monotonic_ns"]
                    .as_u64()
                    .expect("receipt cutoff");
                value["result"]["cleanup"]["term_sent"] = json!(true);
                match mutate {
                    0 => {
                        value["result"]["cleanup"]["verified"] = json!(false);
                        value["result"]["actor_receipt"] =
                            actor_receipt_value(ActorReceiptFixture {
                                phase: "meta_validate",
                                origin: "actor",
                                primary_subtype: "completed",
                                recovery_subtype: None,
                                execution_may_have_started: true,
                                effective_cutoff_monotonic_ns: cutoff,
                                cleanup_verified: Some(false),
                                census_verified: Some(true),
                            });
                    }
                    1 => {
                        value["result"]["census"]["verified"] = json!(false);
                        value["result"]["actor_receipt"] =
                            actor_receipt_value(ActorReceiptFixture {
                                phase: "meta_validate",
                                origin: "actor",
                                primary_subtype: "completed",
                                recovery_subtype: None,
                                execution_may_have_started: true,
                                effective_cutoff_monotonic_ns: cutoff,
                                cleanup_verified: Some(true),
                                census_verified: Some(false),
                            });
                    }
                    2 => value["result"]["census"]["owned_processes_alive"] = json!(1),
                    3 => {
                        value["result"]["target_task_id"] =
                            json!("018f22d6-9f04-7cc0-8000-000000000001");
                    }
                    _ => unreachable!("closed mutation matrix"),
                }
            },
        )
        .await
        .expect_err("uncertain containment must fail closed");
        assert_code(result, expected);
    }

    let background_call = FunctionCall {
        call_id: "call-background-cross-mode".to_owned(),
        name: "run_terminal_command".to_owned(),
        arguments_json: concat!(
            "{\"command\":\"true\",\"description\":\"cross mode\",",
            "\"timeout\":0,\"background\":true}"
        )
        .to_owned(),
    };
    let error = execute_foreground_v3_case(background_call, |value| {
        value["result"]["cleanup"]["term_sent"] = json!(true);
        value["result"]["actor_receipt"] = Value::Null;
    })
    .await
    .expect_err("foreground disposition cannot classify a background operation");
    assert_code(error, "external_stdio_process_disposition_invalid");
}

#[tokio::test]
async fn v3_foreground_fatal_receipt_survives_to_tool_error() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile(),
        v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request_v3(&mut reader).await;
        let mut value = foreground_v3_fatal_value(request.actor_done_monotonic_ns);
        bind_v3_response_identity(&mut value, &request);
        let mut bytes = serde_json::to_vec(&value).expect("fatal response");
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write fatal response");
    });

    let error = executor
        .execute(
            &call("call-receipt", "true"),
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await
        .expect_err("fatal foreground result");
    let receipt = error.actor_receipt().expect("validated receipt transport");
    assert_eq!(receipt.phase, ExternalTerminalActorPhaseV1::Cleanup);
    assert_eq!(receipt.origin, ExternalTerminalActorOriginV1::Transport);
    assert_eq!(
        receipt.recovery_subtype,
        Some(ExternalTerminalActorSubtypeV1::MetaInvalid)
    );
    bridge.await.expect("fatal bridge");
}

#[tokio::test]
async fn v3_post_validation_completed_errors_retain_actor_receipt() {
    for fault in ["process", "base64"] {
        let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
        let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
        let run_spec = spec("/remote/workspace");
        let now = Instant::now();
        let mut executor = ExternalStdioExecutor::from_io_v3(
            response_stream,
            request_stream,
            &run_spec,
            &profile(),
            v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
        )
        .expect("v3 executor");
        let bridge = tokio::spawn(async move {
            let mut reader = BufReader::new(bridge_request_stream);
            let request = read_request_v3(&mut reader).await;
            let mut value = foreground_v3_completed_value(request.actor_done_monotonic_ns);
            bind_v3_response_identity(&mut value, &request);
            if fault == "process" {
                value["result"]["process_disposition"] = json!("no_process");
            } else {
                value["result"]["stdout_base64"] = json!("***");
            }
            let mut bytes = serde_json::to_vec(&value).expect("completed response");
            bytes.push(b'\n');
            bridge_response_stream
                .write_all(&bytes)
                .await
                .expect("write completed response");
        });
        let error = executor
            .execute(
                &call("call-receipt", "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(600),
            )
            .await
            .expect_err("post-validation failure");
        let receipt = error
            .actor_receipt()
            .expect("validated receipt survives downstream error");
        assert_eq!(receipt.phase, ExternalTerminalActorPhaseV1::MetaValidate);
        bridge.await.expect("completed bridge");
    }
}

#[test]
fn v3_foreground_receipt_rejects_missing_unknown_or_contradictory_fields() {
    let valid = foreground_v3_completed_value(1_000_000_000_000);
    let mut missing = valid.clone();
    missing["result"]
        .as_object_mut()
        .expect("completed result")
        .remove("actor_receipt");
    let mut unknown = valid.clone();
    unknown["result"]["actor_receipt"]["unknown"] = Value::Bool(true);
    let mut contradictory = valid;
    contradictory["result"]["actor_receipt"]["execution_may_have_started"] = Value::Bool(false);
    let mut missing_nullable = foreground_v3_completed_value(1_000_000_000_000);
    missing_nullable["result"]["actor_receipt"]
        .as_object_mut()
        .expect("actor receipt")
        .remove("cleanup_verified");
    let mut invalid_digest = foreground_v3_completed_value(1_000_000_000_000);
    invalid_digest["result"]["actor_receipt"]["diagnostic_digest_sha256"] =
        Value::String("0".repeat(64));
    let mut wrong_origin = foreground_v3_completed_value(1_000_000_000_000);
    wrong_origin["result"]["actor_receipt"] = actor_receipt_value(ActorReceiptFixture {
        phase: "meta_validate",
        origin: "actor",
        primary_subtype: "run_transport_timeout",
        recovery_subtype: Some("recovered_settled"),
        execution_may_have_started: true,
        effective_cutoff_monotonic_ns: 1_000_000_000_000,
        cleanup_verified: Some(true),
        census_verified: Some(true),
    });
    let mut wrong_phase = foreground_v3_completed_value(1_000_000_000_000);
    wrong_phase["result"]["actor_receipt"] = actor_receipt_value(ActorReceiptFixture {
        phase: "remote_exec",
        origin: "transport",
        primary_subtype: "run_transport_timeout",
        recovery_subtype: Some("recovered_settled"),
        execution_may_have_started: true,
        effective_cutoff_monotonic_ns: 1_000_000_000_000,
        cleanup_verified: Some(true),
        census_verified: Some(true),
    });
    let mut fatal_recovered = foreground_v3_fatal_value(1_000_000_000_000);
    fatal_recovered["failure"]["actor_receipt"] = actor_receipt_value(ActorReceiptFixture {
        phase: "cleanup",
        origin: "transport",
        primary_subtype: "run_transport_timeout",
        recovery_subtype: Some("recovered_settled"),
        execution_may_have_started: true,
        effective_cutoff_monotonic_ns: 1_000_000_000_000,
        cleanup_verified: Some(false),
        census_verified: Some(false),
    });

    for value in [
        missing,
        unknown,
        contradictory,
        missing_nullable,
        invalid_digest,
        wrong_origin,
        wrong_phase,
        fatal_recovered,
    ] {
        let rejected = serde_json::from_value::<ExternalToolSettlementV3>(value)
            .map(|settlement| settlement.validate().is_err())
            .unwrap_or(true);
        assert!(rejected, "invalid actor receipt was accepted");
    }
}

#[tokio::test]
async fn v3_foreground_receipt_rejects_cutoff_after_actor_done() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile(),
        v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request_v3(&mut reader).await;
        let mut value =
            serde_json::to_value(response_v3(&request, b"ok", false)).expect("response");
        value["result"]["process_disposition"] = Value::String("foreground_cleaned".to_owned());
        value["result"]["cleanup"]["attempted"] = Value::Bool(true);
        value["result"]["actor_receipt"] = actor_receipt_value(ActorReceiptFixture {
            phase: "meta_validate",
            origin: "actor",
            primary_subtype: "completed",
            recovery_subtype: None,
            execution_may_have_started: true,
            effective_cutoff_monotonic_ns: request.actor_done_monotonic_ns + 1,
            cleanup_verified: Some(true),
            census_verified: Some(true),
        });
        let mut bytes = serde_json::to_vec(&value).expect("response bytes");
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write response");
        bridge_response_stream
            .flush()
            .await
            .expect("flush response");
    });

    let error = executor
        .execute(
            &call("call-cutoff-after-actor-done", "true"),
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await
        .expect_err("cutoff after actor_done must fail closed");
    assert!(error.actor_receipt().is_none());
    assert_code(error, "external_stdio_actor_receipt_invalid");
    bridge.await.expect("bridge");
}

fn assert_code(error: ToolExecutionError, expected: &'static str) {
    assert_eq!(error.code(), expected);
}

#[test]
fn settlement_v1_stage_vector_is_ordered_bound_and_uses_strict_boundaries() {
    for settlement_ms in [6_u64, 7, 10_000, 10_003] {
        let actor_done_ns = 11_000_000_000;
        let tool_settled_ns = actor_done_ns + settlement_ms * 1_000_000;
        let stages =
            SettlementStageCutoffsV1::derive_raw(actor_done_ns, tool_settled_ns, settlement_ms)
                .expect("valid settlement allocation");
        assert_eq!(
            stages.raw_cutoffs(),
            std::array::from_fn(|index| {
                actor_done_ns
                    + (tool_settled_ns - actor_done_ns)
                        * u64::try_from(index + 1).expect("stage index")
                        / 6
            })
        );
        assert_eq!(stages.raw_cutoffs()[5], tool_settled_ns);
        assert!(
            stages
                .raw_cutoffs()
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }
    assert!(SettlementStageCutoffsV1::derive_raw(1_000_000_000, 1_005_000_000, 5).is_err());
    assert!(SettlementStageCutoffsV1::derive_raw(1_000_000_000, 1_007_000_001, 7).is_err());
}

#[test]
fn settlement_v1_minus_zero_plus_one_ms_is_fail_closed_at_every_stage() {
    let origin = Instant::now();
    let stages =
        SettlementStageCutoffsV1::derive_instants(origin, origin + Duration::from_secs(10), 10_000)
            .expect("valid settlement allocation");
    for cutoff in stages.instant_cutoffs() {
        assert!(SettlementStageCutoffsV1::strictly_before(
            cutoff - Duration::from_millis(1),
            cutoff
        ));
        assert!(!SettlementStageCutoffsV1::strictly_before(cutoff, cutoff));
        assert!(!SettlementStageCutoffsV1::strictly_before(
            cutoff + Duration::from_millis(1),
            cutoff
        ));
    }
}

#[test]
fn deadline_bridge_and_cleanup_failures_have_explicit_classes() {
    assert_eq!(
        ToolExecutionError::deadline("tool_settlement_deadline_exceeded").class(),
        ToolExecutionFailureClass::Deadline
    );
    assert_eq!(
        ToolExecutionError::bridge("external_stdio_response_eof").class(),
        ToolExecutionFailureClass::Bridge
    );
    assert_eq!(
        ToolExecutionError::cleanup("terminal_actor_cleanup_unverified", true, Some(false), None,)
            .class(),
        ToolExecutionFailureClass::Cleanup
    );
}

#[tokio::test]
async fn typed_fatal_settlement_preserves_known_code_without_tool_completion() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let mut writer = bridge_response_stream;
        let request = read_request(&mut reader).await;
        let settlement = ExternalToolSettlement::Fatal {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: request.seq,
            run_id: request.run_id.clone(),
            trial_id: request.trial_id.clone(),
            attempt_id: request.attempt_id.clone(),
            call_id: request.call_id.clone(),
            tool_name: request.tool_name.clone(),
            request_sha256: request.sha256().expect("request hash"),
            failure: ExternalToolFailure {
                code: "terminal_actor_cleanup_unverified".to_owned(),
                execution_may_have_started: true,
                cleanup_verified: Some(false),
                census_verified: None,
                recoverability: ExternalToolRecoverability::Fatal,
            },
        };
        let mut bytes = serde_json::to_vec(&settlement).expect("settlement");
        bytes.push(b'\n');
        writer.write_all(&bytes).await.expect("write fatal");
        writer.flush().await.expect("flush fatal");
    });
    let error = executor
        .execute(
            &call("call-fatal", "true"),
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect_err("fatal settlement");
    assert_code(error.clone(), "terminal_actor_cleanup_unverified");
    assert!(error.execution_may_have_started());
    assert_eq!(error.cleanup_verified(), Some(false));
    assert_eq!(error.census_verified(), None);
    assert!(error.actor_receipt().is_none());
    bridge.await.expect("fatal bridge");
}

#[tokio::test]
async fn fatal_codes_use_an_explicit_classification_table() {
    for (code, expected_class) in [
        (
            "external_stdio_response_timeout",
            ToolExecutionFailureClass::Deadline,
        ),
        (
            "cleanup_deadline_exceeded",
            ToolExecutionFailureClass::Cleanup,
        ),
        (
            "response_serialization_size_limit_exceeded",
            ToolExecutionFailureClass::Bridge,
        ),
        (
            "terminal_actor_workspace_mapping_changed",
            ToolExecutionFailureClass::Bridge,
        ),
        (
            "external_response_bounds_invalid",
            ToolExecutionFailureClass::Bridge,
        ),
        (
            "external_response_failure_invalid",
            ToolExecutionFailureClass::Bridge,
        ),
        (
            "external_response_media_invalid",
            ToolExecutionFailureClass::Bridge,
        ),
        (
            "external_response_process_invalid",
            ToolExecutionFailureClass::Bridge,
        ),
        (
            "external_response_return_code_invalid",
            ToolExecutionFailureClass::Bridge,
        ),
        (
            "external_response_wait_invalid",
            ToolExecutionFailureClass::Bridge,
        ),
    ] {
        let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
        let (bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
        let run_spec = spec("/remote/workspace");
        let mut executor =
            ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
                .expect("external executor");
        let bridge = tokio::spawn(async move {
            let mut reader = BufReader::new(bridge_request_stream);
            let mut writer = bridge_response_stream;
            let request = read_request(&mut reader).await;
            let settlement = ExternalToolSettlement::Fatal {
                schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
                message_type: ExternalToolMessageType::Response,
                seq: request.seq,
                run_id: request.run_id.clone(),
                trial_id: request.trial_id.clone(),
                attempt_id: request.attempt_id.clone(),
                call_id: request.call_id.clone(),
                tool_name: request.tool_name.clone(),
                request_sha256: request.sha256().expect("request hash"),
                failure: ExternalToolFailure {
                    code: code.to_owned(),
                    execution_may_have_started: true,
                    cleanup_verified: None,
                    census_verified: None,
                    recoverability: ExternalToolRecoverability::Fatal,
                },
            };
            let mut bytes = serde_json::to_vec(&settlement).expect("settlement");
            bytes.push(b'\n');
            writer.write_all(&bytes).await.expect("write fatal");
            writer.flush().await.expect("flush fatal");
        });
        let error = executor
            .execute(
                &call(&format!("call-{code}"), "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect_err("fatal settlement");
        assert_code(error.clone(), code);
        assert_eq!(error.class(), expected_class);
        bridge.await.expect("fatal bridge");
    }
}

#[tokio::test]
async fn mapping_preflight_timeout_preserves_code_without_tool_effect() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let mut writer = bridge_response_stream;
        let request = read_request(&mut reader).await;
        let settlement = ExternalToolSettlement::Fatal {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: request.seq,
            run_id: request.run_id.clone(),
            trial_id: request.trial_id.clone(),
            attempt_id: request.attempt_id.clone(),
            call_id: request.call_id.clone(),
            tool_name: request.tool_name.clone(),
            request_sha256: request.sha256().expect("request hash"),
            failure: ExternalToolFailure {
                code: "terminal_actor_workspace_mapping_check_timeout".to_owned(),
                execution_may_have_started: false,
                cleanup_verified: None,
                census_verified: None,
                recoverability: ExternalToolRecoverability::Fatal,
            },
        };
        let mut bytes = serde_json::to_vec(&settlement).expect("settlement");
        bytes.push(b'\n');
        writer.write_all(&bytes).await.expect("write fatal");
        writer.flush().await.expect("flush fatal");
    });
    let error = executor
        .execute(
            &call("call-mapping-preflight", "true"),
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect_err("mapping preflight timeout settlement");
    assert_code(
        error.clone(),
        "terminal_actor_workspace_mapping_check_timeout",
    );
    assert!(!error.execution_may_have_started());
    assert_eq!(error.cleanup_verified(), None);
    assert_eq!(error.census_verified(), None);
    bridge.await.expect("fatal bridge");
}

#[tokio::test]
async fn png_media_is_verified_and_kept_out_of_text_and_debug_paths() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(64 * 1024);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(64 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut media_profile = profile();
    media_profile.tools.read_file_media_enabled = true;
    media_profile.context.max_request_body_bytes = 16 * 1024 * 1024;
    media_profile.tools.max_read_or_write_bytes = 4 * 1024 * 1024;
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &media_profile)
            .expect("external executor");
    let content = vec![137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3];
    let digest = format!("{:x}", Sha256::digest(&content));
    let bridge_digest = digest.clone();
    let bridge_content = content.clone();
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let mut writer = bridge_response_stream;
        let request = read_request(&mut reader).await;
        assert!(request.limits.read_file_media_enabled);
        let settlement = ExternalToolSettlement::Completed {
            schema_version: EXTERNAL_TOOL_STDIO_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: request.seq,
            run_id: request.run_id.clone(),
            trial_id: request.trial_id.clone(),
            attempt_id: request.attempt_id.clone(),
            call_id: request.call_id.clone(),
            tool_name: request.tool_name.clone(),
            request_sha256: request.sha256().expect("request hash"),
            result: ExternalToolCompletedResult {
                return_code: 0,
                timed_out: false,
                stdout_base64: BASE64.encode(format!(
                    "read_file returned an attached image: image/png, 2x1, sha256={bridge_digest}"
                )),
                stderr_base64: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                process_disposition: ExternalProcessDisposition::NoProcess,
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
                media: Some(Box::new(ExternalMediaPayload {
                    logical_path: "board.png".to_owned(),
                    mime_type: ExternalMediaType::Png,
                    width: 2,
                    height: 1,
                    source_byte_length: u64::try_from(bridge_content.len()).expect("length"),
                    source_sha256: bridge_digest.clone(),
                    canonical_byte_length: u64::try_from(bridge_content.len()).expect("length"),
                    canonical_sha256: bridge_digest,
                    content_base64: BASE64.encode(&bridge_content),
                })),
            },
        };
        let mut bytes = serde_json::to_vec(&settlement).expect("settlement");
        bytes.push(b'\n');
        writer.write_all(&bytes).await.expect("write media");
        writer.flush().await.expect("flush media");
    });
    let call = FunctionCall {
        call_id: "call-media".to_owned(),
        name: "read_file".to_owned(),
        arguments_json: r#"{"target_file":"board.png"}"#.to_owned(),
    };
    let result = executor
        .execute(
            &call,
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("media result");
    bridge.await.expect("media bridge");
    assert!(result.actor_receipt().is_none());

    let media = result.media.as_ref().expect("structured media");
    assert_eq!(media.logical_path(), "board.png");
    assert_eq!(media.bytes(), content);
    assert_eq!(media.canonical_sha256(), digest);
    assert!(!result.output.contains("iVBORw0KGgoBAgM="));
    assert!(!format!("{result:?}").contains("iVBORw0KGgoBAgM="));
}

#[tokio::test]
async fn partial_lines_are_reassembled_and_sequence_is_monotonic() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");
    assert_eq!(executor.workspace_mode(), WorkspaceMode::RemoteLogical);

    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let mut writer = bridge_response_stream;
        for expected_seq in 0..2 {
            let request = read_request(&mut reader).await;
            assert_eq!(request.seq, expected_seq);
            assert_eq!(request.logical_cwd, "/remote/workspace");
            let mut bytes = serde_json::to_vec(&response(
                &request,
                format!("out-{expected_seq}").as_bytes(),
            ))
            .expect("response JSON");
            bytes.push(b'\n');
            for byte in bytes {
                writer.write_all(&[byte]).await.expect("partial response");
            }
            writer.flush().await.expect("flush response");
        }
    });

    for index in 0..2 {
        let result = executor
            .execute(
                &call(&format!("call-{index}"), "printf remote"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect("settled response");
        assert_eq!(result.output, format!("exit: 0\nout-{index}"));
    }
    bridge.await.expect("bridge task");
}

#[tokio::test]
async fn three_foreground_tools_bind_raw_arguments_and_file_output_is_direct() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");

    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let mut writer = bridge_response_stream;
        for (expected_seq, expected_name, expected_arguments, output) in [
            (
                0,
                "run_terminal_command",
                json!({
                    "command": "printf terminal",
                    "description": "external bridge test",
                    "timeout": 1000,
                    "background": false
                }),
                b"terminal".as_slice(),
            ),
            (
                1,
                "read_file",
                json!({"target_file": "notes.txt", "offset": 1, "limit": 5}),
                b"1\xe2\x86\x92hello\n".as_slice(),
            ),
            (
                2,
                "write",
                json!({"file_path": "created.txt", "content": "hello"}),
                concat!(
                    "The file /remote/workspace/created.txt has been ",
                    "created."
                )
                .as_bytes(),
            ),
        ] {
            let request = read_request(&mut reader).await;
            assert_eq!(request.seq, expected_seq);
            assert_eq!(request.tool_name, expected_name);
            assert_eq!(
                serde_json::from_str::<Value>(&request.arguments_json)
                    .expect("request arguments JSON"),
                expected_arguments
            );
            let mut bytes = serde_json::to_vec(&response(&request, output)).expect("response JSON");
            bytes.push(b'\n');
            writer.write_all(&bytes).await.expect("write response");
            writer.flush().await.expect("flush response");
        }
    });

    let calls = [
        call("terminal", "printf terminal"),
        FunctionCall {
            call_id: "read".to_owned(),
            name: "read_file".to_owned(),
            arguments_json: "{\"target_file\":\"notes.txt\",\"offset\":1,\"limit\":5}".to_owned(),
        },
        FunctionCall {
            call_id: "write".to_owned(),
            name: "write".to_owned(),
            arguments_json: "{\"file_path\":\"created.txt\",\"content\":\"hello\"}".to_owned(),
        },
    ];
    let terminal = executor
        .execute(
            &calls[0],
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("terminal result");
    assert_eq!(terminal.output, "exit: 0\nterminal");
    let read = executor
        .execute(
            &calls[1],
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("read result");
    assert_eq!(read.output, "1→hello\n");
    let write = executor
        .execute(
            &calls[2],
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("write result");
    assert_eq!(
        write.output,
        concat!(
            "The file /remote/workspace/created.txt has been ",
            "created."
        )
    );
    bridge.await.expect("bridge task");
}

#[tokio::test]
async fn real_subprocess_stdio_round_trip_does_not_execute_command_on_host() {
    let root = tempfile::tempdir().expect("test root");
    let sentinel = root.path().join("must-not-exist");
    let remote_cwd = PathBuf::from("/remote/logical/workspace");
    let run_spec = spec(&remote_cwd);
    let profile = profile();
    let arguments_json = call("call-0", &format!("touch {}", sentinel.display())).arguments_json;
    let request = ExternalToolRequest::for_call(
        0,
        &run_spec,
        &profile,
        "call-0".to_owned(),
        "run_terminal_command".to_owned(),
        arguments_json,
        1000,
    )
    .expect("expected request");
    let response =
        serde_json::to_string(&response(&request, b"remote-only")).expect("response JSON");

    let mut child = Command::new("/bin/sh")
        .args(["-c", "IFS= read -r request; printf '%s\\n' \"$RESPONSE\""])
        .env("RESPONSE", response)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bridge subprocess");
    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");
    let mut executor =
        ExternalStdioExecutor::from_io(child_stdout, child_stdin, &run_spec, &profile)
            .expect("external executor");
    let result = executor
        .execute(
            &call("call-0", &format!("touch {}", sentinel.display())),
            &remote_cwd,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("subprocess response");
    assert_eq!(result.output, "exit: 0\nremote-only");
    assert!(!sentinel.exists(), "external command ran on the host");
    assert!(child.wait().await.expect("bridge status").success());
}

#[tokio::test]
async fn all_eight_tools_dispatch_but_six_tool_cohort_rejects_background_launch() {
    let (request_stream, _bridge_request_stream) = tokio::io::duplex(4096);
    let (_bridge_response_stream, response_stream) = tokio::io::duplex(4096);
    let run_spec = spec("/remote/workspace");
    let executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");

    for (index, name) in TOOL_ORDER.iter().enumerate() {
        let arguments_json = match *name {
            "run_terminal_command" => call("terminal", "true").arguments_json,
            "read_file" => r#"{"target_file":"notes.txt"}"#.to_owned(),
            "search_replace" => {
                r#"{"file_path":"notes.txt","old_string":"a","new_string":"b"}"#.to_owned()
            }
            "write" => r#"{"file_path":"notes.txt","content":"hello"}"#.to_owned(),
            "list_dir" => r#"{"target_directory":"."}"#.to_owned(),
            "grep" => r#"{"pattern":"hello"}"#.to_owned(),
            "kill_terminal_command" => {
                r#"{"task_id":"018f22d6-9f04-7cc0-8000-000000000001"}"#.to_owned()
            }
            "get_terminal_command_output" => {
                r#"{"task_ids":["018f22d6-9f04-7cc0-8000-000000000001"],"timeout_ms":0}"#.to_owned()
            }
            _ => unreachable!("frozen tool order"),
        };
        let call = FunctionCall {
            call_id: format!("call-{index}"),
            name: (*name).to_owned(),
            arguments_json,
        };
        executor.validate(&call).expect("all eight dispatchable");
    }

    let mut foreground_spec = spec("/remote/workspace");
    foreground_spec.active_tools = Some(
        TOOL_ORDER[..6]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
    );
    let foreground_executor = ExternalStdioExecutor::from_io(
        tokio::io::empty(),
        tokio::io::sink(),
        &foreground_spec,
        &profile(),
    )
    .expect("foreground executor");
    let background_launch = FunctionCall {
        call_id: "call-background".to_owned(),
        name: "run_terminal_command".to_owned(),
        arguments_json:
            r#"{"command":"sleep 60","description":"serve","timeout":0,"background":true}"#
                .to_owned(),
    };
    let rejection = foreground_executor
        .validate(&background_launch)
        .expect_err("six-tool cohort must reject background before spawn");
    assert!(!rejection.execution_attempted);
    assert_eq!(rejection.output, "background_unsupported_in_foreground_six");
}

#[tokio::test]
async fn shared_background_fixture_validates_through_the_rust_dispatch_gate() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/background-tool-cases-v1.json"
    ))
    .expect("background fixture JSON");
    assert_eq!(
        fixture["schema_version"], "background-tool-cases-v1",
        "fixture schema is pinned"
    );
    let (request_stream, _bridge_request_stream) = tokio::io::duplex(4096);
    let (_bridge_response_stream, response_stream) = tokio::io::duplex(4096);
    let run_spec = spec("/remote/workspace");
    let executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");

    let cases = fixture["cases"].as_array().expect("fixture cases");
    assert_eq!(cases.len(), 10);
    for (index, case) in cases.iter().enumerate() {
        let call = FunctionCall {
            call_id: format!("fixture-{index}"),
            name: case["tool_name"]
                .as_str()
                .expect("fixture tool_name")
                .to_owned(),
            arguments_json: serde_json::to_string(&case["arguments"])
                .expect("fixture arguments JSON"),
        };
        executor
            .validate(&call)
            .unwrap_or_else(|error| panic!("fixture case {}: {error:?}", case["case"]));
    }
}

#[tokio::test]
async fn background_launch_is_direct_and_disposition_is_bound_to_raw_mode() {
    let background_call = FunctionCall {
        call_id: "call-background".to_owned(),
        name: "run_terminal_command".to_owned(),
        arguments_json:
            r#"{"command":"sleep 60","description":"serve","timeout":0,"background":true}"#
                .to_owned(),
    };
    let task_id = "018f22d6-9f04-7cc0-8000-000000000001";
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request(&mut reader).await;
        assert!(
            request.timeout_ms > 0,
            "background runtime timeout=0 must not become bridge timeout=0"
        );
        let mut response = response(&request, b"<status>running</status>");
        response.process_disposition = ExternalProcessDisposition::BackgroundRetained;
        response.target_task_id = Some(task_id.to_owned());
        response.cleanup.attempted = false;
        response.census.owned_processes_alive = 1;
        bridge_response_stream
            .write_all(&serde_json::to_vec(&response).expect("response"))
            .await
            .expect("response");
        bridge_response_stream
            .write_all(b"\n")
            .await
            .expect("newline");
    });
    let result = executor
        .execute(
            &background_call,
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("background result");
    assert_eq!(result.output, "<status>running</status>");
    bridge.await.expect("bridge");

    for (call, wrong_disposition) in [
        (
            background_call,
            ExternalProcessDisposition::ForegroundCleaned,
        ),
        (
            call("call-foreground", "true"),
            ExternalProcessDisposition::BackgroundRetained,
        ),
    ] {
        let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
        let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
        let run_spec = spec("/remote/workspace");
        let mut executor =
            ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
                .expect("external executor");
        let bridge = tokio::spawn(async move {
            let mut reader = BufReader::new(bridge_request_stream);
            let request = read_request(&mut reader).await;
            let mut response = response(&request, b"wrong");
            response.process_disposition = wrong_disposition;
            if wrong_disposition == ExternalProcessDisposition::BackgroundRetained {
                response.target_task_id = Some(task_id.to_owned());
                response.cleanup.attempted = false;
                response.census.owned_processes_alive = 1;
            }
            bridge_response_stream
                .write_all(&serde_json::to_vec(&response).expect("response"))
                .await
                .expect("response");
            bridge_response_stream
                .write_all(b"\n")
                .await
                .expect("newline");
        });
        assert_code(
            executor
                .execute(
                    &call,
                    Path::new("/remote/workspace"),
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .expect_err("cross-mode disposition"),
            "external_stdio_process_disposition_invalid",
        );
        bridge.await.expect("bridge");
    }
}

#[tokio::test]
async fn background_limit_rejection_is_model_visible_without_a_process() {
    let background_call = FunctionCall {
        call_id: "call-background-limit".to_owned(),
        name: "run_terminal_command".to_owned(),
        arguments_json:
            r#"{"command":"sleep 60","description":"serve","timeout":0,"background":true}"#
                .to_owned(),
    };
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let mut executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile())
            .expect("external executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request(&mut reader).await;
        let mut response = response(&request, b"background_process_limit_exceeded");
        response.return_code = 2;
        response.process_disposition = ExternalProcessDisposition::NoProcess;
        response.cleanup.attempted = false;
        bridge_response_stream
            .write_all(&serde_json::to_vec(&response).expect("response"))
            .await
            .expect("response");
        bridge_response_stream
            .write_all(b"\n")
            .await
            .expect("newline");
    });
    let result = executor
        .execute(
            &background_call,
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("limit rejection is settled");
    assert!(result.execution_attempted);
    assert_eq!(result.outcome, ToolOutcome::Rejected);
    assert_eq!(result.output, "background_process_limit_exceeded");
    bridge.await.expect("bridge");
}

#[tokio::test]
async fn strict_response_failures_never_produce_a_settled_result() {
    for (case, expected) in [
        ("unknown", "external_stdio_response_invalid"),
        ("duplicate", "external_stdio_response_invalid"),
        ("mismatch", "external_stdio_response_identity_mismatch"),
        ("cleanup", "external_stdio_cleanup_unverified"),
        ("census", "external_stdio_census_unverified"),
        ("base64", "external_stdio_response_base64_invalid"),
        (
            "oversize_output",
            "external_stdio_response_output_limit_exceeded",
        ),
    ] {
        let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
        let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
        let run_spec = spec("/remote/workspace");
        let profile = profile();
        let mut executor =
            ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile)
                .expect("external executor");
        let case = case.to_owned();
        let bridge = tokio::spawn(async move {
            let mut reader = BufReader::new(bridge_request_stream);
            let request = read_request(&mut reader).await;
            let mut value =
                serde_json::to_value(response(&request, b"ok")).expect("response value");
            match case.as_str() {
                "unknown" => {
                    value["unknown"] = Value::Bool(true);
                }
                "mismatch" => {
                    value["call_id"] = Value::String("wrong-call".to_owned());
                }
                "cleanup" => {
                    value["cleanup"]["verified"] = Value::Bool(false);
                }
                "census" => {
                    value["census"]["owned_processes_alive"] = Value::from(1);
                }
                "base64" => {
                    value["stdout_base64"] = Value::String("***".to_owned());
                }
                "oversize_output" => {
                    value["stdout_base64"] = Value::String(BASE64.encode(vec![0_u8; 4097]));
                }
                "duplicate" => {}
                other => panic!("unknown case {other}"),
            }
            let mut encoded = serde_json::to_string(&value).expect("response JSON");
            if case == "duplicate" {
                encoded = encoded.replacen('{', "{\"seq\":0,", 1);
            }
            bridge_response_stream
                .write_all(encoded.as_bytes())
                .await
                .expect("write response");
            bridge_response_stream
                .write_all(b"\n")
                .await
                .expect("write newline");
            bridge_response_stream
                .flush()
                .await
                .expect("flush response");
        });
        let error = executor
            .execute(
                &call("call-0", "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect_err("protocol failure must be incomplete");
        assert_code(error, expected);
        bridge.await.expect("bridge task");
    }
}

#[tokio::test]
async fn bridge_eof_oversize_line_and_late_response_are_incomplete() {
    let run_spec = spec("/remote/workspace");
    let profile = profile();

    let (request_stream, bridge_request_stream) = tokio::io::duplex(4096);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(4096);
    let mut eof_executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile)
            .expect("external executor");
    let eof_bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let _ = read_request(&mut reader).await;
        drop(bridge_response_stream);
    });
    assert_code(
        eof_executor
            .execute(
                &call("call-eof", "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect_err("EOF"),
        "external_stdio_response_eof",
    );
    eof_bridge.await.expect("EOF bridge");

    let (request_stream, bridge_request_stream) = tokio::io::duplex(4096);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(128 * 1024);
    let mut oversize_executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &profile)
            .expect("external executor");
    let oversize_bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let _ = read_request(&mut reader).await;
        bridge_response_stream
            .write_all(&vec![b'x'; 65_536])
            .await
            .expect("write oversized line");
        bridge_response_stream
            .write_all(b"\n")
            .await
            .expect("write newline");
    });
    assert_code(
        oversize_executor
            .execute(
                &call("call-oversize", "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect_err("oversize"),
        "external_stdio_response_line_limit_exceeded",
    );
    oversize_bridge.await.expect("oversize bridge");

    let (request_stream, bridge_request_stream) = tokio::io::duplex(4096);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(4096);
    let mut late_profile = profile.clone();
    late_profile.deadlines.terminalization_reserve_sec = 0;
    let mut late_executor =
        ExternalStdioExecutor::from_io(response_stream, request_stream, &run_spec, &late_profile)
            .expect("external executor");
    let late_bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let _ = read_request(&mut reader).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = bridge_response_stream.write_all(b"{}\n").await;
    });
    assert_code(
        late_executor
            .execute(
                &call("call-late", "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_millis(20),
            )
            .await
            .expect_err("late"),
        "external_stdio_response_timeout",
    );
    late_bridge.await.expect("late bridge");
}

#[test]
fn request_freezes_environment_timeout_caps_and_identity() {
    let run_spec = spec("/remote/workspace");
    let request = ExternalToolRequest::for_call(
        7,
        &run_spec,
        &profile(),
        "call-7".to_owned(),
        "run_terminal_command".to_owned(),
        call("call-7", "printf hello").arguments_json,
        4321,
    )
    .expect("request");
    assert_eq!(request.seq, 7);
    assert_eq!(request.run_id, run_spec.run_id);
    assert_eq!(request.trial_id, run_spec.trial_id);
    assert_eq!(request.attempt_id, run_spec.attempt_id);
    assert_eq!(request.logical_cwd, "/remote/workspace");
    assert_eq!(request.timeout_ms, 4321);
    assert_eq!(request.stdout_cap_bytes, 2048);
    assert_eq!(request.stderr_cap_bytes, 2048);
    assert_eq!(request.limits.max_background_processes, 8);
    assert_eq!(request.limits.process_spool_bytes_per_process, 4096);
    assert_eq!(request.limits.process_spool_bytes_per_run, 8192);
    assert_eq!(request.limits.background_output_wait_max_ms, 600000);
    assert_eq!(
        request.environment,
        ExternalEnvironmentPolicy::minimal_remote()
    );
}

#[tokio::test]
async fn v3_status_keeps_model_300s_semantics_under_absolute_actor_budget() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let deadline = v3_deadline(now + Duration::from_secs(20), now + Duration::from_secs(30));
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile(),
        deadline,
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let mut writer = bridge_response_stream;
        let request = read_request_v3(&mut reader).await;
        assert_eq!(request.schema_version, EXTERNAL_TOOL_STDIO_V3_SCHEMA);
        assert_eq!(request.operation_timeout_ms, 300_000);
        assert_eq!(
            request.hard_deadline_monotonic_ns - request.actor_done_monotonic_ns,
            75_000_000_000
        );
        assert_eq!(
            request.tool_settled_monotonic_ns - request.actor_done_monotonic_ns,
            10_000_000_000
        );
        let settlement = response_v3(&request, b"<status>running</status>", true);
        let mut bytes = serde_json::to_vec(&settlement).expect("v3 response");
        bytes.push(b'\n');
        writer.write_all(&bytes).await.expect("write v3 response");
        writer.flush().await.expect("flush v3 response");
    });
    let status_call = FunctionCall {
        call_id: "call-status-300s".to_owned(),
        name: "get_terminal_command_output".to_owned(),
        arguments_json: concat!(
            "{\"task_ids\":[\"018f22d6-9f04-7cc0-8000-000000000001\"],",
            "\"timeout_ms\":300000}"
        )
        .to_owned(),
    };
    let result = executor
        .execute(&status_call, Path::new("/remote/workspace"), Instant::now())
        .await
        .expect("v3 status settles");
    bridge.await.expect("v3 bridge");
    assert!(result.actor_receipt().is_none());
    assert_eq!(result.output, "<status>running</status>");
    let budget = result.runtime_budget.expect("runtime budget metadata");
    assert!(budget.wait_clamped);
    assert_eq!(budget.wait_reason, Some(ToolWaitReason::RuntimeBudget));
}

#[tokio::test]
async fn v3_background_transport_fatal_preserves_cleanup_provenance() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile(),
        v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let request = read_request_v3(&mut reader).await;
        let settlement = ExternalToolSettlementV3::Fatal {
            schema_version: EXTERNAL_TOOL_STDIO_V3_SCHEMA.to_owned(),
            message_type: ExternalToolMessageType::Response,
            seq: request.seq,
            run_id: request.run_id.clone(),
            trial_id: request.trial_id.clone(),
            attempt_id: request.attempt_id.clone(),
            call_id: request.call_id.clone(),
            tool_name: request.tool_name.clone(),
            request_sha256: request.sha256().expect("request hash"),
            failure: ExternalToolFailureV3 {
                code: "terminal_actor_transport_unknown".to_owned(),
                execution_may_have_started: true,
                cleanup_verified: Some(true),
                census_verified: Some(true),
                recoverability: ExternalToolRecoverability::Fatal,
                actor_receipt: None,
            },
        };
        let mut bytes = serde_json::to_vec(&settlement).expect("settlement");
        bytes.push(b'\n');
        bridge_response_stream
            .write_all(&bytes)
            .await
            .expect("write fatal");
        bridge_response_stream.flush().await.expect("flush fatal");
    });
    let background_call = FunctionCall {
        call_id: "call-transport-fatal".to_owned(),
        name: "run_terminal_command".to_owned(),
        arguments_json:
            r#"{"command":"serve","description":"transport loss","timeout":0,"background":true}"#
                .to_owned(),
    };
    let error = executor
        .execute(
            &background_call,
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await
        .expect_err("transport loss must stay fatal");
    assert!(error.actor_receipt().is_none());
    assert_code(error.clone(), "terminal_actor_transport_unknown");
    assert!(error.execution_may_have_started());
    assert_eq!(error.cleanup_verified(), Some(true));
    assert_eq!(error.census_verified(), Some(true));
    bridge.await.expect("v3 bridge");
}

#[tokio::test]
async fn v3_background_no_id_accepts_only_the_versioned_closed_proof() {
    #[derive(Clone, Copy)]
    enum Fault {
        None,
        CleanupUnverified,
        CensusUnverified,
        Survivor,
        TimedOut,
        TargetId,
        TermSent,
        KillSent,
        ForegroundCrossMode,
        RetainedWithProof,
        WrongProofVersion,
    }

    #[derive(Clone, Copy)]
    struct Case {
        name: &'static str,
        return_code: i32,
        cleanup_attempted: bool,
        observation: Option<(ExternalBackgroundStartKind, bool, Option<i32>)>,
        fault: Fault,
        accepted: bool,
    }

    for case in [
        Case {
            name: "not-started",
            return_code: 2,
            cleanup_attempted: false,
            observation: Some((ExternalBackgroundStartKind::NotStarted, false, None)),
            fault: Fault::None,
            accepted: true,
        },
        Case {
            name: "quick-exit-zero",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::None,
            accepted: true,
        },
        Case {
            name: "quick-exit-nonzero",
            return_code: 2,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(7))),
            fault: Fault::None,
            accepted: true,
        },
        Case {
            name: "rc2-without-proof",
            return_code: 2,
            cleanup_attempted: false,
            observation: None,
            fault: Fault::None,
            accepted: false,
        },
        Case {
            name: "cleaned-transport-without-proof",
            return_code: 2,
            cleanup_attempted: true,
            observation: None,
            fault: Fault::None,
            accepted: false,
        },
        Case {
            name: "publish-before-error-race",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, true, Some(0))),
            fault: Fault::None,
            accepted: false,
        },
        Case {
            name: "forged-rc0-child-nonzero",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(7))),
            fault: Fault::None,
            accepted: false,
        },
        Case {
            name: "cleanup-unverified",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::CleanupUnverified,
            accepted: false,
        },
        Case {
            name: "census-unverified",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::CensusUnverified,
            accepted: false,
        },
        Case {
            name: "survivor",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::Survivor,
            accepted: false,
        },
        Case {
            name: "timed-out",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::TimedOut,
            accepted: false,
        },
        Case {
            name: "published-target-id",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::TargetId,
            accepted: false,
        },
        Case {
            name: "term-sent",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::TermSent,
            accepted: false,
        },
        Case {
            name: "kill-sent",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::KillSent,
            accepted: false,
        },
        Case {
            name: "foreground-cross-mode",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::ForegroundCrossMode,
            accepted: false,
        },
        Case {
            name: "retained-with-no-id-proof",
            return_code: 0,
            cleanup_attempted: false,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::RetainedWithProof,
            accepted: false,
        },
        Case {
            name: "wrong-proof-version",
            return_code: 0,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, Some(0))),
            fault: Fault::WrongProofVersion,
            accepted: false,
        },
        Case {
            name: "quick-exit-missing-child-code",
            return_code: 2,
            cleanup_attempted: true,
            observation: Some((ExternalBackgroundStartKind::QuickExit, false, None)),
            fault: Fault::None,
            accepted: false,
        },
        Case {
            name: "not-started-with-child-code",
            return_code: 2,
            cleanup_attempted: false,
            observation: Some((ExternalBackgroundStartKind::NotStarted, false, Some(7))),
            fault: Fault::None,
            accepted: false,
        },
    ] {
        let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
        let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
        let run_spec = spec("/remote/workspace");
        let now = Instant::now();
        let mut executor = ExternalStdioExecutor::from_io_v3(
            response_stream,
            request_stream,
            &run_spec,
            &profile(),
            v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
        )
        .expect("v3 executor");
        let bridge = tokio::spawn(async move {
            let mut reader = BufReader::new(bridge_request_stream);
            let request = read_request_v3(&mut reader).await;
            let mut settlement = response_v3(
                &request,
                b"<observation>background_start_not_running</observation>",
                false,
            );
            let ExternalToolSettlementV3::Completed { result, .. } = &mut settlement else {
                unreachable!("completed")
            };
            result.return_code = case.return_code;
            result.cleanup.attempted = case.cleanup_attempted;
            result.background_start_observation =
                case.observation
                    .map(|(kind, task_id_published, child_exit_code)| {
                        ExternalBackgroundStartObservation {
                            proof_version: EXTERNAL_BACKGROUND_START_PROOF_VERSION.to_owned(),
                            kind,
                            task_id_published,
                            child_exit_code,
                        }
                    });
            match case.fault {
                Fault::None | Fault::ForegroundCrossMode => {}
                Fault::CleanupUnverified => result.cleanup.verified = false,
                Fault::CensusUnverified => result.census.verified = false,
                Fault::Survivor => result.census.owned_processes_alive = 1,
                Fault::TimedOut => result.timed_out = true,
                Fault::TargetId => {
                    result.target_task_id = Some("018f22d6-9f04-7cc0-8000-000000000001".to_owned());
                }
                Fault::TermSent => result.cleanup.term_sent = true,
                Fault::KillSent => result.cleanup.kill_sent = true,
                Fault::RetainedWithProof => {
                    result.process_disposition = ExternalProcessDisposition::BackgroundRetained;
                    result.target_task_id = Some("018f22d6-9f04-7cc0-8000-000000000001".to_owned());
                    result.census.owned_processes_alive = 1;
                }
                Fault::WrongProofVersion => {
                    result
                        .background_start_observation
                        .as_mut()
                        .expect("proof")
                        .proof_version = "background-start-no-id-proof-v0".to_owned();
                }
            }
            let mut bytes = serde_json::to_vec(&settlement).expect("settlement");
            bytes.push(b'\n');
            bridge_response_stream
                .write_all(&bytes)
                .await
                .expect("write response");
        });
        let background_call = FunctionCall {
            call_id: format!("call-{}", case.name),
            name: "run_terminal_command".to_owned(),
            arguments_json: format!(
                concat!(
                    r#"{{"command":"true","description":"proof matrix","timeout":{},"#,
                    r#""background":{}}}"#,
                ),
                if matches!(case.fault, Fault::ForegroundCrossMode) {
                    1_000
                } else {
                    0
                },
                !matches!(case.fault, Fault::ForegroundCrossMode)
            ),
        };
        let observed = executor
            .execute(
                &background_call,
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(600),
            )
            .await;
        if case.accepted {
            observed.unwrap_or_else(|error| panic!("{} should be accepted: {error:?}", case.name));
        } else {
            assert!(
                observed.is_err(),
                "{} must fail closed without an exact proof",
                case.name
            );
        }
        bridge.await.expect("v3 bridge");
    }
}

#[tokio::test]
async fn v3_nullable_fields_are_required_on_the_live_reader() {
    for missing_field in ["target_task_id", "media", "background_start_observation"] {
        let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
        let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
        let run_spec = spec("/remote/workspace");
        let now = Instant::now();
        let mut executor = ExternalStdioExecutor::from_io_v3(
            response_stream,
            request_stream,
            &run_spec,
            &profile(),
            v3_deadline(now + Duration::from_secs(1), now + Duration::from_secs(2)),
        )
        .expect("v3 executor");
        let bridge = tokio::spawn(async move {
            let mut reader = BufReader::new(bridge_request_stream);
            let request = read_request_v3(&mut reader).await;
            let mut value =
                serde_json::to_value(response_v3(&request, b"status", false)).expect("response");
            value["result"]
                .as_object_mut()
                .expect("result object")
                .remove(missing_field);
            let mut bytes = serde_json::to_vec(&value).expect("response JSON");
            bytes.push(b'\n');
            bridge_response_stream
                .write_all(&bytes)
                .await
                .expect("write response");
        });
        let error = executor
            .execute(
                &call(&format!("call-missing-{missing_field}"), "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(600),
            )
            .await
            .expect_err("missing nullable field");
        assert_code(error, "external_stdio_response_invalid");
        bridge.await.expect("v3 bridge");
    }
}

#[tokio::test]
async fn v3_no_partial_and_late_responses_share_typed_settlement_deadline() {
    for case in ["none", "partial", "late"] {
        let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
        let (mut bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
        let run_spec = spec("/remote/workspace");
        let now = Instant::now();
        let deadline = v3_deadline(
            now + Duration::from_millis(20),
            now + Duration::from_millis(30),
        );
        let mut executor = ExternalStdioExecutor::from_io_v3(
            response_stream,
            request_stream,
            &run_spec,
            &profile(),
            deadline,
        )
        .expect("v3 executor");
        let bridge = tokio::spawn(async move {
            let mut reader = BufReader::new(bridge_request_stream);
            let request = read_request_v3(&mut reader).await;
            if case == "partial" {
                bridge_response_stream
                    .write_all(b"{")
                    .await
                    .expect("partial response");
                bridge_response_stream.flush().await.expect("partial flush");
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            if case == "late" {
                let mut bytes =
                    serde_json::to_vec(&response_v3(&request, b"late", false)).expect("late v3");
                bytes.push(b'\n');
                let _ = bridge_response_stream.write_all(&bytes).await;
            }
        });
        let error = executor
            .execute(
                &call(&format!("call-{case}"), "true"),
                Path::new("/remote/workspace"),
                Instant::now() + Duration::from_secs(600),
            )
            .await
            .expect_err("v3 response must miss tool settlement");
        assert_code(error.clone(), "tool_settlement_deadline_exceeded");
        assert_eq!(error.class(), ToolExecutionFailureClass::Deadline);
        bridge.await.expect("v3 deadline bridge");
    }
}

#[tokio::test]
async fn v3_eof_at_encode_cutoff_is_typed_serialization_deadline() {
    let (request_stream, bridge_request_stream) = tokio::io::duplex(32 * 1024);
    let (bridge_response_stream, response_stream) = tokio::io::duplex(32 * 1024);
    let run_spec = spec("/remote/workspace");
    let now = Instant::now();
    let actor_done = now + Duration::from_millis(20);
    let tool_settled = now + Duration::from_millis(80);
    let stages = SettlementStageCutoffsV1::derive_instants(actor_done, tool_settled, 60)
        .expect("settlement stages")
        .instant_cutoffs();
    let mut executor = ExternalStdioExecutor::from_io_v3(
        response_stream,
        request_stream,
        &run_spec,
        &profile(),
        v3_deadline(actor_done, tool_settled),
    )
    .expect("v3 executor");
    let bridge = tokio::spawn(async move {
        let mut reader = BufReader::new(bridge_request_stream);
        let _request = read_request_v3(&mut reader).await;
        tokio::time::sleep_until(tokio::time::Instant::from_std(stages[2])).await;
        drop(bridge_response_stream);
    });

    let error = executor
        .execute(
            &call("call-encode-eof", "true"),
            Path::new("/remote/workspace"),
            Instant::now() + Duration::from_secs(600),
        )
        .await
        .expect_err("encode-cutoff EOF must be typed");
    assert_code(error.clone(), "response_serialization_deadline_exceeded");
    assert_eq!(error.class(), ToolExecutionFailureClass::Deadline);
    bridge.await.expect("encode EOF bridge");
}
