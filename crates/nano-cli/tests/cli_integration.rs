use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nano_types::contract::{LocalContract, TOOL_ORDER};
use nano_types::run_spec::RunSpec;
use rustix::time::{ClockId, clock_gettime};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CONTRACT_ID: &str = "synthetic-v1";
const PROFILE_ID: &str = "synthetic-profile-v1";

fn monotonic_ns() -> u64 {
    let value = clock_gettime(ClockId::Monotonic);
    u64::try_from(value.tv_sec)
        .expect("positive monotonic seconds")
        .checked_mul(1_000_000_000)
        .and_then(|seconds| {
            u64::try_from(value.tv_nsec)
                .ok()
                .and_then(|nanoseconds| seconds.checked_add(nanoseconds))
        })
        .expect("monotonic nanoseconds")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn no_history(instruction: &str, digest: &str) -> Value {
    json!({
        "schema_version": "nano-git-history-capability-v1",
        "policy_version": "nano-git-history-capability-policy-v2",
        "git_history_access": "not_required",
        "canonical_instruction_sha256": sha256_hex(instruction.as_bytes()),
        "trusted_manifest_sha256": digest,
        "supporting_span_sha256": null
    })
}

fn completed_actor_receipt(effective_cutoff_monotonic_ns: u64) -> Value {
    let mut receipt = json!({
        "schema_version": "terminal-actor-receipt-v1",
        "phase": "meta_validate",
        "origin": "actor",
        "primary_subtype": "completed",
        "recovery_subtype": null,
        "execution_may_have_started": true,
        "effective_cutoff_monotonic_ns": effective_cutoff_monotonic_ns,
        "cleanup_verified": true,
        "census_verified": true
    });
    let digest = sha256_hex(
        &serde_json::to_vec(&receipt).expect("serialize terminal actor receipt diagnostics"),
    );
    receipt["diagnostic_digest_sha256"] = Value::String(digest);
    receipt
}

fn json_file(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("serialize synthetic JSON");
    bytes.push(b'\n');
    bytes
}

fn write_synthetic_contract(directory: &Path) {
    fs::create_dir(directory).expect("create contract directory");
    let prompt = "You are a synthetic first-party walking-slice agent.";
    let wrapper = "<user_query>\n{{USER_QUERY}}\n</user_query>";
    let tools = TOOL_ORDER
        .iter()
        .enumerate()
        .map(|(ordinal, name)| {
            let (description, schema) = match *name {
                "run_terminal_command" => (
                    "Run a command. Foreground commands default to 120000 ms and accept at most 600000 ms. Runtime ownership includes every launched descendant, including setsid and nohup descendants. Model-visible output is capped at 65536 bytes per call.",
                    json!({
                        "additionalProperties": false,
                        "properties": {
                            "text": {"type": "string"},
                            "timeout": {
                                "default": 120000,
                                "maximum": 600000,
                                "minimum": 0,
                                "type": ["integer", "null"]
                            }
                        },
                        "required": ["text"],
                        "type": "object"
                    }),
                ),
                "read_file" => (
                    "Read normal text files and PNG and JPEG image files only.",
                    json!({
                        "additionalProperties": false,
                        "properties": {"target_file": {"type": "string"}},
                        "required": ["target_file"],
                        "type": "object"
                    }),
                ),
                "get_terminal_command_output" => (
                    "Get background output; timeout_ms omitted or zero is nonblocking and a positive wait is capped at 30000 ms.",
                    json!({
                        "additionalProperties": false,
                        "properties": {
                            "timeout_ms": {
                                "default": null,
                                "maximum": 30000,
                                "minimum": 0,
                                "type": ["integer", "null"]
                            }
                        },
                        "required": [],
                        "type": "object"
                    }),
                ),
                _ => (
                    "Synthetic definition.",
                    json!({
                        "additionalProperties": false,
                        "properties": {},
                        "required": [],
                        "type": "object"
                    }),
                ),
            };
            json!({
                "ordinal": ordinal,
                "contract_tool_id": format!("synthetic:{name}"),
                "provider_name": name,
                "description": description,
                "input_schema": schema,
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
                    "renderer_contract_id": format!("synthetic-renderer:{name}"),
                    "truncation_policy": "synthetic-head-tail-v1",
                    "max_model_output_bytes": 65536
                }
            })
        })
        .collect::<Vec<_>>();
    let effective_value = json!({
        "schema_version": "effective-contract-v1",
        "contract_id": CONTRACT_ID,
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
        "contract_id": CONTRACT_ID
    }));
    let tools_hash = sha256_hex(
        &serde_json::to_vec(effective_value.get("tools").expect("tools")).expect("serialize tools"),
    );
    let profile = json_file(&json!({
        "schema_version": "agent-profile-v1",
        "profile_id": PROFILE_ID,
        "contract_id": CONTRACT_ID,
        "provider": {
            "provider_id": "scripted",
            "api": "responses-v1",
            "endpoint": "https://example.invalid/v1/responses",
            "model": "synthetic-model",
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
            "effective_contract_file_sha256": sha256_hex(&effective),
            "system_prompt_utf8_sha256": sha256_hex(prompt.as_bytes()),
            "ordered_tools_value_sha256": tools_hash,
            "contract_delta_file_sha256": sha256_hex(&delta)
        },
        "context": {
            "policy": "fail_closed_no_compaction",
            "counting_rule": "synthetic-context-upper-v1",
            "provider_context_window_tokens": 500000,
            "request_input_upper_tokens": 199000,
            "max_output_tokens_per_request": 16000,
            "max_provider_turns": 64,
            "max_input_tokens_per_run": 450000,
            "max_output_tokens_per_run": 120000,
            "max_history_items": 512,
            "max_request_body_bytes": 1048576
        },
        "transport": {
            "max_function_arguments_bytes": 1048576,
            "max_sse_events_per_response": 65536,
            "max_sse_event_bytes": 2097152,
            "max_sse_response_bytes": 16777216,
            "max_json_depth": 128
        },
        "scheduler": {
            "read_only_parallelism": 1,
            "max_function_calls_per_response": 16,
            "max_function_calls_per_run": 256,
            "mutation_batches_serialized": true
        },
        "deadlines": {
            "source": "run_spec_task_native",
            "absolute_run_wall_cap_sec": 12000,
            "terminalization_reserve_sec": 15,
            "min_provider_send_window_sec": 30,
            "provider_connect_timeout_sec": 10,
            "provider_first_event_timeout_sec": 900,
            "provider_inter_event_timeout_sec": 900,
            "provider_total_timeout_sec": 3600,
            "filesystem_operation_timeout_sec": 30,
            "search_operation_timeout_sec": 60,
            "process_control_timeout_sec": 10,
            "artifactization_timeout_sec": 60
        },
        "tools": {
            "terminal_default_timeout_ms": 120000,
            "terminal_max_timeout_ms": 600000,
            "background_output_wait_max_ms": 30000,
            "max_command_bytes": 65536,
            "max_path_bytes": 4096,
            "max_read_or_write_bytes": 4194304,
            "max_directory_entries": 10000,
            "max_grep_matches": 10000,
            "max_replacements": 10000,
            "model_tool_output_bytes_per_call": 65536,
            "model_tool_output_bytes_per_run": 8388608
        },
        "process": {
            "max_background_processes": 8,
            "term_grace_ms": 5000,
            "kill_confirmation_timeout_ms": 5000,
            "process_spool_bytes_per_process": 16777216,
            "process_spool_bytes_per_run": 134217728
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
    }));
    fs::write(directory.join("effective-contract.json"), effective).expect("write effective");
    fs::write(directory.join("agent-profile.json"), profile).expect("write profile");
    fs::write(directory.join("contract-delta.json"), delta).expect("write delta");
}

fn run_scripted_fixture(max_turns: u64, steps: Value) -> (tempfile::TempDir, PathBuf, Output) {
    let root = tempfile::tempdir().expect("create test root");
    let contract_dir = root.path().join("contract");
    let workspace_dir = root.path().join("workspace");
    let artifact_dir = root.path().join("artifacts");
    fs::create_dir(&workspace_dir).expect("create workspace");
    write_synthetic_contract(&contract_dir);
    let contract = LocalContract::load(&contract_dir).expect("load synthetic contract");
    let spec_path = root.path().join("run-spec.json");
    fs::write(
        &spec_path,
        json_file(&json!({
            "schema_version": "nano-run-spec-alpha-2",
            "run_id": "run-negative-001",
            "trial_id": "trial-negative-001",
            "attempt_id": "attempt-0",
            "task": {
                "id": "synthetic-negative",
                "digest": "b".repeat(64),
                "instruction": "Exercise a synthetic failure boundary.",
                "git_history_capability": no_history(
                    "Exercise a synthetic failure boundary.", &"b".repeat(64)
                )
            },
            "contract": {
                "id": CONTRACT_ID,
                "contract_set_sha256": contract.contract_set_sha256(),
                "profile_id": PROFILE_ID
            },
            "provider": {
                "kind": "scripted",
                "model": "synthetic-model",
                "max_turns": max_turns,
                "retry_max": 0
            },
            "workspace_dir": workspace_dir,
            "artifact_dir": artifact_dir,
            "agent_timeout_sec": 60
        })),
    )
    .expect("write run spec");
    let script_path = root.path().join("script.json");
    fs::write(
        &script_path,
        json_file(&json!({
            "schema_version": "scripted-provider-v1",
            "steps": steps
        })),
    )
    .expect("write provider script");
    let output = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .args([
            "run",
            "--spec",
            spec_path.to_str().expect("UTF-8 spec path"),
            "--contract-dir",
            contract_dir.to_str().expect("UTF-8 contract path"),
            "--provider",
            &format!(
                "scripted:{}",
                script_path.to_str().expect("UTF-8 script path")
            ),
        ])
        .output()
        .expect("run nano CLI");
    (root, artifact_dir, output)
}

#[test]
fn validate_contract_is_provider_free_and_machine_readable() {
    let root = tempfile::tempdir().expect("create admission root");
    let contract_dir = root.path().join("contract");
    write_synthetic_contract(&contract_dir);
    let output = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .env_remove("XAI_API_KEY")
        .args([
            "validate-contract",
            "--contract-dir",
            contract_dir.to_str().expect("UTF-8 contract path"),
        ])
        .output()
        .expect("run contract admission");
    assert!(
        output.status.success(),
        "contract admission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("admission JSON");
    assert_eq!(
        value,
        json!({
            "schema_version": "runtime-profile-v1",
        })
    );
}

#[test]
fn cli_runs_scripted_echo_walking_slice() {
    let root = tempfile::tempdir().expect("create test root");
    let contract_dir = root.path().join("contract");
    let workspace_dir = root.path().join("workspace");
    let artifact_dir = root.path().join("artifacts");
    fs::create_dir(&workspace_dir).expect("create workspace");
    write_synthetic_contract(&contract_dir);
    let contract = LocalContract::load(&contract_dir).expect("load synthetic contract");

    let spec_path = root.path().join("run-spec.json");
    fs::write(
        &spec_path,
        json_file(&json!({
            "schema_version": "nano-run-spec-alpha-2",
            "run_id": "run-walking-001",
            "trial_id": "trial-walking-001",
            "attempt_id": "attempt-0",
            "task": {
                "id": "synthetic-echo",
                "digest": "a".repeat(64),
                "instruction": "Echo the scripted value.",
                "git_history_capability": no_history(
                    "Echo the scripted value.", &"a".repeat(64)
                )
            },
            "contract": {
                "id": CONTRACT_ID,
                "contract_set_sha256": contract.contract_set_sha256(),
                "profile_id": PROFILE_ID
            },
            "provider": {
                "kind": "scripted",
                "model": "synthetic-model",
                "max_turns": 4,
                "retry_max": 0
            },
            "workspace_dir": workspace_dir,
            "artifact_dir": artifact_dir,
            "agent_timeout_sec": 60
        })),
    )
    .expect("write run spec");

    let script_path = root.path().join("script.json");
    fs::write(
        &script_path,
        json_file(&json!({
            "schema_version": "scripted-provider-v1",
            "steps": [
                {
                    "type": "completed",
                    "response": {
                        "response_id": "response-tool",
                        "model": "synthetic-model",
                        "output": [{
                            "type": "function_call",
                            "call_id": "call-echo-001",
                            "name": "run_terminal_command",
                            "arguments_json": "{\"text\":\"walking-slice-pong\"}"
                        }],
                        "usage": {"input_tokens": 10, "output_tokens": 4}
                    }
                },
                {
                    "type": "completed",
                    "response": {
                        "response_id": "response-final",
                        "model": "synthetic-model",
                        "output": [{
                            "type": "assistant_message",
                            "text": "CLI integration complete"
                        }],
                        "usage": null
                    }
                }
            ]
        })),
    )
    .expect("write provider script");

    let output = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .args([
            "run",
            "--spec",
            spec_path.to_str().expect("UTF-8 spec path"),
            "--contract-dir",
            contract_dir.to_str().expect("UTF-8 contract path"),
            "--provider",
            &format!(
                "scripted:{}",
                script_path.to_str().expect("UTF-8 script path")
            ),
        ])
        .output()
        .expect("run nano CLI");
    assert!(
        output.status.success(),
        "CLI failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "durable run emitted a warning");

    let lines = fs::read_to_string(artifact_dir.join("events.jsonl"))
        .expect("read events")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("strict event JSON"))
        .collect::<Vec<_>>();
    let event_types = lines
        .iter()
        .map(|event| event["type"].as_str().expect("event type"))
        .collect::<Vec<_>>();
    assert_eq!(
        event_types,
        [
            "run.started",
            "provider.requested",
            "provider.completed",
            "tool.registered",
            "tool.dispatched",
            "tool.completed",
            "provider.requested",
            "provider.completed",
            "assistant.final",
            "run.completed",
        ]
    );
    for (seq, event) in lines.iter().enumerate() {
        assert_eq!(event["schema_version"], "event-v3");
        assert_eq!(event["run_id"], "run-walking-001");
        assert_eq!(event["trial_id"], "trial-walking-001");
        assert_eq!(event["attempt_id"], "attempt-0");
        assert_eq!(event["seq"], seq);
        if seq > 0 {
            assert!(
                event["elapsed_ms"].as_u64().expect("elapsed")
                    >= lines[seq - 1]["elapsed_ms"]
                        .as_u64()
                        .expect("previous elapsed")
            );
        }
    }
    assert_eq!(lines[3]["data"]["call_id"], "call-echo-001");
    assert_eq!(lines[4]["data"]["call_id"], "call-echo-001");
    assert_eq!(lines[5]["data"]["call_id"], "call-echo-001");
    assert_eq!(lines[5]["data"]["execution_attempted"], true);
    assert_eq!(lines[5]["data"]["output"], "walking-slice-pong");
    assert_eq!(lines[1]["data"]["tool_count"], 8);
    assert_eq!(lines[6]["data"]["tool_count"], 8);
    assert_eq!(
        lines[6]["data"]["function_output_call_ids"],
        json!(["call-echo-001"])
    );

    let run: Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run.json")).expect("read committed run record"),
    )
    .expect("parse run record");
    assert_eq!(run["schema_version"], "nano-run-record-v2");
    assert_eq!(run["run_id"], "run-walking-001");
    assert_eq!(run["trial_id"], "trial-walking-001");
    assert_eq!(run["attempt_id"], "attempt-0");
    assert_eq!(run["terminal_status"], "success");
    assert_eq!(run["terminal_phase"], Value::Null);
    assert_eq!(run["terminal_code"], "completed");
    assert_eq!(run["final_event_seq"], 9);
    assert_eq!(run["provider_turn_count"], 2);
    assert_eq!(run["tool_call_count"], 1);
    assert_eq!(run["provider_call_coverage"]["requested"], 2);
    assert_eq!(run["provider_call_coverage"]["completed"], 2);
    assert_eq!(run["provider_call_coverage"]["usage_present"], 1);
    assert_eq!(run["provider_call_coverage"]["usage_absent"], 1);
    assert_eq!(run["provider_call_coverage"]["state"], "partial");
    assert_eq!(run["usage_totals"]["input_tokens"], 10);
    assert_eq!(run["usage_totals"]["output_tokens"], 4);
    assert_eq!(
        run["events_sha256"].as_str().expect("events hash").len(),
        64
    );
    assert!(!artifact_dir.join(".run.json.tmp").exists());
}

#[test]
fn cli_external_stdio_reserves_stdout_and_accepts_remote_logical_workspace() {
    let root = tempfile::tempdir().expect("create test root");
    let contract_dir = root.path().join("contract");
    let artifact_dir = root.path().join("artifacts");
    let remote_workspace = PathBuf::from("/remote/logical/workspace-not-on-host");
    let host_sentinel = root.path().join("must-not-exist");
    write_synthetic_contract(&contract_dir);
    let contract = LocalContract::load(&contract_dir).expect("load synthetic contract");
    let spec_path = root.path().join("run-spec.json");
    fs::write(
        &spec_path,
        json_file(&json!({
            "schema_version": "nano-run-spec-alpha-2",
            "run_id": "run-external-cli-001",
            "trial_id": "trial-external-cli-001",
            "attempt_id": "attempt-0",
            "task": {
                "id": "synthetic-external",
                "digest": "e".repeat(64),
                "instruction": "Use the remote terminal.",
                "git_history_capability": no_history(
                    "Use the remote terminal.", &"e".repeat(64)
                )
            },
            "contract": {
                "id": CONTRACT_ID,
                "contract_set_sha256": contract.contract_set_sha256(),
                "profile_id": PROFILE_ID
            },
            "provider": {
                "kind": "scripted",
                "model": "synthetic-model",
                "max_turns": 4,
                "retry_max": 0
            },
            "workspace_dir": remote_workspace,
            "artifact_dir": artifact_dir,
            "agent_timeout_sec": 60
        })),
    )
    .expect("write run spec");
    let command = format!("touch {}", host_sentinel.display());
    let script_path = root.path().join("script.json");
    fs::write(
        &script_path,
        json_file(&json!({
            "schema_version": "scripted-provider-v1",
            "steps": [
                {
                    "type": "completed",
                    "response": {
                        "response_id": "response-external-tool",
                        "model": "synthetic-model",
                        "output": [{
                            "type": "function_call",
                            "call_id": "call-external-cli-001",
                            "name": "run_terminal_command",
                            "arguments_json": serde_json::to_string(&json!({
                                "command": command,
                                "description": "prove external dispatch",
                                "timeout": 1000,
                                "background": false
                            })).expect("arguments")
                        }],
                        "usage": null
                    }
                },
                {
                    "type": "completed",
                    "response": {
                        "response_id": "response-external-final",
                        "model": "synthetic-model",
                        "output": [{
                            "type": "assistant_message",
                            "text": "external complete"
                        }],
                        "usage": null
                    }
                }
            ]
        })),
    )
    .expect("write provider script");

    let mut child = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .args([
            "run",
            "--spec",
            spec_path.to_str().expect("UTF-8 spec path"),
            "--contract-dir",
            contract_dir.to_str().expect("UTF-8 contract path"),
            "--provider",
            &format!(
                "scripted:{}",
                script_path.to_str().expect("UTF-8 script path")
            ),
            "--executor",
            "external-stdio",
            "--deadline-mode",
            "legacy-external-stdio-v2",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn external CLI");
    let stdout = child.stdout.take().expect("CLI stdout");
    let mut stdout = std::io::BufReader::new(stdout);
    let mut request_line = String::new();
    stdout
        .read_line(&mut request_line)
        .expect("read protocol request");
    assert!(request_line.ends_with('\n'));
    let request_bytes = request_line
        .strip_suffix('\n')
        .expect("LF framing")
        .as_bytes();
    let request: Value = serde_json::from_slice(request_bytes).expect("request JSON");
    assert_eq!(request["message_type"], "tool.request");
    assert_eq!(request["seq"], 0);
    assert_eq!(request["run_id"], "run-external-cli-001");
    assert_eq!(request["trial_id"], "trial-external-cli-001");
    assert_eq!(request["attempt_id"], "attempt-0");
    assert_eq!(request["call_id"], "call-external-cli-001");
    assert_eq!(request["tool_name"], "run_terminal_command");
    assert_eq!(
        request["logical_cwd"],
        "/remote/logical/workspace-not-on-host"
    );
    let request_sha256 = sha256_hex(request_bytes);
    let response = json_file(&json!({
        "schema_version": "external-tool-stdio-v2",
        "message_type": "tool.response",
        "seq": 0,
        "run_id": "run-external-cli-001",
        "trial_id": "trial-external-cli-001",
        "attempt_id": "attempt-0",
        "call_id": "call-external-cli-001",
        "tool_name": "run_terminal_command",
        "request_sha256": request_sha256,
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
        }
    }));
    let mut stdin = child.stdin.take().expect("CLI stdin");
    stdin.write_all(&response).expect("write protocol response");
    stdin.flush().expect("flush protocol response");
    drop(stdin);
    let mut trailing_stdout = String::new();
    stdout
        .read_to_string(&mut trailing_stdout)
        .expect("read trailing stdout");
    assert!(
        trailing_stdout.is_empty(),
        "external stdout contained non-protocol output: {trailing_stdout:?}"
    );
    let output = child.wait_with_output().expect("wait for external CLI");
    assert!(
        output.status.success(),
        "external CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "nano run status: artifact_published completed\n"
    );
    assert!(!host_sentinel.exists(), "command executed on host");
    assert!(artifact_dir.join("run.json").is_file());
}

#[test]
fn cli_external_stdio_v3_slow_output_commits_history_then_sends_final_exactly_once() {
    let root = tempfile::tempdir().expect("create test root");
    let contract_dir = root.path().join("contract");
    let artifact_dir = root.path().join("artifacts");
    let remote_workspace = PathBuf::from("/remote/live-v3-workspace");
    write_synthetic_contract(&contract_dir);
    fs::create_dir(&artifact_dir).expect("create artifact directory");
    let contract = LocalContract::load(&contract_dir).expect("load synthetic contract");
    let spec_path = root.path().join("run-spec.json");
    fs::write(
        &spec_path,
        json_file(&json!({
            "schema_version": "nano-run-spec-alpha-2",
            "run_id": "run-external-v3-001",
            "trial_id": "trial-external-v3-001",
            "attempt_id": "attempt-0",
            "task": {
                "id": "synthetic-external-v3",
                "digest": "f".repeat(64),
                "instruction": "Use the live v3 remote terminal.",
                "git_history_capability": no_history(
                    "Use the live v3 remote terminal.", &"f".repeat(64)
                )
            },
            "contract": {
                "id": CONTRACT_ID,
                "contract_set_sha256": contract.contract_set_sha256(),
                "profile_id": PROFILE_ID
            },
            "provider": {
                "kind": "scripted",
                "model": "synthetic-model",
                "max_turns": 4,
                "retry_max": 0
            },
            "workspace_dir": remote_workspace,
            "artifact_dir": artifact_dir,
            "agent_timeout_sec": 120
        })),
    )
    .expect("write run spec");
    let loaded_spec = RunSpec::load(&spec_path).expect("load run spec");
    let run_spec_sha256 = loaded_spec.sha256().expect("run spec hash");
    let hard = monotonic_ns() + 120_000_000_000;
    let cleanup_start = hard - 20_000_000_000;
    let runtime_final = cleanup_start - 15_000_000_000;
    let tool_settled = runtime_final - 30_000_000_000;
    let actor_done = tool_settled - 10_000_000_000;
    let deadline_bytes = json_file(&json!({
        "schema_version": "nano-run-deadline-receipt-v1",
        "run_id": "run-external-v3-001",
        "trial_id": "trial-external-v3-001",
        "attempt_id": "attempt-0",
        "run_spec_sha256": run_spec_sha256,
        "deadline": {
            "schema_version": "nano-run-deadline-v1",
            "hard_deadline_monotonic_ns": hard,
            "source": "test_host_phase",
            "agent_timeout_ms": 120_000
        },
        "reserves": {
            "cleanup_ms": 20_000,
            "terminalization_ms": 15_000,
            "provider_send_ms": 30_000,
            "process_settlement_ms": 10_000
        },
        "cutoffs": {
            "actor_done_monotonic_ns": actor_done,
            "tool_settled_monotonic_ns": tool_settled,
            "last_send_monotonic_ns": runtime_final,
            "runtime_final_monotonic_ns": runtime_final,
            "cleanup_start_monotonic_ns": cleanup_start,
            "hard_deadline_monotonic_ns": hard
        }
    }));
    let deadline_sha256 = sha256_hex(&deadline_bytes);
    fs::write(artifact_dir.join("deadline.json"), &deadline_bytes).expect("write deadline receipt");
    let script_path = root.path().join("script.json");
    fs::write(
        &script_path,
        json_file(&json!({
            "schema_version": "scripted-provider-v1",
            "steps": [
                {
                    "type": "completed",
                    "response": {
                        "response_id": "response-v3-tool",
                        "model": "synthetic-model",
                        "output": [{
                            "type": "function_call",
                            "call_id": "call-external-v3-001",
                            "name": "run_terminal_command",
                            "arguments_json": serde_json::to_string(&json!({
                                "command": "printf live-v3",
                                "description": "live v3 dispatch",
                                "timeout": 1000,
                                "background": false
                            })).expect("arguments")
                        }],
                        "usage": null
                    }
                },
                {
                    "type": "completed",
                    "response": {
                        "response_id": "response-v3-final",
                        "model": "synthetic-model",
                        "output": [{
                            "type": "assistant_message",
                            "text": "live v3 complete"
                        }],
                        "usage": null
                    }
                }
            ]
        })),
    )
    .expect("write provider script");

    let hard_text = hard.to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .args([
            "run",
            "--spec",
            spec_path.to_str().expect("UTF-8 spec path"),
            "--contract-dir",
            contract_dir.to_str().expect("UTF-8 contract path"),
            "--provider",
            &format!(
                "scripted:{}",
                script_path.to_str().expect("UTF-8 script path")
            ),
            "--executor",
            "external-stdio",
            "--deadline-monotonic-ns",
            &hard_text,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live v3 CLI");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("CLI stdout"));
    let mut request_line = String::new();
    stdout
        .read_line(&mut request_line)
        .expect("read v3 request");
    let request_bytes = request_line
        .strip_suffix('\n')
        .expect("v3 request LF")
        .as_bytes();
    let request: Value = serde_json::from_slice(request_bytes).expect("v3 request JSON");
    assert_eq!(request["schema_version"], "external-tool-stdio-v3");
    assert_eq!(request["operation_timeout_ms"], 1_000);
    assert!(request.get("timeout_ms").is_none());
    assert_eq!(request["actor_done_monotonic_ns"], actor_done);
    assert_eq!(request["tool_settled_monotonic_ns"], tool_settled);
    assert_eq!(request["hard_deadline_monotonic_ns"], hard);
    assert_eq!(request["deadline_receipt_sha256"], deadline_sha256);
    let response = json_file(&json!({
        "schema_version": "external-tool-stdio-v3",
        "message_type": "tool.response",
        "seq": 0,
        "run_id": "run-external-v3-001",
        "trial_id": "trial-external-v3-001",
        "attempt_id": "attempt-0",
        "call_id": "call-external-v3-001",
        "tool_name": "run_terminal_command",
        "request_sha256": sha256_hex(request_bytes),
        "settlement": "completed",
        "result": {
            "return_code": 0,
            "timed_out": false,
            "stdout_base64": "c2xvdy1vdXRwdXQ=",
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
            "actor_receipt": completed_actor_receipt(
                request["actor_done_monotonic_ns"]
                    .as_u64()
                    .expect("actor_done monotonic nanoseconds")
            )
        }
    }));
    let mut stdin = child.stdin.take().expect("CLI stdin");
    let split = response.len() / 2;
    stdin
        .write_all(&response[..split])
        .expect("write partial v3 response");
    stdin.flush().expect("flush v3 response");
    thread::sleep(Duration::from_millis(50));
    stdin
        .write_all(&response[split..])
        .expect("finish slow v3 response");
    stdin.flush().expect("flush completed v3 response");
    drop(stdin);
    let mut trailing_stdout = String::new();
    stdout
        .read_to_string(&mut trailing_stdout)
        .expect("read trailing stdout");
    assert!(trailing_stdout.is_empty());
    let output = child.wait_with_output().expect("wait for live v3 CLI");
    assert!(
        output.status.success(),
        "live v3 CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run: Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("run.json")).expect("read run record"))
            .expect("run JSON");
    let events = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .collect::<Vec<_>>();
    let started = &parsed[0];
    let tool_completed_index = parsed
        .iter()
        .position(|event| event["type"] == "tool.completed")
        .expect("tool history commit event");
    let final_sends = parsed[tool_completed_index + 1..]
        .iter()
        .filter(|event| event["type"] == "provider.requested")
        .count();
    assert_eq!(run["deadline_receipt_sha256"], deadline_sha256);
    assert_eq!(started["data"]["deadline_receipt_sha256"], deadline_sha256);
    assert_eq!(
        parsed[tool_completed_index]["data"]["output"],
        "exit: 0\nslow-output"
    );
    assert_eq!(
        final_sends, 1,
        "final provider send must happen exactly once"
    );
    assert_eq!(
        parsed
            .iter()
            .filter(|event| event["type"] == "provider.requested")
            .count(),
        2
    );
}

#[derive(Clone, Copy)]
enum StalledBridge {
    NoResponse,
    PartialFrame,
    LateResponse,
    CooperativeCancel,
}

impl StalledBridge {
    fn terminal_code(self) -> &'static str {
        match self {
            Self::NoResponse | Self::PartialFrame | Self::LateResponse => {
                "external_stdio_response_timeout"
            }
            Self::CooperativeCancel => "cooperative_cancelled",
        }
    }

    fn terminal_status(self) -> &'static str {
        match self {
            Self::NoResponse | Self::PartialFrame | Self::LateResponse => "deadline_failure",
            Self::CooperativeCancel => "cancelled",
        }
    }

    fn terminal_phase(self) -> &'static str {
        match self {
            Self::NoResponse | Self::PartialFrame | Self::LateResponse => "deadline",
            Self::CooperativeCancel => "cancellation",
        }
    }
}

fn assert_external_cli_exits_after_deadline(bridge: StalledBridge) {
    const AGENT_TIMEOUT_SEC: u64 = 3;
    const EXIT_LIMIT: Duration = Duration::from_millis(2_750);
    const LATE_RESPONSE_DELAY: Duration = Duration::from_millis(3_250);

    let root = tempfile::tempdir().expect("create deadline test root");
    let contract_dir = root.path().join("contract");
    let artifact_dir = root.path().join("artifacts");
    let remote_workspace = PathBuf::from("/remote/deadline/workspace-not-on-host");
    let host_sentinel = root.path().join("must-not-exist");
    write_synthetic_contract(&contract_dir);
    let profile_path = contract_dir.join("agent-profile.json");
    let mut profile: Value =
        serde_json::from_slice(&fs::read(&profile_path).expect("read profile"))
            .expect("profile JSON");
    profile["deadlines"]["absolute_run_wall_cap_sec"] = json!(4);
    profile["deadlines"]["terminalization_reserve_sec"] = json!(1);
    profile["deadlines"]["min_provider_send_window_sec"] = json!(1);
    profile["tools"]["terminal_default_timeout_ms"] = json!(1_000);
    profile["tools"]["terminal_max_timeout_ms"] = json!(1_000);
    let effective_path = contract_dir.join("effective-contract.json");
    let mut effective: Value =
        serde_json::from_slice(&fs::read(&effective_path).expect("read effective contract"))
            .expect("effective contract JSON");
    effective["tools"][0]["input_schema"]["properties"]["timeout"]["default"] = json!(1_000);
    effective["tools"][0]["input_schema"]["properties"]["timeout"]["maximum"] = json!(1_000);
    effective["tools"][0]["description"] = json!(
        effective["tools"][0]["description"]
            .as_str()
            .expect("terminal description")
            .replace("default to 120000 ms", "default to 1000 ms")
            .replace("at most 600000 ms", "at most 1000 ms")
    );
    let effective_bytes = json_file(&effective);
    profile["contract_bindings"]["effective_contract_file_sha256"] =
        json!(sha256_hex(&effective_bytes));
    profile["contract_bindings"]["ordered_tools_value_sha256"] = json!(sha256_hex(
        &serde_json::to_vec(effective.get("tools").expect("tools")).expect("serialize tools")
    ));
    fs::write(effective_path, effective_bytes).expect("write bounded effective contract");
    fs::write(&profile_path, json_file(&profile)).expect("write bounded profile");
    let contract = LocalContract::load(&contract_dir).expect("load bounded contract");
    let spec_path = root.path().join("run-spec.json");
    fs::write(
        &spec_path,
        json_file(&json!({
            "schema_version": "nano-run-spec-alpha-2",
            "run_id": "run-external-deadline-001",
            "trial_id": "trial-external-deadline-001",
            "attempt_id": "attempt-0",
            "task": {
                "id": "synthetic-external-deadline",
                "digest": "f".repeat(64),
                "instruction": "Use the remote terminal once.",
                "git_history_capability": no_history(
                    "Use the remote terminal once.", &"f".repeat(64)
                )
            },
            "contract": {
                "id": CONTRACT_ID,
                "contract_set_sha256": contract.contract_set_sha256(),
                "profile_id": PROFILE_ID
            },
            "provider": {
                "kind": "scripted",
                "model": "synthetic-model",
                "max_turns": 2,
                "retry_max": 0
            },
            "workspace_dir": remote_workspace,
            "artifact_dir": artifact_dir,
            "agent_timeout_sec": AGENT_TIMEOUT_SEC
        })),
    )
    .expect("write deadline RunSpec");
    let command = format!("touch {}", host_sentinel.display());
    let script_path = root.path().join("script.json");
    fs::write(
        &script_path,
        json_file(&json!({
            "schema_version": "scripted-provider-v1",
            "steps": [{
                "type": "completed",
                "response": {
                    "response_id": "response-external-deadline",
                    "model": "synthetic-model",
                    "output": [{
                        "type": "function_call",
                        "call_id": "call-external-deadline-001",
                        "name": "run_terminal_command",
                        "arguments_json": serde_json::to_string(&json!({
                            "command": command,
                            "description": "prove bounded external input",
                            "timeout": 1000,
                            "background": false
                        })).expect("arguments")
                    }],
                    "usage": null
                }
            }]
        })),
    )
    .expect("write deadline provider");

    let mut child = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .args([
            "run",
            "--spec",
            spec_path.to_str().expect("UTF-8 spec path"),
            "--contract-dir",
            contract_dir.to_str().expect("UTF-8 contract path"),
            "--provider",
            &format!(
                "scripted:{}",
                script_path.to_str().expect("UTF-8 script path")
            ),
            "--executor",
            "external-stdio",
            "--deadline-mode",
            "legacy-external-stdio-v2",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn deadline CLI");
    let mut stdin = Some(child.stdin.take().expect("CLI stdin"));
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("CLI stdout"));
    let mut request_line = String::new();
    stdout
        .read_line(&mut request_line)
        .expect("read deadline request");
    let request_bytes = request_line
        .strip_suffix('\n')
        .expect("request LF")
        .as_bytes();
    let request: Value = serde_json::from_slice(request_bytes).expect("request JSON");
    assert_eq!(request["logical_cwd"], remote_workspace.to_str().unwrap());
    let arguments: Value = serde_json::from_str(
        request["arguments_json"]
            .as_str()
            .expect("arguments JSON string"),
    )
    .expect("arguments JSON");
    assert_eq!(arguments["command"], command);

    let late_writer = match bridge {
        StalledBridge::NoResponse => None,
        StalledBridge::PartialFrame => {
            stdin
                .as_mut()
                .expect("open CLI stdin")
                .write_all(b"{\"schema_version\":\"external-tool-stdio-v2\"")
                .expect("write partial frame");
            stdin
                .as_mut()
                .expect("open CLI stdin")
                .flush()
                .expect("flush partial frame");
            None
        }
        StalledBridge::LateResponse => {
            let response = json_file(&json!({
                "schema_version": "external-tool-stdio-v2",
                "message_type": "tool.response",
                "seq": 0,
                "run_id": "run-external-deadline-001",
                "trial_id": "trial-external-deadline-001",
                "attempt_id": "attempt-0",
                "call_id": "call-external-deadline-001",
                "tool_name": "run_terminal_command",
                "request_sha256": sha256_hex(request_bytes),
                "return_code": 0,
                "timed_out": false,
                "stdout_base64": "",
                "stderr_base64": "",
                "stdout_truncated": false,
                "stderr_truncated": false,
                "cleanup": {
                    "attempted": true,
                    "term_sent": false,
                    "kill_sent": false,
                    "verified": true
                },
                "census": {
                    "verified": true,
                    "owned_processes_alive": 0
                }
            }));
            let mut late_stdin = stdin.take().expect("open CLI stdin");
            Some(thread::spawn(move || {
                thread::sleep(LATE_RESPONSE_DELAY);
                let _ = late_stdin.write_all(&response);
                let _ = late_stdin.flush();
            }))
        }
        StalledBridge::CooperativeCancel => {
            let process_id = child.id();
            Some(thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                let _ = Command::new("kill")
                    .args(["-TERM", &process_id.to_string()])
                    .status();
            }))
        }
    };

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll deadline CLI") {
            break status;
        }
        if started.elapsed() >= EXIT_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "external CLI required forced termination after {:?}",
                started.elapsed()
            );
        }
        thread::sleep(Duration::from_millis(10));
    };
    let elapsed = started.elapsed();
    drop(stdin);
    if let Some(writer) = late_writer {
        writer.join().expect("late writer");
    }
    let mut trailing_stdout = String::new();
    stdout
        .read_to_string(&mut trailing_stdout)
        .expect("read trailing protocol output");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("CLI stderr")
        .read_to_string(&mut stderr)
        .expect("read CLI stderr");

    assert!(!status.success(), "stalled bridge unexpectedly settled");
    assert!(
        elapsed < EXIT_LIMIT,
        "deadline exit exceeded strict margin: {elapsed:?}"
    );
    assert!(trailing_stdout.is_empty(), "non-protocol stdout emitted");
    assert_eq!(
        stderr,
        format!("nano run failed: {}\n", bridge.terminal_code())
    );
    let events = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    assert!(events.contains("\"type\":\"tool.registered\""));
    assert!(events.contains("\"type\":\"tool.dispatched\""));
    assert!(events.contains("\"type\":\"tool.failed\""));
    assert!(events.contains("\"type\":\"run.failed\""));
    assert!(!events.contains("\"type\":\"tool.completed\""));
    let record: Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run.json")).expect("read bridge failure record"),
    )
    .expect("parse bridge failure record");
    assert_eq!(record["schema_version"], "nano-run-record-v2");
    assert_eq!(record["terminal_status"], bridge.terminal_status());
    assert_eq!(record["terminal_phase"], bridge.terminal_phase());
    assert_eq!(record["terminal_code"], bridge.terminal_code());
    assert_eq!(record["provider_call_coverage"]["requested"], 1);
    assert_eq!(record["provider_call_coverage"]["completed"], 1);
    assert_eq!(record["provider_call_coverage"]["failed"], 0);
    assert_eq!(record["provider_call_coverage"]["in_flight"], 0);
    assert_eq!(record["provider_call_coverage"]["usage_present"], 0);
    assert_eq!(record["provider_call_coverage"]["usage_absent"], 1);
    assert_eq!(record["provider_call_coverage"]["state"], "partial");
    assert!(!host_sentinel.exists(), "command executed on host");
}

#[test]
fn cli_external_stdio_no_response_open_pipe_exits_after_deadline() {
    assert_external_cli_exits_after_deadline(StalledBridge::NoResponse);
}

#[test]
fn cli_external_stdio_partial_frame_open_pipe_exits_after_deadline() {
    assert_external_cli_exits_after_deadline(StalledBridge::PartialFrame);
}

#[test]
fn cli_external_stdio_late_response_exits_before_response_arrives() {
    assert_external_cli_exits_after_deadline(StalledBridge::LateResponse);
}

#[cfg(unix)]
#[test]
fn cli_sigterm_cooperatively_finalizes_dispatched_tool() {
    assert_external_cli_exits_after_deadline(StalledBridge::CooperativeCancel);
}

#[test]
fn provider_failure_is_settled_without_any_tool_dispatch() {
    let (_root, artifact_dir, output) =
        run_scripted_fixture(4, json!([{"type": "failure", "code": "scripted_failure"}]));
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(artifact_dir.join("events.jsonl"))
            .expect("read failure events")
            .lines()
            .map(|line| {
                serde_json::from_str::<Value>(line).expect("event")["type"]
                    .as_str()
                    .expect("event type")
                    .to_owned()
            })
            .collect::<Vec<_>>(),
        [
            "run.started",
            "provider.requested",
            "provider.failed",
            "run.failed"
        ]
    );
    let record: Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run.json")).expect("read failure record"),
    )
    .expect("parse failure record");
    assert_eq!(record["terminal_status"], "provider_failure");
    assert_eq!(record["terminal_code"], "scripted_failure");
}

#[test]
fn provider_send_cutoff_finalizes_before_requesting() {
    let root = tempfile::tempdir().expect("create cutoff root");
    let contract_dir = root.path().join("contract");
    let workspace_dir = root.path().join("workspace");
    let artifact_dir = root.path().join("artifacts");
    fs::create_dir(&workspace_dir).expect("create workspace");
    write_synthetic_contract(&contract_dir);
    let profile_path = contract_dir.join("agent-profile.json");
    let mut profile: Value =
        serde_json::from_slice(&fs::read(&profile_path).expect("profile")).expect("profile JSON");
    profile["deadlines"]["min_provider_send_window_sec"] = json!(50);
    fs::write(&profile_path, json_file(&profile)).expect("write cutoff profile");
    let contract = LocalContract::load(&contract_dir).expect("load cutoff contract");
    let spec_path = root.path().join("run-spec.json");
    fs::write(
        &spec_path,
        json_file(&json!({
            "schema_version": "nano-run-spec-alpha-2",
            "run_id": "run-cutoff-001",
            "trial_id": "trial-cutoff-001",
            "attempt_id": "attempt-0",
            "task": {
                "id": "synthetic-cutoff",
                "digest": "9".repeat(64),
                "instruction": "Do not start too late.",
                "git_history_capability": no_history(
                    "Do not start too late.", &"9".repeat(64)
                )
            },
            "contract": {
                "id": CONTRACT_ID,
                "contract_set_sha256": contract.contract_set_sha256(),
                "profile_id": PROFILE_ID
            },
            "provider": {
                "kind": "scripted",
                "model": "synthetic-model",
                "max_turns": 1,
                "retry_max": 0
            },
            "workspace_dir": workspace_dir,
            "artifact_dir": artifact_dir,
            "agent_timeout_sec": 60
        })),
    )
    .expect("write cutoff spec");
    let script_path = root.path().join("script.json");
    fs::write(
        &script_path,
        json_file(&json!({
            "schema_version": "scripted-provider-v1",
            "steps": [{
                "type": "completed",
                "response": {
                    "response_id": "must-not-be-requested",
                    "model": "synthetic-model",
                    "output": [{"type": "assistant_message", "text": "late"}],
                    "usage": null
                }
            }]
        })),
    )
    .expect("write cutoff provider");
    let output = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .args([
            "run",
            "--spec",
            spec_path.to_str().expect("spec"),
            "--contract-dir",
            contract_dir.to_str().expect("contract"),
            "--provider",
            &format!("scripted:{}", script_path.to_str().expect("script")),
        ])
        .output()
        .expect("run cutoff CLI");
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "nano run failed: provider_send_window_exhausted\n"
    );
    let events = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("events");
    assert!(!events.contains("\"type\":\"provider.requested\""));
    assert!(events.contains("\"type\":\"run.failed\""));
    let record: Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("run.json")).expect("record"))
            .expect("record JSON");
    assert_eq!(record["terminal_status"], "deadline_failure");
    assert_eq!(record["terminal_phase"], "deadline");
    assert_eq!(record["provider_call_coverage"]["requested"], 0);
    assert_eq!(record["provider_call_coverage"]["in_flight"], 0);
    assert_eq!(record["provider_call_coverage"]["state"], "complete");
}

#[test]
fn unsupported_known_tool_settles_without_dispatch_then_recovers() {
    let (_root, artifact_dir, output) = run_scripted_fixture(
        4,
        json!([
            {
                "type": "completed",
                "response": {
                    "response_id": "response-unsupported",
                    "model": "synthetic-model",
                    "output": [{
                        "type": "function_call",
                        "call_id": "call-read-001",
                        "name": "read_file",
                        "arguments_json": "{}"
                    }],
                    "usage": null
                }
            },
            {
                "type": "completed",
                "response": {
                    "response_id": "response-recovered",
                    "model": "synthetic-model",
                    "output": [{
                        "type": "assistant_message",
                        "text": "recovered"
                    }],
                    "usage": null
                }
            }
        ]),
    );
    assert!(output.status.success());
    let events = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    assert!(!events.contains("\"type\":\"tool.dispatched\""));
    let completed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event"))
        .find(|event| event["type"] == "tool.completed")
        .expect("tool completion");
    assert_eq!(completed["data"]["call_id"], "call-read-001");
    assert_eq!(completed["data"]["execution_attempted"], false);
    assert_eq!(completed["data"]["output"], "unsupported_in_alpha");
}

#[test]
fn protected_denials_continue_through_legal_tool_to_scripted_final() {
    let (_root, artifact_dir, output) = run_scripted_fixture(
        4,
        json!([
            {
                "type": "completed",
                "response": {
                    "response_id": "response-protected",
                    "model": "synthetic-model",
                    "output": [
                        {
                            "type": "function_call",
                            "call_id": "call-protected-1",
                            "name": "run_terminal_command",
                            "arguments_json": "{\"command\":\"cat /logs/agent/private-token\",\"text\":\"secret-one\"}"
                        },
                        {
                            "type": "function_call",
                            "call_id": "call-protected-2",
                            "name": "run_terminal_command",
                            "arguments_json": "{\"command\":\"cat /proc/self/root/logs/verifier/reward.txt\",\"text\":\"secret-two\"}"
                        }
                    ],
                    "usage": null
                }
            },
            {
                "type": "completed",
                "response": {
                    "response_id": "response-legal",
                    "model": "synthetic-model",
                    "output": [{
                        "type": "function_call",
                        "call_id": "call-legal",
                        "name": "run_terminal_command",
                        "arguments_json": "{\"text\":\"legal-tool-output\"}"
                    }],
                    "usage": null
                }
            },
            {
                "type": "completed",
                "response": {
                    "response_id": "response-final",
                    "model": "synthetic-model",
                    "output": [{
                        "type": "assistant_message",
                        "text": "continued after permission denial"
                    }],
                    "usage": null
                }
            }
        ]),
    );
    assert!(
        output.status.success(),
        "scripted continuation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event"))
        .collect::<Vec<_>>();
    let denied = parsed
        .iter()
        .filter(|event| {
            event["type"] == "tool.completed"
                && matches!(
                    event["data"]["call_id"].as_str(),
                    Some("call-protected-1" | "call-protected-2")
                )
        })
        .collect::<Vec<_>>();
    assert_eq!(denied.len(), 2);
    for event in denied {
        assert_eq!(event["data"]["execution_attempted"], false);
        assert_eq!(event["data"]["outcome"], "rejected");
        assert_eq!(event["data"]["output"], "permission_denied");
        let output = event["data"]["output"].as_str().expect("denial output");
        assert!(!output.contains("/logs"));
        assert!(!output.contains("secret"));
    }
    let dispatched = parsed
        .iter()
        .filter(|event| event["type"] == "tool.dispatched")
        .collect::<Vec<_>>();
    assert_eq!(dispatched.len(), 1);
    assert_eq!(dispatched[0]["data"]["call_id"], "call-legal");
    let legal = parsed
        .iter()
        .find(|event| event["type"] == "tool.completed" && event["data"]["call_id"] == "call-legal")
        .expect("legal tool completion");
    assert_eq!(legal["data"]["execution_attempted"], true);
    assert_eq!(legal["data"]["outcome"], "succeeded");
    assert_eq!(legal["data"]["output"], "legal-tool-output");
    assert!(!parsed.iter().any(|event| event["type"] == "tool.failed"));
    assert!(
        parsed
            .iter()
            .any(|event| event["type"] == "assistant.final")
    );
    assert!(parsed.iter().any(|event| event["type"] == "run.completed"));

    let record: Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("run.json")).expect("read run record"))
            .expect("run record JSON");
    assert_eq!(record["terminal_status"], "success");
    assert_eq!(record["terminal_code"], "completed");
    assert_eq!(record["tool_call_count"], 3);
}

#[test]
fn max_turns_settles_after_the_first_completed_tool_turn_without_retry() {
    let (_root, artifact_dir, output) = run_scripted_fixture(
        1,
        json!([{
            "type": "completed",
            "response": {
                "response_id": "response-only",
                "model": "synthetic-model",
                "output": [{
                    "type": "function_call",
                    "call_id": "call-echo-limit",
                    "name": "run_terminal_command",
                    "arguments_json": "{\"text\":\"one-turn\"}"
                }],
                "usage": null
            }
        }]),
    );
    assert!(!output.status.success());
    let record: Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run.json")).expect("read max-turn record"),
    )
    .expect("parse max-turn record");
    assert_eq!(record["terminal_status"], "provider_failure");
    assert_eq!(record["terminal_code"], "provider_max_turns_exceeded");
    assert_eq!(record["provider_turn_count"], 1);
    assert_eq!(record["tool_call_count"], 1);
}

#[test]
#[ignore = "requires an explicit ignored local review directory"]
fn reviewed_local_contract_runs_final_only_without_tracking_fixture_bytes() {
    let contract_dir = PathBuf::from(
        std::env::var_os("NANO_REVIEW_CONTRACT_DIR")
            .expect("set NANO_REVIEW_CONTRACT_DIR explicitly"),
    );
    let contract = LocalContract::load(&contract_dir).expect("load reviewed local contract");
    let root = tempfile::tempdir().expect("create manual run root");
    let workspace_dir = root.path().join("workspace");
    let artifact_dir = root.path().join("artifacts");
    fs::create_dir(&workspace_dir).expect("create workspace");
    let spec_path = root.path().join("run-spec.json");
    fs::write(
        &spec_path,
        json_file(&json!({
            "schema_version": "nano-run-spec-alpha-2",
            "run_id": "run-reviewed-local",
            "trial_id": "trial-reviewed-local",
            "attempt_id": "attempt-0",
            "task": {
                "id": "reviewed-local-final-only",
                "digest": "c".repeat(64),
                "instruction": "Return a synthetic final response.",
                "git_history_capability": no_history(
                    "Return a synthetic final response.", &"c".repeat(64)
                )
            },
            "contract": {
                "id": contract.effective().contract_id,
                "contract_set_sha256": contract.contract_set_sha256(),
                "profile_id": contract.profile().profile_id
            },
            "provider": {
                "kind": "scripted",
                "model": contract.profile().provider.model,
                "max_turns": 1,
                "retry_max": 0
            },
            "workspace_dir": workspace_dir,
            "artifact_dir": artifact_dir,
            "agent_timeout_sec": 60
        })),
    )
    .expect("write reviewed run spec");
    let script_path = root.path().join("script.json");
    fs::write(
        &script_path,
        json_file(&json!({
            "schema_version": "scripted-provider-v1",
            "steps": [{
                "type": "completed",
                "response": {
                    "response_id": "response-reviewed-local",
                    "model": contract.profile().provider.model,
                    "output": [{
                        "type": "assistant_message",
                        "text": "reviewed contract loaded"
                    }],
                    "usage": null
                }
            }]
        })),
    )
    .expect("write reviewed provider script");
    let output = Command::new(env!("CARGO_BIN_EXE_nano-cli"))
        .args([
            "run",
            "--spec",
            spec_path.to_str().expect("UTF-8 spec path"),
            "--contract-dir",
            contract_dir.to_str().expect("UTF-8 contract path"),
            "--provider",
            &format!(
                "scripted:{}",
                script_path.to_str().expect("UTF-8 script path")
            ),
        ])
        .output()
        .expect("run reviewed contract CLI");
    assert!(
        output.status.success(),
        "reviewed contract run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record: Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run.json")).expect("read reviewed run"),
    )
    .expect("parse reviewed run");
    assert_eq!(record["terminal_status"], "success");
    assert_eq!(record["contract_id"], "nano-v1");
    assert_eq!(record["tool_call_count"], 0);
}
