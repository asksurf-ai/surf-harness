use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use nano_types::event::{
    AssistantFinal, Event, EventBody, ProviderCallCoverage, ProviderCompleted, ProviderRequested,
    RunCompleted, RunRecord, RunStarted, TerminalStatus, UsageState, UsageTotals, EVENT_SCHEMA,
    RUN_RECORD_SCHEMA,
};
use nano_types::run_spec::RunSpec;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const INPUT_SCHEMA: &str = "nano-tb21-historical-v2-deadline-synthetic-input-v1";
const INPUT_SCOPE: &str = "synthetic_historical_v2_deadline_wire_only";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    schema_version: String,
    scope: String,
    run_spec: RunSpec,
    timeline: Timeline,
    usage: Usage,
    #[serde(rename = "deadline")]
    _deadline: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timeline {
    run_started_ms: u64,
    provider_requested_ms: u64,
    provider_completed_ms: u64,
    assistant_final_ms: u64,
    run_completed_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Usage {
    input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    provider_cost_ticks: u64,
}

fn event(spec: &RunSpec, seq: u64, elapsed_ms: u64, body: EventBody) -> Event {
    Event {
        schema_version: EVENT_SCHEMA.to_owned(),
        run_id: spec.run_id.clone(),
        trial_id: spec.trial_id.clone(),
        attempt_id: spec.attempt_id.clone(),
        seq,
        elapsed_ms,
        body,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args_os().collect::<Vec<_>>();
    if arguments.len() != 5 {
        return Err("usage: exporter <input> <run-spec-sha256> <deadline-sha256> <dest>".into());
    }
    let input_path = PathBuf::from(&arguments[1]);
    let expected_spec_sha256 = arguments[2].to_string_lossy().into_owned();
    let deadline_sha256 = arguments[3].to_string_lossy().into_owned();
    let destination = PathBuf::from(&arguments[4]);
    let input: Input = serde_json::from_slice(&fs::read(input_path)?)?;
    if input.schema_version != INPUT_SCHEMA || input.scope != INPUT_SCOPE {
        return Err("synthetic input identity mismatch".into());
    }
    input.run_spec.validate()?;
    let run_spec_sha256 = input.run_spec.sha256()?;
    if run_spec_sha256 != expected_spec_sha256 || deadline_sha256.len() != 64 {
        return Err("derived digest mismatch".into());
    }

    let usage = json!({
        "input_tokens": input.usage.input_tokens,
        "input_tokens_details": {"cached_tokens": input.usage.cached_input_tokens},
        "output_tokens": input.usage.output_tokens,
        "cost_in_usd_ticks": input.usage.provider_cost_ticks,
        "provider_cost_ticks": input.usage.provider_cost_ticks,
    });
    let events = vec![
        event(
            &input.run_spec,
            0,
            input.timeline.run_started_ms,
            EventBody::RunStarted(RunStarted {
                task_id: input.run_spec.task.id.clone(),
                contract_id: input.run_spec.contract.id.clone(),
                profile_id: input.run_spec.contract.profile_id.clone(),
                contract_set_sha256: input.run_spec.contract.contract_set_sha256.clone(),
                model: input.run_spec.provider.model.clone(),
                run_spec_sha256: run_spec_sha256.clone(),
                deadline_receipt_sha256: Some(deadline_sha256.clone()),
                media_history_policy_version: None,
                media_history_policy_sha256: None,
            }),
        ),
        event(
            &input.run_spec,
            1,
            input.timeline.provider_requested_ms,
            EventBody::ProviderRequested(ProviderRequested {
                turn_index: 0,
                history_item_count: 2,
                tool_count: 0,
                function_output_call_ids: Vec::new(),
                media_history_receipt: None,
            }),
        ),
        event(
            &input.run_spec,
            2,
            input.timeline.provider_completed_ms,
            EventBody::ProviderCompleted(ProviderCompleted {
                turn_index: 0,
                response_id: "synthetic-response-0".to_owned(),
                model: input.run_spec.provider.model.clone(),
                call_ids: Vec::new(),
                has_final_text: true,
                usage: Some(usage),
            }),
        ),
        event(
            &input.run_spec,
            3,
            input.timeline.assistant_final_ms,
            EventBody::AssistantFinal(AssistantFinal {
                text: "synthetic historical v2 deadline fixture complete".to_owned(),
            }),
        ),
        event(
            &input.run_spec,
            4,
            input.timeline.run_completed_ms,
            EventBody::RunCompleted(RunCompleted {
                code: "completed".to_owned(),
            }),
        ),
    ];
    let mut event_bytes = Vec::new();
    for value in &events {
        value
            .validate()
            .map_err(|error| format!("event validation failed: {}", error.code()))?;
        event_bytes.extend(serde_json::to_vec(value)?);
        event_bytes.push(b'\n');
    }

    let record = RunRecord {
        schema_version: RUN_RECORD_SCHEMA.to_owned(),
        run_id: input.run_spec.run_id,
        trial_id: input.run_spec.trial_id,
        attempt_id: input.run_spec.attempt_id,
        run_spec_sha256,
        deadline_receipt_sha256: Some(deadline_sha256),
        contract_id: input.run_spec.contract.id,
        contract_set_sha256: input.run_spec.contract.contract_set_sha256,
        profile_id: input.run_spec.contract.profile_id,
        terminal_status: TerminalStatus::Success,
        terminal_phase: None,
        terminal_code: "completed".to_owned(),
        final_event_seq: 4,
        provider_turn_count: 1,
        tool_call_count: 0,
        provider_call_coverage: ProviderCallCoverage {
            requested: 1,
            completed: 1,
            failed: 0,
            in_flight: 0,
            usage_present: 1,
            usage_absent: 0,
            usage_covered: 1,
            cost_present: 1,
            cost_absent: 0,
            state: UsageState::Complete,
        },
        usage_totals: UsageTotals {
            input_tokens: Some(input.usage.input_tokens),
            cached_input_tokens: Some(input.usage.cached_input_tokens),
            output_tokens: Some(input.usage.output_tokens),
            provider_cost_ticks: Some(input.usage.provider_cost_ticks),
        },
        start_elapsed_ms: input.timeline.run_started_ms,
        end_elapsed_ms: input.timeline.run_completed_ms,
        events_sha256: format!("{:x}", Sha256::digest(&event_bytes)),
    };
    record
        .validate()
        .map_err(|error| format!("run record validation failed: {}", error.code()))?;

    let runtime = destination.join("runtime");
    fs::create_dir_all(&runtime)?;
    fs::write(runtime.join("events.jsonl"), event_bytes)?;
    let mut record_bytes = serde_json::to_vec(&record)?;
    record_bytes.push(b'\n');
    fs::write(runtime.join("run.json"), record_bytes)?;
    Ok(())
}
