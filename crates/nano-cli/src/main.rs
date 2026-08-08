//! Explicit-path composition root for scripted and live agent runs.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use nano_provider_xai::{ScriptedProvider, XaiProvider, XaiProviderSettings};
use nano_runtime::{
    CompletionReviewPolicy, DeadlineContext, EchoExecutor, ExternalStdioDeadlineEnvelope,
    ExternalStdioExecutor, TerminalExecutor, run_agent, run_agent_with_deadline_and_review,
};
use nano_types::contract::{LocalContract, TOOL_ORDER};
use nano_types::event::{EVENT_SCHEMA, RUN_RECORD_SCHEMA};
use nano_types::external_tool::EXTERNAL_TOOL_STDIO_SCHEMA;
use nano_types::run_spec::{ProviderKind, RUN_SPEC_SCHEMA, RunSpec};

const CAPABILITIES_SCHEMA: &str = "nano-cli-capabilities-v2";

#[tokio::main]
async fn main() -> ExitCode {
    match command().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

async fn command() -> Result<(), CliError> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["capabilities"] {
        println!("{}", capability_manifest());
        return Ok(());
    }
    if arguments.first().map(String::as_str) == Some("validate-contract") {
        return validate_contract_command(&arguments);
    }
    let parsed = RunArguments::parse(&arguments)?;
    let spec = RunSpec::load(&parsed.spec).map_err(|_| CliError::new("run_spec_invalid"))?;
    let contract = load_contract(&parsed.contract_dir)?;
    let deadline_context = parsed
        .deadline_monotonic_ns
        .map(|hard_deadline| DeadlineContext::load(&spec, contract.profile(), hard_deadline))
        .transpose()
        .map_err(|error| CliError::new(error.code()))?;
    let external_mode = parsed.executor == ExecutorSelector::ExternalStdio;
    if parsed.legacy_external_stdio_v2 && (!external_mode || deadline_context.is_some()) {
        return Err(CliError::new("deadline_mode_mismatch"));
    }
    if external_mode && deadline_context.is_none() && !parsed.legacy_external_stdio_v2 {
        return Err(CliError::new("deadline_contract_unavailable"));
    }
    if parsed.completion_review != CompletionReviewPolicy::Disabled && deadline_context.is_none() {
        return Err(CliError::new("completion_review_requires_deadline"));
    }
    let completion_review = parsed.completion_review;
    let run = match (parsed.provider, parsed.executor) {
        (ProviderSelector::Scripted(script), ExecutorSelector::Default) => {
            if spec.provider.kind != ProviderKind::Scripted {
                return Err(CliError::new("provider_mode_mismatch"));
            }
            let mut provider =
                ScriptedProvider::load(&script).map_err(|error| CliError::new(error.code()))?;
            let mut executor = EchoExecutor::new("run_terminal_command");
            match deadline_context.as_ref() {
                Some(deadline) => {
                    run_agent_with_deadline_and_review(
                        &spec,
                        &contract,
                        &mut provider,
                        &mut executor,
                        deadline,
                        completion_review,
                    )
                    .await
                }
                None => run_agent(&spec, &contract, &mut provider, &mut executor).await,
            }
        }
        (ProviderSelector::Scripted(script), ExecutorSelector::ExternalStdio) => {
            if spec.provider.kind != ProviderKind::Scripted {
                return Err(CliError::new("provider_mode_mismatch"));
            }
            let mut provider =
                ScriptedProvider::load(&script).map_err(|error| CliError::new(error.code()))?;
            match deadline_context.as_ref() {
                Some(deadline) => {
                    let envelope = ExternalStdioDeadlineEnvelope::from_context(deadline)
                        .map_err(|error| CliError::new(error.code()))?;
                    let mut executor = ExternalStdioExecutor::from_process_stdio_v3(
                        &spec,
                        contract.profile(),
                        envelope,
                    )
                    .map_err(|error| CliError::new(error.code()))?;
                    run_agent_with_deadline_and_review(
                        &spec,
                        &contract,
                        &mut provider,
                        &mut executor,
                        deadline,
                        completion_review,
                    )
                    .await
                }
                None => {
                    let mut executor =
                        ExternalStdioExecutor::from_process_stdio(&spec, contract.profile())
                            .map_err(|error| CliError::new(error.code()))?;
                    run_agent(&spec, &contract, &mut provider, &mut executor).await
                }
            }
        }
        (ProviderSelector::Xai, ExecutorSelector::Default) => {
            if spec.provider.kind != ProviderKind::Xai {
                return Err(CliError::new("provider_mode_mismatch"));
            }
            let mut provider = xai_provider(contract.profile())?;
            let mut executor = TerminalExecutor::from_profile(contract.profile());
            match deadline_context.as_ref() {
                Some(deadline) => {
                    run_agent_with_deadline_and_review(
                        &spec,
                        &contract,
                        &mut provider,
                        &mut executor,
                        deadline,
                        completion_review,
                    )
                    .await
                }
                None => run_agent(&spec, &contract, &mut provider, &mut executor).await,
            }
        }
        (ProviderSelector::Xai, ExecutorSelector::ExternalStdio) => {
            if spec.provider.kind != ProviderKind::Xai {
                return Err(CliError::new("provider_mode_mismatch"));
            }
            let mut provider = xai_provider(contract.profile())?;
            match deadline_context.as_ref() {
                Some(deadline) => {
                    let envelope = ExternalStdioDeadlineEnvelope::from_context(deadline)
                        .map_err(|error| CliError::new(error.code()))?;
                    let mut executor = ExternalStdioExecutor::from_process_stdio_v3(
                        &spec,
                        contract.profile(),
                        envelope,
                    )
                    .map_err(|error| CliError::new(error.code()))?;
                    run_agent_with_deadline_and_review(
                        &spec,
                        &contract,
                        &mut provider,
                        &mut executor,
                        deadline,
                        completion_review,
                    )
                    .await
                }
                None => {
                    let mut executor =
                        ExternalStdioExecutor::from_process_stdio(&spec, contract.profile())
                            .map_err(|error| CliError::new(error.code()))?;
                    run_agent(&spec, &contract, &mut provider, &mut executor).await
                }
            }
        }
    };
    let outcome = match run {
        Ok(outcome) => outcome,
        Err(error) => {
            if let Some(warning) = error.publication_warning() {
                print_publication_warning(warning);
            }
            return Err(CliError::owned(error.code()));
        }
    };
    if let Some(warning) = outcome.publication.warning_code() {
        print_publication_warning(warning);
    }
    if external_mode {
        eprintln!(
            "nano run status: artifact_published {}",
            outcome.record.terminal_code
        );
    } else {
        println!(
            "run {} {}",
            outcome.record.run_id, outcome.record.terminal_code
        );
    }
    Ok(())
}

fn validate_contract_command(arguments: &[String]) -> Result<(), CliError> {
    let parsed = ContractAdmissionArguments::parse(arguments)?;
    load_contract(&parsed.contract_dir)?;
    println!("{{\"schema_version\":\"runtime-profile-v1\"}}");
    Ok(())
}

fn load_contract(contract_dir: &PathBuf) -> Result<LocalContract, CliError> {
    LocalContract::load(contract_dir).map_err(|_| CliError::new("contract_invalid"))
}

fn embedded_hex(value: Option<&'static str>, length: usize) -> &'static str {
    value
        .filter(|value| {
            value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .unwrap_or("unbound")
}

fn capability_manifest() -> String {
    let source_tree_sha256 = embedded_hex(option_env!("NANO_SOURCE_TREE_SHA256"), 64);
    let git_head = embedded_hex(option_env!("NANO_BUILD_GIT_HEAD"), 40);
    let known_tools = TOOL_ORDER
        .iter()
        .map(|tool| format!("\"{tool}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        concat!(
            "{{\"schema_version\":\"{}\",",
            "\"binary_version\":\"{}\",",
            "\"source_tree_sha256\":\"{}\",",
            "\"git_head\":\"{}\",",
            "\"run_spec_schema\":\"{}\",",
            "\"event_schema\":\"{}\",",
            "\"run_record_schema\":\"{}\",",
            "\"external_tool_schema\":\"{}\",",
            "\"providers\":[\"scripted\",\"xai\"],",
            "\"executors\":[\"default\",\"external-stdio\"],",
            "\"provider_model_source\":\"contract-profile\",",
            "\"known_tools\":[{}],",
            "\"dispatchable_tools\":[",
            "\"run_terminal_command\",\"read_file\",\"search_replace\",",
            "\"write\",\"list_dir\",\"grep\",\"kill_terminal_command\",",
            "\"get_terminal_command_output\"]}}"
        ),
        CAPABILITIES_SCHEMA,
        env!("CARGO_PKG_VERSION"),
        source_tree_sha256,
        git_head,
        RUN_SPEC_SCHEMA,
        EVENT_SCHEMA,
        RUN_RECORD_SCHEMA,
        EXTERNAL_TOOL_STDIO_SCHEMA,
        known_tools,
    )
}

fn xai_provider(profile: &nano_types::contract::AgentProfile) -> Result<XaiProvider, CliError> {
    let api_key = env::var("XAI_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
        .ok_or_else(|| CliError::new("xai_api_key_missing"))?;
    let settings =
        XaiProviderSettings::from_profile(profile).map_err(|error| CliError::new(error.code()))?;
    XaiProvider::new(api_key, settings).map_err(|error| CliError::new(error.code()))
}

fn print_publication_warning(warning: &str) {
    eprintln!("{}", publication_warning_line(warning));
}

fn publication_warning_line(warning: &str) -> String {
    format!("nano run warning: published_durability_uncertain {warning}")
}

struct RunArguments {
    spec: PathBuf,
    contract_dir: PathBuf,
    provider: ProviderSelector,
    executor: ExecutorSelector,
    deadline_monotonic_ns: Option<u64>,
    legacy_external_stdio_v2: bool,
    completion_review: CompletionReviewPolicy,
}

enum ProviderSelector {
    Scripted(PathBuf),
    Xai,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecutorSelector {
    Default,
    ExternalStdio,
}

struct ContractAdmissionArguments {
    contract_dir: PathBuf,
}

impl ContractAdmissionArguments {
    fn parse(arguments: &[String]) -> Result<Self, CliError> {
        if arguments.first().map(String::as_str) != Some("validate-contract") {
            return Err(CliError::new("usage_invalid"));
        }
        let mut contract_dir = None;
        let mut index = 1;
        while index < arguments.len() {
            let flag = arguments
                .get(index)
                .map(String::as_str)
                .ok_or_else(|| CliError::new("usage_invalid"))?;
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| CliError::new("usage_invalid"))?;
            match flag {
                "--contract-dir" if contract_dir.is_none() => {
                    contract_dir = Some(PathBuf::from(value));
                }
                _ => return Err(CliError::new("usage_invalid")),
            }
            index += 2;
        }
        Ok(Self {
            contract_dir: contract_dir.ok_or_else(|| CliError::new("usage_invalid"))?,
        })
    }
}

impl RunArguments {
    fn parse(arguments: &[String]) -> Result<Self, CliError> {
        if arguments.first().map(String::as_str) != Some("run") {
            return Err(CliError::new("usage_invalid"));
        }
        let mut spec = None;
        let mut contract_dir = None;
        let mut provider = None;
        let mut executor = None;
        let mut deadline_monotonic_ns = None;
        let mut deadline_mode = None;
        let mut completion_review = None;
        let mut index = 1;
        while index < arguments.len() {
            let flag = arguments
                .get(index)
                .map(String::as_str)
                .ok_or_else(|| CliError::new("usage_invalid"))?;
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| CliError::new("usage_invalid"))?;
            match flag {
                "--spec" if spec.is_none() => spec = Some(PathBuf::from(value)),
                "--contract-dir" if contract_dir.is_none() => {
                    contract_dir = Some(PathBuf::from(value));
                }
                "--provider" if provider.is_none() => provider = Some(value.clone()),
                "--executor" if executor.is_none() => executor = Some(value.clone()),
                "--deadline-monotonic-ns" if deadline_monotonic_ns.is_none() => {
                    deadline_monotonic_ns = Some(
                        value
                            .parse::<u64>()
                            .ok()
                            .filter(|value| *value > 0)
                            .ok_or_else(|| CliError::new("deadline_argument_invalid"))?,
                    );
                }
                "--deadline-mode" if deadline_mode.is_none() => {
                    deadline_mode = Some(value.clone());
                }
                "--completion-review" if completion_review.is_none() => {
                    completion_review = Some(match value.as_str() {
                        "independent-falsification-v1" => {
                            CompletionReviewPolicy::IndependentFalsificationV1
                        }
                        "evidence-debt-v2" => CompletionReviewPolicy::EvidenceDebtV2,
                        "fresh-evidence-debt-v3" => CompletionReviewPolicy::FreshEvidenceDebtV3,
                        "fresh-checkpoint-v4" => CompletionReviewPolicy::FreshCheckpointV4,
                        "semantic-checkpoint-v6" => CompletionReviewPolicy::SemanticCheckpointV6,
                        "semantic-checkpoint-v7" => CompletionReviewPolicy::SemanticCheckpointV7,
                        "semantic-checkpoint-v8" => CompletionReviewPolicy::SemanticCheckpointV8,
                        _ => {
                            return Err(CliError::new("completion_review_policy_invalid"));
                        }
                    });
                }
                _ => return Err(CliError::new("usage_invalid")),
            }
            index += 2;
        }
        let provider = provider.ok_or_else(|| CliError::new("usage_invalid"))?;
        let provider = if provider == "xai" {
            ProviderSelector::Xai
        } else if let Some(path) = provider
            .strip_prefix("scripted:")
            .filter(|path| !path.is_empty())
        {
            ProviderSelector::Scripted(PathBuf::from(path))
        } else {
            return Err(CliError::new("provider_selector_invalid"));
        };
        Ok(Self {
            spec: spec.ok_or_else(|| CliError::new("usage_invalid"))?,
            contract_dir: contract_dir.ok_or_else(|| CliError::new("usage_invalid"))?,
            provider,
            deadline_monotonic_ns,
            completion_review: completion_review.unwrap_or_default(),
            legacy_external_stdio_v2: match deadline_mode.as_deref() {
                None => false,
                Some("legacy-external-stdio-v2") => true,
                Some(_) => return Err(CliError::new("deadline_mode_invalid")),
            },
            executor: match executor.as_deref() {
                None | Some("default") => ExecutorSelector::Default,
                Some("external-stdio") => ExecutorSelector::ExternalStdio,
                Some(_) => return Err(CliError::new("executor_selector_invalid")),
            },
        })
    }
}

#[derive(Debug)]
struct CliError {
    code: String,
}

impl CliError {
    fn new(code: &str) -> Self {
        Self {
            code: code.to_owned(),
        }
    }

    fn owned(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "nano run failed: {}", self.code)
    }
}

#[cfg(test)]
mod tests {
    use nano_runtime::CompletionReviewPolicy;

    use super::{ContractAdmissionArguments, ExecutorSelector, ProviderSelector, RunArguments};

    #[test]
    fn publication_warning_is_machine_stable_and_not_an_incomplete_error() {
        assert_eq!(
            super::publication_warning_line("artifact_directory_sync_failed"),
            "nano run warning: published_durability_uncertain artifact_directory_sync_failed"
        );
    }

    #[test]
    fn xai_selector_has_no_endpoint_or_key_argument() {
        let arguments = [
            "run",
            "--spec",
            "/tmp/run.json",
            "--contract-dir",
            "/tmp/contract",
            "--provider",
            "xai",
        ]
        .map(str::to_owned);
        let parsed = RunArguments::parse(&arguments).expect("parse xai selector");
        assert!(matches!(parsed.provider, ProviderSelector::Xai));
        assert!(matches!(parsed.executor, ExecutorSelector::Default));
    }

    #[test]
    fn run_rejects_contract_governance_arguments() {
        let arguments = [
            "run",
            "--spec",
            "/tmp/run.json",
            "--contract-dir",
            "/tmp/contract",
            "--provider",
            "xai",
            "--expected-contract-id",
            "obsolete",
        ]
        .map(str::to_owned);
        let error = RunArguments::parse(&arguments)
            .err()
            .expect("governance selector must fail");
        assert_eq!(error.code, "usage_invalid");
    }

    #[test]
    fn runtime_profile_admission_rejects_governance_arguments() {
        let arguments = [
            "validate-contract",
            "--contract-dir",
            "/tmp/contract",
            "--expected-contract-set-sha256",
            "obsolete",
        ]
        .map(str::to_owned);
        let error = ContractAdmissionArguments::parse(&arguments)
            .err()
            .expect("governance selector must fail");
        assert_eq!(error.code, "usage_invalid");
    }

    #[test]
    fn provider_and_external_executor_are_orthogonal() {
        let arguments = [
            "run",
            "--spec",
            "/tmp/run.json",
            "--contract-dir",
            "/tmp/contract",
            "--provider",
            "scripted:/tmp/script.json",
            "--executor",
            "external-stdio",
        ]
        .map(str::to_owned);
        let parsed = RunArguments::parse(&arguments).expect("parse external executor");
        assert!(matches!(parsed.provider, ProviderSelector::Scripted(_)));
        assert!(matches!(parsed.executor, ExecutorSelector::ExternalStdio));
    }

    #[test]
    fn absolute_deadline_argument_is_a_positive_u64() {
        let arguments = [
            "run",
            "--spec",
            "/tmp/run.json",
            "--contract-dir",
            "/tmp/contract",
            "--deadline-monotonic-ns",
            "130000000000",
            "--provider",
            "xai",
            "--executor",
            "external-stdio",
        ]
        .map(str::to_owned);
        let parsed = RunArguments::parse(&arguments).expect("parse absolute deadline");
        assert_eq!(parsed.deadline_monotonic_ns, Some(130_000_000_000));
        assert_eq!(parsed.completion_review, CompletionReviewPolicy::Disabled);

        for invalid in ["0", "-1", "18446744073709551616", "1.5"] {
            let mut invalid_arguments = arguments.clone();
            invalid_arguments[6] = invalid.to_owned();
            let error = RunArguments::parse(&invalid_arguments)
                .err()
                .expect("deadline must fail");
            assert_eq!(error.code, "deadline_argument_invalid");
        }
    }

    #[test]
    fn completion_review_policy_is_explicit_and_closed() {
        let arguments = [
            "run",
            "--spec",
            "/tmp/run.json",
            "--contract-dir",
            "/tmp/contract",
            "--deadline-monotonic-ns",
            "130000000000",
            "--completion-review",
            "independent-falsification-v1",
            "--provider",
            "xai",
        ]
        .map(str::to_owned);
        let parsed = RunArguments::parse(&arguments).expect("parse completion review");
        assert_eq!(
            parsed.completion_review,
            CompletionReviewPolicy::IndependentFalsificationV1
        );

        let mut v2 = arguments.clone();
        v2[8] = "evidence-debt-v2".to_owned();
        let parsed_v2 = RunArguments::parse(&v2).expect("parse evidence debt review");
        assert_eq!(
            parsed_v2.completion_review,
            CompletionReviewPolicy::EvidenceDebtV2
        );

        let mut v3 = arguments.clone();
        v3[8] = "fresh-evidence-debt-v3".to_owned();
        let parsed_v3 = RunArguments::parse(&v3).expect("parse fresh evidence debt review");
        assert_eq!(
            parsed_v3.completion_review,
            CompletionReviewPolicy::FreshEvidenceDebtV3
        );

        let mut v4 = arguments.clone();
        v4[8] = "fresh-checkpoint-v4".to_owned();
        let parsed_v4 = RunArguments::parse(&v4).expect("parse fresh checkpoint review");
        assert_eq!(
            parsed_v4.completion_review,
            CompletionReviewPolicy::FreshCheckpointV4
        );

        let mut v7 = arguments.clone();
        v7[8] = "semantic-checkpoint-v7".to_owned();
        let parsed_v7 = RunArguments::parse(&v7).expect("parse semantic checkpoint v7");
        assert_eq!(
            parsed_v7.completion_review,
            CompletionReviewPolicy::SemanticCheckpointV7
        );

        let mut v8 = arguments.clone();
        v8[8] = "semantic-checkpoint-v8".to_owned();
        let parsed_v8 = RunArguments::parse(&v8).expect("parse semantic checkpoint v8");
        assert_eq!(
            parsed_v8.completion_review,
            CompletionReviewPolicy::SemanticCheckpointV8
        );

        let mut invalid = arguments;
        invalid[8] = "benchmark-special-v1".to_owned();
        let error = RunArguments::parse(&invalid)
            .err()
            .expect("unknown review must fail");
        assert_eq!(error.code, "completion_review_policy_invalid");
    }

    #[test]
    fn capabilities_are_machine_readable_and_bind_external_xai() {
        let value: serde_json::Value =
            serde_json::from_str(&super::capability_manifest()).expect("capability JSON");
        assert_eq!(value["schema_version"], "nano-cli-capabilities-v2");
        assert_eq!(value["run_spec_schema"], "nano-run-spec-alpha-2");
        assert_eq!(value["event_schema"], "event-v3");
        assert_eq!(value["run_record_schema"], "nano-run-record-v2");
        assert_eq!(value["external_tool_schema"], "external-tool-stdio-v2");
        assert_eq!(value["providers"], serde_json::json!(["scripted", "xai"]));
        assert_eq!(
            value["executors"],
            serde_json::json!(["default", "external-stdio"])
        );
        assert_eq!(value["provider_model_source"], "contract-profile");
        assert!(value.get("xai_models").is_none());
        assert_eq!(
            value["dispatchable_tools"],
            serde_json::json!([
                "run_terminal_command",
                "read_file",
                "search_replace",
                "write",
                "list_dir",
                "grep",
                "kill_terminal_command",
                "get_terminal_command_output"
            ])
        );
    }
}
