//! Immutable alpha run identity and execution bounds.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::contract::{TOOL_ORDER, parse_canonical_json, sha256_hex};

/// The only RunSpec schema accepted by the runtime.
pub const RUN_SPEC_SCHEMA: &str = "nano-run-spec-alpha-1";

/// One immutable execution attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    pub schema_version: String,
    pub run_id: String,
    pub trial_id: String,
    pub attempt_id: String,
    pub task: TaskSpec,
    pub contract: ContractSpec,
    pub provider: ProviderSpec,
    pub workspace_dir: PathBuf,
    pub artifact_dir: PathBuf,
    pub agent_timeout_sec: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_tools: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    pub id: String,
    pub digest: String,
    pub instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSpec {
    pub id: String,
    pub contract_set_sha256: String,
    pub profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSpec {
    pub kind: ProviderKind,
    pub model: String,
    pub max_turns: u64,
    pub retry_max: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Scripted,
    Xai,
}

impl RunSpec {
    /// Load one exact JSON file without following a final-path symlink.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RunSpecError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(RunSpecError::Invalid {
                reason: "RunSpec path must be absolute".to_owned(),
            });
        }
        let metadata = fs::symlink_metadata(path).map_err(|error| RunSpecError::Io {
            reason: error.kind().to_string(),
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RunSpecError::Invalid {
                reason: "RunSpec path must be a non-symlink regular file".to_owned(),
            });
        }
        let bytes = fs::read(path).map_err(|error| RunSpecError::Io {
            reason: error.kind().to_string(),
        })?;
        let (spec, _) = parse_canonical_json::<Self>(&bytes, "run-spec.json").map_err(|error| {
            RunSpecError::Invalid {
                reason: error.to_string(),
            }
        })?;
        spec.validate()?;
        Ok(spec)
    }

    /// Validate immutable identity, retry, timeout, and path invariants.
    pub fn validate(&self) -> Result<(), RunSpecError> {
        require_equal("schema_version", &self.schema_version, RUN_SPEC_SCHEMA)?;
        validate_opaque_id("run_id", &self.run_id)?;
        validate_opaque_id("trial_id", &self.trial_id)?;
        validate_opaque_id("attempt_id", &self.attempt_id)?;
        validate_opaque_id("task.id", &self.task.id)?;
        validate_sha256("task.digest", &self.task.digest)?;
        if self.task.instruction.is_empty() {
            return invalid("task.instruction must not be empty");
        }
        validate_opaque_id("contract.id", &self.contract.id)?;
        validate_sha256(
            "contract.contract_set_sha256",
            &self.contract.contract_set_sha256,
        )?;
        validate_opaque_id("contract.profile_id", &self.contract.profile_id)?;
        validate_opaque_id("provider.model", &self.provider.model)?;
        if self.provider.max_turns == 0 {
            return invalid("provider.max_turns must be positive");
        }
        if self.provider.retry_max != 0 {
            return invalid("provider.retry_max must be zero");
        }
        if self.agent_timeout_sec == 0 {
            return invalid("agent_timeout_sec must be positive");
        }
        self.selected_tool_names()?;
        validate_absolute_normal_path("workspace_dir", &self.workspace_dir)?;
        validate_absolute_normal_path("artifact_dir", &self.artifact_dir)?;
        if self.workspace_dir.starts_with(&self.artifact_dir)
            || self.artifact_dir.starts_with(&self.workspace_dir)
        {
            return invalid("workspace_dir and artifact_dir must not overlap");
        }
        Ok(())
    }

    /// Resolve an optional selection back into the frozen provider order.
    pub fn selected_tool_names(&self) -> Result<Vec<&'static str>, RunSpecError> {
        let Some(requested) = &self.active_tools else {
            return Ok(TOOL_ORDER.to_vec());
        };
        if requested.is_empty() {
            return invalid("active_tools must not be empty");
        }
        let mut selected = std::collections::BTreeSet::new();
        for name in requested {
            if !TOOL_ORDER.contains(&name.as_str()) {
                return invalid(format!(
                    "active_tools contains an unknown or non-dispatchable tool: {name}"
                ));
            }
            if !selected.insert(name.as_str()) {
                return invalid(format!("active_tools contains a duplicate tool: {name}"));
            }
        }
        Ok(TOOL_ORDER
            .iter()
            .copied()
            .filter(|name| selected.contains(name))
            .collect())
    }

    /// Stable exact-field commitment used by the terminal run record.
    pub fn sha256(&self) -> Result<String, RunSpecError> {
        let bytes = serde_json::to_vec(self).map_err(|error| RunSpecError::Invalid {
            reason: format!("cannot serialize RunSpec: {error}"),
        })?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunSpecError {
    Invalid { reason: String },
    Io { reason: String },
}

impl Display for RunSpecError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { reason } => write!(formatter, "invalid RunSpec: {reason}"),
            Self::Io { reason } => write!(formatter, "RunSpec I/O error: {reason}"),
        }
    }
}

impl Error for RunSpecError {}

fn validate_opaque_id(field: &str, value: &str) -> Result<(), RunSpecError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return invalid(format!("{field} must be 1..=256 non-control UTF-8 bytes"));
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), RunSpecError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_absolute_normal_path(field: &str, path: &Path) -> Result<(), RunSpecError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return invalid(format!("{field} must be an absolute lexically-normal path"));
    }
    Ok(())
}

fn require_equal(field: &str, actual: &str, expected: &str) -> Result<(), RunSpecError> {
    if actual != expected {
        return invalid(format!("{field} must equal {expected}"));
    }
    Ok(())
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, RunSpecError> {
    Err(RunSpecError::Invalid {
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        ContractSpec, ProviderKind, ProviderSpec, RUN_SPEC_SCHEMA, RunSpec, RunSpecError, TaskSpec,
    };

    fn valid_spec() -> RunSpec {
        RunSpec {
            schema_version: RUN_SPEC_SCHEMA.to_owned(),
            run_id: "run-1".to_owned(),
            trial_id: "trial-1".to_owned(),
            attempt_id: "attempt-0".to_owned(),
            task: TaskSpec {
                id: "task-1".to_owned(),
                digest: "a".repeat(64),
                instruction: "Do the task.".to_owned(),
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
            active_tools: None,
        }
    }

    #[test]
    fn absent_active_tools_preserves_legacy_bytes_and_hash() {
        let spec = valid_spec();
        let bytes = serde_json::to_vec(&spec).expect("serialize RunSpec");
        assert_eq!(
            String::from_utf8(bytes).expect("RunSpec JSON is UTF-8"),
            concat!(
                "{\"schema_version\":\"nano-run-spec-alpha-1\",",
                "\"run_id\":\"run-1\",\"trial_id\":\"trial-1\",",
                "\"attempt_id\":\"attempt-0\",",
                "\"task\":{\"id\":\"task-1\",",
                "\"digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                "\"instruction\":\"Do the task.\"},",
                "\"contract\":{\"id\":\"synthetic-v1\",",
                "\"contract_set_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
                "\"profile_id\":\"synthetic-profile-v1\"},",
                "\"provider\":{\"kind\":\"scripted\",\"model\":\"synthetic-model\",",
                "\"max_turns\":4,\"retry_max\":0},",
                "\"workspace_dir\":\"/workspace\",",
                "\"artifact_dir\":\"/logs/agent\",",
                "\"agent_timeout_sec\":60}"
            )
        );
        assert_eq!(
            spec.sha256().expect("RunSpec hash"),
            "a3fa4dde75a6b8d5ea4766642eb2f51d908b12eac51a6e24620b23b3f91f7688"
        );
    }

    #[test]
    fn active_tools_are_nonempty_unique_dispatchable_and_contract_ordered() {
        let mut spec = valid_spec();
        spec.active_tools = Some(vec![
            "write".to_owned(),
            "run_terminal_command".to_owned(),
            "read_file".to_owned(),
        ]);
        assert_eq!(
            spec.selected_tool_names().expect("valid selector"),
            ["run_terminal_command", "read_file", "write"]
        );
        spec.active_tools = Some(
            [
                "get_terminal_command_output",
                "kill_terminal_command",
                "run_terminal_command",
            ]
            .map(str::to_owned)
            .to_vec(),
        );
        assert_eq!(
            spec.selected_tool_names().expect("background selector"),
            [
                "run_terminal_command",
                "kill_terminal_command",
                "get_terminal_command_output"
            ]
        );

        for invalid_tools in [
            vec![],
            vec!["read_file".to_owned(), "read_file".to_owned()],
            vec!["unknown".to_owned()],
        ] {
            spec.active_tools = Some(invalid_tools);
            assert!(matches!(
                spec.validate(),
                Err(RunSpecError::Invalid { reason })
                    if reason.contains("active_tools")
            ));
        }
    }

    #[test]
    fn rejects_retry_unknown_fields_and_overlapping_paths() {
        let mut retry = valid_spec();
        retry.provider.retry_max = 1;
        assert!(matches!(
            retry.validate(),
            Err(RunSpecError::Invalid { reason }) if reason.contains("retry_max")
        ));

        let mut overlap = valid_spec();
        overlap.artifact_dir = PathBuf::from("/workspace/logs");
        assert!(matches!(
            overlap.validate(),
            Err(RunSpecError::Invalid { reason }) if reason.contains("must not overlap")
        ));

        let mut value = serde_json::to_value(valid_spec()).expect("serialize RunSpec");
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RunSpec>(value).is_err());
    }

    #[test]
    fn provider_models_are_explicit_and_not_selected_by_the_runtime() {
        let mut live = valid_spec();
        live.provider.kind = ProviderKind::Xai;
        assert!(live.validate().is_ok());
        live.provider.model = "future-xai-model".to_owned();
        assert!(live.validate().is_ok());
    }
}
