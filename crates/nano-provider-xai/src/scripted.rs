//! Deterministic, no-network completed-response provider.

use std::collections::VecDeque;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::types::{CompletedTurn, PreparedTurnRequest, Provider, ProviderFailure};

const SCRIPT_SCHEMA: &str = "scripted-provider-v1";

#[derive(Debug)]
pub struct ScriptedProvider {
    steps: VecDeque<ScriptedStep>,
}

impl ScriptedProvider {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProviderFailure> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(ProviderFailure::new("script_path_not_absolute"));
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| ProviderFailure::new("script_read_failed"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProviderFailure::new("script_not_regular_file"));
        }
        let bytes = fs::read(path).map_err(|_| ProviderFailure::new("script_read_failed"))?;
        if bytes.len() < 2 || !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].ends_with(b"\n") {
            return Err(ProviderFailure::new("script_json_not_canonical"));
        }
        let script: ScriptFile = serde_json::from_slice(&bytes[..bytes.len() - 1])
            .map_err(|_| ProviderFailure::new("script_json_invalid"))?;
        if script.schema_version != SCRIPT_SCHEMA || script.steps.is_empty() {
            return Err(ProviderFailure::new("script_contract_invalid"));
        }
        Ok(Self {
            steps: script.steps.into(),
        })
    }
}

impl Provider for ScriptedProvider {
    async fn send(
        &mut self,
        request: PreparedTurnRequest,
    ) -> Result<CompletedTurn, ProviderFailure> {
        let _request = request.into_request()?;
        match self.steps.pop_front() {
            Some(ScriptedStep::Completed { response }) => Ok(response),
            Some(ScriptedStep::Failure { code }) => Err(ProviderFailure::new(code)),
            None => Err(ProviderFailure::new("script_exhausted")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptFile {
    schema_version: String,
    steps: Vec<ScriptedStep>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
enum ScriptedStep {
    Completed { response: CompletedTurn },
    Failure { code: String },
}
