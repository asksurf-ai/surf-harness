//! Strict, immutable model-visible contract loading.
//!
//! The runtime consumes only the effective contract and its profile.  Source
//! fixtures, review records, and exporter code are intentionally absent from
//! this module.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::external_tool::{READ_FILE_MEDIA_MAX_BYTES, READ_FILE_MEDIA_MAX_HISTORY_BYTES};

/// The immutable provider order of the nano-v1 tool contract.
pub const TOOL_ORDER: [&str; 8] = [
    "run_terminal_command",
    "read_file",
    "search_replace",
    "write",
    "list_dir",
    "grep",
    "kill_terminal_command",
    "get_terminal_command_output",
];

const MANIFEST_SCHEMA: &str = "contract-manifest-v1";
const EFFECTIVE_SCHEMA: &str = "effective-contract-v1";
const PROFILE_SCHEMA: &str = "agent-profile-v1";
const DELTA_SCHEMA: &str = "contract-delta-v1";

/// A validated, owned contract bundle.
#[derive(Debug, Clone)]
pub struct ContractBundle {
    manifest: ContractManifest,
    effective: EffectiveContract,
    profile: AgentProfile,
}

/// A reviewed but deliberately unpromoted contract loaded from an explicit
/// absolute directory.
///
/// This seam exists for local baseline work only. It does not treat the files
/// as redistributable or fall back to cwd discovery.
#[derive(Debug, Clone)]
pub struct LocalContract {
    effective: EffectiveContract,
    profile: AgentProfile,
    contract_set_sha256: String,
}

impl LocalContract {
    /// Read one runtime safety profile from three compatibility basenames.
    pub fn load(contract_dir: impl AsRef<Path>) -> Result<Self, ContractError> {
        let contract_dir = contract_dir.as_ref();
        if !contract_dir.is_absolute() {
            return invalid("local contract directory must be absolute");
        }
        require_directory(contract_dir, "local-contract")?;

        let effective_bytes = read_regular_file(
            &contract_dir.join("effective-contract.json"),
            "effective-contract.json",
        )?;
        let profile_bytes = read_regular_file(
            &contract_dir.join("agent-profile.json"),
            "agent-profile.json",
        )?;
        let delta_bytes = read_regular_file(
            &contract_dir.join("contract-delta.json"),
            "contract-delta.json",
        )?;

        let (effective, effective_value) =
            parse_canonical_json::<EffectiveContract>(&effective_bytes, "effective-contract.json")?;
        let (profile, _) =
            parse_canonical_json::<AgentProfile>(&profile_bytes, "agent-profile.json")?;
        let (_, compatibility_value) =
            parse_canonical_json::<Value>(&delta_bytes, "contract-delta.json")?;
        if !compatibility_value.is_object() {
            return invalid("compatibility contract delta must be a JSON object");
        }
        validate_effective(&effective)?;
        validate_runtime_profile(&effective, &profile)?;
        if profile.contract_bindings.effective_contract_file_sha256 != sha256_hex(&effective_bytes)
        {
            return invalid("profile effective contract hash binding mismatch");
        }
        if profile.contract_bindings.system_prompt_utf8_sha256
            != effective.system_prompt.utf8_sha256
        {
            return invalid("profile system prompt hash binding mismatch");
        }
        let tools = effective_value
            .get("tools")
            .ok_or_else(|| ContractError::InvalidContract {
                reason: "effective tools value is absent".to_owned(),
            })?;
        if profile.contract_bindings.ordered_tools_value_sha256 != value_sha256(tools)? {
            return invalid("profile ordered tools hash binding mismatch");
        }
        if profile.contract_bindings.contract_delta_file_sha256 != sha256_hex(&delta_bytes) {
            return invalid("profile contract delta hash binding mismatch");
        }

        let contract_set_sha256 = local_contract_set_sha256([
            ("agent-profile.json", profile_bytes.as_slice()),
            ("contract-delta.json", delta_bytes.as_slice()),
            ("effective-contract.json", effective_bytes.as_slice()),
        ])?;
        Ok(Self {
            effective,
            profile,
            contract_set_sha256,
        })
    }

    pub fn effective(&self) -> &EffectiveContract {
        &self.effective
    }

    pub fn profile(&self) -> &AgentProfile {
        &self.profile
    }

    /// Hash of ordered `{path, byte_length, file_sha256}` rows.
    pub fn contract_set_sha256(&self) -> &str {
        &self.contract_set_sha256
    }
}

impl ContractBundle {
    /// Load and validate a complete promoted bundle directory.
    ///
    /// The directory must contain exactly one
    /// `contracts/<contract-id>/manifest.json`, every file committed by that
    /// manifest, and no unmanifested files. All entries are read and
    /// length/hash checked before the runtime artifacts are parsed.
    pub fn from_directory(bundle_root: impl AsRef<Path>) -> Result<Self, ContractError> {
        let bundle_root = bundle_root.as_ref();
        require_directory(bundle_root, ".")?;
        let manifest_path = find_manifest(bundle_root)?;
        let manifest_bytes = read_regular_file(&manifest_path, "manifest.json")?;
        let (manifest, _) =
            parse_canonical_json::<ContractManifest>(&manifest_bytes, "manifest.json")?;
        validate_manifest(&manifest)?;

        let expected_manifest_path = contract_path(&manifest.contract_id, "manifest.json")?;
        let actual_manifest_path = relative_path(bundle_root, &manifest_path)?;
        if actual_manifest_path != expected_manifest_path {
            return invalid(format!(
                "manifest path does not match contract_id: {actual_manifest_path}"
            ));
        }

        let mut committed_files = BTreeMap::new();
        for entry in &manifest.files {
            let bytes = read_regular_file(&bundle_root.join(&entry.path), &entry.path)?;
            verify_file_entry(entry, &bytes)?;
            committed_files.insert(entry.path.clone(), bytes);
        }

        let expected_paths = manifest
            .files
            .iter()
            .map(|entry| entry.path.clone())
            .chain(std::iter::once(expected_manifest_path))
            .collect::<BTreeSet<_>>();
        let actual_paths = collect_bundle_files(bundle_root)?;
        if actual_paths != expected_paths {
            return invalid("bundle directory contains unmanifested or missing files");
        }

        let effective_path = contract_path(&manifest.contract_id, "effective-contract.json")?;
        let profile_path = contract_path(&manifest.contract_id, "agent-profile.json")?;
        let effective_bytes = committed_files.get(&effective_path).ok_or_else(|| {
            ContractError::MissingManifestFile {
                path: effective_path.clone(),
            }
        })?;
        let profile_bytes = committed_files.get(&profile_path).ok_or_else(|| {
            ContractError::MissingManifestFile {
                path: profile_path.clone(),
            }
        })?;
        Self::from_embedded_bytes(&manifest_bytes, effective_bytes, profile_bytes)
    }

    /// Load the three runtime-embedded artifacts.
    ///
    /// `manifest_bytes` commits every published bundle file. The loader checks
    /// the exact embedded effective/profile bytes, their schema ids, and the
    /// ordered manifest-entry commitment. Non-runtime evidence remains the
    /// responsibility of the offline bundle validator.
    pub fn from_embedded_bytes(
        manifest_bytes: &[u8],
        effective_bytes: &[u8],
        profile_bytes: &[u8],
    ) -> Result<Self, ContractError> {
        let (manifest, _) =
            parse_canonical_json::<ContractManifest>(manifest_bytes, "manifest.json")?;
        validate_manifest(&manifest)?;

        let effective_path = contract_path(&manifest.contract_id, "effective-contract.json")?;
        let profile_path = contract_path(&manifest.contract_id, "agent-profile.json")?;
        let delta_path = contract_path(&manifest.contract_id, "contract-delta.json")?;

        verify_embedded_file(
            &manifest,
            &effective_path,
            EFFECTIVE_SCHEMA,
            effective_bytes,
        )?;
        verify_embedded_file(&manifest, &profile_path, PROFILE_SCHEMA, profile_bytes)?;

        let (effective, effective_value) =
            parse_canonical_json::<EffectiveContract>(effective_bytes, &effective_path)?;
        let (profile, _) = parse_canonical_json::<AgentProfile>(profile_bytes, &profile_path)?;

        validate_effective(&effective)?;
        validate_profile(
            &manifest,
            &effective,
            &effective_value,
            &profile,
            &effective_path,
            &delta_path,
        )?;

        Ok(Self {
            manifest,
            effective,
            profile,
        })
    }

    /// Load the reviewed nano-v1 bundle compiled into the binary.
    ///
    /// M0b deliberately has no embedded bundle. This fail-closed result
    /// prevents a synthetic test fixture from becoming a production contract.
    pub fn embedded_nano_v1() -> Result<Self, ContractError> {
        Err(ContractError::Unavailable {
            contract_id: "nano-v1",
        })
    }

    /// The manifest for the validated bundle.
    pub fn manifest(&self) -> &ContractManifest {
        &self.manifest
    }

    /// The sole model-visible runtime contract.
    pub fn effective(&self) -> &EffectiveContract {
        &self.effective
    }

    /// The immutable runtime policy bound to the effective contract.
    pub fn profile(&self) -> &AgentProfile {
        &self.profile
    }

    /// The ordered bundle commitment recorded by the manifest.
    pub fn bundle_sha256(&self) -> &str {
        &self.manifest.contract_bundle_sha256
    }
}

/// A strict contract manifest. The manifest intentionally has no self-entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractManifest {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_bundle_sha256: String,
    pub files: Vec<ManifestFile>,
}

/// One ordered exact-byte file commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub path: String,
    pub schema_id: String,
    pub byte_length: u64,
    pub file_sha256: String,
}

/// The sole model-visible effective contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveContract {
    pub schema_version: String,
    pub contract_id: String,
    pub prompt_context: PromptContext,
    pub system_prompt: HashedText,
    pub user_wrapper: UserWrapper,
    pub tools: [ToolContract; 8],
}

impl EffectiveContract {
    /// Return tools in the immutable provider order.
    pub fn ordered_tools(&self) -> &[ToolContract; 8] {
        &self.tools
    }

    /// Substitute arbitrary user text into the wrapper's single literal slot.
    pub fn wrap_user_query(&self, user_query: &str) -> String {
        self.user_wrapper
            .template
            .replacen(&self.user_wrapper.payload_slot, user_query, 1)
    }

    /// Look up the frozen effect class by contract tool id.
    pub fn effect_for(&self, contract_tool_id: &str) -> Option<EffectClass> {
        self.tools
            .iter()
            .find(|tool| tool.contract_tool_id == contract_tool_id)
            .map(|tool| tool.effect_class)
    }
}

/// The effective prompt context frozen at contract review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptContext {
    pub current_date: String,
    pub is_non_interactive: bool,
    pub memory_enabled: bool,
    pub os_name: String,
    pub shell_path: String,
    pub system_prompt_label: String,
    pub working_directory: String,
}

/// Exact UTF-8 text paired with its direct byte hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashedText {
    pub text: String,
    pub utf8_sha256: String,
}

/// A wrapper with one literal, non-interpreted user payload slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserWrapper {
    pub template: String,
    pub payload_slot: String,
    pub utf8_sha256: String,
}

/// One provider-visible tool definition plus kernel-only effect metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolContract {
    pub ordinal: u8,
    pub contract_tool_id: String,
    pub provider_name: String,
    pub description: String,
    pub input_schema: Value,
    pub effect_class: EffectClass,
    pub compatibility_aliases: Vec<String>,
    pub result_policy: ResultPolicy,
}

/// Runtime effect classification. The fixture, not argument inspection, owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    ReadOnly,
    Mutating,
}

/// Frozen bounds and conformance id for model-visible tool results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPolicy {
    pub renderer_contract_id: String,
    pub truncation_policy: String,
    pub max_model_output_bytes: u64,
}

/// Immutable provider, context, scheduler, process, and artifact policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub contract_id: String,
    pub provider: ProviderProfile,
    pub contract_bindings: ContractBindings,
    pub context: ContextPolicy,
    pub transport: TransportLimits,
    pub scheduler: SchedulerPolicy,
    pub deadlines: DeadlinePolicy,
    pub tools: ToolLimits,
    pub process: ProcessPolicy,
    pub artifacts: ArtifactLimits,
    pub schema_versions: ProfileSchemaVersions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    pub provider_id: String,
    pub api: String,
    pub endpoint: String,
    pub model: String,
    pub reasoning_effort: String,
    pub store: bool,
    pub stream: bool,
    pub include: Vec<String>,
    pub parallel_tool_calls: bool,
    pub tool_choice: String,
    pub service_tier: String,
    pub retry_max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractBindings {
    pub effective_contract_file_sha256: String,
    pub system_prompt_utf8_sha256: String,
    pub ordered_tools_value_sha256: String,
    pub contract_delta_file_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPolicy {
    pub policy: String,
    pub counting_rule: String,
    pub provider_context_window_tokens: u64,
    pub request_input_upper_tokens: u64,
    pub max_output_tokens_per_request: u64,
    pub max_provider_turns: u64,
    pub max_input_tokens_per_run: u64,
    pub max_output_tokens_per_run: u64,
    pub max_history_items: u64,
    pub max_request_body_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportLimits {
    pub max_function_arguments_bytes: u64,
    pub max_sse_events_per_response: u64,
    pub max_sse_event_bytes: u64,
    pub max_sse_response_bytes: u64,
    pub max_json_depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerPolicy {
    pub read_only_parallelism: u64,
    pub max_function_calls_per_response: u64,
    pub max_function_calls_per_run: u64,
    pub mutation_batches_serialized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlinePolicy {
    pub source: String,
    pub absolute_run_wall_cap_sec: u64,
    pub terminalization_reserve_sec: u64,
    pub min_provider_send_window_sec: u64,
    pub provider_connect_timeout_sec: u64,
    pub provider_first_event_timeout_sec: u64,
    pub provider_inter_event_timeout_sec: u64,
    pub provider_total_timeout_sec: u64,
    pub filesystem_operation_timeout_sec: u64,
    pub search_operation_timeout_sec: u64,
    pub process_control_timeout_sec: u64,
    pub artifactization_timeout_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLimits {
    pub terminal_default_timeout_ms: u64,
    pub terminal_max_timeout_ms: u64,
    pub background_output_wait_max_ms: u64,
    /// Explicit reviewed capability gate. Historic profiles omit this field
    /// and therefore remain text-only.
    #[serde(default)]
    pub read_file_media_enabled: bool,
    pub max_command_bytes: u64,
    pub max_path_bytes: u64,
    pub max_read_or_write_bytes: u64,
    pub max_directory_entries: u64,
    pub max_grep_matches: u64,
    pub max_replacements: u64,
    pub model_tool_output_bytes_per_call: u64,
    pub model_tool_output_bytes_per_run: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    pub max_background_processes: u64,
    pub term_grace_ms: u64,
    pub kill_confirmation_timeout_ms: u64,
    pub process_spool_bytes_per_process: u64,
    pub process_spool_bytes_per_run: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLimits {
    pub max_events_per_run: u64,
    pub max_event_line_bytes: u64,
    pub max_event_log_bytes: u64,
    pub max_blobs_per_run: u64,
    pub max_blob_bytes: u64,
    pub max_blob_bytes_per_run: u64,
    pub max_agent_run_record_bytes: u64,
    pub max_trajectory_bytes: u64,
    pub max_published_agent_bytes: u64,
    pub max_live_stdout_mirror_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSchemaVersions {
    pub contract_manifest: String,
    pub effective_contract: String,
    pub agent_profile: String,
    pub contract_delta: String,
}

/// Fail-closed loader errors with no source bytes in their display text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    Unavailable {
        contract_id: &'static str,
    },
    InvalidJson {
        artifact: String,
        reason: String,
    },
    InvalidContract {
        reason: String,
    },
    MissingManifestFile {
        path: String,
    },
    FileLengthMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    FileHashMismatch {
        path: String,
    },
    DirectoryIo {
        path: String,
        reason: String,
    },
}

impl Display for ContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { contract_id } => {
                write!(formatter, "contract bundle {contract_id} is unavailable")
            }
            Self::InvalidJson { artifact, reason } => {
                write!(formatter, "invalid JSON in {artifact}: {reason}")
            }
            Self::InvalidContract { reason } => write!(formatter, "invalid contract: {reason}"),
            Self::MissingManifestFile { path } => {
                write!(formatter, "manifest file is missing: {path}")
            }
            Self::FileLengthMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "embedded file length mismatch for {path}: expected {expected}, got {actual}"
            ),
            Self::FileHashMismatch { path } => {
                write!(formatter, "embedded file hash mismatch for {path}")
            }
            Self::DirectoryIo { path, reason } => {
                write!(formatter, "bundle directory error at {path}: {reason}")
            }
        }
    }
}

impl Error for ContractError {}

fn validate_manifest(manifest: &ContractManifest) -> Result<(), ContractError> {
    require_equal(
        "manifest schema_version",
        &manifest.schema_version,
        MANIFEST_SCHEMA,
    )?;
    validate_contract_id(&manifest.contract_id)?;
    validate_sha256(
        "manifest contract_bundle_sha256",
        &manifest.contract_bundle_sha256,
    )?;
    if manifest.files.is_empty() {
        return invalid("manifest files must not be empty");
    }

    let mut paths = BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    for file in &manifest.files {
        if is_root_notice(&file.path) {
            require_equal("root notice schema", &file.schema_id, "text-v1")?;
        } else {
            validate_contract_path(&manifest.contract_id, &file.path)?;
        }
        if file.path.ends_with("/manifest.json") {
            return invalid("manifest must not contain a self-entry");
        }
        if previous_path.is_some_and(|previous| file.path.as_str() <= previous) {
            return invalid(format!(
                "manifest paths must be strictly ordered: {}",
                file.path
            ));
        }
        previous_path = Some(file.path.as_str());
        if !paths.insert(file.path.as_str()) {
            return invalid(format!("duplicate manifest path: {}", file.path));
        }
        if file.schema_id.is_empty() {
            return invalid(format!("empty schema id for {}", file.path));
        }
        validate_sha256("manifest file_sha256", &file.file_sha256)?;
    }

    let derived = ordered_entries_sha256(&manifest.files)?;
    if derived != manifest.contract_bundle_sha256 {
        return invalid("contract_bundle_sha256 does not commit ordered manifest entries");
    }
    Ok(())
}

fn validate_effective(effective: &EffectiveContract) -> Result<(), ContractError> {
    require_equal(
        "effective schema_version",
        &effective.schema_version,
        EFFECTIVE_SCHEMA,
    )?;
    validate_contract_id(&effective.contract_id)?;

    validate_hashed_text("system_prompt", &effective.system_prompt)?;
    validate_sha256(
        "user_wrapper utf8_sha256",
        &effective.user_wrapper.utf8_sha256,
    )?;
    if sha256_hex(effective.user_wrapper.template.as_bytes()) != effective.user_wrapper.utf8_sha256
    {
        return invalid("user_wrapper utf8_sha256 mismatch");
    }
    if effective.user_wrapper.payload_slot.is_empty() {
        return invalid("user_wrapper payload_slot must not be empty");
    }
    if effective
        .user_wrapper
        .template
        .matches(&effective.user_wrapper.payload_slot)
        .count()
        != 1
    {
        return invalid("user_wrapper must contain exactly one literal payload slot");
    }

    let mut ids = BTreeSet::new();
    for (ordinal, (tool, expected_name)) in
        effective.tools.iter().zip(TOOL_ORDER.iter()).enumerate()
    {
        if usize::from(tool.ordinal) != ordinal {
            return invalid(format!("tool ordinal mismatch at position {ordinal}"));
        }
        if tool.provider_name != *expected_name {
            return invalid(format!("tool order mismatch at position {ordinal}"));
        }
        if tool.contract_tool_id.is_empty() || !ids.insert(tool.contract_tool_id.as_str()) {
            return invalid(format!(
                "empty or duplicate contract_tool_id at position {ordinal}"
            ));
        }
        if tool.description.is_empty() {
            return invalid(format!("empty tool description at position {ordinal}"));
        }
        if !tool.input_schema.is_object() {
            return invalid(format!(
                "tool input_schema is not an object at position {ordinal}"
            ));
        }
        if tool.result_policy.renderer_contract_id.is_empty()
            || tool.result_policy.truncation_policy.is_empty()
            || tool.result_policy.max_model_output_bytes == 0
        {
            return invalid(format!("invalid result_policy at position {ordinal}"));
        }
    }
    Ok(())
}

fn validate_profile(
    manifest: &ContractManifest,
    effective: &EffectiveContract,
    effective_value: &Value,
    profile: &AgentProfile,
    effective_path: &str,
    delta_path: &str,
) -> Result<(), ContractError> {
    validate_runtime_profile(effective, profile)?;
    require_equal(
        "profile schema_version",
        &profile.schema_version,
        PROFILE_SCHEMA,
    )?;
    validate_closed_identifier("profile_id", &profile.profile_id)?;
    if profile.contract_id != manifest.contract_id || effective.contract_id != manifest.contract_id
    {
        return invalid("contract_id mismatch across bundle");
    }

    require_equal(
        "profile contract_manifest schema",
        &profile.schema_versions.contract_manifest,
        MANIFEST_SCHEMA,
    )?;
    require_equal(
        "profile effective_contract schema",
        &profile.schema_versions.effective_contract,
        EFFECTIVE_SCHEMA,
    )?;
    require_equal(
        "profile agent_profile schema",
        &profile.schema_versions.agent_profile,
        PROFILE_SCHEMA,
    )?;
    let delta_schema = profile.schema_versions.contract_delta.as_str();
    require_equal("profile contract_delta schema", delta_schema, DELTA_SCHEMA)?;

    let effective_entry = manifest_file(manifest, effective_path)?;
    if effective_entry.file_sha256 != profile.contract_bindings.effective_contract_file_sha256 {
        return invalid("profile effective contract hash binding mismatch");
    }
    if effective.system_prompt.utf8_sha256 != profile.contract_bindings.system_prompt_utf8_sha256 {
        return invalid("profile system prompt hash binding mismatch");
    }
    let tools = effective_value
        .get("tools")
        .ok_or_else(|| ContractError::InvalidContract {
            reason: "effective tools value is absent".to_owned(),
        })?;
    let tools_hash = value_sha256(tools)?;
    if tools_hash != profile.contract_bindings.ordered_tools_value_sha256 {
        return invalid("profile ordered tools hash binding mismatch");
    }
    let delta_entry = manifest_file(manifest, delta_path)?;
    require_equal(
        "delta manifest schema",
        &delta_entry.schema_id,
        delta_schema,
    )?;
    if delta_entry.file_sha256 != profile.contract_bindings.contract_delta_file_sha256 {
        return invalid("profile contract delta hash binding mismatch");
    }
    require_nonempty("provider_id", &profile.provider.provider_id)?;
    require_nonempty("provider api", &profile.provider.api)?;
    require_nonempty("provider endpoint", &profile.provider.endpoint)?;
    require_nonempty("provider model", &profile.provider.model)?;
    require_nonempty(
        "provider reasoning_effort",
        &profile.provider.reasoning_effort,
    )?;
    require_nonempty("provider tool_choice", &profile.provider.tool_choice)?;
    require_nonempty("provider service_tier", &profile.provider.service_tier)?;
    require_nonempty("context policy", &profile.context.policy)?;
    require_nonempty("context counting_rule", &profile.context.counting_rule)?;
    require_nonempty("deadline source", &profile.deadlines.source)?;

    if profile.provider.retry_max != 0 {
        return invalid("provider retry_max must be zero");
    }
    if !profile.provider.stream {
        return invalid("provider stream must be enabled");
    }
    if profile.context.max_output_tokens_per_request > profile.context.max_output_tokens_per_run {
        return invalid("per-request output limit exceeds per-run output limit");
    }
    if profile.scheduler.max_function_calls_per_response
        > profile.scheduler.max_function_calls_per_run
    {
        return invalid("per-response call limit exceeds per-run call limit");
    }
    if profile.tools.terminal_default_timeout_ms > profile.tools.terminal_max_timeout_ms {
        return invalid("terminal default timeout exceeds terminal maximum");
    }
    if profile.tools.background_output_wait_max_ms == 0 {
        return invalid("background output wait maximum must be positive");
    }
    validate_runtime_media_capabilities(effective, profile)?;
    if profile.deadlines.terminalization_reserve_sec == 0 {
        return invalid("terminalization reserve must be positive");
    }
    if profile.deadlines.min_provider_send_window_sec == 0 {
        return invalid("provider send window must be positive");
    }
    let required_run_window = profile
        .deadlines
        .terminalization_reserve_sec
        .checked_add(profile.deadlines.min_provider_send_window_sec)
        .ok_or_else(|| ContractError::InvalidContract {
            reason: "deadline reserve arithmetic overflow".to_owned(),
        })?;
    if profile.deadlines.absolute_run_wall_cap_sec <= required_run_window {
        return invalid("absolute run wall cap does not contain deadline reserves");
    }
    if profile.artifacts.max_events_per_run < 2 {
        return invalid("event limit must reserve run start and terminal events");
    }
    if profile.tools.model_tool_output_bytes_per_call
        > profile.tools.model_tool_output_bytes_per_run
    {
        return invalid("per-call model tool output exceeds per-run output");
    }
    if profile.process.process_spool_bytes_per_process > profile.process.process_spool_bytes_per_run
    {
        return invalid("per-process spool limit exceeds per-run spool limit");
    }
    if profile.artifacts.max_blob_bytes > profile.artifacts.max_blob_bytes_per_run {
        return invalid("per-blob limit exceeds per-run blob limit");
    }

    Ok(())
}

fn validate_runtime_profile(
    effective: &EffectiveContract,
    profile: &AgentProfile,
) -> Result<(), ContractError> {
    require_equal(
        "profile schema_version",
        &profile.schema_version,
        PROFILE_SCHEMA,
    )?;
    validate_closed_identifier("profile_id", &profile.profile_id)?;
    require_equal(
        "runtime profile contract_id",
        &profile.contract_id,
        &effective.contract_id,
    )?;
    require_equal(
        "profile effective_contract schema",
        &profile.schema_versions.effective_contract,
        EFFECTIVE_SCHEMA,
    )?;
    require_equal(
        "profile agent_profile schema",
        &profile.schema_versions.agent_profile,
        PROFILE_SCHEMA,
    )?;
    validate_runtime_media_capabilities(effective, profile)?;
    validate_runtime_profile_values(profile)
}

fn validate_runtime_media_capabilities(
    effective: &EffectiveContract,
    profile: &AgentProfile,
) -> Result<(), ContractError> {
    if !profile.tools.read_file_media_enabled {
        return Ok(());
    }
    let minimum_request_body_bytes = READ_FILE_MEDIA_MAX_HISTORY_BYTES
        .div_ceil(3)
        .checked_mul(4)
        .ok_or_else(|| ContractError::InvalidContract {
            reason: "read_file media request bound overflow".to_owned(),
        })?;
    if profile.provider.provider_id != "xai"
        || profile.provider.api != "responses-v1"
        || profile.provider.store
        || !profile.provider.stream
        || profile.context.max_request_body_bytes < minimum_request_body_bytes
        || profile.tools.max_read_or_write_bytes < READ_FILE_MEDIA_MAX_BYTES
    {
        return invalid("read_file media capability bounds are invalid");
    }
    let read_file = effective
        .tools
        .get(1)
        .ok_or_else(|| ContractError::InvalidContract {
            reason: "read_file tool is absent".to_owned(),
        })?;
    let target_type = read_file
        .input_schema
        .get("properties")
        .and_then(|properties| properties.get("target_file"))
        .and_then(|target| target.get("type"))
        .and_then(Value::as_str);
    if target_type != Some("string") {
        return invalid("read_file media path schema is invalid");
    }
    Ok(())
}

fn validate_runtime_profile_values(profile: &AgentProfile) -> Result<(), ContractError> {
    require_nonempty("provider_id", &profile.provider.provider_id)?;
    require_nonempty("provider api", &profile.provider.api)?;
    require_nonempty("provider endpoint", &profile.provider.endpoint)?;
    require_nonempty("provider model", &profile.provider.model)?;
    require_nonempty(
        "provider reasoning_effort",
        &profile.provider.reasoning_effort,
    )?;
    require_nonempty("provider tool_choice", &profile.provider.tool_choice)?;
    require_nonempty("provider service_tier", &profile.provider.service_tier)?;
    require_nonempty("context policy", &profile.context.policy)?;
    require_nonempty("context counting_rule", &profile.context.counting_rule)?;
    require_nonempty("deadline source", &profile.deadlines.source)?;

    if profile.provider.retry_max != 0 {
        return invalid("provider retry_max must be zero");
    }
    if !profile.provider.stream {
        return invalid("provider stream must be enabled");
    }
    if profile.context.request_input_upper_tokens > profile.context.provider_context_window_tokens {
        return invalid("request input limit exceeds provider context window");
    }
    if profile.context.max_output_tokens_per_request > profile.context.max_output_tokens_per_run {
        return invalid("per-request output limit exceeds per-run output limit");
    }
    if profile.scheduler.max_function_calls_per_response
        > profile.scheduler.max_function_calls_per_run
    {
        return invalid("per-response call limit exceeds per-run call limit");
    }
    if profile.tools.terminal_default_timeout_ms > profile.tools.terminal_max_timeout_ms {
        return invalid("terminal default timeout exceeds terminal maximum");
    }
    if profile.tools.background_output_wait_max_ms == 0 {
        return invalid("background output wait maximum must be positive");
    }
    if profile.deadlines.terminalization_reserve_sec == 0 {
        return invalid("terminalization reserve must be positive");
    }
    if profile.deadlines.min_provider_send_window_sec == 0 {
        return invalid("provider send window must be positive");
    }
    let required_run_window = profile
        .deadlines
        .terminalization_reserve_sec
        .checked_add(profile.deadlines.min_provider_send_window_sec)
        .ok_or_else(|| ContractError::InvalidContract {
            reason: "deadline reserve arithmetic overflow".to_owned(),
        })?;
    if profile.deadlines.absolute_run_wall_cap_sec <= required_run_window {
        return invalid("absolute run wall cap does not contain deadline reserves");
    }
    if profile.artifacts.max_events_per_run < 2 {
        return invalid("event limit must reserve run start and terminal events");
    }
    if profile.tools.model_tool_output_bytes_per_call
        > profile.tools.model_tool_output_bytes_per_run
    {
        return invalid("per-call model tool output exceeds per-run output");
    }
    if profile.process.process_spool_bytes_per_process > profile.process.process_spool_bytes_per_run
    {
        return invalid("per-process spool limit exceeds per-run spool limit");
    }
    if profile.artifacts.max_blob_bytes > profile.artifacts.max_blob_bytes_per_run {
        return invalid("per-blob limit exceeds per-run blob limit");
    }
    let positive_limits = [
        profile.context.provider_context_window_tokens,
        profile.context.request_input_upper_tokens,
        profile.context.max_output_tokens_per_request,
        profile.context.max_provider_turns,
        profile.context.max_input_tokens_per_run,
        profile.context.max_output_tokens_per_run,
        profile.context.max_history_items,
        profile.context.max_request_body_bytes,
        profile.transport.max_function_arguments_bytes,
        profile.transport.max_sse_events_per_response,
        profile.transport.max_sse_event_bytes,
        profile.transport.max_sse_response_bytes,
        profile.transport.max_json_depth,
        profile.scheduler.read_only_parallelism,
        profile.scheduler.max_function_calls_per_response,
        profile.scheduler.max_function_calls_per_run,
        profile.tools.terminal_default_timeout_ms,
        profile.tools.terminal_max_timeout_ms,
        profile.tools.max_command_bytes,
        profile.tools.max_path_bytes,
        profile.tools.max_read_or_write_bytes,
        profile.tools.max_directory_entries,
        profile.tools.max_grep_matches,
        profile.tools.max_replacements,
        profile.tools.model_tool_output_bytes_per_call,
        profile.tools.model_tool_output_bytes_per_run,
        profile.process.max_background_processes,
        profile.process.term_grace_ms,
        profile.process.kill_confirmation_timeout_ms,
        profile.process.process_spool_bytes_per_process,
        profile.process.process_spool_bytes_per_run,
        profile.artifacts.max_event_line_bytes,
        profile.artifacts.max_event_log_bytes,
        profile.artifacts.max_blob_bytes,
        profile.artifacts.max_blob_bytes_per_run,
        profile.artifacts.max_agent_run_record_bytes,
        profile.artifacts.max_trajectory_bytes,
        profile.artifacts.max_published_agent_bytes,
        profile.artifacts.max_live_stdout_mirror_bytes,
    ];
    if positive_limits.contains(&0) {
        return invalid("runtime safety limits must be positive");
    }
    let positive_deadlines = [
        profile.deadlines.provider_connect_timeout_sec,
        profile.deadlines.provider_first_event_timeout_sec,
        profile.deadlines.provider_inter_event_timeout_sec,
        profile.deadlines.provider_total_timeout_sec,
        profile.deadlines.filesystem_operation_timeout_sec,
        profile.deadlines.search_operation_timeout_sec,
        profile.deadlines.process_control_timeout_sec,
        profile.deadlines.artifactization_timeout_sec,
    ];
    if positive_deadlines.contains(&0) {
        return invalid("runtime deadline limits must be positive");
    }
    Ok(())
}

fn verify_embedded_file(
    manifest: &ContractManifest,
    path: &str,
    schema_id: &str,
    bytes: &[u8],
) -> Result<(), ContractError> {
    let entry = manifest_file(manifest, path)?;
    require_equal("manifest entry schema", &entry.schema_id, schema_id)?;
    verify_file_entry(entry, bytes)
}

fn verify_file_entry(entry: &ManifestFile, bytes: &[u8]) -> Result<(), ContractError> {
    let actual_length = u64::try_from(bytes.len()).map_err(|_| ContractError::InvalidContract {
        reason: format!("embedded file length does not fit u64: {}", entry.path),
    })?;
    if entry.byte_length != actual_length {
        return Err(ContractError::FileLengthMismatch {
            path: entry.path.clone(),
            expected: entry.byte_length,
            actual: actual_length,
        });
    }
    if entry.file_sha256 != sha256_hex(bytes) {
        return Err(ContractError::FileHashMismatch {
            path: entry.path.clone(),
        });
    }
    Ok(())
}

fn is_root_notice(path: &str) -> bool {
    matches!(path, "NOTICE" | "THIRD_PARTY_NOTICES.md")
}

fn require_directory(path: &Path, display_path: &str) -> Result<(), ContractError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ContractError::DirectoryIo {
        path: display_path.to_owned(),
        reason: error.kind().to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return invalid(format!(
            "bundle path is not a non-symlink directory: {display_path}"
        ));
    }
    Ok(())
}

fn find_manifest(bundle_root: &Path) -> Result<PathBuf, ContractError> {
    let contracts = bundle_root.join("contracts");
    require_directory(&contracts, "contracts")?;
    let mut manifests = Vec::new();
    let entries = fs::read_dir(&contracts).map_err(|error| ContractError::DirectoryIo {
        path: "contracts".to_owned(),
        reason: error.kind().to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| ContractError::DirectoryIo {
            path: "contracts".to_owned(),
            reason: error.kind().to_string(),
        })?;
        let file_name =
            entry
                .file_name()
                .into_string()
                .map_err(|_| ContractError::InvalidContract {
                    reason: "contracts directory contains a non-UTF-8 name".to_owned(),
                })?;
        let relative = format!("contracts/{file_name}");
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|error| ContractError::DirectoryIo {
                path: relative.clone(),
                reason: error.kind().to_string(),
            })?;
        if metadata.file_type().is_symlink() {
            return invalid(format!("bundle contains a symlink: {relative}"));
        }
        if !metadata.is_dir() {
            return invalid(format!(
                "contracts directory contains a non-directory: {relative}"
            ));
        }
        let candidate = entry.path().join("manifest.json");
        match fs::symlink_metadata(&candidate) {
            Ok(candidate_metadata)
                if candidate_metadata.is_file() && !candidate_metadata.file_type().is_symlink() =>
            {
                manifests.push(candidate)
            }
            Ok(_) => {
                return invalid(format!(
                    "manifest is not a regular file: {relative}/manifest.json"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ContractError::DirectoryIo {
                    path: format!("{relative}/manifest.json"),
                    reason: error.kind().to_string(),
                });
            }
        }
    }
    if manifests.len() != 1 {
        return invalid("bundle must contain exactly one contract manifest");
    }
    Ok(manifests.remove(0))
}

fn read_regular_file(path: &Path, display_path: &str) -> Result<Vec<u8>, ContractError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ContractError::DirectoryIo {
        path: display_path.to_owned(),
        reason: error.kind().to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return invalid(format!("bundle path is not a regular file: {display_path}"));
    }
    fs::read(path).map_err(|error| ContractError::DirectoryIo {
        path: display_path.to_owned(),
        reason: error.kind().to_string(),
    })
}

fn collect_bundle_files(bundle_root: &Path) -> Result<BTreeSet<String>, ContractError> {
    fn visit(
        bundle_root: &Path,
        directory: &Path,
        paths: &mut BTreeSet<String>,
    ) -> Result<(), ContractError> {
        let display_directory = relative_path(bundle_root, directory)?;
        let entries = fs::read_dir(directory).map_err(|error| ContractError::DirectoryIo {
            path: display_directory,
            reason: error.kind().to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| ContractError::DirectoryIo {
                path: relative_path(bundle_root, directory).unwrap_or_else(|_| ".".to_owned()),
                reason: error.kind().to_string(),
            })?;
            let path = entry.path();
            let relative = relative_path(bundle_root, &path)?;
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| ContractError::DirectoryIo {
                    path: relative.clone(),
                    reason: error.kind().to_string(),
                })?;
            if metadata.file_type().is_symlink() {
                return invalid(format!("bundle contains a symlink: {relative}"));
            }
            if metadata.is_dir() {
                visit(bundle_root, &path, paths)?;
            } else if metadata.is_file() {
                paths.insert(relative);
            } else {
                return invalid(format!("bundle contains a special file: {relative}"));
            }
        }
        Ok(())
    }

    let mut paths = BTreeSet::new();
    visit(bundle_root, bundle_root, &mut paths)?;
    Ok(paths)
}

fn relative_path(bundle_root: &Path, path: &Path) -> Result<String, ContractError> {
    let relative = path
        .strip_prefix(bundle_root)
        .map_err(|_| ContractError::InvalidContract {
            reason: "bundle path escapes root".to_owned(),
        })?;
    let text = relative
        .to_str()
        .ok_or_else(|| ContractError::InvalidContract {
            reason: "bundle contains a non-UTF-8 path".to_owned(),
        })?;
    Ok(text.replace(std::path::MAIN_SEPARATOR, "/"))
}

fn manifest_file<'a>(
    manifest: &'a ContractManifest,
    path: &str,
) -> Result<&'a ManifestFile, ContractError> {
    manifest
        .files
        .iter()
        .find(|entry| entry.path == path)
        .ok_or_else(|| ContractError::MissingManifestFile {
            path: path.to_owned(),
        })
}

fn contract_path(contract_id: &str, basename: &str) -> Result<String, ContractError> {
    validate_contract_id(contract_id)?;
    Ok(format!("contracts/{contract_id}/{basename}"))
}

fn validate_contract_id(contract_id: &str) -> Result<(), ContractError> {
    if contract_id.is_empty()
        || contract_id.starts_with('-')
        || contract_id.ends_with('-')
        || !contract_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return invalid("contract_id must be lowercase ASCII letters, digits, and inner hyphens");
    }
    Ok(())
}

fn validate_contract_path(contract_id: &str, path: &str) -> Result<(), ContractError> {
    let prefix = format!("contracts/{contract_id}/");
    if !path.starts_with(&prefix)
        || path.len() == prefix.len()
        || path.contains('\\')
        || path.contains("//")
        || path.split('/').any(|part| part == "." || part == "..")
    {
        return invalid(format!("invalid manifest path: {path}"));
    }
    Ok(())
}

fn validate_hashed_text(field: &str, text: &HashedText) -> Result<(), ContractError> {
    validate_sha256(field, &text.utf8_sha256)?;
    if sha256_hex(text.text.as_bytes()) != text.utf8_sha256 {
        return invalid(format!("{field} utf8_sha256 mismatch"));
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), ContractError> {
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

fn validate_closed_identifier(field: &str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return invalid(format!(
            "{field} must be lowercase ASCII letters, digits, and inner hyphens"
        ));
    }
    Ok(())
}

fn require_equal(field: &str, actual: &str, expected: &str) -> Result<(), ContractError> {
    if actual != expected {
        return invalid(format!("{field} must equal {expected}"));
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ContractError> {
    if value.is_empty() {
        return invalid(format!("{field} must not be empty"));
    }
    Ok(())
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, ContractError> {
    Err(ContractError::InvalidContract {
        reason: reason.into(),
    })
}

fn ordered_entries_sha256(entries: &[ManifestFile]) -> Result<String, ContractError> {
    let value = serde_json::to_value(entries).map_err(|error| ContractError::InvalidContract {
        reason: format!("cannot serialize ordered manifest entries: {error}"),
    })?;
    value_sha256(&value)
}

fn value_sha256(value: &Value) -> Result<String, ContractError> {
    let bytes = serde_json::to_vec(value).map_err(|error| ContractError::InvalidContract {
        reason: format!("cannot canonicalize JSON value: {error}"),
    })?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn parse_canonical_json<T: DeserializeOwned>(
    bytes: &[u8],
    artifact: &str,
) -> Result<(T, Value), ContractError> {
    if bytes.len() < 2 || !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].ends_with(b"\n") {
        return Err(ContractError::InvalidJson {
            artifact: artifact.to_owned(),
            reason: "expected exactly one final LF".to_owned(),
        });
    }
    let payload = &bytes[..bytes.len() - 1];
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let no_duplicates = NoDuplicateValue::deserialize(&mut deserializer).map_err(|error| {
        ContractError::InvalidJson {
            artifact: artifact.to_owned(),
            reason: error.to_string(),
        }
    })?;
    deserializer
        .end()
        .map_err(|error| ContractError::InvalidJson {
            artifact: artifact.to_owned(),
            reason: error.to_string(),
        })?;
    let value = no_duplicates.0;
    let typed =
        serde_json::from_value(value.clone()).map_err(|error| ContractError::InvalidJson {
            artifact: artifact.to_owned(),
            reason: error.to_string(),
        })?;
    Ok((typed, value))
}

#[derive(Serialize)]
struct LocalContractSetRow<'a> {
    path: &'a str,
    byte_length: u64,
    file_sha256: String,
}

fn local_contract_set_sha256<'a>(files: [(&'a str, &'a [u8]); 3]) -> Result<String, ContractError> {
    let mut rows = Vec::with_capacity(files.len());
    for (path, bytes) in files {
        rows.push(LocalContractSetRow {
            path,
            byte_length: u64::try_from(bytes.len()).map_err(|_| {
                ContractError::InvalidContract {
                    reason: format!("local contract file length does not fit u64: {path}"),
                }
            })?,
            file_sha256: sha256_hex(bytes),
        });
    }
    let bytes = serde_json::to_vec(&rows).map_err(|error| ContractError::InvalidContract {
        reason: format!("cannot serialize local contract set: {error}"),
    })?;
    Ok(sha256_hex(&bytes))
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a duplicate-key-free JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        let number =
            serde_json::Number::from_f64(value).ok_or_else(|| E::custom("non-finite number"))?;
        Ok(NoDuplicateValue(Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(NoDuplicateValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        NoDuplicateValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<NoDuplicateValue>()? {
            values.push(value.0);
        }
        Ok(NoDuplicateValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = object.next_entry::<String, NoDuplicateValue>()? {
            if values.insert(key.clone(), value.0).is_some() {
                return Err(A::Error::custom(format!("duplicate JSON key: {key}")));
            }
        }
        Ok(NoDuplicateValue(Value::Object(
            values.into_iter().collect::<Map<String, Value>>(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::{Value, json};

    use super::{
        ContractBundle, ContractError, EffectClass, ManifestFile, TOOL_ORDER,
        ordered_entries_sha256, sha256_hex, validate_runtime_media_capabilities, value_sha256,
    };

    const CONTRACT_ID: &str = "synthetic-v1";
    const FROZEN_LEGACY_DELTA: &[u8] =
        b"{\"contract_id\":\"synthetic-v1\",\"schema_version\":\"contract-delta-v1\"}\n";

    struct SyntheticBundle {
        manifest: Vec<u8>,
        effective: Vec<u8>,
        profile: Vec<u8>,
        delta: Vec<u8>,
        notice: Vec<u8>,
        third_party_notices: Vec<u8>,
    }

    struct SyntheticDirectory {
        path: PathBuf,
    }

    impl Drop for SyntheticDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn json_file(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).expect("serialize synthetic JSON");
        bytes.push(b'\n');
        bytes
    }

    fn synthetic_bundle() -> SyntheticBundle {
        let prompt = "You are a synthetic first-party test agent.";
        let wrapper = "<user_query>\n{{USER_QUERY}}\n</user_query>";
        let tools = TOOL_ORDER
            .iter()
            .enumerate()
            .map(|(ordinal, name)| {
                json!({
                    "ordinal": ordinal,
                    "contract_tool_id": format!("synthetic:{name}"),
                    "provider_name": name,
                    "description": format!("Synthetic definition for {name}."),
                    "input_schema": {
                        "additionalProperties": false,
                        "properties": {},
                        "required": [],
                        "type": "object"
                    },
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
                "current_date": "2025-01-15",
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
        let effective_hash = sha256_hex(&effective);
        let tools_hash =
            value_sha256(effective_value.get("tools").expect("synthetic tools")).unwrap();
        let delta = b"{\"schema_version\":\"contract-delta-v1\"}\n".to_vec();
        let delta_hash = sha256_hex(&delta);
        let notice = b"Synthetic first-party NOTICE.\n".to_vec();
        let third_party_notices = b"Synthetic first-party third-party notices.\n".to_vec();
        let profile_value = json!({
            "schema_version": "agent-profile-v1",
            "profile_id": "synthetic-profile-v1",
            "contract_id": CONTRACT_ID,
            "provider": {
                "provider_id": "xai",
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
                "effective_contract_file_sha256": effective_hash,
                "system_prompt_utf8_sha256": sha256_hex(prompt.as_bytes()),
                "ordered_tools_value_sha256": tools_hash,
                "contract_delta_file_sha256": delta_hash
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
                "read_only_parallelism": 4,
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
                "background_output_wait_max_ms": 600000,
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
                "max_events_per_run": 16384,
                "max_event_line_bytes": 2097152,
                "max_event_log_bytes": 67108864,
                "max_blobs_per_run": 4096,
                "max_blob_bytes": 16777216,
                "max_blob_bytes_per_run": 268435456,
                "max_agent_run_record_bytes": 16777216,
                "max_trajectory_bytes": 33554432,
                "max_published_agent_bytes": 268435456,
                "max_live_stdout_mirror_bytes": 16777216
            },
            "schema_versions": {
                "contract_manifest": "contract-manifest-v1",
                "effective_contract": "effective-contract-v1",
                "agent_profile": "agent-profile-v1",
                "contract_delta": "contract-delta-v1"
            }
        });
        let profile = json_file(&profile_value);
        let files = vec![
            ManifestFile {
                path: "NOTICE".to_owned(),
                schema_id: "text-v1".to_owned(),
                byte_length: notice.len() as u64,
                file_sha256: sha256_hex(&notice),
            },
            ManifestFile {
                path: "THIRD_PARTY_NOTICES.md".to_owned(),
                schema_id: "text-v1".to_owned(),
                byte_length: third_party_notices.len() as u64,
                file_sha256: sha256_hex(&third_party_notices),
            },
            ManifestFile {
                path: format!("contracts/{CONTRACT_ID}/agent-profile.json"),
                schema_id: "agent-profile-v1".to_owned(),
                byte_length: profile.len() as u64,
                file_sha256: sha256_hex(&profile),
            },
            ManifestFile {
                path: format!("contracts/{CONTRACT_ID}/contract-delta.json"),
                schema_id: "contract-delta-v1".to_owned(),
                byte_length: delta.len() as u64,
                file_sha256: delta_hash,
            },
            ManifestFile {
                path: format!("contracts/{CONTRACT_ID}/effective-contract.json"),
                schema_id: "effective-contract-v1".to_owned(),
                byte_length: effective.len() as u64,
                file_sha256: effective_hash,
            },
        ];
        let bundle_hash = ordered_entries_sha256(&files).expect("hash synthetic entries");
        let manifest = json_file(
            &serde_json::to_value(super::ContractManifest {
                schema_version: "contract-manifest-v1".to_owned(),
                contract_id: CONTRACT_ID.to_owned(),
                contract_bundle_sha256: bundle_hash,
                files,
            })
            .expect("serialize synthetic manifest"),
        );

        SyntheticBundle {
            manifest,
            effective,
            profile,
            delta,
            notice,
            third_party_notices,
        }
    }

    fn load(bundle: &SyntheticBundle) -> Result<ContractBundle, ContractError> {
        ContractBundle::from_embedded_bytes(&bundle.manifest, &bundle.effective, &bundle.profile)
    }

    fn mutate_json(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(bytes).expect("parse synthetic fixture");
        mutate(&mut value);
        json_file(&value)
    }

    fn rebuild_manifest(bundle: &mut SyntheticBundle) {
        let mut manifest: Value =
            serde_json::from_slice(&bundle.manifest).expect("parse synthetic manifest");
        let files = manifest
            .get_mut("files")
            .and_then(Value::as_array_mut)
            .expect("synthetic files");
        for entry in files {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .expect("synthetic path");
            let bytes = if path.ends_with("effective-contract.json") {
                &bundle.effective
            } else if path.ends_with("agent-profile.json") {
                &bundle.profile
            } else if path.ends_with("contract-delta.json") {
                &bundle.delta
            } else if path == "NOTICE" {
                &bundle.notice
            } else if path == "THIRD_PARTY_NOTICES.md" {
                &bundle.third_party_notices
            } else {
                continue;
            };
            entry["byte_length"] = json!(bytes.len());
            entry["file_sha256"] = json!(sha256_hex(bytes));
        }
        let typed_files = serde_json::from_value::<Vec<ManifestFile>>(
            manifest.get("files").expect("synthetic files").clone(),
        )
        .expect("typed synthetic files");
        manifest["contract_bundle_sha256"] =
            json!(ordered_entries_sha256(&typed_files).expect("hash synthetic files"));
        bundle.manifest = json_file(&manifest);
    }

    fn write_bundle_directory(bundle: &SyntheticBundle) -> SyntheticDirectory {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nano-types-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create synthetic bundle root");
        let manifest_path = path
            .join("contracts")
            .join(CONTRACT_ID)
            .join("manifest.json");
        fs::create_dir_all(manifest_path.parent().expect("manifest parent"))
            .expect("create synthetic contract directory");
        fs::write(&manifest_path, &bundle.manifest).expect("write synthetic manifest");
        let manifest: super::ContractManifest =
            serde_json::from_slice(&bundle.manifest).expect("parse typed synthetic manifest");
        for entry in manifest.files {
            let bytes = if entry.path.ends_with("effective-contract.json") {
                &bundle.effective
            } else if entry.path.ends_with("agent-profile.json") {
                &bundle.profile
            } else if entry.path.ends_with("contract-delta.json") {
                &bundle.delta
            } else if entry.path == "NOTICE" {
                &bundle.notice
            } else if entry.path == "THIRD_PARTY_NOTICES.md" {
                &bundle.third_party_notices
            } else {
                panic!("unexpected synthetic manifest path: {}", entry.path);
            };
            let destination = path.join(&entry.path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).expect("create synthetic artifact parent");
            }
            fs::write(destination, bytes).expect("write synthetic artifact");
        }
        SyntheticDirectory { path }
    }

    fn synthetic_local_bundle() -> SyntheticBundle {
        let mut bundle = synthetic_bundle();
        bundle.delta = FROZEN_LEGACY_DELTA.to_vec();
        let delta_hash = sha256_hex(&bundle.delta);
        bundle.profile = mutate_json(&bundle.profile, |profile| {
            profile["contract_bindings"]["contract_delta_file_sha256"] = json!(delta_hash);
        });
        bundle
    }

    fn set_local_delta(bundle: &mut SyntheticBundle, delta: &[u8]) {
        bundle.delta = delta.to_vec();
        let delta_hash = sha256_hex(&bundle.delta);
        bundle.profile = mutate_json(&bundle.profile, |profile| {
            profile["contract_bindings"]["contract_delta_file_sha256"] = json!(delta_hash);
        });
    }

    fn media_bundle() -> SyntheticBundle {
        let mut bundle = synthetic_bundle();
        let mut effective: Value =
            serde_json::from_slice(&bundle.effective).expect("parse synthetic effective");
        effective["tools"][1]["input_schema"] = json!({
            "additionalProperties": false,
            "properties": {
                "target_file": {"type": "string"}
            },
            "required": ["target_file"],
            "type": "object"
        });
        bundle.effective = json_file(&effective);
        let effective_hash = sha256_hex(&bundle.effective);
        let tools_hash = value_sha256(effective.get("tools").expect("synthetic tools")).unwrap();
        bundle.profile = mutate_json(&bundle.profile, |profile| {
            profile["provider"]["model"] = json!("grok-4.5");
            profile["context"]["max_request_body_bytes"] = json!(16 * 1024 * 1024);
            profile["tools"]["read_file_media_enabled"] = json!(true);
            profile["contract_bindings"]["effective_contract_file_sha256"] = json!(effective_hash);
            profile["contract_bindings"]["ordered_tools_value_sha256"] = json!(tools_hash);
        });
        rebuild_manifest(&mut bundle);
        bundle
    }

    fn write_local_contract_directory(bundle: &SyntheticBundle) -> SyntheticDirectory {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(10_000);
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nano-types-local-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create local contract directory");
        fs::write(path.join("effective-contract.json"), &bundle.effective)
            .expect("write local effective");
        fs::write(path.join("agent-profile.json"), &bundle.profile).expect("write local profile");
        fs::write(path.join("contract-delta.json"), &bundle.delta).expect("write local delta");
        SyntheticDirectory { path }
    }

    fn rewrite_directory_manifest(directory: &Path, mutate: impl FnOnce(&mut Value)) {
        let manifest_path = directory
            .join("contracts")
            .join(CONTRACT_ID)
            .join("manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        mutate(&mut manifest);
        let files = serde_json::from_value::<Vec<ManifestFile>>(
            manifest.get("files").expect("manifest files").clone(),
        )
        .expect("typed manifest files");
        manifest["contract_bundle_sha256"] =
            json!(ordered_entries_sha256(&files).expect("hash manifest files"));
        fs::write(manifest_path, json_file(&manifest)).expect("rewrite manifest");
    }

    #[test]
    fn loads_strict_synthetic_bundle_and_exposes_immutable_contract() {
        let bundle = load(&synthetic_bundle()).expect("load synthetic contract");
        assert_eq!(bundle.manifest().contract_id, CONTRACT_ID);
        assert_eq!(bundle.effective().ordered_tools().len(), 8);
        assert_eq!(
            bundle.effective().ordered_tools()[0].provider_name,
            "run_terminal_command"
        );
        assert_eq!(
            bundle.effective().effect_for("synthetic:read_file"),
            Some(EffectClass::ReadOnly)
        );
        assert_eq!(
            bundle
                .effective()
                .effect_for("synthetic:run_terminal_command"),
            Some(EffectClass::Mutating)
        );
        assert_eq!(bundle.effective().effect_for("missing"), None);
        assert_eq!(bundle.profile().provider.retry_max, 0);
        assert_eq!(bundle.bundle_sha256().len(), 64);
    }

    #[test]
    fn directory_loader_commits_root_notices_and_loads_every_manifest_file() {
        let synthetic = synthetic_bundle();
        let directory = write_bundle_directory(&synthetic);
        let bundle =
            ContractBundle::from_directory(&directory.path).expect("load promoted directory");
        assert_eq!(bundle.manifest().contract_id, CONTRACT_ID);
        assert_eq!(
            fs::read(directory.path.join("NOTICE")).expect("read committed NOTICE"),
            synthetic.notice
        );
        assert_eq!(
            fs::read(directory.path.join("THIRD_PARTY_NOTICES.md"))
                .expect("read committed third-party notices"),
            synthetic.third_party_notices
        );
    }

    #[test]
    fn directory_loader_rejects_wrong_contract_path_and_missing_profile() {
        let wrong_path = write_bundle_directory(&synthetic_bundle());
        let wrong_effective = "contracts/wrong-v1/effective-contract.json".to_owned();
        let original_effective = format!("contracts/{CONTRACT_ID}/effective-contract.json");
        let wrong_destination = wrong_path.path.join(&wrong_effective);
        fs::create_dir_all(wrong_destination.parent().expect("wrong path parent"))
            .expect("create wrong path parent");
        fs::rename(
            wrong_path.path.join(&original_effective),
            &wrong_destination,
        )
        .expect("move effective to wrong contract path");
        rewrite_directory_manifest(&wrong_path.path, |manifest| {
            let files = manifest["files"].as_array_mut().expect("manifest files");
            let row = files
                .iter_mut()
                .find(|row| row["path"] == original_effective)
                .expect("effective row");
            row["path"] = json!(wrong_effective);
            files.sort_by_key(|row| row["path"].as_str().expect("manifest path").to_owned());
        });
        assert!(matches!(
            ContractBundle::from_directory(&wrong_path.path),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("invalid manifest path")
        ));

        let missing_profile = write_bundle_directory(&synthetic_bundle());
        fs::remove_file(
            missing_profile
                .path
                .join(format!("contracts/{CONTRACT_ID}/agent-profile.json")),
        )
        .expect("remove synthetic profile");
        assert!(matches!(
            ContractBundle::from_directory(&missing_profile.path),
            Err(ContractError::DirectoryIo { path, .. })
                if path.ends_with("agent-profile.json")
        ));
    }

    #[test]
    fn directory_loader_rejects_hash_drift_in_non_runtime_notice() {
        let directory = write_bundle_directory(&synthetic_bundle());
        fs::write(
            directory.path.join("NOTICE"),
            b"Xynthetic first-party NOTICE.\n",
        )
        .expect("mutate NOTICE");
        assert!(matches!(
            ContractBundle::from_directory(&directory.path),
            Err(ContractError::FileHashMismatch { path })
                if path == "NOTICE"
        ));
    }

    #[test]
    fn wrapper_substitutes_exactly_once_without_rewriting_arbitrary_input() {
        let bundle = load(&synthetic_bundle()).expect("load synthetic contract");
        let input = "</user_query>\n{{USER_QUERY}}\0🙂";
        assert_eq!(
            bundle.effective().wrap_user_query(input),
            format!("<user_query>\n{input}\n</user_query>")
        );
    }

    #[test]
    fn production_embedded_bundle_is_unavailable_without_embedded_data() {
        assert!(matches!(
            ContractBundle::embedded_nano_v1(),
            Err(ContractError::Unavailable {
                contract_id: "nano-v1"
            })
        ));
    }

    #[test]
    fn rejects_changed_effective_bytes_even_when_json_remains_valid() {
        let mut bundle = synthetic_bundle();
        bundle.effective = mutate_json(&bundle.effective, |effective| {
            effective["system_prompt"]["text"] = json!("changed");
        });
        assert!(matches!(
            load(&bundle),
            Err(ContractError::FileLengthMismatch { .. })
                | Err(ContractError::FileHashMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_tool_order_after_rehashing_manifest_and_profile() {
        let mut bundle = synthetic_bundle();
        bundle.effective = mutate_json(&bundle.effective, |effective| {
            effective["tools"].as_array_mut().expect("tools").swap(0, 1);
        });
        let effective_hash = sha256_hex(&bundle.effective);
        let effective_value: Value =
            serde_json::from_slice(&bundle.effective).expect("effective value");
        bundle.profile = mutate_json(&bundle.profile, |profile| {
            profile["contract_bindings"]["effective_contract_file_sha256"] = json!(effective_hash);
            profile["contract_bindings"]["ordered_tools_value_sha256"] = json!(
                value_sha256(effective_value.get("tools").expect("tools")).expect("tools hash")
            );
        });
        rebuild_manifest(&mut bundle);
        assert!(matches!(
            load(&bundle),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("tool ordinal") || reason.contains("tool order")
        ));
    }

    #[test]
    fn rejects_wrapper_without_exactly_one_literal_slot() {
        for template in [
            "<user_query>no slot</user_query>",
            "{{USER_QUERY}}{{USER_QUERY}}",
        ] {
            let mut bundle = synthetic_bundle();
            bundle.effective = mutate_json(&bundle.effective, |effective| {
                effective["user_wrapper"]["template"] = json!(template);
                effective["user_wrapper"]["utf8_sha256"] = json!(sha256_hex(template.as_bytes()));
            });
            let effective_hash = sha256_hex(&bundle.effective);
            bundle.profile = mutate_json(&bundle.profile, |profile| {
                profile["contract_bindings"]["effective_contract_file_sha256"] =
                    json!(effective_hash);
            });
            rebuild_manifest(&mut bundle);
            assert!(matches!(
                load(&bundle),
                Err(ContractError::InvalidContract { reason })
                    if reason.contains("exactly one literal payload slot")
            ));
        }
    }

    #[test]
    fn rejects_unknown_and_duplicate_json_fields() {
        let mut unknown = synthetic_bundle();
        unknown.effective = mutate_json(&unknown.effective, |effective| {
            effective["unknown"] = json!(true);
        });
        let hash = sha256_hex(&unknown.effective);
        unknown.profile = mutate_json(&unknown.profile, |profile| {
            profile["contract_bindings"]["effective_contract_file_sha256"] = json!(hash);
        });
        rebuild_manifest(&mut unknown);
        assert!(matches!(
            load(&unknown),
            Err(ContractError::InvalidJson { .. })
        ));

        let bundle = synthetic_bundle();
        let duplicate = String::from_utf8(bundle.profile.clone())
            .expect("synthetic profile is UTF-8")
            .replacen(
                "{\"artifacts\":",
                "{\"profile_id\":\"duplicate\",\"artifacts\":",
                1,
            );
        let mut duplicate_bundle = bundle;
        duplicate_bundle.profile = duplicate.into_bytes();
        rebuild_manifest(&mut duplicate_bundle);
        assert!(matches!(
            load(&duplicate_bundle),
            Err(ContractError::InvalidJson { reason, .. }) if reason.contains("duplicate JSON key")
        ));
    }

    #[test]
    fn rejects_manifest_commitment_and_profile_binding_drift() {
        let mut bad_manifest = synthetic_bundle();
        bad_manifest.manifest = mutate_json(&bad_manifest.manifest, |manifest| {
            manifest["contract_bundle_sha256"] = json!("0".repeat(64));
        });
        assert!(matches!(
            load(&bad_manifest),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("contract_bundle_sha256")
        ));

        let mut bad_profile = synthetic_bundle();
        bad_profile.profile = mutate_json(&bad_profile.profile, |profile| {
            profile["contract_bindings"]["system_prompt_utf8_sha256"] = json!("0".repeat(64));
        });
        rebuild_manifest(&mut bad_profile);
        assert!(matches!(
            load(&bad_profile),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("system prompt hash binding")
        ));
    }

    #[test]
    fn profile_accepts_any_positive_background_wait_cap() {
        for allowed in [1, 30_000, 45_000, 599_999, 600_000, 600_001] {
            let mut bundle = synthetic_bundle();
            bundle.profile = mutate_json(&bundle.profile, |profile| {
                profile["tools"]["background_output_wait_max_ms"] = json!(allowed);
            });
            rebuild_manifest(&mut bundle);
            load(&bundle).expect("bounded background wait cap");
        }
        let mut rejected = synthetic_bundle();
        rejected.profile = mutate_json(&rejected.profile, |profile| {
            profile["tools"]["background_output_wait_max_ms"] = json!(0);
        });
        rebuild_manifest(&mut rejected);
        assert!(matches!(
            load(&rejected),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("background output wait maximum")
        ));

        let mut unknown_delta_schema = synthetic_bundle();
        unknown_delta_schema.profile = mutate_json(&unknown_delta_schema.profile, |profile| {
            profile["schema_versions"]["contract_delta"] = json!("contract-delta-v2");
        });
        rebuild_manifest(&mut unknown_delta_schema);
        assert!(matches!(
            load(&unknown_delta_schema),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("profile contract_delta schema")
        ));
    }

    #[test]
    fn read_file_media_is_off_by_default_and_requires_semantic_safety_bounds() {
        let default = load(&synthetic_bundle()).expect("default profile");
        assert!(!default.profile().tools.read_file_media_enabled);

        let mut incomplete_media = synthetic_bundle();
        incomplete_media.profile = mutate_json(&incomplete_media.profile, |profile| {
            profile["tools"]["read_file_media_enabled"] = json!(true);
            profile["provider"]["model"] = json!("grok-4.5");
            profile["context"]["max_request_body_bytes"] = json!(16 * 1024 * 1024);
        });
        rebuild_manifest(&mut incomplete_media);
        assert!(matches!(
            load(&incomplete_media),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("media path schema")
        ));

        let enabled = media_bundle();
        load(&enabled).expect("bounded media profile");
        let profile = serde_json::from_slice::<super::AgentProfile>(&enabled.profile)
            .expect("typed media profile");
        let effective = serde_json::from_slice::<super::EffectiveContract>(&enabled.effective)
            .expect("typed media contract");
        validate_runtime_media_capabilities(&effective, &profile).expect("media safety bounds");

        let mut alternate = profile.clone();
        alternate.provider.model = "future-xai-model".to_owned();
        alternate.context.max_request_body_bytes = 12 * 1024 * 1024;
        alternate.tools.background_output_wait_max_ms = 45_000;
        validate_runtime_media_capabilities(&effective, &alternate)
            .expect("experiment choices do not define media safety");

        for (section, field, invalid_value) in [
            ("provider", "provider_id", json!("other")),
            ("provider", "api", json!("other")),
            ("provider", "store", json!(true)),
            ("provider", "stream", json!(false)),
            ("context", "max_request_body_bytes", json!(1_048_576)),
            ("tools", "max_read_or_write_bytes", json!(4_194_303)),
        ] {
            let mut invalid = media_bundle();
            invalid.profile = mutate_json(&invalid.profile, |profile| {
                profile[section][field] = invalid_value;
            });
            let profile = serde_json::from_slice::<super::AgentProfile>(&invalid.profile)
                .expect("typed invalid media profile");
            let effective = serde_json::from_slice::<super::EffectiveContract>(&invalid.effective)
                .expect("typed media contract");
            assert!(matches!(
                validate_runtime_media_capabilities(&effective, &profile),
                Err(ContractError::InvalidContract { .. })
            ));
        }
    }

    #[test]
    fn profile_requires_terminal_budget() {
        for (field, value, expected) in [
            (
                "terminalization_reserve_sec",
                json!(0),
                "terminalization reserve",
            ),
            (
                "min_provider_send_window_sec",
                json!(0),
                "provider send window",
            ),
        ] {
            let mut bundle = synthetic_bundle();
            bundle.profile = mutate_json(&bundle.profile, |profile| {
                profile["deadlines"][field] = value;
            });
            rebuild_manifest(&mut bundle);
            assert!(matches!(
                load(&bundle),
                Err(ContractError::InvalidContract { reason }) if reason.contains(expected)
            ));
        }
    }

    #[test]
    fn sha256_implementation_matches_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn local_loader_binds_exact_three_runtime_inputs() {
        let legacy = synthetic_local_bundle();
        assert_eq!(legacy.delta, FROZEN_LEGACY_DELTA);
        let directory = write_local_contract_directory(&legacy);
        let contract = super::LocalContract::load(&directory.path).expect("load local contract");
        assert_eq!(contract.effective().contract_id, CONTRACT_ID);
        assert_eq!(contract.profile().profile_id, "synthetic-profile-v1");
        assert_eq!(contract.contract_set_sha256().len(), 64);

        assert!(matches!(
            super::LocalContract::load(Path::new("relative-contract")),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("must be absolute")
        ));
    }

    #[test]
    fn local_loader_accepts_a_safe_media_profile() {
        let mut profile = media_bundle();
        set_local_delta(&mut profile, b"{}\n");
        let directory = write_local_contract_directory(&profile);
        let loaded =
            super::LocalContract::load(&directory.path).expect("load ordinary runtime profile");
        assert!(loaded.profile().tools.read_file_media_enabled);
    }

    #[test]
    fn local_loader_rejects_unsafe_profile_values_without_hash_rebinding() {
        for (section, field) in [
            ("deadlines", "terminalization_reserve_sec"),
            ("tools", "max_path_bytes"),
            ("process", "kill_confirmation_timeout_ms"),
        ] {
            let mut profile = media_bundle();
            set_local_delta(&mut profile, b"{}\n");
            profile.profile = mutate_json(&profile.profile, |value| {
                value[section][field] = json!(0);
            });
            let directory = write_local_contract_directory(&profile);
            assert!(matches!(
                super::LocalContract::load(&directory.path),
                Err(ContractError::InvalidContract { .. })
            ));
        }
    }

    #[test]
    fn local_loader_rejects_stale_exact_byte_bindings() {
        let mut stale_effective = synthetic_local_bundle();
        stale_effective.effective = mutate_json(&stale_effective.effective, |effective| {
            let prompt = "Changed but internally hash-consistent prompt.";
            effective["system_prompt"]["text"] = json!(prompt);
            effective["system_prompt"]["utf8_sha256"] = json!(sha256_hex(prompt.as_bytes()));
        });
        let directory = write_local_contract_directory(&stale_effective);
        assert!(matches!(
            super::LocalContract::load(&directory.path),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("effective contract hash binding")
        ));

        let mut stale_delta = synthetic_local_bundle();
        stale_delta.delta = b"{\"changed\":true}\n".to_vec();
        let directory = write_local_contract_directory(&stale_delta);
        assert!(matches!(
            super::LocalContract::load(&directory.path),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("contract delta hash binding")
        ));

        let mut stale_prompt_binding = synthetic_local_bundle();
        stale_prompt_binding.profile = mutate_json(&stale_prompt_binding.profile, |profile| {
            profile["contract_bindings"]["system_prompt_utf8_sha256"] = json!("0".repeat(64));
        });
        let directory = write_local_contract_directory(&stale_prompt_binding);
        assert!(matches!(
            super::LocalContract::load(&directory.path),
            Err(ContractError::InvalidContract { reason })
                if reason.contains("system prompt hash binding")
        ));
    }

    #[test]
    fn tracked_v10_3_contract_has_exact_three_file_identity() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("canonical repository root");
        let directory = root.join("contracts/nano-v1");
        assert!(!directory.join("contract-set.json").exists());
        let contract = super::LocalContract::load(&directory).expect("load tracked nano-v1");
        assert_eq!(
            contract.contract_set_sha256(),
            "38971deb36eb777303169e9edad212b0baf4788556d8416c54ef69c5c894f28d"
        );
        assert_eq!(
            contract.effective().system_prompt.utf8_sha256,
            "7006b1c3da050b89c6eb15551b470da783e54243e94771783fabb64c0a09f37f"
        );
        assert!(
            contract
                .effective()
                .system_prompt
                .text
                .contains("<workspace_integrity>")
        );
    }
}
