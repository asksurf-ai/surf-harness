//! Immutable host deadline receipt loading and monotonic cutoff binding.
//!
//! An integration mints the receipt beside its outer execution timeout. This
//! module consumes that root without knowing which host framework owns it and
//! never derives a fresh full-run timeout.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use nano_types::contract::AgentProfile;
use nano_types::run_spec::RunSpec;
use rustix::time::{ClockId, clock_gettime};
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const DEADLINE_RECEIPT_SCHEMA: &str = "nano-run-deadline-receipt-v1";
pub const DEADLINE_SCHEMA: &str = "nano-run-deadline-v1";
pub const DEADLINE_RECEIPT_FILE: &str = "deadline.json";

pub const CLEANUP_RESERVE_MS: u64 = 20_000;
pub const TERMINALIZATION_RESERVE_MS: u64 = 15_000;
pub const PROVIDER_SEND_RESERVE_MS: u64 = 30_000;
pub const PROCESS_SETTLEMENT_RESERVE_MS: u64 = 10_000;

const NANOS_PER_MILLISECOND: u64 = 1_000_000;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_IDENTITY_BYTES: usize = 512;

/// Frozen reserve values carried by the launch receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlineReserves {
    pub cleanup_ms: u64,
    pub terminalization_ms: u64,
    pub provider_send_ms: u64,
    pub process_settlement_ms: u64,
}

impl DeadlineReserves {
    pub const FROZEN: Self = Self {
        cleanup_ms: CLEANUP_RESERVE_MS,
        terminalization_ms: TERMINALIZATION_RESERVE_MS,
        provider_send_ms: PROVIDER_SEND_RESERVE_MS,
        process_settlement_ms: PROCESS_SETTLEMENT_RESERVE_MS,
    };

    fn total_ms(self) -> Result<u64, DeadlineError> {
        self.cleanup_ms
            .checked_add(self.terminalization_ms)
            .and_then(|value| value.checked_add(self.provider_send_ms))
            .and_then(|value| value.checked_add(self.process_settlement_ms))
            .ok_or(DeadlineError::ReserveInvalid)
    }
}

/// Absolute host `CLOCK_MONOTONIC` cutoffs, all in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlineCutoffs {
    pub actor_done_monotonic_ns: u64,
    pub tool_settled_monotonic_ns: u64,
    pub last_send_monotonic_ns: u64,
    pub runtime_final_monotonic_ns: u64,
    pub cleanup_start_monotonic_ns: u64,
    pub hard_deadline_monotonic_ns: u64,
}

/// Runtime-local `Instant` projections anchored to one `CLOCK_MONOTONIC` read.
#[derive(Clone, Copy, Debug)]
pub struct DeadlineInstants {
    pub actor_done: Instant,
    pub tool_settled: Instant,
    pub last_send: Instant,
    pub runtime_final: Instant,
    pub cleanup_start: Instant,
    pub hard_deadline: Instant,
}

/// A fully validated, identity-bound launch deadline.
#[derive(Clone, Debug)]
pub struct DeadlineContext {
    pub cutoffs: DeadlineCutoffs,
    pub instants: DeadlineInstants,
    pub reserves: DeadlineReserves,
    pub receipt_sha256: String,
    pub observed_monotonic_ns: u64,
}

impl DeadlineContext {
    /// Load `<RunSpec.artifact_dir>/deadline.json` without following a final
    /// symlink, validate every binding, then project its absolute cutoffs onto
    /// Rust `Instant`s using `CLOCK_MONOTONIC`.
    pub fn load(
        spec: &RunSpec,
        profile: &AgentProfile,
        cli_hard_deadline_monotonic_ns: u64,
    ) -> Result<Self, DeadlineError> {
        let path = spec.artifact_dir.join(DEADLINE_RECEIPT_FILE);
        let bytes = read_receipt(&path)?;
        let anchor = MonotonicAnchor::capture()?;
        let profile_reserves = reserves_from_profile(profile)?;
        Self::from_bytes_at(
            &bytes,
            spec,
            profile_reserves,
            cli_hard_deadline_monotonic_ns,
            anchor,
        )
    }

    fn from_bytes_at(
        bytes: &[u8],
        spec: &RunSpec,
        profile_reserves: DeadlineReserves,
        cli_hard_deadline_monotonic_ns: u64,
        anchor: MonotonicAnchor,
    ) -> Result<Self, DeadlineError> {
        if cli_hard_deadline_monotonic_ns == 0 {
            return Err(DeadlineError::ArgumentInvalid);
        }
        let receipt = parse_receipt(bytes)?;
        validate_receipt(
            &receipt,
            spec,
            profile_reserves,
            cli_hard_deadline_monotonic_ns,
        )?;
        if receipt.deadline.hard_deadline_monotonic_ns <= anchor.monotonic_ns {
            return Err(DeadlineError::Expired);
        }
        let cutoffs = receipt.cutoffs;
        let instants = DeadlineInstants {
            actor_done: anchor.project(cutoffs.actor_done_monotonic_ns)?,
            tool_settled: anchor.project(cutoffs.tool_settled_monotonic_ns)?,
            last_send: anchor.project(cutoffs.last_send_monotonic_ns)?,
            runtime_final: anchor.project(cutoffs.runtime_final_monotonic_ns)?,
            cleanup_start: anchor.project(cutoffs.cleanup_start_monotonic_ns)?,
            hard_deadline: anchor.project(cutoffs.hard_deadline_monotonic_ns)?,
        };
        Ok(Self {
            cutoffs,
            instants,
            reserves: receipt.reserves,
            receipt_sha256: sha256_hex(bytes),
            observed_monotonic_ns: anchor.monotonic_ns,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct MonotonicAnchor {
    monotonic_ns: u64,
    instant: Instant,
}

impl MonotonicAnchor {
    fn capture() -> Result<Self, DeadlineError> {
        // Take Instant first: any scheduling skew makes the projected cutoffs
        // slightly earlier, never later, than the host absolute cutoff.
        let instant = Instant::now();
        let timestamp = clock_gettime(ClockId::Monotonic);
        let seconds = u64::try_from(timestamp.tv_sec).map_err(|_| DeadlineError::ClockInvalid)?;
        let nanoseconds =
            u64::try_from(timestamp.tv_nsec).map_err(|_| DeadlineError::ClockInvalid)?;
        if nanoseconds >= NANOS_PER_SECOND {
            return Err(DeadlineError::ClockInvalid);
        }
        let monotonic_ns = seconds
            .checked_mul(NANOS_PER_SECOND)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or(DeadlineError::ClockInvalid)?;
        Ok(Self {
            monotonic_ns,
            instant,
        })
    }

    fn project(self, cutoff_monotonic_ns: u64) -> Result<Instant, DeadlineError> {
        let remaining_ns = cutoff_monotonic_ns.saturating_sub(self.monotonic_ns);
        self.instant
            .checked_add(Duration::from_nanos(remaining_ns))
            .ok_or(DeadlineError::ClockInvalid)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeadlineReceipt {
    schema_version: String,
    run_id: String,
    trial_id: String,
    attempt_id: String,
    run_spec_sha256: String,
    deadline: RunDeadline,
    reserves: DeadlineReserves,
    cutoffs: DeadlineCutoffs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunDeadline {
    schema_version: String,
    hard_deadline_monotonic_ns: u64,
    source: String,
    agent_timeout_ms: u64,
}

fn read_receipt(path: &Path) -> Result<Vec<u8>, DeadlineError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => DeadlineError::Unavailable,
        _ => DeadlineError::ReceiptIo,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RECEIPT_BYTES
    {
        return Err(DeadlineError::ReceiptFileInvalid);
    }
    fs::read(path).map_err(|_| DeadlineError::ReceiptIo)
}

fn parse_receipt(bytes: &[u8]) -> Result<DeadlineReceipt, DeadlineError> {
    if bytes.len() < 2 || !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].ends_with(b"\n") {
        return Err(DeadlineError::ReceiptCanonicalInvalid);
    }
    let payload = &bytes[..bytes.len() - 1];
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let value = NoDuplicateValue::deserialize(&mut deserializer)
        .map_err(|_| DeadlineError::ReceiptJsonInvalid)?
        .0;
    deserializer
        .end()
        .map_err(|_| DeadlineError::ReceiptJsonInvalid)?;
    let mut canonical =
        serde_json::to_vec(&value).map_err(|_| DeadlineError::ReceiptJsonInvalid)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(DeadlineError::ReceiptCanonicalInvalid);
    }
    serde_json::from_value(value).map_err(|_| DeadlineError::ReceiptJsonInvalid)
}

fn validate_receipt(
    receipt: &DeadlineReceipt,
    spec: &RunSpec,
    profile_reserves: DeadlineReserves,
    cli_hard_deadline_monotonic_ns: u64,
) -> Result<(), DeadlineError> {
    if receipt.schema_version != DEADLINE_RECEIPT_SCHEMA
        || receipt.deadline.schema_version != DEADLINE_SCHEMA
    {
        return Err(DeadlineError::SchemaInvalid);
    }
    validate_source(&receipt.deadline.source)?;
    validate_identity(&receipt.run_id)?;
    validate_identity(&receipt.trial_id)?;
    validate_identity(&receipt.attempt_id)?;
    validate_sha256(&receipt.run_spec_sha256)?;
    if receipt.run_id != spec.run_id
        || receipt.trial_id != spec.trial_id
        || receipt.attempt_id != spec.attempt_id
    {
        return Err(DeadlineError::IdentityBindingInvalid);
    }
    let spec_sha256 = spec
        .sha256()
        .map_err(|_| DeadlineError::RunSpecBindingInvalid)?;
    if receipt.run_spec_sha256 != spec_sha256 {
        return Err(DeadlineError::RunSpecBindingInvalid);
    }
    if receipt.deadline.hard_deadline_monotonic_ns != cli_hard_deadline_monotonic_ns {
        return Err(DeadlineError::RootBindingInvalid);
    }
    let expected_timeout_ms = spec
        .agent_timeout_sec
        .checked_mul(1_000)
        .ok_or(DeadlineError::TimeoutBindingInvalid)?;
    if receipt.deadline.agent_timeout_ms != expected_timeout_ms {
        return Err(DeadlineError::TimeoutBindingInvalid);
    }
    if receipt.reserves != DeadlineReserves::FROZEN {
        return Err(DeadlineError::ReserveBindingInvalid);
    }
    if profile_reserves != receipt.reserves {
        return Err(DeadlineError::ProfileBindingInvalid);
    }
    let expected_cutoffs = derive_cutoffs(
        receipt.deadline.hard_deadline_monotonic_ns,
        receipt.deadline.agent_timeout_ms,
        receipt.reserves,
    )?;
    if receipt.cutoffs != expected_cutoffs {
        return Err(DeadlineError::CutoffBindingInvalid);
    }
    Ok(())
}

fn reserves_from_profile(profile: &AgentProfile) -> Result<DeadlineReserves, DeadlineError> {
    let process_control_ms = profile
        .deadlines
        .process_control_timeout_sec
        .checked_mul(1_000)
        .ok_or(DeadlineError::ProfileBindingInvalid)?;
    let cleanup_ms = profile
        .process
        .term_grace_ms
        .checked_add(profile.process.kill_confirmation_timeout_ms)
        .and_then(|value| value.checked_add(process_control_ms))
        .ok_or(DeadlineError::ProfileBindingInvalid)?;
    let terminalization_ms = profile
        .deadlines
        .terminalization_reserve_sec
        .checked_mul(1_000)
        .ok_or(DeadlineError::ProfileBindingInvalid)?;
    let provider_send_ms = profile
        .deadlines
        .min_provider_send_window_sec
        .checked_mul(1_000)
        .ok_or(DeadlineError::ProfileBindingInvalid)?;
    Ok(DeadlineReserves {
        cleanup_ms,
        terminalization_ms,
        provider_send_ms,
        process_settlement_ms: process_control_ms,
    })
}

fn derive_cutoffs(
    hard_deadline_monotonic_ns: u64,
    agent_timeout_ms: u64,
    reserves: DeadlineReserves,
) -> Result<DeadlineCutoffs, DeadlineError> {
    if agent_timeout_ms <= reserves.total_ms()? {
        return Err(DeadlineError::ReserveUnderflow);
    }
    fn subtract_ms(value: u64, milliseconds: u64) -> Result<u64, DeadlineError> {
        let nanoseconds = milliseconds
            .checked_mul(NANOS_PER_MILLISECOND)
            .ok_or(DeadlineError::ReserveInvalid)?;
        if value <= nanoseconds {
            return Err(DeadlineError::ReserveUnderflow);
        }
        Ok(value - nanoseconds)
    }
    let cleanup_start_monotonic_ns = subtract_ms(hard_deadline_monotonic_ns, reserves.cleanup_ms)?;
    let runtime_final_monotonic_ns =
        subtract_ms(cleanup_start_monotonic_ns, reserves.terminalization_ms)?;
    let last_send_monotonic_ns = runtime_final_monotonic_ns;
    let tool_settled_monotonic_ns = subtract_ms(last_send_monotonic_ns, reserves.provider_send_ms)?;
    let actor_done_monotonic_ns =
        subtract_ms(tool_settled_monotonic_ns, reserves.process_settlement_ms)?;
    Ok(DeadlineCutoffs {
        actor_done_monotonic_ns,
        tool_settled_monotonic_ns,
        last_send_monotonic_ns,
        runtime_final_monotonic_ns,
        cleanup_start_monotonic_ns,
        hard_deadline_monotonic_ns,
    })
}

fn validate_identity(value: &str) -> Result<(), DeadlineError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES {
        return Err(DeadlineError::IdentityInvalid);
    }
    Ok(())
}

fn validate_source(value: &str) -> Result<(), DeadlineError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_BYTES {
        return Err(DeadlineError::SourceInvalid);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), DeadlineError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DeadlineError::RunSpecHashInvalid);
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Stable launch-time deadline failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineError {
    ArgumentInvalid,
    Unavailable,
    ReceiptIo,
    ReceiptFileInvalid,
    ReceiptJsonInvalid,
    ReceiptCanonicalInvalid,
    SchemaInvalid,
    SourceInvalid,
    IdentityInvalid,
    RunSpecHashInvalid,
    IdentityBindingInvalid,
    RunSpecBindingInvalid,
    RootBindingInvalid,
    TimeoutBindingInvalid,
    ReserveInvalid,
    ReserveBindingInvalid,
    ProfileBindingInvalid,
    ReserveUnderflow,
    CutoffBindingInvalid,
    ClockInvalid,
    Expired,
}

impl DeadlineError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArgumentInvalid => "deadline_argument_invalid",
            Self::Unavailable => "deadline_contract_unavailable",
            Self::ReceiptIo => "deadline_receipt_io_error",
            Self::ReceiptFileInvalid => "deadline_receipt_file_invalid",
            Self::ReceiptJsonInvalid => "deadline_receipt_json_invalid",
            Self::ReceiptCanonicalInvalid => "deadline_receipt_canonical_invalid",
            Self::SchemaInvalid => "deadline_receipt_schema_invalid",
            Self::SourceInvalid => "deadline_source_invalid",
            Self::IdentityInvalid => "deadline_identity_invalid",
            Self::RunSpecHashInvalid => "deadline_run_spec_sha256_invalid",
            Self::IdentityBindingInvalid => "deadline_identity_binding_invalid",
            Self::RunSpecBindingInvalid => "deadline_run_spec_binding_invalid",
            Self::RootBindingInvalid => "deadline_root_binding_invalid",
            Self::TimeoutBindingInvalid => "deadline_timeout_binding_invalid",
            Self::ReserveInvalid => "deadline_reserves_invalid",
            Self::ReserveBindingInvalid => "deadline_reserves_binding_invalid",
            Self::ProfileBindingInvalid => "deadline_profile_binding_invalid",
            Self::ReserveUnderflow => "deadline_reserve_underflow",
            Self::CutoffBindingInvalid => "deadline_cutoffs_binding_invalid",
            Self::ClockInvalid => "deadline_clock_invalid",
            Self::Expired => "deadline_contract_expired",
        }
    }
}

impl Display for DeadlineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for DeadlineError {}

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
    use std::time::{Duration, Instant};

    use nano_types::run_spec::{
        ContractSpec, ProviderKind, ProviderSpec, RUN_SPEC_SCHEMA, RunSpec, TaskSpec,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{
        DeadlineContext, DeadlineError, MonotonicAnchor, derive_cutoffs, parse_receipt, sha256_hex,
    };

    fn fixture() -> (TempDir, RunSpec) {
        let directory = TempDir::new().expect("temp directory");
        let workspace = directory.path().join("workspace");
        let artifact = directory.path().join("runtime");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::create_dir_all(&artifact).expect("artifact");
        let spec = RunSpec {
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
            workspace_dir: workspace,
            artifact_dir: artifact,
            agent_timeout_sec: 120,
            active_tools: None,
        };
        (directory, spec)
    }

    fn receipt_value(spec: &RunSpec, hard: u64) -> Value {
        let reserves = super::DeadlineReserves::FROZEN;
        let cutoffs =
            derive_cutoffs(hard, spec.agent_timeout_sec * 1_000, reserves).expect("cutoffs");
        json!({
            "schema_version": super::DEADLINE_RECEIPT_SCHEMA,
            "run_id": spec.run_id,
            "trial_id": spec.trial_id,
            "attempt_id": spec.attempt_id,
            "run_spec_sha256": spec.sha256().expect("RunSpec hash"),
            "deadline": {
                "schema_version": super::DEADLINE_SCHEMA,
                "hard_deadline_monotonic_ns": hard,
                "source": "test_host_phase",
                "agent_timeout_ms": spec.agent_timeout_sec * 1_000,
            },
            "reserves": {
                "cleanup_ms": reserves.cleanup_ms,
                "terminalization_ms": reserves.terminalization_ms,
                "provider_send_ms": reserves.provider_send_ms,
                "process_settlement_ms": reserves.process_settlement_ms,
            },
            "cutoffs": {
                "actor_done_monotonic_ns": cutoffs.actor_done_monotonic_ns,
                "tool_settled_monotonic_ns": cutoffs.tool_settled_monotonic_ns,
                "last_send_monotonic_ns": cutoffs.last_send_monotonic_ns,
                "runtime_final_monotonic_ns": cutoffs.runtime_final_monotonic_ns,
                "cleanup_start_monotonic_ns": cutoffs.cleanup_start_monotonic_ns,
                "hard_deadline_monotonic_ns": cutoffs.hard_deadline_monotonic_ns,
            },
        })
    }

    fn canonical_bytes(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).expect("canonical JSON");
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn validates_identity_root_spec_reserves_and_projects_from_raw_clock() {
        let (_directory, spec) = fixture();
        let hard = 130_000_000_000;
        let bytes = canonical_bytes(&receipt_value(&spec, hard));
        let instant = Instant::now();
        let context = DeadlineContext::from_bytes_at(
            &bytes,
            &spec,
            super::DeadlineReserves::FROZEN,
            hard,
            MonotonicAnchor {
                monotonic_ns: 27_000_000_000,
                instant,
            },
        )
        .expect("valid receipt");

        assert_eq!(context.cutoffs.actor_done_monotonic_ns, 55_000_000_000);
        assert_eq!(
            context.instants.actor_done.duration_since(instant),
            Duration::from_secs(28)
        );
        assert_eq!(
            context.instants.hard_deadline.duration_since(instant),
            Duration::from_secs(103)
        );
        assert_eq!(context.receipt_sha256, sha256_hex(&bytes));
        assert_eq!(context.observed_monotonic_ns, 27_000_000_000);
    }

    #[test]
    fn rejects_noncanonical_and_duplicate_json_before_typed_validation() {
        let (_directory, spec) = fixture();
        let hard = 130_000_000_000;
        let bytes = canonical_bytes(&receipt_value(&spec, hard));
        let duplicate = [b"{\"run_id\":\"replay\",".as_slice(), &bytes[1..]].concat();
        assert_eq!(
            parse_receipt(&duplicate).expect_err("duplicate fails"),
            DeadlineError::ReceiptJsonInvalid
        );

        let pretty = serde_json::to_string_pretty(&receipt_value(&spec, hard))
            .expect("pretty JSON")
            .into_bytes();
        assert_eq!(
            parse_receipt(&pretty).expect_err("noncanonical fails"),
            DeadlineError::ReceiptCanonicalInvalid
        );
    }

    #[test]
    fn replayed_identity_wrong_root_and_tampered_cutoff_fail_closed() {
        let (_directory, spec) = fixture();
        let hard = 130_000_000_000;
        let instant = Instant::now();
        let anchor = MonotonicAnchor {
            monotonic_ns: 27_000_000_000,
            instant,
        };

        let mut replay = receipt_value(&spec, hard);
        replay["run_id"] = json!("other-run");
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &canonical_bytes(&replay),
                &spec,
                super::DeadlineReserves::FROZEN,
                hard,
                anchor,
            )
            .expect_err("replay fails"),
            DeadlineError::IdentityBindingInvalid
        );

        let valid = canonical_bytes(&receipt_value(&spec, hard));
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &valid,
                &spec,
                super::DeadlineReserves::FROZEN,
                hard + 1,
                anchor,
            )
            .expect_err("wrong CLI root fails"),
            DeadlineError::RootBindingInvalid
        );

        let mut tampered = receipt_value(&spec, hard);
        tampered["cutoffs"]["actor_done_monotonic_ns"] = json!(55_000_000_001_u64);
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &canonical_bytes(&tampered),
                &spec,
                super::DeadlineReserves::FROZEN,
                hard,
                anchor,
            )
            .expect_err("tampered cutoff fails"),
            DeadlineError::CutoffBindingInvalid
        );

        let mut missing_source = receipt_value(&spec, hard);
        missing_source["deadline"]["source"] = json!("");
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &canonical_bytes(&missing_source),
                &spec,
                super::DeadlineReserves::FROZEN,
                hard,
                anchor,
            )
            .expect_err("empty source fails"),
            DeadlineError::SourceInvalid
        );
    }

    #[test]
    fn wrong_run_spec_hash_and_nonfrozen_reserves_fail_closed() {
        let (_directory, spec) = fixture();
        let hard = 130_000_000_000;
        let anchor = MonotonicAnchor {
            monotonic_ns: 27_000_000_000,
            instant: Instant::now(),
        };

        let mut wrong_spec = receipt_value(&spec, hard);
        wrong_spec["run_spec_sha256"] = json!("b".repeat(64));
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &canonical_bytes(&wrong_spec),
                &spec,
                super::DeadlineReserves::FROZEN,
                hard,
                anchor,
            )
            .expect_err("wrong RunSpec hash fails"),
            DeadlineError::RunSpecBindingInvalid
        );

        let mut wrong_reserve = receipt_value(&spec, hard);
        wrong_reserve["reserves"]["cleanup_ms"] = json!(19_999_u64);
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &canonical_bytes(&wrong_reserve),
                &spec,
                super::DeadlineReserves::FROZEN,
                hard,
                anchor,
            )
            .expect_err("nonfrozen reserves fail"),
            DeadlineError::ReserveBindingInvalid
        );
    }

    #[test]
    fn expired_root_and_profile_drift_are_typed() {
        let (_directory, spec) = fixture();
        let hard = 130_000_000_000;
        let bytes = canonical_bytes(&receipt_value(&spec, hard));
        let anchor = MonotonicAnchor {
            monotonic_ns: hard,
            instant: Instant::now(),
        };
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &bytes,
                &spec,
                super::DeadlineReserves::FROZEN,
                hard,
                anchor,
            )
            .expect_err("expired fails"),
            DeadlineError::Expired
        );

        let drifted_profile_reserves = super::DeadlineReserves {
            process_settlement_ms: 11_000,
            ..super::DeadlineReserves::FROZEN
        };
        assert_eq!(
            DeadlineContext::from_bytes_at(
                &bytes,
                &spec,
                drifted_profile_reserves,
                hard,
                MonotonicAnchor {
                    monotonic_ns: 27_000_000_000,
                    instant: Instant::now(),
                },
            )
            .expect_err("profile drift fails"),
            DeadlineError::ProfileBindingInvalid
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_missing_and_final_symlink_receipts() {
        use std::os::unix::fs::symlink;

        let (_directory, spec) = fixture();
        assert_eq!(
            super::read_receipt(&spec.artifact_dir.join(super::DEADLINE_RECEIPT_FILE))
                .expect_err("missing fails"),
            DeadlineError::Unavailable
        );
        let target = spec.artifact_dir.join("target.json");
        fs::write(&target, b"{}\n").expect("target");
        symlink(
            &target,
            spec.artifact_dir.join(super::DEADLINE_RECEIPT_FILE),
        )
        .expect("receipt symlink");
        assert_eq!(
            super::read_receipt(&spec.artifact_dir.join(super::DEADLINE_RECEIPT_FILE))
                .expect_err("symlink fails"),
            DeadlineError::ReceiptFileInvalid
        );
    }

    #[test]
    fn error_codes_are_machine_stable() {
        assert_eq!(
            DeadlineError::IdentityBindingInvalid.code(),
            "deadline_identity_binding_invalid"
        );
        assert_eq!(
            DeadlineError::CutoffBindingInvalid.code(),
            "deadline_cutoffs_binding_invalid"
        );
        assert_eq!(DeadlineError::Expired.code(), "deadline_contract_expired");
    }

    #[test]
    fn canonical_receipt_file_loads_and_hashes_exact_bytes() {
        let (_directory, spec) = fixture();
        let now = super::MonotonicAnchor::capture()
            .expect("monotonic clock")
            .monotonic_ns;
        let hard = now + 120_000_000_000;
        let bytes = canonical_bytes(&receipt_value(&spec, hard));
        let path = spec.artifact_dir.join(super::DEADLINE_RECEIPT_FILE);
        fs::write(&path, &bytes).expect("receipt");
        let receipt = super::read_receipt(&path).expect("read receipt");
        let context = DeadlineContext::from_bytes_at(
            &receipt,
            &spec,
            super::DeadlineReserves::FROZEN,
            hard,
            super::MonotonicAnchor::capture().expect("monotonic clock"),
        )
        .expect("load receipt");
        assert_eq!(context.receipt_sha256, sha256_hex(&bytes));
    }
}
