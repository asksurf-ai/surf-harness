//! Append-only JSONL writer and atomic settled-run marker.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use nano_types::event::{EVENT_SCHEMA, Event, EventBody, ToolReceiptV1, VersionedRunRecord};
use rustix::fs::{CWD, RenameFlags, renameat_with};
use sha2::{Digest, Sha256};

type DirectorySync = dyn Fn(&Path) -> io::Result<()> + Send + Sync;
type EventAppendSync = dyn Fn(&mut File, &[u8]) -> io::Result<()> + Send + Sync;
type EventRestoreSync = dyn Fn(&mut File, u64) -> io::Result<()> + Send + Sync;
const MIN_COMPACT_RUN_RECORD_BYTES: u64 = 4096;
const MAX_TERMINAL_CODE_BYTES: usize = 128;

pub struct EventWriter {
    artifact_dir: PathBuf,
    file: File,
    hasher: Sha256,
    run_id: String,
    trial_id: String,
    attempt_id: String,
    next_seq: u64,
    bytes_written: u64,
    max_events: u64,
    max_line_bytes: u64,
    max_log_bytes: u64,
    max_run_record_bytes: u64,
    terminal_event_reserve_bytes: u64,
    start: Instant,
    terminal_written: bool,
    event_log_poisoned: bool,
    omitted_tool_receipt_samples: u64,
    directory_sync: Box<DirectorySync>,
    event_append_sync: Box<EventAppendSync>,
    event_restore_sync: Box<EventRestoreSync>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWriterLimits {
    pub max_events: u64,
    pub max_line_bytes: u64,
    pub max_log_bytes: u64,
    pub max_run_record_bytes: u64,
}

/// Publication is irreversible after the same-directory no-replace rename succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunRecordPublication {
    Durable,
    PublishedDurabilityUncertain { warning_code: &'static str },
}

impl RunRecordPublication {
    pub fn warning_code(self) -> Option<&'static str> {
        match self {
            Self::Durable => None,
            Self::PublishedDurabilityUncertain { warning_code } => Some(warning_code),
        }
    }
}

impl EventWriter {
    pub fn create(
        artifact_dir: &Path,
        run_id: &str,
        trial_id: &str,
        attempt_id: &str,
        limits: EventWriterLimits,
    ) -> Result<Self, EventWriteError> {
        Self::create_with_directory_sync(
            artifact_dir,
            run_id,
            trial_id,
            attempt_id,
            limits,
            sync_directory,
        )
    }

    fn create_with_directory_sync(
        artifact_dir: &Path,
        run_id: &str,
        trial_id: &str,
        attempt_id: &str,
        limits: EventWriterLimits,
        directory_sync: impl Fn(&Path) -> io::Result<()> + Send + Sync + 'static,
    ) -> Result<Self, EventWriteError> {
        Self::create_with_io(
            artifact_dir,
            run_id,
            trial_id,
            attempt_id,
            limits,
            directory_sync,
            (append_and_sync_event, restore_and_sync_event),
        )
    }

    fn create_with_io(
        artifact_dir: &Path,
        run_id: &str,
        trial_id: &str,
        attempt_id: &str,
        limits: EventWriterLimits,
        directory_sync: impl Fn(&Path) -> io::Result<()> + Send + Sync + 'static,
        event_io: (
            impl Fn(&mut File, &[u8]) -> io::Result<()> + Send + Sync + 'static,
            impl Fn(&mut File, u64) -> io::Result<()> + Send + Sync + 'static,
        ),
    ) -> Result<Self, EventWriteError> {
        let (event_append_sync, event_restore_sync) = event_io;
        if artifact_dir.exists() {
            let metadata = fs::symlink_metadata(artifact_dir)
                .map_err(|_| EventWriteError::new("artifact_directory_metadata_failed"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(EventWriteError::new("artifact_directory_invalid"));
            }
        } else {
            fs::create_dir_all(artifact_dir)
                .map_err(|_| EventWriteError::new("artifact_directory_create_failed"))?;
        }
        if limits.max_events < 2 {
            return Err(EventWriteError::new("event_terminal_reserve_too_small"));
        }
        if limits.max_run_record_bytes < MIN_COMPACT_RUN_RECORD_BYTES {
            return Err(EventWriteError::new("run_record_reserve_too_small"));
        }
        let terminal_event_reserve_bytes = terminal_event_reserve_bytes(
            run_id,
            trial_id,
            attempt_id,
            limits.max_line_bytes,
            limits.max_log_bytes,
        )?;
        if artifact_dir.join("run.json").exists() || artifact_dir.join(".run.json.tmp").exists() {
            return Err(EventWriteError::new("artifact_terminal_marker_exists"));
        }
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(artifact_dir.join("events.jsonl"))
            .map_err(|_| EventWriteError::new("event_log_create_failed"))?;
        Ok(Self {
            artifact_dir: artifact_dir.to_owned(),
            file,
            hasher: Sha256::new(),
            run_id: run_id.to_owned(),
            trial_id: trial_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            next_seq: 0,
            bytes_written: 0,
            max_events: limits.max_events,
            max_line_bytes: limits.max_line_bytes,
            max_log_bytes: limits.max_log_bytes,
            max_run_record_bytes: limits.max_run_record_bytes,
            terminal_event_reserve_bytes,
            start: Instant::now(),
            terminal_written: false,
            event_log_poisoned: false,
            omitted_tool_receipt_samples: 0,
            directory_sync: Box::new(directory_sync),
            event_append_sync: Box::new(event_append_sync),
            event_restore_sync: Box::new(event_restore_sync),
        })
    }

    /// Append a non-terminal event while preserving one terminal slot and the
    /// worst-case bounded terminal line.
    pub fn append_operational(&mut self, body: EventBody) -> Result<Event, EventWriteError> {
        if body.is_terminal() {
            return Err(EventWriteError::new(
                "terminal_event_requires_reserved_append",
            ));
        }
        self.append_inner(body, false)
    }

    /// Append an optional receipt without competing with the terminal
    /// reserve. A post-write failure may be omitted only after restoring the
    /// last authoritative byte offset.
    pub fn append_tool_receipt(
        &mut self,
        receipt: ToolReceiptV1,
    ) -> Result<Option<Event>, EventWriteError> {
        match self.append_operational(EventBody::ToolReceipt(receipt)) {
            Ok(event) => Ok(Some(event)),
            Err(error)
                if matches!(
                    error.code(),
                    "event_count_limit_exceeded"
                        | "event_terminal_reserve_exhausted"
                        | "event_line_limit_exceeded"
                ) =>
            {
                self.omitted_tool_receipt_samples =
                    self.omitted_tool_receipt_samples.saturating_add(1);
                Ok(None)
            }
            Err(error) if error.code() == "event_log_sync_failed" => {
                if (self.event_restore_sync)(&mut self.file, self.bytes_written).is_err() {
                    self.event_log_poisoned = true;
                    return Err(EventWriteError::new("event_log_restore_failed"));
                }
                self.omitted_tool_receipt_samples =
                    self.omitted_tool_receipt_samples.saturating_add(1);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub fn omitted_tool_receipt_samples(&self) -> u64 {
        self.omitted_tool_receipt_samples
    }

    pub fn record_tool_receipt_omissions(&mut self, count: u64) {
        self.omitted_tool_receipt_samples = self.omitted_tool_receipt_samples.saturating_add(count);
    }

    /// Append optional failure detail without consuming the terminal reserve.
    pub fn append_diagnostic_failure(&mut self, body: EventBody) -> Result<Event, EventWriteError> {
        if body.is_terminal() {
            return Err(EventWriteError::new(
                "terminal_event_requires_reserved_append",
            ));
        }
        self.append_inner(body, false)
    }

    /// Consume the dedicated terminal slot. No event may follow it.
    pub fn append_terminal(&mut self, mut body: EventBody) -> Result<Event, EventWriteError> {
        if !body.is_terminal() {
            return Err(EventWriteError::new("reserved_append_requires_terminal"));
        }
        let omitted_samples = self.omitted_tool_receipt_samples;
        match &mut body {
            EventBody::RunCompleted(terminal) => {
                terminal.tool_receipt_omitted_count = omitted_samples;
            }
            EventBody::RunFailed(terminal) => {
                terminal.tool_receipt_omitted_count = omitted_samples;
            }
            _ => unreachable!("terminal body checked above"),
        }
        let mut zero_omission_body = body.clone();
        match &mut zero_omission_body {
            EventBody::RunCompleted(terminal) => {
                terminal.tool_receipt_omitted_count = 0;
            }
            EventBody::RunFailed(terminal) => {
                terminal.tool_receipt_omitted_count = 0;
            }
            _ => unreachable!("terminal body checked above"),
        }
        match self.append_inner(body, true) {
            Err(error)
                if omitted_samples > 0
                    && matches!(
                        error.code(),
                        "event_line_limit_exceeded" | "event_log_limit_exceeded"
                    ) =>
            {
                self.append_inner(zero_omission_body, true)
            }
            result => result,
        }
    }

    /// Compatibility helper for internal callers migrating to explicit APIs.
    pub fn append(&mut self, body: EventBody) -> Result<Event, EventWriteError> {
        if body.is_terminal() {
            self.append_terminal(body)
        } else {
            self.append_operational(body)
        }
    }

    fn append_inner(&mut self, body: EventBody, terminal: bool) -> Result<Event, EventWriteError> {
        if self.event_log_poisoned {
            return Err(EventWriteError::new("event_log_unrecoverable"));
        }
        if self.terminal_written {
            return Err(EventWriteError::new("event_after_terminal"));
        }
        let event_limit = if terminal {
            self.max_events
        } else {
            self.max_events.saturating_sub(1)
        };
        if self.next_seq >= event_limit {
            return Err(EventWriteError::new(if terminal {
                "event_count_limit_exceeded"
            } else {
                "event_terminal_reserve_exhausted"
            }));
        }
        if self.next_seq >= self.max_events {
            return Err(EventWriteError::new("event_count_limit_exceeded"));
        }
        let event = Event {
            schema_version: EVENT_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            trial_id: self.trial_id.clone(),
            attempt_id: self.attempt_id.clone(),
            seq: self.next_seq,
            elapsed_ms: self.elapsed_ms(),
            body,
        };
        event
            .validate()
            .map_err(|_| EventWriteError::new("event_validation_failed"))?;
        let mut line = serde_json::to_vec(&event)
            .map_err(|_| EventWriteError::new("event_serialize_failed"))?;
        line.push(b'\n');
        let line_length = u64::try_from(line.len())
            .map_err(|_| EventWriteError::new("event_line_length_overflow"))?;
        if line_length > self.max_line_bytes {
            return Err(EventWriteError::new("event_line_limit_exceeded"));
        }
        let total = self
            .bytes_written
            .checked_add(line_length)
            .ok_or_else(|| EventWriteError::new("event_log_length_overflow"))?;
        let log_limit = if terminal {
            self.max_log_bytes
        } else {
            self.max_log_bytes
                .saturating_sub(self.terminal_event_reserve_bytes)
        };
        if total > log_limit {
            return Err(EventWriteError::new(if terminal {
                "event_log_limit_exceeded"
            } else {
                "event_terminal_reserve_exhausted"
            }));
        }
        (self.event_append_sync)(&mut self.file, &line)
            .map_err(|_| EventWriteError::new("event_log_sync_failed"))?;
        self.hasher.update(&line);
        self.bytes_written = total;
        self.next_seq += 1;
        if event.body.is_terminal() {
            self.terminal_written = true;
        }
        Ok(event)
    }

    pub fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub fn events_sha256(&self) -> String {
        format!("{:x}", self.hasher.clone().finalize())
    }

    /// Publish `run.json` only after a synced terminal event.
    ///
    /// The no-replace rename is the irreversible publication point. Failures before it
    /// return `Err` and leave no marker. A later directory-sync failure cannot
    /// be reported as incomplete because the settled marker is already
    /// visible; it returns a typed durability warning instead.
    pub fn commit_run_record(
        &mut self,
        record: &VersionedRunRecord,
    ) -> Result<RunRecordPublication, EventWriteError> {
        if !self.terminal_written {
            return Err(EventWriteError::new("run_record_without_terminal"));
        }
        if matches!(record, VersionedRunRecord::V1(_)) {
            return Err(EventWriteError::new(
                "run_record_schema_unsupported_for_publication",
            ));
        }
        record
            .validate()
            .map_err(|_| EventWriteError::new("run_record_validation_failed"))?;
        let mut bytes = serde_json::to_vec(record)
            .map_err(|_| EventWriteError::new("run_record_serialize_failed"))?;
        bytes.push(b'\n');
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > self.max_run_record_bytes {
            return Err(EventWriteError::new("run_record_limit_exceeded"));
        }
        let temporary = self.artifact_dir.join(".run.json.tmp");
        let destination = self.artifact_dir.join("run.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| EventWriteError::new("run_record_temp_create_failed"))?;
        let write_result = file
            .write_all(&bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        if write_result.is_err() {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(EventWriteError::new("run_record_temp_sync_failed"));
        }
        drop(file);
        renameat_with(CWD, &temporary, CWD, &destination, RenameFlags::NOREPLACE).map_err(
            |_| {
                let _ = fs::remove_file(&temporary);
                EventWriteError::new("run_record_publish_failed")
            },
        )?;
        match (self.directory_sync)(&self.artifact_dir) {
            Ok(()) => Ok(RunRecordPublication::Durable),
            Err(_) => Ok(RunRecordPublication::PublishedDurabilityUncertain {
                warning_code: "artifact_directory_sync_failed",
            }),
        }
    }
}

fn terminal_event_reserve_bytes(
    run_id: &str,
    trial_id: &str,
    attempt_id: &str,
    max_line_bytes: u64,
    max_log_bytes: u64,
) -> Result<u64, EventWriteError> {
    let event = Event {
        schema_version: EVENT_SCHEMA.to_owned(),
        run_id: run_id.to_owned(),
        trial_id: trial_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        seq: u64::MAX,
        elapsed_ms: u64::MAX,
        body: EventBody::RunFailed(nano_types::event::RunFailed {
            code: "x".repeat(MAX_TERMINAL_CODE_BYTES),
            tool_receipt_omitted_count: 0,
        }),
    };
    let bytes = serde_json::to_vec(&event)
        .map_err(|_| EventWriteError::new("terminal_reserve_serialize_failed"))?;
    let reserve = u64::try_from(bytes.len().saturating_add(1))
        .map_err(|_| EventWriteError::new("terminal_reserve_length_overflow"))?;
    if reserve > max_line_bytes || reserve > max_log_bytes {
        return Err(EventWriteError::new("event_terminal_reserve_too_small"));
    }
    Ok(reserve)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn append_and_sync_event(file: &mut File, line: &[u8]) -> io::Result<()> {
    file.write_all(line)?;
    file.flush()?;
    file.sync_data()
}

fn restore_and_sync_event(file: &mut File, length: u64) -> io::Result<()> {
    file.set_len(length)?;
    file.flush()?;
    file.sync_data()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWriteError {
    code: &'static str,
}

impl EventWriteError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl Display for EventWriteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "artifact writer failed: {}", self.code)
    }
}

impl Error for EventWriteError {}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::path::Path;

    use nano_types::event::{
        Event, EventBody, ProviderCallCoverage, RUN_RECORD_SCHEMA, RUN_RECORD_V3_SCHEMA,
        RunCompleted, RunFailed, RunRecord, RunRecordV3, RunStarted, TOOL_RECEIPT_V1_SCHEMA,
        TerminalStatus, ToolReceiptV1, UsageState, UsageTotals, VersionedRunRecord,
        tool_receipt_identity_sha256,
    };
    use nano_types::external_tool::{
        ExternalTerminalActorOriginV1, ExternalTerminalActorPhaseV1, ExternalTerminalActorSubtypeV1,
    };
    use sha2::{Digest, Sha256};

    use super::{EventWriter, EventWriterLimits, RunRecordPublication};

    fn limits() -> EventWriterLimits {
        EventWriterLimits {
            max_events: 8,
            max_line_bytes: 4096,
            max_log_bytes: 16_384,
            max_run_record_bytes: 4096,
        }
    }

    fn record(writer: &EventWriter) -> RunRecord {
        RunRecord {
            schema_version: RUN_RECORD_SCHEMA.to_owned(),
            run_id: "run".to_owned(),
            trial_id: "trial".to_owned(),
            attempt_id: "attempt".to_owned(),
            run_spec_sha256: "a".repeat(64),
            deadline_receipt_sha256: None,
            contract_id: "synthetic-v1".to_owned(),
            contract_set_sha256: "b".repeat(64),
            profile_id: "synthetic-profile-v1".to_owned(),
            terminal_status: TerminalStatus::Success,
            terminal_phase: None,
            terminal_code: "completed".to_owned(),
            final_event_seq: 0,
            provider_turn_count: 1,
            tool_call_count: 0,
            provider_call_coverage: ProviderCallCoverage {
                requested: 1,
                completed: 1,
                failed: 0,
                in_flight: 0,
                usage_present: 0,
                usage_absent: 1,
                usage_covered: 0,
                cost_present: 0,
                cost_absent: 1,
                state: UsageState::Partial,
            },
            usage_totals: UsageTotals {
                input_tokens: None,
                cached_input_tokens: None,
                output_tokens: None,
                provider_cost_ticks: None,
            },
            start_elapsed_ms: 0,
            end_elapsed_ms: writer.elapsed_ms(),
            events_sha256: writer.events_sha256(),
        }
    }

    fn versioned_record(writer: &EventWriter, v3: bool) -> VersionedRunRecord {
        let record = record(writer);
        if !v3 {
            return VersionedRunRecord::V2(record);
        }
        VersionedRunRecord::V3(RunRecordV3 {
            schema_version: RUN_RECORD_V3_SCHEMA.to_owned(),
            run_id: record.run_id,
            trial_id: record.trial_id,
            attempt_id: record.attempt_id,
            run_spec_sha256: record.run_spec_sha256,
            deadline_receipt_sha256: "d".repeat(64),
            contract_id: record.contract_id,
            contract_set_sha256: record.contract_set_sha256,
            profile_id: record.profile_id,
            terminal_status: record.terminal_status,
            terminal_phase: record.terminal_phase,
            terminal_code: record.terminal_code,
            final_event_seq: record.final_event_seq,
            provider_turn_count: record.provider_turn_count,
            tool_call_count: record.tool_call_count,
            provider_call_coverage: record.provider_call_coverage,
            usage_totals: record.usage_totals,
            start_elapsed_ms: record.start_elapsed_ms,
            end_elapsed_ms: record.end_elapsed_ms,
            events_sha256: record.events_sha256,
        })
    }

    fn tool_receipt() -> ToolReceiptV1 {
        ToolReceiptV1 {
            schema_version: TOOL_RECEIPT_V1_SCHEMA.to_owned(),
            phase: ExternalTerminalActorPhaseV1::MetaValidate,
            origin: ExternalTerminalActorOriginV1::Actor,
            primary_subtype: ExternalTerminalActorSubtypeV1::Completed,
            recovery_subtype: None,
            receipt_digest_sha256: "d".repeat(64),
            tool_identity_sha256: tool_receipt_identity_sha256("call-1", "run_terminal_command")
                .expect("identity digest"),
            tool_call_ordinal: 1,
        }
    }

    #[test]
    fn receipt_telemetry_is_durable_and_capacity_omission_preserves_terminalization() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut writer = EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
            .expect("create writer");
        let telemetry = writer
            .append_tool_receipt(tool_receipt())
            .expect("advisory append")
            .expect("sample appended");
        assert_eq!(telemetry.seq, 0);
        let terminal = writer
            .append_terminal(EventBody::RunCompleted(RunCompleted {
                code: "completed".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("terminal");
        let mut committed = versioned_record(&writer, true);
        let VersionedRunRecord::V3(record) = &mut committed else {
            panic!("v3");
        };
        record.final_event_seq = terminal.seq;
        record.tool_call_count = 1;
        writer
            .commit_run_record(&committed)
            .expect("durable record binding");
        let events =
            std::fs::read_to_string(directory.path().join("events.jsonl")).expect("events");
        let first: Event =
            serde_json::from_str(events.lines().next().expect("telemetry line")).expect("event");
        assert_eq!(first, telemetry);
        let run: VersionedRunRecord = serde_json::from_slice(
            &std::fs::read(directory.path().join("run.json")).expect("run record"),
        )
        .expect("typed run record");
        let recorded_events_sha256 = match run {
            VersionedRunRecord::V1(record) => record.events_sha256,
            VersionedRunRecord::V2(record) => record.events_sha256,
            VersionedRunRecord::V3(record) => record.events_sha256,
        };
        assert_eq!(recorded_events_sha256, writer.events_sha256());

        let omitted = tempfile::tempdir().expect("omission directory");
        let mut constrained = limits();
        constrained.max_events = 2;
        let mut writer =
            EventWriter::create(omitted.path(), "run", "trial", "attempt", constrained)
                .expect("create constrained writer");
        writer
            .append_operational(EventBody::RunStarted(RunStarted {
                task_id: "task".to_owned(),
                contract_id: "contract".to_owned(),
                profile_id: "profile".to_owned(),
                contract_set_sha256: "a".repeat(64),
                model: "model".to_owned(),
                run_spec_sha256: "b".repeat(64),
                deadline_receipt_sha256: None,
                media_history_policy_version: None,
                media_history_policy_sha256: None,
            }))
            .expect("fill operational capacity");
        assert!(
            writer
                .append_tool_receipt(tool_receipt())
                .expect("capacity omission is advisory")
                .is_none()
        );
        assert_eq!(writer.omitted_tool_receipt_samples(), 1);
        writer
            .append_terminal(EventBody::RunFailed(RunFailed {
                code: "synthetic_failure".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("terminal reserve wins");
        let terminal: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(omitted.path().join("events.jsonl"))
                .expect("omission events")
                .lines()
                .last()
                .expect("terminal line"),
        )
        .expect("terminal event");
        assert_eq!(terminal["data"]["tool_receipt_omitted_count"], 1);
    }

    fn faulting_receipt_writer(directory: &Path, restore_fails: bool) -> EventWriter {
        EventWriter::create_with_io(
            directory,
            "run",
            "trial",
            "attempt",
            limits(),
            |_| Ok(()),
            (
                |file, line| {
                    let marker = b"\"type\":\"tool.receipt\"";
                    if line.windows(marker.len()).any(|window| window == marker) {
                        file.write_all(&line[..line.len() / 2])?;
                        file.flush()?;
                        return Err(io::Error::other("injected partial receipt write"));
                    }
                    super::append_and_sync_event(file, line)
                },
                move |file, length| {
                    if restore_fails {
                        Err(io::Error::other("injected receipt restore failure"))
                    } else {
                        super::restore_and_sync_event(file, length)
                    }
                },
            ),
        )
        .expect("faulting event writer")
    }

    fn append_started(writer: &mut EventWriter) {
        writer
            .append_operational(EventBody::RunStarted(RunStarted {
                task_id: "task".to_owned(),
                contract_id: "contract".to_owned(),
                profile_id: "profile".to_owned(),
                contract_set_sha256: "a".repeat(64),
                model: "model".to_owned(),
                run_spec_sha256: "b".repeat(64),
                deadline_receipt_sha256: None,
                media_history_policy_version: None,
                media_history_policy_sha256: None,
            }))
            .expect("run.started");
    }

    #[test]
    fn partial_advisory_write_is_rolled_back_before_terminalization() {
        let directory = tempfile::tempdir().expect("event directory");
        let mut writer = faulting_receipt_writer(directory.path(), false);
        append_started(&mut writer);

        assert!(
            writer
                .append_tool_receipt(tool_receipt())
                .expect("successful rollback makes receipt advisory")
                .is_none()
        );
        let terminal = writer
            .append_terminal(EventBody::RunFailed(RunFailed {
                code: "synthetic_failure".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("repaired prefix can terminalize");

        assert_eq!(terminal.seq, 1);
        let bytes = std::fs::read(directory.path().join("events.jsonl")).expect("events");
        let events = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Event>(line).expect("canonical event"))
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].body, EventBody::RunStarted(_)));
        let EventBody::RunFailed(terminal) = &events[1].body else {
            panic!("run.failed");
        };
        assert_eq!(terminal.tool_receipt_omitted_count, 1);
        assert_eq!(
            writer.events_sha256(),
            format!("{:x}", Sha256::digest(bytes))
        );
    }

    #[test]
    fn failed_advisory_restore_is_explicitly_fatal_without_terminal_marker() {
        let directory = tempfile::tempdir().expect("event directory");
        let mut writer = faulting_receipt_writer(directory.path(), true);
        append_started(&mut writer);

        let error = writer
            .append_tool_receipt(tool_receipt())
            .expect_err("failed restore cannot be swallowed");

        assert_eq!(error.code(), "event_log_restore_failed");
        assert_eq!(writer.next_seq, 1);
        assert_eq!(writer.omitted_tool_receipt_samples(), 0);
        let terminal_error = writer
            .append_terminal(EventBody::RunFailed(RunFailed {
                code: "must_not_terminalize".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect_err("poisoned log cannot continue");
        assert_eq!(terminal_error.code(), "event_log_unrecoverable");
        assert!(!directory.path().join("run.json").exists());
    }

    #[test]
    fn zero_receipt_telemetry_does_not_expand_terminal_reserve() {
        let directory = tempfile::tempdir().expect("event directory");
        let writer = EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
            .expect("event writer");
        let legacy_sized_terminal = Event {
            schema_version: nano_types::event::EVENT_SCHEMA.to_owned(),
            run_id: "run".to_owned(),
            trial_id: "trial".to_owned(),
            attempt_id: "attempt".to_owned(),
            seq: u64::MAX,
            elapsed_ms: u64::MAX,
            body: EventBody::RunFailed(RunFailed {
                code: "x".repeat(super::MAX_TERMINAL_CODE_BYTES),
                tool_receipt_omitted_count: 0,
            }),
        };
        let expected = u64::try_from(
            serde_json::to_vec(&legacy_sized_terminal)
                .expect("terminal bytes")
                .len()
                .saturating_add(1),
        )
        .expect("terminal length");
        assert_eq!(writer.terminal_event_reserve_bytes, expected);

        let fallback_directory = tempfile::tempdir().expect("fallback event directory");
        let mut fallback_limits = limits();
        fallback_limits.max_events = u64::MAX;
        fallback_limits.max_line_bytes = expected;
        fallback_limits.max_log_bytes = expected;
        let mut fallback_writer = EventWriter::create(
            fallback_directory.path(),
            "run",
            "trial",
            "attempt",
            fallback_limits,
        )
        .expect("legacy-sized fallback writer");
        fallback_writer.next_seq = u64::MAX - 1;
        fallback_writer.omitted_tool_receipt_samples = u64::MAX;
        fallback_writer
            .append_terminal(EventBody::RunFailed(RunFailed {
                code: "x".repeat(super::MAX_TERMINAL_CODE_BYTES),
                tool_receipt_omitted_count: 0,
            }))
            .expect("optional omission counter cannot break terminalization");
        let terminal: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(fallback_directory.path().join("events.jsonl"))
                .expect("fallback events")
                .trim_end(),
        )
        .expect("fallback terminal");
        assert!(
            terminal["data"].get("tool_receipt_omitted_count").is_none(),
            "capacity fallback omits only the optional counter"
        );
    }

    #[test]
    fn terminal_event_closes_prefix_and_incomplete_prefix_has_no_marker() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut writer = EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
            .expect("create writer");
        writer
            .append(EventBody::RunCompleted(RunCompleted {
                code: "completed".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("append terminal");
        assert!(
            writer
                .append(EventBody::RunCompleted(RunCompleted {
                    code: "again".to_owned(),
                    tool_receipt_omitted_count: 0,
                }))
                .is_err()
        );
        assert!(!directory.path().join("run.json").exists());
    }

    #[test]
    fn operational_events_cannot_consume_the_terminal_slot() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut reserved_limits = limits();
        reserved_limits.max_events = 2;
        let mut writer =
            EventWriter::create(directory.path(), "run", "trial", "attempt", reserved_limits)
                .expect("create writer");
        writer
            .append_operational(EventBody::RunStarted(RunStarted {
                task_id: "task".to_owned(),
                contract_id: "contract".to_owned(),
                profile_id: "profile".to_owned(),
                contract_set_sha256: "a".repeat(64),
                model: "model".to_owned(),
                run_spec_sha256: "b".repeat(64),
                deadline_receipt_sha256: None,
                media_history_policy_version: None,
                media_history_policy_sha256: None,
            }))
            .expect("append first operational event");
        let error = writer
            .append_operational(EventBody::RunStarted(RunStarted {
                task_id: "task".to_owned(),
                contract_id: "contract".to_owned(),
                profile_id: "profile".to_owned(),
                contract_set_sha256: "a".repeat(64),
                model: "model".to_owned(),
                run_spec_sha256: "b".repeat(64),
                deadline_receipt_sha256: None,
                media_history_policy_version: None,
                media_history_policy_sha256: None,
            }))
            .expect_err("terminal slot must stay reserved");
        assert_eq!(error.code(), "event_terminal_reserve_exhausted");
        writer
            .append_terminal(EventBody::RunFailed(RunFailed {
                code: "event_capacity_exhausted".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("reserved terminal event");
        assert_eq!(
            std::fs::read_to_string(directory.path().join("events.jsonl"))
                .expect("events")
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn operational_bytes_cannot_consume_the_terminal_line_reserve() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut writer = EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
            .expect("create writer");
        writer.max_log_bytes = writer.terminal_event_reserve_bytes;
        let error = writer
            .append_operational(EventBody::RunStarted(RunStarted {
                task_id: "task".to_owned(),
                contract_id: "contract".to_owned(),
                profile_id: "profile".to_owned(),
                contract_set_sha256: "a".repeat(64),
                model: "model".to_owned(),
                run_spec_sha256: "b".repeat(64),
                deadline_receipt_sha256: None,
                media_history_policy_version: None,
                media_history_policy_sha256: None,
            }))
            .expect_err("terminal bytes must stay reserved");
        assert_eq!(error.code(), "event_terminal_reserve_exhausted");
        writer
            .append_terminal(EventBody::RunFailed(RunFailed {
                code: "event_capacity_exhausted".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("reserved terminal bytes");
    }

    #[test]
    fn compact_record_limit_is_rejected_before_run_started() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut tiny_limits = limits();
        tiny_limits.max_run_record_bytes = 1;
        let error = EventWriter::create(directory.path(), "run", "trial", "attempt", tiny_limits)
            .err()
            .expect("reject impossible compact record limit before run.started");
        assert_eq!(error.code(), "run_record_reserve_too_small");
        assert!(!directory.path().join("events.jsonl").exists());
        assert!(!directory.path().join("run.json").exists());
        assert!(!directory.path().join(".run.json.tmp").exists());
    }

    #[test]
    fn post_publish_sync_failure_is_a_warning_and_keeps_settled_marker() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut writer = EventWriter::create_with_directory_sync(
            directory.path(),
            "run",
            "trial",
            "attempt",
            limits(),
            |_| Err(io::Error::other("injected post-publish sync failure")),
        )
        .expect("create writer");
        writer
            .append(EventBody::RunCompleted(RunCompleted {
                code: "completed".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("append terminal");
        let publication = writer
            .commit_run_record(&versioned_record(&writer, false))
            .expect("no-replace rename is the publish point");
        assert_eq!(
            publication,
            RunRecordPublication::PublishedDurabilityUncertain {
                warning_code: "artifact_directory_sync_failed"
            }
        );
        assert!(directory.path().join("run.json").is_file());
        assert!(!directory.path().join(".run.json.tmp").exists());
    }

    #[test]
    fn v3_uses_the_same_atomic_publication_and_post_publish_warning() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut writer = EventWriter::create_with_directory_sync(
            directory.path(),
            "run",
            "trial",
            "attempt",
            limits(),
            |_| Err(io::Error::other("injected post-publish sync failure")),
        )
        .expect("create writer");
        writer
            .append(EventBody::RunCompleted(RunCompleted {
                code: "completed".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("append terminal");
        let publication = writer
            .commit_run_record(&versioned_record(&writer, true))
            .expect("v3 shares no-replace rename publication");
        assert_eq!(
            publication,
            RunRecordPublication::PublishedDurabilityUncertain {
                warning_code: "artifact_directory_sync_failed"
            }
        );
        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("run.json")).expect("v3 run"),
        )
        .expect("v3 json");
        assert_eq!(value["schema_version"], RUN_RECORD_V3_SCHEMA);
        assert_eq!(value["deadline_receipt_sha256"], "d".repeat(64));
        assert!(!directory.path().join(".run.json.tmp").exists());
    }

    #[test]
    fn v2_and_v3_typed_writer_wire_goldens_are_exact() {
        for v3 in [false, true] {
            let directory = tempfile::tempdir().expect("create event directory");
            let mut writer =
                EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
                    .expect("create writer");
            writer
                .append(EventBody::RunCompleted(RunCompleted {
                    code: "completed".to_owned(),
                    tool_receipt_omitted_count: 0,
                }))
                .expect("append terminal");
            let mut record = versioned_record(&writer, v3);
            match &mut record {
                VersionedRunRecord::V2(record) => {
                    record.end_elapsed_ms = 10;
                    record.events_sha256 = "c".repeat(64);
                }
                VersionedRunRecord::V3(record) => {
                    record.end_elapsed_ms = 10;
                    record.events_sha256 = "c".repeat(64);
                }
                VersionedRunRecord::V1(_) => unreachable!("modern fixture"),
            }
            assert_eq!(
                writer.commit_run_record(&record).expect("publish record"),
                RunRecordPublication::Durable
            );
            let bytes = std::fs::read(directory.path().join("run.json")).expect("run bytes");
            let expected = if v3 {
                concat!(
                    "{\"schema_version\":\"nano-run-record-v3\",\"run_id\":\"run\",",
                    "\"trial_id\":\"trial\",\"attempt_id\":\"attempt\",",
                    "\"run_spec_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                    "\"deadline_receipt_sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",",
                    "\"contract_id\":\"synthetic-v1\",",
                    "\"contract_set_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
                    "\"profile_id\":\"synthetic-profile-v1\",\"terminal_status\":\"success\",",
                    "\"terminal_phase\":null,\"terminal_code\":\"completed\",\"final_event_seq\":0,",
                    "\"provider_turn_count\":1,\"tool_call_count\":0,\"provider_call_coverage\":",
                    "{\"requested\":1,\"completed\":1,\"failed\":0,\"in_flight\":0,",
                    "\"usage_present\":0,\"usage_absent\":1,\"usage_covered\":0,\"cost_present\":0,",
                    "\"cost_absent\":1,\"state\":\"partial\"},\"usage_totals\":",
                    "{\"input_tokens\":null,\"cached_input_tokens\":null,\"output_tokens\":null,",
                    "\"provider_cost_ticks\":null},\"start_elapsed_ms\":0,\"end_elapsed_ms\":10,",
                    "\"events_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}\n"
                )
            } else {
                concat!(
                    "{\"schema_version\":\"nano-run-record-v2\",\"run_id\":\"run\",",
                    "\"trial_id\":\"trial\",\"attempt_id\":\"attempt\",",
                    "\"run_spec_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                    "\"contract_id\":\"synthetic-v1\",",
                    "\"contract_set_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
                    "\"profile_id\":\"synthetic-profile-v1\",\"terminal_status\":\"success\",",
                    "\"terminal_phase\":null,\"terminal_code\":\"completed\",\"final_event_seq\":0,",
                    "\"provider_turn_count\":1,\"tool_call_count\":0,\"provider_call_coverage\":",
                    "{\"requested\":1,\"completed\":1,\"failed\":0,\"in_flight\":0,",
                    "\"usage_present\":0,\"usage_absent\":1,\"usage_covered\":0,\"cost_present\":0,",
                    "\"cost_absent\":1,\"state\":\"partial\"},\"usage_totals\":",
                    "{\"input_tokens\":null,\"cached_input_tokens\":null,\"output_tokens\":null,",
                    "\"provider_cost_ticks\":null},\"start_elapsed_ms\":0,\"end_elapsed_ms\":10,",
                    "\"events_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}\n"
                )
            };
            assert_eq!(bytes, expected.as_bytes());
        }
    }

    #[test]
    fn v2_and_v3_temp_conflicts_fail_before_committed_record() {
        for v3 in [false, true] {
            let directory = tempfile::tempdir().expect("create event directory");
            let mut writer =
                EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
                    .expect("create writer");
            writer
                .append(EventBody::RunCompleted(RunCompleted {
                    code: "completed".to_owned(),
                    tool_receipt_omitted_count: 0,
                }))
                .expect("append terminal");
            std::fs::write(directory.path().join(".run.json.tmp"), b"occupied")
                .expect("create temp conflict");
            let error = writer
                .commit_run_record(&versioned_record(&writer, v3))
                .expect_err("temp conflict");
            assert_eq!(error.code(), "run_record_temp_create_failed");
            assert!(!directory.path().join("run.json").exists());
            assert_eq!(
                std::fs::read(directory.path().join(".run.json.tmp"))
                    .expect("preserved foreign temp"),
                b"occupied"
            );
        }
    }

    #[test]
    fn v2_and_v3_publication_is_atomic_no_replace() {
        for v3 in [false, true] {
            let directory = tempfile::tempdir().expect("create event directory");
            let mut writer =
                EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
                    .expect("create writer");
            writer
                .append(EventBody::RunCompleted(RunCompleted {
                    code: "completed".to_owned(),
                    tool_receipt_omitted_count: 0,
                }))
                .expect("append terminal");
            let record = versioned_record(&writer, v3);
            writer
                .commit_run_record(&record)
                .expect("first commit publishes");
            let original =
                std::fs::read(directory.path().join("run.json")).expect("original record");
            let error = writer
                .commit_run_record(&record)
                .expect_err("second commit must not replace");
            assert_eq!(error.code(), "run_record_publish_failed");
            assert_eq!(
                std::fs::read(directory.path().join("run.json")).expect("preserved record"),
                original
            );
            assert!(!directory.path().join(".run.json.tmp").exists());

            let raced = tempfile::tempdir().expect("create raced directory");
            let mut raced_writer =
                EventWriter::create(raced.path(), "run", "trial", "attempt", limits())
                    .expect("create raced writer");
            raced_writer
                .append(EventBody::RunCompleted(RunCompleted {
                    code: "completed".to_owned(),
                    tool_receipt_omitted_count: 0,
                }))
                .expect("append raced terminal");
            std::fs::write(raced.path().join("run.json"), b"concurrent")
                .expect("create concurrent destination");
            let error = raced_writer
                .commit_run_record(&versioned_record(&raced_writer, v3))
                .expect_err("concurrent destination must not be replaced");
            assert_eq!(error.code(), "run_record_publish_failed");
            assert_eq!(
                std::fs::read(raced.path().join("run.json")).expect("concurrent record"),
                b"concurrent"
            );
            assert!(!raced.path().join(".run.json.tmp").exists());
        }
    }

    #[test]
    fn invalid_v3_fails_before_temp_creation() {
        let directory = tempfile::tempdir().expect("create event directory");
        let mut writer = EventWriter::create(directory.path(), "run", "trial", "attempt", limits())
            .expect("create writer");
        writer
            .append(EventBody::RunCompleted(RunCompleted {
                code: "completed".to_owned(),
                tool_receipt_omitted_count: 0,
            }))
            .expect("append terminal");
        let mut versioned = versioned_record(&writer, true);
        let VersionedRunRecord::V3(record) = &mut versioned else {
            unreachable!("v3 fixture")
        };
        record.deadline_receipt_sha256 = "not-a-sha".to_owned();
        let error = writer
            .commit_run_record(&versioned)
            .expect_err("invalid v3");
        assert_eq!(error.code(), "run_record_validation_failed");
        assert!(!directory.path().join("run.json").exists());
        assert!(!directory.path().join(".run.json.tmp").exists());
    }
}
