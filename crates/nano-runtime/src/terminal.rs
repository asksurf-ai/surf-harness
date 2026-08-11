//! Foreground-only bash execution with bounded output and process-group cleanup.

use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nano_provider_xai::FunctionCall;
use nano_types::contract::AgentProfile;
use nano_types::event::ToolOutcome;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::foreground::truncate_utf8;
use crate::tool::{
    CommandVerdictV1, EffectObservationV1, ExecutionEvidenceV1, ToolExecutionError, ToolExecutor,
    ToolResult,
};

#[derive(Debug, Clone)]
pub struct TerminalExecutor {
    default_timeout: Duration,
    max_timeout: Duration,
    terminalization_reserve: Duration,
    term_grace: Duration,
    kill_confirmation_timeout: Duration,
    max_command_bytes: u64,
    capture_bytes_per_stream: usize,
    max_model_output_bytes: usize,
}

impl TerminalExecutor {
    pub fn from_profile(profile: &AgentProfile) -> Self {
        let per_process =
            usize::try_from(profile.process.process_spool_bytes_per_process).unwrap_or(usize::MAX);
        Self {
            default_timeout: Duration::from_millis(profile.tools.terminal_default_timeout_ms),
            max_timeout: Duration::from_millis(profile.tools.terminal_max_timeout_ms.min(300_000)),
            terminalization_reserve: Duration::from_secs(
                profile.deadlines.terminalization_reserve_sec,
            ),
            term_grace: Duration::from_millis(profile.process.term_grace_ms),
            kill_confirmation_timeout: Duration::from_millis(
                profile.process.kill_confirmation_timeout_ms,
            ),
            max_command_bytes: profile.tools.max_command_bytes,
            capture_bytes_per_stream: per_process.div_ceil(2),
            max_model_output_bytes: usize::try_from(profile.tools.model_tool_output_bytes_per_call)
                .unwrap_or(usize::MAX),
        }
    }

    fn parse_and_validate(&self, call: &FunctionCall) -> Result<TerminalArguments, ToolResult> {
        parse_terminal_call(call, self.max_command_bytes, self.max_timeout)
    }

    async fn execute_foreground(
        &self,
        arguments: TerminalArguments,
        workspace: &Path,
        deadline: Instant,
    ) -> ToolResult {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return attempted_rejection("terminal_deadline_exceeded");
        };
        let command_window = remaining.saturating_sub(self.terminalization_reserve);
        let timeout = Duration::from_millis(
            arguments
                .timeout
                .unwrap_or(u64::try_from(self.default_timeout.as_millis()).unwrap_or(u64::MAX)),
        )
        .min(self.max_timeout)
        .min(command_window);
        if timeout.is_zero() {
            return attempted_rejection("terminal_deadline_exceeded");
        }

        let mut command = Command::new("/bin/bash");
        command
            .arg("-lc")
            .arg(arguments.command)
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env_clear();
        for name in ["PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR", "USER"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(unix)]
        command.process_group(0);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => return attempted_rejection("terminal_spawn_failed"),
        };
        let Some(process_group) = child.id() else {
            let _ = child.start_kill();
            return attempted_rejection("terminal_pid_missing");
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = terminate_group(process_group, self.term_grace).await;
                return attempted_rejection("terminal_stdout_missing");
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                let _ = terminate_group(process_group, self.term_grace).await;
                return attempted_rejection("terminal_stderr_missing");
            }
        };
        let capture_limit = self.capture_bytes_per_stream;
        let stdout_task = tokio::spawn(drain_bounded(stdout, capture_limit));
        let stderr_task = tokio::spawn(drain_bounded(stderr, capture_limit));

        let mut timed_out = false;
        let status = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => Some(status),
            Ok(Err(_)) => None,
            Err(_) => {
                timed_out = true;
                terminate_group_with_child(
                    &mut child,
                    process_group,
                    self.term_grace,
                    self.kill_confirmation_timeout,
                )
                .await
            }
        };
        let cleanup_failed = group_exists(process_group)
            && !force_kill_and_confirm(process_group, self.kill_confirmation_timeout).await;
        let stdout = join_drain(stdout_task, self.kill_confirmation_timeout).await;
        let stderr = join_drain(stderr_task, self.kill_confirmation_timeout).await;
        let rendered = render_result(
            stdout,
            stderr,
            status,
            timed_out,
            cleanup_failed,
            self.max_model_output_bytes,
        );
        ToolResult {
            execution_attempted: true,
            outcome: if cleanup_failed {
                ToolOutcome::Rejected
            } else if timed_out {
                ToolOutcome::TimedOut
            } else {
                ToolOutcome::Succeeded
            },
            output: rendered,
            media: None,
            runtime_budget: None,
            actor_receipt: None,
        }
    }
}

impl ToolExecutor for TerminalExecutor {
    fn validate(&self, call: &FunctionCall) -> Result<(), ToolResult> {
        self.parse_and_validate(call).map(|_| ())
    }

    async fn execute(
        &mut self,
        call: &FunctionCall,
        workspace: &Path,
        deadline: Instant,
    ) -> Result<ToolResult, ToolExecutionError> {
        Ok(match self.parse_and_validate(call) {
            Ok(arguments) => {
                self.execute_foreground(arguments, workspace, deadline)
                    .await
            }
            Err(rejection) => rejection,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct TerminalArguments {
    pub(crate) command: String,
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) timeout: Option<u64>,
    #[serde(default)]
    pub(crate) background: bool,
}

pub(crate) fn parse_terminal_call(
    call: &FunctionCall,
    max_command_bytes: u64,
    max_timeout: Duration,
) -> Result<TerminalArguments, ToolResult> {
    parse_terminal_call_with_background(call, max_command_bytes, max_timeout, false)
}

pub(crate) fn parse_terminal_call_with_background(
    call: &FunctionCall,
    max_command_bytes: u64,
    max_timeout: Duration,
    allow_background: bool,
) -> Result<TerminalArguments, ToolResult> {
    if call.name != "run_terminal_command" {
        return Err(ToolResult::rejected("unsupported_in_alpha"));
    }
    let arguments = serde_json::from_str::<TerminalArguments>(&call.arguments_json)
        .map_err(|_| ToolResult::rejected("invalid_arguments"))?;
    if arguments.command.is_empty()
        || arguments.command.contains('\0')
        || arguments.description.is_empty()
        || u64::try_from(arguments.command.len()).unwrap_or(u64::MAX) > max_command_bytes
    {
        return Err(ToolResult::rejected("invalid_arguments"));
    }
    if arguments.background && !allow_background {
        return Err(ToolResult::rejected(
            "background_unsupported_in_foreground_six",
        ));
    }
    if arguments.timeout.is_some_and(|timeout| {
        (!arguments.background && timeout == 0)
            || (timeout != 0 && Duration::from_millis(timeout) > max_timeout)
    }) {
        return Err(ToolResult::rejected("invalid_arguments"));
    }
    Ok(arguments)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
    read_failed: bool,
}

impl BoundedOutput {
    fn failed() -> Self {
        Self {
            bytes: Vec::new(),
            truncated: false,
            read_failed: true,
        }
    }
}

async fn drain_bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> BoundedOutput {
    let mut kept = Vec::with_capacity(limit.min(65_536));
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(count) => {
                let remaining = limit.saturating_sub(kept.len());
                let to_keep = remaining.min(count);
                kept.extend_from_slice(&buffer[..to_keep]);
                truncated |= to_keep != count;
            }
            Err(_) => {
                return BoundedOutput {
                    bytes: kept,
                    truncated,
                    read_failed: true,
                };
            }
        }
    }
    BoundedOutput {
        bytes: kept,
        truncated,
        read_failed: false,
    }
}

async fn join_drain(
    mut task: tokio::task::JoinHandle<BoundedOutput>,
    timeout: Duration,
) -> BoundedOutput {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) => BoundedOutput::failed(),
        Err(_) => {
            task.abort();
            BoundedOutput::failed()
        }
    }
}

async fn terminate_group(process_group: u32, grace: Duration) -> bool {
    let _ = signal_group(process_group, "TERM");
    tokio::time::sleep(grace).await;
    if group_exists(process_group) {
        let _ = signal_group(process_group, "KILL");
    }
    !group_exists(process_group)
}

async fn terminate_group_with_child(
    child: &mut tokio::process::Child,
    process_group: u32,
    grace: Duration,
    confirmation: Duration,
) -> Option<ExitStatus> {
    let _ = signal_group(process_group, "TERM");
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(Ok(status)) => {
            if group_exists(process_group) {
                let _ = signal_group(process_group, "KILL");
            }
            let _ = wait_for_group_exit(process_group, confirmation).await;
            Some(status)
        }
        Ok(Err(_)) => None,
        Err(_) => {
            let _ = signal_group(process_group, "KILL");
            let status = tokio::time::timeout(confirmation, child.wait())
                .await
                .ok()
                .and_then(Result::ok);
            let _ = wait_for_group_exit(process_group, confirmation).await;
            status
        }
    }
}

async fn force_kill_and_confirm(process_group: u32, timeout: Duration) -> bool {
    let _ = signal_group(process_group, "KILL");
    wait_for_group_exit(process_group, timeout).await
}

async fn wait_for_group_exit(process_group: u32, timeout: Duration) -> bool {
    let started = Instant::now();
    while group_exists(process_group) {
        if started.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

fn signal_group(process_group: u32, signal: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args([
            format!("-{signal}"),
            "--".to_owned(),
            format!("-{process_group}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn group_exists(process_group: u32) -> bool {
    std::process::Command::new("/bin/kill")
        .args([
            "-0".to_owned(),
            "--".to_owned(),
            format!("-{process_group}"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn render_result(
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    status: Option<ExitStatus>,
    timed_out: bool,
    cleanup_failed: bool,
    max_bytes: usize,
) -> String {
    let streams_truncated = stdout.truncated || stderr.truncated;
    let stream_read_failed = stdout.read_failed || stderr.read_failed;
    let command = command_verdict(status.as_ref(), timed_out, cleanup_failed);
    let evidence = ExecutionEvidenceV1 {
        command,
        timed_out,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        effect: EffectObservationV1::Unobserved,
    };
    let header = exit_header(status.as_ref(), timed_out, cleanup_failed);
    let body = render_streams(
        stdout.bytes,
        stderr.bytes,
        header,
        streams_truncated,
        stream_read_failed,
        max_bytes,
    );
    evidence.render_before(&body, max_bytes)
}

fn command_verdict(
    status: Option<&ExitStatus>,
    timed_out: bool,
    cleanup_failed: bool,
) -> CommandVerdictV1 {
    if timed_out {
        return CommandVerdictV1::Timeout;
    }
    if cleanup_failed {
        return CommandVerdictV1::Unknown;
    }
    let Some(status) = status else {
        return CommandVerdictV1::Unknown;
    };
    if let Some(code) = status.code() {
        return CommandVerdictV1::Exit(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return CommandVerdictV1::Signal(signal);
        }
    }
    CommandVerdictV1::Unknown
}

pub(crate) fn render_external_result(
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    return_code: i32,
    timed_out: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    max_bytes: usize,
) -> String {
    let header = if timed_out {
        "exit: killed (timeout)".to_owned()
    } else {
        format!("exit: {return_code}")
    };
    render_streams(
        stdout,
        stderr,
        header,
        stdout_truncated || stderr_truncated,
        false,
        max_bytes,
    )
}

fn render_streams(
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    mut header: String,
    streams_truncated: bool,
    stream_read_failed: bool,
    max_bytes: usize,
) -> String {
    let mut raw_output = String::from_utf8_lossy(&stdout).into_owned();
    let stderr_text = String::from_utf8_lossy(&stderr);
    if !stderr_text.is_empty() {
        ensure_newline(&mut raw_output);
        raw_output.push_str(&stderr_text);
    }
    if streams_truncated {
        header.push_str(" [stream_capture_truncated]");
    }
    if stream_read_failed {
        header.push_str(" [stream_read_failed]");
    }
    let prompt_output = soft_wrap_lines(&strip_ansi(&raw_output), 2_000);
    let rendered = format!("{header}\n{prompt_output}");
    truncate_utf8(&rendered, max_bytes)
}

fn exit_header(status: Option<&ExitStatus>, timed_out: bool, cleanup_failed: bool) -> String {
    if cleanup_failed {
        return "exit: killed (process_group_cleanup_failed)".to_owned();
    }
    if timed_out {
        return "exit: killed (timeout)".to_owned();
    }
    match status {
        Some(status) => {
            if let Some(code) = status.code() {
                return format!("exit: {code}");
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(signal) = status.signal() {
                    return format!("exit: killed (signal {signal})");
                }
            }
            "exit: -1".to_owned()
        }
        None => "exit: -1 [wait_failed]".to_owned(),
    }
}

fn strip_ansi(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some('[') => {
                for next in characters.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                let mut previous_escape = false;
                for next in characters.by_ref() {
                    if next == '\u{7}' || (previous_escape && next == '\\') {
                        break;
                    }
                    previous_escape = next == '\u{1b}';
                }
            }
            Some(_) | None => {}
        }
    }
    output
}

fn soft_wrap_lines(value: &str, width: usize) -> String {
    let mut output = String::with_capacity(value.len() + 32);
    for (line_index, line) in value.lines().enumerate() {
        if line_index > 0 {
            output.push('\n');
        }
        for (character_index, character) in line.chars().enumerate() {
            if character_index > 0 && character_index % width == 0 {
                output.push('\n');
            }
            output.push(character);
        }
    }
    if !value.is_empty() && value.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn ensure_newline(value: &mut String) {
    if !value.is_empty() && !value.ends_with('\n') {
        value.push('\n');
    }
}

fn attempted_rejection(output: &'static str) -> ToolResult {
    ToolResult {
        execution_attempted: true,
        outcome: ToolOutcome::Rejected,
        output: output.to_owned(),
        media: None,
        runtime_budget: None,
        actor_receipt: None,
    }
}

#[cfg(test)]
mod tests {
    use crate::foreground::truncate_utf8;

    #[test]
    fn truncation_never_splits_utf8_and_honors_byte_cap() {
        let value = "🙂".repeat(100);
        let truncated = truncate_utf8(&value, 97);
        assert!(truncated.len() <= 97);
        assert!(truncated.contains("output truncated"));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }
}
