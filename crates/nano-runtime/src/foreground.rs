//! Typed validation and bounded rendering for the six foreground tools.

use std::time::Duration;

use nano_provider_xai::FunctionCall;
use nano_types::contract::ToolLimits;
use serde::Deserialize;

use crate::terminal::parse_terminal_call_with_background;
use crate::tool::ToolResult;

pub(crate) const FROZEN_RESULT_MAX_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForegroundOperation {
    Terminal {
        requested_timeout_ms: Option<u64>,
        background: bool,
    },
    Filesystem,
    Search,
    BackgroundOutput {
        wait_timeout_ms: u64,
    },
    BackgroundKill,
}

#[derive(Deserialize)]
struct ReadFileArguments {
    target_file: String,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    pages: Option<String>,
    #[serde(default)]
    format: Option<String>,
}

#[derive(Deserialize)]
struct SearchReplaceArguments {
    file_path: String,
    old_string: String,
    new_string: String,
    #[serde(default)]
    replace_all: bool,
}

#[derive(Deserialize)]
struct WriteArguments {
    file_path: String,
    content: String,
}

#[derive(Deserialize)]
struct ListDirArguments {
    target_directory: String,
}

#[derive(Deserialize)]
struct GrepArguments {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    glob: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default, rename = "-A")]
    after: Option<i64>,
    #[serde(default, rename = "-B")]
    before: Option<i64>,
    #[serde(default, rename = "-C")]
    context: Option<i64>,
    #[serde(default, rename = "-i")]
    case_insensitive: bool,
    #[serde(default)]
    head_limit: Option<i64>,
    #[serde(default)]
    multiline: bool,
}

#[derive(Deserialize)]
struct KillTerminalArguments {
    task_id: String,
}

#[derive(Deserialize)]
struct GetTerminalOutputArguments {
    #[serde(default)]
    task_ids: Vec<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

pub(crate) fn validate_foreground_call(
    call: &FunctionCall,
    limits: &ToolLimits,
    background_enabled: bool,
) -> Result<ForegroundOperation, ToolResult> {
    let invalid = || ToolResult::rejected("invalid_arguments");
    match call.name.as_str() {
        "run_terminal_command" => {
            let arguments = parse_terminal_call_with_background(
                call,
                limits.max_command_bytes,
                Duration::from_millis(limits.terminal_max_timeout_ms.min(300_000)),
                background_enabled,
            )?;
            Ok(ForegroundOperation::Terminal {
                requested_timeout_ms: arguments.timeout,
                background: arguments.background,
            })
        }
        "read_file" => {
            let arguments = serde_json::from_str::<ReadFileArguments>(&call.arguments_json)
                .map_err(|_| invalid())?;
            validate_path(&arguments.target_file, limits.max_path_bytes)?;
            let _ = (
                arguments.offset,
                arguments.limit,
                arguments.pages,
                arguments.format,
            );
            Ok(ForegroundOperation::Filesystem)
        }
        "search_replace" => {
            let arguments = serde_json::from_str::<SearchReplaceArguments>(&call.arguments_json)
                .map_err(|_| invalid())?;
            validate_path(&arguments.file_path, limits.max_path_bytes)?;
            if arguments.old_string == arguments.new_string
                || exceeds(arguments.old_string.len(), limits.max_read_or_write_bytes)
                || exceeds(arguments.new_string.len(), limits.max_read_or_write_bytes)
            {
                return Err(invalid());
            }
            let _ = arguments.replace_all;
            Ok(ForegroundOperation::Filesystem)
        }
        "write" => {
            let arguments = serde_json::from_str::<WriteArguments>(&call.arguments_json)
                .map_err(|_| invalid())?;
            validate_path(&arguments.file_path, limits.max_path_bytes)?;
            if exceeds(arguments.content.len(), limits.max_read_or_write_bytes) {
                return Err(invalid());
            }
            Ok(ForegroundOperation::Filesystem)
        }
        "list_dir" => {
            let arguments = serde_json::from_str::<ListDirArguments>(&call.arguments_json)
                .map_err(|_| invalid())?;
            validate_path(&arguments.target_directory, limits.max_path_bytes)?;
            Ok(ForegroundOperation::Filesystem)
        }
        "grep" => {
            let arguments = serde_json::from_str::<GrepArguments>(&call.arguments_json)
                .map_err(|_| invalid())?;
            if let Some(path) = &arguments.path {
                validate_path(path, limits.max_path_bytes)?;
            }
            if [
                arguments.after,
                arguments.before,
                arguments.context,
                arguments.head_limit,
            ]
            .into_iter()
            .flatten()
            .any(|value| value < 0)
            {
                return Err(invalid());
            }
            if arguments.head_limit == Some(0) {
                return Err(invalid());
            }
            let _ = (
                arguments.pattern,
                arguments.glob,
                arguments.r#type,
                arguments.case_insensitive,
                arguments.multiline,
            );
            Ok(ForegroundOperation::Search)
        }
        "kill_terminal_command" if background_enabled => {
            let arguments = serde_json::from_str::<KillTerminalArguments>(&call.arguments_json)
                .map_err(|_| invalid())?;
            if !valid_task_id(&arguments.task_id) {
                return Err(invalid());
            }
            Ok(ForegroundOperation::BackgroundKill)
        }
        "get_terminal_command_output" if background_enabled => {
            let arguments =
                serde_json::from_str::<GetTerminalOutputArguments>(&call.arguments_json)
                    .map_err(|_| invalid())?;
            let mut unique = std::collections::HashSet::new();
            for task_id in &arguments.task_ids {
                let trimmed = task_id.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if !valid_task_id(trimmed) {
                    return Err(invalid());
                }
                unique.insert(trimmed);
            }
            if unique.is_empty() || unique.len() > 20 {
                return Err(invalid());
            }
            Ok(ForegroundOperation::BackgroundOutput {
                wait_timeout_ms: arguments
                    .timeout_ms
                    .unwrap_or(0)
                    .min(limits.background_output_wait_max_ms),
            })
        }
        "kill_terminal_command" | "get_terminal_command_output" => Err(ToolResult::rejected(
            "background_requires_full_tool_surface",
        )),
        _ => Err(ToolResult::rejected("unsupported_tool")),
    }
}

fn valid_task_id(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed.len() <= 256 && !trimmed.chars().any(char::is_control)
}

fn validate_path(path: &str, max_path_bytes: u64) -> Result<(), ToolResult> {
    if path.is_empty() || path.contains('\0') || exceeds(path.len(), max_path_bytes) {
        return Err(ToolResult::rejected("invalid_arguments"));
    }
    Ok(())
}

fn exceeds(actual: usize, limit: u64) -> bool {
    u64::try_from(actual).unwrap_or(u64::MAX) > limit
}

pub(crate) fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    const MARKER: &str = "\n... output truncated ...\n";
    if max_bytes <= MARKER.len() {
        let mut end = max_bytes;
        while !MARKER.is_char_boundary(end) {
            end -= 1;
        }
        return MARKER[..end].to_owned();
    }
    let remaining = max_bytes - MARKER.len();
    let mut head_end = remaining / 2;
    while !value.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = value.len() - (remaining - head_end);
    while tail_start < value.len() && !value.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!("{}{}{}", &value[..head_end], MARKER, &value[tail_start..])
}
