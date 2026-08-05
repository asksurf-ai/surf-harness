//! Versioned, task-neutral protected-target policy and pre-dispatch matcher.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Deserialize;

pub const PROTECTED_TARGET_POLICY_JSON: &str =
    include_str!("../../../policy/protected-targets-v1.json");
pub const PROTECTED_HARNESS_MATERIAL_ACCESS_BLOCKED: &str =
    "protected_harness_material_access_blocked";
pub const PROTECTED_TARGET_PERMISSION_DENIED: &str = "permission_denied";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedTargetKind {
    ProtectedPath,
    OfficialBenchmarkRepository,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedTargetMatch {
    pub kind: ProtectedTargetKind,
    pub field: String,
    pub policy_value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedTargetPolicy {
    schema_version: String,
    fatal_code: String,
    workspace_root: String,
    protected_path_families: Vec<String>,
    official_benchmark_repository_slugs: Vec<String>,
    terminal_command_fields: BTreeMap<String, Vec<String>>,
    filesystem_path_fields: BTreeMap<String, Vec<String>>,
}

static POLICY: OnceLock<ProtectedTargetPolicy> = OnceLock::new();

pub fn match_protected_target(
    tool_name: &str,
    arguments_json: &str,
) -> Option<ProtectedTargetMatch> {
    let policy = embedded_policy();
    let arguments = serde_json::from_str::<serde_json::Value>(arguments_json).ok()?;
    let arguments = arguments.as_object()?;

    if let Some(fields) = policy.terminal_command_fields.get(tool_name) {
        for field in fields {
            let Some(command) = arguments.get(field).and_then(serde_json::Value::as_str) else {
                continue;
            };
            let normalized = normalize_syntax(command);
            if let Some(slug) = policy
                .official_benchmark_repository_slugs
                .iter()
                .find(|slug| normalized.contains(slug.as_str()))
            {
                return Some(ProtectedTargetMatch {
                    kind: ProtectedTargetKind::OfficialBenchmarkRepository,
                    field: field.clone(),
                    policy_value: slug.clone(),
                });
            }
            if let Some(root) = terminal_path_fragments(&normalized)
                .find_map(|path| match_protected_path(path, policy))
            {
                return Some(ProtectedTargetMatch {
                    kind: ProtectedTargetKind::ProtectedPath,
                    field: field.clone(),
                    policy_value: root.to_owned(),
                });
            }
        }
    }

    if let Some(fields) = policy.filesystem_path_fields.get(tool_name) {
        for field in fields {
            let Some(path) = arguments.get(field).and_then(serde_json::Value::as_str) else {
                continue;
            };
            if let Some(root) = match_protected_path(path, policy) {
                return Some(ProtectedTargetMatch {
                    kind: ProtectedTargetKind::ProtectedPath,
                    field: field.clone(),
                    policy_value: root.to_owned(),
                });
            }
        }
    }

    None
}

fn embedded_policy() -> &'static ProtectedTargetPolicy {
    POLICY.get_or_init(|| {
        let policy: ProtectedTargetPolicy = serde_json::from_str(PROTECTED_TARGET_POLICY_JSON)
            .expect("embedded protected-target policy must be valid JSON");
        validate_policy(&policy).expect("embedded protected-target policy must be valid");
        policy
    })
}

fn validate_policy(policy: &ProtectedTargetPolicy) -> Result<(), &'static str> {
    if policy.schema_version != "protected-targets-v1" {
        return Err("protected-target schema version mismatch");
    }
    if policy.fatal_code != PROTECTED_HARNESS_MATERIAL_ACCESS_BLOCKED {
        return Err("protected-target fatal code mismatch");
    }
    if lexical_path(&policy.workspace_root, "/") != policy.workspace_root
        || !policy.workspace_root.starts_with('/')
    {
        return Err("protected-target workspace root is not canonical");
    }
    let mut roots = BTreeSet::new();
    for root in &policy.protected_path_families {
        if !root.starts_with('/')
            || lexical_path(root, &policy.workspace_root) != *root
            || !roots.insert(root)
        {
            return Err("protected path family is invalid");
        }
    }
    let mut slugs = BTreeSet::new();
    for slug in &policy.official_benchmark_repository_slugs {
        if slug.is_empty()
            || slug != &slug.to_ascii_lowercase()
            || !slug.contains('/')
            || !slugs.insert(slug)
        {
            return Err("official repository slug is invalid");
        }
    }
    for fields in policy
        .terminal_command_fields
        .values()
        .chain(policy.filesystem_path_fields.values())
    {
        let mut unique = BTreeSet::new();
        if fields.is_empty()
            || fields
                .iter()
                .any(|field| field.is_empty() || !unique.insert(field))
        {
            return Err("protected-target tool fields are invalid");
        }
    }
    if policy
        .terminal_command_fields
        .keys()
        .any(|tool| policy.filesystem_path_fields.contains_key(tool))
    {
        return Err("protected-target tool surface is ambiguous");
    }
    Ok(())
}

fn normalize_syntax(value: &str) -> String {
    let mut normalized = value.to_ascii_lowercase();
    for _ in 0..2 {
        normalized = normalized
            .replace("\\u002f", "/")
            .replace("\\u005c", "/")
            .replace("\\/", "/")
            .replace("%2f", "/")
            .replace("%5c", "/")
            .replace("%2e", ".")
            .replace("%3a", ":");
    }
    normalized = normalized.replace('\\', "/");
    let mut collapsed = String::with_capacity(normalized.len());
    let mut previous_slash = false;
    for character in normalized.chars() {
        if character == '/' {
            if !previous_slash {
                collapsed.push(character);
            }
            previous_slash = true;
        } else {
            collapsed.push(character);
            previous_slash = false;
        }
    }
    collapsed
}

fn terminal_path_fragments(command: &str) -> impl Iterator<Item = &str> {
    command
        .split(|character: char| {
            character.is_ascii_whitespace()
                || matches!(
                    character,
                    '\'' | '"'
                        | '`'
                        | ';'
                        | '|'
                        | '&'
                        | '('
                        | ')'
                        | '<'
                        | '>'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | ','
                        | '='
                )
        })
        .filter(|fragment| {
            fragment.starts_with('/')
                || fragment.starts_with("./")
                || fragment.starts_with("../")
                || fragment.starts_with("file:")
        })
}

fn match_protected_path<'a>(path: &str, policy: &'a ProtectedTargetPolicy) -> Option<&'a str> {
    let syntax = path_without_file_scheme(&normalize_syntax(path));
    let rooted_syntax = if syntax.starts_with('/') {
        syntax
    } else {
        format!("{}/{syntax}", policy.workspace_root)
    };
    let lexical = lexical_path(&rooted_syntax, &policy.workspace_root);
    for candidate in [&rooted_syntax, &lexical] {
        if let Some(root) = policy
            .protected_path_families
            .iter()
            .find(|root| path_is_within(candidate, root))
        {
            return Some(root.as_str());
        }
        if let Some(alias) = linux_proc_root_alias(candidate)
            && let Some(root) = policy
                .protected_path_families
                .iter()
                .find(|root| path_is_within(&alias, root))
        {
            return Some(root.as_str());
        }
    }
    None
}

fn linux_proc_root_alias(path: &str) -> Option<String> {
    let components = path.strip_prefix('/')?.split('/').collect::<Vec<_>>();
    if components.len() < 4 || components[0] != "proc" || components[2] != "root" {
        return None;
    }
    let process = components[1];
    if process != "self"
        && (process.is_empty() || !process.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some(format!("/{}", components[3..].join("/")))
}

fn path_without_file_scheme(path: &str) -> String {
    path.strip_prefix("file:").unwrap_or(path).to_owned()
}

fn lexical_path(path: &str, workspace_root: &str) -> String {
    let normalized = normalize_syntax(path);
    let normalized = path_without_file_scheme(&normalized);
    let rooted = if normalized.starts_with('/') {
        normalized
    } else {
        format!("{workspace_root}/{normalized}")
    };
    let mut components = Vec::new();
    for component in rooted.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    }
}

fn path_is_within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::{
        PROTECTED_HARNESS_MATERIAL_ACCESS_BLOCKED, PROTECTED_TARGET_POLICY_JSON,
        ProtectedTargetKind, ProtectedTargetPolicy, match_protected_target,
    };

    fn arguments(field: &str, value: &str) -> String {
        serde_json::json!({field: value}).to_string()
    }

    #[test]
    fn protected_target_policy_is_versioned_task_neutral_and_covers_every_path_tool() {
        let policy: ProtectedTargetPolicy =
            serde_json::from_str(PROTECTED_TARGET_POLICY_JSON).expect("embedded policy JSON");
        assert_eq!(policy.schema_version, "protected-targets-v1");
        assert_eq!(policy.fatal_code, PROTECTED_HARNESS_MATERIAL_ACCESS_BLOCKED);
        assert_eq!(policy.workspace_root, "/workspace");
        assert_eq!(policy.protected_path_families, ["/logs"]);
        assert_eq!(
            policy.official_benchmark_repository_slugs,
            [
                "harbor-framework/terminal-bench",
                "laude-institute/terminal-bench"
            ]
        );
        assert_eq!(
            policy
                .terminal_command_fields
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["run_terminal_command"]
        );
        assert_eq!(
            policy
                .filesystem_path_fields
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["grep", "list_dir", "read_file", "search_replace", "write"]
        );
        for forbidden_key in ["task_id", "answer", "expected_output", "hint"] {
            assert!(!PROTECTED_TARGET_POLICY_JSON.contains(forbidden_key));
        }
    }

    #[test]
    fn protected_target_normalization_blocks_bounded_direct_references() {
        for (tool, field, value) in [
            (
                "read_file",
                "target_file",
                "/logs/agent/input/run-spec.json",
            ),
            (
                "read_file",
                "target_file",
                "/LOGS/AGENT/runtime/events.jsonl",
            ),
            ("list_dir", "target_directory", r"/logs\u002fverifier"),
            ("grep", "path", "/logs%2Freward"),
            ("write", "file_path", "/logs//judge/result.json"),
            ("search_replace", "file_path", "/logs/./agent/run.json"),
            (
                "read_file",
                "target_file",
                "/tmp/../logs/verifier/reward.txt",
            ),
            (
                "read_file",
                "target_file",
                "../logs/agent/runtime/events.jsonl",
            ),
            ("read_file", "target_file", "file:///logs/agent/run.json"),
            (
                "read_file",
                "target_file",
                "/proc/self/root/logs/agent/input/run-spec.json",
            ),
            (
                "read_file",
                "target_file",
                "/tmp/../proc/123/root/logs/verifier/reward.txt",
            ),
            (
                "read_file",
                "target_file",
                r"/proc/42/root%2flogs%2fagent%2fruntime%2fevents.jsonl",
            ),
        ] {
            let finding = match_protected_target(tool, &arguments(field, value))
                .unwrap_or_else(|| panic!("must block {tool}.{field}={value}"));
            assert_eq!(finding.kind, ProtectedTargetKind::ProtectedPath);
            assert_eq!(finding.field, field);
        }
        for command in [
            "cat /logs/agent/input/run-spec.json",
            "find /logs//verifier -maxdepth 1",
            "cat /tmp/../logs/reward/value",
            "cat ../logs/judge/result.json",
            r"cat file:\/\/\/logs\/agent\/runtime\/events.jsonl",
            "p=/logs; cat \"$p/agent/input/run-spec.json\"",
            "cat /proc/self/root/logs/agent/input/run-spec.json",
            "cat /proc/123/root/logs/verifier/reward.txt",
            "cat /tmp/../proc/456/root/logs/reward/value",
            r"cat /proc/self/root%2flogs%2fjudge%2fresult.json",
        ] {
            let finding =
                match_protected_target("run_terminal_command", &arguments("command", command))
                    .unwrap_or_else(|| panic!("must block terminal command: {command}"));
            assert_eq!(finding.kind, ProtectedTargetKind::ProtectedPath);
            assert_eq!(finding.field, "command");
        }
    }

    #[test]
    fn protected_target_matcher_keeps_workspace_and_non_path_text_available() {
        for (tool, payload) in [
            (
                "read_file",
                arguments("target_file", "/workspace/logs/agent-notes"),
            ),
            (
                "list_dir",
                arguments("target_directory", "/workspace/logs/agent"),
            ),
            ("read_file", arguments("target_file", "/var/logs/agent")),
            (
                "read_file",
                arguments("target_file", "/proc/self/root/workspace/logs/agent"),
            ),
            ("grep", arguments("path", "logs/agent")),
            (
                "run_terminal_command",
                arguments("command", "echo ordinary logs word"),
            ),
            (
                "run_terminal_command",
                serde_json::json!({
                    "command": "git clone https://github.com/rust-lang/cargo",
                    "description": "compare harbor-framework/terminal-bench as policy text"
                })
                .to_string(),
            ),
            (
                "grep",
                serde_json::json!({
                    "path": "/workspace",
                    "pattern": "/logs/agent|harbor-framework/terminal-bench"
                })
                .to_string(),
            ),
            ("read_file", "{".to_owned()),
            ("kill_terminal_command", arguments("task_id", "/logs/agent")),
        ] {
            assert_eq!(
                match_protected_target(tool, &payload),
                None,
                "{tool}: {payload}"
            );
        }
    }

    #[test]
    fn protected_target_matcher_blocks_official_repositories_only_in_command_field() {
        for command in [
            "git clone https://github.com/harbor-framework/terminal-bench",
            "curl https://api.github.com/repos/LAUDE-INSTITUTE%2FTERMINAL-BENCH",
            r"curl https:\/\/github.com\/harbor-framework\u002fterminal-bench",
        ] {
            let finding =
                match_protected_target("run_terminal_command", &arguments("command", command))
                    .expect("official repository must be blocked");
            assert_eq!(
                finding.kind,
                ProtectedTargetKind::OfficialBenchmarkRepository
            );
            assert_eq!(finding.field, "command");
        }
        assert_eq!(
            match_protected_target(
                "run_terminal_command",
                &serde_json::json!({
                    "command": "true",
                    "description": "harbor-framework/terminal-bench"
                })
                .to_string()
            ),
            None
        );
    }
}
