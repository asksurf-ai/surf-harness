use nano_types::run_spec::GitHistoryAccess;

pub const GIT_HISTORY_NOT_REQUIRED: &str = "git_history_not_required";

/// Return whether the bound task capability denies this active tool request.
pub fn deny_git_history_request(
    tool_name: &str,
    arguments_json: &str,
    access: GitHistoryAccess,
) -> bool {
    if access == GitHistoryAccess::Required {
        return false;
    }
    let Ok(arguments) = serde_json::from_str::<serde_json::Value>(arguments_json) else {
        return false;
    };
    let Some(arguments) = arguments.as_object() else {
        return false;
    };
    let (field, classifier): (&str, fn(&str) -> bool) = match tool_name {
        "run_terminal_command" => ("command", terminal_reads_history),
        "read_file" => ("target_file", sensitive_git_path),
        "list_dir" => ("target_directory", sensitive_git_path),
        "grep" => ("path", sensitive_git_path),
        _ => return false,
    };
    arguments
        .get(field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(classifier)
}

fn terminal_reads_history(command: &str) -> bool {
    if sensitive_git_path(command) {
        return true;
    }
    let lower = command.to_ascii_lowercase();
    let Some(tokens) = shell_tokens(command) else {
        return ["git log", "git show", "git reflog", "git cat-file"]
            .iter()
            .any(|needle| lower.contains(needle));
    };
    let mut segment = Vec::new();
    for token in tokens {
        if matches!(token.as_str(), ";" | "|" | "||" | "&&" | "&" | "\n") {
            if command_segment_reads_history(&segment) {
                return true;
            }
            segment.clear();
        } else {
            segment.push(token);
        }
    }
    command_segment_reads_history(&segment)
}

fn command_segment_reads_history(tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }
    let mut index = 0;
    while index < tokens.len() && is_assignment(&tokens[index]) {
        index += 1;
    }
    loop {
        let Some(program) = tokens.get(index).map(|value| basename(value)) else {
            return false;
        };
        match program {
            "env" => {
                index += 1;
                while index < tokens.len()
                    && (tokens[index].starts_with('-') || is_assignment(&tokens[index]))
                {
                    index += 1;
                }
            }
            "command" | "exec" | "nohup" => {
                index += 1;
                while index < tokens.len() && tokens[index].starts_with('-') {
                    index += 1;
                }
            }
            "timeout" => {
                index += 1;
                while index < tokens.len() && tokens[index].starts_with('-') {
                    index += 1;
                }
                index = index.saturating_add(1);
            }
            "sh" | "bash" | "zsh" => {
                let shell_args = &tokens[index + 1..];
                if let Some(command_index) = shell_args.iter().position(|value| {
                    value == "-c" || value.ends_with('c') && value.starts_with('-')
                }) && let Some(nested) = shell_args.get(command_index + 1)
                {
                    return terminal_reads_history(nested);
                }
                return false;
            }
            _ => break,
        }
    }
    if basename(&tokens[index]) != "git" {
        return false;
    }
    git_invocation_reads_history(&tokens[index + 1..])
}

fn git_invocation_reads_history(arguments: &[String]) -> bool {
    let mut index = 0;
    let mut aliases = Vec::new();
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-c" {
            let Some(value) = arguments.get(index + 1) else {
                return true;
            };
            if let Some(alias) = value.strip_prefix("alias.")
                && let Some((name, expansion)) = alias.split_once('=')
            {
                aliases.push((name.to_owned(), expansion.to_owned()));
            }
            index += 2;
        } else if argument.starts_with("-c") && argument.len() > 2 {
            index += 1;
        } else if matches!(argument.as_str(), "-C" | "--git-dir" | "--work-tree") {
            if arguments.get(index + 1).is_none() {
                return true;
            }
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    let Some(subcommand) = arguments.get(index).map(|value| value.to_ascii_lowercase()) else {
        return false;
    };
    if let Some((_, expansion)) = aliases.iter().find(|(name, _)| name == &subcommand) {
        if let Some(shell_expansion) = expansion.strip_prefix('!') {
            return terminal_reads_history(shell_expansion);
        }
        let Some(mut expanded) = shell_tokens(expansion) else {
            return true;
        };
        expanded.extend_from_slice(&arguments[index + 1..]);
        return git_invocation_reads_history(&expanded);
    }
    let rest = &arguments[index + 1..];
    const HISTORY_SUBCOMMANDS: &str = "log reflog blame shortlog bisect cat-file fsck \
        rev-list verify-commit verify-tag merge-base name-rev describe whatchanged range-diff \
        cherry cherry-pick revert stash branch tag merge rebase";
    if HISTORY_SUBCOMMANDS
        .split_ascii_whitespace()
        .any(|candidate| candidate == subcommand)
    {
        return true;
    }
    match subcommand.as_str() {
        "show" => show_reads_history(rest),
        "diff" => diff_reads_history(rest),
        "checkout" | "switch" | "restore" | "reset" => revision_restore(rest),
        "rev-parse" => !rest.iter().all(|argument| {
            const CURRENT_STATE: &str = "--show-toplevel --show-prefix --is-inside-work-tree \
                --is-bare-repository --git-dir --absolute-git-dir";
            CURRENT_STATE
                .split_ascii_whitespace()
                .any(|allowed| allowed == argument)
        }),
        _ => false,
    }
}

fn show_reads_history(arguments: &[String]) -> bool {
    let mut revisions = arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .filter(|argument| !argument.starts_with('-'));
    let Some(revision) = revisions.next() else {
        return false;
    };
    revisions.next().is_some()
        || !(revision == "HEAD"
            || revision
                .strip_prefix("HEAD:")
                .is_some_and(|path| !path.is_empty()))
}

fn diff_reads_history(arguments: &[String]) -> bool {
    if arguments.iter().any(|argument| argument == "--no-index") {
        return false;
    }
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .filter(|argument| !argument.starts_with('-'))
        .any(|argument| argument != "HEAD" && obvious_revision(argument))
}

fn revision_restore(arguments: &[String]) -> bool {
    if arguments
        .iter()
        .filter_map(|argument| argument.strip_prefix("--source="))
        .any(|source| source != "HEAD")
    {
        return true;
    }
    let mut values = arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .filter(|argument| !argument.starts_with('-'));
    values.any(|argument| argument != "HEAD")
}

fn obvious_revision(value: &str) -> bool {
    ["HEAD", "refs/", "origin/"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
        || value.contains("..")
        || value.contains("@{")
        || value.strip_prefix('v').is_some_and(|rest| {
            rest.contains('.') && rest.starts_with(|character: char| character.is_ascii_digit())
        })
        || value.len() >= 7 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sensitive_git_path(value: &str) -> bool {
    let normalized = value
        .to_ascii_lowercase()
        .replace("\\", "/")
        .replace("%2f", "/")
        .replace("%2e", ".")
        .replace("\\u002f", "/");
    ["objects", "logs", "refs", "packed-refs", "stash"]
        .iter()
        .any(|family| normalized.contains(&format!(".git/{family}")))
}

fn basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

fn is_assignment(value: &str) -> bool {
    value.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn shell_tokens(command: &str) -> Option<Vec<String>> {
    let separated = command
        .replace("&&", " && ")
        .replace("||", " || ")
        .replace([';', '|', '&', '\n'], " ; ");
    shlex::split(&separated)
}

#[cfg(test)]
mod tests {
    use nano_types::run_spec::GitHistoryAccess;

    use super::{deny_git_history_request, terminal_reads_history};

    fn terminal(command: &str, access: GitHistoryAccess) -> bool {
        deny_git_history_request(
            "run_terminal_command",
            &serde_json::json!({"command": command}).to_string(),
            access,
        )
    }

    #[test]
    fn denies_history_revision_object_and_bounded_wrapper_forms() {
        for command in [
            "git log -p --all",
            "git show HEAD~1:src/app.c",
            "git show deadbeef",
            "git diff deadbeef -- src/app.c",
            "git diff v1.2.3 -- src/app.c",
            "git checkout refs/tags/v1 -- src/app.c",
            "git restore --source HEAD^ src/app.c",
            "git cat-file -p HEAD~1",
            "env LC_ALL=C git reflog",
            "timeout 5 command git blame src/app.c",
            "bash -lc 'git log -1'",
            "git -c alias.oracle=log oracle -p",
            "python -c \"open('.git/objects/aa/bb','rb').read()\"",
            "cat .git/logs/HEAD",
        ] {
            assert!(
                terminal(command, GitHistoryAccess::NotRequired),
                "{command}"
            );
        }
    }

    #[test]
    fn keeps_current_state_mutation_and_unrelated_git_available() {
        for command in [
            "git status --short",
            "git diff",
            "git diff HEAD",
            "git diff -- src/app.c",
            "git diff src/app.c",
            "git diff file.txt",
            "git diff Makefile",
            "git diff --cached -- src/app.c",
            "git add src/app.c",
            "git commit -m 'fix parser'",
            "git show",
            "git show HEAD",
            "git show HEAD:Makefile",
            "git show HEAD -- Makefile",
            "git restore -- src/app.c",
            "git checkout HEAD -- src/app.c",
            "git reset HEAD -- src/app.c",
            "git rev-parse --show-toplevel",
            "git clone https://example.invalid/dependency.git",
            "echo 'git log is forbidden policy text'",
        ] {
            assert!(
                !terminal(command, GitHistoryAccess::NotRequired),
                "{command}"
            );
        }
    }

    #[test]
    fn explicit_bound_capability_preserves_history_tools() {
        for command in ["git log -p", "git show HEAD~1:file", "cat .git/logs/HEAD"] {
            assert!(!terminal(command, GitHistoryAccess::Required), "{command}");
        }
    }

    #[test]
    fn direct_read_tools_block_only_sensitive_git_families() {
        for (tool, field, path) in [
            ("read_file", "target_file", "/workspace/.git/objects/aa/bb"),
            ("list_dir", "target_directory", ".git/refs/tags"),
            ("grep", "path", ".git/logs"),
        ] {
            assert!(deny_git_history_request(
                tool,
                &serde_json::json!({field: path}).to_string(),
                GitHistoryAccess::NotRequired,
            ));
        }
        assert!(!deny_git_history_request(
            "read_file",
            &serde_json::json!({"target_file": "/workspace/.github/workflows/ci.yml"}).to_string(),
            GitHistoryAccess::NotRequired,
        ));
    }

    #[test]
    fn malformed_nonhistory_input_stays_with_ordinary_argument_validation() {
        assert!(!terminal_reads_history("echo 'unterminated"));
    }
}
