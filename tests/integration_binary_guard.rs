//! Independent regression contract B1-B3, Validator dispatch 2026-09-24.
//! B1 Repository/data references do not select protect_signet_binary.
//! B2 Actual installed executable tampering remains denied by that guard.
//! B3 Bare disable/setup/unlock invocations remain denied.
//! Runs the CLI's policy-test interface; never executes supplied shell commands.
//! Missing policy/rules and isolated HOME/SIGNET_DIR force deterministic defaults.
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn evaluate_case(input: Value) -> (String, String) {
    evaluate_with_executable(&test_executable(), input)
}

fn test_executable() -> PathBuf {
    std::env::var_os("SIGNET_GUARD_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_signet-eval")))
}

fn evaluate_with_executable(executable: &Path, input: Value) -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(executable)
        .args([
            "--policy-path",
            dir.path().join("absent-policy.yaml").to_str().unwrap(),
            "--rules-path",
            dir.path().join("absent-rules.yaml").to_str().unwrap(),
            "test",
            &input.to_string(),
        ])
        .env("HOME", dir.path())
        .env("SIGNET_DIR", dir.path().join("state"))
        .env("CLAUDE_CONFIG_DIR", dir.path().join("claude"))
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "policy test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let field = |name: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(name).map(str::trim))
            .unwrap_or_else(|| panic!("missing {name} in {stdout}"))
            .to_owned()
    };
    (field("Decision:"), field("Matched rule:"))
}

#[test]
fn repository_and_body_references_are_not_installed_binary_targets() {
    // RED B1. Removing target-vs-data discrimination must turn this red.
    for command in [
        "ls -la /Users/example/Code/signet-eval",
        "find /Users/example/Code/signet-eval -maxdepth 1 -type f",
        "rg --files /Users/example/Code/signet-eval",
        "cat /Users/example/Code/signet-eval/README.md",
        "git -C /Users/example/Code/signet-eval status --short",
        "gh pr list --repo wandercom/signet-eval",
        "gh pr view 23 --repo 'wandercom/signet-eval'",
    ] {
        let (_, rule) = evaluate_case(json!({"tool_name":"Bash","tool_input":{"command":command}}));
        assert_ne!(
            rule, "protect_signet_binary",
            "B1 inert repository reference: {command}"
        );
    }
    for (tool, input) in [
        (
            "Write",
            json!({"file_path":"/tmp/review-notes.md","content":"Investigate signet-eval; installed at /opt/homebrew/bin/signet-eval"}),
        ),
        (
            "Edit",
            json!({"file_path":"/tmp/review-notes.md","old_string":"signet-eval","new_string":"Review ~/.cargo/bin/signet-eval"}),
        ),
    ] {
        let (_, rule) = evaluate_case(json!({"tool_name":tool,"tool_input":input}));
        assert_ne!(
            rule, "protect_signet_binary",
            "B1 structured file body is data: {tool}"
        );
    }
}

#[test]
fn actual_installed_binary_targets_stay_protected_under_shell_spelling() {
    // GREEN B2. Match must reach this exact guard, not unrelated rm denial.
    for command in [
        "cp /dev/null /opt/homebrew/bin/signet-eval",
        r#"cp /dev/null /opt/"homebrew"/bin/signet-eval"#,
        r"cp /dev/null /opt/homebrew/b\in/signet-eval",
        concat!("cp /dev/null /opt/homebrew/bi", "\\", "\n", "n/signet-eval"),
        "cp /dev/null /opt/homebrew/bin/./signet-eval",
        "cp /dev/null /opt/homebrew/bin/../bin/signet-eval",
        "cp /dev/null '/opt/homebrew/bin/signet-eval'",
        "cp /dev/null /opt/homebrew/bin/signet\\-eval",
        "cp /dev/null ~/.cargo/bin/signet-eval",
        "cp /dev/null \"$HOME/.cargo/bin/signet-eval\"",
        "cp /dev/null ~/.cargo/bin/signet\\-eval",
        "printf broken > /opt/homebrew/bin/signet-eval",
        "chmod -x ~/.cargo/bin/signet-eval",
    ] {
        let (decision, rule) =
            evaluate_case(json!({"tool_name":"Bash","tool_input":{"command":command}}));
        assert_eq!(decision, "Deny", "B2 installed binary mutation: {command}");
        assert_eq!(
            rule, "protect_signet_binary",
            "B2 correct guard must be reached: {command}"
        );
    }
    for tool in ["Write", "Edit"] {
        for path in [
            "/opt/homebrew/bin/signet-eval",
            "/opt/homebrew/bin/./signet-eval",
            "/opt/homebrew/bin/../bin/signet-eval",
            "/home/example/.cargo/bin/signet-eval",
        ] {
            let (decision, rule) = evaluate_case(
                json!({"tool_name":tool,"tool_input":{"file_path":path,"content":"broken","old_string":"old","new_string":"broken"}}),
            );
            assert_eq!(
                decision, "Deny",
                "B2 direct installed binary mutation: {tool} {path}"
            );
            assert_eq!(
                rule, "protect_signet_binary",
                "B2 direct target must reach binary guard"
            );
        }
    }
}

#[test]
fn signet_control_invocations_remain_protected() {
    // GREEN B3. Unlike repository text, these are invocations that affect Signet.
    for command in [
        "signet-eval disable",
        "signet-eval setup",
        "signet-eval unlock",
        "signet-eval reset-session",
        "signet-eval delete credential",
        "signet-eval pause",
        "signet-eval --adapter claude disable",
        "FOO=bar signet-eval disable",
        "env FOO=bar signet-eval disable",
        "command signet-eval disable",
        "sh -c 'signet-eval disable'",
        "bash -lc 'signet-eval disable'",
    ] {
        let (decision, _) =
            evaluate_case(json!({"tool_name":"Bash","tool_input":{"command":command}}));
        assert_eq!(decision, "Deny", "B3 protected Signet operation: {command}");
    }
}

#[test]
fn ambiguous_relative_binary_write_remains_protected() {
    // B2 extension: Validator review dispatch requires conservative protection
    // when a relative executable target cannot be distinguished from bin cwd.
    let (decision, rule) = evaluate_case(json!({
        "tool_name":"Write",
        "tool_input":{"file_path":"signet-eval","content":"replacement"}
    }));
    assert_eq!(decision, "Deny", "B2 ambiguous relative binary write");
    assert_eq!(
        rule, "protect_signet_binary",
        "B2 relative binary target reaches protection"
    );
}

#[test]
fn wrapped_control_invocations_reach_binary_protection() {
    // B3 release-blocker extension: wrappers change launch mechanics, not the
    // protected control. Exact rule assertions exclude unrelated denials.
    for command in [
        "nice signet-eval disable",
        "nice -n 5 signet-eval disable",
        "nice --adjustment=5 signet-eval pause",
        "nohup signet-eval disable",
        "nohup -- signet-eval reset-session",
        "timeout 10s signet-eval disable",
        "timeout .5s signet-eval disable",
        "timeout 1. signet-eval disable",
        "timeout --signal=TERM -k 1s 10s signet-eval pause",
        "timeout -s TERM -k 1s 10s signet-eval reset-session",
        "timeout --foreground 10s signet-eval disable",
        "nice -n 5 nohup timeout 10s signet-eval disable",
        "env FOO=bar timeout -s TERM 10s nice -n 5 nohup signet-eval pause",
        "command nohup nice -n 5 timeout --signal=TERM 10s signet-eval --adapter claude disable",
    ] {
        let (decision, rule) = evaluate_case(json!({
            "tool_name":"Bash", "tool_input":{"command":command}
        }));
        assert_eq!(decision, "Deny", "B3 wrapped control: {command}");
        assert_eq!(
            rule, "protect_signet_binary",
            "B3 wrapper must reach exact guard: {command}"
        );
    }
}

#[test]
fn custom_and_renamed_running_binary_targets_remain_protected() {
    // B2 release-blocker extension: the executable answering policy-test is
    // the installed owner, including custom directories and renamed binaries.
    // Only policy-test is launched; every mutation string remains JSON data.
    for name in ["signet-eval", "policy-owner-custom"] {
        let installation = tempfile::tempdir().unwrap();
        let directory = installation.path().join("custom tools");
        fs::create_dir(&directory).unwrap();
        let installed = directory.join(name);
        fs::copy(test_executable(), &installed).unwrap();
        let installed = installed.canonicalize().unwrap();
        let quoted = format!("'{}'", installed.to_str().unwrap().replace('\'', "'\\''"));
        for command in [
            format!("cp /dev/null {quoted}"),
            format!("printf replacement > {quoted}"),
            format!("chmod -x {quoted}"),
        ] {
            let (decision, rule) = evaluate_with_executable(
                &installed,
                json!({
                    "tool_name":"Bash", "tool_input":{"command":command}
                }),
            );
            assert_eq!(
                decision, "Deny",
                "B2 actual running binary mutation: {command}"
            );
            assert_eq!(
                rule, "protect_signet_binary",
                "B2 actual owner must reach binary guard: {command}"
            );
        }
        for (tool, input) in [
            (
                "Write",
                json!({"file_path":installed,"content":"replacement"}),
            ),
            (
                "Edit",
                json!({"file_path":installed,"old_string":"old","new_string":"replacement"}),
            ),
        ] {
            let (decision, rule) = evaluate_with_executable(
                &installed,
                json!({
                    "tool_name":tool, "tool_input":input
                }),
            );
            assert_eq!(
                decision, "Deny",
                "B2 direct actual owner mutation: {tool} {name}"
            );
            assert_eq!(
                rule, "protect_signet_binary",
                "B2 direct owner target reaches guard"
            );
        }
        // B1 still holds with a custom owner: repository paths and prose are
        // not binary targets, even when prose names the actual executable.
        for input in [
            json!({"tool_name":"Bash","tool_input":{"command":"cat /workspace/projects/signet-eval/README.md"}}),
            json!({"tool_name":"Bash","tool_input":{"command":"ls /workspace/projects/signet-eval/src"}}),
            json!({"tool_name":"Write","tool_input":{"file_path":"/workspace/notes.md","content":format!("Installed owner: {}", installed.display())}}),
        ] {
            let (_, rule) = evaluate_with_executable(&installed, input);
            assert_ne!(
                rule, "protect_signet_binary",
                "B1 inert reference under custom owner {name}"
            );
        }
    }
}
