//! Integration tests for CLI subcommands.

use std::process::Command;

fn signet_eval(args: &[&str]) -> (String, String, i32) {
    let isolated = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_signet-eval"))
        .args(args)
        .env("HOME", isolated.path())
        .env("SIGNET_DIR", isolated.path().join("state"))
        .env("CLAUDE_CONFIG_DIR", isolated.path().join("claude"))
        .output()
        .expect("failed to start");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.code().unwrap_or(-1))
}

#[test]
fn test_help() {
    let (_, stderr, _code) = signet_eval(&["--help"]);
    // clap prints help to stdout
    let (stdout, _, _) = signet_eval(&["--help"]);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Claude Code policy enforcement") || combined.contains("signet-eval")
    );
}

#[test]
fn test_version() {
    let (stdout, stderr, _) = signet_eval(&["--version"]);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("signet-eval"));
}

#[test]
fn test_validate_no_policy() {
    // With no policy file, should report an error or say no file
    let (_, stderr, _) = signet_eval(&[
        "--policy-path",
        "/tmp/nonexistent_policy_12345.yaml",
        "validate",
    ]);
    assert!(
        stderr.contains("Cannot read") || stderr.contains("ERROR"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_init_and_validate() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let rules_path = dir.path().join("rules.yaml");
    let path_str = policy_path.to_str().unwrap();
    let rules_str = rules_path.to_str().unwrap();

    let (stdout, stderr, code) =
        signet_eval(&["--policy-path", path_str, "--rules-path", rules_str, "init"]);
    assert_eq!(code, 0, "init failed: {stderr}");
    assert!(policy_path.exists(), "policy.yaml should be created");
    assert!(
        !rules_path.exists(),
        "rules.yaml should NOT be created by init"
    );
    // sample.yaml should be created
    assert!(
        dir.path().join("sample.yaml").exists(),
        "sample.yaml should be created by init"
    );
    assert!(
        stdout.contains("Hint:") || stdout.contains("System policy written"),
        "stdout: {stdout}"
    );

    let (stdout, stderr, code) = signet_eval(&[
        "--policy-path",
        path_str,
        "--rules-path",
        rules_str,
        "validate",
    ]);
    assert_eq!(code, 0, "validate failed: {stderr}");
    assert!(
        stdout.contains("Policy valid"),
        "stdout should contain 'Policy valid': {stdout}"
    );
    assert!(stderr.is_empty(), "unexpected diagnostics: {stderr}");
}

#[test]
fn test_init_preserves_user_rules() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let rules_path = dir.path().join("rules.yaml");
    let path_str = policy_path.to_str().unwrap();
    let rules_str = rules_path.to_str().unwrap();

    // Create user rules first
    std::fs::write(
        &rules_path,
        "- name: my_custom_rule\n  tool_pattern: \".*\"\n  action: ASK\n  reason: custom\n",
    )
    .unwrap();

    // Run init — should NOT touch rules.yaml
    signet_eval(&["--policy-path", path_str, "--rules-path", rules_str, "init"]);
    let content = std::fs::read_to_string(&rules_path).unwrap();
    assert!(
        content.contains("my_custom_rule"),
        "User rules should be preserved after init"
    );
}

#[cfg(unix)]
#[test]
fn validation_keeps_warnings_for_missing_custom_checks() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "version: 1\ndefault_action: ALLOW\nrules:\n- name: check\n  tool_pattern: '^Bash$'\n  conditions: ['true']\n  action: ENSURE\n  ensure:\n    check: custom-check\n    timeout: 5\n",
    ).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_signet-eval"))
        .args(["--policy-path", policy.to_str().unwrap(), "validate"])
        .env("HOME", dir.path())
        .env("SIGNET_DIR", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Cannot resolve ensure script"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Policy valid"));
}

#[test]
fn test_rules_command() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let rules_path = dir.path().join("rules.yaml");
    let path_str = policy_path.to_str().unwrap();
    let rules_str = rules_path.to_str().unwrap();

    signet_eval(&["--policy-path", path_str, "--rules-path", rules_str, "init"]);
    let (stdout, _, code) = signet_eval(&[
        "--policy-path",
        path_str,
        "--rules-path",
        rules_str,
        "rules",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("block_rm"),
        "stdout should contain block_rm: {stdout}"
    );
    assert!(
        stdout.contains("[SYSTEM]"),
        "stdout should show [SYSTEM] labels: {stdout}"
    );
    assert!(
        stdout.contains("[LOCKED]"),
        "stdout should show [LOCKED] labels: {stdout}"
    );
}

#[test]
fn test_rules_shows_user_rules() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let rules_path = dir.path().join("rules.yaml");
    let path_str = policy_path.to_str().unwrap();
    let rules_str = rules_path.to_str().unwrap();

    signet_eval(&["--policy-path", path_str, "--rules-path", rules_str, "init"]);
    std::fs::write(
        &rules_path,
        "- name: my_rule\n  tool_pattern: \".*\"\n  action: ASK\n  reason: test\n",
    )
    .unwrap();

    let (stdout, _, code) = signet_eval(&[
        "--policy-path",
        path_str,
        "--rules-path",
        rules_str,
        "rules",
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("my_rule"),
        "stdout should contain user rule: {stdout}"
    );
    assert!(
        stdout.contains("[USER]"),
        "stdout should show [USER] label: {stdout}"
    );
}

#[test]
fn test_test_command() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let rules_path = dir.path().join("rules.yaml");
    let path_str = policy_path.to_str().unwrap();
    let rules_str = rules_path.to_str().unwrap();

    signet_eval(&["--policy-path", path_str, "--rules-path", rules_str, "init"]);

    let (stdout, _, code) = signet_eval(&[
        "--policy-path",
        path_str,
        "--rules-path",
        rules_str,
        "test",
        r#"{"tool_name":"Bash","tool_input":{"command":"rm foo"}}"#,
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Deny"),
        "stdout should contain Deny: {stdout}"
    );

    let (stdout, _, code) = signet_eval(&[
        "--policy-path",
        path_str,
        "--rules-path",
        rules_str,
        "test",
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    ]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Allow"),
        "stdout should contain Allow: {stdout}"
    );
}

#[test]
fn test_test_command_accepts_antigravity_payload() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    let rules_path = dir.path().join("rules.yaml");
    let path_str = policy_path.to_str().unwrap();
    let rules_str = rules_path.to_str().unwrap();

    signet_eval(&["--policy-path", path_str, "--rules-path", rules_str, "init"]);

    let (stdout, stderr, code) = signet_eval(&[
        "--adapter",
        "antigravity",
        "--policy-path",
        path_str,
        "--rules-path",
        rules_str,
        "test",
        r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"rm foo","Cwd":"/tmp"}},"stepIdx":19,"conversationId":"ec33ebf9-0cba-4100-8142-c61503f6c587","workspacePaths":["/tmp"],"transcriptPath":"/tmp/transcript.jsonl","artifactDirectoryPath":"/tmp/artifacts"}"#,
    ]);
    assert_eq!(code, 0, "test failed: {stderr}");
    assert!(
        stdout.contains("Deny"),
        "stdout should contain Deny: {stdout}"
    );
}

#[test]
fn test_status_no_vault() {
    let (stdout, stderr, code) = signet_eval(&["status"]);
    // Without a vault, should tell user to set up (error goes to stderr)
    // With a vault, status goes to stdout
    let combined = format!("{stdout}{stderr}");
    assert!(
        code != 0
            || combined.contains("not set up")
            || combined.contains("locked")
            || combined.contains("Vault")
    );
}
