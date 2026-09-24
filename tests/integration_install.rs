//! Exercise the shipped binary installer in isolated user configuration directories.
#![cfg(unix)]
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn install(dir: &Path) -> Value {
    let dir = dir.canonicalize().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_signet-eval"))
        .args(["integration", "install-modern"])
        .env("HOME", &dir)
        .env("CLAUDE_CONFIG_DIR", dir.join("claude"))
        .env("SIGNET_DIR", dir.join("state"))
        .env("PATH", dir.join("bin"))
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

fn fixture() -> tempfile::TempDir {
    fixture_with_claude("2.1.274")
}

fn fixture_with_claude(version: &str) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("bin")).unwrap();
    let claude = dir.path().join("bin/claude");
    fs::write(
        &claude,
        format!("#!/bin/sh\necho '{version} (Claude Code)'\n"),
    )
    .unwrap();
    fs::set_permissions(claude, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(dir.path().join("claude")).unwrap();
    dir
}

#[test]
fn embedded_install_retires_owned_handlers_preserves_foreign_and_disabled_state() {
    let dir = fixture();
    fs::create_dir(dir.path().join("state")).unwrap();
    fs::write(dir.path().join("state/disabled"), "operator-disabled").unwrap();
    let before = json!({"env":{"EXISTING":"keep"},"hooks":{"PreToolUse":[{"matcher":"Bash","custom":"keep","hooks":[{"type":"command","command":"signet-eval"},{"type":"command","command":"foreign-check","timeout":7}]}]}});
    fs::write(dir.path().join("claude/settings.json"), before.to_string()).unwrap();
    let result = install(dir.path());
    assert_eq!(result["status"], "installed", "{result}");
    assert_eq!(result["legacy_handlers_retired"], 1);
    assert_eq!(result["enforcement_disabled"], true);
    assert_eq!(
        fs::read_to_string(dir.path().join("state/disabled")).unwrap(),
        "operator-disabled"
    );
    let settings: Value =
        serde_json::from_slice(&fs::read(dir.path().join("claude/settings.json")).unwrap())
            .unwrap();
    let registration = &settings["hooks"]["PreToolUse"][0];
    assert_eq!(registration["matcher"], "Bash");
    assert_eq!(registration["custom"], "keep");
    assert_eq!(registration["hooks"].as_array().unwrap().len(), 1);
    assert_eq!(registration["hooks"][0]["command"], "foreign-check");
    assert_eq!(settings["env"]["EXISTING"], "keep");
    assert_eq!(settings["env"]["CLAUDE_CODE_ENABLE_FUNCTION_HOOKS"], "1");
    let options = &settings["pluginConfigs"]["signet-eval-functions@skills-dir"]["options"];
    assert_eq!(options["enabled"], true);
    assert!(Path::new(options["executable"].as_str().unwrap()).is_absolute());
    let backup = Path::new(result["backup_path"].as_str().unwrap());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(backup.join("settings.json")).unwrap()).unwrap(),
        before
    );
    for relative in [
        ".claude-plugin/plugin.json",
        "hooks/hooks.json",
        "hooks/signet.ts",
    ] {
        assert!(Path::new(result["plugin_path"].as_str().unwrap())
            .join(relative)
            .is_file());
    }
    let repeated = install(dir.path());
    assert_eq!(repeated["status"], "installed");
    assert_eq!(repeated["legacy_handlers_retired"], 0);
    assert!(Path::new(repeated["backup_path"].as_str().unwrap())
        .join("previous-plugin/hooks/signet.ts")
        .exists());
}

#[test]
fn installer_refuses_unqualified_claude_without_changing_settings() {
    // 2.1.263 was the previous qualification: its API named the event
    // `PreToolUse`, which this adapter no longer registers.
    let dir = fixture_with_claude("2.1.263");
    let raw =
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"signet-eval"}]}]}}"#;
    fs::write(dir.path().join("claude/settings.json"), raw).unwrap();
    assert_eq!(
        install(dir.path())["error"],
        "unqualified_claude_version_use_legacy"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("claude/settings.json")).unwrap(),
        raw
    );
    assert!(!dir.path().join("claude/skills").exists());
}

#[test]
fn installer_refuses_unknown_wrappers_without_changing_settings() {
    let dir = fixture();
    let raw = r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"signet-eval && foreign-check"}]}]}}"#;
    fs::write(dir.path().join("claude/settings.json"), raw).unwrap();
    assert_eq!(
        install(dir.path())["error"],
        "unrecognized_signet_handler_requires_manual_review"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("claude/settings.json")).unwrap(),
        raw
    );
    assert!(!dir.path().join("claude/skills").exists());
}

#[test]
fn installer_refuses_unowned_or_linked_plugin_directories() {
    use std::os::unix::fs::symlink;
    let dir = fixture();
    let target = dir.path().join("claude/skills/signet-eval-functions");
    fs::create_dir_all(target.join(".claude-plugin")).unwrap();
    fs::write(
        target.join(".claude-plugin/plugin.json"),
        r#"{"name":"foreign-plugin"}"#,
    )
    .unwrap();
    assert_eq!(install(dir.path())["error"], "unowned_plugin_directory");
    let linked = fixture();
    fs::create_dir_all(linked.path().join("claude/skills")).unwrap();
    symlink(
        &target,
        linked.path().join("claude/skills/signet-eval-functions"),
    )
    .unwrap();
    assert_eq!(install(linked.path())["error"], "linked_install_path");
    assert_eq!(
        fs::read_to_string(target.join(".claude-plugin/plugin.json")).unwrap(),
        r#"{"name":"foreign-plugin"}"#
    );
}

#[test]
fn recovery_installer_accepts_both_qualified_hosts_preserving_disable_and_foreign_hooks() {
    // R7: Validator's 2026-09-24 repair contract qualifies exact 2.1.280,
    // preserves 2.1.274, and never broadens that qualification to unknown hosts.
    // Mutation witness: omit either qualified version, enable enforcement during
    // install, or remove a foreign hook. Existing 2.1.263 refusal is a green guard.
    for version in ["2.1.274", "2.1.280"] {
        let dir = fixture_with_claude(version);
        fs::create_dir(dir.path().join("state")).unwrap();
        fs::write(dir.path().join("state/disabled"), "operator-disabled").unwrap();
        let original = json!({"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"foreign-check"}]}]}});
        fs::write(
            dir.path().join("claude/settings.json"),
            original.to_string(),
        )
        .unwrap();
        let result = install(dir.path());
        assert_eq!(result["status"], "installed", "host {version}: {result}");
        let settings: Value =
            serde_json::from_slice(&fs::read(dir.path().join("claude/settings.json")).unwrap())
                .unwrap();
        assert_eq!(
            settings["hooks"], original["hooks"],
            "host {version}: foreign hooks changed"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("state/disabled")).unwrap(),
            "operator-disabled"
        );
        assert_eq!(result["enforcement_disabled"], true);
        assert!(Path::new(result["plugin_path"].as_str().unwrap())
            .join("hooks/signet.ts")
            .is_file());
    }
}
