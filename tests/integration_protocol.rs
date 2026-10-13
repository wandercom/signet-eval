use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn invoke(dir: &Path, action: &str, input: &Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_signet-eval"))
        .args([
            "--policy-path",
            dir.join("policy.yaml").to_str().unwrap(),
            "--rules-path",
            dir.join("rules.yaml").to_str().unwrap(),
            "integration",
            action,
        ])
        .env("SIGNET_DIR", dir.join("state"))
        .env("CLAUDE_CONFIG_DIR", dir.join("claude"))
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "invalid response: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn scope(dir: &Path) -> Value {
    json!({"project_path":dir.to_str().unwrap(),"session_id":"session-1","agent":"agent-1"})
}

fn intent(dir: &Path, id: &str) -> Value {
    let scoped = scope(dir);
    let state = invoke(dir, "describe", &scoped);
    assert_eq!(state["active"], true);
    assert_eq!(state["capabilities"]["host_redaction"]["ready"], false);
    let source = json!({"subject":"durable followup"});
    json!({"protocol_version":1,"operation_id":id,"session_id":"session-1","project_path":dir.to_str().unwrap(),"agent":"agent-1","policy_revision":state["policy_revision"],"source_tool":"TaskCreate","source_input":source,"target_tool":"kindex.task.create","input":{"operation":"create","args":{"title":"durable followup"},"scope":scoped,"source_input":source}})
}

#[test]
fn delegation_replays_and_binds_complete_intent_without_storing_raw_input() {
    let dir = tempfile::tempdir().unwrap();
    let mut request = intent(dir.path(), "operation-1");
    request["input"]["args"]["description"] = json!("api_key=private-canary-value");
    let first = invoke(dir.path(), "adjudicate", &request);
    assert_eq!(first["decision"], "allow", "{first}");
    assert_eq!(first["receipt"]["evidence"], "authorized_intent");
    let repeat = invoke(dir.path(), "adjudicate", &request);
    assert_eq!(repeat["receipt"], first["receipt"]);
    assert_eq!(repeat["replayed"], true);
    request["input"]["args"]["title"] = json!("different operation");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &request)["error"],
        "operation_id_conflict"
    );
    let bytes = std::fs::read(dir.path().join("state/integration.db")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("private-canary-value"));
    assert!(!String::from_utf8_lossy(&bytes).contains("durable followup"));
}

#[test]
fn disabled_revision_and_scope_loss_refuse_even_previous_allow() {
    let dir = tempfile::tempdir().unwrap();
    let request = intent(dir.path(), "operation-1");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &request)["decision"],
        "allow"
    );
    std::fs::write(dir.path().join("state/disabled"), "1").unwrap();
    assert_eq!(
        invoke(dir.path(), "adjudicate", &request)["error"],
        "disabled"
    );
    assert_eq!(
        invoke(dir.path(), "describe", &scope(dir.path()))["capabilities"]["task_enforcement"]
            ["ready"],
        false
    );
    std::fs::remove_file(dir.path().join("state/disabled")).unwrap();
    let mut wrong = request.clone();
    wrong["policy_revision"] = json!("stale");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &wrong)["error"],
        "policy_revision_changed"
    );
    wrong = request;
    wrong["input"]["scope"]["session_id"] = json!("another-session");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &wrong)["error"],
        "input_scope_mismatch"
    );
}

#[test]
fn dedicated_delegation_does_not_suppress_user_source_or_target_denials() {
    for tool in ["TaskCreate", "mcp__kindex__task_add", "kindex.task.create"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rules.yaml"),format!("- name: deliberate_deny\n  tool_pattern: ^{tool}$\n  conditions: ['true']\n  action: DENY\n  reason: Explicit operator denial\n")).unwrap();
        let request = intent(dir.path(), "denied-operation");
        let result = invoke(dir.path(), "adjudicate", &request);
        assert_eq!(result["decision"], "deny", "{tool}: {result}");
        assert!(result["reason"]
            .as_str()
            .unwrap()
            .contains("Explicit operator denial"));
    }
}

#[test]
fn admission_ignores_caller_supplied_agent_model_on_source_and_target() {
    for tool in ["TaskCreate", "mcp__kindex__task_add", "kindex.task.create"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rules.yaml"), format!("- name: opus_only\n  tool_pattern: ^{tool}$\n  conditions: [\"not(matches(agent_model, '^claude-opus-'))\"]\n  action: DENY\n  reason: Opus only\n")).unwrap();
        let mut request = intent(dir.path(), "model-operation");
        request["source_input"]["agent_model"] = json!("claude-opus-5-5");
        request["input"]["source_input"] = request["source_input"].clone();
        request["input"]["args"]["agent_model"] = json!("claude-opus-5-5");
        let result = invoke(dir.path(), "adjudicate", &request);
        assert_eq!(result["decision"], "deny", "{tool}: {result}");
        assert_eq!(result["reason"], "Opus only", "{tool}: {result}");
    }
}

#[test]
fn source_policy_receives_exact_native_fields_without_persisting_their_values() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rules.yaml"), "- name: native_subject_deny\n  tool_pattern: ^TaskCreate$\n  conditions: [\"param_contains(subject, 'secret-subject')\"]\n  action: DENY\n  reason: Subject denied\n").unwrap();
    let mut request = intent(dir.path(), "operation-1");
    request["source_input"] = json!({"subject":"secret-subject"});
    request["input"]["source_input"] = request["source_input"].clone();
    assert_eq!(
        invoke(dir.path(), "adjudicate", &request)["reason"],
        "Subject denied"
    );
    request["source_input"] =
        json!({"subject":"visible title", "description":"api_key=native-secret-canary"});
    request["input"]["source_input"] = request["source_input"].clone();
    let admitted = invoke(dir.path(), "adjudicate", &request);
    assert_eq!(admitted["decision"], "allow", "{admitted}");
    let bytes = std::fs::read(dir.path().join("state/integration.db")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("native-secret-canary"));
    request["input"]["source_input"] = json!({});
    assert_eq!(
        invoke(dir.path(), "adjudicate", &request)["error"],
        "source_input_mismatch"
    );
    request.as_object_mut().unwrap().remove("source_input");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &request)["error"],
        "source_input_required"
    );
}

#[test]
fn exact_source_target_pairs_and_protocol_are_required() {
    let dir = tempfile::tempdir().unwrap();
    let request = intent(dir.path(), "operation-1");
    for source in ["Agent", "Task", "TaskOutput", "TaskStop", "Bash"] {
        let mut wrong = request.clone();
        wrong["source_tool"] = json!(source);
        assert_eq!(
            invoke(dir.path(), "adjudicate", &wrong)["error"],
            "unsupported_delegation"
        );
    }
    let mut wrong = request.clone();
    wrong["input"]["args"]["operation_id"] = json!("mismatch");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &wrong)["error"],
        "target_operation_id_mismatch"
    );
    let mut wrong = request.clone();
    wrong["input"]["operation"] = json!("cancel");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &wrong)["error"],
        "target_input_mismatch"
    );
    let mut wrong = request;
    wrong["protocol_version"] = json!(2);
    assert_eq!(invoke(dir.path(), "adjudicate", &wrong)["decision"], "deny");
}

#[test]
fn operation_ids_are_scoped_by_project_session_agent_and_profile() {
    let dir = tempfile::tempdir().unwrap();
    let first = intent(dir.path(), "same-operation-id");
    let receipt = invoke(dir.path(), "adjudicate", &first)["receipt"].clone();
    let project = dir.path().join("another-project");
    std::fs::create_dir(&project).unwrap();
    for (field, value) in [
        ("project_path", project.to_str().unwrap()),
        ("session_id", "another-session"),
        ("agent", "another-agent"),
        ("profile", "another-profile"),
    ] {
        let mut scoped = first.clone();
        scoped[field] = json!(value);
        scoped["input"]["scope"][field] = json!(value);
        let admitted = invoke(dir.path(), "adjudicate", &scoped);
        assert_eq!(admitted["decision"], "allow", "{field}: {admitted}");
        assert_ne!(admitted["receipt"]["scope_digest"], receipt["scope_digest"]);
        let delivered = invoke(
            dir.path(),
            "record-result",
            &json!({"protocol_version":1,"operation_id":"same-operation-id","receipt":admitted["receipt"],"task_receipt":{"operation_id":"same-operation-id","ok":true}}),
        );
        assert_eq!(delivered["status"], "recorded");
    }
    assert_eq!(invoke(dir.path(), "adjudicate", &first)["receipt"], receipt);
    let mut changed = first;
    changed["input"]["args"]["title"] = json!("conflicting same scope");
    assert_eq!(
        invoke(dir.path(), "adjudicate", &changed)["error"],
        "operation_id_conflict"
    );
}

#[test]
fn result_delivery_is_idempotent_bound_and_sanitized_but_not_execution_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let request = intent(dir.path(), "operation-1");
    let admitted = invoke(dir.path(), "adjudicate", &request);
    let mut delivery = json!({"protocol_version":1,"operation_id":"operation-1","receipt":admitted["receipt"],"task_receipt":{"operation_id":"operation-1","ok":true,"note":"password=private-result-value"}});
    let first = invoke(dir.path(), "record-result", &delivery);
    assert_eq!(first["status"], "recorded");
    assert_eq!(first["evidence"], "reported_task_receipt");
    assert_eq!(invoke(dir.path(), "record-result", &delivery), first);
    delivery["task_receipt"]["operation_id"] = json!("another-operation");
    assert_eq!(
        invoke(dir.path(), "record-result", &delivery)["error"],
        "task_receipt_operation_mismatch"
    );
    delivery["task_receipt"]["operation_id"] = json!("operation-1");
    delivery["task_receipt"]["ok"] = json!(false);
    assert_eq!(
        invoke(dir.path(), "record-result", &delivery)["error"],
        "outcome_conflict"
    );
    delivery["receipt"]["input_digest"] = json!("forged");
    assert_eq!(
        invoke(dir.path(), "record-result", &delivery)["error"],
        "receipt_mismatch"
    );
    let bytes = std::fs::read(dir.path().join("state/integration.db")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("private-result-value"));
}

#[test]
fn concurrent_admission_commits_one_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let request = intent(dir.path(), "operation-1");
    let mut threads = Vec::new();
    for _ in 0..6 {
        let path = dir.path().to_owned();
        let request = request.clone();
        threads.push(std::thread::spawn(move || {
            invoke(&path, "adjudicate", &request)
        }));
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert!(
        results.iter().all(|result| result["decision"] == "allow"),
        "{results:?}"
    );
    assert!(results
        .iter()
        .all(|result| result["receipt"] == results[0]["receipt"]));
    assert_eq!(results.iter().filter(|r| r["replayed"] == false).count(), 1);
}

#[test]
fn invalid_policy_and_legacy_handlers_are_reported_without_configuration_writes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("claude")).unwrap();
    std::fs::write(dir.path().join("claude/settings.json"),r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/local/bin/signet-eval"},{"type":"command","command":"unrelated-check"}]}]}}"#).unwrap();
    assert_eq!(
        invoke(dir.path(), "describe", &scope(dir.path()))["legacy_handlers"],
        1
    );
    std::fs::write(dir.path().join("rules.yaml"), "[not: valid: rules").unwrap();
    let state = invoke(dir.path(), "describe", &scope(dir.path()));
    assert_eq!(state["active"], false);
    assert_eq!(state["reason"], "policy_invalid");
    assert!(!dir.path().join("state").exists());
    std::fs::write(dir.path().join("rules.yaml"), "- name: broken_deny\n  tool_pattern: ^TaskCreate$\n  conditions: ['undefined_condition()']\n  action: DENY\n").unwrap();
    assert_eq!(
        invoke(dir.path(), "describe", &scope(dir.path()))["reason"],
        "policy_invalid"
    );
}

#[test]
fn sanitizer_is_structured_and_preserves_hashes_and_result_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let hash = "abcdef0123456789".repeat(4);
    let response = invoke(
        dir.path(),
        "redact",
        &json!({"value":{"stdout":"Authorization: Bearer private-canary-value","stderr":"","interrupted":false,"sha256":hash,"headers":{"Cookie":"session=opaque"}}}),
    );
    assert_eq!(response["value"]["sha256"], hash);
    assert_eq!(response["value"]["interrupted"], false);
    assert_eq!(response["value"]["headers"]["Cookie"], "[REDACTED]");
    assert!(!response.to_string().contains("private-canary-value"));
}
