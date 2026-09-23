//! Versioned, operation-scoped admission. An allow receipt records intent, not execution.
use crate::{hook, policy, redaction, vault};
use clap::Subcommand;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROTOCOL_VERSION: u32 = 1;
pub const ADAPTER_REVISION: &str = "claude-functions-2.1.274-v1";
const TTL_SECONDS: u64 = 30;
const MAX_INPUT: u64 = 4 * 1024 * 1024;

#[derive(Subcommand)]
pub enum Action {
    Describe,
    Adjudicate,
    RecordResult,
    Redact,
    /// Install the embedded optional Claude adapter; preserve enforcement disabled state
    InstallModern,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    protocol_version: u32,
    operation_id: String,
    session_id: String,
    project_path: String,
    agent: String,
    profile: Option<String>,
    policy_revision: String,
    source_tool: String,
    source_input: Option<Value>,
    target_tool: String,
    input: Value,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn digest(value: &Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}
fn error(message: &str) -> Value {
    json!({"protocol_version":PROTOCOL_VERSION,"owner":"signet-eval","decision":"deny","error":message,"reason":message})
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:@/-".contains(&c))
}

fn effective(
    policy_path: &Path,
    rules_path: &Path,
    admission: bool,
) -> Result<(policy::CompiledPolicy, String, Option<vault::Vault>), &'static str> {
    let signing_key = vault::cached_session_key();
    if vault::vault_exists() && signing_key.is_none() {
        return Err("vault_unavailable");
    }
    if let Some(key) = &signing_key {
        for path in [policy_path, rules_path] {
            if path.exists() && !vault::verify_policy_integrity(key, path) {
                return Err("policy_integrity_failed");
            }
        }
    }
    // Legacy loaders tolerate malformed files; delegated authority cannot claim readiness for them.
    for path in [policy_path, rules_path] {
        if path.exists() {
            let raw = std::fs::read_to_string(path).map_err(|_| "policy_unreadable")?;
            let config = serde_yaml::from_str::<policy::PolicyConfig>(&raw);
            let rules = serde_yaml::from_str::<Vec<policy::PolicyRule>>(&raw);
            if config.is_err() && (path == policy_path || rules.is_err()) {
                return Err("policy_invalid");
            }
            let parsed = match config {
                Ok(config) => config,
                Err(_) => policy::PolicyConfig {
                    version: 1,
                    default_action: policy::Decision::Allow,
                    rules: rules.map_err(|_| "policy_invalid")?,
                },
            };
            if policy::validate_policy(&parsed)
                .iter()
                .any(|diagnostic| diagnostic.severity == policy::DiagnosticSeverity::Error)
            {
                return Err("policy_invalid");
            }
        }
    }
    let compiled = policy::load_merged_policy(policy_path, rules_path);
    let fingerprint = json!({"binary":env!("CARGO_PKG_VERSION"),"adapter":ADAPTER_REVISION,"redaction":redaction::REVISION,"default":compiled.default_action.as_lowercase(),"rules":compiled.rules.iter().map(|r| json!({"name":r.name,"pattern":r.tool_regex.as_str(),"conditions":r.conditions,"action":r.action.as_lowercase(),"locked":r.locked,"reason":r.reason,"alternative":r.alternative,"gate":r.gate,"ensure":r.ensure,"inject":r.inject})).collect::<Vec<_>>()});
    let loaded_vault = if admission && signing_key.is_some() {
        Some(vault::try_load_vault().ok_or("vault_unavailable")?)
    } else {
        None
    };
    Ok((compiled, digest(&fingerprint), loaded_vault))
}

fn inactive() -> Option<&'static str> {
    if vault::is_disabled_file() || vault::is_session_disabled() {
        Some("disabled")
    } else if vault::is_paused_file() || vault::is_globally_paused_json() {
        Some("paused")
    } else {
        None
    }
}

fn legacy_handlers(project: Option<&str>) -> usize {
    let config = std::env::var("CLAUDE_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".claude")
        });
    let mut files = vec![config.join("settings.json")];
    let cwd = project
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok());
    if let Some(cwd) = cwd {
        for parent in cwd.ancestors() {
            for name in ["settings.json", "settings.local.json"] {
                files.push(parent.join(".claude").join(name));
            }
        }
    }
    files.sort();
    files.dedup();
    let mut count = 0;
    for file in files {
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                count += 1;
                continue;
            }
        };
        let Ok(settings) = serde_json::from_str::<Value>(&text) else {
            count += 1;
            continue;
        };
        if let Some(events) = settings["hooks"].as_object() {
            for registrations in events.values().filter_map(Value::as_array) {
                for registration in registrations {
                    if let Some(handlers) = registration["hooks"].as_array() {
                        for handler in handlers {
                            if let Some(command) = handler["command"].as_str() {
                                if command.split_whitespace().any(|word| {
                                    Path::new(word.trim_matches(['\'', '"', ';']))
                                        .file_name()
                                        .and_then(|s| s.to_str())
                                        == Some("signet-eval")
                                }) {
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(plugins) = settings["enabledPlugins"].as_object() {
            count += plugins
                .iter()
                .filter(|(name, enabled)| {
                    (**name == "signet-eval" || name.starts_with("signet-eval@"))
                        && enabled.as_bool() == Some(true)
                })
                .count();
        }
    }
    count
}

fn scope(input: &Value) -> Result<Value, &'static str> {
    let session = input
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or("session_required")?;
    let agent = input
        .get("agent")
        .and_then(Value::as_str)
        .ok_or("agent_required")?;
    let project = input
        .get("project_path")
        .and_then(Value::as_str)
        .ok_or("project_required")?;
    if !identifier(session) || !identifier(agent) || !Path::new(project).is_absolute() {
        return Err("invalid_scope");
    }
    let canonical = Path::new(project)
        .canonicalize()
        .map_err(|_| "project_unavailable")?;
    if !canonical.is_dir() {
        return Err("project_unavailable");
    }
    let mut scoped =
        json!({"session_id":session,"agent":agent,"project_path":canonical.to_string_lossy()});
    if let Some(profile) = input.get("profile").filter(|value| !value.is_null()) {
        let profile = profile
            .as_str()
            .filter(|value| identifier(value))
            .ok_or("invalid_profile")?;
        scoped["profile"] = json!(profile);
    }
    Ok(scoped)
}

fn connection() -> Result<Connection, &'static str> {
    let dir = vault::signet_dir();
    std::fs::create_dir_all(&dir).map_err(|_| "ledger_unavailable")?;
    let path = dir.join("integration.db");
    let conn = Connection::open(&path).map_err(|_| "ledger_unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "ledger_unavailable")?;
    }
    conn.busy_timeout(std::time::Duration::from_secs(3))
        .map_err(|_| "ledger_unavailable")?;
    conn.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS adjudications(scope_digest TEXT NOT NULL, operation_id TEXT NOT NULL, intent_digest TEXT NOT NULL, receipt TEXT NOT NULL, outcome_digest TEXT, outcome TEXT, PRIMARY KEY(scope_digest, operation_id));").map_err(|_| "ledger_unavailable")?;
    Ok(conn)
}

fn target(tool: &str) -> Option<(&'static str, &'static str)> {
    match tool {
        "kindex.task.create" => Some(("create", "mcp__kindex__task_add")),
        "kindex.task.get" => Some(("get", "mcp__kindex__task_get")),
        "kindex.task.list" => Some(("list", "mcp__kindex__task_list")),
        "kindex.task.update" => Some(("update", "mcp__kindex__task_update")),
        "kindex.task.complete" => Some(("complete", "mcp__kindex__task_done")),
        "kindex.task.cancel" => Some(("cancel", "mcp__kindex__task_cancel")),
        "kindex.task.claim" => Some(("claim", "mcp__kindex__task_claim")),
        "kindex.task.release" => Some(("release", "mcp__kindex__task_release")),
        "kindex.task.reconcile" => Some(("reconcile", "mcp__kindex__task_reconcile")),
        _ => None,
    }
}

fn delegated_source(source: &str, operation: &str, mcp: &str) -> bool {
    match source {
        "TaskCreate" => operation == "create",
        "TaskGet" => operation == "get",
        "TaskList" => operation == "list",
        "TaskUpdate" => matches!(
            operation,
            "update" | "complete" | "cancel" | "claim" | "release"
        ),
        "TodoWrite" => operation == "reconcile",
        other => other == mcp || other == format!("kindex.task.{operation}"),
    }
}

fn authorize(
    call: &policy::ToolCall,
    compiled: &policy::CompiledPolicy,
    loaded_vault: Option<&vault::Vault>,
) -> Result<(), String> {
    let result = policy::evaluate(call, compiled, loaded_vault);
    let result = if result.decision == policy::Decision::Ensure {
        hook::resolve_ensure_result(result, call)
    } else {
        result
    };
    if result.decision != policy::Decision::Allow {
        return Err(redaction::text(
            result
                .reason
                .as_deref()
                .unwrap_or("Policy requires authorization"),
        ));
    }
    if let Some(v) = loaded_vault {
        if let Some(preflight) = v.active_preflight() {
            if preflight.escalated {
                return Err("Preflight escalation requires human authorization".into());
            }
            if let Some((_, reason)) = hook::evaluate_preflight_constraint(call, &preflight, v) {
                return Err(redaction::text(&reason));
            }
        }
    }
    Ok(())
}

fn adjudicate(input: Value, policy_path: &Path, rules_path: &Path) -> Result<Value, String> {
    let intent: Intent = serde_json::from_value(input.clone()).map_err(|_| "invalid_intent")?;
    if intent.protocol_version != PROTOCOL_VERSION || !identifier(&intent.operation_id) {
        return Err("unsupported_protocol_or_operation_id".into());
    }
    let bound_scope = scope(
        &json!({"session_id":intent.session_id,"project_path":intent.project_path,"agent":intent.agent,"profile":intent.profile}),
    )?;
    std::env::set_var("SIGNET_CHAT_ID", &intent.session_id);
    if let Some(reason) = inactive() {
        return Err(reason.into());
    }
    let (mut compiled, revision, loaded_vault) = effective(policy_path, rules_path, true)?;
    if intent.policy_revision != revision {
        return Err("policy_revision_changed".into());
    }
    let (operation, mcp) = target(&intent.target_tool).ok_or("unsupported_target")?;
    if !delegated_source(&intent.source_tool, operation, mcp) {
        return Err("unsupported_delegation".into());
    }
    if intent.input.get("operation").and_then(Value::as_str) != Some(operation)
        || !intent.input.get("args").is_some_and(Value::is_object)
    {
        return Err("target_input_mismatch".into());
    }
    if let Some(operation_id) = intent.input["args"].get("operation_id") {
        if operation_id.as_str() != Some(&intent.operation_id) {
            return Err("target_operation_id_mismatch".into());
        }
    }
    let native = matches!(
        intent.source_tool.as_str(),
        "TaskCreate" | "TaskUpdate" | "TaskGet" | "TaskList" | "TodoWrite"
    );
    let source_input = match &intent.source_input {
        Some(source) if source.is_object() && intent.input.get("source_input") == Some(source) => {
            source
        }
        Some(_) => return Err("source_input_mismatch".into()),
        None if native => return Err("source_input_required".into()),
        None if intent.input.get("source_input").is_some() => {
            return Err("source_input_mismatch".into())
        }
        None => &intent.input["args"],
    };
    let input_scope = scope(intent.input.get("scope").ok_or("input_scope_required")?)?;
    if input_scope != bound_scope {
        return Err("input_scope_mismatch".into());
    }
    let scope_digest = digest(&bound_scope);
    let input_digest = digest(&intent.input);
    let intent_digest = digest(&input);
    // Do not run advisory commands while admitting an action. They do not grant permission.
    compiled.has_inject_rules = false;
    let mut source_policy = compiled.clone();
    source_policy
        .rules
        .retain(|r| !(r.locked && r.name == "prefer_persistent_task_store"));
    let parameters = intent.input["args"].clone();
    authorize(
        &policy::ToolCall {
            tool_name: intent.source_tool.clone(),
            parameters: source_input.clone(),
        },
        &source_policy,
        loaded_vault.as_ref(),
    )?;
    for name in [mcp, &intent.target_tool] {
        authorize(
            &policy::ToolCall {
                tool_name: name.into(),
                parameters: parameters.clone(),
            },
            &compiled,
            loaded_vault.as_ref(),
        )?;
    }
    let mut conn = connection()?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "ledger_unavailable")?;
    let prior: Option<(String, String)> = tx
        .query_row(
            "SELECT intent_digest, receipt FROM adjudications WHERE scope_digest=?1 AND operation_id=?2",
            [&scope_digest, &intent.operation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| "ledger_unavailable")?;
    if let Some((previous, receipt)) = prior {
        if previous != intent_digest {
            return Err("operation_id_conflict".into());
        }
        let receipt: Value = serde_json::from_str(&receipt).map_err(|_| "ledger_corrupt")?;
        if receipt["expires_at"].as_u64().unwrap_or(0) < now() {
            return Err("authorization_expired".into());
        }
        return Ok(
            json!({"protocol_version":1,"owner":"signet-eval","decision":"allow","policy_revision":revision,"receipt":receipt,"replayed":true}),
        );
    }
    let issued = now();
    let receipt = json!({"protocol_version":1,"owner":"signet-eval","operation_id":intent.operation_id,"input_digest":input_digest,"source_input_digest":digest(source_input),"scope_digest":scope_digest,"policy_revision":revision,"adapter_revision":ADAPTER_REVISION,"source_tool":intent.source_tool,"target_tool":intent.target_tool,"authorized_at":issued,"expires_at":issued+TTL_SECONDS,"scope":bound_scope,"evidence":"authorized_intent"});
    tx.execute(
        "INSERT INTO adjudications(scope_digest,operation_id,intent_digest,receipt) VALUES(?1,?2,?3,?4)",
        params![scope_digest, intent.operation_id, intent_digest, receipt.to_string()],
    )
    .map_err(|_| "ledger_unavailable")?;
    tx.commit().map_err(|_| "ledger_unavailable")?;
    Ok(
        json!({"protocol_version":1,"owner":"signet-eval","decision":"allow","policy_revision":revision,"receipt":receipt,"replayed":false}),
    )
}

fn record_result(input: &Value) -> Result<Value, &'static str> {
    if input["protocol_version"] != 1 {
        return Err("unsupported_protocol");
    }
    let operation = input["operation_id"]
        .as_str()
        .filter(|s| identifier(s))
        .ok_or("operation_id_required")?;
    let receipt = input.get("receipt").ok_or("receipt_required")?;
    let scope_digest = receipt["scope_digest"]
        .as_str()
        .ok_or("receipt_scope_required")?;
    let task_receipt = input
        .get("task_receipt")
        .filter(|v| v.is_object())
        .ok_or("task_receipt_required")?;
    if task_receipt["operation_id"].as_str() != Some(operation) {
        return Err("task_receipt_operation_mismatch");
    }
    let outcome_digest = digest(task_receipt);
    let mut conn = connection()?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "ledger_unavailable")?;
    let prior: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT receipt,outcome_digest FROM adjudications WHERE scope_digest=?1 AND operation_id=?2",
            [scope_digest, operation],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| "ledger_unavailable")?;
    let (stored, previous) = prior.ok_or("adjudication_not_found")?;
    if serde_json::from_str::<Value>(&stored).map_err(|_| "ledger_corrupt")? != *receipt {
        return Err("receipt_mismatch");
    }
    if let Some(previous) = previous {
        if previous != outcome_digest {
            return Err("outcome_conflict");
        }
    }
    tx.execute(
        "UPDATE adjudications SET outcome_digest=?1,outcome=?2 WHERE scope_digest=?3 AND operation_id=?4",
        params![
            outcome_digest,
            redaction::value(task_receipt).to_string(),
            scope_digest,
            operation
        ],
    )
    .map_err(|_| "ledger_unavailable")?;
    tx.commit().map_err(|_| "ledger_unavailable")?;
    // A caller-supplied delivery is not promoted into successful execution evidence.
    Ok(
        json!({"protocol_version":1,"owner":"signet-eval","status":"recorded","operation_id":operation,"outcome_digest":outcome_digest,"evidence":"reported_task_receipt"}),
    )
}

pub fn run(action: Action, policy_path: &Path, rules_path: &Path) -> i32 {
    if matches!(action, Action::InstallModern) {
        return match crate::claude_install::install_modern() {
            Ok(value) => {
                println!("{value}");
                0
            }
            Err(reason) => {
                println!("{}", error(reason));
                1
            }
        };
    }
    let mut raw = String::new();
    if io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_string(&mut raw)
        .is_err()
        || raw.len() as u64 > MAX_INPUT
    {
        println!("{}", error("invalid_or_oversized_input"));
        return 1;
    }
    let input = if raw.trim().is_empty() {
        json!({})
    } else {
        match serde_json::from_str::<Value>(&raw) {
            Ok(v) => v,
            Err(_) => {
                println!("{}", error("invalid_json"));
                return 1;
            }
        }
    };
    let output = match action {
        Action::InstallModern => unreachable!("installer dispatched before reading stdin"),
        Action::Redact => match input.get("value") {
            Some(v) => Ok(
                json!({"protocol_version":1,"owner":"signet-eval","sanitizer_revision":redaction::REVISION,"value":redaction::value(v)}),
            ),
            None => Err("value_required".into()),
        },
        Action::Adjudicate => adjudicate(input, policy_path, rules_path),
        Action::RecordResult => record_result(&input).map_err(String::from),
        Action::Describe => {
            if let Some(session) = input["session_id"].as_str() {
                std::env::set_var("SIGNET_CHAT_ID", session);
            }
            let state = effective(policy_path, rules_path, false);
            let reason = inactive().or_else(|| state.as_ref().err().copied());
            let revision = state.as_ref().ok().map(|(_, revision, _)| revision.clone());
            let bound_scope = scope(&input).ok();
            Ok(json!({
                "protocol_version": PROTOCOL_VERSION,
                "owner": "signet-eval",
                "version": env!("CARGO_PKG_VERSION"),
                "adapter_revision": ADAPTER_REVISION,
                "policy_revision": revision,
                "active": reason.is_none(),
                "disabled": reason == Some("disabled"),
                "reason": reason,
                "valid_until": now() + TTL_SECONDS,
                "scope": bound_scope,
                "legacy_handlers": legacy_handlers(input["project_path"].as_str()),
                "capabilities": {
                    "task_enforcement": {
                        "ready": reason.is_none() && bound_scope.is_some(),
                        "protocol_version": PROTOCOL_VERSION,
                        "targets": ["create", "get", "list", "update", "complete",
                                    "cancel", "claim", "release", "reconcile"]
                    },
                    "host_redaction": {
                        "ready": false,
                        "reason": "host_activation_not_attested_by_cli",
                        "revision": redaction::REVISION,
                        "scopes": ["tool_result", "user_prompt_projection"],
                        "all_logs": false,
                        "all_transcripts": false
                    },
                    "native_task_guard": ["TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "TodoWrite"]
                }
            }))
        }
    };
    match output {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(reason) => {
            println!("{}", error(&redaction::text(&reason)));
            1
        }
    }
}
