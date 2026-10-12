//! Hook I/O — reads agent hook JSON from stdin, returns an adapter-specific decision on stdout.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wait_timeout::ChildExt;

use crate::policy::{self, CompiledPolicy, Decision, EnsureConfig, EvaluationResult, ToolCall};
use crate::vault::{Preflight, PreflightViolation, SoftConstraint, Vault};

#[derive(Deserialize)]
struct HookInput {
    #[serde(default, alias = "toolName")]
    tool_name: Option<String>,
    #[serde(default, alias = "tool_input", alias = "arguments", alias = "args")]
    parameters: Option<Value>,
    #[serde(rename = "toolCall", default)]
    tool_call: Option<AntigravityToolCall>,
}

#[derive(Deserialize)]
struct AntigravityToolCall {
    name: String,
    #[serde(default)]
    args: Option<Value>,
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
}

fn extract_session_id(value: &Value) -> Option<String> {
    for key in [
        "conversation_id",
        "conversationId",
        "chat_id",
        "chatId",
        "session_id",
        "sessionId",
        "thread_id",
        "threadId",
        "transcript_path",
        "transcriptPath",
    ] {
        if let Some(id) = string_field(value, key) {
            return Some(id);
        }
    }

    for parent in ["conversation", "chat", "session", "thread"] {
        if let Some(child) = value.get(parent).and_then(|v| v.as_object()) {
            for key in [
                "id",
                "conversation_id",
                "chat_id",
                "session_id",
                "thread_id",
            ] {
                if let Some(id) = child
                    .get(key)
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                {
                    return Some(id.to_string());
                }
            }
        }
    }

    None
}

fn install_hook_session(value: &Value) {
    if let Some(session_id) = extract_session_id(value) {
        // Process-local override used by vault::current_session_id(). This keeps
        // hook evaluation scoped even when older shell setup left SIGNET_SESSION
        // pointing at the working directory.
        std::env::set_var("SIGNET_CHAT_ID", session_id);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookAdapter {
    Claude,
    Codex,
    CodexPermission,
    Antigravity,
    OpenCode,
    Cursor,
    Muse,
}

impl HookAdapter {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "claude" | "claude-code" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "codex-permission" | "codex-permission-request" => Ok(Self::CodexPermission),
            "antigravity" => Ok(Self::Antigravity),
            "opencode" => Ok(Self::OpenCode),
            "cursor" => Ok(Self::Cursor),
            "muse" => Ok(Self::Muse),
            _ => Err(format!(
                "unknown adapter '{s}' (expected claude, codex, codex-permission, antigravity, opencode, cursor, or muse)"
            )),
        }
    }

    fn event_name(self, input_event: Option<&str>) -> HookEvent {
        match self {
            Self::Claude | Self::Antigravity | Self::OpenCode => HookEvent::PreToolUse,
            Self::CodexPermission => HookEvent::PermissionRequest,
            Self::Codex | Self::Muse => match input_event {
                Some("PermissionRequest") => HookEvent::PermissionRequest,
                _ => HookEvent::PreToolUse,
            },
            Self::Cursor => match input_event {
                Some(CURSOR_SHELL_EVENT) => HookEvent::BeforeShellExecution,
                Some(CURSOR_MCP_EVENT) => HookEvent::BeforeMcpExecution,
                Some(CURSOR_READ_EVENT) => HookEvent::BeforeReadFile,
                _ => HookEvent::PreToolUse,
            },
        }
    }
}

const CURSOR_SHELL_EVENT: &str = "beforeShellExecution";
const CURSOR_MCP_EVENT: &str = "beforeMCPExecution";
const CURSOR_READ_EVENT: &str = "beforeReadFile";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookEvent {
    PreToolUse,
    PermissionRequest,
    /// Cursor `beforeShellExecution`: the only Cursor event whose `ask` reaches a prompt.
    BeforeShellExecution,
    /// Cursor `beforeMCPExecution`: carries the MCP server identity `preToolUse` lacks.
    BeforeMcpExecution,
    /// Cursor `beforeReadFile`: allow or deny only.
    BeforeReadFile,
}

/// Claude Code and Codex PreToolUse expect hook responses wrapped in hookSpecificOutput.
#[derive(Serialize)]
struct HookResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookOutput,
}

#[derive(Serialize)]
struct HookOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: String,
    #[serde(rename = "permissionDecision", skip_serializing_if = "Option::is_none")]
    permission_decision: Option<String>,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    reason: Option<String>,
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    additional_context: Option<String>,
}

#[derive(Serialize)]
struct CodexPermissionResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: CodexPermissionOutput,
}

#[derive(Serialize)]
struct CodexPermissionOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: String,
    decision: CodexPermissionDecision,
}

#[derive(Serialize)]
struct CodexPermissionDecision {
    behavior: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Cursor permission hooks answer with a flat `permission` object (cursor-agent 2026.10.01).
#[derive(Serialize)]
struct CursorResponse {
    permission: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_context: Option<String>,
}

#[derive(Serialize)]
struct AntigravityResponse {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl HookInput {
    fn into_tool_call(self, adapter: HookAdapter) -> Result<ToolCall, String> {
        if let Some(tool_call) = self.tool_call {
            if adapter == HookAdapter::Antigravity {
                return normalize_antigravity_tool_call(tool_call);
            }

            return Ok(ToolCall {
                tool_name: tool_call.name,
                parameters: tool_call.args.unwrap_or(Value::Object(Default::default())),
            });
        }

        let Some(tool_name) = self.tool_name else {
            return Err("missing tool name".into());
        };
        let parameters = self.parameters.unwrap_or(Value::Object(Default::default()));

        if adapter == HookAdapter::Muse {
            return normalize_muse_tool_call(tool_name, parameters);
        }

        Ok(ToolCall {
            tool_name,
            parameters,
        })
    }
}

pub(crate) fn parse_tool_call_input(
    raw_input: Value,
    adapter: HookAdapter,
) -> Result<ToolCall, String> {
    if adapter == HookAdapter::Cursor {
        return normalize_cursor_input(raw_input);
    }
    let hook_input: HookInput =
        serde_json::from_value(raw_input).map_err(|_| "Malformed hook input".to_string())?;
    hook_input.into_tool_call(adapter)
}

fn required_str(value: &Value, key: &str, host: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{host} {key} must be a non-empty string"))
}

/// Normalize a Cursor hook payload. Cursor names the event in `hook_event_name`;
/// each pre-execution event has its own shape. The host-supplied identity is
/// authoritative and overwrites lookalike fields from tool arguments.
fn normalize_cursor_input(raw: Value) -> Result<ToolCall, String> {
    let event = raw.get("hook_event_name").and_then(Value::as_str);
    match event {
        Some(CURSOR_SHELL_EVENT) => {
            let mut parameters = Map::new();
            parameters.insert(
                "command".into(),
                Value::String(required_str(&raw, "command", "Cursor")?),
            );
            // cursor-agent sends `cwd: ""` when the agent did not choose a directory.
            if let Some(cwd) = raw
                .get("cwd")
                .and_then(Value::as_str)
                .filter(|cwd| !cwd.is_empty())
            {
                parameters.insert("cwd".into(), Value::String(cwd.into()));
            }
            parameters.insert("agent_tool_name".into(), Value::String("Shell".into()));
            Ok(ToolCall {
                tool_name: "Bash".into(),
                parameters: Value::Object(parameters),
            })
        }
        Some(CURSOR_MCP_EVENT) => {
            let server_name = required_str(&raw, "mcp_server_name", "Cursor")?;
            let mcp_tool_name = required_str(&raw, "tool_name", "Cursor")?;
            // Cursor serializes MCP arguments as a JSON string on this event.
            let mut parameters = match raw.get("tool_input") {
                Some(Value::String(text)) => match serde_json::from_str::<Value>(text) {
                    Ok(Value::Object(map)) => map,
                    _ => return Err("Cursor tool_input must encode a JSON object".into()),
                },
                Some(Value::Object(map)) => map.clone(),
                _ => return Err("Cursor tool_input must encode a JSON object".into()),
            };
            parameters.insert(
                "agent_tool_name".into(),
                Value::String(format!("MCP:{mcp_tool_name}")),
            );
            parameters.insert("mcp_server_name".into(), Value::String(server_name.clone()));
            parameters.insert("mcp_tool_name".into(), Value::String(mcp_tool_name.clone()));
            Ok(ToolCall {
                tool_name: format!("mcp__{server_name}__{mcp_tool_name}"),
                parameters: Value::Object(parameters),
            })
        }
        Some(CURSOR_READ_EVENT) => {
            // The payload also carries the file content; policy sees only the path,
            // matching the Read tool on every other host.
            let mut parameters = Map::new();
            parameters.insert(
                "file_path".into(),
                Value::String(required_str(&raw, "file_path", "Cursor")?),
            );
            parameters.insert("agent_tool_name".into(), Value::String("Read".into()));
            Ok(ToolCall {
                tool_name: "Read".into(),
                parameters: Value::Object(parameters),
            })
        }
        _ => {
            let tool_name = required_str(&raw, "tool_name", "Cursor")?;
            let mut parameters = match raw.get("tool_input") {
                None | Some(Value::Null) => Map::new(),
                Some(Value::Object(map)) => map.clone(),
                Some(_) => return Err("Cursor tool_input must be an object".into()),
            };
            let canonical_tool_name = match tool_name.as_str() {
                "Shell" => {
                    if parameters.get("cwd").and_then(Value::as_str) == Some("") {
                        parameters.remove("cwd");
                    }
                    "Bash".to_owned()
                }
                _ => tool_name.clone(),
            };
            parameters.insert("agent_tool_name".into(), Value::String(tool_name));
            Ok(ToolCall {
                tool_name: canonical_tool_name,
                parameters: Value::Object(parameters),
            })
        }
    }
}

/// Map Muse native tool names onto Signet's canonical names. Muse sends its own
/// tool names (e.g. `shell`) in Claude-shaped PreToolUse payloads.
fn normalize_muse_tool_call(tool_name: String, parameters: Value) -> Result<ToolCall, String> {
    let mut parameters = match parameters {
        Value::Object(map) => map,
        _ => return Err("Muse tool_input must be an object".into()),
    };

    let canonical_tool_name = match tool_name.as_str() {
        "shell" | "bash" | "bash_input" | "exec_command" | "execute_command" => {
            if !parameters.contains_key("command") {
                copy_argument(&mut parameters, "cmd", "command");
            }
            "Bash"
        }
        "read_file" => "Read",
        "write_file" => "Write",
        "edit_file" => "Edit",
        "search" => "Grep",
        "web_fetch" => "WebFetch",
        "web_search" => "WebSearch",
        _ => tool_name.as_str(),
    }
    .to_owned();

    if matches!(canonical_tool_name.as_str(), "Read" | "Write" | "Edit") {
        // A native `path` argument is authoritative over a lookalike `file_path`.
        copy_argument(&mut parameters, "path", "file_path");
    }
    parameters.insert("agent_tool_name".into(), Value::String(tool_name));

    Ok(ToolCall {
        tool_name: canonical_tool_name,
        parameters: Value::Object(parameters),
    })
}

fn copy_argument(map: &mut Map<String, Value>, source: &str, target: &str) {
    if let Some(value) = map.get(source).cloned() {
        map.insert(target.into(), value);
    }
}

fn required_string_argument(map: &Map<String, Value>, key: &str) -> Result<String, String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("Antigravity {key} must be a non-empty string"))
}

fn normalize_antigravity_tool_call(tool_call: AntigravityToolCall) -> Result<ToolCall, String> {
    let tool_name = tool_call.name;
    let mut parameters = match tool_call.args.unwrap_or(Value::Object(Default::default())) {
        Value::Object(map) => map,
        _ => return Err("Antigravity toolCall.args must be an object".into()),
    };

    let canonical_tool_name = match tool_name.as_str() {
        "run_command" => {
            copy_argument(&mut parameters, "CommandLine", "command");
            copy_argument(&mut parameters, "Cwd", "cwd");
            "Bash".to_owned()
        }
        "write_to_file" => {
            copy_argument(&mut parameters, "TargetFile", "file_path");
            copy_argument(&mut parameters, "CodeContent", "content");
            "Write".to_owned()
        }
        "replace_file_content" => {
            copy_argument(&mut parameters, "TargetFile", "file_path");
            copy_argument(&mut parameters, "ReplacementContent", "content");
            "Edit".to_owned()
        }
        "multi_replace_file_content" => {
            copy_argument(&mut parameters, "TargetFile", "file_path");
            "MultiEdit".to_owned()
        }
        "view_file" => {
            copy_argument(&mut parameters, "AbsolutePath", "file_path");
            "Read".to_owned()
        }
        "call_mcp_tool" => {
            let server_name = required_string_argument(&parameters, "ServerName")?;
            let mcp_tool_name = required_string_argument(&parameters, "ToolName")?;
            let mut mcp_parameters = match parameters.remove("Arguments") {
                Some(Value::Object(map)) => map,
                _ => return Err("Antigravity Arguments must be an object".into()),
            };

            // The native wrapper is authoritative. Overwrite lookalike fields from
            // Arguments so an MCP caller cannot spoof the identity Signet evaluates.
            mcp_parameters.insert(
                "agent_tool_name".into(),
                Value::String("call_mcp_tool".into()),
            );
            mcp_parameters.insert("mcp_server_name".into(), Value::String(server_name.clone()));
            mcp_parameters.insert("mcp_tool_name".into(), Value::String(mcp_tool_name.clone()));

            return Ok(ToolCall {
                tool_name: format!("mcp__{server_name}__{mcp_tool_name}"),
                parameters: Value::Object(mcp_parameters),
            });
        }
        _ => tool_name.clone(),
    };

    parameters.insert("agent_tool_name".into(), Value::String(tool_name));

    Ok(ToolCall {
        tool_name: canonical_tool_name,
        parameters: Value::Object(parameters),
    })
}

/// Evaluate a tool call against preflight soft constraints.
/// Returns the first matching constraint (if any).
pub(crate) fn evaluate_preflight_constraint(
    call: &ToolCall,
    preflight: &Preflight,
    vault: &Vault,
) -> Option<(SoftConstraint, String)> {
    for constraint in &preflight.constraints {
        // Check tool pattern
        let re = match regex::Regex::new(&constraint.tool_pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !re.is_match(&call.tool_name) {
            continue;
        }
        // Check all conditions (AND)
        let mut all_match = true;
        for cond in &constraint.conditions {
            match policy::evaluate_condition(cond, call, Some(vault)) {
                Ok(true) => {}
                _ => {
                    all_match = false;
                    break;
                }
            }
        }
        if all_match {
            let reason = format!("{} Instead: {}", constraint.reason, constraint.alternative);
            return Some((constraint.clone(), reason));
        }
    }
    None
}

pub fn run_hook_with_adapter(
    policy: &CompiledPolicy,
    vault: Option<&Vault>,
    adapter: HookAdapter,
) -> i32 {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        emit_deny(adapter, HookEvent::PreToolUse, "Failed to read stdin");
        return 0;
    }

    let raw_input: Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => {
            emit_deny(adapter, HookEvent::PreToolUse, "Malformed hook input");
            return 0;
        }
    };
    install_hook_session(&raw_input);

    // Full disable — bypass everything silently (global or session-scoped)
    if crate::vault::is_disabled_file() || crate::vault::is_session_disabled() {
        emit_allow(adapter, HookEvent::PreToolUse);
        return 0;
    }

    let event = adapter.event_name(
        raw_input
            .get("hook_event_name")
            .or_else(|| raw_input.get("hookEventName"))
            .and_then(|value| value.as_str()),
    );

    let envelope_cwd = raw_input
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let call = match parse_tool_call_input(raw_input, adapter) {
        Ok(call) => call,
        Err(_) => {
            emit_deny(adapter, event, "Malformed hook input");
            return 0;
        }
    };

    // Check if paused — if so, only enforce locked (self-protection) rules
    // File-based global pause OR session-scoped global pause from pauses.json
    if crate::vault::is_paused_file() || crate::vault::is_globally_paused_json() {
        let result = policy::evaluate(&call, policy, vault);
        if result.decision == Decision::Deny && result.matched_locked {
            // Self-protection: locked deny always enforced during pause
            emit_decision(adapter, event, "deny", result.reason, None);
            return 0;
        }
        if result.decision == Decision::Ensure && result.matched_locked {
            // Self-protection: locked ensure enforced during pause
            let resolved = resolve_ensure_result_with_cwd(result, &call, envelope_cwd.as_deref());
            if resolved.decision == Decision::Deny {
                emit_decision(adapter, event, "deny", resolved.reason, None);
                return 0;
            }
        }
        // Not a locked rule — allow during pause
        emit_decision(adapter, event, "allow", None, None);
        return 0;
    }

    // Pass 1: Evaluate against compiled hard rules
    let result = policy::evaluate(&call, policy, vault);

    // Resolve Ensure: run check script, convert to Allow/Deny
    let result = if result.decision == Decision::Ensure {
        resolve_ensure_result_with_cwd(result, &call, envelope_cwd.as_deref())
    } else {
        result
    };

    // Per-rule pause: if the matched (non-locked) rule is paused, allow silently
    let result = if result.decision != Decision::Allow && !result.matched_locked {
        if let Some(ref rule_name) = result.matched_rule {
            if crate::vault::is_rule_paused(rule_name) {
                EvaluationResult {
                    decision: Decision::Allow,
                    ..result
                }
            } else {
                result
            }
        } else {
            result
        }
    } else {
        result
    };

    // Capture any inject-pass payload before consuming `result` in subsequent branches.
    let inject_context = result.injected_context.clone();

    // Hard deny always wins — short-circuit. Inject payloads still flow on deny so
    // the agent gets the nudge alongside the denial reason.
    let (final_decision, final_reason, final_context) = if result.decision == Decision::Deny {
        (result.decision, result.reason, None)
    } else {
        // Pass 2: Check active preflight soft constraints
        match vault.and_then(|v| {
            let preflight = v.active_preflight()?;
            Some((v, preflight))
        }) {
            Some((v, preflight)) => {
                if preflight.escalated {
                    // Escalated preflight — build rich context for Claude and user
                    let violations = v.preflight_violations(&preflight.id);

                    // Group violations by constraint
                    let mut by_constraint: std::collections::HashMap<String, Vec<String>> =
                        std::collections::HashMap::new();
                    for viol in violations.iter().take(20) {
                        by_constraint
                            .entry(viol.constraint_name.clone())
                            .or_default()
                            .push(format!(
                                "{}({})",
                                viol.tool_name,
                                crate::redaction::summary(&viol.parameters_summary, 60)
                            ));
                    }

                    // Build constraint detail block
                    let mut constraint_detail = String::new();
                    for constraint in &preflight.constraints {
                        constraint_detail.push_str(&format!(
                            "\n  - [{}] {} ({}): {}\n    INSTEAD: {}",
                            constraint.action,
                            constraint.name,
                            constraint.tool_pattern,
                            constraint.reason,
                            constraint.alternative
                        ));
                        if let Some(hits) = by_constraint.get(&constraint.name) {
                            constraint_detail.push_str(&format!(
                                "\n    YOU DID THIS {} TIME(S): {}",
                                hits.len(),
                                hits.join("; ")
                            ));
                        }
                    }

                    let task_short = if preflight.task.len() > 80 {
                        format!("{}...", crate::redaction::summary(&preflight.task, 77))
                    } else {
                        preflight.task.clone()
                    };

                    let context = format!(
                        "CRITICAL — PREFLIGHT ESCALATED\n\
                         \n\
                         Your task: {task}\n\
                         Violations: {count}\n\
                         \n\
                         You repeatedly violated constraints that were set BEFORE you started working. \
                         ALL tool calls now require human approval until this is resolved.\n\
                         \n\
                         Constraints and what you did wrong:{detail}\n\
                         \n\
                         YOU MUST:\n\
                         1. STOP your current approach immediately\n\
                         2. Tell the user: your preflight constraints escalated, explain which ones and why\n\
                         3. For each violated constraint, explain the alternative approach you should have used\n\
                         4. Ask the user how to proceed — they can clear the escalation once you change approach\n\
                         \n\
                         Do NOT continue with the approach that caused these violations. \
                         Do NOT try to work around the constraints. Change your approach.",
                        task = preflight.task,
                        count = preflight.violation_count,
                        detail = constraint_detail,
                    );

                    let reason = format!(
                        "PREFLIGHT ESCALATED: '{}' — {} violations. Claude should explain what went wrong.",
                        task_short, preflight.violation_count
                    );

                    (Decision::Ask, Some(reason), Some(context))
                } else {
                    // Evaluate soft constraints
                    match evaluate_preflight_constraint(&call, &preflight, v) {
                        Some((constraint, reason)) => {
                            // Log the violation
                            let detail =
                                serde_json::to_string(&call.parameters).unwrap_or_default();
                            let violation = PreflightViolation {
                                preflight_id: preflight.id.clone(),
                                constraint_name: constraint.name.clone(),
                                tool_name: call.tool_name.clone(),
                                parameters_summary: crate::redaction::summary(&detail, 200),
                                alternative: constraint.alternative.clone(),
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            };
                            let _ = v.log_preflight_violation(&violation);

                            // Build context so Claude knows what it violated
                            let context = format!(
                                "PREFLIGHT CONSTRAINT VIOLATED: '{}'\n\
                                 Task: {}\n\
                                 Rule: {}\n\
                                 Alternative: {}\n\
                                 \n\
                                 You MUST use the alternative approach described above. \
                                 Do NOT retry the same action. If you keep violating constraints, \
                                 your preflight will escalate and ALL tool calls will require manual approval.",
                                constraint.name, preflight.task,
                                constraint.reason, constraint.alternative,
                            );

                            // Parse constraint action
                            let decision = match constraint.action.to_uppercase().as_str() {
                                "DENY" => Decision::Deny,
                                "ASK" => Decision::Ask,
                                _ => Decision::Ask,
                            };
                            (decision, Some(reason), Some(context))
                        }
                        None => {
                            // No soft constraint matched — use Pass 1 result
                            (result.decision, result.reason, None)
                        }
                    }
                }
            }
            None => {
                // No active preflight — use Pass 1 result
                (result.decision, result.reason, None)
            }
        }
    };

    // Log to vault if available
    if let Some(v) = vault {
        let params = &call.parameters;
        let amount: f64 = params
            .get("amount")
            .and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(0.0);
        let category = params
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let detail = serde_json::to_string(params).unwrap_or_default();
        let amt = if final_decision == Decision::Allow {
            amount
        } else {
            0.0
        };
        v.log_action(
            &call.tool_name,
            final_decision.as_lowercase(),
            category,
            amt,
            &crate::redaction::summary(&detail, 500),
        );
    }

    // Combine preflight-derived context with any inject-pass payload. Inject context
    // appends after preflight context (preflight is higher-priority, more urgent).
    let combined_context = match (final_context, inject_context) {
        (Some(p), Some(i)) => Some(format!("{p}\n\n---\n\n{i}")),
        (Some(p), None) => Some(p),
        (None, Some(i)) => Some(i),
        (None, None) => None,
    };

    emit_decision(
        adapter,
        event,
        final_decision.as_lowercase(),
        if final_decision != Decision::Allow {
            final_reason
        } else {
            None
        },
        combined_context,
    );
    0
}

fn emit_decision(
    adapter: HookAdapter,
    event: HookEvent,
    decision: &str,
    reason: Option<String>,
    additional_context: Option<String>,
) {
    let reason = reason.map(|v| crate::redaction::text(&v));
    let additional_context = additional_context.map(|v| crate::redaction::text(&v));
    match (adapter, event) {
        (HookAdapter::Claude | HookAdapter::OpenCode, _) => {
            emit_pre_tool_use_decision("PreToolUse", decision, reason, additional_context)
        }
        (HookAdapter::Antigravity, _) => {
            let message = match (reason, additional_context) {
                (Some(r), Some(ctx)) => format!("{}\n\n{}", r, ctx),
                (Some(r), None) => r,
                (None, Some(ctx)) => ctx,
                (None, None) => String::new(),
            };
            let response = AntigravityResponse {
                decision: decision.into(),
                reason: if message.is_empty() {
                    if decision == "allow" {
                        None
                    } else {
                        Some("Blocked by Signet policy.".into())
                    }
                } else {
                    Some(message)
                },
            };
            println!("{}", serde_json::to_string(&response).unwrap());
        }
        (HookAdapter::Cursor, _) => {
            emit_cursor_decision(event, decision, reason, additional_context)
        }
        (HookAdapter::Muse, HookEvent::PreToolUse) => {
            // Muse PreToolUse enforces only deny: `ask` is ignored and a bare `allow`
            // is rejected as a failed hook. Emit nothing (or context only) for allow
            // and turn ask into deny, which also requires a non-empty reason.
            match decision {
                "allow" => {
                    if additional_context.is_some() {
                        emit_hook_specific_output("PreToolUse", None, None, additional_context);
                    }
                }
                "ask" => emit_pre_tool_use_decision(
                    "PreToolUse",
                    "deny",
                    Some(non_empty_or(
                        reason,
                        "Signet policy requires approval; Muse PreToolUse cannot ask.",
                    )),
                    additional_context,
                ),
                _ => emit_pre_tool_use_decision(
                    "PreToolUse",
                    "deny",
                    Some(non_empty_or(reason, "Blocked by Signet policy.")),
                    additional_context,
                ),
            }
        }
        (HookAdapter::Codex | HookAdapter::CodexPermission, HookEvent::PreToolUse) => {
            // Codex PreToolUse currently only supports deny as an enforcing decision.
            // Allow/ask fail open in Codex, so emit no output for allow and turn ask into deny.
            // additional_context is preserved on deny so inject nudges still reach the agent.
            match decision {
                "deny" => {
                    emit_pre_tool_use_decision("PreToolUse", "deny", reason, additional_context)
                }
                "ask" => emit_pre_tool_use_decision(
                    "PreToolUse",
                    "deny",
                    Some(reason.unwrap_or_else(|| {
                        "Signet policy requires approval; Codex PreToolUse cannot ask yet.".into()
                    })),
                    additional_context,
                ),
                _ => {}
            }
        }
        (
            HookAdapter::Codex | HookAdapter::CodexPermission | HookAdapter::Muse,
            HookEvent::PermissionRequest,
        ) => {
            // PermissionRequest can explicitly allow/deny. For ASK, decline to decide so
            // Codex shows its normal approval prompt. Codex PermissionRequest has no separate
            // additionalContext channel, so inject payloads append to the `message` field with
            // a delimiter (defensible: message is freeform explanatory text).
            let codex_message = |base: Option<String>| -> Option<String> {
                match (base, additional_context.clone()) {
                    (Some(b), Some(ctx)) => Some(format!("{b}\n\n[nudge]\n{ctx}")),
                    (Some(b), None) => Some(b),
                    (None, Some(ctx)) => Some(format!("[nudge]\n{ctx}")),
                    (None, None) => None,
                }
            };
            match decision {
                "allow" => emit_permission_request_decision("allow", codex_message(None)),
                "deny" => emit_permission_request_decision(
                    "deny",
                    codex_message(Some(
                        reason.unwrap_or_else(|| "Blocked by Signet policy.".into()),
                    )),
                ),
                "ask" => {}
                _ => {}
            }
        }
        // Cursor-only events are never produced for these adapters; fail closed.
        (
            HookAdapter::Codex | HookAdapter::CodexPermission | HookAdapter::Muse,
            HookEvent::BeforeShellExecution
            | HookEvent::BeforeMcpExecution
            | HookEvent::BeforeReadFile,
        ) => emit_pre_tool_use_decision(
            "PreToolUse",
            "deny",
            Some("Unsupported hook event for this adapter.".into()),
            None,
        ),
    }
}

fn non_empty_or(value: Option<String>, fallback: &str) -> String {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.into())
}

/// Cursor permission events: preToolUse honors only deny (ask is ignored), and
/// cursor-agent ignores ask on beforeMCPExecution; beforeReadFile accepts only
/// allow/deny. Only beforeShellExecution turns ask into a user prompt, so ask maps
/// to deny everywhere else. Allow is emitted explicitly because empty output is
/// a failed (fail-open) hook in Cursor.
fn emit_cursor_decision(
    event: HookEvent,
    decision: &str,
    reason: Option<String>,
    additional_context: Option<String>,
) {
    let ask_supported = event == HookEvent::BeforeShellExecution;
    let context_supported = event == HookEvent::PreToolUse;
    let permission = match decision {
        "allow" => "allow",
        "ask" if ask_supported => "ask",
        _ => "deny",
    };

    let (user_message, agent_message) = if permission == "allow" {
        (None, None)
    } else {
        let message = if decision == "ask" && !ask_supported {
            non_empty_or(
                reason,
                "Signet policy requires approval; this Cursor hook cannot ask.",
            )
        } else {
            non_empty_or(reason, "Blocked by Signet policy.")
        };
        let agent_message = match (&additional_context, event) {
            (_, HookEvent::BeforeReadFile) => None,
            (Some(context), _) if !context_supported => Some(format!("{message}\n\n{context}")),
            _ => Some(message.clone()),
        };
        (Some(message), agent_message)
    };

    let response = CursorResponse {
        permission,
        user_message,
        agent_message,
        additional_context: if context_supported {
            additional_context
        } else {
            None
        },
    };
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn emit_pre_tool_use_decision(
    hook_event_name: &str,
    decision: &str,
    reason: Option<String>,
    additional_context: Option<String>,
) {
    emit_hook_specific_output(
        hook_event_name,
        Some(decision.into()),
        reason,
        additional_context,
    );
}

fn emit_hook_specific_output(
    hook_event_name: &str,
    permission_decision: Option<String>,
    reason: Option<String>,
    additional_context: Option<String>,
) {
    let response = HookResponse {
        hook_specific_output: HookOutput {
            hook_event_name: hook_event_name.into(),
            permission_decision,
            reason,
            additional_context,
        },
    };
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn emit_permission_request_decision(behavior: &str, message: Option<String>) {
    let response = CodexPermissionResponse {
        hook_specific_output: CodexPermissionOutput {
            hook_event_name: "PermissionRequest".into(),
            decision: CodexPermissionDecision {
                behavior: behavior.into(),
                message,
            },
        },
    };
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn emit_allow(adapter: HookAdapter, event: HookEvent) {
    emit_decision(adapter, event, "allow", None, None);
}

fn emit_deny(adapter: HookAdapter, event: HookEvent, reason: &str) {
    emit_decision(adapter, event, "deny", Some(reason.into()), None);
}

/// Run an ensure check script and return (passed, stderr_output).
///
/// A missing or unresolvable check fails closed for every rule. The binary
/// installs no checks, so an absent script means the operator's rule cannot be
/// evaluated, which is not the same as the check passing.
///
/// Every reason for a check that could not run names the check, because a
/// rule's custom message replaces the default one that would.
fn resolve_ensure(
    config: &EnsureConfig,
    call: &ToolCall,
    envelope_cwd: Option<&str>,
) -> (bool, String) {
    let could_not_run = |detail: String| {
        (
            false,
            format!("Check '{}' could not run: {detail}", config.check),
        )
    };

    let script_path = match policy::resolve_ensure_script_path(&config.check) {
        Ok(p) => p,
        Err(e) => return could_not_run(format!("script unavailable: {e}")),
    };

    if !script_path.exists() {
        return could_not_run(format!("script not found: {}", script_path.display()));
    }

    let timeout_secs = config.timeout.max(1).min(30) as u64;

    let normalized_input = serde_json::json!({
        "tool_name": call.tool_name,
        "tool_input": call.parameters,
    })
    .to_string();
    const CHECK_INPUT_MAX_BYTES: usize = 32 * 1024;
    if normalized_input.len() > CHECK_INPUT_MAX_BYTES {
        return could_not_run(format!(
            "input exceeds the {CHECK_INPUT_MAX_BYTES}-byte safety limit"
        ));
    }

    // Forward context as literal child environment values, never shell source.
    let first_non_empty = |keys: &[&str]| {
        keys.iter()
            .filter_map(|key| call.parameters.get(*key).and_then(Value::as_str))
            .find(|value| !value.is_empty())
    };
    let tool_command = first_non_empty(&["command", "cmd"]).unwrap_or("");
    let requested_cwd = first_non_empty(&["cwd", "workdir"]);
    let host_cwd = envelope_cwd.filter(|cwd| !cwd.is_empty());
    let (tool_cwd, cwd_source) = match (requested_cwd, host_cwd) {
        (Some(cwd), _) => (cwd.to_owned(), "tool_input"),
        (None, Some(cwd)) => (cwd.to_owned(), "host"),
        (None, None) => (
            std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            "process",
        ),
    };
    let mut command = Command::new(&script_path);
    command
        .env("SIGNET_TOOL_COMMAND", tool_command)
        .env("SIGNET_TOOL_CWD", tool_cwd)
        .env("SIGNET_TOOL_CWD_SOURCE", cwd_source)
        .env("SIGNET_HOST_CWD", host_cwd.unwrap_or(""))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => return could_not_run(format!("failed to spawn script: {e}")),
    };
    if let Some(mut child_stdin) = child.stdin.take() {
        // Some checks do not consume stdin and may exit before this write. Their
        // exit status remains authoritative, so a broken pipe is intentionally
        // ignored.
        let _ = child_stdin.write_all(normalized_input.as_bytes());
    }

    match child.wait_timeout(Duration::from_secs(timeout_secs)) {
        Ok(Some(status)) => {
            let stderr = child
                .stderr
                .take()
                .and_then(|mut s| {
                    let mut buf = Vec::new();
                    io::Read::read_to_end(&mut s, &mut buf).ok()?;
                    Some(String::from_utf8_lossy(&buf[..buf.len().min(500)]).to_string())
                })
                .unwrap_or_default();
            if status.success() {
                (true, String::new())
            } else {
                (false, stderr)
            }
        }
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            could_not_run(format!("script timed out after {timeout_secs}s"))
        }
        Err(e) => could_not_run(format!("error waiting for script: {e}")),
    }
}

/// Resolve an Ensure evaluation result by running the check script.
pub(crate) fn resolve_ensure_result(result: EvaluationResult, call: &ToolCall) -> EvaluationResult {
    resolve_ensure_result_with_cwd(result, call, None)
}

/// Host cwd is execution context only; it never changes authorization parameters.
pub(crate) fn resolve_ensure_result_with_cwd(
    result: EvaluationResult,
    call: &ToolCall,
    envelope_cwd: Option<&str>,
) -> EvaluationResult {
    if let Some(ref ensure_config) = result.ensure_config {
        let (passed, stderr) = resolve_ensure(ensure_config, call, envelope_cwd);
        if passed {
            EvaluationResult {
                decision: Decision::Allow,
                ensure_config: None,
                ..result
            }
        } else {
            let msg = if ensure_config.message.is_empty() {
                format!("Ensure check '{}' failed", ensure_config.check)
            } else {
                ensure_config.message.clone()
            };
            let reason = if stderr.is_empty() {
                msg
            } else {
                format!("{msg} -- {stderr}")
            };
            EvaluationResult {
                decision: Decision::Deny,
                reason: Some(reason),
                ensure_config: None,
                ..result
            }
        }
    } else {
        // Ensure without config — misconfigured, deny
        EvaluationResult {
            decision: Decision::Deny,
            reason: Some("Ensure rule missing ensure config".into()),
            ensure_config: None,
            ..result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_antigravity(input: Value) -> ToolCall {
        parse_tool_call_input(input, HookAdapter::Antigravity).unwrap()
    }

    #[test]
    fn antigravity_native_file_tools_normalize_to_canonical_policy_fields() {
        let write = parse_antigravity(serde_json::json!({
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": "/app/.env",
                    "CodeContent": "SECRET=x",
                    "file_path": "/spoofed",
                    "content": "spoofed"
                }
            }
        }));
        assert_eq!(write.tool_name, "Write");
        assert_eq!(write.parameters["file_path"], "/app/.env");
        assert_eq!(write.parameters["content"], "SECRET=x");
        assert_eq!(write.parameters["agent_tool_name"], "write_to_file");

        let multi_edit = parse_antigravity(serde_json::json!({
            "toolCall": {
                "name": "multi_replace_file_content",
                "args": {"TargetFile": "/app/.env", "file_path": "/spoofed"}
            }
        }));
        assert_eq!(multi_edit.tool_name, "MultiEdit");
        assert_eq!(multi_edit.parameters["file_path"], "/app/.env");
    }

    #[test]
    fn cursor_shell_and_tool_identity_override_spoofed_arguments() {
        let shell = parse_tool_call_input(
            serde_json::json!({
                "hook_event_name": "preToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "ls", "cwd": "/tmp", "agent_tool_name": "spoofed"}
            }),
            HookAdapter::Cursor,
        )
        .unwrap();
        assert_eq!(shell.tool_name, "Bash");
        assert_eq!(shell.parameters["command"], "ls");
        assert_eq!(shell.parameters["agent_tool_name"], "Shell");

        let before_shell = parse_tool_call_input(
            serde_json::json!({
                "hook_event_name": "beforeShellExecution",
                "command": "git status",
                "cwd": "/repo",
                "sandbox": true
            }),
            HookAdapter::Cursor,
        )
        .unwrap();
        assert_eq!(before_shell.tool_name, "Bash");
        assert_eq!(before_shell.parameters["command"], "git status");
        assert_eq!(before_shell.parameters["cwd"], "/repo");
        assert!(before_shell.parameters.get("sandbox").is_none());

        let empty_cwd = parse_tool_call_input(
            serde_json::json!({
                "hook_event_name": "beforeShellExecution",
                "command": "ls",
                "cwd": ""
            }),
            HookAdapter::Cursor,
        )
        .unwrap();
        assert!(empty_cwd.parameters.get("cwd").is_none());

        let mcp = parse_tool_call_input(
            serde_json::json!({
                "hook_event_name": "beforeMCPExecution",
                "tool_name": "delete",
                "tool_input": "{\"target\":\"prod\",\"mcp_server_name\":\"safe\"}",
                "mcp_server_name": "danger"
            }),
            HookAdapter::Cursor,
        )
        .unwrap();
        assert_eq!(mcp.tool_name, "mcp__danger__delete");
        assert_eq!(mcp.parameters["target"], "prod");
        assert_eq!(mcp.parameters["mcp_server_name"], "danger");
        assert_eq!(mcp.parameters["mcp_tool_name"], "delete");
        assert_eq!(mcp.parameters["agent_tool_name"], "MCP:delete");
    }

    #[test]
    fn muse_native_tools_normalize_to_canonical_policy_fields() {
        let parse = |tool: &str, input: Value| {
            parse_tool_call_input(
                serde_json::json!({
                    "hook_event_name": "PreToolUse",
                    "tool_name": tool,
                    "tool_input": input
                }),
                HookAdapter::Muse,
            )
            .unwrap()
        };

        let shell = parse("shell", serde_json::json!({"command": "ls"}));
        assert_eq!(shell.tool_name, "Bash");
        assert_eq!(shell.parameters["agent_tool_name"], "shell");

        let exec = parse("exec_command", serde_json::json!({"cmd": "rm -rf /"}));
        assert_eq!(exec.tool_name, "Bash");
        assert_eq!(exec.parameters["command"], "rm -rf /");

        let write = parse(
            "write_file",
            serde_json::json!({"path": "/app/.env", "file_path": "/spoofed"}),
        );
        assert_eq!(write.tool_name, "Write");
        assert_eq!(write.parameters["file_path"], "/app/.env");

        let read = parse("read_file", serde_json::json!({"file_path": "/a/b"}));
        assert_eq!(read.tool_name, "Read");
        assert_eq!(read.parameters["file_path"], "/a/b");

        let mcp = parse("mcp__kindex__search", serde_json::json!({"query": "x"}));
        assert_eq!(mcp.tool_name, "mcp__kindex__search");
        assert_eq!(mcp.parameters["agent_tool_name"], "mcp__kindex__search");

        let unknown = parse(
            "apply_patch",
            serde_json::json!({"input": "*** Begin Patch"}),
        );
        assert_eq!(unknown.tool_name, "apply_patch");
    }

    #[test]
    fn antigravity_mcp_wrapper_normalizes_identity_and_unwraps_arguments() {
        let call = parse_antigravity(serde_json::json!({
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "danger",
                    "ToolName": "delete",
                    "Arguments": {
                        "target": "production",
                        "agent_tool_name": "spoofed",
                        "mcp_server_name": "safe",
                        "mcp_tool_name": "read"
                    }
                }
            }
        }));

        assert_eq!(call.tool_name, "mcp__danger__delete");
        assert_eq!(call.parameters["target"], "production");
        assert_eq!(call.parameters["agent_tool_name"], "call_mcp_tool");
        assert_eq!(call.parameters["mcp_server_name"], "danger");
        assert_eq!(call.parameters["mcp_tool_name"], "delete");
        assert!(call.parameters.get("Arguments").is_none());
    }
}
