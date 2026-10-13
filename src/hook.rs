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
    let mut call = hook_input.into_tool_call(adapter)?;

    // The host envelope is authoritative for model identity. Drop any lookalike
    // field from tool input so the agent cannot spoof the model a rule sees.
    if let Value::Object(parameters) = &mut call.parameters {
        parameters.remove(AGENT_MODEL_FIELD);
    }
    Ok(call)
}

/// Parameter field exposing the active model to policy conditions,
/// e.g. `not(matches(agent_model, '^claude-opus-'))`.
pub(crate) const AGENT_MODEL_FIELD: &str = "agent_model";

/// Bytes read from the end of a transcript when looking for the active model.
const TRANSCRIPT_TAIL_BYTES: u64 = 1024 * 1024;

/// Claude Code appends the assistant entry for a tool call to the transcript
/// shortly after PreToolUse fires (384-1836ms observed on 2.1.288, slowest on
/// a session's first call), so a lookup keyed on `tool_use_id` polls until the
/// entry lands or this budget expires.
const TOOL_USE_WAIT: Duration = Duration::from_millis(5000);
const TOOL_USE_POLL: Duration = Duration::from_millis(25);

/// Attach `agent_model` to a parsed hook call when a rule or an active
/// preflight constraint could turn on it. Resolution can wait on the host's
/// transcript, so calls that nothing model-scoped could match skip it. While
/// `paused`, only locked rules are enforced, so only they count.
pub(crate) fn attach_agent_model(
    raw_input: &Value,
    policy: &CompiledPolicy,
    vault: Option<&Vault>,
    paused: bool,
    call: &mut ToolCall,
) {
    let preflight_needs_model = || {
        vault
            .and_then(Vault::active_preflight)
            .is_some_and(|preflight| {
                !preflight.escalated
                    && preflight.constraints.iter().any(|constraint| {
                        regex::Regex::new(&constraint.tool_pattern)
                            .is_ok_and(|re| re.is_match(&call.tool_name))
                            && policy::conditions_need_param(
                                &constraint.conditions,
                                AGENT_MODEL_FIELD,
                                call,
                                vault,
                            )
                    })
            })
    };
    if !policy.needs_param(AGENT_MODEL_FIELD, call, vault, paused)
        && (paused || !preflight_needs_model())
    {
        return;
    }
    let Some(model) = resolve_agent_model(raw_input) else {
        return;
    };
    if let Value::Object(parameters) = &mut call.parameters {
        parameters.insert(AGENT_MODEL_FIELD.into(), Value::String(model));
    }
}

/// Identify the model that issued this tool call.
///
/// 1. An explicit host field: `model` (Claude/Codex style) or `modelName`
///    (Antigravity), as a string or an object with `id`.
/// 2. With a `tool_use_id`, the transcript entry that issued that exact call.
///    Subagent calls (`agent_id`) read the subagent's own transcript. An entry
///    that never appears yields `None`.
/// 3. Without a call id, the newest model recorded in the transcript tail.
fn resolve_agent_model(raw_input: &Value) -> Option<String> {
    let explicit = ["model", "modelName"]
        .iter()
        .find_map(|key| match raw_input.get(*key) {
            Some(Value::String(model)) => Some(model.as_str()),
            Some(Value::Object(model)) => model.get("id").and_then(Value::as_str),
            _ => None,
        });
    if let Some(model) = explicit.map(str::trim).filter(|m| !m.is_empty()) {
        return Some(model.to_owned());
    }

    let transcript = transcript_for_call(raw_input)?;
    match string_field(raw_input, "tool_use_id").or_else(|| string_field(raw_input, "toolUseId")) {
        Some(tool_use_id) => wait_for_tool_use_model(&transcript, &tool_use_id),
        None => newest_transcript_model(&transcript),
    }
}

/// The transcript that records this call: the subagent's own file when the
/// host names an `agent_id`, otherwise the session transcript.
fn transcript_for_call(raw_input: &Value) -> Option<std::path::PathBuf> {
    let transcript = ["transcript_path", "transcriptPath"]
        .iter()
        .find_map(|key| string_field(raw_input, key))?;
    let transcript = std::path::PathBuf::from(transcript);

    let Some(agent_id) = string_field(raw_input, "agent_id") else {
        return Some(transcript);
    };
    let session_id = string_field(raw_input, "session_id")?;
    let safe = |id: &str| {
        id.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    if !safe(&agent_id) || !safe(&session_id) {
        return None;
    }
    Some(
        transcript
            .parent()?
            .join(session_id)
            .join("subagents")
            .join(format!("agent-{agent_id}.jsonl")),
    )
}

fn read_transcript_tail(path: &std::path::Path) -> Option<String> {
    use std::io::{Seek, SeekFrom};

    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(TRANSCRIPT_TAIL_BYTES);
    // Read one byte before the window so a line beginning exactly at the
    // boundary can be told apart from the tail of a longer, cut-off line.
    let lookback = start.saturating_sub(1);
    file.seek(SeekFrom::Start(lookback)).ok()?;
    let mut tail = Vec::new();
    file.take(len - lookback).read_to_end(&mut tail).ok()?;

    let skip = if start == 0 {
        0
    } else {
        // Drop the lookback byte, plus the partial line when one was cut.
        tail.iter()
            .position(|&b| b == b'\n')
            .map_or(tail.len(), |i| i + 1)
    };
    Some(String::from_utf8_lossy(&tail[skip..]).into_owned())
}

/// A usable model name, rejecting blanks and placeholders such as `<synthetic>`.
fn usable_model(model: Option<&Value>) -> Option<String> {
    let model = model?.as_str()?.trim();
    (!model.is_empty() && !model.starts_with('<')).then(|| model.to_owned())
}

fn turn_context_model(entry: &Value) -> Option<String> {
    (entry.get("type")?.as_str()? == "turn_context")
        .then(|| usable_model(entry.get("payload")?.get("model")))
        .flatten()
}

/// Model of the entry that issued `tool_use_id`, scanning in file order so
/// the genuine entry wins over any later line that repeats the id. Claude Code
/// records the model on the assistant entry; Codex records it on the
/// `turn_context` preceding the `function_call`.
fn tool_use_model(tail: &str, tool_use_id: &str) -> Option<String> {
    let mut codex_model = None;
    for line in tail.lines() {
        // Cheap prefilter only: the parsed top-level `type` decides the kind,
        // since tool input can carry either string.
        if !line.contains("\"turn_context\"") && !line.contains(tool_use_id) {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match entry.get("type").and_then(Value::as_str) {
            Some("turn_context") => {
                if let Some(model) = turn_context_model(&entry) {
                    codex_model = Some(model);
                }
            }
            Some("assistant") => {
                let message = entry.get("message");
                let issued = message
                    .and_then(|m| m.get("content"))
                    .and_then(Value::as_array)
                    .is_some_and(|blocks| {
                        blocks.iter().any(|block| {
                            block.get("type").and_then(Value::as_str) == Some("tool_use")
                                && block.get("id").and_then(Value::as_str) == Some(tool_use_id)
                        })
                    });
                if issued {
                    return usable_model(message.and_then(|m| m.get("model")));
                }
            }
            Some("response_item") => {
                let payload = entry.get("payload");
                if payload
                    .and_then(|p| p.get("call_id"))
                    .and_then(Value::as_str)
                    == Some(tool_use_id)
                {
                    return codex_model;
                }
            }
            _ => {}
        }
    }
    None
}

fn wait_for_tool_use_model(path: &std::path::Path, tool_use_id: &str) -> Option<String> {
    let deadline = std::time::Instant::now() + TOOL_USE_WAIT;
    loop {
        if let Some(model) = read_transcript_tail(path)
            .as_deref()
            .and_then(|tail| tool_use_model(tail, tool_use_id))
        {
            return Some(model);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(TOOL_USE_POLL);
    }
}

/// Newest model in the transcript tail, for hosts that send no call id.
/// Understands Claude Code assistant entries and Codex `turn_context` entries.
fn newest_transcript_model(path: &std::path::Path) -> Option<String> {
    let tail = read_transcript_tail(path)?;
    tail.lines().rev().find_map(|line| {
        let entry: Value = serde_json::from_str(line).ok()?;
        match entry.get("type")?.as_str()? {
            "assistant" => usable_model(entry.get("message")?.get("model")),
            "turn_context" => turn_context_model(&entry),
            _ => None,
        }
    })
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
    let mut call = match parse_tool_call_input(raw_input.clone(), adapter) {
        Ok(call) => call,
        Err(_) => {
            emit_deny(adapter, event, "Malformed hook input");
            return 0;
        }
    };

    // Check if paused — if so, only enforce locked (self-protection) rules
    // File-based global pause OR session-scoped global pause from pauses.json
    let paused = crate::vault::is_paused_file() || crate::vault::is_globally_paused_json();
    attach_agent_model(&raw_input, policy, vault, paused, &mut call);

    if paused {
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

    const MODEL_GATE_POLICY: &str = r#"
version: 1
default_action: ALLOW
rules:
  - name: cloud_tools_require_opus
    tool_pattern: "^Bash$"
    conditions:
      - "matches(command, '(^|[;&|(\\s])(gcloud|cloud-sql-proxy)(\\s|$)')"
      - "not(matches(agent_model, '^claude-opus-'))"
    action: DENY
    reason: "gcloud/cloud-sql-proxy restricted to Opus"
"#;

    fn model_gate_policy() -> CompiledPolicy {
        CompiledPolicy::from_config(&serde_yaml::from_str(MODEL_GATE_POLICY).unwrap())
    }

    /// Parse and enrich exactly as hook mode does under a policy that reads agent_model.
    fn parse_with_model(input: Value, adapter: HookAdapter) -> ToolCall {
        let mut call = parse_tool_call_input(input.clone(), adapter).unwrap();
        attach_agent_model(&input, &model_gate_policy(), None, false, &mut call);
        call
    }

    fn claude_model(input: Value) -> Option<String> {
        parse_with_model(input, HookAdapter::Claude).parameters["agent_model"]
            .as_str()
            .map(str::to_owned)
    }

    fn write_lines(path: &std::path::Path, lines: &[Value]) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }

    fn assistant(model: &str, tool_use_id: Option<&str>) -> Value {
        let content = match tool_use_id {
            Some(id) => serde_json::json!([{"type": "tool_use", "id": id, "name": "Bash"}]),
            None => serde_json::json!([{"type": "text", "text": "hi"}]),
        };
        serde_json::json!({"type": "assistant", "message": {"model": model, "content": content}})
    }

    #[test]
    fn agent_model_prefers_explicit_envelope_field() {
        let model = claude_model(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "gcloud auth list"},
            "model": {"id": "claude-sonnet-5-5", "display_name": "Sonnet"}
        }));
        assert_eq!(model.as_deref(), Some("claude-sonnet-5-5"));

        // Antigravity's live payload carries the model as camel-case modelName.
        let call = parse_with_model(
            serde_json::json!({
                "conversationId": "4989a389-5729-4c84-9e4f-44bb9044633a",
                "modelName": "gemini-pro-agent",
                "toolCall": {"name": "run_command", "args": {"CommandLine": "gcloud auth list", "Cwd": "/tmp"}}
            }),
            HookAdapter::Antigravity,
        );
        assert_eq!(call.parameters["agent_model"], "gemini-pro-agent");
    }

    #[test]
    fn agent_model_binds_to_the_entry_that_issued_the_call() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("session.jsonl");
        write_lines(
            &transcript,
            &[
                assistant("claude-opus-5-5", None),
                assistant("claude-haiku-4-5-20251001", Some("toolu_real")),
                // A line planted after the genuine entry cannot override it.
                assistant("claude-opus-5-5", Some("toolu_real")),
                assistant("claude-opus-5-5", None),
            ],
        );
        let model = claude_model(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "gcloud auth list"},
            "transcript_path": transcript,
            "tool_use_id": "toolu_real"
        }));
        assert_eq!(model.as_deref(), Some("claude-haiku-4-5-20251001"));
    }

    #[test]
    fn agent_model_reads_an_issuing_entry_whose_input_mentions_turn_context() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("session.jsonl");
        write_lines(
            &transcript,
            &[serde_json::json!({
                "type": "assistant",
                "message": {
                    "model": "claude-opus-5-5",
                    "content": [{
                        "type": "tool_use",
                        "id": "toolu_ctx",
                        "name": "Bash",
                        "input": {"command": "gcloud auth list", "turn_context": {}}
                    }]
                }
            })],
        );
        let model = claude_model(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "gcloud auth list"},
            "transcript_path": transcript,
            "tool_use_id": "toolu_ctx"
        }));
        assert_eq!(model.as_deref(), Some("claude-opus-5-5"));
    }

    #[test]
    fn agent_model_waits_for_a_late_transcript_write() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("session.jsonl");
        write_lines(&transcript, &[assistant("claude-opus-5-5", None)]);
        let writer = {
            let transcript = transcript.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                write_lines(
                    &transcript,
                    &[assistant("claude-sonnet-5-5", Some("toolu_late"))],
                );
            })
        };
        let model = claude_model(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "gcloud auth list"},
            "transcript_path": transcript,
            "tool_use_id": "toolu_late"
        }));
        writer.join().unwrap();
        assert_eq!(model.as_deref(), Some("claude-sonnet-5-5"));
    }

    #[test]
    fn agent_model_absent_when_issuing_entry_never_appears() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("session.jsonl");
        write_lines(&transcript, &[assistant("claude-opus-5-5", None)]);
        let model = claude_model(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "gcloud auth list"},
            "transcript_path": transcript,
            "tool_use_id": "toolu_missing"
        }));
        assert_eq!(model, None);
    }

    #[test]
    fn agent_model_reads_the_subagent_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("sess-1.jsonl");
        write_lines(
            &transcript,
            &[assistant("claude-opus-5-5", Some("toolu_sub"))],
        );
        let subagents = dir.path().join("sess-1").join("subagents");
        std::fs::create_dir_all(&subagents).unwrap();
        write_lines(
            &subagents.join("agent-a28131507e0931abb.jsonl"),
            &[assistant("claude-haiku-4-5-20251001", Some("toolu_sub"))],
        );
        let input = |agent_id: &str| {
            serde_json::json!({
                "session_id": "sess-1",
                "agent_id": agent_id,
                "tool_name": "Bash",
                "tool_input": {"command": "gcloud auth list"},
                "transcript_path": transcript,
                "tool_use_id": "toolu_sub"
            })
        };
        assert_eq!(
            claude_model(input("a28131507e0931abb")).as_deref(),
            Some("claude-haiku-4-5-20251001")
        );
        assert_eq!(claude_model(input("../../sess-1")), None);
    }

    #[test]
    fn agent_model_reads_codex_rollouts() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("rollout.jsonl");
        write_lines(
            &transcript,
            &[
                serde_json::json!({"type": "turn_context", "payload": {"model": "gpt-5.5-codex"}}),
                serde_json::json!({"type": "response_item", "payload": {"type": "function_call", "call_id": "call_1"}}),
                serde_json::json!({"type": "turn_context", "payload": {"model": "gpt-5.5-mini"}}),
            ],
        );
        let input = |call_id: Option<&str>| {
            let mut input = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "gcloud auth list"},
                "transcript_path": transcript
            });
            if let Some(id) = call_id {
                input["tool_use_id"] = Value::String(id.into());
            }
            parse_with_model(input, HookAdapter::Codex)
        };
        assert_eq!(
            input(Some("call_1")).parameters["agent_model"],
            "gpt-5.5-codex"
        );
        assert_eq!(input(None).parameters["agent_model"], "gpt-5.5-mini");
    }

    #[test]
    fn agent_model_newest_fallback_skips_placeholders_and_partial_lines() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("session.jsonl");
        let filler = "x".repeat(TRANSCRIPT_TAIL_BYTES as usize);
        write_lines(
            &transcript,
            &[
                serde_json::json!({"type": "assistant", "message": {"model": "claude-opus-5-5"}, "pad": filler}),
                assistant("claude-sonnet-5-5", None),
                assistant("<synthetic>", None),
            ],
        );
        let model = claude_model(serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "gcloud auth list"},
            "transcript_path": transcript
        }));
        assert_eq!(model.as_deref(), Some("claude-sonnet-5-5"));
    }

    #[test]
    fn transcript_tail_keeps_a_line_starting_exactly_at_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.jsonl");
        let last = assistant("claude-sonnet-5-5", None).to_string();
        let window = TRANSCRIPT_TAIL_BYTES as usize;

        // The window begins exactly at the start of `last`: it holds `last`
        // plus a filler line, preceded by an earlier complete line.
        let filler = format!("{}\n", "#".repeat(window - last.len() - 2));
        std::fs::write(&path, format!("{{}}\n{last}\n{filler}")).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() - TRANSCRIPT_TAIL_BYTES,
            3
        );
        let tail = read_transcript_tail(&path).unwrap();
        assert!(tail.lines().any(|line| line == last));

        // The window begins one byte into a line: that fragment is dropped.
        std::fs::write(&path, format!("{}\n{last}\n", "#".repeat(window + 1))).unwrap();
        let tail = read_transcript_tail(&path).unwrap();
        assert!(!tail.contains('#'));
        assert!(tail.lines().any(|line| line == last));
    }

    #[test]
    fn agent_model_cannot_be_spoofed_through_tool_input() {
        let spoofed = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "gcloud sql connect", "agent_model": "claude-opus-5-5"}
        });
        assert_eq!(claude_model(spoofed.clone()), None);
        let call = parse_tool_call_input(spoofed, HookAdapter::Claude).unwrap();
        assert!(call.parameters.get("agent_model").is_none());
    }

    #[test]
    fn agent_model_is_only_resolved_when_a_rule_could_match() {
        let attached = |command: &str, policy: &CompiledPolicy| {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "model": "claude-opus-5-5"
            });
            let mut call = parse_tool_call_input(input.clone(), HookAdapter::Claude).unwrap();
            attach_agent_model(&input, policy, None, false, &mut call);
            call.parameters.get("agent_model").is_some()
        };
        assert!(attached("gcloud auth list", &model_gate_policy()));
        assert!(!attached("ls", &model_gate_policy()));
        assert!(!attached("gcloud auth list", &policy::default_policy()));
    }

    fn policy_from_yaml(yaml: &str) -> CompiledPolicy {
        CompiledPolicy::from_config(&serde_yaml::from_str(yaml).unwrap())
    }

    /// Hook-mode decision for a Bash call issued by `model`.
    fn decide_with_model(
        policy: &CompiledPolicy,
        vault: Option<&Vault>,
        command: &str,
        model: &str,
    ) -> Decision {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "model": model
        });
        let mut call = parse_tool_call_input(input.clone(), HookAdapter::Claude).unwrap();
        attach_agent_model(&input, policy, vault, false, &mut call);
        policy::evaluate(&call, policy, vault).decision
    }

    #[test]
    fn agent_model_is_not_resolved_for_rules_shadowed_by_an_earlier_match() {
        let attached = |policy: &CompiledPolicy, command: &str| {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "model": "claude-opus-5-5"
            });
            let mut call = parse_tool_call_input(input.clone(), HookAdapter::Claude).unwrap();
            attach_agent_model(&input, policy, None, false, &mut call);
            call.parameters.get("agent_model").is_some()
        };
        let policy = |model_rule_action: &str| {
            policy_from_yaml(&format!(
                r#"
version: 1
default_action: ALLOW
rules:
  - name: allow_gcloud_auth
    tool_pattern: "^Bash$"
    conditions:
      - "matches(command, '^gcloud auth ')"
    action: ALLOW
  - name: model_rule
    tool_pattern: "^Bash$"
    conditions:
      - "matches(command, '^gcloud ')"
      - "not(matches(agent_model, '^claude-opus-'))"
    action: {model_rule_action}
    inject:
      trigger: {{mode: constant, peak: 1.0}}
      payload: {{text: "use opus"}}
"#
            ))
        };
        // First match wins, so the earlier ALLOW decides `gcloud auth`.
        assert!(!attached(&policy("DENY"), "gcloud auth list"));
        assert!(attached(&policy("DENY"), "gcloud sql connect"));
        // INJECT rules run in their own pass and stay reachable.
        assert!(attached(&policy("INJECT"), "gcloud auth list"));
    }

    #[test]
    fn agent_model_is_only_resolved_for_locked_rules_while_paused() {
        let policy = |locked: bool| {
            policy_from_yaml(&format!(
                r#"
version: 1
default_action: ALLOW
rules:
  - name: gcloud_requires_opus
    tool_pattern: "^Bash$"
    conditions:
      - "matches(command, '^gcloud ')"
      - "not(matches(agent_model, '^claude-opus-'))"
    action: DENY
    locked: {locked}
"#
            ))
        };
        let attached = |policy: &CompiledPolicy, paused: bool| {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {"command": "gcloud auth list"},
                "model": "claude-opus-5-5"
            });
            let mut call = parse_tool_call_input(input.clone(), HookAdapter::Claude).unwrap();
            attach_agent_model(&input, policy, None, paused, &mut call);
            call.parameters.get("agent_model").is_some()
        };
        assert!(attached(&policy(false), false));
        // A pause enforces only locked rules, so nothing else is worth the wait.
        assert!(!attached(&policy(false), true));
        assert!(attached(&policy(true), true));
    }

    #[test]
    fn agent_model_gating_treats_vault_state_as_undecided() {
        crate::vault::set_test_session_id(Some("vault-state-gate"));
        let dir = tempfile::tempdir().unwrap();
        let key = crate::vault::derive_master_key("testpass", &[0u8; 16]);
        let vault = Vault::new(key, dir.path().join("state.db"));
        let policy = policy_from_yaml(
            r#"
version: 1
default_action: ALLOW
rules:
  - name: no_haiku_after_plan
    tool_pattern: "^Bash$"
    conditions:
      - "has_recent_action('EnterPlanMode', 5)"
      - "matches(agent_model, '^claude-haiku-')"
    action: DENY
"#,
        );
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "model": "claude-haiku-4-5-20251001"
        });
        let mut call = parse_tool_call_input(input.clone(), HookAdapter::Claude).unwrap();
        attach_agent_model(&input, &policy, Some(&vault), false, &mut call);
        // The ledger changes between gating and evaluation, as a concurrent
        // hook or a transient read failure would make it.
        vault.log_action("EnterPlanMode", "allow", "", 0.0, "{}");
        let decision = policy::evaluate(&call, &policy, Some(&vault)).decision;
        crate::vault::clear_test_session_id();
        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn agent_model_is_resolved_for_active_preflight_constraints() {
        crate::vault::set_test_session_id(None);
        let dir = tempfile::tempdir().unwrap();
        let key = crate::vault::derive_master_key("testpass", &[0u8; 16]);
        let vault = Vault::new(key, dir.path().join("state.db"));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        vault
            .store_preflight(&Preflight {
                id: "opus-only".into(),
                task: "cloud work".into(),
                risks: vec![],
                constraints: vec![SoftConstraint {
                    name: "gcloud_requires_opus".into(),
                    tool_pattern: "^Bash$".into(),
                    conditions: vec![
                        "matches(command, '^gcloud ')".into(),
                        "not(matches(agent_model, '^claude-opus-'))".into(),
                    ],
                    action: "DENY".into(),
                    reason: "gcloud is Opus-only".into(),
                    alternative: "hand off to Opus".into(),
                }],
                submitted_at: now,
                lockout_until: now + 3600,
                violation_count: 0,
                escalated: false,
                session_id: None,
            })
            .unwrap();
        let preflight = vault.active_preflight().unwrap();

        // The hard policy never names agent_model; only the constraint does.
        let policy = policy::default_policy();
        let violates = |model: &str| {
            let input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {"command": "gcloud sql connect"},
                "model": model
            });
            let mut call = parse_tool_call_input(input.clone(), HookAdapter::Claude).unwrap();
            attach_agent_model(&input, &policy, Some(&vault), false, &mut call);
            evaluate_preflight_constraint(&call, &preflight, &vault).is_some()
        };
        assert!(!violates("claude-opus-5-5"));
        assert!(violates("claude-haiku-4-5-20251001"));
        crate::vault::clear_test_session_id();
    }

    #[test]
    fn agent_model_is_resolved_for_conditions_reading_all_parameters() {
        for reader in [
            "matches(parameters, 'claude-opus-')",
            "contains(parameters, 'claude-opus-')",
            "any_of(parameters, 'claude-opus-', 'gpt-5')",
            "contains_word(parameters, 'claude-opus-5-5')",
            "'claude-opus-'",
            "not(not(contains(parameters, 'claude-opus-')))",
            "or(false, contains(parameters, 'claude-opus-'))",
        ] {
            let policy = policy_from_yaml(&format!(
                r#"
version: 1
default_action: ALLOW
rules:
  - name: opus_reader
    tool_pattern: "^Bash$"
    conditions:
      - "{reader}"
      - "matches(agent_model, '.')"
    action: DENY
"#
            ));
            assert_eq!(
                decide_with_model(&policy, None, "ls", "claude-opus-5-5"),
                Decision::Deny,
                "{reader}"
            );
        }
    }

    #[test]
    fn agent_model_gates_cloud_tools_and_fails_closed_when_unknown() {
        let compiled = model_gate_policy();
        let decide = |command: &str, model: Option<&str>| {
            let mut input = serde_json::json!({
                "tool_name": "Bash",
                "tool_input": {"command": command}
            });
            if let Some(model) = model {
                input["model"] = Value::String(model.into());
            }
            let call = parse_with_model(input, HookAdapter::Claude);
            policy::evaluate(&call, &compiled, None).decision
        };
        let gcloud = "gcloud sql instances list";
        assert_eq!(decide(gcloud, Some("claude-opus-5-5")), Decision::Allow);
        assert_eq!(
            decide(gcloud, Some("claude-haiku-4-5-20251001")),
            Decision::Deny
        );
        assert_eq!(decide(gcloud, None), Decision::Deny);
        assert_eq!(
            decide("ls", Some("claude-haiku-4-5-20251001")),
            Decision::Allow
        );
    }
}
