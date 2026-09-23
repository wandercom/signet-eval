//! Signet MCP Management Server — manage policies conversationally through Claude.

use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::Value;
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;

use crate::policy::{Decision, EnsureConfig, GateConfig, PolicyConfig, PolicyRule};
use crate::vault;

fn policy_path() -> PathBuf {
    vault::signet_dir().join("policy.yaml")
}

fn rules_path() -> PathBuf {
    vault::signet_dir().join("rules.yaml")
}

fn load_policy_raw() -> PolicyConfig {
    let path = policy_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap_or_default(),
        Err(_) => PolicyConfig::default(),
    }
}

fn load_rules_raw() -> Vec<PolicyRule> {
    crate::policy::load_rules(&rules_path())
}

fn save_rules(rules: &[PolicyRule]) {
    let path = rules_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Ok(yaml) = serde_yaml::to_string(rules) {
        std::fs::write(&path, &yaml).ok();
    }
}

fn save_policy(config: &PolicyConfig) {
    let path = policy_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Ok(yaml) = serde_yaml::to_string(config) {
        std::fs::write(&path, &yaml).ok();
    }
}

/// Auto-sign both policy and rules files after MCP modifications (if vault is available).
fn auto_sign() {
    if let Some(v) = vault::try_load_vault() {
        let _ = vault::sign_policy(v.session_key(), &policy_path());
        if rules_path().exists() {
            let _ = vault::sign_policy(v.session_key(), &rules_path());
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            version: 1,
            rules: vec![],
            default_action: Decision::Allow,
        }
    }
}

fn make_tool(name: &'static str, desc: &'static str, schema: serde_json::Value) -> Tool {
    let obj: serde_json::Map<String, Value> = match schema {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    let mut tool = Tool::default();
    tool.name = Cow::Borrowed(name);
    tool.description = Some(Cow::Borrowed(desc));
    tool.input_schema = Arc::new(obj);
    tool
}

pub struct SignetMcpServer;

impl ServerHandler for SignetMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some("Signet policy enforcement for Claude Code. Use these tools to manage what actions are allowed, denied, or require confirmation.".into());
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async {
            let tools = vec![
                make_tool("signet_list_rules", "List all current policy rules. Shows what's blocked, allowed, or requires confirmation.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_add_rule", "Add a policy rule. Action: ALLOW, DENY, ASK, GATE, or ENSURE.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Rule name (e.g. 'block_rm', 'limit_amazon')"},
                        "action": {"type": "string", "description": "ALLOW, DENY, ASK, GATE, or ENSURE"},
                        "reason": {"type": "string", "description": "Why this rule exists"},
                        "tool_pattern": {"type": "string", "description": "Regex matching tool names (default '.*')", "default": ".*"},
                        "conditions": {"type": "array", "items": {"type": "string"}, "description": "Condition expressions"},
                        "gate": {"type": "object", "properties": {"requires_prior": {"type": "string"}, "within": {"type": "integer", "default": 50}}, "description": "Gate config (required for GATE action)"},
                        "ensure": {"type": "object", "properties": {"check": {"type": "string"}, "timeout": {"type": "integer", "default": 5}, "message": {"type": "string"}}, "description": "Ensure config (required for ENSURE action)"}
                    },
                    "required": ["name", "action", "reason"]
                })),
                make_tool("signet_remove_rule", "Remove a policy rule by name.", serde_json::json!({
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Rule name to remove"}},
                    "required": ["name"]
                })),
                make_tool("signet_set_limit", "Set a spending limit for a category.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Spending category (e.g. 'books', 'amazon')"},
                        "max_amount": {"type": "number", "description": "Maximum spend in dollars"},
                        "per": {"type": "string", "description": "'session' or 'total'", "default": "session"},
                        "tool_pattern": {"type": "string", "description": "Regex for purchase tool names", "default": ".*purchase.*|.*buy.*|.*shop.*|.*order.*"}
                    },
                    "required": ["category", "max_amount"]
                })),
                make_tool("signet_status", "Show vault status, spending totals, credential count.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_recent_actions", "Show recent action log.", serde_json::json!({
                    "type": "object",
                    "properties": {"limit": {"type": "integer", "description": "Number of actions to show", "default": 20}},
                })),
                make_tool("signet_store_credential", "Store a Tier 3 credential (compartment-encrypted).", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Credential name (e.g. 'cc_visa')"},
                        "value": {"type": "string", "description": "Secret value to store"}
                    },
                    "required": ["name", "value"]
                })),
                make_tool("signet_list_credentials", "List credential names (not values).", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_delete_credential", "Delete a credential from the vault.", serde_json::json!({
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Credential name to delete"}},
                    "required": ["name"]
                })),
                make_tool("signet_validate", "Validate the current policy file. Shows errors with actionable fix hints. Pass fix=true to auto-fix (removes broken rules, clamps out-of-range values). Locked rules are never modified.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "fix": {"type": "boolean", "description": "If true, auto-fix issues (removes broken unlocked rules, clamps out-of-range values). Default: false (dry-run)."}
                    }
                })),
                make_tool("signet_test", "Test a tool call against the current policy without executing it.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Tool name (e.g. 'Bash', 'Write')"},
                        "tool_input": {"type": "object", "description": "Tool arguments as JSON object"}
                    },
                    "required": ["tool_name"]
                })),
                make_tool("signet_condition_help", "Show all available condition functions with descriptions and examples.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_reorder_rule", "Move a rule to a new position (1-based). Critical since first-match-wins.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Rule name to move"},
                        "position": {"type": "integer", "description": "New position (1-based, 1 = first/highest priority)"}
                    },
                    "required": ["name", "position"]
                })),
                make_tool("signet_edit_rule", "Edit an existing rule's properties.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Rule name to edit"},
                        "action": {"type": "string", "description": "New action (ALLOW/DENY/ASK/GATE/ENSURE)"},
                        "reason": {"type": "string", "description": "New reason"},
                        "tool_pattern": {"type": "string", "description": "New tool pattern regex"},
                        "conditions": {"type": "array", "items": {"type": "string"}, "description": "New conditions (replaces existing)"},
                        "gate": {"type": "object", "properties": {"requires_prior": {"type": "string"}, "within": {"type": "integer"}}, "description": "Gate config (required for GATE action)"},
                        "ensure": {"type": "object", "properties": {"check": {"type": "string"}, "timeout": {"type": "integer"}, "message": {"type": "string"}}, "description": "Ensure config (required for ENSURE action)"}
                    },
                    "required": ["name"]
                })),
                make_tool("signet_sign_policy", "Sign the policy file with HMAC for tamper detection.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_reset_session", "Reset session spending counters.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_use_credential", "Request a credential through the policy-gated capability system. Enforces domain, purpose, amount, and one-time constraints.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Credential name (e.g. 'cc_visa')"},
                        "domain": {"type": "string", "description": "Domain for this use (e.g. 'amazon.com')", "default": ""},
                        "amount": {"type": "number", "description": "Transaction amount (checked against max_amount constraint)", "default": 0},
                        "purpose": {"type": "string", "description": "Purpose of use (e.g. 'purchase')", "default": ""}
                    },
                    "required": ["name"]
                })),
                // --- Preflight tools ---
                make_tool("signet_preflight_submit", "File a preflight: declare task intent, risks, and self-imposed constraints before starting work. Constraints are HMAC-signed and locked for the specified duration.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "task": {"type": "string", "description": "What you intend to do"},
                        "risks": {"type": "array", "items": {"type": "string"}, "description": "What could go wrong"},
                        "constraints": {"type": "array", "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "tool_pattern": {"type": "string", "description": "Regex matching tool names"},
                                "conditions": {"type": "array", "items": {"type": "string"}},
                                "action": {"type": "string", "description": "DENY or ASK"},
                                "reason": {"type": "string"},
                                "alternative": {"type": "string", "description": "Plan B: what to do instead (required)"}
                            },
                            "required": ["name", "tool_pattern", "conditions", "action", "reason", "alternative"]
                        }, "description": "Self-imposed soft constraints (max 20)"},
                        "lockout_minutes": {"type": "integer", "description": "How long this preflight is locked (5-480 min)", "minimum": 5, "maximum": 480},
                        "session_id": {"type": "string", "description": "Optional chat/session id. Defaults to current client session env if available."},
                        "force": {"type": "boolean", "description": "Bypass overly-broad constraint check (default false)", "default": false}
                    },
                    "required": ["task", "risks", "constraints", "lockout_minutes"]
                })),
                make_tool("signet_preflight_active", "View your active preflight: task, constraints, lockout status, violation count.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_preflight_history", "View past preflights and their outcomes.", serde_json::json!({
                    "type": "object",
                    "properties": {"limit": {"type": "integer", "description": "Number of entries", "default": 10}},
                })),
                make_tool("signet_preflight_violations", "View constraint violations for the active or a specified preflight.", serde_json::json!({
                    "type": "object",
                    "properties": {"preflight_id": {"type": "string", "description": "Optional. Defaults to active preflight."}},
                })),
                make_tool("signet_preflight_test", "Dry-run: validate preflight constraints without submitting.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "constraints": {"type": "array", "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "tool_pattern": {"type": "string"},
                                "conditions": {"type": "array", "items": {"type": "string"}},
                                "action": {"type": "string"},
                                "reason": {"type": "string"},
                                "alternative": {"type": "string"}
                            },
                            "required": ["name", "tool_pattern", "conditions", "action", "reason", "alternative"]
                        }}
                    },
                    "required": ["constraints"]
                })),
            ];
            Ok(ListToolsResult {
                tools,
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            let empty = serde_json::Map::new();
            let args_map = request.arguments.as_ref().unwrap_or(&empty);
            let args = &args_map;
            let result = match &*request.name {
                "signet_list_rules" => handle_list_rules(),
                "signet_add_rule" => handle_add_rule(args),
                "signet_remove_rule" => handle_remove_rule(args),
                "signet_set_limit" => handle_set_limit(args),
                "signet_status" => handle_status(),
                "signet_recent_actions" => handle_recent_actions(args),
                "signet_store_credential" => handle_store_credential(args),
                "signet_list_credentials" => handle_list_credentials(),
                "signet_delete_credential" => handle_delete_credential(args),
                "signet_validate" => handle_validate(args),
                "signet_test" => handle_test(args),
                "signet_condition_help" => handle_condition_help(),
                "signet_reorder_rule" => handle_reorder_rule(args),
                "signet_edit_rule" => handle_edit_rule(args),
                "signet_sign_policy" => handle_sign_policy(),
                "signet_reset_session" => handle_reset_session(),
                "signet_use_credential" => handle_use_credential(args),
                "signet_preflight_submit" => handle_preflight_submit(args),
                "signet_preflight_active" => handle_preflight_active(),
                "signet_preflight_history" => handle_preflight_history(args),
                "signet_preflight_violations" => handle_preflight_violations(args),
                "signet_preflight_test" => handle_preflight_test(args),
                _ => format!("Unknown tool: {}", request.name),
            };
            Ok(CallToolResult::success(vec![ContentBlock::text(result)]))
        }
    }
}

// === Tool Handlers ===

fn handle_list_rules() -> String {
    let config = load_policy_raw();
    let user_rules = load_rules_raw();
    let merged = crate::policy::merge_rules(&config.rules, &user_rules);
    if merged.is_empty() {
        return format!(
            "No rules. Default action: {:?}. Everything is allowed.",
            config.default_action
        );
    }
    let user_names: std::collections::HashSet<&str> =
        user_rules.iter().map(|r| r.name.as_str()).collect();
    let mut lines = vec![
        format!("Default: {:?}", config.default_action),
        format!("Rules ({}, eval order):\n", merged.len()),
    ];
    for (i, r) in merged.iter().enumerate() {
        let source = if r.locked {
            " [LOCKED]"
        } else if user_names.contains(r.name.as_str()) {
            " [USER]"
        } else {
            " [SYSTEM]"
        };
        lines.push(format!(
            "  {}. [{:?}] {}{}",
            i + 1,
            r.action,
            r.name,
            source
        ));
        if let Some(ref reason) = r.reason {
            lines.push(format!("     Reason: {reason}"));
        }
        if r.tool_pattern != ".*" {
            lines.push(format!("     Tools: {}", r.tool_pattern));
        }
        for c in &r.conditions {
            lines.push(format!("     Condition: {c}"));
        }
        if let Some(ref gc) = r.gate {
            lines.push(format!(
                "     Gate: requires '{}' in last {} actions",
                gc.requires_prior, gc.within
            ));
        }
        if let Some(ref ec) = r.ensure {
            lines.push(format!(
                "     Ensure: check='{}' timeout={}s",
                ec.check, ec.timeout
            ));
            if !ec.message.is_empty() {
                lines.push(format!("     Message: {}", ec.message));
            }
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn handle_add_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let action_str = args.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let tool_pattern = args
        .get("tool_pattern")
        .and_then(|v| v.as_str())
        .unwrap_or(".*");
    let conditions: Vec<String> = args
        .get("conditions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let action = match action_str.to_uppercase().as_str() {
        "ALLOW" => Decision::Allow,
        "DENY" => Decision::Deny,
        "ASK" => Decision::Ask,
        "GATE" => Decision::Gate,
        "ENSURE" => Decision::Ensure,
        _ => {
            return format!(
                "Invalid action '{action_str}'. Must be ALLOW, DENY, ASK, GATE, or ENSURE."
            )
        }
    };

    // Parse Gate config
    let gate = if action == Decision::Gate {
        let gc = args.get("gate").and_then(|v| v.as_object());
        match gc {
            Some(g) => {
                let requires_prior = g
                    .get("requires_prior")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if requires_prior.is_empty() {
                    return "GATE action requires gate.requires_prior".into();
                }
                let within = g.get("within").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
                if within < 1 || within > 500 {
                    return "gate.within must be 1-500".into();
                }
                Some(GateConfig {
                    requires_prior,
                    within,
                })
            }
            None => return "GATE action requires a 'gate' config object".into(),
        }
    } else {
        None
    };

    // Parse Ensure config
    let ensure = if action == Decision::Ensure {
        let ec = args.get("ensure").and_then(|v| v.as_object());
        match ec {
            Some(e) => {
                let check = e
                    .get("check")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Err(err) = crate::policy::validate_ensure_check_name(&check) {
                    return format!("Invalid ensure.check: {err}");
                }
                let timeout = e.get("timeout").and_then(|v| v.as_u64()).unwrap_or(5) as u32;
                if timeout < 1 || timeout > 30 {
                    return "ensure.timeout must be 1-30".into();
                }
                let message = e
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(EnsureConfig {
                    check,
                    timeout,
                    message,
                })
            }
            None => return "ENSURE action requires an 'ensure' config object".into(),
        }
    } else {
        None
    };

    // Check name uniqueness across both system and user rules
    let system_config = load_policy_raw();
    let mut user_rules = load_rules_raw();
    if system_config.rules.iter().any(|r| r.name == name) {
        return format!(
            "Rule '{name}' already exists in system policy. Use a different name or override it."
        );
    }
    if user_rules.iter().any(|r| r.name == name) {
        return format!("Rule '{name}' already exists in user rules. Remove it first.");
    }

    user_rules.push(PolicyRule {
        name: name.into(),
        tool_pattern: tool_pattern.into(),
        conditions,
        action,
        reason: Some(reason.into()),
        alternative: None,
        locked: false,
        gate,
        ensure,
        inject: None,
    });
    save_rules(&user_rules);
    auto_sign();
    format!("Added rule '{name}' ({action:?}) to user rules: {reason}")
}

fn handle_remove_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    // Check if it's a locked system rule
    let system_config = load_policy_raw();
    if let Some(rule) = system_config.rules.iter().find(|r| r.name == name) {
        if rule.locked {
            return format!("Cannot remove rule '{name}': rule is locked (self-protection).");
        }
        if !rule.locked {
            return format!(
                "Cannot remove system rule '{name}'. Add an overriding rule in user rules instead."
            );
        }
    }
    // Remove from user rules
    let mut user_rules = load_rules_raw();
    let before = user_rules.len();
    user_rules.retain(|r| r.name != name);
    if user_rules.len() == before {
        return format!("Rule '{name}' not found in user rules.");
    }
    save_rules(&user_rules);
    auto_sign();
    format!("Removed rule '{name}' from user rules.")
}

fn handle_set_limit(args: &serde_json::Map<String, Value>) -> String {
    let category = args.get("category").and_then(|v| v.as_str()).unwrap_or("");
    let max_amount = args
        .get("max_amount")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let per = args
        .get("per")
        .and_then(|v| v.as_str())
        .unwrap_or("session");
    let tool_pattern = args
        .get("tool_pattern")
        .and_then(|v| v.as_str())
        .unwrap_or(".*purchase.*|.*buy.*|.*shop.*|.*order.*");

    let name = format!("limit_{}_{}", category, max_amount as u64);

    let mut config = load_policy_raw();
    config.rules.retain(|r| r.name != name);
    config.rules.push(PolicyRule {
        name: name.clone(),
        tool_pattern: tool_pattern.into(),
        conditions: vec![
            format!("param_eq(category, '{category}')"),
            format!("spend_plus_amount_gt('{category}', amount, {max_amount})"),
        ],
        action: Decision::Deny,
        reason: Some(format!(
            "Spending limit: ${max_amount:.0}/{per} on {category}"
        )),
        alternative: None,
        locked: false,
        gate: None,
        ensure: None,
        inject: None,
    });
    save_policy(&config);
    auto_sign();
    format!("Set ${max_amount:.0}/{per} limit on {category}.")
}

fn handle_status() -> String {
    let config = load_policy_raw();
    let mut lines = vec![format!(
        "Policy: {} rules (default: {:?})",
        config.rules.len(),
        config.default_action
    )];
    if !vault::vault_exists() {
        lines.push("Vault: not set up (run: signet-eval setup)".into());
        return lines.join("\n");
    }
    match vault::try_load_vault() {
        Some(v) => {
            lines.push("Vault: unlocked".into());
            lines.push(format!("Credentials: {}", v.list_credentials().len()));
            let spend = v.session_spend("");
            if spend > 0.0 {
                lines.push(format!("Session spend: ${spend:.2}"));
            }
            let actions = v.recent_actions(5);
            if !actions.is_empty() {
                lines.push(format!("\nLast {} actions:", actions.len()));
                for a in &actions {
                    let tool = a["tool"].as_str().unwrap_or("?");
                    let dec = a["decision"].as_str().unwrap_or("?");
                    let amt = a["amount"].as_f64().unwrap_or(0.0);
                    let cat = a["category"].as_str().unwrap_or("");
                    if amt > 0.0 {
                        lines.push(format!("  {tool} [{cat}] ${amt:.2} -> {dec}"));
                    } else {
                        lines.push(format!("  {tool} -> {dec}"));
                    }
                }
            }
        }
        None => lines.push("Vault: locked".into()),
    }
    lines.join("\n")
}

fn handle_recent_actions(args: &serde_json::Map<String, Value>) -> String {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as u32;
    match vault::try_load_vault() {
        Some(v) => {
            let actions = v.recent_actions(limit);
            if actions.is_empty() {
                return "No actions recorded.".into();
            }
            let mut lines = vec![format!("Recent actions ({}):", actions.len())];
            for a in &actions {
                let tool = a["tool"].as_str().unwrap_or("?");
                let dec = a["decision"].as_str().unwrap_or("?");
                let amt = a["amount"].as_f64().unwrap_or(0.0);
                let cat = a["category"].as_str().unwrap_or("");
                if amt > 0.0 {
                    lines.push(format!("  {tool} [{cat}] ${amt:.2} -> {dec}"));
                } else {
                    lines.push(format!("  {tool} -> {dec}"));
                }
            }
            lines.join("\n")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_store_credential(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("");
    match vault::try_load_vault() {
        Some(v) => {
            v.store_credential(name, value, 3);
            format!("Stored '{name}' (Tier 3 compartment-encrypted).")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_list_credentials() -> String {
    match vault::try_load_vault() {
        Some(v) => {
            let creds = v.list_credentials();
            if creds.is_empty() {
                return "No credentials stored.".into();
            }
            let mut lines = vec![format!("Credentials ({}):", creds.len())];
            for c in &creds {
                let name = c["name"].as_str().unwrap_or("?");
                let tier = c["tier"].as_i64().unwrap_or(0);
                lines.push(format!("  {name} (Tier {tier})"));
            }
            lines.join("\n")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_delete_credential(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    match vault::try_load_vault() {
        Some(v) => {
            if v.delete_credential(name) {
                format!("Deleted credential '{name}'.")
            } else {
                format!("Credential '{name}' not found.")
            }
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_validate(args: &serde_json::Map<String, Value>) -> String {
    let fix = args.get("fix").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut lines = Vec::new();

    // Validate system policy
    lines.push("--- System policy ---".to_string());
    let path = policy_path();
    match crate::policy::load_policy_config(&path) {
        Ok(mut config) => {
            if fix {
                let result = crate::policy::fix_policy(&mut config);
                if result.rules_removed.is_empty() && result.rules_modified.is_empty() {
                    lines.push(format!(
                        "No auto-fixable issues. {} rules.",
                        config.rules.len()
                    ));
                } else {
                    lines.push(format!("Fixed: {}", result.description));
                    save_policy(&config);
                    auto_sign();
                }
            }
            let diagnostics = crate::policy::validate_policy(&config);
            if diagnostics.is_empty() {
                lines.push(format!("Valid: {} rules.", config.rules.len()));
            } else {
                for d in &diagnostics {
                    let sev = if d.severity == crate::policy::DiagnosticSeverity::Error {
                        "ERROR"
                    } else {
                        "WARN"
                    };
                    lines.push(format!("  {sev} [{}]: {}", d.rule_name, d.error));
                }
            }
        }
        Err(e) => lines.push(format!("Cannot load system policy: {e}")),
    }

    // Validate user rules
    let user_rules = load_rules_raw();
    if !user_rules.is_empty() {
        lines.push("\n--- User rules ---".to_string());
        let user_config = PolicyConfig {
            version: 1,
            default_action: Decision::Allow,
            rules: user_rules,
        };
        let diagnostics = crate::policy::validate_policy(&user_config);
        if diagnostics.is_empty() {
            lines.push(format!("Valid: {} rules.", user_config.rules.len()));
        } else {
            for d in &diagnostics {
                let sev = if d.severity == crate::policy::DiagnosticSeverity::Error {
                    "ERROR"
                } else {
                    "WARN"
                };
                lines.push(format!("  {sev} [{}]: {}", d.rule_name, d.error));
            }
        }
    }

    lines.join("\n")
}

fn handle_test(args: &serde_json::Map<String, Value>) -> String {
    let tool_name = args.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
    let tool_input = args
        .get("tool_input")
        .cloned()
        .unwrap_or(serde_json::Value::Object(Default::default()));

    let policy = crate::policy::load_merged_policy(&policy_path(), &rules_path());
    let v = vault::try_load_vault();
    let call = crate::policy::ToolCall {
        tool_name: tool_name.to_string(),
        parameters: tool_input,
    };
    let result = crate::policy::evaluate(&call, &policy, v.as_ref());
    let mut lines = vec![format!("Decision: {:?}", result.decision)];
    if let Some(rule) = &result.matched_rule {
        lines.push(format!("Matched rule: {rule}"));
    } else {
        lines.push("Matched rule: (none — default action)".into());
    }
    if let Some(reason) = &result.reason {
        lines.push(format!("Reason: {reason}"));
    }
    lines.push(format!("Eval time: {}us", result.evaluation_time_us));
    lines.join("\n")
}

fn handle_reorder_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let position = args.get("position").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if position == 0 {
        return "Position must be >= 1".into();
    }

    // Check if it's a system/locked rule
    let system_config = load_policy_raw();
    if system_config
        .rules
        .iter()
        .any(|r| r.name == name && r.locked)
    {
        return format!("Cannot reorder rule '{name}': rule is locked (self-protection).");
    }
    if system_config.rules.iter().any(|r| r.name == name) {
        return format!("Cannot reorder system rule '{name}'. Only user rules can be reordered.");
    }

    // Reorder within user rules
    let mut user_rules = load_rules_raw();
    let idx = user_rules.iter().position(|r| r.name == name);
    match idx {
        None => format!("Rule '{name}' not found in user rules."),
        Some(old_idx) => {
            let rule = user_rules.remove(old_idx);
            let new_idx = (position - 1).min(user_rules.len());
            user_rules.insert(new_idx, rule);
            save_rules(&user_rules);
            auto_sign();
            format!(
                "Moved user rule '{name}' to position {} (within user rules).",
                new_idx + 1
            )
        }
    }
}

fn handle_edit_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    // Check if it's a system/locked rule
    let system_config = load_policy_raw();
    if system_config
        .rules
        .iter()
        .any(|r| r.name == name && r.locked)
    {
        return format!("Cannot edit rule '{name}': rule is locked (self-protection).");
    }
    if system_config.rules.iter().any(|r| r.name == name) {
        return format!("Cannot edit system rule '{name}'. Add an overriding user rule instead.");
    }

    // Edit in user rules
    let mut user_rules = load_rules_raw();
    let rule = user_rules.iter_mut().find(|r| r.name == name);
    match rule {
        None => format!("Rule '{name}' not found in user rules."),
        Some(rule) => {
            let mut changes = Vec::new();
            if let Some(action_str) = args.get("action").and_then(|v| v.as_str()) {
                match action_str.to_uppercase().as_str() {
                    "ALLOW" => {
                        rule.action = Decision::Allow;
                        changes.push("action");
                    }
                    "DENY" => {
                        rule.action = Decision::Deny;
                        changes.push("action");
                    }
                    "ASK" => {
                        rule.action = Decision::Ask;
                        changes.push("action");
                    }
                    "GATE" => {
                        rule.action = Decision::Gate;
                        changes.push("action");
                    }
                    "ENSURE" => {
                        rule.action = Decision::Ensure;
                        changes.push("action");
                    }
                    _ => return format!("Invalid action '{action_str}'."),
                }
            }
            if let Some(reason) = args.get("reason").and_then(|v| v.as_str()) {
                rule.reason = Some(reason.into());
                changes.push("reason");
            }
            if let Some(pattern) = args.get("tool_pattern").and_then(|v| v.as_str()) {
                rule.tool_pattern = pattern.into();
                changes.push("tool_pattern");
            }
            if let Some(conds) = args.get("conditions").and_then(|v| v.as_array()) {
                rule.conditions = conds
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                changes.push("conditions");
            }
            if let Some(gc) = args.get("gate").and_then(|v| v.as_object()) {
                let requires_prior = gc
                    .get("requires_prior")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if requires_prior.is_empty() {
                    return "gate.requires_prior cannot be empty".into();
                }
                let within = gc.get("within").and_then(|v| v.as_u64()).unwrap_or(50) as u32;
                rule.gate = Some(GateConfig {
                    requires_prior,
                    within,
                });
                changes.push("gate");
            }
            if let Some(ec) = args.get("ensure").and_then(|v| v.as_object()) {
                let check = ec
                    .get("check")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Err(err) = crate::policy::validate_ensure_check_name(&check) {
                    return format!("Invalid ensure.check: {err}");
                }
                let timeout = ec.get("timeout").and_then(|v| v.as_u64()).unwrap_or(5) as u32;
                let message = ec
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                rule.ensure = Some(EnsureConfig {
                    check,
                    timeout,
                    message,
                });
                changes.push("ensure");
            }
            save_rules(&user_rules);
            auto_sign();
            format!("Updated user rule '{name}': changed {}", changes.join(", "))
        }
    }
}

fn handle_sign_policy() -> String {
    match vault::try_load_vault() {
        Some(v) => {
            let mut results = Vec::new();
            match vault::sign_policy(v.session_key(), &policy_path()) {
                Ok(_) => results.push("System policy signed.".to_string()),
                Err(e) => results.push(format!("Error signing policy: {e}")),
            }
            if rules_path().exists() {
                match vault::sign_policy(v.session_key(), &rules_path()) {
                    Ok(_) => results.push("User rules signed.".to_string()),
                    Err(e) => results.push(format!("Error signing rules: {e}")),
                }
            }
            results.join(" ")
        }
        None => "Vault not set up or locked (needed for signing key).".into(),
    }
}

fn handle_reset_session() -> String {
    // Session reset is sensitive — it clears spending counters, which could
    // allow an agent to bypass spending limits by resetting before each purchase.
    // This should only be done via CLI (signet-eval reset-session) where the
    // user is directly present.
    "Session reset is only available via CLI (signet-eval reset-session) to prevent spending limit bypass. An AI agent could otherwise reset counters before each purchase.".into()
}

fn handle_use_credential(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let domain = args.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let purpose = args.get("purpose").and_then(|v| v.as_str()).unwrap_or("");

    match vault::try_load_vault() {
        Some(v) => {
            match v.request_capability(name, domain, amount, purpose) {
                Ok(value) => {
                    // Mask the credential in the response — show last 4 chars only
                    let masked = if value.len() > 4 {
                        format!(
                            "{}...{}",
                            "*".repeat(value.len() - 4),
                            &value[value.len() - 4..]
                        )
                    } else {
                        "*".repeat(value.len())
                    };
                    format!("Credential '{name}' released (masked: {masked}). Domain: {domain}, Amount: ${amount:.2}, Purpose: {purpose}")
                }
                Err(e) => format!("Credential request denied: {e}"),
            }
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_condition_help() -> String {
    r#"Available condition functions:

  contains(parameters, 'text')        — serialized tool input contains string
  contains_word(parameters, 'word')   — word-boundary match (prevents 'skilled' matching 'kill')
  any_of(parameters, 'a', 'b', ...)   — any of the strings present in tool input
  param_eq(field, 'value')             — parameter field equals value
  param_ne(field, 'value')             — parameter field not equal to value
  param_gt(field, number)              — parameter field > number
  param_lt(field, number)              — parameter field < number
  param_contains(field, 'substr')      — parameter field contains substring
  matches(field, 'regex')              — parameter field matches regex pattern
  has_credential('name')               — credential exists in vault
  spend_gt('category', limit)          — session spend > limit
  spend_plus_amount_gt('cat', field, limit) — session spend + param > limit
  not(condition)                       — negate any condition
  or(cond1 || cond2)                   — either condition is true
  true / false                         — literal boolean

Multiple conditions on a rule are AND'd together. Use or() for OR logic.

Examples:
  Block rm:              contains(parameters, 'rm ')
  Books limit $200:      spend_plus_amount_gt('books', amount, 200)
  Only allow JSON:       not(param_eq(format, 'json'))
  Block large purchases: param_gt(amount, 500)
  Block IP access:       matches(host, '^\d+\.\d+\.\d+\.\d+$')

Action Types:
  ALLOW   — permit the tool call
  DENY    — block the tool call
  ASK     — require user confirmation
  GATE    — require a prior command in the action log before allowing
  ENSURE  — run a validation script from ~/.signet/checks/ before allowing

Gate config (required when action=GATE):
  gate.requires_prior: string to search for in recent allowed actions
  gate.within: number of recent entries to search (default 50, max 500)
  No vault = deny. Only entries with decision=allow are searched.

Ensure config (required when action=ENSURE):
  ensure.check: script name in ~/.signet/checks/ (simple filename, no paths)
  ensure.timeout: max seconds to wait (default 5, max 30)
  ensure.message: message shown to agent on failure
  Exit 0 = allow, non-zero = deny. Script stderr is captured and relayed.
  Note: ensure scripts add latency. Use gate when a log check suffices."#
        .into()
}

// === Preflight Handlers ===

fn parse_soft_constraints(
    args: &serde_json::Map<String, Value>,
) -> Result<Vec<vault::SoftConstraint>, String> {
    let arr = args
        .get("constraints")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Missing 'constraints' array".to_string())?;
    let mut constraints = Vec::new();
    for item in arr {
        let obj = item
            .as_object()
            .ok_or("Each constraint must be an object")?;
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tool_pattern = obj
            .get("tool_pattern")
            .and_then(|v| v.as_str())
            .unwrap_or(".*")
            .to_string();
        let conditions: Vec<String> = obj
            .get("conditions")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let action = obj
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("DENY")
            .to_string();
        let reason = obj
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let alternative = obj
            .get("alternative")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Validate
        if name.is_empty() {
            return Err("Constraint name is required".into());
        }
        if action != "DENY" && action != "ASK" {
            return Err(format!(
                "Constraint '{name}' action must be DENY or ASK, got '{action}'"
            ));
        }
        if alternative.trim().is_empty() {
            return Err(format!(
                "Constraint '{name}' requires a non-empty alternative (plan B)"
            ));
        }
        if regex::Regex::new(&tool_pattern).is_err() {
            return Err(format!(
                "Constraint '{name}' has invalid regex: {tool_pattern}"
            ));
        }

        constraints.push(vault::SoftConstraint {
            name,
            tool_pattern,
            conditions,
            action,
            reason,
            alternative,
        });
    }
    Ok(constraints)
}

fn handle_preflight_submit(args: &serde_json::Map<String, Value>) -> String {
    let task = args
        .get("task")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let risks: Vec<String> = args
        .get("risks")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let lockout_minutes = args
        .get("lockout_minutes")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);

    if task.is_empty() {
        return "Task description is required.".into();
    }
    if lockout_minutes < 5 {
        return "Lockout must be at least 5 minutes.".into();
    }
    if lockout_minutes > 480 {
        return "Lockout cannot exceed 480 minutes (8 hours).".into();
    }

    let constraints = match parse_soft_constraints(args) {
        Ok(c) => c,
        Err(e) => return format!("Validation error: {e}"),
    };

    // Advisory: reject overly broad constraints unless force=true
    let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    if !force {
        let broad: Vec<&str> = constraints
            .iter()
            .filter(|c| {
                let pat = c.tool_pattern.trim();
                (pat == ".*" || pat == ".+" || pat == "^.*$" || pat == "^.+$")
                    && c.conditions.is_empty()
            })
            .map(|c| c.name.as_str())
            .collect();
        if !broad.is_empty() {
            return format!(
                "REJECTED — overly broad constraint(s): {}\n\n\
                 These constraints match ALL tool calls with no conditions, which will block \
                 everything including your own MCP tools. You will lock yourself out.\n\n\
                 Fix: narrow the tool_pattern (e.g. \"^Bash$\") or add conditions \
                 (e.g. \"contains(parameters, 'rm ')\").\n\n\
                 If you genuinely need a universal constraint, re-submit with force: true.",
                broad.join(", ")
            );
        }
    }

    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .or_else(vault::current_session_id);

    match vault::try_load_vault() {
        Some(v) => {
            if v.is_preflight_locked() {
                if let Some(active) = v.active_preflight() {
                    return format!("Active preflight is locked until timestamp {}. Cannot submit a new one until lockout expires or user runs 'signet-eval preflight-override'.", active.lockout_until);
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let preflight = vault::Preflight {
                id: vault::random_hex_id(),
                task,
                risks,
                constraints,
                submitted_at: now,
                lockout_until: now + lockout_minutes * 60,
                violation_count: 0,
                escalated: false,
                session_id: session_id.clone(),
            };
            match v.store_preflight(&preflight) {
                Ok(_) => {
                    let scope = match &preflight.session_id {
                        Some(sid) => format!(" (session: {})", sid),
                        None => " (global)".into(),
                    };
                    format!(
                        "Preflight filed. ID: {}.{} Locked for {} minutes ({} constraints active).",
                        preflight.id,
                        scope,
                        lockout_minutes,
                        preflight.constraints.len()
                    )
                }
                Err(e) => format!("Failed to store preflight: {e}"),
            }
        }
        None => "Vault not set up or locked. Preflight requires vault for HMAC signing.".into(),
    }
}

fn handle_preflight_active() -> String {
    match vault::try_load_vault() {
        Some(v) => match v.active_preflight() {
            Some(pf) => {
                let mut lines = vec![
                    format!("Active preflight: {}", pf.id),
                    format!("Task: {}", pf.task),
                    format!("Risks: {}", pf.risks.join("; ")),
                    format!("Constraints: {}", pf.constraints.len()),
                    format!("Violations: {}", pf.violation_count),
                    format!("Escalated: {}", pf.escalated),
                    format!("Lockout until: {}", pf.lockout_until),
                ];
                match &pf.session_id {
                    Some(sid) => lines.push(format!("Session: {}", sid)),
                    None => lines.push("Session: global".into()),
                }
                for (i, c) in pf.constraints.iter().enumerate() {
                    lines.push(format!(
                        "  {}. [{}] {} — {}",
                        i + 1,
                        c.action,
                        c.name,
                        c.reason
                    ));
                    lines.push(format!("     Plan B: {}", c.alternative));
                }
                lines.join("\n")
            }
            None => "No active preflight.".into(),
        },
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_preflight_history(args: &serde_json::Map<String, Value>) -> String {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as u32;
    match vault::try_load_vault() {
        Some(v) => {
            let history = v.preflight_history(limit);
            if history.is_empty() {
                return "No preflight history.".into();
            }
            let mut lines = vec![format!("Preflight history ({}):", history.len())];
            for h in &history {
                let id = h["id"].as_str().unwrap_or("?");
                let task = h["task"].as_str().unwrap_or("?");
                let violations = h["violation_count"].as_u64().unwrap_or(0);
                let escalated = h["escalated"].as_bool().unwrap_or(false);
                let active = h["active"].as_bool().unwrap_or(false);
                let status = if active {
                    "ACTIVE"
                } else if escalated {
                    "ESCALATED"
                } else {
                    "completed"
                };
                let session = h["session_id"].as_str().unwrap_or("global");
                lines.push(format!(
                    "  {} [{}] {} (violations: {}, session: {})",
                    &id[..8.min(id.len())],
                    status,
                    task,
                    violations,
                    session
                ));
            }
            lines.join("\n")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_preflight_violations(args: &serde_json::Map<String, Value>) -> String {
    match vault::try_load_vault() {
        Some(v) => {
            let preflight_id = args.get("preflight_id").and_then(|v| v.as_str());
            let id = match preflight_id {
                Some(id) => id.to_string(),
                None => match v.active_preflight() {
                    Some(pf) => pf.id,
                    None => return "No active preflight and no preflight_id specified.".into(),
                },
            };
            let violations = v.preflight_violations(&id);
            if violations.is_empty() {
                return format!("No violations for preflight {}.", &id[..8.min(id.len())]);
            }
            let mut lines = vec![format!(
                "Violations for {} ({}):",
                &id[..8.min(id.len())],
                violations.len()
            )];
            for viol in &violations {
                lines.push(format!(
                    "  [{}] {} via {} — Plan B: {}",
                    viol.constraint_name, viol.tool_name, viol.parameters_summary, viol.alternative
                ));
            }
            lines.join("\n")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_preflight_test(args: &serde_json::Map<String, Value>) -> String {
    match parse_soft_constraints(args) {
        Ok(constraints) => {
            let mut lines = vec![format!(
                "Validation passed: {} constraints OK.",
                constraints.len()
            )];
            for (i, c) in constraints.iter().enumerate() {
                lines.push(format!(
                    "  {}. [{}] {} — plan B: {}",
                    i + 1,
                    c.action,
                    c.name,
                    c.alternative
                ));
            }
            lines.join("\n")
        }
        Err(e) => format!("Validation failed: {e}"),
    }
}

/// Run the MCP management server on stdio.
pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let server = SignetMcpServer;
    let service = rmcp::serve_server(server, rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
