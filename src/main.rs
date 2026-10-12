mod claude_install;
mod hook;
mod integration;
mod policy;
mod redaction;
mod vault;

#[cfg(feature = "mcp")]
mod mcp_proxy;
#[cfg(feature = "mcp")]
mod mcp_server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "signet-eval",
    version,
    about = "Deterministic policy enforcement for AI agent tool calls"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to system policy file
    #[arg(long, default_value = "~/.signet/policy.yaml")]
    policy_path: String,

    /// Path to user rules file
    #[arg(long, default_value = "~/.signet/rules.yaml")]
    rules_path: String,

    /// Hook protocol adapter: claude, codex, codex-permission, antigravity, or opencode
    #[arg(long, default_value = "claude")]
    adapter: String,
}

#[derive(Subcommand)]
enum Command {
    /// Versioned function-hook capability and delegated-intent protocol (JSON stdin/stdout)
    Integration {
        #[command(subcommand)]
        action: integration::Action,
    },
    /// Evaluate a tool call from stdin (default, hook mode)
    Eval,
    /// Initialize default policy file
    Init,
    /// Create encrypted vault with passphrase
    Setup,
    /// Show vault status and recent actions
    Status,
    /// Store a Tier 3 credential
    Store {
        /// Credential name
        name: String,
        /// Credential value
        value: String,
    },
    /// Show current policy rules
    Rules,
    /// Show recent actions from the vault ledger
    Log {
        /// Number of entries to show
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Test a policy against sample JSON input
    Test {
        /// JSON tool call, e.g. '{"tool_name":"Bash","tool_input":{"command":"rm foo"}}'
        json: String,
    },
    /// Delete a credential from the vault
    Delete {
        /// Credential name to delete
        name: String,
    },
    /// Reset session — clears spending counters for the current session
    ResetSession,
    /// Sign the policy file (HMAC integrity protection)
    Sign,
    /// Unlock vault and refresh session key
    Unlock,
    /// Validate the policy file
    Validate {
        /// Auto-fix clampable issues (numeric ranges, locked:false removal)
        #[arg(long)]
        fix: bool,
        /// Show what --fix would change without writing (requires --fix)
        #[arg(long, requires = "fix")]
        dry_run: bool,
    },
    /// Run MCP management server (conversational policy editing)
    #[cfg(feature = "mcp")]
    Serve,
    /// Run MCP proxy (wraps upstream servers with policy enforcement)
    #[cfg(feature = "mcp")]
    Proxy,
    /// Show active preflight status
    PreflightStatus,
    /// Override (end) an active preflight early (requires vault passphrase)
    PreflightOverride,
    /// Pause policy enforcement for N minutes (self-protection still active)
    Pause {
        /// Duration in minutes (0 = indefinite, requires --session)
        #[arg(default_value = "10")]
        minutes: u32,
        /// Pause only this rule (by name). Without this, all non-locked rules are paused.
        #[arg(long)]
        rule: Option<String>,
        /// Only pause for this session (requires SIGNET_SESSION env var in the target terminal)
        #[arg(long)]
        session: Option<String>,
    },
    /// Resume policy enforcement (end pause early)
    Resume {
        /// Resume only this rule. Without this, resumes the global pause.
        #[arg(long)]
        rule: Option<String>,
        /// Resume only for this session.
        #[arg(long)]
        session: Option<String>,
    },
    /// Fully disable policy enforcement (bypasses everything including self-protection)
    Disable {
        /// Only disable for this session (requires SIGNET_SESSION env var in the target terminal)
        #[arg(long)]
        session: Option<String>,
    },
    /// Re-enable policy enforcement after disable
    Enable {
        /// Re-enable only for this session
        #[arg(long)]
        session: Option<String>,
    },
    /// Show recent inject rule fires
    Injections {
        /// Max entries to show
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Force-fire a single inject rule for testing (ignores probability/cooldown/cap)
    InjectTest {
        /// Inject rule name to fire
        rule: String,
    },
}

fn expand_home(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

fn run() -> i32 {
    let cli = Cli::parse();
    let policy_path = expand_home(&cli.policy_path);
    let rules_path = expand_home(&cli.rules_path);
    let adapter = match hook::HookAdapter::parse(&cli.adapter) {
        Ok(adapter) => adapter,
        Err(e) => {
            eprintln!("Error: {e}");
            return 2;
        }
    };

    match cli.command {
        Some(Command::Integration { action }) => {
            integration::run(action, &policy_path, &rules_path)
        }
        None | Some(Command::Eval) => {
            let v = vault::try_load_vault();
            // If vault exists, verify HMAC for both policy files — tampered files fall back to safe defaults.
            // Without vault, files are loaded as-is (no cryptographic verification).
            // HMAC (requires vault setup) is the real integrity guarantee.
            if let Some(ref vault) = v {
                if !vault::verify_policy_integrity(vault.session_key(), &policy_path) {
                    eprintln!("WARNING: Policy integrity check failed. Using safe defaults.");
                    let compiled = policy::default_policy();
                    return hook::run_hook_with_adapter(&compiled, Some(vault), adapter);
                }
                // Verify rules.yaml HMAC if the file exists
                if rules_path.exists()
                    && !vault::verify_policy_integrity(vault.session_key(), &rules_path)
                {
                    eprintln!("WARNING: User rules integrity check failed. Using safe defaults.");
                    let compiled = policy::default_policy();
                    return hook::run_hook_with_adapter(&compiled, Some(vault), adapter);
                }
            }
            let compiled = policy::load_merged_policy(&policy_path, &rules_path);
            hook::run_hook_with_adapter(&compiled, v.as_ref(), adapter)
        }
        Some(Command::Init) => {
            let mut rules = policy::self_protection_rules();
            rules.extend(policy::system_default_rules());
            let config = policy::PolicyConfig {
                version: 1,
                default_action: policy::Decision::Allow,
                rules,
            };
            let yaml = serde_yaml::to_string(&config).unwrap();
            if let Some(parent) = policy_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            // Write system policy
            match std::fs::write(&policy_path, &yaml) {
                Ok(_) => {
                    println!("System policy written to {}", policy_path.display());
                }
                Err(e) => {
                    eprintln!("Error writing policy: {e}");
                    return 1;
                }
            }
            // Write sample.yaml (always overwritten — it's a reference, not user data)
            let sample_path = policy_path.parent().unwrap().join("sample.yaml");
            match std::fs::write(&sample_path, policy::sample_yaml()) {
                Ok(_) => println!("Sample rules written to {}", sample_path.display()),
                Err(e) => eprintln!("Warning: could not write sample.yaml: {e}"),
            }
            // Auto-sign if vault exists
            if let Some(v) = vault::try_load_vault() {
                match vault::sign_policy(v.session_key(), &policy_path) {
                    Ok(_) => println!("Policy signed (HMAC verified on every eval)."),
                    Err(e) => eprintln!("Warning: could not sign policy: {e}"),
                }
            } else {
                eprintln!(
                    "Warning: no vault. Run 'signet-eval setup' to enable HMAC verification."
                );
            }
            // Hint about user rules (don't touch rules.yaml)
            if !rules_path.exists() {
                println!(
                    "Hint: create {} for custom rules (see sample.yaml for examples).",
                    rules_path.display()
                );
            } else {
                println!("User rules preserved at {}", rules_path.display());
            }
            0
        }
        Some(Command::Setup) => {
            if vault::vault_exists() {
                eprintln!("Vault already exists. Delete ~/.signet/vault.meta to reset.");
                1
            } else {
                let pass =
                    rpassword::prompt_password("Create vault passphrase: ").unwrap_or_default();
                let confirm =
                    rpassword::prompt_password("Confirm passphrase: ").unwrap_or_default();
                if pass != confirm {
                    eprintln!("Passphrases don't match.");
                    1
                } else if pass.len() < 8 {
                    eprintln!("Passphrase must be at least 8 characters.");
                    1
                } else {
                    match vault::setup_vault(&pass) {
                        Ok(_) => {
                            println!("Vault created. Session key cached.");
                            0
                        }
                        Err(e) => {
                            eprintln!("Error: {e}");
                            1
                        }
                    }
                }
            }
        }
        Some(Command::Status) => {
            // Enforcement overrides (shown regardless of vault state)
            let globally_disabled = vault::is_disabled_file();
            let disabled_sessions = vault::list_disabled_sessions();
            let globally_paused = vault::is_paused_file();
            let pauses = vault::list_pauses();

            if globally_disabled {
                println!("Enforcement: DISABLED (global)");
            } else if globally_paused {
                let until = vault::pause_until_file();
                println!("Enforcement: PAUSED (until ts {until})");
            } else {
                println!("Enforcement: active");
            }

            if !disabled_sessions.is_empty() {
                println!("\nDisabled sessions:");
                for s in &disabled_sessions {
                    println!("  {s}");
                }
            }

            if !pauses.is_empty() {
                println!("\nActive pauses:");
                for p in &pauses {
                    let rule_label = p.rule.as_deref().unwrap_or("(all non-locked)");
                    let session_label = p.session.as_deref().unwrap_or("(all sessions)");
                    println!(
                        "  rule: {rule_label}  session: {session_label}  until: ts {}",
                        p.until
                    );
                }
            }

            match vault::try_load_vault() {
                Some(v) => {
                    let spend = v.session_spend("");
                    let creds = v.list_credentials();
                    let actions = v.recent_actions(10);
                    println!("\nVault: unlocked");
                    println!("Credentials: {}", creds.len());
                    if spend > 0.0 {
                        println!("Session spend: ${spend:.2}");
                    }
                    if !actions.is_empty() {
                        println!("\nRecent actions:");
                        for a in &actions {
                            let tool = a["tool"].as_str().unwrap_or("?");
                            let dec = a["decision"].as_str().unwrap_or("?");
                            let amt = a["amount"].as_f64().unwrap_or(0.0);
                            let cat = a["category"].as_str().unwrap_or("");
                            if amt > 0.0 {
                                println!("  {tool} [{cat}] ${amt:.2} -> {dec}");
                            } else {
                                println!("  {tool} -> {dec}");
                            }
                        }
                    }
                    0
                }
                None => {
                    println!("\nVault: not set up (run: signet-eval setup)");
                    0
                }
            }
        }
        Some(Command::Store { name, value }) => match vault::try_load_vault() {
            Some(v) => {
                v.store_credential(&name, &value, 3);
                println!("Stored '{name}' (Tier 3 compartment-encrypted)");
                0
            }
            None => {
                eprintln!("Vault not set up or locked.");
                1
            }
        },
        Some(Command::Rules) => {
            let system_config = match policy::load_effective_policy_config(&policy_path) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Error loading system policy: {e}");
                    return 1;
                }
            };
            let user_rules = policy::load_rules(&rules_path);
            let merged = policy::merge_rules(&system_config.rules, &user_rules);
            // Build a set of user rule names for labeling
            let user_names: std::collections::HashSet<&str> =
                user_rules.iter().map(|r| r.name.as_str()).collect();

            println!(
                "System policy: {} (v{})",
                policy_path.display(),
                system_config.version
            );
            if !user_rules.is_empty() {
                println!(
                    "User rules: {} ({} rules)",
                    rules_path.display(),
                    user_rules.len()
                );
            }
            println!("Default action: {:?}", system_config.default_action);
            println!("Rules: {} (eval order)\n", merged.len());
            for rule in &merged {
                let action = format!("{:?}", rule.action).to_uppercase();
                let source = if rule.locked {
                    " [LOCKED]"
                } else if user_names.contains(rule.name.as_str()) {
                    " [USER]"
                } else {
                    " [SYSTEM]"
                };
                println!("  {} [{}]{}", rule.name, action, source);
                println!("    tool: {}", rule.tool_pattern);
                for cond in &rule.conditions {
                    println!("    when: {cond}");
                }
                if let Some(reason) = &rule.reason {
                    println!("    reason: {reason}");
                }
                println!();
            }
            0
        }
        Some(Command::Log { limit }) => match vault::try_load_vault() {
            Some(v) => {
                let actions = v.recent_actions(limit);
                if actions.is_empty() {
                    println!("No actions recorded.");
                } else {
                    println!(
                        "{:<24} {:<12} {:<10} {:>8} {}",
                        "TIMESTAMP", "TOOL", "CATEGORY", "AMOUNT", "DECISION"
                    );
                    println!("{}", "-".repeat(70));
                    for a in &actions {
                        let ts = a["timestamp"].as_f64().unwrap_or(0.0);
                        let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
                            .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| format!("{ts:.0}"));
                        let tool = a["tool"].as_str().unwrap_or("?");
                        let cat = a["category"].as_str().unwrap_or("");
                        let amt = a["amount"].as_f64().unwrap_or(0.0);
                        let dec = a["decision"].as_str().unwrap_or("?");
                        let amt_str = if amt > 0.0 {
                            format!("${amt:.2}")
                        } else {
                            "-".into()
                        };
                        println!("{dt:<24} {tool:<12} {cat:<10} {amt_str:>8} {dec}");
                    }
                }
                0
            }
            None => {
                eprintln!("Vault not set up or locked. Run: signet-eval setup");
                1
            }
        },
        Some(Command::Test { json }) => {
            let input: serde_json::Value = match serde_json::from_str(&json) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON: {e}");
                    std::process::exit(1);
                }
            };
            let compiled = policy::load_merged_policy(&policy_path, &rules_path);
            let v = vault::try_load_vault();
            let call = match hook::parse_tool_call_input(input, adapter) {
                Ok(call) => call,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            let result = policy::evaluate(&call, &compiled, v.as_ref());
            println!("Decision:     {:?}", result.decision);
            if let Some(rule) = &result.matched_rule {
                println!("Matched rule: {rule}");
            } else {
                println!("Matched rule: (none — default action)");
            }
            if let Some(reason) = &result.reason {
                println!("Reason:       {reason}");
            }
            println!("Eval time:    {}us", result.evaluation_time_us);
            0
        }
        Some(Command::Delete { name }) => match vault::try_load_vault() {
            Some(v) => {
                if v.delete_credential(&name) {
                    println!("Deleted credential '{name}'.");
                    0
                } else {
                    eprintln!("Credential '{name}' not found.");
                    1
                }
            }
            None => {
                eprintln!("Vault not set up or locked.");
                1
            }
        },
        Some(Command::ResetSession) => match vault::try_load_vault() {
            Some(mut v) => {
                v.reset_session();
                println!("Session reset. Spending counters cleared.");
                0
            }
            None => {
                eprintln!("Vault not set up or locked.");
                1
            }
        },
        Some(Command::Sign) => match vault::try_load_vault() {
            Some(v) => {
                let mut ok = true;
                match vault::sign_policy(v.session_key(), &policy_path) {
                    Ok(_) => println!(
                        "Policy signed: {}",
                        policy_path.with_extension("hmac").display()
                    ),
                    Err(e) => {
                        eprintln!("Error signing policy: {e}");
                        ok = false;
                    }
                }
                if rules_path.exists() {
                    match vault::sign_policy(v.session_key(), &rules_path) {
                        Ok(_) => println!(
                            "Rules signed: {}",
                            rules_path.with_extension("hmac").display()
                        ),
                        Err(e) => {
                            eprintln!("Error signing rules: {e}");
                            ok = false;
                        }
                    }
                }
                let inject_path = policy::inject_commands_path();
                if inject_path.exists() {
                    match vault::sign_policy(v.session_key(), &inject_path) {
                        Ok(_) => println!(
                            "Inject allowlist signed: {}",
                            inject_path.with_extension("hmac").display()
                        ),
                        Err(e) => {
                            eprintln!("Error signing inject allowlist: {e}");
                            ok = false;
                        }
                    }
                }
                if ok {
                    0
                } else {
                    1
                }
            }
            None => {
                eprintln!("Vault not set up or locked (needed for signing key).");
                1
            }
        },
        Some(Command::Unlock) => {
            if !vault::vault_exists() {
                eprintln!("No vault found. Run: signet-eval setup");
                1
            } else {
                let pass = rpassword::prompt_password("Vault passphrase: ").unwrap_or_default();
                match vault::unlock_vault(&pass) {
                    Ok(_) => {
                        println!("Vault unlocked. Session key refreshed.");
                        0
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        1
                    }
                }
            }
        }
        Some(Command::Validate { fix, dry_run }) => {
            let mut exit_code = 0;
            // Validate system policy
            println!("--- System policy: {} ---", policy_path.display());
            match policy::load_policy_config(&policy_path) {
                Ok(mut config) => {
                    if fix {
                        let result = policy::fix_system_policy(&mut config);
                        if result.rules_removed.is_empty() && result.rules_modified.is_empty() {
                            println!("No auto-fixable issues found.");
                        } else {
                            println!("{}", result.description);
                            if dry_run {
                                println!("(dry-run: no changes written)");
                            } else {
                                let yaml = serde_yaml::to_string(&config).unwrap();
                                match std::fs::write(&policy_path, &yaml) {
                                    Ok(_) => {
                                        println!("Policy written to {}", policy_path.display());
                                        if let Some(v) = vault::try_load_vault() {
                                            match vault::sign_policy(v.session_key(), &policy_path)
                                            {
                                                Ok(_) => println!("Policy re-signed."),
                                                Err(e) => {
                                                    eprintln!("Warning: could not re-sign: {e}")
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("ERROR writing policy: {e}");
                                        exit_code = 1;
                                    }
                                }
                            }
                        }
                    } else {
                        let diagnostics = policy::validate_system_policy(&config);
                        let errors: Vec<_> = diagnostics
                            .iter()
                            .filter(|d| d.severity == policy::DiagnosticSeverity::Error)
                            .collect();
                        let warnings: Vec<_> = diagnostics
                            .iter()
                            .filter(|d| d.severity == policy::DiagnosticSeverity::Warning)
                            .collect();

                        if errors.is_empty() && warnings.is_empty() {
                            println!("Policy valid: {} rules", config.rules.len());
                        } else {
                            for e in &errors {
                                eprintln!("ERROR [{}]: {}", e.rule_name, e.error);
                                eprintln!("  Fix: {}", e.fix_hint);
                            }
                            for w in &warnings {
                                eprintln!("WARN  [{}]: {}", w.rule_name, w.error);
                                eprintln!("  Fix: {}", w.fix_hint);
                            }
                            if !errors.is_empty() {
                                exit_code = 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    exit_code = 1;
                }
            }
            // Validate user rules (if file exists)
            if rules_path.exists() {
                println!("\n--- User rules: {} ---", rules_path.display());
                let user_rules = policy::load_rules(&rules_path);
                if user_rules.is_empty() {
                    println!("No user rules (or parse error).");
                } else {
                    let user_config = policy::PolicyConfig {
                        version: 1,
                        default_action: policy::Decision::Allow,
                        rules: user_rules,
                    };
                    let diagnostics = policy::validate_policy(&user_config);
                    let errors: Vec<_> = diagnostics
                        .iter()
                        .filter(|d| d.severity == policy::DiagnosticSeverity::Error)
                        .collect();
                    let warnings: Vec<_> = diagnostics
                        .iter()
                        .filter(|d| d.severity == policy::DiagnosticSeverity::Warning)
                        .collect();
                    if errors.is_empty() && warnings.is_empty() {
                        println!("User rules valid: {} rules", user_config.rules.len());
                    } else {
                        for e in &errors {
                            eprintln!("ERROR [{}]: {}", e.rule_name, e.error);
                            eprintln!("  Fix: {}", e.fix_hint);
                        }
                        for w in &warnings {
                            eprintln!("WARN  [{}]: {}", w.rule_name, w.error);
                            eprintln!("  Fix: {}", w.fix_hint);
                        }
                        if !errors.is_empty() {
                            exit_code = 1;
                        }
                    }
                }
            }
            exit_code
        }
        #[cfg(feature = "mcp")]
        Some(Command::Serve) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            match rt.block_on(mcp_server::run_server()) {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("MCP server error: {e}");
                    1
                }
            }
        }
        #[cfg(feature = "mcp")]
        Some(Command::Proxy) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            match rt.block_on(mcp_proxy::run_proxy()) {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("MCP proxy error: {e}");
                    1
                }
            }
        }
        Some(Command::PreflightStatus) => match vault::try_load_vault() {
            Some(v) => match v.active_preflight() {
                Some(pf) => {
                    println!("Active preflight: {}", pf.id);
                    println!("Task: {}", pf.task);
                    match &pf.session_id {
                        Some(sid) => println!("Session: {}", sid),
                        None => println!("Session: global"),
                    }
                    println!("Constraints: {}", pf.constraints.len());
                    println!("Violations: {}", pf.violation_count);
                    println!("Escalated: {}", pf.escalated);
                    println!("Lockout until: {}", pf.lockout_until);
                    let locked = v.is_preflight_locked();
                    println!("Locked: {locked}");
                    for (i, c) in pf.constraints.iter().enumerate() {
                        println!("  {}. [{}] {} — {}", i + 1, c.action, c.name, c.reason);
                        println!("     Plan B: {}", c.alternative);
                    }
                    0
                }
                None => {
                    println!("No active preflight.");
                    0
                }
            },
            None => {
                eprintln!("Vault not set up or locked.");
                1
            }
        },
        Some(Command::Pause {
            minutes,
            rule,
            session,
        }) => {
            // 0 = indefinite, only allowed with --session
            if minutes == 0 && session.is_none() {
                eprintln!("Indefinite pause (0) requires --session.");
                return 1;
            }
            if minutes > 60 {
                eprintln!("Pause duration must be 0-60 minutes (0 = indefinite with --session).");
                return 1;
            }
            let until = if minutes == 0 {
                u64::MAX
            } else {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + (minutes as u64 * 60)
            };

            if rule.is_some() || session.is_some() {
                // Per-rule and/or per-session pause via pauses.json
                // Validate rule name exists if specified
                if let Some(ref rule_name) = rule {
                    // Check merged policy (system + user rules) for rule name
                    let system_rules = policy::load_effective_policy_config(&policy_path)
                        .map(|c| c.rules)
                        .unwrap_or_default();
                    let user_rules = policy::load_rules(&rules_path);
                    let merged = policy::merge_rules(&system_rules, &user_rules);
                    if !merged.iter().any(|r| r.name == *rule_name) {
                        eprintln!("No rule named '{rule_name}'. Run 'signet-eval rules' to list.");
                        return 1;
                    }
                    if merged.iter().any(|r| r.name == *rule_name && r.locked) {
                        eprintln!("Cannot pause locked rule '{rule_name}'.");
                        return 1;
                    }
                }
                vault::add_pause(rule.as_deref(), until, session.as_deref());
                let duration = if minutes == 0 {
                    "indefinitely".to_string()
                } else {
                    format!("for {minutes} min")
                };
                match (&rule, &session) {
                    (Some(r), Some(s)) => println!("Rule '{r}' paused {duration} (session: {s})."),
                    (Some(r), None) => println!("Rule '{r}' paused {duration}."),
                    (None, Some(s)) => {
                        println!("All non-locked rules paused {duration} (session: {s}).")
                    }
                    (None, None) => unreachable!(),
                }
                println!("Self-protection rules remain active.");
                println!(
                    "Run 'signet-eval resume{}{}' to end early.",
                    rule.as_ref()
                        .map(|r| format!(" --rule {r}"))
                        .unwrap_or_default(),
                    session
                        .as_ref()
                        .map(|s| format!(" --session {s}"))
                        .unwrap_or_default(),
                );
            } else {
                // Global pause (existing behavior)
                if vault::is_paused_file() {
                    eprintln!(
                        "Already paused until timestamp {}.",
                        vault::pause_until_file()
                    );
                    return 1;
                }
                vault::set_pause_file(until);
                println!("Policy enforcement paused for {minutes} minutes.");
                println!("Self-protection rules remain active.");
                println!("Run 'signet-eval resume' to end early.");
            }
            0
        }
        Some(Command::Resume { rule, session }) => {
            if rule.is_some() || session.is_some() {
                // Per-rule/session resume
                vault::remove_pause(rule.as_deref(), session.as_deref());
                match (&rule, &session) {
                    (Some(r), Some(s)) => println!("Rule '{r}' resumed (session: {s})."),
                    (Some(r), None) => println!("Rule '{r}' resumed."),
                    (None, Some(s)) => println!("Session '{s}' pauses cleared."),
                    (None, None) => unreachable!(),
                }
            } else {
                // Global resume (existing behavior)
                if !vault::is_paused_file() {
                    // Also check if there are any json-based pauses to clear
                    let pauses = vault::list_pauses();
                    if pauses.is_empty() {
                        eprintln!("Not currently paused.");
                        return 0;
                    }
                    // Clear all pauses
                    for p in &pauses {
                        vault::remove_pause(p.rule.as_deref(), p.session.as_deref());
                    }
                    println!("All pauses cleared ({} entries).", pauses.len());
                    return 0;
                }
                vault::clear_pause_file();
                println!("Policy enforcement resumed.");
            }
            0
        }
        Some(Command::Disable { session }) => {
            if let Some(ref s) = session {
                vault::add_disabled_session(s);
                println!("Policy enforcement FULLY disabled for session '{s}'.");
                println!("ALL rules bypassed including self-protection for that session.");
                println!("Run 'signet-eval enable --session {s}' to re-enable.");
            } else {
                if vault::is_disabled_file() {
                    eprintln!("Already disabled.");
                    return 0;
                }
                vault::set_disabled_file();
                println!("Policy enforcement FULLY disabled.");
                println!("ALL rules bypassed including self-protection.");
                println!("Run 'signet-eval enable' to re-enable.");
            }
            0
        }
        Some(Command::Enable { session }) => {
            if let Some(ref s) = session {
                if vault::remove_disabled_session(s) {
                    println!("Policy enforcement re-enabled for session '{s}'.");
                } else {
                    eprintln!("Session '{s}' was not disabled.");
                }
            } else {
                // Clear all enforcement overrides in one shot
                let had_global = vault::is_disabled_file();
                let sessions = vault::list_disabled_sessions();

                if !had_global && sessions.is_empty() {
                    eprintln!("Not currently disabled.");
                    return 0;
                }

                if had_global {
                    vault::clear_disabled_file();
                    println!("Global disable cleared.");
                }
                if !sessions.is_empty() {
                    for s in &sessions {
                        vault::remove_disabled_session(s);
                    }
                    println!("{} session disable(s) cleared.", sessions.len());
                }
                println!("Policy enforcement re-enabled.");
            }
            0
        }
        Some(Command::PreflightOverride) => {
            match vault::try_load_vault() {
                Some(v) => {
                    match v.active_preflight() {
                        Some(pf) => {
                            println!("Active preflight: {} (task: {})", pf.id, pf.task);
                            println!(
                                "Violations: {}, Escalated: {}",
                                pf.violation_count, pf.escalated
                            );
                            // Require passphrase confirmation for override
                            let pass = rpassword::prompt_password(
                                "Vault passphrase to confirm override: ",
                            )
                            .unwrap_or_default();
                            match vault::unlock_vault(&pass) {
                                Ok(_) => {
                                    match v.override_preflight() {
                                        Ok(_) => {
                                            println!("Preflight overridden. Soft constraints deactivated.");
                                            0
                                        }
                                        Err(e) => {
                                            eprintln!("Error: {e}");
                                            1
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Authentication failed: {e}");
                                    1
                                }
                            }
                        }
                        None => {
                            eprintln!("No active preflight to override.");
                            0
                        }
                    }
                }
                None => {
                    eprintln!("Vault not set up or locked.");
                    1
                }
            }
        }
        Some(Command::Injections { limit }) => match vault::try_load_vault() {
            Some(v) => {
                let fires = v.recent_inject_fires(limit as i64);
                if fires.is_empty() {
                    println!("No inject rule fires recorded yet.");
                    return 0;
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                println!("{:<40} {:>10} {:>14}", "RULE", "SESSION#", "LAST FIRED");
                for (rule, ts, fires_count) in fires {
                    let ago_s = (now - ts).max(0.0) as u64;
                    let ago_str = if ago_s < 60 {
                        format!("{ago_s}s ago")
                    } else if ago_s < 3600 {
                        format!("{}m ago", ago_s / 60)
                    } else if ago_s < 86400 {
                        format!("{}h ago", ago_s / 3600)
                    } else {
                        format!("{}d ago", ago_s / 86400)
                    };
                    println!("{:<40} {:>10} {:>14}", rule, fires_count, ago_str);
                }
                0
            }
            None => {
                eprintln!("Vault not set up or locked.");
                1
            }
        },
        Some(Command::InjectTest { rule }) => {
            let v = vault::try_load_vault();
            let compiled = policy::load_merged_policy(&policy_path, &rules_path);
            let target = compiled
                .rules
                .iter()
                .find(|r| r.name == rule && r.action == policy::Decision::Inject);
            let target = match target {
                Some(t) => t,
                None => {
                    eprintln!("No INJECT rule named '{}' found.", rule);
                    return 1;
                }
            };
            let inject_cfg = match target.inject.as_ref() {
                Some(c) => c,
                None => {
                    eprintln!("Rule '{}' has action INJECT but no inject config.", rule);
                    return 1;
                }
            };
            let call = policy::ToolCall {
                tool_name: "InjectTest".into(),
                parameters: serde_json::json!({"_inject_test": rule}),
            };
            match policy::resolve_inject_payload(&inject_cfg.payload, &call, v.as_ref()) {
                Ok(payload) => {
                    println!("--- Inject test fired: {rule} ---");
                    println!("{payload}");
                    if let Some(ref vv) = v {
                        vv.record_inject_fire(&rule, vv.session_start());
                    }
                    0
                }
                Err(e) => {
                    eprintln!("Inject payload resolution failed: {e}");
                    1
                }
            }
        }
    }
}

fn main() {
    std::process::exit(run());
}
