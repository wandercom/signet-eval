//! Signet MCP Proxy — wraps upstream MCP servers with policy enforcement.

use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::policy::{self, Decision, ToolCall};
use crate::vault::{self, Vault};

fn proxy_config_path() -> PathBuf {
    vault::signet_dir().join("proxy.yaml")
}

#[derive(Debug, Deserialize)]
struct ProxyConfig {
    #[serde(default)]
    servers: HashMap<String, UpstreamConfig>,
}

#[derive(Debug, Deserialize)]
struct UpstreamConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

struct UpstreamConnection {
    name: String,
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tools: Vec<Tool>,
}

pub struct ProxyServer {
    upstreams: Arc<Mutex<Vec<UpstreamConnection>>>,
    policy_path: PathBuf,
    rules_path: PathBuf,
    vault: Option<Vault>,
}

impl ServerHandler for ProxyServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Signet-proxied MCP server. All tool calls pass through policy enforcement.".into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async {
            let upstreams = self.upstreams.lock().await;
            let mut tools = Vec::new();
            for upstream in upstreams.iter() {
                for tool in &upstream.tools {
                    let mut proxied = tool.clone();
                    proxied.name = Cow::Owned(format!("{}__{}", upstream.name, tool.name));
                    if let Some(ref desc) = proxied.description {
                        proxied.description =
                            Some(Cow::Owned(format!("[{}] {}", upstream.name, desc)));
                    }
                    tools.push(proxied);
                }
            }
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
            let tool_name = request.name.to_string();

            let (server_name, original_name) = match tool_name.split_once("__") {
                Some((s, t)) => (s.to_string(), t.to_string()),
                None => {
                    return Err(McpError::invalid_params(
                        "Tool name must be server__tool format",
                        None,
                    ))
                }
            };

            // Reload policy on each call (hot-reload) with integrity verification
            let current_policy = if let Some(ref v) = self.vault {
                if !vault::verify_policy_integrity(v.session_key(), &self.policy_path) {
                    // Tampered system policy — use safe defaults
                    policy::default_policy()
                } else if self.rules_path.exists()
                    && !vault::verify_policy_integrity(v.session_key(), &self.rules_path)
                {
                    // Tampered user rules — use safe defaults
                    policy::default_policy()
                } else {
                    policy::load_merged_policy(&self.policy_path, &self.rules_path)
                }
            } else {
                // No vault — cannot verify policy integrity, use hardcoded defaults
                policy::default_policy()
            };
            let args_value = request
                .arguments
                .as_ref()
                .map(|a| serde_json::Value::Object(a.clone()))
                .unwrap_or_default();
            let call = ToolCall {
                tool_name: tool_name.clone(),
                parameters: args_value.clone(),
            };
            let result = policy::evaluate(&call, &current_policy, self.vault.as_ref());

            // Log
            if let Some(ref v) = self.vault {
                let amount = args_value
                    .get("amount")
                    .and_then(|v| {
                        v.as_f64()
                            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                    })
                    .unwrap_or(0.0);
                let category = args_value
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let amt = if result.decision == Decision::Allow {
                    amount
                } else {
                    0.0
                };
                let detail = crate::redaction::value(&args_value).to_string();
                v.log_action(
                    &tool_name,
                    result.decision.as_lowercase(),
                    category,
                    amt,
                    &crate::redaction::summary(&detail, 500),
                );
            }

            match result.decision {
                Decision::Deny => {
                    let reason = result.reason.unwrap_or_else(|| "Denied by policy".into());
                    Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "DENIED by Signet: {reason}"
                    ))]))
                }
                Decision::Ask => {
                    let reason = result.reason.unwrap_or_else(|| "Requires approval".into());
                    Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "REQUIRES APPROVAL: {reason}"
                    ))]))
                }
                Decision::Gate => {
                    // Gate should be resolved by evaluate() — safety net
                    let reason = result.reason.unwrap_or_else(|| "Gate check failed".into());
                    Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "DENIED by Signet: {reason}"
                    ))]))
                }
                Decision::Ensure => {
                    let reason = result
                        .reason
                        .unwrap_or_else(|| "Ensure checks cannot run in proxy mode".into());
                    Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                        "DENIED by Signet: {reason}"
                    ))]))
                }
                Decision::Inject => {
                    // Inject rules are non-authoritative and skipped in the auth pass.
                    // Reaching this arm means the default action was Inject, which is misconfigured.
                    // Fall through to Allow semantics to avoid blocking on misconfiguration.
                    let upstreams = self.upstreams.lock().await;
                    let upstream = upstreams.iter().find(|u| u.name == server_name);
                    match upstream {
                        Some(u) => {
                            let mut fwd = CallToolRequestParams::default();
                            fwd.name = Cow::Owned(original_name.clone());
                            fwd.arguments = request.arguments.clone();
                            match u.client.peer().call_tool(fwd).await {
                                Ok(r) => Ok(r),
                                Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(
                                    format!("Upstream error: {e}"),
                                )])),
                            }
                        }
                        None => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                            "Unknown upstream: {server_name}"
                        ))])),
                    }
                }
                Decision::Allow => {
                    let upstreams = self.upstreams.lock().await;
                    let upstream = upstreams.iter().find(|u| u.name == server_name);
                    match upstream {
                        Some(u) => {
                            let mut fwd = CallToolRequestParams::default();
                            fwd.name = Cow::Owned(original_name.clone());
                            fwd.arguments = request.arguments.clone();
                            match u.client.peer().call_tool(fwd).await {
                                Ok(r) => Ok(r),
                                Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(
                                    format!("Upstream error: {e}"),
                                )])),
                            }
                        }
                        None => Err(McpError::invalid_params(
                            format!("Unknown server: {server_name}"),
                            None,
                        )),
                    }
                }
            }
        }
    }
}

async fn connect_upstream(
    name: &str,
    config: &UpstreamConfig,
) -> Result<UpstreamConnection, Box<dyn std::error::Error>> {
    let mut cmd = tokio::process::Command::new(&config.command);
    cmd.args(&config.args);
    for (k, v) in &config.env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    let process = TokioChildProcess::new(cmd)?;
    let client = rmcp::serve_client((), process).await?;

    let tools_result = client.peer().list_tools(Default::default()).await?;

    Ok(UpstreamConnection {
        name: name.to_string(),
        client,
        tools: tools_result.tools,
    })
}

/// Run the MCP proxy server on stdio.
pub async fn run_proxy() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = proxy_config_path();
    let config: ProxyConfig = match std::fs::read_to_string(&config_path) {
        Ok(content) => serde_yaml::from_str(&content)?,
        Err(_) => {
            eprintln!("No proxy config at {}", config_path.display());
            eprintln!("Create ~/.signet/proxy.yaml with upstream server definitions.");
            return Ok(());
        }
    };

    if config.servers.is_empty() {
        eprintln!("No upstream servers configured.");
        return Ok(());
    }

    let mut upstreams: Vec<UpstreamConnection> = Vec::new();
    for (name, server_config) in &config.servers {
        eprintln!("Connecting to upstream: {name}...");
        match connect_upstream(name, server_config).await {
            Ok(conn) => {
                eprintln!("  {} tools from {name}", conn.tools.len());
                upstreams.push(conn);
            }
            Err(e) => eprintln!("  Failed: {e}"),
        }
    }

    let total_tools: usize = upstreams.iter().map(|u| u.tools.len()).sum();
    eprintln!(
        "Proxy ready: {} servers, {} tools",
        upstreams.len(),
        total_tools
    );

    let proxy = ProxyServer {
        upstreams: Arc::new(Mutex::new(upstreams)),
        policy_path: vault::signet_dir().join("policy.yaml"),
        rules_path: vault::signet_dir().join("rules.yaml"),
        vault: vault::try_load_vault(),
    };

    let service = rmcp::serve_server(proxy, rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
