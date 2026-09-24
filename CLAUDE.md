# signet-eval

Deterministic policy enforcement for AI agent tool calls. Rust. Single binary.

## Quick Reference

```bash
cargo build --release          # build
cargo test                     # unit, integration, adversarial, self-protection, inject, admission
cargo install --path .         # install to ~/.cargo/bin

# Hook mode (default — reads stdin, writes stdout)
echo '{"tool_name":"Bash","tool_input":{"command":"rm foo"}}' | signet-eval
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm foo"}}' | signet-eval --adapter codex
echo '{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"rm foo"}}' | signet-eval --adapter codex-permission
echo '{"toolCall":{"name":"run_command","args":{"CommandLine":"rm foo","Cwd":"/tmp"}}}' | signet-eval --adapter antigravity

# CLI
signet-eval init               # write system policy + sample.yaml (never touches rules.yaml)
signet-eval rules              # show merged rules (LOCKED/USER/SYSTEM tagged)
signet-eval validate           # check policy
signet-eval validate --fix     # auto-fix clampable issues
signet-eval validate --fix --dry-run  # preview fixes
signet-eval test '<json>'      # test a tool call
signet-eval setup              # create vault
signet-eval unlock             # refresh session
signet-eval status             # vault info + enforcement state
signet-eval store <n> <v>      # store credential
signet-eval delete <n>         # delete credential
signet-eval log                # action log
signet-eval reset-session      # clear spending
signet-eval sign               # HMAC-sign policy + user rules
signet-eval injections         # recent inject fires
signet-eval inject-test <rule> # force-fire one inject rule for testing
signet-eval serve              # MCP management server (17 tools)
signet-eval proxy              # MCP proxy
```

## Structure

```
src/
  embedded_checks.rs — trusted ENSURE scripts installed atomically on first use
  main.rs          — CLI entry point (clap), 24 subcommands
  policy.rs        — Policy engine, condition functions, first-match-wins auth + advisory inject pass
  vault.rs         — Encrypted vault (Argon2id + AES-256-GCM), 3-tier, spending ledger, scoped credentials
  hook.rs          — Claude/Codex/Antigravity/OpenCode hook I/O adapters (stdin JSON → stdout JSON)
  integration.rs   — versioned Kindex task admission, receipt ledger, read-only capability report
  claude_install.rs — explicit embedded-adapter installation; exact retirement, backups, no enforcement enablement
  redaction.rs     — pure sanitizer shared by diagnostic persistence and optional host projections
  mcp_server.rs    — MCP management server (17 tools, rmcp), locked-rule guards, auto-sign
  mcp_proxy.rs     — MCP proxy for upstream servers (rmcp), hot-reload policy
tests/
  integration_hook.rs  — End-to-end hook subprocess tests (including self-protection)
  integration_cli.rs   — CLI subcommand integration tests
  integration_protocol.rs — admission replay, scope/revision, policy and result-delivery tests
  integration_install.rs — isolated binary-only adapter install and safe retirement tests
  claude_function_host.py — isolated real Claude host with synthetic local provider
adapters/
  claude-function/ — optional TypeScript adapter; no runtime import by legacy clients
examples/
  basic_policy.yaml       — Simple deny/ask rules
  spending_limits.yaml    — Cumulative spending with vault
  enterprise_policy.yaml  — Strict controls for regulated environments
  inject_examples.yaml    — INJECT trigger/payload examples
```

## Security Model

- **Locked rules**: `locked: true` field on PolicyRule. MCP tools refuse to remove/edit/reorder locked rules. Unlocked rules cannot be reordered above locked rules. Self-protection rules ship locked by default.
- **Split policy files**: System rules in `~/.signet/policy.yaml` (managed by `init`), user rules in `~/.signet/rules.yaml` (never touched by `init`). Eval order: locked self-protection → user rules → system defaults. MCP tools operate on rules.yaml only.
- **Self-protection**: 10 locked rules in `self_protection_rules()` (policy.rs) protect .signet/ directory, checks/, vault ops, signet-eval binary, settings.json hook config, symlinks, signet processes, and preflight storage. Hardcoded in `default_policy()` so even a missing/corrupted policy.yaml falls back to protected defaults.
- **Compiled-default reconciliation**: Current built-ins overlay stale system-policy snapshots by rule name on every load. Additional human-authored system rules remain intact.
- **Reserved built-in names**: Names returned by `baseline_system_config()` are binary-owned. Host-specific system rules use distinct names; user rules are the supported override layer for unlocked defaults.
- **Advisory injection**: `INJECT` rules are a separate post-auth pass. They can probabilistically emit context through hook output, but they never authorize or deny tool calls. Authorization remains deterministic.
- **Task delegation**: admit only exact native task-state to Kindex operation pairs. Remove only the binary-owned native-store guard for source evaluation; evaluate all other source rules and both canonical MCP and semantic target identities. An admission receipt proves authorized intent, not completion. Preserve the host permission flow.
- **Diagnostic sanitation**: sanitize before truncating or persisting parameters, preflight violations and result deliveries. Reject secret-bearing preflight definitions instead of silently rewriting policy semantics. Never replace policy-evaluation inputs with sanitized copies.
- **Optional function adapter**: qualified against the exact Claude 2.1.274 and 2.1.280 early-access builds using isolated real-host probes and a synthetic provider. Disabled by default, separate from legacy adapters, and refuses detected legacy coexistence. The CLI cannot attest host plugin activation. No all-log/transcript guarantee; historical raw data is not migrated automatically.
- **Session key file encrypted** with device-specific key (machine ID + username via HKDF)
- **Brute-force protection**: 5 attempts then 5-minute lockout (vault.rs)
- **Policy HMAC integrity**: `signet-eval sign` writes HMAC sidecars for both policy.yaml and rules.yaml, verified on every hook eval when vault exists. MCP mutations auto-sign after every change.
- **Tier 3 credentials** use compartment key (separate from session key, derived via HKDF)
- **Scoped credential access**: `request_capability()` enforces domain, purpose, amount cap, and one-time constraints
- **No NLP or eval() in core authorization** — regex and string comparison only. `ENSURE` may run a trusted external check (including the shipped GitHub identity check), and `INJECT` may run allowlisted commands for advisory payloads.

## Condition Functions

`contains`, `any_of`, `param_eq`, `param_ne`, `param_gt`, `param_lt`,
`param_contains`, `matches`, `has_credential`, `spend_gt`,
`spend_plus_amount_gt`, `has_recent_action`, `not`, `or`, `true`/`false`

## MCP Server Tools (17)

`signet_list_rules`, `signet_add_rule`, `signet_remove_rule`, `signet_edit_rule`,
`signet_reorder_rule`, `signet_set_limit`, `signet_status`, `signet_recent_actions`,
`signet_store_credential`, `signet_use_credential`, `signet_delete_credential`,
`signet_list_credentials`, `signet_validate`, `signet_test`, `signet_condition_help`,
`signet_sign_policy`, `signet_reset_session`

## Testing

Test modules:
- `policy::tests` — condition functions, rule evaluation, edge cases
- `policy::self_protection_tests` — locked rules, self-protection coverage (13 tests)
- `policy::goodhart_tests` — adversarial: unicode homoglyphs, null bytes, 1MB inputs, SQL injection, 1000-rule performance
- `vault::tests` — crypto, credentials, spending, device key, HMAC, brute-force
- `tests/integration_hook.rs` — subprocess e2e: Claude/Codex/Antigravity/OpenCode hook I/O, self-protection, performance
- `tests/integration_cli.rs` — CLI subcommand tests

## Conventions

- Rust 2021 edition, stable toolchain
- No unsafe code
- All errors handled — no unwrap() on user input paths
- Exit code always 0 in hook mode (non-zero = hook failure in Claude Code; Codex PreToolUse also accepts exit 2, but signet-eval uses JSON)
- Policy evaluation deterministic and side-effect-free
- `INJECT` is the only non-deterministic behavior and is scoped to advisory context output
- `locked: false` is not serialized to YAML (skip_serializing_if)
- Auto-sign after all MCP policy mutations
