# signet-eval

Deterministic policy enforcement for AI agent tool calls. Integrated tool calls pass through user-defined rules before execution. No LLM in the authorization path. Advisory nudges are separate from authorization.

## Install

```bash
# crates.io
cargo install signet-eval

# from source
git clone https://github.com/wandercom/signet-eval
cd signet-eval
cargo install --path .
```

There is no npm or PyPI package for signet-eval. The public distribution path is
crates.io plus source install from GitHub. The MCP Registry listing points at
the repository metadata; the runtime is the local `signet-eval serve` stdio
server.

## Quick Start

The command-hook adapters below remain supported and independent. For Claude
Code's optional early-access function hooks, see the
[function adapter](adapters/claude-function/README.md). It is disabled by default;
installing/building this package does not activate it or change user settings.

**1. Hook into Claude Code** — add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{"type": "command", "command": "signet-eval", "timeout": 2000}]
    }]
  }
}
```

For Codex, enable hooks in `~/.codex/config.toml` or `<repo>/.codex/config.toml`:

```toml
[features]
codex_hooks = true
```

Then add `~/.codex/hooks.json` or `<repo>/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "signet-eval --adapter codex",
        "timeout": 30000,
        "statusMessage": "Checking Signet policy"
      }]
    }],
    "PermissionRequest": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "signet-eval --adapter codex-permission",
        "timeout": 30000,
        "statusMessage": "Checking Signet approval policy"
      }]
    }]
  }
}
```

For Antigravity, add this block to `~/.gemini/config/hooks.json` (merge it with any existing hook groups):

```json
{
  "signet": {
    "enabled": true,
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "/bin/bash -lc 'source ~/.profile >/dev/null 2>&1 || true; exec signet-eval --adapter antigravity'",
        "timeout": 30,
        "statusMessage": "Checking Signet policy"
      }]
    }]
  }
}
```

The same configuration is available at [`hooks/antigravity-hooks.json`](hooks/antigravity-hooks.json).

For Cursor, add to `~/.cursor/hooks.json` (user) or `<repo>/.cursor/hooks.json`
(project), merging with any existing events:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [{
      "command": "/bin/bash -lc 'source ~/.profile >/dev/null 2>&1 || true; exec signet-eval --adapter cursor'",
      "matcher": "^(?!Shell$|MCP:)",
      "timeout": 30,
      "failClosed": true
    }],
    "beforeShellExecution": [{
      "command": "/bin/bash -lc 'source ~/.profile >/dev/null 2>&1 || true; exec signet-eval --adapter cursor'",
      "timeout": 30,
      "failClosed": true
    }],
    "beforeMCPExecution": [{
      "command": "/bin/bash -lc 'source ~/.profile >/dev/null 2>&1 || true; exec signet-eval --adapter cursor'",
      "timeout": 30,
      "failClosed": true
    }]
  }
}
```

The same configuration is available at [`hooks/cursor-hooks.json`](hooks/cursor-hooks.json).
The `preToolUse` matcher skips shell and MCP calls because the two dedicated
events evaluate them; without it, each such call is evaluated and logged twice.

For Muse Code, add a top-level `hooks` member to `~/.config/muse/settings.json`
(user scope; keep `schema_version` and your other settings), or save the file as
`<repo>/.muse/hooks.json` (project scope, which Muse enables only for trusted
workspaces):

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{"type": "command", "command": "signet-eval --adapter muse"}]
    }]
  }
}
```

The same configuration is available at [`hooks/muse-hooks.json`](hooks/muse-hooks.json).

**2. Done.** Every tool call now passes through policy evaluation. The default policy blocks destructive operations, protects its own configuration, and allows everything else.

**3. (Optional) Customize** — talk to Claude with the MCP server:

```bash
claude mcp add --scope user --transport stdio signet -- signet-eval serve
```

Then say: *"Add a $50 limit for amazon orders"* or *"Block all rm commands"*.

## Default Policy

Self-protection rules are **locked** — they cannot be removed, edited, or reordered by the AI agent, even through the MCP management server. This prevents the agent from disabling its own guardrails.

| Action | Decision | Locked |
|--------|----------|--------|
| Write/Edit/Bash touching `.signet/` | **deny** | yes |
| Write/Edit/Bash touching `signet-eval` binary | **deny** | yes |
| Write/Edit `settings.json` / `settings.local.json` | **ask** | yes |
| Bash `kill`/`pkill`/`killall` + `signet` | **deny** | yes |
| Direct edit tools without recent Kindex tag/search/context | **deny** | yes |
| Claude `TaskCreate`, `TaskUpdate`, `TaskList`, `TaskGet`, `TodoWrite` | **deny** | yes |
| `rm`, `rmdir` | **deny** | |
| Cursor's native `Delete` tool | **deny** | |
| `git push --force` | **ask** | |
| Git remote and `gh` operations with mismatched target-owner identity | **deny** | |
| `mkfs`, `format`, `dd if=` | **deny** | |
| `curl \| sh`, `wget \| sh` | **deny** | |
| Any tool input carrying a literal [masked secret](#secret-masking) value | **ask** | |
| Everything else | **allow** | |

## Custom Policy

```bash
signet-eval init       # write default policy to ~/.signet/policy.yaml
signet-eval validate   # check policy for errors
signet-eval rules      # show current rules
```

Edit `~/.signet/policy.yaml`:

```yaml
version: 1
default_action: ALLOW
rules:
  - name: block_rm
    tool_pattern: ".*"
    conditions: ["contains(parameters, 'rm ')"]
    action: DENY
    reason: "File deletion blocked"

  - name: books_limit
    tool_pattern: ".*purchase.*"
    conditions:
      - "param_eq(category, 'books')"
      - "spend_plus_amount_gt('books', amount, 200)"
    action: DENY
    reason: "Books spending limit ($200) exceeded"

  - name: protect_my_config
    tool_pattern: ".*"
    conditions: ["contains(parameters, '/etc/')"]
    action: ASK
    locked: true
    reason: "System config changes require confirmation"
```

Rules are evaluated in order — first match wins. Multiple conditions on a rule are AND'd. Rules with `locked: true` cannot be modified through the MCP management server.

## ENSURE check context

User-managed ENSURE scripts receive the original normalized tool name and input
on stdin. `SIGNET_TOOL_COMMAND` carries the first non-empty string among the
normalized `command` and `cmd` fields as a literal environment value. It is empty
when neither field holds one.
The forwarding mechanism does not interpret that value as shell code.

`SIGNET_TOOL_CWD` uses the normalized tool `cwd`/`workdir`, then the host envelope's
`cwd`, then the hook process's working directory. Empty values are skipped.
`SIGNET_TOOL_CWD_SOURCE` says which one was used: `tool_input`, `host`, or `process`.
`SIGNET_HOST_CWD` carries the host envelope's `cwd` on its own, or is empty when the
host sent none. A `tool_input` directory is where the host will run the command, but
the model wrote it. The process fallback is not an independently verified execution
directory. None of these is a trusted location attestation, and a check that
authorizes on location should look at the source before relying on the value.
Signet does not interpret the command, so a `cd` inside it does not change
`SIGNET_TOOL_CWD`. All of these environment values replace inherited ones, and stdin
remains unchanged.

A missing or unresolvable check script denies the call with a reason naming the
check, for user rules as well as locked ones. Signet installs no check scripts, so
copy `~/.signet/checks/` along with any `rules.yaml` that refers to it.

Older releases shipped a `github_identity_guard` system rule. A copy of it left in
`policy.yaml` is ignored, and `signet-eval validate` reports it as a warning. To keep
an identity check, put the rule in `rules.yaml` with a script you maintain.

From the repository root after `cargo build --release`, run the independent local
acceptance checks with:

```bash
SIGNET_EVAL_BINARY="$(pwd)/target/release/signet-eval" python3 tests/test_ensure_behavior.py
```

These Python acceptance checks can run locally and are also collected by hosted
CI on Linux and macOS against the release binary, alongside Rust and packaging checks.

## Advisory Injection

`INJECT` rules probabilistically add advisory context near the tool call that
triggered them. They are nudges, not authorization: the normal
`ALLOW`/`DENY`/`ASK`/`GATE`/`ENSURE` pass remains first-match-wins and
deterministic. Injection runs afterward and only emits context when a matching
inject rule fires.

```yaml
rules:
  - name: maybe_remind_kindex_on_git
    tool_pattern: "^Bash$"
    conditions: ["contains(parameters, 'git ')"]
    action: INJECT
    inject:
      trigger:
        mode: exponential
        peak: 0.35
        cooldown_seconds: 300
        peak_after_seconds: 1800
        max_per_session: 3
      payload:
        text: "Before committing, check whether project `.kin` files should be included."
```

Trigger modes:

| Mode | Behavior |
|------|----------|
| `constant` / `step` | Fixed probability after cooldown |
| `linear` | Ramps from 0 to `peak` over `peak_after_seconds` |
| `exponential` | Approaches `peak` with exponential decay |

Payload sources:

| Source | Notes |
|--------|-------|
| `text` | Inline literal text |
| `text_file` | Bare filename under `~/.signet/injections/` |
| `from_command` | HMAC-signed allowlist entry from `~/.signet/inject_commands.yaml`; direct exec, no shell |

Template substitutions are enabled by default: `{tool_name}`, `{cwd}`, `{date}`,
and `{matched_param.X}`. See `examples/inject_examples.yaml`.

## Condition Functions

| Function | Description | Example |
|----------|-------------|---------|
| `contains(parameters, 'X')` | Tool input contains string | `contains(parameters, 'rm ')` |
| `any_of(parameters, 'X', 'Y')` | Any string present | `any_of(parameters, 'mkfs', 'format')` |
| `param_eq(field, 'value')` | Field equals value | `param_eq(category, 'books')` |
| `param_ne(field, 'value')` | Field not equal | `param_ne(role, 'admin')` |
| `param_gt(field, N)` | Field > number | `param_gt(amount, 100)` |
| `param_lt(field, N)` | Field < number | `param_lt(amount, 5)` |
| `param_contains(field, 'X')` | Field contains substring | `param_contains(command, 'sudo')` |
| `matches(field, 'regex')` | Field matches regex | `matches(file_path, '\\.env$')` |
| `has_credential('name')` | Credential exists in vault | `has_credential('cc_visa')` |
| `spend_gt('cat', N)` | Session spend > limit | `spend_gt('books', 200)` |
| `spend_plus_amount_gt('cat', field, N)` | Spend + this amount > limit | `spend_plus_amount_gt('books', amount, 200)` |
| `not(condition)` | Negate condition | `not(param_eq(format, 'json'))` |
| `or(A \|\| B)` | Either condition | `or(contains(parameters, '-f') \|\| contains(parameters, '--force'))` |
| `has_recent_action('search', N)` | Recent allowed action matches in tool name or detail; pipe-delimited OR | `has_recent_action('EnterPlanMode\|TaskCreate', 500)` |
| `has_current_session()` | Hook host supplied a distinct chat/session identifier | `has_current_session()` |
| `contains_masked_value(parameters)` | Tool input holds a literal value from the [secret masking](#secret-masking) reference files; also takes a field name. Never matches without a config | `contains_masked_value(command)` |
| `true` / `false` | Literal | `true` |

### Model-scoped rules

Hook-mode calls can carry an `agent_model` field naming the model that issued
the tool call. Only the host may supply it: Signet reads the hook envelope's
`model` (a string, or an object with `id`) or Antigravity's `modelName`, and
nothing else.

- Any `agent_model` in tool input is discarded on every evaluation path (all
  hook adapters, the MCP proxy and Kindex task admission), so the agent cannot
  claim a model. The host still runs the original tool input.
- Signet never reads the model from a session transcript. The agent can write
  that file, so a model recorded there is a claim, not a fact.
- Claude Code's classic `PreToolUse` input has no model field, so legacy
  Claude hooks never see `agent_model`. The optional function adapter
  (`adapters/claude-function`) passes the host's `$.session.model()` answer
  when the host provides one. That is the session's model; whether it names a
  subagent's own model is not qualified.
- MCP proxy and Kindex admission calls have no host-attested model, so the
  field is always absent there.
- The field is attached only when a rule or the active preflight names
  `agent_model`. Other policies see tool input exactly as before.

When the model is unknown the field is absent and compares as an empty string.
Write the condition as a negated allowlist so unknown models fail closed:

```yaml
- name: cloud_tools_require_opus
  tool_pattern: "^Bash$"
  conditions:
    - "matches(command, '(^|[;&|(\\s])(gcloud|cloud-sql-proxy)(\\s|$)')"
    - "not(matches(agent_model, '^claude-(opus|fable)-'))"
  action: DENY
  locked: true
  reason: "gcloud and cloud-sql-proxy are limited to Opus and Fable"
```

On a host that reports no model, this rule denies every matching call.
Command matching stays substring-based, so an agent determined to reach the
same binary through an interpreter or wrapper script can still evade it.

## Secret masking

Optional. Create `~/.signet/secret_mask.yaml` (or `$SIGNET_DIR/secret_mask.yaml`)
naming shell env files that hold your secrets:

```yaml
files: [~/.profile]          # required; nothing is masked without files
keys: [OPENAI, "AWS_*_KEY"]  # optional; default fragments below
min_length: 8                # optional; shorter values are ignored
```

Without the file the feature is off. `~` expands to `$HOME`; a relative path is
relative to the signet directory. The file sits under `~/.signet/`, so the
self-protection rules stop the agent from editing it.

Each reference file is read line by line: an optional `export `, then
`NAME=VALUE` with `NAME` matching `[A-Za-z_][A-Za-z0-9_]*`. Matching surrounding
quotes are stripped, and an unquoted value loses a trailing ` #comment`. Values
containing `$` or a backtick, values with unterminated or concatenated quotes,
and values shorter than `min_length` are skipped.

A key is selected when its name contains any `keys` entry, case-insensitive,
with `*` matching any run of characters. A full name therefore also selects
longer names that contain it. Without `keys`, the default fragments are `KEY`,
`TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `PASS`, `PW`, `CREDENTIAL`, `AUTH`,
`PRIVATE`, `SID`, `DSN`, `WEBHOOK`, `COOKIE`, `CLIENT_ID`, `ACCOUNT_ID` and `API`
(`DEFAULT_KEY_PATTERNS` in `src/secret_mask.rs`).

Every occurrence of a selected value, and of its JSON-escaped spelling, becomes
`$NAME`. Longer values are replaced first, file order breaks ties, a value
shared by several names masks to the first, and a name defined twice masks both
values. Files are cached and re-read when their mtime or size changes. A missing
or unreadable file produces one warning on stderr naming the path and masks
nothing from it; an invalid config turns masking off with one warning.

Masking applies to what signet-eval persists or displays: the action ledger,
preflight records and violations, Kindex result deliveries, the `integration
redact` sanitizer used by the Claude function adapter, MCP management replies
(recent actions, status, violations, rule listings, test results), MCP proxy
reasons, hook deny/ask reasons and advisory context, and the `rules`, `test` and
`log` CLI output. It never changes the input policy evaluates and never rewrites
the command the host runs. A preflight definition containing a masked value is
rejected, as with other secrets. Vault credentials are stored as given.

A command can genuinely need the literal value, so the default rule
`block_masked_secret_literal` asks rather than denies when tool input contains
one. Its reason names the key (`$NAME`), never the value, and suggests using
`$NAME` instead. Override it in `rules.yaml` like any unlocked default. Rule
reasons and alternatives can use the `{masked_keys}` placeholder, which expands
to the matched key names. `signet-eval status` reports the masked key names and
file count.

## Encrypted Vault

Three-tier encrypted storage with passphrase-derived key hierarchy (Argon2id + AES-256-GCM):

| Tier | Encryption | Contents |
|------|-----------|----------|
| 1 | None | Action log, spending ledger |
| 2 | Session key | Session state |
| 3 | Compartment key | CC numbers, API tokens, secrets |

```bash
signet-eval setup                      # create vault with passphrase
signet-eval store cc_visa 4111...      # store Tier 3 credential
signet-eval status                     # vault status and spending
signet-eval log                        # recent action log
signet-eval unlock                     # refresh session after timeout
```

Credentials support scoped access via `request_capability`: domain restrictions, purpose constraints, per-use amount caps, and one-time tokens that auto-invalidate after a single use.

Spending limits use the vault ledger — each tool call that spends money is logged, and `spend_plus_amount_gt()` checks cumulative totals before allowing the next purchase.

## Self-Protection

signet-eval ships with locked rules that prevent an AI agent from disabling its own policy enforcement:

1. **protect_signet_dir** — Denies any Write, Edit, or Bash command touching `.signet/` (policy files, vault, HMAC)
2. **protect_signet_binary** — Denies tampering with the `signet-eval` binary itself
3. **protect_hook_config** — Requires user confirmation before modifying `settings.json` (where the hook is configured)
4. **protect_signet_process** — Denies kill/pkill/killall commands targeting signet processes

5. **protect_preflight_storage** — Denies agent-side mutation of preflight records
6. **require_kindex_engagement_before_edits** — Denies direct edit tools until durable session context is recorded
7. **prefer_persistent_task_store** — Denies the five Claude task-state tools above and points agents to durable Kindex tasks. `Agent`, legacy subagent `Task`, `TaskOutput`, and `TaskStop` are not task-state tools and are not blocked by this rule.
8. **protect_checks_dir** — Denies agent-side replacement of trusted ENSURE scripts
9. **protect_vault_passphrase** — Reserves vault setup and unlock operations for the human
10. **protect_signet_symlink** — Denies symlink bypasses targeting protected enforcement surfaces

These rules are:
- **Locked** — MCP tools refuse to remove, edit, or reorder them
- **Position-protected** — Unlocked rules cannot be reordered above locked rules (first-match-wins)
- **Hardcoded in defaults** — If the policy file is corrupted or missing, the binary falls back to hardcoded defaults that include self-protection
- **Version-reconciled** — Current compiled defaults overlay stale system-policy snapshots by rule name, so an upgrade does not require rerunning `init`
- **Reserved-name reconciled** — Built-in rule names are owned by the binary; host-specific system rules must use distinct names, while user rules remain the supported override layer for unlocked defaults
- **HMAC-backed** — Direct file edits break the policy signature, triggering fallback to safe defaults

## MCP Management Server

Manage policies conversationally through Claude:

```bash
claude mcp add --scope user --transport stdio signet -- signet-eval serve
```

| Tool | Purpose |
|------|---------|
| `signet_list_rules` | Show all rules with locked status |
| `signet_add_rule` | Add a new rule (appended after locked rules) |
| `signet_remove_rule` | Remove a rule (refuses on locked rules) |
| `signet_edit_rule` | Modify rule properties (refuses on locked rules) |
| `signet_reorder_rule` | Move a rule (refuses on locked, prevents placing above locked) |
| `signet_set_limit` | Set a spending limit for a category |
| `signet_test` | Test a tool call against the current policy |
| `signet_validate` | Check policy for errors |
| `signet_condition_help` | Show available condition functions |
| `signet_status` | Vault status, spending totals, credential count |
| `signet_recent_actions` | Show recent action log |
| `signet_store_credential` | Store a Tier 3 credential |
| `signet_use_credential` | Request a credential through capability constraints |
| `signet_list_credentials` | List credential names |
| `signet_delete_credential` | Delete a credential |
| `signet_sign_policy` | HMAC-sign the policy file |
| `signet_reset_session` | Clear spending counters |

All mutating operations auto-sign the policy when the vault is available.

## MCP Proxy

Wrap upstream MCP servers with policy enforcement. The agent connects to the proxy, never directly to servers. Policy is hot-reloaded on every call.

```bash
# Configure upstream servers
cat > ~/.signet/proxy.yaml << 'YAML'
servers:
  linear:
    command: npx
    args: ["-y", "mcp-linear"]
    env:
      LINEAR_API_KEY: "your-key"
YAML

# Register proxy with Claude Code
claude mcp add --scope user --transport stdio signet-proxy -- signet-eval proxy
```

## All Commands

| Command | Purpose |
|---------|---------|
| `signet-eval` | Hook evaluation (default, 25ms) |
| `signet-eval --adapter codex` | Codex `PreToolUse` hook evaluation |
| `signet-eval --adapter codex-permission` | Codex `PermissionRequest` hook evaluation |
| `signet-eval --adapter antigravity` | Antigravity `PreToolUse` hook evaluation |
| `signet-eval --adapter cursor` | Cursor `preToolUse`, `beforeShellExecution`, `beforeMCPExecution` and `beforeReadFile` hook evaluation |
| `signet-eval --adapter muse` | Muse Code `PreToolUse` (and optional `PermissionRequest`) hook evaluation |
| `signet-eval integration describe` | Read-only policy/capability inspection from JSON stdin |
| `signet-eval integration adjudicate` | Scoped, revision-bound Kindex task admission with durable intent receipt |
| `signet-eval integration record-result` | Idempotent delivery of a Kindex task receipt; not proof of execution |
| `signet-eval integration redact` | Structured sanitizer for controlled output projections |
| `signet-eval integration install-modern` | Explicitly install the binary-embedded Claude adapter with backups; preserves enforcement disabled state |
| `signet-eval init` | Write default policy with locked self-protection rules |
| `signet-eval rules` | Show current policy rules (locked rules tagged) |
| `signet-eval validate` | Check policy for errors |
| `signet-eval test '<json>'` | Test a tool call against policy |
| `signet-eval setup` | Create encrypted vault |
| `signet-eval unlock` | Refresh vault session |
| `signet-eval status` | Vault status and spending |
| `signet-eval store <name> <value>` | Store Tier 3 credential |
| `signet-eval delete <name>` | Delete a credential |
| `signet-eval log` | Recent action log |
| `signet-eval reset-session` | Clear spending counters |
| `signet-eval sign` | HMAC-sign policy file |
| `signet-eval injections` | Show recent inject rule fires |
| `signet-eval inject-test <rule>` | Force-fire one inject rule for testing |
| `signet-eval serve` | MCP management server (17 tools) |
| `signet-eval proxy` | MCP proxy for upstream servers |

## Performance

| Metric | Value |
|--------|-------|
| Hook eval (end-to-end) | **25ms** — process spawn, stdin, JSON parse, policy load, eval, response |
| In-process policy eval | **14–63μs** — 14μs deny, 21μs ask, 63μs spending check |
| CLI validate / rules | **8ms** |
| Binary size | **6.2MB** (stripped, LTO) |

## Architecture

signet-eval is the enforcement layer of the [Signet](https://signet.tools) personal sovereign agent stack. The core principle: **the authorization layer must not be an LLM.** It processes structured data only — regex, comparisons, and vault queries. No natural language, no context window, no persuasion surface. A rule either matches or it doesn't.

```
Agent proposes action  ->  signet-eval evaluates policy  ->  allow / deny / ask
                           (deterministic, 25ms, no NLP)
```

<!-- mcp-name: io.github.jmcentire/signet-eval -->

## Security Model

signet-eval is a **seatbelt, not a cage**. Understanding what it does and doesn't protect against is critical.

### What it protects against

**A cooperative agent making mistakes.** Claude Code, Codex, Antigravity, Cursor, and Muse Code follow hook protocols — they call signet-eval around tool use and respect the supported responses. Within those protocols, signet-eval reliably enforces policy:

- Blocks destructive commands (`rm`, `mkfs`, piped remote execution)
- Enforces spending limits across tool calls
- Gates credential access with domain, purpose, and amount constraints
- Requires user confirmation for sensitive operations (`git push --force`)
- Prevents casual policy tampering via locked rules and MCP guards

This is the normal operating mode. The agent isn't trying to escape — it's trying to be helpful and the policy keeps it in bounds.

Codex support has one important semantic difference: `PreToolUse` is currently deny-only for enforcement, so Signet `ALLOW` emits no output and Signet `ASK` is converted to a deny at that stage. The `PermissionRequest` adapter explicitly allows or denies requests Codex was already going to send through approval; Signet `ASK` defers to Codex's normal approval prompt.

Antigravity sends a nested `toolCall` payload and expects a top-level `decision` response. The adapter normalizes native command and file tools to Signet's canonical policy names, unwraps `call_mcp_tool` into `mcp__<server>__<tool>`, and fails closed when the native wrapper is malformed.

Cursor semantics (verified against `cursor-agent` 2026.10.01): the adapter reads
`hook_event_name` and answers with Cursor's flat `permission` object. Only
`beforeShellExecution` can ask; there Signet `ASK` becomes Cursor's approval
prompt. `preToolUse` enforces only deny, `cursor-agent` ignores `ask` on
`beforeMCPExecution` although Cursor's documentation lists it, and
`beforeReadFile` accepts only allow or deny, so Signet `ASK` becomes a deny on
those three events. Cursor's `Shell` tool maps to `Bash`, and
`beforeMCPExecution` maps to `mcp__<server>__<tool>` with the arguments decoded
from Cursor's JSON string; `preToolUse` sees MCP calls only as `MCP:<tool>`,
without the server, which is why the sample routes MCP to the dedicated event.
`beforeReadFile` evaluates the path, not the file content Cursor attaches.
Signet emits `allow` explicitly, because Cursor treats empty output as a failed
hook. Cursor fails open when a hook crashes, times out, or exits non-zero unless
the entry sets `failClosed: true`, as the sample does; invalid JSON blocks the
action either way. Cursor also runs hooks from Claude Code's
`~/.claude/settings.json` and project `.claude/settings*.json`. Those receive
Cursor payloads, so a plain `signet-eval` Claude hook there runs a second,
unnormalized evaluation in Cursor; it does not deduplicate against the Cursor
adapter, whose command differs.

Muse Code semantics (verified against Muse 1.4.6): Muse sends Claude-shaped
`PreToolUse` payloads with its own tool names. The adapter maps `shell` (and
`bash`, `bash_input`, `exec_command`, `execute_command`) to `Bash`,
`read_file`/`write_file`/`edit_file` to `Read`/`Write`/`Edit` (copying a native
`path` into `file_path`), `search` to `Grep`, and `web_fetch`/`web_search` to
`WebFetch`/`WebSearch`; MCP tools already arrive as `mcp__<server>__<tool>`.
Muse `PreToolUse` enforces only deny: it ignores `ask` and rejects a bare
`allow`, so Signet `ALLOW` emits no output (or only `additionalContext` for an
inject nudge) and Signet `ASK` becomes a deny. Muse has no fail-closed hook
option: a crashed, timed-out, or unparseable hook lets the tool call proceed.
Project hooks in `.muse/hooks.json` stay disabled until the workspace is
trusted. Muse does not run Claude Code or Codex hooks. The adapter also accepts
`PermissionRequest` with the Codex response shape (`ASK` defers to Muse's
prompt), but the sample omits it: with the default `ALLOW` policy it would
approve every call Muse was about to ask about.

### What it does NOT protect against

**An adversarial agent with shell access.** signet-eval runs at the same privilege level as the agent it constrains. Any process with the same UID can:

- Use shell indirection to evade string matching (`alias`, `eval`, `base64 -d | sh`, `python3 -c "..."`)
- Create symlinks to protected paths under innocent names
- Read the session key file and forge HMAC signatures
- Replace the signet-eval binary itself
- Modify the hook configuration in `settings.json`
- Use `LD_PRELOAD`, `ptrace`, or process injection

No amount of pattern matching fixes this. Adding rules for `ln` invites `alias`. Blocking `alias` invites `eval`. Blocking `eval` invites `python3 -c`. This is an infinite regress — the fundamental issue is privilege level, not pattern coverage.

### Where real containment lives

Protecting against a truly adversarial agent requires **OS-level controls** that operate above the agent's privilege level:

- **Separate user account** — run the agent as a restricted user with no write access to policy files
- **Container/sandbox** — Docker, Flatpak, or `bubblewrap` with a read-only mount for `~/.signet/`
- **Stripped `$PATH`** — remove `ln`, `alias`, and other indirection tools from the agent's environment
- **seccomp / AppArmor / SELinux** — mandatory access controls that the agent cannot override
- **Virtual environment** — run Claude Code in a constrained environment with limited filesystem access

signet-eval is the **policy layer** within such a setup. It handles the "what should this agent be allowed to do" question with clear, auditable rules. The OS handles the "can this agent circumvent the policy" question. Neither replaces the other.

### Defense in depth

The layers work together:

| Layer | Protects against | Mechanism |
|-------|-----------------|-----------|
| **String matching** | Obvious mistakes, clear UX | Regex, substring, word-boundary conditions |
| **Locked rules** | Casual MCP-based policy tampering | Immutable rules, position protection |
| **HMAC signing** | Out-of-band file modification | Cryptographic integrity verification |
| **OS controls** | Privilege escalation, shell indirection | Sandboxing, RBAC, separate users |

Without OS controls, signet-eval is a speed bump, not a wall. With them, it's the policy engine inside a secure perimeter.

## License

MIT
