# Optional Claude function adapter

This thin TypeScript plugin delegates policy and sanitation to the existing Rust
binary. It starts no service. Legacy Claude command hooks, Codex, Antigravity and
OpenCode remain separate: they do not import this adapter, poll it, or require
Claude's function API. Removing this directory removes the modern adapter.

The adapter targets the early-access API emitted by Claude Code **2.1.274** and
**2.1.280** with `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`. The installer accepts those
exact builds, not a version range. The recovery adapter was verified on 2.1.280 with the real-host fixture
(active, disabled, disable-during-call, installed-plugin, and Kindex denial paths)
and 56 independent callback recovery checks. The earlier adapter was qualified on
2.1.274; this repair retains that installer compatibility without a new 2.1.274 host run. The adapter/binary pairing revision is `claude-functions-2.1.280-v1`;
install the rebuilt binary and its embedded adapter together.
The flag also works through `settings.json`'s `env` object in an isolated
2.1.274 probe; no shell-profile change is required for that activation path.
Settings-hook events are named under `classic.` in this API (`classic.PreToolUse`);
2.1.274 rejects a module that registers the bare `PreToolUse` name used on 2.1.263.
Use `/plugin-types` in an isolated directory to obtain the host declarations.
The host's module checker is stricter than ordinary TypeScript.

## Explicit activation

Nothing in a build or package installation enables this adapter. Its `enabled`
option defaults to `false`, which registers no hooks. Do not install the modern
and legacy Claude handlers together. The installer below retires recognized
registrations; unfamiliar wrappers require manual review. Keep other clients'
adapters as needed. The plugin detects common legacy command
registrations in Claude user/project settings and refuses coexistence. Arbitrary
shell wrappers and externally supplied settings require operator inspection.

The binary embeds all runtime assets; no source checkout or third package is
needed. After installing/upgrading Signet-eval, explicitly choose the modern
adapter with:

```bash
signet-eval integration install-modern
```

This checks the exact Claude version allowlist, installs complete assets under
`CLAUDE_CONFIG_DIR/skills/signet-eval-functions` (normally `~/.claude/skills`), sets
the function flag in Claude settings, and configures the adapter with this
binary's absolute path. It retires only exact recognized Signet Claude command
handlers, retaining foreign handlers in shared groups. Unknown Signet wrappers,
malformed settings and linked/unowned installation targets require manual review.
Existing settings and previous plugin files are retained under the Claude config
directory's `signet-adapter-backups`; restore both to roll back. Restart Claude.

Installing the adapter does **not** enable enforcement: global/session disabled
state is preserved. When globally disabled, the installed plugin is neutral.
Other clients' settings are not touched. Default hook mode remains legacy until
this explicit installation command is run. An older Signet binary without the
integration protocol must be upgraded before selecting modern Kindex coexistence;
otherwise retain the legacy integration instead of bypassing an active policy.

To try it from a reviewed source checkout after `cargo build`, start a new Claude
session with the explicit plugin directory and options:

```bash
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude \
  --plugin-dir /absolute/path/to/signet-eval/adapters/claude-function \
  --settings '{"pluginConfigs":{"signet-eval-functions":{"options":{"enabled":true,"executable":"/absolute/path/to/signet-eval/target/debug/signet-eval"}}}}'
```

This is an opt-in invocation, not an installer. Global/session disabled state is
still honored. Every enforcement callback reads the current session ID and actual
working directory and requests a fresh owner description. This works when
`session.start` was skipped, including hot reload and resumed sessions; startup
failure is reported but never stored as a permanent conflict. The adapter checks
protocol version 1 and owner `signet-eval` before trusting any description.
Confirmed disabled state delegates neutrally even if the adapter revision is stale
or legacy handlers remain. Active state requires the matching adapter revision
and zero detected legacy handlers on every callback.

Missing binaries, malformed replies, invalid policy, paused enforcement and
adapter conflicts block tool effects with fixed diagnostic categories. Diagnostics
never copy subprocess stderr or arbitrary describe-response reason text. Valid
policy ask/deny decisions retain their policy explanation. Run
`signet-eval status` in a terminal to inspect the selected owner. Each subsequent
callback checks again, so restoring the owner or correcting a conflict recovers
without a restart. An engine policy allow delegates to the normal host permission
flow; it does not synthesize `allow:true`. Policy ask and deny remain ask and deny;
advisory context does not grant permission.

The prompt channel remains available for human recovery. When owner checks fail,
the adapter displays the failure and still attempts the vault-independent
sanitizer. If sanitation also fails, it forwards the original prompt with an
explicit warning that Signet redaction is unavailable. This is an availability
tradeoff for recovery prompts; avoid entering secrets while that warning is
present. Confirmed disabled state forwards the original prompt neutrally.

When the host returns an error or no typed result, the adapter preserves its
sanitized error text in the denial channel, including the underlying policy
explanation. It never turns an error into a successful typed tool result.

Once the host tool call has returned, a sanitizer failure withholds its result and
reports the post-execution phase. It never calls the tool again. Host exceptions
propagate as host exceptions rather than being mislabeled as a pre-execution
Signet outage; inspect actual effects before retrying.

Claude may skip a plugin that fails to load, throws outside a handled callback,
or violates its hook schema. Plugins are therefore a cooperative host boundary,
not an independent mandatory security monitor.

## Redaction boundary

The Rust `signet-redaction-v1` sanitizer masks known credential formats, private
keys, labeled credentials, and sensitive structured fields. It preserves hashes
and non-secret structural values. It does not treat every high-entropy string,
email address, or IP address as a secret; arbitrary secrets cannot be guaranteed
detectable. It neither stores a secret-handle map nor reinserts credentials into
arbitrary commands.

| Controlled surface | Behavior |
| --- | --- |
| Action ledger / MCP proxy parameter summaries | Sanitize structured data before truncation and persistence |
| Preflight violation summaries | Sanitize at the vault SQL sink |
| New preflight definitions | Reject detected secrets; never rewrite constraint semantics |
| Admission ledger | Store input/scope digests and receipts, never raw task arguments |
| Reported task outcomes | Sanitize before persistence; keep original digest as evidence binding |
| Function `prompt.submit` | Sanitize model/main-transcript prompt projection when available; warn and preserve recovery prompts if sanitation fails |
| Function `tool.call` | Replace successful result with a fresh sanitized, host-validated result; return safe error text on failed calls |

This is **not all-log or all-transcript protection**. The tested Claude path writes
the original prompt to a queue/enqueue transcript row before `prompt.submit`.
Assistant output, host telemetry/debug timing, third-party logs and existing
transcripts/backups are not covered. Legacy command hooks cannot rewrite tool
output. Historical disk cleanup and credential rotation are separate operations.
`integration describe` always reports `host_redaction.ready:false`: CLI presence
does not prove a plugin is loaded in this session. Kindex owns sanitation of its
own data sinks and must not register a duplicate host redactor.

Explicit native `Read`, `Grep` and `Glob` can inspect hook settings. `Write`,
`Edit` and `Bash` still require the settings-change check. A shell command merely
mentioning `settings.json` can still ask: this adapter does not attempt to prove
arbitrary shell text read-only. Other binary/directory self-protection is unchanged.

## Executable self-protection

The locked `protect_signet_binary` rule uses `protected_binary_reference()` to
inspect command fields (`command`, `cmd`, `CommandLine`) and file targets
(`file_path`, `path`, `target_file`, `TargetFile`, `destination`). It does not scan
arbitrary content, issue text, or repository identifiers for the product name.
A non-match grants no permission: remaining policy rules still evaluate.

The guard recognizes `/opt/homebrew/bin`, `/usr/local/bin`, and `.cargo/bin`
executable locations, including slash/backslash forms, common home-directory
spellings, `.exe` names, and simple redundant dot/cancelled path segments.
References to those installed paths are conservatively protected even in shell
read commands. Direct executable invocations (including through ordinary `env`, `command`,
`exec`, `sudo`, leading variable assignments, and literal
`sh`/`bash`/`zsh`/`dash`/`ksh` command strings using `-c`, `-lc`, or `-ec`) and common file mutations targeting
a relative executable basename are also protected, since the working directory
could be an installation directory. Structured relative executable targets are
protected for the same reason.

Command checks also scan a conservative quote/escape-stripped projection after
checking the original text; this can only add denials. The original input still
reaches every other rule, and structured target paths are never transformed.

This is a bounded lexical guard, not shell parsing or resolved-path security.
Quoted shell examples containing command separators can conservatively match;
encoded commands, arbitrary wrappers, uncommon installation directories, shell
expansion and filesystem aliases are not completely modeled. Existing directory,
symlink, process, identity and destructive-operation rules remain independent.

## Kindex admission protocol

All four `integration` subcommands accept JSON stdin and return one JSON object.
Inputs are bounded to 4 MiB; invalid input returns fixed errors without echoing it.
Protocol version is `1`; adapter revision is `claude-functions-2.1.280-v1`.

`describe` accepts `{session_id, project_path, agent}`. `project_path` is the
absolute actual worktree directory, not the main checkout returned by Claude's
repository metadata. The report includes owner, binary/adapter/sanitizer version,
effective policy SHA256, disabled/paused/invalid state, legacy-handler count, and
scope-bound task-enforcement readiness. It neither changes settings nor creates
or migrates a vault database. Missing scope cannot claim task readiness.

`adjudicate` accepts:

```json
{
  "protocol_version": 1,
  "operation_id": "stable-caller-id",
  "session_id": "session-id",
  "project_path": "/absolute/worktree",
  "agent": "claude",
  "policy_revision": "sha256-from-describe",
  "source_tool": "TaskCreate",
  "source_input": {"subject": "Follow up"},
  "target_tool": "kindex.task.create",
  "input": {
    "operation": "create",
    "args": {"title": "Follow up", "operation_id": "stable-caller-id"},
    "scope": {"session_id": "session-id", "project_path": "/absolute/worktree", "agent": "claude"},
    "source_input": {"subject": "Follow up"}
  }
}
```

Targets are `create`, `get`, `list`, `update`, `complete`, `cancel`, `claim`,
`release`, and `reconcile`. Exact native task-state mappings or canonical Kindex
target identities are required; `Agent`, `TaskOutput`, `TaskStop`, arbitrary MCP
destinations, and arbitrary processes are not delegation inputs.

Only the compiled `prefer_persistent_task_store` rule is omitted when evaluating
the admitted native source. All other source rules, the canonical MCP target,
the semantic target and active preflight constraints remain enforced. Any refusal
wins. ASK requires separate human authorization; this protocol cannot grant it.
No advisory command runs during admission.

Native calls require their exact original `source_input`, identical in the outer
envelope and `input.source_input`. Source rules see native fields such as
`subject`; target rules see task fields such as `title`. This raw source crosses
only the trusted local policy stdin; the integration does not write its plaintext
to its logs, model providers or data stores. This does not control operating-system
process inspection, memory, swap or crash dumps.
Sanitized target arguments describe the actual effect. The receipt input digest
binds both, with an additional source-input digest. Substituting a redacted source
would silently weaken policy rules matching the original value.

An allow is durably committed to `SIGNET_DIR/integration.db` before being returned.
The receipt binds operation, exact input digest, canonical scope, effective policy
revision and a 30-second admission lifetime. Concurrent exact retries return one
receipt; changed input under the same scoped ID conflicts. IDs are namespaced by
project, session, agent and optional explicit profile. Disabled/changed policy and
expired authorization refuse new effects. Kindex must query its committed result
receipt before seeking fresh admission for a retry; never retry by fuzzy title.

Digests use SHA256 over sorted-key, compact UTF-8 JSON without Unicode
normalization. Tool identities and scope identifiers are exact/ASCII-validated;
free-text policy conditions evaluate the original Unicode text. Digests are not
encryption: a receipt holder can test guesses for low-entropy input. The local
SQLite ledger is not hash-chained or tamper-evident against its filesystem owner.
Kindex validates the owner, protocol, input/scope/source/target binding, revision
and lifetime before a new task effect; Signet validates the exact stored receipt
when accepting an outcome.

`record-result` accepts `{protocol_version:1, operation_id, receipt, task_receipt}`.
The Signet receipt must exactly match the ledger, and the reported task receipt
must carry the same operation ID. It accepts delayed delivery after expiry or
disablement, but conflicting outcomes fail. Its evidence is explicitly
`reported_task_receipt`, not verified successful execution. Kindex commits this
delivery to an outbox atomically with the task result so an unavailable Signet
process does not turn a committed task into a duplicate retry.

## Offline verification

```bash
cargo test
python3 tests/claude_function_host.py
python3 tests/claude_function_host.py --installed-plugin
python3 tests/claude_function_host.py --kindex-plugin /absolute/kindex/src/kindex/claude_modern
```

The host fixture uses the installed Claude executable, a local synthetic provider,
synthetic secrets and new temporary Git/config/vault directories. It retains
artifacts for inspection and does not load user hooks, MCP servers or credentials.
