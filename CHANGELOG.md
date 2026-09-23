# Changelog

## [Unreleased]

### Fixed
- Restored MCP proxy and management server builds with rmcp 2 by using its renamed text-content constructor.
- The optional Claude function adapter loads again. Claude Code 2.1.274 names settings-hook events under `classic.` and refuses a hooks module that registers the bare `PreToolUse` event, so on that build the whole module failed to load. Because `install-modern` retires the legacy command hooks, Claude sessions then ran with no Signet enforcement at all. The adapter now registers `classic.PreToolUse`, which keeps the same input envelope and `allow` / `ask` / `deny` result.

### Changed
- The function adapter is qualified against Claude Code 2.1.274 instead of 2.1.263. `integration install-modern` now requires 2.1.274, and the adapter revision is `claude-functions-2.1.274-v1`. An installed adapter reports a conflict until the binary and plugin are both upgraded, so rerun `signet-eval integration install-modern` after installing this release.

## [3.12.2] - 2026-08-27

### Added
- Added a ready-to-use Antigravity hook configuration at `hooks/antigravity-hooks.json`, plus setup and protocol documentation in the README and project site.
- Added regression coverage for live Antigravity command, file, multi-edit, MCP, allow, deny, spoofed-identity, and malformed-input payloads. The `test` CLI now exercises the same adapter parser as hook mode.

### Fixed
- Antigravity now parses its native nested `toolCall.name` and `toolCall.args` payload instead of treating valid requests as malformed, and emits Antigravity-native top-level `decision` / `reason` responses.
- Native Antigravity commands and file operations are normalized to Signet's canonical `Bash`, `Read`, `Write`, `Edit`, and `MultiEdit` policy fields so existing protections apply without Antigravity-specific duplicate rules.
- Antigravity `call_mcp_tool` requests now evaluate as canonical `mcp__<server>__<tool>` calls with unwrapped arguments. The native wrapper remains authoritative over lookalike fields, and incomplete or malformed wrappers fail closed.

## [3.12.1] - 2026-08-01

### Added
- Restored `github_identity_guard` as a shipped default covering Git remote operations (including option-bearing commands) and `gh` commands. Its trusted `gh-identity-matches-remote` script is embedded in the binary and installed atomically on first matching evaluation.
- Added locked `require_kindex_engagement_before_edits`, which denies direct edit tools unless tag/search/context engagement appears in the last 200 allowed ledger actions. It is a deny-on-missing precondition so successful engagement cannot bypass later safety or user rules.

### Changed
- Restored locked `prefer_persistent_task_store` to hard denial with Kindex task tools as the durable alternative.
- Existing system-policy snapshots are reconciled with current compiled defaults by rule name on every load. New protections therefore apply after a binary upgrade without rewriting human-authored extra system rules.
- The identity guard uses the remote-owner keyed, per-process GitHub account model and explicitly rejects global account switching as remediation.

### Fixed
- ENSURE checks now receive the normalized tool call on stdin and the shipped identity check receives command/workdir context directly. Explicit clone URLs and `--repo` targets can no longer silently fall back to the current checkout's remote.
- The identity guard remains after destructive Bash defaults, preventing a passing identity check from authorizing a force-push or another command blocked earlier in the policy.
- Allowed-action ledger entries now carry the client session identifier, and `has_recent_action` prerequisites only inspect that same session. The locked Kindex edit prerequisite additionally requires a distinct host-supplied session identifier, failing closed when only the legacy working-directory fallback or no identifier is available; an orientation action from another concurrent agent window can no longer satisfy it.

## [3.12.0] - 2026-06-13

### Added
- Added Antigravity and OpenCode hook adapters.

### Changed
- Changed the persistent-task-store rule from deny to ask. Version 3.12.1 restores the intended hard denial.

## [3.11.1] - 2026-05-29

### Fixed
- Scoped preflight state to real client chat/session identifiers before falling back to `SIGNET_SESSION`, preventing two agent windows in the same repository from sharing a preflight unintentionally.
- Hook evaluation now extracts session identifiers from client payloads and applies them process-locally for preflight, pause, and disable checks.
- Session-scoped preflights no longer deactivate global preflights or preflights from other sessions; active lookup prefers the exact session before an explicit global preflight.


## [3.11.0] - 2026-05-15

### Added
- **`INJECT` rule action** — 6th `Decision` variant alongside `ALLOW`/`DENY`/`ASK`/`GATE`/`ENSURE`. Inject rules emit advisory context strings into the agent's stream via the hook's existing `additionalContext` channel (Claude) or appended to the `message` field with a `[nudge]` delimiter (Codex `PermissionRequest`). Non-authoritative: the first-match-wins auth pass is unchanged; inject rules are evaluated in a separate post-auth pass that collects payloads from all matching rules.
- Recency-weighted probability with four trigger modes: `constant`, `step` (alias for constant), `linear` (ramps from 0 to `peak` over `peak_after_seconds`), `exponential` (`peak * (1 - exp(-(t-cooldown)/peak_after_seconds))`). Per-rule state persisted in new `injection_state` SQLite table (`rule_name`, `last_fired_ts`, `session_fires`, `session_start`).
- Four payload sources: `text:` (inline literal), `text_file:` (bare filename under `~/.signet/injections/`, no path separators or traversal), `from_command:` (entry name against HMAC-signed `~/.signet/inject_commands.yaml` allowlist, direct `execve` with no shell, env scrubbed to `PATH` only, 2s wall-clock timeout, 64KB stdout cap), plus optional template substitutions (`{tool_name}`, `{cwd}`, `{date}`, `{matched_param.X}`).
- **Load-time fast path**: when the loaded policy contains zero `INJECT` rules, the inject pass is skipped entirely (no SQL queries, no allocations). Zero overhead for users who don't author inject rules.
- HMAC integrity for the inject command allowlist: `signet-eval sign` extends to `~/.signet/inject_commands.yaml`; loading fails closed when a vault is set up but the allowlist HMAC sidecar is missing or invalid.
- CLI: `signet-eval injections` shows recent inject fires (`rule`, `session#`, `last fired`). `signet-eval inject-test <rule>` force-fires a single inject rule for testing, ignoring probability and cooldown.
- Validation: `signet-eval validate` rejects inject rules with `peak` outside `[0.0, 1.0]`, negative `cooldown_seconds`, non-positive `peak_after_seconds`, wrong number of payload sources, or unsafe `text_file` paths. `validate --fix` clamps the numeric ranges.
- `examples/inject_examples.yaml` — generic schema templates demonstrating the four trigger modes, payload sources, and template substitutions. Tool ships with no locked or default inject rules; behavioral shaping is entirely user-configured.
- Adversarial tests in `policy::goodhart_tests` covering substring false-positive prevention (`test_block_rm_does_not_false_positive_on_substring_words`), real-rm-invocation coverage (`test_block_rm_still_blocks_real_rm_invocations`), and shell-metacharacter prefix handling (`test_block_rm_handles_rm_at_token_start_in_pipes_and_subshells`).

### Fixed
- **`block_rm` false positives on substring word collisions.** The default `block_rm` rule used `contains(parameters, 'rm ')` — an unanchored substring match that denied any Bash command whose serialized parameters contained the bytes `rm ` as a substring. This produced false positives on benign commands navigating paths or words like `drone_swarm`, `firmware`, `transform`, `arm-toolchain`, `farm`, `warm`, `harmless`, `germ`, and many others. Real failure surfaced when `ls ~/Code/drone_swarm` and `find ~/Code/drone_swarm -name '*.py'` were both denied as "file deletion." The rule now uses `matches(parameters, '\brm\b')` — word-boundary anchored — which still blocks every real `rm` invocation (including those chained through shell metacharacters `;`, `&&`, `||`, `|`, `(`, `$(...)`) while eliminating the substring false positives.
- **`matches(parameters, …)` semantics.** The `matches` condition function previously looked up `parameters` as a literal field name in the JSON object — which always returned empty since the JSON's top-level keys are the parameter names themselves (e.g., `command`), not `parameters`. The function now special-cases the `parameters` field to run the regex against the full serialized parameter JSON, mirroring the existing `contains(parameters, ...)` semantics. Any other field name continues to be looked up by name. This makes `matches(parameters, ...)` actually usable as a regex equivalent of `contains(parameters, ...)`.

### Notes
- The inject pass introduces signet-eval's first non-determinism — `rand::thread_rng` rolls for each matched rule. Strictly scoped to advisory output; the authorization pass remains fully deterministic and reproducible.
- All 17 existing MCP tools (`signet_add_rule`, `signet_edit_rule`, …) accept the new `inject` block via the existing PolicyRule serde schema. Auto-sign continues to work after MCP mutations.

## [3.10.1] - 2026-05-08

### Fixed
- `load_merged_policy` no longer drops user rules from `rules.yaml` when the system `policy.yaml` is missing or malformed. Previously this branch returned `default_policy()` and silently discarded every user rule, so on hosts without a per-host system policy both `signet_test` *and* real hook enforcement were no-op for user-installed rules. Missing/malformed system policy now falls back to the hardcoded baseline (self-protection + system defaults) and still merges user rules on top.
- Three regression tests added covering missing system policy, missing system policy with self-protection preserved, and malformed system policy with user rules preserved.

### Added
- New locked default rule `prefer_persistent_task_store`: denies Anthropic's session-local `Task*` tool family (`TaskCreate` / `TaskUpdate` / `TaskList` / `TaskGet` / `TaskOutput` / `TaskStop`) and routes the agent to a persistent task store such as kindex's `mcp__kindex__task_*`. Ships locked so it cannot be silently overridden by an unlocking user rule.

## [3.10.0] - 2026-05-03

### Added
- Codex hook adapter support via `--adapter codex` and `--adapter codex-permission`.
- Codex `PreToolUse` mapping: `DENY` emits Codex deny JSON, `ALLOW` emits no output, and `ASK` maps to deny because Codex does not yet enforce `ask` at `PreToolUse`.
- Codex `PermissionRequest` mapping: explicit allow/deny decisions, with Signet `ASK` deferring to Codex's normal approval prompt.
- Codex hook configuration example at `hooks/codex-hooks.json`.
- Integration tests covering Codex `PreToolUse` and `PermissionRequest` response shapes.

### Changed
- CLI description and docs now describe signet-eval as agent-agnostic policy enforcement for Claude Code and Codex.

## [3.8.0] - 2026-04-02

### Added
- `validate --fix` CLI flag — auto-fixes clampable issues (gate.within, ensure.timeout clamping) and removes broken unlocked rules; writes updated policy and re-signs if vault exists
- `validate --fix --dry-run` — previews what --fix would change without writing to disk
- `status` now shows complete enforcement state: global disable, disabled sessions, global pause with expiry, per-rule/per-session pauses with timestamps
- `status` shows enforcement overrides even without a vault (file-based state is independent)

### Fixed
- `enable` (no flags) now clears both global disable AND all session disables in one invocation; previously required running twice if both existed
- `status` no longer returns exit code 1 when vault is not set up — enforcement info is still useful without a vault

## [3.6.0] - 2026-04-01

### Changed
- `github_identity_guard` moved from self-protection (locked) to default policy (unlocked) — no longer blocks git operations on fresh installs without the check script
- `validate_policy()` returns structured `ValidationDiagnostic` with severity (Error/Warning), actionable `fix_hint`, and `auto_fixable` flag
- MCP `signet_validate` tool shows actionable fix hints per diagnostic; accepts `fix=true` to auto-repair broken rules
- CLI `signet-eval validate` displays ERROR/WARN with fix instructions

### Added
- `fix_policy()` function — auto-removes broken unlocked rules, clamps out-of-range gate.within and ensure.timeout; never touches locked rules
- Ensure script existence and executable checks (Warning-level diagnostics)
- `has_recent_action` added to KNOWN_CONDITION_FNS (was implemented but missing from validation whitelist)
- Graceful ensure resolution for unlocked rules: missing script = allow (locked rules still fail-closed)

## [3.5.0] - 2026-03-28

### Added
- `has_recent_action('search', within)` condition function -- searches both tool name and detail columns in the action ledger; supports pipe-delimited OR for multiple search terms
- `require_plan_before_code` default rule -- ASKs before Edit/Write/NotebookEdit if no recent EnterPlanMode or TaskCreate action in the ledger
- `protect_core_files` default rule -- ASKs before Edit/Write on paths matching core/dsl/schema/engine patterns

### Changed
- GATE action `has_recent_allowed_action()` now searches both `tool` and `detail` columns (was detail-only, so tool-name-based gates silently failed)
- GATE `requires_prior` supports pipe-delimited OR: `"EnterPlanMode|TaskCreate"` matches either term

### Note
The `require_plan_before_code` rule fires before other Edit/Write rules (first-match-wins). Without a logged plan, agents see "Present a plan" before any other edit-related rule.

## [3.4.0] - 2026-03-27

### Fixed
- Default policy tool patterns were overbroad (matched substrings instead of exact tool names)
- `query` subcommand output now goes to stdout instead of stderr

## [3.3.0] - 2026-03-22

### Added
- Gate and Ensure action types for prerequisite enforcement
- Claude Code plugin structure
