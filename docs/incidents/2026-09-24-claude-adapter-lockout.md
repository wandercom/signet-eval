# Claude adapter lockout, 2026-09-24

## Observed failure

At 04:29-04:44 UTC, multiple Claude 2.1.280 sessions rejected ordinary tool
calls and dropped prompts with the same generic Signet unavailable message.
The action ledger contains an allowed call at 04:29:05 UTC; the later rejected
calls were not recorded. The adapter rejected them before policy evaluation.
The original triggering fault is not established: the old adapter emitted no
reason category. No evidence establishes that vault unlock was necessary.

During investigation the live CLI was reachable, enforcement was globally
disabled, the vault was unlocked, and affected directories reported no legacy
handler conflict. Fresh active and disabled host probes also passed before
repair. Those checks do not explain the earlier outage.

## Confirmed defects and repair

The adapter initialized a registration-local conflict flag to true and updated
it only during session.start. An exception, missing lifecycle initialization,
or conflict persisted across later callbacks. All callbacks checked that flag
before the current disabled state; prompt failures discarded the recovery
channel as well. Validity failures and transport errors shared one diagnostic.

Each callback now reads current session scope and owner state. Only a fresh,
protocol-valid Signet response can establish disabled state. Disabled is neutral
before revision/coexistence checks; active invalid/missing owners and legacy
conflicts still block tool effects. Failed checks are not cached. Policy denial
and approval explanations are retained; transport failures use fixed categories
without echoing raw errors. Sanitization after a tool effect withholds failed
results and never retries execution.

Human prompts remain available during policy outages. The adapter attempts the
vault-independent sanitizer; if that fails it warns that the prompt will be sent
without Signet redaction. This is an explicit availability tradeoff for the
recovery channel, not a guarantee of prompt secrecy. Active tool effects retain
their enforcement and output-sanitation checks.

The binary and adapter use paired revision claude-functions-2.1.280-v1. The
installer accepts exact host builds 2.1.274 and 2.1.280. The earlier build retains
installer compatibility; only 2.1.280 was host-tested during this repair.

## Verification

- Independent callback suite: original adapter 11/56; repaired adapter 56/56.
  The fixture's initial session API mismatch was corrected before these results.
- Installer regression: original rejected 2.1.280; repaired installation passes
  and preserves explicit disablement and foreign hooks.
- Rust suite: 250 passed with MCP; 250 passed without MCP, release profile,
  locked dependencies, one test thread.
- Real Claude 2.1.280, synthetic local provider and isolated configuration:
  active redaction, disabled neutrality, disablement before a tool, installed
  plugin, and Kindex explicit task-denial paths passed.
- Claude plugin validation passed, including host module checking.
- Three safety mutations were rejected by the recovery suite: accepting a
  foreign owner as disabled, ignoring legacy conflict, and returning raw output.
- Independent bounded code/security review found no concrete defects.

The fresh host probes and injected-failure tests verify the repair's behavior;
they are not proof that an already-running affected user session recovered.
Local installation preserves existing disabled state and backs up the old
binary, settings and plugin. Existing loaded Claude sessions may need plugin
reload or restart to load the new code. No hosted CI or release is claimed.

## Local installation outcome

The repaired binary and embedded plugin were installed successfully. Installed
plugin SHA256: `1a53421c8201a1641a3bd3882ee55b87ea77d2471b367032fcba3a13f94329c2`.
The installed plugin exactly matches tested source; effective Claude settings
compare equal before and after installation. Enforcement remains globally
disabled, as found. The live protocol reports paired revision 2.1.280-v1 and no
legacy handlers. A fresh real Claude 2.1.280 smoke test using the actual installed
binary and plugin passed with isolated disabled state and executed its Bash tool.
Existing affected sessions have not been directly reloaded or verified.

## Follow-up: masked policy denial and repository-name false positive

The operator reported `tool_result_unavailable` after the first repair. The live
ledger proves three rejected Bash calls at 15:45:54, 15:46:00, and 15:46:03 UTC
were DENY decisions before execution. The binary guard matched the repository
name in commands. The new adapter then replaced the inner host error text with
a generic message; the initial recovery suite had not covered this nested path.

The other agent subsequently created issues 17 and 18 through GraphQL at 15:47
UTC; a read-only GitHub query verified they exist. No issue creation was retried
by this repair session.

The adapter now returns the sanitized inner host text through the host error
channel. It does not fabricate a successful typed result or retry execution.
A real-host regression failed on the previous adapter and passed after repair:
the refusal reason remains visible and the denied command creates no marker.
A second real-host test executes a failing command exactly once, retains its
error explanation, and redacts the synthetic credential from that explanation.

The locked binary rule now uses a deterministic `protected_binary_reference()`
condition over command and target-path fields. Repository paths, GitHub repo
identifiers, and file content do not trigger binary protection merely by naming
the project. Known installed executable paths, relative binary mutation targets,
and direct executable invocations remain guarded; later identity, destructive,
and other user rules still evaluate. Static patterns are cached. A conservative
secondary command projection covers simple quoting and escaping while original
inputs and structured target strings stay unchanged. This is a bounded lexical
guard, not complete shell interpretation or an OS execution boundary.

Independent review identified and the implementation corrected simple cases
with global CLI options, leading assignments, additional administrative
subcommands, and quoted/escaped installed path segments. The final review found
no remaining concrete defect within that scope. Both issue-described GitHub
identity-guard defects are separate from this source-name guard correction.

Follow-up installation completed with backups. Installed adapter SHA256:
`1eca1590f20d10004775e87ee5fc294990b2ffe58ee6e179233e80b0790546b4`.
The installed bytes match source, effective Claude settings are unchanged, and
existing global disablement remains set. Final release suites: 255 passed with
MCP and 255 without. Callback suites: prior 56/56 plus host-error 8/8. Fresh real
Claude tests using the actual installed binary and plugin passed both the
policy-denial/no-effect and execution-error/exactly-once cases. The installed
source remains local and uncommitted; no hosted CI or release is claimed.
