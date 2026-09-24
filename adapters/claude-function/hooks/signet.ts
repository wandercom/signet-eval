import type { Register } from "claude-code";

const REVISION = "claude-functions-2.1.280-v1";

// Only fixed categories leave this parser: owner-provided error/reason text is
// never a diagnostic. Disabled is neutral even across adapter upgrades.
function ownerState(stdout: string): string {
  try {
    const state = JSON.parse(stdout);
    if (!state || typeof state !== "object" || Array.isArray(state)) return "invalid_response";
    if (state.protocol_version !== 1) return "protocol_mismatch";
    if (state.owner !== "signet-eval") return "owner_mismatch";
    if (typeof state.active !== "boolean" || typeof state.disabled !== "boolean" || (state.active && state.disabled)) return "invalid_response";
    if (state.disabled) return "disabled";
    if (!state.active) {
      if (state.reason === "policy_invalid") return "policy_invalid";
      if (state.reason === "policy_unreadable") return "policy_unreadable";
      if (state.reason === "policy_integrity_failed") return "policy_integrity_failed";
      if (state.reason === "vault_unavailable") return "vault_unavailable";
      if (state.reason === "paused") return "paused";
      return "owner_inactive";
    }
    if (state.adapter_revision !== REVISION) return "adapter_revision_mismatch";
    if (state.legacy_handlers !== 0) return "legacy_handler_conflict";
    return "active";
  } catch { return "invalid_response"; }
}

function blocked(state: string): string {
  return `Signet-eval: ${state}. Tool execution is blocked. Run signet-eval status in a terminal to inspect the selected owner; callbacks recheck automatically.`;
}

export const register: Register = (on, options) => {
  if (options.enabled !== true) return;
  const executable = String(options.executable ?? "signet-eval");
  on("session.start", async ($, e, next) => {
    let state = "scope_unavailable";
    try {
      const sessionId = await $.session.id();
      const cwd = await $.session.cwd();
      if (sessionId && cwd) {
        state = "owner_unavailable";
        const output = await $.process.run([executable,"integration","describe"], {
          stdin:JSON.stringify({session_id:sessionId,agent:sessionId,project_path:cwd}),timeoutMs:5000,
        });
        if (output.exitCode === 0) state = ownerState(output.stdout);
      }
    } catch { /* Report this attempt; never latch failure into later callbacks. */ }
    $.ui.status(state === "active" ? "Signet-eval: policy + output redaction" : state === "disabled" ? "Signet-eval: disabled" : blocked(state));
    return next(e);
  });
  on("prompt.submit", async ($, e, next) => {
    let state = "scope_unavailable";
    try {
      const sessionId = await $.session.id();
      const cwd = await $.session.cwd();
      if (sessionId && cwd) {
        state = "owner_unavailable";
        const output = await $.process.run([executable,"integration","describe"], {
          stdin:JSON.stringify({session_id:sessionId,agent:sessionId,project_path:cwd}),timeoutMs:5000,
        });
        if (output.exitCode === 0) state = ownerState(output.stdout);
      }
    } catch { /* Human recovery stays available while tools remain guarded. */ }
    if (state === "disabled") {
      $.ui.status("Signet-eval: disabled");
      return next(e);
    }
    $.ui.status(state === "active" ? "Signet-eval: policy + output redaction" : blocked(state));
    // The sanitizer needs no vault and can still work during a policy outage.
    let text = e.text;
    let sanitized = false;
    try {
      const output = await $.process.run([executable,"integration","redact"], {stdin:JSON.stringify({value:e.text}),timeoutMs:5000});
      if (output.exitCode === 0) {
        const response = JSON.parse(output.stdout);
        if (response?.protocol_version === 1 && response.owner === "signet-eval" && response.sanitizer_revision === "signet-redaction-v1" && typeof response.value === "string") {
          text = response.value;
          sanitized = true;
        }
      }
    } catch { /* Preserve the recovery prompt with an explicit warning below. */ }
    if (!sanitized) $.ui.status(`Signet-eval: prompt_sanitizer_unavailable. This prompt will be sent without Signet redaction. ${state === "active" ? "Tool calls will recheck policy." : blocked(state)}`);
    return next({...e,text});
  });
  on("classic.PreToolUse", async ($, e, next) => {
    let state = "scope_unavailable";
    let sessionId = "";
    let cwd = "";
    try {
      sessionId = await $.session.id();
      cwd = await $.session.cwd();
      if (sessionId && cwd) {
        state = "owner_unavailable";
        const output = await $.process.run([executable,"integration","describe"], {
          stdin:JSON.stringify({session_id:sessionId,agent:sessionId,project_path:cwd}),timeoutMs:5000,
        });
        if (output.exitCode === 0) state = ownerState(output.stdout);
      }
    } catch { /* No tool effect has run. */ }
    if (state === "disabled") return next(e);
    if (state !== "active") return {deny:blocked(state)};
    let context = "";
    let failure = "policy_owner_unavailable";
    try {
      const {tool, tool_use_id, ...tool_input} = e;
      const output = await $.process.run([executable], {
        stdin:JSON.stringify({hook_event_name:"PreToolUse",tool_name:tool,tool_input,session_id:sessionId,cwd}),timeoutMs:10000,
      });
      if (output.exitCode !== 0) return {deny:blocked(failure)};
      failure = "invalid_policy_response";
      const decision = JSON.parse(output.stdout)?.hookSpecificOutput;
      if (decision?.permissionDecision === "deny") return {deny:typeof decision.permissionDecisionReason === "string" ? decision.permissionDecisionReason : "Signet-eval: policy_denied. The selected policy denied this tool call."};
      if (decision?.permissionDecision === "ask") return {ask:typeof decision.permissionDecisionReason === "string" ? decision.permissionDecisionReason : "Signet-eval: policy_approval_required. The selected policy requires human approval."};
      if (decision?.permissionDecision !== "allow") return {deny:blocked(failure)};
      if (typeof decision.additionalContext === "string") context = decision.additionalContext;
    } catch { return {deny:blocked(failure)}; }
    // An engine allow does not grant host permission or replace host failures.
    const result = await next(e);
    return context ? {...result,additionalContext:[...(result.additionalContext ?? []),context]} : result;
  });
  on("tool.call", async ($, e, next) => {
    let state = "scope_unavailable";
    try {
      const sessionId = await $.session.id();
      const cwd = await $.session.cwd();
      if (sessionId && cwd) {
        state = "owner_unavailable";
        const output = await $.process.run([executable,"integration","describe"], {
          stdin:JSON.stringify({session_id:sessionId,agent:sessionId,project_path:cwd}),timeoutMs:5000,
        });
        if (output.exitCode === 0) state = ownerState(output.stdout);
      }
    } catch { /* No tool effect has run. */ }
    if (state === "disabled") return next(e);
    if (state !== "active") return {deny:blocked(state)};
    // Keep the host invocation outside the owner/sanitizer error handlers.
    const result = await next(e);
    let failure = "output_sanitizer_unavailable";
    try {
      const sanitized = await $.process.run([executable,"integration","redact"], {stdin:JSON.stringify({value:result}),timeoutMs:5000});
      if (sanitized.exitCode !== 0) return {deny:"Signet-eval: output_sanitizer_unavailable. Tool ran, but its result was withheld. Do not retry the tool without checking its effects."};
      failure = "invalid_sanitizer_response";
      const output = JSON.parse(sanitized.stdout);
      if (output?.protocol_version !== 1 || output.owner !== "signet-eval" || output.sanitizer_revision !== "signet-redaction-v1" || !output.value || typeof output.value !== "object" || Array.isArray(output.value)) {
        return {deny:"Signet-eval: invalid_sanitizer_response. Tool ran, but its result was withheld. Do not retry the tool without checking its effects."};
      }
      const safe = output.value;
      if (typeof safe.deny === "string") return {deny:safe.deny};
      // Fresh builtin answers are output-schema-validated even after core failed.
      // Use the host's error channel instead of treating error text as a typed result.
      if (safe.deny !== undefined || safe.isError || safe.result === undefined) return {deny:typeof safe.text === "string" ? safe.text : "Signet-eval: tool_result_unavailable. The host returned without a successful tool result; inspect its effects before retrying."};
      return {result:safe.result,...(safe.context ? {context:safe.context} : {})};
    } catch { return {deny:`Signet-eval: ${failure}. Tool ran, but its result was withheld. Do not retry the tool without checking its effects.`}; }
  });
};
