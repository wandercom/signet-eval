import type { Register } from "claude-code";

const REVISION = "claude-functions-2.1.274-v1";
const FAILURE = "Signet-eval is unavailable for this operation. Reconfigure the selected owner; do not bypass it.";

export const register: Register = (on, options) => {
  if (options.enabled !== true) return;
  const executable = String(options.executable ?? "signet-eval");
  let sessionId = "";
  let conflict = true;
  on("session.start", async ($, e, next) => {
    sessionId = await $.session.id();
    // Selection happens at activation. Reading settings does not install or alter hooks.
    const result = await $.process.run([executable, "integration", "describe"], {
      stdin: JSON.stringify({session_id:sessionId, agent:sessionId, project_path:e.cwd}),
      timeoutMs:5000,
    });
    const state = JSON.parse(result.stdout);
    conflict = result.exitCode !== 0 || state.adapter_revision !== REVISION || state.legacy_handlers !== 0;
    $.ui.status(conflict ? "Signet-eval: adapter conflict" : state.active ? "Signet-eval: policy + output redaction" : "Signet-eval: disabled");
    return next(e);
  });
  on("prompt.submit", async ($, e, next) => {
    if (conflict) return {drop:FAILURE};
    try {
      const checked = await $.process.run([executable,"integration","describe"], {stdin:JSON.stringify({session_id:sessionId}),timeoutMs:5000});
      const state = JSON.parse(checked.stdout);
      if (checked.exitCode !== 0) return {drop:FAILURE};
      if (state.disabled === true) return next(e);
      if (!state.active || state.adapter_revision !== REVISION) return {drop:FAILURE};
      const sanitized = await $.process.run([executable,"integration","redact"], {stdin:JSON.stringify({value:e.text}),timeoutMs:5000});
      const response = JSON.parse(sanitized.stdout);
      if (sanitized.exitCode !== 0 || response.sanitizer_revision !== "signet-redaction-v1" || typeof response.value !== "string") return {drop:FAILURE};
      return next({...e,text:response.value});
    } catch { return {drop:FAILURE}; }
  });
  on("classic.PreToolUse", async ($, e, next) => {
    if (conflict) return {deny:FAILURE};
    try {
      const {tool, tool_use_id, ...tool_input} = e;
      const output = await $.process.run([executable], {
        stdin:JSON.stringify({hook_event_name:"PreToolUse",tool_name:tool,tool_input,session_id:sessionId,cwd:await $.session.cwd()}),
        timeoutMs:10000,
      });
      if (output.exitCode !== 0) return {deny:FAILURE};
      const decision = JSON.parse(output.stdout).hookSpecificOutput;
      if (decision?.permissionDecision === "deny") return {deny:String(decision.permissionDecisionReason ?? "Denied by Signet-eval")};
      if (decision?.permissionDecision === "ask") return {ask:String(decision.permissionDecisionReason ?? "Signet-eval requires approval")};
      if (decision?.permissionDecision !== "allow") return {deny:FAILURE};
      const result = await next(e);
      // An engine policy allow does not grant host permission or erase another hook's decision.
      const context = decision.additionalContext;
      return typeof context === "string" && context ? {...result,additionalContext:[...(result.additionalContext ?? []),context]} : result;
    } catch { return {deny:FAILURE}; }
  });
  on("tool.call", async ($, e, next) => {
    if (conflict) return {deny:FAILURE};
    try {
      const stateOutput = await $.process.run([executable,"integration","describe"], {stdin:JSON.stringify({session_id:sessionId}),timeoutMs:5000});
      if (stateOutput.exitCode !== 0) return {deny:FAILURE};
      const state = JSON.parse(stateOutput.stdout);
      if (state.disabled === true) return next(e);
      if (!state.active || state.adapter_revision !== REVISION) return {deny:FAILURE};
      const result = await next(e);
      const sanitized = await $.process.run([executable,"integration","redact"], {stdin:JSON.stringify({value:result}),timeoutMs:5000});
      if (sanitized.exitCode !== 0) return {deny:"Tool ran, but output sanitization failed; its result was withheld."};
      const output = JSON.parse(sanitized.stdout);
      if (output.protocol_version !== 1 || output.sanitizer_revision !== "signet-redaction-v1") return {deny:"Tool ran, but sanitizer response was invalid; its result was withheld."};
      const safe = output.value;
      if (safe.deny !== undefined) return {deny:safe.deny};
      // Fresh builtin answers are output-schema-validated even after core failed.
      // Use the host's error channel instead of treating error text as a typed result.
      if (safe.isError || safe.result === undefined) return {deny:typeof safe.text === "string" ? safe.text : "The tool did not complete successfully; no safe result is available."};
      return {result:safe.result,...(safe.context ? {context:safe.context} : {})};
    } catch { return {deny:"Signet-eval could not finish this call; execution outcome is unknown. Inspect its operation receipt before retrying."}; }
  });
};
