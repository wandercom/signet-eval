#!/usr/bin/env node
/**
 * Independent acceptance probes for the Claude adapter recovery repair.
 * Usage: node tests/claude_adapter_recovery.mjs /absolute/path/to/adapter.ts [--revision 274|280]
 * Node >= 23.6 strips TypeScript natively. The Tester does not execute the SUT.
 *
 * Oracle: Validator's authorized incident-repair brief, 2026-09-24:
 * R1 Genuine disabled owner is neutral on all hooks without session.start,
 *    after prior failure/conflict, and despite stale adapter revision/conflict.
 * R2 Later valid owner checks recover initialization/transient/conflict failures.
 * R3 Active legacy conflict and missing/invalid owners deny effects with safe,
 *    specific diagnosis. Only genuine protocol owner can attest disablement.
 * R4 Policy allow preserves host permissions, ask stays ask, deny stays deny.
 * R5 Policy-owner unavailability never drops the human recovery prompt; attempt
 *    sanitizer when available. No new prompt-denial rule is introduced here.
 * R6 Output sanitation failure withholds the result, never repeats the tool.
 * Existing contract: adapters/claude-function/README.md, Explicit activation,
 * Redaction boundary, and Kindex admission protocol.
 *
 * Mock ledger: process.run is the external CLI transport, with complete explicit
 * owner/sanitizer envelopes, and failure cases supplied deliberately. next is the
 * host continuation/effect counter; it is not an admission decision. ui.status
 * records diagnostics only. No adapter internals are mocked or inspected.
 * Falsifiability: R1/R2 permanent cached denial or disabling after revision check;
 * R3 fail-open/owner-blind disablement; R4 force-allow or lost ask; R5 dropped prompt;
 * R6 returning raw output or re-running next. Reachability: each effect refusal
 * requires a describe call, zero host continuations, and a structured deny.
 * Guard labels are intended classification, not observed baseline results.
 */
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const target = process.argv[2];
if (!target) throw new Error('Usage: node tests/claude_adapter_recovery.mjs /absolute/path/to/adapter.ts [--revision 274|280]');
const revisionArg = process.argv.indexOf('--revision');
const revision = revisionArg < 0 ? '280' : process.argv[revisionArg + 1];
assert(['274', '280'].includes(revision), 'supported fixture revisions: 274 or 280');
const { register } = await import(pathToFileURL(resolve(target)).href);
assert.equal(typeof register, 'function', 'adapter must expose documented register(on, options)');

const ACTIVE = Object.freeze({ protocol_version: 1, owner: 'signet-eval', adapter_revision: `claude-functions-2.1.${revision}-v1`, active: true, disabled: false, legacy_handlers: 0, reason: null });
const DISABLED = Object.freeze({ ...ACTIVE, active: false, disabled: true, reason: 'disabled' });
const FAILURE = Symbol('transport unavailable');
const MALFORMED = Symbol('malformed JSON');
const CANARY = 'private-test-value-must-not-leak';
const EVENTS = {
  'session.start': { source: 'startup' },
  'prompt.submit': { text: 'Please repair the policy owner so tools work again.' },
  'classic.PreToolUse': { tool: 'Bash', tool_use_id: 'recovery-test-call', command: 'echo hello' },
  'tool.call': { tool: 'Bash', tool_use_id: 'recovery-test-call', command: 'echo hello' },
};
const result = () => ({ result: { stdout: 'hello', stderr: '', interrupted: false } });
const response = value => ({ exitCode: 0, stdout: JSON.stringify(value), stderr: '' });
const tests = [];
const test = (name, run) => tests.push({ name, run });

function harness(initial = ACTIVE, config = {}) {
  const hooks = new Map();
  const state = { owner: initial, policy: 'allow', redact: null, calls: [], statuses: [] };
  const $ = {
    session: { async id() { return 'independent-recovery-test'; }, async cwd() { return '/synthetic/project'; } },
    process: { async run(argv, options) {
      const input = JSON.parse(options.stdin);
      const action = argv.includes('integration') ? argv[argv.indexOf('integration') + 1] : 'policy';
      state.calls.push({ action, input });
      if (action === 'describe') {
        if (state.owner === FAILURE) throw new Error(`ENOENT ${CANARY}`);
        if (state.owner === MALFORMED) return { exitCode: 0, stdout: `not-json ${CANARY}`, stderr: CANARY };
        return response(state.owner);
      }
      if (action === 'redact') {
        if (state.redact === FAILURE) throw new Error(`redaction failed ${CANARY}`);
        if (state.redact === MALFORMED) return { exitCode: 0, stdout: CANARY, stderr: CANARY };
        const value = JSON.parse(JSON.stringify(input.value).replaceAll(CANARY, '[REDACTED]'));
        return response(state.redact ?? { protocol_version: 1, owner: 'signet-eval', sanitizer_revision: 'signet-redaction-v1', value });
      }
      assert.equal(action, 'policy', `Unexpected CLI action: ${action}`);
      return response({ hookSpecificOutput: { permissionDecision: state.policy, permissionDecisionReason: `Fixture ${state.policy}`, additionalContext: '' } });
    } },
    ui: { async status(...args) { state.statuses.push(args); } },
  };
  register((name, callback) => {
    assert(!hooks.has(name), `Duplicate registration ${name}`);
    hooks.set(name, callback);
  }, { enabled: true, executable: '/synthetic/signet-eval', ...config });
  return {
    state,
    hooks,
    async invoke(name, event = EVENTS[name], hostResult = result()) {
      assert(hooks.has(name), `Missing required ${name} registration`);
      const nextCalls = [];
      const before = state.calls.length;
      const output = await hooks.get(name)($, structuredClone(event), async (...args) => {
        nextCalls.push(args);
        return hostResult;
      });
      return { output, nextCalls, calls: state.calls.slice(before), hostResult, event, ownerCalls: state.calls.filter(x => x.action === 'describe') };
    },
  };
}
function neutral(observation, requirement) {
  assert.equal(observation.nextCalls.length, 1, `${requirement}: host continuation must run once`);
  assert.deepEqual(observation.nextCalls[0], [observation.event], `${requirement}: preserve event unchanged`);
  assert.strictEqual(observation.output, observation.hostResult, `${requirement}: preserve host result unchanged`);
  assert(!observation.calls.some(x => x.action === 'policy' || x.action === 'redact'), `${requirement}: disabled policy must be neutral`);
}
function refused(observation, diagnosis, requirement) {
  assert(observation.ownerCalls.length > 0, `${requirement}: refusal must reach owner check`);
  assert.equal(observation.nextCalls.length, 0, `${requirement}: no host tool effect`);
  assert.equal(typeof observation.output?.deny, 'string', `${requirement}: structured host denial required`);
  assert.match(observation.output.deny, diagnosis, `${requirement}: diagnosis must identify the fault`);
  assert(!JSON.stringify(observation.output).includes(CANARY), `${requirement}: diagnostics must not echo unsafe transport text`);
}

for (const hook of Object.keys(EVENTS)) {
  test(`RED R1 disabled without startup: ${hook}`, async () => {
    neutral(await harness(DISABLED).invoke(hook), 'R1');
  });
  test(`RED R1 disabled wins over stale revision and legacy conflict: ${hook}`, async () => {
    const h = harness({ ...DISABLED, adapter_revision: 'older-owner-revision', legacy_handlers: 2 });
    neutral(await h.invoke(hook), 'R1');
  });
  for (const [label, bad] of [['transport failure', FAILURE], ['legacy conflict', { ...ACTIVE, legacy_handlers: 1 }]]) {
    test(`RED R1 disabled recovers after startup ${label}: ${hook}`, async () => {
      const h = harness(bad);
      await h.invoke('session.start');
      h.state.owner = { ...DISABLED, adapter_revision: 'older-owner-revision', legacy_handlers: 1 };
      neutral(await h.invoke(hook), 'R1');
    });
  }
}
for (const hook of ['classic.PreToolUse', 'tool.call']) {
  for (const [label, bad, diagnosis] of [
    ['missing binary', FAILURE, /unavailable|missing|owner|failed|cannot|unable/i],
    ['malformed JSON', MALFORMED, /malformed|invalid|protocol|unavailable|owner|failed/i],
    ['wrong owner claims disabled', { ...DISABLED, owner: 'other-service' }, /owner|protocol|invalid|unsupported|unavailable/i],
    ['wrong protocol claims disabled', { ...DISABLED, protocol_version: 999 }, /protocol|invalid|unsupported|unavailable|owner/i],
    ['invalid policy', { ...ACTIVE, active: false, reason: 'policy_invalid' }, /policy|invalid/i],
    ['legacy conflict', { ...ACTIVE, legacy_handlers: 1 }, /legacy|conflict|coexist/i],
  ]) {
    test(`GREEN R3 ${label} refuses effects: ${hook}`, async () => {
      const h = harness(bad);
      await h.invoke('session.start');
      refused(await h.invoke(hook), diagnosis, 'R3');
    });
    test(`RED R2 ${label} recovers in same session: ${hook}`, async () => {
      const h = harness(bad);
      await h.invoke('session.start');
      refused(await h.invoke(hook), diagnosis, 'R3');
      h.state.owner = ACTIVE;
      const recovered = await h.invoke(hook);
      assert.equal(recovered.nextCalls.length, 1, 'R2: subsequent valid owner must restore host continuation');
      assert.equal(recovered.output?.deny, undefined, 'R2: prior fault must not cause permanent denial');
      assert(recovered.calls.some(x => x.action === 'describe'), 'R2: recovery must use a fresh owner check');
    });
  }
}
for (const [label, bad] of [['unavailable owner', FAILURE], ['invalid policy', { ...ACTIVE, active: false, reason: 'policy_invalid' }], ['legacy conflict', { ...ACTIVE, legacy_handlers: 1 }]]) {
  for (const sanitizerFailure of [false, true]) {
    test(`RED R5 recovery prompt survives ${label}, sanitizer failure=${sanitizerFailure}`, async () => {
      const h = harness(bad);
      if (sanitizerFailure) h.state.redact = FAILURE;
      const observed = await h.invoke('prompt.submit');
      assert.equal(observed.nextCalls.length, 1, 'R5: human recovery prompt must reach host continuation');
      assert.equal(observed.nextCalls[0][0]?.text, EVENTS['prompt.submit'].text, 'R5: recovery request must not be dropped or replaced with an error');
      assert.equal(observed.output?.deny, undefined, 'R5: owner failure must not deny human prompt');
      assert(observed.calls.some(x => x.action === 'redact'), 'R5: attempt available sanitizer despite owner failure');
    });
  }
}
for (const decision of ['allow', 'ask', 'deny']) {
  test(`GREEN R4 active ${decision} preserves host permission`, async () => {
    const h = harness();
    await h.invoke('session.start');
    h.state.policy = decision;
    const observed = await h.invoke('classic.PreToolUse');
    assert(observed.calls.some(x => x.action === 'policy'), 'R4: actual policy decision must be consulted');
    if (decision === 'allow') {
      assert.equal(observed.nextCalls.length, 1, 'R4: allow delegates to host');
      assert.strictEqual(observed.output, observed.hostResult, 'R4: retain host result, do not force permission');
      assert.equal(observed.output?.allow, undefined, 'R4: policy allow must not synthesize host allow');
    } else {
      assert.equal(observed.nextCalls.length, 0, `R4: ${decision} must not silently continue`);
      assert.equal(typeof observed.output?.[decision], 'string', `R4: preserve structured ${decision}`);
    }
  });
}
for (const failure of [FAILURE, MALFORMED, { protocol_version: 1, owner: 'other-service', sanitizer_revision: 'signet-redaction-v1', value: { stdout: CANARY } }]) {
  test(`GREEN R6 output sanitizer failure ${String(failure)} withholds without rerun`, async () => {
    const h = harness();
    await h.invoke('session.start');
    h.state.redact = failure;
    const observed = await h.invoke('tool.call', EVENTS['tool.call'], { result: { stdout: CANARY, stderr: '', interrupted: false } });
    assert.equal(observed.nextCalls.length, 1, 'R6: tool executes exactly once; sanitation failure must not retry effect');
    assert(observed.calls.some(x => x.action === 'redact'), 'R6: must reach output sanitizer');
    assert(!JSON.stringify(observed.output).includes(CANARY), 'R6: raw result and error payload must be withheld');
    assert.equal(typeof observed.output?.deny, 'string', 'R6: sanitation failure must return safe host denial');
  });
}
test('GREEN R6 successful output sanitation preserves structured shape', async () => {
  const h = harness();
  await h.invoke('session.start');
  const observed = await h.invoke('tool.call', EVENTS['tool.call'], { result: { stdout: CANARY, stderr: '', interrupted: false } });
  assert.equal(observed.nextCalls.length, 1, 'R6: admitted tool executes once');
  assert.deepEqual(observed.output, { result: { stdout: '[REDACTED]', stderr: '', interrupted: false } }, 'R6: host sees sanitized replacement preserving result shape');
});

for (const hook of ['classic.PreToolUse', 'tool.call']) {
  test(`GREEN R3 legacy conflict introduced mid-session refuses: ${hook}`, async () => {
    const h = harness();
    await h.invoke('session.start');
    const initial = await h.invoke(hook);
    assert.equal(initial.nextCalls.length, 1, 'R3: healthy owner initially permits host flow');
    h.state.owner = { ...ACTIVE, legacy_handlers: 1 };
    refused(await h.invoke(hook), /legacy|conflict|coexist/i, 'R3');
  });
}
test('GREEN R4 policy evaluates original command, not sanitized projection', async () => {
  const h = harness();
  await h.invoke('session.start');
  const observed = await h.invoke('classic.PreToolUse', { ...EVENTS['classic.PreToolUse'], command: CANARY });
  const evaluations = observed.calls.filter(x => x.action === 'policy');
  assert.equal(evaluations.length, 1, 'R4: exactly one original-input policy evaluation');
  assert.equal(evaluations[0].input.tool_input.command, CANARY, 'R4 / CLAUDE.md Security Model: policy receives original input');
});

let failed = 0;
for (const { name, run } of tests) {
  try { await run(); process.stdout.write(`PASS ${name}\n`); }
  catch (error) { failed += 1; process.stderr.write(`FAIL ${name}\n${error.stack}\n`); }
}
process.stdout.write(`${tests.length - failed}/${tests.length} adapter recovery checks passed\n`);
process.exitCode = failed ? 1 : 0;
