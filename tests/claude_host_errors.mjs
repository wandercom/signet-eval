#!/usr/bin/env node
/** Independent repair contract H1-H4, Validator dispatch 2026-09-24.
 * H1 Host error/refusal string explanations remain visible after sanitation.
 * H2 Never fabricate a successful typed result; host continuation runs once.
 * H3 Raw host secrets never reach the returned value.
 * H4 Non-string host text returns a fixed safe diagnostic.
 * Mock ledger: CLI is external sanitizer/owner transport; host continuation
 * supplies documented text-shaped failures. No adapter implementation inspected.
 * Mutation witnesses: replace host explanation by tool_result_unavailable (H1),
 * fabricate {result} (H2), skip sanitizer (H3), stringify invalid text (H4).
 * Run: node tests/claude_host_errors.mjs <adapter.ts>
 */
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
if (!process.argv[2]) throw new Error('Usage: node tests/claude_host_errors.mjs <adapter.ts>');
const { register } = await import(pathToFileURL(resolve(process.argv[2])).href);
const CANARY = 'synthetic-host-secret-never-return';
const envelope = value => ({ exitCode: 0, stdout: JSON.stringify(value), stderr: '' });
async function invoke(hostResult) {
  const hooks = new Map();
  let effects = 0;
  let redactions = 0;
  const $ = {
    session: { async id() { return 'host-errors-fixture'; }, async cwd() { return '/synthetic/project'; } },
    ui: { async status() {} },
    process: { async run(argv, options) {
      const action = argv[argv.indexOf('integration') + 1];
      if (action === 'describe') return envelope({ protocol_version: 1, owner: 'signet-eval', adapter_revision: 'claude-functions-2.1.280-v1', active: true, disabled: false, legacy_handlers: 0, reason: null });
      assert.equal(action, 'redact', 'fixture expects only owner and sanitizer protocol operations');
      redactions += 1;
      const input = JSON.parse(options.stdin);
      const value = JSON.parse(JSON.stringify(input.value).replaceAll(CANARY, '[REDACTED]'));
      return envelope({ protocol_version: 1, owner: 'signet-eval', sanitizer_revision: 'signet-redaction-v1', value });
    } },
  };
  register((name, callback) => hooks.set(name, callback), { enabled: true, executable: '/synthetic/signet-eval' });
  await hooks.get('session.start')($, { source: 'startup' }, async () => ({}));
  const output = await hooks.get('tool.call')($, { tool: 'Bash', tool_use_id: 'host-error-call', command: 'fixture' }, async () => {
    effects += 1;
    return structuredClone(hostResult);
  });
  assert.equal(effects, 1, 'H2: host continuation must run exactly once');
  assert.equal(typeof output?.deny, 'string', 'H2/H4: failure must be returned as host denial');
  assert.equal(output.result, undefined, 'H2: no successful typed result may be fabricated');
  assert(!JSON.stringify(output).includes(CANARY), 'H3: raw secret must never leave the adapter');
  return { output, redactions };
}
const cases = [
  ['RED H1 structured rule refusal', { isError: true, text: `rule denial ${CANARY}` }, 'rule denial [REDACTED]'],
  ['RED H1 host refusal without error flag', { text: `host denied ${CANARY}` }, 'host denied [REDACTED]'],
  ['RED H1 shell failure detail', { isError: true, text: `Exit code 7: command failed ${CANARY}` }, 'Exit code 7: command failed [REDACTED]'],
];
let failed = 0;
for (const [name, hostResult, expected] of cases) {
  try {
    const { output, redactions } = await invoke(hostResult);
    assert(redactions > 0, 'H3: failure explanation must reach sanitizer');
    assert(output.deny.includes(expected), 'H1: actual sanitized host explanation must remain visible');
    process.stdout.write(`PASS ${name}\n`);
  } catch (error) { failed += 1; process.stderr.write(`FAIL ${name}\n${error.stack}\n`); }
}
let fixedDiagnostic;
for (const text of [null, 42, true, { secret: CANARY }, [CANARY]]) {
  const name = `GREEN H4 invalid host text ${JSON.stringify(text)}`;
  try {
    const { output } = await invoke({ isError: true, text });
    assert(output.deny.length > 0, 'H4: safe diagnostic must not be empty');
    if (fixedDiagnostic === undefined) fixedDiagnostic = output.deny;
    else assert.equal(output.deny, fixedDiagnostic, 'H4: invalid payloads must produce fixed diagnosis, not payload serialization');
    process.stdout.write(`PASS ${name}\n`);
  } catch (error) { failed += 1; process.stderr.write(`FAIL ${name}\n${error.stack}\n`); }
}
process.stdout.write(`${8 - failed}/8 host error checks passed\n`);
process.exitCode = failed ? 1 : 0;
