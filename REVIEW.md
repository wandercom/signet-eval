# Review guide

signet-eval is a policy enforcement point. A bug that allows a call it should
deny, or that stops the hook from running at all, is a security defect even
when every test is green. Review for fail-closed behaviour first.

## Always check

- **Fail closed.** Malformed input, a failed vault read, an unreachable binary
  or an unrecognized host reply must deny or ask, never allow. A missing or
  corrupted `policy.yaml` is the one deliberate exception: it falls back to the
  compiled `default_policy()` (locked self-protection included), which can
  allow calls. Hook mode always exits 0 and reports the decision in JSON.
- **Self-protection.** The locked rules in `self_protection_rules()` stay locked
  and stay ahead of user rules. A change that lets a tool write `.signet/`, the
  binary, hook settings or policy files without the existing checks needs an
  explicit justification and a test in `policy::self_protection_tests`.
- **Deterministic authorization.** Rule evaluation uses regex and string
  comparison only. No NLP, no `eval`, no network. `INJECT` stays advisory and
  never changes an allow/deny/ask outcome.
- **Sanitize before truncating or persisting**, and never feed a sanitized copy
  into policy evaluation. Rules must see the original input.
- **Every new rule, condition function or adapter path has a test**, including
  the adversarial case (unicode lookalikes, null bytes, oversized input) where
  the input is attacker-controlled.
- **Function adapter pairing.** `REVISION` in
  `adapters/claude-function/hooks/signet.ts` must equal `ADAPTER_REVISION` in
  `src/integration.rs`. A mismatch makes every installed session report a
  conflict. When the qualified Claude build changes, update
  `QUALIFIED_CLAUDE_VERSION` in `src/claude_install.rs`, both revision strings,
  the adapter README, `plugin.json` and `CLAUDE.md` together, and run
  `claude plugin validate adapters/claude-function` plus
  `python3 tests/claude_function_host.py` on that build.
- **Installer safety.** `install-modern` retires only exact recognized Signet
  handlers, keeps foreign handlers, backs up settings and the previous plugin,
  and never changes the global/session disabled state.
- **User-facing changes** get a `CHANGELOG.md` entry under `[Unreleased]`.

## Style

- Rust 2021, stable toolchain, `cargo fmt --all` clean. No `unsafe`.
- No `unwrap()` or `expect()` on paths that handle user or host input; return a
  fixed error code instead. `unwrap()` is fine in tests.
- Error codes returned to hosts are fixed snake_case strings that never echo the
  rejected input.
- Prefer early returns over nested conditionals.

## Skip

- `Cargo.lock` (review only for unexpected new dependencies)
- `target/`
- `docs/reviews/` (dated historical records; they are not updated in place)
- `learnings/`, `decomposition/`, `contracts/` (Pact pipeline artifacts)
