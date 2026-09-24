"""Offline Claude 2.1.274 host acceptance probe; synthetic provider, isolated state.

Run after cargo build. Does not enable plugins in the user's configuration.
Artifacts are retained in a newly allocated temporary directory for inspection.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import sqlite3
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--claude", default="claude")
parser.add_argument("--binary", type=Path, help="Signet executable (default: repository target/debug/signet-eval)")
parser.add_argument("--kindex-plugin", type=Path)
parser.add_argument("--disable-policy", action="store_true")
parser.add_argument("--disable-before-task", action="store_true")
parser.add_argument("--deny-task", action="store_true")
parser.add_argument("--reverse-order", action="store_true")
parser.add_argument("--flag-via-settings", action="store_true")
parser.add_argument("--unicode", action="store_true")
parser.add_argument("--deny-native-secret", action="store_true")
parser.add_argument("--installed-plugin", action="store_true")
host_error_mode = parser.add_mutually_exclusive_group()
host_error_mode.add_argument("--deny-bash", action="store_true", help="Verify policy refusal detail and absent shell effect")
host_error_mode.add_argument("--bash-error", action="store_true", help="Verify real shell failure detail without re-execution")
args = parser.parse_args()
if (args.deny_bash or args.bash_error) and (args.kindex_plugin or args.disable_policy or args.disable_before_task or args.deny_task or args.deny_native_secret):
    parser.error("Bash failure probes require active policy and no task fixture")
repo = Path(__file__).resolve().parents[1]
binary = (args.binary or repo / "target/debug/signet-eval").resolve()
root = Path(tempfile.mkdtemp(prefix="signet-function-host.")).resolve()
project = root / "project"
project.mkdir()
subprocess.run(["git", "init", "-q", str(project)], check=True)
(root / "home/.signet").mkdir(parents=True)
if args.disable_policy:
    (root / "home/.signet/disabled").write_text("1")
if args.deny_task:
    (root / "home/.signet/rules.yaml").write_text(
        "- name: explicit_task_deny\n  tool_pattern: '^kindex\\.task\\.create$'\n"
        "  conditions: ['true']\n  action: DENY\n  reason: Synthetic explicit target denial\n"
    )
if args.deny_native_secret:
    (root / "home/.signet/rules.yaml").write_text(
        "- name: native_subject_deny\n  tool_pattern: '^TaskCreate$'\n"
        "  conditions: [\"param_contains(subject, 'source-policy-canary')\"]\n"
        "  action: DENY\n  reason: Synthetic native subject denial\n"
    )
requests = []
canary = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
prompt_canary = "synthetic-prompt-value"
# H1-H3: Validator's host-error repair contract, 2026-09-24.
# The marker is a real effect witness, independent from the model-visible result.
marker = project / "bash-effect-marker"
policy_failure_reason = "Synthetic Bash policy refusal remains visible"
shell_failure_reason = "Synthetic shell execution failure remains visible"
if args.deny_bash:
    (root / "home/.signet/rules.yaml").write_text(
        "- name: synthetic_bash_refusal\n  tool_pattern: '^Bash$'\n"
        "  conditions: ['true']\n  action: DENY\n  reason: " + policy_failure_reason + "\n"
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        requests.append({"path": self.path, "body": data})
        if "count_tokens" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"input_tokens":100}')
            return
        results = [part for message in data.get("messages", [])
                   for part in (message.get("content") if isinstance(message.get("content"), list) else [])
                   if part.get("type") == "tool_result"]
        if not results:
            if args.disable_before_task:
                (root / "home/.signet/disabled").write_text("1")
            tool = "TaskCreate" if args.kindex_plugin else "Bash"
            subject = "api_key=source-policy-canary" if args.deny_native_secret else "Synthetic durable task λ 中文 🔑" if args.unicode else "Synthetic durable task"
            parameters = {"subject": subject, "description": "Offline admission evidence"} if args.kindex_plugin else {"command": "printf '%s\\n' \"$SIGNET_PROBE_OUTPUT\"", "description": "Emit synthetic output"}
            if args.deny_bash:
                parameters = {"command": "printf 'executed\\n' >> " + shlex.quote(str(marker)), "description": "Synthetic policy-refused effect"}
            elif args.bash_error:
                parameters = {"command": "printf 'executed\\n' >> " + shlex.quote(str(marker)) + "; printf '" + shell_failure_reason + ": %s\\n' \"$SIGNET_PROBE_OUTPUT\" >&2; exit 7", "description": "Synthetic shell failure with one observable effect"}
            block = {"type": "tool_use", "id": "toolu_create", "name": tool, "input": parameters}
        elif args.kindex_plugin and len(results) == 1:
            block = {"type": "tool_use", "id": "toolu_list", "name": "TaskList", "input": {}}
        else:
            block = {"type": "text", "text": "Synthetic fixture complete."}
        stop = "tool_use" if block["type"] == "tool_use" else "end_turn"
        message = {"id": "msg_fixture", "type": "message", "role": "assistant", "model": data.get("model"), "content": [block], "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 100, "output_tokens": 20}}
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if data.get("stream") else "application/json")
        self.end_headers()
        if not data.get("stream"):
            self.wfile.write(json.dumps(message).encode())
            return

        def send(kind, payload):
            self.wfile.write(("event: " + kind + "\ndata: " + json.dumps({"type": kind, **payload}) + "\n\n").encode())
            self.wfile.flush()

        send("message_start", {"message": {**message, "content": [], "stop_reason": None, "usage": {"input_tokens": 100, "output_tokens": 0}}})
        initial = {**block, "input": {}} if block["type"] == "tool_use" else {"type": "text", "text": ""}
        send("content_block_start", {"index": 0, "content_block": initial})
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])} if block["type"] == "tool_use" else {"type": "text_delta", "text": block["text"]}
        send("content_block_delta", {"index": 0, "delta": delta})
        send("content_block_stop", {"index": 0})
        send("message_delta", {"delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 20}})
        send("message_stop", {})


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
env = {key: os.environ[key] for key in ("PATH", "USER", "SHELL", "TMPDIR") if key in os.environ}
env.update({"HOME": str(root / "home"), "SIGNET_DIR": str(root / "home/.signet"),
            "PATH": str(binary.parent) + os.pathsep + env.get("PATH", ""),
            "CLAUDE_CONFIG_DIR": str(root / "claude"), "CLAUDE_CODE_ENABLE_FUNCTION_HOOKS": "1",
            "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "ANTHROPIC_API_KEY": "synthetic-local-only", "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{server.server_port}",
            "SIGNET_PROBE_OUTPUT": canary})
plugins = [] if args.installed_plugin else [repo / "adapters/claude-function"]
if args.kindex_plugin:
    plugins.append(args.kindex_plugin.resolve())
    env["PYTHONPATH"] = str(args.kindex_plugin.resolve().parents[1])
if args.reverse_order:
    plugins.reverse()
settings = {"pluginConfigs": {"signet-eval-functions": {"options": {"enabled": True, "executable": str(binary)}}}}
if args.installed_plugin:
    installed = subprocess.run([str(binary), "integration", "install-modern"], env=env, capture_output=True, text=True, check=True)
    (root / "install-result.json").write_text(installed.stdout)
    env.pop("CLAUDE_CODE_ENABLE_FUNCTION_HOOKS")
if args.flag_via_settings:
    env.pop("CLAUDE_CODE_ENABLE_FUNCTION_HOOKS")
    settings["env"] = {"CLAUDE_CODE_ENABLE_FUNCTION_HOOKS": "1"}
    (root / "claude").mkdir(exist_ok=True)
    (root / "claude/settings.json").write_text(json.dumps(settings))
cmd = [shutil.which(args.claude) or args.claude, "--setting-sources", "user" if args.flag_via_settings or args.installed_plugin else "", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
       "--permission-mode", "dontAsk", "--tools", "Bash,TaskCreate,TaskList", "--allowedTools", "Bash,TaskCreate,TaskList"]
if not args.flag_via_settings and not args.installed_plugin:
    cmd += ["--settings", json.dumps(settings)]
for plugin in plugins:
    cmd += ["--plugin-dir", str(plugin)]
cmd += ["--debug-file", str(root / "debug.log"), "--model", "claude-sonnet-4-5", "--max-budget-usd", "0.1",
        "--output-format", "stream-json", "--verbose", "-p", "Run synthetic fixture. api_key=" + prompt_canary]
try:
    result = subprocess.run(cmd, env=env, cwd=project, capture_output=True, text=True, timeout=60)
finally:
    server.shutdown()
(root / "stdout.jsonl").write_text(result.stdout)
(root / "stderr.log").write_text(result.stderr)
(root / "api-requests.json").write_text(json.dumps(requests, indent=2))
summary = {"artifacts": str(root), "exit_code": result.returncode, "requests": len(requests),
           "raw_prompt_in_api": prompt_canary in json.dumps(requests), "raw_output_in_api": canary in json.dumps(requests)}
print(json.dumps(summary), flush=True)
assert result.returncode == 0, "host process failed"
debug = (root / "debug.log").read_text()
# A normal policy refusal can say "resolved by a hooks module (deny: ... failed)".
# Only module diagnostics indicate a loader/callback failure; the result assertions
# below independently check whether an admitted or refused operation had an effect.
assert not any(re.search(r"\] hooks module .*failed", line) for line in debug.splitlines()), "plugin failed to load or execute"
rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
results = [part for row in rows for part in row.get("message", {}).get("content", []) if isinstance(part, dict) and part.get("type") == "tool_result"]
assert len(results) == (2 if args.kindex_plugin else 1), "missing tool result"
assert "does not match its output shape" not in result.stdout, "invalid replacement result"
assert summary["raw_prompt_in_api"] == args.disable_policy, "prompt redaction/disabled mismatch"
if args.kindex_plugin:
    refused = args.deny_task or args.disable_before_task or args.deny_native_secret
    assert bool(results[0].get("is_error")) == refused, "task admission decision mismatch"
    with sqlite3.connect(project / ".kin/local/kindex/kindex.db") as database:
        count = database.execute("SELECT COUNT(*) FROM nodes WHERE type='task'").fetchone()[0]
    assert count == (0 if refused else 1), "durable task mutation mismatch"
    assert not (root / "claude/tasks").exists(), "native task store unexpectedly used"
    if not refused and not args.disable_policy:
        with sqlite3.connect(root / "home/.signet/integration.db") as ledger:
            receipt = ledger.execute("SELECT outcome FROM adjudications WHERE operation_id='toolu_create'").fetchone()
        assert receipt and json.loads(receipt[0])["ok"], "reported task receipt not delivered"
elif args.deny_bash or args.bash_error:
    assert results[0].get("is_error"), "failed or refused Bash must remain a failure"
    visible_result = json.dumps(results[0])
    expected_reason = policy_failure_reason if args.deny_bash else shell_failure_reason
    assert expected_reason in visible_result, "actual refusal/execution explanation lost in host result"
    assert expected_reason in json.dumps(requests), "actual explanation not delivered to model"
    assert canary not in visible_result and not summary["raw_output_in_api"], "raw host-error secret leaked"
    if args.deny_bash:
        assert not marker.exists(), "policy-refused shell command produced an effect"
    else:
        assert marker.read_text() == "executed\n", "shell effect missing or command executed more than once"
else:
    assert not results[0].get("is_error"), "Bash did not execute"
    assert summary["raw_output_in_api"] == (args.disable_policy or args.disable_before_task), "output redaction/disabled mismatch"
print("PASS: host schemas, projection boundaries, admission, and durable effects checked")
