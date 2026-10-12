import os, json, re, shutil, subprocess, tempfile, unittest

BIN = os.environ.get('SIGNET_EVAL_BINARY', '')
POLICY = '''version: 1
default_action: ALLOW
rules:
  - name: github_identity_guard
    tool_pattern: '^Bash$'
    conditions: ['true']
    action: ENSURE
    ensure: {check: gh-identity-matches-remote, timeout: 5}
  - name: retained_system_rule
    tool_pattern: '^Sentinel$'
    conditions: ['true']
    action: DENY
    reason: synthetic system control
'''
GUARD = {'name': 'github_identity_guard', 'tool_pattern': '^Bash$', 'conditions': ['true'], 'action': 'ENSURE',
         'ensure': {'check': 'gh-identity-matches-remote', 'timeout': 5}}


class EnsureBehavior(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.isabs(BIN) and os.access(BIN, os.X_OK), 'SIGNET_EVAL_BINARY must be an absolute executable path')
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix='ensure-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.d = {k: os.path.join(self.tmp, k) for k in ('home', 'signet', 'claude', 'bin', 'cwd', 'proj')}
        for p in self.d.values():
            os.makedirs(p)
        self.checks = os.path.join(self.d['signet'], 'checks')
        self.pp = os.path.join(self.d['signet'], 'policy.yaml')
        self.rp = os.path.join(self.d['signet'], 'rules.yaml')
        self.ghmark = os.path.join(self.tmp, 'gh-called')
        self.exe(os.path.join(self.d['bin'], 'gh'), '#!/bin/sh\ntouch %s\nexit 1\n' % self.ghmark)
        self.env = {'PATH': self.d['bin'] + os.pathsep + os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': self.d['home'],
                    'SIGNET_DIR': self.d['signet'], 'CLAUDE_CONFIG_DIR': self.d['claude'], 'TMPDIR': self.tmp,
                    'SIGNET_TOOL_COMMAND': 'stale-command', 'SIGNET_TOOL_CWD': '/stale/cwd'}

    def exe(self, path, body):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(body)
        os.chmod(path, 0o755)

    def run_cli(self, args, stdin=None, paths=True):
        pre = ['--policy-path', self.pp, '--rules-path', self.rp] if paths else []
        args = list(args)
        if '--adapter' in args:
            i = args.index('--adapter')
            pre = args[i:i + 2] + pre
            del args[i:i + 2]
        return subprocess.run([BIN] + pre + args, input=stdin, cwd=self.d['cwd'], env=self.env,
                              capture_output=True, text=True, timeout=15)

    def claude(self, cmd, tool='Bash'):
        return {'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': {'command': cmd},
                'session_id': 'synthetic', 'cwd': self.d['proj']}

    def decide(self, envelope, extra=(), paths=True):
        r = self.run_cli(['eval'] + list(extra), json.dumps(envelope), paths)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        return json.loads(r.stdout).get('hookSpecificOutput', {}).get('permissionDecision')

    def test_fresh_gh_version_allowed_without_identity_check(self):
        self.assertEqual(self.decide(self.claude('gh --version'), paths=False), 'allow')
        self.assertFalse(os.path.exists(os.path.join(self.checks, 'gh-identity-matches-remote')))
        self.assertFalse(os.path.exists(self.ghmark), 'gh was invoked')

    def test_stale_system_guard_retired_other_system_deny_survives(self):
        with open(self.pp, 'w') as f:
            f.write(POLICY)
        self.assertEqual(self.decide(self.claude('gh --version')), 'allow')
        self.assertEqual(self.decide(self.claude('x', tool='Sentinel')), 'deny')
        rules = self.run_cli(['rules'])
        self.assertIn('retained_system_rule', rules.stdout)
        self.assertNotIn('github_identity_guard', rules.stdout)
        v = self.run_cli(['validate'])
        self.assertNotIn('gh-identity-matches-remote', v.stdout + v.stderr)
        self.assertRegex(v.stderr, r'github_identity_guard.*ignored', 'retired system entry not reported')
        self.assertNotIn('Policy valid', v.stdout)
        self.assertEqual(v.returncode, 0)
        with open(self.rp, 'w') as f:
            json.dump([dict(GUARD, name='custom_missing', ensure={'check': 'missing-custom-check', 'timeout': 5})], f)
        v2 = self.run_cli(['validate'])
        self.assertIn('missing-custom-check', v2.stdout + v2.stderr, 'no warning for invalid nonretired check')
        r = self.run_cli(['eval'], json.dumps(self.claude('git push')))
        out = json.loads(r.stdout)['hookSpecificOutput']
        self.assertEqual(out['permissionDecision'], 'deny', 'missing user check must fail closed')
        self.assertIn('missing-custom-check', out.get('permissionDecisionReason', ''))
        self.assertFalse(os.path.exists(self.ghmark))

    def test_user_rule_with_retired_name_runs_while_stale_system_copy_is_ignored(self):
        with open(self.pp, 'w') as f:
            f.write(POLICY)
        calls = os.path.join(self.tmp, 'user-check-calls')
        verdict = os.path.join(self.tmp, 'verdict')
        self.exe(os.path.join(self.checks, 'user-identity'),
                 '#!/bin/sh\necho x >> %s\nexit "$(cat %s)"\n' % (calls, verdict))
        with open(self.rp, 'w') as f:
            json.dump([dict(GUARD, ensure={'check': 'user-identity', 'timeout': 5})], f)
        for code, expected in (('1', 'deny'), ('0', 'allow')):
            with self.subTest(exit=code):
                with open(verdict, 'w') as f:
                    f.write(code)
                self.assertEqual(self.decide(self.claude('git push')), expected)
        with open(calls) as f:
            self.assertEqual(len(f.read().split()), 2, 'user check not run once per call')
        rules = self.run_cli(['rules'])
        self.assertEqual(rules.stdout.count('github_identity_guard'), 1, rules.stdout)
        v = self.run_cli(['validate'])
        self.assertRegex(v.stderr, r'github_identity_guard.*ignored')
        self.assertIn('User rules valid', v.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.checks, 'gh-identity-matches-remote')))

    def test_user_ensure_gets_actual_context_claude_and_antigravity(self):
        exp, seen = os.path.join(self.tmp, 'exp.json'), os.path.join(self.tmp, 'seen.json')
        script = os.path.join(self.checks, 'ctxcheck')
        self.exe(script, '#!/usr/bin/env python3\nimport os,sys,json\ne=json.load(open(%r))\nd=sys.stdin.read()\n'
                 'c,w=os.environ.get("SIGNET_TOOL_COMMAND"),os.environ.get("SIGNET_TOOL_CWD","")\n'
                 'json.dump({"cmd":c,"cwd":w,"stdin":d,"src":os.environ.get("SIGNET_TOOL_CWD_SOURCE"),'
                 '"host":os.environ.get("SIGNET_HOST_CWD")},open(%r,"w"))\n'
                 'sys.exit(0 if c==e["cmd"] and os.path.realpath(w)==os.path.realpath(e["cwd"]) else 1)\n' % (exp, seen))
        with open(script, 'rb') as f:
            original = f.read()
        with open(self.rp, 'w') as f:
            json.dump([dict(GUARD, ensure={'check': 'ctxcheck', 'timeout': 5})], f)
        mark = os.path.join(self.tmp, 'side-effect')
        cmd = 'touch %s; echo $(id) > %s && true | cat' % (mark, mark)
        ag = {'toolCall': {'name': 'run_command', 'args': {'CommandLine': cmd, 'Cwd': self.d['proj']}}}
        # Claude supplies only the host envelope cwd; Antigravity supplies only the tool's Cwd.
        sources = {'claude': ('host', self.d['proj']), 'antigravity': ('tool_input', '')}
        for name, env_in, extra in (('claude', self.claude(cmd), ()), ('antigravity', ag, ('--adapter', 'antigravity'))):
            with self.subTest(adapter=name):
                with open(exp, 'w') as f:
                    json.dump({'cmd': cmd, 'cwd': self.d['proj']}, f)
                if os.path.exists(seen):
                    os.remove(seen)
                dec = self.decide(env_in, extra) if name == 'claude' else self.run_cli(['eval'] + list(extra), json.dumps(env_in)).returncode
                self.assertEqual(dec, 'allow' if name == 'claude' else 0)
                self.assertTrue(os.path.exists(seen), 'user check not invoked')
                with open(seen) as f:
                    s = json.load(f)
                self.assertEqual(s['cmd'], cmd)
                self.assertEqual(os.path.realpath(s['cwd']), self.d['proj'])
                self.assertEqual((s['src'], s['host']), sources[name])
                self.assertIsInstance(json.loads(s['stdin']), dict)
                self.assertFalse(os.path.exists(mark), 'eval executed the tool command')
        with open(exp, 'w') as f:
            json.dump({'cmd': 'mismatch', 'cwd': self.d['proj']}, f)
        self.assertEqual(self.decide(self.claude(cmd)), 'deny')
        with open(script, 'rb') as f:
            self.assertEqual(f.read(), original)
        self.assertFalse(os.path.exists(mark))

    def test_cwd_provenance_is_reported_separately(self):
        seen = os.path.join(self.tmp, 'seen.json')
        self.exe(os.path.join(self.checks, 'ctx'), '#!/usr/bin/env python3\nimport os,json\n'
                 'json.dump({k:os.environ.get(k) for k in ("SIGNET_TOOL_CWD","SIGNET_TOOL_CWD_SOURCE","SIGNET_HOST_CWD")},'
                 'open(%r,"w"))\n' % seen)
        with open(self.rp, 'w') as f:
            json.dump([dict(GUARD, name='ctx_rule', ensure={'check': 'ctx', 'timeout': 5})], f)
        other = self.d['bin']
        cases = (
            ('requested beats host', {'command': 'ls', 'cwd': other}, (other, 'tool_input', self.d['proj'])),
            ('empty requested ignored', {'command': 'ls', 'cwd': ''}, (self.d['proj'], 'host', self.d['proj'])),
        )
        for label, tool_input, expected in cases:
            with self.subTest(label):
                env_in = dict(self.claude('ls'), tool_input=tool_input)
                self.assertEqual(self.decide(env_in), 'allow')
                with open(seen) as f:
                    got = json.load(f)
                self.assertEqual((got['SIGNET_TOOL_CWD'], got['SIGNET_TOOL_CWD_SOURCE'], got['SIGNET_HOST_CWD']), expected)
        env_in = self.claude('ls')
        del env_in['cwd']
        self.assertEqual(self.decide(env_in), 'allow')
        with open(seen) as f:
            got = json.load(f)
        self.assertEqual((os.path.realpath(got['SIGNET_TOOL_CWD']), got['SIGNET_TOOL_CWD_SOURCE'], got['SIGNET_HOST_CWD']),
                         (self.d['cwd'], 'process', ''))

    def test_command_falls_back_to_first_non_empty_string(self):
        seen = os.path.join(self.tmp, 'seen-cmd')
        self.exe(os.path.join(self.checks, 'cmdctx'), '#!/usr/bin/env python3\nimport os\n'
                 'open(%r,"w").write(os.environ.get("SIGNET_TOOL_COMMAND","<unset>"))\n' % seen)
        with open(self.rp, 'w') as f:
            json.dump([dict(GUARD, name='cmd_rule', ensure={'check': 'cmdctx', 'timeout': 5})], f)
        cases = (
            ({'command': 123, 'cmd': 'git push'}, 'git push'),
            ({'command': '', 'cmd': 'git push'}, 'git push'),
            ({'command': None, 'cmd': 'git push'}, 'git push'),
            ({'cmd': 'git push'}, 'git push'),
            ({'command': 'git fetch', 'cmd': 'git push'}, 'git fetch'),
            ({'command': 123}, ''),
        )
        for tool_input, expected in cases:
            with self.subTest(tool_input=tool_input):
                self.assertEqual(self.decide(dict(self.claude('x'), tool_input=tool_input)), 'allow')
                with open(seen) as f:
                    self.assertEqual(f.read(), expected)

    def test_validate_fix_preserves_raw_entries_and_clamps_timeout(self):
        slow = {'name': 'slow_user_check', 'tool_pattern': '^Slow$', 'conditions': ['true'], 'action': 'ENSURE',
                'ensure': {'check': 'slowcheck', 'timeout': 60}}
        retained = {'name': 'retained_system_rule', 'tool_pattern': '^Sentinel$', 'conditions': ['true'],
                    'action': 'DENY', 'reason': 'synthetic system control'}
        with open(self.pp, 'w') as f:
            json.dump({'version': 1, 'default_action': 'ALLOW', 'rules': [GUARD, retained, slow]}, f)
        with open(self.rp, 'w') as f:
            f.write('[]')
        self.exe(os.path.join(self.checks, 'slowcheck'), '#!/bin/sh\nexit 0\n')
        self.run_cli(['validate', '--fix'])
        with open(self.pp) as f:
            t = f.read()
        for s in ('github_identity_guard', 'gh-identity-matches-remote', 'retained_system_rule',
                  'synthetic system control', 'slow_user_check', 'slowcheck'):
            self.assertIn(s, t)
        self.assertIsNone(re.search(r'timeout\W+60\b', t), 'timeout 60 not clamped')
        self.assertRegex(t, r'timeout\W+30\b')
        self.assertRegex(t, r'timeout\W+5\b')
        self.assertEqual(len(re.findall(r'tool_pattern', t)), 3, 'rules added or removed')
        self.assertTrue(os.path.exists(os.path.join(self.checks, 'slowcheck')))


if __name__ == '__main__':
    unittest.main()
