import os, json, shutil, subprocess, tempfile, unittest

BIN = os.environ.get('SIGNET_EVAL_BINARY', '')
REV = 'claude-functions-2.1.280-v1'
ERR = 'unqualified_claude_version_use_legacy'
SETTINGS = {'theme': 'dark', 'hooks': {'PreToolUse': [{'matcher': 'Foreign', 'hooks': [{'type': 'command', 'command': '/foreign/hook'}]}]}}


def last_json(out):
    try:
        return json.loads(out)
    except ValueError:
        pass
    for line in reversed(out.strip().splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                return json.loads(line)
            except ValueError:
                pass
    return {}


class InstallModern(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.isabs(BIN) and os.access(BIN, os.X_OK), 'SIGNET_EVAL_BINARY must be an absolute executable path')
        self.tmp = tempfile.mkdtemp(prefix='pr15-')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def install(self, script):
        root = tempfile.mkdtemp(dir=self.tmp)
        d = {k: os.path.join(root, k) for k in ('home', 'signet', 'claude', 'bin', 'cwd')}
        for p in d.values():
            os.makedirs(p)
        mock = os.path.join(d['bin'], 'claude')
        with open(mock, 'w') as f:
            f.write('#!/bin/sh\n' + script + '\n')
        os.chmod(mock, 0o755)
        open(os.path.join(d['signet'], 'disabled'), 'w').close()
        sp = os.path.join(d['claude'], 'settings.json')
        with open(sp, 'w') as f:
            json.dump(SETTINGS, f)
        with open(sp, 'rb') as f:
            before = f.read()
        env = {'PATH': d['bin'] + os.pathsep + os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': d['home'],
               'SIGNET_DIR': d['signet'], 'CLAUDE_CONFIG_DIR': d['claude'], 'TMPDIR': self.tmp}
        r = subprocess.run([BIN, 'integration', 'install-modern'], cwd=d['cwd'], env=env,
                           capture_output=True, text=True, timeout=15)
        return d, sp, before, r, last_json(r.stdout)

    def test_accepts_exact_274_and_280(self):
        for v in ('2.1.274', '2.1.280'):
            with self.subTest(version=v):
                d, sp, _, r, out = self.install('echo "%s (Claude Code)"' % v)
                self.assertEqual(out.get('status'), 'installed', r.stdout[-300:] + r.stderr[-300:])
                dest = os.path.join(d['claude'], 'skills', 'signet-eval-functions')
                self.assertTrue(os.path.isdir(dest), 'skill destination missing')
                with open(sp) as f:
                    s = json.load(f)
                self.assertEqual(s.get('theme'), 'dark')
                self.assertIn('/foreign/hook', json.dumps(s))
                self.assertTrue(os.path.exists(os.path.join(d['signet'], 'disabled')), 'disabled marker removed')
                found = {}
                for rt, _, files in os.walk(dest):
                    for n in files:
                        p = os.path.join(rt, n)
                        found[os.path.relpath(p, dest)] = p
                pj = [p for k, p in found.items() if k.endswith(os.path.join('.claude-plugin', 'plugin.json'))]
                ts = [p for k, p in found.items() if k.endswith(os.path.join('hooks', 'signet.ts'))]
                self.assertTrue(pj and ts, 'plugin.json or hooks/signet.ts not installed')
                with open(pj[0]) as f:
                    desc = json.load(f).get('description', '')
                self.assertIn('2.1.274', desc)
                self.assertIn('2.1.280', desc)
                for bad in ('2.1.274-2.1.280', '2.1.274 - 2.1.280', '2.1.274 through', '2.1.274 to 2.1.280', '>=', '2.1.27x'):
                    self.assertNotIn(bad, desc)
                with open(ts[0]) as f:
                    self.assertIn(REV, f.read())

    def test_rejects_unqualified_versions_without_writes(self):
        vers = ('2.1.273', '2.1.275', '2.1.277', '2.1.279', '2.1.281', '2.2.0', '2.1.280-beta', '2.1')
        cases = ['echo "%s (Claude Code)"' % v for v in vers]
        cases += ['echo garbage', 'echo "2.1.280 (Claude Code)"; exit 3']
        for c in cases:
            with self.subTest(mock=c):
                d, sp, before, r, out = self.install(c)
                self.assertNotEqual(out.get('status'), 'installed')
                self.assertIn(ERR, r.stdout, r.stdout[-300:])
                self.assertFalse(os.path.exists(os.path.join(d['claude'], 'skills', 'signet-eval-functions')))
                with open(sp, 'rb') as f:
                    self.assertEqual(f.read(), before, 'settings.json modified on rejection')
                self.assertTrue(os.path.exists(os.path.join(d['signet'], 'disabled')))


if __name__ == '__main__':
    unittest.main()
