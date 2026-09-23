import json, os, queue, re, shutil, subprocess, tempfile, threading, time, unittest

BIN = os.environ.get('SIGNET_EVAL_BINARY', '')
T = 15
TOOLS = ('signet_list_rules', 'signet_validate', 'signet_set_limit')
GUARD = {'name': 'github_identity_guard', 'tool_pattern': '^Bash$', 'conditions': ['true'],
         'action': 'ENSURE', 'ensure': {'check': 'gh-identity-matches-remote', 'timeout': 5}}
SENTINEL = {'name': 'retained_system_rule', 'tool_pattern': '^Sentinel$', 'conditions': ['true'],
            'action': 'DENY', 'reason': 'synthetic-control'}
BLOCK = {'name': 'block_rm', 'tool_pattern': '^OriginalOnly$', 'conditions': ['true'],
         'action': 'DENY', 'reason': 'original-snapshot-marker'}


class Client:
    def __init__(s, env, cwd):
        s.p = subprocess.Popen([BIN, 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, cwd=cwd)
        s.q, s.err, s.n = queue.Queue(), [], 0
        threading.Thread(target=s._rd, daemon=True).start()
        threading.Thread(target=lambda: s.err.extend(s.p.stderr), daemon=True).start()

    def _rd(s):
        for line in s.p.stdout:
            s.q.put(line)
        s.q.put(None)

    def send(s, msg):
        s.p.stdin.write((json.dumps(msg) + '\n').encode())
        s.p.stdin.flush()

    def req(s, method, params):
        s.n += 1
        i = s.n
        s.send({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': params})
        end = time.monotonic() + T
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise AssertionError('timeout waiting for response to %s' % method)
            try:
                line = s.q.get(timeout=left)
            except queue.Empty:
                continue
            if line is None:
                raise AssertionError('server exited early: %r' % b''.join(s.err)[-2000:])
            line = line.strip()
            if not line:
                continue
            m = json.loads(line)
            if 'method' in m or m.get('id') != i:
                continue
            assert m.get('jsonrpc') == '2.0', m
            if 'error' in m:
                raise AssertionError('%s error: %r' % (method, m['error']))
            assert isinstance(m.get('result'), dict), m
            return m['result']

    def close(s):
        try:
            s.p.stdin.close()
        except Exception:
            pass
        try:
            s.p.wait(timeout=5)
        except Exception:
            s.p.kill()
            s.p.wait(timeout=5)
        for f in (s.p.stdout, s.p.stderr):
            try:
                f.close()
            except Exception:
                pass


class MCPBehavior(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.isabs(BIN) and os.access(BIN, os.X_OK), 'SIGNET_EVAL_BINARY must be absolute executable')
        self.tmp = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home, self.sdir, self.cwd = (os.path.join(self.tmp, d) for d in ('home', 'signet', 'work'))
        for d in (self.home, self.sdir, self.cwd):
            os.makedirs(d)
        self.env = {'HOME': self.home, 'SIGNET_DIR': self.sdir, 'PATH': '/usr/bin:/bin'}
        self.pol = os.path.join(self.sdir, 'policy.yaml')
        self.rules = os.path.join(self.sdir, 'rules.yaml')

    def write_policy(self, rules):
        with open(self.pol, 'w') as f:
            json.dump({'version': 1, 'default_action': 'ALLOW', 'rules': rules}, f, indent=2)
        open(self.rules, 'w').close()

    def read(self, p):
        with open(p) as f:
            return f.read()

    def start(self):
        c = Client(self.env, self.cwd)
        self.addCleanup(c.close)
        r = c.req('initialize', {'protocolVersion': '2024-11-05', 'capabilities': {},
                                 'clientInfo': {'name': 'test', 'version': '1'}})
        self.assertIn('protocolVersion', r)
        self.assertIn('capabilities', r)
        c.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        return c

    def call(self, c, name, args):
        r = c.req('tools/call', {'name': name, 'arguments': args})
        self.assertFalse(r.get('isError', False), r)
        self.assertIsInstance(r.get('content'), list)
        self.assertTrue(r['content'], r)
        for b in r['content']:
            self.assertEqual(b.get('type'), 'text', b)
            self.assertIsInstance(b.get('text'), str)
        text = '\n'.join(b['text'] for b in r['content'])
        self.assertTrue(text.strip(), 'empty text from %s' % name)
        return text

    def test_wire_contract(self):
        self.write_policy([SENTINEL])
        c = self.start()
        tools = {t['name']: t for t in c.req('tools/list', {})['tools']}
        for n in TOOLS:
            self.assertIn(n, tools)
            self.assertEqual(tools[n]['inputSchema'].get('type'), 'object')
        v = tools['signet_validate']['inputSchema'].get('properties', {})
        self.assertEqual(v.get('fix', {}).get('type'), 'boolean')
        s = tools['signet_set_limit']['inputSchema']
        self.assertTrue({'category', 'max_amount'} <= set(s.get('required', [])))
        self.assertEqual(s['properties']['category']['type'], 'string')
        self.assertEqual(s['properties']['max_amount']['type'], 'number')
        text = self.call(c, 'signet_list_rules', {})
        self.assertIn('retained_system_rule', text)
        self.assertIsNone(c.p.poll())

    def test_retirement_and_raw_mutation(self):
        self.write_policy([GUARD, SENTINEL, BLOCK])
        orig = self.read(self.pol)
        c = self.start()
        listed = self.call(c, 'signet_list_rules', {})
        self.assertIn('retained_system_rule', listed)
        self.assertNotIn('github_identity_guard', listed)
        diag = self.call(c, 'signet_validate', {'fix': False})
        self.assertNotIn('github_identity_guard', diag)
        self.assertNotIn('gh-identity', diag.lower())
        self.assertEqual(self.read(self.pol), orig, 'read-only calls mutated policy')
        out = self.call(c, 'signet_set_limit', {'category': 'books', 'max_amount': 12})
        self.assertIn('books', out.lower())
        raw = self.read(self.pol)
        both = raw + '\n' + self.read(self.rules)
        for s in ('github_identity_guard', '^Bash$', 'ENSURE', 'gh-identity-matches-remote',
                  'retained_system_rule', '^Sentinel$', 'synthetic-control', '^OriginalOnly$',
                  'original-snapshot-marker', 'DENY'):
            self.assertIn(s, raw)
        self.assertRegex(raw, 'timeout\\W{0,3}5\\b')
        self.assertRegex(raw, 'version\\W{0,3}1\\b')
        self.assertRegex(raw, 'default_action\\W{0,3}ALLOW')
        self.assertEqual(len(re.findall('block_rm', raw)), 1)
        self.assertEqual(len(re.findall('limit_books_12\\b', both)), 1)
        self.assertEqual(len(re.findall('\\bname\\W{0,2}:', both)), 4, 'unexpected rule injection')
        for root, dirs, files in os.walk(self.tmp):
            for f in dirs + files:
                self.assertNotIn('gh-identity', f)
                self.assertNotIn('github_identity', f)
        self.assertIsNone(c.p.poll())


if __name__ == '__main__':
    unittest.main()
