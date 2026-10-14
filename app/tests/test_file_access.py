"""在临时目录验证文件权限、审批、恢复及请求限流。"""
import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import Backend
from file_access import canonical, hashed, safe_output, open_components
from server import Guard, make_app, DESCRIPTIONS, tool_schema

class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / 'root'; self.root.mkdir()
        self.private = self.root / 'private'; self.private.mkdir()
        self.config = self.private / 'config.json'
        cfg = {'stateDir': str(self.private / 'state'), 'authorizedRoots': [{'path': str(self.root), 'read': True, 'write': True}],
               'administratorPaths': [str(self.private)], 'projects': {'code': {'root': str(self.root), 'write': True, 'read': True,
               'writeAllow': ['*'], 'deny': [], 'denyDirs': [], 'gitWrite': False, 'tasks': {}}}}
        self.config.write_text(json.dumps(cfg)); self.b = Backend(self.config)
        (self.root / 'a.txt').write_text('original\n'); (self.root / 'a.txt').chmod(0o640)
        (self.root / '.scratch').mkdir(); (self.root / '.scratch/result.md').write_text('handover\n')
        (self.root / '.agents').mkdir(); (self.root / '.gitignore').write_text('build\n')

    def tearDown(self):
        for handler in self.b.audit.handlers: handler.close()
        self.b.audit.handlers.clear(); self.tmp.cleanup()

    def approve_fixture(self, plan):
        # 只用于临时配置的自动测试，不接触部署审批库。
        file = self.b.state / 'approvals' / (plan['approvalId'] + '.json')
        record = json.loads(file.read_text()); record['approved'] = True; record['approvedBinding'] = record['binding']
        self.b.atomic_json(file, record); return plan['approvalId']

    def apply(self, plan):
        result = self.b.apply_change(self.approve_fixture(plan)); self.assertTrue(result['applied'], result); return result

    def hash(self, path, linkMode='link'): return self.b.get_path_hash('code', path, linkMode)['sha256']
    def write(self, path='a.txt', content='updated\n'):
        return self.b.plan_files('code', [{'path': path, 'content': content, 'expectedHash': self.hash(path)}])

    def test_hidden_absolute_and_route(self):
        self.assertEqual(self.b.read_text_file('code', str(self.root / '.scratch/result.md'))['text'], 'handover\n')
        names = {x['name'] for x in self.b.list_directory('code')['entries']}
        self.assertTrue({'.scratch', '.agents', '.gitignore'}.issubset(names))
        self.assertEqual(self.b.resolve_path(str(self.root / '.scratch/result.md'))['project'], 'code')
        self.assertIn('.scratch', [x['path'] for x in self.b.search_paths('code', '.scratch')['results']])
        self.assertIn('.scratch/result.md', [x['path'] for x in self.b.search_files('code', '*.md')['results']])

    def test_all_file_operations(self):
        self.apply(self.b.create_directory('code', 'dir'))
        self.apply(self.b.create_text_file('code', 'dir/new.txt', 'hello'))
        self.apply(self.b.apply_text_edits('code', 'dir/new.txt', self.hash('dir/new.txt'), [{'oldText': 'hello', 'newText': 'world'}]))
        self.apply(self.b.copy_path('code', 'dir/new.txt', 'dir/copy.txt', self.hash('dir/new.txt')))
        self.apply(self.b.move_path('code', 'dir/new.txt', 'moved.txt', self.hash('dir/new.txt')))
        self.apply(self.b.rename_path('code', 'moved.txt', 'renamed.txt', self.hash('moved.txt')))
        result = self.apply(self.b.delete_path('code', 'renamed.txt', self.hash('renamed.txt')))
        self.assertFalse((self.root / 'renamed.txt').exists())
        self.apply(self.b.restore_snapshot('code', result['snapshotId']))
        self.assertEqual((self.root / 'renamed.txt').read_text(), 'world')

    def test_binary(self):
        data = b'\0\xff\x01data'
        self.apply(self.b.write_binary_file('code', 'binary.bin', base64.b64encode(data).decode()))
        self.assertEqual(base64.b64decode(self.b.read_binary_file('code', 'binary.bin')['base64']), data)

    def test_preview_and_approval(self):
        plan = self.write()
        self.assertEqual((self.root / 'a.txt').read_text(), 'original\n')
        with self.assertRaises(ValueError): self.b.apply_change(plan['approvalId'])
        self.apply(plan); self.assertEqual((self.root / 'a.txt').stat().st_mode & 0o777, 0o640)
        with self.assertRaises(ValueError): self.b.apply_change(plan['approvalId'])

    def test_expired_and_tampered(self):
        plan = self.write(); aid = self.approve_fixture(plan)
        file = self.b.state / 'approvals' / (aid + '.json'); record = json.loads(file.read_text())
        record['expires'] = 0; self.b.atomic_json(file, record)
        with self.assertRaises(ValueError): self.b.apply_change(aid)
        plan = self.write(); aid = self.approve_fixture(plan); file = self.b.state / 'approvals' / (aid + '.json')
        record = json.loads(file.read_text()); record['payload'][0]['after'][str(self.root / 'a.txt')]['data'] = base64.b64encode(b'tampered').decode(); self.b.atomic_json(file, record)
        with self.assertRaises(ValueError): self.b.apply_change(aid)

    def test_conflict(self):
        plan = self.write(); aid = self.approve_fixture(plan); (self.root / 'a.txt').write_text('user change')
        with self.assertRaises(ValueError): self.b.apply_change(aid)
        self.assertEqual((self.root / 'a.txt').read_text(), 'user change')

    def test_create_conflict(self):
        plan = self.b.create_text_file('code', 'new.txt', 'new'); aid = self.approve_fixture(plan)
        (self.root / 'new.txt').write_text('user change')
        with self.assertRaises(ValueError): self.b.apply_change(aid)

    def test_bounds_and_private(self):
        for path in ('../outside', str(self.base / 'outside'), 'private/config.json', 'private/state/approvals/a.json'):
            with self.subTest(path=path), self.assertRaises(ValueError): self.b.allowed('code', path, True)
        with self.assertRaises(ValueError): self.b.delete_path('code', '.', self.hash('.'))
        (self.root / 'private-link').symlink_to(self.private)
        with self.assertRaises(ValueError): self.b.allowed('code', 'private-link/config.json')

    def test_symlink_target_vs_link(self):
        link = self.root / 'link'; link.symlink_to('a.txt')
        self.assertEqual(self.b.read_text_file('code', 'link')['text'], 'original\n')
        self.apply(self.b.plan_files('code', [{'path': 'link', 'expectedHash': self.hash('link', 'target'), 'content': 'target changed'}]))
        self.assertTrue(link.is_symlink()); self.assertEqual((self.root / 'a.txt').read_text(), 'target changed')
        self.apply(self.b.rename_path('code', 'link', 'link2', self.hash('link')))
        self.assertTrue((self.root / 'link2').is_symlink())
        self.apply(self.b.delete_path('code', 'link2', self.hash('link2')))
        self.assertEqual((self.root / 'a.txt').read_text(), 'target changed')
        (self.root / 'outside-link').symlink_to(self.base)
        with self.assertRaises(ValueError): self.b.allowed('code', 'outside-link/outside')

    def test_symlink_copy_rebases(self):
        (self.root / 'dir').mkdir(); (self.root / 'link').symlink_to('a.txt')
        self.apply(self.b.copy_path('code', 'link', 'dir/link', self.hash('link')))
        (self.root / 'deep').mkdir(); (self.root / 'deep/up').symlink_to('../a.txt')
        with self.assertRaises(ValueError): self.b.copy_path('code', 'deep/up', 'up', self.hash('deep/up'))

    def test_sensitive_and_redaction(self):
        for path in ('.env', 'private.key', 'credentials.txt'):
            (self.root / path).write_text('SENTINEL_SECRET')
            with self.assertRaises(ValueError): self.b.read_text_file('code', path)
        result = self.b.create_text_file('code', 'ordinary.txt', 'api_key=sentinel_super_secret')
        self.assertNotIn('sentinel_super_secret', json.dumps(result))
        self.assertNotIn('sentinel_super_secret', json.dumps(safe_output({'text': 'api_key=sentinel_super_secret'})))
        self.b.audit_event('safe', 'ok', 'code')
        self.assertNotIn('sentinel_super_secret', (self.b.state / 'audit.log').read_text())

    def test_sensitive_exact_grant(self):
        (self.root / '.env').write_text('PASSWORD=sentinel_super_secret')
        self.b.sensitive_grants = [{'path': str(self.root / '.env'), 'read': True, 'write': False, 'expires': time.time() + 60}]
        self.assertNotIn('sentinel_super_secret', json.dumps(safe_output(self.b.read_text_file('code', '.env'))))
        with self.assertRaises(ValueError): self.b.plan_files('code', [{'path': '.env', 'expectedHash': self.hash('.env'), 'content': 'replacement'}])

    def test_directory_copy_move_delete_restore(self):
        (self.root / 'dir').mkdir(); (self.root / 'dir/sub').mkdir(); (self.root / 'dir/sub/a.txt').write_text('child')
        (self.root / 'dir/sub').chmod(0o500)
        self.apply(self.b.copy_path('code', 'dir', 'copied', self.hash('dir')))
        self.assertEqual((self.root / 'copied/sub/a.txt').read_text(), 'child')
        self.assertEqual((self.root / 'copied/sub').stat().st_mode & 0o777, 0o500)
        self.apply(self.b.move_path('code', 'copied', 'moved', self.hash('copied')))
        result = self.apply(self.b.delete_path('code', 'moved', self.hash('moved')))
        self.apply(self.b.restore_snapshot('code', result['snapshotId']))
        self.assertEqual((self.root / 'moved/sub/a.txt').read_text(), 'child')
        for p in ('dir/sub', 'moved/sub'): (self.root / p).chmod(0o700)

    def test_overwrite_restore(self):
        (self.root / 'b.txt').write_text('destination')
        result = self.apply(self.b.copy_path('code', 'a.txt', 'b.txt', self.hash('a.txt'), self.hash('b.txt'), True))
        self.apply(self.b.restore_snapshot('code', result['snapshotId']))
        self.assertEqual((self.root / 'b.txt').read_text(), 'destination')

    def test_partial_failure_restore(self):
        (self.root / 'b.txt').write_text('before')
        plan = self.b.plan_files('code', [{'path': p, 'expectedHash': self.hash(p), 'content': 'after'} for p in ('a.txt', 'b.txt')])
        original = self.b.replace_node; calls = []
        def fail(*args):
            calls.append(1)
            if len(calls) == 2: raise PermissionError('SECRET_SHOULD_NOT_LEAK')
            return original(*args)
        with patch.object(self.b, 'replace_node', side_effect=fail):
            result = self.b.apply_change(self.approve_fixture(plan))
        self.assertTrue(result['partial']); self.assertEqual(result['error'], 'linux_permission_denied')
        self.assertNotIn('SECRET_SHOULD_NOT_LEAK', json.dumps(result))
        self.apply(self.b.restore_snapshot('code', result['snapshotId']))
        self.assertEqual((self.root / 'a.txt').read_text(), 'original\n')
        self.assertEqual((self.root / 'b.txt').read_text(), 'before')

    def test_restore_conflict(self):
        result = self.apply(self.write()); (self.root / 'a.txt').write_text('user change')
        with self.assertRaises(ValueError): self.b.restore_snapshot('code', result['snapshotId'])

    def test_git_separate(self):
        (self.root / '.git').mkdir(); (self.root / '.git/config').write_text('config')
        with self.assertRaises(ValueError): self.b.plan_files('code', [{'path': '.git/config', 'content': 'x', 'expectedHash': self.hash('.git/config')}])
        with self.assertRaises(ValueError): self.b.plan_git('code', 'branch', branch='x')
        with self.assertRaises(ValueError): self.b.plan_task('code', 'anything')

    def test_read_only_grant(self):
        cfg = json.loads(self.config.read_text()); cfg['authorizedRoots'][0]['write'] = False; self.config.write_text(json.dumps(cfg))
        with self.assertRaises(ValueError): Backend(self.config)

    def test_permission_and_hardlink(self):
        (self.root / 'a.txt').chmod(0)
        with self.assertRaises(PermissionError): self.b.read('code', 'a.txt')
        (self.root / 'a.txt').chmod(0o640); os.link(self.root / 'a.txt', self.root / 'hard.txt')
        with self.assertRaises(ValueError): self.b.read('code', 'hard.txt')

    def test_cli_approval_fixture(self):
        plan = self.write()
        result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / 'manage.py'), '--config', str(self.config),
            'approve', plan['approvalId']], input='APPROVE\n', capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.b.apply_change(plan['approvalId'])['applied'])

    def test_kernel_race_rejection(self):
        target = self.b.allowed('code', '.scratch/result.md')
        original = self.b.allowed
        count = []
        def race(*args, **kwargs):
            value = original(*args, **kwargs)
            if not count:
                count.append(1); (self.root / '.scratch').rename(self.root / 'old-scratch'); (self.root / '.scratch').symlink_to(self.base)
            return value
        with patch.object(self.b, 'allowed', side_effect=race), self.assertRaises(ValueError): self.b.read('code', '.scratch/result.md')

    def test_directory_descriptor_fallback(self):
        import file_access
        with patch.object(file_access, 'open_beneath', side_effect=open_components):
            self.assertEqual(self.b.read_text_file('code', '.scratch/result.md')['text'], 'handover\n')
            (self.root / 'link').symlink_to('a.txt')
            self.assertEqual(self.b.read_text_file('code', 'link')['text'], 'original\n')
            self.apply(self.write())
            (self.root / 'escape').symlink_to(self.base)
            with self.assertRaises(ValueError): self.b.read('code', 'escape/config.json')

    def tunnel_status(self, active=True, changed=False, message=None):
        invocation = 'a' * 32
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[0] == '/usr/bin/journalctl':
                return subprocess.CompletedProcess(argv, 0, json.dumps({'MESSAGE': message or 'INF | https://current-host.trycloudflare.com     |'}) + '\n', '')
            if 'InvocationID' in argv:
                value = 'b' * 32 if changed and 'ActiveState' in argv else invocation
                text = 'InvocationID=' + value + '\n'
                if 'ActiveState' in argv: text += 'ActiveState=active\n'
                return subprocess.CompletedProcess(argv, 0, text, '')
            return subprocess.CompletedProcess(argv, 0, 'ActiveState=' + ('active' if active else 'inactive') + '\nSubState=running\nMainPID=42\n', '')
        with patch('subprocess.run', side_effect=run):
            report = self.b.get_service_status()
        return report, calls

    def test_current_tunnel_public_url(self):
        report, calls = self.tunnel_status()
        self.assertEqual(report['publicMcpUrl'], 'https://current-host.trycloudflare.com/mcp')
        self.assertTrue(report['publicMcpUrlConfigured'])
        journals = [args for args in calls if args[0] == '/usr/bin/journalctl']
        self.assertEqual(len(journals), 1)
        self.assertIn('_SYSTEMD_INVOCATION_ID=' + 'a' * 32, journals[0])

    def test_tunnel_restart_during_lookup(self):
        report, _ = self.tunnel_status(changed=True)
        self.assertIsNone(report['publicMcpUrl'])

    def test_stopped_tunnel_has_no_current_url(self):
        report, calls = self.tunnel_status(active=False)
        self.assertIsNone(report['publicMcpUrl'])
        self.assertFalse(any(args[0] == '/usr/bin/journalctl' for args in calls))

    def test_tunnel_journal_secrets_not_returned(self):
        report, _ = self.tunnel_status(message='token=SYNTHETIC_SECRET credential=SYNTHETIC_SECRET | https://current-host.trycloudflare.com |')
        self.assertEqual(report['publicMcpUrl'], 'https://current-host.trycloudflare.com/mcp')
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(report))
        for url in ['https://user:SYNTHETIC_SECRET@current-host.trycloudflare.com',
                    'https://current-host.trycloudflare.com?token=SYNTHETIC_SECRET',
                    'https://current-host.trycloudflare.com.evil.invalid',
                    'https://current-host.trycloudflare.com/path',
                    'http://current-host.trycloudflare.com']:
            with self.subTest(url=url):
                report, _ = self.tunnel_status(message='INF | ' + url + ' |')
                self.assertIsNone(report['publicMcpUrl'])
                self.assertNotIn('SYNTHETIC_SECRET', json.dumps(report))

    def test_schema_and_app(self):
        import jsonschema
        for name in DESCRIPTIONS: jsonschema.Draft202012Validator.check_schema(tool_schema(getattr(self.b, name)))
        token = self.private / 'token'; token.write_text('x' * 64); token.chmod(0o600)
        app = make_app(str(self.config), str(token)); self.assertTrue(isinstance(app, Guard))

class Rate(unittest.TestCase):
    def test_discovery_read_and_limits(self):
        async def run():
            with tempfile.TemporaryDirectory() as tmp:
                token = Path(tmp) / 'token'; token.write_text('x' * 64)
                async def app(scope, receive, send):
                    await receive(); await send({'type': 'http.response.start', 'status': 200, 'headers': []}); await send({'type': 'http.response.body', 'body': b'{}'})
                guard = Guard(app, token)
                async def request(method, auth=True):
                    out = []; body = json.dumps({'method': method}).encode()
                    async def receive(): return {'type': 'http.request', 'body': body}
                    async def send(message): out.append(message)
                    await guard({'type': 'http', 'method': 'POST', 'path': '/mcp', 'headers': [(b'authorization', b'Bearer ' + b'x' * 64 if auth else b'bad')]}, receive, send)
                    return out
                self.assertEqual((await request('tools/list', False))[0]['status'], 401)
                for _ in range(180): self.assertEqual((await request('tools/list'))[0]['status'], 200)
                for _ in range(180): self.assertEqual((await request('tools/call'))[0]['status'], 200)
                guard.limits['readPerMinute'] = 180
                result = await request('tools/call'); self.assertEqual(result[0]['status'], 429)
                payload = json.loads(result[1]['body']); self.assertGreater(payload['retryAfterSeconds'], 0)
                self.assertIn('Never automatically replay', payload['retryPolicy'])
                self.assertEqual((await request('tools/list'))[0]['status'], 200)
        asyncio.run(run())

if __name__ == '__main__': unittest.main(verbosity=2)
