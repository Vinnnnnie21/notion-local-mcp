"""临时项目验证副本、自动修改、恢复、哈希冲突和独立 Git。"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import Backend
from dev_workspace import attach_workspace, digest, manifest

# 核心集成之前也能单独运行。
if not hasattr(Backend, 'dev_workspace'):
    attach_workspace(Backend)


class Workspaces(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.base = Path(self.tmp.name)
        self.root = self.base / 'source'; self.root.mkdir()
        self.private = self.base / 'private'; self.private.mkdir()
        self.config = self.private / 'config.json'
        self.profile = 'autonomous-development'
        self.cfg = {'stateDir': str(self.private / 'state'), 'projects': {'test': {'root': str(self.root), 'write': True, 'writeAllow': ['*'], 'deny': [], 'tasks': {}, 'gitWrite': False}},
                    'executionProfiles': {self.profile: {'enabled': True, 'environment': 'isolated-development', 'readRoots': [str(self.root)], 'writeRoots': [str(self.root)], 'projects': ['test'], 'denyPaths': [],
                                                      'network': {'mode': 'loopback-only'}, 'git': {'local': True, 'push': False}, 'limits': {'diskBytes': 1024 * 1024, 'files': 1000, 'maxWorkspaces': 4}}}}
        self.config.write_text(json.dumps(self.cfg))
        self.backend = Backend(self.config)
        (self.root / 'a.py').write_text('def add(a, b):\n    return a - b\n'); (self.root / 'a.py').chmod(0o640)
        (self.root / 'unrelated.txt').write_text('initial\n')
        (self.root / '.scratch').mkdir(); (self.root / '.scratch' / 'handover.md').write_text('excluded runtime artifact')
        (self.root / '.env').write_text('PRIVATE_VALUE')
        (self.root / 'runtime.db').write_text('PRIVATE_DATABASE')
        subprocess.run(['git', '-C', str(self.root), 'init', '-b', 'main'], capture_output=True, check=True)
        subprocess.run(['git', '-C', str(self.root), 'config', 'user.name', 'Tester'], check=True)
        subprocess.run(['git', '-C', str(self.root), 'config', 'user.email', 'tester@example.invalid'], check=True)
        subprocess.run(['git', '-C', str(self.root), 'add', 'a.py', 'unrelated.txt'], check=True)
        subprocess.run(['git', '-C', str(self.root), 'commit', '-m', 'initial'], capture_output=True, check=True)
        (self.root / 'unrelated.txt').write_text('user dirty\n')
        self.workspaceId = self.backend.dev_workspace_create(self.profile, 'test', 'create')['workspaceId']
        self.meta = self.backend.dev_workspace(self.workspaceId, self.profile)
        self.tree = Path(self.meta['path'])
        self.count = 0

    def tearDown(self):
        for handler in self.backend.audit.handlers:
            handler.close()
        self.backend.audit.handlers.clear(); self.tmp.cleanup()

    def call(self, method, **kwargs):
        return getattr(self.backend, method)(profile=self.profile, workspaceId=self.workspaceId, **kwargs)

    def request(self):
        self.count += 1; return 'request-' + str(self.count)

    def write(self, path, text, expected=None):
        expected = expected or (self.call('dev_read', path=path)['sha256'] if (self.tree / path).exists() else 'missing')
        return self.call('dev_write', path=path, expectedHash=expected, requestId=self.request(), content=text)

    def test_copy_excludes_runtime_and_git_preserves_dirty(self):
        self.assertFalse((self.tree / '.git').exists()); self.assertFalse((self.tree / '.env').exists())
        self.assertFalse((self.tree / 'runtime.db').exists()); self.assertFalse((self.tree / '.scratch').exists())
        self.assertEqual((self.tree / 'unrelated.txt').read_text(), 'user dirty\n')
        self.assertEqual(self.backend.dev_workspace_create(self.profile, 'test', 'create')['workspaceId'], self.workspaceId)

    def test_write_edit_binary_modes_and_no_approval(self):
        result = self.write('a.py', 'correct\n'); self.assertTrue(result['applied'])
        self.assertNotIn('approvalId', result); self.assertEqual((self.tree / 'a.py').stat().st_mode & 0o777, 0o640)
        edit = self.call('dev_edit', path='a.py', expectedHash=digest(b'correct\n'), edits=[{'oldText': 'correct', 'newText': 'fixed'}], requestId=self.request())
        self.assertTrue(edit['applied']); self.assertEqual((self.tree / 'a.py').read_text(), 'fixed\n')
        raw = b'\0\xff\x01'; encoded = base64.b64encode(raw).decode()
        result = self.call('dev_write', path='binary.bin', expectedHash='missing', requestId=self.request(), base64Content=encoded)
        self.assertTrue(result['applied']); self.assertEqual(self.call('dev_read', path='binary.bin', binary=True)['base64'], encoded)
        self.assertFalse((self.root / 'binary.bin').exists())

    def test_conflict_does_not_overwrite(self):
        expected = self.call('dev_read', path='a.py')['sha256']
        (self.tree / 'a.py').write_text('new user change')
        result = self.write('a.py', 'wrong', expected)
        self.assertFalse(result['applied']); self.assertIn('Hash conflict', result['results'][0]['error'])
        self.assertEqual((self.tree / 'a.py').read_text(), 'new user change')

    def test_atomic_exchange_catches_change_after_final_hash(self):
        expected = self.call('dev_read', path='a.py')['sha256']
        import dev_workspace
        real_cdll = dev_workspace.ctypes.CDLL
        class RacingLib:
            def __init__(inner, lib):
                inner.lib = lib; inner.first = True
            def renameat2(inner, *args):
                if inner.first:
                    inner.first = False
                    (self.tree / 'a.py').write_text('concurrent final window')
                return inner.lib.renameat2(*args)
        with patch('dev_workspace.ctypes.CDLL', side_effect=lambda *a, **kw: RacingLib(real_cdll(*a, **kw))):
            result = self.write('a.py', 'task content', expected)
        self.assertFalse(result['applied'])
        self.assertEqual((self.tree / 'a.py').read_text(), 'concurrent final window')
        record = json.loads((self.backend.dev_root / self.workspaceId / 'snapshots' / (result['snapshotId'] + '.json')).read_text())
        self.assertNotIn('a.py', record['after'])

    def test_expired_workspace_can_close_but_not_write(self):
        self.meta['created'] = 0
        with self.assertRaisesRegex(ValueError, 'lifetime exhausted'):
            self.call('dev_read', path='a.py')
        result = self.call('dev_workspace_close')
        self.assertTrue(result['closed']); self.assertFalse(self.tree.exists())

    def test_idempotent_and_parameter_reuse_rejected(self):
        args = {'path': 'new.txt', 'expectedHash': 'missing', 'requestId': 'same', 'content': 'one'}
        result = self.call('dev_write', **args)
        self.assertEqual(self.call('dev_write', **args), result)
        with self.assertRaises(ValueError):
            self.call('dev_write', **(args | {'content': 'two'}))

    def test_directory_copy_move_delete_and_restore(self):
        mkdir = self.call('dev_operations', operations=[{'operation': 'mkdir', 'path': 'dir'}], requestId=self.request()); self.assertTrue(mkdir['applied'])
        self.assertTrue(self.write('dir/a.txt', 'one')['applied'])
        expected = self.backend.dev_tree_entry(self.tree, 'dir', self.backend.dev_policy(self.profile))['hash']
        result = self.call('dev_operations', operations=[{'operation': 'copy', 'path': 'dir', 'destination': 'copy', 'expectedHash': expected}], requestId=self.request())
        self.assertTrue(result['applied']); self.assertEqual((self.tree / 'copy/a.txt').read_text(), 'one')
        result = self.call('dev_operations', operations=[{'operation': 'move', 'path': 'dir', 'destination': 'moved', 'expectedHash': expected}], requestId=self.request())
        self.assertTrue(result['applied']); self.assertFalse((self.tree / 'dir').exists())
        restored = self.call('dev_restore', snapshotId=result['snapshotId'], requestId=self.request())
        self.assertTrue(restored['restored']); self.assertTrue((self.tree / 'dir/a.txt').exists()); self.assertFalse((self.tree / 'moved').exists())
        result = self.call('dev_operations', operations=[{'operation': 'delete', 'path': 'dir', 'expectedHash': expected}], requestId=self.request())
        self.assertTrue(result['applied']); self.assertFalse((self.tree / 'dir').exists())
        self.assertTrue(self.call('dev_restore', snapshotId=result['snapshotId'], requestId=self.request())['restored'])

    def test_partial_failure_report_and_snapshot(self):
        result = self.call('dev_operations', operations=[{'operation': 'write', 'path': 'one.txt', 'expectedHash': 'missing', 'content': 'one'}, {'operation': 'write', 'path': 'a.py', 'expectedHash': 'missing', 'content': 'bad'}], requestId=self.request())
        self.assertFalse(result['applied']); self.assertFalse(result['transactional']); self.assertTrue(result['results'][0]['applied'])
        self.assertTrue(self.call('dev_restore', snapshotId=result['snapshotId'], requestId=self.request())['restored'])
        self.assertFalse((self.tree / 'one.txt').exists())

    def test_sync_conflict_preserves_other_dirty_and_restore(self):
        self.write('a.py', 'correct\n')
        result = self.call('dev_sync', paths=['a.py'], requestId=self.request())
        self.assertTrue(result['applied']); self.assertEqual((self.root / 'a.py').read_text(), 'correct\n')
        self.assertEqual((self.root / 'unrelated.txt').read_text(), 'user dirty\n')
        self.assertEqual((self.root / 'a.py').stat().st_mode & 0o777, 0o640)
        self.assertTrue(self.call('dev_restore', snapshotId=result['snapshotId'], requestId=self.request())['restored'])
        self.assertEqual((self.root / 'a.py').read_text(), 'def add(a, b):\n    return a - b\n')
        (self.root / 'a.py').write_text('concurrent original')
        with self.assertRaisesRegex(ValueError, 'concurrent user change'):
            self.call('dev_sync', paths=['a.py'], requestId=self.request())
        self.assertEqual((self.root / 'a.py').read_text(), 'concurrent original')

    def test_policy_reload_and_roots(self):
        self.cfg['executionProfiles'][self.profile]['enabled'] = False
        self.config.write_text(json.dumps(self.cfg))
        with self.assertRaisesRegex(ValueError, 'disabled'):
            self.call('dev_read', path='a.py')
        self.cfg['executionProfiles'][self.profile]['enabled'] = True
        self.cfg['executionProfiles'][self.profile]['readRoots'] = ['/']
        self.config.write_text(json.dumps(self.cfg))
        with self.assertRaisesRegex(ValueError, 'explicit absolute'):
            self.call('dev_read', path='a.py')

    def test_link_traversal_private_and_secret_rejected(self):
        for path in ['../private/config.json', '/etc/passwd', '.git/config', '.env', '.env.credentials.py', '.ssh/id_rsa']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.call('dev_read', path=path)
        (self.tree / 'link').symlink_to(self.private)
        with self.assertRaises(ValueError):
            self.call('dev_read', path='link/config.json')
        (self.tree / 'link').unlink()
        result = self.write('secret.txt', 'password=THIS_IS_A_SECRET')
        self.assertFalse(result['applied']); self.assertNotIn('THIS_IS_A_SECRET', json.dumps(result))
        self.assertNotIn('THIS_IS_A_SECRET', (self.backend.state / 'audit.log').read_text())

    def test_source_code_sensitive_modules_and_private_config_denied(self):
        self.assertTrue(self.write('credentials.py', 'class CredentialProvider:\n    pass\n')['applied'])
        self.assertTrue(self.call('dev_sync', paths=['credentials.py'], requestId=self.request())['applied'])
        self.assertTrue((self.root / 'credentials.py').exists())
        self.assertTrue(self.write('sample.sqlite', 'temporary test database')['applied'])
        with self.assertRaises(ValueError):
            self.call('dev_sync', paths=['sample.sqlite'], requestId=self.request())
        with self.assertRaises(ValueError):
            self.call('dev_read', path='config.json')

    def test_copy_budget_is_checked(self):
        self.write('budget.bin', 'x' * (700 * 1024))
        result = self.call('dev_operations', operations=[{'operation': 'copy', 'path': 'budget.bin', 'destination': 'overflow.bin', 'expectedHash': digest(b'x' * (700 * 1024))}], requestId=self.request())
        self.assertFalse(result['applied']); self.assertFalse((self.tree / 'overflow.bin').exists())

    def test_git_private_does_not_include_dirty_original(self):
        source_head = subprocess.run(['git', '-C', str(self.root), 'rev-parse', 'HEAD'], capture_output=True, check=True).stdout
        self.call('dev_git', operation='branch', branch='codex/test', requestId=self.request())
        self.write('a.py', 'fixed\n')
        self.call('dev_git', operation='commit', paths=['a.py'], message='修复计算', requestId=self.request())
        repo = Path(self.meta['privateRepository'])
        changed = subprocess.run(['git', '-C', str(repo), 'show', '--format=', '--name-only', 'HEAD'], capture_output=True, check=True).stdout.decode().strip()
        self.assertEqual(changed, 'a.py')
        original_unrelated = subprocess.run(['git', '-C', str(repo), 'show', 'HEAD:unrelated.txt'], capture_output=True, check=True).stdout.decode()
        self.assertEqual(original_unrelated, 'initial\n')
        self.assertEqual((self.root / 'unrelated.txt').read_text(), 'user dirty\n')
        self.assertEqual(subprocess.run(['git', '-C', str(self.root), 'rev-parse', 'HEAD'], capture_output=True, check=True).stdout, source_head)
        with self.assertRaises(ValueError):
            self.call('dev_git', operation='push', requestId=self.request())
        with self.assertRaises(ValueError):
            self.call('dev_git', operation='commit', paths=['unrelated.txt'], message='无关修改', requestId=self.request())
        self.write('unrelated.txt', 'user dirty plus task modification\n')
        with self.assertRaisesRegex(ValueError, 'preexisting user change'):
            self.call('dev_git', operation='commit', paths=['unrelated.txt'], message='不应混入既有改动', requestId=self.request())

    def test_unknown_request_rejected_after_restart(self):
        self.backend.dev_request(self.meta, 'unknown', 'operations', [])
        replacement = Backend(self.config)
        try:
            meta = replacement.dev_workspace(self.workspaceId, self.profile)
            with self.assertRaisesRegex(ValueError, 'unknown'):
                replacement.dev_request(meta, 'unknown', 'operations', [])
        finally:
            for handler in replacement.audit.handlers:
                handler.close()
            replacement.audit.handlers.clear()

    def test_resource_budget_and_generated_dependency_cache(self):
        (self.tree / '__pycache__').mkdir(); (self.tree / '__pycache__' / 'a.pyc').write_bytes(b'cache')
        self.assertTrue(self.backend.dev_validate_tree(self.workspaceId, self.profile)['valid'])
        result = self.write('large.bin', 'x' * (1024 * 1024))
        self.assertFalse(result['applied'])

    def test_generated_dependencies_structural_only_and_no_export(self):
        directory = self.tree / '.dev-dependencies'; directory.mkdir()
        (directory / 'fixture.py').write_text('token = parse_expression(value)\n')
        self.assertTrue(self.backend.dev_validate_tree(self.workspaceId, self.profile)['valid'])
        with self.assertRaisesRegex(ValueError, 'not exposed'):
            self.call('dev_read', path='.dev-dependencies/fixture.py')
        with self.assertRaises(ValueError):
            self.call('dev_sync', paths=['.dev-dependencies/fixture.py'], requestId=self.request())
        (directory / 'escape').symlink_to(self.private)
        with self.assertRaises(ValueError):
            self.backend.dev_validate_tree(self.workspaceId, self.profile)

    @unittest.skipUnless(os.environ.get('NOTION_MCP_RUN_INTEGRATION') == '1', 'requires the registered offline dependency cache')
    def test_actual_cached_wheel_files_validate_without_exposure(self):
        cache = Path(os.environ.get('NOTION_MCP_PYTHON_CACHE', '/opt/dependency-cache/python'))
        wheel = next(iter(cache.glob('packaging-*.whl')), None)
        if wheel is None:
            self.skipTest('Local registered offline dependency cache unavailable')
        directory = self.tree / '.dev-dependencies'; directory.mkdir()
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if name.endswith('/'):
                    continue
                target = directory / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(archive.read(name))
        self.cfg['executionProfiles'][self.profile]['limits']['diskBytes'] = 16 * 1024 ** 2
        self.config.write_text(json.dumps(self.cfg))
        self.assertTrue(self.backend.dev_validate_tree(self.workspaceId, self.profile)['valid'])
        with self.assertRaises(ValueError):
            self.call('dev_read', path='.dev-dependencies/packaging/_parser.py')

    @unittest.skipUnless(os.environ.get('NOTION_MCP_RUN_INTEGRATION') == '1', 'requires the isolated executor and offline dependency cache')
    def test_actual_offline_pip_install_in_isolated_workspace(self):
        cache = Path(os.environ.get('NOTION_MCP_PYTHON_CACHE', '/opt/dependency-cache/python'))
        if not hasattr(self.backend, 'dev_executor') or not cache.is_dir():
            self.skipTest('Integrated isolated executor or offline cache unavailable')
        limits = self.cfg['executionProfiles'][self.profile]['limits']
        limits.update(diskBytes=64 * 1024 ** 2, maxWorkspaceBytes=64 * 1024 ** 2, maxMemoryBytes=512 * 1024 ** 2, maxWorkspaceSeconds=60, maxTimeoutSeconds=30, maxRepairRounds=8)
        self.config.write_text(json.dumps(self.cfg))
        try:
            result = self.call('dev_run', argv=['python3', '-m', 'pip', 'install', '--no-index', '--find-links', '/opt/dependency-cache/python', '--target', '/workspace/.dev-dependencies', 'pytest', 'ruff'], timeout=30, requestId='offline-install')
            self.assertEqual(result['status'], 'succeeded', result)
            self.assertEqual(result['exitCode'], 0)
            self.assertTrue(self.backend.dev_validate_tree(self.workspaceId, self.profile)['valid'])
            verify = self.call('dev_run', shell='PYTHONPATH=.dev-dependencies python3 -m pytest --version && .dev-dependencies/bin/ruff --version', timeout=15, requestId='verify-tools')
            self.assertEqual(verify['status'], 'succeeded', verify)
            self.assertIn('pytest', verify['stdout']); self.assertIn('ruff', verify['stdout'])
            with self.assertRaises(ValueError):
                self.call('dev_read', path='.dev-dependencies/packaging/_parser.py')
        finally:
            self.backend.dev_executor.close_workspace(self.workspaceId, self.profile)

    def test_closed_artifacts_are_retained_and_queryable(self):
        artifacts = self.tree / '.dev-artifacts'; artifacts.mkdir()
        (artifacts / 'report.txt').write_text('Tests passed\n')
        result = self.call('dev_workspace_close')
        self.assertTrue(result['artifactsRetained']); self.assertFalse(self.tree.exists())
        listed = self.call('dev_artifacts')['artifacts']
        self.assertEqual(listed[0]['path'], '.dev-artifacts/report.txt')
        self.assertEqual(self.call('dev_read', path='.dev-artifacts/report.txt')['text'], 'Tests passed\n')


if __name__ == '__main__':
    unittest.main()
