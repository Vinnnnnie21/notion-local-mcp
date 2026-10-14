"""维护测试只操作临时安装目录，服务重启与健康由测试替身记录。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dev_maintenance import register_candidate, validate_candidate, execute_maintenance, create_backup, restore_backup, layout, safe_relative, attach_maintenance, SERVICE, canonical, sha, TOOL_SCHEMAS, health_check
from core import Backend
from dev_workspace import attach_workspace

if not hasattr(Backend, 'dev_workspace'):
    attach_workspace(Backend)
if not hasattr(Backend, 'dev_mcp_maintenance'):
    attach_maintenance(Backend)


class Maintenance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.base = Path(self.tmp.name)
        self.install = self.base / 'installation'; self.install.mkdir()
        (self.install / 'app').mkdir(); (self.install / 'app/server.py').write_text('VERSION = "old"\n')
        (self.install / 'app/server.py').chmod(0o640)
        self.project = self.base / 'project'; self.project.mkdir()
        self.cfg = {'stateDir': str(self.install / 'state'), 'projects': {'test': {'root': str(self.project), 'write': True, 'writeAllow': ['*'], 'deny': [], 'tasks': {}, 'gitWrite': False}},
                    'executionProfiles': {'mcp-self-maintenance': {'enabled': True, 'environment': 'fixed-maintenance', 'readRoots': [str(self.install)], 'writeRoots': [str(self.install)], 'projects': [], 'network': {'mode': 'none'}, 'maintenance': {'installationRoot': str(self.install), 'services': [SERVICE], 'registeredCandidates': str(self.install / 'state/maintenance/candidates')}}}}
        (self.install / 'config.json').write_text(json.dumps(self.cfg))
        (self.install / 'token').write_text('SECRET_TOKEN_NEVER_TOUCHED')
        self.source = self.base / 'candidate'; (self.source / 'app').mkdir(parents=True)
        (self.source / 'app/server.py').write_text('VERSION = "new"\n')
        (self.source / 'app/new_module.py').write_text('def hello():\n    return "hello"\n')
        self.backend = Backend(self.install / 'config.json')
        self.backend.dev_maintenance_auth = 'SYNTHETIC_MAINTENANCE_AUTH_HANDLE_12345'

    def tearDown(self):
        for handler in self.backend.audit.handlers:
            handler.close()
        self.backend.audit.handlers.clear(); self.tmp.cleanup()

    def register(self):
        entries = []
        for path in sorted(self.source.rglob('*')):
            if path.is_file() and path.name != 'maintenance-evidence.json':
                raw = path.read_bytes(); entries.append({'path': path.relative_to(self.source).as_posix(), 'sha256': sha(raw), 'size': len(raw)})
        evidence = {'status': 'passed', 'schemaValidated': True, 'testCount': 10, 'filesBinding': sha(canonical(entries)), 'testEnvironment': 'temporary-unit-test-fixture'}
        (self.source / 'maintenance-evidence.json').write_text(json.dumps(evidence))
        return register_candidate(self.install, self.source, 'candidate-v1', 'new')

    def test_local_registration_validates_and_token_not_copied(self):
        result = self.register(); self.assertTrue(result['registered'])
        self.assertTrue(validate_candidate(self.install, 'candidate-v1')['valid'])
        self.assertFalse((layout(self.install) / 'candidates/candidate-v1/files/token').exists())
        self.assertNotIn('SECRET_TOKEN_NEVER_TOUCHED', json.dumps(result))

    def test_unregistered_and_tampered_candidates_rejected(self):
        with self.assertRaises(FileNotFoundError):
            validate_candidate(self.install, 'unregistered')
        self.register()
        target = layout(self.install) / 'candidates/candidate-v1/files/app/server.py'
        target.write_text('VERSION = "tampered"\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            validate_candidate(self.install, 'candidate-v1')

    def test_missing_or_tampered_test_evidence_rejected(self):
        with self.assertRaises(FileNotFoundError):
            register_candidate(self.install, self.source, 'without-evidence', 'new')
        self.register()
        evidence = layout(self.install) / 'candidates/candidate-v1/evidence.json'
        changed = json.loads(evidence.read_text()); changed['testCount'] = 0
        evidence.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'evidence'):
            validate_candidate(self.install, 'candidate-v1')

    def test_authenticated_verify_required_before_completion(self):
        self.backend.dev_discovery_schemas = TOOL_SCHEMAS
        record = {'requestId': 'restart-request', 'operation': 'restart', 'binding': 'fixture', 'status': 'awaiting_client_verification', 'result': {'healthy': True}}
        jobs = layout(self.install) / 'jobs'; (jobs / 'restart-request.json').write_text(json.dumps(record))
        before = self.backend.dev_mcp_maintenance('mcp-self-maintenance', 'status', 'restart-request')
        self.assertEqual(before['status'], 'awaiting_client_verification')
        result = self.backend.dev_mcp_maintenance('mcp-self-maintenance', 'verify', 'restart-request')
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['result']['toolCount'], 1)

    def test_manifest_tampering_and_traversal_rejected(self):
        self.register()
        path = layout(self.install) / 'candidates/candidate-v1/manifest.json'
        envelope = json.loads(path.read_text()); envelope['record']['files'][0]['path'] = '../token'
        path.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(ValueError, 'signature'):
            validate_candidate(self.install, 'candidate-v1')
        for relative in ['../token', '/etc/passwd', 'token', 'state/approvals/a.json', 'app/tests/t.py', 'app/.hidden.py']:
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                safe_relative(relative)

    def test_candidate_config_cannot_expand_permissions(self):
        config = json.loads(json.dumps(self.cfg)); config['executionProfiles']['evil'] = {'enabled': True}
        (self.source / 'config.json').write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, 'authorization'):
            self.register()
        self.assertFalse((layout(self.install) / 'candidates/candidate-v1').exists())

    def test_config_change_after_registration_rejected(self):
        self.register()
        current = json.loads(json.dumps(self.cfg)); current['projects']['test']['write'] = False
        (self.install / 'config.json').write_text(json.dumps(current))
        with self.assertRaisesRegex(ValueError, 'authorization changed'):
            validate_candidate(self.install, 'candidate-v1')

    def test_deploy_and_restore_fixed_files_preserve_mode_and_token(self):
        self.register(); restarts = []
        result = execute_maintenance(self.install, 'deploy', candidateId='candidate-v1', restart=lambda: restarts.append(SERVICE), health=lambda: {'healthy': True, 'version': 'new'})
        self.assertFalse(result['rolledBack']); self.assertEqual(restarts, [SERVICE])
        self.assertEqual((self.install / 'app/server.py').read_text(), 'VERSION = "new"\n')
        self.assertEqual((self.install / 'app/server.py').stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.install / 'token').read_text(), 'SECRET_TOKEN_NEVER_TOUCHED')
        restore_backup(self.install, result['backupId'])
        self.assertEqual((self.install / 'app/server.py').read_text(), 'VERSION = "old"\n')
        self.assertFalse((self.install / 'app/new_module.py').exists())

    def test_failed_health_rolls_back_once(self):
        self.register(); restarts = []; health_calls = []
        def health():
            health_calls.append(1)
            if len(health_calls) == 1:
                raise ValueError('health fails')
            return {'healthy': True, 'version': 'old'}
        result = execute_maintenance(self.install, 'deploy', candidateId='candidate-v1', restart=lambda: restarts.append(SERVICE), health=health)
        self.assertTrue(result['rolledBack']); self.assertFalse(result['deployed']); self.assertEqual(len(restarts), 2)
        self.assertEqual((self.install / 'app/server.py').read_text(), 'VERSION = "old"\n')

    def test_backup_and_validate_tool_idempotency(self):
        self.register()
        args = {'profile': 'mcp-self-maintenance', 'operation': 'backup', 'requestId': 'backup-request'}
        result = self.backend.dev_mcp_maintenance(**args)
        repeated = self.backend.dev_mcp_maintenance(**args)
        self.assertEqual(repeated['result'], result['result']); self.assertFalse(repeated['replayed'])
        with self.assertRaisesRegex(ValueError, 'reused'):
            self.backend.dev_mcp_maintenance(**(args | {'operation': 'validate', 'candidateId': 'candidate-v1'}))
        status = self.backend.dev_mcp_maintenance('mcp-self-maintenance', 'status', 'backup-request')
        self.assertEqual(status['status'], 'complete')

    def test_maintenance_cannot_target_trade_service(self):
        self.cfg['executionProfiles']['mcp-self-maintenance']['maintenance']['services'] = ['trade-worker.service']
        (self.install / 'config.json').write_text(json.dumps(self.cfg))
        with self.assertRaisesRegex(ValueError, 'fixed MCP service'):
            self.backend.dev_mcp_maintenance('mcp-self-maintenance', 'backup', 'request')

    def test_tool_only_launches_fixed_worker_in_separate_unit(self):
        self.register()
        with patch('dev_maintenance.subprocess.Popen') as run:
            run.return_value.stdin = MagicMock()
            result = self.backend.dev_mcp_maintenance('mcp-self-maintenance', 'deploy', 'deployment', candidateId='candidate-v1')
        self.assertEqual(result['status'], 'queued')
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ['systemd-run', '--user']); self.assertIn('--worker', argv)
        self.assertIn(str(self.install / 'app/dev_maintenance.py'), argv)
        self.assertNotIn(self.backend.dev_maintenance_auth, json.dumps(argv))
        self.assertNotIn(self.backend.dev_maintenance_auth, json.dumps(run.call_args.kwargs, default=str))
        run.return_value.stdin.write.assert_called_once_with((self.backend.dev_maintenance_auth + '\n').encode())
        repeated = self.backend.dev_mcp_maintenance('mcp-self-maintenance', 'deploy', 'deployment', candidateId='candidate-v1')
        self.assertFalse(repeated['replayed'])

    def test_health_and_wire_discovery_use_only_process_auth_handle(self):
        handle = self.backend.dev_maintenance_auth
        requests = []
        class Response:
            def __init__(inner, value):
                inner.raw = json.dumps(value).encode()
            def __enter__(inner):
                return inner
            def __exit__(inner, *args):
                pass
            def read(inner, limit):
                return inner.raw[:limit]
        class Opener:
            def open(inner, request, timeout):
                requests.append(request)
                self.assertEqual(request.get_header('Authorization'), 'Bearer ' + handle)
                self.assertTrue(request.full_url.startswith('http://127.0.0.1:8001/'))
                if request.full_url.endswith('/health'):
                    return Response({'state': 'ok', 'version': 'new'})
                payload = json.loads(request.data)
                if payload['method'] == 'tools/list':
                    names = ['health', 'get_capabilities', 'dev_mcp_maintenance']
                    return Response({'result': {'tools': [{'name': name, 'inputSchema': {'type': 'object'}} for name in names]}})
                value = {'state': 'ok'} if payload['params']['name'] == 'health' else {'features': {}}
                return Response({'result': {'content': [{'type': 'text', 'text': json.dumps(value)}]}})
        with patch('dev_maintenance.urllib.request.build_opener', return_value=Opener()):
            result = health_check(handle)
        self.assertEqual(len(requests), 4)
        self.assertEqual(result['toolDiscovery'], 'verified_authenticated_wire_tools_list')
        self.assertNotIn(handle, json.dumps(result))


if __name__ == '__main__':
    unittest.main()
