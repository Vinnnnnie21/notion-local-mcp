import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dev_execution import Execution, ExecutionError

PROFILE = 'autonomous-development'
RUN_INTEGRATION = os.environ.get('NOTION_MCP_RUN_INTEGRATION') == '1'


class Backend:
    def __init__(self, directory):
        self.state = Path(directory) / 'state'; self.state.mkdir()
        self.tree = Path(directory) / 'tree'; self.tree.mkdir()
        self.meta = {'id': 'test-workspace', 'path': str(self.tree), 'profile': PROFILE}
        self.policy = {'enabled': True, 'environment': 'isolated-development', 'network': {'mode': 'loopback-only'},
                       'limits': {'maxWorkspaceBytes': 32 * 1024 ** 2, 'maxMemoryBytes': 256 * 1024 ** 2,
                                  'maxOutputBytes': 16384, 'maxTimeoutSeconds': 10, 'maxWorkspaceSeconds': 300}}
    def dev_policy(self, profile):
        if profile != PROFILE: raise ValueError('profile rejected')
        return self.policy
    def dev_workspace(self, workspace, profile, allowExpired=False):
        self.dev_policy(profile)
        if workspace != self.meta['id']: raise ValueError('workspace rejected')
        return self.meta
    def atomic_json(self, path, data): path.write_text(json.dumps(data))
    def dev_validate_tree(self, workspace, profile, allowExpired=False):
        self.dev_workspace(workspace, profile)
        tree = Path(self.meta.get('livePath') or self.meta['path'])
        for root, dirs, files in os.walk(tree):
            for name in dirs + files:
                if (Path(root) / name).is_symlink(): raise ValueError('link detected')


@unittest.skipUnless(RUN_INTEGRATION, 'requires the isolated Linux runtime')
class RealExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-exec-test-')
        self.backend = Backend(self.temp.name)
        self.executor = Execution(self.backend)
    def tearDown(self):
        self.executor.shutdown()
        self.temp.cleanup()
    def run_command(self, argv=None, shell=None, **kwargs):
        kwargs.setdefault('timeout', 10)
        return self.executor.run(PROFILE, self.backend.meta['id'], argv=argv, shell=shell, **kwargs)
    def wait(self, job):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = self.executor.status(job['taskId'])
            if result['status'] not in {'queued', 'running', 'terminating', 'finalizing'}: return result
            time.sleep(.05)
        self.fail('task did not finish')
    def test_real_argv_shell_node_and_python(self):
        result = self.run_command(argv=['python3', '-c', 'import os; print(os.getuid());print("ok")'])
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertIn('1000', result['stdout'])
        result = self.run_command(shell='printf "hello" > hello.txt; node -e "console.log(6*7)"')
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertIn('42', result['stdout'])
        self.assertEqual((Path(self.backend.meta['livePath']) / 'hello.txt').read_text(), 'hello')
    def test_real_filesystem_and_network_isolation(self):
        code = 'import os,socket;print(os.path.exists(os.path.expanduser("~/.config")));print(os.path.exists("/run/user/"+str(os.getuid())));print(os.path.exists("/var/run/docker.sock"));print(os.getenv("SSH_AUTH_SOCK"));s=socket.socket();s.settimeout(.5)\ntry:s.connect(("1.1.1.1",443));print("BAD")\nexcept OSError:print("DENIED")'
        result = self.run_command(argv=['python3', '-c', code])
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertIn('False\nFalse\nFalse\nNone\nDENIED', result['stdout'])
        record = self.executor.sandboxes[self.backend.meta['id']]
        props = subprocess.check_output(['systemctl', '--user', 'show', record['slice'], '-p', 'MemoryMax', '-p', 'TasksMax', '-p', 'CPUQuotaPerSecUSec']).decode()
        self.assertIn('MemoryMax=268435456', props)
        self.assertIn('TasksMax=128', props)
    def test_same_namespace_background_service(self):
        task = self.run_command(argv=['python3', '-m', 'http.server', '18547', '--bind', '127.0.0.1'], background=True, timeout=10)
        time.sleep(.6)
        probe = self.run_command(argv=['python3', '-c', 'import urllib.request;print(urllib.request.urlopen("http://127.0.0.1:18547").status)'])
        self.assertEqual(probe['status'], 'succeeded', probe)
        self.assertIn('200', probe['stdout'])
        self.executor.cancel(task['taskId'])
        self.assertEqual(self.wait(task)['status'], 'cancelled')
    def test_idempotency_survives_restart_without_replay(self):
        one = self.run_command(shell='printf x >> counter.txt', requestId='one')
        two = self.run_command(shell='printf x >> counter.txt', requestId='one')
        self.assertEqual(one['taskId'], two['taskId'])
        self.assertEqual((Path(self.backend.meta['livePath']) / 'counter.txt').read_text(), 'x')
        self.executor.close_workspace(self.backend.meta['id'])
        other = Execution(self.backend)
        try:
            replay = other.run(PROFILE, self.backend.meta['id'], shell='printf x >> counter.txt', requestId='one', timeout=10)
            self.assertEqual(replay['taskId'], one['taskId'])
            self.assertEqual((self.backend.tree / 'counter.txt').read_text(), 'x')
        finally: other.shutdown()
    def test_timeout_cancellation_does_not_kill_unrelated_process(self):
        unrelated = subprocess.Popen(['/bin/sleep', '30'])
        try:
            result = self.run_command(argv=['python3', '-c', 'import time;time.sleep(30)'], timeout=1)
            self.assertIn(result['status'], {'timeout', 'failed'}, result)
            self.assertIsNone(unrelated.poll())
        finally: unrelated.terminate(); unrelated.wait()
    def test_hard_disk_budget(self):
        result = self.run_command(argv=['python3', '-c', 'from pathlib import Path;p=Path("large.bin");f=p.open("wb")\ntry:\n for _ in range(64): f.write(b"x"*1024*1024);f.flush()\nexcept OSError: print("QUOTA")\nfinally: f.close()'])
        self.assertEqual(result['status'], 'succeeded', result)
        self.assertIn('QUOTA', result['stdout'])
        size = (Path(self.backend.meta['livePath']) / 'large.bin').stat().st_size
        self.assertLessEqual(size, 32 * 1024 ** 2)
    def test_environment_traversal_and_profile_denied(self):
        for env in ({'SSH_AUTH_SOCK': '/tmp/x'}, {'DATABASE_URL': 'x'}, {'PATH': '/home/x'}, {'X': 'https://example.com'}):
            with self.assertRaises(ExecutionError): self.run_command(argv=['true'], env=env)
        with self.assertRaises(ExecutionError): self.run_command(argv=['true'], working_directory='../')
        with self.assertRaises(ValueError): self.executor.run('readonly-runtime', 'test-workspace', argv=['true'])
    def test_output_limit_and_pagination(self):
        result = self.run_command(argv=['python3', '-c', 'print("x"*65536)'])
        self.assertTrue(result['truncated'], result)
        self.assertLessEqual(len(result['stdout']), 16384)
        page = self.executor.output(result['taskId'], limit=10)
        self.assertEqual(len(page['data']), 10)
    def test_real_pty(self):
        task = self.executor.pty_open(PROFILE, self.backend.meta['id'], argv=['/bin/sh'], timeout=10)
        time.sleep(.5)
        self.executor.pty_input(task['taskId'], 'echo pty-ok\n')
        time.sleep(.3)
        result = self.executor.status(task['taskId'])
        self.assertIn('pty-ok', result['stdout'], result)
        self.executor.pty_input(task['taskId'], 'X=unlogged-input\n')
        time.sleep(.1)
        self.assertNotIn('unlogged-input', self.executor.status(task['taskId'])['stdout'])
        self.executor.pty_close(task['taskId'])
        self.assertEqual(self.wait(task)['status'], 'cancelled')
    def test_artifact_symlink_cannot_write_host(self):
        task = self.run_command(argv=['true'])
        live = Path(self.backend.meta['livePath'])
        artifacts = live / '.dev-artifacts'
        import shutil
        shutil.rmtree(artifacts)
        outside = Path(self.temp.name) / 'outside'; outside.mkdir()
        artifacts.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.executor._write_artifacts(self.backend.meta, self.executor.jobs[task['taskId']])
        self.assertEqual(list(outside.iterdir()), [])
        artifacts.unlink()
    def test_reused_id_different_arguments(self):
        self.run_command(argv=['true'], requestId='same')
        with self.assertRaises(ExecutionError): self.run_command(argv=['false'], requestId='same')
    def test_repeated_failure_and_repair_budget_stop(self):
        self.backend.policy['limits'].update(maxRepeatedFailures=2, maxRepairRounds=4)
        for identifier in ('failure-one', 'failure-two'):
            result = self.run_command(argv=['false'], requestId=identifier)
            self.assertEqual(result['status'], 'failed', result)
        with self.assertRaisesRegex(ExecutionError, 'repeated_failure_stop'):
            self.run_command(argv=['false'], requestId='failure-three')
        changed = self.run_command(shell='printf fixed > code.txt', requestId='fix')
        self.assertEqual(changed['status'], 'succeeded', changed)
        failed = self.run_command(argv=['false'], requestId='failure-four')
        self.assertEqual(failed['status'], 'failed', failed)
        failed = self.run_command(argv=['false'], requestId='failure-five')
        self.assertEqual(failed['status'], 'failed', failed)
        with self.assertRaisesRegex(ExecutionError, 'repair_budget_exhausted'):
            self.run_command(argv=['true'], requestId='after-budget')
        self.assertTrue(self.executor.close_workspace(self.backend.meta['id'])['closed'])
    def test_restart_unknown_task_is_not_replayed(self):
        task = self.run_command(argv=['python3', '-c', 'import time;time.sleep(30)'], timeout=10, requestId='restart-task', background=True)
        time.sleep(.15)
        self.executor.shutdown()
        other = Execution(self.backend)
        try:
            old = other.run(PROFILE, self.backend.meta['id'], argv=['python3', '-c', 'import time;time.sleep(30)'], timeout=10, requestId='restart-task', background=True)
            self.assertEqual(old['taskId'], task['taskId'])
            self.assertEqual(old['status'], 'unknown')
            self.assertTrue(old['unknown'])
            with self.assertRaisesRegex(ExecutionError, 'unknown result'):
                other.run(PROFILE, self.backend.meta['id'], argv=['true'], timeout=10, requestId='new')
        finally: other.shutdown()

if __name__ == '__main__': unittest.main()
