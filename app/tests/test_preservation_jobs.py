"""Preservation requests must survive retries without replaying the copy."""
import json
from pathlib import Path
import tempfile
import threading
import unittest

from preservation_jobs import PreservationJobs


class PreservationRequests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'requests'
        self.manager = PreservationJobs(self.root)
        self.workspace = 'a' * 32
        self.profile = 'autonomous-development'

    def submit(self, request, work, **kwargs):
        return self.manager.submit(self.workspace, self.profile, request, work, **kwargs)

    def test_inflight_retry_runs_one_copy_and_reports_progress(self):
        started = threading.Event()
        release = threading.Event()
        calls = []

        def work(identifier, progress):
            calls.append(identifier)
            progress('copying', files=2, directories=1, size=16)
            started.set()
            if not release.wait(5):
                raise RuntimeError('Test worker timed out')
            return {'workspaceId': self.workspace, 'preservationId': identifier,
                    'preserved': True, 'privatePath': '/private/host/preservation'}

        first = self.submit('one', work)
        try:
            self.assertTrue(started.wait(2))
            retry = self.submit('one', lambda *_: self.fail('Retry replayed the copy'))
            self.assertEqual(first['preservationTaskId'], retry['preservationTaskId'])
            self.assertEqual(retry['filesCopied'], 2)
            self.assertEqual(len(calls), 1)
            with self.assertRaises(ValueError):
                self.submit('different', work)
        finally:
            release.set()
            self.manager.threads[first['preservationTaskId']].join(5)
        result = self.submit('one', lambda *_: self.fail('Completed request replayed'))
        self.assertEqual(result['status'], 'succeeded')
        self.assertTrue(result['preserved'])
        self.assertNotIn('/private/host', json.dumps(result))
        self.assertEqual(self.root.joinpath(first['preservationTaskId'] + '.json').stat().st_mode & 0o777, 0o600)

    def test_failed_copy_is_not_replayed_or_disclosed(self):
        def work(*_):
            raise RuntimeError('/private/host SYNTHETIC_CREDENTIAL_12345')

        result = self.submit('failure', work)
        self.manager.threads[result['preservationTaskId']].join(5)
        result = self.submit('failure', lambda *_: self.fail('Failed request replayed'))
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['preserved'])
        self.assertNotIn('SYNTHETIC_CREDENTIAL', json.dumps(result))
        self.assertNotIn('/private/host', json.dumps(result))

    def test_restart_marks_interrupted_copy_unknown_without_replay(self):
        result = self.submit('interrupted', lambda *_: {'preserved': True})
        self.manager.threads[result['preservationTaskId']].join(5)
        path = self.root / (result['preservationTaskId'] + '.json')
        record = json.loads(path.read_text())
        record['status'] = 'running'
        path.write_text(json.dumps(record))
        restarted = PreservationJobs(self.root)
        result = restarted.submit(self.workspace, self.profile, 'interrupted',
                                  lambda *_: self.fail('Interrupted request replayed'))
        self.assertEqual(result['status'], 'unknown')
        self.assertFalse(result['preserved'])
        self.assertEqual(json.loads(path.read_text())['status'], 'unknown')

    def test_closed_workspace_rejects_new_copy(self):
        with self.assertRaises(ValueError):
            self.submit('new', lambda *_: self.fail('Closed workspace started work'), allow_new=False)
        self.assertEqual(list(self.root.iterdir()), [])
