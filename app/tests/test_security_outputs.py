"""Credential output and diagnostic boundaries using synthetic data only."""
import json
import unittest

from credential_scan import first_finding
from dev_diagnostics import DevelopmentDenied, application_status, diagnostic_for
from file_access import safe_output


class SecurityOutputs(unittest.TestCase):
    def test_numeric_fencing_generation_remains_readable(self):
        source = 'fencing_token: int = 42\n'
        self.assertIsNone(first_finding(source.encode(), 'worker.py'))
        self.assertEqual(safe_output(source, 'worker.py'), source)

    def test_string_fencing_generation_is_a_credential(self):
        source = 'fencing_token = "SYNTHETIC_CREDENTIAL_12345"\n'
        self.assertIsNotNone(first_finding(source.encode(), 'worker.py'))
        self.assertNotIn('SYNTHETIC_CREDENTIAL_12345', safe_output(source, 'worker.py'))

    def test_typed_assignment_redacts_only_the_literal(self):
        source = 'api_key: str = "SYNTHETIC_CREDENTIAL_12345"\nprint(42)\n'
        redacted = safe_output(source, 'worker.py')
        self.assertNotIn('SYNTHETIC_CREDENTIAL_12345', redacted)
        self.assertIn('api_key: str', redacted)
        self.assertIn('print(42)', redacted)
        compile(redacted, 'worker.py', 'exec')

    def test_credentials_in_comparisons_are_redacted(self):
        for path, source in [('worker.py', 'if token == "SYNTHETIC_CREDENTIAL_12345": pass\n'),
                             ('worker.ts', 'if (token === "SYNTHETIC_CREDENTIAL_12345") run();')]:
            with self.subTest(path=path):
                self.assertIsNotNone(first_finding(source.encode(), path))
                self.assertNotIn('SYNTHETIC_CREDENTIAL_12345', safe_output(source, path))

    def test_plain_logs_do_not_get_numeric_source_exemptions(self):
        self.assertIsNotNone(first_finding(b'token=12345678', 'output.log'))

    def test_diagnostic_omits_host_paths_and_exception_details(self):
        error = PermissionError('/private/host/project/file.txt SYNTHETIC_CREDENTIAL_12345')
        diagnostic = diagnostic_for(error, 'workspace', 'dev_read', 'preflight')
        self.assertNotIn('/private/host', json.dumps(diagnostic))
        self.assertNotIn('SYNTHETIC_CREDENTIAL', json.dumps(diagnostic))
        self.assertEqual(diagnostic['rule_id'], 'filesystem.permission')
        self.assertEqual(diagnostic['workspace_id'], 'workspace')

    def test_diagnostic_keeps_relative_file_location(self):
        error = DevelopmentDenied('Content withheld', 'secret.assignment', 'src/main.py', line=4)
        diagnostic = diagnostic_for(error, 'workspace', 'dev_write', 'preflight')
        self.assertEqual(diagnostic['path'], 'src/main.py')
        self.assertEqual(diagnostic['line'], 4)
        absolute = DevelopmentDenied('Content withheld', 'path.sensitive', '/private/host/file')
        self.assertNotIn('path', absolute.diagnostic)

    def test_audit_status_distinguishes_partial_failure(self):
        self.assertEqual(application_status({'applied': False, 'results': [{'applied': True}, {'applied': False}]}), 'partial_failure')
        self.assertEqual(application_status({'applied': False}), 'not_applied')
        self.assertEqual(application_status({'status': 'unknown'}), 'unknown')
