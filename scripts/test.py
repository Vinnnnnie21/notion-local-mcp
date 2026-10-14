#!/usr/bin/env python3
"""Run the repository tests from the repository root.

The default suite is portable. Pass ``--integration`` on a host with the
isolated runtimes and user systemd setup required by the integration tests.
"""
import argparse
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--integration', action='store_true', help='run tests that require the isolated Linux runtime')
args = parser.parse_args()
if args.integration:
    os.environ['NOTION_MCP_RUN_INTEGRATION'] = '1'
sys.path.insert(0, str(ROOT / 'app'))
suite = unittest.defaultTestLoader.discover(str(ROOT / 'app' / 'tests'), pattern='test_*.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
