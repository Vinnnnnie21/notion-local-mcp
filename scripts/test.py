#!/usr/bin/env python3
"""Run the portable unit test suite from the repository root."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
suite = unittest.defaultTestLoader.discover(str(ROOT / 'app' / 'tests'), pattern='test_*.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
