#!/usr/bin/env python3
"""Report prerequisites without changing the host."""
import argparse
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path


def command_ok(name):
    return shutil.which(name) is not None


def systemd_user():
    if not command_ok('systemctl'):
        return False
    result = subprocess.run(['systemctl', '--user', 'is-system-running'], capture_output=True, text=True)
    return result.returncode in (0, 1) and bool(os.environ.get('XDG_RUNTIME_DIR'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', action='store_true', help='Exit nonzero when isolated execution is unavailable')
    args = parser.parse_args()
    checks = {
        'python': True,
        'mcp_python_package': importlib.util.find_spec('mcp') is not None,
        'bubblewrap': command_ok('bwrap'),
        'nsenter': command_ok('nsenter'),
        'git': command_ok('git'),
        'node': command_ok('node'),
        'npm': command_ok('npm'),
        'postgresql': command_ok('initdb') or command_ok('postgres'),
        'chromium': command_ok('chromium') or command_ok('chromium-browser') or command_ok('google-chrome'),
        'user_systemd': systemd_user(),
        'cgroup_v2': Path('/sys/fs/cgroup/cgroup.controllers').exists(),
    }
    for name, available in checks.items():
        print(f'{name}: {"ok" if available else "missing"}')
    required = ('mcp_python_package', 'bubblewrap', 'nsenter', 'git', 'user_systemd', 'cgroup_v2')
    raise SystemExit(0 if not args.strict or all(checks[name] for name in required) else 1)


if __name__ == '__main__':
    main()
