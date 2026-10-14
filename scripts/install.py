#!/usr/bin/env python3
"""Install application files into a user-owned prefix without touching private config."""
import argparse
import shutil
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', default=str(Path.home() / '.local/share/notion-local-mcp'))
    parser.add_argument('--update', action='store_true', help='Update an existing application prefix')
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    destination = Path(args.destination).expanduser().resolve()
    if destination.exists() and not args.update:
        raise SystemExit('Destination exists; pass --update to replace application files')
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ('app', 'scripts', 'systemd', 'docs'):
        target = destination / name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source / name, target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in ('README.md', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', '.gitignore', 'config.example.json'):
        shutil.copy2(source / name, destination / name)
    print(f'Installed application files at {destination}')
    print('Private config and token were not copied or changed.')


if __name__ == '__main__':
    main()
