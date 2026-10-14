#!/usr/bin/env python3
"""Create a private config and token for a new local installation."""
import argparse
import json
import os
import secrets
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, help='Existing or new demo project directory')
    parser.add_argument('--config-dir', default=str(Path.home() / '.config/notion-local-mcp'))
    args = parser.parse_args()
    project = Path(args.project).expanduser().resolve()
    config_dir = Path(args.config_dir).expanduser().resolve()
    project.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path = config_dir / 'config.json'
    token_path = config_dir / 'token'
    if config_path.exists() or token_path.exists():
        raise SystemExit('Refusing to overwrite an existing config or token')
    template = Path(__file__).resolve().parents[1] / 'config.example.json'
    config = json.loads(template.read_text())
    text = json.dumps(config, ensure_ascii=False, indent=2)
    text = text.replace('__PROJECT_ROOT__', str(project)).replace('__CONFIG_DIR__', str(config_dir))
    config_path.write_text(text + '\n')
    os.chmod(config_path, 0o600)
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(secrets.token_urlsafe(48) + '\n')
    print(f'Created config: {config_path}')
    print(f'Created token: {token_path} (value not displayed)')


if __name__ == '__main__':
    main()
