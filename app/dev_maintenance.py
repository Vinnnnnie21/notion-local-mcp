"""固定 MCP 安装目录的维护；候选版本由本机流程登记。"""
import argparse
import ast
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

SERVICE = os.environ.get('NOTION_MCP_SERVICE_NAME', 'notion-local-mcp.service')
IDENTIFIER = re.compile(r'^[A-Za-z0-9_-]{1,100}$')
PROTECTED_CONFIG = ('stateDir', 'projects', 'executionProfiles', 'authorizedRoots', 'administratorPaths', 'sensitiveGrants')


def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_relative(relative):
    q = Path(relative)
    if q.is_absolute() or '..' in q.parts or '\0' in relative:
        raise ValueError('Invalid maintenance manifest path')
    if relative not in {'config.json', 'app/requirements.txt'} and not (len(q.parts) >= 2 and q.parts[0] == 'app' and q.suffix == '.py'):
        raise ValueError('Maintenance candidate path is outside fixed app scope')
    if any(part.startswith('.') or part in {'tests', 'state', 'token', 'approvals'} for part in q.parts):
        raise ValueError('Maintenance private path is forbidden')
    return q


def regular(root, relative):
    target = root / relative
    current = root
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            raise ValueError('Maintenance symbolic links are forbidden')
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024 ** 2:
            raise ValueError('Invalid maintenance file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(4 * 1024 ** 2 + 1)
        if len(raw) > 4 * 1024 ** 2:
            raise ValueError('Maintenance file too large')
        return raw, stat.S_IMODE(info.st_mode)
    finally:
        os.close(fd)


def atomic(path, raw, mode=0o600):
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('Maintenance target symbolic link refused')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.maintenance-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), mode & 0o777); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def layout(root):
    base = root / 'state' / 'maintenance'
    for folder in (base, base / 'candidates', base / 'backups', base / 'jobs'):
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base


def key(root, create=False):
    path = layout(root) / 'registry-key'
    if create and not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(secrets.token_bytes(32))
    raw, mode = regular(layout(root), 'registry-key')
    if len(raw) != 32 or mode & 0o077:
        raise ValueError('Invalid local maintenance registry key')
    return raw


def sign(root, value):
    return hmac.new(key(root), canonical(value), hashlib.sha256).hexdigest()


def read_registered(root, folder, identifier):
    if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
        raise ValueError('Invalid registered maintenance identifier')
    location = layout(root) / folder / identifier
    raw, _ = regular(location, 'manifest.json')
    envelope = json.loads(raw)
    record = envelope.get('record')
    if not isinstance(record, dict) or not hmac.compare_digest(sign(root, record), envelope.get('signature', '')):
        raise ValueError('Local maintenance manifest signature mismatch')
    if record.get('id') != identifier or record.get('kind') != folder:
        raise ValueError('Maintenance manifest identity mismatch')
    if not isinstance(record.get('files'), list) or not 1 <= len(record['files']) <= 100:
        raise ValueError('Invalid maintenance manifest file count')
    seen = set(); files = []
    for entry in record['files']:
        relative = entry.get('path'); safe_relative(relative)
        if relative in seen:
            raise ValueError('Repeated maintenance manifest path')
        seen.add(relative)
        raw, mode = regular(location / 'files', relative)
        if sha(raw) != entry['sha256'] or len(raw) != entry['size']:
            raise ValueError('Registered maintenance file changed')
        files.append((relative, raw, mode))
    return record, files


def validate_candidate(root, candidateId):
    record, files = read_registered(root, 'candidates', candidateId)
    current = json.loads(regular(root, 'config.json')[0])
    evidence_raw, _ = regular(layout(root) / 'candidates' / candidateId, 'evidence.json')
    evidence = json.loads(evidence_raw)
    if record.get('evidenceHash') != sha(evidence_raw) or evidence.get('status') != 'passed' or evidence.get('schemaValidated') is not True or type(evidence.get('testCount')) is not int or evidence['testCount'] < 1 or evidence.get('filesBinding') != sha(canonical(record['files'])):
        raise ValueError('Registered candidate lacks matching passed test and schema evidence')
    if record.get('configBinding') != sha(canonical({k: current.get(k) for k in PROTECTED_CONFIG})):
        raise ValueError('Registered candidate authorization changed; local registration required')
    for relative, raw, _ in files:
        if relative.endswith('.py'):
            ast.parse(raw, filename=relative)
        elif relative == 'config.json':
            candidate = json.loads(raw)
            if {k: candidate.get(k) for k in PROTECTED_CONFIG} != {k: current.get(k) for k in PROTECTED_CONFIG}:
                raise ValueError('Candidate cannot change authorization or private state')
    return {'valid': True, 'candidateId': candidateId, 'version': record.get('version'), 'files': [{'path': r, 'sha256': sha(b)} for r, b, _ in files]}


def validate_fixed_policy(root):
    if os.geteuid() == 0:
        raise ValueError('MCP maintenance must run as the existing non-root user')
    config = json.loads(regular(root, 'config.json')[0])
    policy = config.get('executionProfiles', {}).get('mcp-self-maintenance', {})
    settings = policy.get('maintenance', {})
    if policy.get('enabled') is not True or policy.get('environment') != 'fixed-maintenance' or policy.get('network', {}).get('mode') not in {'none', 'loopback-only'}:
        raise ValueError('Fixed MCP maintenance policy disabled or changed')
    if Path(settings.get('installationRoot', '')).resolve() != root.resolve() or settings.get('services') != [SERVICE] or Path(settings.get('registeredCandidates', '')).resolve() != root / 'state/maintenance/candidates':
        raise ValueError('Fixed MCP maintenance scope changed')
    if Path(config.get('stateDir', '')).resolve() != root / 'state':
        raise ValueError('Fixed MCP maintenance state identity changed')


def register_candidate(root, source, candidateId, version):
    """仅由本机部署流程调用；不注册为 MCP 工具。"""
    if not IDENTIFIER.fullmatch(candidateId) or not isinstance(version, str) or len(version) > 100:
        raise ValueError('Invalid local candidate registration')
    root = Path(root).resolve(); source = Path(source).resolve()
    base = layout(root); key(root, True)
    location = base / 'candidates' / candidateId
    if location.exists():
        raise ValueError('Candidate already registered')
    location.mkdir(mode=0o700); entries = []
    try:
        candidates = []
        for directory, dirs, names in os.walk(source / 'app'):
            dirs[:] = [name for name in dirs if name != 'tests' and not name.startswith('.')]
            for name in names:
                relative = (Path(directory) / name).relative_to(source).as_posix()
                if relative.endswith('.py') or relative == 'app/requirements.txt':
                    safe_relative(relative); candidates.append(relative)
        if (source / 'config.json').is_file():
            candidates.append('config.json')
        for relative in sorted(candidates):
            raw, mode = regular(source, relative)
            atomic(location / 'files' / relative, raw, mode)
            entries.append({'path': relative, 'sha256': sha(raw), 'size': len(raw)})
        current = json.loads(regular(root, 'config.json')[0])
        evidence_raw, _ = regular(source, 'maintenance-evidence.json')
        evidence = json.loads(evidence_raw)
        if evidence.get('status') != 'passed' or evidence.get('schemaValidated') is not True or type(evidence.get('testCount')) is not int or evidence['testCount'] < 1 or evidence.get('filesBinding') != sha(canonical(entries)):
            raise ValueError('Local registration requires matching passed test and schema evidence')
        atomic(location / 'evidence.json', evidence_raw)
        record = {'id': candidateId, 'kind': 'candidates', 'version': version, 'created': time.time(), 'files': entries,
                  'configBinding': sha(canonical({k: current.get(k) for k in PROTECTED_CONFIG})), 'evidenceHash': sha(evidence_raw)}
        atomic(location / 'manifest.json', canonical({'record': record, 'signature': sign(root, record)}))
        validate_candidate(root, candidateId)
        return {'registered': True, 'candidateId': candidateId, 'files': len(entries)}
    except Exception:
        shutil.rmtree(location)
        raise


def create_backup(root, paths=None):
    backupId = 'backup-' + time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '-' + secrets.token_hex(4)
    base = layout(root); key(root, True)
    destination = base / 'backups' / backupId; destination.mkdir(mode=0o700)
    if paths is None:
        paths = ['config.json']
        for directory, dirs, names in os.walk(root / 'app'):
            dirs[:] = [name for name in dirs if name != 'tests' and not name.startswith('.')]
            for name in names:
                relative = (Path(directory) / name).relative_to(root).as_posix()
                if relative.endswith('.py') or relative == 'app/requirements.txt':
                    try:
                        safe_relative(relative)
                    except ValueError:
                        continue
                    paths.append(relative)
    entries = []; missing = []
    for relative in paths:
        safe_relative(relative)
        if not (root / relative).exists():
            missing.append(relative); continue
        raw, mode = regular(root, relative)
        atomic(destination / 'files' / relative, raw, mode)
        entries.append({'path': relative, 'sha256': sha(raw), 'size': len(raw)})
    record = {'id': backupId, 'kind': 'backups', 'created': time.time(), 'files': entries, 'missing': missing}
    atomic(destination / 'manifest.json', canonical({'record': record, 'signature': sign(root, record)}))
    return {'backupId': backupId, 'files': [{'path': x['path'], 'sha256': x['sha256']} for x in entries], 'missingPaths': missing}


def fixed_restart():
    completed = subprocess.run(['systemctl', '--user', 'restart', SERVICE], capture_output=True, timeout=30,
                               env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(os.getuid()) + '/bus'})
    if completed.returncode:
        raise ValueError('Fixed MCP service restart failed')


def health_check(auth_handle):
    if not isinstance(auth_handle, str) or not 32 <= len(auth_handle) <= 4096 or '\n' in auth_handle or '\r' in auth_handle:
        raise ValueError('Fixed maintenance authentication handle unavailable')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 30
    for _ in range(20):
        if time.monotonic() > deadline:
            break
        try:
            request = urllib.request.Request('http://127.0.0.1:8001/health', headers={'Authorization': 'Bearer ' + auth_handle})
            with opener.open(request, timeout=2) as response:
                result = json.loads(response.read(65536))
            if result.get('state') == 'ok':
                import jsonschema
                def rpc(method, params):
                    request = urllib.request.Request('http://127.0.0.1:8001/mcp', data=canonical({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
                                                     headers={'Authorization': 'Bearer ' + auth_handle, 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'})
                    with opener.open(request, timeout=5) as response:
                        body = response.read(3 * 1024 ** 2 + 1)
                    if len(body) > 3 * 1024 ** 2:
                        raise ValueError('Maintenance MCP response exceeds limit')
                    envelope = json.loads(body)
                    if 'error' in envelope:
                        raise ValueError('Maintenance MCP protocol verification failed')
                    return envelope['result']
                discovered = rpc('tools/list', {})['tools']
                names = {item['name'] for item in discovered}
                if not {'health', 'get_capabilities', 'dev_mcp_maintenance'} <= names:
                    raise ValueError('Maintenance tool discovery verification failed')
                for item in discovered:
                    jsonschema.Draft202012Validator.check_schema(item['inputSchema'])
                for name in ('health', 'get_capabilities'):
                    called = rpc('tools/call', {'name': name, 'arguments': {}})
                    if called.get('isError'):
                        raise ValueError('Maintenance tool smoke failed')
                    value = json.loads(called['content'][0]['text'])
                    if name == 'health' and value.get('state') != 'ok':
                        raise ValueError('Maintenance health tool failed')
                    if not isinstance(value, dict):
                        raise ValueError('Maintenance capability response invalid')
                return {'healthy': True, 'version': result.get('version'), 'toolDiscovery': 'verified_authenticated_wire_tools_list', 'apiVerification': 'authenticated_health_and_capabilities', 'toolCount': len(discovered)}
        except Exception:
            pass
        time.sleep(.25)
    raise ValueError('MCP health check failed')


def restore_backup(root, backupId):
    record, files = read_registered(root, 'backups', backupId)
    current = json.loads(regular(root, 'config.json')[0])
    for relative, raw, _ in files:
        if relative == 'config.json':
            candidate = json.loads(raw)
            if {k: candidate.get(k) for k in PROTECTED_CONFIG} != {k: current.get(k) for k in PROTECTED_CONFIG}:
                raise ValueError('Backup authorization differs; use local administrator recovery')
    for relative, raw, mode in files:
        atomic(root / safe_relative(relative), raw, mode)
    for relative in record.get('missing', []):
        safe_relative(relative)
        target = root / relative
        if target.is_symlink():
            raise ValueError('Recovery destination symbolic link refused')
        if target.exists():
            target.unlink()
    return {'restored': True, 'backupId': backupId}


def execute_maintenance(root, operation, candidateId=None, backupId=None, restart=None, health=None, auth_handle=None):
    root = Path(root); restart = restart or fixed_restart; health = health or (lambda: health_check(auth_handle))
    validate_fixed_policy(root)
    if operation == 'restart':
        restart(); return health() | {'operation': 'restart'}
    if operation == 'rollback':
        restore_backup(root, backupId); restart()
        return health() | {'operation': 'rollback', 'backupId': backupId}
    if operation != 'deploy':
        raise ValueError('Unsupported maintenance worker operation')
    validate_candidate(root, candidateId)
    record, files = read_registered(root, 'candidates', candidateId)
    backup = create_backup(root, [x[0] for x in files]); snapshotId = backup['backupId']
    try:
        for relative, raw, mode in files:
            validate_fixed_policy(root)
            target = root / safe_relative(relative)
            if target.is_symlink():
                raise ValueError('Deployment target symbolic link refused')
            original_mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else mode
            atomic(target, raw, original_mode)
        restart(); result = health()
        if result.get('version') != record.get('version'):
            raise ValueError('MCP candidate version verification failed')
        return result | {'operation': 'deploy', 'candidateId': candidateId, 'version': record.get('version'), 'backupId': snapshotId, 'rolledBack': False}
    except Exception:
        restore_backup(root, snapshotId)
        try:
            restart(); recovered = health()
            return recovered | {'operation': 'deploy', 'candidateId': candidateId, 'backupId': snapshotId, 'deployed': False, 'rolledBack': True}
        except Exception:
            return {'operation': 'deploy', 'candidateId': candidateId, 'backupId': snapshotId, 'deployed': False, 'rolledBack': True, 'healthy': False, 'error': 'Recovery health verification failed; local administrator action required'}


def attach_maintenance(cls):
    def fixed_root(self, profile):
        policy = self.dev_policy(profile)
        if profile != 'mcp-self-maintenance':
            raise ValueError('MCP maintenance requires fixed maintenance profile')
        settings = policy.get('maintenance', {})
        root = Path(settings.get('installationRoot', '')).resolve()
        if root != self.config_path.parent or self.config_path.name != 'config.json' or self.state != root / 'state':
            raise ValueError('MCP maintenance installation identity mismatch')
        if settings.get('services') != [SERVICE] or Path(settings.get('registeredCandidates', '')).resolve() != root / 'state' / 'maintenance' / 'candidates':
            raise ValueError('MCP maintenance permits only the fixed MCP service and registry')
        return root

    def dev_mcp_maintenance(self, profile, operation, requestId, candidateId=None, backupId=None):
        root = self.dev_maintenance_root(profile)
        if not IDENTIFIER.fullmatch(requestId) or operation not in {'status', 'validate', 'backup', 'deploy', 'rollback', 'restart', 'verify'}:
            raise ValueError('Invalid maintenance request')
        if operation in {'validate', 'deploy'} and not candidateId:
            raise ValueError('Registered candidateId required')
        if operation == 'rollback' and not backupId:
            raise ValueError('Registered backupId required')
        base = layout(root); job_file = base / 'jobs' / (requestId + '.json')
        if operation == 'status':
            if not job_file.exists():
                return {'requestId': requestId, 'status': 'not_found', 'service': SERVICE}
            record = json.loads(regular(base / 'jobs', requestId + '.json')[0])
            return {k: record[k] for k in ('requestId', 'status', 'operation', 'result') if k in record}
        if operation == 'verify':
            if not job_file.exists():
                raise ValueError('Unknown maintenance request; use the same requestId returned by deploy/restart/rollback, then query operation=status before operation=verify. Do not create a new verification requestId.')
            record = json.loads(regular(base / 'jobs', requestId + '.json')[0])
            if record['status'] == 'complete':
                return {'requestId': requestId, 'status': 'complete', 'result': record.get('result'), 'replayed': False}
            if record['status'] != 'awaiting_client_verification':
                raise ValueError('Maintenance is not ready for authenticated client verification')
            try:
                import jsonschema
                schemas = getattr(self, 'dev_discovery_schemas', None)
                if not isinstance(schemas, dict) or 'dev_mcp_maintenance' not in schemas:
                    raise ValueError('Current server discovery schemas are unavailable')
                for name, schema in schemas.items():
                    jsonschema.Draft202012Validator.check_schema(schema)
                    if not callable(getattr(self, name, None)):
                        raise ValueError('Tool discovery method missing')
                healthy = self.health()
                if healthy.get('state') != 'ok':
                    raise ValueError('Current MCP health tool failed')
                capabilities = self.get_capabilities()
                if not isinstance(capabilities, dict):
                    raise ValueError('Current MCP capability smoke failed')
                if record.get('operation') == 'deploy' and record.get('candidateId') and not record['result'].get('rolledBack'):
                    registered, _ = read_registered(root, 'candidates', record['candidateId'])
                    if registered.get('version') != healthy.get('version'):
                        raise ValueError('Current MCP version differs from candidate')
                record['result'].update(toolDiscovery='verified_current_registered_schemas', apiVerification='authenticated_maintenance_tool_with_health_and_capabilities', toolCount=len(schemas))
                record['status'] = 'complete'; atomic(job_file, canonical(record))
                return {'requestId': requestId, 'status': 'complete', 'result': record['result']}
            except Exception:
                record['status'] = 'verification_failed'; record['result']['apiVerification'] = 'failed'; atomic(job_file, canonical(record))
                snapshot = record['result'].get('backupId')
                if snapshot and record.get('operation') == 'deploy' and not record['result'].get('rolledBack'):
                    recovery_id = 'recovery-' + sha(requestId.encode())[:24]
                    return {'requestId': requestId, 'status': 'verification_failed', 'rollback': self.dev_mcp_maintenance(profile, 'rollback', recovery_id, backupId=snapshot)}
                return {'requestId': requestId, 'status': 'verification_failed', 'error': 'Authenticated MCP verification failed; local maintenance required'}
        binding = sha(canonical([operation, candidateId, backupId]))
        if job_file.exists():
            old = json.loads(regular(base / 'jobs', requestId + '.json')[0])
            if old['binding'] != binding:
                raise ValueError('Maintenance request identifier reused with different arguments')
            return {'requestId': requestId, 'status': old['status'], 'result': old.get('result'), 'replayed': False}
        if operation == 'validate':
            result = validate_candidate(root, candidateId)
        elif operation == 'backup':
            result = create_backup(root)
        else:
            if operation == 'deploy':
                validate_candidate(root, candidateId)
            if operation == 'rollback':
                read_registered(root, 'backups', backupId)
            auth_handle = getattr(self, 'dev_maintenance_auth', None)
            if not isinstance(auth_handle, str) or not 32 <= len(auth_handle) <= 4096 or '\n' in auth_handle or '\r' in auth_handle:
                raise ValueError('Fixed maintenance process authentication handle unavailable')
            for prior in (base / 'jobs').glob('*.json'):
                if json.loads(regular(base / 'jobs', prior.name)[0]).get('status') in {'queued', 'running', 'awaiting_client_verification'}:
                    raise ValueError('MCP maintenance already pending; inspect existing request status')
            atomic(job_file, canonical({'requestId': requestId, 'operation': operation, 'binding': binding, 'status': 'queued', 'created': time.time(), 'candidateId': candidateId, 'backupId': backupId}))
            worker = root / 'app' / 'dev_maintenance.py'
            # 独立 systemd 单元使维护进程在 MCP 主服务重启时仍能验收及回退。
            transient_unit = 'notion-local-mcp-maintenance-' + sha(requestId.encode())[:24]
            started = subprocess.Popen(['systemd-run', '--user', '--quiet', '--collect', '--pipe', '--wait', '--unit=' + transient_unit,
                                      '--property=RuntimeMaxSec=180', '--property=NoNewPrivileges=yes',
                                      str(root / 'venv' / 'bin' / 'python'), str(worker), '--worker', str(root), requestId],
                                     env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(os.getuid()) + '/bus'},
                                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            # 只通过匿名 stdin 管道传现有进程内句柄，不放参数、环境或审计记录。
            started.stdin.write((auth_handle + '\n').encode()); started.stdin.flush(); started.stdin.close()
            threading.Thread(target=started.wait, daemon=True).start()
            return {'requestId': requestId, 'status': 'queued', 'operation': operation, 'automatic': True, 'replayed': False}
        record = {'requestId': requestId, 'operation': operation, 'binding': binding, 'status': 'complete', 'result': result}
        atomic(job_file, canonical(record))
        return record

    cls.dev_maintenance_root = fixed_root
    cls.dev_mcp_maintenance = dev_mcp_maintenance


TOOL_DESCRIPTIONS = {'dev_mcp_maintenance': '验证本机登记的 MCP 候选版本、备份、部署、回退或重启固定 MCP 服务；不接受代码上传，不修改令牌或扩大授权。'}
TOOL_SCHEMAS = {'dev_mcp_maintenance': {'type': 'object', 'properties': {
    'profile': {'type': 'string', 'enum': ['mcp-self-maintenance']}, 'operation': {'type': 'string', 'enum': ['status', 'validate', 'backup', 'deploy', 'rollback', 'restart', 'verify']},
    'requestId': {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{1,100}$', 'description': 'status 和 verify 沿用此前 deploy/restart/rollback 返回的 requestId；verify 不创建新维护请求。'}, 'candidateId': {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{1,100}$'}, 'backupId': {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{1,100}$'}},
    'required': ['profile', 'operation', 'requestId'], 'additionalProperties': False}}


def worker(root, requestId, auth_handle):
    base = layout(root); lock = os.open(base / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    job_file = base / 'jobs' / (requestId + '.json')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record = json.loads(regular(base / 'jobs', requestId + '.json')[0])
        if record['status'] != 'queued':
            return
        validate_fixed_policy(root)
        record['status'] = 'running'; atomic(job_file, canonical(record))
        result = execute_maintenance(root, record['operation'], record.get('candidateId'), record.get('backupId'), auth_handle=auth_handle)
        verified = result.get('toolDiscovery') == 'verified_authenticated_wire_tools_list'
        record.update(status='complete' if result.get('healthy') and verified else 'failed', result=result); atomic(job_file, canonical(record))
    except Exception:
        if job_file.exists():
            record = json.loads(regular(base / 'jobs', requestId + '.json')[0])
            record.update(status='failed', result={'error': 'Fixed MCP maintenance failed; inspect local deployment evidence'})
            atomic(job_file, canonical(record))
    finally:
        os.close(lock)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', nargs=2, metavar=('INSTALLATION_ROOT', 'REQUEST_ID'))
    parser.add_argument('--register', nargs=4, metavar=('INSTALLATION_ROOT', 'SOURCE_ROOT', 'CANDIDATE_ID', 'VERSION'))
    args = parser.parse_args()
    if args.worker:
        installation, identifier = args.worker
        if not IDENTIFIER.fullmatch(identifier):
            raise SystemExit(2)
        handle = sys.stdin.buffer.readline(4098).decode().rstrip('\n')
        if not 32 <= len(handle) <= 4096 or '\n' in handle or '\r' in handle:
            raise SystemExit(2)
        worker(Path(installation).resolve(), identifier, handle)
    elif args.register:
        installation, source, identifier, version = args.register
        print(json.dumps(register_candidate(Path(installation), Path(source), identifier, version)))
