"""开发副本的自动文件操作；原工作区同步单独校验哈希和授权。"""
import base64
import ctypes
import difflib
import errno
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from file_access import SECRET, sensitive, safe_output, within, open_components

SKIP_DIRS = {'.git', '.ssh', '.aws', '.gnupg', '.config', 'node_modules', '.venv', 'venv', '__pycache__', '.pytest_cache', '.uv-cache', 'state', 'runtime', 'backups', '.scratch', '.cache', '.codex', '.local'}
PRIVATE_DIRS = {'.git', '.ssh', '.aws', '.gnupg', '.config', '.codex'}
DEPENDENCY_DIRS = {'.dev-dependencies', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'}
BLOCK_NAMES = {'config.json', 'config.local.json', 'production.json', 'production.yaml', 'production.yml', 'settings.local.json'}
HASH = re.compile(r'^[0-9a-f]{64}$')
ID = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def generated_dependency(relative):
    return any(part in DEPENDENCY_DIRS for part in Path(relative).parts)


def possible_secret(data):
    markers = (b'password', b'passwd', b'secret', b'token', b'api', b'access', b'bearer ', b'private key', b'://', b'akia', b'ghp_', b'gho_', b'ghu_', b'ghs_', b'ghr_', b'sk-')
    lower = data.lower()
    if not any(marker in lower for marker in markers):
        return False
    # URI 分支从固定分隔符开始匹配；完整扫描保留跨窗口的凭据保护。
    return bool(SECRET.search(data))


def denied_relative(relative, policy, source=False):
    q = Path(relative)
    if q.is_absolute() or '..' in q.parts or not q.parts or '\0' in str(relative):
        raise ValueError('Use workspace-relative path without traversal')
    code = q.suffix.lower() in {'.py', '.ts', '.tsx', '.js', '.jsx', '.rs', '.go', '.java', '.c', '.cpp', '.h'}
    # 数据库只允许在隔离副本创建；宿主机数据库永不复制或同步。
    temp_db = not source and q.suffix.lower() in {'.db', '.db3', '.sqlite', '.sqlite3', '.sql'}
    if source and generated_dependency(q):
        raise ValueError('Generated dependencies cannot be copied or synchronized from the original project')
    if not source and generated_dependency(q):
        if any(part == '.git' for part in q.parts):
            raise ValueError('Git internals are excluded from execution tree')
        if any(fnmatch.fnmatchcase(q.as_posix(), pattern) for pattern in policy.get('denyPaths', []) if not Path(pattern).is_absolute() and not any(part in DEPENDENCY_DIRS for part in Path(pattern).parts)):
            raise ValueError('Path denied by execution profile')
        return q
    if any(p.lower() in PRIVATE_DIRS or p.lower() == '.env' or p.lower().startswith('.env.') or (source and p.lower() in SKIP_DIRS) or p.lower() in BLOCK_NAMES for p in q.parts) or (sensitive(q) and not code and not temp_db):
        raise ValueError('Sensitive or execution-state path is excluded')
    if any(fnmatch.fnmatchcase(q.as_posix(), p) or fnmatch.fnmatchcase(q.name, p) for p in policy.get('denyPaths', []) if not Path(p).is_absolute()):
        raise ValueError('Path denied by execution profile')
    return q


def read_regular(root, relative, maximum):
    fd = open_components(root, relative, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Require regular file without hard links')
        if info.st_size > maximum:
            raise ValueError('File exceeds development size limit')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('File exceeds development size limit')
        return data, stat.S_IMODE(info.st_mode)
    finally:
        os.close(fd)


def manifest(root, policy, include_content=False):
    """拒绝链接与特殊文件；执行产物也不能把秘密带回宿主机。"""
    output = {}; total = 0
    maximum = int(policy.get('limits', {}).get('diskBytes', 512 * 1024 * 1024))
    files = int(policy.get('limits', {}).get('files', 30000))
    generated_files = int(policy.get('limits', {}).get('generatedFiles', 50000))
    generated_count = 0; source_files = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in sorted(dirs + names):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            denied_relative(rel, policy)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError('Workspace symbolic links are not exportable')
            if stat.S_ISDIR(info.st_mode):
                output[rel] = {'type': 'directory', 'mode': stat.S_IMODE(info.st_mode)}
            else:
                raw, mode = read_regular(root, rel, maximum)
                if not generated_dependency(rel) and possible_secret(raw):
                    raise ValueError('Possible secret detected; content withheld')
                total += len(raw)
                if total > maximum:
                    raise ValueError('Workspace disk budget exceeded')
                output[rel] = {'type': 'file', 'hash': digest(raw), 'mode': mode, 'size': len(raw)}
                if include_content:
                    output[rel]['data'] = base64.b64encode(raw).decode()
            if generated_dependency(rel):
                generated_count += 1
                if generated_count > generated_files:
                    raise ValueError('Generated dependency file budget exceeded')
            elif output[rel]['type'] == 'file':
                source_files += 1
            if source_files > files:
                raise ValueError('Workspace file budget exceeded')
    return output


def git_command(repo, args, timeout=20):
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-C', str(repo), *args],
                            env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ValueError('Local Git operation failed; inspect task diff or conflicts')
    return result.stdout


def attach_workspace(cls):
    previous_init = cls.__init__

    def initialize(self, config_path):
        previous_init(self, config_path)
        self.dev_root = self.state / 'development'
        self.dev_root.mkdir(mode=0o700, exist_ok=True)
        self.dev_workspaces = {}
        self.dev_project_config = json.loads(self.config_path.read_text()).get('projects', {})

    def dev_policy(self, profile):
        fresh = json.loads(self.config_path.read_text())
        policies = fresh.get('executionProfiles', {})
        policy = policies.get(profile)
        if not isinstance(policy, dict) or policy.get('enabled') is not True:
            raise ValueError('Execution profile disabled or not configured')
        policy = json.loads(json.dumps(policy))
        limits = policy.setdefault('limits', {})
        aliases = {'maxWorkspaceBytes': 'diskBytes', 'maxWorkspaceFiles': 'files'}
        for key, target in aliases.items():
            if key in limits:
                if target in limits and limits[key] != limits[target]:
                    raise ValueError('Conflicting development limit aliases')
                limits[target] = limits[key]
        expected = {'autonomous-development': 'isolated-development', 'readonly-runtime': 'fixed-readonly', 'mcp-self-maintenance': 'fixed-maintenance'}
        if profile not in expected or policy.get('environment') != expected[profile]:
            raise ValueError('Invalid execution profile environment')
        for field in ('readRoots', 'writeRoots'):
            values = policy.get(field, [])
            if not isinstance(values, list):
                raise ValueError('Invalid profile root list')
            for value in values:
                root = Path(value)
                if not root.is_absolute() or root.resolve() == Path('/'):
                    raise ValueError('Profile roots must be explicit absolute directories')
        network_mode = policy.get('network', {}).get('mode')
        allowed_network = {'autonomous-development': {'loopback-only'}, 'readonly-runtime': {'none', 'loopback-only'}, 'mcp-self-maintenance': {'none', 'loopback-only'}}
        if network_mode not in allowed_network[profile]:
            raise ValueError('Unsupported execution network policy')
        # 项目身份和根路径固定；普通工具不能改变启动时加载的授权项目。
        projects = policy.get('projects', [])
        if not isinstance(projects, list) or any(x not in self.projects for x in projects):
            raise ValueError('Profile references unknown project')
        for name in projects:
            live = fresh.get('projects', {}).get(name)
            original = self.project(name)
            if not isinstance(live, dict) or Path(live.get('root', '')).resolve() != original['root']:
                raise ValueError('Project identity changed; restart after local configuration validation')
            if original['root'] == Path.home() and profile == 'autonomous-development':
                raise ValueError('Automatic development requires an exact project, not the home browser')
            for key in ('read', 'write', 'writeAllow', 'deny', 'denyDirs'):
                if live.get(key) != self.dev_project_config[name].get(key):
                    raise ValueError('Project permissions changed; restart after local configuration validation')
        limits = policy.get('limits', {})
        for key, maximum in [('diskBytes', 2 * 1024 ** 3), ('files', 100000), ('maxWorkspaces', 20)]:
            if key in limits and (type(limits[key]) is not int or not 1 <= limits[key] <= maximum):
                raise ValueError('Invalid development resource limit')
        return policy

    def check_source(self, project, policy, write=False):
        if project not in policy.get('projects', []):
            raise ValueError('Project is not authorized by execution profile')
        root = self.project(project)['root']
        scopes = [Path(x).resolve() for x in policy.get('writeRoots' if write else 'readRoots', [])]
        if not any(within(root, x) for x in scopes):
            raise ValueError('Project root is outside execution profile')
        for value in policy.get('denyPaths', []):
            if Path(value).is_absolute() and within(root, Path(value).resolve()):
                raise ValueError('Project root is explicitly denied')
        return root

    def source_path(self, project, relative, policy, write=False):
        root = self.dev_check_source(project, policy, write)
        q = denied_relative(relative, policy, source=True)
        target = root / q
        current = root
        for part in q.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('Original workspace symbolic link access refused')
        if any(within(target, private) or (write and within(private, target)) for private in self.private_paths):
            raise ValueError('Administrator path is excluded from development')
        spec = self.project(project)
        if not spec.get('read', True) or (write and not spec.get('write', False)):
            raise ValueError('Original project permission disabled')
        normal = q.as_posix()
        if any(fnmatch.fnmatchcase(normal, p) or fnmatch.fnmatchcase(q.name, p) for p in spec.get('deny', [])):
            raise ValueError('Original project path denied')
        if any(normal == p or normal.startswith(p + '/') for p in spec.get('denyDirs', [])):
            raise ValueError('Original project directory denied')
        if any(Path(p).is_absolute() and within(target, Path(p).resolve()) for p in policy.get('denyPaths', [])):
            raise ValueError('Source path denied by profile')
        if write and not any(fnmatch.fnmatchcase(normal, p) for p in spec.get('writeAllow', [])):
            raise ValueError('Original project write scope exceeded')
        return target

    def dev_workspace(self, workspaceId, profile, allowExpired=False, allowClosed=False):
        policy = self.dev_policy(profile)
        if profile != 'autonomous-development' or not ID.fullmatch(workspaceId):
            raise ValueError('Development workspace requires autonomous-development')
        if workspaceId not in self.dev_workspaces:
            meta_path = self.dev_root / workspaceId / 'metadata.json'
            if not meta_path.is_file():
                raise ValueError('Unknown development workspace')
            self.dev_workspaces[workspaceId] = json.loads(meta_path.read_text())
        meta = self.dev_workspaces[workspaceId]
        if meta.get('profile') != profile or (meta.get('closed') and not allowClosed):
            raise ValueError('Workspace profile mismatch or workspace closed')
        lifetime = policy.get('limits', {}).get('maxWorkspaceSeconds', 86400)
        if type(lifetime) is not int or not 1 <= lifetime <= 7 * 86400:
            raise ValueError('Invalid workspace lifetime')
        if not allowExpired and time.time() - meta['created'] > lifetime:
            raise ValueError('Workspace lifetime exhausted; stop sandbox and close workspace')
        root = self.dev_check_source(meta['project'], policy)
        if str(root) != meta['source'] or Path(meta['path']) != self.dev_root / workspaceId / 'tree':
            raise ValueError('Workspace authorization changed')
        return meta

    def save_meta(self, meta):
        record = {k: v for k, v in meta.items() if k != 'livePath'}
        self.atomic_json(self.dev_root / meta['id'] / 'metadata.json', record)

    def dev_tree(self, meta):
        return Path(meta.get('livePath') or meta['path'])

    def dev_path(self, meta, relative, policy):
        q = denied_relative(relative, policy)
        root = self.dev_tree(meta)
        target = root / q
        # /proc 沙箱根具有内核提供的链接；只拒绝工作目录内的链接。
        current = root
        for part in q.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('Workspace symbolic links require an explicit export path')
        return target

    def request(self, meta, requestId, operation, params):
        if not isinstance(requestId, str) or not ID.fullmatch(requestId):
            raise ValueError('Use a stable alphanumeric requestId')
        binding = digest(json.dumps([operation, params], sort_keys=True, separators=(',', ':')).encode())
        old = meta.setdefault('requests', {}).get(requestId)
        if old:
            if old['binding'] != binding:
                raise ValueError('Request identifier reused with different arguments')
            if old['status'] != 'complete':
                raise ValueError('Previous request result unknown; do not replay mutation')
            return old.get('result'), binding
        if len(meta['requests']) >= 2000:
            raise ValueError('Workspace request budget exhausted')
        meta['requests'][requestId] = {'binding': binding, 'status': 'started'}
        self.dev_save_meta(meta)
        return None, binding

    def finish(self, meta, requestId, result):
        meta['requests'][requestId].update(status='complete', result=result)
        self.dev_save_meta(meta)
        self.audit_event('dev_mutation', 'ok', meta['project'])
        return result

    def dev_workspace_create(self, profile, project, requestId):
        policy = self.dev_policy(profile)
        if profile != 'autonomous-development':
            raise ValueError('Workspace creation requires autonomous-development')
        source = self.dev_check_source(project, policy)
        self.dev_check_source(project, policy, True)
        if not ID.fullmatch(requestId):
            raise ValueError('Invalid request identifier')
        wid = digest((profile + '\0' + project + '\0' + requestId).encode())[:32]
        if (self.dev_root / wid / 'metadata.json').exists():
            return self.dev_workspace_public(self.dev_workspace(wid, profile))
        cap = policy.get('limits', {}).get('maxWorkspaces', 8)
        active = 0
        for entry in self.dev_root.glob('*/metadata.json'):
            if not json.loads(entry.read_text()).get('closed'):
                active += 1
        if active >= cap:
            raise ValueError('Active workspace limit reached')
        location = self.dev_root / wid; location.mkdir(mode=0o700)
        tree = location / 'tree'; tree.mkdir(mode=0o700)
        skipped = 0; baseline = {}; total = 0
        try:
            for directory, dirs, files in os.walk(source, followlinks=False):
                keep = []
                for name in dirs:
                    rel = (Path(directory) / name).relative_to(source).as_posix()
                    try:
                        denied_relative(rel, policy, source=True)
                        candidate = self.dev_source_path(project, rel, policy)
                        if (Path(directory) / name).is_symlink() or candidate != Path(directory) / name:
                            raise ValueError('Link excluded')
                        (tree / rel).mkdir(parents=True, exist_ok=True)
                        keep.append(name)
                    except (ValueError, OSError):
                        skipped += 1
                dirs[:] = keep
                for name in files:
                    rel = (Path(directory) / name).relative_to(source).as_posix()
                    try:
                        denied_relative(rel, policy, source=True)
                        if (source / rel).is_symlink():
                            raise ValueError('Link excluded')
                        self.dev_source_path(project, rel, policy)
                        raw, mode = read_regular(source, rel, policy.get('limits', {}).get('diskBytes', 512 * 1024 ** 2))
                        if possible_secret(raw):
                            raise ValueError('Possible credential excluded')
                    except (ValueError, OSError):
                        skipped += 1; continue
                    total += len(raw)
                    if total > policy.get('limits', {}).get('diskBytes', 512 * 1024 ** 2) or len(baseline) >= policy.get('limits', {}).get('files', 30000):
                        raise ValueError('Source exceeds workspace resource budget')
                    target = tree / rel; target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw); target.chmod(mode & 0o777)
                    baseline[rel] = {'hash': digest(raw), 'mode': mode, 'size': len(raw)}
            meta = {'id': wid, 'profile': profile, 'project': project, 'source': str(source), 'path': str(tree),
                    'privateRepository': str(location / 'repository'), 'artifactsPath': str(tree / '.dev-artifacts'),
                    'baseline': baseline, 'changed': [], 'requests': {}, 'skippedEntries': skipped, 'created': time.time(), 'closed': False}
            meta['initialHashes'] = {rel: data['hash'] for rel, data in baseline.items()}
            initial_head = subprocess.run(['git', '-C', str(source), 'rev-parse', '--verify', 'HEAD'], capture_output=True, timeout=5,
                                          env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'})
            head = initial_head.stdout.decode().strip()
            meta['sourceHead'] = head if initial_head.returncode == 0 and re.fullmatch(r'[0-9a-f]{40,64}', head) else None
            self.dev_workspaces[wid] = meta; self.dev_save_meta(meta)
            return self.dev_workspace_public(meta)
        except Exception:
            shutil.rmtree(location)
            raise

    def public(self, meta):
        return {k: meta[k] for k in ('id', 'profile', 'project', 'created', 'skippedEntries', 'closed')} | {'workspaceId': meta['id'], 'gitScope': 'private-development-repository', 'changedPaths': meta['changed']}

    def dev_workspace_list(self, profile):
        self.dev_policy(profile)
        items = []
        for path in self.dev_root.glob('*/metadata.json'):
            meta = json.loads(path.read_text())
            if meta['profile'] == profile:
                items.append(self.dev_workspace_public(meta))
        return {'workspaces': items}

    def dev_validate_tree(self, workspaceId, profile, allowExpired=False):
        meta = self.dev_workspace(workspaceId, profile, allowExpired=allowExpired)
        entries = manifest(self.dev_tree(meta), self.dev_policy(profile))
        return {'valid': True, 'files': len(entries), 'bytes': sum(x.get('size', 0) for x in entries.values())}

    def dev_read(self, profile, workspaceId, path, binary=False, offset=0, limit=65536):
        policy = self.dev_policy(profile); meta = self.dev_workspace(workspaceId, profile, allowExpired=True, allowClosed=True)
        if generated_dependency(path):
            raise ValueError('Generated dependency content is not exposed through file tools')
        root = self.dev_tree(meta)
        relative = path
        if meta.get('closed'):
            if not path.startswith('.dev-artifacts/') or not meta.get('retainedArtifactRoot'):
                raise ValueError('Closed workspace permits only retained result artifacts')
            root = Path(meta['retainedArtifactRoot']); relative = path[len('.dev-artifacts/'):]
            denied_relative(relative, policy)
        else:
            self.dev_workspace(workspaceId, profile)
            self.dev_path(meta, path, policy)
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 262144:
            raise ValueError('Invalid read pagination')
        raw, _ = read_regular(root, relative, policy.get('limits', {}).get('diskBytes', 512 * 1024 ** 2))
        if possible_secret(raw):
            raise ValueError('Possible secret detected; content withheld')
        page = raw[offset:offset + limit]
        result = {'sha256': digest(raw), 'size': len(raw), 'offset': offset, 'truncated': offset + len(page) < len(raw), 'nextOffset': offset + len(page) if offset + len(page) < len(raw) else None}
        result['base64' if binary else 'text'] = base64.b64encode(page).decode() if binary else page.decode('utf-8', errors='replace')
        return result

    def dev_list(self, profile, workspaceId, path='.', offset=0, limit=100):
        policy = self.dev_policy(profile); meta = self.dev_workspace(workspaceId, profile)
        root = self.dev_tree(meta)
        target = root if path == '.' else self.dev_path(meta, path, policy)
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError('Invalid list pagination')
        entries = []
        for item in target.iterdir():
            try:
                denied_relative(item.relative_to(root), policy)
            except ValueError:
                continue
            if item.is_symlink():
                continue
            entries.append({'name': item.name, 'type': 'directory' if item.is_dir() else 'file'})
        entries.sort(key=lambda x: x['name'])
        return {'entries': entries[offset:offset + limit], 'totalEntries': len(entries), 'hasMore': offset + limit < len(entries)}

    def tree_entry(self, root, relative, policy):
        target = root / relative
        if not target.exists():
            return {'type': 'missing', 'hash': 'missing'}
        if target.is_symlink():
            raise ValueError('Symbolic link mutation forbidden')
        if target.is_dir():
            children = manifest(target, policy, True)
            return {'type': 'directory', 'mode': stat.S_IMODE(target.stat().st_mode), 'children': children, 'hash': digest(json.dumps(children, sort_keys=True).encode())}
        raw, mode = read_regular(root, relative, policy.get('limits', {}).get('diskBytes', 512 * 1024 ** 2))
        if possible_secret(raw):
            raise ValueError('Possible secret detected; content withheld')
        return {'type': 'file', 'hash': digest(raw), 'mode': mode, 'data': base64.b64encode(raw).decode()}

    def atomic_write(self, root, relative, raw, mode, expected):
        recovery_root = self.state / 'development-recovery'
        if recovery_root.exists() and sum(file.stat().st_size for file in recovery_root.iterdir() if file.is_file() and not file.is_symlink()) >= 1024 ** 3:
            raise ValueError('Local recovery retention budget exhausted')
        parent = str(Path(relative).parent)
        fd = open_components(root, parent, os.O_RDONLY | os.O_DIRECTORY)
        name = Path(relative).name; temporary = '.dev-pending-' + secrets.token_hex(12)
        exchanged = False; retained = False
        def exchange():
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.renameat2(fd, os.fsencode(temporary), fd, os.fsencode(name), 2):
                number = ctypes.get_errno()
                raise OSError(number, os.strerror(number))
        def retain_displaced():
            recovery_name = '.dev-recovery-' + secrets.token_hex(12)
            private_recovery = self.state / 'development-recovery'
            private_recovery.mkdir(mode=0o700, exist_ok=True)
            try:
                os.rename(temporary, str(private_recovery / recovery_name), src_dir_fd=fd)
            except OSError as error:
                if error.errno != errno.EXDEV:
                    raise
                # 执行器将 /workspace 与 /tmp 放在同一有上限的 tmpfs。
                # 移到 /tmp 的锚定目录，保留 inode 且不混入任务代码或同步列表。
                if root.parts[:2] == ('/', 'proc') and root.name == 'workspace' and root.parent.name == 'data':
                    tmp_fd = open_components(root.parent, 'tmp', os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        try:
                            os.mkdir('.mcp-file-recovery', 0o700, dir_fd=tmp_fd)
                        except FileExistsError:
                            pass
                        recovery_fd = os.open('.mcp-file-recovery', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=tmp_fd)
                        try:
                            os.rename(temporary, recovery_name, src_dir_fd=fd, dst_dir_fd=recovery_fd)
                        finally:
                            os.close(recovery_fd)
                    finally:
                        os.close(tmp_fd)
                else:
                    os.rename(temporary, recovery_name, src_dir_fd=fd, dst_dir_fd=fd)
        try:
            if expected == 'missing':
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('Hash conflict: destination now exists')
            else:
                current, _ = read_regular(root, relative, max(len(raw), 512 * 1024 ** 2))
                if digest(current) != expected:
                    raise ValueError('Hash conflict: file changed concurrently')
            output = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode, dir_fd=fd)
            with os.fdopen(output, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), mode & 0o777); os.fsync(stream.fileno())
            if expected == 'missing':
                # 创建时 link 不替换并发创建的目标；文件最终只有一个链接。
                os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                os.unlink(temporary, dir_fd=fd)
            else:
                current, _ = read_regular(root, relative, max(len(raw), 512 * 1024 ** 2))
                if digest(current) != expected:
                    raise ValueError('Hash conflict: file changed concurrently')
                # Linux 没有按文件内容比较交换的系统调用。先交换，再校验移出的节点。
                exchange(); exchanged = True
                displaced, _ = read_regular(root, str(Path(relative).parent / temporary), max(len(raw), 512 * 1024 ** 2))
                if digest(displaced) != expected:
                    current, _ = read_regular(root, relative, max(len(raw), 512 * 1024 ** 2))
                    if digest(current) == digest(raw):
                        exchange(); exchanged = False
                        raise ValueError('Hash conflict during atomic exchange; concurrent content restored')
                    retained = True
                    retain_displaced()
                    self.audit_event('dev_atomic_conflict', 'recovery_retained', None)
                    raise ValueError('Hash conflict during atomic exchange; both concurrent versions retained for local recovery')
                # 保留移出的 inode，已经打开的外部写入描述符仍能将并发数据写入恢复文件。
                retain_displaced()
                retained = True
            os.fsync(fd)
        finally:
            if exchanged and not retained:
                try:
                    retain_displaced()
                except FileNotFoundError:
                    pass
            else:
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
            os.close(fd)

    def snapshot(self, meta, before, scope='workspace'):
        sid = secrets.token_hex(16)
        folder = self.dev_root / meta['id'] / 'snapshots'; folder.mkdir(mode=0o700, exist_ok=True)
        policy = self.dev_policy(meta['profile'])
        limit = min(policy.get('limits', {}).get('diskBytes', 512 * 1024 ** 2) * 4, 1024 ** 3)
        used = sum(file.stat().st_size for file in folder.glob('*.json'))
        if used + len(json.dumps(before).encode()) > limit:
            raise ValueError('Snapshot retention budget exhausted; start a new bounded task')
        self.atomic_json(folder / (sid + '.json'), {'id': sid, 'scope': scope, 'before': before, 'after': {}, 'created': time.time()})
        return sid

    def dev_operations(self, profile, workspaceId, operations, requestId):
        policy = self.dev_policy(profile); meta = self.dev_workspace(workspaceId, profile)
        if not isinstance(operations, list) or not 1 <= len(operations) <= 100:
            raise ValueError('Use 1 to 100 file operations')
        cached, _ = self.dev_request(meta, requestId, 'operations', operations)
        if cached is not None:
            return cached
        root = self.dev_tree(meta); before = {}; after = {}; results = []
        sid = self.dev_snapshot(meta, before)
        record_path = self.dev_root / meta['id'] / 'snapshots' / (sid + '.json')
        for op in operations:
            touched = []
            potentially_modified = set()
            try:
                if not isinstance(op, dict) or op.get('operation') not in {'write', 'mkdir', 'copy', 'move', 'rename', 'delete'}:
                    raise ValueError('Unsupported file operation')
                kind = op['operation']; path = op['path']; target = self.dev_path(meta, path, policy)
                entry = self.dev_tree_entry(root, path, policy)
                expected = op.get('expectedHash', 'missing' if kind == 'mkdir' else None)
                if expected is None or entry['hash'] != expected:
                    raise ValueError('Hash conflict: expectedHash does not match')
                before.setdefault(path, entry)
                dest = None; dest_entry = None
                if kind in {'copy', 'move', 'rename'}:
                    dest = op.get('destination'); dest_target = self.dev_path(meta, dest, policy)
                    if dest == path or within(dest_target, target) or within(target, dest_target):
                        raise ValueError('Source and destination overlap')
                    dest_entry = self.dev_tree_entry(root, dest, policy)
                    if dest_entry['hash'] != op.get('destinationExpectedHash', 'missing'):
                        raise ValueError('Destination hash conflict')
                    if dest_entry['type'] != 'missing':
                        raise ValueError('Copy and move destinations must not exist')
                    before.setdefault(dest, dest_entry)
                touched = [path] + ([dest] if dest else [])
                # 快照在每一步修改前保存，崩溃后仍可人工检查恢复。
                self.atomic_json(record_path, {'id': sid, 'scope': 'workspace', 'before': before, 'after': after, 'created': time.time()})
                if kind == 'write':
                    if ('content' in op) == ('base64Content' in op):
                        raise ValueError('Supply exactly one text or binary content')
                    raw = op['content'].encode() if 'content' in op else base64.b64decode(op['base64Content'], validate=True)
                    if possible_secret(raw):
                        raise ValueError('Possible secret detected; write refused')
                    if entry['type'] not in {'file', 'missing'}:
                        raise ValueError('Write target must be a file')
                    used = self.dev_validate_tree(workspaceId, profile)['bytes']
                    if used - len(base64.b64decode(entry.get('data', ''))) + len(raw) > policy.get('limits', {}).get('diskBytes', 512 * 1024 ** 2):
                        raise ValueError('Workspace disk budget exceeded')
                    self.dev_atomic_write(root, path, raw, entry.get('mode', 0o600), expected)
                    potentially_modified.add(path)
                elif kind == 'mkdir':
                    fd = open_components(root, str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.mkdir(Path(path).name, 0o700, dir_fd=fd)
                        potentially_modified.add(path)
                    finally:
                        os.close(fd)
                elif kind in {'copy', 'move', 'rename'}:
                    if entry['type'] == 'missing':
                        raise ValueError('Source does not exist')
                    current_budget = self.dev_validate_tree(workspaceId, profile)
                    added = len(base64.b64decode(entry.get('data', ''))) if entry['type'] == 'file' else sum(x.get('size', 0) for x in entry['children'].values())
                    added_nodes = 1 if entry['type'] == 'file' else 1 + len(entry['children'])
                    if current_budget['bytes'] + added > policy.get('limits', {}).get('diskBytes', 512 * 1024 ** 2) or current_budget['files'] + added_nodes > policy.get('limits', {}).get('files', 30000):
                        raise ValueError('Copy staging exceeds workspace resource budget')
                    potentially_modified.add(dest)
                    self.dev_install_entry(root, dest, entry, policy, 'missing')
                    if kind != 'copy':
                        self.dev_remove_entry(root, path, entry['hash'], policy)
                        potentially_modified.add(path)
                elif kind == 'delete':
                    if entry['type'] == 'missing':
                        raise ValueError('Source does not exist')
                    self.dev_remove_entry(root, path, entry['hash'], policy)
                    potentially_modified.add(path)
                for rel in potentially_modified:
                    after[rel] = self.dev_tree_entry(root, rel, policy)['hash']
                    if rel not in meta['changed']:
                        meta['changed'].append(rel)
                results.append({'path': path, 'operation': kind, 'applied': True, 'sha256': self.dev_tree_entry(root, path, policy)['hash']})
            except Exception as error:
                # 目录复制不是整体事务；失败后记录已经落地的节点，恢复可清理它们。
                for rel in potentially_modified:
                    try:
                        current = self.dev_tree_entry(root, rel, policy)
                        if current['hash'] != before[rel]['hash']:
                            after[rel] = current['hash']
                            if rel not in meta['changed']:
                                meta['changed'].append(rel)
                    except (OSError, ValueError):
                        pass
                message = str(error) if isinstance(error, ValueError) else type(error).__name__
                results.append({'path': op.get('path') if isinstance(op, dict) else None, 'applied': False, 'error': safe_output(message[:200])})
                break
            finally:
                self.atomic_json(record_path, {'id': sid, 'scope': 'workspace', 'before': before, 'after': after, 'created': time.time()})
        result = {'snapshotId': sid, 'results': results, 'applied': len(results) == len(operations) and all(r['applied'] for r in results), 'transactional': False}
        return self.dev_finish(meta, requestId, result)

    def remove_entry(self, root, relative, expected, policy):
        if self.dev_tree_entry(root, relative, policy)['hash'] != expected:
            raise ValueError('Hash conflict before removal')
        fd = open_components(root, str(Path(relative).parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            name = Path(relative).name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                self.dev_retain_removal(root, relative, expected, policy, fd)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                self.dev_retain_removal(root, relative, expected, policy, fd)
            else:
                raise ValueError('Unsafe removal target')
        finally:
            os.close(fd)

    def retain_removal(self, root, relative, expected, policy, fd):
        name = Path(relative).name
        held = '.dev-removal-' + secrets.token_hex(12)
        os.rename(name, held, src_dir_fd=fd, dst_dir_fd=fd)
        held_relative = str(Path(relative).parent / held)
        moved = self.dev_tree_entry(root, held_relative, policy)
        if moved['hash'] != expected:
            # 不覆盖删除窗口中又创建的目标；两份内容都保留并报告冲突。
            try:
                self.rename_noreplace(fd, held, name)
            except FileExistsError:
                raise ValueError('Removal hash conflict; concurrent versions retained for local recovery') from None
            raise ValueError('Removal hash conflict; concurrent content restored')
        recovery = self.state / 'development-recovery'; recovery.mkdir(mode=0o700, exist_ok=True)
        try:
            os.rename(held, str(recovery / held), src_dir_fd=fd)
        except OSError as error:
            if error.errno != errno.EXDEV:
                raise
            if root.parts[:2] == ('/', 'proc') and root.name == 'workspace' and root.parent.name == 'data':
                tmp_fd = open_components(root.parent, 'tmp', os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.rename(held, held, src_dir_fd=fd, dst_dir_fd=tmp_fd)
                finally:
                    os.close(tmp_fd)
            else:
                # 仅隔离副本遇到跨设备；保留 inode，不继续删除未知内容。
                raise ValueError('Removal recovery storage unavailable; removed node retained locally') from None

    def install_entry(self, root, relative, entry, policy, expected):
        if entry['type'] == 'missing':
            current = self.dev_tree_entry(root, relative, policy)
            if current['type'] != 'missing':
                self.dev_remove_entry(root, relative, expected, policy)
        elif entry['type'] == 'file':
            self.dev_atomic_write(root, relative, base64.b64decode(entry['data']), entry['mode'], expected)
        else:
            if expected != 'missing':
                self.dev_remove_entry(root, relative, expected, policy)
            parent_fd = open_components(root, str(Path(relative).parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.mkdir(Path(relative).name, entry['mode'] & 0o777, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            for name, child in sorted(entry['children'].items(), key=lambda x: (len(Path(x[0]).parts), x[0])):
                rel = str(Path(relative) / name)
                denied_relative(rel, policy)
                if child['type'] == 'directory':
                    fd = open_components(root, str(Path(rel).parent), os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.mkdir(Path(rel).name, child['mode'] & 0o777, dir_fd=fd)
                    finally:
                        os.close(fd)
                else:
                    self.dev_atomic_write(root, rel, base64.b64decode(child['data']), child['mode'], 'missing')

    def dev_write(self, profile, workspaceId, path, expectedHash, requestId, content=None, base64Content=None):
        op = {'operation': 'write', 'path': path, 'expectedHash': expectedHash}
        if content is not None:
            op['content'] = content
        if base64Content is not None:
            op['base64Content'] = base64Content
        return self.dev_operations(profile, workspaceId, [op], requestId)

    def dev_edit(self, profile, workspaceId, path, expectedHash, edits, requestId):
        meta = self.dev_workspace(workspaceId, profile)
        cached, _ = self.dev_request(meta, requestId, 'edit', [path, expectedHash, edits])
        if cached is not None:
            return cached
        read = self.dev_read(profile, workspaceId, path, limit=262144)
        if read['truncated']:
            raise ValueError('Use full replacement for large text file')
        if read['sha256'] != expectedHash:
            raise ValueError('Hash conflict before text edit')
        text = read['text']
        if not isinstance(edits, list) or not 1 <= len(edits) <= 100:
            raise ValueError('Use 1 to 100 exact edits')
        for edit in edits:
            old = edit.get('oldText'); new = edit.get('newText')
            if not isinstance(old, str) or not old or not isinstance(new, str) or text.count(old) != 1:
                raise ValueError('Exact edit requires one unique match')
            text = text.replace(old, new, 1)
        internal_request = 'edit-' + digest(requestId.encode())[:32]
        result = self.dev_write(profile, workspaceId, path, expectedHash, internal_request, content=text)
        return self.dev_finish(meta, requestId, result)

    def dev_sync(self, profile, workspaceId, paths, requestId):
        policy = self.dev_policy(profile); meta = self.dev_workspace(workspaceId, profile)
        source = self.dev_check_source(meta['project'], policy, True)
        self.dev_validate_tree(workspaceId, profile)
        if not isinstance(paths, list) or not 1 <= len(paths) <= 100 or len(set(paths)) != len(paths):
            raise ValueError('Supply 1 to 100 unique task file paths')
        cached, _ = self.dev_request(meta, requestId, 'sync', paths)
        if cached is not None:
            return cached
        root = self.dev_tree(meta); before = {}; after = {}; prepared = []
        for rel in paths:
            denied_relative(rel, policy, source=True)
            self.dev_path(meta, rel, policy)
            target = self.dev_source_path(meta['project'], rel, policy, write=True)
            if target != source / rel:
                raise ValueError('Original workspace symbolic link synchronization refused')
            if any(Path(x).is_absolute() and within(target, Path(x).resolve()) for x in policy.get('denyPaths', [])):
                raise ValueError('Source path denied by profile')
            old = self.dev_tree_entry(source, rel, policy)
            expected = meta['baseline'].get(rel, {}).get('hash', 'missing')
            if old['hash'] != expected:
                raise ValueError('Source hash conflict: concurrent user change')
            new = self.dev_tree_entry(root, rel, policy)
            if old['type'] == 'directory' or new['type'] == 'directory':
                raise ValueError('Synchronize explicit files; directory-wide sync is forbidden')
            before[rel] = old; prepared.append((rel, old, new))
        sid = self.dev_snapshot(meta, before, 'source'); results = []
        record_path = self.dev_root / meta['id'] / 'snapshots' / (sid + '.json')
        for rel, old, new in prepared:
            try:
                self.dev_source_path(meta['project'], rel, policy, write=True)
                if new['type'] == 'file':
                    new = {**new, 'mode': old.get('mode', new['mode'])}
                self.dev_install_entry(source, rel, new, policy, old['hash'])
                after[rel] = new['hash']
                if new['type'] == 'missing':
                    meta['baseline'].pop(rel, None)
                else:
                    meta['baseline'][rel] = {'hash': new['hash'], 'mode': new['mode']}
                results.append({'path': rel, 'applied': True})
            except Exception as error:
                results.append({'path': rel, 'applied': False, 'error': str(error)[:200] if isinstance(error, ValueError) else type(error).__name__})
                break
            finally:
                self.atomic_json(record_path, {'id': sid, 'scope': 'source', 'before': before, 'after': after, 'created': time.time()})
        return self.dev_finish(meta, requestId, {'snapshotId': sid, 'applied': len(results) == len(paths) and all(x['applied'] for x in results), 'results': results, 'transactional': False})

    def dev_restore(self, profile, workspaceId, snapshotId, requestId):
        policy = self.dev_policy(profile); meta = self.dev_workspace(workspaceId, profile)
        if not re.fullmatch(r'[0-9a-f]{32}', snapshotId):
            raise ValueError('Invalid snapshot identifier')
        record = json.loads((self.dev_root / workspaceId / 'snapshots' / (snapshotId + '.json')).read_text())
        cached, _ = self.dev_request(meta, requestId, 'restore', snapshotId)
        if cached is not None:
            return cached
        root = self.dev_tree(meta) if record['scope'] == 'workspace' else self.dev_check_source(meta['project'], policy, True)
        results = []
        # 只恢复已确认修改的路径；部分失败记录不会触碰未执行的文件。
        for rel, expected in record['after'].items():
            denied_relative(rel, policy, source=record['scope'] == 'source')
            if record['scope'] == 'source':
                target = self.dev_source_path(meta['project'], rel, policy, write=True)
                if target != root / rel:
                    raise ValueError('Original workspace symbolic link restoration refused')
            else:
                self.dev_path(meta, rel, policy)
            if self.dev_tree_entry(root, rel, policy)['hash'] != expected:
                raise ValueError('Restore hash conflict; newer changes preserved')
        recovery = self.dev_snapshot(meta, {rel: self.dev_tree_entry(root, rel, policy) for rel in record['after']}, record['scope'])
        recovery_after = {}
        for rel, expected in record['after'].items():
            try:
                self.dev_install_entry(root, rel, record['before'][rel], policy, expected)
                recovery_after[rel] = record['before'][rel]['hash']
                if record['scope'] == 'source':
                    old = record['before'][rel]
                    if old['type'] == 'missing':
                        meta['baseline'].pop(rel, None)
                    else:
                        meta['baseline'][rel] = {'hash': old['hash'], 'mode': old['mode']}
                results.append({'path': rel, 'restored': True})
            except Exception as error:
                results.append({'path': rel, 'restored': False, 'error': str(error)[:200] if isinstance(error, ValueError) else type(error).__name__}); break
        recovery_path = self.dev_root / workspaceId / 'snapshots' / (recovery + '.json')
        recovery_record = json.loads(recovery_path.read_text()); recovery_record['after'] = recovery_after; self.atomic_json(recovery_path, recovery_record)
        return self.dev_finish(meta, requestId, {'snapshotId': recovery, 'restored': all(x['restored'] for x in results), 'results': results, 'transactional': False})

    def dev_diff(self, profile, workspaceId, paths=None):
        policy = self.dev_policy(profile); meta = self.dev_workspace(workspaceId, profile)
        root = self.dev_tree(meta); entries = manifest(root, policy)
        paths = paths if paths is not None else sorted(set(meta['baseline']) | {k for k, v in entries.items() if v['type'] == 'file' and not generated_dependency(k) and not k.startswith('.dev-artifacts/')})
        changes = []; used = 0; truncated = False
        for rel in paths:
            self.dev_path(meta, rel, policy)
            current = self.dev_tree_entry(root, rel, policy)
            baseline = meta['baseline'].get(rel, {}).get('hash', 'missing')
            if current['type'] == 'directory' or current['hash'] == baseline:
                continue
            row = {'path': rel, 'beforeHash': baseline, 'afterHash': current['hash']}
            if current['type'] == 'file':
                raw = base64.b64decode(current['data'])
                if b'\0' not in raw and len(raw) <= 65536:
                    try:
                        old, _ = self.read(meta['project'], rel)
                    except (ValueError, OSError):
                        old = b''
                    if not possible_secret(old):
                        row['diff'] = ''.join(difflib.unified_diff(old.decode('utf-8', 'replace').splitlines(True), raw.decode('utf-8', 'replace').splitlines(True), fromfile=rel, tofile=rel))
            used += len(json.dumps(row).encode())
            if used > 131072:
                truncated = True; break
            changes.append(row)
        return {'changes': changes, 'truncated': truncated}

    def dev_git_repository(self, meta, policy):
        repo = Path(meta['privateRepository'])
        if (repo / '.git').is_dir() and (repo / '.git' / 'refs' / 'heads' / 'main').is_file():
            return repo
        repo.mkdir(mode=0o700, exist_ok=True)
        git_command(repo, ['init', '-b', 'main'])
        source = Path(meta['source'])
        identity = {}
        for key in ('user.name', 'user.email'):
            result = subprocess.run(['git', '-C', str(source), 'config', '--get', key], capture_output=True, timeout=5,
                                    env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'GIT_TERMINAL_PROMPT': '0'})
            value = result.stdout.decode().strip()
            if result.returncode or not value or len(value) > 200 or '\n' in value:
                raise ValueError('Existing Git user.name and user.email required')
            identity[key] = value
        for key, value in identity.items():
            git_command(repo, ['config', key, value])
        # 只用已复制的文件名查 HEAD；不复制宿主机 Git 配置、对象和钩子。
        head = meta.get('sourceHead')
        tracked = subprocess.run(['git', '-C', str(source), 'ls-tree', '-r', '--name-only', '-z', head or 'HEAD'], capture_output=True, timeout=10,
                                 env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'})
        names = tracked.stdout.split(b'\0') if tracked.returncode == 0 else []
        original_hashes = {}
        for raw_name in names:
            if not raw_name:
                continue
            rel = os.fsdecode(raw_name)
            if rel not in meta['baseline']:
                continue
            denied_relative(rel, policy)
            original = subprocess.run(['git', '-C', str(source), 'show', (head or 'HEAD') + ':' + rel], capture_output=True, timeout=10,
                                      env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'})
            if original.returncode or len(original.stdout) > 2 * 1024 ** 2 or possible_secret(original.stdout):
                continue
            dest = repo / rel; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(original.stdout)
            original_hashes[rel] = digest(original.stdout)
        git_command(repo, ['add', '--all'])
        git_command(repo, ['commit', '--allow-empty', '-m', '开发副本基线'])
        meta['gitOriginalHashes'] = original_hashes; self.dev_save_meta(meta)
        return repo

    def dev_git(self, profile, workspaceId, operation, requestId, paths=None, branch=None, message=None):
        policy = self.dev_policy(profile); meta = self.dev_workspace(workspaceId, profile)
        if policy.get('git', {}).get('local') is not True:
            raise ValueError('Local Git permission disabled')
        if operation not in {'status', 'diff', 'log', 'branch', 'stage', 'commit', 'merge'}:
            raise ValueError('Git operation denied; push and remote changes are not implemented')
        params = [operation, paths, branch, message]
        cached, _ = self.dev_request(meta, requestId, 'git', params)
        if cached is not None:
            return cached
        repo = self.dev_git_repository(meta, policy)
        if operation == 'branch':
            if not isinstance(branch, str) or not re.fullmatch(r'codex/[A-Za-z0-9][A-Za-z0-9/_-]{0,100}', branch) or '..' in branch or branch.endswith('/'):
                raise ValueError('Use a codex/ development branch')
            git_command(repo, ['checkout', '-b', branch])
        elif operation in {'stage', 'commit'}:
            if not paths or not isinstance(paths, list) or not 1 <= len(paths) <= 100 or len(set(paths)) != len(paths):
                raise ValueError('Git staging requires explicit task file paths')
            root = self.dev_tree(meta)
            for rel in paths:
                self.dev_path(meta, rel, policy)
                initial = meta.get('initialHashes', {}).get(rel, 'missing')
                original = meta.get('gitOriginalHashes', {}).get(rel, 'missing')
                if initial != original:
                    raise ValueError('Task path contained a preexisting user change; local task commit refused to include it')
                current = self.dev_tree_entry(root, rel, policy)
                if current['type'] == 'directory':
                    raise ValueError('Git staging requires explicit files')
                baseline = meta['baseline'].get(rel, {}).get('hash', 'missing')
                if current['hash'] == baseline and rel not in meta['changed']:
                    raise ValueError('Unchanged user file cannot be included in task commit')
                dest = repo / rel
                if current['type'] == 'missing':
                    if dest.is_file():
                        dest.unlink()
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(base64.b64decode(current['data'])); dest.chmod(current['mode'] & 0o777)
            git_command(repo, ['add', '--', *paths])
            if operation == 'commit':
                staged = git_command(repo, ['diff', '--cached', '--name-only', '-z']).split(b'\0')
                if {os.fsdecode(x) for x in staged if x} - set(paths):
                    raise ValueError('Other staged files exist; commit refused')
                if not isinstance(message, str) or not message.strip() or len(message) > 2000 or possible_secret(message.encode()):
                    raise ValueError('Use a non-sensitive commit message')
                git_command(repo, ['commit', '-m', message])
        elif operation == 'merge':
            if not isinstance(branch, str) or not re.fullmatch(r'codex/[A-Za-z0-9][A-Za-z0-9/_-]{0,100}', branch):
                raise ValueError('Merge is restricted to local development branches')
            changed = git_command(repo, ['diff', '--name-only', 'HEAD', branch, '--']).decode().splitlines()
            tree = self.dev_tree(meta)
            for rel in changed:
                self.dev_path(meta, rel, policy)
                tracked = subprocess.run(['git', '-C', str(repo), 'show', 'HEAD:' + rel], capture_output=True, timeout=10)
                current = self.dev_tree_entry(tree, rel, policy)
                if tracked.returncode == 0 and current['hash'] != digest(tracked.stdout):
                    raise ValueError('Merge would overwrite task or user changes')
                if tracked.returncode and current['type'] != 'missing':
                    raise ValueError('Merge destination already exists')
            git_command(repo, ['merge', '--no-edit', branch])
            for rel in changed:
                target = repo / rel; current = self.dev_tree_entry(tree, rel, policy)
                if target.is_file():
                    raw, mode = read_regular(repo, rel, 2 * 1024 ** 2)
                    if possible_secret(raw):
                        raise ValueError('Merged content failed secret check')
                    self.dev_atomic_write(tree, rel, raw, current.get('mode', mode), current['hash'])
                elif current['type'] != 'missing':
                    self.dev_remove_entry(tree, rel, current['hash'], policy)
                if rel not in meta['changed']:
                    meta['changed'].append(rel)
        args = {'status': ['status', '--short'], 'diff': ['diff', '--cached', '--stat'], 'log': ['log', '-10', '--oneline']}.get(operation, ['log', '-1', '--format=%H'])
        output = git_command(repo, args).decode('utf-8', 'replace')
        return self.dev_finish(meta, requestId, {'operation': operation, 'scope': 'private-development-repository', 'stdout': safe_output(output[:131072]), 'truncated': len(output) > 131072, 'sourceRepositoryChanged': False})

    def dev_artifacts(self, profile, workspaceId, offset=0, limit=100):
        meta = self.dev_workspace(workspaceId, profile, allowExpired=True, allowClosed=True); policy = self.dev_policy(profile)
        if meta.get('closed'):
            retained = Path(meta['retainedArtifactRoot']) if meta.get('retainedArtifactRoot') else None
            entries = {'.dev-artifacts/' + rel: data for rel, data in manifest(retained, policy).items()} if retained else {}
        else:
            entries = manifest(self.dev_tree(meta), policy)
        paths = [rel for rel, value in entries.items() if value['type'] == 'file' and (rel.startswith('.dev-artifacts/') or rel.startswith('dist/') or rel.startswith('build/'))]
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError('Invalid artifact pagination')
        paths.sort()
        return {'artifacts': [{'path': p, 'sha256': entries[p]['hash'], 'size': entries[p]['size']} for p in paths[offset:offset + limit]], 'hasMore': offset + limit < len(paths)}

    def dev_workspace_close(self, profile, workspaceId):
        meta = self.dev_workspace(workspaceId, profile, allowExpired=True)
        if meta.get('livePath'):
            raise ValueError('Stop execution sandbox before closing workspace')
        artifact_root = Path(meta['path']) / '.dev-artifacts'
        if artifact_root.is_dir() and not artifact_root.is_symlink():
            retained = self.dev_root / workspaceId / 'artifacts'
            entries = manifest(artifact_root, self.dev_policy(profile), True)
            retained.mkdir(mode=0o700, exist_ok=True)
            for relative, data in sorted(entries.items(), key=lambda x: (len(Path(x[0]).parts), x[0])):
                target = retained / relative
                if data['type'] == 'directory':
                    target.mkdir(mode=0o700, exist_ok=True)
                else:
                    self.dev_atomic_write(retained, relative, base64.b64decode(data['data']), 0o600, 'missing')
            meta['retainedArtifactRoot'] = str(retained)
        meta['closed'] = True; self.dev_save_meta(meta)
        # 保留快照和请求记录以供恢复；清理执行副本，不删除用户工作区。
        shutil.rmtree(meta['path'])
        return {'closed': True, 'workspaceId': workspaceId, 'snapshotsRetained': True, 'artifactsRetained': bool(meta.get('retainedArtifactRoot'))}

    cls.__init__ = initialize
    methods = locals()
    for name in ('dev_policy', 'dev_workspace', 'dev_workspace_create', 'dev_workspace_list', 'dev_validate_tree', 'dev_read', 'dev_list', 'dev_operations', 'dev_write', 'dev_edit', 'dev_sync', 'dev_restore', 'dev_diff', 'dev_git_repository', 'dev_git', 'dev_artifacts', 'dev_workspace_close'):
        setattr(cls, name, methods[name])
    for exposed, local in [('dev_check_source', 'check_source'), ('dev_source_path', 'source_path'), ('dev_save_meta', 'save_meta'), ('dev_tree', 'dev_tree'), ('dev_path', 'dev_path'), ('dev_request', 'request'), ('dev_finish', 'finish'), ('dev_workspace_public', 'public'), ('dev_tree_entry', 'tree_entry'), ('dev_atomic_write', 'atomic_write'), ('dev_snapshot', 'snapshot'), ('dev_remove_entry', 'remove_entry'), ('dev_retain_removal', 'retain_removal'), ('dev_install_entry', 'install_entry')]:
        setattr(cls, exposed, methods[local])


def schema(properties, required):
    common = {'profile': {'type': 'string', 'enum': ['autonomous-development']}, 'workspaceId': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'}}
    return {'type': 'object', 'properties': common | properties, 'required': required, 'additionalProperties': False}


S = {'type': 'string'}
P = {'type': 'array', 'items': S, 'minItems': 1, 'maxItems': 100, 'uniqueItems': True}
R = {'type': 'string', 'pattern': '^[a-zA-Z0-9_-]{1,100}$'}
TOOL_DESCRIPTIONS = {
    'dev_workspace_create': '创建不含凭据、运行数据库和 Git 私有文件的开发副本，无需逐项审批。',
    'dev_workspace_list': '列出开发副本及状态。',
    'dev_workspace_close': '关闭已停止沙箱的开发副本，保留恢复快照。',
    'dev_read': '分页读取开发副本文本或二进制并返回完整文件哈希。',
    'dev_list': '分页列出开发副本目录，支持普通隐藏文件。',
    'dev_write': '按预期哈希原子写入开发副本，新增文件使用 missing。',
    'dev_edit': '按预期哈希执行唯一匹配的精确文本编辑。',
    'dev_operations': '自动文件批量操作及恢复快照，部分失败明确返回；不是整体事务。',
    'dev_sync': '仅同步明确任务文件到原工作区，检查原始哈希并保留用户其他改动。',
    'dev_restore': '按当前哈希恢复开发操作或同步快照，拒绝覆盖后续改动。',
    'dev_diff': '查看副本相对创建时原工作区的任务改动。',
    'dev_git': '在独立私有仓库创建分支、暂存、提交和合并；不修改原 Git 历史或远端。',
    'dev_artifacts': '分页列出构建和测试制品路径、哈希及大小。',
}
TOOL_SCHEMAS = {
    'dev_workspace_create': schema({'project': S, 'requestId': R}, ['profile', 'project', 'requestId']),
    'dev_workspace_list': schema({}, ['profile']),
    'dev_workspace_close': schema({}, ['profile', 'workspaceId']),
    'dev_read': schema({'path': S, 'binary': {'type': 'boolean'}, 'offset': {'type': 'integer', 'minimum': 0}, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 262144}}, ['profile', 'workspaceId', 'path']),
    'dev_list': schema({'path': S, 'offset': {'type': 'integer', 'minimum': 0}, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 200}}, ['profile', 'workspaceId']),
    'dev_write': schema({'path': S, 'expectedHash': S, 'requestId': R, 'content': S, 'base64Content': S}, ['profile', 'workspaceId', 'path', 'expectedHash', 'requestId']),
    'dev_edit': schema({'path': S, 'expectedHash': S, 'requestId': R, 'edits': {'type': 'array', 'minItems': 1, 'maxItems': 100, 'items': {'type': 'object', 'properties': {'oldText': S, 'newText': S}, 'required': ['oldText', 'newText'], 'additionalProperties': False}}}, ['profile', 'workspaceId', 'path', 'expectedHash', 'edits', 'requestId']),
    'dev_operations': schema({'requestId': R, 'operations': {'type': 'array', 'minItems': 1, 'maxItems': 100, 'items': {'type': 'object', 'properties': {'operation': {'type': 'string', 'enum': ['write', 'mkdir', 'copy', 'move', 'rename', 'delete']}, 'path': S, 'destination': S, 'expectedHash': S, 'destinationExpectedHash': S, 'content': S, 'base64Content': S}, 'required': ['operation', 'path'], 'additionalProperties': False}}}, ['profile', 'workspaceId', 'operations', 'requestId']),
    'dev_sync': schema({'paths': P, 'requestId': R}, ['profile', 'workspaceId', 'paths', 'requestId']),
    'dev_restore': schema({'snapshotId': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'}, 'requestId': R}, ['profile', 'workspaceId', 'snapshotId', 'requestId']),
    'dev_diff': schema({'paths': P}, ['profile', 'workspaceId']),
    'dev_git': schema({'operation': {'type': 'string', 'enum': ['status', 'diff', 'log', 'branch', 'stage', 'commit', 'merge']}, 'requestId': R, 'paths': P, 'branch': S, 'message': S}, ['profile', 'workspaceId', 'operation', 'requestId']),
    'dev_artifacts': schema({'offset': {'type': 'integer', 'minimum': 0}, 'limit': {'type': 'integer', 'minimum': 1, 'maximum': 200}}, ['profile', 'workspaceId']),
}
