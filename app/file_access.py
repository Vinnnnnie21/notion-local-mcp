"""本机授权的文件操作。预览、批准和执行使用同一份路径与内容摘要。"""
import base64
import ctypes
import errno
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import time
from pathlib import Path

MAX_FILE = 2 * 1024 * 1024
MAX_TREE = 32 * 1024 * 1024
MAX_NODES = 2000
PRIVATE_TEMP = re.compile(r'^\.mcp-(?:stage|recovery|tmp)-[0-9a-f]+$')
SENSITIVE_DIRS = {'.ssh', '.aws', '.gnupg', '.kube', '.azure', '.docker', 'credentials', 'secrets'}
SENSITIVE_NAMES = {'credentials', 'credential', 'token', 'tokens', 'id_rsa', 'id_ed25519', 'id_dsa', 'id_ecdsa', 'authorized_keys', '.netrc', '.npmrc', '.pypirc', 'passwd', 'shadow'}
from credential_scan import SECRET, findings as credential_findings


def hashed(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _credential_span(data, start, limit):
    """Find one credential expression without consuming the rest of its source line."""
    while start < limit and data[start:start + 1] in b' \t':
        start += 1
    if start >= limit:
        return start, start
    first = data[start:start + 1]
    if first in (b'"', b"'"):
        quote = first
        index = start + 1
        while index < limit:
            if data[index:index + 1] == b'\\':
                index += 2
                continue
            if data[index:index + 1] == quote:
                return start, index + 1
            index += 1
        return start, limit

    pairs = {ord('{'): ord('}'), ord('('): ord(')'), ord('['): ord(']')}
    closers = {value for value in pairs.values()}
    stack = []
    quote = None
    index = start
    while index < limit:
        current = data[index]
        if quote is not None:
            if current == ord('\\'):
                index += 2
                continue
            if current == quote:
                quote = None
            index += 1
            continue
        if current in (ord('"'), ord("'"), ord('`')):
            quote = current
        elif current in pairs:
            stack.append(pairs[current])
        elif current in closers:
            if not stack:
                break
            if current != stack[-1]:
                break
            stack.pop()
            if not stack:
                index += 1
                break
        elif current in (ord(','), ord(';'), ord('\n'), ord('\r')) and not stack:
            break
        index += 1
    end = index
    while end > start and data[end - 1:end] in b' \t':
        end -= 1
    return start, max(start, end)


def _credential_literal_spans(data, start, end, source_path):
    """Return literal payloads in one finding, preserving its surrounding code."""
    suffix = Path(str(source_path or '')).suffix.lower()
    python = suffix == '.py'
    spans = []
    index = start
    while index < end:
        current = data[index]
        following = data[index + 1:index + 2]
        if python and current == ord('#'):
            newline = data.find(b'\n', index, end)
            if newline < 0:
                break
            index = newline + 1
            continue
        if not python and data[index:index + 2] == b'//':
            newline = data.find(b'\n', index, end)
            if newline < 0:
                break
            index = newline + 1
            continue
        if not python and data[index:index + 2] == b'/*':
            close = data.find(b'*/', index + 2, end)
            if close < 0:
                break
            index = close + 2
            continue
        if current in (ord('"'), ord("'"), ord('`')):
            quote = current
            content_start = index + 1
            cursor = content_start
            while cursor < end:
                if data[cursor] == ord('\\'):
                    cursor += 2
                    continue
                if data[cursor] == quote:
                    if cursor > content_start:
                        spans.append((content_start, cursor))
                    index = cursor + 1
                    break
                cursor += 1
            else:
                if end > content_start:
                    spans.append((content_start, end))
                break
            continue
        index += 1
    return spans


def within(path, root):
    return path == root or root in path.parents


def safe_output(value, source_path=None):
    if isinstance(value, str):
        data = value.encode()
        replacements = []
        for match, rule, _ in credential_findings(data, source_path):
            if rule == 'secret.signature':
                start, end = match.span()
            else:
                value_start, value_end = match.span('value')
                if value_start < 0 or value_end <= value_start:
                    continue
                if (match['separator'] == b':' and str(source_path or '').lower().endswith('.py')):
                    typed_value = re.match(
                        rb'\s*(?:str|string|bytes|int|integer|float|bool|boolean|object|Any|None|Optional\[[^\]\n]{1,80}\])\s*=\s*',
                        data[value_start:value_end], re.I)
                    if typed_value:
                        value_start += typed_value.end()
                literal_spans = _credential_literal_spans(data, value_start, value_end, source_path)
                if literal_spans:
                    replacements.extend(literal_spans)
                    continue
                start, end = value_start, value_end
                if start >= end:
                    continue
            replacements.append((start, end))
        if not replacements:
            return value
        # 合并重叠的发现，防止同一凭据被不同规则重复处理。
        replacements.sort()
        merged = []
        for start, end in replacements:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        for start, end in reversed(merged):
            data = data[:start] + b'[REDACTED]' + data[end:]
        return data.decode('utf-8', errors='replace')
    if isinstance(value, list):
        return [safe_output(x, source_path) for x in value]
    if isinstance(value, dict):
        context = source_path
        if context is None and isinstance(value.get('path'), str):
            context = value['path']
        elif context is None and isinstance(value.get('paths'), list) and len(value['paths']) == 1 and isinstance(value['paths'][0], str):
            context = value['paths'][0]
        return {k: safe_output(v, context) for k, v in value.items()}
    return value


def sensitive(path):
    for part in path.parts:
        name = part.lower()
        if name in SENSITIVE_DIRS or name in SENSITIVE_NAMES or name == '.env' or name.startswith('.env.'):
            return True
        if name.endswith(('.pem', '.key', '.p12', '.pfx', '.kdbx', '.db', '.db3', '.sqlite', '.sqlite3', '.sql', '.dump', '.bak')):
            return True
        if re.search(r'(^|[._-])(secret|credentials?|tokens?|passwords?|private[-_]?keys?|api[-_]?keys?|access[-_]?keys?)([._-]|$)', name):
            return True
    return False


def error_code(error):
    if isinstance(error, PermissionError):
        return 'linux_permission_denied'
    if isinstance(error, FileNotFoundError):
        return 'not_found'
    if isinstance(error, OSError):
        return errno.errorcode.get(error.errno, 'filesystem_error')
    if isinstance(error, ValueError):
        return str(error)[:200]
    return 'operation_failed'


class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]


def open_components(root, relative, flags):
    """逐级打开已解析的路径；目录描述符固定后不再跟随链接。"""
    parts = Path(relative).parts
    if Path(relative).is_absolute() or '..' in parts:
        raise ValueError('Invalid anchored path')
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return os.open(parts[-1] if parts else '.', flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError('Path changed during anchored open') from None
        raise
    finally:
        os.close(fd)


def open_beneath(root, relative, flags):
    """openat2 在内核中验证整个路径，防止检查后替换符号链接。"""
    root_fd = os.open(root, os.O_PATH | os.O_DIRECTORY)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        how = OpenHow(flags | os.O_CLOEXEC, 0, 0x08 | 0x02)  # BENEATH, NO_MAGICLINKS
        fd = libc.syscall(437, root_fd, os.fsencode(relative), ctypes.byref(how), ctypes.sizeof(how))
        if fd < 0:
            number = ctypes.get_errno()
            if number in (errno.EXDEV, errno.ELOOP):
                raise ValueError('Path changed or symbolic link crossed authorization boundary')
            if number == errno.ENOSYS:
                return open_components(root, relative, flags)
            raise OSError(number, os.strerror(number))
        return fd
    finally:
        os.close(root_fd)


def attach_file_access(cls):
    previous_init = cls.__init__
    previous_apply = cls.apply_change
    previous_restore = cls.restore_snapshot
    previous_caps = cls.get_capabilities
    previous_approval = cls.approval
    previous_load = cls.load_approval

    def initialize(self, config_path):
        previous_init(self, config_path)
        private = [self.config_path, self.config_path.parent / 'token', self.state, Path(__file__).resolve().parent]
        if any(spec['root'] in self.config_path.parent.parents for spec in self.projects.values()):
            private.append(self.config_path.parent)
        private += [Path(p).resolve() for p in self.cfg.get('administratorPaths', [])]
        self.private_paths = tuple(private)
        grants = self.cfg.get('sensitiveGrants', [])
        for grant in grants:
            if not Path(grant.get('path', '')).is_absolute() or type(grant.get('expires')) not in (int, float):
                raise ValueError('Sensitive grants need an exact absolute path and expiry')
        self.sensitive_grants = grants
        # 启动时验证带目录描述符的安全打开方式。
        for spec in self.projects.values():
            fd = open_beneath(spec['root'], '.', os.O_PATH | os.O_DIRECTORY)
            os.close(fd)

    def has_sensitive_grant(self, target, write=False):
        return any(Path(g['path']) == target and g['expires'] > time.time() and
                   g.get('write' if write else 'read', False) for g in self.sensitive_grants)

    def allowed(self, project, rel, write=False, linkMode='target'):
        spec = self.project(project)
        if not isinstance(rel, str) or not rel or '\0' in rel or '..' in Path(rel).parts:
            raise ValueError('Use an authorized absolute path or relative path without ..')
        root = spec['root']
        q = Path(rel)
        lexical = q if q.is_absolute() else root / q
        if not within(lexical, root):
            raise ValueError('Outside selected authorization root')
        if linkMode not in ('target', 'link'):
            raise ValueError('linkMode must be target or link')
        try:
            resolved = lexical.resolve(strict=False)
        except (OSError, RuntimeError):
            raise ValueError('Cannot resolve symbolic link safely') from None
        if not within(resolved, root):
            raise ValueError('Symbolic link target is outside selected authorization root')
        for candidate in (lexical, resolved):
            if any(PRIVATE_TEMP.fullmatch(part) for part in candidate.parts) or any(within(candidate, private) for private in self.private_paths):
                raise ValueError('MCP administrator path requires independent local maintenance')
        normal = lexical.relative_to(root).as_posix()
        real_normal = resolved.relative_to(root).as_posix()
        for name in (normal, real_normal):
            if any(fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(Path(name).name, pattern)
                   for pattern in spec.get('deny', [])):
                raise ValueError('Explicitly denied project path')
            if any(name.casefold() == d.casefold() or name.casefold().startswith(d.casefold() + '/')
                   for d in spec.get('denyDirs', [])):
                raise ValueError('Explicitly denied project directory')
        if not spec.get('read', True):
            raise ValueError('Read permission disabled')
        if (sensitive(lexical) or sensitive(resolved)) and not self.has_sensitive_grant(resolved, write):
            raise ValueError('Sensitive path requires exact local authorization')
        if write:
            if not spec.get('write', False):
                raise ValueError('Project is read-only')
            scopes = spec.get('writeAllow', [])
            if not any(fnmatch.fnmatchcase(normal, p) for p in scopes):
                raise ValueError('Path is outside writable scope')
            if '.git' in lexical.parts or '.git' in resolved.parts:
                raise ValueError('Git internal files require separate Git permission and tools')
            if any(within(private, lexical) or within(private, resolved) for private in self.private_paths):
                raise ValueError('Cannot mutate an ancestor of an administrator path')
        return lexical.parent.resolve() / lexical.name if linkMode == 'link' else resolved

    def checked_fd(self, project, path, flags=os.O_RDONLY):
        target = self.allowed(project, path)
        root = self.project(project)['root']
        fd = open_beneath(root, target.relative_to(root).as_posix(), flags | os.O_NONBLOCK)
        try:
            actual = Path('/proc/self/fd/' + str(fd)).resolve()
            self.allowed(project, str(actual))
            if actual != target:
                raise ValueError('Path changed during open')
            return fd
        except Exception:
            os.close(fd)
            raise

    def read(self, project, rel, limit=MAX_FILE):
        fd = self.checked_fd(project, rel)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Require a regular file without hard links')
            if info.st_size > limit:
                raise ValueError('File too large; use read_file_lines')
            raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('File grew beyond size limit')
            return raw, stat.S_IMODE(info.st_mode)

    def audit_event(self, tool, status, project=None, paths=None):
        import logging
        record = {'time': time.time(), 'tool': tool, 'status': status, 'project': project}
        if paths is not None:
            visible = []
            for path in paths[:50]:
                try:
                    target = self.allowed(project, path)
                    if sensitive(target) or safe_output(path) != path:
                        continue
                    if path not in visible:
                        visible.append(path)
                except (ValueError, OSError, TypeError):
                    continue
            record['paths'] = visible
        self.audit.info(json.dumps(record, ensure_ascii=False))

    def list_projects(self):
        return {'projects': [{'project': name, 'root': str(p['root']), 'read': p.get('read', True),
                              'write': bool(p.get('write')), 'gitWrite': bool(p.get('gitWrite')),
                              'tasks': sorted(p.get('tasks', {}))} for name, p in self.projects.items()]}

    def resolve_path(self, path, write=False):
        if not Path(path).is_absolute():
            raise ValueError('resolve_path requires an absolute path')
        candidates = sorted(self.projects, key=lambda n: len(self.projects[n]['root'].parts), reverse=True)
        for name in candidates:
            if within(Path(path), self.projects[name]['root']):
                target = self.allowed(name, path, write)
                return {'project': name, 'path': Path(path).relative_to(self.projects[name]['root']).as_posix(),
                        'resolvedPath': str(target), 'symlink': Path(path).is_symlink()}
        raise ValueError('Path is outside all authorized roots')

    def read_text_file(self, project, path):
        raw, _ = self.read(project, path)
        if b'\0' in raw:
            raise ValueError('Binary data; use read_binary_file')
        target = self.allowed(project, path)
        text = '[REDACTED: sensitive file content stays local]' if sensitive(target) else safe_output(raw.decode('utf-8'), path)
        return {'text': text, 'sha256': hashed(raw), 'bytes': len(raw), 'contentRedacted': sensitive(target) or text != raw.decode('utf-8')}

    def read_binary_file(self, project, path):
        raw, _ = self.read(project, path)
        if sensitive(self.allowed(project, path)) or SECRET.search(raw, path):
            raise ValueError('Sensitive bytes are not returned to chat')
        return {'base64': base64.b64encode(raw).decode(), 'sha256': hashed(raw), 'bytes': len(raw)}

    def list_directory(self, project, path='.', offset=0, limit=100):
        if type(offset) is not int or not 0 <= offset <= 20000 or type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError('Invalid pagination')
        target = self.allowed(project, path)
        entries = []
        fd = self.checked_fd(project, path, os.O_RDONLY | os.O_DIRECTORY)
        with os.scandir(fd) as iterator:
            for n, child in enumerate(iterator, 1):
                if n > 20000:
                    raise ValueError('Directory scan capped; narrow the path')
                try:
                    self.allowed(project, str(target / child.name))
                except ValueError:
                    continue
                kind = 'symlink' if child.is_symlink() else 'directory' if child.is_dir(follow_symlinks=False) else 'file'
                entries.append({'name': child.name, 'type': kind})
        os.close(fd)
        entries.sort(key=lambda x: x['name'])
        page = entries[offset:offset + limit]
        more = offset + len(page) < len(entries)
        return {'entries': page, 'totalEntries': len(entries), 'hasMore': more,
                'nextOffset': offset + len(page) if more else None}

    def walk(self, project, path='.', maxDepth=8):
        if type(maxDepth) is not int or not 0 <= maxDepth <= 32:
            raise ValueError('Invalid depth')
        root = self.project(project)['root']
        start = self.allowed(project, path)
        stack, files, visited, incomplete = [(start, 0)], [], 0, False
        deadline = time.monotonic() + 5
        while stack:
            directory, depth = stack.pop()
            try:
                fd = self.checked_fd(project, str(directory), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            visited += 1
                            if visited > 20000 or time.monotonic() > deadline:
                                return sorted(files), True
                            child = directory / entry.name
                            try:
                                target = self.allowed(project, str(child))
                            except ValueError:
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if depth < maxDepth:
                                    stack.append((target, depth + 1))
                                else:
                                    incomplete = True
                            elif entry.is_file(follow_symlinks=False) or entry.is_symlink():
                                files.append(child.relative_to(root).as_posix())
                finally:
                    os.close(fd)
            except OSError:
                incomplete = True
        return sorted(files), incomplete

    def search_paths(self, project, pattern, path='.', offset=0, limit=100, maxDepth=8):
        if type(offset) is not int or not 0 <= offset <= 20000 or type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError('Invalid pagination')
        if type(maxDepth) is not int or not 0 <= maxDepth <= 32 or not pattern or len(pattern) > 256:
            raise ValueError('Invalid depth or pattern')
        start = self.allowed(project, path)
        root = self.project(project)['root']
        stack, matches, count, complete = [(start, 0)], [], 0, True
        deadline = time.monotonic() + 5
        while stack and complete:
            directory, depth = stack.pop()
            try:
                listing = self.list_directory(project, str(directory), limit=200)
                entries = list(listing['entries'])
                while listing['hasMore']:
                    listing = self.list_directory(project, str(directory), offset=listing['nextOffset'], limit=200)
                    entries.extend(listing['entries'])
                for entry in entries:
                    count += 1
                    if count > 20000 or time.monotonic() > deadline:
                        complete = False
                        break
                    child = directory / entry['name']
                    rel = child.relative_to(root).as_posix()
                    if fnmatch.fnmatchcase(rel, pattern) or fnmatch.fnmatchcase(entry['name'], pattern):
                        matches.append({'path': rel, 'type': entry['type']})
                    if entry['type'] == 'directory':
                        if depth < maxDepth:
                            stack.append((child, depth + 1))
                        else:
                            complete = False
            except OSError:
                complete = False
        matches.sort(key=lambda x: x['path'])
        page = matches[offset:offset + limit]
        more = offset + len(page) < len(matches)
        return {'results': page, 'scanComplete': complete, 'hasMore': more, 'nextOffset': offset + len(page) if more else None}

    def validate_configuration(self):
        return {'valid': True, 'version': self.health()['version'], 'projects': self.list_projects()['projects'],
                'privatePathsProtected': True, 'sensitiveGrants': len([g for g in self.sensitive_grants if g['expires'] > time.time()]),
                'configHash': hashed(self.config_path.read_bytes())}

    def get_service_status(self):
        import subprocess
        import re
        units = []
        service_names = self.cfg.get('serviceNames', {})
        mcp_unit = service_names.get('mcp', 'notion-local-mcp.service')
        tunnel_unit = service_names.get('tunnel', 'notion-local-mcp-tunnel.service')
        for unit in (mcp_unit, tunnel_unit):
            try:
                result = subprocess.run(['/usr/bin/systemctl', '--user', 'show', unit, '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID'],
                                        capture_output=True, text=True, timeout=5)
                output = result.stdout.decode('utf-8', errors='replace') if isinstance(result.stdout, bytes) else result.stdout
                fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
                units.append({'unit': unit, **fields})
            except (OSError, subprocess.TimeoutExpired):
                units.append({'unit': unit, 'state': 'unavailable'})
        # Read only the current tunnel announcement. Never return journal text,
        # credentials, tokens, or cloudflared configuration.
        public_url = None
        tunnel = next((unit for unit in units if unit['unit'] == tunnel_unit), {})
        try:
            invocation = subprocess.run(
                ['/usr/bin/systemctl', '--user', 'show',
                 tunnel_unit, '-p', 'InvocationID'],
                capture_output=True, text=True, timeout=5,
            ).stdout
            if isinstance(invocation, bytes):
                invocation = invocation.decode('utf-8', errors='replace')
            invocation_id = invocation.partition('=')[2].strip()
            if tunnel.get('ActiveState') == 'active' and re.fullmatch(r'[0-9a-f]{32}', invocation_id):
                journal = subprocess.run(
                    ['/usr/bin/journalctl', '--user', '--no-pager', '-o', 'json', '-n', '20',
                     '--grep=https://[a-z0-9-]+[.]trycloudflare[.]com[[:space:]]+[|]',
                     '_SYSTEMD_INVOCATION_ID=' + invocation_id],
                    capture_output=True, text=True, timeout=5,
                ).stdout
                if isinstance(journal, bytes):
                    journal = journal.decode('utf-8', errors='replace')
                candidates = []
                for line in journal.splitlines():
                    try:
                        message = json.loads(line).get('MESSAGE', '')
                    except (TypeError, ValueError):
                        continue
                    if not isinstance(message, str):
                        continue
                    for host in re.findall(r'\|\s*https://([a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com)\s*\|\s*$', message):
                        candidate = 'https://' + host + '/mcp'
                        if candidate not in candidates:
                            candidates.append(candidate)
                current = subprocess.run(
                    ['/usr/bin/systemctl', '--user', 'show',
                     tunnel_unit, '-p', 'InvocationID', '-p', 'ActiveState'],
                    capture_output=True, text=True, timeout=5,
                ).stdout
                if isinstance(current, bytes):
                    current = current.decode('utf-8', errors='replace')
                fields = dict(line.split('=', 1) for line in current.splitlines() if '=' in line)
                if candidates and fields.get('InvocationID') == invocation_id and fields.get('ActiveState') == 'active':
                    public_url = candidates[-1]
        except (OSError, subprocess.TimeoutExpired):
            public_url = None
        return {
            'units': units,
            'version': self.health()['version'],
            'publicMcpUrl': public_url,
            'publicMcpUrlConfigured': public_url is not None,
            'publicMcpUrlSource': tunnel_unit + ' journal' if public_url else None,
            'restartRequiresLocalApproval': True,
        }

    def plan_service_restart(self):
        mcp_unit = self.cfg.get('serviceNames', {}).get('mcp', 'notion-local-mcp.service')
        return self.approval('service_restart', None, {'unit': mcp_unit,
                            'configHash': hashed(self.config_path.read_bytes())},
                            {'operation': 'restart', 'unit': mcp_unit,
                             'note': 'Only this MCP service restarts. Local administrator approval required.'})

    def apply_service_restart(self, approvalId):
        import subprocess
        record = self.load_approval(approvalId)
        mcp_unit = self.cfg.get('serviceNames', {}).get('mcp', 'notion-local-mcp.service')
        if record['kind'] != 'service_restart' or record['payload'] != {'unit': mcp_unit, 'configHash': hashed(self.config_path.read_bytes())}:
            raise ValueError('Wrong maintenance approval or configuration changed')
        self.load_approval(approvalId, consume=True)
        result = subprocess.run(['/usr/bin/systemd-run', '--user', '--collect', '--on-active=2s',
            '--unit=notion-local-mcp-approved-restart-' + approvalId,
            '/usr/bin/systemctl', '--user', 'restart', mcp_unit], capture_output=True, timeout=10)
        if result.returncode:
            raise ValueError('Restart scheduling failed; approval consumed, inspect local service status')
        return {'scheduled': True, 'unit': mcp_unit, 'delaySeconds': 2,
                'instruction': 'Reconnect and check health. Do not replay this maintenance operation.'}

    def node(self, project, path, write=False, linkMode='link'):
        target = self.allowed(project, path, write, linkMode)
        if not target.exists() and not target.is_symlink():
            return None
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode):
            return {'kind': 'symlink', 'target': os.readlink(target), 'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISREG(info.st_mode):
            raw, mode = self.read(project, str(target))
            return {'kind': 'file', 'data': base64.b64encode(raw).decode(), 'mode': mode}
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('Special files are not supported')
        children = {}
        for current, directories, filenames in os.walk(target, followlinks=False):
            for name in directories + filenames:
                p = Path(current) / name
                self.allowed(project, str(p), write, 'link')
                key = p.relative_to(target).as_posix()
                inf = p.lstat()
                if p.is_symlink():
                    children[key] = {'kind': 'symlink', 'target': os.readlink(p), 'mode': stat.S_IMODE(inf.st_mode)}
                elif p.is_dir():
                    children[key] = {'kind': 'directory', 'mode': stat.S_IMODE(inf.st_mode)}
                else:
                    children[key] = self.node(project, str(p), write)
                if len(children) > MAX_NODES or sum(len(x.get('data', '')) for x in children.values()) > MAX_TREE * 4 // 3:
                    raise ValueError('Directory operation exceeds snapshot limit')
        return {'kind': 'directory', 'mode': stat.S_IMODE(info.st_mode), 'children': children}

    def node_hash(self, value):
        if value is None:
            return None
        if value['kind'] == 'file':
            return hashed(base64.b64decode(value['data']))
        return hashed(canonical(value))

    def get_path_hash(self, project, path, linkMode='link'):
        value = self.node(project, path, linkMode=linkMode)
        return {'sha256': self.node_hash(value), 'kind': value['kind'] if value else 'missing'}

    def approval(self, kind, project, payload, preview):
        result = previous_approval(self, kind, project, payload, safe_output(preview))
        file = self.state / 'approvals' / (result['approvalId'] + '.json')
        record = json.loads(file.read_text())
        record['binding'] = hashed(canonical({k: record[k] for k in ('id', 'kind', 'project', 'created', 'expires', 'payload')}))
        self.atomic_json(file, record)
        return result

    def load_approval(self, aid, consume=False):
        record = previous_load(self, aid, consume=False)
        if 'binding' not in record:
            raise ValueError('Legacy approval requires a new preview')
        actual = hashed(canonical({k: record[k] for k in ('id', 'kind', 'project', 'created', 'expires', 'payload')}))
        if record['binding'] != actual or record.get('approvedBinding') != actual:
            raise ValueError('Approval payload or expiry changed after local review')
        if consume:
            record['used'] = True
            self.atomic_json(self.state / 'approvals' / (aid + '.json'), record)
        return record

    def plan_file_operations(self, project, operations):
        if not isinstance(operations, list) or not 1 <= len(operations) <= 20:
            raise ValueError('Provide 1 to 20 operations')
        items, previews, used = [], [], []
        for op in operations:
            action = op.get('operation')
            if action not in ('write', 'mkdir', 'copy', 'move', 'delete'):
                raise ValueError('Unsupported file operation')
            if not isinstance(op, dict) or set(op) - {'operation','path','destination','expectedHash','destinationExpectedHash','content','contentBase64','overwrite','linkMode'}:
                raise ValueError('Invalid operation fields')
            link_mode = op.get('linkMode', 'link' if action in ('copy', 'move', 'delete') else 'target')
            path = self.allowed(project, op['path'], write=action != 'copy', linkMode=link_mode)
            if path == self.project(project)['root']:
                raise ValueError('Cannot mutate an authorization root')
            old = self.node(project, str(path), write=action != 'copy', linkMode=link_mode)
            if self.node_hash(old) != op.get('expectedHash'):
                raise ValueError('expectedHash required and must match current path')
            touched = [path]
            before = {str(path): old}
            after = {}
            if action == 'write':
                if old and old['kind'] != 'file':
                    raise ValueError('Write requires a regular file; linkMode=target writes its target')
                if ('content' in op) == ('contentBase64' in op):
                    raise ValueError('Supply exactly one of content or contentBase64')
                try:
                    raw = op['content'].encode('utf-8') if 'content' in op else base64.b64decode(op['contentBase64'], validate=True)
                except Exception:
                    raise ValueError('Invalid write encoding') from None
                if len(raw) > MAX_FILE:
                    raise ValueError('File write exceeds 2 MiB limit')
                after[str(path)] = {'kind': 'file', 'data': base64.b64encode(raw).decode(), 'mode': old['mode'] if old else 0o600}
            elif action == 'mkdir':
                if old is not None:
                    raise ValueError('Directory already exists')
                after[str(path)] = {'kind': 'directory', 'mode': 0o700, 'children': {}}
            elif action == 'delete':
                if old is None:
                    raise ValueError('Path does not exist')
                after[str(path)] = None
            else:
                if old is None:
                    raise ValueError('Source does not exist')
                destination = self.allowed(project, op['destination'], True, 'link')
                previous = self.node(project, str(destination), write=True)
                if self.node_hash(previous) != op.get('destinationExpectedHash'):
                    raise ValueError('destinationExpectedHash required for overwrite')
                if previous and not op.get('overwrite', False):
                    raise ValueError('Destination exists; explicit overwrite required')
                if within(destination, path) or within(path, destination):
                    raise ValueError('Source and destination overlap')
                touched.append(destination)
                before[str(destination)] = previous
                after[str(destination)] = old
                if action == 'move':
                    after[str(path)] = None
                # 复制链接时相对链接目标以新父目录解析，必须再次验证。
                self.validate_links(project, destination, old)
            for target in touched:
                if any(within(target, prior) or within(prior, target) for prior in used):
                    raise ValueError('Plan paths overlap; use separate approvals')
                if not target.parent.is_dir():
                    raise ValueError('Parent directory must already exist')
            used.extend(touched)
            items.append({'operation': action, 'before': before, 'after': after, 'linkMode': link_mode})
            previews.append({'operation': action, 'paths': [str(x) for x in touched], 'linkMode': link_mode,
                             'beforeHashes': {p: self.node_hash(v) for p, v in before.items()},
                             'afterHashes': {p: self.node_hash(v) for p, v in after.items()},
                             'contentPreview': '[REDACTED: sensitive path]' if any(sensitive(x) for x in touched) else safe_output(op.get('content', 'Binary/directory payload: hash only')[:8192], op['path']),
                             'previewTruncated': len(op.get('content', '')) > 8192})
        if len(canonical(items)) > MAX_TREE * 3:
            raise ValueError('Plan exceeds backup limit')
        return self.approval('file_operations', project, items, previews)

    def validate_links(self, project, target, value):
        nodes = {'': value}
        if value and value['kind'] == 'directory':
            nodes.update(value.get('children', {}))
        for rel, child in nodes.items():
            if child and child['kind'] == 'symlink':
                link = target / rel if rel else target
                resolved = (link.parent / child['target']).resolve()
                self.allowed(project, str(resolved), write=True)

    def plan_files(self, project, changes):
        operations = []
        for change in changes:
            op = {'operation': 'write', **change}
            if 'edits' in change:
                raw, _ = self.read(project, change['path'])
                text = raw.decode('utf-8')
                for edit in change['edits']:
                    if not edit['oldText'] or text.count(edit['oldText']) != 1:
                        raise ValueError('Each oldText must match exactly once')
                    text = text.replace(edit['oldText'], edit['newText'], 1)
                op.pop('edits')
                op['content'] = text
            operations.append(op)
        return self.plan_file_operations(project, operations)

    def write_binary_file(self, project, path, contentBase64, expectedHash=None):
        return self.plan_file_operations(project, [{'operation': 'write', 'path': path,
                                                   'contentBase64': contentBase64, 'expectedHash': expectedHash}])

    def create_directory(self, project, path):
        return self.plan_file_operations(project, [{'operation': 'mkdir', 'path': path}])

    def copy_path(self, project, path, destination, expectedHash, destinationExpectedHash=None, overwrite=False, linkMode='link'):
        return self.plan_file_operations(project, [{'operation': 'copy', 'path': path, 'destination': destination,
            'expectedHash': expectedHash, 'destinationExpectedHash': destinationExpectedHash, 'overwrite': overwrite, 'linkMode': linkMode}])

    def move_path(self, project, path, destination, expectedHash, destinationExpectedHash=None, overwrite=False, linkMode='link'):
        return self.plan_file_operations(project, [{'operation': 'move', 'path': path, 'destination': destination,
            'expectedHash': expectedHash, 'destinationExpectedHash': destinationExpectedHash, 'overwrite': overwrite, 'linkMode': linkMode}])

    def rename_path(self, project, path, destination, expectedHash, linkMode='link'):
        return self.move_path(project, path, destination, expectedHash, linkMode=linkMode)

    def delete_path(self, project, path, expectedHash, linkMode='link'):
        return self.plan_file_operations(project, [{'operation': 'delete', 'path': path, 'expectedHash': expectedHash, 'linkMode': linkMode}])

    def materialize(self, path, value):
        if value['kind'] == 'file':
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(base64.b64decode(value['data']))
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), value['mode'])
        elif value['kind'] == 'symlink':
            os.symlink(value['target'], path)
        else:
            path.mkdir(mode=0o700)
            for rel, child in sorted(value.get('children', {}).items(), key=lambda x: (len(Path(x[0]).parts), x[0])):
                self.materialize(path / rel, {**child, 'mode': 0o700} if child['kind'] == 'directory' else child)
            # 子目录的权限最后恢复，避免只读目录阻止重建内容。
            for rel, child in sorted(value.get('children', {}).items(), key=lambda x: -len(Path(x[0]).parts)):
                if child['kind'] == 'directory':
                    os.chmod(path / rel, child['mode'])
            os.chmod(path, value['mode'])

    def replace_node(self, project, path, value, expected):
        target = self.allowed(project, path, True, 'link')
        parent_fd = self.checked_fd(project, str(target.parent), os.O_RDONLY | os.O_DIRECTORY)
        stage_name = '.mcp-stage-' + secrets.token_hex(12)
        trash_name = '.mcp-recovery-' + secrets.token_hex(12)
        held = Path('/proc/self/fd/' + str(parent_fd))
        staged = held / stage_name
        trash = held / trash_name
        try:
            if value is not None:
                self.validate_links(project, target, value)
                self.materialize(staged, value)
            if self.node_hash(self.node(project, str(target), write=True)) != expected:
                raise ValueError('File changed after preview')
            self.allowed(project, str(Path('/proc/self/fd/' + str(parent_fd)).resolve()))
            if expected is not None:
                # 原目录通过同一父目录内的 rename 保留，失败可恢复。
                if value and value['kind'] == 'file' and target.is_file() and not target.is_symlink():
                    os.replace(stage_name, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                else:
                    os.rename(target.name, trash_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    try:
                        if value is not None:
                            self.rename_noreplace(parent_fd, stage_name, target.name)
                    except Exception:
                        self.rename_noreplace(parent_fd, trash_name, target.name)
                        raise
            elif value is not None:
                self.rename_noreplace(parent_fd, stage_name, target.name)
            os.fsync(parent_fd)
        finally:
            # 已有内容在持久快照中；只清理本次生成的随机临时名称。
            for temporary in (staged, trash):
                if temporary.is_symlink() or temporary.is_file():
                    temporary.unlink()
                elif temporary.exists():
                    # 将原目录移到私有恢复范围，不改动原文件权限。
                    recovery = self.state / 'recovery'
                    recovery.mkdir(mode=0o700, exist_ok=True)
                    try:
                        os.rename(temporary, recovery / temporary.name)
                    except OSError:
                        try:
                            shutil.rmtree(temporary)
                        except OSError:
                            self.audit_event('temporary_cleanup', 'local_recovery_retained', project)
            os.close(parent_fd)

    def rename_noreplace(self, parent_fd, source, destination):
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1)
        if result:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))

    def apply_change(self, approvalId):
        with self.lock:
            record = self.load_approval(approvalId)
            if record['kind'] != 'file_operations':
                return previous_apply(self, approvalId)
            project, items = record['project'], record['payload']
            for item in items:
                for path, old in item['before'].items():
                    if self.node_hash(self.node(project, path, write=item['operation'] != 'copy')) != self.node_hash(old):
                        raise ValueError('Change set conflict; no files written')
            self.load_approval(approvalId, consume=True)
            snapshot = {'id': approvalId, 'project': project, 'created': time.time(), 'operations': items,
                        'completedPaths': [], 'observedAfter': {}}
            self.atomic_json(self.state / 'snapshots' / (approvalId + '.json'), snapshot)
            completed = []
            try:
                for item in items:
                    for path, value in item['after'].items():
                        self.replace_node(project, path, value, self.node_hash(item['before'].get(path)))
                        completed.append(path)
                        snapshot['completedPaths'] = list(completed)
                        snapshot['observedAfter'][path] = self.node_hash(value)
                        self.atomic_json(self.state / 'snapshots' / (approvalId + '.json'), snapshot)
            except Exception as error:
                self.audit_event('apply_change', 'partial_failure', project, paths=[str(Path(p).relative_to(self.project(project)['root'])) for p in completed])
                return {'applied': False, 'partial': bool(completed), 'writtenPaths': completed,
                        'snapshotId': approvalId, 'error': error_code(error), 'multiFileAtomic': False,
                        'instruction': 'Inspect current hashes, then preview restore_snapshot; approval is consumed, do not retry this write.'}
            self.audit_event('apply_change', 'ok', project, paths=[str(Path(p).relative_to(self.project(project)['root'])) for p in completed])
            return {'applied': True, 'paths': completed, 'snapshotId': approvalId, 'multiFileAtomic': False}

    def list_snapshots(self, project, limit=20):
        self.project(project)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('Invalid limit')
        result = []
        for p in sorted((self.state / 'snapshots').glob('*.json'), key=lambda x: x.stat().st_mtime, reverse=True):
            obj = json.loads(p.read_text())
            if obj['project'] == project:
                paths = obj.get('completedPaths', [x['path'] for x in obj.get('files', [])])
                result.append({'snapshotId': obj['id'], 'created': obj['created'], 'paths': paths})
            if len(result) == limit:
                break
        return {'snapshots': result}

    def restore_snapshot(self, project, snapshotId):
        if not re.fullmatch('[0-9a-f]{32}', snapshotId):
            raise ValueError('Invalid snapshot ID')
        snap = json.loads((self.state / 'snapshots' / (snapshotId + '.json')).read_text())
        if snap['project'] != project:
            raise ValueError('Wrong project')
        if 'operations' not in snap:
            return previous_restore(self, project, snapshotId)
        operations, previews = [], []
        originals = {p: v for op in snap['operations'] for p, v in op['before'].items()}
        for path in reversed(snap['completedPaths']):
            current = self.node(project, path, write=True)
            if self.node_hash(current) != snap['observedAfter'][path]:
                raise ValueError('Restore conflict; file changed since this snapshot')
            original = originals[path]
            item = {'operation': 'restore', 'before': {path: current}, 'after': {path: original}, 'linkMode': 'link'}
            operations.append(item)
            previews.append({'operation': 'restore', 'path': path, 'expectedHash': self.node_hash(current), 'restoredHash': self.node_hash(original)})
        if not operations:
            raise ValueError('No completed changes to restore')
        return self.approval('file_operations', project, operations, previews)

    def get_capabilities(self, project=None):
        result = previous_caps(self, project)
        for entry in result['projects']:
            entry.pop('broadHomeReadOnly', None)
            entry['root'] = str(self.project(entry['project'])['root'])
        result['features'].update({'hiddenFiles': True, 'absolutePathRouting': True, 'binaryWrite': True,
            'directoryOperations': True, 'recoverableDelete': True, 'localApprovalRequired': True,
            'symlinks': 'in-root targets only; explicit link versus target operations',
            'administratorMaintenance': 'independent local CLI; no remote approval',
            'conflictChecks': 'hash before planning and execution; not CAS against hostile same-uid writers'})
        result['limits'].update({'maxDirectoryNodes': MAX_NODES, 'snapshotBytes': MAX_TREE})
        return result

    for name, method in list(locals().items()):
        if callable(method) and name not in {'previous_init', 'previous_apply', 'previous_restore', 'previous_caps', 'previous_approval', 'previous_load', 'cls'}:
            setattr(cls, '__init__' if name == 'initialize' else name, method)
