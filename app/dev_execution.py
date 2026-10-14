"""在独立用户、文件系统、进程和网络空间内执行开发命令。

每个开发副本使用有容量上限的 tmpfs 和独立用户 cgroup。所有任务均进入
该副本的隔离空间；隔离启动失败时直接拒绝，绝不在宿主机回退执行。
"""
import atexit
import codecs
import hashlib
import json
import os
import pty
import re
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import termios
import time
import uuid
from pathlib import Path

from file_access import safe_output, open_components, SECRET

NODE = Path(os.environ.get('NOTION_MCP_NODE_RUNTIME', '/opt/node'))
NODE_NPM = Path(os.environ.get('NOTION_MCP_NODE_NPM', '/opt/node-v20'))
PYTHON = Path(os.environ.get('NOTION_MCP_PYTHON_RUNTIME', '/opt/python'))
CACHE = Path(os.environ.get('NOTION_MCP_PYTHON_CACHE', '/opt/dependency-cache/python'))
ID = re.compile(r'^[A-Za-z0-9_-]{1,100}$')
ENV_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
SECRET_ENV = re.compile(r'(?i)(token|secret|password|passwd|credential|private.?key|api.?key|auth|ssh|aws|cloud|database|dsn|socket|proxy)')
DEFAULT_ENV = {'PATH': '/opt/node-v20/bin:/opt/node/bin:/opt/python/bin:/usr/bin:/bin', 'HOME': '/home/dev',
               'TMPDIR': '/tmp', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONNOUSERSITE': '1',
               'NODE_PATH': '/opt/node/node_modules', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
               'LD_LIBRARY_PATH': '/opt/postgresql/lib/x86_64-linux-gnu'}
PUBLIC_FIELDS = ('taskId', 'requestId', 'workspaceId', 'profile', 'status', 'exitCode', 'unknown',
                 'stdout', 'stderr', 'truncated', 'startedAt', 'finishedAt', 'artifactsPath', 'pty')
LIVE = {'queued', 'running', 'terminating', 'finalizing'}


def _credential_marker(text):
    lowered=text.lower()
    return any(marker in lowered for marker in ('password','passwd','secret','token','api','access',
        'bearer','private key','://','akia','ghp_','gho_','ghu_','ghs_','ghr_','sk-'))


class ExecutionError(ValueError):
    def __init__(self,message,code=None,classification=None,details=None):
        lowered=message.lower()
        if classification is None:
            classification=('security' if any(x in lowered for x in ('denied','refuses root','symbolic link','traversal','profile','isolated loopback','safety','secret'))
                else 'infrastructure' if any(x in lowered for x in ('sandbox','unavailable','cleanup has not','unknown result')) else 'parameter')
        self.code=code or 'execution_'+classification+'_error'
        self.classification=classification
        self.details=details or {}
        super().__init__(message)



def _exec(args, timeout=20, **kw):
    return subprocess.run(args, capture_output=True, timeout=timeout, env={'PATH': '/usr/bin:/bin',
        'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()), 'DBUS_SESSION_BUS_ADDRESS':
        'unix:path=/run/user/' + str(os.getuid()) + '/bus'}, **kw)


def _limits(policy):
    raw = policy.get('limits', {})
    defaults = {'maxConcurrentTasks': 4, 'maxTimeoutSeconds': 600, 'maxWorkspaceSeconds': 3600,
                'maxWorkspaceBytes': 268435456, 'maxOutputBytes': 1048576, 'maxMemoryBytes': 1073741824,
                'maxProcesses': 128, 'cpuQuotaPercent': 100, 'maxWallSeconds': 3600,
                'maxCapturedBytes': raw.get('maxOutputBytes', 1048576), 'maxPersistedBytes': raw.get('maxOutputBytes',1048576),
                'maxInlineBytes': 16384, 'maxDrainBytes': 64*1024**2}
    ceilings = {'maxConcurrentTasks': 16, 'maxTimeoutSeconds': 3600, 'maxWorkspaceSeconds': 14400,
                'maxWorkspaceBytes': 2 * 1024 ** 3, 'maxOutputBytes': 4 * 1024 ** 2,
                'maxMemoryBytes': 8 * 1024 ** 3, 'maxProcesses': 1024, 'cpuQuotaPercent': 400,
                'maxWallSeconds': 14400, 'maxCapturedBytes':4*1024**2, 'maxPersistedBytes':4*1024**2,
                'maxInlineBytes':65536, 'maxDrainBytes':256*1024**2}
    result = {}
    for key, default in defaults.items():
        value = raw.get(key, default)
        if type(value) is not int or not 1 <= value <= ceilings[key]:
            raise ExecutionError('Invalid execution resource limit: ' + key)
        result[key] = value
    if result['maxMemoryBytes'] < 64 * 1024 ** 2 or result['maxWorkspaceBytes'] < 16 * 1024 ** 2:
        raise ExecutionError('Memory/disk budget too small for isolated execution')
    return result


def _environment(env):
    """命令可自定义普通参数，不能覆盖路径或注入宿主凭据与连接地址。"""
    result = dict(DEFAULT_ENV)
    if env is None: return result
    if not isinstance(env, dict) or len(env) > 32: raise ExecutionError('Invalid environment object')
    for key, value in env.items():
        if not isinstance(key, str) or not ENV_NAME.fullmatch(key) or SECRET_ENV.search(key):
            raise ExecutionError('Environment variable denied')
        if key in DEFAULT_ENV or key.startswith(('LD_', 'PYTHON', 'NODE_', 'GIT_')):
            raise ExecutionError('Runtime environment override denied')
        if not isinstance(value, str) or len(value) > 4096 or '\0' in value:
            raise ExecutionError('Invalid environment value')
        if SECRET_ENV.search(value) or '://' in value or '/run/' in value or value.startswith('/home/'):
            raise ExecutionError('Environment may reference credentials or host resources')
        result[key] = value
    return result


def _command(argv, shell):
    if (argv is None) == (shell is None): raise ExecutionError('Choose argv or explicit shell, not both')
    if shell is not None:
        if not isinstance(shell, str) or not shell or '\0' in shell or len(shell) > 128 * 1024:
            raise ExecutionError('Invalid explicit shell command')
        return ['/bin/sh', '-c', shell]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise ExecutionError('argv must be a nonempty argument array')
    if any(not isinstance(x, str) or '\0' in x or len(x) > 128 * 1024 for x in argv) or not argv[0]:
        raise ExecutionError('Invalid argv element')
    return list(argv)


def _tree_hash(root):
    """不包含输出制品，避免仅产生日志被当作代码修复。"""
    digest = hashlib.sha256()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '.dev-artifacts')
        for name in sorted(files):
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ExecutionError('Execution fingerprint requires regular files without links')
            digest.update(path.relative_to(root).as_posix().encode())
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as stream:
                for chunk in iter(lambda: stream.read(65536), b''): digest.update(chunk)
    return digest.hexdigest()


class Execution:
    def __init__(self, backend):
        if os.getuid() == 0: raise ExecutionError('Development executor refuses root')
        self.backend = backend
        self.lock = threading.RLock()
        self.jobs = {}; self.requests = {}; self.sandboxes = {}
        self.root = backend.state / 'dev-execution'
        self.root.mkdir(mode=0o700, exist_ok=True)
        for path in self.root.glob('*.json'):
            record = json.loads(path.read_text())
            if not isinstance(record, dict) or not ID.fullmatch(record.get('taskId', '')): continue
            if record.get('status') in LIVE:
                self._stop_unit(record.get('unit'))
                record.update(status='unknown', unknown=True, finishedAt=time.time())
                backend.atomic_json(path, record)
            self.jobs[record['taskId']] = record
            self.requests[record['requestKey']] = record['taskId']
        # 仅停止本执行器在已持久化登记中记录的单元，不扫描或管理无关服务。
        registry = self.root / 'sandboxes'
        registry.mkdir(mode=0o700, exist_ok=True)
        for path in registry.glob('*.json'):
            record = json.loads(path.read_text())
            self._stop_unit(record.get('unit'))
            self._stop_slice(record.get('slice'))
            path.unlink()
        self.registry = registry
        atexit.register(self.shutdown)

    def _audit(self, action, task_id, status):
        """只审计任务标识与状态，不记录命令、环境变量或交互输入。"""
        writer = getattr(self.backend, 'audit', None)
        if writer is not None:
            writer.info(json.dumps({'event': action, 'taskId': task_id, 'status': status,
                                    'timestamp': time.time()}, separators=(',', ':')))

    def _save(self, job):
        public = {k: v for k, v in job.items() if k not in {'process', 'ptyFd', 'stopEvent', 'thread', 'supervisor', '_streams', 'interrupted'}}
        left=job.get('persistLimit',1048576)
        for stream in ('stdout','stderr'):
            raw=public.get(stream,'').encode();kept=raw[:left];left-=len(kept)
            public[stream]=kept.decode('utf-8','ignore')
            if len(kept)<len(raw):public['persistenceTruncated']=True
        public['persistedBytes']=sum(len(public.get(x,'').encode()) for x in ('stdout','stderr'))
        self.backend.atomic_json(self.root / (job['taskId'] + '.json'), public)

    def _policy(self, profile):
        policy = self.backend.dev_policy(profile)
        if profile != 'autonomous-development' or policy.get('environment') != 'isolated-development':
            raise ExecutionError('General commands require autonomous-development')
        if policy.get('network', {}).get('mode') != 'loopback-only':
            raise ExecutionError('Only isolated loopback network is supported')
        return policy

    def _stop_unit(self, unit):
        if not isinstance(unit,str) or not re.fullmatch(r'linux-mcp-dev-[a-f0-9]{24}\.service',unit):return False
        try:
            before=_exec(['/usr/bin/systemctl','--user','show',unit,'--property=ControlGroup','--value'],timeout=2)
            location=before.stdout.decode().strip()
            _exec(['/usr/bin/systemctl','--user','stop',unit],timeout=5)
            state=_exec(['/usr/bin/systemctl','--user','show',unit,'--property=ActiveState','--value'],timeout=2)
            inactive=state.stdout.decode().strip() in {'inactive','failed',''}
            if not inactive:return False
            if location:
                if not location.startswith('/user.slice/') or not location.endswith('/'+unit):return False
                cgroup=Path('/sys/fs/cgroup'+location)
                if not cgroup.exists():return True
                return 'populated 0' in (cgroup/'cgroup.events').read_text().splitlines()
            # 已 collect 的登记单元不再有进程 cgroup。检查其固定单元名没有残留。
            base=Path('/sys/fs/cgroup/user.slice/user-'+str(os.getuid())+'.slice/user@'+str(os.getuid())+'.service')
            return not any(base.glob('**/'+unit))
        except (OSError,subprocess.TimeoutExpired):return False

    def _stop_slice(self, name):
        if isinstance(name, str) and re.fullmatch(r'linux-mcp-workspace-[a-f0-9]{24}\.slice', name):
            try:
                _exec(['/usr/bin/systemctl', '--user', 'stop', name], timeout=5)
                _exec(['/usr/bin/systemctl', '--user', 'revert', name], timeout=5)
            except (OSError, subprocess.TimeoutExpired): pass

    def _anchor_argv(self, limits):
        args = ['/usr/bin/bwrap', '--unshare-all', '--new-session', '--clearenv', '--cap-drop', 'ALL',
                '--uid', str(os.getuid()), '--gid', str(os.getgid()), '--ro-bind', '/usr', '/usr',
                '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/sbin', '/sbin',
                '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
                '--proc', '/proc', '--dev', '/dev', '--size', str(limits['maxWorkspaceBytes']), '--tmpfs', '/data',
                '--dir', '/data/workspace', '--dir', '/data/tmp', '--dir', '/data/home', '--dir', '/data/home/dev',
                '--symlink', 'data/workspace', '/workspace', '--symlink', 'data/tmp', '/tmp', '--symlink', 'data/home', '/home',
                '--ro-bind', str(NODE), '/opt/node', '--ro-bind', str(PYTHON), '/opt/python',
                '--ro-bind', str(NODE_NPM), '/opt/node-v20',
                '--ro-bind', str(CACHE), '/opt/dependency-cache/python',
                '--dir', '/etc', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs']
        for filename in ('hosts', 'nsswitch.conf', 'passwd', 'group', 'localtime'):
            path = Path('/etc') / filename
            if path.exists(): args += ['--ro-bind', str(path), str(path)]
        chrome = Path('/opt/google/chrome')
        if chrome.is_dir(): args += ['--ro-bind', str(chrome), str(chrome)]
        postgres = Path(os.environ.get('NOTION_MCP_POSTGRES_RUNTIME', '/opt/postgresql'))
        if postgres.is_dir(): args += ['--ro-bind', str(postgres), '/opt/postgresql']
        for key, value in DEFAULT_ENV.items(): args += ['--setenv', key, value]
        # 在沙箱内保持一个无业务逻辑的进程；命令通过 nsenter 单独进入。
        args += ['--chdir', '/workspace', '--', '/bin/sleep', str(limits['maxWorkspaceSeconds'])]
        return args

    def _ensure_sandbox(self, meta, policy):
        limits = _limits(policy)
        existing = self.sandboxes.get(meta['id'])
        if existing:
            if not Path('/proc/' + str(existing['pid']) + '/root/data/workspace').is_dir():
                meta.pop('livePath', None)
                raise ExecutionError('Sandbox expired or lost; workspace result unknown, do not replay')
            if existing['policyHash'] != hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest():
                raise ExecutionError('Policy changed; close and recreate the development workspace')
            return existing
        if not all(path.exists() for path in (NODE / 'bin/node', PYTHON / 'bin/python3', Path('/usr/bin/bwrap'), Path('/usr/bin/nsenter'), CACHE, NODE_NPM / 'bin/npm')):
            raise ExecutionError('Required isolated runtime unavailable; no host fallback')
        self.backend.dev_validate_tree(meta['id'], meta['profile'])
        unit = 'linux-mcp-dev-' + uuid.uuid4().hex[:24] + '.service'
        slice_name = 'linux-mcp-workspace-' + uuid.uuid4().hex[:24] + '.slice'
        record = {'workspaceId': meta['id'], 'unit': unit, 'slice': slice_name,
                  'policyHash': hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()}
        self.backend.atomic_json(self.registry / (meta['id'] + '.json'), record)
        args = ['/usr/bin/systemd-run', '--user', '--quiet', '--unit=' + unit, '--slice=' + slice_name,
                '-p', 'NoNewPrivileges=yes', '-p', 'MemoryMax=' + str(limits['maxMemoryBytes']),
                '-p', 'MemorySwapMax=0', '-p', 'TasksMax=' + str(limits['maxProcesses']),
                '-p', 'CPUQuota=' + str(limits['cpuQuotaPercent']) + '%', '-p', 'KillMode=control-group',
                '-p', 'KeyringMode=private',
                '-p', 'RuntimeMaxSec=' + str(limits['maxWorkspaceSeconds']), '-p', 'StandardOutput=null',
                '-p', 'StandardError=null', '--', *self._anchor_argv(limits)]
        try:
            result = _exec(args)
            if result.returncode: raise ExecutionError('Failed to create isolated sandbox unit')
            # Aggregate task/anchor resources are also capped by their private slice.
            capped = _exec(['/usr/bin/systemctl', '--user', 'set-property', '--runtime', slice_name,
                'MemoryMax=' + str(limits['maxMemoryBytes']), 'MemorySwapMax=0',
                'TasksMax=' + str(limits['maxProcesses']), 'CPUQuota=' + str(limits['cpuQuotaPercent']) + '%'])
            if capped.returncode: raise ExecutionError('Cannot enforce workspace cgroup limits')
            deadline = time.monotonic() + 10
            pid = None
            while time.monotonic() < deadline:
                result = _exec(['/usr/bin/systemctl', '--user', 'show', unit, '--property=MainPID', '--value'])
                parent = result.stdout.decode().strip()
                if parent.isdigit() and parent != '0':
                    children = Path('/proc/' + parent + '/task/' + parent + '/children')
                    if children.exists():
                        for child in children.read_text().split():
                            if Path('/proc/' + child + '/root/workspace').is_dir(): pid = int(child); break
                if pid is not None: break
                time.sleep(.05)
            if pid is None: raise ExecutionError('Sandbox namespace failed to initialize; no host fallback')
            live = Path('/proc/' + str(pid) + '/root/data/workspace')
            for path in Path(meta['path']).iterdir():
                target = live / path.name
                if path.is_symlink(): raise ExecutionError('Workspace contains a symbolic link')
                if path.is_dir(): shutil.copytree(path, target, symlinks=False)
                else: shutil.copy2(path, target)
            meta['livePath'] = str(live)
            record.update(pid=pid, startedAt=time.time(), limits=limits)
            self.sandboxes[meta['id']] = record
            self.backend.atomic_json(self.registry / (meta['id'] + '.json'), record)
            return record
        except Exception:
            self._stop_unit(unit)
            self._stop_slice(slice_name)
            meta.pop('livePath', None)
            (self.registry / (meta['id'] + '.json')).unlink(missing_ok=True)
            raise

    def _public(self, job, include_output=True):
        record = {k: job.get(k) for k in PUBLIC_FIELDS}
        inline = job.get('maxInlineBytes', 16384)
        for stream in ('stdout', 'stderr'):
            record[stream] = job.get(stream, '').encode()[:inline//2].decode('utf-8', 'ignore')
        if not include_output: record.pop('stdout', None); record.pop('stderr', None)
        record.update(id=record['taskId'], repairRound=job.get('repairRound', 0),
            capturedBytes=job.get('capturedBytes', 0), droppedBytes=job.get('droppedBytes', 0),
            capturedByStream=job.get('capturedByStream', {}), droppedByStream=job.get('droppedByStream', {}),
            outputComplete=job.get('outputComplete', False),pipeComplete=job.get('pipeComplete',False), truncationReason=job.get('truncationReason'),
            effectiveTimeout=job.get('effectiveTimeout'), terminationReason=job.get('terminationReason'),
            cgroupTerminated=job.get('cgroupTerminated'), elapsedSeconds=job.get('elapsedSeconds'),
            inlineTruncated=any(len(job.get(x, '').encode())>inline//2 for x in ('stdout','stderr')),
            outputCursors={x:len(job.get(x,'')) for x in ('stdout','stderr')},
            purpose=job.get('purpose','command'),failureClass=job.get('failureClass'),budget=self._budget_public(job),
            totalObservedBytes=(job.get('capturedBytes',0)+job.get('droppedBytes',0)) if job.get('outputComplete') else None,
            observedBytes=job.get('capturedBytes',0)+job.get('droppedBytes',0),persistedBytes=job.get('persistedBytes'),
            captureLimit=job.get('captureLimit'),persistLimit=job.get('persistLimit'),inlineLimit=inline,
            drainLimit=job.get('drainLimit'),timeoutEvidence=job.get('timeoutEvidence'),persistenceTruncated=job.get('persistenceTruncated',False))
        if 'resourceCounters' in job: record['resourceCounters'] = job['resourceCounters']
        return record

    def _budget_public(self,job):
        related=[j for j in list(self.jobs.values()) if j.get('budgetKey')==job.get('budgetKey')]
        if not job.get('budgetKey'):related=[j for j in list(self.jobs.values()) if j['workspaceId']==job['workspaceId']]
        used=len({j['repairId'] for j in related if j.get('purpose')=='repair' and j.get('repairId')})
        maximum=job.get('budget',{}).get('repairLimit')
        stopped=maximum is not None and used>=maximum
        return {'scope':'project-and-profile','repairUsed':used,'repairLimit':maximum,
            'remaining':max(0,maximum-used) if maximum is not None else None,'stopped':stopped,
            'allowedRecovery':['dev_task_status','dev_output','dev_cancel','dev_pty_close',
                'dev_execution_cleanup','dev_workspace_close','fixed_readonly_diagnostics','fixed_service_and_browser_close']}

    def run(self, profile, workspaceId, argv=None, shell=None, working_directory='.', env=None,
            timeout=60, requestId=None, background=False, purpose='command', repairId=None):
        return self._run(profile, workspaceId, argv, shell, working_directory, env, timeout, requestId,
                         background, False, purpose, repairId, False)

    def _budget_error(self, code, used, maximum):
        detail={'code':code,'classification':'budget','used':used,'limit':maximum,
            'remaining':max(0,maximum-used),'allowedRecovery':['dev_task_status','dev_output','dev_cancel',
                'dev_pty_close','dev_execution_cleanup','dev_workspace_close','fixed_service_and_browser_close']}
        raise ExecutionError(json.dumps(detail),code,'budget',detail)


    def _run(self, profile, workspaceId, argv, shell, working_directory, env, timeout, requestId,
             background, pty_mode, purpose='command', repairId=None, control=False):
        policy = self._policy(profile); limits = _limits(policy)
        allowed = {'command','expected-test','diagnostic','repair'} | ({'helper','cleanup'} if control else set())
        if purpose not in allowed: raise ExecutionError('Invalid command purpose; cleanup is internal only')
        cleanup = control and purpose == 'cleanup'
        if (purpose == 'repair') != (repairId is not None):
            raise ExecutionError('Explicit repair purpose requires a stable repairId; other purposes must omit it')
        if repairId is not None and (not isinstance(repairId,str) or not ID.fullmatch(repairId)):
            raise ExecutionError('Invalid stable repairId')
        if type(timeout) is not int or not 1 <= timeout <= limits['maxTimeoutSeconds']:
            raise ExecutionError('Timeout exceeds execution profile')
        if type(background) is not bool: raise ExecutionError('background must be boolean')
        command = _command(argv, shell); environment = _environment(env)
        if not isinstance(working_directory, str) or '\0' in working_directory:
            raise ExecutionError('Invalid working directory')
        cwd = Path(working_directory)
        if cwd.is_absolute() or '..' in cwd.parts: raise ExecutionError('Working directory must be workspace-relative')
        if requestId is None: requestId = uuid.uuid4().hex
        if not isinstance(requestId, str) or not ID.fullmatch(requestId): raise ExecutionError('Invalid stable requestId')
        request_key = workspaceId + ':' + requestId
        fingerprint = hashlib.sha256(json.dumps([profile, workspaceId, argv, shell, working_directory, env,
                                               timeout, pty_mode, purpose, repairId], sort_keys=True).encode()).hexdigest()
        with self.lock:
            meta = self.backend.dev_workspace(workspaceId, profile, allowExpired=cleanup)
            if request_key in self.requests:
                old = self.jobs[self.requests[request_key]]
                legacy=hashlib.sha256(json.dumps([profile,workspaceId,argv,shell,working_directory,env,timeout,pty_mode],sort_keys=True).encode()).hexdigest()
                if old['fingerprint']!=fingerprint and not (purpose=='command' and repairId is None and
                    'purpose' not in old and old['fingerprint']==legacy):
                    raise ExecutionError('requestId reused with different arguments')
                return self._public(old)
            if sum(j['status'] in LIVE for j in self.jobs.values()) >= limits['maxConcurrentTasks']:
                raise ExecutionError('Development task concurrency limit reached')
            if len(self.jobs) >= 512: raise ExecutionError('Persistent task ledger limit reached; local maintenance required')
            ledger_bytes = sum(len(j.get('stdout', '').encode()) + len(j.get('stderr', '').encode()) for j in self.jobs.values())
            if ledger_bytes >= 64 * 1024 ** 2: raise ExecutionError('Persistent execution output budget exhausted')
            budget_key=profile+':'+str(meta.get('source') or meta.get('project') or meta['path'])
            related=[j for j in self.jobs.values() if j.get('budgetKey')==budget_key or
                     (not j.get('budgetKey') and j['workspaceId']==workspaceId)]
            spent=sum((time.monotonic()-j['monotonicStart']) if j['status'] in LIVE and j.get('thread')
                      else (j.get('elapsedSeconds') or 0) for j in related)
            readonly_diagnostic=control and purpose=='diagnostic'
            reserved=sum(j.get('effectiveTimeout',0) for j in related if j['status'] in LIVE)
            completed_spent=sum(j.get('elapsedSeconds') or 0 for j in related if j['status'] not in LIVE)
            if completed_spent + reserved + timeout > limits['maxWallSeconds'] and not cleanup:
                self._budget_error('execution_time_budget_exhausted',spent,limits['maxWallSeconds'])
            repair_ids={j['repairId'] for j in related if j.get('purpose')=='repair' and j.get('repairId')}
            used=len(repair_ids); maximum=policy.get('limits',{}).get('maxRepairRounds',5)
            if type(maximum) is not int or not 1<=maximum<=100: raise ExecutionError('Invalid repair round limit')
            if purpose=='repair' and repairId in repair_ids:
                raise ExecutionError('repairId already bound to a task; query its requestId instead of starting another attempt')
            if purpose=='repair' and used>=maximum:
                self._budget_error('repair_budget_exhausted',used,maximum)
            if used>=maximum and not (cleanup or readonly_diagnostic):
                self._budget_error('repair_budget_exhausted',used,maximum)
            if any(j['status'] in {'blocked','unknown','termination_failed'} for j in related) and not (cleanup or readonly_diagnostic):
                raise ExecutionError('Workspace stopped after a safety failure or unknown result; use registered cleanup')
            self.backend.dev_validate_tree(workspaceId, profile, allowExpired=cleanup)
            tree_hash = _tree_hash(Path(meta.get('livePath') or meta['path']))
            command_hash=hashlib.sha256(json.dumps([argv,shell,working_directory,env],sort_keys=True).encode()).hexdigest()
            failures=[j for j in related if j.get('status') in {'failed','timeout','output_limit'} and
                      j.get('commandHash')==command_hash and j.get('treeHash')==tree_hash]
            max_repeated=policy.get('limits',{}).get('maxRepeatedFailures',3)
            if type(max_repeated) is not int or not 1<=max_repeated<=100: raise ExecutionError('Invalid repeated failure limit')
            if len(failures)>=max_repeated and not cleanup:
                self._budget_error('repeated_failure_stop',len(failures),max_repeated)
            sandbox = self._ensure_sandbox(meta, policy)
            cwd_host = Path(meta['livePath']) / cwd; cursor = Path(meta['livePath'])
            for part in cwd.parts:
                cursor = cursor / part
                if cursor.is_symlink(): raise ExecutionError('Working directory symbolic link refused')
            if not cwd_host.is_dir(): raise ExecutionError('Working directory does not exist')
            task_id = 'dev-' + uuid.uuid4().hex; unit = 'linux-mcp-dev-' + uuid.uuid4().hex[:24] + '.service'
            job = {'taskId':task_id,'requestId':requestId,'requestKey':request_key,'fingerprint':fingerprint,
                   'workspaceId':workspaceId,'profile':profile,'unit':unit,'status':'queued','exitCode':None,
                   'unknown':False,'stdout':'','stderr':'','truncated':False,'startedAt':time.time(),
                   'finishedAt':None,'artifactsPath':'.dev-artifacts/'+task_id,'pty':pty_mode,'slice':sandbox['slice'],
                   'cancelRequested':False,'outputBytes':0,'stopEvent':threading.Event(), 'purpose':purpose,
                   'budgetKey':budget_key,'repairId':repairId,'repairRound':used+(purpose=='repair' and repairId not in repair_ids),
                   'commandHash':command_hash,'treeHash':tree_hash,'effectiveTimeout':timeout,
                   'capturedBytes':0,'droppedBytes':0,'capturedByStream':{'stdout':0,'stderr':0},
                   'droppedByStream':{'stdout':0,'stderr':0},'outputComplete':False,'terminationReason':None,
                   'cgroupTerminated':None,'elapsedSeconds':None,'maxInlineBytes':limits['maxInlineBytes'],'captureLimit':limits['maxCapturedBytes'],
                   'persistLimit':limits['maxPersistedBytes'],'drainLimit':limits['maxDrainBytes'],
                   'budget':{'repairUsed':used+(purpose=='repair' and repairId not in repair_ids),'repairLimit':maximum},
                   'monotonicStart':time.monotonic()}
            self.jobs[task_id]=job; self.requests[request_key]=task_id
            # requestId 和修复轮次在启动有副作用的子进程之前同一任务记录持久化。
            self._save(job); self._audit('dev_task_start',task_id,'queued')
            enter=['/usr/bin/nsenter','--target',str(sandbox['pid']),'--preserve-credentials',
                   '--user','--mount','--net','--pid','--ipc','--uts','--','/usr/bin/env','-i']
            enter += [key+'='+value for key,value in environment.items()]
            enter += ['/usr/bin/python3','-c','import os,sys;os.chdir(sys.argv[1]);os.execvpe(sys.argv[2],sys.argv[2:],os.environ)',
                      '/workspace/'+cwd.as_posix(),*command]
            args=['/usr/bin/systemd-run','--user','--quiet','--pipe','--wait','--collect','--unit='+unit,
                  '--slice='+sandbox['slice'],'-p','NoNewPrivileges=yes','-p','KillMode=control-group',
                  '-p','KeyringMode=private','-p','RuntimeMaxSec='+str(timeout),'-p','TimeoutStopSec=2','--',*enter]
            thread=threading.Thread(target=self._worker,args=(job,args,timeout,limits,meta),daemon=True)
            job['thread']=thread; thread.start()
        if not background: thread.join(2)
        return self._public(job)

    def _supervise(self, job):
        # 时钟起点是请求持久登记前，包含排队及启动；不依赖采集线程推进。
        deadline=job['monotonicStart']+job['effectiveTimeout']
        while not job['stopEvent'].wait(.05):
            if job['cancelRequested'] or time.monotonic()>=deadline:
                reason='cancelled' if job['cancelRequested'] else 'timeout'
                job.update(status='terminating',terminationReason=reason)
                confirmed=self._stop_unit(job['unit'])
                job['cgroupTerminated']=confirmed
                if not confirmed:
                    job.update(status='termination_failed',unknown=True)
                with self.lock:self._save(job)
                return

    def _consume(self, job, stream, chunk, limits):
        state=job['_streams'][stream]
        room=limits['maxCapturedBytes']-job['capturedBytes']
        accepted=chunk[:max(0,room)]
        job['capturedBytes']+=len(accepted);job['capturedByStream'][stream]+=len(accepted)
        dropped=len(chunk)-len(accepted)
        job['droppedBytes']+=dropped;job['droppedByStream'][stream]+=dropped
        if dropped:
            job.update(truncated=True,truncationReason='capture_limit')
        if not accepted or state['sensitive']:return
        text=state['decoder'].decode(accepted,False)
        state['pending']+=text
        # 实时输出只发布完整且没有凭据标记的行。
        # 单行和带标记的后续内容留在有上限的采集缓冲，防止跨块凭据先被发布。
        if not state.get('held'):
            while '\n' in state['pending']:
                line,tail=state['pending'].split('\n',1)
                if _credential_marker(line):
                    state['held']=True
                    break
                job[stream]+=line+'\n';state['pending']=tail

    def _worker(self, job, args, timeout, limits, meta):
        proc=None; master=None; slave=None;final_status=None;selector=selectors.DefaultSelector()
        job['_streams']={x:{'decoder':codecs.getincrementaldecoder('utf-8')('replace'),
                           'pending':'','sensitive':False} for x in ('stdout','stderr')}
        supervisor=threading.Thread(target=self._supervise,args=(job,),daemon=True)
        job['supervisor']=supervisor;supervisor.start()
        forced_close=False
        try:
            environment={'PATH':'/usr/bin:/bin','XDG_RUNTIME_DIR':'/run/user/'+str(os.getuid()),
                         'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/'+str(os.getuid())+'/bus'}
            if job['pty']:
                master,slave=pty.openpty();attributes=termios.tcgetattr(slave)
                attributes[3]&=~(termios.ECHO|termios.ECHONL);termios.tcsetattr(slave,termios.TCSANOW,attributes)
                proc=subprocess.Popen(args,stdin=slave,stdout=slave,stderr=slave,env=environment,close_fds=True,start_new_session=True)
                os.close(slave);slave=None;selector.register(master,selectors.EVENT_READ,'stdout');job['ptyFd']=master
            else:
                proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                      env=environment,close_fds=True,start_new_session=True)
                selector.register(proc.stdout,selectors.EVENT_READ,'stdout');selector.register(proc.stderr,selectors.EVENT_READ,'stderr')
            with self.lock:
                job['process']=proc
                if job['status']=='queued':job['status']='running'
                self._save(job)
            termination_started=None
            while selector.get_map() or proc.poll() is None:
                if job['terminationReason'] and termination_started is None:termination_started=time.monotonic()
                if termination_started is not None and time.monotonic()-termination_started>8:
                    forced_close=True
                    if proc.poll() is None:proc.kill()
                    break
                for key,_ in selector.select(.05):
                    descriptor=key.fileobj if type(key.fileobj) is int else key.fileobj.fileno()
                    try:chunk=os.read(descriptor,65536)
                    except OSError:chunk=b''
                    if not chunk:selector.unregister(key.fileobj);continue
                    self._consume(job,key.data,chunk,limits)
                    if job['capturedBytes']+job['droppedBytes']>limits['maxDrainBytes'] and not job['terminationReason']:
                        job.update(terminationReason='output_limit',status='terminating',truncationReason='drain_limit',truncated=True)
                        job['cgroupTerminated']=self._stop_unit(job['unit'])
                if proc.poll() is not None and not selector.get_map():break
            if proc.poll() is None:
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)
            # systemd 的独立计时可能先于 Python 监督线程完成停止。
            if job['cancelRequested']:job['terminationReason']='cancelled'
            if proc.returncode!=0 and not job['terminationReason'] and \
                time.monotonic()-job['monotonicStart']>=timeout:
                job['terminationReason']='timeout'
                job['timeoutEvidence']='nonzero exit after effective monotonic deadline'
            job['stopEvent'].set();supervisor.join(6)
            for stream,state in job['_streams'].items():
                if not state['sensitive']:
                    state['pending']+=state['decoder'].decode(b'',True)
                    combined=job[stream]+state['pending']
                    sanitized=safe_output(combined)
                    if job['droppedBytes'] and _credential_marker(state['pending']):
                        sanitized='[REDACTED: incomplete possible credential content]'
                    if sanitized!=combined:job['sensitiveOutput']=True
                    job[stream]=sanitized
            if job.get('cgroupTerminated') is None:job['cgroupTerminated']=self._stop_unit(job['unit'])
            if not job['cgroupTerminated']:job.update(status='termination_failed',unknown=True)
            job.update(exitCode=proc.returncode,pipeComplete=not forced_close,
                       outputComplete=not forced_close and not job['terminationReason'] and not job['cancelRequested'],
                       elapsedSeconds=time.monotonic()-job['monotonicStart'])
            if job.get('status')!='termination_failed':
                if job['terminationReason']:job['status']=job['terminationReason']
                elif job['cancelRequested']:job['status']='cancelled'
                else:job['status']='succeeded' if proc.returncode==0 else 'failed'
            if job['status']=='failed' and not job['stderr']:
                job['resourceCounters']=self._resource_counters(job['slice'])
                job['stderr']='Isolated command failed without diagnostic output; inspect resourceCounters.'
            # 结果状态与输出完整性独立；安全检查失败禁止导出，但不重放命令。
            final_status=job['status'];job['status']='finalizing'
            try:self.backend.dev_validate_tree(meta['id'],meta['profile'],allowExpired=True)
            except (OSError,ValueError):
                final_status='blocked';job.update(stdout='',stderr='Workspace validation failed; output withheld')
            if job.get('interrupted'):final_status='unknown';job['unknown']=True
        except Exception:
            job.update(status='unknown' if proc else 'failed',unknown=bool(proc),
                       stderr='Isolated execution unavailable; no host fallback')
            job['cgroupTerminated']=self._stop_unit(job['unit'])
        finally:
            job['stopEvent'].set();supervisor.join(6);selector.close()
            if proc is not None and not job['pty']:
                if proc.stdout is not None:proc.stdout.close()
                if proc.stderr is not None:proc.stderr.close()
            for fd in (master,slave):
                if fd is not None:
                    try:os.close(fd)
                    except OSError:pass
            job.pop('ptyFd',None);job.pop('process',None)
            job['finishedAt']=time.time();job['elapsedSeconds']=time.monotonic()-job['monotonicStart']
            if final_status is not None:job['status']=final_status
            if job.get('interrupted'):job.update(status='unknown',unknown=True)
            status=job['status']
            job['failureClass']=(None if status=='succeeded' else
                'security' if status=='blocked' else 'infrastructure' if status in {'unknown','termination_failed'} else
                status if status in {'timeout','cancelled','output_limit'} else
                'expected-test' if job['purpose']=='expected-test' else 'repair' if job['purpose']=='repair' else
                'helper' if job['purpose'] in {'helper','diagnostic','cleanup'} else 'ordinary-failure')
            try:self._write_artifacts(meta,job,limits)
            except (OSError,ValueError):job['artifactsUnavailable']=True
            with self.lock:self._save(job)
            self._audit('dev_task_end',job['taskId'],job['status'])

    def _write_artifacts(self, meta, job, limits=None):
        """所有目录都通过 no-follow 的目录句柄创建，不能沿后台链接访问宿主机。"""
        root = Path(meta['livePath'])
        # 采集结束后已对有上限的完整输出执行共享敏感检测。
        descriptor = open_components(root, '.', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in Path(job['artifactsPath']).parts:
                try: os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError: pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor); descriptor = child
            persistence=(limits or {}).get('maxPersistedBytes',1048576)
            left=persistence;persisted={}
            for stream in ('stdout','stderr'):
                raw=job[stream].encode();kept=raw[:left];left-=len(kept)
                persisted[stream]=kept.decode('utf-8','ignore')
                if len(kept)<len(raw):job['persistenceTruncated']=True
            job['persistedBytes']=sum(len(value.encode()) for value in persisted.values())
            values = {'stdout.txt': persisted['stdout'], 'stderr.txt': persisted['stderr'],
                      'result.json': json.dumps(self._public(job, include_output=False), ensure_ascii=False)}
            for name, value in values.items():
                temporary = '.result-' + uuid.uuid4().hex
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(value.encode()); stream.flush(); os.fsync(stream.fileno())
                    os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
                finally:
                    try: os.unlink(temporary, dir_fd=descriptor)
                    except FileNotFoundError: pass
        finally: os.close(descriptor)

    def _resource_counters(self, name):
        if not re.fullmatch(r'linux-mcp-workspace-[a-f0-9]{24}\.slice', name): return {}
        result = _exec(['/usr/bin/systemctl', '--user', 'show', name, '--property=ControlGroup', '--value'])
        location = result.stdout.decode().strip()
        if not location.startswith('/user.slice/'): return {}
        root = Path('/sys/fs/cgroup' + location)
        counters = {}
        for filename in ('pids.current', 'pids.max', 'pids.events', 'memory.current', 'memory.max', 'memory.events'):
            try: counters[filename] = (root / filename).read_text().strip()
            except OSError: pass
        return counters

    def _authorized_job(self, taskId):
        if not isinstance(taskId, str) or taskId not in self.jobs: raise ExecutionError('Unknown development task')
        job = self.jobs[taskId]
        self._policy(job['profile'])
        self.backend.dev_workspace(job['workspaceId'], job['profile'], allowExpired=True)
        return job

    def status(self, taskId=None, requestId=None, workspaceId=None, profile='autonomous-development'):
        if taskId is None:
            if not isinstance(requestId,str) or not isinstance(workspaceId,str):
                raise ExecutionError('Use taskId or stable requestId with workspaceId')
            self._policy(profile)
            taskId=self.requests.get(workspaceId+':'+requestId)
            if taskId is None:raise ExecutionError('Unknown stable requestId; no task was registered')
        return self._public(self._authorized_job(taskId))

    def output(self, taskId, stream='stdout', offset=0, limit=65536):
        job = self._authorized_job(taskId)
        if stream not in {'stdout', 'stderr'} or type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 131072:
            raise ExecutionError('Invalid output pagination')
        text = job[stream]
        return {'taskId': taskId, 'stream': stream, 'data': text[offset:offset + limit], 'text':text[offset:offset + limit],
                'nextOffset': min(len(text), offset + limit), 'complete': job['status'] not in LIVE,
                'truncated': job['truncated'], 'status': job['status'], 'outputComplete':job.get('outputComplete',False),
                'capturedBytes':job.get('capturedByStream',{}).get(stream),'droppedBytes':job.get('droppedByStream',{}).get(stream),
                'truncationReason':job.get('truncationReason')}

    def cancel(self, taskId):
        job = self._authorized_job(taskId)
        if job['status'] in LIVE:
            job['cancelRequested'] = True
            self._stop_unit(job['unit'])
        return self._public(job)

    def pty_open(self, profile, workspaceId, argv=None, shell=None, working_directory='.', env=None, timeout=600, requestId=None):
        # 输入必须显式提供 argv 或 shell；不会自动进入宿主 shell。
        return self._run(profile, workspaceId, argv, shell, working_directory, env, timeout, requestId, True, True)

    def pty_input(self, taskId, data):
        job = self._authorized_job(taskId)
        if not job['pty'] or job['status'] not in LIVE or 'ptyFd' not in job:
            raise ExecutionError('PTY session not available')
        if not isinstance(data, str) or len(data.encode()) > 16384 or '\0' in data:
            raise ExecutionError('Invalid PTY input')
        if safe_output(data) != data or SECRET_ENV.search(data):
            raise ExecutionError('Secret-bearing PTY input denied')
        # 不保存交互输入，也不将其写入审计记录。
        os.write(job['ptyFd'], data.encode())
        return {'taskId': taskId, 'acceptedBytes': len(data.encode())}

    def pty_close(self, taskId):
        return self.cancel(taskId)

    def internal(self, profile, workspaceId, argv=None, shell=None, env=None, timeout=60, background=False, working_directory='.', requestId=None, purpose='helper', control=False):
        if purpose=='cleanup' and not control:raise ExecutionError('Cleanup helper must be a fixed registered control action')
        return self._run(profile, workspaceId, argv, shell, working_directory, env, timeout, requestId,
                         background, False, purpose, None, True)

    def close_workspace(self, workspaceId, profile='autonomous-development', preserve=True):
        self._policy(profile)
        meta = self.backend.dev_workspace(workspaceId, profile, allowExpired=True)
        for job in self.jobs.values():
            if job['workspaceId'] == workspaceId and job['status'] in LIVE:
                job['cancelRequested'] = True; self._stop_unit(job['unit'])
        for job in self.jobs.values():
            if job['workspaceId'] == workspaceId:
                thread = job.get('thread')
                if thread is not None and thread is not threading.current_thread(): thread.join(30)
                if thread is not None and thread.is_alive():
                    raise ExecutionError('Task cleanup has not completed; workspace preservation refused')
        sandbox = self.sandboxes.get(workspaceId)
        if not sandbox: return {'workspaceId': workspaceId, 'closed': True, 'preserved': False}
        try:
            if preserve:
                self.backend.dev_validate_tree(workspaceId, profile, allowExpired=True)
                live = Path(meta['livePath']); persisted = Path(meta['path'])
                candidate = persisted.parent / ('persist-' + uuid.uuid4().hex)
                shutil.copytree(live, candidate, symlinks=False)
                backup = persisted.parent / ('previous-' + uuid.uuid4().hex)
                os.rename(persisted, backup)
                os.rename(candidate, persisted)
                shutil.rmtree(backup)
            return {'workspaceId': workspaceId, 'closed': True, 'preserved': bool(preserve)}
        finally:
            self._stop_unit(sandbox['unit']); self.sandboxes.pop(workspaceId, None)
            self._stop_slice(sandbox['slice'])
            meta.pop('livePath', None)
            (self.registry / (workspaceId + '.json')).unlink(missing_ok=True)

    def shutdown(self):
        for job in list(self.jobs.values()):
            if job['status'] in LIVE:
                job['interrupted']=True
                self._stop_unit(job.get('unit'))
                job.update(status='unknown', unknown=True, finishedAt=time.time())
                try: self._save(job)
                except OSError: pass
        for workspaceId in list(self.sandboxes):
            try: self.close_workspace(workspaceId)
            except Exception:
                self._stop_unit(self.sandboxes.get(workspaceId, {}).get('unit'))


def attach_execution(cls):
    previous = cls.__init__
    def initialize(self, config_path):
        previous(self, config_path)
        self.dev_executor = Execution(self)
    def dev_run(self, profile, workspaceId, argv=None, shell=None, working_directory='.', env=None, timeout=60, requestId=None, background=False, purpose='command', repairId=None):
        return self.dev_executor.run(profile, workspaceId, argv, shell, working_directory, env, timeout, requestId, background,purpose,repairId)
    def dev_task_status(self, taskId=None, requestId=None, workspaceId=None, profile='autonomous-development'): return self.dev_executor.status(taskId,requestId,workspaceId,profile)
    def dev_output(self, taskId, stream='stdout', offset=0, limit=65536): return self.dev_executor.output(taskId, stream, offset, limit)
    def dev_cancel(self, taskId): return self.dev_executor.cancel(taskId)
    def dev_pty_open(self, profile, workspaceId, argv=None, shell=None, working_directory='.', env=None, timeout=600, requestId=None):
        return self.dev_executor.pty_open(profile, workspaceId, argv, shell, working_directory, env, timeout, requestId)
    def dev_pty_input(self, taskId, data): return self.dev_executor.pty_input(taskId, data)
    def dev_pty_close(self, taskId): return self.dev_executor.pty_close(taskId)
    def dev_exec_internal(self, profile, workspaceId, argv=None, shell=None, env=None, timeout=60, background=False, working_directory='.', requestId=None, purpose='helper', control=False):
        return self.dev_executor.internal(profile, workspaceId, argv, shell, env, timeout, background, working_directory, requestId,purpose,control)
    def dev_execution_cleanup(self, workspaceId, profile='autonomous-development'):
        return self.dev_executor.close_workspace(workspaceId, profile)
    cls.__init__ = initialize
    for fn in (dev_run, dev_task_status, dev_output, dev_cancel, dev_pty_open, dev_pty_input, dev_pty_close,
               dev_exec_internal, dev_execution_cleanup): setattr(cls, fn.__name__, fn)
    return cls


TOOL_DESCRIPTIONS = {
    'dev_run': '隔离执行 argv 或显式 shell；同步最多等两秒。长任务返回 taskId，requestId 持久去重。仅显式 repair 加 repairId 消耗修复轮次。',
    'dev_task_status': '通过 taskId，或 requestId 加 workspaceId 查询持久任务。只有 succeeded 才是成功；unknown 不能重放。',
    'dev_output': '分页读取安全 stdout/stderr；单行或含敏感标记输出等结束后检测，返回采集、丢弃及完整性信息。',
    'dev_cancel': '停止指定任务独立 cgroup，不影响其他任务或宿主服务。',
    'dev_pty_open': '在同一个隔离开发副本中创建有时限的 PTY。',
    'dev_pty_input': '向隔离 PTY 写入普通输入，凭据输入被拒绝，输入不会保存。',
    'dev_pty_close': '关闭隔离 PTY 并停止其子进程。',
    'dev_execution_cleanup': '停止副本内全部任务，验证并保留副本文件，销毁隔离网络和临时资源。'}


def _schema(properties, required):
    return {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}

BASE = {'profile': {'type': 'string'}, 'workspaceId': {'type': 'string'},
        'argv': {'type': ['array', 'null'], 'minItems': 1, 'maxItems': 128, 'items': {'type': 'string'}},
        'shell': {'type': ['string', 'null'], 'maxLength': 131072}, 'working_directory': {'type': 'string', 'default': '.'},
        'env': {'type': ['object', 'null'], 'additionalProperties': {'type': 'string'}, 'maxProperties': 32},
        'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600, 'default': 60},
        'requestId': {'type': ['string', 'null'], 'pattern': '^[A-Za-z0-9_-]{1,100}$'}}
TOOL_SCHEMAS = {'dev_run': _schema({**BASE, 'background': {'type': 'boolean', 'default': False},
        'purpose':{'type':'string','enum':['command','expected-test','diagnostic','repair'],'default':'command'},
        'repairId':{'type':['string','null'],'pattern':'^[A-Za-z0-9_-]{1,100}$'}}, ['profile', 'workspaceId']),
    'dev_task_status': _schema({'taskId':{'type':['string','null']}, 'requestId':{'type':['string','null']},
        'workspaceId':{'type':['string','null']},'profile':{'type':'string','default':'autonomous-development'}}, []),
    'dev_output': _schema({'taskId': {'type': 'string'}, 'stream': {'type': 'string', 'enum': ['stdout', 'stderr'], 'default': 'stdout'},
                          'offset': {'type': 'integer', 'minimum': 0, 'default': 0},
                          'limit': {'type': 'integer', 'minimum': 1, 'maximum': 131072, 'default': 65536}}, ['taskId']),
    'dev_cancel': _schema({'taskId': {'type': 'string'}}, ['taskId']),
    'dev_pty_open': _schema({**BASE, 'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600, 'default': 600}}, ['profile', 'workspaceId']),
    'dev_pty_input': _schema({'taskId': {'type': 'string'}, 'data': {'type': 'string', 'maxLength': 16384}}, ['taskId', 'data']),
    'dev_pty_close': _schema({'taskId': {'type': 'string'}}, ['taskId']),
    'dev_execution_cleanup': _schema({'workspaceId': {'type': 'string'}, 'profile': {'type': 'string', 'default': 'autonomous-development'}}, ['workspaceId'])}
