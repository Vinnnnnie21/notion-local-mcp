"""Bounded basic usability additions. No arbitrary shell, approval, or deployment tools."""
import ast
import json
import os
import re
import subprocess
import time
import tomllib
from pathlib import Path

DEFAULT_DENY_DIRS = ('credentials', 'secrets')

def attach_backend(cls):
    original_init = cls.__init__
    original_allowed = cls.allowed
    original_plan_git = cls.plan_git
    original_apply_git = cls.apply_git
    original_references = cls.find_references

    def initialize(self, config_path):
        original_init(self, config_path)
        for spec in self.projects.values():
            values = spec.get('denyDirs', list(DEFAULT_DENY_DIRS))
            if not isinstance(values, list) or len(values) > 100:
                raise ValueError('denyDirs must be a bounded list of relative directory paths')
            normalized = []
            for value in values:
                if not isinstance(value, str) or not value or len(value)>2048:
                    raise ValueError('Invalid denyDirs path')
                path = Path(value)
                if path.is_absolute() or any(part in ('','.','..') for part in value.split('/')) or '\\' in value or any(c in value for c in '*?['):
                    raise ValueError('denyDirs requires exact project-relative paths, not globs')
                normalized.append(path.as_posix())
            spec['denyDirs'] = sorted(set(normalized))

    def allowed(self, project, rel, write=False):
        target = original_allowed(self, project, rel, write=write)
        normal = Path(rel).as_posix().casefold()
        for directory in self.project(project)['denyDirs']:
            directory = directory.casefold()
            if normal == directory or normal.startswith(directory + '/'):
                raise ValueError('Explicitly excluded project directory')
        return target

    def audit_event(self, tool, status, project=None, paths=None):
        record = {'time':time.time(), 'tool':tool, 'status':status, 'project':project}
        if paths is not None:
            accessible = []
            for path in paths[:50]:
                try:
                    self.allowed(project, path)
                except (ValueError, TypeError, OSError):
                    continue
                if path not in accessible:
                    accessible.append(path)
            record['paths'] = accessible
        self.audit.info(json.dumps(record, ensure_ascii=False))

    def get_capabilities(self, project=None):
        projects = [project] if project is not None else list(self.projects)
        permissions = []
        for name in projects:
            spec=self.project(name)
            permissions.append({'project':name,'write':bool(spec.get('write')),
                'writeAllow':spec.get('writeAllow',[]),'gitWrite':bool(spec.get('gitWrite')),
                'tasks':sorted(spec.get('tasks',{})), 'denyDirs':spec['denyDirs'],
                'broadHomeReadOnly':spec['root']==Path.home()})
        return {'version':self.health()['version'], 'projects':permissions,
            'features':{'pythonDefinitions':'AST', 'pythonReferences':'AST name/attribute occurrences; not cross-module semantic resolution',
                'jsTsSymbols':'heuristic','incrementalIndex':'hash-cache; still scans files',
                'projectSummary':'bounded manifest/import parsing; never executes project code',
                'multiFilePreview':True,'snapshots':True,'conflictChecks':'hash-based, not filesystem CAS',
                'multiFileAtomic':False,'automaticRollback':False,'auditFilePaths':True,
                'gitBranches':True,'gitStage':'local approval required','gitMerge':'fast-forward only',
                'gitPush':'allowlisted HTTPS; local approval required','arbitraryShell':False,
                'tasks':'fixed argv, digest-pinned rootless Docker, local approval required',
                'logs':'cursor polling and best-effort redaction','documents':['csv','tsv','pdf_text','image_preview'],
                'ocr':False,'automaticTaskAuthorization':False},
            'limits':{'fileBytes':2*1024*1024,'taskWorkspaceBytes':32*1024*1024,
                'taskOutputBytes':128*1024,'maxTaskSeconds':600,'maxConcurrentTasks':2},
            'deploymentNote':'Use get_service_status for actual startup state; a template is not a configured tunnel.'}

    def git_branches(self, project, limit=100):
        if type(limit) is not int or not 1<=limit<=200: raise ValueError('limit must be 1..200')
        raw=self.git_call(project,['for-each-ref','--count='+str(limit+1),
            '--format=%(refname)\t%(objectname)\t%(HEAD)','refs/heads','refs/remotes'])
        rows=[]
        for line in raw.splitlines():
            parts=line.split('\t')
            if len(parts)!=3: continue
            ref, commit, current=parts
            rows.append({'ref':ref,'commit':commit,'current':current.strip()=='*',
                'kind':'remote' if ref.startswith('refs/remotes/') else 'local'})
        return {'branches':rows[:limit], 'truncated':len(rows)>limit}

    def git_staged_paths(self, project):
        raw=self.git_call(project,['diff','--cached','--name-only','-z'])
        paths=[]
        for path in raw.split('\0'):
            if not path: continue
            try: self.allowed(project,path)
            except ValueError: continue
            paths.append(path)
        return {'paths':paths, 'scope':'accessible staged paths only'}

    def plan_git(self, project, operation, branch=None, message=None, paths=None, remote=None):
        if operation not in {'stage','commit_staged'}:
            return original_plan_git(self,project,operation,branch,message,paths,remote)
        spec=self.project(project)
        if not spec.get('gitWrite'): raise ValueError('Git mutations disabled by operator configuration')
        if branch is not None or remote is not None or (operation=='stage' and message is not None):
            raise ValueError('Invalid arguments for managed staging/commit')
        if operation=='commit_staged' and (not isinstance(message,str) or not message or len(message)>1000):
            raise ValueError('commit_staged requires a bounded commit message')
        if not isinstance(paths,list) or not 1<=len(paths)<=50 or len(set(paths))!=len(paths):
            raise ValueError('stage requires 1..50 unique explicit paths')
        hashes={}
        for path in paths:
            self.allowed(project,path,write=True)
            hashes[path]=self.get_file_hash(project,path)['sha256']
        staged=[p for p in self.git_call(project,['diff','--cached','--name-only','-z']).split('\0') if p]
        if operation=='stage' and staged:
            raise ValueError('Index must be empty before managed staging')
        if operation=='commit_staged' and set(staged)!=set(paths):
            raise ValueError('Explicit paths must exactly match the staged index')
        payload={'operation':operation,'hashes':hashes,
                 'head':self.git_call(project,['rev-parse','HEAD']).strip()}
        if operation=='commit_staged':
            payload['message']=message
            payload['indexObjects']={p:self.git_call(project,['rev-parse','--verify',':'+p]).strip() for p in paths}
        return self.approval('git',project,payload,payload)

    def apply_git(self, approvalId):
        with self.lock:
            record=self.load_approval(approvalId)
            if record['kind']!='git': raise ValueError('Not a Git approval')
            data=record['payload']; project=record['project']
            if data['operation'] not in {'stage','commit_staged'}:
                result=original_apply_git(self,approvalId)
                self.audit_event('apply_git','ok',project,paths=list(data.get('hashes',{})))
                return result
            if not self.project(project).get('gitWrite'): raise ValueError('Git writes not enabled')
            if self.git_call(project,['rev-parse','HEAD']).strip()!=data['head']:
                raise ValueError('HEAD changed after preview')
            staged=[p for p in self.git_call(project,['diff','--cached','--name-only','-z']).split('\0') if p]
            if data['operation']=='stage' and staged:
                raise ValueError('Git index changed after preview')
            if data['operation']=='commit_staged':
                if set(staged)!=set(data['hashes']): raise ValueError('Git index paths changed after preview')
                for p,oid in data['indexObjects'].items():
                    if self.git_call(project,['rev-parse','--verify',':'+p]).strip()!=oid:
                        raise ValueError('Staged content changed after preview')
            for path, expected in data['hashes'].items():
                self.allowed(project,path,write=True)
                if self.get_file_hash(project,path)['sha256']!=expected:
                    raise ValueError('File changed after preview')
            self.load_approval(approvalId,consume=True)
            try:
                if data['operation']=='stage':
                    self.git_call(project,['add','--',*data['hashes']])
                else:
                    self.git_call(project,['commit','-m',data['message']])
            except Exception:
                self.audit_event('apply_git','error',project,paths=list(data['hashes']))
                raise
            self.audit_event('apply_git','ok',project,paths=list(data['hashes']))
            return {'applied':True,'operation':data['operation'],'paths':list(data['hashes']),
                'warning':'Git operations are not transactional. Use commit_staged with exactly the staged paths to commit an approved index.'}

    def find_references(self, project, symbol, path='.', limit=50, mode='literal'):
        if mode=='literal': return original_references(self,project,symbol,path,limit)
        if mode!='python_ast' or not symbol.isidentifier():
            raise ValueError('Use literal or python_ast mode with a Python identifier')
        if type(limit) is not int or not 1<=limit<=200: raise ValueError('limit must be 1..200')
        files,incomplete=self.walk(project,path)
        results=[]; skipped=0; total=0; deadline=time.monotonic()+5
        for rel in files:
            if not rel.endswith('.py'): continue
            if time.monotonic()>deadline or total>=32*1024*1024: incomplete=True; break
            try:
                raw,_=self.read(project,rel); total+=len(raw); tree=ast.parse(raw.decode('utf-8'))
            except (ValueError,OSError,UnicodeError,SyntaxError): skipped+=1; continue
            nodes=sorted(ast.walk(tree),key=lambda n:(getattr(n,'lineno',0),getattr(n,'col_offset',0)))
            for node in nodes:
                kind=None
                if isinstance(node,ast.Name) and node.id==symbol:
                    kind='name_load' if isinstance(node.ctx,ast.Load) else 'name_binding'
                elif isinstance(node,ast.Attribute) and node.attr==symbol: kind='attribute_name_only'
                elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and node.name==symbol: kind='definition'
                if kind:
                    results.append({'path':rel,'line':node.lineno,'column':node.col_offset,
                                    'kind':kind,'symbol':symbol})
                    if len(results)>=limit:
                        return {'results':results,'scanComplete':False,'truncated':True,'skippedFiles':skipped,
                            'method':'Python AST occurrences; excludes comments/strings; not cross-module semantic resolution'}
        return {'results':results,'scanComplete':not incomplete,'truncated':False,'skippedFiles':skipped,
            'method':'Python AST occurrences; excludes comments/strings; not cross-module semantic resolution'}

    def project_summary(self, project):
        top=self.list_directory(project,limit=100)
        files,incomplete=self.walk(project)
        dependencies=set(); entries={}; manifests=[]; modules=[]; tests=[]; problems=[]
        total=0; deadline=time.monotonic()+5
        names={row['name'] for row in top['entries']}
        def dep(value):
            if not isinstance(value,str): return
            value=value.strip()
            if value.startswith(('#','-')) or '://' in value and '@' not in value: return
            match=re.match(r'^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s|\[|[<>=!~;@]|$)',value)
            if match: dependencies.add(match.group(1))
        for name in ('pyproject.toml','requirements.txt','package.json','Cargo.toml','go.mod','Makefile'):
            if name not in names: continue
            try:
                raw,_=self.read(project,name); total+=len(raw); manifests.append(name)
                if name=='pyproject.toml':
                    data=tomllib.loads(raw.decode())
                    project_data=data.get('project',{})
                    for value in project_data.get('dependencies',[]): dep(value)
                    for values in project_data.get('optional-dependencies',{}).values():
                        for value in values: dep(value)
                    for key,value in project_data.get('scripts',{}).items():
                        if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',key) and isinstance(value,str) and re.fullmatch(r'[A-Za-z_][\w.]*:[A-Za-z_][\w.]*',value): entries[key]=value
                elif name=='requirements.txt':
                    for line in raw.decode().splitlines(): dep(line)
                elif name=='package.json':
                    data=json.loads(raw)
                    for group in ('dependencies','devDependencies'):
                        for key in data.get(group,{}):
                            if re.fullmatch(r'[@A-Za-z0-9_./-]{1,200}',key): dependencies.add(key)
            except (ValueError,OSError,UnicodeError,TypeError,AttributeError): problems.append(name)
        for rel in files:
            if total>=32*1024*1024 or time.monotonic()>deadline: incomplete=True; break
            if Path(rel).name.startswith('test_') or 'tests' in Path(rel).parts:
                if len(tests)<100: tests.append(rel)
            if not rel.endswith('.py'): continue
            if len(modules)>=100: incomplete=True; break
            try:
                raw,_=self.read(project,rel); total+=len(raw); tree=ast.parse(raw.decode())
                imports=set(); main_guard=False
                for node in ast.walk(tree):
                    if isinstance(node,ast.Import): imports.update(alias.name for alias in node.names)
                    elif isinstance(node,ast.ImportFrom) and node.module: imports.add('.'*node.level+node.module)
                    elif isinstance(node,ast.If):
                        test=node.test
                        if isinstance(test,ast.Compare) and isinstance(test.left,ast.Name) and test.left.id=='__name__' and any(isinstance(x,ast.Constant) and x.value=='__main__' for x in test.comparators): main_guard=True
                modules.append({'path':rel,'imports':sorted(imports)[:100],'mainGuard':main_guard})
            except (ValueError,OSError,UnicodeError,SyntaxError): problems.append(rel)
        return {'topLevel':top,'manifests':manifests,'likelyEntries':[n for n in ('main.py','app.py','src','tests','test','README.md') if n in names],
            'dependencies':sorted(dependencies)[:200],'entryPoints':entries,'pythonModules':modules,
            'testFiles':tests,'parseFailures':problems[:100],'scanComplete':not incomplete,
            'note':'Static bounded overview. Dependency names only; no manifest commands executed. Imports do not establish runtime dependency resolution.'}

    def get_service_status(self):
        units=[]
        env={'PATH':os.defpath,'HOME':str(Path.home()),'XDG_RUNTIME_DIR':'/run/user/'+str(os.getuid()),
             'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/'+str(os.getuid())+'/bus','SYSTEMD_PAGER':''}
        keys=('LoadState','ActiveState','SubState','UnitFileState','Restart','RestartUSec','StartLimitIntervalUSec','StartLimitBurst')
        names = self.cfg.get('serviceNames', {})
        for unit in (names.get('mcp', 'notion-local-mcp.service'), 'docker.service', names.get('tunnel', 'notion-local-mcp-tunnel.service')):
            try:
                proc=subprocess.run(['/usr/bin/systemctl','--user','--no-pager','show',unit,*['--property='+key for key in keys]],
                    env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
                text=proc.stdout[:16384].decode('utf-8',errors='replace')
                fields=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
                units.append({'unit':unit,'queryExitCode':proc.returncode,**{key:fields.get(key) for key in keys}})
            except (OSError,subprocess.TimeoutExpired): units.append({'unit':unit,'state':'unavailable'})
        from urllib.parse import urlsplit
        raw=self.cfg.get('publicMcpUrl','')
        try:
            url=urlsplit(raw)
            configured=url.scheme=='https' and bool(url.hostname) and not url.username and not url.password and not url.query and not url.fragment and url.path=='/mcp'
        except (ValueError,TypeError): configured=False
        return {'units':units,'publicMcpUrlConfigured':configured,
                'note':'A configured URL is not proof of stable DNS/tunnel reachability. Login-independent startup requires separately approved lingering or a dedicated system service.'}

    cls.__init__=initialize
    cls.allowed=allowed
    cls.audit_event=audit_event
    cls.get_capabilities=get_capabilities
    cls.git_branches=git_branches
    cls.git_staged_paths=git_staged_paths
    cls.plan_git=plan_git
    cls.apply_git=apply_git
    cls.find_references=find_references
    cls.project_summary=project_summary
    cls.get_service_status=get_service_status
