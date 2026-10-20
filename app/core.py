"""Project-scoped MCP backend. Local operator approvals; never unrestricted shell."""
import ast, base64, csv, difflib, fnmatch, hashlib, io, json, logging
import logging.handlers, os, re, secrets, shutil, stat, subprocess, tempfile, threading, time
from pathlib import Path
VERSION='2.2.8-service-timeout-validation'
FILE_LIMIT=2*1024*1024
OUTPUT_LIMIT=128*1024
SCAN_LIMIT=32*1024*1024
DENIED={'.git','.ssh','.aws','.gnupg','node_modules','__pycache__','.venv','venv'}
def digest(data): return hashlib.sha256(data).hexdigest()
def integer(value,low,high):
    if type(value) is not int or not low<=value<=high: raise ValueError('Integer outside allowed range')
    return value

def redact(text):
    text=re.sub(r'(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|bearer\s+)\S+',r'\1[REDACTED]',text)
    text=re.sub(r'(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;]+',r'\1[REDACTED]',text)
    text=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----','[REDACTED PRIVATE KEY]',text,flags=re.S)
    return text

class Backend:
    def __init__(self,config_path):
        self.config_path=Path(config_path).resolve(strict=True)
        self.cfg=json.loads(self.config_path.read_text())
        self.state=Path(self.cfg['stateDir']).expanduser().resolve()
        self.state.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(self.state,0o700)
        self.lock=threading.RLock(); self.jobs={}
        self.projects={}
        for name,spec in self.cfg['projects'].items():
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',name): raise ValueError('Invalid project identifier')
            root=Path(spec['root']).expanduser().resolve(strict=True)
            grants = self.cfg.get('authorizedRoots')
            if grants is not None:
                if not isinstance(grants,list) or not grants:
                    raise ValueError('authorizedRoots must be a non-empty list')
                matches=[]
                for grant in grants:
                    raw=grant.get('path','')
                    if not Path(raw).is_absolute(): raise ValueError('Authorization root must be absolute')
                    scope=Path(raw).resolve(strict=True)
                    if scope==Path('/'): raise ValueError('Filesystem root authorization is not supported')
                    if root==scope or scope in root.parents: matches.append(grant)
                if not matches: raise ValueError('Project is outside authorizedRoots')
                grant=max(matches,key=lambda x:len(Path(x['path']).parts))
                if spec.get('read',True) and not grant.get('read',False): raise ValueError('Read permission exceeds authorization')
                if spec.get('write',False) and not grant.get('write',False): raise ValueError('Write permission exceeds authorization')
            else:
                broad_home=root==Path.home() and self.cfg.get('allowHomeRootReadOnly') is True
                if root==Path.home() and (not broad_home or spec.get('write') or spec.get('gitWrite') or spec.get('tasks')):
                    raise ValueError('Home access requires explicit authorizedRoots permissions')
                if not broad_home and (root==self.state or root in self.state.parents or self.state in root.parents or root in self.config_path.parents):
                    raise ValueError('Private state/config overlap requires explicit authorizedRoots')
            if not root.is_dir() or root==Path('/'): raise ValueError('Invalid project root')
            if any(prior['root']==root for prior in self.projects.values()): raise ValueError('Duplicate project root')
            self.projects[name]={**spec,'root':root}
        if not self.projects: raise ValueError('Configure at least one project')
        for folder in ('approvals','snapshots','indexes','jobs'):
            (self.state/folder).mkdir(mode=0o700,exist_ok=True)
        self.audit=logging.getLogger('mcp-audit-'+str(self.state)); self.audit.setLevel(logging.INFO); self.audit.propagate=False
        if not self.audit.handlers:
            handler=logging.handlers.RotatingFileHandler(self.state/'audit.log',maxBytes=1024*1024,backupCount=3)
            handler.setFormatter(logging.Formatter('%(message)s')); self.audit.addHandler(handler)
    def project(self,name):
        if name not in self.projects: raise ValueError('Unknown project; use list_projects')
        return self.projects[name]
    def allowed(self,project,rel,write=False):
        spec=self.project(project)
        q=Path(rel)
        if not isinstance(rel,str) or q.is_absolute() or '..' in q.parts: raise ValueError('Use project-relative paths without ..')
        for part in q.parts:
            if part.startswith('.') or part.lower() in DENIED or part.lower().endswith(('.key','.pem','.p12','.pfx')):
                raise ValueError('Excluded or hidden path')
        normal=q.as_posix()
        denies=spec.get('deny',[])
        if any(fnmatch.fnmatchcase(normal,pattern) or fnmatch.fnmatchcase(q.name,pattern) for pattern in denies):
            raise ValueError('Denied project path')
        if write:
            if not spec.get('write',False): raise ValueError('Project is read-only')
            scopes=spec.get('writeAllow',[])
            if not scopes or not any(fnmatch.fnmatchcase(normal,p) for p in scopes): raise ValueError('Path is outside writable scope')
        root=spec['root']; cur=root
        for part in q.parts:
            cur=cur/part
            if cur.is_symlink(): raise ValueError('Symbolic links are forbidden')
        resolved=cur.resolve(strict=False)
        if resolved!=root and root not in resolved.parents: raise ValueError('Outside project root')
        if resolved==self.config_path: raise ValueError('Operator configuration is excluded')
        for private in (self.state,self.config_path.parent):
            if root in private.parents and (resolved==private or private in resolved.parents): raise ValueError('Private service directory is excluded')
        return cur
    def read(self,project,rel,limit=FILE_LIMIT):
        path=self.allowed(project,rel)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: raise ValueError('Require regular file without hard links')
            if info.st_size>limit: raise ValueError('File too large; use read_file_lines')
            with os.fdopen(os.dup(fd),'rb') as stream: data=stream.read(limit+1)
            if len(data)>limit: raise ValueError('File grew beyond size limit')
            return data,stat.S_IMODE(info.st_mode)
        finally: os.close(fd)
    def atomic_json(self,path,obj):
        self.atomic_private(path,json.dumps(obj,ensure_ascii=False).encode())
    def atomic_private(self,path,data):
        fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.pending-')
        try:
            with os.fdopen(fd,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
    def walk(self,project,path='.',maxDepth=8):
        root=self.allowed(project,path); integer(maxDepth,0,32)
        if not root.is_dir(): raise ValueError('Not a directory')
        deadline=time.monotonic()+5; visited=0; truncated=False
        stack=[(root,0)]; files=[]
        while stack:
            directory,depth=stack.pop()
            try:
                children=[]
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited+=1
                        if visited>20000 or time.monotonic()>deadline:
                            truncated=True; break
                        children.append(entry)
                if visited>20000 or time.monotonic()>deadline: break
                for entry in sorted(children,key=lambda item:item.name):
                    rel=str(Path(entry.path).relative_to(self.project(project)['root']))
                    try: candidate=self.allowed(project,rel)
                    except ValueError: continue
                    if entry.is_dir(follow_symlinks=False):
                        if depth<maxDepth: stack.append((candidate,depth+1))
                        else: truncated=True
                    elif entry.is_file(follow_symlinks=False): files.append(rel)
            except OSError: truncated=True
        return sorted(files),truncated
    def list_projects(self):
        return {'projects':[{'project':name,'write':bool(p.get('write')),'gitWrite':bool(p.get('gitWrite')),'tasks':sorted(p.get('tasks',{}))} for name,p in self.projects.items()]}
    def health(self):
        return {'version':VERSION,'projects':len(self.projects),'dockerAvailable':bool(shutil.which('docker')),'gitAvailable':bool(shutil.which('git')),'pendingJobs':sum(j['status']=='running' for j in self.jobs.values()),'state':'ok'}
    def list_directory(self,project,path='.',offset=0,limit=100):
        integer(offset,0,20000); integer(limit,1,200)
        directory=self.allowed(project,path)
        if not directory.is_dir(): raise ValueError('Not a directory')
        entries=[]; deadline=time.monotonic()+5
        with os.scandir(directory) as iterator:
            for n,child in enumerate(iterator,1):
                if n>20000 or time.monotonic()>deadline: raise ValueError('Directory scan capped; choose a smaller directory')
                try: self.allowed(project,str(Path(child.path).relative_to(self.project(project)['root'])))
                except ValueError: continue
                kind='directory' if child.is_dir(follow_symlinks=False) else 'file' if child.is_file(follow_symlinks=False) else None
                if kind: entries.append({'name':child.name,'type':kind})
        entries.sort(key=lambda x:x['name']); page=entries[offset:offset+limit]; more=offset+len(page)<len(entries)
        return {'entries':page,'totalEntries':len(entries),'hasMore':more,'nextOffset':offset+len(page) if more else None}
    def read_text_file(self,project,path):
        raw,_=self.read(project,path)
        if b'\0' in raw: raise ValueError('Binary data; use document_preview')
        return {'text':raw.decode('utf-8'),'sha256':digest(raw)}
    def read_file_lines(self,project,path,startLine=1,endLine=None):
        integer(startLine,1,10000000); endLine=endLine or min(startLine+199,10000000); integer(endLine,1,10000000)
        if endLine<startLine or endLine-startLine>=1000: raise ValueError('Range must contain 1 to 1000 lines')
        target=self.allowed(project,path); fd=self.checked_fd(project,path)
        result=[]; used=0; scanned=0; reason=None; nextLine=None; deadline=time.monotonic()+5; eof=False
        with os.fdopen(fd,'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_nlink!=1: raise ValueError('Not an unlinked regular file')
            for n in range(1,10000001):
                if time.monotonic()>deadline: reason='time_limit'; break
                if scanned>=SCAN_LIMIT: reason='scan_limit'; break
                raw=stream.readline(min(65536,SCAN_LIMIT-scanned)+1); scanned+=len(raw)
                if not raw: eof=True; break
                if scanned>SCAN_LIMIT or len(raw)>65536: reason='scan_or_line_limit'; break
                if b'\0' in raw: raise ValueError('Binary data')
                line=raw.decode('utf-8').rstrip('\r\n')
                if n<startLine: continue
                item={'line':n,'text':line}; size=len(json.dumps(item,ensure_ascii=False).encode())
                if used+size>OUTPUT_LIMIT: reason='output_limit'; nextLine=n; break
                result.append(item); used+=size
                if n==endLine:
                    eof=not bool(stream.read(1)); nextLine=None if eof else n+1; reason=None if eof else 'range_limit'; break
        return {'lines':result,'nextLine':nextLine,'eof':eof,'stopReason':reason,'scannedBytes':scanned}
    def search_files(self,project,pattern,path='.',offset=0,limit=100,maxDepth=8):
        integer(offset,0,20000); integer(limit,1,200)
        if not pattern or len(pattern)>256: raise ValueError('Invalid pattern')
        files,truncated=self.walk(project,path,maxDepth)
        matches=[p for p in files if fnmatch.fnmatchcase(p,pattern) or fnmatch.fnmatchcase(Path(p).name,pattern)]
        page=matches[offset:offset+limit]; more=offset+len(page)<len(matches)
        return {'results':[{'path':p} for p in page],'scanComplete':not truncated,'hasMore':more,'nextOffset':offset+len(page) if more else None}
    def search_text(self,project,query,path='.',caseSensitive=True,offset=0,limit=100,maxDepth=8):
        integer(offset,0,20000); integer(limit,1,200)
        if not query or len(query)>1024 or '\n' in query: raise ValueError('Invalid single-line query')
        files,incomplete=self.walk(project,path,maxDepth); results=[]; skipped=0; scanned=0; found=0; used=0; more=False
        needle=query if caseSensitive else query.casefold(); deadline=time.monotonic()+5
        for rel in files:
            if scanned>=SCAN_LIMIT or time.monotonic()>deadline: incomplete=True; break
            try:
                raw,_=self.read(project,rel,min(FILE_LIMIT,SCAN_LIMIT-scanned)); scanned+=len(raw)
                if b'\0' in raw: skipped+=1; continue
                text=raw.decode('utf-8')
            except (OSError,ValueError): skipped+=1; continue
            for n,line in enumerate(text.splitlines(),1):
                if time.monotonic()>deadline: incomplete=True; break
                if needle not in (line if caseSensitive else line.casefold()): continue
                found+=1
                if found<=offset: continue
                item={'path':rel,'line':n,'text':line[:400],'textTruncated':len(line)>400}
                size=len(json.dumps(item,ensure_ascii=False).encode())
                if len(results)>=limit or used+size>OUTPUT_LIMIT: more=True; incomplete=True; break
                results.append(item); used+=size
            if more: break
        return {'results':results,'scanComplete':not incomplete,'skippedFiles':skipped,'hasMore':more,'nextOffset':offset+len(results) if more else None}
    def get_file_hash(self,project,path):
        raw,_=self.read(project,path); return {'sha256':digest(raw),'bytes':len(raw)}
    def approval(self,kind,project,payload,preview):
        aid=secrets.token_hex(16)
        record={'id':aid,'kind':kind,'project':project,'created':time.time(),'expires':time.time()+1800,'approved':False,'used':False,'payload':payload,'preview':preview}
        self.atomic_json(self.state/'approvals'/(aid+'.json'),record)
        return {'approvalId':aid,'preview':preview,'applied':False,'expiresInSeconds':1800,'instruction':'Local operator must run manage.py approve '+aid+' before applying. MCP cannot approve.'}
    def load_approval(self,aid,consume=False):
        if not re.fullmatch('[0-9a-f]{32}',aid): raise ValueError('Invalid approval ID')
        path=self.state/'approvals'/(aid+'.json'); record=json.loads(path.read_text())
        if record['expires']<time.time() or record['used'] or not record['approved']: raise ValueError('Approval expired, used, or not approved by local operator')
        if consume: record['used']=True; self.atomic_json(path,record)
        return record
    def plan_files(self,project,changes):
        if not isinstance(changes,list) or not 1<=len(changes)<=20: raise ValueError('Provide 1 to 20 changes')
        items=[]; preview=[]; seen=set(); total=0
        for change in changes:
            rel=change['path']; path=self.allowed(project,rel,write=True)
            if rel in seen or not path.parent.is_dir(): raise ValueError('Duplicate path or missing parent directory')
            seen.add(rel)
            exists=path.exists()
            if exists:
                old,mode=self.read(project,rel)
                if change.get('expectedHash')!=digest(old): raise ValueError('expectedHash required and must match current file')
            else:
                if change.get('expectedHash') is not None: raise ValueError('New file must not have expectedHash')
                old=b''; mode=0o600
            if 'edits' in change:
                new=old.decode('utf-8')
                if not exists or not 1<=len(change['edits'])<=100: raise ValueError('Edits require an existing file and 1 to 100 edits')
                for edit in change['edits']:
                    source=edit['oldText']; replacement=edit['newText']
                    if not source or new.count(source)!=1: raise ValueError('Each oldText must match exactly once')
                    new=new.replace(source,replacement,1)
                content=new
            else: content=change['content']
            if not isinstance(content,str) or '\0' in content: raise ValueError('UTF-8 text content required')
            encoded=content.encode(); total+=len(encoded)+len(old)
            if len(encoded)>FILE_LIMIT or total>8*FILE_LIMIT: raise ValueError('Change set too large')
            patch=''.join(difflib.unified_diff(old.decode('utf-8').splitlines(True),content.splitlines(True),fromfile=rel,tofile=rel))
            preview.append({'path':rel,'create':not exists,'diff':patch})
            items.append({'path':rel,'oldHash':digest(old) if exists else None,'newHash':digest(encoded),'content':content,'mode':mode})
        if len(json.dumps(preview).encode())>OUTPUT_LIMIT: raise ValueError('Diff too large; use smaller changes')
        return self.approval('files',project,items,preview)
    def create_text_file(self,project,path,content):
        if self.allowed(project,path,write=True).exists(): raise ValueError('Refusing to overwrite an existing file')
        return self.plan_files(project,[{'path':path,'content':content}])
    def apply_text_edits(self,project,path,expectedHash,edits):
        return self.plan_files(project,[{'path':path,'expectedHash':expectedHash,'edits':edits}])
    def edit_file(self,project,path,oldText,newText,dryRun=True):
        if not dryRun: raise ValueError('Use a locally approved apply_change; dryRun=false is no longer allowed')
        raw,_=self.read(project,path)
        return self.apply_text_edits(project,path,digest(raw),[{'oldText':oldText,'newText':newText}])
    def write_one(self,project,item,data,expected):
        target=self.allowed(project,item['path'],write=True)
        # Best-effort conflict check. Not a CAS primitive against hostile writers.
        if expected is None:
            if target.exists(): raise ValueError('Create conflict: file already exists')
        else:
            current,_=self.read(project,item['path'])
            if digest(current)!=expected: raise ValueError('File changed after preview')
        # Revalidate the parent immediately before atomic replacement.
        self.allowed(project,str(target.parent.relative_to(self.project(project)['root'])),write=False)
        fd,temp=tempfile.mkstemp(dir=target.parent,prefix='.mcp-tmp-')
        try:
            os.fchmod(fd,item['mode'])
            with os.fdopen(fd,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
            if expected is None: os.link(temp,target,follow_symlinks=False); os.unlink(temp)
            else: os.replace(temp,target)
        finally:
            if os.path.exists(temp): os.unlink(temp)
    def apply_change(self,approvalId):
        with self.lock:
            record=self.load_approval(approvalId)
            if record['kind']!='files': raise ValueError('Not a file-change approval')
            project=record['project']; items=record['payload']; originals=[]
            for item in items:
                path=self.allowed(project,item['path'],write=True)
                old=None if item['oldHash'] is None else self.read(project,item['path'])[0]
                if (old is None and path.exists()) or (old is not None and digest(old)!=item['oldHash']): raise ValueError('Change set conflict')
                originals.append({'path':item['path'],'old':None if old is None else base64.b64encode(old).decode(),'mode':item['mode'],'newHash':item['newHash']})
            self.load_approval(approvalId,consume=True)
            self.atomic_json(self.state/'snapshots'/(approvalId+'.json'),{'id':approvalId,'project':project,'created':time.time(),'files':originals})
            applied=[]
            try:
                for item in items:
                    self.write_one(project,item,item['content'].encode(),item['oldHash']); applied.append(item['path'])
            except Exception:
                # Recovery is explicit, not an unsafe automatic overwrite of newer data.
                self.audit_event('apply_change','partial_failure',project,paths=applied)
                return {'applied':False,'partial':bool(applied),'writtenPaths':applied,'snapshotId':approvalId,'instruction':'Inspect current hashes and request restore_snapshot; no automatic rollback was performed.'}
            self.audit_event('apply_change','ok',project,paths=applied)
            return {'applied':True,'paths':applied,'snapshotId':approvalId,'multiFileAtomic':False}
    def list_snapshots(self,project,limit=20):
        self.project(project); integer(limit,1,100); result=[]
        for path in sorted((self.state/'snapshots').glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True):
            obj=json.loads(path.read_text())
            if obj['project']==project: result.append({'snapshotId':obj['id'],'created':obj['created'],'paths':[f['path'] for f in obj['files']]})
            if len(result)>=limit: break
        return {'snapshots':result}
    def restore_snapshot(self,project,snapshotId):
        if not re.fullmatch('[0-9a-f]{32}',snapshotId): raise ValueError('Invalid snapshot ID')
        snap=json.loads((self.state/'snapshots'/(snapshotId+'.json')).read_text())
        if snap['project']!=project: raise ValueError('Wrong project')
        changes=[]; excluded=[]
        for item in snap['files']:
            if item['old'] is None: excluded.append(item['path']); continue
            raw,_=self.read(project,item['path'])
            changes.append({'path':item['path'],'expectedHash':digest(raw),'content':base64.b64decode(item['old']).decode('utf-8')})
        if not changes: return {'applied':False,'skippedCreatedFiles':excluded,'instruction':'Snapshot contains only new files; this service does not delete files.'}
        result=self.plan_files(project,changes); result['skippedCreatedFiles']=excluded; return result
    def audit_event(self,tool,status,project=None):
        self.audit.info(json.dumps({'time':time.time(),'tool':tool,'status':status,'project':project},ensure_ascii=False))
    def get_audit(self,limit=50):
        integer(limit,1,200)
        if not (self.state/'audit.log').exists(): return {'entries':[]}
        # Rotated audit log is capped at 1 MiB and contains no payload or credentials.
        lines=(self.state/'audit.log').read_text().splitlines()
        return {'entries':[json.loads(line) for line in lines[-limit:]]}
    def git_call(self,project,args,timeout=15):
        spec=self.project(project); root=spec['root']
        if not (root/'.git').is_dir() or (root/'.git').is_symlink(): raise ValueError('Require a normal local Git repository, not a worktree/symlink')
        env={'PATH':os.defpath,'HOME':str(self.state),'LANG':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_PAGER':'cat','GIT_OPTIONAL_LOCKS':'0'}
        git_binary=shutil.which('git')
        if not git_binary: raise ValueError('Git is not installed')
        cmd=[git_binary,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','commit.gpgSign=false','-c','core.pager=cat','-c','credential.helper=','-c','protocol.file.allow=never','-c','protocol.ext.allow=never',*args]
        # Disk output cap prevents unbounded stdout accumulation.
        with tempfile.TemporaryFile() as output:
            proc=subprocess.Popen(cmd,cwd=root,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            deadline=time.monotonic()+timeout
            while proc.poll() is None:
                if output.tell()>OUTPUT_LIMIT or time.monotonic()>deadline:
                    proc.kill(); proc.wait(); raise ValueError('Git command exceeded time/output limit')
                time.sleep(.02)
            output.seek(0); raw=output.read(OUTPUT_LIMIT+1)
        if len(raw)>OUTPUT_LIMIT: raise ValueError('Git output too large; narrow the request')
        result=redact(raw.decode('utf-8',errors='replace'))
        if proc.returncode: raise ValueError('Git command failed: '+result[:1000])
        return result
    def git_status(self,project):
        raw=self.git_call(project,['status','--porcelain=v1','--untracked-files=no'])
        # Don't disclose filenames in denied paths. Status is scoped, not repo-wide.
        lines=[]
        for line in raw.splitlines():
            rel=line[3:].strip('"')
            try: self.allowed(project,rel)
            except ValueError: continue
            lines.append(line)
        return {'text':'\n'.join(lines),'scope':'tracked accessible paths; untracked excluded'}
    def git_diff(self,project,path,staged=False):
        if not self.allowed(project,path).is_file(): raise ValueError('Specify an accessible current file, not a directory')
        args=['diff','--no-ext-diff','--no-textconv']+(['--cached'] if staged else [])+['--',path]
        return {'text':self.git_call(project,args)}
    def git_log(self,project,path,limit=10):
        if not self.allowed(project,path).is_file(): raise ValueError('Specify an accessible current file, not a directory')
        integer(limit,1,50)
        return {'text':self.git_call(project,['log','--no-show-signature','--format=%h %ad %s','--date=iso-strict','-n',str(limit),'--',path])}
    def plan_git(self,project,operation,branch=None,message=None,paths=None,remote=None):
        spec=self.project(project)
        if not spec.get('gitWrite',False): raise ValueError('Git mutations disabled by operator configuration')
        if operation not in {'branch','commit','merge_ff','push'}: raise ValueError('Unsupported Git operation')
        payload={'operation':operation}
        if operation in {'branch','merge_ff','push'}:
            if not branch or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9/_-]{0,100}',branch) or '..' in branch or branch.endswith('/'):
                raise ValueError('Invalid branch')
            payload['branch']=branch
        if operation=='commit':
            if not message or len(message)>1000 or not paths or len(paths)>50: raise ValueError('Commit needs message and explicit paths')
            hashes={}
            for path in paths: self.allowed(project,path,write=True); hashes[path]=self.get_file_hash(project,path)['sha256']
            if self.git_call(project,['diff','--cached','--name-only']).strip(): raise ValueError('Index must be empty before a managed commit')
            payload.update(message=message,hashes=hashes)
        if operation=='push':
            if remote not in spec.get('pushRemotes',{}): raise ValueError('Remote not allowlisted')
            url=spec['pushRemotes'][remote]
            if not re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9/_.-]+',url): raise ValueError('Require credential-free HTTPS remote URL')
            payload['url']=url
        payload['head']=self.git_call(project,['rev-parse','HEAD']).strip()
        if operation in {'branch','merge_ff'} and self.git_call(project,['status','--porcelain=v1']).strip(): raise ValueError('Working tree must be clean')
        if operation=='merge_ff': payload['target']=self.git_call(project,['rev-parse','--verify',branch+'^{commit}']).strip()
        if operation=='push':
            tip=self.git_call(project,['rev-parse','--verify','refs/heads/'+branch]).strip(); payload['tip']=tip
        return self.approval('git',project,payload,payload)
    def apply_git(self,approvalId):
        with self.lock:
            record=self.load_approval(approvalId); p=record['project']; data=record['payload']; spec=self.project(p)
            if record['kind']!='git' or not spec.get('gitWrite'): raise ValueError('Git writes not enabled')
            if self.git_call(p,['rev-parse','HEAD']).strip()!=data['head']: raise ValueError('HEAD changed after preview')
            op=data['operation']
            if op in {'branch','merge_ff'} and self.git_call(p,['status','--porcelain=v1']).strip(): raise ValueError('Working tree changed after preview')
            if op=='merge_ff' and self.git_call(p,['rev-parse','--verify',data['branch']+'^{commit}']).strip()!=data['target']: raise ValueError('Merge target changed')
            if op=='commit':
                if self.git_call(p,['diff','--cached','--name-only']).strip(): raise ValueError('Git index changed')
                for path,h in data['hashes'].items():
                    self.allowed(p,path,write=True)
                    if self.get_file_hash(p,path)['sha256']!=h: raise ValueError('File changed after preview')
            if op=='push' and (data['url'] not in spec.get('pushRemotes',{}).values() or self.git_call(p,['rev-parse','--verify','refs/heads/'+data['branch']]).strip()!=data['tip']): raise ValueError('Push configuration or branch changed')
            self.load_approval(approvalId,consume=True)
            if op=='branch': result=self.git_call(p,['switch','-c',data['branch']])
            elif op=='merge_ff': result=self.git_call(p,['merge','--ff-only','--no-edit',data['branch']])
            elif op=='commit':
                self.git_call(p,['add','--',*data['hashes']]); result=self.git_call(p,['commit','-m',data['message'],'--',*data['hashes']])
            else: result=self.git_call(p,['push','--porcelain',data['url'],'refs/heads/'+data['branch']+':refs/heads/'+data['branch']],timeout=30)
            return {'applied':True,'text':result,'warning':'Git operations are not transactional; inspect status after failures.'}
    def build_index(self,project):
        files,incomplete=self.walk(project); index_path=self.state/'indexes'/(project+'.json')
        cache=json.loads(index_path.read_text()) if index_path.exists() else {}; result={}; rebuilt=0; total=0; deadline=time.monotonic()+5
        for rel in files:
            if Path(rel).suffix not in {'.py','.js','.jsx','.ts','.tsx'}: continue
            if total>=SCAN_LIMIT or time.monotonic()>deadline: incomplete=True; break
            try: raw,_=self.read(project,rel); total+=len(raw); text=raw.decode()
            except (ValueError,OSError): continue
            h=digest(raw)
            if cache.get(rel,{}).get('sha256')==h: result[rel]=cache[rel]; continue
            symbols=[]; language='python_ast' if rel.endswith('.py') else 'js_ts_heuristic'
            if rel.endswith('.py'):
                try:
                    tree=ast.parse(text)
                    for node in ast.walk(tree):
                        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)): symbols.append({'name':node.name,'kind':type(node).__name__,'line':node.lineno})
                except SyntaxError: language='python_parse_failed'
            else:
                for n,line in enumerate(text.splitlines(),1):
                    match=re.search(r'\b(?:function|class|interface|type)\s+([A-Za-z_$][\w$]*)',line)
                    if match: symbols.append({'name':match.group(1),'kind':'heuristic','line':n})
            result[rel]={'sha256':h,'language':language,'symbols':symbols[:500]}; rebuilt+=1
        if len(json.dumps(result).encode())>8*FILE_LIMIT: raise ValueError('Index exceeds private cache limit')
        self.atomic_json(index_path,result)
        return {'indexedFiles':len(result),'rebuiltFiles':rebuilt,'scanComplete':not incomplete,'note':'Python definitions use AST; JS/TS definitions and references are heuristic, not language-server resolution.'}
    def search_symbols(self,project,query,limit=50):
        integer(limit,1,200); self.project(project)
        path=self.state/'indexes'/(project+'.json')
        if not path.exists(): raise ValueError('Build index first')
        results=[]; stale=0
        for rel,entry in json.loads(path.read_text()).items():
            try: current=self.get_file_hash(project,rel)['sha256']
            except (ValueError,OSError): stale+=1; continue
            if current!=entry['sha256']: stale+=1; continue
            for symbol in entry['symbols']:
                if query.casefold() in symbol['name'].casefold(): results.append({'path':rel,**symbol,'method':entry['language']})
                if len(results)>=limit: return {'results':results,'staleFiles':stale,'truncated':True}
        return {'results':results,'staleFiles':stale,'truncated':False}
    def find_references(self,project,symbol,path='.',limit=50):
        result=self.search_text(project,symbol,path=path,limit=limit)
        result['method']='literal occurrence; includes comments/strings, not semantic references'; return result
    def project_summary(self,project):
        listing=self.list_directory(project,limit=100)
        names={x['name'] for x in listing['entries']}; manifests=[n for n in ['pyproject.toml','requirements.txt','package.json','Cargo.toml','go.mod','Makefile'] if n in names]
        return {'topLevel':listing,'manifests':manifests,'likelyEntries':[n for n in ['main.py','app.py','src','tests','test','README.md'] if n in names],'note':'Filename-based hints only; manifests are not executed.'}
    def tail_log(self,project,path,limit=100,contains=None,level=None,since=None,cursor=None):
        integer(limit,1,1000); target=self.allowed(project,path)
        fd=self.checked_fd(project,path)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: raise ValueError('Not a regular file')
            if cursor:
                if cursor.get('inode')!=info.st_ino or cursor.get('offset',0)>info.st_size: start=max(0,info.st_size-OUTPUT_LIMIT); rotated=True
                else: start=integer(cursor['offset'],0,info.st_size); rotated=False
            else: start=max(0,info.st_size-OUTPUT_LIMIT); rotated=False
            stream.seek(start); raw=stream.read(OUTPUT_LIMIT); end=stream.tell()
        text=raw.decode('utf-8',errors='replace'); rows=text.splitlines()
        if start and not cursor and rows: rows=rows[1:]
        rows=[line for line in rows if (not contains or contains in line) and (not level or level.casefold() in line.casefold()) and (not since or line[:len(since)]>=since)]
        return {'lines':[redact(line) for line in rows[-limit:]],'cursor':{'inode':info.st_ino,'offset':end},'rotated':rotated,'hasMore':end<info.st_size,'note':'Level filter is literal; since assumes ISO timestamp prefix. Redaction is best-effort. Partial lines may be split.'}
    def document_preview(self,project,path,offset=0,limit=20):
        integer(offset,0,100000); integer(limit,1,100)
        data,_=self.read(project,path,8*FILE_LIMIT)
        import sys
        with tempfile.TemporaryDirectory(dir=self.state) as folder:
            source=Path(folder)/'input'; source.write_bytes(data)
            output=Path(folder)/'output'
            with output.open('wb') as stream:
                proc=subprocess.run([sys.executable,str(Path(__file__).with_name('parser_worker.py')),str(source),Path(path).suffix.lower(),str(offset),str(limit)],stdout=stream,stderr=subprocess.DEVNULL,timeout=15,env={'PATH':os.defpath,'HOME':str(folder)})
            if proc.returncode or output.stat().st_size>2*1024*1024:
                raise ValueError('Document parsing failed or exceeded resource/output limits')
            return json.loads(output.read_text())
    def rootless_docker_command(self):
        docker=shutil.which('docker')
        if not docker:
            raise ValueError('Docker unavailable; no host-command fallback')
        if Path(docker).resolve()!=Path('/usr/bin/docker').resolve():
            raise ValueError('Use the reviewed system Docker CLI')
        socket=Path('/run/user')/str(os.getuid())/'docker.sock'
        if socket.is_symlink():
            raise ValueError('Docker socket must not be a symbolic link')
        try:
            info=socket.stat()
        except OSError:
            raise ValueError('Current-user rootless Docker socket unavailable')
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid():
            raise ValueError('Require a current-user Docker socket')
        command=[docker,'--host','unix://'+str(socket)]
        probe=subprocess.run(
            command+['info','--format','{{json .}}'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=10,env={'PATH':os.defpath,'HOME':str(self.state)})
        if probe.returncode or len(probe.stdout)>OUTPUT_LIMIT:
            raise ValueError('Rootless Docker verification failed')
        data=json.loads(probe.stdout)
        fields={key.lower():value for key,value in data.items()}
        security=fields.get('securityoptions',[])
        if not isinstance(security,list) or not any(
            isinstance(x,str) and 'name=rootless' in x.split(',')
            for x in security):
            raise ValueError('Rootless Docker is required')
        if str(fields.get('cgroupversion'))!='2' or fields.get('cgroupdriver')!='systemd':
            raise ValueError('Require systemd cgroup v2')
        required=('memorylimit','cpucfsquota','cpucfsperiod','pidslimit')
        if not all(fields.get(key) is True for key in required):
            raise ValueError('Required container resource limits unavailable')
        return command

    def task_spec(self,project,task):
        spec=self.project(project).get('tasks',{}).get(task)
        if not spec: raise ValueError('Task not configured by local operator')
        if not re.fullmatch(r'[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}',spec.get('image','')): raise ValueError('Task image must be pinned by SHA256 digest')
        argv=spec.get('argv')
        if not isinstance(argv,list) or not argv or len(argv)>50 or any(not isinstance(x,str) or len(x)>2000 for x in argv): raise ValueError('Invalid configured argv')
        integer(spec.get('timeout',60),1,600); return spec
    def plan_task(self,project,task):
        spec=self.task_spec(project,task)
        files,incomplete=self.walk(project)
        if incomplete: raise ValueError('Task export scan incomplete; narrow the project')
        hashes={}; total=0
        for rel in files:
            raw,_=self.read(project,rel); total+=len(raw)
            if total>SCAN_LIMIT: raise ValueError('Task workspace exceeds 32 MiB')
            hashes[rel]=digest(raw)
        return self.approval('task',project,{'task':task,'specHash':digest(json.dumps(spec,sort_keys=True).encode()),'files':hashes},{'task':task,'image':spec['image'],'argv':spec['argv'],'network':'none','workspace':'sanitized read-only copy','files':len(hashes),'timeout':spec.get('timeout',60)})
    def run_project_task(self,approvalId):
        with self.lock:
            record=self.load_approval(approvalId)
            if record['kind']!='task': raise ValueError('Not a task approval')
            project=record['project']; data=record['payload']; spec=self.task_spec(project,data['task'])
            if digest(json.dumps(spec,sort_keys=True).encode())!=data['specHash']: raise ValueError('Task config changed after preview')
            docker_command=self.rootless_docker_command()
            active=sum(j['status']=='running' for j in self.jobs.values())
            if active>=2: raise ValueError('Maximum concurrent tasks reached')
            files,incomplete=self.walk(project)
            if incomplete or set(files)!=set(data['files']): raise ValueError('Workspace changed after preview')
            jobid=secrets.token_hex(16); folder=self.state/'jobs'/jobid; folder.mkdir(mode=0o700)
            workspace=folder/'workspace'; workspace.mkdir(mode=0o755); os.chmod(workspace,0o755)
            for rel,h in data['files'].items():
                raw,_=self.read(project,rel)
                if digest(raw)!=h: shutil.rmtree(folder); raise ValueError('Workspace content changed after preview')
                target=workspace/rel; target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(raw); os.chmod(target,0o644)
                for parent in target.parents:
                    if parent==workspace: break
                    if workspace in parent.parents: os.chmod(parent,0o755)
            self.load_approval(approvalId,consume=True)
            container='local-mcp-'+jobid
            cmd=docker_command+['run','--pull=never','--name',container,'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=512m','--cpus=1','--user=65534:65534','--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m','--mount','type=bind,source='+str(workspace)+',target=/workspace,readonly','--workdir=/workspace','--log-driver=none','--entrypoint',spec['argv'][0],spec['image'],*spec['argv'][1:]]
            job={'id':jobid,'status':'running','created':time.time(),'container':container,'text':'','exitCode':None,'project':project,'cleanupStatus':'pending'}; self.jobs[jobid]=job
            self.atomic_json(folder/'result.json',job)
            thread=threading.Thread(target=self.task_worker,args=(job,cmd,spec.get('timeout',60),folder),daemon=True); thread.start()
            return {'jobId':jobid,'status':'running'}
    def task_worker(self,job,cmd,timeout,folder):
        proc=None; deadline=time.monotonic()+timeout; reason='finished'; buffer=bytearray()
        try:
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={'PATH':os.defpath,'HOME':str(self.state)},start_new_session=True)
            job['_process']=proc; os.set_blocking(proc.stdout.fileno(),False)
            while True:
                try: chunk=os.read(proc.stdout.fileno(),8192)
                except BlockingIOError: chunk=None
                if chunk: buffer.extend(chunk)
                if len(buffer)>OUTPUT_LIMIT: reason='output_limit'; break
                if job['status']=='cancel_requested': reason='cancelled'; break
                if time.monotonic()>deadline: reason='timed_out'; break
                if proc.poll() is not None and chunk==b'': break
                time.sleep(.03)
            if proc.poll() is None: proc.kill()
            proc.wait(timeout=5)
            job['exitCode']=proc.returncode; job['status']=reason
        except Exception:
            job['status']='failed'; buffer.extend(b'Task launcher failed; inspect local operator logs.')
        finally:
            # Docker CLI exit does not guarantee container exit; always remove it.
            try:
                subprocess.run(cmd[:3]+['rm','-f',job['container']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,check=True,env={'PATH':os.defpath,'HOME':str(self.state)})
                job.update(cleanupStatus='succeeded',cleanupFailed=False,cleanupExitCode=0)
            except subprocess.CalledProcessError as error:
                job.update(cleanupStatus='failed',cleanupFailed=True,cleanupExitCode=error.returncode,cleanupErrorType=type(error).__name__)
            except Exception as error:
                job.update(cleanupStatus='failed',cleanupFailed=True,cleanupExitCode=None,cleanupErrorType=type(error).__name__)
            job['text']=redact(bytes(buffer[:OUTPUT_LIMIT]).decode('utf-8',errors='replace')); job.pop('_process',None)
            self.atomic_json(folder/'result.json',job)
            shutil.rmtree(folder/'workspace',ignore_errors=True)
    def get_task_status(self,jobId):
        if not re.fullmatch('[0-9a-f]{32}',jobId): raise ValueError('Invalid job ID')
        if jobId in self.jobs: return {k:v for k,v in self.jobs[jobId].items() if not k.startswith('_')}
        result=self.state/'jobs'/jobId/'result.json'
        if not result.exists(): raise ValueError('Unknown job; running jobs are not resumed after service restart')
        return json.loads(result.read_text())
    def cancel_task(self,jobId):
        job=self.jobs.get(jobId)
        if not job: raise ValueError('Unknown active job')
        if job['status']=='running': job['status']='cancel_requested'
        return {'jobId':jobId,'status':job['status']}

def parse_document(data,suffix,offset,limit):
    if suffix in {'.csv','.tsv'}:
        if b'\0' in data: raise ValueError('Binary data')
        reader=csv.reader(io.StringIO(data.decode('utf-8-sig')),delimiter='\t' if suffix=='.tsv' else ',')
        rows=[]; more=False
        for n,row in enumerate(reader):
            if n<offset: continue
            if len(rows)>=limit: more=True; break
            rows.append([redact(cell[:2000]) for cell in row[:50]])
            if len(json.dumps(rows).encode())>OUTPUT_LIMIT: raise ValueError('Rows too large; reduce limit')
        return {'kind':'table','rows':rows,'hasMore':more,'nextOffset':offset+len(rows) if more else None,'columnsCappedAt':50}
    if suffix=='.pdf':
        from pypdf import PdfReader
        reader=PdfReader(io.BytesIO(data)); pages=[]
        for n in range(offset,min(len(reader.pages),offset+min(limit,5))):
            page=reader.pages[n]
            # Avoid decoding a single enormous content stream.
            contents=page.get('/Contents')
            if contents is not None and len(str(contents))>100000: raise ValueError('PDF page description too large')
            pages.append({'page':n+1,'text':redact((page.extract_text() or '')[:20000])})
            if len(json.dumps(pages).encode())>OUTPUT_LIMIT: raise ValueError('PDF output exceeds limit')
        return {'kind':'pdf','pages':pages,'totalPages':len(reader.pages),'ocr':False,'note':'Scanned PDFs require separate OCR; parsing is best effort.'}
    if suffix in {'.png','.jpg','.jpeg','.webp'}:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS=20000000
        with Image.open(io.BytesIO(data)) as image:
            image.load(); original=image.size; image.thumbnail((1024,1024)); image=image.convert('RGB'); output=io.BytesIO(); image.save(output,format='JPEG',quality=75)
            encoded=output.getvalue()
            if len(encoded)>1024*1024: raise ValueError('Image preview too large')
        return {'kind':'image','mimeType':'image/jpeg','base64':base64.b64encode(encoded).decode(),'originalSize':original,'note':'Image pixels are not redacted; no OCR.'}
    raise ValueError('Supported: CSV, TSV, PDF, PNG, JPG, JPEG, WebP')

# Basic usability extensions; no operator approval endpoints exposed.
from enhancements import attach_backend
attach_backend(Backend)

from file_access import attach_file_access
attach_file_access(Backend)

from dev_workspace import attach_workspace
attach_workspace(Backend)
from dev_execution import attach_execution
attach_execution(Backend)
from dev_services import attach_services
attach_services(Backend)

from dev_maintenance import attach_maintenance
attach_maintenance(Backend)

# 将开发权限与兼容文件审批模式分别返回，避免客户端混淆。
_previous_capabilities = Backend.get_capabilities

def _platform_capabilities(self, project=None):
    result = _previous_capabilities(self, project)
    profiles = {}
    for name in self.cfg.get('executionProfiles', {}):
        policy = self.dev_policy(name)
        profiles[name] = {key: policy.get(key) for key in ('enabled', 'environment', 'projects', 'readRoots', 'writeRoots', 'denyPaths', 'network', 'git', 'limits', 'services')}
    active = profiles.get('autonomous-development', {}).get('enabled') is True
    result['executionProfiles'] = profiles
    from dev_execution import _limits
    result['limitScopes'] = {
        'limits': {
            'appliesTo': ['legacy file tools', 'plan_task', 'run_project_task'],
            'note': 'Compatibility limits; they do not configure dev_run or dev_pty_open.'},
        'executionProfiles': {
            'appliesTo': ['dev_* tools selected by profile'],
            'note': 'Each selected profile supplies its own execution, file and service policy.'}}
    result['effectiveExecutionLimits'] = {
        name: _limits(policy) for name, policy in profiles.items()
        if policy.get('environment') == 'isolated-development'}
    result['features'].update({'arbitraryShell': active, 'automaticTaskAuthorization': active,
        'localApprovalRequired': 'legacy file tools only; autonomous development tools do not require approvalId',
        'tasks': 'general argv and explicit shell in non-root filesystem, process and network namespaces',
        'administratorMaintenance': 'fixed MCP executor; locally registered signed candidates only',
        'developmentGit': 'private development repository; source synchronization is explicit and hash checked',
        'developmentNetwork': 'isolated loopback only; no internet dependency installation',
        'nativeDesktopAutomation': False})
    return result

Backend.get_capabilities = _platform_capabilities
