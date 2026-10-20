"""临时数据库、HTTP 服务与独立浏览器；执行只进入开发网络命名空间。"""
import base64
import os
from pathlib import Path
import subprocess
import urllib.request
import hashlib
import json
import re
import time
import threading
import uuid
from urllib.parse import urlsplit

PROFILE = 'autonomous-development'


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Integer outside allowed service limit')
    return value


def relative(value):
    if not isinstance(value, str) or not value or value.startswith('/') or '\\' in value or '\0' in value or any(x in {'', '..', '.'} for x in value.split('/')):
        raise ValueError('Use a relative path inside the development workspace')
    if any(x.lower() in {'.git', '.ssh', '.aws', '.gnupg', '.config', '.codex'} for x in value.split('/')):
        raise ValueError('Private path is forbidden')
    return value


def origin(url, ports):
    if not isinstance(url, str) or len(url) > 4096:
        raise ValueError('Invalid development URL')
    try:
        p = urlsplit(url)
        port = p.port or 80
    except ValueError:
        raise ValueError('Invalid development URL') from None
    if p.scheme != 'http' or p.hostname != '127.0.0.1' or p.username is not None or p.password is not None or p.fragment or port not in ports:
        raise ValueError('Only a registered isolated development service URL is allowed')
    return url


SQLITE_CODE = r'''
import json, sqlite3, pathlib, sys, base64
p=json.loads(sys.argv[1]); path=pathlib.Path('/workspace')/p['path']
root=pathlib.Path('/workspace').resolve(); real=path.resolve()
if real != root and root not in real.parents: raise ValueError('Database outside workspace')
# /workspace 是 sandbox 内部受控映射；真正边界由 execution workspace manifest 校验。
if p['readonly']:
 conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=1)
 conn.execute('PRAGMA query_only=ON')
 denied={sqlite3.SQLITE_INSERT,sqlite3.SQLITE_UPDATE,sqlite3.SQLITE_DELETE,sqlite3.SQLITE_CREATE_TABLE,sqlite3.SQLITE_DROP_TABLE,sqlite3.SQLITE_ATTACH,sqlite3.SQLITE_DETACH,sqlite3.SQLITE_ALTER_TABLE,sqlite3.SQLITE_PRAGMA}
 conn.set_authorizer(lambda action,*args: sqlite3.SQLITE_DENY if action in denied or (action==sqlite3.SQLITE_READ and len(args)>1 and any(x in str(args[1]).lower() for x in ['secret','password','token','credential','api_key','private_key'])) else sqlite3.SQLITE_OK)
else:
 path.parent.mkdir(parents=True,exist_ok=True); conn=sqlite3.connect(path,timeout=1)
conn.enable_load_extension(False)
import time
end=time.monotonic()+p['timeout']; conn.set_progress_handler(lambda:int(time.monotonic()>end),1000)
rows=[]; columns=[]; truncated=False
try:
 cur=conn.execute(p['sql'],p['parameters']); columns=[x[0] for x in cur.description or []]
 if cur.description:
  rows=cur.fetchmany(p['offset']+p['limit']+1)[p['offset']:]
  truncated=len(rows)>p['limit']; rows=rows[:p['limit']]
  for n,column in enumerate(columns):
   if any(x in column.lower() for x in ['secret','password','token','credential','api_key','private_key']):
    rows=[list(row) for row in rows]
    for row in rows: row[n]='[REDACTED]'
 conn.commit()
 print(json.dumps({'columns':columns,'rows':rows,'truncated':truncated,'readonly':p['readonly'],'changedRows':conn.total_changes},default=lambda x:base64.b64encode(x).decode() if isinstance(x,bytes) else str(x)))
except Exception:
 conn.rollback(); print(json.dumps({'error':'Database operation rejected or failed; SQL and values withheld'})); sys.exit(2)
finally: conn.close()
'''

HTTP_CODE = r'''
import json,sys,http.client,urllib.parse,base64,socket
p=json.loads(sys.argv[1]); url=p['url']; method=p['method']; body=base64.b64decode(p['body']); maximum=p['maximum']; headers={'Content-Type':p['contentType']}
if p['requestId']: headers['Idempotency-Key']=p['requestId']
for step in range(6):
 u=urllib.parse.urlsplit(url)
 if u.scheme!='http' or u.hostname!='127.0.0.1' or u.username or u.password or (u.port or 80) not in p['ports']: raise ValueError('Redirect target outside registered sandbox services')
 c=http.client.HTTPConnection('127.0.0.1',u.port or 80,timeout=p['timeout'])
 try:
  target=(u.path or '/') + (('?'+u.query) if u.query else '')
  c.request(method,target,body=body if method not in ['GET','HEAD'] else None,headers=headers)
  r=c.getresponse(); data=r.read(maximum+1)
  location=r.getheader('Location')
  if r.status in [301,302,303,307,308] and location:
   if method not in ['GET','HEAD']: print(json.dumps({'status':r.status,'redirected':False,'reason':'Mutating redirects are not replayed','unknown':False})); break
   if step==5: raise ValueError('Redirect limit exceeded')
   url=urllib.parse.urljoin(url,location); continue
  text=data[:maximum].decode('utf-8','replace')
  print(json.dumps({'status':r.status,'body':text,'truncated':len(data)>maximum,'unknown':False,'finalUrl':url})); break
 except (socket.timeout,ConnectionError,OSError,http.client.HTTPException):
  print(json.dumps({'unknown':method not in ['GET','HEAD'],'error':'Sandbox HTTP result unknown; no retry was sent'})); break
 finally: c.close()
'''

BROWSER_WORKER = r'''
const http=require('http'); const {chromium}=require('/opt/node/node_modules/playwright');
(async()=>{const p=JSON.parse(process.argv[1]); const consoleLines=[], failures=[]; let browser;
try{browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--renderer-process-limit=2','--disable-gpu'],chromiumSandbox:false});
const context=await browser.newContext({viewport:{width:1280,height:800},acceptDownloads:false});
await context.route('**/*',route=>{try{const u=new URL(route.request().url()); if(u.protocol==='http:' && u.hostname==='127.0.0.1' && p.ports.includes(Number(u.port||80)) && !u.username && !u.password) return route.continue();}catch(e){} return route.abort('blockedbyclient');});
if(typeof context.routeWebSocket!=='function')throw Error('Required WebSocket interception unavailable'); await context.routeWebSocket('**/*',socket=>socket.close());
const page=await context.newPage(); page.setDefaultTimeout(10000); page.on('console',m=>{if(consoleLines.length<200)consoleLines.push({type:m.type(),text:m.text().slice(0,2048)});}); page.on('requestfailed',r=>{if(failures.length<200)failures.push({url:r.url().slice(0,2048),error:r.failure()?.errorText});});
await page.goto(p.url,{waitUntil:'domcontentloaded',timeout:15000});
const server=http.createServer(async(req,res)=>{let raw=''; req.on('data',d=>{raw+=d;if(raw.length>262144)req.destroy();}); req.on('end',async()=>{try{const q=JSON.parse(raw); let result;
if(q.action==='query'){result=await page.locator(q.selector).allTextContents();}
else if(q.action==='click'){await page.locator(q.selector).click();result={clicked:true};}
else if(q.action==='input'){await page.locator(q.selector).fill(q.text);result={filled:true};}
else if(q.action==='screenshot'){await page.screenshot({path:'/workspace/'+q.path,fullPage:true});result={path:q.path};}
else if(q.action==='console'){result=consoleLines;}
else if(q.action==='network_failures'){result=failures;}
else if(q.action==='close'){await context.close();await browser.close();res.end(JSON.stringify({closed:true}));server.close();return;}
else throw Error('Unknown browser action'); res.end(JSON.stringify({result}));}catch(e){res.statusCode=400;res.end(JSON.stringify({error:'Browser action failed; page data and exception withheld'}));}});}); server.listen(p.rpcPort,'127.0.0.1',()=>console.log(JSON.stringify({ready:true,rpcPort:p.rpcPort})));}
catch(e){console.error('Isolated browser unavailable; no host fallback'); process.exit(2);}})();
'''


POSTGRES_CODE = r"""
import json,sys,subprocess,pathlib,os
p=json.loads(sys.argv[1]); base='/opt/postgresql/lib/postgresql/17/bin/'; directory=pathlib.Path('/workspace')/p['path']; root=pathlib.Path('/workspace').resolve()
if root not in directory.resolve().parents: raise ValueError('Postgres directory outside workspace')
# /workspace 是 sandbox 内部受控映射；真正边界由 execution workspace manifest 校验。
if p['action']=='init':
 directory.mkdir(parents=True,exist_ok=True)
 r=subprocess.run([base+'initdb','-D',str(directory),'--no-locale','--encoding=UTF8','--auth-local=trust','--auth-host=reject','-L','/opt/postgresql/share/postgresql/17'],capture_output=True,timeout=30)
 if r.returncode:print(json.dumps({'error':'Temporary PostgreSQL initialization failed; diagnostic withheld'}));sys.exit(2)
 print(json.dumps({'initialized':True,'engine':'PostgreSQL'}))
else:
 import ctypes
 lib=ctypes.CDLL('/opt/postgresql/lib/x86_64-linux-gnu/libpq.so.5')
 lib.PQconnectdb.argtypes=[ctypes.c_char_p];lib.PQconnectdb.restype=ctypes.c_void_p
 lib.PQstatus.argtypes=[ctypes.c_void_p];lib.PQstatus.restype=ctypes.c_int
 lib.PQexec.argtypes=[ctypes.c_void_p,ctypes.c_char_p];lib.PQexec.restype=ctypes.c_void_p
 lib.PQexecParams.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int];lib.PQexecParams.restype=ctypes.c_void_p
 for name in ['PQresultStatus','PQntuples','PQnfields']:
  f=getattr(lib,name);f.argtypes=[ctypes.c_void_p];f.restype=ctypes.c_int
 lib.PQgetvalue.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];lib.PQgetvalue.restype=ctypes.c_char_p
 lib.PQfname.argtypes=[ctypes.c_void_p,ctypes.c_int];lib.PQfname.restype=ctypes.c_char_p
 lib.PQclear.argtypes=[ctypes.c_void_p];lib.PQfinish.argtypes=[ctypes.c_void_p]
 conn=lib.PQconnectdb(('host=/tmp port='+str(p['port'])+' dbname=postgres connect_timeout=3').encode())
 if not conn or lib.PQstatus(conn)!=0:raise ValueError('Temporary PostgreSQL connection unavailable')
 try:
  setup=lib.PQexec(conn,b'SET statement_timeout=5000');lib.PQclear(setup)
  if p['readonly']:
   tx=lib.PQexec(conn,b'BEGIN READ ONLY');lib.PQclear(tx)
  result=lib.PQexecParams(conn,p['sql'].encode(),0,None,None,None,None,0)
  if lib.PQresultStatus(result) not in [1,2]:
   lib.PQclear(result);print(json.dumps({'error':'Temporary PostgreSQL query rejected; SQL and values withheld'}));sys.exit(2)
  columns=[lib.PQfname(result,n).decode() for n in range(lib.PQnfields(result))]
  rows=[[lib.PQgetvalue(result,i,n).decode('utf-8','replace')[:4096] for n in range(len(columns))] for i in range(min(100,lib.PQntuples(result)))]
  for n,col in enumerate(columns):
   if any(x in col.lower() for x in ['secret','token','credential','password','api_key','private_key']):
    for row in rows:row[n]='[REDACTED]'
  value={'columns':columns,'rows':rows,'truncated':lib.PQntuples(result)>100,'readonly':p['readonly']};lib.PQclear(result)
  if p['readonly']:
   tx=lib.PQexec(conn,b'ROLLBACK');lib.PQclear(tx)
  print(json.dumps(value))
 finally:lib.PQfinish(conn)

"""

def attach_services(cls):
    previous = cls.__init__

    def initialize(self, config_path):
        previous(self, config_path)
        self.dev_services_lock=threading.RLock()
        self.dev_services_registry = {}
        self.dev_postgres_registry = {}
        self.dev_browser_registry = {}
        self.dev_http_requests = {}
        self.dev_services_ledger = Path(self.state) / 'development-service-requests.json'
        self.dev_registry_path=Path(self.state)/'development-services-registry.json'
        if self.dev_registry_path.exists():
            try:
                registry=json.loads(self.dev_registry_path.read_text())
                self.dev_services_registry={tuple(x['key']):x['spec'] for x in registry.get('services',[])}
                self.dev_postgres_registry={tuple(x['key']):x['spec'] for x in registry.get('postgres',[])}
                self.dev_browser_registry=registry.get('browsers',{})
            except (ValueError,KeyError,TypeError):raise ValueError('Development service registry invalid; refusing replay') from None
        if self.dev_services_ledger.exists():
            try:
                stored = json.loads(self.dev_services_ledger.read_text())
                for entry in stored:
                    self.dev_http_requests[tuple(entry['key'])] = {'summary': entry['summary'], 'result': {'unknown': True, 'error': 'Service restarted; original outcome unavailable, no replay'}}
            except (ValueError, KeyError, TypeError):
                raise ValueError('Development request ledger is invalid; refusing mutation replay') from None

    def check(self, profile, workspaceId, control=False):
        if profile != PROFILE:
            raise ValueError('This operation requires an isolated autonomous-development workspace')
        self.dev_policy(profile)
        return self.dev_workspace(workspaceId, profile,allowExpired=True) if control else self.dev_workspace(workspaceId, profile)

    def execute(self, profile, workspaceId, argv, timeout=30, requestId=None, background=False,control=False,diagnostic=False):
        check(self, profile, workspaceId,control)
        return self.dev_exec_internal(profile, workspaceId, argv=argv, timeout=timeout, requestId=requestId or 'services-'+uuid.uuid4().hex, background=background,purpose='cleanup' if control else 'diagnostic' if diagnostic else 'helper',control=control or diagnostic)

    def pyjson(self, profile, workspaceId, code, data, timeout=30,control=False,diagnostic=False):
        result = execute(self, profile, workspaceId, ['/usr/bin/python3', '-c', code, json.dumps(data)], timeout=timeout,control=control,diagnostic=diagnostic)
        task=result.get('taskId') or result.get('id')
        deadline=time.monotonic()+timeout+5
        while result.get('status') in {'queued','running','starting','terminating','finalizing'} and time.monotonic()<deadline:
            time.sleep(.05)
            result=self.dev_task_status(task)
        if result.get('status') in {'queued','running','starting','terminating','finalizing'}:
            return {'pending':True,'unknown':True,'taskId':task,'error':'Helper still running; query task status and output, do not replay'}
        if result.get('status') not in {'completed', 'succeeded', 'failed', 'finished'}:
            raise ValueError('Isolated helper did not finish safely; query task status, do not retry a mutation')
        output=result.get('stdout','')
        if task and hasattr(self,'dev_output'):
            parts=[];offset=0
            while offset<262144:
                page=self.dev_output(task,stream='stdout',offset=offset,limit=min(65536,262144-offset))
                text=page.get('text',page.get('data',''))
                parts.append(text)
                next_offset=page.get('nextOffset')
                if not text or next_offset is None or next_offset<=offset:break
                offset=next_offset
            output=''.join(parts)
        try:
            value=json.loads(output.strip().splitlines()[-1])
        except (ValueError,IndexError):raise ValueError('Isolated helper failed; output withheld') from None
        from file_access import safe_output
        return safe_output(value)

    def atomic_private(self,path,value):
        temporary=path.with_suffix('.tmp')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)

    def persist_registry(self):
        value={'services':[{'key':list(key),'spec':{k:v for k,v in spec.items() if k!='argv'}} for key,spec in self.dev_services_registry.items()],
               'postgres':[{'key':list(key),'spec':spec} for key,spec in self.dev_postgres_registry.items()],
               'browsers':{sid:{k:v for k,v in spec.items() if k!='url'} for sid,spec in self.dev_browser_registry.items()}}
        atomic_private(self,self.dev_registry_path,value)

    def reserve(self,key,summary,unknown_message):
        with self.dev_services_lock:
            if key in self.dev_http_requests:
                before=self.dev_http_requests[key]
                if before['summary']!=summary:raise ValueError('requestId already bound to different contents')
                return before['result']
            self.dev_http_requests[key]={'summary':summary,'result':{'unknown':True,'error':unknown_message}}
            persist_requests(self)
        return None

    def ports(self, workspaceId):
        current = []
        with self.dev_services_lock:specs=list(self.dev_services_registry.values())
        for spec in specs:
            if spec['workspaceId'] == workspaceId and spec.get('taskId'):
                state = self.dev_task_status(spec['taskId'])
                if state.get('status') in {'running', 'starting', 'queued'}:
                    current.append(spec['port'])
        return current

    def persist_requests(self):
        records = [{'key': list(key), 'summary': value['summary']} for key, value in self.dev_http_requests.items()]
        if len(records) > 10000:
            raise ValueError('Development mutation ledger limit reached')
        atomic_private(self,self.dev_services_ledger,records)

    def dev_db(self, profile, workspaceId, path, sql, parameters=None, readonly=False, offset=0, limit=100, timeout=10, requestId=None):
        check(self, profile, workspaceId)
        relative(path)
        if not path.endswith(('.db', '.sqlite', '.sqlite3')):
            raise ValueError('Temporary SQLite requires an explicit database filename')
        if not isinstance(sql, str) or len(sql)>65536 or not isinstance(parameters or [], list):
            raise ValueError('Invalid bounded SQL or parameters')
        if type(readonly) is not bool:
            raise ValueError('readonly must be boolean')
        integer(offset,0,10000); integer(limit,1,1000); integer(timeout,1,30)
        if requestId is not None and (not isinstance(requestId,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',requestId)):raise ValueError('Invalid database requestId')
        data={'path':path,'sql':sql,'parameters':parameters or [],'readonly':readonly,'offset':offset,'limit':limit,'timeout':timeout}
        key=('db',workspaceId,requestId) if requestId else None
        summary=hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
        if not readonly and not requestId:
            raise ValueError('Mutating database calls require requestId')
        if key:
            cached=reserve(self,key,summary,'Original operation outcome unavailable; no replay')
            if cached is not None:return cached
        result=pyjson(self,profile,workspaceId,SQLITE_CODE,data,timeout+3,diagnostic=readonly)
        if key:self.dev_http_requests[key]['result']=result
        return result

    def dev_postgres(self,profile,workspaceId,path,action,requestId,sql=None,readonly=False,port=None):
        check(self,profile,workspaceId);relative(path)
        if not isinstance(requestId,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',requestId):raise ValueError('Invalid database requestId')
        if action not in {'init','query'}:raise ValueError('PostgreSQL action must be init or query')
        if not path.startswith('.dev-databases/'):raise ValueError('PostgreSQL requires an explicit .dev-databases directory')
        if action=='query' and (not isinstance(sql,str) or not 1<=len(sql)<=32768):raise ValueError('Bounded PostgreSQL query required')
        if type(readonly) is not bool:raise ValueError('readonly must be boolean')
        with self.dev_services_lock:
            registered=self.dev_postgres_registry.get((workspaceId,path))
            if action=='query':
                if not registered:raise ValueError('PostgreSQL instance not registered; call init for this .dev-databases path first')
                if registered.get('state')!='registered':raise ValueError('PostgreSQL initialization is pending or unavailable; query the original init request/task, do not retry initialization')
                if port is not None and port!=registered['port']:raise ValueError('PostgreSQL port conflicts with registered instance')
                port=registered['port']
            elif registered:
                port=registered['port'] if port is None else port
                if port!=registered['port']:raise ValueError('PostgreSQL path already registered with another port')
            else:port=18432 if port is None else port
            integer(port,1024,65535)
            if action=='init' and not registered:
                if any(x['workspaceId']==workspaceId and x['port']==port for x in self.dev_postgres_registry.values()):raise ValueError('PostgreSQL port already registered for another instance')
                self.dev_postgres_registry[(workspaceId,path)]={'workspaceId':workspaceId,'path':path,'port':port,'initRequestId':requestId,'state':'initializing'}
                persist_registry(self)
        params={'path':path,'action':action,'sql':sql,'readonly':readonly,'port':port}
        key=('postgres',workspaceId,requestId);summary=hashlib.sha256(json.dumps(params,sort_keys=True).encode()).hexdigest()
        cached=reserve(self,key,summary,'Original PostgreSQL operation unavailable; no replay')
        if cached is not None:return cached
        if action=='init' and registered:raise ValueError('PostgreSQL path already initialized; use its original init requestId or query')
        result=pyjson(self,profile,workspaceId,POSTGRES_CODE,params,40)
        result['path']=path;result['port']=port
        if action=='init' and result.get('initialized'):
            started=dev_service_start(self,profile,workspaceId,['/opt/postgresql/lib/postgresql/17/bin/postgres','-D','/workspace/'+path,'-k','/tmp','-h','','-p',str(port)],port,'postgres-'+hashlib.sha256(requestId.encode()).hexdigest(),timeout=min(240,self.dev_policy(profile).get('limits',{}).get('maxTimeoutSeconds',240)))
            result['serviceId']=started['serviceId']
            with self.dev_services_lock:
                self.dev_postgres_registry[(workspaceId,path)].update(state='registered',serviceId=started['serviceId'],taskId=started['taskId'])
                persist_registry(self)
        self.dev_http_requests[key]['result']=result
        return result

    def dev_environment_ready(self,profile,workspaceId):
        check(self,profile,workspaceId)
        code = r"""
import json,pathlib,importlib.util,sys,os
cache=pathlib.Path('/opt/dependency-cache/python');deps=pathlib.Path('/workspace/.dev-dependencies')
result={'python':sys.executable,'offlineCache':str(cache),'offlineCacheAvailable':cache.is_dir(),'offlinePackages':sorted(p.name.split('-')[0] for p in cache.glob('*.whl')) if cache.is_dir() else [],'dependencyTarget':str(deps),'installed':{name:bool(importlib.util.find_spec(name)) for name in ['pytest','ruff']},'protectedEnvironment':['PATH','HOME','TMPDIR','LANG','LC_ALL','LD_*','PYTHON*','NODE_*','GIT_*'],'node':pathlib.Path('/opt/node/bin/node').is_file(),'npm':pathlib.Path('/opt/node-v20/bin/npm').is_file(),'postgres':pathlib.Path('/opt/postgresql/lib/postgresql/17/bin/initdb').is_file(),'chrome':pathlib.Path('/opt/google/chrome/chrome').is_file()}
if deps.is_dir():
 sys.path.insert(0,str(deps));import importlib;importlib.invalidate_caches();result['installedInDependencyTarget']={name:bool(importlib.util.find_spec(name)) for name in ['pytest','ruff']}
else:result['installedInDependencyTarget']={'pytest':False,'ruff':False}
# 固定只读检查：不加载项目模块、不安装依赖、不启动业务代码。
import subprocess,shutil,re

def version(command):
 try:
  completed=subprocess.run(command,capture_output=True,timeout=2)
  value=completed.stdout[:100].decode('ascii',errors='replace').strip()
  return value if completed.returncode==0 and re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?',value) else None
 except (OSError,subprocess.TimeoutExpired):return None
node_version=version(['node','--version']);npm_version=version(['npm','--version'])
match=re.fullmatch(r'v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][A-Za-z0-9.-]+)?',node_version or '')
parts=tuple(map(int,match.groups())) if match else None
result['selectedNode']={'executable':shutil.which('node'),'version':node_version,'supportsModernVite':bool(parts and ((parts[0]==20 and parts>=(20,19,0)) or parts>=(22,12,0)))}
result['selectedNpm']={'executable':shutil.which('npm'),'version':npm_version}
result['node']=node_version is not None;result['npm']=npm_version is not None
result['offlineNpmCache']={'path':'/opt/dependency-cache/npm','available':pathlib.Path('/opt/dependency-cache/npm').is_dir(),'readOnly':True}
probe="const r=require('node:module').createRequire('/workspace/package.json');console.log(JSON.stringify(Object.fromEntries(['react','react-dom','typescript','vite','vitest','@fluentui/react-components'].map(n=>{try{r.resolve(n);return[n,true]}catch{return[n,false]}}))))"
try:
 completed=subprocess.run(['node','-e',probe],capture_output=True,timeout=2)
 result['frontendModulesResolvable']=json.loads(completed.stdout[:4096]) if completed.returncode==0 else None
except (OSError,ValueError,subprocess.TimeoutExpired):result['frontendModulesResolvable']=None
result['frontendResolutionBase']='/workspace/package.json'
result['readinessScope']='Root-workspace version and resolution checks only; nested app dependencies require a working-directory-specific check; not a project build or dependency-lock verification'
print(json.dumps(result))
"""
        return pyjson(self,profile,workspaceId,code,{},15,diagnostic=True)

    def dev_runtime_query(self,profile,targetId,sql,parameters=None,offset=0,limit=100,timeout=5):
        if profile!='readonly-runtime':raise ValueError('Runtime query requires readonly-runtime profile')
        policy=self.dev_policy(profile);targets=policy.get('databases',{})
        target=targets.get(targetId)
        if not isinstance(target,dict) or target.get('engine')!='sqlite' or target.get('readonly') is not True:raise ValueError('No locally configured readonly database target')
        path=Path(target.get('path',''))
        if not path.is_absolute() or not path.is_file() or any(p.is_symlink() for p in [path,*path.parents]):raise ValueError('Fixed readonly database path unavailable')
        roots=[Path(x).resolve() for x in policy.get('readRoots',[])]
        if not any(path==r or r in path.parents for r in roots):raise ValueError('Runtime database outside configured read roots')
        integer(offset,0,10000);integer(limit,1,1000);integer(timeout,1,10)
        if not isinstance(sql,str) or len(sql)>65536 or not isinstance(parameters or [],list):raise ValueError('Invalid bounded runtime query')
        import sqlite3
        if path == self.config_path or self.state == path or self.state in path.parents or self.config_path.parent in path.parents:
            raise ValueError('MCP private database targets are forbidden')
        if Path(str(path)+'-wal').exists() or Path(str(path)+'-journal').exists():
            raise ValueError('Readonly runtime SQLite requires a locally configured consistent snapshot without journal/WAL')
        from file_access import open_components
        fd=open_components(Path('/'),path.relative_to('/').as_posix(),os.O_RDONLY|os.O_NONBLOCK)
        conn=sqlite3.connect('file:/proc/self/fd/'+str(fd)+'?mode=ro&immutable=1',uri=True,timeout=1)
        try:
            conn.execute('PRAGMA query_only=ON');conn.enable_load_extension(False)
            denied={sqlite3.SQLITE_INSERT,sqlite3.SQLITE_UPDATE,sqlite3.SQLITE_DELETE,sqlite3.SQLITE_ATTACH,sqlite3.SQLITE_DETACH,sqlite3.SQLITE_PRAGMA,sqlite3.SQLITE_CREATE_TABLE,sqlite3.SQLITE_DROP_TABLE,sqlite3.SQLITE_ALTER_TABLE}
            conn.set_authorizer(lambda action,*args:sqlite3.SQLITE_DENY if action in denied or (action==sqlite3.SQLITE_READ and len(args)>1 and any(x in str(args[1]).lower() for x in ['secret','password','token','credential','api_key','private_key'])) else sqlite3.SQLITE_OK)
            end=time.monotonic()+timeout;conn.set_progress_handler(lambda:int(time.monotonic()>end),1000)
            cursor=conn.execute(sql,parameters or []);columns=[x[0] for x in cursor.description or []]
            rows=[list(x) for x in cursor.fetchmany(offset+limit+1)[offset:]]
            for n,col in enumerate(columns):
                if any(x in col.lower() for x in ['secret','token','credential','password','private_key','api_key']):
                    for row in rows:row[n]='[REDACTED]'
            from file_access import safe_output
            return safe_output({'columns':columns,'rows':rows[:limit],'truncated':len(rows)>limit,'readonly':True})
        except sqlite3.Error:raise ValueError('Readonly database query rejected; SQL and values withheld') from None
        finally:conn.close();os.close(fd)

    def dev_runtime_status(self,profile,serviceName):
        if profile!='readonly-runtime':raise ValueError('Runtime status requires readonly-runtime profile')
        policy=self.dev_policy(profile)
        names = self.cfg.get('serviceNames', {})
        fixed={names.get('mcp', 'notion-local-mcp.service'), names.get('tunnel', 'notion-local-mcp-tunnel.service')}
        if serviceName not in fixed or serviceName not in policy.get('services',[]):raise ValueError('Service is not a configured MCP status target')
        result=subprocess.run(['/usr/bin/systemctl','--user','show',serviceName,'--property=ActiveState,SubState,MainPID','--no-pager'],capture_output=True,timeout=5,text=True)
        if result.returncode:raise ValueError('Fixed MCP service status unavailable')
        return {'service':serviceName,**dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)}

    def dev_runtime_http(self,profile,targetId,method='GET',timeout=5,maxBytes=65536):
        if profile!='readonly-runtime':raise ValueError('Runtime HTTP requires readonly-runtime profile')
        policy=self.dev_policy(profile)
        if policy.get('network',{}).get('mode')!='loopback-only':raise ValueError('Readonly runtime network access is disabled')
        target=policy.get('httpTargets',{}).get(targetId)
        if not isinstance(target,dict) or target.get('readonly') is not True:raise ValueError('No locally configured readonly HTTP target')
        if method not in {'GET','HEAD'}:raise ValueError('Runtime HTTP only permits GET and HEAD')
        integer(timeout,1,10);integer(maxBytes,1024,65536)
        url=target.get('url','');p=urlsplit(url)
        if p.scheme!='http' or p.hostname!='127.0.0.1' or p.username or p.password or p.fragment or target.get('authentication') is not None:raise ValueError('Fixed runtime HTTP target invalid or needs an unsupported secret handle')
        if not isinstance(target.get('allowedPaths'),list) or p.path not in target['allowedPaths']:raise ValueError('Runtime HTTP path not explicitly authorized')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        request=urllib.request.Request(url,method=method)
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect).open(request,timeout=timeout) as response:
                data=response.read(maxBytes+1)
                from file_access import safe_output
                return safe_output({'status':response.status,'body':data[:maxBytes].decode('utf-8','replace'),'truncated':len(data)>maxBytes,'readonly':True})
        except Exception:raise ValueError('Fixed readonly HTTP request failed; response and credentials withheld') from None

    def dev_service_start(self, profile, workspaceId, argv, port, requestId, timeout=120):
        check(self,profile,workspaceId);integer(port,1024,65535)
        limits=self.dev_policy(profile).get('limits',{})
        maximum=limits.get('maxTimeoutSeconds',600)
        integer(maximum,1,3600);integer(timeout,1,maximum)
        if not isinstance(requestId,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',requestId):raise ValueError('Invalid service requestId')
        key=(workspaceId,requestId)
        summary=hashlib.sha256(json.dumps([argv,port,timeout]).encode()).hexdigest()
        with self.dev_services_lock:
            spec=self.dev_services_registry.get(key)
            if spec:
                if spec.get('summary')!=summary:raise ValueError('Service requestId already used with different parameters')
                return dict(spec)
            if any(x['workspaceId']==workspaceId and x['port']==port and x.get('state') in {'launching','unknown'} for x in self.dev_services_registry.values()) or port in ports(self,workspaceId):raise ValueError('Development service port already registered')
            spec={'serviceId':uuid.uuid4().hex,'workspaceId':workspaceId,'port':port,'url':f'http://127.0.0.1:{port}','summary':summary,'state':'launching'}
            self.dev_services_registry[key]=spec;persist_registry(self)
        try:
            result=execute(self,profile,workspaceId,argv,timeout,requestId='service-'+hashlib.sha256(requestId.encode()).hexdigest(),background=True)
            task=result.get('id') or result.get('taskId')
            if not task or result.get('status') not in {'queued','starting','running'}:raise ValueError('Isolated service did not start; no replay')
        except Exception:
            with self.dev_services_lock:spec['state']='unknown';persist_registry(self)
            raise
        with self.dev_services_lock:spec.update(taskId=task,state='registered');persist_registry(self)
        return dict(spec)

    def service(self, profile,workspaceId,serviceId):
        check(self,profile,workspaceId,control=True)
        with self.dev_services_lock:specs=list(self.dev_services_registry.values())
        for spec in specs:
            if spec['serviceId']==serviceId and spec['workspaceId']==workspaceId:return spec
        raise ValueError('Unknown development service')

    def dev_service_status(self,profile,workspaceId,serviceId):
        spec=service(self,profile,workspaceId,serviceId)
        if not spec.get('taskId'):return {'status':'unknown','serviceId':serviceId,'reason':'Service startup outcome unavailable; no replay'}
        return self.dev_task_status(spec['taskId'])

    def dev_service_stop(self,profile,workspaceId,serviceId):
        spec=service(self,profile,workspaceId,serviceId)
        if not spec.get('taskId'):return {'status':'unknown','serviceId':serviceId,'reason':'Service task not registered; use workspace execution cleanup'}
        return self.dev_cancel(spec['taskId'])

    def dev_http(self,profile,workspaceId,url,method='GET',body='',contentType='application/json',requestId=None,timeout=10,maxBytes=65536):
        check(self,profile,workspaceId); allowed=ports(self,workspaceId); origin(url,allowed)
        if method not in {'GET','HEAD','POST','PUT','PATCH','DELETE'}:raise ValueError('Unsupported HTTP method')
        if not isinstance(body,str) or len(body.encode())>262144:raise ValueError('HTTP body exceeds limit')
        if contentType not in {'application/json','text/plain','application/x-www-form-urlencoded'}:raise ValueError('Unsupported request content type')
        integer(timeout,1,30);integer(maxBytes,1024,262144)
        if method not in {'GET','HEAD'} and not requestId:raise ValueError('Mutating HTTP requests require requestId')
        if requestId is not None and (not isinstance(requestId,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',requestId)):raise ValueError('Invalid HTTP requestId')
        params={'url':url,'method':method,'body':base64.b64encode(body.encode()).decode(),'contentType':contentType,'requestId':requestId,'ports':allowed,'timeout':timeout,'maximum':maxBytes}
        key=('http',workspaceId,requestId) if requestId else None
        summary=hashlib.sha256(json.dumps(params,sort_keys=True).encode()).hexdigest()
        if key:
            cached=reserve(self,key,summary,'Original request outcome unavailable; no replay')
            if cached is not None:return cached
        result=pyjson(self,profile,workspaceId,HTTP_CODE,params,timeout+3)
        # 原始字节可能包含秘密，不向客户端回传绕过文本保护的base64。
        result.pop('bodyBase64',None)
        if key:self.dev_http_requests[key]['result']=result
        return result

    def dev_browser_open(self,profile,workspaceId,url,requestId,timeout=120):
        check(self,profile,workspaceId);allowed=ports(self,workspaceId);origin(url,allowed);integer(timeout,1,3600)
        if not isinstance(requestId,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',requestId):raise ValueError('Invalid browser requestId')
        url_hash=hashlib.sha256(url.encode()).hexdigest()
        with self.dev_services_lock:
            browser_specs=list(self.dev_browser_registry.values())
            for existing in browser_specs:
                if existing['workspaceId']==workspaceId and existing['requestId']==requestId:
                    if existing.get('urlHash')!=url_hash or existing.get('timeout')!=timeout:raise ValueError('Browser requestId bound to other arguments')
                    return {k:v for k,v in existing.items() if k!='requestId'}
            occupied=allowed+[x['rpcPort'] for x in browser_specs if x['workspaceId']==workspaceId]
            rpc=next((p for p in range(42000,42100) if p not in occupied),None)
            if rpc is None:raise ValueError('Browser session port budget exceeded')
            sid=uuid.uuid4().hex
            spec={'sessionId':sid,'workspaceId':workspaceId,'rpcPort':rpc,'urlHash':url_hash,'requestId':requestId,'timeout':timeout,'state':'launching'}
            self.dev_browser_registry[sid]=spec;persist_registry(self)
        data={'url':url,'ports':allowed,'rpcPort':rpc}
        try:
            result=execute(self,profile,workspaceId,['/opt/node/bin/node','-e',BROWSER_WORKER,json.dumps(data)],timeout,requestId='browser-'+hashlib.sha256(requestId.encode()).hexdigest(),background=True)
            task=result.get('id') or result.get('taskId')
            if not task or result.get('status') not in {'queued','running','starting'}:raise ValueError('Isolated browser launch failed')
            with self.dev_services_lock:spec.update(taskId=task,state='starting');persist_registry(self)
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                state=self.dev_task_status(task)
                if '"ready":true' in state.get('stdout','').replace(' ',''):
                    with self.dev_services_lock:spec['state']='ready';persist_registry(self)
                    return {k:v for k,v in spec.items() if k!='requestId'}
                if state.get('exitCode') is not None or state.get('status') in {'unknown','blocked','termination_failed'}:raise ValueError('Isolated browser unavailable; no host fallback')
                time.sleep(.1)
            self.dev_cancel(task)
            raise ValueError('Isolated browser startup timeout')
        except Exception:
            with self.dev_services_lock:spec['state']='unknown';persist_registry(self)
            raise

    def dev_browser_action(self,profile,workspaceId,sessionId,action,selector=None,text=None,path=None):
        check(self,profile,workspaceId,control=action=='close')
        spec=self.dev_browser_registry.get(sessionId)
        if not spec or spec['workspaceId']!=workspaceId:raise ValueError('Unknown isolated browser session')
        if not spec.get('taskId'):raise ValueError('Browser startup outcome unknown; use workspace execution cleanup')
        if action not in {'query','click','input','screenshot','console','network_failures','close'}:raise ValueError('Unsupported browser action')
        data={'action':action}
        if action in {'query','click','input'}:
            if not isinstance(selector,str) or not 1<=len(selector)<=2048:raise ValueError('Bounded DOM selector required')
            data['selector']=selector
        if action=='input':
            if not isinstance(text,str) or len(text)>65536:raise ValueError('Bounded input text required')
            data['text']=text
        if action=='screenshot':
            relative(path)
            if not path.startswith('.dev-artifacts/') or not path.endswith('.png'):raise ValueError('Screenshot must use .dev-artifacts/*.png')
            data['path']=path
        result=pyjson(self,profile,workspaceId,HTTP_CODE,{'url':f'http://127.0.0.1:{spec["rpcPort"]}','method':'POST','body':base64.b64encode(json.dumps(data).encode()).decode(),'contentType':'application/json','requestId':None,'ports':[spec['rpcPort']],'timeout':20,'maximum':131072},25,control=action=='close',diagnostic=action in {'query','console','network_failures'})
        try: parsed=json.loads(result.get('body',''))
        except ValueError:raise ValueError('Browser action result unavailable; do not blindly repeat') from None
        from file_access import safe_output
        if action=='close':
            if parsed.get('closed') is not True:raise ValueError('Browser close was not confirmed; use registered browser close or execution cleanup')
            self.dev_cancel(spec['taskId'])
            with self.dev_services_lock:
                self.dev_browser_registry.pop(sessionId,None);persist_registry(self)
        return safe_output(parsed)

    def dev_browser_close(self,profile,workspaceId,sessionId):
        check(self,profile,workspaceId,control=True)
        with self.dev_services_lock:spec=self.dev_browser_registry.get(sessionId)
        if not spec or spec['workspaceId']!=workspaceId:raise ValueError('Unknown isolated browser session')
        if not spec.get('taskId'):return {'closed':False,'status':'unknown','reason':'Browser task registration unavailable; use workspace execution cleanup'}
        try:return dev_browser_action(self,profile,workspaceId,sessionId,'close')
        except Exception:
            cancelled=self.dev_cancel(spec['taskId'])
            closed=cancelled.get('status') in {'cancelled','succeeded','failed','timeout'} and cancelled.get('cgroupTerminated') is True
            if closed:
                with self.dev_services_lock:self.dev_browser_registry.pop(sessionId,None);persist_registry(self)
            return {'closed':closed,'taskId':spec['taskId'],'cleanupMethod':'cancel-registered-browser','taskStatus':cancelled.get('status','unknown')}

    cls.__init__=initialize
    for name,fn in locals().copy().items():
        if name.startswith('dev_'):
            import functools
            @functools.wraps(fn)
            def locked(self,*args,_fn=fn,**kwargs):
                try:result=_fn(self,*args,**kwargs)
                except Exception:
                    if hasattr(self,'audit_event'):self.audit_event(_fn.__name__,'rejected_or_failed')
                    raise
                if hasattr(self,'audit_event'):self.audit_event(_fn.__name__,'returned')
                return result
            setattr(cls,name,locked)
    return cls


TOOL_DESCRIPTIONS = {
 'dev_environment_ready':'Check the isolated runtime and exact offline Python cache /opt/dependency-cache/python. Reports pytest/Ruff installed in runtime or .dev-dependencies; never installs packages or overrides protected environment variables.',
 'dev_postgres':'Initialize or query a real temporary PostgreSQL cluster inside the isolated development workspace. No host database or host service. Each operation requires requestId; query resolves an omitted port from the initialized .dev-databases path and rejects explicit port conflicts. readonly uses a READ ONLY transaction.',
 'dev_runtime_query':'Run a bounded query against an exact locally configured SQLite target using mode=ro, query_only and an authorizer. Default targets are empty. Sensitive columns withheld.',
 'dev_runtime_status':'Read status for an exact configured MCP service only. Does not restart or change services.',
 'dev_runtime_http':'Read an exact locally configured runtime health URL via GET/HEAD. Default target set is empty. Redirects and authenticated targets are rejected.',
 'dev_db':'Execute one bounded parameterized SQLite statement inside an isolated workspace. Writes require requestId and are never replayed. readonly enforces mode=ro, query_only and authorizer; runtime databases are not accepted.',
 'dev_service_start':'Start a temporary argv service inside the workspace network namespace. Register its isolated loopback port. Never manages host systemd or transaction services.',
 'dev_service_status':'Read status of one registered temporary development service.',
 'dev_service_stop':'Cancel one registered isolated service task.',
 'dev_http':'Call only registered isolated HTTP services; validate every redirect, cap size and time. Mutations require requestId; unknown results are never replayed.',
 'dev_browser_open':'Open an independent headless Chromium session inside the real development sandbox. Only registered temporary service origins are allowed. Never reads daily browser profiles.',
 'dev_browser_action':'Query DOM, click, input, screenshot, read console/network failures, or close one isolated browser session. Screenshots go to .dev-artifacts/*.png.',
 'dev_browser_close':'Close one isolated browser session and its independent profile.'}

def schema(properties,required):return {'type':'object','properties':properties,'required':required,'additionalProperties':False}
STR={'type':'string','maxLength':4096}; COMMON={'profile':{'type':'string','enum':[PROFILE]},'workspaceId':STR}
TOOL_SCHEMAS={
 'dev_db':schema({**COMMON,'path':STR,'sql':{'type':'string','maxLength':65536},'parameters':{'type':['array','null'],'maxItems':1000,'items':{'type':['string','number','integer','boolean','null']}},'readonly':{'type':'boolean'},'offset':{'type':'integer','minimum':0,'maximum':10000},'limit':{'type':'integer','minimum':1,'maximum':1000},'timeout':{'type':'integer','minimum':1,'maximum':30},'requestId':{'type':['string','null'],'maxLength':100}},['profile','workspaceId','path','sql']),
 'dev_service_start':schema({**COMMON,'argv':{'type':'array','minItems':1,'maxItems':128,'items':{'type':'string','maxLength':262144}},'port':{'type':'integer','minimum':1024,'maximum':65535},'requestId':STR,'timeout':{'type':'integer','minimum':1,'maximum':3600}},['profile','workspaceId','argv','port','requestId']),
 'dev_service_status':schema({**COMMON,'serviceId':STR},['profile','workspaceId','serviceId']),
 'dev_service_stop':schema({**COMMON,'serviceId':STR},['profile','workspaceId','serviceId']),
 'dev_http':schema({**COMMON,'url':STR,'method':{'type':'string','enum':['GET','HEAD','POST','PUT','PATCH','DELETE']},'body':{'type':'string','maxLength':262144},'contentType':STR,'requestId':{'type':['string','null'],'maxLength':100},'timeout':{'type':'integer','minimum':1,'maximum':30},'maxBytes':{'type':'integer','minimum':1024,'maximum':262144}},['profile','workspaceId','url']),
 'dev_browser_open':schema({**COMMON,'url':STR,'requestId':STR,'timeout':{'type':'integer','minimum':1,'maximum':3600}},['profile','workspaceId','url','requestId']),
 'dev_browser_action':schema({**COMMON,'sessionId':STR,'action':{'type':'string','enum':['query','click','input','screenshot','console','network_failures','close']},'selector':{'type':['string','null'],'maxLength':2048},'text':{'type':['string','null'],'maxLength':65536},'path':{'type':['string','null'],'maxLength':2048}},['profile','workspaceId','sessionId','action']),
 'dev_browser_close':schema({**COMMON,'sessionId':STR},['profile','workspaceId','sessionId'])}

TOOL_SCHEMAS['dev_postgres']=schema({**COMMON,'path':STR,'action':{'type':'string','enum':['init','query']},'requestId':STR,'sql':{'type':['string','null'],'maxLength':32768},'readonly':{'type':'boolean'},'port':{'type':['integer','null'],'minimum':1024,'maximum':65535,'default':None}},['profile','workspaceId','path','action','requestId'])
TOOL_SCHEMAS['dev_runtime_query']=schema({'profile':{'type':'string','enum':['readonly-runtime']},'targetId':STR,'sql':{'type':'string','maxLength':65536},'parameters':{'type':['array','null'],'maxItems':1000,'items':{'type':['string','number','boolean','null']}},'offset':{'type':'integer','minimum':0,'maximum':10000},'limit':{'type':'integer','minimum':1,'maximum':1000},'timeout':{'type':'integer','minimum':1,'maximum':10}},['profile','targetId','sql'])

TOOL_SCHEMAS['dev_runtime_status']=schema({'profile':{'type':'string','enum':['readonly-runtime']},'serviceName':STR},['profile','serviceName'])
TOOL_SCHEMAS['dev_runtime_http']=schema({'profile':{'type':'string','enum':['readonly-runtime']},'targetId':STR,'method':{'type':'string','enum':['GET','HEAD']},'timeout':{'type':'integer','minimum':1,'maximum':10},'maxBytes':{'type':'integer','minimum':1024,'maximum':65536}},['profile','targetId'])

TOOL_SCHEMAS['dev_environment_ready']=schema(dict(COMMON),['profile','workspaceId'])
