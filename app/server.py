#!/usr/bin/env python3
"""Official MCP SDK Streamable HTTP adapter. Requires requirements.txt."""
import argparse, asyncio, contextlib, hmac, inspect, json, os, time
from pathlib import Path
import jsonschema
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server import NotificationOptions
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount
import uvicorn
from core import Backend,VERSION,OUTPUT_LIMIT
from file_access import safe_output, error_code, within, sensitive
from dev_diagnostics import application_status, diagnostic_for, DevelopmentDenied

DESCRIPTIONS={
 'list_projects':'List configured project IDs and enabled permissions. Never guess project IDs.',
 'health':'Read version, availability and running-task count.',
 'list_directory':'List authorized entries including hidden files, with offset/limit pagination.',
 'read_text_file':'Read a UTF-8 file up to 2 MiB; returns its SHA256. Use lines for larger files.',
 'read_file_lines':'Read 1-based lines with 32 MiB scan, 64 KiB line and 128 KiB output caps.',
 'search_files':'Find accessible files by case-sensitive glob; check scanComplete.',
 'search_text':'Literal UTF-8 search; returns line numbers and bounded snippets. Check scanComplete and skippedFiles.',
 'get_file_hash':'Get a file SHA256 before planning edits.',
 'plan_files':'Preview 1 to 20 file changes. Each existing file needs expectedHash and content or exact edits. Returns a local-approval ID; never writes.',
 'create_text_file':'Preview creation of a new UTF-8 file. No overwrite. Requires local operator approval before apply_change.',
 'apply_text_edits':'Preview multiple unique exact edits in one file with expectedHash. Does not write.',
 'edit_file':'Compatibility preview only. dryRun=false is rejected; use local approval and apply_change.',
 'apply_change':'Apply a file plan explicitly approved on the local machine. Single-use, expires, conflicts rejected. Multi-file application is not transactional; inspect partial failures.',
 'list_snapshots':'List private file snapshots for this project.',
 'restore_snapshot':'Preview restoration from snapshot. Does not delete newly created files. Local approval required.',
 'get_audit':'Read bounded audit metadata; does not include file contents or credentials.',
 'git_status':'Read tracked accessible paths in a normal repository; untracked paths excluded.',
 'git_diff':'Read Git diff for one accessible explicit path; disables textconv and external diff.',
 'git_log':'Read bounded path-specific commit history.',
 'plan_git':'Preview branch, commit, fast-forward-only merge or allowlisted HTTPS push. Disabled by default. Local approval required; no force-push or reset.',
 'apply_git':'Execute one locally approved Git plan. Not transactional. Check Git status after failures.',
 'build_index':'Build/update private hash-based symbol index. Python AST; JS/TS heuristic. Bounded scan.',
 'search_symbols':'Search index definitions. Checks hashes and reports stale entries.',
 'find_references':'Find literal symbol occurrences, not semantic references; includes strings/comments.',
 'project_summary':'Get filename-based project overview without executing manifests.',
 'tail_log':'Read/follow bounded log bytes using cursor. Literal filters; since assumes ISO prefix. Best-effort redaction; not guaranteed.',
 'document_preview':'Read CSV/TSV rows, extract PDF text (no OCR), or return resized image. Best-effort text redaction; image pixels are not redacted.',
 'plan_task':'Preview an operator-configured digest-pinned Docker task with sanitized workspace hashes. No unrestricted commands.',
 'run_project_task':'Run a locally approved Docker task offline, read-only, with resource/time/output limits. Docker must already be installed and image locally available; no host fallback.',
 'get_task_status':'Read background job status/output.',
 'cancel_task':'Request cancellation of a managed task.'}
DESCRIPTIONS.update({
 'get_capabilities':'Read supported features, limits and current project permissions. Capability presence is not permission or production readiness.',
 'get_service_status':'Read MCP and tunnel status, plus the current HTTPS MCP URL from the active tunnel announcement. Never returns credentials or changes services.',
 'git_branches':'List bounded local/remote branch refs in a normal authorized Git repository.',
 'git_staged_paths':'Read accessible paths currently in the Git index.'})
DESCRIPTIONS['plan_git']='Preview branch, stage, commit, commit_staged, fast-forward merge or allowlisted HTTPS push. Explicit paths and local approval required. No force/reset.'
DESCRIPTIONS['find_references']='Search literal occurrences or Python AST name/attribute occurrences (mode=python_ast). AST mode excludes comments/strings, but does not resolve cross-module symbol identity.'
DESCRIPTIONS['project_summary']='Read bounded dependency names, declared entry points, Python imports and test paths. Never executes project code or manifests.'
DESCRIPTIONS.update({
 'resolve_path':'Route an absolute path to the most specific authorized project. Rejects traversal and outside roots.',
 'read_binary_file':'Read bounded non-sensitive bytes as base64 and SHA256.',
 'search_paths':'Search names of files, directories and symlinks, including hidden entries. Bounded and paginated.',
 'get_path_hash':'Get content hash for a file, or manifest hash for directory/link operations. linkMode distinguishes link from target.',
 'write_binary_file':'Preview a base64 file write. Existing file requires expectedHash. Local approval required.',
 'create_directory':'Preview creation of one directory; parent must exist. Local approval required.',
 'copy_path':'Preview file/directory/link copy. Source hash required, explicit destination hash for overwrite; local approval required.',
 'move_path':'Preview recoverable file/directory/link move. Source and overwritten destination hashes bound to local approval.',
 'rename_path':'Preview rename using move semantics; local approval required.',
 'delete_path':'Preview recoverable deletion of an explicit file/directory/link; expectedHash and local approval required.',
 'plan_file_operations':'Preview up to 20 independent write/mkdir/copy/move/delete operations. Precise paths and hashes bound to single-use local approval.',
 'validate_configuration':'Read current validated configuration summary and hash without private values.',
 'plan_service_restart':'Preview restart of this MCP service only. Independent local administrator approval required.',
 'apply_service_restart':'Schedule a single locally approved MCP restart. Never replay automatically; reconnect and check health.'})
DESCRIPTIONS.update({
 'dev_execution_diagnose':'Read project-level execution safety blockers, related tasks and workspaces. Cleanup releases resources but does not clear the block.',
 'dev_execution_preserve':'Create a complete private preservation copy before closing a modified development workspace. A failed preservation keeps the original tree.',
 'dev_execution_request_recovery':'Create a time-limited local recovery request bound to one safety event, workspace tree hash and configuration hash. Does not approve it.',
 'dev_execution_apply_recovery':'Apply one unused locally approved recovery request after rechecking the exact safety event, hashes, stopped resources and safe tree.'})
DESCRIPTIONS['restore_snapshot']='Preview restoration of completed changes, including recoverable deletion/overwrite and new files. Current hashes checked. Local approval required.'
PLATFORM_MODULES = []
for module_name in ('dev_workspace', 'dev_execution', 'dev_services', 'dev_maintenance'):
    module = __import__(module_name)
    PLATFORM_MODULES.append(module)
    DESCRIPTIONS.update(module.TOOL_DESCRIPTIONS)
PLATFORM_SCHEMAS = {name: spec for module in PLATFORM_MODULES for name, spec in module.TOOL_SCHEMAS.items()}
PLATFORM_READONLY = {'dev_workspace_list', 'dev_read', 'dev_list', 'dev_diff', 'dev_artifacts', 'dev_task_status', 'dev_output', 'dev_service_status', 'dev_runtime_query', 'dev_runtime_status', 'dev_runtime_http', 'dev_environment_ready', 'dev_execution_diagnose'}

READONLY=set(DESCRIPTIONS)-{'apply_change','apply_git','run_project_task','cancel_task','build_index','apply_service_restart'}
READONLY.difference_update(set(PLATFORM_SCHEMAS) - PLATFORM_READONLY)

OVERRIDES={
 'changes':{'type':'array','minItems':1,'maxItems':20,'items':{'type':'object','additionalProperties':False,'properties':{'path':{'type':'string'},'expectedHash':{'type':['string','null']},'content':{'type':'string'},'edits':{'type':'array','minItems':1,'maxItems':100,'items':{'type':'object','properties':{'oldText':{'type':'string','minLength':1},'newText':{'type':'string'}},'required':['oldText','newText'],'additionalProperties':False}}},'required':['path']}},
 'edits':{'type':'array','minItems':1,'maxItems':100,'items':{'type':'object','properties':{'oldText':{'type':'string','minLength':1},'newText':{'type':'string'}},'required':['oldText','newText'],'additionalProperties':False}},
 'paths':{'type':['array','null'],'maxItems':50,'items':{'type':'string'}},
 'cursor':{'type':['object','null'],'properties':{'inode':{'type':'integer','minimum':0},'offset':{'type':'integer','minimum':0}},'required':['inode','offset'],'additionalProperties':False}}

OP_PROPERTIES={
 'operation':{'type':'string','enum':['write','mkdir','copy','move','delete']},
 'path':{'type':'string','minLength':1,'maxLength':2048},
 'destination':{'type':'string','minLength':1,'maxLength':2048},
 'expectedHash':{'type':['string','null'],'pattern':'^[0-9a-f]{64}$'},
 'destinationExpectedHash':{'type':['string','null'],'pattern':'^[0-9a-f]{64}$'},
 'content':{'type':'string','maxLength':2097152},
 'contentBase64':{'type':'string','maxLength':2796204},
 'overwrite':{'type':'boolean'},
 'linkMode':{'type':'string','enum':['link','target']}}
OVERRIDES['operations']={'type':'array','minItems':1,'maxItems':20,'items':{
 'type':'object','additionalProperties':False,'properties':OP_PROPERTIES,'required':['operation','path']}}
OVERRIDES['contentBase64']=OP_PROPERTIES['contentBase64']
OVERRIDES['linkMode']=OP_PROPERTIES['linkMode']

def tool_schema(fn):
    properties={}; required=[]
    for name,param in inspect.signature(fn).parameters.items():
        default=param.default; optional=default is not inspect.Parameter.empty
        if name in OVERRIDES: schema=dict(OVERRIDES[name])
        elif name in {'offset','limit','maxDepth','startLine','endLine'}: schema={'type':['integer','null'] if optional and default is None else 'integer','minimum':0 if name=='offset' else 0 if name=='maxDepth' else 1,'maximum':10000000 if name in {'startLine','endLine'} else 20000 if name=='offset' else 32 if name=='maxDepth' else 1000}
        elif name in {'dryRun','staged','caseSensitive','write','overwrite'}: schema={'type':'boolean'}
        else: schema={'type':['string','null'] if optional and default is None else 'string','maxLength':2*1024*1024 if name in {'content','oldText','newText'} else 2048}
        if optional: schema['default']=default
        else: required.append(name)
        properties[name]=schema
    return {'type':'object','properties':properties,'required':required,'additionalProperties':False}

def safe_tool_output(name, arguments, value):
    source_aware = {'read_text_file', 'read_file_lines', 'dev_read', 'git_diff'}
    source_path = arguments.get('path') if name in source_aware and isinstance(arguments, dict) else None
    return safe_output(value, source_path)


class Guard:
    def __init__(self,app,token_path,audit=None,limits=None):
        self.app=app; self.token_path=token_path; self.recent=[]; self.active=0; self.active_methods={}; self.audit=audit
        self.limits={'readPerMinute':600,'discoveryPerMinute':300,'writePerMinute':60,'totalPerMinute':900,'concurrency':32}
        self.limits.update(limits or {})
        if set(self.limits)!={'readPerMinute','discoveryPerMinute','writePerMinute','totalPerMinute','concurrency'} or any(type(v) is not int or not 1<=v<=10000 for v in self.limits.values()):
            raise ValueError('Invalid rateLimits configuration')
    async def __call__(self,scope,receive,send):
        if scope['type']!='http': return await self.app(scope,receive,send)
        headers=dict(scope['headers']); supplied=headers.get(b'authorization',b'')
        token=self.token_path.read_text().strip()
        if len(token)<32 or not hmac.compare_digest(supplied,b'Bearer '+token.encode()):
            return await JSONResponse({'error':'Unauthorized'},status_code=401)(scope,receive,send)
        if b'origin' in headers: return await JSONResponse({'error':'Browser origins rejected'},status_code=403)(scope,receive,send)
        try: length=int(headers.get(b'content-length',b'0'))
        except ValueError: length=-1
        if length<0 or length>4*1024*1024: return await JSONResponse({'error':'Request too large'},status_code=413)(scope,receive,send)
        chunks=[]; total=0
        while True:
            try: message=await asyncio.wait_for(receive(),timeout=15)
            except asyncio.TimeoutError:
                return await JSONResponse({'error':'Request body timeout'},status_code=408)(scope,receive,send)
            if message['type']=='http.disconnect': return
            body=message.get('body',b''); total+=len(body)
            if total>4*1024*1024:
                return await JSONResponse({'error':'Request too large'},status_code=413)(scope,receive,send)
            chunks.append(body)
            if not message.get('more_body',False): break
        request_body=b''.join(chunks)
        method_name=''
        try:
            request=json.loads(request_body)
            method_name=request.get('method','')
            tool_name=request.get('params',{}).get('name','')
        except (ValueError,AttributeError): tool_name=''
        discovery=method_name in {'initialize','tools/list','ping','notifications/initialized'}
        bucket='discovery' if discovery else 'write' if tool_name not in READONLY and bool(tool_name) else 'read'
        now=time.monotonic()
        self.recent=[(t,b) for t,b in self.recent if now-t<60]
        matching=[t for t,b in self.recent if b==bucket]
        rate=self.limits[bucket+'PerMinute']
        if len(self.recent)>=self.limits['totalPerMinute'] or len(matching)>=rate or self.active>=self.limits['concurrency']:
            reason='concurrency_limit' if self.active>=self.limits['concurrency'] else 'request_rate_limit'
            oldest=self.recent[0][0] if len(self.recent)>=self.limits['totalPerMinute'] else matching[0] if matching else now
            retry=2 if reason=='concurrency_limit' else max(1,int(60-(now-oldest))+1)
            if self.audit: self.audit('http_guard',reason)
            return await JSONResponse({'error':'Rate limit','reason':reason,'bucket':bucket,'retryAfterSeconds':retry,
                'retryPolicy':'Retry discovery/read after delay. Never automatically replay a write; query its original requestId after an uncertain result.'},
                status_code=429,headers={'Retry-After':str(retry)})(scope,receive,send)
        if scope.get('method')=='GET' and scope.get('path')=='/mcp':
            self.recent.append((now,bucket))
            return await JSONResponse({'error':'GET stream not supported'},status_code=405,headers={'Allow':'POST'})(scope,receive,send)
        original_receive=receive
        delivered=False
        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered=True
                return {'type':'http.request','body':request_body,'more_body':False}
            return await original_receive()
        receive=replay_receive
        method=scope.get('method','OTHER')
        if method not in {'GET','POST','DELETE','PUT','PATCH','OPTIONS','HEAD'}: method='OTHER'
        self.recent.append((now,bucket)); self.active+=1; self.active_methods[method]=self.active_methods.get(method,0)+1; received=0
        async def bounded_receive():
            nonlocal received
            message=await receive()
            if message['type']=='http.request':
                received+=len(message.get('body',b''))
                if received>4*1024*1024: raise ValueError('Request body exceeds bound')
            return message
        try: await self.app(scope,bounded_receive,send)
        finally:
            self.active-=1
            self.active_methods[method]-=1

def make_app(config,token_path):
    backend=Backend(config)
    credential=Path(token_path).resolve(strict=True)
    authentication_handle = credential.read_text().strip()
    if len(authentication_handle)<32: raise ValueError('Credential must contain at least 32 characters')
    if credential.stat().st_mode & 0o077: raise ValueError('Credential must not be accessible to group/other users')
    if not any(within(credential, private) for private in backend.private_paths):
        raise ValueError('Credential must be inside protected administrator scope')
    backend.dev_maintenance_auth = authentication_handle
    server=Server('linux-local-code-v2',version=VERSION)
    schemas={name:PLATFORM_SCHEMAS[name] if name in PLATFORM_SCHEMAS else tool_schema(getattr(backend,name)) for name in DESCRIPTIONS}
    backend.dev_discovery_schemas = schemas
    @server.list_tools()
    async def tools():
        return [types.Tool(name=name,description=description,inputSchema=schemas[name],annotations=types.ToolAnnotations(readOnlyHint=name in READONLY,destructiveHint=name in {'apply_change','apply_git','run_project_task'},openWorldHint=name=='apply_git')) for name,description in DESCRIPTIONS.items()]
    def execute(name,args):
        if name in PLATFORM_SCHEMAS:
            return getattr(backend,name)(**args)
        with backend.lock:
            if name in {'read_file_lines','tail_log','document_preview','git_diff','git_log'}:
                target=backend.allowed(args['project'],args['path'])
                if sensitive(target): raise ValueError('Sensitive content stays local; use hashes and locally approved file plans')
            if name=='search_text':
                # 搜索不能作为精确敏感文件授权的内容输出渠道。
                grants=backend.sensitive_grants
                backend.sensitive_grants=[]
                try: return backend.search_text(**args)
                finally: backend.sensitive_grants=grants
            return getattr(backend,name)(**args)
    @server.call_tool()
    async def call(name,arguments):
        if name not in DESCRIPTIONS: raise ValueError('Unknown tool')
        try:
            jsonschema.validate(arguments,schemas[name])
            result=await asyncio.to_thread(execute,name,arguments)
            backend.audit_event(name,application_status(result),arguments.get('project'),paths=[arguments['path']] if isinstance(arguments.get('path'),str) else None)
            if name=='document_preview' and result.get('kind')=='image':
                encoded=result.pop('base64')
                return [types.ImageContent(type='image',mimeType=result['mimeType'],data=encoded),types.TextContent(type='text',text=json.dumps(result,ensure_ascii=False))]
            output=json.dumps(safe_tool_output(name,arguments,result),ensure_ascii=False)
            if len(output.encode())>3*1024*1024: raise ValueError('Tool result too large')
            return [types.TextContent(type='text',text=output)]
        except Exception as error:
            backend.audit_event(name,'error',arguments.get('project'),paths=[arguments['path']] if isinstance(arguments.get('path'),str) else None)
            # Avoid SDK tracebacks leaking absolute paths/private state.
            message=error_code(error) if not isinstance(error,jsonschema.exceptions.ValidationError) else 'Invalid tool arguments; use the tool schema'
            if isinstance(error,DevelopmentDenied):
                diagnostic=diagnostic_for(error,arguments.get('workspaceId'),name,
                    'sync' if name=='dev_sync' else 'cleanup' if 'cleanup' in name else 'preflight')
                backend.audit.info(json.dumps({'event':'development_denied',**diagnostic}))
                return types.CallToolResult(content=[types.TextContent(type='text',
                    text=json.dumps({'error':str(error),'diagnostic':diagnostic}))],isError=True)
            if '/' in message and not isinstance(error,ValueError): message='Operation failed'
            if getattr(error, 'classification', None):
                message=json.dumps({'error':message,'code':error.code,
                    'classification':error.classification,'details':error.details},ensure_ascii=False)
            return types.CallToolResult(content=[types.TextContent(type='text',text=safe_output(message[:1000]))],isError=True)
    manager=StreamableHTTPSessionManager(app=server,event_store=None,json_response=True,stateless=True)
    async def endpoint(scope,receive,send): await manager.handle_request(scope,receive,send)
    async def health(request): return JSONResponse(backend.health())
    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with manager.run():
            yield
            for job in backend.jobs.values():
                if job['status']=='running': job['status']='cancel_requested'
            await asyncio.to_thread(backend.dev_executor.shutdown)
            # Container cleanup also occurs in each worker; allow workers to finish.
            deadline=time.monotonic()+12
            while any('_process' in job for job in backend.jobs.values()) and time.monotonic()<deadline: await asyncio.sleep(.1)
    app=Starlette(routes=[Route('/health',health),Mount('/mcp',app=endpoint)],lifespan=lifespan)
    # Mount('/mcp') redirects /mcp to /mcp/; register exact ASGI path instead.
    from starlette.routing import BaseRoute,Match
    class MCPRoute(BaseRoute):
        def matches(self,scope): return (Match.FULL,{}) if scope['type']=='http' and scope['path']=='/mcp' else (Match.NONE,{})
        def url_path_for(self,name,**path_params): raise ValueError('No named route')
        async def handle(self,scope,receive,send): await endpoint(scope,receive,send)
    app.router.routes=[Route('/health',health),MCPRoute()]
    return Guard(app,credential,backend.audit_event,backend.cfg.get('rateLimits'))

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--config',required=True); parser.add_argument('--token-file',required=True); parser.add_argument('--port',type=int,default=8001)
    args=parser.parse_args()
    # Local loopback only; HTTPS provided separately by a configured tunnel.
    uvicorn.run(make_app(args.config,args.token_file),host='127.0.0.1',port=args.port,access_log=False,timeout_keep_alive=5,limit_concurrency=64)
