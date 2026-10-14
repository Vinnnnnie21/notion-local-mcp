#!/usr/bin/env python3
"""Local operator CLI. This file/state must NEVER be in an MCP project root."""
import argparse,json,os,secrets,time
from file_access import canonical, hashed
from pathlib import Path
from core import Backend
DEFAULT=Path(os.environ.get('NOTION_MCP_HOME', Path.home()/'.config/notion-local-mcp'))
p=argparse.ArgumentParser(); p.add_argument('--config',default=str(DEFAULT/'config.json'))
s=p.add_subparsers(dest='action',required=True)
init=s.add_parser('init'); init.add_argument('--project',required=True); init.add_argument('--name',default='code'); init.add_argument('--allow-home-readonly',action='store_true')
review=s.add_parser('approve'); review.add_argument('id')
s.add_parser('health'); s.add_parser('rotate-key'); s.add_parser('validate-config')
s.add_parser('restart')
grant=s.add_parser('authorize-sensitive'); grant.add_argument('--path',required=True); grant.add_argument('--minutes',type=int,default=30); grant.add_argument('--write',action='store_true')
prune=s.add_parser('prune'); prune.add_argument('--days',type=int,default=30)
a=p.parse_args(); path=Path(a.config).expanduser()
if a.action=='init':
    if path.exists(): raise SystemExit('Configuration exists; edit locally instead of overwriting')
    path.parent.mkdir(parents=True,mode=0o700,exist_ok=True); os.chmod(path.parent,0o700)
    root=str(Path(a.project).expanduser().resolve(strict=True)); state=path.parent/'state'
    config={'stateDir':str(state),'projects':{a.name:{'root':root,'write':False,'writeAllow':['src/*','tests/*','docs/*','*.py','*.md','*.txt'],'deny':['*credential*','*secret*','*token*','*.log'],'gitWrite':False,'pushRemotes':{},'tasks':{}}}}
    if a.allow_home_readonly:
        if Path(root)!=Path.home(): raise SystemExit('--allow-home-readonly only applies to the actual home directory')
        config['allowHomeRootReadOnly']=True
    path.write_text(json.dumps(config,ensure_ascii=False,indent=2)); os.chmod(path,0o600)
    try: Backend(path)
    except Exception:
        path.unlink(); raise
    token=path.parent/'token'
    if token.exists(): raise SystemExit('Token already exists; inspect locally')
    token.write_text(secrets.token_hex(32)+'\n'); os.chmod(token,0o600)
    print('Created read-only config:',path); print('Credentials stay local. Edit explicit project permissions before enabling writes.')
else:
    backend=Backend(path)
    if a.action=='validate-config': print(json.dumps(backend.validate_configuration(),ensure_ascii=False,indent=2))
    elif a.action=='restart':
        import subprocess
        print(json.dumps(backend.validate_configuration(),ensure_ascii=False,indent=2))
        unit = backend.cfg.get('serviceNames', {}).get('mcp', 'notion-local-mcp.service')
        if input('仅重启 MCP 服务。输入 RESTART MCP: ')!='RESTART MCP': raise SystemExit('Cancelled')
        subprocess.run(['/usr/bin/systemctl','--user','restart',unit],check=True)
        print('MCP restarted; reconnect and check health.')
    elif a.action=='authorize-sensitive':
        if not Path(a.path).is_absolute() or not 1<=a.minutes<=120: raise SystemExit('Need exact absolute path and 1..120 minutes')
        target=Path(a.path).resolve(strict=True)
        if not target.is_file(): raise SystemExit('Sensitive authorization is for one exact file, never a directory')
        if any(target==private or private in target.parents for private in backend.private_paths): raise SystemExit('Administrator paths require separate local maintenance')
        if not any(target==spec['root'] or spec['root'] in target.parents for spec in backend.projects.values()): raise SystemExit('Outside authorized projects')
        print('精确授权路径:',target,'有效分钟:',a.minutes,'写入:',a.write)
        print('聊天输出继续遮蔽可能的秘密；本机批准后才允许操作该文件。')
        if input('输入 AUTHORIZE EXACT PATH: ')!='AUTHORIZE EXACT PATH': raise SystemExit('Cancelled')
        cfg=json.loads(path.read_text()); cfg.setdefault('sensitiveGrants',[]).append({'path':str(target),'read':True,'write':a.write,'expires':time.time()+a.minutes*60})
        backend.atomic_json(path,cfg); print('Saved. Validate and restart MCP locally to load this authorization.')
    elif a.action=='health': print(json.dumps(backend.health(),ensure_ascii=False,indent=2))
    elif a.action=='approve':
        if len(a.id)!=32 or any(c not in '0123456789abcdef' for c in a.id): raise SystemExit('Invalid approval ID')
        file=backend.state/'approvals'/(a.id+'.json'); record=json.loads(file.read_text())
        if record['approved'] or record['used'] or record['expires']<time.time(): raise SystemExit('Approval is used or expired')
        print('Project:',record['project'],'Operation:',record['kind'])
        # Print only data, never execute command strings from the preview.
        print(json.dumps(record['preview'],ensure_ascii=False,indent=2))
        if input('Review the exact changes above. Type APPROVE to authorize once: ')!='APPROVE': raise SystemExit('Cancelled')
        current=json.loads(file.read_text())
        if current!=record or current['expires']<time.time(): raise SystemExit('Approval changed or expired during review; request a new preview')
        actual=hashed(canonical({k:record[k] for k in ('id','kind','project','created','expires','payload')}))
        if actual!=record.get('binding'): raise SystemExit('Payload changed; request a new preview')
        if record['kind']=='service_restart' and input('管理员维护批准。输入 ADMIN APPROVE: ')!='ADMIN APPROVE': raise SystemExit('Cancelled')
        record['approved']=True; record['approvedBinding']=actual; backend.atomic_json(file,record); print('Approved once. Apply through MCP before expiry.')
    elif a.action=='rotate-key':
        if input('This invalidates the current connection. Type ROTATE: ')!='ROTATE': raise SystemExit('Cancelled')
        backend.atomic_private(path.parent/'token',(secrets.token_hex(32)+'\n').encode()); print('Key rotated. Update authentication locally; never paste token into chat.')
    else:
        if not 1<=a.days<=3650: raise SystemExit('days must be 1..3650')
        if input('Deletes old private snapshots/approvals/indexes/job results, NOT project files. Type PRUNE: ')!='PRUNE': raise SystemExit('Cancelled')
        import shutil
        cutoff=time.time()-a.days*86400; count=0
        for folder in ['approvals','snapshots','indexes','jobs']:
            for child in (backend.state/folder).iterdir():
                if child.stat().st_mtime<cutoff:
                    if child.is_dir(): shutil.rmtree(child)
                    else: child.unlink()
                    count+=1
        print('Removed private entries:',count)
