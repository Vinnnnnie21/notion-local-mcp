"""临时目录验收。通过实际 MCP 接口操作，不批准任何计划。"""
import argparse
import base64
import json
import os
import tempfile
import urllib.request
from pathlib import Path
BASE=Path(os.environ.get('NOTION_MCP_HOME', Path.home()/'.config/notion-local-mcp'))
WORK=Path(os.environ.get('NOTION_MCP_VERIFY_WORK', BASE/'verification'))
PROJECT=os.environ.get('NOTION_MCP_VERIFY_PROJECT', 'demo')
PROJECT_ROOT=Path(os.environ.get('NOTION_MCP_VERIFY_ROOT', Path.home()/'notion-mcp-demo'))


def request(method,params,url='http://127.0.0.1:8001/mcp'):
    token=Path(os.environ.get('NOTION_MCP_TOKEN_FILE', BASE/'token')).read_text().strip()
    req=urllib.request.Request(url,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={
        'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
    with urllib.request.urlopen(req,timeout=15) as response:return json.loads(response.read())


def tool(name,args,url='http://127.0.0.1:8001/mcp'):
    result=request('tools/call',{'name':name,'arguments':args},url)['result']
    if result.get('isError'):return {'error':result['content'][0]['text']}
    return json.loads(result['content'][0]['text'])


def file_hash(path):return tool('get_path_hash',{'project':PROJECT,'path':str(path)})['sha256']


def save(name,value):
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    (WORK/name).write_text(json.dumps(value,indent=2,ensure_ascii=False))
def load(name):return json.loads((WORK/name).read_text())


def prepare():
    root=Path(tempfile.mkdtemp(prefix='notion-mcp-acceptance-',dir=PROJECT_ROOT))
    for name,text in [('edit.txt','before'),('copy.txt','copy source'),('move.txt','move source'),('rename.txt','rename source'),('delete.txt','recover me'),('conflict.txt','before')]:
        (root/name).write_text(text)
    (root/'tree').mkdir();(root/'tree/a.txt').write_text('directory child')
    (root/'outside-link').symlink_to('/etc')
    (root/'.env').write_text('PASSWORD=SYNTHETIC_TEST_SENTINEL_23847')
    (root/'ordinary.txt').write_text('api_key=SYNTHETIC_TEST_SENTINEL_23847')
    operations=[{'operation':'mkdir','path':str(root/'created-directory')},
        {'operation':'write','path':str(root/'created.txt'),'content':'created by approved MCP'},
        {'operation':'write','path':str(root/'binary.bin'),'contentBase64':base64.b64encode(b'\0\xffbinary').decode()},
        {'operation':'write','path':str(root/'edit.txt'),'expectedHash':file_hash(root/'edit.txt'),'content':'after'}]
    for action,source,target in [('copy','copy.txt','copied.txt'),('move','move.txt','moved.txt'),('move','rename.txt','renamed.txt'),('copy','tree','copied-tree')]:
        operations.append({'operation':action,'path':str(root/source),'destination':str(root/target),'expectedHash':file_hash(root/source)})
    operations.append({'operation':'delete','path':str(root/'delete.txt'),'expectedHash':file_hash(root/'delete.txt')})
    plan=tool('plan_file_operations',{'project':PROJECT,'operations':operations})
    conflict=tool('plan_files',{'project':PROJECT,'changes':[{'path':str(root/'conflict.txt'),'expectedHash':file_hash(root/'conflict.txt'),'content':'must not overwrite user change'}]})
    if 'approvalId' not in plan or 'approvalId' not in conflict:raise RuntimeError('Preview failed; inspect local configuration')
    (root/'conflict.txt').write_text('user concurrent change')
    state={'root':str(root),'approvalId':plan['approvalId'],'conflictApprovalId':conflict['approvalId']}
    save('live-write-state.json',state)
    checks={'beforeApprovalRejected':'error' in tool('apply_change',{'approvalId':plan['approvalId']}),
        'outsideLinkRejected':'error' in tool('read_text_file',{'project':PROJECT,'path':str(root/'outside-link/passwd')}),
        'sensitiveRejected':'error' in tool('read_text_file',{'project':PROJECT,'path':str(root/'.env')}),
        'ordinarySecretRedacted':'SYNTHETIC_TEST_SENTINEL_23847' not in json.dumps(tool('read_text_file',{'project':PROJECT,'path':str(root/'ordinary.txt')}))}
    save('live-write-checks.json',checks)
    print(json.dumps({'state':state,'checks':checks},indent=2))


def apply():
    state=load('live-write-state.json');root=Path(state['root'])
    result=tool('apply_change',{'approvalId':state['approvalId']})
    if not result.get('applied'):print(json.dumps(result));raise SystemExit(1)
    checks=load('live-write-checks.json')
    checks.update({'createdDirectory':(root/'created-directory').is_dir(),'createdFile':(root/'created.txt').read_text()=='created by approved MCP',
        'binary':(root/'binary.bin').read_bytes()==b'\0\xffbinary',
        'binaryReadViaMcp':base64.b64decode(tool('read_binary_file',{'project':PROJECT,'path':str(root/'binary.bin')})['base64'])==b'\0\xffbinary',
        'edited':(root/'edit.txt').read_text()=='after','copied':(root/'copied.txt').read_text()=='copy source',
        'moved':(root/'moved.txt').exists() and not (root/'move.txt').exists(),
        'renamed':(root/'renamed.txt').exists() and not (root/'rename.txt').exists(),'deleted':not (root/'delete.txt').exists(),
        'copiedDirectory':(root/'copied-tree/a.txt').read_text()=='directory child',
        'replayRejected':'error' in tool('apply_change',{'approvalId':state['approvalId']}),
        'conflictRejected':'error' in tool('apply_change',{'approvalId':state['conflictApprovalId']}),
        'concurrentEditPreserved':(root/'conflict.txt').read_text()=='user concurrent change'})
    restore=tool('restore_snapshot',{'project':PROJECT,'snapshotId':state['approvalId']})
    state['restoreApprovalId']=restore['approvalId'];save('live-write-state.json',state);save('live-write-checks.json',checks)
    print(json.dumps({'checks':checks,'restoreApprovalId':restore['approvalId']},indent=2))


def restore():
    state=load('live-write-state.json');root=Path(state['root'])
    result=tool('apply_change',{'approvalId':state['restoreApprovalId']})
    if not result.get('applied'):print(json.dumps(result));raise SystemExit(1)
    checks=load('live-write-checks.json')
    checks.update({'deletedFileRestored':(root/'delete.txt').read_text()=='recover me',
        'overwriteRestored':(root/'edit.txt').read_text()=='before',
        'moveRestored':(root/'move.txt').is_file() and not (root/'moved.txt').exists(),
        'createdFileRemoved':not (root/'created.txt').exists()})
    save('live-write-checks.json',checks);print(json.dumps(checks,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','apply','restore']);args=parser.parse_args()
    {'prepare':prepare,'apply':apply,'restore':restore}[args.action]()
