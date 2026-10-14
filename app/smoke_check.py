#!/usr/bin/env python3
"""Authenticated local SDK/protocol smoke test; does not display credentials."""
import argparse,json,urllib.request,urllib.error
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--port',type=int,default=8001); p.add_argument('--token-file',required=True); a=p.parse_args()
url='http://127.0.0.1:%s/mcp'%a.port
key=Path(a.token_file).read_text().strip()
def rpc(method,params):
    req=urllib.request.Request(url,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','Authorization':'Bearer '+key,'MCP-Protocol-Version':'2025-03-26'})
    with urllib.request.urlopen(req,timeout=15) as res: return json.load(res)
try:
    urllib.request.urlopen(urllib.request.Request(url,data=b'{}',headers={'Content-Type':'application/json'}),timeout=5)
    raise SystemExit('FAIL: unauthenticated request was accepted')
except urllib.error.HTTPError as error:
    if error.code!=401: raise SystemExit('FAIL: expected 401')
init=rpc('initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'local-upgrade-check','version':'1.0'}})
assert 'result' in init,init
result=rpc('tools/list',{}); tools=result['result']['tools']; names={t['name'] for t in tools}
assert {'list_projects','health','apply_change','plan_task','document_preview'}<=names
health=rpc('tools/call',{'name':'health','arguments':{}}); assert not health['result'].get('isError'),health
print('PASS: unauthorized 401, initialization, tool discovery (%s tools), health call'%len(tools))
