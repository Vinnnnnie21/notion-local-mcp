#!/usr/bin/env python3
"""Exercise a temporary MCP server over HTTP without production configuration."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
VERSION = '2.2.8-service-timeout-validation'
RECOVERY_TOOLS = {'dev_execution_diagnose', 'dev_execution_preserve',
                  'dev_execution_request_recovery', 'dev_execution_apply_recovery'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    with tempfile.TemporaryDirectory(prefix='notion-mcp-smoke-') as temporary:
        base = Path(temporary)
        project = base / 'demo'
        private = base / 'private'
        subprocess.run([sys.executable, str(ROOT / 'scripts/init.py'), '--project', str(project),
                        '--config-dir', str(private)], check=True, stdout=subprocess.DEVNULL)
        (project / 'hello.txt').write_text('temporary MCP demonstration\n')
        (project / 'worker.py').write_text('fencing_token: int = 42\nprint(42)\n')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        url = f'http://127.0.0.1:{port}'
        credential = (private / 'token').read_text().strip()
        with (base / 'server.log').open('wb') as log:
            server = subprocess.Popen([sys.executable, str(ROOT / 'app/server.py'),
                                       '--config', str(private / 'config.json'),
                                       '--token-file', str(private / 'token'), '--port', str(port)],
                                      stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while True:
                    require(server.poll() is None, 'Temporary MCP server exited before readiness')
                    try:
                        urllib.request.urlopen(url + '/health', timeout=1)
                    except urllib.error.HTTPError as error:
                        require(error.code == 401, 'Unauthenticated health must return 401')
                        break
                    except urllib.error.URLError:
                        require(time.monotonic() < deadline, 'Temporary MCP server readiness timed out')
                        time.sleep(0.1)
                    else:
                        raise RuntimeError('Unauthenticated health was accepted')

                def rpc(method, params, authenticated=True):
                    headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
                               'MCP-Protocol-Version': '2025-03-26'}
                    if authenticated:
                        headers['Authorization'] = 'Bearer ' + credential
                    request = urllib.request.Request(url + '/mcp', headers=headers,
                        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode())
                    with urllib.request.urlopen(request, timeout=15) as response:
                        result = json.load(response)
                    require('result' in result, 'MCP protocol returned an error')
                    return result['result']

                try:
                    rpc('tools/list', {}, authenticated=False)
                except urllib.error.HTTPError as error:
                    require(error.code == 401, 'Unauthenticated MCP must return 401')
                else:
                    raise RuntimeError('Unauthenticated MCP request was accepted')
                initialized = rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                                'clientInfo': {'name': 'public-smoke', 'version': '1.0'}})
                require(initialized['serverInfo']['version'] == VERSION, 'Unexpected initialization version')
                tools = rpc('tools/list', {})['tools']
                names = {tool['name'] for tool in tools}
                require(RECOVERY_TOOLS <= names, 'Recovery tools missing from wire discovery')
                for tool in tools:
                    jsonschema.Draft7Validator.check_schema(tool['inputSchema'])

                def call(name, arguments, allow_error=False):
                    result = rpc('tools/call', {'name': name, 'arguments': arguments})
                    if not allow_error:
                        require(not result.get('isError'), f'{name} failed in temporary MCP server')
                    if result.get('isError'):
                        return result
                    return json.loads(result['content'][0]['text'])

                require(call('health', {})['version'] == VERSION, 'Unexpected health version')
                projects = call('list_projects', {})['projects']
                require([item['project'] for item in projects] == ['demo'], 'Temporary project scope mismatch')
                read = call('read_text_file', {'project': 'demo', 'path': 'worker.py'})
                require('fencing_token: int = 42' in read['text'], 'Numeric source declaration was redacted')
                workspace = call('dev_workspace_create', {'profile': 'autonomous-development',
                                                         'project': 'demo', 'requestId': 'smoke-create'})
                common = {'profile': 'autonomous-development', 'workspaceId': workspace['workspaceId']}
                require(call('dev_read', {**common, 'path': 'hello.txt'})['text'] == 'temporary MCP demonstration\n',
                        'Development copy did not preserve demonstration content')
                denied = call('dev_write', {**common, 'path': 'unsafe.py', 'expectedHash': 'missing',
                                           'content': 'api_key = "SYNTHETIC_CREDENTIAL_12345"\n',
                                           'requestId': 'smoke-denied'})
                require(denied.get('applied') is False, 'Credential write was accepted')
                require('SYNTHETIC_CREDENTIAL_12345' not in json.dumps(denied), 'Credential leaked in failure output')
                written = call('dev_write', {**common, 'path': 'new.txt', 'expectedHash': 'missing',
                                            'content': 'new demonstration content\n', 'requestId': 'smoke-write'})
                require(written.get('applied') is True, 'Development write failed')
                call('dev_execution_diagnose', common)
                refused_close = call('dev_workspace_close', common, allow_error=True)
                require(refused_close.get('isError') is True, 'Modified workspace closed without preservation')
                preserve_args = {**common, 'requestId': 'smoke-preserve'}
                preserved = call('dev_execution_preserve', preserve_args)
                deadline = time.monotonic() + 15
                while preserved['status'] in {'queued', 'running'}:
                    require(time.monotonic() < deadline, 'Temporary preservation did not finish')
                    time.sleep(0.05)
                    preserved = call('dev_execution_preserve', preserve_args)
                require(preserved['status'] == 'succeeded' and preserved['preserved'], 'Preservation failed')
                repeated = call('dev_execution_preserve', preserve_args)
                require(repeated['preservationTaskId'] == preserved['preservationTaskId'], 'Preservation retry changed identity')
                require(call('dev_workspace_close', common)['closed'], 'Preserved workspace did not close')
                require(not (project / 'new.txt').exists(), 'Development write changed the original project')
                print(f'PASS: temporary authenticated MCP, {len(tools)} tool schemas, source reads, '
                      'credential rejection, preservation retry and workspace closure')
            finally:
                server.terminate()
                try:
                    server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)


if __name__ == '__main__':
    main()
