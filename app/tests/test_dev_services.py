"""服务工具边界与幂等测试。真实隔离执行由集成验收覆盖。"""
import json
import tempfile
import threading
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dev_services import attach_services, origin, relative, TOOL_SCHEMAS


class Dummy:
    def __init__(self, config):
        self.state=Path(tempfile.mkdtemp(prefix='mcp-services-unit-'));self.lock=threading.RLock()
        self.calls=[];self.status={'status':'running','stdout':'{"ready":true}'};self.next_stdout='{"columns":["n"],"rows":[[1]],"readonly":false}'
    def dev_policy(self, profile):
        if profile!='autonomous-development':raise ValueError('disabled')
        return {'enabled':True}
    def dev_workspace(self, workspaceId, profile):
        if workspaceId!='w':raise ValueError('unknown')
        return {'path':'/unused'}
    def dev_exec_internal(self, profile, workspaceId, **kwargs):
        self.calls.append(kwargs)
        return {'id':'job','status':'running'} if kwargs.get('background') else {'status':'completed','exitCode':0,'stdout':self.next_stdout}
    def dev_task_status(self,taskId):return self.status
    def dev_cancel(self,taskId):return {'cancelled':taskId}
attach_services(Dummy)


class Tests(unittest.TestCase):
    def setUp(self):self.b=Dummy(None);self.c={'profile':'autonomous-development','workspaceId':'w'}
    def tearDown(self):
        import shutil
        shutil.rmtree(self.b.state)
    def start(self):return self.b.dev_service_start(**self.c,argv=['python3','server.py'],port=18080,requestId='service')
    def test_url_host_boundary(self):
        for u in ['http://localhost:18080','http://127.0.0.1:8001','https://127.0.0.1:18080','http://user:pass@127.0.0.1:18080','http://127.0.0.1:18080/#x','file:///etc/passwd','http://binance.com:18080']:
            with self.subTest(u=u),self.assertRaises(ValueError):origin(u,[18080])
    def test_relative_boundary(self):
        for p in ['../a','/tmp/a','x/../a','a//b','a\\b','.ssh/key','.config/x']:
            with self.subTest(p=p),self.assertRaises(ValueError):relative(p)
    def test_sqlite_mutation_requires_request(self):
        with self.assertRaises(ValueError):self.b.dev_db(**self.c,path='a.db',sql='CREATE TABLE a(n)')
        self.assertEqual(self.b.calls,[])
    def test_sqlite_ro_forwarded(self):
        self.b.dev_db(**self.c,path='a.db',sql='SELECT 1',readonly=True)
        q=json.loads(self.b.calls[-1]['argv'][-1]);self.assertTrue(q['readonly'])
    def test_sqlite_idempotent(self):
        a=self.b.dev_db(**self.c,path='a.db',sql='INSERT INTO a VALUES(1)',requestId='r')
        self.assertEqual(a,self.b.dev_db(**self.c,path='a.db',sql='INSERT INTO a VALUES(1)',requestId='r'))
        self.assertEqual(len(self.b.calls),1)
    def test_sqlite_reused_id_different_operation(self):
        self.b.dev_db(**self.c,path='a.db',sql='SELECT 1',requestId='r')
        with self.assertRaises(ValueError):self.b.dev_db(**self.c,path='a.db',sql='SELECT 2',requestId='r')
    def test_sqlite_unknown_no_replay(self):
        self.b.next_stdout='not JSON'
        with self.assertRaises(ValueError):self.b.dev_db(**self.c,path='a.db',sql='SELECT 1',requestId='r')
        self.assertTrue(self.b.dev_db(**self.c,path='a.db',sql='SELECT 1',requestId='r')['unknown'])
        self.assertEqual(len(self.b.calls),1)
    def test_sqlite_size_bounds(self):
        with self.assertRaises(ValueError):self.b.dev_db(**self.c,path='a.db',sql='SELECT 1',readonly=True,limit=1001)
    def test_runtime_db_not_accepted(self):
        with self.assertRaises(ValueError):self.b.dev_db(profile='readonly-runtime',workspaceId='w',path='a.db',sql='SELECT 1',readonly=True)
    def test_db_extension_required(self):
        with self.assertRaises(ValueError):self.b.dev_db(**self.c,path='a.txt',sql='SELECT 1',readonly=True)
    def test_service_idempotency(self):
        self.assertEqual(self.start(),self.start());self.assertEqual(len(self.b.calls),1)
    def test_service_id_different_argv(self):
        self.start()
        with self.assertRaises(ValueError):self.b.dev_service_start(**self.c,argv=['sh'],port=18080,requestId='service')
    def test_service_stop_owner(self):
        a=self.start();self.assertEqual(self.b.dev_service_stop(**self.c,serviceId=a['serviceId']),{'cancelled':'job'})
        with self.assertRaises(ValueError):self.b.dev_service_stop(**self.c,serviceId='missing')
    def test_http_only_registered_service(self):
        with self.assertRaises(ValueError):self.b.dev_http(**self.c,url='http://127.0.0.1:18080/')
    def test_http_writes_require_id(self):
        self.start()
        with self.assertRaises(ValueError):self.b.dev_http(**self.c,url='http://127.0.0.1:18080/',method='POST')
    def test_http_unknown_no_retry(self):
        self.start();self.b.next_stdout='{"unknown":true,"error":"timeout"}'
        a=self.b.dev_http(**self.c,url='http://127.0.0.1:18080/',method='POST',requestId='http')
        self.assertTrue(a['unknown']);self.assertEqual(a,self.b.dev_http(**self.c,url='http://127.0.0.1:18080/',method='POST',requestId='http'))
        self.assertEqual(len(self.b.calls),2)
    def test_http_no_base64_secret_bypass(self):
        self.start();self.b.next_stdout='{"body":"password=sentinel_0123456","bodyBase64":"c2VjcmV0"}'
        result=self.b.dev_http(**self.c,url='http://127.0.0.1:18080/')
        self.assertNotIn('bodyBase64',result);self.assertNotIn('sentinel',json.dumps(result))
    def test_http_port_not_running(self):
        self.start();self.b.status={'status':'completed','exitCode':0}
        with self.assertRaises(ValueError):self.b.dev_http(**self.c,url='http://127.0.0.1:18080/')
    def test_browser_profile_and_screenshot_bounds(self):
        self.start();x=self.b.dev_browser_open(**self.c,url='http://127.0.0.1:18080/',requestId='browser')
        for path in ['../a.png','a.png','.dev-artifacts/../a.png','.dev-artifacts/a.txt']:
            with self.subTest(path=path),self.assertRaises(ValueError):self.b.dev_browser_action(**self.c,sessionId=x['sessionId'],action='screenshot',path=path)
    def test_browser_schema_contains_real_actions(self):
        actions=TOOL_SCHEMAS['dev_browser_action']['properties']['action']['enum']
        self.assertTrue({'query','click','input','screenshot','console','network_failures'}<=set(actions))
    def test_browser_no_raw_evaluate(self):
        self.start();x=self.b.dev_browser_open(**self.c,url='http://127.0.0.1:18080/',requestId='browser')
        with self.assertRaises(ValueError):self.b.dev_browser_action(**self.c,sessionId=x['sessionId'],action='evaluate',text='document.cookie')
    def test_mutation_ledger_restart_does_not_replay(self):
        self.b.dev_db(**self.c,path='a.db',sql='INSERT INTO a VALUES(1)',requestId='restart')
        oldstate=self.b.state
        b=Dummy(None)
        import shutil
        shutil.rmtree(b.state); b.state=oldstate
        # 重新初始化生产状态加载逻辑需要真实旧state，在独立backend fixture中验证。
        from dev_services import attach_services
        class Reload(Dummy):
            def __init__(self,config):
                self.state=oldstate;self.lock=threading.RLock();self.calls=[]
        attach_services(Reload)
        reload=Reload(None)
        r=reload.dev_db(**self.c,path='a.db',sql='INSERT INTO a VALUES(1)',requestId='restart')
        self.assertTrue(r['unknown']);self.assertEqual(reload.calls,[])
    def test_postgres_private_directory_only(self):
        with self.assertRaises(ValueError):self.b.dev_postgres(**self.c,path='data',action='init',requestId='pg')
    def test_runtime_unconfigured_rejected(self):
        with self.assertRaises(ValueError):self.b.dev_runtime_query(profile='readonly-runtime',targetId='production',sql='SELECT 1')
    def test_fixed_runtime_sqlite_real_ro_and_sensitive_columns(self):
        import sqlite3
        path=self.b.state/'runtime.sqlite';db=sqlite3.connect(path)
        db.execute('CREATE TABLE sample(n INTEGER,password TEXT)');db.execute("INSERT INTO sample VALUES(5,'synthetic-sensitive')");db.commit();db.close()
        self.b.config_path=Path('/no/mcp/config.json')
        oldstate=self.b.state
        self.b.dev_policy=lambda profile:{'readRoots':[str(oldstate)],'databases':{'fixture':{'engine':'sqlite','path':str(path),'readonly':True}}}
        # 数据库fixture和MCP私有state分开，固定readonly配置不允许私有state。
        oldstate=self.b.state;self.b.state=oldstate/'mcp-private'
        result=self.b.dev_runtime_query(profile='readonly-runtime',targetId='fixture',sql='SELECT n FROM sample')
        self.assertEqual(result['rows'],[[5]])
        for sql in ['SELECT password AS innocent_name FROM sample','INSERT INTO sample VALUES(9,"x")','PRAGMA query_only=OFF',"ATTACH DATABASE '/tmp/escape.sqlite' AS x"]:
            with self.subTest(sql=sql),self.assertRaises(ValueError):self.b.dev_runtime_query(profile='readonly-runtime',targetId='fixture',sql=sql)
        db=sqlite3.connect(path);self.assertEqual(db.execute('SELECT count(*) FROM sample').fetchone()[0],1);db.close();self.b.state=oldstate
    def test_schema_valid(self):
        import jsonschema
        for s in TOOL_SCHEMAS.values():jsonschema.Draft202012Validator.check_schema(s)

if __name__=='__main__':unittest.main()
