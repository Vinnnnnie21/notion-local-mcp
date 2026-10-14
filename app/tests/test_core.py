import base64,hashlib,io,json,os,pathlib,secrets,subprocess,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from core import Backend,digest,redact
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.base=pathlib.Path(self.tmp.name)
        self.root=self.base/'project'; self.root.mkdir(); self.state=self.base/'state'
        self.config=self.base/'config.json'
        self.spec={'root':str(self.root),'write':True,'writeAllow':['*.py','*.txt','src/*','tests/*'],'deny':['*secret*','*.key'],'gitWrite':False,'pushRemotes':{},'tasks':{}}
        self.cfg={'stateDir':str(self.state),'projects':{'code':self.spec}}
        self.config.write_text(json.dumps(self.cfg)); self.b=Backend(self.config)
        (self.root/'a.py').write_text('def hello():\n    return "Hello"\n\nclass Widget:\n    pass\n'); os.chmod(self.root/'a.py',0o640)
        (self.root/'b.txt').write_text('hello\nworld\n')
        (self.root/'src').mkdir(); (self.root/'src'/'code.ts').write_text('interface User {}\nfunction run() {}\n')
        (self.root/'.env').write_text('SECRET_VALUE'); (self.root/'secret.txt').write_text('SECRET_VALUE')
    def tearDown(self):
        self.b.audit.handlers[0].close(); self.b.audit.handlers.clear(); self.tmp.cleanup()
    def approve(self,plan):
        file=self.state/'approvals'/(plan['approvalId']+'.json'); rec=json.loads(file.read_text()); rec['approved']=True; rec['approvedBinding']=rec['binding']; self.b.atomic_json(file,rec)
        return plan['approvalId']
    def plan(self,path='a.py',content='new\n'):
        return self.b.plan_files('code',[{'path':path,'expectedHash':self.b.get_file_hash('code',path)['sha256'],'content':content}])
    def test_01_health(self): self.assertEqual(self.b.health()['version'],'2.2.1-execution-reliability')
    def test_02_projects(self): self.assertEqual(self.b.list_projects()['projects'][0]['project'],'code')
    def test_03_root_rejection(self):
        self.cfg['projects']['code']['root']=str(pathlib.Path.home()); self.config.write_text(json.dumps(self.cfg))
        with self.assertRaises(ValueError): Backend(self.config)
    def test_04_overlap_rejection(self):
        self.cfg['stateDir']=str(self.root/'private'); self.config.write_text(json.dumps(self.cfg))
        with self.assertRaises(ValueError): Backend(self.config)
    def test_05_config_in_root_rejection(self):
        inside=self.root/'config.json'; inside.write_text(json.dumps(self.cfg))
        with self.assertRaises(ValueError): Backend(inside)
    def test_06_paths(self):
        for rel in ['../outside','/etc/passwd','.env','secret.txt','anything.key','.config/token']:
            with self.subTest(path=rel),self.assertRaises(ValueError): self.b.allowed('code',rel)
    def test_07_symlink(self):
        (self.root/'link').symlink_to(self.base)
        with self.assertRaises(ValueError): self.b.allowed('code','link/config.json')
    def test_08_hardlink(self):
        os.link(self.root/'a.py',self.root/'hard.py')
        with self.assertRaises(ValueError): self.b.read('code','hard.py')
    def test_09_listing(self):
        first=self.b.list_directory('code',limit=1); self.assertEqual(first['nextOffset'],1)
        second=self.b.list_directory('code',offset=1,limit=1); self.assertNotEqual(first['entries'],second['entries'])
        self.assertNotIn('secret.txt',[x['name'] for x in self.b.list_directory('code')['entries']])
    def test_10_lines(self):
        data=self.b.read_file_lines('code','a.py',2,3); self.assertEqual(data['lines'][0]['line'],2); self.assertEqual(data['nextLine'],4)
    def test_11_search_files(self):
        self.assertEqual(self.b.search_files('code','*.py')['results'],[{'path':'a.py'}])
    def test_12_search_text(self):
        self.assertEqual(self.b.search_text('code','SECRET_VALUE')['results'],[])
        self.assertEqual(self.b.search_text('code','WORLD',caseSensitive=False)['results'][0]['line'],2)
    def test_13_preview_no_write(self):
        before=(self.root/'a.py').read_bytes(); self.assertFalse(self.plan()['applied']); self.assertEqual((self.root/'a.py').read_bytes(),before)
    def test_14_approval_required(self):
        plan=self.plan()
        with self.assertRaises(ValueError): self.b.apply_change(plan['approvalId'])
    def test_15_apply_and_mode(self):
        aid=self.approve(self.plan()); result=self.b.apply_change(aid); self.assertTrue(result['applied'])
        self.assertEqual((self.root/'a.py').read_text(),'new\n'); self.assertEqual((self.root/'a.py').stat().st_mode&0o777,0o640)
    def test_16_replay(self):
        aid=self.approve(self.plan()); self.b.apply_change(aid)
        with self.assertRaises(ValueError): self.b.apply_change(aid)
    def test_17_expired(self):
        aid=self.approve(self.plan()); file=self.state/'approvals'/(aid+'.json'); rec=json.loads(file.read_text()); rec['expires']=0; file.write_text(json.dumps(rec))
        with self.assertRaises(ValueError): self.b.apply_change(aid)
    def test_18_conflict(self):
        aid=self.approve(self.plan()); (self.root/'a.py').write_text('manual edit')
        with self.assertRaises(ValueError): self.b.apply_change(aid)
        self.assertEqual((self.root/'a.py').read_text(),'manual edit')
    def test_19_create(self):
        aid=self.approve(self.b.create_text_file('code','new.py','x=1\n')); self.b.apply_change(aid); self.assertEqual((self.root/'new.py').read_text(),'x=1\n')
    def test_20_create_conflict(self):
        aid=self.approve(self.b.create_text_file('code','new.py','x=1\n')); (self.root/'new.py').write_text('manual')
        with self.assertRaises(ValueError): self.b.apply_change(aid)
    def test_21_no_overwrite(self):
        with self.assertRaises(ValueError): self.b.create_text_file('code','a.py','x')
    def test_22_readonly(self):
        self.b.projects['code']['write']=False
        with self.assertRaises(ValueError): self.plan()
    def test_23_write_scopes(self):
        self.b.projects['code']['writeAllow']=['src/*']
        with self.assertRaises(ValueError): self.plan()
    def test_24_edits(self):
        plan=self.b.apply_text_edits('code','a.py',self.b.get_file_hash('code','a.py')['sha256'],[{'oldText':'hello','newText':'greet'},{'oldText':'Widget','newText':'Box'}])
        self.b.apply_change(self.approve(plan)); text=(self.root/'a.py').read_text(); self.assertIn('greet',text); self.assertIn('Box',text)
    def test_25_old_edit_apply_rejected(self):
        with self.assertRaises(ValueError): self.b.edit_file('code','a.py','hello','greet',dryRun=False)
    def test_26_duplicate_paths(self):
        change={'path':'a.py','expectedHash':self.b.get_file_hash('code','a.py')['sha256'],'content':'x'}
        with self.assertRaises(ValueError): self.b.plan_files('code',[change,change])
    def test_27_restore(self):
        original=(self.root/'a.py').read_text(); aid=self.approve(self.plan()); self.b.apply_change(aid)
        restore=self.b.restore_snapshot('code',aid); self.b.apply_change(self.approve(restore)); self.assertEqual((self.root/'a.py').read_text(),original)
    def test_28_restore_new_no_delete(self):
        aid=self.approve(self.b.create_text_file('code','new.py','x')); self.b.apply_change(aid)
        result=self.b.restore_snapshot('code',aid); self.b.apply_change(self.approve(result)); self.assertFalse((self.root/'new.py').exists())
    def test_29_snapshot_metadata(self):
        aid=self.approve(self.plan()); self.b.apply_change(aid); self.assertEqual(self.b.list_snapshots('code')['snapshots'][0]['snapshotId'],aid)
    def test_30_partial_failure(self):
        plan=self.b.plan_files('code',[{'path':p,'expectedHash':self.b.get_file_hash('code',p)['sha256'],'content':'updated'} for p in ['a.py','b.txt']]); aid=self.approve(plan)
        original=self.b.replace_node; calls=[]
        def fail(project,item,data,expected):
            calls.append(1)
            if len(calls)==2: raise OSError('simulated')
            return original(project,item,data,expected)
        with patch.object(self.b,'replace_node',side_effect=fail): result=self.b.apply_change(aid)
        self.assertTrue(result['partial']); self.assertEqual(result['writtenPaths'],[str(self.root/'a.py')]); self.assertEqual((self.root/'b.txt').read_text(),'hello\nworld\n')
    def test_31_index_incremental(self):
        first=self.b.build_index('code'); second=self.b.build_index('code'); self.assertEqual(first['indexedFiles'],2); self.assertEqual(second['rebuiltFiles'],0)
    def test_32_symbols(self):
        self.b.build_index('code'); self.assertEqual(self.b.search_symbols('code','Widget')['results'][0]['line'],4)
    def test_33_stale_symbols(self):
        self.b.build_index('code'); (self.root/'a.py').write_text('new content'); result=self.b.search_symbols('code','hello'); self.assertEqual(result['results'],[]); self.assertEqual(result['staleFiles'],1)
    def test_34_refs_label(self): self.assertIn('not semantic',self.b.find_references('code','hello')['method'])
    def test_35_summary(self): self.assertIn('topLevel',self.b.project_summary('code'))
    def test_36_log_redaction(self):
        (self.root/'events.log').write_text('2026-10-13 INFO token=abc\n2026-10-14 ERROR failed\n')
        result=self.b.tail_log('code','events.log',level='INFO'); self.assertIn('[REDACTED]',result['lines'][0]); self.assertNotIn('abc',result['lines'][0])
    def test_37_log_cursor(self):
        path=self.root/'events.log'; path.write_text('first\n'); first=self.b.tail_log('code','events.log'); path.write_text('first\nsecond\n'); second=self.b.tail_log('code','events.log',cursor=first['cursor']); self.assertEqual(second['lines'],['second'])
    def test_38_csv(self):
        (self.root/'data.csv').write_text('a,b\n1,2\n3,4\n'); result=self.b.document_preview('code','data.csv',limit=2); self.assertEqual(result['rows'],[['a','b'],['1','2']]); self.assertEqual(result['nextOffset'],2)
    def test_39_image(self):
        from PIL import Image
        Image.new('RGB',(1200,800)).save(self.root/'pic.png'); result=self.b.document_preview('code','pic.png'); self.assertEqual(result['kind'],'image'); self.assertTrue(base64.b64decode(result['base64']).startswith(b'\xff\xd8'))
    def test_40_bad_document(self):
        (self.root/'broken.pdf').write_bytes(b'NOT_PDF')
        with self.assertRaises(ValueError): self.b.document_preview('code','broken.pdf')
    def test_41_audit_no_payload(self):
        self.b.audit_event('edit','ok','code'); data=self.b.get_audit()['entries'][0]; self.assertNotIn('payload',data); self.assertEqual(data['tool'],'edit')
    def test_42_task_disabled(self):
        with self.assertRaises(ValueError): self.b.plan_task('code','test')
    def test_43_image_digest_required(self):
        self.b.projects['code']['tasks']={'test':{'image':'python:latest','argv':['python','-m','pytest']}}
        with self.assertRaises(ValueError): self.b.plan_task('code','test')
    def test_44_no_host_fallback(self):
        self.b.projects['code']['tasks']={'test':{'image':'python@sha256:'+'0'*64,'argv':['python','-m','pytest'],'timeout':60}}
        plan=self.b.plan_task('code','test'); aid=self.approve(plan)
        with patch('core.shutil.which',return_value=None),self.assertRaises(ValueError): self.b.run_project_task(aid)
    def test_45_git_disabled(self):
        with self.assertRaises(ValueError): self.b.plan_git('code','branch',branch='test')
    def git_init(self):
        import shutil
        git=shutil.which('git'); subprocess.run([git,'init','-q'],cwd=self.root,check=True)
        (self.root/'.git/info/exclude').write_text('/.env\n/secret.txt\n/src/\n')
        subprocess.run([git,'config','user.email','test@example.invalid'],cwd=self.root,check=True); subprocess.run([git,'config','user.name','Test'],cwd=self.root,check=True)
        subprocess.run([git,'add','a.py','b.txt'],cwd=self.root,check=True); subprocess.run([git,'commit','-qm','initial'],cwd=self.root,check=True)
    def test_46_git_readonly(self):
        self.git_init(); (self.root/'a.py').write_text('changed\n'); self.assertIn('a.py',self.b.git_status('code')['text']); self.assertIn('+changed',self.b.git_diff('code','a.py')['text']); self.assertIn('initial',self.b.git_log('code','a.py')['text'])
    def test_47_git_branch_approval(self):
        self.git_init(); self.b.projects['code']['gitWrite']=True
        plan=self.b.plan_git('code','branch',branch='feature/test'); aid=self.approve(plan); result=self.b.apply_git(aid); self.assertTrue(result['applied'])
    def test_48_git_reject_force(self):
        self.b.projects['code']['gitWrite']=True
        with self.assertRaises(ValueError): self.b.plan_git('code','reset',branch='main')
        with self.assertRaises(ValueError): self.b.plan_git('code','push',branch='main',remote='origin')
    def test_49_local_approve_cli(self):
        plan=self.plan(); proc=subprocess.run([sys.executable,str(pathlib.Path(__file__).resolve().parents[1]/'manage.py'),'--config',str(self.config),'approve',plan['approvalId']],input='APPROVE\n',text=True,capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stderr); self.assertTrue(self.b.apply_change(plan['approvalId'])['applied'])
    def test_50_large_lines(self):
        (self.root/'large.txt').write_text('row\n'*600000)
        with self.assertRaises(ValueError): self.b.read_text_file('code','large.txt')
        result=self.b.read_file_lines('code','large.txt',599999,600000); self.assertEqual(len(result['lines']),2); self.assertTrue(result['eof'])
    def test_51_unknown_project(self):
        with self.assertRaises(ValueError): self.b.read_text_file('missing','a.py')
    def test_52_empty_readonly_scopes(self):
        self.b.projects['code']['writeAllow']=[]
        with self.assertRaises(ValueError): self.b.create_text_file('code','new.py','x')
    def test_53_redaction_header(self): self.assertNotIn('abc',redact('Authorization: Bearer abc'))
    def test_55_git_directory_diff_forbidden(self):
        self.git_init()
        with self.assertRaises(ValueError): self.b.git_diff('code','.')
    def test_56_private_key_redaction(self):
        self.assertNotIn('FAKE_KEY_CONTENT',redact('-----BEGIN PRIVATE KEY-----\nFAKE_KEY_CONTENT\n-----END PRIVATE KEY-----'))
    def test_54_approval_not_an_mcp_method(self): self.assertFalse(hasattr(self.b,'approve'))
    def test_57_valid_pdf(self):
        from pypdf import PdfWriter
        writer=PdfWriter(); writer.add_blank_page(width=200,height=200)
        with (self.root/'blank.pdf').open('wb') as stream: writer.write(stream)
        result=self.b.document_preview('code','blank.pdf'); self.assertEqual(result['kind'],'pdf'); self.assertEqual(result['totalPages'],1)
    def test_58_git_commit_approved(self):
        self.git_init(); self.b.projects['code']['gitWrite']=True; (self.root/'a.py').write_text('updated\n')
        plan=self.b.plan_git('code','commit',message='managed update',paths=['a.py']); result=self.b.apply_git(self.approve(plan)); self.assertTrue(result['applied']); self.assertIn('managed update',self.b.git_log('code','a.py')['text'])
    def test_59_git_preview_conflict(self):
        self.git_init(); self.b.projects['code']['gitWrite']=True; (self.root/'a.py').write_text('updated\n')
        plan=self.b.plan_git('code','commit',message='managed update',paths=['a.py']); aid=self.approve(plan); (self.root/'a.py').write_text('external change\n')
        with self.assertRaises(ValueError): self.b.apply_git(aid)
    def test_60_docker_command_and_export(self):
        self.b.projects['code']['tasks']={'test':{'image':'python@sha256:'+'0'*64,'argv':['python','-m','pytest'],'timeout':60}}
        plan=self.b.plan_task('code','test'); aid=self.approve(plan); captured=[]
        def worker(job,cmd,timeout,folder):
            captured.append(cmd)
            self.assertFalse((folder/'workspace'/'secret.txt').exists())
            self.assertFalse((folder/'workspace'/'.env').exists())
            self.assertTrue((folder/'workspace'/'a.py').exists())
            job['status']='mock_finished'
        # This test checks command/export construction, not scheduling.
        # Execute its fake worker synchronously so assertions propagate to unittest.
        with patch('core.shutil.which',return_value='/usr/bin/docker'), \
             patch.object(self.b,'rootless_docker_command',return_value=['/usr/bin/docker','--host','unix:///run/user/1000/docker.sock']), \
             patch.object(self.b,'task_worker',side_effect=worker), \
             patch('core.threading.Thread') as thread:
            def run_inline():
                args=thread.call_args.kwargs
                args['target'](*args['args'])
            thread.return_value.start.side_effect=run_inline
            self.b.run_project_task(aid)
        self.assertEqual(len(captured),1)
        for flag in ('--network=none','--read-only','--pull=never','--user=65534:65534'):
            self.assertIn(flag,captured[0])
    def test_61_home_browse_readonly(self):
        self.cfg['allowHomeRootReadOnly']=True; self.spec['write']=False; self.spec['gitWrite']=False; self.config.write_text(json.dumps(self.cfg))
        with patch('core.Path.home',return_value=self.root):
            backend=Backend(self.config); self.assertIn('hello',backend.read_text_file('code','a.py')['text'])
            with self.assertRaises(ValueError): backend.create_text_file('code','new.py','x')
    def test_62_home_write_forbidden(self):
        self.cfg['allowHomeRootReadOnly']=True; self.config.write_text(json.dumps(self.cfg))
        with patch('core.Path.home',return_value=self.root),self.assertRaises(ValueError): Backend(self.config)
    def test_63_home_private_subtree_denied(self):
        private=self.root/'service-private'; private.mkdir(); config=private/'config.json'; self.cfg['stateDir']=str(private/'state'); self.cfg['allowHomeRootReadOnly']=True; self.spec['write']=False; config.write_text(json.dumps(self.cfg))
        with patch('core.Path.home',return_value=self.root):
            backend=Backend(config)
            with self.assertRaises(ValueError): backend.read_text_file('code','service-private/config.json')
            self.assertNotIn('service-private',[item['name'] for item in backend.list_directory('code')['entries']])
            for handler in backend.audit.handlers: handler.close()

    def test_64_workspace_permissions_with_strict_umask(self):
        import threading
        self.b.projects['code']['tasks']={
            'test':{'image':'python@sha256:'+'0'*64,
                    'argv':['python','-m','unittest'],'timeout':60}}
        aid=self.approve(self.b.plan_task('code','test'))
        observed={}; done=threading.Event()
        def worker(job,cmd,timeout,folder):
            try:
                workspace=folder/'workspace'
                observed['root']=workspace.stat().st_mode & 0o777
                observed['src']=(workspace/'src').stat().st_mode & 0o777
                observed['file']=(workspace/'a.py').stat().st_mode & 0o777
                job['status']='mock_finished'
            finally:
                done.set()
        with patch.object(self.b,'rootless_docker_command',
                return_value=['/usr/bin/docker','--host',
                              'unix:///run/user/1000/docker.sock']), \
             patch.object(self.b,'task_worker',side_effect=worker):
            previous=os.umask(0o077)
            try:
                self.b.run_project_task(aid)
            finally:
                os.umask(previous)
            self.assertTrue(done.wait(5),'Mock worker did not finish')
        self.assertEqual(observed.get('root'),0o755)
        self.assertEqual(observed.get('src'),0o755)
        self.assertEqual(observed.get('file'),0o644)


    def cleanup_case(self, failure=None):
        from unittest.mock import MagicMock
        jobid='a'*32
        folder=self.state/'jobs'/jobid
        folder.mkdir()
        (folder/'workspace').mkdir()
        job={'id':jobid,'status':'running','container':'local-mcp-'+jobid,
             'text':'','exitCode':None,'project':'code','cleanupStatus':'pending'}
        self.b.jobs[jobid]=job
        command=['/usr/bin/docker','--host','unix:///run/user/1000/docker.sock','run']
        process=MagicMock()
        process.stdout.fileno.return_value=123
        process.poll.return_value=0
        process.returncode=0
        def cleanup(argv, **kwargs):
            self.assertEqual(argv,command[:3]+['rm','-f',job['container']])
            self.assertTrue(kwargs.get('check'))
            if failure is not None:
                raise failure
            return subprocess.CompletedProcess(argv,0)
        with patch('core.subprocess.Popen',return_value=process), \
             patch('core.os.set_blocking'), \
             patch('core.os.read',return_value=b''), \
             patch('core.subprocess.run',side_effect=cleanup):
            self.b.task_worker(job,command,60,folder)
        self.assertEqual(job['status'],'finished')
        self.assertEqual(job['exitCode'],0)
        self.assertFalse((folder/'workspace').exists())
        stored=json.loads((folder/'result.json').read_text())
        self.assertEqual(stored['cleanupStatus'],job['cleanupStatus'])
        self.assertEqual(self.b.get_task_status(jobid)['cleanupFailed'],job['cleanupFailed'])
        return job

    def test_65_cleanup_success(self):
        result=self.cleanup_case()
        self.assertEqual(result['cleanupStatus'],'succeeded')
        self.assertFalse(result['cleanupFailed'])
        self.assertEqual(result['cleanupExitCode'],0)

    def test_66_cleanup_nonzero(self):
        result=self.cleanup_case(subprocess.CalledProcessError(7,['docker','rm']))
        self.assertEqual(result['cleanupStatus'],'failed')
        self.assertTrue(result['cleanupFailed'])
        self.assertEqual(result['cleanupExitCode'],7)
        self.assertEqual(result['cleanupErrorType'],'CalledProcessError')

    def test_67_cleanup_timeout(self):
        result=self.cleanup_case(subprocess.TimeoutExpired(['docker','rm'],10))
        self.assertEqual(result['cleanupStatus'],'failed')
        self.assertTrue(result['cleanupFailed'])
        self.assertIsNone(result['cleanupExitCode'])
        self.assertEqual(result['cleanupErrorType'],'TimeoutExpired')

if __name__=='__main__': unittest.main(verbosity=1)
