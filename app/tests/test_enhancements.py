import ast, inspect, json, pathlib, subprocess, sys, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import core
import test_core as baseline

class EnhancementTests(unittest.TestCase):
    setUp=baseline.Tests.setUp
    tearDown=baseline.Tests.tearDown
    approve=baseline.Tests.approve
    plan=baseline.Tests.plan
    git_init=baseline.Tests.git_init

    def test_capabilities(self):
        report=self.b.get_capabilities('code')
        self.assertEqual(report['version'],'2.2.8-service-timeout-validation')
        self.assertFalse(report['features']['arbitraryShell'])
        self.assertFalse(report['features']['multiFileAtomic'])
        self.assertFalse(hasattr(self.b,'approve'))

    def test_default_directory_exclusion(self):
        (self.root/'credentials').mkdir()
        (self.root/'credentials'/'ordinary.txt').write_text('SENSITIVE')
        with self.assertRaises(ValueError): self.b.read_text_file('code','credentials/ordinary.txt')
        self.assertNotIn('credentials',[p['name'] for p in self.b.list_directory('code')['entries']])
        self.assertEqual(self.b.search_text('code','SENSITIVE')['results'],[])

    def test_directory_boundary(self):
        self.b.projects['code']['deny']=[]
        (self.root/'secrets2').mkdir(); (self.root/'secrets2'/'a.txt').write_text('public')
        self.assertEqual(self.b.read_text_file('code','secrets2/a.txt')['text'],'public')

    def test_custom_directory_exclusion(self):
        self.b.projects['code']['denyDirs']=['src']
        with self.assertRaises(ValueError): self.b.get_file_hash('code','src/code.ts')

    def test_invalid_directory_config(self):
        for item in ('../x','/tmp/x','src/*','a//b','a\\b'):
            self.spec['denyDirs']=[item]; self.config.write_text(json.dumps(self.cfg))
            with self.subTest(item=item), self.assertRaises(ValueError): core.Backend(self.config)

    def test_excluded_directory_writes(self):
        (self.root/'credentials').mkdir()
        with self.assertRaises(ValueError): self.b.create_text_file('code','credentials/new.py','x=1')

    def test_ast_references(self):
        (self.root/'a.py').write_text('def hello():\n    return 1\n# hello\nx="hello"\nhello()\nobj.hello()\n')
        data=self.b.find_references('code','hello',mode='python_ast')
        self.assertEqual([p['line'] for p in data['results']],[1,5,6])
        self.assertIn('not cross-module',data['method'])
        self.assertTrue(data['scanComplete'])

    def test_ast_references_limit(self):
        (self.root/'a.py').write_text('hello()\nhello()\n')
        data=self.b.find_references('code','hello',limit=1,mode='python_ast')
        self.assertTrue(data['truncated'])
        self.assertEqual(len(data['results']),1)

    def test_ast_bad_mode(self):
        with self.assertRaises(ValueError): self.b.find_references('code','x',mode='semantic_magic')

    def test_ast_bad_syntax(self):
        (self.root/'a.py').write_text('def broken(')
        data=self.b.find_references('code','hello',mode='python_ast')
        self.assertEqual(data['skippedFiles'],1)

    def test_literal_compatibility(self):
        self.assertIn('not semantic',self.b.find_references('code','hello')['method'])

    def test_summary_dependencies_and_entry(self):
        (self.root/'pyproject.toml').write_text('[project]\ndependencies=["requests>=2", "numpy"]\n[project.scripts]\ncli="app:main"\n')
        result=self.b.project_summary('code')
        self.assertEqual(result['dependencies'],['numpy','requests'])
        self.assertEqual(result['entryPoints'],{'cli':'app:main'})
        self.assertTrue(result['scanComplete'])

    def test_summary_imports_and_tests(self):
        (self.root/'a.py').write_text('import json\nfrom pathlib import Path\nif __name__ == "__main__":\n    pass\n')
        (self.root/'tests').mkdir(); (self.root/'tests'/'test_a.py').write_text('import unittest\n')
        result=self.b.project_summary('code')
        item=next(p for p in result['pythonModules'] if p['path']=='a.py')
        self.assertEqual(item['imports'],['json','pathlib']); self.assertTrue(item['mainGuard'])
        self.assertIn('tests/test_a.py',result['testFiles'])

    def test_summary_no_dependency_url_leak(self):
        (self.root/'requirements.txt').write_text('example @ https://user:PRIVATE@host/path\nhttps://PRIVATE@host/x\nrequests>=2\n')
        result=self.b.project_summary('code')
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertIn('example',result['dependencies'])

    def test_summary_parse_failure(self):
        (self.root/'pyproject.toml').write_text('[broken')
        self.assertIn('pyproject.toml',self.b.project_summary('code')['parseFailures'])

    def test_summary_does_not_execute(self):
        (self.root/'Makefile').write_text('all:\n\ttouch IMPOSSIBLE\n')
        self.b.project_summary('code')
        self.assertFalse((self.root/'IMPOSSIBLE').exists())

    def test_branches(self):
        self.git_init()
        result=self.b.git_branches('code')
        self.assertTrue(any(p['current'] for p in result['branches']))
        self.assertTrue(all(p['ref'].startswith('refs/heads/') for p in result['branches']))

    def test_branch_limit(self):
        self.git_init(); self.b.git_call('code',['branch','extra'])
        self.assertTrue(self.b.git_branches('code',limit=1)['truncated'])

    def stage_plan(self):
        self.git_init(); self.b.projects['code']['gitWrite']=True
        (self.root/'a.py').write_text('changed\n')
        return self.b.plan_git('code','stage',paths=['a.py'])

    def test_stage_preview_and_approval(self):
        plan=self.stage_plan()
        self.assertEqual(self.b.git_staged_paths('code')['paths'],[])
        with self.assertRaises(ValueError): self.b.apply_git(plan['approvalId'])
        self.b.apply_git(self.approve(plan))
        self.assertEqual(self.b.git_staged_paths('code')['paths'],['a.py'])

    def test_stage_conflict(self):
        plan=self.stage_plan(); aid=self.approve(plan)
        (self.root/'a.py').write_text('external change\n')
        with self.assertRaises(ValueError): self.b.apply_git(aid)
        self.assertEqual(self.b.git_staged_paths('code')['paths'],[])

    def test_stage_commit_workflow(self):
        plan=self.stage_plan(); self.b.apply_git(self.approve(plan))
        plan=self.b.plan_git('code','commit_staged',paths=['a.py'],message='staged commit')
        self.b.apply_git(self.approve(plan))
        self.assertEqual(self.b.git_staged_paths('code')['paths'],[])
        self.assertIn('staged commit',self.b.git_log('code','a.py')['text'])

    def test_staged_commit_extra_paths(self):
        plan=self.stage_plan(); self.b.apply_git(self.approve(plan))
        (self.root/'b.txt').write_text('extra\n'); self.b.git_call('code',['add','b.txt'])
        with self.assertRaises(ValueError): self.b.plan_git('code','commit_staged',paths=['a.py'],message='bad')

    def test_staged_content_conflict(self):
        plan=self.stage_plan(); self.b.apply_git(self.approve(plan))
        plan=self.b.plan_git('code','commit_staged',paths=['a.py'],message='bad')
        aid=self.approve(plan)
        original=(self.root/'a.py').read_text()
        (self.root/'a.py').write_text('different\n'); self.b.git_call('code',['add','a.py'])
        (self.root/'a.py').write_text(original)
        with self.assertRaises(ValueError): self.b.apply_git(aid)

    def test_git_permissions_preserved(self):
        with self.assertRaises(ValueError): self.b.plan_git('code','stage',paths=['a.py'])
        with self.assertRaises(ValueError): self.b.plan_git('code','reset',branch='main')

    def test_file_audit(self):
        self.b.apply_change(self.approve(self.plan()))
        records=self.b.get_audit()['entries']
        self.assertEqual(records[-1]['paths'],['a.py'])
        self.assertNotIn('content',records[-1])

    def test_audit_does_not_disclose_denied_paths(self):
        self.b.audit_event('read','error','code',paths=['.env','secret.txt','a.py'])
        self.assertEqual(self.b.get_audit()['entries'][-1]['paths'],['a.py'])

    def test_service_query_fixed_units(self):
        completed=subprocess.CompletedProcess([],0,b'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n',b'')
        with patch('enhancements.subprocess.run',return_value=completed) as call:
            result=self.b.get_service_status()
        self.assertEqual(len(result['units']),2)
        self.assertFalse(result['publicMcpUrlConfigured'])
        for invocation in call.call_args_list:
            self.assertEqual(invocation.args[0][0],'/usr/bin/systemctl')
            self.assertIn('--user',invocation.args[0])
            self.assertNotIn('enable',invocation.args[0])

    def test_service_unavailable(self):
        with patch('enhancements.subprocess.run',side_effect=OSError('unavailable')):
            report=self.b.get_service_status()
        self.assertTrue(all(p['state']=='unavailable' for p in report['units']))

    def test_service_url_rejects_credentials(self):
        self.cfg['publicMcpUrl']='https://user:PRIVATE@host/mcp'
        with patch('enhancements.subprocess.run',side_effect=OSError()):
            result=self.b.get_service_status()
        self.assertFalse(result['publicMcpUrlConfigured'])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_tool_schemas(self):
        source=(pathlib.Path(__file__).resolve().parents[1]/'server.py').read_text()
        tree=ast.parse(source)
        nodes=[]
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('DESCRIPTIONS','OVERRIDES') for t in node.targets): nodes.append(node)
            elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and isinstance(node.value.func.value,ast.Name) and node.value.func.value.id=='DESCRIPTIONS': nodes.append(node)
            elif isinstance(node,ast.FunctionDef) and node.name=='tool_schema': nodes.append(node)
        namespace={'inspect':inspect}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'schemas','exec'),namespace)
        import jsonschema
        descriptions=namespace['DESCRIPTIONS']
        self.assertTrue({'dev_execution_diagnose', 'dev_execution_preserve',
                         'dev_execution_request_recovery', 'dev_execution_apply_recovery'} <= descriptions.keys())
        for name in descriptions:
            fn=getattr(self.b,name)
            jsonschema.Draft7Validator.check_schema(namespace['tool_schema'](fn))
        schema=namespace['tool_schema'](self.b.find_references)
        self.assertEqual(schema['properties']['mode']['default'],'literal')

if __name__=='__main__': unittest.main(verbosity=1)
