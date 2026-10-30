import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from audit import DIGEST, analyze, examine_container, load_documents, parse_image, spec_from

D = 'sha256:'+'a'*64

def pod(image, policy=None):
    item={'name':'app', 'image':image}
    if policy is not None: item['imagePullPolicy']=policy
    return {'kind':'Pod','metadata':{'name':'demo'},'spec':{'containers':[item]}}

class ReferenceTest(unittest.TestCase):
    def test_valid_digest(self): self.assertTrue(DIGEST.fullmatch(D))
    def test_bad_digest(self): self.assertFalse(DIGEST.fullmatch('sha256:123'))
    def test_pinned(self): self.assertTrue(parse_image('repo/app@'+D)['pinned'])
    def test_pinned_with_tag(self): self.assertTrue(parse_image('repo/app:v1@'+D)['pinned'])
    def test_registry_port_no_tag(self): self.assertEqual(parse_image('registry:5000/app')['tag'],'latest')
    def test_registry_port_and_tag(self): self.assertEqual(parse_image('registry:5000/app:v2')['tag'],'v2')
    def test_explicit_latest(self): self.assertEqual(parse_image('app:latest')['tag'],'latest')
    def test_implicit_latest(self): self.assertTrue(parse_image('nginx')['implicit'])
    def test_malformed_digest(self): self.assertIn('error', parse_image('x@sha256:bad'))
    def test_double_digest(self): self.assertIn('error',parse_image('x@'+D+'@'+D))
    def test_empty_image(self): self.assertIn('error',parse_image(''))
    def test_whitespace(self): self.assertIn('error',parse_image('x y'))
    def test_bad_tag(self): self.assertIn('error',parse_image('x::'))

class WorkloadTest(unittest.TestCase):
    def test_pod(self): self.assertEqual(spec_from(pod('nginx'))['containers'][0]['image'], 'nginx')
    def test_deployment(self):
        dep={'kind':'Deployment','spec':{'template':{'spec':{'containers':[{'image':'nginx'}]}}}}
        self.assertEqual(analyze([dep])['containers_checked'], 1)
    def test_cronjob(self):
        obj = {'kind': 'CronJob', 'spec': {'jobTemplate': {'spec': {'template': {'spec': {'containers': [{'image':'nginx'}]}}}}}}
        self.assertEqual(analyze([obj])['containers_checked'], 1)
    def test_unknown_kind(self): self.assertEqual(analyze([{'kind':'CustomResource','spec':{}}])['containers_checked'],0)
    def test_safe_digest(self): self.assertFalse(analyze([pod('alpine@'+D)])['findings'])
    def test_latest_high(self): self.assertEqual(analyze([pod('nginx:latest')])['findings'][0]['rule'],'IP001')
    def test_version_tag_medium(self): self.assertEqual(analyze([pod('nginx:v1')])['findings'][0]['rule'],'IP002')
    def test_pull_never(self): self.assertIn('IP003',[f['rule'] for f in analyze([pod('nginx@'+D,'Never')])['findings']])
    def test_bad_policy(self): self.assertIn('IP006',[f['rule'] for f in analyze([pod('nginx@'+D,'Unknown')])['findings']])
    def test_cached_tag(self): self.assertIn('IP005',[f['rule'] for f in analyze([pod('nginx:v1','IfNotPresent')])['findings']])
    def test_pinned_ifnotpresent(self): self.assertFalse(analyze([pod('nginx@'+D,'IfNotPresent')])['findings'])
    def test_init_containers(self):
        p=pod('main@'+D);p['spec']['initContainers']=[{'image':'init:latest'}]
        self.assertEqual(analyze([p])['containers_checked'], 2)
    def test_ephemeral_containers(self):
        p=pod('main@'+D);p['spec']['ephemeralContainers']=[{'image':'debug:latest'}]
        self.assertEqual(analyze([p])['containers_checked'], 2)
    def test_list_kind(self): self.assertEqual(analyze([{'kind':'List','items':[pod('x@'+D)]}])['containers_checked'],1)
    def test_bad_list(self): self.assertEqual(analyze([{'kind':'List','items':{}}])['findings'][0]['rule'],'IP008')
    def test_missing_image(self): self.assertIn('IP007',[f['rule'] for f in analyze([{'kind':'Pod','spec':{'containers':[{'name':'x'}]}}])['findings']])
    def test_bad_collection(self): self.assertIn('IP008',[f['rule'] for f in analyze([{'kind':'Pod','spec':{'containers':'hi'}}])['findings']])
    def test_empty_document(self): self.assertEqual(analyze([None,{}])['containers_checked'],0)

class CLITest(unittest.TestCase):
    def setUp(self): self.d=tempfile.TemporaryDirectory();self.path=Path(self.d.name)/'workload.yml';self.script=Path(__file__).resolve().parents[1]/'scripts/audit.py'
    def tearDown(self): self.d.cleanup()
    def test_yaml_multiple(self):
        self.path.write_text('kind: Pod\nspec:\n  containers:\n  - image: nginx:latest\n---\nkind: Pod\nspec:\n  containers:\n  - image: busybox:1\n')
        self.assertEqual(analyze(load_documents(self.path))['containers_checked'],2)
    def test_oversize(self):
        self.path.write_text('x'* (1024*1024+1))
        with self.assertRaises(ValueError):load_documents(self.path)
    def test_cli_threshold(self):
        self.path.write_text('kind: Pod\nspec:\n  containers:\n  - image: nginx:latest\n')
        base=[sys.executable,str(self.script),str(self.path),'--format','json']
        r=subprocess.run(base,capture_output=True,text=True)
        self.assertEqual(r.returncode,2);self.assertEqual(json.loads(r.stdout)['findings'][0]['rule'],'IP001')
        self.assertEqual(subprocess.run(base+['--fail-on','none'],capture_output=True).returncode,0)
    def test_cli_invalid(self):
        self.path.write_text('[not valid')
        r=subprocess.run([sys.executable,str(self.script),str(self.path)],capture_output=True)
        self.assertEqual(r.returncode,1)

if __name__=='__main__':unittest.main()
