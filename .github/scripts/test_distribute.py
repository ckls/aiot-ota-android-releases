import importlib.util,json,socket,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('distributor',Path(__file__).with_name('distribute.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
COMMIT='a'*40
class Fake:
    def __init__(self,tamper=False):self.calls=[];self.rows=[];self.data={};self.release=None;self.tamper=tamper;self.ref=None
    def request(self,method,path,body=None,upload=False,raw=False):
        self.calls.append((method,path))
        base='/repos/'+p.REPO
        if upload:
            name=path.split('name=')[1];identifier=len(self.rows)+1;self.data[identifier]=body
            row={'id':identifier,'name':name,'state':'uploaded','size':len(body),'digest':'sha256:'+p.digest(body)};self.rows.append(row);return row
        if raw:return self.data[int(path.rsplit('/',1)[1])]
        if path==base:return {'full_name':p.REPO,'private':False,'fork':False,'archived':False}
        if method=='POST' and path.endswith('/git/refs'):self.ref={'object':{'type':'commit','sha':body['sha']}};return self.ref
        if '/git/ref/' in path:return self.ref
        if path.endswith('/releases/latest'):return self.release if self.release and not self.release['draft'] else None
        if '/releases/tags/' in path:return self.release if self.release and not self.release['draft'] else None
        if '/releases?per_page=' in path:return [self.release] if self.release else []
        if method=='POST':self.release=dict(body,id=7);return self.release
        if method=='PATCH':self.release.update(body);return self.release
        if '/assets?' in path:
            rows=[dict(row) for row in self.rows]
            if self.tamper and rows:rows[0]['digest']='sha256:'+'0'*64
            return rows
        return self.release
class Tests(unittest.TestCase):
    def test_exact_manifest_matches_real_signed_file(self):
        root,m,assets,notes=p.bundle('0.3.1')
        self.assertEqual(m['signingCertSha256'],p.PIN);self.assertEqual(m['size'],len(assets[m['assetName']]))
        self.assertEqual(set(assets),{'aiot-ota-mobile-0.3.1.apk','update-manifest.json','SHA256SUMS'})
    def test_candidate_file_paths_cannot_escape(self):
        for v in ['../0.3.1','0.3.1;echo','0.3.1-beta','00.3.1','']:
            with self.subTest(v=v),self.assertRaises(RuntimeError):p.bundle(v)
    def test_draft_has_no_publish_operation(self):
        api=Fake();p.distribute('0.3.1',False,api,COMMIT,lambda r,m:None)
        self.assertTrue(api.release['draft']);self.assertFalse(any(method=='PATCH' for method,path in api.calls))
    def test_formal_publish_follows_three_readbacks(self):
        api=Fake();p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        pivot=next(i for i,x in enumerate(api.calls) if x[0]=='PATCH')
        self.assertEqual(sum('/releases/assets/' in path for method,path in api.calls[:pivot]),3)
        self.assertEqual(sum('/releases/assets/' in path for method,path in api.calls[pivot:]),3)
        self.assertFalse(api.release['draft']);self.assertFalse(api.release['prerelease'])
    def test_bad_remote_digest_does_not_publish(self):
        api=Fake(tamper=True)
        with self.assertRaises(RuntimeError):p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertTrue(api.release['draft']);self.assertFalse(any(method=='PATCH' for method,path in api.calls))
    def test_identical_verified_draft_can_be_published(self):
        api=Fake();p.distribute('0.3.1',False,api,COMMIT,lambda r,m:None)
        uploads=sum('/assets?name=' in path for method,path in api.calls)
        p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertFalse(api.release['draft'])
        self.assertEqual(sum('/assets?name=' in path for method,path in api.calls),uploads)
    def test_published_version_cannot_be_replaced(self):
        api=Fake();p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        pivot=len(api.calls)
        with self.assertRaises(RuntimeError):p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertTrue(all(method=='GET' for method,path in api.calls[pivot:]))
    def test_wrong_tag_prevents_any_upload_or_publish(self):
        api=Fake();api.ref={'object':{'type':'commit','sha':'b'*40}}
        with self.assertRaises(RuntimeError):p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertTrue(all(method=='GET' for method,path in api.calls))
    def test_changed_draft_is_never_adopted(self):
        api=Fake();p.distribute('0.3.1',False,api,COMMIT,lambda r,m:None)
        api.release['target_commitish']='b'*40;pivot=len(api.calls)
        with self.assertRaises(RuntimeError):p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertTrue(all(method=='GET' for method,path in api.calls[pivot:]))
    def test_draft_lookup_uses_authenticated_list(self):
        api=Fake();p.distribute('0.3.1',False,api,COMMIT,lambda r,m:None)
        self.assertIsNone(api.request('GET','/repos/'+p.REPO+'/releases/tags/v0.3.1'))
        self.assertEqual(p.find_release(api,'/repos/'+p.REPO,'v0.3.1')['id'],7)
    def test_wrong_existing_bytes_are_never_replaced(self):
        api=Fake();p.distribute('0.3.1',False,api,COMMIT,lambda r,m:None)
        api.data[1]=b'wrong';pivot=len(api.calls)
        with self.assertRaises(RuntimeError):p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertTrue(all(method=='GET' for method,path in api.calls[pivot:]))
if __name__=='__main__':
    with patch('socket.socket',side_effect=AssertionError('No network in regression')):unittest.main()
