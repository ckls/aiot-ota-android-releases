import importlib.util,io,json,os,socket,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('distributor',Path(__file__).with_name('distribute.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
COMMIT='a'*40
# Captured from official SDK 35.0.0 and 37.0.0, running verify --verbose --print-certs -Werr
# against public 0.3.1 APK SHA256 5237549b38c7a2a20d62baef6e08270bf02a7a25a04abd87b787c9f43465d0fb.
SDK35_CERT_OUTPUT = 'Verifies\nVerified using v1 scheme (JAR signing): false\nVerified using v2 scheme (APK Signature Scheme v2): true\nVerified using v3 scheme (APK Signature Scheme v3): true\nVerified using v3.1 scheme (APK Signature Scheme v3.1): false\nVerified using v4 scheme (APK Signature Scheme v4): false\nVerified for SourceStamp: false\nNumber of signers: 1\nSigner #1 certificate DN: CN=Local OTA Test Assistant\nSigner #1 certificate SHA-256 digest: a19601dfd8336c2f5835d1461f43b00739347b68076b70797b9ad3201b8657c9\nSigner #1 certificate SHA-1 digest: 189d5b89de9fc1d8bda8c27c3ce92de1d2f2fb34\nSigner #1 certificate MD5 digest: 837547d687ec41487de3a857b89e95f3\nSigner #1 key algorithm: RSA\nSigner #1 key size (bits): 3072\nSigner #1 public key SHA-256 digest: 4b9e696b8e7682f67f134d9a2429cd64c69f0fe67b2b9533deac1feacbe8f231\nSigner #1 public key SHA-1 digest: e450c4b5484728f064000d7e3fa1a8fda89846bf\nSigner #1 public key MD5 digest: 7563859d85ef1a05ca40215f1b788d76\n'
SDK37_CERT_OUTPUT = 'Verifies\nVerified using v1 scheme (JAR signing): false\nVerified using v2 scheme (APK Signature Scheme v2): true\nVerified using v3 scheme (APK Signature Scheme v3): true\nVerified using v3.1 scheme (APK Signature Scheme v3.1): false\nVerified using v3.2 scheme (APK Signature Scheme v3.2): false\nVerified using v4 scheme (APK Signature Scheme v4): false\nVerified for SourceStamp: false\nNumber of signers: 1\nV3.0 Signer: certificate DN: CN=Local OTA Test Assistant\nV3.0 Signer: certificate SHA-256 digest: a19601dfd8336c2f5835d1461f43b00739347b68076b70797b9ad3201b8657c9\nV3.0 Signer: certificate SHA-1 digest: 189d5b89de9fc1d8bda8c27c3ce92de1d2f2fb34\nV3.0 Signer: certificate MD5 digest: 837547d687ec41487de3a857b89e95f3\nV3.0 Signer: key algorithm: RSA\nV3.0 Signer: key size (bits): 3072\nV3.0 Signer: public key SHA-256 digest: 4b9e696b8e7682f67f134d9a2429cd64c69f0fe67b2b9533deac1feacbe8f231\nV3.0 Signer: public key SHA-1 digest: e450c4b5484728f064000d7e3fa1a8fda89846bf\nV3.0 Signer: public key MD5 digest: 7563859d85ef1a05ca40215f1b788d76\n'
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
    def make_tools(self,root,version='35.0.0'):
        tools=Path(root)/'build-tools'/version
        (tools/'lib').mkdir(parents=True)
        (tools/'aapt2').write_text('Synthetic test file; never executed')
        (tools/'lib/apksigner.jar').write_text('Synthetic test file; never executed')
        return tools

    def test_captured_official_sdk35_output_matches_one_pinned_signer(self):
        p.verify_signer(SDK35_CERT_OUTPUT)
        self.assertIn('Number of signers: 1',SDK35_CERT_OUTPUT)
        self.assertIn('Signer #1 certificate SHA-256 digest: '+p.PIN,SDK35_CERT_OUTPUT)

    def test_captured_sdk37_output_explains_the_legacy_parser_failure(self):
        self.assertIn('V3.0 Signer: certificate SHA-256 digest: '+p.PIN,SDK37_CERT_OUTPUT)
        self.assertEqual(p.re.findall(r'^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]+)$',SDK37_CERT_OUTPUT,p.re.M),[])
        with self.assertRaisesRegex(RuntimeError,'unsupported certificate output'):
            p.verify_signer(SDK37_CERT_OUTPUT)

    def test_multiple_signers_are_rejected_even_when_one_matches_pin(self):
        output=SDK35_CERT_OUTPUT.replace('Number of signers: 1','Number of signers: 2')
        output+='Signer #2 certificate SHA-256 digest: '+'f'*64+'\n'
        with self.assertRaisesRegex(RuntimeError,'Exactly one'):
            p.verify_signer(output)

    def test_missing_malformed_or_ambiguous_signer_output_is_rejected(self):
        expected='Signer #1 certificate SHA-256 digest: '+p.PIN
        values=[
            '',SDK35_CERT_OUTPUT.replace('Number of signers: 1','Number of signers: 0'),
            SDK35_CERT_OUTPUT.replace('Number of signers: 1','Number of signers: 01'),
            SDK35_CERT_OUTPUT+'Number of signers: 1\n',
            SDK35_CERT_OUTPUT.replace(expected,expected[:-1]),
            SDK35_CERT_OUTPUT.replace(expected,expected+'0'),
            SDK35_CERT_OUTPUT.replace(expected,expected.replace(p.PIN,'f'*64)),
            SDK35_CERT_OUTPUT.replace(expected,expected.replace('#1','#2')),
            SDK35_CERT_OUTPUT.replace(expected,'Signer #1 public key SHA-256 digest: '+p.PIN),
            SDK35_CERT_OUTPUT+expected+'\n',
            SDK35_CERT_OUTPUT+'Signer #2 certificate SHA-256 digest malformed\n',
            SDK35_CERT_OUTPUT+'V3.0 Signer: certificate SHA-256 digest: '+p.PIN+'\n',
        ]
        for index,output in enumerate(values):
            with self.subTest(case=index),self.assertRaises(RuntimeError):p.verify_signer(output)

    def test_source_stamp_cannot_substitute_for_the_apk_signer(self):
        stamp='Source Stamp Signer certificate SHA-256 digest: '+p.PIN+'\n'
        p.verify_signer(SDK35_CERT_OUTPUT+stamp)
        with self.assertRaises(RuntimeError):
            p.verify_signer(SDK35_CERT_OUTPUT.replace(p.PIN,'f'*64)+stamp)

    def test_tool_selection_pins_sdk35_even_when_newer_sdk_exists(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'ANDROID_HOME':directory}):
            trusted=self.make_tools(directory);self.make_tools(directory,'37.0.0')
            self.assertEqual(p.android_tools(),trusted)
            self.assertEqual(p.BUILD_TOOLS_VERSION,'35.0.0')

    def test_missing_pinned_tool_fails_without_newer_sdk_fallback(self):
        for missing in ('aapt2','lib/apksigner.jar','both'):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'ANDROID_HOME':directory}):
                self.make_tools(directory,'37.0.0')
                if missing!='both':
                    tools=self.make_tools(directory);(tools/missing).unlink()
                with self.assertRaisesRegex(RuntimeError,'35.0.0 must already be installed'):
                    p.android_tools()

    def test_inspection_uses_pinned_tools_and_warning_errors(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'ANDROID_HOME':directory}):
            tools=self.make_tools(directory);self.make_tools(directory,'37.0.0')
            root,manifest,assets,notes=p.bundle('0.3.1')
            badge="package: name='com.local.aiotota' versionCode='5' versionName='0.3.1'\nminSdkVersion:'26'\n"
            outputs=[SimpleNamespace(returncode=0,stdout=badge),SimpleNamespace(returncode=0,stdout=SDK35_CERT_OUTPUT)]
            with patch.object(p.subprocess,'run',side_effect=outputs) as run:
                p.inspect(root,manifest)
            commands=[call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0][0],str(tools/'aapt2'))
            self.assertEqual(commands[1][2],str(tools/'lib/apksigner.jar'))
            self.assertIn('-Werr',commands[1]);self.assertIn('--print-certs',commands[1])
            self.assertTrue(all('37.0.0' not in item for command in commands for item in command))

    def test_inspection_failure_prevents_api_mutations_even_with_pinned_text(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'ANDROID_HOME':directory}):
            self.make_tools(directory)
            badge="package: name='com.local.aiotota' versionCode='5' versionName='0.3.1'\nsdkVersion:'26'\n"
            outputs=[SimpleNamespace(returncode=0,stdout=badge),SimpleNamespace(returncode=1,stdout=SDK35_CERT_OUTPUT)]
            api=Fake()
            with patch.object(p.subprocess,'run',side_effect=outputs),self.assertRaisesRegex(RuntimeError,'Android artifact inspection failed'):
                p.distribute('0.3.1',True,api,COMMIT)
            self.assertEqual(api.calls,[])

    def test_workflow_keeps_main_only_serialized_public_release_guards(self):
        workflow=(Path(__file__).resolve().parents[1]/'workflows/publish-apk.yml').read_text()
        self.assertIn("github.repository == 'ckls/aiot-ota-android-releases'",workflow)
        self.assertIn("github.ref == 'refs/heads/main'",workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'",workflow)
        self.assertIn('group: apk-release',workflow);self.assertIn('cancel-in-progress: false',workflow)
        self.assertIn('persist-credentials: false',workflow)
        self.assertIn('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',workflow)
        self.assertNotIn('pull_request',workflow);self.assertNotIn('secrets.',workflow)
        self.assertIn('test -x "$ANDROID_HOME/build-tools/35.0.0/aapt2"',workflow)
        self.assertIn('test -f "$ANDROID_HOME/build-tools/35.0.0/lib/apksigner.jar"',workflow)
        self.assertLess(workflow.index('Require the verified Android Build Tools 35.0.0'),workflow.index('python3 .github/scripts/distribute.py'))

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

    def test_published_response_and_both_readbacks_preserve_reviewed_metadata(self):
        api=Fake()
        with patch('sys.stdout',io.StringIO()) as output:
            p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        pivot=next(i for i,call in enumerate(api.calls) if call[0]=='PATCH')
        base='/repos/'+p.REPO
        self.assertEqual(api.calls[pivot+1:pivot+3],[('GET',base+'/releases/7'),('GET',base+'/releases/latest')])
        self.assertEqual(api.release['target_commitish'],COMMIT)
        self.assertEqual(api.release['name'],'OTA 测试助手 0.3.1')
        self.assertEqual(api.release['body'],p.bundle('0.3.1')[3])
        self.assertIn('Published and verified v0.3.1',output.getvalue())

    def test_missing_or_changed_published_metadata_never_reports_success(self):
        changed={'id':99,'tag_name':'v0.3.2','target_commitish':'b'*40,
                 'name':'Changed release name','body':'Android caveat removed',
                 'draft':True,'prerelease':True}
        for stage in ('patch','release','latest'):
            for field,value in changed.items():
                for missing in (False,True):
                    with self.subTest(stage=stage,field=field,missing=missing):
                        class Drift(Fake):
                            def request(self,method,path,*args,**kwargs):
                                result=super().request(method,path,*args,**kwargs)
                                matches=(stage=='patch' and method=='PATCH') or (
                                    stage=='release' and method=='GET' and path.endswith('/releases/7') and not self.release['draft']) or (
                                    stage=='latest' and path.endswith('/releases/latest') and self.release and not self.release['draft'])
                                if matches:
                                    result=dict(result)
                                    if missing:result.pop(field,None)
                                    else:result[field]=value
                                return result
                        api=Drift()
                        with patch('sys.stdout',io.StringIO()) as output, self.assertRaisesRegex(RuntimeError,'Publication outcome is uncertain'):
                            p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
                        self.assertEqual(sum(method=='PATCH' for method,path in api.calls),1)
                        self.assertFalse(any(method=='DELETE' for method,path in api.calls))
                        self.assertEqual(sum('/assets?name=' in path for method,path in api.calls),3)
                        self.assertNotIn('Published and verified',output.getvalue())

    def test_missing_or_invalid_publish_readback_object_is_uncertain(self):
        for stage in ('patch','release','latest'):
            for replacement in (None,{},[],False):
                with self.subTest(stage=stage,replacement=replacement):
                    class Missing(Fake):
                        def request(self,method,path,*args,**kwargs):
                            result=super().request(method,path,*args,**kwargs)
                            if ((stage=='patch' and method=='PATCH') or
                                (stage=='release' and method=='GET' and path.endswith('/releases/7') and not self.release['draft']) or
                                (stage=='latest' and path.endswith('/releases/latest') and self.release and not self.release['draft'])):
                                return replacement
                            return result
                    api=Missing()
                    with patch('sys.stdout',io.StringIO()) as output, self.assertRaisesRegex(RuntimeError,'Publication outcome is uncertain'):
                        p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
                    self.assertEqual(sum(method=='PATCH' for method,path in api.calls),1)
                    self.assertFalse(any(method=='DELETE' for method,path in api.calls))
                    self.assertNotIn('Published and verified',output.getvalue())

    def test_lost_publish_response_never_retries_or_cleans_up(self):
        class Lost(Fake):
            def request(self,method,path,*args,**kwargs):
                result=super().request(method,path,*args,**kwargs)
                if method=='PATCH':raise OSError('Synthetic response loss after the mutation applied')
                return result
        api=Lost()
        with patch('sys.stdout',io.StringIO()) as output, self.assertRaisesRegex(RuntimeError,'Publication outcome is uncertain'):
            p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertFalse(api.release['draft'])
        self.assertEqual(sum(method=='PATCH' for method,path in api.calls),1)
        self.assertFalse(any(method=='DELETE' for method,path in api.calls))
        self.assertNotIn('Published and verified',output.getvalue())
        pivot=len(api.calls)
        with self.assertRaises(RuntimeError):p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertTrue(all(method=='GET' for method,path in api.calls[pivot:]))

    def test_postpublish_transport_failures_are_uncertain_without_retry(self):
        for suffix in ('/releases/7','/releases/latest','/releases/7/assets?per_page=100','/git/ref/tags/v0.3.1'):
            with self.subTest(suffix=suffix):
                class LostReadback(Fake):
                    def request(self,method,path,*args,**kwargs):
                        result=super().request(method,path,*args,**kwargs)
                        if method=='GET' and path.endswith(suffix) and self.release and not self.release['draft']:
                            raise OSError('Synthetic readback failure')
                        return result
                api=LostReadback()
                with patch('sys.stdout',io.StringIO()) as output, self.assertRaisesRegex(RuntimeError,'Publication outcome is uncertain'):
                    p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
                self.assertEqual(sum(method=='PATCH' for method,path in api.calls),1)
                self.assertFalse(any(method=='DELETE' for method,path in api.calls))
                self.assertNotIn('Published and verified',output.getvalue())

    def test_postpublish_asset_tamper_remains_uncertain(self):
        class Tamper(Fake):
            def request(self,method,path,*args,**kwargs):
                result=super().request(method,path,*args,**kwargs)
                if method=='PATCH':self.data[1]=b'Changed after publication'
                return result
        api=Tamper()
        with patch('sys.stdout',io.StringIO()) as output, self.assertRaisesRegex(RuntimeError,'Publication outcome is uncertain'):
            p.distribute('0.3.1',True,api,COMMIT,lambda r,m:None)
        self.assertEqual(sum(method=='PATCH' for method,path in api.calls),1)
        self.assertFalse(any(method=='DELETE' for method,path in api.calls))
        self.assertNotIn('Published and verified',output.getvalue())
if __name__=='__main__':
    with patch('socket.socket',side_effect=AssertionError('No network in regression')):unittest.main()
