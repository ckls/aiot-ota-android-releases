"""Distribution-only workflow: never builds an app or consumes signing keys."""
import hashlib,json,os,re,subprocess,sys,urllib.error,urllib.parse,urllib.request
from pathlib import Path

REPO='ckls/aiot-ota-android-releases'
PIN='a19601dfd8336c2f5835d1461f43b00739347b68076b70797b9ad3201b8657c9'
MAX=64*1024*1024
BUILD_TOOLS_VERSION='35.0.0'
VERSION=r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})'
HISTORY_PAGES=10

def require(ok,message):
    if not ok:raise RuntimeError(message)
def digest(data):return hashlib.sha256(data).hexdigest()
def bundle(version):
    require(re.fullmatch(VERSION,version),'Invalid version')
    root=Path(__file__).resolve().parents[2]/'staging'/version
    name='aiot-ota-mobile-'+version+'.apk'
    require({p.name for p in root.iterdir() if p.is_file()}=={name,'update-manifest.json','SHA256SUMS','NOTES.md'},'Unexpected staging file set')
    for file in root.iterdir():require(not file.is_symlink() and file.is_file(),'Only regular staging files accepted')
    payload=(root/name).read_bytes();manifest=(root/'update-manifest.json').read_bytes();sums=(root/'SHA256SUMS').read_bytes()
    require(0<len(payload)<=MAX and len(manifest)<16384 and len(sums)<16384,'Invalid bundle size')
    m=json.loads(manifest)
    expected={'schemaVersion':1,'packageName':'com.local.aiotota','versionName':version,'minSdk':26,'signingCertSha256':PIN,'sha256':digest(payload),'size':len(payload),'assetName':name,'tag':'v'+version,'downloadUrl':'https://github.com/'+REPO+'/releases/download/v'+version+'/'+name}
    require(set(m)==set(expected)|{'versionCode'} and type(m.get('versionCode')) is int and m['versionCode']>4,'Invalid manifest fields')
    for key,value in expected.items():require(m[key]==value,'Manifest mismatch: '+key)
    assets={name:payload,'update-manifest.json':manifest,'SHA256SUMS':sums}
    expected_sums=''.join(digest(data)+'  '+file+'\n' for file,data in sorted(assets.items()) if file!='SHA256SUMS')
    require(sums.decode('ascii')==expected_sums,'Invalid checksum file')
    notes=(root/'NOTES.md').read_text('utf-8');require(len(notes)<20000,'Release notes too large')
    return root,m,assets,notes

def android_tools():
    sdk=Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '/usr/local/lib/android/sdk')
    # Match the toolchain used to verify this release, rather than silently
    # adopting a newer CLI/output format when the hosted runner image changes.
    tools=sdk/'build-tools'/BUILD_TOOLS_VERSION
    require((tools/'aapt2').is_file() and (tools/'lib/apksigner.jar').is_file(),
            'Official Android Build Tools '+BUILD_TOOLS_VERSION+' must already be installed; no automatic fallback')
    return tools

def verify_signer(output):
    # This parser deliberately supports the pinned SDK 35 output contract.
    # SDK 37 uses scheme-labelled output; do not silently accept new formats.
    lines=output.splitlines()
    counts=[line for line in lines if line.startswith('Number of signers')]
    certs=[line for line in lines if 'certificate SHA-256 digest' in line
           and not line.startswith('Source Stamp Signer ')]
    require(counts==['Number of signers: 1'],'Exactly one unambiguous APK signer is required')
    require(certs==['Signer #1 certificate SHA-256 digest: '+PIN],'APK signer mismatch or unsupported certificate output')

def inspect(root,m):
    tools=android_tools();apk=root/m['assetName']
    def run(args):
        p=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=90)
        require(p.returncode==0,'Android artifact inspection failed');return p.stdout
    badge=run([tools/'aapt2','dump','badging',apk])
    packages=re.findall(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'",badge,re.M)
    minimum=re.findall(r"^(?:sdkVersion|minSdkVersion):'([0-9]+)'$",badge,re.M)
    require(packages==[(m['packageName'],str(m['versionCode']),m['versionName'])] and minimum==['26'],'APK identity mismatch')
    require('application-debuggable' not in badge,'Debuggable APK refused')
    cert=run(['java','-jar',tools/'lib/apksigner.jar','verify','--verbose','--print-certs','-Werr',apk])
    verify_signer(cert)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):return None

class Api:
    def __init__(self,token):self.token=token;self.opener=urllib.request.build_opener(NoRedirect())
    def request(self,method,path,body=None,upload=False,raw=False):
        require(path.startswith('/repos/'+REPO+'/') or path=='/repos/'+REPO,'Unexpected repository path')
        host='uploads.github.com' if upload else 'api.github.com'
        data=json.dumps(body).encode() if isinstance(body,dict) else body
        headers={'Authorization':'Bearer '+self.token,'User-Agent':'aiot-apk-distributor','Accept':'application/octet-stream' if raw else 'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10'}
        if data is not None:headers['Content-Type']='application/octet-stream' if upload else 'application/json'
        request=urllib.request.Request('https://'+host+path,data=data,method=method,headers=headers)
        try:
            with self.opener.open(request,timeout=30) as response:result=response.read((MAX if raw else 2*1024*1024)+1)
        except urllib.error.HTTPError as e:
            if method=='GET' and e.code==404:return None
            if method=='GET' and raw and e.code in (301,302,303,307,308):
                location=e.headers.get('Location','');uri=urllib.parse.urlsplit(location)
                require(uri.scheme=='https' and uri.hostname in ('release-assets.githubusercontent.com','objects.githubusercontent.com') and uri.port in (None,443) and not uri.username and not uri.password and uri.path.startswith('/github-production-release-asset/'),'Unexpected download redirect')
                # A signed CDN URL receives no GitHub credential.
                with self.opener.open(urllib.request.Request(location,headers={'User-Agent':'aiot-apk-distributor'}),timeout=30) as response:result=response.read(MAX+1)
            else:raise RuntimeError('GitHub returned HTTP '+str(e.code)+'; inspect draft before retry')
        require(len(result)<=(MAX if raw else 2*1024*1024),'Response too large')
        return result if raw else json.loads(result)

def verify_assets(api,identifier,assets,allow_missing=False):
    rows=api.request('GET','/repos/'+REPO+'/releases/'+str(identifier)+'/assets?per_page=100')
    require(isinstance(rows,list) and len({r['name'] for r in rows})==len(rows),'Duplicate or invalid draft assets')
    names={r['name'] for r in rows}
    require(names<=set(assets) and (allow_missing or names==set(assets)),'Draft asset set mismatch')
    for row in rows:
        data=assets[row['name']]
        require(row.get('state')=='uploaded' and row.get('size')==len(data) and row.get('digest')=='sha256:'+digest(data),'Remote asset metadata mismatch')
        require(api.request('GET','/repos/'+REPO+'/releases/assets/'+str(row['id']),raw=True)==data,'Remote asset bytes mismatch')
    return names

def verify_tag(api,base,tag,commit):
    ref=api.request('GET',base+'/git/ref/tags/'+tag)
    require(ref and ref.get('object',{}).get('type')=='commit' and ref['object'].get('sha')==commit,'Release tag does not match approved distribution commit')

def find_release(api,base,tag):
    # The by-tag endpoint documents published releases. Push-authenticated list
    # responses also contain drafts, so a 404 alone does not mean no draft exists.
    published=api.request('GET',base+'/releases/tags/'+tag)
    if published is not None:return published
    matches=[]
    for page in range(1,11):
        rows=api.request('GET',base+'/releases?per_page=100&page='+str(page))
        require(isinstance(rows,list),'Release history unavailable')
        matches.extend(row for row in rows if row.get('tag_name')==tag)
        require(len(matches)<=1,'Duplicate draft tags')
        if len(rows)<100:return matches[0] if matches else None
    raise RuntimeError('Release history exceeds bounded search; no mutation made')

def release_title(version,prerelease):
    return 'OTA 测试助手 '+version+(' [测试版]' if prerelease else '')

def verify_draft(release,tag,commit,version,notes,prerelease=False):
    require(isinstance(release,dict) and type(release.get('id')) is int and release['id']>0 and release.get('draft') is True and release.get('prerelease') is prerelease and release.get('tag_name')==tag and release.get('target_commitish')==commit and release.get('name')==release_title(version,prerelease) and release.get('body')==notes,'Draft does not match the reviewed bundle; no overwrite')

def verify_published(release,identifier,tag,commit,version,notes,prerelease=False):
    require(isinstance(release,dict) and type(release.get('id')) is int and release['id']==identifier and release.get('draft') is False and release.get('prerelease') is prerelease and release.get('tag_name')==tag and release.get('target_commitish')==commit and release.get('name')==release_title(version,prerelease) and release.get('body')==notes,'Published metadata does not match the reviewed draft')

def verify_stable_latest(api,base,expected):
    current=api.request('GET',base+'/releases/latest')
    require(isinstance(current,dict) and type(current.get('id')) is int
            and current['id']==expected['id'] and current.get('tag_name')==expected['tag']
            and current.get('target_commitish')==expected['commit']
            and current.get('draft') is False and current.get('prerelease') is False,
            'Stable Latest drifted or could not be verified')
    verify_tag(api,base,expected['tag'],expected['commit'])
    return current

def previous_version(api,base,identifier,tag):
    rows=api.request('GET',base+'/releases/'+str(identifier)+'/assets?per_page=100')
    require(isinstance(rows,list) and len(rows)<100 and all(isinstance(a,dict) for a in rows),
            'Published release asset set unavailable')
    candidates=[a for a in rows if a.get('name')=='update-manifest.json']
    require(len(candidates)==1,'Previous version manifest missing or ambiguous')
    row=candidates[0]
    require(type(row.get('id')) is int and row['id']>0 and row.get('state')=='uploaded'
            and type(row.get('size')) is int and 0<row['size']<16384,
            'Previous version manifest metadata invalid')
    data=api.request('GET',base+'/releases/assets/'+str(row['id']),raw=True)
    require(isinstance(data,bytes) and len(data)==row['size'] and row.get('digest')=='sha256:'+digest(data),
            'Previous version manifest bytes unverified')
    def unique(entries):
        obj={}
        for key,value in entries:
            require(key not in obj,'Duplicate previous version manifest key')
            obj[key]=value
        return obj
    try:
        m=json.loads(data,object_pairs_hook=unique)
    except (ValueError,UnicodeError) as error:
        raise RuntimeError('Previous version manifest malformed') from error
    require(isinstance(m,dict) and set(m)=={'assetName','downloadUrl','minSdk','packageName',
            'schemaVersion','sha256','signingCertSha256','size','tag','versionCode','versionName'},
            'Previous version manifest fields unsupported')
    name='aiot-ota-mobile-'+tag[1:]+'.apk'
    require(type(m['schemaVersion']) is int and m['schemaVersion']==1
            and m['packageName']=='com.local.aiotota' and type(m['minSdk']) is int and m['minSdk']==26
            and m['signingCertSha256']==PIN and m['tag']==tag and m['versionName']==tag[1:]
            and m['assetName']==name and m['downloadUrl']=='https://github.com/'+REPO+'/releases/download/'+tag+'/'+name
            and type(m['size']) is int and 0<m['size']<=MAX
            and isinstance(m['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',m['sha256'])
            and type(m['versionCode']) is int and 4<m['versionCode']<=2100000000,
            'Previous version manifest identity unsupported')
    return m['versionCode']

def verify_version_high_water(api,base,version,code,latest):
    # API list is owner-authenticated; drafts do not count. Preserve the
    # manifest and immutable Android code boundary across both release kinds.
    seen_ids=set();seen_tags=set();seen_codes=set();stable_by_id={}
    high_code=0;high_version=(0,0,0)
    for page in range(1,HISTORY_PAGES+1):
        rows=api.request('GET',base+'/releases?per_page=100&page='+str(page))
        require(isinstance(rows,list) and len(rows)<=100,'Version history unavailable')
        for row in rows:
            require(isinstance(row,dict) and type(row.get('id')) is int and row['id']>0
                    and isinstance(row.get('tag_name'),str) and type(row.get('draft')) is bool,
                    'Version history metadata invalid')
            identifier=row['id'];tag=row['tag_name']
            require(identifier not in seen_ids and tag not in seen_tags,'Version history is ambiguous')
            seen_ids.add(identifier);seen_tags.add(tag)
            if row['draft']:continue
            require(type(row.get('prerelease')) is bool and re.fullmatch('v'+VERSION,tag),
                    'Published version history has an unsupported release')
            previous_code=previous_version(api,base,identifier,tag)
            require(previous_code not in seen_codes,'Published versionCode history is ambiguous')
            seen_codes.add(previous_code)
            if not row['prerelease']:stable_by_id[identifier]=tag
            high_code=max(high_code,previous_code)
            high_version=max(high_version,tuple(map(int,tag[1:].split('.'))))
        if len(rows)<100:break
    else:
        raise RuntimeError('Version history exceeds bounded search; no publication permitted')
    if latest is not None:
        require(isinstance(latest,dict) and type(latest.get('id')) is int
                and latest.get('draft') is False and latest.get('prerelease') is False
                and latest.get('tag_name')==stable_by_id.get(latest['id'])
                and latest['id'] in stable_by_id,'Stable Latest not represented in published history')
    else:
        require(not stable_by_id,'Stable Latest missing from published history')
    require(code>high_code and tuple(map(int,version.split('.')))>high_version,
            'Version must increase beyond all published stable and test releases')

def distribute(version,publish,api,commit,validator=inspect,*,allow_published=False,before_mutation=lambda:None,verify_only=False,resume_existing=True,test_stable=None):
    require(re.fullmatch(r'[0-9a-f]{40}',commit),'Invalid distribution commit')
    root,m,assets,notes=bundle(version);validator(root,m)
    repo=api.request('GET','/repos/'+REPO)
    require(repo and repo.get('full_name')==REPO and repo.get('private') is False and not repo.get('fork') and not repo.get('archived'),'Distribution repository not verified')
    tag=m['tag'];base='/repos/'+REPO
    prerelease=test_stable is not None
    if prerelease:
        require(publish and tag!=test_stable['tag'],'Test release must not reuse the stable version')
        latest=verify_stable_latest(api,base,test_stable)
    def guard():
        before_mutation()
        if prerelease:verify_stable_latest(api,base,test_stable)
    release=find_release(api,base,tag)
    if allow_published and release and release.get('draft') is False:
        # An owner-request rerun is idempotent only after verifying everything.
        # Never re-publish, move the tag, change latest, or replace any asset.
        identifier=release.get('id')
        require(type(identifier) is int and identifier>0,'Invalid published release identity')
        verify_published(release,identifier,tag,commit,version,notes,prerelease)
        verify_tag(api,base,tag,commit)
        verify_assets(api,identifier,assets)
        verify_published(api.request('GET',base+'/releases/'+str(identifier)),identifier,tag,commit,version,notes,prerelease)
        verify_tag(api,base,tag,commit)
        if prerelease:verify_stable_latest(api,base,test_stable)
        print('Already published and verified '+tag+'; no mutation made');return
    require(not verify_only,'Rerun may only verify an exact published release; inspect incomplete state before a new explicit action')
    require(resume_existing or release is None,'Existing incomplete release requires explicit inspection; no automatic resume')
    if release:
        verify_draft(release,tag,commit,version,notes,prerelease)
    ref=api.request('GET',base+'/git/ref/tags/'+tag)
    require(resume_existing or ref is None,'Existing release tag requires explicit inspection; no automatic resume')
    if ref:verify_tag(api,base,tag,commit)
    if not prerelease:latest=api.request('GET',base+'/releases/latest')
    verify_version_high_water(api,base,version,m['versionCode'],latest)
    if ref is None:
        guard()
        api.request('POST',base+'/git/refs',{'ref':'refs/tags/'+tag,'sha':commit})
        verify_tag(api,base,tag,commit)
    if release is None:
        guard()
        release=api.request('POST',base+'/releases',{'tag_name':tag,'target_commitish':commit,'name':release_title(version,prerelease),'body':notes,'draft':True,'prerelease':prerelease})
    verify_draft(release,tag,commit,version,notes,prerelease)
    identifier=release['id']
    present=verify_assets(api,identifier,assets,allow_missing=True)
    for name,data in assets.items():
        if name not in present:
            guard()
            api.request('POST',base+'/releases/'+str(identifier)+'/assets?name='+urllib.parse.quote(name),data,upload=True)
    verify_assets(api,identifier,assets)
    current=api.request('GET',base+'/releases/'+str(identifier))
    verify_draft(current,tag,commit,version,notes,prerelease)
    require(current['id']==identifier,'Draft identity changed')
    if not publish:print('Verified draft '+tag+'; not published');return
    verify_tag(api,base,tag,commit)
    guard()
    live_latest=verify_stable_latest(api,base,test_stable) if prerelease else api.request('GET',base+'/releases/latest')
    verify_version_high_water(api,base,version,m['versionCode'],live_latest)
    guard()
    try:
        result=api.request('PATCH',base+'/releases/'+str(identifier),{'draft':False,'prerelease':prerelease,'make_latest':'false' if prerelease else 'true'})
        verify_published(result,identifier,tag,commit,version,notes,prerelease)
        final=api.request('GET',base+'/releases/'+str(identifier))
        verify_published(final,identifier,tag,commit,version,notes,prerelease)
        if prerelease:
            tagged=api.request('GET',base+'/releases/tags/'+tag)
            verify_published(tagged,identifier,tag,commit,version,notes,True)
        else:
            latest=api.request('GET',base+'/releases/latest')
            verify_published(latest,identifier,tag,commit,version,notes)
        verify_assets(api,identifier,assets)
        verify_tag(api,base,tag,commit)
        if prerelease:verify_stable_latest(api,base,test_stable)
    except Exception:
        # A failed PATCH response or readback does not prove publication failed.
        # Do not retry, overwrite, or delete after the mutation may have applied.
        raise RuntimeError('Publication outcome is uncertain for '+tag+'; inspect remote state before another attempt. No automatic retry or cleanup was performed.') from None
    print('Published and verified '+tag+' with exactly three assets')

if __name__=='__main__':
    try:
        require(os.environ.get('GITHUB_REPOSITORY')==REPO,'Only the public distribution repository may run this workflow')
        token=os.environ.get('GH_TOKEN','');require(bool(token),'Workflow temporary token missing')
        commit=os.environ.get('GITHUB_SHA','');require(re.fullmatch(r'[0-9a-f]{40}',commit),'Distribution commit missing')
        distribute(os.environ.get('RELEASE_VERSION',''),os.environ.get('PUBLISH_RELEASE','').lower()=='true',Api(token),commit)
    except Exception as e:
        # Never print credential-bearing HTTP requests or third-party response bodies.
        print('Distribution stopped: '+str(e) if isinstance(e,RuntimeError) else 'Distribution stopped: '+type(e).__name__)
        sys.exit(1)
