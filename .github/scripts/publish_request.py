"""A request-only main push may publish one already staged, signed bundle.

No credentials, private build inputs, or executable commands belong in a request.
The owner remains the trust root; these checks do not protect against an admin
who can change the workflow itself.
"""
import json
import os
import re
import subprocess
from pathlib import Path

import distribute as d

ROOT = Path(__file__).resolve().parents[2]
OWNER = 'ckls'
OWNER_ID = '22984376'
REPOSITORY_ID = '1417051638'
SHA = r'[0-9a-f]{40}'
VERSION = r'(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})'
REQUEST = r'\.release/requests/publish/v(' + VERSION + r')\.json'


def strict_json(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    def pairs(items):
        result = {}
        for key, value in items:
            d.require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise RuntimeError('Non-finite JSON value')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args],
                            capture_output=True, timeout=30)
    d.require(result.returncode == 0, 'Request Git verification failed')
    return result.stdout


def validate_push(env, event, root=ROOT):
    d.require(env.get('GITHUB_EVENT_NAME') == 'push' and
              env.get('GITHUB_REPOSITORY') == d.REPO and
              env.get('GITHUB_REPOSITORY_ID') == REPOSITORY_ID and
              env.get('GITHUB_REF') == 'refs/heads/main', 'Request must be a public main push')
    d.require(env.get('GITHUB_ACTOR') == OWNER and
              env.get('GITHUB_ACTOR_ID') == OWNER_ID and
              env.get('GITHUB_TRIGGERING_ACTOR') == OWNER and
              event.get('sender', {}).get('login') == OWNER and
              event.get('sender', {}).get('id') == int(OWNER_ID) and
              event.get('sender', {}).get('type') == 'User', 'Only the authenticated owner may request publication')
    d.require(event.get('repository', {}).get('full_name') == d.REPO and
              event.get('repository', {}).get('id') == int(REPOSITORY_ID) and
              event.get('repository', {}).get('private') is False and
              event.get('ref') == 'refs/heads/main' and
              event.get('forced') is False and event.get('deleted') is False and
              event.get('created') is False, 'Invalid, forced, or newly created main push')
    commit = env.get('GITHUB_SHA', '')
    before = event.get('before', '')
    d.require(isinstance(before, str) and re.fullmatch(SHA, before) and before != '0' * 40 and
              re.fullmatch(SHA, commit) and event.get('after') == commit,
              'Push commit binding is invalid')
    d.require(git(root, 'rev-parse', 'HEAD').decode().strip() == commit,
              'Checkout does not match the request commit')
    parents = git(root, 'rev-list', '--parents', '-n', '1', commit).decode().split()
    d.require(parents == [commit, before], 'Request must be one new single-parent main commit')
    changes = git(root, 'diff-tree', '--no-commit-id', '--name-status', '--no-renames',
                  '-r', '-z', before, commit).split(b'\0')
    d.require(len(changes) == 3 and changes[0] == b'A' and changes[2] == b'',
              'Request commit must only add one file')
    path = changes[1].decode('utf-8')
    match = re.fullmatch(REQUEST, path)
    d.require(match is not None, 'Unexpected publication request path')
    entry = git(root, 'ls-tree', commit, '--', path).decode().strip()
    d.require(re.fullmatch(r'100644 blob ' + SHA + r'\t' + re.escape(path), entry),
              'Request must be a non-executable regular Git file')
    request_object = commit + ':' + path
    d.require(0 < int(git(root, 'cat-file', '-s', request_object)) <= 4096, 'Invalid request size')
    raw = git(root, 'show', request_object)
    d.require(0 < len(raw) <= 4096, 'Invalid request size')
    request = strict_json(raw)
    keys = {'schema_version', 'operation', 'repository', 'base_main_sha',
            'version', 'version_code', 'artifacts'}
    d.require(isinstance(request, dict) and set(request) == keys, 'Invalid request fields')
    d.require(type(request['schema_version']) is int and request['schema_version'] == 1 and
              request['operation'] == 'public-publish' and request['repository'] == d.REPO and
              request['base_main_sha'] == before and request['version'] == match.group(1) and
              type(request['version_code']) is int and 4 < request['version_code'] <= 2100000000,
              'Request identity does not match the staged main commit')
    hashes = request['artifacts']
    d.require(isinstance(hashes, dict) and set(hashes) ==
              {'apk_sha256', 'manifest_sha256', 'checksum_sha256'} and
              all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
                  for value in hashes.values()), 'Invalid artifact digests')
    # The complete tree diff above also binds the notes, scripts and workflows
    # to the previous main commit. Verify checked-out staging against Git bytes.
    directory = root / 'staging' / request['version']
    name = 'aiot-ota-mobile-' + request['version'] + '.apk'
    files = {name: 'apk_sha256', 'update-manifest.json': 'manifest_sha256',
             'SHA256SUMS': 'checksum_sha256', 'NOTES.md': None}
    for name, key in files.items():
        staged = directory / name
        d.require(staged.is_file() and not staged.is_symlink() and
                  not any(parent.is_symlink() for parent in staged.parents if parent != root.parent),
                  'Staged input is not a regular local file')
        limit = d.MAX if name.endswith('.apk') else (20000 if key is None else 16384)
        d.require(0 < staged.stat().st_size <= limit, 'Invalid staged input size')
        rel = str(staged.relative_to(root))
        tree = git(root, 'ls-tree', before, '--', rel).decode().strip()
        d.require(re.fullmatch(r'100644 blob ' + SHA + r'\t' + re.escape(rel), tree),
                  'Staged input was not already a regular file on main')
        staged_object = before + ':' + rel
        d.require(0 < int(git(root, 'cat-file', '-s', staged_object)) <= limit,
                  'Invalid staged Git object size')
        data = staged.read_bytes()
        d.require(data == git(root, 'show', staged_object), 'Staged input differs from approved main')
        if key:
            d.require(d.digest(data) == hashes[key], 'Request artifact digest mismatch')
    manifest = strict_json((directory / 'update-manifest.json').read_bytes())
    d.require(isinstance(manifest, dict) and manifest.get('versionName') == request['version'] and
              type(manifest.get('versionCode')) is int and
              manifest['versionCode'] == request['version_code'], 'Requested version identity mismatch')
    return request


def current_main(api, commit):
    ref = api.request('GET', '/repos/' + d.REPO + '/git/ref/heads/main')
    d.require(isinstance(ref, dict) and ref.get('object', {}).get('type') == 'commit' and
              ref['object'].get('sha') == commit, 'Main advanced; no further release mutation permitted')


def load_push(env=os.environ, root=ROOT):
    path = Path(env.get('GITHUB_EVENT_PATH', ''))
    d.require(path.is_file() and path.stat().st_size <= 1024 * 1024, 'Push event unavailable')
    return validate_push(env, strict_json(path.read_bytes()), root)


def publish_request(api, env=os.environ, root=ROOT):
    request = load_push(env, root)
    commit = env['GITHUB_SHA']
    guard = lambda: current_main(api, commit)
    guard()
    # Reruns may verify an exact published result but never resume a mutation.
    # workflow_dispatch retains its existing explicit draft/resume behavior.
    attempt = env.get('GITHUB_RUN_ATTEMPT', '')
    d.require(re.fullmatch(r'[1-9][0-9]*', attempt), 'Workflow attempt unavailable')
    d.distribute(request['version'], True, api, request['base_main_sha'],
                 allow_published=True, before_mutation=guard,
                 verify_only=attempt != '1', resume_existing=False)


def main():
    import sys
    try:
        d.require(len(sys.argv) == 2 and sys.argv[1] in ('validate', 'publish'), 'Invalid request operation')
        token = os.environ.get('GH_TOKEN', '')
        d.require(bool(token), 'Workflow temporary token missing')
        api = d.Api(token)
        if sys.argv[1] == 'publish':
            publish_request(api)
        else:
            request = load_push()
            current_main(api, os.environ['GITHUB_SHA'])
            print('Validated request for v' + request['version'] + '; no release mutation made')
    except Exception as error:
        print('Publication request stopped: ' +
              (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        sys.exit(1)


if __name__ == '__main__':
    main()
