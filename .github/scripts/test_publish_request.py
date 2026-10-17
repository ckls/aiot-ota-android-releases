"""Offline, synthetic Git/event/API tests; no Android signing or network."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import publish_request as q
import distribute as d

spec = importlib.util.spec_from_file_location('legacy_tests', Path(__file__).with_name('test_distribute.py'))
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q', '-b', 'main')
        self.version = '0.3.11'
        self.directory = self.root / 'staging' / self.version
        self.directory.mkdir(parents=True)
        apk = b'Synthetic APK fixture; never executable or signed.'
        manifest = {'schemaVersion': 1, 'packageName': 'com.local.aiotota',
                    'versionName': self.version, 'versionCode': 15, 'minSdk': 26,
                    'signingCertSha256': d.PIN, 'sha256': d.digest(apk), 'size': len(apk),
                    'assetName': 'aiot-ota-mobile-' + self.version + '.apk',
                    'tag': 'v' + self.version,
                    'downloadUrl': 'https://github.com/' + d.REPO + '/releases/download/v' + self.version + '/aiot-ota-mobile-' + self.version + '.apk'}
        self.assets = {manifest['assetName']: apk, 'update-manifest.json': json.dumps(manifest).encode()}
        self.assets['SHA256SUMS'] = ''.join(d.digest(data) + '  ' + name + '\n' for name, data in sorted(self.assets.items())).encode()
        self.manifest = manifest
        self.notes = 'Synthetic release notes with a retained caveat.\n'
        for name, data in self.assets.items():
            (self.directory / name).write_bytes(data)
        (self.directory / 'NOTES.md').write_text(self.notes)
        (self.root / 'README.md').write_text('Synthetic baseline\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic reviewed base')
        self.before = self.git('rev-parse', 'HEAD').strip()
        self.path = self.root / '.release/requests/publish/v0.3.11.json'
        self.request = {'schema_version': 1, 'operation': 'public-publish', 'repository': d.REPO,
                        'base_main_sha': self.before, 'version': self.version, 'version_code': 15,
                        'artifacts': {'apk_sha256': d.digest(apk),
                                      'manifest_sha256': d.digest(self.assets['update-manifest.json']),
                                      'checksum_sha256': d.digest(self.assets['SHA256SUMS'])}}
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps(self.request))
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic owner publication request')
        self.refresh()

    def git(self, *args):
        result = subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Synthetic Test',
                                 '-c', 'user.email=synthetic@example.invalid', *args],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def refresh(self):
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.env = {'GITHUB_REPOSITORY': d.REPO, 'GITHUB_REPOSITORY_ID': q.REPOSITORY_ID,
                    'GITHUB_REF': 'refs/heads/main', 'GITHUB_ACTOR_ID': q.OWNER_ID,
                    'GITHUB_EVENT_NAME': 'push', 'GITHUB_ACTOR': 'ckls',
                    'GITHUB_TRIGGERING_ACTOR': 'ckls', 'GITHUB_SHA': self.commit,
                    'GITHUB_RUN_ATTEMPT': '1'}
        self.event = {'sender': {'login': 'ckls', 'id': int(q.OWNER_ID), 'type': 'User'},
                      'repository': {'full_name': d.REPO, 'id': int(q.REPOSITORY_ID), 'private': False},
                      'ref': 'refs/heads/main', 'forced': False, 'deleted': False,
                      'created': False, 'before': self.before, 'after': self.commit}

    def amend(self, request=None, raw=None):
        if request is not None:
            self.path.write_text(json.dumps(request))
        if raw is not None:
            self.path.write_text(raw)
        self.git('add', '.')
        self.git('commit', '--amend', '-qm', 'Synthetic request variant')
        self.refresh()

    def validate(self):
        return q.validate_push(self.env, self.event, self.root)

    def bundle(self, version):
        self.assertEqual(version, self.version)
        return self.directory, self.manifest, dict(self.assets), self.notes

    def distribute(self, api, **kwargs):
        with patch.object(d, 'bundle', side_effect=self.bundle):
            return d.distribute(self.version, True, api, self.before, lambda r, m: None,
                                allow_published=True, **kwargs)

    def assert_read_only(self, api, start=0):
        self.assertTrue(all(method == 'GET' for method, path in api.calls[start:]))

    def test_owner_single_added_request_binds_base_version_and_three_hashes(self):
        self.assertEqual(self.validate(), self.request)

    def test_context_and_both_real_actor_checks(self):
        values = {'GITHUB_EVENT_NAME': ['workflow_dispatch', 'pull_request', 'pull_request_target'],
                  'GITHUB_REPOSITORY': ['someone/fork', 'ckls/aiot-ota-android'],
                  'GITHUB_REPOSITORY_ID': ['1', '', int(q.REPOSITORY_ID)],
                  'GITHUB_ACTOR_ID': ['1', '', int(q.OWNER_ID)],
                  'GITHUB_REF': ['refs/heads/feature', 'refs/tags/v0.3.11'],
                  'GITHUB_ACTOR': ['other', 'github-actions[bot]', 'CKLS'],
                  'GITHUB_TRIGGERING_ACTOR': ['other', 'github-actions[bot]', 'CKLS']}
        for key, variants in values.items():
            for value in variants:
                with self.subTest(key=key, value=value):
                    env = dict(self.env, **{key: value})
                    with self.assertRaises(RuntimeError):
                        q.validate_push(env, self.event, self.root)

    def test_stable_sender_and_repository_ids_are_required(self):
        for object_name in ('sender', 'repository'):
            for value in (None, 1, True, '22984376', '1417051638'):
                event = copy.deepcopy(self.event)
                event[object_name]['id'] = value
                with self.subTest(object_name=object_name, value=value), self.assertRaises(RuntimeError):
                    q.validate_push(self.env, event, self.root)

    def test_sender_is_not_commit_author_or_declared_json_owner(self):
        for sender in ({'login': 'someone', 'type': 'User'}, {'login': 'ckls', 'type': 'Bot'}, {}):
            with self.subTest(sender=sender), self.assertRaises(RuntimeError):
                q.validate_push(self.env, dict(self.event, sender=sender), self.root)

    def test_event_repo_ref_and_force_creation_deletion_rejected(self):
        for key, value in [('repository', {'full_name': d.REPO, 'private': True}),
                           ('repository', {'full_name': 'someone/fork', 'private': False}),
                           ('ref', 'refs/heads/other'), ('forced', True), ('created', True),
                           ('deleted', True), ('before', '0' * 40), ('before', '../main'),
                           ('after', 'a' * 40)]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                q.validate_push(self.env, dict(self.event, **{key: value}), self.root)

    def test_request_base_cannot_be_stale(self):
        self.amend(dict(self.request, base_main_sha='a' * 40))
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            self.validate()

    def test_a_push_with_multiple_commits_is_rejected(self):
        self.event['before'] = 'a' * 40
        with self.assertRaisesRegex(RuntimeError, 'single-parent'):
            self.validate()

    def test_wrong_checkout_is_rejected(self):
        self.env['GITHUB_SHA'] = 'b' * 40
        self.event['after'] = 'b' * 40
        with self.assertRaisesRegex(RuntimeError, 'Checkout'):
            self.validate()

    def test_merge_request_commit_is_rejected(self):
        tree = self.git('rev-parse', 'HEAD^{tree}').strip()
        merge = self.git('commit-tree', tree, '-p', self.before, '-p', self.commit, '-m', 'Synthetic merge').strip()
        self.git('checkout', '-q', '--detach', merge)
        self.refresh()
        with self.assertRaisesRegex(RuntimeError, 'single-parent'):
            self.validate()

    def test_request_mixed_with_source_workflow_or_notes_is_rejected(self):
        for name in ('README.md', '.github/workflows/publish-apk.yml', 'staging/0.3.11/NOTES.md'):
            with self.subTest(path=name), tempfile.TemporaryDirectory():
                file = self.root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('Synthetic mixed edit')
                self.amend()
                with self.assertRaisesRegex(RuntimeError, 'only add one file'):
                    self.validate()

    def test_second_request_in_same_commit_is_rejected(self):
        self.path.with_name('v0.3.12.json').write_text(json.dumps(self.request))
        self.amend()
        with self.assertRaisesRegex(RuntimeError, 'only add one file'):
            self.validate()

    def test_modification_not_new_addition_is_rejected(self):
        self.before = self.commit
        self.path.write_text(json.dumps(self.request) + '\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic modification of old request')
        self.refresh()
        with self.assertRaisesRegex(RuntimeError, 'only add one file'):
            self.validate()

    def test_request_path_cannot_encode_another_version(self):
        self.path.rename(self.path.with_name('v0.3.12.json'))
        self.amend()
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            self.validate()

    def test_symlink_and_executable_request_rejected(self):
        self.path.chmod(0o755)
        self.amend()
        with self.assertRaisesRegex(RuntimeError, 'regular Git file'):
            self.validate()
        self.path.unlink()
        self.path.symlink_to('../../../README.md')
        self.amend()
        with self.assertRaisesRegex(RuntimeError, 'regular Git file'):
            self.validate()

    def test_strict_schema_and_types_reject_unknown_omitted_and_unsafe_fields(self):
        variants = [dict(self.request, schema_version=True), dict(self.request, schema_version=2),
                    dict(self.request, version_code=True), dict(self.request, version_code=15.0),
                    dict(self.request, version_code=14), dict(self.request, version_code=2100000001),
                    dict(self.request, operation='private-sign'), dict(self.request, repository='other/repo'),
                    dict(self.request, version='../0.3.11'), dict(self.request, token='synthetic'),
                    dict(self.request, private_source='synthetic')]
        omitted = dict(self.request)
        omitted.pop('artifacts')
        variants.append(omitted)
        for variant in variants:
            with self.subTest(variant=variant):
                self.amend(variant)
                with self.assertRaises(RuntimeError):
                    self.validate()

    def test_duplicate_json_keys_and_nonfinite_values_are_rejected(self):
        for raw in ('{"x":1,"x":1}', '{"x":{"y":1,"y":2}}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                q.strict_json(raw)
        self.amend(raw=json.dumps(self.request)[:-1] + ',"version":"0.3.11"}')
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            self.validate()

    def test_oversized_request_rejected(self):
        self.amend(raw=json.dumps(self.request) + ' ' * 4096)
        with self.assertRaisesRegex(RuntimeError, 'size'):
            self.validate()

    def test_each_digest_mismatch_or_invalid_shape_is_rejected(self):
        for key in ('apk_sha256', 'manifest_sha256', 'checksum_sha256'):
            for value in ('0' * 64, 'F' * 64, 'x', None):
                with self.subTest(key=key, value=value):
                    request = copy.deepcopy(self.request)
                    request['artifacts'][key] = value
                    self.amend(request)
                    with self.assertRaises(RuntimeError):
                        self.validate()

    def test_staged_worktree_tampering_is_rejected(self):
        for name in list(self.assets) + ['NOTES.md']:
            file = self.directory / name
            original = file.read_bytes()
            file.write_bytes(b'Synthetic changed bytes')
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'differs'):
                self.validate()
            file.write_bytes(original)

    def test_staged_symlink_is_rejected(self):
        file = self.directory / 'NOTES.md'
        file.unlink()
        file.symlink_to('../../README.md')
        with self.assertRaisesRegex(RuntimeError, 'regular local file'):
            self.validate()

    def test_current_main_exact_match_and_drift(self):
        class MainApi:
            def __init__(self, sha): self.sha = sha
            def request(self, method, path):
                self.assertion = (method, path)
                return {'object': {'type': 'commit', 'sha': self.sha}}
        api = MainApi(self.commit)
        q.current_main(api, self.commit)
        self.assertEqual(api.assertion, ('GET', '/repos/' + d.REPO + '/git/ref/heads/main'))
        api.sha = 'f' * 40
        with self.assertRaisesRegex(RuntimeError, 'Main advanced'):
            q.current_main(api, self.commit)

    def test_published_identical_request_verifies_only_and_does_not_move_latest(self):
        api = legacy.Fake()
        self.distribute(api)
        start = len(api.calls)
        with patch('sys.stdout', io.StringIO()) as output:
            self.distribute(api, verify_only=True)
        self.assert_read_only(api, start)
        self.assertEqual(sum('/releases/assets/' in path for method, path in api.calls[start:]), 3)
        self.assertFalse(any(path.endswith('/releases/latest') for method, path in api.calls[start:]))
        self.assertIn('Already published and verified', output.getvalue())

    def test_changed_published_metadata_is_never_adopted(self):
        for key, value in {'target_commitish': 'f' * 40, 'name': 'changed', 'body': 'changed',
                           'prerelease': True, 'tag_name': 'v0.3.12'}.items():
            with self.subTest(key=key):
                api = legacy.Fake()
                self.distribute(api)
                api.release[key] = value
                start = len(api.calls)
                with self.assertRaises(RuntimeError): self.distribute(api)
                self.assert_read_only(api, start)

    def test_changed_published_bytes_metadata_tag_or_asset_set_never_overwritten(self):
        for tamper in ('bytes', 'digest', 'tag', 'extra', 'missing'):
            with self.subTest(tamper=tamper):
                api = legacy.Fake()
                self.distribute(api)
                if tamper == 'bytes': api.data[1] = b'Changed synthetic bytes'
                if tamper == 'digest': api.rows[0]['digest'] = 'sha256:' + 'f' * 64
                if tamper == 'tag': api.ref['object']['sha'] = 'f' * 40
                if tamper == 'extra': api.rows.append(dict(api.rows[0], id=99, name='extra.txt'))
                if tamper == 'missing': api.rows.pop()
                start = len(api.calls)
                with self.assertRaises(RuntimeError): self.distribute(api)
                self.assert_read_only(api, start)

    def test_rerun_absent_or_partial_draft_does_not_mutate(self):
        for draft in (False, True):
            with self.subTest(draft=draft):
                api = legacy.Fake()
                if draft:
                    with patch.object(d, 'bundle', side_effect=self.bundle):
                        d.distribute(self.version, False, api, self.before, lambda r, m: None)
                start = len(api.calls)
                with self.assertRaisesRegex(RuntimeError, 'Rerun may only verify'):
                    self.distribute(api, verify_only=True)
                self.assert_read_only(api, start)

    def test_separate_first_attempt_cannot_resume_existing_tag_or_draft(self):
        for existing in ('tag', 'draft'):
            with self.subTest(existing=existing):
                api = legacy.Fake()
                if existing == 'tag':
                    api.ref = {'object': {'type': 'commit', 'sha': self.before}}
                else:
                    with patch.object(d, 'bundle', side_effect=self.bundle):
                        d.distribute(self.version, False, api, self.before, lambda r, m: None)
                start = len(api.calls)
                with self.assertRaisesRegex(RuntimeError, 'no automatic resume'):
                    self.distribute(api, resume_existing=False)
                self.assert_read_only(api, start)

    def test_fresh_controlled_run_retains_draft_readback_publish_sequence(self):
        api = legacy.Fake()
        self.distribute(api, resume_existing=False)
        pivot = next(i for i, call in enumerate(api.calls) if call[0] == 'PATCH')
        self.assertEqual(sum('/releases/assets/' in path for method, path in api.calls[:pivot]), 3)
        self.assertEqual(sum('/releases/assets/' in path for method, path in api.calls[pivot:]), 3)
        self.assertEqual(api.release['target_commitish'], self.before)
        start = len(api.calls)
        self.distribute(api, resume_existing=False)
        self.assert_read_only(api, start)

    def test_file_and_git_size_guards_precede_reading_oversized_data(self):
        oversized = self.directory / 'NOTES.md'
        oversized.write_text('x' * 20001)
        with self.assertRaisesRegex(RuntimeError, 'staged input size'):
            self.validate()
        oversized.write_text(self.notes)
        real_git = q.git
        def fake_git(root, *args):
            if args[:2] == ('cat-file', '-s') and args[2].endswith('/NOTES.md'):
                return b'20001\n'
            return real_git(root, *args)
        with patch.object(q, 'git', side_effect=fake_git), self.assertRaisesRegex(RuntimeError, 'Git object size'):
            self.validate()

    def test_every_mutation_is_guarded_and_main_drift_stops_before_it(self):
        for permitted in range(6):
            with self.subTest(permitted=permitted):
                api = legacy.Fake()
                calls = []
                def guard():
                    calls.append('check')
                    if len(calls) > permitted: raise RuntimeError('Synthetic main drift')
                with self.assertRaisesRegex(RuntimeError, 'Synthetic main drift'):
                    self.distribute(api, before_mutation=guard)
                self.assertEqual(sum(method != 'GET' for method, path in api.calls), permitted)
                self.assertFalse(any(method == 'PATCH' for method, path in api.calls))

    def test_both_version_and_code_must_increase_before_any_mutation(self):
        for old_version, old_code in [('0.3.11', 14), ('0.3.10', 15), ('0.3.12', 16)]:
            with self.subTest(old_version=old_version, old_code=old_code):
                class Previous(legacy.Fake):
                    def request(self, method, path, *args, **kwargs):
                        if path.endswith('/releases/latest'):
                            self.calls.append((method, path))
                            return {'id': 90, 'draft': False, 'prerelease': False}
                        if path.endswith('/releases/90/assets?per_page=100'):
                            self.calls.append((method, path))
                            return [{'name': 'update-manifest.json', 'id': 91}]
                        if path.endswith('/releases/assets/91'):
                            self.calls.append((method, path))
                            return json.dumps({'versionName': old_version, 'versionCode': old_code}).encode()
                        return super().request(method, path, *args, **kwargs)
                api = Previous()
                with self.assertRaisesRegex(RuntimeError, 'Version must increase'):
                    self.distribute(api)
                self.assert_read_only(api)

    def test_wrapper_revalidates_and_routes_exact_base_to_distribution(self):
        with patch.object(q, 'load_push', return_value=self.request), patch.object(q, 'current_main') as guard, patch.object(d, 'distribute') as distribute:
            q.publish_request(object(), self.env, self.root)
            args, kwargs = distribute.call_args
            self.assertEqual(args[0:2], (self.version, True))
            self.assertEqual(args[3], self.before)
            self.assertTrue(kwargs['allow_published'])
            self.assertFalse(kwargs['verify_only'])
            self.assertFalse(kwargs['resume_existing'])
            kwargs['before_mutation']()
            self.assertEqual(guard.call_count, 2)
            self.env['GITHUB_RUN_ATTEMPT'] = '2'
            q.publish_request(object(), self.env, self.root)
            self.assertTrue(distribute.call_args.kwargs['verify_only'])

    def test_workflow_permissions_and_event_routes_are_bounded(self):
        workflow = (Path(__file__).resolve().parents[1] / 'workflows/publish-apk.yml').read_text()
        self.assertIn("paths: ['.release/requests/publish/**']", workflow)
        self.assertIn('permissions:\n  contents: read\n', workflow)
        self.assertEqual(workflow.count('contents: write'), 1)
        self.assertIn('    permissions:\n      contents: write', workflow)
        self.assertIn("github.actor == 'ckls' && github.triggering_actor == 'ckls'", workflow)
        self.assertIn("needs.validate-request.result == 'success'", workflow)
        self.assertIn('group: apk-release\n  cancel-in-progress: false', workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('fetch-depth: 2', workflow)
        self.assertNotIn('secrets.', workflow)
        self.assertNotIn('pull_request', workflow)
        self.assertNotIn('repository_dispatch', workflow)
        self.assertIn('publish_request.py validate', workflow)
        self.assertIn('publish_request.py publish', workflow)
        self.assertIn('python3 .github/scripts/distribute.py', workflow)


if __name__ == '__main__':
    with patch('socket.socket', side_effect=AssertionError('No network in synthetic regression')):
        unittest.main()
