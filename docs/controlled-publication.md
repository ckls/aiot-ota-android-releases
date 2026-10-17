# Controlled publication request

This is a distribution-only entry point. It never builds the application or reads
signing material. The existing manual `workflow_dispatch` entry, including its
`publish: false` draft mode, remains available.

## Two distinct reviewed changes

1. Land the already signed APK, `update-manifest.json`, `SHA256SUMS`, and
   `NOTES.md` under `staging/<version>/` on public `main`. Finish review of all
   four files first. The three downloadable assets retain the existing pinned
   APK signer, package identity, version/code, checksum, and byte-readback checks.
2. The authenticated owner `ckls` adds exactly one new, non-executable regular
   JSON file, `.release/requests/publish/v<version>.json`, directly atop that
   exact main commit. Its only parent must be the previous main commit. This
   separate request commit must not change any other path. A merge commit,
   multiple-commit push, force push, modified old request, or mixed change fails.

The workflow/configuration installation is itself a separate reviewed change.
Do not include an active publication request when installing or changing it.
If staging was landed before the installation, bind the request to the current
installation commit whose tree still contains the reviewed staging bytes.

A request has precisely these fields (replace placeholders; this example is not
an active request):

```json
{
  "schema_version": 1,
  "operation": "public-publish",
  "repository": "ckls/aiot-ota-android-releases",
  "base_main_sha": "<40 lowercase hex characters: immediately preceding main>",
  "version": "0.3.11",
  "version_code": 15,
  "artifacts": {
    "apk_sha256": "<64 lowercase hex characters>",
    "manifest_sha256": "<64 lowercase hex characters>",
    "checksum_sha256": "<64 lowercase hex characters>"
  }
}
```

The version must match the path and staged manifest. Both versionName and
versionCode must increase over the current latest release. Duplicate JSON keys,
unknown fields, non-integer codes, non-finite JSON numbers, malformed hashes,
symlinks, executable request files, and requests over 4096 bytes fail closed.
No private source, keys, tokens, credentials, or configurable commands are allowed.
The notes are bound by the base-main tree and the one-file-only commit diff.

## Execution and retry behavior

- Both GitHub `actor` and `triggering_actor` must be exactly `ckls`, and the push
  sender must be the authenticated user `ckls`. Commit author strings do not
  grant access. App/bot-authored pushes are not silently treated as the owner.
  The immutable actor/sender ID must be `22984376`; the environment and event
  repository ID must both be `1417051638`.
- A read-only job first validates the request against Git history and live main.
  Only a successful request can start the publication job with `contents: write`.
  The publication job checks out the same immutable SHA and revalidates it.
- Main must still equal the request commit, including on rerun. An obsolete
  request fails without re-promoting any release. Main is checked again before
  each tag, draft, asset, or publication mutation.
- The release tag and `target_commitish` point to `base_main_sha`, the exact
  previously staged tree. They do not point to an arbitrary branch name.
- The existing draft → three-asset metadata and byte readback → publish → final
  metadata/tag/three-asset byte readback sequence is retained.
- An already published result succeeds only after exact tag, release metadata,
  notes, three asset metadata records and downloaded bytes all match. This path
  uses GET only and does not change `latest`, even if a newer release exists.
- A workflow rerun can only perform that exact published-result verification.
  An absent release or partial draft is not automatically resumed on rerun.
  Even a separate first-attempt run rejects any pre-existing tag or incomplete
  draft. This also prevents duplicate event deliveries from resuming writes.
  Inspect uncertain outcomes before a new explicitly authorized action. The
  existing manual dispatch draft/resume path is unchanged.
- Unexpected existing bytes, tags, notes or metadata are never overwritten or
  deleted. Uncertain publish responses are not retried or cleaned up.
- Both entry points share the existing `apk-release` concurrency group, with
  `cancel-in-progress: false`. This default concurrency configuration is not a durable queue;
  later queued runs may replace an older pending run. Never assume a queued
  request was published until the run and release are verified.

## Security boundary and activation

This introduces automatic public publication upon an accepted owner request,
including writing a tag, a draft with three assets, publishing it and making it
latest. Explicitly review and approve this change before installing it remotely.
It does not change repository rules, permissions, plans, secrets, or credentials.
No new PAT, cross-repository credential, PR secret context, or privileged PR event
is introduced. The only write token is GitHub's existing ephemeral token in the
publication job. Checkout credentials are not persisted.

The current main branch is not protected by enforced checks/rulesets. The owner
and any administrator who can change workflows remain the trust root. A path
filter is a trigger optimization, not an authorization boundary. These code
checks cannot defend against an administrator replacing the guard/workflow.
Main rechecks and workflow concurrency are not an atomic lock against an
administrator making out-of-band repository/release changes between API calls.

Test locally with synthetic data before activation. An actual post-approval
request run is still necessary to establish that the connector's push is emitted
with the required owner identity and triggers Actions; commits made using a
workflow's own GITHUB_TOKEN ordinarily do not trigger a new workflow. Do not
weaken actor guards or add credentials to work around an identity mismatch.

## Official behavior references

- [GitHub actor and triggering-actor contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)
- [GitHub concurrency defaults](https://docs.github.com/en/actions/concepts/workflows-and-actions/concurrency)
- [GitHub workflow token behavior](https://docs.github.com/en/actions/concepts/security/github_token)
