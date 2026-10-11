# source-acquisition-plan-enumerator

Authors a `source-acquisition-runner-v3` contract for a new authority by walking
the exact Git tree chain from a pinned ref/commit. It extracts the
tree-chain resolution that previously lived only inside the runner's data plane,
with the same fail-closed proofs: annotated-tag chain (bounded, cycle-rejected,
final object == pinned commit), non-recursive tree walk, per-object git
`blob <n>\0<raw>` SHA-1 + raw SHA-256 + byte-count reconstruction, and
redirect-before-send ban.

## Ref kinds

`ref_kind` selects the ref resolution path (absent/`tag` stay byte-identical to
prior contracts, so existing signed plans are unchanged):

- absent or `tag`: resolve `/git/ref/tags/<tag>` and the annotated-tag chain.
- `branch`: resolve `/git/ref/heads/<branch>` through the same redirect-banned
  client, require the head to be a commit equal to `expected_commit_sha1`, and
  bind the commit directly (`expected_ref_object_type` `commit`, empty tag
  chain) exactly like a lightweight tag. This lets untagged repos (e.g. the
  operator's own GitOps/app repos) be ingested; `requested_tag` carries the
  branch name, which may contain `/` (control chars / `..` / leading-trailing
  slashes still fail closed).

## I/O

- Input: `work_id`, per-target repository (`org/repo`), pinned tag + expected
  commit, and selected file paths, plus the top-level spec inputs the runner's
  contract requires:
  - `freeze_id` / `freeze_document_sha256` -> the comparison-only
    `source_denominator`.
  - `execution_manifest_id` / `execution_manifest_payload_sha256` -> the
    `execution_gate`. These MUST equal the runner's embedded
    `execution-manifest.json` (id
    `source-acquisition-execution-manifest:sha256:b1b4a8e9…a7b9`, payload
    `sha256:b1b4a8e9…a7b9`) or the runner rejects the gate.
- Output: the EXACT `source-acquisition-runner-v3` contract document — `$schema`
  `…/source-acquisition-contract-v2.schema.json`, `schema_version` `2.0.0`,
  `contract_kind` `source_file_set_acquisition_v2`, `review_state`
  `implementation_frozen`, capability
  `github-git-objects-rest-exact-file-v2`, `contract_id` /
  `contract_payload_sha256` self-address under
  `source-acquisition-contract:sha256:`, plus per-target/per-file resolutions and
  `bounds` — ready to be signed with the acquisition service signer and fed to
  the runner. It passes the runner's `validateContract` verbatim.
- The GitHub REST layer is injectable so tests exercise a deterministic
  `httptest` tree; a tampered blob (same length, different bytes) fails closed at
  SHA-1 reconstruction. `contract_alignment_test.go` re-runs a faithful copy of
  the runner's `validateContract` over the emitted document.

Blob modes `100644` and `100755` are accepted (matching the runner + data plane).
