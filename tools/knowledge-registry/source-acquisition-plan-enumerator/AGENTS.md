# source-acquisition-plan-enumerator

Authors `source-acquisition-runner-v3` contract for new authority walking
exact Git tree chain from pinned ref/commit. Extracts tree-chain
resolution previously inside runner data plane, keeping fail-closed
proofs: annotated-tag chain (bounded, cycle-rejected, final object ==
pinned commit), non-recursive tree walk, per-object git `blob <n>\0<raw>`
SHA-1 + raw SHA-256 + byte-count reconstruction, redirect-before-send ban.

## Ref kinds

`ref_kind` selects ref resolution path (absent/`tag` byte-identical to
prior contracts; existing signed plans unchanged):

- absent or `tag`: resolve `/git/ref/tags/<tag>` and annotated-tag chain.
- `branch`: resolve `/git/ref/heads/<branch>` via redirect-banned client,
  require head commit equal `expected_commit_sha1`, bind commit directly
  (`expected_ref_object_type` `commit`, empty tag chain) like lightweight
  tag. Enables ingesting untagged repos (operator GitOps/app repos);
  `requested_tag` carries branch name, optionally containing `/` (control
  chars, `..`, leading/trailing slashes fail closed).

## I/O

- Input: `work_id`, per-target repository (`org/repo`), pinned tag +
  expected commit, selected file paths, plus top-level spec inputs
  runner contract requires:
  - `freeze_id` / `freeze_document_sha256` -> comparison-only
    `source_denominator`.
  - `execution_manifest_id` / `execution_manifest_payload_sha256` ->
    `execution_gate`. Required equal runner embedded
    `execution-manifest.json` (id
    `source-acquisition-execution-manifest:sha256:b1b4a8e9…a7b9`, payload
    `sha256:b1b4a8e9…a7b9`) or runner rejects gate.
- Output: exact `source-acquisition-runner-v3` contract document:
  `$schema` `…/source-acquisition-contract-v2.schema.json`,
  `schema_version` `2.0.0`, `contract_kind`
  `source_file_set_acquisition_v2`, `review_state`
  `implementation_frozen`, capability
  `github-git-objects-rest-exact-file-v2`, `contract_id` /
  `contract_payload_sha256` self-address under
  `source-acquisition-contract:sha256:`, plus per-target/per-file
  resolutions and `bounds` — ready for acquisition service signing and
  runner consumption. Passes runner `validateContract` verbatim.
- GitHub REST layer injectable: tests exercise deterministic `httptest`
  tree; tampered blob (same length, different bytes) fails closed at
  SHA-1 reconstruction. `contract_alignment_test.go` re-runs faithful copy
  of runner `validateContract` over emitted document.

Blob modes `100644` and `100755` accepted (matching runner + data plane).

