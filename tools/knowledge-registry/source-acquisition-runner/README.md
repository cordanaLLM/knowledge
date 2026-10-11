# Exact Git-object source acquisition runner

This first-party Go runner is the bounded data-plane implementation for the
accepted P1-SRC-02 Rollouts and Workflows chart-source targets. It consumes only
the exact plan-v3 replay
`source-acquisition-plan:sha256:7b06d690d2edfe08e1fd05060116b3ca08a2a8f82763976f4d4fe1232c844aad`
and never calls the legacy `docs/fetch-docs.sh` adapters.

The runner has no admission, signing, release, pointer, Git mutation, Argo,
Kubernetes, or production-mutation capability. Its receipt and inventory are
always `non_authoritative`, `unreviewed`, `compile_eligible=false`, and
`promote_eligible=false`. The plan's false execution flags remain intact; a
matching command-line acknowledgement prevents accidental execution but is not
an authorization artifact or approval substitute.

## Contract

- GitHub REST origin and version are fixed to `https://api.github.com` and
  `2026-03-10`, with capability-contract digest `dbc41fe1…`.
- Only `argoproj/argo-helm`, the two accepted tags/commits, and
  `charts/argo-rollouts` / `charts/argo-workflows` are reachable.
- Exact tag refs are resolved with an eight-object annotated-tag bound and cycle
  rejection. The final object must be the accepted commit.
- Trees are fetched one object at a time without `recursive`; `truncated=true`
  or any pagination `Link` header fails closed. Only modes `040000`, `100644`,
  and `100755` are accepted inside the selected subtree.
- Each decoded blob must reproduce its Git `blob <bytes>\0<raw>` SHA-1, raw
  SHA-256, and byte count before it enters the raw-SHA-256 CAS.
- GitHub's versioned HTTPS API remains the authority for commit, annotated-tag,
  and tree JSON projections. The runner independently reconstructs
  cryptographic Git identity only for decoded blobs. Stronger raw-object proof
  would require a separately reviewed raw-object transport and contract.
- CAS files, receipts, and inventory proposals are created directly at their
  final path with `O_EXCL`, then file- and directory-`fsync`ed. Exact-byte
  replay reopens the existing file read/write, revalidates it, and durably
  commits it before continuing. The root, subdirectories, and files must be
  effective-user-owned and private; published files must also have one link.
  Once exclusive creation succeeds, no error path deletes that final path: an
  uncertain write can therefore leave an invalid partial object that fails
  closed and requires operator inspection or quarantine, never a receipt
  inferred from partial bytes. A crash after receipt publication may leave
  that valid receipt without an inventory proposal; replay safely completes
  the same proposal and requires the final receipt/proposal sets to be exact
  singletons.

The frozen runner contract is
`sha256:6306df08e525472da822d10477ea12a9ec3929d14d9d322f842ac88b76401fdb`.
Output schemas are
`source-acquisition-receipt.schema.json`,
`source-inventory-proposal.schema.json`, and their exact common-type closure
`source-acquisition-output-common.schema.json`.

## Offline verification

First materialize plan v3 into an ignored declared run root, then verify it
without network access or output mutation:

```bash
repo_root="$(git rev-parse --show-toplevel)"
plan_root="$repo_root/.workingdir2/cache/p1-src-02-plan-v3"
mkdir -p "$plan_root"
python3 "$repo_root/tools/knowledge-registry/acquire_sources.py" plan-v3 \
  --artifact-bundle "$repo_root/knowledge/registry/acceptance/p1-src-02/accepted-record-artifact-bundle.json" \
  --component-id cmp:helm:argoproj/argo-rollouts \
  --component-id cmp:helm:argoproj/argo-workflows \
  --output "$plan_root/plan.json"

cd "$repo_root/tools/knowledge-registry/source-acquisition-runner"
go run . --plan "$plan_root/plan.json" --verify-only
```

## Explicit execution boundary

Network execution is a separate reviewed operation. After that approval exists,
use a fresh or previously created private declared output root. An optional
`GITHUB_TOKEN` raises public GitHub API rate limits; it is never serialized.

```bash
output_root="$repo_root/.workingdir2/cache/p1-src-02-git-object-run"
mkdir -m 0700 "$output_root"
GITHUB_TOKEN="${GITHUB_TOKEN:-}" go run . \
  --plan "$plan_root/plan.json" \
  --acknowledge-plan-id \
    source-acquisition-plan:sha256:7b06d690d2edfe08e1fd05060116b3ca08a2a8f82763976f4d4fe1232c844aad \
  --output-root "$output_root"
```

The output root contains only raw CAS blobs, content-addressed acquisition
receipts, and content-addressed inventory proposals. It has no `current` or
`previous` pointer. Rollback is removal of that declared scratch root after any
needed evidence is retained; no repository, registry, or cluster state changes.

## Tests

All transport tests use local `httptest` servers and make no live network call:

```bash
go test -race -cover ./...
go vet ./...
```

The suite covers lightweight and annotated tags, complete nested tree walking,
empty and executable blobs, byte-identical replay, partial-run recovery,
truncated trees, pagination signals, duplicate JSON keys, tag swaps, path
traversal, duplicate paths, unsupported modes, blob tampering, and CAS symlinks.
It also proves that conflicting or incomplete final-path bytes are rejected and
never cleaned up automatically. Private ownership/mode, single-link, directory
replacement, redirect/header ambiguity, exact receipt-only recovery, and final
publication-set ambiguity are separate negative cases.
