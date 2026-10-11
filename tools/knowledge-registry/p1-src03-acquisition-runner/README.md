# P1-SRC-03 exact-file acquisition runner

This sibling Go module acquires only the six files frozen for `P1-SRC-03` from
the three independent Cilium, Go, and Kubernetes authorities. It does not
modify or reuse the P1-SRC-02 Argo subtree runner. A regression test freezes
every P1-SRC-02 runner and v1 schema byte plus its accepted plan, artifact
bundle, and runner-contract identities.

The v2 acquisition contract is
`source-acquisition-contract:sha256:e2f0091cfad38a5a602cf2e3a1e4aed5c1b1b5d63a1798c127f8fb3be44c923a`.
It binds three distinct source-set and publisher identities, exact tag objects,
commits, commit root trees, every intermediate tree edge in all six paths, Git
blob SHA-1 values, raw SHA-256 values, licenses, and byte counts. The complete
denominator is three targets, six unique files, and 512,214 bytes.

| Source set | Exact version and commit | Files | Bytes |
|---|---|---:|---:|
| Cilium | `v1.19.5` / `20eaccfef029cb046d70219717fb6dbbdf27a59f` | 2 | 86,066 |
| Go | `go1.26.5` / `c19862e5f8415b4f24b189d065ed739517c548ba` | 2 | 27,561 |
| Kubernetes | `v1.36.2` / `24e2b02af5543d7910c2bb074c7264df5a8f0467` | 2 | 398,587 |

## Transport and failure boundary

The production origin is fixed to `https://api.github.com` and GitHub REST API
version `2026-03-10`. The runner uses the documented read-only Git reference,
annotated-tag, commit, non-recursive tree, and blob endpoints. Redirects,
pagination headers, non-identity encodings, ambiguous content types, duplicate
JSON keys, invalid UTF-8 or surrogate escapes, non-finite binary64 numbers,
signed-64-bit integer overflow, unexpected repositories, and bound overruns
fail closed. Contract, receipt, proposal, and execution-manifest content
addresses use the shared `registry_compact_utf8` profile exercised by
`testdata/canonical-json/v1/vectors.json` in both Go and Python.

Each path is resolved one exact segment at a time from the contract-bound root
tree. Every returned parent tree, child name, child type, mode, child SHA-1,
and terminal size must equal the contract's complete path chain. The leaf
mode, Git blob SHA-1, Git-reported size, decoded byte count, raw SHA-256, and
reconstructed `blob <size>\0<bytes>` Git identity must all agree before bytes
enter the private SHA-256 CAS. The committed retrieval fixtures are never read
by the production runner; tests use them only to serve an offline `httptest`
Git-object API.

GitHub documents the current endpoint semantics in its official
[references](https://docs.github.com/en/rest/git/refs?apiVersion=2026-03-10),
[tags](https://docs.github.com/en/rest/git/tags?apiVersion=2026-03-10),
[commits](https://docs.github.com/en/rest/git/commits?apiVersion=2026-03-10),
[trees](https://docs.github.com/en/rest/git/trees?apiVersion=2026-03-10), and
[blobs](https://docs.github.com/en/rest/git/blobs?apiVersion=2026-03-10)
references.

## Authority boundary

The output is only a content-addressed acquisition receipt plus an exact
inventory proposal under v2 schemas. Both are `non_authoritative`,
`unreviewed`, compilation-ineligible, and promotion-ineligible. Source
admission, retrieval release, signing, pointer writes, Git mutation, and
production mutation remain false.

The contract also binds expected execution manifest
`source-acquisition-execution-manifest:sha256:ed25ab8642f9fddfdad23eed5f944591a14242a6b0083b75e6d7fd075976528a`.
It content-addresses the exact runner sources, module definition, five acquisition
schemas, shared canonical vectors, and independent verifier. It also binds the
local `go1.26.5-X:nodwarf5` launcher and the complete 16,671-entry,
225,627,376-byte `/usr/lib/go` tree. The embedded gate deliberately remains
`external_exact_byte_verification_required`, `verified: false`, and
`predecessor_eligible: false`; running the verifier proves byte agreement but
does not silently grant source or predecessor authority.

The scorer-blind freeze identity is a `comparison_only` denominator binding,
not acquisition authority. This module deliberately does not create source
records, snapshots, evidence manifests, admission policies, SpanID crosswalks,
retrieval artifacts, or a v1/v2 adapter. The separately versioned adapter is
the next rollback unit after this v2 receipt/proposal contract is accepted.

## Offline contract verification

From this directory:

```bash
go run . --verify-only
go run . --print-contract
```

Neither command has a network or output-write path.

Verify the repository portion on any test host, or the complete pinned local
toolchain on the bound host:

```bash
repo_root="$(git rev-parse --show-toplevel)"
verifier="$repo_root/tools/knowledge-registry/p1-src03-acquisition-runner/verify_execution_manifest.py"
manifest="$repo_root/tools/knowledge-registry/p1-src03-acquisition-runner/execution-manifest.json"

python3 "$verifier" \
  --repository-root "$repo_root" \
  --manifest "$manifest" \
  --repository-only

python3 "$verifier" \
  --repository-root "$repo_root" \
  --manifest "$manifest"
```

## Explicit execution boundary

Use a fresh ignored run root only after the exact network operation is
approved. An optional `GITHUB_TOKEN` only raises public API rate limits and is
never serialized.

```bash
repo_root="$(git rev-parse --show-toplevel)"
output_root="$repo_root/.workingdir2/cache/p1-src-03-exact-file-acquisition"

go run . \
  --acknowledge-contract-id \
    source-acquisition-contract:sha256:e2f0091cfad38a5a602cf2e3a1e4aed5c1b1b5d63a1798c127f8fb3be44c923a \
  --output-root "$output_root"
```

The output root contains only `cas/sha256`, `receipts`, and
`inventory-proposals`. The store holds and replays no-follow directory
descriptors from the private output root through every write and verification.
Existing paths are accepted only when their private, single-link regular-file
bytes are identical and both the file and containing directory are durable.
Root, parent or leaf replacement, symlinks, hard links, conflicts and ambiguous
final receipt/proposal sets fail closed; nothing is deleted automatically.
An invalid token or proposal-without-receipt state is rejected before output
initialization. If a durable receipt exists without its proposal, the runner
strictly revalidates the receipt, exact CAS bytes, and complete lineage, then
reconstructs the only valid proposal without a network request. Conflicting,
ambiguous, malformed, or differently addressed publication state is rejected
before receipt or proposal synchronization.

## Tests

```bash
gofmt -w *.go
go test -race -count=1 ./...
go vet ./...
cd "$(git rev-parse --show-toplevel)"
python3 -m unittest discover -s tools/knowledge-registry/tests \
  -p 'test_p1_src03_acquisition_runner.py'
```

The suite proves independent byte-identical runs, v2 schema compatibility,
strict authority and exact path chains, P1-SRC-02 immutability, content-address
and lineage mutation rejection, offline receipt recovery, fail-before-write
publication preflight, shared canonical JSON behavior, execution-byte closure,
and fail-closed tag, redirect, path, size, blob, duplicate-key, source-alias,
and scope-widening cases. CI independently formats, vets, and race-tests both
the frozen v1 and hardened v2 modules.
