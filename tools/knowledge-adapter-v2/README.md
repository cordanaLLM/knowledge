# knowledge-adapter-v2

Offline, deterministic adapter that turns the **accepted v2 source-acquisition
receipt/proposal** (P1-SRC-03) into a reviewed source bundle **per authority**
and drives the frozen `knowledge-snapshot` and `knowledge-evidence` compilers.
It is the "later explicit adapter" the acquisition runner's `AGENTS.md`
anticipates: it consumes the versioned v2 receipt/proposal but never edits or
weakens the frozen v1 snapshot/evidence contract, the frozen v2 acquisition
runner, or any schema.

## What it does

For each of the three acquisition authorities (`cilium v1.19.5`, `go go1.26.5`,
`kubernetes v1.36.2`) the adapter:

1. Builds a `knowledge-snapshot` v1 `SourceSpec` whose component, version,
   commit, canonical URI, rights, and every file digest/size are taken from —
   and re-verified against — the acquisition receipt/proposal target. Sources
   are `official`, `public`, `retrieval="true"`, and the GitHub 40-hex commit is
   bound into `canonical_uri`.
2. Wraps it as an unreviewed, non-authoritative `InventoryProposal` whose
   `metadata_sha256` binds the acquisition receipt id, proposal id, authority id,
   target id, and source-set id.
3. Emits an `accepted` `source_spec_review` receipt and signs it with a detached
   Ed25519 SSHSIG (namespace `archeion-knowledge-source-review-v1`) under a
   **deterministic, non-secret development review identity** derived from a fixed
   public seed. The public `allowed_signers` trust policy is regenerated each
   run; no private key is ever written to the tree.
4. Lays the authority's raw blobs into a private mirror (each blob re-hashed
   against the reviewed expectation) and runs `knowledge-snapshot compile` →
   one `snapshot-manifest:sha256:…`.
5. Runs `knowledge-evidence compile` (wire identity `knowledge-evidence@1.2.0`)
   over that snapshot, the raw CAS, and the same review bundle → one
   gap-free `evidence-manifest:sha256:…` under the inert
   `untrusted_evidence_content` envelope.

Three authorities yield three **distinct** snapshot ids and three distinct
evidence ids with no cross-authority payload, span, or occurrence reuse. Two
fully independent runs are byte-identical.

The adapter performs no retrieval, no admission policy, no pointer/generation/
production mutation, and signs nothing beyond the dev-key review bundle.
`verified` and the retrieval authority stay false throughout.

## Signing choice

The plain reviewed-bundle path (dev-key SSHSIG) is used rather than
`standing-admit` because (a) the `go go1.26.5` authority cannot satisfy the
standing policy's mandatory `v`-prefixed strict-semver version gate, and
(b) `standing-admit` requires a live `0400` private key at every run, which is
incompatible with committing byte-reproducible acceptance evidence without a
committed secret. A deterministic public seed keeps the review signature — and
therefore the committed manifests — reproducible without ever committing a key.

## Usage

```bash
bin=$(mktemp -d)
( cd tools/knowledge-snapshot && go build -o "$bin/knowledge-snapshot" . )
( cd tools/knowledge-evidence && go build -o "$bin/knowledge-evidence" . )
( cd tools/knowledge-adapter-v2 && go build -o "$bin/knowledge-adapter-v2" . )

work=$(mktemp -d)
out=".workingdir2/cache/p1-src03-adapter-$(date -u +%Y%m%dT%H%M%SZ)"
"$bin/knowledge-adapter-v2" emit \
  --receipt tools/knowledge-adapter-v2/testdata/acquisition/receipt.json \
  --proposal tools/knowledge-adapter-v2/testdata/acquisition/proposal.json \
  --cas-root tools/knowledge-retrieval/testdata/scorer-blind-multidomain-v1/source-blobs \
  --snapshot-bin "$bin/knowledge-snapshot" \
  --evidence-bin "$bin/knowledge-evidence" \
  --work-root "$work" --out-root "$out"
```

`--cas-root` is any content-addressed store laid out as `sha256/<first-two>/<hex>`.
The committed frozen source blobs under `knowledge-retrieval/testdata` are
byte-identical to the acquisition cache blobs, so either works.

## Gate

```bash
cd tools/knowledge-adapter-v2 && gofmt -l . && go vet ./... && go test -race -count=1 ./...
```

The tests build the two compiler binaries, exercise the full pipeline, and
assert cross-run determinism, per-authority distinctness/non-aliasing,
acquisition cross-binding, and fail-closed behaviour on store overlap, symlinked
mirrors, tampered snapshot manifests, mismatched trust roots, and forged reviews.
Source, tests, and the acquisition receipt/proposal fixtures are tracked; built
executables are never source files.
