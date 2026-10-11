# Knowledge snapshot compiler

The repository retains source, tests and fixtures only. Deterministic binaries
belong in a declared ignored run root or reviewed artifact registry and must
not be committed beside the source.

`knowledge-snapshot` is the first offline P0.3 acquisition gate. It converts a
reviewed source specification plus an already-acquired exact-version mirror into
an immutable snapshot manifest and a SHA-256 content-addressed raw object store.
It performs no network requests and does not write to Kubernetes or another
production service.

This tool implements the raw-snapshot boundary plus a derived occurrence-level
change-pack gate. Parsing, normalized artifacts, exact coordinates, indexing,
promotion and serving remain later P0.3/P0.4 stages. A successful raw snapshot
is never an index or source authority by itself.

It also has a proposal-only inventory command for turning an explicit metadata
candidate plus a local mirror into a deterministic source-spec draft. Inventory
output is always marked `proposal`, `unreviewed`, `non_authoritative`,
`compile_eligible: false`, and `promote_eligible: false`. The command never calls
the compiler, writes raw objects, creates a complete manifest, or promotes data.

## Usage

```sh
GOCACHE=/tmp/knowledge-snapshot-gocache \
  go run . compile \
  --spec testdata/source-spec.json \
  --proposal testdata/review/inventory-proposal.json \
  --review-receipt testdata/review/accepted-review.json \
  --review-signature testdata/review/accepted-review.json.sig \
  --allowed-signers testdata/review/allowed_signers \
  --mirror-base testdata/mirrors \
  --store /tmp/knowledge-snapshot-store
```

To draft an inventory without accepting it:

```sh
GOCACHE=/tmp/knowledge-snapshot-gocache \
  go run . inventory \
  --metadata testdata/inventory-metadata.json \
  --mirror-base testdata/mirrors \
  --proposal-store /tmp/knowledge-inventory-proposals
```

To turn matching recurring official revisions into compiler-compatible signed
admissions under one separately reviewed standing policy:

```sh
GOCACHE=/tmp/knowledge-snapshot-gocache \
  go run . standing-policy \
  --core /etc/archeion/source-policy/argocd-docs-core.json \
  --store /srv/knowledge-standing-policies
```

`standing-policy` derives the content-addressed policy identity from the exact
canonical core and writes the complete public policy immutably. It neither
signs nor authorizes the result; an independent reviewer must still sign the
materialized policy before `standing-admit` accepts it.

```sh
GOCACHE=/tmp/knowledge-snapshot-gocache \
  go run . standing-admit \
  --proposal /srv/knowledge-proposals/inventory-proposal.json \
  --policy /etc/archeion/source-policy/argocd-docs.json \
  --policy-signature /etc/archeion/source-policy/argocd-docs.json.sig \
  --policy-allowed-signers /etc/archeion/trust/source-policy-reviewers \
  --signer-key /run/archeion-source-admission/id_ed25519 \
  --signer-allowed-signers /etc/archeion/trust/source-admission-signers \
  --decision-at 2026-07-16T09:30:00Z \
  --store /srv/knowledge-standing-admissions
```

`standing-admit` removes per-release interaction only inside the exact signed
policy envelope. The canonical policy has a content-derived
`source-admission-policy:sha256:...` identity and is itself covered by a
detached Ed25519 SSHSIG in namespace
`archeion-knowledge-standing-source-policy-v1`. It binds:

- one source-family prefix plus an exact bounded suffix around the resolved
  version (for example `src:github:argoproj/argo-cd@` + `v3.4.5` +
  `:docs-crds`), exact component identity, canonical HTTPS publisher/repository
  prefix, and official/primary origin kind;
- a sorted allowlist of official channel classes and transports;
- the exact rights/use, public security-domain and language profile;
- an immutable version-resolution profile (v1 accepts a `v`-prefixed semantic
  version tied to one full Git commit and the same commit in the GitHub URI);
- distinct policy-reviewer and bounded-service principals plus exact Ed25519
  public-key SHA-256 identities;
- the validation profile, maximum files, per-file bytes and total bytes; and
- a canonical UTC effective interval and explicit revocation state.

A match emits the ordinary `source_spec_review` receipt used by `compile`,
signed in `archeion-knowledge-source-review-v1` by the external bounded-service
key. The caller must supply one canonical UTC `--decision-at` value that is not
earlier than the proposal's already-bound `observed_at` and is inside the
policy's half-open effective interval. The receipt binds that value as
`reviewed_at` together with `admission_method: standing_policy`, the exact policy
ID and policy payload SHA-256. Repeated admission with identical evidence and
the same explicit decision time is byte deterministic. The output gives
immutable source-spec, receipt, signature and standing-admission manifest paths;
the existing compiler still performs its normal proposal/spec/signature/trust
checks and carries the policy identity into `review_admission`.

The private signer key must be a non-symlink owner-only Ed25519 key outside the
output store. It is opened only by the fixed `/usr/bin/ssh-keygen` signer, never
read, copied, returned or retained by this tool. Both reviewer and service
`allowed_signers` inputs remain external trust roots. Public policy, signature,
proposal, source spec, receipt and trust evidence are retained by digest; no
private key material is stored.

Publisher/channel/transport/rights/version/key/limit/time drift, a missing,
backdated or expired decision time, an invalid or forged policy, unsafe keys and
scope expansion produce an immutable
`standing-admission-quarantine` report. They never write accepted review
artifacts. A successful standing admission is `compile_eligible: true` but
always `promote_eligible: false`: it authorizes evidence capture only and cannot
fetch a source, compile a snapshot, promote an index, execute a task or mutate a
cluster.

To derive a deterministic file-occurrence delta from two already reviewed,
complete snapshots:

```sh
GOCACHE=/tmp/knowledge-snapshot-gocache \
  go run . change-pack \
  --old-manifest /srv/knowledge-old/manifests/sha256/aa/<old-digest>.json \
  --old-store /srv/knowledge-old \
  --old-allowed-signers /etc/archeion/trust/old-source-reviewers \
  --new-manifest /srv/knowledge-new/manifests/sha256/bb/<new-digest>.json \
  --new-store /srv/knowledge-new \
  --new-allowed-signers /etc/archeion/trust/new-source-reviewers \
  --store /tmp/knowledge-change-packs
```

`change-pack` independently re-verifies both canonical manifest identities,
their exact proposal/spec/receipt/signature/trust-policy CAS objects, both
detached Ed25519 signatures, source-spec/manifest correspondence, and every
referenced raw-object digest and size. It requires one stable
component/channel/language/rights lineage, different immutable revisions, and
strictly later fetched, observed and signed-review times for the new snapshot.
That ordering basis proves a later reviewed observation; it deliberately does
not guess semantic-version order from arbitrary version strings.

The old and new allowed-signers files are independent operator trust roots,
not paths selected by either input manifest. Each must exactly match the
content-addressed policy retained by that signed admission while remaining
outside both untrusted snapshot stores and on a different inode from the CAS
copy. Separate roots allow an explicit reviewer-key rotation. A manifest cannot
make a self-generated key trusted merely by storing its own policy beside its
signature.

The output lists every relative-path occurrence in lexical order as `added`,
`removed`, `changed` or `unchanged`, binds both complete review-admission
records, and is stored at
`change-packs/sha256/<first-two>/<full-hex-digest>.json`. It is
`state: complete`, `authority_state: derived_non_authoritative`, and
`promote_eligible: false`. No raw object is copied. Same/reversed/ambiguous
lineage, an unreviewed or forged admission, a tampered raw/review/manifest
object, unsafe path or symlink, and nondeterministic ordering all fail before a
change pack is written.

`draft` is an exact alias for `inventory`. The result contains the
content-derived proposal ID and immutable proposal path plus included/excluded
file and byte counts. `source_spec_draft` is data for a separate review and
acceptance workflow; feeding it to `compile` is never automatic.

Compilation requires a separate, signed admission. The canonical review
receipt binds the content-derived proposal ID and payload SHA-256 plus the exact
canonical source-spec SHA-256, reviewer identity, `accepted` decision and
canonical UTC review time. Its detached Ed25519 SSHSIG must use namespace
`archeion-knowledge-source-review-v1`, and the reviewer must be explicitly named
by the supplied simple Ed25519 `allowed_signers` policy. The compiler neither
creates nor accepts a receipt on behalf of a reviewer. Missing, rejected,
mismatched, non-canonical, oversized, symlinked or incorrectly signed review
input is quarantined before raw, review or manifest objects are admitted.

`mirror_path` in the spec is resolved strictly below `--mirror-base`. The
command prints a small JSON result containing the content-derived manifest ID
and local manifest path. Exit status `1` means the attempt was quarantined;
stderr gives its immutable quarantine-report path.

Every run is bounded before staging or raw-object commit. The safe defaults are
100,000 files, 2 GiB per file and 64 GiB total. Override them explicitly with
`--max-files`, `--max-file-bytes` and `--max-total-bytes`; library callers use
the corresponding `CompileConfig` fields. Zero selects the safe default and
negative values are rejected. A non-empty store root is mandatory at the
library boundary. Inventory metadata is independently capped at 1 MiB and must
remain one stable, non-symlink regular file for the complete read; directories,
devices and other special files are rejected before opening.

Schema metadata is bounded independently of those content limits before any
mirror enumeration or canonical re-encoding. Stable IDs are at most 512 bytes,
relative paths and canonical URIs at most 4 KiB, media types at most 256 bytes,
and rights, attribution, exclusion reasons, permission maps, review identities
and signer-policy collections have explicit field and entry caps. Source specs
are capped at 32 MiB, inventory proposals at 40 MiB, and the complete retained
review bundle at 64 MiB. Snapshot manifests and change packs are each capped at
64 MiB, matching the downstream evidence-reader limit. Their encoded sizes are
projected incrementally before repeated file metadata is materialized; the
finished canonical document is checked again before its immutable commit.

## Source specification

The strict JSON contract requires:

- stable snapshot, source, component, component-version and channel IDs;
- an absolute HTTPS canonical authority URI;
- an immutable resolved version and tag, digest or other immutable source
  revision (branches and `main`, `stable`, `latest`, `HEAD`, and similar mutable
  names are rejected);
- one of the registry's 16 reviewed channel classes;
- a license expression, rights basis, attribution and every use-specific rights
  state from the public-source policy;
- explicit public access, classification and security domain for this v1
  SHA-256 store;
- explicit language plus canonical RFC3339 UTC fetched and observed times;
- official or primary, non-generated, non-recursive provenance; and
- an explicit verified-exclusion array; and
- the complete included file inventory with canonical relative path, media
  type, lowercase SHA-256 and byte size.

Inventory metadata contains the same source metadata but omits `files`. The
command walks the mirror in lexical order, accepts regular files only, assigns
media types from a fixed extension table, and streams every file through
SHA-256. Unknown extensions deterministically use
`application/octet-stream`; host MIME databases are never consulted.

Mixed local/upstream trees must be declared rather than silently ignored. Each
inventory exclusion rule has a canonical `relative_path`, `path_kind` (`file`
or `tree`), non-authoritative `source_kind`, and reason. Tree rules are expanded
to individual files. The proposal records every excluded path with its media
type, digest, size, source kind, and reason. A reviewed source spec must contain
that exact ledger; the compiler quarantines missing, changed, undeclared, or
new files. Exclusions count toward every resource limit and are never written to
the raw object store.

Exact-tag Argo mirrors generated by `docs/fetch-docs.sh` contain
`.source-receipt.json`. That file is generated, non-authoritative acquisition
metadata—not an upstream source file—and every inventory metadata candidate
must explicitly exclude it with `source_kind: generated` and a reviewed reason.
The receipt itself binds the fetched upstream tree's canonical relative-path,
digest and size inventory hash, file count and byte size. Repository-local
`AGENTS.md` files and `releases/` trees require their own independent exclusions;
none of these paths may be silently dropped.

Permission values are `true`, `false`, `private_only`, `review_required`, or
`unknown`. Retrieval must be explicitly `true`. The required names are
`retrieval`, `quote`, `eval`, `skill`, `training`, `export`, `redistribution`,
`commercial`, and `media`. Missing data never defaults to allowed.

The Argo CD `v3.4.5` fixture in `testdata/` follows the reviewed
`cmp:github:argoproj/argo-cd`,
`ver:github:argoproj/argo-cd@v3.4.5`, and
`chn:argocd:docs:sync-waves` registry identities. Two fixture paths contain
identical bytes to prove physical blob reuse without collapsing their logical
file/source lineage.

The inventory fixture separately demonstrates the exact release commit
`564b94973b284b8de98da7cee6eeade2cb941e46` and broad
`chn:argocd:source` channel required for a whole documentation/CRD source tree.

## Safety and immutability gates

Before committing a manifest, the compiler:

1. strictly decodes and validates the source spec;
2. enforces scalar, map and collection limits before file-level processing;
3. verifies the canonical proposal, accepted review receipt, detached Ed25519
   SSHSIG and explicit reviewer policy, and requires the spec bytes to equal the
   reviewed proposal draft exactly;
4. enforces the projected manifest-output limit before walking the mirror or
   materializing repeated manifest records;
5. rejects absolute/escaping/non-canonical paths, symlinked path components,
   symlink entries and special files;
6. rejects overlap between the input mirror and generated object store;
7. enforces file-count, per-file and total-byte limits on both the reviewed
   inventory and actual mirror before any blob is committed;
8. requires the actual mirror tree to equal the reviewed inventory exactly;
9. streams every regular file through SHA-256 and verifies size while detecting
   replacement or mutation during the read;
10. stages missing objects until the complete input has validated;
11. verifies an existing object before reuse; and
12. commits review evidence, objects, manifests and quarantine reports with
   synced temporary files plus atomic hard-link creation. One `os.Root` handle
   anchors every staging and final write to the originally validated store
   directory identity; symlinked store roots or `.staging`, `raw`, `review`,
   `manifests`, `quarantine`, inventory and change-pack parents fail closed.
   Root identity and parent components are revalidated immediately around each
   publish operation. Existing immutable paths may only be reused when their
   bytes match exactly.

Raw objects use:

```text
raw/sha256/<first-two>/<full-hex-digest>
```

The exact proposal, source spec, receipt, detached signature and trust policy
are retained independently under
`review/sha256/<first-two>/<full-hex-digest>`. Their digests, sizes and object
paths are embedded in `review_admission`, so downstream verifiers do not have
to trust the compiler's verdict alone. A successful manifest is
`authority_state: reviewed`; that does not itself promote or index the source.

Manifests use the same fan-out under `manifests/sha256/`. Each manifest file
entry retains relative path, media type, digest, size, raw object identity and
snapshot/source/component/version/channel lineage. Duplicate bytes reuse one
raw object while retaining every file occurrence.

The manifest ID is SHA-256 over the canonical compact manifest payload excluding
the self-referential `manifest_id` and `manifest_payload_sha256` fields. Stored
JSON is deterministic and byte-identical for identical source-spec bytes and
mirror bytes, including first run versus object-reuse reruns.

Any missing/unexpected file, changed digest/size, invalid metadata, corrupt CAS
object, or commit failure produces an immutable `state: quarantined` report and
no new complete manifest. A previously valid immutable manifest is preserved;
the failed attempt cannot replace or relabel it.

This v1 compiler deliberately accepts only public content because ordinary
SHA-256 object identities reveal equality. Internal/private/restricted content
requires the contract's domain-keyed opaque identity and isolation before this
gate can be broadened.

## Verification

```sh
GOCACHE=/tmp/knowledge-snapshot-gocache gofmt -w *.go
GOCACHE=/tmp/knowledge-snapshot-gocache go test ./...
GOCACHE=/tmp/knowledge-snapshot-gocache go vet ./...
GOCACHE=/tmp/knowledge-snapshot-gocache go build ./...
```

The suite covers the exact-version Argo mirror, deterministic accepted review,
forged/missing/rejected/mismatched review evidence, bounded and non-symlink
review input, unsafe immutable-path collisions, duplicate blob reuse, mutation
after a valid run, incomplete trees, missing rights, symlinks, path escape,
generated/recursive-source rejection and deterministic reruns across fresh and
reused stores. Output-store coverage includes root/parent swaps and zero-write
rejection for every symlinked staging, raw, review, manifest, quarantine,
inventory and change-pack child. Change-pack coverage includes independently reverified signed
inputs, all four occurrence states, deterministic fresh/reused stores, no raw
copying, ambiguous/reversed lineage, unreviewed manifests, forged review
evidence, tampered raw objects, path escape and symlinked input. Inventory
coverage additionally includes explicit empty
metadata, the 1 MiB metadata bound, symlink/special metadata files, all three
resource limits, proposal-only state, deterministic fresh
and reused stores, exclusion kind/path validation, excluded symlinks, mixed
provenance ledgers, and compiler rejection after an excluded file changes or an
undeclared file appears.

Standing-admission coverage includes deterministic repeat signatures, direct
compatibility with the existing compiler, policy provenance retention,
publisher/channel/transport/rights/version/key/limit/effective-time drift,
forged policy signatures, unsafe or in-store private keys, quarantine-only
failure output and a byte scan proving the private key never enters the output
store.
