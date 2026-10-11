# Knowledge evidence compiler

The tracked Go module is `github.com/cordanaLLM/knowledge/tools/knowledge-evidence`. The independent wire
identity emitted in evidence manifests is `knowledge-evidence@1.2.0`; changing
that compiler identity requires a reviewed semantic-contract change rather
than an incidental module or build-path edit.

`knowledge-evidence` is the offline P0.3 boundary between an immutable raw
`knowledge-snapshot` and later retrieval/index construction. It verifies one
complete snapshot manifest and every referenced SHA-256 raw object, then emits
faithful UTF-8 evidence spans with exact raw coordinates and immutable lineage.
The output safety boundary requires Go 1.26's `os.Root` APIs.

It does **not** fetch anything, call a model, contact Kubernetes, build or
promote an index, decide authority, summarize prose, or rewrite source text. A
complete evidence manifest is therefore a verified normalization artifact, not
a serving-generation pointer.

All source bodies are wrapped by the deterministic
`untrusted-evidence-envelope@1.0.0` policy. It marks content as
`untrusted_source_data`, forbids treating source text as instructions, forbids
execution and tool use, and permits interpretation only as evidence. The
content-derived envelope ID is bound into the evidence manifest, every file
occurrence and every span. Prompt-like text remains inert, byte-faithful source
data.

## Usage

```sh
GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-evidence-gocache \
  go run . compile \
  --manifest /snapshot-store/manifests/sha256/ab/abcdef....json \
  --raw-store /snapshot-store \
  --spec /snapshot-store/review/sha256/aa/aaaaaaaa.... \
  --proposal /snapshot-store/review/sha256/bb/bbbbbbbb.... \
  --review-receipt /snapshot-store/review/sha256/cc/cccccccc.... \
  --review-signature /snapshot-store/review/sha256/dd/dddddddd.... \
  --allowed-signers /operator-trust/knowledge-source-review.allowed_signers \
  --store /tmp/evidence-store
```

The command prints only the content-derived evidence-manifest ID, path, file
count and span count. Exit status `1` means the input was rejected and stderr
contains the path of its immutable typed quarantine report. Exit status `2`
means command/configuration use failed.

Safe defaults bound a run to 100,000 files, 64 MiB per file, 512 MiB total raw
bytes, 1,000,000 spans and 512 MiB logical output bytes. They can be lowered or
explicitly raised with `--max-files`, `--max-file-bytes`,
`--max-total-bytes`, `--max-spans` and `--max-output-bytes`. Zero selects the
safe default; negative values are invalid.

Review verification has fixed, non-configurable role bounds: 32 MiB for the
standalone source specification, 40 MiB for the inventory proposal, 64 KiB for
the receipt, 16 KiB for the detached signature and 1 MiB for each trust-policy
copy. All simultaneously read review artifacts, including both policy copies,
must also fit one 64 MiB aggregate budget.

## Accepted input

The compiler strictly accepts only the current `knowledge-snapshot` v1 contract:

- `schema_version: 1.0.0`, `manifest_kind: knowledge_snapshot` and
  `state: complete`;
- `authority_state: reviewed` plus a content-bound accepted source-spec review
  admission. The admission binds the snapshot source-spec digest to an
  immutable inventory-proposal ID/payload, explicit reviewer and review time,
  detached Ed25519 SSHSIG identity, the
  `archeion-knowledge-source-review-v1` namespace and allowed-signers policy;
- both legacy one-off review receipts and standing-policy receipts. Standing
  admission is accepted only when the receipt and manifest both bind the exact
  `standing_policy` method, content-derived `source-admission-policy:` ID and
  lowercase policy SHA-256; omission remains valid only when all three fields
  are absent;
- the exact canonical proposal, standalone spec, receipt, detached signature
  and review-CAS policy copy. The compiler independently re-hashes and strictly
  decodes them, recomputes proposal identities, checks deterministic draft
  extraction, compares every snapshot source/file/exclusion field to the signed
  spec, inspects the Ed25519 SSHSIG envelope and runs offline `ssh-keygen -Y
  verify` over the exact receipt bytes;
- an operator-configured `--allowed-signers` trust root outside the snapshot
  store. Its exact bytes and digest must equal the review-CAS policy copy; the
  manifest is never allowed to select its own trust root;
- a self-consistent `snapshot-manifest:sha256:...` identity calculated over the
  canonical compact manifest core;
- an internally consistent tree digest, counts, byte totals and source/file
  lineage;
- official or primary, explicitly public input;
- source profile `github-official-commit@1.0.0`: `cmp:github:*`, a full
  lowercase 40-hex commit as `source_revision`, and a canonical GitHub
  `tree`/`blob`/`commit` URI that contains that exact commit. Other source
  profiles fail with a typed `source_profile_unsupported` quarantine until a
  separate immutable-ID policy is implemented;
- the exact `raw/sha256/<first-two>/<hex>` object layout; and
- a complete, lexically ordered inventory whose raw objects all re-hash to the
  declared size and SHA-256.

Unknown JSON fields, incomplete/tampered manifests, generated source kinds,
path escape, raw/output-store overlap, symlinked path components, symlink
objects, special/missing/corrupt objects and mutation while reading are
fail-closed. The compiler never walks an arbitrary source tree: its entire
input surface is the verified manifest plus the objects that manifest names.
If the evidence-store root is unsafe or overlaps the raw store, compilation
returns without writing even a quarantine report through that rejected path.
Every staging, normalized, manifest and quarantine write is anchored to a Go
`os.Root` directory handle. Parent components and the selected store identity
are revalidated immediately around immutable commits, so a replaced root or
child symlink cannot redirect CAS writes outside the selected store.
Legacy or structurally complete snapshots without accepted reviewed authority
are quarantined before any raw object read or normalization staging. An
unreviewed `source_spec_draft` cannot become normalization authority merely
because its hashes and file inventory are internally consistent.
Likewise, a forged self-consistent snapshot cannot reuse a legitimate review
bundle with a substituted tree, and an attacker-signed bundle cannot bring its
own `allowed_signers` file.

## Exact-coordinate profiles

Every accepted payload must be valid UTF-8 and contain no NUL byte.

- `text/markdown` and `text/x-markdown` use
  `markdown-atx-fence-scanner@1.1.0` with profile
  `faithful-utf8-markdown-sections-bounded@1.0.0`. ATX headings outside backtick or
  tilde fenced code delimit sections. Each section retains its heading
  breadcrumb, exact half-open raw byte range `[start,end)` and inclusive
  one-based raw line range. A pre-heading preamble is a separate span.
- JSON, YAML and plain text use `exact-coordinate-line-window@1.0.0` with
  profile `faithful-utf8-bounded-spans@1.0.0`. The compiler does not claim a
  semantic JSON or YAML parse.

Every parser span is then partitioned into exact, non-overlapping payloads of
at most 16 KiB. Splits prefer the last newline inside the window and otherwise
use a valid UTF-8 boundary, so very long source lines remain lossless. This
prevents a CRD or generated asset from becoming an unbounded transformer input
while retaining complete byte and line-coordinate coverage. The byte bound is
an evidence-shape contract, not a universal tokenizer-budget proof; embedding
runtimes must additionally enforce their pinned model's batch/token envelope.

CRLF and all original UTF-8 bytes are retained. The normalized payload for a
span is exactly the corresponding raw byte slice, so its coordinate binding is
directly testable. Unsupported media, invalid UTF-8 and binary-looking input
produce explicit immutable quarantine issues; nothing is silently skipped.

## Output and lineage

Normalized payload objects use:

```text
normalized/sha256/<first-two>/<full-hex-digest>
```

Evidence manifests use the same fan-out under `evidence-manifests/sha256/`.
Manifest, file-occurrence and span IDs are deterministic SHA-256 identities.
Every file occurrence retains snapshot/source/component/version/channel and raw
object lineage; every span retains parser/profile versions and raw coordinates.
Exact duplicate payload bytes share one normalized CAS object, while distinct
file occurrences and span identities remain distinct.

All normalized objects are staged until the entire input validates. Every
staged payload inode is `fsync`ed before its immutable CAS hard link, and the
destination directory is synced after the link. Final objects and manifests
use rooted immutable hard-link commits; an existing path is reusable only if
its bytes match exactly. A failed run cannot relabel or replace an earlier
complete manifest. Orphaned content-addressed objects are harmless if a
filesystem failure occurs between object commits and manifest commit, because
no complete manifest references an incomplete build.

## Verification

```sh
gofmt -w *.go
GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-evidence-gocache go test -count=1 -race ./...
GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-evidence-gocache go vet ./...
GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-evidence-gocache go build -o /tmp/knowledge-evidence ./...
```

The repository retains source, tests and fixtures only. Deterministic binaries
belong in a declared ignored run root or reviewed artifact registry and must
not be committed beside the source.

The test suite covers CRLF and multibyte UTF-8 coordinates, fenced-code heading
exclusion, bounded exact profiles, duplicate-byte CAS reuse with distinct
lineage, corrupt raw objects, manifest tampering, symlinks, path escape,
generated/recursive inputs, every configured resource bound, unsupported and
binary/invalid content, byte-identical fresh/reuse reruns, inert prompt-injection
text, unreviewed drafts, forged manifest/spec substitutions, and attacker-chosen
self-signed trust roots. It also exercises 100,000 exact span coordinates,
million-heading fail-early input, bounded heading labels and breadcrumb reuse,
manifest/output planning below the downstream 64 MiB contract, role-specific
and aggregate review bounds, legacy and standing-policy admission bindings,
receipt/manifest provenance mismatch, output-root replacement and parent
symlinks inserted after the rooted store is opened.
