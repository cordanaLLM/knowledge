# Knowledge source registry

This directory builds deterministic, bounded, observation-only candidates that
describe component identity, exact version evidence, every discovered use,
dependency closure, official source-channel state, and typed gaps. It covers
Git, Helm, OCI, Kubernetes/runtime, SBOM, Go, Node, Python, Terraform, Packer,
and package-manager evidence present in the repository or in an explicit
read-only live capture.

It has zero authority. It cannot acquire or admit source material, publish a
retrieval release, sign a candidate, mutate a current/previous pointer, or
change a cluster. Every output is forced to `candidate`, `unreviewed`, and
ineligible for compilation or promotion.

## Prerequisites

The Draft 2020-12 validator and its complete transitive closure are reviewed
and pinned. Install that exact closure before using repository discovery,
reviewed-record import, merge, or validation:

```bash
python3 -m pip install --requirement \
  tools/knowledge-registry/requirements-reviewed.txt
```

Do not substitute an ambient `jsonschema` version. The registry asserts
`jsonschema==4.26.0`, compiles both registry schemas, and applies deterministic
date, date-time, URI, and URI-reference format checks at runtime.

## Commands

Run from the repository root:

```bash
registry=tools/knowledge-registry/knowledge_registry.py
observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 "$registry" capabilities
python3 "$registry" discover-repo . \
  --observed-at "$observed_at" \
  --output /tmp/repository-candidate.json
python3 "$registry" validate /tmp/repository-candidate.json
python3 "$registry" summarize /tmp/repository-candidate.json
python3 "$registry" coverage /tmp/repository-candidate.json
python3 "$registry" gaps /tmp/repository-candidate.json
```

Outputs are created exclusively and are never overwritten. Use a fresh path
for every command. `--require-complete` makes an intentionally gapped candidate
fail, but never changes its authority.

For a chained repository observation, bind the validated predecessor and use a
strictly newer current observation time:

```bash
python3 "$registry" discover-repo . \
  --previous /tmp/repository-candidate.json \
  --observed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output /tmp/repository-candidate-next.json
```

The registry keeps `observation.observed_at` separate from
`observation.source_valid_at`. For Git discovery, source validity is the exact
HEAD committer time; it is not substituted for capture time. Repeat captures
may use one precommitted current `observed_at` to prove byte determinism. A
predecessor-bound capture rejects an equal or older time.

## Input contract

Repository discovery requires a non-symlink Git checkout with an exact HEAD
and no tracked index or worktree changes. Its denominator is the complete
stage-zero tracked-file inventory. Untracked files do not silently enter it.
Tracked symlinks, gitlinks, unresolved stages, duplicate paths, truncated Git
output, repository changes during scanning, oversized files/inventories, and
untrusted or replaced Git executables fail closed. `.workingdir2` is excluded
unless `--include-workingdir` is set; when included, it remains reference-only
evidence.

JSON imports reject duplicate keys, non-finite numbers, integers outside the
signed 64-bit range, invalid Unicode, excessive nesting, excessive node counts,
oversized documents, and symlink or replacement races. The shared vectors in
`testdata/canonical-json/v1/` exercise those invariants across the registry,
retrieval, Task Evidence Librarian, and storage-canary implementations. Merge
order cannot change canonical output. Conflicting immutable record IDs and
conflicting OCI tag-to-digest observations remain validation failures or typed
gaps.

Every generated candidate is validated against
`knowledge/registry/schemas/discovery-manifest.schema.json` as well as the
canonical ID, graph, bound, and authority invariants. Merge first validates
each input, rejects same-ID conflicts, and records the complete input lineage.
The current observation is selected by the fixed
`latest-observed-at-then-manifest-id-v1` policy; its predecessor is retained as
`base_manifest_id`/`merge_lineage.previous_manifest_id` rather than inferred
from input order.

OCI identity includes an explicit normalized `os/architecture[/variant]`
platform. Dockerfile, runtime Node/Pod, and CycloneDX evidence can establish
it; invalid, missing, or conflicting platform evidence remains an
`oci-platform-invalid`, `oci-platform-unresolved`, or `oci-platform-multi` gap
instead of collapsing distinct artifacts.

Every component that requires official channels carries an explicit state for
all 16 channel classes: docs, reference, API, schema, config, release,
changelog, migration, deprecation, advisory, source, license, package,
artifact, SBOM, and provenance. Allowed availability states are `available`,
`absent`, `ambiguous`, `unresolved`, and `unavailable`. Missing review is
materialized as non-authoritative `unresolved`; it is never omitted.

Lockfile, SBOM, runtime, mutable-reference, exact-version, image-digest,
lineage, official-channel, input-readability, and truncation failures are
retained as typed gaps. OCI observations without an authoritative lockfile or
SBOM receive `transitive-inventory-unavailable` rather than silently claiming
closure.

## Read-only live capture

`capture_live.py` invokes one root-owned, non-writable, non-symlink `kubectl`
whose exact bytes are checked before and after capture. It binds an explicit
private kubeconfig and rejects external credential/key files, executable
credential plugins, duplicate JSON keys, and unsupported YAML constructs. The
original kubeconfig is recorded by path, SHA-256, size, device, and inode, but
is never handed to `kubectl`: capture executes against an anonymous sealed
memfd snapshot. The receipt records that snapshot's policy, SHA-256, and size,
and its seals and contents are rechecked after capture. The helper only uses
`kubectl version`, `kubectl config current-context`, `kubectl get`, and
`kubectl get --raw`. It writes a fresh local directory containing bounded JSON
artifacts and a hash-bound capture manifest. It never invokes apply, create,
delete, edit, exec, patch, replace, rollout, scale, or port-forward.

The projection is identity-only. It omits environment values and sources,
commands, arguments, Secret/ConfigMap data, and sensitive-looking fields. It
retains only bounded workload, image, package, repository, version, digest,
platform, and schema identity needed by the importer. URI and locator checks
reject credentials, sensitive query values, malformed or recursively encoded
escapes, and unsafe image authorities before an artifact can be persisted.
OpenAPI documents retain only bounded group/version/kind identity.

```bash
capture_dir=.workingdir2/cache/knowledge-registry/live-$(date -u +%Y%m%dT%H%M%SZ)
observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
capture_result="$(python3 tools/knowledge-registry/capture_live.py \
  --output-dir "$capture_dir" \
  --kubectl /usr/bin/kubectl \
  --kubeconfig "$HOME/.kube/config" \
  --git-commit "$(git rev-parse HEAD)" \
  --observed-at "$observed_at")"

capture_manifest="$(
  python3 -c 'import json, sys; print(json.load(sys.stdin)["capture_manifest"])' \
    <<<"$capture_result"
)"
mapfile -t live_inputs < <(
  python3 -c \
    'import json, sys; print("\n".join(json.load(sys.stdin)["inputs"]))' \
    <<<"$capture_result"
)

python3 "$registry" import-live \
  --capture-manifest "$capture_manifest" \
  "${live_inputs[@]}" \
  --output /tmp/live-candidate.json
```

The capture result is the authoritative list of positional import inputs.
`capture-manifest.json` is the receipt supplied only through
`--capture-manifest`; never pass it as a positional input and never use
`"$capture_dir"/*.json`. As a shell-only fallback, enumerate regular JSON
files with `find ... ! -name capture-manifest.json` before invoking the
importer.

Import resolves every live occurrence locator plus every version and gap
evidence fragment against its hash-bound projected input and fails closed on
the first mismatch. Evidence of an absent field binds the existing parent
object that proves the absence; it never invents a pointer to the missing key.

A Kubernetes List that advertises continuation or remaining items is a
blocking `live-inventory-truncated` gap. Missing/unavailable surfaces remain
explicit. SBOM package-to-package relationships are retained as transitive
dependency edges.

Capture contract v4 pages the `workload-sboms` surface by namespace. The
cluster-wide `sbomreports` collection exceeds `artifact_bytes` (64 MiB) on its
own, so the surface queries `/api/v1/namespaces` as its paging root and then
one `/apis/aquasecurity.github.io/v1alpha1/namespaces/<namespace>/sbomreports`
page per advertised namespace, ordered by namespace name. Each page is an
independently hash-bound artifact under the unchanged 64 MiB bound, and every
page is a complete untruncated List, so `live-inventory-truncated` still
applies unchanged. Completeness is proved on import the same way API discovery
is: the captured page endpoints must equal the namespaces the receipt-bound
paging root advertises, and each page may only carry reports from its own
namespace. A missing, extra, or misfiled page is a blocking
`live-surface-content-mismatch`. Receipts sealed under contract v3 keep
validating against the v3 bounds and the v3 single-artifact surface shape.

Reviewed channel records can be normalized and candidates can be combined:

```bash
python3 "$registry" import-reviewed reviewed-records/ \
  --output /tmp/reviewed-candidate.json
python3 "$registry" merge \
  /tmp/repository-candidate.json \
  /tmp/live-candidate.json \
  /tmp/reviewed-candidate.json \
  --output /tmp/merged-candidate.json
```

Importing reviewed records does not make the resulting envelope authoritative;
review/admission is a separate future control plane. Reviewed records may carry
optional `registry_kind`/`registry_identity` component fields
(`component-record-v1.1.schema.json`, both-or-neither) that the importer uses
verbatim for the stable component identity, so a derived record closes the
exact harvested component instead of minting a new one. The frozen
`component-record.schema.json` stays byte-pinned by the sealed P1-SRC-02
acceptance and acquisition contracts.

Merge recomputes the re-derivable gap classes (`official-channel-unresolved`,
`exact-version-unresolved`, `mutable-ref`, and the other manifest-derived
types) from merged state instead of carrying stale copies; import-time-only
gap types (`official-channel-state`, `reviewed-record-invalid`, live-capture
classes) keep carrying unchanged. `official-channel-state` is emitted at
component grain — one row per component that still has at least one channel
class short of reviewed-and-available, never one row per slot. The row counts
the shortfall (`unresolved_channel_classes`, `unresolved_by_state`,
`unresolved_channel_types`); the per-slot `availability_state`, `review_state`,
`canonical_uri`, `evidence` and nested `gap.reason` / `gap.next_action` stay
verbatim on `components[].official_channels`, and the exact unresolved slot set
is re-derived from there by `unresolved_reviewed_channels()` — the same
predicate the emitter uses. Slot grain put 162,497 rows carrying 158.8 MB of
duplicated channel evidence into the w7 manifest and is what stopped the
complete envelope from serializing. Purl-less SBOM file-path artifacts
(`kind == ecosystem` in `application`/`library`) are reclassified
`official_channel_required: false` at emission and at materialization
(decision D-R2-2b) and leave the channel denominator.

Ratified per-ecosystem channel policies
(`knowledge/registry/channel-policies/`, schema
`channel-policy.schema.json`) expand deterministically and offline into
reviewed component records, and every wave is gated mechanically:

```bash
python3 "$registry" derive-channels /tmp/merged-candidate.json \
  --policies knowledge/registry/channel-policies \
  --output /tmp/wave
python3 "$registry" merge /tmp/merged-candidate.json /tmp/wave/records/*.json \
  --output /tmp/wave-merged.json
python3 "$registry" wave-gate /tmp/merged-candidate.json /tmp/wave-merged.json \
  --policies knowledge/registry/channel-policies
```

`derive-channels` refuses unratified or invalid policies, emits nothing for a
component whose preconditions fail (the plain gap survives), keeps
non-derivable channel types `unresolved` with typed gaps, stamps every record
with the policy freeze-pin (`<path>@sha256:<hash>`), and emits a deterministic
k=20 sample audit per policy seeded from the policy hash. Research-corpus
policies (schema 1.1.0, `scope.selector: component-table`) carry the
validated corpus as a per-component `rows` table instead of ecosystem
`channels`: rows are matched by `component_id` only after no ecosystem
policy matched, every `available` row must embed its 2xx/3xx probe receipt
(the loader refuses unprobed availability), and each emitted channel binds
the `tables.provenance` sha256 pins (corpus, gates, engines, agy record)
plus `probe:<status>:<final-url>` as evidence. `wave-gate` asserts
merged validity, zero new/removed components, required-slot movement exactly
equal to the reclassified population, accepted-slot arithmetic
(16 x policy-stamped components), gap arithmetic, the
available-implies-accepted invariant, and policy-hash bindings; it exits
non-zero on any failure.

The R3 snapshot train closes the `snapshots` axis with the same derive →
import-reviewed → merge pipeline. `derive-channels --snapshot-receipts <dir>`
consumes separately captured fetch receipts (`<dir>/receipts/*.jsonl`, schema
`channel-snapshot-receipt.schema.json`, artifacts under
`<dir>/cas/sha256/<hex[:2]>/<hex>`) and populates each matching record's
`versions`/`snapshots` arrays: one version copied field-exact from the baseline
(so `stable_id("ver", …)` dedupes onto the existing id — zero version growth)
plus one `channelSnapshot` per receipt. Binding fails closed per channel: a
receipt that does not re-hash against its CAS artifact, names an unknown
channel, disagrees on `canonical_uri`, conflicts with another receipt, or
belongs to a component whose baseline version the reviewed schema cannot
express emits nothing for that channel and is reported in the summary's
`snapshot_binding.channels_unbound`. `snapshot-gate` is the snapshot-wave
analogue of `wave-gate` (whose accepted-slot arithmetic hard-fails any
snapshot-only merge by design): it asserts merged validity, zero new/removed
components AND versions, unchanged required/accepted slots,
`immutable_verified_channels` movement exactly equal to the verified receipts
(with typed `unbindable` explanations), full CAS re-verification, snapshots
referencing only accepted-available channels, and no silently dropped receipt.

```bash
python3 "$registry" derive-channels /tmp/merged-candidate.json \
  --policies knowledge/registry/channel-policies \
  --snapshot-receipts .workingdir2/cache/knowledge-registry/snapshots \
  --output /tmp/wave
python3 "$registry" merge /tmp/merged-candidate.json /tmp/wave/records/*.json \
  --output /tmp/wave-merged.json
python3 "$registry" snapshot-gate /tmp/head-census.json /tmp/wave-merged.json \
  --receipts .workingdir2/cache/knowledge-registry/snapshots
```

Receipts come from runners, never from the tool (the capability boundary
forbids fetching). `snapshot_receipts_offline.py` synthesizes the two
zero-network populations: live-export `schema` channels are re-hashed from the
on-disk live capture inputs (`canonical_uri` already carries the exact
content-addressed sha256), and `git-self` `source` channels bind the raw
commit object bytes of a local ref (`git cat-file commit`, `upstream_ref` =
commit sha). The WAN/LAN fetch runner is
`tools/knowledge-registry/snapshot_channels.py` (workstation-run; designed in
`.workingdir2/cache/knowledge-registry/r3-snapshot-design-20260822.md` §E): it
selects the accepted-available channels still missing snapshots from a census
head, dedupes by `canonical_uri` with the channel fan-out kept per receipt
row, and fetches with per-host token buckets (default 2 req/s jittered,
`--rate HOST=RPS` overrides), bounded retries honouring `Retry-After`, a
per-host circuit breaker, a pinned honest User-Agent, and a response-size
bound (default 64 MiB; npm oversize falls back once to the abbreviated
packument, typed in `coordinates`). Bodies are content-addressed into
`cas/sha256/` and re-verified before the receipt row is appended; failures
(HTTP errors, oversize, unreachable `s3://` without workstation credentials,
circuit-open remainders) are typed in-band `fetch-failed` rows, never silence.
Resume skips URIs already carrying a satisfying receipt and rewrites prior
failure rows out when a retry succeeds, keeping one receipt row per URI.

```bash
/usr/bin/python3.14 tools/knowledge-registry/snapshot_channels.py \
  --baseline /tmp/head-census.json \
  --policy oci-internal --policy s3-model \
  --docker-config-auth registry.example.com \
  --output .workingdir2/cache/knowledge-registry/snapshots
```

## R4 identity wave and ratified deviations

`bind-identity` reuses the same receipt surface for the deliberate
self-repository population: it selects the CAS-verified
`application/x-git-commit` receipts, re-derives the Git object id from the
stored commit bytes (a forged `upstream_ref` fails closed), maps each receipt
channel to its component, and emits a candidate fragment that reproduces the
baseline six-tuple of every deliberate self-repository version exactly — zero
new components, zero new version ids — with the capture-time commit attached
as `versions[].metadata.gitops_source_observation`. A version carrying that
receipt-bound observation stops emitting `exact-version-unresolved` and emits
the non-blocking `gitops-self-reference-observed` instead of
`gitops-self-reference`; the deliberate self-tracking fact stays in
`component.metadata.self_repository` and in the observation. Any tampered
field (ref, commit grammar, resolver, content hash, observation time) restores
both blocking gaps, and a self-reference without a bound observation keeps
emitting `gitops-self-reference` unchanged.

```bash
python3 "$registry" bind-identity /tmp/merged-candidate.json \
  --receipts .workingdir2/cache/knowledge-registry/snapshots \
  --observed-ref main \
  --output /tmp/identity-fragment.json
python3 "$registry" merge /tmp/merged-candidate.json /tmp/wave/records/*.json \
  /tmp/identity-fragment.json \
  --accepted-deviations knowledge/registry/accepted-deviations \
  --output /tmp/identity-merged.json
python3 "$registry" identity-gate /tmp/control.json /tmp/identity-merged.json \
  --receipts .workingdir2/cache/knowledge-registry/snapshots \
  --deviations knowledge/registry/accepted-deviations \
  --anchor /tmp/frozen-baseline.json \
  --expected-plan /tmp/expected-plan.json
```

Ratified accepted deviations (`knowledge/registry/accepted-deviations/`,
schema `accepted-deviation.schema.json`) subtract a deliberate gap class from
one axis' blocking set while every row stays visible in `gaps[]`. A deviation
binds one `scope.gap_type` on one `scope.axis` and applies only where all
`scope.preconditions` match the gap row and its component, so the evidence
that makes a row deliberate is what authorizes the exemption. `merge
--accepted-deviations` re-reads and freeze-pins the directory and stamps
`gaps[].metadata.accepted_deviation` (declaration id, path, sha256, citation,
ratification, expiry); `completeness.<axis>.accepted_deviation_ids` and
`.accepted_deviations` expose exactly which rows were exempted by which
declaration. Nothing is exempted without a ratified `review.status: accepted`
record, without an `observation.observed_at` to date the expiry against, or
when a precondition fails — the row simply keeps blocking, and a merge that
omits the flag re-blocks it.

`bind-oci-identity` is the OCI sibling of the same contract. The fetch runner
`tools/knowledge-registry/resolve_oci_artifacts.py` reuses the
`snapshot_channels.py` stack (token buckets, CAS, JSONL receipts, typed in-band
failures, resume) and adds only registry mechanics: the `WWW-Authenticate`
Bearer dance per `(realm, service, scope)`, a two-phase manifest-then-config
fetch, and an `Authorization` header that is dropped on a cross-host blob
redirect. `bind-oci-identity --plan-only` prints the same deduped plan the
gate re-derives: every version carrying `oci-platform-unresolved` or
`exact-version-unresolved` on an `ecosystem: oci` component, addressed by its
digest when it has one and by its tag otherwise, with the repository taken from
`component.metadata.oci_repository` or the purl `repository_url` qualifier, and
the registry canonicalised (bare first segment and `index.docker.io` collapse
to `docker.io`, whose API host is `registry-1.docker.io`).

An **index digest gets no platform**: the index version stays platform-less and
typed `oci-platform-index`, naming the per-platform children the receipt
enumerated. Stamping N platforms onto one artifact identity would emit
`oci-platform-multi`, which is deliberately outside `MERGE_REDERIVED_GAP_TYPES`
and inside the identity axis, so one emission survives every later merge and
permanently blocks the axis. A single manifest resolves through its config blob
to exactly one platform and is typed `oci-platform-observed`. Either way the
version keeps its resolution state and its six-tuple, so the binding mints zero
components and zero version ids and merges additively through
`versions[].metadata` — the reviewed-record corpus keeps reproducing the same
ids and does not need regenerating.

`normalize_oci_platform` is purely syntactic, so `unknown/unknown` passes it.
Attestation filtering is therefore mandatory, not hygiene: every index entry
annotated `vnd.docker.reference.type: attestation-manifest` or carrying an
`unknown` platform segment is dropped into `coordinates.oci.excluded[]` before
a platform can be derived, `exact_oci_platform` rejects an unknown segment
anywhere a platform is read back, and the gate fails on any version or
observation that asserts one. Every receipt re-derives from its stored bytes
alone — the CAS body must hash to the claimed manifest digest (and to the
requested digest when the ref was digest-addressed), the config blob must hash
to the digest the manifest names, and the children, platforms and exclusions
must recompute exactly — so a doctored `coordinates` block is refused rather
than bound. Typed fetch failures (`manifest-unknown`, `registry-auth-required`,
`digest-mismatch`) bind nothing and leave the blocking gap in place.

```bash
/usr/bin/python3.14 tools/knowledge-registry/resolve_oci_artifacts.py \
  --baseline /tmp/control.json \
  --docker-config-auth registry.example.com --docker-config-auth ghcr.io \
  --rate docker.io=0.030 \
  --output .workingdir2/cache/knowledge-registry/snapshots
python3 "$registry" bind-oci-identity /tmp/control.json \
  --receipts .workingdir2/cache/knowledge-registry/snapshots \
  --output /tmp/oci-identity-fragment.json
```

Docker Hub anonymous pulls are capped at a measured `ratelimit-limit:
100;w=3600` per `docker-ratelimit-source` address, decremented by every
manifest GET including 404s while config blob GETs are free, so `docker.io`
defaults to 0.025 req/s and the wave is resumable across the window.

**The `oci-platform-unresolved` class is closed and its residue is permanent.**
Measured against the `build-20260823T1140Z-r4w5` treatment's 741 rows: 720 hold
a CAS-verified receipt in `snapshots/` (593 index, 127 single manifest) and 21
do not, and those 21 are not a fetch backlog. Two are Kyverno
`disallow-latest-tag-cel` fixture images carrying neither tag nor digest, so
`oci_artifact_reference` returns `None` and there is nothing to address. One names
a registry host with no DNS record, a mistyped name of the internal
registry. The other 18 are `manifest-unknown`: seven
documentation and test placeholders under `example/` that were never published,
and eleven upstream tags and digests garbage-collected since they were
recorded. Every one was re-probed with `skopeo` on 2026-08-25 with credentials
for `ghcr.io` and the internal registry supplied, and all 18 were still gone;
the artifact is
`.workingdir2/cache/knowledge-registry/build-20260825T203545Z-w7/`. Re-running
the wave closes nothing. Clearing the residue is a ratification decision — an
`accepted_deviation` on `scope.axis: identity`, `gap_type:
oci-platform-unresolved` — not a fetch.

Every cluster node is `amd64/linux`, but that does not make an index's
`linux/amd64` child the version's identity. A digest-pinned index pins the
index; the child that runs is a runtime resolution, not what the reference
names. `oci-platform-index` already records the enumerated children and sits in
`OBSERVED_IDENTITY_GAP_TYPES`, so it blocks neither axis, and stamping the
index's platform set onto the version would emit the permanently-blocking
`oci-platform-multi` instead.

A component's transitive inventory is available exactly when the manifest holds
an imported CycloneDX SBOM whose **subject** is that component's own resolved
digest and whose subject version carries at least one `contains` edge resolved
by `cyclonedx-sbom`. That reads the imported SBOM itself rather than the
occurrence lifecycle, which `reconcile_live_sboms` overwrites to
`runtime-resolved`/`orphaned` on every complete live capture; the freshness of
those roots stays measured by `live-sbom-missing` and
`live-sbom-stale-or-orphaned`, which are not closure blockers. An SBOM that
enumerates nothing, or a subject version with no digest, keeps the gap.

`identity-gate` certifies one identity transition against a same-generation
**control** (the identical derive and merge without the wave's identity
inputs): merged validity, control anchored to the frozen generation, zero new
or removed components, a version-id delta equal to what the wave declared in
`--expected-plan`, no reviewed record injecting a version id the current
generation does not mint (the stale-record trap that leaves a re-derive gapped
without failing validation), `oci-platform-multi` zero before and after, no
`unknown/unknown` platform in any version field or observation, every closed
identity gap explained by a CAS-verified receipt (Git commit object or registry
manifest) or a ratified deviation, every gap type new to the treatment absent
from the identity axis set, every verified receipt consumed and every planned
registry ref carrying a satisfying or typed-failure receipt, every closed
closure gap independently re-derived from the treatment's own SBOM subjects,
channel and snapshot axes identical in control and treatment, and every
exemption independently re-derived from the on-disk ratified declaration.

## P1-SRC-03 exact-file acquisition

The sibling Go module under `p1-src03-acquisition-runner/` is a separate v2
contract for only the six Cilium `v1.19.5`, Go `go1.26.5`, and Kubernetes
`v1.36.2` files frozen by the accepted multi-domain retrieval denominator. It
does not modify or route through the P1-SRC-02 Argo subtree runner.

It resolves the three exact Git tag/commit/root-tree identities and every
contract-bound intermediate tree edge for each exact file path through
non-recursive Git-object API calls, then verifies the bound Git blob SHA-1,
byte size, reconstructed Git identity, and raw SHA-256 before writing a private
CAS object. The contract, receipt, proposal, and execution manifest share the
registry's compact UTF-8 canonicalization vectors and strict JSON limits.

The expected execution manifest binds all runner sources, schemas, canonical
vectors, module metadata, independent verifier, exact Go launcher, and the
complete local GOROOT byte tree. Its gate stays externally unverified and
predecessor-ineligible in emitted documents. Receipt-only interruption is
recoverable without network access; proposal-only, malformed, conflicting, or
ambiguous state fails before publication synchronization. The only outputs are
a deterministic v2 acquisition receipt and inventory proposal. They are always
unreviewed and non-authoritative; snapshot/evidence adaptation and source
admission are later separate rollback units. See
[`p1-src03-acquisition-runner/README.md`](p1-src03-acquisition-runner/README.md)
for the exact contract and verification commands.

## Exact-source acquisition planning

`materialize_argo_record_set.py` deterministically projects only the chart and
runtime facts proved by the exact retained P1-SRC-01 candidate, capture result,
and capture manifest. Its draft is an input boundary, not the committed
authority state. `materialize_argo_source_resolution.py` then replaces that
draft with a separately content-addressed, still-proposed source-resolution
set. Both tools perform no network request and cannot review, acquire, admit,
sign, publish, or mutate anything.

The resolution set records the exact argo-helm tag, commit and chart subtree;
release-package and provenance SHA-256; chart `appVersion`; exact upstream tag
and commit; Argo publisher, governance, membership and license locators; and
immutable-versus-mutable channel strategies. Argo CD maps to `argocd`; Argo
Rollouts maps to `argo-rollouts` and `kubectl-argo-rollouts`; Argo Workflows
maps to `workflow-controller`, `argoexec` and `argocli`. Each mapping preserves
the complete exact candidate component/version/occurrence denominator. Argo
Events remains an explicit typed absence. The Argo CD `redis-ha` Chart.lock
edge is retained with separate unresolved third-party rights; the Argo Apache
license is never inherited across that edge.

Record-set format v2 normalizes the complete 5,045-leaf evidence ledger into
77 sorted, content-addressed atoms plus one compact tuple per canonical record
leaf. Candidate and capture atoms bind the exact input-artifact digest and a
source pointer; primary atoms bind exact source URIs; derived/control atoms
carry no source pointer. The set binds leaf enumeration, tuple count, leaf
order, per-record logical bindings and the complete reconstructed ledger with
separate hashes, requires every atom to be used and rejects out-of-range or
kind-incompatible tuples. The planner reconstructs and validates all 5,045
logical bindings before review status can affect target selection. This reduces
the generated set from 2,842,600 to 235,543 bytes (91.7%) without weakening the
logical evidence denominator or the planner's 8 MiB input bound.

Official documentation and schema channels use immutable upstream commit
routes. Rollouts documentation resolves at the exact upstream `docs` tree and
its schema evidence at `manifests/crds`. Workflows documentation resolves at
the exact commit, API evidence at `api/openapi-spec/swagger.json`, and schema
evidence at `manifests/base/crds`, with distinct full and minimal variant
locators and no selected variant. File locators use GitHub `blob` routes and
directory locators use `tree` routes; mutable ReadTheDocs aliases are not
treated as immutable evidence.

Research facts do not become self-approved facts. Every source channel remains
`unresolved`/`proposed`, every chart record has an independent-review gap, and
all six runtimes retain separate unresolved OCI-manifest and
digest-to-source/SBOM/cosign/SLSA gaps. Package and provenance artifacts are only
catalogued with `not-fetched`/unverified state. The set therefore contains
three records, zero accepted records and thirteen blocking set-level gaps.

```bash
python3 tools/knowledge-registry/materialize_argo_source_resolution.py materialize \
  --candidate .workingdir2/cache/knowledge-registry/live-c6852c5d-candidate.json \
  --capture-result .workingdir2/cache/knowledge-registry/capture-result-c6852c5d-20260717T120233Z.json \
  --capture-manifest .workingdir2/cache/knowledge-registry/live-c6852c5d-20260717T120233Z/capture-manifest.json \
  --output-dir .workingdir2/cache/knowledge-source-acquisition/argo-source-resolution
```

The record-set generator binding covers this materializer, its bounded base
materializer, both schemas, exact validator requirements and the installed
validator dependency closure. A review may create a new accepted record-set
identity only after independently reproducing every primary-source fact and
resolving all blocking gaps. Never edit generated records without regenerating
the complete manifest and repeating independent review.

Before the source-resolution materializer executes the bounded base
materializer, it walks from the filesystem root to the source with a held
`O_NOFOLLOW`/`O_DIRECTORY` descriptor for every ancestor, opens the leaf with
`O_NOFOLLOW`/`O_NONBLOCK`, rejects empty, non-regular and oversized inputs, and
rechecks the complete descriptor/path chain. It compiles only the captured
bytes. Ancestor symlinks, FIFOs, leaf replacement, parent replacement and
ancestor replacement fail closed before untrusted bytes can execute.

`acquire_sources.py` requires exact equality between
`knowledge/registry/records/` and the content-addressed record-set manifest.
It uses the same schema, semantic, identity, and URI-safety preflight as
`import-reviewed`. Every plan binds the exact validator source, component
schema, record-set schema, reviewed-validator requirements, and installed
five-package validator closure. Those bytes, the record set, records, and
planner source are captured through no-follow descriptors and rechecked after
validation. Python bytecode caches are never used to load the shared validator.

The planner separates *denominator acceptance* from *per-target authorization*.
A reviewed, `accepted` record set is an accepted denominator even when some
records remain proposed and unrelated Events/runtime/OCI lanes keep blocking
set-level gaps; those gaps never revoke an otherwise ready chart target (partial
explicit coverage). A selected chart target is authorized only when the
denominator is accepted, its own record is accepted and `selected`, its version
is exactly resolved, `versions[0].build_metadata.source_resolution.review_state`
is `accepted`, and no blocking record gap names the selected component, version,
source channel, a dependency originating from that version, or a snapshot bound
to the version/channel. Blocking gaps for unrelated runtime/OCI/dependency
subjects remain visible in the record but do not revoke the chart-source target.

One source channel must be accepted, available, public, `exact-commit`, and
reviewed evidence. Authorization uses exact structured equality, not a text
prefix: publisher is `Argo Project (argoproj)`, refresh policy is `immutable
locator; re-resolve only through a new reviewed record`, rights are the complete
Argo-authored Apache-2.0 statement, and `source_resolution.chart.license` must
contain only `spdx=Apache-2.0` plus the exact commit-bound `LICENSE` blob URI.
Strings such as `immutable-looking but mutable` or `Apache-2.0 except acquisition
is forbidden` fail closed.

Acquisition-plan contract v2 (`schema_version=2.0.0`, record-schema binding
`1.0.0`) is emitted by generator contract v4. Each target exposes its complete
`target_identity` preimage. Target identity is normalized to the tuple
`{repository, requested_tag, expected_commit, content_roots[]}`:
`version.source_ref` is an exact 40-hex commit that must equal
`source_resolution.chart.commit`, `requested_tag` is the profile-derived
`source_resolution.chart.tag`, `content_roots` is the profile-bound
`source_resolution.chart.subtree`, and both `source_resolution.chart.subtree_uri`
and the source channel `canonical_uri` must be the exact
`https://github.com/<repo>/tree/<commit>/<subtree>` tree URI. Any review/gap,
commit/tag/subtree/channel/publisher/rights/refresh/license divergence, a missing
`source_resolution.chart`, a non-commit `source_ref`, an unsupported profile, a
mutable or unresolved version, or a non-selected disposition fails closed as a
typed target gap.
Standalone controller source records have no reviewed exact-source shape yet, so
they stay fail-closed with a `controller_acquisition_deferred` gap. For v2 sets
the planner additionally derives the exact candidate/capture identity prefixes
from `input_artifacts`, validates atom identities, kind and URI semantics, tuple
shape, leaf order and all ledger hashes, and reconstructs the logical bindings.
Source-admission upstream tags and commits must be primary-source-bound, while
canonical runtime IDs must be derived rather than presented as upstream facts.

Plan v3 is a separate path; the v2/generator-v4 contract remains available for
the proposed repo-shaped denominator. V3 consumes the accepted successor through
`accepted-record-artifact-bundle.schema.json` and
`materialize_record_artifact_bundle.py`. That resolver never copies overlay
records into `knowledge/registry/records/`: it maps every logical set path to
exactly one typed `repository` or `bundle` locator and rechecks the outcome,
successor set, record identity, review state, schema, size, SHA-256, physical
aliasing, directory equality, and canonical manifest bytes through held
no-follow descriptors.

V3 has no implicit "all ready" mode. The caller must explicitly select one or
both accepted component IDs, `cmp:helm:argoproj/argo-rollouts` and
`cmp:helm:argoproj/argo-workflows`; empty, duplicate, missing, proposed, or
blocked selections fail before a plan exists. The strict
`source-acquisition-plan.schema.json` excludes all legacy
`docs/fetch-docs.sh` fields. Every target instead names the fixed
`github-git-objects-rest-v1` capability contract: API origin
`https://api.github.com`, API version `2026-03-10`, Git object format SHA-1,
and modes `040000`, `100644`, and `100755`. Its capability-contract digest is
bound in the plan. This finite interface is consumed by the separate Go runner
under `source-acquisition-runner/`; neither the capability digest nor the plan
is authorization to contact GitHub.

The validator also enforces cross-field meaning rather than accepting a merely
schema-valid, readdressed document: counts equal target cardinality, selection
equals target components, each component maps to its one reviewed logical path
and content root, target identities rehash exactly, and output verification
rederives the complete plan from the currently resolved bundle bytes. A target
uses `record_logical_path` only as the stable set coordinate and separately
binds its typed `bundle` artifact descriptor and artifact-bundle identity. The
schema requires `execution_authorized`, `network_access`, `cache_mutation`, and
`inventory_emission` to remain false.

```bash
python3 tools/knowledge-registry/acquire_sources.py plan \
  --records knowledge/registry/records \
  --record-set knowledge/registry/record-sets/argo-p1-src-02.json \
  --output .workingdir2/cache/knowledge-source-acquisition/plan.json
```

```bash
python3 tools/knowledge-registry/acquire_sources.py plan-v3 \
  --artifact-bundle knowledge/registry/acceptance/p1-src-02/accepted-record-artifact-bundle.json \
  --component-id cmp:helm:argoproj/argo-rollouts \
  --component-id cmp:helm:argoproj/argo-workflows \
  --output .workingdir2/cache/knowledge-source-acquisition/plan-v3.json
```

The legacy v2 command against
`knowledge/registry/record-sets/argo-p1-src-02.json` still yields zero targets
and zero ready items, with explicit `reviewed_record_set_not_accepted` and
empty-denominator gaps; `--require-complete` exits non-zero. That result describes
only the proposed v2/generator-v4 input. It does not describe v3: the explicit
accepted-bundle invocation above deterministically yields the two selected
Rollouts and Workflows targets and plan identity
`source-acquisition-plan:sha256:7b06d690d2edfe08e1fd05060116b3ca08a2a8f82763976f4d4fe1232c844aad`.
Both planning paths remain offline. The CLI exposes only `plan` and `plan-v3`;
there is no callable fetch, cache, inventory, proposal, or subprocess surface
here. Optional files are confined to `.workingdir2/` and committed through held
directory descriptors with no-follow, no-replace semantics; an exact
byte-identical replay is a no-op and any difference is a conflict. Failed or
partially written outputs are retained for review and never removed
automatically. Plans always
remain `non_authoritative`, `compile_eligible=false`, and
`promote_eligible=false`; v3 additionally fixes `execution_authorized`,
`network_access`, `cache_mutation`, and `inventory_emission` to false. The
planner has no review, signature, admission, pointer, retrieval-release, Git,
Kubernetes, Argo, or production-mutation authority.

The bounded first-party Go runner now implements only the exact two-target plan
replay. It resolves lightweight or annotated refs with bounded dereference,
verifies the accepted commit and subtree chain, walks every tree through
non-recursive Git-object calls, rejects truncation and pagination signals,
recomputes Git blob SHA-1 plus raw SHA-256/bytes, and publishes into a
crash-safe raw-SHA-256 scratch CAS. Completed receipts and inventory proposals
are content-addressed, byte-replayable, `unreviewed`,
`compile_eligible=false`, and `promote_eligible=false`; there is no pointer.
The CLI fixes the production origin and requires the exact plan ID again at the
execution boundary. That acknowledgement prevents mistakes but grants no
network or authority approval. This implementation unit used only local
`httptest` transports; a real exact acquisition remains a separate reviewed
operation. See `source-acquisition-runner/README.md` for its frozen bounds,
schemas, output layout, and rollback.

Before the source-resolution writer opens or creates an output directory, it
compares that directory with every captured candidate, capture result,
capture manifest, materializer module, schema and requirements path. Equality
and either ancestor/descendant direction fail closed, so an output can never
replace or contain an exact retained input, nor be placed beneath one.

## Offline review and acceptance

`materialize_source_acceptance.py` is the review/acceptance control plane the
acquisition planner has always assumed. It consumes the exact *proposed*
reviewed-record set, one independent review manifest per record, and a
hash-bound standing acceptance policy, then deterministically decides which
routine exact-official-source records may become *accepted* successors. It
performs no network, subprocess, Git, signing, admission, retrieval, release,
pointer, Argo, or Kubernetes action, and it never mutates the proposed set or
its records: every output is a fresh content-addressed successor written below
`.workingdir2/` through the same held-descriptor, no-follow, no-replace commit
as the adjacent tools.

Three versioned schemas back it: `source-acceptance-policy.schema.json` (the
hash-bound standing policy), `independent-review-manifest.schema.json` (the
per-record independent review), and `source-acceptance-outcome.schema.json`
(the always-emitted content-addressed outcome, receipt, and typed exception
queue). The accepted successor set is emitted in the existing
`reviewed-record-set.schema.json` shape so the planner can consume it
unchanged.

A record is accepted only when every gate passes: the policy is content-bound
to the exact set payload, generator source, component/record-set schema, and
validator requirement hashes and is inside its freshness window; exactly one
independent review manifest is bound to the exact record and set, decides
`accept`, and comes from an authorized reviewer who is neither the proposer nor
excluded and stays within the reuse cap; the review is neither out of order nor
stale; the reproduced primary-source hashes equal the record's own chart
package, provenance, and commit; the record is a resolved, selected,
still-proposed exact-commit chart whose one source channel is the exact
immutable `github.com/<repo>/tree/<commit>/<subtree>` locator with the exact
publisher, rights statement, and SPDX licence; the target's own blocking review
gap is resolved by both policy and reviewer; and every retained blocking gap is
an explicitly authorized unrelated residual lane. Ambiguous rights, conflicts,
high-risk subjects, reviewer reuse, stale policy or evidence, missing or
duplicate or out-of-order reviews, path swaps, record tampering, evidence
tampering, and any partial acceptance outside explicit policy fail closed into
the typed exception queue for later UI/human resolution; a compromised
denominator emits no successor at all.

Acceptance never invents a source fact. Transitions are restricted to review
disposition, channel availability, and the immutable-locator handling class,
each verified against its exact prior value and the policy's authorized
constants; ancillary channels that were not independently accepted are marked
non-authoritative `needs-review`; and the resulting record is re-validated
against the component schema and the registry's accepted-record semantics
before it can be emitted. Selected-version third-party dependency rights (for
example Argo CD's bundled `redis-ha`) always fail closed and can never be
waived by routine policy.

```bash
python3 tools/knowledge-registry/materialize_source_acceptance.py materialize \
  --record-set knowledge/registry/record-sets/argo-p1-src-02.json \
  --records knowledge/registry/records \
  --policy knowledge/registry/acceptance/p1-src-02/policy.json \
  --reviews-dir knowledge/registry/acceptance/p1-src-02/reviews \
  --output-dir .workingdir2/cache/knowledge-source-acceptance/outcome
```

The independently reproduced bundle in
`knowledge/registry/acceptance/p1-src-02/` explicitly authorizes Argo Events
absence and the runtime OCI/digest-source gaps only as preserved residual set
lanes. It accepts the exact Workflows and Rollouts chart records, emits
successor set `reviewed-record-set:sha256:a2a00248b70e028385f9ff9d20109a0d221952350ce5cc919913acde46a75ad2`,
and retains all thirteen set gaps. Argo CD has no review in this rollback unit;
its record stays proposed and its `redis-ha` dependency-rights gap fails closed.
The default `knowledge/registry/records/` and `record-sets/` inputs remain the
untouched proposed predecessor, so the ordinary planner still exposes zero
ready targets until a separate promotion changes that pointer/overlay.

Every review must contain exactly one package, provenance and commit
reproduction with both locator and hash equal to the proposed record. Missing,
duplicate or relocated evidence fails as `evidence_tamper`; an explicitly
authorized residual set code preserves a blocker but never resolves it.

The outcome is always `authoritative=false`, `admits_retrieval=false`,
`mutates_pointers=false`, `signs_production=false`, `compile_eligible=false`,
and `promote_eligible=false`. `--require-complete` still exits non-zero for this
intentional partial acceptance because Argo CD remains unresolved. Promotion
(copying accepted records into
`knowledge/registry/records/` and pointing the planner at the successor set) is
a separate human step the tool deliberately does not take.

The generator binding covers this materializer, its bounded base materializer,
the component, record-set, policy, review-manifest, and outcome schemas, the
exact validator requirements, and the installed five-package validator closure.

## Bounds and validation

The canonical candidate records its enforced bounds. Current maxima include
20,000 tracked files, 10,000 discovery files, 8 MiB per discovery input,
128 MiB across repository discovery, 512 MiB per JSON input, 128 levels of
JSON nesting, ten million JSON nodes, and 512 MiB serialized output. Record
collections also have fixed upper bounds. Live capture contract v3 uses one
compiled bound set shared by capture and import: 64 MiB per projected artifact,
512 MiB per capture, 250,000 List items, 4,096 dynamic queries, 8,211 total
commands, and 3,600 seconds. A receipt must declare those exact values; changing
metadata cannot relax or silently narrow the executed limits.

Run the focused gate:

```bash
black --check \
  tools/knowledge-registry/knowledge_registry.py \
  tools/knowledge-registry/capture_live.py \
  tools/knowledge-registry/snapshot_receipts_offline.py \
  tools/knowledge-registry/acquire_sources.py \
  tools/knowledge-registry/materialize_argo_record_set.py \
  tools/knowledge-registry/materialize_argo_source_resolution.py \
  tools/knowledge-registry/materialize_source_acceptance.py \
  tools/knowledge-registry/tests/test_knowledge_registry.py \
  tools/knowledge-registry/tests/test_acquire_sources.py \
  tools/knowledge-registry/tests/test_materialize_argo_record_set.py \
  tools/knowledge-registry/tests/test_materialize_argo_source_resolution.py \
  tools/knowledge-registry/tests/test_materialize_source_acceptance.py
python3 -m pip install --requirement \
  tools/knowledge-registry/requirements-reviewed.txt
python3 -m unittest discover -s tools/knowledge-registry/tests -v
python3 -m json.tool \
  knowledge/registry/schemas/discovery-manifest.schema.json >/dev/null
python3 -m json.tool \
  knowledge/registry/schemas/component-record.schema.json >/dev/null
python3 -m json.tool \
  knowledge/registry/schemas/channel-snapshot-receipt.schema.json >/dev/null
python3 -m json.tool \
  knowledge/registry/schemas/reviewed-record-set.schema.json >/dev/null
python3 -m json.tool \
  knowledge/registry/schemas/source-acceptance-policy.schema.json >/dev/null
python3 -m json.tool \
  knowledge/registry/schemas/independent-review-manifest.schema.json >/dev/null
python3 -m json.tool \
  knowledge/registry/schemas/source-acceptance-outcome.schema.json >/dev/null
```

The tests exercise deterministic captures, explicit temporal separation,
duplicate IDs and JSON keys, mutable identities, incomplete lock/SBOM
inventories, symlink/TOCTOU and executable substitution, truncated live Lists,
fixed bounds, channel-state coverage, and order-independent merging.

## Rollback

The implementation has no deployed or live state. Rollback is the Git revert
of this directory, its schemas, records, record-set manifest, scoped workflow,
and the `tools/` index entry. The acceptance materializer, its three schemas,
and its tests revert with the same directory; the exact rollback boundary is
the Git revert of those files plus the README, `tools/AGENTS.md`, and `STATE.md`
entries. Because the acceptance tool never mutates the proposed set, records, or
any pointer, and only writes disposable `.workingdir2/cache` outcomes, reverting
it leaves the committed proposal and the planner exactly as they were. Local
`.workingdir2/cache` replays are disposable; the exact retained P1-SRC-01
evidence named by the committed record set remains required for reproducibility.
Deleting scratch output cannot change cluster or release state.
