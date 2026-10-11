# Knowledge retrieval candidate compiler

`knowledge-retrieval` builds the P0.4 candidate and implements the P0.5
fail-closed generation lifecycle. It builds an
immutable deterministic lexical inverted index from one reviewed
`knowledge-snapshot` plus its complete `knowledge-evidence` normalization. The
base output is always:

```text
state=partial, promotable=false, serving_eligible=false,
current_eligible=false, lexical=true, dense=false
```

The tool also has an optional hybrid experiment path. `hybridize` binds that
exact lexical candidate to caller-pinned, externally produced dense vectors;
`hybrid-query` binds an exact literal query to a caller-pinned query vector and
an explicit reranking decision, then executes integer dot-product retrieval and
the immutable default deterministic reciprocal-rank fusion. When the caller selects a nonzero rerank
window, the same artifact must also bind the complete reranker-score input and
deterministic reranking is applied. It does not run or claim an embedding or
reranker model.

The raw lexical and hybrid paths have no serving/current pointer, network
client or Kubernetes client. Hybrid outputs remain `state=partial`,
`quality_state=unevaluated`, `promotable=false`, `serving_eligible=false` and
`current_eligible=false`. The evaluator runs real lexical and hybrid queries
over a frozen held-out suite, recomputes the metrics and gates, and emits an
unsigned receipt for external authorization. P0.5 can separately stage a promotable
generation only after an exact canonical quality report passes every gate and
binds the candidate, current admission policy, evaluation dataset, metrics,
runtime and exact retrieval executable. It then supports detached Ed25519
SSHSIG-authorized candidate-to-current promotion and exact current-to-previous
rollback. Merely building or hybridizing a candidate can never enter that
lifecycle.

SSHSIG verification executes only the root-owned, non-symlink,
non-group/world-writable `/usr/bin/ssh-keygen` through a fixed environment and
controlled working directory. Each verification has one 15-second deadline
and bounded stdout/stderr; caller `PATH`, working directory and environment
cannot select or configure the executable.

## Trust boundary

Build does not reinterpret the source review contract. It requires an exact
operator-pinned `knowledge-evidence` executable and SHA-256, copies those
verified bytes into an isolated `/tmp` workspace, and re-runs `compile` over
the reviewed snapshot, raw CAS, standalone spec, proposal, accepted receipt,
detached SSHSIG and external `allowed_signers` trust root. Indexing continues
only when the independently compiled evidence manifest has the same ID, counts
and byte-for-byte canonical document as the supplied complete manifest.

The retrieval compiler then independently verifies:

- strict canonical evidence, snapshot and policy documents;
- evidence manifest identity and exact snapshot binding;
- public retrieval rights and the inert
  `untrusted-evidence-envelope@1.0.0` contract;
- every raw and normalized CAS object's size and SHA-256;
- exact normalized-to-raw byte slices, line coordinates, ordered partition,
  file occurrence ID, span ID and component/version/channel lineage;
- canonical source and content-derived snapshot URIs, observed/fetched times,
  access scope and freshness on every indexed posting; and
- an explicit content-addressed public ACL/deletion policy whose source is
  present, retrieval is allowed, deletion state is active and tombstone is
  false.

The v1 policy is deliberately public-only. It is an explicit operator/policy
controller input, not source text and not selected by the snapshot. The caller
must also pin its whole canonical document with `--admission-policy-sha256`;
the policy's own content-derived ID is an integrity identity, not
self-authorizing proof. That caller-pinned path and digest are the P0 dogfood
policy-authority boundary. A signed/pinned policy-authority generation and
revocation feed is required before any future serving promotion. The policy
binds the exact snapshot, evidence, source, component and component-version
IDs:

```json
{
  "policy_id": "retrieval-admission:sha256:<digest-of-core>",
  "policy_payload_sha256": "sha256:<digest-of-core>",
  "schema_version": "1.0.0",
  "policy_kind": "public_retrieval_admission",
  "state": "active",
  "snapshot_manifest_id": "snapshot-manifest:sha256:...",
  "evidence_manifest_id": "evidence-manifest:sha256:...",
  "snapshot_id": "...",
  "source_id": "...",
  "component_id": "...",
  "component_version_id": "...",
  "access_scope": "public",
  "retrieval_allowed": true,
  "source_state": "present",
  "deletion_state": "active",
  "tombstone": false,
  "evaluated_at": "2026-07-16T00:00:00Z",
  "fresh_until": "2026-07-17T00:00:00Z"
}
```

Source admission is independent from this retrieval ACL. A legacy explicitly
reviewed snapshot carries all three source-admission fields empty. An
automatically admitted revision must carry exactly
`admission_method=standing_policy`, a lowercase canonical SHA-256, and
`admission_policy_id=source-admission-policy:<that SHA-256>`. The snapshot,
review receipt, lexical candidate, hybrid candidate, frozen suite, quality
report and evaluated generation must retain that exact triple. Orphaned or
partially populated provenance fails closed. This is the normal automation
path: routine upstream docs/releases covered by a signed standing policy do not
need one human approval each; only a policy change, an out-of-policy revision or
an exception does.

`policy_payload_sha256` is SHA-256 over compact Go/JSON encoding of the fields
from `schema_version` through `fresh_until`; `policy_id` prefixes that digest
with `retrieval-admission:`. Do not hand-calculate the self-referential envelope.
Give `materialize-admission-policy` a strict canonical `AdmissionPolicyCore`
document; it derives the identity and writes the immutable CAS object:

```sh
knowledge-retrieval materialize-admission-policy \
  --core /operator-policy/public-admission-core.json \
  --store "$RETRIEVAL_STORE"
```

Policy decisions still belong to the ACL/deletion authority. Materialization
only makes an already decided core deterministic. A changed or tombstoned
policy denies a query immediately; it is never hidden by an older candidate.

Query callers must independently pin the whole candidate document with
`--candidate-sha256`. The digest is checked against the stable bytes before
canonical JSON parsing, so a tampered file or a different self-consistent
candidate placed at the configured path fails closed before index resolution.

## Build

```sh
VERIFIER=/tmp/knowledge-evidence
VERIFIER_SHA="sha256:$(sha256sum "$VERIFIER" | cut -d' ' -f1)"
POLICY=/operator-policy/public-admission.json
POLICY_SHA="sha256:$(sha256sum "$POLICY" | cut -d' ' -f1)"

GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-retrieval-gocache \
  go run . build \
  --snapshot-manifest /snapshot-store/manifests/sha256/aa/...json \
  --evidence-manifest /evidence-store/evidence-manifests/sha256/bb/...json \
  --raw-store /snapshot-store \
  --evidence-store /evidence-store \
  --store /tmp/retrieval-store \
  --spec /snapshot-store/review/sha256/cc/... \
  --proposal /snapshot-store/review/sha256/dd/... \
  --review-receipt /snapshot-store/review/sha256/ee/... \
  --review-signature /snapshot-store/review/sha256/ff/... \
  --allowed-signers /operator-trust/knowledge-source-review.allowed_signers \
  --admission-policy "$POLICY" \
  --admission-policy-sha256 "$POLICY_SHA" \
  --evidence-verifier "$VERIFIER" \
  --evidence-verifier-sha256 "$VERIFIER_SHA" \
  --as-of 2026-07-16T00:00:00Z
```

`--as-of` is mandatory canonical UTC and must equal policy `evaluated_at`; the
compiler never infers time. A verified but expired source produces a typed
`freshness_state=stale` partial candidate, never a promotable one. All inputs
and stores reject symlinks and path overlap. Safe default bounds cover files,
spans, payload bytes, total bytes, terms and postings and may be lowered with
the corresponding flags. The serialized P0 dogfood index has a fixed 512 MiB
ceiling and query refuses anything larger before reading it.

Immutable writes are anchored with Go's traversal-resistant `os.Root`, reject
all store-root and child symlinks, create directory components one at a time,
and revalidate the exact target parent immediately before and after hard-link
commit. Raw, evidence and retrieval stores may not overlap.

Objects are immutable and content addressed:

```text
indexes/sha256/<first-two>/<digest>.json
candidates/sha256/<first-two>/<digest>.json
quarantine/sha256/<first-two>/<digest>.json
```

Fresh and object-reuse runs are byte-identical. A failure may leave no
candidate and never changes a serving/current alias; an orphaned immutable
index is harmless if the final candidate commit fails.

### Versioned BM25F lexical profile

Build defaults to the unchanged
`deterministic_raw_term_frequency@1.0.0` profile. Selecting
`--lexical-profile deterministic_bm25f_fixed_point@1.0.0` creates a new
content-addressed candidate and a successor index; it never rewrites an
existing raw-TF candidate. The separately selectable
`deterministic_bm25f_fixed_point@1.1.0` profile is a content-addressed successor,
not an in-place change to v1.0. Both record exact tokenizer and scorer IDs, body
and heading lengths, field term frequencies, document frequencies and
one-based document positions in postings. The selected profile, tokenizer and
scorer lineage must remain byte-for-byte identical through the lexical and
hybrid candidates, quality report, staged generation and serving pointer.
Partial, unknown or mixed-version lineage fails closed.

The BM25F tokenizer retains Unicode letters and numbers, deterministically
splits camel case, acronym boundaries and letter/digit boundaries, and adds at
most one conservative singular variant per raw token. A raw token is bounded
at 128 UTF-8 bytes, and component expansion is bounded at four components.
Profile v1.0 retains its published tokenizer v1.0 semantics: identifiers beyond
four components fail closed, and queries admit at most 32 distinct base terms
and 128 expanded terms. Profile v1.1 binds tokenizer v1.1: an identifier beyond
the component cap retains its exact normalized base and conservative singular
variant without partial component expansion, and queries admit at most 64 base
terms while retaining the 128-expanded-term ceiling. An overlong token is
discarded atomically rather than indexed as a false truncated prefix; body and
heading lengths count retained base tokens after the selected analyzer rule.
Index term, posting and result bounds remain the same build/query limits as the
legacy profile.

Scoring is integer-only fixed point at scale 1,000,000. Field normalization
uses `b=3/4`; saturation uses `k1=6/5`; IDF is a deterministic fixed-point
natural-log series computed once per matched term. Heading TF is capped at two,
weighted by two and then capped at one-half normalized body unit, so repeated
breadcrumb text cannot swamp body relevance. Every add/multiply and final
accumulator is checked for overflow. Equal scores resolve by `SpanID`. After
the immutable candidate, policy and whole index pass their integrity-validation
load, query expansion uses binary term lookup, scoring visits only matching
postings, and a bounded top-K heap avoids sorting every matching document.
Posting document positions avoid a scoring-time document scan to resolve each
hit. The current one-shot CLI intentionally repeats the integrity pass on every
invocation; a resident broker must retain only a fully validated digest-bound
generation and reload it whenever its generation, policy, path identity or
bytes change.

Both BM25F profile versions intentionally bind the same
`bm25f_k1_6_5_b_3_4_heading_2_cap_half_fixed_ppm@1.0.0` scorer: the score
formula, field statistics, fixed-point arithmetic, overflow checks, tie break
and top-K selection are byte-for-byte unchanged. Only tokenizer/query-bound
semantics differ, and therefore carry distinct profile and tokenizer IDs.

The profile changes lexical scores only. Hybrid fusion remains the separately
versioned fixed `RRF(k=60)` contract; score-aware fusion or reranking requires
another profile. Building or evaluating BM25F cannot promote it. Promotion
still requires an additional frozen, scorer-blind suite and the existing
signed quality lifecycle; observed qrels or thresholds must not be edited to
fit this scorer.

## Bounded dogfood query

```sh
CANDIDATE=/tmp/retrieval-store/candidates/sha256/aa/...json
CANDIDATE_SHA="sha256:$(sha256sum "$CANDIDATE" | cut -d' ' -f1)"

go run . query \
  --candidate "$CANDIDATE" \
  --candidate-sha256 "$CANDIDATE_SHA" \
  --store /tmp/retrieval-store \
  --evidence-store /evidence-store \
  --admission-policy "$POLICY" \
  --admission-policy-sha256 "$POLICY_SHA" \
  --principal-scope public \
  --as-of 2026-07-16T12:00:00Z \
  --query 'sync waves' \
  --limit 10
```

Query applies the tokenizer and integer scorer bound by the candidate's exact
lexical profile and returns at most 100 results with bounded exact UTF-8
excerpts. Every result repeats the full evidence reference and inert trust
envelope. Source text is never parsed as a command, prompt, tool request or
policy. Outer `state` remains `partial`; `result_state` is one of `ok`, `empty`,
`stale`, `forbidden` or `backend_unavailable`. Missing/corrupt index or payload
objects never become `empty`.

The query CLI retains explicit `--as-of` for reproducible offline audits. MCP
editor calls do not expose that override: their freshness reference is always
the broker's current UTC clock.

## Candidate-only dense, fusion and reranking

The hybrid path deliberately separates mechanics from quality. A dense artifact
must be strict canonical JSON, carry a content-derived identity and be pinned by
its whole-document SHA-256. It binds every exact lexical document ID once and
records the exact model ID, revision and artifact SHA-256; tokenizer ID and
artifact SHA-256; embedding profile; document instruction; dimension;
normalization; signed-int16 encoding; and quantization scale. The current
deterministic contract is L2 normalization followed by symmetric int16
quantization at scale 32767. Missing, duplicate, zero, differently dimensioned
or lineage-mismatched vectors fail closed.

The query-signal artifact is separately content-addressed and whole-document
pinned. It binds the exact hybrid candidate, literal-query SHA-256, dense model,
revision, tokenizer, query/document instructions and query vector. It also
binds `reranking_requested`. A false decision must carry an empty score list and
no scorer identity; a true decision must bind the reranker model, revision,
artifact, tokenizer, instructions, profile, fixed-point score scale and exact
document scores. This makes the query planner's conditional choice replayable
without letting this candidate invent a quality classifier. Both external
artifacts say `authority_state=untrusted_candidate_input`: their vectors and
scores may rank already admitted evidence, but can never grant authority, prove
quality or support promotion.

```sh
knowledge-retrieval hybridize \
  --candidate "$CANDIDATE" --candidate-sha256 "$CANDIDATE_SHA" \
  --store "$RETRIEVAL_STORE" \
  --dense-artifact "$DENSE" --dense-artifact-sha256 "$DENSE_SHA"

knowledge-retrieval hybrid-query \
  --hybrid-candidate "$HYBRID" --hybrid-candidate-sha256 "$HYBRID_SHA" \
  --store "$RETRIEVAL_STORE" --evidence-store "$EVIDENCE_STORE" \
  --admission-policy "$POLICY" --admission-policy-sha256 "$POLICY_SHA" \
  --query-artifact "$SIGNALS" --query-artifact-sha256 "$SIGNALS_SHA" \
  --query 'sync waves' --principal-scope public \
  --as-of 2026-07-16T12:00:00Z --fusion-window 100 \
  --rerank-window 50 --limit 10
```

Dense dot products are exact int64 operations over bounded int16 vectors.
Lexical and dense ranks are fused with fixed `RRF(k=60)` integer scores; ties
resolve by exact document ID. `--rerank-window 0` returns the fused order without
scorer metadata or scores. A nonzero rerank window must match
`reranking_requested=true`, and scores must cover the complete selected window
or the query returns `backend_unavailable` with a typed error. The default is
zero: an upstream reviewed query plan must opt into the extra scorer work.
Current ACL, deletion, tombstone, freshness, evidence envelope and payload
integrity checks are re-run before evidence is returned.

### Separately versioned fusion challenger

The default `reciprocal_rank_fusion_k60_int64@1.0.0` profile, wire document and
query behavior remain unchanged. An optional
`bounded_lane_champion_rank_sum_int64@1.0.0` profile is a candidate-only
challenger; it is never selected by an implicit default and this implementation
does not evaluate or promote it.

The challenger is a separately content-addressed `FusionProfile` document.
Its caller-authored core binds the exact scorer ID, revision and artifact
SHA-256; lexical candidate document and tokenizer/scorer lineage; dense
artifact, model, tokenizer, embedding and quantization lineage; fusion and
result windows; zero rerank window; checked-int64 arithmetic scale; positive
fixed lane weights; champion bonus; fail-closed missing-lane policy; and
canonical ascending `SpanID` tie-break. Query execution hashes the running
retrieval binary and requires it to equal the bound scorer artifact.
Materialization derives only its
immutable identity and grants no source, quality or promotion authority:

```sh
knowledge-retrieval materialize-fusion-profile \
  --core /candidate/fusion-profile-core.json --store "$RETRIEVAL_STORE"

knowledge-retrieval hybridize \
  --candidate "$CANDIDATE" --candidate-sha256 "$CANDIDATE_SHA" \
  --store "$RETRIEVAL_STORE" \
  --dense-artifact "$DENSE" --dense-artifact-sha256 "$DENSE_SHA" \
  --fusion-profile "$FUSION_PROFILE" \
  --fusion-profile-sha256 "$FUSION_PROFILE_SHA"

knowledge-retrieval hybrid-query \
  --hybrid-candidate "$HYBRID" --hybrid-candidate-sha256 "$HYBRID_SHA" \
  --store "$RETRIEVAL_STORE" --evidence-store "$EVIDENCE_STORE" \
  --admission-policy "$POLICY" --admission-policy-sha256 "$POLICY_SHA" \
  --query-artifact "$SIGNALS" --query-artifact-sha256 "$SIGNALS_SHA" \
  --fusion-profile "$FUSION_PROFILE" \
  --fusion-profile-sha256 "$FUSION_PROFILE_SHA" \
  --query 'sync waves' --principal-scope public \
  --as-of 2026-07-16T12:00:00Z --fusion-window 100 \
  --rerank-window 0 --limit 10
```

Both profile flags are mandatory at build and query time for the challenger;
partial pins, a profile passed to default RRF, mixed lexical/dense lineage and
window drift fail closed. Each lane contributes bounded descending rank points.
A fixed `2 * fusion_window * arithmetic_scale` bonus makes every lexical and
dense rank-one item outrank every non-champion, while the profile requires at
least two result slots. Missing lexical or dense evidence, checked-arithmetic
overflow or loss of a distinct champion returns a typed unavailable result.
Successful challenger responses expose deterministic per-lane champion
`SpanID`, fused/result rank and retention without changing evidence authority.

## Evaluated generation and signed atomic lifecycle

`evaluate` is the bridge from mechanical candidate construction to measured
quality. It accepts one content-derived frozen suite that binds the exact
lexical candidate, hybrid candidate, admission policy and query-signal
artifacts. It executes every lexical and hybrid query twice, recomputes
fixed-point per-case and per-class Recall@k, MRR and nDCG, and derives all gates
from observed outputs. Callers cannot submit passing booleans. The derived
gates are held-out quality, citation lineage, ACL isolation,
deletion/tombstone handling, freshness/time, prompt-injection inertness,
resource bounds, deterministic replay and rollback compatibility.

The suite requires one lexical and one hybrid threshold for every class and at
least one evidence payload containing the declared inert-injection marker.
`target_mode=fusion_only` requires `rerank_window=0` and remains the smallest
initial cutover profile. `target_mode=reranked` requires a bounded nonzero
window and every case must carry the same complete scorer contract: model,
revision, model artifact, tokenizer, tokenizer artifact, profile, query
instruction, document instruction and fixed-point score scale. Mixed contracts
fail closed. Query-signal paths use the content-derived payload digest in
`query_signal_artifact_id`; their separate `query_signal_document_sha256` pins
the whole wrapper. This matches `knowledge-embeddings query` without an adapter.

Prepare each exact signal with the existing model boundary, then record the
printed ID, whole-document SHA-256, path relative to the embedding store and
byte size in the suite case:

```sh
knowledge-embeddings query \
  --hybrid-candidate "$HYBRID" \
  --hybrid-candidate-sha256 "$HYBRID_SHA" \
  --dense-manifest "$DENSE_MANIFEST" \
  --dense-manifest-sha256 "$DENSE_MANIFEST_SHA" \
  --retrieval-store "$RETRIEVAL_STORE" \
  --store "$EMBEDDING_STORE" \
  --literal-query 'argocd sync wave health' \
  --query-instruction 'Retrieve exact Argo CD operational evidence.' \
  --endpoint-env ARCHEION_EMBEDDINGS_ENDPOINT \
  --token-env ARCHEION_EMBEDDINGS_TOKEN
```

The smallest useful Argo fusion suite is one strict, sorted case class with an
Argo evidence-span judgment, one injection marker that really occurs in the
returned evidence payload, both `hybrid` and `lexical` thresholds, and bounded
resources. Its `RetrievalEvaluationSuiteCore` fixes:

```text
state=frozen
metric_algorithm=macro-recall-mrr-ndcg-fixed-point@1.0.0
metric_scale=1000000
target_mode=fusion_only
cutoff_k=10, limit=10, fusion_window=100, rerank_window=0
rollback_mode=bootstrap                 # or base_generation with exact base
cases[].query_sha256=SHA256(literal query)
cases[].query_signal_path=query-signals/sha256/<payload-prefix>/<payload>.json
```

Cases and judgments are strict ID order; thresholds are strict class/profile
order. The core deliberately omits `suite_id` and `suite_payload_sha256`.
Materialization derives them rather than requiring a self-referential manual
ID:

```sh
knowledge-retrieval materialize-evaluation-suite \
  --core /evaluation/argo-fusion-suite-core.json \
  --store "$RETRIEVAL_STORE"
```

Before an executable suite has exact admitted evidence, candidates and query
signals, `materialize-evaluation-freeze` can seal a scorer-blind multi-domain
seed from content-addressed official source files. The freeze binds source
commits and whole-file hashes, exact line/byte spans and SpanIDs, literal query
hashes, graded judgments, absolute metric floors, latency/resource ceilings and
the complete missing-binding barrier. It writes only immutable evidence
excerpts and the freeze object; it does not call retrieval, embeddings, fusion,
reranking or evaluation:

```sh
knowledge-retrieval materialize-evaluation-freeze \
  --core /evaluation/multidomain-freeze.core.json \
  --source-root /evaluation/pinned-official-sources \
  --store "$RETRIEVAL_STORE"
```

Such a freeze must remain `blocked_exact_bindings` until a separate reviewed
step binds every exact admitted evidence/policy, candidate, scorer/profile and
query-signal identity. Binding cannot alter the frozen questions, judgments,
thresholds or ceilings, and a freeze grants no quality or promotion authority.

For the accepted Kubernetes/Cilium/Go freeze, the next rollback unit is a
requirements-only manifest rather than an executable suite. It replays the
exact frozen source bytes and requires three independent source authorities:
Kubernetes `v1.36.2`, Cilium `v1.19.5` and Go `1.26.5`. Each authority has a
distinct admission-policy scope; shared candidates must retain all three
lineages. The barrier adds exact snapshot-manifest, evidence-manifest and
lexical-index ID/document-hash pairs to the earlier policy, lexical/dense,
hybrid, profile, scorer and per-arm query-signal requirements.

```sh
knowledge-retrieval materialize-binding-requirements \
  --core testdata/scorer-blind-multidomain-v1/binding-requirements.core.json \
  --freeze testdata/scorer-blind-multidomain-v1/materialized/evaluation-freezes/sha256/a0/a0fd2cb1067e0b92122e3478632831e8822b5b34f63fa841d3bf60aa65d2de1b.json \
  --freeze-sha256 sha256:376761716b7b0fb4fec98e36dc8fe4b83838e40bcf4a156e1c8fcb482165bfa4 \
  --source-root testdata/scorer-blind-multidomain-v1 \
  --store /tmp/multidomain-binding-requirements
```

The current exact output is
`retrieval-binding-requirements:sha256:d40db301f2e9f44f978665f2030099513605e95c191a9eb1a2d9a39b45db1021`
(document SHA-256 `8318579a...`) with 38 typed blocking absent-artifact
gaps. It always reports zero verified artifacts and
`execution_authorized=false`. It has no artifact-binding, retrieval,
evaluation, signing, generation or pointer-write surface. A separate reviewed
byte verifier must create any successor; Workflows-specific inputs and an
unaccepted scorer cannot satisfy this authority contract.

`materialize-binding-closure` independently verifies committed artifacts
against those 38 typed gaps and emits a distinct successor with only the
verified ones non-blocking; it never mutates the frozen manifest above.
`--admitted-artifacts` binds the 9 authority-local (snapshot/evidence/
admission) gaps. The optional `--shared-corpus-artifacts` extends that to the
remaining 29: the shared lexical candidate/index, dense artifact, both
baseline/challenger hybrid candidates, the challenger fusion profile, its
bound scorer-artifact SHA-256, and one baseline + one challenger query-signal
artifact per frozen case. Each artifact kind is verified against its own
prerequisites in dependency order (candidate before index, candidate+index
before dense, dense+candidate before the fusion profile and both hybrid
candidates, the verified profile before the challenger hybrid, every
prerequisite before its query signals); a defect anywhere in that chain leaves
only the gaps depending on it blocking. Omitting the flag reproduces the
9-gap-only successor unchanged. Neither input, alone or combined, ever flips
`ready`, `promotable`, `execution_authorized` or any capability to true — gap
closure proves artifact existence and internal consistency, not evaluated
quality; see `knowledge/registry/acceptance/p1-src-03/binding-requirements-closure-README.md`
for the current 38/38-closed successor and its provenance.

Expanded challenger definitions freeze comparisons before every exact runtime
artifact exists. They are separate from executable evaluation suites and grant
no source, evaluation, serving or release authority. The contract binds exact
source commits, signed-current generation/admission-policy objects when they
exist, scorer/model/tokenizer and per-case query-signal requirements,
paired-input invariants, per-profile CPU/RAM/latency/byte ceilings, case
outcomes, citations and authority rules.
`execution_state=blocked_exact_bindings` is mandatory while a lane or scorer is
still missing an immutable hash, while a case lacks its exact base query-signal
artifact, or while a paired challenger lacks its distinct immutable scored
query-signal artifact. Partial bindings fail closed. A definition becomes
`ready` only when every required generation, policy, scorer, model, tokenizer,
serving runtime, base signal and derived challenger signal identity is complete;
that state still grants no evaluation or release authority. The executor must
still resolve and verify the bytes behind every identity before a run.

When a lane has no evaluated generation yet, an expanded definition that
requires `reviewed_signed_current` is a post-pass successor template, not an
input to the bootstrap evaluation. The pre-generation run must use a separate
candidate-bound executable suite and evaluator. Only a complete passing result
may create the signed evaluator receipt, stage the retrieval generation and
authorize a separate signed transition; a successor expanded definition may
then bind that exact generation without changing the frozen source judgments.

Paired fusion definitions use schema `3.0.0`, require one lane and exactly one
legacy baseline plus one versioned challenger, and require identical windows,
limits, excerpts and resource ceilings so the fusion algorithm is the only
comparison variable. Their exact reference suite, generation, both scorer
binaries, challenger `fusion-profile:` identity/document hash and both
query-signal sets must be bound before the expanded definition can become
`ready`. The implicit RRF baseline cannot carry a profile-object binding. This
schema does not execute the bootstrap comparison. A
dedicated paired-fusion suite/runner must instead bind both candidate manifests,
exact SpanID judgments, scorer executables and independent query-signal wrappers
before the first run, and must treat the retrieval generation as a post-pass
output.

The candidate-bound bootstrap contract is schema `1.0.0`. It is lane-neutral
and requires `execution_state=blocked_unaccepted_source_authority`: locally
reviewed/complete headers and an active public admission are necessary byte and
lineage checks, but the current upstream snapshot/evidence acquisition objects
do not yet carry accepted P1 source authority. This suite can therefore reach
preflight only, never execution. One strict suite binds the reviewed snapshot,
normalized evidence, admission policy, lexical/index/dense inputs, both hybrid
candidates, the challenger profile, both scorer executables, raw source blobs,
normalized span payloads and
one distinct candidate-bound query-signal wrapper per arm and case. Source
ranges are mechanically re-extracted from the raw blobs and must be fully
covered by the declared SpanIDs. Cases, sources, spans, mappings, gates and
profiles are strictly ordered; duplicate candidates or signals, unused spans,
weakened gates, partial scorer pins and path/symlink drift fail closed. Resource
ceilings apply independently to each profile so both arms receive the same
limits.

Fairness is structural: after removing only `hybrid_candidate_id`, the two
signal cores must be byte-identical, including the query vector and every
reranker flag, model/tokenizer pin, instruction, scale and document score.
Snapshot core identity is recomputed; snapshot/evidence headers, the inert trust
envelope and the full policy-to-snapshot source/component lineage are checked.
Every read follows a deterministic plan that must fit fixed aggregate object and
byte bounds before the first input is opened. Overflow-safe resource math also
requires each per-profile ceiling to cover its declared documents, results,
excerpt bytes and summed signal bytes.

The live hybrid-query loader and paired preflight call the same complete
lexical/index/dense lineage validator. It binds exact paths, document hashes and
byte sizes; snapshot, evidence, active public admission and source-admission
lineage; evaluated/fresh times; lexical profile/tokenizer/scorer; dense model,
tokenizer, representation and counts; and, for the challenger, the exact fusion
profile. Paired preflight additionally requires
`policy.evaluated_at <= suite.frozen_at <= policy.fresh_until` and binds the
profile's fusion/result/rerank windows to the suite target.

Evidence validation deliberately distinguishes two denominators. The manifest
denominator covers all 219 files and 2,604 spans in the frozen evidence object:
metadata, identities, strict ordering, full byte partitions and aggregates are
recomputed without opening undeclared content. The paired judged denominator is
the selected five raw sources and ten normalized spans: every selected byte is
hash/size checked, each payload must equal its exact raw slice, line coordinates
and SpanIDs are recomputed, and its complete evidence reference must occur once
in the lexical index. The selected denominator must equal the judgments exactly;
unused declarations, unknown or duplicate index SpanIDs, malformed/unsorted
judgments and grade drift fail closed.

Materialization and preflight are deliberately separate:

```sh
knowledge-retrieval materialize-paired-fusion-suite \
  --core /evaluation/paired-fusion-suite.core.json \
  --store "$EVALUATION_INPUT_STORE"

knowledge-retrieval prepare-paired-fusion-run \
  --suite "$PAIRED_SUITE" --suite-sha256 "$PAIRED_SUITE_SHA" \
  --snapshot-store "$SNAPSHOT_STORE" --evidence-store "$EVIDENCE_STORE" \
  --retrieval-store "$RETRIEVAL_STORE" \
  --query-signal-store "$QUERY_SIGNAL_STORE" \
  --baseline-scorer "$BASELINE_SCORER" \
  --baseline-scorer-sha256 "$BASELINE_SCORER_SHA" \
  --challenger-scorer "$CHALLENGER_SCORER" \
  --challenger-scorer-sha256 "$CHALLENGER_SCORER_SHA"
```

Preflight reads and hashes every declared byte before semantic validation. Its
only successful state is `preflight_complete_no_execution` with
`execution_authorized=false`; it has no retrieval, scoring, metric, receipt,
generation, signing, pointer or cluster-mutation path. Evaluation requires a
separately reviewed executor and fresh admitted inputs. A preflight plan is not
evaluation evidence and grants no release authority.

Federated definitions use schema `2.0.0` or `3.0.0`. Every case carries one
strictly lane-ID-ordered `lane_query_signals[]` entry for every declared lane,
including
lanes deliberately made unavailable by a failure-boundary case. Each entry
binds the lane's exact hybrid/dense lineage plus a distinct query-signal payload
ID and whole-document SHA-256. The complete case-by-lane matrix also binds its
immutable source-ledger hash and record count. Missing lanes, duplicate IDs or
document hashes, cross-lane candidate aliases and lineage changes across cases
fail closed. The legacy schema `1.0.0` singular federation shape remains
readable only while every singular signal is null and
`required_before_execution`; it can never transition to `exact` or `ready`.

The reranker model binding includes both the served model artifact hash and a
canonical full-file inventory hash, plus the serving runtime image digest. The
inventory prevents a matching weights file from hiding drift in the graph,
tokenizer or serving metadata; the runtime pin prevents tokenizer or floating
score behavior from drifting under the same model files. The earlier CPU-serving
deployment revision and the later provenance-annotation deployment revision are
separate bindings: the former cannot stand in for the latter.

The canonical fixtures are executable schema regressions:

- `testdata/paired-fusion-suites/argo-workflows-v4.0.7-lane-champion-v1.core.json`
  freezes five Workflows v4.0.7 judgments after mechanically mapping their
  source ranges to ten exact evidence SpanIDs. It binds the legacy RRF candidate
  and the lane-champion challenger, their exact scorer/profile bytes and ten
  distinct candidate-bound signal wrappers. Its materialized identity is
  `paired-fusion-suite:sha256:81fb4b67ed820d96afa15955ebfb850ef2804945115ee932f18f4c917c43b09e`;
  the fixture and a successful no-execution preflight grant no evaluation or
  promotion authority.
- `testdata/evaluation-suites/argo-rollouts-v1.9.0-fusion-suite-v1.core.json`
  freezes the independently scorer-blind Rollouts qrels, adversarial query and
  absolute thresholds as an executable suite. Its materialized identity is
  `retrieval-evaluation-suite:sha256:b6baf3525ac470128e441a91d847fa9908e018f6bfa30aadf35d3b9faac0f6a8`;
  observed evaluation results may not rewrite this fixture in place.
- `testdata/evaluation-definitions/argocd-cpu-reranker-v1.core.json` freezes the
  fusion-only baseline versus the CPU Qwen3 reranker on the same Argo CD
  generation and five exact held-out span judgments. Its five reference-suite
  signals are exact fusion-only base vectors. The scorer, model, tokenizer,
  served-tree and runtime image are exact, but the definition remains
  `blocked_exact_bindings` until the exact deployment produces five distinct,
  content-addressed challenger signals with complete reranker scores. Signal
  generation must wait for an exact reviewed provenance-deployment revision and
  verify its deployed model annotations after the GitOps rollout; an earlier
  CPU deployment or model-tree audit is not a runtime attestation.
- `testdata/evaluation-definitions/argo-workflows-rollouts-federation-v3.core.json`
  preserves the safe per-lane query-input shape and independently binds the two
  reviewed standing admission policies by exact policy ID and whole-document
  SHA-256. It deliberately leaves each generation binding
  `required_before_execution`: staging a `retrieval-generation` requires a
  passed held-out evaluation plus its externally signed evaluator receipt and
  cannot be inferred from the existing dense/hybrid candidates. The fixture
  preserves the same
  commit-bound Workflows/Rollouts render, sync, health, operation and
  failure-boundary cases plus stale, conflict, ACL, deletion, injection,
  unavailable-lane, deterministic and resource gates. It binds all 26 exact
  lane-specific query signals from ledger SHA-256
  `2cc2040a4653ef4cc269179c5eed41b00a991bd4e8d5d4e8ebfd6c58ce93bc9e`.
  Its query inputs, standing admissions and deterministic federation scorer are
  exact; it remains `blocked_exact_bindings` until both externally evaluated
  generation objects exist.
- `testdata/evaluation-definitions/argo-workflows-rollouts-federation-v2.core.json`
  retains immutable definition `25ed2c6c...` as the earlier safe per-lane signal
  binding. Its combined object wrapper cannot express an exact admission policy
  while its generation remains unresolved, so it stays blocked and is
  superseded by v3 without changing its bytes or identity.
- `testdata/evaluation-definitions/argo-workflows-rollouts-federation-v1.core.json`
  retains immutable definition `b99d8a07...` as forever-blocked history. Its
  singular federation signal cannot be populated or promoted under the current
  validator.

Materialization derives an immutable definition identity but neither signs nor
promotes it:

```sh
knowledge-retrieval materialize-evaluation-definition \
  --core testdata/evaluation-definitions/argocd-cpu-reranker-v1.core.json \
  --store "$RETRIEVAL_STORE"
```

Build the release binary first. Because evaluator and query code are linked in
this P0 binary, both exact executable pins must be the bytes of the binary that
is currently running `evaluate`:

```sh
RETRIEVAL_BIN=/immutable/bin/knowledge-retrieval
RETRIEVAL_BIN_SHA="sha256:$(sha256sum "$RETRIEVAL_BIN" | cut -d' ' -f1)"

"$RETRIEVAL_BIN" evaluate \
  --suite "$SUITE" --suite-sha256 "$SUITE_SHA" \
  --lexical-candidate "$CANDIDATE" \
  --lexical-candidate-sha256 "$CANDIDATE_SHA" \
  --hybrid-candidate "$HYBRID" --hybrid-candidate-sha256 "$HYBRID_SHA" \
  --store "$RETRIEVAL_STORE" --evidence-store "$EVIDENCE_STORE" \
  --query-signal-store "$EMBEDDING_STORE" \
  --admission-policy "$POLICY" --admission-policy-sha256 "$POLICY_SHA" \
  --retrieval-executable "$RETRIEVAL_BIN" \
  --retrieval-executable-sha256 "$RETRIEVAL_BIN_SHA" \
  --evaluator-executable "$RETRIEVAL_BIN" \
  --evaluator-executable-sha256 "$RETRIEVAL_BIN_SHA" \
  --evaluator-allowed-signers "$EVALUATOR_ALLOWED_SIGNERS" \
  --evaluator-actor "$EVALUATOR_ACTOR" --evaluator-key-id "$EVALUATOR_KEY_ID"
```

Failed gates still produce immutable metrics, runtime and report objects for
diagnosis, but no receipt. A fully passed run emits an unsigned, immutable
receipt. External authorization signs those exact bytes:

```sh
ssh-keygen -Y sign -f evaluator_ed25519 \
  -n archeion-retrieval-quality-evaluation-v1 "$QUALITY_RECEIPT"
QUALITY_SIGNATURE="$QUALITY_RECEIPT.sig"
```

`stage-generation` is the only bridge from passed evaluation evidence to a
promotable generation. It independently verifies the frozen suite, recomputed
case/aggregate metrics, runtime, quality report, receipt, SSHSIG, external
`allowed_signers`, current policy and both exact executable byte streams. The
generation records their immutable paths and whole-document hashes plus the
complete sorted evidence-span ID set.

The evaluator signature and generation-transition signature are independent
trust boundaries. The evaluator attests to measured quality; the transition
signer authorizes an exact pointer change after that evidence has passed. P0.5
recomputes the metrics before signing and then revalidates their complete
content-derived lineage at staging, status, promotion, rollback and serving.

Reranking is conditional and cannot be overclaimed. A fusion-only report sets
`reranking_evaluated=false` and every reranker binding to `null`; the resulting
generation is eligible only for its evaluated fusion path. A report with
`reranking_evaluated=true` must bind the complete reranker model, revision,
artifact, tokenizer, profile, query instruction, document instruction and
fixed-point score scale. The evaluator rejects mixed scorer contracts, the
signed quality report preserves the canonical contract, and staging copies and
revalidates every field in the generation. Failed or unavailable reranking
cannot be represented as a passing reranking evaluation.

```sh
knowledge-retrieval stage-generation \
  --hybrid-candidate "$HYBRID" --hybrid-candidate-sha256 "$HYBRID_SHA" \
  --store "$RETRIEVAL_STORE" \
  --quality-report "$QUALITY" --quality-report-sha256 "$QUALITY_SHA" \
  --quality-receipt "$QUALITY_RECEIPT" \
  --quality-receipt-sha256 "$QUALITY_RECEIPT_SHA" \
  --quality-signature "$QUALITY_RECEIPT.sig" \
  --quality-signature-sha256 "$QUALITY_SIGNATURE_SHA" \
  --evaluator-allowed-signers "$EVALUATOR_ALLOWED_SIGNERS" \
  --evaluation-dataset "$SUITE" \
  --evaluation-dataset-sha256 "$SUITE_SHA" \
  --evaluation-metrics "$EVALUATION_METRICS" \
  --evaluation-metrics-sha256 "$EVALUATION_METRICS_SHA" \
  --evaluation-runtime "$EVALUATION_RUNTIME" \
  --evaluation-runtime-sha256 "$EVALUATION_RUNTIME_SHA" \
  --admission-policy "$POLICY" --admission-policy-sha256 "$POLICY_SHA" \
  --retrieval-executable "$RETRIEVAL_BIN" \
  --retrieval-executable-sha256 "$RETRIEVAL_BIN_SHA" \
  --evaluator-executable "$RETRIEVAL_BIN" \
  --evaluator-executable-sha256 "$RETRIEVAL_BIN_SHA" \
  --as-of 2026-07-16T12:00:00Z
```

Promotion is a prepare/sign/apply transaction. Prepare validates the entire
candidate and current chain under an exclusive lock, binds the caller's exact
current pointer (or explicit empty-store bootstrap), current policy, external
`allowed_signers` document, actor and Ed25519 fingerprint, and emits one
canonical content-addressed intent. `TransitionedAt` may not precede the target
generation's creation time and must strictly advance the prior pointer time;
apply rechecks both conditions under the lock before writing any transition
state or exchanging the alias. The operator signs those exact bytes:

```sh
knowledge-retrieval prepare-promotion \
  --generation "$GENERATION" --generation-sha256 "$GENERATION_SHA" \
  --store "$RETRIEVAL_STORE" --state "$GENERATION_STATE" \
  --admission-policy "$POLICY" --admission-policy-sha256 "$POLICY_SHA" \
  --allowed-signers "$ALLOWED_SIGNERS" --actor "$ACTOR" --key-id "$KEY_ID" \
  --transitioned-at 2026-07-16T13:00:00Z --bootstrap > intent.json

ssh-keygen -Y sign -f operator_ed25519 \
  -n archeion-retrieval-generation-transition-v1 intent.json

knowledge-retrieval apply-transition \
  --decision promoted --intent intent.json --intent-sha256 "$INTENT_SHA" \
  --signature intent.json.sig --signature-sha256 "$SIGNATURE_SHA" \
  --generation "$GENERATION" --generation-sha256 "$GENERATION_SHA" \
  --store "$RETRIEVAL_STORE" --state "$GENERATION_STATE" \
  --admission-policy "$POLICY" --admission-policy-sha256 "$POLICY_SHA" \
  --allowed-signers "$ALLOWED_SIGNERS"
```

Later promotions replace `--bootstrap` with `--expect-pointer
retrieval-pointer:sha256:...` and stage a generation whose exact base is that
pointer's current generation. Rollback uses `prepare-rollback` with the current
pointer, signs the new intent, then calls `apply-transition --decision
rolled_back` without a generation argument. It restores the exact previous
generation document and evidence IDs; it does not rebuild or reinterpret it.

The state root contains immutable generation copies, receipts, pointer objects,
signatures and allowed-signers snapshots. `generation-pointer.json` is the only
mutable alias. Apply uses an advisory file lock, pointer compare-and-swap,
synced immutable objects, then one atomic rename over the alias. Crashes before
the rename leave the old current intact; crashes after it leave the new current
fully verifiable and retries are idempotent. `generation-status` recursively
verifies the complete receipt/signature/policy/pointer chain plus both current
and previous whole generations. Any tamper, stale policy, symlink, missing
artifact or inconsistent rollback returns `backend_unavailable` rather than an
empty or partially trusted state.

`VerifyGenerationState` allowlists only the states that genuinely mean verified.
`ok` passes. An absent store reports `empty`, which does **not** verify: a store
that does not exist has proven nothing. A caller that can legitimately accept
absence — a bootstrap path running before the first promotion — must ask for it
explicitly with `GenerationStatusConfig.AllowAbsentGeneration`, and even then
`backend_unavailable` still fails. Every other state fails closed with its
typed `error_code`.

## Read-only current query cutover

MCP/TEL serving must use `current-query`; the lower-level `query` and
`hybrid-query` commands are candidate audit tools. `current-query` has no
candidate, generation or pointer selector, so a caller cannot bypass the signed
current identity. It verifies the immutable pointer/receipt/signature chain and
the whole current generation, requires the running binary hash to equal the
retrieval executable evaluated by that generation, rechecks the exact fresh
policy, executes the independently evaluated lexical profile, then verifies
that the pointer bytes did not change while the query ran. It creates no lock
or state file.

```sh
knowledge-retrieval current-query \
  --store "$RETRIEVAL_STORE" --state "$GENERATION_STATE" \
  --evidence-store "$EVIDENCE_STORE" \
  --admission-policy "$POLICY" --admission-policy-sha256 "$POLICY_SHA" \
  --query 'why is my Argo CD Application Progressing?' \
  --principal-scope public --as-of 2026-07-16T14:00:00Z \
  --limit 10
```

A successful response says `state=current`,
`authority_state=evaluated_current`, `profile=lexical`; a BM25F response also
exposes its immutable `lexical_profile` plus tokenizer and scorer IDs. Both bind
the exact `pointer_id`, pointer revision, transition receipt, current generation
ID/hash, quality report, frozen suite, metrics and lexical candidate.
Missing/tampered state, a policy mismatch, an unevaluated running binary or a
concurrent pointer exchange returns `state=backend_unavailable` with no
evidence results. A future current hybrid profile may accept a query signal,
but it must remain selected through this same generation and may only use the
exact mode evaluated by that generation.

## Admission successor / revocation registry

The forward-referenced revocation feed is a typed, content-addressed
`retrieval_admission_successor` record (`SealAdmissionSuccessorRecord`). It does
not mutate the admission it supersedes — a policy's identity is a digest of its
own bytes — so a revocation or correction is its own reviewed object that
resolution consults. Each record binds the exact prior admission
(`prior_admission_policy_id` plus its document SHA-256), a `disposition` of
`revoked` or `corrected`, a `reason`, the valid-time `effective_at` and
transaction-time `known_at`, the reviewing `reviewer` and `reviewer_key_id`, and
a reviewed-decision `evidence` object. A `revoked` record names no successor; a
`corrected` record must name a separately reviewed successor admission whose ID
and SHA-256 both differ from the prior. It must also bind one exact
`retrieval_admission_review` document. That review embeds the complete
content-addressed admission policy and has an explicit `accepted` or `rejected`
state; resolution accepts only an active policy with an exact accepted review.
An ID-shaped successor, a missing review, a rejected policy or mismatched policy
bytes fails closed.

`ResolveAdmissionSuccessors` takes independent canonical UTC `valid_at` and
`known_at` cutoffs. A record is visible only when its transaction-time
`known_at` is at or before the view's cutoff. A visible successor effective at
or before `valid_at` quarantines the derivative
(`quarantined_revoked` or `quarantined_superseded`); the same read before the
effective time stays `historically_reproducible`. A later-known retroactive
decision cannot rewrite an earlier as-known view. Duplicate and out-of-order
records collapse by content identity; visible conflicts, correction cycles and
corrections into revoked admissions fail closed.

The pure resolver reads a required
`caller_supplied_unpersisted_projection@1.0.0` scope and returns
`persistence_verified=false`. A lexical derivative must include the exact
content-addressed candidate/index pair because the versioned index schema alone
contains only the admission ID; the candidate supplies the policy document
SHA-256. Generations, suites and pointer/generation pairs must retain their
content identities. This function does not load the persisted current store and
therefore cannot itself gate `current-query`, sign, promote, quarantine or
mutate a pointer. Store-backed projection and apply remain a separate rollback
unit.

## Verification

```sh
gofmt -w *.go
GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-retrieval-gocache \
  go test -count=1 -race ./...
GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-retrieval-gocache go vet ./...
CGO_ENABLED=0 GOTMPDIR=/tmp GOCACHE=/tmp/knowledge-retrieval-gocache \
  go build -trimpath -buildvcs=false -ldflags='-buildid=' \
  -o /tmp/knowledge-retrieval ./...
```

The reproducible release recipe fixes `CGO_ENABLED=0`, strips host paths and
the Go build ID, and disables ambient dirty-worktree VCS stamping. Its release
receipt must bind the exact source-tree digest and Go toolchain separately;
changing any build input creates a new immutable binary hash.
The path-scoped `knowledge-retrieval` workflow runs formatting, vet, race tests
and two independently produced static builds with a byte-for-byte comparison.

Tests cover deterministic fresh/reuse builds, exact evidence envelopes,
prompt-injection inertness, normalized-payload tampering, path escape,
store-root/child symlinks, store overlap with no writes, pinned verifier
tampering, forged-review/verifier rejection, public ACL denial,
empty/deleted/tombstoned source states, query-time tombstones, freshness
expiry/time-travel rejection and backend failure. Adversarial resource cases
cover megabyte tokens, unique-term/posting exhaustion, and breadcrumb-heavy
documents with tens of thousands of terms. Postings reference one document
table entry instead of copying the complete evidence envelope per term; query
resolution still returns the exact source-preserving evidence reference. The
cryptographic review implementation and forged/self-signed trust-root cases
remain owned and tested by the exact `knowledge-evidence` verifier that this
compiler re-executes.

BM25F tests additionally cover concise exact evidence versus long repetition,
camel/acronym/plural expansion, unequal-length rational normalization, bounded
heading contribution, exact 32/128 query boundaries, token/term/posting and
integer-overflow failure, body/heading posting union accounting, stable SpanID
ties, repeated canonical builds, legacy-byte isolation and exact lineage or
mixed-lineage rejection across lexical, hybrid, evaluation, generation and
serving-pointer artifacts.

Hybrid tests additionally cover exact model/tokenizer/profile/instruction
bindings, whole-document replacement attacks, mismatched revisions, duplicate
and missing scores, zero vectors, dimensions and score bounds, non-integer
numeric input, deterministic ties, conditional rerank selection, complete
rerank windows, live tombstones and the invariant that no candidate build
creates a serving/current pointer. Evaluator tests execute real lexical and
hybrid queries, recompute fixed-point metrics, enforce exact frozen-suite
coverage, exercise injection/citation/ACL/deletion/freshness/resource/replay
gates, reject signal and executable substitution, and prove deterministic
immutable outputs. They also reject mixed reranker query/document instructions
and prove that a fully bound reranked evaluation stages into a generation
without losing its fixed-point scorer contract. Lifecycle tests cover
failed/unevaluated quality, fusion-only truthfulness, detached Ed25519
authorization, caller-`PATH` executable shadowing,
intent/signature/policy/generation tampering, stale policy, symlink rejection,
concurrent pointer CAS, every atomic-exchange crash point, idempotent retry,
current/previous whole-generation checks and rollback restoration of the exact
evidence ID set. Current-query tests prove
that only the signed pointer-selected generation can serve, that the running
binary was evaluated, and that a missing pointer remains read-only and
fail-closed.
