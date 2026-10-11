# Scorer-blind multi-domain freeze v1

This fixture freezes an untouched evaluation seed for the versioned fusion
challenger. It was authored only from exact official upstream source text. No
existing qrels, thresholds, ranks, metrics, result objects or scorer output were
read, and neither retrieval profile was executed while authoring it.

The three component lanes match versions already used by this repository:

- Kubernetes `v1.36.2`, commit `24e2b02af5543d7910c2bb074c7264df5a8f0467`;
- Cilium `v1.19.5`, commit `20eaccfef029cb046d70219717fb6dbbdf27a59f`;
- Go `go1.26.5`, commit `c19862e5f8415b4f24b189d065ed739517c548ba`.

`source-blobs/` contains six exact content-addressed upstream files. The frozen
core binds their repository, commit, path, whole-file hash and byte size. Its
eleven judgments bind exact inclusive line and byte ranges, content-derived
SpanIDs and payload hashes. `materialized/evaluation-evidence/` contains those
exact excerpts at their content paths. The prompt-injection case treats its
marker as inert query data.

The immutable freeze is
`retrieval-evaluation-freeze:sha256:a0fd2cb1067e0b92122e3478632831e8822b5b34f63fa841d3bf60aa65d2de1b`.
It fixes the absolute Recall/MRR/NDCG floors, zero allowed challenger regression,
latency ceiling, resource ceilings, query text and graded judgments before any
comparison. Changing any of them creates a different freeze identity.

The freeze intentionally remains `blocked_exact_bindings`. It is not an
executable evaluation suite and grants no quality, serving, generation or
promotion authority. Before execution, a separate reviewed step must bind the
canonical admitted evidence manifest and policy, lexical and dense artifacts,
baseline and challenger hybrid candidates, exact materialized fusion profile,
scorer artifact, and all query-signal artifacts. Those bindings may not alter
this freeze's source bytes, queries, judgments, thresholds or ceilings.

`binding-requirements.core.json` is the first requirements-only rollback unit
for that work. It preserves separate Cilium, Go and Kubernetes source/policy
authority and adds exact snapshot-manifest, evidence-manifest and lexical-index
ID/hash pairs to the original barrier. Its current materialization is
`retrieval-binding-requirements:sha256:d40db301f2e9f44f978665f2030099513605e95c191a9eb1a2d9a39b45db1021`
with 38 typed absent-artifact gaps and no verified artifact or execution
authority. It contains no Workflows profile/scorer substitution and cannot
bind, fetch, retrieve, score, evaluate, sign, stage or move a pointer.

Re-materialize without invoking a retriever or scorer:

```sh
go run . materialize-evaluation-freeze \
  --core testdata/scorer-blind-multidomain-v1/suite-freeze.core.json \
  --source-root testdata/scorer-blind-multidomain-v1 \
  --store /tmp/scorer-blind-freeze-store
```

If a correction is needed after any result is visible, preserve this fixture
unchanged and create a separately named revision with an explicit rationale.
