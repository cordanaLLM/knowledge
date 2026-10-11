# Scorer-blind multi-domain freeze v2 (candidate successor)

This fixture is the successor seed to `../scorer-blind-multidomain-v1`. The v1
freeze `retrieval-evaluation-freeze:sha256:a0fd2cb1…65d2de1b` was burned by
observation: its graded judgments were authored before results existed, but
results were subsequently opened against them, so it can no longer serve as a
pre-result gate. Per v1's own instruction ("preserve this fixture unchanged and
create a separately named revision"), v1 is untouched and this is a separately
named revision.

## What is identical to v1, and what is not

Identical, byte-for-byte: the six content-addressed upstream source blobs, the
three component lanes and commits, all eleven span coordinates, span identities
and evidence payloads, all eleven case IDs and query strings, the injection
case and its inert marker, the comparison target, resource ceilings, latency
ceiling, challenger comparison gates and the exact-binding barrier.

Different: `revision` (`v2`), `frozen_at` and
`provenance.base_repository_commit`. The **relevance judgments** were re-derived
from scratch by the blind reviewers below — and landed on exactly v1's values:
the two freezes' `cases` arrays are byte-identical, verified field by field.
What v2 changes is therefore the judgments' *provenance*, not their content. v1
was burned because its authors had seen results, not because its qrels were
wrong; the independent blind re-derivation reproducing them is evidence the
qrels themselves were sound.

The component lanes are unchanged:

- Kubernetes `v1.36.2`, commit `24e2b02af5543d7910c2bb074c7264df5a8f0467`;
- Cilium `v1.19.5`, commit `20eaccfef029cb046d70219717fb6dbbdf27a59f`;
- Go `go1.26.5`, commit `c19862e5f8415b4f24b189d065ed739517c548ba`.

The immutable freeze is
`retrieval-evaluation-freeze:sha256:ddb38ed65dce0a56e6308689b82c085bd1276e3e1f6d48dea68dc792d5d0959d`
with document hash
`sha256:6bdf06f366ad3e7adc206f2d1c420775df222ed2c032ba8f0ab3714f6d8efd28`.

## How the judgments were derived

Two independent blind relevance reviews were produced first, by two different
fresh-context model reviewers. Neither read any retrieval result, ranking,
score, metric, prior grade, threshold value, or the other reviewer's output.
Both judged all eleven cases and both found that each case has exactly one span
that fully answers it. They were then reconciled by reading the span text and
query directly for every pair where they differed.

Reconciliation outcome: eleven judgments, one grade-3 answer span per case,
each span the answer to exactly one case. Every pair that either reviewer had
graded 1 or 2 was adjudicated down to non-relevant on content — in all three
cases the span in question is the full grade-3 answer to a *sibling* case in
the same suite and does not answer the case under review. Grading those
designed near-misses as partially relevant would blunt exactly the precision
signal the suite exists to measure.

The scale was taken from the validators, not from either reviewer's summary:
`evaluation_freeze.go` and `evaluator_validate.go` accept recorded grades
`1..3`, and a span not recorded for a case is implicitly non-relevant. The
validator additionally rejects any judgment whose span component differs from
the case class, so cross-class pairs cannot be recorded at all.

Full adjudication record, including the per-pair reasoning:
`.workingdir2/cluster-2/audits/p1-retrieval-freeze-v2-adjudication-2026-07-20.md`.

## Thresholds

The absolute Recall/MRR/NDCG floors, the zero-regression challenger gate, the
latency ceiling and the resource ceilings are carried forward unchanged from
v1's *declared* values. Those are declared gates, separable from and authored
before any result, so carrying them forward introduces no result exposure. They
remain meaningful under the stricter qrels: with a single grade-3 answer per
case, `min_ndcg_ppm = 600000` requires the answer at rank 1 or 2, and
`min_recall_ppm = 1000000` requires it inside the top ten of eleven spans.

## Judges were models, not humans

The two reviewers were independent fresh-context model reviewers, blind by
construction. They were not human. A third agent adjudicated the three
disagreements and minted this freeze.

**Operator ratification (2026-07-20).** The operator reviewed that provenance
and accepted these model reviewers as satisfying the acceptance contract's
relevance-judgement requirement. The acceptance is explicitly of *model*
reviewers; nothing here relabels them as human, and no human relevance judge
reviewed these qrels. That decision is what re-pointed the acceptance anchor
below; see
`.workingdir2/cluster-2/audits/p1-rag-01-freeze-v2-acceptance-2026-07-20.md`.

## Status: accepted anchor, evaluated, gate not passed

`evaluation_binding_requirements.go` now pins this freeze in
`p1MultidomainFreezeID` / `p1MultidomainFreezeDocumentSHA256`; v1's identity is
retained as `p1RetiredMultidomainFreezeID` and now fails closed with "binding
requirements do not target the exact accepted multidomain freeze". The check was
re-pointed, not weakened — v1 was verified to fail closed against the new
constants before the fixtures moved.

The binding-requirements closure reaches 38/38 closed, 0 blocking against this
freeze. The evaluation was then executed over both arms and **failed** its
`challenger_gain` gate (`state: failed`); the receipt was therefore never
minted. `promotable` / `execution_authorized` remain `false`. The qrels,
thresholds and comparison gates in this fixture were **not** touched in response
to that result.

Re-materialize without invoking a retriever or scorer:

```sh
go run . materialize-evaluation-freeze \
  --core testdata/scorer-blind-multidomain-v2/suite-freeze.core.json \
  --source-root testdata/scorer-blind-multidomain-v2 \
  --store testdata/scorer-blind-multidomain-v2/materialized
```

If a correction is needed after any result is visible, preserve this fixture
unchanged and create a separately named revision with an explicit rationale.
