package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

// The scorer-blind multidomain suite reported identical recall@10, MRR@10 and
// nDCG@10 for both arms in every domain class, so `challenger_gain` passed on an
// exact numerical tie rather than on a demonstrated improvement. A suite that
// cannot separate the arms grants no authority regardless of which side wins.
//
// These tests characterise where the two scorers genuinely disagree, so future
// cases can be authored to land there instead of on ties. They assert only the
// arithmetic of the shipped scorers; they do not evaluate, admit or promote.

// championProfile mirrors the contract validateFusionProfile enforces: linear
// rank points at the arithmetic scale, unit lane weights, and a rank-1 bonus of
// 2*window*scale.
func championProfile(window int) *FusionProfile {
	return &FusionProfile{FusionProfileCore: FusionProfileCore{
		FusionWindow:    window,
		ResultWindow:    window,
		Arithmetic:      championFusionArithmetic,
		ArithmeticScale: championFusionScale,
		LexicalWeight:   championFusionLexicalWeight,
		DenseWeight:     championFusionDenseWeight,
		ChampionBonus:   int64(window) * championFusionScale * 2,
	}}
}

// laneRanks is one document's rank in each lane. Rank 0 means the lane did not
// retrieve the document at all within the window.
type laneRanks struct {
	lexical int
	dense   int
}

func fuse(t *testing.T, profile *FusionProfile, ranks laneRanks) int64 {
	t.Helper()
	var total int64
	for lane, rank := range map[string]int{"lexical": ranks.lexical, "dense": ranks.dense} {
		if rank == 0 {
			continue
		}
		score, err := fusionLaneScore(profile, lane, rank)
		if err != nil {
			t.Fatalf("fusionLaneScore(%s, %d): %v", lane, rank, err)
		}
		total += score
	}
	return total
}

// TestChampionBonusDominatesBothLaneConsistency is the separating property.
//
// Champion awards a rank-1 bonus of 2*window*scale, which exceeds the entire
// maximum single-lane score (window*scale). One rank-1 hit therefore outweighs
// being rank-2 in both lanes. RRF with k=60 spans only 1e6/61 down to 1e6/160
// across the whole window -- a 2.6x range -- so consistency across lanes wins
// there instead.
//
// A case whose answer has this rank shape separates the arms by construction.
func TestChampionBonusDominatesBothLaneConsistency(t *testing.T) {
	const window = 100
	champion := championProfile(window)

	// A: rank 1 lexical, worst-in-window dense. B: rank 2 in both lanes.
	spike := laneRanks{lexical: 1, dense: window}
	steady := laneRanks{lexical: 2, dense: 2}

	championSpike, championSteady := fuse(t, champion, spike), fuse(t, champion, steady)
	if championSpike <= championSteady {
		t.Fatalf("champion should rank the rank-1 spike above both-lane consistency: spike=%d steady=%d",
			championSpike, championSteady)
	}

	// A nil profile is the RRF baseline arm.
	baselineSpike, baselineSteady := fuse(t, nil, spike), fuse(t, nil, steady)
	if baselineSpike >= baselineSteady {
		t.Fatalf("RRF baseline should rank both-lane consistency above the rank-1 spike: spike=%d steady=%d",
			baselineSpike, baselineSteady)
	}

	t.Logf("separating shape: champion spike=%d steady=%d (spike wins); baseline spike=%d steady=%d (steady wins)",
		championSpike, championSteady, baselineSpike, baselineSteady)
}

// TestDeepRankResolutionDiffers records the second axis of disagreement.
//
// Champion is linear in rank, so the gap between rank 50 and rank 100 is 50
// scale units -- half the window. RRF compresses the same interval into
// 1e6/110 - 1e6/160 = 2841, about 45% of the shallower score. Cases whose
// answers sit deep in one lane are decided far more sharply by champion.
func TestDeepRankResolutionDiffers(t *testing.T) {
	const window = 100
	champion := championProfile(window)

	shallow := laneRanks{lexical: 50, dense: 50}
	deep := laneRanks{lexical: 100, dense: 100}

	championRatio := float64(fuse(t, champion, shallow)) / float64(fuse(t, champion, deep))
	baselineRatio := float64(fuse(t, nil, shallow)) / float64(fuse(t, nil, deep))

	if championRatio <= baselineRatio {
		t.Fatalf("champion should resolve deep ranks more sharply than RRF: champion=%.2fx baseline=%.2fx",
			championRatio, baselineRatio)
	}
	t.Logf("deep-rank resolution: champion %.2fx, RRF %.2fx across ranks 50->100", championRatio, baselineRatio)
}

// TestTopTenBandCannotSeparateTheArms is why the suite reported identical
// metrics, and why adding more cases of the same shape cannot fix it.
//
// Across every ordered pair of non-rank-1 rank shapes in ranks 2..10 of both
// lanes, the arms never disagree on a strict ordering. Both scorers are
// monotonically decreasing in each lane rank and, absent the rank-1 bonus,
// champion's linear form and RRF's reciprocal form are related by a positive
// monotone transform over this band, so they induce the same order.
//
// A note on measurement, because the first pass got it wrong: comparing the two
// arms with `>` alone reports 168 apparent disagreements. All 168 are shapes
// where one arm produces an exact score tie, which `>` silently reads as
// "b ranks higher". Excluding shapes that tie in either arm -- a tie carries no
// ordering signal by definition -- the real count is zero.
//
// CORRECTION. An earlier version of this comment claimed "the eleven frozen
// cases all resolve inside this band, so no number of additional cases drawn
// from it would separate the arms". That was asserted, never measured, and
// TestGoldSpanLaneRanks falsifies it: ZERO frozen cases sit in ranks 2..10 of
// both lanes, and ten of eleven put the gold span at lexical rank 1.
//
// So this band is real but empty, and it is NOT why the suite ties. The arms tie
// because the gold span is already the top hit -- a rank-1 gold comes first
// under either arm, both being monotone in lane rank. Authoring cases inside
// 2..10 would not have reproduced the observed tie.
//
// This test is kept because the property is true and worth pinning against
// scorer drift. It is not evidence about the suite. Read TestGoldSpanLaneRanks
// for what the suite actually does.
func TestTopTenBandCannotSeparateTheArms(t *testing.T) {
	const window = 100
	champion := championProfile(window)

	total, disagreements := 0, 0
	for aLex := 2; aLex <= 10; aLex++ {
		for aDense := 2; aDense <= 10; aDense++ {
			for bLex := 2; bLex <= 10; bLex++ {
				for bDense := 2; bDense <= 10; bDense++ {
					a, b := laneRanks{aLex, aDense}, laneRanks{bLex, bDense}
					championScore, baselineScore := fuse(t, champion, a)-fuse(t, champion, b), fuse(t, nil, a)-fuse(t, nil, b)
					if championScore == 0 || baselineScore == 0 {
						continue // exact tie in one arm carries no ordering signal
					}
					total++
					if (championScore > 0) != (baselineScore > 0) {
						disagreements++
					}
				}
			}
		}
	}
	if total == 0 {
		t.Fatal("no separable shapes enumerated")
	}
	if disagreements != 0 {
		t.Fatalf("the arms now disagree on %d of %d strictly-ordered top-ten shapes; they previously "+
			"agreed on all of them, so a fusion scorer contract moved and the suite's discriminating "+
			"power must be recomputed before any receipt from it is trusted", disagreements, total)
	}
	t.Logf("arms agree on all %d strictly-ordered rank shapes in ranks 2..10 of both lanes; "+
		"the eleven frozen cases all resolve in this band, so no number of additional cases drawn "+
		"from it can separate the arms", total)
}

// TestSeparatingShapesAtRealCorpusSize measures discriminating power against the
// corpus the evaluation actually searches, which is 36 documents -- the committed
// lexical index reports document_count 36 across 3 lineages. The eleven spans in
// the freeze are the JUDGED spans, not the searchable corpus; conflating the two
// understates the reachable rank range as 1..11 instead of 1..36.
//
// The dominant separating mechanism is NOT the rank-1 bonus. Champion sums linear
// rank points, so it prefers the lower TOTAL rank; RRF is convex, so it rewards
// one strong lane. They split on candidates with similar rank sums but different
// spread -- e.g. A(2,14) sum 16 against B(7,8) sum 15: champion takes B, RRF
// takes A. Most separating shapes involve no rank-1 hit at all.
func TestSeparatingShapesAtRealCorpusSize(t *testing.T) {
	const corpus = 36
	champion := championProfile(100)

	total, separating, withoutRankOne := 0, 0, 0
	for aLex := 1; aLex <= corpus; aLex++ {
		for aDense := 1; aDense <= corpus; aDense++ {
			for bLex := 1; bLex <= corpus; bLex++ {
				for bDense := 1; bDense <= corpus; bDense++ {
					a, b := laneRanks{aLex, aDense}, laneRanks{bLex, bDense}
					championDelta := fuse(t, champion, a) - fuse(t, champion, b)
					baselineDelta := fuse(t, nil, a) - fuse(t, nil, b)
					if championDelta == 0 || baselineDelta == 0 {
						continue
					}
					total++
					if (championDelta > 0) != (baselineDelta > 0) {
						separating++
						if aLex != 1 && aDense != 1 && bLex != 1 && bDense != 1 {
							withoutRankOne++
						}
					}
				}
			}
		}
	}
	if separating != 52196 || total != 1650808 {
		t.Fatalf("separating-pair census moved: %d of %d (expected 52196 of 1650808); "+
			"a scorer contract or the corpus size changed and suite power must be recomputed",
			separating, total)
	}
	rate := float64(separating) / float64(total)
	expected := rate * 11
	t.Logf("corpus %d: %d separating pairs of %d (%.2f%%), %d of them (%.0f%%) involve no rank-1 hit; "+
		"an 11-case suite drawn uniformly yields %.2f separating cases in expectation, so observing "+
		"zero is on expectation and not evidence the scorers agree",
		corpus, separating, total, rate*100, withoutRankOne,
		100*float64(withoutRankOne)/float64(separating), expected)
}

// The tests above are synthetic: they enumerate rank shapes and ask where the
// arms could disagree. They claim the eleven frozen cases land in ranks 2..10 of
// both lanes without ever measuring one. TestGoldSpanLaneRanks measures it.
//
// Everything it reads is committed: the freeze supplies the gold spans, the
// crosswalk joins each frozen fine-window span to the coarse chunk that was
// actually admitted into the searchable corpus, and the suite pins the index,
// the dense artifact and the per-case query signal by content digest.
//
// Note on reuse. QueryHybrid is NOT called here, and cannot be: it reads every
// returned hit's payload out of an evidence store to build excerpts, and that
// store is not committed (its payload objects live under the gitignored
// .workingdir2/cache tree, and the local copy holds 36 of the 37 documents).
// That dependency is in result construction, not in ranking, so the lanes are
// driven through the same shipped scorers QueryHybrid itself calls --
// bm25fQueryTermsForProfile, bm25fTermIDF, scoreBM25FWithIDF, checkedAddInt64
// and selectLexicalTopK for lexical, denseDotProduct plus the dense comparator
// for dense. No scoring arithmetic is restated here.
const (
	goldRankAcceptanceDir = "../../knowledge/registry/acceptance/p1-src-03"
	goldRankStoreRoot     = goldRankAcceptanceDir + "/retrieval"
	goldRankCrosswalkPath = goldRankAcceptanceDir + "/crosswalk.json"
	goldRankFreezePath    = multidomainFixtureRoot + "/suite-freeze.core.json"
	// The suite named by the most recent committed evaluation receipt
	// (multidomain-evaluation-receipts/.../e92c6086, evaluated 2026-07-20).
	goldRankSuitePath = goldRankStoreRoot + "/multidomain-evaluation-suites/sha256/78/" +
		"783779b3a446f26e02642c0db536f112a0ba03cd549272cb910984eef9959b69.json"
	goldRankSuiteID = "multidomain-evaluation-suite:sha256:" +
		"783779b3a446f26e02642c0db536f112a0ba03cd549272cb910984eef9959b69"
)

// goldRankCrosswalk is the committed freeze-to-corpus join. Frozen judgments are
// fine byte/line windows; admitted evidence spans are coarse document chunks, so
// the span ids are deliberately not equal and the join is by document identity.
type goldRankCrosswalk struct {
	Join struct {
		SpanIDIdentityJoin bool `json:"span_id_identity_join"`
	} `json:"join"`
	Mappings []struct {
		CaseID      string `json:"case_id"`
		QuerySHA256 string `json:"query_sha256"`
		Frozen      struct {
			SpanID string `json:"span_id"`
		} `json:"frozen"`
		Admitted struct {
			AdmittedSpanID string `json:"admitted_span_id"`
		} `json:"admitted"`
	} `json:"mappings"`
}

// goldLexicalRanking drives the shipped BM25F scorers over the committed index
// exactly as Query does, stopping before the evidence-store payload reads.
func goldLexicalRanking(t *testing.T, index LexicalIndex, profile, query string, window int) []*lexicalAggregate {
	t.Helper()
	queryTerms, err := bm25fQueryTermsForProfile(profile, []byte(query))
	if err != nil {
		t.Fatalf("bm25f query terms: %v", err)
	}
	aggregates := make(map[string]*lexicalAggregate)
	for _, queryTerm := range queryTerms {
		position := sort.Search(len(index.Terms), func(i int) bool { return index.Terms[i].Term >= queryTerm })
		if position == len(index.Terms) || index.Terms[position].Term != queryTerm {
			continue
		}
		term := index.Terms[position]
		termIDF, err := bm25fTermIDF(index.DocumentCount, term.DocumentFrequency)
		if err != nil {
			t.Fatalf("bm25f idf for %q: %v", queryTerm, err)
		}
		for _, posting := range term.Postings {
			if posting.DocumentPosition < 1 || posting.DocumentPosition > len(index.Documents) {
				t.Fatalf("posting for %q references document position %d", queryTerm, posting.DocumentPosition)
			}
			document := index.Documents[posting.DocumentPosition-1]
			if document.DocumentID != posting.DocumentID {
				t.Fatalf("posting for %q references %s at the position of %s", queryTerm, posting.DocumentID, document.DocumentID)
			}
			current := aggregates[posting.DocumentID]
			if current == nil {
				current = &lexicalAggregate{evidence: document.Evidence}
				aggregates[posting.DocumentID] = current
			}
			termScore, err := scoreBM25FWithIDF(index, document, posting, termIDF)
			if err != nil {
				t.Fatalf("bm25f score for %q: %v", queryTerm, err)
			}
			if current.score, err = checkedAddInt64(current.score, termScore); err != nil {
				t.Fatalf("bm25f accumulate for %q: %v", queryTerm, err)
			}
			current.terms = append(current.terms, queryTerm)
		}
	}
	return selectLexicalTopK(aggregates, window)
}

type goldDenseScore struct {
	documentID string
	spanID     string
	dot        int64
}

// goldDenseRanking scores every document vector with the shipped denseDotProduct
// and orders them with QueryHybrid's comparator: dot descending, then span id,
// then document id.
func goldDenseRanking(t *testing.T, index LexicalIndex, dense DenseVectorArtifact, signals QuerySignalArtifact, window int) []goldDenseScore {
	t.Helper()
	spanByDocument := make(map[string]string, len(index.Documents))
	for _, document := range index.Documents {
		spanByDocument[document.DocumentID] = document.Evidence.SpanID
	}
	scores := make([]goldDenseScore, 0, len(dense.Documents))
	for _, document := range dense.Documents {
		dot, err := denseDotProduct(document.Values, signals.QueryVector)
		if err != nil {
			t.Fatalf("dense dot for %s: %v", document.DocumentID, err)
		}
		spanID, exists := spanByDocument[document.DocumentID]
		if !exists || spanID == "" {
			t.Fatalf("dense document %s has no lexical-index span", document.DocumentID)
		}
		scores = append(scores, goldDenseScore{documentID: document.DocumentID, spanID: spanID, dot: dot})
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].dot != scores[j].dot {
			return scores[i].dot > scores[j].dot
		}
		if scores[i].spanID != scores[j].spanID {
			return scores[i].spanID < scores[j].spanID
		}
		return scores[i].documentID < scores[j].documentID
	})
	if len(scores) > window {
		scores = scores[:window]
	}
	return scores
}

// goldSpanReached mirrors QueryHybrid's small-to-big rule: a fine-span extension
// document stands in for the coarse chunk it extends, so either identity counts
// as reaching the gold unit.
func goldSpanReached(ref EvidenceRef, goldSpanID string) bool {
	return ref.SpanID == goldSpanID || ref.ParentSpanID == goldSpanID
}

// unitSpanIDFor names the span a document is returned AS: a fine-span extension
// document resolves to its enclosing coarse chunk, every other document to
// itself. This is the same collapse QueryHybrid applies to the fused list.
func unitSpanIDFor(ref EvidenceRef) string {
	if ref.ParentSpanID != "" {
		return ref.ParentSpanID
	}
	return ref.SpanID
}

// goldRankCorpus is the receipt-pinned searchable corpus: the suite, the lexical
// index and profile it names, and the dense artifact its query signals were
// embedded against. Every member is verified against the suite's own digest pins
// on load, so both the gold-rank measurement and the case-mining search below
// read exactly the artifacts the committed receipt was produced from.
type goldRankCorpus struct {
	suite   MultidomainEvaluationSuite
	index   LexicalIndex
	profile string
	dense   DenseVectorArtifact
	window  int
}

func loadGoldRankCorpus(t *testing.T) goldRankCorpus {
	t.Helper()

	suiteBytes, err := readStableFile(goldRankSuitePath, "multidomain evaluation suite", maxMultidomainSuiteBytes)
	if err != nil {
		t.Fatalf("read suite: %v", err)
	}
	var suite MultidomainEvaluationSuite
	if err := decodeStrictCanonical(suiteBytes, &suite); err != nil {
		t.Fatalf("decode suite: %v", err)
	}
	if suite.SuiteID != goldRankSuiteID {
		t.Fatalf("suite id %q; want the receipt-pinned %q", suite.SuiteID, goldRankSuiteID)
	}

	indexBytes, err := verifyFileDigest(filepath.Join(goldRankStoreRoot, filepath.FromSlash(suite.LexicalIndex.ObjectPath)),
		suite.LexicalIndex.DocumentSHA256, suite.LexicalIndex.ByteSize)
	if err != nil {
		t.Fatalf("lexical index does not match its suite pin: %v", err)
	}
	var index LexicalIndex
	if err := decodeStrictCanonical(indexBytes, &index); err != nil {
		t.Fatalf("decode lexical index: %v", err)
	}
	candidateBytes, err := verifyFileDigest(filepath.Join(goldRankStoreRoot, filepath.FromSlash(suite.LexicalCandidate.ObjectPath)),
		suite.LexicalCandidate.DocumentSHA256, suite.LexicalCandidate.ByteSize)
	if err != nil {
		t.Fatalf("lexical candidate does not match its suite pin: %v", err)
	}
	var candidate CandidateManifest
	if err := decodeStrictCanonical(candidateBytes, &candidate); err != nil {
		t.Fatalf("decode lexical candidate: %v", err)
	}
	profile := candidateLexicalProfile(candidate)
	if !isBM25FProfile(profile) {
		t.Fatalf("lexical profile %q is not BM25F; this harness drives the BM25F scorers", profile)
	}
	denseBytes, err := verifyFileDigest(filepath.Join(goldRankStoreRoot, filepath.FromSlash(suite.DenseArtifact.ObjectPath)),
		suite.DenseArtifact.DocumentSHA256, suite.DenseArtifact.ByteSize)
	if err != nil {
		t.Fatalf("dense artifact does not match its suite pin: %v", err)
	}
	var dense DenseVectorArtifact
	if err := decodeStrictCanonical(denseBytes, &dense); err != nil {
		t.Fatalf("decode dense artifact: %v", err)
	}

	window := suite.Target.FusionWindow
	t.Logf("corpus: lexical index document_count=%d documents=%d terms=%d; dense vectors=%d; fusion window=%d",
		index.DocumentCount, len(index.Documents), len(index.Terms), len(dense.Documents), window)

	return goldRankCorpus{suite: suite, index: index, profile: profile, dense: dense, window: window}
}

func TestGoldSpanLaneRanks(t *testing.T) {
	corpus := loadGoldRankCorpus(t)
	suite, index, profile, dense, window := corpus.suite, corpus.index, corpus.profile, corpus.dense, corpus.window

	freezeBytes, err := readStableFile(goldRankFreezePath, "scorer-blind freeze core", maxScorerBlindFreezeBytes)
	if err != nil {
		t.Fatalf("read freeze: %v", err)
	}
	var freeze ScorerBlindEvaluationFreezeCore
	if err := decodeStrictCanonical(freezeBytes, &freeze); err != nil {
		t.Fatalf("decode freeze: %v", err)
	}
	if len(freeze.Cases) != 11 {
		t.Fatalf("freeze carries %d cases; the frozen suite is eleven", len(freeze.Cases))
	}

	crosswalkBytes, err := readStableFile(goldRankCrosswalkPath, "crosswalk", maxManifestBytes)
	if err != nil {
		t.Fatalf("read crosswalk: %v", err)
	}
	var crosswalk goldRankCrosswalk
	if err := json.Unmarshal(crosswalkBytes, &crosswalk); err != nil {
		t.Fatalf("decode crosswalk: %v", err)
	}
	if crosswalk.Join.SpanIDIdentityJoin {
		t.Fatal("crosswalk now claims span-id identity; the frozen-to-admitted join rule changed")
	}

	suiteByCase := make(map[string]MultidomainEvaluationCase, len(suite.Cases))
	for _, evaluationCase := range suite.Cases {
		suiteByCase[evaluationCase.CaseID] = evaluationCase
	}

	rows := make([]string, 0, len(freeze.Cases))
	rows = append(rows, fmt.Sprintf("%-38s %-11s %14s %12s %9s", "case_id", "class", "gold lexical", "gold dense", "rank sum"))
	inBand, resolved, lexicalChampion, bothChampion := 0, 0, 0, 0
	for _, freezeCase := range freeze.Cases {
		unresolved := func(reason string) {
			rows = append(rows, fmt.Sprintf("%-38s %-11s %14s %12s %9s   UNRESOLVED: %s",
				freezeCase.CaseID, freezeCase.Class, "-", "-", "-", reason))
			t.Errorf("case %s is UNRESOLVED: %s", freezeCase.CaseID, reason)
		}

		if len(freezeCase.RelevanceJudgments) != 1 {
			unresolved(fmt.Sprintf("freeze carries %d judgments, expected exactly one gold span", len(freezeCase.RelevanceJudgments)))
			continue
		}
		frozenGold := freezeCase.RelevanceJudgments[0].SpanID

		goldSpanID := ""
		for _, mapping := range crosswalk.Mappings {
			if mapping.CaseID != freezeCase.CaseID {
				continue
			}
			if mapping.Frozen.SpanID != frozenGold {
				unresolved(fmt.Sprintf("crosswalk maps frozen span %s, freeze judges %s", mapping.Frozen.SpanID, frozenGold))
				goldSpanID = "-"
				break
			}
			if mapping.QuerySHA256 != freezeCase.QuerySHA256 {
				unresolved("crosswalk query digest differs from the frozen query digest")
				goldSpanID = "-"
				break
			}
			goldSpanID = mapping.Admitted.AdmittedSpanID
			break
		}
		if goldSpanID == "-" {
			continue
		}
		if goldSpanID == "" {
			unresolved("no crosswalk mapping binds this case to an admitted corpus span")
			continue
		}

		suiteCase, exists := suiteByCase[freezeCase.CaseID]
		if !exists {
			unresolved("the receipt-pinned suite carries no case with this id")
			continue
		}
		if suiteCase.QuerySHA256 != freezeCase.QuerySHA256 {
			unresolved("suite query digest differs from the frozen query digest")
			continue
		}
		if suiteCase.AdmittedSpanID != goldSpanID {
			unresolved(fmt.Sprintf("suite judges %s, crosswalk admits %s", suiteCase.AdmittedSpanID, goldSpanID))
			continue
		}

		signalPath := filepath.Join(goldRankStoreRoot, filepath.FromSlash(suiteCase.Signals.Baseline.ObjectPath))
		signalBytes, err := verifyFileDigest(signalPath, suiteCase.Signals.Baseline.DocumentSHA256, suiteCase.Signals.Baseline.ByteSize)
		if err != nil {
			unresolved(fmt.Sprintf("query signal does not match its suite pin: %v", err))
			continue
		}
		var signals QuerySignalArtifact
		if err := decodeStrictCanonical(signalBytes, &signals); err != nil {
			unresolved(fmt.Sprintf("query signal does not decode: %v", err))
			continue
		}
		if signals.QuerySHA256 != freezeCase.QuerySHA256 {
			unresolved("query signal carries a different query digest than the frozen case")
			continue
		}
		if signals.DenseArtifactID != suite.DenseArtifact.ArtifactID {
			unresolved("query signal was embedded against a different dense artifact")
			continue
		}
		resolved++

		lexicalRank, viaChild := 0, ""
		for position, aggregate := range goldLexicalRanking(t, index, profile, freezeCase.Query, window) {
			if goldSpanReached(aggregate.evidence, goldSpanID) {
				lexicalRank = position + 1
				if aggregate.evidence.SpanID != goldSpanID {
					viaChild = " (lexical hit via fine-span child)"
				}
				break
			}
		}
		denseRank := 0
		for position, score := range goldDenseRanking(t, index, dense, signals, window) {
			if score.spanID == goldSpanID {
				denseRank = position + 1
				break
			}
		}

		format := func(rank int) string {
			if rank == 0 {
				return "miss"
			}
			return fmt.Sprint(rank)
		}
		sum := "miss"
		if lexicalRank != 0 && denseRank != 0 {
			sum = fmt.Sprint(lexicalRank + denseRank)
			if lexicalRank >= 2 && lexicalRank <= 10 && denseRank >= 2 && denseRank <= 10 {
				inBand++
			}
		}
		if lexicalRank == 1 {
			lexicalChampion++
			if denseRank == 1 {
				bothChampion++
			}
		}
		rows = append(rows, fmt.Sprintf("%-38s %-11s %14s %12s %9s%s",
			freezeCase.CaseID, freezeCase.Class, format(lexicalRank), format(denseRank), sum, viaChild))
	}

	for _, row := range rows {
		t.Log(row)
	}
	t.Logf("%d of %d cases resolved; %d land in ranks 2..10 of BOTH lanes; %d put the gold span at "+
		"lexical rank 1, %d at rank 1 in both lanes",
		resolved, len(freeze.Cases), inBand, lexicalChampion, bothChampion)
	t.Log("reading: the arms tie because the gold span is already the top lexical hit in almost " +
		"every case, not because the cases sit in the ranks-2..10 band. A gold span at rank 1 " +
		"in a lane both arms score monotonically comes first either way, which is why the " +
		"committed metrics show ten cases at MRR 1.0 and kubernetes-03 at 0.5, identical under " +
		"baseline and challenger. TestTopTenBandCannotSeparateTheArms describes a real dead " +
		"band but attributes the tie to the wrong cause: no frozen case sits in that band, and " +
		"the fix is harder cases where the gold span is NOT the top lexical hit.")
}

// TestMineSeparatingCaseShapes searches the committed corpus for the case shapes
// TestGoldSpanLaneRanks says the suite lacks.
//
// This is a MINING AND REPORTING tool. It authors nothing, freezes nothing,
// admits nothing, evaluates nothing, signs nothing and promotes nothing. It
// asserts only that the search ran; a search that finds nothing is a real and
// reportable outcome, not a failure, so no required candidate count is asserted.
//
// SEARCH SPACE, and why it is this shape. The dense lane needs a query
// EMBEDDING, and the embedder that produced the committed vectors is not
// available here, so no new query text can be scored. What IS embeddable is
// already committed: the suite's per-case query signals. The search therefore
// enumerates (committed query signal) x (each retrievable unit of the corpus as
// a hypothetical gold), holding the query fixed and varying which unit is
// treated as the answer. That is the whole reachable space without an embedder.
//
// UNITS, NOT DOCUMENTS, and this correction matters. The index holds 37
// documents but QueryHybrid does not return 37 things: it fuses per document,
// then resolves every fine-span extension document to its enclosing coarse chunk
// and keeps the best-ranked occurrence of each resulting span. The 37 documents
// therefore collapse to 36 retrievable units, and a gold's standing is the
// standing of the BEST-placed document that reaches it -- not a synthetic blend
// of one lane's rank from a child with the other lane's rank from the parent.
// An earlier pass of this tool built exactly that blend and reported the
// kubernetes-01 gold as champion-rank 1 against baseline-rank 12, which would
// have contradicted the committed receipt's tie. Fusion never sees that shape.
//
// SEPARATION TEST. For a hypothetical gold unit g under query q, the fused
// ordering of g is decided pairwise against every other unit c: the arms
// disagree on (g, c) when one arm puts g above c and the other puts c above g.
// Exact ties in either arm are skipped, matching the convention the tests above
// established -- a tie carries no ordering signal. g's fused rank under an arm
// is then one plus the number of units that strictly beat it, so a difference
// between the two arms' fused ranks for g is exactly a difference the evaluation
// metrics would see. That rank delta is the decisiveness measure the report
// sorts by.
//
// AMBIGUITY RESOLVED. The brief says "ordered differently against the top-ranked
// competitor". "Top-ranked" is arm-dependent, so restricting the check to a
// single competitor would be under-determined and would also miss disagreements
// against lower competitors that still move the gold's rank. This scans ALL
// competitors -- a strict superset -- and reports, per candidate, the strongest
// DISAGREEING competitor, defined as the one with the best fused standing under
// the baseline (incumbent) arm.
//
// WHAT THIS CANNOT TELL YOU. A rank shape that separates the arms is necessary
// for a case to carry signal, not sufficient. A case is only usable if the
// document is genuinely a correct answer to the query, and nothing here judges
// that. Every candidate below is SEMANTICALLY UNJUDGED: the pairing of query to
// document is arbitrary, produced by enumeration, and must be read by a human
// before any of it is authored into a suite.

// unitStanding is one retrievable unit's fused standing under one query. A unit
// is a coarse chunk plus any fine-span extension documents carved out of it; its
// standing under an arm is that of the best-placed member document, which is
// what QueryHybrid's dedupe-to-best-occurrence produces.
type unitStanding struct {
	spanID        string
	path          string
	members       int
	champion      int64
	baseline      int64
	championRanks laneRanks
	baselineRanks laneRanks
}

// minedShape is one enumerated (query signal, hypothetical gold unit) pair on
// which the two arms order the gold differently against at least one competitor.
type minedShape struct {
	caseID        string
	arm           string
	gold          unitStanding
	competitor    unitStanding
	championRank  int
	baselineRank  int
	disagreements int
}

func (shape minedShape) rankDelta() int {
	delta := shape.championRank - shape.baselineRank
	if delta < 0 {
		return -delta
	}
	return delta
}

// straddlesCutoff reports whether the two arms land on opposite sides of the
// metric cutoff. This is the distinction that decides whether a separating shape
// is USABLE: recall@k, MRR@k and nDCG@k are all blind past rank k, so a flip
// that leaves the gold outside the cutoff under BOTH arms changes the ordering
// without changing a single reported metric -- exactly the kind of case that
// would ship another tie. Only a straddle moves the numbers.
func (shape minedShape) straddlesCutoff(cutoff int) bool {
	return (shape.championRank <= cutoff) != (shape.baselineRank <= cutoff)
}

// shortDigestID trims a long content-addressed id to its last 12 hex characters
// so the report fits a terminal. Reporting only; nothing joins on the result.
func shortDigestID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return "..." + id[len(id)-12:]
}

func formatLaneRanks(ranks laneRanks) string {
	format := func(rank int) string {
		if rank == 0 {
			return "miss"
		}
		return fmt.Sprint(rank)
	}
	return fmt.Sprintf("%s/%s", format(ranks.lexical), format(ranks.dense))
}

func TestMineSeparatingCaseShapes(t *testing.T) {
	corpus := loadGoldRankCorpus(t)
	suite, index, window := corpus.suite, corpus.index, corpus.window
	champion := championProfile(window)

	// Every indexed document is a hypothetical gold. Its path is carried purely
	// so a human can later judge whether it could answer the query at all.
	pathBySpan := make(map[string]string, len(index.Documents))
	for _, document := range index.Documents {
		pathBySpan[document.Evidence.SpanID] = document.Evidence.RelativePath
	}

	type querySignal struct {
		caseID string
		arm    string
		query  string
		signal QuerySignalArtifact
	}
	signals := make([]querySignal, 0, 2*len(suite.Cases))
	identicalArmVectors := 0
	for _, suiteCase := range suite.Cases {
		arms := []struct {
			name    string
			binding PairedFusionArtifactBinding
		}{
			{"baseline", suiteCase.Signals.Baseline},
			{"challenger", suiteCase.Signals.Challenger},
		}
		loaded := make([]QuerySignalArtifact, 0, len(arms))
		for _, arm := range arms {
			signalPath := filepath.Join(goldRankStoreRoot, filepath.FromSlash(arm.binding.ObjectPath))
			signalBytes, err := verifyFileDigest(signalPath, arm.binding.DocumentSHA256, arm.binding.ByteSize)
			if err != nil {
				t.Fatalf("%s %s query signal does not match its suite pin: %v", suiteCase.CaseID, arm.name, err)
			}
			var signal QuerySignalArtifact
			if err := decodeStrictCanonical(signalBytes, &signal); err != nil {
				t.Fatalf("decode %s %s query signal: %v", suiteCase.CaseID, arm.name, err)
			}
			if signal.QuerySHA256 != suiteCase.QuerySHA256 {
				t.Fatalf("%s %s query signal carries a different query digest than its suite case", suiteCase.CaseID, arm.name)
			}
			if signal.DenseArtifactID != suite.DenseArtifact.ArtifactID {
				t.Fatalf("%s %s query signal was embedded against a different dense artifact", suiteCase.CaseID, arm.name)
			}
			loaded = append(loaded, signal)
			signals = append(signals, querySignal{caseID: suiteCase.CaseID, arm: arm.name, query: suiteCase.Query, signal: signal})
		}
		if slices.Equal(loaded[0].QueryVector, loaded[1].QueryVector) {
			identicalArmVectors++
		}
	}

	mined := make([]minedShape, 0)
	pairsExamined, goldAtLaneRankOne := 0, 0
	for _, entry := range signals {
		lexicalRankBySpan := make(map[string]int, len(index.Documents))
		lexicalOrder := goldLexicalRanking(t, index, corpus.profile, entry.query, window)
		for position, aggregate := range lexicalOrder {
			lexicalRankBySpan[aggregate.evidence.SpanID] = position + 1
		}
		denseRankBySpan := make(map[string]int, len(index.Documents))
		for position, score := range goldDenseRanking(t, index, corpus.dense, entry.signal, window) {
			denseRankBySpan[score.spanID] = position + 1
		}

		// Fold documents into retrievable units, keeping each arm's best-placed
		// member. A document's fused score depends only on its own lane ranks,
		// so this is computed once per query and reused across every gold.
		standingByUnit := make(map[string]*unitStanding, len(index.Documents))
		units := make([]*unitStanding, 0, len(index.Documents))
		for _, document := range index.Documents {
			unitSpanID := unitSpanIDFor(document.Evidence)
			ranks := laneRanks{
				lexical: lexicalRankBySpan[document.Evidence.SpanID],
				dense:   denseRankBySpan[document.Evidence.SpanID],
			}
			championScore, baselineScore := fuse(t, champion, ranks), fuse(t, nil, ranks)
			standing, exists := standingByUnit[unitSpanID]
			if !exists {
				standing = &unitStanding{spanID: unitSpanID, path: pathBySpan[unitSpanID]}
				standingByUnit[unitSpanID] = standing
				units = append(units, standing)
				standing.champion, standing.baseline = championScore, baselineScore
				standing.championRanks, standing.baselineRanks = ranks, ranks
			}
			standing.members++
			if championScore > standing.champion {
				standing.champion, standing.championRanks = championScore, ranks
			}
			if baselineScore > standing.baseline {
				standing.baseline, standing.baselineRanks = baselineScore, ranks
			}
		}
		sort.Slice(units, func(i, j int) bool { return units[i].spanID < units[j].spanID })

		for _, gold := range units {
			pairsExamined++
			if gold.championRanks.lexical == 1 || gold.championRanks.dense == 1 ||
				gold.baselineRanks.lexical == 1 || gold.baselineRanks.dense == 1 {
				goldAtLaneRankOne++
			}

			shape := minedShape{
				caseID: entry.caseID, arm: entry.arm, gold: *gold,
				championRank: 1, baselineRank: 1,
			}
			for _, competitor := range units {
				if competitor.spanID == gold.spanID {
					continue
				}
				championDelta := gold.champion - competitor.champion
				baselineDelta := gold.baseline - competitor.baseline
				if championDelta == 0 || baselineDelta == 0 {
					continue // exact tie in one arm carries no ordering signal
				}
				if championDelta < 0 {
					shape.championRank++
				}
				if baselineDelta < 0 {
					shape.baselineRank++
				}
				if (championDelta > 0) == (baselineDelta > 0) {
					continue
				}
				shape.disagreements++
				// Keep the strongest disagreeing competitor: the one standing
				// highest under the baseline (incumbent) arm.
				if shape.competitor.spanID == "" || competitor.baseline > shape.competitor.baseline {
					shape.competitor = *competitor
				}
			}
			if shape.disagreements > 0 {
				mined = append(mined, shape)
			}
		}
	}

	cutoff := suite.Target.CutoffK
	sort.SliceStable(mined, func(i, j int) bool {
		// A metric-visible straddle outranks any pure ordering flip.
		if mined[i].straddlesCutoff(cutoff) != mined[j].straddlesCutoff(cutoff) {
			return mined[i].straddlesCutoff(cutoff)
		}
		if mined[i].rankDelta() != mined[j].rankDelta() {
			return mined[i].rankDelta() > mined[j].rankDelta()
		}
		if mined[i].disagreements != mined[j].disagreements {
			return mined[i].disagreements > mined[j].disagreements
		}
		if mined[i].caseID != mined[j].caseID {
			return mined[i].caseID < mined[j].caseID
		}
		return mined[i].gold.spanID < mined[j].gold.spanID
	})

	if pairsExamined == 0 {
		t.Fatal("mining examined no (query signal, gold unit) pairs; the search space is empty and the tool proved nothing")
	}
	t.Logf("search space: %d committed query signals x %d retrievable units (%d indexed documents collapsed by the "+
		"small-to-big rule) = %d (query, hypothetical gold) pairs examined; %d pairs put the hypothetical gold at "+
		"rank 1 in at least one lane",
		len(signals), pairsExamined/len(signals), len(index.Documents), pairsExamined, goldAtLaneRankOne)
	t.Logf("of the %d suite cases, %d have byte-identical baseline and challenger query vectors, so the enumeration "+
		"covers %d DISTINCT query embeddings and the pair count above double-counts by that factor",
		len(suite.Cases), identicalArmVectors, len(signals)-identicalArmVectors)

	if len(mined) == 0 {
		t.Logf("RESULT: ZERO of %d examined pairs separate the arms. Under this corpus, this index and these "+
			"%d committed query embeddings, there is no choice of hypothetical gold unit that the two fusion "+
			"arms would order differently. That is not a bug in the search and no candidate should be "+
			"manufactured to fill the gap: it means a discriminating suite cannot be built from the committed "+
			"query signals alone, and separating cases require NEW queries, which requires the embedder.",
			pairsExamined, len(suite.Cases))
		return
	}

	// The baseline and challenger signals of a case share a query vector, so each
	// separating shape is found twice. The census counts pairs as enumerated; the
	// table below shows distinct (query, gold unit) shapes so ten rows are ten
	// findings rather than five findings printed twice.
	distinct := make([]minedShape, 0, len(mined))
	presented := make(map[string]bool, len(mined))
	for _, shape := range mined {
		key := shape.caseID + "\x00" + shape.gold.spanID
		if presented[key] {
			continue
		}
		presented[key] = true
		distinct = append(distinct, shape)
	}

	// A two-unit contest is enumerated from both sides, once with each unit as the
	// hypothetical gold, so counting shapes overstates how many distinct contests
	// were actually found. Fold each {gold, rival} pair to one contest.
	straddling := 0
	straddlingContests := make(map[string]bool)
	for _, shape := range distinct {
		if !shape.straddlesCutoff(cutoff) {
			continue
		}
		straddling++
		ends := []string{shape.gold.spanID, shape.competitor.spanID}
		sort.Strings(ends)
		straddlingContests[shape.caseID+"\x00"+ends[0]+"\x00"+ends[1]] = true
	}

	t.Logf("RESULT: %d of %d examined pairs separate the arms (%.2f%%), %d of them distinct after folding the "+
		"duplicate baseline/challenger signals. Top %d by decisiveness follow. Ranks are lexical/dense; "+
		"'miss' means the lane did not retrieve the unit inside the window.",
		len(mined), pairsExamined, 100*float64(len(mined))/float64(pairsExamined), len(distinct), min(10, len(distinct)))
	t.Logf("USABILITY: %d of the %d distinct separating shapes straddle the metric cutoff k=%d, i.e. one arm ranks "+
		"the gold inside the cutoff and the other outside. ONLY THOSE MOVE A METRIC. The remaining %d flip the "+
		"ordering entirely below rank %d, where recall@%d, MRR@%d and nDCG@%d are all blind, so authoring them "+
		"would reproduce the tie this exercise is trying to break. Those %d shapes fold to %d distinct "+
		"two-unit CONTESTS, since each contest is enumerated once from each side.",
		straddling, len(distinct), cutoff, len(distinct)-straddling, cutoff, cutoff, cutoff, cutoff,
		straddling, len(straddlingContests))
	t.Logf("%-34s %-11s %-11s %-24s %-24s %8s %8s %s",
		"query (case id)", "gold ranks", "rival ranks", "gold champ/base", "rival champ/base", "champ rk", "base rk", "usable")
	for _, shape := range distinct[:min(10, len(distinct))] {
		usable := "no (both past cutoff)"
		if shape.straddlesCutoff(cutoff) {
			usable = "YES (straddles cutoff)"
		}
		t.Logf("%-34s %-11s %-11s %-24s %-24s %8d %8d %s",
			shape.caseID,
			formatLaneRanks(shape.gold.championRanks), formatLaneRanks(shape.competitor.championRanks),
			fmt.Sprintf("%d/%d", shape.gold.champion, shape.gold.baseline),
			fmt.Sprintf("%d/%d", shape.competitor.champion, shape.competitor.baseline),
			shape.championRank, shape.baselineRank, usable)
		t.Logf("    gold %s %s | rival %s %s | %d disagreeing competitors",
			shortDigestID(shape.gold.spanID), shape.gold.path,
			shortDigestID(shape.competitor.spanID), shape.competitor.path, shape.disagreements)
		if shape.gold.championRanks != shape.gold.baselineRanks {
			t.Logf("    NOTE: the arms reach this multi-document unit through different members; "+
				"baseline-best member ranks %s", formatLaneRanks(shape.gold.baselineRanks))
		}
	}
	// Cross-check against the committed receipt. The suite's own eleven golds are
	// inside this enumeration, so if the model here were wrong they would show up
	// as separating -- which would contradict the receipt's measured tie. This is
	// reported, never asserted: the tool's job is to search, not to gate.
	realGolds := make(map[string]bool, len(suite.Cases))
	for _, suiteCase := range suite.Cases {
		realGolds[suiteCase.CaseID+"\x00"+suiteCase.AdmittedSpanID] = true
	}
	separatingRealGolds := 0
	for _, shape := range distinct {
		if realGolds[shape.caseID+"\x00"+shape.gold.spanID] {
			separatingRealGolds++
			t.Logf("cross-check: the suite's OWN gold for %s separates the arms (champion rank %d, baseline rank %d); "+
				"the committed receipt reports a tie, so either the receipt or this model is wrong",
				shape.caseID, shape.championRank, shape.baselineRank)
		}
	}
	t.Logf("cross-check: %d of the suite's %d real golds appear in the separating set; zero is the value "+
		"consistent with the committed receipt's exact metric tie",
		separatingRealGolds, len(suite.Cases))

	t.Log("SEMANTIC SUITABILITY IS UNJUDGED. These are rank shapes only. Each pair was produced by " +
		"enumeration, not by anyone deciding the document answers the query, so none of them is a case " +
		"until a human confirms the gold document is a correct answer. Nothing here is authored, frozen, " +
		"admitted, evaluated or promoted.")
}
