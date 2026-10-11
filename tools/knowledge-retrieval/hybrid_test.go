package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type hybridTestFixture struct {
	*testFixture
	lexical       BuildResult
	index         LexicalIndex
	dense         DenseVectorArtifact
	densePath     string
	denseHash     string
	hybrid        HybridBuildResult
	fusionProfile FusionProfile
	fusionPath    string
	fusionHash    string
	alphaDocID    string
	semanticDocID string
}

func TestHybridCandidateExecutesDenseFusionAndExternalReranking(t *testing.T) {
	fx := newHybridTestFixture(t)
	if fx.hybrid.Manifest.State != "partial" || fx.hybrid.Manifest.Promotable || fx.hybrid.Manifest.ServingEligible || fx.hybrid.Manifest.CurrentEligible || !fx.hybrid.Manifest.Dense || !fx.hybrid.Manifest.Fusion || !fx.hybrid.Manifest.Reranking || fx.hybrid.Manifest.QualityState != "unevaluated" {
		t.Fatalf("hybrid candidate overclaimed capability: %#v", fx.hybrid.Manifest)
	}
	if !containsString(fx.hybrid.Manifest.MissingCapabilities, "held_out_retrieval_evaluation") || !containsString(fx.hybrid.Manifest.MissingCapabilities, "signed_generation_promotion") {
		t.Fatalf("hybrid candidate hid quality/promotion gates: %#v", fx.hybrid.Manifest.MissingCapabilities)
	}
	if _, err := os.Stat(filepath.Join(fx.outputRoot, "current")); !os.IsNotExist(err) {
		t.Fatalf("candidate-only build created a current pointer: %v", err)
	}
	manifestBytes, err := os.ReadFile(fx.hybrid.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if fx.hybrid.Manifest.FusionProfile != hybridFusionProfile || fx.hybrid.Manifest.FusionProfileID != "" || fx.hybrid.Manifest.FusionProfileSHA256 != "" || fx.hybrid.Manifest.FusionProfilePath != "" || fx.hybrid.Manifest.FusionProfileByteSize != 0 || bytes.Contains(manifestBytes, []byte(`"fusion_profile_id"`)) {
		t.Fatalf("immutable default RRF manifest gained challenger lineage: %s", manifestBytes)
	}

	signals, signalsPath, signalsHash := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{
		fx.alphaDocID: 100, fx.semanticDocID: 900,
	})
	response, err := QueryHybrid(fx.hybridQueryConfig(signalsPath, signalsHash, "alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if response.State != "partial" || response.ResultState != "ok" || response.Promotable || response.ServingEligible || response.CurrentEligible || len(response.Results) != 2 {
		t.Fatalf("hybrid response contract = %#v", response)
	}
	if response.QuerySignalArtifactID != signals.ArtifactID || response.RerankerModelID != signals.RerankerModelID || response.DenseScannedDocuments != 2 || response.RerankedDocuments != 2 {
		t.Fatalf("hybrid execution metadata incomplete: %#v", response)
	}
	if got := lexicalDocumentIdentity(response.Results[0].Evidence); got != fx.semanticDocID {
		t.Fatalf("external reranker did not reorder fused shortlist: got %s want %s", got, fx.semanticDocID)
	}
	if response.Results[0].Score.DenseRank != 1 || response.Results[0].Score.RerankerScore == nil || *response.Results[0].Score.RerankerScore != 900 || response.Results[0].Evidence.RawByteStart == 0 || response.Results[0].Evidence.InstructionPolicy != "forbidden" {
		t.Fatalf("dense/reranker score or exact evidence lost: %#v", response.Results[0])
	}
	if !strings.Contains(response.Results[0].Excerpt, "semantic") || !containsString(response.Results[0].RetrievalPath, "external_reranker_scores") {
		t.Fatalf("hybrid result did not preserve exact evidence/path: %#v", response.Results[0])
	}

	again, err := Hybridize(fx.hybridBuildConfig())
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(fx.hybrid.ManifestPath)
	againBytes, _ := os.ReadFile(again.ManifestPath)
	if again.Manifest.ManifestID != fx.hybrid.Manifest.ManifestID || !bytes.Equal(firstBytes, againBytes) {
		t.Fatal("hybrid candidate changed across immutable object reuse")
	}
}

func TestChampionFusionRequiresExactCallerPinAndRetainsBothLanes(t *testing.T) {
	fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
	fx.enableChampionFusion(t, 2, 2)
	signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{
		fx.alphaDocID: 0, fx.semanticDocID: 0,
	})
	disableReranking(&signals)
	hash := writeResealedSignals(t, path, &signals)
	config := fx.hybridQueryConfig(path, hash, "alpha")
	config.RerankWindow = 0

	missingPin := config
	missingPin.FusionProfilePath = ""
	missingPin.FusionProfileHash = ""
	response, err := QueryHybrid(missingPin)
	if err != nil || response.ErrorCode != "fusion_profile_pin_missing" || len(response.Results) != 0 {
		t.Fatalf("challenger executed without caller pin: response=%#v err=%v", response, err)
	}

	first, err := QueryHybrid(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := QueryHybrid(config)
	if err != nil {
		t.Fatal(err)
	}
	if !canonicalEqual(first, second) {
		t.Fatal("challenger response changed across deterministic replay")
	}
	if first.ResultState != "ok" || first.FusionProfile != championFusionProfile || first.FusionProfileID != fx.fusionProfile.ProfileID || first.FusionObservation == nil || !first.FusionObservation.AllChampionsRetained || first.FusionObservation.UniqueChampionCount != 2 || first.FusionObservation.RetainedChampionCount != 2 {
		t.Fatalf("challenger did not retain or expose both lane champions: %#v", first)
	}
	if len(first.FusionObservation.LaneChampions) != 2 || first.FusionObservation.LaneChampions[0].Lane != "lexical" || first.FusionObservation.LaneChampions[1].Lane != "dense" {
		t.Fatalf("lane-champion observation is not canonical: %#v", first.FusionObservation)
	}
	for _, hit := range first.Results {
		if !containsString(hit.RetrievalPath, "bounded_lane_champion_rank_sum") || containsString(hit.RetrievalPath, "reciprocal_rank_fusion") {
			t.Fatalf("challenger result reported the wrong execution path: %#v", hit)
		}
	}
}

func TestChampionFusionFailsClosedOnMissingLaneMixedLineageAndWindowDrift(t *testing.T) {
	t.Run("missing lexical lane", func(t *testing.T) {
		fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
		fx.enableChampionFusion(t, 2, 2)
		signals, path, _ := fx.writeSignals(t, "unmatched", []int16{23_170, 23_170}, map[string]int64{})
		disableReranking(&signals)
		hash := writeResealedSignals(t, path, &signals)
		config := fx.hybridQueryConfig(path, hash, "unmatched")
		config.RerankWindow = 0
		response, err := QueryHybrid(config)
		if err != nil || response.ErrorCode != "fusion_lane_missing" || len(response.Results) != 0 {
			t.Fatalf("missing lane did not fail closed: response=%#v err=%v", response, err)
		}
	})

	t.Run("mixed dense lineage", func(t *testing.T) {
		fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
		profileCore := fx.championFusionProfileCore(2, 2)
		profileCore.DenseModelRevision = "revision:other-embedding"
		profilePath := filepath.Join(fx.root, "mixed-fusion-profile-core.json")
		writeCanonical(t, profilePath, profileCore)
		_, sealedPath, err := MaterializeFusionProfile(profilePath, fx.outputRoot)
		if err != nil {
			t.Fatal(err)
		}
		config := fx.hybridBuildConfig()
		config.FusionProfilePath = sealedPath
		config.FusionProfileHash = fileDigest(sealedPath)
		if _, err := Hybridize(config); err == nil || !strings.Contains(err.Error(), "mixes dense lineage") {
			t.Fatalf("mixed dense profile was accepted: %v", err)
		}
	})

	t.Run("window drift", func(t *testing.T) {
		fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
		fx.enableChampionFusion(t, 2, 2)
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{})
		disableReranking(&signals)
		hash := writeResealedSignals(t, path, &signals)
		config := fx.hybridQueryConfig(path, hash, "alpha")
		config.Limit = 1
		config.RerankWindow = 0
		response, err := QueryHybrid(config)
		if err != nil || response.ErrorCode != "fusion_profile_window_mismatch" {
			t.Fatalf("caller window drift was accepted: response=%#v err=%v", response, err)
		}
	})

	t.Run("running scorer artifact mismatch", func(t *testing.T) {
		fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
		core := fx.championFusionProfileCore(2, 2)
		core.ScorerArtifactSHA256 = "sha256:" + strings.Repeat("5", 64)
		corePath := filepath.Join(fx.root, "wrong-scorer-fusion-profile-core.json")
		writeCanonical(t, corePath, core)
		profile, profilePath, err := MaterializeFusionProfile(corePath, fx.outputRoot)
		if err != nil {
			t.Fatal(err)
		}
		fx.fusionProfile, fx.fusionPath, fx.fusionHash = profile, profilePath, fileDigest(profilePath)
		fx.hybrid, err = Hybridize(fx.hybridBuildConfig())
		if err != nil {
			t.Fatal(err)
		}
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{})
		disableReranking(&signals)
		hash := writeResealedSignals(t, path, &signals)
		config := fx.hybridQueryConfig(path, hash, "alpha")
		config.RerankWindow = 0
		response, err := QueryHybrid(config)
		if err != nil || response.ErrorCode != "fusion_scorer_artifact_mismatch" || len(response.Results) != 0 {
			t.Fatalf("unbound running scorer executed: response=%#v err=%v", response, err)
		}
	})

	t.Run("lane suppression", func(t *testing.T) {
		fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
		core := fx.championFusionProfileCore(2, 2)
		core.DenseWeight = 0
		corePath := filepath.Join(fx.root, "suppressed-lane-fusion-profile-core.json")
		writeCanonical(t, corePath, core)
		if _, _, err := MaterializeFusionProfile(corePath, fx.outputRoot); err == nil || !strings.Contains(err.Error(), "arithmetic contract") {
			t.Fatalf("caller-selected lane suppression was accepted: %v", err)
		}
	})

	t.Run("partial build pin", func(t *testing.T) {
		fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
		config := fx.hybridBuildConfig()
		config.FusionProfilePath = filepath.Join(fx.root, "profile.json")
		if _, err := Hybridize(config); err == nil || !strings.Contains(err.Error(), "both be present") {
			t.Fatalf("partial fusion profile pin was accepted: %v", err)
		}
	})
}

// tiedFusionRanking queries the fixture with a query and dense vector chosen so
// both documents carry the identical RRF fusion score: each is champion of one
// lane and runner-up in the other. It returns the ranked SpanIDs, the ranked
// document IDs and the reported ties.
func tiedFusionRanking(t *testing.T, fx *hybridTestFixture) ([]string, []string, []FusionScoreTie) {
	t.Helper()
	// "alpha semantic" matches one distinct term in each two-token document, so
	// the lexical lane ties exactly and resolves on ascending SpanID. Point the
	// dense lane at whichever document the lexical lane placed second.
	spanByDocument := make(map[string]string, len(fx.index.Documents))
	for _, document := range fx.index.Documents {
		spanByDocument[document.DocumentID] = document.Evidence.SpanID
	}
	vector := []int16{denseQuantizationScale, 0}
	if spanByDocument[fx.alphaDocID] < spanByDocument[fx.semanticDocID] {
		vector = []int16{0, denseQuantizationScale}
	}
	signals, path, _ := fx.writeSignals(t, "alpha semantic", vector, nil)
	disableReranking(&signals)
	hash := writeResealedSignals(t, path, &signals)
	config := fx.hybridQueryConfig(path, hash, "alpha semantic")
	config.RerankWindow = 0
	response, err := QueryHybrid(config)
	if err != nil || response.ResultState != "ok" {
		t.Fatalf("tied fusion query failed: state=%s code=%s err=%v", response.ResultState, response.ErrorCode, err)
	}
	spans := make([]string, 0, len(response.Results))
	for _, hit := range response.Results {
		spans = append(spans, hit.Evidence.SpanID)
	}
	documents := make([]string, 0, len(fx.index.Documents))
	for _, document := range fx.index.Documents {
		documents = append(documents, document.DocumentID)
	}
	return spans, documents, response.ScoreTies
}

// TestFusionTieBreakIsStableAcrossReadmission is the regression proof for the
// determinism defect: the lexical-document identity digests the whole
// EvidenceRef including the admission policy's fresh_until, so re-admitting an
// unchanged corpus renumbers and physically reorders every document. Ranking
// must not move. The property is universally quantified over admission
// policies, so it is asserted over a sweep rather than a single re-admission.
func TestFusionTieBreakIsStableAcrossReadmission(t *testing.T) {
	freshUntils := []string{
		"2026-07-17T00:00:00Z", "2026-07-19T00:00:00Z", "2026-07-23T00:00:00Z", "2026-08-02T00:00:00Z",
		"2026-08-14T00:00:00Z", "2026-09-05T00:00:00Z", "2026-10-16T00:00:00Z", "2026-10-18T00:00:00Z",
	}
	var expectedSpans []string
	seenDocumentOrders := make(map[string]struct{})
	for _, freshUntil := range freshUntils {
		fx := newHybridTestFixtureForAdmission(t, "", freshUntil)
		spans, documents, ties := tiedFusionRanking(t, fx)
		seenDocumentOrders[strings.Join(documents, ",")] = struct{}{}
		if len(ties) != 1 || len(ties[0].SpanIDs) != 2 || ties[0].FirstRank != 1 {
			t.Fatalf("fresh_until %s: expected one reported two-way rank-1 tie, got %#v", freshUntil, ties)
		}
		if expectedSpans == nil {
			expectedSpans = spans
			continue
		}
		if !reflect.DeepEqual(spans, expectedSpans) {
			t.Fatalf("fresh_until %s reordered a tied ranking: %v != %v", freshUntil, spans, expectedSpans)
		}
	}
	// Guards the test itself: if re-admission stopped renumbering documents the
	// sweep above would prove nothing, because every arm would be byte-identical.
	if len(seenDocumentOrders) < 2 {
		t.Fatalf("re-admission no longer renumbers documents, so this test cannot detect the defect (%d distinct orders)", len(seenDocumentOrders))
	}
}

// TestFusionTieBreakIgnoresDocumentIdentity pins the rule directly: two
// aggregates tied on fusion score order by ascending SpanID, and flipping only
// the assigned document identities must not move them.
func TestFusionTieBreakIgnoresDocumentIdentity(t *testing.T) {
	left := &hybridAggregate{documentID: "lexical-document:zzz", spanID: "evidence-span:aaa", fusionScore: 32522}
	right := &hybridAggregate{documentID: "lexical-document:aaa", spanID: "evidence-span:zzz", fusionScore: 32522}
	if !fusionAggregateBetter(left, right) || fusionAggregateBetter(right, left) {
		t.Fatal("tied aggregates did not order by ascending canonical SpanID")
	}
	left.documentID, right.documentID = right.documentID, left.documentID
	if !fusionAggregateBetter(left, right) || fusionAggregateBetter(right, left) {
		t.Fatal("tie-break moved when only the assigned document identities changed")
	}
	right.fusionScore = 32523
	if fusionAggregateBetter(left, right) {
		t.Fatal("fusion score stopped dominating the tie-break")
	}
}

func TestChampionFusionCheckedArithmeticAndCanonicalSpanTieBreak(t *testing.T) {
	fx := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
	core := fx.championFusionProfileCore(3, 2)
	profile, err := sealFusionProfile(core)
	if err != nil {
		t.Fatal(err)
	}
	lexicalChampion := &hybridAggregate{documentID: "z-document", spanID: "span:z", lexicalRank: 1}
	denseChampion := &hybridAggregate{documentID: "a-document", spanID: "span:a", denseRank: 1}
	intersection := &hybridAggregate{documentID: "m-document", spanID: "span:m", lexicalRank: 2, denseRank: 2}
	for _, aggregate := range []*hybridAggregate{lexicalChampion, denseChampion, intersection} {
		if aggregate.lexicalRank > 0 {
			aggregate.fusionScore, err = fusionLaneScore(&profile, "lexical", aggregate.lexicalRank)
			if err != nil {
				t.Fatal(err)
			}
		}
		if aggregate.denseRank > 0 {
			dense, scoreErr := fusionLaneScore(&profile, "dense", aggregate.denseRank)
			if scoreErr != nil {
				t.Fatal(scoreErr)
			}
			aggregate.fusionScore, err = checkedAddInt64(aggregate.fusionScore, dense)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	fused := []*hybridAggregate{intersection, lexicalChampion, denseChampion}
	sort.Slice(fused, func(i, j int) bool { return fusionAggregateBetter(fused[i], fused[j]) })
	if fused[0].spanID != "span:a" || fused[1].spanID != "span:z" || fused[2].spanID != "span:m" {
		t.Fatalf("champion preservation or canonical SpanID tie-break failed: %v, %v, %v", fused[0].spanID, fused[1].spanID, fused[2].spanID)
	}
	observation, err := buildFusionObservation(profile, fused, lexicalChampion.spanID, denseChampion.spanID, 2)
	if err != nil || !observation.AllChampionsRetained || observation.RetainedChampionCount != 2 {
		t.Fatalf("champion retention proof failed: observation=%#v err=%v", observation, err)
	}

	overflow := profile
	overflow.ArithmeticScale = math.MaxInt64
	if _, err := fusionLaneScore(&overflow, "lexical", 1); err == nil {
		t.Fatal("fusion score overflow was accepted")
	}
}

func TestHybridConditionalRerankingCanBeSkipped(t *testing.T) {
	fx := newHybridTestFixture(t)
	signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{
		fx.alphaDocID: 100, fx.semanticDocID: 900,
	})
	disableReranking(&signals)
	hash := writeResealedSignals(t, path, &signals)
	config := fx.hybridQueryConfig(path, hash, "alpha")
	config.RerankWindow = 0

	response, err := QueryHybrid(config)
	if err != nil {
		t.Fatal(err)
	}
	if response.ResultState != "ok" || response.Reranking || response.RerankedDocuments != 0 || response.RerankerModelID != "" || len(response.Results) != 2 {
		t.Fatalf("fusion-only conditional path failed: %#v", response)
	}
	for _, hit := range response.Results {
		if !containsString(hit.RetrievalPath, "reciprocal_rank_fusion") || containsString(hit.RetrievalPath, "external_reranker_scores") || hit.Score.RerankerScore != nil || hit.Score.RerankerScale != nil {
			t.Fatalf("disabled reranking leaked scorer semantics: %#v", hit)
		}
	}
}

func TestHybridCandidatePreservesStandingSourceAdmission(t *testing.T) {
	fx := newHybridTestFixture(t)
	policyDigest := "sha256:" + strings.Repeat("6", 64)
	fx.lexical.Manifest.SourceAdmissionMethod = "standing_policy"
	fx.lexical.Manifest.SourceAdmissionPolicySHA256 = policyDigest
	fx.lexical.Manifest.SourceAdmissionPolicyID = "source-admission-policy:" + policyDigest
	coreBytes, _ := json.Marshal(fx.lexical.Manifest.CandidateManifestCore)
	payloadDigest := digestBytes(coreBytes)
	fx.lexical.Manifest.ManifestPayloadSHA256 = payloadDigest
	fx.lexical.Manifest.ManifestID = "retrieval-candidate:" + payloadDigest
	fx.lexical.ManifestPath = filepath.Join(fx.root, "standing-lexical-candidate.json")
	writeCanonical(t, fx.lexical.ManifestPath, fx.lexical.Manifest)
	fx.dense.LexicalCandidateID = fx.lexical.Manifest.ManifestID
	fx.resealDense(t)

	result, err := Hybridize(fx.hybridBuildConfig())
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.SourceAdmissionMethod != fx.lexical.Manifest.SourceAdmissionMethod ||
		result.Manifest.SourceAdmissionPolicyID != fx.lexical.Manifest.SourceAdmissionPolicyID ||
		result.Manifest.SourceAdmissionPolicySHA256 != fx.lexical.Manifest.SourceAdmissionPolicySHA256 {
		t.Fatalf("hybrid candidate lost standing source admission: %+v", result.Manifest.HybridCandidateManifestCore)
	}
}

func TestHybridRerankerZeroScoreRemainsExplicit(t *testing.T) {
	fx := newHybridTestFixture(t)
	_, path, hash := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{
		fx.alphaDocID: 0, fx.semanticDocID: 0,
	})
	response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range response.Results {
		if hit.Score.RerankerScore == nil || *hit.Score.RerankerScore != 0 || hit.Score.RerankerScale == nil {
			t.Fatalf("valid zero reranker score was erased: %#v", hit.Score)
		}
	}
}

func TestHybridTieOrderingIsDeterministic(t *testing.T) {
	fx := newHybridTestFixture(t)
	_, signalsPath, signalsHash := fx.writeSignals(t, "unmatched", []int16{23_170, 23_170}, map[string]int64{
		fx.alphaDocID: 500, fx.semanticDocID: 500,
	})
	config := fx.hybridQueryConfig(signalsPath, signalsHash, "unmatched")
	first, err := QueryHybrid(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := QueryHybrid(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Results) != 2 || len(second.Results) != 2 {
		t.Fatalf("tie query returned wrong result count: %#v", first)
	}
	// The declared tie-break is the canonical span id, ascending.
	firstSpans := []string{first.Results[0].Evidence.SpanID, first.Results[1].Evidence.SpanID}
	secondSpans := []string{second.Results[0].Evidence.SpanID, second.Results[1].Evidence.SpanID}
	if !sort.StringsAreSorted(firstSpans) || firstSpans[0] != secondSpans[0] || firstSpans[1] != secondSpans[1] {
		t.Fatalf("tie order is not stable canonical span-ID order: first=%v second=%v", firstSpans, secondSpans)
	}
}

func TestHybridWholeDocumentPinsRejectSelfConsistentReplacement(t *testing.T) {
	t.Run("dense artifact", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		originalHash := fx.denseHash
		fx.dense.ModelRevision = "replacement-revision"
		fx.resealDense(t)
		config := fx.hybridBuildConfig()
		config.DenseArtifactHash = originalHash
		if _, err := Hybridize(config); err == nil || !strings.Contains(err.Error(), "caller pin") {
			t.Fatalf("self-consistent dense replacement accepted: %v", err)
		}
	})

	t.Run("query signals", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		signals, signalsPath, signalsHash := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{
			fx.alphaDocID: 100, fx.semanticDocID: 900,
		})
		signals.Scores[0].Score++
		resealQuerySignals(&signals)
		writeCanonical(t, signalsPath, signals)
		response, err := QueryHybrid(fx.hybridQueryConfig(signalsPath, signalsHash, "alpha"))
		if err != nil {
			t.Fatal(err)
		}
		if response.ErrorCode != "query_signal_document_mismatch" || response.ResultState != "backend_unavailable" {
			t.Fatalf("self-consistent query replacement accepted: %#v", response)
		}
	})
}

func TestHybridRejectsMismatchesDuplicatesMissingScoresAndBounds(t *testing.T) {
	t.Run("model revision mismatch", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		signals.DenseModelRevision = "wrong-revision"
		hash := writeResealedSignals(t, path, &signals)
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("model mismatch did not fail closed: response=%#v err=%v", response, err)
		}
	})

	t.Run("tokenizer mismatch", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		signals.DenseTokenizerSHA256 = "sha256:" + strings.Repeat("f", 64)
		hash := writeResealedSignals(t, path, &signals)
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("tokenizer mismatch did not fail closed: response=%#v err=%v", response, err)
		}
	})

	t.Run("quantization mismatch", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		signals.QuantizationScale--
		hash := writeResealedSignals(t, path, &signals)
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("quantization mismatch did not fail closed: response=%#v err=%v", response, err)
		}
	})

	t.Run("duplicate score", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		signals.Scores[1].DocumentID = signals.Scores[0].DocumentID
		hash := writeResealedSignals(t, path, &signals)
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("duplicate score did not fail closed: response=%#v err=%v", response, err)
		}
	})

	t.Run("duplicate dense document", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		fx.dense.Documents[1].DocumentID = fx.dense.Documents[0].DocumentID
		fx.resealDense(t)
		if _, err := Hybridize(fx.hybridBuildConfig()); err == nil || !strings.Contains(err.Error(), "strict document-ID order") {
			t.Fatalf("duplicate dense document was accepted: %v", err)
		}
	})

	t.Run("missing dense document", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		fx.dense.Documents = fx.dense.Documents[:1]
		fx.dense.DocumentCount = 1
		fx.resealDense(t)
		if _, err := Hybridize(fx.hybridBuildConfig()); err == nil || !strings.Contains(err.Error(), "dimensions or counts") {
			t.Fatalf("missing dense document was accepted: %v", err)
		}
	})

	t.Run("missing rerank score", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		_, path, hash := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1})
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "reranker_window_incomplete" {
			t.Fatalf("incomplete rerank window did not fail closed: response=%#v err=%v", response, err)
		}
	})

	t.Run("reranking route mismatch", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		_, path, hash := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		config := fx.hybridQueryConfig(path, hash, "alpha")
		config.RerankWindow = 0
		response, err := QueryHybrid(config)
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("query artifact reranking decision was not bound: response=%#v err=%v", response, err)
		}
	})

	t.Run("dense dimension resource bound", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		config := fx.hybridBuildConfig()
		config.MaxDenseDimension = 1
		if _, err := Hybridize(config); err == nil || !strings.Contains(err.Error(), "dimensions") {
			t.Fatalf("dense dimension bound was not enforced: %v", err)
		}
	})

	t.Run("uppercase model digest", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		fx.dense.ModelArtifactSHA256 = "sha256:" + strings.Repeat("A", 64)
		fx.resealDense(t)
		if _, err := Hybridize(fx.hybridBuildConfig()); err == nil || !strings.Contains(err.Error(), "model identity") {
			t.Fatalf("non-canonical uppercase model digest was accepted: %v", err)
		}
	})

	t.Run("non-unit dense vector", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		fx.dense.Documents[0].Values = []int16{100, 0}
		fx.resealDense(t)
		if _, err := Hybridize(fx.hybridBuildConfig()); err == nil || !strings.Contains(err.Error(), "normalization contract") {
			t.Fatalf("falsely normalized dense vector was accepted: %v", err)
		}
	})

	t.Run("asymmetric minimum dense coordinate", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		fx.dense.Documents[0].Values = []int16{-32_768, 0}
		fx.resealDense(t)
		if _, err := Hybridize(fx.hybridBuildConfig()); err == nil || !strings.Contains(err.Error(), "symmetric quantization") {
			t.Fatalf("asymmetric int16 minimum was accepted: %v", err)
		}
	})

	t.Run("zero query vector", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		_, path, hash := fx.writeSignals(t, "alpha", []int16{0, 0}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("zero query vector was accepted: response=%#v err=%v", response, err)
		}
	})

	t.Run("non-unit query vector", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		_, path, hash := fx.writeSignals(t, "alpha", []int16{0, 100}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("falsely normalized query vector was accepted: response=%#v err=%v", response, err)
		}
	})

	t.Run("asymmetric minimum query coordinate", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		_, path, hash := fx.writeSignals(t, "alpha", []int16{0, -32_768}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("asymmetric int16 minimum query coordinate was accepted: response=%#v err=%v", response, err)
		}
	})

	t.Run("uppercase reranker digest", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		signals.RerankerModelArtifactSHA256 = "sha256:" + strings.Repeat("A", 64)
		hash := writeResealedSignals(t, path, &signals)
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("non-canonical uppercase reranker digest was accepted: response=%#v err=%v", response, err)
		}
	})

	t.Run("reranker score overflow", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		signals, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		signals.Scores[0].Score = maxRerankerScore + 1
		hash := writeResealedSignals(t, path, &signals)
		response, err := QueryHybrid(fx.hybridQueryConfig(path, hash, "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("score overflow was accepted: response=%#v err=%v", response, err)
		}
	})

	t.Run("non-integer score", func(t *testing.T) {
		fx := newHybridTestFixture(t)
		_, path, _ := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.Replace(data, []byte(`"score": 1`), []byte(`"score": 1e999`), 1)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		response, err := QueryHybrid(fx.hybridQueryConfig(path, digestBytes(data), "alpha"))
		if err != nil || response.ErrorCode != "query_signal_invalid" {
			t.Fatalf("non-integer/non-finite score was accepted: response=%#v err=%v", response, err)
		}
	})
}

func TestDenseDotProductUsesCheckedInt64Arithmetic(t *testing.T) {
	left := []int16{denseQuantizationScale, -denseQuantizationScale}
	right := []int16{denseQuantizationScale, denseQuantizationScale}
	dot, err := denseDotProduct(left, right)
	if err != nil || dot != 0 {
		t.Fatalf("bounded dense dot product = %d, %v", dot, err)
	}
	if _, err := denseDotProduct(left, right[:1]); err == nil {
		t.Fatal("mismatched dense dimensions were accepted")
	}
	maxLeft := make([]int16, hardMaxDenseDimension)
	maxRight := make([]int16, hardMaxDenseDimension)
	for position := range maxLeft {
		maxLeft[position] = denseQuantizationScale
		maxRight[position] = denseQuantizationScale
	}
	dot, err = denseDotProduct(maxLeft, maxRight)
	want := maxDenseProduct * int64(hardMaxDenseDimension)
	if err != nil || dot != want {
		t.Fatalf("hard-bound dense dot product = %d, %v; want %d", dot, err, want)
	}
}

func TestHybridQueryRechecksCurrentPolicyBeforeSignals(t *testing.T) {
	fx := newHybridTestFixture(t)
	_, signalsPath, signalsHash := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
	fx.policy.Tombstone = true
	fx.policy.DeletionState = "deleted"
	fx.resealPolicy(t)
	response, err := QueryHybrid(fx.hybridQueryConfig(signalsPath, signalsHash, "alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if response.ResultState != "forbidden" || response.ErrorCode != "source_deleted_or_tombstoned" || len(response.Results) != 0 {
		t.Fatalf("hybrid query bypassed current deletion policy: %#v", response)
	}
}

func TestHybridFinalPolicyRecheckRejectsMidQueryRevocation(t *testing.T) {
	fx := newHybridTestFixture(t)
	_, signalsPath, signalsHash := fx.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 1, fx.semanticDocID: 2})
	config := fx.hybridQueryConfig(signalsPath, signalsHash, "alpha")
	loaded, code := loadHybridCandidate(config)
	if code != "" {
		t.Fatal(code)
	}
	fx.policy.Tombstone = true
	fx.policy.DeletionState = "deleted"
	fx.resealPolicy(t)
	config.AdmissionPolicyHash = fx.policyHash
	resultState, _, code := recheckHybridAdmissionPolicy(config, loaded.lexical)
	if resultState != "forbidden" || code != "source_deleted_or_tombstoned" {
		t.Fatalf("final policy recheck accepted revocation: state=%s code=%s", resultState, code)
	}
}

func newHybridTestFixture(t *testing.T) *hybridTestFixture {
	return newHybridTestFixtureForProfile(t, "")
}

func newHybridTestFixtureForProfile(t *testing.T, lexicalProfile string) *hybridTestFixture {
	return newHybridTestFixtureForAdmission(t, lexicalProfile, "2026-07-17T00:00:00Z")
}

// newHybridTestFixtureForAdmission builds the fixture corpus under one exact
// admission freshness window. Only fresh_until varies, which is precisely what
// a re-admission changes, so two fixtures differing in it are the same corpus
// admitted under two policies.
func newHybridTestFixtureForAdmission(t *testing.T, lexicalProfile, freshUntil string) *hybridTestFixture {
	t.Helper()
	first := []byte("alpha lexical\n")
	second := []byte("beta semantic\n")
	data := append(append([]byte(nil), first...), second...)
	base := newTestFixture(t, data, freshUntil)
	replaceFixtureSpans(t, base, [][]byte{first, second})
	buildConfig := base.buildConfig(base.outputRoot)
	buildConfig.LexicalProfile = lexicalProfile
	lexical, err := Build(buildConfig)
	if err != nil {
		t.Fatal(err)
	}
	index, err := readBoundLexicalIndex(base.outputRoot, lexical.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	fx := &hybridTestFixture{testFixture: base, lexical: lexical, index: index, densePath: filepath.Join(base.root, "dense.json")}
	documents := make([]DenseDocumentVector, 0, len(index.Documents))
	for _, document := range index.Documents {
		vector := []int16{denseQuantizationScale, 0}
		if document.Evidence.RawByteStart != 0 {
			vector = []int16{0, denseQuantizationScale}
			fx.semanticDocID = document.DocumentID
		} else {
			fx.alphaDocID = document.DocumentID
		}
		documents = append(documents, DenseDocumentVector{DocumentID: document.DocumentID, Values: vector})
	}
	fx.dense = DenseVectorArtifact{DenseVectorArtifactCore: DenseVectorArtifactCore{
		SchemaVersion: retrievalSchemaVersion, ArtifactKind: "external_dense_document_vectors",
		State: "candidate_input", AuthorityState: "untrusted_candidate_input",
		LexicalCandidateID: lexical.Manifest.ManifestID, LexicalIndexID: lexical.Manifest.LexicalIndexID,
		EvidenceManifestID: lexical.Manifest.EvidenceManifestID, ModelID: "model:test-embedding",
		ModelRevision: "revision:test-embedding-1", ModelArtifactSHA256: "sha256:" + strings.Repeat("1", 64),
		TokenizerID: "tokenizer:test-embedding", TokenizerSHA256: "sha256:" + strings.Repeat("2", 64),
		EmbeddingProfile: "test-asymmetric-embedding@1.0.0", DocumentInstruction: "Represent this technical evidence span for retrieval.",
		VectorEncoding: denseVectorEncoding, Normalization: denseVectorNormalization, QuantizationScale: denseQuantizationScale,
		Dimension: 2, DocumentCount: len(documents), Documents: documents,
	}}
	fx.resealDense(t)
	hybrid, err := Hybridize(fx.hybridBuildConfig())
	if err != nil {
		t.Fatal(err)
	}
	fx.hybrid = hybrid
	return fx
}

func replaceFixtureSpans(t *testing.T, fx *testFixture, chunks [][]byte) {
	t.Helper()
	file := fx.evidence.Files[0]
	offset := 0
	spans := make([]EvidenceSpan, 0, len(chunks))
	unique := make(map[string]int64)
	for ordinal, chunk := range chunks {
		digest := digestBytes(chunk)
		relative := normalizedObjectRelativePath(digest)
		payloadPath := filepath.Join(fx.evidenceRoot, filepath.FromSlash(relative))
		if _, err := os.Lstat(payloadPath); errors.Is(err, os.ErrNotExist) {
			writeTestFile(t, payloadPath, chunk, 0o444)
		} else if err != nil {
			t.Fatal(err)
		}
		span := EvidenceSpan{
			Ordinal: ordinal, Kind: "document", HeadingBreadcrumb: []string{},
			RawByteStart: int64(offset), RawByteEnd: int64(offset + len(chunk)),
			PayloadSHA256: digest, PayloadID: "normalized:" + digest, ObjectPath: relative,
			ByteSize: int64(len(chunk)), TrustEnvelopeID: fx.evidence.TrustEnvelope.EnvelopeID,
		}
		raw, _ := os.ReadFile(filepath.Join(fx.rawRoot, filepath.FromSlash(fx.snapshot.Files[0].ObjectPath)))
		span.RawLineStart, span.RawLineEnd = spanLines(raw, offset, offset+len(chunk))
		span.SpanID = spanIdentity(file.OccurrenceID, file.ParserVersion, file.ProfileVersion, span)
		spans = append(spans, span)
		unique[digest] = int64(len(chunk))
		offset += len(chunk)
	}
	file.Spans = spans
	fx.evidence.Files[0] = file
	fx.evidence.SpanCount = len(spans)
	fx.evidence.UniquePayloadCount = len(unique)
	fx.evidence.UniquePayloadByteSize = 0
	for _, size := range unique {
		fx.evidence.UniquePayloadByteSize += size
	}
	fx.resealEvidence(t)
	fx.policy.EvidenceManifestID = fx.evidence.ManifestID
	fx.resealPolicy(t)
	fx.rewriteVerifier(t, true)
}

func (fx *hybridTestFixture) resealDense(t *testing.T) {
	t.Helper()
	coreBytes, _ := json.Marshal(fx.dense.DenseVectorArtifactCore)
	digest := digestBytes(coreBytes)
	fx.dense.ArtifactPayloadSHA256 = digest
	fx.dense.ArtifactID = "dense-vector-artifact:" + digest
	writeCanonical(t, fx.densePath, fx.dense)
	data, _ := os.ReadFile(fx.densePath)
	fx.denseHash = digestBytes(data)
}

func (fx *hybridTestFixture) hybridBuildConfig() HybridBuildConfig {
	return HybridBuildConfig{
		CandidatePath: fx.lexical.ManifestPath, CandidateHash: fileDigest(fx.lexical.ManifestPath),
		StoreRoot: fx.outputRoot, DenseArtifactPath: fx.densePath, DenseArtifactHash: fx.denseHash,
		FusionProfilePath: fx.fusionPath, FusionProfileHash: fx.fusionHash,
		MaxDenseDocuments: 100, MaxDenseDimension: 32,
	}
}

func (fx *hybridTestFixture) championFusionProfileCore(fusionWindow, resultWindow int) FusionProfileCore {
	runningPath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return FusionProfileCore{
		SchemaVersion: retrievalSchemaVersion, ProfileKind: championFusionProfileKind,
		State: "candidate", AuthorityState: "caller_pinned_candidate_input",
		FusionProfile: championFusionProfile, ScorerID: championFusionScorerID,
		ScorerRevision:         championFusionScorerRevision,
		ScorerArtifactSHA256:   fileDigest(runningPath),
		LexicalCandidateID:     fx.lexical.Manifest.ManifestID,
		LexicalCandidateSHA256: fileDigest(fx.lexical.ManifestPath),
		LexicalProfile:         fx.lexical.Manifest.LexicalProfile,
		LexicalTokenizerID:     fx.lexical.Manifest.LexicalTokenizerID,
		LexicalScorerID:        fx.lexical.Manifest.LexicalScorerID,
		DenseArtifactID:        fx.dense.ArtifactID, DenseArtifactSHA256: fx.denseHash,
		DenseModelID: fx.dense.ModelID, DenseModelRevision: fx.dense.ModelRevision,
		DenseModelArtifactSHA256: fx.dense.ModelArtifactSHA256,
		DenseTokenizerID:         fx.dense.TokenizerID, DenseTokenizerSHA256: fx.dense.TokenizerSHA256,
		EmbeddingProfile: fx.dense.EmbeddingProfile, VectorEncoding: fx.dense.VectorEncoding,
		Normalization: fx.dense.Normalization, QuantizationScale: fx.dense.QuantizationScale,
		Dimension: fx.dense.Dimension, FusionWindow: fusionWindow, ResultWindow: resultWindow,
		RerankWindow: 0, Arithmetic: championFusionArithmetic,
		ArithmeticScale: championFusionScale, LexicalWeight: championFusionLexicalWeight,
		DenseWeight:       championFusionDenseWeight,
		ChampionBonus:     int64(2*fusionWindow) * championFusionScale,
		MissingLanePolicy: championFusionMissingLanePolicy, TieBreak: championFusionTieBreak,
	}
}

func (fx *hybridTestFixture) enableChampionFusion(t *testing.T, fusionWindow, resultWindow int) {
	t.Helper()
	corePath := filepath.Join(fx.root, "fusion-profile-core.json")
	writeCanonical(t, corePath, fx.championFusionProfileCore(fusionWindow, resultWindow))
	profile, profilePath, err := MaterializeFusionProfile(corePath, fx.outputRoot)
	if err != nil {
		t.Fatal(err)
	}
	fx.fusionProfile = profile
	fx.fusionPath = profilePath
	fx.fusionHash = fileDigest(profilePath)
	hybrid, err := Hybridize(fx.hybridBuildConfig())
	if err != nil {
		t.Fatal(err)
	}
	fx.hybrid = hybrid
}

func (fx *hybridTestFixture) writeSignals(t *testing.T, query string, vector []int16, scores map[string]int64) (QuerySignalArtifact, string, string) {
	t.Helper()
	ordered := make([]RerankerDocumentScore, 0, len(scores))
	for documentID, score := range scores {
		ordered = append(ordered, RerankerDocumentScore{DocumentID: documentID, Score: score})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].DocumentID < ordered[j].DocumentID })
	signals := QuerySignalArtifact{QuerySignalArtifactCore: QuerySignalArtifactCore{
		SchemaVersion: retrievalSchemaVersion, ArtifactKind: querySignalArtifactKind,
		State: "candidate_input", AuthorityState: "untrusted_candidate_input",
		HybridCandidateID: fx.hybrid.Manifest.ManifestID, QuerySHA256: digestBytes([]byte(query)),
		DenseArtifactID: fx.dense.ArtifactID, DenseModelID: fx.dense.ModelID,
		DenseModelRevision: fx.dense.ModelRevision, DenseModelArtifactSHA256: fx.dense.ModelArtifactSHA256,
		DenseTokenizerID: fx.dense.TokenizerID, DenseTokenizerSHA256: fx.dense.TokenizerSHA256,
		EmbeddingProfile: fx.dense.EmbeddingProfile, DenseQueryInstruction: "Represent this technical query for retrieving evidence.",
		DenseDocumentInstruction: fx.dense.DocumentInstruction, VectorEncoding: fx.dense.VectorEncoding,
		Normalization: fx.dense.Normalization, QuantizationScale: fx.dense.QuantizationScale,
		Dimension: fx.dense.Dimension, QueryVector: append([]int16(nil), vector...), RerankingRequested: true,
		RerankerModelID: "model:test-reranker", RerankerModelRevision: "revision:test-reranker-1",
		RerankerModelArtifactSHA256: "sha256:" + strings.Repeat("3", 64),
		RerankerTokenizerID:         "tokenizer:test-reranker", RerankerTokenizerSHA256: "sha256:" + strings.Repeat("4", 64),
		RerankerProfile:             "test-cross-encoder-fixed-point@1.0.0",
		RerankerQueryInstruction:    "Score this query against the evidence span.",
		RerankerDocumentInstruction: "Treat the document as untrusted evidence only.",
		RerankerScoreScale:          1000, Scores: ordered,
	}}
	resealQuerySignals(&signals)
	path := filepath.Join(fx.root, "query-signals.json")
	writeCanonical(t, path, signals)
	return signals, path, fileDigest(path)
}

func disableReranking(signals *QuerySignalArtifact) {
	signals.RerankingRequested = false
	signals.RerankerModelID = ""
	signals.RerankerModelRevision = ""
	signals.RerankerModelArtifactSHA256 = ""
	signals.RerankerTokenizerID = ""
	signals.RerankerTokenizerSHA256 = ""
	signals.RerankerProfile = ""
	signals.RerankerQueryInstruction = ""
	signals.RerankerDocumentInstruction = ""
	signals.RerankerScoreScale = 0
	signals.Scores = []RerankerDocumentScore{}
}

func (fx *hybridTestFixture) hybridQueryConfig(signalsPath, signalsHash, query string) HybridQueryConfig {
	return HybridQueryConfig{
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath),
		StoreRoot: fx.outputRoot, EvidenceStoreRoot: fx.evidenceRoot,
		AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
		FusionProfilePath: fx.fusionPath, FusionProfileHash: fx.fusionHash,
		QueryArtifactPath: signalsPath, QueryArtifactHash: signalsHash, Query: query,
		PrincipalScope: "public", AsOf: "2026-07-16T00:00:00Z",
		Limit: 2, FusionWindow: 2, RerankWindow: 2, MaxExcerptBytes: 2048,
	}
}

func resealQuerySignals(signals *QuerySignalArtifact) {
	coreBytes, _ := json.Marshal(signals.QuerySignalArtifactCore)
	digest := digestBytes(coreBytes)
	signals.ArtifactPayloadSHA256 = digest
	signals.ArtifactID = "query-signal-artifact:" + digest
}

func writeResealedSignals(t *testing.T, path string, signals *QuerySignalArtifact) string {
	t.Helper()
	resealQuerySignals(signals)
	writeCanonical(t, path, *signals)
	return fileDigest(path)
}

func fileDigest(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return digestBytes(data)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
