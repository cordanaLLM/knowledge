package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// sharedClosureFixture is a fully self-contained shared-corpus/comparison/
// evaluation-case fixture: one real BM25F-profiled multidomain candidate+index
// (single authority, so it is fast), a real structurally valid dense artifact,
// a real default-RRF baseline hybrid candidate, a real challenger fusion
// profile and its bounded-lane-champion hybrid candidate, and one baseline +
// one challenger query signal per case. Every artifact is written under
// t.TempDir() so `verifyMultidomainSharedCorpusArtifacts` reads real bytes
// exactly like the production CLI does; nothing here calls a network or
// embedding endpoint.
type sharedClosureFixture struct {
	root   string
	base   MultidomainBindingRequirementsManifest
	freeze ScorerBlindEvaluationFreeze
	shared MultidomainBindingClosureSharedCorpusArtifacts
}

func buildSharedClosureFixture(t *testing.T) sharedClosureFixture {
	t.Helper()
	root := t.TempDir()
	cilium, _, _ := threeAuthorityFixtures(t, root)
	verifier, verifierHash := writeSharedVerifier(t, root, cilium)
	store := filepath.Join(root, "retrieval")
	buildConfig := multiBuildConfig(root, store, verifier, verifierHash, cilium.lineageConfig())
	buildConfig.LexicalProfile = "deterministic_bm25f_fixed_point@1.1.0"
	built, err := Build(buildConfig)
	if err != nil {
		t.Fatalf("build BM25F multidomain candidate: %v", err)
	}
	candidate := built.Manifest
	candidateBytes, err := marshalDocument(candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidateSHA := digestBytes(candidateBytes)

	index, err := readBoundLexicalIndex(store, candidate)
	if err != nil {
		t.Fatal(err)
	}
	indexBytes, err := marshalDocument(index)
	if err != nil {
		t.Fatal(err)
	}
	indexSHA := digestBytes(indexBytes)

	dense := sealMultidomainDense(candidate, index, candidate.Lineages)
	denseBytes, err := marshalDocument(dense)
	if err != nil {
		t.Fatal(err)
	}
	denseSHA := digestBytes(denseBytes)
	densePath := filepath.Join(root, "dense.json")
	writeCanonical(t, densePath, dense)

	candidatePath := filepath.Join(root, "candidate.json")
	writeCanonical(t, candidatePath, candidate)

	baselineResult, err := Hybridize(HybridBuildConfig{
		CandidatePath: candidatePath, CandidateHash: candidateSHA,
		StoreRoot: store, DenseArtifactPath: densePath, DenseArtifactHash: denseSHA,
	})
	if err != nil {
		t.Fatalf("hybridize baseline: %v", err)
	}
	baselineBytes, err := marshalDocument(baselineResult.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	baselineSHA := digestBytes(baselineBytes)

	scorerArtifactSHA256 := "sha256:" + strings.Repeat("7", 64)
	profileCore := FusionProfileCore{
		SchemaVersion: retrievalSchemaVersion, ProfileKind: championFusionProfileKind,
		State: "candidate", AuthorityState: "caller_pinned_candidate_input",
		FusionProfile: championFusionProfile, ScorerID: championFusionScorerID, ScorerRevision: championFusionScorerRevision,
		ScorerArtifactSHA256: scorerArtifactSHA256,
		LexicalCandidateID:   candidate.ManifestID, LexicalCandidateSHA256: candidateSHA,
		LexicalProfile: candidate.LexicalProfile, LexicalTokenizerID: candidate.LexicalTokenizerID, LexicalScorerID: candidate.LexicalScorerID,
		DenseArtifactID: dense.ArtifactID, DenseArtifactSHA256: denseSHA,
		DenseModelID: dense.ModelID, DenseModelRevision: dense.ModelRevision, DenseModelArtifactSHA256: dense.ModelArtifactSHA256,
		DenseTokenizerID: dense.TokenizerID, DenseTokenizerSHA256: dense.TokenizerSHA256, EmbeddingProfile: dense.EmbeddingProfile,
		VectorEncoding: dense.VectorEncoding, Normalization: dense.Normalization, QuantizationScale: dense.QuantizationScale, Dimension: dense.Dimension,
		FusionWindow: 100, ResultWindow: 10, RerankWindow: 0,
		Arithmetic: championFusionArithmetic, ArithmeticScale: championFusionScale,
		LexicalWeight: championFusionLexicalWeight, DenseWeight: championFusionDenseWeight,
		ChampionBonus: 200_000_000, MissingLanePolicy: championFusionMissingLanePolicy, TieBreak: championFusionTieBreak,
	}
	profile, err := sealFusionProfile(profileCore)
	if err != nil {
		t.Fatalf("seal fusion profile: %v", err)
	}
	profileBytes, err := marshalDocument(profile)
	if err != nil {
		t.Fatal(err)
	}
	profileSHA := digestBytes(profileBytes)
	profilePath := filepath.Join(root, "fusion-profile.json")
	writeCanonical(t, profilePath, profile)

	challengerResult, err := Hybridize(HybridBuildConfig{
		CandidatePath: candidatePath, CandidateHash: candidateSHA,
		StoreRoot: store, DenseArtifactPath: densePath, DenseArtifactHash: denseSHA,
		FusionProfilePath: profilePath, FusionProfileHash: profileSHA,
	})
	if err != nil {
		t.Fatalf("hybridize challenger: %v", err)
	}
	challengerBytes, err := marshalDocument(challengerResult.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	challengerSHA := digestBytes(challengerBytes)

	// Two frozen cases bound to the single admitted authority.
	authority := MultidomainSourceAuthorityRequirement{
		AuthorityID: cilium.spec.authorityID, ComponentID: "cilium", ComponentVersion: cilium.spec.resolved,
		AdmissionPolicyScopeID: cilium.spec.scopeID,
	}
	queryOne, queryTwo := "first frozen query", "second frozen query"
	caseOne, caseTwo := "case-one", "case-two"
	freeze := ScorerBlindEvaluationFreeze{
		ScorerBlindEvaluationFreezeCore: ScorerBlindEvaluationFreezeCore{
			Cases: []ScorerBlindFreezeCase{
				{CaseID: caseOne, Class: "cilium", Query: queryOne, QuerySHA256: digestBytes([]byte(queryOne))},
				{CaseID: caseTwo, Class: "cilium", Query: queryTwo, QuerySHA256: digestBytes([]byte(queryTwo))},
			},
		},
	}

	base := MultidomainBindingRequirementsManifest{
		MultidomainBindingRequirementsCore: MultidomainBindingRequirementsCore{
			SourceAuthorities: []MultidomainSourceAuthorityRequirement{authority},
		},
		ManifestID: "retrieval-binding-requirements:sha256:" + strings.Repeat("5", 64),
		Gaps: []MultidomainAbsentArtifactGap{
			{Scope: "shared_corpus", ArtifactKind: closureKindLexicalCandidate, Blocking: true},
			{Scope: "shared_corpus", ArtifactKind: closureKindLexicalIndex, Blocking: true},
			{Scope: "shared_corpus", ArtifactKind: closureKindDenseArtifact, Blocking: true},
			{Scope: "shared_corpus", ArtifactKind: closureKindHybridBaselineCandidate, Blocking: true},
			{Scope: "shared_corpus", ArtifactKind: closureKindHybridChallengerCandidate, Blocking: true},
			{Scope: "comparison", ArtifactKind: closureKindFusionProfile, Blocking: true},
			{Scope: "comparison", ArtifactKind: closureKindScorerArtifact, Blocking: true},
			{Scope: "evaluation_case", CaseID: caseOne, ProfileRole: "baseline", ExpectedQuerySHA256: digestBytes([]byte(queryOne)), Blocking: true},
			{Scope: "evaluation_case", CaseID: caseOne, ProfileRole: "challenger", ExpectedQuerySHA256: digestBytes([]byte(queryOne)), Blocking: true},
			{Scope: "evaluation_case", CaseID: caseTwo, ProfileRole: "baseline", ExpectedQuerySHA256: digestBytes([]byte(queryTwo)), Blocking: true},
			{Scope: "evaluation_case", CaseID: caseTwo, ProfileRole: "challenger", ExpectedQuerySHA256: digestBytes([]byte(queryTwo)), Blocking: true},
		},
	}

	sealSignal := func(hybridID, denseID, query string) QuerySignalArtifact {
		core := QuerySignalArtifactCore{
			SchemaVersion: retrievalSchemaVersion, ArtifactKind: querySignalArtifactKind,
			State: "candidate_input", AuthorityState: "untrusted_candidate_input",
			HybridCandidateID: hybridID, QuerySHA256: digestBytes([]byte(query)),
			DenseArtifactID: denseID, DenseModelID: dense.ModelID, DenseModelRevision: dense.ModelRevision,
			DenseModelArtifactSHA256: dense.ModelArtifactSHA256, DenseTokenizerID: dense.TokenizerID, DenseTokenizerSHA256: dense.TokenizerSHA256,
			EmbeddingProfile: dense.EmbeddingProfile, DenseQueryInstruction: "Retrieve exact operational evidence.",
			DenseDocumentInstruction: dense.DocumentInstruction, VectorEncoding: dense.VectorEncoding, Normalization: dense.Normalization,
			QuantizationScale: dense.QuantizationScale, Dimension: dense.Dimension, QueryVector: []int16{denseQuantizationScale, 0},
			RerankingRequested: false, Scores: []RerankerDocumentScore{},
		}
		coreBytes, err := json.Marshal(core)
		if err != nil {
			t.Fatal(err)
		}
		digest := digestBytes(coreBytes)
		return QuerySignalArtifact{ArtifactID: "query-signal-artifact:" + digest, ArtifactPayloadSHA256: digest, QuerySignalArtifactCore: core}
	}

	writeArtifact := func(name string, value any) (MultidomainBindingClosureAdmittedArtifact, string) {
		path := filepath.Join(root, name+".json")
		writeCanonical(t, path, value)
		data, err := marshalDocument(value)
		if err != nil {
			t.Fatal(err)
		}
		return MultidomainBindingClosureAdmittedArtifact{Path: name + ".json"}, digestBytes(data)
	}

	lexicalCandidateArtifact, _ := writeArtifact("candidate", candidate)
	lexicalCandidateArtifact.ArtifactID = candidate.ManifestID
	lexicalCandidateArtifact.DocumentSHA256 = candidateSHA

	lexicalIndexArtifact, _ := writeArtifact("index", index)
	lexicalIndexArtifact.ArtifactID = index.IndexID
	lexicalIndexArtifact.DocumentSHA256 = indexSHA

	denseArtifact, _ := writeArtifact("dense-for-closure", dense)
	denseArtifact.ArtifactID = dense.ArtifactID
	denseArtifact.DocumentSHA256 = denseSHA

	baselineArtifact, _ := writeArtifact("hybrid-baseline", baselineResult.Manifest)
	baselineArtifact.ArtifactID = baselineResult.Manifest.ManifestID
	baselineArtifact.DocumentSHA256 = baselineSHA

	challengerArtifact, _ := writeArtifact("hybrid-challenger", challengerResult.Manifest)
	challengerArtifact.ArtifactID = challengerResult.Manifest.ManifestID
	challengerArtifact.DocumentSHA256 = challengerSHA

	fusionProfileArtifact, _ := writeArtifact("fusion-profile-for-closure", profile)
	fusionProfileArtifact.ArtifactID = profile.ProfileID
	fusionProfileArtifact.DocumentSHA256 = profileSHA

	signalOneBaseline := sealSignal(baselineResult.Manifest.ManifestID, dense.ArtifactID, queryOne)
	signalOneChallenger := sealSignal(challengerResult.Manifest.ManifestID, dense.ArtifactID, queryOne)
	signalTwoBaseline := sealSignal(baselineResult.Manifest.ManifestID, dense.ArtifactID, queryTwo)
	signalTwoChallenger := sealSignal(challengerResult.Manifest.ManifestID, dense.ArtifactID, queryTwo)

	signalArtifact := func(name string, signal QuerySignalArtifact) MultidomainBindingClosureAdmittedArtifact {
		art, digest := writeArtifact(name, signal)
		art.ArtifactID = signal.ArtifactID
		art.DocumentSHA256 = digest
		return art
	}

	shared := MultidomainBindingClosureSharedCorpusArtifacts{
		SchemaVersion: multidomainBindingRequirementsVersion, InputKind: multidomainBindingClosureSharedInputKind,
		RequirementsManifestID: base.ManifestID,
		LexicalCandidate:       lexicalCandidateArtifact, LexicalIndex: lexicalIndexArtifact,
		DenseArtifact: denseArtifact, HybridBaselineCandidate: baselineArtifact, HybridChallengerCandidate: challengerArtifact,
		FusionProfile: fusionProfileArtifact, ScorerArtifactSHA256: scorerArtifactSHA256,
		QuerySignals: []MultidomainBindingClosureQuerySignalArtifact{
			{CaseID: caseOne, ProfileRole: "baseline", Artifact: signalArtifact("signal-one-baseline", signalOneBaseline)},
			{CaseID: caseOne, ProfileRole: "challenger", Artifact: signalArtifact("signal-one-challenger", signalOneChallenger)},
			{CaseID: caseTwo, ProfileRole: "baseline", Artifact: signalArtifact("signal-two-baseline", signalTwoBaseline)},
			{CaseID: caseTwo, ProfileRole: "challenger", Artifact: signalArtifact("signal-two-challenger", signalTwoChallenger)},
		},
	}

	return sharedClosureFixture{root: root, base: base, freeze: freeze, shared: shared}
}

func TestVerifyMultidomainSharedCorpusArtifactsClosesEveryTargetGap(t *testing.T) {
	fx := buildSharedClosureFixture(t)
	closed, checks := verifyMultidomainSharedCorpusArtifacts(fx.base, fx.freeze, fx.shared, fx.root)

	wantClosed := []string{
		closureKindLexicalCandidate, closureKindLexicalIndex, closureKindDenseArtifact,
		closureKindHybridBaselineCandidate, closureKindHybridChallengerCandidate,
		closureKindFusionProfile, closureKindScorerArtifact,
		evaluationCaseClosureKey("case-one", "baseline"), evaluationCaseClosureKey("case-one", "challenger"),
		evaluationCaseClosureKey("case-two", "baseline"), evaluationCaseClosureKey("case-two", "challenger"),
	}
	if len(closed) != len(wantClosed) {
		t.Fatalf("closed = %v (%d keys); want %d keys", closed, len(closed), len(wantClosed))
	}
	for _, key := range wantClosed {
		if !closed[key] {
			t.Fatalf("gap %q did not close: %v", key, closed)
		}
	}
	// scorer_artifact has no separate file of its own: it ties directly to the
	// already-checked fusion profile's bound scorer digest, so it contributes
	// no additional revalidation entry.
	if wantChecks := len(wantClosed) - 1; len(checks) != wantChecks {
		t.Fatalf("checks = %d; want %d (one revalidation entry per file-backed closed gap)", len(checks), wantChecks)
	}

	// Feeding the closed set through the real gap-flip merge closes exactly
	// these 11 gaps and leaves everything else (there is nothing else here)
	// alone; capabilities and promotable/execution_authorized stay false
	// regardless, mirroring the source_authority closure's own invariant.
	sealed := sealMultidomainBindingClosure(MultidomainBindingRequirementsCore{}, fx.base, nil, nil, closed, "2026-07-19T00:00:00Z")
	if sealed.ClosedGapCount != len(wantClosed) || sealed.BlockingGapCount != 0 {
		t.Fatalf("sealed closure = %d closed / %d blocking; want %d/0", sealed.ClosedGapCount, sealed.BlockingGapCount, len(wantClosed))
	}
	if sealed.Promotable || sealed.ExecutionAuthorized || sealed.Capabilities != (MultidomainBindingClosureCapabilities{}) {
		t.Fatalf("a fully closed gap set must still grant zero authority: %+v", sealed)
	}
}

func TestVerifyMultidomainSharedCorpusArtifactsFailsClosed(t *testing.T) {
	t.Run("schema_mismatch_closes_nothing", func(t *testing.T) {
		fx := buildSharedClosureFixture(t)
		fx.shared.RequirementsManifestID = "retrieval-binding-requirements:sha256:" + strings.Repeat("9", 64)
		closed, checks := verifyMultidomainSharedCorpusArtifacts(fx.base, fx.freeze, fx.shared, fx.root)
		if len(closed) != 0 || len(checks) != 0 {
			t.Fatalf("mismatched requirements target closed gaps: %v", closed)
		}
	})

	t.Run("candidate_digest_mismatch_blocks_everything_downstream", func(t *testing.T) {
		fx := buildSharedClosureFixture(t)
		fx.shared.LexicalCandidate.DocumentSHA256 = "sha256:" + strings.Repeat("0", 64)
		closed, _ := verifyMultidomainSharedCorpusArtifacts(fx.base, fx.freeze, fx.shared, fx.root)
		if len(closed) != 0 {
			t.Fatalf("tampered candidate pin still closed gaps: %v", closed)
		}
	})

	t.Run("dense_lineage_mismatch_blocks_dense_and_hybrid_and_cases_but_not_lexical", func(t *testing.T) {
		fx := buildSharedClosureFixture(t)
		var dense DenseVectorArtifact
		mustReadJSON(t, filepath.Join(fx.root, "dense-for-closure.json"), &dense)
		dense.Lineages[0].DocumentCount++
		rewritten, err := marshalDocument(dense)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(fx.root, "dense-for-closure.json"), rewritten, 0o644)
		fx.shared.DenseArtifact.DocumentSHA256 = digestBytes(rewritten)
		closed, _ := verifyMultidomainSharedCorpusArtifacts(fx.base, fx.freeze, fx.shared, fx.root)
		if closed[closureKindDenseArtifact] || closed[closureKindHybridBaselineCandidate] || closed[closureKindHybridChallengerCandidate] ||
			closed[closureKindFusionProfile] || closed[closureKindScorerArtifact] ||
			closed[evaluationCaseClosureKey("case-one", "baseline")] {
			t.Fatalf("tampered dense lineage still closed a dependent gap: %v", closed)
		}
		if !closed[closureKindLexicalCandidate] || !closed[closureKindLexicalIndex] {
			t.Fatalf("lexical gaps must stay closed independent of the dense defect: %v", closed)
		}
	})

	t.Run("query_signal_wrong_hybrid_candidate_blocks_only_that_case_role", func(t *testing.T) {
		fx := buildSharedClosureFixture(t)
		for i := range fx.shared.QuerySignals {
			if fx.shared.QuerySignals[i].CaseID == "case-one" && fx.shared.QuerySignals[i].ProfileRole == "baseline" {
				fx.shared.QuerySignals[i].Artifact.DocumentSHA256 = "sha256:" + strings.Repeat("1", 64)
			}
		}
		closed, _ := verifyMultidomainSharedCorpusArtifacts(fx.base, fx.freeze, fx.shared, fx.root)
		if closed[evaluationCaseClosureKey("case-one", "baseline")] {
			t.Fatal("tampered query-signal pin still closed its own gap")
		}
		if !closed[evaluationCaseClosureKey("case-one", "challenger")] || !closed[evaluationCaseClosureKey("case-two", "baseline")] {
			t.Fatalf("an unrelated case/role gap was wrongly left blocking: %v", closed)
		}
	})

	t.Run("query_signal_reranking_requested_fails_closed", func(t *testing.T) {
		fx := buildSharedClosureFixture(t)
		var signal QuerySignalArtifact
		path := filepath.Join(fx.root, "signal-one-baseline.json")
		mustReadJSON(t, path, &signal)
		signal.RerankingRequested = true
		rewritten, err := marshalDocument(signal)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, path, rewritten, 0o644)
		for i := range fx.shared.QuerySignals {
			if fx.shared.QuerySignals[i].CaseID == "case-one" && fx.shared.QuerySignals[i].ProfileRole == "baseline" {
				fx.shared.QuerySignals[i].Artifact.DocumentSHA256 = digestBytes(rewritten)
			}
		}
		closed, _ := verifyMultidomainSharedCorpusArtifacts(fx.base, fx.freeze, fx.shared, fx.root)
		if closed[evaluationCaseClosureKey("case-one", "baseline")] {
			t.Fatal("a rerank-requested signal must fail closed against the fusion_only target")
		}
	})

	t.Run("absent_shared_input_closes_nothing", func(t *testing.T) {
		fx := buildSharedClosureFixture(t)
		closed, checks := verifyMultidomainSharedCorpusArtifacts(fx.base, fx.freeze, MultidomainBindingClosureSharedCorpusArtifacts{}, fx.root)
		if len(closed) != 0 || len(checks) != 0 {
			t.Fatalf("zero-value shared input closed gaps: %v", closed)
		}
	})
}

func mustReadJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := readStableFile(path, "test fixture", maxMultidomainAdmittedArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
