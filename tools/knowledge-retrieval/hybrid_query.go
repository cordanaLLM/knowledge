package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxQuerySignalBytes = int64(32 * 1024 * 1024)
	rrfScale            = int64(1_000_000)
	rrfK                = 60
	maxRerankerScore    = int64(1_000_000_000_000)
)

type loadedHybridCandidate struct {
	root      string
	hybrid    HybridCandidateManifest
	lexical   CandidateManifest
	index     LexicalIndex
	dense     DenseVectorArtifact
	fusion    *FusionProfile
	lexicalAt string
}

type hybridAggregate struct {
	documentID    string
	spanID        string
	lexicalRank   int
	lexicalScore  int64
	denseRank     int
	denseDot      int64
	fusionScore   int64
	rerankerScore int64
	matchedTerms  []string
}

func QueryHybrid(config HybridQueryConfig) (HybridQueryResponse, error) {
	base := HybridQueryResponse{
		State: "partial", ResultState: "backend_unavailable", Promotable: false,
		ServingEligible: false, CurrentEligible: false, Lexical: true, Dense: true,
		Fusion: true, Reranking: false, Results: []HybridQueryHit{},
	}
	for name, value := range map[string]string{
		"hybrid-candidate": config.HybridCandidatePath, "hybrid-candidate-sha256": config.HybridCandidateHash,
		"store": config.StoreRoot, "evidence-store": config.EvidenceStoreRoot,
		"admission-policy": config.AdmissionPolicyPath, "admission-policy-sha256": config.AdmissionPolicyHash,
		"query-artifact": config.QueryArtifactPath, "query-artifact-sha256": config.QueryArtifactHash,
		"query": config.Query, "principal-scope": config.PrincipalScope, "as-of": config.AsOf,
	} {
		if strings.TrimSpace(value) == "" {
			return base, fmt.Errorf("%s is required", name)
		}
	}
	if config.Limit < 1 || config.Limit > 100 || config.FusionWindow < 1 || config.FusionWindow > 100 || config.RerankWindow < 0 || config.RerankWindow > config.FusionWindow || (config.RerankWindow > 0 && config.Limit > config.RerankWindow) || (config.RerankWindow == 0 && config.Limit > config.FusionWindow) {
		return base, errors.New("require 1 <= limit <= fusion-window <= 100 and rerank-window=0 or limit <= rerank-window <= fusion-window")
	}
	rerankingRequested := config.RerankWindow > 0
	base.Reranking = rerankingRequested
	if config.MaxExcerptBytes < 1 || config.MaxExcerptBytes > 8192 {
		return base, errors.New("max-excerpt-bytes must be between 1 and 8192")
	}
	if config.PrincipalScope != "public" {
		base.ResultState = "forbidden"
		base.ErrorCode = "principal_scope_forbidden"
		return base, nil
	}

	loaded, code := loadHybridCandidate(config)
	if code != "" {
		base.ErrorCode = code
		return base, nil
	}
	base.HybridCandidateID = loaded.hybrid.ManifestID
	base.FreshnessState = loaded.hybrid.FreshnessState
	base.FusionProfile = loaded.hybrid.FusionProfile
	base.FusionProfileID = loaded.hybrid.FusionProfileID
	base.LexicalProfile = loaded.lexical.LexicalProfile
	if code := validateCallerFusionProfile(config, loaded); code != "" {
		base.ErrorCode = code
		return base, nil
	}

	lexicalResponse, err := Query(QueryConfig{
		CandidatePath: loaded.lexicalAt, CandidateHash: loaded.hybrid.LexicalCandidateSHA256,
		StoreRoot: loaded.root, EvidenceStoreRoot: config.EvidenceStoreRoot,
		AdmissionPolicyPath: config.AdmissionPolicyPath, AdmissionPolicyHash: config.AdmissionPolicyHash,
		LineageSetPath: config.LineageSetPath,
		Query:          config.Query, PrincipalScope: config.PrincipalScope, AsOf: config.AsOf,
		Limit: config.FusionWindow, MaxExcerptBytes: config.MaxExcerptBytes,
	})
	if err != nil {
		return base, err
	}
	base.FreshnessState = lexicalResponse.FreshnessState
	base.QueryTerms = lexicalResponse.QueryTerms
	if lexicalResponse.LexicalProfile != base.LexicalProfile {
		base.ErrorCode = "lexical_profile_lineage_invalid"
		return base, nil
	}
	if lexicalResponse.ResultState == "forbidden" || lexicalResponse.ResultState == "backend_unavailable" {
		base.ResultState = lexicalResponse.ResultState
		base.ErrorCode = lexicalResponse.ErrorCode
		return base, nil
	}

	signals, code := loadAndValidateQuerySignals(config, loaded, rerankingRequested)
	if code != "" {
		base.ErrorCode = code
		return base, nil
	}
	base.QuerySignalArtifactID = signals.ArtifactID
	if rerankingRequested {
		base.RerankerModelID = signals.RerankerModelID
	}

	aggregates := make(map[string]*hybridAggregate, config.FusionWindow*2)
	for position, hit := range lexicalResponse.Results {
		documentID := lexicalDocumentIdentity(hit.Evidence)
		current := &hybridAggregate{
			documentID: documentID, spanID: hit.Evidence.SpanID,
			lexicalRank: position + 1, lexicalScore: hit.Score,
			matchedTerms: append([]string(nil), hit.MatchedTerms...),
		}
		current.fusionScore, err = fusionLaneScore(loaded.fusion, "lexical", current.lexicalRank)
		if err != nil {
			base.ErrorCode = "fusion_score_overflow"
			return base, nil
		}
		aggregates[documentID] = current
	}

	type denseScore struct {
		documentID string
		spanID     string
		dot        int64
	}
	spanByDocument := make(map[string]string, len(loaded.index.Documents))
	for _, document := range loaded.index.Documents {
		spanByDocument[document.DocumentID] = document.Evidence.SpanID
	}
	denseScores := make([]denseScore, 0, len(loaded.dense.Documents))
	for _, document := range loaded.dense.Documents {
		dot, err := denseDotProduct(document.Values, signals.QueryVector)
		if err != nil {
			base.ErrorCode = "dense_score_overflow"
			return base, nil
		}
		spanID, exists := spanByDocument[document.DocumentID]
		if !exists || spanID == "" {
			base.ErrorCode = "dense_document_reference_invalid"
			return base, nil
		}
		denseScores = append(denseScores, denseScore{documentID: document.DocumentID, spanID: spanID, dot: dot})
	}
	base.DenseScannedDocuments = len(denseScores)
	sort.Slice(denseScores, func(i, j int) bool {
		if denseScores[i].dot != denseScores[j].dot {
			return denseScores[i].dot > denseScores[j].dot
		}
		if denseScores[i].spanID != denseScores[j].spanID {
			return denseScores[i].spanID < denseScores[j].spanID
		}
		return denseScores[i].documentID < denseScores[j].documentID
	})
	if len(denseScores) > config.FusionWindow {
		denseScores = denseScores[:config.FusionWindow]
	}
	for position, score := range denseScores {
		current := aggregates[score.documentID]
		if current == nil {
			current = &hybridAggregate{documentID: score.documentID, spanID: score.spanID}
			aggregates[score.documentID] = current
		} else if current.spanID != score.spanID {
			base.ErrorCode = "fusion_lane_lineage_mismatch"
			return base, nil
		}
		current.denseRank = position + 1
		current.denseDot = score.dot
		denseContribution, err := fusionLaneScore(loaded.fusion, "dense", current.denseRank)
		if err != nil {
			base.ErrorCode = "fusion_score_overflow"
			return base, nil
		}
		if loaded.fusion == nil {
			current.fusionScore += denseContribution
		} else {
			current.fusionScore, err = checkedAddInt64(current.fusionScore, denseContribution)
			if err != nil {
				base.ErrorCode = "fusion_score_overflow"
				return base, nil
			}
		}
	}
	if loaded.fusion != nil && (len(lexicalResponse.Results) == 0 || len(denseScores) == 0) {
		base.ErrorCode = "fusion_lane_missing"
		return base, nil
	}

	fused := make([]*hybridAggregate, 0, len(aggregates))
	for _, current := range aggregates {
		fused = append(fused, current)
	}
	sort.Slice(fused, func(i, j int) bool {
		return fusionAggregateBetter(fused[i], fused[j])
	})
	base.TieBreak = championFusionTieBreak
	base.ScoreTies = collectFusionScoreTies(fused, config.Limit)
	var fusionObservation *FusionObservation
	if loaded.fusion != nil {
		observation, err := buildFusionObservation(*loaded.fusion, fused, lexicalResponse.Results[0].Evidence.SpanID, denseScores[0].spanID, config.Limit)
		if err != nil {
			base.ErrorCode = "fusion_champion_retention_failed"
			return base, nil
		}
		fusionObservation = &observation
	}
	selectionWindow := config.Limit
	if rerankingRequested {
		selectionWindow = config.RerankWindow
	}
	if len(fused) > selectionWindow {
		fused = fused[:selectionWindow]
	}
	if rerankingRequested {
		scoreByDocument := make(map[string]int64, len(signals.Scores))
		for _, score := range signals.Scores {
			scoreByDocument[score.DocumentID] = score.Score
		}
		for _, current := range fused {
			score, exists := scoreByDocument[current.documentID]
			if !exists {
				base.ErrorCode = "reranker_window_incomplete"
				return base, nil
			}
			current.rerankerScore = score
		}
		base.RerankedDocuments = len(fused)
		sort.Slice(fused, func(i, j int) bool {
			if fused[i].rerankerScore != fused[j].rerankerScore {
				return fused[i].rerankerScore > fused[j].rerankerScore
			}
			return fusionAggregateBetter(fused[i], fused[j])
		})
	}
	if len(fused) > config.Limit {
		fused = fused[:config.Limit]
	}
	documents := make(map[string]EvidenceRef, len(loaded.index.Documents))
	documentsBySpan := make(map[string]EvidenceRef, len(loaded.index.Documents))
	for _, document := range loaded.index.Documents {
		documents[document.DocumentID] = document.Evidence
		documentsBySpan[document.Evidence.SpanID] = document.Evidence
	}
	evidenceRoot, err := filepath.Abs(config.EvidenceStoreRoot)
	if err != nil || validateNoSymlinkPath(evidenceRoot) != nil {
		base.ErrorCode = "evidence_store_unavailable"
		return base, nil
	}
	hits := make([]HybridQueryHit, 0, len(fused))
	seenSpan := make(map[string]bool, len(fused))
	for _, current := range fused {
		ref, exists := documents[current.documentID]
		if !exists {
			base.ErrorCode = "dense_document_reference_invalid"
			return base, nil
		}
		// Small-to-big: a fine-span extension document always resolves to its
		// enclosing coarse chunk as the returned unit, matched documents and
		// scores stay the fine document's own. A duplicate resulting SpanID
		// (the coarse chunk itself also matched, independently or via another
		// fine sibling) is shown once, keeping the best-ranked occurrence.
		if ref.ParentSpanID != "" {
			parentRef, parentExists := documentsBySpan[ref.ParentSpanID]
			if !parentExists {
				base.ErrorCode = "small_to_big_parent_missing"
				return base, nil
			}
			ref = parentRef
		}
		if seenSpan[ref.SpanID] {
			continue
		}
		seenSpan[ref.SpanID] = true
		payload, code := readEvidencePayload(evidenceRoot, loaded.hybrid, ref)
		if code != "" {
			base.ErrorCode = code
			return base, nil
		}
		excerpt, truncated := boundedUTF8(payload, config.MaxExcerptBytes)
		path := make([]string, 0, 4)
		if current.lexicalRank != 0 {
			path = append(path, "lexical")
		}
		if current.denseRank != 0 {
			path = append(path, "dense")
		}
		if loaded.fusion == nil {
			path = append(path, "reciprocal_rank_fusion")
		} else {
			path = append(path, "bounded_lane_champion_rank_sum")
		}
		if rerankingRequested {
			path = append(path, "external_reranker_scores")
		}
		score := HybridScore{
			LexicalRank: current.lexicalRank, LexicalScore: current.lexicalScore,
			DenseRank: current.denseRank, DenseDot: current.denseDot,
			FusionScore: current.fusionScore,
		}
		if rerankingRequested {
			rerankerScore := current.rerankerScore
			rerankerScale := signals.RerankerScoreScale
			score.RerankerScore = &rerankerScore
			score.RerankerScale = &rerankerScale
		}
		hits = append(hits, HybridQueryHit{
			Rank: len(hits) + 1, RetrievalPath: path, MatchedTerms: current.matchedTerms,
			Score:    score,
			Evidence: ref, Excerpt: excerpt, ExcerptTruncated: truncated,
		})
	}
	// External query signals, a full dense scan and bounded payload reads can be
	// expensive. Re-read the operator-pinned policy after that work and
	// immediately before results become observable so a revocation, tombstone or
	// freshness transition during ranking fails closed.
	resultState, freshnessState, code := recheckHybridAdmissionPolicy(config, loaded.lexical)
	if code != "" {
		base.ResultState = resultState
		base.ErrorCode = code
		return base, nil
	}
	base.FreshnessState = freshnessState
	base.FusionObservation = fusionObservation
	base.Results = hits
	if len(hits) == 0 {
		base.ResultState = "empty"
	} else {
		base.ResultState = "ok"
	}
	if base.FreshnessState == "stale" {
		base.ResultState = "stale"
	}
	return base, nil
}

func loadHybridCandidate(config HybridQueryConfig) (loadedHybridCandidate, string) {
	var zero loadedHybridCandidate
	root, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkPath(root) != nil {
		return zero, "candidate_store_unavailable"
	}
	data, err := readStableFile(config.HybridCandidatePath, "hybrid candidate", maxManifestBytes)
	if err != nil {
		return zero, "hybrid_candidate_unavailable"
	}
	if digestBytes(data) != config.HybridCandidateHash {
		return zero, "hybrid_candidate_document_mismatch"
	}
	var hybrid HybridCandidateManifest
	if err := decodeStrictCanonical(data, &hybrid); err != nil || validateHybridCandidate(hybrid) != nil {
		return zero, "hybrid_candidate_invalid"
	}
	lexicalBytes, lexicalAt, err := readBoundStoreDocument(root, hybrid.LexicalCandidatePath, hybrid.LexicalCandidateSHA256, hybrid.LexicalCandidateByteSize, maxManifestBytes)
	if err != nil {
		return zero, "lexical_candidate_backend_unavailable"
	}
	var lexical CandidateManifest
	if err := decodeStrictCanonical(lexicalBytes, &lexical); err != nil || validateCandidate(lexical) != nil {
		return zero, "lexical_candidate_invalid"
	}
	indexBytes, _, err := readBoundStoreDocument(root, lexical.LexicalIndexPath, lexical.LexicalIndexSHA256, lexical.LexicalIndexByteSize, maxIndexBytes)
	if err != nil {
		return zero, "index_backend_unavailable"
	}
	var index LexicalIndex
	if err := decodeStrictCanonical(indexBytes, &index); err != nil {
		return zero, "lexical_index_invalid"
	}
	denseBytes, _, err := readBoundStoreDocument(root, hybrid.DenseArtifactPath, hybrid.DenseArtifactSHA256, hybrid.DenseArtifactByteSize, maxDenseArtifactBytes)
	if err != nil {
		return zero, "dense_backend_unavailable"
	}
	var dense DenseVectorArtifact
	if err := decodeStrictCanonical(denseBytes, &dense); err != nil {
		return zero, "dense_artifact_invalid"
	}
	var fusion *FusionProfile
	var fusionBinding *hybridDocumentBinding
	if hybrid.FusionProfile == championFusionProfile {
		profileBytes, _, err := readBoundStoreDocument(root, hybrid.FusionProfilePath, hybrid.FusionProfileSHA256, hybrid.FusionProfileByteSize, maxFusionProfileBytes)
		if err != nil {
			return zero, "fusion_profile_backend_unavailable"
		}
		var profile FusionProfile
		if err := decodeStrictCanonical(profileBytes, &profile); err != nil {
			return zero, "fusion_profile_lineage_invalid"
		}
		fusion = &profile
		fusionBinding = &hybridDocumentBinding{path: hybrid.FusionProfilePath, digest: digestBytes(profileBytes), size: int64(len(profileBytes))}
	}
	bindings := hybridLineageBindings{
		lexical: hybridDocumentBinding{path: hybrid.LexicalCandidatePath, digest: digestBytes(lexicalBytes), size: int64(len(lexicalBytes))},
		index:   hybridDocumentBinding{path: lexical.LexicalIndexPath, digest: digestBytes(indexBytes), size: int64(len(indexBytes))},
		dense:   hybridDocumentBinding{path: hybrid.DenseArtifactPath, digest: digestBytes(denseBytes), size: int64(len(denseBytes))},
		fusion:  fusionBinding,
	}
	if err := validateLoadedHybridLineage(hybrid, lexical, index, dense, fusion, bindings); err != nil {
		return zero, "hybrid_lineage_invalid"
	}
	return loadedHybridCandidate{root: root, hybrid: hybrid, lexical: lexical, index: index, dense: dense, fusion: fusion, lexicalAt: lexicalAt}, ""
}

func validateCallerFusionProfile(config HybridQueryConfig, loaded loadedHybridCandidate) string {
	if loaded.fusion == nil {
		if config.FusionProfilePath != "" || config.FusionProfileHash != "" {
			return "fusion_profile_unexpected"
		}
		return ""
	}
	if config.FusionProfilePath == "" || config.FusionProfileHash == "" {
		return "fusion_profile_pin_missing"
	}
	if config.FusionProfileHash != loaded.hybrid.FusionProfileSHA256 {
		return "fusion_profile_document_mismatch"
	}
	data, err := readStableFile(config.FusionProfilePath, "caller-pinned fusion profile", maxFusionProfileBytes)
	if err != nil {
		return "fusion_profile_unavailable"
	}
	if digestBytes(data) != config.FusionProfileHash {
		return "fusion_profile_document_mismatch"
	}
	stored, _, err := readBoundStoreDocument(loaded.root, loaded.hybrid.FusionProfilePath, loaded.hybrid.FusionProfileSHA256, loaded.hybrid.FusionProfileByteSize, maxFusionProfileBytes)
	if err != nil || !bytes.Equal(data, stored) {
		return "fusion_profile_document_mismatch"
	}
	var profile FusionProfile
	if err := decodeStrictCanonical(data, &profile); err != nil || profile.ProfileID != loaded.fusion.ProfileID || validateFusionProfileLineage(profile, loaded.lexical, loaded.hybrid.LexicalCandidateSHA256, loaded.dense, loaded.hybrid.DenseArtifactSHA256) != nil {
		return "fusion_profile_lineage_invalid"
	}
	runningPath, err := os.Executable()
	if err != nil {
		return "fusion_scorer_artifact_unavailable"
	}
	runningBytes, err := readStableFile(runningPath, "running fusion scorer", maxExecutableBytes)
	if err != nil {
		return "fusion_scorer_artifact_unavailable"
	}
	if digestBytes(runningBytes) != profile.ScorerArtifactSHA256 {
		return "fusion_scorer_artifact_mismatch"
	}
	if config.FusionWindow != profile.FusionWindow || config.Limit != profile.ResultWindow || config.RerankWindow != profile.RerankWindow {
		return "fusion_profile_window_mismatch"
	}
	return ""
}

func loadAndValidateQuerySignals(config HybridQueryConfig, loaded loadedHybridCandidate, rerankingRequested bool) (QuerySignalArtifact, string) {
	var zero QuerySignalArtifact
	data, err := readStableFile(config.QueryArtifactPath, "query signal artifact", maxQuerySignalBytes)
	if err != nil {
		return zero, "query_signal_unavailable"
	}
	if digestBytes(data) != config.QueryArtifactHash {
		return zero, "query_signal_document_mismatch"
	}
	var signals QuerySignalArtifact
	if err := decodeStrictCanonical(data, &signals); err != nil || validateQuerySignals(signals, loaded, config.Query, rerankingRequested) != nil {
		return zero, "query_signal_invalid"
	}
	return signals, ""
}

func recheckHybridAdmissionPolicy(config HybridQueryConfig, candidate CandidateManifest) (string, string, string) {
	asOf, err := parseCanonicalUTC(config.AsOf)
	if err != nil {
		return "backend_unavailable", "", "admission_policy_time_invalid"
	}
	// A shared multidomain lexical candidate carries no single-authority binding;
	// re-admit every authority against the operator-pinned lineage set instead.
	if candidate.ManifestKind == lexicalMultidomainCandidate {
		return validateMultidomainAdmission(candidate, config.LineageSetPath, asOf)
	}
	data, err := readStableFile(config.AdmissionPolicyPath, "admission policy", maxPolicyBytes)
	if err != nil {
		return "backend_unavailable", "", "admission_policy_unavailable"
	}
	if digestBytes(data) != config.AdmissionPolicyHash {
		return "forbidden", "", "admission_policy_document_mismatch"
	}
	var policy AdmissionPolicy
	if err := decodeStrictCanonical(data, &policy); err != nil || validatePolicyIdentity(policy) != nil {
		return "forbidden", "", "admission_policy_invalid"
	}
	if policy.AccessScope != "public" || !policy.RetrievalAllowed || policy.State != "active" {
		return "forbidden", "", "admission_policy_forbidden"
	}
	if policy.SourceState != "present" || policy.DeletionState != "active" || policy.Tombstone {
		return "forbidden", "", "source_deleted_or_tombstoned"
	}
	evaluatedAt, _ := parseCanonicalUTC(policy.EvaluatedAt)
	if asOf.Before(evaluatedAt) {
		return "forbidden", "", "query_before_policy_evaluation"
	}
	if policy.PolicyID != candidate.AdmissionPolicyID || policy.SnapshotManifestID != candidate.SnapshotManifestID || policy.EvidenceManifestID != candidate.EvidenceManifestID || config.AdmissionPolicyHash != candidate.AdmissionPolicySHA256 {
		return "forbidden", "", "admission_policy_changed"
	}
	freshUntil, _ := parseCanonicalUTC(policy.FreshUntil)
	if asOf.After(freshUntil) {
		return "", "stale", ""
	}
	return "", "fresh", ""
}

func validateQuerySignals(signals QuerySignalArtifact, loaded loadedHybridCandidate, query string, rerankingRequested bool) error {
	coreBytes, err := json.Marshal(signals.QuerySignalArtifactCore)
	if err != nil || signals.ArtifactPayloadSHA256 != digestBytes(coreBytes) || signals.ArtifactID != "query-signal-artifact:"+signals.ArtifactPayloadSHA256 {
		return errors.New("query signal identity mismatch")
	}
	if signals.SchemaVersion != retrievalSchemaVersion || signals.ArtifactKind != querySignalArtifactKind || signals.State != "candidate_input" || signals.AuthorityState != "untrusted_candidate_input" {
		return errors.New("query signal contract unsupported")
	}
	if signals.HybridCandidateID != loaded.hybrid.ManifestID || signals.QuerySHA256 != digestBytes([]byte(query)) || signals.DenseArtifactID != loaded.dense.ArtifactID {
		return errors.New("query signal lineage mismatch")
	}
	if signals.DenseModelID != loaded.dense.ModelID || signals.DenseModelRevision != loaded.dense.ModelRevision || signals.DenseModelArtifactSHA256 != loaded.dense.ModelArtifactSHA256 || signals.DenseTokenizerID != loaded.dense.TokenizerID || signals.DenseTokenizerSHA256 != loaded.dense.TokenizerSHA256 || signals.EmbeddingProfile != loaded.dense.EmbeddingProfile || !boundedMetadata(signals.DenseQueryInstruction) || signals.DenseDocumentInstruction != loaded.dense.DocumentInstruction || signals.VectorEncoding != loaded.dense.VectorEncoding || signals.Normalization != loaded.dense.Normalization || signals.QuantizationScale != loaded.dense.QuantizationScale || signals.Dimension != loaded.dense.Dimension || len(signals.QueryVector) != loaded.dense.Dimension {
		return errors.New("query vector contract mismatch")
	}
	if err := validateQuantizedUnitVector(signals.QueryVector); err != nil {
		return fmt.Errorf("query vector violates normalization contract: %w", err)
	}
	if signals.RerankingRequested != rerankingRequested {
		return errors.New("query signal reranking decision mismatch")
	}
	if !rerankingRequested {
		if signals.RerankerModelID != "" || signals.RerankerModelRevision != "" || signals.RerankerModelArtifactSHA256 != "" || signals.RerankerTokenizerID != "" || signals.RerankerTokenizerSHA256 != "" || signals.RerankerProfile != "" || signals.RerankerQueryInstruction != "" || signals.RerankerDocumentInstruction != "" || signals.RerankerScoreScale != 0 || signals.Scores == nil || len(signals.Scores) != 0 {
			return errors.New("disabled reranking carries scorer metadata or scores")
		}
		return nil
	}
	if !boundedMetadata(signals.RerankerModelID) || !boundedMetadata(signals.RerankerModelRevision) || !validSHA256(signals.RerankerModelArtifactSHA256) || !boundedMetadata(signals.RerankerTokenizerID) || !validSHA256(signals.RerankerTokenizerSHA256) || !boundedMetadata(signals.RerankerProfile) || !boundedMetadata(signals.RerankerQueryInstruction) || !boundedMetadata(signals.RerankerDocumentInstruction) || signals.RerankerScoreScale < 1 || signals.RerankerScoreScale > 1_000_000_000 || len(signals.Scores) < 1 || len(signals.Scores) > 100 {
		return errors.New("reranker identity or score contract invalid")
	}
	known := make(map[string]struct{}, len(loaded.index.Documents))
	for _, document := range loaded.index.Documents {
		known[document.DocumentID] = struct{}{}
	}
	previous := ""
	for position, score := range signals.Scores {
		if position > 0 && score.DocumentID <= previous {
			return errors.New("reranker scores are not in strict document-ID order")
		}
		previous = score.DocumentID
		if _, exists := known[score.DocumentID]; !exists || score.Score == math.MinInt64 || score.Score < -maxRerankerScore || score.Score > maxRerankerScore {
			return errors.New("reranker score is invalid")
		}
	}
	return nil
}

func readBoundStoreDocument(root, relative, digest string, size, maxBytes int64) ([]byte, string, error) {
	if validateRelativePath(relative) != nil || !validSHA256(digest) || size < 1 || size > maxBytes {
		return nil, "", errors.New("store object binding invalid")
	}
	target := filepath.Join(root, filepath.FromSlash(relative))
	if !isWithin(root, target) {
		return nil, "", errors.New("store object path escapes root")
	}
	data, err := verifyFileDigest(target, digest, size)
	return data, target, err
}

func readEvidencePayload(root string, hybrid HybridCandidateManifest, ref EvidenceRef) ([]byte, string) {
	if ref.AccessScope != "public" || !evidenceRefBindsAdmittedLineage(ref, hybrid.SnapshotManifestID, hybrid.EvidenceManifestID, hybrid.Lineages) || ref.TrustEnvelopeID != expectedTrustEnvelope().EnvelopeID || ref.InstructionPolicy != "forbidden" || ref.ExecutionPolicy != "never" || ref.ToolPolicy != "never" || ref.InterpretationPolicy != "evidence_only" {
		return nil, "index_evidence_envelope_invalid"
	}
	if validateRelativePath(ref.PayloadObjectPath) != nil || ref.PayloadByteSize < 0 || ref.PayloadByteSize > defaultMaxPayloadBytes {
		return nil, "payload_path_invalid"
	}
	target := filepath.Join(root, filepath.FromSlash(ref.PayloadObjectPath))
	if !isWithin(root, target) {
		return nil, "payload_path_escape"
	}
	data, err := verifyFileDigest(target, ref.PayloadSHA256, ref.PayloadByteSize)
	if err != nil {
		return nil, "payload_backend_unavailable"
	}
	return data, ""
}

func fusionLaneScore(profile *FusionProfile, lane string, rank int) (int64, error) {
	if profile == nil {
		return reciprocalRank(rank), nil
	}
	if rank < 1 || rank > profile.FusionWindow {
		return 0, errors.New("fusion rank outside bound profile window")
	}
	var weight int64
	switch lane {
	case "lexical":
		weight = profile.LexicalWeight
	case "dense":
		weight = profile.DenseWeight
	default:
		return 0, errors.New("unknown fusion lane")
	}
	points := int64(profile.FusionWindow - rank + 1)
	score, err := checkedMultiplyInt64(points, profile.ArithmeticScale)
	if err != nil {
		return 0, err
	}
	score, err = checkedMultiplyInt64(score, weight)
	if err != nil {
		return 0, err
	}
	if rank == 1 {
		score, err = checkedAddInt64(score, profile.ChampionBonus)
		if err != nil {
			return 0, err
		}
	}
	return score, nil
}

// fusionAggregateBetter applies canonical_span_id_ascending on both arms. The
// lexical-document identity digests the whole EvidenceRef, including the
// admission policy's fresh_until, so it renumbers on every re-admission and
// cannot order a reproducible ranking; spanID is derived from content and
// coordinates only. documentID remains solely to keep the order total if two
// documents ever claim one span, which index build rejects as a span alias.
func fusionAggregateBetter(left, right *hybridAggregate) bool {
	if left.fusionScore != right.fusionScore {
		return left.fusionScore > right.fusionScore
	}
	if left.spanID != right.spanID {
		return left.spanID < right.spanID
	}
	return left.documentID < right.documentID
}

// collectFusionScoreTies reports every exact fusion-score tie the total order
// had to break inside or straddling the result window. A tie crossing the
// window boundary is reported because it decides inclusion, not merely order.
func collectFusionScoreTies(fused []*hybridAggregate, limit int) []FusionScoreTie {
	ties := make([]FusionScoreTie, 0)
	for start := 0; start < len(fused); {
		end := start + 1
		for end < len(fused) && fused[end].fusionScore == fused[start].fusionScore {
			end++
		}
		if end-start > 1 && start < limit {
			spanIDs := make([]string, 0, end-start)
			for _, aggregate := range fused[start:end] {
				spanIDs = append(spanIDs, aggregate.spanID)
			}
			ties = append(ties, FusionScoreTie{
				FusionScore: fused[start].fusionScore, FirstRank: start + 1, SpanIDs: spanIDs,
			})
		}
		start = end
	}
	return ties
}

func buildFusionObservation(profile FusionProfile, fused []*hybridAggregate, lexicalChampion, denseChampion string, limit int) (FusionObservation, error) {
	if lexicalChampion == "" || denseChampion == "" {
		return FusionObservation{}, errors.New("fusion lane champion is missing")
	}
	rankBySpan := make(map[string]int, len(fused))
	for position, aggregate := range fused {
		if aggregate.spanID == "" {
			return FusionObservation{}, errors.New("fusion result lacks canonical SpanID")
		}
		if _, exists := rankBySpan[aggregate.spanID]; exists {
			return FusionObservation{}, errors.New("fusion result repeats canonical SpanID")
		}
		rankBySpan[aggregate.spanID] = position + 1
	}
	champions := []struct {
		lane   string
		spanID string
	}{{"lexical", lexicalChampion}, {"dense", denseChampion}}
	observed := make([]FusionLaneChampion, 0, len(champions))
	unique := make(map[string]bool, len(champions))
	for _, champion := range champions {
		fusionRank, exists := rankBySpan[champion.spanID]
		if !exists {
			return FusionObservation{}, errors.New("lane champion absent from fused ranking")
		}
		retained := fusionRank <= limit
		resultRank := 0
		if retained {
			resultRank = fusionRank
		}
		observed = append(observed, FusionLaneChampion{
			Lane: champion.lane, SpanID: champion.spanID, FusionRank: fusionRank,
			ResultRank: resultRank, Retained: retained,
		})
		unique[champion.spanID] = retained
	}
	retainedCount := 0
	for _, retained := range unique {
		if retained {
			retainedCount++
		}
	}
	observation := FusionObservation{
		TieBreak: profile.TieBreak, MissingLanePolicy: profile.MissingLanePolicy,
		UniqueChampionCount: len(unique), RetainedChampionCount: retainedCount,
		AllChampionsRetained: retainedCount == len(unique), LaneChampions: observed,
	}
	if !observation.AllChampionsRetained {
		return FusionObservation{}, errors.New("fusion result window dropped a lane champion")
	}
	return observation, nil
}

func reciprocalRank(rank int) int64 {
	return rrfScale / int64(rrfK+rank)
}

func denseDotProduct(left, right []int16) (int64, error) {
	if len(left) != len(right) || len(left) < 1 {
		return 0, errors.New("dense vector dimensions differ")
	}
	var result int64
	for position, value := range left {
		product := int64(value) * int64(right[position])
		if (product > 0 && result > math.MaxInt64-product) || (product < 0 && result < math.MinInt64-product) {
			return 0, errors.New("dense dot product overflows int64")
		}
		result += product
	}
	return result, nil
}

func lexicalDocumentIdentity(ref EvidenceRef) string {
	refBytes, _ := json.Marshal(ref)
	return "lexical-document:" + digestBytes(refBytes)
}
