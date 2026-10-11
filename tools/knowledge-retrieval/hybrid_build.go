package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"strings"
)

const (
	maxDenseArtifactBytes    = int64(256 * 1024 * 1024)
	defaultMaxDenseDocuments = 100_000
	defaultMaxDenseDimension = 4_096
	hardMaxDenseDocuments    = 1_000_000
	hardMaxDenseDimension    = 8_192
	denseVectorEncoding      = "signed_int16_json"
	denseVectorNormalization = "l2_unit_before_symmetric_int16_quantization"
	denseQuantizationScale   = 32_767
	maxDenseCoordinate       = int64(denseQuantizationScale)
	maxDenseProduct          = maxDenseCoordinate * maxDenseCoordinate
	hybridFusionProfile      = "reciprocal_rank_fusion_k60_int64@1.0.0"
	hybridRerankingContract  = "caller_pinned_conditional_query_scores_for_complete_rerank_window@1.0.0"
	querySignalArtifactKind  = "external_query_vector_and_optional_reranker_scores"
)

func Hybridize(config HybridBuildConfig) (HybridBuildResult, error) {
	var zero HybridBuildResult
	for name, value := range map[string]string{
		"candidate": config.CandidatePath, "candidate-sha256": config.CandidateHash,
		"store": config.StoreRoot, "dense-artifact": config.DenseArtifactPath,
		"dense-artifact-sha256": config.DenseArtifactHash,
	} {
		if strings.TrimSpace(value) == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	maxDocuments, maxDimension, err := normalizeDenseLimits(config.MaxDenseDocuments, config.MaxDenseDimension)
	if err != nil {
		return zero, err
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkExistingPrefix(storeRoot) != nil {
		return zero, errors.New("store path is unavailable")
	}

	candidateBytes, err := readStableFile(config.CandidatePath, "lexical candidate", maxManifestBytes)
	if err != nil {
		return zero, fmt.Errorf("read lexical candidate: %w", err)
	}
	if digestBytes(candidateBytes) != config.CandidateHash {
		return zero, errors.New("lexical candidate document does not match caller pin")
	}
	var candidate CandidateManifest
	if err := decodeStrictCanonical(candidateBytes, &candidate); err != nil || validateCandidate(candidate) != nil {
		return zero, errors.New("lexical candidate is invalid")
	}
	if candidate.DocumentCount < 1 || candidate.DocumentCount > maxDocuments {
		return zero, errors.New("lexical candidate document count exceeds dense bound")
	}
	index, err := readBoundLexicalIndex(storeRoot, candidate)
	if err != nil {
		return zero, err
	}

	denseBytes, err := readStableFile(config.DenseArtifactPath, "dense vector artifact", maxDenseArtifactBytes)
	if err != nil {
		return zero, fmt.Errorf("read dense artifact: %w", err)
	}
	if digestBytes(denseBytes) != config.DenseArtifactHash {
		return zero, errors.New("dense artifact document does not match caller pin")
	}
	var dense DenseVectorArtifact
	if err := decodeStrictCanonical(denseBytes, &dense); err != nil {
		return zero, errors.New("dense artifact is not strict canonical JSON")
	}
	if err := validateDenseArtifact(dense, candidate, index, maxDocuments, maxDimension); err != nil {
		return zero, err
	}

	var fusionProfile *FusionProfile
	var fusionProfileBytes []byte
	if (config.FusionProfilePath == "") != (config.FusionProfileHash == "") {
		return zero, errors.New("fusion profile path and caller pin must both be present or absent")
	}
	if config.FusionProfilePath != "" {
		fusionProfileBytes, err = readStableFile(config.FusionProfilePath, "fusion profile", maxFusionProfileBytes)
		if err != nil {
			return zero, fmt.Errorf("read fusion profile: %w", err)
		}
		if digestBytes(fusionProfileBytes) != config.FusionProfileHash {
			return zero, errors.New("fusion profile document does not match caller pin")
		}
		var profile FusionProfile
		if err := decodeStrictCanonical(fusionProfileBytes, &profile); err != nil {
			return zero, errors.New("fusion profile is not strict canonical JSON")
		}
		if err := validateFusionProfileLineage(profile, candidate, config.CandidateHash, dense, config.DenseArtifactHash); err != nil {
			return zero, fmt.Errorf("fusion profile lineage invalid: %w", err)
		}
		fusionProfile = &profile
	}

	candidateRelative, err := contentObjectPath("candidates", candidate.ManifestPayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, candidateRelative, candidateBytes); err != nil {
		return zero, fmt.Errorf("commit lexical candidate binding: %w", err)
	}
	denseRelative, err := contentObjectPath("dense-artifacts", dense.ArtifactPayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, denseRelative, denseBytes); err != nil {
		return zero, fmt.Errorf("commit dense artifact binding: %w", err)
	}
	var fusionProfileRelative string
	if fusionProfile != nil {
		fusionProfileRelative, err = contentObjectPath("fusion-profiles", fusionProfile.ProfilePayloadSHA256)
		if err != nil {
			return zero, err
		}
		if err := writeImmutableObject(storeRoot, fusionProfileRelative, fusionProfileBytes); err != nil {
			return zero, fmt.Errorf("commit fusion profile binding: %w", err)
		}
	}
	fusionProfileName := hybridFusionProfile
	var fusionProfileID, fusionProfileHash string
	var fusionProfileSize int64
	if fusionProfile != nil {
		fusionProfileName = fusionProfile.FusionProfile
		fusionProfileID = fusionProfile.ProfileID
		fusionProfileHash = config.FusionProfileHash
		fusionProfileSize = int64(len(fusionProfileBytes))
	}

	core := HybridCandidateManifestCore{
		SchemaVersion: retrievalSchemaVersion, ManifestKind: "knowledge_hybrid_retrieval_candidate",
		State: "partial", Promotable: false, ServingEligible: false, CurrentEligible: false,
		Lexical: true, Dense: true, Fusion: true, Reranking: true, QualityState: "unevaluated",
		FreshnessState: candidate.FreshnessState, EvaluatedAt: candidate.EvaluatedAt, FreshUntil: candidate.FreshUntil,
		SnapshotManifestID: candidate.SnapshotManifestID, EvidenceManifestID: candidate.EvidenceManifestID,
		Lineages:          candidate.Lineages,
		AdmissionPolicyID: candidate.AdmissionPolicyID, AdmissionPolicySHA256: candidate.AdmissionPolicySHA256,
		SourceAdmissionMethod: candidate.SourceAdmissionMethod, SourceAdmissionPolicyID: candidate.SourceAdmissionPolicyID,
		SourceAdmissionPolicySHA256: candidate.SourceAdmissionPolicySHA256,
		LexicalCandidateID:          candidate.ManifestID, LexicalCandidateSHA256: config.CandidateHash,
		LexicalCandidatePath: candidateRelative, LexicalCandidateByteSize: int64(len(candidateBytes)),
		LexicalIndexID: candidate.LexicalIndexID, LexicalProfile: candidate.LexicalProfile,
		LexicalTokenizerID: candidate.LexicalTokenizerID, LexicalScorerID: candidate.LexicalScorerID,
		DenseArtifactID:     dense.ArtifactID,
		DenseArtifactSHA256: config.DenseArtifactHash, DenseArtifactPath: denseRelative,
		DenseArtifactByteSize: int64(len(denseBytes)), DenseModelID: dense.ModelID,
		DenseModelRevision: dense.ModelRevision, DenseModelArtifactSHA256: dense.ModelArtifactSHA256,
		DenseTokenizerID: dense.TokenizerID, DenseTokenizerSHA256: dense.TokenizerSHA256,
		EmbeddingProfile: dense.EmbeddingProfile, DenseDocumentInstruction: dense.DocumentInstruction,
		VectorEncoding: dense.VectorEncoding, Normalization: dense.Normalization,
		QuantizationScale: dense.QuantizationScale, Dimension: dense.Dimension,
		DocumentCount: dense.DocumentCount, FusionProfile: fusionProfileName,
		FusionProfileID: fusionProfileID, FusionProfileSHA256: fusionProfileHash,
		FusionProfilePath: fusionProfileRelative, FusionProfileByteSize: fusionProfileSize,
		RerankingContract: hybridRerankingContract,
		MissingCapabilities: []string{
			"change_pack", "admitted_dense_model_runtime", "admitted_reranker_model_runtime",
			"held_out_retrieval_evaluation", "signed_generation_promotion",
		},
	}
	coreBytes, _ := json.Marshal(core)
	digest := digestBytes(coreBytes)
	manifest := HybridCandidateManifest{ManifestID: "hybrid-retrieval-candidate:" + digest, ManifestPayloadSHA256: digest, HybridCandidateManifestCore: core}
	manifestBytes, err := marshalDocument(manifest)
	if err != nil {
		return zero, err
	}
	manifestRelative, err := contentObjectPath("hybrid-candidates", digest)
	if err != nil {
		return zero, err
	}
	manifestPath := filepath.Join(storeRoot, filepath.FromSlash(manifestRelative))
	if err := writeImmutableObject(storeRoot, manifestRelative, manifestBytes); err != nil {
		return zero, fmt.Errorf("commit hybrid candidate: %w", err)
	}
	return HybridBuildResult{Manifest: manifest, ManifestPath: manifestPath}, nil
}

func normalizeDenseLimits(documents, dimension int) (int, int, error) {
	if documents == 0 {
		documents = defaultMaxDenseDocuments
	}
	if dimension == 0 {
		dimension = defaultMaxDenseDimension
	}
	if documents < 1 || documents > hardMaxDenseDocuments || dimension < 1 || dimension > hardMaxDenseDimension || int64(dimension) > math.MaxInt64/maxDenseProduct {
		return 0, 0, errors.New("dense limits are outside hard resource bounds")
	}
	return documents, dimension, nil
}

func readBoundLexicalIndex(storeRoot string, candidate CandidateManifest) (LexicalIndex, error) {
	var zero LexicalIndex
	if validateRelativePath(candidate.LexicalIndexPath) != nil || candidate.LexicalIndexByteSize < 1 || candidate.LexicalIndexByteSize > maxIndexBytes {
		return zero, errors.New("lexical index binding is invalid")
	}
	indexPath := filepath.Join(storeRoot, filepath.FromSlash(candidate.LexicalIndexPath))
	if !isWithin(storeRoot, indexPath) {
		return zero, errors.New("lexical index binding escapes store")
	}
	indexBytes, err := verifyFileDigest(indexPath, candidate.LexicalIndexSHA256, candidate.LexicalIndexByteSize)
	if err != nil {
		return zero, errors.New("lexical index binding is unavailable")
	}
	var index LexicalIndex
	if err := decodeStrictCanonical(indexBytes, &index); err != nil || validateIndex(index, candidate) != nil {
		return zero, errors.New("lexical index binding is invalid")
	}
	return index, nil
}

func validateDenseArtifact(dense DenseVectorArtifact, candidate CandidateManifest, index LexicalIndex, maxDocuments, maxDimension int) error {
	coreBytes, err := json.Marshal(dense.DenseVectorArtifactCore)
	if err != nil || dense.ArtifactPayloadSHA256 != digestBytes(coreBytes) || dense.ArtifactID != "dense-vector-artifact:"+dense.ArtifactPayloadSHA256 {
		return errors.New("dense artifact identity mismatch")
	}
	if dense.SchemaVersion != retrievalSchemaVersion || dense.ArtifactKind != "external_dense_document_vectors" || dense.State != "candidate_input" || dense.AuthorityState != "untrusted_candidate_input" {
		return errors.New("dense artifact contract unsupported")
	}
	if dense.LexicalCandidateID != candidate.ManifestID || dense.LexicalIndexID != candidate.LexicalIndexID || dense.EvidenceManifestID != candidate.EvidenceManifestID {
		return errors.New("dense artifact lineage mismatch")
	}
	// Shared multi-authority corpora carry per-authority lineages instead of a
	// single evidence manifest id; the dense artifact must retain them verbatim.
	if !lineagesEqual(dense.Lineages, candidate.Lineages) {
		return errors.New("dense artifact authority lineage mismatch")
	}
	if !boundedMetadata(dense.ModelID) || !boundedMetadata(dense.ModelRevision) || !validSHA256(dense.ModelArtifactSHA256) || !boundedMetadata(dense.TokenizerID) || !validSHA256(dense.TokenizerSHA256) || !boundedMetadata(dense.EmbeddingProfile) || !boundedMetadata(dense.DocumentInstruction) {
		return errors.New("dense model identity is invalid")
	}
	if dense.VectorEncoding != denseVectorEncoding || dense.Normalization != denseVectorNormalization || dense.QuantizationScale != denseQuantizationScale {
		return errors.New("dense vector representation unsupported")
	}
	if dense.Dimension < 1 || dense.Dimension > maxDimension || dense.DocumentCount != len(dense.Documents) || dense.DocumentCount != index.DocumentCount || dense.DocumentCount > maxDocuments {
		return errors.New("dense artifact dimensions or counts are invalid")
	}
	expected := make(map[string]struct{}, len(index.Documents))
	for _, document := range index.Documents {
		expected[document.DocumentID] = struct{}{}
	}
	previous := ""
	for position, document := range dense.Documents {
		if position > 0 && document.DocumentID <= previous {
			return errors.New("dense documents are not in strict document-ID order")
		}
		previous = document.DocumentID
		if _, exists := expected[document.DocumentID]; !exists || len(document.Values) != dense.Dimension {
			return errors.New("dense vector does not bind one exact lexical document")
		}
		if err := validateQuantizedUnitVector(document.Values); err != nil {
			return fmt.Errorf("dense document vector violates normalization contract: %w", err)
		}
		delete(expected, document.DocumentID)
	}
	if len(expected) != 0 {
		return errors.New("dense artifact does not cover the complete lexical document set")
	}
	return nil
}

func validateHybridCandidate(candidate HybridCandidateManifest) error {
	coreBytes, err := json.Marshal(candidate.HybridCandidateManifestCore)
	if err != nil || candidate.ManifestPayloadSHA256 != digestBytes(coreBytes) || candidate.ManifestID != "hybrid-retrieval-candidate:"+candidate.ManifestPayloadSHA256 {
		return errors.New("hybrid candidate identity mismatch")
	}
	if candidate.SchemaVersion != retrievalSchemaVersion || candidate.ManifestKind != "knowledge_hybrid_retrieval_candidate" || candidate.State != "partial" || candidate.Promotable || candidate.ServingEligible || candidate.CurrentEligible || !candidate.Lexical || !candidate.Dense || !candidate.Fusion || !candidate.Reranking || candidate.QualityState != "unevaluated" {
		return errors.New("hybrid candidate capability contract mismatch")
	}
	if candidate.RerankingContract != hybridRerankingContract || candidate.DocumentCount < 1 || candidate.Dimension < 1 || candidate.QuantizationScale != denseQuantizationScale {
		return errors.New("hybrid candidate execution contract invalid")
	}
	switch candidate.FusionProfile {
	case hybridFusionProfile:
		if candidate.FusionProfileID != "" || candidate.FusionProfileSHA256 != "" || candidate.FusionProfilePath != "" || candidate.FusionProfileByteSize != 0 {
			return errors.New("immutable RRF candidate carries challenger lineage")
		}
	case championFusionProfile:
		if !validPrefixedDigest(candidate.FusionProfileID, "fusion-profile:") || !validSHA256(candidate.FusionProfileSHA256) || validateRelativePath(candidate.FusionProfilePath) != nil || candidate.FusionProfileByteSize < 1 || candidate.FusionProfileByteSize > maxFusionProfileBytes {
			return errors.New("challenger fusion profile binding invalid")
		}
	default:
		return errors.New("hybrid candidate fusion profile unsupported")
	}
	if !validSHA256(candidate.LexicalCandidateSHA256) || !validSHA256(candidate.DenseArtifactSHA256) || !validSHA256(candidate.DenseModelArtifactSHA256) || !validSHA256(candidate.DenseTokenizerSHA256) {
		return errors.New("hybrid candidate digest binding invalid")
	}
	if candidate.LexicalProfile == "" {
		if candidate.LexicalTokenizerID != "" || candidate.LexicalScorerID != "" {
			return errors.New("legacy hybrid candidate carries successor lexical lineage")
		}
	} else if !validBM25FLineage(candidate.LexicalProfile, candidate.LexicalTokenizerID, candidate.LexicalScorerID) {
		return errors.New("hybrid candidate lexical profile binding invalid")
	}
	if validateSourceAdmissionBinding(candidate.SourceAdmissionMethod, candidate.SourceAdmissionPolicyID, candidate.SourceAdmissionPolicySHA256) != nil {
		return errors.New("hybrid candidate source admission binding invalid")
	}
	return nil
}

func contentObjectPath(directory, digest string) (string, error) {
	if !validSHA256(digest) {
		return "", errors.New("content identity is not SHA-256")
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return path.Join(directory, "sha256", hexDigest[:2], hexDigest+".json"), nil
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	hexDigest := strings.TrimPrefix(value, "sha256:")
	if strings.ToLower(hexDigest) != hexDigest {
		return false
	}
	_, err := hex.DecodeString(hexDigest)
	return err == nil
}

func validateQuantizedUnitVector(values []int16) error {
	if len(values) < 1 || int64(len(values)) > math.MaxInt64/maxDenseProduct {
		return errors.New("dimension cannot be accumulated safely")
	}
	var squaredNorm int64
	for _, value := range values {
		if value == math.MinInt16 {
			return errors.New("coordinate exceeds symmetric quantization scale")
		}
		coordinate := int64(value)
		term := coordinate * coordinate
		if squaredNorm > math.MaxInt64-term {
			return errors.New("squared norm overflows int64")
		}
		squaredNorm += term
	}
	// Nearest-integer quantization can move the vector norm by at most
	// sqrt(dimension)/2. A full ceil(sqrt(dimension)) allowance is deliberately
	// conservative while still rejecting vectors that merely claim L2
	// normalization.
	deviation := int64(0)
	for deviation*deviation < int64(len(values)) {
		deviation++
	}
	lower := maxDenseCoordinate - deviation
	upper := maxDenseCoordinate + deviation
	if squaredNorm < lower*lower || squaredNorm > upper*upper {
		return errors.New("vector is not L2-unit quantized at the declared scale")
	}
	return nil
}

func boundedMetadata(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == value && len(value) >= 1 && len(value) <= 512
}

// lineagesEqual reports whether two authority lineage sets are identical in order
// and content. AuthorityLineageBinding has only comparable fields, so == is exact.
func lineagesEqual(a, b []AuthorityLineageBinding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
