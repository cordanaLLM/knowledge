package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CurrentQueryConfig intentionally has no candidate, generation or pointer
// selector. The only selectable corpus is the exact generation reached through
// the verified signed current-pointer chain.
type CurrentQueryConfig struct {
	StoreRoot           string
	StateRoot           string
	EvidenceStoreRoot   string
	AdmissionPolicyPath string
	AdmissionPolicyHash string
	Query               string
	PrincipalScope      string
	AsOf                string
	Limit               int
	MaxExcerptBytes     int
}

type CurrentQueryResponse struct {
	State                   string     `json:"state"`
	ResultState             string     `json:"result_state"`
	AuthorityState          string     `json:"authority_state"`
	Profile                 string     `json:"profile"`
	LexicalProfile          string     `json:"lexical_profile,omitempty"`
	LexicalTokenizerID      string     `json:"lexical_tokenizer_id,omitempty"`
	LexicalScorerID         string     `json:"lexical_scorer_id,omitempty"`
	ServingEligible         bool       `json:"serving_eligible"`
	CurrentEligible         bool       `json:"current_eligible"`
	PointerID               string     `json:"pointer_id,omitempty"`
	PointerRevision         int        `json:"pointer_revision,omitempty"`
	TransitionReceiptID     string     `json:"transition_receipt_id,omitempty"`
	CurrentGenerationID     string     `json:"current_generation_id,omitempty"`
	CurrentGenerationSHA256 string     `json:"current_generation_document_sha256,omitempty"`
	GenerationCreatedAt     string     `json:"generation_created_at,omitempty"`
	QualityReportID         string     `json:"quality_report_id,omitempty"`
	EvaluationDatasetID     string     `json:"evaluation_dataset_id,omitempty"`
	EvaluationMetricsID     string     `json:"evaluation_metrics_id,omitempty"`
	CandidateManifestID     string     `json:"candidate_manifest_id,omitempty"`
	FreshnessState          string     `json:"freshness_state,omitempty"`
	QueryTerms              []string   `json:"query_terms,omitempty"`
	Results                 []QueryHit `json:"results"`
	ErrorCode               string     `json:"error_code,omitempty"`
}

// CurrentQuery performs the independently evaluated lexical profile through a
// signed current generation. It is read-only: pointer consistency is checked
// optimistically before and after retrieval instead of creating the lifecycle
// lock file.
func CurrentQuery(config CurrentQueryConfig) (CurrentQueryResponse, error) {
	base := CurrentQueryResponse{
		State: "backend_unavailable", ResultState: "backend_unavailable",
		AuthorityState: "unavailable", Profile: "lexical", Results: []QueryHit{},
	}
	for name, value := range map[string]string{
		"store": config.StoreRoot, "state": config.StateRoot, "evidence-store": config.EvidenceStoreRoot,
		"admission-policy": config.AdmissionPolicyPath, "admission-policy-sha256": config.AdmissionPolicyHash,
		"query": config.Query, "principal-scope": config.PrincipalScope, "as-of": config.AsOf,
	} {
		if strings.TrimSpace(value) == "" {
			return base, fmt.Errorf("%s is required", name)
		}
	}
	if !validSHA256(config.AdmissionPolicyHash) {
		return base, errors.New("admission-policy-sha256 must be a canonical SHA-256")
	}
	if config.Limit < 1 || config.Limit > 100 {
		return base, errors.New("limit must be between 1 and 100")
	}
	if config.MaxExcerptBytes < 1 || config.MaxExcerptBytes > 8192 {
		return base, errors.New("max-excerpt-bytes must be between 1 and 8192")
	}
	if _, err := parseCanonicalUTC(config.AsOf); err != nil {
		return base, fmt.Errorf("as-of: %w", err)
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkPath(storeRoot) != nil {
		base.ErrorCode = "retrieval-store-unavailable"
		return base, nil
	}
	stateRoot, err := filepath.Abs(config.StateRoot)
	if err != nil || validateNoSymlinkPath(stateRoot) != nil {
		base.ErrorCode = "state-root-unavailable"
		return base, nil
	}
	evidenceRoot, err := filepath.Abs(config.EvidenceStoreRoot)
	if err != nil || validateNoSymlinkPath(evidenceRoot) != nil {
		base.ErrorCode = "evidence-store-unavailable"
		return base, nil
	}

	pointer, pointerBytes, err := validateCurrentGenerationState(stateRoot, storeRoot, true)
	if err != nil {
		base.ErrorCode = lifecycleCode(err)
		return base, nil
	}
	generation, _, err := loadStateGeneration(stateRoot, storeRoot, pointer.CurrentGenerationID, pointer.CurrentGenerationSHA256)
	if err != nil {
		base.ErrorCode = lifecycleCode(err)
		return base, nil
	}
	policy, _, err := loadCurrentAdmissionPolicy(config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.AsOf)
	if err != nil || !generationMatchesPolicy(generation, policy, config.AdmissionPolicyHash) {
		base.ErrorCode = "current-policy-invalid"
		return base, nil
	}
	if err := verifyCurrentQueryExecutable(generation); err != nil {
		base.ErrorCode = "retrieval-executable-mismatch"
		return base, nil
	}

	hybridPath := filepath.Join(storeRoot, filepath.FromSlash(generation.HybridCandidatePath))
	if !isWithin(storeRoot, hybridPath) {
		base.ErrorCode = "current-generation-path-invalid"
		return base, nil
	}
	loaded, code := loadHybridCandidate(HybridQueryConfig{
		HybridCandidatePath: hybridPath, HybridCandidateHash: generation.HybridCandidateSHA256,
		StoreRoot: storeRoot,
	})
	if code != "" || loaded.hybrid.ManifestID != generation.HybridCandidateID || loaded.hybrid.LexicalCandidateID != generation.LexicalCandidateID || loaded.hybrid.LexicalCandidateSHA256 != generation.LexicalCandidateSHA256 || loaded.hybrid.LexicalProfile != generation.LexicalProfile || loaded.hybrid.LexicalTokenizerID != generation.LexicalTokenizerID || loaded.hybrid.LexicalScorerID != generation.LexicalScorerID || pointer.CurrentLexicalProfile != generation.LexicalProfile || pointer.CurrentLexicalTokenizerID != generation.LexicalTokenizerID || pointer.CurrentLexicalScorerID != generation.LexicalScorerID {
		base.ErrorCode = "current-generation-lineage-invalid"
		return base, nil
	}
	candidatePath := filepath.Join(storeRoot, filepath.FromSlash(loaded.hybrid.LexicalCandidatePath))
	if !isWithin(storeRoot, candidatePath) {
		base.ErrorCode = "current-candidate-path-invalid"
		return base, nil
	}

	queryResponse, err := Query(QueryConfig{
		CandidatePath: candidatePath, CandidateHash: generation.LexicalCandidateSHA256,
		StoreRoot: storeRoot, EvidenceStoreRoot: evidenceRoot,
		AdmissionPolicyPath: config.AdmissionPolicyPath, AdmissionPolicyHash: config.AdmissionPolicyHash,
		Query: config.Query, PrincipalScope: config.PrincipalScope, AsOf: config.AsOf,
		Limit: config.Limit, MaxExcerptBytes: config.MaxExcerptBytes,
	})
	if err != nil {
		return base, err
	}

	afterPointer, afterBytes, err := validateCurrentGenerationState(stateRoot, storeRoot, true)
	if err != nil || afterPointer.PointerID != pointer.PointerID || !bytes.Equal(afterBytes, pointerBytes) {
		base.ErrorCode = "pointer-changed-during-query"
		return base, nil
	}
	if queryResponse.CandidateManifestID != generation.LexicalCandidateID || queryResponse.LexicalProfile != generation.LexicalProfile {
		base.ErrorCode = "current-candidate-lineage-invalid"
		return base, nil
	}

	base.State = "current"
	base.LexicalProfile = generation.LexicalProfile
	base.LexicalTokenizerID = generation.LexicalTokenizerID
	base.LexicalScorerID = generation.LexicalScorerID
	base.ResultState = queryResponse.ResultState
	base.AuthorityState = "evaluated_current"
	base.CurrentEligible = true
	base.ServingEligible = queryResponse.ResultState != "backend_unavailable" && queryResponse.ResultState != "stale"
	base.PointerID = pointer.PointerID
	base.PointerRevision = pointer.Revision
	base.TransitionReceiptID = pointer.TransitionReceiptID
	base.CurrentGenerationID = generation.GenerationID
	base.CurrentGenerationSHA256 = pointer.CurrentGenerationSHA256
	base.GenerationCreatedAt = generation.CreatedAt
	base.QualityReportID = generation.QualityReportID
	base.EvaluationDatasetID = generation.EvaluationDatasetID
	base.EvaluationMetricsID = generation.EvaluationMetricsObjectID
	base.CandidateManifestID = queryResponse.CandidateManifestID
	base.FreshnessState = queryResponse.FreshnessState
	base.QueryTerms = queryResponse.QueryTerms
	base.Results = queryResponse.Results
	base.ErrorCode = queryResponse.ErrorCode
	if !base.ServingEligible {
		base.Results = []QueryHit{}
	}
	return base, nil
}

func verifyCurrentQueryExecutable(generation RetrievalGeneration) error {
	runningPath, err := os.Executable()
	if err != nil {
		return err
	}
	runningBytes, err := readStableFile(runningPath, "running retrieval executable", maxExecutableBytes)
	if err != nil || digestBytes(runningBytes) != generation.RetrievalExecutableSHA256 {
		return errors.New("running retrieval executable was not evaluated by the current generation")
	}
	return nil
}
