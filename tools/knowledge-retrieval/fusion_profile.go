package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
)

const (
	championFusionProfile                 = "bounded_lane_champion_rank_sum_int64@1.0.0"
	championFusionProfileKind             = "deterministic_hybrid_fusion_profile"
	championFusionScorerID                = "bounded_lane_champion_rank_sum_int64"
	championFusionScorerRevision          = "1.0.0"
	championFusionArithmetic              = "checked_int64"
	championFusionScale             int64 = 1_000_000
	championFusionLexicalWeight     int64 = 1
	championFusionDenseWeight       int64 = 1
	championFusionMissingLanePolicy       = "fail_closed"
	championFusionTieBreak                = "canonical_span_id_ascending"
	maxFusionProfileBytes           int64 = 1024 * 1024
)

// FusionProfileCore is a caller-authored, immutable execution contract. It
// binds one challenger to the exact lexical and dense inputs, scorer artifact,
// arithmetic and query windows that may execute it. The v1 challenger is
// intentionally fusion-only; reranking remains an independent experiment.
type FusionProfileCore struct {
	SchemaVersion            string `json:"schema_version"`
	ProfileKind              string `json:"profile_kind"`
	State                    string `json:"state"`
	AuthorityState           string `json:"authority_state"`
	FusionProfile            string `json:"fusion_profile"`
	ScorerID                 string `json:"scorer_id"`
	ScorerRevision           string `json:"scorer_revision"`
	ScorerArtifactSHA256     string `json:"scorer_artifact_sha256"`
	LexicalCandidateID       string `json:"lexical_candidate_id"`
	LexicalCandidateSHA256   string `json:"lexical_candidate_document_sha256"`
	LexicalProfile           string `json:"lexical_profile"`
	LexicalTokenizerID       string `json:"lexical_tokenizer_id"`
	LexicalScorerID          string `json:"lexical_scorer_id"`
	DenseArtifactID          string `json:"dense_artifact_id"`
	DenseArtifactSHA256      string `json:"dense_artifact_document_sha256"`
	DenseModelID             string `json:"dense_model_id"`
	DenseModelRevision       string `json:"dense_model_revision"`
	DenseModelArtifactSHA256 string `json:"dense_model_artifact_sha256"`
	DenseTokenizerID         string `json:"dense_tokenizer_id"`
	DenseTokenizerSHA256     string `json:"dense_tokenizer_artifact_sha256"`
	EmbeddingProfile         string `json:"embedding_profile"`
	VectorEncoding           string `json:"vector_encoding"`
	Normalization            string `json:"normalization"`
	QuantizationScale        int    `json:"quantization_scale"`
	Dimension                int    `json:"dimension"`
	FusionWindow             int    `json:"fusion_window"`
	ResultWindow             int    `json:"result_window"`
	RerankWindow             int    `json:"rerank_window"`
	Arithmetic               string `json:"arithmetic"`
	ArithmeticScale          int64  `json:"arithmetic_scale"`
	LexicalWeight            int64  `json:"lexical_weight"`
	DenseWeight              int64  `json:"dense_weight"`
	ChampionBonus            int64  `json:"champion_bonus"`
	MissingLanePolicy        string `json:"missing_lane_policy"`
	TieBreak                 string `json:"tie_break"`
}

type FusionProfile struct {
	ProfileID            string `json:"profile_id"`
	ProfilePayloadSHA256 string `json:"profile_payload_sha256"`
	FusionProfileCore
}

func MaterializeFusionProfile(corePath, storeRoot string) (FusionProfile, string, error) {
	var zero FusionProfile
	if strings.TrimSpace(corePath) == "" || strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("fusion profile core path and store are required")
	}
	coreBytes, err := readStableFile(corePath, "fusion profile core", maxFusionProfileBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read fusion profile core: %w", err)
	}
	var core FusionProfileCore
	if err := decodeStrictCanonical(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode fusion profile core: %w", err)
	}
	profile, err := sealFusionProfile(core)
	if err != nil {
		return zero, "", err
	}
	data, err := marshalDocument(profile)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("fusion-profiles", profile.ProfilePayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkExistingPrefix(root) != nil {
		return zero, "", errors.New("fusion profile store is unavailable")
	}
	if err := writeImmutableObject(root, relative, data); err != nil {
		return zero, "", fmt.Errorf("commit fusion profile: %w", err)
	}
	return profile, filepath.Join(root, filepath.FromSlash(relative)), nil
}

func sealFusionProfile(core FusionProfileCore) (FusionProfile, error) {
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return FusionProfile{}, err
	}
	digest := digestBytes(coreBytes)
	profile := FusionProfile{
		ProfileID:            "fusion-profile:" + digest,
		ProfilePayloadSHA256: digest,
		FusionProfileCore:    core,
	}
	if err := validateFusionProfile(profile); err != nil {
		return FusionProfile{}, fmt.Errorf("fusion profile core is invalid: %w", err)
	}
	return profile, nil
}

func validateFusionProfile(profile FusionProfile) error {
	coreBytes, err := json.Marshal(profile.FusionProfileCore)
	if err != nil || profile.ProfilePayloadSHA256 != digestBytes(coreBytes) || profile.ProfileID != "fusion-profile:"+profile.ProfilePayloadSHA256 {
		return errors.New("fusion profile identity mismatch")
	}
	if profile.SchemaVersion != retrievalSchemaVersion || profile.ProfileKind != championFusionProfileKind || profile.State != "candidate" || profile.AuthorityState != "caller_pinned_candidate_input" {
		return errors.New("fusion profile envelope unsupported")
	}
	if profile.FusionProfile != championFusionProfile || profile.ScorerID != championFusionScorerID || profile.ScorerRevision != championFusionScorerRevision || !validSHA256(profile.ScorerArtifactSHA256) {
		return errors.New("fusion scorer lineage unsupported")
	}
	if !validPrefixedDigest(profile.LexicalCandidateID, "retrieval-candidate:") || !validSHA256(profile.LexicalCandidateSHA256) || !validBM25FLineage(profile.LexicalProfile, profile.LexicalTokenizerID, profile.LexicalScorerID) {
		return errors.New("fusion lexical lineage invalid")
	}
	if !validPrefixedDigest(profile.DenseArtifactID, "dense-vector-artifact:") || !validSHA256(profile.DenseArtifactSHA256) || !boundedMetadata(profile.DenseModelID) || !boundedMetadata(profile.DenseModelRevision) || !validSHA256(profile.DenseModelArtifactSHA256) || !boundedMetadata(profile.DenseTokenizerID) || !validSHA256(profile.DenseTokenizerSHA256) || !boundedMetadata(profile.EmbeddingProfile) {
		return errors.New("fusion dense lineage invalid")
	}
	if profile.VectorEncoding != denseVectorEncoding || profile.Normalization != denseVectorNormalization || profile.QuantizationScale != denseQuantizationScale || profile.Dimension < 1 || profile.Dimension > hardMaxDenseDimension {
		return errors.New("fusion dense arithmetic lineage invalid")
	}
	if profile.FusionWindow < 2 || profile.FusionWindow > 100 || profile.ResultWindow < 2 || profile.ResultWindow > profile.FusionWindow || profile.RerankWindow != 0 {
		return errors.New("fusion windows outside challenger bounds")
	}
	if profile.Arithmetic != championFusionArithmetic || profile.ArithmeticScale != championFusionScale || profile.LexicalWeight != championFusionLexicalWeight || profile.DenseWeight != championFusionDenseWeight {
		return errors.New("fusion arithmetic contract unsupported")
	}
	expectedBonus, err := checkedMultiplyInt64(int64(profile.FusionWindow), profile.ArithmeticScale)
	if err != nil {
		return errors.New("fusion champion bonus overflows")
	}
	expectedBonus, err = checkedMultiplyInt64(expectedBonus, 2)
	if err != nil || profile.ChampionBonus != expectedBonus {
		return errors.New("fusion champion bonus invalid")
	}
	if profile.MissingLanePolicy != championFusionMissingLanePolicy || profile.TieBreak != championFusionTieBreak {
		return errors.New("fusion failure or tie-break policy unsupported")
	}
	// Prove the published hard bounds still fit the selected integer domain.
	maximumBase, err := checkedMultiplyInt64(profile.ArithmeticScale, int64(profile.FusionWindow))
	if err != nil {
		return errors.New("fusion base score overflows")
	}
	maximumBase, err = checkedMultiplyInt64(maximumBase, profile.LexicalWeight+profile.DenseWeight)
	if err != nil {
		return errors.New("fusion weighted score overflows")
	}
	maximumBonus, err := checkedMultiplyInt64(profile.ChampionBonus, 2)
	if err != nil || maximumBase > math.MaxInt64-maximumBonus {
		return errors.New("fusion maximum score overflows")
	}
	return nil
}

func validateFusionProfileLineage(profile FusionProfile, lexical CandidateManifest, lexicalHash string, dense DenseVectorArtifact, denseHash string) error {
	if err := validateFusionProfile(profile); err != nil {
		return err
	}
	if profile.LexicalCandidateID != lexical.ManifestID || profile.LexicalCandidateSHA256 != lexicalHash || profile.LexicalProfile != lexical.LexicalProfile || profile.LexicalTokenizerID != lexical.LexicalTokenizerID || profile.LexicalScorerID != lexical.LexicalScorerID {
		return errors.New("fusion profile mixes lexical lineage")
	}
	if profile.DenseArtifactID != dense.ArtifactID || profile.DenseArtifactSHA256 != denseHash || profile.DenseModelID != dense.ModelID || profile.DenseModelRevision != dense.ModelRevision || profile.DenseModelArtifactSHA256 != dense.ModelArtifactSHA256 || profile.DenseTokenizerID != dense.TokenizerID || profile.DenseTokenizerSHA256 != dense.TokenizerSHA256 || profile.EmbeddingProfile != dense.EmbeddingProfile || profile.VectorEncoding != dense.VectorEncoding || profile.Normalization != dense.Normalization || profile.QuantizationScale != dense.QuantizationScale || profile.Dimension != dense.Dimension {
		return errors.New("fusion profile mixes dense lineage")
	}
	return nil
}

func checkedMultiplyInt64(left, right int64) (int64, error) {
	if left == 0 || right == 0 {
		return 0, nil
	}
	if left == math.MinInt64 && right == -1 || right == math.MinInt64 && left == -1 {
		return 0, errors.New("int64 multiplication overflow")
	}
	result := left * right
	if result/right != left {
		return 0, errors.New("int64 multiplication overflow")
	}
	return result, nil
}
