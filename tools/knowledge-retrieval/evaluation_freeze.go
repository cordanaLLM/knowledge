package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

const (
	scorerBlindFreezeKind      = "retrieval_scorer_blind_multidomain_freeze"
	scorerBlindFreezeVersion   = "1.0.0"
	scorerBlindSpanAlgorithm   = "official-source-line-span@1.0.0"
	scorerBlindAuthoringBasis  = "pinned_official_source_text_only"
	scorerBlindExecutionState  = "blocked_exact_bindings"
	scorerBlindComparisonMode  = "paired_fusion_profiles"
	scorerBlindBaselineProfile = "reciprocal_rank_fusion_k60_int64@1.0.0"
	scorerBlindChallenger      = "bounded_lane_champion_rank_sum_int64@1.0.0"
	maxScorerBlindFreezeBytes  = int64(16 * 1024 * 1024)
	maxScorerBlindSourceBytes  = int64(4 * 1024 * 1024)
	maxScorerBlindSources      = 64
	maxScorerBlindSpans        = 10_000
	maxScorerBlindPayloadBytes = int64(256 * 1024)
)

var scorerBlindRequiredBindings = []string{
	"admission_policy_document_sha256",
	"admission_policy_id",
	"dense_artifact_document_sha256",
	"dense_artifact_id",
	"fusion_profile_document_sha256",
	"fusion_profile_id",
	"hybrid_baseline_candidate_document_sha256",
	"hybrid_baseline_candidate_id",
	"hybrid_challenger_candidate_document_sha256",
	"hybrid_challenger_candidate_id",
	"lexical_candidate_document_sha256",
	"lexical_candidate_id",
	"query_signal_artifacts",
	"scorer_artifact_sha256",
}

var scorerBlindForbiddenInputs = []string{
	"evaluation_metrics",
	"evaluation_results",
	"existing_qrels",
	"existing_thresholds",
	"retrieval_ranks",
	"scorer_outputs",
}

type ScorerBlindFreezeSource struct {
	SourceKey           string `json:"source_key"`
	ComponentID         string `json:"component_id"`
	ComponentVersion    string `json:"component_version"`
	RepositoryURI       string `json:"repository_uri"`
	SourceCommitSHA     string `json:"source_commit_sha"`
	SourcePath          string `json:"source_path"`
	CanonicalSourceURI  string `json:"canonical_source_uri"`
	LicenseExpression   string `json:"license_expression"`
	RawDocumentSHA256   string `json:"raw_document_sha256"`
	RawDocumentByteSize int64  `json:"raw_document_byte_size"`
	SourceObjectPath    string `json:"source_object_path"`
}

type ScorerBlindFreezeSpan struct {
	SpanID            string   `json:"span_id"`
	SourceKey         string   `json:"source_key"`
	HeadingBreadcrumb []string `json:"heading_breadcrumb"`
	RawByteStart      int64    `json:"raw_byte_start"`
	RawByteEnd        int64    `json:"raw_byte_end"`
	RawLineStart      int      `json:"raw_line_start"`
	RawLineEnd        int      `json:"raw_line_end"`
	PayloadSHA256     string   `json:"payload_sha256"`
	PayloadByteSize   int64    `json:"payload_byte_size"`
	PayloadObjectPath string   `json:"payload_object_path"`
}

type ScorerBlindFreezeCase struct {
	CaseID             string                       `json:"case_id"`
	Class              string                       `json:"class"`
	Query              string                       `json:"query"`
	QuerySHA256        string                       `json:"query_sha256"`
	InjectionMarker    string                       `json:"injection_marker,omitempty"`
	RelevanceJudgments []RetrievalRelevanceJudgment `json:"relevance_judgments"`
}

type ScorerBlindFreezeTarget struct {
	ComparisonMode    string `json:"comparison_mode"`
	BaselineProfile   string `json:"baseline_profile"`
	ChallengerProfile string `json:"challenger_profile"`
	MetricAlgorithm   string `json:"metric_algorithm"`
	MetricScale       int64  `json:"metric_scale"`
	CutoffK           int    `json:"cutoff_k"`
	Limit             int    `json:"limit"`
	FusionWindow      int    `json:"fusion_window"`
	RerankWindow      int    `json:"rerank_window"`
}

type ScorerBlindFreezeComparisonGates struct {
	MaximumChallengerRegressionPPM int64 `json:"maximum_challenger_regression_ppm"`
	MinimumChallengerGainPPM       int64 `json:"minimum_challenger_gain_ppm"`
}

type ScorerBlindFreezeProvenance struct {
	AuthoringBasis        string   `json:"authoring_basis"`
	BaseRepositoryCommit  string   `json:"base_repository_commit"`
	ScorerBlind           bool     `json:"scorer_blind"`
	RetrievalExecuted     bool     `json:"retrieval_executed"`
	ScorerExecuted        bool     `json:"scorer_executed"`
	ForbiddenInputClasses []string `json:"forbidden_input_classes"`
}

type ScorerBlindEvaluationFreezeCore struct {
	SchemaVersion         string                            `json:"schema_version"`
	FreezeKind            string                            `json:"freeze_kind"`
	State                 string                            `json:"state"`
	ExecutionState        string                            `json:"execution_state"`
	Name                  string                            `json:"name"`
	Revision              string                            `json:"revision"`
	FrozenAt              string                            `json:"frozen_at"`
	SpanIdentityAlgorithm string                            `json:"span_identity_algorithm"`
	Target                ScorerBlindFreezeTarget           `json:"target"`
	ResourceLimits        RetrievalEvaluationResourceLimits `json:"resource_limits"`
	MaxP95LatencyMillis   int64                             `json:"max_p95_latency_milliseconds"`
	ComparisonGates       ScorerBlindFreezeComparisonGates  `json:"comparison_gates"`
	RequiredExactBindings []string                          `json:"required_exact_bindings"`
	BlockedBindingFields  []string                          `json:"blocked_binding_fields"`
	Provenance            ScorerBlindFreezeProvenance       `json:"provenance"`
	Sources               []ScorerBlindFreezeSource         `json:"sources"`
	Spans                 []ScorerBlindFreezeSpan           `json:"spans"`
	Thresholds            []RetrievalMetricThreshold        `json:"thresholds"`
	Cases                 []ScorerBlindFreezeCase           `json:"cases"`
}

type ScorerBlindEvaluationFreeze struct {
	FreezeID            string `json:"freeze_id"`
	FreezePayloadSHA256 string `json:"freeze_payload_sha256"`
	ScorerBlindEvaluationFreezeCore
}

func MaterializeScorerBlindEvaluationFreeze(corePath, sourceRoot, storeRoot string) (ScorerBlindEvaluationFreeze, string, error) {
	var zero ScorerBlindEvaluationFreeze
	if strings.TrimSpace(corePath) == "" || strings.TrimSpace(sourceRoot) == "" || strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("scorer-blind freeze core, source root and store are required")
	}
	coreBytes, err := readStableFile(corePath, "scorer-blind evaluation freeze core", maxScorerBlindFreezeBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read scorer-blind freeze core: %w", err)
	}
	var core ScorerBlindEvaluationFreezeCore
	if err := decodeStrictCanonical(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode scorer-blind freeze core: %w", err)
	}
	freeze, payloads, err := sealScorerBlindEvaluationFreeze(core, sourceRoot)
	if err != nil {
		return zero, "", err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkExistingPrefix(root) != nil {
		return zero, "", errors.New("scorer-blind freeze store is unavailable")
	}
	for relative, payload := range payloads {
		if err := writeImmutableObject(root, relative, payload); err != nil {
			return zero, "", fmt.Errorf("commit scorer-blind evidence payload: %w", err)
		}
	}
	data, err := marshalDocument(freeze)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("evaluation-freezes", freeze.FreezePayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	if err := writeImmutableObject(root, relative, data); err != nil {
		return zero, "", fmt.Errorf("commit scorer-blind evaluation freeze: %w", err)
	}
	return freeze, filepath.Join(root, filepath.FromSlash(relative)), nil
}

func sealScorerBlindEvaluationFreeze(core ScorerBlindEvaluationFreezeCore, sourceRoot string) (ScorerBlindEvaluationFreeze, map[string][]byte, error) {
	payloads, err := validateScorerBlindEvaluationFreezeCore(core, sourceRoot)
	if err != nil {
		return ScorerBlindEvaluationFreeze{}, nil, fmt.Errorf("scorer-blind evaluation freeze core is invalid: %w", err)
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return ScorerBlindEvaluationFreeze{}, nil, err
	}
	digest := digestBytes(coreBytes)
	return ScorerBlindEvaluationFreeze{
		FreezeID:                        "retrieval-evaluation-freeze:" + digest,
		FreezePayloadSHA256:             digest,
		ScorerBlindEvaluationFreezeCore: core,
	}, payloads, nil
}

func validateScorerBlindEvaluationFreezeCore(core ScorerBlindEvaluationFreezeCore, sourceRoot string) (map[string][]byte, error) {
	if core.SchemaVersion != scorerBlindFreezeVersion || core.FreezeKind != scorerBlindFreezeKind || core.State != "frozen" || core.ExecutionState != scorerBlindExecutionState || core.SpanIdentityAlgorithm != scorerBlindSpanAlgorithm {
		return nil, errors.New("freeze envelope unsupported")
	}
	if !boundedMetadata(core.Name) || !boundedMetadata(core.Revision) {
		return nil, errors.New("freeze name or revision invalid")
	}
	if _, err := parseCanonicalUTC(core.FrozenAt); err != nil {
		return nil, fmt.Errorf("frozen_at: %w", err)
	}
	if core.Target.ComparisonMode != scorerBlindComparisonMode || core.Target.BaselineProfile != scorerBlindBaselineProfile || core.Target.ChallengerProfile != scorerBlindChallenger || core.Target.MetricAlgorithm != metricAlgorithm || core.Target.MetricScale != retrievalMetricScale {
		return nil, errors.New("freeze comparison target unsupported")
	}
	if core.Target.CutoffK < 1 || core.Target.CutoffK > 20 || core.Target.Limit < core.Target.CutoffK || core.Target.Limit > 100 || core.Target.FusionWindow < core.Target.Limit || core.Target.FusionWindow > 100 || core.Target.RerankWindow != 0 {
		return nil, errors.New("freeze retrieval bounds invalid")
	}
	if core.ComparisonGates.MaximumChallengerRegressionPPM != 0 || core.ComparisonGates.MinimumChallengerGainPPM < 0 || core.ComparisonGates.MinimumChallengerGainPPM > retrievalMetricScale {
		return nil, errors.New("freeze challenger comparison gates invalid")
	}
	if !equalStringSlices(core.RequiredExactBindings, scorerBlindRequiredBindings) || !equalStringSlices(core.BlockedBindingFields, scorerBlindRequiredBindings) {
		return nil, errors.New("freeze exact binding barrier changed")
	}
	if core.Provenance.AuthoringBasis != scorerBlindAuthoringBasis || !validGitCommitSHA(core.Provenance.BaseRepositoryCommit) || !core.Provenance.ScorerBlind || core.Provenance.RetrievalExecuted || core.Provenance.ScorerExecuted || !equalStringSlices(core.Provenance.ForbiddenInputClasses, scorerBlindForbiddenInputs) {
		return nil, errors.New("freeze scorer-blind provenance invalid")
	}
	if len(core.Sources) < 3 || len(core.Sources) > maxScorerBlindSources {
		return nil, errors.New("freeze must bind at least three bounded official sources")
	}
	sourceRootAbs, err := filepath.Abs(sourceRoot)
	if err != nil || validateNoSymlinkPath(sourceRootAbs) != nil {
		return nil, errors.New("freeze source root is unavailable")
	}
	sources := make(map[string]ScorerBlindFreezeSource, len(core.Sources))
	sourceBytes := make(map[string][]byte, len(core.Sources))
	components := make(map[string]struct{})
	componentBindings := make(map[string]string)
	sourceCoordinates := make(map[string]struct{})
	previousSource := ""
	for index, source := range core.Sources {
		if !boundedMetadata(source.SourceKey) || !boundedMetadata(source.ComponentID) || !boundedMetadata(source.ComponentVersion) || (index > 0 && source.SourceKey <= previousSource) {
			return nil, errors.New("freeze sources are invalid or not strict source-key order")
		}
		previousSource = source.SourceKey
		if _, exists := sources[source.SourceKey]; exists {
			return nil, errors.New("freeze source key duplicated")
		}
		if !validRepositoryURI(source.RepositoryURI) || !validGitCommitSHA(source.SourceCommitSHA) || validateRelativePath(source.SourcePath) != nil || !validSHA256(source.RawDocumentSHA256) || source.RawDocumentByteSize < 1 || source.RawDocumentByteSize > maxScorerBlindSourceBytes || validateRelativePath(source.SourceObjectPath) != nil {
			return nil, fmt.Errorf("freeze source %s binding invalid", source.SourceKey)
		}
		if source.CanonicalSourceURI != strings.TrimSuffix(source.RepositoryURI, ".git")+"/blob/"+source.SourceCommitSHA+"/"+source.SourcePath {
			return nil, fmt.Errorf("freeze source %s canonical URI is not commit-pinned", source.SourceKey)
		}
		if source.LicenseExpression == "" || strings.TrimSpace(source.LicenseExpression) != source.LicenseExpression {
			return nil, fmt.Errorf("freeze source %s license missing", source.SourceKey)
		}
		componentBinding := source.ComponentVersion + "\x00" + source.RepositoryURI + "\x00" + source.SourceCommitSHA + "\x00" + source.LicenseExpression
		if prior, exists := componentBindings[source.ComponentID]; exists && prior != componentBinding {
			return nil, fmt.Errorf("freeze component %s mixes version or source lineage", source.ComponentID)
		}
		componentBindings[source.ComponentID] = componentBinding
		coordinate := source.RepositoryURI + "\x00" + source.SourceCommitSHA + "\x00" + source.SourcePath
		if _, exists := sourceCoordinates[coordinate]; exists {
			return nil, fmt.Errorf("freeze source coordinate %s is duplicated", source.SourceKey)
		}
		sourceCoordinates[coordinate] = struct{}{}
		expectedPath := scorerBlindSourceObjectPath(source.RawDocumentSHA256)
		if source.SourceObjectPath != expectedPath {
			return nil, fmt.Errorf("freeze source %s is not at its content path", source.SourceKey)
		}
		absolute := filepath.Join(sourceRootAbs, filepath.FromSlash(source.SourceObjectPath))
		if !isWithin(sourceRootAbs, absolute) {
			return nil, fmt.Errorf("freeze source %s escaped source root", source.SourceKey)
		}
		data, err := verifyFileDigest(absolute, source.RawDocumentSHA256, source.RawDocumentByteSize)
		if err != nil {
			return nil, fmt.Errorf("freeze source %s bytes unavailable: %w", source.SourceKey, err)
		}
		sources[source.SourceKey] = source
		sourceBytes[source.SourceKey] = data
		components[source.ComponentID] = struct{}{}
	}
	if len(components) < 3 {
		return nil, errors.New("freeze sources do not cover three distinct components")
	}
	if len(core.Spans) < len(components) || len(core.Spans) > maxScorerBlindSpans {
		return nil, errors.New("freeze span count invalid")
	}
	payloads := make(map[string][]byte, len(core.Spans))
	spans := make(map[string]ScorerBlindFreezeSpan, len(core.Spans))
	coveredComponents := make(map[string]struct{})
	previousSpan := ""
	for index, span := range core.Spans {
		if index > 0 && span.SpanID <= previousSpan {
			return nil, errors.New("freeze spans are not strict span-ID order")
		}
		previousSpan = span.SpanID
		source, exists := sources[span.SourceKey]
		if !exists || span.RawLineStart < 1 || span.RawLineEnd < span.RawLineStart || span.RawByteStart < 0 || span.RawByteEnd <= span.RawByteStart || span.PayloadByteSize < 1 || span.PayloadByteSize > maxScorerBlindPayloadBytes || !validSHA256(span.PayloadSHA256) {
			return nil, fmt.Errorf("freeze span %d binding invalid", index)
		}
		payload, start, end, err := exactInclusiveLineRange(sourceBytes[span.SourceKey], span.RawLineStart, span.RawLineEnd)
		if err != nil || int64(start) != span.RawByteStart || int64(end) != span.RawByteEnd || int64(len(payload)) != span.PayloadByteSize || digestBytes(payload) != span.PayloadSHA256 {
			return nil, fmt.Errorf("freeze span %s source coordinates or payload mismatch", span.SpanID)
		}
		if span.PayloadObjectPath != scorerBlindEvidenceObjectPath(span.PayloadSHA256) {
			return nil, fmt.Errorf("freeze span %s payload is not content-addressed", span.SpanID)
		}
		if span.SpanID != deriveScorerBlindSpanID(source, span) {
			return nil, fmt.Errorf("freeze span %s identity mismatch", span.SpanID)
		}
		if prior, exists := payloads[span.PayloadObjectPath]; exists && !bytes.Equal(prior, payload) {
			return nil, fmt.Errorf("freeze payload identity collision at %s", span.PayloadObjectPath)
		}
		payloads[span.PayloadObjectPath] = payload
		spans[span.SpanID] = span
		coveredComponents[source.ComponentID] = struct{}{}
	}
	if len(coveredComponents) != len(components) {
		return nil, errors.New("freeze evidence does not cover every component")
	}
	classes := make(map[string]struct{})
	caseComponents := make(map[string]struct{})
	judgedSpans := make(map[string]struct{}, len(spans))
	previousCase := ""
	hasInjection := false
	for index, evaluationCase := range core.Cases {
		if !boundedMetadata(evaluationCase.CaseID) || !boundedMetadata(evaluationCase.Class) || strings.TrimSpace(evaluationCase.Query) != evaluationCase.Query || evaluationCase.Query == "" || len(evaluationCase.Query) > 16*1024 || (index > 0 && evaluationCase.CaseID <= previousCase) {
			return nil, errors.New("freeze cases are invalid or not strict case-ID order")
		}
		previousCase = evaluationCase.CaseID
		if evaluationCase.QuerySHA256 != digestBytes([]byte(evaluationCase.Query)) {
			return nil, fmt.Errorf("freeze case %s query digest mismatch", evaluationCase.CaseID)
		}
		if evaluationCase.InjectionMarker != "" {
			if strings.TrimSpace(evaluationCase.InjectionMarker) != evaluationCase.InjectionMarker || !strings.Contains(evaluationCase.Query, evaluationCase.InjectionMarker) {
				return nil, fmt.Errorf("freeze case %s injection marker invalid", evaluationCase.CaseID)
			}
			hasInjection = true
		}
		if len(evaluationCase.RelevanceJudgments) < 1 || len(evaluationCase.RelevanceJudgments) > 1000 {
			return nil, fmt.Errorf("freeze case %s relevance judgment count invalid", evaluationCase.CaseID)
		}
		previousJudgment := ""
		for judgmentIndex, judgment := range evaluationCase.RelevanceJudgments {
			span, exists := spans[judgment.SpanID]
			if !exists || judgment.Grade < 1 || judgment.Grade > 3 || (judgmentIndex > 0 && judgment.SpanID <= previousJudgment) {
				return nil, fmt.Errorf("freeze case %s relevance judgments invalid", evaluationCase.CaseID)
			}
			previousJudgment = judgment.SpanID
			componentID := sources[span.SourceKey].ComponentID
			if componentID != evaluationCase.Class {
				return nil, fmt.Errorf("freeze case %s class does not match its evidence component", evaluationCase.CaseID)
			}
			caseComponents[componentID] = struct{}{}
			judgedSpans[judgment.SpanID] = struct{}{}
		}
		classes[evaluationCase.Class] = struct{}{}
	}
	if len(core.Cases) < 6 || !hasInjection || len(caseComponents) != len(components) || len(judgedSpans) != len(spans) {
		return nil, errors.New("freeze cases lack bounded multi-domain or injection coverage")
	}
	executions := len(core.Cases) * 2
	limits := core.ResourceLimits
	if limits.MaxExecutions != executions || limits.MaxDenseScannedDocuments < executions || limits.MaxDenseScannedDocuments > executions*1_000_000 || limits.MaxReturnedResults != executions*core.Target.Limit || limits.MaxReturnedExcerptBytes != int64(limits.MaxReturnedResults)*8192 || limits.MaxQuerySignalBytes < int64(executions) || limits.MaxQuerySignalBytes > int64(executions)*maxQuerySignalBytes || core.MaxP95LatencyMillis < 1 || core.MaxP95LatencyMillis > 60_000 {
		return nil, errors.New("freeze latency or resource ceilings invalid")
	}
	wantThresholds := len(classes) * 2
	if len(core.Thresholds) != wantThresholds {
		return nil, errors.New("freeze must bind one baseline and challenger threshold per class")
	}
	seenThresholds := make(map[string]struct{}, wantThresholds)
	thresholdByKey := make(map[string]RetrievalMetricThreshold, wantThresholds)
	previousThreshold := ""
	for index, threshold := range core.Thresholds {
		key := threshold.Class + "\x00" + threshold.Profile
		if index > 0 && key <= previousThreshold {
			return nil, errors.New("freeze thresholds are not strict class/profile order")
		}
		previousThreshold = key
		if _, exists := classes[threshold.Class]; !exists || (threshold.Profile != "baseline" && threshold.Profile != "challenger") {
			return nil, errors.New("freeze threshold targets an unknown class or profile")
		}
		for _, value := range []int64{threshold.MinRecallPPM, threshold.MinMRRPPM, threshold.MinNDCGPPM} {
			if value < 1 || value > retrievalMetricScale {
				return nil, errors.New("freeze absolute threshold is outside the fixed metric scale")
			}
		}
		seenThresholds[key] = struct{}{}
		thresholdByKey[key] = threshold
	}
	for class := range classes {
		for _, profile := range []string{"baseline", "challenger"} {
			if _, exists := seenThresholds[class+"\x00"+profile]; !exists {
				return nil, errors.New("freeze threshold coverage incomplete")
			}
		}
		baseline := thresholdByKey[class+"\x00baseline"]
		challenger := thresholdByKey[class+"\x00challenger"]
		if challenger.MinRecallPPM < baseline.MinRecallPPM || challenger.MinMRRPPM < baseline.MinMRRPPM || challenger.MinNDCGPPM < baseline.MinNDCGPPM {
			return nil, errors.New("freeze challenger threshold is weaker than baseline")
		}
	}
	return payloads, nil
}

func exactInclusiveLineRange(data []byte, startLine, endLine int) ([]byte, int, int, error) {
	if startLine < 1 || endLine < startLine {
		return nil, 0, 0, errors.New("invalid line range")
	}
	line := 1
	start := -1
	end := -1
	for index := 0; index <= len(data); index++ {
		if line == startLine && start == -1 {
			start = index
		}
		if index == len(data) {
			if line <= endLine {
				end = index
			}
			break
		}
		if data[index] == '\n' {
			if line == endLine {
				end = index + 1
				break
			}
			line++
		}
	}
	if start < 0 || end < start {
		return nil, 0, 0, errors.New("line range outside source")
	}
	return append([]byte(nil), data[start:end]...), start, end, nil
}

func deriveScorerBlindSpanID(source ScorerBlindFreezeSource, span ScorerBlindFreezeSpan) string {
	payload, _ := json.Marshal(struct {
		Algorithm         string   `json:"algorithm"`
		SourceKey         string   `json:"source_key"`
		ComponentID       string   `json:"component_id"`
		ComponentVersion  string   `json:"component_version"`
		RepositoryURI     string   `json:"repository_uri"`
		SourceCommitSHA   string   `json:"source_commit_sha"`
		SourcePath        string   `json:"source_path"`
		RawDocumentSHA256 string   `json:"raw_document_sha256"`
		HeadingBreadcrumb []string `json:"heading_breadcrumb"`
		RawByteStart      int64    `json:"raw_byte_start"`
		RawByteEnd        int64    `json:"raw_byte_end"`
		RawLineStart      int      `json:"raw_line_start"`
		RawLineEnd        int      `json:"raw_line_end"`
		PayloadSHA256     string   `json:"payload_sha256"`
	}{scorerBlindSpanAlgorithm, source.SourceKey, source.ComponentID, source.ComponentVersion, source.RepositoryURI, source.SourceCommitSHA, source.SourcePath, source.RawDocumentSHA256, span.HeadingBreadcrumb, span.RawByteStart, span.RawByteEnd, span.RawLineStart, span.RawLineEnd, span.PayloadSHA256})
	return "evidence-span:" + digestBytes(payload)
}

func scorerBlindSourceObjectPath(digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return "invalid"
	}
	return path.Join("source-blobs", "sha256", hexDigest[:2], hexDigest)
}

func scorerBlindEvidenceObjectPath(digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return "invalid"
	}
	return path.Join("evaluation-evidence", "sha256", hexDigest[:2], hexDigest)
}
