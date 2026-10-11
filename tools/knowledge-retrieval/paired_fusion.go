package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pairedFusionSuiteKind      = "retrieval_candidate_bound_paired_fusion_suite"
	pairedFusionExecutionState = "blocked_unaccepted_source_authority"
	pairedFusionBaselineRole   = "baseline"
	pairedFusionChallengerRole = "challenger"
	pairedFusionBaselineID     = "reciprocal_rank_fusion_k60_int64"
	pairedFusionBaselineRev    = "1.0.0"
	maxPairedFusionSuiteBytes  = int64(16 * 1024 * 1024)
	maxPairedFusionCases       = 256
	maxPairedFusionSources     = 1_024
	maxPairedFusionSpans       = 2_048
	maxPairedFusionInputCount  = 4_096
	maxPairedFusionInputBytes  = int64(512 * 1024 * 1024)

	hardMaxPairedExecutions            = 4_096
	hardMaxPairedScannedDocuments      = 16_000_000
	hardMaxPairedInputDocuments        = 1_000_000
	hardMaxPairedInputBytes            = int64(512 * 1024 * 1024)
	hardMaxPairedReturnedResults       = 25_600
	hardMaxPairedReturnedExcerptBytes  = int64(512 * 1024 * 1024)
	hardMaxPairedQuerySignalBytes      = int64(128 * 1024 * 1024)
	hardMaxPairedExecutionMilliseconds = int64(600_000)
	hardMaxPairedPeakRSSBytes          = int64(16 * 1024 * 1024 * 1024)
)

var pairedFusionRequiredGates = []string{
	"citation_lineage",
	"deterministic_replay",
	"exact_input",
	"latency",
	"prompt_injection",
	"protected_class_non_regression",
	"quality_gain",
	"resource",
}

// PairedFusionArtifactBinding identifies one immutable input and its exact
// path within the root selected by its surrounding field. Paths are data, not
// command-line overrides: a runner may read only the bytes sealed here.
type PairedFusionArtifactBinding struct {
	ArtifactID     string `json:"artifact_id"`
	DocumentSHA256 string `json:"document_sha256"`
	ObjectPath     string `json:"object_path"`
	ByteSize       int64  `json:"byte_size"`
}

type PairedFusionScorerBinding struct {
	ScorerID           string `json:"scorer_id"`
	ScorerRevision     string `json:"scorer_revision"`
	ExecutableSHA256   string `json:"executable_sha256"`
	ExecutableByteSize int64  `json:"executable_byte_size"`
}

type PairedFusionArmBinding struct {
	Role                  string                       `json:"role"`
	FusionProfile         string                       `json:"fusion_profile"`
	HybridCandidate       PairedFusionArtifactBinding  `json:"hybrid_candidate"`
	Scorer                PairedFusionScorerBinding    `json:"scorer"`
	FusionProfileArtifact *PairedFusionArtifactBinding `json:"fusion_profile_artifact,omitempty"`
}

type PairedFusionSourceBinding struct {
	SourcePath      string `json:"source_path"`
	SourceCommitSHA string `json:"source_commit_sha"`
	RawSHA256       string `json:"raw_sha256"`
	RawByteSize     int64  `json:"raw_byte_size"`
	RawObjectPath   string `json:"raw_object_path"`
}

type PairedFusionSpanBinding struct {
	SpanID            string `json:"span_id"`
	SourcePath        string `json:"source_path"`
	RawLineStart      int    `json:"raw_line_start"`
	RawLineEnd        int    `json:"raw_line_end"`
	PayloadSHA256     string `json:"payload_sha256"`
	PayloadByteSize   int64  `json:"payload_byte_size"`
	PayloadObjectPath string `json:"payload_object_path"`
}

type PairedFusionLineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type PairedFusionSourceJudgment struct {
	SourcePath      string                  `json:"source_path"`
	SourceCommitSHA string                  `json:"source_commit_sha"`
	Ranges          []PairedFusionLineRange `json:"ranges"`
	ExcerptSHA256   string                  `json:"excerpt_sha256"`
	Grade           int                     `json:"grade"`
	MappedSpanIDs   []string                `json:"mapped_span_ids"`
}

type PairedFusionCaseSignals struct {
	Baseline   PairedFusionArtifactBinding `json:"baseline"`
	Challenger PairedFusionArtifactBinding `json:"challenger"`
}

type PairedFusionCase struct {
	CaseID                  string                       `json:"case_id"`
	Class                   string                       `json:"class"`
	Query                   string                       `json:"query"`
	QuerySHA256             string                       `json:"query_sha256"`
	ProtectedClass          bool                         `json:"protected_class"`
	InjectionMarker         string                       `json:"injection_marker,omitempty"`
	InjectionMarkerSHA256   string                       `json:"injection_marker_sha256,omitempty"`
	InjectionMarkerLocation string                       `json:"injection_marker_location,omitempty"`
	Signals                 PairedFusionCaseSignals      `json:"signals"`
	SourceJudgments         []PairedFusionSourceJudgment `json:"source_judgments"`
	RelevanceJudgments      []RetrievalRelevanceJudgment `json:"relevance_judgments"`
}

type PairedFusionTarget struct {
	ComparisonMode    string `json:"comparison_mode"`
	BaselineProfile   string `json:"baseline_profile"`
	ChallengerProfile string `json:"challenger_profile"`
	MetricAlgorithm   string `json:"metric_algorithm"`
	MetricScale       int64  `json:"metric_scale"`
	CutoffK           int    `json:"cutoff_k"`
	Limit             int    `json:"limit"`
	FusionWindow      int    `json:"fusion_window"`
	RerankWindow      int    `json:"rerank_window"`
	MaxExcerptBytes   int    `json:"max_excerpt_bytes"`
}

type PairedFusionComparisonGates struct {
	MinimumRecallGainPPM       int64    `json:"minimum_recall_gain_ppm"`
	MinimumMRRGainPPM          int64    `json:"minimum_mrr_gain_ppm"`
	MinimumNDCGGainPPM         int64    `json:"minimum_ndcg_gain_ppm"`
	MaximumProtectedRegression int64    `json:"maximum_protected_regression_ppm"`
	MinimumCasesPerClass       int      `json:"minimum_cases_per_class"`
	RequiredGates              []string `json:"required_gates"`
}

type PairedFusionResourceLimits struct {
	MaxExecutions                   int   `json:"max_executions"`
	MaxScannedDocuments             int   `json:"max_scanned_documents"`
	MaxInputDocumentsPerExecution   int   `json:"max_input_documents_per_execution"`
	MaxInputBytesPerExecution       int64 `json:"max_input_bytes_per_execution"`
	MaxReturnedResults              int   `json:"max_returned_results"`
	MaxReturnedExcerptBytes         int64 `json:"max_returned_excerpt_bytes"`
	MaxQuerySignalBytes             int64 `json:"max_query_signal_bytes"`
	MaxWallMillisecondsPerExecution int64 `json:"max_wall_milliseconds_per_execution"`
	MaxCPUMillisecondsPerExecution  int64 `json:"max_cpu_milliseconds_per_execution"`
	MaxPeakRSSBytes                 int64 `json:"max_peak_rss_bytes"`
}

type PairedFusionSuiteCore struct {
	SchemaVersion    string                      `json:"schema_version"`
	SuiteKind        string                      `json:"suite_kind"`
	State            string                      `json:"state"`
	ExecutionState   string                      `json:"execution_state"`
	Name             string                      `json:"name"`
	Revision         string                      `json:"revision"`
	FrozenAt         string                      `json:"frozen_at"`
	Target           PairedFusionTarget          `json:"target"`
	ComparisonGates  PairedFusionComparisonGates `json:"comparison_gates"`
	ResourceLimits   PairedFusionResourceLimits  `json:"resource_limits"`
	SnapshotManifest PairedFusionArtifactBinding `json:"snapshot_manifest"`
	EvidenceManifest PairedFusionArtifactBinding `json:"evidence_manifest"`
	AdmissionPolicy  PairedFusionArtifactBinding `json:"admission_policy"`
	LexicalCandidate PairedFusionArtifactBinding `json:"lexical_candidate"`
	LexicalIndex     PairedFusionArtifactBinding `json:"lexical_index"`
	DenseArtifact    PairedFusionArtifactBinding `json:"dense_artifact"`
	Arms             []PairedFusionArmBinding    `json:"arms"`
	Sources          []PairedFusionSourceBinding `json:"sources"`
	Spans            []PairedFusionSpanBinding   `json:"spans"`
	Cases            []PairedFusionCase          `json:"cases"`
}

type PairedFusionSuite struct {
	SuiteID            string `json:"suite_id"`
	SuitePayloadSHA256 string `json:"suite_payload_sha256"`
	PairedFusionSuiteCore
}

type PreparePairedFusionRunConfig struct {
	SuitePath            string
	SuiteHash            string
	RetrievalStoreRoot   string
	SnapshotStoreRoot    string
	EvidenceStoreRoot    string
	QuerySignalStoreRoot string
	BaselineScorerPath   string
	BaselineScorerHash   string
	ChallengerScorerPath string
	ChallengerScorerHash string
}

// PairedFusionRunPlan is deliberately non-authoritative. This rollback unit
// proves that an exact execution can start atomically, but does not retrieve,
// score, evaluate, sign, stage or mutate anything.
type PairedFusionRunPlan struct {
	State               string `json:"state"`
	ExecutionAuthorized bool   `json:"execution_authorized"`
	SuiteID             string `json:"suite_id"`
	SuiteSHA256         string `json:"suite_document_sha256"`
	CaseCount           int    `json:"case_count"`
	PlannedExecutions   int    `json:"planned_executions"`
}

func MaterializePairedFusionSuite(corePath, storeRoot string) (PairedFusionSuite, string, error) {
	var zero PairedFusionSuite
	if strings.TrimSpace(corePath) == "" || strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("paired fusion suite core path and store are required")
	}
	data, err := readStableFile(corePath, "paired fusion suite core", maxPairedFusionSuiteBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read paired fusion suite core: %w", err)
	}
	var core PairedFusionSuiteCore
	if err := decodeStrictCanonical(data, &core); err != nil {
		return zero, "", fmt.Errorf("decode paired fusion suite core: %w", err)
	}
	suite, err := sealPairedFusionSuite(core)
	if err != nil {
		return zero, "", fmt.Errorf("seal paired fusion suite: %w", err)
	}
	document, err := marshalDocument(suite)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("paired-fusion-suites", suite.SuitePayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkExistingPrefix(root) != nil {
		return zero, "", errors.New("paired fusion suite store is unavailable")
	}
	if err := writeImmutableObject(root, relative, document); err != nil {
		return zero, "", fmt.Errorf("commit paired fusion suite: %w", err)
	}
	return suite, filepath.Join(root, filepath.FromSlash(relative)), nil
}

func sealPairedFusionSuite(core PairedFusionSuiteCore) (PairedFusionSuite, error) {
	if err := validatePairedFusionSuiteCore(core); err != nil {
		return PairedFusionSuite{}, err
	}
	data, err := json.Marshal(core)
	if err != nil {
		return PairedFusionSuite{}, err
	}
	digest := digestBytes(data)
	return PairedFusionSuite{
		SuiteID:               "paired-fusion-suite:" + digest,
		SuitePayloadSHA256:    digest,
		PairedFusionSuiteCore: core,
	}, nil
}

func validatePairedFusionSuite(suite PairedFusionSuite) error {
	data, err := json.Marshal(suite.PairedFusionSuiteCore)
	if err != nil || suite.SuitePayloadSHA256 != digestBytes(data) || suite.SuiteID != "paired-fusion-suite:"+suite.SuitePayloadSHA256 {
		return errors.New("paired fusion suite identity mismatch")
	}
	return validatePairedFusionSuiteCore(suite.PairedFusionSuiteCore)
}

func validatePairedFusionSuiteCore(core PairedFusionSuiteCore) error {
	if core.SchemaVersion != retrievalSchemaVersion || core.SuiteKind != pairedFusionSuiteKind || core.State != "frozen" || core.ExecutionState != pairedFusionExecutionState {
		return errors.New("paired fusion suite envelope unsupported")
	}
	if !boundedMetadata(core.Name) || !boundedMetadata(core.Revision) {
		return errors.New("paired fusion suite name or revision invalid")
	}
	if _, err := parseCanonicalUTC(core.FrozenAt); err != nil {
		return fmt.Errorf("paired fusion frozen_at: %w", err)
	}
	if core.Target.ComparisonMode != "paired_fusion_profiles" || core.Target.BaselineProfile != hybridFusionProfile || core.Target.ChallengerProfile != championFusionProfile || core.Target.MetricAlgorithm != metricAlgorithm || core.Target.MetricScale != retrievalMetricScale {
		return errors.New("paired fusion target unsupported")
	}
	if core.Target.CutoffK < 1 || core.Target.Limit < core.Target.CutoffK || core.Target.Limit > 100 || core.Target.FusionWindow < core.Target.Limit || core.Target.FusionWindow > 100 || core.Target.RerankWindow != 0 || core.Target.MaxExcerptBytes < 1 || core.Target.MaxExcerptBytes > 8192 {
		return errors.New("paired fusion target bounds invalid")
	}
	if core.ComparisonGates.MinimumRecallGainPPM < 0 || core.ComparisonGates.MinimumMRRGainPPM < 0 || core.ComparisonGates.MinimumNDCGGainPPM < 0 || core.ComparisonGates.MaximumProtectedRegression != 0 || core.ComparisonGates.MinimumCasesPerClass < 1 || !equalStringSlices(core.ComparisonGates.RequiredGates, pairedFusionRequiredGates) {
		return errors.New("paired fusion comparison gates invalid")
	}
	for _, item := range []struct {
		label   string
		binding PairedFusionArtifactBinding
		prefix  string
		maximum int64
	}{
		{"snapshot manifest", core.SnapshotManifest, "snapshot-manifest:", maxManifestBytes},
		{"evidence manifest", core.EvidenceManifest, "evidence-manifest:", maxManifestBytes},
		{"admission policy", core.AdmissionPolicy, "retrieval-admission:", maxPolicyBytes},
		{"lexical candidate", core.LexicalCandidate, "retrieval-candidate:", maxManifestBytes},
		{"lexical index", core.LexicalIndex, "lexical-index:", maxIndexBytes},
		{"dense artifact", core.DenseArtifact, "dense-vector-artifact:", maxDenseArtifactBytes},
	} {
		if err := validatePairedArtifactBinding(item.binding, item.prefix, item.maximum); err != nil {
			return fmt.Errorf("%s binding: %w", item.label, err)
		}
	}
	if len(core.Arms) != 2 || core.Arms[0].Role != pairedFusionBaselineRole || core.Arms[1].Role != pairedFusionChallengerRole {
		return errors.New("paired fusion arms must be strict baseline/challenger order")
	}
	baseline, challenger := core.Arms[0], core.Arms[1]
	if baseline.FusionProfile != hybridFusionProfile || baseline.Scorer.ScorerID != pairedFusionBaselineID || baseline.Scorer.ScorerRevision != pairedFusionBaselineRev || baseline.FusionProfileArtifact != nil {
		return errors.New("paired fusion baseline arm invalid")
	}
	if challenger.FusionProfile != championFusionProfile || challenger.Scorer.ScorerID != championFusionScorerID || challenger.Scorer.ScorerRevision != championFusionScorerRevision || challenger.FusionProfileArtifact == nil {
		return errors.New("paired fusion challenger arm invalid")
	}
	for _, arm := range core.Arms {
		if err := validatePairedArtifactBinding(arm.HybridCandidate, "hybrid-retrieval-candidate:", maxManifestBytes); err != nil || !validSHA256(arm.Scorer.ExecutableSHA256) || arm.Scorer.ExecutableByteSize < 1 || arm.Scorer.ExecutableByteSize > maxExecutableBytes {
			return fmt.Errorf("paired fusion %s arm binding invalid", arm.Role)
		}
	}
	if err := validatePairedArtifactBinding(*challenger.FusionProfileArtifact, "fusion-profile:", maxFusionProfileBytes); err != nil {
		return fmt.Errorf("paired fusion challenger profile binding invalid: %w", err)
	}
	if samePairedArtifact(baseline.HybridCandidate, challenger.HybridCandidate) {
		return errors.New("paired fusion arms must bind distinct candidates")
	}
	if len(core.Sources) < 1 || len(core.Sources) > maxPairedFusionSources || len(core.Spans) < 1 || len(core.Spans) > maxPairedFusionSpans || len(core.Cases) < 1 || len(core.Cases) > maxPairedFusionCases {
		return errors.New("paired fusion source, span or case count invalid")
	}
	sourcePaths := make(map[string]PairedFusionSourceBinding, len(core.Sources))
	previous := ""
	for index, source := range core.Sources {
		if validateRelativePath(source.SourcePath) != nil || !validGitCommitSHA(source.SourceCommitSHA) || !validSHA256(source.RawSHA256) || source.RawByteSize < 1 || source.RawByteSize > maxManifestBytes || validateRelativePath(source.RawObjectPath) != nil || (index > 0 && source.SourcePath <= previous) {
			return errors.New("paired fusion sources invalid or not strict path order")
		}
		previous = source.SourcePath
		sourcePaths[source.SourcePath] = source
	}
	spanIDs := make(map[string]PairedFusionSpanBinding, len(core.Spans))
	previous = ""
	for index, span := range core.Spans {
		if !validPrefixedDigest(span.SpanID, "evidence-span:") || (index > 0 && span.SpanID <= previous) || sourcePaths[span.SourcePath].SourcePath == "" || span.RawLineStart < 1 || span.RawLineEnd < span.RawLineStart || !validSHA256(span.PayloadSHA256) || span.PayloadByteSize < 1 || span.PayloadByteSize > defaultMaxPayloadBytes || validateRelativePath(span.PayloadObjectPath) != nil {
			return errors.New("paired fusion spans invalid or not strict SpanID order")
		}
		previous = span.SpanID
		spanIDs[span.SpanID] = span
	}
	classes := make(map[string]int)
	usedSpans := make(map[string]struct{})
	usedSources := make(map[string]struct{})
	previous = ""
	hasInjection := false
	for index, evaluationCase := range core.Cases {
		if !boundedMetadata(evaluationCase.CaseID) || !boundedMetadata(evaluationCase.Class) || strings.TrimSpace(evaluationCase.Query) != evaluationCase.Query || evaluationCase.Query == "" || evaluationCase.QuerySHA256 != digestBytes([]byte(evaluationCase.Query)) || (index > 0 && evaluationCase.CaseID <= previous) || !evaluationCase.ProtectedClass {
			return errors.New("paired fusion cases invalid or not strict case-ID order")
		}
		previous = evaluationCase.CaseID
		if err := validatePairedArtifactBinding(evaluationCase.Signals.Baseline, "query-signal-artifact:", maxQuerySignalBytes); err != nil {
			return fmt.Errorf("paired fusion case %s baseline signal: %w", evaluationCase.CaseID, err)
		}
		if err := validatePairedArtifactBinding(evaluationCase.Signals.Challenger, "query-signal-artifact:", maxQuerySignalBytes); err != nil {
			return fmt.Errorf("paired fusion case %s challenger signal: %w", evaluationCase.CaseID, err)
		}
		if samePairedArtifact(evaluationCase.Signals.Baseline, evaluationCase.Signals.Challenger) {
			return fmt.Errorf("paired fusion case %s reuses one signal across arms", evaluationCase.CaseID)
		}
		if evaluationCase.InjectionMarker != "" {
			if evaluationCase.InjectionMarkerSHA256 != digestBytes([]byte(evaluationCase.InjectionMarker)) || (evaluationCase.InjectionMarkerLocation != "query" && evaluationCase.InjectionMarkerLocation != "source_excerpt") {
				return fmt.Errorf("paired fusion case %s injection marker invalid", evaluationCase.CaseID)
			}
			hasInjection = true
		} else if evaluationCase.InjectionMarkerSHA256 != "" || evaluationCase.InjectionMarkerLocation != "" {
			return fmt.Errorf("paired fusion case %s carries partial injection marker", evaluationCase.CaseID)
		}
		if len(evaluationCase.SourceJudgments) < 1 || len(evaluationCase.RelevanceJudgments) < 1 {
			return fmt.Errorf("paired fusion case %s lacks judgments", evaluationCase.CaseID)
		}
		caseSpans := make(map[string]int)
		previousJudgmentSource := ""
		for _, judgment := range evaluationCase.SourceJudgments {
			if sourcePaths[judgment.SourcePath].SourcePath == "" || sourcePaths[judgment.SourcePath].SourceCommitSHA != judgment.SourceCommitSHA || judgment.SourcePath <= previousJudgmentSource || judgment.Grade < 1 || judgment.Grade > 3 || !validSHA256(judgment.ExcerptSHA256) || len(judgment.Ranges) < 1 || len(judgment.MappedSpanIDs) < 1 {
				return fmt.Errorf("paired fusion case %s source judgment invalid", evaluationCase.CaseID)
			}
			previousJudgmentSource = judgment.SourcePath
			usedSources[judgment.SourcePath] = struct{}{}
			lastEnd := 0
			for _, lineRange := range judgment.Ranges {
				if lineRange.Start < 1 || lineRange.End < lineRange.Start || lineRange.Start <= lastEnd {
					return fmt.Errorf("paired fusion case %s source ranges overlap or are unordered", evaluationCase.CaseID)
				}
				lastEnd = lineRange.End
			}
			lastSpan := ""
			for _, spanID := range judgment.MappedSpanIDs {
				span, exists := spanIDs[spanID]
				if !exists || span.SourcePath != judgment.SourcePath || spanID <= lastSpan {
					return fmt.Errorf("paired fusion case %s mapped spans invalid", evaluationCase.CaseID)
				}
				lastSpan = spanID
				caseSpans[spanID] = judgment.Grade
				usedSpans[spanID] = struct{}{}
			}
		}
		lastSpan := ""
		if len(caseSpans) != len(evaluationCase.RelevanceJudgments) {
			return fmt.Errorf("paired fusion case %s relevance judgments do not match mappings", evaluationCase.CaseID)
		}
		for _, judgment := range evaluationCase.RelevanceJudgments {
			mappedGrade, known := caseSpans[judgment.SpanID]
			if !validPrefixedDigest(judgment.SpanID, "evidence-span:") || !known || judgment.Grade < 1 || judgment.Grade > 3 || judgment.SpanID <= lastSpan || mappedGrade != judgment.Grade {
				return fmt.Errorf("paired fusion case %s relevance judgment mismatch", evaluationCase.CaseID)
			}
			lastSpan = judgment.SpanID
		}
		classes[evaluationCase.Class]++
	}
	if !hasInjection || len(usedSpans) != len(core.Spans) || len(usedSources) != len(core.Sources) {
		return errors.New("paired fusion suite lacks injection coverage or its source/span denominator is not exact")
	}
	for _, count := range classes {
		if count < core.ComparisonGates.MinimumCasesPerClass {
			return errors.New("paired fusion class case minimum not met")
		}
	}
	// Limits are per profile so the baseline and challenger receive identical
	// ceilings and one arm cannot consume the other's budget.
	executions := int64(len(core.Cases))
	limits := core.ResourceLimits
	if limits.MaxExecutions < 1 || limits.MaxExecutions > hardMaxPairedExecutions ||
		limits.MaxScannedDocuments < 1 || limits.MaxScannedDocuments > hardMaxPairedScannedDocuments ||
		limits.MaxInputDocumentsPerExecution < 1 || limits.MaxInputDocumentsPerExecution > hardMaxPairedInputDocuments ||
		limits.MaxInputBytesPerExecution < 1 || limits.MaxInputBytesPerExecution > hardMaxPairedInputBytes ||
		limits.MaxReturnedResults < 1 || limits.MaxReturnedResults > hardMaxPairedReturnedResults ||
		limits.MaxReturnedExcerptBytes < 1 || limits.MaxReturnedExcerptBytes > hardMaxPairedReturnedExcerptBytes ||
		limits.MaxQuerySignalBytes < 1 || limits.MaxQuerySignalBytes > hardMaxPairedQuerySignalBytes ||
		limits.MaxWallMillisecondsPerExecution < 1 || limits.MaxWallMillisecondsPerExecution > hardMaxPairedExecutionMilliseconds ||
		limits.MaxCPUMillisecondsPerExecution < 1 || limits.MaxCPUMillisecondsPerExecution > hardMaxPairedExecutionMilliseconds ||
		limits.MaxPeakRSSBytes < 1 || limits.MaxPeakRSSBytes > hardMaxPairedPeakRSSBytes {
		return errors.New("paired fusion resource limits exceed hard bounds")
	}
	scannedMinimum, ok := checkedPairedProduct(executions, int64(limits.MaxInputDocumentsPerExecution))
	if !ok {
		return errors.New("paired fusion scanned-document resource bound overflow")
	}
	returnedMinimum, ok := checkedPairedProduct(executions, int64(core.Target.Limit))
	if !ok {
		return errors.New("paired fusion returned-result resource bound overflow")
	}
	excerptMinimum, ok := checkedPairedProduct(int64(limits.MaxReturnedResults), int64(core.Target.MaxExcerptBytes))
	if !ok {
		return errors.New("paired fusion returned-excerpt resource bound overflow")
	}
	baselineSignalBytes, challengerSignalBytes := int64(0), int64(0)
	for _, evaluationCase := range core.Cases {
		if !checkedPairedAdd(&baselineSignalBytes, evaluationCase.Signals.Baseline.ByteSize, hardMaxPairedQuerySignalBytes) ||
			!checkedPairedAdd(&challengerSignalBytes, evaluationCase.Signals.Challenger.ByteSize, hardMaxPairedQuerySignalBytes) {
			return errors.New("paired fusion query-signal resource bound overflow")
		}
	}
	if int64(limits.MaxExecutions) < executions || int64(limits.MaxScannedDocuments) < scannedMinimum || int64(limits.MaxReturnedResults) < returnedMinimum || limits.MaxReturnedExcerptBytes < excerptMinimum || limits.MaxQuerySignalBytes < baselineSignalBytes || limits.MaxQuerySignalBytes < challengerSignalBytes {
		return errors.New("paired fusion resource limits cannot cover the frozen execution")
	}
	if err := validatePairedFusionInputBudget(core, maxPairedFusionSuiteBytes); err != nil {
		return err
	}
	return nil
}

func checkedPairedProduct(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || (right != 0 && left > int64(^uint64(0)>>1)/right) {
		return 0, false
	}
	return left * right, true
}

func checkedPairedAdd(total *int64, value, maximum int64) bool {
	if value < 0 || *total < 0 || value > maximum || *total > maximum-value {
		return false
	}
	*total += value
	return true
}

func validatePairedFusionInputBudget(core PairedFusionSuiteCore, suiteBytes int64) error {
	count, total := 0, int64(0)
	add := func(size int64) bool {
		if count >= maxPairedFusionInputCount || !checkedPairedAdd(&total, size, maxPairedFusionInputBytes) {
			return false
		}
		count++
		return true
	}
	if !add(suiteBytes) {
		return errors.New("paired fusion aggregate preflight input budget exceeded")
	}
	for _, binding := range []PairedFusionArtifactBinding{
		core.SnapshotManifest, core.EvidenceManifest, core.AdmissionPolicy,
		core.LexicalCandidate, core.LexicalIndex, core.DenseArtifact,
		core.Arms[0].HybridCandidate, core.Arms[1].HybridCandidate,
		*core.Arms[1].FusionProfileArtifact,
	} {
		if !add(binding.ByteSize) {
			return errors.New("paired fusion aggregate preflight input budget exceeded")
		}
	}
	for _, source := range core.Sources {
		if !add(source.RawByteSize) {
			return errors.New("paired fusion aggregate preflight input budget exceeded")
		}
	}
	for _, span := range core.Spans {
		if !add(span.PayloadByteSize) {
			return errors.New("paired fusion aggregate preflight input budget exceeded")
		}
	}
	for _, evaluationCase := range core.Cases {
		if !add(evaluationCase.Signals.Baseline.ByteSize) || !add(evaluationCase.Signals.Challenger.ByteSize) {
			return errors.New("paired fusion aggregate preflight input budget exceeded")
		}
	}
	for _, arm := range core.Arms {
		if !add(arm.Scorer.ExecutableByteSize) {
			return errors.New("paired fusion aggregate preflight input budget exceeded")
		}
	}
	return nil
}

func validatePairedArtifactBinding(binding PairedFusionArtifactBinding, prefix string, maximum int64) error {
	if strings.TrimSpace(binding.ArtifactID) != binding.ArtifactID || binding.ArtifactID == "" || (prefix != "" && !validPrefixedDigest(binding.ArtifactID, prefix)) || !validSHA256(binding.DocumentSHA256) || validateRelativePath(binding.ObjectPath) != nil || binding.ByteSize < 1 || binding.ByteSize > maximum {
		return errors.New("artifact identity, digest, path or size invalid")
	}
	return nil
}

func samePairedArtifact(left, right PairedFusionArtifactBinding) bool {
	return left.ArtifactID == right.ArtifactID || left.DocumentSHA256 == right.DocumentSHA256 || left.ObjectPath == right.ObjectPath
}

func PreparePairedFusionRun(config PreparePairedFusionRunConfig) (PairedFusionRunPlan, error) {
	var zero PairedFusionRunPlan
	if !validSHA256(config.SuiteHash) || !validSHA256(config.BaselineScorerHash) || !validSHA256(config.ChallengerScorerHash) {
		return zero, errors.New("paired fusion caller pins are required")
	}
	suiteBytes, err := readStableFile(config.SuitePath, "paired fusion suite", maxPairedFusionSuiteBytes)
	if err != nil || digestBytes(suiteBytes) != config.SuiteHash {
		return zero, errors.New("paired fusion suite bytes do not match the caller pin")
	}
	var suite PairedFusionSuite
	if err := decodeStrictCanonical(suiteBytes, &suite); err != nil || validatePairedFusionSuite(suite) != nil {
		return zero, errors.New("paired fusion suite is invalid")
	}
	roots, err := pairedFusionRoots(config)
	if err != nil {
		return zero, err
	}
	if err := validatePairedFusionInputBudget(suite.PairedFusionSuiteCore, int64(len(suiteBytes))); err != nil {
		return zero, err
	}
	// Read and hash every declared byte input before interpreting any of it.
	artifacts := make(map[string][]byte)
	for _, input := range pairedFusionReadPlan(suite, roots) {
		data, readErr := readPairedArtifact(input.root, input.binding)
		if readErr != nil {
			return zero, fmt.Errorf("paired fusion %s unavailable: %w", input.label, readErr)
		}
		artifacts[input.label] = data
	}
	baselineScorer, err := readStableFile(config.BaselineScorerPath, "baseline scorer", suite.Arms[0].Scorer.ExecutableByteSize)
	if err != nil || int64(len(baselineScorer)) != suite.Arms[0].Scorer.ExecutableByteSize || digestBytes(baselineScorer) != config.BaselineScorerHash || config.BaselineScorerHash != suite.Arms[0].Scorer.ExecutableSHA256 {
		return zero, errors.New("paired fusion baseline scorer bytes do not match the suite and caller pins")
	}
	challengerScorer, err := readStableFile(config.ChallengerScorerPath, "challenger scorer", suite.Arms[1].Scorer.ExecutableByteSize)
	if err != nil || int64(len(challengerScorer)) != suite.Arms[1].Scorer.ExecutableByteSize || digestBytes(challengerScorer) != config.ChallengerScorerHash || config.ChallengerScorerHash != suite.Arms[1].Scorer.ExecutableSHA256 {
		return zero, errors.New("paired fusion challenger scorer bytes do not match the suite and caller pins")
	}
	if err := validatePairedFusionBytes(suite, artifacts); err != nil {
		return zero, err
	}
	return PairedFusionRunPlan{
		State: "preflight_complete_no_execution", ExecutionAuthorized: false,
		SuiteID: suite.SuiteID, SuiteSHA256: config.SuiteHash,
		CaseCount: len(suite.Cases), PlannedExecutions: len(suite.Cases) * 2,
	}, nil
}

type pairedFusionRootSet struct{ retrieval, snapshot, evidence, signals string }

type pairedFusionReadInput struct {
	label   string
	root    string
	binding PairedFusionArtifactBinding
}

func pairedFusionReadPlan(suite PairedFusionSuite, roots pairedFusionRootSet) []pairedFusionReadInput {
	inputs := []pairedFusionReadInput{
		{"snapshot", roots.snapshot, suite.SnapshotManifest},
		{"evidence", roots.evidence, suite.EvidenceManifest},
		{"admission", roots.retrieval, suite.AdmissionPolicy},
		{"lexical", roots.retrieval, suite.LexicalCandidate},
		{"index", roots.retrieval, suite.LexicalIndex},
		{"dense", roots.retrieval, suite.DenseArtifact},
		{"baseline candidate", roots.retrieval, suite.Arms[0].HybridCandidate},
		{"challenger candidate", roots.retrieval, suite.Arms[1].HybridCandidate},
		{"challenger profile", roots.retrieval, *suite.Arms[1].FusionProfileArtifact},
	}
	for _, source := range suite.Sources {
		inputs = append(inputs, pairedFusionReadInput{
			"source " + source.SourcePath,
			roots.snapshot,
			PairedFusionArtifactBinding{ArtifactID: "raw:" + source.RawSHA256, DocumentSHA256: source.RawSHA256, ObjectPath: source.RawObjectPath, ByteSize: source.RawByteSize},
		})
	}
	for _, span := range suite.Spans {
		inputs = append(inputs, pairedFusionReadInput{
			"span " + span.SpanID,
			roots.evidence,
			PairedFusionArtifactBinding{ArtifactID: "normalized:" + span.PayloadSHA256, DocumentSHA256: span.PayloadSHA256, ObjectPath: span.PayloadObjectPath, ByteSize: span.PayloadByteSize},
		})
	}
	for _, evaluationCase := range suite.Cases {
		inputs = append(inputs,
			pairedFusionReadInput{"baseline signal " + evaluationCase.CaseID, roots.signals, evaluationCase.Signals.Baseline},
			pairedFusionReadInput{"challenger signal " + evaluationCase.CaseID, roots.signals, evaluationCase.Signals.Challenger},
		)
	}
	return inputs
}

func pairedFusionRoots(config PreparePairedFusionRunConfig) (pairedFusionRootSet, error) {
	values := []*string{&config.RetrievalStoreRoot, &config.SnapshotStoreRoot, &config.EvidenceStoreRoot, &config.QuerySignalStoreRoot}
	for _, value := range values {
		root, err := filepath.Abs(strings.TrimSpace(*value))
		if err != nil || validateNoSymlinkPath(root) != nil {
			return pairedFusionRootSet{}, errors.New("paired fusion input root is unavailable")
		}
		*value = root
	}
	return pairedFusionRootSet{config.RetrievalStoreRoot, config.SnapshotStoreRoot, config.EvidenceStoreRoot, config.QuerySignalStoreRoot}, nil
}

func readPairedArtifact(root string, binding PairedFusionArtifactBinding) ([]byte, error) {
	absolute := filepath.Join(root, filepath.FromSlash(binding.ObjectPath))
	if !isWithin(root, absolute) {
		return nil, errors.New("artifact path escaped its root")
	}
	return verifyFileDigest(absolute, binding.DocumentSHA256, binding.ByteSize)
}

func validatePairedFusionBytes(suite PairedFusionSuite, artifacts map[string][]byte) error {
	var snapshot SnapshotManifest
	var evidence EvidenceManifest
	var policy AdmissionPolicy
	var lexical CandidateManifest
	var index LexicalIndex
	var dense DenseVectorArtifact
	var baseline, challenger HybridCandidateManifest
	var profile FusionProfile
	decodes := []struct {
		label string
		into  any
	}{
		{"snapshot", &snapshot}, {"evidence", &evidence}, {"admission", &policy}, {"lexical", &lexical},
		{"index", &index}, {"dense", &dense}, {"baseline candidate", &baseline}, {"challenger candidate", &challenger},
		{"challenger profile", &profile},
	}
	for _, item := range decodes {
		if err := decodeStrictCanonical(artifacts[item.label], item.into); err != nil {
			return fmt.Errorf("paired fusion %s is not strict canonical JSON: %w", item.label, err)
		}
	}
	if snapshot.ManifestID != suite.SnapshotManifest.ArtifactID || evidence.ManifestID != suite.EvidenceManifest.ArtifactID || policy.PolicyID != suite.AdmissionPolicy.ArtifactID || lexical.ManifestID != suite.LexicalCandidate.ArtifactID || index.IndexID != suite.LexicalIndex.ArtifactID || dense.ArtifactID != suite.DenseArtifact.ArtifactID || baseline.ManifestID != suite.Arms[0].HybridCandidate.ArtifactID || challenger.ManifestID != suite.Arms[1].HybridCandidate.ArtifactID || profile.ProfileID != suite.Arms[1].FusionProfileArtifact.ArtifactID {
		return errors.New("paired fusion decoded artifact identity differs from suite binding")
	}
	if err := validateSnapshotAndEvidenceIdentities(snapshot, evidence); err != nil {
		return err
	}
	if err := validateMaterializedAdmissionPolicy(policy); err != nil || len(validateAdmissionPolicy(policy, evidence, snapshot, policy.EvaluatedAt)) != 0 {
		return errors.New("paired fusion retrieval lineage validation failed")
	}
	evaluatedAt, evaluatedErr := parseCanonicalUTC(policy.EvaluatedAt)
	frozenAt, frozenErr := parseCanonicalUTC(suite.FrozenAt)
	freshUntil, freshErr := parseCanonicalUTC(policy.FreshUntil)
	if evaluatedErr != nil || frozenErr != nil || freshErr != nil || evaluatedAt.After(frozenAt) || frozenAt.After(freshUntil) {
		return errors.New("paired fusion frozen time is outside the exact admission-policy validity interval")
	}
	if policy.SnapshotManifestID != snapshot.ManifestID || policy.EvidenceManifestID != evidence.ManifestID || lexical.SnapshotManifestID != snapshot.ManifestID || lexical.EvidenceManifestID != evidence.ManifestID || lexical.AdmissionPolicyID != policy.PolicyID || lexical.AdmissionPolicySHA256 != suite.AdmissionPolicy.DocumentSHA256 || lexical.EvaluatedAt != policy.EvaluatedAt || lexical.FreshUntil != policy.FreshUntil || lexical.SourceAdmissionMethod != snapshot.ReviewAdmission.AdmissionMethod || lexical.SourceAdmissionPolicyID != snapshot.ReviewAdmission.AdmissionPolicyID || lexical.SourceAdmissionPolicySHA256 != snapshot.ReviewAdmission.AdmissionPolicySHA256 {
		return errors.New("paired fusion admission, snapshot, evidence and lexical lineage mixed")
	}
	commonBindings := hybridLineageBindings{
		lexical: hybridDocumentBinding{path: suite.LexicalCandidate.ObjectPath, digest: suite.LexicalCandidate.DocumentSHA256, size: suite.LexicalCandidate.ByteSize},
		index:   hybridDocumentBinding{path: suite.LexicalIndex.ObjectPath, digest: suite.LexicalIndex.DocumentSHA256, size: suite.LexicalIndex.ByteSize},
		dense:   hybridDocumentBinding{path: suite.DenseArtifact.ObjectPath, digest: suite.DenseArtifact.DocumentSHA256, size: suite.DenseArtifact.ByteSize},
	}
	if err := validateLoadedHybridLineage(baseline, lexical, index, dense, nil, commonBindings); err != nil {
		return fmt.Errorf("paired fusion baseline candidate lineage invalid: %w", err)
	}
	challengerBindings := commonBindings
	challengerBindings.fusion = &hybridDocumentBinding{path: suite.Arms[1].FusionProfileArtifact.ObjectPath, digest: suite.Arms[1].FusionProfileArtifact.DocumentSHA256, size: suite.Arms[1].FusionProfileArtifact.ByteSize}
	if err := validateLoadedHybridLineage(challenger, lexical, index, dense, &profile, challengerBindings); err != nil {
		return fmt.Errorf("paired fusion challenger candidate lineage invalid: %w", err)
	}
	for _, item := range []struct {
		role      string
		candidate HybridCandidateManifest
	}{{"baseline", baseline}, {"challenger", challenger}} {
		if item.candidate.LexicalCandidateID != lexical.ManifestID || item.candidate.LexicalCandidateSHA256 != suite.LexicalCandidate.DocumentSHA256 || item.candidate.LexicalCandidatePath != suite.LexicalCandidate.ObjectPath || item.candidate.LexicalCandidateByteSize != suite.LexicalCandidate.ByteSize || item.candidate.LexicalIndexID != index.IndexID || lexical.LexicalIndexPath != suite.LexicalIndex.ObjectPath || lexical.LexicalIndexSHA256 != suite.LexicalIndex.DocumentSHA256 || lexical.LexicalIndexByteSize != suite.LexicalIndex.ByteSize || item.candidate.DenseArtifactID != dense.ArtifactID || item.candidate.DenseArtifactSHA256 != suite.DenseArtifact.DocumentSHA256 || item.candidate.DenseArtifactPath != suite.DenseArtifact.ObjectPath || item.candidate.DenseArtifactByteSize != suite.DenseArtifact.ByteSize || item.candidate.AdmissionPolicyID != policy.PolicyID || item.candidate.AdmissionPolicySHA256 != suite.AdmissionPolicy.DocumentSHA256 {
			return fmt.Errorf("paired fusion %s candidate mixes common lineage", item.role)
		}
	}
	if baseline.FusionProfile != hybridFusionProfile || challenger.FusionProfile != championFusionProfile || challenger.FusionProfileID != profile.ProfileID || challenger.FusionProfileSHA256 != suite.Arms[1].FusionProfileArtifact.DocumentSHA256 || challenger.FusionProfilePath != suite.Arms[1].FusionProfileArtifact.ObjectPath || challenger.FusionProfileByteSize != suite.Arms[1].FusionProfileArtifact.ByteSize || profile.ScorerArtifactSHA256 != suite.Arms[1].Scorer.ExecutableSHA256 || profile.FusionWindow != suite.Target.FusionWindow || profile.ResultWindow != suite.Target.Limit || profile.RerankWindow != suite.Target.RerankWindow {
		return errors.New("paired fusion candidate/profile/scorer lineage mismatch")
	}
	sourceBindings, spanBindings, err := validatePairedEvidenceLineage(suite, snapshot, evidence, policy, index, artifacts)
	if err != nil {
		return err
	}
	for _, evaluationCase := range suite.Cases {
		if err := validatePairedCaseBytes(suite, evaluationCase, baseline, challenger, dense, artifacts, sourceBindings, spanBindings); err != nil {
			return err
		}
	}
	return nil
}

// validatePairedEvidenceLineage keeps two denominators explicit. The manifest
// denominator is every snapshot/evidence file and span; it is checked for
// complete metadata, identity, order and aggregate consistency without opening
// undeclared content. The paired judged denominator is the suite's selected
// sources and spans; it must equal the judgments exactly and is checked against
// the raw and normalized bytes that the deterministic read plan already pinned
// and read. Semantic validation never reopens a store object.
func validatePairedEvidenceLineage(suite PairedFusionSuite, snapshot SnapshotManifest, evidence EvidenceManifest, policy AdmissionPolicy, index LexicalIndex, artifacts map[string][]byte) (map[string]PairedFusionSourceBinding, map[string]PairedFusionSpanBinding, error) {
	fail := func(message string) (map[string]PairedFusionSourceBinding, map[string]PairedFusionSpanBinding, error) {
		return nil, nil, errors.New(message)
	}
	if snapshot.FileCount != len(snapshot.Files) || evidence.FileCount != len(evidence.Files) || snapshot.FileCount != evidence.FileCount {
		return fail("paired fusion snapshot/evidence file denominator mismatch")
	}

	snapshotFiles := make(map[string]SnapshotFile, len(snapshot.Files))
	uniqueRaw := make(map[string]int64)
	var snapshotBytes int64
	previousPath := ""
	for position, file := range snapshot.Files {
		if validateRelativePath(file.RelativePath) != nil || (position > 0 && file.RelativePath <= previousPath) || !validSHA256(file.SHA256) || file.Size < 0 || file.RawBlobID != "raw:"+file.SHA256 || file.ObjectPath != rawObjectRelativePath(file.SHA256) || validateRelativePath(file.ObjectPath) != nil || file.SnapshotID != snapshot.SnapshotID || file.SourceID != snapshot.Source.SourceID || file.ComponentID != snapshot.Source.ComponentID || file.ComponentVersionID != snapshot.Source.ComponentVersionID || file.ChannelID != snapshot.Source.ChannelID {
			return fail("paired fusion snapshot file lineage invalid")
		}
		previousPath = file.RelativePath
		if _, exists := snapshotFiles[file.RelativePath]; exists {
			return fail("paired fusion snapshot file denominator contains duplicates")
		}
		snapshotFiles[file.RelativePath] = file
		if prior, exists := uniqueRaw[file.SHA256]; exists && prior != file.Size {
			return fail("paired fusion snapshot raw identity has inconsistent sizes")
		}
		uniqueRaw[file.SHA256] = file.Size
		if !checkedPairedAdd(&snapshotBytes, file.Size, defaultMaxTotalBytes) {
			return fail("paired fusion snapshot byte denominator overflow")
		}
	}
	if snapshotBytes != snapshot.ByteSize || len(uniqueRaw) != snapshot.UniqueBlobCount {
		return fail("paired fusion snapshot aggregate lineage mismatch")
	}

	evidenceFiles := make(map[string]EvidenceFile, len(evidence.Files))
	evidenceSpans := make(map[string]struct {
		file EvidenceFile
		span EvidenceSpan
	})
	uniquePayloads := make(map[string]int64)
	spanCount := 0
	var rawBytes, logicalBytes int64
	previousPath = ""
	for position, file := range evidence.Files {
		if position > 0 && file.RelativePath <= previousPath {
			return fail("paired fusion evidence files are not in strict path order")
		}
		previousPath = file.RelativePath
		snapshotFile, exists := snapshotFiles[file.RelativePath]
		if !exists || file.OccurrenceID != occurrenceIdentity(snapshot.ManifestID, snapshotFile) || file.MediaType != snapshotFile.MediaType || file.RawSHA256 != snapshotFile.SHA256 || file.RawBlobID != snapshotFile.RawBlobID || file.RawObjectPath != snapshotFile.ObjectPath || file.RawByteSize != snapshotFile.Size || file.SnapshotID != snapshot.SnapshotID || file.SourceID != snapshot.Source.SourceID || file.ComponentID != snapshot.Source.ComponentID || file.ComponentVersionID != snapshot.Source.ComponentVersionID || file.ChannelID != snapshot.Source.ChannelID || file.TrustEnvelopeID != evidence.TrustEnvelope.EnvelopeID || !boundedMetadata(file.ParserVersion) || !boundedMetadata(file.ProfileVersion) {
			return fail("paired fusion evidence occurrence/source/component/version/channel/trust lineage invalid")
		}
		if _, duplicate := evidenceFiles[file.RelativePath]; duplicate {
			return fail("paired fusion evidence file denominator contains duplicates")
		}
		evidenceFiles[file.RelativePath] = file
		if !checkedPairedAdd(&rawBytes, file.RawByteSize, defaultMaxTotalBytes) {
			return fail("paired fusion evidence raw-byte denominator overflow")
		}
		previousEnd := int64(0)
		for ordinal, span := range file.Spans {
			spanCount++
			if span.Ordinal != ordinal || span.RawByteStart != previousEnd || span.RawByteEnd < span.RawByteStart || span.RawByteEnd > file.RawByteSize || span.ByteSize != span.RawByteEnd-span.RawByteStart || span.ByteSize > defaultMaxPayloadBytes || span.RawLineStart < 1 || span.RawLineEnd < span.RawLineStart || !validSHA256(span.PayloadSHA256) || span.PayloadID != "normalized:"+span.PayloadSHA256 || span.ObjectPath != normalizedObjectRelativePath(span.PayloadSHA256) || validateRelativePath(span.ObjectPath) != nil || span.TrustEnvelopeID != evidence.TrustEnvelope.EnvelopeID || span.SpanID != spanIdentity(file.OccurrenceID, file.ParserVersion, file.ProfileVersion, span) {
				return fail("paired fusion evidence span ordinal, partition, identity, payload path or trust lineage invalid")
			}
			previousEnd = span.RawByteEnd
			if _, duplicate := evidenceSpans[span.SpanID]; duplicate {
				return fail("paired fusion evidence span denominator contains duplicates")
			}
			evidenceSpans[span.SpanID] = struct {
				file EvidenceFile
				span EvidenceSpan
			}{file: file, span: span}
			if prior, exists := uniquePayloads[span.PayloadSHA256]; exists && prior != span.ByteSize {
				return fail("paired fusion evidence payload identity has inconsistent sizes")
			}
			uniquePayloads[span.PayloadSHA256] = span.ByteSize
			if !checkedPairedAdd(&logicalBytes, span.ByteSize, defaultMaxTotalBytes) {
				return fail("paired fusion evidence logical-byte denominator overflow")
			}
		}
		if previousEnd != file.RawByteSize {
			return fail("paired fusion evidence spans do not form a full raw-byte partition")
		}
	}
	if len(evidenceFiles) != len(snapshotFiles) || spanCount != evidence.SpanCount || rawBytes != evidence.RawByteSize || logicalBytes != evidence.LogicalOutputByteSize || len(uniquePayloads) != evidence.UniquePayloadCount {
		return fail("paired fusion evidence source/span denominator aggregate mismatch")
	}
	var uniquePayloadBytes int64
	for _, size := range uniquePayloads {
		if !checkedPairedAdd(&uniquePayloadBytes, size, defaultMaxTotalBytes) {
			return fail("paired fusion unique-payload denominator overflow")
		}
	}
	if uniquePayloadBytes != evidence.UniquePayloadByteSize {
		return fail("paired fusion unique-payload byte denominator mismatch")
	}

	indexBySpan := make(map[string]IndexedDocument, len(index.Documents))
	for _, document := range index.Documents {
		if _, duplicate := indexBySpan[document.Evidence.SpanID]; duplicate {
			return fail("paired fusion lexical index contains a duplicate SpanID")
		}
		indexBySpan[document.Evidence.SpanID] = document
	}
	declaredSources := make(map[string]PairedFusionSourceBinding, len(suite.Sources))
	declaredSpans := make(map[string]PairedFusionSpanBinding, len(suite.Spans))
	spansBySource := make(map[string]int)
	for _, source := range suite.Sources {
		snapshotFile, snapshotOK := snapshotFiles[source.SourcePath]
		evidenceFile, evidenceOK := evidenceFiles[source.SourcePath]
		raw := artifacts["source "+source.SourcePath]
		if !snapshotOK || !evidenceOK || snapshotFile.SHA256 != source.RawSHA256 || snapshotFile.Size != source.RawByteSize || snapshotFile.ObjectPath != source.RawObjectPath || evidenceFile.RawSHA256 != source.RawSHA256 || evidenceFile.RawObjectPath != source.RawObjectPath || evidenceFile.RawByteSize != source.RawByteSize || snapshot.Source.SourceRevision != source.SourceCommitSHA || int64(len(raw)) != source.RawByteSize || digestBytes(raw) != source.RawSHA256 {
			return fail("paired fusion declared source does not match exact snapshot/evidence/raw lineage")
		}
		for _, span := range evidenceFile.Spans {
			startLine, endLine := spanLines(raw, int(span.RawByteStart), int(span.RawByteEnd))
			if span.RawLineStart != startLine || span.RawLineEnd != endLine {
				return fail("paired fusion evidence span line coordinates do not match exact raw bytes")
			}
		}
		declaredSources[source.SourcePath] = source
	}
	for _, binding := range suite.Spans {
		lineage, exists := evidenceSpans[binding.SpanID]
		if !exists || lineage.file.RelativePath != binding.SourcePath || lineage.span.RawLineStart != binding.RawLineStart || lineage.span.RawLineEnd != binding.RawLineEnd || lineage.span.PayloadSHA256 != binding.PayloadSHA256 || lineage.span.ByteSize != binding.PayloadByteSize || lineage.span.ObjectPath != binding.PayloadObjectPath {
			return fail("paired fusion declared span does not match exact evidence lineage")
		}
		raw := artifacts["source "+binding.SourcePath]
		payload := artifacts["span "+binding.SpanID]
		if int64(len(payload)) != binding.PayloadByteSize || digestBytes(payload) != binding.PayloadSHA256 || lineage.span.RawByteStart < 0 || lineage.span.RawByteEnd > int64(len(raw)) || !bytes.Equal(payload, raw[lineage.span.RawByteStart:lineage.span.RawByteEnd]) {
			return fail("paired fusion normalized payload is not the exact declared raw slice")
		}
		document, indexed := indexBySpan[binding.SpanID]
		expectedRef := evidenceReference(snapshot, evidence, policy, lineage.file, lineage.span)
		expectedRefBytes, _ := json.Marshal(expectedRef)
		indexedRefBytes, _ := json.Marshal(document.Evidence)
		if !indexed || !bytes.Equal(expectedRefBytes, indexedRefBytes) || document.DocumentID != "lexical-document:"+digestBytes(expectedRefBytes) {
			return fail("paired fusion judged SpanID is absent from or mismatched in the lexical index")
		}
		declaredSpans[binding.SpanID] = binding
		spansBySource[binding.SourcePath]++
	}
	for sourcePath := range declaredSources {
		if spansBySource[sourcePath] == 0 {
			return fail("paired fusion declared source has no exact declared span")
		}
	}

	referencedSources := make(map[string]struct{})
	referencedSpans := make(map[string]struct{})
	for _, evaluationCase := range suite.Cases {
		for _, judgment := range evaluationCase.SourceJudgments {
			referencedSources[judgment.SourcePath] = struct{}{}
			for _, spanID := range judgment.MappedSpanIDs {
				referencedSpans[spanID] = struct{}{}
				if _, indexed := indexBySpan[spanID]; !indexed {
					return fail("paired fusion mapped SpanID is absent from the lexical index")
				}
			}
		}
		for _, judgment := range evaluationCase.RelevanceJudgments {
			referencedSpans[judgment.SpanID] = struct{}{}
			if _, indexed := indexBySpan[judgment.SpanID]; !indexed {
				return fail("paired fusion relevance SpanID is absent from the lexical index")
			}
		}
	}
	if len(referencedSources) != len(declaredSources) || len(referencedSpans) != len(declaredSpans) {
		return fail("paired fusion declared and judged source/span denominators differ")
	}
	for sourcePath := range referencedSources {
		if _, exists := declaredSources[sourcePath]; !exists {
			return fail("paired fusion judgment references an undeclared source")
		}
	}
	for spanID := range referencedSpans {
		if _, exists := declaredSpans[spanID]; !exists {
			return fail("paired fusion judgment references an undeclared span")
		}
	}
	return declaredSources, declaredSpans, nil
}

func validateSnapshotAndEvidenceIdentities(snapshot SnapshotManifest, evidence EvidenceManifest) error {
	coreBytes, err := json.Marshal(snapshotIdentityCore(snapshot))
	if err != nil || snapshot.ManifestPayloadSHA256 != digestBytes(coreBytes) || snapshot.ManifestID != "snapshot-manifest:"+snapshot.ManifestPayloadSHA256 {
		return errors.New("paired fusion snapshot identity mismatch")
	}
	evidenceCore, err := json.Marshal(evidence.EvidenceManifestCore)
	if err != nil || evidence.ManifestPayloadSHA256 != digestBytes(evidenceCore) || evidence.ManifestID != "evidence-manifest:"+evidence.ManifestPayloadSHA256 {
		return errors.New("paired fusion evidence identity mismatch")
	}
	limits := buildLimits{
		maxFiles: defaultMaxFiles, maxSpans: defaultMaxSpans,
		maxPayloadBytes: defaultMaxPayloadBytes, maxTotalBytes: defaultMaxTotalBytes,
		maxTerms: defaultMaxTerms, maxPostings: defaultMaxPostings,
	}
	if snapshot.ReviewAdmission.Decision != "accepted" {
		return errors.New("paired fusion snapshot review admission is not accepted")
	}
	if issues := validateEvidenceAndSnapshotHeaders(evidence, snapshot, limits); len(issues) != 0 {
		return errors.New("paired fusion snapshot/evidence headers are not reviewed, complete and trusted")
	}
	return nil
}

type pairedSnapshotManifestCore struct {
	SchemaVersion     string              `json:"schema_version"`
	ManifestKind      string              `json:"manifest_kind"`
	State             string              `json:"state"`
	AuthorityState    string              `json:"authority_state"`
	ReviewAdmission   ReviewAdmission     `json:"review_admission"`
	SnapshotID        string              `json:"snapshot_id"`
	SourceSpecSHA256  string              `json:"source_spec_sha256"`
	Source            SourceLineage       `json:"source"`
	TreeSHA256        string              `json:"tree_sha256"`
	FileCount         int                 `json:"file_count"`
	ByteSize          int64               `json:"byte_size"`
	UniqueBlobCount   int                 `json:"unique_blob_count"`
	ObjectLayout      string              `json:"object_layout"`
	ExcludedFileCount int                 `json:"excluded_file_count"`
	ExcludedByteSize  int64               `json:"excluded_byte_size"`
	Exclusions        []VerifiedExclusion `json:"exclusions"`
	Files             []SnapshotFile      `json:"files"`
}

func snapshotIdentityCore(snapshot SnapshotManifest) pairedSnapshotManifestCore {
	return pairedSnapshotManifestCore{
		SchemaVersion: snapshot.SchemaVersion, ManifestKind: snapshot.ManifestKind,
		State: snapshot.State, AuthorityState: snapshot.AuthorityState,
		ReviewAdmission: snapshot.ReviewAdmission, SnapshotID: snapshot.SnapshotID,
		SourceSpecSHA256: snapshot.SourceSpecSHA256, Source: snapshot.Source,
		TreeSHA256: snapshot.TreeSHA256, FileCount: snapshot.FileCount,
		ByteSize: snapshot.ByteSize, UniqueBlobCount: snapshot.UniqueBlobCount,
		ObjectLayout: snapshot.ObjectLayout, ExcludedFileCount: snapshot.ExcludedFileCount,
		ExcludedByteSize: snapshot.ExcludedByteSize, Exclusions: snapshot.Exclusions,
		Files: snapshot.Files,
	}
}

func validatePairedCaseBytes(suite PairedFusionSuite, evaluationCase PairedFusionCase, baseline, challenger HybridCandidateManifest, dense DenseVectorArtifact, artifacts map[string][]byte, sources map[string]PairedFusionSourceBinding, spans map[string]PairedFusionSpanBinding) error {
	baselineLabel, challengerLabel := "baseline signal "+evaluationCase.CaseID, "challenger signal "+evaluationCase.CaseID
	var baselineSignal, challengerSignal QuerySignalArtifact
	if err := decodeStrictCanonical(artifacts[baselineLabel], &baselineSignal); err != nil {
		return fmt.Errorf("paired fusion case %s baseline signal invalid", evaluationCase.CaseID)
	}
	if err := decodeStrictCanonical(artifacts[challengerLabel], &challengerSignal); err != nil {
		return fmt.Errorf("paired fusion case %s challenger signal invalid", evaluationCase.CaseID)
	}
	if baselineSignal.ArtifactID != evaluationCase.Signals.Baseline.ArtifactID || challengerSignal.ArtifactID != evaluationCase.Signals.Challenger.ArtifactID {
		return fmt.Errorf("paired fusion case %s signal identity mismatch", evaluationCase.CaseID)
	}
	baselineLoaded := loadedHybridCandidate{hybrid: baseline, dense: dense}
	challengerLoaded := loadedHybridCandidate{hybrid: challenger, dense: dense}
	if validateQuerySignals(baselineSignal, baselineLoaded, evaluationCase.Query, false) != nil || validateQuerySignals(challengerSignal, challengerLoaded, evaluationCase.Query, false) != nil {
		return fmt.Errorf("paired fusion case %s signal lineage mismatch", evaluationCase.CaseID)
	}
	if err := validatePairedSignalSemantics(baselineSignal, challengerSignal); err != nil {
		return fmt.Errorf("paired fusion case %s: %w", evaluationCase.CaseID, err)
	}
	for _, judgment := range evaluationCase.SourceJudgments {
		raw := artifacts["source "+judgment.SourcePath]
		excerpt, err := pairedFusionExcerpt(raw, judgment.Ranges)
		if err != nil || digestBytes(excerpt) != judgment.ExcerptSHA256 {
			return fmt.Errorf("paired fusion case %s frozen excerpt mismatch", evaluationCase.CaseID)
		}
		if evaluationCase.InjectionMarkerLocation == "source_excerpt" && !bytes.Contains(excerpt, []byte(evaluationCase.InjectionMarker)) {
			return fmt.Errorf("paired fusion case %s inert marker missing from source excerpt", evaluationCase.CaseID)
		}
		mapped := make([]string, 0)
		for spanID, span := range spans {
			if span.SourcePath != judgment.SourcePath {
				continue
			}
			for _, lineRange := range judgment.Ranges {
				if span.RawLineStart <= lineRange.End && span.RawLineEnd >= lineRange.Start {
					mapped = append(mapped, spanID)
					break
				}
			}
		}
		sort.Strings(mapped)
		if !equalStringSlices(mapped, judgment.MappedSpanIDs) {
			return fmt.Errorf("paired fusion case %s mechanical SpanID mapping changed", evaluationCase.CaseID)
		}
		for _, lineRange := range judgment.Ranges {
			for line := lineRange.Start; line <= lineRange.End; line++ {
				covered := false
				for _, spanID := range mapped {
					span := spans[spanID]
					if span.RawLineStart <= line && span.RawLineEnd >= line {
						covered = true
						break
					}
				}
				if !covered {
					return fmt.Errorf("paired fusion case %s source range is not fully covered", evaluationCase.CaseID)
				}
			}
		}
		_ = sources[judgment.SourcePath]
	}
	if evaluationCase.InjectionMarkerLocation == "query" && !strings.Contains(evaluationCase.Query, evaluationCase.InjectionMarker) {
		return fmt.Errorf("paired fusion case %s injection marker missing from query", evaluationCase.CaseID)
	}
	return nil
}

func validatePairedSignalSemantics(baseline, challenger QuerySignalArtifact) error {
	baselineCore, challengerCore := baseline.QuerySignalArtifactCore, challenger.QuerySignalArtifactCore
	// The two wrappers must differ only in the hybrid candidate they bind. This
	// compares the exact vector and every reranker decision, pin, instruction,
	// scale and document score without relying on an allow-list that can drift.
	baselineCore.HybridCandidateID = ""
	challengerCore.HybridCandidateID = ""
	baselineBytes, baselineErr := json.Marshal(baselineCore)
	challengerBytes, challengerErr := json.Marshal(challengerCore)
	if baselineErr != nil || challengerErr != nil || !bytes.Equal(baselineBytes, challengerBytes) {
		return errors.New("baseline and challenger query-signal semantics differ")
	}
	return nil
}

func pairedFusionExcerpt(raw []byte, ranges []PairedFusionLineRange) ([]byte, error) {
	lines := bytes.Split(raw, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	selected := make([][]byte, 0)
	for _, lineRange := range ranges {
		if lineRange.Start < 1 || lineRange.End > len(lines) || lineRange.End < lineRange.Start {
			return nil, errors.New("source range exceeds raw document")
		}
		for line := lineRange.Start; line <= lineRange.End; line++ {
			selected = append(selected, lines[line-1])
		}
	}
	return bytes.Join(selected, []byte("\n")), nil
}
