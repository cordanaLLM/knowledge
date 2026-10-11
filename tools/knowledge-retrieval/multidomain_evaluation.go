package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// The multidomain paired-fusion evaluation suite extends the single-authority
// PairedFusionSuiteCore contract (paired_fusion.go) to the shared-corpus
// P1-RAG-01 case: one lexical/dense/hybrid corpus spanning several admitted
// source authorities, each retaining its own snapshot, evidence and admission
// lineage. It preserves the exact scorer-blind frozen target, thresholds and
// challenger gates and, like the preflight suite, grants no execution or
// promotion authority: the sealed suite is only a fail-closed input contract
// for a separately signed evaluation.
const (
	multidomainEvaluationSuiteKind      = "retrieval_multidomain_paired_fusion_evaluation_suite"
	multidomainEvaluationExecutionState = "blocked_pending_signed_evaluation"
	maxMultidomainSuiteBytes            = int64(16 * 1024 * 1024)
	maxMultidomainCases                 = 256
	maxMultidomainLineages              = 64
	multidomainEvaluationGrade          = 3
)

// MultidomainLineageBinding pins one admitted source authority and its exact
// snapshot, evidence and admission objects. The bindings mirror the shared
// candidate's per-authority lineage records and the admission lineage-set the
// evaluator replays, so no authority can be collapsed, aliased or mixed.
type MultidomainLineageBinding struct {
	AuthorityID            string                      `json:"authority_id"`
	AdmissionPolicyScopeID string                      `json:"admission_policy_scope_id"`
	ComponentID            string                      `json:"component_id"`
	ComponentVersion       string                      `json:"component_version"`
	DocumentCount          int                         `json:"document_count"`
	SnapshotManifest       PairedFusionArtifactBinding `json:"snapshot_manifest"`
	EvidenceManifest       PairedFusionArtifactBinding `json:"evidence_manifest"`
	AdmissionPolicy        PairedFusionArtifactBinding `json:"admission_policy"`
}

// MultidomainEvaluationCase binds one frozen query to the crosswalk admitted
// (coarse) span it must return on both arms. The admitted span is the
// small-to-big return target: a fine judged span that wins the fused ranking is
// returned as its enclosing coarse chunk, which is exactly this admitted id.
type MultidomainEvaluationCase struct {
	CaseID         string                  `json:"case_id"`
	Class          string                  `json:"class"`
	Query          string                  `json:"query"`
	QuerySHA256    string                  `json:"query_sha256"`
	AdmittedSpanID string                  `json:"admitted_span_id"`
	Grade          int                     `json:"grade"`
	Signals        PairedFusionCaseSignals `json:"signals"`
}

type MultidomainEvaluationSuiteCore struct {
	SchemaVersion               string                      `json:"schema_version"`
	SuiteKind                   string                      `json:"suite_kind"`
	State                       string                      `json:"state"`
	ExecutionState              string                      `json:"execution_state"`
	Name                        string                      `json:"name"`
	Revision                    string                      `json:"revision"`
	FrozenAt                    string                      `json:"frozen_at"`
	Target                      PairedFusionTarget          `json:"target"`
	MinChallengerGainPPM        int64                       `json:"minimum_challenger_gain_ppm"`
	MaximumChallengerRegression int64                       `json:"maximum_challenger_regression_ppm"`
	Thresholds                  []RetrievalMetricThreshold  `json:"thresholds"`
	LexicalCandidate            PairedFusionArtifactBinding `json:"lexical_candidate"`
	LexicalIndex                PairedFusionArtifactBinding `json:"lexical_index"`
	DenseArtifact               PairedFusionArtifactBinding `json:"dense_artifact"`
	Arms                        []PairedFusionArmBinding    `json:"arms"`
	Lineages                    []MultidomainLineageBinding `json:"lineages"`
	Cases                       []MultidomainEvaluationCase `json:"cases"`
}

type MultidomainEvaluationSuite struct {
	SuiteID            string `json:"suite_id"`
	SuitePayloadSHA256 string `json:"suite_payload_sha256"`
	MultidomainEvaluationSuiteCore
}

func MaterializeMultidomainEvaluationSuite(corePath, storeRoot string) (MultidomainEvaluationSuite, string, error) {
	var zero MultidomainEvaluationSuite
	if strings.TrimSpace(corePath) == "" || strings.TrimSpace(storeRoot) == "" {
		return zero, "", errors.New("multidomain evaluation suite core path and store are required")
	}
	data, err := readStableFile(corePath, "multidomain evaluation suite core", maxMultidomainSuiteBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read multidomain evaluation suite core: %w", err)
	}
	var core MultidomainEvaluationSuiteCore
	if err := decodeStrictCanonical(data, &core); err != nil {
		return zero, "", fmt.Errorf("decode multidomain evaluation suite core: %w", err)
	}
	suite, err := sealMultidomainEvaluationSuite(core)
	if err != nil {
		return zero, "", fmt.Errorf("seal multidomain evaluation suite: %w", err)
	}
	document, err := marshalDocument(suite)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("multidomain-evaluation-suites", suite.SuitePayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkExistingPrefix(root) != nil {
		return zero, "", errors.New("multidomain evaluation suite store is unavailable")
	}
	if err := writeImmutableObject(root, relative, document); err != nil {
		return zero, "", fmt.Errorf("commit multidomain evaluation suite: %w", err)
	}
	return suite, filepath.Join(root, filepath.FromSlash(relative)), nil
}

func sealMultidomainEvaluationSuite(core MultidomainEvaluationSuiteCore) (MultidomainEvaluationSuite, error) {
	if err := validateMultidomainEvaluationSuiteCore(core); err != nil {
		return MultidomainEvaluationSuite{}, err
	}
	data, err := json.Marshal(core)
	if err != nil {
		return MultidomainEvaluationSuite{}, err
	}
	digest := digestBytes(data)
	return MultidomainEvaluationSuite{
		SuiteID:                        "multidomain-evaluation-suite:" + digest,
		SuitePayloadSHA256:             digest,
		MultidomainEvaluationSuiteCore: core,
	}, nil
}

func validateMultidomainEvaluationSuite(suite MultidomainEvaluationSuite) error {
	data, err := json.Marshal(suite.MultidomainEvaluationSuiteCore)
	if err != nil || suite.SuitePayloadSHA256 != digestBytes(data) || suite.SuiteID != "multidomain-evaluation-suite:"+suite.SuitePayloadSHA256 {
		return errors.New("multidomain evaluation suite identity mismatch")
	}
	return validateMultidomainEvaluationSuiteCore(suite.MultidomainEvaluationSuiteCore)
}

func validateMultidomainEvaluationSuiteCore(core MultidomainEvaluationSuiteCore) error {
	if core.SchemaVersion != retrievalSchemaVersion || core.SuiteKind != multidomainEvaluationSuiteKind || core.State != "frozen" || core.ExecutionState != multidomainEvaluationExecutionState {
		return errors.New("multidomain evaluation suite envelope unsupported")
	}
	if !boundedMetadata(core.Name) || !boundedMetadata(core.Revision) {
		return errors.New("multidomain evaluation suite name or revision invalid")
	}
	if _, err := parseCanonicalUTC(core.FrozenAt); err != nil {
		return fmt.Errorf("multidomain frozen_at: %w", err)
	}
	if err := validateMultidomainTarget(core.Target); err != nil {
		return err
	}
	// The frozen challenger gates permit no regression and no negative gain. A
	// weakened maximum regression or a negative minimum gain is rejected before
	// any evaluation runs.
	if core.MinChallengerGainPPM < 0 || core.MinChallengerGainPPM > retrievalMetricScale || core.MaximumChallengerRegression != 0 {
		return errors.New("multidomain challenger gates invalid")
	}
	if err := validateMultidomainThresholds(core.Thresholds); err != nil {
		return err
	}
	for _, item := range []struct {
		label   string
		binding PairedFusionArtifactBinding
		prefix  string
		maximum int64
	}{
		{"lexical candidate", core.LexicalCandidate, "retrieval-candidate:", maxManifestBytes},
		{"lexical index", core.LexicalIndex, "lexical-index:", maxIndexBytes},
		{"dense artifact", core.DenseArtifact, "dense-vector-artifact:", maxDenseArtifactBytes},
	} {
		if err := validatePairedArtifactBinding(item.binding, item.prefix, item.maximum); err != nil {
			return fmt.Errorf("%s binding: %w", item.label, err)
		}
	}
	if err := validateMultidomainArms(core.Arms); err != nil {
		return err
	}
	classes, err := validateMultidomainLineages(core.Lineages)
	if err != nil {
		return err
	}
	return validateMultidomainCases(core, classes)
}

func validateMultidomainTarget(target PairedFusionTarget) error {
	if target.ComparisonMode != "paired_fusion_profiles" || target.BaselineProfile != hybridFusionProfile || target.ChallengerProfile != championFusionProfile || target.MetricAlgorithm != metricAlgorithm || target.MetricScale != retrievalMetricScale {
		return errors.New("multidomain evaluation target unsupported")
	}
	if target.CutoffK != 10 || target.Limit != 10 || target.FusionWindow != 100 || target.RerankWindow != 0 || target.MaxExcerptBytes < 1 || target.MaxExcerptBytes > 8192 {
		return errors.New("multidomain evaluation target bounds do not match the frozen suite")
	}
	return nil
}

func validateMultidomainThresholds(thresholds []RetrievalMetricThreshold) error {
	if len(thresholds) < 2 || len(thresholds) > 2*maxMultidomainLineages {
		return errors.New("multidomain thresholds count invalid")
	}
	previous := ""
	for index, threshold := range thresholds {
		key := threshold.Class + "\x00" + threshold.Profile
		if !boundedMetadata(threshold.Class) || (threshold.Profile != "baseline" && threshold.Profile != "challenger") || (index > 0 && key <= previous) {
			return errors.New("multidomain thresholds invalid or not in strict (class, profile) order")
		}
		if threshold.MinRecallPPM != retrievalMetricScale || threshold.MinMRRPPM != 400000 || threshold.MinNDCGPPM != 600000 {
			return errors.New("multidomain threshold does not match the frozen recall/mrr/ndcg floors")
		}
		previous = key
	}
	if len(thresholds)%2 != 0 {
		return errors.New("multidomain thresholds must pair baseline and challenger per class")
	}
	perClass := make(map[string]map[string]struct{})
	for _, threshold := range thresholds {
		if perClass[threshold.Class] == nil {
			perClass[threshold.Class] = make(map[string]struct{})
		}
		perClass[threshold.Class][threshold.Profile] = struct{}{}
	}
	for class, profiles := range perClass {
		if _, ok := profiles["baseline"]; !ok {
			return fmt.Errorf("multidomain class %s lacks a baseline threshold", class)
		}
		if _, ok := profiles["challenger"]; !ok {
			return fmt.Errorf("multidomain class %s lacks a challenger threshold", class)
		}
	}
	return nil
}

func validateMultidomainArms(arms []PairedFusionArmBinding) error {
	if len(arms) != 2 || arms[0].Role != pairedFusionBaselineRole || arms[1].Role != pairedFusionChallengerRole {
		return errors.New("multidomain evaluation arms must be strict baseline/challenger order")
	}
	baseline, challenger := arms[0], arms[1]
	if baseline.FusionProfile != hybridFusionProfile || baseline.Scorer.ScorerID != pairedFusionBaselineID || baseline.Scorer.ScorerRevision != pairedFusionBaselineRev || baseline.FusionProfileArtifact != nil {
		return errors.New("multidomain baseline arm invalid")
	}
	if challenger.FusionProfile != championFusionProfile || challenger.Scorer.ScorerID != championFusionScorerID || challenger.Scorer.ScorerRevision != championFusionScorerRevision || challenger.FusionProfileArtifact == nil {
		return errors.New("multidomain challenger arm invalid")
	}
	for _, arm := range arms {
		if err := validatePairedArtifactBinding(arm.HybridCandidate, "hybrid-retrieval-candidate:", maxManifestBytes); err != nil || !validSHA256(arm.Scorer.ExecutableSHA256) || arm.Scorer.ExecutableByteSize < 1 || arm.Scorer.ExecutableByteSize > maxExecutableBytes {
			return fmt.Errorf("multidomain %s arm binding invalid", arm.Role)
		}
	}
	if err := validatePairedArtifactBinding(*challenger.FusionProfileArtifact, "fusion-profile:", maxFusionProfileBytes); err != nil {
		return fmt.Errorf("multidomain challenger profile binding invalid: %w", err)
	}
	if samePairedArtifact(baseline.HybridCandidate, challenger.HybridCandidate) {
		return errors.New("multidomain arms must bind distinct candidates")
	}
	return nil
}

// validateMultidomainLineages enforces the shared-corpus authority rules:
// no two lineages may share a source authority, admission-policy
// scope, snapshot, evidence or admission object. The returned set is the exact
// admitted-class denominator every case must fall inside.
func validateMultidomainLineages(lineages []MultidomainLineageBinding) (map[string]struct{}, error) {
	if len(lineages) < 1 || len(lineages) > maxMultidomainLineages {
		return nil, errors.New("multidomain lineage count invalid")
	}
	classes := make(map[string]struct{}, len(lineages))
	authorities := make(map[string]struct{}, len(lineages))
	scopes := make(map[string]struct{}, len(lineages))
	snapshots := make(map[string]struct{}, len(lineages))
	evidences := make(map[string]struct{}, len(lineages))
	policies := make(map[string]struct{}, len(lineages))
	previous := ""
	for index, lineage := range lineages {
		if !boundedMetadata(lineage.AuthorityID) || !boundedMetadata(lineage.AdmissionPolicyScopeID) || !boundedMetadata(lineage.ComponentID) || !boundedMetadata(lineage.ComponentVersion) || lineage.DocumentCount < 1 || (index > 0 && lineage.AuthorityID <= previous) {
			return nil, errors.New("multidomain lineages invalid or not in strict authority order")
		}
		previous = lineage.AuthorityID
		if err := validatePairedArtifactBinding(lineage.SnapshotManifest, "snapshot-manifest:", maxManifestBytes); err != nil {
			return nil, fmt.Errorf("multidomain lineage %s snapshot: %w", lineage.AuthorityID, err)
		}
		if err := validatePairedArtifactBinding(lineage.EvidenceManifest, "evidence-manifest:", maxManifestBytes); err != nil {
			return nil, fmt.Errorf("multidomain lineage %s evidence: %w", lineage.AuthorityID, err)
		}
		if err := validatePairedArtifactBinding(lineage.AdmissionPolicy, "retrieval-admission:", maxPolicyBytes); err != nil {
			return nil, fmt.Errorf("multidomain lineage %s admission: %w", lineage.AuthorityID, err)
		}
		for _, dedup := range []struct {
			set map[string]struct{}
			key string
		}{
			{authorities, lineage.AuthorityID}, {scopes, lineage.AdmissionPolicyScopeID},
			{snapshots, lineage.SnapshotManifest.ArtifactID}, {evidences, lineage.EvidenceManifest.ArtifactID},
			{policies, lineage.AdmissionPolicy.ArtifactID},
		} {
			if _, exists := dedup.set[dedup.key]; exists {
				return nil, errors.New("multidomain lineages alias a source authority, scope, snapshot, evidence or admission object")
			}
			dedup.set[dedup.key] = struct{}{}
		}
		classes[lineage.ComponentID] = struct{}{}
	}
	return classes, nil
}

func validateMultidomainCases(core MultidomainEvaluationSuiteCore, componentIDs map[string]struct{}) error {
	if len(core.Cases) < 1 || len(core.Cases) > maxMultidomainCases {
		return errors.New("multidomain case count invalid")
	}
	thresholdClasses := make(map[string]struct{}, len(core.Thresholds))
	for _, threshold := range core.Thresholds {
		thresholdClasses[threshold.Class] = struct{}{}
	}
	previous := ""
	classCases := make(map[string]int, len(thresholdClasses))
	for index, evaluationCase := range core.Cases {
		if !boundedMetadata(evaluationCase.CaseID) || !boundedMetadata(evaluationCase.Class) || (index > 0 && evaluationCase.CaseID <= previous) {
			return errors.New("multidomain cases invalid or not in strict case-ID order")
		}
		previous = evaluationCase.CaseID
		if _, ok := thresholdClasses[evaluationCase.Class]; !ok {
			return fmt.Errorf("multidomain case %s has no threshold class", evaluationCase.CaseID)
		}
		if strings.TrimSpace(evaluationCase.Query) != evaluationCase.Query || evaluationCase.Query == "" || evaluationCase.QuerySHA256 != digestBytes([]byte(evaluationCase.Query)) {
			return fmt.Errorf("multidomain case %s query identity invalid", evaluationCase.CaseID)
		}
		if !validPrefixedDigest(evaluationCase.AdmittedSpanID, "evidence-span:") || evaluationCase.Grade != multidomainEvaluationGrade {
			return fmt.Errorf("multidomain case %s admitted span or grade invalid", evaluationCase.CaseID)
		}
		if err := validatePairedArtifactBinding(evaluationCase.Signals.Baseline, "query-signal-artifact:", maxQuerySignalBytes); err != nil {
			return fmt.Errorf("multidomain case %s baseline signal: %w", evaluationCase.CaseID, err)
		}
		if err := validatePairedArtifactBinding(evaluationCase.Signals.Challenger, "query-signal-artifact:", maxQuerySignalBytes); err != nil {
			return fmt.Errorf("multidomain case %s challenger signal: %w", evaluationCase.CaseID, err)
		}
		if samePairedArtifact(evaluationCase.Signals.Baseline, evaluationCase.Signals.Challenger) {
			return fmt.Errorf("multidomain case %s reuses one signal across arms", evaluationCase.CaseID)
		}
		// The crosswalk admitted (coarse) span is legitimately shared across
		// cases whose distinct fine judged spans resolve to the same enclosing
		// chunk, so it is not required to be unique per case.
		classCases[evaluationCase.Class]++
	}
	for class := range thresholdClasses {
		if classCases[class] < 1 {
			return fmt.Errorf("multidomain class %s has no case", class)
		}
	}
	return nil
}
