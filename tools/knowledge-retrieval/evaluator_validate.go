package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const (
	maxEvaluationSuiteBytes   = int64(16 * 1024 * 1024)
	maxEvaluationMetricsBytes = int64(32 * 1024 * 1024)
	maxEvaluationRuntimeBytes = int64(4 * 1024 * 1024)
	maxEvaluationCases        = 10_000
	evaluatorID               = "archeion-retrieval-evaluator"
	evaluatorRevision         = "retrieval-evaluator@1.0.0"
	metricAlgorithm           = "macro-recall-mrr-ndcg-fixed-point@1.0.0"
)

var ndcgDiscountPPM = [...]int64{
	0,
	1_000_000, 630_930, 500_000, 430_677, 386_853,
	356_207, 333_333, 315_465, 301_030, 289_065,
	278_943, 270_238, 262_650, 255_958, 250_000,
	244_651, 239_812, 235_409, 231_378, 227_671,
}

func sealEvaluationSuite(core RetrievalEvaluationSuiteCore) (RetrievalEvaluationSuite, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalEvaluationSuite{}, err
	}
	digest := digestBytes(data)
	suite := RetrievalEvaluationSuite{SuiteID: "retrieval-evaluation-suite:" + digest, SuitePayloadSHA256: digest, RetrievalEvaluationSuiteCore: core}
	if err := validateEvaluationSuite(suite); err != nil {
		return RetrievalEvaluationSuite{}, err
	}
	return suite, nil
}

func validateEvaluationSuite(suite RetrievalEvaluationSuite) error {
	coreBytes, err := json.Marshal(suite.RetrievalEvaluationSuiteCore)
	if err != nil || suite.SuitePayloadSHA256 != digestBytes(coreBytes) || suite.SuiteID != "retrieval-evaluation-suite:"+suite.SuitePayloadSHA256 {
		return errors.New("evaluation suite identity mismatch")
	}
	if suite.SchemaVersion != retrievalSchemaVersion || suite.SuiteKind != retrievalEvaluationSuiteKind || suite.State != "frozen" || suite.MetricAlgorithm != metricAlgorithm || suite.MetricScale != retrievalMetricScale {
		return errors.New("evaluation suite contract invalid")
	}
	if !boundedMetadata(suite.Name) || !boundedMetadata(suite.Revision) {
		return errors.New("evaluation suite name or revision invalid")
	}
	if _, err := parseCanonicalUTC(suite.EvaluatedAt); err != nil {
		return fmt.Errorf("evaluation suite evaluated_at: %w", err)
	}
	for _, digest := range []string{suite.LexicalCandidateSHA256, suite.HybridCandidateSHA256, suite.AdmissionPolicySHA256} {
		if !validSHA256(digest) {
			return errors.New("evaluation suite contains an invalid whole-document digest")
		}
	}
	if !validPrefixedDigest(suite.LexicalCandidateID, "retrieval-candidate:") || !validPrefixedDigest(suite.HybridCandidateID, "hybrid-retrieval-candidate:") || !validPrefixedDigest(suite.AdmissionPolicyID, "retrieval-admission:") {
		return errors.New("evaluation suite contains an invalid object identity")
	}
	if err := validateSourceAdmissionBinding(suite.SourceAdmissionMethod, suite.SourceAdmissionPolicyID, suite.SourceAdmissionPolicySHA256); err != nil {
		return fmt.Errorf("evaluation suite source admission: %w", err)
	}
	if suite.TargetMode != "fusion_only" && suite.TargetMode != "reranked" {
		return errors.New("evaluation suite target_mode must be fusion_only or reranked")
	}
	if suite.CutoffK < 1 || suite.CutoffK > 20 || suite.Limit < suite.CutoffK || suite.Limit > 100 || suite.FusionWindow < suite.Limit || suite.FusionWindow > 100 || suite.MaxExcerptBytes < 1 || suite.MaxExcerptBytes > 8192 {
		return errors.New("evaluation suite retrieval bounds invalid")
	}
	if suite.TargetMode == "fusion_only" && suite.RerankWindow != 0 {
		return errors.New("fusion-only suite must set rerank_window to zero")
	}
	if suite.TargetMode == "reranked" && (suite.RerankWindow < suite.Limit || suite.RerankWindow > suite.FusionWindow) {
		return errors.New("reranked suite window invalid")
	}
	if suite.RollbackMode != "bootstrap" && suite.RollbackMode != "base_generation" {
		return errors.New("evaluation suite rollback_mode invalid")
	}
	limits := suite.ResourceLimits
	if limits.MaxExecutions < 1 || limits.MaxDenseScannedDocuments < 1 || limits.MaxReturnedResults < 1 || limits.MaxReturnedExcerptBytes < 1 || limits.MaxQuerySignalBytes < 1 {
		return errors.New("evaluation suite resource limits must be positive")
	}
	if len(suite.Cases) < 1 || len(suite.Cases) > maxEvaluationCases {
		return errors.New("evaluation suite case count invalid")
	}
	classes := make(map[string]struct{})
	previousCase := ""
	hasInjection := false
	for index, evaluationCase := range suite.Cases {
		if !boundedMetadata(evaluationCase.CaseID) || !boundedMetadata(evaluationCase.Class) || strings.TrimSpace(evaluationCase.Query) != evaluationCase.Query || evaluationCase.Query == "" || len(evaluationCase.Query) > 16*1024 {
			return fmt.Errorf("evaluation case %d metadata invalid", index)
		}
		if index > 0 && evaluationCase.CaseID <= previousCase {
			return errors.New("evaluation cases are not strict case-ID order")
		}
		previousCase = evaluationCase.CaseID
		classes[evaluationCase.Class] = struct{}{}
		if evaluationCase.QuerySHA256 != digestBytes([]byte(evaluationCase.Query)) {
			return fmt.Errorf("evaluation case %s query digest mismatch", evaluationCase.CaseID)
		}
		if !validPrefixedDigest(evaluationCase.QuerySignalArtifactID, "query-signal-artifact:") || !validSHA256(evaluationCase.QuerySignalSHA256) || validateRelativePath(evaluationCase.QuerySignalPath) != nil || evaluationCase.QuerySignalByteSize < 1 || evaluationCase.QuerySignalByteSize > maxQuerySignalBytes {
			return fmt.Errorf("evaluation case %s query-signal binding invalid", evaluationCase.CaseID)
		}
		// Query-signal artifacts are stored by their content-derived payload
		// identity. Their separately pinned whole-document digest protects the
		// complete wrapper. This is the exact CAS contract emitted by
		// knowledge-embeddings.
		signalPayloadDigest := strings.TrimPrefix(evaluationCase.QuerySignalArtifactID, "query-signal-artifact:")
		expectedSignalPath, _ := contentObjectPath("query-signals", signalPayloadDigest)
		if evaluationCase.QuerySignalPath != expectedSignalPath {
			return fmt.Errorf("evaluation case %s query signal is not stored at its whole-document content path", evaluationCase.CaseID)
		}
		if evaluationCase.InjectionMarker != "" {
			if strings.TrimSpace(evaluationCase.InjectionMarker) != evaluationCase.InjectionMarker || len(evaluationCase.InjectionMarker) > 1024 {
				return fmt.Errorf("evaluation case %s injection marker invalid", evaluationCase.CaseID)
			}
			hasInjection = true
		}
		if len(evaluationCase.RelevanceJudgments) < 1 || len(evaluationCase.RelevanceJudgments) > 1000 {
			return fmt.Errorf("evaluation case %s relevance judgments invalid", evaluationCase.CaseID)
		}
		previousSpan := ""
		for judgmentIndex, judgment := range evaluationCase.RelevanceJudgments {
			if !validPrefixedDigest(judgment.SpanID, "evidence-span:") || judgment.Grade < 1 || judgment.Grade > 3 || (judgmentIndex > 0 && judgment.SpanID <= previousSpan) {
				return fmt.Errorf("evaluation case %s relevance judgments are invalid or not strict span-ID order", evaluationCase.CaseID)
			}
			previousSpan = judgment.SpanID
		}
	}
	if !hasInjection {
		return errors.New("evaluation suite does not exercise prompt-injection inertness")
	}
	wantThresholds := len(classes) * 2
	if len(suite.Thresholds) != wantThresholds {
		return errors.New("evaluation suite must bind one lexical and hybrid threshold per class")
	}
	previousThreshold := ""
	seenThresholds := make(map[string]struct{}, wantThresholds)
	for index, threshold := range suite.Thresholds {
		key := threshold.Class + "\x00" + threshold.Profile
		if index > 0 && key <= previousThreshold {
			return errors.New("evaluation thresholds are not strict class/profile order")
		}
		previousThreshold = key
		if _, exists := classes[threshold.Class]; !exists || (threshold.Profile != "lexical" && threshold.Profile != "hybrid") {
			return errors.New("evaluation threshold targets an unknown class or profile")
		}
		for _, value := range []int64{threshold.MinRecallPPM, threshold.MinMRRPPM, threshold.MinNDCGPPM} {
			if value < 0 || value > retrievalMetricScale {
				return errors.New("evaluation threshold is outside the fixed metric scale")
			}
		}
		seenThresholds[key] = struct{}{}
	}
	for class := range classes {
		for _, profile := range []string{"lexical", "hybrid"} {
			if _, exists := seenThresholds[class+"\x00"+profile]; !exists {
				return errors.New("evaluation threshold coverage is incomplete")
			}
		}
	}
	return nil
}

func sealEvaluationMetrics(core RetrievalEvaluationMetricsCore) (RetrievalEvaluationMetrics, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalEvaluationMetrics{}, err
	}
	digest := digestBytes(data)
	metrics := RetrievalEvaluationMetrics{MetricsID: "retrieval-evaluation-metrics:" + digest, MetricsPayloadSHA256: digest, RetrievalEvaluationMetricsCore: core}
	if err := validateEvaluationMetrics(metrics); err != nil {
		return RetrievalEvaluationMetrics{}, err
	}
	return metrics, nil
}

func validateEvaluationMetrics(metrics RetrievalEvaluationMetrics) error {
	coreBytes, err := json.Marshal(metrics.RetrievalEvaluationMetricsCore)
	if err != nil || metrics.MetricsPayloadSHA256 != digestBytes(coreBytes) || metrics.MetricsID != "retrieval-evaluation-metrics:"+metrics.MetricsPayloadSHA256 {
		return errors.New("evaluation metrics identity mismatch")
	}
	if metrics.SchemaVersion != retrievalSchemaVersion || metrics.MetricsKind != retrievalEvaluationMetricsKind || (metrics.State != "passed" && metrics.State != "failed") || metrics.MetricAlgorithm != metricAlgorithm || metrics.MetricScale != retrievalMetricScale || metrics.CutoffK < 1 || metrics.CutoffK > 20 {
		return errors.New("evaluation metrics contract invalid")
	}
	if !validPrefixedDigest(metrics.SuiteID, "retrieval-evaluation-suite:") || !validSHA256(metrics.SuiteSHA256) || !validPrefixedDigest(metrics.LexicalCandidateID, "retrieval-candidate:") || !validSHA256(metrics.LexicalCandidateSHA256) || !validPrefixedDigest(metrics.HybridCandidateID, "hybrid-retrieval-candidate:") || !validSHA256(metrics.HybridCandidateSHA256) || !validPrefixedDigest(metrics.AdmissionPolicyID, "retrieval-admission:") || !validSHA256(metrics.AdmissionPolicySHA256) {
		return errors.New("evaluation metrics lineage invalid")
	}
	if metrics.TargetMode != "fusion_only" && metrics.TargetMode != "reranked" {
		return errors.New("evaluation metrics target mode invalid")
	}
	if metrics.CaseMetrics == nil || metrics.AggregateMetrics == nil || len(metrics.CaseMetrics) < 2 || len(metrics.CaseMetrics) > maxEvaluationCases*2 {
		return errors.New("evaluation metrics collections must be present")
	}
	limits := metrics.ResourceLimits
	if limits.MaxExecutions < 1 || limits.MaxDenseScannedDocuments < 1 || limits.MaxReturnedResults < 1 || limits.MaxReturnedExcerptBytes < 1 || limits.MaxQuerySignalBytes < 1 {
		return errors.New("evaluation metrics resource limits invalid")
	}
	usage := metrics.ResourceUsage
	if usage.Executions < 0 || usage.DenseScannedDocuments < 0 || usage.ReturnedResults < 0 || usage.ReturnedExcerptBytes < 0 || usage.QuerySignalBytes < 0 {
		return errors.New("evaluation metrics resource usage is negative")
	}
	if metrics.Gates.ResourceBounds != withinEvaluationResourceLimits(usage, limits) {
		return errors.New("evaluation resource gate differs from measured usage")
	}

	caseProfiles := make(map[string]uint8)
	caseClasses := make(map[string]string)
	previousCaseKey := ""
	for index, metric := range metrics.CaseMetrics {
		key := metric.CaseID + "\x00" + metric.Profile
		if !boundedMetadata(metric.CaseID) || !boundedMetadata(metric.Class) || (metric.Profile != "hybrid" && metric.Profile != "lexical") || (index > 0 && key <= previousCaseKey) {
			return errors.New("evaluation case metrics are invalid or not in strict case/profile order")
		}
		previousCaseKey = key
		for _, value := range []int64{metric.RecallPPM, metric.MRRPPM, metric.NDCGPPM} {
			if value < 0 || value > retrievalMetricScale {
				return errors.New("evaluation case metric is outside the fixed metric scale")
			}
		}
		if metric.ReturnedIDs == nil || len(metric.ReturnedIDs) > metrics.CutoffK || containsDuplicateString(metric.ReturnedIDs) {
			return errors.New("evaluation case returned IDs are invalid")
		}
		for _, spanID := range metric.ReturnedIDs {
			if !validPrefixedDigest(spanID, "evidence-span:") {
				return errors.New("evaluation case returned span identity invalid")
			}
		}
		if class, exists := caseClasses[metric.CaseID]; exists && class != metric.Class {
			return errors.New("evaluation case class changes between profiles")
		}
		caseClasses[metric.CaseID] = metric.Class
		bit := uint8(1)
		if metric.Profile == "lexical" {
			bit = 2
		}
		caseProfiles[metric.CaseID] |= bit
	}
	for caseID, profiles := range caseProfiles {
		if profiles != 3 {
			return fmt.Errorf("evaluation case %s does not contain exactly one hybrid and lexical metric", caseID)
		}
	}

	thresholds := make([]RetrievalMetricThreshold, 0, len(metrics.AggregateMetrics))
	previousAggregateKey := ""
	caseCounts := make(map[string]int)
	for _, metric := range metrics.CaseMetrics {
		caseCounts[metric.Class+"\x00"+metric.Profile]++
	}
	for index, aggregate := range metrics.AggregateMetrics {
		key := aggregate.Class + "\x00" + aggregate.Profile
		if !boundedMetadata(aggregate.Class) || (aggregate.Profile != "hybrid" && aggregate.Profile != "lexical") || (index > 0 && key <= previousAggregateKey) || aggregate.QueryCount != caseCounts[key] || aggregate.QueryCount < 1 {
			return errors.New("evaluation aggregate metrics are invalid or not in strict class/profile order")
		}
		previousAggregateKey = key
		for _, value := range []int64{aggregate.RecallPPM, aggregate.MRRPPM, aggregate.NDCGPPM, aggregate.MinRecallPPM, aggregate.MinMRRPPM, aggregate.MinNDCGPPM} {
			if value < 0 || value > retrievalMetricScale {
				return errors.New("evaluation aggregate metric is outside the fixed metric scale")
			}
		}
		wantPassed := aggregate.RecallPPM >= aggregate.MinRecallPPM && aggregate.MRRPPM >= aggregate.MinMRRPPM && aggregate.NDCGPPM >= aggregate.MinNDCGPPM
		if aggregate.ThresholdPassed != wantPassed {
			return errors.New("evaluation aggregate threshold decision is not derived from its metrics")
		}
		thresholds = append(thresholds, RetrievalMetricThreshold{Class: aggregate.Class, Profile: aggregate.Profile, MinRecallPPM: aggregate.MinRecallPPM, MinMRRPPM: aggregate.MinMRRPPM, MinNDCGPPM: aggregate.MinNDCGPPM})
	}
	recomputedAggregates, heldOutPassed := aggregateCaseMetrics(metrics.CaseMetrics, thresholds)
	if !reflect.DeepEqual(recomputedAggregates, metrics.AggregateMetrics) || metrics.Gates.HeldOutQuality != heldOutPassed {
		return errors.New("evaluation aggregates or held-out gate differ from case metrics")
	}
	if (metrics.State == "passed") != allQualityGatesPassed(metrics.Gates) {
		return errors.New("evaluation metrics state differs from derived gates")
	}
	return nil
}

// validateEvaluationMetricsAgainstSuite proves that the recomputed metrics are
// for every exact case in the frozen suite, using the suite's judgments,
// thresholds and deterministic evaluator accounting contract.
func validateEvaluationMetricsAgainstSuite(metrics RetrievalEvaluationMetrics, suite RetrievalEvaluationSuite) error {
	if err := validateEvaluationMetrics(metrics); err != nil {
		return err
	}
	suiteBytes, err := marshalDocument(suite)
	if err != nil || metrics.SuiteID != suite.SuiteID || metrics.SuiteSHA256 != digestBytes(suiteBytes) || metrics.LexicalCandidateID != suite.LexicalCandidateID || metrics.LexicalCandidateSHA256 != suite.LexicalCandidateSHA256 || metrics.HybridCandidateID != suite.HybridCandidateID || metrics.HybridCandidateSHA256 != suite.HybridCandidateSHA256 || metrics.AdmissionPolicyID != suite.AdmissionPolicyID || metrics.AdmissionPolicySHA256 != suite.AdmissionPolicySHA256 || metrics.MetricAlgorithm != suite.MetricAlgorithm || metrics.MetricScale != suite.MetricScale || metrics.CutoffK != suite.CutoffK || metrics.TargetMode != suite.TargetMode || metrics.ResourceLimits != suite.ResourceLimits || len(metrics.CaseMetrics) != len(suite.Cases)*2 {
		return errors.New("evaluation metrics do not cover the exact frozen suite")
	}
	expected := make([]RetrievalCaseMetric, 0, len(suite.Cases)*2)
	byKey := make(map[string]RetrievalCaseMetric, len(metrics.CaseMetrics))
	for _, metric := range metrics.CaseMetrics {
		byKey[metric.CaseID+"\x00"+metric.Profile] = metric
	}
	for _, evaluationCase := range suite.Cases {
		for _, profile := range []string{"hybrid", "lexical"} {
			actual, exists := byKey[evaluationCase.CaseID+"\x00"+profile]
			if !exists || actual.Class != evaluationCase.Class {
				return fmt.Errorf("evaluation metrics omit exact case/profile %s/%s", evaluationCase.CaseID, profile)
			}
			expected = append(expected, computeCaseMetric(evaluationCase.CaseID, evaluationCase.Class, profile, evaluationCase.RelevanceJudgments, actual.ReturnedIDs, suite.CutoffK))
		}
	}
	if !reflect.DeepEqual(expected, metrics.CaseMetrics) {
		return errors.New("evaluation case metrics differ from frozen relevance judgments")
	}
	expectedAggregates, heldOutPassed := aggregateCaseMetrics(expected, suite.Thresholds)
	if !reflect.DeepEqual(expectedAggregates, metrics.AggregateMetrics) || metrics.Gates.HeldOutQuality != heldOutPassed {
		return errors.New("evaluation aggregates differ from frozen thresholds")
	}
	wantExecutions := len(suite.Cases)*4 + 8
	wantQuerySignalBytes := int64(0)
	for _, evaluationCase := range suite.Cases {
		wantQuerySignalBytes += evaluationCase.QuerySignalByteSize
	}
	if metrics.ResourceUsage.Executions != wantExecutions || metrics.ResourceUsage.QuerySignalBytes != wantQuerySignalBytes {
		return errors.New("evaluation resource accounting differs from the fixed evaluator execution plan")
	}
	return nil
}

func containsDuplicateString(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func sealEvaluationRuntime(core RetrievalEvaluationRuntimeCore) (RetrievalEvaluationRuntime, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalEvaluationRuntime{}, err
	}
	digest := digestBytes(data)
	runtime := RetrievalEvaluationRuntime{RuntimeID: "retrieval-evaluation-runtime:" + digest, RuntimePayloadSHA256: digest, RetrievalEvaluationRuntimeCore: core}
	if err := validateEvaluationRuntime(runtime); err != nil {
		return RetrievalEvaluationRuntime{}, err
	}
	return runtime, nil
}

func validateEvaluationRuntime(runtime RetrievalEvaluationRuntime) error {
	coreBytes, err := json.Marshal(runtime.RetrievalEvaluationRuntimeCore)
	if err != nil || runtime.RuntimePayloadSHA256 != digestBytes(coreBytes) || runtime.RuntimeID != "retrieval-evaluation-runtime:"+runtime.RuntimePayloadSHA256 {
		return errors.New("evaluation runtime identity mismatch")
	}
	if runtime.SchemaVersion != retrievalSchemaVersion || runtime.RuntimeKind != retrievalEvaluationRuntimeKind || (runtime.State != "passed" && runtime.State != "failed") || runtime.EvaluatorID != evaluatorID || runtime.EvaluatorRevision != evaluatorRevision || runtime.MetricAlgorithm != metricAlgorithm || (runtime.TargetMode != "fusion_only" && runtime.TargetMode != "reranked") {
		return errors.New("evaluation runtime contract invalid")
	}
	for _, digest := range []string{runtime.EvaluatorExecutableSHA256, runtime.RetrievalExecutableSHA256, runtime.SuiteSHA256, runtime.LexicalCandidateSHA256, runtime.HybridCandidateSHA256, runtime.AdmissionPolicySHA256, runtime.MetricsSHA256} {
		if !validSHA256(digest) {
			return errors.New("evaluation runtime digest invalid")
		}
	}
	if !validPrefixedDigest(runtime.SuiteID, "retrieval-evaluation-suite:") {
		return errors.New("evaluation runtime suite identity invalid")
	}
	_, err = parseCanonicalUTC(runtime.EvaluatedAt)
	return err
}

func computeCaseMetric(caseID, class, profile string, judgments []RetrievalRelevanceJudgment, returned []string, cutoff int) RetrievalCaseMetric {
	grades := make(map[string]int, len(judgments))
	for _, judgment := range judgments {
		grades[judgment.SpanID] = judgment.Grade
	}
	if len(returned) > cutoff {
		returned = returned[:cutoff]
	}
	relevantRetrieved := 0
	firstRelevantRank := 0
	dcg := int64(0)
	for index, spanID := range returned {
		grade := grades[spanID]
		if grade == 0 {
			continue
		}
		relevantRetrieved++
		if firstRelevantRank == 0 {
			firstRelevantRank = index + 1
		}
		gain := int64((1 << grade) - 1)
		dcg += gain * ndcgDiscountPPM[index+1]
	}
	idealGrades := make([]int, 0, len(judgments))
	for _, judgment := range judgments {
		idealGrades = append(idealGrades, judgment.Grade)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(idealGrades)))
	if len(idealGrades) > cutoff {
		idealGrades = idealGrades[:cutoff]
	}
	idcg := int64(0)
	for index, grade := range idealGrades {
		idcg += int64((1<<grade)-1) * ndcgDiscountPPM[index+1]
	}
	recall := int64(relevantRetrieved) * retrievalMetricScale / int64(len(judgments))
	mrr := int64(0)
	if firstRelevantRank > 0 {
		mrr = retrievalMetricScale / int64(firstRelevantRank)
	}
	ndcg := int64(0)
	if idcg > 0 {
		ndcg = dcg * retrievalMetricScale / idcg
	}
	return RetrievalCaseMetric{CaseID: caseID, Class: class, Profile: profile, RecallPPM: recall, MRRPPM: mrr, NDCGPPM: ndcg, ReturnedIDs: append([]string{}, returned...)}
}

func aggregateCaseMetrics(caseMetrics []RetrievalCaseMetric, thresholds []RetrievalMetricThreshold) ([]RetrievalAggregateMetric, bool) {
	type totals struct {
		count             int
		recall, mrr, ndcg int64
	}
	byKey := make(map[string]*totals)
	for _, metric := range caseMetrics {
		key := metric.Class + "\x00" + metric.Profile
		current := byKey[key]
		if current == nil {
			current = &totals{}
			byKey[key] = current
		}
		current.count++
		current.recall += metric.RecallPPM
		current.mrr += metric.MRRPPM
		current.ndcg += metric.NDCGPPM
	}
	result := make([]RetrievalAggregateMetric, 0, len(thresholds))
	allPassed := true
	for _, threshold := range thresholds {
		current := byKey[threshold.Class+"\x00"+threshold.Profile]
		if current == nil || current.count == 0 {
			allPassed = false
			continue
		}
		aggregate := RetrievalAggregateMetric{
			Class: threshold.Class, Profile: threshold.Profile, QueryCount: current.count,
			RecallPPM: current.recall / int64(current.count), MRRPPM: current.mrr / int64(current.count), NDCGPPM: current.ndcg / int64(current.count),
			MinRecallPPM: threshold.MinRecallPPM, MinMRRPPM: threshold.MinMRRPPM, MinNDCGPPM: threshold.MinNDCGPPM,
		}
		aggregate.ThresholdPassed = aggregate.RecallPPM >= aggregate.MinRecallPPM && aggregate.MRRPPM >= aggregate.MinMRRPPM && aggregate.NDCGPPM >= aggregate.MinNDCGPPM
		if !aggregate.ThresholdPassed {
			allPassed = false
		}
		result = append(result, aggregate)
	}
	return result, allPassed
}
