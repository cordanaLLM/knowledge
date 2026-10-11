package main

import (
	"errors"
	"fmt"
)

type verifiedEvaluationArtifacts struct {
	suite        RetrievalEvaluationSuite
	suiteBytes   []byte
	metrics      RetrievalEvaluationMetrics
	metricsBytes []byte
	runtime      RetrievalEvaluationRuntime
	runtimeBytes []byte
}

func loadAndVerifyEvaluationArtifacts(config StageGenerationConfig, quality RetrievalQualityReport, loaded loadedHybridCandidate) (verifiedEvaluationArtifacts, error) {
	var zero verifiedEvaluationArtifacts
	for name, value := range map[string]string{
		"evaluation-dataset": config.EvaluationDatasetPath, "evaluation-dataset-sha256": config.EvaluationDatasetHash,
		"evaluation-metrics": config.EvaluationMetricsPath, "evaluation-metrics-sha256": config.EvaluationMetricsHash,
		"evaluation-runtime": config.EvaluationRuntimePath, "evaluation-runtime-sha256": config.EvaluationRuntimeHash,
	} {
		if value == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	suiteBytes, err := readStableFile(config.EvaluationDatasetPath, "frozen evaluation suite", maxEvaluationSuiteBytes)
	if err != nil || !validSHA256(config.EvaluationDatasetHash) || digestBytes(suiteBytes) != config.EvaluationDatasetHash {
		return zero, errors.New("frozen evaluation suite does not match caller pin")
	}
	var suite RetrievalEvaluationSuite
	if err := decodeStrictCanonical(suiteBytes, &suite); err != nil || validateEvaluationSuite(suite) != nil {
		return zero, errors.New("frozen evaluation suite is invalid")
	}
	metricsBytes, err := readStableFile(config.EvaluationMetricsPath, "recomputed evaluation metrics", maxEvaluationMetricsBytes)
	if err != nil || !validSHA256(config.EvaluationMetricsHash) || digestBytes(metricsBytes) != config.EvaluationMetricsHash {
		return zero, errors.New("recomputed evaluation metrics do not match caller pin")
	}
	var metrics RetrievalEvaluationMetrics
	if err := decodeStrictCanonical(metricsBytes, &metrics); err != nil || validateEvaluationMetrics(metrics) != nil || metrics.State != "passed" {
		return zero, errors.New("recomputed evaluation metrics are not a valid passed object")
	}
	if err := validateEvaluationMetricsAgainstSuite(metrics, suite); err != nil {
		return zero, errors.New("recomputed evaluation metrics do not match the frozen suite")
	}
	runtimeBytes, err := readStableFile(config.EvaluationRuntimePath, "evaluation runtime", maxEvaluationRuntimeBytes)
	if err != nil || !validSHA256(config.EvaluationRuntimeHash) || digestBytes(runtimeBytes) != config.EvaluationRuntimeHash {
		return zero, errors.New("evaluation runtime does not match caller pin")
	}
	var runtime RetrievalEvaluationRuntime
	if err := decodeStrictCanonical(runtimeBytes, &runtime); err != nil || validateEvaluationRuntime(runtime) != nil || runtime.State != "passed" {
		return zero, errors.New("evaluation runtime is not a valid passed object")
	}

	if suite.SuiteID != quality.EvaluationDatasetID || config.EvaluationDatasetHash != quality.EvaluationDatasetSHA256 || suite.HybridCandidateID != quality.HybridCandidateID || suite.HybridCandidateSHA256 != quality.HybridCandidateSHA256 || suite.AdmissionPolicyID != quality.AdmissionPolicyID || suite.AdmissionPolicySHA256 != quality.AdmissionPolicySHA256 || suite.LexicalCandidateID != loaded.hybrid.LexicalCandidateID || suite.LexicalCandidateSHA256 != loaded.hybrid.LexicalCandidateSHA256 || suite.SourceAdmissionMethod != quality.SourceAdmissionMethod || suite.SourceAdmissionPolicyID != quality.SourceAdmissionPolicyID || suite.SourceAdmissionPolicySHA256 != quality.SourceAdmissionPolicySHA256 {
		return zero, errors.New("frozen evaluation suite lineage differs from the quality report")
	}
	if (suite.TargetMode == "reranked") != quality.RerankingEvaluated || suite.EvaluatedAt != quality.EvaluatedAt {
		return zero, errors.New("frozen evaluation suite mode/time differs from the quality report")
	}
	if metrics.SuiteID != suite.SuiteID || metrics.SuiteSHA256 != config.EvaluationDatasetHash || metrics.LexicalCandidateID != suite.LexicalCandidateID || metrics.LexicalCandidateSHA256 != suite.LexicalCandidateSHA256 || metrics.HybridCandidateID != suite.HybridCandidateID || metrics.HybridCandidateSHA256 != suite.HybridCandidateSHA256 || metrics.AdmissionPolicyID != suite.AdmissionPolicyID || metrics.AdmissionPolicySHA256 != suite.AdmissionPolicySHA256 || metrics.MetricAlgorithm != suite.MetricAlgorithm || metrics.MetricScale != suite.MetricScale || metrics.CutoffK != suite.CutoffK || metrics.TargetMode != suite.TargetMode || metrics.Gates != quality.Gates || config.EvaluationMetricsHash != quality.EvaluationMetricsObjectSHA256 {
		return zero, errors.New("recomputed evaluation metrics lineage differs")
	}
	if runtime.EvaluatorID != quality.EvaluatorID || runtime.EvaluatorRevision != quality.EvaluatorRevision || runtime.EvaluatorExecutableSHA256 != quality.EvaluatorExecutableSHA256 || runtime.RetrievalExecutableSHA256 != quality.RetrievalExecutableSHA256 || runtime.SuiteID != suite.SuiteID || runtime.SuiteSHA256 != config.EvaluationDatasetHash || runtime.LexicalCandidateSHA256 != suite.LexicalCandidateSHA256 || runtime.HybridCandidateSHA256 != suite.HybridCandidateSHA256 || runtime.AdmissionPolicySHA256 != suite.AdmissionPolicySHA256 || runtime.MetricsSHA256 != config.EvaluationMetricsHash || runtime.MetricAlgorithm != suite.MetricAlgorithm || runtime.TargetMode != suite.TargetMode || runtime.EvaluatedAt != suite.EvaluatedAt || config.EvaluationRuntimeHash != quality.EvaluationRuntimeSHA256 {
		return zero, errors.New("evaluation runtime lineage differs")
	}
	return verifiedEvaluationArtifacts{suite: suite, suiteBytes: suiteBytes, metrics: metrics, metricsBytes: metricsBytes, runtime: runtime, runtimeBytes: runtimeBytes}, nil
}

func verifyStoredEvaluationArtifacts(storeRoot string, generation RetrievalGeneration, quality RetrievalQualityReport, loaded loadedHybridCandidate) error {
	suiteBytes, _, err := readBoundStoreDocument(storeRoot, generation.EvaluationDatasetPath, generation.EvaluationDatasetSHA256, generation.EvaluationDatasetByteSize, maxEvaluationSuiteBytes)
	if err != nil {
		return errors.New("generation frozen evaluation suite is unavailable")
	}
	var suite RetrievalEvaluationSuite
	if err := decodeStrictCanonical(suiteBytes, &suite); err != nil || validateEvaluationSuite(suite) != nil || suite.SuiteID != generation.EvaluationDatasetID {
		return errors.New("generation frozen evaluation suite is invalid")
	}
	metricsBytes, _, err := readBoundStoreDocument(storeRoot, generation.EvaluationMetricsObjectPath, generation.EvaluationMetricsObjectSHA256, generation.EvaluationMetricsObjectByteSize, maxEvaluationMetricsBytes)
	if err != nil {
		return errors.New("generation recomputed evaluation metrics are unavailable")
	}
	var metrics RetrievalEvaluationMetrics
	if err := decodeStrictCanonical(metricsBytes, &metrics); err != nil || validateEvaluationMetrics(metrics) != nil || metrics.State != "passed" || metrics.MetricsID != generation.EvaluationMetricsObjectID {
		return errors.New("generation recomputed evaluation metrics are invalid")
	}
	if err := validateEvaluationMetricsAgainstSuite(metrics, suite); err != nil {
		return errors.New("generation recomputed evaluation metrics differ from the frozen suite")
	}
	runtimeBytes, _, err := readBoundStoreDocument(storeRoot, generation.EvaluationRuntimePath, generation.EvaluationRuntimeSHA256, generation.EvaluationRuntimeByteSize, maxEvaluationRuntimeBytes)
	if err != nil {
		return errors.New("generation evaluation runtime is unavailable")
	}
	var runtime RetrievalEvaluationRuntime
	if err := decodeStrictCanonical(runtimeBytes, &runtime); err != nil || validateEvaluationRuntime(runtime) != nil || runtime.State != "passed" || runtime.RuntimeID != generation.EvaluationRuntimeID {
		return errors.New("generation evaluation runtime is invalid")
	}
	// The shared lineage checks do not inspect filesystem paths until after all
	// three canonical documents are decoded. Re-run them explicitly here because
	// stored paths are relative to the retrieval CAS rather than process paths.
	if suite.SuiteID != quality.EvaluationDatasetID || suite.SuiteID != generation.EvaluationDatasetID || suite.HybridCandidateID != generation.HybridCandidateID || suite.HybridCandidateSHA256 != generation.HybridCandidateSHA256 || suite.LexicalCandidateID != generation.LexicalCandidateID || suite.LexicalCandidateSHA256 != generation.LexicalCandidateSHA256 || suite.AdmissionPolicyID != generation.AdmissionPolicyID || suite.AdmissionPolicySHA256 != generation.AdmissionPolicySHA256 || suite.SourceAdmissionMethod != generation.SourceAdmissionMethod || suite.SourceAdmissionPolicyID != generation.SourceAdmissionPolicyID || suite.SourceAdmissionPolicySHA256 != generation.SourceAdmissionPolicySHA256 || (suite.TargetMode == "reranked") != generation.RerankingEvaluated || suite.EvaluatedAt != quality.EvaluatedAt {
		return errors.New("generation frozen evaluation suite lineage differs")
	}
	if metrics.SuiteID != suite.SuiteID || metrics.SuiteSHA256 != generation.EvaluationDatasetSHA256 || metrics.LexicalCandidateID != generation.LexicalCandidateID || metrics.LexicalCandidateSHA256 != generation.LexicalCandidateSHA256 || metrics.HybridCandidateID != generation.HybridCandidateID || metrics.HybridCandidateSHA256 != generation.HybridCandidateSHA256 || metrics.AdmissionPolicyID != generation.AdmissionPolicyID || metrics.AdmissionPolicySHA256 != generation.AdmissionPolicySHA256 || metrics.Gates != quality.Gates || metrics.TargetMode != suite.TargetMode {
		return errors.New("generation recomputed evaluation metrics lineage differs")
	}
	if runtime.EvaluatorID != generation.EvaluatorID || runtime.EvaluatorRevision != generation.EvaluatorRevision || runtime.EvaluatorExecutableSHA256 != generation.EvaluatorExecutableSHA256 || runtime.RetrievalExecutableSHA256 != generation.RetrievalExecutableSHA256 || runtime.SuiteID != suite.SuiteID || runtime.SuiteSHA256 != generation.EvaluationDatasetSHA256 || runtime.LexicalCandidateSHA256 != generation.LexicalCandidateSHA256 || runtime.HybridCandidateSHA256 != generation.HybridCandidateSHA256 || runtime.AdmissionPolicySHA256 != generation.AdmissionPolicySHA256 || runtime.MetricsSHA256 != generation.EvaluationMetricsObjectSHA256 || runtime.TargetMode != suite.TargetMode || runtime.EvaluatedAt != quality.EvaluatedAt {
		return errors.New("generation evaluation runtime lineage differs")
	}
	if loaded.hybrid.SourceAdmissionMethod != generation.SourceAdmissionMethod || loaded.hybrid.SourceAdmissionPolicyID != generation.SourceAdmissionPolicyID || loaded.hybrid.SourceAdmissionPolicySHA256 != generation.SourceAdmissionPolicySHA256 {
		return errors.New("generation source-admission lineage differs from hybrid candidate")
	}
	return nil
}
