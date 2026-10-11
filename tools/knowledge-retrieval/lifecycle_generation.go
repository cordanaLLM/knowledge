package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	qualityReportKind       = "retrieval_held_out_quality_report"
	retrievalGenerationKind = "evaluated_hybrid_retrieval_generation"
	maxQualityReportBytes   = int64(16 * 1024 * 1024)
	maxExecutableBytes      = int64(256 * 1024 * 1024)
)

func StageGeneration(config StageGenerationConfig) (StageGenerationResult, error) {
	var zero StageGenerationResult
	for name, value := range map[string]string{
		"hybrid-candidate": config.HybridCandidatePath, "hybrid-candidate-sha256": config.HybridCandidateHash,
		"store": config.StoreRoot, "quality-report": config.QualityReportPath,
		"quality-report-sha256": config.QualityReportHash, "admission-policy": config.AdmissionPolicyPath,
		"quality-receipt": config.QualityReceiptPath, "quality-receipt-sha256": config.QualityReceiptHash,
		"quality-signature": config.QualitySignaturePath, "quality-signature-sha256": config.QualitySignatureHash,
		"evaluator-allowed-signers": config.EvaluatorAllowedSignersPath,
		"evaluation-dataset":        config.EvaluationDatasetPath, "evaluation-dataset-sha256": config.EvaluationDatasetHash,
		"evaluation-metrics": config.EvaluationMetricsPath, "evaluation-metrics-sha256": config.EvaluationMetricsHash,
		"evaluation-runtime": config.EvaluationRuntimePath, "evaluation-runtime-sha256": config.EvaluationRuntimeHash,
		"evaluator-executable": config.EvaluatorExecutablePath, "evaluator-executable-sha256": config.EvaluatorExecutableHash,
		"admission-policy-sha256": config.AdmissionPolicyHash, "retrieval-executable": config.RetrievalExecutablePath,
		"retrieval-executable-sha256": config.RetrievalExecutableHash, "as-of": config.AsOf,
	} {
		if strings.TrimSpace(value) == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	asOf, err := parseCanonicalUTC(config.AsOf)
	if err != nil {
		return zero, fmt.Errorf("as-of: %w", err)
	}
	if (config.BaseGenerationPath == "") != (config.BaseGenerationHash == "") {
		return zero, errors.New("base generation path and hash must both be present or absent")
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkExistingPrefix(storeRoot) != nil {
		return zero, errors.New("retrieval store is unavailable")
	}

	loaded, code := loadHybridCandidate(HybridQueryConfig{
		HybridCandidatePath: config.HybridCandidatePath,
		HybridCandidateHash: config.HybridCandidateHash,
		StoreRoot:           storeRoot,
	})
	if code != "" {
		return zero, fmt.Errorf("hybrid candidate failed whole-artifact verification: %s", code)
	}
	hybridBytes, err := readStableFile(config.HybridCandidatePath, "hybrid candidate", maxManifestBytes)
	if err != nil || digestBytes(hybridBytes) != config.HybridCandidateHash {
		return zero, errors.New("hybrid candidate changed after verification")
	}

	policy, policyBytes, err := loadCurrentAdmissionPolicy(config.AdmissionPolicyPath, config.AdmissionPolicyHash, config.AsOf)
	if err != nil {
		return zero, err
	}
	if policy.PolicyID != loaded.hybrid.AdmissionPolicyID || config.AdmissionPolicyHash != loaded.hybrid.AdmissionPolicySHA256 || policy.SnapshotManifestID != loaded.hybrid.SnapshotManifestID || policy.EvidenceManifestID != loaded.hybrid.EvidenceManifestID {
		return zero, errors.New("current admission policy does not bind the hybrid candidate")
	}

	executableBytes, err := readStableFile(config.RetrievalExecutablePath, "retrieval executable", maxExecutableBytes)
	if err != nil {
		return zero, err
	}
	if digestBytes(executableBytes) != config.RetrievalExecutableHash {
		return zero, errors.New("retrieval executable does not match caller pin")
	}
	evaluatorExecutableBytes, err := readStableFile(config.EvaluatorExecutablePath, "evaluator executable", maxExecutableBytes)
	if err != nil {
		return zero, err
	}
	if digestBytes(evaluatorExecutableBytes) != config.EvaluatorExecutableHash {
		return zero, errors.New("evaluator executable does not match caller pin")
	}

	qualityBytes, err := readStableFile(config.QualityReportPath, "quality report", maxQualityReportBytes)
	if err != nil {
		return zero, err
	}
	if digestBytes(qualityBytes) != config.QualityReportHash {
		return zero, errors.New("quality report does not match caller pin")
	}
	var quality RetrievalQualityReport
	if err := decodeStrictCanonical(qualityBytes, &quality); err != nil || validateQualityReport(quality) != nil {
		return zero, errors.New("quality report is not a valid passed canonical report")
	}
	qualityAt, _ := parseCanonicalUTC(quality.EvaluatedAt)
	policyEvaluatedAt, _ := parseCanonicalUTC(policy.EvaluatedAt)
	policyFreshUntil, _ := parseCanonicalUTC(policy.FreshUntil)
	if qualityAt.Before(policyEvaluatedAt) || qualityAt.After(policyFreshUntil) || qualityAt.After(asOf) {
		return zero, errors.New("quality report is outside the bound policy/generation time window")
	}
	if err := qualityMatchesHybrid(quality, loaded, config); err != nil {
		return zero, err
	}
	if quality.EvaluatorExecutableSHA256 != config.EvaluatorExecutableHash {
		return zero, errors.New("quality report does not bind the supplied evaluator executable")
	}
	evaluationArtifacts, err := loadAndVerifyEvaluationArtifacts(config, quality, loaded)
	if err != nil {
		return zero, err
	}
	qualityEvidence, err := loadAndVerifyQualityEvidence(config, quality)
	if err != nil {
		return zero, err
	}

	var baseID, baseHash *string
	if config.BaseGenerationPath != "" {
		base, _, err := loadAndVerifyGeneration(config.BaseGenerationPath, config.BaseGenerationHash, storeRoot)
		if err != nil {
			return zero, fmt.Errorf("base generation: %w", err)
		}
		baseIDValue := base.GenerationID
		baseHashValue := config.BaseGenerationHash
		baseID, baseHash = &baseIDValue, &baseHashValue
	}

	hybridRelative, err := contentObjectPath("hybrid-candidates", loaded.hybrid.ManifestPayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, hybridRelative, hybridBytes); err != nil {
		return zero, fmt.Errorf("commit hybrid candidate: %w", err)
	}
	qualityRelative, err := contentObjectPath("quality-reports", quality.ReportPayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, qualityRelative, qualityBytes); err != nil {
		return zero, fmt.Errorf("commit quality report: %w", err)
	}
	evaluationDatasetRelative, err := contentObjectPath("evaluation-suites", evaluationArtifacts.suite.SuitePayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, evaluationDatasetRelative, evaluationArtifacts.suiteBytes); err != nil {
		return zero, fmt.Errorf("commit frozen evaluation suite: %w", err)
	}
	evaluationMetricsRelative, err := contentObjectPath("evaluation-metrics", evaluationArtifacts.metrics.MetricsPayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, evaluationMetricsRelative, evaluationArtifacts.metricsBytes); err != nil {
		return zero, fmt.Errorf("commit recomputed evaluation metrics: %w", err)
	}
	evaluationRuntimeRelative, err := contentObjectPath("evaluation-runtimes", evaluationArtifacts.runtime.RuntimePayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, evaluationRuntimeRelative, evaluationArtifacts.runtimeBytes); err != nil {
		return zero, fmt.Errorf("commit evaluation runtime: %w", err)
	}
	qualityReceiptRelative, err := contentObjectPath("quality-receipts", qualityEvidence.receipt.ReceiptPayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, qualityReceiptRelative, qualityEvidence.receiptBytes); err != nil {
		return zero, fmt.Errorf("commit quality evaluator receipt: %w", err)
	}
	qualitySignatureRelative, err := contentBinaryPath("quality-signatures", config.QualitySignatureHash, ".sshsig")
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, qualitySignatureRelative, qualityEvidence.signature); err != nil {
		return zero, fmt.Errorf("commit quality evaluator signature: %w", err)
	}
	evaluatorPolicyHash := digestBytes(qualityEvidence.allowedSigners)
	evaluatorPolicyRelative, err := contentBinaryPath("evaluator-allowed-signers", evaluatorPolicyHash, ".allowed_signers")
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, evaluatorPolicyRelative, qualityEvidence.allowedSigners); err != nil {
		return zero, fmt.Errorf("commit evaluator allowed_signers: %w", err)
	}
	policyRelative, err := contentObjectPath("admission-policies", policy.PolicyPayloadSHA256)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, policyRelative, policyBytes); err != nil {
		return zero, fmt.Errorf("commit admission policy: %w", err)
	}
	executableRelative, err := contentBinaryPath("executables", config.RetrievalExecutableHash, ".bin")
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, executableRelative, executableBytes); err != nil {
		return zero, fmt.Errorf("commit retrieval executable: %w", err)
	}
	evaluatorExecutableRelative, err := contentBinaryPath("evaluator-executables", config.EvaluatorExecutableHash, ".bin")
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, evaluatorExecutableRelative, evaluatorExecutableBytes); err != nil {
		return zero, fmt.Errorf("commit evaluator executable: %w", err)
	}

	evidenceIDs := make([]string, 0, len(loaded.index.Documents))
	for _, document := range loaded.index.Documents {
		evidenceIDs = append(evidenceIDs, document.Evidence.SpanID)
	}
	sort.Strings(evidenceIDs)
	if len(evidenceIDs) != loaded.index.DocumentCount || hasDuplicateStrings(evidenceIDs) {
		return zero, errors.New("hybrid candidate evidence IDs are not one-to-one")
	}
	core := RetrievalGenerationCore{
		SchemaVersion: retrievalSchemaVersion, GenerationKind: retrievalGenerationKind,
		State: "candidate", QualityState: "passed", Promotable: true, ServingEligible: true, CurrentEligible: true,
		BaseGenerationID: baseID, BaseGenerationSHA256: baseHash, CreatedAt: config.AsOf,
		HybridCandidateID: loaded.hybrid.ManifestID, HybridCandidateSHA256: config.HybridCandidateHash,
		HybridCandidatePath: hybridRelative, HybridCandidateByteSize: int64(len(hybridBytes)),
		SnapshotManifestID: loaded.hybrid.SnapshotManifestID, EvidenceManifestID: loaded.hybrid.EvidenceManifestID,
		EvidenceSpanIDs: evidenceIDs, DocumentCount: loaded.index.DocumentCount,
		AdmissionPolicyID: policy.PolicyID, AdmissionPolicySHA256: config.AdmissionPolicyHash,
		SourceAdmissionMethod:       loaded.hybrid.SourceAdmissionMethod,
		SourceAdmissionPolicyID:     loaded.hybrid.SourceAdmissionPolicyID,
		SourceAdmissionPolicySHA256: loaded.hybrid.SourceAdmissionPolicySHA256,
		AdmissionPolicyPath:         policyRelative, AdmissionPolicyByteSize: int64(len(policyBytes)),
		LexicalCandidateID: loaded.hybrid.LexicalCandidateID, LexicalCandidateSHA256: loaded.hybrid.LexicalCandidateSHA256,
		LexicalIndexID: loaded.hybrid.LexicalIndexID, LexicalProfile: loaded.hybrid.LexicalProfile,
		LexicalTokenizerID: loaded.hybrid.LexicalTokenizerID, LexicalScorerID: loaded.hybrid.LexicalScorerID,
		DenseArtifactID:     loaded.hybrid.DenseArtifactID,
		DenseArtifactSHA256: loaded.hybrid.DenseArtifactSHA256, DenseModelID: loaded.hybrid.DenseModelID,
		DenseModelRevision: loaded.hybrid.DenseModelRevision, DenseModelArtifactSHA256: loaded.hybrid.DenseModelArtifactSHA256,
		DenseTokenizerID: loaded.hybrid.DenseTokenizerID, DenseTokenizerSHA256: loaded.hybrid.DenseTokenizerSHA256,
		EmbeddingProfile: loaded.hybrid.EmbeddingProfile, VectorEncoding: loaded.hybrid.VectorEncoding,
		Normalization: loaded.hybrid.Normalization, QuantizationScale: loaded.hybrid.QuantizationScale,
		Dimension: loaded.hybrid.Dimension, FusionProfile: loaded.hybrid.FusionProfile,
		RerankingContract: loaded.hybrid.RerankingContract, RerankingEvaluated: quality.RerankingEvaluated,
		RerankerModelID:       quality.RerankerModelID,
		RerankerModelRevision: quality.RerankerModelRevision, RerankerModelArtifactSHA256: quality.RerankerModelArtifactSHA256,
		RerankerTokenizerID: quality.RerankerTokenizerID, RerankerTokenizerSHA256: quality.RerankerTokenizerSHA256,
		RerankerProfile: quality.RerankerProfile, RerankerQueryInstruction: quality.RerankerQueryInstruction,
		RerankerDocumentInstruction: quality.RerankerDocumentInstruction, RerankerScoreScale: quality.RerankerScoreScale,
		QualityReportID:     quality.ReportID,
		QualityReportSHA256: config.QualityReportHash, QualityReportPath: qualityRelative,
		QualityReportByteSize: int64(len(qualityBytes)), EvaluationDatasetID: quality.EvaluationDatasetID,
		QualityReceiptID: qualityEvidence.receipt.ReceiptID, QualityReceiptSHA256: config.QualityReceiptHash,
		QualityReceiptPath: qualityReceiptRelative, QualityReceiptByteSize: int64(len(qualityEvidence.receiptBytes)),
		QualitySignatureSHA256: config.QualitySignatureHash, QualitySignaturePath: qualitySignatureRelative,
		QualitySignatureByteSize:      int64(len(qualityEvidence.signature)),
		EvaluatorAllowedSignersSHA256: evaluatorPolicyHash, EvaluatorAllowedSignersPath: evaluatorPolicyRelative,
		EvaluatorAllowedSignersByteSize: int64(len(qualityEvidence.allowedSigners)),
		EvaluatorActor:                  qualityEvidence.receipt.Authorization.Actor, EvaluatorKeyID: qualityEvidence.receipt.Authorization.KeyID,
		EvaluatorSignatureNamespace: qualityEvidence.receipt.Authorization.Namespace,
		EvaluatorID:                 quality.EvaluatorID, EvaluatorRevision: quality.EvaluatorRevision,
		EvaluatorExecutableSHA256:       quality.EvaluatorExecutableSHA256,
		EvaluatorExecutablePath:         evaluatorExecutableRelative,
		EvaluatorExecutableByteSize:     int64(len(evaluatorExecutableBytes)),
		EvaluationDatasetSHA256:         quality.EvaluationDatasetSHA256,
		EvaluationDatasetPath:           evaluationDatasetRelative,
		EvaluationDatasetByteSize:       int64(len(evaluationArtifacts.suiteBytes)),
		EvaluationMetricsObjectID:       evaluationArtifacts.metrics.MetricsID,
		EvaluationMetricsObjectSHA256:   quality.EvaluationMetricsObjectSHA256,
		EvaluationMetricsObjectPath:     evaluationMetricsRelative,
		EvaluationMetricsObjectByteSize: int64(len(evaluationArtifacts.metricsBytes)),
		EvaluationRuntimeID:             evaluationArtifacts.runtime.RuntimeID,
		EvaluationRuntimeSHA256:         quality.EvaluationRuntimeSHA256,
		EvaluationRuntimePath:           evaluationRuntimeRelative,
		EvaluationRuntimeByteSize:       int64(len(evaluationArtifacts.runtimeBytes)),
		RetrievalExecutableSHA256:       config.RetrievalExecutableHash, RetrievalExecutablePath: executableRelative,
		RetrievalExecutableByteSize: int64(len(executableBytes)), MissingCapabilities: []string{},
	}
	coreBytes, _ := json.Marshal(core)
	digest := digestBytes(coreBytes)
	generation := RetrievalGeneration{GenerationID: "retrieval-generation:" + digest, GenerationPayloadSHA256: digest, RetrievalGenerationCore: core}
	generationBytes, err := marshalDocument(generation)
	if err != nil {
		return zero, err
	}
	generationRelative, err := contentObjectPath("generations", digest)
	if err != nil {
		return zero, err
	}
	if err := writeImmutableObject(storeRoot, generationRelative, generationBytes); err != nil {
		return zero, fmt.Errorf("commit evaluated generation: %w", err)
	}
	generationPath := filepath.Join(storeRoot, filepath.FromSlash(generationRelative))
	if _, _, err := loadAndVerifyGeneration(generationPath, digestBytes(generationBytes), storeRoot); err != nil {
		return zero, fmt.Errorf("post-commit generation verification: %w", err)
	}
	return StageGenerationResult{Generation: generation, GenerationPath: generationPath}, nil
}

func validateQualityReport(report RetrievalQualityReport) error {
	return validateQualityReportDocument(report, true)
}

func validateQualityReportDocument(report RetrievalQualityReport, requirePassed bool) error {
	coreBytes, err := json.Marshal(report.RetrievalQualityReportCore)
	if err != nil || report.ReportPayloadSHA256 != digestBytes(coreBytes) || report.ReportID != "retrieval-quality-report:"+report.ReportPayloadSHA256 {
		return errors.New("quality report identity mismatch")
	}
	if report.SchemaVersion != retrievalSchemaVersion || report.ReportKind != qualityReportKind || (report.State != "passed" && report.State != "failed") {
		return errors.New("quality report contract invalid")
	}
	if _, err := parseCanonicalUTC(report.EvaluatedAt); err != nil {
		return err
	}
	if (report.State == "passed") != allQualityGatesPassed(report.Gates) {
		return errors.New("quality report state differs from derived gates")
	}
	if requirePassed && report.State != "passed" {
		return errors.New("quality report contains a failed gate")
	}
	if err := validateSourceAdmissionBinding(report.SourceAdmissionMethod, report.SourceAdmissionPolicyID, report.SourceAdmissionPolicySHA256); err != nil {
		return errors.New("quality report source admission binding invalid")
	}
	for name, digest := range map[string]string{
		"hybrid": report.HybridCandidateSHA256, "policy": report.AdmissionPolicySHA256,
		"executable": report.RetrievalExecutableSHA256, "dense": report.DenseArtifactSHA256,
		"dense-model": report.DenseModelArtifactSHA256, "dense-tokenizer": report.DenseTokenizerSHA256,
		"dataset": report.EvaluationDatasetSHA256, "metrics": report.EvaluationMetricsObjectSHA256,
		"runtime": report.EvaluationRuntimeSHA256, "evaluator-executable": report.EvaluatorExecutableSHA256,
	} {
		if !validSHA256(digest) {
			return fmt.Errorf("quality report %s digest invalid", name)
		}
	}
	for name, value := range map[string]string{
		"candidate": report.HybridCandidateID, "policy": report.AdmissionPolicyID, "lexical-index": report.LexicalIndexID,
		"dense-artifact": report.DenseArtifactID, "dense-model": report.DenseModelID, "dense-model-revision": report.DenseModelRevision,
		"dense-tokenizer": report.DenseTokenizerID, "embedding-profile": report.EmbeddingProfile,
		"fusion-profile": report.FusionProfile, "reranking-contract": report.RerankingContract,
		"evaluation-dataset": report.EvaluationDatasetID, "evaluator": report.EvaluatorID,
		"evaluator-revision": report.EvaluatorRevision,
	} {
		if !boundedMetadata(value) {
			return fmt.Errorf("quality report %s metadata invalid", name)
		}
	}
	if report.LexicalProfile == "" {
		if report.LexicalTokenizerID != "" || report.LexicalScorerID != "" {
			return errors.New("legacy quality report carries successor lexical lineage")
		}
	} else if !validBM25FLineage(report.LexicalProfile, report.LexicalTokenizerID, report.LexicalScorerID) {
		return errors.New("quality report lexical profile binding invalid")
	}
	rerankerFields := []*string{report.RerankerModelID, report.RerankerModelRevision, report.RerankerModelArtifactSHA256, report.RerankerTokenizerID, report.RerankerTokenizerSHA256, report.RerankerProfile, report.RerankerQueryInstruction, report.RerankerDocumentInstruction}
	if !report.RerankingEvaluated {
		for _, value := range rerankerFields {
			if value != nil {
				return errors.New("fusion-only quality report carries reranker bindings")
			}
		}
		if report.RerankerScoreScale != nil {
			return errors.New("fusion-only quality report carries a reranker score scale")
		}
	} else {
		for _, value := range rerankerFields {
			if value == nil || !boundedMetadata(*value) {
				return errors.New("reranking quality report lacks a complete scorer binding")
			}
		}
		if !validSHA256(*report.RerankerModelArtifactSHA256) || !validSHA256(*report.RerankerTokenizerSHA256) {
			return errors.New("reranking quality report scorer digest invalid")
		}
		if report.RerankerScoreScale == nil || *report.RerankerScoreScale < 1 || *report.RerankerScoreScale > 1_000_000_000 {
			return errors.New("reranking quality report score scale invalid")
		}
	}
	return nil
}

func allQualityGatesPassed(gates RetrievalQualityGates) bool {
	return gates.HeldOutQuality && gates.CitationLineage && gates.ACLIsolation && gates.DeletionAndTombstone && gates.FreshnessAndTime && gates.PromptInjectionInert && gates.ResourceBounds && gates.DeterministicReplay && gates.RollbackCompatibility
}

func qualityMatchesHybrid(report RetrievalQualityReport, loaded loadedHybridCandidate, config StageGenerationConfig) error {
	if report.HybridCandidateID != loaded.hybrid.ManifestID || report.HybridCandidateSHA256 != config.HybridCandidateHash || report.AdmissionPolicyID != loaded.hybrid.AdmissionPolicyID || report.AdmissionPolicySHA256 != config.AdmissionPolicyHash || report.SourceAdmissionMethod != loaded.hybrid.SourceAdmissionMethod || report.SourceAdmissionPolicyID != loaded.hybrid.SourceAdmissionPolicyID || report.SourceAdmissionPolicySHA256 != loaded.hybrid.SourceAdmissionPolicySHA256 || report.RetrievalExecutableSHA256 != config.RetrievalExecutableHash || report.LexicalIndexID != loaded.hybrid.LexicalIndexID || report.LexicalProfile != loaded.hybrid.LexicalProfile || report.LexicalTokenizerID != loaded.hybrid.LexicalTokenizerID || report.LexicalScorerID != loaded.hybrid.LexicalScorerID || report.DenseArtifactID != loaded.hybrid.DenseArtifactID || report.DenseArtifactSHA256 != loaded.hybrid.DenseArtifactSHA256 || report.DenseModelID != loaded.hybrid.DenseModelID || report.DenseModelRevision != loaded.hybrid.DenseModelRevision || report.DenseModelArtifactSHA256 != loaded.hybrid.DenseModelArtifactSHA256 || report.DenseTokenizerID != loaded.hybrid.DenseTokenizerID || report.DenseTokenizerSHA256 != loaded.hybrid.DenseTokenizerSHA256 || report.EmbeddingProfile != loaded.hybrid.EmbeddingProfile || report.FusionProfile != loaded.hybrid.FusionProfile || report.RerankingContract != loaded.hybrid.RerankingContract {
		return errors.New("quality report does not bind every hybrid generation input")
	}
	return nil
}

func validateGeneration(generation RetrievalGeneration) error {
	coreBytes, err := json.Marshal(generation.RetrievalGenerationCore)
	if err != nil || generation.GenerationPayloadSHA256 != digestBytes(coreBytes) || generation.GenerationID != "retrieval-generation:"+generation.GenerationPayloadSHA256 {
		return errors.New("retrieval generation identity mismatch")
	}
	if generation.SchemaVersion != retrievalSchemaVersion || generation.GenerationKind != retrievalGenerationKind || generation.State != "candidate" || generation.QualityState != "passed" || !generation.Promotable || !generation.ServingEligible || !generation.CurrentEligible || generation.DocumentCount < 1 || len(generation.EvidenceSpanIDs) != generation.DocumentCount || generation.MissingCapabilities == nil || len(generation.MissingCapabilities) != 0 {
		return errors.New("retrieval generation promotion contract invalid")
	}
	if _, err := parseCanonicalUTC(generation.CreatedAt); err != nil {
		return err
	}
	if (generation.BaseGenerationID == nil) != (generation.BaseGenerationSHA256 == nil) {
		return errors.New("base generation ID/hash nullability differs")
	}
	if generation.BaseGenerationID != nil && (!validPrefixedDigest(*generation.BaseGenerationID, "retrieval-generation:") || !validSHA256(*generation.BaseGenerationSHA256)) {
		return errors.New("base generation binding invalid")
	}
	if !sort.StringsAreSorted(generation.EvidenceSpanIDs) || hasDuplicateStrings(generation.EvidenceSpanIDs) {
		return errors.New("generation evidence IDs are not strict sorted unique")
	}
	if err := validateSourceAdmissionBinding(generation.SourceAdmissionMethod, generation.SourceAdmissionPolicyID, generation.SourceAdmissionPolicySHA256); err != nil {
		return errors.New("generation source admission binding invalid")
	}
	for _, evidenceID := range generation.EvidenceSpanIDs {
		if !validPrefixedDigest(evidenceID, "evidence-span:") {
			return errors.New("generation contains an invalid evidence span ID")
		}
	}
	for name, value := range map[string]string{
		"snapshot": generation.SnapshotManifestID, "evidence": generation.EvidenceManifestID,
		"lexical-candidate": generation.LexicalCandidateID, "lexical-index": generation.LexicalIndexID,
		"dense-artifact": generation.DenseArtifactID, "dense-model": generation.DenseModelID,
		"dense-model-revision": generation.DenseModelRevision, "dense-tokenizer": generation.DenseTokenizerID,
		"embedding-profile": generation.EmbeddingProfile, "fusion-profile": generation.FusionProfile,
		"reranking-contract": generation.RerankingContract, "evaluation-dataset": generation.EvaluationDatasetID,
		"evaluator": generation.EvaluatorID, "evaluator-revision": generation.EvaluatorRevision,
		"evaluator-actor": generation.EvaluatorActor, "evaluator-key": generation.EvaluatorKeyID,
		"evaluator-namespace": generation.EvaluatorSignatureNamespace,
	} {
		if !boundedMetadata(value) {
			return fmt.Errorf("generation %s metadata invalid", name)
		}
	}
	if generation.LexicalProfile == "" {
		if generation.LexicalTokenizerID != "" || generation.LexicalScorerID != "" {
			return errors.New("legacy generation carries successor lexical lineage")
		}
	} else if !validBM25FLineage(generation.LexicalProfile, generation.LexicalTokenizerID, generation.LexicalScorerID) {
		return errors.New("generation lexical profile binding invalid")
	}
	if !validPrefixedDigest(generation.HybridCandidateID, "hybrid-retrieval-candidate:") || !validPrefixedDigest(generation.AdmissionPolicyID, "retrieval-admission:") || !validPrefixedDigest(generation.QualityReportID, "retrieval-quality-report:") || !validPrefixedDigest(generation.QualityReceiptID, "retrieval-quality-receipt:") || !validPrefixedDigest(generation.LexicalCandidateID, "retrieval-candidate:") || !validPrefixedDigest(generation.LexicalIndexID, "lexical-index:") || !validPrefixedDigest(generation.DenseArtifactID, "dense-vector-artifact:") || !validPrefixedDigest(generation.EvaluationDatasetID, "retrieval-evaluation-suite:") || !validPrefixedDigest(generation.EvaluationMetricsObjectID, "retrieval-evaluation-metrics:") || !validPrefixedDigest(generation.EvaluationRuntimeID, "retrieval-evaluation-runtime:") || !sshFingerprintPattern.MatchString(generation.EvaluatorKeyID) || generation.EvaluatorSignatureNamespace != qualityReceiptSignatureNamespace {
		return errors.New("generation content identity invalid")
	}
	if generation.HybridCandidateByteSize < 1 || generation.HybridCandidateByteSize > maxManifestBytes || generation.AdmissionPolicyByteSize < 1 || generation.AdmissionPolicyByteSize > maxPolicyBytes || generation.QualityReportByteSize < 1 || generation.QualityReportByteSize > maxQualityReportBytes || generation.QualityReceiptByteSize < 1 || generation.QualityReceiptByteSize > maxQualityReceiptBytes || generation.QualitySignatureByteSize < 1 || generation.QualitySignatureByteSize > maxSignatureBytes || generation.EvaluatorAllowedSignersByteSize < 1 || generation.EvaluatorAllowedSignersByteSize > maxAllowedSignersBytes || generation.EvaluatorExecutableByteSize < 1 || generation.EvaluatorExecutableByteSize > maxExecutableBytes || generation.EvaluationDatasetByteSize < 1 || generation.EvaluationDatasetByteSize > maxEvaluationSuiteBytes || generation.EvaluationMetricsObjectByteSize < 1 || generation.EvaluationMetricsObjectByteSize > maxEvaluationMetricsBytes || generation.EvaluationRuntimeByteSize < 1 || generation.EvaluationRuntimeByteSize > maxEvaluationRuntimeBytes || generation.RetrievalExecutableByteSize < 1 || generation.RetrievalExecutableByteSize > maxExecutableBytes {
		return errors.New("generation bound object size invalid")
	}
	expectedHybridPath, _ := contentObjectPath("hybrid-candidates", strings.TrimPrefix(generation.HybridCandidateID, "hybrid-retrieval-candidate:"))
	expectedPolicyPath, _ := contentObjectPath("admission-policies", strings.TrimPrefix(generation.AdmissionPolicyID, "retrieval-admission:"))
	expectedQualityPath, _ := contentObjectPath("quality-reports", strings.TrimPrefix(generation.QualityReportID, "retrieval-quality-report:"))
	expectedReceiptPath, _ := contentObjectPath("quality-receipts", strings.TrimPrefix(generation.QualityReceiptID, "retrieval-quality-receipt:"))
	expectedQualitySignaturePath, _ := contentBinaryPath("quality-signatures", generation.QualitySignatureSHA256, ".sshsig")
	expectedEvaluatorPolicyPath, _ := contentBinaryPath("evaluator-allowed-signers", generation.EvaluatorAllowedSignersSHA256, ".allowed_signers")
	expectedEvaluatorExecutablePath, _ := contentBinaryPath("evaluator-executables", generation.EvaluatorExecutableSHA256, ".bin")
	expectedDatasetPath, _ := contentObjectPath("evaluation-suites", strings.TrimPrefix(generation.EvaluationDatasetID, "retrieval-evaluation-suite:"))
	expectedMetricsPath, _ := contentObjectPath("evaluation-metrics", strings.TrimPrefix(generation.EvaluationMetricsObjectID, "retrieval-evaluation-metrics:"))
	expectedRuntimePath, _ := contentObjectPath("evaluation-runtimes", strings.TrimPrefix(generation.EvaluationRuntimeID, "retrieval-evaluation-runtime:"))
	expectedExecutablePath, _ := contentBinaryPath("executables", generation.RetrievalExecutableSHA256, ".bin")
	if generation.HybridCandidatePath != expectedHybridPath || generation.AdmissionPolicyPath != expectedPolicyPath || generation.QualityReportPath != expectedQualityPath || generation.QualityReceiptPath != expectedReceiptPath || generation.QualitySignaturePath != expectedQualitySignaturePath || generation.EvaluatorAllowedSignersPath != expectedEvaluatorPolicyPath || generation.EvaluatorExecutablePath != expectedEvaluatorExecutablePath || generation.EvaluationDatasetPath != expectedDatasetPath || generation.EvaluationMetricsObjectPath != expectedMetricsPath || generation.EvaluationRuntimePath != expectedRuntimePath || generation.RetrievalExecutablePath != expectedExecutablePath {
		return errors.New("generation content path differs from its immutable identity")
	}
	for _, digest := range []string{
		generation.HybridCandidateSHA256, generation.AdmissionPolicySHA256, generation.LexicalCandidateSHA256,
		generation.DenseArtifactSHA256, generation.DenseModelArtifactSHA256, generation.DenseTokenizerSHA256,
		generation.QualityReportSHA256, generation.QualityReceiptSHA256, generation.QualitySignatureSHA256,
		generation.EvaluatorAllowedSignersSHA256, generation.EvaluatorExecutableSHA256,
		generation.EvaluationDatasetSHA256, generation.EvaluationMetricsObjectSHA256, generation.EvaluationRuntimeSHA256,
		generation.RetrievalExecutableSHA256,
	} {
		if !validSHA256(digest) {
			return errors.New("generation contains an invalid digest binding")
		}
	}
	rerankerFields := []*string{generation.RerankerModelID, generation.RerankerModelRevision, generation.RerankerModelArtifactSHA256, generation.RerankerTokenizerID, generation.RerankerTokenizerSHA256, generation.RerankerProfile, generation.RerankerQueryInstruction, generation.RerankerDocumentInstruction}
	if !generation.RerankingEvaluated {
		for _, value := range rerankerFields {
			if value != nil {
				return errors.New("fusion-only generation carries reranker bindings")
			}
		}
		if generation.RerankerScoreScale != nil {
			return errors.New("fusion-only generation carries a reranker score scale")
		}
	} else {
		for _, value := range rerankerFields {
			if value == nil || !boundedMetadata(*value) {
				return errors.New("reranking generation lacks a complete scorer binding")
			}
		}
		if !validSHA256(*generation.RerankerModelArtifactSHA256) || !validSHA256(*generation.RerankerTokenizerSHA256) {
			return errors.New("reranking generation scorer digest invalid")
		}
		if generation.RerankerScoreScale == nil || *generation.RerankerScoreScale < 1 || *generation.RerankerScoreScale > 1_000_000_000 {
			return errors.New("reranking generation score scale invalid")
		}
	}
	return nil
}

func loadAndVerifyGeneration(filePath, expectedHash, storeRoot string) (RetrievalGeneration, []byte, error) {
	var zero RetrievalGeneration
	data, err := readStableFile(filePath, "retrieval generation", maxManifestBytes)
	if err != nil {
		return zero, nil, err
	}
	if digestBytes(data) != expectedHash {
		return zero, nil, errors.New("retrieval generation does not match caller/pointer pin")
	}
	var generation RetrievalGeneration
	if err := decodeStrictCanonical(data, &generation); err != nil || validateGeneration(generation) != nil {
		return zero, nil, errors.New("retrieval generation is invalid")
	}
	if err := verifyWholeGeneration(storeRoot, generation); err != nil {
		return zero, nil, err
	}
	return generation, data, nil
}

func verifyWholeGeneration(storeRoot string, generation RetrievalGeneration) error {
	if err := validateGeneration(generation); err != nil {
		return err
	}
	root, err := filepath.Abs(storeRoot)
	if err != nil || validateNoSymlinkPath(root) != nil {
		return errors.New("retrieval store is unavailable")
	}
	hybridBytes, hybridPath, err := readBoundStoreDocument(root, generation.HybridCandidatePath, generation.HybridCandidateSHA256, generation.HybridCandidateByteSize, maxManifestBytes)
	if err != nil {
		return errors.New("generation hybrid candidate is unavailable")
	}
	loaded, code := loadHybridCandidate(HybridQueryConfig{HybridCandidatePath: hybridPath, HybridCandidateHash: generation.HybridCandidateSHA256, StoreRoot: root})
	if code != "" {
		return fmt.Errorf("generation hybrid verification failed: %s", code)
	}
	if int64(len(hybridBytes)) != generation.HybridCandidateByteSize || generation.HybridCandidateID != loaded.hybrid.ManifestID || generation.SnapshotManifestID != loaded.hybrid.SnapshotManifestID || generation.EvidenceManifestID != loaded.hybrid.EvidenceManifestID || generation.AdmissionPolicyID != loaded.hybrid.AdmissionPolicyID || generation.AdmissionPolicySHA256 != loaded.hybrid.AdmissionPolicySHA256 || generation.SourceAdmissionMethod != loaded.hybrid.SourceAdmissionMethod || generation.SourceAdmissionPolicyID != loaded.hybrid.SourceAdmissionPolicyID || generation.SourceAdmissionPolicySHA256 != loaded.hybrid.SourceAdmissionPolicySHA256 || generation.LexicalCandidateID != loaded.hybrid.LexicalCandidateID || generation.LexicalCandidateSHA256 != loaded.hybrid.LexicalCandidateSHA256 || generation.LexicalIndexID != loaded.hybrid.LexicalIndexID || generation.LexicalProfile != loaded.hybrid.LexicalProfile || generation.LexicalTokenizerID != loaded.hybrid.LexicalTokenizerID || generation.LexicalScorerID != loaded.hybrid.LexicalScorerID || generation.DenseArtifactID != loaded.hybrid.DenseArtifactID || generation.DenseArtifactSHA256 != loaded.hybrid.DenseArtifactSHA256 || generation.DenseModelID != loaded.hybrid.DenseModelID || generation.DenseModelRevision != loaded.hybrid.DenseModelRevision || generation.DenseModelArtifactSHA256 != loaded.hybrid.DenseModelArtifactSHA256 || generation.DenseTokenizerID != loaded.hybrid.DenseTokenizerID || generation.DenseTokenizerSHA256 != loaded.hybrid.DenseTokenizerSHA256 || generation.EmbeddingProfile != loaded.hybrid.EmbeddingProfile || generation.VectorEncoding != loaded.hybrid.VectorEncoding || generation.Normalization != loaded.hybrid.Normalization || generation.QuantizationScale != loaded.hybrid.QuantizationScale || generation.Dimension != loaded.hybrid.Dimension || generation.FusionProfile != loaded.hybrid.FusionProfile || generation.RerankingContract != loaded.hybrid.RerankingContract || generation.DocumentCount != loaded.index.DocumentCount {
		return errors.New("generation hybrid lineage differs")
	}
	evidenceIDs := make([]string, 0, len(loaded.index.Documents))
	for _, document := range loaded.index.Documents {
		evidenceIDs = append(evidenceIDs, document.Evidence.SpanID)
	}
	sort.Strings(evidenceIDs)
	if !equalStrings(evidenceIDs, generation.EvidenceSpanIDs) {
		return errors.New("generation evidence ID set differs from exact index")
	}

	qualityBytes, _, err := readBoundStoreDocument(root, generation.QualityReportPath, generation.QualityReportSHA256, generation.QualityReportByteSize, maxQualityReportBytes)
	if err != nil {
		return errors.New("generation quality report is unavailable")
	}
	var quality RetrievalQualityReport
	if err := decodeStrictCanonical(qualityBytes, &quality); err != nil || validateQualityReport(quality) != nil {
		return errors.New("generation quality report is invalid")
	}
	if quality.ReportID != generation.QualityReportID || quality.HybridCandidateID != generation.HybridCandidateID || quality.HybridCandidateSHA256 != generation.HybridCandidateSHA256 || quality.AdmissionPolicyID != generation.AdmissionPolicyID || quality.AdmissionPolicySHA256 != generation.AdmissionPolicySHA256 || quality.SourceAdmissionMethod != generation.SourceAdmissionMethod || quality.SourceAdmissionPolicyID != generation.SourceAdmissionPolicyID || quality.SourceAdmissionPolicySHA256 != generation.SourceAdmissionPolicySHA256 || quality.RetrievalExecutableSHA256 != generation.RetrievalExecutableSHA256 || quality.LexicalIndexID != generation.LexicalIndexID || quality.LexicalProfile != generation.LexicalProfile || quality.LexicalTokenizerID != generation.LexicalTokenizerID || quality.LexicalScorerID != generation.LexicalScorerID || quality.DenseArtifactID != generation.DenseArtifactID || quality.DenseArtifactSHA256 != generation.DenseArtifactSHA256 || quality.DenseModelID != generation.DenseModelID || quality.DenseModelRevision != generation.DenseModelRevision || quality.DenseModelArtifactSHA256 != generation.DenseModelArtifactSHA256 || quality.DenseTokenizerID != generation.DenseTokenizerID || quality.DenseTokenizerSHA256 != generation.DenseTokenizerSHA256 || quality.EmbeddingProfile != generation.EmbeddingProfile || quality.FusionProfile != generation.FusionProfile || quality.RerankingContract != generation.RerankingContract || quality.RerankingEvaluated != generation.RerankingEvaluated || !equalOptionalStrings(quality.RerankerModelID, generation.RerankerModelID) || !equalOptionalStrings(quality.RerankerModelRevision, generation.RerankerModelRevision) || !equalOptionalStrings(quality.RerankerModelArtifactSHA256, generation.RerankerModelArtifactSHA256) || !equalOptionalStrings(quality.RerankerTokenizerID, generation.RerankerTokenizerID) || !equalOptionalStrings(quality.RerankerTokenizerSHA256, generation.RerankerTokenizerSHA256) || !equalOptionalStrings(quality.RerankerProfile, generation.RerankerProfile) || !equalOptionalStrings(quality.RerankerQueryInstruction, generation.RerankerQueryInstruction) || !equalOptionalStrings(quality.RerankerDocumentInstruction, generation.RerankerDocumentInstruction) || !equalOptionalInt64s(quality.RerankerScoreScale, generation.RerankerScoreScale) || quality.EvaluatorID != generation.EvaluatorID || quality.EvaluatorRevision != generation.EvaluatorRevision || quality.EvaluatorExecutableSHA256 != generation.EvaluatorExecutableSHA256 || quality.EvaluationDatasetID != generation.EvaluationDatasetID || quality.EvaluationDatasetSHA256 != generation.EvaluationDatasetSHA256 || quality.EvaluationMetricsObjectSHA256 != generation.EvaluationMetricsObjectSHA256 || quality.EvaluationRuntimeSHA256 != generation.EvaluationRuntimeSHA256 {
		return errors.New("generation quality lineage differs")
	}
	if err := verifyStoredEvaluationArtifacts(root, generation, quality, loaded); err != nil {
		return err
	}
	if err := verifyStoredQualityEvidence(root, generation, quality); err != nil {
		return err
	}

	policyBytes, _, err := readBoundStoreDocument(root, generation.AdmissionPolicyPath, generation.AdmissionPolicySHA256, generation.AdmissionPolicyByteSize, maxPolicyBytes)
	if err != nil {
		return errors.New("generation admission policy is unavailable")
	}
	var policy AdmissionPolicy
	if err := decodeStrictCanonical(policyBytes, &policy); err != nil || validatePolicyIdentity(policy) != nil || policy.PolicyID != generation.AdmissionPolicyID {
		return errors.New("generation admission policy is invalid")
	}
	qualityAt, _ := parseCanonicalUTC(quality.EvaluatedAt)
	createdAt, _ := parseCanonicalUTC(generation.CreatedAt)
	policyEvaluatedAt, _ := parseCanonicalUTC(policy.EvaluatedAt)
	policyFreshUntil, _ := parseCanonicalUTC(policy.FreshUntil)
	if qualityAt.Before(policyEvaluatedAt) || qualityAt.After(policyFreshUntil) || qualityAt.After(createdAt) {
		return errors.New("generation quality evidence is outside its exact policy/generation time window")
	}
	if _, _, err := readBoundStoreDocument(root, generation.EvaluatorExecutablePath, generation.EvaluatorExecutableSHA256, generation.EvaluatorExecutableByteSize, maxExecutableBytes); err != nil {
		return errors.New("generation evaluator executable is unavailable")
	}
	if _, _, err := readBoundStoreDocument(root, generation.RetrievalExecutablePath, generation.RetrievalExecutableSHA256, generation.RetrievalExecutableByteSize, maxExecutableBytes); err != nil {
		return errors.New("generation retrieval executable is unavailable")
	}
	return nil
}

func loadCurrentAdmissionPolicy(filePath, expectedHash, asOfText string) (AdmissionPolicy, []byte, error) {
	var zero AdmissionPolicy
	asOf, err := parseCanonicalUTC(asOfText)
	if err != nil {
		return zero, nil, fmt.Errorf("policy as-of: %w", err)
	}
	data, err := readStableFile(filePath, "current admission policy", maxPolicyBytes)
	if err != nil {
		return zero, nil, err
	}
	if digestBytes(data) != expectedHash {
		return zero, nil, errors.New("current admission policy does not match caller pin")
	}
	var policy AdmissionPolicy
	if err := decodeStrictCanonical(data, &policy); err != nil || validatePolicyIdentity(policy) != nil {
		return zero, nil, errors.New("current admission policy is invalid")
	}
	if policy.State != "active" || policy.AccessScope != "public" || !policy.RetrievalAllowed || policy.SourceState != "present" || policy.DeletionState != "active" || policy.Tombstone {
		return zero, nil, errors.New("current admission policy forbids promotion")
	}
	evaluatedAt, _ := parseCanonicalUTC(policy.EvaluatedAt)
	freshUntil, _ := parseCanonicalUTC(policy.FreshUntil)
	if asOf.Before(evaluatedAt) || asOf.After(freshUntil) {
		return zero, nil, errors.New("current admission policy is stale or not yet valid")
	}
	return policy, data, nil
}

func contentBinaryPath(directory, digest, suffix string) (string, error) {
	if !validSHA256(digest) || strings.ContainsAny(suffix, `/\\`) || !strings.HasPrefix(suffix, ".") {
		return "", errors.New("content binary identity invalid")
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return filepath.ToSlash(filepath.Join(directory, "sha256", hexDigest[:2], hexDigest+suffix)), nil
}

func validPrefixedDigest(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && validSHA256(strings.TrimPrefix(value, prefix))
}

func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalOptionalStrings(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func equalOptionalInt64s(left, right *int64) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
