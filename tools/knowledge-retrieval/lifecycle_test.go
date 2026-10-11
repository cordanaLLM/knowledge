package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type lifecycleTestFixture struct {
	*hybridTestFixture
	stateRoot             string
	executable            string
	executableSHA         string
	quality               RetrievalQualityReport
	qualityPath           string
	qualitySHA            string
	qualityReceipt        RetrievalQualityReceipt
	qualityReceiptPath    string
	qualityReceiptSHA     string
	qualitySignaturePath  string
	qualitySignatureSHA   string
	evaluationSuite       RetrievalEvaluationSuite
	evaluationSuitePath   string
	evaluationSuiteSHA    string
	evaluationMetrics     RetrievalEvaluationMetrics
	evaluationMetricsPath string
	evaluationMetricsSHA  string
	evaluationRuntime     RetrievalEvaluationRuntime
	evaluationRuntimePath string
	evaluationRuntimeSHA  string
	evaluatorActor        string
	evaluatorKeyID        string
	evaluatorPrivateKey   string
	evaluatorAllowed      string
	actor                 string
	keyID                 string
	privateKey            string
	allowed               string
}

func newLifecycleTestFixture(t *testing.T) *lifecycleTestFixture {
	return newLifecycleTestFixtureForProfile(t, "")
}

func newLifecycleTestFixtureForProfile(t *testing.T, lexicalProfile string) *lifecycleTestFixture {
	t.Helper()
	hybrid := newHybridTestFixtureForProfile(t, lexicalProfile)
	fixture := &lifecycleTestFixture{
		hybridTestFixture: hybrid, stateRoot: filepath.Join(hybrid.root, "retrieval-state"),
		executable:  filepath.Join(hybrid.root, "knowledge-retrieval-evaluated"),
		qualityPath: filepath.Join(hybrid.root, "quality.json"), actor: "retrieval-operator",
		privateKey: filepath.Join(hybrid.root, "operator_ed25519"), allowed: filepath.Join(hybrid.root, "allowed_signers"),
		evaluatorActor: "retrieval-quality-evaluator", evaluatorPrivateKey: filepath.Join(hybrid.root, "evaluator_ed25519"),
		evaluatorAllowed: filepath.Join(hybrid.root, "evaluator_allowed_signers"),
	}
	writeTestFile(t, fixture.executable, []byte("exact-evaluated-retrieval-executable-v1\n"), 0o555)
	fixture.executableSHA = fileDigest(fixture.executable)
	fixture.keyID = createTestSigner(t, fixture.privateKey, fixture.allowed, fixture.actor)
	fixture.evaluatorKeyID = createTestSigner(t, fixture.evaluatorPrivateKey, fixture.evaluatorAllowed, fixture.evaluatorActor)
	fixture.writeQuality(t, true)
	return fixture
}

func createTestSigner(t *testing.T, privateKey, allowedSigners, actor string) string {
	t.Helper()
	command := exec.Command(sshKeygenPath, "-q", "-t", "ed25519", "-N", "", "-f", privateKey)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create Ed25519 test key: %v: %s", err, output)
	}
	publicBytes, err := os.ReadFile(privateKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(publicBytes))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("unexpected public key: %s", publicBytes)
	}
	keyID, err := fingerprintEd25519Key(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, allowedSigners, []byte(actor+" ssh-ed25519 "+fields[1]+"\n"), 0o444)
	return keyID
}

func (fx *lifecycleTestFixture) writeQuality(t *testing.T, passed bool) {
	t.Helper()
	evidenceIDs := sortedEvidenceIDs(fx.index)
	if len(evidenceIDs) == 0 {
		t.Fatal("lifecycle fixture has no evidence spans")
	}
	thresholds := []RetrievalMetricThreshold{
		{Class: "lifecycle", Profile: "hybrid", MinRecallPPM: 1, MinMRRPPM: 1, MinNDCGPPM: 1},
		{Class: "lifecycle", Profile: "lexical", MinRecallPPM: 1, MinMRRPPM: 1, MinNDCGPPM: 1},
	}
	returnedIDs := []string{evidenceIDs[0]}
	if !passed {
		returnedIDs = []string{}
	}
	caseMetrics := []RetrievalCaseMetric{
		computeCaseMetric("lifecycle-case", "lifecycle", "hybrid", []RetrievalRelevanceJudgment{{SpanID: evidenceIDs[0], Grade: 3}}, returnedIDs, 2),
		computeCaseMetric("lifecycle-case", "lifecycle", "lexical", []RetrievalRelevanceJudgment{{SpanID: evidenceIDs[0], Grade: 3}}, returnedIDs, 2),
	}
	aggregates, heldOutPassed := aggregateCaseMetrics(caseMetrics, thresholds)
	gates := RetrievalQualityGates{heldOutPassed, true, true, true, true, true, true, true, true}
	state := "failed"
	if allQualityGatesPassed(gates) {
		state = "passed"
	}
	suite, err := sealEvaluationSuite(RetrievalEvaluationSuiteCore{
		SchemaVersion: retrievalSchemaVersion, SuiteKind: retrievalEvaluationSuiteKind, State: "frozen",
		Name: "lifecycle-held-out-suite", Revision: "fixture@1.0.0", EvaluatedAt: "2026-07-16T00:30:00Z",
		LexicalCandidateID: fx.lexical.Manifest.ManifestID, LexicalCandidateSHA256: fileDigest(fx.lexical.ManifestPath),
		HybridCandidateID: fx.hybrid.Manifest.ManifestID, HybridCandidateSHA256: fileDigest(fx.hybrid.ManifestPath),
		AdmissionPolicyID: fx.policy.PolicyID, AdmissionPolicySHA256: fx.policyHash,
		SourceAdmissionMethod:       fx.hybrid.Manifest.SourceAdmissionMethod,
		SourceAdmissionPolicyID:     fx.hybrid.Manifest.SourceAdmissionPolicyID,
		SourceAdmissionPolicySHA256: fx.hybrid.Manifest.SourceAdmissionPolicySHA256,
		TargetMode:                  "fusion_only", MetricAlgorithm: metricAlgorithm, MetricScale: retrievalMetricScale,
		CutoffK: 2, Limit: 2, FusionWindow: 2, RerankWindow: 0, MaxExcerptBytes: 2048,
		RollbackMode:   "bootstrap",
		ResourceLimits: RetrievalEvaluationResourceLimits{MaxExecutions: 100, MaxDenseScannedDocuments: 100, MaxReturnedResults: 100, MaxReturnedExcerptBytes: 1_000_000, MaxQuerySignalBytes: 1_000_000},
		Thresholds:     thresholds,
		Cases: []RetrievalEvaluationCase{{
			CaseID: "lifecycle-case", Class: "lifecycle", Query: "alpha", QuerySHA256: digestBytes([]byte("alpha")),
			QuerySignalArtifactID: "query-signal-artifact:sha256:" + strings.Repeat("1", 64),
			QuerySignalSHA256:     "sha256:" + strings.Repeat("2", 64), QuerySignalPath: "query-signals/sha256/11/" + strings.Repeat("1", 64) + ".json",
			QuerySignalByteSize: 1, InjectionMarker: "fixture-injection-marker",
			RelevanceJudgments: []RetrievalRelevanceJudgment{{SpanID: evidenceIDs[0], Grade: 3}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.evaluationSuite = suite
	fx.evaluationSuitePath = filepath.Join(fx.root, "evaluation-suite.json")
	writeCanonical(t, fx.evaluationSuitePath, suite)
	fx.evaluationSuiteSHA = fileDigest(fx.evaluationSuitePath)
	metrics, err := sealEvaluationMetrics(RetrievalEvaluationMetricsCore{
		SchemaVersion: retrievalSchemaVersion, MetricsKind: retrievalEvaluationMetricsKind, State: state,
		SuiteID: suite.SuiteID, SuiteSHA256: fx.evaluationSuiteSHA,
		LexicalCandidateID: fx.lexical.Manifest.ManifestID, LexicalCandidateSHA256: fileDigest(fx.lexical.ManifestPath),
		HybridCandidateID: fx.hybrid.Manifest.ManifestID, HybridCandidateSHA256: fileDigest(fx.hybrid.ManifestPath),
		AdmissionPolicyID: fx.policy.PolicyID, AdmissionPolicySHA256: fx.policyHash,
		MetricAlgorithm: metricAlgorithm, MetricScale: retrievalMetricScale, CutoffK: 2, TargetMode: "fusion_only",
		CaseMetrics: caseMetrics, AggregateMetrics: aggregates,
		ResourceLimits: suite.ResourceLimits,
		ResourceUsage:  RetrievalEvaluationResourceUsage{Executions: 12, DenseScannedDocuments: 1, ReturnedResults: len(returnedIDs) * 2, ReturnedExcerptBytes: int64(len(returnedIDs)), QuerySignalBytes: 1},
		Gates:          gates,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEvaluationMetricsAgainstSuite(metrics, suite); err != nil {
		t.Fatal(err)
	}
	fx.evaluationMetrics = metrics
	fx.evaluationMetricsPath = filepath.Join(fx.root, "evaluation-metrics.json")
	writeCanonical(t, fx.evaluationMetricsPath, metrics)
	fx.evaluationMetricsSHA = fileDigest(fx.evaluationMetricsPath)
	runtime, err := sealEvaluationRuntime(RetrievalEvaluationRuntimeCore{
		SchemaVersion: retrievalSchemaVersion, RuntimeKind: retrievalEvaluationRuntimeKind, State: state,
		EvaluatorID: evaluatorID, EvaluatorRevision: evaluatorRevision,
		EvaluatorExecutableSHA256: fx.executableSHA, RetrievalExecutableSHA256: fx.executableSHA,
		SuiteID: suite.SuiteID, SuiteSHA256: fx.evaluationSuiteSHA,
		LexicalCandidateSHA256: fileDigest(fx.lexical.ManifestPath), HybridCandidateSHA256: fileDigest(fx.hybrid.ManifestPath),
		AdmissionPolicySHA256: fx.policyHash, MetricsSHA256: fx.evaluationMetricsSHA,
		MetricAlgorithm: metricAlgorithm, TargetMode: "fusion_only", EvaluatedAt: suite.EvaluatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.evaluationRuntime = runtime
	fx.evaluationRuntimePath = filepath.Join(fx.root, "evaluation-runtime.json")
	writeCanonical(t, fx.evaluationRuntimePath, runtime)
	fx.evaluationRuntimeSHA = fileDigest(fx.evaluationRuntimePath)
	core := RetrievalQualityReportCore{
		SchemaVersion: retrievalSchemaVersion, ReportKind: qualityReportKind, State: state,
		HybridCandidateID: fx.hybrid.Manifest.ManifestID, HybridCandidateSHA256: fileDigest(fx.hybrid.ManifestPath),
		AdmissionPolicyID: fx.policy.PolicyID, AdmissionPolicySHA256: fx.policyHash,
		SourceAdmissionMethod:       fx.hybrid.Manifest.SourceAdmissionMethod,
		SourceAdmissionPolicyID:     fx.hybrid.Manifest.SourceAdmissionPolicyID,
		SourceAdmissionPolicySHA256: fx.hybrid.Manifest.SourceAdmissionPolicySHA256,
		RetrievalExecutableSHA256:   fx.executableSHA, LexicalIndexID: fx.hybrid.Manifest.LexicalIndexID,
		LexicalProfile:     fx.hybrid.Manifest.LexicalProfile,
		LexicalTokenizerID: fx.hybrid.Manifest.LexicalTokenizerID,
		LexicalScorerID:    fx.hybrid.Manifest.LexicalScorerID,
		DenseArtifactID:    fx.hybrid.Manifest.DenseArtifactID, DenseArtifactSHA256: fx.hybrid.Manifest.DenseArtifactSHA256,
		DenseModelID: fx.hybrid.Manifest.DenseModelID, DenseModelRevision: fx.hybrid.Manifest.DenseModelRevision,
		DenseModelArtifactSHA256: fx.hybrid.Manifest.DenseModelArtifactSHA256,
		DenseTokenizerID:         fx.hybrid.Manifest.DenseTokenizerID, DenseTokenizerSHA256: fx.hybrid.Manifest.DenseTokenizerSHA256,
		EmbeddingProfile: fx.hybrid.Manifest.EmbeddingProfile, FusionProfile: fx.hybrid.Manifest.FusionProfile,
		RerankingContract: fx.hybrid.Manifest.RerankingContract, RerankingEvaluated: false,
		RerankerModelID: nil, RerankerModelRevision: nil, RerankerModelArtifactSHA256: nil,
		RerankerTokenizerID: nil, RerankerTokenizerSHA256: nil, RerankerProfile: nil,
		RerankerQueryInstruction: nil, RerankerDocumentInstruction: nil, RerankerScoreScale: nil,
		EvaluationDatasetID: suite.SuiteID, EvaluationDatasetSHA256: fx.evaluationSuiteSHA,
		EvaluationMetricsObjectSHA256: fx.evaluationMetricsSHA, EvaluationRuntimeSHA256: fx.evaluationRuntimeSHA,
		EvaluatorID: evaluatorID, EvaluatorRevision: evaluatorRevision,
		EvaluatorExecutableSHA256: fx.executableSHA,
		EvaluatedAt:               "2026-07-16T00:30:00Z", Gates: gates,
	}
	coreBytes, _ := json.Marshal(core)
	digest := digestBytes(coreBytes)
	fx.quality = RetrievalQualityReport{ReportID: "retrieval-quality-report:" + digest, ReportPayloadSHA256: digest, RetrievalQualityReportCore: core}
	writeCanonical(t, fx.qualityPath, fx.quality)
	fx.qualitySHA = fileDigest(fx.qualityPath)
	allowedSigners, err := os.ReadFile(fx.evaluatorAllowed)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := sealQualityReceipt(RetrievalQualityReceiptCore{
		SchemaVersion: retrievalSchemaVersion, ReceiptKind: qualityReceiptKind, State: "passed",
		QualityReportID: fx.quality.ReportID, QualityReportSHA256: fx.qualitySHA,
		EvaluatorID: fx.quality.EvaluatorID, EvaluatorRevision: fx.quality.EvaluatorRevision,
		EvaluatorExecutableSHA256: fx.quality.EvaluatorExecutableSHA256,
		EvaluationRuntimeSHA256:   fx.quality.EvaluationRuntimeSHA256,
		Authorization: RetrievalTransitionAuthorization{Actor: fx.evaluatorActor, Method: retrievalTransitionSignatureMethod,
			KeyID: fx.evaluatorKeyID, Namespace: qualityReceiptSignatureNamespace, AllowedSignersSHA256: digestBytes(allowedSigners)},
		EvaluatedAt: fx.quality.EvaluatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.qualityReceipt = receipt
	fx.qualityReceiptPath = filepath.Join(fx.root, "quality-receipt-"+strings.TrimPrefix(receipt.ReceiptPayloadSHA256, "sha256:")+".json")
	writeCanonical(t, fx.qualityReceiptPath, receipt)
	fx.qualityReceiptSHA = fileDigest(fx.qualityReceiptPath)
	command := exec.Command(sshKeygenPath, "-Y", "sign", "-f", fx.evaluatorPrivateKey, "-n", qualityReceiptSignatureNamespace, fx.qualityReceiptPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sign quality evaluator receipt: %v: %s", err, output)
	}
	fx.qualitySignaturePath = fx.qualityReceiptPath + ".sig"
	fx.qualitySignatureSHA = fileDigest(fx.qualitySignaturePath)
}

func (fx *lifecycleTestFixture) stage(t *testing.T, asOf string, base *StageGenerationResult) StageGenerationResult {
	t.Helper()
	config := fx.stageConfig(asOf, base)
	result, err := StageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (fx *lifecycleTestFixture) stageConfig(asOf string, base *StageGenerationResult) StageGenerationConfig {
	config := StageGenerationConfig{
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath), StoreRoot: fx.outputRoot,
		QualityReportPath: fx.qualityPath, QualityReportHash: fx.qualitySHA,
		QualityReceiptPath: fx.qualityReceiptPath, QualityReceiptHash: fx.qualityReceiptSHA,
		QualitySignaturePath: fx.qualitySignaturePath, QualitySignatureHash: fx.qualitySignatureSHA,
		EvaluatorAllowedSignersPath: fx.evaluatorAllowed,
		EvaluationDatasetPath:       fx.evaluationSuitePath, EvaluationDatasetHash: fx.evaluationSuiteSHA,
		EvaluationMetricsPath: fx.evaluationMetricsPath, EvaluationMetricsHash: fx.evaluationMetricsSHA,
		EvaluationRuntimePath: fx.evaluationRuntimePath, EvaluationRuntimeHash: fx.evaluationRuntimeSHA,
		AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
		RetrievalExecutablePath: fx.executable, RetrievalExecutableHash: fx.executableSHA,
		EvaluatorExecutablePath: fx.executable, EvaluatorExecutableHash: fx.executableSHA, AsOf: asOf,
	}
	if base != nil {
		config.BaseGenerationPath = base.GenerationPath
		config.BaseGenerationHash = mustDocumentHash(base.Generation)
	}
	return config
}

func (fx *lifecycleTestFixture) preparePromotion(t *testing.T, generation StageGenerationResult, transitionedAt string, bootstrap bool, expected string) RetrievalTransitionIntent {
	t.Helper()
	intent, err := PrepareGenerationPromotion(PreparePromotionConfig{
		GenerationPath: generation.GenerationPath, GenerationHash: mustDocumentHash(generation.Generation), StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot,
		AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash, AllowedSignersPath: fx.allowed,
		Actor: fx.actor, KeyID: fx.keyID, TransitionedAt: transitionedAt, Bootstrap: bootstrap, ExpectPointerID: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func (fx *lifecycleTestFixture) prepareRollback(t *testing.T, transitionedAt, expected string) RetrievalTransitionIntent {
	t.Helper()
	intent, err := PrepareGenerationRollback(PrepareRollbackConfig{
		StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot, AdmissionPolicyPath: fx.policyPath,
		AdmissionPolicyHash: fx.policyHash, AllowedSignersPath: fx.allowed, Actor: fx.actor,
		KeyID: fx.keyID, TransitionedAt: transitionedAt, ExpectPointerID: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func (fx *lifecycleTestFixture) signedApplyConfig(t *testing.T, intent RetrievalTransitionIntent, generation *StageGenerationResult) ApplyTransitionConfig {
	t.Helper()
	directory := t.TempDir()
	intentPath := filepath.Join(directory, "intent.json")
	writeCanonical(t, intentPath, intent)
	command := exec.Command(sshKeygenPath, "-Y", "sign", "-f", fx.privateKey, "-n", retrievalTransitionSignatureNamespace, intentPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sign intent: %v: %s", err, output)
	}
	signaturePath := intentPath + ".sig"
	config := ApplyTransitionConfig{
		StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot, IntentPath: intentPath, IntentHash: fileDigest(intentPath),
		SignaturePath: signaturePath, SignatureHash: fileDigest(signaturePath), AllowedSignersPath: fx.allowed,
		AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash, ExpectedDecision: intent.Decision,
	}
	if generation != nil {
		config.GenerationPath = generation.GenerationPath
		config.GenerationHash = mustDocumentHash(generation.Generation)
	}
	return config
}

func (fx *lifecycleTestFixture) status(asOf string) GenerationStatus {
	return GetGenerationStatus(GenerationStatusConfig{StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot, AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash, AsOf: asOf})
}

func signCanonicalTestDocument(t *testing.T, value any, privateKey, namespace string) (string, string, string, string) {
	t.Helper()
	documentPath := filepath.Join(t.TempDir(), "signed.json")
	writeCanonical(t, documentPath, value)
	command := exec.Command(sshKeygenPath, "-Y", "sign", "-f", privateKey, "-n", namespace, documentPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sign canonical test document: %v: %s", err, output)
	}
	signaturePath := documentPath + ".sig"
	return documentPath, fileDigest(documentPath), signaturePath, fileDigest(signaturePath)
}

func TestSignedGenerationPromotionAndExactRollback(t *testing.T) {
	fx := newLifecycleTestFixture(t)
	first := fx.stage(t, "2026-07-16T01:00:00Z", nil)
	if first.Generation.RerankingEvaluated || first.Generation.RerankerModelID != nil || first.Generation.RerankerTokenizerID != nil || !first.Generation.Promotable {
		t.Fatalf("fusion-only generation overclaimed reranking or lost eligibility: %#v", first.Generation)
	}
	firstIntent := fx.preparePromotion(t, first, "2026-07-16T02:00:00Z", true, "")
	firstApply, err := ApplyGenerationTransition(fx.signedApplyConfig(t, firstIntent, &first))
	if err != nil || firstApply.Idempotent {
		t.Fatalf("bootstrap promotion failed: result=%#v err=%v", firstApply, err)
	}

	second := fx.stage(t, "2026-07-16T03:00:00Z", &first)
	secondIntent := fx.preparePromotion(t, second, "2026-07-16T04:00:00Z", false, firstApply.Pointer.PointerID)
	secondApply, err := ApplyGenerationTransition(fx.signedApplyConfig(t, secondIntent, &second))
	if err != nil || secondApply.Pointer.CurrentGenerationID != second.Generation.GenerationID {
		t.Fatalf("second promotion failed: result=%#v err=%v", secondApply, err)
	}

	rollbackIntent := fx.prepareRollback(t, "2026-07-16T05:00:00Z", secondApply.Pointer.PointerID)
	rollbackConfig := fx.signedApplyConfig(t, rollbackIntent, nil)
	rollback, err := ApplyGenerationTransition(rollbackConfig)
	if err != nil || rollback.Pointer.CurrentGenerationID != first.Generation.GenerationID || rollback.Pointer.PreviousGenerationID == nil || *rollback.Pointer.PreviousGenerationID != second.Generation.GenerationID {
		t.Fatalf("exact rollback failed: result=%#v err=%v", rollback, err)
	}
	current, _, err := loadStateGeneration(fx.stateRoot, fx.outputRoot, rollback.Pointer.CurrentGenerationID, rollback.Pointer.CurrentGenerationSHA256)
	if err != nil || !equalStrings(current.EvidenceSpanIDs, first.Generation.EvidenceSpanIDs) {
		t.Fatalf("rollback did not restore exact evidence IDs: current=%#v err=%v", current.EvidenceSpanIDs, err)
	}
	status := fx.status("2026-07-16T06:00:00Z")
	if status.State != "ok" || status.Revision != 3 || status.CurrentGenerationID == nil || *status.CurrentGenerationID != first.Generation.GenerationID {
		t.Fatalf("verified status differs: %#v", status)
	}
	idempotent, err := ApplyGenerationTransition(rollbackConfig)
	if err != nil || !idempotent.Idempotent || idempotent.Pointer.PointerID != rollback.Pointer.PointerID {
		t.Fatalf("transition retry was not idempotent: result=%#v err=%v", idempotent, err)
	}
}

func TestUnevaluatedAndFailedQualityCannotPromote(t *testing.T) {
	fx := newLifecycleTestFixture(t)
	if _, err := PrepareGenerationPromotion(PreparePromotionConfig{
		GenerationPath: fx.hybrid.ManifestPath, GenerationHash: fileDigest(fx.hybrid.ManifestPath), StoreRoot: fx.outputRoot,
		StateRoot: fx.stateRoot, AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
		AllowedSignersPath: fx.allowed, Actor: fx.actor, KeyID: fx.keyID, TransitionedAt: "2026-07-16T02:00:00Z", Bootstrap: true,
	}); err == nil {
		t.Fatal("unevaluated hybrid candidate was accepted as a promotable generation")
	}
	fx.writeQuality(t, false)
	_, err := StageGeneration(StageGenerationConfig{
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath), StoreRoot: fx.outputRoot,
		QualityReportPath: fx.qualityPath, QualityReportHash: fx.qualitySHA, AdmissionPolicyPath: fx.policyPath,
		QualityReceiptPath: fx.qualityReceiptPath, QualityReceiptHash: fx.qualityReceiptSHA,
		QualitySignaturePath: fx.qualitySignaturePath, QualitySignatureHash: fx.qualitySignatureSHA,
		EvaluatorAllowedSignersPath: fx.evaluatorAllowed,
		EvaluationDatasetPath:       fx.evaluationSuitePath, EvaluationDatasetHash: fx.evaluationSuiteSHA,
		EvaluationMetricsPath: fx.evaluationMetricsPath, EvaluationMetricsHash: fx.evaluationMetricsSHA,
		EvaluationRuntimePath: fx.evaluationRuntimePath, EvaluationRuntimeHash: fx.evaluationRuntimeSHA,
		AdmissionPolicyHash: fx.policyHash, RetrievalExecutablePath: fx.executable, RetrievalExecutableHash: fx.executableSHA,
		EvaluatorExecutablePath: fx.executable, EvaluatorExecutableHash: fx.executableSHA,
		AsOf: "2026-07-16T01:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "valid passed") {
		t.Fatalf("failed quality report was accepted: %v", err)
	}

	fx.writeQuality(t, true)
	model := "model:unproven-reranker"
	fx.quality.RerankerModelID = &model
	coreBytes, _ := json.Marshal(fx.quality.RetrievalQualityReportCore)
	digest := digestBytes(coreBytes)
	fx.quality.ReportPayloadSHA256 = digest
	fx.quality.ReportID = "retrieval-quality-report:" + digest
	writeCanonical(t, fx.qualityPath, fx.quality)
	fx.qualitySHA = fileDigest(fx.qualityPath)
	_, err = StageGeneration(StageGenerationConfig{
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath), StoreRoot: fx.outputRoot,
		QualityReportPath: fx.qualityPath, QualityReportHash: fx.qualitySHA, AdmissionPolicyPath: fx.policyPath,
		QualityReceiptPath: fx.qualityReceiptPath, QualityReceiptHash: fx.qualityReceiptSHA,
		QualitySignaturePath: fx.qualitySignaturePath, QualitySignatureHash: fx.qualitySignatureSHA,
		EvaluatorAllowedSignersPath: fx.evaluatorAllowed,
		EvaluationDatasetPath:       fx.evaluationSuitePath, EvaluationDatasetHash: fx.evaluationSuiteSHA,
		EvaluationMetricsPath: fx.evaluationMetricsPath, EvaluationMetricsHash: fx.evaluationMetricsSHA,
		EvaluationRuntimePath: fx.evaluationRuntimePath, EvaluationRuntimeHash: fx.evaluationRuntimeSHA,
		AdmissionPolicyHash: fx.policyHash, RetrievalExecutablePath: fx.executable, RetrievalExecutableHash: fx.executableSHA,
		EvaluatorExecutablePath: fx.executable, EvaluatorExecutableHash: fx.executableSHA,
		AsOf: "2026-07-16T01:00:00Z",
	})
	if err == nil {
		t.Fatal("fusion-only report with unproven reranker bindings was accepted")
	}
}

func TestGenerationStagingRequiresTrustedEvaluatorReceipt(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		config := fx.stageConfig("2026-07-16T01:00:00Z", nil)
		config.QualityReceiptPath = ""
		if _, err := StageGeneration(config); err == nil || !strings.Contains(err.Error(), "quality-receipt") {
			t.Fatalf("missing evaluator receipt was accepted: %v", err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		invalid := fx.qualityReceipt
		invalid.State = "failed"
		coreBytes, _ := json.Marshal(invalid.RetrievalQualityReceiptCore)
		invalid.ReceiptPayloadSHA256 = digestBytes(coreBytes)
		invalid.ReceiptID = "retrieval-quality-receipt:" + invalid.ReceiptPayloadSHA256
		receiptPath, receiptHash, signaturePath, signatureHash := signCanonicalTestDocument(t, invalid, fx.evaluatorPrivateKey, qualityReceiptSignatureNamespace)
		config := fx.stageConfig("2026-07-16T01:00:00Z", nil)
		config.QualityReceiptPath, config.QualityReceiptHash = receiptPath, receiptHash
		config.QualitySignaturePath, config.QualitySignatureHash = signaturePath, signatureHash
		if _, err := StageGeneration(config); err == nil || !strings.Contains(err.Error(), "receipt is invalid") {
			t.Fatalf("failed evaluator receipt was accepted: %v", err)
		}
	})

	t.Run("report mismatch", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		core := fx.qualityReceipt.RetrievalQualityReceiptCore
		core.QualityReportSHA256 = "sha256:" + strings.Repeat("0", 64)
		mismatch, err := sealQualityReceipt(core)
		if err != nil {
			t.Fatal(err)
		}
		receiptPath, receiptHash, signaturePath, signatureHash := signCanonicalTestDocument(t, mismatch, fx.evaluatorPrivateKey, qualityReceiptSignatureNamespace)
		config := fx.stageConfig("2026-07-16T01:00:00Z", nil)
		config.QualityReceiptPath, config.QualityReceiptHash = receiptPath, receiptHash
		config.QualitySignaturePath, config.QualitySignatureHash = signaturePath, signatureHash
		if _, err := StageGeneration(config); err == nil || !strings.Contains(err.Error(), "does not bind") {
			t.Fatalf("receipt for a different report was accepted: %v", err)
		}
	})

	t.Run("signature tamper", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		config := fx.stageConfig("2026-07-16T01:00:00Z", nil)
		signature, _ := os.ReadFile(config.QualitySignaturePath)
		body := len("-----BEGIN SSH SIGNATURE-----\n")
		if signature[body] == 'A' {
			signature[body] = 'B'
		} else {
			signature[body] = 'A'
		}
		path := filepath.Join(t.TempDir(), "tampered.sshsig")
		writeTestFile(t, path, signature, 0o644)
		config.QualitySignaturePath, config.QualitySignatureHash = path, fileDigest(path)
		if _, err := StageGeneration(config); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Fatalf("tampered evaluator signature was accepted: %v", err)
		}
	})

	t.Run("trust policy changed", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		config := fx.stageConfig("2026-07-16T01:00:00Z", nil)
		policy, _ := os.ReadFile(fx.evaluatorAllowed)
		changed := filepath.Join(t.TempDir(), "changed.allowed_signers")
		writeTestFile(t, changed, append(policy, []byte("# changed\n")...), 0o444)
		config.EvaluatorAllowedSignersPath = changed
		if _, err := StageGeneration(config); err == nil || !strings.Contains(err.Error(), "allowed_signers") {
			t.Fatalf("changed evaluator trust policy was accepted: %v", err)
		}
	})

	t.Run("receipt pin", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		config := fx.stageConfig("2026-07-16T01:00:00Z", nil)
		config.QualityReceiptHash = "sha256:" + strings.Repeat("f", 64)
		if _, err := StageGeneration(config); err == nil || !strings.Contains(err.Error(), "caller pin") {
			t.Fatalf("wrong evaluator receipt pin was accepted: %v", err)
		}
	})
}

func TestSSHSIGVerificationIgnoresPATHShadow(t *testing.T) {
	shadowRoot := t.TempDir()
	marker := filepath.Join(shadowRoot, "path-shadow-invoked")
	writeTestFile(t, filepath.Join(shadowRoot, "ssh-keygen"), []byte("#!/bin/sh\n: > \"$SHADOW_MARKER\"\nexit 99\n"), 0o755)
	t.Setenv("SHADOW_MARKER", marker)
	t.Setenv("PATH", shadowRoot)

	fx := newLifecycleTestFixture(t)
	if _, err := StageGeneration(fx.stageConfig("2026-07-16T01:00:00Z", nil)); err != nil {
		t.Fatalf("fixed ssh-keygen boundary rejected a valid signature: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("PATH-shadowed ssh-keygen was invoked: %v", err)
	}
}

func TestTransitionCrashPointsNeverCreateEmptyCurrentWindow(t *testing.T) {
	for _, failpoint := range []string{"after-receipt", "after-pointer", "before-alias", "after-alias"} {
		t.Run(failpoint, func(t *testing.T) {
			fx := newLifecycleTestFixture(t)
			generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
			intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
			config := fx.signedApplyConfig(t, intent, &generation)
			config.Failpoint = failpoint
			if _, err := ApplyGenerationTransition(config); lifecycleCode(err) != "injected-crash" {
				t.Fatalf("failpoint did not interrupt transition: %v", err)
			}
			status := fx.status("2026-07-16T03:00:00Z")
			if failpoint == "after-alias" {
				if status.State != "ok" || status.CurrentGenerationID == nil || *status.CurrentGenerationID != generation.Generation.GenerationID {
					t.Fatalf("post-exchange crash lost current generation: %#v", status)
				}
			} else if status.State != "empty" {
				t.Fatalf("pre-exchange crash exposed partial current state: %#v", status)
			}
			config.Failpoint = ""
			result, err := ApplyGenerationTransition(config)
			if err != nil || result.Pointer.CurrentGenerationID != generation.Generation.GenerationID || (failpoint == "after-alias" && !result.Idempotent) {
				t.Fatalf("crash retry failed: result=%#v err=%v", result, err)
			}
		})
	}
}

func TestTransitionChronologyFailsBeforePointerPublication(t *testing.T) {
	t.Run("bootstrap generation after transition", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		core := intent.RetrievalTransitionIntentCore
		core.TransitionedAt = "2026-07-16T00:45:00Z"
		forged, err := sealTransitionIntent(core)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyGenerationTransition(fx.signedApplyConfig(t, forged, &generation)); lifecycleCode(err) != "generation-time-invalid" {
			t.Fatalf("future generation transition was not rejected before publish: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(fx.stateRoot, generationAliasPath)); !os.IsNotExist(err) {
			t.Fatalf("failed bootstrap published a pointer alias: %v", err)
		}
		if status := fx.status("2026-07-16T03:00:00Z"); status.State != "empty" {
			t.Fatalf("failed bootstrap changed current state: %#v", status)
		}
	})

	t.Run("update timestamp does not advance", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		first := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		firstIntent := fx.preparePromotion(t, first, "2026-07-16T02:00:00Z", true, "")
		firstApply, err := ApplyGenerationTransition(fx.signedApplyConfig(t, firstIntent, &first))
		if err != nil {
			t.Fatal(err)
		}
		second := fx.stage(t, "2026-07-16T01:30:00Z", &first)
		secondIntent := fx.preparePromotion(t, second, "2026-07-16T03:00:00Z", false, firstApply.Pointer.PointerID)
		core := secondIntent.RetrievalTransitionIntentCore
		core.TransitionedAt = firstApply.Pointer.UpdatedAt
		forged, err := sealTransitionIntent(core)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyGenerationTransition(fx.signedApplyConfig(t, forged, &second)); lifecycleCode(err) != "timestamp-not-monotonic" {
			t.Fatalf("non-monotonic transition was not rejected before publish: %v", err)
		}
		status := fx.status("2026-07-16T03:00:00Z")
		if status.State != "ok" || status.Revision != 1 || status.PointerID == nil || *status.PointerID != firstApply.Pointer.PointerID {
			t.Fatalf("failed update changed the current pointer: %#v", status)
		}
	})
}

func TestTransitionTamperAndStalePolicyFailClosed(t *testing.T) {
	t.Run("intent", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		config := fx.signedApplyConfig(t, intent, &generation)
		changedCore := intent.RetrievalTransitionIntentCore
		changedCore.TransitionedAt = "2026-07-16T02:01:00Z"
		changed, err := sealTransitionIntent(changedCore)
		if err != nil {
			t.Fatal(err)
		}
		writeCanonical(t, config.IntentPath, changed)
		config.IntentHash = fileDigest(config.IntentPath)
		if _, err := ApplyGenerationTransition(config); lifecycleCode(err) != "signature-verification-failed" {
			t.Fatalf("self-consistent intent replacement bypassed signature: %v", err)
		}
	})

	t.Run("signature", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		config := fx.signedApplyConfig(t, intent, &generation)
		signature, _ := os.ReadFile(config.SignaturePath)
		body := len("-----BEGIN SSH SIGNATURE-----\n")
		if signature[body] == 'A' {
			signature[body] = 'B'
		} else {
			signature[body] = 'A'
		}
		writeTestFile(t, config.SignaturePath, signature, 0o644)
		config.SignatureHash = fileDigest(config.SignaturePath)
		if _, err := ApplyGenerationTransition(config); lifecycleCode(err) != "signature-verification-failed" {
			t.Fatalf("tampered signature was accepted: %v", err)
		}
	})

	t.Run("allowed signers", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		config := fx.signedApplyConfig(t, intent, &generation)
		policy, _ := os.ReadFile(fx.allowed)
		if err := os.Chmod(fx.allowed, 0o644); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, fx.allowed, append(policy, []byte("# changed\n")...), 0o444)
		if _, err := ApplyGenerationTransition(config); lifecycleCode(err) != "authorization-policy-hash-mismatch" {
			t.Fatalf("changed allowed_signers was accepted: %v", err)
		}
	})

	t.Run("stored generation", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		result, err := ApplyGenerationTransition(fx.signedApplyConfig(t, intent, &generation))
		if err != nil {
			t.Fatal(err)
		}
		relative, _ := generationStateRelative(generation.Generation)
		stateGeneration := filepath.Join(fx.stateRoot, filepath.FromSlash(relative))
		data, _ := os.ReadFile(stateGeneration)
		if err := os.Chmod(stateGeneration, 0o644); err != nil {
			t.Fatal(err)
		}
		data[len(data)-2] ^= 1
		if err := os.WriteFile(stateGeneration, data, 0o644); err != nil {
			t.Fatal(err)
		}
		status := fx.status("2026-07-16T03:00:00Z")
		if status.State != "backend_unavailable" || result.Pointer.CurrentGenerationID == "" {
			t.Fatalf("tampered current generation remained available: %#v", status)
		}
	})

	t.Run("stored previous generation", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		first := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		firstIntent := fx.preparePromotion(t, first, "2026-07-16T02:00:00Z", true, "")
		firstApply, err := ApplyGenerationTransition(fx.signedApplyConfig(t, firstIntent, &first))
		if err != nil {
			t.Fatal(err)
		}
		second := fx.stage(t, "2026-07-16T03:00:00Z", &first)
		secondIntent := fx.preparePromotion(t, second, "2026-07-16T04:00:00Z", false, firstApply.Pointer.PointerID)
		if _, err := ApplyGenerationTransition(fx.signedApplyConfig(t, secondIntent, &second)); err != nil {
			t.Fatal(err)
		}
		relative, _ := generationStateRelative(first.Generation)
		previousPath := filepath.Join(fx.stateRoot, filepath.FromSlash(relative))
		data, _ := os.ReadFile(previousPath)
		if err := os.Chmod(previousPath, 0o644); err != nil {
			t.Fatal(err)
		}
		data[len(data)-2] ^= 1
		if err := os.WriteFile(previousPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if status := fx.status("2026-07-16T05:00:00Z"); status.State != "backend_unavailable" {
			t.Fatalf("tampered previous generation remained available: %#v", status)
		}
	})

	t.Run("stale admission policy", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		_, err := PrepareGenerationPromotion(PreparePromotionConfig{
			GenerationPath: generation.GenerationPath, GenerationHash: mustDocumentHash(generation.Generation), StoreRoot: fx.outputRoot,
			StateRoot: fx.stateRoot, AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
			AllowedSignersPath: fx.allowed, Actor: fx.actor, KeyID: fx.keyID, TransitionedAt: "2026-07-18T00:00:00Z", Bootstrap: true,
		})
		if lifecycleCode(err) != "admission-policy-invalid" {
			t.Fatalf("stale policy was accepted: %v", err)
		}
	})
}

func TestPromotedGenerationReverifiesStoredEvaluatorEvidence(t *testing.T) {
	tests := []struct {
		name string
		path func(RetrievalGeneration) string
	}{
		{name: "receipt", path: func(generation RetrievalGeneration) string { return generation.QualityReceiptPath }},
		{name: "signature", path: func(generation RetrievalGeneration) string { return generation.QualitySignaturePath }},
		{name: "trust policy", path: func(generation RetrievalGeneration) string { return generation.EvaluatorAllowedSignersPath }},
		{name: "frozen suite", path: func(generation RetrievalGeneration) string { return generation.EvaluationDatasetPath }},
		{name: "recomputed metrics", path: func(generation RetrievalGeneration) string { return generation.EvaluationMetricsObjectPath }},
		{name: "runtime", path: func(generation RetrievalGeneration) string { return generation.EvaluationRuntimePath }},
		{name: "evaluator executable", path: func(generation RetrievalGeneration) string { return generation.EvaluatorExecutablePath }},
		{name: "retrieval executable", path: func(generation RetrievalGeneration) string { return generation.RetrievalExecutablePath }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fx := newLifecycleTestFixture(t)
			generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
			intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
			if _, err := ApplyGenerationTransition(fx.signedApplyConfig(t, intent, &generation)); err != nil {
				t.Fatal(err)
			}

			target := filepath.Join(fx.outputRoot, filepath.FromSlash(test.path(generation.Generation)))
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			data[len(data)/2] ^= 1
			if err := os.WriteFile(target, data, 0o444); err != nil {
				t.Fatal(err)
			}

			if status := fx.status("2026-07-16T03:00:00Z"); status.State != "backend_unavailable" {
				t.Fatalf("tampered stored evaluator %s remained available: %#v", test.name, status)
			}
		})
	}
}

func TestGenerationLifecycleRejectsSymlinkedInputsAndState(t *testing.T) {
	t.Run("generation object path escape", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		forged := generation.Generation
		forged.QualityReportPath = "../quality.json"
		coreBytes, _ := json.Marshal(forged.RetrievalGenerationCore)
		forged.GenerationPayloadSHA256 = digestBytes(coreBytes)
		forged.GenerationID = "retrieval-generation:" + forged.GenerationPayloadSHA256
		forgedPath := filepath.Join(fx.root, "path-escape-generation.json")
		writeCanonical(t, forgedPath, forged)
		_, err := PrepareGenerationPromotion(PreparePromotionConfig{
			GenerationPath: forgedPath, GenerationHash: fileDigest(forgedPath), StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot,
			AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash, AllowedSignersPath: fx.allowed,
			Actor: fx.actor, KeyID: fx.keyID, TransitionedAt: "2026-07-16T02:00:00Z", Bootstrap: true,
		})
		if lifecycleCode(err) != "candidate-invalid" {
			t.Fatalf("generation object path escape was accepted: %v", err)
		}
	})

	t.Run("generation input", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		link := filepath.Join(fx.root, "generation-link.json")
		if err := os.Symlink(generation.GenerationPath, link); err != nil {
			t.Fatal(err)
		}
		_, err := PrepareGenerationPromotion(PreparePromotionConfig{
			GenerationPath: link, GenerationHash: mustDocumentHash(generation.Generation), StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot,
			AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash, AllowedSignersPath: fx.allowed,
			Actor: fx.actor, KeyID: fx.keyID, TransitionedAt: "2026-07-16T02:00:00Z", Bootstrap: true,
		})
		if lifecycleCode(err) != "candidate-invalid" {
			t.Fatalf("symlinked generation input was accepted: %v", err)
		}
	})

	t.Run("state root", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		realState := filepath.Join(fx.root, "real-state")
		if err := os.MkdirAll(realState, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realState, fx.stateRoot); err != nil {
			t.Fatal(err)
		}
		_, err := PrepareGenerationPromotion(PreparePromotionConfig{
			GenerationPath: generation.GenerationPath, GenerationHash: mustDocumentHash(generation.Generation), StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot,
			AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash, AllowedSignersPath: fx.allowed,
			Actor: fx.actor, KeyID: fx.keyID, TransitionedAt: "2026-07-16T02:00:00Z", Bootstrap: true,
		})
		if lifecycleCode(err) != "state-root-invalid" {
			t.Fatalf("symlinked state root was accepted: %v", err)
		}
	})

	t.Run("state lock", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		if err := os.MkdirAll(fx.stateRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(fx.stateRoot, "lock-target")
		writeTestFile(t, target, []byte{}, 0o600)
		if err := os.Symlink(target, filepath.Join(fx.stateRoot, generationLockPath)); err != nil {
			t.Fatal(err)
		}
		_, err := PrepareGenerationPromotion(PreparePromotionConfig{
			GenerationPath: generation.GenerationPath, GenerationHash: mustDocumentHash(generation.Generation), StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot,
			AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash, AllowedSignersPath: fx.allowed,
			Actor: fx.actor, KeyID: fx.keyID, TransitionedAt: "2026-07-16T02:00:00Z", Bootstrap: true,
		})
		if lifecycleCode(err) != "lock-invalid" {
			t.Fatalf("symlinked state lock was accepted: %v", err)
		}
	})

	t.Run("pointer alias", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		result, err := ApplyGenerationTransition(fx.signedApplyConfig(t, intent, &generation))
		if err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(fx.stateRoot, generationAliasPath)
		pointerRelative, _ := pointerStateRelative(result.Pointer.PointerID)
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(fx.stateRoot, filepath.FromSlash(pointerRelative)), alias); err != nil {
			t.Fatal(err)
		}
		status := fx.status("2026-07-16T03:00:00Z")
		if status.State != "backend_unavailable" {
			t.Fatalf("symlinked pointer alias remained available: %#v", status)
		}
	})
}

func TestConcurrentGenerationPromotionsUsePointerCAS(t *testing.T) {
	fx := newLifecycleTestFixture(t)
	base := fx.stage(t, "2026-07-16T01:00:00Z", nil)
	baseIntent := fx.preparePromotion(t, base, "2026-07-16T02:00:00Z", true, "")
	baseApply, err := ApplyGenerationTransition(fx.signedApplyConfig(t, baseIntent, &base))
	if err != nil {
		t.Fatal(err)
	}
	left := fx.stage(t, "2026-07-16T03:00:00Z", &base)
	right := fx.stage(t, "2026-07-16T03:01:00Z", &base)
	leftIntent := fx.preparePromotion(t, left, "2026-07-16T04:00:00Z", false, baseApply.Pointer.PointerID)
	rightIntent := fx.preparePromotion(t, right, "2026-07-16T04:01:00Z", false, baseApply.Pointer.PointerID)
	configs := []ApplyTransitionConfig{fx.signedApplyConfig(t, leftIntent, &left), fx.signedApplyConfig(t, rightIntent, &right)}
	var wait sync.WaitGroup
	errorsSeen := make([]error, 2)
	for index := range configs {
		wait.Add(1)
		go func(position int) {
			defer wait.Done()
			_, errorsSeen[position] = ApplyGenerationTransition(configs[position])
		}(index)
	}
	wait.Wait()
	successes, conflicts := 0, 0
	for _, err := range errorsSeen {
		if err == nil {
			successes++
		} else if lifecycleCode(err) == "cas-mismatch" {
			conflicts++
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent promotions did not produce one winner: errors=%v", errorsSeen)
	}
	status := fx.status("2026-07-16T05:00:00Z")
	if status.State != "ok" || status.Revision != 2 {
		t.Fatalf("winning CAS did not leave a valid state: %#v", status)
	}
}

func TestLifecycleErrorsRemainTyped(t *testing.T) {
	err := lifecycleFailure("example", "message")
	var typed *LifecycleError
	if !errors.As(err, &typed) || lifecycleCode(err) != "example" {
		t.Fatalf("typed lifecycle error contract lost: %v", err)
	}
}

// TestVerifyGenerationStateAllowlistsOnlyVerifiedStates pins the fail-closed
// contract: only a genuinely verified state passes, an absent generation store
// never passes by default, and a caller that can accept absence must say so.
func TestVerifyGenerationStateAllowlistsOnlyVerifiedStates(t *testing.T) {
	verifyConfig := func(fx *lifecycleTestFixture, asOf string, allowAbsent bool) GenerationStatusConfig {
		return GenerationStatusConfig{
			StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot,
			AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
			AsOf: asOf, AllowAbsentGeneration: allowAbsent,
		}
	}

	t.Run("absent generation store does not verify", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		if status := fx.status("2026-07-16T03:00:00Z"); status.State != "empty" {
			t.Fatalf("fixture was not an absent store: %#v", status)
		}
		err := VerifyGenerationState(verifyConfig(fx, "2026-07-16T03:00:00Z", false))
		if err == nil {
			t.Fatal("an absent generation store verified successfully")
		}
		if lifecycleCode(err) != "generation-absent" {
			t.Fatalf("absent store failed with the wrong typed code: %s", lifecycleCode(err))
		}
	})

	t.Run("absent generation store verifies only when explicitly allowed", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		if err := VerifyGenerationState(verifyConfig(fx, "2026-07-16T03:00:00Z", true)); err != nil {
			t.Fatalf("explicit absent-is-acceptable caller was rejected: %v", err)
		}
	})

	t.Run("promoted generation verifies", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		if _, err := ApplyGenerationTransition(fx.signedApplyConfig(t, intent, &generation)); err != nil {
			t.Fatal(err)
		}
		if status := fx.status("2026-07-16T03:00:00Z"); status.State != "ok" {
			t.Fatalf("promoted fixture was not ok: %#v", status)
		}
		if err := VerifyGenerationState(verifyConfig(fx, "2026-07-16T03:00:00Z", false)); err != nil {
			t.Fatalf("a genuinely verified generation was rejected: %v", err)
		}
		// Absence handling must not have weakened tamper detection.
		if err := os.Remove(filepath.Join(fx.stateRoot, generationAliasPath)); err != nil {
			t.Fatal(err)
		}
		if err := VerifyGenerationState(verifyConfig(fx, "2026-07-16T03:00:00Z", false)); err == nil {
			t.Fatal("a removed pointer alias verified successfully")
		}
	})

	t.Run("unavailable backend does not verify", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		config := verifyConfig(fx, "2026-07-16T03:00:00Z", true)
		config.AdmissionPolicyHash = ""
		if err := VerifyGenerationState(config); err == nil {
			t.Fatal("an unavailable backend verified successfully even for an absent-tolerant caller")
		}
	})
}
