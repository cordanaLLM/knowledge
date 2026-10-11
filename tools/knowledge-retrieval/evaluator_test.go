package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	rolloutsEvaluationSuiteFixture  = "testdata/evaluation-suites/argo-rollouts-v1.9.0-fusion-suite-v1.core.json"
	workflowsEvaluationSuiteFixture = "testdata/evaluation-suites/argo-workflows-v4.0.7-fusion-suite-v1.core.json"
)

type evaluatorTestFixture struct {
	*hybridTestFixture
	signalRoot     string
	suitePath      string
	suite          RetrievalEvaluationSuite
	suiteHash      string
	executablePath string
	executableHash string
	actor          string
	keyID          string
	privateKey     string
	allowedSigners string
}

func TestEvaluatorRecomputesRealFusionOnlyMetricsAndGates(t *testing.T) {
	fx := newEvaluatorTestFixture(t)
	result, err := EvaluateRetrieval(fx.config())
	if err != nil {
		t.Fatal(err)
	}
	if result.Metrics.State != "passed" || result.QualityReport.State != "passed" || result.Runtime.State != "passed" || result.QualityReceipt == nil {
		t.Fatalf("evaluator did not produce a passed signable result: %+v", result)
	}
	if !allQualityGatesPassed(result.Metrics.Gates) || result.QualityReport.Gates != result.Metrics.Gates {
		t.Fatalf("evaluator gates were not derived consistently: metrics=%+v report=%+v", result.Metrics.Gates, result.QualityReport.Gates)
	}
	if result.QualityReport.EvaluationDatasetID != fx.suite.SuiteID || result.QualityReport.EvaluationDatasetSHA256 != fx.suiteHash || result.QualityReport.RerankingEvaluated || result.QualityReport.RerankerModelID != nil {
		t.Fatalf("quality report lost frozen suite or fusion-only binding: %+v", result.QualityReport)
	}
	if result.Metrics.ResourceUsage.Executions != 12 || result.Metrics.ResourceUsage.DenseScannedDocuments == 0 {
		t.Fatalf("deterministic resource accounting is incomplete: %+v", result.Metrics.ResourceUsage)
	}
	for _, target := range []string{result.MetricsPath, result.RuntimePath, result.QualityReportPath, result.QualityReceiptPath} {
		if target == "" {
			t.Fatal("passed evaluation omitted an immutable output path")
		}
		if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o444 {
			t.Fatalf("evaluation output %s is not immutable: %v %v", target, info, err)
		}
	}

	again, err := EvaluateRetrieval(fx.config())
	if err != nil {
		t.Fatal(err)
	}
	if again.Metrics.MetricsID != result.Metrics.MetricsID || again.Runtime.RuntimeID != result.Runtime.RuntimeID || again.QualityReport.ReportID != result.QualityReport.ReportID || again.QualityReceipt == nil || again.QualityReceipt.ReceiptID != result.QualityReceipt.ReceiptID {
		t.Fatal("deterministic evaluator output changed across identical runs")
	}
}

func TestEvaluatorFailedDerivedGateCannotProduceReceipt(t *testing.T) {
	fx := newEvaluatorTestFixture(t)
	fx.suite.ResourceLimits.MaxExecutions = 1
	fx.resealSuite(t)
	result, err := EvaluateRetrieval(fx.config())
	if err != nil {
		t.Fatal(err)
	}
	if result.Metrics.State != "failed" || result.Metrics.Gates.ResourceBounds || result.QualityReport.State != "failed" || result.QualityReceipt != nil || result.QualityReceiptPath != "" {
		t.Fatalf("failed resource gate became signable: %+v", result)
	}
	if err := validateQualityReport(result.QualityReport); err == nil {
		t.Fatal("stage-quality validation accepted a failed evaluator report")
	}
}

func TestEvaluatorRejectsTamperedSignalsAndExecutablePins(t *testing.T) {
	t.Run("signal", func(t *testing.T) {
		fx := newEvaluatorTestFixture(t)
		signalPath := filepath.Join(fx.signalRoot, filepath.FromSlash(fx.suite.Cases[0].QuerySignalPath))
		if err := os.Chmod(signalPath, 0o644); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(signalPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(signalPath, append(data, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := EvaluateRetrieval(fx.config()); err == nil || !strings.Contains(err.Error(), "query signal") {
			t.Fatalf("tampered query signal was accepted: %v", err)
		}
	})

	t.Run("executable", func(t *testing.T) {
		fx := newEvaluatorTestFixture(t)
		config := fx.config()
		config.EvaluatorExecutableHash = "sha256:" + strings.Repeat("0", 64)
		if _, err := EvaluateRetrieval(config); err == nil || !strings.Contains(err.Error(), "executable") {
			t.Fatalf("wrong evaluator executable pin was accepted: %v", err)
		}
	})
}

func TestEvaluatorRejectsMixedRerankerInstructions(t *testing.T) {
	for name, mutate := range map[string]func(*QuerySignalArtifact){
		"query": func(signal *QuerySignalArtifact) {
			signal.RerankerQueryInstruction = "Use a different query instruction."
		},
		"document": func(signal *QuerySignalArtifact) {
			signal.RerankerDocumentInstruction = "Use a different document instruction."
		},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newEvaluatorTestFixture(t)
			first := fx.enableReranking(t)
			second := first
			mutate(&second)
			resealQuerySignals(&second)
			secondRelative, secondHash, secondSize := fx.writeEvaluationSignal(t, second)
			secondCase := fx.suite.Cases[0]
			secondCase.CaseID = "case-beta"
			secondCase.QuerySignalArtifactID = second.ArtifactID
			secondCase.QuerySignalSHA256 = secondHash
			secondCase.QuerySignalPath = secondRelative
			secondCase.QuerySignalByteSize = secondSize
			secondCase.InjectionMarker = ""
			fx.suite.Cases = append(fx.suite.Cases, secondCase)
			fx.resealSuite(t)

			if _, err := EvaluateRetrieval(fx.config()); err == nil || !strings.Contains(err.Error(), "mixes reranker contracts") {
				t.Fatalf("mixed reranker %s instructions were accepted: %v", name, err)
			}
		})
	}
}

func TestRerankedEvaluationStagesCompleteCanonicalContract(t *testing.T) {
	fx := newEvaluatorTestFixture(t)
	signal := fx.enableReranking(t)
	evaluated, err := EvaluateRetrieval(fx.config())
	if err != nil {
		t.Fatal(err)
	}
	if evaluated.QualityReceipt == nil || evaluated.QualityReport.RerankerQueryInstruction == nil || *evaluated.QualityReport.RerankerQueryInstruction != signal.RerankerQueryInstruction || evaluated.QualityReport.RerankerDocumentInstruction == nil || *evaluated.QualityReport.RerankerDocumentInstruction != signal.RerankerDocumentInstruction || evaluated.QualityReport.RerankerScoreScale == nil || *evaluated.QualityReport.RerankerScoreScale != signal.RerankerScoreScale {
		t.Fatalf("reranked quality report lost its canonical scorer contract: %+v", evaluated.QualityReport)
	}

	receiptPath, receiptHash, signaturePath, signatureHash := signCanonicalTestDocument(t, *evaluated.QualityReceipt, fx.privateKey, qualityReceiptSignatureNamespace)
	staged, err := StageGeneration(StageGenerationConfig{
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath), StoreRoot: fx.outputRoot,
		QualityReportPath: evaluated.QualityReportPath, QualityReportHash: fileDigest(evaluated.QualityReportPath),
		QualityReceiptPath: receiptPath, QualityReceiptHash: receiptHash,
		QualitySignaturePath: signaturePath, QualitySignatureHash: signatureHash,
		EvaluatorAllowedSignersPath: fx.allowedSigners,
		EvaluationDatasetPath:       fx.suitePath, EvaluationDatasetHash: fx.suiteHash,
		EvaluationMetricsPath: evaluated.MetricsPath, EvaluationMetricsHash: fileDigest(evaluated.MetricsPath),
		EvaluationRuntimePath: evaluated.RuntimePath, EvaluationRuntimeHash: fileDigest(evaluated.RuntimePath),
		EvaluatorExecutablePath: fx.executablePath, EvaluatorExecutableHash: fx.executableHash,
		AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
		RetrievalExecutablePath: fx.executablePath, RetrievalExecutableHash: fx.executableHash,
		AsOf: fx.suite.EvaluatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !staged.Generation.RerankingEvaluated || staged.Generation.RerankerQueryInstruction == nil || *staged.Generation.RerankerQueryInstruction != signal.RerankerQueryInstruction || staged.Generation.RerankerDocumentInstruction == nil || *staged.Generation.RerankerDocumentInstruction != signal.RerankerDocumentInstruction || staged.Generation.RerankerScoreScale == nil || *staged.Generation.RerankerScoreScale != signal.RerankerScoreScale {
		t.Fatalf("staged generation lost its canonical reranker contract: %+v", staged.Generation)
	}
}

func TestEvaluationSuiteBindsThresholdsAndExactCandidateLineage(t *testing.T) {
	fx := newEvaluatorTestFixture(t)

	fx.suite.Thresholds[0].MinRecallPPM = retrievalMetricScale + 1
	if _, err := sealEvaluationSuite(fx.suite.RetrievalEvaluationSuiteCore); err == nil {
		t.Fatal("out-of-scale threshold was accepted")
	}

	fx = newEvaluatorTestFixture(t)
	fx.suite.HybridCandidateSHA256 = "sha256:" + strings.Repeat("9", 64)
	fx.resealSuite(t)
	if _, err := EvaluateRetrieval(fx.config()); err == nil || !strings.Contains(err.Error(), "candidate lineage") {
		t.Fatalf("suite candidate substitution was accepted: %v", err)
	}

	t.Run("limit must cover metric cutoff", func(t *testing.T) {
		fx := newEvaluatorTestFixture(t)
		fx.suite.CutoffK = 3
		fx.suite.Limit = 2
		if _, err := sealEvaluationSuite(fx.suite.RetrievalEvaluationSuiteCore); err == nil {
			t.Fatal("suite whose result limit cannot cover its metric cutoff was accepted")
		}
	})

	t.Run("limit may exceed metric cutoff", func(t *testing.T) {
		fx := newEvaluatorTestFixture(t)
		fx.suite.CutoffK = 1
		fx.suite.Limit = 2
		if _, err := sealEvaluationSuite(fx.suite.RetrievalEvaluationSuiteCore); err != nil {
			t.Fatalf("suite with a result limit above its metric cutoff was rejected: %v", err)
		}
	})
}

func newEvaluatorTestFixture(t *testing.T) *evaluatorTestFixture {
	return newEvaluatorTestFixtureForProfile(t, "")
}

func newEvaluatorTestFixtureForProfile(t *testing.T, lexicalProfile string) *evaluatorTestFixture {
	t.Helper()
	hybrid := newHybridTestFixtureForProfile(t, lexicalProfile)
	executablePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	fx := &evaluatorTestFixture{
		hybridTestFixture: hybrid, signalRoot: filepath.Join(hybrid.root, "evaluation-signals"),
		suitePath: filepath.Join(hybrid.root, "held-out-suite.json"), executablePath: executablePath,
		executableHash: digestBytes(executableBytes), actor: "retrieval-quality-evaluator",
		allowedSigners: filepath.Join(hybrid.root, "evaluation-allowed-signers"),
	}
	fx.privateKey = filepath.Join(hybrid.root, "evaluation-ed25519")
	fx.keyID = createTestSigner(t, fx.privateKey, fx.allowedSigners, fx.actor)

	signals, _, _ := hybrid.writeSignals(t, "alpha", []int16{0, denseQuantizationScale}, map[string]int64{hybrid.alphaDocID: 0, hybrid.semanticDocID: 0})
	disableReranking(&signals)
	resealQuerySignals(&signals)
	signalBytes, err := marshalDocument(signals)
	if err != nil {
		t.Fatal(err)
	}
	signalHash := digestBytes(signalBytes)
	signalRelative, err := contentObjectPath("query-signals", signals.ArtifactPayloadSHA256)
	if err != nil {
		t.Fatal(err)
	}
	signalPath := filepath.Join(fx.signalRoot, filepath.FromSlash(signalRelative))
	writeTestFile(t, signalPath, signalBytes, 0o444)

	alphaSpan := ""
	for _, document := range hybrid.index.Documents {
		if document.DocumentID == hybrid.alphaDocID {
			alphaSpan = document.Evidence.SpanID
		}
	}
	if alphaSpan == "" {
		t.Fatal("alpha test span not found")
	}
	core := RetrievalEvaluationSuiteCore{
		SchemaVersion: retrievalSchemaVersion, SuiteKind: retrievalEvaluationSuiteKind, State: "frozen",
		Name: "smallest-argo-fusion-suite", Revision: "fixture@1.0.0", EvaluatedAt: "2026-07-16T00:00:00Z",
		LexicalCandidateID: hybrid.lexical.Manifest.ManifestID, LexicalCandidateSHA256: fileDigest(hybrid.lexical.ManifestPath),
		HybridCandidateID: hybrid.hybrid.Manifest.ManifestID, HybridCandidateSHA256: fileDigest(hybrid.hybrid.ManifestPath),
		AdmissionPolicyID: hybrid.policy.PolicyID, AdmissionPolicySHA256: hybrid.policyHash,
		SourceAdmissionMethod:       hybrid.hybrid.Manifest.SourceAdmissionMethod,
		SourceAdmissionPolicyID:     hybrid.hybrid.Manifest.SourceAdmissionPolicyID,
		SourceAdmissionPolicySHA256: hybrid.hybrid.Manifest.SourceAdmissionPolicySHA256,
		TargetMode:                  "fusion_only", MetricAlgorithm: metricAlgorithm, MetricScale: retrievalMetricScale,
		CutoffK: 2, Limit: 2, FusionWindow: 2, RerankWindow: 0, MaxExcerptBytes: 2048,
		RollbackMode:   "bootstrap",
		ResourceLimits: RetrievalEvaluationResourceLimits{MaxExecutions: 100, MaxDenseScannedDocuments: 100, MaxReturnedResults: 100, MaxReturnedExcerptBytes: 1_000_000, MaxQuerySignalBytes: 1_000_000},
		Thresholds: []RetrievalMetricThreshold{
			{Class: "smoke", Profile: "hybrid", MinRecallPPM: 0, MinMRRPPM: 0, MinNDCGPPM: 0},
			{Class: "smoke", Profile: "lexical", MinRecallPPM: 0, MinMRRPPM: 0, MinNDCGPPM: 0},
		},
		Cases: []RetrievalEvaluationCase{{
			CaseID: "case-alpha", Class: "smoke", Query: "alpha", QuerySHA256: digestBytes([]byte("alpha")),
			QuerySignalArtifactID: signals.ArtifactID, QuerySignalSHA256: signalHash, QuerySignalPath: signalRelative,
			QuerySignalByteSize: int64(len(signalBytes)), InjectionMarker: "alpha lexical",
			RelevanceJudgments: []RetrievalRelevanceJudgment{{SpanID: alphaSpan, Grade: 3}},
		}},
	}
	suite, err := sealEvaluationSuite(core)
	if err != nil {
		t.Fatal(err)
	}
	fx.suite = suite
	fx.resealSuite(t)
	return fx
}

func (fx *evaluatorTestFixture) writeEvaluationSignal(t *testing.T, signal QuerySignalArtifact) (string, string, int64) {
	t.Helper()
	signalBytes, err := marshalDocument(signal)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := contentObjectPath("query-signals", signal.ArtifactPayloadSHA256)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(fx.signalRoot, filepath.FromSlash(relative)), signalBytes, 0o444)
	return relative, digestBytes(signalBytes), int64(len(signalBytes))
}

func (fx *evaluatorTestFixture) enableReranking(t *testing.T) QuerySignalArtifact {
	t.Helper()
	signal, _, _ := fx.writeSignals(t, fx.suite.Cases[0].Query, []int16{0, denseQuantizationScale}, map[string]int64{fx.alphaDocID: 0, fx.semanticDocID: 0})
	relative, hash, size := fx.writeEvaluationSignal(t, signal)
	fx.suite.TargetMode = "reranked"
	fx.suite.RerankWindow = fx.suite.FusionWindow
	fx.suite.Cases[0].QuerySignalArtifactID = signal.ArtifactID
	fx.suite.Cases[0].QuerySignalSHA256 = hash
	fx.suite.Cases[0].QuerySignalPath = relative
	fx.suite.Cases[0].QuerySignalByteSize = size
	fx.resealSuite(t)
	return signal
}

func (fx *evaluatorTestFixture) resealSuite(t *testing.T) {
	t.Helper()
	suite, err := sealEvaluationSuite(fx.suite.RetrievalEvaluationSuiteCore)
	if err != nil {
		t.Fatal(err)
	}
	fx.suite = suite
	writeCanonical(t, fx.suitePath, suite)
	data, err := os.ReadFile(fx.suitePath)
	if err != nil {
		t.Fatal(err)
	}
	fx.suiteHash = digestBytes(data)
}

func (fx *evaluatorTestFixture) config() EvaluateRetrievalConfig {
	return EvaluateRetrievalConfig{
		SuitePath: fx.suitePath, SuiteHash: fx.suiteHash,
		LexicalCandidatePath: fx.lexical.ManifestPath, LexicalCandidateHash: fileDigest(fx.lexical.ManifestPath),
		HybridCandidatePath: fx.hybrid.ManifestPath, HybridCandidateHash: fileDigest(fx.hybrid.ManifestPath),
		StoreRoot: fx.outputRoot, EvidenceStoreRoot: fx.evidenceRoot, QuerySignalStoreRoot: fx.signalRoot,
		AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
		RetrievalExecutablePath: fx.executablePath, RetrievalExecutableHash: fx.executableHash,
		EvaluatorExecutablePath: fx.executablePath, EvaluatorExecutableHash: fx.executableHash,
		EvaluatorAllowedSignersPath: fx.allowedSigners, EvaluatorActor: fx.actor, EvaluatorKeyID: fx.keyID,
	}
}

func TestEvaluatorCanonicalOutputBytesAreStable(t *testing.T) {
	fx := newEvaluatorTestFixture(t)
	first, err := EvaluateRetrieval(fx.config())
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first.QualityReportPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluateRetrieval(fx.config())
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second.QualityReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("canonical quality report bytes changed across deterministic replay")
	}
}

func TestMaterializeEvaluationSuiteDerivesIdentityAndImmutableCAS(t *testing.T) {
	fx := newEvaluatorTestFixture(t)
	corePath := filepath.Join(t.TempDir(), "suite-core.json")
	writeCanonical(t, corePath, fx.suite.RetrievalEvaluationSuiteCore)
	store := filepath.Join(t.TempDir(), "suite-store")
	first, firstPath, err := MaterializeEvaluationSuite(corePath, store)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializeEvaluationSuite(corePath, store)
	if err != nil {
		t.Fatal(err)
	}
	if first.SuiteID != fx.suite.SuiteID || !reflect.DeepEqual(first, second) || firstPath != secondPath {
		t.Fatalf("suite materialization is not content-derived and deterministic: first=%+v second=%+v", first, second)
	}
	data, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RetrievalEvaluationSuite
	if err := decodeStrictCanonical(data, &decoded); err != nil || decoded.SuiteID != first.SuiteID {
		t.Fatalf("materialized suite is not strict canonical: %v", err)
	}
	if info, err := os.Stat(firstPath); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("materialized suite is not immutable: %v %v", info, err)
	}
}

func TestFrozenRolloutsEvaluationSuiteIdentity(t *testing.T) {
	store := t.TempDir()
	first, firstPath, err := MaterializeEvaluationSuite(rolloutsEvaluationSuiteFixture, store)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializeEvaluationSuite(rolloutsEvaluationSuiteFixture, store)
	if err != nil {
		t.Fatal(err)
	}

	const wantID = "retrieval-evaluation-suite:sha256:b6baf3525ac470128e441a91d847fa9908e018f6bfa30aadf35d3b9faac0f6a8"
	const wantDocumentHash = "sha256:4e712e2fbaf5ca6895d32e3c36531a366da8fc14f0573f9ed768e1ee6b8c50e6"
	if first.SuiteID != wantID || firstPath != secondPath || !reflect.DeepEqual(first, second) {
		t.Fatalf("frozen Rollouts suite identity or deterministic replay drifted: first=%+v second=%+v", first, second)
	}
	if got := fileDigest(firstPath); got != wantDocumentHash {
		t.Fatalf("frozen Rollouts suite document hash changed: got %s want %s", got, wantDocumentHash)
	}
	if len(first.Cases) != 4 || len(first.Thresholds) != 8 {
		t.Fatalf("frozen Rollouts suite lost reviewed cases or thresholds: cases=%d thresholds=%d", len(first.Cases), len(first.Thresholds))
	}
}

// Binds the frozen Rollouts suite to the accepted scorer-blind review in
// .workingdir2/cluster-2/audits/argo-rollouts-scorer-blind-qrels-2026-07-16.md.
// TestFrozenRolloutsEvaluationSuiteIdentity seals the bytes, but passes if a
// regenerated suite and its expected hash are updated together; these constants
// come from the pre-result human review, so a post-result qrel or threshold
// edit cannot be made to pass without visibly rewriting the review anchor.
func TestFrozenRolloutsSuiteMatchesAcceptedScorerBlindReview(t *testing.T) {
	suite, _, err := MaterializeEvaluationSuite(rolloutsEvaluationSuiteFixture, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	reviewedCases := map[string]struct {
		class       string
		querySHA256 string
		judgments   []RetrievalRelevanceJudgment
		marker      string
	}{
		"case-rollouts-analysis-failure": {
			class:       "failure-boundary",
			querySHA256: "sha256:e9bf3cf9b538e2b84e428431e0943aac67cf9fc8287b849e7a0698251a5d2302",
			judgments: []RetrievalRelevanceJudgment{
				{SpanID: "evidence-span:sha256:51c3d6cd72d75ceb200ac3f7437fb0ee3cf8fb7915e5f6627e582a38adcbdf29", Grade: 3},
				{SpanID: "evidence-span:sha256:97e169b5a6adc18b5b8f47b2d36695f69e037386cadda74776a33bf7cead7c7e", Grade: 2},
				{SpanID: "evidence-span:sha256:b52aaa93d7d3d492942fcf01f3488359c40e8fe247e4660ecd054346d3f16465", Grade: 2},
			},
		},
		"case-rollouts-bluegreen-health": {
			class:       "health",
			querySHA256: "sha256:7b4725af5d39e520820c357ba747d7e37c60bfb81f585534dea5a33c921d5321",
			judgments: []RetrievalRelevanceJudgment{
				{SpanID: "evidence-span:sha256:67aea01bfdc1c85003600813cdda4dc3e186daab346d992cac9ee62ca82c2d5c", Grade: 3},
				{SpanID: "evidence-span:sha256:736045cc82a66cf50a72a10725a6e7eb08d89e28c244bf57f47bb75d2d52e6e1", Grade: 2},
			},
		},
		"case-rollouts-canary-sync": {
			class:       "sync",
			querySHA256: "sha256:a2325b7599fc39143171a2bf326b563d9883175bfbc52acb019b9b72d3e6d22f",
			judgments: []RetrievalRelevanceJudgment{
				{SpanID: "evidence-span:sha256:c3f2228875cef14eab312a39632feabc678cfdf28f73ffd0e73e50fb43256516", Grade: 3},
			},
		},
		"case-rollouts-command-injection": {
			class:       "security",
			querySHA256: "sha256:f383c3f85e7f2097ff043f9b3858c4d4800bf12837532218507e62623a4b188c",
			judgments: []RetrievalRelevanceJudgment{
				{SpanID: "evidence-span:sha256:812ed4d879db60c80962d4567227342a287f88ffdf6916f087e5da8ca841b7b1", Grade: 3},
			},
			marker: "kubectl argo rollouts abort ROLLOUT_NAME [flags]",
		},
	}

	if len(suite.Cases) != len(reviewedCases) {
		t.Fatalf("frozen Rollouts case count = %d, reviewed %d", len(suite.Cases), len(reviewedCases))
	}
	for _, testCase := range suite.Cases {
		reviewed, ok := reviewedCases[testCase.CaseID]
		if !ok {
			t.Fatalf("frozen Rollouts suite contains unreviewed case %q", testCase.CaseID)
		}
		if testCase.Class != reviewed.class {
			t.Fatalf("case %s class = %q, reviewed %q", testCase.CaseID, testCase.Class, reviewed.class)
		}
		if got := digestBytes([]byte(testCase.Query)); got != reviewed.querySHA256 {
			t.Fatalf("case %s query text no longer hashes to the reviewed query: got %s want %s", testCase.CaseID, got, reviewed.querySHA256)
		}
		if testCase.QuerySHA256 != reviewed.querySHA256 {
			t.Fatalf("case %s query_sha256 = %s, reviewed %s", testCase.CaseID, testCase.QuerySHA256, reviewed.querySHA256)
		}
		if !reflect.DeepEqual(testCase.RelevanceJudgments, reviewed.judgments) {
			t.Fatalf("case %s qrels drifted from the accepted review: got %+v want %+v", testCase.CaseID, testCase.RelevanceJudgments, reviewed.judgments)
		}
		if testCase.InjectionMarker != reviewed.marker {
			t.Fatalf("case %s injection marker = %q, reviewed %q", testCase.CaseID, testCase.InjectionMarker, reviewed.marker)
		}
	}

	reviewedThresholds := []RetrievalMetricThreshold{
		{Class: "failure-boundary", Profile: "hybrid", MinRecallPPM: 1000000, MinMRRPPM: 1000000, MinNDCGPPM: 900000},
		{Class: "failure-boundary", Profile: "lexical", MinRecallPPM: 666666, MinMRRPPM: 500000, MinNDCGPPM: 800000},
		{Class: "health", Profile: "hybrid", MinRecallPPM: 1000000, MinMRRPPM: 1000000, MinNDCGPPM: 900000},
		{Class: "health", Profile: "lexical", MinRecallPPM: 500000, MinMRRPPM: 500000, MinNDCGPPM: 490000},
		{Class: "security", Profile: "hybrid", MinRecallPPM: 1000000, MinMRRPPM: 1000000, MinNDCGPPM: 1000000},
		{Class: "security", Profile: "lexical", MinRecallPPM: 1000000, MinMRRPPM: 500000, MinNDCGPPM: 630930},
		{Class: "sync", Profile: "hybrid", MinRecallPPM: 1000000, MinMRRPPM: 1000000, MinNDCGPPM: 1000000},
		{Class: "sync", Profile: "lexical", MinRecallPPM: 1000000, MinMRRPPM: 500000, MinNDCGPPM: 630930},
	}
	for _, reviewed := range reviewedThresholds {
		found := false
		for _, live := range suite.Thresholds {
			if live == reviewed {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("reviewed threshold %+v is no longer frozen in the Rollouts suite", reviewed)
		}
	}
}

func TestFrozenWorkflowsEvaluationSuiteIdentity(t *testing.T) {
	store := t.TempDir()
	first, firstPath, err := MaterializeEvaluationSuite(workflowsEvaluationSuiteFixture, store)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializeEvaluationSuite(workflowsEvaluationSuiteFixture, store)
	if err != nil {
		t.Fatal(err)
	}

	const wantID = "retrieval-evaluation-suite:sha256:239e660825f2f5a3e480c392651e42b5ff488f48123b6644f78fdc8bc1d039a4"
	const wantDocumentHash = "sha256:4e3f82377c4740f0d71ea2c2cae57d72d153a3ba4670a4b4799d67b479012eaa"
	if first.SuiteID != wantID || firstPath != secondPath || !reflect.DeepEqual(first, second) {
		t.Fatalf("frozen Workflows suite identity or deterministic replay drifted: first=%+v second=%+v", first, second)
	}
	if got := fileDigest(firstPath); got != wantDocumentHash {
		t.Fatalf("frozen Workflows suite document hash changed: got %s want %s", got, wantDocumentHash)
	}
	if len(first.Cases) != 4 || len(first.Thresholds) != 8 {
		t.Fatalf("frozen Workflows suite lost reviewed cases or thresholds: cases=%d thresholds=%d", len(first.Cases), len(first.Thresholds))
	}
}

func TestFrozenWorkflowsEvaluationDiagnostics(t *testing.T) {
	const root = "testdata/evaluation-results/workflows-v4.0.7-20260717"
	wantGates := RetrievalQualityGates{
		HeldOutQuality: false, CitationLineage: true, ACLIsolation: true,
		DeletionAndTombstone: true, FreshnessAndTime: true,
		PromptInjectionInert: true, ResourceBounds: true,
		DeterministicReplay: true, RollbackCompatibility: true,
	}
	diagnostics := []struct {
		name            string
		paths           map[string]string
		wantHashes      map[string]string
		thresholdPasses int
		lexicalProfile  string
		tokenizerID     string
		scorerID        string
	}{
		{
			name: "baseline",
			paths: map[string]string{
				"suite":   filepath.Join(root, "baseline-suite-fd5c5114.json"),
				"metrics": filepath.Join(root, "baseline-evaluation-metrics-54e3b399.json"),
				"runtime": filepath.Join(root, "baseline-evaluation-runtime-5a2905f3.json"),
				"report":  filepath.Join(root, "baseline-quality-report-42781635.json"),
			},
			wantHashes: map[string]string{
				"suite":   "sha256:76bf7f989e65452dce7a4ecc28e313bd982aca937a2dd61a4b76c4117a2b1802",
				"metrics": "sha256:0dbcee33c92d7f72231d6bfe249ad925a2d8d63a2ba365793f934d3aecdbf9ad",
				"runtime": "sha256:543f009de555906691f9be7561b900e72e5bdaf2269fa395980e97b65bba1f8c",
				"report":  "sha256:a2bc69c349125e6c439891d512250b0e9076c1e7b23cb0869b4e7037c61cd06a",
			},
		},
		{
			name: "bm25f-v1.1",
			paths: map[string]string{
				"suite":   filepath.Join(root, "bm25f-v11-suite-ca99e6ce.json"),
				"metrics": filepath.Join(root, "bm25f-v11-evaluation-metrics-fd3d6f45.json"),
				"runtime": filepath.Join(root, "bm25f-v11-evaluation-runtime-098e4223.json"),
				"report":  filepath.Join(root, "bm25f-v11-quality-report-0e284ce5.json"),
			},
			wantHashes: map[string]string{
				"suite":   "sha256:d1862e296076d364027ab8e7946ef1f6f4ba8b7849bfd8b5bb714a5406059a99",
				"metrics": "sha256:0abb8f5c21e8bf5663fea67abb484d401a473a42ca87c0f1269455f874460202",
				"runtime": "sha256:2c329417089f6cc25483915b45f073cccf822dc5d3d7f259948ee867f1645a69",
				"report":  "sha256:26ff494f49570114d0c5fa326d4246b304669a87096457d0a4327e0480e69d32",
			},
			thresholdPasses: 2,
			lexicalProfile:  bm25fLexicalProfileV11,
			tokenizerID:     bm25fTokenizerIDV11,
			scorerID:        bm25fScorerID,
		},
	}

	decode := func(path string, target any) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeStrictCanonical(data, target); err != nil {
			t.Fatalf("decode frozen diagnostic %s: %v", path, err)
		}
	}
	for _, diagnostic := range diagnostics {
		t.Run(diagnostic.name, func(t *testing.T) {
			for name, path := range diagnostic.paths {
				if got := fileDigest(path); got != diagnostic.wantHashes[name] {
					t.Fatalf("frozen Workflows %s diagnostic drifted: got %s want %s", name, got, diagnostic.wantHashes[name])
				}
			}

			var suite RetrievalEvaluationSuite
			var metrics RetrievalEvaluationMetrics
			var runtime RetrievalEvaluationRuntime
			var report RetrievalQualityReport
			decode(diagnostic.paths["suite"], &suite)
			decode(diagnostic.paths["metrics"], &metrics)
			decode(diagnostic.paths["runtime"], &runtime)
			decode(diagnostic.paths["report"], &report)

			if err := validateEvaluationSuite(suite); err != nil {
				t.Fatalf("frozen Workflows suite invalid: %v", err)
			}
			if err := validateEvaluationMetricsAgainstSuite(metrics, suite); err != nil {
				t.Fatalf("frozen Workflows metrics invalid: %v", err)
			}
			if err := validateEvaluationRuntime(runtime); err != nil {
				t.Fatalf("frozen Workflows runtime invalid: %v", err)
			}
			if err := validateQualityReportDocument(report, false); err != nil {
				t.Fatalf("frozen Workflows quality report invalid: %v", err)
			}
			if metrics.State != "failed" || runtime.State != "failed" || report.State != "failed" ||
				metrics.Gates != wantGates || report.Gates != wantGates {
				t.Fatalf("diagnostic no longer fails only held-out quality: metrics=%+v runtime=%s report=%+v", metrics.Gates, runtime.State, report.Gates)
			}
			if runtime.MetricsSHA256 != diagnostic.wantHashes["metrics"] || runtime.SuiteSHA256 != diagnostic.wantHashes["suite"] ||
				report.EvaluationDatasetSHA256 != diagnostic.wantHashes["suite"] || report.EvaluationMetricsObjectSHA256 != diagnostic.wantHashes["metrics"] ||
				report.EvaluationRuntimeSHA256 != diagnostic.wantHashes["runtime"] {
				t.Fatal("diagnostic lineage is no longer exact")
			}
			passes := 0
			for _, aggregate := range metrics.AggregateMetrics {
				if aggregate.ThresholdPassed {
					passes++
				}
			}
			if passes != diagnostic.thresholdPasses {
				t.Fatalf("threshold passes = %d, want %d", passes, diagnostic.thresholdPasses)
			}
			if report.LexicalProfile != diagnostic.lexicalProfile || report.LexicalTokenizerID != diagnostic.tokenizerID || report.LexicalScorerID != diagnostic.scorerID {
				t.Fatalf("lexical lineage changed: %s / %s / %s", report.LexicalProfile, report.LexicalTokenizerID, report.LexicalScorerID)
			}
		})
	}
}
