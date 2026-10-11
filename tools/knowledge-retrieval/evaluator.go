package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

type evaluatorContext struct {
	config          EvaluateRetrievalConfig
	suite           RetrievalEvaluationSuite
	lexical         CandidateManifest
	loaded          loadedHybridCandidate
	policy          AdmissionPolicy
	querySignalRoot string
	indexedBySpan   map[string]EvidenceRef
	usage           RetrievalEvaluationResourceUsage
	citationPassed  bool
	deterministic   bool
	injectionPassed bool
	rerankerBinding *QuerySignalArtifact
}

func EvaluateRetrieval(config EvaluateRetrievalConfig) (EvaluateRetrievalResult, error) {
	var zero EvaluateRetrievalResult
	for name, value := range map[string]string{
		"suite": config.SuitePath, "suite-sha256": config.SuiteHash,
		"lexical-candidate": config.LexicalCandidatePath, "lexical-candidate-sha256": config.LexicalCandidateHash,
		"hybrid-candidate": config.HybridCandidatePath, "hybrid-candidate-sha256": config.HybridCandidateHash,
		"store": config.StoreRoot, "evidence-store": config.EvidenceStoreRoot, "query-signal-store": config.QuerySignalStoreRoot,
		"admission-policy": config.AdmissionPolicyPath, "admission-policy-sha256": config.AdmissionPolicyHash,
		"retrieval-executable": config.RetrievalExecutablePath, "retrieval-executable-sha256": config.RetrievalExecutableHash,
		"evaluator-executable": config.EvaluatorExecutablePath, "evaluator-executable-sha256": config.EvaluatorExecutableHash,
		"evaluator-allowed-signers": config.EvaluatorAllowedSignersPath, "evaluator-actor": config.EvaluatorActor,
		"evaluator-key-id": config.EvaluatorKeyID,
	} {
		if strings.TrimSpace(value) == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	if (config.BaseGenerationPath == "") != (config.BaseGenerationHash == "") {
		return zero, errors.New("base generation path and hash must both be present or absent")
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkPath(storeRoot) != nil {
		return zero, errors.New("retrieval store is unavailable")
	}
	evidenceRoot, err := filepath.Abs(config.EvidenceStoreRoot)
	if err != nil || validateNoSymlinkPath(evidenceRoot) != nil {
		return zero, errors.New("evidence store is unavailable")
	}
	querySignalRoot, err := filepath.Abs(config.QuerySignalStoreRoot)
	if err != nil || validateNoSymlinkPath(querySignalRoot) != nil {
		return zero, errors.New("query-signal store is unavailable")
	}

	suiteBytes, err := readStableFile(config.SuitePath, "frozen evaluation suite", maxEvaluationSuiteBytes)
	if err != nil || !validSHA256(config.SuiteHash) || digestBytes(suiteBytes) != config.SuiteHash {
		return zero, errors.New("frozen evaluation suite does not match caller pin")
	}
	var suite RetrievalEvaluationSuite
	if err := decodeStrictCanonical(suiteBytes, &suite); err != nil || validateEvaluationSuite(suite) != nil {
		return zero, errors.New("frozen evaluation suite is invalid")
	}

	lexicalBytes, err := readStableFile(config.LexicalCandidatePath, "lexical candidate", maxManifestBytes)
	if err != nil || !validSHA256(config.LexicalCandidateHash) || digestBytes(lexicalBytes) != config.LexicalCandidateHash {
		return zero, errors.New("lexical candidate does not match caller pin")
	}
	var lexical CandidateManifest
	if err := decodeStrictCanonical(lexicalBytes, &lexical); err != nil || validateCandidate(lexical) != nil {
		return zero, errors.New("lexical candidate is invalid")
	}
	loaded, code := loadHybridCandidate(HybridQueryConfig{HybridCandidatePath: config.HybridCandidatePath, HybridCandidateHash: config.HybridCandidateHash, StoreRoot: storeRoot})
	if code != "" {
		return zero, fmt.Errorf("hybrid candidate failed whole-artifact verification: %s", code)
	}
	hybridBytes, err := readStableFile(config.HybridCandidatePath, "hybrid candidate", maxManifestBytes)
	if err != nil || digestBytes(hybridBytes) != config.HybridCandidateHash {
		return zero, errors.New("hybrid candidate changed after verification")
	}
	if lexical.ManifestID != suite.LexicalCandidateID || config.LexicalCandidateHash != suite.LexicalCandidateSHA256 || loaded.hybrid.ManifestID != suite.HybridCandidateID || config.HybridCandidateHash != suite.HybridCandidateSHA256 || loaded.hybrid.LexicalCandidateID != lexical.ManifestID || loaded.hybrid.LexicalCandidateSHA256 != config.LexicalCandidateHash {
		return zero, errors.New("evaluation suite candidate lineage mismatch")
	}
	if lexical.SourceAdmissionMethod != suite.SourceAdmissionMethod || lexical.SourceAdmissionPolicyID != suite.SourceAdmissionPolicyID || lexical.SourceAdmissionPolicySHA256 != suite.SourceAdmissionPolicySHA256 || loaded.hybrid.SourceAdmissionMethod != suite.SourceAdmissionMethod || loaded.hybrid.SourceAdmissionPolicyID != suite.SourceAdmissionPolicyID || loaded.hybrid.SourceAdmissionPolicySHA256 != suite.SourceAdmissionPolicySHA256 {
		return zero, errors.New("evaluation suite source-admission lineage mismatch")
	}

	policy, _, err := loadCurrentAdmissionPolicy(config.AdmissionPolicyPath, config.AdmissionPolicyHash, suite.EvaluatedAt)
	if err != nil {
		return zero, err
	}
	if policy.PolicyID != suite.AdmissionPolicyID || config.AdmissionPolicyHash != suite.AdmissionPolicySHA256 || policy.PolicyID != lexical.AdmissionPolicyID || config.AdmissionPolicyHash != lexical.AdmissionPolicySHA256 || policy.PolicyID != loaded.hybrid.AdmissionPolicyID || config.AdmissionPolicyHash != loaded.hybrid.AdmissionPolicySHA256 {
		return zero, errors.New("evaluation suite admission-policy lineage mismatch")
	}

	if err := verifyRunningEvaluatorExecutables(config); err != nil {
		return zero, err
	}
	allowedSigners, err := readAndAuthorizeAllowedSigners(config.EvaluatorAllowedSignersPath, config.EvaluatorActor, config.EvaluatorKeyID)
	if err != nil {
		return zero, fmt.Errorf("evaluator authorization: %w", err)
	}
	allowedSignersHash := digestBytes(allowedSigners)

	var baseBefore []byte
	if suite.RollbackMode == "bootstrap" {
		if config.BaseGenerationPath != "" {
			return zero, errors.New("bootstrap evaluation must not bind a base generation")
		}
	} else {
		if config.BaseGenerationPath == "" {
			return zero, errors.New("base_generation evaluation requires an exact base generation")
		}
		_, baseBefore, err = loadAndVerifyGeneration(config.BaseGenerationPath, config.BaseGenerationHash, storeRoot)
		if err != nil {
			return zero, fmt.Errorf("base generation before evaluation: %w", err)
		}
	}

	indexedBySpan := make(map[string]EvidenceRef, len(loaded.index.Documents))
	for _, document := range loaded.index.Documents {
		indexedBySpan[document.Evidence.SpanID] = document.Evidence
	}
	ctx := &evaluatorContext{
		config: config, suite: suite, lexical: lexical, loaded: loaded, policy: policy,
		querySignalRoot: querySignalRoot, indexedBySpan: indexedBySpan,
		citationPassed: true, deterministic: true, injectionPassed: true,
	}
	caseMetrics, err := ctx.evaluateCases(evidenceRoot)
	if err != nil {
		return zero, err
	}
	aggregates, heldOutPassed := aggregateCaseMetrics(caseMetrics, suite.Thresholds)
	aclPassed, err := ctx.evaluateACL()
	if err != nil {
		return zero, err
	}
	deletionPassed, err := ctx.evaluateDeletion()
	if err != nil {
		return zero, err
	}
	freshnessPassed, err := ctx.evaluateFreshness()
	if err != nil {
		return zero, err
	}
	rollbackPassed := true
	if suite.RollbackMode == "base_generation" {
		_, baseAfter, err := loadAndVerifyGeneration(config.BaseGenerationPath, config.BaseGenerationHash, storeRoot)
		if err != nil {
			return zero, fmt.Errorf("base generation after evaluation: %w", err)
		}
		rollbackPassed = bytes.Equal(baseBefore, baseAfter)
	}
	resourcePassed := withinEvaluationResourceLimits(ctx.usage, suite.ResourceLimits)
	gates := RetrievalQualityGates{
		HeldOutQuality: heldOutPassed, CitationLineage: ctx.citationPassed, ACLIsolation: aclPassed,
		DeletionAndTombstone: deletionPassed, FreshnessAndTime: freshnessPassed,
		PromptInjectionInert: ctx.injectionPassed, ResourceBounds: resourcePassed,
		DeterministicReplay: ctx.deterministic, RollbackCompatibility: rollbackPassed,
	}
	state := "failed"
	if allQualityGatesPassed(gates) {
		state = "passed"
	}
	metrics, err := sealEvaluationMetrics(RetrievalEvaluationMetricsCore{
		SchemaVersion: retrievalSchemaVersion, MetricsKind: retrievalEvaluationMetricsKind, State: state,
		SuiteID: suite.SuiteID, SuiteSHA256: config.SuiteHash,
		LexicalCandidateID: lexical.ManifestID, LexicalCandidateSHA256: config.LexicalCandidateHash,
		HybridCandidateID: loaded.hybrid.ManifestID, HybridCandidateSHA256: config.HybridCandidateHash,
		AdmissionPolicyID: policy.PolicyID, AdmissionPolicySHA256: config.AdmissionPolicyHash,
		MetricAlgorithm: suite.MetricAlgorithm, MetricScale: suite.MetricScale, CutoffK: suite.CutoffK, TargetMode: suite.TargetMode,
		CaseMetrics: caseMetrics, AggregateMetrics: aggregates, ResourceLimits: suite.ResourceLimits, ResourceUsage: ctx.usage, Gates: gates,
	})
	if err != nil {
		return zero, err
	}
	if err := validateEvaluationMetricsAgainstSuite(metrics, suite); err != nil {
		return zero, fmt.Errorf("derived evaluation metrics: %w", err)
	}
	metricsPath, metricsHash, err := commitEvaluationDocument(storeRoot, "evaluation-metrics", metrics.MetricsPayloadSHA256, metrics)
	if err != nil {
		return zero, err
	}
	runtime, err := sealEvaluationRuntime(RetrievalEvaluationRuntimeCore{
		SchemaVersion: retrievalSchemaVersion, RuntimeKind: retrievalEvaluationRuntimeKind, State: state,
		EvaluatorID: evaluatorID, EvaluatorRevision: evaluatorRevision,
		EvaluatorExecutableSHA256: config.EvaluatorExecutableHash, RetrievalExecutableSHA256: config.RetrievalExecutableHash,
		SuiteID: suite.SuiteID, SuiteSHA256: config.SuiteHash,
		LexicalCandidateSHA256: config.LexicalCandidateHash, HybridCandidateSHA256: config.HybridCandidateHash,
		AdmissionPolicySHA256: config.AdmissionPolicyHash, MetricsSHA256: metricsHash,
		MetricAlgorithm: suite.MetricAlgorithm, TargetMode: suite.TargetMode, EvaluatedAt: suite.EvaluatedAt,
	})
	if err != nil {
		return zero, err
	}
	runtimePath, runtimeHash, err := commitEvaluationDocument(storeRoot, "evaluation-runtimes", runtime.RuntimePayloadSHA256, runtime)
	if err != nil {
		return zero, err
	}

	report, err := sealEvaluatorQualityReport(buildEvaluatorQualityReportCore(ctx, state, gates, metricsHash, runtimeHash))
	if err != nil {
		return zero, err
	}
	reportPath, reportHash, err := commitEvaluationDocument(storeRoot, "quality-reports", report.ReportPayloadSHA256, report)
	if err != nil {
		return zero, err
	}
	result := EvaluateRetrievalResult{Suite: suite, Metrics: metrics, MetricsPath: metricsPath, Runtime: runtime, RuntimePath: runtimePath, QualityReport: report, QualityReportPath: reportPath}
	if state == "passed" {
		receipt, err := sealQualityReceipt(RetrievalQualityReceiptCore{
			SchemaVersion: retrievalSchemaVersion, ReceiptKind: qualityReceiptKind, State: "passed",
			QualityReportID: report.ReportID, QualityReportSHA256: reportHash,
			EvaluatorID: evaluatorID, EvaluatorRevision: evaluatorRevision,
			EvaluatorExecutableSHA256: config.EvaluatorExecutableHash, EvaluationRuntimeSHA256: runtimeHash,
			Authorization: RetrievalTransitionAuthorization{
				Actor: config.EvaluatorActor, Method: retrievalTransitionSignatureMethod, KeyID: config.EvaluatorKeyID,
				Namespace: qualityReceiptSignatureNamespace, AllowedSignersSHA256: allowedSignersHash,
			},
			EvaluatedAt: suite.EvaluatedAt,
		})
		if err != nil {
			return zero, err
		}
		receiptPath, _, err := commitEvaluationDocument(storeRoot, "quality-receipts", receipt.ReceiptPayloadSHA256, receipt)
		if err != nil {
			return zero, err
		}
		result.QualityReceipt = &receipt
		result.QualityReceiptPath = receiptPath
	}
	return result, nil
}

func verifyRunningEvaluatorExecutables(config EvaluateRetrievalConfig) error {
	currentPath, err := os.Executable()
	if err != nil {
		return errors.New("cannot resolve running evaluator executable")
	}
	currentBytes, err := readStableFile(currentPath, "running evaluator executable", maxExecutableBytes)
	if err != nil {
		return err
	}
	currentHash := digestBytes(currentBytes)
	for label, binding := range map[string]struct{ path, hash string }{
		"retrieval": {config.RetrievalExecutablePath, config.RetrievalExecutableHash},
		"evaluator": {config.EvaluatorExecutablePath, config.EvaluatorExecutableHash},
	} {
		data, err := readStableFile(binding.path, label+" executable", maxExecutableBytes)
		if err != nil || !validSHA256(binding.hash) || digestBytes(data) != binding.hash {
			return fmt.Errorf("%s executable does not match its exact pin", label)
		}
		if binding.hash != currentHash || !bytes.Equal(data, currentBytes) {
			return fmt.Errorf("%s executable is not the running in-process evaluator binary", label)
		}
	}
	return nil
}

func (ctx *evaluatorContext) evaluateCases(evidenceRoot string) ([]RetrievalCaseMetric, error) {
	metrics := make([]RetrievalCaseMetric, 0, len(ctx.suite.Cases)*2)
	injectionCases := 0
	for _, evaluationCase := range ctx.suite.Cases {
		signalPath := filepath.Join(ctx.querySignalRoot, filepath.FromSlash(evaluationCase.QuerySignalPath))
		if !isWithin(ctx.querySignalRoot, signalPath) {
			return nil, fmt.Errorf("case %s query signal escaped its store", evaluationCase.CaseID)
		}
		signalBytes, err := verifyFileDigest(signalPath, evaluationCase.QuerySignalSHA256, evaluationCase.QuerySignalByteSize)
		if err != nil {
			return nil, fmt.Errorf("case %s query signal: %w", evaluationCase.CaseID, err)
		}
		ctx.usage.QuerySignalBytes += int64(len(signalBytes))
		var signal QuerySignalArtifact
		if err := decodeStrictCanonical(signalBytes, &signal); err != nil || signal.ArtifactID != evaluationCase.QuerySignalArtifactID {
			return nil, fmt.Errorf("case %s query signal identity invalid", evaluationCase.CaseID)
		}
		if ctx.suite.TargetMode == "fusion_only" && signal.RerankingRequested {
			return nil, fmt.Errorf("case %s fusion-only signal requests reranking", evaluationCase.CaseID)
		}
		if ctx.suite.TargetMode == "reranked" {
			if !signal.RerankingRequested {
				return nil, fmt.Errorf("case %s reranked signal disables reranking", evaluationCase.CaseID)
			}
			if ctx.rerankerBinding == nil {
				copy := signal
				ctx.rerankerBinding = &copy
			} else if !sameRerankerBinding(*ctx.rerankerBinding, signal) {
				return nil, errors.New("evaluation suite mixes reranker contracts")
			}
		}

		lexicalConfig := QueryConfig{
			CandidatePath: ctx.config.LexicalCandidatePath, CandidateHash: ctx.config.LexicalCandidateHash,
			StoreRoot: ctx.config.StoreRoot, EvidenceStoreRoot: ctx.config.EvidenceStoreRoot,
			AdmissionPolicyPath: ctx.config.AdmissionPolicyPath, AdmissionPolicyHash: ctx.config.AdmissionPolicyHash,
			Query: evaluationCase.Query, PrincipalScope: "public", AsOf: ctx.suite.EvaluatedAt,
			Limit: ctx.suite.Limit, MaxExcerptBytes: ctx.suite.MaxExcerptBytes,
		}
		firstLexical, err := Query(lexicalConfig)
		if err != nil {
			return nil, fmt.Errorf("case %s lexical query: %w", evaluationCase.CaseID, err)
		}
		secondLexical, err := Query(lexicalConfig)
		if err != nil {
			return nil, fmt.Errorf("case %s lexical replay: %w", evaluationCase.CaseID, err)
		}
		ctx.usage.Executions += 2
		ctx.addLexicalUsage(firstLexical)
		ctx.addLexicalUsage(secondLexical)
		ctx.deterministic = ctx.deterministic && canonicalEqual(firstLexical, secondLexical)
		if firstLexical.ResultState != "ok" {
			return nil, fmt.Errorf("case %s lexical query state %s/%s", evaluationCase.CaseID, firstLexical.ResultState, firstLexical.ErrorCode)
		}
		lexicalIDs := lexicalResponseIDs(firstLexical)
		metrics = append(metrics, computeCaseMetric(evaluationCase.CaseID, evaluationCase.Class, "lexical", evaluationCase.RelevanceJudgments, lexicalIDs, ctx.suite.CutoffK))
		ctx.citationPassed = ctx.citationPassed && ctx.validateLexicalCitations(firstLexical, evidenceRoot)

		hybridConfig := HybridQueryConfig{
			HybridCandidatePath: ctx.config.HybridCandidatePath, HybridCandidateHash: ctx.config.HybridCandidateHash,
			StoreRoot: ctx.config.StoreRoot, EvidenceStoreRoot: ctx.config.EvidenceStoreRoot,
			AdmissionPolicyPath: ctx.config.AdmissionPolicyPath, AdmissionPolicyHash: ctx.config.AdmissionPolicyHash,
			QueryArtifactPath: signalPath, QueryArtifactHash: evaluationCase.QuerySignalSHA256,
			Query: evaluationCase.Query, PrincipalScope: "public", AsOf: ctx.suite.EvaluatedAt,
			Limit: ctx.suite.Limit, FusionWindow: ctx.suite.FusionWindow, RerankWindow: ctx.suite.RerankWindow,
			MaxExcerptBytes: ctx.suite.MaxExcerptBytes,
		}
		firstHybrid, err := QueryHybrid(hybridConfig)
		if err != nil {
			return nil, fmt.Errorf("case %s hybrid query: %w", evaluationCase.CaseID, err)
		}
		secondHybrid, err := QueryHybrid(hybridConfig)
		if err != nil {
			return nil, fmt.Errorf("case %s hybrid replay: %w", evaluationCase.CaseID, err)
		}
		ctx.usage.Executions += 2
		ctx.addHybridUsage(firstHybrid)
		ctx.addHybridUsage(secondHybrid)
		ctx.deterministic = ctx.deterministic && canonicalEqual(firstHybrid, secondHybrid)
		if firstHybrid.ResultState != "ok" {
			return nil, fmt.Errorf("case %s hybrid query state %s/%s", evaluationCase.CaseID, firstHybrid.ResultState, firstHybrid.ErrorCode)
		}
		hybridIDs := hybridResponseIDs(firstHybrid)
		metrics = append(metrics, computeCaseMetric(evaluationCase.CaseID, evaluationCase.Class, "hybrid", evaluationCase.RelevanceJudgments, hybridIDs, ctx.suite.CutoffK))
		ctx.citationPassed = ctx.citationPassed && ctx.validateHybridCitations(firstHybrid, evidenceRoot)
		if evaluationCase.InjectionMarker != "" {
			injectionCases++
			if !ctx.validateInjectionMarker(evaluationCase.InjectionMarker, firstLexical, firstHybrid, evidenceRoot) {
				ctx.injectionPassed = false
			}
		}
	}
	if injectionCases == 0 {
		ctx.injectionPassed = false
	}
	sort.Slice(metrics, func(left, right int) bool {
		leftKey := metrics[left].CaseID + "\x00" + metrics[left].Profile
		rightKey := metrics[right].CaseID + "\x00" + metrics[right].Profile
		return leftKey < rightKey
	})
	return metrics, nil
}

func (ctx *evaluatorContext) evaluateACL() (bool, error) {
	evaluationCase := ctx.suite.Cases[0]
	signalPath := filepath.Join(ctx.querySignalRoot, filepath.FromSlash(evaluationCase.QuerySignalPath))
	lexicalConfig := ctx.lexicalQueryConfig(evaluationCase.Query, ctx.suite.EvaluatedAt, "private")
	lexical, err := Query(lexicalConfig)
	if err != nil {
		return false, err
	}
	hybridConfig := ctx.hybridQueryConfig(evaluationCase, signalPath, ctx.suite.EvaluatedAt, "private", ctx.config.AdmissionPolicyPath, ctx.config.AdmissionPolicyHash)
	hybrid, err := QueryHybrid(hybridConfig)
	if err != nil {
		return false, err
	}
	ctx.usage.Executions += 2
	return lexical.ResultState == "forbidden" && lexical.ErrorCode == "principal_scope_forbidden" && len(lexical.Results) == 0 && hybrid.ResultState == "forbidden" && hybrid.ErrorCode == "principal_scope_forbidden" && len(hybrid.Results) == 0, nil
}

func (ctx *evaluatorContext) evaluateDeletion() (bool, error) {
	core := ctx.policy.AdmissionPolicyCore
	core.DeletionState = "deleted"
	core.Tombstone = true
	deleted, err := deriveAdmissionPolicy(core)
	if err != nil {
		return false, err
	}
	data, err := marshalDocument(deleted)
	if err != nil {
		return false, err
	}
	directory, err := os.MkdirTemp("", "retrieval-evaluator-deletion-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(directory)
	policyPath := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(policyPath, data, 0o600); err != nil {
		return false, err
	}
	evaluationCase := ctx.suite.Cases[0]
	signalPath := filepath.Join(ctx.querySignalRoot, filepath.FromSlash(evaluationCase.QuerySignalPath))
	lexical, err := Query(ctx.lexicalQueryConfigWithPolicy(evaluationCase.Query, ctx.suite.EvaluatedAt, "public", policyPath, digestBytes(data)))
	if err != nil {
		return false, err
	}
	hybrid, err := QueryHybrid(ctx.hybridQueryConfig(evaluationCase, signalPath, ctx.suite.EvaluatedAt, "public", policyPath, digestBytes(data)))
	if err != nil {
		return false, err
	}
	ctx.usage.Executions += 2
	return lexical.ResultState == "forbidden" && lexical.ErrorCode == "source_deleted_or_tombstoned" && len(lexical.Results) == 0 && hybrid.ResultState == "forbidden" && hybrid.ErrorCode == "source_deleted_or_tombstoned" && len(hybrid.Results) == 0, nil
}

func (ctx *evaluatorContext) evaluateFreshness() (bool, error) {
	freshUntil, _ := parseCanonicalUTC(ctx.policy.FreshUntil)
	afterFresh := freshUntil.Add(time.Second).UTC().Format("2006-01-02T15:04:05Z")
	evaluatedAt, _ := parseCanonicalUTC(ctx.policy.EvaluatedAt)
	beforeEvaluation := evaluatedAt.Add(-time.Second).UTC().Format("2006-01-02T15:04:05Z")
	evaluationCase := ctx.suite.Cases[0]
	signalPath := filepath.Join(ctx.querySignalRoot, filepath.FromSlash(evaluationCase.QuerySignalPath))
	lexicalStale, err := Query(ctx.lexicalQueryConfig(evaluationCase.Query, afterFresh, "public"))
	if err != nil {
		return false, err
	}
	hybridStale, err := QueryHybrid(ctx.hybridQueryConfig(evaluationCase, signalPath, afterFresh, "public", ctx.config.AdmissionPolicyPath, ctx.config.AdmissionPolicyHash))
	if err != nil {
		return false, err
	}
	lexicalEarly, err := Query(ctx.lexicalQueryConfig(evaluationCase.Query, beforeEvaluation, "public"))
	if err != nil {
		return false, err
	}
	hybridEarly, err := QueryHybrid(ctx.hybridQueryConfig(evaluationCase, signalPath, beforeEvaluation, "public", ctx.config.AdmissionPolicyPath, ctx.config.AdmissionPolicyHash))
	if err != nil {
		return false, err
	}
	ctx.usage.Executions += 4
	ctx.addLexicalUsage(lexicalStale)
	ctx.addHybridUsage(hybridStale)
	return lexicalStale.ResultState == "stale" && lexicalStale.FreshnessState == "stale" && hybridStale.ResultState == "stale" && hybridStale.FreshnessState == "stale" && lexicalEarly.ResultState == "forbidden" && lexicalEarly.ErrorCode == "query_before_policy_evaluation" && hybridEarly.ResultState == "forbidden" && hybridEarly.ErrorCode == "query_before_policy_evaluation", nil
}

func (ctx *evaluatorContext) lexicalQueryConfig(query, asOf, scope string) QueryConfig {
	return ctx.lexicalQueryConfigWithPolicy(query, asOf, scope, ctx.config.AdmissionPolicyPath, ctx.config.AdmissionPolicyHash)
}

func (ctx *evaluatorContext) lexicalQueryConfigWithPolicy(query, asOf, scope, policyPath, policyHash string) QueryConfig {
	return QueryConfig{CandidatePath: ctx.config.LexicalCandidatePath, CandidateHash: ctx.config.LexicalCandidateHash, StoreRoot: ctx.config.StoreRoot, EvidenceStoreRoot: ctx.config.EvidenceStoreRoot, AdmissionPolicyPath: policyPath, AdmissionPolicyHash: policyHash, Query: query, PrincipalScope: scope, AsOf: asOf, Limit: ctx.suite.Limit, MaxExcerptBytes: ctx.suite.MaxExcerptBytes}
}

func (ctx *evaluatorContext) hybridQueryConfig(evaluationCase RetrievalEvaluationCase, signalPath, asOf, scope, policyPath, policyHash string) HybridQueryConfig {
	return HybridQueryConfig{HybridCandidatePath: ctx.config.HybridCandidatePath, HybridCandidateHash: ctx.config.HybridCandidateHash, StoreRoot: ctx.config.StoreRoot, EvidenceStoreRoot: ctx.config.EvidenceStoreRoot, AdmissionPolicyPath: policyPath, AdmissionPolicyHash: policyHash, QueryArtifactPath: signalPath, QueryArtifactHash: evaluationCase.QuerySignalSHA256, Query: evaluationCase.Query, PrincipalScope: scope, AsOf: asOf, Limit: ctx.suite.Limit, FusionWindow: ctx.suite.FusionWindow, RerankWindow: ctx.suite.RerankWindow, MaxExcerptBytes: ctx.suite.MaxExcerptBytes}
}

func (ctx *evaluatorContext) addLexicalUsage(response QueryResponse) {
	ctx.usage.ReturnedResults += len(response.Results)
	for _, hit := range response.Results {
		ctx.usage.ReturnedExcerptBytes += int64(len([]byte(hit.Excerpt)))
	}
}

func (ctx *evaluatorContext) addHybridUsage(response HybridQueryResponse) {
	ctx.usage.DenseScannedDocuments += response.DenseScannedDocuments
	ctx.usage.ReturnedResults += len(response.Results)
	for _, hit := range response.Results {
		ctx.usage.ReturnedExcerptBytes += int64(len([]byte(hit.Excerpt)))
	}
}

func (ctx *evaluatorContext) validateLexicalCitations(response QueryResponse, evidenceRoot string) bool {
	seen := make(map[string]struct{}, len(response.Results))
	for _, hit := range response.Results {
		if _, exists := seen[hit.Evidence.SpanID]; exists || !ctx.validateCitation(hit.Evidence, hit.Excerpt, evidenceRoot) {
			return false
		}
		seen[hit.Evidence.SpanID] = struct{}{}
	}
	return true
}

func (ctx *evaluatorContext) validateHybridCitations(response HybridQueryResponse, evidenceRoot string) bool {
	seen := make(map[string]struct{}, len(response.Results))
	for _, hit := range response.Results {
		if _, exists := seen[hit.Evidence.SpanID]; exists || !ctx.validateCitation(hit.Evidence, hit.Excerpt, evidenceRoot) {
			return false
		}
		seen[hit.Evidence.SpanID] = struct{}{}
	}
	return true
}

func (ctx *evaluatorContext) validateCitation(ref EvidenceRef, excerpt, evidenceRoot string) bool {
	expected, exists := ctx.indexedBySpan[ref.SpanID]
	if !exists || !reflect.DeepEqual(expected, ref) || ref.InstructionPolicy != "forbidden" || ref.ExecutionPolicy != "never" || ref.ToolPolicy != "never" || ref.InterpretationPolicy != "evidence_only" {
		return false
	}
	payloadPath := filepath.Join(evidenceRoot, filepath.FromSlash(ref.PayloadObjectPath))
	if !isWithin(evidenceRoot, payloadPath) {
		return false
	}
	payload, err := verifyFileDigest(payloadPath, ref.PayloadSHA256, ref.PayloadByteSize)
	if err != nil {
		return false
	}
	wantExcerpt, _ := boundedUTF8(payload, ctx.suite.MaxExcerptBytes)
	return excerpt == wantExcerpt
}

func (ctx *evaluatorContext) validateInjectionMarker(marker string, lexical QueryResponse, hybrid HybridQueryResponse, evidenceRoot string) bool {
	found := false
	check := func(ref EvidenceRef) bool {
		payloadPath := filepath.Join(evidenceRoot, filepath.FromSlash(ref.PayloadObjectPath))
		payload, err := verifyFileDigest(payloadPath, ref.PayloadSHA256, ref.PayloadByteSize)
		if err != nil {
			return false
		}
		if bytes.Contains(payload, []byte(marker)) {
			found = true
			return ref.InstructionPolicy == "forbidden" && ref.ExecutionPolicy == "never" && ref.ToolPolicy == "never" && ref.InterpretationPolicy == "evidence_only"
		}
		return true
	}
	for _, hit := range lexical.Results {
		if !check(hit.Evidence) {
			return false
		}
	}
	for _, hit := range hybrid.Results {
		if !check(hit.Evidence) {
			return false
		}
	}
	return found
}

func buildEvaluatorQualityReportCore(ctx *evaluatorContext, state string, gates RetrievalQualityGates, metricsHash, runtimeHash string) RetrievalQualityReportCore {
	core := RetrievalQualityReportCore{
		SchemaVersion: retrievalSchemaVersion, ReportKind: qualityReportKind, State: state,
		HybridCandidateID: ctx.loaded.hybrid.ManifestID, HybridCandidateSHA256: ctx.config.HybridCandidateHash,
		AdmissionPolicyID: ctx.policy.PolicyID, AdmissionPolicySHA256: ctx.config.AdmissionPolicyHash,
		SourceAdmissionMethod:       ctx.loaded.hybrid.SourceAdmissionMethod,
		SourceAdmissionPolicyID:     ctx.loaded.hybrid.SourceAdmissionPolicyID,
		SourceAdmissionPolicySHA256: ctx.loaded.hybrid.SourceAdmissionPolicySHA256,
		RetrievalExecutableSHA256:   ctx.config.RetrievalExecutableHash, LexicalIndexID: ctx.loaded.hybrid.LexicalIndexID,
		LexicalProfile:     ctx.loaded.hybrid.LexicalProfile,
		LexicalTokenizerID: ctx.loaded.hybrid.LexicalTokenizerID,
		LexicalScorerID:    ctx.loaded.hybrid.LexicalScorerID,
		DenseArtifactID:    ctx.loaded.hybrid.DenseArtifactID, DenseArtifactSHA256: ctx.loaded.hybrid.DenseArtifactSHA256,
		DenseModelID: ctx.loaded.hybrid.DenseModelID, DenseModelRevision: ctx.loaded.hybrid.DenseModelRevision,
		DenseModelArtifactSHA256: ctx.loaded.hybrid.DenseModelArtifactSHA256,
		DenseTokenizerID:         ctx.loaded.hybrid.DenseTokenizerID, DenseTokenizerSHA256: ctx.loaded.hybrid.DenseTokenizerSHA256,
		EmbeddingProfile: ctx.loaded.hybrid.EmbeddingProfile, FusionProfile: ctx.loaded.hybrid.FusionProfile,
		RerankingContract: ctx.loaded.hybrid.RerankingContract, RerankingEvaluated: ctx.suite.TargetMode == "reranked",
		EvaluationDatasetID: ctx.suite.SuiteID, EvaluationDatasetSHA256: ctx.config.SuiteHash,
		EvaluationMetricsObjectSHA256: metricsHash, EvaluationRuntimeSHA256: runtimeHash,
		EvaluatorID: evaluatorID, EvaluatorRevision: evaluatorRevision,
		EvaluatorExecutableSHA256: ctx.config.EvaluatorExecutableHash, EvaluatedAt: ctx.suite.EvaluatedAt, Gates: gates,
	}
	if ctx.suite.TargetMode == "reranked" && ctx.rerankerBinding != nil {
		signal := ctx.rerankerBinding
		core.RerankerModelID = stringPointer(signal.RerankerModelID)
		core.RerankerModelRevision = stringPointer(signal.RerankerModelRevision)
		core.RerankerModelArtifactSHA256 = stringPointer(signal.RerankerModelArtifactSHA256)
		core.RerankerTokenizerID = stringPointer(signal.RerankerTokenizerID)
		core.RerankerTokenizerSHA256 = stringPointer(signal.RerankerTokenizerSHA256)
		core.RerankerProfile = stringPointer(signal.RerankerProfile)
		core.RerankerQueryInstruction = stringPointer(signal.RerankerQueryInstruction)
		core.RerankerDocumentInstruction = stringPointer(signal.RerankerDocumentInstruction)
		core.RerankerScoreScale = int64Pointer(signal.RerankerScoreScale)
	}
	return core
}

func sealEvaluatorQualityReport(core RetrievalQualityReportCore) (RetrievalQualityReport, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalQualityReport{}, err
	}
	digest := digestBytes(data)
	report := RetrievalQualityReport{ReportID: "retrieval-quality-report:" + digest, ReportPayloadSHA256: digest, RetrievalQualityReportCore: core}
	if err := validateQualityReportDocument(report, false); err != nil {
		return RetrievalQualityReport{}, err
	}
	return report, nil
}

func commitEvaluationDocument(storeRoot, directory, payloadDigest string, value any) (string, string, error) {
	data, err := marshalDocument(value)
	if err != nil {
		return "", "", err
	}
	relative, err := contentObjectPath(directory, payloadDigest)
	if err != nil {
		return "", "", err
	}
	if err := writeImmutableObject(storeRoot, relative, data); err != nil {
		return "", "", err
	}
	return filepath.Join(storeRoot, filepath.FromSlash(relative)), digestBytes(data), nil
}

func canonicalEqual(left, right any) bool {
	leftBytes, leftErr := marshalDocument(left)
	rightBytes, rightErr := marshalDocument(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func lexicalResponseIDs(response QueryResponse) []string {
	result := make([]string, 0, len(response.Results))
	for _, hit := range response.Results {
		result = append(result, hit.Evidence.SpanID)
	}
	return result
}

func hybridResponseIDs(response HybridQueryResponse) []string {
	result := make([]string, 0, len(response.Results))
	for _, hit := range response.Results {
		result = append(result, hit.Evidence.SpanID)
	}
	return result
}

func sameRerankerBinding(left, right QuerySignalArtifact) bool {
	return left.RerankerModelID == right.RerankerModelID && left.RerankerModelRevision == right.RerankerModelRevision && left.RerankerModelArtifactSHA256 == right.RerankerModelArtifactSHA256 && left.RerankerTokenizerID == right.RerankerTokenizerID && left.RerankerTokenizerSHA256 == right.RerankerTokenizerSHA256 && left.RerankerProfile == right.RerankerProfile && left.RerankerQueryInstruction == right.RerankerQueryInstruction && left.RerankerDocumentInstruction == right.RerankerDocumentInstruction && left.RerankerScoreScale == right.RerankerScoreScale
}

func withinEvaluationResourceLimits(usage RetrievalEvaluationResourceUsage, limits RetrievalEvaluationResourceLimits) bool {
	return usage.Executions <= limits.MaxExecutions && usage.DenseScannedDocuments <= limits.MaxDenseScannedDocuments && usage.ReturnedResults <= limits.MaxReturnedResults && usage.ReturnedExcerptBytes <= limits.MaxReturnedExcerptBytes && usage.QuerySignalBytes <= limits.MaxQuerySignalBytes
}

func stringPointer(value string) *string {
	result := value
	return &result
}

func int64Pointer(value int64) *int64 {
	result := value
	return &result
}

func sortedEvidenceIDs(index LexicalIndex) []string {
	result := make([]string, 0, len(index.Documents))
	for _, document := range index.Documents {
		result = append(result, document.Evidence.SpanID)
	}
	sort.Strings(result)
	return result
}
