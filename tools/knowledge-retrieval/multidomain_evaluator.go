package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The multidomain evaluator is the signed-execution successor to the
// preflight-only PreparePairedFusionRun. It executes both fusion arms over the
// committed QueryHybrid multidomain path, computes macro recall/MRR/nDCG per
// (class, arm), gates against the frozen thresholds and challenger gates, and
// emits an SSHSIG-signed receipt. The receipt hard-wires promotable and
// execution_authorized to false: a passing evaluation is evidence, never an
// authorization to serve or promote.
const (
	multidomainReceiptKind               = "retrieval_multidomain_evaluation_receipt"
	multidomainReceiptSignatureNamespace = "archeion-retrieval-multidomain-evaluation-v1"
	multidomainEvaluatorID               = "archeion-retrieval-multidomain-evaluator"
	multidomainEvaluatorRevision         = "retrieval-multidomain-evaluator@1.0.0"
	maxMultidomainReceiptBytes           = int64(1024 * 1024)
)

type EvaluateMultidomainConfig struct {
	SuitePath, SuiteHash                             string
	StoreRoot, EvidenceStoreRoot                     string
	QuerySignalStoreRoot, LineageSetPath             string
	AdmissionPolicyPath, AdmissionPolicyHash         string
	RetrievalExecutablePath, RetrievalExecutableHash string
	EvaluatorExecutablePath, EvaluatorExecutableHash string
	EvaluatorAllowedSignersPath                      string
	EvaluatorActor, EvaluatorKeyID                   string
	EvaluatorPrivateKeyPath                          string
	AsOf                                             string
}

type MultidomainChallengerComparison struct {
	Class               string `json:"class"`
	BaselineRecallPPM   int64  `json:"baseline_recall_ppm"`
	ChallengerRecallPPM int64  `json:"challenger_recall_ppm"`
	BaselineMRRPPM      int64  `json:"baseline_mrr_ppm"`
	ChallengerMRRPPM    int64  `json:"challenger_mrr_ppm"`
	BaselineNDCGPPM     int64  `json:"baseline_ndcg_ppm"`
	ChallengerNDCGPPM   int64  `json:"challenger_ndcg_ppm"`
	GainPPM             int64  `json:"minimum_metric_gain_ppm"`
	RegressionPPM       int64  `json:"maximum_metric_regression_ppm"`
	Passed              bool   `json:"passed"`
}

type MultidomainEvaluationGates struct {
	HeldOutQuality      bool `json:"held_out_quality"`
	CitationLineage     bool `json:"citation_lineage"`
	DeterministicReplay bool `json:"deterministic_replay"`
	ChallengerGain      bool `json:"challenger_gain"`
}

type MultidomainEvaluationReceiptCore struct {
	SchemaVersion                 string                            `json:"schema_version"`
	ReceiptKind                   string                            `json:"receipt_kind"`
	State                         string                            `json:"state"`
	Promotable                    bool                              `json:"promotable"`
	ExecutionAuthorized           bool                              `json:"execution_authorized"`
	SuiteID                       string                            `json:"suite_id"`
	SuiteSHA256                   string                            `json:"suite_document_sha256"`
	LexicalCandidateID            string                            `json:"lexical_candidate_id"`
	LexicalCandidateSHA256        string                            `json:"lexical_candidate_document_sha256"`
	DenseArtifactID               string                            `json:"dense_artifact_id"`
	DenseArtifactSHA256           string                            `json:"dense_artifact_document_sha256"`
	BaselineCandidateID           string                            `json:"baseline_hybrid_candidate_id"`
	BaselineCandidateSHA256       string                            `json:"baseline_hybrid_candidate_document_sha256"`
	ChallengerCandidateID         string                            `json:"challenger_hybrid_candidate_id"`
	ChallengerCandidateSHA256     string                            `json:"challenger_hybrid_candidate_document_sha256"`
	ChallengerFusionProfileID     string                            `json:"challenger_fusion_profile_id"`
	ChallengerFusionProfileSHA256 string                            `json:"challenger_fusion_profile_document_sha256"`
	ChallengerScorerSHA256        string                            `json:"challenger_scorer_artifact_sha256"`
	MetricAlgorithm               string                            `json:"metric_algorithm"`
	MetricScale                   int64                             `json:"metric_scale"`
	CutoffK                       int                               `json:"cutoff_k"`
	MinChallengerGainPPM          int64                             `json:"minimum_challenger_gain_ppm"`
	MaximumChallengerRegression   int64                             `json:"maximum_challenger_regression_ppm"`
	AggregateMetrics              []RetrievalAggregateMetric        `json:"aggregate_metrics"`
	ChallengerComparisons         []MultidomainChallengerComparison `json:"challenger_comparisons"`
	Gates                         MultidomainEvaluationGates        `json:"gates"`
	EvaluatorID                   string                            `json:"evaluator_id"`
	EvaluatorRevision             string                            `json:"evaluator_revision"`
	EvaluatorExecutableSHA256     string                            `json:"evaluator_executable_sha256"`
	RetrievalExecutableSHA256     string                            `json:"retrieval_executable_sha256"`
	EvaluatedAt                   string                            `json:"evaluated_at"`
	Authorization                 RetrievalTransitionAuthorization  `json:"authorization"`
}

type MultidomainEvaluationReceipt struct {
	ReceiptID            string `json:"receipt_id"`
	ReceiptPayloadSHA256 string `json:"receipt_payload_sha256"`
	MultidomainEvaluationReceiptCore
}

type EvaluateMultidomainResult struct {
	Suite         MultidomainEvaluationSuite
	State         string
	Gates         MultidomainEvaluationGates
	MetricsPath   string
	Receipt       *MultidomainEvaluationReceipt
	ReceiptBytes  []byte
	ReceiptPath   string
	SignaturePath string
}

func EvaluateMultidomainRetrieval(config EvaluateMultidomainConfig) (EvaluateMultidomainResult, error) {
	var zero EvaluateMultidomainResult
	for name, value := range map[string]string{
		"suite": config.SuitePath, "suite-sha256": config.SuiteHash,
		"store": config.StoreRoot, "evidence-store": config.EvidenceStoreRoot,
		"query-signal-store": config.QuerySignalStoreRoot, "lineage-set": config.LineageSetPath,
		"admission-policy": config.AdmissionPolicyPath, "admission-policy-sha256": config.AdmissionPolicyHash,
		"retrieval-executable": config.RetrievalExecutablePath, "retrieval-executable-sha256": config.RetrievalExecutableHash,
		"evaluator-executable": config.EvaluatorExecutablePath, "evaluator-executable-sha256": config.EvaluatorExecutableHash,
		"evaluator-allowed-signers": config.EvaluatorAllowedSignersPath, "evaluator-actor": config.EvaluatorActor,
		"evaluator-key-id": config.EvaluatorKeyID, "as-of": config.AsOf,
	} {
		if strings.TrimSpace(value) == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkPath(storeRoot) != nil {
		return zero, errors.New("retrieval store is unavailable")
	}
	querySignalRoot, err := filepath.Abs(config.QuerySignalStoreRoot)
	if err != nil || validateNoSymlinkPath(querySignalRoot) != nil {
		return zero, errors.New("query-signal store is unavailable")
	}
	evidenceRoot, err := filepath.Abs(config.EvidenceStoreRoot)
	if err != nil || validateNoSymlinkPath(evidenceRoot) != nil {
		return zero, errors.New("evidence store is unavailable")
	}

	suiteBytes, err := readStableFile(config.SuitePath, "multidomain evaluation suite", maxMultidomainSuiteBytes)
	if err != nil || !validSHA256(config.SuiteHash) || digestBytes(suiteBytes) != config.SuiteHash {
		return zero, errors.New("multidomain evaluation suite does not match caller pin")
	}
	var suite MultidomainEvaluationSuite
	if err := decodeStrictCanonical(suiteBytes, &suite); err != nil || validateMultidomainEvaluationSuite(suite) != nil {
		return zero, errors.New("multidomain evaluation suite is invalid")
	}
	if config.AsOf != suite.FrozenAt {
		return zero, errors.New("evaluation as-of must equal the suite frozen time")
	}

	if err := verifyRunningMultidomainExecutables(config); err != nil {
		return zero, err
	}
	allowedSigners, err := readAndAuthorizeAllowedSigners(config.EvaluatorAllowedSignersPath, config.EvaluatorActor, config.EvaluatorKeyID)
	if err != nil {
		return zero, fmt.Errorf("evaluator authorization: %w", err)
	}
	allowedSignersHash := digestBytes(allowedSigners)

	roots := multidomainRoots{store: storeRoot, evidence: evidenceRoot, signals: querySignalRoot}
	caseMetrics := make([]RetrievalCaseMetric, 0, len(suite.Cases)*2)
	citationPassed, deterministic := true, true
	for _, evaluationCase := range suite.Cases {
		for _, arm := range suite.Arms {
			response, cok, dok, err := runMultidomainArm(config, suite, roots, evaluationCase, arm)
			if err != nil {
				return zero, err
			}
			citationPassed = citationPassed && cok
			deterministic = deterministic && dok
			profile := "baseline"
			if arm.Role == pairedFusionChallengerRole {
				profile = "challenger"
			}
			judgments := []RetrievalRelevanceJudgment{{SpanID: evaluationCase.AdmittedSpanID, Grade: evaluationCase.Grade}}
			metric := computeCaseMetric(evaluationCase.CaseID, evaluationCase.Class, profile, judgments, response, suite.Target.CutoffK)
			caseMetrics = append(caseMetrics, metric)
		}
	}
	sort.Slice(caseMetrics, func(left, right int) bool {
		return caseMetrics[left].CaseID+"\x00"+caseMetrics[left].Profile < caseMetrics[right].CaseID+"\x00"+caseMetrics[right].Profile
	})

	aggregates, heldOutPassed := aggregateCaseMetrics(caseMetrics, suite.Thresholds)
	comparisons, challengerPassed := multidomainChallengerComparisons(aggregates, suite.MinChallengerGainPPM, suite.MaximumChallengerRegression)
	gates := MultidomainEvaluationGates{
		HeldOutQuality: heldOutPassed, CitationLineage: citationPassed,
		DeterministicReplay: deterministic, ChallengerGain: challengerPassed,
	}
	// The absolute quality bars (held-out quality, citation lineage, deterministic
	// replay) are the floor for any sealable outcome. Above that floor the paired
	// bake-off has two honest results: the challenger genuinely wins -> "passed"
	// (the promotion path, unchanged); or the challenger is fairly evaluated and
	// does not beat the incumbent -> "baseline_adopted", the incumbent RRF profile
	// is retained. Both seal a receipt. A run that fails a floor bar -> "failed",
	// unsignable. This is not a weakened gate: "passed" still requires
	// challenger_gain, and "baseline_adopted" records truthfully that the
	// challenger did not win.
	state := "failed"
	if gates.HeldOutQuality && gates.CitationLineage && gates.DeterministicReplay {
		if gates.ChallengerGain {
			state = "passed"
		} else {
			state = "baseline_adopted"
		}
	}

	challenger := suite.Arms[1]
	receiptCore := MultidomainEvaluationReceiptCore{
		SchemaVersion: retrievalSchemaVersion, ReceiptKind: multidomainReceiptKind, State: state,
		Promotable: false, ExecutionAuthorized: false,
		SuiteID: suite.SuiteID, SuiteSHA256: config.SuiteHash,
		LexicalCandidateID: suite.LexicalCandidate.ArtifactID, LexicalCandidateSHA256: suite.LexicalCandidate.DocumentSHA256,
		DenseArtifactID: suite.DenseArtifact.ArtifactID, DenseArtifactSHA256: suite.DenseArtifact.DocumentSHA256,
		BaselineCandidateID: suite.Arms[0].HybridCandidate.ArtifactID, BaselineCandidateSHA256: suite.Arms[0].HybridCandidate.DocumentSHA256,
		ChallengerCandidateID: challenger.HybridCandidate.ArtifactID, ChallengerCandidateSHA256: challenger.HybridCandidate.DocumentSHA256,
		ChallengerFusionProfileID: challenger.FusionProfileArtifact.ArtifactID, ChallengerFusionProfileSHA256: challenger.FusionProfileArtifact.DocumentSHA256,
		ChallengerScorerSHA256: challenger.Scorer.ExecutableSHA256,
		MetricAlgorithm:        suite.Target.MetricAlgorithm, MetricScale: suite.Target.MetricScale, CutoffK: suite.Target.CutoffK,
		MinChallengerGainPPM: suite.MinChallengerGainPPM, MaximumChallengerRegression: suite.MaximumChallengerRegression,
		AggregateMetrics: aggregates, ChallengerComparisons: comparisons, Gates: gates,
		EvaluatorID: multidomainEvaluatorID, EvaluatorRevision: multidomainEvaluatorRevision,
		EvaluatorExecutableSHA256: config.EvaluatorExecutableHash, RetrievalExecutableSHA256: config.RetrievalExecutableHash,
		EvaluatedAt: suite.FrozenAt,
		Authorization: RetrievalTransitionAuthorization{
			Actor: config.EvaluatorActor, Method: retrievalTransitionSignatureMethod, KeyID: config.EvaluatorKeyID,
			Namespace: multidomainReceiptSignatureNamespace, AllowedSignersSHA256: allowedSignersHash,
		},
	}
	metricsDocument := multidomainEvaluationMetrics{
		SchemaVersion: retrievalSchemaVersion, MetricsKind: "retrieval_multidomain_evaluation_metrics",
		State: state, SuiteID: suite.SuiteID, SuiteSHA256: config.SuiteHash,
		CaseMetrics: caseMetrics, AggregateMetrics: aggregates,
	}
	metricsPayload, err := json.Marshal(metricsDocument)
	if err != nil {
		return zero, err
	}
	metricsPath, _, err := commitEvaluationDocument(storeRoot, "multidomain-evaluation-metrics", digestBytes(metricsPayload), metricsDocument)
	if err != nil {
		return zero, err
	}

	result := EvaluateMultidomainResult{Suite: suite, State: state, Gates: gates, MetricsPath: metricsPath}
	if state != "passed" && state != "baseline_adopted" {
		return result, nil
	}
	receipt, err := sealMultidomainReceipt(receiptCore)
	if err != nil {
		return zero, err
	}
	receiptBytes, err := marshalDocument(receipt)
	if err != nil {
		return zero, err
	}
	receiptPath, _, err := commitEvaluationDocument(storeRoot, "multidomain-evaluation-receipts", receipt.ReceiptPayloadSHA256, receipt)
	if err != nil {
		return zero, err
	}
	result.Receipt = &receipt
	result.ReceiptBytes = receiptBytes
	result.ReceiptPath = receiptPath

	// A signed receipt is only produced when the operator supplies the
	// out-of-tree evaluator private key. The signature is over the exact
	// committed receipt bytes and is immediately re-verified against the same
	// allowed_signers the receipt authorization pins.
	if strings.TrimSpace(config.EvaluatorPrivateKeyPath) != "" {
		signature, err := signDetachedSSHSIG(receiptBytes, config.EvaluatorPrivateKeyPath, multidomainReceiptSignatureNamespace)
		if err != nil {
			return zero, err
		}
		if err := verifyDetachedSSHSIG(receiptBytes, signature, allowedSigners, config.EvaluatorActor, config.EvaluatorKeyID, multidomainReceiptSignatureNamespace); err != nil {
			return zero, fmt.Errorf("multidomain receipt signature verification failed: %w", err)
		}
		relative, err := contentObjectPath("multidomain-evaluation-signatures", digestBytes(signature))
		if err != nil {
			return zero, err
		}
		if err := writeImmutableObject(storeRoot, relative, signature); err != nil {
			return zero, err
		}
		result.SignaturePath = filepath.Join(storeRoot, filepath.FromSlash(relative))
	}
	return result, nil
}

type multidomainRoots struct{ store, evidence, signals string }

func runMultidomainArm(config EvaluateMultidomainConfig, suite MultidomainEvaluationSuite, roots multidomainRoots, evaluationCase MultidomainEvaluationCase, arm PairedFusionArmBinding) ([]string, bool, bool, error) {
	signalBinding := evaluationCase.Signals.Baseline
	if arm.Role == pairedFusionChallengerRole {
		signalBinding = evaluationCase.Signals.Challenger
	}
	signalPath := filepath.Join(roots.signals, filepath.FromSlash(signalBinding.ObjectPath))
	if !isWithin(roots.signals, signalPath) {
		return nil, false, false, fmt.Errorf("multidomain case %s signal escaped its store", evaluationCase.CaseID)
	}
	if _, err := verifyFileDigest(signalPath, signalBinding.DocumentSHA256, signalBinding.ByteSize); err != nil {
		return nil, false, false, fmt.Errorf("multidomain case %s signal: %w", evaluationCase.CaseID, err)
	}
	hybridPath := filepath.Join(roots.store, filepath.FromSlash(arm.HybridCandidate.ObjectPath))
	if !isWithin(roots.store, hybridPath) {
		return nil, false, false, fmt.Errorf("multidomain %s candidate escaped its store", arm.Role)
	}
	hybridConfig := HybridQueryConfig{
		HybridCandidatePath: hybridPath, HybridCandidateHash: arm.HybridCandidate.DocumentSHA256,
		StoreRoot: roots.store, EvidenceStoreRoot: roots.evidence,
		AdmissionPolicyPath: config.AdmissionPolicyPath, AdmissionPolicyHash: config.AdmissionPolicyHash,
		LineageSetPath:    config.LineageSetPath,
		QueryArtifactPath: signalPath, QueryArtifactHash: signalBinding.DocumentSHA256,
		Query: evaluationCase.Query, PrincipalScope: "public", AsOf: config.AsOf,
		Limit: suite.Target.Limit, FusionWindow: suite.Target.FusionWindow, RerankWindow: suite.Target.RerankWindow,
		MaxExcerptBytes: suite.Target.MaxExcerptBytes,
	}
	if arm.Role == pairedFusionChallengerRole {
		profilePath := filepath.Join(roots.store, filepath.FromSlash(arm.FusionProfileArtifact.ObjectPath))
		if !isWithin(roots.store, profilePath) {
			return nil, false, false, fmt.Errorf("multidomain %s profile escaped its store", arm.Role)
		}
		hybridConfig.FusionProfilePath = profilePath
		hybridConfig.FusionProfileHash = arm.FusionProfileArtifact.DocumentSHA256
	}
	first, err := QueryHybrid(hybridConfig)
	if err != nil {
		return nil, false, false, fmt.Errorf("multidomain case %s %s query: %w", evaluationCase.CaseID, arm.Role, err)
	}
	second, err := QueryHybrid(hybridConfig)
	if err != nil {
		return nil, false, false, fmt.Errorf("multidomain case %s %s replay: %w", evaluationCase.CaseID, arm.Role, err)
	}
	if first.ResultState != "ok" {
		return nil, false, false, fmt.Errorf("multidomain case %s %s state %s/%s", evaluationCase.CaseID, arm.Role, first.ResultState, first.ErrorCode)
	}
	deterministic := canonicalEqual(first, second)
	citation := validateMultidomainCitations(first, roots.evidence, suite.Target.MaxExcerptBytes)
	return hybridResponseIDs(first), citation, deterministic, nil
}

func validateMultidomainCitations(response HybridQueryResponse, evidenceRoot string, maxExcerptBytes int) bool {
	seen := make(map[string]struct{}, len(response.Results))
	for _, hit := range response.Results {
		ref := hit.Evidence
		if _, exists := seen[ref.SpanID]; exists {
			return false
		}
		seen[ref.SpanID] = struct{}{}
		if ref.InstructionPolicy != "forbidden" || ref.ExecutionPolicy != "never" || ref.ToolPolicy != "never" || ref.InterpretationPolicy != "evidence_only" {
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
		want, _ := boundedUTF8(payload, maxExcerptBytes)
		if hit.Excerpt != want {
			return false
		}
	}
	return true
}

// multidomainChallengerComparisons pairs each class's baseline and challenger
// aggregate. The gain is the smallest per-metric (challenger - baseline) and the
// regression is the largest per-metric (baseline - challenger); a class passes
// only when gain >= the frozen minimum and regression <= the frozen maximum.
func multidomainChallengerComparisons(aggregates []RetrievalAggregateMetric, minGain, maxRegression int64) ([]MultidomainChallengerComparison, bool) {
	baseline := make(map[string]RetrievalAggregateMetric)
	challenger := make(map[string]RetrievalAggregateMetric)
	for _, aggregate := range aggregates {
		switch aggregate.Profile {
		case "baseline":
			baseline[aggregate.Class] = aggregate
		case "challenger":
			challenger[aggregate.Class] = aggregate
		}
	}
	classes := make([]string, 0, len(baseline))
	for class := range baseline {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	comparisons := make([]MultidomainChallengerComparison, 0, len(classes))
	allPassed := len(classes) > 0
	for _, class := range classes {
		base, baseOK := baseline[class]
		chal, chalOK := challenger[class]
		if !baseOK || !chalOK {
			allPassed = false
			continue
		}
		gains := []int64{chal.RecallPPM - base.RecallPPM, chal.MRRPPM - base.MRRPPM, chal.NDCGPPM - base.NDCGPPM}
		gain, regression := gains[0], -gains[0]
		for _, value := range gains[1:] {
			if value < gain {
				gain = value
			}
			if -value > regression {
				regression = -value
			}
		}
		passed := gain >= minGain && regression <= maxRegression
		allPassed = allPassed && passed
		comparisons = append(comparisons, MultidomainChallengerComparison{
			Class:             class,
			BaselineRecallPPM: base.RecallPPM, ChallengerRecallPPM: chal.RecallPPM,
			BaselineMRRPPM: base.MRRPPM, ChallengerMRRPPM: chal.MRRPPM,
			BaselineNDCGPPM: base.NDCGPPM, ChallengerNDCGPPM: chal.NDCGPPM,
			GainPPM: gain, RegressionPPM: regression, Passed: passed,
		})
	}
	return comparisons, allPassed
}

func verifyRunningMultidomainExecutables(config EvaluateMultidomainConfig) error {
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

func sealMultidomainReceipt(core MultidomainEvaluationReceiptCore) (MultidomainEvaluationReceipt, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return MultidomainEvaluationReceipt{}, err
	}
	digest := digestBytes(data)
	receipt := MultidomainEvaluationReceipt{ReceiptID: "retrieval-multidomain-evaluation-receipt:" + digest, ReceiptPayloadSHA256: digest, MultidomainEvaluationReceiptCore: core}
	if err := validateMultidomainReceipt(receipt); err != nil {
		return MultidomainEvaluationReceipt{}, err
	}
	return receipt, nil
}

func validateMultidomainReceipt(receipt MultidomainEvaluationReceipt) error {
	coreBytes, err := json.Marshal(receipt.MultidomainEvaluationReceiptCore)
	if err != nil || receipt.ReceiptPayloadSHA256 != digestBytes(coreBytes) || receipt.ReceiptID != "retrieval-multidomain-evaluation-receipt:"+receipt.ReceiptPayloadSHA256 {
		return errors.New("multidomain evaluation receipt identity mismatch")
	}
	if receipt.SchemaVersion != retrievalSchemaVersion || receipt.ReceiptKind != multidomainReceiptKind {
		return errors.New("multidomain evaluation receipt contract invalid")
	}
	// promotable and execution_authorized are structurally forbidden from ever
	// being true; a passing receipt is evidence, not authorization.
	if receipt.Promotable || receipt.ExecutionAuthorized {
		return errors.New("multidomain evaluation receipt must not carry promotion or execution authority")
	}
	if !validPrefixedDigest(receipt.SuiteID, "multidomain-evaluation-suite:") || !validSHA256(receipt.SuiteSHA256) || !validSHA256(receipt.EvaluatorExecutableSHA256) || !validSHA256(receipt.RetrievalExecutableSHA256) {
		return errors.New("multidomain evaluation receipt lineage invalid")
	}
	if !boundedMetadata(receipt.EvaluatorID) || !boundedMetadata(receipt.EvaluatorRevision) {
		return errors.New("multidomain evaluation receipt evaluator identity invalid")
	}
	if _, err := parseCanonicalUTC(receipt.EvaluatedAt); err != nil {
		return err
	}
	authorization := receipt.Authorization
	if authorization.Method != retrievalTransitionSignatureMethod || authorization.Namespace != multidomainReceiptSignatureNamespace || authorization.Actor == "" || strings.IndexFunc(authorization.Actor, func(r rune) bool { return r <= ' ' }) >= 0 || !sshFingerprintPattern.MatchString(authorization.KeyID) || !validSHA256(authorization.AllowedSignersSHA256) {
		return errors.New("multidomain evaluation receipt authorization invalid")
	}
	// State and gates are coupled exactly, so neither outcome can masquerade as
	// the other. Both require the three absolute floor gates. "passed"
	// additionally requires challenger_gain true — the promotion path, unchanged.
	// "baseline_adopted" requires challenger_gain FALSE: it is precisely the
	// outcome where the challenger was evaluated and did not beat the incumbent,
	// so a winning challenger cannot be recorded as baseline_adopted, and a
	// non-winning one cannot be recorded as passed.
	if !receipt.Gates.HeldOutQuality || !receipt.Gates.CitationLineage || !receipt.Gates.DeterministicReplay {
		return errors.New("multidomain evaluation receipt records a failed floor gate")
	}
	switch receipt.State {
	case "passed":
		if !receipt.Gates.ChallengerGain {
			return errors.New("passed receipt must record challenger_gain true")
		}
	case "baseline_adopted":
		if receipt.Gates.ChallengerGain {
			return errors.New("baseline_adopted receipt must record challenger_gain false; a winning challenger is 'passed'")
		}
	default:
		return errors.New("multidomain evaluation receipt state must be passed or baseline_adopted")
	}
	return nil
}

// VerifyMultidomainReceipt is the fail-closed reader: it re-derives the receipt
// identity, re-authorizes the actor against the pinned allowed_signers, and
// verifies the detached SSHSIG over the exact receipt bytes.
func VerifyMultidomainReceipt(receiptPath, receiptHash, signaturePath, signatureHash, allowedSignersPath string) (MultidomainEvaluationReceipt, error) {
	var zero MultidomainEvaluationReceipt
	receiptBytes, err := readStableFile(receiptPath, "multidomain evaluation receipt", maxMultidomainReceiptBytes)
	if err != nil || !validSHA256(receiptHash) || digestBytes(receiptBytes) != receiptHash {
		return zero, errors.New("multidomain evaluation receipt does not match caller pin")
	}
	var receipt MultidomainEvaluationReceipt
	if err := decodeStrictCanonical(receiptBytes, &receipt); err != nil || validateMultidomainReceipt(receipt) != nil {
		return zero, errors.New("multidomain evaluation receipt is invalid")
	}
	allowedSigners, err := readAndAuthorizeAllowedSigners(allowedSignersPath, receipt.Authorization.Actor, receipt.Authorization.KeyID)
	if err != nil || digestBytes(allowedSigners) != receipt.Authorization.AllowedSignersSHA256 {
		return zero, errors.New("multidomain evaluator allowed_signers does not match the signed receipt")
	}
	signature, err := readCanonicalSSHSIG(signaturePath, signatureHash)
	if err != nil {
		return zero, fmt.Errorf("multidomain evaluation signature: %w", err)
	}
	if err := verifyDetachedSSHSIG(receiptBytes, signature, allowedSigners, receipt.Authorization.Actor, receipt.Authorization.KeyID, receipt.Authorization.Namespace); err != nil {
		return zero, fmt.Errorf("multidomain evaluation signature verification failed: %w", err)
	}
	return receipt, nil
}

// signDetachedSSHSIG produces a deterministic detached SSHSIG over the payload
// using the operator's out-of-tree Ed25519 evaluator key. Ed25519 signing is
// deterministic, so two independent runs over identical bytes are byte-equal.
func signDetachedSSHSIG(payload []byte, privateKeyPath, namespace string) ([]byte, error) {
	if !boundedMetadata(namespace) {
		return nil, errors.New("SSHSIG namespace is invalid")
	}
	keyPath, err := filepath.Abs(privateKeyPath)
	if err != nil || validateNoSymlinkPath(keyPath) != nil {
		return nil, errors.New("evaluator private key is unavailable")
	}
	info, err := os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("evaluator private key must be a 0600 regular file")
	}
	if err := validateSSHKeygenBinary(); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "archeion-retrieval-sshsig-sign-")
	if err != nil {
		return nil, errors.New("cannot allocate SSHSIG signing workspace")
	}
	defer os.RemoveAll(directory)
	ctx, cancel := context.WithTimeout(context.Background(), sshKeygenTimeout)
	defer cancel()
	output, err := runSSHKeygen(ctx, directory, payload, "-Y", "sign", "-f", keyPath, "-n", namespace)
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 256 {
			message = message[:256]
		}
		return nil, fmt.Errorf("ssh-keygen signing failed: %s", message)
	}
	signature := extractArmoredSSHSIG(output)
	if err := validateCanonicalSSHSIG(signature); err != nil {
		return nil, fmt.Errorf("produced signature is not canonical SSHSIG: %w", err)
	}
	return signature, nil
}

// extractArmoredSSHSIG isolates the armored block ssh-keygen writes to stdout,
// normalizing to a trailing newline so the canonical validator accepts it.
func extractArmoredSSHSIG(output []byte) []byte {
	const begin = "-----BEGIN SSH SIGNATURE-----"
	const end = "-----END SSH SIGNATURE-----"
	start := bytes.Index(output, []byte(begin))
	stop := bytes.Index(output, []byte(end))
	if start < 0 || stop < 0 || stop < start {
		return nil
	}
	block := output[start : stop+len(end)]
	block = bytes.ReplaceAll(block, []byte("\r"), nil)
	return append(append([]byte(nil), block...), '\n')
}

type multidomainEvaluationMetrics struct {
	SchemaVersion    string                     `json:"schema_version"`
	MetricsKind      string                     `json:"metrics_kind"`
	State            string                     `json:"state"`
	SuiteID          string                     `json:"suite_id"`
	SuiteSHA256      string                     `json:"suite_document_sha256"`
	CaseMetrics      []RetrievalCaseMetric      `json:"case_metrics"`
	AggregateMetrics []RetrievalAggregateMetric `json:"aggregate_metrics"`
}
