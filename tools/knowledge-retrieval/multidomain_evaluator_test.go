package main

import "testing"

func validMultidomainReceiptCore() MultidomainEvaluationReceiptCore {
	return MultidomainEvaluationReceiptCore{
		SchemaVersion: retrievalSchemaVersion, ReceiptKind: multidomainReceiptKind, State: "passed",
		Promotable: false, ExecutionAuthorized: false,
		SuiteID: "multidomain-evaluation-suite:" + digestBytes([]byte("suite")), SuiteSHA256: digestBytes([]byte("suite-doc")),
		LexicalCandidateID: "retrieval-candidate:" + digestBytes([]byte("lex")), LexicalCandidateSHA256: digestBytes([]byte("lex-doc")),
		DenseArtifactID: "dense-vector-artifact:" + digestBytes([]byte("dense")), DenseArtifactSHA256: digestBytes([]byte("dense-doc")),
		BaselineCandidateID: "hybrid-retrieval-candidate:" + digestBytes([]byte("b")), BaselineCandidateSHA256: digestBytes([]byte("b-doc")),
		ChallengerCandidateID: "hybrid-retrieval-candidate:" + digestBytes([]byte("c")), ChallengerCandidateSHA256: digestBytes([]byte("c-doc")),
		ChallengerFusionProfileID: "fusion-profile:" + digestBytes([]byte("p")), ChallengerFusionProfileSHA256: digestBytes([]byte("p-doc")),
		ChallengerScorerSHA256: digestBytes([]byte("bin")),
		MetricAlgorithm:        metricAlgorithm, MetricScale: retrievalMetricScale, CutoffK: 10,
		MinChallengerGainPPM: 0, MaximumChallengerRegression: 0,
		Gates:       MultidomainEvaluationGates{HeldOutQuality: true, CitationLineage: true, DeterministicReplay: true, ChallengerGain: true},
		EvaluatorID: multidomainEvaluatorID, EvaluatorRevision: multidomainEvaluatorRevision,
		EvaluatorExecutableSHA256: digestBytes([]byte("bin")), RetrievalExecutableSHA256: digestBytes([]byte("bin")),
		EvaluatedAt: "2026-07-18T00:00:00Z",
		Authorization: RetrievalTransitionAuthorization{
			Actor: "archeion-retrieval-multidomain-evaluator", Method: retrievalTransitionSignatureMethod,
			KeyID: "SHA256:Wt4nyE03UVXkRV1E3vkbTfQs0eSUus0xOQOsc/rt93M", Namespace: multidomainReceiptSignatureNamespace,
			AllowedSignersSHA256: digestBytes([]byte("allowed")),
		},
	}
}

func TestValidMultidomainReceiptSeals(t *testing.T) {
	receipt, err := sealMultidomainReceipt(validMultidomainReceiptCore())
	if err != nil {
		t.Fatalf("valid receipt must seal: %v", err)
	}
	if receipt.Promotable || receipt.ExecutionAuthorized {
		t.Fatal("receipt must never carry promotion or execution authority")
	}
}

func TestMultidomainReceiptFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(core *MultidomainEvaluationReceiptCore)
	}{
		{"promotable true", func(c *MultidomainEvaluationReceiptCore) { c.Promotable = true }},
		{"execution authorized true", func(c *MultidomainEvaluationReceiptCore) { c.ExecutionAuthorized = true }},
		{"failed held out gate", func(c *MultidomainEvaluationReceiptCore) { c.Gates.HeldOutQuality = false }},
		{"failed challenger gate", func(c *MultidomainEvaluationReceiptCore) { c.Gates.ChallengerGain = false }},
		{"state not passed", func(c *MultidomainEvaluationReceiptCore) { c.State = "failed" }},
		{"wrong signature namespace", func(c *MultidomainEvaluationReceiptCore) {
			c.Authorization.Namespace = "archeion-retrieval-generation-transition-v1"
		}},
		{"non fingerprint key id", func(c *MultidomainEvaluationReceiptCore) { c.Authorization.KeyID = "not-a-fingerprint" }},
		{"suite id not prefixed", func(c *MultidomainEvaluationReceiptCore) { c.SuiteID = "suite:" + digestBytes([]byte("x")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core := validMultidomainReceiptCore()
			tc.mutate(&core)
			if _, err := sealMultidomainReceipt(core); err == nil {
				t.Fatalf("mutation %q must fail closed", tc.name)
			}
		})
	}
}

func aggregate(class, profile string, recall, mrr, ndcg int64) RetrievalAggregateMetric {
	return RetrievalAggregateMetric{Class: class, Profile: profile, QueryCount: 3, RecallPPM: recall, MRRPPM: mrr, NDCGPPM: ndcg, MinRecallPPM: 1000000, MinMRRPPM: 400000, MinNDCGPPM: 600000, ThresholdPassed: true}
}

func TestMultidomainChallengerComparisons(t *testing.T) {
	equal := []RetrievalAggregateMetric{
		aggregate("cilium", "baseline", 1000000, 1000000, 1000000),
		aggregate("cilium", "challenger", 1000000, 1000000, 1000000),
	}
	if _, passed := multidomainChallengerComparisons(equal, 0, 0); !passed {
		t.Fatal("equal metrics must satisfy zero-gain / zero-regression gates")
	}
	regressed := []RetrievalAggregateMetric{
		aggregate("cilium", "baseline", 1000000, 1000000, 1000000),
		aggregate("cilium", "challenger", 1000000, 900000, 1000000),
	}
	if _, passed := multidomainChallengerComparisons(regressed, 0, 0); passed {
		t.Fatal("a challenger MRR regression must fail the gate")
	}
	gained := []RetrievalAggregateMetric{
		aggregate("cilium", "baseline", 800000, 800000, 800000),
		aggregate("cilium", "challenger", 1000000, 1000000, 1000000),
	}
	if _, passed := multidomainChallengerComparisons(gained, 0, 0); !passed {
		t.Fatal("a strictly improved challenger must pass")
	}
}

func TestVerifyMultidomainReceiptRejectsMissingInputs(t *testing.T) {
	if _, err := VerifyMultidomainReceipt("", "", "", "", ""); err == nil {
		t.Fatal("empty inputs must fail closed")
	}
}

// baselineAdoptedCore is the honest non-winning outcome: the three floor gates
// pass and the challenger did NOT beat the incumbent (ChallengerGain false), so
// baseline RRF is adopted.
func baselineAdoptedCore() MultidomainEvaluationReceiptCore {
	c := validMultidomainReceiptCore()
	c.State = "baseline_adopted"
	c.Gates.ChallengerGain = false
	return c
}

func TestBaselineAdoptedReceiptSealsAndCouplesStateToGates(t *testing.T) {
	// The honest baseline-adopted outcome must seal.
	if _, err := sealMultidomainReceipt(baselineAdoptedCore()); err != nil {
		t.Fatalf("valid baseline_adopted receipt must seal: %v", err)
	}

	// Neither state may masquerade as the other, and the floor is mandatory for
	// both. Each of these must fail closed.
	cases := []struct {
		name   string
		mutate func(c *MultidomainEvaluationReceiptCore)
	}{
		// A winning challenger cannot be recorded as baseline_adopted.
		{"baseline_adopted with challenger_gain true", func(c *MultidomainEvaluationReceiptCore) {
			*c = baselineAdoptedCore()
			c.Gates.ChallengerGain = true
		}},
		// A non-winning run cannot be recorded as passed.
		{"passed with challenger_gain false", func(c *MultidomainEvaluationReceiptCore) {
			c.State = "passed"
			c.Gates.ChallengerGain = false
		}},
		// The floor is mandatory even for baseline_adopted.
		{"baseline_adopted with floor gate false", func(c *MultidomainEvaluationReceiptCore) {
			*c = baselineAdoptedCore()
			c.Gates.HeldOutQuality = false
		}},
		// No third state is sealable.
		{"invented state", func(c *MultidomainEvaluationReceiptCore) {
			*c = baselineAdoptedCore()
			c.State = "challenger_adopted"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core := validMultidomainReceiptCore()
			tc.mutate(&core)
			if _, err := sealMultidomainReceipt(core); err == nil {
				t.Fatalf("mutation %q must fail closed", tc.name)
			}
		})
	}
}
