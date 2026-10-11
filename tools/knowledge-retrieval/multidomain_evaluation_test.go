package main

import (
	"strings"
	"testing"
)

func mdArtifact(prefix, seed string) PairedFusionArtifactBinding {
	return PairedFusionArtifactBinding{
		ArtifactID:     prefix + digestBytes([]byte(seed)),
		DocumentSHA256: digestBytes([]byte(seed + "-doc")),
		ObjectPath:     "objects/" + seed + ".json",
		ByteSize:       128,
	}
}

func mdScorer(id, rev, seed string) PairedFusionScorerBinding {
	return PairedFusionScorerBinding{ScorerID: id, ScorerRevision: rev, ExecutableSHA256: digestBytes([]byte(seed)), ExecutableByteSize: 1024}
}

func mdThresholds() []RetrievalMetricThreshold {
	var out []RetrievalMetricThreshold
	for _, class := range []string{"cilium", "go", "kubernetes"} {
		for _, profile := range []string{"baseline", "challenger"} {
			out = append(out, RetrievalMetricThreshold{Class: class, Profile: profile, MinRecallPPM: 1000000, MinMRRPPM: 400000, MinNDCGPPM: 600000})
		}
	}
	return out
}

func mdLineages() []MultidomainLineageBinding {
	authorities := []struct{ id, scope, comp, ver string }{
		{"retrieval-source-authority:cilium:v1.19.5", "retrieval-admission-scope:cilium:v1.19.5", "cilium", "v1.19.5"},
		{"retrieval-source-authority:go:go1.26.5", "retrieval-admission-scope:go:go1.26.5", "go", "go1.26.5"},
		{"retrieval-source-authority:kubernetes:v1.36.2", "retrieval-admission-scope:kubernetes:v1.36.2", "kubernetes", "v1.36.2"},
	}
	var out []MultidomainLineageBinding
	for _, a := range authorities {
		out = append(out, MultidomainLineageBinding{
			AuthorityID: a.id, AdmissionPolicyScopeID: a.scope, ComponentID: a.comp, ComponentVersion: a.ver, DocumentCount: 5,
			SnapshotManifest: mdArtifact("snapshot-manifest:", "snap-"+a.comp),
			EvidenceManifest: mdArtifact("evidence-manifest:", "evid-"+a.comp),
			AdmissionPolicy:  mdArtifact("retrieval-admission:", "adm-"+a.comp),
		})
	}
	return out
}

func mdCases() []MultidomainEvaluationCase {
	specs := []struct{ id, class, query string }{
		{"cilium-01", "cilium", "cilium query one"},
		{"go-01", "go", "go query one"},
		{"kubernetes-01", "kubernetes", "kubernetes query one"},
	}
	var out []MultidomainEvaluationCase
	for _, s := range specs {
		out = append(out, MultidomainEvaluationCase{
			CaseID: s.id, Class: s.class, Query: s.query, QuerySHA256: digestBytes([]byte(s.query)),
			AdmittedSpanID: "evidence-span:" + digestBytes([]byte("span-"+s.id)), Grade: 3,
			Signals: PairedFusionCaseSignals{
				Baseline:   mdArtifact("query-signal-artifact:", "base-sig-"+s.id),
				Challenger: mdArtifact("query-signal-artifact:", "chal-sig-"+s.id),
			},
		})
	}
	return out
}

func validMultidomainCore() MultidomainEvaluationSuiteCore {
	return MultidomainEvaluationSuiteCore{
		SchemaVersion: retrievalSchemaVersion, SuiteKind: multidomainEvaluationSuiteKind,
		State: "frozen", ExecutionState: multidomainEvaluationExecutionState,
		Name: "test-suite", Revision: "v1", FrozenAt: "2026-07-18T00:00:00Z",
		Target: PairedFusionTarget{
			ComparisonMode: "paired_fusion_profiles", BaselineProfile: hybridFusionProfile,
			ChallengerProfile: championFusionProfile, MetricAlgorithm: metricAlgorithm, MetricScale: retrievalMetricScale,
			CutoffK: 10, Limit: 10, FusionWindow: 100, RerankWindow: 0, MaxExcerptBytes: 2048,
		},
		MinChallengerGainPPM: 0, MaximumChallengerRegression: 0,
		Thresholds:       mdThresholds(),
		LexicalCandidate: mdArtifact("retrieval-candidate:", "lex"),
		LexicalIndex:     mdArtifact("lexical-index:", "idx"),
		DenseArtifact:    mdArtifact("dense-vector-artifact:", "dense"),
		Arms: []PairedFusionArmBinding{
			{Role: "baseline", FusionProfile: hybridFusionProfile, HybridCandidate: mdArtifact("hybrid-retrieval-candidate:", "base-hyb"), Scorer: mdScorer(pairedFusionBaselineID, pairedFusionBaselineRev, "bin")},
			func() PairedFusionArmBinding {
				profile := mdArtifact("fusion-profile:", "profile")
				return PairedFusionArmBinding{Role: "challenger", FusionProfile: championFusionProfile, HybridCandidate: mdArtifact("hybrid-retrieval-candidate:", "chal-hyb"), Scorer: mdScorer(championFusionScorerID, championFusionScorerRevision, "bin"), FusionProfileArtifact: &profile}
			}(),
		},
		Lineages: mdLineages(),
		Cases:    mdCases(),
	}
}

func TestValidMultidomainSuiteSeals(t *testing.T) {
	suite, err := sealMultidomainEvaluationSuite(validMultidomainCore())
	if err != nil {
		t.Fatalf("valid core must seal: %v", err)
	}
	if !strings.HasPrefix(suite.SuiteID, "multidomain-evaluation-suite:sha256:") {
		t.Fatalf("unexpected suite id %q", suite.SuiteID)
	}
	if err := validateMultidomainEvaluationSuite(suite); err != nil {
		t.Fatalf("sealed suite must revalidate: %v", err)
	}
}

func TestMultidomainSuiteFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(core *MultidomainEvaluationSuiteCore)
	}{
		{"weakened execution state", func(c *MultidomainEvaluationSuiteCore) { c.ExecutionState = "authorized" }},
		{"weakened recall floor", func(c *MultidomainEvaluationSuiteCore) { c.Thresholds[0].MinRecallPPM = 999999 }},
		{"weakened mrr floor", func(c *MultidomainEvaluationSuiteCore) { c.Thresholds[0].MinMRRPPM = 1 }},
		{"weakened challenger regression gate", func(c *MultidomainEvaluationSuiteCore) { c.MaximumChallengerRegression = 1 }},
		{"negative challenger gain gate", func(c *MultidomainEvaluationSuiteCore) { c.MinChallengerGainPPM = -1 }},
		{"non-zero rerank window", func(c *MultidomainEvaluationSuiteCore) { c.Target.RerankWindow = 5 }},
		{"wrong cutoff", func(c *MultidomainEvaluationSuiteCore) { c.Target.CutoffK = 5 }},
		{"wrong fusion window", func(c *MultidomainEvaluationSuiteCore) { c.Target.FusionWindow = 50 }},
		{"baseline arm carries profile", func(c *MultidomainEvaluationSuiteCore) {
			profile := mdArtifact("fusion-profile:", "sneak")
			c.Arms[0].FusionProfileArtifact = &profile
		}},
		{"challenger arm missing profile", func(c *MultidomainEvaluationSuiteCore) { c.Arms[1].FusionProfileArtifact = nil }},
		{"arms reuse candidate", func(c *MultidomainEvaluationSuiteCore) { c.Arms[1].HybridCandidate = c.Arms[0].HybridCandidate }},
		{"aliased lineage authority", func(c *MultidomainEvaluationSuiteCore) { c.Lineages[1].AuthorityID = c.Lineages[0].AuthorityID }},
		{"aliased lineage snapshot", func(c *MultidomainEvaluationSuiteCore) {
			c.Lineages[1].SnapshotManifest = c.Lineages[0].SnapshotManifest
		}},
		{"aliased lineage admission", func(c *MultidomainEvaluationSuiteCore) { c.Lineages[1].AdmissionPolicy = c.Lineages[0].AdmissionPolicy }},
		{"case reuses signal across arms", func(c *MultidomainEvaluationSuiteCore) { c.Cases[0].Signals.Challenger = c.Cases[0].Signals.Baseline }},
		{"case query hash mismatch", func(c *MultidomainEvaluationSuiteCore) { c.Cases[0].QuerySHA256 = digestBytes([]byte("other")) }},
		{"case admitted span not evidence span", func(c *MultidomainEvaluationSuiteCore) {
			c.Cases[0].AdmittedSpanID = "lexical-document:" + digestBytes([]byte("x"))
		}},
		{"case grade out of range", func(c *MultidomainEvaluationSuiteCore) { c.Cases[0].Grade = 2 }},
		{"cases not in order", func(c *MultidomainEvaluationSuiteCore) {
			c.Cases[0].CaseID, c.Cases[2].CaseID = c.Cases[2].CaseID, c.Cases[0].CaseID
		}},
		{"threshold class without case", func(c *MultidomainEvaluationSuiteCore) { c.Cases = c.Cases[:2] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core := validMultidomainCore()
			tc.mutate(&core)
			if _, err := sealMultidomainEvaluationSuite(core); err == nil {
				t.Fatalf("mutation %q must fail closed", tc.name)
			}
		})
	}
}

func TestMultidomainSharedAdmittedSpanAllowed(t *testing.T) {
	core := validMultidomainCore()
	// Two cases in the same class legitimately resolve to one coarse chunk.
	core.Cases[1].AdmittedSpanID = core.Cases[0].AdmittedSpanID
	if _, err := sealMultidomainEvaluationSuite(core); err != nil {
		t.Fatalf("shared admitted span must be allowed: %v", err)
	}
}
