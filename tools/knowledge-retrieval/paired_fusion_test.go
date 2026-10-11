package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type pairedFusionTestFixture struct {
	*hybridTestFixture
	core             PairedFusionSuiteCore
	corePath         string
	suiteStore       string
	signalRoot       string
	snapshotRoot     string
	baseline         HybridCandidateManifest
	baselinePath     string
	baselineSignal   QuerySignalArtifact
	challengerSignal QuerySignalArtifact
	executablePath   string
	executableHash   string
	executableSize   int64
}

func TestTrackedWorkflowsPairedFusionSuiteMaterializes(t *testing.T) {
	corePath := filepath.Join("testdata", "paired-fusion-suites", "argo-workflows-v4.0.7-lane-champion-v1.core.json")
	first, firstPath, err := MaterializePairedFusionSuite(corePath, filepath.Join(t.TempDir(), "first"))
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializePairedFusionSuite(corePath, filepath.Join(t.TempDir(), "second"))
	if err != nil {
		t.Fatal(err)
	}
	if first.SuiteID != "paired-fusion-suite:sha256:81fb4b67ed820d96afa15955ebfb850ef2804945115ee932f18f4c917c43b09e" {
		t.Fatalf("unexpected tracked suite identity: %s", first.SuiteID)
	}
	if first.SuiteID != second.SuiteID || fileDigest(firstPath) != fileDigest(secondPath) {
		t.Fatal("tracked Workflows suite did not materialize deterministically")
	}
	if len(first.Cases) != 5 || len(first.Spans) != 10 || first.ExecutionState != pairedFusionExecutionState {
		t.Fatalf("tracked Workflows suite lost its frozen shape: %#v", first)
	}
}

func TestPairedFusionSuiteMaterializesAndPreflightsWithoutExecution(t *testing.T) {
	fx := newPairedFusionTestFixture(t)
	first, firstPath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(firstPath)
	secondBytes, _ := os.ReadFile(secondPath)
	if first.SuiteID != second.SuiteID || firstPath != secondPath || string(firstBytes) != string(secondBytes) {
		t.Fatal("paired fusion suite materialization was not deterministic")
	}
	plan, err := PreparePairedFusionRun(fx.prepareConfig(firstPath))
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != "preflight_complete_no_execution" || plan.ExecutionAuthorized || plan.CaseCount != 1 || plan.PlannedExecutions != 2 || plan.SuiteID != first.SuiteID {
		t.Fatalf("paired fusion preflight overclaimed or lost its plan: %#v", plan)
	}
}

func TestPairedFusionSignalSemanticsCompareEveryRerankerField(t *testing.T) {
	baseline := QuerySignalArtifact{QuerySignalArtifactCore: QuerySignalArtifactCore{
		HybridCandidateID: "hybrid-retrieval-candidate:baseline", QueryVector: []int16{1, 2},
		RerankingRequested: true, RerankerModelID: "model", RerankerModelRevision: "revision",
		RerankerModelArtifactSHA256: "sha256:" + strings.Repeat("1", 64),
		RerankerTokenizerID:         "tokenizer", RerankerTokenizerSHA256: "sha256:" + strings.Repeat("2", 64),
		RerankerProfile: "profile", RerankerQueryInstruction: "query", RerankerDocumentInstruction: "document",
		RerankerScoreScale: 1_000, Scores: []RerankerDocumentScore{{DocumentID: "doc", Score: 7}},
	}}
	challenger := baseline
	challenger.HybridCandidateID = "hybrid-retrieval-candidate:challenger"
	if err := validatePairedSignalSemantics(baseline, challenger); err != nil {
		t.Fatalf("candidate-only signal difference was rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*QuerySignalArtifact)
	}{
		{"reranker model", func(signal *QuerySignalArtifact) { signal.RerankerModelID = "other" }},
		{"reranker score", func(signal *QuerySignalArtifact) {
			signal.Scores = []RerankerDocumentScore{{DocumentID: "doc", Score: 8}}
		}},
		{"query vector", func(signal *QuerySignalArtifact) { signal.QueryVector = []int16{2, 1} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drifted := challenger
			tc.mutate(&drifted)
			if err := validatePairedSignalSemantics(baseline, drifted); err == nil {
				t.Fatal("cross-arm semantic drift was accepted")
			}
		})
	}
}

func TestPairedFusionReadPlanIsDeterministicAndCountBounded(t *testing.T) {
	fx := newPairedFusionTestFixture(t)
	suite, err := sealPairedFusionSuite(fx.core)
	if err != nil {
		t.Fatal(err)
	}
	roots := pairedFusionRootSet{retrieval: "retrieval", snapshot: "snapshot", evidence: "evidence", signals: "signals"}
	first := pairedFusionReadPlan(suite, roots)
	second := pairedFusionReadPlan(suite, roots)
	if len(first) != len(second) {
		t.Fatal("paired fusion read plan changed length")
	}
	for index := range first {
		if first[index].label != second[index].label || first[index].root != second[index].root || first[index].binding != second[index].binding {
			t.Fatalf("paired fusion read plan changed at %d", index)
		}
	}
	maximumDeclaredInputs := 1 + 9 + maxPairedFusionSources + maxPairedFusionSpans + 2*maxPairedFusionCases + 2
	if maximumDeclaredInputs > maxPairedFusionInputCount {
		t.Fatalf("declared shape can exceed hard input count: %d > %d", maximumDeclaredInputs, maxPairedFusionInputCount)
	}
}

func TestPairedFusionSuiteRejectsBindingDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PairedFusionSuiteCore)
	}{
		{"same arm candidate", func(core *PairedFusionSuiteCore) { core.Arms[1].HybridCandidate = core.Arms[0].HybridCandidate }},
		{"same arm signal", func(core *PairedFusionSuiteCore) { core.Cases[0].Signals.Challenger = core.Cases[0].Signals.Baseline }},
		{"missing mapped span", func(core *PairedFusionSuiteCore) {
			core.Cases[0].SourceJudgments[0].MappedSpanIDs = core.Cases[0].SourceJudgments[0].MappedSpanIDs[:1]
		}},
		{"weakened gate", func(core *PairedFusionSuiteCore) {
			core.ComparisonGates.RequiredGates = core.ComparisonGates.RequiredGates[1:]
		}},
		{"partial scorer", func(core *PairedFusionSuiteCore) { core.Arms[1].Scorer.ExecutableSHA256 = "" }},
		{"snapshot artifact type", func(core *PairedFusionSuiteCore) {
			core.SnapshotManifest.ArtifactID = "evidence-manifest:" + core.SnapshotManifest.DocumentSHA256
		}},
		{"evidence artifact type", func(core *PairedFusionSuiteCore) {
			core.EvidenceManifest.ArtifactID = "snapshot-manifest:" + core.EvidenceManifest.DocumentSHA256
		}},
		{"admission artifact type", func(core *PairedFusionSuiteCore) {
			core.AdmissionPolicy.ArtifactID = "source-admission-policy:" + core.AdmissionPolicy.DocumentSHA256
		}},
		{"lexical candidate artifact type", func(core *PairedFusionSuiteCore) {
			core.LexicalCandidate.ArtifactID = "hybrid-retrieval-candidate:" + core.LexicalCandidate.DocumentSHA256
		}},
		{"lexical index artifact type", func(core *PairedFusionSuiteCore) {
			core.LexicalIndex.ArtifactID = "dense-vector-artifact:" + core.LexicalIndex.DocumentSHA256
		}},
		{"dense artifact type", func(core *PairedFusionSuiteCore) {
			core.DenseArtifact.ArtifactID = "lexical-index:" + core.DenseArtifact.DocumentSHA256
		}},
		{"oversized admission policy", func(core *PairedFusionSuiteCore) { core.AdmissionPolicy.ByteSize = maxPolicyBytes + 1 }},
		{"oversized lexical index", func(core *PairedFusionSuiteCore) { core.LexicalIndex.ByteSize = maxIndexBytes + 1 }},
		{"oversized dense artifact", func(core *PairedFusionSuiteCore) { core.DenseArtifact.ByteSize = maxDenseArtifactBytes + 1 }},
		{"unused evidence", func(core *PairedFusionSuiteCore) {
			core.Cases[0].RelevanceJudgments = core.Cases[0].RelevanceJudgments[:1]
		}},
		{"unknown relevance span", func(core *PairedFusionSuiteCore) {
			core.Cases[0].RelevanceJudgments[0].SpanID = "evidence-span:sha256:" + strings.Repeat("f", 64)
		}},
		{"malformed relevance span", func(core *PairedFusionSuiteCore) {
			core.Cases[0].RelevanceJudgments[0].SpanID = "span:sha256:" + strings.Repeat("f", 64)
		}},
		{"zero relevance grade", func(core *PairedFusionSuiteCore) { core.Cases[0].RelevanceJudgments[0].Grade = 0 }},
		{"high relevance grade", func(core *PairedFusionSuiteCore) { core.Cases[0].RelevanceJudgments[0].Grade = 4 }},
		{"relevance grade differs from map", func(core *PairedFusionSuiteCore) {
			core.Cases[0].RelevanceJudgments[0].Grade = 2
		}},
		{"relevance order", func(core *PairedFusionSuiteCore) {
			if len(core.Cases[0].RelevanceJudgments) > 1 {
				core.Cases[0].RelevanceJudgments[0], core.Cases[0].RelevanceJudgments[1] = core.Cases[0].RelevanceJudgments[1], core.Cases[0].RelevanceJudgments[0]
			}
		}},
		{"resource hard cap", func(core *PairedFusionSuiteCore) { core.ResourceLimits.MaxPeakRSSBytes = hardMaxPairedPeakRSSBytes + 1 }},
		{"scanned-document coherence", func(core *PairedFusionSuiteCore) { core.ResourceLimits.MaxScannedDocuments = 1 }},
		{"excerpt-byte coherence", func(core *PairedFusionSuiteCore) {
			core.ResourceLimits.MaxReturnedExcerptBytes = int64(core.ResourceLimits.MaxReturnedResults*core.Target.MaxExcerptBytes) - 1
		}},
		{"query-signal-byte coherence", func(core *PairedFusionSuiteCore) {
			core.ResourceLimits.MaxQuerySignalBytes = core.Cases[0].Signals.Baseline.ByteSize - 1
		}},
		{"aggregate input bytes", func(core *PairedFusionSuiteCore) {
			core.SnapshotManifest.ByteSize = maxManifestBytes
			core.EvidenceManifest.ByteSize = maxManifestBytes
			core.LexicalCandidate.ByteSize = maxManifestBytes
			core.LexicalIndex.ByteSize = maxManifestBytes
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newPairedFusionTestFixture(t)
			core := fx.core
			tc.mutate(&core)
			writeCanonical(t, fx.corePath, core)
			if _, _, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore); err == nil {
				t.Fatal("binding drift unexpectedly materialized")
			}
		})
	}
}

func TestSharedHybridLineageRejectsEveryBindingClass(t *testing.T) {
	fx := newPairedFusionTestFixture(t)
	baseBindings := hybridLineageBindings{
		lexical: hybridDocumentBinding{path: fx.core.LexicalCandidate.ObjectPath, digest: fx.core.LexicalCandidate.DocumentSHA256, size: fx.core.LexicalCandidate.ByteSize},
		index:   hybridDocumentBinding{path: fx.core.LexicalIndex.ObjectPath, digest: fx.core.LexicalIndex.DocumentSHA256, size: fx.core.LexicalIndex.ByteSize},
		dense:   hybridDocumentBinding{path: fx.core.DenseArtifact.ObjectPath, digest: fx.core.DenseArtifact.DocumentSHA256, size: fx.core.DenseArtifact.ByteSize},
	}
	if err := validateLoadedHybridLineage(fx.baseline, fx.lexical.Manifest, fx.index, fx.dense, nil, baseBindings); err != nil {
		t.Fatalf("valid shared hybrid lineage rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*HybridCandidateManifest)
	}{
		{"snapshot", func(value *HybridCandidateManifest) {
			value.SnapshotManifestID = "snapshot-manifest:sha256:" + strings.Repeat("f", 64)
		}},
		{"evidence", func(value *HybridCandidateManifest) {
			value.EvidenceManifestID = "evidence-manifest:sha256:" + strings.Repeat("f", 64)
		}},
		{"admission ID", func(value *HybridCandidateManifest) {
			value.AdmissionPolicyID = "retrieval-admission:sha256:" + strings.Repeat("f", 64)
		}},
		{"admission document", func(value *HybridCandidateManifest) {
			value.AdmissionPolicySHA256 = "sha256:" + strings.Repeat("f", 64)
		}},
		{"source admission method", func(value *HybridCandidateManifest) {
			value.SourceAdmissionMethod = "standing_policy"
			value.SourceAdmissionPolicySHA256 = "sha256:" + strings.Repeat("e", 64)
			value.SourceAdmissionPolicyID = "source-admission-policy:" + value.SourceAdmissionPolicySHA256
		}},
		{"source admission ID", func(value *HybridCandidateManifest) {
			value.SourceAdmissionPolicyID = "source-admission-policy:sha256:" + strings.Repeat("f", 64)
		}},
		{"source admission hash", func(value *HybridCandidateManifest) {
			value.SourceAdmissionPolicySHA256 = "sha256:" + strings.Repeat("f", 64)
		}},
		{"freshness state", func(value *HybridCandidateManifest) { value.FreshnessState = "stale" }},
		{"evaluated at", func(value *HybridCandidateManifest) { value.EvaluatedAt = "2025-01-01T00:00:00Z" }},
		{"fresh until", func(value *HybridCandidateManifest) { value.FreshUntil = "2028-01-01T00:00:00Z" }},
		{"lexical profile", func(value *HybridCandidateManifest) { value.LexicalProfile = "other" }},
		{"lexical tokenizer", func(value *HybridCandidateManifest) { value.LexicalTokenizerID = "other" }},
		{"lexical scorer", func(value *HybridCandidateManifest) { value.LexicalScorerID = "other" }},
		{"dense model", func(value *HybridCandidateManifest) { value.DenseModelID = "other" }},
		{"dense revision", func(value *HybridCandidateManifest) { value.DenseModelRevision = "other" }},
		{"dense model hash", func(value *HybridCandidateManifest) {
			value.DenseModelArtifactSHA256 = "sha256:" + strings.Repeat("f", 64)
		}},
		{"dense tokenizer", func(value *HybridCandidateManifest) { value.DenseTokenizerID = "other" }},
		{"dense tokenizer hash", func(value *HybridCandidateManifest) { value.DenseTokenizerSHA256 = "sha256:" + strings.Repeat("f", 64) }},
		{"embedding profile", func(value *HybridCandidateManifest) { value.EmbeddingProfile = "other" }},
		{"dense instruction", func(value *HybridCandidateManifest) { value.DenseDocumentInstruction = "other" }},
		{"vector encoding", func(value *HybridCandidateManifest) { value.VectorEncoding = "other" }},
		{"normalization", func(value *HybridCandidateManifest) { value.Normalization = "other" }},
		{"quantization", func(value *HybridCandidateManifest) { value.QuantizationScale-- }},
		{"dimension", func(value *HybridCandidateManifest) { value.Dimension++ }},
		{"document count", func(value *HybridCandidateManifest) { value.DocumentCount++ }},
		{"authority lineages", func(value *HybridCandidateManifest) {
			value.Lineages = []AuthorityLineageBinding{{
				AuthorityID: "forged", ComponentID: "component:forged", ComponentVersion: "v1",
				AdmissionPolicyScopeID: "scope:forged", SourceID: "src:forged", SnapshotID: "snap:forged",
				SnapshotManifestID: "s1", EvidenceManifestID: "e1", AdmissionPolicyID: "p1",
				SnapshotManifestDocumentSHA256: "sha256:" + strings.Repeat("1", 64),
				EvidenceManifestDocumentSHA256: "sha256:" + strings.Repeat("2", 64),
				AdmissionPolicyDocumentSHA256:  "sha256:" + strings.Repeat("3", 64),
				AdmissionEvaluatedAt:           "2026-07-18T00:00:00Z", AdmissionFreshUntil: "2026-08-18T00:00:00Z",
				FreshnessState: "fresh", DocumentCount: 1,
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := fx.baseline
			tc.mutate(&candidate)
			resealHybridCandidate(&candidate)
			if err := validateLoadedHybridLineage(candidate, fx.lexical.Manifest, fx.index, fx.dense, nil, baseBindings); err == nil {
				t.Fatal("hybrid lineage drift was accepted")
			}
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*hybridLineageBindings)
	}{
		{"lexical path", func(value *hybridLineageBindings) { value.lexical.path = "candidates/other.json" }},
		{"lexical hash", func(value *hybridLineageBindings) { value.lexical.digest = "sha256:" + strings.Repeat("f", 64) }},
		{"lexical size", func(value *hybridLineageBindings) { value.lexical.size++ }},
		{"index path", func(value *hybridLineageBindings) { value.index.path = "indexes/other.json" }},
		{"index hash", func(value *hybridLineageBindings) { value.index.digest = "sha256:" + strings.Repeat("f", 64) }},
		{"index size", func(value *hybridLineageBindings) { value.index.size++ }},
		{"dense path", func(value *hybridLineageBindings) { value.dense.path = "dense-indexes/other.json" }},
		{"dense hash", func(value *hybridLineageBindings) { value.dense.digest = "sha256:" + strings.Repeat("f", 64) }},
		{"dense size", func(value *hybridLineageBindings) { value.dense.size++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bindings := baseBindings
			tc.mutate(&bindings)
			if err := validateLoadedHybridLineage(fx.baseline, fx.lexical.Manifest, fx.index, fx.dense, nil, bindings); err == nil {
				t.Fatal("hybrid store-binding drift was accepted")
			}
		})
	}
}

func TestPairedFusionPreflightRejectsTemporalAndProfileWindowDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*pairedFusionTestFixture)
	}{
		{"policy evaluated after freeze", func(fx *pairedFusionTestFixture) { fx.core.FrozenAt = "2025-01-01T00:00:00Z" }},
		{"policy stale before freeze", func(fx *pairedFusionTestFixture) { fx.core.FrozenAt = "2028-01-01T00:00:00Z" }},
		{"challenger fusion window", func(fx *pairedFusionTestFixture) { fx.core.Target.FusionWindow++ }},
		{"challenger result window", func(fx *pairedFusionTestFixture) {
			fx.core.Target.CutoffK = 1
			fx.core.Target.Limit = 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newPairedFusionTestFixture(t)
			tc.mutate(fx)
			writeCanonical(t, fx.corePath, fx.core)
			_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
			if err != nil {
				// A malformed target rejected while freezing is also a fail-closed
				// outcome; temporal cases remain structurally valid and reach preflight.
				if strings.Contains(tc.name, "window") {
					return
				}
				t.Fatal(err)
			}
			if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil {
				t.Fatal("temporal or profile-window drift was accepted")
			}
		})
	}
}

func TestPairedEvidenceLineageRejectsMalformedManifestAndExactBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*EvidenceManifest, *LexicalIndex, map[string][]byte)
	}{
		{"occurrence source", func(evidence *EvidenceManifest, _ *LexicalIndex, _ map[string][]byte) {
			evidence.Files[0].SourceID = "other"
		}},
		{"span ordinal", func(evidence *EvidenceManifest, _ *LexicalIndex, _ map[string][]byte) {
			evidence.Files[0].Spans[0].Ordinal++
		}},
		{"span byte partition", func(evidence *EvidenceManifest, _ *LexicalIndex, _ map[string][]byte) {
			evidence.Files[0].Spans[0].RawByteStart++
		}},
		{"span line coordinates", func(evidence *EvidenceManifest, _ *LexicalIndex, _ map[string][]byte) {
			evidence.Files[0].Spans[0].RawLineStart++
		}},
		{"payload identity", func(evidence *EvidenceManifest, _ *LexicalIndex, _ map[string][]byte) {
			evidence.Files[0].Spans[0].PayloadID = "normalized:other"
		}},
		{"manifest span denominator", func(evidence *EvidenceManifest, _ *LexicalIndex, _ map[string][]byte) { evidence.SpanCount++ }},
		{"payload differs from raw", func(_ *EvidenceManifest, _ *LexicalIndex, artifacts map[string][]byte) {
			for label := range artifacts {
				if strings.HasPrefix(label, "span ") {
					artifacts[label] = []byte("different")
					return
				}
			}
		}},
		{"duplicate indexed SpanID", func(_ *EvidenceManifest, index *LexicalIndex, _ map[string][]byte) {
			index.Documents[1].Evidence.SpanID = index.Documents[0].Evidence.SpanID
		}},
		{"judged index reference", func(_ *EvidenceManifest, index *LexicalIndex, _ map[string][]byte) {
			index.Documents[0].Evidence.SourceID = "other"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newPairedFusionTestFixture(t)
			suite, err := sealPairedFusionSuite(fx.core)
			if err != nil {
				t.Fatal(err)
			}
			artifacts := fx.readArtifacts(t, suite)
			evidence := fx.evidence
			index := fx.index
			tc.mutate(&evidence, &index, artifacts)
			if _, _, err := validatePairedEvidenceLineage(suite, fx.snapshot, evidence, fx.policy, index, artifacts); err == nil {
				t.Fatal("malformed evidence or index lineage was accepted")
			}
		})
	}
}

func TestPairedFusionPreflightRejectsByteAndMechanicalDrift(t *testing.T) {
	t.Run("query vector differs across arms", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		signal := fx.challengerSignal
		signal.QueryVector = []int16{denseQuantizationScale, 0}
		resealQuerySignals(&signal)
		fx.core.Cases[0].Signals.Challenger = fx.replaceSignal(t, fx.core.Cases[0].Signals.Challenger, signal)
		writeCanonical(t, fx.corePath, fx.core)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil || !strings.Contains(err.Error(), "query-signal semantics differ") {
			t.Fatalf("cross-arm query vector drift did not fail closed: %v", err)
		}
	})

	t.Run("snapshot core identity", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		snapshot := fx.snapshot
		snapshot.TreeSHA256 = "sha256:" + strings.Repeat("f", 64)
		fx.core.SnapshotManifest = fx.replaceBoundDocument(t, fx.snapshotRoot, fx.core.SnapshotManifest, snapshot, snapshot.ManifestID)
		writeCanonical(t, fx.corePath, fx.core)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil || !strings.Contains(err.Error(), "snapshot identity mismatch") {
			t.Fatalf("snapshot core tamper did not fail closed: %v", err)
		}
	})

	t.Run("revoked admission", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		policy := fx.policy
		policy.State = "revoked"
		coreBytes, _ := json.Marshal(policy.AdmissionPolicyCore)
		policy.PolicyPayloadSHA256 = digestBytes(coreBytes)
		policy.PolicyID = "retrieval-admission:" + policy.PolicyPayloadSHA256
		fx.core.AdmissionPolicy = fx.replaceBoundDocument(t, fx.outputRoot, fx.core.AdmissionPolicy, policy, policy.PolicyID)
		writeCanonical(t, fx.corePath, fx.core)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil || !strings.Contains(err.Error(), "retrieval lineage validation failed") {
			t.Fatalf("revoked admission did not fail closed: %v", err)
		}
	})

	t.Run("admission source identity", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		policy := fx.policy
		policy.SourceID = "src:github:unrelated/project"
		policy.ComponentID = "cmp:github:unrelated/project"
		coreBytes, _ := json.Marshal(policy.AdmissionPolicyCore)
		policy.PolicyPayloadSHA256 = digestBytes(coreBytes)
		policy.PolicyID = "retrieval-admission:" + policy.PolicyPayloadSHA256
		fx.core.AdmissionPolicy = fx.replaceBoundDocument(t, fx.outputRoot, fx.core.AdmissionPolicy, policy, policy.PolicyID)
		writeCanonical(t, fx.corePath, fx.core)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil || !strings.Contains(err.Error(), "retrieval lineage validation failed") {
			t.Fatalf("admission source/component drift did not fail closed: %v", err)
		}
	})

	t.Run("source range", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		core := fx.core
		core.Cases[0].SourceJudgments[0].Ranges[0].Start = 2
		writeCanonical(t, fx.corePath, core)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil || !strings.Contains(err.Error(), "excerpt mismatch") {
			t.Fatalf("source range drift did not fail closed: %v", err)
		}
	})

	t.Run("candidate bytes", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fx.baselinePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fx.baselinePath, []byte("drift\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil {
			t.Fatal("candidate byte drift did not fail closed")
		}
	})

	t.Run("scorer pin", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		config := fx.prepareConfig(suitePath)
		config.ChallengerScorerHash = "sha256:" + strings.Repeat("f", 64)
		if _, err := PreparePairedFusionRun(config); err == nil {
			t.Fatal("challenger scorer pin drift did not fail closed")
		}
	})

	t.Run("symlinked signal", func(t *testing.T) {
		fx := newPairedFusionTestFixture(t)
		_, suitePath, err := MaterializePairedFusionSuite(fx.corePath, fx.suiteStore)
		if err != nil {
			t.Fatal(err)
		}
		binding := fx.core.Cases[0].Signals.Baseline
		target := filepath.Join(fx.signalRoot, filepath.FromSlash(binding.ObjectPath))
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(fx.root, "outside-signal.json")
		writeCanonical(t, outside, fx.baselineSignal)
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
		if _, err := PreparePairedFusionRun(fx.prepareConfig(suitePath)); err == nil {
			t.Fatal("symlinked signal did not fail closed")
		}
	})
}

func newPairedFusionTestFixture(t *testing.T) *pairedFusionTestFixture {
	t.Helper()
	base := newHybridTestFixtureForProfile(t, bm25fLexicalProfileV11)
	fx := &pairedFusionTestFixture{
		hybridTestFixture: base,
		corePath:          filepath.Join(base.root, "paired-fusion.core.json"), suiteStore: filepath.Join(base.root, "suite-store"),
		signalRoot: filepath.Join(base.root, "signal-store"), snapshotRoot: base.rawRoot,
	}
	fx.baseline = base.hybrid.Manifest
	fx.baselinePath = base.hybrid.ManifestPath
	baselineSignal, _, _ := base.writeSignals(t, "IGNORE alpha", []int16{0, denseQuantizationScale}, map[string]int64{})
	disableReranking(&baselineSignal)
	resealQuerySignals(&baselineSignal)
	fx.baselineSignal = baselineSignal
	baselineSignalBinding := fx.storeSignal(t, baselineSignal)

	base.enableChampionFusion(t, 2, 2)
	challengerSignal, _, _ := base.writeSignals(t, "IGNORE alpha", []int16{0, denseQuantizationScale}, map[string]int64{})
	disableReranking(&challengerSignal)
	resealQuerySignals(&challengerSignal)
	fx.challengerSignal = challengerSignal
	challengerSignalBinding := fx.storeSignal(t, challengerSignal)

	fx.executablePath, _ = os.Executable()
	fx.executableHash = fileDigest(fx.executablePath)
	executableInfo, err := os.Stat(fx.executablePath)
	if err != nil {
		t.Fatal(err)
	}
	fx.executableSize = executableInfo.Size()

	snapshotBinding := fx.copyArtifact(t, fx.snapshotPath, fx.snapshotRoot, "manifests", fx.snapshot.ManifestPayloadSHA256, fx.snapshot.ManifestID)
	evidenceBinding := fx.copyArtifact(t, fx.evidenceManifestPath, fx.evidenceRoot, "evidence-manifests", fx.evidence.ManifestPayloadSHA256, fx.evidence.ManifestID)
	policyBinding := fx.copyArtifact(t, fx.policyPath, fx.outputRoot, "admission-policies", fx.policy.PolicyPayloadSHA256, fx.policy.PolicyID)
	lexicalBinding := fx.bindingForPath(t, fx.lexical.ManifestPath, fx.outputRoot, fx.lexical.Manifest.ManifestID)
	indexPath := filepath.Join(fx.outputRoot, filepath.FromSlash(fx.lexical.Manifest.LexicalIndexPath))
	indexBinding := fx.bindingForPath(t, indexPath, fx.outputRoot, fx.index.IndexID)
	densePath := filepath.Join(fx.outputRoot, filepath.FromSlash(base.hybrid.Manifest.DenseArtifactPath))
	denseBinding := fx.bindingForPath(t, densePath, fx.outputRoot, fx.dense.ArtifactID)
	baselineBinding := fx.bindingForPath(t, fx.baselinePath, fx.outputRoot, fx.baseline.ManifestID)
	challengerBinding := fx.bindingForPath(t, base.hybrid.ManifestPath, fx.outputRoot, base.hybrid.Manifest.ManifestID)
	profileBinding := fx.bindingForPath(t, base.fusionPath, fx.outputRoot, base.fusionProfile.ProfileID)

	source := fx.snapshot.Files[0]
	spans := append([]EvidenceSpan(nil), fx.evidence.Files[0].Spans...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].SpanID < spans[j].SpanID })
	spanBindings := make([]PairedFusionSpanBinding, 0, len(spans))
	mapped := make([]string, 0, len(spans))
	relevance := make([]RetrievalRelevanceJudgment, 0, len(spans))
	for _, span := range spans {
		spanBindings = append(spanBindings, PairedFusionSpanBinding{
			SpanID: span.SpanID, SourcePath: source.RelativePath, RawLineStart: span.RawLineStart, RawLineEnd: span.RawLineEnd,
			PayloadSHA256: span.PayloadSHA256, PayloadByteSize: span.ByteSize, PayloadObjectPath: span.ObjectPath,
		})
		mapped = append(mapped, span.SpanID)
		relevance = append(relevance, RetrievalRelevanceJudgment{SpanID: span.SpanID, Grade: 3})
	}
	raw, _ := os.ReadFile(filepath.Join(fx.snapshotRoot, filepath.FromSlash(source.ObjectPath)))
	excerpt, err := pairedFusionExcerpt(raw, []PairedFusionLineRange{{Start: 1, End: 2}})
	if err != nil {
		t.Fatal(err)
	}
	fx.core = PairedFusionSuiteCore{
		SchemaVersion: retrievalSchemaVersion, SuiteKind: pairedFusionSuiteKind, State: "frozen", ExecutionState: pairedFusionExecutionState,
		Name: "generic-test-lane", Revision: "test-1", FrozenAt: fx.policy.EvaluatedAt,
		Target:           PairedFusionTarget{ComparisonMode: "paired_fusion_profiles", BaselineProfile: hybridFusionProfile, ChallengerProfile: championFusionProfile, MetricAlgorithm: metricAlgorithm, MetricScale: retrievalMetricScale, CutoffK: 2, Limit: 2, FusionWindow: 2, RerankWindow: 0, MaxExcerptBytes: 4096},
		ComparisonGates:  PairedFusionComparisonGates{MinimumRecallGainPPM: 0, MinimumMRRGainPPM: 0, MinimumNDCGGainPPM: 1, MaximumProtectedRegression: 0, MinimumCasesPerClass: 1, RequiredGates: append([]string(nil), pairedFusionRequiredGates...)},
		ResourceLimits:   PairedFusionResourceLimits{MaxExecutions: 2, MaxScannedDocuments: 4, MaxInputDocumentsPerExecution: 2, MaxInputBytesPerExecution: 1 << 20, MaxReturnedResults: 4, MaxReturnedExcerptBytes: 16_384, MaxQuerySignalBytes: 1 << 20, MaxWallMillisecondsPerExecution: 20_000, MaxCPUMillisecondsPerExecution: 20_000, MaxPeakRSSBytes: 1 << 30},
		SnapshotManifest: snapshotBinding, EvidenceManifest: evidenceBinding, AdmissionPolicy: policyBinding,
		LexicalCandidate: lexicalBinding, LexicalIndex: indexBinding, DenseArtifact: denseBinding,
		Arms: []PairedFusionArmBinding{
			{Role: pairedFusionBaselineRole, FusionProfile: hybridFusionProfile, HybridCandidate: baselineBinding, Scorer: PairedFusionScorerBinding{ScorerID: pairedFusionBaselineID, ScorerRevision: pairedFusionBaselineRev, ExecutableSHA256: fx.executableHash, ExecutableByteSize: fx.executableSize}},
			{Role: pairedFusionChallengerRole, FusionProfile: championFusionProfile, HybridCandidate: challengerBinding, Scorer: PairedFusionScorerBinding{ScorerID: championFusionScorerID, ScorerRevision: championFusionScorerRevision, ExecutableSHA256: fx.executableHash, ExecutableByteSize: fx.executableSize}, FusionProfileArtifact: &profileBinding},
		},
		Sources: []PairedFusionSourceBinding{{SourcePath: source.RelativePath, SourceCommitSHA: fx.snapshot.Source.SourceRevision, RawSHA256: source.SHA256, RawByteSize: source.Size, RawObjectPath: source.ObjectPath}},
		Spans:   spanBindings,
		Cases: []PairedFusionCase{{
			CaseID: "generic-01", Class: "generic", Query: "IGNORE alpha", QuerySHA256: digestBytes([]byte("IGNORE alpha")), ProtectedClass: true,
			InjectionMarker: "IGNORE", InjectionMarkerSHA256: digestBytes([]byte("IGNORE")), InjectionMarkerLocation: "query",
			Signals:            PairedFusionCaseSignals{Baseline: baselineSignalBinding, Challenger: challengerSignalBinding},
			SourceJudgments:    []PairedFusionSourceJudgment{{SourcePath: source.RelativePath, SourceCommitSHA: fx.snapshot.Source.SourceRevision, Ranges: []PairedFusionLineRange{{Start: 1, End: 2}}, ExcerptSHA256: digestBytes(excerpt), Grade: 3, MappedSpanIDs: mapped}},
			RelevanceJudgments: relevance,
		}},
	}
	writeCanonical(t, fx.corePath, fx.core)
	return fx
}

func (fx *pairedFusionTestFixture) storeSignal(t *testing.T, signal QuerySignalArtifact) PairedFusionArtifactBinding {
	t.Helper()
	data, err := marshalDocument(signal)
	if err != nil {
		t.Fatal(err)
	}
	relative, _ := contentObjectPath("query-signals", signal.ArtifactPayloadSHA256)
	if err := writeImmutableObject(fx.signalRoot, relative, data); err != nil {
		t.Fatal(err)
	}
	return PairedFusionArtifactBinding{ArtifactID: signal.ArtifactID, DocumentSHA256: digestBytes(data), ObjectPath: relative, ByteSize: int64(len(data))}
}

func (fx *pairedFusionTestFixture) replaceSignal(t *testing.T, binding PairedFusionArtifactBinding, signal QuerySignalArtifact) PairedFusionArtifactBinding {
	t.Helper()
	return fx.replaceBoundDocument(t, fx.signalRoot, binding, signal, signal.ArtifactID)
}

func (fx *pairedFusionTestFixture) replaceBoundDocument(t *testing.T, root string, binding PairedFusionArtifactBinding, value any, artifactID string) PairedFusionArtifactBinding {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(binding.ObjectPath))
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	writeCanonical(t, target, value)
	if err := os.Chmod(target, 0o444); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	binding.ArtifactID = artifactID
	binding.DocumentSHA256 = fileDigest(target)
	binding.ByteSize = info.Size()
	return binding
}

func (fx *pairedFusionTestFixture) copyArtifact(t *testing.T, sourcePath, root, directory, payloadDigest, artifactID string) PairedFusionArtifactBinding {
	t.Helper()
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	relative, _ := contentObjectPath(directory, payloadDigest)
	if err := writeImmutableObject(root, relative, data); err != nil {
		t.Fatal(err)
	}
	return PairedFusionArtifactBinding{ArtifactID: artifactID, DocumentSHA256: digestBytes(data), ObjectPath: relative, ByteSize: int64(len(data))}
}

func (fx *pairedFusionTestFixture) bindingForPath(t *testing.T, filePath, root, artifactID string) PairedFusionArtifactBinding {
	t.Helper()
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(root, filePath)
	if err != nil {
		t.Fatal(err)
	}
	return PairedFusionArtifactBinding{ArtifactID: artifactID, DocumentSHA256: digestBytes(data), ObjectPath: filepath.ToSlash(relative), ByteSize: int64(len(data))}
}

func (fx *pairedFusionTestFixture) prepareConfig(suitePath string) PreparePairedFusionRunConfig {
	return PreparePairedFusionRunConfig{
		SuitePath: suitePath, SuiteHash: fileDigest(suitePath), RetrievalStoreRoot: fx.outputRoot,
		SnapshotStoreRoot: fx.snapshotRoot, EvidenceStoreRoot: fx.evidenceRoot, QuerySignalStoreRoot: fx.signalRoot,
		BaselineScorerPath: fx.executablePath, BaselineScorerHash: fx.executableHash,
		ChallengerScorerPath: fx.executablePath, ChallengerScorerHash: fx.executableHash,
	}
}

func (fx *pairedFusionTestFixture) readArtifacts(t *testing.T, suite PairedFusionSuite) map[string][]byte {
	t.Helper()
	roots := pairedFusionRootSet{retrieval: fx.outputRoot, snapshot: fx.snapshotRoot, evidence: fx.evidenceRoot, signals: fx.signalRoot}
	artifacts := make(map[string][]byte)
	for _, input := range pairedFusionReadPlan(suite, roots) {
		data, err := readPairedArtifact(input.root, input.binding)
		if err != nil {
			t.Fatalf("read %s: %v", input.label, err)
		}
		artifacts[input.label] = data
	}
	return artifacts
}

func resealHybridCandidate(candidate *HybridCandidateManifest) {
	coreBytes, _ := json.Marshal(candidate.HybridCandidateManifestCore)
	candidate.ManifestPayloadSHA256 = digestBytes(coreBytes)
	candidate.ManifestID = "hybrid-retrieval-candidate:" + candidate.ManifestPayloadSHA256
}

func TestPairedFusionWireHasNoEvaluationOrAuthorityFields(t *testing.T) {
	fx := newPairedFusionTestFixture(t)
	data, err := json.Marshal(fx.core)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"evaluation_results", "evaluation_metrics", "quality_receipt", "generation", "promotable", "serving_eligible", "current_eligible"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("paired fusion suite gained forbidden authority/output field %q", forbidden)
		}
	}
}
