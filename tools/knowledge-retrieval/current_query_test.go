package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentQueryUsesOnlySignedEvaluatedCurrentGeneration(t *testing.T) {
	fx := newLifecycleTestFixture(t)
	running, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fx.executable = running
	fx.executableSHA = fileDigest(running)
	fx.writeQuality(t, true)

	generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
	intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
	applied, err := ApplyGenerationTransition(fx.signedApplyConfig(t, intent, &generation))
	if err != nil {
		t.Fatal(err)
	}

	response, err := CurrentQuery(fx.currentQueryConfig("2026-07-16T03:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if response.State != "current" || response.ResultState != "ok" || response.AuthorityState != "evaluated_current" || response.Profile != "lexical" || !response.ServingEligible || !response.CurrentEligible {
		t.Fatalf("current query lost evaluated-current authority: %#v", response)
	}
	if response.PointerID != applied.Pointer.PointerID || response.CurrentGenerationID != generation.Generation.GenerationID || response.CurrentGenerationSHA256 != mustDocumentHash(generation.Generation) || response.CandidateManifestID != generation.Generation.LexicalCandidateID || len(response.Results) == 0 {
		t.Fatalf("current query did not bind the signed pointer and exact generation: %#v", response)
	}
	if response.QualityReportID != generation.Generation.QualityReportID || response.EvaluationDatasetID != generation.Generation.EvaluationDatasetID || response.EvaluationMetricsID != generation.Generation.EvaluationMetricsObjectID {
		t.Fatalf("current query omitted evaluation lineage: %#v", response)
	}
}

func TestCurrentQueryFailsClosedWithoutPointerOrEvaluatedRunningBinary(t *testing.T) {
	t.Run("missing pointer is read only", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		if err := os.MkdirAll(fx.stateRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		response, err := CurrentQuery(fx.currentQueryConfig("2026-07-16T03:00:00Z"))
		if err != nil {
			t.Fatal(err)
		}
		if response.State != "backend_unavailable" || response.ErrorCode != "pointer-missing" || len(response.Results) != 0 {
			t.Fatalf("missing pointer did not fail closed: %#v", response)
		}
		if _, err := os.Stat(filepath.Join(fx.stateRoot, generationLockPath)); !os.IsNotExist(err) {
			t.Fatalf("read-only current query created lifecycle state: %v", err)
		}
	})

	t.Run("different running binary", func(t *testing.T) {
		fx := newLifecycleTestFixture(t)
		generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
		intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
		if _, err := ApplyGenerationTransition(fx.signedApplyConfig(t, intent, &generation)); err != nil {
			t.Fatal(err)
		}
		response, err := CurrentQuery(fx.currentQueryConfig("2026-07-16T03:00:00Z"))
		if err != nil {
			t.Fatal(err)
		}
		if response.State != "backend_unavailable" || response.ErrorCode != "retrieval-executable-mismatch" || len(response.Results) != 0 {
			t.Fatalf("unevaluated running binary was allowed to serve current: %#v", response)
		}
	})
}

func (fx *lifecycleTestFixture) currentQueryConfig(asOf string) CurrentQueryConfig {
	return CurrentQueryConfig{
		StoreRoot: fx.outputRoot, StateRoot: fx.stateRoot, EvidenceStoreRoot: fx.evidenceRoot,
		AdmissionPolicyPath: fx.policyPath, AdmissionPolicyHash: fx.policyHash,
		Query: "alpha", PrincipalScope: "public", AsOf: asOf, Limit: 2, MaxExcerptBytes: 2048,
	}
}
