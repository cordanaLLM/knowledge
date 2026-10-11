package main

import (
	"os"
	"path/filepath"
	"testing"
)

func loadScorerBlindFreezeCore(t *testing.T) ScorerBlindEvaluationFreezeCore {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "scorer-blind-multidomain-v1", "suite-freeze.core.json"))
	if err != nil {
		t.Fatal(err)
	}
	var core ScorerBlindEvaluationFreezeCore
	if err := decodeStrictCanonical(data, &core); err != nil {
		t.Fatal(err)
	}
	return core
}

func TestScorerBlindMultidomainFreezeMaterializesExactCommittedEvidence(t *testing.T) {
	root := filepath.Join("testdata", "scorer-blind-multidomain-v1")
	freeze, generatedPath, err := MaterializeScorerBlindEvaluationFreeze(
		filepath.Join(root, "suite-freeze.core.json"),
		root,
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if freeze.FreezeID != p1RetiredMultidomainFreezeID {
		t.Fatalf("unexpected freeze identity %s", freeze.FreezeID)
	}
	if freeze.FreezeID == p1MultidomainFreezeID {
		t.Fatal("retired v1 freeze is still the accepted acceptance anchor")
	}
	generated, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join(root, "materialized", "evaluation-freezes", "sha256", "a0", "a0fd2cb1067e0b92122e3478632831e8822b5b34f63fa841d3bf60aa65d2de1b.json")
	want, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	if string(generated) != string(want) {
		t.Fatal("materialized freeze differs from the committed content-addressed object")
	}
	for _, span := range freeze.Spans {
		payload, _, _, err := exactInclusiveLineRange(
			mustReadFreezeSource(t, root, freeze.Sources, span.SourceKey),
			span.RawLineStart,
			span.RawLineEnd,
		)
		if err != nil {
			t.Fatal(err)
		}
		committedPayload, err := os.ReadFile(filepath.Join(root, "materialized", filepath.FromSlash(span.PayloadObjectPath)))
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != string(committedPayload) {
			t.Fatalf("committed payload for %s differs from exact source lines", span.SpanID)
		}
	}
}

func TestScorerBlindMultidomainFreezeFailsClosedOnLineOrProvenanceDrift(t *testing.T) {
	root := filepath.Join("testdata", "scorer-blind-multidomain-v1")
	core := loadScorerBlindFreezeCore(t)
	core.Spans[0].RawLineEnd++
	if _, _, err := sealScorerBlindEvaluationFreeze(core, root); err == nil {
		t.Fatal("changed source coordinates were accepted")
	}

	core = loadScorerBlindFreezeCore(t)
	core.Provenance.ScorerExecuted = true
	if _, _, err := sealScorerBlindEvaluationFreeze(core, root); err == nil {
		t.Fatal("non-blind provenance was accepted")
	}

	core = loadScorerBlindFreezeCore(t)
	core.BlockedBindingFields = core.BlockedBindingFields[:len(core.BlockedBindingFields)-1]
	if _, _, err := sealScorerBlindEvaluationFreeze(core, root); err == nil {
		t.Fatal("an incomplete exact-binding barrier was accepted")
	}
}

func TestScorerBlindMultidomainFreezeIdentityChangesWithPreResultGate(t *testing.T) {
	root := filepath.Join("testdata", "scorer-blind-multidomain-v1")
	core := loadScorerBlindFreezeCore(t)
	first, _, err := sealScorerBlindEvaluationFreeze(core, root)
	if err != nil {
		t.Fatal(err)
	}
	core.Thresholds[1].MinMRRPPM++
	second, _, err := sealScorerBlindEvaluationFreeze(core, root)
	if err != nil {
		t.Fatal(err)
	}
	if first.FreezeID == second.FreezeID {
		t.Fatal("changed pre-result threshold did not change the immutable freeze identity")
	}
}

func TestScorerBlindMultidomainFreezeV2MaterializesAdjudicatedQrels(t *testing.T) {
	root := filepath.Join("testdata", "scorer-blind-multidomain-v2")
	freeze, generatedPath, err := MaterializeScorerBlindEvaluationFreeze(
		filepath.Join(root, "suite-freeze.core.json"),
		root,
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if freeze.FreezeID != "retrieval-evaluation-freeze:sha256:ddb38ed65dce0a56e6308689b82c085bd1276e3e1f6d48dea68dc792d5d0959d" {
		t.Fatalf("unexpected successor freeze identity %s", freeze.FreezeID)
	}
	// v2 is the operator-accepted acceptance anchor; v1 is retired, not reused.
	if freeze.FreezeID != p1MultidomainFreezeID || freeze.FreezeID == p1RetiredMultidomainFreezeID {
		t.Fatal("accepted freeze constant does not name the v2 successor")
	}
	generated, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join(root, "materialized", "evaluation-freezes", "sha256", "dd", "ddb38ed65dce0a56e6308689b82c085bd1276e3e1f6d48dea68dc792d5d0959d.json")
	want, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	if string(generated) != string(want) {
		t.Fatal("materialized successor freeze differs from the committed content-addressed object")
	}
	// Adjudicated qrels: exactly one grade-3 answer span per case, every span covered once.
	judged := make(map[string]string, len(freeze.Spans))
	for _, frozenCase := range freeze.Cases {
		if len(frozenCase.RelevanceJudgments) != 1 || frozenCase.RelevanceJudgments[0].Grade != 3 {
			t.Fatalf("case %s is not a single grade-3 judgment", frozenCase.CaseID)
		}
		spanID := frozenCase.RelevanceJudgments[0].SpanID
		if prior, exists := judged[spanID]; exists {
			t.Fatalf("span %s is the answer for both %s and %s", spanID, prior, frozenCase.CaseID)
		}
		judged[spanID] = frozenCase.CaseID
	}
	if len(judged) != len(freeze.Spans) {
		t.Fatalf("judged %d spans, freeze binds %d", len(judged), len(freeze.Spans))
	}
}

func mustReadFreezeSource(t *testing.T, root string, sources []ScorerBlindFreezeSource, sourceKey string) []byte {
	t.Helper()
	for _, source := range sources {
		if source.SourceKey == sourceKey {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(source.SourceObjectPath)))
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
	t.Fatalf("missing source %s", sourceKey)
	return nil
}
