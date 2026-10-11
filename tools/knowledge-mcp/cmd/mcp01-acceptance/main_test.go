package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func suiteDirectory(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs(filepath.Join("..", "..", "testdata", "mcp01-acceptance"))
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func TestSuiteFreezeLoadsAndPinsVerify(t *testing.T) {
	suiteDir := suiteDirectory(t)
	freeze, err := loadSuite(suiteDir)
	if err != nil {
		t.Fatalf("frozen suite failed to load: %v", err)
	}
	if freeze.SuiteID != "p1-mcp-01-broker-acceptance" || freeze.Revision != "v1" || freeze.FrozenAt == "" {
		t.Fatalf("frozen suite identity drifted: %#v", freeze)
	}
	if err := verifyFixturePins(suiteDir, freeze); err != nil {
		t.Fatalf("committed fixtures do not match their frozen pins: %v", err)
	}
}

// TestSingleFlippedFixtureByteFailsClosed is the tamper negative control: the
// pin gate every case runs behind must reject one mutated fixture byte.
func TestSingleFlippedFixtureByteFailsClosed(t *testing.T) {
	suiteDir := suiteDirectory(t)
	freeze, err := loadSuite(suiteDir)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := copySuiteTree(suiteDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tampered) })
	if err := verifyFixturePins(tampered, freeze); err != nil {
		t.Fatalf("byte-identical suite copy failed verification: %v", err)
	}
	if err := tamperFile(filepath.Join(tampered, "fixtures", "responses", "alpha-ok.json")); err != nil {
		t.Fatal(err)
	}
	err = verifyFixturePins(tampered, freeze)
	if err == nil || !strings.Contains(err.Error(), "does not match its frozen pin") {
		t.Fatalf("one flipped fixture byte was not detected: %v", err)
	}
}

func TestUnpinnedPlantedFixtureFailsClosed(t *testing.T) {
	suiteDir := suiteDirectory(t)
	freeze, err := loadSuite(suiteDir)
	if err != nil {
		t.Fatal(err)
	}
	planted, err := copySuiteTree(suiteDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(planted) })
	if err := os.WriteFile(filepath.Join(planted, "fixtures", "responses", "planted.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = verifyFixturePins(planted, freeze)
	if err == nil || !strings.Contains(err.Error(), "not pinned by the freeze") {
		t.Fatalf("a planted unpinned fixture was not detected: %v", err)
	}
}

func TestNormalizationReplacesOnlyDeclaredVolatileFields(t *testing.T) {
	normalization := suiteNormalization{
		VolatileFields: []string{"observed_at"},
		Replacement:    "<volatile>",
		WorkspaceToken: "${WORKSPACE}",
	}
	input := map[string]any{
		"observed_at": "2026-08-22T10:00:00Z",
		"pointer_id":  "retrieval-pointer:sha256:abc",
		"message":     "validate /work/space/catalog.json",
		"nested":      []any{map[string]any{"observed_at": "x", "kept": "/work/space/file"}},
	}
	normalized := normalizeValue(input, "/work/space", normalization).(map[string]any)
	if normalized["observed_at"] != "<volatile>" || normalized["pointer_id"] != "retrieval-pointer:sha256:abc" {
		t.Fatalf("volatile-field normalization drifted: %#v", normalized)
	}
	if normalized["message"] != "validate ${WORKSPACE}/catalog.json" {
		t.Fatalf("workspace-path normalization drifted: %#v", normalized["message"])
	}
	nested := normalized["nested"].([]any)[0].(map[string]any)
	if nested["observed_at"] != "<volatile>" || nested["kept"] != "${WORKSPACE}/file" {
		t.Fatalf("nested normalization drifted: %#v", nested)
	}
}

// TestHermeticSuiteIsGreenAndDeterministic builds the real broker binary and
// runs the full frozen suite against it over the live stdio protocol. The
// one-lane-timeout case deliberately rides the broker's fixed 20s lane
// deadline, so this test takes ~25s.
func TestHermeticSuiteIsGreenAndDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("full hermetic acceptance run skipped in -short mode")
	}
	suiteDir := suiteDirectory(t)
	freeze, err := loadSuite(suiteDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFixturePins(suiteDir, freeze); err != nil {
		t.Fatal(err)
	}
	brokerPath := filepath.Join(t.TempDir(), "archeion-knowledge-mcp")
	build := exec.Command("go", "build", "-o", brokerPath, "github.com/cordanaLLM/knowledge/tools/knowledge-mcp")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build broker: %v: %s", err, output)
	}
	outDir := t.TempDir()
	report, err := runHermeticSuite(suiteDir, brokerPath, outDir, freeze)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != len(freeze.Cases) {
		t.Fatalf("suite ran %d of %d cases", len(report.Cases), len(freeze.Cases))
	}
	for _, verdict := range report.Cases {
		if verdict.Verdict != "pass" {
			t.Errorf("case %s: %s (%s)", verdict.CaseID, verdict.Verdict, verdict.Failure)
		}
		if verdict.CaseClass != "one_lane_timeout" && !verdict.DoubleRun {
			t.Errorf("case %s was not double-run", verdict.CaseID)
		}
		transcriptPath := filepath.Join(outDir, verdict.CaseID+".transcript.json")
		transcriptBytes, readErr := os.ReadFile(transcriptPath)
		if readErr != nil {
			t.Errorf("case %s wrote no transcript: %v", verdict.CaseID, readErr)
			continue
		}
		if bytes.Contains(transcriptBytes, []byte("mcp01-acceptance-")) {
			t.Errorf("case %s transcript leaked a workspace path", verdict.CaseID)
		}
	}
}
