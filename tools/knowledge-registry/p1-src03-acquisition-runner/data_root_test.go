package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testingTB interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

func knowledgeDataRoot(tb testingTB, purpose string, expectedPaths ...string) string {
	tb.Helper()
	root := strings.TrimSpace(os.Getenv("KNOWLEDGE_DATA_ROOT"))
	if root == "" {
		tb.Skipf("knowledge data root absent: %s", purpose)
		return ""
	}
	checks := expectedPaths
	if len(checks) == 0 {
		checks = []string{"knowledge/registry"}
	}
	for _, rel := range checks {
		target := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(target); err != nil {
			tb.Fatalf("knowledge data root %s lacking expected file: %s", root, target)
			return ""
		}
	}
	return root
}

type spyTB struct {
	failed  bool
	skipped bool
	message string
}

func (s *spyTB) Helper() {}

func (s *spyTB) Skipf(format string, args ...any) {
	s.skipped = true
	s.message = fmt.Sprintf(format, args...)
}

func (s *spyTB) Fatalf(format string, args ...any) {
	s.failed = true
	s.message = fmt.Sprintf(format, args...)
}

func TestKnowledgeDataRootPlantedUnsetSkipsWithPrefix(t *testing.T) {
	for _, envVal := range []string{"", "   "} {
		t.Setenv("KNOWLEDGE_DATA_ROOT", envVal)
		spy := &spyTB{}
		got := knowledgeDataRoot(spy, "planted unset check")
		if got != "" {
			t.Fatalf("expected empty root on unset, got %q", got)
		}
		if !spy.skipped || spy.failed {
			t.Fatalf("expected skip without failure, got skipped=%v failed=%v", spy.skipped, spy.failed)
		}
		const wantPrefix = "knowledge data root absent:"
		if !strings.HasPrefix(spy.message, wantPrefix) {
			t.Fatalf("skip message %q missing prefix %q", spy.message, wantPrefix)
		}
		if !strings.Contains(spy.message, "planted unset check") {
			t.Fatalf("skip message %q missing purpose", spy.message)
		}
	}
}

func TestKnowledgeDataRootPlantedEmptyTempDirFails(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("KNOWLEDGE_DATA_ROOT", emptyDir)
	spy := &spyTB{}
	got := knowledgeDataRoot(spy, "planted empty check", "knowledge/registry")
	if got != "" {
		t.Fatalf("expected empty root on failure, got %q", got)
	}
	if !spy.failed || spy.skipped {
		t.Fatalf("expected fatal failure without skip, got failed=%v skipped=%v", spy.failed, spy.skipped)
	}
	if !strings.Contains(spy.message, emptyDir) {
		t.Fatalf("fatal message %q missing empty dir path %s", spy.message, emptyDir)
	}
}

func TestKnowledgeDataRootPlantedTempDirWithFixturesPasses(t *testing.T) {
	tempDir := t.TempDir()
	fixtureRel := filepath.Join("knowledge", "registry", "acceptance", "fixture.json")
	fullPath := filepath.Join(tempDir, fixtureRel)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KNOWLEDGE_DATA_ROOT", tempDir)
	spy := &spyTB{}
	got := knowledgeDataRoot(spy, "planted fixture check", fixtureRel)
	if spy.failed || spy.skipped {
		t.Fatalf("expected success without fail or skip, got failed=%v skipped=%v msg=%s", spy.failed, spy.skipped, spy.message)
	}
	if got != tempDir {
		t.Fatalf("got root %q, want %q", got, tempDir)
	}
}
