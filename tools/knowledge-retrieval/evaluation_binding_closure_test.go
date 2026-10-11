package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	closureAcceptanceDir  = "../../knowledge/registry/acceptance/p1-src-03"
	closureEvaluationTime = "2026-07-20T13:00:00Z"
	frozenRequirementsID  = "retrieval-binding-requirements:sha256:8c58e1e9cfe2cef672f104cfc88ab0229ba666e829d94188cda277b6a4e87f49"
)

// closureFixture copies the committed admitted-artifacts envelope and its nine
// referenced manifests into a writable temp tree so negative cases can tamper
// freely without touching the committed evidence.
func closureFixture(t *testing.T) (admittedPath, root string) {
	t.Helper()
	root = t.TempDir()
	raw, err := os.ReadFile(filepath.Join(closureAcceptanceDir, "admitted-artifacts.json"))
	if err != nil {
		t.Fatalf("read admitted-artifacts: %v", err)
	}
	var env MultidomainBindingClosureAdmittedArtifacts
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode admitted-artifacts: %v", err)
	}
	for _, a := range env.Authorities {
		for _, art := range []MultidomainBindingClosureAdmittedArtifact{a.SnapshotManifest, a.EvidenceManifest, a.AdmissionPolicy} {
			b, err := os.ReadFile(filepath.Join(closureAcceptanceDir, art.Path))
			if err != nil {
				t.Fatalf("read artifact %s: %v", art.Path, err)
			}
			out := filepath.Join(root, filepath.FromSlash(art.Path))
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(out, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	admittedPath = filepath.Join(root, "admitted-artifacts.json")
	if err := os.WriteFile(admittedPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return admittedPath, root
}

func materializeClosure(t *testing.T, admittedPath string) (MultidomainBindingClosureManifest, string) {
	t.Helper()
	manifest, path, err := MaterializeMultidomainBindingClosure(
		multidomainCorePath, multidomainFreezePath, p1MultidomainFreezeDocumentSHA256,
		multidomainFixtureRoot, t.TempDir(), admittedPath, closureEvaluationTime, "",
	)
	if err != nil {
		t.Fatalf("materialize closure: %v", err)
	}
	return manifest, path
}

// rewriteAdmitted applies mutate to the decoded envelope and writes it back in
// strict-canonical form (struct field order, indent 2, trailing newline).
func rewriteAdmitted(t *testing.T, admittedPath string, mutate func(*MultidomainBindingClosureAdmittedArtifacts)) {
	t.Helper()
	raw, err := os.ReadFile(admittedPath)
	if err != nil {
		t.Fatal(err)
	}
	var env MultidomainBindingClosureAdmittedArtifacts
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	mutate(&env)
	canonical, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(admittedPath, append(canonical, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMultidomainBindingClosureDeterministicNineClose(t *testing.T) {
	admitted, _ := closureFixture(t)
	freezeBefore, err := os.ReadFile(multidomainFreezePath)
	if err != nil {
		t.Fatal(err)
	}

	first, firstPath := materializeClosure(t, admitted)

	if first.ClosedGapCount != 9 || first.BlockingGapCount != 29 || first.GapCount != 38 {
		t.Fatalf("gaps = %d closed / %d blocking / %d total; want 9/29/38",
			first.ClosedGapCount, first.BlockingGapCount, first.GapCount)
	}
	closed := 0
	for _, g := range first.Gaps {
		if g.Blocking {
			continue
		}
		closed++
		if g.Scope != "source_authority" {
			t.Fatalf("non-blocking gap has scope %q; only source_authority may close", g.Scope)
		}
	}
	if closed != 9 {
		t.Fatalf("%d gaps flipped non-blocking; want exactly 9", closed)
	}
	if first.State != "blocked" || first.Promotable || first.ExecutionAuthorized || first.Ready {
		t.Fatalf("state=%q promotable=%v execution=%v ready=%v; want blocked/false/false/false",
			first.State, first.Promotable, first.ExecutionAuthorized, first.Ready)
	}
	c := first.Capabilities
	if c.RetrievalAuthorized || c.EvaluationAuthorized || c.SigningAuthorized ||
		c.GenerationAuthorized || c.PointerWriteAuthorized || c.ServingAuthorized {
		t.Fatalf("closure granted an authority capability: %+v", c)
	}
	if !strings.HasPrefix(first.ManifestID, "retrieval-binding-requirements:sha256:") {
		t.Fatalf("manifest id %q lacks the expected prefix", first.ManifestID)
	}
	if first.ManifestID == frozenRequirementsID {
		t.Fatal("successor must be a distinct content address, not the frozen manifest")
	}
	if first.SupersedesManifestID != frozenRequirementsID {
		t.Fatalf("supersedes %q; want the frozen d40db301 manifest", first.SupersedesManifestID)
	}

	// deterministic: an independent run is byte-identical.
	second, secondPath := materializeClosure(t, admitted)
	if first.ManifestID != second.ManifestID {
		t.Fatalf("nondeterministic id: %q vs %q", first.ManifestID, second.ManifestID)
	}
	fb, _ := os.ReadFile(firstPath)
	sb, _ := os.ReadFile(secondPath)
	if !bytes.Equal(fb, sb) {
		t.Fatal("nondeterministic successor bytes")
	}

	// the frozen freeze input is never mutated.
	freezeAfter, err := os.ReadFile(multidomainFreezePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(freezeBefore, freezeAfter) {
		t.Fatal("closure mutated the frozen freeze input")
	}
}

func TestMultidomainBindingClosureFailsClosed(t *testing.T) {
	// wrong frozen requirements target
	t.Run("wrong_requirements_target", func(t *testing.T) {
		admitted, _ := closureFixture(t)
		rewriteAdmitted(t, admitted, func(e *MultidomainBindingClosureAdmittedArtifacts) {
			e.RequirementsManifestID = "retrieval-binding-requirements:sha256:" + strings.Repeat("0", 64)
		})
		if _, _, err := MaterializeMultidomainBindingClosure(multidomainCorePath, multidomainFreezePath,
			p1MultidomainFreezeDocumentSHA256, multidomainFixtureRoot, t.TempDir(), admitted, closureEvaluationTime, ""); err == nil {
			t.Fatal("expected failure when admitted artifacts do not target the frozen requirements manifest")
		}
	})

	// only two authorities: cannot collapse to fewer than the three frozen authorities
	t.Run("collapsed_authorities", func(t *testing.T) {
		admitted, _ := closureFixture(t)
		rewriteAdmitted(t, admitted, func(e *MultidomainBindingClosureAdmittedArtifacts) {
			e.Authorities = e.Authorities[:2]
		})
		if _, _, err := MaterializeMultidomainBindingClosure(multidomainCorePath, multidomainFreezePath,
			p1MultidomainFreezeDocumentSHA256, multidomainFixtureRoot, t.TempDir(), admitted, closureEvaluationTime, ""); err == nil {
			t.Fatal("expected failure when fewer than three source authorities are admitted")
		}
	})

	// bad freeze caller pin (missing sha256: prefix)
	t.Run("invalid_freeze_pin", func(t *testing.T) {
		admitted, _ := closureFixture(t)
		bare := strings.TrimPrefix(p1MultidomainFreezeDocumentSHA256, "sha256:")
		if _, _, err := MaterializeMultidomainBindingClosure(multidomainCorePath, multidomainFreezePath,
			bare, multidomainFixtureRoot, t.TempDir(), admitted, closureEvaluationTime, ""); err == nil {
			t.Fatal("expected failure for a freeze pin without the sha256: prefix")
		}
	})

	// a mutated admitted manifest no longer matches its pinned document sha256
	t.Run("mutated_admitted_artifact_bytes", func(t *testing.T) {
		admitted, root := closureFixture(t)
		var env MultidomainBindingClosureAdmittedArtifacts
		raw, _ := os.ReadFile(admitted)
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(env.Authorities[0].EvidenceManifest.Path))
		b, _ := os.ReadFile(target)
		if err := os.WriteFile(target, append(b, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		manifest, _, err := MaterializeMultidomainBindingClosure(multidomainCorePath, multidomainFreezePath,
			p1MultidomainFreezeDocumentSHA256, multidomainFixtureRoot, t.TempDir(), admitted, closureEvaluationTime, "")
		// Fail-closed: a mismatched document sha256 must not close its gap — either
		// the run errors or the tampered authority's gap stays blocking (closed < 9).
		if err == nil && manifest.ClosedGapCount >= 9 {
			t.Fatalf("tampered artifact still closed all 9 gaps (closed=%d); a mismatched document sha256 must leave its gap blocking", manifest.ClosedGapCount)
		}
	})
}
