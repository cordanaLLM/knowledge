package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	snapshotBin string
	evidenceBin string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "adapter-compilers-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	snapshotBin = filepath.Join(dir, "knowledge-snapshot")
	evidenceBin = filepath.Join(dir, "knowledge-evidence")
	if err := buildBinary("../knowledge-snapshot", snapshotBin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	if err := buildBinary("../knowledge-evidence", evidenceBin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func buildBinary(moduleDir, output string) error {
	abs, err := filepath.Abs(moduleDir)
	if err != nil {
		return err
	}
	command := exec.Command("go", "build", "-o", output, ".")
	command.Dir = abs
	if out, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %v: %s", moduleDir, err, out)
	}
	return nil
}

func absPath(t *testing.T, relative string) string {
	t.Helper()
	abs, err := filepath.Abs(relative)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		ReceiptPath:  absPath(t, filepath.Join("testdata", "acquisition", "receipt.json")),
		ProposalPath: absPath(t, filepath.Join("testdata", "acquisition", "proposal.json")),
		CASRoot:      absPath(t, filepath.Join("..", "knowledge-retrieval", "testdata", "scorer-blind-multidomain-v1", "source-blobs")),
		SnapshotBin:  snapshotBin,
		EvidenceBin:  evidenceBin,
		WorkRoot:     t.TempDir(),
	}
}

func loadReceipt(t *testing.T, cfg Config) acquisitionDocument {
	t.Helper()
	receipt, err := loadAcquisition(cfg.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

// TestAdaptEmitsDistinctAuthoritiesDeterministically covers the two headline
// invariants: three authorities produce three distinct, non-aliasing snapshot
// and evidence manifests, and two fully independent runs are byte-identical.
func TestAdaptEmitsDistinctAuthoritiesDeterministically(t *testing.T) {
	first := testConfig(t)
	first.OutRoot = filepath.Join(t.TempDir(), "out-a")
	resultsA, err := Adapt(first)
	if err != nil {
		t.Fatalf("first Adapt() error = %v", err)
	}
	if len(resultsA) != 3 {
		t.Fatalf("authorities = %d, want 3", len(resultsA))
	}

	second := testConfig(t)
	second.OutRoot = filepath.Join(t.TempDir(), "out-b")
	resultsB, err := Adapt(second)
	if err != nil {
		t.Fatalf("second Adapt() error = %v", err)
	}

	snapshotIDs := make(map[string]struct{})
	evidenceIDs := make(map[string]struct{})
	spanIDs := make(map[string]string)
	occurrenceIDs := make(map[string]string)
	wantComponents := map[string]bool{
		"cmp:github:cilium/cilium":         false,
		"cmp:github:golang/go":             false,
		"cmp:github:kubernetes/kubernetes": false,
	}
	for index, result := range resultsA {
		if !strings.HasPrefix(result.SnapshotManifestID, "snapshot-manifest:sha256:") ||
			!strings.HasPrefix(result.EvidenceManifestID, "evidence-manifest:sha256:") {
			t.Fatalf("authority %s ids are not content-addressed: %+v", result.AuthorityID, result)
		}
		if _, seen := snapshotIDs[result.SnapshotManifestID]; seen {
			t.Fatalf("snapshot manifest id reused across authorities: %s", result.SnapshotManifestID)
		}
		if _, seen := evidenceIDs[result.EvidenceManifestID]; seen {
			t.Fatalf("evidence manifest id reused across authorities: %s", result.EvidenceManifestID)
		}
		snapshotIDs[result.SnapshotManifestID] = struct{}{}
		evidenceIDs[result.EvidenceManifestID] = struct{}{}
		if _, ok := wantComponents[result.ComponentID]; !ok {
			t.Fatalf("unexpected component %s", result.ComponentID)
		}
		wantComponents[result.ComponentID] = true

		evidence := readEvidenceManifest(t, result.EvidenceManifestPath)
		if evidence.TrustEnvelope.EnvelopeKind != "untrusted_evidence_content" {
			t.Fatalf("authority %s evidence envelope = %q, want inert untrusted_evidence_content", result.AuthorityID, evidence.TrustEnvelope.EnvelopeKind)
		}
		if evidence.InputSnapshotID == "" || evidence.SpanCount == 0 {
			t.Fatalf("authority %s evidence manifest is empty: %+v", result.AuthorityID, evidence)
		}
		for _, file := range evidence.Files {
			if prior, seen := occurrenceIDs[file.OccurrenceID]; seen {
				t.Fatalf("occurrence %s reused by %s and %s", file.OccurrenceID, prior, result.AuthorityID)
			}
			occurrenceIDs[file.OccurrenceID] = result.AuthorityID
			for _, span := range file.Spans {
				if prior, seen := spanIDs[span.SpanID]; seen {
					t.Fatalf("span %s reused by %s and %s", span.SpanID, prior, result.AuthorityID)
				}
				spanIDs[span.SpanID] = result.AuthorityID
			}
		}

		other := resultsB[index]
		if result.SnapshotManifestID != other.SnapshotManifestID || result.EvidenceManifestID != other.EvidenceManifestID {
			t.Fatalf("authority %s ids not reproduced: %+v vs %+v", result.AuthorityID, result, other)
		}
	}
	for component, seen := range wantComponents {
		if !seen {
			t.Fatalf("component %s missing from results", component)
		}
	}
	assertTreesEqual(t, first.OutRoot, second.OutRoot)
}

// TestSourceSpecCrossBoundToAcquisition proves every derived source-spec file
// digest, size, version and commit equals the acquisition receipt fact.
func TestSourceSpecCrossBoundToAcquisition(t *testing.T) {
	cfg := testConfig(t)
	receipt := loadReceipt(t, cfg)
	for _, target := range receipt.Targets {
		spec := buildSourceSpec(target)
		if spec.SourceRevision != target.ResolvedCommitSHA1 {
			t.Fatalf("%s revision = %q, want %q", target.AuthorityID, spec.SourceRevision, target.ResolvedCommitSHA1)
		}
		if !strings.HasSuffix(spec.ComponentVersionID, "@"+target.ComponentVersion) || spec.ResolvedVersion != target.ComponentVersion {
			t.Fatalf("%s version binding is wrong: %+v", target.AuthorityID, spec)
		}
		if !strings.Contains(spec.CanonicalURI, target.ResolvedCommitSHA1) {
			t.Fatalf("%s canonical uri does not bind the commit: %s", target.AuthorityID, spec.CanonicalURI)
		}
		byPath := make(map[string]acquisitionFile, len(target.Files))
		for _, file := range target.Files {
			byPath[file.Path] = file
		}
		if len(spec.Files) != len(target.Files) {
			t.Fatalf("%s file count = %d, want %d", target.AuthorityID, len(spec.Files), len(target.Files))
		}
		for _, specFile := range spec.Files {
			acq, ok := byPath[specFile.RelativePath]
			if !ok {
				t.Fatalf("%s spec file %s absent from receipt", target.AuthorityID, specFile.RelativePath)
			}
			if specFile.SHA256 != acq.RawSHA256 || specFile.Size != acq.Bytes {
				t.Fatalf("%s file %s not cross-bound: spec(%s,%d) receipt(%s,%d)",
					target.AuthorityID, specFile.RelativePath, specFile.SHA256, specFile.Size, acq.RawSHA256, acq.Bytes)
			}
		}
	}
}

func TestFailClosedRecursiveStoreOverlap(t *testing.T) {
	cfg := testConfig(t)
	receipt := loadReceipt(t, cfg)
	root := t.TempDir()
	bundle, err := prepareBundle(cfg, receipt.Targets[0], receipt.ReceiptID, "acquisition-proposal", root)
	if err != nil {
		t.Fatal(err)
	}
	// Nest the snapshot store inside the mirror root to force the frozen
	// recursive-overlap guard, which must refuse without writing any manifest.
	bundle.snapshotStore = filepath.Join(bundle.mirrorBase, filepath.FromSlash(bundle.spec.MirrorPath), "generated-store")
	if _, err := runSnapshotCompile(cfg.SnapshotBin, bundle); err == nil {
		t.Fatal("snapshot compile accepted a store overlapping the mirror")
	}
	if _, statErr := os.Stat(filepath.Join(bundle.snapshotStore, "manifests")); statErr == nil {
		t.Fatal("recursive overlap still produced a manifest tree")
	}
}

func TestFailClosedSymlinkMirror(t *testing.T) {
	cfg := testConfig(t)
	receipt := loadReceipt(t, cfg)
	root := t.TempDir()
	bundle, err := prepareBundle(cfg, receipt.Targets[0], receipt.ReceiptID, "acquisition-proposal", root)
	if err != nil {
		t.Fatal(err)
	}
	mirrorRoot := filepath.Join(bundle.mirrorBase, filepath.FromSlash(bundle.spec.MirrorPath))
	victim := filepath.Join(mirrorRoot, filepath.FromSlash(bundle.spec.Files[0].RelativePath))
	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(external, []byte("outside the mirror\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, victim); err != nil {
		t.Fatal(err)
	}
	if _, err := runSnapshotCompile(cfg.SnapshotBin, bundle); err == nil {
		t.Fatal("snapshot compile accepted a symlinked mirror file")
	}
	assertQuarantineCode(t, bundle.snapshotStore, "symlink_rejected")
}

func TestFailClosedManifestTamper(t *testing.T) {
	cfg := testConfig(t)
	receipt := loadReceipt(t, cfg)
	root := t.TempDir()
	bundle, err := prepareBundle(cfg, receipt.Targets[0], receipt.ReceiptID, "acquisition-proposal", root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := runSnapshotCompile(cfg.SnapshotBin, bundle)
	if err != nil {
		t.Fatalf("snapshot compile failed: %v", err)
	}
	tampered := filepath.Join(root, "tampered-manifest.json")
	original, err := os.ReadFile(snapshot.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one payload byte without touching the declared content-address.
	mutated := strings.Replace(string(original), `"file_count": 2`, `"file_count": 3`, 1)
	if mutated == string(original) {
		t.Fatal("snapshot manifest fixture lacked the expected file_count field")
	}
	if err := os.WriteFile(tampered, []byte(mutated), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runEvidenceCompile(cfg.EvidenceBin, bundle, tampered, bundle.allowedSignersPath); err == nil {
		t.Fatal("evidence compile accepted a tampered snapshot manifest")
	}
	assertQuarantineCode(t, bundle.evidenceStore, "manifest_payload_tampered")
}

func TestFailClosedTrustRootMismatch(t *testing.T) {
	cfg := testConfig(t)
	receipt := loadReceipt(t, cfg)
	root := t.TempDir()
	bundle, err := prepareBundle(cfg, receipt.Targets[0], receipt.ReceiptID, "acquisition-proposal", root)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := runSnapshotCompile(cfg.SnapshotBin, bundle)
	if err != nil {
		t.Fatalf("snapshot compile failed: %v", err)
	}
	// A same-shape allowed_signers carrying a different key must not verify
	// against the review CAS trust-policy copy the snapshot manifest binds.
	foreign := filepath.Join(root, "foreign_allowed_signers")
	trusted, err := os.ReadFile(bundle.allowedSignersPath)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), trusted...)
	keyByte := len(mutated) - 8 // inside the base64 key, before the trailing newline
	if mutated[keyByte] == 'A' {
		mutated[keyByte] = 'B'
	} else {
		mutated[keyByte] = 'A'
	}
	if err := os.WriteFile(foreign, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runEvidenceCompile(cfg.EvidenceBin, bundle, snapshot.ManifestPath, foreign); err == nil {
		t.Fatal("evidence compile accepted a mismatched trust root")
	}
	assertQuarantineCode(t, bundle.evidenceStore, "review_trust_root_mismatch")
}

// TestFailClosedForgedReview substitutes for the standing-admit "backdated
// decision" case (not applicable to the plain reviewed-bundle path): a forged
// review signature must be refused before any snapshot is admitted.
func TestFailClosedForgedReview(t *testing.T) {
	cfg := testConfig(t)
	receipt := loadReceipt(t, cfg)
	root := t.TempDir()
	bundle, err := prepareBundle(cfg, receipt.Targets[0], receipt.ReceiptID, "acquisition-proposal", root)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(bundle.signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	marker := strings.Index(string(signature), "U1NIU0lH")
	if marker < 0 {
		t.Fatal("signature fixture has no mutable armored payload")
	}
	forged := append([]byte(nil), signature...)
	forged[marker] = 'V'
	if err := os.WriteFile(bundle.signaturePath, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSnapshotCompile(cfg.SnapshotBin, bundle); err == nil {
		t.Fatal("snapshot compile accepted a forged review signature")
	}
	assertQuarantineCode(t, bundle.snapshotStore, "review_signature_verification_failed")
}

type evidenceManifest struct {
	InputSnapshotID string `json:"input_snapshot_id"`
	SpanCount       int    `json:"span_count"`
	TrustEnvelope   struct {
		EnvelopeKind string `json:"envelope_kind"`
	} `json:"trust_envelope"`
	Files []struct {
		OccurrenceID string `json:"occurrence_id"`
		Spans        []struct {
			SpanID    string `json:"span_id"`
			PayloadID string `json:"payload_id"`
		} `json:"spans"`
	} `json:"files"`
}

func readEvidenceManifest(t *testing.T, path string) evidenceManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidenceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func assertQuarantineCode(t *testing.T, storeRoot, code string) {
	t.Helper()
	found := false
	err := filepath.WalkDir(storeRoot, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(current, ".json") {
			return nil
		}
		data, readErr := os.ReadFile(current)
		if readErr != nil {
			return nil
		}
		var report struct {
			Issues []struct {
				Code string `json:"code"`
			} `json:"issues"`
		}
		if json.Unmarshal(data, &report) != nil {
			return nil
		}
		for _, issue := range report.Issues {
			if issue.Code == code {
				found = true
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no quarantine report under %s carried code %q", storeRoot, code)
	}
}

func assertTreesEqual(t *testing.T, left, right string) {
	t.Helper()
	leftFiles := hashTree(t, left)
	rightFiles := hashTree(t, right)
	if len(leftFiles) != len(rightFiles) {
		t.Fatalf("retained trees differ in file count: %d vs %d", len(leftFiles), len(rightFiles))
	}
	for relative, digest := range leftFiles {
		if rightFiles[relative] != digest {
			t.Fatalf("retained tree entry %s differs between independent runs", relative)
		}
	}
}

func hashTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = digestBytes(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
