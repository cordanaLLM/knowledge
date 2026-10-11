package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestCompileExactVersionArgoMirror(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	result, err := Compile(withFixtureReview(CompileConfig{
		SpecPath:   filepath.Join("testdata", "source-spec.json"),
		MirrorBase: filepath.Join("testdata", "mirrors"),
		StoreRoot:  store,
	}))
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	manifest := result.Manifest
	if manifest.State != "complete" {
		t.Fatalf("state = %q, want complete", manifest.State)
	}
	if manifest.ManifestKind != "knowledge_snapshot" {
		t.Fatalf("manifest_kind = %q", manifest.ManifestKind)
	}
	if manifest.AuthorityState != "reviewed" || manifest.ReviewAdmission.Decision != "accepted" ||
		manifest.ReviewAdmission.Reviewer != "fixture-reviewer" {
		t.Fatalf("manifest review authority is incomplete: %+v", manifest.ReviewAdmission)
	}
	if manifest.FileCount != 4 || len(manifest.Files) != 4 {
		t.Fatalf("file count = %d/%d, want 4", manifest.FileCount, len(manifest.Files))
	}
	if manifest.UniqueBlobCount != 3 {
		t.Fatalf("unique blob count = %d, want 3", manifest.UniqueBlobCount)
	}
	if manifest.Source.ComponentID != "cmp:github:argoproj/argo-cd" ||
		manifest.Source.ComponentVersionID != "ver:github:argoproj/argo-cd@v3.4.5" ||
		manifest.Source.ChannelID != "chn:argocd:source" {
		t.Fatalf("unexpected source lineage: %+v", manifest.Source)
	}
	if manifest.Source.ResolvedVersion != "v3.4.5" || manifest.Source.SourceRevision != "564b94973b284b8de98da7cee6eeade2cb941e46" {
		t.Fatalf("version lineage is not exact: %+v", manifest.Source)
	}
	if !strings.HasPrefix(manifest.ManifestID, "snapshot-manifest:sha256:") {
		t.Fatalf("manifest ID is not content-addressed: %q", manifest.ManifestID)
	}
	coreBytes, err := json.Marshal(manifest.SnapshotManifestCore)
	if err != nil {
		t.Fatal(err)
	}
	if got := digestBytes(coreBytes); got != manifest.ManifestPayloadSHA256 {
		t.Fatalf("payload digest = %q, want %q", manifest.ManifestPayloadSHA256, got)
	}
	if _, err := os.Stat(result.ManifestPath); err != nil {
		t.Fatalf("manifest path: %v", err)
	}
	if got := countRegularFiles(t, filepath.Join(store, "raw")); got != 3 {
		t.Fatalf("raw object files = %d, want 3", got)
	}
	if got := countRegularFiles(t, filepath.Join(store, "review")); got != 5 {
		t.Fatalf("review CAS object files = %d, want 5", got)
	}
	for _, file := range manifest.Files {
		if file.SourceID != manifest.Source.SourceID || file.SnapshotID != manifest.SnapshotID ||
			file.ComponentID != manifest.Source.ComponentID || file.ComponentVersionID != manifest.Source.ComponentVersionID ||
			file.ChannelID != manifest.Source.ChannelID {
			t.Fatalf("file lineage is incomplete: %+v", file)
		}
		if err := verifyFileDigest(filepath.Join(store, filepath.FromSlash(file.ObjectPath)), file.SHA256, file.Size); err != nil {
			t.Fatalf("object %s: %v", file.RelativePath, err)
		}
	}
}

func TestDuplicateBytesReuseOneRawBlob(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	result := mustCompileFixture(t, filepath.Join("testdata", "mirrors"), filepath.Join("testdata", "source-spec.json"), store)
	byPath := make(map[string]ManifestFile)
	for _, file := range result.Manifest.Files {
		byPath[file.RelativePath] = file
	}
	left := byPath["docs/reference/reused.md"]
	right := byPath["docs/user-guide/reused.md"]
	if left.RawBlobID == "" || left.RawBlobID != right.RawBlobID || left.ObjectPath != right.ObjectPath {
		t.Fatalf("duplicate objects were not reused: left=%+v right=%+v", left, right)
	}
	if got := countRegularFiles(t, filepath.Join(store, "raw")); got != 3 {
		t.Fatalf("raw object files = %d, want 3", got)
	}
}

func TestMutationQuarantinesWithoutReplacingValidManifest(t *testing.T) {
	root := t.TempDir()
	mirrorBase := filepath.Join(root, "mirrors")
	copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
	store := filepath.Join(root, "store")
	first := mustCompileFixture(t, mirrorBase, filepath.Join("testdata", "source-spec.json"), store)
	before, err := os.ReadFile(first.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	mutated := filepath.Join(mirrorBase, "argo-cd", "v3.4.5", "docs", "user-guide", "sync-waves.md")
	if err := os.WriteFile(mutated, []byte("changed after reviewed acquisition\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Compile(withFixtureReview(CompileConfig{
		SpecPath:   filepath.Join("testdata", "source-spec.json"),
		MirrorBase: mirrorBase,
		StoreRoot:  store,
	}))
	quarantined := requireQuarantined(t, err, "source_digest_changed")
	if _, statErr := os.Stat(quarantined.ReportPath); statErr != nil {
		t.Fatalf("quarantine report: %v", statErr)
	}
	after, err := os.ReadFile(first.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("valid immutable manifest changed after a quarantined mutation")
	}
	if got := countRegularFiles(t, filepath.Join(store, "manifests")); got != 1 {
		t.Fatalf("manifest files = %d, want only the original valid manifest", got)
	}
}

func TestMissingRightsQuarantinesBeforeBlobCommit(t *testing.T) {
	root := t.TempDir()
	spec := loadFixtureSpec(t)
	spec.Rights.LicenseExpression = ""
	specPath := writeSpec(t, root, spec)
	store := filepath.Join(root, "store")
	_, err := Compile(CompileConfig{
		SpecPath:   specPath,
		MirrorBase: filepath.Join("testdata", "mirrors"),
		StoreRoot:  store,
	})
	requireQuarantined(t, err, "rights_missing")
	if got := countRegularFiles(t, filepath.Join(store, "raw")); got != 0 {
		t.Fatalf("raw object files = %d, want 0", got)
	}
	if got := countRegularFiles(t, filepath.Join(store, "manifests")); got != 0 {
		t.Fatalf("manifest files = %d, want 0", got)
	}
}

func TestOversizedStableIDQuarantinesBeforeAdmission(t *testing.T) {
	root := t.TempDir()
	spec := loadFixtureSpec(t)
	spec.SnapshotID = "snp:" + strings.Repeat("x", maxStableIDBytes)
	store := filepath.Join(root, "store")

	_, err := Compile(CompileConfig{
		SpecPath:   writeSpec(t, root, spec),
		MirrorBase: filepath.Join("testdata", "mirrors"),
		StoreRoot:  store,
	})
	rejected := requireQuarantined(t, err, "metadata_scalar_limit_exceeded")
	if rejected.ReportPath == "" {
		t.Fatal("oversized metadata rejection did not retain a quarantine report")
	}
	assertNoAdmittedContent(t, store)
}

func TestProjectedManifestOver64MiBQuarantinesBeforeMirrorOrAdmissionCommit(t *testing.T) {
	root := t.TempDir()
	spec := loadFixtureSpec(t)
	spec.ResolvedVersion = "v1"
	spec.SourceRevision = "revision-v1"
	spec.SnapshotID = paddedStableID("snp:test:", "")
	spec.SourceID = paddedStableID("src:test:", "")
	spec.ComponentID = paddedStableID("cmp:test:", "")
	spec.ComponentVersionID = paddedStableID("ver:test:", "@v1")
	spec.ChannelID = paddedStableID("chn:test:", "")
	spec.Exclusions = []VerifiedExclusion{}
	spec.Files = make([]ExpectedFile, 25_000)
	for index := range spec.Files {
		spec.Files[index] = ExpectedFile{
			RelativePath: fmt.Sprintf("tiny/%05d.txt", index),
			MediaType:    "text/plain",
			SHA256:       "sha256:" + strings.Repeat("0", 64),
			Size:         0,
		}
	}

	specPath := writeSpec(t, root, spec)
	proposal, proposalPath := writeProposalForSpec(t, root, spec)
	reviewDirectory := filepath.Join(root, "review")
	if err := os.MkdirAll(reviewDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := createTestReviewAdmission(t, proposal, proposalPath, specPath, reviewDirectory)
	config.MirrorBase = filepath.Join("testdata", "mirrors")
	config.StoreRoot = filepath.Join(root, "store")

	_, err := Compile(config)
	requireQuarantined(t, err, "manifest_output_limit_exceeded")
	assertNoAdmittedContent(t, config.StoreRoot)
}

func TestSymlinkQuarantines(t *testing.T) {
	root := t.TempDir()
	mirrorBase := filepath.Join(root, "mirrors")
	copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
	target := filepath.Join(mirrorBase, "argo-cd", "v3.4.5", "CHANGELOG.md")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external.md")
	if err := os.WriteFile(external, []byte("outside mirror\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, target); err != nil {
		t.Fatal(err)
	}
	_, err := Compile(withFixtureReview(CompileConfig{
		SpecPath:   filepath.Join("testdata", "source-spec.json"),
		MirrorBase: mirrorBase,
		StoreRoot:  filepath.Join(root, "store"),
	}))
	requireQuarantined(t, err, "symlink_rejected")
}

func TestCompileRejectsRecursiveStoreOverlapWithoutWrite(t *testing.T) {
	t.Run("store inside mirror", func(t *testing.T) {
		root := t.TempDir()
		mirrorBase := filepath.Join(root, "mirrors")
		copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
		mirrorRoot := filepath.Join(mirrorBase, "argo-cd", "v3.4.5")
		store := filepath.Join(mirrorRoot, "generated-store")
		before := captureTestTree(t, mirrorRoot)

		_, err := Compile(withFixtureReview(CompileConfig{
			SpecPath:   filepath.Join("testdata", "source-spec.json"),
			MirrorBase: mirrorBase,
			StoreRoot:  store,
		}))
		rejected := requireQuarantined(t, err, "recursive_store_overlap")
		if rejected.ReportPath != "" {
			t.Fatalf("unsafe overlap unexpectedly wrote quarantine report %q", rejected.ReportPath)
		}
		if _, statErr := os.Lstat(store); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("recursive object store was created: %v", statErr)
		}
		if after := captureTestTree(t, mirrorRoot); after != before {
			t.Fatal("input mirror changed after rejected recursive object store")
		}
	})

	t.Run("mirror inside store", func(t *testing.T) {
		root := t.TempDir()
		store := filepath.Join(root, "store")
		mirrorBase := filepath.Join(store, "mirrors")
		copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
		before := captureTestTree(t, store)

		_, err := Compile(withFixtureReview(CompileConfig{
			SpecPath:   filepath.Join("testdata", "source-spec.json"),
			MirrorBase: mirrorBase,
			StoreRoot:  store,
		}))
		rejected := requireQuarantined(t, err, "recursive_store_overlap")
		if rejected.ReportPath != "" {
			t.Fatalf("unsafe overlap unexpectedly wrote quarantine report %q", rejected.ReportPath)
		}
		if after := captureTestTree(t, store); after != before {
			t.Fatal("object-store parent changed after rejected nested input mirror")
		}
	})
}

func TestPathEscapeAndGeneratedRecursiveSourceQuarantine(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*SourceSpec)
		codes []string
	}{
		{
			name: "path escape",
			alter: func(spec *SourceSpec) {
				spec.Files[0].RelativePath = "../CHANGELOG.md"
			},
			codes: []string{"file_path_escape"},
		},
		{
			name: "generated recursive source",
			alter: func(spec *SourceSpec) {
				spec.Provenance.Generated = true
				spec.Provenance.RecursiveSource = true
			},
			codes: []string{"generated_source_rejected", "recursive_source_rejected"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			spec := loadFixtureSpec(t)
			test.alter(&spec)
			_, err := Compile(CompileConfig{
				SpecPath:   writeSpec(t, root, spec),
				MirrorBase: filepath.Join("testdata", "mirrors"),
				StoreRoot:  filepath.Join(root, "store"),
			})
			for _, code := range test.codes {
				requireQuarantined(t, err, code)
			}
		})
	}
}

func TestPartialMirrorQuarantines(t *testing.T) {
	root := t.TempDir()
	mirrorBase := filepath.Join(root, "mirrors")
	copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
	missing := filepath.Join(mirrorBase, "argo-cd", "v3.4.5", "CHANGELOG.md")
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	unexpected := filepath.Join(mirrorBase, "argo-cd", "v3.4.5", "partial.tmp")
	if err := os.WriteFile(unexpected, []byte("partial\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Compile(withFixtureReview(CompileConfig{
		SpecPath:   filepath.Join("testdata", "source-spec.json"),
		MirrorBase: mirrorBase,
		StoreRoot:  filepath.Join(root, "store"),
	}))
	requireQuarantined(t, err, "expected_file_missing")
	requireQuarantined(t, err, "unexpected_file")
}

func TestResourceLimitsQuarantineBeforeBlobCommit(t *testing.T) {
	tests := []struct {
		name   string
		config CompileConfig
		code   string
	}{
		{
			name:   "file count",
			config: CompileConfig{MaxFiles: 3},
			code:   "file_count_limit_exceeded",
		},
		{
			name:   "per file bytes",
			config: CompileConfig{MaxFileBytes: 80},
			code:   "file_size_limit_exceeded",
		},
		{
			name:   "total bytes",
			config: CompileConfig{MaxTotalBytes: 200},
			code:   "total_size_limit_exceeded",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.config.SpecPath = filepath.Join("testdata", "source-spec.json")
			test.config.MirrorBase = filepath.Join("testdata", "mirrors")
			test.config.StoreRoot = filepath.Join(root, "store")
			test.config = withFixtureReview(test.config)
			_, err := Compile(test.config)
			requireQuarantined(t, err, test.code)
			if got := countRegularFiles(t, filepath.Join(test.config.StoreRoot, "raw")); got != 0 {
				t.Fatalf("raw object files = %d, want 0", got)
			}
			if got := countRegularFiles(t, filepath.Join(test.config.StoreRoot, "manifests")); got != 0 {
				t.Fatalf("manifest files = %d, want 0", got)
			}
		})
	}
}

func TestCompileRequiresNonEmptyStoreRoot(t *testing.T) {
	_, err := Compile(CompileConfig{
		SpecPath:   filepath.Join("testdata", "source-spec.json"),
		MirrorBase: filepath.Join("testdata", "mirrors"),
	})
	if err == nil || !strings.Contains(err.Error(), "store root is required") {
		t.Fatalf("error = %v, want non-empty store-root error", err)
	}
	var quarantined *QuarantinedError
	if errors.As(err, &quarantined) {
		t.Fatal("missing store root must fail configuration before quarantine writes")
	}
}

func TestReviewAdmissionFailuresBeforeContentCommit(t *testing.T) {
	fixture := withFixtureReview(CompileConfig{
		SpecPath:   filepath.Join("testdata", "source-spec.json"),
		MirrorBase: filepath.Join("testdata", "mirrors"),
	})
	tests := []struct {
		name      string
		code      string
		configure func(*testing.T, string, *CompileConfig)
	}{
		{
			name: "missing receipt",
			code: "review_admission_missing",
			configure: func(_ *testing.T, _ string, config *CompileConfig) {
				config.ReviewReceiptPath = ""
			},
		},
		{
			name: "forged signature",
			code: "review_signature_verification_failed",
			configure: func(t *testing.T, root string, config *CompileConfig) {
				signature := readTestFile(t, config.ReviewSignaturePath)
				marker := bytes.Index(signature, []byte("U1NIU0lH"))
				if marker < 0 {
					t.Fatal("fixture signature has no mutable armored payload")
				}
				signature[marker] = 'V'
				config.ReviewSignaturePath = writeTestFile(t, root, "forged.sig", signature)
			},
		},
		{
			name: "rejected receipt",
			code: "review_decision_not_accepted",
			configure: func(t *testing.T, root string, config *CompileConfig) {
				receipt := loadFixtureReceipt(t)
				receipt.Decision = "rejected"
				config.ReviewReceiptPath = writeReviewReceipt(t, root, receipt)
			},
		},
		{
			name: "receipt binds another spec",
			code: "review_receipt_spec_mismatch",
			configure: func(t *testing.T, root string, config *CompileConfig) {
				receipt := loadFixtureReceipt(t)
				receipt.SourceSpecSHA256 = "sha256:" + strings.Repeat("0", 64)
				config.ReviewReceiptPath = writeReviewReceipt(t, root, receipt)
			},
		},
		{
			name: "source spec differs from reviewed proposal",
			code: "review_source_spec_mismatch",
			configure: func(t *testing.T, root string, config *CompileConfig) {
				spec := loadFixtureSpec(t)
				spec.Language = "de"
				config.SpecPath = writeSpec(t, root, spec)
			},
		},
		{
			name: "signature symlink",
			code: "review_signature_read_failed",
			configure: func(t *testing.T, root string, config *CompileConfig) {
				link := filepath.Join(root, "signature-link")
				if err := os.Symlink(absoluteTestPath(t, config.ReviewSignaturePath), link); err != nil {
					t.Fatal(err)
				}
				config.ReviewSignaturePath = link
			},
		},
		{
			name: "signature parent symlink",
			code: "review_signature_read_failed",
			configure: func(t *testing.T, root string, config *CompileConfig) {
				realParent := filepath.Join(root, "real")
				if err := os.Mkdir(realParent, 0o700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, realParent, "review.sig", readTestFile(t, config.ReviewSignaturePath))
				linkedParent := filepath.Join(root, "linked")
				if err := os.Symlink(realParent, linkedParent); err != nil {
					t.Fatal(err)
				}
				config.ReviewSignaturePath = filepath.Join(linkedParent, "review.sig")
			},
		},
		{
			name: "oversized receipt",
			code: "review_receipt_read_failed",
			configure: func(t *testing.T, root string, config *CompileConfig) {
				config.ReviewReceiptPath = writeTestFile(t, root, "oversized.json", bytes.Repeat([]byte{'x'}, int(maxReviewReceiptBytes+1)))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			config := fixture
			config.StoreRoot = filepath.Join(root, "store")
			test.configure(t, root, &config)
			_, err := Compile(config)
			requireQuarantined(t, err, test.code)
			assertNoAdmittedContent(t, config.StoreRoot)
		})
	}
}

func TestWriteImmutableRejectsUnsafeExistingPaths(t *testing.T) {
	data := []byte("immutable bytes\n")
	tests := []struct {
		name  string
		setup func(*testing.T, string) string
	}{
		{
			name: "target symlink",
			setup: func(t *testing.T, root string) string {
				external := writeTestFile(t, root, "external", data)
				target := filepath.Join(root, "objects", "object")
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, target); err != nil {
					t.Fatal(err)
				}
				return target
			},
		},
		{
			name: "wrong size collision",
			setup: func(t *testing.T, root string) string {
				target := filepath.Join(root, "objects", "object")
				return writeTestFile(t, filepath.Dir(target), filepath.Base(target), append(data, 'x'))
			},
		},
		{
			name: "parent symlink",
			setup: func(t *testing.T, root string) string {
				realParent := filepath.Join(root, "real")
				if err := os.Mkdir(realParent, 0o755); err != nil {
					t.Fatal(err)
				}
				linkedParent := filepath.Join(root, "linked")
				if err := os.Symlink(realParent, linkedParent); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(linkedParent, "object")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			target := test.setup(t, root)
			relative, err := filepath.Rel(root, target)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeImmutableObject(root, filepath.ToSlash(relative), data, 0o444); err == nil {
				t.Fatal("writeImmutableObject() succeeded for an unsafe immutable path")
			}
		})
	}
}

func TestDeterministicRerunAcrossStores(t *testing.T) {
	root := t.TempDir()
	first := mustCompileFixture(t, filepath.Join("testdata", "mirrors"), filepath.Join("testdata", "source-spec.json"), filepath.Join(root, "one"))
	second := mustCompileFixture(t, filepath.Join("testdata", "mirrors"), filepath.Join("testdata", "source-spec.json"), filepath.Join(root, "two"))
	third := mustCompileFixture(t, filepath.Join("testdata", "mirrors"), filepath.Join("testdata", "source-spec.json"), filepath.Join(root, "one"))
	if first.Manifest.ManifestID != second.Manifest.ManifestID || first.Manifest.ManifestID != third.Manifest.ManifestID {
		t.Fatalf("manifest IDs differ: %q %q %q", first.Manifest.ManifestID, second.Manifest.ManifestID, third.Manifest.ManifestID)
	}
	firstBytes, err := os.ReadFile(first.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	thirdBytes, err := os.ReadFile(third.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || !bytes.Equal(firstBytes, thirdBytes) {
		t.Fatal("identical source specs and mirror bytes did not emit byte-identical manifests")
	}
	if got := countRegularFiles(t, filepath.Join(root, "one", "raw")); got != 3 {
		t.Fatalf("rerun produced %d raw objects, want 3", got)
	}
	if got := countRegularFiles(t, filepath.Join(root, "one", ".staging")); got != 0 {
		t.Fatalf("staging retains %d files after successful rerun", got)
	}
}

func mustCompileFixture(t *testing.T, mirrorBase, specPath, store string) CompileResult {
	t.Helper()
	result, err := Compile(withFixtureReview(CompileConfig{SpecPath: specPath, MirrorBase: mirrorBase, StoreRoot: store}))
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return result
}

func withFixtureReview(config CompileConfig) CompileConfig {
	config.ProposalPath = filepath.Join("testdata", "review", "inventory-proposal.json")
	config.ReviewReceiptPath = filepath.Join("testdata", "review", "accepted-review.json")
	config.ReviewSignaturePath = filepath.Join("testdata", "review", "accepted-review.json.sig")
	config.AllowedSignersPath = filepath.Join("testdata", "review", "allowed_signers")
	return config
}

func requireQuarantined(t *testing.T, err error, code string) *QuarantinedError {
	t.Helper()
	var quarantined *QuarantinedError
	if !errors.As(err, &quarantined) {
		t.Fatalf("error = %v, want QuarantinedError", err)
	}
	for _, got := range quarantined.Issues {
		if got.Code == code {
			return quarantined
		}
	}
	codes := make([]string, 0, len(quarantined.Issues))
	for _, got := range quarantined.Issues {
		codes = append(codes, got.Code)
	}
	sort.Strings(codes)
	t.Fatalf("quarantine codes = %v, want %q", codes, code)
	return nil
}

func loadFixtureSpec(t *testing.T) SourceSpec {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "source-spec.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec SourceSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	return spec
}

func loadFixtureReceipt(t *testing.T) SourceSpecReviewReceipt {
	t.Helper()
	data := readTestFile(t, filepath.Join("testdata", "review", "accepted-review.json"))
	var receipt SourceSpecReviewReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func writeReviewReceipt(t *testing.T, directory string, receipt SourceSpecReviewReceipt) string {
	t.Helper()
	data, err := marshalDocument(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestFile(t, directory, "review.json", data)
}

func readTestFile(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeTestFile(t *testing.T, directory, name string, data []byte) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, name)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func absoluteTestPath(t *testing.T, candidate string) string {
	t.Helper()
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func assertNoAdmittedContent(t *testing.T, store string) {
	t.Helper()
	for _, subtree := range []string{"raw", "review", "manifests"} {
		if got := countRegularFiles(t, filepath.Join(store, subtree)); got != 0 {
			t.Fatalf("%s contains %d admitted files after review failure, want 0", subtree, got)
		}
	}
}

func writeSpec(t *testing.T, directory string, spec SourceSpec) string {
	t.Helper()
	data, err := marshalDocument(spec)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "source-spec.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func paddedStableID(prefix, suffix string) string {
	padding := maxStableIDBytes - len(prefix) - len(suffix)
	if padding < 0 {
		panic("stable-ID test prefix and suffix exceed the schema limit")
	}
	return prefix + strings.Repeat("x", padding) + suffix
}

func writeProposalForSpec(t *testing.T, directory string, spec SourceSpec) (InventoryProposal, string) {
	t.Helper()
	var includedBytes, excludedBytes int64
	for _, file := range spec.Files {
		includedBytes += file.Size
	}
	for _, exclusion := range spec.Exclusions {
		excludedBytes += exclusion.Size
	}
	core := InventoryProposalCore{
		SchemaVersion:     sourceSpecSchemaVersion,
		ProposalKind:      "source_spec_inventory_proposal",
		State:             "proposal",
		ReviewState:       "unreviewed",
		AuthorityState:    "non_authoritative",
		CompileEligible:   false,
		PromoteEligible:   false,
		MetadataSHA256:    digestBytes([]byte("bounded-test-metadata")),
		FileCount:         len(spec.Files),
		ByteSize:          includedBytes,
		ExcludedFileCount: len(spec.Exclusions),
		ExcludedByteSize:  excludedBytes,
		Exclusions:        append([]VerifiedExclusion{}, spec.Exclusions...),
		SourceSpecDraft:   spec,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := digestBytes(coreBytes)
	proposal := InventoryProposal{
		ProposalID:            "inventory-proposal:" + payloadDigest,
		ProposalPayloadSHA256: payloadDigest,
		InventoryProposalCore: core,
	}
	data, err := marshalDocument(proposal)
	if err != nil {
		t.Fatal(err)
	}
	return proposal, writeTestFile(t, directory, "inventory-proposal.json", data)
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func countRegularFiles(t *testing.T, root string) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return walkErr
		}
		if !entry.IsDir() && entry.Type().IsRegular() {
			count++
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return count
}

func captureTestTree(t *testing.T, root string) string {
	t.Helper()
	entries := make([]string, 0)
	if err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		identity := fmt.Sprintf("%s|%s", filepath.ToSlash(relative), info.Mode())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(current)
			if err != nil {
				return err
			}
			identity += "|" + digestBytes(data)
		}
		entries = append(entries, identity)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	return strings.Join(entries, "\n")
}
