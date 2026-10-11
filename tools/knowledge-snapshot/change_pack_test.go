package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestBuildChangePackDeterministicReviewedInputs(t *testing.T) {
	fixture := createChangePackFixture(t)
	firstStore := filepath.Join(fixture.root, "change-one")
	secondStore := filepath.Join(fixture.root, "change-two")
	first := mustBuildChangePack(t, fixture.config(firstStore))
	second := mustBuildChangePack(t, fixture.config(secondStore))
	third := mustBuildChangePack(t, fixture.config(firstStore))

	if first.Manifest.ChangePackID != second.Manifest.ChangePackID || first.Manifest.ChangePackID != third.Manifest.ChangePackID {
		t.Fatalf("change-pack IDs differ: %q %q %q", first.Manifest.ChangePackID, second.Manifest.ChangePackID, third.Manifest.ChangePackID)
	}
	firstBytes := readTestFile(t, first.ManifestPath)
	secondBytes := readTestFile(t, second.ManifestPath)
	thirdBytes := readTestFile(t, third.ManifestPath)
	if !bytes.Equal(firstBytes, secondBytes) || !bytes.Equal(firstBytes, thirdBytes) {
		t.Fatal("identical reviewed inputs did not emit byte-identical change packs")
	}
	manifest := first.Manifest
	if manifest.State != "complete" || manifest.AuthorityState != "derived_non_authoritative" || manifest.PromoteEligible {
		t.Fatalf("unsafe change-pack state: %+v", manifest.ChangePackManifestCore)
	}
	if manifest.OrderingBasis != changePackOrdering || manifest.ManifestKind != changePackManifestKind {
		t.Fatalf("unexpected change-pack contract: %+v", manifest.ChangePackManifestCore)
	}
	if manifest.Counts != (ChangePackCounts{Added: 1, Removed: 1, Changed: 1, Unchanged: 2}) {
		t.Fatalf("change counts = %+v", manifest.Counts)
	}
	wantChanges := map[string]string{
		"CHANGELOG.md":                  "unchanged",
		"docs/new.md":                   "added",
		"docs/reference/reused.md":      "changed",
		"docs/user-guide/reused.md":     "removed",
		"docs/user-guide/sync-waves.md": "unchanged",
	}
	if len(manifest.Changes) != len(wantChanges) {
		t.Fatalf("changes = %d, want %d", len(manifest.Changes), len(wantChanges))
	}
	previous := ""
	for _, change := range manifest.Changes {
		if change.RelativePath <= previous {
			t.Fatalf("changes are not in strict lexical order: %q after %q", change.RelativePath, previous)
		}
		previous = change.RelativePath
		if wantChanges[change.RelativePath] != change.ChangeType {
			t.Fatalf("change %q = %q, want %q", change.RelativePath, change.ChangeType, wantChanges[change.RelativePath])
		}
	}
	if manifest.OldSnapshot.ManifestID != fixture.oldManifest.ManifestID ||
		manifest.NewSnapshot.ManifestID != fixture.newManifest.ManifestID ||
		manifest.OldSnapshot.ReviewAdmission != fixture.oldManifest.ReviewAdmission ||
		manifest.NewSnapshot.ReviewAdmission != fixture.newManifest.ReviewAdmission {
		t.Fatal("change pack did not bind both complete signed snapshot admissions")
	}
	coreBytes, err := json.Marshal(manifest.ChangePackManifestCore)
	if err != nil {
		t.Fatal(err)
	}
	if got := digestBytes(coreBytes); got != manifest.ChangePackPayloadSHA256 || manifest.ChangePackID != "change-pack:"+got {
		t.Fatalf("change-pack identity is not content-derived: %+v", manifest)
	}
	for _, store := range []string{firstStore, secondStore} {
		if got := countRegularFiles(t, filepath.Join(store, "change-packs")); got != 1 {
			t.Fatalf("change-pack objects in %s = %d, want 1", store, got)
		}
		if got := countRegularFiles(t, filepath.Join(store, "raw")); got != 0 {
			t.Fatalf("change-pack copied %d raw objects into %s", got, store)
		}
	}
}

func TestChangePackBudgetRejectsCombinedOutputOver64MiB(t *testing.T) {
	const fileCount = 20_000
	pathPrefix := strings.Repeat("p", 1_780)
	mediaType := "application/" + strings.Repeat("x", maxMediaTypeBytes-len("application/"))
	digest := "sha256:" + strings.Repeat("0", 64)
	files := make([]ManifestFile, fileCount)
	for index := range files {
		files[index] = ManifestFile{
			RelativePath:       pathPrefix + fmt.Sprintf("/%05d", index),
			MediaType:          mediaType,
			SHA256:             digest,
			Size:               0,
			RawBlobID:          "raw:" + digest,
			ObjectPath:         objectRelativePath(strings.TrimPrefix(digest, "sha256:")),
			SnapshotID:         "snp:test",
			SourceID:           "src:test",
			ComponentID:        "cmp:test",
			ComponentVersionID: "ver:test@v1",
			ChannelID:          "chn:test",
		}
	}
	oldManifest := SnapshotManifest{SnapshotManifestCore: SnapshotManifestCore{
		Files: files, Exclusions: []VerifiedExclusion{},
	}}
	newManifest := oldManifest
	encoded, err := marshalDocument(oldManifest)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(encoded)) > maxSnapshotManifestBytes {
		t.Fatalf("synthetic input manifest = %d bytes, want at most %d", len(encoded), maxSnapshotManifestBytes)
	}
	if issues := validateChangePackOutputBudget(oldManifest, newManifest); len(issues) != 1 ||
		issues[0].Code != "change_pack_output_limit_exceeded" {
		t.Fatalf("budget issues = %+v, want change_pack_output_limit_exceeded", issues)
	}
}

func TestBuildChangePackRejectsAmbiguousOrdering(t *testing.T) {
	fixture := createChangePackFixture(t)
	tests := []struct {
		name   string
		config ChangePackConfig
		code   string
	}{
		{
			name: "same snapshot",
			config: ChangePackConfig{
				OldManifestPath:       fixture.oldManifestPath,
				OldStoreRoot:          fixture.oldStore,
				OldAllowedSignersPath: fixture.oldAllowedSignersPath,
				NewManifestPath:       fixture.oldManifestPath,
				NewStoreRoot:          fixture.oldStore,
				NewAllowedSignersPath: fixture.oldAllowedSignersPath,
			},
			code: "change_lineage_ambiguous",
		},
		{
			name: "reverse order",
			config: ChangePackConfig{
				OldManifestPath:       fixture.newManifestPath,
				OldStoreRoot:          fixture.newStore,
				OldAllowedSignersPath: fixture.newAllowedSignersPath,
				NewManifestPath:       fixture.oldManifestPath,
				NewStoreRoot:          fixture.oldStore,
				NewAllowedSignersPath: fixture.oldAllowedSignersPath,
			},
			code: "change_lineage_order_ambiguous",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.config.StoreRoot = filepath.Join(t.TempDir(), "output")
			_, err := BuildChangePack(test.config)
			requireChangePackRejected(t, err, test.code)
			assertNoChangePack(t, test.config.StoreRoot)
		})
	}
}

func TestBuildChangePackRejectsUnreviewedTamperedAndUnsafeInputs(t *testing.T) {
	fixture := createChangePackFixture(t)
	tests := []struct {
		name      string
		code      string
		configure func(*testing.T, *ChangePackConfig)
	}{
		{
			name: "manifest-selected self trust root",
			code: "change_input_trust_root_unsafe",
			configure: func(_ *testing.T, config *ChangePackConfig) {
				config.OldAllowedSignersPath = filepath.Join(config.OldStoreRoot,
					filepath.FromSlash(fixture.oldManifest.ReviewAdmission.TrustPolicyObjectPath))
			},
		},
		{
			name: "unrelated operator trust root",
			code: "change_input_trust_root_mismatch",
			configure: func(_ *testing.T, config *ChangePackConfig) {
				config.NewAllowedSignersPath = fixture.oldAllowedSignersPath
			},
		},
		{
			name: "hard-linked trust root",
			code: "change_input_trust_root_unsafe",
			configure: func(t *testing.T, config *ChangePackConfig) {
				storedPolicy := filepath.Join(config.OldStoreRoot,
					filepath.FromSlash(fixture.oldManifest.ReviewAdmission.TrustPolicyObjectPath))
				externalLink := filepath.Join(t.TempDir(), "allowed_signers")
				if err := os.Link(storedPolicy, externalLink); err != nil {
					t.Fatal(err)
				}
				config.OldAllowedSignersPath = externalLink
			},
		},
		{
			name: "unreviewed manifest",
			code: "change_input_manifest_unreviewed",
			configure: func(t *testing.T, config *ChangePackConfig) {
				store := filepath.Join(t.TempDir(), "old-copy")
				copyTree(t, fixture.oldStore, store)
				manifest := fixture.oldManifest
				manifest.AuthorityState = "unreviewed"
				config.OldStoreRoot = store
				config.OldManifestPath = writeSnapshotManifestCAS(t, store, manifest)
			},
		},
		{
			name: "forged review signature",
			code: "review_signature_invalid",
			configure: func(t *testing.T, config *ChangePackConfig) {
				store := filepath.Join(t.TempDir(), "old-copy")
				copyTree(t, fixture.oldStore, store)
				config.OldStoreRoot = store
				config.OldManifestPath = manifestPathInCopiedStore(t, fixture.oldManifestPath, fixture.oldStore, store)
				signature := filepath.Join(store, filepath.FromSlash(fixture.oldManifest.ReviewAdmission.SignatureObjectPath))
				if err := os.Chmod(signature, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(signature, []byte("forged signature\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered raw object",
			code: "change_input_raw_object_invalid",
			configure: func(t *testing.T, config *ChangePackConfig) {
				store := filepath.Join(t.TempDir(), "old-copy")
				copyTree(t, fixture.oldStore, store)
				config.OldStoreRoot = store
				config.OldManifestPath = manifestPathInCopiedStore(t, fixture.oldManifestPath, fixture.oldStore, store)
				object := filepath.Join(store, filepath.FromSlash(fixture.oldManifest.Files[0].ObjectPath))
				if err := os.WriteFile(object, []byte("tampered raw object\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "escaping occurrence path",
			code: "change_input_file_order_invalid",
			configure: func(t *testing.T, config *ChangePackConfig) {
				store := filepath.Join(t.TempDir(), "old-copy")
				copyTree(t, fixture.oldStore, store)
				manifest := fixture.oldManifest
				manifest.Files = append([]ManifestFile(nil), fixture.oldManifest.Files...)
				manifest.Files[0].RelativePath = "../escape.md"
				config.OldStoreRoot = store
				config.OldManifestPath = writeSnapshotManifestCAS(t, store, manifest)
			},
		},
		{
			name: "symlinked manifest parent",
			code: "change_input_manifest_read_failed",
			configure: func(t *testing.T, config *ChangePackConfig) {
				root := t.TempDir()
				linked := filepath.Join(root, "linked-manifests")
				if err := os.Symlink(filepath.Join(fixture.oldStore, "manifests"), linked); err != nil {
					t.Fatal(err)
				}
				relative, err := filepath.Rel(filepath.Join(fixture.oldStore, "manifests"), fixture.oldManifestPath)
				if err != nil {
					t.Fatal(err)
				}
				config.OldManifestPath = filepath.Join(linked, relative)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "change-output")
			config := fixture.config(output)
			test.configure(t, &config)
			_, err := BuildChangePack(config)
			requireChangePackRejected(t, err, test.code)
			assertNoChangePack(t, output)
		})
	}
}

type changePackFixture struct {
	root                  string
	oldStore              string
	oldManifestPath       string
	oldManifest           SnapshotManifest
	oldAllowedSignersPath string
	newStore              string
	newManifestPath       string
	newManifest           SnapshotManifest
	newAllowedSignersPath string
}

func (fixture changePackFixture) config(output string) ChangePackConfig {
	return ChangePackConfig{
		OldManifestPath:       fixture.oldManifestPath,
		OldStoreRoot:          fixture.oldStore,
		OldAllowedSignersPath: fixture.oldAllowedSignersPath,
		NewManifestPath:       fixture.newManifestPath,
		NewStoreRoot:          fixture.newStore,
		NewAllowedSignersPath: fixture.newAllowedSignersPath,
		StoreRoot:             output,
	}
}

func createChangePackFixture(t *testing.T) changePackFixture {
	t.Helper()
	root := t.TempDir()
	oldStore := filepath.Join(root, "old-store")
	old := mustCompileFixture(t, filepath.Join("testdata", "mirrors"), filepath.Join("testdata", "source-spec.json"), oldStore)

	newMirrorBase := filepath.Join(root, "new-mirrors")
	newMirror := filepath.Join(newMirrorBase, "argo-cd", "v3.4.6")
	copyTree(t, filepath.Join("testdata", "mirrors", "argo-cd", "v3.4.5"), newMirror)
	if err := os.WriteFile(filepath.Join(newMirror, "docs", "reference", "reused.md"), []byte("changed reference occurrence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(newMirror, "docs", "user-guide", "reused.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newMirror, "docs", "new.md"), []byte("new occurrence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := loadInventoryMetadata(t)
	metadata.SnapshotID = "snp:argocd:docs:sync-waves@v3.4.6:fixture"
	metadata.SourceID = "src:argocd:docs@v3.4.6"
	metadata.CanonicalURI = "https://github.com/argoproj/argo-cd/tree/dddddddddddddddddddddddddddddddddddddddd"
	metadata.ComponentVersionID = "ver:github:argoproj/argo-cd@v3.4.6"
	metadata.ResolvedVersion = "v3.4.6"
	metadata.SourceRevision = "dddddddddddddddddddddddddddddddddddddddd"
	metadata.FetchedAt = "2026-07-16T09:15:00Z"
	metadata.ObservedAt = "2026-07-16T09:15:00Z"
	metadata.MirrorPath = "argo-cd/v3.4.6"
	proposal := mustDraftInventory(t, InventoryConfig{
		MetadataPath:  writeInventoryMetadata(t, root, metadata),
		MirrorBase:    newMirrorBase,
		ProposalStore: filepath.Join(root, "new-proposals"),
	})
	newSpecPath := writeSpec(t, root, proposal.Proposal.SourceSpecDraft)
	reviewDirectory := filepath.Join(root, "new-review")
	if err := os.MkdirAll(reviewDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	newConfig := createTestReviewAdmission(t, proposal.Proposal, proposal.ProposalPath, newSpecPath, reviewDirectory)
	newStore := filepath.Join(root, "new-store")
	newConfig.MirrorBase = newMirrorBase
	newConfig.StoreRoot = newStore
	newResult, err := Compile(newConfig)
	if err != nil {
		t.Fatalf("compile new change-pack fixture: %v", err)
	}
	return changePackFixture{
		root:                  root,
		oldStore:              oldStore,
		oldManifestPath:       old.ManifestPath,
		oldManifest:           old.Manifest,
		oldAllowedSignersPath: filepath.Join("testdata", "review", "allowed_signers"),
		newStore:              newStore,
		newManifestPath:       newResult.ManifestPath,
		newManifest:           newResult.Manifest,
		newAllowedSignersPath: newConfig.AllowedSignersPath,
	}
}

func mustBuildChangePack(t *testing.T, config ChangePackConfig) ChangePackResult {
	t.Helper()
	result, err := BuildChangePack(config)
	if err != nil {
		t.Fatalf("BuildChangePack() error = %v", err)
	}
	return result
}

func requireChangePackRejected(t *testing.T, err error, code string) *ChangePackRejectedError {
	t.Helper()
	var rejected *ChangePackRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("error = %v, want ChangePackRejectedError", err)
	}
	for _, got := range rejected.Issues {
		if got.Code == code {
			return rejected
		}
	}
	codes := make([]string, 0, len(rejected.Issues))
	for _, got := range rejected.Issues {
		codes = append(codes, got.Code)
	}
	sort.Strings(codes)
	t.Fatalf("change-pack rejection codes = %v, want %q", codes, code)
	return nil
}

func assertNoChangePack(t *testing.T, store string) {
	t.Helper()
	if got := countRegularFiles(t, filepath.Join(store, "change-packs")); got != 0 {
		t.Fatalf("rejected input emitted %d change packs", got)
	}
}

func writeSnapshotManifestCAS(t *testing.T, store string, manifest SnapshotManifest) string {
	t.Helper()
	coreBytes, err := json.Marshal(manifest.SnapshotManifestCore)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(coreBytes)
	manifest.ManifestPayloadSHA256 = digest
	manifest.ManifestID = "snapshot-manifest:" + digest
	data, err := marshalDocument(manifest)
	if err != nil {
		t.Fatal(err)
	}
	hexDigest := digest[len("sha256:"):]
	directory := filepath.Join(store, "manifests", "sha256", hexDigest[:2])
	return writeTestFile(t, directory, hexDigest+".json", data)
}

func manifestPathInCopiedStore(t *testing.T, originalPath, originalStore, copiedStore string) string {
	t.Helper()
	relative, err := filepath.Rel(originalStore, originalPath)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(copiedStore, relative)
}
