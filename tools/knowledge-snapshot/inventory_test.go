package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestDraftInventoryRejectsUnsafeMetadataFilesWithoutExternalWrites(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string, string) string
	}{
		{
			name: "oversized",
			setup: func(t *testing.T, _ string, external string) string {
				return writeTestFile(t, external, "oversized.json", bytes.Repeat([]byte{'x'}, int(maxInventoryMetadataBytes)+1))
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, base, external string) string {
				target := writeTestFile(t, external, "metadata.json", mustReadFile(t, filepath.Join("testdata", "inventory-metadata.json")))
				linked := filepath.Join(base, "metadata-link.json")
				if err := os.Symlink(target, linked); err != nil {
					t.Fatal(err)
				}
				return linked
			},
		},
		{
			name: "special-file",
			setup: func(_ *testing.T, _, _ string) string {
				return "/dev/null"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			external := filepath.Join(base, "external")
			writeTestFile(t, external, "canary", []byte("do not modify\n"))
			metadataPath := test.setup(t, base, external)
			before := directoryFingerprint(t, external)
			config := InventoryConfig{
				MetadataPath:  metadataPath,
				MirrorBase:    filepath.Join("testdata", "mirrors"),
				ProposalStore: filepath.Join(base, "proposals"),
			}
			_, err := DraftInventory(config)
			requireInventoryRejected(t, err, "inventory_metadata_read_failed")
			assertNoInventoryProposal(t, config.ProposalStore)
			if after := directoryFingerprint(t, external); after != before {
				t.Fatalf("external input directory changed after %s metadata rejection\nbefore %s\nafter  %s", test.name, before, after)
			}
		})
	}
}

func TestDraftInventoryDeterministicAndProposalOnly(t *testing.T) {
	root := t.TempDir()
	config := InventoryConfig{
		MetadataPath:  filepath.Join("testdata", "inventory-metadata.json"),
		MirrorBase:    filepath.Join("testdata", "mirrors"),
		ProposalStore: filepath.Join(root, "one"),
	}
	first := mustDraftInventory(t, config)
	config.ProposalStore = filepath.Join(root, "two")
	second := mustDraftInventory(t, config)
	config.ProposalStore = filepath.Join(root, "one")
	third := mustDraftInventory(t, config)

	if first.Proposal.ProposalID != second.Proposal.ProposalID || first.Proposal.ProposalID != third.Proposal.ProposalID {
		t.Fatalf("proposal IDs differ: %q %q %q", first.Proposal.ProposalID, second.Proposal.ProposalID, third.Proposal.ProposalID)
	}
	firstBytes := mustReadFile(t, first.ProposalPath)
	secondBytes := mustReadFile(t, second.ProposalPath)
	thirdBytes := mustReadFile(t, third.ProposalPath)
	if !bytes.Equal(firstBytes, secondBytes) || !bytes.Equal(firstBytes, thirdBytes) {
		t.Fatal("identical metadata and mirrors did not emit byte-identical proposals")
	}
	proposal := first.Proposal
	if proposal.State != "proposal" || proposal.ReviewState != "unreviewed" || proposal.AuthorityState != "non_authoritative" {
		t.Fatalf("proposal safety states = %q/%q/%q", proposal.State, proposal.ReviewState, proposal.AuthorityState)
	}
	if proposal.CompileEligible || proposal.PromoteEligible {
		t.Fatalf("proposal unexpectedly eligible for compile/promotion: %+v", proposal.InventoryProposalCore)
	}
	if proposal.FileCount != 4 || proposal.ByteSize != 281 || proposal.ExcludedFileCount != 0 || proposal.ExcludedByteSize != 0 {
		t.Fatalf("proposal counts = files %d/%d bytes %d/%d", proposal.FileCount, proposal.ExcludedFileCount, proposal.ByteSize, proposal.ExcludedByteSize)
	}
	if proposal.SourceSpecDraft.SourceRevision != "564b94973b284b8de98da7cee6eeade2cb941e46" ||
		proposal.SourceSpecDraft.ChannelID != "chn:argocd:source" || proposal.SourceSpecDraft.ChannelType != "source" {
		t.Fatalf("proposal lineage is not exact and broad: %+v", proposal.SourceSpecDraft)
	}
	if len(proposal.SourceSpecDraft.Exclusions) != 0 || proposal.SourceSpecDraft.Exclusions == nil {
		t.Fatalf("explicit empty exclusions lost: %#v", proposal.SourceSpecDraft.Exclusions)
	}
	coreBytes, err := json.Marshal(proposal.InventoryProposalCore)
	if err != nil {
		t.Fatal(err)
	}
	if got := digestBytes(coreBytes); got != proposal.ProposalPayloadSHA256 {
		t.Fatalf("proposal payload digest = %q, want %q", proposal.ProposalPayloadSHA256, got)
	}
	for _, store := range []string{filepath.Join(root, "one"), filepath.Join(root, "two")} {
		if got := countRegularFiles(t, filepath.Join(store, "inventory-proposals")); got != 1 {
			t.Fatalf("proposal files in %s = %d, want 1", store, got)
		}
		if got := countRegularFiles(t, filepath.Join(store, "raw")); got != 0 {
			t.Fatalf("inventory wrote %d raw objects", got)
		}
		if got := countRegularFiles(t, filepath.Join(store, "manifests")); got != 0 {
			t.Fatalf("inventory wrote %d manifests", got)
		}
	}
}

func TestDraftInventorySymlinkQuarantines(t *testing.T) {
	root := t.TempDir()
	mirrorBase := filepath.Join(root, "mirrors")
	copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
	target := filepath.Join(mirrorBase, "argo-cd", "v3.4.5", "CHANGELOG.md")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external.md")
	if err := os.WriteFile(external, []byte("outside mirror\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, target); err != nil {
		t.Fatal(err)
	}
	config := fixtureInventoryConfig(root, mirrorBase)
	_, err := DraftInventory(config)
	requireInventoryRejected(t, err, "symlink_rejected")
	assertNoInventoryProposal(t, config.ProposalStore)
}

func TestDraftInventoryMetadataPathAndProvenanceGates(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*InventoryMetadata)
		codes []string
	}{
		{
			name: "mirror path escape",
			alter: func(metadata *InventoryMetadata) {
				metadata.MirrorPath = "../v3.4.5"
			},
			codes: []string{"mirror_path_escape"},
		},
		{
			name: "generated recursive source",
			alter: func(metadata *InventoryMetadata) {
				metadata.Provenance.Generated = true
				metadata.Provenance.RecursiveSource = true
			},
			codes: []string{"generated_source_rejected", "recursive_source_rejected"},
		},
		{
			name: "oversized stable ID",
			alter: func(metadata *InventoryMetadata) {
				metadata.SnapshotID = "snp:" + strings.Repeat("x", maxStableIDBytes)
			},
			codes: []string{"metadata_scalar_limit_exceeded"},
		},
		{
			name: "exclusion path escape",
			alter: func(metadata *InventoryMetadata) {
				metadata.Exclusions = []InventoryExclusionRule{{
					RelativePath: "../AGENTS.md",
					PathKind:     "file",
					SourceKind:   "local_projection",
					Reason:       "test",
				}}
			},
			codes: []string{"exclusion_path_escape"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			metadata := loadInventoryMetadata(t)
			test.alter(&metadata)
			config := InventoryConfig{
				MetadataPath:  writeInventoryMetadata(t, root, metadata),
				MirrorBase:    filepath.Join("testdata", "mirrors"),
				ProposalStore: filepath.Join(root, "proposals"),
			}
			_, err := DraftInventory(config)
			for _, code := range test.codes {
				requireInventoryRejected(t, err, code)
			}
			assertNoInventoryProposal(t, config.ProposalStore)
		})
	}
}

func TestDraftInventoryResourceLimitsQuarantine(t *testing.T) {
	tests := []struct {
		name   string
		config InventoryConfig
		code   string
	}{
		{name: "file count", config: InventoryConfig{MaxFiles: 3}, code: "file_count_limit_exceeded"},
		{name: "per file bytes", config: InventoryConfig{MaxFileBytes: 80}, code: "file_size_limit_exceeded"},
		{name: "total bytes", config: InventoryConfig{MaxTotalBytes: 200}, code: "total_size_limit_exceeded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.config.MetadataPath = filepath.Join("testdata", "inventory-metadata.json")
			test.config.MirrorBase = filepath.Join("testdata", "mirrors")
			test.config.ProposalStore = filepath.Join(root, "proposals")
			_, err := DraftInventory(test.config)
			requireInventoryRejected(t, err, test.code)
			assertNoInventoryProposal(t, test.config.ProposalStore)
		})
	}
}

func TestDraftInventoryEmptyMetadataQuarantines(t *testing.T) {
	root := t.TempDir()
	metadataPath := filepath.Join(root, "empty.json")
	if err := os.WriteFile(metadataPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := InventoryConfig{
		MetadataPath:  metadataPath,
		MirrorBase:    filepath.Join("testdata", "mirrors"),
		ProposalStore: filepath.Join(root, "proposals"),
	}
	_, err := DraftInventory(config)
	requireInventoryRejected(t, err, "metadata_field_missing")
	assertNoInventoryProposal(t, config.ProposalStore)
}

func TestVerifiedExclusionsBindMixedProvenanceMirror(t *testing.T) {
	root := t.TempDir()
	mirrorBase := filepath.Join(root, "mirrors")
	copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
	mirror := filepath.Join(mirrorBase, "argo-cd", "v3.4.5")
	agentsBytes := []byte("local operational instructions\n")
	releaseBytes := []byte("local release digest\n")
	if err := os.WriteFile(filepath.Join(mirror, "AGENTS.md"), agentsBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(mirror, "releases"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "releases", "local.md"), releaseBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := loadInventoryMetadata(t)
	metadata.Exclusions = []InventoryExclusionRule{
		{
			RelativePath: "AGENTS.md",
			PathKind:     "file",
			SourceKind:   "local_projection",
			Reason:       "repository-local operational guide preserved beside upstream bytes",
		},
		{
			RelativePath: "releases",
			PathKind:     "tree",
			SourceKind:   "derived_summary",
			Reason:       "repository-local release summaries preserved beside upstream bytes",
		},
	}
	config := InventoryConfig{
		MetadataPath:  writeInventoryMetadata(t, root, metadata),
		MirrorBase:    mirrorBase,
		ProposalStore: filepath.Join(root, "proposals"),
	}
	result := mustDraftInventory(t, config)
	if result.Proposal.FileCount != 4 || result.Proposal.ByteSize != 281 ||
		result.Proposal.ExcludedFileCount != 2 || result.Proposal.ExcludedByteSize != int64(len(agentsBytes)+len(releaseBytes)) {
		t.Fatalf("mixed proposal counts = %+v", result.Proposal.InventoryProposalCore)
	}
	if len(result.Proposal.Exclusions) != 2 || len(result.Proposal.SourceSpecDraft.Exclusions) != 2 {
		t.Fatalf("verified exclusion ledger missing: %+v", result.Proposal.Exclusions)
	}
	for index, expectedPath := range []string{"AGENTS.md", "releases/local.md"} {
		exclusion := result.Proposal.Exclusions[index]
		if exclusion.RelativePath != expectedPath || exclusion.SHA256 == "" || exclusion.Size == 0 ||
			exclusion.SourceKind == "" || exclusion.Reason == "" {
			t.Fatalf("exclusion %d is incomplete: %+v", index, exclusion)
		}
	}
	limited := config
	limited.ProposalStore = filepath.Join(root, "limited-proposals")
	limited.MaxFiles = 5
	_, err := DraftInventory(limited)
	requireInventoryRejected(t, err, "file_count_limit_exceeded")
	assertNoInventoryProposal(t, limited.ProposalStore)

	specPath := writeSpec(t, root, result.Proposal.SourceSpecDraft)
	reviewedConfig := createTestReviewAdmission(t, result.Proposal, result.ProposalPath, specPath, root)
	reviewedConfig.MirrorBase = mirrorBase
	reviewedConfig.StoreRoot = filepath.Join(root, "objects")
	compiled, err := Compile(reviewedConfig)
	if err != nil {
		t.Fatalf("Compile() mixed-provenance error = %v", err)
	}
	if compiled.Manifest.ExcludedFileCount != 2 || compiled.Manifest.ExcludedByteSize != result.Proposal.ExcludedByteSize ||
		len(compiled.Manifest.Exclusions) != 2 {
		t.Fatalf("compiled exclusion ledger differs: %+v", compiled.Manifest)
	}
	if got := countRegularFiles(t, filepath.Join(root, "objects", "raw")); got != 3 {
		t.Fatalf("raw object files = %d, want only 3 included unique blobs", got)
	}

	if err := os.WriteFile(filepath.Join(mirror, "AGENTS.md"), []byte("changed local instructions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Compile(reviewedConfig)
	requireQuarantined(t, err, "declared_exclusion_changed")
	if err := os.WriteFile(filepath.Join(mirror, "undeclared.md"), []byte("extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Compile(reviewedConfig)
	requireQuarantined(t, err, "unexpected_file")
}

func TestExcludedSymlinkStillQuarantines(t *testing.T) {
	root := t.TempDir()
	mirrorBase := filepath.Join(root, "mirrors")
	copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
	mirror := filepath.Join(mirrorBase, "argo-cd", "v3.4.5")
	external := filepath.Join(root, "external.md")
	if err := os.WriteFile(external, []byte("external\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(mirror, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	metadata := loadInventoryMetadata(t)
	metadata.Exclusions = []InventoryExclusionRule{{
		RelativePath: "AGENTS.md",
		PathKind:     "file",
		SourceKind:   "local_projection",
		Reason:       "test exclusion",
	}}
	config := InventoryConfig{
		MetadataPath:  writeInventoryMetadata(t, root, metadata),
		MirrorBase:    mirrorBase,
		ProposalStore: filepath.Join(root, "proposals"),
	}
	_, err := DraftInventory(config)
	requireInventoryRejected(t, err, "symlink_rejected")
	assertNoInventoryProposal(t, config.ProposalStore)
}

func TestExclusionPathKindMismatchQuarantines(t *testing.T) {
	root := t.TempDir()
	metadata := loadInventoryMetadata(t)
	metadata.Exclusions = []InventoryExclusionRule{{
		RelativePath: "CHANGELOG.md",
		PathKind:     "tree",
		SourceKind:   "local_projection",
		Reason:       "intentionally wrong kind",
	}}
	config := InventoryConfig{
		MetadataPath:  writeInventoryMetadata(t, root, metadata),
		MirrorBase:    filepath.Join("testdata", "mirrors"),
		ProposalStore: filepath.Join(root, "proposals"),
	}
	_, err := DraftInventory(config)
	requireInventoryRejected(t, err, "exclusion_kind_mismatch")
	assertNoInventoryProposal(t, config.ProposalStore)
}

func TestDraftInventoryRejectsRecursiveProposalStoreOverlapWithoutWrite(t *testing.T) {
	t.Run("valid metadata with store inside mirror", func(t *testing.T) {
		root := t.TempDir()
		mirrorBase := filepath.Join(root, "mirrors")
		copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
		mirrorRoot := filepath.Join(mirrorBase, "argo-cd", "v3.4.5")
		proposalStore := filepath.Join(mirrorRoot, "generated-proposals")
		before := captureTestTree(t, mirrorRoot)

		_, err := DraftInventory(InventoryConfig{
			MetadataPath:  filepath.Join("testdata", "inventory-metadata.json"),
			MirrorBase:    mirrorBase,
			ProposalStore: proposalStore,
		})
		assertInventoryOverlapRejectedWithoutReport(t, err)
		if _, statErr := os.Lstat(proposalStore); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("recursive proposal store was created: %v", statErr)
		}
		if after := captureTestTree(t, mirrorRoot); after != before {
			t.Fatal("input mirror changed after rejected recursive proposal store")
		}
	})

	t.Run("valid metadata with mirror inside store", func(t *testing.T) {
		root := t.TempDir()
		proposalStore := filepath.Join(root, "store")
		mirrorBase := filepath.Join(proposalStore, "mirrors")
		copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
		before := captureTestTree(t, proposalStore)

		_, err := DraftInventory(InventoryConfig{
			MetadataPath:  filepath.Join("testdata", "inventory-metadata.json"),
			MirrorBase:    mirrorBase,
			ProposalStore: proposalStore,
		})
		assertInventoryOverlapRejectedWithoutReport(t, err)
		if after := captureTestTree(t, proposalStore); after != before {
			t.Fatal("proposal-store parent changed after rejected nested input mirror")
		}
	})

	t.Run("missing metadata with store inside mirror base", func(t *testing.T) {
		root := t.TempDir()
		mirrorBase := filepath.Join(root, "mirrors")
		copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
		proposalStore := filepath.Join(mirrorBase, "argo-cd", "v3.4.5", "generated-proposals")
		before := captureTestTree(t, mirrorBase)

		_, err := DraftInventory(InventoryConfig{
			MetadataPath:  filepath.Join(root, "missing-metadata.json"),
			MirrorBase:    mirrorBase,
			ProposalStore: proposalStore,
		})
		assertInventoryOverlapRejectedWithoutReport(t, err)
		if _, statErr := os.Lstat(proposalStore); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("proposal store was created for unavailable metadata: %v", statErr)
		}
		if after := captureTestTree(t, mirrorBase); after != before {
			t.Fatal("mirror base changed after unavailable metadata rejection")
		}
	})

	t.Run("symlinked metadata with mirror base inside store", func(t *testing.T) {
		root := t.TempDir()
		proposalStore := filepath.Join(root, "store")
		mirrorBase := filepath.Join(proposalStore, "mirrors")
		copyTree(t, filepath.Join("testdata", "mirrors"), mirrorBase)
		metadataLink := filepath.Join(root, "metadata-link.json")
		if err := os.Symlink(absoluteTestPath(t, filepath.Join("testdata", "inventory-metadata.json")), metadataLink); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		before := captureTestTree(t, proposalStore)

		_, err := DraftInventory(InventoryConfig{
			MetadataPath:  metadataLink,
			MirrorBase:    mirrorBase,
			ProposalStore: proposalStore,
		})
		assertInventoryOverlapRejectedWithoutReport(t, err)
		if after := captureTestTree(t, proposalStore); after != before {
			t.Fatal("proposal store changed after unsafe metadata rejection")
		}
	})
}

func assertInventoryOverlapRejectedWithoutReport(t *testing.T, err error) {
	t.Helper()
	rejected := requireInventoryRejected(t, err, "recursive_store_overlap")
	if rejected.ReportPath != "" {
		t.Fatalf("unsafe overlap unexpectedly wrote quarantine report %q", rejected.ReportPath)
	}
}

func mustDraftInventory(t *testing.T, config InventoryConfig) InventoryResult {
	t.Helper()
	result, err := DraftInventory(config)
	if err != nil {
		t.Fatalf("DraftInventory() error = %v", err)
	}
	return result
}

func requireInventoryRejected(t *testing.T, err error, code string) *InventoryRejectedError {
	t.Helper()
	var rejected *InventoryRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("error = %v, want InventoryRejectedError", err)
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
	t.Fatalf("inventory quarantine codes = %v, want %q", codes, code)
	return nil
}

func fixtureInventoryConfig(root, mirrorBase string) InventoryConfig {
	return InventoryConfig{
		MetadataPath:  filepath.Join("testdata", "inventory-metadata.json"),
		MirrorBase:    mirrorBase,
		ProposalStore: filepath.Join(root, "proposals"),
	}
}

func loadInventoryMetadata(t *testing.T) InventoryMetadata {
	t.Helper()
	data := mustReadFile(t, filepath.Join("testdata", "inventory-metadata.json"))
	var metadata InventoryMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func writeInventoryMetadata(t *testing.T, directory string, metadata InventoryMetadata) string {
	t.Helper()
	data, err := marshalDocument(metadata)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "inventory-metadata.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func mustReadFile(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertNoInventoryProposal(t *testing.T, store string) {
	t.Helper()
	if got := countRegularFiles(t, filepath.Join(store, "inventory-proposals")); got != 0 {
		t.Fatalf("inventory wrote %d proposals for quarantined input", got)
	}
	if got := countRegularFiles(t, filepath.Join(store, "raw")); got != 0 {
		t.Fatalf("inventory wrote %d raw objects for quarantined input", got)
	}
	if got := countRegularFiles(t, filepath.Join(store, "manifests")); got != 0 {
		t.Fatalf("inventory wrote %d manifests for quarantined input", got)
	}
}

func TestDraftInventoryRequiresNonEmptyConfigurationPaths(t *testing.T) {
	_, err := DraftInventory(InventoryConfig{})
	if err == nil || !strings.Contains(err.Error(), "proposal store is required") {
		t.Fatalf("error = %v, want proposal-store configuration error", err)
	}
}

func createTestReviewAdmission(t *testing.T, proposal InventoryProposal, proposalPath, specPath, directory string) CompileConfig {
	t.Helper()
	receipt := SourceSpecReviewReceipt{
		SchemaVersion:         reviewReceiptSchemaVersion,
		ReceiptKind:           "source_spec_review",
		ProposalID:            proposal.ProposalID,
		ProposalPayloadSHA256: proposal.ProposalPayloadSHA256,
		SourceSpecSHA256:      digestBytes(mustReadFile(t, specPath)),
		Reviewer:              "dynamic-reviewer",
		Decision:              "accepted",
		ReviewedAt:            "2026-07-16T09:30:00Z",
	}
	receiptBytes, err := marshalDocument(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "review-receipt.json")
	if err := os.WriteFile(receiptPath, receiptBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "review-key")
	if output, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("generate review key: %v: %s", err, output)
	}
	publicFields := strings.Fields(string(mustReadFile(t, keyPath+".pub")))
	if len(publicFields) < 2 {
		t.Fatal("generated Ed25519 public key is malformed")
	}
	allowedSignersPath := filepath.Join(directory, "allowed_signers")
	allowed := []byte("dynamic-reviewer " + publicFields[0] + " " + publicFields[1] + "\n")
	if err := os.WriteFile(allowedSignersPath, allowed, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/ssh-keygen", "-Y", "sign", "-q", "-f", keyPath,
		"-n", reviewSignatureNamespace, receiptPath).CombinedOutput(); err != nil {
		t.Fatalf("sign review receipt: %v: %s", err, output)
	}
	return CompileConfig{
		SpecPath:            specPath,
		ProposalPath:        proposalPath,
		ReviewReceiptPath:   receiptPath,
		ReviewSignaturePath: receiptPath + ".sig",
		AllowedSignersPath:  allowedSignersPath,
	}
}
