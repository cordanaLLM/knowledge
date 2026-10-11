package main

import (
	"encoding/json"
	"errors"
	"math"
)

const (
	prettyDocumentBaseOverhead = int64(64 * 1024)
	prettyManifestFileOverhead = int64(256)
	prettyExpectedFileOverhead = int64(192)
	prettyExclusionOverhead    = int64(256)
	prettyChangeOverhead       = int64(512)
)

func projectedManifestFile(spec SourceSpec, file ExpectedFile) ManifestFile {
	digestHex := file.SHA256[len("sha256:"):]
	return ManifestFile{
		RelativePath:       file.RelativePath,
		MediaType:          file.MediaType,
		SHA256:             file.SHA256,
		Size:               file.Size,
		RawBlobID:          "raw:" + file.SHA256,
		ObjectPath:         objectRelativePath(digestHex),
		SnapshotID:         spec.SnapshotID,
		SourceID:           spec.SourceID,
		ComponentID:        spec.ComponentID,
		ComponentVersionID: spec.ComponentVersionID,
		ChannelID:          spec.ChannelID,
	}
}

func validateManifestOutputBudget(spec SourceSpec, admission ReviewAdmission) []QuarantineIssue {
	// Use printable fixed-width placeholders; their byte length, rather than
	// their value, is what controls the encoded-size plan.
	placeholderDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	skeleton := SnapshotManifest{
		ManifestID:            "snapshot-manifest:" + placeholderDigest,
		ManifestPayloadSHA256: placeholderDigest,
		SnapshotManifestCore: SnapshotManifestCore{
			SchemaVersion:    manifestSchemaVersion,
			ManifestKind:     "knowledge_snapshot",
			State:            "complete",
			AuthorityState:   "reviewed",
			ReviewAdmission:  admission,
			SnapshotID:       spec.SnapshotID,
			SourceSpecSHA256: placeholderDigest,
			Source:           sourceLineageFromSpec(spec),
			TreeSHA256:       placeholderDigest,
			FileCount:        len(spec.Files),
			// Maximum-width numeric placeholders make the projection independent
			// from summing attacker-controlled counts before the normal inventory
			// overflow checks run.
			ByteSize:          math.MaxInt64,
			UniqueBlobCount:   len(spec.Files),
			ObjectLayout:      objectLayout,
			ExcludedFileCount: len(spec.Exclusions),
			ExcludedByteSize:  math.MaxInt64,
			Exclusions:        []VerifiedExclusion{},
			Files:             []ManifestFile{},
		},
	}
	total, err := initialJSONBudget(skeleton, maxSnapshotManifestBytes)
	if err != nil {
		return []QuarantineIssue{issue("manifest_output_limit_exceeded", "<manifest>",
			"snapshot manifest metadata exceeds the downstream 64 MiB input limit")}
	}
	for _, file := range spec.Files {
		if !addJSONBudget(&total, projectedManifestFile(spec, file), prettyManifestFileOverhead, maxSnapshotManifestBytes) {
			return []QuarantineIssue{issue("manifest_output_limit_exceeded", "files",
				"projected snapshot manifest exceeds the downstream 64 MiB input limit")}
		}
	}
	for _, exclusion := range spec.Exclusions {
		if !addJSONBudget(&total, exclusion, prettyExclusionOverhead, maxSnapshotManifestBytes) {
			return []QuarantineIssue{issue("manifest_output_limit_exceeded", "exclusions",
				"projected snapshot manifest exceeds the downstream 64 MiB input limit")}
		}
	}
	return nil
}

func validateChangePackOutputBudget(oldManifest, newManifest SnapshotManifest) []QuarantineIssue {
	placeholderDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	skeleton := ChangePackManifest{
		ChangePackID:            "change-pack:" + placeholderDigest,
		ChangePackPayloadSHA256: placeholderDigest,
		ChangePackManifestCore: ChangePackManifestCore{
			SchemaVersion:   manifestSchemaVersion,
			ManifestKind:    changePackManifestKind,
			State:           "complete",
			AuthorityState:  "derived_non_authoritative",
			PromoteEligible: false,
			OrderingBasis:   changePackOrdering,
			ObjectLayout:    changePackLayout,
			OldSnapshot:     snapshotBinding(oldManifest),
			NewSnapshot:     snapshotBinding(newManifest),
			Counts: ChangePackCounts{
				Added:     len(newManifest.Files),
				Removed:   len(oldManifest.Files),
				Changed:   len(oldManifest.Files),
				Unchanged: len(oldManifest.Files),
			},
			Changes: []FileOccurrenceChange{},
		},
	}
	total, err := initialJSONBudget(skeleton, maxChangePackBytes)
	if err != nil {
		return []QuarantineIssue{issue("change_pack_output_limit_exceeded", "<change-pack>",
			"change-pack bindings exceed the 64 MiB output limit")}
	}
	exceeded := false
	walkFileOccurrenceChanges(oldManifest.Files, newManifest.Files, func(change FileOccurrenceChange) bool {
		if !addJSONBudget(&total, change, prettyChangeOverhead, maxChangePackBytes) {
			exceeded = true
			return false
		}
		return true
	})
	if exceeded {
		return []QuarantineIssue{issue("change_pack_output_limit_exceeded", "changes",
			"projected change pack exceeds the 64 MiB output limit")}
	}
	return nil
}

func validateSourceSpecOutputBudget(spec SourceSpec) []QuarantineIssue {
	skeleton := spec
	skeleton.Files = []ExpectedFile{}
	skeleton.Exclusions = []VerifiedExclusion{}
	total, err := initialJSONBudget(skeleton, maxSourceSpecBytes)
	if err != nil {
		return []QuarantineIssue{issue("source_spec_output_limit_exceeded", "<source-spec>",
			"source specification exceeds the downstream 32 MiB review-artifact limit")}
	}
	for _, file := range spec.Files {
		if !addJSONBudget(&total, file, prettyExpectedFileOverhead, maxSourceSpecBytes) {
			return []QuarantineIssue{issue("source_spec_output_limit_exceeded", "files",
				"source specification exceeds the downstream 32 MiB review-artifact limit")}
		}
	}
	for _, exclusion := range spec.Exclusions {
		if !addJSONBudget(&total, exclusion, prettyExclusionOverhead, maxSourceSpecBytes) {
			return []QuarantineIssue{issue("source_spec_output_limit_exceeded", "exclusions",
				"source specification exceeds the downstream 32 MiB review-artifact limit")}
		}
	}
	return nil
}

func validateInventoryProposalOutputBudget(metadata InventoryMetadata, files []ExpectedFile, exclusions []VerifiedExclusion,
	includedBytes, excludedBytes int64) []QuarantineIssue {
	draft := metadata.toSourceSpec([]ExpectedFile{}, []VerifiedExclusion{})
	placeholderDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	skeleton := InventoryProposal{
		ProposalID:            "inventory-proposal:" + placeholderDigest,
		ProposalPayloadSHA256: placeholderDigest,
		InventoryProposalCore: InventoryProposalCore{
			SchemaVersion:     sourceSpecSchemaVersion,
			ProposalKind:      "source_spec_inventory_proposal",
			State:             "proposal",
			ReviewState:       "unreviewed",
			AuthorityState:    "non_authoritative",
			MetadataSHA256:    placeholderDigest,
			FileCount:         len(files),
			ByteSize:          includedBytes,
			ExcludedFileCount: len(exclusions),
			ExcludedByteSize:  excludedBytes,
			Exclusions:        []VerifiedExclusion{},
			SourceSpecDraft:   draft,
		},
	}
	total, err := initialJSONBudget(skeleton, maxInventoryProposalBytes)
	if err != nil {
		return []QuarantineIssue{issue("inventory_proposal_output_limit_exceeded", "<proposal>",
			"inventory proposal exceeds the downstream 40 MiB review-artifact limit")}
	}
	for _, file := range files {
		if !addJSONBudget(&total, file, prettyExpectedFileOverhead, maxInventoryProposalBytes) {
			return []QuarantineIssue{issue("inventory_proposal_output_limit_exceeded", "files",
				"inventory proposal exceeds the downstream 40 MiB review-artifact limit")}
		}
	}
	for _, exclusion := range exclusions {
		// Every verified exclusion appears in both the proposal ledger and its
		// embedded source-spec draft.
		if !addJSONBudget(&total, exclusion, 2*prettyExclusionOverhead, maxInventoryProposalBytes) ||
			!addJSONBudget(&total, exclusion, 0, maxInventoryProposalBytes) {
			return []QuarantineIssue{issue("inventory_proposal_output_limit_exceeded", "exclusions",
				"inventory proposal exceeds the downstream 40 MiB review-artifact limit")}
		}
	}
	return nil
}

func initialJSONBudget(value any, limit int64) (int64, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	total := int64(len(data))
	if prettyDocumentBaseOverhead > limit-total {
		return 0, errors.New("output budget exceeded")
	}
	return total + prettyDocumentBaseOverhead, nil
}

func addJSONBudget(total *int64, value any, prettyOverhead, limit int64) bool {
	data, err := json.Marshal(value)
	if err != nil {
		return false
	}
	addition := int64(len(data)) + prettyOverhead + 1 // one possible array comma
	if addition > limit-*total {
		return false
	}
	*total += addition
	return true
}
