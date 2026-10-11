package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const maxInventoryMetadataBytes = int64(1024 * 1024)

var deterministicMediaTypes = map[string]string{
	".cff":   "application/yaml",
	".conf":  "text/plain",
	".css":   "text/css",
	".csv":   "text/csv",
	".gif":   "image/gif",
	".go":    "text/x-go",
	".gz":    "application/gzip",
	".htm":   "text/html",
	".html":  "text/html",
	".ico":   "image/x-icon",
	".jpeg":  "image/jpeg",
	".jpg":   "image/jpeg",
	".js":    "text/javascript",
	".json":  "application/json",
	".lock":  "text/plain",
	".md":    "text/markdown",
	".pdf":   "application/pdf",
	".png":   "image/png",
	".proto": "text/plain",
	".svg":   "image/svg+xml",
	".tgz":   "application/gzip",
	".toml":  "application/toml",
	".ts":    "text/typescript",
	".txt":   "text/plain",
	".webp":  "image/webp",
	".xml":   "application/xml",
	".yaml":  "application/yaml",
	".yml":   "application/yaml",
}

var inventoryMetadataFields = []string{
	"schema_version", "snapshot_id", "source_id", "canonical_uri",
	"component_id", "component_version_id", "resolved_version",
	"source_revision", "channel_id", "channel_type", "rights",
	"access_scope", "classification", "security_domain", "language",
	"fetched_at", "observed_at", "mirror_path", "provenance", "exclusions",
}

func DraftInventory(config InventoryConfig) (InventoryResult, error) {
	var zero InventoryResult
	if strings.TrimSpace(config.ProposalStore) == "" {
		return zero, errors.New("proposal store is required")
	}
	if strings.TrimSpace(config.MirrorBase) == "" {
		return zero, errors.New("mirror base is required")
	}
	limits, err := normalizedLimits(CompileConfig{
		MaxFiles:      config.MaxFiles,
		MaxFileBytes:  config.MaxFileBytes,
		MaxTotalBytes: config.MaxTotalBytes,
	})
	if err != nil {
		return zero, err
	}
	proposalStore, err := filepath.Abs(config.ProposalStore)
	if err != nil {
		return zero, fmt.Errorf("resolve proposal store: %w", err)
	}
	base, baseErr := filepath.Abs(config.MirrorBase)
	issues := make([]QuarantineIssue, 0)
	if baseErr != nil {
		issues = append(issues, issue("mirror_base_invalid", "<mirror-base>", "mirror base path is invalid"))
	}

	metadataBytes, readErr := readBoundedRegular(config.MetadataPath, maxInventoryMetadataBytes)
	metadataDigest := digestBytes(metadataBytes)
	var metadata InventoryMetadata
	var metadataIssues []QuarantineIssue
	if readErr != nil {
		metadataDigest = digestBytes(nil)
		metadataIssues = append(metadataIssues, issue("inventory_metadata_read_failed", "<metadata>", "inventory metadata could not be read"))
	} else {
		metadataIssues = decodeInventoryMetadata(metadataBytes, &metadata)
		if len(metadataIssues) == 0 {
			metadataIssues = append(metadataIssues, validateInventoryMetadata(metadataBytes, metadata)...)
		}
	}
	issues = append(issues, metadataIssues...)

	var mirrorRoot string
	if baseErr == nil && len(metadataIssues) == 0 {
		mirrorRoot = filepath.Join(base, filepath.FromSlash(metadata.MirrorPath))
		if !isWithin(base, mirrorRoot) {
			issues = append(issues, issue("mirror_path_escape", metadata.MirrorPath, "mirror path escapes the declared mirror base"))
		}
	}
	if baseErr == nil {
		issues = append(issues, validateNoSymlinkPath(base, "<mirror-base>")...)
	}
	if mirrorRoot != "" {
		issues = append(issues, validateNoSymlinkPath(mirrorRoot, "<mirror>")...)
	}
	unsafeOverlap := mirrorRoot != "" && pathsOverlap(mirrorRoot, proposalStore)
	if mirrorRoot == "" && baseErr == nil && pathsOverlap(base, proposalStore) {
		// Invalid or unavailable metadata cannot prove a narrower input root.
		// Refuse to create a quarantine store anywhere that overlaps the
		// configured mirror base.
		unsafeOverlap = true
	}
	if unsafeOverlap {
		issues = append(issues, issue("recursive_store_overlap", "<mirror>", "mirror and generated proposal-store paths overlap"))
		return zero, &InventoryRejectedError{Issues: sortedIssues(issues)}
	}
	output, err := openOutputStore(proposalStore)
	if err != nil {
		return zero, fmt.Errorf("open safe proposal store: %w", err)
	}
	defer output.Close()
	if len(issues) != 0 {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, issues)
	}

	files, exclusions, includedBytes, excludedBytes, inventoryIssues := inventoryMirror(mirrorRoot, metadata.Exclusions, limits)
	if len(inventoryIssues) != 0 {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, inventoryIssues)
	}
	draft := metadata.toSourceSpec(files, exclusions)
	if draftIssues := validateSourceSpec(draft); len(draftIssues) != 0 {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, draftIssues)
	}
	if budgetIssues := validateSourceSpecOutputBudget(draft); len(budgetIssues) != 0 {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, budgetIssues)
	}
	if budgetIssues := validateInventoryProposalOutputBudget(metadata, files, exclusions, includedBytes, excludedBytes); len(budgetIssues) != 0 {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, budgetIssues)
	}
	core := InventoryProposalCore{
		SchemaVersion:     sourceSpecSchemaVersion,
		ProposalKind:      "source_spec_inventory_proposal",
		State:             "proposal",
		ReviewState:       "unreviewed",
		AuthorityState:    "non_authoritative",
		CompileEligible:   false,
		PromoteEligible:   false,
		MetadataSHA256:    metadataDigest,
		FileCount:         len(files),
		ByteSize:          includedBytes,
		ExcludedFileCount: len(exclusions),
		ExcludedByteSize:  excludedBytes,
		Exclusions:        exclusions,
		SourceSpecDraft:   draft,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, []QuarantineIssue{
			issue("inventory_proposal_encode_failed", "<proposal>", "inventory proposal could not be encoded"),
		})
	}
	payloadDigest := digestBytes(coreBytes)
	proposal := InventoryProposal{
		ProposalID:            "inventory-proposal:" + payloadDigest,
		ProposalPayloadSHA256: payloadDigest,
		InventoryProposalCore: core,
	}
	proposalBytes, err := marshalDocument(proposal)
	if err != nil {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, []QuarantineIssue{
			issue("inventory_proposal_encode_failed", "<proposal>", "inventory proposal could not be encoded"),
		})
	}
	if int64(len(proposalBytes)) > maxInventoryProposalBytes {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, []QuarantineIssue{
			issue("inventory_proposal_output_limit_exceeded", "<proposal>", "encoded inventory proposal exceeds the downstream 40 MiB review-artifact limit"),
		})
	}
	hexDigest := strings.TrimPrefix(payloadDigest, "sha256:")
	relative := path.Join("inventory-proposals", "sha256", hexDigest[:2], hexDigest+".json")
	proposalPath := filepath.Join(proposalStore, filepath.FromSlash(relative))
	if err := output.writeImmutable(relative, proposalBytes, 0o444); err != nil {
		return zero, inventoryQuarantine(output, metadataDigest, metadata, []QuarantineIssue{
			issue("inventory_proposal_commit_failed", relative, "inventory proposal could not be committed atomically"),
		})
	}
	return InventoryResult{Proposal: proposal, ProposalPath: proposalPath}, nil
}

func (metadata InventoryMetadata) toSourceSpec(files []ExpectedFile, exclusions []VerifiedExclusion) SourceSpec {
	return SourceSpec{
		SchemaVersion:      metadata.SchemaVersion,
		SnapshotID:         metadata.SnapshotID,
		SourceID:           metadata.SourceID,
		CanonicalURI:       metadata.CanonicalURI,
		ComponentID:        metadata.ComponentID,
		ComponentVersionID: metadata.ComponentVersionID,
		ResolvedVersion:    metadata.ResolvedVersion,
		SourceRevision:     metadata.SourceRevision,
		ChannelID:          metadata.ChannelID,
		ChannelType:        metadata.ChannelType,
		Rights:             metadata.Rights,
		AccessScope:        metadata.AccessScope,
		Classification:     metadata.Classification,
		SecurityDomain:     metadata.SecurityDomain,
		Language:           metadata.Language,
		FetchedAt:          metadata.FetchedAt,
		ObservedAt:         metadata.ObservedAt,
		MirrorPath:         metadata.MirrorPath,
		Provenance:         metadata.Provenance,
		Exclusions:         exclusions,
		Files:              files,
	}
}

func decodeInventoryMetadata(data []byte, metadata *InventoryMetadata) []QuarantineIssue {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(metadata); err != nil {
		return []QuarantineIssue{issue("inventory_metadata_invalid_json", "<metadata>", "inventory metadata is not valid strict JSON")}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return []QuarantineIssue{issue("inventory_metadata_multiple_values", "<metadata>", "inventory metadata contains more than one JSON value")}
	}
	return nil
}

func validateInventoryMetadata(data []byte, metadata InventoryMetadata) []QuarantineIssue {
	issues := make([]QuarantineIssue, 0)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		for _, field := range inventoryMetadataFields {
			value, exists := raw[field]
			if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				issues = append(issues, issue("metadata_field_missing", field, "inventory metadata field must be explicit"))
			}
		}
		issues = append(issues, requireNestedFields(raw, "provenance", []string{"origin_kind", "generated", "recursive_source"})...)
		issues = append(issues, requireNestedFields(raw, "rights", []string{"license_expression", "rights_basis", "attribution", "permissions"})...)
	}
	draft := metadata.toSourceSpec([]ExpectedFile{{
		RelativePath: "placeholder",
		MediaType:    "application/octet-stream",
		SHA256:       "sha256:" + strings.Repeat("0", 64),
		Size:         0,
	}}, []VerifiedExclusion{})
	metadataIssues := validateSourceMetadata(draft)
	issues = append(issues, metadataIssues...)
	if len(metadataIssues) != 0 {
		return sortedIssues(issues)
	}
	if err := validateRelativePath(metadata.MirrorPath); err != nil {
		issues = append(issues, issue("mirror_path_escape", "mirror_path", "mirror path must be canonical and remain below mirror base"))
	}
	if metadata.Exclusions == nil {
		issues = append(issues, issue("exclusions_missing", "exclusions", "inventory metadata must explicitly declare an exclusions array"))
	}
	if len(metadata.Exclusions) > maxSourceInventoryEntries {
		issues = append(issues, issue("metadata_collection_limit_exceeded", "exclusions",
			"inventory exclusion collection exceeds the absolute schema entry limit"))
		return sortedIssues(issues)
	}
	seen := make(map[string]InventoryExclusionRule, len(metadata.Exclusions))
	for index, exclusion := range metadata.Exclusions {
		fieldPath := fmt.Sprintf("exclusions[%d]", index)
		if boundIssues := validateInventoryExclusionBounds(exclusion, fieldPath); len(boundIssues) != 0 {
			issues = append(issues, boundIssues...)
			continue
		}
		if err := validateRelativePath(exclusion.RelativePath); err != nil {
			issues = append(issues, issue("exclusion_path_escape", exclusion.RelativePath, "exclusion path must be canonical and remain inside the mirror"))
		}
		if exclusion.PathKind != "file" && exclusion.PathKind != "tree" {
			issues = append(issues, issue("exclusion_path_kind_invalid", fieldPath+".path_kind", "exclusion path kind must be file or tree"))
		}
		if _, ok := exclusionSourceKinds[exclusion.SourceKind]; !ok {
			issues = append(issues, issue("exclusion_source_kind_invalid", fieldPath+".source_kind", "exclusion requires an explicit non-authoritative source kind"))
		}
		if strings.TrimSpace(exclusion.Reason) == "" {
			issues = append(issues, issue("exclusion_reason_missing", fieldPath+".reason", "exclusion requires a reason"))
		}
		if previous, exists := seen[exclusion.RelativePath]; exists {
			issues = append(issues, issue("exclusion_duplicate", exclusion.RelativePath, "exclusion path is declared more than once"))
			_ = previous
		}
		for priorPath, prior := range seen {
			if (prior.PathKind == "tree" && pathIsBelow(priorPath, exclusion.RelativePath)) ||
				(exclusion.PathKind == "tree" && pathIsBelow(exclusion.RelativePath, priorPath)) {
				issues = append(issues, issue("exclusion_overlap", exclusion.RelativePath, "exclusion rules overlap"))
			}
		}
		seen[exclusion.RelativePath] = exclusion
	}
	return sortedIssues(issues)
}

func requireNestedFields(raw map[string]json.RawMessage, parent string, fields []string) []QuarantineIssue {
	value, exists := raw[parent]
	if !exists {
		return nil
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(value, &nested); err != nil {
		return nil
	}
	issues := make([]QuarantineIssue, 0)
	for _, field := range fields {
		item, found := nested[field]
		if !found || bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
			issues = append(issues, issue("metadata_field_missing", parent+"."+field, "inventory metadata field must be explicit"))
		}
	}
	return issues
}

func inventoryMirror(root string, rules []InventoryExclusionRule, limits compileLimits) ([]ExpectedFile, []VerifiedExclusion, int64, int64, []QuarantineIssue) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, nil, 0, 0, []QuarantineIssue{issue("mirror_unavailable", "<mirror>", "mirror root is not an available directory")}
	}
	ruleByPath := make(map[string]InventoryExclusionRule, len(rules))
	foundRules := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		ruleByPath[rule.RelativePath] = rule
	}
	files := make([]ExpectedFile, 0)
	exclusions := make([]VerifiedExclusion, 0)
	issues := make([]QuarantineIssue, 0)
	fileCount := 0
	var totalBytes, includedBytes, excludedBytes int64
	walkErr := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			issues = append(issues, issue("mirror_walk_failed", "<mirror>", "mirror tree could not be read completely"))
			return fs.SkipAll
		}
		if current == root {
			return nil
		}
		relativeOS, relErr := filepath.Rel(root, current)
		if relErr != nil || !isWithin(root, current) {
			issues = append(issues, issue("mirror_path_escape", "<mirror>", "mirror entry escapes the mirror root"))
			return fs.SkipAll
		}
		relative := filepath.ToSlash(relativeOS)
		if entry.Type()&os.ModeSymlink != 0 {
			issues = append(issues, issue("symlink_rejected", relative, "symlinks are forbidden in inventory mirrors"))
			return nil
		}
		exactRule, exactExcluded := ruleByPath[relative]
		if entry.IsDir() {
			if exactExcluded {
				if exactRule.PathKind != "tree" {
					issues = append(issues, issue("exclusion_kind_mismatch", relative, "file exclusion points to a directory"))
				} else {
					foundRules[relative] = struct{}{}
				}
			}
			return nil
		}
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			issues = append(issues, issue("mirror_entry_unreadable", relative, "mirror entry could not be inspected"))
			return nil
		}
		if !entryInfo.Mode().IsRegular() {
			issues = append(issues, issue("special_file_rejected", relative, "only regular files are accepted"))
			return nil
		}
		if exactExcluded && exactRule.PathKind == "tree" {
			issues = append(issues, issue("exclusion_kind_mismatch", relative, "tree exclusion points to a regular file"))
			return nil
		}
		fileCount++
		if fileCount > limits.maxFiles {
			issues = append(issues, issue("file_count_limit_exceeded", "<mirror>", "mirror exceeds the configured file-count limit"))
			return fs.SkipAll
		}
		if entryInfo.Size() > limits.maxFileBytes {
			issues = append(issues, issue("file_size_limit_exceeded", relative, "mirror file exceeds the configured per-file byte limit"))
			return nil
		}
		if entryInfo.Size() > limits.maxTotalBytes-totalBytes {
			issues = append(issues, issue("total_size_limit_exceeded", "<mirror>", "mirror exceeds the configured total-byte limit"))
			return fs.SkipAll
		}
		totalBytes += entryInfo.Size()
		digest, size, hashErr := hashInput(current)
		if hashErr != nil {
			issues = append(issues, issue("source_file_read_failed", relative, "source file could not be read safely"))
			return nil
		}
		mediaType := mediaTypeForPath(relative)
		rule, excluded := matchingExclusionRule(relative, rules)
		if excluded {
			foundRules[rule.RelativePath] = struct{}{}
			if rule.PathKind == "file" && rule.RelativePath != relative {
				issues = append(issues, issue("exclusion_kind_mismatch", relative, "file exclusion does not exactly match the file"))
				return nil
			}
			exclusions = append(exclusions, VerifiedExclusion{
				RelativePath: relative,
				MediaType:    mediaType,
				SHA256:       digest,
				Size:         size,
				SourceKind:   rule.SourceKind,
				Reason:       rule.Reason,
			})
			excludedBytes += size
			return nil
		}
		files = append(files, ExpectedFile{RelativePath: relative, MediaType: mediaType, SHA256: digest, Size: size})
		includedBytes += size
		return nil
	})
	if walkErr != nil {
		issues = append(issues, issue("mirror_walk_failed", "<mirror>", "mirror tree could not be read completely"))
	}
	for _, rule := range rules {
		if _, found := foundRules[rule.RelativePath]; !found {
			issues = append(issues, issue("exclusion_not_found", rule.RelativePath, "declared exclusion was not found in the mirror"))
		}
	}
	if len(files) == 0 {
		issues = append(issues, issue("file_inventory_empty", "<mirror>", "inventory contains no includable regular files"))
	}
	sort.Slice(files, func(i, j int) bool { return files[i].RelativePath < files[j].RelativePath })
	sort.Slice(exclusions, func(i, j int) bool { return exclusions[i].RelativePath < exclusions[j].RelativePath })
	return files, exclusions, includedBytes, excludedBytes, sortedIssues(issues)
}

func matchingExclusionRule(relative string, rules []InventoryExclusionRule) (InventoryExclusionRule, bool) {
	for _, rule := range rules {
		if rule.PathKind == "file" && relative == rule.RelativePath {
			return rule, true
		}
		if rule.PathKind == "tree" && pathIsBelow(rule.RelativePath, relative) {
			return rule, true
		}
	}
	return InventoryExclusionRule{}, false
}

func pathIsBelow(parent, candidate string) bool {
	return candidate == parent || strings.HasPrefix(candidate, parent+"/")
}

func mediaTypeForPath(relative string) string {
	if mediaType, ok := deterministicMediaTypes[strings.ToLower(path.Ext(relative))]; ok {
		return mediaType
	}
	return "application/octet-stream"
}

func inventoryQuarantine(store *outputStore, metadataDigest string, metadata InventoryMetadata, issues []QuarantineIssue) error {
	issues = sortedIssues(issues)
	identityPayload, _ := json.Marshal(struct {
		MetadataSHA256 string            `json:"metadata_sha256"`
		Issues         []QuarantineIssue `json:"issues"`
	}{MetadataSHA256: metadataDigest, Issues: issues})
	digest := digestBytes(identityPayload)
	report := InventoryQuarantineReport{
		SchemaVersion:      sourceSpecSchemaVersion,
		ReportKind:         "inventory_proposal_quarantine",
		State:              "quarantined",
		QuarantineID:       "inventory-quarantine:" + digest,
		MetadataSHA256:     metadataDigest,
		SnapshotID:         boundedReportScalar(metadata.SnapshotID, maxStableIDBytes),
		SourceID:           boundedReportScalar(metadata.SourceID, maxStableIDBytes),
		ComponentID:        boundedReportScalar(metadata.ComponentID, maxStableIDBytes),
		ComponentVersionID: boundedReportScalar(metadata.ComponentVersionID, maxStableIDBytes),
		ChannelID:          boundedReportScalar(metadata.ChannelID, maxStableIDBytes),
		Issues:             issues,
	}
	data, _ := marshalDocument(report)
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	relative := path.Join("inventory-quarantine", "sha256", hexDigest[:2], hexDigest+".json")
	reportPath := filepath.Join(store.path, filepath.FromSlash(relative))
	if err := store.writeImmutable(relative, data, 0o444); err != nil {
		return fmt.Errorf("inventory invalid and quarantine report failed: %w", err)
	}
	return &InventoryRejectedError{ReportPath: reportPath, Issues: issues}
}
