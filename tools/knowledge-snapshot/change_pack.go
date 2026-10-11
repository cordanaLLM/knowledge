package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	changePackManifestKind = "knowledge_snapshot_change_pack"
	changePackOrdering     = "strict-fetched-observed-reviewed-time-v1"
	changePackLayout       = "change-packs/sha256/<first-two>/<hex>.json"
)

type verifiedSnapshot struct {
	Manifest SnapshotManifest
	Spec     SourceSpec
}

func BuildChangePack(config ChangePackConfig) (ChangePackResult, error) {
	var zero ChangePackResult
	requiredPaths := []struct {
		name  string
		value string
	}{
		{"old manifest", config.OldManifestPath},
		{"old store", config.OldStoreRoot},
		{"old allowed signers", config.OldAllowedSignersPath},
		{"new manifest", config.NewManifestPath},
		{"new store", config.NewStoreRoot},
		{"new allowed signers", config.NewAllowedSignersPath},
		{"output store", config.StoreRoot},
	}
	for _, required := range requiredPaths {
		if strings.TrimSpace(required.value) == "" {
			return zero, fmt.Errorf("%s is required", required.name)
		}
	}
	output, err := openOutputStore(config.StoreRoot)
	if err != nil {
		return zero, fmt.Errorf("open safe change-pack store: %w", err)
	}
	defer output.Close()

	forbiddenTrustRoots := []string{config.OldStoreRoot, config.NewStoreRoot}
	oldSnapshot, oldIssues := verifySnapshotInput("old", config.OldManifestPath, config.OldStoreRoot,
		config.OldAllowedSignersPath, forbiddenTrustRoots)
	newSnapshot, newIssues := verifySnapshotInput("new", config.NewManifestPath, config.NewStoreRoot,
		config.NewAllowedSignersPath, forbiddenTrustRoots)
	issues := append(oldIssues, newIssues...)
	if len(issues) == 0 {
		issues = append(issues, validateChangeLineage(oldSnapshot.Manifest, newSnapshot.Manifest)...)
	}
	if len(issues) != 0 {
		return zero, &ChangePackRejectedError{Issues: sortedIssues(issues)}
	}
	if budgetIssues := validateChangePackOutputBudget(oldSnapshot.Manifest, newSnapshot.Manifest); len(budgetIssues) != 0 {
		return zero, &ChangePackRejectedError{Issues: budgetIssues}
	}

	changes, counts := compareFileOccurrences(oldSnapshot.Manifest.Files, newSnapshot.Manifest.Files)
	core := ChangePackManifestCore{
		SchemaVersion:   manifestSchemaVersion,
		ManifestKind:    changePackManifestKind,
		State:           "complete",
		AuthorityState:  "derived_non_authoritative",
		PromoteEligible: false,
		OrderingBasis:   changePackOrdering,
		ObjectLayout:    changePackLayout,
		OldSnapshot:     snapshotBinding(oldSnapshot.Manifest),
		NewSnapshot:     snapshotBinding(newSnapshot.Manifest),
		Counts:          counts,
		Changes:         changes,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return zero, err
	}
	payloadDigest := digestBytes(coreBytes)
	manifest := ChangePackManifest{
		ChangePackID:            "change-pack:" + payloadDigest,
		ChangePackPayloadSHA256: payloadDigest,
		ChangePackManifestCore:  core,
	}
	manifestBytes, err := marshalDocument(manifest)
	if err != nil {
		return zero, err
	}
	if int64(len(manifestBytes)) > maxChangePackBytes {
		return zero, &ChangePackRejectedError{Issues: []QuarantineIssue{
			issue("change_pack_output_limit_exceeded", "changes", "encoded change pack exceeds the 64 MiB output limit"),
		}}
	}
	hexDigest := strings.TrimPrefix(payloadDigest, "sha256:")
	relative := path.Join("change-packs", "sha256", hexDigest[:2], hexDigest+".json")
	store := output.path
	manifestPath := filepath.Join(store, filepath.FromSlash(relative))
	if err := output.writeImmutable(relative, manifestBytes, 0o444); err != nil {
		return zero, fmt.Errorf("commit immutable change pack: %w", err)
	}
	return ChangePackResult{Manifest: manifest, ManifestPath: manifestPath}, nil
}

func verifySnapshotInput(label, manifestPath, storeRoot, allowedSignersPath string, forbiddenTrustRoots []string) (verifiedSnapshot, []QuarantineIssue) {
	var zero verifiedSnapshot
	store, err := filepath.Abs(storeRoot)
	if err != nil || validateExistingPathComponents(store) != nil {
		return zero, []QuarantineIssue{issue("change_input_store_invalid", label, "snapshot store must be an existing non-symlink path")}
	}
	trustedPolicyPath, trustedPolicyBytes, trustIssues := readExternalTrustRoot(label, allowedSignersPath, forbiddenTrustRoots)
	if len(trustIssues) != 0 {
		return zero, trustIssues
	}
	manifestBytes, err := readBoundedRegular(manifestPath, maxSnapshotManifestBytes)
	if err != nil {
		return zero, []QuarantineIssue{issue("change_input_manifest_read_failed", label, "snapshot manifest must be a bounded regular non-symlink file")}
	}
	var manifest SnapshotManifest
	if err := decodeStrictDocument(manifestBytes, &manifest); err != nil {
		return zero, []QuarantineIssue{issue("change_input_manifest_invalid", label, "snapshot manifest is not strict canonical JSON")}
	}
	if boundIssues := validateSnapshotDocumentBounds(manifest); len(boundIssues) != 0 {
		for index := range boundIssues {
			boundIssues[index].Path = label + "/" + boundIssues[index].Path
		}
		return zero, boundIssues
	}
	canonicalManifest, err := marshalDocument(manifest)
	if err != nil || !bytes.Equal(canonicalManifest, manifestBytes) {
		return zero, []QuarantineIssue{issue("change_input_manifest_noncanonical", label, "snapshot manifest bytes are not canonical")}
	}
	coreBytes, err := json.Marshal(manifest.SnapshotManifestCore)
	if err != nil {
		return zero, []QuarantineIssue{issue("change_input_manifest_invalid", label, "snapshot manifest payload cannot be encoded")}
	}
	payloadDigest := digestBytes(coreBytes)
	if manifest.ManifestPayloadSHA256 != payloadDigest || manifest.ManifestID != "snapshot-manifest:"+payloadDigest {
		return zero, []QuarantineIssue{issue("change_input_manifest_identity_mismatch", label, "snapshot manifest identity is not content-derived")}
	}
	hexDigest := strings.TrimPrefix(payloadDigest, "sha256:")
	expectedManifestPath := filepath.Join(store, "manifests", "sha256", hexDigest[:2], hexDigest+".json")
	absoluteManifestPath, err := filepath.Abs(manifestPath)
	if err != nil || filepath.Clean(absoluteManifestPath) != filepath.Clean(expectedManifestPath) {
		return zero, []QuarantineIssue{issue("change_input_manifest_path_invalid", label, "snapshot manifest is not at its exact content-addressed store path")}
	}
	if manifest.SchemaVersion != manifestSchemaVersion || manifest.ManifestKind != "knowledge_snapshot" ||
		manifest.State != "complete" || manifest.AuthorityState != "reviewed" {
		return zero, []QuarantineIssue{issue("change_input_manifest_unreviewed", label, "only complete reviewed snapshot manifests can enter a change pack")}
	}

	specPath, artifactIssues := reviewCASPath(store, manifest.ReviewAdmission.SourceSpecObjectPath,
		manifest.ReviewAdmission.SourceSpecSHA256, manifest.ReviewAdmission.SourceSpecSize, label+"/source-spec")
	issues := append([]QuarantineIssue(nil), artifactIssues...)
	reviewReferences := []struct {
		objectPath string
		digest     string
		size       int64
		label      string
	}{
		{manifest.ReviewAdmission.ProposalObjectPath, manifest.ReviewAdmission.ProposalDocumentSHA256, manifest.ReviewAdmission.ProposalDocumentSize, "proposal"},
		{manifest.ReviewAdmission.ReceiptObjectPath, manifest.ReviewAdmission.ReceiptSHA256, manifest.ReviewAdmission.ReceiptSize, "receipt"},
		{manifest.ReviewAdmission.SignatureObjectPath, manifest.ReviewAdmission.SignatureSHA256, manifest.ReviewAdmission.SignatureSize, "signature"},
		{manifest.ReviewAdmission.TrustPolicyObjectPath, manifest.ReviewAdmission.TrustPolicySHA256, manifest.ReviewAdmission.TrustPolicySize, "trust-policy"},
	}
	resolvedReviewPaths := make(map[string]string, len(reviewReferences))
	for _, reference := range reviewReferences {
		resolved, referenceIssues := reviewCASPath(store, reference.objectPath, reference.digest, reference.size, label+"/"+reference.label)
		issues = append(issues, referenceIssues...)
		resolvedReviewPaths[reference.label] = resolved
	}
	if len(issues) != 0 {
		return zero, issues
	}
	storedPolicyPath := resolvedReviewPaths["trust-policy"]
	storedPolicyBytes, storedPolicyErr := readBoundedRegular(storedPolicyPath, maxAllowedSignersBytes)
	trustedInfo, trustedStatErr := os.Lstat(trustedPolicyPath)
	storedInfo, storedStatErr := os.Lstat(storedPolicyPath)
	if storedPolicyErr != nil || digestBytes(storedPolicyBytes) != manifest.ReviewAdmission.TrustPolicySHA256 ||
		int64(len(storedPolicyBytes)) != manifest.ReviewAdmission.TrustPolicySize {
		return zero, []QuarantineIssue{issue("change_input_trust_policy_invalid", label, "retained review trust policy is missing, mutated or misidentified")}
	}
	if digestBytes(trustedPolicyBytes) != manifest.ReviewAdmission.TrustPolicySHA256 ||
		int64(len(trustedPolicyBytes)) != manifest.ReviewAdmission.TrustPolicySize ||
		!bytes.Equal(trustedPolicyBytes, storedPolicyBytes) {
		return zero, []QuarantineIssue{issue("change_input_trust_root_mismatch", label, "operator trust root does not exactly match the signed admission policy")}
	}
	if trustedStatErr != nil || storedStatErr != nil || os.SameFile(trustedInfo, storedInfo) {
		return zero, []QuarantineIssue{issue("change_input_trust_root_unsafe", label, "operator trust root must be independent from the untrusted snapshot store")}
	}

	specBytes, err := readBoundedRegular(specPath, maxSourceSpecBytes)
	if err != nil || digestBytes(specBytes) != manifest.SourceSpecSHA256 || int64(len(specBytes)) != manifest.ReviewAdmission.SourceSpecSize {
		return zero, []QuarantineIssue{issue("change_input_source_spec_invalid", label, "reviewed source-spec object is missing, mutated or misidentified")}
	}
	var spec SourceSpec
	if err := decodeStrictDocument(specBytes, &spec); err != nil {
		return zero, []QuarantineIssue{issue("change_input_source_spec_invalid", label, "reviewed source-spec object is not strict JSON")}
	}
	if specIssues := validateSourceSpec(spec); len(specIssues) != 0 {
		return zero, []QuarantineIssue{issue("change_input_source_spec_invalid", label, "reviewed source-spec metadata, collections or file records exceed the schema bounds")}
	}
	canonicalSpec, err := marshalDocument(spec)
	if err != nil || !bytes.Equal(canonicalSpec, specBytes) {
		return zero, []QuarantineIssue{issue("change_input_source_spec_noncanonical", label, "reviewed source-spec bytes are not canonical")}
	}
	validatedReview, reviewIssues := validateReviewAdmission(CompileConfig{
		ProposalPath:        resolvedReviewPaths["proposal"],
		ReviewReceiptPath:   resolvedReviewPaths["receipt"],
		ReviewSignaturePath: resolvedReviewPaths["signature"],
		AllowedSignersPath:  trustedPolicyPath,
	}, specBytes, spec)
	for _, reviewIssue := range reviewIssues {
		reviewIssue.Path = label + "/" + reviewIssue.Path
		issues = append(issues, reviewIssue)
	}
	if len(reviewIssues) == 0 && !reflect.DeepEqual(validatedReview.Admission, manifest.ReviewAdmission) {
		issues = append(issues, issue("change_input_review_admission_mismatch", label, "manifest review admission differs from independently verified signed evidence"))
	}
	if len(issues) == 0 {
		issues = append(issues, validateManifestAgainstSpecAndStore(label, manifest, spec, store)...)
	}
	if len(issues) != 0 {
		return zero, issues
	}
	return verifiedSnapshot{Manifest: manifest, Spec: spec}, nil
}

func readExternalTrustRoot(label, candidate string, forbiddenRoots []string) (string, []byte, []QuarantineIssue) {
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return "", nil, []QuarantineIssue{issue("change_input_trust_root_invalid", label, "operator trust root path is invalid")}
	}
	for _, root := range forbiddenRoots {
		absoluteRoot, rootErr := filepath.Abs(root)
		if rootErr != nil || isWithin(absoluteRoot, absolute) {
			return "", nil, []QuarantineIssue{issue("change_input_trust_root_unsafe", label, "operator trust root must be outside both untrusted snapshot stores")}
		}
	}
	data, err := readBoundedRegular(absolute, maxAllowedSignersBytes)
	if err != nil {
		return "", nil, []QuarantineIssue{issue("change_input_trust_root_invalid", label, "operator trust root must be a bounded regular non-symlink file")}
	}
	return absolute, data, nil
}

func reviewCASPath(store, objectPath, digest string, size int64, label string) (string, []QuarantineIssue) {
	if !sha256Pattern.MatchString(digest) || size < 0 {
		return "", []QuarantineIssue{issue("change_input_review_reference_invalid", label, "review artifact digest or size is invalid")}
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	expected := path.Join("review", "sha256", hexDigest[:2], hexDigest)
	if objectPath != expected {
		return "", []QuarantineIssue{issue("change_input_review_reference_invalid", label, "review artifact path is not derived from its digest")}
	}
	return filepath.Join(store, filepath.FromSlash(expected)), nil
}

func validateManifestAgainstSpecAndStore(label string, manifest SnapshotManifest, spec SourceSpec, store string) []QuarantineIssue {
	issues := make([]QuarantineIssue, 0)
	limits, limitErr := normalizedLimits(CompileConfig{})
	if limitErr != nil {
		return []QuarantineIssue{issue("change_input_limits_invalid", label, "safe snapshot verification limits could not be established")}
	}
	for _, limitIssue := range validateInventoryLimits(spec.Files, spec.Exclusions, limits) {
		limitIssue.Path = label + "/" + limitIssue.Path
		issues = append(issues, limitIssue)
	}
	if len(issues) != 0 {
		return sortedIssues(issues)
	}
	if manifest.SnapshotID != spec.SnapshotID || manifest.SourceSpecSHA256 != manifest.ReviewAdmission.SourceSpecSHA256 {
		issues = append(issues, issue("change_input_manifest_spec_mismatch", label, "manifest does not bind the reviewed source specification and snapshot identity"))
	}
	expectedLineage := sourceLineageFromSpec(spec)
	if !reflect.DeepEqual(manifest.Source, expectedLineage) {
		issues = append(issues, issue("change_input_manifest_lineage_mismatch", label, "manifest source lineage differs from the reviewed source specification"))
	}
	if manifest.ObjectLayout != objectLayout || !reflect.DeepEqual(manifest.Exclusions, spec.Exclusions) {
		issues = append(issues, issue("change_input_manifest_shape_invalid", label, "manifest object layout or exclusion ledger differs from its reviewed specification"))
	}

	specFiles := make(map[string]ExpectedFile, len(spec.Files))
	for _, file := range spec.Files {
		specFiles[file.RelativePath] = file
	}
	seenPaths := make(map[string]struct{}, len(manifest.Files))
	uniqueDigests := make(map[string]struct{}, len(manifest.Files))
	verifiedObjects := make(map[string]int64, len(manifest.Files))
	var byteSize int64
	previousPath := ""
	for index, file := range manifest.Files {
		itemLabel := fmt.Sprintf("%s/files[%d]", label, index)
		if validateRelativePath(file.RelativePath) != nil || (index > 0 && file.RelativePath <= previousPath) {
			issues = append(issues, issue("change_input_file_order_invalid", itemLabel, "manifest paths must be unique canonical paths in strict lexical order"))
		}
		previousPath = file.RelativePath
		if _, exists := seenPaths[file.RelativePath]; exists {
			issues = append(issues, issue("change_input_file_duplicate", itemLabel, "manifest contains a duplicate file occurrence"))
		}
		seenPaths[file.RelativePath] = struct{}{}
		expectedFile, exists := specFiles[file.RelativePath]
		if !exists || expectedFile.MediaType != file.MediaType || expectedFile.SHA256 != file.SHA256 || expectedFile.Size != file.Size {
			issues = append(issues, issue("change_input_file_spec_mismatch", itemLabel, "manifest file differs from its reviewed source-spec occurrence"))
		}
		hexDigest := strings.TrimPrefix(file.SHA256, "sha256:")
		if !sha256Pattern.MatchString(file.SHA256) || len(hexDigest) != 64 {
			issues = append(issues, issue("change_input_file_digest_invalid", itemLabel, "manifest file has no full lowercase SHA-256"))
			continue
		}
		expectedObjectPath := objectRelativePath(hexDigest)
		if file.RawBlobID != "raw:"+file.SHA256 || file.ObjectPath != expectedObjectPath ||
			file.SnapshotID != manifest.SnapshotID || file.SourceID != manifest.Source.SourceID ||
			file.ComponentID != manifest.Source.ComponentID || file.ComponentVersionID != manifest.Source.ComponentVersionID ||
			file.ChannelID != manifest.Source.ChannelID {
			issues = append(issues, issue("change_input_file_lineage_invalid", itemLabel, "manifest file object identity or lineage is inconsistent"))
		}
		if file.Size < 0 || file.Size > math.MaxInt64-byteSize {
			issues = append(issues, issue("change_input_file_size_invalid", itemLabel, "manifest file size is invalid or overflows the snapshot total"))
		} else {
			byteSize += file.Size
		}
		uniqueDigests[file.SHA256] = struct{}{}
		if verifiedSize, verified := verifiedObjects[file.SHA256]; verified {
			if verifiedSize != file.Size {
				issues = append(issues, issue("change_input_raw_object_invalid", itemLabel, "one raw-object identity is claimed with conflicting occurrence sizes"))
			}
		} else {
			objectPath := filepath.Join(store, filepath.FromSlash(expectedObjectPath))
			if validateExistingPathComponents(objectPath) != nil {
				issues = append(issues, issue("change_input_raw_object_invalid", itemLabel, "referenced raw object path is absent, unsafe or symlinked"))
			} else {
				actualDigest, actualSize, readErr := hashInput(objectPath)
				if readErr != nil || actualDigest != file.SHA256 || actualSize != file.Size {
					issues = append(issues, issue("change_input_raw_object_invalid", itemLabel, "referenced raw object is missing, mutated or misidentified"))
				}
			}
			verifiedObjects[file.SHA256] = file.Size
		}
	}
	if len(seenPaths) != len(specFiles) {
		issues = append(issues, issue("change_input_file_set_mismatch", label, "manifest and reviewed source spec enumerate different file sets"))
	}
	var excludedBytes int64
	for _, exclusion := range spec.Exclusions {
		if exclusion.Size > math.MaxInt64-excludedBytes {
			issues = append(issues, issue("change_input_exclusion_size_invalid", label, "exclusion byte total overflows"))
			break
		}
		excludedBytes += exclusion.Size
	}
	if manifest.FileCount != len(manifest.Files) || manifest.FileCount != len(spec.Files) ||
		manifest.ByteSize != byteSize || manifest.UniqueBlobCount != len(uniqueDigests) ||
		manifest.ExcludedFileCount != len(spec.Exclusions) || manifest.ExcludedByteSize != excludedBytes {
		issues = append(issues, issue("change_input_manifest_counts_invalid", label, "manifest counts do not match independently recomputed values"))
	}
	treePayload, err := json.Marshal(struct {
		Files      []ManifestFile      `json:"files"`
		Exclusions []VerifiedExclusion `json:"exclusions"`
	}{Files: manifest.Files, Exclusions: manifest.Exclusions})
	if err != nil || manifest.TreeSHA256 != digestBytes(treePayload) {
		issues = append(issues, issue("change_input_tree_digest_invalid", label, "manifest tree digest does not match its file and exclusion occurrences"))
	}
	return sortedIssues(issues)
}

func sourceLineageFromSpec(spec SourceSpec) SourceLineage {
	return SourceLineage{
		SourceID:           spec.SourceID,
		CanonicalURI:       spec.CanonicalURI,
		ComponentID:        spec.ComponentID,
		ComponentVersionID: spec.ComponentVersionID,
		ResolvedVersion:    spec.ResolvedVersion,
		SourceRevision:     spec.SourceRevision,
		ChannelID:          spec.ChannelID,
		ChannelType:        spec.ChannelType,
		Rights:             spec.Rights,
		AccessScope:        spec.AccessScope,
		Classification:     spec.Classification,
		SecurityDomain:     spec.SecurityDomain,
		Language:           spec.Language,
		FetchedAt:          spec.FetchedAt,
		ObservedAt:         spec.ObservedAt,
		OriginKind:         spec.Provenance.OriginKind,
	}
}

func validateChangeLineage(oldManifest, newManifest SnapshotManifest) []QuarantineIssue {
	issues := make([]QuarantineIssue, 0)
	if oldManifest.ManifestID == newManifest.ManifestID || oldManifest.SnapshotID == newManifest.SnapshotID ||
		oldManifest.Source.SourceRevision == newManifest.Source.SourceRevision {
		issues = append(issues, issue("change_lineage_ambiguous", "old/new", "old and new must be distinct reviewed snapshot observations and immutable revisions"))
	}
	oldSource, newSource := oldManifest.Source, newManifest.Source
	if oldSource.ComponentID != newSource.ComponentID || oldSource.ChannelID != newSource.ChannelID ||
		oldSource.ChannelType != newSource.ChannelType || oldSource.Language != newSource.Language ||
		oldSource.OriginKind != newSource.OriginKind || oldSource.AccessScope != newSource.AccessScope ||
		oldSource.Classification != newSource.Classification || oldSource.SecurityDomain != newSource.SecurityDomain ||
		!reflect.DeepEqual(oldSource.Rights, newSource.Rights) {
		issues = append(issues, issue("change_lineage_mismatch", "old/new", "snapshots do not belong to the same stable component/channel/language/rights lineage"))
	}
	oldFetched, oldObserved, oldReviewed, oldOK := snapshotTimes(oldManifest)
	newFetched, newObserved, newReviewed, newOK := snapshotTimes(newManifest)
	if !oldOK || !newOK || !newFetched.After(oldFetched) || !newObserved.After(oldObserved) || !newReviewed.After(oldReviewed) {
		issues = append(issues, issue("change_lineage_order_ambiguous", "old/new", "new snapshot must have strictly later fetched, observed and signed-review times"))
	}
	return sortedIssues(issues)
}

func snapshotTimes(manifest SnapshotManifest) (time.Time, time.Time, time.Time, bool) {
	fetched, fetchedErr := time.Parse(time.RFC3339, manifest.Source.FetchedAt)
	observed, observedErr := time.Parse(time.RFC3339, manifest.Source.ObservedAt)
	reviewed, reviewedErr := time.Parse(time.RFC3339, manifest.ReviewAdmission.ReviewedAt)
	valid := fetchedErr == nil && observedErr == nil && reviewedErr == nil &&
		!observed.Before(fetched) && !reviewed.Before(observed)
	return fetched, observed, reviewed, valid
}

func compareFileOccurrences(oldFiles, newFiles []ManifestFile) ([]FileOccurrenceChange, ChangePackCounts) {
	changes := make([]FileOccurrenceChange, 0, len(oldFiles)+len(newFiles))
	counts := walkFileOccurrenceChanges(oldFiles, newFiles, func(change FileOccurrenceChange) bool {
		changes = append(changes, change)
		return true
	})
	return changes, counts
}

func walkFileOccurrenceChanges(oldFiles, newFiles []ManifestFile, visit func(FileOccurrenceChange) bool) ChangePackCounts {
	counts := ChangePackCounts{}
	for oldIndex, newIndex := 0, 0; oldIndex < len(oldFiles) || newIndex < len(newFiles); {
		var oldFile, newFile ManifestFile
		inOld, inNew := oldIndex < len(oldFiles), newIndex < len(newFiles)
		if inOld {
			oldFile = oldFiles[oldIndex]
		}
		if inNew {
			newFile = newFiles[newIndex]
		}
		change := FileOccurrenceChange{}
		switch {
		case !inOld || (inNew && newFile.RelativePath < oldFile.RelativePath):
			change.RelativePath = newFile.RelativePath
			change.ChangeType = "added"
			change.New = occurrenceVersion(newFile)
			counts.Added++
			newIndex++
		case !inNew || oldFile.RelativePath < newFile.RelativePath:
			change.RelativePath = oldFile.RelativePath
			change.ChangeType = "removed"
			change.Old = occurrenceVersion(oldFile)
			counts.Removed++
			oldIndex++
		case sameOccurrenceVersion(oldFile, newFile):
			change.RelativePath = oldFile.RelativePath
			change.ChangeType = "unchanged"
			change.Old = occurrenceVersion(oldFile)
			change.New = occurrenceVersion(newFile)
			counts.Unchanged++
			oldIndex++
			newIndex++
		default:
			change.RelativePath = oldFile.RelativePath
			change.ChangeType = "changed"
			change.Old = occurrenceVersion(oldFile)
			change.New = occurrenceVersion(newFile)
			counts.Changed++
			oldIndex++
			newIndex++
		}
		if !visit(change) {
			return counts
		}
	}
	return counts
}

func sameOccurrenceVersion(left, right ManifestFile) bool {
	return left.MediaType == right.MediaType && left.SHA256 == right.SHA256 && left.Size == right.Size &&
		left.RawBlobID == right.RawBlobID && left.ObjectPath == right.ObjectPath
}

func occurrenceVersion(file ManifestFile) *FileOccurrenceVersion {
	return &FileOccurrenceVersion{
		MediaType:  file.MediaType,
		SHA256:     file.SHA256,
		Size:       file.Size,
		RawBlobID:  file.RawBlobID,
		ObjectPath: file.ObjectPath,
	}
}

func snapshotBinding(manifest SnapshotManifest) SnapshotBinding {
	return SnapshotBinding{
		ManifestID:            manifest.ManifestID,
		ManifestPayloadSHA256: manifest.ManifestPayloadSHA256,
		SnapshotID:            manifest.SnapshotID,
		SourceSpecSHA256:      manifest.SourceSpecSHA256,
		TreeSHA256:            manifest.TreeSHA256,
		FileCount:             manifest.FileCount,
		ByteSize:              manifest.ByteSize,
		Source:                manifest.Source,
		ReviewAdmission:       manifest.ReviewAdmission,
	}
}
