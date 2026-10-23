package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	sourceSpecSchemaVersion = "1.0.0"
	manifestSchemaVersion   = "1.0.0"
	objectLayout            = "raw/sha256/<first-two>/<hex>"
	defaultMaxFiles         = 100_000
	defaultMaxFileBytes     = int64(2 * 1024 * 1024 * 1024)
	defaultMaxTotalBytes    = int64(64 * 1024 * 1024 * 1024)
)

var (
	stableIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+?=&%-]*$`)
	sha256Pattern    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	languagePattern  = regexp.MustCompile(`^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$`)
	gitCommitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
)

var channelTypes = map[string]struct{}{
	"docs": {}, "reference": {}, "api": {}, "schema": {},
	"config": {}, "release": {}, "changelog": {}, "migration": {},
	"deprecation": {}, "advisory": {}, "source": {}, "license": {},
	"package": {}, "artifact": {}, "sbom": {}, "provenance": {},
}

var requiredPermissions = []string{
	"commercial", "eval", "export", "media", "quote", "redistribution",
	"retrieval", "skill", "training",
}

var permissionValues = map[string]struct{}{
	"true": {}, "false": {}, "private_only": {}, "review_required": {}, "unknown": {},
}

var mutableResolutionValues = map[string]struct{}{
	"branch": {}, "canary": {}, "current": {}, "dev": {}, "develop": {},
	"development": {}, "edge": {}, "head": {}, "latest": {}, "main": {},
	"master": {}, "nightly": {}, "stable": {}, "trunk": {},
}

var exclusionSourceKinds = map[string]struct{}{
	"derived_summary": {}, "generated": {}, "local_projection": {},
	"non_source": {}, "recursive": {},
}

func Compile(config CompileConfig) (CompileResult, error) {
	var zero CompileResult
	if strings.TrimSpace(config.StoreRoot) == "" {
		return zero, errors.New("store root is required")
	}
	if strings.TrimSpace(config.MirrorBase) == "" {
		return zero, errors.New("mirror base is required")
	}
	limits, err := normalizedLimits(config)
	if err != nil {
		return zero, err
	}
	store, err := filepath.Abs(config.StoreRoot)
	if err != nil {
		return zero, fmt.Errorf("resolve output store: %w", err)
	}
	base, baseErr := filepath.Abs(config.MirrorBase)
	issues := make([]QuarantineIssue, 0)
	if baseErr != nil {
		issues = append(issues, issue("mirror_base_invalid", "<mirror-base>", "mirror base path is invalid"))
	}

	specBytes, readErr := readBoundedRegular(config.SpecPath, maxSourceSpecBytes)
	specDigest := digestBytes(specBytes)
	var spec SourceSpec
	var specIssues []QuarantineIssue
	if readErr != nil {
		specDigest = digestBytes(nil)
		specIssues = append(specIssues, issue("source_spec_read_failed", "<source-spec>", "source specification could not be read"))
	} else {
		specIssues = decodeSourceSpec(specBytes, &spec)
		if len(specIssues) == 0 {
			specIssues = append(specIssues, validateSourceSpec(spec)...)
		}
	}
	issues = append(issues, specIssues...)

	var mirrorRoot string
	if baseErr == nil && len(specIssues) == 0 {
		mirrorRoot = filepath.Join(base, filepath.FromSlash(spec.MirrorPath))
		if !isWithin(base, mirrorRoot) {
			issues = append(issues, issue("mirror_path_escape", spec.MirrorPath, "mirror path escapes the declared mirror base"))
		}
	}
	if baseErr == nil {
		issues = append(issues, validateNoSymlinkPath(base, "<mirror-base>")...)
	}
	if mirrorRoot != "" {
		issues = append(issues, validateNoSymlinkPath(mirrorRoot, "<mirror>")...)
	}

	unsafeOverlap := mirrorRoot != "" && pathsOverlap(mirrorRoot, store)
	if mirrorRoot == "" && baseErr == nil && pathsOverlap(base, store) {
		// Without a valid source specification, no narrower input root can be
		// proven. Refuse to create a quarantine store anywhere that overlaps the
		// configured mirror base.
		unsafeOverlap = true
	}
	if unsafeOverlap {
		issues = append(issues, issue("recursive_store_overlap", "<mirror>", "mirror and generated object-store paths overlap"))
		return zero, &QuarantinedError{Issues: sortedIssues(issues)}
	}

	var review validatedReview
	if len(issues) == 0 {
		var reviewIssues []QuarantineIssue
		review, reviewIssues = validateReviewAdmission(config, specBytes, spec)
		issues = append(issues, reviewIssues...)
	}
	if len(issues) == 0 {
		issues = append(issues, validateManifestOutputBudget(spec, review.Admission)...)
	}

	output, err := openOutputStore(store)
	if err != nil {
		return zero, fmt.Errorf("open safe output store: %w", err)
	}
	defer output.Close()

	if len(issues) == 0 {
		issues = append(issues, validateInventoryLimits(spec.Files, spec.Exclusions, limits)...)
	}
	if len(issues) == 0 {
		issues = append(issues, validateMirrorTree(mirrorRoot, spec.Files, spec.Exclusions, limits)...)
	}
	if len(issues) != 0 {
		return zero, quarantine(output, specDigest, spec, issues)
	}

	stagingDir, err := output.createStagingDirectory()
	if err != nil {
		return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
			issue("staging_create_failed", "<object-store>", "object staging directory could not be created"),
		})
	}
	defer output.removeAll(stagingDir)

	expected := append([]ExpectedFile(nil), spec.Files...)
	sort.Slice(expected, func(i, j int) bool { return expected[i].RelativePath < expected[j].RelativePath })
	staged := make(map[string]string)
	verifiedObjects := make(map[string]struct{})
	manifestFiles := make([]ManifestFile, 0, len(expected))
	var totalBytes int64

	for _, file := range expected {
		digestHex := strings.TrimPrefix(file.SHA256, "sha256:")
		objectRel := objectRelativePath(digestHex)
		stagePath := ""
		if _, alreadyStaged := staged[file.SHA256]; !alreadyStaged {
			if _, alreadyVerified := verifiedObjects[file.SHA256]; !alreadyVerified {
				if objectInfo, statErr := output.root.Lstat(objectRel); statErr == nil {
					if objectInfo.Mode().IsRegular() && objectInfo.Mode()&os.ModeSymlink == 0 && output.validateDirectories(path.Dir(objectRel)) == nil {
						if verifyErr := output.verifyDigest(objectRel, file.SHA256, file.Size); verifyErr != nil {
							issues = append(issues, issue("object_store_corrupt", objectRel, "existing content-addressed object does not match its identity"))
						} else {
							verifiedObjects[file.SHA256] = struct{}{}
						}
					} else {
						issues = append(issues, issue("object_store_invalid", objectRel, "content-addressed object is not a regular file"))
					}
				} else if !errors.Is(statErr, fs.ErrNotExist) {
					issues = append(issues, issue("object_store_read_failed", objectRel, "content-addressed object could not be inspected"))
				} else {
					stagePath = path.Join(stagingDir, digestHex)
				}
			}
		}

		actualPath := filepath.Join(mirrorRoot, filepath.FromSlash(file.RelativePath))
		computedDigest, computedSize, stageErr := stageAndHashInputRoot(actualPath, output, stagePath)
		if stageErr != nil {
			issues = append(issues, issue("source_file_read_failed", file.RelativePath, "source file could not be read safely"))
			continue
		}
		if computedDigest != file.SHA256 {
			issues = append(issues, issue("source_digest_changed", file.RelativePath, "source bytes differ from the reviewed SHA-256"))
		}
		if computedSize != file.Size {
			issues = append(issues, issue("source_size_changed", file.RelativePath, "source byte size differs from the reviewed size"))
		}
		if stagePath != "" && computedDigest == file.SHA256 && computedSize == file.Size {
			staged[file.SHA256] = stagePath
		} else if stagePath != "" {
			_ = output.root.Remove(stagePath)
		}

		manifestFiles = append(manifestFiles, projectedManifestFile(spec, file))
		totalBytes += file.Size
	}
	if len(issues) != 0 {
		return zero, quarantine(output, specDigest, spec, issues)
	}
	if err := commitReviewArtifacts(output, review.Artifacts); err != nil {
		return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
			issue("review_object_commit_failed", "review", "verified review artifacts could not be committed immutably"),
		})
	}

	stagedDigests := sortedKeys(staged)
	for _, digest := range stagedDigests {
		digestHex := strings.TrimPrefix(digest, "sha256:")
		target := objectRelativePath(digestHex)
		if commitErr := output.commitStagedObject(staged[digest], target, digest); commitErr != nil {
			return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
				issue("object_commit_failed", objectRelativePath(digestHex), "content-addressed object could not be committed atomically"),
			})
		}
	}

	unique := make(map[string]struct{}, len(manifestFiles))
	for _, file := range manifestFiles {
		unique[file.SHA256] = struct{}{}
	}
	treePayload, err := json.Marshal(struct {
		Files      []ManifestFile      `json:"files"`
		Exclusions []VerifiedExclusion `json:"exclusions"`
	}{Files: manifestFiles, Exclusions: spec.Exclusions})
	if err != nil {
		return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
			issue("manifest_encode_failed", "<manifest>", "snapshot file manifest could not be encoded"),
		})
	}
	var excludedBytes int64
	for _, exclusion := range spec.Exclusions {
		excludedBytes += exclusion.Size
	}
	core := SnapshotManifestCore{
		SchemaVersion:     manifestSchemaVersion,
		ManifestKind:      "knowledge_snapshot",
		State:             "complete",
		AuthorityState:    "reviewed",
		ReviewAdmission:   review.Admission,
		SnapshotID:        spec.SnapshotID,
		SourceSpecSHA256:  specDigest,
		Source:            sourceLineageFromSpec(spec),
		TreeSHA256:        digestBytes(treePayload),
		FileCount:         len(manifestFiles),
		ByteSize:          totalBytes,
		UniqueBlobCount:   len(unique),
		ObjectLayout:      objectLayout,
		ExcludedFileCount: len(spec.Exclusions),
		ExcludedByteSize:  excludedBytes,
		Exclusions:        spec.Exclusions,
		Files:             manifestFiles,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
			issue("manifest_encode_failed", "<manifest>", "snapshot manifest could not be encoded"),
		})
	}
	payloadDigest := digestBytes(coreBytes)
	manifest := SnapshotManifest{
		ManifestID:            "snapshot-manifest:" + payloadDigest,
		ManifestPayloadSHA256: payloadDigest,
		SnapshotManifestCore:  core,
	}
	manifestBytes, err := marshalDocument(manifest)
	if err != nil {
		return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
			issue("manifest_encode_failed", "<manifest>", "snapshot manifest could not be encoded"),
		})
	}
	if int64(len(manifestBytes)) > maxSnapshotManifestBytes {
		return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
			issue("manifest_output_limit_exceeded", "<manifest>", "encoded snapshot manifest exceeds the downstream 64 MiB input limit"),
		})
	}
	manifestHex := strings.TrimPrefix(payloadDigest, "sha256:")
	manifestRel := path.Join("manifests", "sha256", manifestHex[:2], manifestHex+".json")
	manifestPath := filepath.Join(store, filepath.FromSlash(manifestRel))
	if err := output.writeImmutable(manifestRel, manifestBytes, 0o444); err != nil {
		return zero, quarantine(output, specDigest, spec, []QuarantineIssue{
			issue("manifest_commit_failed", manifestRel, "immutable snapshot manifest could not be committed atomically"),
		})
	}
	return CompileResult{Manifest: manifest, ManifestPath: manifestPath}, nil
}

func decodeSourceSpec(data []byte, spec *SourceSpec) []QuarantineIssue {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(spec); err != nil {
		return []QuarantineIssue{issue("source_spec_invalid_json", "<source-spec>", "source specification is not valid strict JSON")}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return []QuarantineIssue{issue("source_spec_multiple_values", "<source-spec>", "source specification contains more than one JSON value")}
	}
	return nil
}

func validateSourceSpec(spec SourceSpec) []QuarantineIssue {
	issues := validateSourceMetadata(spec)
	if len(issues) != 0 {
		return sortedIssues(issues)
	}
	if collectionIssues := validateSourceCollections(spec); len(collectionIssues) != 0 {
		return sortedIssues(collectionIssues)
	}
	if err := validateRelativePath(spec.MirrorPath); err != nil {
		issues = append(issues, issue("mirror_path_escape", "mirror_path", "mirror path must be a canonical relative path below mirror base"))
	}
	if len(spec.Files) == 0 {
		issues = append(issues, issue("file_inventory_empty", "files", "source specification must enumerate at least one file"))
	}
	if spec.Exclusions == nil {
		issues = append(issues, issue("exclusions_missing", "exclusions", "source specification must explicitly declare an exclusions array"))
	}
	seen := make(map[string]struct{}, len(spec.Files)+len(spec.Exclusions))
	for index, exclusion := range spec.Exclusions {
		fieldPath := fmt.Sprintf("exclusions[%d]", index)
		if boundIssues := validateVerifiedExclusionBounds(exclusion, fieldPath); len(boundIssues) != 0 {
			issues = append(issues, boundIssues...)
			continue
		}
		if err := validateRelativePath(exclusion.RelativePath); err != nil {
			issues = append(issues, issue("exclusion_path_escape", exclusion.RelativePath, "excluded file path must be canonical and remain inside the mirror"))
		}
		if _, exists := seen[exclusion.RelativePath]; exists {
			issues = append(issues, issue("source_path_duplicate", exclusion.RelativePath, "source path is declared more than once"))
		}
		seen[exclusion.RelativePath] = struct{}{}
		if _, _, err := mime.ParseMediaType(exclusion.MediaType); err != nil || !strings.Contains(exclusion.MediaType, "/") {
			issues = append(issues, issue("media_type_invalid", fieldPath+".media_type", "media type is invalid"))
		}
		if !sha256Pattern.MatchString(exclusion.SHA256) {
			issues = append(issues, issue("sha256_invalid", fieldPath+".sha256", "excluded-file SHA-256 must be a full lowercase digest"))
		}
		if exclusion.Size < 0 {
			issues = append(issues, issue("size_invalid", fieldPath+".size", "excluded-file size cannot be negative"))
		}
		if _, ok := exclusionSourceKinds[exclusion.SourceKind]; !ok {
			issues = append(issues, issue("exclusion_source_kind_invalid", fieldPath+".source_kind", "excluded file must have an explicit non-authoritative source kind"))
		}
		if strings.TrimSpace(exclusion.Reason) == "" {
			issues = append(issues, issue("exclusion_reason_missing", fieldPath+".reason", "excluded file requires a reason"))
		}
	}
	for index, file := range spec.Files {
		fieldPath := fmt.Sprintf("files[%d]", index)
		if boundIssues := validateExpectedFileBounds(file, fieldPath); len(boundIssues) != 0 {
			issues = append(issues, boundIssues...)
			continue
		}
		if err := validateRelativePath(file.RelativePath); err != nil {
			issues = append(issues, issue("file_path_escape", file.RelativePath, "file path must be canonical and remain inside the mirror"))
		}
		if _, exists := seen[file.RelativePath]; exists {
			issues = append(issues, issue("source_path_duplicate", file.RelativePath, "source path is declared more than once"))
		}
		seen[file.RelativePath] = struct{}{}
		if _, _, err := mime.ParseMediaType(file.MediaType); err != nil || !strings.Contains(file.MediaType, "/") {
			issues = append(issues, issue("media_type_invalid", fieldPath+".media_type", "media type is invalid"))
		}
		if !sha256Pattern.MatchString(file.SHA256) {
			issues = append(issues, issue("sha256_invalid", fieldPath+".sha256", "file SHA-256 must be a full lowercase digest"))
		}
		if file.Size < 0 {
			issues = append(issues, issue("size_invalid", fieldPath+".size", "file size cannot be negative"))
		}
	}
	return sortedIssues(issues)
}

func validateSourceMetadata(spec SourceSpec) []QuarantineIssue {
	issues := validateSourceMetadataBounds(spec)
	if len(issues) != 0 {
		return sortedIssues(issues)
	}
	if spec.SchemaVersion != sourceSpecSchemaVersion {
		issues = append(issues, issue("schema_version_unsupported", "schema_version", "source specification schema version must be 1.0.0"))
	}
	for name, value := range map[string]string{
		"snapshot_id":          spec.SnapshotID,
		"source_id":            spec.SourceID,
		"component_id":         spec.ComponentID,
		"component_version_id": spec.ComponentVersionID,
		"channel_id":           spec.ChannelID,
	} {
		if len(value) < 3 || !stableIDPattern.MatchString(value) {
			issues = append(issues, issue("stable_id_invalid", name, name+" is not a valid stable identifier"))
		}
	}
	if !strings.HasSuffix(spec.ComponentVersionID, "@"+spec.ResolvedVersion) {
		issues = append(issues, issue("version_identity_mismatch", "component_version_id", "component version identity does not bind the resolved version"))
	}
	if !isImmutableResolution(spec.ResolvedVersion) {
		issues = append(issues, issue("resolved_version_mutable", "resolved_version", "resolved version is empty or mutable"))
	}
	if !isImmutableResolution(spec.SourceRevision) {
		issues = append(issues, issue("source_revision_mutable", "source_revision", "source revision is empty or mutable"))
	}
	if strings.HasPrefix(spec.ComponentID, "cmp:github:") && !gitCommitPattern.MatchString(spec.SourceRevision) {
		issues = append(issues, issue("source_revision_not_full_commit", "source_revision", "GitHub source revisions must be resolved to a full lowercase 40-hex commit"))
	}
	if strings.HasPrefix(spec.ComponentID, "cmp:github:") && gitCommitPattern.MatchString(spec.SourceRevision) &&
		!githubURIContainsCommit(spec.CanonicalURI, spec.SourceRevision) {
		issues = append(issues, issue("canonical_uri_revision_mismatch", "canonical_uri", "GitHub canonical URI must bind the same full commit as source_revision"))
	}
	if _, ok := channelTypes[spec.ChannelType]; !ok {
		issues = append(issues, issue("channel_type_invalid", "channel_type", "channel type is not one of the reviewed registry classes"))
	}
	if err := validateCanonicalURI(spec.CanonicalURI); err != nil {
		issues = append(issues, issue("canonical_uri_invalid", "canonical_uri", "canonical URI must be an absolute HTTPS authority URI"))
	}
	if !languagePattern.MatchString(spec.Language) {
		issues = append(issues, issue("language_invalid", "language", "language must be an explicit BCP-47-style tag"))
	}
	for field, value := range map[string]string{"fetched_at": spec.FetchedAt, "observed_at": spec.ObservedAt} {
		if !isCanonicalUTC(value) {
			issues = append(issues, issue("timestamp_invalid", field, field+" must be canonical RFC3339 UTC without fractional seconds"))
		}
	}
	issues = append(issues, validateRights(spec.Rights)...)
	if spec.AccessScope != "public" || spec.Classification != "public" || spec.SecurityDomain != "public" {
		issues = append(issues, issue("security_domain_unsupported", "security_domain", "the SHA-256 v1 store accepts only explicitly public content"))
	}
	if spec.Provenance.OriginKind != "official" && spec.Provenance.OriginKind != "primary" {
		issues = append(issues, issue("origin_kind_invalid", "provenance.origin_kind", "origin kind must be official or primary"))
	}
	if spec.Provenance.Generated {
		issues = append(issues, issue("generated_source_rejected", "provenance.generated", "generated projections cannot become source inputs"))
	}
	if spec.Provenance.RecursiveSource {
		issues = append(issues, issue("recursive_source_rejected", "provenance.recursive_source", "recursive source inputs are forbidden"))
	}
	return sortedIssues(issues)
}

func validateRights(rights Rights) []QuarantineIssue {
	issues := make([]QuarantineIssue, 0)
	if strings.TrimSpace(rights.LicenseExpression) == "" {
		issues = append(issues, issue("rights_missing", "rights.license_expression", "license expression is required"))
	}
	if strings.TrimSpace(rights.RightsBasis) == "" {
		issues = append(issues, issue("rights_missing", "rights.rights_basis", "rights basis is required"))
	}
	if strings.TrimSpace(rights.Attribution) == "" {
		issues = append(issues, issue("rights_missing", "rights.attribution", "attribution is required"))
	}
	if rights.Permissions == nil {
		issues = append(issues, issue("rights_missing", "rights.permissions", "all use-specific permissions are required"))
		return issues
	}
	for _, name := range requiredPermissions {
		value, exists := rights.Permissions[name]
		if !exists {
			issues = append(issues, issue("rights_permission_missing", "rights.permissions."+name, "use-specific permission is required"))
			continue
		}
		if _, ok := permissionValues[value]; !ok {
			issues = append(issues, issue("rights_permission_invalid", "rights.permissions."+name, "permission has an unsupported state"))
		}
	}
	for name := range rights.Permissions {
		if !contains(requiredPermissions, name) {
			issues = append(issues, issue("rights_permission_unknown", "rights.permissions."+name, "permission name is unsupported"))
		}
	}
	if rights.Permissions["retrieval"] != "true" {
		issues = append(issues, issue("retrieval_rights_denied", "rights.permissions.retrieval", "retrieval permission must be explicitly true for snapshot acquisition"))
	}
	return issues
}

type compileLimits struct {
	maxFiles      int
	maxFileBytes  int64
	maxTotalBytes int64
}

func normalizedLimits(config CompileConfig) (compileLimits, error) {
	limits := compileLimits{
		maxFiles:      config.MaxFiles,
		maxFileBytes:  config.MaxFileBytes,
		maxTotalBytes: config.MaxTotalBytes,
	}
	if limits.maxFiles == 0 {
		limits.maxFiles = defaultMaxFiles
	}
	if limits.maxFileBytes == 0 {
		limits.maxFileBytes = defaultMaxFileBytes
	}
	if limits.maxTotalBytes == 0 {
		limits.maxTotalBytes = defaultMaxTotalBytes
	}
	if limits.maxFiles < 1 || limits.maxFiles > maxSourceInventoryEntries || limits.maxFileBytes < 1 || limits.maxTotalBytes < 1 {
		return compileLimits{}, errors.New("snapshot limits must be positive")
	}
	return limits, nil
}

func validateInventoryLimits(expected []ExpectedFile, exclusions []VerifiedExclusion, limits compileLimits) []QuarantineIssue {
	issues := make([]QuarantineIssue, 0)
	if len(expected)+len(exclusions) > limits.maxFiles {
		issues = append(issues, issue("file_count_limit_exceeded", "files", "reviewed file inventory exceeds the configured file-count limit"))
	}
	var total int64
	for _, file := range expected {
		if file.Size > limits.maxFileBytes {
			issues = append(issues, issue("file_size_limit_exceeded", file.RelativePath, "reviewed file size exceeds the configured per-file byte limit"))
		}
		if file.Size > limits.maxTotalBytes-total {
			issues = append(issues, issue("total_size_limit_exceeded", "files", "reviewed file inventory exceeds the configured total-byte limit"))
			break
		}
		total += file.Size
	}
	for _, exclusion := range exclusions {
		if exclusion.Size > limits.maxFileBytes {
			issues = append(issues, issue("file_size_limit_exceeded", exclusion.RelativePath, "declared excluded-file size exceeds the configured per-file byte limit"))
		}
		if exclusion.Size > limits.maxTotalBytes-total {
			issues = append(issues, issue("total_size_limit_exceeded", "files", "reviewed file inventory exceeds the configured total-byte limit"))
			break
		}
		total += exclusion.Size
	}
	return sortedIssues(issues)
}

func validateMirrorTree(root string, expected []ExpectedFile, exclusions []VerifiedExclusion, limits compileLimits) []QuarantineIssue {
	issues := make([]QuarantineIssue, 0)
	info, err := os.Lstat(root)
	if err != nil {
		return []QuarantineIssue{issue("mirror_unavailable", "<mirror>", "mirror root does not exist or cannot be inspected")}
	}
	if !info.IsDir() {
		return []QuarantineIssue{issue("mirror_not_directory", "<mirror>", "mirror root is not a directory")}
	}
	expectedPaths := make(map[string]struct{}, len(expected)+len(exclusions))
	excludedByPath := make(map[string]VerifiedExclusion, len(exclusions))
	for _, file := range expected {
		expectedPaths[file.RelativePath] = struct{}{}
	}
	for _, exclusion := range exclusions {
		expectedPaths[exclusion.RelativePath] = struct{}{}
		excludedByPath[exclusion.RelativePath] = exclusion
	}
	actual := make(map[string]struct{}, len(expected)+len(exclusions))
	actualFiles := 0
	var actualBytes int64
	walkErr := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			issues = append(issues, issue("mirror_walk_failed", "<mirror>", "mirror tree could not be read completely"))
			return fs.SkipAll
		}
		if current == root {
			return nil
		}
		relative, relErr := filepath.Rel(root, current)
		if relErr != nil || !isWithin(root, current) {
			issues = append(issues, issue("mirror_path_escape", "<mirror>", "mirror entry escapes the mirror root"))
			return fs.SkipAll
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			issues = append(issues, issue("symlink_rejected", relative, "symlinks are forbidden in source mirrors"))
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		actualFiles++
		if actualFiles > limits.maxFiles {
			issues = append(issues, issue("file_count_limit_exceeded", "<mirror>", "mirror exceeds the configured file-count limit"))
			return fs.SkipAll
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
		if entryInfo.Size() > limits.maxFileBytes {
			issues = append(issues, issue("file_size_limit_exceeded", relative, "mirror file exceeds the configured per-file byte limit"))
		}
		if entryInfo.Size() > limits.maxTotalBytes-actualBytes {
			issues = append(issues, issue("total_size_limit_exceeded", "<mirror>", "mirror exceeds the configured total-byte limit"))
			return fs.SkipAll
		}
		actualBytes += entryInfo.Size()
		actual[relative] = struct{}{}
		if exclusion, excluded := excludedByPath[relative]; excluded {
			computedDigest, computedSize, hashErr := hashInput(current)
			if hashErr != nil {
				issues = append(issues, issue("excluded_file_read_failed", relative, "declared excluded file could not be read safely"))
				return nil
			}
			if computedDigest != exclusion.SHA256 || computedSize != exclusion.Size || mediaTypeForPath(relative) != exclusion.MediaType {
				issues = append(issues, issue("declared_exclusion_changed", relative, "declared excluded file no longer matches its reviewed hash, size, or media type"))
			}
			return nil
		}
		if _, exists := expectedPaths[relative]; !exists {
			issues = append(issues, issue("unexpected_file", relative, "mirror contains a file absent from the reviewed inventory"))
		}
		return nil
	})
	if walkErr != nil {
		issues = append(issues, issue("mirror_walk_failed", "<mirror>", "mirror tree could not be read completely"))
	}
	for relative := range expectedPaths {
		if _, exists := actual[relative]; !exists {
			if _, excluded := excludedByPath[relative]; excluded {
				issues = append(issues, issue("declared_exclusion_missing", relative, "declared excluded file is missing from the mirror"))
			} else {
				issues = append(issues, issue("expected_file_missing", relative, "reviewed source file is missing from the mirror"))
			}
		}
	}
	return sortedIssues(issues)
}

func hashInput(sourcePath string) (string, int64, error) {
	before, err := os.Lstat(sourcePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", 0, errors.New("unsafe source file")
	}
	source, err := os.Open(sourcePath) // #nosec G304 -- Source is in the operator-selected mirror; regular-file and descriptor identity checks bracket reads.
	if err != nil {
		return "", 0, err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", 0, errors.New("source identity changed before read")
	}

	hash := sha256.New()
	size, copyErr := io.Copy(hash, source)
	if copyErr != nil {
		return "", 0, copyErr
	}
	after, err := os.Lstat(sourcePath)
	if err != nil || !os.SameFile(opened, after) || after.Size() != size || after.ModTime() != opened.ModTime() {
		return "", 0, errors.New("source identity changed during read")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

func stageAndHashInputRoot(sourcePath string, store *outputStore, stageRelative string) (string, int64, error) {
	if stageRelative == "" {
		return hashInput(sourcePath)
	}
	if err := validateRelativePath(stageRelative); err != nil {
		return "", 0, err
	}
	before, err := os.Lstat(sourcePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", 0, errors.New("unsafe source file")
	}
	source, err := os.Open(sourcePath) // #nosec G304 -- Source is in the operator-selected mirror; regular-file and descriptor identity checks bracket reads.
	if err != nil {
		return "", 0, err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", 0, errors.New("source identity changed before read")
	}
	stageParent := path.Dir(stageRelative)
	if err := store.validateDirectories(stageParent); err != nil {
		return "", 0, err
	}
	if err := store.verifyBinding(); err != nil {
		return "", 0, err
	}
	// The descriptor remains writable even though the newly created inode is
	// born read-only, avoiding a path-based chmod race before hard-link commit.
	stage, err := store.root.OpenFile(stageRelative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return "", 0, err
	}
	removeStage := true
	defer func() {
		if removeStage {
			_ = store.root.Remove(stageRelative)
		}
	}()
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(hash, stage), source)
	if copyErr == nil {
		copyErr = stage.Sync()
	}
	closeErr := stage.Close()
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return "", 0, copyErr
	}
	after, err := os.Lstat(sourcePath)
	if err != nil || !os.SameFile(opened, after) || after.Size() != size || after.ModTime() != opened.ModTime() {
		return "", 0, errors.New("source identity changed during read")
	}
	if err := store.validateDirectories(stageParent); err != nil {
		return "", 0, err
	}
	if err := store.verifyBinding(); err != nil {
		return "", 0, err
	}
	removeStage = false
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

func verifyFileDigest(filePath, expectedDigest string, expectedSize int64) error {
	file, err := os.Open(filePath) // #nosec G304 -- Path identifies a compiler-created CAS object, checked against its declared size and SHA-256 digest.
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return err
	}
	if expectedSize >= 0 && size != expectedSize {
		return errors.New("size mismatch")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return errors.New("digest mismatch")
	}
	return nil
}

func quarantine(store *outputStore, specDigest string, spec SourceSpec, issues []QuarantineIssue) error {
	issues = sortedIssues(issues)
	identityPayload, _ := json.Marshal(struct {
		SourceSpecSHA256 string            `json:"source_spec_sha256"`
		Issues           []QuarantineIssue `json:"issues"`
	}{SourceSpecSHA256: specDigest, Issues: issues})
	quarantineDigest := digestBytes(identityPayload)
	report := QuarantineReport{
		SchemaVersion:      manifestSchemaVersion,
		ReportKind:         "knowledge_snapshot_quarantine",
		State:              "quarantined",
		QuarantineID:       "snapshot-quarantine:" + quarantineDigest,
		SourceSpecSHA256:   specDigest,
		SnapshotID:         boundedReportScalar(spec.SnapshotID, maxStableIDBytes),
		SourceID:           boundedReportScalar(spec.SourceID, maxStableIDBytes),
		ComponentID:        boundedReportScalar(spec.ComponentID, maxStableIDBytes),
		ComponentVersionID: boundedReportScalar(spec.ComponentVersionID, maxStableIDBytes),
		ChannelID:          boundedReportScalar(spec.ChannelID, maxStableIDBytes),
		Issues:             issues,
	}
	data, _ := marshalDocument(report)
	hexDigest := strings.TrimPrefix(quarantineDigest, "sha256:")
	relative := path.Join("quarantine", "sha256", hexDigest[:2], hexDigest+".json")
	reportPath := filepath.Join(store.path, filepath.FromSlash(relative))
	if err := store.writeImmutable(relative, data, 0o444); err != nil {
		return fmt.Errorf("snapshot input invalid and quarantine report failed: %w", err)
	}
	return &QuarantinedError{ReportPath: reportPath, Issues: issues}
}

func githubURIContainsCommit(value, commit string) bool {
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Host, "github.com") {
		return false
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index := 2; index+1 < len(segments); index++ {
		if (segments[index] == "tree" || segments[index] == "blob" || segments[index] == "commit") && segments[index+1] == commit {
			return true
		}
	}
	return false
}

func validateNoSymlinkPath(candidate, label string) []QuarantineIssue {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return []QuarantineIssue{issue("path_invalid", label, "path could not be resolved")}
	}
	current := filepath.Clean(abs)
	for {
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, fs.ErrNotExist) && current != abs {
				// An absent descendant is reported by the mirror-root validation.
			} else if errors.Is(statErr, fs.ErrNotExist) {
				return []QuarantineIssue{issue("path_unavailable", label, "path does not exist")}
			} else {
				return []QuarantineIssue{issue("path_unreadable", label, "path could not be inspected")}
			}
		} else if info.Mode()&os.ModeSymlink != 0 {
			return []QuarantineIssue{issue("symlink_rejected", label, "symlinked path components are forbidden")}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return nil
}

func validateCanonicalURI(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || strings.TrimSpace(value) != value {
		return errors.New("invalid canonical URI")
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || strings.Contains(value, `\`) || path.IsAbs(value) || path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return errors.New("invalid relative path")
	}
	return nil
}

func isImmutableResolution(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(strings.ToLower(trimmed), "refs/heads/") || strings.HasPrefix(strings.ToLower(trimmed), "refs/remotes/") {
		return false
	}
	_, mutable := mutableResolutionValues[strings.ToLower(trimmed)]
	return !mutable
}

func isCanonicalUTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && strings.HasSuffix(value, "Z") && parsed.Format(time.RFC3339) == value
}

func pathsOverlap(a, b string) bool {
	return isWithin(a, b) || isWithin(b, a)
}

func isWithin(base, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(candidate))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func objectRelativePath(digestHex string) string {
	return path.Join("raw", "sha256", digestHex[:2], digestHex)
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func marshalDocument(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func issue(code, itemPath, message string) QuarantineIssue {
	return QuarantineIssue{Code: code, Path: itemPath, Message: message}
}

func sortedIssues(issues []QuarantineIssue) []QuarantineIssue {
	result := append([]QuarantineIssue(nil), issues...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Code != result[j].Code {
			return result[i].Code < result[j].Code
		}
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].Message < result[j].Message
	})
	return result
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
