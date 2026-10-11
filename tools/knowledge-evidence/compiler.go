package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	snapshotSchemaVersion     = "1.0.0"
	evidenceSchemaVersion     = "1.0.0"
	compilerVersion           = "knowledge-evidence@1.2.0"
	markdownParserVersion     = "markdown-atx-fence-scanner@1.1.0"
	markdownProfile           = "faithful-utf8-markdown-sections-bounded@1.0.0"
	wholeFileParser           = "exact-coordinate-line-window@1.0.0"
	wholeFileProfile          = "faithful-utf8-bounded-spans@1.0.0"
	rawObjectLayout           = "raw/sha256/<first-two>/<hex>"
	normalizedLayout          = "normalized/sha256/<first-two>/<hex>"
	defaultMaxFiles           = 100_000
	defaultMaxFileBytes       = int64(64 * 1024 * 1024)
	defaultMaxTotalBytes      = int64(512 * 1024 * 1024)
	defaultMaxSpans           = 1_000_000
	defaultMaxOutputBytes     = int64(512 * 1024 * 1024)
	maxManifestBytes          = int64(64 * 1024 * 1024)
	maxReviewSourceSpecBytes  = int64(32 * 1024 * 1024)
	maxReviewProposalBytes    = int64(40 * 1024 * 1024)
	maxReviewReceiptBytes     = int64(64 * 1024)
	maxReviewSignatureBytes   = int64(16 * 1024)
	maxReviewTrustPolicyBytes = int64(1024 * 1024)
	maxReviewBundleBytes      = int64(64 * 1024 * 1024)
	maxHeadingLabelBytes      = 1024
	maxNormalizedSpanBytes    = 16 * 1024
	maxBreadcrumbBytes        = int64(8 * 1024 * 1024)
	maxManifestPlanningBytes  = int64(48 * 1024 * 1024)
	maxEvidenceManifestBytes  = int64(64 * 1024 * 1024)
	manifestSpanOverhead      = int64(512)
	manifestFileOverhead      = int64(1024)
	trustProfileVersion       = "untrusted-evidence-envelope@1.0.0"
	sourceProfileVersion      = "github-official-commit@1.0.0"
	reviewSignatureNamespace  = "archeion-knowledge-source-review-v1"
	sshKeygenPath             = "/usr/bin/ssh-keygen"
)

var (
	sha256Pattern        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	fullGitCommitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
	reviewerPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{2,127}$`)
)

type compileLimits struct {
	maxFiles       int
	maxFileBytes   int64
	maxTotalBytes  int64
	maxSpans       int
	maxOutputBytes int64
}

type stagedPayload struct {
	relative string
	size     int64
}

func Compile(config CompileConfig) (CompileResult, error) {
	var zero CompileResult
	if strings.TrimSpace(config.ManifestPath) == "" {
		return zero, errors.New("snapshot manifest path is required")
	}
	if strings.TrimSpace(config.RawStoreRoot) == "" {
		return zero, errors.New("raw store root is required")
	}
	if strings.TrimSpace(config.StoreRoot) == "" {
		return zero, errors.New("evidence store root is required")
	}
	limits, err := normalizeLimits(config)
	if err != nil {
		return zero, err
	}

	manifestBytes, manifestReadIssues := readManifestDocument(config.ManifestPath)
	inputDocumentDigest := digestBytes(manifestBytes)
	var snapshot SnapshotManifest
	issues := append([]QuarantineIssue(nil), manifestReadIssues...)
	if len(issues) == 0 {
		issues = append(issues, decodeStrict(manifestBytes, &snapshot)...)
	}
	if len(issues) == 0 {
		issues = append(issues, validateSnapshotManifest(snapshot, limits)...)
	}

	rawRoot, rawErr := filepath.Abs(config.RawStoreRoot)
	if rawErr != nil {
		issues = append(issues, issue("raw_store_invalid", "<raw-store>", "raw object store path is invalid"))
	}
	storeRoot, storeErr := filepath.Abs(config.StoreRoot)
	storeSafeForQuarantine := storeErr == nil
	if storeErr != nil {
		issues = append(issues, issue("evidence_store_invalid", "<evidence-store>", "evidence object store path is invalid"))
	}
	if rawErr == nil {
		issues = append(issues, validateNoSymlinkPath(rawRoot, "<raw-store>")...)
	}
	if storeErr == nil {
		storePathIssues := validateNoSymlinkPathExistingPrefix(storeRoot, "<evidence-store>")
		if len(storePathIssues) != 0 {
			storeSafeForQuarantine = false
		}
		issues = append(issues, storePathIssues...)
	}
	if rawErr == nil && storeErr == nil && pathsOverlap(rawRoot, storeRoot) {
		issues = append(issues, issue("recursive_store_overlap", "<evidence-store>", "raw and evidence object stores must not overlap"))
		storeSafeForQuarantine = false
	}
	if len(issues) == 0 {
		issues = append(issues, verifyReviewBundle(config, rawRoot, snapshot)...)
	}
	if len(issues) != 0 {
		if !storeSafeForQuarantine {
			return zero, fmt.Errorf("unsafe evidence-store path; quarantine was not written (%s)", issues[0].Code)
		}
		return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, issues)
	}

	outputRoot, outputRootInfo, err := openSafeOutputRoot(storeRoot)
	if err != nil {
		return zero, fmt.Errorf("evidence output store could not be anchored safely: %w", err)
	}
	defer outputRoot.Close()
	stagingDir, err := makeRootTempDirectory(outputRoot, storeRoot, outputRootInfo, ".staging", "evidence-")
	if err != nil {
		return zero, fmt.Errorf("evidence staging directory could not be created safely: %w", err)
	}
	defer outputRoot.RemoveAll(stagingDir)

	files := make([]EvidenceFile, 0, len(snapshot.Files))
	trustEnvelope := newTrustEnvelope()
	staged := make(map[string]stagedPayload)
	uniqueSizes := make(map[string]int64)
	spanCount := 0
	var logicalOutputBytes int64
	var breadcrumbBytes int64
	var manifestPlanningBytes int64
	for _, input := range snapshot.Files {
		data, readIssues := readVerifiedRaw(rawRoot, input, limits.maxFileBytes)
		issues = append(issues, readIssues...)
		if len(readIssues) != 0 {
			continue
		}
		if !utf8.Valid(data) {
			issues = append(issues, issue("invalid_utf8", input.RelativePath, "text input is not valid UTF-8"))
			continue
		}
		if bytes.IndexByte(data, 0) >= 0 {
			issues = append(issues, issue("binary_content_rejected", input.RelativePath, "text input contains a NUL byte"))
			continue
		}

		remainingSpans := limits.maxSpans - spanCount
		if remainingSpans < 1 {
			issues = append(issues, issue("span_count_limit_exceeded", input.RelativePath, "normalized spans exceed the configured span-count limit"))
			continue
		}
		parserVersion, profileVersion, rawSpans, profileIssues := profileFor(input, data, remainingSpans)
		issues = append(issues, profileIssues...)
		if len(profileIssues) != 0 {
			continue
		}
		if len(rawSpans) > limits.maxSpans-spanCount {
			issues = append(issues, issue("span_count_limit_exceeded", input.RelativePath, "normalized spans exceed the configured span-count limit"))
			continue
		}
		lineRanges, coordinateErr := spanLineRanges(data, rawSpans)
		if coordinateErr != nil {
			issues = append(issues, issue("span_coordinate_invalid", input.RelativePath, "normalized spans do not have valid ordered byte coordinates"))
			continue
		}
		occurrenceID := occurrenceIdentity(snapshot.ManifestID, input)
		outputFile := EvidenceFile{
			OccurrenceID:       occurrenceID,
			RelativePath:       input.RelativePath,
			MediaType:          input.MediaType,
			RawSHA256:          input.SHA256,
			RawBlobID:          input.RawBlobID,
			RawObjectPath:      input.ObjectPath,
			RawByteSize:        input.Size,
			SnapshotID:         input.SnapshotID,
			SourceID:           input.SourceID,
			ComponentID:        input.ComponentID,
			ComponentVersionID: input.ComponentVersionID,
			ChannelID:          input.ChannelID,
			ParserVersion:      parserVersion,
			ProfileVersion:     profileVersion,
			TrustEnvelopeID:    trustEnvelope.EnvelopeID,
			Spans:              make([]EvidenceSpan, 0, len(rawSpans)),
		}
		fileMetadata, metadataErr := json.Marshal(outputFile)
		if metadataErr != nil || int64(len(fileMetadata))+manifestFileOverhead > maxManifestPlanningBytes-manifestPlanningBytes {
			issues = append(issues, issue("evidence_manifest_size_limit_exceeded", input.RelativePath, "evidence manifest metadata exceeds the fixed downstream-compatible bound"))
			continue
		}
		manifestPlanningBytes += int64(len(fileMetadata)) + manifestFileOverhead
		fileOutputBytes := int64(0)
		for ordinal, rawSpan := range rawSpans {
			payload := data[rawSpan.start:rawSpan.end]
			payloadSize := int64(len(payload))
			if payloadSize > limits.maxOutputBytes-logicalOutputBytes-fileOutputBytes {
				issues = append(issues, issue("output_size_limit_exceeded", input.RelativePath, "normalized output exceeds the configured logical-byte limit"))
				break
			}
			payloadDigest := digestBytes(payload)
			payloadPath := normalizedObjectRelativePath(payloadDigest)
			if priorSize, exists := uniqueSizes[payloadDigest]; exists && priorSize != payloadSize {
				issues = append(issues, issue("payload_identity_collision", input.RelativePath, "normalized payload identity has inconsistent size"))
				break
			}
			lineStart, lineEnd := lineRanges[ordinal].start, lineRanges[ordinal].end
			spanBreadcrumbBytes := int64(0)
			for _, label := range rawSpan.breadcrumb {
				spanBreadcrumbBytes += int64(len(label))
			}
			if spanBreadcrumbBytes > maxBreadcrumbBytes-breadcrumbBytes {
				issues = append(issues, issue("breadcrumb_metadata_limit_exceeded", input.RelativePath, "repeated heading breadcrumb metadata exceeds the fixed bound"))
				break
			}
			span := EvidenceSpan{
				Ordinal:           ordinal,
				Kind:              rawSpan.kind,
				HeadingBreadcrumb: rawSpan.breadcrumb,
				RawByteStart:      int64(rawSpan.start),
				RawByteEnd:        int64(rawSpan.end),
				RawLineStart:      lineStart,
				RawLineEnd:        lineEnd,
				PayloadSHA256:     payloadDigest,
				PayloadID:         "normalized:" + payloadDigest,
				ObjectPath:        payloadPath,
				ByteSize:          payloadSize,
				TrustEnvelopeID:   trustEnvelope.EnvelopeID,
			}
			spanMetadata, metadataErr := json.Marshal(span)
			if metadataErr != nil || int64(len(spanMetadata))+manifestSpanOverhead > maxManifestPlanningBytes-manifestPlanningBytes {
				issues = append(issues, issue("evidence_manifest_size_limit_exceeded", input.RelativePath, "evidence manifest metadata exceeds the fixed downstream-compatible bound"))
				break
			}
			breadcrumbBytes += spanBreadcrumbBytes
			manifestPlanningBytes += int64(len(spanMetadata)) + manifestSpanOverhead
			span.SpanID = spanIdentity(occurrenceID, parserVersion, profileVersion, span)
			if _, exists := staged[payloadDigest]; !exists {
				if info, statErr := outputRoot.Lstat(payloadPath); statErr == nil {
					if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || verifyRootFileDigest(outputRoot, payloadPath, payloadDigest, payloadSize) != nil {
						issues = append(issues, issue("normalized_store_corrupt", payloadPath, "existing normalized object does not match its content identity"))
						break
					}
				} else if !errors.Is(statErr, fs.ErrNotExist) {
					issues = append(issues, issue("normalized_store_read_failed", payloadPath, "normalized object could not be inspected"))
					break
				} else {
					stageRelative := path.Join(stagingDir, strings.TrimPrefix(payloadDigest, "sha256:"))
					if writeErr := writeRootSyncedFile(outputRoot, storeRoot, outputRootInfo, stageRelative, payload, 0o444); writeErr != nil {
						issues = append(issues, issue("normalized_stage_failed", input.RelativePath, "normalized payload could not be staged"))
						break
					}
					staged[payloadDigest] = stagedPayload{relative: stageRelative, size: payloadSize}
				}
			}
			uniqueSizes[payloadDigest] = payloadSize
			outputFile.Spans = append(outputFile.Spans, span)
			fileOutputBytes += payloadSize
		}
		if len(outputFile.Spans) != len(rawSpans) {
			continue
		}
		if fileOutputBytes != int64(len(data)) {
			issues = append(issues, issue("span_partition_invalid", input.RelativePath, "normalized spans do not form an exact byte partition of the raw object"))
			continue
		}
		spanCount += len(outputFile.Spans)
		logicalOutputBytes += fileOutputBytes
		files = append(files, outputFile)
	}

	if len(issues) != 0 || len(files) != len(snapshot.Files) {
		return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, issues)
	}

	digests := make([]string, 0, len(staged))
	for digest := range staged {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		entry := staged[digest]
		target := normalizedObjectRelativePath(digest)
		if err := commitStagedObject(outputRoot, storeRoot, outputRootInfo, entry.relative, target, digest, entry.size); err != nil {
			return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, []QuarantineIssue{
				issue("normalized_object_commit_failed", normalizedObjectRelativePath(digest), "normalized object could not be committed immutably"),
			})
		}
	}

	var uniquePayloadBytes int64
	for _, size := range uniqueSizes {
		if size > limits.maxOutputBytes-uniquePayloadBytes {
			return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, []QuarantineIssue{
				issue("output_size_limit_exceeded", "<manifest>", "unique normalized payload bytes exceed the configured limit"),
			})
		}
		uniquePayloadBytes += size
	}
	core := EvidenceManifestCore{
		SchemaVersion:              evidenceSchemaVersion,
		ManifestKind:               "knowledge_evidence",
		State:                      "complete",
		InputManifestID:            snapshot.ManifestID,
		InputManifestPayloadSHA256: snapshot.ManifestPayloadSHA256,
		InputSnapshotID:            snapshot.SnapshotID,
		CompilerVersion:            compilerVersion,
		SourceProfileVersion:       sourceProfileVersion,
		TrustEnvelope:              trustEnvelope,
		ObjectLayout:               normalizedLayout,
		FileCount:                  len(files),
		RawByteSize:                snapshot.ByteSize,
		SpanCount:                  spanCount,
		LogicalOutputByteSize:      logicalOutputBytes,
		UniquePayloadCount:         len(uniqueSizes),
		UniquePayloadByteSize:      uniquePayloadBytes,
		Files:                      files,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil || int64(len(coreBytes)) > maxEvidenceManifestBytes {
		return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, []QuarantineIssue{
			issue("evidence_manifest_size_limit_exceeded", "<manifest>", "evidence manifest exceeds the fixed downstream-compatible bound"),
		})
	}
	payloadDigest := digestBytes(coreBytes)
	manifest := EvidenceManifest{
		ManifestID:            "evidence-manifest:" + payloadDigest,
		ManifestPayloadSHA256: payloadDigest,
		EvidenceManifestCore:  core,
	}
	evidenceManifestBytes, err := marshalDocument(manifest)
	if err != nil {
		return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, []QuarantineIssue{
			issue("evidence_manifest_encode_failed", "<manifest>", "evidence manifest could not be encoded"),
		})
	}
	if int64(len(evidenceManifestBytes)) > maxEvidenceManifestBytes {
		return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, []QuarantineIssue{
			issue("evidence_manifest_size_limit_exceeded", "<manifest>", "evidence manifest exceeds the fixed downstream-compatible bound"),
		})
	}
	hexDigest := strings.TrimPrefix(payloadDigest, "sha256:")
	manifestRel := path.Join("evidence-manifests", "sha256", hexDigest[:2], hexDigest+".json")
	manifestPath := filepath.Join(storeRoot, filepath.FromSlash(manifestRel))
	if err := writeImmutableAtRoot(outputRoot, storeRoot, outputRootInfo, manifestRel, evidenceManifestBytes, 0o444); err != nil {
		return zero, quarantine(storeRoot, inputDocumentDigest, snapshot, []QuarantineIssue{
			issue("evidence_manifest_commit_failed", manifestRel, "evidence manifest could not be committed immutably"),
		})
	}
	return CompileResult{Manifest: manifest, ManifestPath: manifestPath}, nil
}

func normalizeLimits(config CompileConfig) (compileLimits, error) {
	limits := compileLimits{config.MaxFiles, config.MaxFileBytes, config.MaxTotalBytes, config.MaxSpans, config.MaxOutputBytes}
	if limits.maxFiles == 0 {
		limits.maxFiles = defaultMaxFiles
	}
	if limits.maxFileBytes == 0 {
		limits.maxFileBytes = defaultMaxFileBytes
	}
	if limits.maxTotalBytes == 0 {
		limits.maxTotalBytes = defaultMaxTotalBytes
	}
	if limits.maxSpans == 0 {
		limits.maxSpans = defaultMaxSpans
	}
	if limits.maxOutputBytes == 0 {
		limits.maxOutputBytes = defaultMaxOutputBytes
	}
	if limits.maxFiles < 1 || limits.maxFileBytes < 1 || limits.maxTotalBytes < 1 || limits.maxSpans < 1 || limits.maxOutputBytes < 1 {
		return compileLimits{}, errors.New("evidence compiler limits must be positive")
	}
	return limits, nil
}

func readManifestDocument(filePath string) ([]byte, []QuarantineIssue) {
	if issues := validateNoSymlinkPath(filePath, "<snapshot-manifest>"); len(issues) != 0 {
		return nil, issues
	}
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, []QuarantineIssue{issue("manifest_read_failed", "<snapshot-manifest>", "snapshot manifest is not a readable regular file")}
	}
	if info.Size() > maxManifestBytes {
		return nil, []QuarantineIssue{issue("manifest_size_limit_exceeded", "<snapshot-manifest>", "snapshot manifest exceeds the fixed input limit")}
	}
	handle, err := os.Open(filePath)
	if err != nil {
		return nil, []QuarantineIssue{issue("manifest_read_failed", "<snapshot-manifest>", "snapshot manifest could not be read")}
	}
	opened, err := handle.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		handle.Close()
		return nil, []QuarantineIssue{issue("manifest_replaced", "<snapshot-manifest>", "snapshot manifest identity changed before read")}
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxManifestBytes+1))
	closeErr := handle.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maxManifestBytes {
		return nil, []QuarantineIssue{issue("manifest_read_failed", "<snapshot-manifest>", "snapshot manifest could not be read within bounds")}
	}
	after, err := os.Lstat(filePath)
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || after.ModTime() != opened.ModTime() {
		return nil, []QuarantineIssue{issue("manifest_replaced", "<snapshot-manifest>", "snapshot manifest identity changed during read")}
	}
	return data, nil
}

func decodeStrict(data []byte, target any) []QuarantineIssue {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return []QuarantineIssue{issue("manifest_invalid_json", "<snapshot-manifest>", "snapshot manifest is not valid strict JSON")}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return []QuarantineIssue{issue("manifest_multiple_values", "<snapshot-manifest>", "snapshot manifest contains more than one JSON value")}
	}
	return nil
}

func validateSnapshotManifest(manifest SnapshotManifest, limits compileLimits) []QuarantineIssue {
	var issues []QuarantineIssue
	if manifest.SchemaVersion != snapshotSchemaVersion {
		issues = append(issues, issue("snapshot_schema_unsupported", "schema_version", "snapshot manifest schema must be 1.0.0"))
	}
	if manifest.ManifestKind != "knowledge_snapshot" || manifest.State != "complete" {
		issues = append(issues, issue("snapshot_not_complete", "state", "only a complete knowledge snapshot may be normalized"))
	}
	issues = append(issues, validateReviewAdmission(manifest)...)
	if manifest.Source.OriginKind != "official" && manifest.Source.OriginKind != "primary" {
		issues = append(issues, issue("generated_source_rejected", "source.origin_kind", "only official or primary non-generated input is accepted"))
	}
	if manifest.Source.AccessScope != "public" || manifest.Source.Classification != "public" || manifest.Source.SecurityDomain != "public" {
		issues = append(issues, issue("security_domain_unsupported", "source.security_domain", "v1 evidence CAS accepts only explicitly public snapshots"))
	}
	if manifest.ObjectLayout != rawObjectLayout {
		issues = append(issues, issue("raw_layout_unsupported", "object_layout", "snapshot raw object layout is unsupported"))
	}
	if !sha256Pattern.MatchString(manifest.SourceSpecSHA256) {
		issues = append(issues, issue("source_spec_identity_invalid", "source_spec_sha256", "snapshot does not bind a full lowercase source-spec SHA-256"))
	}
	if !sha256Pattern.MatchString(manifest.TreeSHA256) {
		issues = append(issues, issue("tree_identity_invalid", "tree_sha256", "snapshot tree SHA-256 is malformed"))
	}
	for field, value := range map[string]string{
		"snapshot_id": manifest.SnapshotID, "source.source_id": manifest.Source.SourceID,
		"source.component_id": manifest.Source.ComponentID, "source.component_version_id": manifest.Source.ComponentVersionID,
		"source.channel_id": manifest.Source.ChannelID, "source.resolved_version": manifest.Source.ResolvedVersion,
		"source.source_revision": manifest.Source.SourceRevision,
	} {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, issue("source_lineage_incomplete", field, "complete snapshot source lineage is missing a required value"))
		}
	}
	if manifest.Source.Rights.Permissions["retrieval"] != "true" {
		issues = append(issues, issue("retrieval_rights_denied", "source.rights.permissions.retrieval", "snapshot retrieval rights are not explicitly allowed"))
	}
	if !sha256Pattern.MatchString(manifest.ManifestPayloadSHA256) || manifest.ManifestID != "snapshot-manifest:"+manifest.ManifestPayloadSHA256 {
		issues = append(issues, issue("manifest_identity_invalid", "manifest_id", "snapshot manifest identity is malformed"))
	}
	coreBytes, err := json.Marshal(manifest.SnapshotManifestCore)
	if err != nil || digestBytes(coreBytes) != manifest.ManifestPayloadSHA256 {
		issues = append(issues, issue("manifest_payload_tampered", "<snapshot-manifest>", "snapshot payload does not match its declared identity"))
	}
	if len(manifest.Files) == 0 || len(manifest.Files) != manifest.FileCount {
		issues = append(issues, issue("file_count_mismatch", "files", "snapshot file count is empty or inconsistent"))
	}
	if len(manifest.Files) > limits.maxFiles {
		issues = append(issues, issue("file_count_limit_exceeded", "files", "snapshot exceeds the configured file-count limit"))
	}
	if len(manifest.Exclusions) != manifest.ExcludedFileCount {
		issues = append(issues, issue("exclusion_count_mismatch", "exclusions", "snapshot exclusion count is inconsistent"))
	}
	var total, excludedTotal int64
	unique := make(map[string]struct{})
	seenPaths := make(map[string]struct{})
	previousPath := ""
	for index, file := range manifest.Files {
		fieldPath := fmt.Sprintf("files[%d]", index)
		if validateRelativePath(file.RelativePath) != nil {
			issues = append(issues, issue("file_path_escape", file.RelativePath, "snapshot file path is not canonical and relative"))
		}
		if _, exists := seenPaths[file.RelativePath]; exists {
			issues = append(issues, issue("file_path_duplicate", file.RelativePath, "snapshot contains the same file occurrence twice"))
		}
		seenPaths[file.RelativePath] = struct{}{}
		if index > 0 && file.RelativePath <= previousPath {
			issues = append(issues, issue("file_order_invalid", file.RelativePath, "snapshot files must be in strict lexical order"))
		}
		previousPath = file.RelativePath
		if !sha256Pattern.MatchString(file.SHA256) || file.RawBlobID != "raw:"+file.SHA256 {
			issues = append(issues, issue("raw_identity_invalid", fieldPath, "raw SHA-256 and blob identity are inconsistent"))
		}
		expectedPath := rawObjectRelativePath(file.SHA256)
		if file.ObjectPath != expectedPath || validateRelativePath(file.ObjectPath) != nil {
			issues = append(issues, issue("raw_object_path_invalid", file.ObjectPath, "raw object path does not match its SHA-256 identity"))
		}
		if file.Size < 0 || file.Size > limits.maxFileBytes {
			issues = append(issues, issue("file_size_limit_exceeded", file.RelativePath, "snapshot file size is invalid or exceeds the configured limit"))
		} else if file.Size > limits.maxTotalBytes-total {
			issues = append(issues, issue("total_size_limit_exceeded", "files", "snapshot exceeds the configured total-byte limit"))
		} else {
			total += file.Size
		}
		if file.SnapshotID != manifest.SnapshotID || file.SourceID != manifest.Source.SourceID || file.ComponentID != manifest.Source.ComponentID || file.ComponentVersionID != manifest.Source.ComponentVersionID || file.ChannelID != manifest.Source.ChannelID {
			issues = append(issues, issue("file_lineage_mismatch", file.RelativePath, "file occurrence lineage does not match the snapshot source"))
		}
		if _, _, err := mime.ParseMediaType(file.MediaType); err != nil {
			issues = append(issues, issue("media_type_invalid", fieldPath+".media_type", "snapshot media type is invalid"))
		}
		unique[file.SHA256] = struct{}{}
	}
	for _, exclusion := range manifest.Exclusions {
		if exclusion.Size < 0 || exclusion.Size > limits.maxTotalBytes-excludedTotal {
			issues = append(issues, issue("exclusion_size_invalid", exclusion.RelativePath, "snapshot exclusion byte size is inconsistent"))
			break
		}
		excludedTotal += exclusion.Size
	}
	if total != manifest.ByteSize {
		issues = append(issues, issue("byte_size_mismatch", "byte_size", "snapshot byte size does not equal its file inventory"))
	}
	if excludedTotal != manifest.ExcludedByteSize {
		issues = append(issues, issue("exclusion_byte_size_mismatch", "excluded_byte_size", "snapshot excluded byte size is inconsistent"))
	}
	if len(unique) != manifest.UniqueBlobCount {
		issues = append(issues, issue("unique_blob_count_mismatch", "unique_blob_count", "snapshot unique raw blob count is inconsistent"))
	}
	treePayload, err := json.Marshal(struct {
		Files      []ManifestFile      `json:"files"`
		Exclusions []VerifiedExclusion `json:"exclusions"`
	}{Files: manifest.Files, Exclusions: manifest.Exclusions})
	if err != nil || digestBytes(treePayload) != manifest.TreeSHA256 {
		issues = append(issues, issue("tree_identity_invalid", "tree_sha256", "snapshot tree identity is inconsistent"))
	}
	return sortedIssues(issues)
}

func validateReviewAdmission(manifest SnapshotManifest) []QuarantineIssue {
	var issues []QuarantineIssue
	admission := manifest.ReviewAdmission
	issues = append(issues, validateAdmissionPolicyBinding(
		admission.AdmissionMethod,
		admission.AdmissionPolicyID,
		admission.AdmissionPolicySHA256,
		"review_admission",
	)...)
	if manifest.AuthorityState != "reviewed" {
		issues = append(issues, issue("source_review_not_accepted", "authority_state", "snapshot lacks reviewed source-spec authority"))
	}
	if admission.Decision != "accepted" {
		issues = append(issues, issue("source_review_not_accepted", "review_admission.decision", "source-spec review decision is not accepted"))
	}
	for field, digest := range map[string]string{
		"review_admission.receipt_sha256":           admission.ReceiptSHA256,
		"review_admission.proposal_payload_sha256":  admission.ProposalPayloadSHA256,
		"review_admission.proposal_document_sha256": admission.ProposalDocumentSHA256,
		"review_admission.source_spec_sha256":       admission.SourceSpecSHA256,
		"review_admission.signature_sha256":         admission.SignatureSHA256,
		"review_admission.trust_policy_sha256":      admission.TrustPolicySHA256,
	} {
		if !sha256Pattern.MatchString(digest) {
			issues = append(issues, issue("review_admission_identity_invalid", field, "review admission requires a full lowercase SHA-256 identity"))
		}
	}
	if admission.SourceSpecSHA256 != manifest.SourceSpecSHA256 {
		issues = append(issues, issue("review_admission_source_mismatch", "review_admission.source_spec_sha256", "review admission does not bind the snapshot source specification"))
	}
	if admission.ProposalID != "inventory-proposal:"+admission.ProposalPayloadSHA256 {
		issues = append(issues, issue("review_admission_proposal_mismatch", "review_admission.proposal_id", "review admission proposal ID does not bind its proposal payload"))
	}
	if !reviewerPattern.MatchString(admission.Reviewer) {
		issues = append(issues, issue("review_admission_reviewer_missing", "review_admission.reviewer", "accepted source review requires an explicit reviewer"))
	}
	if !isCanonicalUTC(admission.ReviewedAt) {
		issues = append(issues, issue("review_admission_time_invalid", "review_admission.reviewed_at", "accepted source review requires canonical RFC3339 UTC time"))
	}
	if admission.SignatureFormat != "sshsig-ed25519" {
		issues = append(issues, issue("review_admission_signature_invalid", "review_admission.signature_format", "source review must use an Ed25519 SSHSIG signature"))
	}
	if admission.SignatureNamespace != "archeion-knowledge-source-review-v1" {
		issues = append(issues, issue("review_admission_signature_invalid", "review_admission.signature_namespace", "source review SSHSIG namespace is unsupported"))
	}
	for field, binding := range map[string]struct{ objectPath, digest string }{
		"review_admission.receipt_object_path":      {admission.ReceiptObjectPath, admission.ReceiptSHA256},
		"review_admission.proposal_object_path":     {admission.ProposalObjectPath, admission.ProposalDocumentSHA256},
		"review_admission.source_spec_object_path":  {admission.SourceSpecObjectPath, admission.SourceSpecSHA256},
		"review_admission.signature_object_path":    {admission.SignatureObjectPath, admission.SignatureSHA256},
		"review_admission.trust_policy_object_path": {admission.TrustPolicyObjectPath, admission.TrustPolicySHA256},
	} {
		if !sha256Pattern.MatchString(binding.digest) || binding.objectPath != reviewObjectRelativePath(binding.digest) || validateRelativePath(binding.objectPath) != nil {
			issues = append(issues, issue("review_admission_object_path_invalid", field, "review object path does not match its whole-document SHA-256"))
		}
	}
	for _, artifact := range []struct {
		field    string
		size     int64
		maxBytes int64
	}{
		{"review_admission.receipt_size", admission.ReceiptSize, maxReviewReceiptBytes},
		{"review_admission.proposal_document_size", admission.ProposalDocumentSize, maxReviewProposalBytes},
		{"review_admission.source_spec_size", admission.SourceSpecSize, maxReviewSourceSpecBytes},
		{"review_admission.signature_size", admission.SignatureSize, maxReviewSignatureBytes},
		{"review_admission.trust_policy_size", admission.TrustPolicySize, maxReviewTrustPolicyBytes},
	} {
		if artifact.size <= 0 || artifact.size > artifact.maxBytes {
			issues = append(issues, issue("review_admission_size_invalid", artifact.field, "review artifact size is missing or exceeds its role-specific verification bound"))
		}
	}
	return sortedIssues(issues)
}

func validateAdmissionPolicyBinding(method, policyID, policySHA256, fieldPrefix string) []QuarantineIssue {
	if method == "" && policyID == "" && policySHA256 == "" {
		return nil
	}
	if method != "standing_policy" {
		return []QuarantineIssue{issue("review_admission_method_invalid", fieldPrefix+".admission_method", "admission provenance must be omitted for legacy review or use the supported standing-policy method")}
	}
	var issues []QuarantineIssue
	if !sha256Pattern.MatchString(policySHA256) {
		issues = append(issues, issue("review_admission_policy_invalid", fieldPrefix+".admission_policy_sha256", "standing admission requires a full lowercase SHA-256 policy identity"))
	}
	if policyID != "source-admission-policy:"+policySHA256 {
		issues = append(issues, issue("review_admission_policy_invalid", fieldPrefix+".admission_policy_id", "standing admission policy ID must bind the exact policy SHA-256"))
	}
	return sortedIssues(issues)
}

func isCanonicalUTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format("2006-01-02T15:04:05Z") == value
}

type reviewArtifactBinding struct {
	label      string
	configPath string
	objectPath string
	digest     string
	size       int64
	maxBytes   int64
}

func verifyReviewBundle(config CompileConfig, rawRoot string, manifest SnapshotManifest) []QuarantineIssue {
	admission := manifest.ReviewAdmission
	bindings := []reviewArtifactBinding{
		{"source specification", config.SpecPath, admission.SourceSpecObjectPath, admission.SourceSpecSHA256, admission.SourceSpecSize, maxReviewSourceSpecBytes},
		{"inventory proposal", config.ProposalPath, admission.ProposalObjectPath, admission.ProposalDocumentSHA256, admission.ProposalDocumentSize, maxReviewProposalBytes},
		{"review receipt", config.ReviewReceiptPath, admission.ReceiptObjectPath, admission.ReceiptSHA256, admission.ReceiptSize, maxReviewReceiptBytes},
		{"review signature", config.ReviewSignaturePath, admission.SignatureObjectPath, admission.SignatureSHA256, admission.SignatureSize, maxReviewSignatureBytes},
	}
	issues := make([]QuarantineIssue, 0)
	// The external operator policy and the manifest-bound CAS copy are both read
	// and compared, so both count against the process-memory admission budget.
	if !reviewBundleSizeWithinLimit(
		admission.SourceSpecSize,
		admission.ProposalDocumentSize,
		admission.ReceiptSize,
		admission.SignatureSize,
		admission.TrustPolicySize,
		admission.TrustPolicySize,
	) {
		return []QuarantineIssue{issue("review_bundle_size_limit_exceeded", "review bundle", "combined review artifacts exceed the fixed verification budget")}
	}
	artifactBytes := make(map[string][]byte, len(bindings))
	for _, binding := range bindings {
		if strings.TrimSpace(binding.configPath) == "" {
			issues = append(issues, issue("review_artifact_path_missing", binding.label, "independent review verification requires an explicit artifact path"))
			continue
		}
		expectedPath := filepath.Join(rawRoot, filepath.FromSlash(binding.objectPath))
		providedPath, err := filepath.Abs(binding.configPath)
		if err != nil || filepath.Clean(providedPath) != filepath.Clean(expectedPath) {
			issues = append(issues, issue("review_artifact_path_mismatch", binding.label, "review artifact path does not match the manifest-bound review CAS object"))
			continue
		}
		if binding.size <= 0 || binding.size > binding.maxBytes {
			issues = append(issues, issue("review_artifact_size_invalid", binding.label, "review artifact declaration exceeds its role-specific bound"))
			continue
		}
		// Read no more than the exact signed declaration. Combined with the
		// aggregate declaration check, malformed files cannot inflate verifier
		// memory before their size mismatch is detected.
		data, readIssues := readStableBoundedFile(providedPath, binding.label, binding.size)
		issues = append(issues, readIssues...)
		if len(readIssues) != 0 {
			continue
		}
		if digestBytes(data) != binding.digest {
			issues = append(issues, issue("review_artifact_digest_mismatch", binding.label, "review artifact bytes do not match the manifest-bound SHA-256"))
			continue
		}
		if int64(len(data)) != binding.size {
			issues = append(issues, issue("review_artifact_size_mismatch", binding.label, "review artifact bytes do not match the manifest-bound size"))
			continue
		}
		artifactBytes[binding.label] = data
	}
	if len(issues) != 0 {
		return sortedIssues(issues)
	}
	policyCASPath := filepath.Join(rawRoot, filepath.FromSlash(admission.TrustPolicyObjectPath))
	policyCASBytes, policyCASIssues := readStableBoundedFile(policyCASPath, "review trust-policy CAS copy", admission.TrustPolicySize)
	issues = append(issues, policyCASIssues...)
	trustedPolicyPath, policyPathErr := filepath.Abs(config.AllowedSignersPath)
	if strings.TrimSpace(config.AllowedSignersPath) == "" || policyPathErr != nil || isWithin(rawRoot, trustedPolicyPath) {
		issues = append(issues, issue("review_trust_root_invalid", "allowed signers", "operator-trusted allowed_signers must be an explicit path outside the snapshot store"))
	} else {
		trustedPolicyBytes, policyIssues := readStableBoundedFile(trustedPolicyPath, "operator-trusted allowed signers", admission.TrustPolicySize)
		issues = append(issues, policyIssues...)
		if len(policyIssues) == 0 && len(policyCASIssues) == 0 {
			if digestBytes(trustedPolicyBytes) != admission.TrustPolicySHA256 || digestBytes(policyCASBytes) != admission.TrustPolicySHA256 || int64(len(trustedPolicyBytes)) != admission.TrustPolicySize || int64(len(policyCASBytes)) != admission.TrustPolicySize || !bytes.Equal(trustedPolicyBytes, policyCASBytes) {
				issues = append(issues, issue("review_trust_root_mismatch", "allowed signers", "snapshot trust-policy copy does not equal the independently configured operator trust root"))
			} else {
				artifactBytes["allowed signers"] = trustedPolicyBytes
			}
		}
	}
	if len(issues) != 0 {
		return sortedIssues(issues)
	}

	var proposal InventoryProposal
	issues = append(issues, decodeStrictReviewDocument(artifactBytes["inventory proposal"], &proposal, "inventory proposal")...)
	var spec SourceSpec
	issues = append(issues, decodeStrictReviewDocument(artifactBytes["source specification"], &spec, "source specification")...)
	var receipt SourceReviewReceipt
	issues = append(issues, decodeStrictReviewDocument(artifactBytes["review receipt"], &receipt, "review receipt")...)
	if len(issues) != 0 {
		return sortedIssues(issues)
	}

	canonicalProposal, _ := marshalDocument(proposal)
	coreBytes, _ := json.Marshal(proposal.InventoryProposalCore)
	proposalPayloadDigest := digestBytes(coreBytes)
	if !bytes.Equal(canonicalProposal, artifactBytes["inventory proposal"]) ||
		proposal.ProposalPayloadSHA256 != proposalPayloadDigest ||
		proposal.ProposalID != "inventory-proposal:"+proposalPayloadDigest ||
		proposal.ProposalID != admission.ProposalID ||
		proposal.ProposalPayloadSHA256 != admission.ProposalPayloadSHA256 {
		issues = append(issues, issue("review_proposal_identity_invalid", "inventory proposal", "proposal canonical bytes, payload identity, ID, or admission binding do not match"))
	}
	if proposal.SchemaVersion != snapshotSchemaVersion || proposal.ProposalKind != "source_spec_inventory_proposal" || proposal.State != "proposal" || proposal.ReviewState != "unreviewed" || proposal.AuthorityState != "non_authoritative" || proposal.CompileEligible || proposal.PromoteEligible {
		issues = append(issues, issue("review_proposal_state_invalid", "inventory proposal", "signed proposal does not preserve its safe unreviewed non-authoritative state"))
	}
	if !sha256Pattern.MatchString(proposal.MetadataSHA256) {
		issues = append(issues, issue("review_proposal_identity_invalid", "inventory proposal.metadata_sha256", "proposal metadata identity is malformed"))
	}
	canonicalSpec, _ := marshalDocument(proposal.SourceSpecDraft)
	if !bytes.Equal(canonicalSpec, artifactBytes["source specification"]) {
		issues = append(issues, issue("review_spec_extraction_mismatch", "source specification", "standalone source specification is not the deterministic proposal draft extraction"))
	}
	if !reflect.DeepEqual(spec, proposal.SourceSpecDraft) || digestBytes(artifactBytes["source specification"]) != manifest.SourceSpecSHA256 {
		issues = append(issues, issue("review_spec_identity_invalid", "source specification", "source specification does not match the signed proposal and snapshot identity"))
	}
	issues = append(issues, validateReviewedSourceSpec(spec, proposal)...)
	issues = append(issues, compareSnapshotToSpec(manifest, spec)...)

	canonicalReceipt, _ := marshalDocument(receipt)
	if !bytes.Equal(canonicalReceipt, artifactBytes["review receipt"]) {
		issues = append(issues, issue("review_receipt_canonical_invalid", "review receipt", "review receipt is not canonical JSON with one trailing newline"))
	}
	if receipt.SchemaVersion != snapshotSchemaVersion || receipt.ReceiptKind != "source_spec_review" || receipt.Decision != "accepted" || receipt.ProposalID != proposal.ProposalID || receipt.ProposalPayloadSHA256 != proposal.ProposalPayloadSHA256 || receipt.SourceSpecSHA256 != manifest.SourceSpecSHA256 || receipt.Reviewer != admission.Reviewer || receipt.ReviewedAt != admission.ReviewedAt || !isCanonicalUTC(receipt.ReviewedAt) {
		issues = append(issues, issue("review_receipt_binding_invalid", "review receipt", "review receipt does not bind the accepted proposal, source spec, reviewer, time, and manifest admission"))
	}
	issues = append(issues, validateAdmissionPolicyBinding(
		receipt.AdmissionMethod,
		receipt.AdmissionPolicyID,
		receipt.AdmissionPolicySHA256,
		"review receipt",
	)...)
	if receipt.AdmissionMethod != admission.AdmissionMethod || receipt.AdmissionPolicyID != admission.AdmissionPolicyID || receipt.AdmissionPolicySHA256 != admission.AdmissionPolicySHA256 {
		issues = append(issues, issue("review_receipt_binding_invalid", "review receipt", "review receipt admission provenance does not exactly match the snapshot manifest"))
	}
	if err := validateEd25519SSHSIG(artifactBytes["review signature"], reviewSignatureNamespace); err != nil {
		issues = append(issues, issue("review_signature_format_invalid", "review signature", "detached signature is not a canonical Ed25519 SSHSIG for the required namespace"))
	}
	if len(issues) == 0 {
		issues = append(issues, verifySSHSIG(receipt.Reviewer, artifactBytes["review receipt"], artifactBytes["review signature"], artifactBytes["allowed signers"])...)
	}
	return sortedIssues(issues)
}

func reviewBundleSizeWithinLimit(sizes ...int64) bool {
	total := int64(0)
	for _, size := range sizes {
		if size < 0 || size > maxReviewBundleBytes-total {
			return false
		}
		total += size
	}
	return true
}

func decodeStrictReviewDocument(data []byte, target any, label string) []QuarantineIssue {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return []QuarantineIssue{issue("review_artifact_invalid_json", label, "review artifact is not valid strict JSON")}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return []QuarantineIssue{issue("review_artifact_multiple_values", label, "review artifact contains more than one JSON value")}
	}
	return nil
}

func validateReviewedSourceSpec(spec SourceSpec, proposal InventoryProposal) []QuarantineIssue {
	var issues []QuarantineIssue
	if spec.SchemaVersion != snapshotSchemaVersion || len(spec.Files) == 0 {
		issues = append(issues, issue("review_spec_invalid", "source specification", "reviewed source specification schema or file inventory is invalid"))
	}
	if spec.Provenance.Generated || spec.Provenance.RecursiveSource || (spec.Provenance.OriginKind != "official" && spec.Provenance.OriginKind != "primary") {
		issues = append(issues, issue("review_spec_provenance_invalid", "source specification.provenance", "reviewed source specification is generated, recursive, or lacks official/primary provenance"))
	}
	if !strings.HasPrefix(spec.ComponentID, "cmp:github:") {
		issues = append(issues, issue("source_profile_unsupported", "source specification.component_id", "evidence v1 accepts only the explicit GitHub official full-commit source profile"))
	} else if !fullGitCommitPattern.MatchString(spec.SourceRevision) || !isCommitBoundGitHubURI(spec.CanonicalURI, spec.SourceRevision) {
		issues = append(issues, issue("review_spec_revision_not_exact", "source specification.source_revision", "v1 official Git source revision must be a full lowercase 40-hex commit bound into canonical_uri"))
	}
	if spec.Rights.Permissions["retrieval"] != "true" {
		issues = append(issues, issue("retrieval_rights_denied", "source specification.rights", "reviewed source specification does not explicitly allow retrieval"))
	}
	var bytesTotal, excludedBytes int64
	for _, file := range spec.Files {
		bytesTotal += file.Size
	}
	for _, exclusion := range spec.Exclusions {
		excludedBytes += exclusion.Size
	}
	if proposal.FileCount != len(spec.Files) || proposal.ByteSize != bytesTotal || proposal.ExcludedFileCount != len(spec.Exclusions) || proposal.ExcludedByteSize != excludedBytes || !reflect.DeepEqual(proposal.Exclusions, spec.Exclusions) {
		issues = append(issues, issue("review_proposal_inventory_mismatch", "inventory proposal", "proposal counts, bytes, or exclusions do not match its source-spec draft"))
	}
	return issues
}

func isCommitBoundGitHubURI(value, commit string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "github.com") {
		return false
	}
	segments := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	for index := 1; index < len(segments); index++ {
		if segments[index] == commit && (segments[index-1] == "tree" || segments[index-1] == "blob" || segments[index-1] == "commit") {
			return true
		}
	}
	return false
}

func compareSnapshotToSpec(manifest SnapshotManifest, spec SourceSpec) []QuarantineIssue {
	expectedSource := SourceLineage{
		SourceID: spec.SourceID, CanonicalURI: spec.CanonicalURI, ComponentID: spec.ComponentID,
		ComponentVersionID: spec.ComponentVersionID, ResolvedVersion: spec.ResolvedVersion,
		SourceRevision: spec.SourceRevision, ChannelID: spec.ChannelID, ChannelType: spec.ChannelType,
		Rights: spec.Rights, AccessScope: spec.AccessScope, Classification: spec.Classification,
		SecurityDomain: spec.SecurityDomain, Language: spec.Language, FetchedAt: spec.FetchedAt,
		ObservedAt: spec.ObservedAt, OriginKind: spec.Provenance.OriginKind,
	}
	if manifest.SnapshotID != spec.SnapshotID || !reflect.DeepEqual(manifest.Source, expectedSource) || !reflect.DeepEqual(manifest.Exclusions, spec.Exclusions) {
		return []QuarantineIssue{issue("review_snapshot_spec_mismatch", "snapshot manifest", "snapshot source lineage or exclusions differ from the accepted source specification")}
	}
	expectedFiles := append([]ExpectedFile(nil), spec.Files...)
	sort.Slice(expectedFiles, func(i, j int) bool { return expectedFiles[i].RelativePath < expectedFiles[j].RelativePath })
	if len(expectedFiles) != len(manifest.Files) {
		return []QuarantineIssue{issue("review_snapshot_spec_mismatch", "snapshot manifest.files", "snapshot file inventory differs from the accepted source specification")}
	}
	for index, expected := range expectedFiles {
		actual := manifest.Files[index]
		wanted := ManifestFile{
			RelativePath: expected.RelativePath, MediaType: expected.MediaType, SHA256: expected.SHA256,
			Size: expected.Size, RawBlobID: "raw:" + expected.SHA256,
			ObjectPath: rawObjectRelativePath(expected.SHA256), SnapshotID: spec.SnapshotID,
			SourceID: spec.SourceID, ComponentID: spec.ComponentID,
			ComponentVersionID: spec.ComponentVersionID, ChannelID: spec.ChannelID,
		}
		if !reflect.DeepEqual(actual, wanted) {
			return []QuarantineIssue{issue("review_snapshot_spec_mismatch", actual.RelativePath, "snapshot file occurrence differs from the accepted source specification")}
		}
	}
	return nil
}

func verifySSHSIG(reviewer string, receipt, signature, policy []byte) []QuarantineIssue {
	if issues := validateNoSymlinkPath(sshKeygenPath, "<ssh-keygen>"); len(issues) != 0 {
		return []QuarantineIssue{issue("review_verifier_unavailable", "<ssh-keygen>", "offline SSHSIG verifier is unavailable or unsafe")}
	}
	policyFile, err := immutableExecInput("allowed-signers-", policy)
	if err != nil {
		return []QuarantineIssue{issue("review_verifier_input_failed", "allowed signers", "verified trust-root bytes could not be isolated for SSHSIG verification")}
	}
	defer policyFile.Close()
	signatureFile, err := immutableExecInput("review-signature-", signature)
	if err != nil {
		return []QuarantineIssue{issue("review_verifier_input_failed", "review signature", "verified signature bytes could not be isolated for SSHSIG verification")}
	}
	defer signatureFile.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, sshKeygenPath, "-Y", "verify", "-f", "/proc/self/fd/3", "-I", reviewer, "-n", reviewSignatureNamespace, "-s", "/proc/self/fd/4")
	command.ExtraFiles = []*os.File{policyFile, signatureFile}
	command.Stdin = bytes.NewReader(receipt)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return []QuarantineIssue{issue("review_signature_verification_failed", "review signature", "detached SSHSIG did not verify against the exact allowed-signers policy")}
	}
	return nil
}

func immutableExecInput(prefix string, data []byte) (*os.File, error) {
	file, err := os.CreateTemp("", prefix)
	if err != nil {
		return nil, err
	}
	name := file.Name()
	if removeErr := os.Remove(name); removeErr != nil {
		file.Close()
		return nil, removeErr
	}
	if chmodErr := file.Chmod(0o400); chmodErr != nil {
		file.Close()
		return nil, chmodErr
	}
	if _, writeErr := file.Write(data); writeErr != nil {
		file.Close()
		return nil, writeErr
	}
	if syncErr := file.Sync(); syncErr != nil {
		file.Close()
		return nil, syncErr
	}
	if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
		file.Close()
		return nil, seekErr
	}
	return file, nil
}

func validateEd25519SSHSIG(data []byte, namespace string) error {
	if !bytes.HasPrefix(data, []byte("-----BEGIN SSH SIGNATURE-----\n")) || !bytes.HasSuffix(data, []byte("-----END SSH SIGNATURE-----\n")) {
		return errors.New("noncanonical SSH signature armor")
	}
	block, remainder := pem.Decode(data)
	if block == nil || block.Type != "SSH SIGNATURE" || len(bytes.TrimSpace(remainder)) != 0 {
		return errors.New("invalid SSH signature PEM")
	}
	reader := bytes.NewReader(block.Bytes)
	magic := make([]byte, 6)
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != "SSHSIG" {
		return errors.New("invalid SSHSIG magic")
	}
	var version uint32
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil || version != 1 {
		return errors.New("unsupported SSHSIG version")
	}
	publicKey, err := readSSHString(reader)
	if err != nil {
		return err
	}
	keyReader := bytes.NewReader(publicKey)
	keyAlgorithm, err := readSSHString(keyReader)
	if err != nil || string(keyAlgorithm) != "ssh-ed25519" {
		return errors.New("SSHSIG key is not Ed25519")
	}
	keyBytes, err := readSSHString(keyReader)
	if err != nil || len(keyBytes) != 32 || keyReader.Len() != 0 {
		return errors.New("invalid Ed25519 public key")
	}
	signedNamespace, err := readSSHString(reader)
	if err != nil || string(signedNamespace) != namespace {
		return errors.New("SSHSIG namespace mismatch")
	}
	reserved, err := readSSHString(reader)
	if err != nil || len(reserved) != 0 {
		return errors.New("SSHSIG reserved field is not empty")
	}
	hashAlgorithm, err := readSSHString(reader)
	if err != nil || (string(hashAlgorithm) != "sha256" && string(hashAlgorithm) != "sha512") {
		return errors.New("unsupported SSHSIG hash")
	}
	signatureBlob, err := readSSHString(reader)
	if err != nil || reader.Len() != 0 {
		return errors.New("invalid SSHSIG envelope")
	}
	signatureReader := bytes.NewReader(signatureBlob)
	signatureAlgorithm, err := readSSHString(signatureReader)
	if err != nil || string(signatureAlgorithm) != "ssh-ed25519" {
		return errors.New("SSHSIG signature is not Ed25519")
	}
	signature, err := readSSHString(signatureReader)
	if err != nil || len(signature) != 64 || signatureReader.Len() != 0 {
		return errors.New("invalid Ed25519 signature")
	}
	return nil
}

func readSSHString(reader *bytes.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if uint64(length) > uint64(reader.Len()) {
		return nil, errors.New("SSH string exceeds envelope")
	}
	value := make([]byte, int(length))
	_, err := io.ReadFull(reader, value)
	return value, err
}

func readStableBoundedFile(filePath, label string, maxBytes int64) ([]byte, []QuarantineIssue) {
	if issues := validateNoSymlinkPath(filePath, label); len(issues) != 0 {
		return nil, issues
	}
	before, err := os.Lstat(filePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > maxBytes {
		return nil, []QuarantineIssue{issue("review_artifact_unavailable", label, "review artifact is not a bounded regular file")}
	}
	handle, err := os.Open(filePath)
	if err != nil {
		return nil, []QuarantineIssue{issue("review_artifact_unavailable", label, "review artifact could not be opened")}
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		handle.Close()
		return nil, []QuarantineIssue{issue("review_artifact_replaced", label, "review artifact identity changed before read")}
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxBytes+1))
	closeErr := handle.Close()
	after, statErr := os.Lstat(filePath)
	if readErr != nil || closeErr != nil || statErr != nil || int64(len(data)) > maxBytes || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || after.ModTime() != opened.ModTime() {
		return nil, []QuarantineIssue{issue("review_artifact_replaced", label, "review artifact changed or exceeded bounds during read")}
	}
	return data, nil
}

func profileFor(input ManifestFile, data []byte, maxSpans int) (string, string, []rawSpan, []QuarantineIssue) {
	mediaType, _, err := mime.ParseMediaType(input.MediaType)
	if err != nil {
		return "", "", nil, []QuarantineIssue{issue("media_type_invalid", input.RelativePath, "input media type is invalid")}
	}
	switch strings.ToLower(mediaType) {
	case "text/markdown", "text/x-markdown":
		spans, err := markdownSpans(data, maxSpans)
		if errors.Is(err, errMarkdownSpanLimit) {
			return "", "", nil, []QuarantineIssue{issue("span_count_limit_exceeded", input.RelativePath, "normalized spans exceed the configured span-count limit")}
		}
		if errors.Is(err, errMarkdownHeadingLabelLimit) {
			return "", "", nil, []QuarantineIssue{issue("heading_label_limit_exceeded", input.RelativePath, "markdown heading label exceeds the fixed metadata bound")}
		}
		if err != nil {
			return "", "", nil, []QuarantineIssue{issue("markdown_parse_failed", input.RelativePath, "markdown span extraction failed within its configured bounds")}
		}
		spans, err = boundedExactSpans(data, spans, maxSpans, maxNormalizedSpanBytes)
		if errors.Is(err, errMarkdownSpanLimit) {
			return "", "", nil, []QuarantineIssue{issue("span_count_limit_exceeded", input.RelativePath, "normalized spans exceed the configured span-count limit")}
		}
		if err != nil {
			return "", "", nil, []QuarantineIssue{issue("span_coordinate_invalid", input.RelativePath, "normalized spans do not form a bounded exact-byte partition")}
		}
		return markdownParserVersion, markdownProfile, spans, nil
	case "application/json", "text/json", "application/yaml", "application/x-yaml", "text/yaml", "text/x-yaml", "text/plain":
		spans, err := boundedExactSpans(data, []rawSpan{{kind: "document", start: 0, end: len(data)}}, maxSpans, maxNormalizedSpanBytes)
		if errors.Is(err, errMarkdownSpanLimit) {
			return "", "", nil, []QuarantineIssue{issue("span_count_limit_exceeded", input.RelativePath, "normalized spans exceed the configured span-count limit")}
		}
		if err != nil {
			return "", "", nil, []QuarantineIssue{issue("span_coordinate_invalid", input.RelativePath, "normalized spans do not form a bounded exact-byte partition")}
		}
		return wholeFileParser, wholeFileProfile, spans, nil
	default:
		return "", "", nil, []QuarantineIssue{issue("unsupported_media_type", input.RelativePath, "input media type has no reviewed exact-coordinate profile")}
	}
}

func readVerifiedRaw(rawRoot string, file ManifestFile, maxBytes int64) ([]byte, []QuarantineIssue) {
	expectedRelative := rawObjectRelativePath(file.SHA256)
	if file.ObjectPath != expectedRelative {
		return nil, []QuarantineIssue{issue("raw_object_path_invalid", file.RelativePath, "raw object path does not match the declared digest")}
	}
	objectPath := filepath.Join(rawRoot, filepath.FromSlash(expectedRelative))
	if !isWithin(rawRoot, objectPath) {
		return nil, []QuarantineIssue{issue("raw_object_path_escape", file.RelativePath, "raw object path escapes the raw store")}
	}
	if issues := validateNoSymlinkPath(objectPath, file.RelativePath); len(issues) != 0 {
		return nil, issues
	}
	before, err := os.Lstat(objectPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, []QuarantineIssue{issue("raw_object_unavailable", file.RelativePath, "raw object is not a regular readable file")}
	}
	if before.Size() != file.Size || before.Size() > maxBytes {
		return nil, []QuarantineIssue{issue("raw_object_size_mismatch", file.RelativePath, "raw object size differs from the complete snapshot")}
	}
	handle, err := os.Open(objectPath)
	if err != nil {
		return nil, []QuarantineIssue{issue("raw_object_read_failed", file.RelativePath, "raw object could not be opened")}
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		handle.Close()
		return nil, []QuarantineIssue{issue("raw_object_replaced", file.RelativePath, "raw object identity changed before read")}
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxBytes+1))
	closeErr := handle.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maxBytes {
		return nil, []QuarantineIssue{issue("raw_object_read_failed", file.RelativePath, "raw object could not be read within bounds")}
	}
	after, err := os.Lstat(objectPath)
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || after.ModTime() != opened.ModTime() {
		return nil, []QuarantineIssue{issue("raw_object_replaced", file.RelativePath, "raw object identity changed during read")}
	}
	if int64(len(data)) != file.Size || digestBytes(data) != file.SHA256 {
		return nil, []QuarantineIssue{issue("raw_object_corrupt", file.RelativePath, "raw object bytes do not match the complete snapshot")}
	}
	return data, nil
}

func occurrenceIdentity(manifestID string, file ManifestFile) string {
	payload, _ := json.Marshal(struct {
		ManifestID   string `json:"manifest_id"`
		SnapshotID   string `json:"snapshot_id"`
		RelativePath string `json:"relative_path"`
		RawSHA256    string `json:"raw_sha256"`
	}{manifestID, file.SnapshotID, file.RelativePath, file.SHA256})
	return "evidence-occurrence:" + digestBytes(payload)
}

func spanIdentity(occurrenceID, parserVersion, profileVersion string, span EvidenceSpan) string {
	payload, _ := json.Marshal(struct {
		OccurrenceID      string   `json:"occurrence_id"`
		ParserVersion     string   `json:"parser_version"`
		ProfileVersion    string   `json:"profile_version"`
		Ordinal           int      `json:"ordinal"`
		Kind              string   `json:"kind"`
		HeadingBreadcrumb []string `json:"heading_breadcrumb"`
		RawByteStart      int64    `json:"raw_byte_start"`
		RawByteEnd        int64    `json:"raw_byte_end"`
		RawLineStart      int      `json:"raw_line_start"`
		RawLineEnd        int      `json:"raw_line_end"`
		PayloadSHA256     string   `json:"payload_sha256"`
		TrustEnvelopeID   string   `json:"trust_envelope_id"`
	}{occurrenceID, parserVersion, profileVersion, span.Ordinal, span.Kind, span.HeadingBreadcrumb, span.RawByteStart, span.RawByteEnd, span.RawLineStart, span.RawLineEnd, span.PayloadSHA256, span.TrustEnvelopeID})
	return "evidence-span:" + digestBytes(payload)
}

func newTrustEnvelope() TrustEnvelope {
	core := TrustEnvelopeCore{
		SchemaVersion:        evidenceSchemaVersion,
		EnvelopeKind:         "untrusted_evidence_content",
		ProfileVersion:       trustProfileVersion,
		ContentClass:         "untrusted_source_data",
		InstructionPolicy:    "forbidden",
		ExecutionPolicy:      "never",
		ToolPolicy:           "never",
		InterpretationPolicy: "evidence_only",
	}
	payload, _ := json.Marshal(core)
	digest := digestBytes(payload)
	return TrustEnvelope{
		EnvelopeID:            "trust-envelope:" + digest,
		EnvelopePayloadSHA256: digest,
		TrustEnvelopeCore:     core,
	}
}

func rawObjectRelativePath(digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return "invalid"
	}
	return path.Join("raw", "sha256", hexDigest[:2], hexDigest)
}

func reviewObjectRelativePath(digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return "invalid"
	}
	return path.Join("review", "sha256", hexDigest[:2], hexDigest)
}

func normalizedObjectRelativePath(digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return path.Join("normalized", "sha256", hexDigest[:2], hexDigest)
}

func validateRelativePath(value string) error {
	if value == "" || strings.Contains(value, "\\") || path.IsAbs(value) || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return errors.New("invalid relative path")
	}
	return nil
}

func validateNoSymlinkPath(candidate, label string) []QuarantineIssue {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return []QuarantineIssue{issue("path_invalid", label, "path could not be resolved")}
	}
	current := string(filepath.Separator)
	volume := filepath.VolumeName(abs)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	rel := strings.TrimPrefix(abs, current)
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, fs.ErrNotExist) {
				return []QuarantineIssue{issue("path_unavailable", label, "required input path does not exist")}
			}
			return []QuarantineIssue{issue("path_unreadable", label, "required input path cannot be inspected")}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return []QuarantineIssue{issue("symlink_rejected", label, "symlinks are forbidden in evidence inputs")}
		}
	}
	return nil
}

func validateNoSymlinkPathExistingPrefix(candidate, label string) []QuarantineIssue {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return []QuarantineIssue{issue("path_invalid", label, "path could not be resolved")}
	}
	for current := abs; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return []QuarantineIssue{issue("symlink_rejected", label, "symlinks are forbidden in evidence-store paths")}
			}
			return validateNoSymlinkPath(current, label)
		}
		if !errors.Is(statErr, fs.ErrNotExist) {
			return []QuarantineIssue{issue("path_unreadable", label, "evidence-store path cannot be inspected")}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func pathsOverlap(a, b string) bool { return isWithin(a, b) || isWithin(b, a) }

func isWithin(base, candidate string) bool {
	rel, err := filepath.Rel(base, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func openSafeOutputRoot(storeRoot string) (*os.Root, fs.FileInfo, error) {
	abs, err := filepath.Abs(storeRoot)
	if err != nil {
		return nil, nil, err
	}
	root, opened, err := openAbsoluteRootNoSymlinks(abs, 0o755)
	if err != nil {
		return nil, nil, err
	}
	pathInfo, err := os.Lstat(abs)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !os.SameFile(opened, pathInfo) {
		root.Close()
		return nil, nil, errors.New("output store root path changed while opening")
	}
	if err := verifyRootStillBound(abs, root, opened); err != nil {
		root.Close()
		return nil, nil, err
	}
	return root, opened, nil
}

func openAbsoluteRootNoSymlinks(directory string, mode fs.FileMode) (*os.Root, fs.FileInfo, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, nil, err
	}
	volume := filepath.VolumeName(abs)
	base := volume + string(filepath.Separator)
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, nil, err
	}
	relative := strings.TrimPrefix(abs, base)
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		info, statErr := root.Lstat(part)
		if errors.Is(statErr, fs.ErrNotExist) {
			if err := root.Mkdir(part, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				root.Close()
				return nil, nil, err
			}
			info, statErr = root.Lstat(part)
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			root.Close()
			return nil, nil, errors.New("output store path contains a symlink or non-directory component")
		}
		child, err := root.OpenRoot(part)
		if err != nil {
			root.Close()
			return nil, nil, err
		}
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			child.Close()
			root.Close()
			return nil, nil, errors.New("output store component changed while opening")
		}
		root.Close()
		root = child
	}
	opened, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	return root, opened, nil
}

func ensureRootDirectories(root *os.Root, directory string, mode fs.FileMode) error {
	if directory == "." {
		return nil
	}
	current := ""
	for _, part := range strings.Split(directory, "/") {
		if part == "" || part == "." {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = path.Join(current, part)
		}
		info, err := root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := root.Mkdir(current, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			info, err = root.Lstat(current)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("immutable object parent contains a symlink or non-directory component")
		}
	}
	return nil
}

func validateRootDirectoryComponents(root *os.Root, directory string) error {
	if directory == "." {
		return nil
	}
	current := ""
	for _, part := range strings.Split(directory, "/") {
		if part == "" || part == "." {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = path.Join(current, part)
		}
		info, err := root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("immutable object parent contains a symlink or non-directory component")
		}
	}
	return nil
}

func makeRootTempDirectory(root *os.Root, storeRoot string, rootInfo fs.FileInfo, parent, prefix string) (string, error) {
	if validateRelativePath(parent) != nil || strings.Contains(prefix, "/") {
		return "", errors.New("unsafe staging directory request")
	}
	if err := ensureRootDirectories(root, parent, 0o700); err != nil {
		return "", err
	}
	if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
		return "", err
	}
	for attempts := 0; attempts < 32; attempts++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		relative := path.Join(parent, prefix+hex.EncodeToString(random))
		if err := root.Mkdir(relative, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return "", err
		}
		if err := validateRootDirectoryComponents(root, relative); err != nil {
			return "", err
		}
		if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
			return "", err
		}
		if err := syncRootDirectory(root, parent); err != nil {
			return "", err
		}
		return relative, nil
	}
	return "", errors.New("could not allocate a unique staging directory")
}

func writeRootSyncedFile(root *os.Root, storeRoot string, rootInfo fs.FileInfo, relative string, data []byte, mode fs.FileMode) error {
	if validateRelativePath(relative) != nil {
		return errors.New("staged object path is not canonical and relative")
	}
	if err := validateRootDirectoryComponents(root, path.Dir(relative)); err != nil {
		return err
	}
	if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
		return err
	}
	handle, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written, writeErr := handle.Write(data)
	if writeErr != nil || written != len(data) {
		handle.Close()
		return errors.New("staged object write was incomplete")
	}
	if err := handle.Sync(); err != nil {
		handle.Close()
		return err
	}
	if err := handle.Close(); err != nil {
		return err
	}
	if err := verifyRootFileDigest(root, relative, digestBytes(data), int64(len(data))); err != nil {
		return err
	}
	return verifyRootStillBound(storeRoot, root, rootInfo)
}

func verifyRootFileDigest(root *os.Root, relative, expectedDigest string, expectedSize int64) error {
	if validateRelativePath(relative) != nil || expectedSize < 0 {
		return errors.New("unsafe rooted object request")
	}
	if err := validateRootDirectoryComponents(root, path.Dir(relative)); err != nil {
		return err
	}
	before, err := root.Lstat(relative)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != expectedSize {
		return errors.New("unsafe object")
	}
	handle, err := root.Open(relative)
	if err != nil {
		return err
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		handle.Close()
		return errors.New("object identity changed before read")
	}
	hash := sha256.New()
	readLimit := expectedSize
	if readLimit < int64(^uint64(0)>>1) {
		readLimit++
	}
	size, readErr := io.Copy(hash, io.LimitReader(handle, readLimit))
	closeErr := handle.Close()
	after, statErr := root.Lstat(relative)
	if readErr != nil || closeErr != nil || statErr != nil || !os.SameFile(opened, after) || after.Size() != size || after.ModTime() != opened.ModTime() {
		return errors.New("object identity changed during read")
	}
	if size != expectedSize || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return errors.New("object mismatch")
	}
	return nil
}

func syncRootFile(root *os.Root, relative string) error {
	if validateRelativePath(relative) != nil {
		return errors.New("unsafe rooted sync request")
	}
	if err := validateRootDirectoryComponents(root, path.Dir(relative)); err != nil {
		return err
	}
	before, err := root.Lstat(relative)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("rooted sync target is not a regular file")
	}
	handle, err := root.Open(relative)
	if err != nil {
		return err
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		handle.Close()
		return errors.New("rooted sync target changed before sync")
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	after, statErr := root.Lstat(relative)
	if syncErr != nil || closeErr != nil || statErr != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || after.ModTime() != opened.ModTime() {
		return errors.New("rooted sync target changed during sync")
	}
	return nil
}

func commitStagedObject(root *os.Root, storeRoot string, rootInfo fs.FileInfo, stageRelative, targetRelative, digest string, size int64) error {
	if validateRelativePath(stageRelative) != nil || validateRelativePath(targetRelative) != nil {
		return errors.New("immutable object path is not canonical and relative")
	}
	targetParent := path.Dir(targetRelative)
	if err := ensureRootDirectories(root, targetParent, 0o755); err != nil {
		return err
	}
	if err := validateRootDirectoryComponents(root, path.Dir(stageRelative)); err != nil {
		return err
	}
	if err := validateRootDirectoryComponents(root, targetParent); err != nil {
		return err
	}
	if err := verifyRootFileDigest(root, stageRelative, digest, size); err != nil {
		return err
	}
	// The staged payload inode is explicitly durable before its CAS hard link is
	// created. This is repeated here even though staging already synced it.
	if err := syncRootFile(root, stageRelative); err != nil {
		return err
	}
	if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
		return err
	}
	if err := root.Link(stageRelative, targetRelative); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := validateRootDirectoryComponents(root, targetParent); err != nil {
		return err
	}
	if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
		return err
	}
	if err := verifyRootFileDigest(root, targetRelative, digest, size); err != nil {
		return err
	}
	if err := syncRootDirectory(root, targetParent); err != nil {
		return err
	}
	return root.Remove(stageRelative)
}

func quarantine(storeRoot, inputDigest string, manifest SnapshotManifest, issues []QuarantineIssue) error {
	issues = sortedIssues(issues)
	if len(issues) == 0 {
		issues = []QuarantineIssue{issue("evidence_compile_incomplete", "<manifest>", "evidence compilation did not cover every input file")}
	}
	identityPayload, _ := json.Marshal(struct {
		InputDocumentSHA256 string            `json:"input_document_sha256"`
		InputManifestID     string            `json:"input_manifest_id,omitempty"`
		Issues              []QuarantineIssue `json:"issues"`
	}{inputDigest, manifest.ManifestID, issues})
	quarantineDigest := digestBytes(identityPayload)
	report := QuarantineReport{
		SchemaVersion:       evidenceSchemaVersion,
		ReportKind:          "knowledge_evidence_quarantine",
		State:               "quarantined",
		QuarantineID:        "evidence-quarantine:" + quarantineDigest,
		InputDocumentSHA256: inputDigest,
		InputManifestID:     manifest.ManifestID,
		InputSnapshotID:     manifest.SnapshotID,
		Issues:              issues,
	}
	data, _ := marshalDocument(report)
	hexDigest := strings.TrimPrefix(quarantineDigest, "sha256:")
	relative := path.Join("quarantine", "sha256", hexDigest[:2], hexDigest+".json")
	reportPath := filepath.Join(storeRoot, filepath.FromSlash(relative))
	if err := writeImmutableObject(storeRoot, relative, data, 0o444); err != nil {
		return fmt.Errorf("evidence input invalid and quarantine report failed: %w", err)
	}
	return &QuarantinedError{ReportPath: reportPath, Issues: issues}
}

func writeImmutableObject(storeRoot, relative string, data []byte, mode fs.FileMode) error {
	root, rootInfo, err := openSafeOutputRoot(storeRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	return writeImmutableAtRoot(root, storeRoot, rootInfo, relative, data, mode)
}

func writeImmutableAtRoot(root *os.Root, storeRoot string, rootInfo fs.FileInfo, relative string, data []byte, mode fs.FileMode) error {
	if validateRelativePath(relative) != nil {
		return errors.New("immutable object path is not canonical and relative")
	}
	parent := path.Dir(relative)
	if err := ensureRootDirectories(root, parent, 0o755); err != nil {
		return err
	}
	if err := validateRootDirectoryComponents(root, parent); err != nil {
		return err
	}
	if existing, err := readRootStableFile(root, relative, int64(len(data))); err == nil {
		if !bytes.Equal(existing, data) {
			return errors.New("immutable path contains different bytes")
		}
		return verifyRootStillBound(storeRoot, root, rootInfo)
	} else if _, statErr := root.Lstat(relative); !errors.Is(statErr, fs.ErrNotExist) {
		return err
	}

	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tempRelative := path.Join(parent, ".atomic-"+hex.EncodeToString(random))
	temp, err := root.OpenFile(tempRelative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer root.Remove(tempRelative)
	written, writeErr := temp.Write(data)
	if writeErr != nil || written != len(data) {
		temp.Close()
		return errors.New("immutable staged object write was incomplete")
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if staged, err := readRootStableFile(root, tempRelative, int64(len(data))); err != nil || !bytes.Equal(staged, data) {
		return errors.New("immutable staged object failed its byte check")
	}
	if err := validateRootDirectoryComponents(root, parent); err != nil {
		return err
	}
	if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
		return err
	}
	if err := root.Link(tempRelative, relative); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := validateRootDirectoryComponents(root, parent); err != nil {
		return err
	}
	if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
		return err
	}
	existing, err := readRootStableFile(root, relative, int64(len(data)))
	if err != nil || !bytes.Equal(existing, data) {
		return errors.New("immutable path collision")
	}
	if err := syncRootDirectory(root, parent); err != nil {
		return err
	}
	return verifyRootStillBound(storeRoot, root, rootInfo)
}

func readRootStableFile(root *os.Root, relative string, maxBytes int64) ([]byte, error) {
	if validateRelativePath(relative) != nil || maxBytes < 0 {
		return nil, errors.New("unsafe rooted object request")
	}
	if err := validateRootDirectoryComponents(root, path.Dir(relative)); err != nil {
		return nil, err
	}
	before, err := root.Lstat(relative)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > maxBytes {
		return nil, errors.New("rooted object is not a bounded regular file")
	}
	handle, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		handle.Close()
		return nil, errors.New("rooted object changed before read")
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxBytes+1))
	closeErr := handle.Close()
	after, statErr := root.Lstat(relative)
	if readErr != nil || closeErr != nil || statErr != nil || int64(len(data)) > maxBytes || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || after.ModTime() != opened.ModTime() {
		return nil, errors.New("rooted object changed or exceeded its bound during read")
	}
	return data, nil
}

func verifyRootStillBound(storeRoot string, root *os.Root, rootInfo fs.FileInfo) error {
	if issues := validateNoSymlinkPath(storeRoot, storeRoot); len(issues) != 0 {
		return errors.New("output store root path became unsafe")
	}
	pathInfo, err := os.Lstat(storeRoot)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return errors.New("output store root is no longer a directory")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, opened) || !os.SameFile(rootInfo, pathInfo) {
		return errors.New("output store root identity changed during commit")
	}
	return nil
}

func syncRootDirectory(root *os.Root, directory string) error {
	handle, err := root.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func issue(code, pathValue, message string) QuarantineIssue {
	return QuarantineIssue{Code: code, Path: pathValue, Message: message}
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

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func marshalDocument(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
