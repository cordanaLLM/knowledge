package main

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxFineSpanExtensionBytes = int64(1024 * 1024)
	maxFineSpanDocuments      = 1000
	fineSpanExtensionKindDoc  = "document_chunk"
)

// FineSpanExtensionDocument declares one caller-supplied child window nested
// inside an already-admitted coarse evidence span, for small-to-big lexical
// indexing (index the fine judged span as its own document; a hit resolves
// to its enclosing coarse chunk at query time). Every field is untrusted
// operator input: Build independently re-derives and re-verifies the byte
// window, payload hash, line coordinates and content-addressed span identity
// from the exact same raw bytes it already verified for the named parent
// span. Nothing here is trusted blindly, and no new raw source, snapshot or
// evidence manifest is introduced.
type FineSpanExtensionDocument struct {
	ParentSpanID      string   `json:"parent_span_id"`
	Kind              string   `json:"kind"`
	HeadingBreadcrumb []string `json:"heading_breadcrumb"`
	RawByteStart      int64    `json:"raw_byte_start"`
	RawByteEnd        int64    `json:"raw_byte_end"`
}

// FineSpanExtensionInput is the plain per-lineage file bound via
// LineageConfig.FineSpanExtensionPath / lineageSetLineage.FineSpanExtension.
// It carries no separate self-referential content identity: every declared
// document is independently reverified against its lineage's admitted
// evidence before it can enter the merged index, so a pinned hash here would
// add no trust beyond that verification.
type FineSpanExtensionInput struct {
	SchemaVersion string                      `json:"schema_version"`
	Documents     []FineSpanExtensionDocument `json:"documents"`
}

// loadFineSpanExtension reads and structurally validates one fine-span
// extension file. It never touches raw bytes or admitted evidence; that
// binding and verification happens in processFineSpanExtensions, which has
// the lineage's already-verified state in scope.
func loadFineSpanExtension(path string) (FineSpanExtensionInput, error) {
	var zero FineSpanExtensionInput
	data, err := readStableFile(path, "fine span extension", maxFineSpanExtensionBytes)
	if err != nil {
		return zero, fmt.Errorf("read fine span extension: %w", err)
	}
	var input FineSpanExtensionInput
	if err := decodeStrictCanonical(data, &input); err != nil {
		return zero, fmt.Errorf("decode fine span extension: %w", err)
	}
	if input.SchemaVersion != retrievalSchemaVersion {
		return zero, errors.New("fine span extension schema version unsupported")
	}
	if len(input.Documents) < 1 || len(input.Documents) > maxFineSpanDocuments {
		return zero, errors.New("fine span extension document count invalid")
	}
	previousKey := ""
	for _, document := range input.Documents {
		if !validPrefixedDigest(document.ParentSpanID, "evidence-span:") {
			return zero, errors.New("fine span extension parent span id invalid")
		}
		if strings.TrimSpace(document.Kind) == "" || document.Kind == fineSpanExtensionKindDoc {
			return zero, errors.New("fine span extension kind must be non-empty and distinct from the coarse chunk kind")
		}
		if document.RawByteStart < 0 || document.RawByteEnd <= document.RawByteStart {
			return zero, errors.New("fine span extension byte window invalid")
		}
		key := document.ParentSpanID + "\x00" + formatOrderedInt64(document.RawByteStart) + "\x00" + formatOrderedInt64(document.RawByteEnd)
		if key <= previousKey {
			return zero, errors.New("fine span extension documents are not in strict order")
		}
		previousKey = key
	}
	return input, nil
}

func formatOrderedInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}

// findSpanByID locates the exact evidence file and coarse span carrying the
// given SpanID within one lineage's already-admitted evidence manifest.
func findSpanByID(evidence EvidenceManifest, spanID string) (EvidenceFile, EvidenceSpan, bool) {
	for _, file := range evidence.Files {
		for _, span := range file.Spans {
			if span.SpanID == spanID {
				return file, span, true
			}
		}
	}
	return EvidenceFile{}, EvidenceSpan{}, false
}

func snapshotFileByPath(snapshot SnapshotManifest, relativePath string) (SnapshotFile, bool) {
	for _, file := range snapshot.Files {
		if file.RelativePath == relativePath {
			return file, true
		}
	}
	return SnapshotFile{}, false
}

// processFineSpanExtensions verifies and merges every declared fine-span
// document for one lineage into the shared accumulator. It runs only after
// that lineage's primary per-file coarse-span partition has already verified
// cleanly (indexLineageInto's own aggregate check). Every window is
// independently re-derived from the exact raw bytes already verified for its
// named parent span: no caller-declared hash, byte count or line coordinate
// is trusted. The sliced normalized payload must already be committed to the
// evidence store at its content-addressed path (materialize-fine-span-payload
// writes it there ahead of build) — Build never writes into the evidence
// store itself.
func processFineSpanExtensions(acc *indexAccumulator, lineageIndex int, entry parsedLineage, limits buildLimits, bm25fContract bm25fProfileContract, bm25f bool) []QuarantineIssue {
	var issues []QuarantineIssue
	evidence, snapshot, policy := entry.evidence, entry.snapshot, entry.policy
	for _, document := range entry.fineSpanExtension.Documents {
		file, parentSpan, found := findSpanByID(evidence, document.ParentSpanID)
		if !found {
			issues = append(issues, issue("fine_span_parent_missing", document.ParentSpanID, "fine span extension parent span is not part of the admitted evidence"))
			continue
		}
		if document.RawByteStart < parentSpan.RawByteStart || document.RawByteEnd > parentSpan.RawByteEnd {
			issues = append(issues, issue("fine_span_window_invalid", document.ParentSpanID, "fine span extension window is not strictly contained in its parent span"))
			continue
		}
		snapshotFile, snapFound := snapshotFileByPath(snapshot, file.RelativePath)
		if !snapFound {
			issues = append(issues, issue("fine_span_snapshot_missing", document.ParentSpanID, "fine span extension parent file has no reviewed snapshot entry"))
			continue
		}
		rawPath := filepath.Join(entry.rawRoot, filepath.FromSlash(snapshotFile.ObjectPath))
		if !isWithin(entry.rawRoot, rawPath) {
			issues = append(issues, issue("fine_span_raw_path_escape", document.ParentSpanID, "fine span extension raw object escaped its store"))
			continue
		}
		raw, err := verifyFileDigest(rawPath, snapshotFile.SHA256, snapshotFile.Size)
		if err != nil || document.RawByteEnd > int64(len(raw)) {
			issues = append(issues, issue("fine_span_raw_invalid", document.ParentSpanID, "fine span extension raw object no longer matches the reviewed snapshot or window exceeds it"))
			continue
		}
		payload := raw[document.RawByteStart:document.RawByteEnd]
		if int64(len(payload)) > limits.maxPayloadBytes {
			issues = append(issues, issue("fine_span_payload_limit", document.ParentSpanID, "fine span extension payload exceeds the configured bound"))
			continue
		}
		if !utf8.Valid(payload) {
			issues = append(issues, issue("fine_span_payload_invalid_utf8", document.ParentSpanID, "fine span extension payload is not valid UTF-8"))
			continue
		}
		payloadDigest := digestBytes(payload)
		lineStart, lineEnd := spanLines(raw, int(document.RawByteStart), int(document.RawByteEnd))
		syntheticSpan := EvidenceSpan{
			Ordinal:           -1,
			Kind:              document.Kind,
			HeadingBreadcrumb: append([]string(nil), document.HeadingBreadcrumb...),
			RawByteStart:      document.RawByteStart,
			RawByteEnd:        document.RawByteEnd,
			RawLineStart:      lineStart,
			RawLineEnd:        lineEnd,
			PayloadSHA256:     payloadDigest,
			PayloadID:         "normalized:" + payloadDigest,
			ObjectPath:        normalizedObjectRelativePath(payloadDigest),
			ByteSize:          int64(len(payload)),
			TrustEnvelopeID:   evidence.TrustEnvelope.EnvelopeID,
		}
		spanID := spanIdentity(file.OccurrenceID, file.ParserVersion, file.ProfileVersion, syntheticSpan)
		if spanID == document.ParentSpanID {
			issues = append(issues, issue("fine_span_identity_collision", document.ParentSpanID, "fine span extension window reproduces its own parent span identity"))
			continue
		}
		syntheticSpan.SpanID = spanID
		payloadPath := filepath.Join(entry.evidenceRoot, filepath.FromSlash(syntheticSpan.ObjectPath))
		if !isWithin(entry.evidenceRoot, payloadPath) {
			issues = append(issues, issue("fine_span_payload_path_escape", spanID, "fine span extension normalized payload escaped its store"))
			continue
		}
		stored, err := verifyFileDigest(payloadPath, payloadDigest, int64(len(payload)))
		if err != nil || !bytes.Equal(stored, payload) {
			issues = append(issues, issue("fine_span_payload_not_materialized", spanID, "fine span extension normalized payload is not yet committed to the evidence store"))
			continue
		}
		ref := evidenceReference(snapshot, evidence, policy, file, syntheticSpan)
		ref.ParentSpanID = parentSpan.SpanID
		docIssues := mergeDocumentIntoIndex(acc, lineageIndex, ref, syntheticSpan.HeadingBreadcrumb, payload, limits, bm25fContract, bm25f)
		issues = append(issues, docIssues...)
	}
	return issues
}

// FineSpanPayloadResult reports the content-addressed identity Build will
// independently recompute for this exact window, so the operator can bind it
// into a FineSpanExtensionDocument before running build.
type FineSpanPayloadResult struct {
	PayloadSHA256 string `json:"payload_sha256"`
	ByteSize      int64  `json:"byte_size"`
	RawLineStart  int    `json:"raw_line_start"`
	RawLineEnd    int    `json:"raw_line_end"`
	ObjectPath    string `json:"object_path"`
}

// MaterializeFineSpanPayload slices one exact byte window out of an
// already-admitted raw source object and commits it as an immutable
// content-addressed normalized-payload object in the evidence store, ahead of
// build. It reuses the identical raw-object verification and
// content-addressing convention as the admitted per-file coarse spans; it
// introduces no new raw source and mutates no existing evidence-manifest
// object (writes are additive, content-addressed, and collide only on
// byte-identical content).
func MaterializeFineSpanPayload(rawStoreRoot, rawSHA256 string, rawSize int64, evidenceStoreRoot string, start, end int64) (FineSpanPayloadResult, error) {
	var zero FineSpanPayloadResult
	rawRoot, err := filepath.Abs(rawStoreRoot)
	if err != nil || validateNoSymlinkPath(rawRoot) != nil {
		return zero, errors.New("raw store path is unavailable")
	}
	evidenceRoot, err := filepath.Abs(evidenceStoreRoot)
	if err != nil || validateNoSymlinkExistingPrefix(evidenceRoot) != nil {
		return zero, errors.New("evidence store path is unavailable")
	}
	if !validSHA256(rawSHA256) || rawSize < 1 {
		return zero, errors.New("raw object digest or size is invalid")
	}
	if start < 0 || end <= start {
		return zero, errors.New("byte window is invalid")
	}
	rawPath := filepath.Join(rawRoot, filepath.FromSlash(rawObjectRelativePath(rawSHA256)))
	if !isWithin(rawRoot, rawPath) {
		return zero, errors.New("raw object path escaped its store")
	}
	raw, err := verifyFileDigest(rawPath, rawSHA256, rawSize)
	if err != nil {
		return zero, fmt.Errorf("raw object does not match its pinned identity: %w", err)
	}
	if end > int64(len(raw)) {
		return zero, errors.New("byte window exceeds the raw object")
	}
	payload := raw[start:end]
	if !utf8.Valid(payload) {
		return zero, errors.New("sliced payload is not valid UTF-8")
	}
	payloadDigest := digestBytes(payload)
	lineStart, lineEnd := spanLines(raw, int(start), int(end))
	relative := normalizedObjectRelativePath(payloadDigest)
	if err := writeImmutableObject(evidenceRoot, relative, payload); err != nil {
		return zero, fmt.Errorf("commit fine span payload: %w", err)
	}
	return FineSpanPayloadResult{
		PayloadSHA256: payloadDigest, ByteSize: int64(len(payload)),
		RawLineStart: lineStart, RawLineEnd: lineEnd, ObjectPath: relative,
	}, nil
}
