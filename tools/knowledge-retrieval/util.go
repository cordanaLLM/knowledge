package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"time"
)

const (
	retrievalSchemaVersion = "1.0.0"
	maxManifestBytes       = int64(128 * 1024 * 1024)
	maxPolicyBytes         = int64(1024 * 1024)
	defaultMaxFiles        = 100_000
	defaultMaxSpans        = 1_000_000
	defaultMaxPayloadBytes = int64(64 * 1024 * 1024)
	defaultMaxTotalBytes   = int64(512 * 1024 * 1024)
	defaultMaxTerms        = 2_000_000
	defaultMaxPostings     = 500_000
	maxIndexBytes          = int64(512 * 1024 * 1024)
)

type buildLimits struct {
	maxFiles        int
	maxSpans        int
	maxPayloadBytes int64
	maxTotalBytes   int64
	maxTerms        int
	maxPostings     int
}

func normalizeLimits(config BuildConfig) (buildLimits, error) {
	result := buildLimits{config.MaxFiles, config.MaxSpans, config.MaxPayloadBytes, config.MaxTotalBytes, config.MaxTerms, config.MaxPostings}
	if result.maxFiles == 0 {
		result.maxFiles = defaultMaxFiles
	}
	if result.maxSpans == 0 {
		result.maxSpans = defaultMaxSpans
	}
	if result.maxPayloadBytes == 0 {
		result.maxPayloadBytes = defaultMaxPayloadBytes
	}
	if result.maxTotalBytes == 0 {
		result.maxTotalBytes = defaultMaxTotalBytes
	}
	if result.maxTerms == 0 {
		result.maxTerms = defaultMaxTerms
	}
	if result.maxPostings == 0 {
		result.maxPostings = defaultMaxPostings
	}
	if result.maxFiles < 1 || result.maxSpans < 1 || result.maxPayloadBytes < 1 || result.maxTotalBytes < 1 || result.maxTerms < 1 || result.maxPostings < 1 {
		return buildLimits{}, errors.New("retrieval build limits must be positive")
	}
	return result, nil
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

func decodeStrictCanonical(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("document contains multiple JSON values")
	}
	canonical, err := marshalDocument(target)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return errors.New("document is not canonical JSON")
	}
	return nil
}

func readStableFile(filePath, label string, maxBytes int64) ([]byte, error) {
	if err := validateNoSymlinkPath(filePath); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	before, err := os.Lstat(filePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > maxBytes {
		return nil, fmt.Errorf("%s is not a bounded regular file", label)
	}
	handle, err := os.Open(filePath) // #nosec G304 -- Operator-selected input passes component, regular-file, size and identity checks.
	if err != nil {
		return nil, fmt.Errorf("%s cannot be opened", label)
	}
	opened, err := handle.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, closeWithError(fmt.Errorf("%s changed before read", label), handle)
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxBytes+1))
	closeErr := handle.Close()
	after, statErr := os.Lstat(filePath)
	if readErr != nil || closeErr != nil || statErr != nil || int64(len(data)) > maxBytes || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || after.ModTime() != opened.ModTime() {
		return nil, fmt.Errorf("%s changed or exceeded its bound during read", label)
	}
	return data, nil
}

func verifyFileDigest(filePath, expectedDigest string, expectedSize int64) ([]byte, error) {
	if expectedSize < 0 {
		return nil, errors.New("negative expected object size")
	}
	data, err := readStableFile(filePath, filePath, expectedSize)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != expectedSize || digestBytes(data) != expectedDigest {
		return nil, errors.New("object bytes do not match content identity")
	}
	return data, nil
}

func validateNoSymlinkPath(candidate string) error {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return errors.New("path cannot be resolved")
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
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlinks are forbidden")
		}
	}
	return nil
}

func validateNoSymlinkExistingPrefix(candidate string) error {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}
	for current := abs; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("symlinks are forbidden")
			}
			return validateNoSymlinkPath(current)
		}
		if !errors.Is(statErr, fs.ErrNotExist) {
			return statErr
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func validateRelativePath(value string) error {
	if value == "" || strings.Contains(value, "\\") || path.IsAbs(value) || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return errors.New("path is not canonical and relative")
	}
	return nil
}

func isWithin(base, candidate string) bool {
	rel, err := filepath.Rel(base, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathsOverlap(a, b string) bool { return isWithin(a, b) || isWithin(b, a) }

func writeImmutableObject(storeRoot, relative string, data []byte) error {
	if validateRelativePath(relative) != nil {
		return errors.New("immutable object path is not canonical and relative")
	}
	root, rootInfo, err := openSafeOutputRoot(storeRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	parent := path.Dir(relative)
	if err := ensureRootDirectories(root, parent); err != nil {
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
	temp, err := root.OpenFile(tempRelative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	defer root.Remove(tempRelative)
	if _, err := temp.Write(data); err != nil {
		return closeWithError(err, temp)
	}
	if err := temp.Sync(); err != nil {
		return closeWithError(err, temp)
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if staged, err := readRootStableFile(root, tempRelative, int64(len(data))); err != nil || !bytes.Equal(staged, data) {
		return errors.New("immutable staged object failed its byte check")
	}

	// This check is intentionally immediately adjacent to the hard-link commit.
	// os.Root prevents a concurrent link swap from escaping the anchored store;
	// the component checks additionally reject even in-root symlink routing.
	if err := validateRootDirectoryComponents(root, parent); err != nil {
		return err
	}
	if err := verifyRootStillBound(storeRoot, root, rootInfo); err != nil {
		return err
	}
	if err := root.Link(tempRelative, relative); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
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
	return syncRootDirectory(root, parent)
}

func openSafeOutputRoot(storeRoot string) (*os.Root, fs.FileInfo, error) {
	abs, err := filepath.Abs(storeRoot)
	if err != nil {
		return nil, nil, err
	}
	if err := ensureAbsoluteDirectoryTree(abs); err != nil {
		return nil, nil, err
	}
	if err := validateNoSymlinkPath(abs); err != nil {
		return nil, nil, err
	}
	before, err := os.Lstat(abs)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, errors.New("output store root is not a regular directory")
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return nil, nil, closeWithError(errors.New("output store root changed while opening"), root)
	}
	if err := verifyRootStillBound(abs, root, opened); err != nil {
		return nil, nil, closeWithError(err, root)
	}
	return root, opened, nil
}

func ensureAbsoluteDirectoryTree(directory string) error {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return err
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
		if errors.Is(statErr, fs.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output store path contains a symlink or non-directory component")
		}
	}
	return nil
}

func ensureRootDirectories(root *os.Root, directory string) error {
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
			if err := root.Mkdir(current, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
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
		return nil, closeWithError(errors.New("rooted object changed before read"), handle)
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
	if err := validateNoSymlinkPath(storeRoot); err != nil {
		return err
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

func issue(code, pathValue, message string) QuarantineIssue {
	return QuarantineIssue{Code: code, Path: pathValue, Message: message}
}

func quarantine(storeRoot, inputDigest, evidenceID string, issues []QuarantineIssue) error {
	issues = sortedIssues(issues)
	identity, _ := json.Marshal(struct {
		InputDocumentSHA256 string            `json:"input_document_sha256"`
		EvidenceManifestID  string            `json:"evidence_manifest_id,omitempty"`
		Issues              []QuarantineIssue `json:"issues"`
	}{inputDigest, evidenceID, issues})
	digest := digestBytes(identity)
	report := QuarantineReport{
		SchemaVersion:       retrievalSchemaVersion,
		ReportKind:          "knowledge_retrieval_quarantine",
		State:               "quarantined",
		QuarantineID:        "retrieval-quarantine:" + digest,
		InputDocumentSHA256: inputDigest,
		EvidenceManifestID:  evidenceID,
		Issues:              issues,
	}
	data, _ := marshalDocument(report)
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	relative := path.Join("quarantine", "sha256", hexDigest[:2], hexDigest+".json")
	reportPath := filepath.Join(storeRoot, filepath.FromSlash(relative))
	if err := writeImmutableObject(storeRoot, relative, data); err != nil {
		return fmt.Errorf("retrieval input invalid and quarantine report failed: %w", err)
	}
	return &QuarantinedError{ReportPath: reportPath, Issues: issues}
}

func parseCanonicalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, errors.New("time must be canonical RFC3339 UTC")
	}
	return parsed, nil
}

func rawObjectRelativePath(digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return "invalid"
	}
	return path.Join("raw", "sha256", hexDigest[:2], hexDigest)
}

func normalizedObjectRelativePath(digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return "invalid"
	}
	return path.Join("normalized", "sha256", hexDigest[:2], hexDigest)
}

func canonicalSnapshotURI(manifestID string) string {
	digest := strings.TrimPrefix(manifestID, "snapshot-manifest:sha256:")
	return "urn:archeion:knowledge-snapshot:sha256:" + digest
}

func occurrenceIdentity(manifestID string, file SnapshotFile) string {
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

func expectedTrustEnvelope() TrustEnvelope {
	core := TrustEnvelopeCore{
		SchemaVersion:        "1.0.0",
		EnvelopeKind:         "untrusted_evidence_content",
		ProfileVersion:       "untrusted-evidence-envelope@1.0.0",
		ContentClass:         "untrusted_source_data",
		InstructionPolicy:    "forbidden",
		ExecutionPolicy:      "never",
		ToolPolicy:           "never",
		InterpretationPolicy: "evidence_only",
	}
	payload, _ := json.Marshal(core)
	digest := digestBytes(payload)
	return TrustEnvelope{EnvelopeID: "trust-envelope:" + digest, EnvelopePayloadSHA256: digest, TrustEnvelopeCore: core}
}

func spanLines(data []byte, start, end int) (int, int) {
	startLine := 1 + bytes.Count(data[:start], []byte{'\n'})
	if end == start {
		return startLine, startLine
	}
	line := 1 + bytes.Count(data[:end], []byte{'\n'})
	if data[end-1] == '\n' {
		line--
	}
	if line < startLine {
		line = startLine
	}
	return startLine, line
}
