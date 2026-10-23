package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	maxRetrievalExecutableBytes = 128 << 20
	maxRetrievalOutputBytes     = 1 << 20
	maxRetrievalDiagnosticBytes = 64 << 10
	retrievalCommandTimeout     = 15 * time.Second
)

type retrievalProvider struct {
	configured          bool
	executable          string
	executableSHA256    string
	store               string
	state               string
	evidenceStore       string
	admissionPolicy     string
	admissionPolicyHash string
	catalog             string
	catalogSHA256       string
	commandTimeout      time.Duration
	now                 func() time.Time
}

func newRetrievalProvider(configuration config) *retrievalProvider {
	return &retrievalProvider{
		configured:          configuration.retrievalExecutable != "" || configuration.retrievalCatalog != "",
		executable:          configuration.retrievalExecutable,
		executableSHA256:    configuration.retrievalExecutableHash,
		store:               configuration.retrievalStore,
		state:               configuration.retrievalState,
		evidenceStore:       configuration.retrievalEvidenceStore,
		admissionPolicy:     configuration.retrievalAdmissionPolicy,
		admissionPolicyHash: configuration.retrievalAdmissionPolicyHash,
		catalog:             configuration.retrievalCatalog,
		catalogSHA256:       configuration.retrievalCatalogHash,
		now:                 time.Now,
	}
}

// These private types are a strict copy of knowledge-retrieval's public
// current-query response.  Keeping the boundary typed makes output drift fail
// closed and retains every exact citation coordinate without importing another
// command package.
type currentRetrievalResponse struct {
	State                   string                `json:"state"`
	ResultState             string                `json:"result_state"`
	AuthorityState          string                `json:"authority_state"`
	Profile                 string                `json:"profile"`
	ServingEligible         bool                  `json:"serving_eligible"`
	CurrentEligible         bool                  `json:"current_eligible"`
	PointerID               string                `json:"pointer_id,omitempty"`
	PointerRevision         int                   `json:"pointer_revision,omitempty"`
	TransitionReceiptID     string                `json:"transition_receipt_id,omitempty"`
	CurrentGenerationID     string                `json:"current_generation_id,omitempty"`
	CurrentGenerationSHA256 string                `json:"current_generation_document_sha256,omitempty"`
	GenerationCreatedAt     string                `json:"generation_created_at,omitempty"`
	QualityReportID         string                `json:"quality_report_id,omitempty"`
	EvaluationDatasetID     string                `json:"evaluation_dataset_id,omitempty"`
	EvaluationMetricsID     string                `json:"evaluation_metrics_id,omitempty"`
	CandidateManifestID     string                `json:"candidate_manifest_id,omitempty"`
	FreshnessState          string                `json:"freshness_state,omitempty"`
	QueryTerms              []string              `json:"query_terms,omitempty"`
	Results                 []currentRetrievalHit `json:"results"`
	ErrorCode               string                `json:"error_code,omitempty"`
}

type currentRetrievalHit struct {
	Score            int                      `json:"score"`
	MatchedTerms     []string                 `json:"matched_terms"`
	Evidence         currentRetrievalEvidence `json:"evidence"`
	Excerpt          string                   `json:"excerpt"`
	ExcerptTruncated bool                     `json:"excerpt_truncated"`
}

type currentRetrievalEvidence struct {
	SpanID               string   `json:"span_id"`
	OccurrenceID         string   `json:"occurrence_id"`
	SourceID             string   `json:"source_id"`
	ComponentID          string   `json:"component_id"`
	ComponentVersionID   string   `json:"component_version_id"`
	ChannelID            string   `json:"channel_id"`
	CanonicalSourceURI   string   `json:"canonical_source_uri"`
	CanonicalSnapshotURI string   `json:"canonical_snapshot_uri"`
	SnapshotManifestID   string   `json:"snapshot_manifest_id"`
	EvidenceManifestID   string   `json:"evidence_manifest_id"`
	SnapshotID           string   `json:"snapshot_id"`
	RelativePath         string   `json:"relative_path"`
	HeadingBreadcrumb    []string `json:"heading_breadcrumb"`
	RawSHA256            string   `json:"raw_sha256"`
	PayloadSHA256        string   `json:"payload_sha256"`
	PayloadObjectPath    string   `json:"payload_object_path"`
	PayloadByteSize      int64    `json:"payload_byte_size"`
	RawByteStart         int64    `json:"raw_byte_start"`
	RawByteEnd           int64    `json:"raw_byte_end"`
	RawLineStart         int      `json:"raw_line_start"`
	RawLineEnd           int      `json:"raw_line_end"`
	FetchedAt            string   `json:"fetched_at"`
	ObservedAt           string   `json:"observed_at"`
	AccessScope          string   `json:"access_scope"`
	FreshUntil           string   `json:"fresh_until"`
	TrustEnvelopeID      string   `json:"trust_envelope_id"`
	ContentClass         string   `json:"content_class"`
	InstructionPolicy    string   `json:"instruction_policy"`
	ExecutionPolicy      string   `json:"execution_policy"`
	ToolPolicy           string   `json:"tool_policy"`
	InterpretationPolicy string   `json:"interpretation_policy"`
}

// retrievalAbortReason reports why a retrieval child was aborted, separating a
// caller-driven cancellation/deadline from the broker's own lane bound. Every
// reason stays a backend_unavailable failure that carries no evidence.
func retrievalAbortReason(caller, run context.Context) string {
	if caller != nil {
		switch caller.Err() {
		case context.Canceled:
			return "exact-source retrieval was cancelled by the caller"
		case context.DeadlineExceeded:
			return "exact-source retrieval exceeded the caller deadline"
		}
	}
	if run.Err() != nil {
		return "exact-source retrieval timed out"
	}
	return ""
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// search bounds the retrieval child by min(caller deadline, lane timeout): the
// caller context propagates cancellation, the lane timeout stays a hard bound.
func (provider *retrievalProvider) search(ctx context.Context, values map[string]json.RawMessage) toolOutcome {
	if err := rejectUnknown(values, "query", "limit", "max_excerpt_bytes"); err != nil {
		return invalidArguments(err)
	}
	query, err := boundedStringArg(values, "query", true, 512)
	if err != nil {
		return invalidArguments(err)
	}
	limit, err := intArg(values, "limit", 8, 1, 20)
	if err != nil {
		return invalidArguments(err)
	}
	maxExcerptBytes, err := intArg(values, "max_excerpt_bytes", 2048, 256, 4096)
	if err != nil {
		return invalidArguments(err)
	}
	now := time.Now
	if provider != nil && provider.now != nil {
		now = provider.now
	}
	asOf := now().UTC().Format("2006-01-02T15:04:05Z")
	if provider == nil || !provider.configured {
		return errorOutcome(stateBackendUnavailable, "exact-source retrieval is not configured", map[string]any{
			"result_state": "backend_unavailable",
			"observed_at":  asOf,
		})
	}
	if provider.catalog != "" {
		return provider.searchFederation(ctx, query, limit, maxExcerptBytes, asOf)
	}

	executableFile, err := provider.openValidatedExecutable()
	if err != nil {
		return errorOutcome(stateBackendUnavailable, "validate exact retrieval executable: "+err.Error(), map[string]any{
			"result_state": "backend_unavailable",
			"observed_at":  asOf,
		})
	}
	defer func() { _ = executableFile.Close() }()
	arguments := []string{
		"current-query",
		"--store", provider.store,
		"--state", provider.state,
		"--evidence-store", provider.evidenceStore,
		"--admission-policy", provider.admissionPolicy,
		"--admission-policy-sha256", "sha256:" + provider.admissionPolicyHash,
		"--query", query,
		"--principal-scope", "public",
		"--as-of", asOf,
		"--limit", fmt.Sprintf("%d", limit),
		"--max-excerpt-bytes", fmt.Sprintf("%d", maxExcerptBytes),
	}
	timeout := retrievalCommandTimeout
	if provider.commandTimeout > 0 {
		timeout = provider.commandTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := provider.retrievalCommand(runCtx, executableFile, arguments)
	// current-query verifies the signed pointer and quality receipts with
	// ssh-keygen. Keep that verifier reachable through one fixed, minimal search
	// path instead of inheriting caller-controlled process lookup state.
	stdout := &commandCapture{maximum: maxRetrievalOutputBytes}
	stderr := &commandCapture{maximum: maxRetrievalDiagnosticBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	// command.Run waits, so the SIGKILLed process group is already reaped here.
	if err := retrievalAbortReason(ctx, runCtx); err != "" {
		return errorOutcome(stateBackendUnavailable, err, map[string]any{"result_state": "backend_unavailable", "observed_at": asOf})
	}
	if verifyErr := provider.validateOpenedExecutable(executableFile); verifyErr != nil {
		return errorOutcome(stateBackendUnavailable, "retrieval executable changed during invocation: "+verifyErr.Error(), map[string]any{"result_state": "backend_unavailable", "observed_at": asOf})
	}
	if stdout.overflow {
		return errorOutcome(stateBackendUnavailable, "exact-source retrieval output exceeded its safety bound", map[string]any{"result_state": "backend_unavailable", "observed_at": asOf})
	}
	if runErr != nil {
		diagnostic := strings.TrimSpace(stderr.value.String())
		if stderr.overflow {
			diagnostic += " [diagnostic truncated]"
		}
		return errorOutcome(stateBackendUnavailable, fmt.Sprintf("exact-source retrieval failed: %v: %s", runErr, diagnostic), map[string]any{"result_state": "backend_unavailable", "observed_at": asOf})
	}
	var response currentRetrievalResponse
	if err := decodeStrictTyped(stdout.value.Bytes(), &response); err != nil {
		return errorOutcome(stateBackendUnavailable, "exact-source retrieval returned invalid JSON", map[string]any{"result_state": "backend_unavailable", "observed_at": asOf})
	}
	if err := validateCurrentRetrievalResponse(response, limit, maxExcerptBytes); err != nil {
		return errorOutcome(stateBackendUnavailable, "exact-source retrieval violated its signed-current contract: "+err.Error(), map[string]any{"result_state": "backend_unavailable", "observed_at": asOf})
	}
	data := currentRetrievalData(response)
	data["observed_at"] = asOf
	data["time_source"] = "broker_host_clock_utc"
	data["principal_scope"] = "public"
	data["retrieval_executable_sha256"] = "sha256:" + provider.executableSHA256
	data["retrieval_admission_policy_sha256"] = "sha256:" + provider.admissionPolicyHash
	switch response.ResultState {
	case "ok":
		return outcome(stateOK, data)
	case "empty":
		return outcome(stateEmpty, data)
	case "stale":
		return errorOutcome(stateStale, "the signed current evidence generation is stale", data)
	case "forbidden":
		return errorOutcome(stateForbidden, "exact-source retrieval policy forbids this query", data)
	case "backend_unavailable":
		return errorOutcome(stateBackendUnavailable, "exact-source retrieval backend is unavailable", data)
	default:
		return errorOutcome(stateBackendUnavailable, "exact-source retrieval returned an unsupported result_state", data)
	}
}

func currentRetrievalData(response currentRetrievalResponse) map[string]any {
	return map[string]any{
		"retrieval_state":                    response.State,
		"result_state":                       response.ResultState,
		"authority_state":                    response.AuthorityState,
		"profile":                            response.Profile,
		"serving_eligible":                   response.ServingEligible,
		"current_eligible":                   response.CurrentEligible,
		"pointer_id":                         response.PointerID,
		"pointer_revision":                   response.PointerRevision,
		"transition_receipt_id":              response.TransitionReceiptID,
		"current_generation_id":              response.CurrentGenerationID,
		"current_generation_document_sha256": response.CurrentGenerationSHA256,
		"generation_created_at":              response.GenerationCreatedAt,
		"quality_report_id":                  response.QualityReportID,
		"evaluation_dataset_id":              response.EvaluationDatasetID,
		"evaluation_metrics_id":              response.EvaluationMetricsID,
		"candidate_manifest_id":              response.CandidateManifestID,
		"freshness_state":                    response.FreshnessState,
		"query_terms":                        response.QueryTerms,
		"results":                            response.Results,
		"error_code":                         response.ErrorCode,
	}
}

func validateCurrentRetrievalResponse(response currentRetrievalResponse, limit, maxExcerptBytes int) error {
	if response.Results == nil {
		return errors.New("results must be an explicit array")
	}
	if response.State == "backend_unavailable" {
		if response.ResultState != "backend_unavailable" || response.AuthorityState != "unavailable" || response.Profile != "lexical" || response.ServingEligible || response.CurrentEligible || response.ErrorCode == "" || len(response.Results) != 0 {
			return errors.New("backend-unavailable response overstates current authority")
		}
		if response.PointerID != "" || response.PointerRevision != 0 || response.TransitionReceiptID != "" || response.CurrentGenerationID != "" || response.CurrentGenerationSHA256 != "" || response.QualityReportID != "" || response.EvaluationDatasetID != "" || response.EvaluationMetricsID != "" {
			return errors.New("backend-unavailable response carries unverified lineage")
		}
		return nil
	}
	if response.State != "current" || response.AuthorityState != "evaluated_current" || response.Profile != "lexical" || !response.CurrentEligible {
		return errors.New("response is not evaluated current authority")
	}
	if !validRetrievalObjectID(response.PointerID, "retrieval-pointer:") || response.PointerRevision < 1 ||
		!validRetrievalObjectID(response.TransitionReceiptID, "retrieval-receipt:") ||
		!validRetrievalObjectID(response.CurrentGenerationID, "retrieval-generation:") ||
		!validRetrievalDigest(response.CurrentGenerationSHA256) ||
		!validRetrievalObjectID(response.QualityReportID, "retrieval-quality-report:") ||
		!validRetrievalObjectID(response.EvaluationDatasetID, "retrieval-evaluation-suite:") ||
		!validRetrievalObjectID(response.EvaluationMetricsID, "retrieval-evaluation-metrics:") ||
		!validRetrievalObjectID(response.CandidateManifestID, "retrieval-candidate:") {
		return errors.New("evaluated-current lineage is incomplete or invalid")
	}
	if !canonicalRetrievalTime(response.GenerationCreatedAt) {
		return errors.New("generation_created_at is not canonical UTC")
	}
	if response.FreshnessState != "fresh" && response.FreshnessState != "stale" {
		return errors.New("freshness_state is unsupported")
	}
	if err := validateSortedRetrievalTerms(response.QueryTerms, 32); err != nil {
		return fmt.Errorf("query terms: %w", err)
	}
	if len(response.Results) > limit {
		return errors.New("result count exceeds the requested limit")
	}
	switch response.ResultState {
	case "ok":
		if !response.ServingEligible || response.FreshnessState != "fresh" || response.ErrorCode != "" || len(response.Results) == 0 {
			return errors.New("ok result is not fresh serving-eligible evidence")
		}
	case "empty":
		if !response.ServingEligible || response.FreshnessState != "fresh" || response.ErrorCode != "" || len(response.Results) != 0 {
			return errors.New("empty result has inconsistent serving state")
		}
	case "stale":
		if response.ServingEligible || response.FreshnessState != "stale" || response.ErrorCode != "" || len(response.Results) != 0 {
			return errors.New("stale result was allowed to serve evidence")
		}
	case "forbidden":
		if response.ErrorCode == "" || len(response.Results) != 0 {
			return errors.New("forbidden result omitted its code or carried evidence")
		}
	case "backend_unavailable":
		if response.ServingEligible || response.ErrorCode == "" || len(response.Results) != 0 {
			return errors.New("backend-unavailable result was allowed to serve evidence")
		}
	default:
		return errors.New("result_state is unsupported")
	}
	queryTerms := make(map[string]struct{}, len(response.QueryTerms))
	for _, term := range response.QueryTerms {
		queryTerms[term] = struct{}{}
	}
	seen := make(map[string]struct{}, len(response.Results))
	for _, hit := range response.Results {
		if hit.Score < 1 || len(hit.Excerpt) > maxExcerptBytes || !utf8.ValidString(hit.Excerpt) || strings.ContainsRune(hit.Excerpt, '\x00') {
			return errors.New("retrieval hit score or excerpt is invalid")
		}
		if err := validateSortedRetrievalTerms(hit.MatchedTerms, 32); err != nil || len(hit.MatchedTerms) == 0 {
			return errors.New("retrieval hit matched terms are invalid")
		}
		for _, term := range hit.MatchedTerms {
			if _, exists := queryTerms[term]; !exists {
				return errors.New("retrieval hit contains an unrequested matched term")
			}
		}
		if err := validateCurrentRetrievalEvidence(hit.Evidence); err != nil {
			return err
		}
		if _, duplicate := seen[hit.Evidence.SpanID]; duplicate {
			return errors.New("retrieval response repeats an evidence span")
		}
		seen[hit.Evidence.SpanID] = struct{}{}
	}
	return nil
}

func validateCurrentRetrievalEvidence(evidence currentRetrievalEvidence) error {
	for label, value := range map[string]string{
		"span_id": evidence.SpanID, "occurrence_id": evidence.OccurrenceID,
		"source_id": evidence.SourceID, "component_id": evidence.ComponentID,
		"component_version_id": evidence.ComponentVersionID, "channel_id": evidence.ChannelID,
		"canonical_source_uri": evidence.CanonicalSourceURI, "canonical_snapshot_uri": evidence.CanonicalSnapshotURI,
		"snapshot_manifest_id": evidence.SnapshotManifestID, "evidence_manifest_id": evidence.EvidenceManifestID,
		"snapshot_id": evidence.SnapshotID, "relative_path": evidence.RelativePath,
		"payload_object_path": evidence.PayloadObjectPath, "trust_envelope_id": evidence.TrustEnvelopeID,
	} {
		if !validRetrievalString(value, 16<<10, false) {
			return fmt.Errorf("retrieval citation %s is invalid", label)
		}
	}
	if !validRetrievalObjectID(evidence.SpanID, "evidence-span:") ||
		!validRetrievalObjectID(evidence.OccurrenceID, "evidence-occurrence:") ||
		!validRetrievalObjectID(evidence.SnapshotManifestID, "snapshot-manifest:") ||
		!validRetrievalObjectID(evidence.EvidenceManifestID, "evidence-manifest:") ||
		!validRetrievalObjectID(evidence.TrustEnvelopeID, "trust-envelope:") ||
		!validRetrievalDigest(evidence.RawSHA256) || !validRetrievalDigest(evidence.PayloadSHA256) {
		return errors.New("retrieval citation content identity is invalid")
	}
	if _, err := normalizeRequestedPath(evidence.RelativePath); err != nil {
		return errors.New("retrieval citation source path is not canonical")
	}
	if _, err := normalizeRequestedPath(evidence.PayloadObjectPath); err != nil {
		return errors.New("retrieval citation payload path is not canonical")
	}
	if evidence.PayloadByteSize < 1 || evidence.PayloadByteSize > 64<<20 || evidence.RawByteStart < 0 || evidence.RawByteEnd <= evidence.RawByteStart || evidence.RawLineStart < 1 || evidence.RawLineEnd < evidence.RawLineStart {
		return errors.New("retrieval citation byte or line coordinates are invalid")
	}
	// The payload is the verbatim raw slice, so its size equals the raw span exactly.
	if evidence.RawByteEnd-evidence.RawByteStart != evidence.PayloadByteSize {
		return errors.New("retrieval citation payload size does not match its raw byte span")
	}
	// An inclusive line range L..M spans at least M-L newline bytes.
	if int64(evidence.RawLineEnd-evidence.RawLineStart) > evidence.PayloadByteSize {
		return errors.New("retrieval citation line span cannot fit its payload bytes")
	}
	if !canonicalRetrievalTime(evidence.FetchedAt) || !canonicalRetrievalTime(evidence.ObservedAt) || !canonicalRetrievalTime(evidence.FreshUntil) {
		return errors.New("retrieval citation time lineage is invalid")
	}
	if evidence.AccessScope != "public" || evidence.ContentClass != "untrusted_source_data" || evidence.InstructionPolicy != "forbidden" || evidence.ExecutionPolicy != "never" || evidence.ToolPolicy != "never" || evidence.InterpretationPolicy != "evidence_only" {
		return errors.New("retrieval citation trust envelope is invalid")
	}
	if derivedRetrievalAuthority(evidence.SourceID) || derivedRetrievalAuthority(evidence.CanonicalSourceURI) || derivedRetrievalAuthority(evidence.CanonicalSnapshotURI) {
		return errors.New("retrieval citation points to generated or recursive authority")
	}
	if len(evidence.HeadingBreadcrumb) > 64 {
		return errors.New("retrieval citation heading breadcrumb exceeds its bound")
	}
	for _, heading := range evidence.HeadingBreadcrumb {
		if !validRetrievalString(heading, 2048, true) {
			return errors.New("retrieval citation heading breadcrumb is invalid")
		}
	}
	return nil
}

func validRetrievalDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validSHA256Hex(strings.TrimPrefix(value, "sha256:"))
}

func validRetrievalObjectID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && validRetrievalDigest(strings.TrimPrefix(value, prefix))
}

func canonicalRetrievalTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format("2006-01-02T15:04:05Z") == value
}

func validRetrievalString(value string, maximum int, emptyAllowed bool) bool {
	return (emptyAllowed || value != "") && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func validateSortedRetrievalTerms(values []string, maximum int) error {
	if len(values) > maximum || !sort.StringsAreSorted(values) {
		return errors.New("values are unbounded or unsorted")
	}
	for index, value := range values {
		if !validRetrievalString(value, 512, false) || (index > 0 && values[index-1] == value) {
			return errors.New("values are invalid or repeated")
		}
	}
	return nil
}

func derivedRetrievalAuthority(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"task-evidence-manifest:", "context-pack:", "claim-support:", "generated:", "run-output:", "dream:", "summary:", "projection:", "rendered-view:"} {
		for _, wrapper := range []string{"", "urn:", "source:", "artifact:"} {
			if strings.HasPrefix(normalized, wrapper+prefix) {
				return true
			}
		}
	}
	return false
}

func (provider *retrievalProvider) openValidatedExecutable() (*os.File, error) {
	if provider.executable == "" || !validSHA256Hex(provider.executableSHA256) {
		return nil, errors.New("executable path or SHA-256 pin is missing")
	}
	if !filepath.IsAbs(provider.executable) {
		return nil, errors.New("executable path is not absolute")
	}
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(provider.executable)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(provider.executable) // #nosec G703 -- operator-pinned executable is absolute, has symlink-free parents, and is checked for immutable inode identity and SHA-256.
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o222 != 0 {
		return nil, errors.New("executable is not an immutable executable regular file")
	}
	file, err := os.Open(provider.executable) // #nosec G703 -- operator-pinned executable is absolute, has symlink-free parents, and is checked for immutable inode identity and SHA-256.
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, joinCloseError(errors.Join(err, errors.New("executable path changed while it was opened")), file)
	}
	if err := provider.validateOpenedExecutable(file); err != nil {
		return nil, joinCloseError(err, file)
	}
	return file, nil
}

func (provider *retrievalProvider) validateOpenedExecutable(file *os.File) error {
	if file == nil {
		return errors.New("executable descriptor is missing")
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 || before.Mode().Perm()&0o222 != 0 || before.Size() < 1 || before.Size() > maxRetrievalExecutableBytes {
		return errors.New("opened executable is not an immutable executable regular file")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, maxRetrievalExecutableBytes+1))
	if err != nil || written != before.Size() || written > maxRetrievalExecutableBytes {
		return errors.New("opened executable changed or exceeded its bound while hashing")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() {
		return errors.New("opened executable metadata changed while hashing")
	}
	if hex.EncodeToString(digest.Sum(nil)) != provider.executableSHA256 {
		return errors.New("executable SHA-256 does not match the operator pin")
	}
	pathInfo, err := os.Lstat(provider.executable) // #nosec G703 -- operator-pinned executable is absolute, has symlink-free parents, and is checked for immutable inode identity and SHA-256.
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, pathInfo) {
		return errors.New("configured executable path no longer names the opened inode")
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func (provider *retrievalProvider) retrievalCommand(ctx context.Context, executableFile *os.File, arguments []string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/proc/self/fd/3") // #nosec G702 -- fixed descriptor path executes the immutable SHA-256-pinned binary; caller text remains separate argument values.
	command.Args = append(command.Args, arguments...)
	command.Dir = "/"
	command.ExtraFiles = []*os.File{executableFile}
	command.Env = []string{"LANG=C", "LC_ALL=C", "TZ=UTC", "PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 100 * time.Millisecond
	return command
}
