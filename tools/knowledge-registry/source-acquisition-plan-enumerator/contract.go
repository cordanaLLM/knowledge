package main

// Schema types and canonicalization for the source-acquisition contract the
// enumerator authors.
//
// The emitted document is the EXACT canonical contract the sibling
// source-acquisition-runner-v3 consumes: identical $schema/schema_version/kind,
// contract_id/contract_payload_sha256 self-address, source_denominator,
// acquisition_capability, and execution_gate. The runner is the authority; this
// enumerator matches it byte-for-byte so the runner's validateContract accepts
// the output verbatim (constants below mirror
// tools/knowledge-registry/source-acquisition-runner-v3/contract.go +
// execution_manifest.go).
//
// The target/file/path-binding schema, the strict canonical-JSON machinery, and
// the fail-closed path-resolution proof are reused VERBATIM from that runner.
// This tool AUTHORS a fresh, unsigned contract for a new authority which a
// downstream signer freezes; every byte-exact and fail-closed invariant is
// preserved.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	apiOrigin          = "https://api.github.com"
	apiVersion         = "2026-03-10"
	canonicalProfile   = "registry_compact_utf8"
	maxJSONDepth       = 128
	maxJSONNodes       = 10_000_000
	maxObjectJSONBytes = int64(4 * 1024 * 1024)
	maxResponseBytes   = int64(32 * 1024 * 1024)
	maxBlobBytes       = int64(1024 * 1024)
	maxHTTPRequests    = 128
	maxTokenBytes      = 4096

	// Plan-authoring bounds. The annotated-tag chain, path depth, and per-tree
	// entry caps are enforced during enumeration and re-asserted on the plan.
	maxAnnotatedTagChain = 8
	maxPathDepth         = 16
	maxTreeEntries       = 8192
	maxPlanTargets       = 64
	maxPlanFiles         = 512

	// Emitted-document constants mirror the runner's canonical acquisition
	// contract so validateContract accepts the output verbatim. Values are copied
	// from tools/knowledge-registry/source-acquisition-runner-v3/contract.go
	// (contractSchema/contractSchemaVersion/contractKind, review_state) and the
	// reviewed acquisition-capability allowlist entry keyed by capabilityID.
	contractSchema             = "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-contract-v2.schema.json"
	contractSchemaVersion      = "2.0.0"
	contractKind               = "source_file_set_acquisition_v2"
	contractAuthorityState     = "non_authoritative"
	contractReviewState        = "implementation_frozen"
	capabilityID               = "github-git-objects-rest-exact-file-v2"
	contractIDPrefix           = "source-acquisition-contract:sha256:"
	targetIDPrefix             = "source-acquisition-target:sha256:"
	executionVerificationState = "external_exact_byte_verification_required"
)

var (
	sha1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	// branchPattern admits the '/' that tags forbid (e.g. "release/1.2") while
	// still banning control chars and empty leading segments; validBranchName
	// adds the trailing-slash, "..", and "//" bans the charset alone cannot make.
	branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
	repoPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// validBranchName accepts a branch ref name for the branch-HEAD resolution path.
// Unlike a tag, a branch may contain '/', so it cannot reuse tagPattern; it still
// fails closed on control chars, "..", and leading/trailing/empty segments.
func validBranchName(value string) bool {
	if !branchPattern.MatchString(value) {
		return false
	}
	if strings.HasSuffix(value, "/") || strings.Contains(value, "..") || strings.Contains(value, "//") {
		return false
	}
	return true
}

// validRequestedRef validates the requested ref name against the ref kind:
// "branch" uses validBranchName; absent or "tag" uses the tag pattern; any other
// ref kind is rejected. Absent stays byte-identical to the historical tag path.
func validRequestedRef(refKind, requested string) bool {
	switch refKind {
	case "branch":
		return validBranchName(requested)
	case "", "tag":
		return tagPattern.MatchString(requested)
	default:
		return false
	}
}

type authorityBoundary struct {
	SourceAdmission    bool `json:"source_admission"`
	RetrievalRelease   bool `json:"retrieval_release"`
	Signing            bool `json:"signing"`
	PointerMutation    bool `json:"pointer_mutation"`
	GitMutation        bool `json:"git_mutation"`
	ProductionMutation bool `json:"production_mutation"`
}

type publisher struct {
	PublisherID string `json:"publisher_id"`
	Name        string `json:"name"`
	URI         string `json:"uri"`
}

// sourceDenominator mirrors the runner's comparison-only freeze binding
// (source-acquisition-runner-v3/contract.go). It carries no admission authority.
type sourceDenominator struct {
	FreezeID             string `json:"freeze_id"`
	FreezeDocumentSHA256 string `json:"freeze_document_sha256"`
	ComparisonOnly       bool   `json:"comparison_only"`
}

type acquisitionCapability struct {
	CapabilityID   string `json:"capability_id"`
	Transport      string `json:"transport"`
	APIOrigin      string `json:"api_origin"`
	APIVersion     string `json:"api_version"`
	ObjectFormat   string `json:"object_format"`
	SelectionMode  string `json:"selection_mode"`
	RedirectPolicy string `json:"redirect_policy"`
}

// executionGate mirrors the runner's exactExecutionGateBinding() shape
// (source-acquisition-runner-v3/execution_manifest.go): an external-verification
// gate that is never pre-verified and never predecessor-eligible.
type executionGate struct {
	ManifestID                   string `json:"manifest_id"`
	ManifestPayloadSHA256        string `json:"manifest_payload_sha256"`
	VerificationState            string `json:"verification_state"`
	ExternalVerificationRequired bool   `json:"external_verification_required"`
	Verified                     bool   `json:"verified"`
	PredecessorEligible          bool   `json:"predecessor_eligible"`
}

type contractBounds struct {
	Targets           int   `json:"targets"`
	Files             int   `json:"files"`
	LogicalBytes      int64 `json:"logical_bytes"`
	AnnotatedTagDepth int   `json:"annotated_tag_depth"`
	PathDepth         int   `json:"path_depth"`
	TreeEntries       int   `json:"tree_entries"`
	BlobBytes         int64 `json:"blob_bytes"`
	HTTPRequests      int   `json:"http_requests"`
	HTTPResponseBytes int64 `json:"http_response_bytes"`
	ObjectJSONBytes   int64 `json:"object_json_bytes"`
}

type expectedTagObject struct {
	SHA1       string `json:"sha1"`
	Name       string `json:"name"`
	TargetType string `json:"target_type"`
	TargetSHA1 string `json:"target_sha1"`
}

type pathBinding struct {
	ParentTreeSHA1 string `json:"parent_tree_sha1"`
	Segment        string `json:"segment"`
	ObjectType     string `json:"object_type"`
	Mode           string `json:"mode"`
	ObjectSHA1     string `json:"object_sha1"`
	Bytes          *int64 `json:"bytes,omitempty"`
}

type contractFile struct {
	SourceKey              string        `json:"source_key"`
	Path                   string        `json:"path"`
	Mode                   string        `json:"mode"`
	GitBlobSHA1            string        `json:"git_blob_sha1"`
	RawSHA256              string        `json:"raw_sha256"`
	Bytes                  int64         `json:"bytes"`
	ExpectedPathResolution []pathBinding `json:"expected_path_resolution"`
}

type contractTargetCore struct {
	AuthorityID          string              `json:"authority_id"`
	SourceSetID          string              `json:"source_set_id"`
	ComponentID          string              `json:"component_id"`
	ComponentVersion     string              `json:"component_version"`
	Repository           string              `json:"repository"`
	Publisher            publisher           `json:"publisher"`
	LicenseExpression    string              `json:"license_expression"`
	RequestedTag         string              `json:"requested_tag"`
	RefKind              string              `json:"ref_kind,omitempty"`
	ExpectedRefType      string              `json:"expected_ref_object_type"`
	ExpectedRefSHA1      string              `json:"expected_ref_object_sha1"`
	ExpectedTagObjects   []expectedTagObject `json:"expected_annotated_tag_objects"`
	ExpectedCommitSHA1   string              `json:"expected_commit_sha1"`
	ExpectedRootTreeSHA1 string              `json:"expected_root_tree_sha1"`
	Files                []contractFile      `json:"files"`
}

type contractTarget struct {
	TargetID string `json:"target_id"`
	contractTargetCore
}

type planCore struct {
	Schema                string                `json:"$schema"`
	SchemaVersion         string                `json:"schema_version"`
	Canonicalization      string                `json:"canonicalization"`
	ContractKind          string                `json:"contract_kind"`
	WorkID                string                `json:"work_id"`
	AuthorityState        string                `json:"authority_state"`
	ReviewState           string                `json:"review_state"`
	CompileEligible       bool                  `json:"compile_eligible"`
	PromoteEligible       bool                  `json:"promote_eligible"`
	AuthorityBoundary     authorityBoundary     `json:"authority_boundary"`
	SourceDenominator     sourceDenominator     `json:"source_denominator"`
	AcquisitionCapability acquisitionCapability `json:"acquisition_capability"`
	ExecutionGate         executionGate         `json:"execution_gate"`
	Bounds                contractBounds        `json:"bounds"`
	Targets               []contractTarget      `json:"targets"`
}

type acquisitionPlan struct {
	ContractID            string `json:"contract_id"`
	ContractPayloadSHA256 string `json:"contract_payload_sha256"`
	planCore
}

// planCapability returns the EXACT struct stored in the runner's
// reviewedCapabilities["github-git-objects-rest-exact-file-v2"]; every field is
// copied from source-acquisition-runner-v3/contract.go so the runner's
// allowlist admits it.
func planCapability() acquisitionCapability {
	return acquisitionCapability{CapabilityID: capabilityID, Transport: "https-json", APIOrigin: apiOrigin, APIVersion: apiVersion, ObjectFormat: "sha1", SelectionMode: "exact_paths_only", RedirectPolicy: "forbid"}
}

func planBounds(targets []contractTarget) contractBounds {
	files := 0
	var logical int64
	for _, target := range targets {
		files += len(target.Files)
		for _, file := range target.Files {
			logical += file.Bytes
		}
	}
	return contractBounds{
		Targets: len(targets), Files: files, LogicalBytes: logical,
		AnnotatedTagDepth: maxAnnotatedTagChain, PathDepth: maxPathDepth, TreeEntries: maxTreeEntries,
		BlobBytes: maxBlobBytes, HTTPRequests: maxHTTPRequests, HTTPResponseBytes: maxResponseBytes, ObjectJSONBytes: maxObjectJSONBytes,
	}
}

// deriveTargetID content-addresses a target core exactly as P1-SRC-03 does.
func deriveTargetID(core contractTargetCore) (string, error) {
	raw, err := canonicalJSON(core)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return targetIDPrefix + hex.EncodeToString(digest[:]), nil
}

// materializePlan recomputes the content address from the canonical core
// exactly like the runner's materializeContract: sha256 over canonicalJSON(core),
// with the runner's "source-acquisition-contract:sha256:" contract-id prefix.
func materializePlan(core planCore) (acquisitionPlan, []byte, error) {
	if err := validatePlan(core); err != nil {
		return acquisitionPlan{}, nil, err
	}
	payload, err := canonicalJSON(core)
	if err != nil {
		return acquisitionPlan{}, nil, err
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := acquisitionPlan{ContractID: contractIDPrefix + hex.EncodeToString(digest[:]), ContractPayloadSHA256: payloadSHA, planCore: core}
	document, err := documentJSON(value)
	if err != nil {
		return acquisitionPlan{}, nil, err
	}
	return value, document, nil
}

// validatePlan re-proves every authority-agnostic invariant on an authored
// contract: exact runner schema/kind, non-widened authority boundary,
// comparison-only source denominator, external-verification execution gate,
// fixed transport capability, computed byte and cardinality denominators,
// distinct authorities/sets/publishers/paths, and an exact non-recursive
// tree-chain path resolution for every file.
func validatePlan(value planCore) error {
	if value.Schema != contractSchema || value.SchemaVersion != contractSchemaVersion || value.Canonicalization != canonicalProfile || value.ContractKind != contractKind {
		return errors.New("plan schema or kind is invalid")
	}
	if value.WorkID == "" || !utf8.ValidString(value.WorkID) || len(value.WorkID) > 256 || strings.TrimSpace(value.WorkID) != value.WorkID {
		return errors.New("plan work identity is empty or over-bound")
	}
	if value.AuthorityState != contractAuthorityState || value.ReviewState != contractReviewState || value.CompileEligible || value.PromoteEligible || value.AuthorityBoundary != (authorityBoundary{}) {
		return errors.New("plan authority state widened")
	}
	if !value.SourceDenominator.ComparisonOnly || !validSHA256(value.SourceDenominator.FreezeDocumentSHA256) || value.SourceDenominator.FreezeID == "" || len(value.SourceDenominator.FreezeID) > 512 || !utf8.ValidString(value.SourceDenominator.FreezeID) {
		return errors.New("plan source denominator is not a comparison-only freeze")
	}
	if value.ExecutionGate.ManifestID == "" || len(value.ExecutionGate.ManifestID) > 512 || !validSHA256(value.ExecutionGate.ManifestPayloadSHA256) || value.ExecutionGate.VerificationState != executionVerificationState || !value.ExecutionGate.ExternalVerificationRequired || value.ExecutionGate.Verified || value.ExecutionGate.PredecessorEligible {
		return errors.New("plan execution gate is not an external-verification binding")
	}
	if value.AcquisitionCapability != planCapability() {
		return errors.New("plan transport capability changed")
	}
	if len(value.Targets) == 0 || len(value.Targets) > maxPlanTargets {
		return errors.New("plan target cardinality is empty or over-bound")
	}
	if value.Bounds != planBounds(value.Targets) {
		return errors.New("plan bounds do not match the enumerated denominators")
	}
	seenAuthorities := map[string]struct{}{}
	seenSets := map[string]struct{}{}
	seenPublishers := map[string]struct{}{}
	seenFiles := map[string]struct{}{}
	totalFiles := 0
	for _, target := range value.Targets {
		if target.AuthorityID == "" || target.SourceSetID == "" || target.ComponentID == "" || target.ComponentVersion == "" || target.Publisher.PublisherID == "" {
			return errors.New("plan target identity is incomplete")
		}
		if _, ok := seenAuthorities[target.AuthorityID]; ok {
			return errors.New("plan aliases source authorities")
		}
		if _, ok := seenSets[target.SourceSetID]; ok {
			return errors.New("plan aliases source sets")
		}
		if _, ok := seenPublishers[target.Publisher.PublisherID]; ok {
			return errors.New("plan aliases publishers")
		}
		seenAuthorities[target.AuthorityID] = struct{}{}
		seenSets[target.SourceSetID] = struct{}{}
		seenPublishers[target.Publisher.PublisherID] = struct{}{}
		if !repoPattern.MatchString(target.Repository) || !validRequestedRef(target.RefKind, target.RequestedTag) {
			return errors.New("plan target repository, ref kind, or ref name syntax is invalid")
		}
		if (target.ExpectedRefType != "tag" && target.ExpectedRefType != "commit") || !sha1Pattern.MatchString(target.ExpectedRefSHA1) || !sha1Pattern.MatchString(target.ExpectedCommitSHA1) || !sha1Pattern.MatchString(target.ExpectedRootTreeSHA1) {
			return errors.New("plan target ref, commit, or root-tree binding is malformed")
		}
		if target.RefKind == "branch" && target.ExpectedRefType != "commit" {
			return errors.New("plan branch target must resolve to a commit ref")
		}
		if len(target.ExpectedTagObjects) > maxAnnotatedTagChain {
			return errors.New("plan annotated tag chain exceeds bound")
		}
		if err := validateAnnotatedChain(target); err != nil {
			return err
		}
		if len(target.Files) == 0 {
			return errors.New("plan target selects no files")
		}
		for _, file := range target.Files {
			if err := validatePath(file.Path); err != nil {
				return err
			}
			if file.SourceKey == "" || !utf8.ValidString(file.SourceKey) {
				return errors.New("plan file source key is empty")
			}
			if (file.Mode != "100644" && file.Mode != "100755") || !sha1Pattern.MatchString(file.GitBlobSHA1) || !validSHA256(file.RawSHA256) || file.Bytes < 0 || file.Bytes > maxBlobBytes {
				return errors.New("plan file identity is malformed")
			}
			if err := validateExpectedPathResolution(file, target.ExpectedRootTreeSHA1); err != nil {
				return err
			}
			key := target.Repository + ":" + file.Path
			if _, ok := seenFiles[key]; ok {
				return errors.New("plan duplicates a source path")
			}
			seenFiles[key] = struct{}{}
			totalFiles++
		}
		wantID, err := deriveTargetID(target.contractTargetCore)
		if err != nil {
			return err
		}
		if target.TargetID != wantID {
			return errors.New("plan target ID does not content-address its core")
		}
	}
	if totalFiles > maxPlanFiles {
		return errors.New("plan file cardinality is over-bound")
	}
	return nil
}

func validateAnnotatedChain(target contractTarget) error {
	if target.ExpectedRefType == "commit" {
		if len(target.ExpectedTagObjects) != 0 || target.ExpectedRefSHA1 != target.ExpectedCommitSHA1 {
			return errors.New("plan lightweight ref must bind the commit directly")
		}
		return nil
	}
	if len(target.ExpectedTagObjects) == 0 {
		return errors.New("plan annotated ref has no tag chain")
	}
	seen := map[string]struct{}{}
	current := target.ExpectedRefSHA1
	for index, object := range target.ExpectedTagObjects {
		if object.SHA1 != current || !sha1Pattern.MatchString(object.SHA1) || !sha1Pattern.MatchString(object.TargetSHA1) {
			return errors.New("plan annotated tag chain is disconnected or malformed")
		}
		if _, ok := seen[object.SHA1]; ok {
			return errors.New("plan annotated tag chain contains a cycle")
		}
		seen[object.SHA1] = struct{}{}
		if index == 0 && object.Name != target.RequestedTag {
			return errors.New("plan first annotated tag name differs from the requested tag")
		}
		last := index == len(target.ExpectedTagObjects)-1
		if last {
			if object.TargetType != "commit" || object.TargetSHA1 != target.ExpectedCommitSHA1 {
				return errors.New("plan annotated tag chain does not terminate at the pinned commit")
			}
			return nil
		}
		if object.TargetType != "tag" {
			return errors.New("plan intermediate annotated tag does not point at another tag")
		}
		current = object.TargetSHA1
	}
	return nil
}

func validateExpectedPathResolution(file contractFile, rootTree string) error {
	segments := strings.Split(file.Path, "/")
	if len(file.ExpectedPathResolution) != len(segments) {
		return errors.New("plan path resolution cardinality differs from the file path")
	}
	current := rootTree
	seenTrees := map[string]struct{}{rootTree: {}}
	for index, binding := range file.ExpectedPathResolution {
		if binding.ParentTreeSHA1 != current || binding.Segment != segments[index] || !sha1Pattern.MatchString(binding.ObjectSHA1) {
			return errors.New("plan path resolution is disconnected or malformed")
		}
		last := index == len(segments)-1
		if !last {
			if binding.ObjectType != "tree" || binding.Mode != "040000" || binding.Bytes != nil {
				return errors.New("plan intermediate path binding is not an exact tree")
			}
			if _, exists := seenTrees[binding.ObjectSHA1]; exists {
				return errors.New("plan path resolution contains a tree cycle")
			}
			seenTrees[binding.ObjectSHA1] = struct{}{}
			current = binding.ObjectSHA1
			continue
		}
		if binding.ObjectType != "blob" || binding.Mode != file.Mode || binding.ObjectSHA1 != file.GitBlobSHA1 || binding.Bytes == nil || *binding.Bytes != file.Bytes {
			return errors.New("plan terminal path binding differs from the exact blob")
		}
	}
	return nil
}

func validatePath(value string) error {
	if value == "" || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || !utf8.ValidString(value) {
		return errors.New("source path is empty, over-bound, or noncanonical")
	}
	segments := strings.Split(value, "/")
	if len(segments) > maxPathDepth {
		return errors.New("source path exceeds depth bound")
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\x00\r\n") {
			return errors.New("source path has a noncanonical segment")
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

// --- Canonical JSON machinery reused VERBATIM from P1-SRC-03 contract.go. ---

func canonicalJSON(value any) ([]byte, error) {
	if err := validateCanonicalInput(reflect.ValueOf(value), 0, new(int), make(map[canonicalVisit]struct{})); err != nil {
		return nil, err
	}
	if normalized, generic, err := normalizeCanonicalInput(value); err != nil {
		return nil, err
	} else if generic {
		value = normalized
	}
	initial, err := marshalCanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	normalized, err := parseStrictJSON(initial)
	if err != nil {
		return nil, err
	}
	return marshalCanonicalJSON(normalized)
}

type canonicalVisit struct {
	typeName string
	pointer  uintptr
}

func validateCanonicalInput(value reflect.Value, depth int, nodes *int, active map[canonicalVisit]struct{}) error {
	if !value.IsValid() {
		return nil
	}
	if depth > maxJSONDepth {
		return errors.New("canonical JSON input exceeds maximum depth")
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return errors.New("canonical JSON input exceeds maximum node count")
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		return validateCanonicalInput(value.Elem(), depth, nodes, active)
	}
	var visit canonicalVisit
	switch value.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice:
		if value.IsNil() {
			return nil
		}
		visit = canonicalVisit{typeName: value.Type().String(), pointer: value.Pointer()}
		if _, exists := active[visit]; exists {
			return errors.New("canonical JSON input contains a reference cycle")
		}
		active[visit] = struct{}{}
		defer delete(active, visit)
	}
	switch value.Kind() {
	case reflect.Bool:
		return nil
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return errors.New("canonical JSON input contains invalid UTF-8")
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if value.Uint() > math.MaxInt64 {
			return errors.New("canonical JSON input contains an integer outside signed 64-bit range")
		}
		return nil
	case reflect.Float32, reflect.Float64:
		floating := value.Float()
		if math.IsInf(floating, 0) || math.IsNaN(floating) {
			return errors.New("canonical JSON input contains a non-finite number")
		}
		return nil
	case reflect.Pointer:
		return validateCanonicalInput(value.Elem(), depth+1, nodes, active)
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalInput(value.Index(index), depth+1, nodes, active); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return errors.New("canonical JSON input map keys are not strings")
		}
		iterator := value.MapRange()
		for iterator.Next() {
			if !utf8.ValidString(iterator.Key().String()) {
				return errors.New("canonical JSON input contains an invalid UTF-8 map key")
			}
			if err := validateCanonicalInput(iterator.Value(), depth+1, nodes, active); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			if (field.PkgPath != "" && !field.Anonymous) || field.Tag.Get("json") == "-" {
				continue
			}
			if err := validateCanonicalInput(value.Field(index), depth+1, nodes, active); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("canonical JSON input contains unsupported Go kind %s", value.Kind())
	}
}

func marshalCanonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	raw := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	return unescapeJSONLineSeparators(raw), nil
}

func unescapeJSONLineSeparators(raw []byte) []byte {
	result := make([]byte, 0, len(raw))
	for index := 0; index < len(raw); {
		if raw[index] != '\\' || index+1 >= len(raw) {
			result = append(result, raw[index])
			index++
			continue
		}
		if raw[index+1] == '\\' {
			result = append(result, raw[index], raw[index+1])
			index += 2
			continue
		}
		if index+5 < len(raw) && raw[index+1] == 'u' {
			switch string(raw[index+2 : index+6]) {
			case "2028":
				result = append(result, []byte(" ")...)
				index += 6
				continue
			case "2029":
				result = append(result, []byte(" ")...)
				index += 6
				continue
			}
		}
		result = append(result, raw[index], raw[index+1])
		index += 2
	}
	return result
}

func normalizeCanonicalInput(value any) (any, bool, error) {
	switch typed := value.(type) {
	case nil, bool, string:
		return typed, true, nil
	case json.Number:
		number, err := normalizeJSONNumber(typed)
		return number, true, err
	case float64:
		number, err := canonicalBinary64(typed)
		return number, true, err
	case float32:
		number, err := canonicalBinary64(float64(typed))
		return number, true, err
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return typed, true, nil
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			normalized, generic, err := normalizeCanonicalInput(item)
			if err != nil || !generic {
				return nil, generic, err
			}
			result[index] = normalized
		}
		return result, true, nil
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized, generic, err := normalizeCanonicalInput(item)
			if err != nil || !generic {
				return nil, generic, err
			}
			result[key] = normalized
		}
		return result, true, nil
	default:
		return value, false, nil
	}
}

func documentJSON(value any) ([]byte, error) {
	raw, err := canonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func parseStrictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	if err := validateEscapedUnicode(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	value, err := parseJSONValue(decoder, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON has trailing content")
		}
		return nil, fmt.Errorf("JSON trailing content: %w", err)
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder, depth int, nodes *int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("JSON exceeds maximum depth")
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return nil, errors.New("JSON exceeds maximum node count")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		switch value := token.(type) {
		case json.Number:
			normalized, err := normalizeJSONNumber(value)
			if err != nil {
				return nil, err
			}
			return normalized, nil
		case string:
			if !utf8.ValidString(value) {
				return nil, errors.New("JSON string is not valid UTF-8")
			}
		}
		return token, nil
	}
	switch delimiter {
	case '{':
		result := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, exists := result[key]; exists {
				return nil, fmt.Errorf("JSON duplicate key: %s", key)
			}
			item, err := parseJSONValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result[key] = item
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("JSON object is not terminated")
		}
		return result, nil
	case '[':
		result := make([]any, 0)
		for decoder.More() {
			item, err := parseJSONValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result = append(result, item)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("JSON array is not terminated")
		}
		return result, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func normalizeJSONNumber(value json.Number) (json.Number, error) {
	raw := value.String()
	if !strings.ContainsAny(raw, ".eE") {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return "", errors.New("JSON integer is outside the signed 64-bit range")
		}
		if parsed == 0 {
			return json.Number("0"), nil
		}
		return value, nil
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
		return "", errors.New("JSON number is not finite binary64")
	}
	return canonicalBinary64(parsed)
}

func canonicalBinary64(value float64) (json.Number, error) {
	if math.IsInf(value, 0) || math.IsNaN(value) {
		return "", errors.New("JSON number is not finite binary64")
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	exponentIndex := strings.LastIndexByte(scientific, 'e')
	exponent, err := strconv.Atoi(scientific[exponentIndex+1:])
	if err != nil {
		return "", errors.New("JSON binary64 exponent is invalid")
	}
	raw := scientific
	if exponent >= -4 && exponent < 16 {
		raw = strconv.FormatFloat(value, 'f', -1, 64)
	}
	if !strings.ContainsAny(raw, ".eE") {
		raw += ".0"
	}
	return json.Number(raw), nil
}

func validateEscapedUnicode(raw []byte) error {
	inside := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inside = !inside
		case '\\':
			if !inside || index+1 >= len(raw) {
				continue
			}
			index++
			if raw[index] != 'u' || index+4 >= len(raw) {
				continue
			}
			value, ok := parseHexQuad(raw[index+1 : index+5])
			if !ok {
				continue
			}
			index += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return errors.New("JSON string contains an unpaired low surrogate")
			}
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
				return errors.New("JSON string contains an unpaired high surrogate")
			}
			low, ok := parseHexQuad(raw[index+3 : index+7])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return errors.New("JSON string contains an unpaired high surrogate")
			}
			index += 6
		}
	}
	return nil
}

func parseHexQuad(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var result uint16
	for _, character := range raw {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}
