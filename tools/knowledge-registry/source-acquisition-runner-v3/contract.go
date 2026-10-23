package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	apiOrigin             = "https://api.github.com"
	apiVersion            = "2026-03-10"
	canonicalProfile      = "registry_compact_utf8"
	contractSchema        = "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-contract-v2.schema.json"
	contractSchemaVersion = "2.0.0"
	contractKind          = "source_file_set_acquisition_v2"
	maxJSONDepth          = 128
	maxJSONNodes          = 10_000_000
	maxObjectJSONBytes    = int64(4 * 1024 * 1024)
	maxResponseBytes      = int64(32 * 1024 * 1024)
	maxBlobBytes          = int64(1024 * 1024)
	maxHTTPRequests       = 128
	maxTreeEntries        = 8192
	maxPathDepth          = 16
	maxAnnotatedTagDepth  = 16
	maxTokenBytes         = 4096
	maxContractBytes      = int64(8 * 1024 * 1024)
)

var (
	sha1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	// branchPattern admits the '/' that tags forbid (e.g. "release/1.2") while
	// still banning control chars and empty leading segments; validBranchName
	// adds the trailing-slash, "..", and "//" bans the charset alone cannot make.
	branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
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

// reviewedCapabilities is the acquisition-capability allowlist. Only a contract
// whose acquisition_capability exactly equals a reviewed entry (keyed by its
// capability_id) is admitted. Adding a new authority family means adding a new
// reviewed entry here — never widening the data plane at runtime.
var reviewedCapabilities = map[string]acquisitionCapability{
	"github-git-objects-rest-exact-file-v2": {
		CapabilityID:   "github-git-objects-rest-exact-file-v2",
		Transport:      "https-json",
		APIOrigin:      apiOrigin,
		APIVersion:     apiVersion,
		ObjectFormat:   "sha1",
		SelectionMode:  "exact_paths_only",
		RedirectPolicy: "forbid",
	},
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

type contractCore struct {
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

type acquisitionContract struct {
	ContractID            string `json:"contract_id"`
	ContractPayloadSHA256 string `json:"contract_payload_sha256"`
	contractCore
}

// materializeContract recomputes the content address from the canonical core
// and returns the self-addressed contract plus its canonical document bytes.
// Integrity is now the self-address (sha256 of the canonical core), not a
// compiled-in tuple.
func materializeContract(core contractCore) (acquisitionContract, []byte, error) {
	if err := validateContract(core); err != nil {
		return acquisitionContract{}, nil, err
	}
	payload, err := canonicalJSON(core)
	if err != nil {
		return acquisitionContract{}, nil, err
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := acquisitionContract{ContractID: "source-acquisition-contract:" + payloadSHA, ContractPayloadSHA256: payloadSHA, contractCore: core}
	document, err := documentJSON(value)
	if err != nil {
		return acquisitionContract{}, nil, err
	}
	return value, document, nil
}

// loadContract reads one stable no-follow regular file, parses it strictly,
// decodes the contract core, and re-materializes it so the file's declared
// content address and canonical bytes must equal the recomputed self-address.
func loadContract(path string) (acquisitionContract, []byte, error) {
	raw, err := readRegularNoFollow(path, maxContractBytes)
	if err != nil {
		return acquisitionContract{}, nil, err
	}
	return loadContractBytes(raw)
}

func loadContractBytes(raw []byte) (acquisitionContract, []byte, error) {
	if _, err := parseStrictJSON(raw); err != nil {
		return acquisitionContract{}, nil, fmt.Errorf("strict contract JSON: %w", err)
	}
	var value acquisitionContract
	if err := json.Unmarshal(raw, &value); err != nil {
		return acquisitionContract{}, nil, err
	}
	rebuilt, document, err := materializeContract(value.contractCore)
	if err != nil {
		return acquisitionContract{}, nil, err
	}
	if value.ContractID != rebuilt.ContractID || value.ContractPayloadSHA256 != rebuilt.ContractPayloadSHA256 || !bytes.Equal(raw, document) {
		return acquisitionContract{}, nil, errors.New("contract self-address or canonical bytes are invalid")
	}
	return rebuilt, document, nil
}

func validWorkID(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value
}

func validateBounds(b contractBounds) error {
	if b.Targets <= 0 || b.Files <= 0 || b.Files < b.Targets || b.LogicalBytes < 0 {
		return errors.New("contract bounds cardinality is nonpositive or inconsistent")
	}
	if b.AnnotatedTagDepth < 0 || b.AnnotatedTagDepth > maxAnnotatedTagDepth {
		return errors.New("contract annotated-tag-depth bound is out of range")
	}
	if b.PathDepth <= 0 || b.PathDepth > maxPathDepth {
		return errors.New("contract path-depth bound is out of range")
	}
	if b.TreeEntries <= 0 || b.TreeEntries > maxTreeEntries {
		return errors.New("contract tree-entries bound is out of range")
	}
	if b.BlobBytes <= 0 || b.BlobBytes > maxBlobBytes {
		return errors.New("contract blob-bytes bound is out of range")
	}
	if b.HTTPRequests <= 0 || b.HTTPRequests > maxHTTPRequests {
		return errors.New("contract http-requests bound is out of range")
	}
	if b.HTTPResponseBytes <= 0 || b.HTTPResponseBytes > maxResponseBytes {
		return errors.New("contract http-response-bytes bound is out of range")
	}
	if b.ObjectJSONBytes <= 0 || b.ObjectJSONBytes > maxObjectJSONBytes {
		return errors.New("contract object-json-bytes bound is out of range")
	}
	return nil
}

func validateContract(value contractCore) error {
	if value.Schema != contractSchema || value.SchemaVersion != contractSchemaVersion || value.Canonicalization != canonicalProfile || value.ContractKind != contractKind {
		return errors.New("contract schema, version, or kind differs from the generalized acquisition format")
	}
	if !validWorkID(value.WorkID) {
		return errors.New("contract work identity is malformed")
	}
	// KEEP verbatim: the runner never widens authority; every acquisition stays
	// non-authoritative, unreviewed for compile/promote, with a false boundary.
	if value.AuthorityState != "non_authoritative" || value.ReviewState != "implementation_frozen" || value.CompileEligible || value.PromoteEligible || value.AuthorityBoundary != (authorityBoundary{}) {
		return errors.New("contract authority state widened")
	}
	if !value.SourceDenominator.ComparisonOnly || !validSHA256(value.SourceDenominator.FreezeDocumentSHA256) || value.SourceDenominator.FreezeID == "" || len(value.SourceDenominator.FreezeID) > 512 || !utf8.ValidString(value.SourceDenominator.FreezeID) {
		return errors.New("contract source denominator is not a comparison-only freeze")
	}
	reviewed, ok := reviewedCapabilities[value.AcquisitionCapability.CapabilityID]
	if !ok || value.AcquisitionCapability != reviewed {
		return errors.New("contract acquisition capability is not in the reviewed allowlist")
	}
	execution, err := exactExecutionGateBinding()
	if err != nil {
		return err
	}
	if value.ExecutionGate != execution {
		return errors.New("contract execution verifier gate changed or widened")
	}
	if err := validateBounds(value.Bounds); err != nil {
		return err
	}
	if value.Bounds.Targets != len(value.Targets) {
		return errors.New("contract target cardinality differs from declared bounds")
	}
	seenAuthorities := map[string]struct{}{}
	seenSets := map[string]struct{}{}
	seenPublishers := map[string]struct{}{}
	seenFiles := map[string]struct{}{}
	var bytesTotal int64
	fileCount := 0
	for _, target := range value.Targets {
		// Per-target content-address: a target id must bind its own core (p1-src03
		// enforced this via equalTargets against sha256-derived ids). Without it a
		// signed plan could mislabel a target's authority/files under any id.
		targetCoreBytes, canonErr := canonicalJSON(target.contractTargetCore)
		if canonErr != nil {
			return errors.New("contract target core is not canonicalizable")
		}
		targetDigest := sha256.Sum256(targetCoreBytes)
		if target.TargetID != "source-acquisition-target:sha256:"+hex.EncodeToString(targetDigest[:]) {
			return errors.New("contract target id does not content-address its core")
		}
		// KEEP verbatim: per-target authority / source-set / publisher aliasing
		// rejection so one contract can never launder two authorities as one.
		if _, ok := seenAuthorities[target.AuthorityID]; ok {
			return errors.New("contract aliases source authorities")
		}
		if _, ok := seenSets[target.SourceSetID]; ok {
			return errors.New("contract aliases source sets")
		}
		if _, ok := seenPublishers[target.Publisher.PublisherID]; ok {
			return errors.New("contract aliases publishers")
		}
		seenAuthorities[target.AuthorityID] = struct{}{}
		seenSets[target.SourceSetID] = struct{}{}
		seenPublishers[target.Publisher.PublisherID] = struct{}{}
		if len(target.Files) == 0 || !validRequestedRef(target.RefKind, target.RequestedTag) || !sha1Pattern.MatchString(target.ExpectedRefSHA1) || !sha1Pattern.MatchString(target.ExpectedCommitSHA1) || !sha1Pattern.MatchString(target.ExpectedRootTreeSHA1) {
			return errors.New("contract target identity or file scope is invalid")
		}
		if target.RefKind == "branch" && (target.ExpectedRefType != "commit" || len(target.ExpectedTagObjects) != 0 || target.ExpectedRefSHA1 != target.ExpectedCommitSHA1) {
			return errors.New("contract branch target must bind the commit directly with no tag chain")
		}
		if len(target.ExpectedTagObjects) > value.Bounds.AnnotatedTagDepth {
			return errors.New("contract annotated tag chain exceeds declared bounds")
		}
		for _, file := range target.Files {
			if err := validatePath(file.Path); err != nil {
				return err
			}
			if depth := len(strings.Split(file.Path, "/")); depth > value.Bounds.PathDepth {
				return errors.New("contract source path exceeds declared path-depth bound")
			}
			if err := validateExpectedPathResolution(file, target.ExpectedRootTreeSHA1); err != nil {
				return err
			}
			key := target.Repository + ":" + file.Path
			if _, ok := seenFiles[key]; ok {
				return errors.New("contract duplicates a source path")
			}
			seenFiles[key] = struct{}{}
			if (file.Mode != "100644" && file.Mode != "100755") || !sha1Pattern.MatchString(file.GitBlobSHA1) || !validSHA256(file.RawSHA256) || file.Bytes < 0 || file.Bytes > value.Bounds.BlobBytes {
				return errors.New("contract file identity is malformed or exceeds declared blob bound")
			}
			bytesTotal += file.Bytes
			fileCount++
		}
	}
	// Internal-consistency asserts (replacing the P1-SRC-03 fixed 3/6/512214
	// denominator): declared bounds must equal the observed target/file/byte
	// cardinality of the contract itself.
	if fileCount != value.Bounds.Files || len(seenFiles) != value.Bounds.Files {
		return errors.New("contract file count differs from declared bounds")
	}
	if bytesTotal != value.Bounds.LogicalBytes {
		return errors.New("contract logical-byte sum differs from declared bounds")
	}
	return nil
}

func validateExpectedPathResolution(file contractFile, rootTree string) error {
	segments := strings.Split(file.Path, "/")
	if len(file.ExpectedPathResolution) != len(segments) {
		return errors.New("contract path resolution cardinality differs from exact path")
	}
	current := rootTree
	seenTrees := map[string]struct{}{rootTree: {}}
	for index, binding := range file.ExpectedPathResolution {
		if binding.ParentTreeSHA1 != current || binding.Segment != segments[index] || !sha1Pattern.MatchString(binding.ObjectSHA1) {
			return errors.New("contract path resolution is disconnected or malformed")
		}
		last := index == len(segments)-1
		if !last {
			if binding.ObjectType != "tree" || binding.Mode != "040000" || binding.Bytes != nil {
				return errors.New("contract intermediate path binding is not an exact tree")
			}
			if _, exists := seenTrees[binding.ObjectSHA1]; exists {
				return errors.New("contract path resolution contains a tree cycle")
			}
			seenTrees[binding.ObjectSHA1] = struct{}{}
			current = binding.ObjectSHA1
			continue
		}
		if binding.ObjectType != "blob" || binding.Mode != file.Mode || binding.ObjectSHA1 != file.GitBlobSHA1 || binding.Bytes == nil || *binding.Bytes != file.Bytes {
			return errors.New("contract terminal path binding differs from exact blob")
		}
	}
	return nil
}

type runnerContract struct {
	APIOrigin              string   `json:"api_origin"`
	APIVersion             string   `json:"api_version"`
	CASCommit              string   `json:"cas_commit"`
	ContractValidation     string   `json:"contract_validation"`
	ExactContractID        string   `json:"exact_contract_id"`
	ExecutionManifestID    string   `json:"execution_manifest_id"`
	GitBlobIdentity        string   `json:"git_blob_identity"`
	HTTPResponseValidation string   `json:"http_response_validation"`
	OutputSchemas          []string `json:"output_schemas"`
	PathResolution         string   `json:"path_resolution"`
	RedirectPolicy         string   `json:"redirect_policy"`
	TagResolution          string   `json:"tag_resolution"`
}

func runnerContractDigest(contract acquisitionContract) (string, error) {
	core := runnerContract{APIOrigin: apiOrigin, APIVersion: apiVersion, CASCommit: "dirfd-anchored-private-single-link-fsync-direct-o-excl-no-delete-v3", ContractValidation: "strict-self-address-plus-plan-signature-v3", ExactContractID: contract.ContractID, ExecutionManifestID: contract.ExecutionGate.ManifestID, GitBlobIdentity: "git-sha1-header-body-plus-raw-sha256-v1", HTTPResponseValidation: "strict-json-shared-vectors-single-content-type-identity-no-link-v2", OutputSchemas: []string{"source-acquisition-receipt-v2", "source-inventory-proposal-v2"}, PathResolution: "non-recursive-exact-segment-and-tree-chain-v2", RedirectPolicy: "forbid-before-send-v1", TagResolution: "exact-ref-object-and-annotated-chain-v1"}
	raw, err := canonicalJSON(core)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validatePath(value string) error {
	if value == "" || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || !utf8.ValidString(value) {
		return errors.New("source path is empty, over-bound, or noncanonical")
	}
	segments := strings.Split(value, "/")
	if len(segments) > 16 {
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

// readRegularNoFollow opens one bounded regular file without following symlinks
// and rejects any file that changes underneath the read.
func readRegularNoFollow(path string, maximum int64) (result []byte, err error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		return nil, closeDescriptorWithError(errors.New("could not own file descriptor"), descriptor)
	}
	defer func() { err = closeWithError(err, file) }()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > maximum {
		return nil, errors.New("input is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, errors.New("input exceeds byte bound")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !sameStableFile(before, after) {
		return nil, errors.New("input changed while it was read")
	}
	return raw, nil
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sameStableFile(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime() == after.ModTime()
}
