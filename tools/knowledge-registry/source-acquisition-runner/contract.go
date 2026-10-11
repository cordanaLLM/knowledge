package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

const (
	acceptedPlanID   = "source-acquisition-plan:sha256:7b06d690d2edfe08e1fd05060116b3ca08a2a8f82763976f4d4fe1232c844aad"
	acceptedBundleID = "accepted-record-artifact-bundle:sha256:61310bc368840c0202b0bd6e6d828c140aba26b7a389922d9b1fdbb836aecba6"
	capabilityDigest = "sha256:dbc41fe166ae7672119d2655b57be528151474cad8edb4c8332a95c6f5151889"
	apiOrigin        = "https://api.github.com"
	apiVersion       = "2026-03-10"
	maxPlanBytes     = 32 * 1024 * 1024
	maxJSONDepth     = 128
	maxJSONNodes     = 1_000_000
)

var expectedTargets = []expectedTarget{
	{
		ComponentID:         "cmp:helm:argoproj/argo-rollouts",
		TargetID:            "source-acquisition-target:4373fe183d527428e3a6418772c7c5c7c57fd252ba4d1b1404de559f41aedb9c",
		RecordID:            "record:p1-src-02:argo-chart:argo-rollouts",
		RecordSHA256:        "sha256:fa3b9d84a5ea67492a21b2ec2fa66e3a1b677af7fae40364119fee84f4ac639a",
		RecordLogicalPath:   "knowledge/registry/records/argo-argo-rollouts-chart.json",
		RecordArtifactPath:  "accepted-records/argo-argo-rollouts-chart.json",
		RecordArtifactBytes: 97985,
		ComponentVersionID:  "ver:helm:argoproj/argo-rollouts@2.41.0",
		ResolvedVersion:     "2.41.0",
		RequestedTag:        "argo-rollouts-2.41.0",
		ExpectedCommit:      "8796aeaa82428f96c3a20293f75a1a805f99d32b",
		ContentRoot:         "charts/argo-rollouts",
	},
	{
		ComponentID:         "cmp:helm:argoproj/argo-workflows",
		TargetID:            "source-acquisition-target:cf9e813ef4139a18baead84e8752be6414508a1873e1d1d1156c6f8ac20b5b5e",
		RecordID:            "record:p1-src-02:argo-chart:argo-workflows",
		RecordSHA256:        "sha256:5210407c2b1f85ec909615429d28c7d56fd2b51e6ea572b818dc309fb06bd801",
		RecordLogicalPath:   "knowledge/registry/records/argo-argo-workflows-chart.json",
		RecordArtifactPath:  "accepted-records/argo-argo-workflows-chart.json",
		RecordArtifactBytes: 135283,
		ComponentVersionID:  "ver:helm:argoproj/argo-workflows@1.0.20",
		ResolvedVersion:     "1.0.20",
		RequestedTag:        "argo-workflows-1.0.20",
		ExpectedCommit:      "f5030f65031287ae00222bfc2bf47004dff5dc5b",
		ContentRoot:         "charts/argo-workflows",
	},
}

type expectedTarget struct {
	ComponentID         string
	TargetID            string
	RecordID            string
	RecordSHA256        string
	RecordLogicalPath   string
	RecordArtifactPath  string
	RecordArtifactBytes int64
	ComponentVersionID  string
	ResolvedVersion     string
	RequestedTag        string
	ExpectedCommit      string
	ContentRoot         string
}

type plan struct {
	Schema              string          `json:"$schema"`
	SchemaVersion       string          `json:"schema_version"`
	RecordSchemaVersion string          `json:"record_schema_version"`
	PlanKind            string          `json:"plan_kind"`
	PlanID              string          `json:"plan_id"`
	PlanPayloadSHA256   string          `json:"plan_payload_sha256"`
	AuthorityState      string          `json:"authority_state"`
	ReviewState         string          `json:"review_state"`
	CompileEligible     bool            `json:"compile_eligible"`
	PromoteEligible     bool            `json:"promote_eligible"`
	AuthorityBoundary   map[string]bool `json:"authority_boundary"`
	ExecutionBoundary   map[string]bool `json:"execution_boundary"`
	Generator           struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Source  string `json:"source"`
	} `json:"generator"`
	ArtifactBundle struct {
		BundleID             string `json:"bundle_id"`
		PayloadSHA256        string `json:"payload_sha256"`
		SuccessorRecordSetID string `json:"successor_record_set_id"`
		AcceptanceOutcomeID  string `json:"acceptance_outcome_id"`
	} `json:"artifact_bundle"`
	Selection struct {
		Mode         string   `json:"mode"`
		ComponentIDs []string `json:"component_ids"`
	} `json:"selection"`
	AcquisitionCapability capability   `json:"acquisition_capability"`
	Targets               []planTarget `json:"targets"`
	Counts                struct {
		Total        int `json:"total"`
		Ready        int `json:"ready"`
		Blocked      int `json:"blocked"`
		BlockingGaps int `json:"blocking_gaps"`
	} `json:"counts"`
}

type capability struct {
	CapabilityID             string   `json:"capability_id"`
	CapabilityContractSHA256 string   `json:"capability_contract_sha256"`
	Transport                string   `json:"transport"`
	APIOrigin                string   `json:"api_origin"`
	APIVersion               string   `json:"api_version"`
	ObjectFormat             string   `json:"object_format"`
	SupportedModes           []string `json:"supported_modes"`
}

type planTarget struct {
	TargetID          string `json:"target_id"`
	State             string `json:"state"`
	RecordLogicalPath string `json:"record_logical_path"`
	RecordArtifact    struct {
		Base          string `json:"base"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"content_sha256"`
		Bytes         int64  `json:"bytes"`
	} `json:"record_artifact"`
	ArtifactBundleID   string   `json:"artifact_bundle_id"`
	RecordSHA256       string   `json:"record_sha256"`
	RecordID           string   `json:"record_id"`
	ComponentID        string   `json:"component_id"`
	ComponentVersionID string   `json:"component_version_id"`
	ComponentKind      string   `json:"component_kind"`
	Lifecycle          string   `json:"lifecycle"`
	Repository         string   `json:"repository"`
	ResolvedVersion    string   `json:"resolved_version"`
	RequestedTag       string   `json:"requested_tag"`
	ExpectedCommit     string   `json:"expected_commit"`
	ContentRoots       []string `json:"content_roots"`
	TargetIdentity     struct {
		Repository     string   `json:"repository"`
		RequestedTag   string   `json:"requested_tag"`
		ExpectedCommit string   `json:"expected_commit"`
		ContentRoots   []string `json:"content_roots"`
	} `json:"target_identity"`
	SourceResolutionReviewState string            `json:"source_resolution_review_state"`
	AcquisitionCapability       string            `json:"acquisition_capability"`
	ChannelType                 string            `json:"channel_type"`
	Gaps                        []json.RawMessage `json:"gaps"`
}

func loadPlan(path, allowedPlanID string) (*plan, error) {
	raw, err := readRegularNoFollow(path, maxPlanBytes)
	if err != nil {
		return nil, fmt.Errorf("read plan: %w", err)
	}
	return parsePlan(raw, allowedPlanID)
}

func parsePlan(raw []byte, allowedPlanID string) (*plan, error) {
	value, err := parseStrictJSON(raw, maxJSONDepth, maxJSONNodes)
	if err != nil {
		return nil, fmt.Errorf("decode plan: %w", err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("plan root must be an object")
	}
	planID, ok := root["plan_id"].(string)
	if !ok {
		return nil, errors.New("plan_id must be a string")
	}
	payloadClaim, ok := root["plan_payload_sha256"].(string)
	if !ok {
		return nil, errors.New("plan_payload_sha256 must be a string")
	}
	payload := make(map[string]any, len(root)-2)
	for key, item := range root {
		if key != "plan_id" && key != "plan_payload_sha256" {
			payload[key] = item
		}
	}
	payloadRaw, err := canonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalize plan payload: %w", err)
	}
	digest := sha256.Sum256(payloadRaw)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	if payloadClaim != payloadSHA {
		return nil, fmt.Errorf("plan payload SHA-256 does not match its semantic content: claimed %s, computed %s over %d bytes", payloadClaim, payloadSHA, len(payloadRaw))
	}
	if planID != "source-acquisition-plan:"+payloadSHA {
		return nil, errors.New("plan ID does not match its payload SHA-256")
	}
	if planID != allowedPlanID {
		return nil, fmt.Errorf("plan ID is not the accepted P1-SRC-02 replay: %s", planID)
	}
	var decoded plan
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode typed plan: %w", err)
	}
	if err := validatePlan(&decoded); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func validatePlan(value *plan) error {
	if value.Schema != "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-plan.schema.json" || value.SchemaVersion != "3.0.0" || value.RecordSchemaVersion != "1.0.0" || value.PlanKind != "reviewed_source_acquisition_plan" {
		return errors.New("plan schema identity is not the accepted v3 contract")
	}
	if value.AuthorityState != "non_authoritative" || value.ReviewState != "not_applicable" || value.CompileEligible || value.PromoteEligible {
		return errors.New("plan authority state widened")
	}
	if err := requireExactFalseBoundary(value.AuthorityBoundary, []string{"git_mutation", "pointer_mutation", "production_mutation", "retrieval_release", "signing", "source_admission"}, "authority"); err != nil {
		return err
	}
	if err := requireExactFalseBoundary(value.ExecutionBoundary, []string{"cache_mutation", "execution_authorized", "inventory_emission", "network_access"}, "execution"); err != nil {
		return err
	}
	if value.Generator.Name != "archeion-reviewed-source-acquisition" || value.Generator.Version != "5" || value.Generator.Source != "tools/knowledge-registry/acquire_sources.py" {
		return errors.New("plan generator identity is not v3 generator 5")
	}
	if value.ArtifactBundle.BundleID != acceptedBundleID || value.ArtifactBundle.PayloadSHA256 != strings.TrimPrefix(acceptedBundleID, "accepted-record-artifact-bundle:") {
		return errors.New("plan does not bind the accepted P1-SRC-02 artifact bundle")
	}
	if value.ArtifactBundle.SuccessorRecordSetID != "reviewed-record-set:sha256:a2a00248b70e028385f9ff9d20109a0d221952350ce5cc919913acde46a75ad2" || value.ArtifactBundle.AcceptanceOutcomeID != "source-acceptance-outcome:sha256:9d46784ca9183d120045525b156171b9de7f4c473688ecfccba19055bb33b475" {
		return errors.New("plan acceptance lineage is not the accepted P1-SRC-02 lineage")
	}
	if value.Selection.Mode != "explicit_exact" || !equalStrings(value.Selection.ComponentIDs, []string{expectedTargets[0].ComponentID, expectedTargets[1].ComponentID}) {
		return errors.New("plan selection is not the exact Rollouts/Workflows pair")
	}
	if value.AcquisitionCapability.CapabilityID != "github-git-objects-rest-v1" || value.AcquisitionCapability.CapabilityContractSHA256 != capabilityDigest || value.AcquisitionCapability.Transport != "https-json" || value.AcquisitionCapability.APIOrigin != apiOrigin || value.AcquisitionCapability.APIVersion != apiVersion || value.AcquisitionCapability.ObjectFormat != "sha1" || !equalStrings(value.AcquisitionCapability.SupportedModes, []string{"040000", "100644", "100755"}) {
		return errors.New("plan acquisition capability differs from the pinned contract")
	}
	if value.Counts.Total != 2 || value.Counts.Ready != 2 || value.Counts.Blocked != 0 || value.Counts.BlockingGaps != 0 || len(value.Targets) != 2 {
		return errors.New("plan target cardinality is not exactly two ready targets")
	}
	for index, expected := range expectedTargets {
		if err := validatePlanTarget(value.Targets[index], expected); err != nil {
			return fmt.Errorf("target %d: %w", index, err)
		}
	}
	return nil
}

func validatePlanTarget(value planTarget, expected expectedTarget) error {
	if value.TargetID != expected.TargetID || value.ComponentID != expected.ComponentID || value.RecordID != expected.RecordID || value.RecordSHA256 != expected.RecordSHA256 || value.RecordLogicalPath != expected.RecordLogicalPath || value.ComponentVersionID != expected.ComponentVersionID || value.ResolvedVersion != expected.ResolvedVersion || value.RequestedTag != expected.RequestedTag || value.ExpectedCommit != expected.ExpectedCommit {
		return errors.New("immutable target identity differs from the accepted target")
	}
	if value.State != "ready" || value.ComponentKind != "chart" || value.Lifecycle != "deployed" || value.Repository != "argoproj/argo-helm" || value.SourceResolutionReviewState != "accepted" || value.AcquisitionCapability != "github-git-objects-rest-v1" || value.ChannelType != "source" || len(value.Gaps) != 0 {
		return errors.New("target readiness or authority fields differ from the accepted target")
	}
	if !equalStrings(value.ContentRoots, []string{expected.ContentRoot}) || value.TargetIdentity.Repository != value.Repository || value.TargetIdentity.RequestedTag != value.RequestedTag || value.TargetIdentity.ExpectedCommit != value.ExpectedCommit || !equalStrings(value.TargetIdentity.ContentRoots, value.ContentRoots) {
		return errors.New("target identity projection is inconsistent")
	}
	if value.ArtifactBundleID != acceptedBundleID || value.RecordArtifact.Base != "bundle" || value.RecordArtifact.Path != expected.RecordArtifactPath || value.RecordArtifact.ContentSHA256 != expected.RecordSHA256 || value.RecordArtifact.Bytes != expected.RecordArtifactBytes {
		return errors.New("target record artifact is not the accepted bundle artifact")
	}
	return nil
}

func requireExactFalseBoundary(value map[string]bool, expected []string, label string) error {
	if len(value) != len(expected) {
		return fmt.Errorf("%s boundary has missing or extra fields", label)
	}
	for _, key := range expected {
		item, ok := value[key]
		if !ok || item {
			return fmt.Errorf("%s boundary widened at %s", label, key)
		}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func canonicalJSON(value any) ([]byte, error) {
	initial, err := marshalJSON(value)
	if err != nil {
		return nil, err
	}
	normalized, err := parseStrictJSON(initial, maxJSONDepth, maxJSONNodes)
	if err != nil {
		return nil, err
	}
	return marshalJSON(normalized)
}

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func parseStrictJSON(raw []byte, maxDepth, maxNodes int) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	value, err := parseJSONValue(decoder, 0, maxDepth, maxNodes, &nodes)
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

func parseJSONValue(decoder *json.Decoder, depth, maxDepth, maxNodes int, nodes *int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("JSON exceeds maximum depth")
	}
	*nodes++
	if *nodes > maxNodes {
		return nil, errors.New("JSON exceeds maximum node count")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
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
			item, err := parseJSONValue(decoder, depth+1, maxDepth, maxNodes, nodes)
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
			item, err := parseJSONValue(decoder, depth+1, maxDepth, maxNodes, nodes)
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

func readRegularNoFollow(path string, maximum int64) ([]byte, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		syscall.Close(descriptor)
		return nil, errors.New("could not own file descriptor")
	}
	defer file.Close()
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
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, errors.New("input changed while it was read")
	}
	return raw, nil
}

func sortedKeys(value map[string]struct{}) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
