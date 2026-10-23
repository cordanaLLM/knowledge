package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	runnerName               = "archeion-github-git-object-runner"
	runnerVersion            = "3"
	runnerContractSHA256     = "sha256:6306df08e525472da822d10477ea12a9ec3929d14d9d322f842ac88b76401fdb"
	maxAnnotatedTagDepth     = 8
	maxTreeDepth             = 32
	maxTreeEntries           = 8192
	maxTreesPerTarget        = 2048
	maxFilesPerTarget        = 8192
	maxBlobBytes             = 16 * 1024 * 1024
	maxLogicalBytesPerTarget = 128 * 1024 * 1024
	maxLogicalBytesPerRun    = 256 * 1024 * 1024
	maxHTTPRequests          = 20_000
	maxHTTPResponseBytes     = 384 * 1024 * 1024
	maxObjectJSONBytes       = 24 * 1024 * 1024
	maxInventoryPathBytes    = 4096
	maxTagObjectNameRunes    = 255
	maxTokenBytes            = 4096
)

var (
	sha1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
)

type runner struct {
	client  *http.Client
	baseURL *url.URL
	token   string

	requests      int
	responseBytes int64
	treeCache     map[string]gitTree
	blobCache     map[string][]byte
}

type gitObject struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type gitRef struct {
	Ref    string    `json:"ref"`
	Object gitObject `json:"object"`
}

type gitTag struct {
	Tag    string    `json:"tag"`
	SHA    string    `json:"sha"`
	Object gitObject `json:"object"`
}

type gitCommit struct {
	SHA  string `json:"sha"`
	Tree struct {
		SHA string `json:"sha"`
	} `json:"tree"`
}

type gitTree struct {
	SHA       string         `json:"sha"`
	Tree      []gitTreeEntry `json:"tree"`
	Truncated *bool          `json:"truncated"`
}

type gitTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size *int64 `json:"size,omitempty"`
}

type gitBlob struct {
	SHA      string `json:"sha"`
	Size     *int64 `json:"size"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

type runnerContract struct {
	APIOrigin                string `json:"api_origin"`
	APIVersion               string `json:"api_version"`
	CapabilityContractSHA256 string `json:"capability_contract_sha256"`
	CASCommit                string `json:"cas_commit"`
	GitBlobIdentity          string `json:"git_blob_identity"`
	HTTPResponseValidation   string `json:"http_response_validation"`
	MaxAnnotatedTagDepth     int    `json:"max_annotated_tag_depth"`
	ObjectFormat             string `json:"object_format"`
	ReceiptRecovery          string `json:"receipt_recovery"`
	ReceiptVersion           string `json:"receipt_version"`
	RedirectPolicy           string `json:"redirect_policy"`
	TreeTraversal            string `json:"tree_traversal"`
}

type runnerDescriptor struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	ContractSHA256 string `json:"contract_sha256"`
}

type runnerBounds struct {
	Targets               int   `json:"targets"`
	AnnotatedTagDepth     int   `json:"annotated_tag_depth"`
	TreeDepth             int   `json:"tree_depth"`
	TreeEntries           int   `json:"tree_entries"`
	TreesPerTarget        int   `json:"trees_per_target"`
	FilesPerTarget        int   `json:"files_per_target"`
	BlobBytes             int64 `json:"blob_bytes"`
	LogicalBytesPerTarget int64 `json:"logical_bytes_per_target"`
	LogicalBytesPerRun    int64 `json:"logical_bytes_per_run"`
	HTTPRequests          int   `json:"http_requests"`
	HTTPResponseBytes     int64 `json:"http_response_bytes"`
	ObjectJSONBytes       int64 `json:"object_json_bytes"`
	JSONDepth             int   `json:"json_depth"`
	JSONNodes             int   `json:"json_nodes"`
	InventoryPathBytes    int   `json:"inventory_path_bytes"`
	TagObjectNameRunes    int   `json:"tag_object_name_runes"`
}

type authorityBoundary struct {
	SourceAdmission    bool `json:"source_admission"`
	RetrievalRelease   bool `json:"retrieval_release"`
	Signing            bool `json:"signing"`
	PointerMutation    bool `json:"pointer_mutation"`
	GitMutation        bool `json:"git_mutation"`
	ProductionMutation bool `json:"production_mutation"`
}

type tagObjectReceipt struct {
	SHA1       string `json:"sha1"`
	Name       string `json:"name"`
	TargetType string `json:"target_type"`
	TargetSHA1 string `json:"target_sha1"`
}

type tagResolution struct {
	Ref                 string             `json:"ref"`
	InitialObjectType   string             `json:"initial_object_type"`
	InitialObjectSHA1   string             `json:"initial_object_sha1"`
	AnnotatedTagObjects []tagObjectReceipt `json:"annotated_tag_objects"`
	ResolvedCommitSHA1  string             `json:"resolved_commit_sha1"`
}

type subtreeBinding struct {
	Path     string `json:"path"`
	TreeSHA1 string `json:"tree_sha1"`
}

type fileInventory struct {
	Path        string `json:"path"`
	Mode        string `json:"mode"`
	GitBlobSHA1 string `json:"git_blob_sha1"`
	RawSHA256   string `json:"raw_sha256"`
	Bytes       int64  `json:"bytes"`
	CASPath     string `json:"cas_path"`
}

type targetCounts struct {
	Files        int   `json:"files"`
	Trees        int   `json:"trees"`
	LogicalBytes int64 `json:"logical_bytes"`
}

type targetInventory struct {
	TargetID           string           `json:"target_id"`
	ComponentID        string           `json:"component_id"`
	RecordID           string           `json:"record_id"`
	RecordSHA256       string           `json:"record_sha256"`
	Repository         string           `json:"repository"`
	RequestedTag       string           `json:"requested_tag"`
	TagResolution      tagResolution    `json:"tag_resolution"`
	ExpectedCommitSHA1 string           `json:"expected_commit_sha1"`
	ResolvedCommitSHA1 string           `json:"resolved_commit_sha1"`
	CommitTreeSHA1     string           `json:"commit_tree_sha1"`
	ContentRoot        string           `json:"content_root"`
	SubtreeSHA1        string           `json:"subtree_sha1"`
	SubtreeResolution  []subtreeBinding `json:"subtree_resolution"`
	Files              []fileInventory  `json:"files"`
	Counts             targetCounts     `json:"counts"`
}

type runCounts struct {
	Targets          int   `json:"targets"`
	Files            int   `json:"files"`
	LogicalBytes     int64 `json:"logical_bytes"`
	UniqueCASObjects int   `json:"unique_cas_objects"`
	UniqueCASBytes   int64 `json:"unique_cas_bytes"`
	HTTPRequests     int   `json:"http_requests"`
}

type receiptCore struct {
	Schema                string            `json:"$schema"`
	SchemaVersion         string            `json:"schema_version"`
	ReceiptKind           string            `json:"receipt_kind"`
	AuthorityState        string            `json:"authority_state"`
	ReviewState           string            `json:"review_state"`
	CompileEligible       bool              `json:"compile_eligible"`
	PromoteEligible       bool              `json:"promote_eligible"`
	AuthorityBoundary     authorityBoundary `json:"authority_boundary"`
	PlanID                string            `json:"plan_id"`
	PlanPayloadSHA256     string            `json:"plan_payload_sha256"`
	ArtifactBundleID      string            `json:"artifact_bundle_id"`
	AcquisitionCapability capability        `json:"acquisition_capability"`
	Runner                runnerDescriptor  `json:"runner"`
	Bounds                runnerBounds      `json:"bounds"`
	Targets               []targetInventory `json:"targets"`
	Counts                runCounts         `json:"counts"`
}

type receipt struct {
	ReceiptID            string `json:"receipt_id"`
	ReceiptPayloadSHA256 string `json:"receipt_payload_sha256"`
	receiptCore
}

type receiptBinding struct {
	ReceiptID            string `json:"receipt_id"`
	ReceiptPayloadSHA256 string `json:"receipt_payload_sha256"`
}

type proposalCore struct {
	Schema             string            `json:"$schema"`
	SchemaVersion      string            `json:"schema_version"`
	ProposalKind       string            `json:"proposal_kind"`
	AuthorityState     string            `json:"authority_state"`
	ReviewState        string            `json:"review_state"`
	CompileEligible    bool              `json:"compile_eligible"`
	PromoteEligible    bool              `json:"promote_eligible"`
	AuthorityBoundary  authorityBoundary `json:"authority_boundary"`
	PlanID             string            `json:"plan_id"`
	ArtifactBundleID   string            `json:"artifact_bundle_id"`
	AcquisitionReceipt receiptBinding    `json:"acquisition_receipt"`
	Targets            []targetInventory `json:"targets"`
	Counts             runCounts         `json:"counts"`
}

type inventoryProposal struct {
	ProposalID            string `json:"proposal_id"`
	ProposalPayloadSHA256 string `json:"proposal_payload_sha256"`
	proposalCore
}

type runResult struct {
	Receipt       receipt
	ReceiptBytes  []byte
	ReceiptPath   string
	Proposal      inventoryProposal
	ProposalBytes []byte
	ProposalPath  string
}

func newRunner(client *http.Client, baseURL, token string, allowTestOrigin bool) (*runner, error) {
	if client == nil {
		return nil, errors.New("HTTP client is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API origin: %w", err)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.User != nil || parsed.ForceQuery || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" || parsed.Host == "" {
		return nil, errors.New("API origin must contain only scheme and authority")
	}
	if !allowTestOrigin && parsed.String() != apiOrigin {
		return nil, errors.New("production runner API origin differs from the pinned capability")
	}
	if !allowTestOrigin && parsed.Scheme != "https" {
		return nil, errors.New("production runner requires HTTPS")
	}
	if allowTestOrigin && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("test API origin requires HTTP or HTTPS")
	}
	if !validTokenHeaderValue(token) {
		return nil, errors.New("GitHub token is not a bounded single-line header value")
	}
	parsed.Path = ""
	clientCopy := *client
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("redirects are forbidden for exact Git-object acquisition")
	}
	return &runner{client: &clientCopy, baseURL: parsed, token: token}, nil
}

func validTokenHeaderValue(token string) bool {
	if len(token) > maxTokenBytes || !utf8.ValidString(token) || strings.TrimSpace(token) != token {
		return false
	}
	for _, value := range []byte(token) {
		if value <= 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}

func (r *runner) run(ctx context.Context, selected *plan, store *casStore) (*runResult, error) {
	if selected == nil || store == nil {
		return nil, errors.New("plan and CAS store are required")
	}
	recovered, err := recoverPublishedRun(selected, store)
	if err != nil {
		return nil, fmt.Errorf("recover published run: %w", err)
	}
	if recovered != nil {
		return recovered, nil
	}
	r.requests = 0
	r.responseBytes = 0
	r.treeCache = make(map[string]gitTree)
	r.blobCache = make(map[string][]byte)
	targets := make([]targetInventory, 0, len(selected.Targets))
	var logicalBytes int64
	for _, target := range selected.Targets {
		inventory, err := r.acquireTarget(ctx, target, store)
		if err != nil {
			return nil, fmt.Errorf("acquire %s: %w", target.ComponentID, err)
		}
		logicalBytes += inventory.Counts.LogicalBytes
		if logicalBytes > maxLogicalBytesPerRun {
			return nil, errors.New("run exceeds logical byte bound")
		}
		targets = append(targets, inventory)
	}
	if err := store.verifyTargets(targets); err != nil {
		return nil, fmt.Errorf("verify durable CAS before receipt: %w", err)
	}
	counts := countRun(targets, r.requests)
	contractDigest, err := runnerContractDigest()
	if err != nil {
		return nil, err
	}
	core := receiptCore{
		Schema:                "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-receipt.schema.json",
		SchemaVersion:         "1.0.0",
		ReceiptKind:           "github_git_object_acquisition_receipt",
		AuthorityState:        "non_authoritative",
		ReviewState:           "unreviewed",
		CompileEligible:       false,
		PromoteEligible:       false,
		AuthorityBoundary:     authorityBoundary{},
		PlanID:                selected.PlanID,
		PlanPayloadSHA256:     selected.PlanPayloadSHA256,
		ArtifactBundleID:      selected.ArtifactBundle.BundleID,
		AcquisitionCapability: selected.AcquisitionCapability,
		Runner:                runnerDescriptor{Name: runnerName, Version: runnerVersion, ContractSHA256: contractDigest},
		Bounds:                fixedRunnerBounds(),
		Targets:               targets,
		Counts:                counts,
	}
	receiptValue, receiptBytes, err := materializeReceipt(core)
	if err != nil {
		return nil, err
	}
	proposalValue, proposalBytes, err := materializeProposal(selected, receiptValue, targets, counts)
	if err != nil {
		return nil, err
	}
	receiptPath, err := store.putReceipt(receiptValue.ReceiptID, receiptBytes)
	if err != nil {
		return nil, fmt.Errorf("publish receipt: %w", err)
	}
	proposalPath, err := store.putProposal(proposalValue.ProposalID, proposalBytes)
	if err != nil {
		return nil, fmt.Errorf("publish inventory proposal: %w", err)
	}
	if err := verifyPublishedRunSet(store, receiptValue.ReceiptID, receiptBytes, proposalValue.ProposalID, proposalBytes); err != nil {
		return nil, fmt.Errorf("verify published run set: %w", err)
	}
	return &runResult{Receipt: receiptValue, ReceiptBytes: receiptBytes, ReceiptPath: receiptPath, Proposal: proposalValue, ProposalBytes: proposalBytes, ProposalPath: proposalPath}, nil
}

func recoverPublishedRun(selected *plan, store *casStore) (*runResult, error) {
	receiptNames, err := store.listPublishedDirectory("receipts", 2)
	if err != nil {
		return nil, err
	}
	proposalNames, err := store.listPublishedDirectory("inventory-proposals", 2)
	if err != nil {
		return nil, err
	}
	if len(receiptNames) == 0 {
		if len(proposalNames) != 0 {
			return nil, errors.New("inventory proposal exists without its predecessor receipt")
		}
		return nil, nil
	}
	if len(receiptNames) != 1 {
		return nil, errors.New("published receipt recovery is ambiguous")
	}
	receiptName := receiptNames[0]
	if len(receiptName) != 69 || !strings.HasSuffix(receiptName, ".json") {
		return nil, errors.New("published receipt filename is not content-addressed")
	}
	receiptHex := strings.TrimSuffix(receiptName, ".json")
	if _, err := stripPrefixedID("source-acquisition-receipt:sha256:"+receiptHex, "source-acquisition-receipt:sha256:"); err != nil {
		return nil, errors.New("published receipt filename is not content-addressed")
	}
	receiptPath := path.Join("receipts", receiptName)
	receiptRaw, err := store.readPublished(receiptPath, maxPublishedJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("read published receipt: %w", err)
	}
	if _, err := parseStrictJSON(receiptRaw, maxJSONDepth, maxJSONNodes); err != nil {
		return nil, fmt.Errorf("strict published receipt JSON: %w", err)
	}
	var receiptValue receipt
	if err := json.Unmarshal(receiptRaw, &receiptValue); err != nil {
		return nil, fmt.Errorf("decode published receipt: %w", err)
	}
	rebuiltReceipt, rebuiltRaw, err := materializeReceipt(receiptValue.receiptCore)
	if err != nil {
		return nil, err
	}
	if receiptValue.ReceiptID != rebuiltReceipt.ReceiptID || receiptValue.ReceiptPayloadSHA256 != rebuiltReceipt.ReceiptPayloadSHA256 || receiptHex != strings.TrimPrefix(rebuiltReceipt.ReceiptID, "source-acquisition-receipt:sha256:") || !bytes.Equal(receiptRaw, rebuiltRaw) {
		return nil, errors.New("published receipt content address or exact bytes are invalid")
	}
	if err := validateRecoveredReceipt(selected, receiptValue); err != nil {
		return nil, err
	}
	if err := store.verifyTargets(receiptValue.Targets); err != nil {
		return nil, fmt.Errorf("verify recovered receipt CAS: %w", err)
	}
	receiptPath, err = store.putReceipt(receiptValue.ReceiptID, receiptRaw)
	if err != nil {
		return nil, fmt.Errorf("rehabilitate recovered receipt: %w", err)
	}
	proposalValue, proposalRaw, err := materializeProposal(selected, receiptValue, receiptValue.Targets, receiptValue.Counts)
	if err != nil {
		return nil, err
	}
	expectedProposalName := strings.TrimPrefix(proposalValue.ProposalID, "source-inventory-proposal:sha256:") + ".json"
	if len(proposalNames) > 1 || (len(proposalNames) == 1 && proposalNames[0] != expectedProposalName) {
		return nil, errors.New("published inventory proposal recovery is conflicting or ambiguous")
	}
	proposalPath, err := store.putProposal(proposalValue.ProposalID, proposalRaw)
	if err != nil {
		return nil, fmt.Errorf("publish recovered inventory proposal: %w", err)
	}
	if err := verifyPublishedRunSet(store, receiptValue.ReceiptID, receiptRaw, proposalValue.ProposalID, proposalRaw); err != nil {
		return nil, fmt.Errorf("verify recovered run set: %w", err)
	}
	return &runResult{Receipt: receiptValue, ReceiptBytes: receiptRaw, ReceiptPath: receiptPath, Proposal: proposalValue, ProposalBytes: proposalRaw, ProposalPath: proposalPath}, nil
}

func verifyPublishedRunSet(store *casStore, receiptID string, receiptRaw []byte, proposalID string, proposalRaw []byte) error {
	receiptHex, err := stripPrefixedID(receiptID, "source-acquisition-receipt:sha256:")
	if err != nil {
		return err
	}
	proposalHex, err := stripPrefixedID(proposalID, "source-inventory-proposal:sha256:")
	if err != nil {
		return err
	}
	receipts, err := store.listPublishedDirectory("receipts", 1)
	if err != nil {
		return err
	}
	proposals, err := store.listPublishedDirectory("inventory-proposals", 1)
	if err != nil {
		return err
	}
	if !equalStrings(receipts, []string{receiptHex + ".json"}) || !equalStrings(proposals, []string{proposalHex + ".json"}) {
		return errors.New("published receipt/proposal set is incomplete or ambiguous")
	}
	publishedReceipt, err := store.readPublished(path.Join("receipts", receipts[0]), maxPublishedJSONBytes)
	if err != nil || !bytes.Equal(publishedReceipt, receiptRaw) {
		return errors.Join(errors.New("published receipt changed during final run-set verification"), err)
	}
	publishedProposal, err := store.readPublished(path.Join("inventory-proposals", proposals[0]), maxPublishedJSONBytes)
	if err != nil || !bytes.Equal(publishedProposal, proposalRaw) {
		return errors.Join(errors.New("published inventory proposal changed during final run-set verification"), err)
	}
	return nil
}

func validateRecoveredReceipt(selected *plan, value receipt) error {
	contractDigest, err := runnerContractDigest()
	if err != nil {
		return err
	}
	core := value.receiptCore
	if core.Schema != "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-receipt.schema.json" || core.SchemaVersion != "1.0.0" || core.ReceiptKind != "github_git_object_acquisition_receipt" {
		return errors.New("published receipt schema identity is invalid")
	}
	if core.AuthorityState != "non_authoritative" || core.ReviewState != "unreviewed" || core.CompileEligible || core.PromoteEligible || core.AuthorityBoundary != (authorityBoundary{}) {
		return errors.New("published receipt authority state widened")
	}
	if core.PlanID != selected.PlanID || core.PlanPayloadSHA256 != selected.PlanPayloadSHA256 || core.ArtifactBundleID != selected.ArtifactBundle.BundleID {
		return errors.New("published receipt plan lineage is invalid")
	}
	if !equalCapabilities(core.AcquisitionCapability, selected.AcquisitionCapability) {
		return errors.New("published receipt capability differs from the exact plan")
	}
	if core.Runner != (runnerDescriptor{Name: runnerName, Version: runnerVersion, ContractSHA256: contractDigest}) || core.Bounds != fixedRunnerBounds() {
		return errors.New("published receipt runner contract or bounds are invalid")
	}
	if len(core.Targets) != len(expectedTargets) {
		return errors.New("published receipt target cardinality is invalid")
	}
	for index, target := range core.Targets {
		if err := validateRecoveredTarget(target, expectedTargets[index]); err != nil {
			return fmt.Errorf("published receipt target %d: %w", index, err)
		}
	}
	if core.Counts.HTTPRequests < 1 || core.Counts.HTTPRequests > maxHTTPRequests || core.Counts != countRun(core.Targets, core.Counts.HTTPRequests) {
		return errors.New("published receipt run counts are invalid")
	}
	return nil
}

func validateRecoveredTarget(value targetInventory, expected expectedTarget) error {
	if value.TargetID != expected.TargetID || value.ComponentID != expected.ComponentID || value.RecordID != expected.RecordID || value.RecordSHA256 != expected.RecordSHA256 || value.Repository != "argoproj/argo-helm" || value.RequestedTag != expected.RequestedTag || value.ExpectedCommitSHA1 != expected.ExpectedCommit || value.ResolvedCommitSHA1 != expected.ExpectedCommit || value.ContentRoot != expected.ContentRoot {
		return errors.New("immutable target identity differs from the exact plan")
	}
	if !sha1Pattern.MatchString(value.CommitTreeSHA1) || !sha1Pattern.MatchString(value.SubtreeSHA1) {
		return errors.New("commit or subtree SHA-1 is malformed")
	}
	if err := validateRecoveredTag(value.TagResolution, expected); err != nil {
		return err
	}
	expectedPaths := []string{"", "charts", expected.ContentRoot}
	if len(value.SubtreeResolution) != len(expectedPaths) {
		return errors.New("subtree resolution is incomplete")
	}
	for index, binding := range value.SubtreeResolution {
		if binding.Path != expectedPaths[index] || !sha1Pattern.MatchString(binding.TreeSHA1) {
			return errors.New("subtree resolution binding is invalid")
		}
	}
	if value.SubtreeResolution[0].TreeSHA1 != value.CommitTreeSHA1 || value.SubtreeResolution[len(value.SubtreeResolution)-1].TreeSHA1 != value.SubtreeSHA1 {
		return errors.New("subtree resolution endpoints are inconsistent")
	}
	if len(value.Files) < 1 || len(value.Files) > maxFilesPerTarget || value.Counts.Files != len(value.Files) || value.Counts.Trees < 1 || value.Counts.Trees > maxTreesPerTarget {
		return errors.New("target file or tree counts are invalid")
	}
	var logicalBytes int64
	previousPath := ""
	for _, file := range value.Files {
		if err := validateInventoryPath(file.Path); err != nil {
			return err
		}
		if previousPath != "" && file.Path <= previousPath {
			return errors.New("target files are not strictly path-sorted")
		}
		previousPath = file.Path
		if file.Mode != "100644" && file.Mode != "100755" {
			return errors.New("target file mode is unsupported")
		}
		if !sha1Pattern.MatchString(file.GitBlobSHA1) || file.Bytes < 0 || file.Bytes > maxBlobBytes {
			return errors.New("target file Git identity or byte count is invalid")
		}
		hexDigest, err := stripSHA256(file.RawSHA256)
		if err != nil {
			return err
		}
		if file.CASPath != path.Join("cas", "sha256", hexDigest[:2], hexDigest) {
			return errors.New("target file CAS path is not content-derived")
		}
		logicalBytes += file.Bytes
		if logicalBytes > maxLogicalBytesPerTarget {
			return errors.New("target logical bytes exceed the fixed bound")
		}
	}
	if value.Counts.LogicalBytes != logicalBytes {
		return errors.New("target logical byte count is inconsistent")
	}
	return nil
}

func validateRecoveredTag(value tagResolution, expected expectedTarget) error {
	if value.Ref != "refs/tags/"+expected.RequestedTag || value.ResolvedCommitSHA1 != expected.ExpectedCommit || !sha1Pattern.MatchString(value.InitialObjectSHA1) {
		return errors.New("tag resolution identity is invalid")
	}
	if value.InitialObjectType == "commit" {
		if value.InitialObjectSHA1 != expected.ExpectedCommit || len(value.AnnotatedTagObjects) != 0 {
			return errors.New("lightweight tag resolution is inconsistent")
		}
		return nil
	}
	if value.InitialObjectType != "tag" || len(value.AnnotatedTagObjects) < 1 || len(value.AnnotatedTagObjects) > maxAnnotatedTagDepth {
		return errors.New("annotated tag resolution is invalid")
	}
	current := value.InitialObjectSHA1
	seen := make(map[string]struct{}, len(value.AnnotatedTagObjects))
	for index, object := range value.AnnotatedTagObjects {
		if object.SHA1 != current || !sha1Pattern.MatchString(object.SHA1) || !sha1Pattern.MatchString(object.TargetSHA1) {
			return errors.New("annotated tag chain identity is inconsistent")
		}
		if _, exists := seen[object.SHA1]; exists {
			return errors.New("annotated tag chain contains a cycle")
		}
		seen[object.SHA1] = struct{}{}
		if err := validateTagObjectName(object.Name); err != nil {
			return err
		}
		if index == 0 && object.Name != expected.RequestedTag {
			return errors.New("first annotated tag name differs from the requested tag")
		}
		last := index == len(value.AnnotatedTagObjects)-1
		if last {
			if object.TargetType != "commit" || object.TargetSHA1 != expected.ExpectedCommit {
				return errors.New("annotated tag chain does not terminate at the expected commit")
			}
		} else if object.TargetType != "tag" || object.TargetSHA1 != value.AnnotatedTagObjects[index+1].SHA1 {
			return errors.New("annotated tag chain link is invalid")
		}
		current = object.TargetSHA1
	}
	return nil
}

func equalCapabilities(left, right capability) bool {
	return left.CapabilityID == right.CapabilityID && left.CapabilityContractSHA256 == right.CapabilityContractSHA256 && left.Transport == right.Transport && left.APIOrigin == right.APIOrigin && left.APIVersion == right.APIVersion && left.ObjectFormat == right.ObjectFormat && equalStrings(left.SupportedModes, right.SupportedModes)
}

func (r *runner) acquireTarget(ctx context.Context, target planTarget, store *casStore) (targetInventory, error) {
	resolvedTag, err := r.resolveTag(ctx, target.Repository, target.RequestedTag, target.ExpectedCommit)
	if err != nil {
		return targetInventory{}, err
	}
	commit, err := r.getCommit(ctx, target.Repository, target.ExpectedCommit)
	if err != nil {
		return targetInventory{}, err
	}
	bindings, subtreeSHA, err := r.resolveSubtree(ctx, target.Repository, commit.Tree.SHA, target.ContentRoots[0])
	if err != nil {
		return targetInventory{}, err
	}
	resolutionAncestors := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		resolutionAncestors = append(resolutionAncestors, binding.TreeSHA1)
	}
	files, trees, logicalBytes, err := r.walkSubtree(ctx, target.Repository, subtreeSHA, resolutionAncestors, store)
	if err != nil {
		return targetInventory{}, err
	}
	return targetInventory{
		TargetID:           target.TargetID,
		ComponentID:        target.ComponentID,
		RecordID:           target.RecordID,
		RecordSHA256:       target.RecordSHA256,
		Repository:         target.Repository,
		RequestedTag:       target.RequestedTag,
		TagResolution:      resolvedTag,
		ExpectedCommitSHA1: target.ExpectedCommit,
		ResolvedCommitSHA1: commit.SHA,
		CommitTreeSHA1:     commit.Tree.SHA,
		ContentRoot:        target.ContentRoots[0],
		SubtreeSHA1:        subtreeSHA,
		SubtreeResolution:  bindings,
		Files:              files,
		Counts:             targetCounts{Files: len(files), Trees: trees, LogicalBytes: logicalBytes},
	}, nil
}

func (r *runner) resolveTag(ctx context.Context, repository, tag, expectedCommit string) (tagResolution, error) {
	if !tagPattern.MatchString(tag) {
		return tagResolution{}, errors.New("tag is outside the exact bounded syntax")
	}
	var reference gitRef
	if err := r.getJSON(ctx, repository, "/git/ref/tags/"+url.PathEscape(tag), &reference); err != nil {
		return tagResolution{}, fmt.Errorf("get exact tag ref: %w", err)
	}
	if reference.Ref != "refs/tags/"+tag || !sha1Pattern.MatchString(reference.Object.SHA) || (reference.Object.Type != "commit" && reference.Object.Type != "tag") {
		return tagResolution{}, errors.New("tag ref response is not the exact requested ref")
	}
	result := tagResolution{Ref: reference.Ref, InitialObjectType: reference.Object.Type, InitialObjectSHA1: reference.Object.SHA, AnnotatedTagObjects: []tagObjectReceipt{}}
	object := reference.Object
	seen := make(map[string]struct{})
	for depth := 0; object.Type == "tag"; depth++ {
		if depth >= maxAnnotatedTagDepth {
			return tagResolution{}, errors.New("annotated tag dereference exceeds bound")
		}
		if _, exists := seen[object.SHA]; exists {
			return tagResolution{}, errors.New("annotated tag cycle detected")
		}
		seen[object.SHA] = struct{}{}
		var annotated gitTag
		if err := r.getJSON(ctx, repository, "/git/tags/"+object.SHA, &annotated); err != nil {
			return tagResolution{}, fmt.Errorf("get annotated tag object: %w", err)
		}
		if annotated.SHA != object.SHA || !sha1Pattern.MatchString(annotated.SHA) || !sha1Pattern.MatchString(annotated.Object.SHA) || (annotated.Object.Type != "commit" && annotated.Object.Type != "tag") {
			return tagResolution{}, errors.New("annotated tag object is malformed or swapped")
		}
		if err := validateTagObjectName(annotated.Tag); err != nil {
			return tagResolution{}, err
		}
		if depth == 0 && annotated.Tag != tag {
			return tagResolution{}, errors.New("annotated tag name differs from the requested tag")
		}
		result.AnnotatedTagObjects = append(result.AnnotatedTagObjects, tagObjectReceipt{SHA1: annotated.SHA, Name: annotated.Tag, TargetType: annotated.Object.Type, TargetSHA1: annotated.Object.SHA})
		object = annotated.Object
	}
	if object.Type != "commit" || object.SHA != expectedCommit {
		return tagResolution{}, errors.New("tag does not resolve to the accepted commit")
	}
	result.ResolvedCommitSHA1 = object.SHA
	return result, nil
}

func (r *runner) getCommit(ctx context.Context, repository, commitSHA string) (gitCommit, error) {
	if !sha1Pattern.MatchString(commitSHA) {
		return gitCommit{}, errors.New("commit SHA-1 is malformed")
	}
	var commit gitCommit
	if err := r.getJSON(ctx, repository, "/git/commits/"+commitSHA, &commit); err != nil {
		return gitCommit{}, fmt.Errorf("get commit: %w", err)
	}
	if commit.SHA != commitSHA || !sha1Pattern.MatchString(commit.Tree.SHA) {
		return gitCommit{}, errors.New("commit response is swapped or has no exact tree")
	}
	return commit, nil
}

func (r *runner) resolveSubtree(ctx context.Context, repository, rootTreeSHA, contentRoot string) ([]subtreeBinding, string, error) {
	if contentRoot == "" || path.Clean(contentRoot) != contentRoot || strings.HasPrefix(contentRoot, "/") {
		return nil, "", errors.New("content root is not canonical")
	}
	segments := strings.Split(contentRoot, "/")
	current := rootTreeSHA
	bindings := []subtreeBinding{{Path: "", TreeSHA1: rootTreeSHA}}
	seen := map[string]struct{}{rootTreeSHA: {}}
	var traversed string
	for _, segment := range segments {
		if err := validateTreeName(segment); err != nil {
			return nil, "", fmt.Errorf("content-root segment: %w", err)
		}
		tree, err := r.getTree(ctx, repository, current)
		if err != nil {
			return nil, "", err
		}
		entry, err := exactTreeEntry(tree.Tree, segment)
		if err != nil {
			return nil, "", fmt.Errorf("resolve content root %s: %w", contentRoot, err)
		}
		if entry.Type != "tree" || entry.Mode != "040000" || entry.Size != nil {
			return nil, "", errors.New("content-root segment is not a Git tree")
		}
		if _, exists := seen[entry.SHA]; exists {
			return nil, "", errors.New("content-root tree cycle detected")
		}
		seen[entry.SHA] = struct{}{}
		current = entry.SHA
		if traversed == "" {
			traversed = segment
		} else {
			traversed += "/" + segment
		}
		bindings = append(bindings, subtreeBinding{Path: traversed, TreeSHA1: current})
	}
	return bindings, current, nil
}

type treeJob struct {
	SHA       string
	Prefix    string
	Depth     int
	Ancestors []string
}

func (r *runner) walkSubtree(ctx context.Context, repository, subtreeSHA string, resolutionAncestors []string, store *casStore) ([]fileInventory, int, int64, error) {
	if len(resolutionAncestors) == 0 || resolutionAncestors[len(resolutionAncestors)-1] != subtreeSHA {
		return nil, 0, 0, errors.New("subtree traversal lacks its complete resolution ancestry")
	}
	queue := []treeJob{{SHA: subtreeSHA, Ancestors: append([]string{}, resolutionAncestors...)}}
	files := make([]fileInventory, 0)
	treeCount := 0
	var logicalBytes int64
	for len(queue) > 0 {
		job := queue[0]
		queue = queue[1:]
		if job.Depth > maxTreeDepth {
			return nil, 0, 0, errors.New("subtree exceeds depth bound")
		}
		treeCount++
		if treeCount > maxTreesPerTarget {
			return nil, 0, 0, errors.New("subtree exceeds tree-object bound")
		}
		tree, err := r.getTree(ctx, repository, job.SHA)
		if err != nil {
			return nil, 0, 0, err
		}
		seenNames := make(map[string]struct{}, len(tree.Tree))
		for _, entry := range tree.Tree {
			if err := validateTreeName(entry.Path); err != nil {
				return nil, 0, 0, fmt.Errorf("unsafe tree entry: %w", err)
			}
			if _, exists := seenNames[entry.Path]; exists {
				return nil, 0, 0, errors.New("tree contains a duplicate path")
			}
			seenNames[entry.Path] = struct{}{}
			if !sha1Pattern.MatchString(entry.SHA) {
				return nil, 0, 0, errors.New("tree entry has malformed SHA-1")
			}
			relative := entry.Path
			if job.Prefix != "" {
				relative = job.Prefix + "/" + entry.Path
			}
			if err := validateInventoryPath(relative); err != nil {
				return nil, 0, 0, fmt.Errorf("unsafe inventory path: %w", err)
			}
			switch {
			case entry.Type == "tree" && entry.Mode == "040000":
				if entry.Size != nil {
					return nil, 0, 0, errors.New("tree entry unexpectedly declares blob size")
				}
				for _, ancestor := range job.Ancestors {
					if entry.SHA == ancestor {
						return nil, 0, 0, errors.New("tree cycle detected")
					}
				}
				chain := append(append([]string{}, job.Ancestors...), entry.SHA)
				queue = append(queue, treeJob{SHA: entry.SHA, Prefix: relative, Depth: job.Depth + 1, Ancestors: chain})
			case entry.Type == "blob" && (entry.Mode == "100644" || entry.Mode == "100755"):
				if entry.Size == nil || *entry.Size < 0 || *entry.Size > maxBlobBytes {
					return nil, 0, 0, errors.New("blob entry has missing or out-of-bound size")
				}
				raw, err := r.getBlob(ctx, repository, entry.SHA, *entry.Size)
				if err != nil {
					return nil, 0, 0, err
				}
				rawDigest := sha256.Sum256(raw)
				rawSHA := "sha256:" + hex.EncodeToString(rawDigest[:])
				casPath, err := store.putBlob(rawSHA, raw)
				if err != nil {
					return nil, 0, 0, fmt.Errorf("store blob %s: %w", relative, err)
				}
				files = append(files, fileInventory{Path: relative, Mode: entry.Mode, GitBlobSHA1: entry.SHA, RawSHA256: rawSHA, Bytes: int64(len(raw)), CASPath: casPath})
				logicalBytes += int64(len(raw))
				if len(files) > maxFilesPerTarget || logicalBytes > maxLogicalBytesPerTarget {
					return nil, 0, 0, errors.New("subtree exceeds file or logical-byte bound")
				}
			default:
				return nil, 0, 0, fmt.Errorf("unsupported Git tree entry type/mode: %s/%s", entry.Type, entry.Mode)
			}
		}
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	if len(files) == 0 {
		return nil, 0, 0, errors.New("selected subtree contains no files")
	}
	return files, treeCount, logicalBytes, nil
}

func (r *runner) getTree(ctx context.Context, repository, sha string) (gitTree, error) {
	if cached, ok := r.treeCache[sha]; ok {
		return cached, nil
	}
	var tree gitTree
	if err := r.getJSON(ctx, repository, "/git/trees/"+sha, &tree); err != nil {
		return gitTree{}, fmt.Errorf("get tree %s: %w", sha, err)
	}
	if tree.SHA != sha || tree.Truncated == nil {
		return gitTree{}, errors.New("tree response is swapped or omits truncation state")
	}
	if *tree.Truncated {
		return gitTree{}, errors.New("Git tree response is truncated")
	}
	if len(tree.Tree) > maxTreeEntries {
		return gitTree{}, errors.New("Git tree exceeds entry bound")
	}
	r.treeCache[sha] = tree
	return tree, nil
}

func (r *runner) getBlob(ctx context.Context, repository, sha string, expectedSize int64) ([]byte, error) {
	if cached, ok := r.blobCache[sha]; ok {
		if int64(len(cached)) != expectedSize {
			return nil, errors.New("reused blob size differs between tree entries")
		}
		return cached, nil
	}
	var blob gitBlob
	if err := r.getJSON(ctx, repository, "/git/blobs/"+sha, &blob); err != nil {
		return nil, fmt.Errorf("get blob %s: %w", sha, err)
	}
	if blob.SHA != sha || blob.Size == nil || *blob.Size != expectedSize || blob.Encoding != "base64" || expectedSize > maxBlobBytes {
		return nil, errors.New("blob response identity, encoding, or size differs from tree entry")
	}
	compact := strings.Map(func(value rune) rune {
		if value == '\n' || value == '\r' {
			return -1
		}
		return value
	}, blob.Content)
	raw, err := base64.StdEncoding.Strict().DecodeString(compact)
	if err != nil {
		return nil, errors.New("blob content is not strict base64")
	}
	if int64(len(raw)) != expectedSize {
		return nil, errors.New("decoded blob byte count differs from Git metadata")
	}
	identityInput := append([]byte("blob "+strconv.Itoa(len(raw))+"\x00"), raw...)
	gitDigest := sha1.Sum(identityInput)
	if hex.EncodeToString(gitDigest[:]) != sha {
		return nil, errors.New("decoded blob does not reproduce its Git SHA-1")
	}
	r.blobCache[sha] = raw
	return raw, nil
}

func (r *runner) getJSON(ctx context.Context, repository, suffix string, destination any) error {
	if repository != "argoproj/argo-helm" {
		return errors.New("repository is outside the accepted denominator")
	}
	if r.requests >= maxHTTPRequests {
		return errors.New("HTTP request bound exceeded")
	}
	endpoint := r.baseURL.String() + "/repos/argoproj/argo-helm" + suffix
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("User-Agent", "archeion-source-acquisition-runner/"+runnerVersion)
	request.Header.Set("Accept-Encoding", "identity")
	if r.token != "" {
		request.Header.Set("Authorization", "Bearer "+r.token)
	}
	r.requests++
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("GitHub REST returned HTTP %d", response.StatusCode)
	}
	if len(response.Header.Values("Link")) != 0 {
		return errors.New("non-paginated Git-object endpoint returned a pagination Link header")
	}
	encodings := response.Header.Values("Content-Encoding")
	if len(encodings) > 1 || (len(encodings) == 1 && encodings[0] != "identity") {
		return errors.New("Git-object response used an unexpected content encoding")
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errors.New("Git-object response has an ambiguous or missing content type")
	}
	contentType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || contentType != "application/json" {
		return errors.New("Git-object response is not application/json")
	}
	remaining := maxHTTPResponseBytes - r.responseBytes
	if remaining <= 0 {
		return errors.New("HTTP response byte bound exceeded")
	}
	limit := int64(maxObjectJSONBytes)
	if remaining < limit {
		limit = remaining
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return errors.New("Git-object response exceeds byte bound")
	}
	r.responseBytes += int64(len(raw))
	if _, err := parseStrictJSON(raw, maxJSONDepth, maxJSONNodes); err != nil {
		return fmt.Errorf("strict Git-object JSON: %w", err)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("decode Git-object response: %w", err)
	}
	return nil
}

func exactTreeEntry(entries []gitTreeEntry, name string) (gitTreeEntry, error) {
	var match *gitTreeEntry
	seen := make(map[string]struct{}, len(entries))
	for index := range entries {
		entry := entries[index]
		if err := validateTreeName(entry.Path); err != nil {
			return gitTreeEntry{}, err
		}
		if _, exists := seen[entry.Path]; exists {
			return gitTreeEntry{}, errors.New("tree contains duplicate paths")
		}
		seen[entry.Path] = struct{}{}
		if entry.Path == name {
			copy := entry
			match = &copy
		}
	}
	if match == nil {
		return gitTreeEntry{}, errors.New("tree has no exact requested child")
	}
	if !sha1Pattern.MatchString(match.SHA) {
		return gitTreeEntry{}, errors.New("tree child SHA-1 is malformed")
	}
	return *match, nil
}

func validateTreeName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || !utf8ValidString(name) {
		return fmt.Errorf("noncanonical Git tree name %q", name)
	}
	return nil
}

func validateInventoryPath(value string) error {
	if value == "" || len(value) > maxInventoryPathBytes || path.Clean(value) != value || strings.HasPrefix(value, "/") {
		return errors.New("inventory path is empty, over-bound, or noncanonical")
	}
	for _, segment := range strings.Split(value, "/") {
		if err := validateTreeName(segment); err != nil {
			return err
		}
	}
	return nil
}

func validateTagObjectName(value string) error {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxTagObjectNameRunes || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("annotated tag name is empty, invalid, or over-bound")
	}
	return nil
}

func utf8ValidString(value string) bool {
	return utf8.ValidString(value)
}

func runnerContractDigest() (string, error) {
	contract := runnerContract{APIOrigin: apiOrigin, APIVersion: apiVersion, CapabilityContractSHA256: capabilityDigest, CASCommit: "dirfd-anchored-private-single-link-fsync-direct-o-excl-no-delete-v3", GitBlobIdentity: "git-sha1-header-body-v1", HTTPResponseValidation: "single-content-type-identity-no-link-v1", MaxAnnotatedTagDepth: maxAnnotatedTagDepth, ObjectFormat: "sha1", ReceiptRecovery: "cas-verified-receipt-to-exact-singleton-proposal-v3", ReceiptVersion: "1.0.0", RedirectPolicy: "forbid-before-send-v1", TreeTraversal: "non-recursive-complete-v1"}
	raw, err := canonicalJSON(contract)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	actual := "sha256:" + hex.EncodeToString(digest[:])
	if actual != runnerContractSHA256 {
		return "", fmt.Errorf("runner contract digest constant is stale: computed %s", actual)
	}
	return actual, nil
}

func fixedRunnerBounds() runnerBounds {
	return runnerBounds{Targets: 2, AnnotatedTagDepth: maxAnnotatedTagDepth, TreeDepth: maxTreeDepth, TreeEntries: maxTreeEntries, TreesPerTarget: maxTreesPerTarget, FilesPerTarget: maxFilesPerTarget, BlobBytes: maxBlobBytes, LogicalBytesPerTarget: maxLogicalBytesPerTarget, LogicalBytesPerRun: maxLogicalBytesPerRun, HTTPRequests: maxHTTPRequests, HTTPResponseBytes: maxHTTPResponseBytes, ObjectJSONBytes: maxObjectJSONBytes, JSONDepth: maxJSONDepth, JSONNodes: maxJSONNodes, InventoryPathBytes: maxInventoryPathBytes, TagObjectNameRunes: maxTagObjectNameRunes}
}

func countRun(targets []targetInventory, requests int) runCounts {
	objects := make(map[string]int64)
	result := runCounts{Targets: len(targets), HTTPRequests: requests}
	for _, target := range targets {
		result.Files += target.Counts.Files
		result.LogicalBytes += target.Counts.LogicalBytes
		for _, file := range target.Files {
			objects[file.RawSHA256] = file.Bytes
		}
	}
	result.UniqueCASObjects = len(objects)
	for _, size := range objects {
		result.UniqueCASBytes += size
	}
	return result
}

func materializeReceipt(core receiptCore) (receipt, []byte, error) {
	payload, err := canonicalJSON(core)
	if err != nil {
		return receipt{}, nil, err
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := receipt{ReceiptID: "source-acquisition-receipt:" + payloadSHA, ReceiptPayloadSHA256: payloadSHA, receiptCore: core}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return receipt{}, nil, err
	}
	return value, append(raw, '\n'), nil
}

func materializeProposal(selected *plan, bound receipt, targets []targetInventory, counts runCounts) (inventoryProposal, []byte, error) {
	core := proposalCore{Schema: "https://github.com/cordanaLLM/knowledge/schemas/registry/source-inventory-proposal.schema.json", SchemaVersion: "1.0.0", ProposalKind: "exact_source_inventory_proposal", AuthorityState: "non_authoritative", ReviewState: "unreviewed", CompileEligible: false, PromoteEligible: false, AuthorityBoundary: authorityBoundary{}, PlanID: selected.PlanID, ArtifactBundleID: selected.ArtifactBundle.BundleID, AcquisitionReceipt: receiptBinding{ReceiptID: bound.ReceiptID, ReceiptPayloadSHA256: bound.ReceiptPayloadSHA256}, Targets: targets, Counts: counts}
	payload, err := canonicalJSON(core)
	if err != nil {
		return inventoryProposal{}, nil, err
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := inventoryProposal{ProposalID: "source-inventory-proposal:" + payloadSHA, ProposalPayloadSHA256: payloadSHA, proposalCore: core}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return inventoryProposal{}, nil, err
	}
	return value, append(raw, '\n'), nil
}
