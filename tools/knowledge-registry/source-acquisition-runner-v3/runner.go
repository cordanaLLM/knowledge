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
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	runnerName    = "archeion-source-acquisition-runner-v3"
	runnerVersion = "3"
)

type runner struct {
	client        *http.Client
	baseURL       *url.URL
	token         string
	allowedRepos  map[string]struct{}
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

type tagResolution struct {
	Ref                 string              `json:"ref"`
	InitialObjectType   string              `json:"initial_object_type"`
	InitialObjectSHA1   string              `json:"initial_object_sha1"`
	AnnotatedTagObjects []expectedTagObject `json:"annotated_tag_objects"`
	ResolvedCommitSHA1  string              `json:"resolved_commit_sha1"`
}

type fileInventory struct {
	SourceKey      string        `json:"source_key"`
	Path           string        `json:"path"`
	Mode           string        `json:"mode"`
	GitBlobSHA1    string        `json:"git_blob_sha1"`
	RawSHA256      string        `json:"raw_sha256"`
	Bytes          int64         `json:"bytes"`
	CASPath        string        `json:"cas_path"`
	PathResolution []pathBinding `json:"path_resolution"`
}

type targetCounts struct {
	Files        int   `json:"files"`
	Trees        int   `json:"trees"`
	LogicalBytes int64 `json:"logical_bytes"`
}

type targetInventory struct {
	TargetID           string          `json:"target_id"`
	AuthorityID        string          `json:"authority_id"`
	SourceSetID        string          `json:"source_set_id"`
	ComponentID        string          `json:"component_id"`
	ComponentVersion   string          `json:"component_version"`
	Repository         string          `json:"repository"`
	Publisher          publisher       `json:"publisher"`
	LicenseExpression  string          `json:"license_expression"`
	RequestedTag       string          `json:"requested_tag"`
	TagResolution      tagResolution   `json:"tag_resolution"`
	ExpectedCommitSHA1 string          `json:"expected_commit_sha1"`
	ResolvedCommitSHA1 string          `json:"resolved_commit_sha1"`
	CommitTreeSHA1     string          `json:"commit_tree_sha1"`
	Files              []fileInventory `json:"files"`
	Counts             targetCounts    `json:"counts"`
}

type runCounts struct {
	Targets          int   `json:"targets"`
	Files            int   `json:"files"`
	LogicalBytes     int64 `json:"logical_bytes"`
	UniqueCASObjects int   `json:"unique_cas_objects"`
	UniqueCASBytes   int64 `json:"unique_cas_bytes"`
	HTTPRequests     int   `json:"http_requests"`
}

type contractBinding struct {
	ContractID            string `json:"contract_id"`
	ContractPayloadSHA256 string `json:"contract_payload_sha256"`
}

type runnerDescriptor struct {
	Name                    string `json:"name"`
	Version                 string `json:"version"`
	ContractSHA256          string `json:"contract_sha256"`
	ExecutionManifestID     string `json:"execution_manifest_id"`
	ExecutionManifestSHA256 string `json:"execution_manifest_sha256"`
}

type receiptCore struct {
	Schema                string                `json:"$schema"`
	SchemaVersion         string                `json:"schema_version"`
	Canonicalization      string                `json:"canonicalization"`
	ReceiptKind           string                `json:"receipt_kind"`
	AuthorityState        string                `json:"authority_state"`
	ReviewState           string                `json:"review_state"`
	CompileEligible       bool                  `json:"compile_eligible"`
	PromoteEligible       bool                  `json:"promote_eligible"`
	AuthorityBoundary     authorityBoundary     `json:"authority_boundary"`
	AcquisitionContract   contractBinding       `json:"acquisition_contract"`
	SourceDenominator     sourceDenominator     `json:"source_denominator"`
	AcquisitionCapability acquisitionCapability `json:"acquisition_capability"`
	Runner                runnerDescriptor      `json:"runner"`
	ExecutionGate         executionGate         `json:"execution_gate"`
	Bounds                contractBounds        `json:"bounds"`
	Targets               []targetInventory     `json:"targets"`
	Counts                runCounts             `json:"counts"`
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
	Schema              string            `json:"$schema"`
	SchemaVersion       string            `json:"schema_version"`
	Canonicalization    string            `json:"canonicalization"`
	ProposalKind        string            `json:"proposal_kind"`
	AuthorityState      string            `json:"authority_state"`
	ReviewState         string            `json:"review_state"`
	CompileEligible     bool              `json:"compile_eligible"`
	PromoteEligible     bool              `json:"promote_eligible"`
	AuthorityBoundary   authorityBoundary `json:"authority_boundary"`
	AcquisitionContract contractBinding   `json:"acquisition_contract"`
	AcquisitionReceipt  receiptBinding    `json:"acquisition_receipt"`
	ExecutionGate       executionGate     `json:"execution_gate"`
	Targets             []targetInventory `json:"targets"`
	Counts              runCounts         `json:"counts"`
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

func newRunner(client *http.Client, baseURL, token string, allowTestOrigin bool, contract acquisitionContract) (*runner, error) {
	if client == nil {
		return nil, errors.New("HTTP client is required")
	}
	if err := validateMaterializedContract(contract); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API origin: %w", err)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.User != nil || parsed.ForceQuery || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" || parsed.Host == "" {
		return nil, errors.New("API origin must contain only scheme and authority")
	}
	if !allowTestOrigin && parsed.String() != apiOrigin {
		return nil, errors.New("production API origin differs from the exact contract")
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
	clientCopy := *client
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("redirects are forbidden for exact Git-object acquisition")
	}
	allowed := make(map[string]struct{}, len(contract.Targets))
	for _, target := range contract.Targets {
		allowed[target.Repository] = struct{}{}
	}
	parsed.Path = ""
	return &runner{client: &clientCopy, baseURL: parsed, token: token, allowedRepos: allowed, treeCache: map[string]gitTree{}, blobCache: map[string][]byte{}}, nil
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

func (r *runner) run(ctx context.Context, contract acquisitionContract, store *casStore) (*runResult, error) {
	if store == nil {
		return nil, errors.New("exact acquisition contract and output store are required")
	}
	if err := validateMaterializedContract(contract); err != nil {
		return nil, err
	}
	recovered, err := recoverPublishedRun(contract, store)
	if err != nil {
		return nil, fmt.Errorf("recover published run: %w", err)
	}
	if recovered != nil {
		return recovered, nil
	}
	r.requests = 0
	r.responseBytes = 0
	r.treeCache = map[string]gitTree{}
	r.blobCache = map[string][]byte{}
	targets := make([]targetInventory, 0, len(contract.Targets))
	for _, target := range contract.Targets {
		inventory, err := r.acquireTarget(ctx, target, store)
		if err != nil {
			return nil, fmt.Errorf("acquire %s: %w", target.AuthorityID, err)
		}
		targets = append(targets, inventory)
	}
	if err := validateInventories(contract, targets); err != nil {
		return nil, err
	}
	if err := store.verifyTargets(targets); err != nil {
		return nil, fmt.Errorf("verify CAS before receipt: %w", err)
	}
	counts := countRun(targets, r.requests)
	runnerSHA, err := runnerContractDigest(contract)
	if err != nil {
		return nil, err
	}
	binding := contractBinding{ContractID: contract.ContractID, ContractPayloadSHA256: contract.ContractPayloadSHA256}
	descriptor := runnerDescriptor{Name: runnerName, Version: runnerVersion, ContractSHA256: runnerSHA, ExecutionManifestID: contract.ExecutionGate.ManifestID, ExecutionManifestSHA256: contract.ExecutionGate.ManifestPayloadSHA256}
	receiptValue, receiptBytes, err := materializeReceipt(receiptCore{
		Schema: "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-receipt-v2.schema.json", SchemaVersion: "2.0.0", Canonicalization: canonicalProfile, ReceiptKind: "github_exact_file_set_acquisition_receipt", AuthorityState: "non_authoritative", ReviewState: "unreviewed", CompileEligible: false, PromoteEligible: false, AuthorityBoundary: authorityBoundary{},
		AcquisitionContract: binding, SourceDenominator: contract.SourceDenominator, AcquisitionCapability: contract.AcquisitionCapability, Runner: descriptor, ExecutionGate: contract.ExecutionGate, Bounds: contract.Bounds, Targets: targets, Counts: counts,
	})
	if err != nil {
		return nil, err
	}
	proposalValue, proposalBytes, err := materializeProposal(proposalCoreFor(contract, receiptValue))
	if err != nil {
		return nil, err
	}
	if err := validateReceiptDocument(contract, receiptValue, receiptBytes); err != nil {
		return nil, fmt.Errorf("validate receipt before publication: %w", err)
	}
	if err := validateProposalDocument(contract, receiptValue, proposalValue, proposalBytes); err != nil {
		return nil, fmt.Errorf("validate proposal before publication: %w", err)
	}
	receiptPath, err := store.putReceipt(receiptValue.ReceiptID, receiptBytes)
	if err != nil {
		return nil, fmt.Errorf("publish receipt: %w", err)
	}
	proposalPath, err := store.putProposal(proposalValue.ProposalID, proposalBytes)
	if err != nil {
		return nil, fmt.Errorf("publish proposal: %w", err)
	}
	if err := store.verifyRunSet(receiptPath, receiptBytes, proposalPath, proposalBytes); err != nil {
		return nil, err
	}
	return &runResult{Receipt: receiptValue, ReceiptBytes: receiptBytes, ReceiptPath: receiptPath, Proposal: proposalValue, ProposalBytes: proposalBytes, ProposalPath: proposalPath}, nil
}

func validateMaterializedContract(value acquisitionContract) error {
	rebuilt, raw, err := materializeContract(value.contractCore)
	if err != nil {
		return err
	}
	actual, err := documentJSON(value)
	if err != nil {
		return err
	}
	if value.ContractID != rebuilt.ContractID || value.ContractPayloadSHA256 != rebuilt.ContractPayloadSHA256 || !bytes.Equal(actual, raw) {
		return errors.New("materialized acquisition contract content address or exact bytes are invalid")
	}
	return nil
}

func recoverPublishedRun(contract acquisitionContract, store *casStore) (*runResult, error) {
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
	if err := validatePublishedName(receiptName); err != nil {
		return nil, fmt.Errorf("published receipt filename: %w", err)
	}
	receiptPath := "receipts/" + receiptName
	receiptRaw, err := store.readPublished(receiptPath, maxPublishedJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("read published receipt: %w", err)
	}
	var receiptValue receipt
	if err := unmarshalStrictJSON(receiptRaw, &receiptValue); err != nil {
		return nil, fmt.Errorf("decode published receipt: %w", err)
	}
	if err := validateReceiptDocument(contract, receiptValue, receiptRaw); err != nil {
		return nil, err
	}
	if receiptName != strings.TrimPrefix(receiptValue.ReceiptID, "source-acquisition-receipt:sha256:")+".json" {
		return nil, errors.New("published receipt filename does not match its content address")
	}
	if err := store.verifyTargets(receiptValue.Targets); err != nil {
		return nil, fmt.Errorf("verify recovered receipt CAS: %w", err)
	}
	proposalValue, proposalRaw, err := materializeProposal(proposalCoreFor(contract, receiptValue))
	if err != nil {
		return nil, err
	}
	expectedProposalName := strings.TrimPrefix(proposalValue.ProposalID, "source-inventory-proposal:sha256:") + ".json"
	if len(proposalNames) > 1 || (len(proposalNames) == 1 && proposalNames[0] != expectedProposalName) {
		return nil, errors.New("published inventory proposal recovery is conflicting or ambiguous")
	}
	if len(proposalNames) == 1 {
		if err := validatePublishedName(proposalNames[0]); err != nil {
			return nil, fmt.Errorf("published proposal filename: %w", err)
		}
		existing, err := store.readPublished("inventory-proposals/"+proposalNames[0], maxPublishedJSONBytes)
		if err != nil {
			return nil, fmt.Errorf("read published inventory proposal: %w", err)
		}
		var existingValue inventoryProposal
		if err := unmarshalStrictJSON(existing, &existingValue); err != nil {
			return nil, fmt.Errorf("decode published inventory proposal: %w", err)
		}
		if err := validateProposalDocument(contract, receiptValue, existingValue, existing); err != nil {
			return nil, err
		}
		if !bytes.Equal(existing, proposalRaw) {
			return nil, errors.New("published inventory proposal differs from exact recovered receipt projection")
		}
	}
	receiptPath, err = store.putReceipt(receiptValue.ReceiptID, receiptRaw)
	if err != nil {
		return nil, fmt.Errorf("rehabilitate recovered receipt: %w", err)
	}
	proposalPath, err := store.putProposal(proposalValue.ProposalID, proposalRaw)
	if err != nil {
		return nil, fmt.Errorf("publish recovered inventory proposal: %w", err)
	}
	if err := store.verifyRunSet(receiptPath, receiptRaw, proposalPath, proposalRaw); err != nil {
		return nil, err
	}
	return &runResult{Receipt: receiptValue, ReceiptBytes: receiptRaw, ReceiptPath: receiptPath, Proposal: proposalValue, ProposalBytes: proposalRaw, ProposalPath: proposalPath}, nil
}

func validatePublishedName(name string) error {
	if len(name) != 69 || !strings.HasSuffix(name, ".json") {
		return errors.New("name is not one lowercase SHA-256 plus .json")
	}
	_, err := stripSHA256("sha256:" + strings.TrimSuffix(name, ".json"))
	return err
}

func unmarshalStrictJSON(raw []byte, destination any) error {
	if _, err := parseStrictJSON(raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, destination)
}

func proposalCoreFor(contract acquisitionContract, bound receipt) proposalCore {
	return proposalCore{
		Schema: "https://github.com/cordanaLLM/knowledge/schemas/registry/source-inventory-proposal-v2.schema.json", SchemaVersion: "2.0.0", Canonicalization: canonicalProfile,
		ProposalKind: "exact_source_inventory_proposal", AuthorityState: "non_authoritative", ReviewState: "unreviewed", CompileEligible: false, PromoteEligible: false, AuthorityBoundary: authorityBoundary{},
		AcquisitionContract: contractBinding{ContractID: contract.ContractID, ContractPayloadSHA256: contract.ContractPayloadSHA256},
		AcquisitionReceipt:  receiptBinding{ReceiptID: bound.ReceiptID, ReceiptPayloadSHA256: bound.ReceiptPayloadSHA256}, ExecutionGate: contract.ExecutionGate,
		Targets: bound.Targets, Counts: bound.Counts,
	}
}

func validateReceiptDocument(contract acquisitionContract, value receipt, raw []byte) error {
	rebuilt, rebuiltRaw, err := materializeReceipt(value.receiptCore)
	if err != nil {
		return err
	}
	if value.ReceiptID != rebuilt.ReceiptID || value.ReceiptPayloadSHA256 != rebuilt.ReceiptPayloadSHA256 || !bytes.Equal(raw, rebuiltRaw) {
		return errors.New("receipt content address or exact canonical bytes are invalid")
	}
	runnerSHA, err := runnerContractDigest(contract)
	if err != nil {
		return err
	}
	wantRunner := runnerDescriptor{Name: runnerName, Version: runnerVersion, ContractSHA256: runnerSHA, ExecutionManifestID: contract.ExecutionGate.ManifestID, ExecutionManifestSHA256: contract.ExecutionGate.ManifestPayloadSHA256}
	wantContract := contractBinding{ContractID: contract.ContractID, ContractPayloadSHA256: contract.ContractPayloadSHA256}
	core := value.receiptCore
	if core.Schema != "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-receipt-v2.schema.json" || core.SchemaVersion != "2.0.0" || core.Canonicalization != canonicalProfile || core.ReceiptKind != "github_exact_file_set_acquisition_receipt" {
		return errors.New("receipt schema or kind is invalid")
	}
	if core.AuthorityState != "non_authoritative" || core.ReviewState != "unreviewed" || core.CompileEligible || core.PromoteEligible || core.AuthorityBoundary != (authorityBoundary{}) {
		return errors.New("receipt authority state widened")
	}
	if core.AcquisitionContract != wantContract || core.SourceDenominator != contract.SourceDenominator || core.AcquisitionCapability != contract.AcquisitionCapability || core.Runner != wantRunner || core.ExecutionGate != contract.ExecutionGate || core.Bounds != contract.Bounds {
		return errors.New("receipt contract, runner, or execution lineage is invalid")
	}
	if err := validateInventories(contract, core.Targets); err != nil {
		return err
	}
	if core.Counts.HTTPRequests < 0 || core.Counts.HTTPRequests > contract.Bounds.HTTPRequests || core.Counts != countRun(core.Targets, core.Counts.HTTPRequests) {
		return errors.New("receipt aggregate counts are invalid")
	}
	return nil
}

func validateProposalDocument(contract acquisitionContract, bound receipt, value inventoryProposal, raw []byte) error {
	rebuilt, rebuiltRaw, err := materializeProposal(value.proposalCore)
	if err != nil {
		return err
	}
	if value.ProposalID != rebuilt.ProposalID || value.ProposalPayloadSHA256 != rebuilt.ProposalPayloadSHA256 || !bytes.Equal(raw, rebuiltRaw) {
		return errors.New("proposal content address or exact canonical bytes are invalid")
	}
	want := proposalCoreFor(contract, bound)
	actual, err := canonicalJSON(value.proposalCore)
	if err != nil {
		return err
	}
	expected, err := canonicalJSON(want)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("proposal does not exactly project its validated contract and receipt")
	}
	return nil
}

func (r *runner) acquireTarget(ctx context.Context, target contractTarget, store *casStore) (targetInventory, error) {
	resolved, err := r.resolveRef(ctx, target)
	if err != nil {
		return targetInventory{}, err
	}
	commit, err := r.getCommit(ctx, target.Repository, target.ExpectedCommitSHA1, target.ExpectedRootTreeSHA1)
	if err != nil {
		return targetInventory{}, err
	}
	seenTrees := map[string]struct{}{commit.Tree.SHA: {}}
	files := make([]fileInventory, 0, len(target.Files))
	var logicalBytes int64
	for _, expected := range target.Files {
		bindings, err := r.resolveFile(ctx, target.Repository, commit.Tree.SHA, expected)
		if err != nil {
			return targetInventory{}, fmt.Errorf("resolve %s: %w", expected.Path, err)
		}
		for _, binding := range bindings {
			seenTrees[binding.ParentTreeSHA1] = struct{}{}
			if binding.ObjectType == "tree" {
				seenTrees[binding.ObjectSHA1] = struct{}{}
			}
		}
		raw, err := r.getBlob(ctx, target.Repository, expected)
		if err != nil {
			return targetInventory{}, fmt.Errorf("blob %s: %w", expected.Path, err)
		}
		casPath, err := store.putBlob(expected.RawSHA256, raw)
		if err != nil {
			return targetInventory{}, err
		}
		files = append(files, fileInventory{SourceKey: expected.SourceKey, Path: expected.Path, Mode: expected.Mode, GitBlobSHA1: expected.GitBlobSHA1, RawSHA256: expected.RawSHA256, Bytes: expected.Bytes, CASPath: casPath, PathResolution: bindings})
		logicalBytes += expected.Bytes
	}
	return targetInventory{TargetID: target.TargetID, AuthorityID: target.AuthorityID, SourceSetID: target.SourceSetID, ComponentID: target.ComponentID, ComponentVersion: target.ComponentVersion, Repository: target.Repository, Publisher: target.Publisher, LicenseExpression: target.LicenseExpression, RequestedTag: target.RequestedTag, TagResolution: resolved, ExpectedCommitSHA1: target.ExpectedCommitSHA1, ResolvedCommitSHA1: commit.SHA, CommitTreeSHA1: commit.Tree.SHA, Files: files, Counts: targetCounts{Files: len(files), Trees: len(seenTrees), LogicalBytes: logicalBytes}}, nil
}

// resolveRef dispatches on the target's ref kind: a "branch" target resolves the
// branch HEAD ref directly to a commit; absent or "tag" resolves the tag ref and
// annotated-tag chain unchanged.
func (r *runner) resolveRef(ctx context.Context, target contractTarget) (tagResolution, error) {
	if target.RefKind == "branch" {
		return r.resolveBranch(ctx, target)
	}
	return r.resolveTag(ctx, target)
}

// resolveBranch resolves a branch-head ref through the SAME redirect-banned
// client. A branch carries no annotated-tag chain, so the contract must bind the
// commit directly (expected_ref_object_type "commit", empty chain,
// expected_ref_object_sha1 == expected_commit_sha1); the live head ref must
// point at exactly that commit.
func (r *runner) resolveBranch(ctx context.Context, target contractTarget) (tagResolution, error) {
	if !validBranchName(target.RequestedTag) {
		return tagResolution{}, errors.New("branch is outside the exact syntax")
	}
	if target.ExpectedRefType != "commit" || len(target.ExpectedTagObjects) != 0 || target.ExpectedRefSHA1 != target.ExpectedCommitSHA1 {
		return tagResolution{}, errors.New("branch target must bind the commit directly with no tag chain")
	}
	var reference gitRef
	if err := r.getJSON(ctx, target.Repository, "/git/ref/heads/"+url.PathEscape(target.RequestedTag), &reference); err != nil {
		return tagResolution{}, fmt.Errorf("get exact branch ref: %w", err)
	}
	if reference.Ref != expectedRefName(target) || reference.Object.Type != target.ExpectedRefType || reference.Object.SHA != target.ExpectedRefSHA1 {
		return tagResolution{}, errors.New("branch ref drifted from the exact object binding")
	}
	if reference.Object.Type != "commit" || reference.Object.SHA != target.ExpectedCommitSHA1 {
		return tagResolution{}, errors.New("branch ref does not resolve to the exact commit")
	}
	return tagResolution{Ref: reference.Ref, InitialObjectType: reference.Object.Type, InitialObjectSHA1: reference.Object.SHA, AnnotatedTagObjects: []expectedTagObject{}, ResolvedCommitSHA1: reference.Object.SHA}, nil
}

// expectedRefName returns the fully-qualified ref the resolver must observe:
// refs/heads/<branch> for a branch target, refs/tags/<tag> otherwise.
func expectedRefName(target contractTarget) string {
	if target.RefKind == "branch" {
		return "refs/heads/" + target.RequestedTag
	}
	return "refs/tags/" + target.RequestedTag
}

func (r *runner) resolveTag(ctx context.Context, target contractTarget) (tagResolution, error) {
	if !tagPattern.MatchString(target.RequestedTag) {
		return tagResolution{}, errors.New("tag is outside the exact syntax")
	}
	var reference gitRef
	if err := r.getJSON(ctx, target.Repository, "/git/ref/tags/"+url.PathEscape(target.RequestedTag), &reference); err != nil {
		return tagResolution{}, fmt.Errorf("get exact tag ref: %w", err)
	}
	if reference.Ref != "refs/tags/"+target.RequestedTag || reference.Object.Type != target.ExpectedRefType || reference.Object.SHA != target.ExpectedRefSHA1 {
		return tagResolution{}, errors.New("tag ref drifted from the exact object binding")
	}
	result := tagResolution{Ref: reference.Ref, InitialObjectType: reference.Object.Type, InitialObjectSHA1: reference.Object.SHA, AnnotatedTagObjects: []expectedTagObject{}}
	current := reference.Object
	for index, expected := range target.ExpectedTagObjects {
		if current.Type != "tag" || current.SHA != expected.SHA1 {
			return tagResolution{}, errors.New("annotated tag chain differs from the exact contract")
		}
		var annotated gitTag
		if err := r.getJSON(ctx, target.Repository, "/git/tags/"+current.SHA, &annotated); err != nil {
			return tagResolution{}, err
		}
		actual := expectedTagObject{SHA1: annotated.SHA, Name: annotated.Tag, TargetType: annotated.Object.Type, TargetSHA1: annotated.Object.SHA}
		if actual != expected || (index == 0 && actual.Name != target.RequestedTag) {
			return tagResolution{}, errors.New("annotated tag object drifted from the exact contract")
		}
		result.AnnotatedTagObjects = append(result.AnnotatedTagObjects, actual)
		current = annotated.Object
	}
	if current.Type != "commit" || current.SHA != target.ExpectedCommitSHA1 {
		return tagResolution{}, errors.New("tag does not terminate at the exact commit")
	}
	result.ResolvedCommitSHA1 = current.SHA
	return result, nil
}

func (r *runner) getCommit(ctx context.Context, repository, commitSHA, treeSHA string) (gitCommit, error) {
	var commit gitCommit
	if err := r.getJSON(ctx, repository, "/git/commits/"+commitSHA, &commit); err != nil {
		return gitCommit{}, err
	}
	if commit.SHA != commitSHA || commit.Tree.SHA != treeSHA {
		return gitCommit{}, errors.New("commit or root tree drifted from the exact contract")
	}
	return commit, nil
}

func (r *runner) resolveFile(ctx context.Context, repository, rootTree string, expected contractFile) ([]pathBinding, error) {
	if err := validatePath(expected.Path); err != nil {
		return nil, err
	}
	segments := strings.Split(expected.Path, "/")
	current := rootTree
	bindings := make([]pathBinding, 0, len(segments))
	seenTrees := map[string]struct{}{rootTree: {}}
	for index, segment := range segments {
		tree, err := r.getTree(ctx, repository, current)
		if err != nil {
			return nil, err
		}
		entry, err := exactTreeEntry(tree.Tree, segment)
		if err != nil {
			return nil, err
		}
		last := index == len(segments)-1
		if !last {
			if entry.Type != "tree" || entry.Mode != "040000" || entry.Size != nil {
				return nil, errors.New("exact path segment is not a Git tree")
			}
			if _, exists := seenTrees[entry.SHA]; exists {
				return nil, errors.New("tree cycle in exact source path")
			}
			seenTrees[entry.SHA] = struct{}{}
			bindings = append(bindings, pathBinding{ParentTreeSHA1: current, Segment: segment, ObjectType: entry.Type, Mode: entry.Mode, ObjectSHA1: entry.SHA})
			current = entry.SHA
			continue
		}
		if entry.Type != "blob" || entry.Mode != expected.Mode || entry.SHA != expected.GitBlobSHA1 || entry.Size == nil || *entry.Size != expected.Bytes {
			return nil, errors.New("exact file path, mode, blob, or size drifted")
		}
		bindings = append(bindings, pathBinding{ParentTreeSHA1: current, Segment: segment, ObjectType: entry.Type, Mode: entry.Mode, ObjectSHA1: entry.SHA, Bytes: entry.Size})
	}
	if !equalPathBindings(bindings, expected.ExpectedPathResolution) {
		return nil, errors.New("exact path tree chain drifted from the contract")
	}
	return bindings, nil
}

func (r *runner) getTree(ctx context.Context, repository, sha string) (gitTree, error) {
	key := repository + ":" + sha
	if cached, ok := r.treeCache[key]; ok {
		return cached, nil
	}
	var tree gitTree
	if err := r.getJSON(ctx, repository, "/git/trees/"+sha, &tree); err != nil {
		return gitTree{}, err
	}
	if tree.SHA != sha || tree.Truncated == nil || *tree.Truncated || len(tree.Tree) > 8192 {
		return gitTree{}, errors.New("tree response is swapped, truncated, or over-bound")
	}
	if _, err := exactTreeEntry(tree.Tree, "__archeion_nonexistent_probe__"); err != nil && !strings.Contains(err.Error(), "no exact requested child") {
		return gitTree{}, err
	}
	r.treeCache[key] = tree
	return tree, nil
}

func (r *runner) getBlob(ctx context.Context, repository string, expected contractFile) ([]byte, error) {
	key := repository + ":" + expected.GitBlobSHA1
	if cached, ok := r.blobCache[key]; ok {
		return cached, nil
	}
	var blob gitBlob
	if err := r.getJSON(ctx, repository, "/git/blobs/"+expected.GitBlobSHA1, &blob); err != nil {
		return nil, err
	}
	if blob.SHA != expected.GitBlobSHA1 || blob.Size == nil || *blob.Size != expected.Bytes || blob.Encoding != "base64" {
		return nil, errors.New("blob response identity, encoding, or size drifted")
	}
	compact := strings.NewReplacer("\n", "", "\r", "").Replace(blob.Content)
	raw, err := base64.StdEncoding.Strict().DecodeString(compact)
	if err != nil {
		return nil, errors.New("blob content is not strict base64")
	}
	if int64(len(raw)) != expected.Bytes {
		return nil, errors.New("decoded blob size drifted")
	}
	identity := append([]byte("blob "+strconv.Itoa(len(raw))+"\x00"), raw...)
	gitDigest := sha1.Sum(identity)
	if hex.EncodeToString(gitDigest[:]) != expected.GitBlobSHA1 {
		return nil, errors.New("decoded blob does not reproduce the exact Git SHA-1")
	}
	rawDigest := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(rawDigest[:]) != expected.RawSHA256 {
		return nil, errors.New("decoded blob raw SHA-256 drifted")
	}
	r.blobCache[key] = raw
	return raw, nil
}

func (r *runner) getJSON(ctx context.Context, repository, suffix string, destination any) error {
	if _, ok := r.allowedRepos[repository]; !ok {
		return errors.New("repository is outside the exact three-source denominator")
	}
	if r.requests >= maxHTTPRequests || !strings.HasPrefix(suffix, "/git/") || strings.ContainsAny(suffix, "?#") {
		return errors.New("HTTP request is outside the exact capability")
	}
	endpoint := r.baseURL.String() + "/repos/" + repository + suffix
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	request.Header.Set("User-Agent", "archeion-source-acquisition-runner-v3/"+runnerVersion)
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
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("GitHub REST returned HTTP %d", response.StatusCode)
	}
	if response.Request == nil || response.Request.URL.String() != endpoint {
		return errors.New("Git-object response arrived through a redirected or changed endpoint")
	}
	if len(response.Header.Values("Link")) != 0 {
		return errors.New("Git-object endpoint returned a pagination Link header")
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
	remaining := maxResponseBytes - r.responseBytes
	if remaining <= 0 {
		return errors.New("HTTP response byte bound exceeded")
	}
	limit := maxObjectJSONBytes
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
	if _, err := parseStrictJSON(raw); err != nil {
		return fmt.Errorf("strict Git-object JSON: %w", err)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return err
	}
	return nil
}

func exactTreeEntry(entries []gitTreeEntry, name string) (gitTreeEntry, error) {
	seen := make(map[string]struct{}, len(entries))
	var match *gitTreeEntry
	for index := range entries {
		entry := entries[index]
		if entry.Path == "" || entry.Path == "." || entry.Path == ".." || strings.ContainsAny(entry.Path, "/\x00\r\n") || !utf8.ValidString(entry.Path) || !sha1Pattern.MatchString(entry.SHA) {
			return gitTreeEntry{}, errors.New("tree contains a noncanonical entry")
		}
		if _, ok := seen[entry.Path]; ok {
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
	return *match, nil
}

func materializeReceipt(core receiptCore) (receipt, []byte, error) {
	payload, err := canonicalJSON(core)
	if err != nil {
		return receipt{}, nil, err
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := receipt{ReceiptID: "source-acquisition-receipt:" + payloadSHA, ReceiptPayloadSHA256: payloadSHA, receiptCore: core}
	document, err := documentJSON(value)
	return value, document, err
}

func materializeProposal(core proposalCore) (inventoryProposal, []byte, error) {
	payload, err := canonicalJSON(core)
	if err != nil {
		return inventoryProposal{}, nil, err
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := inventoryProposal{ProposalID: "source-inventory-proposal:" + payloadSHA, ProposalPayloadSHA256: payloadSHA, proposalCore: core}
	document, err := documentJSON(value)
	return value, document, err
}

func countRun(targets []targetInventory, requests int) runCounts {
	objects := map[string]int64{}
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

func validateInventories(contract acquisitionContract, values []targetInventory) error {
	if len(values) != len(contract.Targets) {
		return errors.New("inventory target cardinality differs from contract")
	}
	for index, value := range values {
		expected := contract.Targets[index]
		if value.TargetID != expected.TargetID || value.AuthorityID != expected.AuthorityID || value.SourceSetID != expected.SourceSetID || value.ComponentID != expected.ComponentID || value.ComponentVersion != expected.ComponentVersion || value.Repository != expected.Repository || value.Publisher != expected.Publisher || value.LicenseExpression != expected.LicenseExpression || value.RequestedTag != expected.RequestedTag || value.ExpectedCommitSHA1 != expected.ExpectedCommitSHA1 || value.ResolvedCommitSHA1 != expected.ExpectedCommitSHA1 || value.CommitTreeSHA1 != expected.ExpectedRootTreeSHA1 || len(value.Files) != len(expected.Files) {
			return errors.New("inventory authority, source set, publisher, commit, or file scope drifted")
		}
		if err := validateTagResolution(value.TagResolution, expected); err != nil {
			return err
		}
		seenTrees := map[string]struct{}{expected.ExpectedRootTreeSHA1: {}}
		var logicalBytes int64
		for fileIndex, file := range value.Files {
			want := expected.Files[fileIndex]
			hexDigest, err := stripSHA256(want.RawSHA256)
			if err != nil {
				return err
			}
			wantCASPath := "cas/sha256/" + hexDigest[:2] + "/" + hexDigest
			if file.SourceKey != want.SourceKey || file.Path != want.Path || file.Mode != want.Mode || file.GitBlobSHA1 != want.GitBlobSHA1 || file.RawSHA256 != want.RawSHA256 || file.Bytes != want.Bytes || file.CASPath != wantCASPath || len(file.PathResolution) != len(strings.Split(file.Path, "/")) {
				return errors.New("inventory file differs from exact contract")
			}
			if err := validatePathResolution(file.PathResolution, want, expected.ExpectedRootTreeSHA1, seenTrees); err != nil {
				return err
			}
			logicalBytes += file.Bytes
		}
		if value.Counts.Files != len(value.Files) || value.Counts.Trees != len(seenTrees) || value.Counts.LogicalBytes != logicalBytes {
			return errors.New("inventory target counts differ from verified files and trees")
		}
	}
	counts := countRun(values, 1)
	uniqueObjects, uniqueBytes := contractUniqueObjects(contract)
	if counts.Targets != contract.Bounds.Targets || counts.Files != contract.Bounds.Files || counts.LogicalBytes != contract.Bounds.LogicalBytes || counts.UniqueCASObjects != uniqueObjects || counts.UniqueCASBytes != uniqueBytes {
		return errors.New("inventory denominator differs from the contract's declared bounds")
	}
	return nil
}

// contractUniqueObjects returns the number of distinct content-addressed blobs
// the contract declares and their total logical bytes, deduplicated by raw
// SHA-256 so a contract that legitimately reuses a blob across paths does not
// over-count its CAS denominator.
func contractUniqueObjects(contract acquisitionContract) (int, int64) {
	objects := map[string]int64{}
	for _, target := range contract.Targets {
		for _, file := range target.Files {
			objects[file.RawSHA256] = file.Bytes
		}
	}
	var bytesTotal int64
	for _, size := range objects {
		bytesTotal += size
	}
	return len(objects), bytesTotal
}

func validateTagResolution(value tagResolution, expected contractTarget) error {
	if value.Ref != expectedRefName(expected) || value.InitialObjectType != expected.ExpectedRefType || value.InitialObjectSHA1 != expected.ExpectedRefSHA1 || value.ResolvedCommitSHA1 != expected.ExpectedCommitSHA1 || len(value.AnnotatedTagObjects) != len(expected.ExpectedTagObjects) {
		return errors.New("inventory tag resolution differs from exact contract")
	}
	for index, actual := range value.AnnotatedTagObjects {
		if actual != expected.ExpectedTagObjects[index] {
			return errors.New("inventory annotated tag object differs from exact contract")
		}
	}
	return nil
}

func validatePathResolution(values []pathBinding, expected contractFile, rootTree string, seenTrees map[string]struct{}) error {
	segments := strings.Split(expected.Path, "/")
	if len(values) != len(segments) {
		return errors.New("inventory path resolution cardinality differs from exact path")
	}
	current := rootTree
	pathTrees := map[string]struct{}{rootTree: {}}
	for index, value := range values {
		if value.ParentTreeSHA1 != current || value.Segment != segments[index] || !sha1Pattern.MatchString(value.ObjectSHA1) {
			return errors.New("inventory path resolution is disconnected or noncanonical")
		}
		seenTrees[value.ParentTreeSHA1] = struct{}{}
		last := index == len(values)-1
		if !last {
			if value.ObjectType != "tree" || value.Mode != "040000" || value.Bytes != nil {
				return errors.New("inventory intermediate path binding is not an exact tree")
			}
			if _, exists := pathTrees[value.ObjectSHA1]; exists {
				return errors.New("inventory path resolution contains a tree cycle")
			}
			pathTrees[value.ObjectSHA1] = struct{}{}
			seenTrees[value.ObjectSHA1] = struct{}{}
			current = value.ObjectSHA1
			continue
		}
		if value.ObjectType != "blob" || value.Mode != expected.Mode || value.ObjectSHA1 != expected.GitBlobSHA1 || value.Bytes == nil || *value.Bytes != expected.Bytes {
			return errors.New("inventory terminal path binding differs from exact blob")
		}
	}
	if !equalPathBindings(values, expected.ExpectedPathResolution) {
		return errors.New("inventory path resolution differs from exact contract tree chain")
	}
	return nil
}

func equalPathBindings(left, right []pathBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ParentTreeSHA1 != right[index].ParentTreeSHA1 || left[index].Segment != right[index].Segment || left[index].ObjectType != right[index].ObjectType || left[index].Mode != right[index].Mode || left[index].ObjectSHA1 != right[index].ObjectSHA1 {
			return false
		}
		if (left[index].Bytes == nil) != (right[index].Bytes == nil) || (left[index].Bytes != nil && *left[index].Bytes != *right[index].Bytes) {
			return false
		}
	}
	return true
}
