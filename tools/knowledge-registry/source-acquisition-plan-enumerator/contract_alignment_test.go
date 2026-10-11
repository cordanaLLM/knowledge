package main

// Cross-module alignment proof: the enumerator must emit the EXACT canonical
// contract the sibling source-acquisition-runner-v3 consumes. The runner is the
// authority; every expected value here is quoted from its source and must not be
// changed to make a test pass:
//   - schema / version / kind / states: source-acquisition-runner-v3/contract.go:26-28,263,271
//   - reviewed capability:              source-acquisition-runner-v3/contract.go:52-60
//   - execution gate id + payload sha:  source-acquisition-runner-v3/execution-manifest.json
//   - gate shape:                       source-acquisition-runner-v3/execution_manifest.go:115-125
//
// runnerValidateContract is a faithful copy of the runner's validateContract
// (contract.go:262-364); a failure here means the real runner would reject the
// emitted document with the same error.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// Spec inputs shared by the enumerator fixtures. The execution-manifest values
// are the runner's embedded manifest (execution-manifest.json); supplying any
// other value makes the runner reject the emitted execution gate.
const (
	fixtureExecutionManifestID  = "source-acquisition-execution-manifest:sha256:77408c9e73350efb068c17863b2282ce1db44c2d9ca3075e26bcff7149241690"
	fixtureExecutionManifestSHA = "sha256:77408c9e73350efb068c17863b2282ce1db44c2d9ca3075e26bcff7149241690"
	fixtureFreezeID             = "retrieval-evaluation-freeze:acme:v1.2.3"

	// Quoted from source-acquisition-runner-v3/contract.go.
	runnerContractSchema        = "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-contract-v2.schema.json"
	runnerContractSchemaVersion = "2.0.0"
	runnerContractKind          = "source_file_set_acquisition_v2"
	runnerCanonicalProfile      = "registry_compact_utf8"
	runnerReviewState           = "implementation_frozen"
	runnerAuthorityState        = "non_authoritative"

	// Quoted from source-acquisition-runner-v3/contract.go bounds validators.
	runnerMaxAnnotatedTagDepth = 16
	runnerMaxPathDepth         = 16
	runnerMaxTreeEntries       = 8192
	runnerMaxBlobBytes         = int64(1024 * 1024)
	runnerMaxHTTPRequests      = 128
	runnerMaxResponseBytes     = int64(32 * 1024 * 1024)
	runnerMaxObjectJSONBytes   = int64(4 * 1024 * 1024)
)

var fixtureFreezeDocumentSHA256 = testSHA256Prefixed([]byte("retrieval-evaluation-freeze-document:acme:v1.2.3"))

func testSHA256Prefixed(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// runnerReviewedCapabilities mirrors the runner's allowlist entry verbatim.
var runnerReviewedCapabilities = map[string]acquisitionCapability{
	"github-git-objects-rest-exact-file-v2": {
		CapabilityID:   "github-git-objects-rest-exact-file-v2",
		Transport:      "https-json",
		APIOrigin:      "https://api.github.com",
		APIVersion:     "2026-03-10",
		ObjectFormat:   "sha1",
		SelectionMode:  "exact_paths_only",
		RedirectPolicy: "forbid",
	},
}

// runnerExactExecutionGate mirrors exactExecutionGateBinding() bound to the
// runner's embedded execution manifest.
func runnerExactExecutionGate() executionGate {
	return executionGate{
		ManifestID:                   fixtureExecutionManifestID,
		ManifestPayloadSHA256:        fixtureExecutionManifestSHA,
		VerificationState:            "external_exact_byte_verification_required",
		ExternalVerificationRequired: true,
		Verified:                     false,
		PredecessorEligible:          false,
	}
}

func runnerValidWorkID(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value
}

func runnerValidateBounds(b contractBounds) error {
	if b.Targets <= 0 || b.Files <= 0 || b.Files < b.Targets || b.LogicalBytes < 0 {
		return errors.New("contract bounds cardinality is nonpositive or inconsistent")
	}
	if b.AnnotatedTagDepth < 0 || b.AnnotatedTagDepth > runnerMaxAnnotatedTagDepth {
		return errors.New("contract annotated-tag-depth bound is out of range")
	}
	if b.PathDepth <= 0 || b.PathDepth > runnerMaxPathDepth {
		return errors.New("contract path-depth bound is out of range")
	}
	if b.TreeEntries <= 0 || b.TreeEntries > runnerMaxTreeEntries {
		return errors.New("contract tree-entries bound is out of range")
	}
	if b.BlobBytes <= 0 || b.BlobBytes > runnerMaxBlobBytes {
		return errors.New("contract blob-bytes bound is out of range")
	}
	if b.HTTPRequests <= 0 || b.HTTPRequests > runnerMaxHTTPRequests {
		return errors.New("contract http-requests bound is out of range")
	}
	if b.HTTPResponseBytes <= 0 || b.HTTPResponseBytes > runnerMaxResponseBytes {
		return errors.New("contract http-response-bytes bound is out of range")
	}
	if b.ObjectJSONBytes <= 0 || b.ObjectJSONBytes > runnerMaxObjectJSONBytes {
		return errors.New("contract object-json-bytes bound is out of range")
	}
	return nil
}

// runnerValidateContract is a faithful copy of the runner's validateContract. It
// operates on the enumerator's planCore, which is structurally identical to the
// runner's contractCore, so passing here proves the emitted document is admitted
// by the real runner.
func runnerValidateContract(value planCore) error {
	if value.Schema != runnerContractSchema || value.SchemaVersion != runnerContractSchemaVersion || value.Canonicalization != runnerCanonicalProfile || value.ContractKind != runnerContractKind {
		return errors.New("contract schema, version, or kind differs from the generalized acquisition format")
	}
	if !runnerValidWorkID(value.WorkID) {
		return errors.New("contract work identity is malformed")
	}
	if value.AuthorityState != runnerAuthorityState || value.ReviewState != runnerReviewState || value.CompileEligible || value.PromoteEligible || value.AuthorityBoundary != (authorityBoundary{}) {
		return errors.New("contract authority state widened")
	}
	if !value.SourceDenominator.ComparisonOnly || !validSHA256(value.SourceDenominator.FreezeDocumentSHA256) || value.SourceDenominator.FreezeID == "" || len(value.SourceDenominator.FreezeID) > 512 || !utf8.ValidString(value.SourceDenominator.FreezeID) {
		return errors.New("contract source denominator is not a comparison-only freeze")
	}
	reviewed, ok := runnerReviewedCapabilities[value.AcquisitionCapability.CapabilityID]
	if !ok || value.AcquisitionCapability != reviewed {
		return errors.New("contract acquisition capability is not in the reviewed allowlist")
	}
	if value.ExecutionGate != runnerExactExecutionGate() {
		return errors.New("contract execution verifier gate changed or widened")
	}
	if err := runnerValidateBounds(value.Bounds); err != nil {
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
		targetCoreBytes, canonErr := canonicalJSON(target.contractTargetCore)
		if canonErr != nil {
			return errors.New("contract target core is not canonicalizable")
		}
		targetDigest := sha256.Sum256(targetCoreBytes)
		if target.TargetID != "source-acquisition-target:sha256:"+hex.EncodeToString(targetDigest[:]) {
			return errors.New("contract target id does not content-address its core")
		}
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
	if fileCount != value.Bounds.Files || len(seenFiles) != value.Bounds.Files {
		return errors.New("contract file count differs from declared bounds")
	}
	if bytesTotal != value.Bounds.LogicalBytes {
		return errors.New("contract logical-byte sum differs from declared bounds")
	}
	return nil
}

func TestEnumeratorConstantsMatchRunnerContract(t *testing.T) {
	if contractSchema != runnerContractSchema {
		t.Errorf("$schema = %q, want runner %q", contractSchema, runnerContractSchema)
	}
	if contractSchemaVersion != runnerContractSchemaVersion {
		t.Errorf("schema_version = %q, want %q", contractSchemaVersion, runnerContractSchemaVersion)
	}
	if contractKind != runnerContractKind {
		t.Errorf("contract_kind = %q, want %q", contractKind, runnerContractKind)
	}
	if canonicalProfile != runnerCanonicalProfile {
		t.Errorf("canonicalization = %q, want %q", canonicalProfile, runnerCanonicalProfile)
	}
	if contractReviewState != runnerReviewState {
		t.Errorf("review_state = %q, want %q", contractReviewState, runnerReviewState)
	}
	if contractAuthorityState != runnerAuthorityState {
		t.Errorf("authority_state = %q, want %q", contractAuthorityState, runnerAuthorityState)
	}
	if contractIDPrefix != "source-acquisition-contract:sha256:" {
		t.Errorf("contract id prefix = %q, want %q", contractIDPrefix, "source-acquisition-contract:sha256:")
	}
	want := runnerReviewedCapabilities["github-git-objects-rest-exact-file-v2"]
	if planCapability() != want {
		t.Fatalf("planCapability() = %+v, want runner reviewed entry %+v", planCapability(), want)
	}
}

func TestEmittedContractPassesRunnerValidation(t *testing.T) {
	repository, tag := "acme/widgets", "v1.2.3"
	fixture, commit, _ := buildAnnotatedFixture(t, repository, tag, sampleFiles())
	request := sampleRequest(repository, tag, commit)
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	contract, document, err := enum.enumerate(context.Background(), request)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	// The emitted document must decode into the runner's contractCore shape.
	var decoded acquisitionPlan
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("emitted document does not decode into the contract shape: %v", err)
	}
	if decoded.ContractID != contract.ContractID || decoded.ContractPayloadSHA256 != contract.ContractPayloadSHA256 {
		t.Fatal("decoded contract identity drifted from the emitted contract")
	}
	// And it must pass a faithful copy of the runner's validateContract.
	if err := runnerValidateContract(decoded.planCore); err != nil {
		t.Fatalf("emitted contract failed the runner's validateContract copy: %v", err)
	}
	// The two newly-wired fields must land at the runner's exact values.
	if decoded.ExecutionGate != runnerExactExecutionGate() {
		t.Fatalf("execution gate = %+v, want %+v", decoded.ExecutionGate, runnerExactExecutionGate())
	}
	if !decoded.SourceDenominator.ComparisonOnly || decoded.SourceDenominator.FreezeID != fixtureFreezeID || decoded.SourceDenominator.FreezeDocumentSHA256 != fixtureFreezeDocumentSHA256 {
		t.Fatalf("source denominator drifted: %+v", decoded.SourceDenominator)
	}
}

// TestBranchContractPassesRunnerValidation proves a branch-ref contract is
// admitted by the runner's validateContract copy AND that its content addresses
// (contract_id + every target_id) round-trip with ref_kind folded into the core.
func TestBranchContractPassesRunnerValidation(t *testing.T) {
	repository, branch := "acme/untagged", "main"
	fixture, commit, _ := buildBranchFixture(t, repository, branch, sampleFiles())
	request := sampleBranchRequest(repository, branch, commit)
	enum, server := fixtureEnumerator(t, fixture, request)
	defer server.Close()
	contract, document, err := enum.enumerate(context.Background(), request)
	if err != nil {
		t.Fatalf("enumerate branch: %v", err)
	}
	var decoded acquisitionPlan
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("emitted branch document does not decode into the contract shape: %v", err)
	}
	if decoded.ContractID != contract.ContractID || decoded.ContractPayloadSHA256 != contract.ContractPayloadSHA256 {
		t.Fatal("decoded branch contract identity drifted from the emitted contract")
	}
	// contract_id self-address must round-trip with ref_kind included in the core.
	payload, err := canonicalJSON(decoded.planCore)
	if err != nil {
		t.Fatalf("canonical branch core: %v", err)
	}
	digest := sha256.Sum256(payload)
	if decoded.ContractID != contractIDPrefix+hex.EncodeToString(digest[:]) {
		t.Fatal("branch contract id does not content-address its core")
	}
	// runnerValidateContract recomputes and checks every target_id self-address.
	if err := runnerValidateContract(decoded.planCore); err != nil {
		t.Fatalf("emitted branch contract failed the runner's validateContract copy: %v", err)
	}
	target := decoded.Targets[0]
	if target.RefKind != "branch" || target.ExpectedRefType != "commit" || len(target.ExpectedTagObjects) != 0 || target.ExpectedRefSHA1 != commit {
		t.Fatalf("decoded branch ref binding drifted: %+v", target)
	}
}
