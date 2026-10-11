package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testRootTreeSHA1 = "1111111111111111111111111111111111111111"
	testSubTreeSHA1  = "2222222222222222222222222222222222222222"
	testBlobSHA1     = "3333333333333333333333333333333333333333"
	testCommitSHA1   = "4444444444444444444444444444444444444444"
)

// ---- helpers ---------------------------------------------------------------

func sha256Of(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func int64Ptr(v int64) *int64 { return &v }

// validContractCore builds a tiny, internally-consistent one-target/one-file
// contract that passes validateContract.
func validContractCore(t *testing.T) contractCore {
	t.Helper()
	gate, err := exactExecutionGateBinding()
	if err != nil {
		t.Fatalf("execution gate binding: %v", err)
	}
	const blobBytes = int64(11)
	file := contractFile{
		SourceKey:   "test-doc",
		Path:        "docs/readme.txt",
		Mode:        "100644",
		GitBlobSHA1: testBlobSHA1,
		RawSHA256:   sha256Of([]byte("hello world")),
		Bytes:       blobBytes,
		ExpectedPathResolution: []pathBinding{
			{ParentTreeSHA1: testRootTreeSHA1, Segment: "docs", ObjectType: "tree", Mode: "040000", ObjectSHA1: testSubTreeSHA1},
			{ParentTreeSHA1: testSubTreeSHA1, Segment: "readme.txt", ObjectType: "blob", Mode: "100644", ObjectSHA1: testBlobSHA1, Bytes: int64Ptr(blobBytes)},
		},
	}
	targetCore := contractTargetCore{
		AuthorityID:          "retrieval-source-authority:test:v1.0.0",
		SourceSetID:          "source-acquisition-set:test:v1.0.0",
		ComponentID:          "test",
		ComponentVersion:     "v1.0.0",
		Repository:           "example/test",
		Publisher:            publisher{PublisherID: "publisher:github:example", Name: "Example", URI: "https://github.com/example"},
		LicenseExpression:    "Apache-2.0",
		RequestedTag:         "v1.0.0",
		ExpectedRefType:      "commit",
		ExpectedRefSHA1:      testCommitSHA1,
		ExpectedTagObjects:   []expectedTagObject{},
		ExpectedCommitSHA1:   testCommitSHA1,
		ExpectedRootTreeSHA1: testRootTreeSHA1,
		Files:                []contractFile{file},
	}
	targetCoreBytes, err := canonicalJSON(targetCore)
	if err != nil {
		t.Fatalf("canonical target core: %v", err)
	}
	targetDigest := sha256.Sum256(targetCoreBytes)
	target := contractTarget{
		TargetID:           "source-acquisition-target:sha256:" + hex.EncodeToString(targetDigest[:]),
		contractTargetCore: targetCore,
	}
	return contractCore{
		Schema:                contractSchema,
		SchemaVersion:         contractSchemaVersion,
		Canonicalization:      canonicalProfile,
		ContractKind:          contractKind,
		WorkID:                "TEST-SRC-V3",
		AuthorityState:        "non_authoritative",
		ReviewState:           "implementation_frozen",
		CompileEligible:       false,
		PromoteEligible:       false,
		AuthorityBoundary:     authorityBoundary{},
		SourceDenominator:     sourceDenominator{FreezeID: "retrieval-evaluation-freeze:test", FreezeDocumentSHA256: sha256Of([]byte("freeze")), ComparisonOnly: true},
		AcquisitionCapability: reviewedCapabilities["github-git-objects-rest-exact-file-v2"],
		ExecutionGate:         gate,
		Bounds: contractBounds{
			Targets: 1, Files: 1, LogicalBytes: blobBytes, AnnotatedTagDepth: 0, PathDepth: 2,
			TreeEntries: maxTreeEntries, BlobBytes: maxBlobBytes, HTTPRequests: maxHTTPRequests,
			HTTPResponseBytes: maxResponseBytes, ObjectJSONBytes: maxObjectJSONBytes,
		},
		Targets: []contractTarget{target},
	}
}

// selfAddressDocument content-addresses a core WITHOUT running validateContract,
// so tests can craft self-consistent-but-invalid plans.
func selfAddressDocument(t *testing.T, core contractCore) []byte {
	t.Helper()
	payload, err := canonicalJSON(core)
	if err != nil {
		t.Fatalf("canonical core: %v", err)
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := acquisitionContract{ContractID: "source-acquisition-contract:" + payloadSHA, ContractPayloadSHA256: payloadSHA, contractCore: core}
	document, err := documentJSON(value)
	if err != nil {
		t.Fatalf("document json: %v", err)
	}
	return document
}

// signingIdentity generates a throwaway Ed25519 key and returns its key path
// plus an allowed_signers policy authorizing `principal`.
func signingIdentity(t *testing.T, principal string) (keyPath string, allowedSigners []byte) {
	t.Helper()
	if _, err := os.Stat(sshKeygenPath); err != nil {
		t.Skipf("ssh-keygen unavailable: %v", err)
	}
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "signer")
	cmd := exec.Command(sshKeygenPath, "-t", "ed25519", "-N", "", "-C", principal, "-f", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate key: %v: %s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		t.Fatalf("malformed public key: %q", pub)
	}
	line := principal + " " + fields[0] + " " + fields[1] + "\n"
	return keyPath, []byte(line)
}

// signDetached produces a detached armored SSHSIG over exactly `document`.
func signDetached(t *testing.T, keyPath, namespace string, document []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	docPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(docPath, document, 0o600); err != nil {
		t.Fatalf("write document: %v", err)
	}
	cmd := exec.Command(sshKeygenPath, "-Y", "sign", "-q", "-f", keyPath, "-n", namespace, docPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sign: %v: %s", err, out)
	}
	sig, err := os.ReadFile(docPath + ".sig")
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	return sig
}

// ---- positive roundtrip ----------------------------------------------------

func TestSignedPlanRoundtripAccepts(t *testing.T) {
	core := validContractCore(t)
	contract, document, err := materializeContract(core)
	if err != nil {
		t.Fatalf("materialize valid contract: %v", err)
	}
	keyPath, allowed := signingIdentity(t, planSignerPrincipal)
	signature := signDetached(t, keyPath, planSignatureNamespace, document)

	if err := verifyPlanSignature(document, signature, allowed); err != nil {
		t.Fatalf("valid signed plan was rejected: %v", err)
	}
	loaded, loadedDoc, err := loadContractBytes(document)
	if err != nil {
		t.Fatalf("load valid plan: %v", err)
	}
	if loaded.ContractID != contract.ContractID {
		t.Fatalf("loaded contract id %q != %q", loaded.ContractID, contract.ContractID)
	}
	if !bytes.Equal(loadedDoc, document) {
		t.Fatal("loaded canonical document is not byte-identical")
	}
}

// ---- fail-closed negatives -------------------------------------------------

func TestUnsignedPlanRejected(t *testing.T) {
	core := validContractCore(t)
	_, document, err := materializeContract(core)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	keyPath, _ := signingIdentity(t, planSignerPrincipal)
	// Trust a DIFFERENT principal's policy than the key that signs — the key is
	// not authorized, so verification must fail closed.
	_, foreignAllowed := signingIdentity(t, planSignerPrincipal)
	signature := signDetached(t, keyPath, planSignatureNamespace, document)
	if err := verifyPlanSignature(document, signature, foreignAllowed); err == nil {
		t.Fatal("plan signed by an unauthorized key was accepted")
	}
	// A non-SSHSIG blob is rejected before ssh-keygen runs.
	if err := verifyPlanSignature(document, []byte("not a signature"), foreignAllowed); err == nil {
		t.Fatal("non-SSHSIG signature was accepted")
	}
}

func TestWrongNamespaceSignatureRejected(t *testing.T) {
	core := validContractCore(t)
	_, document, err := materializeContract(core)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	keyPath, allowed := signingIdentity(t, planSignerPrincipal)
	// Sign under the source-review namespace instead of the plan namespace.
	signature := signDetached(t, keyPath, "archeion-knowledge-source-review-v1", document)
	if err := verifyPlanSignature(document, signature, allowed); err == nil {
		t.Fatal("signature in the wrong namespace was accepted")
	}
}

func TestTamperedPlanSignatureRejected(t *testing.T) {
	core := validContractCore(t)
	_, document, err := materializeContract(core)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	keyPath, allowed := signingIdentity(t, planSignerPrincipal)
	signature := signDetached(t, keyPath, planSignatureNamespace, document)
	tampered := append([]byte(nil), document...)
	tampered[len(tampered)/2] ^= 0x20
	if err := verifyPlanSignature(tampered, signature, allowed); err == nil {
		t.Fatal("tampered plan bytes verified against the original signature")
	}
}

func TestSelfAddressMismatchRejected(t *testing.T) {
	core := validContractCore(t)
	_, document, err := materializeContract(core)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	// Flip the declared contract id while leaving the core (and thus the
	// recomputed self-address) unchanged.
	corrupted := bytes.Replace(document, []byte("\"contract_id\":\"source-acquisition-contract:sha256:"), []byte("\"contract_id\":\"source-acquisition-contract:sha256:0"), 1)
	if bytes.Equal(corrupted, document) {
		t.Fatal("failed to corrupt contract id")
	}
	if _, _, err := loadContractBytes(corrupted); err == nil {
		t.Fatal("plan with a mismatched self-address was accepted")
	}
}

func TestCapabilityNotAllowlistedRejected(t *testing.T) {
	core := validContractCore(t)
	core.AcquisitionCapability.CapabilityID = "unreviewed-transport-v9"
	document := selfAddressDocument(t, core)
	if _, _, err := loadContractBytes(document); err == nil {
		t.Fatal("plan with an unreviewed acquisition capability was accepted")
	}
}

func TestInternalConsistencyViolationRejected(t *testing.T) {
	// Declared Files bound disagrees with the actual single file.
	core := validContractCore(t)
	core.Bounds.Files = 2
	document := selfAddressDocument(t, core)
	if _, _, err := loadContractBytes(document); err == nil {
		t.Fatal("plan whose declared file count differs from its files was accepted")
	}

	// Declared LogicalBytes disagrees with the summed file bytes.
	core = validContractCore(t)
	core.Bounds.LogicalBytes = core.Bounds.LogicalBytes + 1
	document = selfAddressDocument(t, core)
	if _, _, err := loadContractBytes(document); err == nil {
		t.Fatal("plan whose declared logical bytes differ from its files was accepted")
	}

	// Declared target cardinality disagrees with the target list length.
	core = validContractCore(t)
	core.Bounds.Targets = 2
	document = selfAddressDocument(t, core)
	if _, _, err := loadContractBytes(document); err == nil {
		t.Fatal("plan whose declared target cardinality differs was accepted")
	}
}

func TestWidenedAuthorityRejected(t *testing.T) {
	core := validContractCore(t)
	core.CompileEligible = true
	document := selfAddressDocument(t, core)
	if _, _, err := loadContractBytes(document); err == nil {
		t.Fatal("plan that widened compile eligibility was accepted")
	}
}

func TestNonComparisonDenominatorRejected(t *testing.T) {
	core := validContractCore(t)
	core.SourceDenominator.ComparisonOnly = false
	document := selfAddressDocument(t, core)
	if _, _, err := loadContractBytes(document); err == nil {
		t.Fatal("plan whose source denominator is not comparison-only was accepted")
	}
}
