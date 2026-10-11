package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type standingTestFixture struct {
	root          string
	proposal      InventoryProposal
	proposalPath  string
	policyCore    StandingSourceAdmissionPolicyCore
	reviewerKey   string
	reviewerTrust string
	signerKey     string
	signerTrust   string
	config        StandingAdmissionConfig
}

func TestMaterializeStandingPolicyDerivesImmutableIdentity(t *testing.T) {
	fixture := newStandingTestFixture(t)
	coreBytes, err := marshalDocument(fixture.policyCore)
	if err != nil {
		t.Fatal(err)
	}
	corePath := writeTestFile(t, t.TempDir(), "standing-policy-core.json", coreBytes)
	store := filepath.Join(t.TempDir(), "policy-store")
	first, firstPath, err := MaterializeStandingPolicy(corePath, store)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPath, err := MaterializeStandingPolicy(corePath, store)
	if err != nil {
		t.Fatal(err)
	}
	if first.PolicyID != "source-admission-policy:"+first.PolicyPayloadSHA256 ||
		first.PolicyID != second.PolicyID || firstPath != secondPath {
		t.Fatalf("materialized policy identity is unstable: first=%+v second=%+v", first, second)
	}
	materialized := mustReadFile(t, firstPath)
	var decoded StandingSourceAdmissionPolicy
	if err := decodeStrictDocument(materialized, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PolicyID != first.PolicyID {
		t.Fatalf("stored policy ID = %q, want %q", decoded.PolicyID, first.PolicyID)
	}
	if info, err := os.Stat(firstPath); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("materialized policy mode = %v, %v; want 0444", info, err)
	}
}

func TestStandingAdmissionDeterministicAndCompilerCompatible(t *testing.T) {
	fixture := newStandingTestFixture(t)
	firstConfig := fixture.config
	firstConfig.StoreRoot = filepath.Join(fixture.root, "standing-store-a")
	if digest, digestErr := privateSignerPublicDigest(fixture.signerKey, firstConfig.StoreRoot); digestErr != nil || digest != fixture.policyCore.SignerKeySHA256 {
		t.Fatalf("fixture signer identity = %q, %v; want %q", digest, digestErr, fixture.policyCore.SignerKeySHA256)
	}
	first, err := AdmitWithStandingPolicy(firstConfig)
	if err != nil {
		var rejected *StandingAdmissionRejectedError
		if errors.As(err, &rejected) {
			t.Fatalf("AdmitWithStandingPolicy() quarantined: %+v", rejected.Issues)
		}
		t.Fatalf("AdmitWithStandingPolicy() error = %v", err)
	}
	secondConfig := fixture.config
	secondConfig.StoreRoot = filepath.Join(fixture.root, "standing-store-b")
	second, err := AdmitWithStandingPolicy(secondConfig)
	if err != nil {
		t.Fatalf("second AdmitWithStandingPolicy() error = %v", err)
	}
	if first.Manifest.State != "accepted" || !first.Manifest.CompileEligible || first.Manifest.PromoteEligible {
		t.Fatalf("standing state is unsafe: %+v", first.Manifest.StandingAdmissionManifestCore)
	}
	if fixture.proposal.SourceSpecDraft.SourceID != "src:github:argoproj/argo-cd@v3.4.5:docs-crds" ||
		fixture.policyCore.Publisher.SourceIDPrefix != "src:github:argoproj/argo-cd@" ||
		fixture.policyCore.Publisher.SourceIDSuffix != ":docs-crds" {
		t.Fatalf("fixture does not exercise the real Argo source-ID shape: proposal=%q publisher=%+v",
			fixture.proposal.SourceSpecDraft.SourceID, fixture.policyCore.Publisher)
	}
	if first.Manifest.AdmissionID != second.Manifest.AdmissionID ||
		!bytes.Equal(mustReadFile(t, first.ManifestPath), mustReadFile(t, second.ManifestPath)) ||
		!bytes.Equal(mustReadFile(t, first.ReviewReceiptPath), mustReadFile(t, second.ReviewReceiptPath)) ||
		!bytes.Equal(mustReadFile(t, first.ReviewSignaturePath), mustReadFile(t, second.ReviewSignaturePath)) {
		t.Fatal("identical proposal, policy, and key did not produce byte-identical signed admission evidence")
	}
	var receipt SourceSpecReviewReceipt
	if err := decodeStrictDocument(mustReadFile(t, first.ReviewReceiptPath), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.AdmissionMethod != standingAdmissionMethod || receipt.AdmissionPolicyID != first.Manifest.PolicyID ||
		receipt.AdmissionPolicySHA256 != first.Manifest.PolicyPayloadSHA256 || receipt.Reviewer != fixture.policyCore.SignerPrincipal ||
		receipt.ReviewedAt != firstConfig.DecisionAt || first.Manifest.AdmittedAt != firstConfig.DecisionAt {
		t.Fatalf("receipt does not bind the standing policy and explicit deterministic decision time: %+v", receipt)
	}
	if err := verifySSHSIG(mustReadFile(t, first.ReviewReceiptPath), mustReadFile(t, first.ReviewSignaturePath),
		mustReadFile(t, fixture.signerTrust), fixture.policyCore.SignerPrincipal); err != nil {
		t.Fatalf("generated admission signature does not verify: %v", err)
	}

	compiled, err := Compile(CompileConfig{
		SpecPath:            first.SourceSpecPath,
		ProposalPath:        fixture.proposalPath,
		ReviewReceiptPath:   first.ReviewReceiptPath,
		ReviewSignaturePath: first.ReviewSignaturePath,
		AllowedSignersPath:  fixture.signerTrust,
		MirrorBase:          filepath.Join("testdata", "mirrors"),
		StoreRoot:           filepath.Join(fixture.root, "compiled-store"),
	})
	if err != nil {
		t.Fatalf("existing compiler rejected standing admission: %v", err)
	}
	if compiled.Manifest.ReviewAdmission.AdmissionMethod != standingAdmissionMethod ||
		compiled.Manifest.ReviewAdmission.AdmissionPolicyID != first.Manifest.PolicyID ||
		compiled.Manifest.ReviewAdmission.AdmissionPolicySHA256 != first.Manifest.PolicyPayloadSHA256 {
		t.Fatalf("compiled manifest lost standing-policy provenance: %+v", compiled.Manifest.ReviewAdmission)
	}
	assertPrivateKeyNotCopied(t, firstConfig.StoreRoot, fixture.signerKey)
}

func TestStandingAdmissionRejectsUnsafeDecisionTimes(t *testing.T) {
	fixture := newStandingTestFixture(t)
	tests := []struct {
		name       string
		decisionAt string
		code       string
	}{
		{name: "missing", decisionAt: "", code: "standing_decision_time_missing"},
		{name: "non-canonical", decisionAt: "2026-07-16T11:30:00+02:00", code: "standing_decision_time_invalid"},
		{name: "before observation", decisionAt: "2026-07-16T07:59:59Z", code: "standing_decision_precedes_observation"},
		{name: "at policy expiry", decisionAt: fixture.policyCore.EffectiveTo, code: "standing_policy_not_effective"},
		{name: "after policy expiry", decisionAt: "2027-01-01T00:00:01Z", code: "standing_policy_not_effective"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := fixture.config
			config.DecisionAt = test.decisionAt
			config.StoreRoot = filepath.Join(t.TempDir(), "store")
			assertStandingQuarantine(t, config, test.code)
		})
	}
}

func TestStandingAdmissionQuarantinesPolicyDrift(t *testing.T) {
	fixture := newStandingTestFixture(t)
	tests := []struct {
		name    string
		code    string
		prepare func(*testing.T, StandingAdmissionConfig, StandingSourceAdmissionPolicyCore) StandingAdmissionConfig
	}{
		{
			name: "publisher identity",
			code: "standing_publisher_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.Publisher.SourceIDPrefix = "src:other:docs@"
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "publisher suffix",
			code: "standing_publisher_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.Publisher.SourceIDSuffix = ":docs"
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "publisher suffix syntax",
			code: "standing_publisher_identity_invalid",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.Publisher.SourceIDSuffix = "docs-crds"
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "publisher suffix bound",
			code: "metadata_scalar_limit_exceeded",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.Publisher.SourceIDSuffix = ":" + strings.Repeat("x", maxStandingSourceIDSuffixBytes)
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "channel class",
			code: "standing_channel_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.AllowedChannelTypes = []string{"docs"}
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "transport",
			code: "standing_transport_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, _ StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				proposal := cloneProposal(t, fixture.proposal)
				proposal.SourceSpecDraft.CanonicalURI = strings.Replace(proposal.SourceSpecDraft.CanonicalURI, "https://", "http://", 1)
				config.ProposalPath = writeCanonicalProposal(t, filepath.Join(t.TempDir(), "proposal.json"), proposal)
				return config
			},
		},
		{
			name: "rights profile",
			code: "standing_rights_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.RightsProfile.Rights.LicenseExpression = "Apache-2.0 OR MIT"
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "version resolution",
			code: "standing_version_resolution_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, _ StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				proposal := cloneProposal(t, fixture.proposal)
				proposal.SourceSpecDraft.ResolvedVersion = "v3.4.5-rc.1"
				proposal.SourceSpecDraft.ComponentVersionID = "ver:github:argoproj/argo-cd@v3.4.5-rc.1"
				proposal.SourceSpecDraft.SourceID = "src:github:argoproj/argo-cd@v3.4.5-rc.1:docs-crds"
				config.ProposalPath = writeCanonicalProposal(t, filepath.Join(t.TempDir(), "proposal.json"), proposal)
				return config
			},
		},
		{
			name: "reviewer key",
			code: "standing_policy_reviewer_key_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.ReviewerKeySHA256 = "sha256:" + strings.Repeat("0", 64)
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "signer key",
			code: "standing_signer_key_mismatch",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.SignerKeySHA256 = "sha256:" + strings.Repeat("1", 64)
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "resource limits",
			code: "standing_resource_limit_exceeded",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.ResourceLimits.MaxFiles = 3
				return fixture.withSignedPolicy(t, config, core)
			},
		},
		{
			name: "expired policy",
			code: "standing_policy_not_effective",
			prepare: func(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
				core.EffectiveTo = "2026-07-16T08:00:00Z"
				return fixture.withSignedPolicy(t, config, core)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := fixture.config
			config.StoreRoot = filepath.Join(t.TempDir(), "store")
			config = test.prepare(t, config, clonePolicyCore(t, fixture.policyCore))
			assertStandingQuarantine(t, config, test.code)
		})
	}
}

func TestStandingAdmissionQuarantinesForgedPolicyAndUnsafePrivateKeys(t *testing.T) {
	fixture := newStandingTestFixture(t)
	t.Run("forged policy signature", func(t *testing.T) {
		config := fixture.config
		config.StoreRoot = filepath.Join(t.TempDir(), "store")
		signature := append([]byte(nil), mustReadFile(t, config.PolicySignaturePath)...)
		marker := bytes.Index(signature, []byte("U1NIU0lH"))
		if marker < 0 {
			t.Fatal("signature fixture has no mutable payload")
		}
		signature[marker] = 'V'
		config.PolicySignaturePath = writeTestFile(t, t.TempDir(), "forged.sig", signature)
		assertStandingQuarantine(t, config, "standing_policy_signature_verification_failed")
	})

	t.Run("private key permissions", func(t *testing.T) {
		config := fixture.config
		config.StoreRoot = filepath.Join(t.TempDir(), "store")
		unsafeKey := filepath.Join(t.TempDir(), "unsafe-key")
		if err := os.WriteFile(unsafeKey, mustReadFile(t, fixture.signerKey), 0o644); err != nil {
			t.Fatal(err)
		}
		config.SignerPrivateKeyPath = unsafeKey
		assertStandingQuarantine(t, config, "standing_signer_key_mismatch")
	})

	t.Run("private key inside store", func(t *testing.T) {
		store := filepath.Join(t.TempDir(), "store")
		if err := os.MkdirAll(store, 0o755); err != nil {
			t.Fatal(err)
		}
		keyInside := filepath.Join(store, "signer-key")
		if err := os.WriteFile(keyInside, mustReadFile(t, fixture.signerKey), 0o600); err != nil {
			t.Fatal(err)
		}
		config := fixture.config
		config.StoreRoot = store
		config.SignerPrivateKeyPath = keyInside
		assertStandingQuarantine(t, config, "standing_signer_key_mismatch")
	})

	t.Run("trust root inside store", func(t *testing.T) {
		store := filepath.Join(t.TempDir(), "store")
		if err := os.MkdirAll(store, 0o755); err != nil {
			t.Fatal(err)
		}
		trustInside := filepath.Join(store, "allowed_signers")
		if err := os.WriteFile(trustInside, mustReadFile(t, fixture.signerTrust), 0o600); err != nil {
			t.Fatal(err)
		}
		config := fixture.config
		config.StoreRoot = store
		config.SignerAllowedSignersPath = trustInside
		assertStandingQuarantine(t, config, "standing_trust_not_external")
	})
}

func assertStandingQuarantine(t *testing.T, config StandingAdmissionConfig, code string) {
	t.Helper()
	_, err := AdmitWithStandingPolicy(config)
	var rejected *StandingAdmissionRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("error = %v, want StandingAdmissionRejectedError", err)
	}
	if !hasIssueCode(rejected.Issues, code) {
		t.Fatalf("issues = %+v, want %q", rejected.Issues, code)
	}
	if _, statErr := os.Stat(rejected.ReportPath); statErr != nil {
		t.Fatalf("quarantine report missing: %v", statErr)
	}
	if got := countRegularFiles(t, filepath.Join(config.StoreRoot, "standing-admissions")); got != 0 {
		t.Fatalf("quarantined attempt wrote %d standing admissions", got)
	}
	if got := countRegularFiles(t, filepath.Join(config.StoreRoot, "review")); got != 0 {
		t.Fatalf("quarantined attempt wrote %d review artifacts", got)
	}
}

func newStandingTestFixture(t *testing.T) standingTestFixture {
	t.Helper()
	root := t.TempDir()
	proposalPath := filepath.Join("testdata", "review", "inventory-proposal.json")
	var proposal InventoryProposal
	if err := decodeStrictDocument(mustReadFile(t, proposalPath), &proposal); err != nil {
		t.Fatal(err)
	}
	proposal.SourceSpecDraft.SourceID = "src:github:argoproj/argo-cd@" + proposal.SourceSpecDraft.ResolvedVersion + ":docs-crds"
	proposalPath = writeCanonicalProposal(t, filepath.Join(root, "inventory-proposal.json"), proposal)
	if err := decodeStrictDocument(mustReadFile(t, proposalPath), &proposal); err != nil {
		t.Fatal(err)
	}
	reviewerKey, reviewerTrust, reviewerDigest := generateStandingIdentity(t, root, "policy-reviewer", "policy-reviewer")
	signerKey, signerTrust, signerDigest := generateStandingIdentity(t, root, "admission-signer", "admission-signer")
	spec := proposal.SourceSpecDraft
	core := StandingSourceAdmissionPolicyCore{
		SchemaVersion: standingPolicySchemaVersion,
		PolicyKind:    standingPolicyKind,
		State:         "accepted",
		Publisher: StandingPublisherPolicy{
			SourceIDPrefix:     "src:github:argoproj/argo-cd@",
			SourceIDSuffix:     ":docs-crds",
			ComponentID:        spec.ComponentID,
			CanonicalURIPrefix: "https://github.com/argoproj/argo-cd/",
			OriginKind:         spec.Provenance.OriginKind,
		},
		AllowedChannelTypes: []string{spec.ChannelType},
		AllowedTransports:   []string{"https"},
		VersionResolution: StandingVersionPolicy{
			ResolvedVersionKind:      "semver_tag",
			SourceRevisionKind:       "git_commit_sha1",
			CanonicalRevisionBinding: "github_commit",
			TagPrefix:                "v",
			AllowPrerelease:          false,
		},
		RightsProfile: StandingRightsProfile{
			Rights:         spec.Rights,
			AccessScope:    spec.AccessScope,
			Classification: spec.Classification,
			SecurityDomain: spec.SecurityDomain,
			Language:       spec.Language,
		},
		ReviewerPrincipal: "policy-reviewer",
		ReviewerKeySHA256: reviewerDigest,
		SignerPrincipal:   "admission-signer",
		SignerKeySHA256:   signerDigest,
		ValidationProfile: standingValidationProfile,
		ResourceLimits: StandingResourceLimits{
			MaxFiles:      100,
			MaxFileBytes:  1024 * 1024,
			MaxTotalBytes: 16 * 1024 * 1024,
		},
		EffectiveFrom: "2026-01-01T00:00:00Z",
		EffectiveTo:   "2027-01-01T00:00:00Z",
		RevokedAt:     "",
	}
	fixture := standingTestFixture{
		root:          root,
		proposal:      proposal,
		proposalPath:  proposalPath,
		policyCore:    core,
		reviewerKey:   reviewerKey,
		reviewerTrust: reviewerTrust,
		signerKey:     signerKey,
		signerTrust:   signerTrust,
	}
	fixture.config = StandingAdmissionConfig{
		ProposalPath:             proposalPath,
		PolicyAllowedSignersPath: reviewerTrust,
		SignerPrivateKeyPath:     signerKey,
		SignerAllowedSignersPath: signerTrust,
		DecisionAt:               "2026-07-16T09:30:00Z",
	}
	fixture.config = fixture.withSignedPolicy(t, fixture.config, core)
	return fixture
}

func (fixture standingTestFixture) withSignedPolicy(t *testing.T, config StandingAdmissionConfig, core StandingSourceAdmissionPolicyCore) StandingAdmissionConfig {
	t.Helper()
	directory := t.TempDir()
	policy, err := newStandingPolicy(core)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := marshalDocument(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := writeTestFile(t, directory, "standing-policy.json", policyBytes)
	signFileWithNamespace(t, fixture.reviewerKey, standingPolicySignatureNamespace, policyPath)
	config.PolicyPath = policyPath
	config.PolicySignaturePath = policyPath + ".sig"
	return config
}

func generateStandingIdentity(t *testing.T, directory, name, principal string) (string, string, string) {
	t.Helper()
	keyPath := filepath.Join(directory, name)
	if output, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("generate %s: %v: %s", name, err, output)
	}
	publicFields := strings.Fields(string(mustReadFile(t, keyPath+".pub")))
	if len(publicFields) < 2 || publicFields[0] != "ssh-ed25519" {
		t.Fatalf("generated %s public key is malformed", name)
	}
	trustPath := filepath.Join(directory, name+"-allowed_signers")
	trust := []byte(principal + " " + publicFields[0] + " " + publicFields[1] + "\n")
	if err := os.WriteFile(trustPath, trust, 0o600); err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString(publicFields[1])
	if err != nil {
		t.Fatal(err)
	}
	return keyPath, trustPath, digestBytes(blob)
}

func signFileWithNamespace(t *testing.T, keyPath, namespace, documentPath string) {
	t.Helper()
	if output, err := exec.Command("/usr/bin/ssh-keygen", "-Y", "sign", "-q", "-f", keyPath,
		"-n", namespace, documentPath).CombinedOutput(); err != nil {
		t.Fatalf("sign %s: %v: %s", filepath.Base(documentPath), err, output)
	}
}

func cloneProposal(t *testing.T, proposal InventoryProposal) InventoryProposal {
	t.Helper()
	data, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var cloned InventoryProposal
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func clonePolicyCore(t *testing.T, core StandingSourceAdmissionPolicyCore) StandingSourceAdmissionPolicyCore {
	t.Helper()
	data, err := json.Marshal(core)
	if err != nil {
		t.Fatal(err)
	}
	var cloned StandingSourceAdmissionPolicyCore
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func writeCanonicalProposal(t *testing.T, destination string, proposal InventoryProposal) string {
	t.Helper()
	coreBytes, err := json.Marshal(proposal.InventoryProposalCore)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(coreBytes)
	proposal.ProposalPayloadSHA256 = digest
	proposal.ProposalID = "inventory-proposal:" + digest
	data, err := marshalDocument(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return destination
}

func hasIssueCode(issues []QuarantineIssue, code string) bool {
	for _, item := range issues {
		if item.Code == code {
			return true
		}
	}
	return false
}

func assertPrivateKeyNotCopied(t *testing.T, storeRoot, keyPath string) {
	t.Helper()
	privateBytes := mustReadFile(t, keyPath)
	if err := filepath.WalkDir(storeRoot, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		if bytes.Equal(mustReadFile(t, current), privateBytes) {
			t.Fatalf("private signer key bytes were copied into %s", current)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
