package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	standingPolicySchemaVersion       = "1.0.0"
	standingPolicyKind                = "standing_source_admission"
	standingAdmissionManifestKind     = "standing_source_admission"
	standingAdmissionMethod           = "standing_policy"
	standingPolicySignatureNamespace  = "archeion-knowledge-standing-source-policy-v1"
	standingValidationProfile         = "knowledge-snapshot-v1"
	maxStandingPolicyBytes            = int64(1024 * 1024)
	maxStandingAdmissionManifestBytes = int64(1024 * 1024)
	maxPrivateSignerKeyBytes          = int64(1024 * 1024)
	maxStandingSourceIDSuffixBytes    = 128
)

var strictSemverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var standingSourceIDSuffixPattern = regexp.MustCompile(`^:[A-Za-z0-9][A-Za-z0-9._:/+-]*$`)

type standingAdmissionInputs struct {
	proposalBytes        []byte
	proposal             InventoryProposal
	specBytes            []byte
	policyBytes          []byte
	policy               StandingSourceAdmissionPolicy
	policySignature      []byte
	policyTrust          []byte
	signerTrust          []byte
	policyDocumentHash   string
	proposalDocumentHash string
}

// MaterializeStandingPolicy derives the self-referential policy identity from
// a canonical core document and stores the complete policy immutably. Review
// and signing remain separate operations, so generation grants no authority.
func MaterializeStandingPolicy(corePath, storeRoot string) (StandingSourceAdmissionPolicy, string, error) {
	var zero StandingSourceAdmissionPolicy
	coreBytes, err := readBoundedRegular(corePath, maxStandingPolicyBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read standing policy core: %w", err)
	}
	var core StandingSourceAdmissionPolicyCore
	if err := decodeStrictDocument(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode standing policy core: %w", err)
	}
	canonicalCore, err := marshalDocument(core)
	if err != nil || !bytes.Equal(canonicalCore, coreBytes) {
		return zero, "", errors.New("standing policy core must use canonical serialization")
	}
	policy, err := newStandingPolicy(core)
	if err != nil {
		return zero, "", fmt.Errorf("derive standing policy identity: %w", err)
	}
	policyBytes, err := marshalDocument(policy)
	if err != nil {
		return zero, "", fmt.Errorf("encode standing policy: %w", err)
	}
	if issues := validateStandingPolicy(policyBytes, policy); len(issues) != 0 {
		return zero, "", fmt.Errorf("standing policy core is invalid: %s at %s", issues[0].Code, issues[0].Path)
	}
	store, err := openOutputStore(storeRoot)
	if err != nil {
		return zero, "", fmt.Errorf("open safe standing-policy store: %w", err)
	}
	defer store.Close()
	hexDigest := strings.TrimPrefix(policy.PolicyPayloadSHA256, "sha256:")
	relative := path.Join("standing-policies", "sha256", hexDigest[:2], hexDigest+".json")
	if err := store.writeImmutable(relative, policyBytes, 0o444); err != nil {
		return zero, "", fmt.Errorf("commit standing policy: %w", err)
	}
	return policy, filepath.Join(store.path, filepath.FromSlash(relative)), nil
}

// AdmitWithStandingPolicy validates one unreviewed inventory proposal and one
// explicit decision time against a separately reviewed standing policy, then
// signs the ordinary compiler review receipt with a bounded external service
// key. It performs no acquisition, compilation, promotion, network access, or
// production mutation.
func AdmitWithStandingPolicy(config StandingAdmissionConfig) (StandingAdmissionResult, error) {
	var zero StandingAdmissionResult
	if strings.TrimSpace(config.StoreRoot) == "" {
		return zero, errors.New("standing-admission store is required")
	}
	output, err := openOutputStore(config.StoreRoot)
	if err != nil {
		return zero, fmt.Errorf("open safe standing-admission store: %w", err)
	}
	defer output.Close()

	inputs, issues := loadStandingAdmissionInputs(config)
	issues = append(issues, validateExternalStandingTrust(config.PolicyAllowedSignersPath, output.path, "policy_allowed_signers")...)
	issues = append(issues, validateExternalStandingTrust(config.SignerAllowedSignersPath, output.path, "signer_allowed_signers")...)
	issues = append(issues, validateStandingDecisionTime(config.DecisionAt)...)
	issues = sortedIssues(issues)
	if len(issues) == 0 {
		issues = append(issues, validateStandingPolicy(inputs.policyBytes, inputs.policy)...)
	}
	if len(issues) == 0 {
		issues = append(issues, validateStandingPolicyReview(inputs.policyBytes, inputs.policy, inputs.policySignature, inputs.policyTrust)...)
	}
	if len(issues) == 0 {
		issues = append(issues, matchStandingPolicy(inputs.proposal, inputs.policy, config.DecisionAt)...)
	}
	if len(issues) == 0 {
		issues = append(issues, validateStandingSigner(config, output.path, inputs.policy, inputs.signerTrust)...)
	}
	if len(issues) != 0 {
		return zero, standingAdmissionQuarantine(output, inputs, issues)
	}

	receipt := SourceSpecReviewReceipt{
		SchemaVersion:         reviewReceiptSchemaVersion,
		ReceiptKind:           "source_spec_review",
		ProposalID:            inputs.proposal.ProposalID,
		ProposalPayloadSHA256: inputs.proposal.ProposalPayloadSHA256,
		SourceSpecSHA256:      digestBytes(inputs.specBytes),
		Reviewer:              inputs.policy.SignerPrincipal,
		Decision:              "accepted",
		ReviewedAt:            config.DecisionAt,
		AdmissionMethod:       standingAdmissionMethod,
		AdmissionPolicyID:     inputs.policy.PolicyID,
		AdmissionPolicySHA256: inputs.policy.PolicyPayloadSHA256,
	}
	receiptBytes, err := marshalDocument(receipt)
	if err != nil {
		return zero, fmt.Errorf("encode standing admission receipt: %w", err)
	}
	if receiptIssues := validateReceiptAdmissionMethod(receipt); len(receiptIssues) != 0 {
		return zero, standingAdmissionQuarantine(output, inputs, receiptIssues)
	}
	receiptSignature, err := signStandingReceipt(config.SignerPrivateKeyPath, receiptBytes)
	if err != nil {
		return zero, standingAdmissionQuarantine(output, inputs, []QuarantineIssue{
			issue("standing_signer_failed", "signer_key", "bounded service identity could not sign the policy-matched admission"),
		})
	}
	if err := verifySSHSIGNamespace(receiptBytes, receiptSignature, inputs.signerTrust,
		inputs.policy.SignerPrincipal, reviewSignatureNamespace); err != nil {
		return zero, standingAdmissionQuarantine(output, inputs, []QuarantineIssue{
			issue("standing_signature_verification_failed", "receipt_signature", "generated admission signature failed independent Ed25519 verification"),
		})
	}

	artifacts := []reviewArtifact{
		makeReviewArtifact("proposal", inputs.proposalBytes),
		makeReviewArtifact("source_spec", inputs.specBytes),
		makeReviewArtifact("standing_policy", inputs.policyBytes),
		makeReviewArtifact("standing_policy_signature", inputs.policySignature),
		makeReviewArtifact("standing_policy_trust", inputs.policyTrust),
		makeReviewArtifact("standing_signer_trust", inputs.signerTrust),
		makeReviewArtifact("receipt", receiptBytes),
		makeReviewArtifact("signature", receiptSignature),
	}
	if err := commitReviewArtifacts(output, artifacts); err != nil {
		return zero, fmt.Errorf("commit standing-admission evidence: %w", err)
	}
	byRole := make(map[string]reviewArtifact, len(artifacts))
	for _, artifact := range artifacts {
		byRole[artifact.Role] = artifact
	}
	core := StandingAdmissionManifestCore{
		SchemaVersion:              standingPolicySchemaVersion,
		ManifestKind:               standingAdmissionManifestKind,
		State:                      "accepted",
		AuthorityState:             "reviewed_standing_policy",
		AdmissionMethod:            standingAdmissionMethod,
		CompileEligible:            true,
		PromoteEligible:            false,
		ProposalID:                 inputs.proposal.ProposalID,
		ProposalPayloadSHA256:      inputs.proposal.ProposalPayloadSHA256,
		ProposalDocumentSHA256:     byRole["proposal"].SHA256,
		ProposalObjectPath:         byRole["proposal"].RelativePath,
		SourceSpecSHA256:           byRole["source_spec"].SHA256,
		SourceSpecObjectPath:       byRole["source_spec"].RelativePath,
		PolicyID:                   inputs.policy.PolicyID,
		PolicyPayloadSHA256:        inputs.policy.PolicyPayloadSHA256,
		PolicyDocumentSHA256:       byRole["standing_policy"].SHA256,
		PolicyObjectPath:           byRole["standing_policy"].RelativePath,
		PolicySignatureSHA256:      byRole["standing_policy_signature"].SHA256,
		PolicySignatureObjectPath:  byRole["standing_policy_signature"].RelativePath,
		PolicySignatureNamespace:   standingPolicySignatureNamespace,
		PolicyTrustSHA256:          byRole["standing_policy_trust"].SHA256,
		PolicyTrustObjectPath:      byRole["standing_policy_trust"].RelativePath,
		PolicyReviewer:             inputs.policy.ReviewerPrincipal,
		PolicyReviewerKeySHA256:    inputs.policy.ReviewerKeySHA256,
		Signer:                     inputs.policy.SignerPrincipal,
		SignerKeySHA256:            inputs.policy.SignerKeySHA256,
		SignerTrustSHA256:          byRole["standing_signer_trust"].SHA256,
		SignerTrustObjectPath:      byRole["standing_signer_trust"].RelativePath,
		ReceiptSHA256:              byRole["receipt"].SHA256,
		ReceiptObjectPath:          byRole["receipt"].RelativePath,
		ReceiptSignatureSHA256:     byRole["signature"].SHA256,
		ReceiptSignatureObjectPath: byRole["signature"].RelativePath,
		ReceiptSignatureNamespace:  reviewSignatureNamespace,
		AdmittedAt:                 receipt.ReviewedAt,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return zero, fmt.Errorf("encode standing-admission manifest payload: %w", err)
	}
	payloadDigest := digestBytes(coreBytes)
	manifest := StandingAdmissionManifest{
		AdmissionID:                   "standing-admission:" + payloadDigest,
		AdmissionPayloadSHA256:        payloadDigest,
		StandingAdmissionManifestCore: core,
	}
	manifestBytes, err := marshalDocument(manifest)
	if err != nil {
		return zero, fmt.Errorf("encode standing-admission manifest: %w", err)
	}
	if int64(len(manifestBytes)) > maxStandingAdmissionManifestBytes {
		return zero, standingAdmissionQuarantine(output, inputs, []QuarantineIssue{
			issue("standing_manifest_limit_exceeded", "manifest", "standing-admission manifest exceeds its fixed output limit"),
		})
	}
	hexDigest := strings.TrimPrefix(payloadDigest, "sha256:")
	manifestRelative := path.Join("standing-admissions", "sha256", hexDigest[:2], hexDigest+".json")
	if err := output.writeImmutable(manifestRelative, manifestBytes, 0o444); err != nil {
		return zero, fmt.Errorf("commit standing-admission manifest: %w", err)
	}
	return StandingAdmissionResult{
		Manifest:            manifest,
		ManifestPath:        filepath.Join(output.path, filepath.FromSlash(manifestRelative)),
		SourceSpecPath:      filepath.Join(output.path, filepath.FromSlash(byRole["source_spec"].RelativePath)),
		ReviewReceiptPath:   filepath.Join(output.path, filepath.FromSlash(byRole["receipt"].RelativePath)),
		ReviewSignaturePath: filepath.Join(output.path, filepath.FromSlash(byRole["signature"].RelativePath)),
	}, nil
}

func validateExternalStandingTrust(candidate, storeRoot, label string) []QuarantineIssue {
	candidateAbs, candidateErr := filepath.Abs(candidate)
	storeAbs, storeErr := filepath.Abs(storeRoot)
	if candidateErr != nil || storeErr != nil || isWithin(storeAbs, candidateAbs) {
		return []QuarantineIssue{issue("standing_trust_not_external", label, "standing admission trust roots must remain outside the untrusted output store")}
	}
	return nil
}

func loadStandingAdmissionInputs(config StandingAdmissionConfig) (standingAdmissionInputs, []QuarantineIssue) {
	var inputs standingAdmissionInputs
	inputs.proposalBytes, _ = readBoundedRegular(config.ProposalPath, maxInventoryProposalBytes)
	inputs.policyBytes, _ = readBoundedRegular(config.PolicyPath, maxStandingPolicyBytes)
	inputs.proposalDocumentHash = digestBytes(inputs.proposalBytes)
	inputs.policyDocumentHash = digestBytes(inputs.policyBytes)
	issues := make([]QuarantineIssue, 0)
	if len(inputs.proposalBytes) == 0 {
		issues = append(issues, issue("standing_proposal_read_failed", "proposal", "proposal must be a bounded regular non-symlink file"))
	}
	if len(inputs.policyBytes) == 0 {
		issues = append(issues, issue("standing_policy_read_failed", "policy", "standing policy must be a bounded regular non-symlink file"))
	}
	if len(issues) != 0 {
		return inputs, sortedIssues(issues)
	}
	if err := decodeStrictDocument(inputs.proposalBytes, &inputs.proposal); err != nil {
		issues = append(issues, issue("standing_proposal_invalid", "proposal", "proposal is not strict canonical JSON"))
	} else {
		issues = append(issues, validateStandingProposal(inputs.proposalBytes, inputs.proposal)...)
		inputs.specBytes, _ = marshalDocument(inputs.proposal.SourceSpecDraft)
	}
	if err := decodeStrictDocument(inputs.policyBytes, &inputs.policy); err != nil {
		issues = append(issues, issue("standing_policy_invalid", "policy", "standing policy is not strict canonical JSON"))
	}
	var err error
	inputs.policySignature, err = readBoundedRegular(config.PolicySignaturePath, maxReviewSignatureBytes)
	if err != nil {
		issues = append(issues, issue("standing_policy_signature_read_failed", "policy_signature", "policy signature must be a bounded regular non-symlink file"))
	}
	inputs.policyTrust, err = readBoundedRegular(config.PolicyAllowedSignersPath, maxAllowedSignersBytes)
	if err != nil {
		issues = append(issues, issue("standing_policy_trust_read_failed", "policy_allowed_signers", "policy trust must be a bounded regular non-symlink file"))
	}
	inputs.signerTrust, err = readBoundedRegular(config.SignerAllowedSignersPath, maxAllowedSignersBytes)
	if err != nil {
		issues = append(issues, issue("standing_signer_trust_read_failed", "signer_allowed_signers", "signer trust must be a bounded regular non-symlink file"))
	}
	return inputs, sortedIssues(issues)
}

func validateStandingProposal(document []byte, proposal InventoryProposal) []QuarantineIssue {
	issues := validateProposalMetadataBounds(proposal)
	if specIssues := validateSourceSpec(proposal.SourceSpecDraft); len(specIssues) != 0 {
		issues = append(issues, issue("standing_proposal_spec_invalid", "proposal.source_spec_draft", "proposal source-spec draft is structurally invalid"))
	}
	if parsed, err := url.Parse(proposal.SourceSpecDraft.CanonicalURI); err != nil || parsed.Scheme != "https" {
		issues = append(issues, issue("standing_transport_mismatch", "proposal.source_spec_draft.canonical_uri", "proposal transport is outside the standing admission contract"))
	}
	canonical, err := marshalDocument(proposal)
	if err != nil || !bytes.Equal(canonical, document) {
		issues = append(issues, issue("standing_proposal_noncanonical", "proposal", "proposal bytes must use canonical inventory serialization"))
	}
	coreBytes, err := json.Marshal(proposal.InventoryProposalCore)
	if err != nil {
		issues = append(issues, issue("standing_proposal_invalid", "proposal", "proposal payload could not be encoded"))
	} else {
		payloadDigest := digestBytes(coreBytes)
		if proposal.ProposalPayloadSHA256 != payloadDigest || proposal.ProposalID != "inventory-proposal:"+payloadDigest {
			issues = append(issues, issue("standing_proposal_identity_mismatch", "proposal", "proposal ID and payload hash are not content-derived"))
		}
	}
	if proposal.State != "proposal" || proposal.ReviewState != "unreviewed" || proposal.AuthorityState != "non_authoritative" ||
		proposal.CompileEligible || proposal.PromoteEligible {
		issues = append(issues, issue("standing_proposal_state_invalid", "proposal", "only an original unreviewed non-authoritative proposal is eligible"))
	}
	if !proposalCountsMatch(proposal) {
		issues = append(issues, issue("standing_proposal_counts_mismatch", "proposal", "proposal counts or exclusions do not match the embedded source spec"))
	}
	return sortedIssues(issues)
}

func validateStandingPolicy(document []byte, policy StandingSourceAdmissionPolicy) []QuarantineIssue {
	issues := validateScalarBounds([]boundedScalar{
		{"policy.policy_id", policy.PolicyID, maxReviewIdentityBytes},
		{"policy.policy_payload_sha256", policy.PolicyPayloadSHA256, len("sha256:") + 64},
		{"policy.schema_version", policy.SchemaVersion, maxSchemaScalarBytes},
		{"policy.policy_kind", policy.PolicyKind, maxReviewIdentityBytes},
		{"policy.state", policy.State, maxReviewDecisionBytes},
		{"policy.publisher.source_id_prefix", policy.Publisher.SourceIDPrefix, maxStableIDBytes},
		{"policy.publisher.source_id_suffix", policy.Publisher.SourceIDSuffix, maxStandingSourceIDSuffixBytes},
		{"policy.publisher.component_id", policy.Publisher.ComponentID, maxStableIDBytes},
		{"policy.publisher.canonical_uri_prefix", policy.Publisher.CanonicalURIPrefix, maxCanonicalURIBytes},
		{"policy.publisher.origin_kind", policy.Publisher.OriginKind, maxOriginKindBytes},
		{"policy.reviewer_principal", policy.ReviewerPrincipal, 128},
		{"policy.reviewer_key_sha256", policy.ReviewerKeySHA256, len("sha256:") + 64},
		{"policy.signer_principal", policy.SignerPrincipal, 128},
		{"policy.signer_key_sha256", policy.SignerKeySHA256, len("sha256:") + 64},
		{"policy.validation_profile", policy.ValidationProfile, maxReviewIdentityBytes},
		{"policy.effective_from", policy.EffectiveFrom, maxTimestampBytes},
		{"policy.effective_to", policy.EffectiveTo, maxTimestampBytes},
		{"policy.revoked_at", policy.RevokedAt, maxTimestampBytes},
		{"policy.version_resolution.resolved_version_kind", policy.VersionResolution.ResolvedVersionKind, maxReviewIdentityBytes},
		{"policy.version_resolution.source_revision_kind", policy.VersionResolution.SourceRevisionKind, maxReviewIdentityBytes},
		{"policy.version_resolution.canonical_revision_binding", policy.VersionResolution.CanonicalRevisionBinding, maxReviewIdentityBytes},
		{"policy.version_resolution.tag_prefix", policy.VersionResolution.TagPrefix, 16},
	})
	canonical, err := marshalDocument(policy)
	if err != nil || !bytes.Equal(canonical, document) {
		issues = append(issues, issue("standing_policy_noncanonical", "policy", "standing policy bytes must use canonical serialization"))
	}
	coreBytes, err := json.Marshal(policy.StandingSourceAdmissionPolicyCore)
	if err != nil {
		issues = append(issues, issue("standing_policy_invalid", "policy", "standing policy payload could not be encoded"))
	} else {
		payloadDigest := digestBytes(coreBytes)
		if policy.PolicyPayloadSHA256 != payloadDigest || policy.PolicyID != "source-admission-policy:"+payloadDigest {
			issues = append(issues, issue("standing_policy_identity_mismatch", "policy", "standing policy ID and payload hash are not content-derived"))
		}
	}
	if policy.SchemaVersion != standingPolicySchemaVersion || policy.PolicyKind != standingPolicyKind || policy.State != "accepted" {
		issues = append(issues, issue("standing_policy_state_invalid", "policy", "only an accepted v1 standing source-admission policy is supported"))
	}
	if !stableIDPattern.MatchString(policy.Publisher.SourceIDPrefix) || !strings.HasSuffix(policy.Publisher.SourceIDPrefix, "@") ||
		!standingSourceIDSuffixPattern.MatchString(policy.Publisher.SourceIDSuffix) ||
		len(policy.Publisher.SourceIDPrefix)+len(policy.Publisher.SourceIDSuffix)+1 > maxStableIDBytes ||
		!stableIDPattern.MatchString(policy.Publisher.ComponentID) {
		issues = append(issues, issue("standing_publisher_identity_invalid", "policy.publisher", "publisher source prefix, exact source suffix, and component identity must form one bounded stable ID"))
	}
	if !strings.HasSuffix(policy.Publisher.CanonicalURIPrefix, "/") || validateCanonicalURI(policy.Publisher.CanonicalURIPrefix) != nil {
		issues = append(issues, issue("standing_publisher_uri_invalid", "policy.publisher.canonical_uri_prefix", "publisher URI prefix must be a canonical absolute HTTPS directory URI"))
	}
	if policy.Publisher.OriginKind != "official" && policy.Publisher.OriginKind != "primary" {
		issues = append(issues, issue("standing_publisher_origin_invalid", "policy.publisher.origin_kind", "publisher origin kind must be official or primary"))
	}
	issues = append(issues, validateSortedPolicyValues("policy.allowed_channel_types", policy.AllowedChannelTypes, channelTypes)...)
	issues = append(issues, validateSortedPolicyValues("policy.allowed_transports", policy.AllowedTransports, map[string]struct{}{"https": {}})...)
	if policy.VersionResolution.ResolvedVersionKind != "semver_tag" ||
		policy.VersionResolution.SourceRevisionKind != "git_commit_sha1" ||
		policy.VersionResolution.CanonicalRevisionBinding != "github_commit" ||
		policy.VersionResolution.TagPrefix != "v" {
		issues = append(issues, issue("standing_version_policy_unsupported", "policy.version_resolution", "v1 supports exact v-prefixed semantic-version tags bound to full GitHub commit IDs"))
	}
	if rightsIssues := validateRights(policy.RightsProfile.Rights); len(rightsIssues) != 0 {
		issues = append(issues, issue("standing_rights_profile_invalid", "policy.rights_profile", "standing rights profile is incomplete or unsupported"))
	}
	if policy.RightsProfile.AccessScope != "public" || policy.RightsProfile.Classification != "public" || policy.RightsProfile.SecurityDomain != "public" ||
		!languagePattern.MatchString(policy.RightsProfile.Language) {
		issues = append(issues, issue("standing_rights_profile_invalid", "policy.rights_profile", "v1 standing admission requires one explicit public security domain and language"))
	}
	if !reviewerPattern.MatchString(policy.ReviewerPrincipal) || !reviewerPattern.MatchString(policy.SignerPrincipal) ||
		policy.ReviewerPrincipal == policy.SignerPrincipal {
		issues = append(issues, issue("standing_principal_invalid", "policy", "policy reviewer and bounded signer must be distinct explicit principals"))
	}
	if !sha256Pattern.MatchString(policy.ReviewerKeySHA256) || !sha256Pattern.MatchString(policy.SignerKeySHA256) {
		issues = append(issues, issue("standing_key_identity_invalid", "policy", "reviewer and signer key identities must be full SHA-256 values"))
	} else if policy.ReviewerKeySHA256 == policy.SignerKeySHA256 {
		issues = append(issues, issue("standing_key_separation_invalid", "policy", "policy reviewer and bounded signer must use distinct Ed25519 keys"))
	}
	if policy.ValidationProfile != standingValidationProfile {
		issues = append(issues, issue("standing_validation_profile_unsupported", "policy.validation_profile", "standing policy validation profile is unsupported"))
	}
	limits := policy.ResourceLimits
	if limits.MaxFiles < 1 || limits.MaxFiles > defaultMaxFiles || limits.MaxFileBytes < 1 || limits.MaxFileBytes > defaultMaxFileBytes ||
		limits.MaxTotalBytes < 1 || limits.MaxTotalBytes > defaultMaxTotalBytes {
		issues = append(issues, issue("standing_resource_limits_invalid", "policy.resource_limits", "standing limits must be positive and no broader than compiler safe defaults"))
	}
	if !isCanonicalUTC(policy.EffectiveFrom) || !isCanonicalUTC(policy.EffectiveTo) || policy.EffectiveFrom >= policy.EffectiveTo {
		issues = append(issues, issue("standing_effective_interval_invalid", "policy", "standing policy requires one increasing canonical UTC effective interval"))
	}
	if policy.RevokedAt != "" {
		issues = append(issues, issue("standing_policy_revoked", "policy.revoked_at", "a revoked standing policy cannot admit new revisions"))
	}
	return sortedIssues(issues)
}

func validateSortedPolicyValues(field string, values []string, allowed map[string]struct{}) []QuarantineIssue {
	if len(values) == 0 || len(values) > 32 {
		return []QuarantineIssue{issue("standing_policy_collection_invalid", field, "standing policy collection must be non-empty and bounded")}
	}
	for index, value := range values {
		if _, ok := allowed[value]; !ok {
			return []QuarantineIssue{issue("standing_policy_value_unsupported", field, "standing policy collection contains an unsupported value")}
		}
		if index > 0 && values[index-1] >= value {
			return []QuarantineIssue{issue("standing_policy_collection_noncanonical", field, "standing policy collection must be sorted and unique")}
		}
	}
	return nil
}

func validateStandingPolicyReview(policyBytes []byte, policy StandingSourceAdmissionPolicy, signature, trust []byte) []QuarantineIssue {
	if err := validateAllowedSignersPolicy(trust, policy.ReviewerPrincipal); err != nil {
		return []QuarantineIssue{issue("standing_policy_trust_invalid", "policy_allowed_signers", "external reviewer trust must explicitly authorize one Ed25519 policy reviewer")}
	}
	keyDigest, err := principalKeyDigest(trust, policy.ReviewerPrincipal)
	if err != nil || keyDigest != policy.ReviewerKeySHA256 {
		return []QuarantineIssue{issue("standing_policy_reviewer_key_mismatch", "policy.reviewer_key_sha256", "standing policy reviewer key differs from the external trust root")}
	}
	if !canonicalArmoredSSHSIG(signature) {
		return []QuarantineIssue{issue("standing_policy_signature_invalid", "policy_signature", "standing policy signature must be a canonical armored SSHSIG")}
	}
	if err := verifySSHSIGNamespace(policyBytes, signature, trust, policy.ReviewerPrincipal, standingPolicySignatureNamespace); err != nil {
		return []QuarantineIssue{issue("standing_policy_signature_verification_failed", "policy_signature", "detached Ed25519 standing-policy verification failed")}
	}
	return nil
}

func validateStandingDecisionTime(value string) []QuarantineIssue {
	if strings.TrimSpace(value) == "" {
		return []QuarantineIssue{issue("standing_decision_time_missing", "decision_at", "standing admission requires an explicit decision time")}
	}
	if !isCanonicalUTC(value) {
		return []QuarantineIssue{issue("standing_decision_time_invalid", "decision_at", "standing admission decision time must be canonical RFC3339 UTC")}
	}
	return nil
}

func matchStandingPolicy(proposal InventoryProposal, policy StandingSourceAdmissionPolicy, decisionAtValue string) []QuarantineIssue {
	spec := proposal.SourceSpecDraft
	issues := make([]QuarantineIssue, 0)
	if spec.SourceID != policy.Publisher.SourceIDPrefix+spec.ResolvedVersion+policy.Publisher.SourceIDSuffix || spec.ComponentID != policy.Publisher.ComponentID || spec.Provenance.OriginKind != policy.Publisher.OriginKind ||
		!strings.HasPrefix(spec.CanonicalURI, policy.Publisher.CanonicalURIPrefix) {
		issues = append(issues, issue("standing_publisher_mismatch", "proposal.source_spec_draft", "proposal publisher identity does not exactly match the standing policy"))
	}
	parsedURI, err := url.Parse(spec.CanonicalURI)
	if err != nil || !contains(policy.AllowedTransports, parsedURI.Scheme) {
		issues = append(issues, issue("standing_transport_mismatch", "proposal.source_spec_draft.canonical_uri", "proposal transport is outside the standing policy"))
	}
	if !contains(policy.AllowedChannelTypes, spec.ChannelType) {
		issues = append(issues, issue("standing_channel_mismatch", "proposal.source_spec_draft.channel_type", "proposal channel class is outside the standing policy"))
	}
	rightsProfile := StandingRightsProfile{
		Rights:         spec.Rights,
		AccessScope:    spec.AccessScope,
		Classification: spec.Classification,
		SecurityDomain: spec.SecurityDomain,
		Language:       spec.Language,
	}
	if !reflect.DeepEqual(rightsProfile, policy.RightsProfile) {
		issues = append(issues, issue("standing_rights_mismatch", "proposal.source_spec_draft.rights", "proposal rights/use profile differs from the standing policy"))
	}
	if !matchesStandingVersion(spec, policy.VersionResolution) {
		issues = append(issues, issue("standing_version_resolution_mismatch", "proposal.source_spec_draft.resolved_version", "proposal version resolution differs from the standing policy"))
	}
	limits := compileLimits{
		maxFiles:      policy.ResourceLimits.MaxFiles,
		maxFileBytes:  policy.ResourceLimits.MaxFileBytes,
		maxTotalBytes: policy.ResourceLimits.MaxTotalBytes,
	}
	for _, item := range validateInventoryLimits(spec.Files, spec.Exclusions, limits) {
		issues = append(issues, issue("standing_resource_limit_exceeded", item.Path, "proposal exceeds the reviewed standing-policy resource limits"))
	}
	observedAt, observedErr := time.Parse(time.RFC3339, spec.ObservedAt)
	fetchedAt, fetchedErr := time.Parse(time.RFC3339, spec.FetchedAt)
	decisionAt, decisionErr := time.Parse(time.RFC3339, decisionAtValue)
	effectiveFrom, fromErr := time.Parse(time.RFC3339, policy.EffectiveFrom)
	effectiveTo, toErr := time.Parse(time.RFC3339, policy.EffectiveTo)
	if observedErr != nil || fetchedErr != nil || fetchedAt.After(observedAt) {
		issues = append(issues, issue("standing_observation_time_invalid", "proposal.source_spec_draft.observed_at", "proposal observation must not precede its acquisition"))
	}
	if decisionErr != nil {
		issues = append(issues, issue("standing_decision_time_invalid", "decision_at", "standing admission decision time must be canonical RFC3339 UTC"))
	} else if observedErr == nil && decisionAt.Before(observedAt) {
		issues = append(issues, issue("standing_decision_precedes_observation", "decision_at", "standing admission decision time must not precede the proposal observation"))
	}
	if decisionErr != nil || fromErr != nil || toErr != nil || decisionAt.Before(effectiveFrom) || !decisionAt.Before(effectiveTo) {
		issues = append(issues, issue("standing_policy_not_effective", "decision_at", "standing admission decision time is outside the policy effective interval"))
	}
	return sortedIssues(issues)
}

func matchesStandingVersion(spec SourceSpec, policy StandingVersionPolicy) bool {
	if policy.ResolvedVersionKind != "semver_tag" || policy.SourceRevisionKind != "git_commit_sha1" ||
		policy.CanonicalRevisionBinding != "github_commit" || !gitCommitPattern.MatchString(spec.SourceRevision) ||
		!githubURIContainsCommit(spec.CanonicalURI, spec.SourceRevision) || !strings.HasPrefix(spec.ResolvedVersion, policy.TagPrefix) {
		return false
	}
	version := strings.TrimPrefix(spec.ResolvedVersion, policy.TagPrefix)
	matches := strictSemverPattern.FindStringSubmatch(version)
	if matches == nil || (!policy.AllowPrerelease && matches[4] != "") {
		return false
	}
	return strings.HasSuffix(spec.ComponentVersionID, "@"+spec.ResolvedVersion)
}

func validateStandingSigner(config StandingAdmissionConfig, storeRoot string, policy StandingSourceAdmissionPolicy, trust []byte) []QuarantineIssue {
	if err := validateAllowedSignersPolicy(trust, policy.SignerPrincipal); err != nil {
		return []QuarantineIssue{issue("standing_signer_trust_invalid", "signer_allowed_signers", "external signer trust must explicitly authorize one Ed25519 bounded signer")}
	}
	trustDigest, err := principalKeyDigest(trust, policy.SignerPrincipal)
	if err != nil || trustDigest != policy.SignerKeySHA256 {
		return []QuarantineIssue{issue("standing_signer_key_mismatch", "policy.signer_key_sha256", "bounded signer key differs from the external signer trust root")}
	}
	privateDigest, err := privateSignerPublicDigest(config.SignerPrivateKeyPath, storeRoot)
	if err != nil || privateDigest != policy.SignerKeySHA256 {
		return []QuarantineIssue{issue("standing_signer_key_mismatch", "signer_key", "external private signer key does not match the reviewed bounded signer identity")}
	}
	return nil
}

func principalKeyDigest(policy []byte, principal string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(policy))
	digests := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "ssh-ed25519" {
			return "", errors.New("invalid allowed-signers entry")
		}
		if !contains(strings.Split(fields[0], ","), principal) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil || validateEd25519SSHBlob(fields[2]) != nil {
			return "", errors.New("invalid Ed25519 key")
		}
		digests[digestBytes(blob)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(digests) != 1 {
		return "", errors.New("principal has zero or ambiguous keys")
	}
	for digest := range digests {
		return digest, nil
	}
	return "", errors.New("principal key missing")
}

func privateSignerPublicDigest(keyPath, storeRoot string) (string, error) {
	if strings.TrimSpace(keyPath) == "" {
		return "", errors.New("private signer key is required")
	}
	if err := validateStandingSSHKeygen(); err != nil {
		return "", err
	}
	if err := validateExistingPathComponents(keyPath); err != nil {
		return "", err
	}
	before, err := os.Lstat(keyPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > maxPrivateSignerKeyBytes ||
		before.Mode().Perm()&0o077 != 0 || before.Mode().Perm()&0o400 == 0 {
		return "", errors.New("private signer key is unsafe")
	}
	keyAbs, err := filepath.Abs(keyPath)
	if err != nil {
		return "", err
	}
	storeAbs, err := filepath.Abs(storeRoot)
	if err != nil || isWithin(storeAbs, keyAbs) {
		return "", errors.New("private signer key must remain outside the output store")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-y", "-f", keyPath)
	command.Stdin = nil
	var public bytes.Buffer
	command.Stdout = &public
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || ctx.Err() != nil || public.Len() > 16*1024 {
		return "", errors.New("private signer public identity unavailable")
	}
	after, err := os.Lstat(keyPath)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return "", errors.New("private signer key changed during identity check")
	}
	fields := strings.Fields(public.String())
	if len(fields) < 2 || fields[0] != "ssh-ed25519" || validateEd25519SSHBlob(fields[1]) != nil {
		return "", errors.New("private signer is not Ed25519")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", err
	}
	return digestBytes(blob), nil
}

func signStandingReceipt(keyPath string, receipt []byte) ([]byte, error) {
	if err := validateStandingSSHKeygen(); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "knowledge-standing-sign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	receiptPath := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(receiptPath, receipt, 0o600); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-Y", "sign", "-q", "-f", keyPath,
		"-n", reviewSignatureNamespace, receiptPath)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || ctx.Err() != nil {
		return nil, errors.New("receipt signing failed")
	}
	signature, err := readBoundedRegular(receiptPath+".sig", maxReviewSignatureBytes)
	if err != nil || !canonicalArmoredSSHSIG(signature) {
		return nil, errors.New("receipt signature is invalid")
	}
	return signature, nil
}

func validateStandingSSHKeygen() error {
	const sshKeygenPath = "/usr/bin/ssh-keygen"
	if err := validateExistingPathComponents(sshKeygenPath); err != nil {
		return err
	}
	info, err := os.Lstat(sshKeygenPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("fixed ssh-keygen signer is unavailable")
	}
	return nil
}

func canonicalArmoredSSHSIG(signature []byte) bool {
	return bytes.HasPrefix(signature, []byte("-----BEGIN SSH SIGNATURE-----\n")) &&
		bytes.HasSuffix(signature, []byte("-----END SSH SIGNATURE-----\n"))
}

func standingAdmissionQuarantine(store *outputStore, inputs standingAdmissionInputs, issues []QuarantineIssue) error {
	issues = sortedIssues(issues)
	identityPayload, _ := json.Marshal(struct {
		ProposalDocumentSHA256 string            `json:"proposal_document_sha256"`
		PolicyDocumentSHA256   string            `json:"policy_document_sha256"`
		Issues                 []QuarantineIssue `json:"issues"`
	}{
		ProposalDocumentSHA256: inputs.proposalDocumentHash,
		PolicyDocumentSHA256:   inputs.policyDocumentHash,
		Issues:                 issues,
	})
	digest := digestBytes(identityPayload)
	report := StandingAdmissionQuarantineReport{
		SchemaVersion:          standingPolicySchemaVersion,
		ReportKind:             "standing_source_admission_quarantine",
		State:                  "quarantined",
		QuarantineID:           "standing-admission-quarantine:" + digest,
		ProposalDocumentSHA256: inputs.proposalDocumentHash,
		PolicyDocumentSHA256:   inputs.policyDocumentHash,
		ProposalID:             boundedReportScalar(inputs.proposal.ProposalID, maxReviewIdentityBytes),
		PolicyID:               boundedReportScalar(inputs.policy.PolicyID, maxReviewIdentityBytes),
		Issues:                 issues,
	}
	data, _ := marshalDocument(report)
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	relative := path.Join("standing-admission-quarantine", "sha256", hexDigest[:2], hexDigest+".json")
	reportPath := filepath.Join(store.path, filepath.FromSlash(relative))
	if err := store.writeImmutable(relative, data, 0o444); err != nil {
		return fmt.Errorf("standing admission invalid and quarantine write failed: %w", err)
	}
	return &StandingAdmissionRejectedError{ReportPath: reportPath, Issues: issues}
}

// newStandingPolicy is intentionally unexported production support for callers
// and tests that materialize a reviewed policy: identity is always derived from
// the exact core bytes, never supplied independently.
func newStandingPolicy(core StandingSourceAdmissionPolicyCore) (StandingSourceAdmissionPolicy, error) {
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return StandingSourceAdmissionPolicy{}, err
	}
	digest := digestBytes(coreBytes)
	return StandingSourceAdmissionPolicy{
		PolicyID:                          "source-admission-policy:" + digest,
		PolicyPayloadSHA256:               digest,
		StandingSourceAdmissionPolicyCore: core,
	}, nil
}
