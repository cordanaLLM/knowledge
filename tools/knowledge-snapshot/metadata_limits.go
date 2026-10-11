package main

import "fmt"

const (
	maxSchemaScalarBytes       = 32
	maxStableIDBytes           = 512
	maxCanonicalURIBytes       = 4096
	maxVersionScalarBytes      = 512
	maxChannelTypeBytes        = 64
	maxRightsExpressionBytes   = 4096
	maxRightsBasisBytes        = 8192
	maxAttributionBytes        = 16 * 1024
	maxSecurityScalarBytes     = 64
	maxLanguageBytes           = 64
	maxTimestampBytes          = 64
	maxMirrorPathBytes         = 4096
	maxOriginKindBytes         = 64
	maxPermissionEntries       = 16
	maxPermissionKeyBytes      = 64
	maxPermissionValueBytes    = 32
	maxRelativePathBytes       = 4096
	maxMediaTypeBytes          = 256
	maxExclusionReasonBytes    = 4096
	maxSourceKindBytes         = 64
	maxReviewIdentityBytes     = 512
	maxReviewDecisionBytes     = 32
	maxSignatureMetadataBytes  = 128
	maxSourceInventoryEntries  = 100_000
	maxAllowedSignerEntries    = 256
	maxPrincipalsPerSignerLine = 32

	maxSourceSpecBytes        = int64(32 * 1024 * 1024)
	maxInventoryProposalBytes = int64(40 * 1024 * 1024)
	maxSnapshotManifestBytes  = int64(64 * 1024 * 1024)
	maxReviewBundleBytes      = int64(64 * 1024 * 1024)
	maxChangePackBytes        = int64(64 * 1024 * 1024)
)

type boundedScalar struct {
	field string
	value string
	max   int
}

func validateScalarBounds(values []boundedScalar) []QuarantineIssue {
	issues := make([]QuarantineIssue, 0)
	for _, value := range values {
		if len(value.value) > value.max {
			issues = append(issues, issue("metadata_scalar_limit_exceeded", value.field,
				fmt.Sprintf("metadata scalar exceeds the %d-byte schema limit", value.max)))
		}
	}
	return issues
}

func validateSourceMetadataBounds(spec SourceSpec) []QuarantineIssue {
	issues := validateScalarBounds([]boundedScalar{
		{"schema_version", spec.SchemaVersion, maxSchemaScalarBytes},
		{"snapshot_id", spec.SnapshotID, maxStableIDBytes},
		{"source_id", spec.SourceID, maxStableIDBytes},
		{"canonical_uri", spec.CanonicalURI, maxCanonicalURIBytes},
		{"component_id", spec.ComponentID, maxStableIDBytes},
		{"component_version_id", spec.ComponentVersionID, maxStableIDBytes},
		{"resolved_version", spec.ResolvedVersion, maxVersionScalarBytes},
		{"source_revision", spec.SourceRevision, maxVersionScalarBytes},
		{"channel_id", spec.ChannelID, maxStableIDBytes},
		{"channel_type", spec.ChannelType, maxChannelTypeBytes},
		{"rights.license_expression", spec.Rights.LicenseExpression, maxRightsExpressionBytes},
		{"rights.rights_basis", spec.Rights.RightsBasis, maxRightsBasisBytes},
		{"rights.attribution", spec.Rights.Attribution, maxAttributionBytes},
		{"access_scope", spec.AccessScope, maxSecurityScalarBytes},
		{"classification", spec.Classification, maxSecurityScalarBytes},
		{"security_domain", spec.SecurityDomain, maxSecurityScalarBytes},
		{"language", spec.Language, maxLanguageBytes},
		{"fetched_at", spec.FetchedAt, maxTimestampBytes},
		{"observed_at", spec.ObservedAt, maxTimestampBytes},
		{"mirror_path", spec.MirrorPath, maxMirrorPathBytes},
		{"provenance.origin_kind", spec.Provenance.OriginKind, maxOriginKindBytes},
	})
	if len(spec.Rights.Permissions) > maxPermissionEntries {
		issues = append(issues, issue("metadata_collection_limit_exceeded", "rights.permissions",
			"permission map exceeds the schema entry limit"))
		return issues
	}
	for key, value := range spec.Rights.Permissions {
		issues = append(issues, validateScalarBounds([]boundedScalar{
			{"rights.permissions.<key>", key, maxPermissionKeyBytes},
			{"rights.permissions." + key, value, maxPermissionValueBytes},
		})...)
	}
	return issues
}

func validateSourceCollections(spec SourceSpec) []QuarantineIssue {
	if len(spec.Files) > maxSourceInventoryEntries || len(spec.Exclusions) > maxSourceInventoryEntries ||
		len(spec.Files) > maxSourceInventoryEntries-len(spec.Exclusions) {
		return []QuarantineIssue{issue("metadata_collection_limit_exceeded", "files",
			"source file and exclusion collections exceed the absolute schema entry limit")}
	}
	return nil
}

func validateExpectedFileBounds(file ExpectedFile, fieldPath string) []QuarantineIssue {
	return validateScalarBounds([]boundedScalar{
		{fieldPath + ".relative_path", file.RelativePath, maxRelativePathBytes},
		{fieldPath + ".media_type", file.MediaType, maxMediaTypeBytes},
		{fieldPath + ".sha256", file.SHA256, len("sha256:") + 64},
	})
}

func validateVerifiedExclusionBounds(exclusion VerifiedExclusion, fieldPath string) []QuarantineIssue {
	return validateScalarBounds([]boundedScalar{
		{fieldPath + ".relative_path", exclusion.RelativePath, maxRelativePathBytes},
		{fieldPath + ".media_type", exclusion.MediaType, maxMediaTypeBytes},
		{fieldPath + ".sha256", exclusion.SHA256, len("sha256:") + 64},
		{fieldPath + ".source_kind", exclusion.SourceKind, maxSourceKindBytes},
		{fieldPath + ".reason", exclusion.Reason, maxExclusionReasonBytes},
	})
}

func validateInventoryExclusionBounds(exclusion InventoryExclusionRule, fieldPath string) []QuarantineIssue {
	return validateScalarBounds([]boundedScalar{
		{fieldPath + ".relative_path", exclusion.RelativePath, maxRelativePathBytes},
		{fieldPath + ".path_kind", exclusion.PathKind, maxSourceKindBytes},
		{fieldPath + ".source_kind", exclusion.SourceKind, maxSourceKindBytes},
		{fieldPath + ".reason", exclusion.Reason, maxExclusionReasonBytes},
	})
}

func validateReviewReceiptBounds(receipt SourceSpecReviewReceipt) []QuarantineIssue {
	return validateScalarBounds([]boundedScalar{
		{"review_receipt.schema_version", receipt.SchemaVersion, maxSchemaScalarBytes},
		{"review_receipt.receipt_kind", receipt.ReceiptKind, maxReviewIdentityBytes},
		{"review_receipt.proposal_id", receipt.ProposalID, maxReviewIdentityBytes},
		{"review_receipt.proposal_payload_sha256", receipt.ProposalPayloadSHA256, len("sha256:") + 64},
		{"review_receipt.source_spec_sha256", receipt.SourceSpecSHA256, len("sha256:") + 64},
		{"review_receipt.reviewer", receipt.Reviewer, 128},
		{"review_receipt.decision", receipt.Decision, maxReviewDecisionBytes},
		{"review_receipt.reviewed_at", receipt.ReviewedAt, maxTimestampBytes},
		{"review_receipt.admission_method", receipt.AdmissionMethod, maxReviewDecisionBytes},
		{"review_receipt.admission_policy_id", receipt.AdmissionPolicyID, maxReviewIdentityBytes},
		{"review_receipt.admission_policy_sha256", receipt.AdmissionPolicySHA256, len("sha256:") + 64},
	})
}

func validateProposalMetadataBounds(proposal InventoryProposal) []QuarantineIssue {
	issues := validateScalarBounds([]boundedScalar{
		{"proposal.proposal_id", proposal.ProposalID, maxReviewIdentityBytes},
		{"proposal.proposal_payload_sha256", proposal.ProposalPayloadSHA256, len("sha256:") + 64},
		{"proposal.schema_version", proposal.SchemaVersion, maxSchemaScalarBytes},
		{"proposal.proposal_kind", proposal.ProposalKind, maxReviewIdentityBytes},
		{"proposal.state", proposal.State, maxReviewDecisionBytes},
		{"proposal.review_state", proposal.ReviewState, maxReviewDecisionBytes},
		{"proposal.authority_state", proposal.AuthorityState, maxReviewIdentityBytes},
		{"proposal.metadata_sha256", proposal.MetadataSHA256, len("sha256:") + 64},
	})
	if len(proposal.Exclusions) > maxSourceInventoryEntries {
		issues = append(issues, issue("metadata_collection_limit_exceeded", "proposal.exclusions",
			"proposal exclusion collection exceeds the absolute schema entry limit"))
		return issues
	}
	for index, exclusion := range proposal.Exclusions {
		issues = append(issues, validateVerifiedExclusionBounds(exclusion,
			fmt.Sprintf("proposal.exclusions[%d]", index))...)
	}
	return issues
}

func validateReviewAdmissionBounds(admission ReviewAdmission) []QuarantineIssue {
	return validateScalarBounds([]boundedScalar{
		{"review_admission.receipt_sha256", admission.ReceiptSHA256, len("sha256:") + 64},
		{"review_admission.receipt_object_path", admission.ReceiptObjectPath, maxRelativePathBytes},
		{"review_admission.proposal_id", admission.ProposalID, maxReviewIdentityBytes},
		{"review_admission.proposal_payload_sha256", admission.ProposalPayloadSHA256, len("sha256:") + 64},
		{"review_admission.proposal_document_sha256", admission.ProposalDocumentSHA256, len("sha256:") + 64},
		{"review_admission.proposal_object_path", admission.ProposalObjectPath, maxRelativePathBytes},
		{"review_admission.source_spec_sha256", admission.SourceSpecSHA256, len("sha256:") + 64},
		{"review_admission.source_spec_object_path", admission.SourceSpecObjectPath, maxRelativePathBytes},
		{"review_admission.reviewer", admission.Reviewer, 128},
		{"review_admission.decision", admission.Decision, maxReviewDecisionBytes},
		{"review_admission.reviewed_at", admission.ReviewedAt, maxTimestampBytes},
		{"review_admission.signature_format", admission.SignatureFormat, maxSignatureMetadataBytes},
		{"review_admission.signature_namespace", admission.SignatureNamespace, maxSignatureMetadataBytes},
		{"review_admission.signature_sha256", admission.SignatureSHA256, len("sha256:") + 64},
		{"review_admission.signature_object_path", admission.SignatureObjectPath, maxRelativePathBytes},
		{"review_admission.trust_policy_sha256", admission.TrustPolicySHA256, len("sha256:") + 64},
		{"review_admission.trust_policy_object_path", admission.TrustPolicyObjectPath, maxRelativePathBytes},
		{"review_admission.admission_method", admission.AdmissionMethod, maxReviewDecisionBytes},
		{"review_admission.admission_policy_id", admission.AdmissionPolicyID, maxReviewIdentityBytes},
		{"review_admission.admission_policy_sha256", admission.AdmissionPolicySHA256, len("sha256:") + 64},
	})
}

func boundedReportScalar(value string, maximum int) string {
	if len(value) > maximum {
		return ""
	}
	return value
}

func validateSnapshotDocumentBounds(manifest SnapshotManifest) []QuarantineIssue {
	issues := validateScalarBounds([]boundedScalar{
		{"manifest_id", manifest.ManifestID, maxReviewIdentityBytes},
		{"manifest_payload_sha256", manifest.ManifestPayloadSHA256, len("sha256:") + 64},
		{"schema_version", manifest.SchemaVersion, maxSchemaScalarBytes},
		{"manifest_kind", manifest.ManifestKind, maxReviewIdentityBytes},
		{"state", manifest.State, maxReviewDecisionBytes},
		{"authority_state", manifest.AuthorityState, maxReviewIdentityBytes},
		{"snapshot_id", manifest.SnapshotID, maxStableIDBytes},
		{"source_spec_sha256", manifest.SourceSpecSHA256, len("sha256:") + 64},
		{"tree_sha256", manifest.TreeSHA256, len("sha256:") + 64},
		{"object_layout", manifest.ObjectLayout, maxReviewIdentityBytes},
	})
	issues = append(issues, validateReviewAdmissionBounds(manifest.ReviewAdmission)...)
	lineage := SourceSpec{
		SnapshotID:         manifest.SnapshotID,
		SourceID:           manifest.Source.SourceID,
		CanonicalURI:       manifest.Source.CanonicalURI,
		ComponentID:        manifest.Source.ComponentID,
		ComponentVersionID: manifest.Source.ComponentVersionID,
		ResolvedVersion:    manifest.Source.ResolvedVersion,
		SourceRevision:     manifest.Source.SourceRevision,
		ChannelID:          manifest.Source.ChannelID,
		ChannelType:        manifest.Source.ChannelType,
		Rights:             manifest.Source.Rights,
		AccessScope:        manifest.Source.AccessScope,
		Classification:     manifest.Source.Classification,
		SecurityDomain:     manifest.Source.SecurityDomain,
		Language:           manifest.Source.Language,
		FetchedAt:          manifest.Source.FetchedAt,
		ObservedAt:         manifest.Source.ObservedAt,
		Provenance:         Provenance{OriginKind: manifest.Source.OriginKind},
	}
	issues = append(issues, validateSourceMetadataBounds(lineage)...)
	if len(manifest.Files) > maxSourceInventoryEntries || len(manifest.Exclusions) > maxSourceInventoryEntries ||
		len(manifest.Files) > maxSourceInventoryEntries-len(manifest.Exclusions) {
		issues = append(issues, issue("metadata_collection_limit_exceeded", "files",
			"snapshot file and exclusion collections exceed the absolute schema entry limit"))
		return issues
	}
	for index, file := range manifest.Files {
		fieldPath := fmt.Sprintf("files[%d]", index)
		issues = append(issues, validateScalarBounds([]boundedScalar{
			{fieldPath + ".relative_path", file.RelativePath, maxRelativePathBytes},
			{fieldPath + ".media_type", file.MediaType, maxMediaTypeBytes},
			{fieldPath + ".sha256", file.SHA256, len("sha256:") + 64},
			{fieldPath + ".raw_blob_id", file.RawBlobID, maxReviewIdentityBytes},
			{fieldPath + ".object_path", file.ObjectPath, maxRelativePathBytes},
			{fieldPath + ".snapshot_id", file.SnapshotID, maxStableIDBytes},
			{fieldPath + ".source_id", file.SourceID, maxStableIDBytes},
			{fieldPath + ".component_id", file.ComponentID, maxStableIDBytes},
			{fieldPath + ".component_version_id", file.ComponentVersionID, maxStableIDBytes},
			{fieldPath + ".channel_id", file.ChannelID, maxStableIDBytes},
		})...)
	}
	for index, exclusion := range manifest.Exclusions {
		issues = append(issues, validateVerifiedExclusionBounds(exclusion, fmt.Sprintf("exclusions[%d]", index))...)
	}
	return issues
}
