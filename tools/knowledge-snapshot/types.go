package main

// SourceSpec is the reviewed, exact-version input contract for one local
// official-channel mirror. Every field is explicit so the compiler never
// invents authority, rights, language, version, or time metadata.
type SourceSpec struct {
	SchemaVersion      string              `json:"schema_version"`
	SnapshotID         string              `json:"snapshot_id"`
	SourceID           string              `json:"source_id"`
	CanonicalURI       string              `json:"canonical_uri"`
	ComponentID        string              `json:"component_id"`
	ComponentVersionID string              `json:"component_version_id"`
	ResolvedVersion    string              `json:"resolved_version"`
	SourceRevision     string              `json:"source_revision"`
	ChannelID          string              `json:"channel_id"`
	ChannelType        string              `json:"channel_type"`
	Rights             Rights              `json:"rights"`
	AccessScope        string              `json:"access_scope"`
	Classification     string              `json:"classification"`
	SecurityDomain     string              `json:"security_domain"`
	Language           string              `json:"language"`
	FetchedAt          string              `json:"fetched_at"`
	ObservedAt         string              `json:"observed_at"`
	MirrorPath         string              `json:"mirror_path"`
	Provenance         Provenance          `json:"provenance"`
	Exclusions         []VerifiedExclusion `json:"exclusions"`
	Files              []ExpectedFile      `json:"files"`
}

type Rights struct {
	LicenseExpression string            `json:"license_expression"`
	RightsBasis       string            `json:"rights_basis"`
	Attribution       string            `json:"attribution"`
	Permissions       map[string]string `json:"permissions"`
}

type Provenance struct {
	OriginKind      string `json:"origin_kind"`
	Generated       bool   `json:"generated"`
	RecursiveSource bool   `json:"recursive_source"`
}

type ExpectedFile struct {
	RelativePath string `json:"relative_path"`
	MediaType    string `json:"media_type"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

// InventoryMetadata is an explicit metadata candidate without a file
// inventory. The inventory command supplies only the deterministic file list
// and always wraps the result as an unreviewed, non-authoritative proposal.
type InventoryMetadata struct {
	SchemaVersion      string                   `json:"schema_version"`
	SnapshotID         string                   `json:"snapshot_id"`
	SourceID           string                   `json:"source_id"`
	CanonicalURI       string                   `json:"canonical_uri"`
	ComponentID        string                   `json:"component_id"`
	ComponentVersionID string                   `json:"component_version_id"`
	ResolvedVersion    string                   `json:"resolved_version"`
	SourceRevision     string                   `json:"source_revision"`
	ChannelID          string                   `json:"channel_id"`
	ChannelType        string                   `json:"channel_type"`
	Rights             Rights                   `json:"rights"`
	AccessScope        string                   `json:"access_scope"`
	Classification     string                   `json:"classification"`
	SecurityDomain     string                   `json:"security_domain"`
	Language           string                   `json:"language"`
	FetchedAt          string                   `json:"fetched_at"`
	ObservedAt         string                   `json:"observed_at"`
	MirrorPath         string                   `json:"mirror_path"`
	Provenance         Provenance               `json:"provenance"`
	Exclusions         []InventoryExclusionRule `json:"exclusions"`
}

type InventoryExclusionRule struct {
	RelativePath string `json:"relative_path"`
	PathKind     string `json:"path_kind"`
	SourceKind   string `json:"source_kind"`
	Reason       string `json:"reason"`
}

type VerifiedExclusion struct {
	RelativePath string `json:"relative_path"`
	MediaType    string `json:"media_type"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	SourceKind   string `json:"source_kind"`
	Reason       string `json:"reason"`
}

type InventoryProposal struct {
	ProposalID            string `json:"proposal_id"`
	ProposalPayloadSHA256 string `json:"proposal_payload_sha256"`
	InventoryProposalCore
}

type InventoryProposalCore struct {
	SchemaVersion     string              `json:"schema_version"`
	ProposalKind      string              `json:"proposal_kind"`
	State             string              `json:"state"`
	ReviewState       string              `json:"review_state"`
	AuthorityState    string              `json:"authority_state"`
	CompileEligible   bool                `json:"compile_eligible"`
	PromoteEligible   bool                `json:"promote_eligible"`
	MetadataSHA256    string              `json:"metadata_sha256"`
	FileCount         int                 `json:"file_count"`
	ByteSize          int64               `json:"byte_size"`
	ExcludedFileCount int                 `json:"excluded_file_count"`
	ExcludedByteSize  int64               `json:"excluded_byte_size"`
	Exclusions        []VerifiedExclusion `json:"exclusions"`
	SourceSpecDraft   SourceSpec          `json:"source_spec_draft"`
}

type InventoryQuarantineReport struct {
	SchemaVersion      string            `json:"schema_version"`
	ReportKind         string            `json:"report_kind"`
	State              string            `json:"state"`
	QuarantineID       string            `json:"quarantine_id"`
	MetadataSHA256     string            `json:"metadata_sha256"`
	SnapshotID         string            `json:"snapshot_id,omitempty"`
	SourceID           string            `json:"source_id,omitempty"`
	ComponentID        string            `json:"component_id,omitempty"`
	ComponentVersionID string            `json:"component_version_id,omitempty"`
	ChannelID          string            `json:"channel_id,omitempty"`
	Issues             []QuarantineIssue `json:"issues"`
}

type InventoryConfig struct {
	MetadataPath  string
	MirrorBase    string
	ProposalStore string
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

type InventoryResult struct {
	Proposal     InventoryProposal
	ProposalPath string
}

type InventoryRejectedError struct {
	ReportPath string
	Issues     []QuarantineIssue
}

func (e *InventoryRejectedError) Error() string {
	return "inventory proposal input quarantined"
}

type SnapshotManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	SnapshotManifestCore
}

type SnapshotManifestCore struct {
	SchemaVersion     string              `json:"schema_version"`
	ManifestKind      string              `json:"manifest_kind"`
	State             string              `json:"state"`
	AuthorityState    string              `json:"authority_state"`
	ReviewAdmission   ReviewAdmission     `json:"review_admission"`
	SnapshotID        string              `json:"snapshot_id"`
	SourceSpecSHA256  string              `json:"source_spec_sha256"`
	Source            SourceLineage       `json:"source"`
	TreeSHA256        string              `json:"tree_sha256"`
	FileCount         int                 `json:"file_count"`
	ByteSize          int64               `json:"byte_size"`
	UniqueBlobCount   int                 `json:"unique_blob_count"`
	ObjectLayout      string              `json:"object_layout"`
	ExcludedFileCount int                 `json:"excluded_file_count"`
	ExcludedByteSize  int64               `json:"excluded_byte_size"`
	Exclusions        []VerifiedExclusion `json:"exclusions"`
	Files             []ManifestFile      `json:"files"`
}

type SourceSpecReviewReceipt struct {
	SchemaVersion         string `json:"schema_version"`
	ReceiptKind           string `json:"receipt_kind"`
	ProposalID            string `json:"proposal_id"`
	ProposalPayloadSHA256 string `json:"proposal_payload_sha256"`
	SourceSpecSHA256      string `json:"source_spec_sha256"`
	Reviewer              string `json:"reviewer"`
	Decision              string `json:"decision"`
	ReviewedAt            string `json:"reviewed_at"`
	AdmissionMethod       string `json:"admission_method,omitempty"`
	AdmissionPolicyID     string `json:"admission_policy_id,omitempty"`
	AdmissionPolicySHA256 string `json:"admission_policy_sha256,omitempty"`
}

type ReviewAdmission struct {
	ReceiptSHA256          string `json:"receipt_sha256"`
	ReceiptSize            int64  `json:"receipt_size"`
	ReceiptObjectPath      string `json:"receipt_object_path"`
	ProposalID             string `json:"proposal_id"`
	ProposalPayloadSHA256  string `json:"proposal_payload_sha256"`
	ProposalDocumentSHA256 string `json:"proposal_document_sha256"`
	ProposalDocumentSize   int64  `json:"proposal_document_size"`
	ProposalObjectPath     string `json:"proposal_object_path"`
	SourceSpecSHA256       string `json:"source_spec_sha256"`
	SourceSpecSize         int64  `json:"source_spec_size"`
	SourceSpecObjectPath   string `json:"source_spec_object_path"`
	Reviewer               string `json:"reviewer"`
	Decision               string `json:"decision"`
	ReviewedAt             string `json:"reviewed_at"`
	SignatureFormat        string `json:"signature_format"`
	SignatureNamespace     string `json:"signature_namespace"`
	SignatureSHA256        string `json:"signature_sha256"`
	SignatureSize          int64  `json:"signature_size"`
	SignatureObjectPath    string `json:"signature_object_path"`
	TrustPolicySHA256      string `json:"trust_policy_sha256"`
	TrustPolicySize        int64  `json:"trust_policy_size"`
	TrustPolicyObjectPath  string `json:"trust_policy_object_path"`
	AdmissionMethod        string `json:"admission_method,omitempty"`
	AdmissionPolicyID      string `json:"admission_policy_id,omitempty"`
	AdmissionPolicySHA256  string `json:"admission_policy_sha256,omitempty"`
}

// StandingSourceAdmissionPolicy is a separately reviewed authorization for a
// bounded service identity to accept recurring official immutable revisions.
// The content-derived identity excludes only its two self-referential fields.
type StandingSourceAdmissionPolicy struct {
	PolicyID            string `json:"policy_id"`
	PolicyPayloadSHA256 string `json:"policy_payload_sha256"`
	StandingSourceAdmissionPolicyCore
}

type StandingSourceAdmissionPolicyCore struct {
	SchemaVersion       string                  `json:"schema_version"`
	PolicyKind          string                  `json:"policy_kind"`
	State               string                  `json:"state"`
	Publisher           StandingPublisherPolicy `json:"publisher"`
	AllowedChannelTypes []string                `json:"allowed_channel_types"`
	AllowedTransports   []string                `json:"allowed_transports"`
	VersionResolution   StandingVersionPolicy   `json:"version_resolution"`
	RightsProfile       StandingRightsProfile   `json:"rights_profile"`
	ReviewerPrincipal   string                  `json:"reviewer_principal"`
	ReviewerKeySHA256   string                  `json:"reviewer_key_sha256"`
	SignerPrincipal     string                  `json:"signer_principal"`
	SignerKeySHA256     string                  `json:"signer_key_sha256"`
	ValidationProfile   string                  `json:"validation_profile"`
	ResourceLimits      StandingResourceLimits  `json:"resource_limits"`
	EffectiveFrom       string                  `json:"effective_from"`
	EffectiveTo         string                  `json:"effective_to"`
	RevokedAt           string                  `json:"revoked_at"`
}

type StandingPublisherPolicy struct {
	SourceIDPrefix     string `json:"source_id_prefix"`
	SourceIDSuffix     string `json:"source_id_suffix"`
	ComponentID        string `json:"component_id"`
	CanonicalURIPrefix string `json:"canonical_uri_prefix"`
	OriginKind         string `json:"origin_kind"`
}

type StandingVersionPolicy struct {
	ResolvedVersionKind      string `json:"resolved_version_kind"`
	SourceRevisionKind       string `json:"source_revision_kind"`
	CanonicalRevisionBinding string `json:"canonical_revision_binding"`
	TagPrefix                string `json:"tag_prefix"`
	AllowPrerelease          bool   `json:"allow_prerelease"`
}

type StandingRightsProfile struct {
	Rights         Rights `json:"rights"`
	AccessScope    string `json:"access_scope"`
	Classification string `json:"classification"`
	SecurityDomain string `json:"security_domain"`
	Language       string `json:"language"`
}

type StandingResourceLimits struct {
	MaxFiles      int   `json:"max_files"`
	MaxFileBytes  int64 `json:"max_file_bytes"`
	MaxTotalBytes int64 `json:"max_total_bytes"`
}

type StandingAdmissionManifest struct {
	AdmissionID            string `json:"admission_id"`
	AdmissionPayloadSHA256 string `json:"admission_payload_sha256"`
	StandingAdmissionManifestCore
}

type StandingAdmissionManifestCore struct {
	SchemaVersion              string `json:"schema_version"`
	ManifestKind               string `json:"manifest_kind"`
	State                      string `json:"state"`
	AuthorityState             string `json:"authority_state"`
	AdmissionMethod            string `json:"admission_method"`
	CompileEligible            bool   `json:"compile_eligible"`
	PromoteEligible            bool   `json:"promote_eligible"`
	ProposalID                 string `json:"proposal_id"`
	ProposalPayloadSHA256      string `json:"proposal_payload_sha256"`
	ProposalDocumentSHA256     string `json:"proposal_document_sha256"`
	ProposalObjectPath         string `json:"proposal_object_path"`
	SourceSpecSHA256           string `json:"source_spec_sha256"`
	SourceSpecObjectPath       string `json:"source_spec_object_path"`
	PolicyID                   string `json:"policy_id"`
	PolicyPayloadSHA256        string `json:"policy_payload_sha256"`
	PolicyDocumentSHA256       string `json:"policy_document_sha256"`
	PolicyObjectPath           string `json:"policy_object_path"`
	PolicySignatureSHA256      string `json:"policy_signature_sha256"`
	PolicySignatureObjectPath  string `json:"policy_signature_object_path"`
	PolicySignatureNamespace   string `json:"policy_signature_namespace"`
	PolicyTrustSHA256          string `json:"policy_trust_sha256"`
	PolicyTrustObjectPath      string `json:"policy_trust_object_path"`
	PolicyReviewer             string `json:"policy_reviewer"`
	PolicyReviewerKeySHA256    string `json:"policy_reviewer_key_sha256"`
	Signer                     string `json:"signer"`
	SignerKeySHA256            string `json:"signer_key_sha256"`
	SignerTrustSHA256          string `json:"signer_trust_sha256"`
	SignerTrustObjectPath      string `json:"signer_trust_object_path"`
	ReceiptSHA256              string `json:"receipt_sha256"`
	ReceiptObjectPath          string `json:"receipt_object_path"`
	ReceiptSignatureSHA256     string `json:"receipt_signature_sha256"`
	ReceiptSignatureObjectPath string `json:"receipt_signature_object_path"`
	ReceiptSignatureNamespace  string `json:"receipt_signature_namespace"`
	AdmittedAt                 string `json:"admitted_at"`
}

type StandingAdmissionConfig struct {
	ProposalPath             string
	PolicyPath               string
	PolicySignaturePath      string
	PolicyAllowedSignersPath string
	SignerPrivateKeyPath     string
	SignerAllowedSignersPath string
	DecisionAt               string
	StoreRoot                string
}

type StandingAdmissionResult struct {
	Manifest            StandingAdmissionManifest
	ManifestPath        string
	SourceSpecPath      string
	ReviewReceiptPath   string
	ReviewSignaturePath string
}

type StandingAdmissionQuarantineReport struct {
	SchemaVersion          string            `json:"schema_version"`
	ReportKind             string            `json:"report_kind"`
	State                  string            `json:"state"`
	QuarantineID           string            `json:"quarantine_id"`
	ProposalDocumentSHA256 string            `json:"proposal_document_sha256"`
	PolicyDocumentSHA256   string            `json:"policy_document_sha256"`
	ProposalID             string            `json:"proposal_id,omitempty"`
	PolicyID               string            `json:"policy_id,omitempty"`
	Issues                 []QuarantineIssue `json:"issues"`
}

type StandingAdmissionRejectedError struct {
	ReportPath string
	Issues     []QuarantineIssue
}

func (e *StandingAdmissionRejectedError) Error() string {
	return "standing source admission quarantined"
}

type SourceLineage struct {
	SourceID           string `json:"source_id"`
	CanonicalURI       string `json:"canonical_uri"`
	ComponentID        string `json:"component_id"`
	ComponentVersionID string `json:"component_version_id"`
	ResolvedVersion    string `json:"resolved_version"`
	SourceRevision     string `json:"source_revision"`
	ChannelID          string `json:"channel_id"`
	ChannelType        string `json:"channel_type"`
	Rights             Rights `json:"rights"`
	AccessScope        string `json:"access_scope"`
	Classification     string `json:"classification"`
	SecurityDomain     string `json:"security_domain"`
	Language           string `json:"language"`
	FetchedAt          string `json:"fetched_at"`
	ObservedAt         string `json:"observed_at"`
	OriginKind         string `json:"origin_kind"`
}

type ManifestFile struct {
	RelativePath       string `json:"relative_path"`
	MediaType          string `json:"media_type"`
	SHA256             string `json:"sha256"`
	Size               int64  `json:"size"`
	RawBlobID          string `json:"raw_blob_id"`
	ObjectPath         string `json:"object_path"`
	SnapshotID         string `json:"snapshot_id"`
	SourceID           string `json:"source_id"`
	ComponentID        string `json:"component_id"`
	ComponentVersionID string `json:"component_version_id"`
	ChannelID          string `json:"channel_id"`
}

type QuarantineIssue struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type QuarantineReport struct {
	SchemaVersion      string            `json:"schema_version"`
	ReportKind         string            `json:"report_kind"`
	State              string            `json:"state"`
	QuarantineID       string            `json:"quarantine_id"`
	SourceSpecSHA256   string            `json:"source_spec_sha256"`
	SnapshotID         string            `json:"snapshot_id,omitempty"`
	SourceID           string            `json:"source_id,omitempty"`
	ComponentID        string            `json:"component_id,omitempty"`
	ComponentVersionID string            `json:"component_version_id,omitempty"`
	ChannelID          string            `json:"channel_id,omitempty"`
	Issues             []QuarantineIssue `json:"issues"`
}

type CompileConfig struct {
	SpecPath            string
	ProposalPath        string
	ReviewReceiptPath   string
	ReviewSignaturePath string
	AllowedSignersPath  string
	MirrorBase          string
	StoreRoot           string
	MaxFiles            int
	MaxFileBytes        int64
	MaxTotalBytes       int64
}

type CompileResult struct {
	Manifest     SnapshotManifest
	ManifestPath string
}

type ChangePackManifest struct {
	ChangePackID            string `json:"change_pack_id"`
	ChangePackPayloadSHA256 string `json:"change_pack_payload_sha256"`
	ChangePackManifestCore
}

type ChangePackManifestCore struct {
	SchemaVersion   string                 `json:"schema_version"`
	ManifestKind    string                 `json:"manifest_kind"`
	State           string                 `json:"state"`
	AuthorityState  string                 `json:"authority_state"`
	PromoteEligible bool                   `json:"promote_eligible"`
	OrderingBasis   string                 `json:"ordering_basis"`
	ObjectLayout    string                 `json:"object_layout"`
	OldSnapshot     SnapshotBinding        `json:"old_snapshot"`
	NewSnapshot     SnapshotBinding        `json:"new_snapshot"`
	Counts          ChangePackCounts       `json:"counts"`
	Changes         []FileOccurrenceChange `json:"changes"`
}

type SnapshotBinding struct {
	ManifestID            string          `json:"manifest_id"`
	ManifestPayloadSHA256 string          `json:"manifest_payload_sha256"`
	SnapshotID            string          `json:"snapshot_id"`
	SourceSpecSHA256      string          `json:"source_spec_sha256"`
	TreeSHA256            string          `json:"tree_sha256"`
	FileCount             int             `json:"file_count"`
	ByteSize              int64           `json:"byte_size"`
	Source                SourceLineage   `json:"source"`
	ReviewAdmission       ReviewAdmission `json:"review_admission"`
}

type ChangePackCounts struct {
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
}

type FileOccurrenceVersion struct {
	MediaType  string `json:"media_type"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	RawBlobID  string `json:"raw_blob_id"`
	ObjectPath string `json:"object_path"`
}

type FileOccurrenceChange struct {
	RelativePath string                 `json:"relative_path"`
	ChangeType   string                 `json:"change_type"`
	Old          *FileOccurrenceVersion `json:"old,omitempty"`
	New          *FileOccurrenceVersion `json:"new,omitempty"`
}

type ChangePackConfig struct {
	OldManifestPath       string
	OldStoreRoot          string
	OldAllowedSignersPath string
	NewManifestPath       string
	NewStoreRoot          string
	NewAllowedSignersPath string
	StoreRoot             string
}

type ChangePackResult struct {
	Manifest     ChangePackManifest
	ManifestPath string
}

type ChangePackRejectedError struct {
	Issues []QuarantineIssue
}

func (e *ChangePackRejectedError) Error() string {
	return "change-pack input rejected"
}

type QuarantinedError struct {
	ReportPath string
	Issues     []QuarantineIssue
}

func (e *QuarantinedError) Error() string {
	return "snapshot input quarantined"
}
