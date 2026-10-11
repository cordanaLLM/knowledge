package main

// These input types intentionally mirror knowledge-snapshot schema 1.0.0.
// Keeping a strict local copy prevents an evidence build from silently
// accepting a newer acquisition contract it does not understand.
type Rights struct {
	LicenseExpression string            `json:"license_expression"`
	RightsBasis       string            `json:"rights_basis"`
	Attribution       string            `json:"attribution"`
	Permissions       map[string]string `json:"permissions"`
}

type VerifiedExclusion struct {
	RelativePath string `json:"relative_path"`
	MediaType    string `json:"media_type"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	SourceKind   string `json:"source_kind"`
	Reason       string `json:"reason"`
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

type InventoryProposal struct {
	ProposalID            string `json:"proposal_id"`
	ProposalPayloadSHA256 string `json:"proposal_payload_sha256"`
	InventoryProposalCore
}

type SourceReviewReceipt struct {
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

type SnapshotManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	SnapshotManifestCore
}

type EvidenceSpan struct {
	SpanID            string   `json:"span_id"`
	Ordinal           int      `json:"ordinal"`
	Kind              string   `json:"kind"`
	HeadingBreadcrumb []string `json:"heading_breadcrumb"`
	RawByteStart      int64    `json:"raw_byte_start"`
	RawByteEnd        int64    `json:"raw_byte_end"`
	RawLineStart      int      `json:"raw_line_start"`
	RawLineEnd        int      `json:"raw_line_end"`
	PayloadSHA256     string   `json:"payload_sha256"`
	PayloadID         string   `json:"payload_id"`
	ObjectPath        string   `json:"object_path"`
	ByteSize          int64    `json:"byte_size"`
	TrustEnvelopeID   string   `json:"trust_envelope_id"`
}

type EvidenceFile struct {
	OccurrenceID       string         `json:"occurrence_id"`
	RelativePath       string         `json:"relative_path"`
	MediaType          string         `json:"media_type"`
	RawSHA256          string         `json:"raw_sha256"`
	RawBlobID          string         `json:"raw_blob_id"`
	RawObjectPath      string         `json:"raw_object_path"`
	RawByteSize        int64          `json:"raw_byte_size"`
	SnapshotID         string         `json:"snapshot_id"`
	SourceID           string         `json:"source_id"`
	ComponentID        string         `json:"component_id"`
	ComponentVersionID string         `json:"component_version_id"`
	ChannelID          string         `json:"channel_id"`
	ParserVersion      string         `json:"parser_version"`
	ProfileVersion     string         `json:"profile_version"`
	TrustEnvelopeID    string         `json:"trust_envelope_id"`
	Spans              []EvidenceSpan `json:"spans"`
}

type TrustEnvelopeCore struct {
	SchemaVersion        string `json:"schema_version"`
	EnvelopeKind         string `json:"envelope_kind"`
	ProfileVersion       string `json:"profile_version"`
	ContentClass         string `json:"content_class"`
	InstructionPolicy    string `json:"instruction_policy"`
	ExecutionPolicy      string `json:"execution_policy"`
	ToolPolicy           string `json:"tool_policy"`
	InterpretationPolicy string `json:"interpretation_policy"`
}

type TrustEnvelope struct {
	EnvelopeID            string `json:"envelope_id"`
	EnvelopePayloadSHA256 string `json:"envelope_payload_sha256"`
	TrustEnvelopeCore
}

type EvidenceManifestCore struct {
	SchemaVersion              string         `json:"schema_version"`
	ManifestKind               string         `json:"manifest_kind"`
	State                      string         `json:"state"`
	InputManifestID            string         `json:"input_manifest_id"`
	InputManifestPayloadSHA256 string         `json:"input_manifest_payload_sha256"`
	InputSnapshotID            string         `json:"input_snapshot_id"`
	CompilerVersion            string         `json:"compiler_version"`
	SourceProfileVersion       string         `json:"source_profile_version"`
	TrustEnvelope              TrustEnvelope  `json:"trust_envelope"`
	ObjectLayout               string         `json:"object_layout"`
	FileCount                  int            `json:"file_count"`
	RawByteSize                int64          `json:"raw_byte_size"`
	SpanCount                  int            `json:"span_count"`
	LogicalOutputByteSize      int64          `json:"logical_output_byte_size"`
	UniquePayloadCount         int            `json:"unique_payload_count"`
	UniquePayloadByteSize      int64          `json:"unique_payload_byte_size"`
	Files                      []EvidenceFile `json:"files"`
}

type EvidenceManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	EvidenceManifestCore
}

type QuarantineIssue struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type QuarantineReport struct {
	SchemaVersion       string            `json:"schema_version"`
	ReportKind          string            `json:"report_kind"`
	State               string            `json:"state"`
	QuarantineID        string            `json:"quarantine_id"`
	InputDocumentSHA256 string            `json:"input_document_sha256"`
	InputManifestID     string            `json:"input_manifest_id,omitempty"`
	InputSnapshotID     string            `json:"input_snapshot_id,omitempty"`
	Issues              []QuarantineIssue `json:"issues"`
}

type CompileConfig struct {
	ManifestPath        string
	RawStoreRoot        string
	StoreRoot           string
	SpecPath            string
	ProposalPath        string
	ReviewReceiptPath   string
	ReviewSignaturePath string
	AllowedSignersPath  string
	MaxFiles            int
	MaxFileBytes        int64
	MaxTotalBytes       int64
	MaxSpans            int
	MaxOutputBytes      int64
}

type CompileResult struct {
	Manifest     EvidenceManifest
	ManifestPath string
}

type QuarantinedError struct {
	ReportPath string
	Issues     []QuarantineIssue
}

func (e *QuarantinedError) Error() string { return "snapshot evidence quarantined" }
