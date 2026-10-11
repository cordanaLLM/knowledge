package main

// The v1 review-bound types below intentionally mirror the frozen
// knowledge-snapshot schema 1.0.0 field order and JSON tags byte-for-byte. The
// snapshot and evidence compilers re-marshal every review artifact and compare
// the canonical bytes, so any drift here would be rejected at admission. This
// adapter never edits the frozen modules; it only produces inputs they accept.

// Acquisition v2 documents (receipt and inventory proposal) are decoded
// leniently: only the fields this adapter binds are modeled, and the rest of
// the versioned contract is ignored without widening it.
type acquisitionDocument struct {
	ReceiptID  string              `json:"receipt_id"`
	ProposalID string              `json:"proposal_id"`
	Targets    []acquisitionTarget `json:"targets"`
}

type acquisitionTarget struct {
	AuthorityID        string               `json:"authority_id"`
	TargetID           string               `json:"target_id"`
	SourceSetID        string               `json:"source_set_id"`
	ComponentID        string               `json:"component_id"`
	ComponentVersion   string               `json:"component_version"`
	Repository         string               `json:"repository"`
	RequestedTag       string               `json:"requested_tag"`
	ResolvedCommitSHA1 string               `json:"resolved_commit_sha1"`
	CommitTreeSHA1     string               `json:"commit_tree_sha1"`
	LicenseExpression  string               `json:"license_expression"`
	Publisher          acquisitionPublisher `json:"publisher"`
	Files              []acquisitionFile    `json:"files"`
}

type acquisitionPublisher struct {
	Name        string `json:"name"`
	PublisherID string `json:"publisher_id"`
	URI         string `json:"uri"`
}

type acquisitionFile struct {
	Path      string `json:"path"`
	Bytes     int64  `json:"bytes"`
	RawSHA256 string `json:"raw_sha256"`
	SourceKey string `json:"source_key"`
}

// SourceSpec mirrors knowledge-snapshot/types.go SourceSpec exactly.
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

type VerifiedExclusion struct {
	RelativePath string `json:"relative_path"`
	MediaType    string `json:"media_type"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	SourceKind   string `json:"source_kind"`
	Reason       string `json:"reason"`
}

// InventoryProposal mirrors knowledge-snapshot/types.go InventoryProposal.
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

// SourceSpecReviewReceipt mirrors knowledge-snapshot/types.go.
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

// reviewAdmission captures the subset of the snapshot manifest this adapter
// reads back to locate the review CAS objects the evidence compiler re-verifies.
type reviewAdmission struct {
	ProposalObjectPath   string `json:"proposal_object_path"`
	SourceSpecObjectPath string `json:"source_spec_object_path"`
	ReceiptObjectPath    string `json:"receipt_object_path"`
	SignatureObjectPath  string `json:"signature_object_path"`
}

type snapshotManifestHead struct {
	ManifestID      string          `json:"manifest_id"`
	ReviewAdmission reviewAdmission `json:"review_admission"`
}

// Config drives one full acquisition-to-evidence adaptation run.
type Config struct {
	ReceiptPath  string
	ProposalPath string
	CASRoot      string
	SnapshotBin  string
	EvidenceBin  string
	WorkRoot     string
	OutRoot      string
}

// AuthorityResult records the emitted per-authority manifests.
type AuthorityResult struct {
	AuthorityID          string
	ComponentID          string
	ResolvedVersion      string
	SourceRevision       string
	SnapshotManifestID   string
	SnapshotManifestPath string
	EvidenceManifestID   string
	EvidenceManifestPath string
	SnapshotOutPath      string
	EvidenceOutPath      string
}
