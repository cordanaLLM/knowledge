package main

type Rights struct {
	LicenseExpression string            `json:"license_expression"`
	RightsBasis       string            `json:"rights_basis"`
	Attribution       string            `json:"attribution"`
	Permissions       map[string]string `json:"permissions"`
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

// ReviewAdmission and VerifiedExclusion deliberately mirror the canonical
// knowledge-snapshot v1 wire contract. These must remain typed: decoding them
// into map[string]any reorders object keys during canonical re-encoding and
// falsely rejects a valid manifest produced by knowledge-snapshot.
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

type VerifiedExclusion struct {
	RelativePath string `json:"relative_path"`
	MediaType    string `json:"media_type"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	SourceKind   string `json:"source_kind"`
	Reason       string `json:"reason"`
}

type SnapshotManifest struct {
	ManifestID            string              `json:"manifest_id"`
	ManifestPayloadSHA256 string              `json:"manifest_payload_sha256"`
	SchemaVersion         string              `json:"schema_version"`
	ManifestKind          string              `json:"manifest_kind"`
	State                 string              `json:"state"`
	AuthorityState        string              `json:"authority_state"`
	ReviewAdmission       ReviewAdmission     `json:"review_admission"`
	SnapshotID            string              `json:"snapshot_id"`
	SourceSpecSHA256      string              `json:"source_spec_sha256"`
	Source                SourceLineage       `json:"source"`
	TreeSHA256            string              `json:"tree_sha256"`
	FileCount             int                 `json:"file_count"`
	ByteSize              int64               `json:"byte_size"`
	UniqueBlobCount       int                 `json:"unique_blob_count"`
	ObjectLayout          string              `json:"object_layout"`
	ExcludedFileCount     int                 `json:"excluded_file_count"`
	ExcludedByteSize      int64               `json:"excluded_byte_size"`
	Exclusions            []VerifiedExclusion `json:"exclusions"`
	Files                 []SnapshotFile      `json:"files"`
}

type SnapshotFile struct {
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

type AdmissionPolicyCore struct {
	SchemaVersion      string `json:"schema_version"`
	PolicyKind         string `json:"policy_kind"`
	State              string `json:"state"`
	SnapshotManifestID string `json:"snapshot_manifest_id"`
	EvidenceManifestID string `json:"evidence_manifest_id"`
	SnapshotID         string `json:"snapshot_id"`
	SourceID           string `json:"source_id"`
	ComponentID        string `json:"component_id"`
	ComponentVersionID string `json:"component_version_id"`
	AccessScope        string `json:"access_scope"`
	RetrievalAllowed   bool   `json:"retrieval_allowed"`
	SourceState        string `json:"source_state"`
	DeletionState      string `json:"deletion_state"`
	Tombstone          bool   `json:"tombstone"`
	EvaluatedAt        string `json:"evaluated_at"`
	FreshUntil         string `json:"fresh_until"`
}

type AdmissionPolicy struct {
	PolicyID            string `json:"policy_id"`
	PolicyPayloadSHA256 string `json:"policy_payload_sha256"`
	AdmissionPolicyCore
}

type EvidenceRef struct {
	SpanID string `json:"span_id"`
	// ParentSpanID is set only on a small-to-big fine-span extension document:
	// the exact SpanID of the coarser evidence chunk it was carved out of, both
	// indexed as independent documents. Empty on every historical document.
	ParentSpanID         string   `json:"parent_span_id,omitempty"`
	OccurrenceID         string   `json:"occurrence_id"`
	SourceID             string   `json:"source_id"`
	ComponentID          string   `json:"component_id"`
	ComponentVersionID   string   `json:"component_version_id"`
	ChannelID            string   `json:"channel_id"`
	CanonicalSourceURI   string   `json:"canonical_source_uri"`
	CanonicalSnapshotURI string   `json:"canonical_snapshot_uri"`
	SnapshotManifestID   string   `json:"snapshot_manifest_id"`
	EvidenceManifestID   string   `json:"evidence_manifest_id"`
	SnapshotID           string   `json:"snapshot_id"`
	RelativePath         string   `json:"relative_path"`
	HeadingBreadcrumb    []string `json:"heading_breadcrumb"`
	RawSHA256            string   `json:"raw_sha256"`
	PayloadSHA256        string   `json:"payload_sha256"`
	PayloadObjectPath    string   `json:"payload_object_path"`
	PayloadByteSize      int64    `json:"payload_byte_size"`
	RawByteStart         int64    `json:"raw_byte_start"`
	RawByteEnd           int64    `json:"raw_byte_end"`
	RawLineStart         int      `json:"raw_line_start"`
	RawLineEnd           int      `json:"raw_line_end"`
	FetchedAt            string   `json:"fetched_at"`
	ObservedAt           string   `json:"observed_at"`
	AccessScope          string   `json:"access_scope"`
	FreshUntil           string   `json:"fresh_until"`
	TrustEnvelopeID      string   `json:"trust_envelope_id"`
	ContentClass         string   `json:"content_class"`
	InstructionPolicy    string   `json:"instruction_policy"`
	ExecutionPolicy      string   `json:"execution_policy"`
	ToolPolicy           string   `json:"tool_policy"`
	InterpretationPolicy string   `json:"interpretation_policy"`
}

type IndexedDocument struct {
	DocumentID    string      `json:"document_id"`
	Evidence      EvidenceRef `json:"evidence"`
	BodyLength    int         `json:"body_length,omitempty"`
	HeadingLength int         `json:"heading_length,omitempty"`
}

type Posting struct {
	TermFrequency        int    `json:"term_frequency,omitempty"`
	BodyTermFrequency    int    `json:"body_term_frequency,omitempty"`
	HeadingTermFrequency int    `json:"heading_term_frequency,omitempty"`
	DocumentPosition     int    `json:"document_position,omitempty"`
	DocumentID           string `json:"document_id"`
}

type TermEntry struct {
	Term              string    `json:"term"`
	DocumentFrequency int       `json:"document_frequency,omitempty"`
	Postings          []Posting `json:"postings"`
}

// AuthorityLineageBinding retains one source authority's exact snapshot,
// evidence and admission identities inside a shared multi-authority lexical
// candidate/index. A single-authority (N=1) artifact never carries these; it
// keeps the historical singular fields byte-for-byte. Field naming mirrors the
// multidomain binding-closure per-authority record so the retained artifact is
// directly consumable by the later shared-corpus closure unit.
type AuthorityLineageBinding struct {
	AuthorityID                    string `json:"authority_id"`
	ComponentID                    string `json:"component_id"`
	ComponentVersion               string `json:"component_version"`
	AdmissionPolicyScopeID         string `json:"admission_policy_scope_id"`
	SourceID                       string `json:"source_id"`
	SnapshotID                     string `json:"snapshot_id"`
	SnapshotManifestID             string `json:"snapshot_manifest_id"`
	SnapshotManifestDocumentSHA256 string `json:"snapshot_manifest_document_sha256"`
	EvidenceManifestID             string `json:"evidence_manifest_id"`
	EvidenceManifestDocumentSHA256 string `json:"evidence_manifest_document_sha256"`
	AdmissionPolicyID              string `json:"admission_policy_id"`
	AdmissionPolicyDocumentSHA256  string `json:"admission_policy_document_sha256"`
	SourceAdmissionMethod          string `json:"source_admission_method,omitempty"`
	SourceAdmissionPolicyID        string `json:"source_admission_policy_id,omitempty"`
	SourceAdmissionPolicySHA256    string `json:"source_admission_policy_sha256,omitempty"`
	AdmissionEvaluatedAt           string `json:"admission_evaluated_at"`
	AdmissionFreshUntil            string `json:"admission_fresh_until"`
	FreshnessState                 string `json:"freshness_state"`
	DocumentCount                  int    `json:"document_count"`
}

type LexicalIndexCore struct {
	SchemaVersion      string                    `json:"schema_version"`
	IndexKind          string                    `json:"index_kind"`
	Lexical            bool                      `json:"lexical"`
	Dense              bool                      `json:"dense"`
	EvidenceManifestID string                    `json:"evidence_manifest_id,omitempty"`
	SnapshotManifestID string                    `json:"snapshot_manifest_id,omitempty"`
	AdmissionPolicyID  string                    `json:"admission_policy_id,omitempty"`
	FreshnessState     string                    `json:"freshness_state,omitempty"`
	Lineages           []AuthorityLineageBinding `json:"lineages,omitempty"`
	DocumentCount      int                       `json:"document_count"`
	TermCount          int                       `json:"term_count"`
	PostingCount       int                       `json:"posting_count"`
	LexicalProfile     string                    `json:"lexical_profile,omitempty"`
	LexicalTokenizerID string                    `json:"lexical_tokenizer_id,omitempty"`
	LexicalScorerID    string                    `json:"lexical_scorer_id,omitempty"`
	TotalBodyLength    int64                     `json:"total_body_length,omitempty"`
	TotalHeadingLength int64                     `json:"total_heading_length,omitempty"`
	Documents          []IndexedDocument         `json:"documents"`
	Terms              []TermEntry               `json:"terms"`
}

type LexicalIndex struct {
	IndexID            string `json:"index_id"`
	IndexPayloadSHA256 string `json:"index_payload_sha256"`
	LexicalIndexCore
}

type CandidateManifestCore struct {
	SchemaVersion               string                    `json:"schema_version"`
	ManifestKind                string                    `json:"manifest_kind"`
	State                       string                    `json:"state"`
	Promotable                  bool                      `json:"promotable"`
	ServingEligible             bool                      `json:"serving_eligible"`
	CurrentEligible             bool                      `json:"current_eligible"`
	Lexical                     bool                      `json:"lexical"`
	Dense                       bool                      `json:"dense"`
	FreshnessState              string                    `json:"freshness_state,omitempty"`
	EvaluatedAt                 string                    `json:"evaluated_at,omitempty"`
	FreshUntil                  string                    `json:"fresh_until,omitempty"`
	SnapshotManifestID          string                    `json:"snapshot_manifest_id,omitempty"`
	EvidenceManifestID          string                    `json:"evidence_manifest_id,omitempty"`
	AdmissionPolicyID           string                    `json:"admission_policy_id,omitempty"`
	AdmissionPolicySHA256       string                    `json:"admission_policy_document_sha256,omitempty"`
	SourceAdmissionMethod       string                    `json:"source_admission_method,omitempty"`
	SourceAdmissionPolicyID     string                    `json:"source_admission_policy_id,omitempty"`
	SourceAdmissionPolicySHA256 string                    `json:"source_admission_policy_sha256,omitempty"`
	EvidenceVerifierSHA256      string                    `json:"evidence_verifier_sha256"`
	Lineages                    []AuthorityLineageBinding `json:"lineages,omitempty"`
	LexicalIndexID              string                    `json:"lexical_index_id"`
	LexicalIndexSHA256          string                    `json:"lexical_index_sha256"`
	LexicalIndexPath            string                    `json:"lexical_index_path"`
	LexicalIndexByteSize        int64                     `json:"lexical_index_byte_size"`
	DocumentCount               int                       `json:"document_count"`
	TermCount                   int                       `json:"term_count"`
	PostingCount                int                       `json:"posting_count"`
	LexicalProfile              string                    `json:"lexical_profile,omitempty"`
	LexicalTokenizerID          string                    `json:"lexical_tokenizer_id,omitempty"`
	LexicalScorerID             string                    `json:"lexical_scorer_id,omitempty"`
	MissingCapabilities         []string                  `json:"missing_capabilities"`
}

type CandidateManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	CandidateManifestCore
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
	EvidenceManifestID  string            `json:"evidence_manifest_id,omitempty"`
	Issues              []QuarantineIssue `json:"issues"`
}

// LineageConfig is one source authority's admitted inputs for a shared
// multi-authority build. The output store, evidence verifier, resource limits
// and lexical profile stay shared on BuildConfig; every source-identity input
// is per authority so no lineage can be silently collapsed or aliased.
type LineageConfig struct {
	AuthorityID            string
	AdmissionPolicyScopeID string
	SnapshotManifestPath   string
	EvidenceManifestPath   string
	RawStoreRoot           string
	EvidenceStoreRoot      string
	SpecPath               string
	ProposalPath           string
	ReviewReceiptPath      string
	ReviewSignaturePath    string
	AllowedSignersPath     string
	AdmissionPolicyPath    string
	AdmissionPolicyHash    string
	AsOf                   string
	// FineSpanExtensionPath optionally names a plain per-lineage input file
	// declaring small-to-big child windows nested inside this lineage's own
	// already-admitted coarse evidence spans. Empty reproduces the historical
	// build byte-for-byte; every declared window is independently re-verified
	// against the exact raw bytes this lineage already verified, never trusted.
	FineSpanExtensionPath string
}

type BuildConfig struct {
	SnapshotManifestPath string
	EvidenceManifestPath string
	RawStoreRoot         string
	EvidenceStoreRoot    string
	OutputStoreRoot      string
	SpecPath             string
	ProposalPath         string
	ReviewReceiptPath    string
	ReviewSignaturePath  string
	AllowedSignersPath   string
	AdmissionPolicyPath  string
	AdmissionPolicyHash  string
	EvidenceVerifierPath string
	EvidenceVerifierHash string
	AsOf                 string
	MaxFiles             int
	MaxSpans             int
	MaxPayloadBytes      int64
	MaxTotalBytes        int64
	MaxTerms             int
	MaxPostings          int
	LexicalProfile       string
	// FineSpanExtensionPath applies to the single-authority (N=1) path only;
	// see LineageConfig.FineSpanExtensionPath for the shared multi-authority
	// equivalent.
	FineSpanExtensionPath string
	// Lineages, when non-empty, selects the shared multi-authority path: one
	// candidate and one lexical index merging every listed authority. When
	// empty the historical singular flat fields drive a byte-identical N=1 build.
	Lineages []LineageConfig
}

type BuildResult struct {
	Manifest     CandidateManifest
	ManifestPath string
}

type QuarantinedError struct {
	ReportPath string
	Issues     []QuarantineIssue
}

func (e *QuarantinedError) Error() string { return "retrieval candidate quarantined" }

type QueryConfig struct {
	CandidatePath       string
	CandidateHash       string
	StoreRoot           string
	EvidenceStoreRoot   string
	AdmissionPolicyPath string
	AdmissionPolicyHash string
	// LineageSetPath supplies the per-authority admission lineage set for a shared
	// multidomain candidate. It is ignored on the single-authority path.
	LineageSetPath  string
	Query           string
	PrincipalScope  string
	AsOf            string
	Limit           int
	MaxExcerptBytes int
}

type QueryHit struct {
	Score            int64       `json:"score"`
	MatchedTerms     []string    `json:"matched_terms"`
	Evidence         EvidenceRef `json:"evidence"`
	Excerpt          string      `json:"excerpt"`
	ExcerptTruncated bool        `json:"excerpt_truncated"`
}

type QueryResponse struct {
	State               string     `json:"state"`
	ResultState         string     `json:"result_state"`
	Promotable          bool       `json:"promotable"`
	Lexical             bool       `json:"lexical"`
	Dense               bool       `json:"dense"`
	CandidateManifestID string     `json:"candidate_manifest_id,omitempty"`
	LexicalProfile      string     `json:"lexical_profile,omitempty"`
	FreshnessState      string     `json:"freshness_state,omitempty"`
	QueryTerms          []string   `json:"query_terms,omitempty"`
	Results             []QueryHit `json:"results"`
	ErrorCode           string     `json:"error_code,omitempty"`
}
