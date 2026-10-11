package main

type DenseDocumentVector struct {
	DocumentID string  `json:"document_id"`
	Values     []int16 `json:"values"`
}

type DenseVectorArtifactCore struct {
	SchemaVersion       string                    `json:"schema_version"`
	ArtifactKind        string                    `json:"artifact_kind"`
	State               string                    `json:"state"`
	AuthorityState      string                    `json:"authority_state"`
	LexicalCandidateID  string                    `json:"lexical_candidate_id"`
	LexicalIndexID      string                    `json:"lexical_index_id"`
	EvidenceManifestID  string                    `json:"evidence_manifest_id"`
	Lineages            []AuthorityLineageBinding `json:"lineages,omitempty"`
	ModelID             string                    `json:"model_id"`
	ModelRevision       string                    `json:"model_revision"`
	ModelArtifactSHA256 string                    `json:"model_artifact_sha256"`
	TokenizerID         string                    `json:"tokenizer_id"`
	TokenizerSHA256     string                    `json:"tokenizer_artifact_sha256"`
	EmbeddingProfile    string                    `json:"embedding_profile"`
	DocumentInstruction string                    `json:"document_instruction"`
	VectorEncoding      string                    `json:"vector_encoding"`
	Normalization       string                    `json:"normalization"`
	QuantizationScale   int                       `json:"quantization_scale"`
	Dimension           int                       `json:"dimension"`
	DocumentCount       int                       `json:"document_count"`
	Documents           []DenseDocumentVector     `json:"documents"`
}

type DenseVectorArtifact struct {
	ArtifactID            string `json:"artifact_id"`
	ArtifactPayloadSHA256 string `json:"artifact_payload_sha256"`
	DenseVectorArtifactCore
}

type HybridCandidateManifestCore struct {
	SchemaVersion               string                    `json:"schema_version"`
	ManifestKind                string                    `json:"manifest_kind"`
	State                       string                    `json:"state"`
	Promotable                  bool                      `json:"promotable"`
	ServingEligible             bool                      `json:"serving_eligible"`
	CurrentEligible             bool                      `json:"current_eligible"`
	Lexical                     bool                      `json:"lexical"`
	Dense                       bool                      `json:"dense"`
	Fusion                      bool                      `json:"fusion"`
	Reranking                   bool                      `json:"reranking"`
	QualityState                string                    `json:"quality_state"`
	FreshnessState              string                    `json:"freshness_state"`
	EvaluatedAt                 string                    `json:"evaluated_at"`
	FreshUntil                  string                    `json:"fresh_until"`
	SnapshotManifestID          string                    `json:"snapshot_manifest_id"`
	EvidenceManifestID          string                    `json:"evidence_manifest_id"`
	Lineages                    []AuthorityLineageBinding `json:"lineages,omitempty"`
	AdmissionPolicyID           string                    `json:"admission_policy_id"`
	AdmissionPolicySHA256       string                    `json:"admission_policy_document_sha256"`
	SourceAdmissionMethod       string                    `json:"source_admission_method,omitempty"`
	SourceAdmissionPolicyID     string                    `json:"source_admission_policy_id,omitempty"`
	SourceAdmissionPolicySHA256 string                    `json:"source_admission_policy_sha256,omitempty"`
	LexicalCandidateID          string                    `json:"lexical_candidate_id"`
	LexicalCandidateSHA256      string                    `json:"lexical_candidate_document_sha256"`
	LexicalCandidatePath        string                    `json:"lexical_candidate_path"`
	LexicalCandidateByteSize    int64                     `json:"lexical_candidate_byte_size"`
	LexicalIndexID              string                    `json:"lexical_index_id"`
	LexicalProfile              string                    `json:"lexical_profile,omitempty"`
	LexicalTokenizerID          string                    `json:"lexical_tokenizer_id,omitempty"`
	LexicalScorerID             string                    `json:"lexical_scorer_id,omitempty"`
	DenseArtifactID             string                    `json:"dense_artifact_id"`
	DenseArtifactSHA256         string                    `json:"dense_artifact_document_sha256"`
	DenseArtifactPath           string                    `json:"dense_artifact_path"`
	DenseArtifactByteSize       int64                     `json:"dense_artifact_byte_size"`
	DenseModelID                string                    `json:"dense_model_id"`
	DenseModelRevision          string                    `json:"dense_model_revision"`
	DenseModelArtifactSHA256    string                    `json:"dense_model_artifact_sha256"`
	DenseTokenizerID            string                    `json:"dense_tokenizer_id"`
	DenseTokenizerSHA256        string                    `json:"dense_tokenizer_artifact_sha256"`
	EmbeddingProfile            string                    `json:"embedding_profile"`
	DenseDocumentInstruction    string                    `json:"dense_document_instruction"`
	VectorEncoding              string                    `json:"vector_encoding"`
	Normalization               string                    `json:"normalization"`
	QuantizationScale           int                       `json:"quantization_scale"`
	Dimension                   int                       `json:"dimension"`
	DocumentCount               int                       `json:"document_count"`
	FusionProfile               string                    `json:"fusion_profile"`
	FusionProfileID             string                    `json:"fusion_profile_id,omitempty"`
	FusionProfileSHA256         string                    `json:"fusion_profile_document_sha256,omitempty"`
	FusionProfilePath           string                    `json:"fusion_profile_path,omitempty"`
	FusionProfileByteSize       int64                     `json:"fusion_profile_byte_size,omitempty"`
	RerankingContract           string                    `json:"reranking_contract"`
	MissingCapabilities         []string                  `json:"missing_capabilities"`
}

type HybridCandidateManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	HybridCandidateManifestCore
}

type RerankerDocumentScore struct {
	DocumentID string `json:"document_id"`
	Score      int64  `json:"score"`
}

type QuerySignalArtifactCore struct {
	SchemaVersion               string                  `json:"schema_version"`
	ArtifactKind                string                  `json:"artifact_kind"`
	State                       string                  `json:"state"`
	AuthorityState              string                  `json:"authority_state"`
	HybridCandidateID           string                  `json:"hybrid_candidate_id"`
	QuerySHA256                 string                  `json:"query_sha256"`
	DenseArtifactID             string                  `json:"dense_artifact_id"`
	DenseModelID                string                  `json:"dense_model_id"`
	DenseModelRevision          string                  `json:"dense_model_revision"`
	DenseModelArtifactSHA256    string                  `json:"dense_model_artifact_sha256"`
	DenseTokenizerID            string                  `json:"dense_tokenizer_id"`
	DenseTokenizerSHA256        string                  `json:"dense_tokenizer_artifact_sha256"`
	EmbeddingProfile            string                  `json:"embedding_profile"`
	DenseQueryInstruction       string                  `json:"dense_query_instruction"`
	DenseDocumentInstruction    string                  `json:"dense_document_instruction"`
	VectorEncoding              string                  `json:"vector_encoding"`
	Normalization               string                  `json:"normalization"`
	QuantizationScale           int                     `json:"quantization_scale"`
	Dimension                   int                     `json:"dimension"`
	QueryVector                 []int16                 `json:"query_vector"`
	RerankingRequested          bool                    `json:"reranking_requested"`
	RerankerModelID             string                  `json:"reranker_model_id"`
	RerankerModelRevision       string                  `json:"reranker_model_revision"`
	RerankerModelArtifactSHA256 string                  `json:"reranker_model_artifact_sha256"`
	RerankerTokenizerID         string                  `json:"reranker_tokenizer_id"`
	RerankerTokenizerSHA256     string                  `json:"reranker_tokenizer_artifact_sha256"`
	RerankerProfile             string                  `json:"reranker_profile"`
	RerankerQueryInstruction    string                  `json:"reranker_query_instruction"`
	RerankerDocumentInstruction string                  `json:"reranker_document_instruction"`
	RerankerScoreScale          int64                   `json:"reranker_score_scale"`
	Scores                      []RerankerDocumentScore `json:"scores"`
}

type QuerySignalArtifact struct {
	ArtifactID            string `json:"artifact_id"`
	ArtifactPayloadSHA256 string `json:"artifact_payload_sha256"`
	QuerySignalArtifactCore
}

type HybridBuildConfig struct {
	CandidatePath     string
	CandidateHash     string
	StoreRoot         string
	DenseArtifactPath string
	DenseArtifactHash string
	FusionProfilePath string
	FusionProfileHash string
	MaxDenseDocuments int
	MaxDenseDimension int
}

type HybridBuildResult struct {
	Manifest     HybridCandidateManifest
	ManifestPath string
}

type HybridQueryConfig struct {
	HybridCandidatePath string
	HybridCandidateHash string
	StoreRoot           string
	EvidenceStoreRoot   string
	AdmissionPolicyPath string
	AdmissionPolicyHash string
	// LineageSetPath supplies the per-authority admission lineage set for a shared
	// multidomain hybrid candidate. It is ignored on the single-authority path.
	LineageSetPath    string
	QueryArtifactPath string
	QueryArtifactHash string
	FusionProfilePath string
	FusionProfileHash string
	Query             string
	PrincipalScope    string
	AsOf              string
	Limit             int
	FusionWindow      int
	RerankWindow      int
	MaxExcerptBytes   int
}

type HybridScore struct {
	LexicalRank   int    `json:"lexical_rank,omitempty"`
	LexicalScore  int64  `json:"lexical_score,omitempty"`
	DenseRank     int    `json:"dense_rank,omitempty"`
	DenseDot      int64  `json:"dense_dot,omitempty"`
	FusionScore   int64  `json:"fusion_score"`
	RerankerScore *int64 `json:"reranker_score,omitempty"`
	RerankerScale *int64 `json:"reranker_scale,omitempty"`
}

type HybridQueryHit struct {
	Rank             int         `json:"rank"`
	RetrievalPath    []string    `json:"retrieval_path"`
	MatchedTerms     []string    `json:"matched_terms"`
	Score            HybridScore `json:"score"`
	Evidence         EvidenceRef `json:"evidence"`
	Excerpt          string      `json:"excerpt"`
	ExcerptTruncated bool        `json:"excerpt_truncated"`
}

type FusionLaneChampion struct {
	Lane       string `json:"lane"`
	SpanID     string `json:"span_id"`
	FusionRank int    `json:"fusion_rank"`
	ResultRank int    `json:"result_rank"`
	Retained   bool   `json:"retained"`
}

// FusionScoreTie names one exact fusion-score tie that the documented total
// order had to break. It is observability only: no gate, threshold or metric
// consumes it. Reporting the tie keeps "these spans are indistinguishable
// under this scorer" visible instead of hiding it behind an arbitrary pick.
type FusionScoreTie struct {
	FusionScore int64    `json:"fusion_score"`
	FirstRank   int      `json:"first_rank"`
	SpanIDs     []string `json:"span_ids"`
}

type FusionObservation struct {
	TieBreak              string               `json:"tie_break"`
	MissingLanePolicy     string               `json:"missing_lane_policy"`
	UniqueChampionCount   int                  `json:"unique_champion_count"`
	RetainedChampionCount int                  `json:"retained_champion_count"`
	AllChampionsRetained  bool                 `json:"all_champions_retained"`
	LaneChampions         []FusionLaneChampion `json:"lane_champions"`
}

type HybridQueryResponse struct {
	State                 string             `json:"state"`
	ResultState           string             `json:"result_state"`
	Promotable            bool               `json:"promotable"`
	ServingEligible       bool               `json:"serving_eligible"`
	CurrentEligible       bool               `json:"current_eligible"`
	Lexical               bool               `json:"lexical"`
	Dense                 bool               `json:"dense"`
	Fusion                bool               `json:"fusion"`
	Reranking             bool               `json:"reranking"`
	HybridCandidateID     string             `json:"hybrid_candidate_id,omitempty"`
	QuerySignalArtifactID string             `json:"query_signal_artifact_id,omitempty"`
	FreshnessState        string             `json:"freshness_state,omitempty"`
	QueryTerms            []string           `json:"query_terms,omitempty"`
	FusionProfile         string             `json:"fusion_profile,omitempty"`
	FusionProfileID       string             `json:"fusion_profile_id,omitempty"`
	FusionObservation     *FusionObservation `json:"fusion_observation,omitempty"`
	TieBreak              string             `json:"tie_break,omitempty"`
	ScoreTies             []FusionScoreTie   `json:"score_ties,omitempty"`
	LexicalProfile        string             `json:"lexical_profile,omitempty"`
	RerankerModelID       string             `json:"reranker_model_id,omitempty"`
	DenseScannedDocuments int                `json:"dense_scanned_documents,omitempty"`
	RerankedDocuments     int                `json:"reranked_documents,omitempty"`
	Results               []HybridQueryHit   `json:"results"`
	ErrorCode             string             `json:"error_code,omitempty"`
}
