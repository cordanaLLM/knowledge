package main

type RetrievalQualityGates struct {
	HeldOutQuality        bool `json:"held_out_quality"`
	CitationLineage       bool `json:"citation_lineage"`
	ACLIsolation          bool `json:"acl_isolation"`
	DeletionAndTombstone  bool `json:"deletion_and_tombstone"`
	FreshnessAndTime      bool `json:"freshness_and_time"`
	PromptInjectionInert  bool `json:"prompt_injection_inert"`
	ResourceBounds        bool `json:"resource_bounds"`
	DeterministicReplay   bool `json:"deterministic_replay"`
	RollbackCompatibility bool `json:"rollback_compatibility"`
}

type RetrievalQualityReportCore struct {
	SchemaVersion                 string                `json:"schema_version"`
	ReportKind                    string                `json:"report_kind"`
	State                         string                `json:"state"`
	HybridCandidateID             string                `json:"hybrid_candidate_id"`
	HybridCandidateSHA256         string                `json:"hybrid_candidate_document_sha256"`
	AdmissionPolicyID             string                `json:"admission_policy_id"`
	AdmissionPolicySHA256         string                `json:"admission_policy_document_sha256"`
	SourceAdmissionMethod         string                `json:"source_admission_method,omitempty"`
	SourceAdmissionPolicyID       string                `json:"source_admission_policy_id,omitempty"`
	SourceAdmissionPolicySHA256   string                `json:"source_admission_policy_sha256,omitempty"`
	RetrievalExecutableSHA256     string                `json:"retrieval_executable_sha256"`
	LexicalIndexID                string                `json:"lexical_index_id"`
	LexicalProfile                string                `json:"lexical_profile,omitempty"`
	LexicalTokenizerID            string                `json:"lexical_tokenizer_id,omitempty"`
	LexicalScorerID               string                `json:"lexical_scorer_id,omitempty"`
	DenseArtifactID               string                `json:"dense_artifact_id"`
	DenseArtifactSHA256           string                `json:"dense_artifact_document_sha256"`
	DenseModelID                  string                `json:"dense_model_id"`
	DenseModelRevision            string                `json:"dense_model_revision"`
	DenseModelArtifactSHA256      string                `json:"dense_model_artifact_sha256"`
	DenseTokenizerID              string                `json:"dense_tokenizer_id"`
	DenseTokenizerSHA256          string                `json:"dense_tokenizer_artifact_sha256"`
	EmbeddingProfile              string                `json:"embedding_profile"`
	FusionProfile                 string                `json:"fusion_profile"`
	RerankingContract             string                `json:"reranking_contract"`
	RerankingEvaluated            bool                  `json:"reranking_evaluated"`
	RerankerModelID               *string               `json:"reranker_model_id"`
	RerankerModelRevision         *string               `json:"reranker_model_revision"`
	RerankerModelArtifactSHA256   *string               `json:"reranker_model_artifact_sha256"`
	RerankerTokenizerID           *string               `json:"reranker_tokenizer_id"`
	RerankerTokenizerSHA256       *string               `json:"reranker_tokenizer_artifact_sha256"`
	RerankerProfile               *string               `json:"reranker_profile"`
	RerankerQueryInstruction      *string               `json:"reranker_query_instruction"`
	RerankerDocumentInstruction   *string               `json:"reranker_document_instruction"`
	RerankerScoreScale            *int64                `json:"reranker_score_scale"`
	EvaluationDatasetID           string                `json:"evaluation_dataset_id"`
	EvaluationDatasetSHA256       string                `json:"evaluation_dataset_sha256"`
	EvaluationMetricsObjectSHA256 string                `json:"evaluation_metrics_object_sha256"`
	EvaluationRuntimeSHA256       string                `json:"evaluation_runtime_sha256"`
	EvaluatorID                   string                `json:"evaluator_id"`
	EvaluatorRevision             string                `json:"evaluator_revision"`
	EvaluatorExecutableSHA256     string                `json:"evaluator_executable_sha256"`
	EvaluatedAt                   string                `json:"evaluated_at"`
	Gates                         RetrievalQualityGates `json:"gates"`
}

type RetrievalQualityReport struct {
	ReportID            string `json:"report_id"`
	ReportPayloadSHA256 string `json:"report_payload_sha256"`
	RetrievalQualityReportCore
}

type RetrievalQualityReceiptCore struct {
	SchemaVersion             string                           `json:"schema_version"`
	ReceiptKind               string                           `json:"receipt_kind"`
	State                     string                           `json:"state"`
	QualityReportID           string                           `json:"quality_report_id"`
	QualityReportSHA256       string                           `json:"quality_report_document_sha256"`
	EvaluatorID               string                           `json:"evaluator_id"`
	EvaluatorRevision         string                           `json:"evaluator_revision"`
	EvaluatorExecutableSHA256 string                           `json:"evaluator_executable_sha256"`
	EvaluationRuntimeSHA256   string                           `json:"evaluation_runtime_sha256"`
	Authorization             RetrievalTransitionAuthorization `json:"authorization"`
	EvaluatedAt               string                           `json:"evaluated_at"`
}

type RetrievalQualityReceipt struct {
	ReceiptID            string `json:"receipt_id"`
	ReceiptPayloadSHA256 string `json:"receipt_payload_sha256"`
	RetrievalQualityReceiptCore
}

type RetrievalGenerationCore struct {
	SchemaVersion                   string   `json:"schema_version"`
	GenerationKind                  string   `json:"generation_kind"`
	State                           string   `json:"state"`
	QualityState                    string   `json:"quality_state"`
	Promotable                      bool     `json:"promotable"`
	ServingEligible                 bool     `json:"serving_eligible"`
	CurrentEligible                 bool     `json:"current_eligible"`
	BaseGenerationID                *string  `json:"base_generation_id"`
	BaseGenerationSHA256            *string  `json:"base_generation_document_sha256"`
	CreatedAt                       string   `json:"created_at"`
	HybridCandidateID               string   `json:"hybrid_candidate_id"`
	HybridCandidateSHA256           string   `json:"hybrid_candidate_document_sha256"`
	HybridCandidatePath             string   `json:"hybrid_candidate_path"`
	HybridCandidateByteSize         int64    `json:"hybrid_candidate_byte_size"`
	SnapshotManifestID              string   `json:"snapshot_manifest_id"`
	EvidenceManifestID              string   `json:"evidence_manifest_id"`
	EvidenceSpanIDs                 []string `json:"evidence_span_ids"`
	DocumentCount                   int      `json:"document_count"`
	AdmissionPolicyID               string   `json:"admission_policy_id"`
	AdmissionPolicySHA256           string   `json:"admission_policy_document_sha256"`
	SourceAdmissionMethod           string   `json:"source_admission_method,omitempty"`
	SourceAdmissionPolicyID         string   `json:"source_admission_policy_id,omitempty"`
	SourceAdmissionPolicySHA256     string   `json:"source_admission_policy_sha256,omitempty"`
	AdmissionPolicyPath             string   `json:"admission_policy_path"`
	AdmissionPolicyByteSize         int64    `json:"admission_policy_byte_size"`
	LexicalCandidateID              string   `json:"lexical_candidate_id"`
	LexicalCandidateSHA256          string   `json:"lexical_candidate_document_sha256"`
	LexicalIndexID                  string   `json:"lexical_index_id"`
	LexicalProfile                  string   `json:"lexical_profile,omitempty"`
	LexicalTokenizerID              string   `json:"lexical_tokenizer_id,omitempty"`
	LexicalScorerID                 string   `json:"lexical_scorer_id,omitempty"`
	DenseArtifactID                 string   `json:"dense_artifact_id"`
	DenseArtifactSHA256             string   `json:"dense_artifact_document_sha256"`
	DenseModelID                    string   `json:"dense_model_id"`
	DenseModelRevision              string   `json:"dense_model_revision"`
	DenseModelArtifactSHA256        string   `json:"dense_model_artifact_sha256"`
	DenseTokenizerID                string   `json:"dense_tokenizer_id"`
	DenseTokenizerSHA256            string   `json:"dense_tokenizer_artifact_sha256"`
	EmbeddingProfile                string   `json:"embedding_profile"`
	VectorEncoding                  string   `json:"vector_encoding"`
	Normalization                   string   `json:"normalization"`
	QuantizationScale               int      `json:"quantization_scale"`
	Dimension                       int      `json:"dimension"`
	FusionProfile                   string   `json:"fusion_profile"`
	RerankingContract               string   `json:"reranking_contract"`
	RerankingEvaluated              bool     `json:"reranking_evaluated"`
	RerankerModelID                 *string  `json:"reranker_model_id"`
	RerankerModelRevision           *string  `json:"reranker_model_revision"`
	RerankerModelArtifactSHA256     *string  `json:"reranker_model_artifact_sha256"`
	RerankerTokenizerID             *string  `json:"reranker_tokenizer_id"`
	RerankerTokenizerSHA256         *string  `json:"reranker_tokenizer_artifact_sha256"`
	RerankerProfile                 *string  `json:"reranker_profile"`
	RerankerQueryInstruction        *string  `json:"reranker_query_instruction"`
	RerankerDocumentInstruction     *string  `json:"reranker_document_instruction"`
	RerankerScoreScale              *int64   `json:"reranker_score_scale"`
	QualityReportID                 string   `json:"quality_report_id"`
	QualityReportSHA256             string   `json:"quality_report_document_sha256"`
	QualityReportPath               string   `json:"quality_report_path"`
	QualityReportByteSize           int64    `json:"quality_report_byte_size"`
	QualityReceiptID                string   `json:"quality_receipt_id"`
	QualityReceiptSHA256            string   `json:"quality_receipt_document_sha256"`
	QualityReceiptPath              string   `json:"quality_receipt_path"`
	QualityReceiptByteSize          int64    `json:"quality_receipt_byte_size"`
	QualitySignatureSHA256          string   `json:"quality_signature_sha256"`
	QualitySignaturePath            string   `json:"quality_signature_path"`
	QualitySignatureByteSize        int64    `json:"quality_signature_byte_size"`
	EvaluatorAllowedSignersSHA256   string   `json:"evaluator_allowed_signers_sha256"`
	EvaluatorAllowedSignersPath     string   `json:"evaluator_allowed_signers_path"`
	EvaluatorAllowedSignersByteSize int64    `json:"evaluator_allowed_signers_byte_size"`
	EvaluatorActor                  string   `json:"evaluator_actor"`
	EvaluatorKeyID                  string   `json:"evaluator_key_id"`
	EvaluatorSignatureNamespace     string   `json:"evaluator_signature_namespace"`
	EvaluatorID                     string   `json:"evaluator_id"`
	EvaluatorRevision               string   `json:"evaluator_revision"`
	EvaluatorExecutableSHA256       string   `json:"evaluator_executable_sha256"`
	EvaluatorExecutablePath         string   `json:"evaluator_executable_path"`
	EvaluatorExecutableByteSize     int64    `json:"evaluator_executable_byte_size"`
	EvaluationDatasetID             string   `json:"evaluation_dataset_id"`
	EvaluationDatasetSHA256         string   `json:"evaluation_dataset_sha256"`
	EvaluationDatasetPath           string   `json:"evaluation_dataset_path"`
	EvaluationDatasetByteSize       int64    `json:"evaluation_dataset_byte_size"`
	EvaluationMetricsObjectID       string   `json:"evaluation_metrics_object_id"`
	EvaluationMetricsObjectSHA256   string   `json:"evaluation_metrics_object_sha256"`
	EvaluationMetricsObjectPath     string   `json:"evaluation_metrics_object_path"`
	EvaluationMetricsObjectByteSize int64    `json:"evaluation_metrics_object_byte_size"`
	EvaluationRuntimeID             string   `json:"evaluation_runtime_id"`
	EvaluationRuntimeSHA256         string   `json:"evaluation_runtime_sha256"`
	EvaluationRuntimePath           string   `json:"evaluation_runtime_path"`
	EvaluationRuntimeByteSize       int64    `json:"evaluation_runtime_byte_size"`
	RetrievalExecutableSHA256       string   `json:"retrieval_executable_sha256"`
	RetrievalExecutablePath         string   `json:"retrieval_executable_path"`
	RetrievalExecutableByteSize     int64    `json:"retrieval_executable_byte_size"`
	MissingCapabilities             []string `json:"missing_capabilities"`
}

type RetrievalGeneration struct {
	GenerationID            string `json:"generation_id"`
	GenerationPayloadSHA256 string `json:"generation_payload_sha256"`
	RetrievalGenerationCore
}

type StageGenerationConfig struct {
	HybridCandidatePath         string
	HybridCandidateHash         string
	StoreRoot                   string
	QualityReportPath           string
	QualityReportHash           string
	QualityReceiptPath          string
	QualityReceiptHash          string
	QualitySignaturePath        string
	QualitySignatureHash        string
	EvaluatorAllowedSignersPath string
	EvaluationDatasetPath       string
	EvaluationDatasetHash       string
	EvaluationMetricsPath       string
	EvaluationMetricsHash       string
	EvaluationRuntimePath       string
	EvaluationRuntimeHash       string
	EvaluatorExecutablePath     string
	EvaluatorExecutableHash     string
	AdmissionPolicyPath         string
	AdmissionPolicyHash         string
	RetrievalExecutablePath     string
	RetrievalExecutableHash     string
	BaseGenerationPath          string
	BaseGenerationHash          string
	AsOf                        string
}

type StageGenerationResult struct {
	Generation     RetrievalGeneration
	GenerationPath string
}

type RetrievalTransitionAssertions struct {
	TargetWholeGenerationVerified bool `json:"target_whole_generation_verified"`
	QualityEvidencePassed         bool `json:"quality_evidence_passed"`
	AdmissionPolicyFresh          bool `json:"admission_policy_fresh"`
	ArtifactBindingsVerified      bool `json:"artifact_bindings_verified"`
	EvidenceIDsVerified           bool `json:"evidence_ids_verified"`
	PriorPointerVerified          bool `json:"prior_pointer_verified"`
	TargetMatchesPriorPrevious    bool `json:"target_matches_prior_previous"`
}

type RetrievalTransitionAuthorization struct {
	Actor                string `json:"actor"`
	Method               string `json:"method"`
	KeyID                string `json:"key_id"`
	Namespace            string `json:"namespace"`
	AllowedSignersSHA256 string `json:"allowed_signers_sha256"`
}

type RetrievalTransitionIntentCore struct {
	SchemaVersion          string                           `json:"schema_version"`
	RecordKind             string                           `json:"record_kind"`
	Decision               string                           `json:"decision"`
	RollbackOfReceiptID    *string                          `json:"rollback_of_receipt_id"`
	TargetGenerationID     string                           `json:"target_generation_id"`
	TargetGenerationSHA256 string                           `json:"target_generation_document_sha256"`
	PriorPointerID         *string                          `json:"prior_pointer_id"`
	PriorPointerSHA256     *string                          `json:"prior_pointer_document_sha256"`
	TransitionAssertions   RetrievalTransitionAssertions    `json:"transition_assertions"`
	Authorization          RetrievalTransitionAuthorization `json:"authorization"`
	TransitionedAt         string                           `json:"transitioned_at"`
}

type RetrievalTransitionIntent struct {
	IntentID            string `json:"intent_id"`
	IntentPayloadSHA256 string `json:"intent_payload_sha256"`
	RetrievalTransitionIntentCore
}

type RetrievalTransitionReceiptIdentity struct {
	SchemaVersion          string                    `json:"schema_version"`
	RecordKind             string                    `json:"record_kind"`
	Intent                 RetrievalTransitionIntent `json:"intent"`
	IntentDocumentSHA256   string                    `json:"intent_document_sha256"`
	SignatureSHA256        string                    `json:"signature_sha256"`
	SignaturePath          string                    `json:"signature_path"`
	SignatureByteSize      int64                     `json:"signature_byte_size"`
	AllowedSignersSHA256   string                    `json:"allowed_signers_sha256"`
	AllowedSignersPath     string                    `json:"allowed_signers_path"`
	AllowedSignersByteSize int64                     `json:"allowed_signers_byte_size"`
}

type RetrievalTransitionReceipt struct {
	ReceiptID            string `json:"receipt_id"`
	ReceiptPayloadSHA256 string `json:"receipt_payload_sha256"`
	RetrievalTransitionReceiptIdentity
	ResultingPointerID     string `json:"resulting_pointer_id"`
	ResultingPointerSHA256 string `json:"resulting_pointer_document_sha256"`
}

type RetrievalGenerationPointerCore struct {
	SchemaVersion              string  `json:"schema_version"`
	RecordKind                 string  `json:"record_kind"`
	Revision                   int     `json:"revision"`
	CurrentGenerationID        string  `json:"current_generation_id"`
	CurrentGenerationSHA256    string  `json:"current_generation_document_sha256"`
	CurrentLexicalProfile      string  `json:"current_lexical_profile,omitempty"`
	CurrentLexicalTokenizerID  string  `json:"current_lexical_tokenizer_id,omitempty"`
	CurrentLexicalScorerID     string  `json:"current_lexical_scorer_id,omitempty"`
	PreviousGenerationID       *string `json:"previous_generation_id"`
	PreviousGenerationSHA256   *string `json:"previous_generation_document_sha256"`
	PreviousLexicalProfile     *string `json:"previous_lexical_profile,omitempty"`
	PreviousLexicalTokenizerID *string `json:"previous_lexical_tokenizer_id,omitempty"`
	PreviousLexicalScorerID    *string `json:"previous_lexical_scorer_id,omitempty"`
	TransitionReceiptID        string  `json:"transition_receipt_id"`
	UpdatedAt                  string  `json:"updated_at"`
}

type RetrievalGenerationPointer struct {
	PointerID            string `json:"pointer_id"`
	PointerPayloadSHA256 string `json:"pointer_payload_sha256"`
	RetrievalGenerationPointerCore
}

type PreparePromotionConfig struct {
	GenerationPath      string
	GenerationHash      string
	StoreRoot           string
	StateRoot           string
	AdmissionPolicyPath string
	AdmissionPolicyHash string
	AllowedSignersPath  string
	Actor               string
	KeyID               string
	TransitionedAt      string
	Bootstrap           bool
	ExpectPointerID     string
}

type PrepareRollbackConfig struct {
	StoreRoot           string
	StateRoot           string
	AdmissionPolicyPath string
	AdmissionPolicyHash string
	AllowedSignersPath  string
	Actor               string
	KeyID               string
	TransitionedAt      string
	ExpectPointerID     string
}

type ApplyTransitionConfig struct {
	StoreRoot           string
	StateRoot           string
	IntentPath          string
	IntentHash          string
	SignaturePath       string
	SignatureHash       string
	AllowedSignersPath  string
	AdmissionPolicyPath string
	AdmissionPolicyHash string
	GenerationPath      string
	GenerationHash      string
	ExpectedDecision    string
	Failpoint           string
}

type ApplyTransitionResult struct {
	State      string                     `json:"state"`
	Idempotent bool                       `json:"idempotent"`
	Decision   string                     `json:"decision"`
	Receipt    RetrievalTransitionReceipt `json:"receipt"`
	Pointer    RetrievalGenerationPointer `json:"pointer"`
}

type GenerationStatusConfig struct {
	StoreRoot           string
	StateRoot           string
	AdmissionPolicyPath string
	AdmissionPolicyHash string
	AsOf                string
	// AllowAbsentGeneration opts a caller into treating an absent generation
	// store as verified; it is never the default.
	AllowAbsentGeneration bool
}

type GenerationStatus struct {
	State                    string  `json:"state"`
	CurrentGenerationID      *string `json:"current_generation_id"`
	CurrentGenerationSHA256  *string `json:"current_generation_document_sha256"`
	PreviousGenerationID     *string `json:"previous_generation_id"`
	PreviousGenerationSHA256 *string `json:"previous_generation_document_sha256"`
	PointerID                *string `json:"pointer_id"`
	Revision                 int     `json:"revision"`
	TransitionReceiptID      *string `json:"transition_receipt_id"`
	UpdatedAt                *string `json:"updated_at"`
	ErrorCode                string  `json:"error_code,omitempty"`
}

type LifecycleError struct {
	Code    string
	Message string
}

func (e *LifecycleError) Error() string { return e.Message }
