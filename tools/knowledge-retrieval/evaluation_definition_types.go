package main

const (
	retrievalEvaluationDefinitionKind = "retrieval_expanded_evaluation_definition"
	retrievalEvaluationDefinitionV2   = "2.0.0"
	retrievalEvaluationDefinitionV3   = "3.0.0"
	maxEvaluationDefinitionBytes      = int64(8 * 1024 * 1024)
	maxEvaluationDefinitionInputs     = 8
	maxEvaluationDefinitionProfiles   = 8
	maxEvaluationDefinitionCases      = 10_000
)

type RetrievalEvaluationObjectBinding struct {
	BindingState                  string  `json:"binding_state"`
	GenerationID                  *string `json:"generation_id"`
	GenerationDocumentSHA256      *string `json:"generation_document_sha256"`
	AdmissionPolicyID             *string `json:"admission_policy_id"`
	AdmissionPolicyDocumentSHA256 *string `json:"admission_policy_document_sha256"`
}

// RetrievalEvaluationLaneObjectBindings separates generation authority from
// source-admission authority. A reviewed admission policy may therefore be
// bound exactly without implying that an externally evaluated generation
// exists. The combined v1/v2 object shape remains available only for decoding
// and replaying those immutable definition versions.
type RetrievalEvaluationLaneObjectBindings struct {
	Generation      RetrievalEvaluationGenerationBinding      `json:"generation"`
	AdmissionPolicy RetrievalEvaluationAdmissionPolicyBinding `json:"admission_policy"`
}

type RetrievalEvaluationGenerationBinding struct {
	BindingState             string  `json:"binding_state"`
	GenerationID             *string `json:"generation_id"`
	GenerationDocumentSHA256 *string `json:"generation_document_sha256"`
}

type RetrievalEvaluationAdmissionPolicyBinding struct {
	BindingState                  string  `json:"binding_state"`
	AdmissionPolicyID             *string `json:"admission_policy_id"`
	AdmissionPolicyDocumentSHA256 *string `json:"admission_policy_document_sha256"`
}

type RetrievalEvaluationLaneDefinition struct {
	LaneID           string                                 `json:"lane_id"`
	ComponentID      string                                 `json:"component_id"`
	ComponentVersion string                                 `json:"component_version"`
	RepositoryURI    string                                 `json:"repository_uri"`
	SourceCommitSHA  string                                 `json:"source_commit_sha"`
	Objects          *RetrievalEvaluationObjectBinding      `json:"objects,omitempty"`
	ObjectBindings   *RetrievalEvaluationLaneObjectBindings `json:"object_bindings,omitempty"`
}

type RetrievalEvaluationInputContract struct {
	SameQuerySet                   bool                                `json:"same_query_set"`
	SameEvidenceGeneration         bool                                `json:"same_evidence_generation"`
	CrossGenerationScoreComparison bool                                `json:"cross_generation_score_comparison"`
	PrincipalScope                 string                              `json:"principal_scope"`
	ReferenceSuiteID               *string                             `json:"reference_suite_id"`
	ReferenceSuiteDocumentSHA256   *string                             `json:"reference_suite_document_sha256"`
	QuerySignalBindingLedger       *RetrievalEvaluationBindingLedger   `json:"query_signal_binding_ledger,omitempty"`
	RequiredExactBindingFields     []string                            `json:"required_exact_binding_fields"`
	Lanes                          []RetrievalEvaluationLaneDefinition `json:"lanes"`
}

type RetrievalEvaluationBindingLedger struct {
	DocumentSHA256 string `json:"document_sha256"`
	RecordCount    int    `json:"record_count"`
}

type RetrievalEvaluationRerankerDefinition struct {
	BindingState              string                             `json:"binding_state"`
	ModelID                   string                             `json:"model_id"`
	ModelRevision             *string                            `json:"model_revision"`
	ModelArtifactSHA256       *string                            `json:"model_artifact_sha256"`
	ModelInventorySHA256      *string                            `json:"model_inventory_sha256"`
	TokenizerID               *string                            `json:"tokenizer_id"`
	TokenizerArtifactSHA256   *string                            `json:"tokenizer_artifact_sha256"`
	ServingRuntimeImageSHA256 *string                            `json:"serving_runtime_image_sha256"`
	BaseDeploymentRevisionSHA string                             `json:"base_deployment_revision_sha"`
	ProvenanceDeployment      RetrievalEvaluationRevisionBinding `json:"provenance_deployment"`
	ServingProfile            string                             `json:"serving_profile"`
	RerankerProfile           string                             `json:"reranker_profile"`
	SignalDerivationProfile   string                             `json:"signal_derivation_profile"`
	QueryInstruction          string                             `json:"query_instruction"`
	DocumentInstruction       string                             `json:"document_instruction"`
	ScoreScale                int64                              `json:"score_scale"`
}

type RetrievalEvaluationScorerBinding struct {
	BindingState         string  `json:"binding_state"`
	ScorerID             string  `json:"scorer_id"`
	ScorerRevision       *string `json:"scorer_revision"`
	ScorerArtifactSHA256 *string `json:"scorer_artifact_sha256"`
}

type RetrievalEvaluationQuerySignalBinding struct {
	BindingState   string  `json:"binding_state"`
	ArtifactID     *string `json:"artifact_id"`
	DocumentSHA256 *string `json:"document_sha256"`
}

type RetrievalEvaluationLaneQuerySignalBinding struct {
	LaneID            string                                `json:"lane_id"`
	HybridCandidateID string                                `json:"hybrid_candidate_id"`
	DenseArtifactID   string                                `json:"dense_artifact_id"`
	QuerySignal       RetrievalEvaluationQuerySignalBinding `json:"query_signal"`
}

type RetrievalEvaluationRevisionBinding struct {
	BindingState string  `json:"binding_state"`
	RevisionSHA  *string `json:"revision_sha"`
}

type RetrievalEvaluationProfileResourceLimits struct {
	MaxExecutions                 int   `json:"max_executions"`
	MaxScannedDocuments           int   `json:"max_scanned_documents"`
	MaxInputDocumentsPerExecution int   `json:"max_input_documents_per_execution"`
	MaxInputBytesPerExecution     int64 `json:"max_input_bytes_per_execution"`
	MaxReturnedResults            int   `json:"max_returned_results"`
	MaxReturnedExcerptBytes       int64 `json:"max_returned_excerpt_bytes"`
	MaxQuerySignalBytes           int64 `json:"max_query_signal_bytes"`
	MaxWallTimeMillisPerExecution int64 `json:"max_wall_time_ms_per_execution"`
	MaxCPUTimeMillisPerExecution  int64 `json:"max_cpu_time_ms_per_execution"`
	MaxPeakRSSBytes               int64 `json:"max_peak_rss_bytes"`
}

type RetrievalEvaluationFusionProfileBinding struct {
	BindingState   string  `json:"binding_state"`
	ProfileID      *string `json:"profile_id"`
	DocumentSHA256 *string `json:"document_sha256"`
}

type RetrievalEvaluationProfileDefinition struct {
	ProfileID           string                                   `json:"profile_id"`
	Role                string                                   `json:"role"`
	Mode                string                                   `json:"mode"`
	FusionProfile       string                                   `json:"fusion_profile"`
	FusionProfileObject *RetrievalEvaluationFusionProfileBinding `json:"fusion_profile_object,omitempty"`
	FusionConstant      int                                      `json:"fusion_constant"`
	FusionWindow        int                                      `json:"fusion_window"`
	RerankWindow        int                                      `json:"rerank_window"`
	Limit               int                                      `json:"limit"`
	MaxExcerptBytes     int                                      `json:"max_excerpt_bytes"`
	Scorer              RetrievalEvaluationScorerBinding         `json:"scorer"`
	Reranker            *RetrievalEvaluationRerankerDefinition   `json:"reranker"`
	ResourceLimits      RetrievalEvaluationProfileResourceLimits `json:"resource_limits"`
}

type RetrievalEvaluationAuthorityContract struct {
	DefinitionAuthority          string `json:"definition_authority"`
	RequiredLaneAuthority        string `json:"required_lane_authority"`
	RequiredEvaluatorAuthority   string `json:"required_evaluator_authority"`
	RequiredReleaseAuthority     string `json:"required_release_authority"`
	CallerLaneSelectionAllowed   bool   `json:"caller_lane_selection_allowed"`
	ScorerMayGrantAuthority      bool   `json:"scorer_may_grant_authority"`
	FailedLaneSuppressionAllowed bool   `json:"failed_lane_suppression_allowed"`
	ExactCitationsRequired       bool   `json:"exact_citations_required"`
}

type RetrievalEvaluationComparisonGates struct {
	MinimumRecallGainPPM       int64 `json:"minimum_recall_gain_ppm"`
	MinimumMRRGainPPM          int64 `json:"minimum_mrr_gain_ppm"`
	MinimumNDCGGainPPM         int64 `json:"minimum_ndcg_gain_ppm"`
	MaximumProtectedRegression int64 `json:"maximum_protected_regression_ppm"`
	MinimumCasesPerClass       int   `json:"minimum_cases_per_class"`
}

type RetrievalEvaluationEvidenceExpectation struct {
	LaneID          string  `json:"lane_id"`
	SelectorType    string  `json:"selector_type"`
	SpanID          *string `json:"span_id"`
	SourcePath      *string `json:"source_path"`
	SourceCommitSHA string  `json:"source_commit_sha"`
	Relation        string  `json:"relation"`
	MinimumGrade    int     `json:"minimum_grade"`
}

type RetrievalExpandedEvaluationCase struct {
	CaseID                string                                      `json:"case_id"`
	Class                 string                                      `json:"class"`
	Scenario              string                                      `json:"scenario"`
	Query                 string                                      `json:"query"`
	QuerySHA256           string                                      `json:"query_sha256"`
	QuerySignal           *RetrievalEvaluationQuerySignalBinding      `json:"query_signal,omitempty"`
	LaneQuerySignals      []RetrievalEvaluationLaneQuerySignalBinding `json:"lane_query_signals,omitempty"`
	ChallengerQuerySignal *RetrievalEvaluationQuerySignalBinding      `json:"challenger_query_signal,omitempty"`
	RequiredLaneIDs       []string                                    `json:"required_lane_ids"`
	ExpectedOutcome       string                                      `json:"expected_outcome"`
	ProtectedClass        bool                                        `json:"protected_class"`
	RequiredGates         []string                                    `json:"required_gates"`
	InjectionMarker       *string                                     `json:"injection_marker"`
	InjectionMarkerSHA256 *string                                     `json:"injection_marker_sha256"`
	UnavailableLaneID     *string                                     `json:"unavailable_lane_id"`
	ExpectedEvidence      []RetrievalEvaluationEvidenceExpectation    `json:"expected_evidence"`
}

type RetrievalExpandedEvaluationDefinitionCore struct {
	SchemaVersion   string                                 `json:"schema_version"`
	DefinitionKind  string                                 `json:"definition_kind"`
	State           string                                 `json:"state"`
	ExecutionState  string                                 `json:"execution_state"`
	Name            string                                 `json:"name"`
	Revision        string                                 `json:"revision"`
	FrozenAt        string                                 `json:"frozen_at"`
	ComparisonMode  string                                 `json:"comparison_mode"`
	MetricAlgorithm string                                 `json:"metric_algorithm"`
	MetricScale     int64                                  `json:"metric_scale"`
	CutoffK         int                                    `json:"cutoff_k"`
	Inputs          RetrievalEvaluationInputContract       `json:"inputs"`
	Profiles        []RetrievalEvaluationProfileDefinition `json:"profiles"`
	Authority       RetrievalEvaluationAuthorityContract   `json:"authority"`
	ComparisonGates RetrievalEvaluationComparisonGates     `json:"comparison_gates"`
	Cases           []RetrievalExpandedEvaluationCase      `json:"cases"`
}

type RetrievalExpandedEvaluationDefinition struct {
	DefinitionID            string `json:"definition_id"`
	DefinitionPayloadSHA256 string `json:"definition_payload_sha256"`
	RetrievalExpandedEvaluationDefinitionCore
}
