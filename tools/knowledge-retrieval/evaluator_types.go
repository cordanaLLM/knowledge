package main

const (
	retrievalEvaluationSuiteKind   = "retrieval_frozen_held_out_suite"
	retrievalEvaluationMetricsKind = "retrieval_recomputed_metrics"
	retrievalEvaluationRuntimeKind = "retrieval_evaluator_runtime"
	retrievalMetricScale           = int64(1_000_000)
)

type RetrievalRelevanceJudgment struct {
	SpanID string `json:"span_id"`
	Grade  int    `json:"grade"`
}

type RetrievalEvaluationCase struct {
	CaseID                string                       `json:"case_id"`
	Class                 string                       `json:"class"`
	Query                 string                       `json:"query"`
	QuerySHA256           string                       `json:"query_sha256"`
	QuerySignalArtifactID string                       `json:"query_signal_artifact_id"`
	QuerySignalSHA256     string                       `json:"query_signal_document_sha256"`
	QuerySignalPath       string                       `json:"query_signal_path"`
	QuerySignalByteSize   int64                        `json:"query_signal_byte_size"`
	InjectionMarker       string                       `json:"injection_marker,omitempty"`
	RelevanceJudgments    []RetrievalRelevanceJudgment `json:"relevance_judgments"`
}

type RetrievalMetricThreshold struct {
	Class        string `json:"class"`
	Profile      string `json:"profile"`
	MinRecallPPM int64  `json:"min_recall_ppm"`
	MinMRRPPM    int64  `json:"min_mrr_ppm"`
	MinNDCGPPM   int64  `json:"min_ndcg_ppm"`
}

type RetrievalEvaluationResourceLimits struct {
	MaxExecutions            int   `json:"max_executions"`
	MaxDenseScannedDocuments int   `json:"max_dense_scanned_documents"`
	MaxReturnedResults       int   `json:"max_returned_results"`
	MaxReturnedExcerptBytes  int64 `json:"max_returned_excerpt_bytes"`
	MaxQuerySignalBytes      int64 `json:"max_query_signal_bytes"`
}

type RetrievalEvaluationSuiteCore struct {
	SchemaVersion               string                            `json:"schema_version"`
	SuiteKind                   string                            `json:"suite_kind"`
	State                       string                            `json:"state"`
	Name                        string                            `json:"name"`
	Revision                    string                            `json:"revision"`
	EvaluatedAt                 string                            `json:"evaluated_at"`
	LexicalCandidateID          string                            `json:"lexical_candidate_id"`
	LexicalCandidateSHA256      string                            `json:"lexical_candidate_document_sha256"`
	HybridCandidateID           string                            `json:"hybrid_candidate_id"`
	HybridCandidateSHA256       string                            `json:"hybrid_candidate_document_sha256"`
	AdmissionPolicyID           string                            `json:"admission_policy_id"`
	AdmissionPolicySHA256       string                            `json:"admission_policy_document_sha256"`
	SourceAdmissionMethod       string                            `json:"source_admission_method,omitempty"`
	SourceAdmissionPolicyID     string                            `json:"source_admission_policy_id,omitempty"`
	SourceAdmissionPolicySHA256 string                            `json:"source_admission_policy_sha256,omitempty"`
	TargetMode                  string                            `json:"target_mode"`
	MetricAlgorithm             string                            `json:"metric_algorithm"`
	MetricScale                 int64                             `json:"metric_scale"`
	CutoffK                     int                               `json:"cutoff_k"`
	Limit                       int                               `json:"limit"`
	FusionWindow                int                               `json:"fusion_window"`
	RerankWindow                int                               `json:"rerank_window"`
	MaxExcerptBytes             int                               `json:"max_excerpt_bytes"`
	RollbackMode                string                            `json:"rollback_mode"`
	ResourceLimits              RetrievalEvaluationResourceLimits `json:"resource_limits"`
	Thresholds                  []RetrievalMetricThreshold        `json:"thresholds"`
	Cases                       []RetrievalEvaluationCase         `json:"cases"`
}

type RetrievalEvaluationSuite struct {
	SuiteID            string `json:"suite_id"`
	SuitePayloadSHA256 string `json:"suite_payload_sha256"`
	RetrievalEvaluationSuiteCore
}

type RetrievalCaseMetric struct {
	CaseID      string   `json:"case_id"`
	Class       string   `json:"class"`
	Profile     string   `json:"profile"`
	RecallPPM   int64    `json:"recall_ppm"`
	MRRPPM      int64    `json:"mrr_ppm"`
	NDCGPPM     int64    `json:"ndcg_ppm"`
	ReturnedIDs []string `json:"returned_span_ids"`
}

type RetrievalAggregateMetric struct {
	Class           string `json:"class"`
	Profile         string `json:"profile"`
	QueryCount      int    `json:"query_count"`
	RecallPPM       int64  `json:"recall_ppm"`
	MRRPPM          int64  `json:"mrr_ppm"`
	NDCGPPM         int64  `json:"ndcg_ppm"`
	MinRecallPPM    int64  `json:"min_recall_ppm"`
	MinMRRPPM       int64  `json:"min_mrr_ppm"`
	MinNDCGPPM      int64  `json:"min_ndcg_ppm"`
	ThresholdPassed bool   `json:"threshold_passed"`
}

type RetrievalEvaluationResourceUsage struct {
	Executions            int   `json:"executions"`
	DenseScannedDocuments int   `json:"dense_scanned_documents"`
	ReturnedResults       int   `json:"returned_results"`
	ReturnedExcerptBytes  int64 `json:"returned_excerpt_bytes"`
	QuerySignalBytes      int64 `json:"query_signal_bytes"`
}

type RetrievalEvaluationMetricsCore struct {
	SchemaVersion          string                            `json:"schema_version"`
	MetricsKind            string                            `json:"metrics_kind"`
	State                  string                            `json:"state"`
	SuiteID                string                            `json:"suite_id"`
	SuiteSHA256            string                            `json:"suite_document_sha256"`
	LexicalCandidateID     string                            `json:"lexical_candidate_id"`
	LexicalCandidateSHA256 string                            `json:"lexical_candidate_document_sha256"`
	HybridCandidateID      string                            `json:"hybrid_candidate_id"`
	HybridCandidateSHA256  string                            `json:"hybrid_candidate_document_sha256"`
	AdmissionPolicyID      string                            `json:"admission_policy_id"`
	AdmissionPolicySHA256  string                            `json:"admission_policy_document_sha256"`
	MetricAlgorithm        string                            `json:"metric_algorithm"`
	MetricScale            int64                             `json:"metric_scale"`
	CutoffK                int                               `json:"cutoff_k"`
	TargetMode             string                            `json:"target_mode"`
	CaseMetrics            []RetrievalCaseMetric             `json:"case_metrics"`
	AggregateMetrics       []RetrievalAggregateMetric        `json:"aggregate_metrics"`
	ResourceLimits         RetrievalEvaluationResourceLimits `json:"resource_limits"`
	ResourceUsage          RetrievalEvaluationResourceUsage  `json:"resource_usage"`
	Gates                  RetrievalQualityGates             `json:"gates"`
}

type RetrievalEvaluationMetrics struct {
	MetricsID            string `json:"metrics_id"`
	MetricsPayloadSHA256 string `json:"metrics_payload_sha256"`
	RetrievalEvaluationMetricsCore
}

type RetrievalEvaluationRuntimeCore struct {
	SchemaVersion             string `json:"schema_version"`
	RuntimeKind               string `json:"runtime_kind"`
	State                     string `json:"state"`
	EvaluatorID               string `json:"evaluator_id"`
	EvaluatorRevision         string `json:"evaluator_revision"`
	EvaluatorExecutableSHA256 string `json:"evaluator_executable_sha256"`
	RetrievalExecutableSHA256 string `json:"retrieval_executable_sha256"`
	SuiteID                   string `json:"suite_id"`
	SuiteSHA256               string `json:"suite_document_sha256"`
	LexicalCandidateSHA256    string `json:"lexical_candidate_document_sha256"`
	HybridCandidateSHA256     string `json:"hybrid_candidate_document_sha256"`
	AdmissionPolicySHA256     string `json:"admission_policy_document_sha256"`
	MetricsSHA256             string `json:"metrics_document_sha256"`
	MetricAlgorithm           string `json:"metric_algorithm"`
	TargetMode                string `json:"target_mode"`
	EvaluatedAt               string `json:"evaluated_at"`
}

type RetrievalEvaluationRuntime struct {
	RuntimeID            string `json:"runtime_id"`
	RuntimePayloadSHA256 string `json:"runtime_payload_sha256"`
	RetrievalEvaluationRuntimeCore
}

type EvaluateRetrievalConfig struct {
	SuitePath                   string
	SuiteHash                   string
	LexicalCandidatePath        string
	LexicalCandidateHash        string
	HybridCandidatePath         string
	HybridCandidateHash         string
	StoreRoot                   string
	EvidenceStoreRoot           string
	QuerySignalStoreRoot        string
	AdmissionPolicyPath         string
	AdmissionPolicyHash         string
	RetrievalExecutablePath     string
	RetrievalExecutableHash     string
	EvaluatorExecutablePath     string
	EvaluatorExecutableHash     string
	EvaluatorAllowedSignersPath string
	EvaluatorActor              string
	EvaluatorKeyID              string
	BaseGenerationPath          string
	BaseGenerationHash          string
}

type EvaluateRetrievalResult struct {
	Suite              RetrievalEvaluationSuite
	Metrics            RetrievalEvaluationMetrics
	MetricsPath        string
	Runtime            RetrievalEvaluationRuntime
	RuntimePath        string
	QualityReport      RetrievalQualityReport
	QualityReportPath  string
	QualityReceipt     *RetrievalQualityReceipt
	QualityReceiptPath string
}
