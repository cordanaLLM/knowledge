package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	evaluationObjectBindingExact    = "exact"
	evaluationObjectBindingRequired = "required_before_execution"
)

var evaluationCaseScenarios = map[string]string{
	"normal":           "evidence",
	"acl_forbidden":    "forbidden",
	"deleted_source":   "empty",
	"prompt_injection": "evidence",
	"stale_lane":       "stale",
	"conflicting_span": "fail_closed",
	"lane_unavailable": "partial",
}

var evaluationCaseGates = map[string]struct{}{
	"acl":                            {},
	"authority_isolation":            {},
	"citation_lineage":               {},
	"conflict":                       {},
	"deletion":                       {},
	"deterministic_replay":           {},
	"exact_input":                    {},
	"lane_unavailable":               {},
	"latency":                        {},
	"prompt_injection":               {},
	"protected_class_non_regression": {},
	"quality_gain":                   {},
	"resource":                       {},
	"stale":                          {},
}

func sealExpandedEvaluationDefinition(core RetrievalExpandedEvaluationDefinitionCore) (RetrievalExpandedEvaluationDefinition, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return RetrievalExpandedEvaluationDefinition{}, err
	}
	digest := digestBytes(data)
	definition := RetrievalExpandedEvaluationDefinition{
		DefinitionID:                              "retrieval-evaluation-definition:" + digest,
		DefinitionPayloadSHA256:                   digest,
		RetrievalExpandedEvaluationDefinitionCore: core,
	}
	if err := validateExpandedEvaluationDefinition(definition); err != nil {
		return RetrievalExpandedEvaluationDefinition{}, err
	}
	return definition, nil
}

func validateExpandedEvaluationDefinition(definition RetrievalExpandedEvaluationDefinition) error {
	coreBytes, err := json.Marshal(definition.RetrievalExpandedEvaluationDefinitionCore)
	if err != nil || definition.DefinitionPayloadSHA256 != digestBytes(coreBytes) || definition.DefinitionID != "retrieval-evaluation-definition:"+definition.DefinitionPayloadSHA256 {
		return errors.New("expanded evaluation definition identity mismatch")
	}
	if (definition.SchemaVersion != retrievalSchemaVersion && definition.SchemaVersion != retrievalEvaluationDefinitionV2 && definition.SchemaVersion != retrievalEvaluationDefinitionV3) || definition.DefinitionKind != retrievalEvaluationDefinitionKind || definition.State != "frozen" {
		return errors.New("expanded evaluation definition contract invalid")
	}
	if !boundedMetadata(definition.Name) || !boundedMetadata(definition.Revision) {
		return errors.New("expanded evaluation definition name or revision invalid")
	}
	if _, err := parseCanonicalUTC(definition.FrozenAt); err != nil {
		return fmt.Errorf("expanded evaluation definition frozen_at: %w", err)
	}
	if definition.ComparisonMode != "paired_reranker" && definition.ComparisonMode != "paired_fusion" && definition.ComparisonMode != "federated_lanes" {
		return errors.New("expanded evaluation comparison_mode invalid")
	}
	if definition.ComparisonMode == "paired_reranker" && definition.SchemaVersion != retrievalSchemaVersion {
		return errors.New("paired reranker definition schema version invalid")
	}
	if definition.ComparisonMode == "paired_fusion" && definition.SchemaVersion != retrievalEvaluationDefinitionV3 {
		return errors.New("paired fusion definition schema version invalid")
	}
	if definition.ComparisonMode == "federated_lanes" && definition.SchemaVersion != retrievalSchemaVersion && definition.SchemaVersion != retrievalEvaluationDefinitionV2 && definition.SchemaVersion != retrievalEvaluationDefinitionV3 {
		return errors.New("federated lane definition schema version invalid")
	}
	if definition.MetricAlgorithm != metricAlgorithm || definition.MetricScale != retrievalMetricScale || definition.CutoffK < 1 || definition.CutoffK > 20 {
		return errors.New("expanded evaluation metric contract invalid")
	}

	blocked, lanes, err := validateExpandedEvaluationInputs(definition.SchemaVersion, definition.ComparisonMode, definition.Inputs)
	if err != nil {
		return err
	}
	profileBlocked, err := validateExpandedEvaluationProfiles(definition.ComparisonMode, definition.CutoffK, definition.Profiles)
	if err != nil {
		return err
	}
	blocked = blocked || profileBlocked
	caseBlocked, err := validateExpandedEvaluationCases(definition.SchemaVersion, definition.ComparisonMode, definition.ComparisonGates.MinimumCasesPerClass, lanes, definition.Inputs.QuerySignalBindingLedger, definition.Cases)
	if err != nil {
		return err
	}
	blocked = blocked || caseBlocked
	wantExecutionState := "ready"
	if blocked {
		wantExecutionState = "blocked_exact_bindings"
	}
	if definition.ExecutionState != wantExecutionState {
		return fmt.Errorf("expanded evaluation execution_state must be %s", wantExecutionState)
	}
	if err := validateExpandedEvaluationAuthority(definition.Authority); err != nil {
		return err
	}
	if err := validateExpandedEvaluationComparisonGates(definition.ComparisonMode, definition.ComparisonGates); err != nil {
		return err
	}
	return nil
}

func validateExpandedEvaluationInputs(schemaVersion, mode string, inputs RetrievalEvaluationInputContract) (bool, map[string]RetrievalEvaluationLaneDefinition, error) {
	if !inputs.SameQuerySet || inputs.CrossGenerationScoreComparison || inputs.PrincipalScope != "public" {
		return false, nil, errors.New("expanded evaluation input comparison is not isolated")
	}
	blocked := false
	if mode == "paired_reranker" {
		if !inputs.SameEvidenceGeneration || inputs.ReferenceSuiteID == nil || inputs.ReferenceSuiteDocumentSHA256 == nil || !validPrefixedDigest(*inputs.ReferenceSuiteID, "retrieval-evaluation-suite:") || !validSHA256(*inputs.ReferenceSuiteDocumentSHA256) {
			return false, nil, errors.New("paired reranker input must bind one exact reference suite and evidence generation")
		}
		if inputs.QuerySignalBindingLedger != nil {
			return false, nil, errors.New("paired reranker input has an unexpected federation query-signal ledger")
		}
	} else if mode == "paired_fusion" {
		if !inputs.SameEvidenceGeneration || inputs.QuerySignalBindingLedger != nil {
			return false, nil, errors.New("paired fusion input must preserve one evidence generation without a federation query-signal ledger")
		}
		switch {
		case inputs.ReferenceSuiteID == nil && inputs.ReferenceSuiteDocumentSHA256 == nil:
			blocked = true
		case inputs.ReferenceSuiteID == nil || inputs.ReferenceSuiteDocumentSHA256 == nil:
			return false, nil, errors.New("paired fusion reference suite binding is partial")
		case !validPrefixedDigest(*inputs.ReferenceSuiteID, "retrieval-evaluation-suite:") || !validSHA256(*inputs.ReferenceSuiteDocumentSHA256):
			return false, nil, errors.New("paired fusion reference suite binding is invalid")
		}
	} else if inputs.SameEvidenceGeneration || inputs.ReferenceSuiteID != nil || inputs.ReferenceSuiteDocumentSHA256 != nil {
		return false, nil, errors.New("federated lanes must preserve independent generations without a single reference suite")
	}
	if mode == "federated_lanes" {
		if isLaneQuerySignalDefinition(schemaVersion) {
			if inputs.QuerySignalBindingLedger == nil || !validSHA256(inputs.QuerySignalBindingLedger.DocumentSHA256) || inputs.QuerySignalBindingLedger.RecordCount < 1 || inputs.QuerySignalBindingLedger.RecordCount > maxEvaluationDefinitionCases*maxEvaluationDefinitionInputs {
				return false, nil, errors.New("federated lane query-signal binding ledger is missing or invalid")
			}
		} else if inputs.QuerySignalBindingLedger != nil {
			return false, nil, errors.New("legacy federated lane definition cannot carry a lane query-signal ledger")
		}
	}
	wantFields := []string{
		"admission_policy_document_sha256",
		"admission_policy_id",
		"generation_document_sha256",
		"generation_id",
		"query_sha256",
		"query_signal_artifact_id",
		"query_signal_document_sha256",
		"scorer_artifact_sha256",
		"scorer_id",
		"scorer_revision",
		"source_commit_sha",
	}
	if mode == "federated_lanes" && isLaneQuerySignalDefinition(schemaVersion) {
		wantFields = append(wantFields,
			"query_signal_binding_ledger_document_sha256",
			"query_signal_binding_ledger_record_count",
			"query_signal_dense_artifact_id",
			"query_signal_hybrid_candidate_id",
			"query_signal_lane_id",
		)
		sort.Strings(wantFields)
	}
	if mode == "paired_reranker" || mode == "paired_fusion" {
		wantFields = append(wantFields,
			"challenger_query_signal_artifact_id",
			"challenger_query_signal_document_sha256",
			"reference_suite_document_sha256",
			"reference_suite_id",
		)
	}
	if mode == "paired_fusion" {
		wantFields = append(wantFields,
			"fusion_profile_document_sha256",
			"fusion_profile_id",
		)
	}
	if mode == "paired_reranker" {
		wantFields = append(wantFields,
			"reranker_base_deployment_revision_sha",
			"reranker_model_artifact_sha256",
			"reranker_model_id",
			"reranker_model_inventory_sha256",
			"reranker_model_revision",
			"reranker_provenance_deployment_revision_sha",
			"reranker_serving_runtime_image_sha256",
			"reranker_tokenizer_artifact_sha256",
			"reranker_tokenizer_id",
		)
	}
	sort.Strings(wantFields)
	if !equalStringSlices(inputs.RequiredExactBindingFields, wantFields) {
		return false, nil, errors.New("expanded evaluation exact binding field set invalid")
	}
	if len(inputs.Lanes) < 1 || len(inputs.Lanes) > maxEvaluationDefinitionInputs || ((mode == "paired_reranker" || mode == "paired_fusion") && len(inputs.Lanes) != 1) || (mode == "federated_lanes" && len(inputs.Lanes) < 2) {
		return false, nil, errors.New("expanded evaluation lane count invalid")
	}
	lanes := make(map[string]RetrievalEvaluationLaneDefinition, len(inputs.Lanes))
	previous := ""
	components := make(map[string]struct{}, len(inputs.Lanes))
	generationIdentities := make(map[string]string, len(inputs.Lanes))
	generationDocuments := make(map[string]string, len(inputs.Lanes))
	admissionIdentities := make(map[string]string, len(inputs.Lanes))
	admissionDocuments := make(map[string]string, len(inputs.Lanes))
	for index, lane := range inputs.Lanes {
		if !boundedMetadata(lane.LaneID) || !boundedMetadata(lane.ComponentID) || !boundedMetadata(lane.ComponentVersion) || (index > 0 && lane.LaneID <= previous) {
			return false, nil, errors.New("expanded evaluation lanes are invalid or not strict lane-ID order")
		}
		previous = lane.LaneID
		if _, exists := lanes[lane.LaneID]; exists {
			return false, nil, errors.New("expanded evaluation lane ID is duplicated")
		}
		if _, exists := components[lane.ComponentID]; exists {
			return false, nil, errors.New("expanded evaluation component is duplicated")
		}
		components[lane.ComponentID] = struct{}{}
		if !validRepositoryURI(lane.RepositoryURI) || !validGitCommitSHA(lane.SourceCommitSHA) {
			return false, nil, fmt.Errorf("expanded evaluation lane %s source binding invalid", lane.LaneID)
		}
		laneBlocked, err := validateEvaluationLaneObjectBindings(schemaVersion, lane, generationIdentities, generationDocuments, admissionIdentities, admissionDocuments)
		if err != nil {
			return false, nil, fmt.Errorf("expanded evaluation lane %s: %w", lane.LaneID, err)
		}
		blocked = blocked || laneBlocked
		lanes[lane.LaneID] = lane
	}
	return blocked, lanes, nil
}

func isLaneQuerySignalDefinition(schemaVersion string) bool {
	return schemaVersion == retrievalEvaluationDefinitionV2 || schemaVersion == retrievalEvaluationDefinitionV3
}

func validateEvaluationLaneObjectBindings(schemaVersion string, lane RetrievalEvaluationLaneDefinition, generationIdentities, generationDocuments, admissionIdentities, admissionDocuments map[string]string) (bool, error) {
	if schemaVersion != retrievalEvaluationDefinitionV3 {
		if lane.Objects == nil || lane.ObjectBindings != nil {
			return false, errors.New("legacy lane object binding shape invalid")
		}
		return validateEvaluationObjectBinding(*lane.Objects)
	}
	if lane.Objects != nil || lane.ObjectBindings == nil {
		return false, errors.New("v3 lane object binding shape invalid")
	}
	generationBlocked, err := validateEvaluationGenerationBinding(lane.ObjectBindings.Generation)
	if err != nil {
		return false, fmt.Errorf("generation: %w", err)
	}
	admissionBlocked, err := validateEvaluationAdmissionPolicyBinding(lane.ObjectBindings.AdmissionPolicy)
	if err != nil {
		return false, fmt.Errorf("admission policy: %w", err)
	}
	if !generationBlocked {
		if err := claimEvaluationObjectIdentity(lane.LaneID, *lane.ObjectBindings.Generation.GenerationID, generationIdentities, "generation identity"); err != nil {
			return false, err
		}
		if err := claimEvaluationObjectIdentity(lane.LaneID, *lane.ObjectBindings.Generation.GenerationDocumentSHA256, generationDocuments, "generation document"); err != nil {
			return false, err
		}
	}
	if !admissionBlocked {
		if err := claimEvaluationObjectIdentity(lane.LaneID, *lane.ObjectBindings.AdmissionPolicy.AdmissionPolicyID, admissionIdentities, "admission-policy identity"); err != nil {
			return false, err
		}
		if err := claimEvaluationObjectIdentity(lane.LaneID, *lane.ObjectBindings.AdmissionPolicy.AdmissionPolicyDocumentSHA256, admissionDocuments, "admission-policy document"); err != nil {
			return false, err
		}
	}
	return generationBlocked || admissionBlocked, nil
}

func claimEvaluationObjectIdentity(laneID, identity string, owners map[string]string, kind string) error {
	if owner, exists := owners[identity]; exists && owner != laneID {
		return fmt.Errorf("lanes %s and %s alias one %s", owner, laneID, kind)
	}
	owners[identity] = laneID
	return nil
}

func validateEvaluationObjectBinding(binding RetrievalEvaluationObjectBinding) (bool, error) {
	values := []*string{binding.GenerationID, binding.GenerationDocumentSHA256, binding.AdmissionPolicyID, binding.AdmissionPolicyDocumentSHA256}
	switch binding.BindingState {
	case evaluationObjectBindingRequired:
		for _, value := range values {
			if value != nil {
				return false, errors.New("required object binding must not contain a partial exact identity")
			}
		}
		return true, nil
	case evaluationObjectBindingExact:
		for _, value := range values {
			if value == nil {
				return false, errors.New("exact object binding is incomplete")
			}
		}
		if !validPrefixedDigest(*binding.GenerationID, "retrieval-generation:") || !validSHA256(*binding.GenerationDocumentSHA256) || !validPrefixedDigest(*binding.AdmissionPolicyID, "retrieval-admission:") || !validSHA256(*binding.AdmissionPolicyDocumentSHA256) {
			return false, errors.New("exact object binding contains an invalid identity")
		}
		return false, nil
	default:
		return false, errors.New("object binding state invalid")
	}
}

func validateEvaluationGenerationBinding(binding RetrievalEvaluationGenerationBinding) (bool, error) {
	values := []*string{binding.GenerationID, binding.GenerationDocumentSHA256}
	switch binding.BindingState {
	case evaluationObjectBindingRequired:
		for _, value := range values {
			if value != nil {
				return false, errors.New("required generation binding must not contain a partial exact identity")
			}
		}
		return true, nil
	case evaluationObjectBindingExact:
		for _, value := range values {
			if value == nil {
				return false, errors.New("exact generation binding is incomplete")
			}
		}
		if !validPrefixedDigest(*binding.GenerationID, "retrieval-generation:") || !validSHA256(*binding.GenerationDocumentSHA256) {
			return false, errors.New("exact generation binding contains an invalid identity")
		}
		return false, nil
	default:
		return false, errors.New("generation binding state invalid")
	}
}

func validateEvaluationAdmissionPolicyBinding(binding RetrievalEvaluationAdmissionPolicyBinding) (bool, error) {
	values := []*string{binding.AdmissionPolicyID, binding.AdmissionPolicyDocumentSHA256}
	switch binding.BindingState {
	case evaluationObjectBindingRequired:
		for _, value := range values {
			if value != nil {
				return false, errors.New("required admission-policy binding must not contain a partial exact identity")
			}
		}
		return true, nil
	case evaluationObjectBindingExact:
		for _, value := range values {
			if value == nil {
				return false, errors.New("exact admission-policy binding is incomplete")
			}
		}
		if !validPrefixedDigest(*binding.AdmissionPolicyID, "retrieval-admission:") || !validSHA256(*binding.AdmissionPolicyDocumentSHA256) {
			return false, errors.New("exact admission-policy binding contains an invalid identity")
		}
		return false, nil
	default:
		return false, errors.New("admission-policy binding state invalid")
	}
}

func validateExpandedEvaluationProfiles(mode string, cutoffK int, profiles []RetrievalEvaluationProfileDefinition) (bool, error) {
	if len(profiles) < 1 || len(profiles) > maxEvaluationDefinitionProfiles || ((mode == "paired_reranker" || mode == "paired_fusion") && len(profiles) != 2) || (mode == "federated_lanes" && len(profiles) != 1) {
		return false, errors.New("expanded evaluation profile count invalid")
	}
	blocked := false
	previous := ""
	baselineCount := 0
	challengerCount := 0
	pairedProfiles := make(map[string]RetrievalEvaluationProfileDefinition, 2)
	for index, profile := range profiles {
		if !boundedMetadata(profile.ProfileID) || (index > 0 && profile.ProfileID <= previous) || (profile.Role != "baseline" && profile.Role != "challenger") {
			return false, errors.New("expanded evaluation profiles are invalid or not strict profile-ID order")
		}
		previous = profile.ProfileID
		if profile.Role == "baseline" {
			baselineCount++
		} else {
			challengerCount++
		}
		if mode == "paired_fusion" {
			pairedProfiles[profile.Role] = profile
		}
		profileObjectBlocked, err := validateEvaluationFusionProfileBinding(mode, profile)
		if err != nil {
			return false, fmt.Errorf("expanded evaluation profile %s: %w", profile.ProfileID, err)
		}
		blocked = blocked || profileObjectBlocked
		if profile.Limit < cutoffK || profile.Limit > 100 || profile.FusionWindow < profile.Limit || profile.FusionWindow > 100 || profile.MaxExcerptBytes < 1 || profile.MaxExcerptBytes > 8192 {
			return false, errors.New("expanded evaluation profile retrieval bounds invalid")
		}
		scorerBlocked, err := validateEvaluationScorer(profile.Scorer, profile.FusionProfile)
		if err != nil {
			return false, fmt.Errorf("expanded evaluation profile %s: %w", profile.ProfileID, err)
		}
		blocked = blocked || scorerBlocked
		switch profile.Mode {
		case "fusion_only":
			validPairedRerankerBaseline := mode == "paired_reranker" && profile.Role == "baseline" && profile.FusionProfile == hybridFusionProfile
			validPairedFusionProfile := mode == "paired_fusion" && ((profile.Role == "baseline" && profile.FusionProfile == hybridFusionProfile) || (profile.Role == "challenger" && profile.FusionProfile == championFusionProfile))
			if (!validPairedRerankerBaseline && !validPairedFusionProfile) || profile.FusionConstant != 60 || profile.RerankWindow != 0 || profile.Reranker != nil {
				return false, errors.New("fusion-only profile invalid")
			}
		case "reranked":
			if mode != "paired_reranker" || profile.Role != "challenger" || profile.FusionProfile != hybridFusionProfile || profile.FusionConstant != 60 || profile.RerankWindow < profile.Limit || profile.RerankWindow > profile.FusionWindow || profile.Reranker == nil {
				return false, errors.New("reranked challenger profile invalid")
			}
			rerankerBlocked, err := validateEvaluationReranker(*profile.Reranker)
			if err != nil {
				return false, err
			}
			blocked = blocked || rerankerBlocked
		case "federated_fusion":
			if mode != "federated_lanes" || profile.Role != "baseline" || profile.FusionProfile != "bounded_borda_v1" || profile.FusionConstant != 0 || profile.RerankWindow != 0 || profile.Reranker != nil {
				return false, errors.New("federated fusion profile invalid")
			}
		default:
			return false, errors.New("expanded evaluation profile mode invalid")
		}
		if err := validateEvaluationProfileResources(profile.ResourceLimits); err != nil {
			return false, fmt.Errorf("expanded evaluation profile %s: %w", profile.ProfileID, err)
		}
	}
	if baselineCount != 1 || ((mode == "paired_reranker" || mode == "paired_fusion") && challengerCount != 1) || (mode == "federated_lanes" && challengerCount != 0) {
		return false, errors.New("expanded evaluation profile roles invalid")
	}
	if mode == "paired_fusion" {
		baseline := pairedProfiles["baseline"]
		challenger := pairedProfiles["challenger"]
		if baseline.FusionConstant != challenger.FusionConstant || baseline.FusionWindow != challenger.FusionWindow || baseline.RerankWindow != challenger.RerankWindow || baseline.Limit != challenger.Limit || baseline.MaxExcerptBytes != challenger.MaxExcerptBytes || baseline.ResourceLimits != challenger.ResourceLimits {
			return false, errors.New("paired fusion profiles do not isolate the fusion algorithm")
		}
	}
	return blocked, nil
}

func validateEvaluationFusionProfileBinding(mode string, profile RetrievalEvaluationProfileDefinition) (bool, error) {
	if mode != "paired_fusion" || profile.Role == "baseline" {
		if profile.FusionProfileObject != nil {
			return false, errors.New("implicit or non-paired fusion profile cannot bind a profile object")
		}
		return false, nil
	}
	if profile.Role != "challenger" || profile.FusionProfile != championFusionProfile || profile.FusionProfileObject == nil {
		return false, errors.New("paired fusion challenger lacks its content-addressed profile binding")
	}
	binding := profile.FusionProfileObject
	switch binding.BindingState {
	case evaluationObjectBindingRequired:
		if binding.ProfileID != nil || binding.DocumentSHA256 != nil {
			return false, errors.New("required fusion-profile binding must not contain a partial exact identity")
		}
		return true, nil
	case evaluationObjectBindingExact:
		if binding.ProfileID == nil || binding.DocumentSHA256 == nil || !validPrefixedDigest(*binding.ProfileID, "fusion-profile:") || !validSHA256(*binding.DocumentSHA256) {
			return false, errors.New("exact fusion-profile binding is incomplete or invalid")
		}
		return false, nil
	default:
		return false, errors.New("fusion-profile binding state invalid")
	}
}

func validateEvaluationScorer(scorer RetrievalEvaluationScorerBinding, fusionProfile string) (bool, error) {
	if !boundedMetadata(scorer.ScorerID) || scorer.ScorerID != fusionProfile {
		return false, errors.New("scorer identity does not match the frozen fusion profile")
	}
	values := []*string{scorer.ScorerRevision, scorer.ScorerArtifactSHA256}
	switch scorer.BindingState {
	case evaluationObjectBindingRequired:
		for _, value := range values {
			if value != nil {
				return false, errors.New("required scorer binding must not contain a partial exact identity")
			}
		}
		return true, nil
	case evaluationObjectBindingExact:
		for _, value := range values {
			if value == nil {
				return false, errors.New("exact scorer binding is incomplete")
			}
		}
		if !boundedMetadata(*scorer.ScorerRevision) || !validSHA256(*scorer.ScorerArtifactSHA256) {
			return false, errors.New("exact scorer binding contains an invalid identity")
		}
		return false, nil
	default:
		return false, errors.New("scorer binding state invalid")
	}
}

func validateEvaluationReranker(reranker RetrievalEvaluationRerankerDefinition) (bool, error) {
	if !boundedMetadata(reranker.ModelID) || !validGitCommitSHA(reranker.BaseDeploymentRevisionSHA) || !boundedMetadata(reranker.ServingProfile) || !boundedMetadata(reranker.RerankerProfile) || reranker.SignalDerivationProfile != hybridRerankingContract || !boundedMetadata(reranker.QueryInstruction) || !boundedMetadata(reranker.DocumentInstruction) || reranker.ScoreScale < 1 || reranker.ScoreScale > 1_000_000_000 {
		return false, errors.New("expanded evaluation reranker metadata invalid")
	}
	provenanceBlocked, err := validateEvaluationRevisionBinding(reranker.ProvenanceDeployment)
	if err != nil {
		return false, fmt.Errorf("expanded evaluation reranker provenance deployment: %w", err)
	}
	values := []*string{reranker.ModelRevision, reranker.ModelArtifactSHA256, reranker.ModelInventorySHA256, reranker.TokenizerID, reranker.TokenizerArtifactSHA256, reranker.ServingRuntimeImageSHA256}
	switch reranker.BindingState {
	case evaluationObjectBindingRequired:
		for _, value := range values {
			if value != nil {
				return false, errors.New("required reranker binding must not contain a partial exact identity")
			}
		}
		return true, nil
	case evaluationObjectBindingExact:
		for _, value := range values {
			if value == nil {
				return false, errors.New("exact reranker binding is incomplete")
			}
		}
		if !boundedMetadata(*reranker.ModelRevision) || !validSHA256(*reranker.ModelArtifactSHA256) || !validSHA256(*reranker.ModelInventorySHA256) || !boundedMetadata(*reranker.TokenizerID) || !validSHA256(*reranker.TokenizerArtifactSHA256) || !validSHA256(*reranker.ServingRuntimeImageSHA256) {
			return false, errors.New("exact reranker binding contains an invalid identity")
		}
		return provenanceBlocked, nil
	default:
		return false, errors.New("reranker binding state invalid")
	}
}

func validateEvaluationRevisionBinding(binding RetrievalEvaluationRevisionBinding) (bool, error) {
	switch binding.BindingState {
	case evaluationObjectBindingRequired:
		if binding.RevisionSHA != nil {
			return false, errors.New("required revision binding must not contain a partial exact identity")
		}
		return true, nil
	case evaluationObjectBindingExact:
		if binding.RevisionSHA == nil || !validGitCommitSHA(*binding.RevisionSHA) {
			return false, errors.New("exact revision binding is incomplete or invalid")
		}
		return false, nil
	default:
		return false, errors.New("revision binding state invalid")
	}
}

func validateEvaluationProfileResources(resources RetrievalEvaluationProfileResourceLimits) error {
	if resources.MaxExecutions < 1 || resources.MaxScannedDocuments < 1 || resources.MaxInputDocumentsPerExecution < 1 || resources.MaxInputBytesPerExecution < 1 || resources.MaxReturnedResults < 1 || resources.MaxReturnedExcerptBytes < 1 || resources.MaxQuerySignalBytes < 1 || resources.MaxWallTimeMillisPerExecution < 1 || resources.MaxCPUTimeMillisPerExecution < 1 || resources.MaxPeakRSSBytes < 1 {
		return errors.New("resource limits must be positive")
	}
	if resources.MaxExecutions > 100_000 || resources.MaxScannedDocuments > 100_000_000 || resources.MaxInputDocumentsPerExecution > 1_000_000 || resources.MaxInputBytesPerExecution > 1<<30 || resources.MaxReturnedResults > 10_000_000 || resources.MaxReturnedExcerptBytes > 1<<30 || resources.MaxQuerySignalBytes > 64<<20 || resources.MaxWallTimeMillisPerExecution > 600_000 || resources.MaxCPUTimeMillisPerExecution > 4_800_000 || resources.MaxPeakRSSBytes > 1<<40 {
		return errors.New("resource limits exceed the expanded evaluation ceiling")
	}
	if resources.MaxReturnedResults > resources.MaxExecutions*100 || resources.MaxInputDocumentsPerExecution > resources.MaxScannedDocuments {
		return errors.New("resource limits are internally inconsistent")
	}
	return nil
}

func validateExpandedEvaluationAuthority(authority RetrievalEvaluationAuthorityContract) error {
	if authority.DefinitionAuthority != "git_reviewed_frozen_definition" || authority.RequiredLaneAuthority != "reviewed_signed_current" || authority.RequiredEvaluatorAuthority != "external_signed_evaluator" || authority.RequiredReleaseAuthority != "separate_signed_transition" || authority.CallerLaneSelectionAllowed || authority.ScorerMayGrantAuthority || authority.FailedLaneSuppressionAllowed || !authority.ExactCitationsRequired {
		return errors.New("expanded evaluation authority contract invalid")
	}
	return nil
}

func validateExpandedEvaluationComparisonGates(mode string, gates RetrievalEvaluationComparisonGates) error {
	for _, value := range []int64{gates.MinimumRecallGainPPM, gates.MinimumMRRGainPPM, gates.MinimumNDCGGainPPM, gates.MaximumProtectedRegression} {
		if value < 0 || value > retrievalMetricScale {
			return errors.New("expanded evaluation comparison gate outside metric scale")
		}
	}
	if gates.MinimumCasesPerClass < 1 || gates.MinimumCasesPerClass > maxEvaluationDefinitionCases {
		return errors.New("expanded evaluation minimum cases per class invalid")
	}
	if (mode == "paired_reranker" || mode == "paired_fusion") && gates.MinimumRecallGainPPM == 0 && gates.MinimumMRRGainPPM == 0 && gates.MinimumNDCGGainPPM == 0 {
		return errors.New("paired challenger definition requires a positive quality gain")
	}
	if mode == "federated_lanes" && (gates.MinimumRecallGainPPM != 0 || gates.MinimumMRRGainPPM != 0 || gates.MinimumNDCGGainPPM != 0 || gates.MaximumProtectedRegression != 0) {
		return errors.New("federated lane definition cannot claim an unmeasured challenger gain")
	}
	return nil
}

func validateExpandedEvaluationCases(schemaVersion, mode string, minimumCasesPerClass int, lanes map[string]RetrievalEvaluationLaneDefinition, ledger *RetrievalEvaluationBindingLedger, cases []RetrievalExpandedEvaluationCase) (bool, error) {
	if len(cases) < 1 || len(cases) > maxEvaluationDefinitionCases {
		return false, errors.New("expanded evaluation case count invalid")
	}
	blocked := false
	previousCase := ""
	classes := make(map[string]int)
	coveredGates := make(map[string]struct{})
	normalLaneCoverage := make(map[string]bool, len(lanes))
	laneSignalState := newEvaluationLaneQuerySignalValidationState()
	for index, evaluationCase := range cases {
		if !boundedMetadata(evaluationCase.CaseID) || !boundedMetadata(evaluationCase.Class) || (index > 0 && evaluationCase.CaseID <= previousCase) {
			return false, errors.New("expanded evaluation cases are invalid or not strict case-ID order")
		}
		previousCase = evaluationCase.CaseID
		classes[evaluationCase.Class]++
		if strings.TrimSpace(evaluationCase.Query) != evaluationCase.Query || evaluationCase.Query == "" || len(evaluationCase.Query) > 16*1024 || evaluationCase.QuerySHA256 != digestBytes([]byte(evaluationCase.Query)) {
			return false, fmt.Errorf("expanded evaluation case %s query binding invalid", evaluationCase.CaseID)
		}
		switch {
		case mode == "paired_reranker" || mode == "paired_fusion":
			if evaluationCase.QuerySignal == nil || evaluationCase.LaneQuerySignals != nil {
				return false, fmt.Errorf("expanded evaluation case %s paired query-signal shape invalid", evaluationCase.CaseID)
			}
			querySignalBlocked, err := validateEvaluationQuerySignal(*evaluationCase.QuerySignal)
			if err != nil {
				return false, fmt.Errorf("expanded evaluation case %s: %w", evaluationCase.CaseID, err)
			}
			blocked = blocked || querySignalBlocked
			if evaluationCase.ChallengerQuerySignal == nil {
				return false, fmt.Errorf("expanded evaluation case %s lacks its challenger query-signal binding", evaluationCase.CaseID)
			}
			challengerBlocked, err := validateEvaluationQuerySignal(*evaluationCase.ChallengerQuerySignal)
			if err != nil {
				return false, fmt.Errorf("expanded evaluation case %s challenger: %w", evaluationCase.CaseID, err)
			}
			if !challengerBlocked && !querySignalBlocked && (*evaluationCase.ChallengerQuerySignal.ArtifactID == *evaluationCase.QuerySignal.ArtifactID || *evaluationCase.ChallengerQuerySignal.DocumentSHA256 == *evaluationCase.QuerySignal.DocumentSHA256) {
				return false, fmt.Errorf("expanded evaluation case %s reuses its fusion-only signal as a challenger signal", evaluationCase.CaseID)
			}
			blocked = blocked || challengerBlocked
		case isLaneQuerySignalDefinition(schemaVersion):
			if evaluationCase.QuerySignal != nil || evaluationCase.ChallengerQuerySignal != nil {
				return false, fmt.Errorf("expanded evaluation case %s lane-bound federation uses a singular query-signal binding", evaluationCase.CaseID)
			}
			querySignalsBlocked, err := validateFederatedLaneQuerySignals(evaluationCase, lanes, laneSignalState)
			if err != nil {
				return false, err
			}
			blocked = blocked || querySignalsBlocked
		default:
			if evaluationCase.QuerySignal == nil || evaluationCase.LaneQuerySignals != nil || evaluationCase.ChallengerQuerySignal != nil {
				return false, fmt.Errorf("expanded evaluation case %s legacy federation query-signal shape invalid", evaluationCase.CaseID)
			}
			querySignalBlocked, err := validateEvaluationQuerySignal(*evaluationCase.QuerySignal)
			if err != nil {
				return false, fmt.Errorf("expanded evaluation case %s: %w", evaluationCase.CaseID, err)
			}
			if !querySignalBlocked {
				return false, fmt.Errorf("expanded evaluation case %s legacy singular federation query signal cannot become exact", evaluationCase.CaseID)
			}
			blocked = true
		}
		wantOutcome, exists := evaluationCaseScenarios[evaluationCase.Scenario]
		if !exists || evaluationCase.ExpectedOutcome != wantOutcome {
			return false, fmt.Errorf("expanded evaluation case %s scenario outcome invalid", evaluationCase.CaseID)
		}
		if !strictKnownLaneIDs(evaluationCase.RequiredLaneIDs, lanes) {
			return false, fmt.Errorf("expanded evaluation case %s lane set invalid", evaluationCase.CaseID)
		}
		if !strictKnownGates(evaluationCase.RequiredGates, coveredGates) {
			return false, fmt.Errorf("expanded evaluation case %s gate set invalid", evaluationCase.CaseID)
		}
		if evaluationCase.Scenario == "prompt_injection" {
			if evaluationCase.InjectionMarker == nil || evaluationCase.InjectionMarkerSHA256 == nil || !boundedMetadata(*evaluationCase.InjectionMarker) || *evaluationCase.InjectionMarkerSHA256 != digestBytes([]byte(*evaluationCase.InjectionMarker)) {
				return false, fmt.Errorf("expanded evaluation case %s injection binding invalid", evaluationCase.CaseID)
			}
		} else if evaluationCase.InjectionMarker != nil || evaluationCase.InjectionMarkerSHA256 != nil {
			return false, fmt.Errorf("expanded evaluation case %s has an unexpected injection binding", evaluationCase.CaseID)
		}
		if evaluationCase.Scenario == "lane_unavailable" {
			if evaluationCase.UnavailableLaneID == nil || !sortedContainsString(evaluationCase.RequiredLaneIDs, *evaluationCase.UnavailableLaneID) {
				return false, fmt.Errorf("expanded evaluation case %s unavailable lane binding invalid", evaluationCase.CaseID)
			}
		} else if evaluationCase.UnavailableLaneID != nil {
			return false, fmt.Errorf("expanded evaluation case %s has an unexpected unavailable lane", evaluationCase.CaseID)
		}
		if err := validateEvaluationEvidenceExpectations(evaluationCase, lanes); err != nil {
			return false, err
		}
		if evaluationCase.Scenario == "normal" {
			for _, laneID := range evaluationCase.RequiredLaneIDs {
				normalLaneCoverage[laneID] = true
			}
		}
	}
	if mode == "federated_lanes" && isLaneQuerySignalDefinition(schemaVersion) && (ledger == nil || ledger.RecordCount != laneSignalState.bindingCount || ledger.RecordCount != len(cases)*len(lanes)) {
		return false, errors.New("federated lane query-signal ledger record count does not cover the complete case-by-lane matrix")
	}
	for class, count := range classes {
		if count < minimumCasesPerClass {
			return false, fmt.Errorf("expanded evaluation class %s has too few cases", class)
		}
	}
	requiredGates := []string{"citation_lineage", "deterministic_replay", "exact_input", "latency", "resource"}
	if mode == "paired_reranker" || mode == "paired_fusion" {
		requiredGates = append(requiredGates, "protected_class_non_regression", "quality_gain")
	} else {
		requiredGates = append(requiredGates, "acl", "authority_isolation", "conflict", "deletion", "lane_unavailable", "prompt_injection", "stale")
		for laneID := range lanes {
			if !normalLaneCoverage[laneID] {
				return false, fmt.Errorf("expanded evaluation lane %s lacks a normal held-out case", laneID)
			}
		}
	}
	for _, gate := range requiredGates {
		if _, exists := coveredGates[gate]; !exists {
			return false, fmt.Errorf("expanded evaluation required gate %s is uncovered", gate)
		}
	}
	return blocked, nil
}

type evaluationLaneQuerySignalValidationState struct {
	lineageByLane  map[string]string
	hybridOwners   map[string]string
	denseOwners    map[string]string
	artifactOwners map[string]string
	documentOwners map[string]string
	bindingCount   int
}

func newEvaluationLaneQuerySignalValidationState() *evaluationLaneQuerySignalValidationState {
	return &evaluationLaneQuerySignalValidationState{
		lineageByLane:  make(map[string]string),
		hybridOwners:   make(map[string]string),
		denseOwners:    make(map[string]string),
		artifactOwners: make(map[string]string),
		documentOwners: make(map[string]string),
	}
}

func validateFederatedLaneQuerySignals(evaluationCase RetrievalExpandedEvaluationCase, lanes map[string]RetrievalEvaluationLaneDefinition, state *evaluationLaneQuerySignalValidationState) (bool, error) {
	if len(evaluationCase.LaneQuerySignals) != len(lanes) {
		return false, fmt.Errorf("expanded evaluation case %s does not bind one query signal for every federation lane", evaluationCase.CaseID)
	}
	previousLane := ""
	for index, laneSignal := range evaluationCase.LaneQuerySignals {
		if !boundedMetadata(laneSignal.LaneID) || (index > 0 && laneSignal.LaneID <= previousLane) {
			return false, fmt.Errorf("expanded evaluation case %s lane query signals are not in strict lane-ID order", evaluationCase.CaseID)
		}
		previousLane = laneSignal.LaneID
		if _, exists := lanes[laneSignal.LaneID]; !exists {
			return false, fmt.Errorf("expanded evaluation case %s query signal binds an unknown lane", evaluationCase.CaseID)
		}
		if !validPrefixedDigest(laneSignal.HybridCandidateID, "hybrid-retrieval-candidate:") || !validPrefixedDigest(laneSignal.DenseArtifactID, "dense-vector-artifact:") {
			return false, fmt.Errorf("expanded evaluation case %s lane %s query-signal lineage invalid", evaluationCase.CaseID, laneSignal.LaneID)
		}
		lineage := laneSignal.HybridCandidateID + "\x00" + laneSignal.DenseArtifactID
		if previous, exists := state.lineageByLane[laneSignal.LaneID]; exists && previous != lineage {
			return false, fmt.Errorf("expanded evaluation case %s lane %s query-signal lineage changed across cases", evaluationCase.CaseID, laneSignal.LaneID)
		} else if !exists {
			state.lineageByLane[laneSignal.LaneID] = lineage
		}
		if owner, exists := state.hybridOwners[laneSignal.HybridCandidateID]; exists && owner != laneSignal.LaneID {
			return false, fmt.Errorf("expanded evaluation lanes %s and %s alias one hybrid candidate", owner, laneSignal.LaneID)
		}
		state.hybridOwners[laneSignal.HybridCandidateID] = laneSignal.LaneID
		if owner, exists := state.denseOwners[laneSignal.DenseArtifactID]; exists && owner != laneSignal.LaneID {
			return false, fmt.Errorf("expanded evaluation lanes %s and %s alias one dense artifact", owner, laneSignal.LaneID)
		}
		state.denseOwners[laneSignal.DenseArtifactID] = laneSignal.LaneID
		querySignalBlocked, err := validateEvaluationQuerySignal(laneSignal.QuerySignal)
		if err != nil {
			return false, fmt.Errorf("expanded evaluation case %s lane %s: %w", evaluationCase.CaseID, laneSignal.LaneID, err)
		}
		if querySignalBlocked {
			return false, fmt.Errorf("expanded evaluation case %s lane %s is unresolved despite an exact v2 binding ledger", evaluationCase.CaseID, laneSignal.LaneID)
		}
		ownerKey := evaluationCase.CaseID + "/" + laneSignal.LaneID
		if owner, exists := state.artifactOwners[*laneSignal.QuerySignal.ArtifactID]; exists {
			return false, fmt.Errorf("expanded evaluation query-signal artifact is aliased by %s and %s", owner, ownerKey)
		}
		state.artifactOwners[*laneSignal.QuerySignal.ArtifactID] = ownerKey
		if owner, exists := state.documentOwners[*laneSignal.QuerySignal.DocumentSHA256]; exists {
			return false, fmt.Errorf("expanded evaluation query-signal document is aliased by %s and %s", owner, ownerKey)
		}
		state.documentOwners[*laneSignal.QuerySignal.DocumentSHA256] = ownerKey
		state.bindingCount++
	}
	return false, nil
}

func validateEvaluationQuerySignal(binding RetrievalEvaluationQuerySignalBinding) (bool, error) {
	values := []*string{binding.ArtifactID, binding.DocumentSHA256}
	switch binding.BindingState {
	case evaluationObjectBindingRequired:
		for _, value := range values {
			if value != nil {
				return false, errors.New("required query-signal binding must not contain a partial exact identity")
			}
		}
		return true, nil
	case evaluationObjectBindingExact:
		for _, value := range values {
			if value == nil {
				return false, errors.New("exact query-signal binding is incomplete")
			}
		}
		if !validPrefixedDigest(*binding.ArtifactID, "query-signal-artifact:") || !validSHA256(*binding.DocumentSHA256) {
			return false, errors.New("exact query-signal binding contains an invalid identity")
		}
		return false, nil
	default:
		return false, errors.New("query-signal binding state invalid")
	}
}

func validateEvaluationEvidenceExpectations(evaluationCase RetrievalExpandedEvaluationCase, lanes map[string]RetrievalEvaluationLaneDefinition) error {
	if len(evaluationCase.ExpectedEvidence) > 1000 {
		return fmt.Errorf("expanded evaluation case %s has too many evidence expectations", evaluationCase.CaseID)
	}
	if (evaluationCase.Scenario == "normal" || evaluationCase.Scenario == "prompt_injection") && len(evaluationCase.ExpectedEvidence) < 1 {
		return fmt.Errorf("expanded evaluation case %s requires expected evidence", evaluationCase.CaseID)
	}
	previous := ""
	for _, expected := range evaluationCase.ExpectedEvidence {
		lane, exists := lanes[expected.LaneID]
		if !exists || !sortedContainsString(evaluationCase.RequiredLaneIDs, expected.LaneID) || expected.SourceCommitSHA != lane.SourceCommitSHA || (expected.Relation != "supports" && expected.Relation != "qualifies" && expected.Relation != "contradicts") || expected.MinimumGrade < 1 || expected.MinimumGrade > 3 {
			return fmt.Errorf("expanded evaluation case %s evidence authority binding invalid", evaluationCase.CaseID)
		}
		selector := ""
		switch expected.SelectorType {
		case "span_id":
			if expected.SpanID == nil || expected.SourcePath != nil || !validPrefixedDigest(*expected.SpanID, "evidence-span:") {
				return fmt.Errorf("expanded evaluation case %s span selector invalid", evaluationCase.CaseID)
			}
			selector = *expected.SpanID
		case "source_path":
			if expected.SourcePath == nil || expected.SpanID != nil || validateRelativePath(*expected.SourcePath) != nil || len(*expected.SourcePath) > 4096 {
				return fmt.Errorf("expanded evaluation case %s source-path selector invalid", evaluationCase.CaseID)
			}
			selector = *expected.SourcePath
		default:
			return fmt.Errorf("expanded evaluation case %s selector type invalid", evaluationCase.CaseID)
		}
		key := expected.LaneID + "\x00" + expected.SelectorType + "\x00" + selector + "\x00" + expected.Relation
		if key <= previous {
			return fmt.Errorf("expanded evaluation case %s evidence selectors are not strict order", evaluationCase.CaseID)
		}
		previous = key
	}
	return nil
}

func strictKnownLaneIDs(values []string, lanes map[string]RetrievalEvaluationLaneDefinition) bool {
	if len(values) < 1 || len(values) > len(lanes) {
		return false
	}
	previous := ""
	for index, value := range values {
		if _, exists := lanes[value]; !exists || (index > 0 && value <= previous) {
			return false
		}
		previous = value
	}
	return true
}

func strictKnownGates(values []string, covered map[string]struct{}) bool {
	if len(values) < 1 || len(values) > len(evaluationCaseGates) {
		return false
	}
	previous := ""
	for index, value := range values {
		if _, exists := evaluationCaseGates[value]; !exists || (index > 0 && value <= previous) {
			return false
		}
		previous = value
		covered[value] = struct{}{}
	}
	return true
}

func validGitCommitSHA(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validRepositoryURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && strings.TrimSpace(value) == value && len(value) <= 2048 && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path != ""
}

func equalStringSlices(left, right []string) bool {
	if left == nil || right == nil || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortedContainsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}
