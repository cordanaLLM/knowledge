package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	multidomainBindingRequirementsVersion        = "1.0.0"
	multidomainBindingRequirementsKind           = "retrieval_multidomain_binding_requirements"
	multidomainBindingRequirementsState          = "blocked"
	multidomainBindingRequirementsExecutionState = "blocked_absent_artifacts"
	multidomainBindingRequirementsMode           = "independent_source_authorities"
	multidomainBindingRequirementsIDPrefix       = "retrieval-binding-requirements:"
	maxMultidomainBindingRequirementsBytes       = int64(1024 * 1024)
	maxMultidomainBindingCases                   = 256
	maxMultidomainBindingGaps                    = 1024

	// Operator-accepted freeze is revision v2; v1 is burned by result observation.
	p1MultidomainFreezeID             = "retrieval-evaluation-freeze:sha256:ddb38ed65dce0a56e6308689b82c085bd1276e3e1f6d48dea68dc792d5d0959d"
	p1MultidomainFreezeDocumentSHA256 = "sha256:6bdf06f366ad3e7adc206f2d1c420775df222ed2c032ba8f0ab3714f6d8efd28"
	p1RetiredMultidomainFreezeID      = "retrieval-evaluation-freeze:sha256:a0fd2cb1067e0b92122e3478632831e8822b5b34f63fa841d3bf60aa65d2de1b"
)

var multidomainRequiredExactBindings = []string{
	"admission_policy_document_sha256",
	"admission_policy_id",
	"dense_artifact_document_sha256",
	"dense_artifact_id",
	"evidence_manifest_document_sha256",
	"evidence_manifest_id",
	"fusion_profile_document_sha256",
	"fusion_profile_id",
	"hybrid_baseline_candidate_document_sha256",
	"hybrid_baseline_candidate_id",
	"hybrid_challenger_candidate_document_sha256",
	"hybrid_challenger_candidate_id",
	"lexical_candidate_document_sha256",
	"lexical_candidate_id",
	"lexical_index_document_sha256",
	"lexical_index_id",
	"query_signal_artifacts",
	"scorer_artifact_sha256",
	"snapshot_manifest_document_sha256",
	"snapshot_manifest_id",
}

type MultidomainBindingAuthorityRules struct {
	SingularSourceCollapseForbidden      bool   `json:"singular_source_collapse_forbidden"`
	AliasedAdmissionPoliciesForbidden    bool   `json:"aliased_admission_policies_forbidden"`
	MixedLineageForbidden                bool   `json:"mixed_lineage_forbidden"`
	BackdatedAdmissionForbidden          bool   `json:"backdated_admission_forbidden"`
	ExpiredAdmissionForbidden            bool   `json:"expired_admission_forbidden"`
	WorkflowsLaneAuthorityReuseForbidden bool   `json:"workflows_lane_authority_reuse_forbidden"`
	UnacceptedScorerAuthorityForbidden   bool   `json:"unaccepted_scorer_authority_forbidden"`
	AdmissionValidityRelation            string `json:"admission_validity_relation"`
}

type MultidomainBindingCapabilities struct {
	ArtifactBytesVerified  bool `json:"artifact_bytes_verified"`
	RetrievalAuthorized    bool `json:"retrieval_authorized"`
	EvaluationAuthorized   bool `json:"evaluation_authorized"`
	SigningAuthorized      bool `json:"signing_authorized"`
	GenerationAuthorized   bool `json:"generation_authorized"`
	PointerWriteAuthorized bool `json:"pointer_write_authorized"`
}

type MultidomainSourceAuthorityRequirement struct {
	AuthorityID                        string   `json:"authority_id"`
	ComponentID                        string   `json:"component_id"`
	ComponentVersion                   string   `json:"component_version"`
	RepositoryURI                      string   `json:"repository_uri"`
	SourceCommitSHA                    string   `json:"source_commit_sha"`
	LicenseExpression                  string   `json:"license_expression"`
	SourceKeys                         []string `json:"source_keys"`
	AdmissionPolicyScopeID             string   `json:"admission_policy_scope_id"`
	PolicyEvaluatedAtNotBefore         string   `json:"policy_evaluated_at_not_before"`
	PolicyMustRemainFreshStrictlyAfter string   `json:"policy_must_remain_fresh_strictly_after"`
}

type MultidomainBindingRequirementsCore struct {
	SchemaVersion                    string                                  `json:"schema_version"`
	ManifestKind                     string                                  `json:"manifest_kind"`
	State                            string                                  `json:"state"`
	ExecutionState                   string                                  `json:"execution_state"`
	Ready                            bool                                    `json:"ready"`
	Name                             string                                  `json:"name"`
	Revision                         string                                  `json:"revision"`
	RequirementsFrozenAt             string                                  `json:"requirements_frozen_at"`
	FreezeID                         string                                  `json:"freeze_id"`
	FreezeDocumentSHA256             string                                  `json:"freeze_document_sha256"`
	AuthorityMode                    string                                  `json:"authority_mode"`
	RequiredExactBindings            []string                                `json:"required_exact_bindings"`
	SourceAuthorities                []MultidomainSourceAuthorityRequirement `json:"source_authorities"`
	RequiredSharedLineageAuthorities []string                                `json:"required_shared_lineage_authorities"`
	AuthorityRules                   MultidomainBindingAuthorityRules        `json:"authority_rules"`
	Capabilities                     MultidomainBindingCapabilities          `json:"capabilities"`
}

type MultidomainAbsentArtifactGap struct {
	Code                      string   `json:"code"`
	Blocking                  bool     `json:"blocking"`
	Scope                     string   `json:"scope"`
	AuthorityIDs              []string `json:"authority_ids"`
	CaseID                    string   `json:"case_id"`
	ProfileRole               string   `json:"profile_role"`
	ArtifactKind              string   `json:"artifact_kind"`
	RequiredIDPrefix          string   `json:"required_id_prefix"`
	RequiredFields            []string `json:"required_fields"`
	DistinctAcrossAuthorities bool     `json:"distinct_across_authorities"`
	ExpectedQuerySHA256       string   `json:"expected_query_sha256"`
}

// MultidomainBindingRequirementsManifest is a requirements-only artifact. It
// deliberately carries no artifact binding or executable surface. A separate
// reviewed byte verifier must create any successor that consumes these gaps.
type MultidomainBindingRequirementsManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	MultidomainBindingRequirementsCore
	VerifiedArtifactCount int                            `json:"verified_artifact_count"`
	ExecutionAuthorized   bool                           `json:"execution_authorized"`
	GapCount              int                            `json:"gap_count"`
	Gaps                  []MultidomainAbsentArtifactGap `json:"gaps"`
}

func MaterializeMultidomainBindingRequirements(corePath, freezePath, freezeHash, sourceRoot, storeRoot string) (MultidomainBindingRequirementsManifest, string, error) {
	var zero MultidomainBindingRequirementsManifest
	for _, value := range []string{corePath, freezePath, sourceRoot, storeRoot} {
		if strings.TrimSpace(value) == "" {
			return zero, "", errors.New("binding requirements core, freeze, source root and store are required")
		}
	}
	if !validSHA256(freezeHash) {
		return zero, "", errors.New("binding requirements freeze caller pin is invalid")
	}
	coreBytes, err := readStableFile(corePath, "multidomain binding requirements core", maxMultidomainBindingRequirementsBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read multidomain binding requirements core: %w", err)
	}
	var core MultidomainBindingRequirementsCore
	if err := decodeStrictCanonical(coreBytes, &core); err != nil {
		return zero, "", fmt.Errorf("decode multidomain binding requirements core: %w", err)
	}
	freezeBytes, err := readStableFile(freezePath, "scorer-blind multidomain freeze", maxScorerBlindFreezeBytes)
	if err != nil || digestBytes(freezeBytes) != freezeHash {
		return zero, "", errors.New("scorer-blind multidomain freeze bytes do not match the caller pin")
	}
	var freeze ScorerBlindEvaluationFreeze
	if err := decodeStrictCanonical(freezeBytes, &freeze); err != nil {
		return zero, "", fmt.Errorf("decode scorer-blind multidomain freeze: %w", err)
	}
	coreAbsolute, coreErr := filepath.Abs(corePath)
	freezeAbsolute, freezeErr := filepath.Abs(freezePath)
	sourceAbsolute, sourceErr := filepath.Abs(sourceRoot)
	storeAbsolute, storeErr := filepath.Abs(storeRoot)
	if coreErr != nil || freezeErr != nil || sourceErr != nil || storeErr != nil ||
		validateNoSymlinkPath(sourceAbsolute) != nil || validateNoSymlinkExistingPrefix(storeAbsolute) != nil {
		return zero, "", errors.New("binding requirements input or output root is unavailable")
	}
	if pathsOverlap(sourceAbsolute, storeAbsolute) || pathsOverlap(coreAbsolute, storeAbsolute) || pathsOverlap(freezeAbsolute, storeAbsolute) {
		return zero, "", errors.New("binding requirements inputs and output store must not overlap")
	}
	manifest, err := sealMultidomainBindingRequirements(core, freeze, freezeHash, sourceAbsolute)
	if err != nil {
		return zero, "", err
	}
	document, err := marshalDocument(manifest)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("binding-requirements", manifest.ManifestPayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	if err := revalidateMultidomainBindingInputs(corePath, coreBytes, freezePath, freezeBytes, freezeHash, freeze, sourceAbsolute); err != nil {
		return zero, "", fmt.Errorf("binding requirements inputs changed before commit: %w", err)
	}
	if err := writeImmutableObject(storeAbsolute, relative, document); err != nil {
		return zero, "", fmt.Errorf("commit multidomain binding requirements: %w", err)
	}
	if err := revalidateMultidomainBindingInputs(corePath, coreBytes, freezePath, freezeBytes, freezeHash, freeze, sourceAbsolute); err != nil {
		return zero, "", fmt.Errorf("binding requirements inputs changed during commit: %w", err)
	}
	manifestPath := filepath.Join(storeAbsolute, filepath.FromSlash(relative))
	if _, err := verifyFileDigest(manifestPath, digestBytes(document), int64(len(document))); err != nil {
		return zero, "", fmt.Errorf("binding requirements output verification failed: %w", err)
	}
	return manifest, manifestPath, nil
}

func revalidateMultidomainBindingInputs(corePath string, coreBytes []byte, freezePath string, freezeBytes []byte, freezeHash string, freeze ScorerBlindEvaluationFreeze, sourceRoot string) error {
	currentCore, err := readStableFile(corePath, "multidomain binding requirements core", maxMultidomainBindingRequirementsBytes)
	if err != nil || !bytes.Equal(currentCore, coreBytes) {
		return errors.New("binding requirements core identity changed")
	}
	currentFreeze, err := readStableFile(freezePath, "scorer-blind multidomain freeze", maxScorerBlindFreezeBytes)
	if err != nil || !bytes.Equal(currentFreeze, freezeBytes) || digestBytes(currentFreeze) != freezeHash {
		return errors.New("scorer-blind multidomain freeze identity changed")
	}
	if _, err := validateScorerBlindEvaluationFreezeCore(freeze.ScorerBlindEvaluationFreezeCore, sourceRoot); err != nil {
		return fmt.Errorf("scorer-blind source identity changed: %w", err)
	}
	return nil
}

func sealMultidomainBindingRequirements(core MultidomainBindingRequirementsCore, freeze ScorerBlindEvaluationFreeze, freezeDocumentSHA256, sourceRoot string) (MultidomainBindingRequirementsManifest, error) {
	if err := validateMultidomainBindingRequirementsCore(core, freeze, freezeDocumentSHA256, sourceRoot); err != nil {
		return MultidomainBindingRequirementsManifest{}, fmt.Errorf("multidomain binding requirements core is invalid: %w", err)
	}
	payload, err := json.Marshal(core)
	if err != nil {
		return MultidomainBindingRequirementsManifest{}, err
	}
	digest := digestBytes(payload)
	gaps := deriveMultidomainAbsentArtifactGaps(core, freeze)
	if len(gaps) > maxMultidomainBindingGaps {
		return MultidomainBindingRequirementsManifest{}, errors.New("binding requirements gap denominator exceeds its hard bound")
	}
	return MultidomainBindingRequirementsManifest{
		ManifestID:                         multidomainBindingRequirementsIDPrefix + digest,
		ManifestPayloadSHA256:              digest,
		MultidomainBindingRequirementsCore: core,
		VerifiedArtifactCount:              0,
		ExecutionAuthorized:                false,
		GapCount:                           len(gaps),
		Gaps:                               gaps,
	}, nil
}

func validateMultidomainBindingRequirementsCore(core MultidomainBindingRequirementsCore, freeze ScorerBlindEvaluationFreeze, freezeDocumentSHA256, sourceRoot string) error {
	if core.SchemaVersion != multidomainBindingRequirementsVersion || core.ManifestKind != multidomainBindingRequirementsKind || core.State != multidomainBindingRequirementsState || core.ExecutionState != multidomainBindingRequirementsExecutionState || core.Ready {
		return errors.New("binding requirements envelope is unsupported or prematurely ready")
	}
	if !boundedMetadata(core.Name) || !boundedMetadata(core.Revision) || core.AuthorityMode != multidomainBindingRequirementsMode {
		return errors.New("binding requirements metadata or authority mode is invalid")
	}
	requirementsFrozenAt, err := parseCanonicalUTC(core.RequirementsFrozenAt)
	if err != nil {
		return fmt.Errorf("requirements_frozen_at: %w", err)
	}
	freezeFrozenAt, err := parseCanonicalUTC(freeze.FrozenAt)
	if err != nil || !requirementsFrozenAt.After(freezeFrozenAt) {
		return errors.New("binding requirements timestamp backdates the immutable freeze")
	}
	if core.FreezeID != p1MultidomainFreezeID || freeze.FreezeID != p1MultidomainFreezeID || core.FreezeDocumentSHA256 != p1MultidomainFreezeDocumentSHA256 || freezeDocumentSHA256 != p1MultidomainFreezeDocumentSHA256 {
		return errors.New("binding requirements do not target the exact accepted multidomain freeze")
	}
	freezeCoreBytes, err := json.Marshal(freeze.ScorerBlindEvaluationFreezeCore)
	if err != nil || freeze.FreezePayloadSHA256 != digestBytes(freezeCoreBytes) || freeze.FreezeID != "retrieval-evaluation-freeze:"+freeze.FreezePayloadSHA256 {
		return errors.New("scorer-blind multidomain freeze identity is invalid")
	}
	if _, err := validateScorerBlindEvaluationFreezeCore(freeze.ScorerBlindEvaluationFreezeCore, sourceRoot); err != nil {
		return fmt.Errorf("scorer-blind multidomain freeze replay failed: %w", err)
	}
	if len(freeze.Cases) < 1 || len(freeze.Cases) > maxMultidomainBindingCases {
		return errors.New("binding requirements case denominator exceeds its hard bound")
	}
	if !equalStringSlices(core.RequiredExactBindings, multidomainRequiredExactBindings) {
		return errors.New("binding requirements exact ID/hash barrier is partial or changed")
	}
	rules := core.AuthorityRules
	if !rules.SingularSourceCollapseForbidden || !rules.AliasedAdmissionPoliciesForbidden || !rules.MixedLineageForbidden || !rules.BackdatedAdmissionForbidden || !rules.ExpiredAdmissionForbidden || !rules.WorkflowsLaneAuthorityReuseForbidden || !rules.UnacceptedScorerAuthorityForbidden || rules.AdmissionValidityRelation != "requirements_frozen_at<=policy_evaluated_at<=evaluation_time<policy_fresh_until" {
		return errors.New("binding requirements authority rules are incomplete")
	}
	capabilities := core.Capabilities
	if capabilities.ArtifactBytesVerified || capabilities.RetrievalAuthorized || capabilities.EvaluationAuthorized || capabilities.SigningAuthorized || capabilities.GenerationAuthorized || capabilities.PointerWriteAuthorized {
		return errors.New("binding requirements cannot grant runtime or release authority")
	}
	expectedAuthorities, err := deriveMultidomainSourceAuthorities(freeze, core.RequirementsFrozenAt)
	if err != nil {
		return err
	}
	if len(core.SourceAuthorities) != 3 || len(expectedAuthorities) != 3 {
		return errors.New("binding requirements collapsed the three source authorities")
	}
	policyScopes := make(map[string]struct{}, len(core.SourceAuthorities))
	authorityIDs := make([]string, 0, len(core.SourceAuthorities))
	for index, authority := range core.SourceAuthorities {
		if !equalMultidomainSourceAuthority(authority, expectedAuthorities[index]) {
			return fmt.Errorf("source authority %d mixes or changes frozen lineage", index)
		}
		if _, exists := policyScopes[authority.AdmissionPolicyScopeID]; exists {
			return errors.New("source authorities alias one admission-policy scope")
		}
		policyScopes[authority.AdmissionPolicyScopeID] = struct{}{}
		authorityIDs = append(authorityIDs, authority.AuthorityID)
	}
	if !equalStringSlices(core.RequiredSharedLineageAuthorities, authorityIDs) {
		return errors.New("shared artifact lineage omits or aliases a source authority")
	}
	return nil
}

func equalMultidomainSourceAuthority(left, right MultidomainSourceAuthorityRequirement) bool {
	return left.AuthorityID == right.AuthorityID &&
		left.ComponentID == right.ComponentID &&
		left.ComponentVersion == right.ComponentVersion &&
		left.RepositoryURI == right.RepositoryURI &&
		left.SourceCommitSHA == right.SourceCommitSHA &&
		left.LicenseExpression == right.LicenseExpression &&
		equalStringSlices(left.SourceKeys, right.SourceKeys) &&
		left.AdmissionPolicyScopeID == right.AdmissionPolicyScopeID &&
		left.PolicyEvaluatedAtNotBefore == right.PolicyEvaluatedAtNotBefore &&
		left.PolicyMustRemainFreshStrictlyAfter == right.PolicyMustRemainFreshStrictlyAfter
}

func deriveMultidomainSourceAuthorities(freeze ScorerBlindEvaluationFreeze, requirementsFrozenAt string) ([]MultidomainSourceAuthorityRequirement, error) {
	type accumulator struct {
		componentVersion  string
		repositoryURI     string
		sourceCommitSHA   string
		licenseExpression string
		sourceKeys        []string
	}
	byComponent := make(map[string]accumulator)
	for _, source := range freeze.Sources {
		current, exists := byComponent[source.ComponentID]
		if exists && (current.componentVersion != source.ComponentVersion || current.repositoryURI != source.RepositoryURI || current.sourceCommitSHA != source.SourceCommitSHA || current.licenseExpression != source.LicenseExpression) {
			return nil, fmt.Errorf("freeze component %s has mixed source authority", source.ComponentID)
		}
		current.componentVersion = source.ComponentVersion
		current.repositoryURI = source.RepositoryURI
		current.sourceCommitSHA = source.SourceCommitSHA
		current.licenseExpression = source.LicenseExpression
		current.sourceKeys = append(current.sourceKeys, source.SourceKey)
		byComponent[source.ComponentID] = current
	}
	componentIDs := make([]string, 0, len(byComponent))
	for componentID := range byComponent {
		componentIDs = append(componentIDs, componentID)
	}
	sort.Strings(componentIDs)
	result := make([]MultidomainSourceAuthorityRequirement, 0, len(componentIDs))
	for _, componentID := range componentIDs {
		current := byComponent[componentID]
		sort.Strings(current.sourceKeys)
		authorityID := "retrieval-source-authority:" + componentID + ":" + current.componentVersion
		result = append(result, MultidomainSourceAuthorityRequirement{
			AuthorityID: authorityID, ComponentID: componentID, ComponentVersion: current.componentVersion,
			RepositoryURI: current.repositoryURI, SourceCommitSHA: current.sourceCommitSHA,
			LicenseExpression: current.licenseExpression, SourceKeys: current.sourceKeys,
			AdmissionPolicyScopeID:             "retrieval-admission-scope:" + componentID + ":" + current.componentVersion,
			PolicyEvaluatedAtNotBefore:         requirementsFrozenAt,
			PolicyMustRemainFreshStrictlyAfter: requirementsFrozenAt,
		})
	}
	return result, nil
}

func deriveMultidomainAbsentArtifactGaps(core MultidomainBindingRequirementsCore, freeze ScorerBlindEvaluationFreeze) []MultidomainAbsentArtifactGap {
	allAuthorities := append([]string(nil), core.RequiredSharedLineageAuthorities...)
	gaps := make([]MultidomainAbsentArtifactGap, 0, len(core.SourceAuthorities)*3+7+len(freeze.Cases)*2)
	add := func(scope string, authorities []string, caseID, role, kind, prefix string, fields []string, distinct bool, querySHA string) {
		gaps = append(gaps, MultidomainAbsentArtifactGap{
			Code: "required_artifact_absent", Blocking: true, Scope: scope,
			AuthorityIDs: append([]string(nil), authorities...), CaseID: caseID, ProfileRole: role,
			ArtifactKind: kind, RequiredIDPrefix: prefix, RequiredFields: append([]string(nil), fields...),
			DistinctAcrossAuthorities: distinct, ExpectedQuerySHA256: querySHA,
		})
	}
	for _, authority := range core.SourceAuthorities {
		ids := []string{authority.AuthorityID}
		add("source_authority", ids, "", "", "admission_policy", "retrieval-admission:", []string{"admission_policy_document_sha256", "admission_policy_id"}, true, "")
		add("source_authority", ids, "", "", "evidence_manifest", "evidence-manifest:", []string{"evidence_manifest_document_sha256", "evidence_manifest_id"}, true, "")
		add("source_authority", ids, "", "", "snapshot_manifest", "snapshot-manifest:", []string{"snapshot_manifest_document_sha256", "snapshot_manifest_id"}, true, "")
	}
	add("shared_corpus", allAuthorities, "", "", "dense_artifact", "dense-vector-artifact:", []string{"dense_artifact_document_sha256", "dense_artifact_id"}, false, "")
	add("shared_corpus", allAuthorities, "", "", "hybrid_baseline_candidate", "hybrid-retrieval-candidate:", []string{"hybrid_baseline_candidate_document_sha256", "hybrid_baseline_candidate_id"}, false, "")
	add("shared_corpus", allAuthorities, "", "", "hybrid_challenger_candidate", "hybrid-retrieval-candidate:", []string{"hybrid_challenger_candidate_document_sha256", "hybrid_challenger_candidate_id"}, false, "")
	add("shared_corpus", allAuthorities, "", "", "lexical_candidate", "retrieval-candidate:", []string{"lexical_candidate_document_sha256", "lexical_candidate_id"}, false, "")
	add("shared_corpus", allAuthorities, "", "", "lexical_index", "lexical-index:", []string{"lexical_index_document_sha256", "lexical_index_id"}, false, "")
	add("comparison", allAuthorities, "", "challenger", "fusion_profile", "fusion-profile:", []string{"fusion_profile_document_sha256", "fusion_profile_id"}, false, "")
	add("comparison", allAuthorities, "", "challenger", "scorer_artifact", "", []string{"scorer_artifact_sha256"}, false, "")
	authorityByComponent := make(map[string]string, len(core.SourceAuthorities))
	for _, authority := range core.SourceAuthorities {
		authorityByComponent[authority.ComponentID] = authority.AuthorityID
	}
	for _, evaluationCase := range freeze.Cases {
		ids := []string{authorityByComponent[evaluationCase.Class]}
		add("evaluation_case", ids, evaluationCase.CaseID, "baseline", "query_signal_artifact", "query-signal-artifact:", []string{"query_signal_artifacts"}, false, evaluationCase.QuerySHA256)
		add("evaluation_case", ids, evaluationCase.CaseID, "challenger", "query_signal_artifact", "query-signal-artifact:", []string{"query_signal_artifacts"}, false, evaluationCase.QuerySHA256)
	}
	sort.Slice(gaps, func(i, j int) bool {
		left := gaps[i].Scope + "\x00" + strings.Join(gaps[i].AuthorityIDs, "\x00") + "\x00" + gaps[i].CaseID + "\x00" + gaps[i].ProfileRole + "\x00" + gaps[i].ArtifactKind
		right := gaps[j].Scope + "\x00" + strings.Join(gaps[j].AuthorityIDs, "\x00") + "\x00" + gaps[j].CaseID + "\x00" + gaps[j].ProfileRole + "\x00" + gaps[j].ArtifactKind
		return left < right
	})
	return gaps
}
