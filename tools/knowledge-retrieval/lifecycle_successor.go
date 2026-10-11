package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const (
	admissionSuccessorKind        = "retrieval_admission_successor"
	admissionSuccessorIDPrefix    = "retrieval-admission-successor:"
	admissionPolicyIDPrefix       = "retrieval-admission:"
	admissionPolicyReviewKind     = "retrieval_admission_review"
	admissionPolicyReviewIDPrefix = "retrieval-admission-review:"

	admissionReviewAccepted = "accepted"
	admissionReviewRejected = "rejected"

	successorDispositionRevoked   = "revoked"
	successorDispositionCorrected = "corrected"

	// This resolver is deliberately pure. Requiring and returning this marker
	// prevents a caller-supplied object set from being mistaken for a complete
	// projection loaded from the persisted current-generation store.
	admissionScopeCallerSupplied = "caller_supplied_unpersisted_projection@1.0.0"

	maxAdmissionSuccessorRecords = 4_096
	maxAdmissionPolicyReviews    = 4_096
	maxAdmissionScopeDerivatives = 65_536
)

const (
	derivativeKindGeneration        = "generation"
	derivativeKindLexicalIndex      = "lexical_index"
	derivativeKindPairedSuite       = "paired_fusion_suite"
	derivativeKindCurrentProjection = "current_projection"
)

const (
	derivativeVerdictUnaffected   = "unaffected"
	derivativeVerdictReproducible = "historically_reproducible"
	derivativeVerdictRevoked      = "quarantined_revoked"
	derivativeVerdictSuperseded   = "quarantined_superseded"
)

// AdmissionPolicyReview is the separately reviewed state a correction must
// bind. Embedding the complete policy makes an accepted review verifiable
// against the actual content-addressed policy object, not merely ID-shaped
// strings supplied by the correction record.
type AdmissionPolicyReviewCore struct {
	SchemaVersion                 string          `json:"schema_version"`
	RecordKind                    string          `json:"record_kind"`
	Decision                      string          `json:"decision"`
	AdmissionPolicy               AdmissionPolicy `json:"admission_policy"`
	AdmissionPolicyDocumentSHA256 string          `json:"admission_policy_document_sha256"`
	ReviewedAt                    string          `json:"reviewed_at"`
	Reviewer                      string          `json:"reviewer"`
	ReviewerKeyID                 string          `json:"reviewer_key_id"`
	EvidenceObjectPath            string          `json:"evidence_object_path"`
	EvidenceSHA256                string          `json:"evidence_document_sha256"`
	EvidenceByteSize              int64           `json:"evidence_byte_size"`
}

type AdmissionPolicyReview struct {
	ReviewID            string `json:"review_id"`
	ReviewPayloadSHA256 string `json:"review_payload_sha256"`
	AdmissionPolicyReviewCore
}

func SealAdmissionPolicyReview(core AdmissionPolicyReviewCore) (AdmissionPolicyReview, error) {
	if err := validateAdmissionPolicyReviewCore(core); err != nil {
		return AdmissionPolicyReview{}, err
	}
	data, err := json.Marshal(core)
	if err != nil {
		return AdmissionPolicyReview{}, err
	}
	digest := digestBytes(data)
	review := AdmissionPolicyReview{
		ReviewID:                  admissionPolicyReviewIDPrefix + digest,
		ReviewPayloadSHA256:       digest,
		AdmissionPolicyReviewCore: core,
	}
	if err := validateAdmissionPolicyReview(review); err != nil {
		return AdmissionPolicyReview{}, err
	}
	return review, nil
}

func validateAdmissionPolicyReview(review AdmissionPolicyReview) error {
	data, err := json.Marshal(review.AdmissionPolicyReviewCore)
	if err != nil || review.ReviewPayloadSHA256 != digestBytes(data) || review.ReviewID != admissionPolicyReviewIDPrefix+review.ReviewPayloadSHA256 {
		return errors.New("admission policy review identity mismatch")
	}
	return validateAdmissionPolicyReviewCore(review.AdmissionPolicyReviewCore)
}

func validateAdmissionPolicyReviewCore(core AdmissionPolicyReviewCore) error {
	if core.SchemaVersion != retrievalSchemaVersion || core.RecordKind != admissionPolicyReviewKind {
		return errors.New("admission policy review envelope unsupported")
	}
	if core.Decision != admissionReviewAccepted && core.Decision != admissionReviewRejected {
		return errors.New("admission policy review decision invalid")
	}
	if err := validatePolicyIdentity(core.AdmissionPolicy); err != nil {
		return fmt.Errorf("admission policy review policy invalid: %w", err)
	}
	policyDocumentSHA256, _, err := documentSHA256(core.AdmissionPolicy)
	if err != nil || policyDocumentSHA256 != core.AdmissionPolicyDocumentSHA256 {
		return errors.New("admission policy review document binding invalid")
	}
	if core.Decision == admissionReviewAccepted {
		if err := validateMaterializedAdmissionPolicy(core.AdmissionPolicy); err != nil {
			return fmt.Errorf("accepted admission policy review is not active: %w", err)
		}
	}
	reviewedAt, err := parseCanonicalUTC(core.ReviewedAt)
	if err != nil {
		return fmt.Errorf("admission policy review reviewed_at: %w", err)
	}
	evaluatedAt, _ := parseCanonicalUTC(core.AdmissionPolicy.EvaluatedAt)
	freshUntil, _ := parseCanonicalUTC(core.AdmissionPolicy.FreshUntil)
	if reviewedAt.Before(evaluatedAt) || reviewedAt.After(freshUntil) {
		return errors.New("admission policy review falls outside policy evaluation validity")
	}
	if !boundedMetadata(core.Reviewer) || !sshFingerprintPattern.MatchString(core.ReviewerKeyID) {
		return errors.New("admission policy review authority invalid")
	}
	if validateRelativePath(core.EvidenceObjectPath) != nil || !validSHA256(core.EvidenceSHA256) || core.EvidenceByteSize < 1 || core.EvidenceByteSize > maxPolicyBytes {
		return errors.New("admission policy review evidence binding invalid")
	}
	return nil
}

// AdmissionSuccessorRecordCore is a distinct lifecycle decision over one
// unchanged prior admission. EffectiveAt is valid time. KnownAt is transaction
// time: a record cannot affect a view whose known-at cutoff precedes it.
type AdmissionSuccessorRecordCore struct {
	SchemaVersion                  string  `json:"schema_version"`
	RecordKind                     string  `json:"record_kind"`
	Disposition                    string  `json:"disposition"`
	PriorAdmissionPolicyID         string  `json:"prior_admission_policy_id"`
	PriorAdmissionPolicySHA256     string  `json:"prior_admission_policy_document_sha256"`
	SuccessorAdmissionPolicyID     *string `json:"successor_admission_policy_id"`
	SuccessorAdmissionPolicySHA256 *string `json:"successor_admission_policy_document_sha256"`
	SuccessorAdmissionReviewID     *string `json:"successor_admission_review_id"`
	SuccessorAdmissionReviewSHA256 *string `json:"successor_admission_review_document_sha256"`
	Reason                         string  `json:"reason"`
	EffectiveAt                    string  `json:"effective_at"`
	KnownAt                        string  `json:"known_at"`
	Reviewer                       string  `json:"reviewer"`
	ReviewerKeyID                  string  `json:"reviewer_key_id"`
	EvidenceObjectPath             string  `json:"evidence_object_path"`
	EvidenceSHA256                 string  `json:"evidence_document_sha256"`
	EvidenceByteSize               int64   `json:"evidence_byte_size"`
}

type AdmissionSuccessorRecord struct {
	RecordID            string `json:"record_id"`
	RecordPayloadSHA256 string `json:"record_payload_sha256"`
	AdmissionSuccessorRecordCore
}

func SealAdmissionSuccessorRecord(core AdmissionSuccessorRecordCore) (AdmissionSuccessorRecord, error) {
	if err := validateAdmissionSuccessorCore(core); err != nil {
		return AdmissionSuccessorRecord{}, err
	}
	data, err := json.Marshal(core)
	if err != nil {
		return AdmissionSuccessorRecord{}, err
	}
	digest := digestBytes(data)
	record := AdmissionSuccessorRecord{
		RecordID:                     admissionSuccessorIDPrefix + digest,
		RecordPayloadSHA256:          digest,
		AdmissionSuccessorRecordCore: core,
	}
	if err := validateAdmissionSuccessorRecord(record); err != nil {
		return AdmissionSuccessorRecord{}, err
	}
	return record, nil
}

func validateAdmissionSuccessorRecord(record AdmissionSuccessorRecord) error {
	data, err := json.Marshal(record.AdmissionSuccessorRecordCore)
	if err != nil || record.RecordPayloadSHA256 != digestBytes(data) || record.RecordID != admissionSuccessorIDPrefix+record.RecordPayloadSHA256 {
		return errors.New("admission successor identity mismatch")
	}
	return validateAdmissionSuccessorCore(record.AdmissionSuccessorRecordCore)
}

func validateAdmissionSuccessorCore(core AdmissionSuccessorRecordCore) error {
	if core.SchemaVersion != retrievalSchemaVersion || core.RecordKind != admissionSuccessorKind {
		return errors.New("admission successor envelope unsupported")
	}
	if !validPrefixedDigest(core.PriorAdmissionPolicyID, admissionPolicyIDPrefix) || !validSHA256(core.PriorAdmissionPolicySHA256) {
		return errors.New("admission successor prior binding invalid")
	}
	switch core.Disposition {
	case successorDispositionRevoked:
		if core.SuccessorAdmissionPolicyID != nil || core.SuccessorAdmissionPolicySHA256 != nil || core.SuccessorAdmissionReviewID != nil || core.SuccessorAdmissionReviewSHA256 != nil {
			return errors.New("revocation must not name a successor or review")
		}
	case successorDispositionCorrected:
		if core.SuccessorAdmissionPolicyID == nil || core.SuccessorAdmissionPolicySHA256 == nil || core.SuccessorAdmissionReviewID == nil || core.SuccessorAdmissionReviewSHA256 == nil {
			return errors.New("correction must bind a successor and its separate review")
		}
		if !validPrefixedDigest(*core.SuccessorAdmissionPolicyID, admissionPolicyIDPrefix) || !validSHA256(*core.SuccessorAdmissionPolicySHA256) || !validPrefixedDigest(*core.SuccessorAdmissionReviewID, admissionPolicyReviewIDPrefix) || !validSHA256(*core.SuccessorAdmissionReviewSHA256) {
			return errors.New("admission successor successor binding invalid")
		}
		if *core.SuccessorAdmissionPolicyID == core.PriorAdmissionPolicyID || *core.SuccessorAdmissionPolicySHA256 == core.PriorAdmissionPolicySHA256 {
			return errors.New("correction successor must differ from the prior admission")
		}
	default:
		return errors.New("admission successor disposition invalid")
	}
	if !boundedMetadata(core.Reason) || !boundedMetadata(core.Reviewer) {
		return errors.New("admission successor reason or reviewer invalid")
	}
	if !sshFingerprintPattern.MatchString(core.ReviewerKeyID) {
		return errors.New("admission successor reviewer key invalid")
	}
	if _, err := parseCanonicalUTC(core.EffectiveAt); err != nil {
		return fmt.Errorf("admission successor effective_at: %w", err)
	}
	if _, err := parseCanonicalUTC(core.KnownAt); err != nil {
		return fmt.Errorf("admission successor known_at: %w", err)
	}
	if validateRelativePath(core.EvidenceObjectPath) != nil || !validSHA256(core.EvidenceSHA256) || core.EvidenceByteSize < 1 || core.EvidenceByteSize > maxPolicyBytes {
		return errors.New("admission successor evidence binding invalid")
	}
	return nil
}

type DerivativeBinding struct {
	Kind                       string `json:"kind"`
	DerivativeID               string `json:"derivative_id"`
	PriorAdmissionPolicyID     string `json:"admission_policy_id"`
	PriorAdmissionPolicySHA256 string `json:"admission_policy_document_sha256"`
}

// AdmissionLexicalIndexInput supplies the exact candidate that binds both the
// lexical-index document and the admission-policy document. The index's v1/v2
// wire schema carries only the admission ID, so the index alone is not a safe
// lifecycle binding.
type AdmissionLexicalIndexInput struct {
	Candidate CandidateManifest `json:"candidate"`
	Index     LexicalIndex      `json:"index"`
}

type AdmissionSuccessorScope struct {
	Boundary    string                       `json:"boundary"`
	Generations []RetrievalGeneration        `json:"generations"`
	Indexes     []AdmissionLexicalIndexInput `json:"indexes"`
	Suites      []PairedFusionSuite          `json:"suites"`
	Projections []AdmissionProjectionInput   `json:"projections"`
}

type AdmissionProjectionInput struct {
	Pointer           RetrievalGenerationPointer `json:"pointer"`
	CurrentGeneration RetrievalGeneration        `json:"current_generation"`
}

func generationDerivativeBinding(generation RetrievalGeneration) (DerivativeBinding, error) {
	core, err := json.Marshal(generation.RetrievalGenerationCore)
	if err != nil || generation.GenerationPayloadSHA256 != digestBytes(core) || generation.GenerationID != "retrieval-generation:"+generation.GenerationPayloadSHA256 {
		return DerivativeBinding{}, errors.New("generation scope identity mismatch")
	}
	return DerivativeBinding{
		Kind: derivativeKindGeneration, DerivativeID: generation.GenerationID,
		PriorAdmissionPolicyID: generation.AdmissionPolicyID, PriorAdmissionPolicySHA256: generation.AdmissionPolicySHA256,
	}, nil
}

func lexicalIndexDerivativeBinding(input AdmissionLexicalIndexInput) (DerivativeBinding, error) {
	if err := validateCandidate(input.Candidate); err != nil {
		return DerivativeBinding{}, fmt.Errorf("lexical scope candidate invalid: %w", err)
	}
	if err := validateIndex(input.Index, input.Candidate); err != nil {
		return DerivativeBinding{}, fmt.Errorf("lexical scope index invalid: %w", err)
	}
	indexDocumentSHA256, _, err := documentSHA256(input.Index)
	if err != nil || indexDocumentSHA256 != input.Candidate.LexicalIndexSHA256 {
		return DerivativeBinding{}, errors.New("lexical scope index document binding mismatch")
	}
	if !validSHA256(input.Candidate.AdmissionPolicySHA256) {
		return DerivativeBinding{}, errors.New("lexical scope admission document binding invalid")
	}
	return DerivativeBinding{
		Kind: derivativeKindLexicalIndex, DerivativeID: input.Index.IndexID,
		PriorAdmissionPolicyID: input.Candidate.AdmissionPolicyID, PriorAdmissionPolicySHA256: input.Candidate.AdmissionPolicySHA256,
	}, nil
}

func pairedSuiteDerivativeBinding(suite PairedFusionSuite) (DerivativeBinding, error) {
	core, err := json.Marshal(suite.PairedFusionSuiteCore)
	if err != nil || suite.SuitePayloadSHA256 != digestBytes(core) || suite.SuiteID != "paired-fusion-suite:"+suite.SuitePayloadSHA256 {
		return DerivativeBinding{}, errors.New("paired suite scope identity mismatch")
	}
	return DerivativeBinding{
		Kind: derivativeKindPairedSuite, DerivativeID: suite.SuiteID,
		PriorAdmissionPolicyID: suite.AdmissionPolicy.ArtifactID, PriorAdmissionPolicySHA256: suite.AdmissionPolicy.DocumentSHA256,
	}, nil
}

func projectionDerivativeBinding(input AdmissionProjectionInput) (DerivativeBinding, error) {
	pointerCore, pointerErr := json.Marshal(input.Pointer.RetrievalGenerationPointerCore)
	generationBinding, generationErr := generationDerivativeBinding(input.CurrentGeneration)
	if pointerErr != nil || input.Pointer.PointerPayloadSHA256 != digestBytes(pointerCore) || input.Pointer.PointerID != "retrieval-pointer:"+input.Pointer.PointerPayloadSHA256 {
		return DerivativeBinding{}, errors.New("current projection pointer identity mismatch")
	}
	if generationErr != nil {
		return DerivativeBinding{}, generationErr
	}
	if input.Pointer.CurrentGenerationID != input.CurrentGeneration.GenerationID || input.Pointer.CurrentGenerationSHA256 != input.CurrentGeneration.GenerationPayloadSHA256 {
		return DerivativeBinding{}, errors.New("current projection does not bind its supplied generation")
	}
	generationBinding.Kind = derivativeKindCurrentProjection
	generationBinding.DerivativeID = input.Pointer.PointerID
	return generationBinding, nil
}

type DerivativeVerdict struct {
	Kind              string `json:"kind"`
	DerivativeID      string `json:"derivative_id"`
	Verdict           string `json:"verdict"`
	GoverningRecordID string `json:"governing_record_id,omitempty"`
	Disposition       string `json:"disposition,omitempty"`
	EffectiveAt       string `json:"effective_at,omitempty"`
}

type SuccessorResolutionView struct {
	ValidAt string `json:"valid_at"`
	KnownAt string `json:"known_at"`
}

type SuccessorResolution struct {
	SchemaVersion       string              `json:"schema_version"`
	ValidAt             string              `json:"valid_at"`
	KnownAt             string              `json:"known_at"`
	ScopeBoundary       string              `json:"scope_boundary"`
	PersistenceVerified bool                `json:"persistence_verified"`
	RecordIDs           []string            `json:"record_ids"`
	Quarantined         []DerivativeVerdict `json:"quarantined"`
	Reproducible        []DerivativeVerdict `json:"reproducible"`
	Unaffected          []DerivativeVerdict `json:"unaffected"`
}

// ResolveAdmissionSuccessors is bitemporal: ValidAt chooses the valid-time
// world being reconstructed, while KnownAt excludes decisions the system had
// not learned by that transaction-time cutoff. It validates every supplied
// object but only visible records may conflict with or govern that historical
// view.
func ResolveAdmissionSuccessors(records []AdmissionSuccessorRecord, reviews []AdmissionPolicyReview, scope AdmissionSuccessorScope, view SuccessorResolutionView) (SuccessorResolution, error) {
	var zero SuccessorResolution
	validAt, err := parseCanonicalUTC(view.ValidAt)
	if err != nil {
		return zero, errors.New("admission successor valid-at time is not canonical UTC")
	}
	knownAt, err := parseCanonicalUTC(view.KnownAt)
	if err != nil {
		return zero, errors.New("admission successor known-at time is not canonical UTC")
	}
	if scope.Boundary != admissionScopeCallerSupplied {
		return zero, errors.New("admission successor scope is not explicitly caller-supplied and unpersisted")
	}
	if len(records) > maxAdmissionSuccessorRecords || len(reviews) > maxAdmissionPolicyReviews {
		return zero, errors.New("admission successor registry exceeds its bound")
	}

	uniqueRecords := make(map[string]AdmissionSuccessorRecord, len(records))
	visibleRecords := make(map[string]AdmissionSuccessorRecord, len(records))
	for _, record := range records {
		if err := validateAdmissionSuccessorRecord(record); err != nil {
			return zero, fmt.Errorf("admission successor registry invalid: %w", err)
		}
		if existing, seen := uniqueRecords[record.RecordID]; seen {
			if existing.RecordPayloadSHA256 != record.RecordPayloadSHA256 {
				return zero, errors.New("admission successor identity collision")
			}
			continue
		}
		uniqueRecords[record.RecordID] = record
		recordKnownAt, _ := parseCanonicalUTC(record.KnownAt)
		if !recordKnownAt.After(knownAt) {
			visibleRecords[record.RecordID] = record
		}
	}

	uniqueReviews := make(map[string]AdmissionPolicyReview, len(reviews))
	reviewDocumentSHA256 := make(map[string]string, len(reviews))
	for _, review := range reviews {
		if err := validateAdmissionPolicyReview(review); err != nil {
			return zero, fmt.Errorf("admission policy review registry invalid: %w", err)
		}
		if existing, seen := uniqueReviews[review.ReviewID]; seen {
			if existing != review {
				return zero, errors.New("admission policy review identity collision")
			}
			continue
		}
		uniqueReviews[review.ReviewID] = review
		digest, _, err := documentSHA256(review)
		if err != nil {
			return zero, errors.New("admission policy review document is not canonical")
		}
		reviewDocumentSHA256[review.ReviewID] = digest
	}

	governing := make(map[string]AdmissionSuccessorRecord, len(visibleRecords))
	for _, record := range visibleRecords {
		if existing, seen := governing[record.PriorAdmissionPolicyID]; seen && existing.RecordID != record.RecordID {
			return zero, errors.New("conflicting admission successor records for one prior admission")
		}
		governing[record.PriorAdmissionPolicyID] = record
	}
	for _, record := range governing {
		if record.Disposition != successorDispositionCorrected {
			continue
		}
		review, seen := uniqueReviews[*record.SuccessorAdmissionReviewID]
		if !seen || reviewDocumentSHA256[review.ReviewID] != *record.SuccessorAdmissionReviewSHA256 {
			return zero, errors.New("correction successor review is missing or does not match its exact document")
		}
		if review.Decision != admissionReviewAccepted {
			return zero, errors.New("correction successor is not admitted by an accepted review")
		}
		if review.AdmissionPolicy.PolicyID != *record.SuccessorAdmissionPolicyID || review.AdmissionPolicyDocumentSHA256 != *record.SuccessorAdmissionPolicySHA256 {
			return zero, errors.New("correction successor differs from its reviewed admission object")
		}
		reviewedAt, _ := parseCanonicalUTC(review.ReviewedAt)
		recordKnownAt, _ := parseCanonicalUTC(record.KnownAt)
		if reviewedAt.After(recordKnownAt) {
			return zero, errors.New("correction was known before its successor review")
		}
	}
	if err := validateVisibleCorrectionGraph(governing); err != nil {
		return zero, err
	}

	bindings, err := scopeDerivativeBindings(scope)
	if err != nil {
		return zero, err
	}
	resolution := SuccessorResolution{
		SchemaVersion: retrievalSchemaVersion, ValidAt: view.ValidAt, KnownAt: view.KnownAt,
		ScopeBoundary: admissionScopeCallerSupplied, PersistenceVerified: false,
	}
	for _, binding := range bindings {
		if !validPrefixedDigest(binding.PriorAdmissionPolicyID, admissionPolicyIDPrefix) || !validSHA256(binding.PriorAdmissionPolicySHA256) {
			return zero, errors.New("derivative does not bind an exact admission identity")
		}
		record, affected := governing[binding.PriorAdmissionPolicyID]
		if !affected {
			resolution.Unaffected = append(resolution.Unaffected, DerivativeVerdict{Kind: binding.Kind, DerivativeID: binding.DerivativeID, Verdict: derivativeVerdictUnaffected})
			continue
		}
		if binding.PriorAdmissionPolicySHA256 != record.PriorAdmissionPolicySHA256 {
			return zero, errors.New("derivative binds an inconsistent admission identity")
		}
		verdict := DerivativeVerdict{Kind: binding.Kind, DerivativeID: binding.DerivativeID, GoverningRecordID: record.RecordID, Disposition: record.Disposition, EffectiveAt: record.EffectiveAt}
		effectiveAt, _ := parseCanonicalUTC(record.EffectiveAt)
		if validAt.Before(effectiveAt) {
			verdict.Verdict = derivativeVerdictReproducible
			resolution.Reproducible = append(resolution.Reproducible, verdict)
		} else if record.Disposition == successorDispositionRevoked {
			verdict.Verdict = derivativeVerdictRevoked
			resolution.Quarantined = append(resolution.Quarantined, verdict)
		} else {
			verdict.Verdict = derivativeVerdictSuperseded
			resolution.Quarantined = append(resolution.Quarantined, verdict)
		}
	}

	resolution.RecordIDs = make([]string, 0, len(visibleRecords))
	for id := range visibleRecords {
		resolution.RecordIDs = append(resolution.RecordIDs, id)
	}
	sort.Strings(resolution.RecordIDs)
	sortDerivativeVerdicts(resolution.Quarantined)
	sortDerivativeVerdicts(resolution.Reproducible)
	sortDerivativeVerdicts(resolution.Unaffected)
	return resolution, nil
}

func validateVisibleCorrectionGraph(governing map[string]AdmissionSuccessorRecord) error {
	const (
		unseen = iota
		visiting
		done
	)
	state := make(map[string]int, len(governing))
	var visit func(string) error
	visit = func(policyID string) error {
		switch state[policyID] {
		case visiting:
			return errors.New("admission correction graph contains a cycle")
		case done:
			return nil
		}
		record, seen := governing[policyID]
		if !seen || record.Disposition != successorDispositionCorrected {
			state[policyID] = done
			return nil
		}
		state[policyID] = visiting
		target := *record.SuccessorAdmissionPolicyID
		if targetRecord, seen := governing[target]; seen && targetRecord.Disposition == successorDispositionRevoked {
			return errors.New("correction targets an admission that is itself revoked")
		}
		if err := visit(target); err != nil {
			return err
		}
		state[policyID] = done
		return nil
	}
	for policyID := range governing {
		if err := visit(policyID); err != nil {
			return err
		}
	}
	return nil
}

func scopeDerivativeBindings(scope AdmissionSuccessorScope) ([]DerivativeBinding, error) {
	total := len(scope.Generations) + len(scope.Indexes) + len(scope.Suites) + len(scope.Projections)
	if total > maxAdmissionScopeDerivatives {
		return nil, errors.New("admission successor scope exceeds its bound")
	}
	bindings := make([]DerivativeBinding, 0, total)
	for _, generation := range scope.Generations {
		binding, err := generationDerivativeBinding(generation)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	for _, index := range scope.Indexes {
		binding, err := lexicalIndexDerivativeBinding(index)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	for _, suite := range scope.Suites {
		binding, err := pairedSuiteDerivativeBinding(suite)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	for _, projection := range scope.Projections {
		binding, err := projectionDerivativeBinding(projection)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	seen := make(map[string]DerivativeBinding, len(bindings))
	deduped := make([]DerivativeBinding, 0, len(bindings))
	for _, binding := range bindings {
		if binding.DerivativeID == "" {
			return nil, errors.New("derivative scope entry has no identity")
		}
		key := binding.Kind + "\x00" + binding.DerivativeID
		if prior, ok := seen[key]; ok {
			if prior != binding {
				return nil, errors.New("derivative scope binds one identity to two admissions")
			}
			continue
		}
		seen[key] = binding
		deduped = append(deduped, binding)
	}
	return deduped, nil
}

func sortDerivativeVerdicts(verdicts []DerivativeVerdict) {
	sort.Slice(verdicts, func(i, j int) bool {
		if verdicts[i].Kind != verdicts[j].Kind {
			return verdicts[i].Kind < verdicts[j].Kind
		}
		return verdicts[i].DerivativeID < verdicts[j].DerivativeID
	})
}
