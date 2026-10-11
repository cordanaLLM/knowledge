package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func succDigest(seed string) string { return digestBytes([]byte(seed)) }

func succAdmissionID(seed string) string {
	return admissionPolicyIDPrefix + succDigest("admission:"+seed)
}

const succReviewerKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func baseRevocationCore() AdmissionSuccessorRecordCore {
	return AdmissionSuccessorRecordCore{
		SchemaVersion:              retrievalSchemaVersion,
		RecordKind:                 admissionSuccessorKind,
		Disposition:                successorDispositionRevoked,
		PriorAdmissionPolicyID:     succAdmissionID("prior"),
		PriorAdmissionPolicySHA256: succDigest("prior-doc"),
		Reason:                     "source upstream deleted the reviewed revision",
		EffectiveAt:                "2026-07-16T00:00:00Z",
		KnownAt:                    "2026-07-16T12:00:00Z",
		Reviewer:                   "acl-authority",
		ReviewerKeyID:              succReviewerKey,
		EvidenceObjectPath:         "review/sha256/aa/decision.json",
		EvidenceSHA256:             succDigest("evidence"),
		EvidenceByteSize:           2048,
	}
}

func mustSeal(t *testing.T, core AdmissionSuccessorRecordCore) AdmissionSuccessorRecord {
	t.Helper()
	record, err := SealAdmissionSuccessorRecord(core)
	if err != nil {
		t.Fatalf("seal admission successor: %v", err)
	}
	return record
}

func successorPolicy(t *testing.T, seed, state string) AdmissionPolicy {
	t.Helper()
	core := materializationTestPolicyCore()
	core.State = state
	core.SnapshotID = "snp:test:" + seed
	core.SourceID = "src:test:" + seed
	core.ComponentID = "cmp:test:" + seed
	core.ComponentVersionID = "cv:test:" + seed
	core.EvaluatedAt = "2026-07-16T00:00:00Z"
	core.FreshUntil = "2026-07-20T00:00:00Z"
	policy, err := deriveAdmissionPolicy(core)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func policyDocumentSHA256(t *testing.T, policy AdmissionPolicy) string {
	t.Helper()
	digest, _, err := documentSHA256(policy)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustReview(t *testing.T, policy AdmissionPolicy, decision string) AdmissionPolicyReview {
	t.Helper()
	review, err := SealAdmissionPolicyReview(AdmissionPolicyReviewCore{
		SchemaVersion:                 retrievalSchemaVersion,
		RecordKind:                    admissionPolicyReviewKind,
		Decision:                      decision,
		AdmissionPolicy:               policy,
		AdmissionPolicyDocumentSHA256: policyDocumentSHA256(t, policy),
		ReviewedAt:                    "2026-07-16T10:00:00Z",
		Reviewer:                      "admission-authority",
		ReviewerKeyID:                 succReviewerKey,
		EvidenceObjectPath:            "review/sha256/bb/admission.json",
		EvidenceSHA256:                succDigest("admission-review:" + policy.PolicyID + ":" + decision),
		EvidenceByteSize:              4096,
	})
	if err != nil {
		t.Fatalf("seal admission review: %v", err)
	}
	return review
}

func correctionCoreForReview(t *testing.T, priorID, priorSHA string, review AdmissionPolicyReview) AdmissionSuccessorRecordCore {
	t.Helper()
	reviewSHA, _, err := documentSHA256(review)
	if err != nil {
		t.Fatal(err)
	}
	core := baseRevocationCore()
	core.Disposition = successorDispositionCorrected
	core.PriorAdmissionPolicyID = priorID
	core.PriorAdmissionPolicySHA256 = priorSHA
	core.SuccessorAdmissionPolicyID = stringPointer(review.AdmissionPolicy.PolicyID)
	core.SuccessorAdmissionPolicySHA256 = stringPointer(review.AdmissionPolicyDocumentSHA256)
	core.SuccessorAdmissionReviewID = stringPointer(review.ReviewID)
	core.SuccessorAdmissionReviewSHA256 = stringPointer(reviewSHA)
	core.Reason = "reviewed correction to the admitted revision"
	return core
}

func successorScope() AdmissionSuccessorScope {
	return AdmissionSuccessorScope{Boundary: admissionScopeCallerSupplied}
}

func successorView(validAt, knownAt string) SuccessorResolutionView {
	return SuccessorResolutionView{ValidAt: validAt, KnownAt: knownAt}
}

func currentSuccessorView() SuccessorResolutionView {
	return successorView("2026-07-17T00:00:00Z", "2026-07-17T00:00:00Z")
}

func generationBoundTo(seed, admissionID, admissionSHA string) RetrievalGeneration {
	core := RetrievalGenerationCore{AdmissionPolicyID: admissionID, AdmissionPolicySHA256: admissionSHA}
	data, _ := json.Marshal(core)
	digest := digestBytes(data)
	return RetrievalGeneration{GenerationID: "retrieval-generation:" + digest, GenerationPayloadSHA256: digest, RetrievalGenerationCore: core}
}

func lexicalInputBoundTo(t *testing.T, seed, admissionID, admissionSHA string) AdmissionLexicalIndexInput {
	t.Helper()
	indexCore := LexicalIndexCore{
		SchemaVersion: retrievalSchemaVersion, IndexKind: "deterministic_lexical_inverted_index",
		Lexical: true, Dense: false, EvidenceManifestID: "evidence-manifest:" + succDigest("evidence:"+seed),
		SnapshotManifestID: "snapshot-manifest:" + succDigest("snapshot:"+seed), AdmissionPolicyID: admissionID,
		FreshnessState: "fresh", Documents: []IndexedDocument{}, Terms: []TermEntry{},
	}
	indexCoreBytes, _ := json.Marshal(indexCore)
	indexDigest := digestBytes(indexCoreBytes)
	index := LexicalIndex{IndexID: "lexical-index:" + indexDigest, IndexPayloadSHA256: indexDigest, LexicalIndexCore: indexCore}
	indexDocumentSHA, indexDocument, err := documentSHA256(index)
	if err != nil {
		t.Fatal(err)
	}
	candidateCore := CandidateManifestCore{
		SchemaVersion: retrievalSchemaVersion, ManifestKind: "knowledge_retrieval_candidate", State: "partial",
		Lexical: true, Dense: false, AdmissionPolicyID: admissionID, AdmissionPolicySHA256: admissionSHA,
		EvidenceManifestID: index.EvidenceManifestID, SnapshotManifestID: index.SnapshotManifestID,
		LexicalIndexID: index.IndexID, LexicalIndexSHA256: indexDocumentSHA,
		LexicalIndexByteSize: int64(len(indexDocument)), MissingCapabilities: []string{"dense"},
	}
	candidateCoreBytes, _ := json.Marshal(candidateCore)
	candidateDigest := digestBytes(candidateCoreBytes)
	candidate := CandidateManifest{ManifestID: "retrieval-candidate:" + candidateDigest, ManifestPayloadSHA256: candidateDigest, CandidateManifestCore: candidateCore}
	return AdmissionLexicalIndexInput{Candidate: candidate, Index: index}
}

func suiteBoundTo(seed, admissionID, admissionSHA string) PairedFusionSuite {
	core := PairedFusionSuiteCore{AdmissionPolicy: PairedFusionArtifactBinding{ArtifactID: admissionID, DocumentSHA256: admissionSHA}}
	data, _ := json.Marshal(core)
	digest := digestBytes(data)
	return PairedFusionSuite{SuiteID: "paired-fusion-suite:" + digest, SuitePayloadSHA256: digest, PairedFusionSuiteCore: core}
}

func pointerTo(seed string, generation RetrievalGeneration) RetrievalGenerationPointer {
	core := RetrievalGenerationPointerCore{CurrentGenerationID: generation.GenerationID, CurrentGenerationSHA256: generation.GenerationPayloadSHA256}
	data, _ := json.Marshal(core)
	digest := digestBytes(data)
	return RetrievalGenerationPointer{PointerID: "retrieval-pointer:" + digest, PointerPayloadSHA256: digest, RetrievalGenerationPointerCore: core}
}

func TestAdmissionSuccessorSealIsContentAddressedAndStable(t *testing.T) {
	core := baseRevocationCore()
	first := mustSeal(t, core)
	second := mustSeal(t, core)
	if first != second || !strings.HasPrefix(first.RecordID, admissionSuccessorIDPrefix) {
		t.Fatalf("seal is not stable: first=%+v second=%+v", first, second)
	}
	tampered := first
	tampered.Reason = "different reason"
	if err := validateAdmissionSuccessorRecord(tampered); err == nil {
		t.Fatal("tampered record accepted")
	}
}

func TestAdmissionPolicyReviewBindsActualPolicyObjectAndState(t *testing.T) {
	policy := successorPolicy(t, "successor", "active")
	review := mustReview(t, policy, admissionReviewAccepted)
	if err := validateAdmissionPolicyReview(review); err != nil {
		t.Fatalf("valid review rejected: %v", err)
	}
	forged := review
	forged.AdmissionPolicy.SourceID = "src:test:forged"
	if err := validateAdmissionPolicyReview(forged); err == nil {
		t.Fatal("review with forged policy bytes accepted")
	}

	draft := successorPolicy(t, "draft", "draft")
	core := review.AdmissionPolicyReviewCore
	core.AdmissionPolicy = draft
	core.AdmissionPolicyDocumentSHA256 = policyDocumentSHA256(t, draft)
	if _, err := SealAdmissionPolicyReview(core); err == nil {
		t.Fatal("accepted review admitted a non-active policy")
	}
	core.Decision = admissionReviewRejected
	if _, err := SealAdmissionPolicyReview(core); err != nil {
		t.Fatalf("rejected review could not preserve the rejected policy object: %v", err)
	}
}

func TestAdmissionSuccessorCoreRejectsMalformedRecords(t *testing.T) {
	policy := successorPolicy(t, "successor", "active")
	review := mustReview(t, policy, admissionReviewAccepted)
	validCorrection := correctionCoreForReview(t, succAdmissionID("prior"), succDigest("prior-doc"), review)
	tests := []struct {
		name   string
		core   AdmissionSuccessorRecordCore
		mutate func(*AdmissionSuccessorRecordCore)
	}{
		{"bad schema", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.SchemaVersion = "9.9.9" }},
		{"bad kind", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.RecordKind = "other" }},
		{"bad disposition", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.Disposition = "cancelled" }},
		{"prior id", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.PriorAdmissionPolicyID = succDigest("x") }},
		{"prior sha", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.PriorAdmissionPolicySHA256 = "bad" }},
		{"revocation names successor", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.SuccessorAdmissionPolicyID = stringPointer(policy.PolicyID) }},
		{"correction lacks review", validCorrection, func(c *AdmissionSuccessorRecordCore) { c.SuccessorAdmissionReviewID = nil }},
		{"correction equals prior id", validCorrection, func(c *AdmissionSuccessorRecordCore) {
			c.SuccessorAdmissionPolicyID = stringPointer(c.PriorAdmissionPolicyID)
		}},
		{"correction equals prior sha", validCorrection, func(c *AdmissionSuccessorRecordCore) {
			c.SuccessorAdmissionPolicySHA256 = stringPointer(c.PriorAdmissionPolicySHA256)
		}},
		{"empty reason", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.Reason = "" }},
		{"bad reviewer key", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.ReviewerKeyID = "bad" }},
		{"effective not utc", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.EffectiveAt = "2026-07-16T02:00:00+02:00" }},
		{"known not utc", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.KnownAt = "yesterday" }},
		{"evidence escape", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.EvidenceObjectPath = "../secret" }},
		{"evidence sha", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.EvidenceSHA256 = "nope" }},
		{"evidence size", baseRevocationCore(), func(c *AdmissionSuccessorRecordCore) { c.EvidenceByteSize = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := test.core
			test.mutate(&core)
			if _, err := SealAdmissionSuccessorRecord(core); err == nil {
				t.Fatal("malformed record accepted")
			}
		})
	}
}

func TestResolveQuarantinesEveryBoundDerivativeBitemporally(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	core := baseRevocationCore()
	core.PriorAdmissionPolicyID, core.PriorAdmissionPolicySHA256 = priorID, priorSHA
	record := mustSeal(t, core)
	generation := generationBoundTo("g1", priorID, priorSHA)
	index := lexicalInputBoundTo(t, "i1", priorID, priorSHA)
	suite := suiteBoundTo("s1", priorID, priorSHA)
	pointer := pointerTo("p1", generation)
	scope := successorScope()
	scope.Generations = []RetrievalGeneration{generation}
	scope.Indexes = []AdmissionLexicalIndexInput{index}
	scope.Suites = []PairedFusionSuite{suite}
	scope.Projections = []AdmissionProjectionInput{{Pointer: pointer, CurrentGeneration: generation}}

	after, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, currentSuccessorView())
	if err != nil {
		t.Fatalf("resolve after effective and known: %v", err)
	}
	if len(after.Quarantined) != 4 || len(after.Reproducible) != 0 || len(after.Unaffected) != 0 || after.PersistenceVerified {
		t.Fatalf("unexpected current resolution: %+v", after)
	}
	before, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, successorView("2026-07-15T00:00:00Z", "2026-07-17T00:00:00Z"))
	if err != nil || len(before.Reproducible) != 4 || len(before.Quarantined) != 0 {
		t.Fatalf("historical valid-time view changed: result=%+v err=%v", before, err)
	}
}

func TestResolveHonorsKnownAtWithoutLeakingLaterEvidence(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	core := baseRevocationCore()
	core.PriorAdmissionPolicyID, core.PriorAdmissionPolicySHA256 = priorID, priorSHA
	core.EffectiveAt = "2026-07-10T00:00:00Z"
	core.KnownAt = "2026-07-16T12:00:00Z"
	record := mustSeal(t, core)
	scope := successorScope()
	scope.Generations = []RetrievalGeneration{generationBoundTo("g1", priorID, priorSHA)}

	beforeKnown, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, successorView("2026-07-17T00:00:00Z", "2026-07-16T11:59:59Z"))
	if err != nil || len(beforeKnown.Unaffected) != 1 || len(beforeKnown.RecordIDs) != 0 {
		t.Fatalf("later-known record leaked into historical transaction view: result=%+v err=%v", beforeKnown, err)
	}
	afterKnown, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, successorView("2026-07-17T00:00:00Z", "2026-07-16T12:00:00Z"))
	if err != nil || len(afterKnown.Quarantined) != 1 || len(afterKnown.RecordIDs) != 1 {
		t.Fatalf("visible retroactive record did not govern: result=%+v err=%v", afterKnown, err)
	}
}

func TestResolveSeparatesFutureValidTimeFromTransactionTime(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	core := baseRevocationCore()
	core.PriorAdmissionPolicyID, core.PriorAdmissionPolicySHA256 = priorID, priorSHA
	core.KnownAt = "2026-07-16T00:00:00Z"
	core.EffectiveAt = "2026-07-18T00:00:00Z"
	record := mustSeal(t, core)
	scope := successorScope()
	scope.Generations = []RetrievalGeneration{generationBoundTo("g1", priorID, priorSHA)}

	beforeValid, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, successorView("2026-07-17T00:00:00Z", "2026-07-17T00:00:00Z"))
	if err != nil || len(beforeValid.Reproducible) != 1 {
		t.Fatalf("known scheduled decision did not preserve pre-effective view: result=%+v err=%v", beforeValid, err)
	}
	afterValid, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, successorView("2026-07-18T00:00:00Z", "2026-07-17T00:00:00Z"))
	if err != nil || len(afterValid.Quarantined) != 1 {
		t.Fatalf("scheduled decision did not activate at valid time: result=%+v err=%v", afterValid, err)
	}
}

func TestResolveOnlyVisibleRecordsCanConflictWithHistoricalView(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	first := baseRevocationCore()
	first.PriorAdmissionPolicyID, first.PriorAdmissionPolicySHA256 = priorID, priorSHA
	first.KnownAt = "2026-07-16T12:00:00Z"
	second := first
	second.KnownAt = "2026-07-16T13:00:00Z"
	second.Reason = "later contradictory review"
	records := []AdmissionSuccessorRecord{mustSeal(t, first), mustSeal(t, second)}
	scope := successorScope()
	scope.Generations = []RetrievalGeneration{generationBoundTo("g1", priorID, priorSHA)}

	earlier, err := ResolveAdmissionSuccessors(records, nil, scope, successorView("2026-07-17T00:00:00Z", "2026-07-16T12:30:00Z"))
	if err != nil || len(earlier.Quarantined) != 1 || len(earlier.RecordIDs) != 1 {
		t.Fatalf("later conflict rewrote earlier as-known view: result=%+v err=%v", earlier, err)
	}
	if _, err := ResolveAdmissionSuccessors(records, nil, scope, successorView("2026-07-17T00:00:00Z", "2026-07-16T13:00:00Z")); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("visible conflict did not fail closed: %v", err)
	}
}

func TestResolveCorrectionRequiresExactAcceptedSuccessorReview(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	policy := successorPolicy(t, "successor", "active")
	accepted := mustReview(t, policy, admissionReviewAccepted)
	core := correctionCoreForReview(t, priorID, priorSHA, accepted)
	record := mustSeal(t, core)
	scope := successorScope()
	scope.Generations = []RetrievalGeneration{generationBoundTo("g1", priorID, priorSHA)}

	result, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, []AdmissionPolicyReview{accepted}, scope, currentSuccessorView())
	if err != nil || len(result.Quarantined) != 1 || result.Quarantined[0].Verdict != derivativeVerdictSuperseded {
		t.Fatalf("accepted reviewed successor did not resolve: result=%+v err=%v", result, err)
	}
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, currentSuccessorView()); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing successor review accepted: %v", err)
	}
	forged := accepted
	forged.AdmissionPolicy.SourceID = "src:test:forged"
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, []AdmissionPolicyReview{forged}, scope, currentSuccessorView()); err == nil || !strings.Contains(err.Error(), "review registry invalid") {
		t.Fatalf("forged successor policy bytes accepted: %v", err)
	}
	rejected := mustReview(t, policy, admissionReviewRejected)
	rejectedCore := correctionCoreForReview(t, priorID, priorSHA, rejected)
	rejectedRecord := mustSeal(t, rejectedCore)
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{rejectedRecord}, []AdmissionPolicyReview{rejected}, scope, currentSuccessorView()); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("rejected successor accepted: %v", err)
	}

	otherPolicy := successorPolicy(t, "other", "active")
	otherReview := mustReview(t, otherPolicy, admissionReviewAccepted)
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, []AdmissionPolicyReview{otherReview}, scope, currentSuccessorView()); err == nil {
		t.Fatal("different reviewed successor object accepted")
	}
}

func TestResolveRejectsReviewKnownAfterCorrection(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	policy := successorPolicy(t, "successor", "active")
	review := mustReview(t, policy, admissionReviewAccepted)
	core := correctionCoreForReview(t, priorID, priorSHA, review)
	core.KnownAt = "2026-07-16T09:00:00Z"
	record := mustSeal(t, core)
	_, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, []AdmissionPolicyReview{review}, successorScope(), currentSuccessorView())
	if err == nil || !strings.Contains(err.Error(), "before its successor review") {
		t.Fatalf("correction known before review accepted: %v", err)
	}
}

func TestResolveFailsClosedOnConflictsAndCorrectionCycles(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	first := baseRevocationCore()
	first.PriorAdmissionPolicyID, first.PriorAdmissionPolicySHA256 = priorID, priorSHA
	second := first
	second.Reason = "a different reviewed reason"
	_, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{mustSeal(t, first), mustSeal(t, second)}, nil, successorScope(), currentSuccessorView())
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("ambiguous records accepted: %v", err)
	}

	policyA := successorPolicy(t, "A", "active")
	policyB := successorPolicy(t, "B", "active")
	reviewA := mustReview(t, policyA, admissionReviewAccepted)
	reviewB := mustReview(t, policyB, admissionReviewAccepted)
	toB := mustSeal(t, correctionCoreForReview(t, policyA.PolicyID, policyDocumentSHA256(t, policyA), reviewB))
	toA := mustSeal(t, correctionCoreForReview(t, policyB.PolicyID, policyDocumentSHA256(t, policyB), reviewA))
	_, err = ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{toB, toA}, []AdmissionPolicyReview{reviewA, reviewB}, successorScope(), currentSuccessorView())
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("correction cycle accepted: %v", err)
	}
}

func TestResolveFailsClosedWhenCorrectionTargetsRevokedSuccessor(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	policy := successorPolicy(t, "successor", "active")
	review := mustReview(t, policy, admissionReviewAccepted)
	correction := mustSeal(t, correctionCoreForReview(t, priorID, priorSHA, review))
	revocationCore := baseRevocationCore()
	revocationCore.PriorAdmissionPolicyID = policy.PolicyID
	revocationCore.PriorAdmissionPolicySHA256 = policyDocumentSHA256(t, policy)
	revocation := mustSeal(t, revocationCore)
	_, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{correction, revocation}, []AdmissionPolicyReview{review}, successorScope(), currentSuccessorView())
	if err == nil || !strings.Contains(err.Error(), "itself revoked") {
		t.Fatalf("correction into revoked successor accepted: %v", err)
	}
}

func TestResolveLexicalIndexRequiresExactCandidateAdmissionDocumentBinding(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	core := baseRevocationCore()
	core.PriorAdmissionPolicyID, core.PriorAdmissionPolicySHA256 = priorID, priorSHA
	record := mustSeal(t, core)
	input := lexicalInputBoundTo(t, "i1", priorID, priorSHA)
	scope := successorScope()
	scope.Indexes = []AdmissionLexicalIndexInput{input}
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, currentSuccessorView()); err != nil {
		t.Fatalf("exact lexical binding rejected: %v", err)
	}

	forged := input
	forged.Candidate.AdmissionPolicySHA256 = succDigest("wrong-policy-document")
	coreBytes, _ := json.Marshal(forged.Candidate.CandidateManifestCore)
	forged.Candidate.ManifestPayloadSHA256 = digestBytes(coreBytes)
	forged.Candidate.ManifestID = "retrieval-candidate:" + forged.Candidate.ManifestPayloadSHA256
	scope.Indexes = []AdmissionLexicalIndexInput{forged}
	_, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, currentSuccessorView())
	if err == nil || !strings.Contains(err.Error(), "inconsistent admission identity") {
		t.Fatalf("admission ID with wrong document bytes accepted: %v", err)
	}
}

func TestResolveMakesUnpersistedProjectionBoundaryExplicit(t *testing.T) {
	scope := successorScope()
	result, err := ResolveAdmissionSuccessors(nil, nil, scope, currentSuccessorView())
	if err != nil {
		t.Fatal(err)
	}
	if result.ScopeBoundary != admissionScopeCallerSupplied || result.PersistenceVerified {
		t.Fatalf("pure resolver overstated persistence: %+v", result)
	}
	scope.Boundary = ""
	if _, err := ResolveAdmissionSuccessors(nil, nil, scope, currentSuccessorView()); err == nil || !strings.Contains(err.Error(), "unpersisted") {
		t.Fatalf("implicit projection boundary accepted: %v", err)
	}
}

func TestResolveFailsClosedOnProjectionAndDuplicateDerivativeMismatch(t *testing.T) {
	priorID, priorSHA := succAdmissionID("prior"), succDigest("prior-doc")
	record := mustSeal(t, baseRevocationCore())
	generation := generationBoundTo("g1", priorID, priorSHA)
	pointer := pointerTo("p1", generation)
	pointer.CurrentGenerationID = "retrieval-generation:" + succDigest("other")
	pointerCore, _ := json.Marshal(pointer.RetrievalGenerationPointerCore)
	pointer.PointerPayloadSHA256 = digestBytes(pointerCore)
	pointer.PointerID = "retrieval-pointer:" + pointer.PointerPayloadSHA256
	scope := successorScope()
	scope.Projections = []AdmissionProjectionInput{{Pointer: pointer, CurrentGeneration: generation}}
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, currentSuccessorView()); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("projection mismatch accepted: %v", err)
	}

	first := generationBoundTo("same", priorID, priorSHA)
	second := first
	second.AdmissionPolicyID = succAdmissionID("other")
	second.AdmissionPolicySHA256 = succDigest("other-doc")
	secondCore, _ := json.Marshal(second.RetrievalGenerationCore)
	second.GenerationPayloadSHA256 = digestBytes(secondCore)
	// Force the same derivative identity while changing the bound admission.
	second.GenerationID = first.GenerationID
	scope = successorScope()
	scope.Generations = []RetrievalGeneration{first, second}
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, scope, currentSuccessorView()); err == nil {
		t.Fatal("forged duplicate derivative accepted")
	}
}

func TestResolveIsIdempotentAndOrderInsensitiveWithinKnownAtView(t *testing.T) {
	priorA, priorB := succAdmissionID("A"), succAdmissionID("B")
	shaA, shaB := succDigest("A-doc"), succDigest("B-doc")
	coreA := baseRevocationCore()
	coreA.PriorAdmissionPolicyID, coreA.PriorAdmissionPolicySHA256 = priorA, shaA
	coreB := baseRevocationCore()
	coreB.PriorAdmissionPolicyID, coreB.PriorAdmissionPolicySHA256 = priorB, shaB
	recordA, recordB := mustSeal(t, coreA), mustSeal(t, coreB)
	scope := successorScope()
	scope.Generations = []RetrievalGeneration{generationBoundTo("A", priorA, shaA), generationBoundTo("B", priorB, shaB)}
	canonical := func(records []AdmissionSuccessorRecord) string {
		result, err := ResolveAdmissionSuccessors(records, nil, scope, currentSuccessorView())
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(result)
		return string(data)
	}
	if canonical([]AdmissionSuccessorRecord{recordA, recordB}) != canonical([]AdmissionSuccessorRecord{recordB, recordA, recordA, recordB}) {
		t.Fatal("resolution depends on input order or duplicates")
	}
}

func TestResolveRejectsInvalidViewsAndTamperedRecords(t *testing.T) {
	record := mustSeal(t, baseRevocationCore())
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, successorScope(), successorView("bad", "2026-07-17T00:00:00Z")); err == nil {
		t.Fatal("invalid valid-at accepted")
	}
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{record}, nil, successorScope(), successorView("2026-07-17T00:00:00Z", "bad")); err == nil {
		t.Fatal("invalid known-at accepted")
	}
	tampered := record
	tampered.RecordPayloadSHA256 = succDigest("tamper")
	if _, err := ResolveAdmissionSuccessors([]AdmissionSuccessorRecord{tampered}, nil, successorScope(), currentSuccessorView()); err == nil {
		t.Fatal("tampered record accepted")
	}
}
