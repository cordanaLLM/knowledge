package main

import (
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const maxQueryUniqueTerms = 64

type lexicalAggregate struct {
	score    int64
	terms    []string
	evidence EvidenceRef
}

// lexicalTopK keeps the worst retained hit at index zero. Query result limits
// are capped at 100, so selection is O(matched postings * log(limit)) without
// sorting every matching document in the corpus-sized worst case.
type lexicalTopK []*lexicalAggregate

func (h lexicalTopK) Len() int { return len(h) }
func (h lexicalTopK) Less(i, j int) bool {
	return lexicalAggregateWorse(h[i], h[j])
}
func (h lexicalTopK) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *lexicalTopK) Push(value any) {
	*h = append(*h, value.(*lexicalAggregate))
}
func (h *lexicalTopK) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func lexicalAggregateBetter(left, right *lexicalAggregate) bool {
	if left.score != right.score {
		return left.score > right.score
	}
	return left.evidence.SpanID < right.evidence.SpanID
}

func lexicalAggregateWorse(left, right *lexicalAggregate) bool {
	if left.score != right.score {
		return left.score < right.score
	}
	return left.evidence.SpanID > right.evidence.SpanID
}

func selectLexicalTopK(aggregates map[string]*lexicalAggregate, limit int) []*lexicalAggregate {
	top := make(lexicalTopK, 0, limit)
	for _, current := range aggregates {
		if len(top) < limit {
			heap.Push(&top, current)
			continue
		}
		if lexicalAggregateBetter(current, top[0]) {
			heap.Pop(&top)
			heap.Push(&top, current)
		}
	}
	ordered := append([]*lexicalAggregate(nil), top...)
	sort.Slice(ordered, func(i, j int) bool {
		return lexicalAggregateBetter(ordered[i], ordered[j])
	})
	return ordered
}

func Query(config QueryConfig) (QueryResponse, error) {
	base := QueryResponse{State: "partial", ResultState: "backend_unavailable", Promotable: false, Lexical: true, Dense: false, Results: []QueryHit{}}
	for name, value := range map[string]string{
		"candidate": config.CandidatePath, "candidate-sha256": config.CandidateHash,
		"store": config.StoreRoot, "evidence-store": config.EvidenceStoreRoot,
		"admission-policy": config.AdmissionPolicyPath, "admission-policy-sha256": config.AdmissionPolicyHash,
		"query": config.Query, "principal-scope": config.PrincipalScope, "as-of": config.AsOf,
	} {
		if strings.TrimSpace(value) == "" {
			return base, fmt.Errorf("%s is required", name)
		}
	}
	if config.Limit < 1 || config.Limit > 100 {
		return base, errors.New("limit must be between 1 and 100")
	}
	if config.MaxExcerptBytes < 1 || config.MaxExcerptBytes > 8192 {
		return base, errors.New("max-excerpt-bytes must be between 1 and 8192")
	}
	asOf, err := parseCanonicalUTC(config.AsOf)
	if err != nil {
		return base, fmt.Errorf("as-of: %w", err)
	}
	if config.PrincipalScope != "public" {
		base.ResultState = "forbidden"
		base.ErrorCode = "principal_scope_forbidden"
		return base, nil
	}
	storeRoot, err := filepath.Abs(config.StoreRoot)
	if err != nil || validateNoSymlinkPath(storeRoot) != nil {
		base.ErrorCode = "candidate_store_unavailable"
		return base, nil
	}
	evidenceRoot, err := filepath.Abs(config.EvidenceStoreRoot)
	if err != nil || validateNoSymlinkPath(evidenceRoot) != nil {
		base.ErrorCode = "evidence_store_unavailable"
		return base, nil
	}

	candidateBytes, err := readStableFile(config.CandidatePath, "candidate manifest", maxManifestBytes)
	if err != nil {
		base.ErrorCode = "candidate_unavailable"
		return base, nil
	}
	if digestBytes(candidateBytes) != config.CandidateHash {
		base.ErrorCode = "candidate_document_mismatch"
		return base, nil
	}
	var candidate CandidateManifest
	if err := decodeStrictCanonical(candidateBytes, &candidate); err != nil || validateCandidate(candidate) != nil {
		base.ErrorCode = "candidate_invalid"
		return base, nil
	}
	base.CandidateManifestID = candidate.ManifestID
	base.LexicalProfile = candidate.LexicalProfile
	base.FreshnessState = candidate.FreshnessState
	bm25f := isBM25FProfile(candidateLexicalProfile(candidate))

	// A shared multidomain candidate carries no single-authority admission binding;
	// its admission lives per authority in candidate.Lineages and is re-checked
	// against the operator-pinned lineage set. Single-authority candidates keep the
	// historical one-policy path byte-for-byte.
	if candidate.ManifestKind == lexicalMultidomainCandidate {
		resultState, freshnessState, errorCode := validateMultidomainAdmission(candidate, config.LineageSetPath, asOf)
		if errorCode != "" {
			base.ResultState = resultState
			base.ErrorCode = errorCode
			return base, nil
		}
		base.FreshnessState = freshnessState
	} else {
		policyBytes, err := readStableFile(config.AdmissionPolicyPath, "admission policy", maxPolicyBytes)
		if err != nil {
			base.ErrorCode = "admission_policy_unavailable"
			return base, nil
		}
		if digestBytes(policyBytes) != config.AdmissionPolicyHash {
			base.ResultState = "forbidden"
			base.ErrorCode = "admission_policy_document_mismatch"
			return base, nil
		}
		var policy AdmissionPolicy
		if err := decodeStrictCanonical(policyBytes, &policy); err != nil || validatePolicyIdentity(policy) != nil {
			base.ResultState = "forbidden"
			base.ErrorCode = "admission_policy_invalid"
			return base, nil
		}
		if policy.AccessScope != "public" || !policy.RetrievalAllowed || policy.State != "active" {
			base.ResultState = "forbidden"
			base.ErrorCode = "admission_policy_forbidden"
			return base, nil
		}
		if policy.SourceState != "present" || policy.DeletionState != "active" || policy.Tombstone {
			base.ResultState = "forbidden"
			base.ErrorCode = "source_deleted_or_tombstoned"
			return base, nil
		}
		evaluatedAt, _ := parseCanonicalUTC(policy.EvaluatedAt)
		if asOf.Before(evaluatedAt) {
			base.ResultState = "forbidden"
			base.ErrorCode = "query_before_policy_evaluation"
			return base, nil
		}
		if policy.PolicyID != candidate.AdmissionPolicyID || policy.SnapshotManifestID != candidate.SnapshotManifestID || policy.EvidenceManifestID != candidate.EvidenceManifestID {
			base.ResultState = "forbidden"
			base.ErrorCode = "admission_policy_changed"
			return base, nil
		}
		if config.AdmissionPolicyHash != candidate.AdmissionPolicySHA256 {
			base.ResultState = "forbidden"
			base.ErrorCode = "admission_policy_changed"
			return base, nil
		}
		freshUntil, _ := parseCanonicalUTC(policy.FreshUntil)
		base.FreshnessState = "fresh"
		if asOf.After(freshUntil) {
			base.FreshnessState = "stale"
		}
	}

	if validateRelativePath(candidate.LexicalIndexPath) != nil {
		base.ErrorCode = "index_path_invalid"
		return base, nil
	}
	if candidate.LexicalIndexByteSize < 1 || candidate.LexicalIndexByteSize > maxIndexBytes {
		base.ErrorCode = "index_size_limit"
		return base, nil
	}
	indexPath := filepath.Join(storeRoot, filepath.FromSlash(candidate.LexicalIndexPath))
	if !isWithin(storeRoot, indexPath) {
		base.ErrorCode = "index_path_escape"
		return base, nil
	}
	indexBytes, err := verifyFileDigest(indexPath, candidate.LexicalIndexSHA256, candidate.LexicalIndexByteSize)
	if err != nil {
		base.ErrorCode = "index_backend_unavailable"
		return base, nil
	}
	var index LexicalIndex
	if err := decodeStrictCanonical(indexBytes, &index); err != nil || validateIndex(index, candidate) != nil {
		base.ErrorCode = "index_invalid"
		return base, nil
	}

	// Keep prompt-wrapped operational questions bounded without rejecting
	// legitimate held-out queries that carry an explicit untrusted-instruction
	// envelope. One extra slot lets us return the precise query-limit error.
	var queryTerms []string
	if bm25f {
		queryTerms, err = bm25fQueryTermsForProfile(candidate.LexicalProfile, []byte(config.Query))
		if err != nil {
			return base, err
		}
	} else {
		queryFrequencies, tokenIssue := lexicalFrequencies([]byte(config.Query), nil, maxQueryUniqueTerms+1, maxQueryUniqueTerms+1)
		if tokenIssue != nil {
			if tokenIssue.Code == "posting_count_limit" || tokenIssue.Code == "term_count_limit" {
				return base, fmt.Errorf("query contains more than %d unique lexical terms", maxQueryUniqueTerms)
			}
			return base, errors.New(tokenIssue.Message)
		}
		if len(queryFrequencies) > maxQueryUniqueTerms {
			return base, fmt.Errorf("query contains more than %d unique lexical terms", maxQueryUniqueTerms)
		}
		queryTerms = make([]string, 0, len(queryFrequencies))
		for term := range queryFrequencies {
			queryTerms = append(queryTerms, term)
		}
		sort.Strings(queryTerms)
	}
	base.QueryTerms = queryTerms
	if len(queryTerms) == 0 {
		if base.FreshnessState == "stale" {
			base.ResultState = "stale"
		} else {
			base.ResultState = "empty"
		}
		return base, nil
	}

	documents := make(map[string]IndexedDocument)
	if !bm25f {
		documents = make(map[string]IndexedDocument, len(index.Documents))
		for _, document := range index.Documents {
			documents[document.DocumentID] = document
		}
	}
	aggregates := make(map[string]*lexicalAggregate)
	for _, queryTerm := range queryTerms {
		termIndex := sort.Search(len(index.Terms), func(i int) bool { return index.Terms[i].Term >= queryTerm })
		if termIndex == len(index.Terms) || index.Terms[termIndex].Term != queryTerm {
			continue
		}
		term := index.Terms[termIndex]
		termIDF := int64(0)
		if bm25f {
			termIDF, err = bm25fTermIDF(index.DocumentCount, term.DocumentFrequency)
			if err != nil {
				base.ErrorCode = "lexical_score_overflow"
				return base, nil
			}
		}
		for _, posting := range term.Postings {
			var document IndexedDocument
			if bm25f {
				if posting.DocumentPosition < 1 || posting.DocumentPosition > len(index.Documents) {
					base.ErrorCode = "index_document_reference_invalid"
					return base, nil
				}
				document = index.Documents[posting.DocumentPosition-1]
				if document.DocumentID != posting.DocumentID {
					base.ErrorCode = "index_document_reference_invalid"
					return base, nil
				}
			} else {
				var exists bool
				document, exists = documents[posting.DocumentID]
				if !exists {
					base.ErrorCode = "index_document_reference_invalid"
					return base, nil
				}
			}
			current := aggregates[posting.DocumentID]
			if current == nil {
				current = &lexicalAggregate{evidence: document.Evidence}
				aggregates[posting.DocumentID] = current
			}
			termScore := int64(posting.TermFrequency)
			if bm25f {
				termScore, err = scoreBM25FWithIDF(index, document, posting, termIDF)
				if err != nil {
					base.ErrorCode = "lexical_score_overflow"
					return base, nil
				}
			}
			current.score, err = checkedAddInt64(current.score, termScore)
			if err != nil {
				base.ErrorCode = "lexical_score_overflow"
				return base, nil
			}
			current.terms = append(current.terms, queryTerm)
		}
	}
	ordered := selectLexicalTopK(aggregates, config.Limit)
	hits := make([]QueryHit, 0, len(ordered))
	for _, current := range ordered {
		ref := current.evidence
		if ref.AccessScope != "public" || !evidenceRefBindsAdmittedLineage(ref, candidate.SnapshotManifestID, candidate.EvidenceManifestID, candidate.Lineages) || ref.TrustEnvelopeID != expectedTrustEnvelope().EnvelopeID || ref.InstructionPolicy != "forbidden" || ref.ExecutionPolicy != "never" || ref.ToolPolicy != "never" || ref.InterpretationPolicy != "evidence_only" {
			base.ErrorCode = "index_evidence_envelope_invalid"
			return base, nil
		}
		if validateRelativePath(ref.PayloadObjectPath) != nil {
			base.ErrorCode = "payload_path_invalid"
			return base, nil
		}
		payloadPath := filepath.Join(evidenceRoot, filepath.FromSlash(ref.PayloadObjectPath))
		if !isWithin(evidenceRoot, payloadPath) {
			base.ErrorCode = "payload_path_escape"
			return base, nil
		}
		payload, err := verifyFileDigest(payloadPath, ref.PayloadSHA256, ref.PayloadByteSize)
		if err != nil {
			base.ErrorCode = "payload_backend_unavailable"
			return base, nil
		}
		excerpt, truncated := boundedUTF8(payload, config.MaxExcerptBytes)
		hits = append(hits, QueryHit{Score: current.score, MatchedTerms: current.terms, Evidence: ref, Excerpt: excerpt, ExcerptTruncated: truncated})
	}
	base.Results = hits
	if len(hits) == 0 {
		base.ResultState = "empty"
	} else {
		base.ResultState = "ok"
	}
	if base.FreshnessState == "stale" {
		base.ResultState = "stale"
	}
	return base, nil
}

func validateCandidate(candidate CandidateManifest) error {
	coreBytes, err := json.Marshal(candidate.CandidateManifestCore)
	if err != nil || candidate.ManifestPayloadSHA256 != digestBytes(coreBytes) || candidate.ManifestID != "retrieval-candidate:"+candidate.ManifestPayloadSHA256 {
		return errors.New("candidate identity mismatch")
	}
	multi := candidate.ManifestKind == lexicalMultidomainCandidate
	if candidate.SchemaVersion != retrievalSchemaVersion || (candidate.ManifestKind != lexicalCandidateKind && !multi) || candidate.State != "partial" || candidate.Promotable || candidate.ServingEligible || candidate.CurrentEligible || !candidate.Lexical || candidate.Dense {
		return errors.New("candidate capability contract mismatch")
	}
	if candidate.LexicalIndexSHA256 == "" || candidate.LexicalIndexByteSize < 1 {
		return errors.New("candidate index binding missing")
	}
	// Shared multi-authority candidates carry per-authority lineages instead of a
	// single admission/snapshot/evidence binding; single-authority candidates carry
	// exactly the inverse. Both are exclusive.
	if multi {
		if candidate.AdmissionPolicySHA256 != "" || candidate.SnapshotManifestID != "" || candidate.EvidenceManifestID != "" || candidate.AdmissionPolicyID != "" {
			return errors.New("multidomain candidate must not carry single-authority admission binding")
		}
		if err := validateAuthorityLineages(candidate.Lineages); err != nil {
			return err
		}
	} else if candidate.AdmissionPolicySHA256 == "" || len(candidate.Lineages) != 0 {
		return errors.New("candidate index binding missing")
	}
	if candidate.LexicalProfile == "" {
		if candidate.LexicalTokenizerID != "" || candidate.LexicalScorerID != "" {
			return errors.New("legacy candidate carries successor lexical lineage")
		}
	} else if !validBM25FLineage(candidate.LexicalProfile, candidate.LexicalTokenizerID, candidate.LexicalScorerID) {
		return errors.New("candidate lexical profile binding invalid")
	}
	if validateSourceAdmissionBinding(candidate.SourceAdmissionMethod, candidate.SourceAdmissionPolicyID, candidate.SourceAdmissionPolicySHA256) != nil {
		return errors.New("candidate source admission binding invalid")
	}
	return nil
}

func validatePolicyIdentity(policy AdmissionPolicy) error {
	coreBytes, err := json.Marshal(policy.AdmissionPolicyCore)
	if err != nil || policy.PolicyPayloadSHA256 != digestBytes(coreBytes) || policy.PolicyID != "retrieval-admission:"+policy.PolicyPayloadSHA256 {
		return errors.New("policy identity mismatch")
	}
	if policy.SchemaVersion != retrievalSchemaVersion || policy.PolicyKind != "public_retrieval_admission" {
		return errors.New("policy contract unsupported")
	}
	if _, err := parseCanonicalUTC(policy.EvaluatedAt); err != nil {
		return err
	}
	if _, err := parseCanonicalUTC(policy.FreshUntil); err != nil {
		return err
	}
	return nil
}

// validateAuthorityLineages checks a shared multi-authority lineage set is
// well-formed: at least one authority, strictly ascending distinct authority ids,
// and every per-authority snapshot/evidence/admission binding present and
// content-addressed. Whether each policy was actually admitted is the
// binding-closure's concern, not the retrieval consume path's.
func validateAuthorityLineages(lineages []AuthorityLineageBinding) error {
	if len(lineages) < 1 {
		return errors.New("multidomain artifact carries no authority lineage")
	}
	previous := ""
	for position, lineage := range lineages {
		if position > 0 && lineage.AuthorityID <= previous {
			return errors.New("authority lineages are not in strict distinct authority-id order")
		}
		previous = lineage.AuthorityID
		if !boundedMetadata(lineage.AuthorityID) || !boundedMetadata(lineage.ComponentID) || !boundedMetadata(lineage.ComponentVersion) ||
			!boundedMetadata(lineage.SnapshotManifestID) || !boundedMetadata(lineage.EvidenceManifestID) || !boundedMetadata(lineage.AdmissionPolicyID) {
			return errors.New("authority lineage identity is invalid")
		}
		if !validSHA256(lineage.SnapshotManifestDocumentSHA256) || !validSHA256(lineage.EvidenceManifestDocumentSHA256) || !validSHA256(lineage.AdmissionPolicyDocumentSHA256) {
			return errors.New("authority lineage digest binding is invalid")
		}
		if lineage.DocumentCount < 1 {
			return errors.New("authority lineage document count is invalid")
		}
		if !boundedMetadata(lineage.SourceID) || !boundedMetadata(lineage.SnapshotID) || !boundedMetadata(lineage.AdmissionPolicyScopeID) || !boundedMetadata(lineage.FreshnessState) {
			return errors.New("authority lineage provenance identity is invalid")
		}
		if _, err := parseCanonicalUTC(lineage.AdmissionEvaluatedAt); err != nil {
			return errors.New("authority lineage admission evaluation time is invalid")
		}
		if _, err := parseCanonicalUTC(lineage.AdmissionFreshUntil); err != nil {
			return errors.New("authority lineage freshness bound is invalid")
		}
		if validateSourceAdmissionBinding(lineage.SourceAdmissionMethod, lineage.SourceAdmissionPolicyID, lineage.SourceAdmissionPolicySHA256) != nil {
			return errors.New("authority lineage source admission binding is invalid")
		}
	}
	return nil
}

// validateMultidomainAdmission re-admits a shared multidomain candidate at query
// time. It fails closed: the operator lineage set must pin exactly the candidate's
// authority set, and every authority's current admission policy must match both
// the candidate's frozen document hash and the lineage-set pin and still enforce
// the exact public-retrieval, deletion and freshness predicates the single path
// enforces. It returns the same (resultState, freshnessState, errorCode) shape as
// the hybrid recheck; errorCode == "" means admitted with the reported freshness
// derived from the MINIMUM per-authority freshness horizon.
func validateMultidomainAdmission(candidate CandidateManifest, lineageSetPath string, asOf time.Time) (string, string, string) {
	if strings.TrimSpace(lineageSetPath) == "" {
		return "forbidden", "", "lineage_set_required"
	}
	set, err := ParseLineageSet(lineageSetPath)
	if err != nil {
		return "backend_unavailable", "", "admission_policy_unavailable"
	}
	byAuthority := make(map[string]LineageConfig, len(set.Lineages))
	for _, cfg := range set.Lineages {
		if _, duplicate := byAuthority[cfg.AuthorityID]; duplicate {
			return "forbidden", "", "admission_policy_changed"
		}
		byAuthority[cfg.AuthorityID] = cfg
	}
	if len(byAuthority) != len(candidate.Lineages) {
		return "forbidden", "", "admission_policy_changed"
	}
	var minFreshUntil time.Time
	for position, lineage := range candidate.Lineages {
		cfg, present := byAuthority[lineage.AuthorityID]
		if !present {
			return "forbidden", "", "admission_policy_changed"
		}
		policyBytes, err := readStableFile(cfg.AdmissionPolicyPath, "admission policy", maxPolicyBytes)
		if err != nil {
			return "backend_unavailable", "", "admission_policy_unavailable"
		}
		documentDigest := digestBytes(policyBytes)
		if documentDigest != lineage.AdmissionPolicyDocumentSHA256 || documentDigest != cfg.AdmissionPolicyHash {
			return "forbidden", "", "admission_policy_document_mismatch"
		}
		var policy AdmissionPolicy
		if err := decodeStrictCanonical(policyBytes, &policy); err != nil || validatePolicyIdentity(policy) != nil {
			return "forbidden", "", "admission_policy_invalid"
		}
		if policy.AccessScope != "public" || !policy.RetrievalAllowed || policy.State != "active" {
			return "forbidden", "", "admission_policy_forbidden"
		}
		if policy.SourceState != "present" || policy.DeletionState != "active" || policy.Tombstone {
			return "forbidden", "", "source_deleted_or_tombstoned"
		}
		if policy.PolicyID != lineage.AdmissionPolicyID || policy.SnapshotManifestID != lineage.SnapshotManifestID || policy.EvidenceManifestID != lineage.EvidenceManifestID {
			return "forbidden", "", "admission_policy_changed"
		}
		evaluatedAt, _ := parseCanonicalUTC(policy.EvaluatedAt)
		if asOf.Before(evaluatedAt) {
			return "forbidden", "", "query_before_policy_evaluation"
		}
		freshUntil, _ := parseCanonicalUTC(policy.FreshUntil)
		if position == 0 || freshUntil.Before(minFreshUntil) {
			minFreshUntil = freshUntil
		}
	}
	if asOf.After(minFreshUntil) {
		return "", "stale", ""
	}
	return "", "fresh", ""
}

// evidenceRefBindsAdmittedLineage confirms one emitted result's evidence ref cites
// the admitted snapshot and evidence manifests. A single-authority artifact carries
// no lineages and binds the ref to the one candidate manifest pair, byte-identically
// to the historical check. A shared multidomain artifact binds the ref to the single
// authority lineage that shares its source identity, then requires that authority's
// exact snapshot and evidence manifests. A ref matching no lineage, or splicing one
// authority's source onto another authority's manifests, fails closed.
func evidenceRefBindsAdmittedLineage(ref EvidenceRef, snapshotManifestID, evidenceManifestID string, lineages []AuthorityLineageBinding) bool {
	if len(lineages) == 0 {
		return ref.SnapshotManifestID == snapshotManifestID && ref.EvidenceManifestID == evidenceManifestID
	}
	for _, lineage := range lineages {
		if ref.SourceID != lineage.SourceID || ref.ComponentID != lineage.ComponentID || ref.SnapshotID != lineage.SnapshotID {
			continue
		}
		return ref.SnapshotManifestID == lineage.SnapshotManifestID && ref.EvidenceManifestID == lineage.EvidenceManifestID
	}
	return false
}

func validateIndex(index LexicalIndex, candidate CandidateManifest) error {
	coreBytes, err := json.Marshal(index.LexicalIndexCore)
	if err != nil || index.IndexPayloadSHA256 != digestBytes(coreBytes) || index.IndexID != "lexical-index:"+index.IndexPayloadSHA256 || index.IndexID != candidate.LexicalIndexID {
		return errors.New("index identity mismatch")
	}
	if !index.Lexical || index.Dense || index.EvidenceManifestID != candidate.EvidenceManifestID || index.SnapshotManifestID != candidate.SnapshotManifestID || index.AdmissionPolicyID != candidate.AdmissionPolicyID || index.DocumentCount != len(index.Documents) || index.TermCount != len(index.Terms) {
		return errors.New("index contract mismatch")
	}
	multi := candidate.ManifestKind == lexicalMultidomainCandidate
	if multi {
		if !lineagesEqual(index.Lineages, candidate.Lineages) {
			return errors.New("multidomain index lineage mismatch")
		}
		perAuthority := 0
		for _, lineage := range index.Lineages {
			perAuthority += lineage.DocumentCount
		}
		if perAuthority != index.DocumentCount {
			return errors.New("multidomain lineage document counts do not sum to the index total")
		}
	} else if len(index.Lineages) != 0 {
		return errors.New("single-authority index must not carry lineages")
	}
	bm25fContract, bm25f := bm25fContractForProfile(candidateLexicalProfile(candidate))
	if bm25f {
		wantKind := bm25fIndexKind
		if multi {
			wantKind = bm25fMultidomainIndexKind
		}
		if index.SchemaVersion != bm25fIndexSchema || index.IndexKind != wantKind || index.LexicalProfile != bm25fContract.lexicalProfile || index.LexicalTokenizerID != bm25fContract.tokenizerID || index.LexicalScorerID != bm25fScorerID || candidate.LexicalProfile != index.LexicalProfile || candidate.LexicalTokenizerID != index.LexicalTokenizerID || candidate.LexicalScorerID != index.LexicalScorerID || index.TotalBodyLength < 0 || index.TotalHeadingLength < 0 {
			return errors.New("BM25F index profile contract mismatch")
		}
	} else {
		wantKind := "deterministic_lexical_inverted_index"
		if multi {
			wantKind = lexicalMultidomainIndexKind
		}
		if index.SchemaVersion != retrievalSchemaVersion || index.IndexKind != wantKind || index.LexicalProfile != "" || index.LexicalTokenizerID != "" || index.LexicalScorerID != "" || index.TotalBodyLength != 0 || index.TotalHeadingLength != 0 {
			return errors.New("legacy index profile contract mismatch")
		}
	}
	postingCount := 0
	totalBodyLength := int64(0)
	totalHeadingLength := int64(0)
	documents := make(map[string]EvidenceRef, len(index.Documents))
	spanDocuments := make(map[string]string, len(index.Documents))
	previousDocument := ""
	for i, document := range index.Documents {
		if i > 0 && document.DocumentID <= previousDocument {
			return errors.New("index document order invalid")
		}
		previousDocument = document.DocumentID
		refBytes, _ := json.Marshal(document.Evidence)
		if document.DocumentID != "lexical-document:"+digestBytes(refBytes) {
			return errors.New("index document identity invalid")
		}
		if _, exists := documents[document.DocumentID]; exists {
			return errors.New("index document identity duplicate")
		}
		if _, exists := spanDocuments[document.Evidence.SpanID]; exists {
			return errors.New("index document span duplicate")
		}
		documents[document.DocumentID] = document.Evidence
		spanDocuments[document.Evidence.SpanID] = document.DocumentID
		if bm25f {
			if document.BodyLength < 0 || document.HeadingLength < 0 {
				return errors.New("BM25F document length invalid")
			}
			var lengthErr error
			totalBodyLength, lengthErr = checkedAddInt64(totalBodyLength, int64(document.BodyLength))
			if lengthErr == nil {
				totalHeadingLength, lengthErr = checkedAddInt64(totalHeadingLength, int64(document.HeadingLength))
			}
			if lengthErr != nil {
				return errors.New("BM25F document length overflow")
			}
		} else if document.BodyLength != 0 || document.HeadingLength != 0 {
			return errors.New("legacy index carries BM25F document lengths")
		}
	}
	previousTerm := ""
	for i, term := range index.Terms {
		if i > 0 && term.Term <= previousTerm {
			return errors.New("index term order invalid")
		}
		previousTerm = term.Term
		if bm25f && term.DocumentFrequency != len(term.Postings) {
			return errors.New("BM25F document frequency invalid")
		}
		if !bm25f && term.DocumentFrequency != 0 {
			return errors.New("legacy index carries BM25F document frequency")
		}
		previousDocument := ""
		for j, posting := range term.Postings {
			if j > 0 && posting.DocumentID <= previousDocument {
				return errors.New("index posting invalid")
			}
			if bm25f {
				if posting.TermFrequency != 0 || posting.BodyTermFrequency < 0 || posting.HeadingTermFrequency < 0 || (posting.BodyTermFrequency == 0 && posting.HeadingTermFrequency == 0) || posting.DocumentPosition < 1 || posting.DocumentPosition > len(index.Documents) || index.Documents[posting.DocumentPosition-1].DocumentID != posting.DocumentID {
					return errors.New("BM25F posting invalid")
				}
				document := index.Documents[posting.DocumentPosition-1]
				if posting.BodyTermFrequency > document.BodyLength || posting.HeadingTermFrequency > document.HeadingLength {
					return errors.New("BM25F posting frequency exceeds its retained field length")
				}
			} else if posting.TermFrequency < 1 || posting.BodyTermFrequency != 0 || posting.HeadingTermFrequency != 0 || posting.DocumentPosition != 0 {
				return errors.New("legacy posting carries mixed profile fields")
			}
			if _, exists := documents[posting.DocumentID]; !exists {
				return errors.New("index posting does not point to its exact indexed document")
			}
			previousDocument = posting.DocumentID
			postingCount++
		}
	}
	if bm25f && (totalBodyLength != index.TotalBodyLength || totalHeadingLength != index.TotalHeadingLength) {
		return errors.New("BM25F field length aggregate mismatch")
	}
	if postingCount != index.PostingCount || postingCount != candidate.PostingCount || index.DocumentCount != candidate.DocumentCount || index.TermCount != candidate.TermCount {
		return errors.New("index aggregate mismatch")
	}
	return nil
}

func boundedUTF8(data []byte, limit int) (string, bool) {
	if len(data) <= limit {
		return string(data), false
	}
	end := limit
	for end > 0 && !utf8.Valid(data[:end]) {
		end--
	}
	return string(data[:end]), true
}
