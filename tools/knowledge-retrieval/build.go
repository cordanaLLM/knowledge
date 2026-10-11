package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	lexicalIndexKind            = "deterministic_lexical_inverted_index"
	lexicalMultidomainIndexKind = "deterministic_lexical_multidomain_inverted_index"
	bm25fMultidomainIndexKind   = "deterministic_bm25f_lexical_multidomain_inverted_index"
	lexicalCandidateKind        = "knowledge_retrieval_candidate"
	lexicalMultidomainCandidate = "knowledge_retrieval_multidomain_candidate"
)

// parsedLineage is one fully validated source authority ready for merge.
type parsedLineage struct {
	lineage           LineageConfig
	authorityID       string
	scopeID           string
	snapshot          SnapshotManifest
	evidence          EvidenceManifest
	policy            AdmissionPolicy
	snapshotDocSHA    string
	evidenceDocSHA    string
	rawRoot           string
	evidenceRoot      string
	freshnessState    string
	documentCount     int
	fineSpanExtension FineSpanExtensionInput
}

// indexAccumulator holds the shared inverted index while every authority's
// evidence is merged in. documentOwner/spanOwner bind each identity to exactly
// one authority so no document or span can span two lineages.
type indexAccumulator struct {
	documents          []IndexedDocument
	postingsByTerm     map[string][]Posting
	postingCount       int
	totalBodyLength    int64
	totalHeadingLength int64
	documentOwner      map[string]int
	spanOwner          map[string]int
}

func newIndexAccumulator() *indexAccumulator {
	return &indexAccumulator{
		postingsByTerm: make(map[string][]Posting),
		documentOwner:  make(map[string]int),
		spanOwner:      make(map[string]int),
	}
}

// resolveLineages selects the shared multi-authority path when Lineages is
// populated, otherwise synthesizes one legacy lineage from the flat fields so a
// single-authority build reproduces its historical singular artifact bytes.
func resolveLineages(config BuildConfig) ([]LineageConfig, bool) {
	if len(config.Lineages) > 0 {
		return config.Lineages, true
	}
	return []LineageConfig{{
		SnapshotManifestPath:  config.SnapshotManifestPath,
		EvidenceManifestPath:  config.EvidenceManifestPath,
		RawStoreRoot:          config.RawStoreRoot,
		EvidenceStoreRoot:     config.EvidenceStoreRoot,
		SpecPath:              config.SpecPath,
		ProposalPath:          config.ProposalPath,
		ReviewReceiptPath:     config.ReviewReceiptPath,
		ReviewSignaturePath:   config.ReviewSignaturePath,
		AllowedSignersPath:    config.AllowedSignersPath,
		AdmissionPolicyPath:   config.AdmissionPolicyPath,
		AdmissionPolicyHash:   config.AdmissionPolicyHash,
		AsOf:                  config.AsOf,
		FineSpanExtensionPath: config.FineSpanExtensionPath,
	}}, false
}

func Build(config BuildConfig) (BuildResult, error) {
	var zero BuildResult
	lineages, multi := resolveLineages(config)
	for name, value := range map[string]string{
		"store":                    config.OutputStoreRoot,
		"evidence-verifier":        config.EvidenceVerifierPath,
		"evidence-verifier-sha256": config.EvidenceVerifierHash,
	} {
		if strings.TrimSpace(value) == "" {
			return zero, fmt.Errorf("%s is required", name)
		}
	}
	if len(lineages) < 1 {
		return zero, errors.New("at least one source authority lineage is required")
	}
	limits, err := normalizeLimits(config)
	if err != nil {
		return zero, err
	}
	lexicalProfile, err := normalizeLexicalProfile(config.LexicalProfile)
	if err != nil {
		return zero, err
	}
	bm25fContract, bm25f := bm25fContractForProfile(lexicalProfile)

	storeRoot, storeErr := filepath.Abs(config.OutputStoreRoot)
	if storeErr != nil {
		return zero, errors.New("store path cannot be resolved")
	}
	if err := validateNoSymlinkExistingPrefix(storeRoot); err != nil {
		return zero, fmt.Errorf("store: %w", err)
	}

	for index, lineage := range lineages {
		if err := validateLineageInputs(lineage, multi); err != nil {
			return zero, fmt.Errorf("lineage %d: %w", index, err)
		}
		rawRoot, rawErr := filepath.Abs(lineage.RawStoreRoot)
		evidenceRoot, evidenceErr := filepath.Abs(lineage.EvidenceStoreRoot)
		if rawErr != nil || evidenceErr != nil {
			return zero, errors.New("store path cannot be resolved")
		}
		if err := validateNoSymlinkPath(rawRoot); err != nil {
			return zero, fmt.Errorf("raw-store: %w", err)
		}
		if err := validateNoSymlinkPath(evidenceRoot); err != nil {
			return zero, fmt.Errorf("evidence-store: %w", err)
		}
		if pathsOverlap(rawRoot, evidenceRoot) || pathsOverlap(rawRoot, storeRoot) || pathsOverlap(evidenceRoot, storeRoot) {
			return zero, errors.New("raw, evidence and retrieval stores must not overlap")
		}
	}

	parsed := make([]parsedLineage, 0, len(lineages))
	for _, lineage := range lineages {
		entry, err := loadLineage(config, lineage, multi, limits, storeRoot)
		if err != nil {
			return zero, err
		}
		parsed = append(parsed, entry)
	}

	if multi {
		if issues := validateSharedCorpusAuthorities(parsed); len(issues) != 0 {
			return zero, quarantine(storeRoot, parsed[0].evidenceDocSHA, parsed[0].evidence.ManifestID, issues)
		}
	}
	// Deterministic merge order: sort by authority id so two independent builds
	// consume the shared term/posting budget in an identical order.
	sort.SliceStable(parsed, func(i, j int) bool { return parsed[i].authorityID < parsed[j].authorityID })

	acc := newIndexAccumulator()
	for lineageIndex := range parsed {
		count, issues := indexLineageInto(acc, lineageIndex, parsed[lineageIndex], limits, lexicalProfile)
		if len(issues) != 0 {
			return zero, quarantine(storeRoot, parsed[lineageIndex].evidenceDocSHA, parsed[lineageIndex].evidence.ManifestID, issues)
		}
		parsed[lineageIndex].documentCount = count
	}
	documents, terms := finalizeMergedIndex(acc, bm25f)

	bindings := make([]AuthorityLineageBinding, 0, len(parsed))
	for _, entry := range parsed {
		bindings = append(bindings, lineageBinding(entry))
	}

	indexCore := LexicalIndexCore{
		SchemaVersion: retrievalSchemaVersion,
		IndexKind:     lexicalIndexKind,
		Lexical:       true,
		Dense:         false,
		DocumentCount: len(documents),
		TermCount:     len(terms),
		PostingCount:  acc.postingCount,
		Documents:     documents,
		Terms:         terms,
	}
	if multi {
		indexCore.IndexKind = lexicalMultidomainIndexKind
		indexCore.Lineages = bindings
	} else {
		indexCore.EvidenceManifestID = parsed[0].evidence.ManifestID
		indexCore.SnapshotManifestID = parsed[0].snapshot.ManifestID
		indexCore.AdmissionPolicyID = parsed[0].policy.PolicyID
		indexCore.FreshnessState = parsed[0].freshnessState
	}
	if bm25f {
		indexCore.SchemaVersion = bm25fIndexSchema
		indexCore.IndexKind = bm25fIndexKind
		if multi {
			indexCore.IndexKind = bm25fMultidomainIndexKind
		}
		indexCore.LexicalProfile = bm25fContract.lexicalProfile
		indexCore.LexicalTokenizerID = bm25fContract.tokenizerID
		indexCore.LexicalScorerID = bm25fScorerID
		indexCore.TotalBodyLength = acc.totalBodyLength
		indexCore.TotalHeadingLength = acc.totalHeadingLength
	}
	indexCoreBytes, _ := json.Marshal(indexCore)
	indexDigest := digestBytes(indexCoreBytes)
	index := LexicalIndex{IndexID: "lexical-index:" + indexDigest, IndexPayloadSHA256: indexDigest, LexicalIndexCore: indexCore}
	indexBytes, err := marshalDocument(index)
	if err != nil {
		return zero, err
	}
	if int64(len(indexBytes)) > maxIndexBytes {
		return zero, quarantine(storeRoot, parsed[0].evidenceDocSHA, parsed[0].evidence.ManifestID, []QuarantineIssue{
			issue("lexical_index_size_limit", "lexical-index", "serialized lexical index exceeds the fixed 512 MiB P0 dogfood bound"),
		})
	}
	hexIndex := strings.TrimPrefix(indexDigest, "sha256:")
	indexRelative := path.Join("indexes", "sha256", hexIndex[:2], hexIndex+".json")
	if err := writeImmutableObject(storeRoot, indexRelative, indexBytes); err != nil {
		return zero, fmt.Errorf("commit immutable lexical index: %w", err)
	}

	manifestCore := CandidateManifestCore{
		SchemaVersion:          retrievalSchemaVersion,
		ManifestKind:           lexicalCandidateKind,
		State:                  "partial",
		Promotable:             false,
		ServingEligible:        false,
		CurrentEligible:        false,
		Lexical:                true,
		Dense:                  false,
		EvidenceVerifierSHA256: config.EvidenceVerifierHash,
		LexicalIndexID:         index.IndexID,
		LexicalIndexSHA256:     digestBytes(indexBytes),
		LexicalIndexPath:       indexRelative,
		LexicalIndexByteSize:   int64(len(indexBytes)),
		DocumentCount:          len(documents),
		TermCount:              len(terms),
		PostingCount:           acc.postingCount,
		MissingCapabilities:    []string{"change_pack", "dense_retrieval", "fusion", "reranking", "serving_promotion"},
	}
	if multi {
		manifestCore.ManifestKind = lexicalMultidomainCandidate
		manifestCore.Lineages = bindings
	} else {
		manifestCore.FreshnessState = parsed[0].freshnessState
		manifestCore.EvaluatedAt = parsed[0].policy.EvaluatedAt
		manifestCore.FreshUntil = parsed[0].policy.FreshUntil
		manifestCore.SnapshotManifestID = parsed[0].snapshot.ManifestID
		manifestCore.EvidenceManifestID = parsed[0].evidence.ManifestID
		manifestCore.AdmissionPolicyID = parsed[0].policy.PolicyID
		manifestCore.AdmissionPolicySHA256 = parsed[0].lineage.AdmissionPolicyHash
		manifestCore.SourceAdmissionMethod = parsed[0].snapshot.ReviewAdmission.AdmissionMethod
		manifestCore.SourceAdmissionPolicyID = parsed[0].snapshot.ReviewAdmission.AdmissionPolicyID
		manifestCore.SourceAdmissionPolicySHA256 = parsed[0].snapshot.ReviewAdmission.AdmissionPolicySHA256
	}
	if bm25f {
		manifestCore.LexicalProfile = bm25fContract.lexicalProfile
		manifestCore.LexicalTokenizerID = bm25fContract.tokenizerID
		manifestCore.LexicalScorerID = bm25fScorerID
	}
	manifestCoreBytes, _ := json.Marshal(manifestCore)
	manifestDigest := digestBytes(manifestCoreBytes)
	manifest := CandidateManifest{ManifestID: "retrieval-candidate:" + manifestDigest, ManifestPayloadSHA256: manifestDigest, CandidateManifestCore: manifestCore}
	manifestBytes, err := marshalDocument(manifest)
	if err != nil {
		return zero, err
	}
	hexManifest := strings.TrimPrefix(manifestDigest, "sha256:")
	manifestRelative := path.Join("candidates", "sha256", hexManifest[:2], hexManifest+".json")
	manifestPath := filepath.Join(storeRoot, filepath.FromSlash(manifestRelative))
	if err := writeImmutableObject(storeRoot, manifestRelative, manifestBytes); err != nil {
		return zero, fmt.Errorf("commit immutable candidate manifest: %w", err)
	}
	return BuildResult{Manifest: manifest, ManifestPath: manifestPath}, nil
}

// validateLineageInputs enforces that every per-authority input is present. The
// declared authority id and admission-policy scope are required only on the
// shared multi-authority path; the legacy singular path carries neither.
func validateLineageInputs(lineage LineageConfig, multi bool) error {
	required := map[string]string{
		"snapshot-manifest":       lineage.SnapshotManifestPath,
		"evidence-manifest":       lineage.EvidenceManifestPath,
		"raw-store":               lineage.RawStoreRoot,
		"evidence-store":          lineage.EvidenceStoreRoot,
		"spec":                    lineage.SpecPath,
		"proposal":                lineage.ProposalPath,
		"review-receipt":          lineage.ReviewReceiptPath,
		"review-signature":        lineage.ReviewSignaturePath,
		"allowed-signers":         lineage.AllowedSignersPath,
		"admission-policy":        lineage.AdmissionPolicyPath,
		"admission-policy-sha256": lineage.AdmissionPolicyHash,
		"as-of":                   lineage.AsOf,
	}
	if multi {
		required["authority-id"] = lineage.AuthorityID
		required["admission-policy-scope-id"] = lineage.AdmissionPolicyScopeID
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}

// loadLineage reads, validates and independently reverifies one authority's
// admitted inputs. It is the single-authority body of the historical Build,
// scoped to one lineage so N=1 reproduces the exact legacy quarantine and
// artifact bytes.
func loadLineage(config BuildConfig, lineage LineageConfig, multi bool, limits buildLimits, storeRoot string) (parsedLineage, error) {
	var zero parsedLineage
	if _, err := parseCanonicalUTC(lineage.AsOf); err != nil {
		return zero, fmt.Errorf("as-of: %w", err)
	}
	rawRoot, _ := filepath.Abs(lineage.RawStoreRoot)
	evidenceRoot, _ := filepath.Abs(lineage.EvidenceStoreRoot)

	evidenceBytes, evidenceReadErr := readStableFile(lineage.EvidenceManifestPath, "evidence manifest", maxManifestBytes)
	inputDigest := digestBytes(evidenceBytes)
	var evidence EvidenceManifest
	issues := make([]QuarantineIssue, 0)
	if evidenceReadErr != nil {
		issues = append(issues, issue("evidence_manifest_read_failed", "evidence-manifest", "evidence manifest is not a bounded regular non-symlink file"))
	} else if err := decodeStrictCanonical(evidenceBytes, &evidence); err != nil {
		issues = append(issues, issue("evidence_manifest_invalid", "evidence-manifest", "evidence manifest is not strict canonical JSON"))
	}
	snapshotBytes, snapshotReadErr := readStableFile(lineage.SnapshotManifestPath, "snapshot manifest", maxManifestBytes)
	var snapshot SnapshotManifest
	if snapshotReadErr != nil {
		issues = append(issues, issue("snapshot_manifest_read_failed", "snapshot-manifest", "snapshot manifest is not a bounded regular non-symlink file"))
	} else if err := decodeStrictCanonical(snapshotBytes, &snapshot); err != nil {
		issues = append(issues, issue("snapshot_manifest_invalid", "snapshot-manifest", "snapshot manifest is not strict canonical JSON"))
	}
	policyBytes, policyReadErr := readStableFile(lineage.AdmissionPolicyPath, "admission policy", maxPolicyBytes)
	var policy AdmissionPolicy
	if policyReadErr != nil {
		issues = append(issues, issue("admission_policy_read_failed", "admission-policy", "admission policy is not a bounded regular non-symlink file"))
	} else if err := decodeStrictCanonical(policyBytes, &policy); err != nil {
		issues = append(issues, issue("admission_policy_invalid", "admission-policy", "admission policy is not strict canonical JSON"))
	}
	if policyReadErr == nil && digestBytes(policyBytes) != lineage.AdmissionPolicyHash {
		issues = append(issues, issue("admission_policy_document_mismatch", "admission-policy-sha256", "policy bytes do not match the operator-pinned whole-document SHA-256"))
	}
	reviewReceiptBytes, reviewReceiptReadErr := readStableFile(lineage.ReviewReceiptPath, "review receipt", maxPolicyBytes)
	var reviewReceipt SourceReviewReceipt
	if reviewReceiptReadErr != nil {
		issues = append(issues, issue("review_receipt_read_failed", "review-receipt", "review receipt is not a bounded regular non-symlink file"))
	} else if err := decodeStrictCanonical(reviewReceiptBytes, &reviewReceipt); err != nil {
		issues = append(issues, issue("review_receipt_invalid", "review-receipt", "review receipt is not strict canonical JSON"))
	}
	var fineSpanExtension FineSpanExtensionInput
	if strings.TrimSpace(lineage.FineSpanExtensionPath) != "" {
		parsedExtension, err := loadFineSpanExtension(lineage.FineSpanExtensionPath)
		if err != nil {
			issues = append(issues, issue("fine_span_extension_invalid", "fine-span-extension", err.Error()))
		} else {
			fineSpanExtension = parsedExtension
		}
	}
	if len(issues) == 0 {
		issues = append(issues, validateEvidenceAndSnapshotHeaders(evidence, snapshot, limits)...)
		issues = append(issues, validateAdmissionPolicy(policy, evidence, snapshot, lineage.AsOf)...)
		issues = append(issues, validateSourceReviewAdmission(snapshot.ReviewAdmission, reviewReceipt)...)
		if multi {
			issues = append(issues, validateAuthorityLabels(lineage, snapshot)...)
		}
	}
	if len(issues) == 0 {
		issues = append(issues, verifyEvidenceBoundary(lineageVerifierInputs(lineage), config.EvidenceVerifierPath, config.EvidenceVerifierHash, limits, evidenceBytes, evidence)...)
	}
	if len(issues) != 0 {
		return zero, quarantine(storeRoot, inputDigest, evidence.ManifestID, issues)
	}

	asOf, _ := parseCanonicalUTC(lineage.AsOf)
	freshUntil, _ := parseCanonicalUTC(policy.FreshUntil)
	freshnessState := "fresh"
	if asOf.After(freshUntil) {
		freshnessState = "stale"
	}
	return parsedLineage{
		lineage:           lineage,
		authorityID:       lineage.AuthorityID,
		scopeID:           lineage.AdmissionPolicyScopeID,
		snapshot:          snapshot,
		evidence:          evidence,
		policy:            policy,
		snapshotDocSHA:    digestBytes(snapshotBytes),
		evidenceDocSHA:    inputDigest,
		rawRoot:           rawRoot,
		evidenceRoot:      evidenceRoot,
		freshnessState:    freshnessState,
		fineSpanExtension: fineSpanExtension,
	}, nil
}

// validateAuthorityLabels binds the declared authority id and admission-policy
// scope to the lineage's own reviewed source version. A label whose version
// suffix does not match the snapshot's resolved version is a mixed lineage.
func validateAuthorityLabels(lineage LineageConfig, snapshot SnapshotManifest) []QuarantineIssue {
	var issues []QuarantineIssue
	version := snapshot.Source.ResolvedVersion
	if !labelBindsVersion(lineage.AuthorityID, version) || !labelBindsVersion(lineage.AdmissionPolicyScopeID, version) {
		issues = append(issues, issue("mixed_authority_lineage", "authority-id", "declared authority id or admission-policy scope does not bind the reviewed source version"))
	}
	return issues
}

func labelBindsVersion(label, version string) bool {
	if strings.TrimSpace(version) == "" {
		return false
	}
	idx := strings.LastIndex(label, ":")
	return idx >= 0 && label[idx+1:] == version
}

// validateSharedCorpusAuthorities enforces the three shared-corpus authority
// rules across the merged set: no two authorities may collapse to one source
// (singular_source_collapse_forbidden), alias one admission-policy scope
// (aliased_admission_policies_forbidden), or share a snapshot/evidence/policy
// artifact identity (mixed_lineage_forbidden).
func validateSharedCorpusAuthorities(parsed []parsedLineage) []QuarantineIssue {
	var issues []QuarantineIssue
	authority := map[string]bool{}
	source := map[string]bool{}
	scope := map[string]bool{}
	policy := map[string]bool{}
	artifact := map[string]bool{}
	for _, entry := range parsed {
		if authority[entry.authorityID] || source[entry.snapshot.Source.SourceID] || source[entry.snapshot.ManifestID] {
			issues = append(issues, issue("singular_source_collapse", "lineages", "two source authorities collapse to one source identity"))
		}
		authority[entry.authorityID] = true
		source[entry.snapshot.Source.SourceID] = true
		source[entry.snapshot.ManifestID] = true

		if scope[entry.scopeID] || policy[entry.policy.PolicyID] || policy[entry.lineage.AdmissionPolicyHash] {
			issues = append(issues, issue("aliased_admission_policy", "lineages", "two source authorities alias one admission-policy scope or identity"))
		}
		scope[entry.scopeID] = true
		policy[entry.policy.PolicyID] = true
		policy[entry.lineage.AdmissionPolicyHash] = true

		for _, id := range []string{entry.snapshot.ManifestID, entry.evidence.ManifestID, entry.policy.PolicyID} {
			if artifact[id] {
				issues = append(issues, issue("mixed_authority_lineage", "lineages", "one snapshot, evidence or admission artifact is claimed by more than one authority"))
			}
			artifact[id] = true
		}
	}
	return sortedIssues(issues)
}

// lineageSetLimits mirrors the optional resource ceilings a lineage-set file may
// pin. A zero value keeps the fixed defaults.
type lineageSetLimits struct {
	MaxFiles        int   `json:"max_files"`
	MaxSpans        int   `json:"max_spans"`
	MaxPayloadBytes int64 `json:"max_payload_bytes"`
	MaxTotalBytes   int64 `json:"max_total_bytes"`
	MaxTerms        int   `json:"max_terms"`
	MaxPostings     int   `json:"max_postings"`
}

type lineageSetLineage struct {
	AuthorityID            string `json:"authority_id"`
	AdmissionPolicyScopeID string `json:"admission_policy_scope_id"`
	SnapshotManifest       string `json:"snapshot_manifest"`
	EvidenceManifest       string `json:"evidence_manifest"`
	RawStore               string `json:"raw_store"`
	EvidenceStore          string `json:"evidence_store"`
	Spec                   string `json:"spec"`
	Proposal               string `json:"proposal"`
	ReviewReceipt          string `json:"review_receipt"`
	ReviewSignature        string `json:"review_signature"`
	AllowedSigners         string `json:"allowed_signers"`
	AdmissionPolicy        string `json:"admission_policy"`
	AdmissionPolicySHA256  string `json:"admission_policy_sha256"`
	AsOf                   string `json:"as_of"`
	FineSpanExtension      string `json:"fine_span_extension,omitempty"`
}

// lineageSet is the self-contained operator description of a shared
// multi-authority build: the shared output store, evidence verifier, lexical
// profile and limits, plus one entry per admitted source authority.
type lineageSet struct {
	OutputStore            string              `json:"output_store"`
	EvidenceVerifier       string              `json:"evidence_verifier"`
	EvidenceVerifierSHA256 string              `json:"evidence_verifier_sha256"`
	LexicalProfile         string              `json:"lexical_profile"`
	Limits                 lineageSetLimits    `json:"limits"`
	Lineages               []lineageSetLineage `json:"lineages"`
}

// ParseLineageSet turns a lineage-set file into a shared multi-authority
// BuildConfig. Only the shared fields and the ordered per-authority lineages are
// populated; the singular flat fields stay empty so Build selects the shared path.
func ParseLineageSet(path string) (BuildConfig, error) {
	var config BuildConfig
	data, err := readStableFile(path, "lineage set", maxPolicyBytes)
	if err != nil {
		return config, fmt.Errorf("lineage-set: %w", err)
	}
	var set lineageSet
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return config, fmt.Errorf("lineage-set: %w", err)
	}
	if len(set.Lineages) == 0 {
		return config, errors.New("lineage-set: at least one lineage is required")
	}
	config = BuildConfig{
		OutputStoreRoot:      set.OutputStore,
		EvidenceVerifierPath: set.EvidenceVerifier,
		EvidenceVerifierHash: set.EvidenceVerifierSHA256,
		LexicalProfile:       set.LexicalProfile,
		MaxFiles:             set.Limits.MaxFiles,
		MaxSpans:             set.Limits.MaxSpans,
		MaxPayloadBytes:      set.Limits.MaxPayloadBytes,
		MaxTotalBytes:        set.Limits.MaxTotalBytes,
		MaxTerms:             set.Limits.MaxTerms,
		MaxPostings:          set.Limits.MaxPostings,
	}
	for _, lineage := range set.Lineages {
		config.Lineages = append(config.Lineages, LineageConfig{
			AuthorityID:            lineage.AuthorityID,
			AdmissionPolicyScopeID: lineage.AdmissionPolicyScopeID,
			SnapshotManifestPath:   lineage.SnapshotManifest,
			EvidenceManifestPath:   lineage.EvidenceManifest,
			RawStoreRoot:           lineage.RawStore,
			EvidenceStoreRoot:      lineage.EvidenceStore,
			SpecPath:               lineage.Spec,
			ProposalPath:           lineage.Proposal,
			ReviewReceiptPath:      lineage.ReviewReceipt,
			ReviewSignaturePath:    lineage.ReviewSignature,
			AllowedSignersPath:     lineage.AllowedSigners,
			AdmissionPolicyPath:    lineage.AdmissionPolicy,
			AdmissionPolicyHash:    lineage.AdmissionPolicySHA256,
			AsOf:                   lineage.AsOf,
			FineSpanExtensionPath:  lineage.FineSpanExtension,
		})
	}
	return config, nil
}

func lineageBinding(entry parsedLineage) AuthorityLineageBinding {
	return AuthorityLineageBinding{
		AuthorityID:                    entry.authorityID,
		ComponentID:                    entry.snapshot.Source.ComponentID,
		ComponentVersion:               entry.snapshot.Source.ResolvedVersion,
		AdmissionPolicyScopeID:         entry.scopeID,
		SourceID:                       entry.snapshot.Source.SourceID,
		SnapshotID:                     entry.snapshot.SnapshotID,
		SnapshotManifestID:             entry.snapshot.ManifestID,
		SnapshotManifestDocumentSHA256: entry.snapshotDocSHA,
		EvidenceManifestID:             entry.evidence.ManifestID,
		EvidenceManifestDocumentSHA256: entry.evidenceDocSHA,
		AdmissionPolicyID:              entry.policy.PolicyID,
		AdmissionPolicyDocumentSHA256:  entry.lineage.AdmissionPolicyHash,
		SourceAdmissionMethod:          entry.snapshot.ReviewAdmission.AdmissionMethod,
		SourceAdmissionPolicyID:        entry.snapshot.ReviewAdmission.AdmissionPolicyID,
		SourceAdmissionPolicySHA256:    entry.snapshot.ReviewAdmission.AdmissionPolicySHA256,
		AdmissionEvaluatedAt:           entry.policy.EvaluatedAt,
		AdmissionFreshUntil:            entry.policy.FreshUntil,
		FreshnessState:                 entry.freshnessState,
		DocumentCount:                  entry.documentCount,
	}
}

func validateSourceReviewAdmission(admission ReviewAdmission, receipt SourceReviewReceipt) []QuarantineIssue {
	var issues []QuarantineIssue
	if err := validateSourceAdmissionBinding(admission.AdmissionMethod, admission.AdmissionPolicyID, admission.AdmissionPolicySHA256); err != nil {
		issues = append(issues, issue("review_admission_policy_invalid", "snapshot-manifest.review_admission", err.Error()))
	}
	if err := validateSourceAdmissionBinding(receipt.AdmissionMethod, receipt.AdmissionPolicyID, receipt.AdmissionPolicySHA256); err != nil {
		issues = append(issues, issue("review_receipt_admission_policy_invalid", "review-receipt", err.Error()))
	}
	if admission.AdmissionMethod != receipt.AdmissionMethod || admission.AdmissionPolicyID != receipt.AdmissionPolicyID || admission.AdmissionPolicySHA256 != receipt.AdmissionPolicySHA256 {
		issues = append(issues, issue("review_admission_policy_mismatch", "review-receipt", "snapshot and exact review receipt carry different source-admission provenance"))
	}
	return issues
}

func validateSourceAdmissionBinding(method, policyID, policySHA256 string) error {
	if method == "" && policyID == "" && policySHA256 == "" {
		return nil
	}
	if method != "standing_policy" {
		return errors.New("source admission must be omitted for legacy review or use standing_policy")
	}
	if !validSHA256(policySHA256) || policyID != "source-admission-policy:"+policySHA256 {
		return errors.New("standing source admission must bind one exact content-derived policy identity")
	}
	return nil
}

func validateEvidenceAndSnapshotHeaders(evidence EvidenceManifest, snapshot SnapshotManifest, limits buildLimits) []QuarantineIssue {
	var issues []QuarantineIssue
	if evidence.SchemaVersion != "1.0.0" || evidence.ManifestKind != "knowledge_evidence" || evidence.State != "complete" {
		issues = append(issues, issue("evidence_manifest_not_complete", "evidence-manifest", "only knowledge-evidence v1 complete manifests are accepted"))
	}
	if snapshot.SchemaVersion != "1.0.0" || snapshot.ManifestKind != "knowledge_snapshot" || snapshot.State != "complete" || snapshot.AuthorityState != "reviewed" {
		issues = append(issues, issue("snapshot_not_reviewed_complete", "snapshot-manifest", "only reviewed complete knowledge-snapshot v1 manifests are accepted"))
	}
	if evidence.InputManifestID != snapshot.ManifestID || evidence.InputManifestPayloadSHA256 != snapshot.ManifestPayloadSHA256 || evidence.InputSnapshotID != snapshot.SnapshotID {
		issues = append(issues, issue("evidence_snapshot_identity_mismatch", "evidence-manifest", "evidence input identity does not match the reviewed snapshot"))
	}
	if evidence.FileCount != snapshot.FileCount || evidence.RawByteSize != snapshot.ByteSize {
		issues = append(issues, issue("evidence_snapshot_aggregate_mismatch", "evidence-manifest", "evidence file and raw-byte totals do not match the reviewed snapshot"))
	}
	coreBytes, err := json.Marshal(evidence.EvidenceManifestCore)
	if err != nil || evidence.ManifestPayloadSHA256 != digestBytes(coreBytes) || evidence.ManifestID != "evidence-manifest:"+evidence.ManifestPayloadSHA256 {
		issues = append(issues, issue("evidence_manifest_identity_invalid", "evidence-manifest", "evidence manifest does not match its content-derived identity"))
	}
	if !reflect.DeepEqual(evidence.TrustEnvelope, expectedTrustEnvelope()) {
		issues = append(issues, issue("untrusted_envelope_invalid", "trust-envelope", "evidence does not carry the exact inert untrusted-source envelope"))
	}
	if evidence.ObjectLayout != "normalized/sha256/<first-two>/<hex>" {
		issues = append(issues, issue("evidence_layout_unsupported", "object_layout", "evidence normalized object layout is unsupported"))
	}
	if evidence.FileCount < 1 || evidence.FileCount != len(evidence.Files) || evidence.FileCount > limits.maxFiles {
		issues = append(issues, issue("evidence_file_count_invalid", "files", "evidence file count is empty, inconsistent or exceeds its bound"))
	}
	if evidence.SpanCount < 1 || evidence.SpanCount > limits.maxSpans {
		issues = append(issues, issue("evidence_span_count_invalid", "spans", "evidence span count is empty or exceeds its bound"))
	}
	if evidence.LogicalOutputByteSize < 0 || evidence.LogicalOutputByteSize > limits.maxTotalBytes {
		issues = append(issues, issue("evidence_size_limit", "logical_output_byte_size", "evidence logical output exceeds its bound"))
	}
	if snapshot.Source.AccessScope != "public" || snapshot.Source.Classification != "public" || snapshot.Source.SecurityDomain != "public" || snapshot.Source.Rights.Permissions["retrieval"] != "true" {
		issues = append(issues, issue("snapshot_not_public_retrievable", "source", "P0 lexical candidate accepts only explicit public retrieval-authorized source evidence"))
	}
	if strings.TrimSpace(snapshot.Source.CanonicalURI) == "" || strings.TrimSpace(snapshot.Source.FetchedAt) == "" || strings.TrimSpace(snapshot.Source.ObservedAt) == "" {
		issues = append(issues, issue("snapshot_source_lineage_incomplete", "source", "canonical source URI and fetched/observed times are required"))
	}
	if _, err := parseCanonicalUTC(snapshot.Source.FetchedAt); err != nil {
		issues = append(issues, issue("snapshot_fetched_time_invalid", "source.fetched_at", "source fetched time must be canonical RFC3339 UTC"))
	}
	if _, err := parseCanonicalUTC(snapshot.Source.ObservedAt); err != nil {
		issues = append(issues, issue("snapshot_observed_time_invalid", "source.observed_at", "source observed time must be canonical RFC3339 UTC"))
	}
	return issues
}

func validateAdmissionPolicy(policy AdmissionPolicy, evidence EvidenceManifest, snapshot SnapshotManifest, asOf string) []QuarantineIssue {
	var issues []QuarantineIssue
	coreBytes, err := json.Marshal(policy.AdmissionPolicyCore)
	if err != nil || policy.PolicyPayloadSHA256 != digestBytes(coreBytes) || policy.PolicyID != "retrieval-admission:"+policy.PolicyPayloadSHA256 {
		issues = append(issues, issue("admission_policy_identity_invalid", "admission-policy", "policy does not match its content-derived identity"))
	}
	if policy.SchemaVersion != retrievalSchemaVersion || policy.PolicyKind != "public_retrieval_admission" || policy.State != "active" {
		issues = append(issues, issue("admission_policy_inactive", "admission-policy", "only an active public retrieval admission v1 policy is accepted"))
	}
	if policy.SnapshotManifestID != snapshot.ManifestID || policy.EvidenceManifestID != evidence.ManifestID || policy.SnapshotID != snapshot.SnapshotID || policy.SourceID != snapshot.Source.SourceID || policy.ComponentID != snapshot.Source.ComponentID || policy.ComponentVersionID != snapshot.Source.ComponentVersionID {
		issues = append(issues, issue("admission_policy_lineage_mismatch", "admission-policy", "policy does not bind the exact source, snapshot, evidence, component and version identities"))
	}
	if policy.AccessScope != "public" || !policy.RetrievalAllowed {
		issues = append(issues, issue("admission_policy_forbidden", "access_scope", "policy must explicitly authorize public retrieval"))
	}
	if policy.SourceState != "present" {
		issues = append(issues, issue("admission_source_empty", "source_state", "empty or unavailable source state cannot enter the lexical candidate"))
	}
	if policy.DeletionState != "active" {
		issues = append(issues, issue("admission_source_deleted", "deletion_state", "deleted, revoked or pending-purge evidence cannot enter the lexical candidate"))
	}
	if policy.Tombstone {
		issues = append(issues, issue("admission_source_tombstoned", "tombstone", "a tombstoned source cannot enter the lexical candidate"))
	}
	if _, err := parseCanonicalUTC(policy.EvaluatedAt); err != nil || policy.EvaluatedAt != asOf {
		issues = append(issues, issue("admission_time_invalid", "evaluated_at", "policy evaluated_at must equal the explicit canonical build as-of time"))
	}
	if _, err := parseCanonicalUTC(policy.FreshUntil); err != nil {
		issues = append(issues, issue("admission_freshness_invalid", "fresh_until", "policy fresh_until must be canonical RFC3339 UTC"))
	}
	return issues
}

// indexLineageInto verifies and merges one authority's evidence into the shared
// accumulator, returning the number of documents this authority contributed. The
// shared documents, postings, term/posting budget and BM25F length aggregates
// live on acc; span, byte and unique-payload aggregates are checked per
// authority. documentOwner/spanOwner reject any identity claimed by two
// authorities so a document or span belongs to exactly one lineage. For a single
// authority this reproduces the historical single-triple index byte-for-byte.
func indexLineageInto(acc *indexAccumulator, lineageIndex int, entry parsedLineage, limits buildLimits, lexicalProfile string) (int, []QuarantineIssue) {
	var issues []QuarantineIssue
	snapshot, evidence, policy := entry.snapshot, entry.evidence, entry.policy
	rawRoot, evidenceRoot := entry.rawRoot, entry.evidenceRoot
	bm25fContract, bm25f := bm25fContractForProfile(lexicalProfile)
	snapshotFiles := make(map[string]SnapshotFile, len(snapshot.Files))
	for _, file := range snapshot.Files {
		snapshotFiles[file.RelativePath] = file
	}
	startDoc := len(acc.documents)
	uniquePayloads := make(map[string]int64)
	spanCount := 0
	logicalBytes := int64(0)
	rawBytes := int64(0)
	previousPath := ""
	for fileIndex, file := range evidence.Files {
		if fileIndex > 0 && file.RelativePath <= previousPath {
			issues = append(issues, issue("evidence_file_order_invalid", file.RelativePath, "evidence files must be in strict lexical order"))
		}
		previousPath = file.RelativePath
		snapshotFile, found := snapshotFiles[file.RelativePath]
		if !found {
			issues = append(issues, issue("evidence_occurrence_missing_snapshot", file.RelativePath, "evidence occurrence has no reviewed snapshot file"))
			continue
		}
		if file.OccurrenceID != occurrenceIdentity(snapshot.ManifestID, snapshotFile) || file.RawSHA256 != snapshotFile.SHA256 || file.RawBlobID != snapshotFile.RawBlobID || file.RawObjectPath != snapshotFile.ObjectPath || file.RawByteSize != snapshotFile.Size || file.SnapshotID != snapshot.SnapshotID || file.SourceID != snapshot.Source.SourceID || file.ComponentID != snapshot.Source.ComponentID || file.ComponentVersionID != snapshot.Source.ComponentVersionID || file.ChannelID != snapshot.Source.ChannelID {
			issues = append(issues, issue("evidence_occurrence_lineage_invalid", file.RelativePath, "evidence occurrence does not match exact snapshot lineage"))
			continue
		}
		if file.TrustEnvelopeID != evidence.TrustEnvelope.EnvelopeID {
			issues = append(issues, issue("evidence_occurrence_trust_invalid", file.RelativePath, "evidence occurrence lost the untrusted-source envelope"))
			continue
		}
		if snapshotFile.ObjectPath != rawObjectRelativePath(snapshotFile.SHA256) || validateRelativePath(snapshotFile.ObjectPath) != nil {
			issues = append(issues, issue("raw_object_path_invalid", file.RelativePath, "raw object path does not match its content identity"))
			continue
		}
		rawPath := filepath.Join(rawRoot, filepath.FromSlash(snapshotFile.ObjectPath))
		if !isWithin(rawRoot, rawPath) {
			issues = append(issues, issue("raw_object_path_escape", file.RelativePath, "raw object escaped its store"))
			continue
		}
		raw, err := verifyFileDigest(rawPath, snapshotFile.SHA256, snapshotFile.Size)
		if err != nil {
			issues = append(issues, issue("raw_object_invalid", file.RelativePath, "raw object no longer matches the reviewed snapshot"))
			continue
		}
		rawBytes += int64(len(raw))
		previousEnd := int64(0)
		for spanIndex, span := range file.Spans {
			spanCount++
			if spanCount > limits.maxSpans {
				issues = append(issues, issue("span_count_limit", file.RelativePath, "evidence spans exceed the configured bound"))
				break
			}
			if span.Ordinal != spanIndex || span.RawByteStart != previousEnd || span.RawByteEnd < span.RawByteStart || span.RawByteEnd > int64(len(raw)) || span.ByteSize != span.RawByteEnd-span.RawByteStart {
				issues = append(issues, issue("span_coordinates_invalid", span.SpanID, "span coordinates do not form an exact ordered raw-byte partition"))
				continue
			}
			previousEnd = span.RawByteEnd
			startLine, endLine := spanLines(raw, int(span.RawByteStart), int(span.RawByteEnd))
			if span.RawLineStart != startLine || span.RawLineEnd != endLine {
				issues = append(issues, issue("span_line_coordinates_invalid", span.SpanID, "span line coordinates do not match exact raw bytes"))
				continue
			}
			if span.TrustEnvelopeID != evidence.TrustEnvelope.EnvelopeID || span.SpanID != spanIdentity(file.OccurrenceID, file.ParserVersion, file.ProfileVersion, span) {
				issues = append(issues, issue("span_identity_invalid", span.SpanID, "span identity or trust lineage is inconsistent"))
				continue
			}
			if span.PayloadID != "normalized:"+span.PayloadSHA256 || span.ObjectPath != normalizedObjectRelativePath(span.PayloadSHA256) || validateRelativePath(span.ObjectPath) != nil || span.ByteSize > limits.maxPayloadBytes {
				issues = append(issues, issue("payload_identity_invalid", span.SpanID, "normalized payload identity, path or size is invalid"))
				continue
			}
			payloadPath := filepath.Join(evidenceRoot, filepath.FromSlash(span.ObjectPath))
			if !isWithin(evidenceRoot, payloadPath) {
				issues = append(issues, issue("payload_path_escape", span.SpanID, "normalized payload escaped its store"))
				continue
			}
			payload, err := verifyFileDigest(payloadPath, span.PayloadSHA256, span.ByteSize)
			if err != nil || !bytes.Equal(payload, raw[span.RawByteStart:span.RawByteEnd]) {
				issues = append(issues, issue("payload_raw_mismatch", span.SpanID, "normalized payload is not the exact declared raw-byte span"))
				continue
			}
			logicalBytes += span.ByteSize
			if logicalBytes > limits.maxTotalBytes {
				issues = append(issues, issue("logical_output_limit", span.SpanID, "logical normalized bytes exceed the configured bound"))
				break
			}
			if prior, exists := uniquePayloads[span.PayloadSHA256]; exists && prior != span.ByteSize {
				issues = append(issues, issue("payload_identity_collision", span.SpanID, "one normalized digest has inconsistent sizes"))
				continue
			}
			uniquePayloads[span.PayloadSHA256] = span.ByteSize
			ref := evidenceReference(snapshot, evidence, policy, file, span)
			docIssues := mergeDocumentIntoIndex(acc, lineageIndex, ref, span.HeadingBreadcrumb, payload, limits, bm25fContract, bm25f)
			if len(docIssues) != 0 {
				issues = append(issues, docIssues...)
				continue
			}
		}
		if previousEnd != int64(len(raw)) {
			issues = append(issues, issue("span_partition_invalid", file.RelativePath, "evidence spans do not cover the exact raw object"))
		}
	}
	if spanCount != evidence.SpanCount || len(acc.documents)-startDoc != evidence.SpanCount || logicalBytes != evidence.LogicalOutputByteSize || rawBytes != evidence.RawByteSize || len(uniquePayloads) != evidence.UniquePayloadCount {
		issues = append(issues, issue("evidence_aggregate_mismatch", "evidence-manifest", "verified span, document, logical-byte or unique-payload totals do not match the evidence manifest"))
	}
	var uniqueBytes int64
	for _, size := range uniquePayloads {
		uniqueBytes += size
	}
	if uniqueBytes != evidence.UniquePayloadByteSize {
		issues = append(issues, issue("evidence_unique_size_mismatch", "evidence-manifest", "verified unique payload bytes do not match the evidence manifest"))
	}
	if len(issues) != 0 {
		return 0, sortedIssues(issues)
	}
	// Small-to-big fine-span extension documents are additive to the exact
	// admitted coarse partition above, verified only after that partition is
	// fully clean, and never counted against the evidence manifest's own
	// span/byte aggregates (they are not part of evidence.Files).
	if len(entry.fineSpanExtension.Documents) != 0 {
		extIssues := processFineSpanExtensions(acc, lineageIndex, entry, limits, bm25fContract, bm25f)
		if len(extIssues) != 0 {
			return 0, sortedIssues(extIssues)
		}
	}
	return len(acc.documents) - startDoc, nil
}

// mergeDocumentIntoIndex appends one document's Evidence-derived record into
// the shared accumulator and indexes its lexical/BM25F terms. Shared by the
// primary per-file coarse-span loop and the small-to-big fine-span extension
// path so both merge identically.
func mergeDocumentIntoIndex(acc *indexAccumulator, lineageIndex int, ref EvidenceRef, headingBreadcrumb []string, payload []byte, limits buildLimits, bm25fContract bm25fProfileContract, bm25f bool) []QuarantineIssue {
	var issues []QuarantineIssue
	refBytes, _ := json.Marshal(ref)
	document := IndexedDocument{DocumentID: "lexical-document:" + digestBytes(refBytes), Evidence: ref}
	if owner, seen := acc.documentOwner[document.DocumentID]; seen && owner != lineageIndex {
		return append(issues, issue("cross_authority_document_alias", ref.SpanID, "one lexical document identity is claimed by more than one source authority"))
	}
	if owner, seen := acc.spanOwner[ref.SpanID]; seen && owner != lineageIndex {
		return append(issues, issue("cross_authority_span_alias", ref.SpanID, "one evidence span is claimed by more than one source authority"))
	}
	acc.documentOwner[document.DocumentID] = lineageIndex
	acc.spanOwner[ref.SpanID] = lineageIndex
	acc.documents = append(acc.documents, document)
	bodyFrequencies := map[string]int(nil)
	headingFrequencies := map[string]int(nil)
	if bm25f {
		body, tokenIssue := scanBM25FTerms(payload, bm25fContract, 0, limits.maxPostings-acc.postingCount, acc.postingsByTerm, nil, limits.maxTerms-len(acc.postingsByTerm))
		if tokenIssue != nil {
			return append(issues, *tokenIssue)
		}
		headingBytes := []byte(strings.Join(headingBreadcrumb, " "))
		heading, tokenIssue := scanBM25FTerms(headingBytes, bm25fContract, 0, limits.maxPostings-acc.postingCount-len(body.terms), acc.postingsByTerm, body.terms, limits.maxTerms-len(acc.postingsByTerm)-countNewTerms(body.terms, acc.postingsByTerm))
		if tokenIssue != nil {
			return append(issues, *tokenIssue)
		}
		bodyFrequencies = body.terms
		headingFrequencies = heading.terms
		document.BodyLength = body.baseCount
		document.HeadingLength = heading.baseCount
		var lengthErr error
		acc.totalBodyLength, lengthErr = checkedAddInt64(acc.totalBodyLength, int64(body.baseCount))
		if lengthErr == nil {
			acc.totalHeadingLength, lengthErr = checkedAddInt64(acc.totalHeadingLength, int64(heading.baseCount))
		}
		if lengthErr != nil {
			return append(issues, issue("document_length_overflow", ref.SpanID, "BM25F document length aggregate overflowed"))
		}
		acc.documents[len(acc.documents)-1] = document
	} else {
		frequencies, tokenIssue := lexicalFrequencies(
			payload,
			acc.postingsByTerm,
			limits.maxTerms-len(acc.postingsByTerm),
			limits.maxPostings-acc.postingCount,
		)
		if tokenIssue != nil {
			return append(issues, *tokenIssue)
		}
		bodyFrequencies = frequencies
	}
	allTerms := make(map[string]struct{}, len(bodyFrequencies)+len(headingFrequencies))
	for term := range bodyFrequencies {
		allTerms[term] = struct{}{}
	}
	for term := range headingFrequencies {
		allTerms[term] = struct{}{}
	}
	termNames := make([]string, 0, len(allTerms))
	for term := range allTerms {
		termNames = append(termNames, term)
	}
	sort.Strings(termNames)
	for _, term := range termNames {
		if _, exists := acc.postingsByTerm[term]; !exists && len(acc.postingsByTerm) >= limits.maxTerms {
			issues = append(issues, issue("term_count_limit", ref.SpanID, "unique lexical terms exceed the configured bound"))
			break
		}
		if acc.postingCount >= limits.maxPostings {
			issues = append(issues, issue("posting_count_limit", ref.SpanID, "lexical postings exceed the configured bound"))
			break
		}
		posting := Posting{DocumentID: document.DocumentID}
		if bm25f {
			posting.BodyTermFrequency = bodyFrequencies[term]
			posting.HeadingTermFrequency = headingFrequencies[term]
		} else {
			posting.TermFrequency = bodyFrequencies[term]
		}
		acc.postingsByTerm[term] = append(acc.postingsByTerm[term], posting)
		acc.postingCount++
	}
	return issues
}

// finalizeMergedIndex applies the single deterministic ordering over the whole
// merged corpus: documents by identity, terms lexically and postings by document
// identity, with BM25F document positions and document frequencies assigned last.
// For a single authority this is the historical single-triple finalization.
func finalizeMergedIndex(acc *indexAccumulator, bm25f bool) ([]IndexedDocument, []TermEntry) {
	documents := acc.documents
	sort.Slice(documents, func(i, j int) bool { return documents[i].DocumentID < documents[j].DocumentID })
	documentPositions := make(map[string]int, len(documents))
	if bm25f {
		for position, document := range documents {
			documentPositions[document.DocumentID] = position + 1
		}
	}
	termNames := make([]string, 0, len(acc.postingsByTerm))
	for term := range acc.postingsByTerm {
		termNames = append(termNames, term)
	}
	sort.Strings(termNames)
	terms := make([]TermEntry, 0, len(termNames))
	for _, term := range termNames {
		postings := acc.postingsByTerm[term]
		sort.Slice(postings, func(i, j int) bool { return postings[i].DocumentID < postings[j].DocumentID })
		if bm25f {
			for position := range postings {
				postings[position].DocumentPosition = documentPositions[postings[position].DocumentID]
			}
		}
		entry := TermEntry{Term: term, Postings: postings}
		if bm25f {
			entry.DocumentFrequency = len(postings)
		}
		terms = append(terms, entry)
	}
	return documents, terms
}

func evidenceReference(snapshot SnapshotManifest, evidence EvidenceManifest, policy AdmissionPolicy, file EvidenceFile, span EvidenceSpan) EvidenceRef {
	return EvidenceRef{
		SpanID: span.SpanID, OccurrenceID: file.OccurrenceID, SourceID: file.SourceID,
		ComponentID: file.ComponentID, ComponentVersionID: file.ComponentVersionID, ChannelID: file.ChannelID,
		CanonicalSourceURI: snapshot.Source.CanonicalURI, CanonicalSnapshotURI: canonicalSnapshotURI(snapshot.ManifestID),
		SnapshotManifestID: snapshot.ManifestID, EvidenceManifestID: evidence.ManifestID, SnapshotID: snapshot.SnapshotID,
		RelativePath: file.RelativePath, HeadingBreadcrumb: append([]string(nil), span.HeadingBreadcrumb...), RawSHA256: file.RawSHA256,
		PayloadSHA256: span.PayloadSHA256, PayloadObjectPath: span.ObjectPath, PayloadByteSize: span.ByteSize,
		RawByteStart: span.RawByteStart, RawByteEnd: span.RawByteEnd, RawLineStart: span.RawLineStart, RawLineEnd: span.RawLineEnd,
		FetchedAt: snapshot.Source.FetchedAt, ObservedAt: snapshot.Source.ObservedAt, AccessScope: policy.AccessScope,
		FreshUntil: policy.FreshUntil, TrustEnvelopeID: evidence.TrustEnvelope.EnvelopeID,
		ContentClass: evidence.TrustEnvelope.ContentClass, InstructionPolicy: evidence.TrustEnvelope.InstructionPolicy,
		ExecutionPolicy: evidence.TrustEnvelope.ExecutionPolicy, ToolPolicy: evidence.TrustEnvelope.ToolPolicy,
		InterpretationPolicy: evidence.TrustEnvelope.InterpretationPolicy,
	}
}

func countNewTerms(terms map[string]int, known map[string][]Posting) int {
	count := 0
	for term := range terms {
		if _, exists := known[term]; !exists {
			count++
		}
	}
	return count
}

const maxLexicalTokenBytes = 128

// lexicalFrequencies enforces token, new-term and per-document posting bounds
// while scanning. Callers must pass the remaining global budgets; validating
// them only after this function returns would allow a hostile payload to build
// an unbounded token or unique-term map first.
func lexicalFrequencies(data []byte, knownTerms map[string][]Posting, maxNewTerms, maxUniqueTerms int) (map[string]int, *QuarantineIssue) {
	frequencies := make(map[string]int)
	token := make([]byte, 0, maxLexicalTokenBytes)
	discardToken := false
	newTerms := 0
	flush := func() *QuarantineIssue {
		if discardToken {
			token = token[:0]
			discardToken = false
			return nil
		}
		if len(token) == 0 {
			return nil
		}
		value := strings.ToLower(string(token))
		token = token[:0]
		if count, exists := frequencies[value]; exists {
			frequencies[value] = count + 1
			return nil
		}
		if len(frequencies) >= maxUniqueTerms {
			problem := issue("posting_count_limit", "payload", "lexical postings exceed the configured bound")
			return &problem
		}
		if _, exists := knownTerms[value]; !exists {
			if newTerms >= maxNewTerms {
				problem := issue("term_count_limit", "payload", "unique lexical terms exceed the configured bound")
				return &problem
			}
			newTerms++
		}
		frequencies[value] = 1
		return nil
	}
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			problem := issue("lexical_payload_invalid_utf8", "payload", "lexical payload is not valid UTF-8")
			return nil, &problem
		}
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			if !discardToken && len(token)+size > maxLexicalTokenBytes {
				// Hashes, signatures, generated identifiers and adversarial
				// megabyte words are not useful lexical terms. Discard the
				// complete token without truncating it (which could create a
				// false searchable prefix) and without growing memory.
				token = token[:0]
				discardToken = true
			} else if !discardToken {
				token = append(token, data[:size]...)
			}
		} else if problem := flush(); problem != nil {
			return nil, problem
		}
		data = data[size:]
	}
	if problem := flush(); problem != nil {
		return nil, problem
	}
	return frequencies, nil
}
