package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	multidomainBindingClosureKind       = "retrieval_multidomain_binding_closure"
	multidomainBindingClosureInputKind  = "retrieval_multidomain_binding_closure_admitted_artifacts"
	maxMultidomainAdmittedInputBytes    = int64(1024 * 1024)
	maxMultidomainAdmittedArtifactBytes = int64(16 * 1024 * 1024)

	closureKindSnapshotManifest = "snapshot_manifest"
	closureKindEvidenceManifest = "evidence_manifest"
	closureKindAdmissionPolicy  = "admission_policy"

	closureSnapshotIDPrefix  = "snapshot-manifest:"
	closureEvidenceIDPrefix  = "evidence-manifest:"
	closureAdmissionIDPrefix = "retrieval-admission:"

	multidomainBindingClosureSharedInputKind = "retrieval_multidomain_binding_closure_shared_corpus_artifacts"
	maxMultidomainSharedArtifactBytes        = int64(64 * 1024 * 1024)

	closureKindLexicalCandidate          = "lexical_candidate"
	closureKindLexicalIndex              = "lexical_index"
	closureKindDenseArtifact             = "dense_artifact"
	closureKindHybridBaselineCandidate   = "hybrid_baseline_candidate"
	closureKindHybridChallengerCandidate = "hybrid_challenger_candidate"
	closureKindFusionProfile             = "fusion_profile"
	closureKindScorerArtifact            = "scorer_artifact"

	closureLexicalCandidateIDPrefix = "retrieval-candidate:"
	closureLexicalIndexIDPrefix     = "lexical-index:"
	closureDenseArtifactIDPrefix    = "dense-vector-artifact:"
	closureHybridCandidateIDPrefix  = "hybrid-retrieval-candidate:"
	closureFusionProfileIDPrefix    = "fusion-profile:"
	closureQuerySignalIDPrefix      = "query-signal-artifact:"
)

// MultidomainBindingClosureQuerySignalArtifact binds one frozen case/profile-role
// pair to its committed query-signal artifact reference.
type MultidomainBindingClosureQuerySignalArtifact struct {
	CaseID      string                                    `json:"case_id"`
	ProfileRole string                                    `json:"profile_role"`
	Artifact    MultidomainBindingClosureAdmittedArtifact `json:"artifact"`
}

// MultidomainBindingClosureSharedCorpusArtifacts is the strict-canonical input
// binding the five shared-corpus, two comparison and every evaluation-case
// artifact the frozen requirements manifest gapped. It is optional: an absent
// or structurally invalid input leaves every one of those 29 gaps blocking,
// exactly as before this extension existed.
type MultidomainBindingClosureSharedCorpusArtifacts struct {
	SchemaVersion             string                                         `json:"schema_version"`
	InputKind                 string                                         `json:"input_kind"`
	RequirementsManifestID    string                                         `json:"requirements_manifest_id"`
	LexicalCandidate          MultidomainBindingClosureAdmittedArtifact      `json:"lexical_candidate"`
	LexicalIndex              MultidomainBindingClosureAdmittedArtifact      `json:"lexical_index"`
	DenseArtifact             MultidomainBindingClosureAdmittedArtifact      `json:"dense_artifact"`
	HybridBaselineCandidate   MultidomainBindingClosureAdmittedArtifact      `json:"hybrid_baseline_candidate"`
	HybridChallengerCandidate MultidomainBindingClosureAdmittedArtifact      `json:"hybrid_challenger_candidate"`
	FusionProfile             MultidomainBindingClosureAdmittedArtifact      `json:"fusion_profile"`
	ScorerArtifactSHA256      string                                         `json:"scorer_artifact_sha256"`
	QuerySignals              []MultidomainBindingClosureQuerySignalArtifact `json:"query_signals"`
}

// MultidomainBindingClosureAdmittedArtifact is one committed authority-local
// artifact reference: its typed identity, the pinned whole-document SHA-256 of
// the retained bytes, and the path (relative to the admitted-artifacts file's
// own directory) of those bytes.
type MultidomainBindingClosureAdmittedArtifact struct {
	ArtifactID     string `json:"artifact_id"`
	DocumentSHA256 string `json:"document_sha256"`
	Path           string `json:"path"`
}

// MultidomainBindingClosureAdmittedAuthority binds one source authority to its
// three admitted authority-local artifacts (snapshot, evidence, admission).
type MultidomainBindingClosureAdmittedAuthority struct {
	AuthorityID            string                                    `json:"authority_id"`
	AdmissionPolicyScopeID string                                    `json:"admission_policy_scope_id"`
	ComponentID            string                                    `json:"component_id"`
	ComponentVersion       string                                    `json:"component_version"`
	SnapshotManifest       MultidomainBindingClosureAdmittedArtifact `json:"snapshot_manifest"`
	EvidenceManifest       MultidomainBindingClosureAdmittedArtifact `json:"evidence_manifest"`
	AdmissionPolicy        MultidomainBindingClosureAdmittedArtifact `json:"admission_policy"`
}

// MultidomainBindingClosureAdmittedArtifacts is the strict-canonical closure
// input: the frozen requirements identity plus the per-authority artifacts.
type MultidomainBindingClosureAdmittedArtifacts struct {
	SchemaVersion          string                                       `json:"schema_version"`
	InputKind              string                                       `json:"input_kind"`
	RequirementsManifestID string                                       `json:"requirements_manifest_id"`
	Authorities            []MultidomainBindingClosureAdmittedAuthority `json:"authorities"`
}

// MultidomainBindingClosureCapabilities keeps every runtime/release axis false;
// a closure that flips authority-local gaps still authorizes nothing.
type MultidomainBindingClosureCapabilities struct {
	ArtifactBytesVerified  bool `json:"artifact_bytes_verified"`
	RetrievalAuthorized    bool `json:"retrieval_authorized"`
	EvaluationAuthorized   bool `json:"evaluation_authorized"`
	SigningAuthorized      bool `json:"signing_authorized"`
	GenerationAuthorized   bool `json:"generation_authorized"`
	PointerWriteAuthorized bool `json:"pointer_write_authorized"`
	ServingAuthorized      bool `json:"serving_authorized"`
}

// MultidomainAdmittedAuthorityBinding is the verified per-authority record
// carried into the successor manifest.
type MultidomainAdmittedAuthorityBinding struct {
	AuthorityID                    string   `json:"authority_id"`
	ComponentID                    string   `json:"component_id"`
	ComponentVersion               string   `json:"component_version"`
	AdmissionPolicyScopeID         string   `json:"admission_policy_scope_id"`
	SnapshotID                     string   `json:"snapshot_id"`
	SnapshotManifestID             string   `json:"snapshot_manifest_id"`
	SnapshotManifestDocumentSHA256 string   `json:"snapshot_manifest_document_sha256"`
	EvidenceManifestID             string   `json:"evidence_manifest_id"`
	EvidenceManifestDocumentSHA256 string   `json:"evidence_manifest_document_sha256"`
	AdmissionPolicyID              string   `json:"admission_policy_id"`
	AdmissionPolicyDocumentSHA256  string   `json:"admission_policy_document_sha256"`
	AdmissionEvaluatedAt           string   `json:"admission_evaluated_at"`
	AdmissionFreshUntil            string   `json:"admission_fresh_until"`
	ClosedGapKinds                 []string `json:"closed_gap_kinds"`
}

// MultidomainBindingClosureCore is the content-addressed payload of the
// successor. It embeds the flipped 38-gap denominator and its identity is a
// fresh SHA-256 distinct from the frozen requirements manifest it supersedes.
type MultidomainBindingClosureCore struct {
	SchemaVersion           string                                `json:"schema_version"`
	ManifestKind            string                                `json:"manifest_kind"`
	State                   string                                `json:"state"`
	ExecutionState          string                                `json:"execution_state"`
	Ready                   bool                                  `json:"ready"`
	Name                    string                                `json:"name"`
	Revision                string                                `json:"revision"`
	SupersedesManifestID    string                                `json:"supersedes_manifest_id"`
	SupersedesPayloadSHA256 string                                `json:"supersedes_manifest_payload_sha256"`
	RequirementsFrozenAt    string                                `json:"requirements_frozen_at"`
	FreezeID                string                                `json:"freeze_id"`
	FreezeDocumentSHA256    string                                `json:"freeze_document_sha256"`
	AuthorityMode           string                                `json:"authority_mode"`
	EvaluationTime          string                                `json:"evaluation_time"`
	AuthorityRules          MultidomainBindingAuthorityRules      `json:"authority_rules"`
	Capabilities            MultidomainBindingClosureCapabilities `json:"capabilities"`
	Promotable              bool                                  `json:"promotable"`
	ExecutionAuthorized     bool                                  `json:"execution_authorized"`
	AdmittedAuthorities     []MultidomainAdmittedAuthorityBinding `json:"admitted_authorities"`
	ClosedGapCount          int                                   `json:"closed_gap_count"`
	BlockingGapCount        int                                   `json:"blocking_gap_count"`
	GapCount                int                                   `json:"gap_count"`
	Gaps                    []MultidomainAbsentArtifactGap        `json:"gaps"`
}

// MultidomainBindingClosureManifest is the successor to the frozen requirements
// manifest. It never mutates that frozen object; it emits a distinct
// content-addressed document with the nine verified authority-local gaps
// non-blocking and the twenty-nine shared/comparison/case gaps still blocking.
type MultidomainBindingClosureManifest struct {
	ManifestID            string `json:"manifest_id"`
	ManifestPayloadSHA256 string `json:"manifest_payload_sha256"`
	MultidomainBindingClosureCore
}

type closureSnapshotProjection struct {
	ManifestID string `json:"manifest_id"`
	SnapshotID string `json:"snapshot_id"`
}

type closureEvidenceProjection struct {
	ManifestID      string `json:"manifest_id"`
	InputManifestID string `json:"input_manifest_id"`
	InputSnapshotID string `json:"input_snapshot_id"`
}

type closureAdmissionProjection struct {
	PolicyID           string `json:"policy_id"`
	State              string `json:"state"`
	SnapshotManifestID string `json:"snapshot_manifest_id"`
	EvidenceManifestID string `json:"evidence_manifest_id"`
	SnapshotID         string `json:"snapshot_id"`
	ComponentID        string `json:"component_id"`
	ComponentVersionID string `json:"component_version_id"`
	RetrievalAllowed   bool   `json:"retrieval_allowed"`
	EvaluatedAt        string `json:"evaluated_at"`
	FreshUntil         string `json:"fresh_until"`
}

type parsedClosureAuthority struct {
	authority  MultidomainSourceAuthorityRequirement
	entry      MultidomainBindingClosureAdmittedAuthority
	snapshot   closureSnapshotProjection
	evidence   closureEvidenceProjection
	admission  closureAdmissionProjection
	snapDigest string
	evidDigest string
	admDigest  string
	snapOK     bool // artifact prefix + declared hash + self-id gate
	evidOK     bool
	admOK      bool
}

type admittedArtifactCheck struct {
	path   string
	digest string
}

// MaterializeMultidomainBindingClosure re-runs the frozen requirements
// validation exactly as materialize-binding-requirements, derives the same 38
// typed gaps, verifies the nine committed authority-local artifacts, and emits a
// distinct content-addressed successor in which only the verified authority-local
// gaps are non-blocking. It never writes or mutates the frozen requirements
// manifest, the freeze, or any source blob.
func MaterializeMultidomainBindingClosure(corePath, freezePath, freezeHash, sourceRoot, storeRoot, admittedPath, evaluationTime, sharedCorpusPath string) (MultidomainBindingClosureManifest, string, error) {
	var zero MultidomainBindingClosureManifest
	for _, value := range []string{corePath, freezePath, sourceRoot, storeRoot, admittedPath} {
		if strings.TrimSpace(value) == "" {
			return zero, "", errors.New("binding closure core, freeze, source root, store and admitted artifacts are required")
		}
	}
	if !validSHA256(freezeHash) {
		return zero, "", errors.New("binding closure freeze caller pin is invalid")
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
	admittedBytes, err := readStableFile(admittedPath, "binding closure admitted artifacts", maxMultidomainAdmittedInputBytes)
	if err != nil {
		return zero, "", fmt.Errorf("read binding closure admitted artifacts: %w", err)
	}
	var admitted MultidomainBindingClosureAdmittedArtifacts
	if err := decodeStrictCanonical(admittedBytes, &admitted); err != nil {
		return zero, "", fmt.Errorf("decode binding closure admitted artifacts: %w", err)
	}
	var sharedBytes []byte
	var shared MultidomainBindingClosureSharedCorpusArtifacts
	haveShared := strings.TrimSpace(sharedCorpusPath) != ""
	if haveShared {
		sharedBytes, err = readStableFile(sharedCorpusPath, "binding closure shared-corpus artifacts", maxMultidomainAdmittedInputBytes)
		if err != nil {
			return zero, "", fmt.Errorf("read binding closure shared-corpus artifacts: %w", err)
		}
		if err := decodeStrictCanonical(sharedBytes, &shared); err != nil {
			return zero, "", fmt.Errorf("decode binding closure shared-corpus artifacts: %w", err)
		}
	}
	coreAbsolute, coreErr := filepath.Abs(corePath)
	freezeAbsolute, freezeErr := filepath.Abs(freezePath)
	sourceAbsolute, sourceErr := filepath.Abs(sourceRoot)
	storeAbsolute, storeErr := filepath.Abs(storeRoot)
	admittedAbsolute, admittedErr := filepath.Abs(admittedPath)
	if coreErr != nil || freezeErr != nil || sourceErr != nil || storeErr != nil || admittedErr != nil ||
		validateNoSymlinkPath(sourceAbsolute) != nil || validateNoSymlinkPath(admittedAbsolute) != nil ||
		validateNoSymlinkExistingPrefix(storeAbsolute) != nil {
		return zero, "", errors.New("binding closure input or output root is unavailable")
	}
	artifactsRoot := filepath.Dir(admittedAbsolute)
	var sharedAbsolute, sharedArtifactsRoot string
	if haveShared {
		sharedAbsolute, err = filepath.Abs(sharedCorpusPath)
		if err != nil || validateNoSymlinkPath(sharedAbsolute) != nil {
			return zero, "", errors.New("binding closure shared-corpus artifacts root is unavailable")
		}
		sharedArtifactsRoot = filepath.Dir(sharedAbsolute)
		if pathsOverlap(sharedAbsolute, storeAbsolute) || pathsOverlap(sharedArtifactsRoot, storeAbsolute) {
			return zero, "", errors.New("binding closure shared-corpus artifacts and output store must not overlap")
		}
	}
	if pathsOverlap(sourceAbsolute, storeAbsolute) || pathsOverlap(coreAbsolute, storeAbsolute) ||
		pathsOverlap(freezeAbsolute, storeAbsolute) || pathsOverlap(admittedAbsolute, storeAbsolute) ||
		pathsOverlap(artifactsRoot, storeAbsolute) {
		return zero, "", errors.New("binding closure inputs and output store must not overlap")
	}

	// Re-run the exact frozen validation of materialize-binding-requirements:
	// freeze identity + six source blobs + rules gate + three source authorities,
	// producing the identical 38-gap denominator. Nothing is written here.
	base, err := sealMultidomainBindingRequirements(core, freeze, freezeHash, sourceAbsolute)
	if err != nil {
		return zero, "", err
	}
	if admitted.SchemaVersion != multidomainBindingRequirementsVersion || admitted.InputKind != multidomainBindingClosureInputKind {
		return zero, "", errors.New("binding closure admitted artifacts envelope is unsupported")
	}
	if admitted.RequirementsManifestID != base.ManifestID {
		return zero, "", errors.New("binding closure admitted artifacts do not target the exact frozen requirements manifest")
	}

	bindings, verified, effectiveEvaluationTime, checks, err := verifyMultidomainAdmittedArtifacts(base.MultidomainBindingRequirementsCore, admitted, artifactsRoot, evaluationTime)
	if err != nil {
		return zero, "", err
	}

	var sharedClosed map[string]bool
	if haveShared {
		var sharedChecks []admittedArtifactCheck
		sharedClosed, sharedChecks = verifyMultidomainSharedCorpusArtifacts(base, freeze, shared, sharedArtifactsRoot)
		checks = append(checks, sharedChecks...)
	}

	manifest := sealMultidomainBindingClosure(core, base, bindings, verified, sharedClosed, effectiveEvaluationTime)

	document, err := marshalDocument(manifest)
	if err != nil {
		return zero, "", err
	}
	relative, err := contentObjectPath("binding-requirements-closure", manifest.ManifestPayloadSHA256)
	if err != nil {
		return zero, "", err
	}
	if err := revalidateMultidomainBindingInputs(corePath, coreBytes, freezePath, freezeBytes, freezeHash, freeze, sourceAbsolute); err != nil {
		return zero, "", fmt.Errorf("binding closure inputs changed before commit: %w", err)
	}
	if err := revalidateAdmittedArtifacts(admittedPath, admittedBytes, checks); err != nil {
		return zero, "", fmt.Errorf("binding closure admitted artifacts changed before commit: %w", err)
	}
	if err := revalidateSharedCorpusInput(sharedCorpusPath, sharedBytes); err != nil {
		return zero, "", fmt.Errorf("binding closure shared-corpus artifacts changed before commit: %w", err)
	}
	if err := writeImmutableObject(storeAbsolute, relative, document); err != nil {
		return zero, "", fmt.Errorf("commit multidomain binding closure: %w", err)
	}
	if err := revalidateMultidomainBindingInputs(corePath, coreBytes, freezePath, freezeBytes, freezeHash, freeze, sourceAbsolute); err != nil {
		return zero, "", fmt.Errorf("binding closure inputs changed during commit: %w", err)
	}
	if err := revalidateAdmittedArtifacts(admittedPath, admittedBytes, checks); err != nil {
		return zero, "", fmt.Errorf("binding closure admitted artifacts changed during commit: %w", err)
	}
	if err := revalidateSharedCorpusInput(sharedCorpusPath, sharedBytes); err != nil {
		return zero, "", fmt.Errorf("binding closure shared-corpus artifacts changed during commit: %w", err)
	}
	manifestPath := filepath.Join(storeAbsolute, filepath.FromSlash(relative))
	if _, err := verifyFileDigest(manifestPath, digestBytes(document), int64(len(document))); err != nil {
		return zero, "", fmt.Errorf("binding closure output verification failed: %w", err)
	}
	return manifest, manifestPath, nil
}

func revalidateAdmittedArtifacts(admittedPath string, admittedBytes []byte, checks []admittedArtifactCheck) error {
	current, err := readStableFile(admittedPath, "binding closure admitted artifacts", maxMultidomainAdmittedInputBytes)
	if err != nil || !bytes.Equal(current, admittedBytes) {
		return errors.New("binding closure admitted artifacts identity changed")
	}
	for _, check := range checks {
		data, err := readStableFile(check.path, "admitted artifact", maxMultidomainAdmittedArtifactBytes)
		if err != nil || digestBytes(data) != check.digest {
			return errors.New("admitted artifact bytes changed")
		}
	}
	return nil
}

// revalidateSharedCorpusInput re-checks the optional shared-corpus-artifacts
// envelope itself (not just the artifacts it references, which `checks`
// already covers) has not changed since it was parsed. A no-op when the
// caller never supplied one.
func revalidateSharedCorpusInput(sharedCorpusPath string, sharedBytes []byte) error {
	if strings.TrimSpace(sharedCorpusPath) == "" {
		return nil
	}
	current, err := readStableFile(sharedCorpusPath, "binding closure shared-corpus artifacts", maxMultidomainAdmittedInputBytes)
	if err != nil || !bytes.Equal(current, sharedBytes) {
		return errors.New("binding closure shared-corpus artifacts identity changed")
	}
	return nil
}

// verifyMultidomainAdmittedArtifacts binds the committed artifacts to the frozen
// three-authority denominator. Structural collapse (wrong count, aliased or
// unknown authority, aliased artifact identity, unreadable bytes) fails the whole
// closure. Per-artifact defects (wrong hash, cross-authority alias, mis-scope,
// backdated or expired admission) fail closed by leaving that gap blocking.
func verifyMultidomainAdmittedArtifacts(core MultidomainBindingRequirementsCore, admitted MultidomainBindingClosureAdmittedArtifacts, artifactsRoot, evaluationTime string) ([]MultidomainAdmittedAuthorityBinding, map[string]map[string]bool, string, []admittedArtifactCheck, error) {
	if len(admitted.Authorities) != len(core.SourceAuthorities) || len(admitted.Authorities) != 3 {
		return nil, nil, "", nil, errors.New("binding closure collapsed the three source authorities")
	}
	authorityByID := make(map[string]MultidomainSourceAuthorityRequirement, len(core.SourceAuthorities))
	for _, authority := range core.SourceAuthorities {
		authorityByID[authority.AuthorityID] = authority
	}
	requirementsFrozenAt, err := parseCanonicalUTC(core.RequirementsFrozenAt)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("requirements_frozen_at: %w", err)
	}

	seenAuthority := make(map[string]struct{}, 3)
	seenScope := make(map[string]struct{}, 3)
	seenArtifact := make(map[string]struct{}, 9)
	parsedByID := make(map[string]parsedClosureAuthority, 3)
	var checks []admittedArtifactCheck

	for _, entry := range admitted.Authorities {
		authority, exists := authorityByID[entry.AuthorityID]
		if !exists {
			return nil, nil, "", nil, fmt.Errorf("binding closure references unknown authority %s", entry.AuthorityID)
		}
		if authority.AdmissionPolicyScopeID != entry.AdmissionPolicyScopeID || authority.ComponentID != entry.ComponentID || authority.ComponentVersion != entry.ComponentVersion {
			return nil, nil, "", nil, fmt.Errorf("binding closure authority %s does not match its frozen scope", entry.AuthorityID)
		}
		if _, dup := seenAuthority[entry.AuthorityID]; dup {
			return nil, nil, "", nil, errors.New("binding closure aliases one source authority")
		}
		if _, dup := seenScope[entry.AdmissionPolicyScopeID]; dup {
			return nil, nil, "", nil, errors.New("binding closure aliases one admission-policy scope")
		}
		seenAuthority[entry.AuthorityID] = struct{}{}
		seenScope[entry.AdmissionPolicyScopeID] = struct{}{}
		for _, artifact := range []MultidomainBindingClosureAdmittedArtifact{entry.SnapshotManifest, entry.EvidenceManifest, entry.AdmissionPolicy} {
			if _, dup := seenArtifact[artifact.ArtifactID]; dup {
				return nil, nil, "", nil, errors.New("binding closure aliases one artifact identity across authorities")
			}
			seenArtifact[artifact.ArtifactID] = struct{}{}
		}

		snapBytes, snapDigest, err := readAdmittedArtifact(artifactsRoot, entry.SnapshotManifest, "admitted snapshot manifest")
		if err != nil {
			return nil, nil, "", nil, err
		}
		evidBytes, evidDigest, err := readAdmittedArtifact(artifactsRoot, entry.EvidenceManifest, "admitted evidence manifest")
		if err != nil {
			return nil, nil, "", nil, err
		}
		admBytes, admDigest, err := readAdmittedArtifact(artifactsRoot, entry.AdmissionPolicy, "admitted admission policy")
		if err != nil {
			return nil, nil, "", nil, err
		}
		checks = append(checks,
			admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(entry.SnapshotManifest.Path)), digest: snapDigest},
			admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(entry.EvidenceManifest.Path)), digest: evidDigest},
			admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(entry.AdmissionPolicy.Path)), digest: admDigest},
		)
		var snapshot closureSnapshotProjection
		var evidence closureEvidenceProjection
		var admission closureAdmissionProjection
		if err := json.Unmarshal(snapBytes, &snapshot); err != nil {
			return nil, nil, "", nil, fmt.Errorf("decode admitted snapshot manifest: %w", err)
		}
		if err := json.Unmarshal(evidBytes, &evidence); err != nil {
			return nil, nil, "", nil, fmt.Errorf("decode admitted evidence manifest: %w", err)
		}
		if err := json.Unmarshal(admBytes, &admission); err != nil {
			return nil, nil, "", nil, fmt.Errorf("decode admitted admission policy: %w", err)
		}
		parsedByID[entry.AuthorityID] = parsedClosureAuthority{
			authority: authority, entry: entry,
			snapshot: snapshot, evidence: evidence, admission: admission,
			snapDigest: snapDigest, evidDigest: evidDigest, admDigest: admDigest,
			snapOK: strings.HasPrefix(entry.SnapshotManifest.ArtifactID, closureSnapshotIDPrefix) &&
				entry.SnapshotManifest.DocumentSHA256 == snapDigest && snapshot.ManifestID == entry.SnapshotManifest.ArtifactID,
			evidOK: strings.HasPrefix(entry.EvidenceManifest.ArtifactID, closureEvidenceIDPrefix) &&
				entry.EvidenceManifest.DocumentSHA256 == evidDigest && evidence.ManifestID == entry.EvidenceManifest.ArtifactID,
			admOK: strings.HasPrefix(entry.AdmissionPolicy.ArtifactID, closureAdmissionIDPrefix) &&
				entry.AdmissionPolicy.DocumentSHA256 == admDigest && admission.PolicyID == entry.AdmissionPolicy.ArtifactID,
		}
	}

	effectiveTime, effectiveString, err := resolveClosureEvaluationTime(evaluationTime, parsedByID)
	if err != nil {
		return nil, nil, "", nil, err
	}

	verified := make(map[string]map[string]bool, 3)
	bindings := make([]MultidomainAdmittedAuthorityBinding, 0, 3)
	for authorityID, item := range parsedByID {
		version := item.authority.ComponentVersion
		snapVerified := item.snapOK && endsWithVersion(item.snapshot.SnapshotID, version)
		evidVerified := item.evidOK &&
			item.evidence.InputManifestID == item.snapshot.ManifestID &&
			item.evidence.InputSnapshotID == item.snapshot.SnapshotID &&
			endsWithVersion(item.evidence.InputSnapshotID, version)
		admVerified := item.admOK &&
			item.admission.State == "active" && item.admission.RetrievalAllowed &&
			item.admission.SnapshotManifestID == item.snapshot.ManifestID &&
			item.admission.EvidenceManifestID == item.evidence.ManifestID &&
			item.admission.SnapshotID == item.snapshot.SnapshotID &&
			endsWithVersion(item.admission.ComponentVersionID, version) &&
			validClosureAdmissionWindow(requirementsFrozenAt, effectiveTime, item.admission)
		verified[authorityID] = map[string]bool{
			closureKindSnapshotManifest: snapVerified,
			closureKindEvidenceManifest: evidVerified,
			closureKindAdmissionPolicy:  admVerified,
		}
		closed := make([]string, 0, 3)
		if snapVerified {
			closed = append(closed, closureKindSnapshotManifest)
		}
		if evidVerified {
			closed = append(closed, closureKindEvidenceManifest)
		}
		if admVerified {
			closed = append(closed, closureKindAdmissionPolicy)
		}
		sort.Strings(closed)
		bindings = append(bindings, MultidomainAdmittedAuthorityBinding{
			AuthorityID: authorityID, ComponentID: item.authority.ComponentID, ComponentVersion: version,
			AdmissionPolicyScopeID:         item.authority.AdmissionPolicyScopeID,
			SnapshotID:                     item.snapshot.SnapshotID,
			SnapshotManifestID:             item.entry.SnapshotManifest.ArtifactID,
			SnapshotManifestDocumentSHA256: item.snapDigest,
			EvidenceManifestID:             item.entry.EvidenceManifest.ArtifactID,
			EvidenceManifestDocumentSHA256: item.evidDigest,
			AdmissionPolicyID:              item.entry.AdmissionPolicy.ArtifactID,
			AdmissionPolicyDocumentSHA256:  item.admDigest,
			AdmissionEvaluatedAt:           item.admission.EvaluatedAt,
			AdmissionFreshUntil:            item.admission.FreshUntil,
			ClosedGapKinds:                 closed,
		})
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].AuthorityID < bindings[j].AuthorityID })
	return bindings, verified, effectiveString, checks, nil
}

// resolveClosureEvaluationTime honours an explicit canonical --evaluation-time,
// otherwise defaults to the latest admission evaluated_at so the operative
// admission-validity checks become exactly requirements_frozen_at<=evaluated_at
// (non-backdated) and evaluation_time<fresh_until (non-expired).
func resolveClosureEvaluationTime(evaluationTime string, parsedByID map[string]parsedClosureAuthority) (time.Time, string, error) {
	if strings.TrimSpace(evaluationTime) != "" {
		parsed, err := parseCanonicalUTC(evaluationTime)
		if err != nil {
			return time.Time{}, "", fmt.Errorf("evaluation_time: %w", err)
		}
		return parsed, evaluationTime, nil
	}
	var maxTime time.Time
	maxString := ""
	found := false
	authorityIDs := make([]string, 0, len(parsedByID))
	for authorityID := range parsedByID {
		authorityIDs = append(authorityIDs, authorityID)
	}
	sort.Strings(authorityIDs)
	for _, authorityID := range authorityIDs {
		parsed, err := parseCanonicalUTC(parsedByID[authorityID].admission.EvaluatedAt)
		if err != nil {
			continue
		}
		if !found || parsed.After(maxTime) {
			maxTime = parsed
			maxString = parsedByID[authorityID].admission.EvaluatedAt
			found = true
		}
	}
	if !found {
		return time.Time{}, "", errors.New("binding closure evaluation time is absent and no admission carries a canonical evaluated_at")
	}
	return maxTime, maxString, nil
}

func validClosureAdmissionWindow(requirementsFrozenAt, evaluationTime time.Time, admission closureAdmissionProjection) bool {
	evaluatedAt, err := parseCanonicalUTC(admission.EvaluatedAt)
	if err != nil {
		return false
	}
	freshUntil, err := parseCanonicalUTC(admission.FreshUntil)
	if err != nil {
		return false
	}
	if evaluatedAt.Before(requirementsFrozenAt) {
		return false
	}
	if evaluationTime.Before(evaluatedAt) {
		return false
	}
	return evaluationTime.Before(freshUntil)
}

func readAdmittedArtifact(artifactsRoot string, artifact MultidomainBindingClosureAdmittedArtifact, label string) ([]byte, string, error) {
	if validateRelativePath(artifact.Path) != nil {
		return nil, "", fmt.Errorf("%s path is not canonical and relative", label)
	}
	full := filepath.Join(artifactsRoot, filepath.FromSlash(artifact.Path))
	data, err := readStableFile(full, label, maxMultidomainAdmittedArtifactBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", label, err)
	}
	return data, digestBytes(data), nil
}

// evaluationCaseClosureKey is the shared-closure map key for one frozen case's
// baseline or challenger query-signal gap.
func evaluationCaseClosureKey(caseID, profileRole string) string {
	return "evaluation_case:" + caseID + ":" + profileRole
}

// candidateBindsFrozenAuthorities requires the exact frozen three-authority
// denominator: same count, same authority id, exact reviewed component
// version and the same admission-policy scope per authority. The freeze's own
// `component_id` (e.g. "cilium") is a short scorer-blind label distinct from
// the retrieval build's `cmp:github:<owner>/<repo>` component identity, so it
// is deliberately not compared here; `authority_id` and
// `admission_policy_scope_id` are the two identifiers both vocabularies share
// verbatim. It does not re-check internal lineage ordering or distinctness;
// validateCandidate already fails closed on those before this is reached.
func candidateBindsFrozenAuthorities(lineages []AuthorityLineageBinding, authorities []MultidomainSourceAuthorityRequirement) bool {
	if len(lineages) != len(authorities) || len(lineages) == 0 {
		return false
	}
	want := make(map[string]MultidomainSourceAuthorityRequirement, len(authorities))
	for _, authority := range authorities {
		want[authority.AuthorityID] = authority
	}
	for _, lineage := range lineages {
		expected, ok := want[lineage.AuthorityID]
		if !ok || expected.ComponentVersion != lineage.ComponentVersion || expected.AdmissionPolicyScopeID != lineage.AdmissionPolicyScopeID {
			return false
		}
	}
	return true
}

// verifyMultidomainSharedCorpusArtifacts independently verifies the five
// shared-corpus, two comparison and every evaluation-case artifact against the
// frozen three-authority denominator and the requirements' own gap list. Each
// artifact kind is checked against its own prerequisites in dependency order
// (candidate before index, candidate+index before dense, dense+candidate
// before the fusion profile and both hybrid candidates, the verified profile
// before the challenger hybrid, and every prerequisite before its query
// signals); a defect anywhere in that chain leaves every gap depending on it
// blocking. It performs no filesystem write, calls no network or embedding
// endpoint, and mutates nothing.
func verifyMultidomainSharedCorpusArtifacts(base MultidomainBindingRequirementsManifest, freeze ScorerBlindEvaluationFreeze, shared MultidomainBindingClosureSharedCorpusArtifacts, artifactsRoot string) (map[string]bool, []admittedArtifactCheck) {
	closed := make(map[string]bool)
	if shared.SchemaVersion != multidomainBindingRequirementsVersion || shared.InputKind != multidomainBindingClosureSharedInputKind || shared.RequirementsManifestID != base.ManifestID {
		return closed, nil
	}
	var checks []admittedArtifactCheck

	candidateBytes, candidateDigest, err := readAdmittedArtifact(artifactsRoot, shared.LexicalCandidate, "shared lexical candidate")
	candidateOK := err == nil && strings.HasPrefix(shared.LexicalCandidate.ArtifactID, closureLexicalCandidateIDPrefix) && shared.LexicalCandidate.DocumentSHA256 == candidateDigest
	var candidate CandidateManifest
	if candidateOK && (json.Unmarshal(candidateBytes, &candidate) != nil || candidate.ManifestID != shared.LexicalCandidate.ArtifactID || validateCandidate(candidate) != nil) {
		candidateOK = false
	}
	if candidateOK && candidateBindsFrozenAuthorities(candidate.Lineages, base.SourceAuthorities) {
		checks = append(checks, admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(shared.LexicalCandidate.Path)), digest: candidateDigest})
		closed[closureKindLexicalCandidate] = true
	} else {
		candidateOK = false
	}

	indexBytes, indexDigest, err := readAdmittedArtifact(artifactsRoot, shared.LexicalIndex, "shared lexical index")
	indexOK := candidateOK && err == nil && strings.HasPrefix(shared.LexicalIndex.ArtifactID, closureLexicalIndexIDPrefix) && shared.LexicalIndex.DocumentSHA256 == indexDigest
	var index LexicalIndex
	if indexOK && (json.Unmarshal(indexBytes, &index) != nil || index.IndexID != shared.LexicalIndex.ArtifactID ||
		index.IndexID != candidate.LexicalIndexID || validateIndex(index, candidate) != nil) {
		indexOK = false
	}
	if indexOK {
		checks = append(checks, admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(shared.LexicalIndex.Path)), digest: indexDigest})
		closed[closureKindLexicalIndex] = true
	}

	denseBytes, denseDigest, err := readAdmittedArtifact(artifactsRoot, shared.DenseArtifact, "shared dense artifact")
	denseOK := indexOK && err == nil && strings.HasPrefix(shared.DenseArtifact.ArtifactID, closureDenseArtifactIDPrefix) && shared.DenseArtifact.DocumentSHA256 == denseDigest
	var dense DenseVectorArtifact
	if denseOK {
		maxDocuments, maxDimension, limitErr := normalizeDenseLimits(0, 0)
		if limitErr != nil || json.Unmarshal(denseBytes, &dense) != nil || dense.ArtifactID != shared.DenseArtifact.ArtifactID ||
			validateDenseArtifact(dense, candidate, index, maxDocuments, maxDimension) != nil {
			denseOK = false
		}
	}
	if denseOK {
		checks = append(checks, admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(shared.DenseArtifact.Path)), digest: denseDigest})
		closed[closureKindDenseArtifact] = true
	}

	profileBytes, profileDigest, err := readAdmittedArtifact(artifactsRoot, shared.FusionProfile, "shared fusion profile")
	profileOK := denseOK && err == nil && strings.HasPrefix(shared.FusionProfile.ArtifactID, closureFusionProfileIDPrefix) && shared.FusionProfile.DocumentSHA256 == profileDigest
	var profile FusionProfile
	if profileOK && (json.Unmarshal(profileBytes, &profile) != nil || profile.ProfileID != shared.FusionProfile.ArtifactID ||
		validateFusionProfileLineage(profile, candidate, shared.LexicalCandidate.DocumentSHA256, dense, shared.DenseArtifact.DocumentSHA256) != nil) {
		profileOK = false
	}
	if profileOK {
		checks = append(checks, admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(shared.FusionProfile.Path)), digest: profileDigest})
		closed[closureKindFusionProfile] = true
	}

	// The scorer-artifact gap ties directly to the fusion profile's own
	// independently verified scorer binding; it has no separate executable
	// surface here.
	if profileOK && validSHA256(shared.ScorerArtifactSHA256) && shared.ScorerArtifactSHA256 == profile.ScorerArtifactSHA256 {
		closed[closureKindScorerArtifact] = true
	}

	baselineBytes, baselineDigest, err := readAdmittedArtifact(artifactsRoot, shared.HybridBaselineCandidate, "shared hybrid baseline candidate")
	baselineOK := denseOK && err == nil && strings.HasPrefix(shared.HybridBaselineCandidate.ArtifactID, closureHybridCandidateIDPrefix) && shared.HybridBaselineCandidate.DocumentSHA256 == baselineDigest
	var hybridBaseline HybridCandidateManifest
	if baselineOK && (json.Unmarshal(baselineBytes, &hybridBaseline) != nil || hybridBaseline.ManifestID != shared.HybridBaselineCandidate.ArtifactID || validateHybridCandidate(hybridBaseline) != nil) {
		baselineOK = false
	}
	if baselineOK {
		baselineOK = hybridBaseline.FusionProfile == hybridFusionProfile &&
			hybridBaseline.LexicalCandidateID == candidate.ManifestID && hybridBaseline.LexicalCandidateSHA256 == shared.LexicalCandidate.DocumentSHA256 &&
			hybridBaseline.DenseArtifactID == dense.ArtifactID && hybridBaseline.DenseArtifactSHA256 == shared.DenseArtifact.DocumentSHA256
	}
	if baselineOK {
		checks = append(checks, admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(shared.HybridBaselineCandidate.Path)), digest: baselineDigest})
		closed[closureKindHybridBaselineCandidate] = true
	}

	challengerBytes, challengerDigest, err := readAdmittedArtifact(artifactsRoot, shared.HybridChallengerCandidate, "shared hybrid challenger candidate")
	challengerOK := profileOK && denseOK && err == nil && strings.HasPrefix(shared.HybridChallengerCandidate.ArtifactID, closureHybridCandidateIDPrefix) && shared.HybridChallengerCandidate.DocumentSHA256 == challengerDigest
	var hybridChallenger HybridCandidateManifest
	if challengerOK && (json.Unmarshal(challengerBytes, &hybridChallenger) != nil || hybridChallenger.ManifestID != shared.HybridChallengerCandidate.ArtifactID || validateHybridCandidate(hybridChallenger) != nil) {
		challengerOK = false
	}
	if challengerOK {
		challengerOK = hybridChallenger.FusionProfile == profile.FusionProfile &&
			hybridChallenger.FusionProfileID == profile.ProfileID && hybridChallenger.FusionProfileSHA256 == shared.FusionProfile.DocumentSHA256 &&
			hybridChallenger.LexicalCandidateID == candidate.ManifestID && hybridChallenger.LexicalCandidateSHA256 == shared.LexicalCandidate.DocumentSHA256 &&
			hybridChallenger.DenseArtifactID == dense.ArtifactID && hybridChallenger.DenseArtifactSHA256 == shared.DenseArtifact.DocumentSHA256
	}
	if challengerOK {
		checks = append(checks, admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(shared.HybridChallengerCandidate.Path)), digest: challengerDigest})
		closed[closureKindHybridChallengerCandidate] = true
	}

	freezeQueryByCase := make(map[string]string, len(freeze.Cases))
	for _, frozenCase := range freeze.Cases {
		freezeQueryByCase[frozenCase.CaseID] = frozenCase.Query
	}
	signalByKey := make(map[string]MultidomainBindingClosureQuerySignalArtifact, len(shared.QuerySignals))
	for _, signalEntry := range shared.QuerySignals {
		signalByKey[evaluationCaseClosureKey(signalEntry.CaseID, signalEntry.ProfileRole)] = signalEntry
	}
	for _, gap := range base.Gaps {
		if gap.Scope != "evaluation_case" {
			continue
		}
		key := evaluationCaseClosureKey(gap.CaseID, gap.ProfileRole)
		entry, hasEntry := signalByKey[key]
		if !hasEntry || !denseOK {
			continue
		}
		var expectedHybridID, expectedHybridSHA string
		switch gap.ProfileRole {
		case "baseline":
			if !baselineOK {
				continue
			}
			expectedHybridID, expectedHybridSHA = hybridBaseline.ManifestID, shared.HybridBaselineCandidate.DocumentSHA256
		case "challenger":
			if !challengerOK {
				continue
			}
			expectedHybridID, expectedHybridSHA = hybridChallenger.ManifestID, shared.HybridChallengerCandidate.DocumentSHA256
		default:
			continue
		}
		query, hasQuery := freezeQueryByCase[gap.CaseID]
		if !hasQuery {
			continue
		}
		expectedQuerySHA256 := digestBytes([]byte(query))
		if expectedQuerySHA256 != gap.ExpectedQuerySHA256 {
			continue
		}
		signalBytes, signalDigest, signalErr := readAdmittedArtifact(artifactsRoot, entry.Artifact, "shared query signal")
		if signalErr != nil || !strings.HasPrefix(entry.Artifact.ArtifactID, closureQuerySignalIDPrefix) || entry.Artifact.DocumentSHA256 != signalDigest {
			continue
		}
		var signal QuerySignalArtifact
		if json.Unmarshal(signalBytes, &signal) != nil || signal.ArtifactID != entry.Artifact.ArtifactID {
			continue
		}
		if expectedHybridSHA == "" || signal.HybridCandidateID != expectedHybridID || signal.DenseArtifactID != dense.ArtifactID ||
			signal.QuerySHA256 != expectedQuerySHA256 || signal.RerankingRequested || len(signal.Scores) != 0 {
			continue
		}
		checks = append(checks, admittedArtifactCheck{path: filepath.Join(artifactsRoot, filepath.FromSlash(entry.Artifact.Path)), digest: signalDigest})
		closed[key] = true
	}

	return closed, checks
}

func sealMultidomainBindingClosure(core MultidomainBindingRequirementsCore, base MultidomainBindingRequirementsManifest, bindings []MultidomainAdmittedAuthorityBinding, verified map[string]map[string]bool, sharedClosed map[string]bool, evaluationTime string) MultidomainBindingClosureManifest {
	gaps := make([]MultidomainAbsentArtifactGap, len(base.Gaps))
	closed := 0
	for index, gap := range base.Gaps {
		gap.AuthorityIDs = append([]string(nil), gap.AuthorityIDs...)
		gap.RequiredFields = append([]string(nil), gap.RequiredFields...)
		switch gap.Scope {
		case "source_authority":
			if len(gap.AuthorityIDs) == 1 {
				if kinds, ok := verified[gap.AuthorityIDs[0]]; ok && kinds[gap.ArtifactKind] {
					gap.Blocking = false
					closed++
				}
			}
		case "shared_corpus", "comparison":
			if sharedClosed[gap.ArtifactKind] {
				gap.Blocking = false
				closed++
			}
		case "evaluation_case":
			if sharedClosed[evaluationCaseClosureKey(gap.CaseID, gap.ProfileRole)] {
				gap.Blocking = false
				closed++
			}
		}
		gaps[index] = gap
	}
	closureCore := MultidomainBindingClosureCore{
		SchemaVersion:           multidomainBindingRequirementsVersion,
		ManifestKind:            multidomainBindingClosureKind,
		State:                   multidomainBindingRequirementsState,
		ExecutionState:          multidomainBindingRequirementsExecutionState,
		Ready:                   false,
		Name:                    core.Name,
		Revision:                core.Revision,
		SupersedesManifestID:    base.ManifestID,
		SupersedesPayloadSHA256: base.ManifestPayloadSHA256,
		RequirementsFrozenAt:    core.RequirementsFrozenAt,
		FreezeID:                core.FreezeID,
		FreezeDocumentSHA256:    core.FreezeDocumentSHA256,
		AuthorityMode:           core.AuthorityMode,
		EvaluationTime:          evaluationTime,
		AuthorityRules:          core.AuthorityRules,
		Capabilities:            MultidomainBindingClosureCapabilities{},
		Promotable:              false,
		ExecutionAuthorized:     false,
		AdmittedAuthorities:     bindings,
		ClosedGapCount:          closed,
		BlockingGapCount:        len(gaps) - closed,
		GapCount:                len(gaps),
		Gaps:                    gaps,
	}
	payload, _ := json.Marshal(closureCore)
	digest := digestBytes(payload)
	return MultidomainBindingClosureManifest{
		ManifestID:                    multidomainBindingRequirementsIDPrefix + digest,
		ManifestPayloadSHA256:         digest,
		MultidomainBindingClosureCore: closureCore,
	}
}

func endsWithVersion(identity, version string) bool {
	return version != "" && strings.HasSuffix(identity, "@"+version)
}
