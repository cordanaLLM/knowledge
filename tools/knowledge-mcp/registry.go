package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	manifestIDPattern     = regexp.MustCompile(`^mft-[0-9a-f]{64}$`)
	pointerIDPattern      = regexp.MustCompile(`^ptr-[0-9a-f]{64}$`)
	receiptIDPattern      = regexp.MustCompile(`^prc-[0-9a-f]{64}$`)
	sha256Pattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sshFingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/=]+$`)
	sshSignaturePattern   = regexp.MustCompile(`(?s)^-----BEGIN SSH SIGNATURE-----\n[A-Za-z0-9+/=\n]+-----END SSH SIGNATURE-----\n$`)
	registryTimestamp     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

const (
	maxControlObjectBytes        int64 = 1 << 20
	postLoadCompactionThreshold        = 64 << 20
	maxSignatureCommandOutput          = 64 << 10
	generationSignatureMethod          = "sshsig-ed25519-detached"
	generationSignatureNamespace       = "archeion-knowledge-registry-transition-v1"
	sshKeygenPath                      = "/usr/bin/ssh-keygen"
)

type registrySource struct {
	ContentHash string         `json:"content_hash,omitempty"`
	EvidenceURI string         `json:"evidence_uri"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	SourceID    string         `json:"source_id"`
	SourceType  string         `json:"source_type"`
}

type registryComponent struct {
	ComponentID              string           `json:"component_id"`
	Ecosystem                string           `json:"ecosystem"`
	Kind                     string           `json:"kind"`
	Lifecycles               []string         `json:"lifecycles"`
	Metadata                 map[string]any   `json:"metadata,omitempty"`
	Name                     string           `json:"name"`
	Namespace                string           `json:"namespace"`
	OfficialChannelProposals []map[string]any `json:"official_channel_proposals,omitempty"`
	OfficialChannelRequired  bool             `json:"official_channel_required"`
	OfficialChannelSnapshots []map[string]any `json:"official_channel_snapshots,omitempty"`
	OfficialChannels         []map[string]any `json:"official_channels"`
	OfficialResolutions      []map[string]any `json:"official_resolutions,omitempty"`
	PURL                     string           `json:"purl,omitempty"`
}

type registryVersion struct {
	ArtifactDigest     string         `json:"artifact_digest,omitempty"`
	ComponentID        string         `json:"component_id"`
	ComponentVersionID string         `json:"component_version_id"`
	Constraint         string         `json:"constraint,omitempty"`
	Evidence           []string       `json:"evidence,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	Platform           string         `json:"platform,omitempty"`
	ResolutionState    string         `json:"resolution_state,omitempty"`
	ResolvedVersion    string         `json:"resolved_version,omitempty"`
	SourceRef          string         `json:"source_ref,omitempty"`
}

type registryOccurrence struct {
	ComponentID        string         `json:"component_id"`
	ComponentVersionID string         `json:"component_version_id"`
	DependencyScope    string         `json:"dependency_scope"`
	Directness         string         `json:"directness"`
	EvidenceLocator    string         `json:"evidence_locator"`
	Lifecycle          string         `json:"lifecycle"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	OccurrenceID       string         `json:"occurrence_id"`
	Optional           bool           `json:"optional"`
	RawValue           string         `json:"raw_value"`
	Role               string         `json:"role"`
	RootID             string         `json:"root_id,omitempty"`
	SourceID           string         `json:"source_id"`
}

type registryEdge struct {
	Constraint             string         `json:"constraint,omitempty"`
	EdgeID                 string         `json:"edge_id"`
	FromComponentVersionID string         `json:"from_component_version_id"`
	Metadata               map[string]any `json:"metadata,omitempty"`
	Optional               bool           `json:"optional"`
	Relationship           string         `json:"relationship"`
	Resolver               string         `json:"resolver"`
	Scope                  string         `json:"scope"`
	SourceOccurrenceID     string         `json:"source_occurrence_id"`
	ToComponentVersionID   string         `json:"to_component_version_id"`
}

type registryGap struct {
	ComponentID        string         `json:"component_id,omitempty"`
	ComponentVersionID string         `json:"component_version_id,omitempty"`
	Evidence           []string       `json:"evidence"`
	GapID              string         `json:"gap_id"`
	GapType            string         `json:"gap_type"`
	Message            string         `json:"message"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	SourceID           string         `json:"source_id,omitempty"`
}

type registryAuthorityBoundary struct {
	Authoritative      *bool  `json:"authoritative"`
	CompileEligible    *bool  `json:"compile_eligible"`
	ProductionMutation *bool  `json:"production_mutation"`
	PromoteEligible    *bool  `json:"promote_eligible"`
	RetrievalRelease   *bool  `json:"retrieval_release"`
	ReviewState        string `json:"review_state"`
	SourceAdmission    *bool  `json:"source_admission"`
}

type registryBounds struct {
	Components            int `json:"components"`
	DependencyEdges       int `json:"dependency_edges"`
	DiscoveryFileBytes    int `json:"discovery_file_bytes"`
	DiscoveryFiles        int `json:"discovery_files"`
	DiscoveryTotalBytes   int `json:"discovery_total_bytes"`
	Gaps                  int `json:"gaps"`
	JSONDepth             int `json:"json_depth"`
	JSONInputBytes        int `json:"json_input_bytes"`
	JSONNodes             int `json:"json_nodes"`
	Occurrences           int `json:"occurrences"`
	SerializedOutputBytes int `json:"serialized_output_bytes"`
	Sources               int `json:"sources"`
	TrackedFiles          int `json:"tracked_files"`
	Versions              int `json:"versions"`
}

// The producer freezes each historical bounds envelope as a literal so already
// sealed manifest_ids stay reproducible (MANIFEST_BOUNDS_KNOWN in
// knowledge_registry.py). The broker must accept the same SET: pinning a single
// struct rejected every manifest sealed under a newer envelope, and pinning only
// the newest would reject every older sealed manifest.
var registryBoundsKnown = []registryBounds{
	// V1 - pre-W3 512 MiB envelope.
	{
		Components: 100_000, DependencyEdges: 400_000,
		DiscoveryFileBytes: 8 << 20, DiscoveryFiles: 10_000, DiscoveryTotalBytes: 128 << 20,
		Gaps: 400_000, JSONDepth: 128, JSONInputBytes: 512 << 20, JSONNodes: 10_000_000,
		Occurrences: 400_000, SerializedOutputBytes: 512 << 20, Sources: 100_000,
		TrackedFiles: 20_000, Versions: 200_000,
	},
	// V2 - pre-paged-SBOM 768 MiB envelope.
	{
		Components: 100_000, DependencyEdges: 400_000,
		DiscoveryFileBytes: 8 << 20, DiscoveryFiles: 10_000, DiscoveryTotalBytes: 128 << 20,
		Gaps: 400_000, JSONDepth: 128, JSONInputBytes: 768 << 20, JSONNodes: 10_000_000,
		Occurrences: 400_000, SerializedOutputBytes: 768 << 20, Sources: 100_000,
		TrackedFiles: 20_000, Versions: 200_000,
	},
	// V3 - paged-SBOM envelope: 768 MiB with the measured edge and node ceilings.
	{
		Components: 100_000, DependencyEdges: 700_000,
		DiscoveryFileBytes: 8 << 20, DiscoveryFiles: 10_000, DiscoveryTotalBytes: 128 << 20,
		Gaps: 400_000, JSONDepth: 128, JSONInputBytes: 768 << 20, JSONNodes: 20_000_000,
		Occurrences: 400_000, SerializedOutputBytes: 768 << 20, Sources: 100_000,
		TrackedFiles: 20_000, Versions: 200_000,
	},
}

func knownRegistryBounds(bounds registryBounds) bool {
	for _, known := range registryBoundsKnown {
		if bounds == known {
			return true
		}
	}
	return false
}

type registryObservation struct {
	ObservedAt           string `json:"observed_at"`
	SourceValidAt        string `json:"source_valid_at"`
	SourceValidTimeBasis string `json:"source_valid_time_basis"`
}

type registryMergeLineage struct {
	CurrentManifestID  *string  `json:"current_manifest_id"`
	InputManifestIDs   []string `json:"input_manifest_ids"`
	PreviousManifestID *string  `json:"previous_manifest_id"`
	SelectionPolicy    string   `json:"selection_policy"`
}

type registryManifest struct {
	JSONSchema        string                    `json:"$schema"`
	AuthorityBoundary registryAuthorityBoundary `json:"authority_boundary"`
	BaseManifestID    *string                   `json:"base_manifest_id"`
	Bounds            registryBounds            `json:"bounds"`
	Completeness      map[string]any            `json:"completeness"`
	Components        []registryComponent       `json:"components"`
	Counts            map[string]int            `json:"counts"`
	DependencyEdges   []registryEdge            `json:"dependency_edges"`
	DiscoveryScope    map[string]any            `json:"discovery_scope,omitempty"`
	Gaps              []registryGap             `json:"gaps"`
	GenerationState   string                    `json:"generation_state"`
	Generator         map[string]any            `json:"generator"`
	InputSet          map[string]any            `json:"input_set"`
	Integrity         map[string]any            `json:"integrity"`
	ManifestID        string                    `json:"manifest_id"`
	ManifestVersion   int                       `json:"manifest_version"`
	MergeLineage      *registryMergeLineage     `json:"merge_lineage,omitempty"`
	Observation       *registryObservation      `json:"observation,omitempty"`
	Occurrences       []registryOccurrence      `json:"occurrences"`
	Reconciliation    map[string]any            `json:"reconciliation"`
	RecordKind        string                    `json:"record_kind"`
	SchemaVersion     string                    `json:"schema_version"`
	Sources           []registrySource          `json:"sources"`
	Versions          []registryVersion         `json:"versions"`
	sourceByID        map[string]*registrySource
	componentByID     map[string]*registryComponent
	versionByID       map[string]*registryVersion
	occurrenceByID    map[string]*registryOccurrence
	gapByID           map[string]*registryGap
	versionsByComp    map[string][]registryVersion
	occurrencesByComp map[string][]registryOccurrence
	gapsByComp        map[string][]registryGap
	sourcesByComp     map[string][]registrySource
	relationsFromComp map[string][]registryRelation
	relationsToComp   map[string][]registryRelation
}

type registryRelation struct {
	FromComponentID     string
	ToComponentID       string
	Relationship        string
	Scope               string
	Optional            bool
	EdgeCount           int
	EvidenceOccurrences []string
}

type registryRelationKey struct {
	FromComponentID string
	ToComponentID   string
	Relationship    string
	Scope           string
	Optional        bool
}

type generationPointer struct {
	SchemaVersion        string  `json:"schema_version"`
	RecordKind           string  `json:"record_kind"`
	PointerID            string  `json:"pointer_id"`
	Revision             int     `json:"revision"`
	CurrentManifestID    string  `json:"current_manifest_id"`
	CurrentManifestHash  string  `json:"current_manifest_hash"`
	PreviousManifestID   *string `json:"previous_manifest_id"`
	PreviousManifestHash *string `json:"previous_manifest_hash"`
	TransitionReceiptID  string  `json:"transition_receipt_id"`
	UpdatedAt            string  `json:"updated_at"`
}

type registrySnapshot struct {
	state        typedState
	message      string
	mode         string
	source       string
	pointer      *generationPointer
	current      *registryManifest
	projection   *registryProjection
	previous     *registryManifest
	warnings     []string
	loadDuration time.Duration
	sourceSize   int64
}

// verifiedArtifact pins one exact file that a signed-store verification read.
type verifiedArtifact struct {
	path string
	hash string
}

// artifactRecorder collects the exact artifact set a store load verified, so a
// cached verdict can be invalidated by any change to what it asserts.
type artifactRecorder struct {
	artifacts []verifiedArtifact
}

func (recorder *artifactRecorder) record(path, hash string) {
	if recorder == nil {
		return
	}
	recorder.artifacts = append(recorder.artifacts, verifiedArtifact{path: path, hash: hash})
}

type registryProvider struct {
	registryPath    string
	projectionPath  string
	stateDir        string
	allowedSigners  string
	maxBytes        int64
	direct          *registrySnapshot
	mutex           sync.Mutex
	cachedAliasHash string
	cachedTrustHash string
	cachedStore     *registrySnapshot
	cachedArtifacts []verifiedArtifact
}

func newRegistryProvider(configuration config) *registryProvider {
	provider := &registryProvider{
		registryPath:   configuration.registryPath,
		projectionPath: configuration.projectionPath,
		stateDir:       configuration.stateDirectory,
		allowedSigners: configuration.allowedSigners,
		maxBytes:       configuration.maxRegistrySize,
	}
	return provider
}

func (provider *registryProvider) snapshot() *registrySnapshot {
	if provider.stateDir != "" {
		provider.mutex.Lock()
		defer provider.mutex.Unlock()
		trustedPolicy, trustedPolicyHash, trustErr := loadExternalTrustRoot(provider.stateDir, provider.allowedSigners)
		if trustErr != nil {
			return unavailableSnapshot("generation-store", provider.stateDir, trustErr)
		}
		aliasPath := filepath.Join(provider.stateDir, "generation-pointer.json")
		aliasRaw, err := readBoundRegular(aliasPath, maxControlObjectBytes, true)
		if errors.Is(err, os.ErrNotExist) {
			return &registrySnapshot{state: stateNoVerifiedState, mode: "generation-store", source: provider.stateDir, message: "generation store has no current signed pointer; no verified registry state exists and registry emptiness cannot be asserted"}
		}
		if err != nil {
			return unavailableSnapshot("generation-store", provider.stateDir, err)
		}
		aliasHash := hashBytes(aliasRaw)
		if provider.cachedStore != nil && provider.cachedStore.state == stateOK &&
			provider.cachedAliasHash == aliasHash && provider.cachedTrustHash == trustedPolicyHash &&
			provider.verifiedArtifactsUnchanged() {
			return provider.cachedStore
		}
		recorder := &artifactRecorder{}
		snapshot := provider.loadStore(aliasRaw, trustedPolicy, trustedPolicyHash, recorder)
		provider.cachedAliasHash, provider.cachedTrustHash = "", ""
		provider.cachedArtifacts, provider.cachedStore = nil, nil
		if snapshot.state == stateOK && len(recorder.artifacts) > 0 {
			provider.cachedAliasHash = aliasHash
			provider.cachedTrustHash = trustedPolicyHash
			provider.cachedArtifacts = recorder.artifacts
			provider.cachedStore = snapshot
		}
		return snapshot
	}
	if provider.direct != nil {
		return provider.direct
	}
	if provider.projectionPath != "" {
		provider.mutex.Lock()
		defer provider.mutex.Unlock()
		if provider.direct == nil {
			provider.direct = provider.loadProjectionDirect()
		}
		return provider.direct
	}
	if provider.registryPath != "" {
		provider.mutex.Lock()
		defer provider.mutex.Unlock()
		if provider.direct == nil {
			provider.direct = provider.loadDirect()
		}
		return provider.direct
	}
	return &registrySnapshot{state: stateNotConfigured, mode: "none", message: "no dependency registry backend is configured; registry content and emptiness cannot be asserted"}
}

// verifiedArtifactsUnchanged re-reads every artifact the cached verdict was
// derived from and compares its exact hash. The store verdict is a pure
// deterministic function of the provider's immutable configuration and these
// exact bytes, so identical bytes imply an identical verification result: this
// is exactly as strong as re-running loadStore, and only skips recomputing the
// JSON decode, manifest admission and SSHSIG check. Hashing streams, so a
// removed, replaced or tampered artifact invalidates the cache in bounded
// memory without a full re-verification on the hot path.
func (provider *registryProvider) verifiedArtifactsUnchanged() bool {
	if len(provider.cachedArtifacts) == 0 {
		return false
	}
	for _, artifact := range provider.cachedArtifacts {
		hash, err := hashBoundRegular(artifact.path, provider.maxBytes)
		if err != nil || hash != artifact.hash {
			return false
		}
	}
	return true
}

// hashBoundRegular hashes an exact bounded non-symlink regular file without
// holding its bytes, rejecting any file whose size changes while it is read.
func hashBoundRegular(path string, maximum int64) (string, error) {
	file, size, err := openBoundRegular(path, maximum, true)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	copied, err := io.Copy(digest, io.LimitReader(file, maximum+1))
	if err != nil {
		return "", err
	}
	if copied != size {
		return "", errors.New("registry object changed while it was hashed")
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func (provider *registryProvider) loadProjectionDirect() *registrySnapshot {
	started := time.Now()
	projection, err := openRegistryProjection(provider.projectionPath, provider.maxBytes)
	if err != nil {
		return unavailableSnapshot("candidate-projection", provider.projectionPath, err)
	}
	return &registrySnapshot{
		state: statePartial, mode: "candidate-projection", source: provider.projectionPath,
		message: "compact projection is hash-bound to a validated candidate manifest but has not been selected by a signed generation pointer; it cannot upgrade authority",
		current: projection.manifestHeader(), projection: projection,
		loadDuration: time.Since(started), sourceSize: fileSize(provider.projectionPath),
	}
}

func (provider *registryProvider) loadDirect() *registrySnapshot {
	started := time.Now()
	manifest, err := loadRegistryManifest(provider.registryPath, provider.maxBytes)
	if err != nil {
		return unavailableSnapshot("candidate", provider.registryPath, err)
	}
	message := "candidate manifest is readable but has not been selected by a signed generation pointer"
	if complete, reason := manifestIsComplete(manifest); !complete {
		message += "; candidate completeness is gapped: " + reason
	}
	return &registrySnapshot{
		state: statePartial, mode: "candidate", source: provider.registryPath,
		message:      message,
		current:      manifest,
		loadDuration: time.Since(started),
		sourceSize:   fileSize(provider.registryPath),
	}
}

func (provider *registryProvider) loadStore(aliasRaw, trustedPolicy []byte, trustedPolicyHash string, recorder *artifactRecorder) *registrySnapshot {
	started := time.Now()
	var pointer generationPointer
	if err := decodeStrictTyped(aliasRaw, &pointer); err != nil {
		return unavailableSnapshot("generation-store", provider.stateDir, fmt.Errorf("decode current pointer: %w", err))
	}
	if err := validatePointer(&pointer); err != nil {
		return unavailableSnapshot("generation-store", provider.stateDir, err)
	}
	recorder.record(provider.allowedSigners, trustedPolicyHash)
	recorder.record(filepath.Join(provider.stateDir, "generation-pointer.json"), hashBytes(aliasRaw))
	immutablePointerPath := filepath.Join(provider.stateDir, "pointers", pointer.PointerID+".json")
	immutableRaw, err := readBoundRegular(immutablePointerPath, maxControlObjectBytes, true)
	if err != nil {
		return unavailableSnapshot("generation-store", provider.stateDir, fmt.Errorf("read immutable pointer: %w", err))
	}
	if !bytes.Equal(aliasRaw, immutableRaw) {
		return unavailableSnapshot("generation-store", provider.stateDir, errors.New("mutable pointer alias differs from its immutable pointer object"))
	}
	recorder.record(immutablePointerPath, hashBytes(immutableRaw))
	if err := verifyReceiptBinding(provider.stateDir, &pointer, provider.allowedSigners, trustedPolicy, trustedPolicyHash, recorder); err != nil {
		return unavailableSnapshot("generation-store", provider.stateDir, err)
	}
	currentPath := filepath.Join(provider.stateDir, "manifests", pointer.CurrentManifestID+".json")
	current, currentFileHash, err := loadRegistryManifestHashed(currentPath, provider.maxBytes)
	if err != nil {
		return unavailableSnapshot("generation-store", provider.stateDir, fmt.Errorf("load current manifest: %w", err))
	}
	if current.ManifestID != pointer.CurrentManifestID || manifestHash(current) != pointer.CurrentManifestHash {
		return unavailableSnapshot("generation-store", provider.stateDir, errors.New("current manifest does not match pointer binding"))
	}
	if complete, reason := manifestIsComplete(current); !complete {
		return unavailableSnapshot("generation-store", provider.stateDir, fmt.Errorf("selected manifest is not complete and promotable: %s", reason))
	}
	recorder.record(currentPath, currentFileHash)
	snapshot := &registrySnapshot{state: stateOK, mode: "generation-store", source: provider.stateDir, pointer: &pointer, current: current, loadDuration: time.Since(started), sourceSize: fileSize(currentPath)}
	if pointer.PreviousManifestID != nil {
		previousPath := filepath.Join(provider.stateDir, "manifests", *pointer.PreviousManifestID+".json")
		previous, previousFileHash, loadErr := loadRegistryManifestHashed(previousPath, provider.maxBytes)
		if loadErr != nil || previous.ManifestID != *pointer.PreviousManifestID || manifestHash(previous) != *pointer.PreviousManifestHash {
			if loadErr == nil {
				loadErr = errors.New("previous manifest does not match pointer binding")
			}
			return unavailableSnapshot("generation-store", provider.stateDir, fmt.Errorf("load previous manifest: %w", loadErr))
		}
		recorder.record(previousPath, previousFileHash)
		snapshot.previous = previous
	}
	return snapshot
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func unavailableSnapshot(mode, source string, err error) *registrySnapshot {
	return &registrySnapshot{state: stateBackendUnavailable, mode: mode, source: source, message: err.Error()}
}

func loadExternalTrustRoot(stateDir, policyPath string) ([]byte, string, error) {
	if strings.TrimSpace(policyPath) == "" {
		return nil, "", errors.New("signed generation store requires an external operator allowed-signers trust root")
	}
	stateRoot, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, "", fmt.Errorf("resolve generation store: %w", err)
	}
	trustedPath, err := filepath.Abs(policyPath)
	if err != nil {
		return nil, "", fmt.Errorf("resolve operator trust root: %w", err)
	}
	inside, err := pathWithin(stateRoot, trustedPath)
	if err != nil || inside {
		return nil, "", errors.New("operator allowed-signers trust root must be outside the generation store")
	}
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(trustedPath)); err != nil {
		return nil, "", fmt.Errorf("validate operator trust-root parent: %w", err)
	}
	if err := requireReadOnlyRegular(trustedPath); err != nil {
		return nil, "", fmt.Errorf("validate operator trust-root file: %w", err)
	}
	policy, err := readBoundRegular(trustedPath, maxControlObjectBytes, true)
	if err != nil {
		return nil, "", fmt.Errorf("read operator trust root: %w", err)
	}
	return policy, hashBytes(policy), nil
}

func pathWithin(root, candidate string) (bool, error) {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil {
		return false, err
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))), nil
}

func readBoundRegular(path string, maximum int64, rejectSymlink bool) ([]byte, error) {
	file, size, err := openBoundRegular(path, maximum, rejectSymlink)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedBefore, err := file.Stat()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum || int64(len(data)) != size {
		return nil, fmt.Errorf("registry object changed or exceeds %d-byte limit", maximum)
	}
	openedAfter, err := file.Stat()
	if err != nil || openedAfter.Size() != openedBefore.Size() || !openedAfter.ModTime().Equal(openedBefore.ModTime()) {
		return nil, errors.New("registry object metadata changed while it was read")
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || (rejectSymlink && pathAfter.Mode()&os.ModeSymlink != 0) || !os.SameFile(openedBefore, pathAfter) {
		return nil, errors.New("registry object path changed while it was read")
	}
	return data, nil
}

func openBoundRegular(path string, maximum int64, rejectSymlink bool) (*os.File, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if rejectSymlink && info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("symlink registry objects are forbidden")
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("registry object is not a regular file")
	}
	if info.Size() > maximum {
		return nil, 0, fmt.Errorf("registry object exceeds %d-byte limit", maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		file.Close()
		return nil, 0, errors.New("registry object changed while it was opened")
	}
	return file, opened.Size(), nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func decodeStrictTyped(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return err
	}
	return nil
}

func loadRegistryManifest(path string, maximum int64) (*registryManifest, error) {
	manifest, _, err := loadRegistryManifestHashed(path, maximum)
	return manifest, err
}

// loadRegistryManifestHashed additionally returns the exact SHA-256 of the file
// bytes it decoded, hashed from the same handle so no second read can be
// substituted, without ever holding the whole manifest as raw bytes.
func loadRegistryManifestHashed(path string, maximum int64) (*registryManifest, string, error) {
	file, size, err := openBoundRegular(path, maximum, true)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	digest := sha256.New()
	counter := &countingReader{reader: io.TeeReader(io.LimitReader(file, maximum+1), digest)}
	var manifest registryManifest
	decoder := json.NewDecoder(counter)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, "", fmt.Errorf("decode registry records: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, "", errors.New("registry manifest contains multiple JSON values")
		}
		return nil, "", fmt.Errorf("finish registry decode: %w", err)
	}
	if _, err := io.Copy(io.Discard, counter); err != nil {
		return nil, "", fmt.Errorf("finish registry read: %w", err)
	}
	if counter.count != size {
		return nil, "", errors.New("registry manifest changed while it was read")
	}
	if err := validateManifest(&manifest); err != nil {
		return nil, "", err
	}
	manifest.buildIndexes()
	// Manifest validation temporarily needs encoding and relation-group buffers.
	// After a large immutable generation is fully indexed, return those pages to
	// the OS instead of leaving a multi-hundred-megabyte transient heap resident
	// for the life of an editor MCP session.
	if size >= postLoadCompactionThreshold {
		debug.FreeOSMemory()
	}
	return &manifest, "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

// countingReader counts the bytes that actually passed through the manifest
// hash, so a partial read can never be mistaken for a whole-file digest.
type countingReader struct {
	reader io.Reader
	count  int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.count += int64(read)
	return read, err
}

func validateManifest(manifest *registryManifest) error {
	if manifest.JSONSchema != "https://json-schema.org/draft/2020-12/schema" || manifest.RecordKind != "generated_discovery_manifest" || manifest.SchemaVersion != "2.0.0" || manifest.ManifestVersion != 2 || manifest.GenerationState != "candidate" {
		return errors.New("registry must be a v2 immutable candidate envelope")
	}
	if !manifestIDPattern.MatchString(manifest.ManifestID) {
		return errors.New("registry manifest_id is invalid")
	}
	if err := validateManifestEnvelope(manifest); err != nil {
		return err
	}
	hash, ok := manifest.Integrity["manifest_hash"].(string)
	if !ok || !sha256Pattern.MatchString(hash) || manifest.ManifestID != "mft-"+strings.TrimPrefix(hash, "sha256:") {
		return errors.New("registry manifest identity fields are inconsistent")
	}
	// Reject structurally valid but resource-amplifying manifests before any
	// canonical encoding or index construction. Both direct candidates and each
	// manifest selected by a signed generation pointer pass through this gate.
	if err := validateManifestResourceBounds(manifest); err != nil {
		return fmt.Errorf("registry resource bounds: %w", err)
	}
	preimage := manifestHashPreimage(manifest)
	computed, err := canonicalHash(preimage)
	if err != nil || computed != hash {
		return fmt.Errorf("registry manifest content hash mismatch: computed %s, expected %s", computed, hash)
	}
	expected := map[string]int{
		"sources":    len(manifest.Sources),
		"components": len(manifest.Components), "versions": len(manifest.Versions),
		"occurrences": len(manifest.Occurrences), "dependency_edges": len(manifest.DependencyEdges),
		"gaps": len(manifest.Gaps),
	}
	for key, count := range expected {
		if manifest.Counts[key] != count {
			return fmt.Errorf("registry count mismatch for %s", key)
		}
	}
	componentIDs := make(map[string]struct{}, len(manifest.Components))
	sourceIDs := make(map[string]struct{}, len(manifest.Sources))
	versionOwners := make(map[string]string, len(manifest.Versions))
	occurrenceIDs := make(map[string]struct{}, len(manifest.Occurrences))
	edgeIDs := make(map[string]struct{}, len(manifest.DependencyEdges))
	gapIDs := make(map[string]struct{}, len(manifest.Gaps))
	for _, source := range manifest.Sources {
		if source.SourceID == "" || source.SourceType == "" || source.EvidenceURI == "" {
			return errors.New("registry contains an invalid source")
		}
		if source.ContentHash != "" && !sha256Pattern.MatchString(source.ContentHash) {
			return fmt.Errorf("source %s has an invalid content hash", source.SourceID)
		}
		if _, duplicate := sourceIDs[source.SourceID]; duplicate {
			return fmt.Errorf("duplicate source %s", source.SourceID)
		}
		sourceIDs[source.SourceID] = struct{}{}
	}
	for _, component := range manifest.Components {
		if component.ComponentID == "" || component.Name == "" {
			return errors.New("registry contains an invalid component")
		}
		if _, duplicate := componentIDs[component.ComponentID]; duplicate {
			return fmt.Errorf("duplicate component %s", component.ComponentID)
		}
		componentIDs[component.ComponentID] = struct{}{}
	}
	for _, version := range manifest.Versions {
		if _, exists := componentIDs[version.ComponentID]; !exists || version.ComponentVersionID == "" {
			return fmt.Errorf("version %s has an unknown component", version.ComponentVersionID)
		}
		if _, duplicate := versionOwners[version.ComponentVersionID]; duplicate {
			return fmt.Errorf("duplicate version %s", version.ComponentVersionID)
		}
		versionOwners[version.ComponentVersionID] = version.ComponentID
	}
	for _, occurrence := range manifest.Occurrences {
		if versionOwners[occurrence.ComponentVersionID] != occurrence.ComponentID || occurrence.OccurrenceID == "" {
			return fmt.Errorf("occurrence %s has inconsistent component/version identity", occurrence.OccurrenceID)
		}
		if _, exists := sourceIDs[occurrence.SourceID]; !exists {
			return fmt.Errorf("occurrence %s has an unknown source", occurrence.OccurrenceID)
		}
		if _, duplicate := occurrenceIDs[occurrence.OccurrenceID]; duplicate {
			return fmt.Errorf("duplicate occurrence %s", occurrence.OccurrenceID)
		}
		occurrenceIDs[occurrence.OccurrenceID] = struct{}{}
	}
	for _, edge := range manifest.DependencyEdges {
		if edge.EdgeID == "" {
			return errors.New("registry contains an edge without an ID")
		}
		if _, duplicate := edgeIDs[edge.EdgeID]; duplicate {
			return fmt.Errorf("duplicate edge %s", edge.EdgeID)
		}
		edgeIDs[edge.EdgeID] = struct{}{}
		if _, ok := versionOwners[edge.FromComponentVersionID]; !ok {
			return fmt.Errorf("edge %s has unknown source version", edge.EdgeID)
		}
		if _, ok := versionOwners[edge.ToComponentVersionID]; !ok {
			return fmt.Errorf("edge %s has unknown target version", edge.EdgeID)
		}
		if _, ok := occurrenceIDs[edge.SourceOccurrenceID]; !ok {
			return fmt.Errorf("edge %s has unknown evidence occurrence", edge.EdgeID)
		}
	}
	for _, gap := range manifest.Gaps {
		if gap.GapID == "" || gap.GapType == "" || gap.Message == "" {
			return errors.New("registry contains an invalid gap")
		}
		if _, duplicate := gapIDs[gap.GapID]; duplicate {
			return fmt.Errorf("duplicate gap %s", gap.GapID)
		}
		gapIDs[gap.GapID] = struct{}{}
		if gap.ComponentID != "" {
			if _, exists := componentIDs[gap.ComponentID]; !exists {
				return fmt.Errorf("gap %s has an unknown component", gap.GapID)
			}
		}
	}
	return nil
}

func validateManifestEnvelope(manifest *registryManifest) error {
	authority := manifest.AuthorityBoundary
	if authority.ReviewState != "unreviewed" || !explicitlyFalse(authority.Authoritative) ||
		!explicitlyFalse(authority.CompileEligible) || !explicitlyFalse(authority.ProductionMutation) ||
		!explicitlyFalse(authority.PromoteEligible) || !explicitlyFalse(authority.RetrievalRelease) ||
		!explicitlyFalse(authority.SourceAdmission) {
		return errors.New("registry authority_boundary must remain unreviewed and deny admission, release, and mutation")
	}
	if !knownRegistryBounds(manifest.Bounds) {
		return errors.New("registry bounds match no known producer envelope")
	}
	if manifest.Generator == nil || manifest.InputSet == nil || manifest.Counts == nil ||
		manifest.Completeness == nil || manifest.Reconciliation == nil || manifest.Integrity == nil ||
		manifest.Sources == nil || manifest.Components == nil || manifest.Versions == nil ||
		manifest.Occurrences == nil || manifest.DependencyEdges == nil || manifest.Gaps == nil {
		return errors.New("registry is missing a required v2 envelope field")
	}
	if observation := manifest.Observation; observation != nil {
		if !registryTimestamp.MatchString(observation.ObservedAt) ||
			!registryTimestamp.MatchString(observation.SourceValidAt) ||
			observation.SourceValidTimeBasis != "git-commit-committer-time" {
			return errors.New("registry observation is invalid")
		}
	}
	if lineage := manifest.MergeLineage; lineage != nil {
		if lineage.SelectionPolicy != "latest-observed-at-then-manifest-id-v1" || len(lineage.InputManifestIDs) == 0 {
			return errors.New("registry merge_lineage is invalid")
		}
		for index, manifestID := range lineage.InputManifestIDs {
			if !manifestIDPattern.MatchString(manifestID) || (index > 0 && lineage.InputManifestIDs[index-1] >= manifestID) {
				return errors.New("registry merge_lineage.input_manifest_ids must be valid, unique, and sorted")
			}
		}
		if lineage.CurrentManifestID != nil {
			if manifest.Observation == nil || !manifestIDPattern.MatchString(*lineage.CurrentManifestID) ||
				!sortedStringsContain(lineage.InputManifestIDs, *lineage.CurrentManifestID) {
				return errors.New("registry merge_lineage.current_manifest_id is invalid")
			}
		}
		if !equalOptionalStrings(lineage.PreviousManifestID, manifest.BaseManifestID) {
			return errors.New("registry merge_lineage.previous_manifest_id does not match base_manifest_id")
		}
	}
	return nil
}

func explicitlyFalse(value *bool) bool {
	return value != nil && !*value
}

func sortedStringsContain(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func equalOptionalStrings(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func manifestHashPreimage(manifest *registryManifest) map[string]any {
	integrity := cloneJSONMap(manifest.Integrity)
	delete(integrity, "manifest_hash")
	preimage := map[string]any{
		"$schema":            manifest.JSONSchema,
		"authority_boundary": manifest.AuthorityBoundary,
		"base_manifest_id":   manifest.BaseManifestID,
		"bounds":             manifest.Bounds,
		"completeness":       manifest.Completeness,
		"components":         manifest.Components,
		"counts":             manifest.Counts,
		"dependency_edges":   manifest.DependencyEdges,
		"gaps":               manifest.Gaps,
		"generation_state":   manifest.GenerationState,
		"generator":          manifest.Generator,
		"input_set":          manifest.InputSet,
		"integrity":          integrity,
		"manifest_version":   manifest.ManifestVersion,
		"occurrences":        manifest.Occurrences,
		"reconciliation":     manifest.Reconciliation,
		"record_kind":        manifest.RecordKind,
		"schema_version":     manifest.SchemaVersion,
		"sources":            manifest.Sources,
		"versions":           manifest.Versions,
	}
	if manifest.DiscoveryScope != nil {
		preimage["discovery_scope"] = manifest.DiscoveryScope
	}
	if manifest.MergeLineage != nil {
		preimage["merge_lineage"] = manifest.MergeLineage
	}
	if manifest.Observation != nil {
		preimage["observation"] = manifest.Observation
	}
	return preimage
}

func (manifest *registryManifest) buildIndexes() {
	manifest.sourceByID = make(map[string]*registrySource, len(manifest.Sources))
	manifest.componentByID = make(map[string]*registryComponent, len(manifest.Components))
	manifest.versionByID = make(map[string]*registryVersion, len(manifest.Versions))
	manifest.occurrenceByID = make(map[string]*registryOccurrence, len(manifest.Occurrences))
	manifest.gapByID = make(map[string]*registryGap, len(manifest.Gaps))
	manifest.versionsByComp = make(map[string][]registryVersion)
	manifest.occurrencesByComp = make(map[string][]registryOccurrence)
	manifest.gapsByComp = make(map[string][]registryGap)
	manifest.sourcesByComp = make(map[string][]registrySource)
	manifest.relationsFromComp = make(map[string][]registryRelation)
	manifest.relationsToComp = make(map[string][]registryRelation)
	for index := range manifest.Sources {
		source := &manifest.Sources[index]
		manifest.sourceByID[source.SourceID] = source
	}
	for index := range manifest.Components {
		component := &manifest.Components[index]
		manifest.componentByID[component.ComponentID] = component
	}
	for index := range manifest.Versions {
		version := &manifest.Versions[index]
		manifest.versionByID[version.ComponentVersionID] = version
		manifest.versionsByComp[version.ComponentID] = append(manifest.versionsByComp[version.ComponentID], *version)
	}
	for _, occurrence := range manifest.Occurrences {
		manifest.occurrencesByComp[occurrence.ComponentID] = append(manifest.occurrencesByComp[occurrence.ComponentID], occurrence)
	}
	for index := range manifest.Occurrences {
		occurrence := &manifest.Occurrences[index]
		manifest.occurrenceByID[occurrence.OccurrenceID] = occurrence
	}
	for index := range manifest.Gaps {
		gap := &manifest.Gaps[index]
		manifest.gapsByComp[gap.ComponentID] = append(manifest.gapsByComp[gap.ComponentID], *gap)
		manifest.gapByID[gap.GapID] = gap
	}
	manifest.buildSourceIndex()
	manifest.buildRelationIndex()
}

func (manifest *registryManifest) buildSourceIndex() {
	for componentID, occurrences := range manifest.occurrencesByComp {
		seen := make(map[string]struct{})
		for _, occurrence := range occurrences {
			if _, exists := seen[occurrence.SourceID]; exists {
				continue
			}
			seen[occurrence.SourceID] = struct{}{}
			if source := manifest.sourceByID[occurrence.SourceID]; source != nil {
				manifest.sourcesByComp[componentID] = append(manifest.sourcesByComp[componentID], *source)
			}
		}
		sort.Slice(manifest.sourcesByComp[componentID], func(i, j int) bool {
			return manifest.sourcesByComp[componentID][i].SourceID < manifest.sourcesByComp[componentID][j].SourceID
		})
	}
}

func (manifest *registryManifest) buildRelationIndex() {
	groups := make(map[registryRelationKey]*registryRelation)
	for _, edge := range manifest.DependencyEdges {
		fromVersion := manifest.versionByID[edge.FromComponentVersionID]
		toVersion := manifest.versionByID[edge.ToComponentVersionID]
		if fromVersion == nil || toVersion == nil {
			continue
		}
		key := registryRelationKey{
			FromComponentID: fromVersion.ComponentID,
			ToComponentID:   toVersion.ComponentID,
			Relationship:    edge.Relationship,
			Scope:           edge.Scope,
			Optional:        edge.Optional,
		}
		relation := groups[key]
		if relation == nil {
			relation = &registryRelation{
				FromComponentID: fromVersion.ComponentID,
				ToComponentID:   toVersion.ComponentID,
				Relationship:    edge.Relationship,
				Scope:           edge.Scope,
				Optional:        edge.Optional,
			}
			groups[key] = relation
		}
		relation.EdgeCount++
		if len(relation.EvidenceOccurrences) < 8 {
			relation.EvidenceOccurrences = append(relation.EvidenceOccurrences, edge.SourceOccurrenceID)
		}
	}
	for _, relation := range groups {
		manifest.relationsFromComp[relation.FromComponentID] = append(manifest.relationsFromComp[relation.FromComponentID], *relation)
		manifest.relationsToComp[relation.ToComponentID] = append(manifest.relationsToComp[relation.ToComponentID], *relation)
	}
	for _, relations := range []map[string][]registryRelation{manifest.relationsFromComp, manifest.relationsToComp} {
		for componentID := range relations {
			sort.Slice(relations[componentID], func(i, j int) bool {
				return relationLess(relations[componentID][i], relations[componentID][j])
			})
		}
	}
}

func relationLess(left, right registryRelation) bool {
	if left.FromComponentID != right.FromComponentID {
		return left.FromComponentID < right.FromComponentID
	}
	if left.ToComponentID != right.ToComponentID {
		return left.ToComponentID < right.ToComponentID
	}
	if left.Relationship != right.Relationship {
		return left.Relationship < right.Relationship
	}
	if left.Scope != right.Scope {
		return left.Scope < right.Scope
	}
	return !left.Optional && right.Optional
}

func validatePointer(pointer *generationPointer) error {
	if pointer.SchemaVersion != "2.0.0" || pointer.RecordKind != "generation_pointer" || pointer.Revision < 1 {
		return errors.New("generation pointer shape is invalid")
	}
	if !pointerIDPattern.MatchString(pointer.PointerID) || !manifestIDPattern.MatchString(pointer.CurrentManifestID) || !sha256Pattern.MatchString(pointer.CurrentManifestHash) || !receiptIDPattern.MatchString(pointer.TransitionReceiptID) {
		return errors.New("generation pointer identities are invalid")
	}
	if (pointer.PreviousManifestID == nil) != (pointer.PreviousManifestHash == nil) {
		return errors.New("generation pointer previous ID/hash nullability differs")
	}
	if pointer.PreviousManifestID != nil && (!manifestIDPattern.MatchString(*pointer.PreviousManifestID) || !sha256Pattern.MatchString(*pointer.PreviousManifestHash)) {
		return errors.New("generation pointer previous binding is invalid")
	}
	if _, err := parseGenerationTimestamp(pointer.UpdatedAt); err != nil {
		return err
	}
	var generic map[string]any
	raw, _ := json.Marshal(pointer)
	if err := decodeStrict(raw, &generic); err != nil {
		return err
	}
	delete(generic, "pointer_id")
	hash, err := canonicalHash(generic)
	if err != nil || pointer.PointerID != "ptr-"+strings.TrimPrefix(hash, "sha256:") {
		return errors.New("generation pointer content identity is invalid")
	}
	return nil
}

func verifyReceiptBinding(stateDir string, pointer *generationPointer, trustedPolicyPath string, trustedPolicy []byte, trustedPolicyHash string, recorder *artifactRecorder) error {
	path := filepath.Join(stateDir, "receipts", pointer.TransitionReceiptID+".json")
	raw, err := readBoundRegular(path, maxControlObjectBytes, true)
	if err != nil {
		return fmt.Errorf("read transition receipt: %w", err)
	}
	recorder.record(path, hashBytes(raw))
	var receipt map[string]any
	if err := decodeStrict(raw, &receipt); err != nil {
		return fmt.Errorf("decode transition receipt: %w", err)
	}
	if err := requireExactKeys(receipt, []string{
		"schema_version", "record_kind", "receipt_id", "decision",
		"rollback_of_receipt_id", "target_manifest_id", "target_manifest_hash",
		"prior_pointer_id", "prior_pointer_hash", "resulting_pointer_id",
		"resulting_pointer_hash", "transition_assertions", "removal_allowed",
		"removed", "authorization", "transitioned_at",
	}); err != nil {
		return fmt.Errorf("transition receipt shape: %w", err)
	}
	if receipt["schema_version"] != "2.0.0" || receipt["record_kind"] != "generation_transition_receipt" {
		return errors.New("transition receipt schema or kind is invalid")
	}
	decision, _ := receipt["decision"].(string)
	if decision != "promoted" && decision != "rolled_back" {
		return errors.New("transition receipt decision is invalid")
	}
	if receipt["receipt_id"] != pointer.TransitionReceiptID || receipt["resulting_pointer_id"] != pointer.PointerID || receipt["target_manifest_id"] != pointer.CurrentManifestID || receipt["target_manifest_hash"] != pointer.CurrentManifestHash || receipt["transitioned_at"] != pointer.UpdatedAt {
		return errors.New("transition receipt does not bind the selected pointer and manifest")
	}
	resultHash, _ := receipt["resulting_pointer_hash"].(string)
	if resultHash != "sha256:"+strings.TrimPrefix(pointer.PointerID, "ptr-") {
		return errors.New("transition receipt resulting pointer hash is invalid")
	}
	preimage := cloneJSONMap(receipt)
	delete(preimage, "receipt_id")
	delete(preimage, "resulting_pointer_id")
	delete(preimage, "resulting_pointer_hash")
	hash, err := canonicalHash(preimage)
	if err != nil || pointer.TransitionReceiptID != "prc-"+strings.TrimPrefix(hash, "sha256:") {
		return errors.New("transition receipt content identity is invalid")
	}
	if err := verifyReceiptAuthorization(stateDir, receipt, trustedPolicyPath, trustedPolicy, trustedPolicyHash, recorder); err != nil {
		return err
	}
	return verifyReceiptPriorBinding(stateDir, pointer, receipt, recorder)
}

func verifyReceiptAuthorization(stateDir string, receipt map[string]any, trustedPolicyPath string, trustedPolicy []byte, trustedPolicyHash string, recorder *artifactRecorder) error {
	authorization, ok := receipt["authorization"].(map[string]any)
	if !ok {
		return errors.New("transition receipt authorization is missing")
	}
	if err := requireExactKeys(authorization, []string{
		"actor", "method", "key_id", "namespace", "authorization_policy_hash",
		"signed_payload_hash", "signature",
	}); err != nil {
		return fmt.Errorf("transition receipt authorization shape: %w", err)
	}
	actor, _ := authorization["actor"].(string)
	method, _ := authorization["method"].(string)
	keyID, _ := authorization["key_id"].(string)
	namespace, _ := authorization["namespace"].(string)
	policyHash, _ := authorization["authorization_policy_hash"].(string)
	signedPayloadHash, _ := authorization["signed_payload_hash"].(string)
	signature, _ := authorization["signature"].(string)
	if actor == "" || strings.IndexFunc(actor, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) >= 0 {
		return errors.New("transition receipt actor is invalid")
	}
	if method != generationSignatureMethod || namespace != generationSignatureNamespace {
		return errors.New("transition receipt signature method or namespace is invalid")
	}
	if !sshFingerprintPattern.MatchString(keyID) || !sha256Pattern.MatchString(policyHash) || !sha256Pattern.MatchString(signedPayloadHash) {
		return errors.New("transition receipt authorization identity is invalid")
	}
	if len(signature) > int(maxControlObjectBytes) || !sshSignaturePattern.MatchString(normalizeSignature(signature)) {
		return errors.New("transition receipt SSHSIG armor is invalid")
	}

	signedPayload := cloneJSONMap(receipt)
	delete(signedPayload, "receipt_id")
	delete(signedPayload, "resulting_pointer_id")
	delete(signedPayload, "resulting_pointer_hash")
	signedAuthorization, ok := signedPayload["authorization"].(map[string]any)
	if !ok {
		return errors.New("transition receipt signed authorization is invalid")
	}
	delete(signedAuthorization, "signature")
	delete(signedAuthorization, "signed_payload_hash")
	payload, err := canonicalJSON(signedPayload)
	if err != nil {
		return fmt.Errorf("encode signed transition payload: %w", err)
	}
	if hashBytes(payload) != signedPayloadHash {
		return errors.New("transition receipt signed payload hash is invalid")
	}

	policyPath := filepath.Join(stateDir, "policies", strings.TrimPrefix(policyHash, "sha256:")+".allowed_signers")
	policy, err := readBoundRegular(policyPath, maxControlObjectBytes, true)
	if err != nil {
		return fmt.Errorf("read persisted allowed-signers policy: %w", err)
	}
	if hashBytes(policy) != policyHash || trustedPolicyHash != policyHash || !bytes.Equal(policy, trustedPolicy) {
		return errors.New("persisted allowed-signers policy does not match the external operator trust root")
	}
	trustedInfo, trustedErr := os.Lstat(trustedPolicyPath)
	persistedInfo, persistedErr := os.Lstat(policyPath)
	if trustedErr != nil || persistedErr != nil || os.SameFile(trustedInfo, persistedInfo) {
		return errors.New("persisted policy and external operator trust root must be independent files")
	}
	if err := verifySSHSignature(payload, []byte(normalizeSignature(signature)), trustedPolicy, actor, keyID); err != nil {
		return fmt.Errorf("verify transition receipt signature: %w", err)
	}
	recorder.record(policyPath, hashBytes(policy))
	return nil
}

func verifyReceiptPriorBinding(stateDir string, pointer *generationPointer, receipt map[string]any, recorder *artifactRecorder) error {
	priorID, priorIDOK := receipt["prior_pointer_id"].(string)
	priorHash, priorHashOK := receipt["prior_pointer_hash"].(string)
	if receipt["prior_pointer_id"] == nil && receipt["prior_pointer_hash"] == nil {
		if pointer.Revision != 1 || pointer.PreviousManifestID != nil || pointer.PreviousManifestHash != nil {
			return errors.New("bootstrap pointer has an invalid revision or previous binding")
		}
		return nil
	}
	if !priorIDOK || !priorHashOK || !pointerIDPattern.MatchString(priorID) || !sha256Pattern.MatchString(priorHash) {
		return errors.New("transition receipt prior pointer binding is invalid")
	}
	priorPath := filepath.Join(stateDir, "pointers", priorID+".json")
	priorRaw, err := readBoundRegular(priorPath, maxControlObjectBytes, true)
	if err != nil {
		return fmt.Errorf("read prior pointer: %w", err)
	}
	recorder.record(priorPath, hashBytes(priorRaw))
	var prior generationPointer
	if err := decodeStrictTyped(priorRaw, &prior); err != nil {
		return fmt.Errorf("decode prior pointer: %w", err)
	}
	if err := validatePointer(&prior); err != nil {
		return fmt.Errorf("validate prior pointer: %w", err)
	}
	if prior.PointerID != priorID || "sha256:"+strings.TrimPrefix(prior.PointerID, "ptr-") != priorHash {
		return errors.New("transition receipt prior pointer content binding is invalid")
	}
	if pointer.Revision != prior.Revision+1 || pointer.PreviousManifestID == nil || pointer.PreviousManifestHash == nil || *pointer.PreviousManifestID != prior.CurrentManifestID || *pointer.PreviousManifestHash != prior.CurrentManifestHash {
		return errors.New("selected pointer is not derived from its prior pointer")
	}
	if pointer.UpdatedAt <= prior.UpdatedAt {
		return errors.New("selected pointer timestamp is not monotonic")
	}
	return nil
}

func requireExactKeys(value map[string]any, expected []string) error {
	if len(value) != len(expected) {
		return errors.New("object keys differ")
	}
	for _, key := range expected {
		if _, exists := value[key]; !exists {
			return fmt.Errorf("missing key %s", key)
		}
	}
	return nil
}

func parseGenerationTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, errors.New("generation timestamp is not canonical UTC to whole seconds")
	}
	return parsed, nil
}

func normalizeSignature(value string) string {
	return strings.TrimSpace(value) + "\n"
}

func verifySSHSignature(payload, signature, policy []byte, actor, keyID string) error {
	if err := validateSSHKeygen(); err != nil {
		return err
	}
	signatureFile, err := immutableExecInput("archeion-knowledge-signature-", signature)
	if err != nil {
		return fmt.Errorf("isolate SSHSIG bytes: %w", err)
	}
	defer signatureFile.Close()
	policyFile, err := immutableExecInput("archeion-knowledge-policy-", policy)
	if err != nil {
		return fmt.Errorf("isolate allowed-signers bytes: %w", err)
	}
	defer policyFile.Close()

	inspectOutput, err := runSSHKeygen(payload, []*os.File{signatureFile}, "-Y", "check-novalidate", "-n", generationSignatureNamespace, "-s", "/proc/self/fd/3")
	if err != nil {
		return fmt.Errorf("inspect SSHSIG: %w", err)
	}
	if !strings.Contains(strings.ToUpper(inspectOutput), "ED25519") || !strings.Contains(inspectOutput, keyID) {
		return errors.New("SSHSIG key type or fingerprint differs from the receipt")
	}
	if _, err := signatureFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := policyFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := runSSHKeygen(payload, []*os.File{policyFile, signatureFile}, "-Y", "verify", "-f", "/proc/self/fd/3", "-I", actor, "-n", generationSignatureNamespace, "-s", "/proc/self/fd/4"); err != nil {
		return fmt.Errorf("allowed-signers verification failed: %w", err)
	}
	return nil
}

func immutableExecInput(prefix string, data []byte) (*os.File, error) {
	file, err := os.CreateTemp("", prefix)
	if err != nil {
		return nil, err
	}
	path := file.Name()
	if err := os.Remove(path); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Chmod(0o400); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateSSHKeygen() error {
	if err := validateDirectoryPathNoSymlinks(filepath.Dir(sshKeygenPath)); err != nil {
		return fmt.Errorf("validate fixed ssh-keygen parent: %w", err)
	}
	info, err := os.Lstat(sshKeygenPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("fixed ssh-keygen verifier is unavailable or unsafe")
	}
	return nil
}

func runSSHKeygen(payload []byte, extraFiles []*os.File, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, sshKeygenPath, arguments...)
	command.ExtraFiles = extraFiles
	command.Stdin = bytes.NewReader(payload)
	var output boundedBuffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if ctx.Err() != nil {
		return output.String(), errors.New("ssh-keygen timed out")
	}
	if err != nil {
		return output.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(output.String()))
	}
	return output.String(), nil
}

type boundedBuffer struct {
	value    bytes.Buffer
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := maxSignatureCommandOutput - buffer.value.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			buffer.overflow = true
		}
		_, _ = buffer.value.Write(value)
	} else {
		buffer.overflow = true
	}
	return original, nil
}

func (buffer *boundedBuffer) String() string {
	if buffer.overflow {
		return buffer.value.String() + " [output truncated]"
	}
	return buffer.value.String()
}

func manifestHash(manifest *registryManifest) string {
	value, _ := manifest.Integrity["manifest_hash"].(string)
	return value
}

func canonicalHash(value any) (string, error) {
	digest := sha256.New()
	writer := canonicalDigestWriter{destination: digest, buffer: make([]byte, 0, 64<<10)}
	encoder := json.NewEncoder(&writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	if err := writer.finish(); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

// canonicalDigestWriter hashes the same bytes as canonicalJSON without
// retaining another full encoded copy of a potentially hundreds-of-megabytes
// manifest. encoding/json already constructs an encode buffer internally; a
// bounded transform here avoids an additional large bytes.Buffer and the two
// whole-buffer U+2028/U+2029 replacement allocations.
type canonicalDigestWriter struct {
	destination io.Writer
	buffer      []byte
}

func (writer *canonicalDigestWriter) Write(value []byte) (int, error) {
	original := len(value)
	for len(value) > 0 {
		space := cap(writer.buffer) - len(writer.buffer)
		if space == 0 {
			if err := writer.flushKeeping(16); err != nil {
				return 0, err
			}
			space = cap(writer.buffer) - len(writer.buffer)
		}
		count := len(value)
		if count > space {
			count = space
		}
		writer.buffer = append(writer.buffer, value[:count]...)
		value = value[count:]
		if len(writer.buffer) == cap(writer.buffer) {
			if err := writer.flushKeeping(16); err != nil {
				return 0, err
			}
		}
	}
	return original, nil
}

func (writer *canonicalDigestWriter) finish() error {
	if len(writer.buffer) > 0 && writer.buffer[len(writer.buffer)-1] == '\n' {
		writer.buffer = writer.buffer[:len(writer.buffer)-1]
	}
	if err := writeCanonicalDigestBytes(writer.destination, writer.buffer); err != nil {
		return err
	}
	writer.buffer = writer.buffer[:0]
	return nil
}

func (writer *canonicalDigestWriter) flushKeeping(keep int) error {
	if len(writer.buffer) <= keep {
		return nil
	}
	cut := len(writer.buffer) - keep
	patterns := [][]byte{[]byte(`\u2028`), []byte(`\u2029`)}
	start := cut - 5
	if start < 0 {
		start = 0
	}
	for index := start; index < cut; index++ {
		for _, pattern := range patterns {
			if index+len(pattern) > cut && index+len(pattern) <= len(writer.buffer) && bytes.Equal(writer.buffer[index:index+len(pattern)], pattern) {
				cut = index
				break
			}
		}
	}
	if err := writeCanonicalDigestBytes(writer.destination, writer.buffer[:cut]); err != nil {
		return err
	}
	copy(writer.buffer, writer.buffer[cut:])
	writer.buffer = writer.buffer[:len(writer.buffer)-cut]
	return nil
}

func writeCanonicalDigestBytes(destination io.Writer, value []byte) error {
	patterns := []struct {
		escaped []byte
		utf8    []byte
	}{
		{escaped: []byte(`\u2028`), utf8: []byte("\u2028")},
		{escaped: []byte(`\u2029`), utf8: []byte("\u2029")},
	}
	for len(value) > 0 {
		index := bytes.IndexByte(value, '\\')
		if index < 0 {
			_, err := destination.Write(value)
			return err
		}
		if index > 0 {
			if _, err := destination.Write(value[:index]); err != nil {
				return err
			}
			value = value[index:]
		}
		replaced := false
		for _, pattern := range patterns {
			if bytes.HasPrefix(value, pattern.escaped) {
				if _, err := destination.Write(pattern.utf8); err != nil {
					return err
				}
				value = value[len(pattern.escaped):]
				replaced = true
				break
			}
		}
		if replaced {
			continue
		}
		if _, err := destination.Write(value[:1]); err != nil {
			return err
		}
		value = value[1:]
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	raw := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	raw = bytes.ReplaceAll(raw, []byte(`\u2028`), []byte("\u2028"))
	raw = bytes.ReplaceAll(raw, []byte(`\u2029`), []byte("\u2029"))
	return raw, nil
}

func cloneJSONMap(value map[string]any) map[string]any {
	raw, _ := json.Marshal(value)
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&result)
	return result
}

func reviewedAvailableChannels(channels []map[string]any) int {
	count := 0
	for _, channel := range channels {
		review, _ := channel["review_state"].(string)
		state, _ := channel["availability_state"].(string)
		uri, _ := channel["canonical_uri"].(string)
		// Authority is explicit: a URI alone does not turn a proposal,
		// unresolved channel or needs-review record into reviewed authority.
		if review == "accepted" && state == "available" && uri != "" {
			count++
		}
	}
	return count
}

func manifestIsComplete(manifest *registryManifest) (bool, string) {
	if manifest == nil {
		return false, "manifest is missing"
	}
	if manifest.Completeness["all_axes_complete"] != true {
		return false, "completeness.all_axes_complete is not true"
	}
	for _, axis := range []string{"input", "enumeration", "closure", "identity", "channel_review", "snapshots"} {
		value, ok := manifest.Completeness[axis].(map[string]any)
		if !ok || value["state"] != "complete" {
			return false, "completeness." + axis + " is not complete"
		}
	}
	if manifest.Reconciliation["complete_mark"] != true {
		return false, "reconciliation.complete_mark is not true"
	}
	if manifest.Reconciliation["removal_allowed"] != false {
		return false, "reconciliation.removal_allowed is not false"
	}
	removed, ok := manifest.Reconciliation["removed"].([]any)
	if !ok || len(removed) != 0 {
		return false, "reconciliation.removed is not empty"
	}
	return true, "complete"
}

func componentLess(left, right *registryComponent) bool {
	if left.Ecosystem != right.Ecosystem {
		return left.Ecosystem < right.Ecosystem
	}
	if left.Namespace != right.Namespace {
		return left.Namespace < right.Namespace
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	return left.ComponentID < right.ComponentID
}
