package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func fixtureManifest(t *testing.T, complete bool) *registryManifest {
	t.Helper()
	denied := false
	source := registrySource{
		ContentHash: "sha256:" + strings.Repeat("1", 64),
		EvidenceURI: "docs/argocd/README.md",
		SourceID:    "src-test",
		SourceType:  "repository-file",
	}
	component := registryComponent{
		ComponentID: "cmp-test", Ecosystem: "git", Kind: "application",
		Lifecycles: []string{"deployed"}, Name: "argo-cd", Namespace: "argoproj",
		OfficialChannels: []map[string]any{}, PURL: "pkg:github/argoproj/argo-cd",
	}
	version := registryVersion{
		ComponentID: "cmp-test", ComponentVersionID: "ver-test",
		ResolvedVersion: "v3.5.0", ResolutionState: "resolved",
		Evidence: []string{"docs/argocd/README.md"},
	}
	occurrence := registryOccurrence{
		ComponentID: "cmp-test", ComponentVersionID: "ver-test",
		DependencyScope: "runtime", Directness: "direct",
		EvidenceLocator: "docs/argocd/README.md:1", Lifecycle: "deployed",
		OccurrenceID: "occ-test", Optional: false, RawValue: "v3.5.0",
		Role: "application", SourceID: "src-test",
	}
	axisState := "gapped"
	allAxesComplete := false
	completeMark := false
	if complete {
		axisState = "complete"
		allAxesComplete = true
		completeMark = true
	}
	completeness := map[string]any{
		"all_axes_complete": allAxesComplete,
		"input": map[string]any{
			"state": axisState, "input_count": 0, "blocking_input_ids": []any{},
		},
		"enumeration": map[string]any{"state": axisState},
		"closure": map[string]any{
			"state": axisState, "blocking_gap_ids": []any{},
		},
		"identity": map[string]any{
			"state": axisState, "blocking_gap_ids": []any{},
		},
		"channel_review": map[string]any{
			"state": axisState, "required_slots": 0, "accepted_slots": 0,
		},
		"snapshots": map[string]any{
			"state": axisState, "accepted_available_channels": 0,
			"immutable_verified_channels": 0, "missing_channel_ids": []any{},
		},
	}
	manifest := &registryManifest{
		JSONSchema: "https://json-schema.org/draft/2020-12/schema",
		AuthorityBoundary: registryAuthorityBoundary{
			Authoritative: &denied, CompileEligible: &denied, ProductionMutation: &denied,
			PromoteEligible: &denied, RetrievalRelease: &denied, ReviewState: "unreviewed",
			SourceAdmission: &denied,
		},
		Bounds: registryBounds{
			Components: 100_000, DependencyEdges: 400_000,
			DiscoveryFileBytes: 8 << 20, DiscoveryFiles: 10_000, DiscoveryTotalBytes: 128 << 20,
			Gaps: 400_000, JSONDepth: 128, JSONInputBytes: 512 << 20, JSONNodes: 10_000_000,
			Occurrences: 400_000, SerializedOutputBytes: 512 << 20, Sources: 100_000,
			TrackedFiles: 20_000, Versions: 200_000,
		},
		SchemaVersion: "2.0.0", RecordKind: "generated_discovery_manifest",
		ManifestVersion: 2, GenerationState: "candidate", BaseManifestID: nil,
		Counts: map[string]int{
			"sources": 1, "components": 1, "versions": 1, "occurrences": 1,
			"dependency_edges": 0, "gaps": 0,
		},
		Completeness: completeness,
		Reconciliation: map[string]any{
			"added": []any{}, "changed": []any{}, "complete_mark": completeMark,
			"missing": []any{}, "previous_manifest_id": nil,
			"removal_allowed": false, "removed": []any{},
		},
		Integrity: map[string]any{
			"canonicalization":    "archeion-canonical-json-v1",
			"deterministic_order": true,
		},
		Generator: map[string]any{
			"name": "test", "version": "1", "source_ref": "tools/knowledge-mcp/registry_test.go",
			"schema_hash":  "sha256:" + strings.Repeat("2", 64),
			"ruleset_hash": "sha256:" + strings.Repeat("3", 64),
		},
		InputSet: map[string]any{"required_source_classes": []any{}, "entries": []any{}},
		Observation: &registryObservation{
			ObservedAt: "2026-07-21T12:00:01Z", SourceValidAt: "2026-07-21T12:00:00Z",
			SourceValidTimeBasis: "git-commit-committer-time",
		},
		Sources: []registrySource{source}, Components: []registryComponent{component},
		Versions: []registryVersion{version}, Occurrences: []registryOccurrence{occurrence},
		DependencyEdges: []registryEdge{}, Gaps: []registryGap{},
	}
	sealFixtureManifest(t, manifest)
	return manifest
}

func sealFixtureManifest(t *testing.T, manifest *registryManifest) {
	t.Helper()
	delete(manifest.Integrity, "manifest_hash")
	manifest.ManifestID = ""
	hash, err := canonicalHash(manifestHashPreimage(manifest))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Integrity["manifest_hash"] = hash
	manifest.ManifestID = "mft-" + strings.TrimPrefix(hash, "sha256:")
	manifest.buildIndexes()
}

func writeManifest(t *testing.T, path string, manifest *registryManifest) {
	t.Helper()
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDirectCandidateIsAlwaysPartial(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	manifest := fixtureManifest(t, true)
	writeManifest(t, path, manifest)
	provider := newRegistryProvider(config{registryPath: path, maxRegistrySize: defaultMaxRegistryBytes})
	if provider.direct != nil {
		t.Fatal("direct candidate loaded eagerly")
	}
	snapshot := provider.snapshot()
	if snapshot.state != statePartial || snapshot.mode != "candidate" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if snapshot.current == nil || snapshot.current.ManifestID != manifest.ManifestID {
		t.Fatal("candidate identity was not retained")
	}
	if provider.snapshot() != snapshot {
		t.Fatal("immutable candidate snapshot was not cached")
	}
}

func TestCurrentV2EnvelopeAndRetiredFields(t *testing.T) {
	manifest := fixtureManifest(t, false)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"authority_boundary", "bounds", "observation"} {
		if _, exists := envelope[field]; !exists {
			t.Fatalf("current v2 envelope omitted %s", field)
		}
	}
	for _, retired := range []string{"official_resolution_runs", "official_resolution_summary"} {
		if _, exists := envelope[retired]; exists {
			t.Fatalf("retired v2 field %s was serialized", retired)
		}
	}
	if len(manifest.Counts) != maxRegistryCountKeys {
		t.Fatalf("manifest count shape drifted: %#v", manifest.Counts)
	}

	manifest.AuthorityBoundary.CompileEligible = nil
	if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), "authority_boundary") {
		t.Fatalf("missing fail-closed authority field was accepted: %v", err)
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "retired-field.json")
	envelope["official_resolution_runs"] = []any{}
	retiredRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, retiredRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRegistryManifest(path, defaultMaxRegistryBytes); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("retired top-level field was accepted: %v", err)
	}
}

func TestDefaultRegistryBoundFitsCurrentCandidateClass(t *testing.T) {
	if defaultMaxRegistryBytes < 512<<20 {
		t.Fatalf("default registry limit %d is below the 512 MiB P1 bound", defaultMaxRegistryBytes)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "oversized")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(defaultMaxRegistryBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if _, err := loadRegistryManifest(path, defaultMaxRegistryBytes); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded rejection, got %v", err)
	}
}

func TestStreamingCanonicalHashMatchesCanonicalJSON(t *testing.T) {
	value := map[string]any{
		"html":    "<>&",
		"literal": `\u2028 and \u2029`,
		"nested":  []any{map[string]any{"z": "line\u2028separator", "a": "paragraph\u2029separator"}},
	}
	raw, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	want := hashBytes(raw)
	got, err := canonicalHash(value)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("streaming canonical hash mismatch: got %s, want %s", got, want)
	}
}

func TestManifestResourceBoundsRunBeforeCanonicalHash(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*registryManifest)
		want   string
	}{
		{
			name: "oversized numeric metadata",
			mutate: func(manifest *registryManifest) {
				manifest.Sources[0].Metadata = map[string]any{
					"number": json.Number(strings.Repeat("9", maxRegistryStringBytes+1)),
				}
			},
			want: "string exceeds",
		},
		{
			name: "unknown count field",
			mutate: func(manifest *registryManifest) {
				delete(manifest.Counts, "gaps")
				manifest.Counts["unexpected"] = 0
			},
			want: "unknown field",
		},
		{
			name: "unknown reconciliation field",
			mutate: func(manifest *registryManifest) {
				manifest.Reconciliation["unexpected"] = []any{}
			},
			want: "reconciliation shape",
		},
		{
			name: "invalid base manifest",
			mutate: func(manifest *registryManifest) {
				value := "mft-invalid"
				manifest.BaseManifestID = &value
			},
			want: "base_manifest_id",
		},
		{
			name: "too many official channels",
			mutate: func(manifest *registryManifest) {
				manifest.Components[0].OfficialChannels = make([]map[string]any, maxRegistryChannelsPerComponent+1)
			},
			want: "official-channel count",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := fixtureManifest(t, true)
			test.mutate(manifest)
			err := validateManifest(manifest)
			if err == nil || !strings.Contains(err.Error(), "registry resource bounds") ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("resource amplification was not rejected before hashing: %v", err)
			}
			if strings.Contains(err.Error(), "content hash mismatch") {
				t.Fatalf("canonical hash ran before resource admission: %v", err)
			}
		})
	}
}

func TestCompactChangeRecordRejectsOversizedNumericValue(t *testing.T) {
	record, valid := compactChangeRecordBounded(map[string]any{
		"number": json.Number(strings.Repeat("9", maxRegistryStringBytes+1)),
	})
	if valid {
		t.Fatal("oversized numeric change record was accepted")
	}
	result, ok := record.(map[string]any)
	if !ok || result["state"] != "oversized_or_invalid" || result["truncated"] != true {
		t.Fatalf("unexpected bounded change marker: %#v", record)
	}
}

func TestHighCardinalityRelationIndexUsesBoundedEvidenceAndStableOrdering(t *testing.T) {
	manifest := fixtureManifest(t, true)
	manifest.Components = append(manifest.Components, registryComponent{
		ComponentID: "cmp-relation-target", Ecosystem: "test", Kind: "library",
		Lifecycles: []string{"planned"}, Name: "relation-target", OfficialChannels: []map[string]any{},
	})
	manifest.Versions = append(manifest.Versions, registryVersion{
		ComponentID: "cmp-relation-target", ComponentVersionID: "ver-relation-target",
	})
	const uniqueRelations = 10_000
	for index := 0; index < uniqueRelations; index++ {
		manifest.DependencyEdges = append(manifest.DependencyEdges, registryEdge{
			EdgeID: fmt.Sprintf("edge-cardinality-%05d", index), FromComponentVersionID: "ver-test",
			ToComponentVersionID: "ver-relation-target", Relationship: "depends_on",
			Scope: fmt.Sprintf("scope-%05d", index), SourceOccurrenceID: "occ-test",
		})
	}
	for index := 0; index < 9; index++ {
		manifest.DependencyEdges = append(manifest.DependencyEdges, registryEdge{
			EdgeID: fmt.Sprintf("edge-shared-%02d", index), FromComponentVersionID: "ver-test",
			ToComponentVersionID: "ver-relation-target", Relationship: "depends_on",
			Scope: "shared", SourceOccurrenceID: "occ-test",
		})
	}
	manifest.buildIndexes()
	relations := manifest.relationsFromComp["cmp-test"]
	if len(relations) != uniqueRelations+1 {
		t.Fatalf("unexpected concentrated relation groups: %d", len(relations))
	}
	for index := 1; index < len(relations); index++ {
		if relationLess(relations[index], relations[index-1]) {
			t.Fatalf("relations are not deterministically ordered at %d", index)
		}
	}
	shared := relations[len(relations)-1]
	if shared.Scope != "shared" || shared.EdgeCount != 9 || len(shared.EvidenceOccurrences) != 8 {
		t.Fatalf("grouped relation evidence was not bounded: %#v", shared)
	}
	less := false
	allocations := testing.AllocsPerRun(1_000, func() {
		less = relationLess(relations[0], relations[1])
	})
	if !less || allocations != 0 {
		t.Fatalf("relation comparator allocated or ordered incorrectly: less=%v allocs=%f", less, allocations)
	}
}

// signedStore is one fully verifiable signed generation store plus the exact
// artifact paths a verification bypass would have to survive.
type signedStore struct {
	stateDir          string
	trustedPolicyPath string
	policy            []byte
	policyHash        string
	policyPath        string
	receipt           map[string]any
	receiptPath       string
	pointerPath       string
	aliasPath         string
	manifestPath      string
}

func buildSignedStore(t *testing.T) signedStore {
	t.Helper()
	if _, err := os.Stat(sshKeygenPath); err != nil {
		t.Skip("ssh-keygen is required for signed generation verification")
	}
	stateDir := t.TempDir()
	for _, child := range []string{"manifests", "pointers", "receipts", "policies"} {
		if err := os.Mkdir(filepath.Join(stateDir, child), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := fixtureManifest(t, true)
	writeManifest(t, filepath.Join(stateDir, "manifests", manifest.ManifestID+".json"), manifest)

	keyPath := filepath.Join(t.TempDir(), "signing-key")
	command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate signing key: %v: %s", err, output)
	}
	public, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fingerprintOutput, err := exec.Command("ssh-keygen", "-lf", keyPath+".pub", "-E", "sha256").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	keyID := regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`).FindString(string(fingerprintOutput))
	if keyID == "" {
		t.Fatalf("fingerprint missing from %s", fingerprintOutput)
	}
	actor := "registry-test"
	policy := []byte(actor + " " + strings.TrimSpace(string(public)) + "\n")
	policyHash := hashBytes(policy)
	trustedPolicyPath := filepath.Join(t.TempDir(), "operator.allowed_signers")
	if err := os.WriteFile(trustedPolicyPath, policy, 0o400); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(stateDir, "policies", strings.TrimPrefix(policyHash, "sha256:")+".allowed_signers")
	if err := os.WriteFile(policyPath, policy, 0o400); err != nil {
		t.Fatal(err)
	}
	transitionedAt := "2026-07-16T12:00:00Z"
	intent := map[string]any{
		"schema_version": "2.0.0", "record_kind": "generation_transition_receipt",
		"decision": "promoted", "rollback_of_receipt_id": nil,
		"target_manifest_id": manifest.ManifestID, "target_manifest_hash": manifestHash(manifest),
		"prior_pointer_id": nil, "prior_pointer_hash": nil,
		"transition_assertions": map[string]any{
			"assertion_kind": "promotion", "target_manifest_hash_verified": true,
			"target_schema_validated": true, "target_semantic_validated": true,
			"target_generation_state": "candidate", "input": "complete",
			"enumeration": "complete", "closure": "complete", "identity": "complete",
			"channel_review": "complete", "snapshots": "complete", "promotable": true,
			"reconciliation_complete_mark": true, "candidate_removal_allowed": false,
			"base_binding": "bootstrap", "recomputed_diff_verified": true,
		},
		"removal_allowed": false, "removed": []any{},
		"authorization": map[string]any{
			"actor": actor, "method": generationSignatureMethod, "key_id": keyID,
			"namespace": generationSignatureNamespace, "authorization_policy_hash": policyHash,
		},
		"transitioned_at": transitionedAt,
	}
	payload, err := canonicalJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	sign := exec.Command("ssh-keygen", "-Y", "sign", "-f", keyPath, "-n", generationSignatureNamespace)
	sign.Stdin = bytes.NewReader(payload)
	signature, err := sign.Output()
	if err != nil {
		t.Fatal(err)
	}
	receipt := cloneJSONMap(intent)
	authorization := receipt["authorization"].(map[string]any)
	authorization["signed_payload_hash"] = hashBytes(payload)
	authorization["signature"] = normalizeSignature(string(signature))
	receiptPreimage := cloneJSONMap(receipt)
	receiptHash, err := canonicalHash(receiptPreimage)
	if err != nil {
		t.Fatal(err)
	}
	receiptID := "prc-" + strings.TrimPrefix(receiptHash, "sha256:")
	receipt["receipt_id"] = receiptID
	pointerMap := map[string]any{
		"schema_version": "2.0.0", "record_kind": "generation_pointer", "revision": 1,
		"current_manifest_id": manifest.ManifestID, "current_manifest_hash": manifestHash(manifest),
		"previous_manifest_id": nil, "previous_manifest_hash": nil,
		"transition_receipt_id": receiptID, "updated_at": transitionedAt,
	}
	pointerHash, err := canonicalHash(pointerMap)
	if err != nil {
		t.Fatal(err)
	}
	pointerID := "ptr-" + strings.TrimPrefix(pointerHash, "sha256:")
	pointerMap["pointer_id"] = pointerID
	receipt["resulting_pointer_id"] = pointerID
	receipt["resulting_pointer_hash"] = pointerHash
	writeJSON := func(path string, value any) {
		t.Helper()
		raw, marshalErr := canonicalJSON(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.WriteFile(path, append(raw, '\n'), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	writeJSON(filepath.Join(stateDir, "receipts", receiptID+".json"), receipt)
	writeJSON(filepath.Join(stateDir, "pointers", pointerID+".json"), pointerMap)
	writeJSON(filepath.Join(stateDir, "generation-pointer.json"), pointerMap)
	return signedStore{
		stateDir: stateDir, trustedPolicyPath: trustedPolicyPath,
		policy: policy, policyHash: policyHash, policyPath: policyPath,
		receipt: receipt, receiptPath: filepath.Join(stateDir, "receipts", receiptID+".json"),
		pointerPath:  filepath.Join(stateDir, "pointers", pointerID+".json"),
		aliasPath:    filepath.Join(stateDir, "generation-pointer.json"),
		manifestPath: filepath.Join(stateDir, "manifests", manifest.ManifestID+".json"),
	}
}

func TestSignedGenerationStoreAndForgedSignature(t *testing.T) {
	store := buildSignedStore(t)
	stateDir, trustedPolicyPath := store.stateDir, store.trustedPolicyPath
	policy, policyHash, receipt := store.policy, store.policyHash, store.receipt
	pointerID := strings.TrimSuffix(filepath.Base(store.pointerPath), ".json")

	missingTrustProvider := newRegistryProvider(config{stateDirectory: stateDir, maxRegistrySize: defaultMaxRegistryBytes})
	if missing := missingTrustProvider.snapshot(); missing.state != stateBackendUnavailable || !strings.Contains(missing.message, "external operator") {
		t.Fatalf("generation store accepted without external trust root: %#v", missing)
	}
	provider := newRegistryProvider(config{stateDirectory: stateDir, allowedSigners: trustedPolicyPath, maxRegistrySize: defaultMaxRegistryBytes})
	snapshot := provider.snapshot()
	if snapshot.state != stateOK || snapshot.pointer == nil || snapshot.pointer.PointerID != pointerID {
		t.Fatalf("signed store rejected: %#v", snapshot)
	}
	forged := cloneJSONMap(receipt)
	forgedAuthorization := forged["authorization"].(map[string]any)
	forgedAuthorization["signature"] = strings.Replace(forgedAuthorization["signature"].(string), "A", "B", 1)
	if err := verifyReceiptAuthorization(stateDir, forged, trustedPolicyPath, policy, policyHash, &artifactRecorder{}); err == nil {
		t.Fatal("forged SSH signature was accepted")
	}
	attackerPolicyPath := filepath.Join(stateDir, "policies", "attacker.allowed_signers")
	if err := os.WriteFile(attackerPolicyPath, policy, 0o400); err != nil {
		t.Fatal(err)
	}
	selfRootProvider := newRegistryProvider(config{stateDirectory: stateDir, allowedSigners: attackerPolicyPath, maxRegistrySize: defaultMaxRegistryBytes})
	if selfRoot := selfRootProvider.snapshot(); selfRoot.state != stateBackendUnavailable || !strings.Contains(selfRoot.message, "outside") {
		t.Fatalf("generation store accepted a self-selected trust root: %#v", selfRoot)
	}
}

// TestWarmCacheStopsAssertingVerifiedAfterArtifactTampering is the actual
// attack: every mutation below leaves the mutable pointer alias and the trust
// root byte-identical, so a cache keyed only on those two hashes would keep
// serving state=ok and signed_selection_verified=true without re-verification.
func TestWarmCacheStopsAssertingVerifiedAfterArtifactTampering(t *testing.T) {
	cases := []struct {
		name   string
		attack func(t *testing.T, store signedStore)
	}{
		{"immutable pointer target replaced", func(t *testing.T, store signedStore) {
			overwriteJSONField(t, store.pointerPath, "revision", json.Number("2"))
		}},
		{"immutable pointer target removed", func(t *testing.T, store signedStore) {
			removeReadOnly(t, store.pointerPath)
		}},
		{"transition receipt replaced", func(t *testing.T, store signedStore) {
			overwriteJSONField(t, store.receiptPath, "transitioned_at", "2026-07-17T12:00:00Z")
		}},
		{"transition receipt removed", func(t *testing.T, store signedStore) {
			removeReadOnly(t, store.receiptPath)
		}},
		{"persisted allowed-signers copy replaced", func(t *testing.T, store signedStore) {
			writeReadOnly(t, store.policyPath, append([]byte("attacker "), store.policy...))
		}},
		{"persisted allowed-signers copy removed", func(t *testing.T, store signedStore) {
			removeReadOnly(t, store.policyPath)
		}},
		{"selected manifest replaced", func(t *testing.T, store signedStore) {
			overwriteJSONField(t, store.manifestPath, "manifest_id", "dgm-tampered")
		}},
		{"selected manifest removed", func(t *testing.T, store signedStore) {
			removeReadOnly(t, store.manifestPath)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := buildSignedStore(t)
			provider := newRegistryProvider(config{
				stateDirectory: store.stateDir, allowedSigners: store.trustedPolicyPath,
				maxRegistrySize: defaultMaxRegistryBytes,
			})
			warm := provider.snapshot()
			if warm.state != stateOK {
				t.Fatalf("fixture did not verify before tampering: %#v", warm)
			}
			if provider.cachedStore == nil || len(provider.cachedArtifacts) == 0 {
				t.Fatal("verified snapshot did not warm the cache; the attack would be vacuous")
			}
			aliasBefore := readFileForTest(t, store.aliasPath)
			trustBefore := readFileForTest(t, store.trustedPolicyPath)

			testCase.attack(t, store)

			if !bytes.Equal(aliasBefore, readFileForTest(t, store.aliasPath)) {
				t.Fatal("attack changed the pointer alias; it no longer tests the cache key bypass")
			}
			if !bytes.Equal(trustBefore, readFileForTest(t, store.trustedPolicyPath)) {
				t.Fatal("attack changed the trust root; it no longer tests the cache key bypass")
			}
			after := provider.snapshot()
			if after.state == stateOK {
				t.Fatalf("warm cache still asserted verified state after tampering: %#v", after)
			}
			descriptor := snapshotDescriptor(after)
			if descriptor["signed_selection_verified"] != false {
				t.Fatalf("tampered store still reported signed_selection_verified: %#v", descriptor)
			}
		})
	}
}

// TestWarmCacheStillServesUntouchedVerifiedStore keeps the cache useful: an
// untampered store must keep verifying across repeated reads.
func TestWarmCacheStillServesUntouchedVerifiedStore(t *testing.T) {
	store := buildSignedStore(t)
	provider := newRegistryProvider(config{
		stateDirectory: store.stateDir, allowedSigners: store.trustedPolicyPath,
		maxRegistrySize: defaultMaxRegistryBytes,
	})
	first := provider.snapshot()
	if first.state != stateOK {
		t.Fatalf("signed store did not verify: %#v", first)
	}
	second := provider.snapshot()
	if second.state != stateOK {
		t.Fatalf("untouched signed store stopped verifying: %#v", second)
	}
	if second != first {
		t.Fatal("untouched signed store was fully reloaded instead of served from cache")
	}
	if snapshotDescriptor(second)["signed_selection_verified"] != true {
		t.Fatalf("untouched signed store lost its verified marker: %#v", snapshotDescriptor(second))
	}
}

func readFileForTest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func removeReadOnly(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func writeReadOnly(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func overwriteJSONField(t *testing.T, path, key string, value any) {
	t.Helper()
	raw := readFileForTest(t, path)
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	document[key] = value
	encoded, err := canonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	writeReadOnly(t, path, append(encoded, '\n'))
}
