package main

import (
	"os"
	"strings"
	"testing"
)

// mcp01AcceptanceRegistryManifest is the frozen P1-MCP-01 pagination corpus: one
// root component with three dependency edges so offset/limit cursors page.
func mcp01AcceptanceRegistryManifest(t *testing.T) *registryManifest {
	t.Helper()
	denied := false
	source := registrySource{
		ContentHash: "sha256:" + strings.Repeat("1", 64),
		EvidenceURI: "docs/mcp01/README.md",
		SourceID:    "src-mcp01",
		SourceType:  "repository-file",
	}
	components := []registryComponent{}
	versions := []registryVersion{}
	occurrences := []registryOccurrence{}
	for _, name := range []string{"root", "dep-a", "dep-b", "dep-c"} {
		components = append(components, registryComponent{
			ComponentID: "cmp-mcp01-" + name, Ecosystem: "git", Kind: "application",
			Lifecycles: []string{"deployed"}, Name: "mcp01-" + name, Namespace: "example",
			OfficialChannels: []map[string]any{}, PURL: "pkg:github/example/mcp01-" + name,
		})
		versions = append(versions, registryVersion{
			ComponentID: "cmp-mcp01-" + name, ComponentVersionID: "ver-mcp01-" + name,
			ResolvedVersion: "v1.0.0", ResolutionState: "resolved",
			Evidence: []string{"docs/mcp01/README.md"},
		})
		occurrences = append(occurrences, registryOccurrence{
			ComponentID: "cmp-mcp01-" + name, ComponentVersionID: "ver-mcp01-" + name,
			DependencyScope: "runtime", Directness: "direct",
			EvidenceLocator: "docs/mcp01/README.md:1", Lifecycle: "deployed",
			OccurrenceID: "occ-mcp01-" + name, Optional: false, RawValue: "v1.0.0",
			Role: "application", SourceID: "src-mcp01",
		})
	}
	edges := []registryEdge{}
	for _, dep := range []string{"dep-a", "dep-b", "dep-c"} {
		edges = append(edges, registryEdge{
			EdgeID:                 "edge-mcp01-root-" + dep,
			FromComponentVersionID: "ver-mcp01-root",
			ToComponentVersionID:   "ver-mcp01-" + dep,
			Optional:               false, Relationship: "depends_on", Resolver: "static",
			Scope: "runtime", SourceOccurrenceID: "occ-mcp01-" + dep,
		})
	}
	completeness := map[string]any{
		"all_axes_complete": true,
		"input": map[string]any{
			"state": "complete", "input_count": 0, "blocking_input_ids": []any{},
		},
		"enumeration": map[string]any{"state": "complete"},
		"closure": map[string]any{
			"state": "complete", "blocking_gap_ids": []any{},
		},
		"identity": map[string]any{
			"state": "complete", "blocking_gap_ids": []any{},
		},
		"channel_review": map[string]any{
			"state": "complete", "required_slots": 0, "accepted_slots": 0,
		},
		"snapshots": map[string]any{
			"state": "complete", "accepted_available_channels": 0,
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
			"sources": 1, "components": 4, "versions": 4, "occurrences": 4,
			"dependency_edges": 3, "gaps": 0,
		},
		Completeness: completeness,
		Reconciliation: map[string]any{
			"added": []any{}, "changed": []any{}, "complete_mark": true,
			"missing": []any{}, "previous_manifest_id": nil,
			"removal_allowed": false, "removed": []any{},
		},
		Integrity: map[string]any{
			"canonicalization":    "archeion-canonical-json-v1",
			"deterministic_order": true,
		},
		Generator: map[string]any{
			"name": "mcp01-acceptance-fixture", "version": "1",
			"source_ref":   "tools/knowledge-mcp/mcp01_fixture_gen_test.go",
			"schema_hash":  "sha256:" + strings.Repeat("2", 64),
			"ruleset_hash": "sha256:" + strings.Repeat("3", 64),
		},
		InputSet: map[string]any{"required_source_classes": []any{}, "entries": []any{}},
		Observation: &registryObservation{
			ObservedAt: "2026-08-22T00:00:01Z", SourceValidAt: "2026-08-22T00:00:00Z",
			SourceValidTimeBasis: "git-commit-committer-time",
		},
		Sources: []registrySource{source}, Components: components,
		Versions: versions, Occurrences: occurrences,
		DependencyEdges: edges, Gaps: []registryGap{},
	}
	sealFixtureManifest(t, manifest)
	return manifest
}

// TestWriteMCP01AcceptanceRegistryFixture regenerates the frozen candidate
// manifest byte-identically. Guarded: it only writes when the target path is
// supplied, so normal test runs never touch the frozen fixture.
func TestWriteMCP01AcceptanceRegistryFixture(t *testing.T) {
	target := os.Getenv("ARCHEION_MCP01_WRITE_REGISTRY_FIXTURE")
	if target == "" {
		t.Skip("set ARCHEION_MCP01_WRITE_REGISTRY_FIXTURE=<path> to regenerate the frozen fixture")
	}
	writeManifest(t, target, mcp01AcceptanceRegistryManifest(t))
}

// TestMCP01AcceptanceRegistryFixtureIsFrozen fails when the committed fixture
// and the generator drift apart, so the sealed canonical hash stays honest.
func TestMCP01AcceptanceRegistryFixtureIsFrozen(t *testing.T) {
	const frozen = "testdata/mcp01-acceptance/fixtures/registry/candidate-manifest.json"
	committed, err := os.ReadFile(frozen)
	if err != nil {
		t.Fatalf("read frozen registry fixture: %v", err)
	}
	regenerated := t.TempDir() + "/candidate-manifest.json"
	writeManifest(t, regenerated, mcp01AcceptanceRegistryManifest(t))
	fresh, err := os.ReadFile(regenerated)
	if err != nil {
		t.Fatal(err)
	}
	if string(committed) != string(fresh) {
		t.Fatal("frozen registry fixture and its generator drifted; regenerate deliberately and re-pin the suite")
	}
}
