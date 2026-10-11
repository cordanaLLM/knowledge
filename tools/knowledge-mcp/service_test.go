package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcceptedOfficialChannelRequiresAllReviewFields(t *testing.T) {
	accepted := map[string]any{
		"channel_id":         "chn-accepted",
		"channel_type":       "documentation",
		"canonical_uri":      "https://argo-cd.readthedocs.io/",
		"review_state":       "accepted",
		"availability_state": "available",
	}
	needsReview := map[string]any{
		"channel_id":         "chn-needs-review",
		"channel_type":       "documentation",
		"canonical_uri":      "https://example.invalid/docs",
		"review_state":       "needs_review",
		"availability_state": "available",
	}
	unavailable := map[string]any{
		"channel_id":         "chn-unavailable",
		"channel_type":       "documentation",
		"canonical_uri":      "https://example.invalid/old",
		"review_state":       "accepted",
		"availability_state": "unavailable",
	}
	missingURI := map[string]any{
		"channel_id":         "chn-no-uri",
		"channel_type":       "documentation",
		"review_state":       "accepted",
		"availability_state": "available",
	}
	channels := []map[string]any{accepted, needsReview, unavailable, missingURI}
	if got := reviewedAvailableChannels(channels); got != 1 {
		t.Fatalf("expected one accepted and available official channel, got %d", got)
	}
	if !acceptedAvailableChannel(accepted) {
		t.Fatal("fully reviewed channel was rejected")
	}
	for _, channel := range channels[1:] {
		if acceptedAvailableChannel(channel) {
			t.Fatalf("incomplete channel was accepted: %#v", channel)
		}
	}
}

func TestCandidateQueriesPreserveResultStateUnderPartialAuthority(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	manifest := fixtureManifest(t, true)
	manifest.Components[0].OfficialChannelRequired = true
	manifest.Components[0].OfficialChannels = []map[string]any{{
		"channel_id":         "chn-candidate",
		"channel_type":       "documentation",
		"canonical_uri":      "https://example.invalid/unreviewed",
		"review_state":       "needs_review",
		"availability_state": "available",
	}}
	sealFixtureManifest(t, manifest)
	writeManifest(t, path, manifest)

	service := newToolService(&knowledgeIndex{state: stateEmpty}, newRegistryProvider(config{
		registryPath: path, maxRegistrySize: defaultMaxRegistryBytes,
	}))
	search := service.call(context.Background(), "registry_search_components", json.RawMessage(`{"query":"argo-cd","limit":1}`))
	if search.Error || search.State != statePartial || search.Data["result_state"] != stateOK {
		t.Fatalf("candidate search lost partial/result state: %#v", search)
	}
	channels := service.call(context.Background(), "registry_official_channels", json.RawMessage(`{"component_id":"cmp-test"}`))
	if channels.Error || channels.State != statePartial || channels.Data["result_state"] != stateNoOfficialChannel {
		t.Fatalf("candidate channel result was overstated: %#v", channels)
	}
}

func TestDependencyChangesPagesSegmentsWithoutAggregatingAllRecords(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	manifest := fixtureManifest(t, true)
	for _, kind := range []string{"added", "changed", "removed", "missing"} {
		items := make([]any, 75)
		for index := range items {
			items[index] = map[string]any{"id": fmt.Sprintf("%s-%03d", kind, index)}
		}
		manifest.Reconciliation[kind] = items
	}
	sealFixtureManifest(t, manifest)
	writeManifest(t, path, manifest)
	service := newToolService(&knowledgeIndex{state: stateEmpty}, newRegistryProvider(config{
		registryPath: path, maxRegistrySize: defaultMaxRegistryBytes,
	}))

	result := service.call(context.Background(), "dependency_changes", json.RawMessage(`{"change_kind":"all","offset":70,"limit":20}`))
	if result.Error || result.State != statePartial || result.Data["result_state"] != stateOK {
		t.Fatalf("bounded candidate change page failed: %#v", result)
	}
	if result.Data["total"] != 300 || result.Data["total_exact"] != true ||
		result.Data["offset"] != 70 || result.Data["next_offset"] != 90 {
		t.Fatalf("change page lost exact segment pagination: %#v", result.Data)
	}
	items, ok := result.Data["changes"].([]map[string]any)
	if !ok || len(items) != 20 || items[0]["change_kind"] != "added" || items[5]["change_kind"] != "changed" {
		t.Fatalf("change page crossed segments incorrectly: %#v", result.Data["changes"])
	}
}

func TestRelationshipEvidenceIDsReportBoundedTruncation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	manifest := fixtureManifest(t, true)
	manifest.Components = append(manifest.Components, registryComponent{
		ComponentID: "cmp-target", Ecosystem: "test", Kind: "library", Lifecycles: []string{"planned"},
		Name: "target", OfficialChannels: []map[string]any{},
	})
	manifest.Versions = append(manifest.Versions, registryVersion{
		ComponentID: "cmp-target", ComponentVersionID: "ver-target", ResolvedVersion: "1.0.0",
	})
	manifest.Components = append(manifest.Components, registryComponent{
		ComponentID: "cmp-source", Ecosystem: "test", Kind: "library", Lifecycles: []string{"planned"},
		Name: "source", OfficialChannels: []map[string]any{},
	})
	manifest.Versions = append(manifest.Versions, registryVersion{
		ComponentID: "cmp-source", ComponentVersionID: "ver-source", ResolvedVersion: "1.0.0",
	})
	for index := 0; index < 9; index++ {
		manifest.DependencyEdges = append(manifest.DependencyEdges, registryEdge{
			EdgeID: fmt.Sprintf("edge-%02d", index), FromComponentVersionID: "ver-test",
			ToComponentVersionID: "ver-target", Relationship: "depends_on", Resolver: "test",
			Scope: "runtime", SourceOccurrenceID: "occ-test",
		})
	}
	manifest.DependencyEdges = append(manifest.DependencyEdges, registryEdge{
		EdgeID: "edge-dependent", FromComponentVersionID: "ver-source",
		ToComponentVersionID: "ver-test", Relationship: "depends_on", Resolver: "test",
		Scope: "runtime", SourceOccurrenceID: "occ-test",
	})
	manifest.Counts["components"] = len(manifest.Components)
	manifest.Counts["versions"] = len(manifest.Versions)
	manifest.Counts["dependency_edges"] = len(manifest.DependencyEdges)
	sealFixtureManifest(t, manifest)
	writeManifest(t, path, manifest)
	service := newToolService(&knowledgeIndex{state: stateEmpty}, newRegistryProvider(config{
		registryPath: path, maxRegistrySize: defaultMaxRegistryBytes,
	}))

	result := service.call(context.Background(), "registry_relationships", json.RawMessage(`{"component_id":"cmp-test","limit":1}`))
	if result.Error || result.State != statePartial || result.Data["result_state"] != stateOK {
		t.Fatalf("bounded relationship query failed: %#v", result)
	}
	items, ok := result.Data["relationships"].([]map[string]any)
	if !ok || len(items) != 1 {
		t.Fatalf("unexpected relationships: %#v", result.Data["relationships"])
	}
	ids, ok := items[0]["evidence_occurrence_ids"].([]string)
	if !ok || len(ids) != 8 || items[0]["evidence_occurrence_count"] != 9 ||
		items[0]["evidence_occurrences_truncated"] != true {
		t.Fatalf("relationship evidence bound was not explicit: %#v", items[0])
	}
	both := service.call(context.Background(), "registry_relationships", json.RawMessage(`{"component_id":"cmp-test","direction":"both","limit":10}`))
	bothItems, ok := both.Data["relationships"].([]map[string]any)
	if both.Error || !ok || len(bothItems) != 2 || bothItems[0]["direction"] != "dependency" ||
		bothItems[1]["direction"] != "dependent" || both.Data["total"] != 2 || both.Data["total_exact"] != true {
		t.Fatalf("pre-sorted relationship segments were not merged deterministically: %#v", both)
	}
}

func TestRegistryStatusSamplesGapTypesWithExactTotal(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	manifest := fixtureManifest(t, true)
	for index := 0; index < maxRegistryStatusGapTypes+9; index++ {
		manifest.Gaps = append(manifest.Gaps, registryGap{
			GapID: fmt.Sprintf("gap-%03d", index), GapType: fmt.Sprintf("type-%03d", index),
			Message: "bounded gap type",
		})
	}
	manifest.Counts["gaps"] = len(manifest.Gaps)
	sealFixtureManifest(t, manifest)
	writeManifest(t, path, manifest)
	service := newToolService(&knowledgeIndex{state: stateEmpty}, newRegistryProvider(config{
		registryPath: path, maxRegistrySize: defaultMaxRegistryBytes,
	}))

	result := service.call(context.Background(), "registry_status", json.RawMessage(`{}`))
	if result.Error || result.State != statePartial {
		t.Fatalf("candidate status failed: %#v", result)
	}
	types, ok := result.Data["gap_types"].([]map[string]any)
	if !ok || len(types) != maxRegistryStatusGapTypes ||
		result.Data["gap_types_total"] != maxRegistryStatusGapTypes+9 ||
		result.Data["gap_types_truncated"] != true {
		t.Fatalf("gap type status was not bounded with exact total: %#v", result.Data)
	}
}

func TestDirectSearchKeepsOnlyBoundedTopKWithExactMatchCount(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "candidate.json")
	manifest := fixtureManifest(t, true)
	const broadMatches = 5_000
	for index := 0; index < broadMatches; index++ {
		manifest.Components = append(manifest.Components, registryComponent{
			ComponentID: fmt.Sprintf("cmp-broad-%05d", index), Ecosystem: "test", Kind: "library",
			Lifecycles: []string{"planned"}, Name: fmt.Sprintf("common-%05d", index),
			Namespace: "bounded", OfficialChannels: []map[string]any{},
		})
	}
	manifest.Counts["components"] = len(manifest.Components)
	sealFixtureManifest(t, manifest)
	writeManifest(t, path, manifest)
	service := newToolService(&knowledgeIndex{state: stateEmpty}, newRegistryProvider(config{
		registryPath: path, maxRegistrySize: defaultMaxRegistryBytes,
	}))

	result := service.call(context.Background(), "registry_search_components", json.RawMessage(`{"query":"common","limit":7}`))
	if result.Error || result.State != statePartial || result.Data["result_state"] != stateOK ||
		result.Data["matched_count"] != broadMatches || result.Data["matched_count_exact"] != true ||
		result.Data["result_count"] != 7 || result.Data["ranking_complete"] != true {
		t.Fatalf("bounded top-k search lost exact semantics: %#v", result)
	}
	matches, ok := result.Data["matches"].([]map[string]any)
	if !ok || len(matches) != 7 || matches[0]["component_id"] != "cmp-broad-00000" ||
		matches[6]["component_id"] != "cmp-broad-00006" {
		t.Fatalf("bounded top-k search order is not deterministic: %#v", result.Data["matches"])
	}
}

func TestFoldPatternIsLinearAndAllocationFreeForRepeatedPrefixNearMatch(t *testing.T) {
	value := strings.Repeat("a", maxRegistryToolRowBytes-1) + "b"
	pattern := newFoldPattern(strings.Repeat("a", 511) + "c")
	if pattern.contains(value) {
		t.Fatal("near-match pattern unexpectedly matched")
	}
	if !newFoldPattern("ÄRGO").contains("prefix-ärgo-suffix") {
		t.Fatal("Unicode case-folded pattern did not match")
	}
	found := false
	allocations := testing.AllocsPerRun(100, func() {
		found = pattern.contains(value)
	})
	if found || allocations != 0 {
		t.Fatalf("bounded matcher allocated or matched unexpectedly: found=%v allocs=%f", found, allocations)
	}
}

func BenchmarkFoldPatternRepeatedPrefixNearMatch(b *testing.B) {
	value := strings.Repeat("a", maxRegistryToolRowBytes-1) + "b"
	pattern := newFoldPattern(strings.Repeat("a", 511) + "c")
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if pattern.contains(value) {
			b.Fatal("near-match pattern unexpectedly matched")
		}
	}
}

// TestAbsentRegistryBackendIsNotAuthoritativeEmptiness separates the three
// meanings of "nothing": no backend, a backend with no verified selection, and
// a verified backend that genuinely holds no matching record.
func TestAbsentRegistryBackendIsNotAuthoritativeEmptiness(t *testing.T) {
	t.Run("no backend configured", func(t *testing.T) {
		service := newToolService(&knowledgeIndex{state: stateOK}, newRegistryProvider(config{
			maxRegistrySize: defaultMaxRegistryBytes,
		}))
		result := service.call(context.Background(), "registry_search_components", json.RawMessage(`{"query":"argo-cd"}`))
		if result.State != stateNotConfigured {
			t.Fatalf("unconfigured registry reported %q instead of not_configured: %#v", result.State, result.Data)
		}
		if !result.Error {
			t.Fatal("unconfigured registry answered a content query without failing closed")
		}
		status := service.call(context.Background(), "registry_status", json.RawMessage(`{}`))
		if status.State != stateNotConfigured {
			t.Fatalf("registry_status hid the unconfigured backend: %#v", status.Data)
		}
	})

	t.Run("configured store with no verified pointer", func(t *testing.T) {
		if _, err := os.Stat(sshKeygenPath); err != nil {
			t.Skip("ssh-keygen is required for signed generation verification")
		}
		store := buildSignedStore(t)
		if err := os.Remove(store.aliasPath); err != nil {
			t.Fatal(err)
		}
		service := newToolService(&knowledgeIndex{state: stateOK}, newRegistryProvider(config{
			stateDirectory: store.stateDir, allowedSigners: store.trustedPolicyPath,
			maxRegistrySize: defaultMaxRegistryBytes,
		}))
		result := service.call(context.Background(), "registry_search_components", json.RawMessage(`{"query":"argo-cd"}`))
		if result.State != stateNoVerifiedState {
			t.Fatalf("store without a signed pointer reported %q instead of no_verified_state: %#v", result.State, result.Data)
		}
		if !result.Error {
			t.Fatal("store without a signed pointer answered a content query without failing closed")
		}
	})

	t.Run("verified backend genuinely holds no match", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "candidate.json")
		manifest := fixtureManifest(t, true)
		sealFixtureManifest(t, manifest)
		writeManifest(t, path, manifest)
		service := newToolService(&knowledgeIndex{state: stateOK}, newRegistryProvider(config{
			registryPath: path, maxRegistrySize: defaultMaxRegistryBytes,
		}))
		result := service.call(context.Background(), "registry_search_components", json.RawMessage(`{"query":"zzzznosuchcomponent"}`))
		if result.Error {
			t.Fatalf("genuine no-match over a readable registry became an error: %#v", result.Data)
		}
		if result.Data["result_state"] != stateEmpty {
			t.Fatalf("genuine no-match stopped being empty: %#v", result.Data)
		}
	})
}
