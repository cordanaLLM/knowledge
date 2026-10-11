package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProjectionIsDeterministicBoundAndQueryable(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "candidate.json")
	manifest := fixtureManifest(t, false)
	manifest.Components[0].OfficialChannelRequired = true
	manifest.Components[0].OfficialChannels = []map[string]any{{
		"channel_id": "chn-test", "channel_type": "documentation",
		"canonical_uri": "https://example.invalid/docs", "review_state": "needs_review",
		"availability_state": "available",
	}}
	sealFixtureManifest(t, manifest)
	writeManifest(t, manifestPath, manifest)

	firstPath := filepath.Join(directory, "first.sqlite")
	secondPath := filepath.Join(directory, "second.sqlite")
	first, err := compileRegistryProjection(manifestPath, firstPath, defaultMaxRegistryBytes)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileRegistryProjection(manifestPath, secondPath, defaultMaxRegistryBytes)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProjectionSHA256 != second.ProjectionSHA256 || first.ProjectionSizeBytes != second.ProjectionSizeBytes {
		t.Fatalf("repeated projection was not byte-deterministic: %#v %#v", first, second)
	}
	firstReceipt, err := os.ReadFile(firstPath + projectionReceiptSuffix)
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err := os.ReadFile(secondPath + projectionReceiptSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstReceipt, secondReceipt) {
		t.Fatal("repeated projection receipt was not byte-deterministic")
	}
	if first.SourceManifestID != manifest.ManifestID || first.SourceManifestHash != manifestHash(manifest) || first.AuthorityState != projectionAuthority {
		t.Fatalf("source or authority binding was lost: %#v", first)
	}
	for _, immutablePath := range []string{firstPath, firstPath + projectionReceiptSuffix} {
		info, err := os.Lstat(immutablePath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o222 != 0 {
			t.Fatalf("immutable artifact is writable: %s %04o", immutablePath, info.Mode().Perm())
		}
	}

	provider := newRegistryProvider(config{projectionPath: firstPath, maxRegistrySize: defaultMaxRegistryBytes})
	if provider.direct != nil {
		t.Fatal("compact projection loaded eagerly")
	}
	snapshot := provider.snapshot()
	if snapshot.state != statePartial || snapshot.mode != "candidate-projection" || snapshot.projection == nil {
		t.Fatalf("compact candidate authority was overstated or unavailable: %#v", snapshot)
	}
	if len(snapshot.current.Components) != 0 || snapshot.current.ManifestID != manifest.ManifestID {
		t.Fatalf("compact runtime rematerialized records or lost manifest identity: %#v", snapshot.current)
	}
	if len(snapshot.current.Counts) != maxRegistryCountKeys {
		t.Fatalf("projection compatibility metadata leaked into manifest counts: %#v", snapshot.current.Counts)
	}
	var storedCountsRaw string
	if err := snapshot.projection.db.QueryRow("SELECT value FROM projection_meta WHERE key='counts'").Scan(&storedCountsRaw); err != nil {
		t.Fatal(err)
	}
	var storedCounts map[string]int
	if err := json.Unmarshal([]byte(storedCountsRaw), &storedCounts); err != nil {
		t.Fatal(err)
	}
	if storedCounts[projectionLegacyResolutionCount] != 0 || len(storedCounts) != maxRegistryCountKeys+1 {
		t.Fatalf("projection v1 compatibility count is missing: %#v", storedCounts)
	}
	rows, err := snapshot.projection.db.Query("PRAGMA table_info(versions)")
	if err != nil {
		t.Fatal(err)
	}
	var columns []string
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(columns, projectionColumns["versions"]) {
		t.Fatalf("versions DDL drifted: got %v want %v", columns, projectionColumns["versions"])
	}
	service := newToolService(&knowledgeIndex{state: stateEmpty}, provider)
	lookup := service.call(context.Background(), "dependency_lookup", json.RawMessage(`{"query":"argo-cd","limit":1}`))
	if lookup.Error || lookup.State != statePartial || lookup.Data["result_state"] != stateOK {
		t.Fatalf("compact dependency lookup failed: %#v", lookup)
	}
	status := service.call(context.Background(), "knowledge_status", json.RawMessage(`{}`))
	if status.Error || status.State != statePartial {
		t.Fatalf("compact knowledge status failed: %#v", status)
	}
	projectionStatus, ok := status.Data["projection"].(map[string]any)
	if !ok || projectionStatus["source_manifest_id"] != manifest.ManifestID || projectionStatus["authority_state"] != projectionAuthority {
		t.Fatalf("status omitted projection binding: %#v", status.Data)
	}
	if err := snapshot.projection.close(); err != nil {
		t.Fatal(err)
	}
}

func TestProjectionRejectsSymlinkedOutputParent(t *testing.T) {
	directory := t.TempDir()
	realParent := filepath.Join(directory, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "candidate.json")
	writeManifest(t, manifestPath, fixtureManifest(t, false))
	_, err := compileRegistryProjection(manifestPath, filepath.Join(linkedParent, "candidate.sqlite"), defaultMaxRegistryBytes)
	if err == nil {
		t.Fatal("symlinked projection output parent was accepted")
	}
}

func TestProjectionPublisherRejectsSymlinkedAncestorAndChildWithoutExternalWrites(t *testing.T) {
	manifestDirectory := t.TempDir()
	manifestPath := filepath.Join(manifestDirectory, "candidate.json")
	writeManifest(t, manifestPath, fixtureManifest(t, false))

	t.Run("ancestor", func(t *testing.T) {
		directory := t.TempDir()
		realAncestor := filepath.Join(directory, "real")
		if err := os.MkdirAll(filepath.Join(realAncestor, "nested"), 0o700); err != nil {
			t.Fatal(err)
		}
		linkedAncestor := filepath.Join(directory, "linked")
		if err := os.Symlink(realAncestor, linkedAncestor); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(linkedAncestor, "nested", "candidate.sqlite")
		if _, err := compileRegistryProjection(manifestPath, outputPath, defaultMaxRegistryBytes); err == nil {
			t.Fatal("symlinked projection output ancestor was accepted")
		}
		for _, external := range []string{
			filepath.Join(realAncestor, "nested", "candidate.sqlite"),
			filepath.Join(realAncestor, "nested", "candidate.sqlite"+projectionReceiptSuffix),
		} {
			if _, err := os.Lstat(external); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("symlinked ancestor received projection output %s: %v", external, err)
			}
		}
	})

	t.Run("projection child", func(t *testing.T) {
		directory := t.TempDir()
		external := filepath.Join(t.TempDir(), "external")
		original := []byte("do-not-change")
		if err := os.WriteFile(external, original, 0o600); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(directory, "candidate.sqlite")
		if err := os.Symlink(external, outputPath); err != nil {
			t.Fatal(err)
		}
		if _, err := compileRegistryProjection(manifestPath, outputPath, defaultMaxRegistryBytes); err == nil {
			t.Fatal("symlinked projection output child was accepted")
		}
		got, err := os.ReadFile(external)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, original) {
			t.Fatal("symlinked projection output child modified external bytes")
		}
		if _, err := os.Lstat(outputPath + projectionReceiptSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("receipt was published beside a rejected child symlink: %v", err)
		}
	})

	t.Run("receipt child", func(t *testing.T) {
		directory := t.TempDir()
		external := filepath.Join(t.TempDir(), "external")
		original := []byte("do-not-change")
		if err := os.WriteFile(external, original, 0o600); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(directory, "candidate.sqlite")
		if err := os.Symlink(external, outputPath+projectionReceiptSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := compileRegistryProjection(manifestPath, outputPath, defaultMaxRegistryBytes); err == nil {
			t.Fatal("symlinked projection receipt child was accepted")
		}
		got, err := os.ReadFile(external)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, original) {
			t.Fatal("symlinked projection receipt child modified external bytes")
		}
		if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("projection was published before a rejected receipt child: %v", err)
		}
	})
}

func TestProjectionPublisherRejectsParentReplacementDuringCommit(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "candidate.json")
	writeManifest(t, manifestPath, fixtureManifest(t, false))
	parent := filepath.Join(directory, "publish")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	originalParent := filepath.Join(directory, "publish-original")
	outputPath := filepath.Join(parent, "candidate.sqlite")
	replaced := false
	_, err := compileRegistryProjectionWithPublishHook(manifestPath, outputPath, defaultMaxRegistryBytes, func(phase projectionPublishPhase) error {
		if phase != projectionPublishReceipt || replaced {
			return nil
		}
		replaced = true
		if err := os.Rename(parent, originalParent); err != nil {
			return err
		}
		return os.Mkdir(parent, 0o700)
	})
	if err == nil || !replaced {
		t.Fatalf("projection parent replacement during commit was accepted: replaced=%v err=%v", replaced, err)
	}
	for _, base := range []string{parent, originalParent} {
		for _, name := range []string{"candidate.sqlite", "candidate.sqlite" + projectionReceiptSuffix} {
			candidate := filepath.Join(base, name)
			if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("parent replacement left a published artifact at %s: %v", candidate, err)
			}
		}
		entries, err := os.ReadDir(base)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("parent replacement left rooted staging artifacts in %s: %v", base, entries)
		}
	}
}

func TestProjectionPublisherNeverOverwritesExistingOutput(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "candidate.json")
	writeManifest(t, manifestPath, fixtureManifest(t, false))
	outputPath := filepath.Join(directory, "candidate.sqlite")
	original := []byte("immutable-existing-projection")
	if err := os.WriteFile(outputPath, original, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := compileRegistryProjection(manifestPath, outputPath, defaultMaxRegistryBytes); err == nil {
		t.Fatal("different immutable projection was overwritten")
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatal("existing immutable projection bytes changed")
	}
	if _, err := os.Lstat(outputPath + projectionReceiptSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt was published for a conflicting projection: %v", err)
	}
}

func TestProjectionRejectsChangedBytes(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "candidate.json")
	writeManifest(t, manifestPath, fixtureManifest(t, false))
	projectionPath := filepath.Join(directory, "candidate.sqlite")
	if _, err := compileRegistryProjection(manifestPath, projectionPath, defaultMaxRegistryBytes); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectionPath, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(projectionPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openRegistryProjection(projectionPath, defaultMaxRegistryBytes); err == nil {
		t.Fatal("changed projection bytes passed receipt validation")
	}
}

func TestProjectionRejectsMutatedTableAttributesAndIndexOrder(t *testing.T) {
	tests := []struct {
		name     string
		mutation string
	}{
		{
			name: "nullable table value",
			mutation: `ALTER TABLE projection_meta RENAME TO projection_meta_old;
CREATE TABLE projection_meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
INSERT INTO projection_meta SELECT key,value FROM projection_meta_old;
DROP TABLE projection_meta_old;`,
		},
		{
			name: "reordered index columns",
			mutation: `DROP INDEX components_name_idx;
CREATE INDEX components_name_idx ON components(component_id, name COLLATE NOCASE);`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			manifestPath := filepath.Join(directory, "candidate.json")
			writeManifest(t, manifestPath, fixtureManifest(t, false))
			projectionPath := filepath.Join(directory, "candidate.sqlite")
			if _, err := compileRegistryProjection(manifestPath, projectionPath, defaultMaxRegistryBytes); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(projectionPath, 0o600); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", sqliteReadWriteURI(projectionPath))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.mutation); err != nil {
				db.Close()
				t.Fatal(err)
			}
			projection := &registryProjection{db: db}
			if err := projection.validateSchemaObjects(context.Background()); err == nil {
				db.Close()
				t.Fatal("mutated exact schema passed validation")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectionSearchAndRelationshipsUseBoundedPagesWithExactTotals(t *testing.T) {
	manifest := fixtureManifest(t, false)
	matchCount := maxProjectionSearchRows + 8
	relationCount := 240
	for index := 0; index < matchCount; index++ {
		componentID := fmt.Sprintf("cmp-common-%05d", index)
		manifest.Components = append(manifest.Components, registryComponent{
			ComponentID: componentID, Ecosystem: "test", Kind: "library",
			Lifecycles: []string{"planned"}, Name: fmt.Sprintf("common-package-%05d", index),
			Namespace: "bounded", OfficialChannels: []map[string]any{},
			PURL: "pkg:test/common-" + fmt.Sprintf("%05d", index),
		})
	}
	for index := 0; index < relationCount; index++ {
		componentID := fmt.Sprintf("cmp-relation-%05d", index)
		versionID := fmt.Sprintf("ver-relation-%05d", index)
		manifest.Components = append(manifest.Components, registryComponent{
			ComponentID: componentID, Ecosystem: "test", Kind: "library",
			Lifecycles: []string{"planned"},
			Name:       fmt.Sprintf("relation-package-%05d", index),
			Namespace:  "bounded", OfficialChannels: []map[string]any{},
			PURL: "pkg:test/relation-" + fmt.Sprintf("%05d", index),
		})
		manifest.Versions = append(manifest.Versions, registryVersion{
			ComponentID: componentID, ComponentVersionID: versionID,
			ResolvedVersion: "1.0.0", ResolutionState: "resolved",
		})
		manifest.DependencyEdges = append(manifest.DependencyEdges, registryEdge{
			EdgeID: fmt.Sprintf("edge-%05d", index), FromComponentVersionID: "ver-test",
			ToComponentVersionID: versionID, Relationship: "depends_on", Resolver: "test",
			Scope: "runtime", SourceOccurrenceID: "occ-test",
		})
	}
	manifest.Counts["components"] = len(manifest.Components)
	manifest.Counts["versions"] = len(manifest.Versions)
	manifest.Counts["dependency_edges"] = len(manifest.DependencyEdges)
	sealFixtureManifest(t, manifest)

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "candidate.json")
	writeManifest(t, manifestPath, manifest)
	projectionPath := filepath.Join(directory, "candidate.sqlite")
	if _, err := compileRegistryProjection(manifestPath, projectionPath, defaultMaxRegistryBytes); err != nil {
		t.Fatal(err)
	}
	projection, err := openRegistryProjection(projectionPath, defaultMaxRegistryBytes)
	if err != nil {
		t.Fatal(err)
	}

	search := projection.searchComponents("common", "", "", "planned", 5)
	if search.Error || search.State != statePartial || search.Data["matched_count"] != matchCount || search.Data["matched_count_exact"] != true {
		t.Fatalf("large search lost exact bounded semantics: %#v", search)
	}
	if search.Data["scan_truncated"] != true || search.Data["scanned_count"] != maxProjectionSearchRows || search.Data["result_count"] != 5 {
		t.Fatalf("large search did not enforce scan cap: %#v", search.Data)
	}

	relations := projection.relationships("cmp-test", "dependencies", "runtime", 100, 25)
	if relations.Error || relations.State != stateOK || relations.Data["total"] != relationCount || relations.Data["total_exact"] != true {
		t.Fatalf("large relationship page lost exact total: %#v", relations)
	}
	items, ok := relations.Data["relationships"].([]map[string]any)
	if !ok || len(items) != 25 || relations.Data["offset"] != 100 || relations.Data["next_offset"] != 125 {
		t.Fatalf("large relationship page was not SQL bounded: %#v", relations.Data)
	}
	if err := projection.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectionPath, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteReadWriteURI(projectionPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE components SET name=? WHERE component_id LIKE 'cmp-relation-%'`, strings.Repeat("x", 50_000)); err != nil {
		t.Fatal(err)
	}
	budgetProjection := &registryProjection{db: db}
	budgeted := budgetProjection.relationships("cmp-test", "dependencies", "runtime", 0, 100)
	if !budgeted.Error || budgeted.State != stateBackendUnavailable {
		t.Fatalf("oversized projected relationship component was not rejected: %#v", budgeted)
	}
}

func TestProjectionJSONBudgetsRejectOversizedCellsAndAggregateRows(t *testing.T) {
	budget := newProjectionJSONBudget()
	if err := budget.add(strings.Repeat("x", maxProjectionJSONCell+1)); err == nil {
		t.Fatal("oversized projection JSON cell was accepted")
	}
	budget = newProjectionJSONBudget()
	for index := 0; index < maxProjectionRowBudget/maxProjectionJSONCell; index++ {
		if err := budget.add(strings.Repeat("x", maxProjectionJSONCell)); err != nil {
			t.Fatalf("valid bounded cell unexpectedly failed: %v", err)
		}
	}
	if err := budget.add("x"); err != errProjectionRowBudget {
		t.Fatalf("aggregate projection row budget was not enforced: %v", err)
	}
	terms := make([]string, maxProjectionQueryTerms+1)
	for index := range terms {
		terms[index] = fmt.Sprintf("term%d", index)
	}
	result := (&registryProjection{}).searchComponents(strings.Join(terms, " "), "", "", "", 1)
	if !result.Error || result.State != stateForbidden {
		t.Fatalf("oversized projection search expression was accepted: %#v", result)
	}
}

func TestProjectionGapTypesAreSampledWithExactTotal(t *testing.T) {
	directory := t.TempDir()
	manifest := fixtureManifest(t, false)
	for index := 0; index < maxRegistryStatusGapTypes+11; index++ {
		manifest.Gaps = append(manifest.Gaps, registryGap{
			GapID: fmt.Sprintf("gap-projection-%03d", index), GapType: fmt.Sprintf("projection-type-%03d", index),
			Message: "bounded projection gap type",
		})
	}
	manifest.Counts["gaps"] = len(manifest.Gaps)
	sealFixtureManifest(t, manifest)
	manifestPath := filepath.Join(directory, "candidate.json")
	projectionPath := filepath.Join(directory, "candidate.sqlite")
	writeManifest(t, manifestPath, manifest)
	if _, err := compileRegistryProjection(manifestPath, projectionPath, defaultMaxRegistryBytes); err != nil {
		t.Fatal(err)
	}
	projection, err := openRegistryProjection(projectionPath, defaultMaxRegistryBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer projection.close()

	types, total, err := projection.gapTypes(maxRegistryStatusGapTypes)
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != maxRegistryStatusGapTypes || total != maxRegistryStatusGapTypes+11 {
		t.Fatalf("projection gap types were not bounded with exact total: len=%d total=%d", len(types), total)
	}
}

func TestProjectionValidationRejectsOversizedStoredCellsAndRows(t *testing.T) {
	tests := []struct {
		name   string
		update func(*testing.T, *sql.DB)
	}{
		{
			name: "cell",
			update: func(t *testing.T, db *sql.DB) {
				t.Helper()
				if _, err := db.Exec("UPDATE components SET official_channels_json=?", strings.Repeat("ä", maxProjectionJSONCell/2+1)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "row",
			update: func(t *testing.T, db *sql.DB) {
				t.Helper()
				large := strings.Repeat("x", 900_000)
				if _, err := db.Exec("UPDATE components SET ecosystem=?,kind=?,name=?,namespace=?,purl=?", large, large, large, large, large); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			manifestPath := filepath.Join(directory, "candidate.json")
			writeManifest(t, manifestPath, fixtureManifest(t, false))
			projectionPath := filepath.Join(directory, "candidate.sqlite")
			if _, err := compileRegistryProjection(manifestPath, projectionPath, defaultMaxRegistryBytes); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(projectionPath, 0o600); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", sqliteReadWriteURI(projectionPath))
			if err != nil {
				t.Fatal(err)
			}
			test.update(t, db)
			projection := &registryProjection{db: db}
			if err := projection.validateCellAndRowBounds(context.Background()); err == nil {
				db.Close()
				t.Fatal("oversized stored projection value passed validation")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
