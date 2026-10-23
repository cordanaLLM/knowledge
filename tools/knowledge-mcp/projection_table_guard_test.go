package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectionReceiptTableAllowlist(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "candidate.json")
	writeManifest(t, manifestPath, fixtureManifest(t, false))
	projectionPath := filepath.Join(directory, "candidate.sqlite")
	if _, err := compileRegistryProjection(manifestPath, projectionPath, defaultMaxRegistryBytes); err != nil {
		t.Fatal(err)
	}
	projection, err := openRegistryProjection(projectionPath, defaultMaxRegistryBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := projection.close(); err != nil {
			t.Errorf("close projection: %v", err)
		}
	})
	knownCount := projection.receipt.TableCounts["components"]
	for _, test := range []struct {
		name, table, wantError string
		count                  int
	}{
		{"known table", "components", "", knownCount},
		{"wrong count", "components", "count mismatch for components", knownCount + 1},
		{"injection", "x; DROP TABLE components", "unknown projection table", 0},
		{"empty name", "", "unknown projection table", 0},
		{"unknown name", "x", "unknown projection table", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection.receipt.TableCounts = map[string]int{test.table: test.count}
			err := projection.validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) || !strings.Contains(err.Error(), test.table) {
				t.Fatalf("table %q: want %q naming table, got %v", test.table, test.wantError, err)
			}
		})
	}
}
