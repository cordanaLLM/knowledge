package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteExclusivePrivateAndNoReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := writeExclusive(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("plan exposes group/world permissions: %o", info.Mode().Perm())
	}
	if err := writeExclusive(path, []byte("second")); err == nil {
		t.Fatal("replaced existing output")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "first" {
		t.Fatalf("output changed to %q", raw)
	}
	if err := writeExclusive(filepath.Join(path, "child"), nil); err == nil {
		t.Fatal("accepted non-directory parent")
	}
}
