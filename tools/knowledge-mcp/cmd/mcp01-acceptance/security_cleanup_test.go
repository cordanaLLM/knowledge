package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopySuiteTreeRejectsSymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, external := range []bool{false, true} {
		suite := t.TempDir()
		target := outside
		if !external {
			target = "inside"
			if err := os.WriteFile(filepath.Join(suite, target), []byte("inside"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(target, filepath.Join(suite, "link")); err != nil {
			t.Fatal(err)
		}
		copied, err := copySuiteTree(suite)
		if copied != "" {
			t.Cleanup(func() {
				if err := os.RemoveAll(copied); err != nil {
					t.Error(err)
				}
			})
		}
		if err == nil {
			t.Errorf("accepted symlink (external=%v)", external)
		}
	}
}

func TestCopySuiteTreeRegularAndEmpty(t *testing.T) {
	for _, content := range []string{"", "fixture"} {
		suite := t.TempDir()
		if err := os.WriteFile(filepath.Join(suite, "file"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		copied, err := copySuiteTree(suite)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(copied); err != nil {
				t.Error(err)
			}
		})
		raw, err := os.ReadFile(filepath.Join(copied, "file"))
		if err != nil || string(raw) != content {
			t.Fatalf("copy: %q %v", raw, err)
		}
	}
}
