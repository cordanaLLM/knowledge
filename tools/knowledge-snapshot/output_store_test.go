package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestOutputStoreRejectsSymlinkedOutputChildrenWithoutExternalWrites(t *testing.T) {
	children := []string{
		".staging",
		"raw",
		"review",
		"manifests",
		"quarantine",
		"inventory-proposals",
		"inventory-quarantine",
		"change-packs",
		"standing-admissions",
		"standing-admission-quarantine",
	}
	for _, child := range children {
		t.Run(child, func(t *testing.T) {
			base := t.TempDir()
			store := filepath.Join(base, "store")
			external := filepath.Join(base, "external")
			if err := os.Mkdir(store, 0o755); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, external, "canary", []byte("do not modify\n"))
			before := directoryFingerprint(t, external)
			if err := os.Symlink(external, filepath.Join(store, child)); err != nil {
				t.Fatal(err)
			}
			relative := child + "/sha256/aa/object"
			if err := writeImmutableObject(store, relative, []byte("snapshot output\n"), 0o444); err == nil {
				t.Fatalf("writeImmutableObject() followed symlinked %s output parent", child)
			}
			if after := directoryFingerprint(t, external); after != before {
				t.Fatalf("external directory changed through symlinked %s parent\nbefore %s\nafter  %s", child, before, after)
			}
		})
	}
}

func TestOutputStoreRejectsSymlinkedStoreRootWithoutExternalWrites(t *testing.T) {
	base := t.TempDir()
	external := filepath.Join(base, "external")
	writeTestFile(t, external, "canary", []byte("do not modify\n"))
	before := directoryFingerprint(t, external)
	store := filepath.Join(base, "store")
	if err := os.Symlink(external, store); err != nil {
		t.Fatal(err)
	}
	if err := writeImmutableObject(store, "manifests/sha256/aa/object.json", []byte("snapshot output\n"), 0o444); err == nil {
		t.Fatal("writeImmutableObject() accepted a symlinked store root")
	}
	if after := directoryFingerprint(t, external); after != before {
		t.Fatalf("external directory changed through symlinked store root\nbefore %s\nafter  %s", before, after)
	}
}

func TestOutputStoreRejectsRootIdentitySwapBeforeCommit(t *testing.T) {
	base := t.TempDir()
	storePath := filepath.Join(base, "store")
	if err := os.Mkdir(storePath, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := openOutputStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	moved := filepath.Join(base, "moved-store")
	if err := os.Rename(storePath, moved); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(base, "external")
	writeTestFile(t, external, "canary", []byte("do not modify\n"))
	before := directoryFingerprint(t, external)
	if err := os.Symlink(external, storePath); err != nil {
		t.Fatal(err)
	}
	if err := store.writeImmutable("manifests/sha256/aa/object.json", []byte("snapshot output\n"), 0o444); err == nil {
		t.Fatal("writeImmutable() accepted a replaced store-root identity")
	}
	if after := directoryFingerprint(t, external); after != before {
		t.Fatalf("external directory changed after root swap\nbefore %s\nafter  %s", before, after)
	}
	if _, err := os.Lstat(filepath.Join(moved, "manifests", "sha256", "aa", "object.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("root-swap failure published an object in the detached store: %v", err)
	}
}

func TestOutputStoreRejectsParentSwapWithoutExternalWrites(t *testing.T) {
	base := t.TempDir()
	storePath := filepath.Join(base, "store")
	parent := filepath.Join(storePath, "manifests")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := openOutputStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	external := filepath.Join(base, "external")
	writeTestFile(t, external, "canary", []byte("do not modify\n"))
	before := directoryFingerprint(t, external)
	parked := filepath.Join(storePath, "manifests.parked")
	swapped := make(chan error, 1)
	restore := make(chan struct{})
	restored := make(chan error, 1)
	go func() {
		if err := os.Rename(parent, parked); err != nil {
			swapped <- err
			return
		}
		if err := os.Symlink(external, parent); err != nil {
			swapped <- err
			return
		}
		swapped <- nil
		<-restore
		if err := os.Remove(parent); err != nil {
			restored <- err
			return
		}
		restored <- os.Rename(parked, parent)
	}()
	if err := <-swapped; err != nil {
		t.Fatal(err)
	}
	writeErr := store.writeImmutable("manifests/sha256/aa/object.json", []byte("snapshot output\n"), 0o444)
	close(restore)
	if err := <-restored; err != nil {
		t.Fatal(err)
	}
	if writeErr == nil {
		t.Fatal("writeImmutable() accepted a concurrently swapped output parent")
	}
	if after := directoryFingerprint(t, external); after != before {
		t.Fatalf("external directory changed after parent swap\nbefore %s\nafter  %s", before, after)
	}
}

func TestCompileRejectsRawStoreSymlinkWithoutExternalWrites(t *testing.T) {
	base := t.TempDir()
	store := filepath.Join(base, "store")
	if err := os.Mkdir(store, 0o755); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(base, "external")
	writeTestFile(t, external, "canary", []byte("do not modify\n"))
	before := directoryFingerprint(t, external)
	if err := os.Symlink(external, filepath.Join(store, "raw")); err != nil {
		t.Fatal(err)
	}
	_, err := Compile(withFixtureReview(CompileConfig{
		SpecPath:   filepath.Join("testdata", "source-spec.json"),
		MirrorBase: filepath.Join("testdata", "mirrors"),
		StoreRoot:  store,
	}))
	if err == nil {
		t.Fatal("Compile() succeeded through a symlinked raw CAS root")
	}
	if after := directoryFingerprint(t, external); after != before {
		t.Fatalf("compile changed external directory through raw symlink\nbefore %s\nafter  %s", before, after)
	}
	if got := countRegularFiles(t, filepath.Join(store, "manifests")); got != 0 {
		t.Fatalf("compile emitted %d manifests after raw output rejection", got)
	}
}

func directoryFingerprint(t *testing.T, root string) string {
	t.Helper()
	entries := make([]string, 0)
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		line := filepath.ToSlash(relative) + "|" + info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(current)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			line += "|" + hex.EncodeToString(digest[:])
		}
		entries = append(entries, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	digest := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(digest[:])
}
