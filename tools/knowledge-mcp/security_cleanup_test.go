package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingCloser struct{ failure error }

func (closer failingCloser) Close() error { return closer.failure }

func TestJoinCloseError(t *testing.T) {
	primary := errors.New("primary")
	closing := errors.New("closing")
	for _, cause := range []error{nil, primary} {
		err := joinCloseError(cause, failingCloser{closing})
		if !errors.Is(err, closing) || (cause != nil && !errors.Is(err, cause)) {
			t.Fatalf("joined error %v lost cause %v or close error", err, cause)
		}
	}
	if err := joinCloseError(nil, io.NopCloser(nil)); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryTreeRejectsSymlinkRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := sealDirectoryTree(link); err == nil {
		t.Error("accepted symlink tree root")
	}
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("outside mode changed: %v %v", info, err)
	}
}

func TestDirectoryTreeModesAndBoundaries(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{publishSealedDirMode, publishDirMode} {
		if err := setDirectoryTreeMode(root, mode); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{root, child} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("mode %s: %v %v", path, info, err)
			}
		}
	}
	if err := setDirectoryTreeMode(filepath.Join(root, "absent"), publishDirMode); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setDirectoryTreeMode(file, publishDirMode); err == nil {
		t.Error("accepted regular file as tree")
	}
}

func TestRootedDirectoryModeRejectsEscape(t *testing.T) {
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(directory, "escape")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := chmodRootedDirectory(root, "escape", 0o777); err == nil {
		t.Error("accepted outside symlink")
	}
	if err := chmodRootedDirectory(root, "../escape", 0o777); err == nil {
		t.Error("accepted parent escape")
	}
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("outside changed: %v %v", info, err)
	}
}

func TestRemoveFileError(t *testing.T) {
	primary := errors.New("primary")
	path := filepath.Join(t.TempDir(), "temporary")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeFileError(primary, path); !errors.Is(err, primary) {
		t.Fatal(err)
	}
	err := removeFileError(primary, path)
	if !errors.Is(err, primary) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lost cleanup cause: %v", err)
	}
}

func TestPublishStatusErrorsAndPermissions(t *testing.T) {
	root := t.TempDir()
	if err := writePublishStatus(root, nil, errors.New("failure")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, publishStatusFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("status mode: %v %v", info, err)
	}
	if err := writePublishStatus(filepath.Join(root, "missing"), nil, nil); err == nil {
		t.Error("lost status write failure")
	}
}

func TestPublishCleanupFailureClearsPublishedTrees(t *testing.T) {
	target := t.TempDir()
	published := filepath.Join(target, publishStateDirName)
	if err := os.Mkdir(published, 0o700); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("staging cleanup failed")
	status := &publishStatus{State: "published"}
	err := finishPublishMaterialization(target, "staging", status, nil, func(string) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("lost staging cleanup failure: %v", err)
	}
	if _, err := os.Stat(published); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("published tree survived failure: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(target, publishStatusFileName))
	if err != nil {
		t.Fatal(err)
	}
	var record publishStatus
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.State != "degraded" || record.Reason != failure.Error() {
		t.Errorf("status mismatch: %+v", record)
	}
}

func TestPublishCleanupSuccessKeepsPublishedTrees(t *testing.T) {
	target := t.TempDir()
	published := filepath.Join(target, publishStateDirName)
	if err := os.Mkdir(published, 0o700); err != nil {
		t.Fatal(err)
	}
	status := &publishStatus{State: "published"}
	if err := finishPublishMaterialization(target, "staging", status, nil, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(published); err != nil {
		t.Fatal(err)
	}
}

func placementFixture(t *testing.T) (string, string) {
	t.Helper()
	payload, target := t.TempDir(), t.TempDir()
	for _, name := range []string{publishStateDirName, publishTrustDirName} {
		if err := os.Mkdir(filepath.Join(payload, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return payload, target
}

func assertDegradedPublication(t *testing.T, target string) {
	t.Helper()
	for _, name := range []string{publishStateDirName, publishTrustDirName, publishRetrievalDirName} {
		if _, err := os.Lstat(filepath.Join(target, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("published %s survived failure: %v", name, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(target, publishStatusFileName))
	if err != nil {
		t.Fatal(err)
	}
	var record publishStatus
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.State != "degraded" {
		t.Errorf("status mismatch: %+v", record)
	}
}

func TestRetrievalSealFailureDegradesPublication(t *testing.T) {
	payload, target := placementFixture(t)
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(payload, publishRetrievalDirName)); err != nil {
		t.Fatal(err)
	}
	status := &publishStatus{State: "published"}
	cause := placePublishPayload(config{}, payload, target, status)
	err := finishPublishMaterialization(target, "unused", status, cause, func(string) error { return nil })
	if err == nil {
		t.Error("retrieval sealing failure was not propagated")
	}
	assertDegradedPublication(t, target)
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("outside directory changed: %v %v", info, err)
	}
}

func TestUnpinnedRetrievalPublication(t *testing.T) {
	payload, target := placementFixture(t)
	if err := os.Mkdir(filepath.Join(payload, publishRetrievalDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	status := &publishStatus{State: "published"}
	if err := placePublishPayload(config{}, payload, target, status); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unsealDirectoryTree(target); err != nil {
			t.Error(err)
		}
	})
	if status.RetrievalState != "published_unverified: no catalog pin was configured" {
		t.Fatal(status.RetrievalState)
	}
}

func TestRetrievalPlacementRenameFailure(t *testing.T) {
	target := t.TempDir()
	state, err := placeRetrievalTree(config{}, filepath.Join(target, "missing"), target)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rename failure: %q %v", state, err)
	}
	if state != "" {
		t.Fatalf("failed placement reported state: %q", state)
	}
}

func TestRejectedRetrievalCatalogRemovesTree(t *testing.T) {
	payload, target := placementFixture(t)
	retrieval := filepath.Join(payload, publishRetrievalDirName)
	if err := os.MkdirAll(filepath.Join(retrieval, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(retrieval, "nested", "fixture"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := placeRetrievalTree(config{retrievalCatalog: filepath.Join(target, "missing-catalog"), retrievalCatalogHash: strings.Repeat("0", 64)}, retrieval, target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(state, "unavailable: catalog verification failed:") {
		t.Fatal(state)
	}
	if _, err := os.Lstat(filepath.Join(target, publishRetrievalDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected retrieval tree survived: %v", err)
	}
}
