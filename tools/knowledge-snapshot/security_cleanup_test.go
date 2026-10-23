package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failingCloser struct {
	err   error
	calls int
}

func (closer *failingCloser) Close() error { closer.calls++; return closer.err }
func TestCloseWithErrorPreservesBothFailures(t *testing.T) {
	primary := errors.New("operation failed")
	cleanup := errors.New("close failed")
	for _, closeErr := range []error{nil, cleanup} {
		closer := &failingCloser{err: closeErr}
		got := closeWithError(primary, closer)
		if !errors.Is(got, primary) || (closeErr != nil && !errors.Is(got, closeErr)) || closer.calls != 1 {
			t.Fatalf("close result %v calls %d", got, closer.calls)
		}
	}
	if got := closeWithError(nil, &failingCloser{}); got != nil {
		t.Fatal(got)
	}
}

func TestOutputDirectoryPrivateAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "new", "store")
	if err := ensureOutputDirectoryTree(target); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("output directory visible outside owner: %o", info.Mode().Perm())
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureOutputDirectoryTree(filepath.Join(link, "child")); err == nil {
		t.Fatal("accepted symlink output directory")
	}
}
