package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if err := ensureAbsoluteDirectoryTree(target); err != nil {
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
	if err := ensureAbsoluteDirectoryTree(filepath.Join(link, "child")); err == nil {
		t.Fatal("accepted symlink output directory")
	}
}

type embeddingBody struct {
	*strings.Reader
	err    error
	closed bool
}

func (body *embeddingBody) Close() error { body.closed = true; return body.err }
func TestDecodeEmbeddingResponseClosesBodyAndReportsErrors(t *testing.T) {
	closeErr := errors.New("body close failed")
	for _, fixture := range []struct {
		payload  string
		closeErr error
		wantErr  bool
	}{
		{`{"data":[]}`, nil, false}, {`{"data":[]}`, closeErr, true}, {`{`, nil, true}, {``, nil, true},
	} {
		body := &embeddingBody{Reader: strings.NewReader(fixture.payload), err: fixture.closeErr}
		_, err := decodeEmbeddingResponse(body)
		if !body.closed || (err != nil) != fixture.wantErr {
			t.Errorf("payload %q err %v closed %v", fixture.payload, err, body.closed)
		}
		if fixture.closeErr != nil && !errors.Is(err, fixture.closeErr) {
			t.Errorf("lost close cause: %v", err)
		}
	}
}
