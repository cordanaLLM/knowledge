package main

import (
	"bytes"
	"encoding/binary"
	"errors"
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
func TestReadSSHStringEnvelopeBounds(t *testing.T) {
	for _, length := range []uint32{0, 1, 2, 1<<32 - 1} {
		var data bytes.Buffer
		if err := binary.Write(&data, binary.BigEndian, length); err != nil {
			t.Fatal(err)
		}
		data.WriteByte('x')
		got, err := readSSHString(bytes.NewReader(data.Bytes()))
		if length <= 1 && (err != nil || len(got) != int(length)) {
			t.Fatalf("length %d: %q %v", length, got, err)
		}
		if length > 1 && err == nil {
			t.Fatalf("accepted truncated length %d", length)
		}
	}
}
