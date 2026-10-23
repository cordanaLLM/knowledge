package main

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

type failingCloser struct {
	err   error
	calls int
}

func (c *failingCloser) Close() error { c.calls++; return c.err }

func TestCheckedUID(t *testing.T) {
	cases := []struct {
		name  string
		value int
		want  uint32
		bad   bool
	}{
		{"negative", -1, 0, true}, {"zero", 0, 0, false}, {"positive", 42, 42, false},
	}
	if strconv.IntSize == 64 {
		cases = append(cases,
			struct {
				name  string
				value int
				want  uint32
				bad   bool
			}{"maximum", math.MaxUint32, math.MaxUint32, false},
			struct {
				name  string
				value int
				want  uint32
				bad   bool
			}{"overflow", math.MaxUint32 + 1, 0, true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkedUID(tc.value)
			if (err != nil) != tc.bad || got != tc.want {
				t.Fatalf("checkedUID(%d) = %d, %v", tc.value, got, err)
			}
		})
	}
}

func TestCloseWithError(t *testing.T) {
	primary := errors.New("operation")
	cleanup := errors.New("cleanup")
	cases := []struct {
		name             string
		primary, cleanup error
	}{
		{"success", nil, nil}, {"primary", primary, nil}, {"cleanup", nil, cleanup}, {"both", primary, cleanup},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			closer := &failingCloser{err: tc.cleanup}
			got := closeWithError(tc.primary, closer)
			if closer.calls != 1 {
				t.Fatalf("close calls = %d", closer.calls)
			}
			if (got == nil) != (tc.primary == nil && tc.cleanup == nil) {
				t.Fatalf("error = %v", got)
			}
			for _, want := range []error{tc.primary, tc.cleanup} {
				if want != nil && !errors.Is(got, want) {
					t.Fatalf("lost error %v: %v", want, got)
				}
			}
		})
	}
}
