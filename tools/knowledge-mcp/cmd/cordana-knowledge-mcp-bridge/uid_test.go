package main

import (
	"math"
	"testing"
)

func TestCredentialUIDBounds(t *testing.T) {
	for _, value := range []int{0, 1, math.MaxUint32} {
		got, err := credentialUID(value)
		if err != nil || uint64(got) != uint64(value) {
			t.Fatalf("uid %d: %d %v", value, got, err)
		}
	}
	for _, value := range []int{-1, math.MaxUint32 + 1} {
		if _, err := credentialUID(value); err == nil {
			t.Errorf("accepted uid %d", value)
		}
	}
}
