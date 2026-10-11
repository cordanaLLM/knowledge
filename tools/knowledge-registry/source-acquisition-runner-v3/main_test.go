package main

import (
	"strings"
	"testing"
)

// TestVerifyPinnedTrustRoot proves the runner binds to the committed acquisition
// signer key: a caller-supplied allowed_signers policy is only honored when it
// authorizes the pinned key, so an attacker cannot swap in their own trust root.
func TestVerifyPinnedTrustRoot(t *testing.T) {
	valid := []byte("archeion-knowledge-acquisition-signer@example.com namespaces=\"archeion-knowledge-source-acquisition-plan-v1\" " + pinnedAcquisitionSignerKey + "\n")
	if err := verifyPinnedTrustRoot(valid); err != nil {
		t.Fatalf("policy pinning the committed key was rejected: %v", err)
	}
	foreign := []byte("attacker@evil namespaces=\"archeion-knowledge-source-acquisition-plan-v1\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + strings.Repeat("B", 43) + "\n")
	if err := verifyPinnedTrustRoot(foreign); err == nil {
		t.Fatal("policy without the committed key was accepted")
	}
	if err := verifyPinnedTrustRoot(nil); err == nil {
		t.Fatal("empty policy accepted")
	}
}
