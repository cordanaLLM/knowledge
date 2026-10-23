package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// The review bundle is signed by a deterministic, non-secret development
// Ed25519 identity derived from a fixed public seed. Nothing here grants
// authority: the produced review only marks the non-authoritative acceptance
// evidence, and the compilers still independently re-verify the SSHSIG. The
// seed is public on purpose so the committed acceptance manifests reproduce
// byte-for-byte without ever committing a private key.
const (
	devReviewerPrincipal     = "knowledge-adapter-v2-dev-reviewer"
	devKeySeedLabel          = "example.com/knowledge-adapter-v2 deterministic dev review key v1"
	reviewSignatureNamespace = "archeion-knowledge-source-review-v1"
	sshKeygenPath            = "/usr/bin/ssh-keygen"
)

func devSeed() []byte {
	digest := sha256.Sum256([]byte(devKeySeedLabel))
	return digest[:]
}

func devPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(devSeed())
}

func sshString(value []byte) []byte {
	length, err := sshStringLength(len(value))
	if err != nil {
		panic(err)
	}
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(out, length)
	copy(out[4:], value)
	return out
}

func sshStringLength(length int) (uint32, error) {
	if length < 0 || length > math.MaxUint32 {
		return 0, errors.New("SSH string exceeds uint32 length")
	}
	return uint32(length), nil
}

func ed25519PublicBlob(pub ed25519.PublicKey) []byte {
	var blob []byte
	blob = append(blob, sshString([]byte("ssh-ed25519"))...)
	blob = append(blob, sshString(pub)...)
	return blob
}

// allowedSignersDocument returns the operator-trusted allowed_signers policy
// authorizing exactly the deterministic dev reviewer with its Ed25519 key.
func allowedSignersDocument() []byte {
	pub := devPrivateKey().Public().(ed25519.PublicKey)
	line := devReviewerPrincipal + " ssh-ed25519 " + base64.StdEncoding.EncodeToString(ed25519PublicBlob(pub)) + "\n"
	return []byte(line)
}

// marshalOpenSSHPrivateKey encodes the deterministic dev key in the unencrypted
// OpenSSH private-key format so /usr/bin/ssh-keygen can sign with it. The two
// four-byte check words are fixed (they never affect the detached signature),
// keeping the transient key file itself deterministic.
func marshalOpenSSHPrivateKey(priv ed25519.PrivateKey, comment string) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	pubBlob := ed25519PublicBlob(pub)
	check := []byte{0x63, 0x61, 0x75, 0x64} // "caud"
	var private []byte
	private = append(private, check...)
	private = append(private, check...)
	private = append(private, sshString([]byte("ssh-ed25519"))...)
	private = append(private, sshString(pub)...)
	private = append(private, sshString(priv)...)
	private = append(private, sshString([]byte(comment))...)
	for pad := byte(1); len(private)%8 != 0; pad++ {
		private = append(private, pad)
	}
	var blob []byte
	blob = append(blob, []byte("openssh-key-v1\x00")...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString([]byte{})...)
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, 1)
	blob = append(blob, count...)
	blob = append(blob, sshString(pubBlob)...)
	blob = append(blob, sshString(private)...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: blob})
}

// signReviewReceipt writes the receipt and the transient dev key, produces a
// detached armored Ed25519 SSHSIG with the review namespace, and returns the
// signature bytes. The result is deterministic for a fixed receipt.
func signReviewReceipt(receiptBytes []byte, workDir string) ([]byte, error) {
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare signing work dir: %w", err)
	}
	keyPath := filepath.Join(workDir, "dev-review-key")
	if err := os.WriteFile(keyPath, marshalOpenSSHPrivateKey(devPrivateKey(), devReviewerPrincipal), 0o400); err != nil {
		return nil, fmt.Errorf("write transient dev review key: %w", err)
	}
	defer os.Remove(keyPath)
	receiptPath := filepath.Join(workDir, "review-receipt.json")
	if err := os.WriteFile(receiptPath, receiptBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write review receipt for signing: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, sshKeygenPath, "-Y", "sign", "-q", "-f", keyPath,
		"-n", reviewSignatureNamespace, receiptPath) // #nosec G204 -- Fixed /usr/bin/ssh-keygen binary; paths are arguments without a shell.
	if output, err := command.CombinedOutput(); err != nil || ctx.Err() != nil {
		return nil, fmt.Errorf("ssh-keygen review signing failed: %v: %s", err, output)
	}
	signature, err := os.ReadFile(receiptPath + ".sig") // #nosec G304 -- Signature is emitted by fixed ssh-keygen in the operator-selected private signing directory.
	if err != nil {
		return nil, fmt.Errorf("read detached review signature: %w", err)
	}
	if !isArmoredSSHSIG(signature) {
		return nil, errors.New("produced review signature is not a canonical armored SSHSIG")
	}
	return signature, nil
}

func isArmoredSSHSIG(signature []byte) bool {
	const begin = "-----BEGIN SSH SIGNATURE-----\n"
	const end = "-----END SSH SIGNATURE-----\n"
	return len(signature) > len(begin)+len(end) &&
		string(signature[:len(begin)]) == begin &&
		string(signature[len(signature)-len(end):]) == end
}
