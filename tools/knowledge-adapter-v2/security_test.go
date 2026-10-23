package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestHexRejectsNonHex(t *testing.T) {
	for _, value := range []string{"sha256:" + strings.Repeat("a", 63) + "/", "sha256:" + strings.Repeat("g", 64), "sha256:" + strings.Repeat("a", 63)} {
		if _, err := manifestHex(value); err == nil {
			t.Errorf("accepted malformed manifest ID %q", value)
		}
	}
	if _, err := manifestHex("sha256:" + strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorRejectsTraversalAndUsesPrivateModes(t *testing.T) {
	root := t.TempDir()
	data := []byte("source")
	digest := digestBytes(data)
	hex := strings.TrimPrefix(digest, "sha256:")
	blob := filepath.Join(root, "cas", "sha256", hex[:2], hex)
	if err := os.MkdirAll(filepath.Dir(blob), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../escape", "/absolute", "."} {
		spec := SourceSpec{Files: []ExpectedFile{{RelativePath: name, SHA256: digest, Size: int64(len(data))}}}
		if err := layMirror(filepath.Join(root, "mirror"), spec, filepath.Join(root, "cas")); err == nil {
			t.Errorf("accepted unsafe path %q", name)
		}
	}
	spec := SourceSpec{Files: []ExpectedFile{{RelativePath: "dir/source", SHA256: digest, Size: int64(len(data))}}}
	if err := layMirror(filepath.Join(root, "mirror"), spec, filepath.Join(root, "cas")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "mirror", "dir", "source"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("mirror readable outside owner: %o", info.Mode().Perm())
	}
}

func TestSSHStringLengthBounds(t *testing.T) {
	for _, value := range []int{-1, 1 << 32} {
		if _, err := sshStringLength(value); err == nil {
			t.Errorf("accepted length %d", value)
		}
	}
	for _, value := range []int{0, 32, 1<<32 - 1} {
		got, err := sshStringLength(value)
		if err != nil || uint64(got) != uint64(value) {
			t.Errorf("length %d: %d %v", value, got, err)
		}
	}
}

func TestSSHStringOverflowReturnsError(t *testing.T) {
	prev := sshStringLength
	defer func() { sshStringLength = prev }()

	overflowErr := errors.New("SSH string exceeds uint32 length")
	sshStringLength = func(length int) (uint32, error) {
		return 0, overflowErr
	}

	if _, err := sshString([]byte("test")); !errors.Is(err, overflowErr) {
		t.Fatalf("sshString: expected overflow error, got %v", err)
	}

	pub := devPrivateKey().Public().(ed25519.PublicKey)
	if _, err := ed25519PublicBlob(pub); err == nil || !strings.Contains(err.Error(), "key type") {
		t.Fatalf("ed25519PublicBlob: expected field in error, got %v", err)
	}

	if _, err := allowedSignersDocument(); err == nil || !strings.Contains(err.Error(), "key type") {
		t.Fatalf("allowedSignersDocument: expected field in error, got %v", err)
	}
}

func TestMarshalPrivateKeyFieldOverflow(t *testing.T) {
	prev := sshStringLength
	defer func() { sshStringLength = prev }()

	var failIdx int
	var currentCall int
	sshStringLength = func(length int) (uint32, error) {
		currentCall++
		if currentCall == failIdx {
			return 0, errors.New("SSH string exceeds uint32 length")
		}
		return defaultSSHStringLength(length)
	}

	priv := devPrivateKey()
	fields := []string{
		"key type", "public key",
		"key type", "public key", "private key", "comment",
		"cipher name", "kdf name", "kdf options",
		"public key blob", "private key blob",
	}
	for i, field := range fields {
		currentCall = 0
		failIdx = i + 1
		_, err := marshalOpenSSHPrivateKey(priv, "dev-comment")
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("field %q: expected field name in error, got %v", field, err)
		}
	}
}
