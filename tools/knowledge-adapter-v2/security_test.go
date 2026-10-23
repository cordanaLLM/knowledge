package main

import (
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
