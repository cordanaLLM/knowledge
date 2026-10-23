package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	retrievalTransitionSignatureMethod    = "sshsig-ed25519-detached"
	retrievalTransitionSignatureNamespace = "archeion-retrieval-generation-transition-v1"
	maxAllowedSignersBytes                = int64(1024 * 1024)
	maxSignatureBytes                     = int64(64 * 1024)
	maxSSHKeygenOutputBytes               = int64(64 * 1024)
	sshKeygenPath                         = "/usr/bin/ssh-keygen"
	sshKeygenTimeout                      = 15 * time.Second
)

var sshFingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func readAndAuthorizeAllowedSigners(filePath, actor, keyID string) ([]byte, error) {
	if actor == "" || strings.IndexFunc(actor, func(r rune) bool { return r <= ' ' }) >= 0 {
		return nil, errors.New("actor must be a non-empty SSH principal without whitespace")
	}
	if !sshFingerprintPattern.MatchString(keyID) {
		return nil, errors.New("key ID is not a canonical SSH SHA256 fingerprint")
	}
	policy, err := readStableFile(filePath, "allowed signers", maxAllowedSignersBytes)
	if err != nil {
		return nil, err
	}
	if len(policy) == 0 || bytes.IndexByte(policy, 0) >= 0 || !utf8.Valid(policy) {
		return nil, errors.New("allowed signers policy is empty or invalid UTF-8")
	}
	found := false
	for lineNumber, rawLine := range strings.Split(string(policy), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("allowed signers line %d is malformed", lineNumber+1)
		}
		principalMatch := false
		for _, principal := range strings.Split(fields[0], ",") {
			if principal == actor {
				principalMatch = true
			}
		}
		if !principalMatch {
			continue
		}
		keyIndex := -1
		for index, field := range fields {
			if field == "ssh-ed25519" {
				keyIndex = index
				break
			}
		}
		if keyIndex < 1 || keyIndex+1 >= len(fields) {
			continue
		}
		fingerprint, err := fingerprintEd25519Key(fields[keyIndex+1])
		if err != nil {
			return nil, fmt.Errorf("allowed signers line %d: %w", lineNumber+1, err)
		}
		if fingerprint == keyID {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("actor %q is not authorized by the pinned Ed25519 key", actor)
	}
	return policy, nil
}

func fingerprintEd25519Key(encoded string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("Ed25519 public key is not canonical base64")
	}
	if base64.StdEncoding.EncodeToString(blob) != encoded || len(blob) != 4+len("ssh-ed25519")+4+32 {
		return "", errors.New("Ed25519 public key blob has an invalid shape")
	}
	nameLength := int(binary.BigEndian.Uint32(blob[:4]))
	if nameLength != len("ssh-ed25519") || string(blob[4:4+nameLength]) != "ssh-ed25519" {
		return "", errors.New("public key is not Ed25519")
	}
	offset := 4 + nameLength
	keyLength := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	if keyLength != 32 || offset+4+keyLength != len(blob) {
		return "", errors.New("Ed25519 public key payload is invalid")
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func readCanonicalSSHSIG(filePath, expectedHash string) ([]byte, error) {
	if !validSHA256(expectedHash) {
		return nil, errors.New("signature caller pin is invalid")
	}
	signature, err := readStableFile(filePath, "detached SSHSIG", maxSignatureBytes)
	if err != nil {
		return nil, err
	}
	if digestBytes(signature) != expectedHash {
		return nil, errors.New("detached SSHSIG does not match caller pin")
	}
	if err := validateCanonicalSSHSIG(signature); err != nil {
		return nil, err
	}
	return signature, nil
}

func validateCanonicalSSHSIG(signature []byte) error {
	const begin = "-----BEGIN SSH SIGNATURE-----\n"
	const end = "-----END SSH SIGNATURE-----\n"
	if len(signature) == 0 || bytes.IndexByte(signature, 0) >= 0 || bytes.Contains(signature, []byte("\r")) || !bytes.HasPrefix(signature, []byte(begin)) || !bytes.HasSuffix(signature, []byte(end)) {
		return errors.New("signature is not canonical armored SSHSIG")
	}
	body := signature[len(begin) : len(signature)-len(end)]
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return errors.New("signature SSHSIG body is empty")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		if line == "" || len(line) > 76 {
			return errors.New("signature SSHSIG armor line is invalid")
		}
		for _, character := range line {
			if !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '+' && character != '/' && character != '=' {
				return errors.New("signature SSHSIG armor contains an invalid character")
			}
		}
	}
	return nil
}

func verifyDetachedSSHSIG(payload, signature, policy []byte, actor, keyID, namespace string) error {
	if err := validateCanonicalSSHSIG(signature); err != nil {
		return err
	}
	if !boundedMetadata(namespace) || strings.IndexFunc(namespace, func(r rune) bool { return r <= ' ' }) >= 0 {
		return errors.New("SSHSIG namespace is invalid")
	}
	if _, err := readAndAuthorizeAllowedSignersBytes(policy, actor, keyID); err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "archeion-retrieval-sshsig-")
	if err != nil {
		return errors.New("cannot allocate SSHSIG verification workspace")
	}
	defer os.RemoveAll(directory)
	signaturePath := directory + "/intent.sshsig"
	policyPath := directory + "/allowed_signers"
	if err := writePrivateVerificationFile(signaturePath, signature); err != nil {
		return err
	}
	if err := writePrivateVerificationFile(policyPath, policy); err != nil {
		return err
	}
	if err := validateSSHKeygenBinary(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshKeygenTimeout)
	defer cancel()
	inspectOutput, inspectErr := runSSHKeygen(ctx, directory, payload, "-Y", "check-novalidate", "-n", namespace, "-s", signaturePath)
	if inspectErr != nil || !bytes.Contains(inspectOutput, []byte("with ED25519 key "+keyID)) {
		return errors.New("SSHSIG is not an Ed25519 signature from the declared key")
	}
	if output, err := runSSHKeygen(ctx, directory, payload, "-Y", "verify", "-f", policyPath, "-I", actor, "-n", namespace, "-s", signaturePath); err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 256 {
			message = message[:256]
		}
		return fmt.Errorf("allowed-signers verification failed: %s", message)
	}
	return nil
}

func validateSSHKeygenBinary() error {
	if !filepath.IsAbs(sshKeygenPath) || filepath.Clean(sshKeygenPath) != sshKeygenPath || validateNoSymlinkPath(sshKeygenPath) != nil {
		return errors.New("trusted ssh-keygen path is unavailable")
	}
	for directory := filepath.Dir(sshKeygenPath); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		stat, ok := infoSysStat(info)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ok || stat.Uid != 0 {
			return errors.New("trusted ssh-keygen directory chain is unsafe")
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	info, err := os.Lstat(sshKeygenPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("trusted ssh-keygen binary has unsafe type or permissions")
	}
	stat, ok := infoSysStat(info)
	if !ok || stat.Uid != 0 {
		return errors.New("trusted ssh-keygen binary is not root-owned")
	}
	return nil
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func runSSHKeygen(ctx context.Context, directory string, payload []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, sshKeygenPath, args...) // #nosec G204 -- Fixed /usr/bin/ssh-keygen binary; arguments bypass a shell.
	command.Dir = directory
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	command.Stdin = bytes.NewReader(payload)
	stdout := &cappedBuffer{limit: maxSSHKeygenOutputBytes}
	stderr := &cappedBuffer{limit: maxSSHKeygenOutputBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	output := append(append([]byte(nil), stdout.buffer.Bytes()...), stderr.buffer.Bytes()...)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, errors.New("ssh-keygen verification exceeded the fixed 15-second boundary")
	}
	if stdout.overflow || stderr.overflow {
		return output, errors.New("ssh-keygen verification output exceeded its fixed bound")
	}
	return output, err
}

func readAndAuthorizeAllowedSignersBytes(policy []byte, actor, keyID string) ([]byte, error) {
	temp, err := os.CreateTemp("", "archeion-retrieval-policy-")
	if err != nil {
		return nil, err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		return nil, closeWithError(err, temp)
	}
	if _, err := temp.Write(policy); err != nil {
		return nil, closeWithError(err, temp)
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	return readAndAuthorizeAllowedSigners(name, actor, keyID)
}

func writePrivateVerificationFile(filePath string, data []byte) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- Caller uses fixed artifact filenames under a new private verification directory; exclusive create rejects replacements.
	if err != nil {
		return errors.New("cannot create SSHSIG verification input")
	}
	if _, err := file.Write(data); err != nil {
		return closeWithError(errors.New("cannot write SSHSIG verification input"), file)
	}
	if err := file.Sync(); err != nil {
		return closeWithError(errors.New("cannot sync SSHSIG verification input"), file)
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close SSHSIG verification input")
	}
	return nil
}
