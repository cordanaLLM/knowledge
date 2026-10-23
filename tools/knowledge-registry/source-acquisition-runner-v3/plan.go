package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// The acquisition plan (the contract document) is authorized by a detached
// Ed25519 SSHSIG produced by the committed knowledge-acquisition service signer
// and verified against the operator-trusted allowed_signers policy. The runner
// refuses to use any plan bytes until the signature verifies in the exact plan
// namespace; the acknowledged contract id is a second, human gate on top.
const (
	planSignatureNamespace = "archeion-knowledge-source-acquisition-plan-v1"
	planSignerPrincipal    = "archeion-knowledge-acquisition-signer@example.com"
	sshKeygenPath          = "/usr/bin/ssh-keygen"
	maxSignatureBytes      = int64(64 * 1024)
	maxAllowedSignersBytes = int64(256 * 1024)
	sshKeygenVerifyTimeout = 15 * time.Second
)

// verifyPlanSignature fails closed unless the detached SSHSIG over the exact
// plan bytes verifies for the fixed acquisition-signer principal in the exact
// plan namespace, using the operator-supplied allowed_signers policy.
func verifyPlanSignature(planBytes, signature, allowedSigners []byte) error {
	if len(planBytes) == 0 {
		return errors.New("acquisition plan is empty")
	}
	if !isArmoredSSHSIG(signature) {
		return errors.New("plan signature is not a canonical armored SSHSIG")
	}
	if len(allowedSigners) == 0 {
		return errors.New("allowed-signers policy is empty")
	}
	return verifySSHSIGNamespace(planBytes, signature, allowedSigners, planSignerPrincipal, planSignatureNamespace)
}

func isArmoredSSHSIG(signature []byte) bool {
	const begin = "-----BEGIN SSH SIGNATURE-----\n"
	const end = "-----END SSH SIGNATURE-----\n"
	return len(signature) > len(begin)+len(end) &&
		string(signature[:len(begin)]) == begin &&
		string(signature[len(signature)-len(end):]) == end
}

// verifySSHSIGNamespace mirrors the fixed-binary /usr/bin/ssh-keygen -Y verify
// invocation used across the knowledge tools: the document is fed on stdin, the
// principal and namespace are pinned, and the allowed_signers policy plus the
// detached signature are written to a private temp directory.
func verifySSHSIGNamespace(document, signature, allowedSigners []byte, principal, namespace string) (err error) {
	info, err := os.Lstat(sshKeygenPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return errors.New("fixed ssh-keygen verifier is unavailable")
	}
	directory, err := os.MkdirTemp("", "source-acquisition-plan-verify-")
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := os.RemoveAll(directory); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove signature verification directory: %w", cleanupErr))
		}
	}()
	policyPath := filepath.Join(directory, "allowed_signers")
	signaturePath := filepath.Join(directory, "plan.sig")
	if err := os.WriteFile(policyPath, allowedSigners, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshKeygenVerifyTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, sshKeygenPath, "-Y", "verify", "-f", policyPath,
		"-I", principal, "-n", namespace, "-s", signaturePath) // #nosec G204 -- sshKeygenPath is the fixed /usr/bin/ssh-keygen verifier; arguments are passed directly without a shell.
	command.Stdin = bytes.NewReader(document)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.New("plan signature failed verification for the acquisition signer")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
