package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const maxVerifierBytes = int64(128 * 1024 * 1024)

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	overflow bool
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining <= 0 {
		b.overflow = true
		return len(data), nil
	}
	write := data
	if int64(len(write)) > remaining {
		write = write[:remaining]
		b.overflow = true
	}
	_, _ = b.buffer.Write(write)
	return len(data), nil
}

// verifierInputs is the per-authority slice of a build the trusted evidence
// verifier reruns. The verifier binary and its pinned digest are shared across
// every lineage; only these source paths change per authority.
type verifierInputs struct {
	SnapshotManifestPath string
	RawStoreRoot         string
	SpecPath             string
	ProposalPath         string
	ReviewReceiptPath    string
	ReviewSignaturePath  string
	AllowedSignersPath   string
}

func lineageVerifierInputs(lineage LineageConfig) verifierInputs {
	return verifierInputs{
		SnapshotManifestPath: lineage.SnapshotManifestPath,
		RawStoreRoot:         lineage.RawStoreRoot,
		SpecPath:             lineage.SpecPath,
		ProposalPath:         lineage.ProposalPath,
		ReviewReceiptPath:    lineage.ReviewReceiptPath,
		ReviewSignaturePath:  lineage.ReviewSignaturePath,
		AllowedSignersPath:   lineage.AllowedSignersPath,
	}
}

func verifyEvidenceBoundary(inputs verifierInputs, verifierPath, verifierHash string, limits buildLimits, evidenceBytes []byte, expected EvidenceManifest) []QuarantineIssue {
	verifierBytes, err := readStableFile(verifierPath, "evidence verifier", maxVerifierBytes)
	if err != nil {
		return []QuarantineIssue{issue("evidence_verifier_unavailable", "evidence-verifier", "trusted evidence verifier is not a bounded regular non-symlink file")}
	}
	if digestBytes(verifierBytes) != verifierHash {
		return []QuarantineIssue{issue("evidence_verifier_identity_mismatch", "evidence-verifier-sha256", "evidence verifier bytes do not match the operator-pinned SHA-256")}
	}
	info, err := os.Stat(verifierPath)
	if err != nil || info.Mode()&0o111 == 0 {
		return []QuarantineIssue{issue("evidence_verifier_not_executable", "evidence-verifier", "evidence verifier is not executable")}
	}
	verifyStore, err := os.MkdirTemp("", "knowledge-retrieval-evidence-verify-")
	if err != nil {
		return []QuarantineIssue{issue("evidence_verifier_workspace_failed", "evidence-verifier", "isolated evidence verification workspace could not be created")}
	}
	defer os.RemoveAll(verifyStore)
	// Execute an isolated copy of the bytes whose operator-pinned digest was
	// checked above. Re-opening the caller path for exec would leave a path
	// replacement window between hashing and execution.
	verifiedExecutable := filepath.Join(verifyStore, "knowledge-evidence")
	if err := os.WriteFile(verifiedExecutable, verifierBytes, 0o500); err != nil { // #nosec G306 -- Owner execute is required to run the digest-pinned verifier; owner read and no group/world permissions.
		return []QuarantineIssue{issue("evidence_verifier_workspace_failed", "evidence-verifier", "verified evidence executable could not be materialized in its isolated workspace")}
	}
	if copied, err := readStableFile(verifiedExecutable, "verified evidence executable", maxVerifierBytes); err != nil || digestBytes(copied) != verifierHash {
		return []QuarantineIssue{issue("evidence_verifier_workspace_failed", "evidence-verifier", "isolated evidence executable failed its post-copy identity check")}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := []string{
		"compile",
		"--manifest", inputs.SnapshotManifestPath,
		"--raw-store", inputs.RawStoreRoot,
		"--store", verifyStore,
		"--spec", inputs.SpecPath,
		"--proposal", inputs.ProposalPath,
		"--review-receipt", inputs.ReviewReceiptPath,
		"--review-signature", inputs.ReviewSignaturePath,
		"--allowed-signers", inputs.AllowedSignersPath,
		"--max-files", strconv.Itoa(limits.maxFiles),
		"--max-file-bytes", strconv.FormatInt(limits.maxPayloadBytes, 10),
		"--max-total-bytes", strconv.FormatInt(limits.maxTotalBytes, 10),
		"--max-spans", strconv.Itoa(limits.maxSpans),
		"--max-output-bytes", strconv.FormatInt(limits.maxTotalBytes, 10),
	}
	command := exec.CommandContext(ctx, verifiedExecutable, args...) // #nosec G204 -- Executes isolated knowledge-evidence bytes verified against the operator-pinned digest; no shell.
	command.Dir = verifyStore
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	stdout := &cappedBuffer{limit: 1024 * 1024}
	stderr := &cappedBuffer{limit: 1024 * 1024}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return []QuarantineIssue{issue("evidence_verifier_timeout", "evidence-verifier", "evidence verifier exceeded the fixed five-minute boundary")}
	}
	if runErr != nil {
		return []QuarantineIssue{issue("evidence_verifier_rejected", "evidence-verifier", "knowledge-evidence rejected the signed snapshot or exact evidence compilation failed")}
	}
	if stdout.overflow || stderr.overflow {
		return []QuarantineIssue{issue("evidence_verifier_output_limit", "evidence-verifier", "evidence verifier output exceeded its fixed bound")}
	}
	var response struct {
		ManifestID   string `json:"manifest_id"`
		ManifestPath string `json:"manifest_path"`
		FileCount    int    `json:"file_count"`
		SpanCount    int    `json:"span_count"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.buffer.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return []QuarantineIssue{issue("evidence_verifier_response_invalid", "evidence-verifier", "evidence verifier did not return its strict result contract")}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return []QuarantineIssue{issue("evidence_verifier_response_invalid", "evidence-verifier", "evidence verifier returned multiple values")}
	}
	if response.ManifestID != expected.ManifestID || response.FileCount != expected.FileCount || response.SpanCount != expected.SpanCount {
		return []QuarantineIssue{issue("evidence_verifier_result_mismatch", "evidence-manifest", "independent evidence compilation produced a different identity or count")}
	}
	manifestPath, err := filepath.Abs(response.ManifestPath)
	if err != nil || !isWithin(verifyStore, manifestPath) {
		return []QuarantineIssue{issue("evidence_verifier_path_escape", "evidence-verifier", "evidence verifier result path escaped its isolated output store")}
	}
	recompiled, err := readStableFile(manifestPath, "recompiled evidence manifest", maxManifestBytes)
	if err != nil || !bytes.Equal(recompiled, evidenceBytes) {
		return []QuarantineIssue{issue("evidence_verifier_manifest_mismatch", "evidence-manifest", "independent evidence compilation was not byte-identical to the supplied manifest")}
	}
	return nil
}
