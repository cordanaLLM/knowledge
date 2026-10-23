package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const (
	reviewReceiptSchemaVersion = "1.0.0"
	reviewSignatureNamespace   = "archeion-knowledge-source-review-v1"
	reviewObjectLayout         = "review/sha256/<first-two>/<hex>"
	maxReviewReceiptBytes      = int64(64 * 1024)
	maxReviewSignatureBytes    = int64(16 * 1024)
	maxAllowedSignersBytes     = int64(1024 * 1024)
)

var reviewerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{2,127}$`)

type reviewArtifact struct {
	Role         string
	Bytes        []byte
	SHA256       string
	Size         int64
	RelativePath string
}

type validatedReview struct {
	Admission ReviewAdmission
	Artifacts []reviewArtifact
}

func validateReviewAdmission(config CompileConfig, specBytes []byte, spec SourceSpec) (validatedReview, []QuarantineIssue) {
	var zero validatedReview
	paths := []struct {
		name  string
		value string
		max   int64
	}{
		{"proposal", config.ProposalPath, maxInventoryProposalBytes},
		{"review_receipt", config.ReviewReceiptPath, maxReviewReceiptBytes},
		{"review_signature", config.ReviewSignaturePath, maxReviewSignatureBytes},
		{"allowed_signers", config.AllowedSignersPath, maxAllowedSignersBytes},
	}
	for _, candidate := range paths {
		if strings.TrimSpace(candidate.value) == "" {
			return zero, []QuarantineIssue{issue("review_admission_missing", candidate.name, "review admission requires every explicitly configured review artifact")}
		}
	}

	proposalBytes, err := readBoundedRegular(config.ProposalPath, maxInventoryProposalBytes)
	if err != nil {
		return zero, []QuarantineIssue{issue("review_proposal_read_failed", "proposal", "review proposal must be a bounded regular non-symlink file")}
	}
	receiptBytes, err := readBoundedRegular(config.ReviewReceiptPath, maxReviewReceiptBytes)
	if err != nil {
		return zero, []QuarantineIssue{issue("review_receipt_read_failed", "review_receipt", "review receipt must be a bounded regular non-symlink file")}
	}
	signatureBytes, err := readBoundedRegular(config.ReviewSignaturePath, maxReviewSignatureBytes)
	if err != nil {
		return zero, []QuarantineIssue{issue("review_signature_read_failed", "review_signature", "review signature must be a bounded regular non-symlink file")}
	}
	policyBytes, err := readBoundedRegular(config.AllowedSignersPath, maxAllowedSignersBytes)
	if err != nil {
		return zero, []QuarantineIssue{issue("review_policy_read_failed", "allowed_signers", "allowed-signers policy must be a bounded regular non-symlink file")}
	}
	reviewBundleSize := int64(len(specBytes)) + int64(len(proposalBytes)) + int64(len(receiptBytes)) +
		int64(len(signatureBytes)) + int64(len(policyBytes))
	if reviewBundleSize > maxReviewBundleBytes {
		return zero, []QuarantineIssue{issue("review_bundle_limit_exceeded", "review", "review artifact bundle exceeds the downstream 64 MiB limit")}
	}

	var proposal InventoryProposal
	if err := decodeStrictDocument(proposalBytes, &proposal); err != nil {
		return zero, []QuarantineIssue{issue("review_proposal_invalid", "proposal", "review proposal is not strict canonical JSON")}
	}
	if boundIssues := validateProposalMetadataBounds(proposal); len(boundIssues) != 0 {
		return zero, boundIssues
	}
	if issues := validateSourceSpec(proposal.SourceSpecDraft); len(issues) != 0 {
		return zero, []QuarantineIssue{issue("review_proposal_spec_invalid", "proposal.source_spec_draft", "proposal source-spec draft is structurally invalid")}
	}
	canonicalProposal, err := marshalDocument(proposal)
	if err != nil || !bytes.Equal(canonicalProposal, proposalBytes) {
		return zero, []QuarantineIssue{issue("review_proposal_noncanonical", "proposal", "review proposal bytes must use the canonical inventory serialization")}
	}
	coreBytes, err := json.Marshal(proposal.InventoryProposalCore)
	if err != nil {
		return zero, []QuarantineIssue{issue("review_proposal_invalid", "proposal", "review proposal payload could not be encoded")}
	}
	payloadDigest := digestBytes(coreBytes)
	if proposal.ProposalPayloadSHA256 != payloadDigest || proposal.ProposalID != "inventory-proposal:"+payloadDigest {
		return zero, []QuarantineIssue{issue("review_proposal_identity_mismatch", "proposal", "review proposal ID and payload hash are not content-derived")}
	}
	if proposal.State != "proposal" || proposal.ReviewState != "unreviewed" || proposal.AuthorityState != "non_authoritative" ||
		proposal.CompileEligible || proposal.PromoteEligible {
		return zero, []QuarantineIssue{issue("review_proposal_state_invalid", "proposal", "only an original unreviewed non-authoritative inventory proposal can enter review admission")}
	}
	draftBytes, err := marshalDocument(proposal.SourceSpecDraft)
	if err != nil || !bytes.Equal(draftBytes, specBytes) || !reflect.DeepEqual(proposal.SourceSpecDraft, spec) {
		return zero, []QuarantineIssue{issue("review_source_spec_mismatch", "source_spec", "source-spec bytes must exactly equal the canonical draft embedded in the reviewed proposal")}
	}
	if !proposalCountsMatch(proposal) {
		return zero, []QuarantineIssue{issue("review_proposal_counts_mismatch", "proposal", "proposal counts or exclusion ledger do not match its embedded source spec")}
	}

	var receipt SourceSpecReviewReceipt
	if err := decodeStrictDocument(receiptBytes, &receipt); err != nil {
		return zero, []QuarantineIssue{issue("review_receipt_invalid", "review_receipt", "review receipt is not strict canonical JSON")}
	}
	if boundIssues := validateReviewReceiptBounds(receipt); len(boundIssues) != 0 {
		return zero, boundIssues
	}
	canonicalReceipt, err := marshalDocument(receipt)
	if err != nil || !bytes.Equal(canonicalReceipt, receiptBytes) {
		return zero, []QuarantineIssue{issue("review_receipt_noncanonical", "review_receipt", "review receipt bytes must use canonical serialization")}
	}
	specDigest := digestBytes(specBytes)
	if receipt.SchemaVersion != reviewReceiptSchemaVersion || receipt.ReceiptKind != "source_spec_review" {
		return zero, []QuarantineIssue{issue("review_receipt_schema_invalid", "review_receipt", "review receipt schema or kind is unsupported")}
	}
	if receipt.ProposalID != proposal.ProposalID || receipt.ProposalPayloadSHA256 != proposal.ProposalPayloadSHA256 {
		return zero, []QuarantineIssue{issue("review_receipt_proposal_mismatch", "review_receipt", "review receipt does not bind the supplied proposal identity")}
	}
	if receipt.SourceSpecSHA256 != specDigest {
		return zero, []QuarantineIssue{issue("review_receipt_spec_mismatch", "review_receipt", "review receipt does not bind the exact source-spec bytes")}
	}
	if !reviewerPattern.MatchString(receipt.Reviewer) {
		return zero, []QuarantineIssue{issue("reviewer_invalid", "review_receipt.reviewer", "reviewer must be an explicit allowed-signers identity")}
	}
	if receipt.Decision != "accepted" {
		return zero, []QuarantineIssue{issue("review_decision_not_accepted", "review_receipt.decision", "only an explicitly accepted review decision admits compilation")}
	}
	if !isCanonicalUTC(receipt.ReviewedAt) {
		return zero, []QuarantineIssue{issue("review_time_invalid", "review_receipt.reviewed_at", "review time must be canonical RFC3339 UTC")}
	}
	if issues := validateReceiptAdmissionMethod(receipt); len(issues) != 0 {
		return zero, issues
	}
	if err := validateAllowedSignersPolicy(policyBytes, receipt.Reviewer); err != nil {
		return zero, []QuarantineIssue{issue("review_policy_invalid", "allowed_signers", "allowed-signers policy must explicitly authorize the reviewer with Ed25519")}
	}
	if !bytes.HasPrefix(signatureBytes, []byte("-----BEGIN SSH SIGNATURE-----\n")) ||
		!bytes.HasSuffix(signatureBytes, []byte("-----END SSH SIGNATURE-----\n")) {
		return zero, []QuarantineIssue{issue("review_signature_invalid", "review_signature", "review signature must be a canonical armored SSHSIG")}
	}
	if err := verifySSHSIG(receiptBytes, signatureBytes, policyBytes, receipt.Reviewer); err != nil {
		return zero, []QuarantineIssue{issue("review_signature_verification_failed", "review_signature", "detached Ed25519 SSHSIG review verification failed")}
	}

	proposalArtifact := makeReviewArtifact("proposal", proposalBytes)
	specArtifact := makeReviewArtifact("source_spec", specBytes)
	receiptArtifact := makeReviewArtifact("receipt", receiptBytes)
	signatureArtifact := makeReviewArtifact("signature", signatureBytes)
	policyArtifact := makeReviewArtifact("trust_policy", policyBytes)
	admission := ReviewAdmission{
		ReceiptSHA256:          receiptArtifact.SHA256,
		ReceiptSize:            receiptArtifact.Size,
		ReceiptObjectPath:      receiptArtifact.RelativePath,
		ProposalID:             proposal.ProposalID,
		ProposalPayloadSHA256:  proposal.ProposalPayloadSHA256,
		ProposalDocumentSHA256: proposalArtifact.SHA256,
		ProposalDocumentSize:   proposalArtifact.Size,
		ProposalObjectPath:     proposalArtifact.RelativePath,
		SourceSpecSHA256:       specArtifact.SHA256,
		SourceSpecSize:         specArtifact.Size,
		SourceSpecObjectPath:   specArtifact.RelativePath,
		Reviewer:               receipt.Reviewer,
		Decision:               receipt.Decision,
		ReviewedAt:             receipt.ReviewedAt,
		SignatureFormat:        "sshsig-ed25519",
		SignatureNamespace:     reviewSignatureNamespace,
		SignatureSHA256:        signatureArtifact.SHA256,
		SignatureSize:          signatureArtifact.Size,
		SignatureObjectPath:    signatureArtifact.RelativePath,
		TrustPolicySHA256:      policyArtifact.SHA256,
		TrustPolicySize:        policyArtifact.Size,
		TrustPolicyObjectPath:  policyArtifact.RelativePath,
		AdmissionMethod:        receipt.AdmissionMethod,
		AdmissionPolicyID:      receipt.AdmissionPolicyID,
		AdmissionPolicySHA256:  receipt.AdmissionPolicySHA256,
	}
	return validatedReview{
		Admission: admission,
		Artifacts: []reviewArtifact{proposalArtifact, specArtifact, receiptArtifact, signatureArtifact, policyArtifact},
	}, nil
}

func validateReceiptAdmissionMethod(receipt SourceSpecReviewReceipt) []QuarantineIssue {
	if receipt.AdmissionMethod == "" {
		if receipt.AdmissionPolicyID != "" || receipt.AdmissionPolicySHA256 != "" {
			return []QuarantineIssue{issue("review_admission_policy_orphaned", "review_receipt.admission_method", "policy identity requires the standing_policy admission method")}
		}
		return nil
	}
	if receipt.AdmissionMethod != "standing_policy" {
		return []QuarantineIssue{issue("review_admission_method_invalid", "review_receipt.admission_method", "admission method is unsupported")}
	}
	if !strings.HasPrefix(receipt.AdmissionPolicyID, "source-admission-policy:sha256:") ||
		!sha256Pattern.MatchString(receipt.AdmissionPolicySHA256) ||
		receipt.AdmissionPolicyID != "source-admission-policy:"+receipt.AdmissionPolicySHA256 {
		return []QuarantineIssue{issue("review_admission_policy_invalid", "review_receipt.admission_policy_id", "standing admission must bind one content-derived policy identity")}
	}
	return nil
}

func decodeStrictDocument(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("document contains multiple JSON values")
	}
	return nil
}

func proposalCountsMatch(proposal InventoryProposal) bool {
	if proposal.FileCount != len(proposal.SourceSpecDraft.Files) ||
		proposal.ExcludedFileCount != len(proposal.SourceSpecDraft.Exclusions) ||
		!reflect.DeepEqual(proposal.Exclusions, proposal.SourceSpecDraft.Exclusions) {
		return false
	}
	var includedBytes, excludedBytes int64
	for _, file := range proposal.SourceSpecDraft.Files {
		includedBytes += file.Size
	}
	for _, excluded := range proposal.SourceSpecDraft.Exclusions {
		excludedBytes += excluded.Size
	}
	return proposal.ByteSize == includedBytes && proposal.ExcludedByteSize == excludedBytes
}

func readBoundedRegular(filePath string, limit int64) ([]byte, error) {
	if err := validateExistingPathComponents(filePath); err != nil {
		return nil, err
	}
	before, err := os.Lstat(filePath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > limit {
		return nil, errors.New("unsafe or oversized review artifact")
	}
	file, err := os.Open(filePath) // #nosec G304 -- Operator-selected review artifact passes component, regular-file, size and identity checks.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("review artifact identity changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("review artifact read failed or exceeded limit")
	}
	after, err := os.Lstat(filePath)
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(data)) || after.ModTime() != opened.ModTime() {
		return nil, errors.New("review artifact changed during read")
	}
	return data, nil
}

func validateExistingPathComponents(candidate string) error {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}
	current := filepath.Clean(abs)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlinked path component")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func validateAllowedSignersPolicy(policy []byte, reviewer string) error {
	scanner := bufio.NewScanner(bytes.NewReader(policy))
	foundReviewer := false
	activeLines := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		activeLines++
		if activeLines > maxAllowedSignerEntries {
			return errors.New("allowed-signers policy exceeds the entry limit")
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "ssh-ed25519" {
			return errors.New("v1 policy permits only simple Ed25519 allowed-signers entries")
		}
		if err := validateEd25519SSHBlob(fields[2]); err != nil {
			return err
		}
		principals := strings.Split(fields[0], ",")
		if len(principals) > maxPrincipalsPerSignerLine {
			return errors.New("allowed-signers entry exceeds the principal limit")
		}
		for _, principal := range principals {
			if principal == reviewer {
				foundReviewer = true
			}
			if principal == "" || len(principal) > 128 || strings.ContainsAny(principal, "*?!") {
				return errors.New("wildcard or empty reviewer principals are forbidden")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if activeLines == 0 || !foundReviewer {
		return errors.New("reviewer absent from policy")
	}
	return nil
}

func validateEd25519SSHBlob(encoded string) error {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	readString := func(data []byte) ([]byte, []byte, error) {
		if len(data) < 4 {
			return nil, nil, errors.New("short SSH key blob")
		}
		length := int(binary.BigEndian.Uint32(data[:4]))
		if length < 0 || len(data) < 4+length {
			return nil, nil, errors.New("invalid SSH key blob length")
		}
		return data[4 : 4+length], data[4+length:], nil
	}
	kind, rest, err := readString(blob)
	if err != nil || string(kind) != "ssh-ed25519" {
		return errors.New("SSH key is not Ed25519")
	}
	key, rest, err := readString(rest)
	if err != nil || len(key) != 32 || len(rest) != 0 {
		return errors.New("invalid Ed25519 SSH key")
	}
	return nil
}

func verifySSHSIG(receipt, signature, allowedSigners []byte, reviewer string) error {
	return verifySSHSIGNamespace(receipt, signature, allowedSigners, reviewer, reviewSignatureNamespace)
}

func verifySSHSIGNamespace(document, signature, allowedSigners []byte, principal, namespace string) error {
	const sshKeygenPath = "/usr/bin/ssh-keygen"
	if err := validateExistingPathComponents(sshKeygenPath); err != nil {
		return err
	}
	keygenInfo, err := os.Lstat(sshKeygenPath)
	if err != nil || !keygenInfo.Mode().IsRegular() || keygenInfo.Mode()&0o111 == 0 {
		return errors.New("fixed ssh-keygen verifier is unavailable")
	}
	directory, err := os.MkdirTemp("", "knowledge-review-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	policyPath := filepath.Join(directory, "allowed_signers")
	signaturePath := filepath.Join(directory, "receipt.sig")
	if err := os.WriteFile(policyPath, allowedSigners, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, sshKeygenPath, "-Y", "verify", "-f", policyPath, "-I", principal,
		"-n", namespace, "-s", signaturePath) // #nosec G204 -- Fixed /usr/bin/ssh-keygen verifier; private artifact paths and principal bypass a shell.
	command.Stdin = bytes.NewReader(document)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func makeReviewArtifact(role string, data []byte) reviewArtifact {
	digest := digestBytes(data)
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return reviewArtifact{
		Role:         role,
		Bytes:        append([]byte(nil), data...),
		SHA256:       digest,
		Size:         int64(len(data)),
		RelativePath: path.Join("review", "sha256", hexDigest[:2], hexDigest),
	}
}

func commitReviewArtifacts(store *outputStore, artifacts []reviewArtifact) error {
	for _, artifact := range artifacts {
		if err := store.writeImmutable(artifact.RelativePath, artifact.Bytes, 0o444); err != nil {
			return fmt.Errorf("commit %s review artifact: %w", artifact.Role, err)
		}
	}
	return nil
}
