package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	sourceSpecSchemaVersion    = "1.0.0"
	reviewReceiptSchemaVersion = "1.0.0"
	// observedAt fixes the deterministic acquisition-observation, review, and
	// decision instant. It is at or after the acquisition execution time so the
	// review never predates the source it accepts.
	observedAt  = "2026-07-17T14:45:40Z"
	reviewedAt  = "2026-07-17T14:45:40Z"
	toolTimeout = 180 * time.Second
)

var requiredPermissions = []string{
	"commercial", "eval", "export", "media", "quote",
	"redistribution", "retrieval", "skill", "training",
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func marshalDocument(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func loadAcquisition(path string) (acquisitionDocument, error) {
	var doc acquisitionDocument
	data, err := os.ReadFile(path)
	if err != nil {
		return doc, fmt.Errorf("read acquisition document %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("decode acquisition document %s: %w", path, err)
	}
	if len(doc.Targets) == 0 {
		return doc, fmt.Errorf("acquisition document %s carries no targets", path)
	}
	return doc, nil
}

// buildSourceSpec derives the reviewed exact-version source specification for
// one authority. Every version, revision, rights, file digest and size is taken
// from the acquisition receipt/proposal target so the spec is cross-bound to it.
func buildSourceSpec(target acquisitionTarget) SourceSpec {
	files := make([]ExpectedFile, 0, len(target.Files))
	for _, file := range target.Files {
		files = append(files, ExpectedFile{
			RelativePath: file.Path,
			MediaType:    "text/plain",
			SHA256:       file.RawSHA256,
			Size:         file.Bytes,
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].RelativePath < files[j].RelativePath })
	permissions := make(map[string]string, len(requiredPermissions))
	for _, name := range requiredPermissions {
		permissions[name] = "true"
	}
	return SourceSpec{
		SchemaVersion:      sourceSpecSchemaVersion,
		SnapshotID:         "snp:p1-src-03:" + target.Repository + "@" + target.ComponentVersion,
		SourceID:           "src:github:" + target.Repository + "@" + target.ComponentVersion,
		CanonicalURI:       "https://github.com/" + target.Repository + "/tree/" + target.ResolvedCommitSHA1,
		ComponentID:        "cmp:github:" + target.Repository,
		ComponentVersionID: "ver:github:" + target.Repository + "@" + target.ComponentVersion,
		ResolvedVersion:    target.ComponentVersion,
		SourceRevision:     target.ResolvedCommitSHA1,
		ChannelID:          "chn:" + target.ComponentID + ":source",
		ChannelType:        "source",
		Rights: Rights{
			LicenseExpression: target.LicenseExpression,
			RightsBasis:       "upstream-license",
			Attribution:       target.Publisher.Name,
			Permissions:       permissions,
		},
		AccessScope:    "public",
		Classification: "public",
		SecurityDomain: "public",
		Language:       "en",
		FetchedAt:      observedAt,
		ObservedAt:     observedAt,
		MirrorPath:     target.ComponentID + "/" + target.ComponentVersion,
		Provenance:     Provenance{OriginKind: "official"},
		Exclusions:     []VerifiedExclusion{},
		Files:          files,
	}
}

// buildProposal wraps the spec as an unreviewed non-authoritative inventory
// proposal. The metadata hash binds the acquisition receipt, proposal, and
// authority identity so the proposal cannot be replayed against another source.
func buildProposal(spec SourceSpec, target acquisitionTarget, receiptID, acquisitionProposalID string) (InventoryProposal, error) {
	var byteSize int64
	for _, file := range spec.Files {
		byteSize += file.Size
	}
	metaBytes, err := json.Marshal(struct {
		AcquisitionReceiptID  string `json:"acquisition_receipt_id"`
		AcquisitionProposalID string `json:"acquisition_proposal_id"`
		AuthorityID           string `json:"authority_id"`
		TargetID              string `json:"target_id"`
		SourceSetID           string `json:"source_set_id"`
	}{receiptID, acquisitionProposalID, target.AuthorityID, target.TargetID, target.SourceSetID})
	if err != nil {
		return InventoryProposal{}, fmt.Errorf("encode proposal metadata binding: %w", err)
	}
	core := InventoryProposalCore{
		SchemaVersion:     sourceSpecSchemaVersion,
		ProposalKind:      "source_spec_inventory_proposal",
		State:             "proposal",
		ReviewState:       "unreviewed",
		AuthorityState:    "non_authoritative",
		CompileEligible:   false,
		PromoteEligible:   false,
		MetadataSHA256:    digestBytes(metaBytes),
		FileCount:         len(spec.Files),
		ByteSize:          byteSize,
		ExcludedFileCount: 0,
		ExcludedByteSize:  0,
		Exclusions:        []VerifiedExclusion{},
		SourceSpecDraft:   spec,
	}
	coreBytes, err := json.Marshal(core)
	if err != nil {
		return InventoryProposal{}, fmt.Errorf("encode proposal payload: %w", err)
	}
	payloadDigest := digestBytes(coreBytes)
	return InventoryProposal{
		ProposalID:            "inventory-proposal:" + payloadDigest,
		ProposalPayloadSHA256: payloadDigest,
		InventoryProposalCore: core,
	}, nil
}

func buildReceipt(specBytes []byte, proposal InventoryProposal) SourceSpecReviewReceipt {
	return SourceSpecReviewReceipt{
		SchemaVersion:         reviewReceiptSchemaVersion,
		ReceiptKind:           "source_spec_review",
		ProposalID:            proposal.ProposalID,
		ProposalPayloadSHA256: proposal.ProposalPayloadSHA256,
		SourceSpecSHA256:      digestBytes(specBytes),
		Reviewer:              devReviewerPrincipal,
		Decision:              "accepted",
		ReviewedAt:            reviewedAt,
	}
}

// layMirror materializes the reviewed files into a private mirror, reading each
// blob from the content-addressed store and re-verifying its digest and size
// against the reviewed (and therefore acquisition-bound) expectation.
func layMirror(mirrorRoot string, spec SourceSpec, casRoot string) error {
	for _, file := range spec.Files {
		hexDigest := strings.TrimPrefix(file.SHA256, "sha256:")
		if len(hexDigest) != 64 {
			return fmt.Errorf("malformed digest for %s", file.RelativePath)
		}
		blobPath := filepath.Join(casRoot, "sha256", hexDigest[:2], hexDigest)
		data, err := os.ReadFile(blobPath)
		if err != nil {
			return fmt.Errorf("read CAS blob for %s: %w", file.RelativePath, err)
		}
		if int64(len(data)) != file.Size {
			return fmt.Errorf("CAS size mismatch for %s: have %d, want %d", file.RelativePath, len(data), file.Size)
		}
		if digestBytes(data) != file.SHA256 {
			return fmt.Errorf("CAS digest mismatch for %s", file.RelativePath)
		}
		destination := filepath.Join(mirrorRoot, filepath.FromSlash(file.RelativePath))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return fmt.Errorf("create mirror directory for %s: %w", file.RelativePath, err)
		}
		if err := os.WriteFile(destination, data, 0o644); err != nil {
			return fmt.Errorf("write mirror file %s: %w", file.RelativePath, err)
		}
	}
	return nil
}

// authorityBundle holds every path the compilers consume for one authority.
type authorityBundle struct {
	target             acquisitionTarget
	spec               SourceSpec
	proposal           InventoryProposal
	specPath           string
	proposalPath       string
	receiptPath        string
	signaturePath      string
	allowedSignersPath string
	mirrorBase         string
	snapshotStore      string
	evidenceStore      string
}

// prepareBundle builds and writes the full reviewed input bundle for one
// authority: spec, proposal, receipt, detached SSHSIG, external allowed_signers,
// and the private mirror. It performs no compilation.
func prepareBundle(cfg Config, target acquisitionTarget, receiptID, acquisitionProposalID, root string) (authorityBundle, error) {
	var bundle authorityBundle
	if err := os.MkdirAll(root, 0o700); err != nil {
		return bundle, fmt.Errorf("create authority work dir: %w", err)
	}
	spec := buildSourceSpec(target)
	specBytes, err := marshalDocument(spec)
	if err != nil {
		return bundle, fmt.Errorf("encode source spec: %w", err)
	}
	proposal, err := buildProposal(spec, target, receiptID, acquisitionProposalID)
	if err != nil {
		return bundle, err
	}
	proposalBytes, err := marshalDocument(proposal)
	if err != nil {
		return bundle, fmt.Errorf("encode inventory proposal: %w", err)
	}
	receipt := buildReceipt(specBytes, proposal)
	receiptBytes, err := marshalDocument(receipt)
	if err != nil {
		return bundle, fmt.Errorf("encode review receipt: %w", err)
	}
	signature, err := signReviewReceipt(receiptBytes, filepath.Join(root, "sign"))
	if err != nil {
		return bundle, err
	}

	bundle = authorityBundle{
		target:             target,
		spec:               spec,
		proposal:           proposal,
		specPath:           filepath.Join(root, "source-spec.json"),
		proposalPath:       filepath.Join(root, "inventory-proposal.json"),
		receiptPath:        filepath.Join(root, "review-receipt.json"),
		signaturePath:      filepath.Join(root, "review-receipt.json.sig"),
		allowedSignersPath: filepath.Join(root, "allowed_signers"),
		mirrorBase:         filepath.Join(root, "mirror"),
		snapshotStore:      filepath.Join(root, "snapshot-store"),
		evidenceStore:      filepath.Join(root, "evidence-store"),
	}
	writes := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{bundle.specPath, specBytes, 0o600},
		{bundle.proposalPath, proposalBytes, 0o600},
		{bundle.receiptPath, receiptBytes, 0o600},
		{bundle.signaturePath, signature, 0o600},
		{bundle.allowedSignersPath, allowedSignersDocument(), 0o600},
	}
	for _, write := range writes {
		if err := os.WriteFile(write.path, write.data, write.mode); err != nil {
			return bundle, fmt.Errorf("write %s: %w", filepath.Base(write.path), err)
		}
	}
	mirrorRoot := filepath.Join(bundle.mirrorBase, filepath.FromSlash(spec.MirrorPath))
	if err := layMirror(mirrorRoot, spec, cfg.CASRoot); err != nil {
		return bundle, err
	}
	return bundle, nil
}

func runTool(bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out", filepath.Base(bin))
	}
	if err != nil {
		return nil, fmt.Errorf("%s failed: %v: %s", filepath.Base(bin), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

type manifestReference struct {
	ManifestID   string `json:"manifest_id"`
	ManifestPath string `json:"manifest_path"`
}

func runSnapshotCompile(bin string, bundle authorityBundle) (manifestReference, error) {
	out, err := runTool(bin, "compile",
		"--spec", bundle.specPath,
		"--proposal", bundle.proposalPath,
		"--review-receipt", bundle.receiptPath,
		"--review-signature", bundle.signaturePath,
		"--allowed-signers", bundle.allowedSignersPath,
		"--mirror-base", bundle.mirrorBase,
		"--store", bundle.snapshotStore)
	if err != nil {
		return manifestReference{}, err
	}
	var reference manifestReference
	if err := json.Unmarshal(out, &reference); err != nil {
		return manifestReference{}, fmt.Errorf("decode snapshot compile output: %w", err)
	}
	return reference, nil
}

func runEvidenceCompile(bin string, bundle authorityBundle, snapshotManifestPath, allowedSignersPath string) (manifestReference, error) {
	head, err := readSnapshotManifestHead(snapshotManifestPath)
	if err != nil {
		return manifestReference{}, err
	}
	reviewCAS := func(objectPath string) string {
		return filepath.Join(bundle.snapshotStore, filepath.FromSlash(objectPath))
	}
	out, err := runTool(bin, "compile",
		"--manifest", snapshotManifestPath,
		"--raw-store", bundle.snapshotStore,
		"--store", bundle.evidenceStore,
		"--spec", reviewCAS(head.ReviewAdmission.SourceSpecObjectPath),
		"--proposal", reviewCAS(head.ReviewAdmission.ProposalObjectPath),
		"--review-receipt", reviewCAS(head.ReviewAdmission.ReceiptObjectPath),
		"--review-signature", reviewCAS(head.ReviewAdmission.SignatureObjectPath),
		"--allowed-signers", allowedSignersPath)
	if err != nil {
		return manifestReference{}, err
	}
	var reference manifestReference
	if err := json.Unmarshal(out, &reference); err != nil {
		return manifestReference{}, fmt.Errorf("decode evidence compile output: %w", err)
	}
	return reference, nil
}

func readSnapshotManifestHead(path string) (snapshotManifestHead, error) {
	var head snapshotManifestHead
	data, err := os.ReadFile(path)
	if err != nil {
		return head, fmt.Errorf("read snapshot manifest: %w", err)
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return head, fmt.Errorf("decode snapshot manifest: %w", err)
	}
	return head, nil
}

func manifestHex(manifestID string) (string, error) {
	index := strings.LastIndex(manifestID, ":")
	if index < 0 || index+1 >= len(manifestID) {
		return "", fmt.Errorf("malformed manifest id %q", manifestID)
	}
	hexDigest := manifestID[index+1:]
	if len(hexDigest) != 64 {
		return "", fmt.Errorf("manifest id %q is not content-addressed", manifestID)
	}
	return hexDigest, nil
}

func copyRetained(sourcePath, destDir, manifestID string) (string, error) {
	hexDigest, err := manifestHex(manifestID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("create retained-evidence directory: %w", err)
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", fmt.Errorf("read compiled manifest: %w", err)
	}
	destination := filepath.Join(destDir, hexDigest+".json")
	if err := os.WriteFile(destination, data, 0o644); err != nil {
		return "", fmt.Errorf("write retained manifest: %w", err)
	}
	return destination, nil
}

func adaptAuthority(cfg Config, target acquisitionTarget, receiptID, acquisitionProposalID, root string) (AuthorityResult, error) {
	var result AuthorityResult
	bundle, err := prepareBundle(cfg, target, receiptID, acquisitionProposalID, root)
	if err != nil {
		return result, err
	}
	snapshot, err := runSnapshotCompile(cfg.SnapshotBin, bundle)
	if err != nil {
		return result, fmt.Errorf("authority %s snapshot compile: %w", target.AuthorityID, err)
	}
	evidence, err := runEvidenceCompile(cfg.EvidenceBin, bundle, snapshot.ManifestPath, bundle.allowedSignersPath)
	if err != nil {
		return result, fmt.Errorf("authority %s evidence compile: %w", target.AuthorityID, err)
	}
	result = AuthorityResult{
		AuthorityID:          target.AuthorityID,
		ComponentID:          bundle.spec.ComponentID,
		ResolvedVersion:      bundle.spec.ResolvedVersion,
		SourceRevision:       bundle.spec.SourceRevision,
		SnapshotManifestID:   snapshot.ManifestID,
		SnapshotManifestPath: snapshot.ManifestPath,
		EvidenceManifestID:   evidence.ManifestID,
		EvidenceManifestPath: evidence.ManifestPath,
	}
	if strings.TrimSpace(cfg.OutRoot) != "" {
		result.SnapshotOutPath, err = copyRetained(snapshot.ManifestPath, filepath.Join(cfg.OutRoot, "snapshots", "sha256"), snapshot.ManifestID)
		if err != nil {
			return result, err
		}
		result.EvidenceOutPath, err = copyRetained(evidence.ManifestPath, filepath.Join(cfg.OutRoot, "evidence", "sha256"), evidence.ManifestID)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// Adapt turns the accepted v2 acquisition receipt/proposal into, per authority,
// a reviewed source bundle and drives the frozen snapshot and evidence
// compilers, returning one distinct snapshot and evidence manifest per target.
func Adapt(cfg Config) ([]AuthorityResult, error) {
	if strings.TrimSpace(cfg.SnapshotBin) == "" || strings.TrimSpace(cfg.EvidenceBin) == "" {
		return nil, errors.New("snapshot and evidence compiler binaries are required")
	}
	if strings.TrimSpace(cfg.CASRoot) == "" {
		return nil, errors.New("content-addressed source-blob root is required")
	}
	if strings.TrimSpace(cfg.WorkRoot) == "" {
		return nil, errors.New("work root is required")
	}
	receipt, err := loadAcquisition(cfg.ReceiptPath)
	if err != nil {
		return nil, err
	}
	proposal, err := loadAcquisition(cfg.ProposalPath)
	if err != nil {
		return nil, err
	}
	if err := crossCheckAcquisition(receipt, proposal); err != nil {
		return nil, err
	}
	results := make([]AuthorityResult, 0, len(receipt.Targets))
	seenSnapshots := make(map[string]string)
	seenEvidence := make(map[string]string)
	for index, target := range receipt.Targets {
		root := filepath.Join(cfg.WorkRoot, fmt.Sprintf("%02d-%s", index, sanitizeComponent(target.ComponentID)))
		result, err := adaptAuthority(cfg, target, receipt.ReceiptID, proposal.ProposalID, root)
		if err != nil {
			return nil, err
		}
		if prior, ok := seenSnapshots[result.SnapshotManifestID]; ok {
			return nil, fmt.Errorf("authority %s reused snapshot manifest of %s", target.AuthorityID, prior)
		}
		if prior, ok := seenEvidence[result.EvidenceManifestID]; ok {
			return nil, fmt.Errorf("authority %s reused evidence manifest of %s", target.AuthorityID, prior)
		}
		seenSnapshots[result.SnapshotManifestID] = target.AuthorityID
		seenEvidence[result.EvidenceManifestID] = target.AuthorityID
		results = append(results, result)
	}
	return results, nil
}

// crossCheckAcquisition confirms the receipt and inventory proposal describe the
// same non-aliasing target set before any authority is adapted.
func crossCheckAcquisition(receipt, proposal acquisitionDocument) error {
	if len(receipt.Targets) != len(proposal.Targets) {
		return errors.New("acquisition receipt and proposal target counts differ")
	}
	setIDs := make(map[string]struct{}, len(receipt.Targets))
	for index := range receipt.Targets {
		receiptTarget := receipt.Targets[index]
		proposalTarget := proposal.Targets[index]
		if receiptTarget.TargetID != proposalTarget.TargetID || receiptTarget.AuthorityID != proposalTarget.AuthorityID {
			return fmt.Errorf("acquisition receipt and proposal disagree on target %d identity", index)
		}
		if _, ok := setIDs[receiptTarget.SourceSetID]; ok {
			return fmt.Errorf("acquisition target %s aliases an earlier source set", receiptTarget.AuthorityID)
		}
		setIDs[receiptTarget.SourceSetID] = struct{}{}
	}
	return nil
}

func sanitizeComponent(componentID string) string {
	var builder strings.Builder
	for _, r := range componentID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	return builder.String()
}
