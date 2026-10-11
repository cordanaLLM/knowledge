package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "compile":
		runCompile(os.Args[2:])
	case "standing-policy":
		runStandingPolicy(os.Args[2:])
	case "standing-admit":
		runStandingAdmit(os.Args[2:])
	case "change-pack":
		runChangePack(os.Args[2:])
	case "inventory", "draft":
		runInventory(os.Args[1], os.Args[2:])
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  knowledge-snapshot compile --spec FILE --proposal FILE --review-receipt FILE --review-signature FILE --allowed-signers FILE --mirror-base DIR --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-snapshot standing-policy --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-snapshot standing-admit --proposal FILE --policy FILE --policy-signature FILE --policy-allowed-signers FILE --signer-key FILE --signer-allowed-signers FILE --decision-at RFC3339 --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-snapshot change-pack --old-manifest FILE --old-store DIR --old-allowed-signers FILE --new-manifest FILE --new-store DIR --new-allowed-signers FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-snapshot inventory --metadata FILE --mirror-base DIR --proposal-store DIR")
}

func runStandingPolicy(args []string) {
	flags := flag.NewFlagSet("standing-policy", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	core := flags.String("core", "", "canonical standing source-admission policy core JSON")
	store := flags.String("store", "", "content-addressed standing-policy store")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || *core == "" || *store == "" {
		fmt.Fprintln(os.Stderr, "standing-policy requires --core and --store")
		os.Exit(2)
	}
	policy, policyPath, err := MaterializeStandingPolicy(*core, *store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "standing policy materialization failed: %v\n", err)
		os.Exit(1)
	}
	output := struct {
		State               string `json:"state"`
		PolicyID            string `json:"policy_id"`
		PolicyPayloadSHA256 string `json:"policy_payload_sha256"`
		PolicyPath          string `json:"policy_path"`
	}{
		State:               policy.State,
		PolicyID:            policy.PolicyID,
		PolicyPayloadSHA256: policy.PolicyPayloadSHA256,
		PolicyPath:          policyPath,
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "encode standing policy result: %v\n", err)
		os.Exit(1)
	}
}

func runStandingAdmit(args []string) {
	flags := flag.NewFlagSet("standing-admit", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	proposal := flags.String("proposal", "", "canonical unreviewed inventory proposal JSON")
	policy := flags.String("policy", "", "canonical reviewed standing source-admission policy JSON")
	policySignature := flags.String("policy-signature", "", "detached reviewer SSHSIG over the standing policy")
	policyAllowedSigners := flags.String("policy-allowed-signers", "", "external Ed25519 trust policy for the standing-policy reviewer")
	signerKey := flags.String("signer-key", "", "external private Ed25519 key for the bounded admission service")
	signerAllowedSigners := flags.String("signer-allowed-signers", "", "external Ed25519 trust policy for generated admissions")
	decisionAt := flags.String("decision-at", "", "explicit canonical UTC admission decision time")
	store := flags.String("store", "", "content-addressed standing-admission evidence store")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || *proposal == "" || *policy == "" || *policySignature == "" ||
		*policyAllowedSigners == "" || *signerKey == "" || *signerAllowedSigners == "" || *decisionAt == "" || *store == "" {
		fmt.Fprintln(os.Stderr, "standing-admit requires --proposal, --policy, --policy-signature, --policy-allowed-signers, --signer-key, --signer-allowed-signers, --decision-at, and --store")
		os.Exit(2)
	}
	result, err := AdmitWithStandingPolicy(StandingAdmissionConfig{
		ProposalPath:             *proposal,
		PolicyPath:               *policy,
		PolicySignaturePath:      *policySignature,
		PolicyAllowedSignersPath: *policyAllowedSigners,
		SignerPrivateKeyPath:     *signerKey,
		SignerAllowedSignersPath: *signerAllowedSigners,
		DecisionAt:               *decisionAt,
		StoreRoot:                *store,
	})
	if err != nil {
		var rejected *StandingAdmissionRejectedError
		if errors.As(err, &rejected) {
			fmt.Fprintf(os.Stderr, "standing admission quarantined: %s (%d issue(s))\n", rejected.ReportPath, len(rejected.Issues))
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "standing admission failed: %v\n", err)
		os.Exit(1)
	}
	output := struct {
		State               string `json:"state"`
		CompileEligible     bool   `json:"compile_eligible"`
		PromoteEligible     bool   `json:"promote_eligible"`
		AdmissionID         string `json:"admission_id"`
		ManifestPath        string `json:"manifest_path"`
		SourceSpecPath      string `json:"source_spec_path"`
		ReviewReceiptPath   string `json:"review_receipt_path"`
		ReviewSignaturePath string `json:"review_signature_path"`
	}{
		State:               result.Manifest.State,
		CompileEligible:     result.Manifest.CompileEligible,
		PromoteEligible:     result.Manifest.PromoteEligible,
		AdmissionID:         result.Manifest.AdmissionID,
		ManifestPath:        result.ManifestPath,
		SourceSpecPath:      result.SourceSpecPath,
		ReviewReceiptPath:   result.ReviewReceiptPath,
		ReviewSignaturePath: result.ReviewSignaturePath,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "result encode failed: %v\n", err)
		os.Exit(1)
	}
}

func runCompile(args []string) {
	flags := flag.NewFlagSet("compile", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	specPath := flags.String("spec", "", "strict source-spec JSON")
	proposalPath := flags.String("proposal", "", "canonical unreviewed inventory proposal JSON")
	reviewReceiptPath := flags.String("review-receipt", "", "canonical accepted source-spec review receipt JSON")
	reviewSignaturePath := flags.String("review-signature", "", "detached Ed25519 SSHSIG over the review receipt")
	allowedSignersPath := flags.String("allowed-signers", "", "explicit Ed25519 SSH allowed-signers trust policy")
	mirrorBase := flags.String("mirror-base", "", "base directory containing exact-version mirrors")
	storeRoot := flags.String("store", "", "content-addressed snapshot store")
	maxFiles := flags.Int("max-files", defaultMaxFiles, "maximum files accepted in one snapshot")
	maxFileBytes := flags.Int64("max-file-bytes", defaultMaxFileBytes, "maximum bytes accepted for one file")
	maxTotalBytes := flags.Int64("max-total-bytes", defaultMaxTotalBytes, "maximum total bytes accepted in one snapshot")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || *specPath == "" || *proposalPath == "" || *reviewReceiptPath == "" ||
		*reviewSignaturePath == "" || *allowedSignersPath == "" || *mirrorBase == "" || *storeRoot == "" {
		fmt.Fprintln(os.Stderr, "compile requires --spec, --proposal, --review-receipt, --review-signature, --allowed-signers, --mirror-base, and --store")
		os.Exit(2)
	}
	result, err := Compile(CompileConfig{
		SpecPath:            *specPath,
		ProposalPath:        *proposalPath,
		ReviewReceiptPath:   *reviewReceiptPath,
		ReviewSignaturePath: *reviewSignaturePath,
		AllowedSignersPath:  *allowedSignersPath,
		MirrorBase:          *mirrorBase,
		StoreRoot:           *storeRoot,
		MaxFiles:            *maxFiles,
		MaxFileBytes:        *maxFileBytes,
		MaxTotalBytes:       *maxTotalBytes,
	})
	if err != nil {
		var quarantined *QuarantinedError
		if errors.As(err, &quarantined) {
			fmt.Fprintf(os.Stderr, "quarantined: %s (%d issue(s))\n", quarantined.ReportPath, len(quarantined.Issues))
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "compile failed: %v\n", err)
		os.Exit(1)
	}
	output := struct {
		State        string `json:"state"`
		ManifestID   string `json:"manifest_id"`
		ManifestPath string `json:"manifest_path"`
	}{State: result.Manifest.State, ManifestID: result.Manifest.ManifestID, ManifestPath: result.ManifestPath}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "result encode failed: %v\n", err)
		os.Exit(1)
	}
}

func runChangePack(args []string) {
	flags := flag.NewFlagSet("change-pack", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	oldManifest := flags.String("old-manifest", "", "content-addressed old reviewed snapshot manifest")
	oldStore := flags.String("old-store", "", "content-addressed store containing the old snapshot and review evidence")
	oldAllowedSigners := flags.String("old-allowed-signers", "", "operator-trusted external Ed25519 allowed-signers policy for the old snapshot")
	newManifest := flags.String("new-manifest", "", "content-addressed new reviewed snapshot manifest")
	newStore := flags.String("new-store", "", "content-addressed store containing the new snapshot and review evidence")
	newAllowedSigners := flags.String("new-allowed-signers", "", "operator-trusted external Ed25519 allowed-signers policy for the new snapshot")
	store := flags.String("store", "", "content-addressed output store for the derived change pack")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || *oldManifest == "" || *oldStore == "" || *oldAllowedSigners == "" ||
		*newManifest == "" || *newStore == "" || *newAllowedSigners == "" || *store == "" {
		fmt.Fprintln(os.Stderr, "change-pack requires --old-manifest, --old-store, --old-allowed-signers, --new-manifest, --new-store, --new-allowed-signers, and --store")
		os.Exit(2)
	}
	result, err := BuildChangePack(ChangePackConfig{
		OldManifestPath:       *oldManifest,
		OldStoreRoot:          *oldStore,
		OldAllowedSignersPath: *oldAllowedSigners,
		NewManifestPath:       *newManifest,
		NewStoreRoot:          *newStore,
		NewAllowedSignersPath: *newAllowedSigners,
		StoreRoot:             *store,
	})
	if err != nil {
		var rejected *ChangePackRejectedError
		if errors.As(err, &rejected) {
			fmt.Fprintf(os.Stderr, "change-pack rejected (%d issue(s))\n", len(rejected.Issues))
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "change-pack failed: %v\n", err)
		os.Exit(1)
	}
	output := struct {
		State           string `json:"state"`
		PromoteEligible bool   `json:"promote_eligible"`
		ChangePackID    string `json:"change_pack_id"`
		ManifestPath    string `json:"manifest_path"`
	}{
		State:           result.Manifest.State,
		PromoteEligible: result.Manifest.PromoteEligible,
		ChangePackID:    result.Manifest.ChangePackID,
		ManifestPath:    result.ManifestPath,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "result encode failed: %v\n", err)
		os.Exit(1)
	}
}

func runInventory(command string, args []string) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	metadataPath := flags.String("metadata", "", "strict inventory-metadata JSON")
	mirrorBase := flags.String("mirror-base", "", "base directory containing the local mirror")
	proposalStore := flags.String("proposal-store", "", "content-addressed proposal/quarantine store")
	maxFiles := flags.Int("max-files", defaultMaxFiles, "maximum files accepted in one inventory")
	maxFileBytes := flags.Int64("max-file-bytes", defaultMaxFileBytes, "maximum bytes accepted for one file")
	maxTotalBytes := flags.Int64("max-total-bytes", defaultMaxTotalBytes, "maximum total bytes accepted in one inventory")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || *metadataPath == "" || *mirrorBase == "" || *proposalStore == "" {
		fmt.Fprintf(os.Stderr, "%s requires --metadata, --mirror-base, and --proposal-store\n", command)
		os.Exit(2)
	}
	result, err := DraftInventory(InventoryConfig{
		MetadataPath:  *metadataPath,
		MirrorBase:    *mirrorBase,
		ProposalStore: *proposalStore,
		MaxFiles:      *maxFiles,
		MaxFileBytes:  *maxFileBytes,
		MaxTotalBytes: *maxTotalBytes,
	})
	if err != nil {
		var rejected *InventoryRejectedError
		if errors.As(err, &rejected) {
			if rejected.ReportPath == "" {
				fmt.Fprintf(os.Stderr, "inventory rejected before safe quarantine write (%d issue(s))\n", len(rejected.Issues))
			} else {
				fmt.Fprintf(os.Stderr, "inventory quarantined: %s (%d issue(s))\n", rejected.ReportPath, len(rejected.Issues))
			}
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "inventory failed: %v\n", err)
		os.Exit(1)
	}
	output := struct {
		State             string `json:"state"`
		ReviewState       string `json:"review_state"`
		AuthorityState    string `json:"authority_state"`
		CompileEligible   bool   `json:"compile_eligible"`
		PromoteEligible   bool   `json:"promote_eligible"`
		ProposalID        string `json:"proposal_id"`
		ProposalPath      string `json:"proposal_path"`
		FileCount         int    `json:"file_count"`
		ByteSize          int64  `json:"byte_size"`
		ExcludedFileCount int    `json:"excluded_file_count"`
		ExcludedByteSize  int64  `json:"excluded_byte_size"`
	}{
		State:             result.Proposal.State,
		ReviewState:       result.Proposal.ReviewState,
		AuthorityState:    result.Proposal.AuthorityState,
		CompileEligible:   result.Proposal.CompileEligible,
		PromoteEligible:   result.Proposal.PromoteEligible,
		ProposalID:        result.Proposal.ProposalID,
		ProposalPath:      result.ProposalPath,
		FileCount:         result.Proposal.FileCount,
		ByteSize:          result.Proposal.ByteSize,
		ExcludedFileCount: result.Proposal.ExcludedFileCount,
		ExcludedByteSize:  result.Proposal.ExcludedByteSize,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "result encode failed: %v\n", err)
		os.Exit(1)
	}
}
