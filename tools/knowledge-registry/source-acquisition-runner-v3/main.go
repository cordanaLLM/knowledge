package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// pinnedAcquisitionSignerKey binds the runner to the committed acquisition trust
// root (knowledge/registry/trust/acquisition-allowed-signers). The --allowed-signers
// policy is caller-supplied, so without this pin an adversary who controls the
// invocation could substitute their own key and forge a plan signature. Rotation
// = append the successor key here (and to the committed policy).
const pinnedAcquisitionSignerKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICJHJ4bqb7YoYPQ2x1Zj7SQReM8HVdSH9jSJX06f3Sc7"

// verifyPinnedTrustRoot fails closed unless the supplied allowed_signers policy
// authorizes the committed acquisition signer key.
func verifyPinnedTrustRoot(signersRaw []byte) error {
	if !bytes.Contains(signersRaw, []byte(pinnedAcquisitionSignerKey)) {
		return errors.New("allowed-signers policy does not pin the committed acquisition signer key")
	}
	return nil
}

type cliResult struct {
	ContractID   string `json:"contract_id"`
	ReceiptID    string `json:"receipt_id,omitempty"`
	ReceiptPath  string `json:"receipt_path,omitempty"`
	ProposalID   string `json:"proposal_id,omitempty"`
	ProposalPath string `json:"proposal_path,omitempty"`
}

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "source-acquisition-runner-v3 failed: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("source-acquisition-runner-v3", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	verifyOnly := flags.Bool("verify-only", false, "verify the signed plan and print its content-addressed contract id without network or output mutation")
	printContract := flags.Bool("print-contract", false, "verify the signed plan and print its complete canonical contract document without network or output mutation")
	plan := flags.String("plan", "", "path to the signed acquisition plan (contract document) to authorize and execute")
	planSignature := flags.String("plan-signature", "", "path to the detached Ed25519 SSHSIG over the exact plan bytes")
	allowedSigners := flags.String("allowed-signers", "", "path to the trusted allowed_signers policy authorizing the acquisition signer")
	outputRoot := flags.String("output-root", "", "declared private CAS output root")
	acknowledged := flags.String("acknowledge-contract-id", "", "explicitly acknowledge the exact contract id authorized for network execution")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not supported")
	}
	if *plan == "" || *planSignature == "" || *allowedSigners == "" {
		return errors.New("--plan, --plan-signature, and --allowed-signers are required")
	}
	// Plan-authorization gate: verify the detached signature over the exact plan
	// bytes BEFORE the plan is parsed or used for anything.
	planRaw, err := readRegularNoFollow(*plan, maxContractBytes)
	if err != nil {
		return fmt.Errorf("read acquisition plan: %w", err)
	}
	signatureRaw, err := readRegularNoFollow(*planSignature, maxSignatureBytes)
	if err != nil {
		return fmt.Errorf("read plan signature: %w", err)
	}
	signersRaw, err := readRegularNoFollow(*allowedSigners, maxAllowedSignersBytes)
	if err != nil {
		return fmt.Errorf("read allowed-signers policy: %w", err)
	}
	if err := verifyPinnedTrustRoot(signersRaw); err != nil {
		return err
	}
	if err := verifyPlanSignature(planRaw, signatureRaw, signersRaw); err != nil {
		return fmt.Errorf("authorize acquisition plan: %w", err)
	}
	contract, contractRaw, err := loadContractBytes(planRaw)
	if err != nil {
		return fmt.Errorf("load authorized plan: %w", err)
	}
	if *verifyOnly || *printContract {
		if *outputRoot != "" || *acknowledged != "" || (*verifyOnly && *printContract) {
			return errors.New("offline contract modes cannot be combined with output, acknowledgement, or each other")
		}
		if *printContract {
			_, err = os.Stdout.Write(contractRaw)
			return err
		}
		return writeCLIResult(cliResult{ContractID: contract.ContractID})
	}
	if *outputRoot == "" {
		return errors.New("--output-root is required for execution")
	}
	// Second human gate: the acknowledged id must equal the plan's self-address.
	if *acknowledged != contract.ContractID {
		return errors.New("--acknowledge-contract-id must exactly equal the authorized plan contract id")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	githubRunner, err := newRunner(client, apiOrigin, os.Getenv("GITHUB_TOKEN"), false, contract)
	if err != nil {
		return err
	}
	store, err := newCASStore(*outputRoot)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.close()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := githubRunner.run(ctx, contract, store)
	if err != nil {
		return err
	}
	return writeCLIResult(cliResult{ContractID: contract.ContractID, ReceiptID: result.Receipt.ReceiptID, ReceiptPath: result.ReceiptPath, ProposalID: result.Proposal.ProposalID, ProposalPath: result.ProposalPath})
}

func writeCLIResult(value cliResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
