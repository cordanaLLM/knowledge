package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

type cliResult struct {
	ContractID   string `json:"contract_id"`
	ReceiptID    string `json:"receipt_id,omitempty"`
	ReceiptPath  string `json:"receipt_path,omitempty"`
	ProposalID   string `json:"proposal_id,omitempty"`
	ProposalPath string `json:"proposal_path,omitempty"`
}

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "P1-SRC-03 acquisition runner failed: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("p1-src03-acquisition-runner", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	verifyOnly := flags.Bool("verify-only", false, "verify and print the frozen exact-six-file contract without network or output mutation")
	printContract := flags.Bool("print-contract", false, "print the complete content-addressed contract without network or output mutation")
	outputRoot := flags.String("output-root", "", "declared private CAS output root")
	acknowledged := flags.String("acknowledge-contract-id", "", "explicitly acknowledge the exact contract selected for network execution")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not supported")
	}
	contract, contractRaw, err := exactContract()
	if err != nil {
		return err
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
	if *acknowledged != contract.ContractID {
		return errors.New("--acknowledge-contract-id must exactly equal the frozen contract ID")
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
