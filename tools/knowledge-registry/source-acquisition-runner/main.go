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
	PlanID       string `json:"plan_id"`
	ReceiptID    string `json:"receipt_id,omitempty"`
	ReceiptPath  string `json:"receipt_path,omitempty"`
	ProposalID   string `json:"proposal_id,omitempty"`
	ProposalPath string `json:"proposal_path,omitempty"`
}

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "source acquisition runner failed: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(arguments []string) error {
	flags := flag.NewFlagSet("source-acquisition-runner", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	planPath := flags.String("plan", "", "exact accepted source-acquisition plan v3")
	outputRoot := flags.String("output-root", "", "declared crash-safe CAS output root")
	acknowledgedPlanID := flags.String("acknowledge-plan-id", "", "explicitly acknowledge the exact plan selected for network execution")
	verifyOnly := flags.Bool("verify-only", false, "verify the exact plan and exit without network or output mutation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not supported")
	}
	if *planPath == "" {
		return errors.New("--plan is required")
	}
	selected, err := loadPlan(*planPath, acceptedPlanID)
	if err != nil {
		return err
	}
	if *verifyOnly {
		if *outputRoot != "" || *acknowledgedPlanID != "" {
			return errors.New("--verify-only cannot be combined with output or execution acknowledgement")
		}
		return writeCLIResult(cliResult{PlanID: selected.PlanID})
	}
	if *outputRoot == "" {
		return errors.New("--output-root is required for execution")
	}
	if *acknowledgedPlanID != selected.PlanID {
		return errors.New("--acknowledge-plan-id must exactly equal the accepted plan ID")
	}
	store, err := newCASStore(*outputRoot)
	if err != nil {
		return err
	}
	defer store.close()
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are forbidden for exact Git-object acquisition")
		},
	}
	githubRunner, err := newRunner(client, apiOrigin, os.Getenv("GITHUB_TOKEN"), false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := githubRunner.run(ctx, selected, store)
	if err != nil {
		return err
	}
	if err := store.close(); err != nil {
		return fmt.Errorf("close output root: %w", err)
	}
	return writeCLIResult(cliResult{PlanID: selected.PlanID, ReceiptID: result.Receipt.ReceiptID, ReceiptPath: result.ReceiptPath, ProposalID: result.Proposal.ProposalID, ProposalPath: result.ProposalPath})
}

func writeCLIResult(value cliResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
