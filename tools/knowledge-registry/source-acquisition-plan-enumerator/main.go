package main

// CLI for the source-acquisition plan enumerator.
//
//	enumerator --spec plan-request.json [--output plan.json]
//
// It reads a strict plan request (repository, pinned annotated tag, expected
// commit, selected file paths, plus the freeze + execution-manifest inputs),
// walks the Git-object closure over api.github.com, and writes the exact
// source-acquisition-runner-v3 contract whose bytes are canonical and
// content-addressed, ready to be signed and fed to that runner. The contract is
// emitted with authority_state non_authoritative and review_state
// implementation_frozen: the enumerator neither signs, admits, nor mutates
// anything.

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

const maxPlanRequestBytes = int64(1024 * 1024)

type cliResult struct {
	ContractID            string `json:"contract_id"`
	ContractPayloadSHA256 string `json:"contract_payload_sha256"`
	Targets               int    `json:"targets"`
	Files                 int    `json:"files"`
	LogicalBytes          int64  `json:"logical_bytes"`
	OutputPath            string `json:"output_path,omitempty"`
}

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "source-acquisition plan enumerator failed: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(arguments []string) error {
	flags := flag.NewFlagSet("source-acquisition-plan-enumerator", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	specPath := flags.String("spec", "", "path to the strict JSON plan request (repository, tag, expected commit, file paths)")
	outputPath := flags.String("output", "", "path to write the authored plan document (default stdout)")
	apiOriginFlag := flags.String("api-origin", apiOrigin, "Git-object REST origin (scheme and authority only)")
	allowTestOrigin := flags.Bool("allow-test-origin", false, "permit a non-production API origin (testing only)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not supported")
	}
	if *specPath == "" {
		return errors.New("--spec is required")
	}
	request, err := readPlanRequest(*specPath)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	enum, err := newEnumerator(client, *apiOriginFlag, os.Getenv("GITHUB_TOKEN"), *allowTestOrigin, request)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, document, err := enum.enumerate(ctx, request)
	if err != nil {
		return err
	}
	if *outputPath != "" {
		if err := writeExclusive(*outputPath, document); err != nil {
			return err
		}
	} else {
		if _, err := os.Stdout.Write(document); err != nil {
			return err
		}
	}
	return writeCLIResult(cliResult{
		ContractID: plan.ContractID, ContractPayloadSHA256: plan.ContractPayloadSHA256,
		Targets: plan.Bounds.Targets, Files: plan.Bounds.Files, LogicalBytes: plan.Bounds.LogicalBytes, OutputPath: *outputPath,
	})
}

func readPlanRequest(path string) (planRequest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return planRequest{}, err
	}
	if info.IsDir() || info.Size() > maxPlanRequestBytes {
		return planRequest{}, errors.New("plan request is a directory or exceeds the byte bound")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- --spec is an explicit local CLI input path, bounded and strictly parsed below.
	if err != nil {
		return planRequest{}, err
	}
	if int64(len(raw)) > maxPlanRequestBytes {
		return planRequest{}, errors.New("plan request exceeds the byte bound")
	}
	if _, err := parseStrictJSON(raw); err != nil {
		return planRequest{}, fmt.Errorf("strict plan request JSON: %w", err)
	}
	var request planRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return planRequest{}, err
	}
	if err := validatePlanRequest(request); err != nil {
		return planRequest{}, err
	}
	return request, nil
}

// writeExclusive writes the plan document to a new file only; it never
// overwrites an existing path.
func writeExclusive(path string, document []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- --output is an explicit local CLI destination; O_EXCL prevents overwriting an existing path.
	if err != nil {
		return err
	}
	if _, err := file.Write(document); err != nil {
		return errors.Join(err, file.Close())
	}
	return file.Close()
}

func writeCLIResult(value cliResult) error {
	encoder := json.NewEncoder(os.Stderr)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
