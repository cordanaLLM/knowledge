package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "emit" {
		fmt.Fprintln(os.Stderr, "usage: knowledge-adapter-v2 emit --receipt FILE --proposal FILE --cas-root DIR --snapshot-bin FILE --evidence-bin FILE --work-root DIR [--out-root DIR]")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("emit", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := Config{}
	flags.StringVar(&config.ReceiptPath, "receipt", "", "accepted v2 source-acquisition receipt JSON")
	flags.StringVar(&config.ProposalPath, "proposal", "", "accepted v2 source-inventory proposal JSON")
	flags.StringVar(&config.CASRoot, "cas-root", "", "content-addressed raw source-blob root (sha256/<first-two>/<hex>)")
	flags.StringVar(&config.SnapshotBin, "snapshot-bin", "", "built knowledge-snapshot binary")
	flags.StringVar(&config.EvidenceBin, "evidence-bin", "", "built knowledge-evidence binary")
	flags.StringVar(&config.WorkRoot, "work-root", "", "scratch root for per-authority mirrors, review bundles and CAS stores")
	flags.StringVar(&config.OutRoot, "out-root", "", "optional retained-evidence root for snapshots/ and evidence/")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || config.ReceiptPath == "" || config.ProposalPath == "" || config.CASRoot == "" ||
		config.SnapshotBin == "" || config.EvidenceBin == "" || config.WorkRoot == "" {
		fmt.Fprintln(os.Stderr, "emit requires --receipt, --proposal, --cas-root, --snapshot-bin, --evidence-bin, and --work-root")
		os.Exit(2)
	}
	results, err := Adapt(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adaptation failed: %v\n", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(struct {
		Authorities []AuthorityResult `json:"authorities"`
	}{results}); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(1)
	}
}
