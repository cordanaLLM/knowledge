package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "compile" {
		fmt.Fprintln(os.Stderr, "usage: knowledge-evidence compile --manifest FILE --raw-store DIR --store DIR --spec FILE --proposal FILE --review-receipt FILE --review-signature FILE --allowed-signers FILE")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("compile", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := CompileConfig{}
	flags.StringVar(&config.ManifestPath, "manifest", "", "complete knowledge-snapshot manifest")
	flags.StringVar(&config.RawStoreRoot, "raw-store", "", "knowledge-snapshot SHA-256 raw CAS root")
	flags.StringVar(&config.StoreRoot, "store", "", "evidence output CAS root")
	flags.StringVar(&config.SpecPath, "spec", "", "reviewed standalone source specification in review CAS")
	flags.StringVar(&config.ProposalPath, "proposal", "", "original inventory proposal in review CAS")
	flags.StringVar(&config.ReviewReceiptPath, "review-receipt", "", "canonical accepted review receipt in review CAS")
	flags.StringVar(&config.ReviewSignaturePath, "review-signature", "", "detached Ed25519 SSHSIG in review CAS")
	flags.StringVar(&config.AllowedSignersPath, "allowed-signers", "", "operator-trusted allowed_signers file outside the snapshot store")
	flags.IntVar(&config.MaxFiles, "max-files", 0, "maximum input files (zero uses safe default)")
	flags.Int64Var(&config.MaxFileBytes, "max-file-bytes", 0, "maximum bytes per raw object (zero uses safe default)")
	flags.Int64Var(&config.MaxTotalBytes, "max-total-bytes", 0, "maximum total raw bytes (zero uses safe default)")
	flags.IntVar(&config.MaxSpans, "max-spans", 0, "maximum output spans (zero uses safe default)")
	flags.Int64Var(&config.MaxOutputBytes, "max-output-bytes", 0, "maximum logical normalized bytes (zero uses safe default)")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	result, err := Compile(config)
	if err != nil {
		var quarantined *QuarantinedError
		if errors.As(err, &quarantined) {
			fmt.Fprintln(os.Stderr, quarantined.ReportPath)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	response := struct {
		ManifestID   string `json:"manifest_id"`
		ManifestPath string `json:"manifest_path"`
		FileCount    int    `json:"file_count"`
		SpanCount    int    `json:"span_count"`
	}{result.Manifest.ManifestID, result.ManifestPath, result.Manifest.FileCount, result.Manifest.SpanCount}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
