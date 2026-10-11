// Command mcp01-acceptance runs the frozen P1-MCP-01 acceptance-case suite
// against the live-shaped knowledge-mcp broker contract: a local
// hermetic broker spawn for CI, or the in-cluster authenticated Streamable
// HTTP endpoint for acceptance execution.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type caseVerdict struct {
	CaseID           string   `json:"case_id"`
	CaseClass        string   `json:"case_class"`
	Verdict          string   `json:"verdict"`
	DoubleRun        bool     `json:"double_run"`
	TranscriptSHA256 string   `json:"transcript_sha256,omitempty"`
	Notes            []string `json:"notes,omitempty"`
	Failure          string   `json:"failure,omitempty"`

	// transcriptBytes rides along outside the JSON report so the orchestrator
	// can persist the first run's transcript.
	transcriptBytes []byte
}

type suiteReport struct {
	SuiteID  string        `json:"suite_id"`
	Revision string        `json:"revision"`
	FrozenAt string        `json:"frozen_at"`
	Mode     string        `json:"mode"`
	Cases    []caseVerdict `json:"cases"`
}

func canonicalJSON(value any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// hermeticRunners maps each frozen case class to its implementation and
// whether the orchestrator double-runs it for byte-identity.
type hermeticCase struct {
	run       func(*caseContext) (*transcript, error)
	doubleRun bool
}

func hermeticRunners() map[string]hermeticCase {
	return map[string]hermeticCase{
		"success":             {run: caseSuccess, doubleRun: true},
		"stale":               {run: caseStale, doubleRun: true},
		"one_lane_timeout":    {run: caseOneLaneTimeout, doubleRun: false},
		"tamper":              {run: caseTamper, doubleRun: true},
		"conflict":            {run: caseConflict, doubleRun: true},
		"acl":                 {run: caseACL, doubleRun: true},
		"deletion":            {run: caseDeletion, doubleRun: true},
		"pagination":          {run: casePagination, doubleRun: true},
		"reconnect":           {run: caseReconnect, doubleRun: true},
		"deterministic_order": {run: caseDeterministicOrder, doubleRun: true},
	}
}

func runHermeticCase(suiteDir, brokerPath string, freeze *suiteFreeze, ws *workspace, frozenCase suiteCase) caseVerdict {
	verdict := caseVerdict{CaseID: frozenCase.CaseID, CaseClass: frozenCase.CaseClass}
	implementation, exists := hermeticRunners()[frozenCase.CaseClass]
	if !exists {
		verdict.Verdict = "fail"
		verdict.Failure = "no implementation for frozen case class"
		return verdict
	}
	execute := func() ([]byte, []string, error) {
		// Every case fails closed when any frozen fixture byte has drifted.
		if err := verifyFixturePins(suiteDir, freeze); err != nil {
			return nil, nil, fmt.Errorf("fixture pin verification: %w", err)
		}
		ctx := &caseContext{ws: ws, freeze: freeze, brokerPath: brokerPath, suiteDir: suiteDir}
		record, err := implementation.run(ctx)
		if err != nil {
			return nil, ctx.notes, err
		}
		encoded, err := record.encode()
		if err != nil {
			return nil, ctx.notes, err
		}
		return encoded, ctx.notes, nil
	}
	first, notes, err := execute()
	verdict.Notes = notes
	if err != nil {
		verdict.Verdict = "fail"
		verdict.Failure = err.Error()
		return verdict
	}
	if implementation.doubleRun {
		second, _, err := execute()
		if err != nil {
			verdict.Verdict = "fail"
			verdict.Failure = "second run: " + err.Error()
			return verdict
		}
		if !bytes.Equal(first, second) {
			verdict.Verdict = "fail"
			verdict.Failure = "double-run transcripts are not byte-identical"
			return verdict
		}
		verdict.DoubleRun = true
	}
	digest := sha256.Sum256(first)
	verdict.TranscriptSHA256 = hex.EncodeToString(digest[:])
	verdict.Verdict = "pass"
	verdict.transcriptBytes = first
	return verdict
}

func runHermeticSuite(suiteDir, brokerPath, outDir string, freeze *suiteFreeze) (*suiteReport, error) {
	ws, err := materializeWorkspace(suiteDir, freeze)
	if err != nil {
		return nil, err
	}
	defer ws.remove()
	report := &suiteReport{SuiteID: freeze.SuiteID, Revision: freeze.Revision, FrozenAt: freeze.FrozenAt, Mode: "hermetic"}
	for _, frozenCase := range freeze.Cases {
		verdict := runHermeticCase(suiteDir, brokerPath, freeze, ws, frozenCase)
		if verdict.transcriptBytes != nil {
			target := filepath.Join(outDir, frozenCase.CaseID+".transcript.json")
			if err := os.WriteFile(target, verdict.transcriptBytes, 0o644); err != nil {
				return nil, err
			}
		}
		verdict.transcriptBytes = nil
		report.Cases = append(report.Cases, verdict)
	}
	return report, nil
}

func runClusterSuite(endpoint, tokenFile, outDir string, freeze *suiteFreeze) (*suiteReport, error) {
	rawToken, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read cluster bearer token file: %w", err)
	}
	client := &httpBroker{endpoint: endpoint, token: strings.TrimSpace(string(rawToken))}
	report := &suiteReport{SuiteID: freeze.SuiteID, Revision: freeze.Revision, FrozenAt: freeze.FrozenAt, Mode: "cluster"}
	for _, frozenCase := range freeze.Cases {
		verdict := caseVerdict{CaseID: frozenCase.CaseID, CaseClass: frozenCase.CaseClass}
		if !slices.Contains(frozenCase.ExecutionSurface, "cluster") {
			verdict.Verdict = "not_executable_on_live"
			verdict.Failure = "requires hermetic fixture control"
			report.Cases = append(report.Cases, verdict)
			continue
		}
		transcriptBytes := runClusterCase(client, freeze, frozenCase, &verdict)
		if transcriptBytes != nil {
			target := filepath.Join(outDir, frozenCase.CaseID+".transcript.json")
			if err := os.WriteFile(target, transcriptBytes, 0o644); err != nil {
				return nil, err
			}
			digest := sha256.Sum256(transcriptBytes)
			verdict.TranscriptSHA256 = hex.EncodeToString(digest[:])
		}
		report.Cases = append(report.Cases, verdict)
	}
	return report, nil
}

func exitCode(report *suiteReport) int {
	blocked := false
	for _, verdict := range report.Cases {
		switch verdict.Verdict {
		case "fail":
			return 1
		case "blocked":
			blocked = true
		}
	}
	if blocked {
		return 3
	}
	return 0
}

func run() int {
	suiteDir := flag.String("suite", "", "directory holding suite-freeze.json and fixtures/")
	brokerPath := flag.String("broker", "", "locally built archeion-knowledge-mcp binary (hermetic mode)")
	endpoint := flag.String("endpoint", "", "in-cluster Streamable HTTP MCP endpoint (cluster mode)")
	tokenFile := flag.String("token-file", "", "bearer-token file for --endpoint (never the value itself)")
	outDir := flag.String("out", "", "directory receiving the normalized case transcripts")
	flag.Parse()
	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "mcp01-acceptance: %v\n", err)
		return 1
	}
	if *suiteDir == "" || *outDir == "" {
		return fail(errors.New("--suite and --out are required"))
	}
	hermetic := *brokerPath != ""
	cluster := *endpoint != ""
	if hermetic == cluster {
		return fail(errors.New("exactly one of --broker (hermetic) or --endpoint (cluster) is required"))
	}
	if cluster && *tokenFile == "" {
		return fail(errors.New("--endpoint requires --token-file"))
	}
	resolvedSuite, err := filepath.Abs(*suiteDir)
	if err != nil {
		return fail(err)
	}
	freeze, err := loadSuite(resolvedSuite)
	if err != nil {
		return fail(err)
	}
	if err := verifyFixturePins(resolvedSuite, freeze); err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fail(err)
	}
	var report *suiteReport
	if hermetic {
		resolvedBroker, absErr := filepath.Abs(*brokerPath)
		if absErr != nil {
			return fail(absErr)
		}
		report, err = runHermeticSuite(resolvedSuite, resolvedBroker, *outDir, freeze)
	} else {
		report, err = runClusterSuite(*endpoint, *tokenFile, *outDir, freeze)
	}
	if err != nil {
		return fail(err)
	}
	for _, verdict := range report.Cases {
		line := fmt.Sprintf("%-8s %s", strings.ToUpper(verdict.Verdict), verdict.CaseID)
		if verdict.Failure != "" {
			line += " — " + verdict.Failure
		}
		for _, note := range verdict.Notes {
			line += " [" + note + "]"
		}
		fmt.Println(line)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fail(err)
	}
	fmt.Println(string(encoded))
	return exitCode(report)
}

func main() {
	os.Exit(run())
}
