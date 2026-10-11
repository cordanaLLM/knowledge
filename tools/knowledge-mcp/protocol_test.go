package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtocolHarnessEmitsOnlyJSONAndListsBoundedTools(t *testing.T) {
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "README.md"), []byte("Argo CD reconciliation evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("git", "-C", root, "add", "docs/README.md").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	registryPath := filepath.Join(t.TempDir(), "candidate.json")
	writeManifest(t, registryPath, fixtureManifest(t, true))
	retrieval := currentRetrievalFixture(t, currentRetrievalOKResponse(), "2026-07-16T10:34:56Z")

	service := newToolService(buildKnowledgeIndex(root), newRegistryProvider(config{
		registryPath: registryPath, maxRegistrySize: defaultMaxRegistryBytes,
	}), retrieval)
	var diagnostics bytes.Buffer
	server := newProtocolServer(service, log.New(&diagnostics, "test: ", 0))
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"registry_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"evidence_search","arguments":{"query":"sync","limit":1}}}`,
	}, "\n") + "\n"
	var stdout bytes.Buffer
	if err := server.serve(strings.NewReader(input), &stdout); err != nil {
		t.Fatal(err)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected diagnostics for valid protocol traffic: %q", diagnostics.String())
	}

	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	responses := make([]map[string]any, 0, 4)
	for decoder.More() {
		var response map[string]any
		if err := decoder.Decode(&response); err != nil {
			t.Fatalf("stdout contains non-JSON protocol data: %v; %q", err, stdout.String())
		}
		responses = append(responses, response)
	}
	if len(responses) != 4 {
		t.Fatalf("expected four request responses and no notification response, got %d", len(responses))
	}
	listResult := responses[1]["result"].(map[string]any)
	tools := listResult["tools"].([]any)
	if len(tools) != 13 {
		t.Fatalf("expected thirteen read-only tools including exact-source evidence search, got %d", len(tools))
	}
	callResult := responses[2]["result"].(map[string]any)
	if callResult["isError"] != false {
		t.Fatalf("candidate status must be usable, got %#v", callResult)
	}
	structured := callResult["structuredContent"].(map[string]any)
	if structured["state"] != string(statePartial) {
		t.Fatalf("direct candidate was not signalled partial: %#v", structured)
	}
	retrievalResult := responses[3]["result"].(map[string]any)
	if retrievalResult["isError"] != false {
		t.Fatalf("evaluated-current evidence search failed: %#v", retrievalResult)
	}
	retrievalStructured := retrievalResult["structuredContent"].(map[string]any)
	if retrievalStructured["state"] != string(stateOK) || retrievalStructured["retrieval_state"] != "current" || retrievalStructured["pointer_id"] != retrievalID("retrieval-pointer:", "1") {
		t.Fatalf("protocol lost signed-current lineage: %#v", retrievalStructured)
	}
	hits := retrievalStructured["results"].([]any)
	evidence := hits[0].(map[string]any)["evidence"].(map[string]any)
	if evidence["span_id"] != retrievalID("evidence-span:", "a") || evidence["raw_line_start"] != float64(8) || evidence["payload_sha256"] != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("protocol lost exact citation fields: %#v", evidence)
	}
}

func TestProtocolPreservesFederatedLaneLineageAndExactCitations(t *testing.T) {
	retrieval, _ := currentRetrievalFederationFixture(t, []federationFixtureLane{
		{laneID: "alpha", state: "/state-alpha", response: currentRetrievalOKResponseFor("alpha", "a")},
		{laneID: "beta", state: "/state-beta", response: currentRetrievalOKResponseFor("beta", "b")},
	}, "2026-07-16T11:00:00Z")
	server := newProtocolServer(newToolService(nil, nil, retrieval), log.New(&bytes.Buffer{}, "test: ", 0))
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"evidence_search","arguments":{"query":"sync","limit":2}}}`,
	}, "\n") + "\n"
	var stdout bytes.Buffer
	if err := server.serve(strings.NewReader(input), &stdout); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&stdout)
	var initialize map[string]any
	var call map[string]any
	if err := decoder.Decode(&initialize); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&call); err != nil {
		t.Fatal(err)
	}
	structured := call["result"].(map[string]any)["structuredContent"].(map[string]any)
	if structured["state"] != string(stateOK) || structured["retrieval_state"] != "federated_current" || structured["lane_count"] != float64(2) {
		t.Fatalf("protocol lost federation authority state: %#v", structured)
	}
	lanes := structured["lanes"].([]any)
	if lanes[0].(map[string]any)["pointer_id"] == lanes[1].(map[string]any)["pointer_id"] {
		t.Fatalf("protocol collapsed independent lane lineage: %#v", lanes)
	}
	hits := structured["results"].([]any)
	if len(hits) != 2 || hits[0].(map[string]any)["evidence"].(map[string]any)["span_id"] != retrievalID("evidence-span:", "a") || hits[1].(map[string]any)["evidence"].(map[string]any)["span_id"] != retrievalID("evidence-span:", "b") {
		t.Fatalf("protocol lost federated exact citations: %#v", hits)
	}
}

func TestProtocolRejectsOversizedFrameWithoutStdoutNoise(t *testing.T) {
	server := newProtocolServer(nil, log.New(&bytes.Buffer{}, "test: ", 0))
	var stdout bytes.Buffer
	err := server.serve(bytes.NewReader(bytes.Repeat([]byte("x"), maxProtocolMessageBytes+1)), &stdout)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected explicit bounded-frame error, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("oversized frame emitted stdout noise: %q", stdout.String())
	}
}
