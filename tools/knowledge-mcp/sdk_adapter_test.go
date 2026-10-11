package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const sdkProtocolCurrent = "2026-07-28"

// connectSDK runs the adapter server against an in-memory transport and returns
// a connected official-SDK client session, exercising the real
// protocol negotiation -> tools/list -> tools/call sequence a standard MCP
// client uses.
func connectSDK(t *testing.T, service *toolService) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := newSDKServer(service).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	return clientSession
}

func TestSDKAdapterHandshakeAndReusedToolContract(t *testing.T) {
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
	session := connectSDK(t, service)
	ctx := context.Background()

	initialize := session.InitializeResult()
	if initialize.ServerInfo == nil || initialize.ServerInfo.Name != serverName || initialize.ServerInfo.Version != serverVersion {
		t.Fatalf("SDK handshake lost broker identity: %#v", initialize.ServerInfo)
	}
	if initialize.ProtocolVersion != sdkProtocolCurrent {
		t.Fatalf("SDK negotiated unexpected protocol version: %q", initialize.ProtocolVersion)
	}
	if initialize.Instructions != sdkInstructions {
		t.Fatalf("SDK dropped the untrusted-data trust instructions: %q", initialize.Instructions)
	}

	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(list.Tools) != 13 {
		t.Fatalf("expected thirteen read-only tools over the SDK transport, got %d", len(list.Tools))
	}

	status, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "registry_status"})
	if err != nil {
		t.Fatalf("tools/call registry_status: %v", err)
	}
	if status.IsError {
		t.Fatalf("candidate status must be usable, got %#v", status)
	}
	statusStructured, ok := status.StructuredContent.(map[string]any)
	if !ok || statusStructured["state"] != string(statePartial) {
		t.Fatalf("direct candidate was not signalled partial over the SDK: %#v", status.StructuredContent)
	}
	if _, ok := statusStructured["content_envelope"].(map[string]any); !ok {
		t.Fatalf("SDK adapter dropped the hostile-content envelope: %#v", statusStructured)
	}
	if len(status.Content) == 0 {
		t.Fatalf("SDK adapter returned no unstructured content mirror")
	}
	if text, ok := status.Content[0].(*mcp.TextContent); !ok || !strings.Contains(text.Text, string(statePartial)) {
		t.Fatalf("SDK adapter text content lost the typed state: %#v", status.Content)
	}

	evidence, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "evidence_search",
		Arguments: map[string]any{"query": "sync", "limit": 1},
	})
	if err != nil {
		t.Fatalf("tools/call evidence_search: %v", err)
	}
	if evidence.IsError {
		t.Fatalf("evaluated-current evidence search failed: %#v", evidence)
	}
	evidenceStructured := evidence.StructuredContent.(map[string]any)
	if evidenceStructured["state"] != string(stateOK) || evidenceStructured["retrieval_state"] != "current" || evidenceStructured["pointer_id"] != retrievalID("retrieval-pointer:", "1") {
		t.Fatalf("SDK adapter lost signed-current lineage: %#v", evidenceStructured)
	}
	hits := evidenceStructured["results"].([]any)
	span := hits[0].(map[string]any)["evidence"].(map[string]any)
	if span["span_id"] != retrievalID("evidence-span:", "a") || span["raw_line_start"] != float64(8) || span["payload_sha256"] != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("SDK adapter lost exact citation fields: %#v", span)
	}
}

// TestSDKAdapterCancellationReachesTheRetrievalChild is the end-to-end proof
// that a client cancellation crosses the SDK transport, the handler context and
// service.call, and reclaims the retrieval subprocess.
func TestSDKAdapterCancellationReachesTheRetrievalChild(t *testing.T) {
	retrieval, childPIDPath, grandchildPIDPath := blockingRetrievalFixture(t, time.Minute)
	service := newToolService(buildKnowledgeIndex(t.TempDir()), newRegistryProvider(config{
		maxRegistrySize: defaultMaxRegistryBytes,
	}), retrieval)
	session := connectSDK(t, service)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "evidence_search",
			Arguments: map[string]any{"query": "sync", "limit": 1},
		})
		done <- err
	}()

	parentPID := awaitPID(t, childPIDPath)
	childPID := awaitPID(t, grandchildPIDPath)
	cancel()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("cancelled tools/call never returned: the SDK handler context does not reach the child")
	}
	requireProcessReaped(t, parentPID, "retrieval child")
	requireProcessReaped(t, childPID, "retrieval grandchild")
}

func TestSDKAdapterPreservesTypedFailureForUnknownArguments(t *testing.T) {
	service := newToolService(buildKnowledgeIndex(t.TempDir()), newRegistryProvider(config{maxRegistrySize: defaultMaxRegistryBytes}))
	session := connectSDK(t, service)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "knowledge_search",
		Arguments: map[string]any{"query": "argo", "unexpected": true},
	})
	if err != nil {
		t.Fatalf("tools/call knowledge_search: %v", err)
	}
	if !result.IsError {
		t.Fatalf("broker validation must fail closed on unknown arguments, got %#v", result)
	}
	structured := result.StructuredContent.(map[string]any)
	if structured["state"] != string(stateForbidden) {
		t.Fatalf("SDK adapter dropped the broker's typed forbidden state: %#v", structured)
	}
}
