package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testToken is a fixture credential only: it never leaves the test process and
// is deliberately low-entropy and self-describing, so it is not mistaken for a
// real token. Deployed tokens are operator-generated and sealed.
const testToken = "knowledge-mcp-test-token-not-a-real-secret"

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeTokenFile writes a bearer token exactly as a mounted Secret key would
// present it, including the trailing newline real tooling appends.
func writeTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

// emptyService builds a broker whose registry backend is deliberately degraded:
// a generation store with no external operator trust root, which the registry
// provider reports as backend_unavailable.
func degradedService(t *testing.T) *toolService {
	t.Helper()
	return newToolService(buildKnowledgeIndex(t.TempDir()), newRegistryProvider(config{
		stateDirectory:  t.TempDir(),
		maxRegistrySize: defaultMaxRegistryBytes,
	}))
}

// authTransport injects the bearer credential the way an in-cluster agent
// would, so the client exercises the real authenticated request path.
type authTransport struct {
	token string
	base  http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if t.token != "" {
		clone.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(clone)
}

// startHTTPBroker serves the broker over the authenticated Streamable HTTP
// handler and returns the endpoint.
func startHTTPBroker(t *testing.T, service *toolService, token string) string {
	t.Helper()
	server := httptest.NewServer(newHTTPHandler(service, token, discardLogger()))
	t.Cleanup(server.Close)
	return server.URL
}

// rawMCPRequest exercises a specific session identifier without relying on a
// client library to discard or replace it. That lets the regression test below
// reproduce clients which retain an ID after the server has forgotten it.
func rawMCPRequest(t *testing.T, endpoint, token, method, sessionID, body string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", protocolCurrent)
	}
	if sessionID != "" {
		request.Header.Set("Mcp-Session-Id", sessionID)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s MCP request: %v", method, err)
	}
	defer response.Body.Close() // #nosec G307 -- test-scoped response body
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s MCP response: %v", method, err)
	}
	return response, responseBody
}

// connectHTTP completes a real initialize handshake over Streamable HTTP.
func connectHTTP(t *testing.T, endpoint, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: &authTransport{token: token, base: http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatalf("streamable HTTP connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// TestHTTPAuthenticatedRequestSucceeds proves the authenticated path completes
// the full initialize -> tools/list -> tools/call handshake over HTTP with the
// identical tool surface and trust contract the stdio transport exposes.
func TestHTTPAuthenticatedRequestSucceeds(t *testing.T) {
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
	service := newToolService(buildKnowledgeIndex(root), newRegistryProvider(config{maxRegistrySize: defaultMaxRegistryBytes}))
	session := connectHTTP(t, startHTTPBroker(t, service, testToken), testToken)

	initialize := session.InitializeResult()
	if initialize.ServerInfo == nil || initialize.ServerInfo.Name != serverName {
		t.Fatalf("HTTP handshake lost broker identity: %#v", initialize.ServerInfo)
	}
	if initialize.Instructions != sdkInstructions {
		t.Fatalf("HTTP transport dropped the untrusted-data trust instructions: %q", initialize.Instructions)
	}

	list, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list over HTTP: %v", err)
	}
	if len(list.Tools) != 13 {
		t.Fatalf("expected thirteen read-only tools over HTTP, got %d", len(list.Tools))
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "knowledge_search",
		Arguments: map[string]any{"query": "reconciliation"},
	})
	if err != nil {
		t.Fatalf("tools/call knowledge_search over HTTP: %v", err)
	}
	if result.IsError {
		t.Fatalf("authenticated knowledge_search failed: %#v", result)
	}
	structured, ok := result.StructuredContent.(map[string]any)
	if !ok || structured["state"] != string(stateOK) {
		t.Fatalf("HTTP transport lost the typed ok state: %#v", result.StructuredContent)
	}
	if _, ok := structured["content_envelope"].(map[string]any); !ok {
		t.Fatalf("HTTP transport dropped the hostile-content envelope: %#v", structured)
	}
}

// TestHTTPIgnoresRetainedSessionID reproduces the failure seen by Codex and
// other long-lived clients: the client keeps Mcp-Session-Id after the server
// has discarded the corresponding state. The request/response-only broker is
// stateless, so it must neither issue a session ID nor reject a stale one.
func TestHTTPIgnoresRetainedSessionID(t *testing.T) {
	endpoint := startHTTPBroker(t, degradedService(t), testToken)
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"retained-session-test","version":"1"}}}`

	response, responseBody := rawMCPRequest(t, endpoint, testToken, http.MethodPost, "", initialize)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("initialize returned %d: %s", response.StatusCode, responseBody)
	}
	if sessionID := response.Header.Get("Mcp-Session-Id"); sessionID != "" {
		t.Fatalf("stateless initialize returned a session ID: %q", sessionID)
	}

	const retainedSessionID = "expired-session-retained-by-client"
	const listTools = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	response, responseBody = rawMCPRequest(t, endpoint, testToken, http.MethodPost, retainedSessionID, listTools)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("request with retained expired session ID returned %d: %s", response.StatusCode, responseBody)
	}
	if !strings.Contains(string(responseBody), `"tools"`) {
		t.Fatalf("request with retained expired session ID did not execute tools/list: %s", responseBody)
	}
}

// TestHTTPCancellationReachesTheRetrievalChild proves that the v1.7
// Streamable HTTP cancellation boundary remains explicit: cancelling the
// request must cancel the SDK handler and reclaim the retrieval process group.
func TestHTTPCancellationReachesTheRetrievalChild(t *testing.T) {
	retrieval, childPIDPath, grandchildPIDPath := blockingRetrievalFixture(t, time.Minute)
	service := newToolService(buildKnowledgeIndex(t.TempDir()), newRegistryProvider(config{
		maxRegistrySize: defaultMaxRegistryBytes,
	}), retrieval)
	session := connectHTTP(t, startHTTPBroker(t, service, testToken), testToken)

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
		t.Fatal("cancelled HTTP tools/call never returned")
	}
	requireProcessReaped(t, parentPID, "retrieval child")
	requireProcessReaped(t, childPID, "retrieval grandchild")
}

// TestHTTPRejectsUnauthenticatedRequests is the mutation-sensitive core of the
// auth contract: each case must be rejected with 401 before any handler runs.
// Inverting or deleting the constant-time comparison in staticBearerVerifier
// turns the wrong-token and empty-token cases into 200s and fails this test.
func TestHTTPRejectsUnauthenticatedRequests(t *testing.T) {
	endpoint := startHTTPBroker(t, degradedService(t), testToken)
	// A well-formed initialize body, so a rejection can only come from auth.
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	for _, testCase := range []struct {
		name   string
		header string
	}{
		{"no authorization header", ""},
		{"wrong token", "Bearer " + strings.Repeat("f", len(testToken))},
		{"empty bearer token", "Bearer "},
		{"token prefix only", "Bearer " + testToken[:len(testToken)-1]},
		{"token with extra suffix", "Bearer " + testToken + "x"},
		{"wrong scheme", "Basic " + testToken},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(initialize))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			if testCase.header != "" {
				request.Header.Set("Authorization", testCase.header)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer response.Body.Close() // #nosec G307 -- test-scoped response body
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("unauthenticated request was not rejected with 401, got %d", response.StatusCode)
			}
			// A rejected request must not carry an MCP session: proof the auth
			// middleware ran before the streamable handler, not after it.
			if session := response.Header.Get("Mcp-Session-Id"); session != "" {
				t.Fatalf("rejected request still created an MCP session: %q", session)
			}
		})
	}
}

// TestHTTPAcceptsOnlyTheExactToken guards the accept side of the same check, so
// a mutation that makes the verifier accept everything cannot pass by way of
// the rejection cases alone.
func TestHTTPAcceptsOnlyTheExactToken(t *testing.T) {
	if !constantTimeTokenMatch(testToken, testToken) {
		t.Fatal("verifier rejected the exact configured token")
	}
	for _, wrong := range []string{"", testToken[:len(testToken)-1], testToken + "x", strings.ToUpper(testToken), strings.Repeat("f", len(testToken))} {
		if constantTimeTokenMatch(testToken, wrong) {
			t.Fatalf("verifier accepted a non-matching token: %q", wrong)
		}
	}
}

// TestHTTPRefusesToStartWithoutToken is the "no token, no listener" contract:
// every unusable token state must fail server construction, never degrade into
// an open listener.
func TestHTTPRefusesToStartWithoutToken(t *testing.T) {
	service := degradedService(t)
	for _, testCase := range []struct {
		name string
		path string
	}{
		{"unconfigured token file", ""},
		{"absent token file", filepath.Join(t.TempDir(), "missing")},
		{"empty token file", writeTokenFile(t, "")},
		{"whitespace-only token file", writeTokenFile(t, "   ")},
		{"token below the minimum length", writeTokenFile(t, "tooshort")},
		{"token file is a directory", t.TempDir()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server, err := newHTTPTransportServer(service, config{
				httpBind:      "127.0.0.1:0",
				httpTokenFile: testCase.path,
			}, discardLogger())
			if err == nil {
				t.Fatal("broker built an HTTP listener without a usable token")
			}
			if server != nil {
				t.Fatal("broker returned a server alongside a token error")
			}
		})
	}
}

// TestHTTPServerBuildsWithMountedToken is the positive counterpart: a valid
// mounted token must actually yield a listener, so the refusal test above
// cannot pass vacuously by construction always failing.
func TestHTTPServerBuildsWithMountedToken(t *testing.T) {
	server, err := newHTTPTransportServer(degradedService(t), config{
		httpBind:      "127.0.0.1:0",
		httpTokenFile: writeTokenFile(t, testToken),
	}, discardLogger())
	if err != nil {
		t.Fatalf("valid mounted token was refused: %v", err)
	}
	if server == nil || server.Handler == nil {
		t.Fatal("no usable HTTP server for a valid token")
	}
	if server.ReadHeaderTimeout == 0 {
		t.Fatal("HTTP server has no read-header timeout")
	}
}

// TestHTTPPreservesTypedDegradation is the fail-closed contract over the wire:
// a degraded backend must stay a typed, distinguishable error over HTTP and
// must never flatten into an empty success.
func TestHTTPPreservesTypedDegradation(t *testing.T) {
	session := connectHTTP(t, startHTTPBroker(t, degradedService(t), testToken), testToken)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "registry_status"})
	if err != nil {
		t.Fatalf("tools/call registry_status over HTTP: %v", err)
	}
	if !result.IsError {
		t.Fatalf("degraded backend was flattened into a success over HTTP: %#v", result)
	}
	structured, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("degraded HTTP result carried no structured content: %#v", result.StructuredContent)
	}
	if structured["state"] != string(stateBackendUnavailable) {
		t.Fatalf("HTTP transport lost the typed backend_unavailable state: %#v", structured)
	}
	// Distinguishable from empty-success: a degraded result carries a reason,
	// and its typed state is not the empty state.
	if structured["state"] == string(stateEmpty) {
		t.Fatal("degraded backend was reported as empty success")
	}
	if message, ok := structured["message"].(string); !ok || message == "" {
		t.Fatalf("degraded HTTP result carried no diagnostic message: %#v", structured)
	}
	if len(result.Content) == 0 {
		t.Fatal("degraded HTTP result carried no unstructured content mirror")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, string(stateBackendUnavailable)) {
		t.Fatalf("degraded HTTP text content lost the typed state: %#v", result.Content)
	}
}

// TestHTTPTransportIsOffByDefault pins the default-off contract: stdio stays
// the default transport and the HTTP listener is opt-in.
func TestHTTPTransportIsOffByDefault(t *testing.T) {
	root := t.TempDir()
	values, err := loadConfig([]string{"--repository-root", root}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	if values.httpBind != "" {
		t.Fatalf("HTTP listener is on by default: %q", values.httpBind)
	}
	if values.httpTokenFile != "" {
		t.Fatalf("HTTP token file is set by default: %q", values.httpTokenFile)
	}
	if values.sdkTransport {
		t.Fatal("SDK transport changed the default transport selection")
	}
}

// TestHTTPConfigurationFailsClosed pins the configuration-level guards that keep
// an unauthenticated or ambiguous listener unrepresentable.
func TestHTTPConfigurationFailsClosed(t *testing.T) {
	root := t.TempDir()
	for _, testCase := range []struct {
		name      string
		arguments []string
		getenv    func(string) string
		wants     string
	}{
		{
			name:      "bind without a token file",
			arguments: []string{"--repository-root", root, "--http-bind", "0.0.0.0:8080"},
			wants:     "requires --http-token-file",
		},
		{
			name:      "token file without a bind",
			arguments: []string{"--repository-root", root, "--http-token-file", "/etc/token"},
			wants:     "valid only with --http-bind",
		},
		{
			name:      "malformed bind address",
			arguments: []string{"--repository-root", root, "--http-bind", "8080", "--http-token-file", "/etc/token"},
			wants:     "must be host:port",
		},
		{
			name:      "http and stdio SDK together",
			arguments: []string{"--repository-root", root, "--http-bind", "0.0.0.0:8080", "--http-token-file", "/etc/token", "--mcp-sdk"},
			wants:     "choose one",
		},
		{
			name:      "inline token in the environment",
			arguments: []string{"--repository-root", root},
			getenv: func(key string) string {
				if key == "ARCHEION_KNOWLEDGE_HTTP_TOKEN" {
					return testToken
				}
				return ""
			},
			wants: "inline HTTP bearer tokens are unsupported",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			getenv := testCase.getenv
			if getenv == nil {
				getenv = func(string) string { return "" }
			}
			_, err := loadConfig(testCase.arguments, getenv)
			if err == nil {
				t.Fatal("configuration was accepted")
			}
			if !strings.Contains(err.Error(), testCase.wants) {
				t.Fatalf("expected an error containing %q, got %v", testCase.wants, err)
			}
		})
	}
}

// TestHTTPConfigurationAcceptsValidPair keeps the guard test above honest: the
// intended opt-in combination must still load.
func TestHTTPConfigurationAcceptsValidPair(t *testing.T) {
	root := t.TempDir()
	values, err := loadConfig([]string{
		"--repository-root", root,
		"--http-bind", "0.0.0.0:8080",
		"--http-token-file", "/etc/knowledge-mcp/http-token/token",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("valid HTTP configuration was rejected: %v", err)
	}
	if values.httpBind != "0.0.0.0:8080" {
		t.Fatalf("unexpected bind: %q", values.httpBind)
	}
	if values.httpTokenFile != "/etc/knowledge-mcp/http-token/token" {
		t.Fatalf("unexpected token file: %q", values.httpTokenFile)
	}
}
