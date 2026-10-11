package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	maxFrameBytes = 4 << 20
	// callDeadline must exceed the broker's fixed 20s federation lane timeout,
	// which the one-lane-timeout case deliberately rides out.
	callDeadline    = 90 * time.Second
	protocolVersion = "2025-11-25"
)

// callResult is one tools/call outcome as observed over the live protocol.
type callResult struct {
	IsError    bool
	Structured map[string]any
}

// stdioBroker drives a spawned broker binary over its default single-line
// JSON-RPC stdio transport — the same wire shape a real MCP client sees.
type stdioBroker struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	frames  chan string
	readErr chan error
	stderr  *bytes.Buffer
	nextID  int
}

func startStdioBroker(brokerPath string, arguments []string) (*stdioBroker, error) {
	command := exec.Command(brokerPath, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	broker := &stdioBroker{
		command: command, stdin: stdin, stderr: stderr,
		frames: make(chan string, 16), readErr: make(chan error, 1),
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), maxFrameBytes)
		for scanner.Scan() {
			broker.frames <- scanner.Text()
		}
		broker.readErr <- scanner.Err()
		close(broker.frames)
	}()
	return broker, nil
}

func (broker *stdioBroker) close() {
	_ = broker.stdin.Close()
	if broker.command.Process != nil {
		_ = syscall.Kill(-broker.command.Process.Pid, syscall.SIGKILL)
	}
	_ = broker.command.Wait()
}

func (broker *stdioBroker) send(frame map[string]any) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	_, err = broker.stdin.Write(append(encoded, '\n'))
	return err
}

func (broker *stdioBroker) receive(wantID int) (map[string]any, error) {
	deadline := time.After(callDeadline)
	for {
		select {
		case frame, open := <-broker.frames:
			if !open {
				return nil, fmt.Errorf("broker closed its protocol stream: %s", broker.stderr.String())
			}
			var response map[string]any
			if err := json.Unmarshal([]byte(frame), &response); err != nil {
				return nil, fmt.Errorf("broker emitted a non-JSON frame: %w", err)
			}
			if id, ok := response["id"].(float64); ok && int(id) == wantID {
				return response, nil
			}
		case <-deadline:
			return nil, errors.New("broker response exceeded the runner call deadline")
		}
	}
}

func (broker *stdioBroker) request(method string, params map[string]any) (map[string]any, error) {
	broker.nextID++
	id := broker.nextID
	frame := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		frame["params"] = params
	}
	if err := broker.send(frame); err != nil {
		return nil, err
	}
	return broker.receive(id)
}

func (broker *stdioBroker) initialize() error {
	response, err := broker.request("initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcp01-acceptance", "version": "1"},
	})
	if err != nil {
		return err
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		return fmt.Errorf("initialize failed: %v", response["error"])
	}
	server, _ := result["serverInfo"].(map[string]any)
	if server["name"] != "archeion-knowledge-mcp" {
		return fmt.Errorf("unexpected serverInfo: %v", server)
	}
	return broker.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

func (broker *stdioBroker) callTool(name string, arguments map[string]any) (callResult, error) {
	response, err := broker.request("tools/call", map[string]any{"name": name, "arguments": arguments})
	if err != nil {
		return callResult{}, err
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		return callResult{}, fmt.Errorf("tools/call %s failed at the protocol layer: %v", name, response["error"])
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		return callResult{}, fmt.Errorf("tools/call %s returned no structuredContent", name)
	}
	isError, _ := result["isError"].(bool)
	return callResult{IsError: isError, Structured: structured}, nil
}

// httpBroker drives the authenticated Streamable HTTP transport with raw
// stateless POSTs, mirroring a reconnecting client that retains a stale
// Mcp-Session-Id.
type httpBroker struct {
	endpoint string
	token    string
	client   *http.Client
}

func (broker *httpBroker) post(body, sessionID string, withAuth bool) (*http.Response, []byte, error) {
	request, err := http.NewRequest(http.MethodPost, broker.endpoint, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", protocolVersion)
	if withAuth {
		request.Header.Set("Authorization", "Bearer "+broker.token)
	}
	if sessionID != "" {
		request.Header.Set("Mcp-Session-Id", sessionID)
	}
	client := broker.client
	if client == nil {
		client = &http.Client{Timeout: callDeadline}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxFrameBytes))
	if err != nil {
		return nil, nil, err
	}
	return response, payload, nil
}

// decodeHTTPFrame extracts the JSON-RPC response from either a plain JSON body
// or a text/event-stream body.
func decodeHTTPFrame(contentType string, payload []byte) (map[string]any, error) {
	if strings.Contains(contentType, "text/event-stream") {
		for _, line := range strings.Split(string(payload), "\n") {
			line = strings.TrimSpace(line)
			if data, found := strings.CutPrefix(line, "data:"); found {
				var frame map[string]any
				if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &frame); err != nil {
					return nil, err
				}
				if _, hasID := frame["id"]; hasID {
					return frame, nil
				}
			}
		}
		return nil, errors.New("event stream carried no JSON-RPC response")
	}
	var frame map[string]any
	if err := json.Unmarshal(payload, &frame); err != nil {
		return nil, fmt.Errorf("decode HTTP JSON-RPC response: %w", err)
	}
	return frame, nil
}

func (broker *httpBroker) callTool(name string, arguments map[string]any, sessionID string) (callResult, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": arguments},
	})
	if err != nil {
		return callResult{}, err
	}
	response, payload, err := broker.post(string(body), sessionID, true)
	if err != nil {
		return callResult{}, err
	}
	if response.StatusCode != http.StatusOK {
		return callResult{}, fmt.Errorf("tools/call %s returned HTTP %d: %s", name, response.StatusCode, payload)
	}
	frame, err := decodeHTTPFrame(response.Header.Get("Content-Type"), payload)
	if err != nil {
		return callResult{}, err
	}
	result, ok := frame["result"].(map[string]any)
	if !ok {
		return callResult{}, fmt.Errorf("tools/call %s failed at the protocol layer: %v", name, frame["error"])
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		return callResult{}, fmt.Errorf("tools/call %s returned no structuredContent", name)
	}
	isError, _ := result["isError"].(bool)
	return callResult{IsError: isError, Structured: structured}, nil
}

// normalizeValue rewrites the declared volatile fields and workspace paths so
// transcripts are byte-reproducible across runs and machines without hiding
// any other drift.
func normalizeValue(value any, workspaceRoot string, normalization suiteNormalization) any {
	volatile := make(map[string]struct{}, len(normalization.VolatileFields))
	for _, field := range normalization.VolatileFields {
		volatile[field] = struct{}{}
	}
	var walk func(node any) any
	walk = func(node any) any {
		switch typed := node.(type) {
		case map[string]any:
			normalized := make(map[string]any, len(typed))
			for key, nested := range typed {
				if _, isVolatile := volatile[key]; isVolatile {
					normalized[key] = normalization.Replacement
					continue
				}
				normalized[key] = walk(nested)
			}
			return normalized
		case []any:
			normalized := make([]any, len(typed))
			for index, nested := range typed {
				normalized[index] = walk(nested)
			}
			return normalized
		case string:
			if workspaceRoot != "" {
				return strings.ReplaceAll(typed, workspaceRoot, normalization.WorkspaceToken)
			}
			return typed
		default:
			return node
		}
	}
	return walk(value)
}

// transcriptCall is one normalized protocol exchange inside a case transcript.
type transcriptCall struct {
	Step      string         `json:"step"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	IsError   bool           `json:"is_error"`
	Result    any            `json:"result"`
}

type transcript struct {
	SuiteID  string           `json:"suite_id"`
	Revision string           `json:"revision"`
	CaseID   string           `json:"case_id"`
	Calls    []transcriptCall `json:"calls"`
}

func (record *transcript) add(step, tool string, arguments map[string]any, result callResult, workspaceRoot string, normalization suiteNormalization) {
	record.Calls = append(record.Calls, transcriptCall{
		Step: step, Tool: tool, Arguments: arguments, IsError: result.IsError,
		Result: normalizeValue(result.Structured, workspaceRoot, normalization),
	})
}

func (record *transcript) encode() ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
