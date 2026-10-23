package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sys/unix"
)

const (
	bridgeName             = "cordana-knowledge-mcp-bridge"
	bridgeVersion          = "0.3.0"
	remoteEndpointPath     = "/knowledge/mcp"
	remoteAggregatePath    = "/mcp/"
	remoteToolPrefix       = "knowledge-"
	minimumTokenBytes      = 32
	maximumTokenFileBytes  = 4097
	maximumUpstreamTools   = 64
	maximumAggregateTools  = 128
	maximumToolListPages   = 16
	defaultConnectTimeout  = 25 * time.Second
	defaultDialTimeout     = 10 * time.Second
	defaultIdleConnTimeout = 90 * time.Second
)

var allowedToolOrder = []string{
	"registry_status",
	"knowledge_status",
	"registry_search_components",
	"dependency_lookup",
	"dependency_changes",
	"registry_get_component",
	"registry_relationships",
	"registry_official_channels",
	"registry_evidence",
	"knowledge_search",
	"knowledge_get",
	"knowledge_context",
	"evidence_search",
}

type bridgeConfig struct {
	endpoint       *url.URL
	tokenFile      string
	connectTimeout time.Duration
}

type bridgeRuntime struct {
	server   *mcp.Server
	upstream *mcp.ClientSession
}

type bridgedTool struct {
	definition   *mcp.Tool
	upstreamName string
}

func main() {
	configuration, showVersion, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: configuration error: %v\n", bridgeName, err)
		os.Exit(2)
	}
	if showVersion {
		fmt.Fprintf(os.Stderr, "%s %s\n", bridgeName, bridgeVersion)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runtime, err := newBridgeRuntime(ctx, configuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: startup failed: %v\n", bridgeName, err)
		os.Exit(1)
	}
	defer runtime.close()

	if err := runtime.server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "%s: protocol stopped: %v\n", bridgeName, err)
		os.Exit(1)
	}
}

func parseConfig(arguments []string) (bridgeConfig, bool, error) {
	set := flag.NewFlagSet(bridgeName, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var endpoint string
	var tokenFile string
	var connectTimeout time.Duration
	var showVersion bool
	set.StringVar(&endpoint, "endpoint", "", "allowlisted Streamable HTTP endpoint")
	set.StringVar(&tokenFile, "token-file", "", "protected bearer-token file")
	set.DurationVar(&connectTimeout, "connect-timeout", defaultConnectTimeout, "upstream initialize timeout")
	set.BoolVar(&showVersion, "version", false, "print the bridge version and exit")
	if err := set.Parse(arguments); err != nil {
		return bridgeConfig{}, false, err
	}
	if set.NArg() != 0 {
		return bridgeConfig{}, false, fmt.Errorf("unexpected positional arguments: %v", set.Args())
	}
	if showVersion {
		return bridgeConfig{}, true, nil
	}
	parsedEndpoint, err := parseEndpoint(endpoint)
	if err != nil {
		return bridgeConfig{}, false, err
	}
	if tokenFile == "" {
		return bridgeConfig{}, false, errors.New("--token-file is required")
	}
	if !strings.HasPrefix(tokenFile, "/") {
		return bridgeConfig{}, false, errors.New("--token-file must be an absolute path")
	}
	if connectTimeout <= 0 || connectTimeout > 2*time.Minute {
		return bridgeConfig{}, false, errors.New("--connect-timeout must be greater than zero and at most 2m")
	}
	return bridgeConfig{
		endpoint:       parsedEndpoint,
		tokenFile:      tokenFile,
		connectTimeout: connectTimeout,
	}, false, nil
}

func parseEndpoint(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("--endpoint is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse --endpoint: %w", err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errors.New("--endpoint must not contain user information, query, fragment or opaque data")
	}
	if parsed.Scheme == "http" && parsed.Hostname() == "127.0.0.1" {
		if parsed.Path != "/" || parsed.RawPath != "" {
			return nil, errors.New("loopback endpoint path must be exactly /")
		}
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("loopback endpoint must contain a valid explicit TCP port")
		}
		parsed.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		return parsed, nil
	}
	if parsed.Scheme == "https" && parsed.Host == remoteEndpointHost &&
		(parsed.Path == remoteEndpointPath || parsed.Path == remoteAggregatePath) &&
		parsed.RawPath == "" {
		return parsed, nil
	}
	return nil, fmt.Errorf(
		"--endpoint must be http://127.0.0.1:<port>/, https://%s%s, or https://%s%s",
		remoteEndpointHost,
		remoteEndpointPath,
		remoteEndpointHost,
		remoteAggregatePath,
	)
}

// remoteEndpointHost is the one remote host the bridge sends the credential
// to. The value here is a placeholder; a build names the real gateway with
// -ldflags "-X main.remoteEndpointHost=<host>". It is not a flag: a host
// chosen at run time would let a caller redirect the credential.
var remoteEndpointHost = "gateway.example.com"

func readCredential(path string) (string, error) {
	uid, err := credentialUID(os.Getuid())
	if err != nil {
		return "", err
	}
	return readCredentialForUID(path, uid)
}

func readCredentialForUID(path string, expectedUID uint32) (string, error) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", errors.New("credential path must be absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open credential: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", errors.New("open credential: invalid file descriptor")
	}
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return "", fmt.Errorf("inspect credential: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errors.New("credential must be a regular file")
	}
	if stat.Uid != expectedUID {
		return "", errors.New("credential owner does not match the current user")
	}
	permissions := stat.Mode & 0o777
	if permissions != 0o400 && permissions != 0o600 {
		return "", fmt.Errorf("credential mode must be 0400 or 0600, got %04o", permissions)
	}
	if stat.Size < minimumTokenBytes || stat.Size > maximumTokenFileBytes {
		return "", fmt.Errorf("credential size must be between %d and %d bytes", minimumTokenBytes, maximumTokenFileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read credential: %w", err)
	}
	if len(raw) > maximumTokenFileBytes {
		return "", errors.New("credential grew beyond the maximum size while being read")
	}
	if bytes.HasSuffix(raw, []byte{'\n'}) {
		raw = raw[:len(raw)-1]
	}
	if len(raw) < minimumTokenBytes {
		return "", fmt.Errorf("credential must contain at least %d token bytes", minimumTokenBytes)
	}
	for _, value := range raw {
		if !isBearerTokenByte(value) {
			return "", errors.New("credential contains an unsupported byte")
		}
	}
	return string(raw), nil
}

func isBearerTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		strings.ContainsRune("-._~+/=", rune(value))
}

type credentialTransport struct {
	endpoint  *url.URL
	tokenFile string
	base      http.RoundTripper
}

func (transport *credentialTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !sameEndpoint(request.URL, transport.endpoint) {
		return nil, errors.New("refusing to send the credential outside the configured endpoint")
	}
	token, err := readCredential(transport.tokenFile)
	if err != nil {
		return nil, err
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+token)
	return transport.base.RoundTrip(clone)
}

func sameEndpoint(candidate, expected *url.URL) bool {
	return candidate != nil && expected != nil &&
		candidate.Scheme == expected.Scheme &&
		candidate.Host == expected.Host &&
		candidate.EscapedPath() == expected.EscapedPath() &&
		candidate.RawQuery == "" && !candidate.ForceQuery &&
		candidate.Fragment == "" && candidate.User == nil && candidate.Opaque == ""
}

func newUpstreamHTTPClient(configuration bridgeConfig) *http.Client {
	dialer := &net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}
	base := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultDialTimeout,
		ResponseHeaderTimeout: configuration.connectTimeout,
	}
	return &http.Client{
		Transport: &credentialTransport{
			endpoint:  configuration.endpoint,
			tokenFile: configuration.tokenFile,
			base:      base,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newBridgeRuntime(ctx context.Context, configuration bridgeConfig) (*bridgeRuntime, error) {
	connectCtx, cancel := context.WithTimeout(ctx, configuration.connectTimeout)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{
		Name:    bridgeName,
		Title:   "Cordana Knowledge MCP bridge",
		Version: bridgeVersion,
	}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	upstream, err := client.Connect(connectCtx, &mcp.StreamableClientTransport{
		Endpoint:             configuration.endpoint.String(),
		HTTPClient:           newUpstreamHTTPClient(configuration),
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to canonical broker: %w", err)
	}

	tools, order, err := loadTools(connectCtx, upstream, configuration.endpoint.Path)
	if err != nil {
		_ = upstream.Close()
		return nil, err
	}
	initialize := upstream.InitializeResult()
	if initialize == nil || initialize.ServerInfo == nil {
		_ = upstream.Close()
		return nil, errors.New("canonical broker returned no server identity")
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    bridgeName,
		Title:   "Cordana Knowledge MCP",
		Version: bridgeVersion,
	}, &mcp.ServerOptions{
		Instructions: initialize.Instructions,
		Capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolCapabilities{},
		},
	})
	for _, name := range order {
		entry := tools[name]
		tool := *entry.definition
		tool.Name = name
		upstreamName := entry.upstreamName
		server.AddTool(&tool, func(callCtx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if request == nil || request.Params == nil {
				return nil, errors.New("missing tool-call parameters")
			}
			meta := maps.Clone(request.Params.Meta)
			delete(meta, mcp.MetaKeyProtocolVersion)
			delete(meta, mcp.MetaKeyClientInfo)
			delete(meta, mcp.MetaKeyClientCapabilities)
			return upstream.CallTool(callCtx, &mcp.CallToolParams{
				// Protocol version, client identity and capabilities describe
				// one MCP connection. Do not copy that reserved metadata across
				// the bridge: the upstream SDK injects values for its own hop.
				Meta:      meta,
				Name:      upstreamName,
				Arguments: request.Params.Arguments,
			})
		})
	}
	return &bridgeRuntime{server: server, upstream: upstream}, nil
}

func loadTools(
	ctx context.Context,
	upstream *mcp.ClientSession,
	endpointPath string,
) (map[string]*bridgedTool, []string, error) {
	if endpointPath != remoteAggregatePath {
		tools, err := loadAllowedTools(ctx, upstream)
		return tools, allowedToolOrder, err
	}
	tools, err := loadAggregateTools(ctx, upstream)
	if err != nil {
		return nil, nil, err
	}
	order := make([]string, 0, len(tools))
	for name := range tools {
		order = append(order, name)
	}
	sort.Strings(order)
	return tools, order, nil
}

func loadAggregateTools(
	ctx context.Context,
	upstream *mcp.ClientSession,
) (map[string]*bridgedTool, error) {
	found := make(map[string]*bridgedTool)
	seen := make(map[string]struct{})
	cursors := make(map[string]struct{})
	cursor := ""
	total := 0
	for page := 0; page < maximumToolListPages; page++ {
		result, err := upstream.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("list aggregate tools: %w", err)
		}
		for _, tool := range result.Tools {
			if tool == nil || tool.Name == "" {
				return nil, errors.New("aggregate broker returned an unnamed tool")
			}
			if _, duplicate := seen[tool.Name]; duplicate {
				return nil, fmt.Errorf("aggregate broker returned duplicate tool %q", tool.Name)
			}
			seen[tool.Name] = struct{}{}
			total++
			if total > maximumAggregateTools {
				return nil, fmt.Errorf(
					"aggregate broker returned more than %d tools",
					maximumAggregateTools,
				)
			}
			name := strings.TrimPrefix(tool.Name, remoteToolPrefix)
			if name == "" {
				return nil, fmt.Errorf("aggregate broker returned invalid tool %q", tool.Name)
			}
			if found[name] != nil {
				return nil, fmt.Errorf("aggregate broker returned ambiguous tool %q", name)
			}
			if tool.Annotations != nil && tool.Annotations.DestructiveHint != nil &&
				*tool.Annotations.DestructiveHint {
				return nil, fmt.Errorf("aggregate tool %q is destructive", tool.Name)
			}
			if tool.InputSchema == nil {
				return nil, fmt.Errorf("aggregate tool %q has no input schema", tool.Name)
			}
			found[name] = &bridgedTool{
				definition:   tool,
				upstreamName: tool.Name,
			}
		}
		if result.NextCursor == "" {
			break
		}
		if _, repeated := cursors[result.NextCursor]; repeated {
			return nil, errors.New("aggregate tool pagination repeated a cursor")
		}
		cursors[result.NextCursor] = struct{}{}
		cursor = result.NextCursor
		if page == maximumToolListPages-1 {
			return nil, fmt.Errorf(
				"aggregate tool listing exceeded %d pages",
				maximumToolListPages,
			)
		}
	}
	if len(found) == 0 {
		return nil, errors.New("aggregate broker returned no tools")
	}
	return found, nil
}

func loadAllowedTools(ctx context.Context, upstream *mcp.ClientSession) (map[string]*bridgedTool, error) {
	allowed := make(map[string]struct{}, len(allowedToolOrder))
	for _, name := range allowedToolOrder {
		allowed[name] = struct{}{}
	}
	found := make(map[string]*bridgedTool, len(allowedToolOrder))
	seen := make(map[string]struct{})
	cursors := make(map[string]struct{})
	cursor := ""
	total := 0
	for page := 0; page < maximumToolListPages; page++ {
		result, err := upstream.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("list canonical tools: %w", err)
		}
		for _, tool := range result.Tools {
			if tool == nil || tool.Name == "" {
				return nil, errors.New("canonical broker returned an unnamed tool")
			}
			if _, duplicate := seen[tool.Name]; duplicate {
				return nil, fmt.Errorf("canonical broker returned duplicate tool %q", tool.Name)
			}
			seen[tool.Name] = struct{}{}
			total++
			if total > maximumUpstreamTools {
				return nil, fmt.Errorf("canonical broker returned more than %d tools", maximumUpstreamTools)
			}
			canonicalName := tool.Name
			if strings.HasPrefix(canonicalName, remoteToolPrefix) {
				canonicalName = strings.TrimPrefix(canonicalName, remoteToolPrefix)
			}
			if _, accepted := allowed[canonicalName]; !accepted {
				continue
			}
			if found[canonicalName] != nil {
				return nil, fmt.Errorf("canonical broker returned ambiguous tool %q", canonicalName)
			}
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint ||
				(tool.Annotations.DestructiveHint != nil && *tool.Annotations.DestructiveHint) {
				return nil, fmt.Errorf("canonical tool %q does not satisfy the read-only boundary", tool.Name)
			}
			if tool.InputSchema == nil {
				return nil, fmt.Errorf("canonical tool %q has no input schema", tool.Name)
			}
			found[canonicalName] = &bridgedTool{
				definition:   tool,
				upstreamName: tool.Name,
			}
		}
		if result.NextCursor == "" {
			break
		}
		if _, repeated := cursors[result.NextCursor]; repeated {
			return nil, errors.New("canonical tool pagination repeated a cursor")
		}
		cursors[result.NextCursor] = struct{}{}
		cursor = result.NextCursor
		if page == maximumToolListPages-1 {
			return nil, fmt.Errorf("canonical tool listing exceeded %d pages", maximumToolListPages)
		}
	}

	var missing []string
	for _, name := range allowedToolOrder {
		if found[name] == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("canonical broker is missing required tools: %s", strings.Join(missing, ", "))
	}
	return found, nil
}

func (runtime *bridgeRuntime) close() {
	if runtime != nil && runtime.upstream != nil {
		_ = runtime.upstream.Close()
	}
}
