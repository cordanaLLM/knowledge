package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The bearer token is an operator-generated shared secret mounted from a
// Kubernetes Secret. A short token is indistinguishable from a misconfigured
// or truncated mount, so refuse it rather than serve a guessable listener.
const minHTTPTokenBytes = 32

// Bounds the read of the mounted token file; a larger file is a misconfigured
// mount, not a credential.
const maxHTTPTokenBytes = 4096

// Bounds header reads against slow-request resource exhaustion. Read and Write
// timeouts stay unset: streamable HTTP holds long-lived SSE responses open.
const httpReadHeaderTimeout = 10 * time.Second

// httpTokenLifetime is the validity window reported for an accepted request.
// The shared secret has no expiry of its own — rotation is a re-seal of the
// mounted Secret — but auth.RequireBearerToken rejects a zero Expiration, so
// each accepted request reports a bounded window from the moment it verified.
const httpTokenLifetime = time.Hour

// readHTTPToken loads the bearer token from the operator-mounted Secret file.
// Every failure path returns an error: no token means no listener, never an
// open one.
func readHTTPToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("no bearer-token file configured; refusing to serve HTTP unauthenticated")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read bearer-token file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("bearer-token file is a directory: %s", path)
	}
	if info.Size() > maxHTTPTokenBytes {
		return "", fmt.Errorf("bearer-token file exceeds %d bytes: %s", maxHTTPTokenBytes, path)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied mount path, size-bounded above
	if err != nil {
		return "", fmt.Errorf("read bearer-token file: %w", err)
	}
	token := stringTrimSpace(string(raw))
	if len(token) < minHTTPTokenBytes {
		return "", fmt.Errorf("bearer token must be at least %d bytes after trimming; refusing to serve HTTP with an empty or weak token", minHTTPTokenBytes)
	}
	return token, nil
}

// constantTimeTokenMatch compares over fixed-width SHA-256 digests, so neither
// the token value nor its length leaks through comparison timing.
func constantTimeTokenMatch(expected, presented string) bool {
	expectedDigest := sha256.Sum256([]byte(expected))
	presentedDigest := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(expectedDigest[:], presentedDigest[:]) == 1
}

// staticBearerVerifier accepts exactly the operator-mounted shared secret.
// UserID stays empty: one shared credential identifies no distinct users, so
// claiming otherwise would give the transport's session-hijack check a value
// it cannot actually distinguish.
func staticBearerVerifier(expected string) auth.TokenVerifier {
	return func(_ context.Context, presented string, _ *http.Request) (*auth.TokenInfo, error) {
		if !constantTimeTokenMatch(expected, presented) {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{Expiration: time.Now().Add(httpTokenLifetime)}, nil
	}
}

// newHTTPHandler wraps the official SDK's Streamable HTTP handler in bearer
// authentication. The auth middleware runs first, so an unauthenticated
// request is rejected with 401 before the MCP handler — and therefore before
// any tool — observes it.
//
// The broker is stateless at the transport boundary. Its tools are read-only
// request/response operations and never initiate server-to-client requests or
// notifications, so retaining SDK session state adds no capability. Stateless
// mode also accepts a client-retained Mcp-Session-Id after a server restart or
// prior session expiry instead of trapping that client in a permanent 404.
func newHTTPHandler(service *toolService, token string, logger *slog.Logger) http.Handler {
	server := newSDKServer(service)
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		Logger:                       logger,
		PropagateRequestCancellation: true,
	})
	return auth.RequireBearerToken(staticBearerVerifier(token), nil)(streamable)
}

// newHTTPTransportServer builds the authenticated listener. It returns an error
// — and therefore no server to listen with — whenever the token cannot be
// loaded, which is the fail-closed half of "no token, no listener".
func newHTTPTransportServer(service *toolService, configuration config, logger *slog.Logger) (*http.Server, error) {
	token, err := readHTTPToken(configuration.httpTokenFile)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              configuration.httpBind,
		Handler:           newHTTPHandler(service, token, logger),
		ReadHeaderTimeout: httpReadHeaderTimeout,
	}, nil
}

// serveHTTPTransport serves the broker over authenticated Streamable HTTP until
// ctx is cancelled.
func serveHTTPTransport(ctx context.Context, service *toolService, configuration config, logger *slog.Logger) error {
	server, err := newHTTPTransportServer(service, configuration, logger)
	if err != nil {
		return err
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Info("serving authenticated streamable HTTP", "bind", configuration.httpBind)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-shutdownDone
	return nil
}
