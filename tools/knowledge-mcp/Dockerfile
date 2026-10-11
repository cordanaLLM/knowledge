# syntax=docker/dockerfile:1.27@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
# archeion-knowledge-mcp — canonical read-only stdio MCP broker (REQ-006).
# Build context: tools/knowledge-mcp/ (see apps/ai/knowledge-mcp/README.md
# for the build+push runbook; this image has no network listener — the
# broker speaks JSON-RPC over its own stdin/stdout only).

FROM golang:1.27.1-alpine3.23@sha256:d9e2f2f07b10cc922da3e80e035c3058810b328d5aef82d2c63680967c5e2ec9 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
      -trimpath -buildvcs=false -ldflags='-buildid=' \
      -o /out/archeion-knowledge-mcp .

# The broker enumerates Git-tracked paths through a fixed /usr/bin/git
# (git.go validateGitExecutable). distroless/static ships none, so the broker
# indexed zero files and reported backend_unavailable. Supply git + its two
# runtime libs; base-debian12 (not static) provides the glibc git links against.
#
# Signed generation-store mode additionally shells out to a fixed
# /usr/bin/ssh-keygen (registry.go sshKeygenPath) to verify the SSHSIG on each
# transition receipt. Without it the broker fails closed on every signed store,
# so openssh-client ships here too. `ldd /usr/bin/ssh-keygen` on this exact
# base resolves libselinux, libcrypto and libpcre2-8 beyond glibc.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS gitprovider
RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*

FROM gcr.io/distroless/base-debian12@sha256:fabbf1c0c357a3d42550111351daed089b20a2c954df13ee2fcff60602515e84

COPY --from=gitprovider /usr/bin/git /usr/bin/git
COPY --from=gitprovider /usr/bin/ssh-keygen /usr/bin/ssh-keygen
COPY --from=gitprovider /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0 /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0
COPY --from=gitprovider /usr/lib/x86_64-linux-gnu/libz.so.1 /usr/lib/x86_64-linux-gnu/libz.so.1
COPY --from=gitprovider /usr/lib/x86_64-linux-gnu/libselinux.so.1 /usr/lib/x86_64-linux-gnu/libselinux.so.1
COPY --from=gitprovider /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
COPY --from=builder --chmod=0555 /out/archeion-knowledge-mcp /usr/local/bin/archeion-knowledge-mcp

LABEL org.opencontainers.image.source="https://github.com/cordanaLLM/knowledge" \
      org.opencontainers.image.title="archeion-knowledge-mcp" \
      org.opencontainers.image.description="Read-only stdio MCP broker: registry, Git-tracked repository evidence, signed-current exact-source retrieval federation"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/archeion-knowledge-mcp"]
