# kb-mcp

> **Retired workload.** This chart is retained as historical source and is no
> longer registered with ArgoCD or LiteLLM. Do not deploy it or add new
> consumers. Use the authenticated `knowledge-mcp` broker and the dedicated
> research MCP services instead.

Remote MCP server that exposes one Open WebUI knowledge base and
a narrow read-only web/scholarly research surface. The same image runs as two
processes in one pod: legacy **SSE** for Paperclip and JSON-only, stateless
**Streamable HTTP** for Codex/VS Code. The HTTP process deliberately disables
SSE response streaming because every exported tool is bounded request/response.
The research tools proxy selected existing `mcpo` routes.

Paperclip reaches this surface through the LiteLLM MCP gateway (registered as
the `archeion_kb` server, granted to the `paperclip-opencode` virtual key by exact
object permission), not a direct client. LiteLLM connects to the Streamable
HTTP listener:

```text
http://kb-mcp.<namespace>.svc.cluster.local:8001/mcp
```

The legacy SSE endpoint (`:8000/sse`) no longer has a direct client and is
retained only until its removal.

Codex/VS Code use the cluster-private HTTP endpoint through a localhost-only
port-forward:

```text
kubectl -n ai port-forward service/kb-mcp 38001:8001
http://127.0.0.1:38001/mcp
```

## Tools

`search_knowledge(query: str, top_k: int = 5) -> [{source_path, text, distance}]`

The server resolves the KB collection id by name at startup
(`GET /api/v1/knowledge/` → `name == <knowledgeBaseName>` → `id`), then per call runs a
hybrid retrieval query:

```text
POST /api/v1/retrieval/query/collection
  { "collection_names": ["<kb_id>"], "query": ..., "k": top_k, "hybrid": true }
```

Empty-collection / param-mismatch 400s degrade to an empty list rather than an
MCP error.

The external research tools return an envelope with `ok`, `tool`,
`external_content`, `truncated`, and `data` fields:

| Tool | mcpo route | Bounds |
|---|---|---|
| `search_web` | `duckduckgo/search` | 1–20 results, 500-character query |
| `fetch_web_page` | `duckduckgo/fetch_content` | public HTTP(S) only, ports 80/443, 500–20000 returned characters |
| `search_arxiv` | `arxiv/search_papers` | 1–20 papers, optional date/category filters |
| `search_semantic_scholar` | `semantic-scholar/search_papers` | 1–20 papers, bounded pagination/filtering |
| `search_openalex` | `openalex/search_works` | 1–20 works, bounded pagination/year/citation filters |

All upstream calls have a 90-second timeout and responses are capped at 65536
serialized characters. Upstream timeouts, transport failures, invalid JSON,
and non-2xx responses become small `ok: false` results so a research outage
does not crash an agent run. Search results, abstracts, and fetched page text
are marked as external content and must be treated as untrusted evidence, not
instructions.

`fetch_web_page` additionally rejects credentials in URLs, non-HTTP schemes,
custom ports, unqualified/cluster-local hostnames, and any hostname resolving
to private, loopback, link-local, reserved, multicast, or unspecified IPs.

## Wiring

```text
paperclip opencode agent
      │  (mcp: cordana-mcp -> LiteLLM gateway, archeion_kb server)
      ▼
gateway :4000/mcp/  ──▶  kb-mcp.<namespace>.svc.cluster.local:8001/mcp
      ├── search_knowledge ──▶ open-webui:8080
      │                         knowledge base `<knowledgeBaseName>`
      └── bounded research ──▶ mcpo:8000
                                DuckDuckGo / arXiv /
                                Semantic Scholar / OpenAlex

Codex CLI / VS Code extension
      │  (shared config.toml; Streamable HTTP)
      ▼
http://127.0.0.1:38001/mcp
      │  kubectl port-forward, loopback only
      ▼
kb-mcp.<namespace>.svc.cluster.local:8001/mcp
```

Registered as the `archeion_kb` MCP server in the LiteLLM gateway
(`apps/ai/litellm/values.yaml`, `proxyConfig.mcp_servers.archeion_kb`, transport
http on `:8001/mcp`) and granted to the `paperclip-opencode` virtual key by
exact object permission, so Paperclip reaches these tools through `cordana-mcp`
with no side-channel client. Codex CLI and the VS Code extension share
`config.toml`, so one project-scoped entry connects both local surfaces after
the extension is restarted.

## Image

Tiny custom image (`python:3.14-slim`, non-root uid 1000). The exact Python
dependency closure, including MCP transport/test dependencies, lives in
[`files/requirements.lock`](files/requirements.lock),
including the Starlette version exercised by the HTTP transport test. Build it and
push it to your own registry (`registry.example.com` below), then replace the
digest in `values.yaml` with the digest `skopeo` reports:

```shell
docker build -t registry.example.com/library/kb-mcp:0.3.1 \
  -f apps/ai/kb-mcp/Dockerfile apps/ai/kb-mcp
skopeo copy --all \
  docker-daemon:registry.example.com/library/kb-mcp:0.3.1 \
  docker://registry.example.com/library/kb-mcp:0.3.1
# skopeo prints the pushed manifest digest → paste into values.yaml image.digest
skopeo inspect --format '{{.Digest}}' \
  docker://registry.example.com/library/kb-mcp:0.3.1
```

## Secret

Reads the Open WebUI API key from the key `OPENWEBUI_API_KEY` of the secret
named in `openwebui.existingSecret` (default `kb-mcp-openwebui`). The chart
creates no secret.
The mcpo routes used here are keyless and read-only; kb-mcp receives no mcpo
credential.

## Validation

```shell
python3 -m py_compile \
  apps/ai/kb-mcp/files/server.py \
  apps/ai/kb-mcp/files/mcpo_proxy.py
python3 -m venv /tmp/kb-mcp-tests
/tmp/kb-mcp-tests/bin/pip install \
  --requirement apps/ai/kb-mcp/files/requirements.lock
PYTHONWARNINGS=error /tmp/kb-mcp-tests/bin/python -m unittest discover \
  -s apps/ai/kb-mcp/files -p 'test_*.py'
docker build -t kb-mcp:test \
  -f apps/ai/kb-mcp/Dockerfile apps/ai/kb-mcp
helm lint apps/ai/kb-mcp
helm template kb-mcp apps/ai/kb-mcp >/tmp/kb-mcp-rendered.yaml
```

The image build runs all proxy and FastMCP registration unit tests before it
produces the runtime image.
