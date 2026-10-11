# Awesome-list → archeion connection map (low-token discovery layer)

Goal: agents get "a lot more help finding things with low token effort" by connecting the
curated awesome-lists (especially MCP server indexes) to what archeion actually runs, instead
of re-searching the web blind each time. The `context-awesome` MCP tool is the cheap query
interface; this file is the curated map of which lists/servers are archeion-relevant.

## 1. Wired now (`.mcp.json`, gitignored/local) — PROVEN live

| server | what | proof | auth |
|---|---|---|---|
| `archeion-dogfood-registry` | signed 46-authority cluster-inventory RAG (`search_cluster_docs`) | Module-1, served | none |
| `gitea` (`docker.gitea.com/gitea-mcp-server` 1.3.0) | 53 tools over the **self-hosted Gitea forge** — repos/issues/PRs/releases | handshake OK, 53 tools | `GITEA_ACCESS_TOKEN` env (Gitea PAT) — tools/list works unauth, calls need it |
| `github` (`ghcr.io/github/github-mcp-server` v1.6.0) | 44 tools over the owner's repositories — PRs, files, issues, actions | handshake OK, 44 tools | token fetched fresh from `gh auth token` at launch (nothing stored) |

Already available in-session: `mcp__kubernetes__*` (cluster ops), `context7` (lib docs),
`archeion_kb` (engineering KB), `context-awesome` (awesome-list index), 16 `discourse-*` forums
(kubernetes, prometheus, grafana, cilium… — vendor community Q&A).

**To activate gitea tool CALLS:** create a Gitea PAT on the forge → user settings →
applications, then `export GITEA_ACCESS_TOKEN=…` (or set it in `.claude/settings.local.json`).

## 2. Reference catalog — archeion component → MCP server (from `rohitg00/awesome-devops-mcp-servers`)

Not wired (redundant / needs vetting), but catalogued so agents can pull them on demand:

| archeion thing | candidate MCP servers |
|---|---|
| Kubernetes (have `mcp__kubernetes__*`) | `manusa/kubernetes-mcp-server` (+OpenShift, specialized tools), `Flux159/mcp-server-kubernetes`, `strowk/mcp-k8s-go`, `weibaohui/k8m` (~50 tools, CRD), `wenhuwang/mcp-k8s-eye` (health), `kubestellar/console` (CNCF sandbox, multi-cluster) |
| Terraform | `nwiizo/tfmcp` (plan/apply/state), `stakpak/mcp` (TF+K8s+Actions+Dockerfile gen) |
| Cloudflare (tunnels/DNS) | `cloudflare/mcp-server-cloudflare` (Workers/KV/R2/D1) |
| Postgres / CNPG | `haymon-ai/database` (PG/MySQL/SQLite single binary), `julien040/anyquery` (SQL over apps+PG) |
| Image/code security (Trivy/Kyverno) | `semgrep/mcp` (code vuln scan), `rad-security/mcp-server` (k8s+cloud security), `roadwy/cve-search_mcp` |
| Node/SSH ops (PVE, unreachable nodes) | `muchiny/mcp-ssh-bridge` (SSH + K8s-Exec adapters) |
| Git (local) | `modelcontextprotocol/server-git`, `bgauryy/octocode-mcp` (GitHub ecosystem research) |
| Logs (Loki) | `rog0x/mcp-log-tools` (parse/anomaly) |

## 3. Awesome-list discovery layer — query these cheaply via `context-awesome`

`find_awesome_section("<topic>")` → sections; `get_awesome_items(repo, section)` → entries.
Archeion-relevant indexes confirmed present:

- **`rohitg00/awesome-devops-mcp-servers`** — THE devops MCP index. Sections: Cloud Infrastructure
  (Container Orchestration 15, IaC 9, Security 36, Cloud Providers 16, Version Control 11, DB, CLI),
  CI/CD & DevOps Pipelines (Aggregators 24, CI 4, Code Execution, Browser Automation). Primary source.
- `mcphubcloud/awesome-mcp`, `sourcegraph/awesome-code-ai` (MCP section), `promacanthus/awesome-golang-ai` (MCP)
- `nataz77/awesome-k8s` (k8s infra mgmt), `neomatrix369/awesome-ai-ml-dl` (infra & cloud)

## 4. MCP meta-aggregators — the "find MORE MCP servers cheaply" layer

When the catalog above doesn't cover a need, these are directories/proxies over the whole ecosystem:

- **`pumanitro/global-chat`** — searchable directory of **18K+ MCP servers** across mcp.so / Glama /
  Smithery / PulseMCP. Single query surfaces servers for any tool archeion might add.
- **`smart-mcp-proxy/mcpproxy-go`** — local proxy aggregating many MCP servers behind one endpoint,
  with **BM25 tool discovery** + quarantine. Directly matches archeion's "low-token discovery" goal:
  one proxy, agents search tools instead of loading dozens of servers.
- `MetaMCP` (metatool-ai), `VeriTeknik/pluggedin-mcp-proxy`, `glenngillen/mcpmcp-server` — similar aggregators.

**Follow-up worth doing:** evaluate `mcpproxy-go` as the single front for gitea+github+k8s+future
servers — BM25 tool-search means agents pay tokens only for the tools they actually need, which is
exactly the low-token-effort principle applied to the MCP surface itself.
