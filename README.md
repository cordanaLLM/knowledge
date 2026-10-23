# Archeion

The name Archeion (say *ar-KAY-on*) is the Greek *arkheion*: the public records office of a Greek city, where official records and evidence were kept.

Archeion is a Tekmora project. Tekmora, from Greek *tekmor* (Homeric *tekmor*): a set goal, and the sign that shows the way to it; said *TEK-mo-ra*.

Extracted Cordana component providing the **Knowledge Subsystem**: the knowledge registry, MCP bridges, hybrid retrieval engine, snapshot compiler, evidence verification harness, external adapters, and cluster MCP serving endpoints.

## Overview

- **`tools/knowledge-registry`**: Python & Go registry toolset for discovering, validating, snapshotting, and materializing content-addressed knowledge records, source acquisition contracts, channel policies, and independent review bundles. Enforces strict JSON schemas and cryptographic signers.
- **`tools/knowledge-mcp`**: High-performance Go Model Context Protocol (MCP) server providing knowledge retrieval, registry inspection, official channel discovery, and dependency diffing for AI agents, plus an in-process Codex bridge and MCP 0.1 acceptance harness.
- **`tools/knowledge-retrieval`**: Go hybrid retrieval engine implementing BM25F token ranking, reciprocal rank fusion (RRF), multidomain evaluation suites, gold span lane ranks, and blind query scoring.
- **`tools/knowledge-snapshot`**: Go snapshot compiler, change-pack generator, inventory indexer, and standing admission verifier for knowledge repositories.
- **`tools/knowledge-evidence`**: Go evidence compiler, verification harness, and tamper-evident reviewer signature validator.
- **`tools/knowledge-adapter-v2`**: Go adapter translating between external source formats, OCI registries, Git trees, and Cordana canonical knowledge records.
- **`tools/knowledge-dogfood-evidence`**: Python verification harness enforcing fail-closed assertions, admission gates, and cryptographic audit proofs for dogfood cluster environments.
- **`apps/ai/kb-mcp`**: FastMCP Python server and Helm chart exposing internal cluster knowledge and read-only research tools over MCP (SSE and Streamable HTTP transports), backed by Open WebUI and MCPO.

## Provenance & Monorepo Extraction

- **Source**: a private cluster monorepo of the same owner
- **Monorepo Source Paths**:
  - `tools/knowledge-registry`
  - `tools/knowledge-mcp`
  - `tools/knowledge-retrieval`
  - `tools/knowledge-snapshot`
  - `tools/knowledge-evidence`
  - `tools/knowledge-adapter-v2`
  - `tools/knowledge-dogfood-evidence`
  - `apps/ai/kb-mcp`
- **Monorepo Cut Commit**: `1b8c489d46868ccf8103a144c250e5534f8d9ecf` (`origin/main` on 2026-09-05)
- **This Repository**: `https://github.com/cordanaLLM/knowledge`

Directory paths are kept as they were in the monorepo. The history before the first commit here stays with the source and is not part of this repository.

## Repository Structure

```
.
├── .gitea/
│   └── workflows/
│       └── ci.yml                     # Gitea Actions CI workflow
├── .gitignore
├── README.md                          # Root documentation (this file)
├── apps/
│   └── ai/
│       └── kb-mcp/                    # FastMCP server & Helm chart for cluster MCP
└── tools/
    ├── knowledge-adapter-v2/          # Format adapter for canonical records (Go)
    ├── knowledge-dogfood-evidence/    # Fail-closed admission & dogfood evidence (Python)
    ├── knowledge-evidence/            # Tamper-evident reviewer signature validator (Go)
    ├── knowledge-mcp/                 # Core knowledge MCP server & Codex bridge (Go)
    ├── knowledge-registry/            # Content-addressed registry & acquisition runner (Python/Go)
    ├── knowledge-retrieval/           # Hybrid BM25F + RRF retrieval engine (Go)
    └── knowledge-snapshot/            # Snapshot compiler & change-pack engine (Go)
```

## Running Tests Locally

The extracted component contains Go test suites, Python test suites, and Helm chart linters.

### 1. Go Tests

Run unit tests directly in each module:

```bash
# Knowledge Adapter v2
(cd tools/knowledge-adapter-v2 && go test -v ./...)

# Knowledge Evidence
(cd tools/knowledge-evidence && go test -v ./...)

# Knowledge MCP (server, bridge, and acceptance tests)
(cd tools/knowledge-mcp && go test -v ./...)

# Knowledge Registry Go Runners
(cd tools/knowledge-registry/source-acquisition-plan-enumerator && go test -v ./...)
(cd tools/knowledge-registry/source-acquisition-runner && go test -v ./...)
(cd tools/knowledge-registry/source-acquisition-runner-v3 && go test -v ./...)

# Knowledge Snapshot
(cd tools/knowledge-snapshot && go test -v ./...)

# Knowledge Retrieval
(cd tools/knowledge-retrieval && go test -v -run 'Test(BM25|Dense|Current|Hybrid|Lifecycle|Paired|Situating|FineSpan)' ./...)
```

*Note on conformance and integration tests*: Tests in `tools/knowledge-registry/p1-src03-acquisition-runner` and `tools/knowledge-retrieval` that depend on shared registry schemas (`knowledge/registry/schemas/`) and acceptance data (`knowledge/registry/acceptance/p1-src-03/`) read them from the directory named by the `KNOWLEDGE_DATA_ROOT` environment variable. When `KNOWLEDGE_DATA_ROOT` is unset or empty, these tests skip with the fixed prefix `knowledge data root absent:` followed by the test purpose. To run with shared data, set `KNOWLEDGE_DATA_ROOT` to a directory containing the `knowledge/registry` tree (e.g. `KNOWLEDGE_DATA_ROOT=/path/to/data go test ./...`). If `KNOWLEDGE_DATA_ROOT` is set but lacks the expected files, the tests fail with the missing file path. Tests depending on test vectors (`testdata/canonical-json/v1/vectors.json`) fail when that file is absent from the repository.

### 2. Python Tests

Run decoupled Python test suites using `pytest`:

```bash
# Dogfood evidence fail-closed assertions (52 tests)
python3 -m pytest -q tools/knowledge-dogfood-evidence/tests/test_fail_closed.py

# KB-MCP proxy tests (11 tests)
python3 -m pytest -q apps/ai/kb-mcp/files/test_mcpo_proxy.py
```

*Note on registry and server tools tests*: `tools/knowledge-registry/tests/` tests assert against monorepo schema directories (`knowledge/registry/schemas/`) and require `rpds-py==2026.6.3`. `apps/ai/kb-mcp/files/test_server_tools.py` asserts against container image dependencies (`fastmcp==3.4.2`, `httpx==0.28.1`, `mcp==1.28.1`, `starlette==1.3.1`).

### 3. Helm Chart Linting & Template Rendering

Lint and render the `kb-mcp` Helm chart:

```bash
helm lint apps/ai/kb-mcp
helm template kb-mcp apps/ai/kb-mcp > /dev/null
```

### 4. Public Tree Check

No tracked file may hold a home path, a private network address, a host name
under a domain this repository used before it became public, or the product
word the tool carried before it was named Archeion:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/check_public_tree.py
```

The first command runs the planted cases, the second reads every tracked file.
Example addresses that upstream fixture files hold are listed, one per file, in
[scripts/public-tree-addresses.txt](scripts/public-tree-addresses.txt); an
entry that matches nothing fails the check. The `Public tree check` job
(`.github/workflows/public-tree.yml`) runs both on every pull request.

## Licence

Copyright 2026 Lusoris.

The repository is under the European Union Public Licence, version 1.2
(`EUPL-1.2`; text in [LICENSE](LICENSE)). No release has been tagged yet, so the
first release and every later one are under these terms.

| Part | Licence |
| :--- | :--- |
| Code, configuration and test data written for this repository | `EUPL-1.2` |
| Documentation text: this README and `docs/` | `CC-BY-SA-4.0` |
| Upstream files and excerpts in the scorer-blind evaluation fixtures under `tools/knowledge-retrieval/testdata/` | the licence of their source: `BSD-3-Clause` (Go), `Apache-2.0` (Kubernetes, Cilium) |

[REUSE.toml](REUSE.toml) names the licence and the copyright holder of every
file by path, and [LICENSES/](LICENSES/) holds each licence text. The
`REUSE lint` job (`.github/workflows/licence.yml`) checks both on every pull
request; `reuse lint` runs the same check locally.
