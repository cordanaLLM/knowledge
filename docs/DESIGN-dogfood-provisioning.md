# Design north star: dogfooded agent provisioning

The reason this product exists. Everything else (the two-module RAG, the harvest
pipeline, the MCP connection layer) is a means to this end.

## Thesis

The AI product's job is to make **every agent it spins up start pre-loaded, not
blind.** Given a task, the product assembles the context an agent needs — the
relevant knowledge and the relevant tools — and hands it over ready to work.
Dogfooding is not incidental; it *is* the design. The product uses its own RAG
and its own MCP-discovery layer to provision the agents that, in turn, extend the
product.

## The two primitives (named by the operator)

### 1. RAG capsule — a task-scoped slice of the registry, not the whole corpus

A capsule is a **lineage-subset**: the subset of registry authorities relevant to
a task, exposed to the agent as a scoped retrieval tool (or pre-fetched context).
An agent working Cilium gets a `{cilium, gateway-api}` capsule — 2 authorities,
not all 46. Result: sharper retrieval, fewer tokens, no cross-authority noise.

Why it is cheap: the multidomain lineage architecture already supports
per-authority binding and cross-authority routing (proven live). A capsule is the
same machinery run with a **filtered lineage-set**. The hard part (signed,
content-addressed, byte-reproducible multidomain retrieval) is done; scoping
*down* is a selection step, not new retrieval infrastructure.

### 2. Preconnected MCP bundle — task → the tools it will need

From the connection catalog (`docs/awesome-mcp-connections.md`), map a task to the
MCP servers it needs and preconnect them:

| task kind | capsule | MCP bundle |
|---|---|---|
| k8s / cluster op | cluster authorities | kubernetes MCP + `search_cluster_docs` |
| PR / repo work | dev-sync authorities | gitea/github MCP + `search_dev_docs` |
| research / harvest | (topic authorities) | harvest tools + `search_*` |

"Perhaps needed" = speculatively preconnect the **adjacent** tools. The
overlap-ranked harvest catalog (`overlap_count` across many lists) is exactly the
signal for what is adjacent to a given tool/topic. The agent never fumbles
discovering or wiring tools.

## Staging — easy wins first

- **Stage 1 (in flight):** connect related MCPs (gitea/github/k8s done) + dogfood
  the research (harvest runs on cheap Gemini/local models + the RAG, not
  frontier). The win is time + compute: grunt work at grunt-model cost, proven
  knowledge *served* instead of re-derived.
- **Stage 2:** the **provisioner** — given a task, assemble `{capsule + MCP
  bundle}` and hand the agent both, preloaded. Smallest first step: a
  **capsule-selector** (task intent → relevant authorities → filtered
  lineage-set), because lineage-subsetting already works.

## The flywheel closes it

Log which capsules and MCPs each agent **actually used**, then feed that back:
the capsule tightens (drop authorities that never got hit), and the "perhaps
needed" MCPs get promoted or dropped. The product learns its own provisioning —
dogfooding all the way down.

## Non-goals (for now)

- A human rating UI (deferred; the flywheel stays headless on deterministic gates).
- Moving the Go engine out of the source monorepo (referenced for now; consolidate later).
