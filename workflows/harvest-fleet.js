// Master "research harvest fleet": run the reusable harvest-source pipeline across a
// QUEUE of curated lists, then union + DEDUPE by URL (awesome lists are overlapping
// indexes) and rank by overlap-count as a corroboration signal. Emits one master
// catalog + one deduplicated RAG-ingest plan across the whole ecosystem.
//   Workflow({ name: 'harvest-fleet' })                      // default archeion queue
//   Workflow({ name: 'harvest-fleet', args: { sources:[{repo,name,note}] } })
export const meta = {
  name: 'harvest-fleet',
  description: 'Harvest a queue of curated lists via harvest-source, then union + dedupe by URL (overlap = importance) into a master catalog + deduplicated RAG-ingest plan',
  phases: [
    { title: 'Harvest', detail: 'run harvest-source per source in the queue (sequential, fault-isolated)' },
    { title: 'Dedup', detail: 'union all findings, dedupe by URL, rank by overlap-count, emit master catalog + ingest plan' },
  ],
}

// Deduped, canonical, archeion-relevant queue (core topics first, large indexes last).
const DEFAULT_SOURCES = [
  { repo: 'Danielskry/Awesome-RAG', name: 'awesome-rag', note: 'RAG/retrieval — archeion core' },
  { repo: 'tensorchord/Awesome-LLMOps', name: 'awesome-llmops', note: 'LLM serving/ops — LiteLLM/OVMS' },
  { repo: 'akuity/awesome-argo', name: 'awesome-argo', note: 'ArgoCD — archeion GitOps engine' },
  { repo: 'weaveworks/awesome-gitops', name: 'awesome-gitops', note: 'GitOps discipline' },
  { repo: 'magnologan/awesome-k8s-security', name: 'awesome-k8s-security', note: 'k8s security — Kyverno/Trivy' },
  { repo: 'adriannovegil/awesome-observability', name: 'awesome-observability', note: 'Prometheus/Loki/Grafana' },
  { repo: 'rootsongjc/awesome-cloud-native', name: 'awesome-cloud-native', note: 'cloud-native landscape' },
  { repo: 'kelvins/awesome-mlops', name: 'awesome-mlops', note: 'MLOps' },
  { repo: 'ramitsurana/awesome-kubernetes', name: 'awesome-kubernetes', note: 'k8s canonical (large)' },
  { repo: 'e2b-dev/awesome-ai-agents', name: 'awesome-ai-agents', note: 'AI/research agents (large)' },
  { repo: 'punkpeye/awesome-mcp-servers', name: 'awesome-mcp-servers', note: 'MCP servers (large)' },
  { repo: 'ruanbekker/awesome-homelab', name: 'awesome-homelab', note: 'homelab' },
]
let a = args || {}
if (typeof a === 'string') { try { a = JSON.parse(a) } catch (e) { a = {} } }
const sources = (a && Array.isArray(a.sources) && a.sources.length) ? a.sources : DEFAULT_SOURCES
// Path of the per-source workflow, from the repository root; `harvestSource` overrides it.
const HARVEST_SRC = (a && typeof a.harvestSource === 'string' && a.harvestSource) || 'workflows/harvest-source.js'

phase('Harvest')
const results = []
for (const s of sources) {
  try {
    const r = await workflow({ scriptPath: HARVEST_SRC }, s)
    results.push(r)
    log('harvested ' + s.name + (r && r.clusters ? (' (' + r.clusters + ' clusters)') : ' (no clusters)'))
  } catch (e) {
    log('harvest FAILED ' + s.name + ': ' + (e && e.message))
    results.push({ name: s.name, error: String(e && e.message) })
  }
}

// Project the essential fields so the dedup prompt stays bounded across 12 sources.
const proj = results.filter(r => r && !r.error && r.synthesis).map(r => ({
  source: r.name,
  ingest: r.synthesis.top_ingest_candidates || [],
  repos: (r.synthesis.topics || []).flatMap(t => (t.advanced_repos || []).map(x => ({ name: x.name, url: x.url, why: x.why, action: x.action, effort: x.effort, topic: t.archeion_topic }))),
  principles: r.synthesis.borrowable_principles || [],
  actions: r.synthesis.ranked_actions || [],
}))

phase('Dedup')
const MASTER_SCHEMA = {
  type: 'object', required: ['master_catalog', 'ranked_ingest_plan', 'cross_source_principles', 'top_actions'],
  properties: {
    master_catalog: { type: 'array', items: { type: 'object', required: ['name', 'topic', 'appears_in', 'overlap_count'], properties: {
      name: { type: 'string' }, url: { type: 'string' }, topic: { type: 'string' },
      appears_in: { type: 'array', items: { type: 'string' } }, overlap_count: { type: 'integer' },
      borrowable_principle: { type: 'string' }, action: { type: 'string' }, effort: { type: 'string' } } } },
    cross_source_principles: { type: 'array', items: { type: 'object', properties: {
      principle: { type: 'string' }, sources: { type: 'array', items: { type: 'string' } }, apply_to_archeion: { type: 'string' } } } },
    ranked_ingest_plan: { type: 'array', items: { type: 'object', required: ['what', 'into_corpus', 'priority'], properties: {
      what: { type: 'string' }, url: { type: 'string' }, into_corpus: { type: 'string', enum: ['module1', 'dev-sync', 'new-corpus'] },
      why: { type: 'string' }, overlap_count: { type: 'integer' }, priority: { type: 'string', enum: ['high', 'med', 'low'] } } } },
    dedup_stats: { type: 'object', properties: { total_raw: { type: 'integer' }, unique: { type: 'integer' }, most_corroborated: { type: 'array', items: { type: 'string' } } } },
    top_actions: { type: 'array', items: { type: 'object', properties: { action: { type: 'string' }, impact: { type: 'string' }, effort: { type: 'string' }, rank: { type: 'integer' } } } },
  },
}

const merged = await agent([
  'ARCHEION = dual-site self-hosted Kubernetes platform running a signed content-addressed RAG knowledge registry (served over MCP), an agent fleet behind a LiteLLM proxy over local Qwen/gpt-oss GPUs, Kyverno/Trivy security, ArgoCD GitOps, Prometheus/Loki/Grafana.',
  'You are merging ' + proj.length + ' per-list harvest reports into ONE master. Awesome lists are OVERLAPPING INDEXES of the same universe — the whole point is to DEDUPLICATE.',
  '',
  'Per-list reports (JSON): ' + JSON.stringify(proj),
  '',
  'Produce:',
  '1. master_catalog[]: every DISTINCT repo/paper, DEDUPED BY URL (normalize github.com/owner/repo). For each: which lists it appears_in[], overlap_count (how many lists), its topic, the best borrowable_principle across duplicates, action, effort. Rank the catalog by overlap_count DESC then value — the most-corroborated items first (a repo in many lists is a stronger signal).',
  '2. cross_source_principles[]: techniques/principles that recur across MULTIPLE lists (the durable ideas), each with which sources and how to apply to archeion.',
  '3. ranked_ingest_plan[]: the deduplicated set of sources whose docs should enter the archeion RAG (module1 = infra component docs, dev-sync = archeion own repos, new-corpus = a new topical authority e.g. rag/agents/llmops), ranked by priority and overlap_count. Do NOT list the same URL twice.',
  '4. dedup_stats: total_raw (sum before dedup), unique (after), most_corroborated (top URLs by overlap).',
  '5. top_actions[]: the highest impact x cheapness moves across the whole harvest.',
  'Be comprehensive; token cost is not a constraint. The value is a single deduplicated, corroboration-ranked view of the entire ecosystem relevant to archeion.',
].join('\n'), { model: 'fable', phase: 'Dedup', label: 'dedup-merge', schema: MASTER_SCHEMA })

return {
  sources: sources.length,
  harvested_ok: results.filter(r => r && !r.error && r.synthesis).length,
  failed: results.filter(r => r && r.error).map(r => r.name),
  no_clusters: results.filter(r => r && !r.error && !r.synthesis).map(r => r.name),
  merged,
}
