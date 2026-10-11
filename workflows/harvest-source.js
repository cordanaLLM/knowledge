// Reusable exhaustive "research harvest" pipeline for archeion.
// Point it at any curated source (awesome list / index / paper set):
//   Workflow({ name: 'harvest-source', args: { repo: 'owner/name', name: 'slug', note: '...' } })
// It auto-partitions the source into archeion-topic clusters, deep-mines each for
// technique knowledge + borrowable principles + live OSS repos, adversarially
// verifies the top harvest, runs a completeness critic, and emits a digest plus
// a concrete RAG-ingest plan (so the knowledge becomes queryable, not just a doc).
export const meta = {
  name: 'harvest-source',
  description: 'Exhaustively harvest a curated source for archeion: auto-partition into topic clusters, deep-mine each (technique + borrowable principle + liveness), verify, synthesize a deepening digest + RAG ingest plan',
  phases: [
    { title: 'Partition', detail: 'read the source README, propose archeion-relevant topic clusters with line ranges' },
    { title: 'Mine', detail: 'one Fable agent per cluster: papers (technique+insight) and repos (borrowable principle + liveness)' },
    { title: 'Synthesize', detail: 'organize by archeion topic -> deepening knowledge + borrowable principles + ranked harvest + ingest candidates' },
    { title: 'VerifyCritic', detail: 'adversarial liveness/accuracy check + completeness critic with RAG ingest plan' },
  ],
}

let src = args || {}
if (typeof src === 'string') { try { src = JSON.parse(src) } catch (e) { src = {} } }
const REPO = src.repo || ''
const NAME = (src.name || REPO.split('/').pop() || 'source').replace(/[^A-Za-z0-9._-]/g, '-')
const NOTE = src.note || ''
const PIN = '/tmp/harvest-' + NAME + '.md'
if (!REPO && !src.url) {
  log('harvest-source: no args.repo or args.url provided')
  return { error: 'no source provided' }
}

const ARCHEION = [
  'ARCHEION = dual-site self-hosted Kubernetes platform (GitOps via ArgoCD; Cilium Gateway API; CNPG Postgres; Longhorn; Harbor; Prometheus/Loki/Grafana; Kyverno/Trivy; cert-manager; KEDA).',
  'It runs a signed, content-addressed RAG knowledge registry (hybrid lexical+dense+RRF+reranker, served over MCP), a fleet of coding+revenue agents (Claude Code / Gemini-CLI agy / opencode / ollama) behind a LiteLLM proxy fronting local Qwen3.x + gpt-oss on Arc B60/B580 + a 4090 (OVMS, scale-to-zero), a 9-gate DETERMINISTIC eval, strict JSON tool contracts, and just wired gitea+github MCP servers.',
  'Topics archeion actively runs: RAG/retrieval, prompt optimization, multi-agent orchestration, reasoning models, structured output, token-thrift/compression, prompt-injection security, MCP, coding agents, eval/benchmarking, self-improving/research agents, cloud-native/k8s ops, observability.',
  'OPERATOR FRAMING: exhaustive, not shortlists. Even if we adopt NO finished product, we borrow techniques and principles. For EVERY item (paper OR repo) extract the transferable idea, not just an adopt/skip verdict. The end goal is to DEEPEN archeion: ingest the best sources into the RAG so agents can query them.',
].join('\n')

const REPO_ITEM = {
  type: 'object', required: ['name', 'what', 'borrowable_principle', 'action', 'effort', 'alive'],
  properties: {
    name: { type: 'string' }, url: { type: 'string' }, what: { type: 'string' }, why_archeion: { type: 'string' },
    borrowable_principle: { type: 'string', description: 'transferable technique/idea worth borrowing EVEN IF we never adopt the product' },
    action: { type: 'string', enum: ['adopt', 'study', 'ingest', 'borrow-only', 'skip'] },
    effort: { type: 'string', enum: ['trivial', 'small', 'medium', 'large'] },
    alive: { type: 'boolean' }, last_activity: { type: 'string' }, note: { type: 'string' },
  },
}
const MINE_SCHEMA = {
  type: 'object', required: ['cluster', 'items', 'highest_value_item'],
  properties: {
    cluster: { type: 'string' },
    papers: { type: 'array', items: { type: 'object', required: ['title', 'technique', 'insight'], properties: {
      title: { type: 'string' }, url: { type: 'string' }, technique: { type: 'string' }, insight: { type: 'string' },
      archeion_topic: { type: 'string' }, depth_value: { type: 'string', enum: ['high', 'med', 'low'] } } } },
    items: { type: 'array', items: REPO_ITEM },
    highest_value_item: { type: 'string' },
  },
}

// ---- Phase 0: partition ----
phase('Partition')
const PART_SCHEMA = {
  type: 'object', required: ['source_name', 'clusters', 'pinned'],
  properties: {
    source_name: { type: 'string' }, pinned: { type: 'boolean' }, total_headings: { type: 'integer' },
    archeion_relevance_overall: { type: 'string', enum: ['high', 'med', 'low', 'none'] },
    clusters: { type: 'array', items: { type: 'object', required: ['key', 'name', 'lines', 'archeion_topic'], properties: {
      key: { type: 'string' }, name: { type: 'string' },
      lines: { type: 'string', description: 'line range(s) in the pinned file, e.g. "120-160" or "120-160 and 300-320"' },
      archeion_topic: { type: 'string' } } } },
  },
}
const partition = await agent([
  ARCHEION, '',
  'You are partitioning a curated source for exhaustive harvesting. Source repo: ' + (REPO || src.url) + (NOTE ? ('  (' + NOTE + ')') : ''),
  '',
  'STEP 1 — pin the README locally so downstream agents read identical bytes:',
  '  - Resolve the default branch: gh api repos/' + REPO + ' --jq .default_branch',
  '  - curl the raw README to ' + PIN + ' :  curl -s -L "https://raw.githubusercontent.com/' + REPO + '/<branch>/README.md" -o ' + PIN,
  '  - If that README is a thin index that points to other list files (docs/*.md, README-*.md), append them into ' + PIN + ' too (this list may be multi-file). Confirm the file is non-empty (wc -c).',
  'STEP 2 — enumerate structure: grep -nE "^#{2,4} " ' + PIN + ' to get every heading with its line number.',
  'STEP 3 — propose up to 12 CLUSTERS that map the source onto archeion topics. Each cluster groups related sections; give it a key, a human name, the exact line range(s) in ' + PIN + ', and the archeion topic it serves. Skip sections with no plausible archeion relevance (badges, sponsors, license, contributing). If the whole source is irrelevant to archeion, return an empty clusters array and archeion_relevance_overall=none.',
  'Return the structured object. pinned=true only if ' + PIN + ' exists and is non-empty.',
].join('\n'), { model: 'fable', phase: 'Partition', label: 'partition:' + NAME, schema: PART_SCHEMA })

const clusters = (partition.clusters || []).slice(0, 12)
if (!partition.pinned || clusters.length === 0) {
  log('harvest-source ' + NAME + ': no clusters (pinned=' + partition.pinned + ', relevance=' + partition.archeion_relevance_overall + ')')
  return { name: NAME, repo: REPO, partition, note: 'no archeion-relevant clusters harvested' }
}
log('harvest ' + NAME + ': ' + clusters.length + ' clusters from ' + (partition.total_headings || '?') + ' headings')

// ---- Phase 1: mine ----
phase('Mine')
const minePrompt = (c) => [
  ARCHEION, '',
  'You are the deep-mining specialist for ONE cluster of the source "' + NAME + '".',
  'Cluster: ' + c.name + '   (archeion topic: ' + c.archeion_topic + ')',
  'The source README is pinned at: ' + PIN,
  'Read YOUR section(s) at lines ' + c.lines + ' of that file (Read tool with offset/limit, or sed -n via Bash). Read every entry in range.',
  '',
  'EXHAUSTIVE, not a shortlist:',
  '- For every PAPER: give the actual TECHNIQUE (mechanism, not a title restatement) and the load-bearing INSIGHT archeion learns.',
  '- For every REPO/tool (the "items"): what it does, why it matters to archeion, and CRUCIALLY the borrowable_principle (transferable idea worth borrowing even if we never adopt it). Then action (adopt/study/ingest/borrow-only/skip), effort, and VERIFY liveness: gh api repos/OWNER/REPO --jq .pushed_at (also stargazers_count). Mark alive=false for anything not pushed within ~12 months.',
  '- Prioritize ADVANCED, non-obvious items over basics. Use WebFetch on the 2-3 most promising entries to extract real substance.',
  'Return the structured object. Token cost is not a constraint; the failure mode is missing a valuable item or mis-describing a technique.',
].join('\n')
const mined = (await parallel(clusters.map(c => () =>
  agent(minePrompt(c), { model: 'fable', phase: 'Mine', label: 'mine:' + c.key, schema: MINE_SCHEMA })
))).filter(Boolean)

// ---- Phase 2: synthesize ----
phase('Synthesize')
const SYNTH_SCHEMA = {
  type: 'object', required: ['topics', 'borrowable_principles', 'top_ingest_candidates', 'ranked_actions'],
  properties: {
    topics: { type: 'array', items: { type: 'object', required: ['archeion_topic', 'deepening_knowledge', 'advanced_repos'], properties: {
      archeion_topic: { type: 'string' },
      deepening_knowledge: { type: 'array', items: { type: 'object', properties: { item: { type: 'string' }, url: { type: 'string' }, what_we_learn: { type: 'string' } } } },
      advanced_repos: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, url: { type: 'string' }, why: { type: 'string' }, action: { type: 'string' }, effort: { type: 'string' } } } } } } },
    borrowable_principles: { type: 'array', items: { type: 'object', properties: { principle: { type: 'string' }, from: { type: 'string' }, apply_to_archeion: { type: 'string' } } } },
    top_ingest_candidates: { type: 'array', items: { type: 'object', required: ['url', 'type', 'why', 'priority'], properties: {
      url: { type: 'string' }, type: { type: 'string', enum: ['paper', 'repo', 'list', 'survey', 'doc'] }, why: { type: 'string' }, priority: { type: 'string', enum: ['high', 'med', 'low'] } } } },
    ranked_actions: { type: 'array', items: { type: 'object', properties: { action: { type: 'string' }, impact: { type: 'string' }, effort: { type: 'string' }, rank: { type: 'integer' } } } },
  },
}
const synthesis = await agent([
  ARCHEION, '',
  'Synthesize ' + mined.length + ' deep-mining reports from the source "' + NAME + '" into a knowledge-DEEPENING digest for archeion.',
  'Reports (JSON): ' + JSON.stringify(mined),
  '',
  'Produce: (1) topics[] grouped by archeion topic, each with deepening_knowledge[] (papers/techniques + what_we_learn) and advanced_repos[] (ranked live OSS to adopt/study); (2) borrowable_principles[] cross-cutting techniques worth borrowing regardless of adoption, each with from + apply_to_archeion; (3) top_ingest_candidates[] highest-value sources whose docs belong in the archeion RAG, ranked by priority; (4) ranked_actions[] concrete moves by impact x cheapness. Be comprehensive, specific, advanced.',
].join('\n'), { model: 'fable', phase: 'Synthesize', label: 'synthesize:' + NAME, schema: SYNTH_SCHEMA })

// ---- Phase 3: verify + critic ----
phase('VerifyCritic')
const VERIFY_SCHEMA = { type: 'object', required: ['checked'], properties: {
  checked: { type: 'array', items: { type: 'object', required: ['item', 'verdict'], properties: {
    item: { type: 'string' }, url: { type: 'string' },
    verdict: { type: 'string', enum: ['real_alive_accurate', 'dead_or_stale', 'hype_overstated', 'misattributed'] }, note: { type: 'string' } } } },
  survivors: { type: 'array', items: { type: 'string' } }, killed: { type: 'array', items: { type: 'string' } } } }
const CRITIC_SCHEMA = { type: 'object', required: ['ingest_plan'], properties: {
  missing_items: { type: 'array', items: { type: 'object', properties: { item: { type: 'string' }, section: { type: 'string' }, why_valuable: { type: 'string' } } } },
  missing_topics: { type: 'array', items: { type: 'string' } },
  unverified_claims: { type: 'array', items: { type: 'string' } },
  ingest_plan: { type: 'array', items: { type: 'object', required: ['what', 'into_corpus', 'why'], properties: {
    what: { type: 'string' }, url: { type: 'string' }, into_corpus: { type: 'string', enum: ['module1', 'dev-sync', 'new-corpus'] }, why: { type: 'string' } } } } } }

const [verify, critic] = await parallel([
  () => agent([
    ARCHEION,
    'Adversarially verify the TOP harvest from source "' + NAME + '".',
    'topics: ' + JSON.stringify(synthesis.topics),
    'ingest candidates: ' + JSON.stringify(synthesis.top_ingest_candidates),
    'For the ~20 highest-ranked repos/papers: is each REAL, ALIVE (gh api repos/OWNER/REPO --jq .pushed_at via Bash), and ACCURATELY described, or dead/stale, hype-overstated, or misattributed? Default to skepticism. Return checked[] + survivors[] + killed[].',
  ].join('\n'), { model: 'fable', phase: 'VerifyCritic', label: 'verify:' + NAME, schema: VERIFY_SCHEMA }),
  () => agent([
    ARCHEION,
    'Completeness critic for source "' + NAME + '". Pinned README at ' + PIN + ' (read any section you doubt was covered).',
    'Cluster coverage: ' + JSON.stringify(mined.map(m => ({ cluster: m.cluster, papers: (m.papers || []).length, items: (m.items || []).length, top: m.highest_value_item }))),
    'Synthesis actions: ' + JSON.stringify(synthesis.ranked_actions),
    'What high-value items/topics were MISSED or under-covered? What claims are unverified? Then produce ingest_plan[]: which sources to ingest into which corpus (module1 = component docs, dev-sync = archeion own repos, new-corpus = a new topical authority) and why. Be exhaustive about gaps.',
  ].join('\n'), { model: 'fable', phase: 'VerifyCritic', label: 'critic:' + NAME, schema: CRITIC_SCHEMA }),
])

return { name: NAME, repo: REPO, clusters: clusters.length, synthesis, verify, critic }
