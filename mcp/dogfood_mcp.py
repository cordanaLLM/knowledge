#!/usr/bin/env python3
"""Dogfood knowledge-registry MCP server (stdio, no external deps).

Serves the proven 46-authority signed dogfood corpus to agents (Claude Code / Codex)
as an MCP tool `search_cluster_docs`. Per query: in-tree query-signal generation
(materialize-query-signal) -> served multidomain hybrid-query --lineage-set ->
cross-authority results with per-authority citation + source URI + excerpt.

Requires ARCHEION_EMBEDDINGS_ENDPOINT to point at an OpenAI-compatible /v1/embeddings endpoint
(e.g. kubectl port-forward -n ai svc/qwen3-embed-cpu 18082:80). Speaks
newline-delimited JSON-RPC 2.0 on stdio (MCP stdio transport)."""
import json, sys, os, subprocess, hashlib, glob, tempfile, datetime, time, urllib.request

def ensure_endpoint():
    """Make the embeddings endpoint reachable, starting a port-forward if needed.
    Runs outside the Bash sandbox when spawned by an MCP client, so the forward persists."""
    ep = os.environ.get('ARCHEION_EMBEDDINGS_ENDPOINT') or 'http://127.0.0.1:18082/v1/embeddings'
    os.environ['ARCHEION_EMBEDDINGS_ENDPOINT'] = ep
    probe = urllib.request.Request(ep, data=json.dumps({'model': 'qwen3-embed', 'input': ['x'],
                                   'encoding_format': 'float'}).encode(), headers={'Content-Type': 'application/json'})
    def up():
        try:
            urllib.request.urlopen(probe, timeout=5); return True
        except Exception:
            return False
    if up():
        return True
    if '127.0.0.1:18082' in ep or 'localhost:18082' in ep:
        # History: predictor -> router -> cpu. qwen3-embed-predictor has NO
        # endpoints at all, and qwen3-embed-router answers every request with
        # 503 "B60 cache cannot fit qwen3-embed": the OVMS arbiter and
        # llama-swap both own that card and cannot see each other, so the GPU
        # embed lane never loads. Both registries were therefore dead.
        # qwen3-embed-cpu is the live CPU leg that
        # LiteLLM's own cordana/qwen3-embed already routes to; it needs no auth
        # in-cluster and serves the SAME Qwen3-Embedding model, verified
        # dim=1024 for both "qwen3-embed" and "qwen3-embed-cpu" model IDs, so
        # existing dense artifacts stay compatible. Note the path is /v1, not
        # the router's /v3.
        subprocess.Popen(['kubectl', 'port-forward', '-n', 'ai', 'svc/qwen3-embed-cpu', '18082:80'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(10):
            time.sleep(1)
            if up():
                return True
    return False

BASE = os.environ.get('ARCHEION_RAG_PROBE_HOME', '.workingdir2/cache/p1-rag-01-probe')
BIN = BASE + '/bin/knowledge-retrieval'
STORE = BASE + '/retrieval-shared-full'
EVID = BASE + '/evidence-merged-full'
LINEAGE = BASE + '/lineage-set-full.json'
QUERY_INSTRUCTION = 'Given a web search query, retrieve relevant passages that answer the query'
PROTOCOL = '2024-11-05'

def _load():
    ls = json.load(open(LINEAGE))
    hyb = sorted(glob.glob(STORE + '/hybrid-candidates/sha256/*/*.json'))[0]
    dense = sorted(glob.glob(BASE + '/dense-46/dense-artifacts/sha256/*/*.json'))[0]
    return {
        'hyb': hyb, 'hyb_sha': 'sha256:' + hashlib.sha256(open(hyb, 'rb').read()).hexdigest(),
        'dense': dense, 'dense_sha': 'sha256:' + hashlib.sha256(open(dense, 'rb').read()).hexdigest(),
        'pol': ls['lineages'][0]['admission_policy'], 'pol_sha': ls['lineages'][0]['admission_policy_sha256'],
        'n_auth': len(ls['lineages']),
    }

def _jparse(r):
    for s in (r.stdout, r.stderr):
        s = (s or '').strip()
        i = s.find('{')
        if i >= 0:
            try:
                return json.loads(s[i:])
            except Exception:
                pass
    return None

def _rerank(query, hits):
    """Reorder fusion hits by the live qwen3-rerank cross-encoder (Qwen3 template).
    Serve-time reranking of excerpts — improves passage precision. Best-effort: on
    any failure the fusion order is returned unchanged."""
    ep = os.environ.get('ARCHEION_RERANK_ENDPOINT') or 'http://127.0.0.1:18095/v3/rerank'
    os.environ['ARCHEION_RERANK_ENDPOINT'] = ep
    docs = [h.get('excerpt', '') for h in hits]
    if not docs:
        return hits
    inst = 'Instruct: Given a web search query, retrieve the most relevant passage.\nQuery: ' + query
    body = json.dumps({'model': 'qwen3-rerank', 'query': inst, 'documents': docs}).encode()
    req = urllib.request.Request(ep, data=body, headers={'Content-Type': 'application/json'})
    def call():
        return json.load(urllib.request.urlopen(req, timeout=30)).get('results', [])
    try:
        res = call()
    except Exception:
        if '127.0.0.1:18095' in ep:
            subprocess.Popen(['kubectl', 'port-forward', '-n', 'ai', 'svc/qwen3-rerank-predictor', '18095:80'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(6)
            try:
                res = call()
            except Exception:
                return hits
        else:
            return hits
    order = sorted(res, key=lambda x: -x.get('relevance_score', 0))
    ranked = []
    for o in order:
        i = o.get('index')
        if isinstance(i, int) and 0 <= i < len(hits):
            h = dict(hits[i]); h['rerank_score'] = round(o.get('relevance_score', 0), 4); ranked.append(h)
    return ranked or hits

def search(query, limit=5):
    cfg = _load()
    if not ensure_endpoint():
        return {'error': 'embedding endpoint unreachable (could not reach or port-forward svc/qwen3-embed-cpu -n ai /v1/embeddings)'}
    tmp = tempfile.mkdtemp(prefix='mcp-qsig-')
    r = subprocess.run([BIN, 'materialize-query-signal', '--hybrid-candidate', cfg['hyb'],
                        '--hybrid-candidate-sha256', cfg['hyb_sha'], '--dense-artifact', cfg['dense'],
                        '--dense-artifact-sha256', cfg['dense_sha'], '--query', query,
                        '--query-instruction', QUERY_INSTRUCTION, '--embedding-model', 'qwen3-embed',
                        '--store', tmp], capture_output=True, text=True)
    sig = _jparse(r)
    if not sig or 'artifact_path' not in sig:
        return {'error': 'query embedding failed: ' + (r.stderr or r.stdout)[:200]}
    sp = sig['artifact_path']; ssha = 'sha256:' + hashlib.sha256(open(sp, 'rb').read()).hexdigest()
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    r = subprocess.run([BIN, 'hybrid-query', '--hybrid-candidate', cfg['hyb'], '--hybrid-candidate-sha256', cfg['hyb_sha'],
                        '--store', STORE, '--evidence-store', EVID, '--admission-policy', cfg['pol'],
                        '--admission-policy-sha256', cfg['pol_sha'], '--lineage-set', LINEAGE,
                        '--query-artifact', sp, '--query-artifact-sha256', ssha, '--query', query,
                        '--principal-scope', 'public', '--as-of', now, '--rerank-window', '0',
                        '--limit', str(max(1, min(int(limit), 20)))], capture_output=True, text=True)
    d = _jparse(r)
    if not d or d.get('result_state') != 'ok':
        return {'error': 'retrieval failed: ' + json.dumps(d)[:200] if d else (r.stderr or r.stdout)[:200]}
    hits = []
    for h in d.get('results', []):
        ev = h.get('evidence', {})
        hits.append({
            'authority': ev.get('component_id', '?'),
            'version': ev.get('component_version_id', ''),
            'source_uri': ev.get('canonical_source_uri', ''),
            'span_id': ev.get('span_id', ''),
            'excerpt': ' '.join((h.get('excerpt') or '').split())[:600],
        })
    # NOTE: cross-authority reranking de-routes (semantically-plausible wrong-authority
    # passages win); fusion dense+lexical routes correctly. Rerank only WITHIN a chosen
    # authority, not across — left as a follow-up. Return fusion order.
    return {'authorities_searched': cfg['n_auth'], 'result_count': len(hits), 'results': hits}

TOOLS = [{
    'name': 'search_cluster_docs',
    'description': ('Search the signed dogfood knowledge registry — 46 cluster-component authorities '
                   '(cilium, argocd, longhorn, cnpg, prometheus, kyverno, cert-manager, kserve, vault, '
                   'harbor, gateway-api, loki, grafana, trivy, keda, etc.). Returns cross-authority '
                   'documentation passages with exact per-authority provenance (source repo + commit). '
                   'Use for "how do I configure X" cluster questions.'),
    'inputSchema': {'type': 'object', 'required': ['query'], 'properties': {
        'query': {'type': 'string', 'description': 'The cluster documentation question.'},
        'limit': {'type': 'integer', 'description': 'Max results (1-20, default 5).', 'default': 5}}},
}]

def handle(msg):
    m = msg.get('method'); mid = msg.get('id')
    if m == 'initialize':
        return {'jsonrpc': '2.0', 'id': mid, 'result': {
            'protocolVersion': PROTOCOL, 'capabilities': {'tools': {}},
            'serverInfo': {'name': 'archeion-dogfood-registry', 'version': '0.1.0'}}}
    if m == 'notifications/initialized':
        return None
    if m == 'tools/list':
        return {'jsonrpc': '2.0', 'id': mid, 'result': {'tools': TOOLS}}
    if m == 'tools/call':
        p = msg.get('params', {})
        if p.get('name') != 'search_cluster_docs':
            return {'jsonrpc': '2.0', 'id': mid, 'error': {'code': -32601, 'message': 'unknown tool'}}
        args = p.get('arguments', {})
        out = search(args.get('query', ''), args.get('limit', 5))
        return {'jsonrpc': '2.0', 'id': mid, 'result': {
            'content': [{'type': 'text', 'text': json.dumps(out, indent=2)}],
            'isError': 'error' in out}}
    if mid is not None:
        return {'jsonrpc': '2.0', 'id': mid, 'error': {'code': -32601, 'message': 'method not found: ' + str(m)}}
    return None

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + '\n')
            sys.stdout.flush()

if __name__ == '__main__':
    main()
