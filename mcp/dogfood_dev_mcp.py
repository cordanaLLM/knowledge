#!/usr/bin/env python3
"""Dev-sync knowledge-registry MCP server (stdio, no external deps).

Module 2 of the archeion dogfood RAG. Serves the signed 11-authority dev-sync corpus
(the owner's own repositories at default-branch HEAD) to agents as `search_dev_docs`.
Same served path as the Module-1 cluster server: in-tree query-signal generation
(materialize-query-signal) -> served multidomain hybrid-query --lineage-set ->
cross-authority results with per-repo provenance (source repo + commit).

Requires ARCHEION_EMBEDDINGS_ENDPOINT at an OpenAI-compatible /v1/embeddings endpoint
(kubectl port-forward -n ai svc/qwen3-embed-cpu 18082:80)."""
import json, sys, os, subprocess, hashlib, glob, tempfile, datetime, time, urllib.request

DEV = os.environ.get('ARCHEION_RAG_DEVSYNC_HOME', '.workingdir2/cache/dev-sync')
BIN = os.environ.get('ARCHEION_RAG_PROBE_HOME', '.workingdir2/cache/p1-rag-01-probe') + '/bin/knowledge-retrieval'
STORE = DEV + '/retrieval-shared-dev'
EVID = DEV + '/evidence-merged-dev'
LINEAGE = DEV + '/lineage-set-dev.json'
DENSE_GLOB = DEV + '/dense-dev/dense-artifacts/sha256/*/*.json'
QUERY_INSTRUCTION = 'Given a web search query, retrieve relevant passages that answer the query'
PROTOCOL = '2024-11-05'


def ensure_endpoint():
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


def _load():
    ls = json.load(open(LINEAGE))
    hyb = sorted(glob.glob(STORE + '/hybrid-candidates/sha256/*/*.json'))[0]
    dense = sorted(glob.glob(DENSE_GLOB))[0]
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


def search(query, limit=5):
    cfg = _load()
    if not ensure_endpoint():
        return {'error': 'embedding endpoint unreachable (could not reach or port-forward svc/qwen3-embed-cpu -n ai /v1/embeddings)'}
    tmp = tempfile.mkdtemp(prefix='mcp-devqsig-')
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
            'repo': ev.get('component_id', '?'),
            'version': ev.get('component_version_id', ''),
            'source_uri': ev.get('canonical_source_uri', ''),
            'span_id': ev.get('span_id', ''),
            'excerpt': ' '.join((h.get('excerpt') or '').split())[:600],
        })
    return {'repos_searched': cfg['n_auth'], 'result_count': len(hits), 'results': hits}


TOOLS = [{
    'name': 'search_dev_docs',
    'description': ("Search the signed dev-sync knowledge registry — the owner's own repositories at "
                   "default-branch HEAD (k8s, paperclip, k8s-wiki, wetbulb, home-zeus, thrustworthy, "
                   "revit-ai-mcp, northlight, jellyfin-plugin-lastfm, community-repository, jellyfin-utilities). "
                   "Returns documentation/README/ADR passages with exact per-repo provenance (repo + commit). "
                   "Use for \"how does OUR X work / where is OUR Y documented\" questions about archeion's own code."),
    'inputSchema': {'type': 'object', 'required': ['query'], 'properties': {
        'query': {'type': 'string', 'description': 'The question about archeion\'s own repos/docs.'},
        'limit': {'type': 'integer', 'description': 'Max results (1-20, default 5).', 'default': 5}}},
}]


def handle(msg):
    m = msg.get('method'); mid = msg.get('id')
    if m == 'initialize':
        return {'jsonrpc': '2.0', 'id': mid, 'result': {
            'protocolVersion': PROTOCOL, 'capabilities': {'tools': {}},
            'serverInfo': {'name': 'archeion-dev-registry', 'version': '0.1.0'}}}
    if m == 'notifications/initialized':
        return None
    if m == 'tools/list':
        return {'jsonrpc': '2.0', 'id': mid, 'result': {'tools': TOOLS}}
    if m == 'tools/call':
        p = msg.get('params', {})
        if p.get('name') != 'search_dev_docs':
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
