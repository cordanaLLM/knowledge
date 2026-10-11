#!/usr/bin/env python3
"""Known-item routing verification for the dev-sync corpus over the SAME served path
the Module-1 MCP uses: materialize-query-signal -> hybrid-query --lineage-set
--rerank-window 0. Prints per-query top-1 authority + excerpt. Usage: verify_dev.py"""
import json, os, subprocess, glob, hashlib, datetime, sys

DEV = os.environ.get('ARCHEION_RAG_DEVSYNC_HOME', '.workingdir2/cache/dev-sync')
BIN = os.environ.get('ARCHEION_RAG_PROBE_HOME', '.workingdir2/cache/p1-rag-01-probe') + '/bin/knowledge-retrieval'
STORE = DEV + '/retrieval-shared-dev'
EVID = DEV + '/evidence-merged-dev'
LINEAGE = DEV + '/lineage-set-dev.json'
QINST = 'Given a web search query, retrieve relevant passages that answer the query'
os.environ.setdefault('ARCHEION_EMBEDDINGS_ENDPOINT', 'http://127.0.0.1:18080/v3/embeddings')

HYB = sorted(glob.glob(STORE + '/hybrid-candidates/sha256/*/*.json'))[0]
HSHA = 'sha256:' + hashlib.sha256(open(HYB, 'rb').read()).hexdigest()
DA = sorted(glob.glob(DEV + '/dense-dev/dense-artifacts/sha256/*/*.json'))[0]
DSHA = 'sha256:' + hashlib.sha256(open(DA, 'rb').read()).hexdigest()
ls = json.load(open(LINEAGE))
POL = ls['lineages'][0]['admission_policy']; PSHA = ls['lineages'][0]['admission_policy_sha256']

# (query, expected authority slug)
QUERIES = [
    ('paperclip reconciler org invariants', 'paperclip'),
    ('archeion gpu unified backend palette', 'k8s'),
    ('thedesknook northlight org', 'northlight'),
    ('revit autodesk machine tuning', 'revit-ai-mcp'),
    ('wetbulb gnss ptp time architecture holdover', 'wetbulb'),
    ('thrustworthy consent failsafe control invariant', 'thrustworthy'),
    ('jellyfin lastfm api scrobbling plugin', 'jellyfin-plugin-lastfm'),
]

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def jparse(r):
    for s in (r.stderr, r.stdout):
        s = (s or '').strip()
        if not s:
            continue
        i = s.find('{')
        if i >= 0:
            try:
                return json.loads(s[i:])
            except Exception:
                pass
    return None

results = []
for query, expect in QUERIES:
    subprocess.run(['rm', '-rf', DEV + '/qsig-dev'])
    r = run([BIN, 'materialize-query-signal', '--hybrid-candidate', HYB, '--hybrid-candidate-sha256', HSHA,
             '--dense-artifact', DA, '--dense-artifact-sha256', DSHA, '--query', query,
             '--query-instruction', QINST, '--embedding-model', 'qwen3-embed', '--store', DEV + '/qsig-dev'])
    sig = jparse(r)
    if not sig or 'artifact_path' not in sig:
        results.append({'query': query, 'expect': expect, 'top': 'SIGNAL_FAIL',
                        'ok': False, 'err': (r.stderr or r.stdout)[:200]}); continue
    sp = sig['artifact_path']; ssha = 'sha256:' + hashlib.sha256(open(sp, 'rb').read()).hexdigest()
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    r = run([BIN, 'hybrid-query', '--hybrid-candidate', HYB, '--hybrid-candidate-sha256', HSHA,
             '--store', STORE, '--evidence-store', EVID, '--admission-policy', POL, '--admission-policy-sha256', PSHA,
             '--lineage-set', LINEAGE, '--query-artifact', sp, '--query-artifact-sha256', ssha, '--query', query,
             '--principal-scope', 'public', '--as-of', now, '--rerank-window', '0', '--limit', '3'])
    d = jparse(r)
    if not d or d.get('result_state') != 'ok':
        results.append({'query': query, 'expect': expect, 'top': 'QUERY_FAIL',
                        'ok': False, 'err': json.dumps(d)[:200] if d else (r.stderr or r.stdout)[:200]}); continue
    hits = d.get('results', [])
    top_repo = hits[0]['evidence'].get('component_id', '?').split('/')[-1] if hits else 'NONE'
    top_uri = hits[0]['evidence'].get('canonical_source_uri', '') if hits else ''
    excerpt = ' '.join((hits[0].get('excerpt') or '').split())[:160] if hits else ''
    results.append({'query': query, 'expect': expect, 'top': top_repo, 'ok': top_repo == expect,
                    'uri': top_uri, 'excerpt': excerpt,
                    'top3': [h['evidence'].get('component_id', '?').split('/')[-1] for h in hits]})

ok = sum(1 for x in results if x['ok'])
print('=== dev-sync known-item routing ===')
print(f'hybrid_candidate: {HYB}')
print(f'hybrid_candidate_sha256: {HSHA}')
print(f'dense_artifact_sha256: {DSHA}')
print(f'authorities: {len(ls["lineages"])}   correct: {ok}/{len(results)}')
for x in results:
    mark = 'OK ' if x['ok'] else 'XX '
    print(f'\n{mark} q="{x["query"]}"  expect={x["expect"]}  top={x["top"]}  top3={x.get("top3")}')
    if x.get('uri'):
        print(f'     uri: {x["uri"]}')
    if x.get('excerpt'):
        print(f'     excerpt: {x["excerpt"]}')
    if x.get('err'):
        print(f'     err: {x["err"]}')
print('\nRESULT=' + json.dumps({'authorities': len(ls['lineages']), 'correct': ok, 'total': len(results),
                                'hybrid_candidate_sha256': HSHA}))
