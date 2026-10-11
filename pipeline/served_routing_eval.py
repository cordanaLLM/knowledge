#!/usr/bin/env python3
"""Comprehensive SERVED cross-authority routing eval over all 46 authorities:
for each authority, derive a distinctive query, generate a query-signal in-tree
(materialize-query-signal), run served multidomain hybrid-query --lineage-set,
check whether the top-1 result routes to that authority. Prints RESULT=<json>."""
import json, os, re, subprocess, glob, hashlib, sys

BASE = os.environ.get('ARCHEION_RAG_PROBE_HOME', '.workingdir2/cache/p1-rag-01-probe')
BIN = BASE + '/bin/knowledge-retrieval'
HYB = glob.glob(BASE + '/retrieval-shared-full/hybrid-candidates/sha256/*/*.json')[0]
HSHA = 'sha256:' + hashlib.sha256(open(HYB, 'rb').read()).hexdigest()
DA = glob.glob(BASE + '/dense-46/dense-artifacts/sha256/*/*.json')[0]
DSHA = 'sha256:' + hashlib.sha256(open(DA, 'rb').read()).hexdigest()
ls = json.load(open(BASE + '/lineage-set-full.json'))
POL = ls['lineages'][0]['admission_policy']; PSHA = ls['lineages'][0]['admission_policy_sha256']
os.environ.setdefault('ARCHEION_EMBEDDINGS_ENDPOINT', 'http://127.0.0.1:18080/v3/embeddings')
SKIP = ('readme', 'contributing', 'code_of_conduct', 'security', 'index', 'license',
        'changelog', 'adopters', 'maintainers', 'owners', 'pull_request', 'issue', 'proposal', 'bug_report')

def topic(p):
    return re.sub(r'[_\-]+', ' ', re.sub(r'\.md$', '', p.split('/')[-1])).strip()

def distinctive_topic(e):
    ev = json.load(open(e['evidence_manifest']))
    cands = [f['relative_path'] for f in ev['files']
             if not any(s in f['relative_path'].split('/')[-1].lower() for s in SKIP)]
    if not cands:
        cands = [f['relative_path'] for f in ev['files']]
    return topic(sorted(cands)[0]) if cands else ''

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
for e in ls['lineages']:
    slug = e['authority_id'].split(':')[-2]
    t = distinctive_topic(e)
    query = f'{slug} {t}'.strip()
    subprocess.run(['rm', '-rf', BASE + '/qsig-eval'])
    r = run([BIN, 'materialize-query-signal', '--hybrid-candidate', HYB, '--hybrid-candidate-sha256', HSHA,
             '--dense-artifact', DA, '--dense-artifact-sha256', DSHA, '--query', query,
             '--query-instruction', 'Given a web search query, retrieve relevant passages that answer the query',
             '--embedding-model', 'qwen3-embed', '--store', BASE + '/qsig-eval'])
    sig = jparse(r)
    if not sig or 'artifact_path' not in sig:
        results.append({'slug': slug, 'query': query, 'top': 'SIGNAL_FAIL', 'ok': False}); continue
    sp = sig['artifact_path']; ssha = 'sha256:' + hashlib.sha256(open(sp, 'rb').read()).hexdigest()
    r = run([BIN, 'hybrid-query', '--hybrid-candidate', HYB, '--hybrid-candidate-sha256', HSHA,
             '--store', BASE + '/retrieval-shared-full', '--evidence-store', BASE + '/evidence-merged-full',
             '--admission-policy', POL, '--admission-policy-sha256', PSHA, '--lineage-set', BASE + '/lineage-set-full.json',
             '--query-artifact', sp, '--query-artifact-sha256', ssha, '--query', query,
             '--principal-scope', 'public', '--as-of', '2026-07-18T12:00:00Z', '--rerank-window', '0', '--limit', '1'])
    d = jparse(r)
    res = (d.get('results') if d else None) or []
    top = (res[0]['evidence'].get('component_id', '?').split('/')[-1]) if res else 'NONE'
    results.append({'slug': slug, 'query': query, 'top': top, 'ok': top == slug})

ok = sum(1 for x in results if x['ok'])
print('RESULT=' + json.dumps({'total': len(results), 'correct': ok,
                              'accuracy': round(ok / len(results), 3), 'results': results}))
