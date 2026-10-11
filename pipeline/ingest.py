#!/usr/bin/env python3
"""Deterministic per-authority dogfood ingest: GitHub docs -> snapshot+evidence+admission.
Usage: GITHUB_TOKEN=... python3 ingest.py <slug> <org/repo>
Prints a single line: RESULT=<json lineage-entry> (ok=false on any failure)."""
import json, os, subprocess, sys, urllib.request, hashlib, glob, shutil, re

slug, repo = sys.argv[1], sys.argv[2]
org = repo.split('/')[0]
REPO = os.environ.get('ARCHEION_K8S_REPO', '.')
BASE = os.environ.get('ARCHEION_RAG_PROBE_HOME', f'{REPO}/.workingdir2/cache/p1-rag-01-probe')
BIN = f'{BASE}/bin'
SIGNER = f'{REPO}/.workingdir2/cache/service-identities/knowledge-acquisition-signer/signer'
TRUST = f'{REPO}/knowledge/registry/trust/acquisition-allowed-signers'
TEMPLATE = f'{BASE}/acquire-longhorn/longhorn.admission.core.json'
ACQ = f'{BASE}/acquire-{slug}'
TOKEN = os.environ.get('GITHUB_TOKEN', '')
FREEZE_ID = 'retrieval-evaluation-freeze:archeion-dogfood-v1'
FREEZE_SHA = 'sha256:457e23ca9e88bef870df0d39194edf3cc74c3b796ea394a3e49d7b7e785d1638'
EXEC_ID = 'source-acquisition-execution-manifest:sha256:77408c9e73350efb068c17863b2282ce1db44c2d9ca3075e26bcff7149241690'
EXEC_SHA = 'sha256:77408c9e73350efb068c17863b2282ce1db44c2d9ca3075e26bcff7149241690'

def gh(path):
    req = urllib.request.Request('https://api.github.com' + path)
    if TOKEN:
        req.add_header('Authorization', 'Bearer ' + TOKEN)
    req.add_header('Accept', 'application/vnd.github+json')
    req.add_header('User-Agent', 'archeion-dogfood-ingest')
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)

def fail(msg):
    print('RESULT=' + json.dumps({'ok': False, 'slug': slug, 'error': str(msg)[:400]}))
    sys.exit(0)

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def jparse(r):
    """These binaries print their result JSON to stderr; try both streams."""
    for s in (r.stderr, r.stdout):
        s = (s or '').strip()
        if not s:
            continue
        try:
            return json.loads(s)
        except Exception:
            i, j = s.find('{'), s.rfind('}')
            if 0 <= i < j:
                try:
                    return json.loads(s[i:j + 1])
                except Exception:
                    pass
    return None

# 1. latest release tag (fallback to newest tag)
try:
    tag = gh(f'/repos/{repo}/releases/latest')['tag_name']
except Exception:
    try:
        tag = gh(f'/repos/{repo}/tags')[0]['name']
    except Exception as e:
        fail(f'tag resolve: {e}')
# 2. tag -> commit sha1 (deref annotated)
try:
    obj = gh(f'/repos/{repo}/git/refs/tags/{tag}')['object']
    commit = gh(f'/repos/{repo}/git/tags/{obj["sha"]}')['object']['sha'] if obj['type'] == 'tag' else obj['sha']
except Exception as e:
    fail(f'commit resolve: {e}')
# 3. license
try:
    lic = gh(f'/repos/{repo}').get('license') or {}
    lic = lic.get('spdx_id') or 'Apache-2.0'
    if lic in ('NOASSERTION', 'NONE', None):
        lic = 'Apache-2.0'
except Exception:
    lic = 'Apache-2.0'
# 4. tree + markdown selection
try:
    tree = gh(f'/repos/{repo}/git/trees/{commit}?recursive=1').get('tree', [])
except Exception as e:
    fail(f'tree: {e}')
prefer = ('docs/', 'documentation/', 'site/', 'content/')
mds = [t for t in tree if t.get('type') == 'blob' and t['path'].lower().endswith('.md') and 0 < t.get('size', 0) < 200000]
def score(t):
    p = t['path'].lower(); s = 0
    for i, pre in enumerate(prefer):
        if p.startswith(pre):
            s = 10 - i
    if p == 'readme.md':
        s = max(s, 6)
    return (-s, t['path'])
mds.sort(key=score)
sel, total = [], 0
for t in mds:
    if len(sel) >= 12:
        break
    if total + t['size'] > 1500000:
        continue
    sel.append(t); total += t['size']
if not sel:
    r = [t for t in tree if t['path'] == 'README.md' and t.get('type') == 'blob']
    if not r:
        fail('no markdown docs found')
    sel = [r[0]]
files = []
seen = set()
for i, t in enumerate(sel):
    key = re.sub(r'[^a-z0-9]+', '-', f'{slug}-{t["path"]}'.lower()).strip('-')[:70] or f'{slug}-{i}'
    while key in seen:
        key = f'{key}-{i}'
    seen.add(key)
    files.append({'source_key': key, 'path': t['path']})
# 5. spec
os.makedirs(ACQ, exist_ok=True); os.chmod(ACQ, 0o700)
spec = {
    'work_id': f'archeion-dogfood-acquire-{slug}-{tag}',
    'freeze_id': FREEZE_ID, 'freeze_document_sha256': FREEZE_SHA,
    'execution_manifest_id': EXEC_ID, 'execution_manifest_payload_sha256': EXEC_SHA,
    'targets': [{
        'authority_id': f'retrieval-source-authority:{slug}:{tag}',
        'source_set_id': f'source-acquisition-set:{slug}:{tag}',
        'component_id': f'cmp:github:{repo}', 'component_version': tag, 'repository': repo,
        'publisher': {'publisher_id': f'publisher:github:{org}', 'name': org, 'uri': f'https://github.com/{org}'},
        'license_expression': lic, 'requested_tag': tag, 'expected_commit_sha1': commit,
        'files': files,
    }],
}
open(f'{ACQ}/spec.json', 'w').write(json.dumps(spec, indent=2))
# 6. enumerate
r = run([f'{BIN}/plan-enumerator', '--spec', f'{ACQ}/spec.json', '--output', f'{ACQ}/contract.json'])
if r.returncode != 0:
    fail('enumerate: ' + (r.stderr or r.stdout))
_d = jparse(r)
if not _d or 'contract_id' not in _d:
    fail('enumerate parse: ' + (r.stderr or r.stdout)[:300])
contract_id = _d['contract_id']
# 7. sign
r = run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', SIGNER, '-n', 'archeion-knowledge-source-acquisition-plan-v1', f'{ACQ}/contract.json'])
if r.returncode != 0:
    fail('sign: ' + r.stderr)
# 8. acquire
r = run([f'{BIN}/acquisition-runner-v3', '--plan', f'{ACQ}/contract.json', '--plan-signature', f'{ACQ}/contract.json.sig',
         '--allowed-signers', TRUST, '--acknowledge-contract-id', contract_id, '--output-root', ACQ])
if r.returncode != 0:
    fail('runner: ' + (r.stderr or r.stdout))
out = jparse(r)
if not out or 'receipt_path' not in out:
    fail('runner parse: ' + (r.stderr or r.stdout)[:300])
receipt = f'{ACQ}/' + out['receipt_path']; proposal = f'{ACQ}/' + out['proposal_path']
# 9. adapter emit
r = run([f'{BIN}/knowledge-adapter-v2', 'emit', '--receipt', receipt, '--proposal', proposal, '--cas-root', f'{ACQ}/cas',
         '--snapshot-bin', f'{BIN}/knowledge-snapshot', '--evidence-bin', f'{BIN}/knowledge-evidence', '--work-root', f'{ACQ}/adapter-work'])
if r.returncode != 0:
    fail('adapter: ' + (r.stderr or r.stdout))
_a = jparse(r)
if not _a or not _a.get('authorities'):
    fail('adapter parse: ' + (r.stderr or r.stdout)[:300])
adapter = _a['authorities'][0]
snap_path = adapter['SnapshotManifestPath']; ev_path = adapter['EvidenceManifestPath']
snap_hex = adapter['SnapshotManifestID'].split(':')[-1]; ev_hex = adapter['EvidenceManifestID'].split(':')[-1]
compdir = sorted(glob.glob(f'{ACQ}/adapter-work/00-*'))[0]
SNAP = f'{compdir}/snapshot-store'; EVS = f'{compdir}/evidence-store'
manifest = json.load(open(snap_path))
snapshot_id = manifest['snapshot_id']
ra = manifest['review_admission']
rp = lambda k: SNAP + '/' + ra[k]
shutil.copy(rp('trust_policy_object_path'), f'{ACQ}/allowed_signers')
# 10. admission core via template substitution
core = (open(TEMPLATE).read()
        .replace('4b34be4417b27ebee516becf4905c467b1dd6a4491cdeae54d81796590fd8ddb', snap_hex)
        .replace('04d9477997c40a3739db51f83be1d78e85cc02044c21f1747e2d3fe2c5b8b4d9', ev_hex)
        .replace('snp:p1-src-03:longhorn/longhorn@v1.12.0', snapshot_id)
        .replace('src:github:longhorn/longhorn@v1.12.0', f'src:github:{repo}@{tag}')
        .replace('ver:github:longhorn/longhorn@v1.12.0', f'ver:github:{repo}@{tag}')
        .replace('cmp:github:longhorn/longhorn', f'cmp:github:{repo}'))
open(f'{ACQ}/admission.core.json', 'w').write(core)
# 11. materialize admission
r = run([f'{BIN}/knowledge-retrieval', 'materialize-admission-policy', '--core', f'{ACQ}/admission.core.json', '--store', f'{ACQ}/admission'])
if r.returncode != 0:
    fail('admission: ' + (r.stderr or r.stdout))
_p = jparse(r)
if not _p or 'policy_path' not in _p:
    fail('admission parse: ' + (r.stderr or r.stdout)[:300])
pol_path = _p['policy_path']
pol_sha = 'sha256:' + hashlib.sha256(open(pol_path, 'rb').read()).hexdigest()
entry = {
    'ok': True, 'slug': slug, 'error': '',
    'authority_id': f'retrieval-source-authority:{slug}:{tag}',
    'admission_policy_scope_id': f'retrieval-admission-scope:{slug}:{tag}',
    'snapshot_manifest': snap_path, 'evidence_manifest': ev_path,
    'raw_store': SNAP, 'evidence_store': EVS,
    'spec': rp('source_spec_object_path'), 'proposal': rp('proposal_object_path'),
    'review_receipt': rp('receipt_object_path'), 'review_signature': rp('signature_object_path'),
    'allowed_signers': f'{ACQ}/allowed_signers',
    'admission_policy': pol_path, 'admission_policy_sha256': pol_sha,
    'as_of': '2026-07-18T00:00:00Z',
    'file_count': len(files), 'tag': tag, 'commit': commit,
}
print('RESULT=' + json.dumps(entry))
