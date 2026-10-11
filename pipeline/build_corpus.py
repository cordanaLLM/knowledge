#!/usr/bin/env python3
"""Assemble the full dogfood lineage-set from disk: base 3 authorities (cilium/go/kubernetes)
plus every complete acquire-<slug>/ dir, then print the lineage-set path.
Reconstructs each entry from on-disk artifacts so it does not depend on any workflow return."""
import json, glob, hashlib, os, sys

BASE = os.environ.get('ARCHEION_RAG_PROBE_HOME', '.workingdir2/cache/p1-rag-01-probe')
CURRENT_VERIFIER = 'sha256:c577c963fbbc43617f37f71b89a9e47138e018ea3b52015acc131d7576c59671'

def entry_from_acquire(d):
    slug = os.path.basename(d).replace('acquire-', '')
    try:
        spec = json.load(open(f'{d}/spec.json'))['targets'][0]
    except Exception:
        return None
    tag = spec['requested_tag']
    authority_id = spec['authority_id']
    aw = glob.glob(f'{d}/adapter-work/00-*')
    if not aw:
        return None
    aw = sorted(aw)[0]
    snap = f'{aw}/snapshot-store'
    snapf = glob.glob(f'{snap}/manifests/sha256/*/*.json')
    evf = glob.glob(f'{aw}/evidence-store/evidence-manifests/sha256/*/*.json')
    polf = glob.glob(f'{d}/admission/admission-policies/sha256/*/*.json')
    allowed = f'{d}/allowed_signers'
    if not (snapf and evf and polf and os.path.exists(allowed)):
        return None
    m = json.load(open(snapf[0]))
    ra = m['review_admission']
    polsha = 'sha256:' + hashlib.sha256(open(polf[0], 'rb').read()).hexdigest()
    return {
        'authority_id': authority_id,
        'admission_policy_scope_id': f'retrieval-admission-scope:{slug}:{tag}',
        'snapshot_manifest': snapf[0], 'evidence_manifest': evf[0],
        'raw_store': snap, 'evidence_store': f'{aw}/evidence-store',
        'spec': f'{snap}/' + ra['source_spec_object_path'],
        'proposal': f'{snap}/' + ra['proposal_object_path'],
        'review_receipt': f'{snap}/' + ra['receipt_object_path'],
        'review_signature': f'{snap}/' + ra['signature_object_path'],
        'allowed_signers': allowed,
        'admission_policy': polf[0], 'admission_policy_sha256': polsha,
        'as_of': '2026-07-18T00:00:00Z',
    }

base_ls = json.load(open(f'{BASE}/lineage-set-5auth.json'))
lineages = list(base_ls['lineages'])  # cilium/go/kubernetes/argo-cd/longhorn
have = {e['authority_id'] for e in lineages}
added, skipped = [], []
for d in sorted(glob.glob(f'{BASE}/acquire-*')):
    e = entry_from_acquire(d)
    if e and e['authority_id'] not in have:
        lineages.append(e); have.add(e['authority_id']); added.append(e['authority_id'])
    elif not e:
        skipped.append(os.path.basename(d))
out = dict(base_ls)
out['lineages'] = lineages
out['evidence_verifier_sha256'] = CURRENT_VERIFIER
out['output_store'] = f'{BASE}/retrieval-shared-full'
open(f'{BASE}/lineage-set-full.json', 'w').write(json.dumps(out, indent=2) + '\n')
print('added:', ', '.join(a.split(':')[-2] for a in added))
print('skipped(incomplete):', ', '.join(skipped) or 'none')
print('total authorities:', len(lineages))
print('lineage-set:', f'{BASE}/lineage-set-full.json')
