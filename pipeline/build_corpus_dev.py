#!/usr/bin/env python3
"""Assemble the dev-sync lineage-set from disk: one AuthorityLineageBinding per
complete acquire-<slug>/ dir. Reconstructs each entry from on-disk artifacts so it
does not depend on any workflow return. Mirrors p1-rag-01-probe/build_corpus.py but
starts fresh (no base cluster authorities) — a corpus of the owner's own repositories."""
import json, glob, hashlib, os

DEV = os.environ.get('ARCHEION_RAG_DEVSYNC_HOME', '.workingdir2/cache/dev-sync')
PROBE = os.environ.get('ARCHEION_RAG_PROBE_HOME', '.workingdir2/cache/p1-rag-01-probe')
BIN = PROBE + '/bin'
CURRENT_VERIFIER = 'sha256:c577c963fbbc43617f37f71b89a9e47138e018ea3b52015acc131d7576c59671'

def entry_from_acquire(d):
    slug = os.path.basename(d).replace('acquire-', '')
    try:
        spec = json.load(open(f'{d}/spec.json'))['targets'][0]
    except Exception:
        return None
    ver = spec['component_version']  # immutable commit sha for a branch target
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
        'admission_policy_scope_id': f'retrieval-admission-scope:{slug}:{ver}',
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

lineages, skipped = [], []
have = set()
for d in sorted(glob.glob(f'{DEV}/acquire-*')):
    e = entry_from_acquire(d)
    if e and e['authority_id'] not in have:
        lineages.append(e); have.add(e['authority_id'])
    else:
        skipped.append(os.path.basename(d))
out = {
    'output_store': f'{DEV}/retrieval-shared-dev',
    'evidence_verifier': f'{BIN}/knowledge-evidence',
    'evidence_verifier_sha256': CURRENT_VERIFIER,
    'lexical_profile': 'deterministic_raw_term_frequency@1.0.0',
    'limits': {'max_files': 100000, 'max_spans': 1000000, 'max_payload_bytes': 67108864,
               'max_total_bytes': 536870912, 'max_terms': 2000000, 'max_postings': 500000},
    'lineages': lineages,
}
open(f'{DEV}/lineage-set-dev.json', 'w').write(json.dumps(out, indent=2) + '\n')
print('authorities:', ', '.join(e['authority_id'].split(':')[-2] for e in lineages))
print('skipped(incomplete):', ', '.join(skipped) or 'none')
print('total authorities:', len(lineages))
print('lineage-set:', f'{DEV}/lineage-set-dev.json')
