# source-acquisition-runner-v3

Generalized first-party Git-object source acquisition runner for Cluster 2.0
flywheel. Fork of `p1-src03-acquisition-runner` moving contract integrity
from **compile-time freeze** to **content-addressed, Ed25519-signed external
plan**: one runner serves every authority instead of one frozen module per
authority. Preserves fail-closed invariants verbatim: git blob SHA-1
reconstruction, non-recursive exact tree-chain walk rejecting cycles,
redirect-before-send ban, single-content-type/no-Link HTTP guards, strict
canonical JSON, private single-link fsync CAS.

## Contract

- `--plan` (signed contract document), `--plan-signature` (detached SSHSIG,
  namespace `archeion-knowledge-source-acquisition-plan-v1`), `--allowed-signers`
  all **required**; verifies signature over exact plan bytes **before** parsing
  plan. `--acknowledge-contract-id` remains second human gate for network
  execution.
- Trust root **pinned** to committed acquisition signer key
  (`knowledge/registry/trust/acquisition-allowed-signers`); callers cannot swap
  in custom `--allowed-signers` policy.
- Contract identity self-address only: `contract_id` and each `target_id`
  equal `sha256(canonical(core))`.
- Acquisition capability requires exact entry in reviewed allowlist; adding
  new transport/authority family means adding reviewed capability entry, never
  widening data plane.
- Grants no authority: receipts/inventories stay `non_authoritative`,
  `unreviewed`, compile/promote-ineligible.
- `ref_kind` selects ref resolution: absent/`tag` resolves tag ref plus
  annotated-tag chain (unchanged, byte-identical); `branch` resolves
  `/git/ref/heads/<branch>` via redirect-banned client and requires head
  commit equal `expected_commit_sha1` with empty tag chain, enabling untagged
  repo acquisition.

Author contracts with `source-acquisition-plan-enumerator`; sign with service
signer; consume snapshots/evidence/admission/build downstream (already generic).

