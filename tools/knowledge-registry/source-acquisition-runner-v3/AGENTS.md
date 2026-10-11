# source-acquisition-runner-v3

Generalized first-party Git-object source acquisition runner for the Cluster 2.0
flywheel. A fork of `p1-src03-acquisition-runner` that moves contract integrity
from **compile-time freeze** to a **content-addressed, Ed25519-signed external
plan**, so one runner serves every authority instead of one frozen module per
authority. Every fail-closed invariant is preserved verbatim: git blob SHA-1
reconstruction, non-recursive exact tree-chain walk with cycle rejection,
redirect-before-send ban, single-content-type/no-Link HTTP guards, strict
canonical JSON, and the private single-link fsync CAS.

## Contract

- `--plan` (the signed contract document), `--plan-signature` (detached SSHSIG,
  namespace `archeion-knowledge-source-acquisition-plan-v1`) and `--allowed-signers`
  are all **required**; the signature is verified over the exact plan bytes
  **before** the plan is parsed. `--acknowledge-contract-id` remains a second
  human gate for network execution.
- The trust root is **pinned** to the committed acquisition signer key
  (`knowledge/registry/trust/acquisition-allowed-signers`) — a caller cannot swap
  in their own `--allowed-signers` policy.
- Contract identity is self-address only: `contract_id` and each `target_id`
  must equal `sha256(canonical(core))`.
- Acquisition capability must be an exact entry in the reviewed allowlist; adding
  a new transport/authority family = adding a reviewed capability entry, never
  widening the data plane.
- Grants no authority: receipts/inventories stay `non_authoritative`,
  `unreviewed`, compile/promote-ineligible.
- `ref_kind` selects ref resolution: absent/`tag` resolves the tag ref +
  annotated-tag chain (unchanged, byte-identical); `branch` resolves
  `/git/ref/heads/<branch>` through the same redirect-banned client and requires
  the head commit == `expected_commit_sha1` with an empty tag chain, so untagged
  repos can be acquired.

Author contracts with `source-acquisition-plan-enumerator`; sign with the service
signer; consume snapshots/evidence/admission/build downstream (already generic).
