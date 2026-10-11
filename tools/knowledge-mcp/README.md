# Archeion local knowledge MCP

`archeion-knowledge-mcp` is a read-only stdio MCP server for three local evidence
planes:

- the generated component/dependency registry; and
- high-signal files tracked by this Git repository; and
- the signed, evaluated current exact-source retrieval generation with span
  citations.

It is deliberately not a crawler, mutation API, or authority promotion path.
Protocol stdout contains JSON-RPC frames only; diagnostics go to stderr.

## Trust model

The preferred registry input is a signed generation store selected by an
immutable pointer and detached Ed25519 SSHSIG receipt. The reader verifies the
pointer/receipt/manifest bindings, signer fingerprint, timestamp chain, and
manifest completeness before reporting the selected generation as `ok`. It
requires a read-only operator `--allowed-signers` trust root outside the
generation store and byte-compares that independent root with the persisted
policy copy; a store can never introduce the key that authorizes itself.

A manifest supplied directly with `--registry` is useful for local review, but
is always reported as `partial`. A readable candidate is never presented as
promoted authority, even if its own completeness fields claim success.

Repository knowledge is limited to high-signal worktree files whose paths are
Git-tracked. The bytes may include uncommitted edits, so every evidence hit is
honestly labelled and hash-bound:

```text
provenance_class=git_tracked_path_worktree_snapshot
authority_class=local_worktree_evidence
content_binding=sha256_of_worktree_bytes_at_mcp_index_time
```

"High-signal" spans both the curated prose planes (`knowledge/`, `docs/`, the
planning roots under `.workingdir2/`, and any `README.md` / `AGENTS.md` /
`PRINCIPLES.md` / `STATE.md` / `CLAUDE.md`) and the operational GitOps/IaC
surface an agent must read to answer cluster questions: `apps/`, `argocd-apps/`,
`cluster/`, `terraform/`, `ansible/`, `packer/`, `engineering/`, `scripts/`,
`tools/`, `.claude/` and `.githooks/`. Those operational roots admit declarative
config (`.yaml`, `.yml`, `.json`, `.tpl`, `.tf`, `.tftpl`, `.hcl`, `.j2`,
`.toml`, `.cfg`, `.conf`, `.example`) and automation source (`.go`, `.py`,
`.sh`, `.sql`, `.js`, `.mjs`, `.ps1`) alongside prose.

Regardless of root, the index denies sealed ciphertext (`sealed-secrets/sealed/`
and any `*.sealed.yaml`), real Terraform variable files (`*.tfvars` — the
committed `*.tfvars.example` templates stay indexable), `vault.yml`, `kubeconfig`
and key material (`*.key`, `*.pem`, `*.crt`, `*.p12`, `*.pfx`, `*.jks`),
content-addressed blobs under any `sha256/` path, lockfiles and pinned
dependency closures, and `testdata/` / `vendor/` / `node_modules/` trees.

Untracked Argo directory trees are excluded. Their directory names do not prove
that bytes are official, immutable, or version-correct. They may be admitted in
a future revision only through an exact-hash provenance/snapshot manifest.
Git discovery uses the validated fixed `/usr/bin/git` executable with a hard
timeout and bounded stdout/stderr; `PATH` cannot replace it. The repository
index applies deterministic prefix caps to enumerated/examined files, aggregate
source bytes, chunks, token occurrences, unique terms and warning records.
Reaching any cap makes repository state `partial`, and `knowledge_status`
reports exact usage, limits and typed cap metadata instead of hiding omitted
coverage.

The repository index follows atomic `git-sync` generation rotation without a
broker restart. The broker resolves `--repository-root` to one immutable
worktree, records its exact Git commit when available, and polls the configured
link every `--repository-refresh-interval` (default `15s`). An unchanged target
does not rebuild. When a new target appears, one candidate is built while all
tools continue serving the prior complete index. The link and commit are
checked again after the build; only that fully built candidate can swap in, and
the swap waits for in-flight readers. A failed or superseded candidate is
discarded, leaving the prior generation available. The serialized builder plus
reader/writer boundary limits live index generations to the serving index and
one candidate.

`knowledge_status` reports `indexed_commit`, `indexed_at`, `index_age_ms` and
the resolved serving root separately from the refresh observation. Its
`refresh` object exposes `observed_commit`, `observed_resolved_root`,
`source_current`, `build_in_progress`, check/success/error times, and the last
bounded refresh error. Therefore a caller can distinguish “fresh and current,”
“new commit observed and rebuilding,” and “old complete index retained after a
refresh failure.” A non-rotating worktree with uncommitted byte changes still
requires a commit/target change or process restart; Git-tracked membership
alone does not turn mutable working-tree bytes into a generation signal.
Each `knowledge_search`, `knowledge_get`, and `knowledge_context` response also
includes a compact `repository_generation` binding with its serving commit,
index time and current/stale observation state.

All tool results carry a hostile-content envelope declaring returned strings
to be `untrusted_data_only`, non-executable, and forbidden as instructions.
Source text is evidence data even when it contains prompt injection or claims
to be a system/tool instruction.

Exact-source serving is a separate fail-closed boundary. `evidence_search`
executes a hash-pinned, non-writable `knowledge-retrieval` binary through its
`current-query` command for either one lane or each lane in an externally
hash-pinned federation catalog. Every lane keeps its own retrieval CAS, signed
generation-state root, normalized evidence CAS and exact admission-policy
document/hash. There is no candidate, generation, pointer or lane selector.
Each subprocess verifies its signed current pointer and transition chain,
proves that its running binary is the one evaluated by that lane's selected
generation, checks the pointer again after retrieval, and returns no evidence
if any part of that contract fails. MCP independently verifies every response
shape, evaluated-current lineage, trust envelope and exact citation coordinate.
Federation happens only after those checks and never creates shared authority.
MCP opens and hashes the immutable retrieval executable once, executes that
exact inode through a preserved `/proc/self/fd` descriptor, then revalidates the
descriptor and configured path. A transient path replacement therefore cannot
substitute different executable bytes between validation and `exec`.

## Compact candidate projection

The large discovery JSON can be compiled once into deterministic SQLite plus a
canonical read-only receipt. The receipt binds the source manifest ID,
canonical manifest hash, raw source-file SHA-256/size, candidate state,
projection SHA-256/size, schema and exact table counts. Runtime opens the file
with SQLite `mode=ro&immutable=1`, forces query-only mode, verifies hashes before
and after open, checks exact versioned table/index SQL (including types,
nullability, keys, checks, foreign keys, collations and index column order),
counts and `quick_check`, then performs indexed queries without rebuilding the
full Go object graph. Component search has an exact SQL total plus a bounded
row scan; relationship pagination is applied in SQL. Both paths enforce
per-cell text/JSON and aggregate row budgets and expose explicit truncation
metadata.

Compilation builds the database and receipt in a private temporary workspace,
then copies each into read-only `O_EXCL` stages beneath one opened parent
`os.Root`. Publication uses hard links only, never overwrites an existing name,
fsyncs both files and the opened directory, and revalidates every ancestor plus
the pinned parent identity immediately around each link. A parent replacement
or child symlink fails closed with inode-checked rollback and cannot redirect
bytes outside the originally opened directory.

The compact projection is always `candidate_partial`. It cannot become a signed
current generation or upgrade authority. Signed generation-store mode retains
its existing strict JSON verification path until a separately reviewed signed
projection selection contract exists.

The manifest compiler consumes the authoritative discovery-manifest v2
envelope, including `authority_boundary`, producer `bounds`, optional
`observation`/`merge_lineage`, the six-field `counts` object and
`completeness.all_axes_complete`. Retired top-level official-resolution fields
are rejected. The versioned `archeion-registry-sqlite-v1` metadata retains one
zero-valued `official_resolution_runs` compatibility counter so the deployed
0.6.0 reader can open newly compiled projections; current readers strip that
projection-only field before exposing manifest counts. It never changes the
source candidate, its hash or its six-field schema.

## Tools

| Tool | Purpose |
|---|---|
| `registry_status` | Selected generation, trust mode, completeness, bounded gap counts, repository coverage, and process memory |
| `knowledge_status` | Stable broker-contract alias for `registry_status` |
| `registry_search_components` | Deterministic component/PURL/name search |
| `dependency_lookup` | Stable broker-contract alias for component/dependency lookup |
| `dependency_changes` | Bounded selected-generation reconciliation delta against its base manifest |
| `registry_get_component` | Exact identity and bounded version summary |
| `registry_relationships` | Paginated dependencies and reverse dependents |
| `registry_official_channels` | Reviewed official channels; accepted-only requires accepted + available + canonical URI |
| `registry_evidence` | Paginated gaps, occurrences, sources, or versions |
| `knowledge_search` | Ranked Git-tracked-path worktree evidence with line/hash coordinates |
| `knowledge_get` | Bounded exact evidence span |
| `knowledge_context` | Compact, source-preserving evidence context |
| `evidence_search` | Single-lane or federated signed-current exact-source search with independent lineage and immutable span citations |

`evidence_search` always evaluates freshness against the broker's current UTC
clock. It does not accept a caller-provided historical `as_of`; reproducible
historical audits remain a lower-level `knowledge-retrieval query` operation.
Its MCP `state` preserves the retrieval result as `ok`, `empty`, `stale`,
`forbidden` or `backend_unavailable`; federation can additionally return a
non-error `partial` result when at least one independently verified lane can
serve and another lane cannot. Single-lane `retrieval_state=current` and
`authority_state=evaluated_current` retain the upstream authority contract.
Successful results include pointer ID/revision, transition receipt, current
generation ID/document hash, generation time, quality report, frozen
evaluation suite, evaluation metrics and the lexical candidate ID selected by
that generation. Missing or changing current state never falls back to a
partial candidate.

Federated mode accepts at most eight strictly sorted, uniquely named lanes and
requires a distinct signed-state root for each lane. MCP reads each exact
whole-document-pinned admission policy and derives the cryptographically bound
`source_id`; source identities must be unique, every returned hit must match
its lane's source, and two lanes may not select the same signed generation. It
queries at most four lanes concurrently with a fixed twenty-second per-lane
deadline, applies the caller's bounded result limit independently to each lane,
and fuses only verified `ok`
results with integer `bounded_borda_v1` rank scores. An identical global
evidence-span citation is deduplicated and never gains additive score; exact
cross-source corroboration belongs at the claim/evidence layer, not rank fusion.
A repeated span ID with conflicting citation or excerpt bytes fails the whole
request closed without claiming current or serving federation authority.
Ties use lane ID, source ID and span ID, so scheduling cannot change output.
Every result retains exact evidence coordinates and every lane descriptor
retains that lane's pointer, generation, quality/evaluation and policy/binary
pins.

The deadline is not caller-selectable. The maximum eight-lane catalog drains
through four workers in at most two child-process waves: `2 * 20s = 40s` of
bounded child execution. That leaves twenty seconds inside the required
60-second MCP tool budget for the separately bounded catalog, policy,
executable, response-validation and serialization work.

The default transport is a hand-rolled single-line JSON-RPC loop. Its
`notifications/cancelled` frame cannot be read while a `tools/call` blocks on
the retrieval child, so it has no caller context to thread and passes an
explicit `context.Background()`; there the fixed per-lane deadline remains the
only bound. The `--mcp-sdk` transport (see below) reads and cancels
concurrently at the handler boundary, and that handler context is now threaded
through `service.call` -> `retrieval.search` into the child: the child is
bounded by `min(caller deadline, lane timeout)`. A caller cancellation SIGKILLs
the child's whole process group and `Run` reaps it before returning; the lane
timeout still fires on its own when the caller sets no deadline. Every aborted
call stays a typed `backend_unavailable` failure carrying no evidence, and
cancellation, caller-deadline and lane-timeout aborts are reported distinctly
rather than all being labelled a timeout.

All input strings, pagination values, file sizes, protocol frames, and output
sizes are bounded. Registry results retain typed states such as `empty`,
`not_found`, and `no_official_channel`. In direct-candidate mode the top-level
state is `partial` and `result_state` preserves the query result; this prevents a
candidate from silently becoming authority while keeping it usable for review.

### Absence and degradation are typed, never a successful empty

A degraded, absent or unverified state stays typed and is never confusable with
a successful empty result. Three distinct states carry absence, and only one of
them is an authoritative answer:

| State | Meaning | Authoritative? |
| --- | --- | --- |
| `empty` | A verified backend genuinely holds no match | Yes |
| `not_configured` | No registry backend is wired, so emptiness cannot be asserted | No — fails closed |
| `no_verified_state` | A generation store is wired but holds no signed current pointer | No — fails closed |

Degradation is typed the same way. A zero-hit `knowledge_search` or
`knowledge_context` over a `partial` index returns `state: partial` with
`result_state: empty`, `degraded_reason` and `index_caps`, because matching
evidence may have been skipped by a file-read failure or a resource cap. A
zero-hit search over a complete index still returns `empty`; a genuine no-match
never becomes an error.

The `registry_status` and `knowledge_status` tools report `not_configured` and
`no_verified_state` as their own typed state without `isError`, since reporting
that state is exactly what a status query asks for. Every registry *content*
tool fails closed with `isError` on those two states, because it cannot answer.

A verified signed-store snapshot is cached, but the cache is keyed on the exact
verified artifact set — pointer alias, immutable pointer, transition receipt,
persisted allowed-signers copy, prior pointer, trust root and both selected
manifests. Every read re-hashes that set, so a replaced, tampered or removed
artifact stops the broker reporting `state: ok` and `signed_selection_verified:
true` even when the mutable alias and trust-root hashes are unchanged. Because
the verdict is a deterministic function of those exact bytes, an unchanged set
implies an unchanged verification result: the re-check is as strong as a full
re-verification and only skips recomputing the decode, admission and SSHSIG work.

Manifest admission runs before canonical hashing and index construction for a
direct candidate and for both current/previous manifests selected by a signed
pointer. The fixed structural ceilings are 100,000 components/sources, 200,000
versions/gaps, 500,000 occurrences/edges, 64 official channels per component,
64 KiB per decoded string/number token, 8 KiB per tool-exposed record, 1 MiB per
full record, 4 MiB per generic top-level object, 64 MiB/100,000 entries for the
reconciliation delta, depth 32, and exact seven-field `counts` plus exact
seven-field reconciliation shapes. Status returns at most 256 of at most 1,024
unique 128-byte gap types with an exact total/truncation flag. Relationship
evidence IDs are sampled at eight with exact count/truncation metadata. Direct
component search scans for an exact match count but retains only its requested
top-k (maximum 50), and direct relationship/change pagination walks pre-sorted
segments without materializing or sorting the entire result set.

## Build and run

```bash
go -C tools/knowledge-mcp build -trimpath -o /tmp/archeion-knowledge-mcp .
```

Direct candidate review:

```bash
/tmp/archeion-knowledge-mcp \
  --repository-root /path/to/repository \
  --registry /absolute/path/to/candidate-mft-<sha256>.json
```

Compile and use the compact candidate projection (the destination parent must
already exist and contain no symlink components):

```bash
/tmp/archeion-knowledge-mcp \
  --compile-projection /absolute/path/to/candidate-mft-<sha256>.json \
  --projection-output /absolute/path/to/projection-mft-<sha256>.sqlite

/tmp/archeion-knowledge-mcp \
  --repository-root /path/to/repository \
  --projection /absolute/path/to/projection-mft-<sha256>.sqlite
```

Preferred signed generation store:

```bash
/tmp/archeion-knowledge-mcp \
  --repository-root /path/to/repository \
  --state-dir /absolute/path/to/generation-store \
  --allowed-signers /operator-trust/knowledge-registry.allowed_signers
```

Signed-current exact-source retrieval can be combined with any of those
registry modes:

```bash
/tmp/archeion-knowledge-mcp \
  --repository-root /path/to/repository \
  --projection /absolute/path/to/registry-projection.sqlite \
  --retrieval-executable /immutable/knowledge-retrieval-<sha256> \
  --retrieval-executable-sha256 <64-lowercase-hex> \
  --retrieval-store /absolute/path/to/retrieval-generation-cas \
  --retrieval-state /absolute/path/to/signed-generation-state \
  --retrieval-evidence-store /absolute/path/to/normalized-evidence-cas \
  --retrieval-admission-policy /absolute/path/to/current-admission-policy.json \
  --retrieval-admission-policy-sha256 <64-lowercase-hex>
```

All seven retrieval values are required together. The legacy
`--retrieval-candidate` and `--retrieval-candidate-sha256` selectors are not
accepted; their environment equivalents are rejected explicitly. A missing,
invalid or racing signed current pointer yields `backend_unavailable` with an
empty result set.

As an alternative to those seven single-lane values, configure exactly one
immutable catalog and its external whole-document pin:

```bash
/tmp/archeion-knowledge-mcp \
  --repository-root /path/to/repository \
  --projection /absolute/path/to/registry-projection.sqlite \
  --retrieval-catalog /immutable/retrieval-federation-catalog.json \
  --retrieval-catalog-sha256 <64-lowercase-hex>
```

The catalog and single-lane flags are mutually exclusive. The catalog is a
non-writable, non-symlink regular JSON file with this strict shape;
unknown fields, unsorted/duplicate lane IDs, shared state roots, duplicated
policy-bound source identities, non-canonical paths, invalid pins and more than
eight lanes are rejected:

```json
{"schema_version":"1.0.0","record_kind":"retrieval_federation_catalog","lanes":[{"lane_id":"argocd","retrieval_executable":"/immutable/knowledge-retrieval-<sha256>","retrieval_executable_sha256":"<64-lowercase-hex>","retrieval_store":"/retrieval/argocd/store","retrieval_state":"/retrieval/argocd/state","retrieval_evidence_store":"/retrieval/argocd/evidence","retrieval_admission_policy":"/retrieval/argocd/admission.json","retrieval_admission_policy_sha256":"<64-lowercase-hex>"}]}
```

The generation store reader expects:

```text
generation-pointer.json
manifests/mft-<sha256>.json
pointers/ptr-<sha256>.json
receipts/prc-<sha256>.json
policies/<policy-sha256>.allowed_signers
```

`--registry`, `--projection` and `--state-dir` are mutually exclusive. Signed
store mode fails closed unless `--allowed-signers` names a non-symlink,
read-only regular file outside the store. The
default object ceiling is 512 MiB and may be changed within the enforced
1 MiB–1 GiB range via `--max-registry-bytes`.

Signed-store mode shells out to a fixed `/usr/bin/ssh-keygen` to verify each
transition receipt's SSHSIG, so that binary must exist in any image that serves
a generation store.

## Publishing a generation store into the cluster (`--publish-pack` / `--publish-materialize`)

The same binary packs and places publication bundles, using its own verification
code rather than a reimplementation, so the publisher and the broker cannot
disagree about what is trustworthy. Publish modes never serve and are mutually
exclusive with every serving input.

Pack on the workstation — this refuses to emit anything unless the store passes
full signature and content-address verification first:

```bash
archeion-knowledge-mcp \
  --publish-pack   /absolute/path/to/generation-store \
  --publish-output /absolute/path/to/bundle.tar \
  --allowed-signers /operator-trust/knowledge-registry.allowed_signers
# optional: --publish-retrieval /absolute/path/to/retrieval-tree
```

The receipt on stdout carries `bundle_sha256`. The tar is deterministic (entries
sorted, timestamps and ownership zeroed, fixed modes), so identical store
contents always yield the same pin.

Place it in the cluster, normally as an initContainer:

```bash
archeion-knowledge-mcp \
  --publish-materialize https://object-store/knowledge/bundle.tar \
  --publish-sha256 <64-lowercase-hex> \
  --publish-target /var/lib/knowledge-mcp \
  --publish-trust-source /etc/knowledge-mcp/allowed-signers/allowed_signers
```

`--publish-materialize` accepts a local path or an `http(s)` URL. The transport
is deliberately untrusted; integrity comes from three independent layers:

1. the operator's whole-bundle SHA-256 pin, checked before a byte is extracted;
2. per-entry SHA-256 digests in the bundle's own `bundle.json`, which must
   describe exactly the set of entries present — no extras, no omissions;
3. the broker's signed-store verifier, re-run against the staged tree with the
   trust root supplied by `--publish-trust-source`.

The target receives `state/` (the reader layout), `trust/` (the allowed-signers
root, deliberately outside the store), optional `retrieval/`, and a
`publish-status.json`. Bundle paths are restricted to `state/` and `retrieval/`;
a bundle that tries to ship its own `trust/` directory is rejected, so a store
can never supply the key that authorises it.

Everything is built under a staging directory and moved into place only after
verification passes. On failure the trees are removed, the reason is recorded in
`publish-status.json` and the process exits 0 — leaving the broker to report
typed `backend_unavailable`/degraded rather than serving unverified evidence.
`--publish-strict` turns that into a non-zero exit for deliberate debugging.

## Official MCP Go SDK stdio transport (`--mcp-sdk`)

The binary built from current sources can serve the identical read-only tool surface over the
official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) stdio
transport, pinned at `github.com/modelcontextprotocol/go-sdk v1.7.0` (current
stable at 2026-07-28). The SDK negotiates MCP `2026-07-28` on transports that
support it and retains backward compatibility with `2025-11-25` and earlier
endpoints.

The pinned local broker binary `sha256:4cdae7f913ce99fdddad697495bfe66b308bd5a1af9868da6e720df71a6f4150`
does not support the `--mcp-sdk` flag (running it with `--mcp-sdk` yields `flag provided but not defined`).
The CURRENT in-cluster broker image (`registry.example.com/library/knowledge-mcp`, digest `sha256:b0189473ee610cda5e91c4dda80990baa071e2af63608aa0afee47cb6fd680f0`)
does support it and is reached via:

```bash
kubectl exec -i -n ai deploy/knowledge-mcp -c knowledge-mcp -- archeion-knowledge-mcp --mcp-sdk --repository-root /repo/current
```

Add `--mcp-sdk` to any of the serving invocations above when using a supported binary:

```bash
/tmp/archeion-knowledge-mcp --mcp-sdk \
  --repository-root /path/to/repository \
  --projection /absolute/path/to/registry-projection.sqlite \
  --retrieval-catalog /immutable/retrieval-federation-catalog.json \
  --retrieval-catalog-sha256 <64-lowercase-hex>
```

The adapter reuses the broker's tool implementations verbatim: it registers
every tool from the service definition set with a low-level SDK handler that
performs no independent input/output validation, so the broker's own
decode/bounds/typed-state/hostile-content-envelope contract stays the single
authority. `initialize` reports the same `serverInfo` identity and untrusted-
data instructions; `tools/list` returns the same 13 tools; `tools/call`
returns the same `structuredContent`, text mirror, typed `state` and `isError`
under the same `maxToolResultBytes` bound. The maintained SDK owns spec-
conformant framing, protocol-version negotiation and concurrent request
dispatch, replacing the bespoke single-line JSON-RPC loop for real MCP clients
(Codex, Claude Code, VS Code). `--mcp-sdk` cannot be combined with
`--compile-projection`. The SDK handler context is threaded into the retrieval
child, so a client cancellation over this transport reclaims the
`evidence_search` subprocess instead of waiting out the per-lane deadline.

## Authenticated Streamable HTTP transport (`--http-bind`)

Serves the same tool surface over the same pinned SDK's
`mcp.NewStreamableHTTPHandler`, so in-cluster agents can reach the broker over
the network. **Off by default** — stdio remains the default transport and is
unchanged. `--http-bind` and `--mcp-sdk` select different transports and cannot
be combined; neither can `--http-bind` and `--compile-projection`.

```bash
archeion-knowledge-mcp \
  --http-bind 0.0.0.0:8080 \
  --http-token-file /etc/knowledge-mcp/http-token/token \
  --repository-root /repo/current
```

Authentication is a bearer token, enforced by the SDK's own
`auth.RequireBearerToken` middleware wrapping the MCP handler:

- Unauthenticated or wrong-token requests get **401 before any handler runs**,
  so no tool ever observes them and no MCP session is created.
- The token is compared in constant time over fixed-width SHA-256 digests, so
  neither the value nor its length leaks through timing.
- `--http-token-file` takes a **path**; the token value is read from that file
  (a mounted Secret in the cluster). It is never a flag value and never an env
  var — setting `ARCHEION_KNOWLEDGE_HTTP_TOKEN` is rejected at startup.
- **No token, no listener.** An absent, empty, whitespace-only, directory or
  under-32-byte token file makes the server fail to start rather than serve
  open. `--http-bind` without `--http-token-file` is a configuration error.

The HTTP transport uses the SDK's **stateless** mode. The broker exposes only
read-only request/response tools and never sends server-to-client requests or
out-of-band notifications, so retaining transport session state adds no usable
capability. Stateless mode neither issues nor reads `Mcp-Session-Id`: after an
idle gap, broker restart, reschedule or expired prior session, Codex, LiteLLM
and Paperclip can continue even if they send a cached ID instead of receiving a
permanent `404 session not found`. Each request gets a temporary SDK session
that closes with the response, so abandoned clients accumulate no server-side
sessions. The handler explicitly enables request-cancellation propagation, so
an abandoned HTTP call cancels the tool context and reclaims any retrieval
process group. The tradeoff is explicit: standalone `GET` SSE streams and
server-to-client requests are unsupported; adding either requires a separate
reviewed stateful transport design with reconnect acceptance tests. Normal
streamed POST responses remain supported. `ReadHeaderTimeout` bounds slow-header
requests while leaving read/write timeouts unset for streamed responses.

The fail-closed contract crosses the transport intact: a degraded backend
returns the same typed state and `isError` over HTTP as over stdio, never a
200-with-empty-body that a caller could read as empty-success.

Deliberately cluster-internal: the chart exposes this on a ClusterIP `Service`
with no `HTTPRoute` and no Gateway hostname. See
`apps/ai/knowledge-mcp/README.md` "Streamable HTTP transport".

Any source change here — including this adapter — requires rebuilding and
pushing the container image from the home workstation and bumping the digest in
`apps/ai/knowledge-mcp/values.yaml`; see that chart's README for the runbook.

## Codex project configuration

Codex reaches the canonical in-cluster broker through the scoped
`cordana-knowledge-mcp-bridge` command and LiteLLM's native MCP gateway. The
stdio bridge reads the mode-`0400`/`0600` scoped token file itself and connects
only to the exact TLS gateway endpoint. The token value is never placed in
Codex TOML, a process argument or a process environment.

Build the bridge from this module and install it atomically:

```bash
mkdir -p "$HOME/.local/libexec"
go -C tools/knowledge-mcp build -trimpath -buildvcs=false \
  -ldflags "-X main.remoteEndpointHost=gateway.example.com" \
  -o "$HOME/.local/libexec/cordana-knowledge-mcp-bridge.new" \
  ./cmd/cordana-knowledge-mcp-bridge
chmod 0755 "$HOME/.local/libexec/cordana-knowledge-mcp-bridge.new"
mv -f \
  "$HOME/.local/libexec/cordana-knowledge-mcp-bridge.new" \
  "$HOME/.local/libexec/cordana-knowledge-mcp-bridge"
```

The `-X main.remoteEndpointHost=` value is the host of your own gateway: the
bridge sends the credential to that host and to a loopback endpoint only, and
the host is fixed when the bridge is built.

Keep the explicit tool list. A project
configuration change takes effect after Codex reloads the workspace session.

```toml
[mcp_servers.cordana-knowledge]
command = "/absolute/path/to/cordana-knowledge-mcp-bridge"
args = [
  "--endpoint", "https://gateway.example.com/knowledge/mcp",
  "--token-file", "/absolute/path/to/agent-token",
]
enabled = true
required = true
startup_timeout_sec = 20
tool_timeout_sec = 120
default_tools_approval_mode = "approve"
enabled_tools = [
  "registry_status",
  "knowledge_status",
  "registry_search_components",
  "dependency_lookup",
  "dependency_changes",
  "registry_get_component",
  "registry_relationships",
  "registry_official_channels",
  "registry_evidence",
  "knowledge_search",
  "knowledge_get",
  "knowledge_context",
  "evidence_search",
]
```

At startup the bridge verifies that all 13 required tools exist upstream and
still carry read-only, non-destructive annotations. Unallowlisted upstream
tools are never registered locally. It rejects redirects and any endpoint
other than the exact LiteLLM TLS endpoint or literal IPv4-loopback recovery
endpoint, normalizes only LiteLLM's exact `knowledge-` tool prefix, reloads the
protected credential for each HTTP request, and propagates request cancellation
to the canonical MCP session. Protocol version, client identity and capability
metadata are hop-scoped and regenerated by the upstream session rather than
copied from the local client, so a local `2026-07-28` session can safely bridge
to a stateful upstream negotiated at `2025-11-25`. Do not replace it with an
authentication-free proxy or `go run`.

Installation, migration from the retired environment-import draft and live
smoke tests are documented in `tools/codex-mcp-tunnel/README.md`.

## Verification

```bash
GOTMPDIR=/durable/tmp GOCACHE=/durable/go-cache \
  go -C tools/knowledge-mcp test -count=1 ./...
GOTMPDIR=/durable/tmp GOCACHE=/durable/go-cache \
  go -C tools/knowledge-mcp test -count=1 -race ./...
GOTMPDIR=/durable/tmp GOCACHE=/durable/go-cache \
  go -C tools/knowledge-mcp vet ./...
CGO_ENABLED=0 GOTMPDIR=/durable/tmp GOCACHE=/durable/go-cache \
  go -C tools/knowledge-mcp build -trimpath -buildvcs=false \
  -ldflags='-buildid=' -o /tmp/archeion-knowledge-mcp .
CGO_ENABLED=0 GOTMPDIR=/durable/tmp GOCACHE=/durable/go-cache \
  go -C tools/knowledge-mcp build -trimpath -buildvcs=false \
  -ldflags='-buildid= -X main.remoteEndpointHost=gateway.example.com' \
  -o /tmp/cordana-knowledge-mcp-bridge \
  ./cmd/cordana-knowledge-mcp-bridge
```

The tests cover candidate partial signalling, deterministic projection bytes,
receipt tamper/mode/symlink rejection, mutated table/index DDL, SQL-bounded
large-match queries, JSON cell/row budgets, fixed-Git PATH poisoning and output
bounds, deterministic aggregate repository caps, tracked/untracked admission,
prompt-injection-as-data classification, JSON-only protocol framing, tool
aliases, canonical hash parity, signed generation selection, and forged SSH
signature rejection. Adversarial cases also cover oversized nested strings and
numeric tokens before hashing, unknown count/reconciliation fields, exact-count
bounded top-k search, relationship segment paging/evidence sampling, bounded
change pagination, and exact-total gap-type sampling in JSON and SQLite modes.
Projection publication tests additionally cover symlinked parent/ancestor and
projection/receipt child paths, mid-commit parent replacement, immutable-name
collisions, zero external writes, and byte-identical database and receipt
rebuilds. Signed-current retrieval tests require the exact `current-query`
subcommand and state root, reject candidate-era responses/configuration and
caller-supplied `as_of`, preserve typed result states, fail closed on a missing
pointer, validate pointer/generation/evaluation lineage and independently
validate exact citation identities, hashes, paths, time, coordinates and trust
envelopes. Federation tests additionally cover strict external catalog pins,
configuration exclusivity, independent state roots and lineages, deterministic
fusion, typed partial/all-unavailable states, source/generation alias rejection,
non-additive exact-span deduplication, conflicting-span fail-closed metadata,
descriptor-bound executable execution and catalog tamper. The stdio protocol
replay exercises the same successful current response rather than only the
provider helper.

The current 2026-07-16 v0.4.1 federation binary is 11,647,859 bytes, mode
`0555`, with SHA-256
`4cdae7f913ce99fdddad697495bfe66b308bd5a1af9868da6e720df71a6f4150`.
Normal, race and vet suites, focused shuffled runs and full shuffled runs
passed; two independent builds using Go
`go1.26.5-X:nodwarf5 linux/amd64`, `CGO_ENABLED=0`, `-trimpath`,
`-buildvcs=false` and an empty Go build ID were byte-identical. The immutable
artifact is
`.workingdir2/cache/knowledge-mcp/archeion-knowledge-mcp-4cdae7f913ce99fdddad697495bfe66b308bd5a1af9868da6e720df71a6f4150`.
The 1,054-byte mode-`0444` catalog has SHA-256
`72bbfd1bc447bc9968b808784eabfb1f667e767cc0931daf1c582cc59c22b499`.
Real stdio initialize and 13-tool discovery passed; a signed-current search
returned `federated_current`, one of one current lanes, exact citations and no
degraded lane in about 13.2 seconds. A caller-supplied timeout override was
rejected. The prior v0.3.1 binary remains an immutable single-lane config
rollback, not a candidate-selection fallback.

## Frozen P1-MCP-01 acceptance suite (`cmd/mcp01-acceptance`)

`testdata/mcp01-acceptance/suite-freeze.json` freezes the P1-MCP-01
acceptance-case suite: ten case classes —
success, stale, one-lane timeout, tamper, conflict, ACL, deletion, pagination,
reconnect and deterministic-order — with every fixture SHA-256-pinned and a
declared normalization contract for byte-reproducible transcripts. The
`cmd/mcp01-acceptance` runner exercises the live-shaped broker contract over
the real stdio JSON-RPC protocol (hermetic mode, spawning a locally built
broker plus a loopback authenticated Streamable HTTP listener) or over the
in-cluster HTTP endpoint (`--endpoint`/`--token-file`, acceptance execution).
Every case re-verifies the fixture pins first and fails closed on one mutated
byte; all cases except the deliberate 20-second one-lane-timeout ride are
double-run and must produce byte-identical transcripts. The ACL and deletion
cases encode the broker's actual authorization semantics (admission-policy
`retrieval_allowed`/`access_scope` gating before any lane metadata disclosure,
typed `forbidden`, HTTP 401 before any handler) and deletion semantics
(`deletion_state`, `tombstone`, `source_state` each individually failing the
lane closed at admission-policy load). See
`testdata/mcp01-acceptance/README.md` for invocation, and
`TestHermeticSuiteIsGreenAndDeterministic` for the CI-integrated full run.

## Admission-policy freshness is a recurring obligation

The lane's admission policy carries a ~24 h `fresh_until`. Once `as_of` passes
it, `loadCurrentAdmissionPolicy` fails `current-policy-invalid` and every tool
returns `backend_unavailable` — the lane stops serving with no config change.
A fresh policy alone does not restore it: `generationMatchesPolicy` binds the
promoted generation to the exact `AdmissionPolicyID` and document SHA-256, so
renewal means re-running the whole chain (materialize policy -> `build` ->
dense -> `hybridize` -> query signals -> suite -> `evaluate` -> signed quality
receipt -> `stage-generation` -> signed promotion) and repinning the catalog.
See [`p1-argocd-lane-policy-renewal-2026-07-19`](../../.workingdir2/cluster-2/audits/p1-argocd-lane-policy-renewal-2026-07-19.md)
for the executed procedure and the cadence decision this forces.

The activation template uses the current 108,343,296-byte mode-`0444` registry
projection `mft-dc06ed1c...`, whose SHA-256 is
`9811b52020f7e77f41b77e5aecb621a57b9c90f2f7c5be61b6088b80cd1bb23e`.
Its receipt retains honest `candidate_partial` registry authority and exact
counts for 11,236 components, 150,747 occurrences and 38,694 relationships;
this does not weaken or upgrade the separate signed-current retrieval plane.

The v0.2.1 candidate-selecting retrieval configuration is retired and is not a
fallback for v0.4.1. Adding a lane still requires an independently promoted
signed current pointer whose generation evaluates that lane's exact configured
retrieval executable.
