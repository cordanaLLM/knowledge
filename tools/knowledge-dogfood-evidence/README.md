# knowledge-dogfood-evidence

Collects retainable, schema-versioned dogfooding evidence for the knowledge
broker across all ten [roadmap](../../.workingdir2/99-roadmap.md) T1 item 8
categories: `correctness`, `citation`, `time_freshness`, `token`, `latency`,
`storage`, `energy`, `acl_deletion`, `backup`, `rollback`.

It reads signals that already exist — the broker's own MCP tools, the
Prometheus already scraped in `monitoring`, the Kubernetes API, the ArgoCD
Application and the signed artifacts tracked in Git. It adds no
instrumentation, no exporter and no agent. Where no signal exists it times the
calls itself and says so in the provenance.

## Run it

```sh
python3 tools/knowledge-dogfood-evidence/collect.py
```

Writes `.workingdir2/evidence/dogfood/<timestamp>-<mode>.md` and prints the
path. Useful flags:

| flag | effect |
| --- | --- |
| `--stdout` | print the artifact instead of writing it |
| `--local` | mark the run as a local binary, **not** dogfooding evidence |
| `--no-cluster` | record every cluster signal as unavailable (offline check) |
| `--no-repo` | record every local-repository signal as unavailable |
| `--output-dir` | alternate artifact directory |
| `--repo-root` | local clone the cited Git artifacts are read from |
| `--broker-args` | arguments for `archeion-knowledge-mcp` inside the Pod |

One run opens **one** in-Pod MCP session and drives every probe through it, so
the startup index build is paid once rather than per signal. Calls are issued
strictly sequentially — request written, response read, clock stopped — because
the SDK server answers concurrently and a pipelined batch would time the
scheduler instead of the call.

The artifact is **Markdown with an embedded canonical JSON block**, not a bare
`.json`, because `.gitignore` tracks only `*.md` under `.workingdir2/`. A JSON
artifact there would be untracked and would not be retained.

## Run target matters

`run_target.mode` records where the numbers came from, because that decides
whether the run counts as dogfooding evidence at all:

- `deployed_broker` — read in-Pod from the deployed image digest, over the same
  git-sync worktree the serving process indexes. The MCP call starts a **fresh
  process inside the running Pod**; it does not attach to the long-lived stdio
  session. Index counts are therefore a faithful rebuild of the same corpus,
  not a read of the serving process's own heap. This is the mode that counts.
- `local_binary` — a locally built binary. Recorded, but explicitly *not*
  dogfooding evidence for the deployed service.
- `unavailable` — the broker could not be reached; the reason is retained.

## Fail closed

Every value carries a provenance string naming the exact metric, API field or
command it came from. A signal that cannot be read is recorded as
`state: unavailable` with a `reason`, and its `value` is `null`.

**A missing signal is never a zero and is never an omitted field.** `validate()`
enforces this before anything is written: it rejects an unavailable signal that
carries a value, an available signal whose value is null, any signal without
provenance, any unavailable signal without a reason, a missing category and an
emptied signal set. All cluster reads funnel through `Cluster.kubectl_json`, so
a disabled or stubbed collector cannot silently reach the live apiserver, and
all local reads funnel through `Repo`.

Two further invariants exist because derived numbers are easy to fake:

- a signal listed in `DERIVED_DEPENDENCIES` may not be `available` while any
  input it was computed from is not — a staleness bound cannot outlive the
  index age it was built from;
- an `excluded_*` claim may not be `available` unless `indexed_positive_control`
  is, because "everything is forbidden" would otherwise pass trivially.

## What each category derives from

**correctness** — the signed retrieval evaluation receipt at
`knowledge/registry/acceptance/p1-src-03/retrieval/multidomain-evaluation-receipts/`,
with the detached SSHSIG re-verified offline at collection time (`ssh-keygen -Y
verify`) against `knowledge/registry/trust/evaluator-allowed-signers`. The
receipt's own `allowed_signers_sha256` must equal that tracked trust root, so a
receipt cannot bring its own trust root. Its `promotable` and
`execution_authorized` flags are recorded verbatim: this is a measured
evaluation, **not** an acceptance authorization. It measures the
`tools/knowledge-retrieval` lanes over the admitted cilium/go/kubernetes
corpus, so correctness of the **deployed broker's own lexical index over this
repository** stays unavailable — that needs a scorer-blind qrels suite whose
judged spans are paths in this repository.

**citation** — real bindings, actually exercised. Each hit from a live
`knowledge_search` is re-fetched with `knowledge_get` at the cited path and
exact line range, and every bound field is compared (`sha256`, `start_line`,
`end_line`, snippet bytes). Then, for each file small enough to read whole, the
collector recomputes SHA-256 over the reconstructed bytes **itself** — that half
is computed outside the broker, so it checks the digest claim rather than the
broker's self-consistency. Files that are not line-reconstructible (CRLF, no
trailing newline) or exceed the whole-file read bound are counted in
`skipped_reasons`, never silently dropped. Whether a citation survives a broker
restart is a two-run protocol and is recorded as unevidenced.

**time/freshness** — derived from the period the Pod actually runs with
(`--period` on the git-sync sidecar), not from any documented value. The
important part is that `buildKnowledgeIndex` runs once before the transport
starts and nothing re-indexes, so the bound on served content is **the serving
process's age plus one sync period**, not the sync period alone. Push-to-remote
time is not bounded by any signal here and the artifact says so.

**latency** — measured, because nothing else measures it: the broker registers
no metrics handler and the chart ships no ServiceMonitor, so
`server_side_latency_histogram` is unavailable and every number is
client-measured. Sample counts and p50/p90/p95 are recorded rather than a bare
mean. Timings include the `kubectl exec` stream and apiserver hop, so they are
upper bounds. The initialize round-trip is reported separately because it also
covers process start and the index build.

**ACL/deletion** — candidate paths come from the tracked tree of the ref the
broker actually serves (`git ls-tree origin/main`), which is what makes a
`forbidden` answer mean *denied* rather than *absent*. Each class is probed with
`knowledge_get`; only the path name and the typed refusal are recorded, never
any content. `indexed_positive_control` must resolve or every exclusion claim is
voided. Untracked exclusion cannot be exercised against a clean git-sync clone,
and no deletion drill has been run — both are recorded as unevidenced with what
they would need.

**rollback** — the mechanism, evidenced: the running `imageID` digest, the
digest declared in `values.yaml` at the served ref, and whether they agree (a
revert only selects the running bytes while they do), plus the ArgoCD
Application's automated/selfHeal/prune state. Whether a rollback has ever been
*exercised* is separate: a revision appearing twice in `.status.history` is the
signature of a reconciled rollback, and its absence within the retained window
is reported as absence, not as success.

**token** — the broker's own `knowledge_status`, field
`repository.index_usage.{token_occurrences,chunks,unique_terms,files_indexed}`
plus `repository.index_limits.token_occurrences` for headroom
(`tools/knowledge-mcp/service.go`, `knowledgeDescriptor`). These are indexed
lexical token occurrences, not model prompt/completion tokens — this broker
has no per-query billing signal, and the artifact says so.

**storage** — `repository.index_usage.source_bytes` for the corpus,
`process_memory.{vmrss_bytes,go_heap_inuse_bytes}` for the resident index, and
the Pod's volume kinds. `published_store_bytes` is unavailable while
`registry.state.enabled=false`, recorded with that reason rather than as `0`.

**energy** — deliberately allowed to be empty. `node_rapl_*` is absent
cluster-wide (the node-exporter rapl collector is not enabled).
`node_hwmon_energy_joule_total` does exist, but only on two home worker nodes
and only for a PCI hwmon chip — not a node total, not a pod. The broker runs on
`k8s-worker-office-3`, which has no such counter, so **no energy value is
attributable to the broker** and none is emitted. A CPU-seconds proxy scaled by
an assumed watts-per-core, or a node total divided by pod count, would not be
an energy measurement; the collector refuses to produce one even when a
node-local counter does exist, because per-process power accounting does not
run in this cluster.

**backup** — the broker's own state. It mounts no PersistentVolumeClaim
(`configMap`, `emptyDir`, `secret` only), so it is stateless by design and has
no volume data to back up: durability is the Git remote it syncs from plus the
digest-pinned Harbor image. Velero coverage is reported as the most recent
*completed* backup whose `includedNamespaces` covers `ai`, with its timestamp.
Longhorn recurring-job coverage is computed by intersecting job `spec.groups`
with the `recurring-job-group.longhorn.io/<group>=enabled` volume labels, which
surfaces groups that are targeted but empty and volumes that belong to no
targeted group — a job aimed at an empty group protects nothing.

## Verification

```sh
python3 tools/knowledge-dogfood-evidence/tests/test_fail_closed.py
```

Covers total outage, partial outage (Pod visible, broker silent), the
never-a-zero invariant, provenance enforcement, run-target labelling, every
validator rejection, and three energy-honesty cases including a counter present
on the broker's own node. Each of the ten categories has an explicit
unavailable-signal test, plus the failure each new category can actually
produce: a citation digest that does not match, a positive control that fails
and voids every exclusion claim, a leaked path recorded by name with no
content, a receipt that tries to select its own trust root, a drifted audit
reference, a derived staleness bound whose input went unavailable, and a
repeated ArgoCD revision reported as a real rollback. The suite runs offline in
milliseconds; a probe that bypasses the cluster or repository guard fails it.
Wired into `pre-commit` as `knowledge-dogfood-evidence-fail-closed`.

The collector is read-only: it performs `kubectl get`, a Prometheus instant
query through the API-server proxy, one `kubectl exec` running the broker's own
read-only MCP tools, and local `git`/`ssh-keygen -Y verify` reads. It mutates
nothing, in the cluster or in the working tree.
