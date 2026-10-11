#!/usr/bin/env python3
"""Collect retainable dogfooding evidence for the knowledge broker.

Covers the ten T1 item 8 categories. Every emitted number carries a provenance
string naming the exact metric, command or API field it came from. A signal
that cannot be read is recorded as unavailable with a reason -- never as zero
and never omitted. A category that cannot be honestly evidenced with signals
that exist stays empty rather than acquiring a proxy.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = "1.1.0"
ARTIFACT_KIND = "knowledge_dogfood_evidence"
COLLECTOR_VERSION = "knowledge-dogfood-evidence@1.1.0"
CATEGORIES = (
    "correctness",
    "citation",
    "time_freshness",
    "token",
    "latency",
    "storage",
    "energy",
    "acl_deletion",
    "backup",
    "rollback",
)

BROKER_NAMESPACE = "ai"
BROKER_SELECTOR = "app.kubernetes.io/name=knowledge-mcp"
BROKER_CONTAINER = "knowledge-mcp"
GIT_SYNC_CONTAINER = "git-sync"
BROKER_APPLICATION = "knowledge-mcp"
BROKER_CHART_VALUES = "apps/ai/knowledge-mcp/values.yaml"
SERVED_REF = "origin/main"
# The in-Pod call rebuilds the index before answering; measured ~10s for this repo.
BROKER_CALL_TIMEOUT = 600
PROM_PROXY = (
    "/api/v1/namespaces/monitoring/services"
    "/kube-prometheus-stack-prometheus:9090/proxy/api/v1"
)

# Candidate power/energy series, in preference order. All are probed and all
# outcomes are recorded; none is ever rewritten into an attributed number.
ENERGY_CANDIDATES = (
    (
        "node_rapl_package_joules_total",
        "node-exporter rapl collector, per CPU package",
    ),
    (
        "node_hwmon_energy_joule_total",
        "node-exporter hwmon collector, per sensor chip",
    ),
)

# Real GitOps queries, in the shape of the Argo/Kubernetes/package work the
# roadmap item asks the broker to be dogfooded on. Each runs LATENCY_REPEATS
# times so the sample count is honest rather than a single lucky call.
LATENCY_QUERIES = (
    "argocd application sync policy selfHeal prune",
    "cilium gateway api https listener hostname",
    "cnpg postgres cluster scheduled backup",
    "kyverno policy require container resource limits",
    "longhorn recurring job group snapshot",
    "sealed secrets controller certificate rotation",
    "velero backup schedule included namespaces",
    "helm chart pinned image digest",
)
LATENCY_REPEATS = 2
# Percentiles reported for every timed call set. Averages hide the tail.
LATENCY_PERCENTILES = (0.50, 0.90, 0.95)
# Citations taken from the first successful search and verified one by one.
CITATION_SAMPLE = 5

# Path classes the broker must never index, matched against the tracked tree of
# the ref the broker actually serves. Only path names are ever recorded.
ACL_EXCLUSION_CLASSES = (
    ("sealed_secret_ciphertext", r"^sealed-secrets/sealed/.*\.sealed\.ya?ml$"),
    ("terraform_variable_values", r"\.tfvars$"),
    ("ansible_vault", r"(^|/)vault\.ya?ml$"),
    ("credential_material", r"\.(key|pem|crt|p12|pfx|jks)$"),
    ("kubeconfig", r"(^|/)kubeconfig$|\.kubeconfig$"),
    ("content_addressed_object", r"/sha256/"),
)
ACL_PROBE_LIMIT = 4
# Without a positive control, "everything is forbidden" would pass trivially.
ACL_POSITIVE_CONTROLS = ("PRINCIPLES.md", "CLAUDE.md", BROKER_CHART_VALUES)

# The signed retrieval evaluation. Its SSHSIG is re-verified at collection time
# against the trust root that ships in Git, so this is a checked reference and
# not a transcription.
CORRECTNESS_RECEIPT = (
    "knowledge/registry/acceptance/p1-src-03/retrieval/multidomain-evaluation-receipts"
    "/sha256/f2/f221a84d113de1c4ef3ec60637042308ad3bc341bb69384538647c2700f74bec.json"
)
CORRECTNESS_SIGNATURE = (
    "knowledge/registry/acceptance/p1-src-03/retrieval/multidomain-evaluation-signatures"
    "/sha256/74/743c9e28f97f3440b0808c58b5d961fe4675497c3f9c1821b2494de8f4dccb84.json"
)
CORRECTNESS_TRUST_ROOT = "knowledge/registry/trust/evaluator-allowed-signers"
CORRECTNESS_AUDIT = (
    ".workingdir2/cluster-2/audits/p1-rag-01-small-to-big-2026-07-19.md"
)
CORRECTNESS_AUDIT_MARKER = "1.000/1.000/1.000"

UNAVAILABLE = "unavailable"
AVAILABLE = "available"

# A derived number may not outlive its inputs. If the left signal is available
# every input on the right must be available too, or the artifact is rejected.
DERIVED_DEPENDENCIES: dict[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("time_freshness", "worst_case_served_content_staleness_seconds"): (
        ("time_freshness", "serving_index_age_seconds"),
        ("time_freshness", "git_sync_period_seconds"),
    ),
    ("rollback", "deployed_image_matches_git_declaration"): (
        ("rollback", "deployed_image_digest"),
        ("rollback", "git_declared_image_digest"),
    ),
    ("citation", "citation_byte_reconstruction"): (("citation", "citation_resolution"),),
}
ACL_CONTROL_SIGNAL = "indexed_positive_control"


class ProbeError(RuntimeError):
    """A signal could not be read. Carries the reason recorded in the artifact."""


def available(value: Any, unit: str, provenance: str) -> dict[str, Any]:
    """A signal that was actually read. Provenance is mandatory."""
    if not provenance:
        raise ValueError("available signal requires a provenance string")
    return {"state": AVAILABLE, "value": value, "unit": unit, "provenance": provenance}


def unavailable(reason: str, provenance: str) -> dict[str, Any]:
    """A signal that could not be read. Never carries a value."""
    if not reason:
        raise ValueError("unavailable signal requires a reason")
    if not provenance:
        raise ValueError("unavailable signal requires a provenance string")
    return {
        "state": UNAVAILABLE,
        "value": None,
        "reason": reason,
        "provenance": provenance,
    }


def signal(
    fetch: Callable[[], tuple[Any, str]], unit: str, provenance: str
) -> dict[str, Any]:
    """Run a fetch, converting any ProbeError into a recorded unavailable."""
    try:
        value, detail = fetch()
    except ProbeError as err:
        return unavailable(str(err), provenance)
    return available(value, unit, provenance if not detail else f"{provenance}; {detail}")


def run(
    argv: list[str],
    timeout: int = 60,
    stdin: str | None = None,
    stdin_bytes: bytes | None = None,
) -> str:
    """Read-only subprocess helper. Non-zero exit becomes a ProbeError."""
    try:
        proc = subprocess.run(
            argv,
            input=stdin_bytes if stdin_bytes is not None else stdin,
            capture_output=True,
            text=stdin_bytes is None,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as err:
        raise ProbeError(f"command not found: {argv[0]}") from err
    except subprocess.TimeoutExpired as err:
        raise ProbeError(f"command timed out after {timeout}s: {' '.join(argv[:3])}") from err
    stdout = proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        detail = (stderr or stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit {proc.returncode}"
        raise ProbeError(f"command failed: {' '.join(argv[:3])}: {tail[:300]}")
    return stdout


def kubectl_json(args: list[str], timeout: int = 30) -> Any:
    out = run(["kubectl", f"--request-timeout={timeout}s", *args], timeout=timeout + 15)
    try:
        return json.loads(out)
    except json.JSONDecodeError as err:
        raise ProbeError(f"kubectl returned non-JSON: {err}") from err


def percentile(samples: list[float], fraction: float) -> float:
    """Nearest-rank percentile. Raises rather than inventing a value."""
    ordered = sorted(samples)
    if not ordered:
        raise ProbeError("no latency samples to summarise")
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return round(ordered[index], 4)


def parse_duration_seconds(value: str) -> float:
    """Parse a Go-style duration as git-sync spells it (60s, 1m30s, 500ms)."""
    matches = re.findall(r"(\d+(?:\.\d+)?)(ms|s|m|h)", value.strip())
    if not matches:
        raise ProbeError(f"unparseable duration {value!r}")
    scale = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    return round(sum(float(amount) * scale[unit] for amount, unit in matches), 4)


def parse_rfc3339(value: str) -> dt.datetime:
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as err:
        raise ProbeError(f"unparseable timestamp {value!r}") from err


class BrokerSession:
    """One in-Pod MCP session. Every call is timed and retained by key."""

    def __init__(self) -> None:
        self.initialize_seconds: float | None = None
        self.results: list[dict[str, Any]] = []
        self.error: str | None = None

    def by_key(self, key: str) -> dict[str, Any] | None:
        for entry in self.results:
            if entry["key"] == key:
                return entry
        return None

    def with_prefix(self, prefix: str) -> list[dict[str, Any]]:
        return [entry for entry in self.results if entry["key"].startswith(prefix)]

    def structured(self, key: str) -> dict[str, Any]:
        entry = self.by_key(key)
        if entry is None:
            raise ProbeError(self.error or f"broker call {key} was never made")
        if entry.get("failure"):
            raise ProbeError(entry["failure"])
        return entry["structured"]


class Repo:
    """Read-only local repository access for the artifacts this collector cites."""

    def __init__(self, root: str | Path | None = None, enabled: bool = True) -> None:
        self.root = Path(root or ".")
        self.enabled = enabled

    def _guard(self) -> None:
        if not self.enabled:
            raise ProbeError("local repository access disabled (--no-repo)")

    def read_bytes(self, relative: str) -> bytes:
        self._guard()
        path = self.root / relative
        try:
            return path.read_bytes()
        except OSError as err:
            raise ProbeError(f"cannot read {relative}: {err}") from err

    def git(self, args: list[str], timeout: int = 60) -> str:
        self._guard()
        return run(["git", "-C", str(self.root), *args], timeout=timeout)

    def verify_sshsig(
        self, payload: str, signature: str, trust_root: str, actor: str, namespace: str
    ) -> str:
        """Offline `ssh-keygen -Y verify` over the exact payload bytes."""
        self._guard()
        return run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(self.root / trust_root),
                "-I",
                actor,
                "-n",
                namespace,
                "-s",
                str(self.root / signature),
            ],
            timeout=30,
            stdin_bytes=self.read_bytes(payload),
        ).strip()


class Cluster:
    """Read-only cluster access. Every method raises ProbeError when unavailable."""

    def __init__(self, kubectl: bool = True) -> None:
        self.enabled = kubectl

    def _guard(self) -> None:
        if not self.enabled:
            raise ProbeError("cluster access disabled (--no-cluster)")

    def kubectl_json(self, args: list[str], timeout: int = 30) -> Any:
        """Guarded read. Every cluster read must go through here, so that a
        disabled or stubbed Cluster cannot silently reach the live apiserver."""
        self._guard()
        return kubectl_json(args, timeout=timeout)

    def broker_pod(self) -> dict[str, Any]:
        data = self.kubectl_json(
            ["get", "pods", "-n", BROKER_NAMESPACE, "-l", BROKER_SELECTOR, "-o", "json"]
        )
        running = [
            item
            for item in data.get("items", [])
            if item.get("status", {}).get("phase") == "Running"
        ]
        if not running:
            raise ProbeError(
                f"no Running pod matching {BROKER_SELECTOR} in namespace {BROKER_NAMESPACE}"
            )
        return running[0]

    def broker_session(
        self,
        pod: str,
        args: list[str],
        session: BrokerSession,
        drive: Callable[[BrokerSession], dict[str, Any] | None],
    ) -> None:
        """Run one stdio MCP session inside the deployed pod, filling `session`.

        Calls are issued strictly sequentially -- request written, response read,
        clock stopped -- because the SDK server answers concurrently and a
        pipelined batch would time the scheduler rather than the call.
        """
        self._guard()
        # stdin must stay open while the broker builds its index (tens of
        # seconds); closing it early makes the process exit before answering.
        argv = [
            "kubectl",
            f"--request-timeout={BROKER_CALL_TIMEOUT}s",
            "exec",
            "-i",
            "-n",
            BROKER_NAMESPACE,
            pod,
            "-c",
            BROKER_CONTAINER,
            "--",
            "archeion-knowledge-mcp",
            *args,
        ]
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except FileNotFoundError as err:
            raise ProbeError("command not found: kubectl") from err

        assert proc.stdin is not None and proc.stdout is not None
        deadline = time.monotonic() + BROKER_CALL_TIMEOUT

        def exchange(request: dict[str, Any], request_id: int) -> tuple[dict[str, Any], float]:
            start = time.monotonic()
            proc.stdin.write(json.dumps(request) + "\n")
            proc.stdin.flush()
            for line in proc.stdout:
                if time.monotonic() > deadline:
                    raise ProbeError(f"broker session exceeded {BROKER_CALL_TIMEOUT}s")
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if message.get("id") == request_id:
                    return message, round(time.monotonic() - start, 4)
            raise ProbeError(f"broker produced no JSON-RPC response for id {request_id}")

        try:
            handshake, elapsed = exchange(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "knowledge-dogfood-evidence",
                            "version": "1",
                        },
                    },
                },
                1,
            )
            if "result" not in handshake:
                raise ProbeError("broker rejected the MCP initialize handshake")
            session.initialize_seconds = elapsed
            proc.stdin.write(
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
            )
            proc.stdin.flush()

            request_id = 1
            while True:
                call = drive(session)
                if call is None:
                    break
                request_id += 1
                message, elapsed = exchange(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "tools/call",
                        "params": {"name": call["name"], "arguments": call["arguments"]},
                    },
                    request_id,
                )
                structured = message.get("result", {}).get("structuredContent")
                session.results.append(
                    {
                        "key": call["key"],
                        "name": call["name"],
                        "arguments": call["arguments"],
                        "elapsed_seconds": elapsed,
                        "structured": structured if isinstance(structured, dict) else {},
                        "is_error": bool(message.get("result", {}).get("isError")),
                        "failure": (
                            None
                            if isinstance(structured, dict)
                            else f"{call['name']} returned no structuredContent"
                        ),
                    }
                )
        finally:
            for stream in (proc.stdin, proc.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()

    def prom_query(self, query: str) -> list[dict[str, Any]]:
        from urllib.parse import quote

        data = self.kubectl_json(
            ["get", "--raw", f"{PROM_PROXY}/query?query={quote(query)}"], timeout=30
        )
        if data.get("status") != "success":
            raise ProbeError(f"prometheus query rejected: {str(data)[:200]}")
        return data.get("data", {}).get("result", [])


def acl_candidate_paths(repo: Repo) -> tuple[list[tuple[str, str]], str | None, str]:
    """Excluded-class candidates taken from the tracked tree of the served ref.

    Driving the probe from the served ref is what makes a `forbidden` answer
    mean "denied" rather than "absent".
    """
    revision = repo.git(["rev-parse", SERVED_REF]).strip()
    listing = repo.git(["ls-tree", "-r", "--name-only", SERVED_REF], timeout=120)
    tracked = sorted(line for line in listing.splitlines() if line)
    selected: list[tuple[str, str]] = []
    for name, pattern in ACL_EXCLUSION_CLASSES:
        matcher = re.compile(pattern)
        matched = [path for path in tracked if matcher.search(path)]
        selected.extend((name, path) for path in matched[:ACL_PROBE_LIMIT])
    return selected, revision, str(len(tracked))


def citation_calls(session: BrokerSession) -> list[dict[str, Any]]:
    """Two follow-up calls per citation: exact window, then whole file."""
    for entry in session.with_prefix("latency:"):
        hits = entry["structured"].get("hits")
        if not isinstance(hits, list) or not hits:
            continue
        calls: list[dict[str, Any]] = []
        for index, hit in enumerate(hits[:CITATION_SAMPLE]):
            if not isinstance(hit, dict) or not hit.get("path"):
                continue
            calls.append(
                {
                    "key": f"cite-window:{index}",
                    "name": "knowledge_get",
                    "arguments": {
                        "path": hit["path"],
                        "start_line": hit.get("start_line", 1),
                        "end_line": hit.get("end_line", 0),
                    },
                }
            )
            calls.append(
                {
                    "key": f"cite-file:{index}",
                    "name": "knowledge_get",
                    "arguments": {"path": hit["path"]},
                }
            )
        return calls
    return []


def cited_hits(session: BrokerSession) -> list[dict[str, Any]]:
    for entry in session.with_prefix("latency:"):
        hits = entry["structured"].get("hits")
        if isinstance(hits, list) and hits:
            return [hit for hit in hits[:CITATION_SAMPLE] if isinstance(hit, dict)]
    return []


def session_driver(
    acl_paths: list[tuple[str, str]]
) -> Callable[[BrokerSession], dict[str, Any] | None]:
    """Fixed plan first, then the citation follow-ups the searches produced."""
    plan: list[dict[str, Any]] = [
        {"key": "status", "name": "knowledge_status", "arguments": {}}
    ]
    for index, query in enumerate(LATENCY_QUERIES):
        for repeat in range(LATENCY_REPEATS):
            plan.append(
                {
                    "key": f"latency:{index}:{repeat}",
                    "name": "knowledge_search",
                    "arguments": {"query": query, "limit": CITATION_SAMPLE},
                }
            )
    for name, path in acl_paths:
        plan.append(
            {
                "key": f"acl:{name}:{path}",
                "name": "knowledge_get",
                "arguments": {"path": path},
            }
        )
    for path in ACL_POSITIVE_CONTROLS:
        plan.append(
            {
                "key": f"control:{path}",
                "name": "knowledge_get",
                "arguments": {"path": path},
            }
        )

    def drive(session: BrokerSession) -> dict[str, Any] | None:
        index = len(session.results)
        if index < len(plan):
            return plan[index]
        for call in citation_calls(session):
            if session.by_key(call["key"]) is None:
                return call
        return None

    return drive


def collect_token(session: BrokerSession) -> dict[str, Any]:
    """Index token/chunk volume, from the broker's own knowledge_status."""
    base = "MCP tools/call knowledge_status -> structuredContent.repository"
    code = "tools/knowledge-mcp/service.go knowledgeDescriptor"

    def field(path: str, key: str) -> Callable[[], tuple[Any, str]]:
        def fetch() -> tuple[Any, str]:
            node = session.structured("status").get("repository", {})
            for part in path.split("."):
                if not isinstance(node, dict) or part not in node:
                    raise ProbeError(f"field repository.{path} absent from knowledge_status")
                node = node[part]
            if not isinstance(node, dict) or key not in node:
                raise ProbeError(f"field repository.{path}.{key} absent from knowledge_status")
            return node[key], ""

        return fetch

    usage = "index_usage"
    limits = "index_limits"
    return {
        "description": (
            "Index token volume as reported by the broker itself. These are indexed "
            "token occurrences in the lexical index, not model prompt/completion "
            "tokens; no per-query billing signal exists for this broker."
        ),
        "signals": {
            "indexed_token_occurrences": signal(
                field(usage, "token_occurrences"),
                "occurrences",
                f"{base}.{usage}.token_occurrences ({code})",
            ),
            "indexed_chunks": signal(
                field(usage, "chunks"), "chunks", f"{base}.{usage}.chunks ({code})"
            ),
            "unique_terms": signal(
                field(usage, "unique_terms"),
                "terms",
                f"{base}.{usage}.unique_terms ({code})",
            ),
            "files_indexed": signal(
                field(usage, "files_indexed"),
                "files",
                f"{base}.{usage}.files_indexed ({code})",
            ),
            "token_occurrence_limit": signal(
                field(limits, "token_occurrences"),
                "occurrences",
                f"{base}.{limits}.token_occurrences ({code}; "
                "maxKnowledgeTokenOccurrences in knowledge.go)",
            ),
        },
    }


def collect_storage(
    session: BrokerSession,
    pod: dict[str, Any] | None,
    pod_error: str | None,
) -> dict[str, Any]:
    """Corpus bytes, resident index footprint and published-store footprint."""
    base = "MCP tools/call knowledge_status -> structuredContent"
    code = "tools/knowledge-mcp/service.go knowledgeDescriptor"

    def repo_field(group: str, key: str) -> Callable[[], tuple[Any, str]]:
        def fetch() -> tuple[Any, str]:
            node = session.structured("status").get("repository", {}).get(group)
            if not isinstance(node, dict) or key not in node:
                raise ProbeError(f"field repository.{group}.{key} absent from knowledge_status")
            return node[key], ""

        return fetch

    def mem_field(key: str) -> Callable[[], tuple[Any, str]]:
        def fetch() -> tuple[Any, str]:
            node = session.structured("status").get("process_memory")
            if not isinstance(node, dict) or key not in node:
                raise ProbeError(f"field process_memory.{key} absent from knowledge_status")
            return node[key], ""

        return fetch

    def published_store() -> tuple[Any, str]:
        registry = session.structured("status").get("registry")
        if not isinstance(registry, dict):
            raise ProbeError("field registry absent from knowledge_status")
        state = registry.get("state")
        if state != "ok":
            raise ProbeError(
                f"no published generation store to measure: registry.state={state!r} "
                "(chart values registry.state.enabled=false in apps/ai/knowledge-mcp/values.yaml)"
            )
        return registry.get("store_bytes"), ""

    def ephemeral_backing() -> tuple[Any, str]:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        volumes = pod.get("spec", {}).get("volumes", [])
        kinds = sorted(
            {key for volume in volumes for key in volume if key != "name"}
        )
        return kinds, f"{len(volumes)} volumes"

    return {
        "description": (
            "Storage footprint of the corpus the broker indexes and of the process "
            "that holds the index. The index is built at startup and held in memory; "
            "the broker mounts no PersistentVolume."
        ),
        "signals": {
            "corpus_source_bytes": signal(
                repo_field("index_usage", "source_bytes"),
                "bytes",
                f"{base}.repository.index_usage.source_bytes ({code})",
            ),
            "resident_process_bytes": signal(
                mem_field("vmrss_bytes"),
                "bytes",
                f"{base}.process_memory.vmrss_bytes ({code}; /proc/self/status VmRSS)",
            ),
            "go_heap_inuse_bytes": signal(
                mem_field("go_heap_inuse_bytes"),
                "bytes",
                f"{base}.process_memory.go_heap_inuse_bytes ({code}; runtime.MemStats)",
            ),
            "published_store_bytes": signal(
                published_store,
                "bytes",
                f"{base}.registry (publisher store; "
                "apps/ai/knowledge-mcp/values.yaml registry.state.enabled)",
            ),
            "backing_volume_kinds": signal(
                ephemeral_backing,
                "volume-kinds",
                "kubectl get pod -n ai -l "
                f"{BROKER_SELECTOR} -o json -> .spec.volumes[].<kind>",
            ),
        },
    }


def collect_energy(
    cluster: Cluster, node: str | None, host_ip: str | None, node_error: str | None
) -> dict[str, Any]:
    """Energy. Honest by construction: no proxy is ever promoted to a number.

    Every candidate series is probed and every outcome recorded. A value is only
    attributed to the broker if a real energy counter exists on the node the
    broker actually runs on. Otherwise the category is explicitly unavailable.
    """
    probes: dict[str, Any] = {}
    node_scoped_hit = False

    for metric, description in ENERGY_CANDIDATES:
        provenance = f"Prometheus instant query {metric} via {PROM_PROXY}/query ({description})"
        try:
            series = cluster.prom_query(metric)
        except ProbeError as err:
            probes[metric] = unavailable(str(err), provenance)
            continue
        if not series:
            probes[metric] = unavailable(
                f"metric {metric} has no series in Prometheus (collector not enabled "
                "on any scraped node-exporter)",
                provenance,
            )
            continue
        instances = sorted(
            {item.get("metric", {}).get("instance", "") for item in series}
        )
        # node-exporter labels series by host IP, while the Pod records a node
        # name; matching the wrong one would silently report "no counter here".
        on_node = [
            item
            for item in series
            if host_ip and item.get("metric", {}).get("instance", "").split(":")[0] == host_ip
        ]
        if on_node:
            node_scoped_hit = True
            probes[metric] = available(
                {
                    "series_on_broker_node": len(on_node),
                    "instances_cluster_wide": instances,
                },
                "series",
                provenance,
            )
        else:
            probes[metric] = unavailable(
                f"metric {metric} exists on {len(series)} series ({', '.join(instances)}) "
                f"but none on the node running the broker "
                f"({node or 'unknown'} / {host_ip or 'unknown IP'}); "
                "the counter is scoped to a PCI hwmon chip on those hosts, not to a "
                "node total and not to a pod",
                provenance,
            )

    if node_scoped_hit:
        attributed = unavailable(
            "an energy counter exists on the broker's node, but attributing a share of "
            "it to a single CPU-only pod requires per-process power accounting this "
            "cluster does not run; no defensible attribution rule exists",
            "derived from the probes recorded in this category",
        )
    else:
        attributed = unavailable(
            "no energy or power counter is scraped on the node running the broker; "
            "node_rapl_* is absent cluster-wide (node-exporter rapl collector not "
            "enabled) and node_hwmon_energy_joule_total covers only PCI hwmon chips "
            "on two home worker nodes",
            "derived from the probes recorded in this category",
        )

    return {
        "description": (
            "Energy attributable to the broker. This category is deliberately allowed "
            "to be empty: a fabricated proxy (CPU-seconds scaled by an assumed "
            "watts-per-core, or a node total divided by pod count) would not be an "
            "energy measurement and is not emitted."
        ),
        "signals": {
            "broker_attributable_energy": attributed,
            "broker_node": (
                available(node, "node-name", "kubectl get pod -o json -> .spec.nodeName")
                if node
                else unavailable(
                    node_error or "broker node unknown",
                    "kubectl get pod -o json -> .spec.nodeName",
                )
            ),
            **probes,
        },
    }


def collect_backup(
    cluster: Cluster, pod: dict[str, Any] | None, pod_error: str | None
) -> dict[str, Any]:
    """What of the broker's own state is protected, where, and when last verified."""

    def volume_inventory() -> tuple[Any, str]:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        volumes = pod.get("spec", {}).get("volumes", [])
        claims = [v["name"] for v in volumes if "persistentVolumeClaim" in v]
        return {
            "volume_count": len(volumes),
            "persistent_volume_claims": claims,
            "stateless": not claims,
        }, "a stateless broker has no volume data to back up by design"

    def corpus_origin() -> tuple[Any, str]:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        for container in pod.get("spec", {}).get("containers", []):
            if container.get("name") != GIT_SYNC_CONTAINER:
                continue
            args = container.get("args", [])
            repo = next((a.split("=", 1)[1] for a in args if a.startswith("--repo=")), None)
            ref = next((a.split("=", 1)[1] for a in args if a.startswith("--ref=")), None)
            if not repo:
                raise ProbeError("git-sync container has no --repo argument")
            return {"repo": repo, "ref": ref}, "corpus durability is the Git remote"
        raise ProbeError("no git-sync container in the broker pod")

    def image_pin() -> tuple[Any, str]:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        for status in pod.get("status", {}).get("containerStatuses", []):
            if status.get("name") != BROKER_CONTAINER:
                continue
            # containerd reports the registry reference in imageID here and a
            # bare digest in image, so both are recorded rather than guessed.
            return {
                "image": status.get("image"),
                "image_id": status.get("imageID"),
            }, "digest-pinned image in Harbor is the binary's durability"
        raise ProbeError(f"no containerStatus for {BROKER_CONTAINER}")

    def velero_coverage() -> tuple[Any, str]:
        backups = cluster.kubectl_json(
            ["get", "backups.velero.io", "-A", "-o", "json"], timeout=30
        )
        covering = []
        for item in backups.get("items", []):
            spec = item.get("spec", {})
            included = spec.get("includedNamespaces") or ["*"]
            if "*" not in included and BROKER_NAMESPACE not in included:
                continue
            status = item.get("status", {})
            if status.get("phase") != "Completed":
                continue
            covering.append(
                {
                    "name": item["metadata"]["name"],
                    "completed": status.get("completionTimestamp"),
                    "included_namespaces": included,
                }
            )
        if not covering:
            raise ProbeError(
                f"no Completed Velero backup includes namespace {BROKER_NAMESPACE}"
            )
        covering.sort(key=lambda item: item["completed"] or "", reverse=True)
        return covering[0], f"{len(covering)} completed backups cover the namespace"

    def longhorn_recurring_coverage() -> tuple[Any, str]:
        jobs = cluster.kubectl_json(
            ["get", "recurringjobs.longhorn.io", "-A", "-o", "json"], timeout=30
        )
        volumes = cluster.kubectl_json(
            ["get", "volumes.longhorn.io", "-A", "-o", "json"], timeout=45
        )
        targeted: set[str] = set()
        for job in jobs.get("items", []):
            for group in job.get("spec", {}).get("groups", []) or []:
                targeted.add(group)
        populated: dict[str, int] = {}
        for volume in volumes.get("items", []):
            for key, value in (volume["metadata"].get("labels") or {}).items():
                prefix = "recurring-job-group.longhorn.io/"
                if key.startswith(prefix) and value == "enabled":
                    group = key[len(prefix) :]
                    populated[group] = populated.get(group, 0) + 1
        empty_targets = sorted(targeted - set(populated))
        unserved = sorted(set(populated) - targeted)
        return {
            "groups_targeted_by_recurring_jobs": sorted(targeted),
            "group_volume_counts": dict(sorted(populated.items())),
            "targeted_groups_with_zero_volumes": empty_targets,
            "populated_groups_with_no_recurring_job": {
                group: populated[group] for group in unserved
            },
        }, (
            "group membership is the volume label recurring-job-group.longhorn.io/<group>=enabled; "
            "a job targeting an empty group protects nothing"
        )

    return {
        "description": (
            "Protection of the broker's own state. Recorded as what is actually "
            "protected today, not what is configured. Longhorn coverage is included "
            "because it is the cluster's volume-protection mechanism, even though the "
            "broker itself holds no volume."
        ),
        "signals": {
            "broker_volume_inventory": signal(
                volume_inventory,
                "inventory",
                "kubectl get pod -n ai -l "
                f"{BROKER_SELECTOR} -o json -> .spec.volumes",
            ),
            "corpus_origin": signal(
                corpus_origin,
                "git-remote",
                "kubectl get pod -o json -> .spec.containers[name=git-sync].args",
            ),
            "broker_image_pin": signal(
                image_pin,
                "image-ref",
                "kubectl get pod -o json -> "
                f".status.containerStatuses[name={BROKER_CONTAINER}].image",
            ),
            "last_velero_backup_covering_namespace": signal(
                velero_coverage,
                "backup",
                "kubectl get backups.velero.io -A -o json -> "
                ".spec.includedNamespaces + .status.phase/.status.completionTimestamp",
            ),
            "longhorn_recurring_job_coverage": signal(
                longhorn_recurring_coverage,
                "coverage",
                "kubectl get recurringjobs.longhorn.io,volumes.longhorn.io -A -o json",
            ),
        },
    }


def collect_latency(cluster: Cluster, session: BrokerSession) -> dict[str, Any]:
    """Real request latency of broker calls, measured because nothing else times them."""
    measured = (
        "wall clock in this collector around each JSON-RPC request/response over "
        "`kubectl exec -i`, issued strictly sequentially; includes the apiserver "
        "exec stream round-trip, so every number is an upper bound on in-process "
        "handling time"
    )

    def summary(entries: list[dict[str, Any]], label: str) -> Callable[[], tuple[Any, str]]:
        def fetch() -> tuple[Any, str]:
            if session.error:
                raise ProbeError(session.error)
            samples = [entry["elapsed_seconds"] for entry in entries]
            if not samples:
                raise ProbeError(f"no {label} calls completed in the broker session")
            value = {
                "samples": len(samples),
                "min": round(min(samples), 4),
                "max": round(max(samples), 4),
                "mean": round(sum(samples) / len(samples), 4),
            }
            for fraction in LATENCY_PERCENTILES:
                value[f"p{int(fraction * 100)}"] = percentile(samples, fraction)
            return value, f"{len(samples)} samples"

        return fetch

    def handshake() -> tuple[Any, str]:
        if session.initialize_seconds is None:
            raise ProbeError(session.error or "the broker session never handshook")
        return session.initialize_seconds, "1 sample"

    def server_side_metric() -> tuple[Any, str]:
        series = cluster.prom_query(
            'count({namespace="ai", service="knowledge-mcp"}) by (__name__)'
        )
        if not series:
            raise ProbeError(
                "no Prometheus series is scraped from the broker: the binary registers "
                "no metrics handler (no promhttp in tools/knowledge-mcp) and the chart "
                "ships no ServiceMonitor, so there is no server-side latency histogram "
                "to read and every latency number here is client-measured"
            )
        return sorted(item.get("metric", {}).get("__name__", "") for item in series), ""

    searches = session.with_prefix("latency:")
    gets = session.with_prefix("cite-") + session.with_prefix("acl:")
    return {
        "description": (
            "Latency of real broker calls. No server-side timer exists, so the "
            "collector times the calls itself and says so; sample counts and "
            "percentiles are recorded rather than a bare mean. Measured against a "
            "fresh in-Pod process holding an equivalent in-memory index, not against "
            "the long-lived serving session."
        ),
        "signals": {
            "startup_to_first_response_seconds": signal(
                handshake,
                "seconds",
                f"{measured}; the initialize round-trip also covers process start and "
                "the startup index build (buildKnowledgeIndex runs before serving in "
                "tools/knowledge-mcp/main.go)",
            ),
            "knowledge_search_latency_seconds": signal(
                summary(searches, "knowledge_search"),
                "seconds",
                f"{measured}; tools/call knowledge_search over "
                f"{len(LATENCY_QUERIES)} distinct GitOps queries x {LATENCY_REPEATS} repeats",
            ),
            "knowledge_get_latency_seconds": signal(
                summary(gets, "knowledge_get"),
                "seconds",
                f"{measured}; tools/call knowledge_get, citation and exclusion probes",
            ),
            "server_side_latency_histogram": signal(
                server_side_metric,
                "metric-names",
                "Prometheus instant query for any series scraped from the broker "
                f"Service via {PROM_PROXY}/query",
            ),
        },
    }


def collect_correctness(repo: Repo) -> dict[str, Any]:
    """Retain the signed retrieval evaluation as dogfood evidence, re-verified."""

    def receipt_payload() -> dict[str, Any]:
        raw = repo.read_bytes(CORRECTNESS_RECEIPT)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as err:
            raise ProbeError(f"evaluation receipt is not valid JSON: {err}") from err
        if not isinstance(payload, dict):
            raise ProbeError("evaluation receipt is not a JSON object")
        return payload

    def receipt() -> tuple[Any, str]:
        payload = receipt_payload()
        digest = hashlib.sha256(repo.read_bytes(CORRECTNESS_RECEIPT)).hexdigest()
        return {
            "receipt_id": payload.get("receipt_id"),
            "receipt_kind": payload.get("receipt_kind"),
            "state": payload.get("state"),
            "evaluated_at": payload.get("evaluated_at"),
            "evaluator_revision": payload.get("evaluator_revision"),
            "suite_id": payload.get("suite_id"),
            "metric_algorithm": payload.get("metric_algorithm"),
            "cutoff_k": payload.get("cutoff_k"),
            "gates": payload.get("gates"),
            "promotable": payload.get("promotable"),
            "execution_authorized": payload.get("execution_authorized"),
            "file_sha256": f"sha256:{digest}",
        }, (
            "promotable/execution_authorized are recorded verbatim: this receipt is a "
            "measured evaluation, not an acceptance authorization"
        )

    def signature() -> tuple[Any, str]:
        payload = receipt_payload()
        authorization = payload.get("authorization")
        if not isinstance(authorization, dict):
            raise ProbeError("evaluation receipt carries no authorization block")
        actor = authorization.get("actor")
        namespace = authorization.get("namespace")
        if not actor or not namespace:
            raise ProbeError("evaluation receipt authorization has no actor/namespace")
        trust_digest = hashlib.sha256(repo.read_bytes(CORRECTNESS_TRUST_ROOT)).hexdigest()
        claimed = authorization.get("allowed_signers_sha256")
        if claimed != f"sha256:{trust_digest}":
            raise ProbeError(
                "the tracked trust root does not match the receipt's "
                f"allowed_signers_sha256 ({claimed}); the receipt cannot select its "
                "own trust root"
            )
        verdict = repo.verify_sshsig(
            CORRECTNESS_RECEIPT, CORRECTNESS_SIGNATURE, CORRECTNESS_TRUST_ROOT, actor, namespace
        )
        return {
            "verified": True,
            "signer": actor,
            "key_id": authorization.get("key_id"),
            "namespace": namespace,
            "method": authorization.get("method"),
            "trust_root": CORRECTNESS_TRUST_ROOT,
            "trust_root_sha256": f"sha256:{trust_digest}",
            "verdict": verdict,
        }, "offline `ssh-keygen -Y verify` re-run at collection time over the exact receipt bytes"

    def metrics() -> tuple[Any, str]:
        payload = receipt_payload()
        aggregates = payload.get("aggregate_metrics")
        if not isinstance(aggregates, list) or not aggregates:
            raise ProbeError("evaluation receipt carries no aggregate_metrics")
        scale = payload.get("metric_scale")
        if not isinstance(scale, int) or scale <= 0:
            raise ProbeError("evaluation receipt carries no usable metric_scale")
        rows = []
        for item in aggregates:
            rows.append(
                {
                    "class": item.get("class"),
                    "profile": item.get("profile"),
                    "query_count": item.get("query_count"),
                    "recall": round(item.get("recall_ppm", 0) / scale, 6),
                    "mrr": round(item.get("mrr_ppm", 0) / scale, 6),
                    "ndcg": round(item.get("ndcg_ppm", 0) / scale, 6),
                    "threshold_passed": item.get("threshold_passed"),
                }
            )
        return {
            "cutoff_k": payload.get("cutoff_k"),
            "total_queries": sum(int(item.get("query_count") or 0) for item in aggregates),
            "arms": sorted({str(item.get("profile")) for item in aggregates}),
            "classes": sorted({str(item.get("class")) for item in aggregates}),
            "aggregates": rows,
        }, "ppm values divided by the receipt's own metric_scale"

    def audit_reference() -> tuple[Any, str]:
        raw = repo.read_bytes(CORRECTNESS_AUDIT)
        text = raw.decode("utf-8", "replace")
        lines = [
            number
            for number, line in enumerate(text.splitlines(), start=1)
            if CORRECTNESS_AUDIT_MARKER in line
        ]
        if not lines:
            raise ProbeError(
                f"{CORRECTNESS_AUDIT} no longer contains {CORRECTNESS_AUDIT_MARKER!r}; "
                "the narrative reference has drifted from the recorded result"
            )
        return {
            "path": CORRECTNESS_AUDIT,
            "sha256": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "result_lines": lines,
            "signed": False,
        }, "unsigned narrative corroboration; the receipt above is the signed artifact"

    return {
        "description": (
            "Retrieval correctness measured against a frozen judged suite and retained "
            "with its signing identity. The signature is re-verified offline at "
            "collection time against the trust root that ships in Git, so this is a "
            "checked reference rather than a transcription. It evaluates the "
            "tools/knowledge-retrieval lanes over the admitted 3-authority corpus -- "
            "not the deployed broker's own lexical index over this repository."
        ),
        "signals": {
            "retrieval_evaluation_receipt": signal(
                receipt, "receipt", f"{CORRECTNESS_RECEIPT} (tracked in Git)"
            ),
            "retrieval_evaluation_signature": signal(
                signature,
                "signature-verdict",
                f"ssh-keygen -Y verify -f {CORRECTNESS_TRUST_ROOT} "
                f"-s {CORRECTNESS_SIGNATURE} < {CORRECTNESS_RECEIPT}",
            ),
            "retrieval_held_out_metrics": signal(
                metrics,
                "recall/mrr/ndcg",
                f"{CORRECTNESS_RECEIPT} -> aggregate_metrics, metric_scale, cutoff_k",
            ),
            "held_out_quality_audit_reference": signal(
                audit_reference, "audit-reference", f"{CORRECTNESS_AUDIT} (tracked in Git)"
            ),
            "broker_lexical_search_correctness": unavailable(
                "no judged query set exists for the deployed broker's own lexical index "
                "over this repository: the signed receipt covers a different engine "
                "(tools/knowledge-retrieval) and a different corpus (the admitted "
                "cilium/go/kubernetes authorities). Evidencing it needs a scorer-blind "
                "qrels suite whose judged spans are paths in this repository, frozen "
                "before any run, plus a runner that replays it through knowledge_search",
                "absence of a judged suite bound to the broker corpus",
            ),
        },
    }


def collect_citation(session: BrokerSession) -> dict[str, Any]:
    """Do the exact path/line/sha256 bindings the broker returns actually resolve."""

    def resolution() -> tuple[Any, str]:
        hits = cited_hits(session)
        if not hits:
            raise ProbeError(
                session.error or "no search returned a citation to verify"
            )
        checked = 0
        resolved = 0
        mismatches: list[dict[str, Any]] = []
        for index, hit in enumerate(hits):
            entry = session.by_key(f"cite-window:{index}")
            if entry is None or entry.get("failure"):
                continue
            checked += 1
            evidence = entry["structured"].get("evidence")
            if not isinstance(evidence, dict):
                mismatches.append({"path": hit.get("path"), "problem": "no evidence returned"})
                continue
            problems = []
            if evidence.get("sha256") != hit.get("sha256"):
                problems.append("sha256 differs from the cited digest")
            if evidence.get("start_line") != hit.get("start_line") or evidence.get(
                "end_line"
            ) != hit.get("end_line"):
                problems.append("resolved line range differs from the cited range")
            if evidence.get("snippet") != hit.get("snippet"):
                problems.append("resolved bytes differ from the cited snippet")
            if problems:
                mismatches.append({"path": hit.get("path"), "problem": "; ".join(problems)})
            else:
                resolved += 1
        if not checked:
            raise ProbeError("no citation could be re-fetched through knowledge_get")
        return {
            "citations_checked": checked,
            "citations_resolved": resolved,
            "mismatches": mismatches,
        }, "each citation re-fetched by path and exact line range and compared field by field"

    def reconstruction() -> tuple[Any, str]:
        hits = cited_hits(session)
        if not hits:
            raise ProbeError(session.error or "no search returned a citation to verify")
        attempted = 0
        reconstructible = 0
        digest_matches = 0
        skipped: dict[str, int] = {}
        failures: list[str] = []
        for index, hit in enumerate(hits):
            entry = session.by_key(f"cite-file:{index}")
            if entry is None or entry.get("failure"):
                continue
            attempted += 1
            data = entry["structured"]
            evidence = data.get("evidence")
            if not isinstance(evidence, dict):
                skipped["no evidence returned"] = skipped.get("no evidence returned", 0) + 1
                continue
            size = data.get("size_bytes")
            line_count = data.get("line_count")
            if evidence.get("truncated") or evidence.get("end_line") != line_count:
                skipped["file exceeds the whole-file read bound"] = (
                    skipped.get("file exceeds the whole-file read bound", 0) + 1
                )
                continue
            rebuilt = (evidence.get("snippet") or "").encode("utf-8") + b"\n"
            if not isinstance(size, int) or len(rebuilt) != size:
                skipped["bytes are not line-reconstructible (CRLF or no trailing newline)"] = (
                    skipped.get(
                        "bytes are not line-reconstructible (CRLF or no trailing newline)", 0
                    )
                    + 1
                )
                continue
            reconstructible += 1
            if f"sha256:{hashlib.sha256(rebuilt).hexdigest()}" == evidence.get("sha256"):
                digest_matches += 1
            else:
                failures.append(str(evidence.get("path")))
        if not attempted:
            raise ProbeError("no cited file could be re-read for byte reconstruction")
        return {
            "files_attempted": attempted,
            "byte_reconstructible": reconstructible,
            "digest_matches": digest_matches,
            "digest_mismatch_paths": failures,
            "skipped_reasons": skipped,
        }, (
            "the collector recomputes SHA-256 over the reconstructed file bytes itself, "
            "so the digest claim is checked outside the broker"
        )

    return {
        "description": (
            "Whether the broker's exact path/line/sha256 bindings resolve to the bytes "
            "they claim. Resolution re-fetches each citation through knowledge_get and "
            "compares every bound field; reconstruction recomputes the digest in this "
            "collector. Both sides of the resolution check come from one broker "
            "process, so resolution proves internal binding consistency, while the "
            "reconstruction check is the part computed outside the broker."
        ),
        "signals": {
            "citation_resolution": signal(
                resolution,
                "citations",
                "tools/call knowledge_search hits re-fetched with tools/call "
                "knowledge_get at the cited path and line range",
            ),
            "citation_byte_reconstruction": signal(
                reconstruction,
                "files",
                "tools/call knowledge_get whole-file read, SHA-256 recomputed locally "
                "(tools/knowledge-mcp/knowledge.go hashBytes over raw worktree bytes)",
            ),
            "citation_stability_across_processes": unavailable(
                "citations were taken and resolved inside one broker process, so this "
                "run cannot show that a citation issued by the long-lived serving "
                "process still resolves after a restart onto a newer worktree. "
                "Evidencing it needs a citation retained from one process and replayed "
                "against a later one, which is a two-run protocol this single-session "
                "collector does not implement",
                "single-session collection design",
            ),
        },
    }


def collect_time_freshness(
    pod: dict[str, Any] | None, pod_error: str | None, collected_at: str
) -> dict[str, Any]:
    """How stale served content can be, derived from the real configured period."""

    def git_sync_period() -> tuple[Any, str]:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        for container in pod.get("spec", {}).get("containers", []):
            if container.get("name") != GIT_SYNC_CONTAINER:
                continue
            for argument in container.get("args", []):
                if argument.startswith("--period="):
                    return parse_duration_seconds(argument.split("=", 1)[1]), argument
            raise ProbeError("git-sync container has no --period argument")
        raise ProbeError("no git-sync container in the broker pod")

    def container_started() -> str:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        for status in pod.get("status", {}).get("containerStatuses", []):
            if status.get("name") != BROKER_CONTAINER:
                continue
            started = (status.get("state", {}).get("running") or {}).get("startedAt")
            if not started:
                raise ProbeError(f"container {BROKER_CONTAINER} is not in a running state")
            return started
        raise ProbeError(f"no containerStatus for {BROKER_CONTAINER}")

    def served_ref() -> tuple[Any, str]:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        for container in pod.get("spec", {}).get("containers", []):
            if container.get("name") != GIT_SYNC_CONTAINER:
                continue
            for argument in container.get("args", []):
                if argument.startswith("--ref="):
                    return argument.split("=", 1)[1], ""
            raise ProbeError("git-sync container has no --ref argument")
        raise ProbeError("no git-sync container in the broker pod")

    def started_at() -> tuple[Any, str]:
        return container_started(), "the serving index is built once before this process serves"

    def index_age() -> tuple[Any, str]:
        started = parse_rfc3339(container_started())
        age = (parse_rfc3339(collected_at) - started).total_seconds()
        if age < 0:
            raise ProbeError("container start time is in the future relative to collection")
        return round(age, 1), "collection time minus container start time"

    def staleness_bound() -> tuple[Any, str]:
        period, _ = git_sync_period()
        age, _ = index_age()
        return round(float(age) + float(period), 1), (
            "index age plus one git-sync period; excludes push-to-remote time, which "
            "no signal here bounds"
        )

    return {
        "description": (
            "Freshness of what the broker serves. The git-sync sidecar refreshes the "
            "worktree on a period, but the index is built once at process start and "
            "never rebuilt, so the bound on served content is the age of the serving "
            "process plus one sync period -- not the sync period alone. Derived from "
            "the period the Pod actually runs with, not from a documented value."
        ),
        "signals": {
            "git_sync_period_seconds": signal(
                git_sync_period,
                "seconds",
                "kubectl get pod -o json -> "
                f".spec.containers[name={GIT_SYNC_CONTAINER}].args[--period]",
            ),
            "served_ref": signal(
                served_ref,
                "git-ref",
                "kubectl get pod -o json -> "
                f".spec.containers[name={GIT_SYNC_CONTAINER}].args[--ref]",
            ),
            "serving_index_built_at": signal(
                started_at,
                "timestamp",
                "kubectl get pod -o json -> "
                f".status.containerStatuses[name={BROKER_CONTAINER}].state.running.startedAt",
            ),
            "serving_index_age_seconds": signal(
                index_age,
                "seconds",
                "container start time compared with this artifact's collected_at",
            ),
            "index_refresh_mechanism": available(
                {
                    "rebuilt_after_start": False,
                    "mechanism": "buildKnowledgeIndex runs once before serving",
                    "invalidation": "process restart only",
                },
                "mechanism",
                "tools/knowledge-mcp/main.go builds the index before the transport "
                "starts, and tools/knowledge-mcp/knowledge.go registers no ticker, "
                "watch or re-index path",
            ),
            "worst_case_served_content_staleness_seconds": signal(
                staleness_bound,
                "seconds",
                "serving_index_age_seconds + git_sync_period_seconds, both recorded above",
            ),
        },
    }


def collect_acl_deletion(session: BrokerSession, repo: Repo) -> dict[str, Any]:
    """Do the broker's exclusions actually hold against the live index."""
    control_paths = list(ACL_POSITIVE_CONTROLS)
    control_entries = [session.by_key(f"control:{path}") for path in control_paths]
    resolved_controls = [
        path
        for path, entry in zip(control_paths, control_entries)
        if entry is not None
        and not entry.get("failure")
        and not entry.get("is_error")
        and isinstance(entry["structured"].get("evidence"), dict)
    ]

    def control() -> tuple[Any, str]:
        if not any(entry is not None for entry in control_entries):
            raise ProbeError(session.error or "no positive control was probed")
        if not resolved_controls:
            raise ProbeError(
                "every positive control was refused, so a refusal cannot be "
                "distinguished from an absent path and no exclusion claim is provable"
            )
        return {
            "paths_probed": len([entry for entry in control_entries if entry is not None]),
            "paths_resolved": len(resolved_controls),
            "paths": resolved_controls,
        }, "an indexed path must resolve, or the exclusion probe proves nothing"

    signals: dict[str, Any] = {ACL_CONTROL_SIGNAL: signal(
        control,
        "paths",
        "tools/call knowledge_get on paths that must be indexed",
    )}

    for name, _pattern in ACL_EXCLUSION_CLASSES:
        entries = session.with_prefix(f"acl:{name}:")

        def make(name: str = name, entries: list[dict[str, Any]] = entries):
            def fetch() -> tuple[Any, str]:
                if not resolved_controls:
                    raise ProbeError(
                        "positive control failed, so a refusal here cannot be "
                        "distinguished from an absent path"
                    )
                if not entries:
                    raise ProbeError(
                        session.error
                        or f"the served ref {SERVED_REF} tracks no path of class {name}, "
                        "so the rule has no live candidate to exercise; it stays covered "
                        "offline by tools/knowledge-mcp/knowledge_test.go"
                    )
                refused = []
                leaked = []
                for entry in entries:
                    path = entry["arguments"]["path"]
                    if entry.get("failure"):
                        continue
                    body = entry["structured"]
                    # Only the path and the typed refusal are ever recorded.
                    if entry.get("is_error") and body.get("state") == "forbidden":
                        refused.append(path)
                    else:
                        leaked.append(path)
                return {
                    "paths_probed": len(entries),
                    "paths_refused": len(refused),
                    "refused_paths": refused,
                    "indexed_paths": leaked,
                }, "only path names and the typed refusal are recorded; no content is read"

            return fetch

        signals[f"excluded_{name}"] = signal(
            make(),
            "paths",
            f"tracked {SERVED_REF} paths of class {name}, each probed with tools/call "
            "knowledge_get; the served ref supplies the candidates so a refusal means "
            "denied and not absent",
        )

    def candidate_source() -> tuple[Any, str]:
        revision = repo.git(["rev-parse", SERVED_REF]).strip()
        return {
            "ref": SERVED_REF,
            "revision": revision,
            "classes": [name for name, _ in ACL_EXCLUSION_CLASSES],
            "paths_per_class": ACL_PROBE_LIMIT,
        }, "candidates come from the tracked tree of the ref the broker serves"

    signals["exclusion_candidate_source"] = signal(
        candidate_source,
        "ref",
        f"git ls-tree -r --name-only {SERVED_REF} in the local clone",
    )
    signals["untracked_exclusion"] = unavailable(
        "the broker's worktree is a clean shallow git-sync clone, so it contains no "
        "untracked file to probe and the untracked-exclusion rule cannot be exercised "
        "against this deployment. It is covered offline by "
        "tools/knowledge-mcp/knowledge_test.go, which fails if an untracked path "
        "enters the index. Evidencing it live would need a deliberately dirtied "
        "worktree in the Pod, which is a cluster mutation",
        "git-sync clone semantics (--depth=1 clean checkout)",
    )
    signals["deletion_exercised"] = unavailable(
        "no delete-then-observe cycle has been run against the deployed broker. The "
        "index is built once at process start with no invalidation path, so a path "
        "removed from the served ref stays answerable until the broker process "
        "restarts -- see time_freshness.index_refresh_mechanism for the mechanism and "
        "serving_index_age_seconds for the current bound. Evidencing it needs a commit "
        "that removes an indexed path on the served ref plus a probe before and after "
        "the next broker restart",
        "absence of a recorded deletion drill",
    )

    return {
        "description": (
            "Whether the broker's exclusions hold against the live index. Candidate "
            "paths are taken from the tracked tree of the ref the broker serves and "
            "probed one by one; a path that is refused is recorded as refused, and its "
            "contents are never read or retained. Deletion is a separate property and "
            "is recorded as unexercised."
        ),
        "signals": signals,
    }


def collect_rollback(
    cluster: Cluster, repo: Repo, pod: dict[str, Any] | None, pod_error: str | None
) -> dict[str, Any]:
    """Rollback here is a Git revert plus reconcile. Evidence the parts that exist."""

    def application() -> dict[str, Any]:
        data = cluster.kubectl_json(
            ["get", "application.argoproj.io", BROKER_APPLICATION, "-n", "argocd", "-o", "json"]
        )
        if not isinstance(data, dict) or "spec" not in data:
            raise ProbeError(f"ArgoCD Application {BROKER_APPLICATION} returned no spec")
        return data

    def deployed_digest() -> tuple[Any, str]:
        if pod is None:
            raise ProbeError(pod_error or "broker pod unavailable")
        for status in pod.get("status", {}).get("containerStatuses", []):
            if status.get("name") != BROKER_CONTAINER:
                continue
            image_id = status.get("imageID") or ""
            match = re.search(r"(sha256:[0-9a-f]{64})", image_id)
            if not match:
                raise ProbeError(f"containerStatus imageID carries no digest: {image_id!r}")
            return match.group(1), image_id
        raise ProbeError(f"no containerStatus for {BROKER_CONTAINER}")

    def git_digest() -> tuple[Any, str]:
        text = repo.git(["show", f"{SERVED_REF}:{BROKER_CHART_VALUES}"], timeout=60)
        match = re.search(r"^image:\n(?:[ \t]+.*\n)*?[ \t]+digest:[ \t]*\"([^\"]+)\"", text, re.M)
        if not match:
            raise ProbeError(
                f"no image.digest found in {BROKER_CHART_VALUES} at {SERVED_REF}"
            )
        return match.group(1), f"{SERVED_REF}:{BROKER_CHART_VALUES}"

    def digest_match() -> tuple[Any, str]:
        running, _ = deployed_digest()
        declared, _ = git_digest()
        return {
            "matches": running == declared,
            "running": running,
            "declared": declared,
        }, "a Git revert only selects the running bytes while these agree"

    def sync_state() -> tuple[Any, str]:
        data = application()
        spec = data.get("spec", {})
        status = data.get("status", {})
        policy = (spec.get("syncPolicy") or {}).get("automated") or {}
        source = spec.get("source") or {}
        return {
            "sync_status": status.get("sync", {}).get("status"),
            "health": status.get("health", {}).get("status"),
            "revision": status.get("sync", {}).get("revision"),
            "target_revision": source.get("targetRevision"),
            "path": source.get("path"),
            "automated": bool(policy),
            "self_heal": bool(policy.get("selfHeal")),
            "prune": bool(policy.get("prune")),
        }, "reconcile is automated, so a revert commit is the whole rollback action"

    def history() -> tuple[Any, str]:
        entries = application().get("status", {}).get("history") or []
        if not entries:
            raise ProbeError(
                f"ArgoCD Application {BROKER_APPLICATION} retains no deployment history"
            )
        revisions = [entry.get("revision") for entry in entries]
        repeats = sorted(
            {revision for revision in revisions if revisions.count(revision) > 1 and revision}
        )
        return {
            "entries_retained": len(entries),
            "distinct_revisions": len({revision for revision in revisions if revision}),
            "repeated_revisions": repeats,
            "oldest_deployed_at": entries[0].get("deployedAt"),
            "newest_deployed_at": entries[-1].get("deployedAt"),
        }, "a revision that appears twice is the signature of a reconciled rollback"

    history_signal = signal(
        history,
        "history",
        f"kubectl get application.argoproj.io {BROKER_APPLICATION} -n argocd -o json "
        "-> .status.history[].revision/.deployedAt",
    )
    if history_signal["state"] == AVAILABLE and history_signal["value"]["repeated_revisions"]:
        exercised = available(
            {
                "repeated_revisions": history_signal["value"]["repeated_revisions"],
                "window_entries": history_signal["value"]["entries_retained"],
            },
            "rollback",
            "a revision redeployed after a later one in .status.history is a "
            "reconciled rollback of this Application",
        )
    else:
        window = (
            history_signal["value"]["entries_retained"]
            if history_signal["state"] == AVAILABLE
            else "unknown"
        )
        exercised = unavailable(
            "no rollback has been exercised: within the retained ArgoCD history window "
            f"({window} entries) no revision is deployed twice, and no rollback drill "
            "is recorded anywhere in this repository. The mechanism below is evidenced, "
            "the act is not. Evidencing it needs a revert commit on the served ref, a "
            "recorded reconcile, and a post-revert probe showing the previous image "
            "digest serving again",
            "ArgoCD .status.history contains no repeated revision, and the window is "
            "bounded by revisionHistoryLimit",
        )

    return {
        "description": (
            "Rollback of this broker is a Git revert plus an ArgoCD reconcile: the "
            "image is digest-pinned in the chart and the Application syncs "
            "automatically. The mechanism is evidenced from live state; whether it has "
            "ever been exercised is recorded separately and honestly."
        ),
        "signals": {
            "deployed_image_digest": signal(
                deployed_digest,
                "digest",
                "kubectl get pod -o json -> "
                f".status.containerStatuses[name={BROKER_CONTAINER}].imageID",
            ),
            "git_declared_image_digest": signal(
                git_digest,
                "digest",
                f"git show {SERVED_REF}:{BROKER_CHART_VALUES} -> image.digest",
            ),
            "deployed_image_matches_git_declaration": signal(
                digest_match, "match", "the two digests recorded above, compared"
            ),
            "argocd_reconcile_state": signal(
                sync_state,
                "application",
                f"kubectl get application.argoproj.io {BROKER_APPLICATION} -n argocd -o json",
            ),
            "argocd_revision_history": history_signal,
            "rollback_exercised": exercised,
        },
    }


def validate(artifact: dict[str, Any]) -> None:
    """Fail-closed invariants. Raises ValueError on any violation."""
    if artifact.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("artifact schema_version mismatch")
    if artifact.get("artifact_kind") != ARTIFACT_KIND:
        raise ValueError("artifact_kind mismatch")
    if not artifact.get("collected_at"):
        raise ValueError("artifact has no collected_at timestamp")
    target = artifact.get("run_target", {})
    if target.get("mode") not in {"deployed_broker", "local_binary", "unavailable"}:
        raise ValueError("run_target.mode must be recorded")

    categories = artifact.get("categories", {})
    missing = [name for name in CATEGORIES if name not in categories]
    if missing:
        raise ValueError(f"categories missing from artifact: {missing}")

    for name in CATEGORIES:
        signals = categories[name].get("signals")
        if not signals:
            raise ValueError(f"category {name} has no signals")
        for key, entry in signals.items():
            where = f"{name}.{key}"
            if not isinstance(entry, dict):
                raise ValueError(f"{where} is not a signal object")
            state = entry.get("state")
            if state not in {AVAILABLE, UNAVAILABLE}:
                raise ValueError(f"{where} has invalid state {state!r}")
            if not entry.get("provenance"):
                raise ValueError(f"{where} has no provenance string")
            if state == UNAVAILABLE:
                if entry.get("value") is not None:
                    raise ValueError(f"{where} is unavailable but carries a value")
                if not entry.get("reason"):
                    raise ValueError(f"{where} is unavailable with no reason")
            else:
                if "value" not in entry:
                    raise ValueError(f"{where} is available with no value key")
                if entry.get("value") is None:
                    raise ValueError(f"{where} is available but its value is null")

    energy = categories["energy"]["signals"].get("broker_attributable_energy")
    if not energy or energy.get("state") != UNAVAILABLE:
        if not energy or not energy.get("provenance"):
            raise ValueError("energy attribution must carry provenance")

    # A derived number may never outlive the inputs it was derived from.
    for (name, key), dependencies in DERIVED_DEPENDENCIES.items():
        entry = categories.get(name, {}).get("signals", {}).get(key)
        if not entry or entry.get("state") != AVAILABLE:
            continue
        for dependency_name, dependency_key in dependencies:
            dependency = (
                categories.get(dependency_name, {}).get("signals", {}).get(dependency_key)
            )
            if not dependency or dependency.get("state") != AVAILABLE:
                raise ValueError(
                    f"{name}.{key} is available but its input "
                    f"{dependency_name}.{dependency_key} is not"
                )

    # An exclusion claim without a passing positive control proves nothing.
    acl = categories.get("acl_deletion", {}).get("signals", {})
    control = acl.get(ACL_CONTROL_SIGNAL)
    for key, entry in acl.items():
        if not key.startswith("excluded_") or entry.get("state") != AVAILABLE:
            continue
        if not control or control.get("state") != AVAILABLE:
            raise ValueError(
                f"acl_deletion.{key} claims an exclusion while "
                f"{ACL_CONTROL_SIGNAL} is not available"
            )


def build(
    cluster: Cluster,
    broker_args: list[str],
    local: bool,
    repo: Repo | None = None,
) -> dict[str, Any]:
    repo = repo if repo is not None else Repo()
    collected_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    pod: dict[str, Any] | None = None
    pod_error: str | None = None
    try:
        pod = cluster.broker_pod()
    except ProbeError as err:
        pod_error = str(err)

    acl_paths: list[tuple[str, str]] = []
    try:
        acl_paths, _revision, _tracked = acl_candidate_paths(repo)
    except ProbeError:
        acl_paths = []

    session = BrokerSession()
    if pod is not None:
        try:
            cluster.broker_session(
                pod["metadata"]["name"], broker_args, session, session_driver(acl_paths)
            )
        except ProbeError as err:
            session.error = str(err)
    else:
        session.error = pod_error

    node = pod.get("spec", {}).get("nodeName") if pod else None
    host_ip = pod.get("status", {}).get("hostIP") if pod else None
    image = None
    if pod:
        for entry in pod.get("status", {}).get("containerStatuses", []):
            if entry.get("name") == BROKER_CONTAINER:
                image = entry.get("imageID") or entry.get("image")

    reached = session.by_key("status") is not None
    if local:
        mode = "local_binary"
        note = (
            "Collected against a locally built binary. This does NOT count as "
            "dogfooding evidence for the deployed service."
        )
    elif reached:
        mode = "deployed_broker"
        note = (
            "Collected in-pod against the deployed image digest, over the same "
            "git-sync worktree the serving process indexes. The MCP call starts a "
            "fresh process inside the running Pod rather than attaching to the "
            "long-lived stdio session, so index counts are a faithful rebuild of the "
            "same corpus, not a read of the serving process's own heap."
        )
    else:
        mode = "unavailable"
        note = f"The deployed broker could not be reached: {session.error}"

    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": ARTIFACT_KIND,
        "collector_version": COLLECTOR_VERSION,
        "collected_at": collected_at,
        "roadmap_item": ".workingdir2/99-roadmap.md T1 item 8",
        "run_target": {
            "mode": mode,
            "note": note,
            "pod": pod["metadata"]["name"] if pod else None,
            "namespace": BROKER_NAMESPACE if pod else None,
            "node": node,
            "host_ip": host_ip,
            "image": image,
            "broker_calls": len(session.results),
        },
        "categories": {
            "correctness": collect_correctness(repo),
            "citation": collect_citation(session),
            "time_freshness": collect_time_freshness(pod, pod_error, collected_at),
            "token": collect_token(session),
            "latency": collect_latency(cluster, session),
            "storage": collect_storage(session, pod, pod_error),
            "energy": collect_energy(cluster, node, host_ip, pod_error),
            "acl_deletion": collect_acl_deletion(session, repo),
            "backup": collect_backup(cluster, pod, pod_error),
            "rollback": collect_rollback(cluster, repo, pod, pod_error),
        },
    }


def render(artifact: dict[str, Any]) -> str:
    """Markdown wrapper. .workingdir2 tracks *.md only, so the artifact is Markdown."""
    target = artifact["run_target"]
    lines = [
        "---",
        "name: knowledge-dogfood-evidence",
        "lifecycle: generated",
        "authority: dogfood-evidence-artifact",
        f"updated: {artifact['collected_at'][:10]}",
        "---",
        "",
        "# Knowledge broker dogfooding evidence",
        "",
        f"Schema `{artifact['schema_version']}` | collector `{artifact['collector_version']}` "
        f"| collected `{artifact['collected_at']}`.",
        f"Covers all ten evidence categories in {artifact['roadmap_item']}.",
        "",
        f"**Run target: `{target['mode']}`** — {target['note']}",
        "",
    ]
    if target.get("pod"):
        lines += [
            f"Pod `{target['pod']}` in namespace `{target['namespace']}` on node "
            f"`{target['node']}`, image `{target['image']}`.",
            "",
        ]
    for name in CATEGORIES:
        category = artifact["categories"][name]
        lines += [f"## {name}", "", category["description"], ""]
        lines += ["| signal | state | value | provenance / reason |", "| --- | --- | --- | --- |"]
        for key, entry in category["signals"].items():
            if entry["state"] == AVAILABLE:
                value = json.dumps(entry["value"])
                detail = entry["provenance"]
            else:
                value = "_unavailable_"
                detail = f"**{entry['reason']}** (probe: {entry['provenance']})"
            value = value.replace("|", "\\|")
            detail = detail.replace("|", "\\|")
            lines.append(f"| `{key}` | {entry['state']} | {value} | {detail} |")
        lines.append("")
    lines += [
        "## Canonical artifact",
        "",
        "Machine-readable form. Every number above re-derives from the provenance string.",
        "",
        "```json",
        json.dumps(artifact, indent=2, sort_keys=True),
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=".workingdir2/evidence/dogfood",
        help="directory for the artifact (tracked path; Markdown only)",
    )
    parser.add_argument(
        "--broker-args",
        default="--mcp-sdk --repository-root /repo/current",
        help="arguments passed to archeion-knowledge-mcp inside the Pod",
    )
    parser.add_argument(
        "--repo-root", default=".", help="local clone the cited Git artifacts are read from"
    )
    parser.add_argument(
        "--local", action="store_true", help="mark the run as a local binary, not dogfooding"
    )
    parser.add_argument(
        "--no-cluster", action="store_true", help="record every cluster signal as unavailable"
    )
    parser.add_argument(
        "--no-repo", action="store_true", help="record every local-repository signal as unavailable"
    )
    parser.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = parser.parse_args(argv)

    cluster = Cluster(kubectl=not args.no_cluster)
    repo = Repo(args.repo_root, enabled=not args.no_repo)
    artifact = build(cluster, args.broker_args.split(), args.local, repo)
    validate(artifact)
    document = render(artifact)

    if args.stdout:
        sys.stdout.write(document)
        return 0

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = artifact["collected_at"].replace(":", "").replace("-", "")
    path = out_dir / f"{stamp}-{artifact['run_target']['mode']}.md"
    path.write_text(document, encoding="utf-8")
    sys.stdout.write(f"{path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
