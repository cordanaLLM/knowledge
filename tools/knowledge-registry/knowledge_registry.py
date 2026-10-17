#!/usr/bin/env python3
"""Deterministic, bounded, observation-only component registry tooling.

The executable is intentionally incapable of source acquisition, source
admission, signing, release, pointer mutation, or Kubernetes mutation.  It
discovers a Git-tracked repository, imports separately captured read-only live
JSON, merges candidate observations, and validates canonical output.  Every
discovered use is retained as a UsageOccurrence; missing closure is a typed
gap, never an omitted success.
"""

from __future__ import annotations

import argparse
import ast
import copy
import dataclasses
import fcntl
import hashlib
import importlib.metadata
import json
import math
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import types
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import parse_qs, quote, unquote, unquote_plus, urlparse, urlsplit

_LOADED_MODULE_CODE = sys._getframe().f_code

MANIFEST_VERSION = 2
MANIFEST_SCHEMA_VERSION = "2.0.0"
MANIFEST_RECORD_KIND = "generated_discovery_manifest"
MANIFEST_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"
GENERATOR_NAME = "knowledge-registry"
GENERATOR_VERSION = "2"
GENERATOR_SOURCE_REF = "tools/knowledge-registry/knowledge_registry.py"
CANONICALIZATION = "archeion-canonical-json-v1"
ARRAY_FIELDS = (
    "sources",
    "components",
    "versions",
    "occurrences",
    "dependency_edges",
    "gaps",
)
ID_FIELDS = {
    "sources": "source_id",
    "components": "component_id",
    "versions": "component_version_id",
    "occurrences": "occurrence_id",
    "dependency_edges": "edge_id",
    "gaps": "gap_id",
}
ID_PREFIXES = {
    "sources": "src",
    "components": "cmp",
    "versions": "ver",
    "occurrences": "occ",
    "dependency_edges": "edge",
    "gaps": "gap",
}

SKIP_DIRS = {
    ".claude",
    ".git",
    ".terraform",
    ".venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
}
IGNORED_CANONICAL_LOCKFILES = {"chart.lock"}
TARGETED_INSTALL_SCRIPTS = {
    "ansible/prepare-node.sh",
    "apps/infra/node-gpu-firmware/files/fw-update.sh",
    "scripts/setup/linux-apt-mise.sh",
}
NON_AUTHORITATIVE_DISCOVERY_PREFIXES = (
    "docs/app-template/",
    "docs/argo-events/",
    "docs/argo-rollouts/",
    "docs/argo-workflows/",
    "docs/argocd/",
    "docs/cilium/",
    "docs/kube-prometheus-stack/",
)
MUTABLE_REFS = {"latest", "edge", "main", "master", "head", "stable", "develop", "dev"}
MODEL_UPSTREAM_LINEAGE_RELATIONSHIPS = {"converts-to", "publishes"}
RANGE_RE = re.compile(r"(?:^|\s)(?:[~^*]|>=?|<=?|!=)|\s(?:and|or)\s", re.IGNORECASE)
TEMPLATE_EXPRESSION_RE = re.compile(
    r"(?:\{\{|\$\{|<%|\$\(|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)"
)
RESOLUTION_STATES = {"resolved", "partial", "unresolved", "ambiguous", "unavailable"}
LIFECYCLE_STATES = {
    "conditional",
    "deployed",
    "historical-runtime",
    "orphaned",
    "planned",
    "reference",
    "reference-only",
    "rejected",
    "repository-used",
    "retired",
    "runtime-resolved",
    "sbom-observed",
    "test-only",
}
DIRECTNESS_STATES = {"root", "direct", "transitive"}
DEPENDENCY_SCOPES = {
    "api",
    "automation",
    "build",
    "ci",
    "deployment",
    "development",
    "optional",
    "platform",
    "runtime",
    "test",
    "unknown",
}
OFFICIAL_CHANNEL_TYPES = (
    "docs",
    "reference",
    "api",
    "schema",
    "config",
    "release",
    "changelog",
    "migration",
    "deprecation",
    "advisory",
    "source",
    "license",
    "package",
    "artifact",
    "sbom",
    "provenance",
)
EXPLICIT_CHANNEL_GAP_STATES = {"absent", "ambiguous", "unresolved", "unavailable"}
# Builder.manifest() re-derives these gap types in full from merged state, so
# merge recomputes them; oci-platform-multi also has an import-time emitter and
# must keep carrying.
MERGE_REDERIVED_GAP_TYPES = frozenset(
    {
        "dynamic-ref-unresolved",
        "exact-version-unresolved",
        "gitops-self-reference",
        "gitops-self-reference-observed",
        "model-artifact-lineage-unresolved",
        "mutable-ref",
        "oci-artifact-version-observed",
        "oci-platform-index",
        "oci-platform-observed",
        "oci-platform-unresolved",
        "oci-tag-digest-conflict",
        "official-channel-unresolved",
        "test-fixture-reference",
        "transitive-inventory-unavailable",
        "version-unobserved",
    }
)
SBOM_PATH_ARTIFACT_KINDS = frozenset({"application", "library"})
CHANNEL_POLICY_SCHEMA_RELATIVE = "knowledge/registry/schemas/channel-policy.schema.json"
CHANNEL_POLICY_RECORD_KIND = "channel_policy"
CHANNEL_POLICY_DISPOSITIONS = frozenset(
    {
        "available",
        "derived-unverified",
        "absent",
        "ambiguous",
        "unavailable",
        "unresolved",
    }
)
CHANNEL_POLICY_TABLE_SELECTOR = "component-table"
CHANNEL_POLICY_ROW_DISPOSITIONS = frozenset(
    {
        "available",
        "absent",
        "ambiguous",
        "unavailable",
        "unresolved",
    }
)
CHANNEL_POLICY_ROW_PASSES = frozenset({"1", "2", "3", "sweep"})
CHANNEL_POLICY_PROVENANCE_TABLE = "provenance"
CHANNEL_POLICY_COMPONENT_ID_RE = re.compile(r"^cmp-[0-9a-f]{24}$")
CHANNEL_POLICY_SAMPLE_SIZE = 20
CHANNEL_POLICY_REVIEWER_PREFIX = "channel-policy:"
CHANNEL_POLICY_CITATION_RE = re.compile(
    r"^(?P<path>[^@\s]+\.json)@(?P<hash>sha256:[0-9a-f]{64})$"
)
CHANNEL_POLICY_REVIEWER_RE = re.compile(
    r"^channel-policy:(?P<record_id>[^@\s]+)@(?P<hash>sha256:[0-9a-f]{64})$"
)
MAX_CHANNEL_POLICIES = 64
OFFICIAL_PROPOSAL_STATES = {
    "ambiguous",
    "failed",
    "proposed",
    "unavailable",
    "unresolved",
}
OFFICIAL_REVIEW_STATES = {"accepted", "pending", "rejected", "reopened", "superseded"}
OFFICIAL_CONFIDENCE_LEVELS = {"high", "medium", "low", "none"}
OFFICIAL_RESOLUTION_STATES = {"failed", "partial", "resolved", "unresolved"}
OFFICIAL_RESOLVER_PRODUCER = "knowledge-registry-official-resolver-v1"
OFFICIAL_RESOLVER_MODEL_DEPENDENCY = "none"
OFFICIAL_RESOLVER_EVIDENCE_METHOD = "deterministic-authoritative-protocol"
OFFICIAL_RESOLUTION_CACHE_CONTRACT = "archeion-official-resolution-cache-evidence-v1"
OFFICIAL_RESOLUTION_NETWORK_MODES = {
    "offline-cache-only",
    "online-cache-read-through",
    "online-cache-refresh",
}
OFFICIAL_TARGET_ECOSYSTEMS = {
    "apk",
    "deb",
    "go-toolchain",
    "golang",
    "helm",
    "node-toolchain",
    "npm",
    "oci",
    "python-toolchain",
    "pypi",
    "rpm",
}
FULL_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
MANIFEST_ID_RE = re.compile(r"mft-[0-9a-f]{64}")
CODEX_GENERATED_PROJECTION_PATH_RE = re.compile(
    r"(?:^|/)\.workingdir2/cache/knowledge-registry/"
    r"projection-mft-[0-9a-f]{64}\.sqlite\Z"
)
CODEX_CANONICAL_PROJECTION_REF = (
    b".workingdir2/cache/knowledge-registry/projection-mft-" + (b"0" * 64) + b".sqlite"
)
CAPTURE_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)

LIVE_CAPTURE_RECORD_KIND = "live_capture_manifest"
LIVE_CAPTURE_CONTRACT_VERSION = 4
LIVE_CAPTURE_SUPPORTED_CONTRACT_VERSIONS = frozenset({1, 2, 3, 4})
LIVE_CAPTURE_PROJECTION = {
    "policy": "identity-only-no-sensitive-literals-v1",
    "sensitive_fields": "omitted",
    "version": 1,
}
LIVE_CAPTURE_V1_SURFACES = (
    "server-version",
    "nodes",
    "argo",
    "controllers",
    "pods",
    "crds-openapi",
    "workload-sboms",
    "cluster-sboms",
)
LIVE_REQUIRED_SURFACES = LIVE_CAPTURE_V1_SURFACES + (
    "api-discovery",
    "builtin-openapi",
)
LIVE_CONTROLLER_KINDS = (
    "CronJob",
    "DaemonSet",
    "Deployment",
    "Job",
    "ReplicaSet",
    "StatefulSet",
)
LIVE_SURFACE_RESOURCE_KINDS_V3 = {
    "server-version": (),
    "nodes": ("Node",),
    "argo": ("Application", "ApplicationSet"),
    "controllers": LIVE_CONTROLLER_KINDS,
    "pods": ("Pod",),
    "crds-openapi": ("CustomResourceDefinition",),
    "workload-sboms": ("SbomReport",),
    "cluster-sboms": ("ClusterSbomReport",),
    "api-discovery": ("APIVersions", "APIGroupList", "APIResourceList"),
    "builtin-openapi": ("OpenAPIv3Discovery", "OpenAPIv3Document"),
}
# v4 pages workload-sboms by namespace; the namespace index is its paging root.
LIVE_SURFACE_RESOURCE_KINDS = {
    **LIVE_SURFACE_RESOURCE_KINDS_V3,
    "workload-sboms": ("Namespace", "SbomReport"),
}
LIVE_NAMESPACE_INDEX_ENDPOINT = "/api/v1/namespaces"
LIVE_PAGED_SURFACES = frozenset({"workload-sboms"})
LIVE_SBOM_PAGE_ENDPOINT_TEMPLATE = (
    "/apis/aquasecurity.github.io/v1alpha1/namespaces/{namespace}/sbomreports"
)
LIVE_SBOM_PAGE_ENDPOINT_RE = re.compile(
    r"^/apis/aquasecurity\.github\.io/v1alpha1/namespaces/"
    r"(?P<namespace>[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)/sbomreports$"
)
LIVE_STATIC_ARTIFACTS_V3 = {
    "server-version": (("/version", "server-version"),),
    "nodes": (("/api/v1/nodes", "Node"),),
    "argo": (
        ("/apis/argoproj.io/v1alpha1/applications", "Application"),
        ("/apis/argoproj.io/v1alpha1/applicationsets", "ApplicationSet"),
    ),
    "controllers": (
        ("/apis/batch/v1/cronjobs", "CronJob"),
        ("/apis/apps/v1/daemonsets", "DaemonSet"),
        ("/apis/apps/v1/deployments", "Deployment"),
        ("/apis/batch/v1/jobs", "Job"),
        ("/apis/apps/v1/replicasets", "ReplicaSet"),
        ("/apis/apps/v1/statefulsets", "StatefulSet"),
    ),
    "pods": (("/api/v1/pods", "Pod"),),
    "crds-openapi": (
        (
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            "CustomResourceDefinition",
        ),
    ),
    "workload-sboms": (
        ("/apis/aquasecurity.github.io/v1alpha1/sbomreports", "SbomReport"),
    ),
    "cluster-sboms": (
        (
            "/apis/aquasecurity.github.io/v1alpha1/clustersbomreports",
            "ClusterSbomReport",
        ),
    ),
    "api-discovery": (("/api", "APIVersions"), ("/apis", "APIGroupList")),
    "builtin-openapi": (("/openapi/v3", "OpenAPIv3Discovery"),),
}
LIVE_STATIC_ARTIFACTS = {
    **LIVE_STATIC_ARTIFACTS_V3,
    "workload-sboms": ((LIVE_NAMESPACE_INDEX_ENDPOINT, "Namespace"),),
}
LIVE_SURFACE_STATES = {"captured", "failed", "unavailable"}
LIVE_CAPTURE_BOUNDS_V3 = {
    "artifact_bytes": 64 * 2**20,
    "capture_bytes": 512 * 2**20,
    "list_items": 250_000,
    "dynamic_queries": 4_096,
    "capture_commands": 8_211,
    "capture_seconds": 60 * 60,
}
# v4 adds one namespace-paged dynamic dimension: 17 + 3*4096 + 2 commands.
LIVE_CAPTURE_BOUNDS = {
    **LIVE_CAPTURE_BOUNDS_V3,
    "capture_commands": 12_307,
}
LIVE_CAPTURE_TIME_TOLERANCE_SECONDS = 5
LIVE_CAPTURE_GENERATOR_PATHS = (
    "tools/knowledge-registry/capture_live.py",
    "tools/knowledge-registry/knowledge_registry.py",
    "knowledge/registry/schemas/discovery-manifest.schema.json",
    "knowledge/registry/schemas/component-record.schema.json",
)
LIVE_CAPTURE_BLOCKING_GAPS = {
    "live-capture-manifest-missing",
    "live-capture-metadata-invalid",
    "live-crd-openapi-missing",
    "live-api-discovery-invalid",
    "live-export-unbound",
    "live-required-surface-missing",
    "live-required-surface-unavailable",
    "live-surface-content-mismatch",
    "live-surface-hash-mismatch",
    "live-inventory-truncated",
}

# All discovery and serialization work is bounded before an input can become
# part of a candidate.  These are format limits, not knobs controlled by the
# scanned repository.
MAX_GIT_OUTPUT_BYTES = 8 * 2**20
MAX_TRACKED_FILES = 20_000
MAX_DISCOVERY_FILES = 10_000
MAX_DISCOVERY_FILE_BYTES = 8 * 2**20
MAX_DISCOVERY_TOTAL_BYTES = 128 * 2**20
# W3 measured: 39.6 KB/derived record (W2b 463.2MB-210.9MB over 6,368); +1,099 W3/W4 records projects 507MB > 94% of 512 MiB, so 768 MiB.
MAX_JSON_INPUT_BYTES = 768 * 2**20
MAX_JSON_DEPTH = 128
# Paged-SBOM measured: 27.83 nodes and 1,235 B per edge, so the ratified 768 MiB
# envelope tops out near 18.1M nodes; 20M keeps bytes the binding resource guard.
MAX_JSON_NODES = 20_000_000
MAX_SERIALIZED_OUTPUT_BYTES = 768 * 2**20
MAX_SOURCES = 100_000
MAX_COMPONENTS = 100_000
MAX_VERSIONS = 200_000
MAX_OCCURRENCES = 400_000
# Paged-SBOM measured: 625 SbomReports need ~425k edges at 430.3 edges/report;
# 768 MiB holds ~652k, so 700k keeps bytes binding first across a doubled fleet.
MAX_DEPENDENCY_EDGES = 700_000
MAX_GAPS = 400_000
# Pre-W3 512 MiB envelope; manifests sealed with it re-seal byte-identically.
# Every value is a literal on purpose: an alias would let a raise above silently
# re-stamp this table and change 17 sealed manifest_ids.
MANIFEST_BOUNDS_V1 = {
    "tracked_files": 20_000,
    "discovery_files": 10_000,
    "discovery_file_bytes": 8 * 2**20,
    "discovery_total_bytes": 128 * 2**20,
    "json_input_bytes": 512 * 2**20,
    "json_depth": 128,
    "json_nodes": 10_000_000,
    "serialized_output_bytes": 512 * 2**20,
    "sources": 100_000,
    "components": 100_000,
    "versions": 200_000,
    "occurrences": 400_000,
    "dependency_edges": 400_000,
    "gaps": 400_000,
}
# Pre-paged-SBOM 768 MiB envelope; same freeze, one generation newer.
MANIFEST_BOUNDS_V2 = {
    **MANIFEST_BOUNDS_V1,
    "json_input_bytes": 768 * 2**20,
    "serialized_output_bytes": 768 * 2**20,
}
# Paged-SBOM envelope: same 768 MiB as V2, with the edge and node ceilings the
# measured comments above justify. Frozen literal for the same reason V1/V2 are:
# aliasing the MAX_ constants would let a later raise silently re-stamp this
# table and change already-sealed manifest_ids.
MANIFEST_BOUNDS_V3 = {
    **MANIFEST_BOUNDS_V2,
    "json_nodes": 20_000_000,
    "dependency_edges": 700_000,
}
# Every historical envelope stays known-good so sealed manifest_ids stay reproducible.
MANIFEST_BOUNDS_KNOWN = (MANIFEST_BOUNDS_V1, MANIFEST_BOUNDS_V2, MANIFEST_BOUNDS_V3)
MAX_DISCOVERY_INPUTS = 20_000
MAX_EXECUTABLE_BYTES = 128 * 2**20
MAX_SCHEMA_ERRORS = 20
JSONSCHEMA_VERSION = "4.26.0"
DISCOVERY_SCHEMA_RELATIVE = "knowledge/registry/schemas/discovery-manifest.schema.json"
# v1.1 adds optional registry_kind/registry_identity; the sealed P1-SRC-02
# ceremony keeps byte-pinning the frozen v1.0 file.
REVIEWED_SCHEMA_RELATIVE = (
    "knowledge/registry/schemas/component-record-v1.1.schema.json"
)
SNAPSHOT_RECEIPT_SCHEMA_RELATIVE = (
    "knowledge/registry/schemas/channel-snapshot-receipt.schema.json"
)
ACCEPTED_DEVIATION_SCHEMA_RELATIVE = (
    "knowledge/registry/schemas/accepted-deviation.schema.json"
)
ACCEPTED_DEVIATION_RECORD_KIND = "accepted_deviation"
ACCEPTED_DEVIATION_KEY = "accepted_deviation"
ACCEPTED_DEVIATION_AXES = frozenset({"closure", "identity"})
ACCEPTED_DEVIATION_CITATION_RE = re.compile(
    r"^(?P<path>[^@\s]+\.json)@(?P<hash>sha256:[0-9a-f]{64})$"
)
MAX_ACCEPTED_DEVIATIONS = 32
GIT_COMMIT_ID_RE = re.compile(r"^[0-9a-f]{40}$")
GITOPS_OBSERVATION_KEY = "gitops_source_observation"
GITOPS_OBSERVATION_RESOLVERS = frozenset({"git-commit-object-receipt"})
GITOPS_COMMIT_MEDIA_TYPE = "application/x-git-commit"
CHANNEL_ID_COMPONENT_RE = re.compile(r":(?P<component_id>cmp-[0-9a-f]{24}):[a-z-]+$")
ISO_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
SNAPSHOT_RECEIPT_STATUSES = frozenset(
    {"fetched", "verified", "fetch-failed", "parse-failed", "unavailable"}
)
SNAPSHOT_SATISFYING_STATUSES = frozenset({"fetched", "verified"})
SNAPSHOT_CAS_MAX_BYTES = 64 * 2**20
MAX_SNAPSHOT_RECEIPT_ROWS = 20_000
# Mirrors component-record-v1.1 $defs.immutableResolutionValue exactly.
SNAPSHOT_MUTABLE_RESOLUTION_RE = re.compile(
    r"^(?:refs/(?:heads|remotes)/.+"
    r"|[Bb][Rr][Aa][Nn][Cc][Hh]:.+"
    r"|[Ll][Aa][Tt][Ee][Ss][Tt]|[Ss][Tt][Aa][Bb][Ll][Ee]"
    r"|[Cc][Uu][Rr][Rr][Ee][Nn][Tt]|[Hh][Ee][Aa][Dd]|[Mm][Aa][Ii][Nn]"
    r"|[Mm][Aa][Ss][Tt][Ee][Rr]|[Tt][Rr][Uu][Nn][Kk]|[Dd][Ee][Vv]"
    r"|[Dd][Ee][Vv][Ee][Ll][Oo][Pp]"
    r"|[Dd][Ee][Vv][Ee][Ll][Oo][Pp][Mm][Ee][Nn][Tt]"
    r"|[Nn][Ii][Gg][Hh][Tt][Ll][Yy]|[Ee][Dd][Gg][Ee]"
    r"|[Cc][Aa][Nn][Aa][Rr][Yy])$"
)
MAX_GIT_METADATA_BYTES = 64 * 2**20
MAX_REPOSITORY_DISCOVERY_SECONDS = 5 * 60
DEFAULT_GIT_EXECUTABLE = Path("/usr/bin/git")
FIXED_SUBPROCESS_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_EXTERNAL_DIFF": "",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
    "PAGER": "cat",
}
SAFE_GIT_OPTIONS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "diff.external=",
    "-c",
    "core.pager=cat",
    "--no-pager",
)

CANDIDATE_ARRAY_BOUNDS = {
    "sources": MAX_SOURCES,
    "components": MAX_COMPONENTS,
    "versions": MAX_VERSIONS,
    "occurrences": MAX_OCCURRENCES,
    "dependency_edges": MAX_DEPENDENCY_EDGES,
    "gaps": MAX_GAPS,
}


class RegistryInputError(ValueError):
    """A stable fail-closed input or capture error."""


def _reject_duplicate_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryInputError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise RegistryInputError(f"non-finite JSON number {value!r} is unsupported")


def _validate_json_shape(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise RegistryInputError(
                f"JSON document exceeds {MAX_JSON_NODES} structural nodes"
            )
        if depth > MAX_JSON_DEPTH:
            raise RegistryInputError(
                f"JSON document exceeds depth bound {MAX_JSON_DEPTH}"
            )
        if isinstance(current, dict):
            for key in current:
                try:
                    key.encode("utf-8")
                except UnicodeError as exc:
                    raise RegistryInputError(
                        "JSON document contains an invalid Unicode object key"
                    ) from exc
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeError as exc:
                raise RegistryInputError(
                    "JSON document contains an invalid Unicode string"
                ) from exc
        elif isinstance(current, float) and not math.isfinite(current):
            raise RegistryInputError("JSON document contains a non-finite number")
        elif (
            isinstance(current, int)
            and not isinstance(current, bool)
            and not -(2**63) <= current <= 2**63 - 1
        ):
            raise RegistryInputError(
                "JSON document contains an integer outside signed 64-bit range"
            )


def parse_json_bytes(
    raw: bytes,
    *,
    label: str,
    max_bytes: int = MAX_JSON_INPUT_BYTES,
) -> Any:
    if len(raw) > max_bytes:
        raise RegistryInputError(
            f"{label} exceeds byte bound {max_bytes} ({len(raw)} bytes)"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryInputError(f"{label} is not UTF-8 JSON") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise RegistryInputError(f"{label} is not valid JSON: {exc}") from exc
    _validate_json_shape(value)
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def stable_id(prefix: str, *parts: Any) -> str:
    payload = canonical_json(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:24]}"


def argo_application_identity(kind: str, namespace: str, name: str) -> str:
    """Return the shared desired/live identity for an Argo application object."""

    return f"argocd:{kind}:{namespace or 'argocd'}:{name}"


def scalar(value: str) -> str:
    value = value.strip()
    if value and value[0:1] == value[-1:] and value[0] in "\"'":
        value = value[1:-1]
    return value.strip()


def json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def resolve_json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise KeyError("invalid JSON Pointer")
    current = value
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            current = current[token]
        elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            current = current[int(token)]
        else:
            raise KeyError("unresolved JSON Pointer")
    return current


def validate_live_evidence_pointers(
    manifest: Mapping[str, Any], payload_by_source_id: Mapping[str, Any]
) -> int:
    sources = {
        str(source.get("source_id") or ""): source
        for source in manifest.get("sources", [])
        if isinstance(source, Mapping)
    }
    payload_by_uri = {
        str(sources[source_id].get("evidence_uri") or ""): payload
        for source_id, payload in payload_by_source_id.items()
        if source_id in sources
    }
    checked = 0

    def resolve_evidence(evidence: str, record_kind: str) -> None:
        nonlocal checked
        evidence_uri, separator, pointer = evidence.partition("#")
        if not evidence_uri.startswith("live-export:"):
            return
        payload = payload_by_uri.get(evidence_uri)
        if payload is None:
            raise RegistryInputError(
                f"live {record_kind} evidence source is not bound to an input"
            )
        try:
            resolve_json_pointer(payload, pointer if separator else "")
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RegistryInputError(
                f"live {record_kind} evidence pointer is unresolved at "
                f"{pointer or '/'}"
            ) from exc
        checked += 1

    for occurrence in manifest.get("occurrences", []):
        if not isinstance(occurrence, Mapping):
            continue
        source_id = str(occurrence.get("source_id") or "")
        source = sources.get(source_id)
        if source is None or source.get("source_type") != "live-export":
            continue
        if source_id not in payload_by_source_id:
            raise RegistryInputError(
                "live occurrence evidence source is not bound to an input"
            )
        locator = str(occurrence.get("evidence_locator") or "")
        resolve_evidence(
            f"{source.get('evidence_uri')}#{locator}",
            "occurrence",
        )
    for version in manifest.get("versions", []):
        if not isinstance(version, Mapping):
            continue
        for evidence in version.get("evidence", []):
            if isinstance(evidence, str):
                resolve_evidence(evidence, "version")
    for gap in manifest.get("gaps", []):
        if not isinstance(gap, Mapping):
            continue
        for evidence in gap.get("evidence", []):
            if isinstance(evidence, str):
                resolve_evidence(evidence, "gap")
    return checked


def sorted_records(records: Iterable[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return sorted(
        records, key=lambda item: (str(item.get(key, "")), canonical_json(item))
    )


def looks_exact(version: str | None) -> bool:
    if not version:
        return False
    raw_value = version.strip()
    if not raw_value or TEMPLATE_EXPRESSION_RE.search(raw_value):
        return False
    value = raw_value.lower()
    if value in MUTABLE_REFS or value.startswith(("refs/heads/", "branch:")):
        return False
    if RANGE_RE.search(value) or "||" in value or "," in value:
        return False
    return True


def normalize_git_repository_url(value: str) -> str:
    """Reduce ssh/https/scp git URL forms to one comparable host/path identity."""

    raw = value.strip().lower().removeprefix("git+")
    raw = re.sub(r"^(?:ssh|git|https?)://", "", raw)
    match = re.match(r"^(?:[\w.~-]+@)?([\w.-]+(?::\d+)?)[:/](.+)$", raw)
    if not match:
        return raw.rstrip("/").removesuffix(".git")
    host, path = match.groups()
    return f"{host.split(':', 1)[0]}/{path.strip('/').removesuffix('.git')}"


def channel_is_available(channel: Mapping[str, Any]) -> bool:
    return bool(
        channel.get("availability_state", "available") == "available"
        and channel.get("canonical_uri")
    )


def channel_class_is_reviewed(channel: Mapping[str, Any]) -> bool:
    if channel.get("review_state") != "accepted":
        return False
    state = str(channel.get("availability_state") or "")
    return channel_is_available(channel) or state in EXPLICIT_CHANNEL_GAP_STATES


def reviewed_record_channels(
    channels: Iterable[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    """The channel slots a reviewed record contributed, never the seeded ones."""

    return [
        channel
        for channel in channels
        if isinstance(channel, Mapping) and channel.get("reviewed_component_id")
    ]


def unresolved_reviewed_channels(
    channels: Iterable[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    """The reviewed slots left short of reviewed-and-available, at any grain."""

    return [
        channel
        for channel in reviewed_record_channels(channels)
        if not (channel_class_is_reviewed(channel) and channel_is_available(channel))
    ]


def sbom_path_artifact_component(component: Mapping[str, Any]) -> bool:
    """Purl-less SBOM file-path artifacts leave the channel denominator (D-R2-2b)."""

    kind = str(component.get("kind") or "")
    return (
        kind in SBOM_PATH_ARTIFACT_KINDS
        and str(component.get("ecosystem") or "") == kind
        and not component.get("purl")
    )


def component_requires_official_channels(component: Mapping[str, Any]) -> bool:
    return bool(
        component.get("official_channel_required", True)
    ) and not sbom_path_artifact_component(component)


def version_metadata_entry(version: Mapping[str, Any], key: str) -> Any:
    """Read a version metadata entry, including the reviewed build_metadata lift."""

    metadata = version.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    if key in metadata:
        return metadata[key]
    build_metadata = metadata.get("build_metadata")
    return build_metadata.get(key) if isinstance(build_metadata, Mapping) else None


def gitops_source_observation(
    component: Mapping[str, Any], version: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Return the receipt-bound commit a deliberate self-repository ref pointed at."""

    metadata = component.get("metadata")
    if (
        str(component.get("ecosystem") or "") != "git"
        or not isinstance(metadata, Mapping)
        or metadata.get("self_repository") is not True
        or version.get("artifact_digest")
    ):
        return None
    ref = str(
        version.get("source_ref") or version.get("resolved_version") or ""
    ).lower()
    if ref not in MUTABLE_REFS and not ref.startswith("refs/heads/"):
        return None
    observation = version_metadata_entry(version, GITOPS_OBSERVATION_KEY)
    if not isinstance(observation, Mapping):
        return None
    if (
        str(observation.get("observed_ref") or "").lower() != ref
        or not GIT_COMMIT_ID_RE.fullmatch(str(observation.get("observed_commit") or ""))
        or str(observation.get("resolver") or "") not in GITOPS_OBSERVATION_RESOLVERS
        or not FULL_SHA256_RE.fullmatch(
            str(observation.get("evidence_content_hash") or "")
        )
        or not valid_live_observed_at(observation.get("observed_at"))
    ):
        return None
    return dict(observation)


def oci_artifact_observation(
    component: Mapping[str, Any], version: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Return the receipt-bound registry manifest this OCI version resolves to."""

    if str(component.get("ecosystem") or "") != "oci":
        return None
    observation = version_metadata_entry(version, OCI_OBSERVATION_KEY)
    if not isinstance(observation, Mapping):
        return None
    split = canonical_oci_repository(component_oci_repository(component))
    reference = oci_artifact_reference(version)
    if split is None or reference is None:
        return None
    kind = str(observation.get("manifest_kind") or "")
    media_type = str(observation.get("manifest_media_type") or "")
    resolved_digest, _ = normalize_oci_digest(observation.get("resolved_digest"))
    platform = str(observation.get("platform") or "")
    platforms = [str(item) for item in observation.get("platforms", [])]
    if (
        kind not in OCI_OBSERVATION_KINDS
        or media_type not in OCI_ARTIFACT_MEDIA_TYPES
        or (kind == "index") != (media_type in OCI_INDEX_MEDIA_TYPES)
        or not resolved_digest
        or not platforms
        or sorted(set(platforms)) != platforms
        or any(not exact_oci_platform(item) for item in platforms)
        or str(observation.get("resolver") or "") not in OCI_OBSERVATION_RESOLVERS
        or str(observation.get("registry") or "") != split[0]
        or str(observation.get("repository") or "") != split[1]
        or str(observation.get("reference") or "") != reference[0]
        or str(observation.get("reference_kind") or "") != reference[1]
        or not valid_live_observed_at(observation.get("observed_at"))
        # The manifest bytes hash to the artifact digest; one value binds both.
        or str(observation.get("evidence_content_hash") or "") != resolved_digest
    ):
        return None
    if reference[1] == "digest" and reference[0] != resolved_digest:
        return None
    if kind == "manifest" and (len(platforms) != 1 or platform != platforms[0]):
        return None
    if kind == "index" and platform:
        return None
    return dict(observation)


def oci_platform_gap(
    version: Mapping[str, Any], observation: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Type a platform-less OCI version against its receipt-bound manifest identity."""

    if observation is None:
        return make_gap(
            "oci-platform-unresolved",
            "OCI artifact has no exact operating-system/architecture platform identity",
            component_id=version["component_id"],
            component_version_id=version["component_version_id"],
            evidence=version.get("evidence", []),
        )
    evidence = (
        *version.get("evidence", []),
        str(observation["evidence_content_hash"]),
    )
    if str(observation.get("manifest_kind") or "") == "index":
        return make_gap(
            "oci-platform-index",
            "OCI artifact is a multi-platform index; the per-platform children "
            f"{', '.join(str(item) for item in observation['platforms'])} carry the "
            "exact platform identity",
            component_id=version["component_id"],
            component_version_id=version["component_version_id"],
            evidence=evidence,
        )
    return make_gap(
        "oci-platform-observed",
        f"OCI artifact platform {observation['platform']} is bound to the "
        "receipt-verified registry image config",
        component_id=version["component_id"],
        component_version_id=version["component_version_id"],
        evidence=evidence,
    )


def component_has_accepted_available_channel(component: Mapping[str, Any]) -> bool:
    return any(
        isinstance(channel, Mapping)
        and channel_class_is_reviewed(channel)
        and channel_is_available(channel)
        for channel in component.get("official_channels", [])
    )


def split_image(image: str) -> tuple[str, str | None, str | None]:
    image = image.strip()
    digest = None
    tag = None
    repository = image
    if "@" in repository:
        repository, digest = repository.rsplit("@", 1)
    slash = repository.rfind("/")
    colon = repository.rfind(":")
    if colon > slash:
        repository, tag = repository[:colon], repository[colon + 1 :]
    return repository, tag, digest


OCI_REFERENCE_INVALID_REASONS = frozenset(
    {
        "empty-reference",
        "invalid-digest",
        "missing-repository",
        "multiple-digest-separators",
        "runtime-digest-without-valid-desired-reference",
    }
)
OCI_DEFAULT_REGISTRY = "docker.io"
OCI_REGISTRY_ALIASES = {
    "index.docker.io": OCI_DEFAULT_REGISTRY,
    "registry-1.docker.io": OCI_DEFAULT_REGISTRY,
}
OCI_INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    }
)
OCI_IMAGE_MEDIA_TYPES = frozenset(
    {
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    }
)
OCI_ARTIFACT_MEDIA_TYPES = OCI_INDEX_MEDIA_TYPES | OCI_IMAGE_MEDIA_TYPES
OCI_ATTESTATION_ANNOTATION = "vnd.docker.reference.type"
OCI_ATTESTATION_REFERENCE_TYPE = "attestation-manifest"
OCI_UNKNOWN_PLATFORM_SEGMENT = "unknown"
OCI_OBSERVATION_KEY = "oci_artifact_observation"
# Identity binders attach these as provenance, not as use sites.
IDENTITY_OBSERVATION_ROLES = frozenset(
    {"gitops-source-observation", "oci-artifact-observation"}
)
OCI_OBSERVATION_RESOLVERS = frozenset({"oci-registry-manifest"})
OCI_OBSERVATION_KINDS = frozenset({"index", "manifest"})
OCI_IDENTITY_PLAN_GAP_TYPES = frozenset(
    {"exact-version-unresolved", "oci-platform-unresolved"}
)
MAX_OCI_INDEX_ENTRIES = 4096
# An imported CycloneDX SBOM is the transitive inventory of its own subject only.
SBOM_INVENTORY_SUBJECT_ROLES = frozenset({"live-sbom-artifact"})
SBOM_INVENTORY_RELATIONSHIP = "contains"
SBOM_INVENTORY_RESOLVER = "cyclonedx-sbom"


def oci_image_reference_error(image: str) -> str | None:
    """Return a fixed structural error without deriving an OCI identity."""

    raw = image.strip()
    if not raw:
        return "empty-reference"
    separator_count = raw.count("@")
    if separator_count > 1:
        return "multiple-digest-separators"
    if separator_count == 1:
        repository, digest = raw.rsplit("@", 1)
        if not repository:
            return "missing-repository"
        if not FULL_SHA256_RE.fullmatch(digest):
            return "invalid-digest"
    return None


def normalize_oci_digest(value: str | None) -> tuple[str | None, str | None]:
    """Return a canonical immutable OCI digest or a typed rejection reason."""

    raw = str(value or "").strip()
    if not raw:
        return None, None
    if not FULL_SHA256_RE.fullmatch(raw):
        return None, "invalid-format"
    if raw == "sha256:" + "0" * 64:
        return None, "zero-placeholder"
    return raw, None


OCI_PLATFORM_RE = re.compile(
    r"[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?"
)


def normalize_oci_platform(value: str | None) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw or TEMPLATE_EXPRESSION_RE.search(raw):
        return None
    return raw if OCI_PLATFORM_RE.fullmatch(raw) else None


def exact_oci_platform(value: str | None) -> str | None:
    """normalize_oci_platform is purely syntactic; an unknown segment is not identity."""

    normalized = normalize_oci_platform(value)
    if normalized is None or OCI_UNKNOWN_PLATFORM_SEGMENT in normalized.split("/"):
        return None
    return normalized


def purl_oci_platform(purl: str) -> str | None:
    query = purl.split("?", 1)[1].split("#", 1)[0] if "?" in purl else ""
    qualifiers = parse_qs(query, keep_blank_values=False, strict_parsing=False)
    explicit = next(iter(qualifiers.get("platform", [])), "")
    if explicit:
        return normalize_oci_platform(explicit)
    operating_system = next(iter(qualifiers.get("os", [])), "")
    architecture = next(
        iter(qualifiers.get("arch", qualifiers.get("architecture", []))), ""
    )
    return normalize_oci_platform(
        f"{operating_system}/{architecture}"
        if operating_system and architecture
        else None
    )


def repository_has_registry(repository: str) -> bool:
    first_segment = repository.split("/", 1)[0]
    return "." in first_segment or ":" in first_segment or first_segment == "localhost"


def normalize_registry_server(server: str) -> str:
    value = server.strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.rstrip("/")
    host, separator, path = value.partition("/")
    host = {
        "index.docker.io": "docker.io",
        "registry-1.docker.io": "docker.io",
    }.get(host.lower(), host.lower())
    return f"{host}/{path}" if separator else host


def normalize_sbom_artifact_tag(tag: str) -> str:
    """Normalize Trivy reports that put a full image reference in `tag`."""

    value = tag.strip()
    if "/" not in value:
        return value
    _, parsed_tag, _ = split_image(value)
    return parsed_tag or ""


def canonical_oci_repository(repository: str | None) -> tuple[str, str] | None:
    """Split an image repository into its canonical (registry, path) pair."""

    value = str(repository or "").strip().strip("/")
    if not value or TEMPLATE_EXPRESSION_RE.search(value):
        return None
    if repository_has_registry(value):
        registry, _, path = value.partition("/")
        registry = OCI_REGISTRY_ALIASES.get(registry.lower(), registry.lower())
    else:
        registry, path = OCI_DEFAULT_REGISTRY, value
    if registry == OCI_DEFAULT_REGISTRY and "/" not in path:
        path = f"library/{path}"
    return (registry, path) if registry and path else None


def component_oci_repository(component: Mapping[str, Any]) -> str | None:
    """Repository from the image metadata, falling back to the purl qualifier."""

    metadata = component.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("oci_repository"):
        return str(metadata["oci_repository"])
    purl = str(component.get("purl") or "")
    query = purl.split("?", 1)[1].split("#", 1)[0] if "?" in purl else ""
    qualifiers = parse_qs(query, keep_blank_values=False, strict_parsing=False)
    return next(iter(qualifiers.get("repository_url", [])), "") or None


def oci_artifact_reference(version: Mapping[str, Any]) -> tuple[str, str] | None:
    """Return the (reference, kind) an OCI version addresses in its registry."""

    digest, _ = normalize_oci_digest(version.get("artifact_digest"))
    if digest:
        return digest, "digest"
    resolved = str(version.get("resolved_version") or "").strip()
    exact, _ = normalize_oci_digest(resolved)
    if exact:
        return exact, "digest"
    if not resolved or TEMPLATE_EXPRESSION_RE.search(resolved):
        return None
    return resolved, "tag"


def oci_canonical_uri(
    registry: str, repository: str, reference: str, reference_kind: str
) -> str:
    separator = "@" if reference_kind == "digest" else ":"
    return f"oci://{registry}/{repository}{separator}{reference}"


def oci_identity_plan(
    manifest: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Deduped registry-manifest fetch plan for every identity-gapped OCI version."""

    components = _manifest_component_map(manifest)
    versions = _manifest_version_map(manifest)
    targets: set[str] = set()
    for gap in manifest.get("gaps", []):
        if (
            not isinstance(gap, Mapping)
            or str(gap.get("gap_type") or "") not in OCI_IDENTITY_PLAN_GAP_TYPES
        ):
            continue
        version_id = str(gap.get("component_version_id") or "")
        component = components.get(str(gap.get("component_id") or ""), {})
        if version_id in versions and component.get("ecosystem") == "oci":
            targets.add(version_id)
    rows: dict[str, dict[str, Any]] = {}
    unfetchable: list[str] = []
    for version_id in sorted(targets):
        version = versions[version_id]
        component = components.get(str(version.get("component_id") or ""), {})
        split = canonical_oci_repository(component_oci_repository(component))
        reference = oci_artifact_reference(version)
        if split is None or reference is None:
            unfetchable.append(version_id)
            continue
        registry, repository = split
        value, reference_kind = reference
        uri = oci_canonical_uri(registry, repository, value, reference_kind)
        row = rows.setdefault(
            uri,
            {
                "canonical_uri": uri,
                "registry": registry,
                "repository": repository,
                "reference": value,
                "reference_kind": reference_kind,
                "component_version_ids": [],
            },
        )
        row["component_version_ids"].append(version_id)
    for row in rows.values():
        row["component_version_ids"].sort()
    return [rows[uri] for uri in sorted(rows)], unfetchable


def oci_manifest_identity(data: bytes) -> dict[str, Any]:
    """Re-derive an OCI manifest identity from its exact bytes; attestations drop out."""

    document = parse_json_bytes(
        data, label="OCI manifest", max_bytes=SNAPSHOT_CAS_MAX_BYTES
    )
    if not isinstance(document, Mapping):
        raise RegistryInputError("OCI manifest is not a JSON object")
    media_type = str(document.get("mediaType") or "")
    entries = document.get("manifests")
    if entries is None:
        config = document.get("config")
        config_digest, config_error = normalize_oci_digest(
            config.get("digest") if isinstance(config, Mapping) else None
        )
        if not config_digest:
            raise RegistryInputError(
                f"OCI manifest has no exact config digest ({config_error})"
            )
        return {
            "kind": "manifest",
            "manifest_media_type": media_type,
            "config_digest": config_digest,
            "children": [],
            "platforms": [],
            "excluded": [],
        }
    if not isinstance(entries, list) or len(entries) > MAX_OCI_INDEX_ENTRIES:
        raise RegistryInputError(
            "OCI index manifests[] is invalid or exceeds its bound"
        )
    children: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise RegistryInputError("OCI index entry is not a JSON object")
        digest, digest_error = normalize_oci_digest(entry.get("digest"))
        if not digest:
            raise RegistryInputError(
                f"OCI index entry has no exact digest ({digest_error})"
            )
        annotations = entry.get("annotations")
        reference_type = (
            str(annotations.get(OCI_ATTESTATION_ANNOTATION) or "")
            if isinstance(annotations, Mapping)
            else ""
        )
        platform = entry.get("platform")
        segments = [
            str((platform.get(key) if isinstance(platform, Mapping) else "") or "")
            .strip()
            .lower()
            for key in ("os", "architecture", "variant")
        ]
        normalized = _exact_platform_from_segments(segments)
        if reference_type == OCI_ATTESTATION_REFERENCE_TYPE:
            reason = "attestation"
        elif OCI_UNKNOWN_PLATFORM_SEGMENT in set(segments):
            reason = "unknown-platform"
        elif not normalized:
            reason = "platform-unexpressible"
        else:
            reason = ""
        if reason:
            excluded.append({"digest": digest, "reason": reason})
            continue
        children.append(
            {
                "digest": digest,
                "media_type": str(entry.get("mediaType") or ""),
                "platform": str(normalized),
            }
        )
    return {
        "kind": "index",
        "manifest_media_type": media_type,
        "config_digest": "",
        "children": sorted(
            children, key=lambda item: (item["platform"], item["digest"])
        ),
        "platforms": sorted({item["platform"] for item in children}),
        "excluded": sorted(excluded, key=lambda item: (item["digest"], item["reason"])),
    }


def _exact_platform_from_segments(segments: Sequence[str]) -> str:
    """Join os/architecture/variant positionally; a missing required segment is
    not expressible. Dropping empties would slide variant into the architecture
    slot and produce a plausible platform the source never named."""

    os_name, architecture, variant = (segments + ["", "", ""])[:3]
    if not os_name or not architecture:
        return ""
    joined = f"{os_name}/{architecture}" + (f"/{variant}" if variant else "")
    return exact_oci_platform(joined) or ""


def oci_config_platform(data: bytes) -> str | None:
    """Exact platform of a single OCI image from its config blob bytes."""

    document = parse_json_bytes(
        data, label="OCI image config", max_bytes=SNAPSHOT_CAS_MAX_BYTES
    )
    if not isinstance(document, Mapping):
        return None
    segments = [
        str(document.get(key) or "").strip().lower()
        for key in ("os", "architecture", "variant")
    ]
    return _exact_platform_from_segments(segments) or None


def purl_base(purl: str) -> str:
    value = purl.strip()
    if "#" in value:
        value = value.split("#", 1)[0]
    if "?" in value:
        path, query = value.split("?", 1)
    else:
        path, query = value, ""
    # A version delimiter appears after the final path slash. The leading @ in
    # a scoped npm name (pkg:npm/@scope/name) is part of the namespace.
    if path.rfind("@") > path.rfind("/"):
        path = path.rsplit("@", 1)[0]
    return f"{path}?{query}" if query else path


def purl_version(purl: str) -> str | None:
    path = purl.split("?", 1)[0].split("#", 1)[0]
    body = path[len("pkg:") :] if path.startswith("pkg:") else path
    if body.rfind("@") <= body.rfind("/"):
        return None
    return body.rsplit("@", 1)[1]


def ecosystem_from_purl(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return "unknown"
    return purl[4:].split("/", 1)[0].lower()


def name_from_purl(purl: str) -> tuple[str, str]:
    path = purl_base(purl).split("?", 1)[0]
    body = path.split("/", 1)[1] if "/" in path else path
    parts = body.split("/")
    if len(parts) == 1:
        return "", parts[0]
    return "/".join(parts[:-1]), parts[-1]


def golang_module_namespace_name(module: str) -> tuple[str, str]:
    """Host-first split; a bare vanity host serves as namespace and name."""

    if "/" in module:
        namespace, _, short_name = module.rpartition("/")
        return namespace, short_name
    if "." in module and "%" not in module:
        return module, module
    return "", module


def package_purl(ecosystem: str, name: str, version: str | None = None) -> str:
    encoded = "/".join(quote(part, safe="@._-+") for part in name.strip("/").split("/"))
    result = f"pkg:{ecosystem}/{encoded}"
    if version:
        result += f"@{quote(version, safe='._-+:~') }"
    return result


class Builder:
    def __init__(self) -> None:
        self.sources: dict[str, dict[str, Any]] = {}
        self.components: dict[str, dict[str, Any]] = {}
        self.versions: dict[str, dict[str, Any]] = {}
        self.occurrences: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.extra_gaps: dict[str, dict[str, Any]] = {}
        self.discovery_inputs: dict[str, dict[str, Any]] = {}
        self.node_platforms: dict[str, str] = {}
        self.self_repository_urls: frozenset[str] = frozenset()
        self.helm_lock_policy_evidence: tuple[str, ...] = ()
        self.latest_image_fixture_policy: (
            tuple[re.Pattern[str], tuple[str, ...]] | None
        ) = None
        self.accepted_deviations: tuple[Mapping[str, Any], ...] = ()

    @staticmethod
    def _merge_bounded(
        target: dict[str, dict[str, Any]],
        key: str,
        record: Mapping[str, Any],
        *,
        limit: int,
        label: str,
    ) -> None:
        if key not in target and len(target) >= limit:
            raise RegistryInputError(f"{label} exceeds record bound {limit}")
        target[key] = merge_dicts(target.get(key, {}), record)

    def add_discovery_input(
        self,
        evidence_uri: str,
        *,
        content_hash: str | None,
        disposition: str,
        scanners: Sequence[str] = (),
        tracked: bool = True,
        evidence_class: str = "repository",
        error: str | None = None,
    ) -> str:
        discovery_input_id = stable_id("din", evidence_uri, content_hash or "")
        record: dict[str, Any] = {
            "discovery_input_id": discovery_input_id,
            "evidence_uri": evidence_uri,
            "disposition": disposition,
            "scanners": sorted(set(scanners)),
            "tracked": bool(tracked),
            "evidence_class": evidence_class,
        }
        if content_hash:
            record["content_hash"] = content_hash
        if error:
            record["error"] = error
        self._merge_bounded(
            self.discovery_inputs,
            discovery_input_id,
            record,
            limit=MAX_DISCOVERY_INPUTS,
            label="discovery inputs",
        )
        return discovery_input_id

    def add_source(
        self,
        path: str,
        source_type: str,
        *,
        content_hash: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        # A source is an immutable observation, not merely an authority URI.  A
        # changed payload therefore cannot be silently deep-merged into the old
        # observation under the same identity.
        source_id = stable_id("src", source_type, path, content_hash or "")
        record: dict[str, Any] = {
            "source_id": source_id,
            "source_type": source_type,
            "evidence_uri": path,
        }
        if content_hash:
            record["content_hash"] = content_hash
        if metadata:
            record["metadata"] = dict(metadata)
        self._merge_bounded(
            self.sources,
            source_id,
            record,
            limit=MAX_SOURCES,
            label="sources",
        )
        return source_id

    def add_component(
        self,
        *,
        kind: str,
        ecosystem: str,
        name: str,
        namespace: str = "",
        purl: str | None = None,
        identity: str | None = None,
        lifecycles: Sequence[str] = ("repository-used",),
        metadata: Mapping[str, Any] | None = None,
        official_channels: Sequence[Mapping[str, Any]] = (),
        official_channel_required: bool = True,
    ) -> str:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (kind, ecosystem, name)
        ):
            raise RegistryInputError(
                "component kind, ecosystem, and name must be non-empty strings"
            )
        base_purl = purl_base(purl) if purl else None
        identity_value = identity or base_purl or f"{ecosystem}:{namespace}:{name}"
        component_id = stable_id("cmp", kind, identity_value.lower())
        record: dict[str, Any] = {
            "component_id": component_id,
            "kind": kind,
            "ecosystem": ecosystem,
            "namespace": namespace,
            "name": name,
            "lifecycles": sorted(set(lifecycles)),
            "official_channels": [dict(item) for item in official_channels],
            "official_channel_required": bool(official_channel_required),
        }
        if base_purl:
            record["purl"] = base_purl
        if metadata:
            record["metadata"] = dict(metadata)
        self._merge_bounded(
            self.components,
            component_id,
            record,
            limit=MAX_COMPONENTS,
            label="components",
        )
        return component_id

    def add_version(
        self,
        component_id: str,
        *,
        resolved_version: str | None = None,
        constraint: str | None = None,
        source_ref: str | None = None,
        artifact_digest: str | None = None,
        platform: str | None = None,
        resolution_state: str | None = None,
        evidence: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        resolution_state = resolution_state or (
            "resolved"
            if artifact_digest
            or looks_exact(resolved_version)
            or (source_ref and looks_exact(source_ref))
            else "unresolved"
        )
        component_version_id = stable_id(
            "ver",
            component_id,
            resolved_version or "",
            constraint or "",
            source_ref or "",
            artifact_digest or "",
            platform or "",
        )
        record: dict[str, Any] = {
            "component_version_id": component_version_id,
            "component_id": component_id,
            "resolution_state": resolution_state,
            "evidence": sorted(set(evidence)),
        }
        for key, value in (
            ("resolved_version", resolved_version),
            ("constraint", constraint),
            ("source_ref", source_ref),
            ("artifact_digest", artifact_digest),
            ("platform", platform),
        ):
            if value not in (None, ""):
                record[key] = value
        if metadata:
            record["metadata"] = dict(metadata)
        self._merge_bounded(
            self.versions,
            component_version_id,
            record,
            limit=MAX_VERSIONS,
            label="versions",
        )
        return component_version_id

    def add_occurrence(
        self,
        component_id: str,
        component_version_id: str,
        source_id: str,
        *,
        locator: str,
        role: str,
        raw_value: str,
        root_id: str | None = None,
        directness: str = "direct",
        dependency_scope: str = "runtime",
        optional: bool = False,
        lifecycle: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        lifecycle = lifecycle or self.lifecycle_for_source(source_id)
        occurrence_id = stable_id(
            "occ",
            source_id,
            locator,
            role,
            component_version_id,
            raw_value,
            root_id or "",
        )
        record: dict[str, Any] = {
            "occurrence_id": occurrence_id,
            "component_id": component_id,
            "component_version_id": component_version_id,
            "source_id": source_id,
            "evidence_locator": locator,
            "role": role,
            "raw_value": raw_value,
            "directness": directness,
            "dependency_scope": dependency_scope,
            "optional": bool(optional),
            "lifecycle": lifecycle,
        }
        if root_id:
            record["root_id"] = root_id
        if metadata:
            record["metadata"] = dict(metadata)
        self._merge_bounded(
            self.occurrences,
            occurrence_id,
            record,
            limit=MAX_OCCURRENCES,
            label="occurrences",
        )
        return occurrence_id

    def lifecycle_for_source(self, source_id: str) -> str:
        evidence_class = (
            self.sources.get(source_id, {}).get("metadata", {}).get("evidence_class")
        )
        return {
            "test": "test-only",
            "reference": "reference-only",
            "scratch": "reference-only",
        }.get(str(evidence_class), "repository-used")

    def add_edge(
        self,
        from_version_id: str,
        to_version_id: str,
        *,
        relationship: str,
        source_occurrence_id: str,
        constraint: str | None = None,
        scope: str = "runtime",
        optional: bool = False,
        resolver: str = "manifest",
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        edge_id = stable_id(
            "edge",
            from_version_id,
            to_version_id,
            relationship,
            source_occurrence_id,
            scope,
            constraint or "",
        )
        record: dict[str, Any] = {
            "edge_id": edge_id,
            "from_component_version_id": from_version_id,
            "to_component_version_id": to_version_id,
            "relationship": relationship,
            "source_occurrence_id": source_occurrence_id,
            "scope": scope,
            "optional": bool(optional),
            "resolver": resolver,
        }
        if constraint:
            record["constraint"] = constraint
        if metadata:
            record["metadata"] = dict(metadata)
        self._merge_bounded(
            self.edges,
            edge_id,
            record,
            limit=MAX_DEPENDENCY_EDGES,
            label="dependency edges",
        )
        return edge_id

    def add_gap(
        self,
        gap_type: str,
        message: str,
        *,
        component_id: str | None = None,
        component_version_id: str | None = None,
        source_id: str | None = None,
        evidence: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        gap_id = stable_id(
            "gap",
            gap_type,
            component_id or "",
            component_version_id or "",
            source_id or "",
            message,
        )
        record: dict[str, Any] = {
            "gap_id": gap_id,
            "gap_type": gap_type,
            "message": message,
            "evidence": sorted(set(evidence)),
        }
        for key, value in (
            ("component_id", component_id),
            ("component_version_id", component_version_id),
            ("source_id", source_id),
        ):
            if value:
                record[key] = value
        if metadata:
            record["metadata"] = dict(metadata)
        self._merge_bounded(
            self.extra_gaps,
            gap_id,
            record,
            limit=MAX_GAPS,
            label="gaps",
        )
        return gap_id

    def add_image(
        self,
        image: str,
        source_id: str,
        locator: str,
        role: str,
        *,
        platform: str | None = None,
        root_id: str | None = None,
        lifecycle: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        invalid_reason: str | None = None,
    ) -> tuple[str, str, str]:
        invalid_reason = invalid_reason or oci_image_reference_error(image)
        if invalid_reason:
            if invalid_reason not in OCI_REFERENCE_INVALID_REASONS:
                raise RegistryInputError("invalid OCI reference reason is unsupported")
            lifecycle = lifecycle or self.lifecycle_for_source(source_id)
            observed_hash = file_hash(image.encode("utf-8"))
            hash_suffix = observed_hash.removeprefix("sha256:")
            evidence_uri = self.sources[source_id]["evidence_uri"]
            safe_metadata = {
                "invalid_reference_reason": invalid_reason,
                "observed_reference_sha256": observed_hash,
            }
            component_id = self.add_component(
                kind="invalid-oci-image-reference",
                ecosystem="invalid-oci-reference",
                name=f"invalid-reference-{hash_suffix[:16]}",
                identity=(
                    f"invalid-oci-reference:{source_id}:{locator}:{observed_hash}"
                ),
                lifecycles=(lifecycle,),
                metadata=safe_metadata,
                official_channel_required=False,
            )
            version_id = self.add_version(
                component_id,
                constraint="invalid-oci-reference",
                resolution_state="unresolved",
                evidence=(f"{evidence_uri}#{locator}",),
                metadata=safe_metadata,
            )
            occurrence_id = self.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=locator,
                role=role,
                raw_value=f"invalid-image-reference:{observed_hash}",
                root_id=root_id,
                lifecycle=lifecycle,
                metadata=safe_metadata,
            )
            self.add_gap(
                "oci-reference-invalid",
                f"OCI image reference at {locator} is structurally invalid",
                component_id=component_id,
                component_version_id=version_id,
                source_id=source_id,
                evidence=(f"{evidence_uri}#{locator}",),
                metadata=safe_metadata,
            )
            return component_id, version_id, occurrence_id

        repository, tag, digest = split_image(image)
        immutable_digest, digest_error = normalize_oci_digest(digest)
        normalized_platform = normalize_oci_platform(platform)
        lifecycle = lifecycle or self.lifecycle_for_source(source_id)
        namespace, name = (
            repository.rsplit("/", 1) if "/" in repository else ("", repository)
        )
        purl = f"pkg:oci/{quote(name, safe='._-')}?repository_url={quote(repository, safe=':/._-')}"
        component_id = self.add_component(
            kind="oci-image",
            ecosystem="oci",
            namespace=namespace,
            name=name,
            purl=purl,
            identity=f"oci:{repository}",
            lifecycles=(lifecycle,),
            metadata={"oci_repository": repository},
        )
        constraint = None
        if not tag and not immutable_digest:
            constraint = repository if digest_error else image
        version_id = self.add_version(
            component_id,
            resolved_version=tag,
            artifact_digest=immutable_digest,
            platform=normalized_platform,
            constraint=constraint,
            resolution_state="resolved" if immutable_digest else "unresolved",
            evidence=(f"{self.sources[source_id]['evidence_uri']}#{locator}",),
        )
        if digest_error:
            self.add_gap(
                "oci-digest-invalid",
                f"OCI digest {digest!r} at {locator} is invalid ({digest_error})",
                component_id=component_id,
                component_version_id=version_id,
                source_id=source_id,
                evidence=(f"{self.sources[source_id]['evidence_uri']}#{locator}",),
                metadata={
                    "observed_digest": digest,
                    "reason": digest_error,
                },
            )
        if platform and not normalized_platform:
            self.add_gap(
                "oci-platform-invalid",
                f"OCI platform {platform!r} at {locator} is not an exact platform",
                component_id=component_id,
                component_version_id=version_id,
                source_id=source_id,
                evidence=(f"{self.sources[source_id]['evidence_uri']}#{locator}",),
                metadata={"observed_platform": platform},
            )
        occurrence_id = self.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=locator,
            role=role,
            raw_value=image,
            root_id=root_id,
            lifecycle=lifecycle,
            metadata=metadata,
        )
        return component_id, version_id, occurrence_id

    def sbom_inventory_subjects(self) -> set[str]:
        """Components whose own digest is the subject of an SBOM that enumerates it."""

        enumerated = {
            str(edge.get("from_component_version_id") or "")
            for edge in self.edges.values()
            if edge.get("relationship") == SBOM_INVENTORY_RELATIONSHIP
            and edge.get("resolver") == SBOM_INVENTORY_RESOLVER
        }
        subjects: set[str] = set()
        for occurrence in self.occurrences.values():
            version_id = str(occurrence.get("component_version_id") or "")
            if (
                occurrence.get("role") in SBOM_INVENTORY_SUBJECT_ROLES
                and version_id in enumerated
                and self.versions.get(version_id, {}).get("artifact_digest")
            ):
                subjects.add(str(occurrence.get("component_id") or ""))
        return subjects

    def manifest(
        self,
        *,
        base_manifest_id: str | None = None,
    ) -> dict[str, Any]:
        gaps = dict(self.extra_gaps)
        occurrences_by_version: dict[str, list[dict[str, Any]]] = {}
        for occurrence in self.occurrences.values():
            occurrences_by_version.setdefault(
                str(occurrence.get("component_version_id") or ""), []
            ).append(occurrence)
        version_by_component: dict[str, list[dict[str, Any]]] = {}
        for version in self.versions.values():
            version_by_component.setdefault(version["component_id"], []).append(version)
            owner = self.components.get(version["component_id"], {})
            if version.get("resolution_state") != "resolved" and not (
                # A receipt-bound capture-time commit is the exact version (D1).
                gitops_source_observation(owner, version)
                # A receipt-bound registry manifest digest is the exact version (R4).
                or oci_artifact_observation(owner, version)
            ):
                message = f"Exact version is unresolved for {version['component_id']}"
                record = make_gap(
                    "exact-version-unresolved",
                    message,
                    component_id=version["component_id"],
                    component_version_id=version["component_version_id"],
                    evidence=version.get("evidence", []),
                )
                gaps[record["gap_id"]] = record
        for component_id, versions in version_by_component.items():
            component = self.components.get(component_id, {})
            digests_by_tag: dict[str, set[str]] = {}
            for version in versions:
                if component.get("ecosystem") == "oci":
                    tag = str(version.get("resolved_version") or "")
                    digest = str(version.get("artifact_digest") or "")
                    if tag and digest:
                        digests_by_tag.setdefault(tag, set()).add(digest)
                    observation = oci_artifact_observation(component, version)
                    platform = str(version.get("platform") or "")
                    if not normalize_oci_platform(platform):
                        record = oci_platform_gap(version, observation)
                        gaps[record["gap_id"]] = record
                    if observation and version.get("resolution_state") != "resolved":
                        record = make_gap(
                            "oci-artifact-version-observed",
                            "OCI artifact version is bound to the receipt-verified "
                            f"registry manifest {observation['resolved_digest']}",
                            component_id=version["component_id"],
                            component_version_id=version["component_version_id"],
                            evidence=(
                                *version.get("evidence", []),
                                str(observation["evidence_content_hash"]),
                            ),
                        )
                        gaps[record["gap_id"]] = record
                ref = str(
                    version.get("source_ref") or version.get("resolved_version") or ""
                )
                normalized_ref = ref.lower()
                if TEMPLATE_EXPRESSION_RE.search(ref):
                    record = make_gap(
                        "dynamic-ref-unresolved",
                        f"Dynamic ref {ref!r} requires runtime resolution",
                        component_id=version["component_id"],
                        component_version_id=version["component_version_id"],
                        evidence=version.get("evidence", []),
                    )
                    gaps[record["gap_id"]] = record
                elif (
                    normalized_ref in MUTABLE_REFS
                    or normalized_ref.startswith("refs/heads/")
                ) and not version.get("artifact_digest"):
                    component_metadata = component.get("metadata", {})
                    self_repository = (
                        component_metadata.get("self_repository") is True
                        if isinstance(component_metadata, Mapping)
                        else False
                    )
                    occurrence_records = occurrences_by_version.get(
                        version["component_version_id"], []
                    )
                    fixture_evidence: set[str] = set()
                    use_sites = [
                        item
                        for item in occurrence_records
                        if str(item.get("role") or "") not in IDENTITY_OBSERVATION_ROLES
                    ]
                    test_fixture = bool(use_sites)
                    for occurrence in use_sites:
                        occurrence_metadata = occurrence.get("metadata", {})
                        if not (
                            isinstance(occurrence_metadata, Mapping)
                            and occurrence_metadata.get("test_fixture") is True
                        ):
                            test_fixture = False
                            break
                        fixture_evidence.update(
                            str(item)
                            for item in occurrence_metadata.get(
                                "test_fixture_evidence", []
                            )
                        )
                    if component.get("ecosystem") == "git" and self_repository:
                        observation = gitops_source_observation(component, version)
                        if observation:
                            # Resolved by observation: the marker stops blocking (D1).
                            record = make_gap(
                                "gitops-self-reference-observed",
                                f"Self-repository GitOps ref {normalized_ref!r} "
                                "deliberately tracks this repository at observed "
                                f"commit {observation['observed_commit']}",
                                component_id=version["component_id"],
                                component_version_id=version["component_version_id"],
                                evidence=(
                                    *version.get("evidence", []),
                                    str(observation["evidence_content_hash"]),
                                ),
                            )
                        else:
                            record = make_gap(
                                "gitops-self-reference",
                                f"Self-repository GitOps ref {normalized_ref!r} "
                                "deliberately tracks this repository",
                                component_id=version["component_id"],
                                component_version_id=version["component_version_id"],
                                evidence=version.get("evidence", []),
                            )
                    elif test_fixture:
                        # Typing holds only while every occurrence carries proof.
                        record = make_gap(
                            "test-fixture-reference",
                            f"Mutable ref {normalized_ref!r} is a deliberate "
                            "test-fixture input",
                            component_id=version["component_id"],
                            component_version_id=version["component_version_id"],
                            evidence=(
                                *version.get("evidence", []),
                                *sorted(fixture_evidence),
                            ),
                        )
                    else:
                        record = make_gap(
                            "mutable-ref",
                            f"Mutable ref {normalized_ref!r} is not an immutable version",
                            component_id=version["component_id"],
                            component_version_id=version["component_version_id"],
                            evidence=version.get("evidence", []),
                        )
                    gaps[record["gap_id"]] = record
            if component.get("ecosystem") == "oci":
                platforms_by_artifact: dict[tuple[str, ...], set[str]] = {}
                for version in versions:
                    platform = normalize_oci_platform(version.get("platform"))
                    if not platform:
                        continue
                    artifact_key = tuple(
                        str(version.get(key) or "")
                        for key in (
                            "resolved_version",
                            "constraint",
                            "source_ref",
                            "artifact_digest",
                        )
                    )
                    platforms_by_artifact.setdefault(artifact_key, set()).add(platform)
                for artifact_key, platforms in sorted(platforms_by_artifact.items()):
                    if len(platforms) < 2:
                        continue
                    record = make_gap(
                        "oci-platform-multi",
                        "OCI artifact identity resolves to multiple explicit platforms",
                        component_id=component_id,
                        evidence=tuple(sorted(platforms)),
                    )
                    record["metadata"] = {
                        "artifact_identity": list(artifact_key),
                        "platforms": sorted(platforms),
                    }
                    gaps[record["gap_id"]] = record
                for tag, digests in sorted(digests_by_tag.items()):
                    if len(digests) < 2:
                        continue
                    record = make_gap(
                        "oci-tag-digest-conflict",
                        f"OCI tag {tag!r} resolves to conflicting immutable digests",
                        component_id=component_id,
                        evidence=tuple(sorted(digests)),
                    )
                    # Digest set lives in set-merged evidence; strict metadata keeps only the tag.
                    record["metadata"] = {"tag": tag}
                    gaps[record["gap_id"]] = record
        for component_id, component in self.components.items():
            if not version_by_component.get(component_id):
                record = make_gap(
                    "version-unobserved",
                    f"No component version was observed for {component_id}",
                    component_id=component_id,
                )
                gaps[record["gap_id"]] = record
            metadata = component.get("metadata", {})
            if (
                component.get("kind") == "model-artifact"
                and isinstance(metadata, Mapping)
                and metadata.get("lineage_required") is True
            ):
                upstream_bound_versions = {
                    str(edge.get("to_component_version_id") or "")
                    for edge in self.edges.values()
                    if edge.get("relationship") in MODEL_UPSTREAM_LINEAGE_RELATIONSHIPS
                }
                component_versions = {
                    str(version.get("component_version_id") or "")
                    for version in version_by_component.get(component_id, [])
                }
                if component_versions.isdisjoint(upstream_bound_versions):
                    lineage_evidence = metadata.get("lineage_evidence", [])
                    record = make_gap(
                        "model-artifact-lineage-unresolved",
                        f"No upstream model artifact lineage is mapped for {component_id}",
                        component_id=component_id,
                        evidence=(
                            tuple(str(value) for value in lineage_evidence)
                            if isinstance(lineage_evidence, list)
                            else ()
                        ),
                    )
                    gaps[record["gap_id"]] = record
            channels = component.get("official_channels", [])
            if component_requires_official_channels(component) and not any(
                isinstance(channel, dict)
                and channel_class_is_reviewed(channel)
                and channel_is_available(channel)
                for channel in channels
            ):
                record = make_gap(
                    "official-channel-unresolved",
                    f"No reviewed official channel is registered for {component_id}",
                    component_id=component_id,
                )
                gaps[record["gap_id"]] = record
        lifecycles_by_component: dict[str, set[str]] = {}
        for occurrence in self.occurrences.values():
            component_id = occurrence.get("component_id")
            lifecycle = occurrence.get("lifecycle")
            if component_id and lifecycle:
                lifecycles_by_component.setdefault(component_id, set()).add(lifecycle)
        inventory_subjects = self.sbom_inventory_subjects()
        for component_id, component in self.components.items():
            if (
                component.get("ecosystem") != "oci"
                or component_id in inventory_subjects
                or "sbom-observed" in lifecycles_by_component.get(component_id, set())
            ):
                continue
            record = make_gap(
                "transitive-inventory-unavailable",
                "No authoritative lockfile or SBOM exposes transitive packages "
                f"for {component_id}",
                component_id=component_id,
            )
            gaps[record["gap_id"]] = record
        if self.accepted_deviations:
            gaps = stamp_accepted_deviations(
                gaps, self.components, self.accepted_deviations
            )
        components = []
        for component_id, component in self.components.items():
            materialized = dict(component)
            if component_id in lifecycles_by_component:
                materialized["lifecycles"] = sorted(
                    lifecycles_by_component[component_id]
                )
            channels = [
                dict(item)
                for item in materialized.get("official_channels", [])
                if isinstance(item, Mapping)
            ]
            # Normalize the denominator: reclassified path artifacts stay out.
            materialized["official_channel_required"] = (
                component_requires_official_channels(materialized)
            )
            if materialized.get("official_channel_required", True):
                represented = {str(item.get("channel_type") or "") for item in channels}
                for channel_type in OFFICIAL_CHANNEL_TYPES:
                    if channel_type in represented:
                        continue
                    channels.append(
                        {
                            "channel_id": stable_id(
                                "chn", component_id, channel_type, "unresolved"
                            ),
                            "channel_type": channel_type,
                            "availability_state": "unresolved",
                            "review_state": "needs-review",
                            "authority_state": "non-authoritative",
                        }
                    )
            materialized["official_channels"] = sorted(
                channels,
                key=lambda item: (
                    str(item.get("channel_type") or ""),
                    str(item.get("channel_id") or ""),
                    canonical_json(item),
                ),
            )
            components.append(materialized)
        manifest: dict[str, Any] = {
            "$schema": MANIFEST_SCHEMA_URI,
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "record_kind": MANIFEST_RECORD_KIND,
            "manifest_version": MANIFEST_VERSION,
            "generator": generator_identity(),
            "generation_state": "candidate",
            "authority_boundary": {
                "review_state": "unreviewed",
                "authoritative": False,
                "compile_eligible": False,
                "promote_eligible": False,
                "source_admission": False,
                "retrieval_release": False,
                "production_mutation": False,
            },
            "base_manifest_id": base_manifest_id,
            "input_set": {"required_source_classes": [], "entries": []},
            "sources": sorted_records(self.sources.values(), "source_id"),
            "components": sorted_records(components, "component_id"),
            "versions": sorted_records(self.versions.values(), "component_version_id"),
            "occurrences": sorted_records(self.occurrences.values(), "occurrence_id"),
            "dependency_edges": sorted_records(self.edges.values(), "edge_id"),
            "gaps": sorted_records(gaps.values(), "gap_id"),
        }
        if self.discovery_inputs:
            discovery_inputs = sorted_records(
                self.discovery_inputs.values(), "discovery_input_id"
            )
            disposition_counts = Counter(
                item["disposition"] for item in discovery_inputs
            )
            manifest["discovery_scope"] = {
                "producer": "knowledge-registry-discovery-v1",
                "model_dependency": "none",
                "complete": not any(
                    item["disposition"] in {"unhandled", "unreadable"}
                    for item in discovery_inputs
                ),
                "input_count": len(discovery_inputs),
                "disposition_counts": {
                    key: disposition_counts[key] for key in sorted(disposition_counts)
                },
                "inputs": discovery_inputs,
            }
            manifest["input_set"] = input_set_for(discovery_inputs)
        return seal_manifest(manifest)


def make_gap(
    gap_type: str,
    message: str,
    *,
    component_id: str | None = None,
    component_version_id: str | None = None,
    source_id: str | None = None,
    evidence: Sequence[str] = (),
) -> dict[str, Any]:
    gap_id = stable_id(
        "gap",
        gap_type,
        component_id or "",
        component_version_id or "",
        source_id or "",
        message,
    )
    record: dict[str, Any] = {
        "gap_id": gap_id,
        "gap_type": gap_type,
        "message": message,
        "evidence": sorted(set(evidence)),
    }
    for key, value in (
        ("component_id", component_id),
        ("component_version_id", component_version_id),
        ("source_id", source_id),
    ):
        if value:
            record[key] = value
    return record


def accepted_deviation_validator() -> Any:
    return draft202012_validator(
        ACCEPTED_DEVIATION_SCHEMA_RELATIVE,
        label="accepted deviation schema",
    )


def accepted_deviation_semantic_errors(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("record_kind") != ACCEPTED_DEVIATION_RECORD_KIND:
        errors.append(f"record_kind must equal {ACCEPTED_DEVIATION_RECORD_KIND}")
    review = record.get("review")
    review = review if isinstance(review, Mapping) else {}
    if review.get("status") != "accepted":
        errors.append("review.status must be accepted")
    if not str(review.get("reviewed_by") or ""):
        errors.append("review.reviewed_by is required")
    if not ISO_DATE_RE.fullmatch(str(review.get("reviewed_at") or "")):
        errors.append("review.reviewed_at must be an exact date")
    if not ISO_DATE_RE.fullmatch(str(record.get("expires_at") or "")):
        errors.append("expires_at must be an exact date")
    scope = record.get("scope")
    scope = scope if isinstance(scope, Mapping) else {}
    if str(scope.get("axis") or "") not in ACCEPTED_DEVIATION_AXES:
        errors.append("scope.axis must be a completeness axis that carries gaps")
    if not str(scope.get("gap_type") or ""):
        errors.append("scope.gap_type is required")
    preconditions = scope.get("preconditions")
    if not isinstance(preconditions, list) or not preconditions:
        errors.append("scope.preconditions must be a non-empty array")
        preconditions = []
    for index, precondition in enumerate(preconditions):
        if not isinstance(precondition, Mapping):
            errors.append(f"scope.preconditions[{index}] must be an object")
            continue
        if not str(precondition.get("field") or ""):
            errors.append(f"scope.preconditions[{index}].field is required")
        try:
            re.compile(str(precondition.get("pattern") or ""))
        except re.error as exc:
            errors.append(
                f"scope.preconditions[{index}].pattern is not a valid regex: {exc}"
            )
    return errors


def load_accepted_deviations(directory: str) -> list[dict[str, Any]]:
    """Load, validate and freeze-pin every ratified deviation in a directory."""

    path = Path(directory)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RegistryInputError(
            f"cannot inspect accepted deviations {directory}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RegistryInputError(
            f"accepted deviations {directory} must be a non-symlink directory"
        )
    entries = sorted(item for item in path.iterdir() if item.suffix == ".json")
    if len(entries) > MAX_ACCEPTED_DEVIATIONS:
        raise RegistryInputError(
            f"accepted deviations exceed record bound {MAX_ACCEPTED_DEVIATIONS}"
        )
    validator = accepted_deviation_validator()
    deviations: list[dict[str, Any]] = []
    record_ids: set[str] = set()
    scopes: dict[tuple[str, str], str] = {}
    for item in entries:
        item_metadata = os.lstat(item)
        if stat.S_ISLNK(item_metadata.st_mode) or not stat.S_ISREG(
            item_metadata.st_mode
        ):
            raise RegistryInputError(
                f"accepted deviation {item} must be a regular file"
            )
        raw = read_regular_file(
            item,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label="accepted deviation",
        )
        payload = parse_json_bytes(raw, label=f"accepted deviation {item}")
        if not isinstance(payload, dict):
            raise RegistryInputError(f"accepted deviation {item} must be a JSON object")
        errors = [
            *schema_validation_errors(validator, payload),
            *accepted_deviation_semantic_errors(payload),
        ]
        if errors:
            raise RegistryInputError(
                f"{item} is not a ratified accepted deviation: "
                + "; ".join(errors[:MAX_SCHEMA_ERRORS])
            )
        record_id = str(payload["record_id"])
        if record_id in record_ids:
            raise RegistryInputError(
                f"duplicate accepted deviation record_id {record_id}"
            )
        scope_key = (str(payload["scope"]["axis"]), str(payload["scope"]["gap_type"]))
        if scope_key in scopes:
            raise RegistryInputError(
                f"one deviation per axis and gap type: {scope_key[1]} appears in "
                f"{scopes[scope_key]} and {item}"
            )
        record_ids.add(record_id)
        scopes[scope_key] = item.as_posix()
        digest = file_hash(raw)
        deviations.append(
            {
                "path": item.as_posix(),
                "sha256": digest,
                "citation": f"{item.as_posix()}@{digest}",
                "record": payload,
                "preconditions": [
                    (
                        str(precondition["field"]),
                        re.compile(str(precondition["pattern"])),
                    )
                    for precondition in payload["scope"]["preconditions"]
                ],
            }
        )
    return deviations


def accepted_deviation_context(
    gap: Mapping[str, Any], component: Mapping[str, Any]
) -> dict[str, Any]:
    """Flatten the gap and its component into the precondition lookup space."""

    metadata = component.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    return {
        "gap": {
            "gap_type": str(gap.get("gap_type") or ""),
            "message": str(gap.get("message") or ""),
            "component_id": str(gap.get("component_id") or ""),
            "component_version_id": str(gap.get("component_version_id") or ""),
            "source_id": str(gap.get("source_id") or ""),
            "evidence": "\n".join(
                str(item) for item in gap.get("evidence", []) if isinstance(item, str)
            ),
        },
        "component": {
            "kind": str(component.get("kind") or ""),
            "ecosystem": str(component.get("ecosystem") or ""),
            "name": str(component.get("name") or ""),
            "namespace": str(component.get("namespace") or ""),
            "purl": str(component.get("purl") or ""),
            "metadata": {
                key: str(value)
                for key, value in metadata.items()
                if isinstance(value, (str, bool, int, float))
            },
        },
    }


def accepted_deviation_stamp(
    gap: Mapping[str, Any],
    component: Mapping[str, Any],
    deviations: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Return the stamp of the first ratified deviation whose scope proves out."""

    gap_type = str(gap.get("gap_type") or "")
    for deviation in deviations:
        record = deviation["record"]
        scope = record["scope"]
        if str(scope["gap_type"]) != gap_type:
            continue
        context = accepted_deviation_context(gap, component)
        matched = True
        for field, pattern in deviation["preconditions"]:
            value: Any = context
            for token in str(field).split("."):
                value = value.get(token) if isinstance(value, Mapping) else None
            if not isinstance(value, str) or not pattern.search(value):
                matched = False
                break
        if not matched:
            # Fail closed: an unproven precondition leaves the gap blocking.
            continue
        review = record["review"]
        return {
            "axis": str(scope["axis"]),
            "citation": str(deviation["citation"]),
            "declaration_id": str(record["record_id"]),
            "declaration_path": str(deviation["path"]),
            "declaration_sha256": str(deviation["sha256"]),
            "expires_at": str(record["expires_at"]),
            "gap_type": gap_type,
            "ratified_at": str(review["reviewed_at"]),
            "review_status": str(review["status"]),
            "reviewed_by": str(review["reviewed_by"]),
        }
    return None


def stamp_accepted_deviations(
    gaps: Mapping[str, Mapping[str, Any]],
    components: Mapping[str, Mapping[str, Any]],
    deviations: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Attach ratified exemption provenance; rows stay in gaps[] either way."""

    stamped: dict[str, dict[str, Any]] = {}
    for gap_id, gap in gaps.items():
        stamp = accepted_deviation_stamp(
            gap, components.get(str(gap.get("component_id") or ""), {}), deviations
        )
        if stamp is None:
            stamped[gap_id] = dict(gap)
            continue
        record = dict(gap)
        metadata = dict(record.get("metadata") or {})
        metadata[ACCEPTED_DEVIATION_KEY] = stamp
        record["metadata"] = metadata
        stamped[gap_id] = record
    return stamped


def accepted_deviation_exemption(
    gap: Mapping[str, Any], axis: str, observed_at: str | None
) -> dict[str, Any] | None:
    """Return the in-manifest stamp that subtracts one gap from one axis."""

    metadata = gap.get("metadata")
    stamp = (
        metadata.get(ACCEPTED_DEVIATION_KEY) if isinstance(metadata, Mapping) else None
    )
    if not isinstance(stamp, Mapping):
        return None
    expires_at = str(stamp.get("expires_at") or "")
    if (
        str(stamp.get("axis") or "") != axis
        or str(stamp.get("gap_type") or "") != str(gap.get("gap_type") or "")
        or str(stamp.get("review_status") or "") != "accepted"
        or not ACCEPTED_DEVIATION_CITATION_RE.fullmatch(
            str(stamp.get("citation") or "")
        )
        or not ISO_DATE_RE.fullmatch(expires_at)
    ):
        return None
    if not observed_at or str(observed_at)[:10] >= expires_at:
        # No observation, or the ratification has lapsed: the gap blocks again.
        return None
    return dict(stamp)


def axis_blocking_gaps(
    gaps: Sequence[Mapping[str, Any]],
    gap_types: frozenset[str],
    axis: str,
    observed_at: str | None,
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Split one axis into blocking ids, exempted ids and exemption provenance."""

    blocking: list[str] = []
    exempted: list[str] = []
    by_declaration: dict[tuple[str, str], int] = {}
    for gap in gaps:
        if gap.get("gap_type") not in gap_types:
            continue
        gap_id = str(gap.get("gap_id"))
        stamp = accepted_deviation_exemption(gap, axis, observed_at)
        if stamp is None:
            blocking.append(gap_id)
            continue
        exempted.append(gap_id)
        key = (str(stamp["declaration_id"]), str(stamp["declaration_sha256"]))
        by_declaration[key] = by_declaration.get(key, 0) + 1
    declarations = [
        {
            "declaration_id": declaration_id,
            "declaration_sha256": declaration_sha256,
            "exempted_gaps": count,
        }
        for (declaration_id, declaration_sha256), count in sorted(
            by_declaration.items()
        )
    ]
    return sorted(blocking), sorted(exempted), declarations


def merge_values(left: Any, right: Any) -> Any:
    if left == right:
        return left
    if left in (None, "", [], {}):
        return right
    if right in (None, "", [], {}):
        return left
    if isinstance(left, dict) and isinstance(right, dict):
        return merge_dicts(left, right)
    if isinstance(left, list) and isinstance(right, list):
        unique = {canonical_json(item): item for item in [*left, *right]}
        return [unique[key] for key in sorted(unique)]
    # Input order must not affect a candidate.  Conflicting scalar observations
    # remain available in occurrences; choose a deterministic representation.
    return min((left, right), key=canonical_json)


def merge_dicts(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = dict(left)
    for key in sorted(right):
        result[key] = (
            merge_values(result[key], right[key]) if key in result else right[key]
        )
    return result


def counts_for(manifest: Mapping[str, Any]) -> dict[str, int]:
    return {field: len(manifest.get(field, [])) for field in ARRAY_FIELDS}


def file_hash(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _identity_from_stat(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_regular_file_capture(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> tuple[bytes, os.stat_result]:
    """Read one regular file through no-follow descriptors and revalidate it.

    Every path component is opened relative to the prior directory descriptor,
    so a symlink or directory substitution cannot redirect the read outside the
    path the caller named.  The same leaf identity is reopened after the read;
    any concurrent replacement fails the capture instead of mixing evidence.
    """

    absolute = path.absolute()
    parts = absolute.parts
    if (
        not parts
        or parts[0] != os.sep
        or any(part in {"", ".", ".."} for part in parts[1:])
    ):
        raise RegistryInputError(f"{label} must be an absolute normalized path")
    directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    opened: list[int] = [directory_fd]
    try:
        for component in parts[1:-1]:
            descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            opened.append(descriptor)
            directory_fd = descriptor
        if len(parts) < 2:
            raise RegistryInputError(f"{label} does not name a file")
        leaf = parts[-1]
        descriptor = os.open(
            leaf,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        opened.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RegistryInputError(f"{label} is not a regular file")
        if before.st_size > max_bytes:
            raise RegistryInputError(
                f"{label} exceeds byte bound {max_bytes} ({before.st_size} bytes)"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) > max_bytes:
            raise RegistryInputError(f"{label} exceeds byte bound {max_bytes}")
        if len(data) != before.st_size or _identity_from_stat(
            before
        ) != _identity_from_stat(after):
            raise RegistryInputError(f"{label} changed while it was read")

        reopened = os.open(
            leaf,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        try:
            if _identity_from_stat(os.fstat(reopened)) != _identity_from_stat(after):
                raise RegistryInputError(f"{label} was replaced after it was read")
        finally:
            os.close(reopened)
        return data, before
    except OSError as exc:
        raise RegistryInputError(f"cannot safely read {label}: {exc}") from exc
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass


def read_regular_file(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    data, _ = read_regular_file_capture(path, max_bytes=max_bytes, label=label)
    return data


def trusted_executable_identity(path: Path) -> dict[str, Any]:
    """Bind an absolute root-owned immutable executable by exact bytes."""

    absolute = path.absolute()
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise RegistryInputError(
            f"cannot inspect executable {absolute}: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RegistryInputError(f"executable {absolute} must be a regular non-symlink")
    if metadata.st_uid != 0:
        raise RegistryInputError(f"executable {absolute} must be owned by root")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RegistryInputError(
            f"executable {absolute} must not be group/world writable"
        )
    if not metadata.st_mode & stat.S_IXUSR:
        raise RegistryInputError(f"executable {absolute} is not executable")
    raw = read_regular_file(
        absolute,
        max_bytes=MAX_EXECUTABLE_BYTES,
        label=f"executable {absolute}",
    )
    return {
        "path": absolute.as_posix(),
        "sha256": file_hash(raw),
        "size": len(raw),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the process group a child started with start_new_session leads, else the child alone.

    The group id is the child's pid. One of 1 or less, or this process's own group, is never
    signalled: os.killpg(1, sig) is kill(-1, sig) and reaches every process the user owns,
    killpg(0, sig) reaches the caller's own group, and a test double's pid reads as 1
    (cordanaLLM/knowledge#2). Such a child is killed alone.
    """
    group = process.pid
    if not isinstance(group, int) or isinstance(group, bool) or group <= 1 or group == os.getpgrp():
        process.kill()
        return
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()


def run_trusted_executable(
    executable: Path,
    arguments: Sequence[str],
    *,
    cwd: Path,
    max_stdout_bytes: int = MAX_GIT_OUTPUT_BYTES,
    timeout: float = 30.0,
    stdin_bytes: bytes | None = None,
    env_overrides: Mapping[str, str] | None = None,
    pass_fds: Sequence[int] = (),
) -> tuple[bytes, dict[str, Any]]:
    before = trusted_executable_identity(executable)
    command = [before["path"], *SAFE_GIT_OPTIONS, *arguments]
    stdin_stream = None
    if stdin_bytes is not None:
        stdin_stream = tempfile.TemporaryFile()
        stdin_stream.write(stdin_bytes)
        stdin_stream.seek(0)
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env={**FIXED_SUBPROCESS_ENV, **dict(env_overrides or {})},
            stdin=stdin_stream if stdin_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(pass_fds),
            start_new_session=True,
        )
    except OSError as exc:
        if stdin_stream is not None:
            stdin_stream.close()
        raise RegistryInputError(f"cannot execute {before['path']}: {exc}") from exc
    assert process.stdout is not None
    assert process.stderr is not None
    limits = {"stdout": max_stdout_bytes, "stderr": 64 * 2**10}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RegistryInputError(f"subprocess timed out after {timeout:g}s")
            events = selector.select(remaining)
            if not events:
                raise RegistryInputError(f"subprocess timed out after {timeout:g}s")
            for key, _ in events:
                stream_name = key.data
                chunk = os.read(key.fileobj.fileno(), 64 * 2**10)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffers[stream_name].extend(chunk)
                if len(buffers[stream_name]) > limits[stream_name]:
                    raise RegistryInputError(
                        f"subprocess {stream_name} exceeds byte bound "
                        f"{limits[stream_name]}"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RegistryInputError(f"subprocess timed out after {timeout:g}s")
        returncode = process.wait(timeout=remaining)
    except (RegistryInputError, subprocess.TimeoutExpired) as exc:
        if process.poll() is None:
            kill_process_group(process)
        process.wait()
        if isinstance(exc, subprocess.TimeoutExpired):
            raise RegistryInputError(
                f"subprocess timed out after {timeout:g}s"
            ) from exc
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if stdin_stream is not None:
            stdin_stream.close()
    stdout = bytes(buffers["stdout"])
    stderr = bytes(buffers["stderr"])
    after = trusted_executable_identity(executable)
    if before != after:
        raise RegistryInputError(f"executable {before['path']} changed during capture")
    if returncode != 0:
        detail = stderr[: 64 * 2**10].decode("utf-8", errors="replace").strip()
        raise RegistryInputError(
            f"subprocess {arguments[0] if arguments else before['path']} failed: {detail}"
        )
    return stdout, before


def _repository_file(relative: str) -> Path:
    return Path(__file__).resolve().parents[2] / relative


def generator_identity() -> dict[str, str]:
    schema_path = _repository_file(DISCOVERY_SCHEMA_RELATIVE)
    source_path = Path(__file__).absolute()
    schema_hash = file_hash(
        read_regular_file(
            schema_path,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label="registry schema",
        )
    )
    source_hash = file_hash(
        read_regular_file(
            source_path,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label="registry generator",
        )
    )
    ruleset_material = {
        "dependency_scopes": sorted(DEPENDENCY_SCOPES),
        "lifecycle_states": sorted(LIFECYCLE_STATES),
        "mutable_refs": sorted(MUTABLE_REFS),
        "official_channel_types": list(OFFICIAL_CHANNEL_TYPES),
        "target_ecosystems": sorted(OFFICIAL_TARGET_ECOSYSTEMS),
    }
    return {
        "name": GENERATOR_NAME,
        "version": GENERATOR_VERSION,
        "source_ref": f"{GENERATOR_SOURCE_REF}#{source_hash}",
        "schema_hash": schema_hash,
        "ruleset_hash": file_hash(canonical_json(ruleset_material).encode("utf-8")),
    }


def ruleset_hash_from_registry_source(raw: bytes, filename: str) -> str:
    """Derive the declared ruleset from exact registry source bytes."""

    try:
        syntax_tree = ast.parse(raw.decode("utf-8"), filename=filename)
    except (SyntaxError, UnicodeError) as exc:
        raise RegistryInputError(
            "registry source is not compilable UTF-8 Python"
        ) from exc
    names = {
        "DEPENDENCY_SCOPES",
        "LIFECYCLE_STATES",
        "MUTABLE_REFS",
        "OFFICIAL_CHANNEL_TYPES",
        "OFFICIAL_TARGET_ECOSYSTEMS",
    }
    values: dict[str, Any] = {}
    for node in syntax_tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in names:
            continue
        try:
            values[target.id] = ast.literal_eval(node.value)
        except (TypeError, ValueError) as exc:
            raise RegistryInputError(
                "registry ruleset is not statically bound"
            ) from exc
    if set(values) != names:
        raise RegistryInputError("registry ruleset declarations are incomplete")
    ruleset_material = {
        "dependency_scopes": sorted(values["DEPENDENCY_SCOPES"]),
        "lifecycle_states": sorted(values["LIFECYCLE_STATES"]),
        "mutable_refs": sorted(values["MUTABLE_REFS"]),
        "official_channel_types": list(values["OFFICIAL_CHANNEL_TYPES"]),
        "target_ecosystems": sorted(values["OFFICIAL_TARGET_ECOSYSTEMS"]),
    }
    return file_hash(canonical_json(ruleset_material).encode("utf-8"))


def _source_code_map(raw: bytes, filename: str) -> dict[str, types.CodeType]:
    try:
        source = raw.decode("utf-8")
        syntax_tree = ast.parse(source, filename=filename)
        root_code = compile(source, filename, "exec", dont_inherit=True)
    except (SyntaxError, UnicodeError) as exc:
        raise RegistryInputError(
            "registry source is not compilable UTF-8 Python"
        ) from exc
    wanted: set[str] = set()
    for node in syntax_tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            wanted.add(node.name)
        elif isinstance(node, ast.ClassDef):
            wanted.update(
                f"{node.name}.{member.name}"
                for member in node.body
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
    result: dict[str, types.CodeType] = {}
    stack = [root_code]
    while stack:
        code = stack.pop()
        if code.co_qualname in wanted:
            result[code.co_qualname] = code
        stack.extend(
            constant
            for constant in code.co_consts
            if isinstance(constant, types.CodeType)
        )
    return result


def _bound_constant_value(value: Any) -> Any:
    if isinstance(value, re.Pattern):
        return ("regex", value.pattern, value.flags)
    if isinstance(value, Path):
        return ("path", value.as_posix())
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            "dataclass",
            value.__class__.__qualname__,
            tuple(
                (field.name, _bound_constant_value(getattr(value, field.name)))
                for field in dataclasses.fields(value)
            ),
        )
    if isinstance(value, Mapping):
        pairs = [
            (_bound_constant_value(key), _bound_constant_value(nested))
            for key, nested in value.items()
        ]
        return ("mapping", tuple(sorted(pairs, key=repr)))
    if isinstance(value, tuple):
        return ("tuple", tuple(_bound_constant_value(item) for item in value))
    if isinstance(value, list):
        return ("list", tuple(_bound_constant_value(item) for item in value))
    if isinstance(value, (set, frozenset)):
        return (
            "set",
            tuple(sorted((_bound_constant_value(item) for item in value), key=repr)),
        )
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return (type(value).__name__, value)
    raise TypeError(f"unsupported bound constant type {type(value).__name__}")


def _source_constant_map(
    raw: bytes,
    filename: str,
    *,
    evaluation_globals: Mapping[str, Any] | None = None,
    require_all: bool = False,
) -> dict[str, Any]:
    try:
        syntax_tree = ast.parse(raw.decode("utf-8"), filename=filename)
    except (SyntaxError, UnicodeError) as exc:
        raise RegistryInputError(
            "module source is not compilable UTF-8 Python"
        ) from exc
    safe_globals = {
        "__builtins__": {},
        "Path": Path,
        "frozenset": frozenset,
        "re": re,
    }
    if evaluation_globals:
        safe_globals.update(evaluation_globals)
    evaluated: dict[str, Any] = {}
    result: dict[str, Any] = {}
    declared: set[str] = set()
    for node in syntax_tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not re.fullmatch(
            r"[A-Z][A-Z0-9_]*", target.id
        ):
            continue
        declared.add(target.id)
        try:
            value = eval(
                compile(
                    ast.Expression(node.value), filename, "eval", dont_inherit=True
                ),
                safe_globals,
                evaluated,
            )
            normalized = _bound_constant_value(value)
        except (AttributeError, NameError, SyntaxError, TypeError, ValueError):
            continue
        evaluated[target.id] = value
        result[target.id] = normalized
    if require_all and set(result) != declared:
        missing = sorted(declared - set(result))
        raise RegistryInputError(
            f"module constants are not statically bound: {', '.join(missing)}"
        )
    return result


def _loaded_code_map(
    namespace: Mapping[str, Any] | None = None,
    module_name: str | None = None,
) -> dict[str, types.CodeType]:
    result: dict[str, types.CodeType] = {}
    namespace = namespace or globals()
    module_name = module_name or __name__
    for value in namespace.values():
        if isinstance(value, types.FunctionType) and value.__module__ == module_name:
            result[value.__qualname__] = value.__code__
        elif isinstance(value, type) and value.__module__ == module_name:
            for member in vars(value).values():
                if isinstance(member, (staticmethod, classmethod)):
                    member = member.__func__
                if isinstance(member, types.FunctionType):
                    result[member.__qualname__] = member.__code__
    return result


def verify_loaded_python_module_source(
    raw: bytes,
    filename: str,
    namespace: Mapping[str, Any],
    module_name: str,
    *,
    constant_evaluation_globals: Mapping[str, Any] | None = None,
    require_all_constants: bool = False,
) -> None:
    try:
        source_root = compile(raw.decode("utf-8"), filename, "exec", dont_inherit=True)
    except (SyntaxError, UnicodeError) as exc:
        raise RegistryInputError(
            "module source is not compilable UTF-8 Python"
        ) from exc
    if namespace.get("_LOADED_MODULE_CODE") != source_root:
        raise RegistryInputError(
            "loaded Python module does not match committed source bytes"
        )
    expected = _source_code_map(raw, filename)
    loaded_all = _loaded_code_map(namespace, module_name)
    loaded = {name: loaded_all[name] for name in expected if name in loaded_all}
    expected_constants = _source_constant_map(
        raw,
        filename,
        evaluation_globals=constant_evaluation_globals,
        require_all=require_all_constants,
    )
    try:
        loaded_constants = {
            name: _bound_constant_value(namespace[name]) for name in expected_constants
        }
    except (KeyError, TypeError):
        loaded_constants = {}
    if loaded != expected or loaded_constants != expected_constants:
        raise RegistryInputError(
            "loaded Python implementation does not match committed source bytes"
        )


def verify_loaded_registry_source(raw: bytes, filename: str) -> None:
    verify_loaded_python_module_source(raw, filename, globals(), __name__)


def registry_generator_source_binding() -> dict[str, Any]:
    """Bind registry generation/validation to exact clean committed local sources."""

    repository = Path(__file__).resolve().parents[2]
    _files, tracked, snapshot = repository_snapshot(repository)
    paths = (
        GENERATOR_SOURCE_REF,
        "tools/knowledge-registry/capture_live.py",
        DISCOVERY_SCHEMA_RELATIVE,
        REVIEWED_SCHEMA_RELATIVE,
        SNAPSHOT_RECEIPT_SCHEMA_RELATIVE,
    )
    sources: list[dict[str, Any]] = []
    for relative in paths:
        if relative not in tracked:
            raise RegistryInputError("registry generator source is not committed")
        raw = read_regular_file(
            repository / relative,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label=f"registry generator source {relative}",
        )
        sources.append({"path": relative, "sha256": file_hash(raw), "size": len(raw)})
        if relative == GENERATOR_SOURCE_REF:
            verify_loaded_registry_source(raw, (repository / relative).as_posix())
    return {
        "git_commit": str(snapshot["head_commit"]),
        "sources": sources,
        "generator": generator_identity(),
    }


def input_set_for(inputs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    entries = []
    for item in inputs:
        entry = {
            "input_id": item.get("discovery_input_id"),
            "kind": item.get("evidence_class") or "unknown",
            "uri": item.get("evidence_uri"),
            "content_hash": item.get("content_hash"),
            "disposition": item.get("disposition"),
            "tracked": bool(item.get("tracked")),
            "scanners": sorted(str(value) for value in item.get("scanners", [])),
        }
        if item.get("error"):
            entry["error"] = item["error"]
        entries.append(entry)
    entries.sort(
        key=lambda item: (str(item.get("input_id") or ""), canonical_json(item))
    )
    return {
        "required_source_classes": sorted(
            {
                str(item.get("kind") or "unknown")
                for item in entries
                if item.get("tracked")
            }
        ),
        "entries": entries,
    }


CLOSURE_GAP_TYPES = frozenset(
    {
        "discovery-input-unhandled",
        "docker-copy-input-untracked",
        "helm-lock-missing",
        "helm-lock-policy",
        "helm-lock-untracked",
        "live-export-invalid",
        "live-kind-unsupported",
        "node-lock-missing",
        "oci-tag-digest-conflict",
        "python-lock-missing",
        "reviewed-record-invalid",
        "reviewed-reference-unresolved",
        "source-unreadable",
        "terraform-lock-missing",
        "transitive-inventory-unavailable",
        *LIVE_CAPTURE_BLOCKING_GAPS,
    }
)
# Receipt-bound observations of an otherwise blocking fact; never in either axis.
OBSERVED_IDENTITY_GAP_TYPES = frozenset(
    {
        "gitops-self-reference-observed",
        "oci-artifact-version-observed",
        "oci-platform-index",
        "oci-platform-observed",
    }
)
# Zero-tolerance axis: a new gap type is non-blocking only by staying out.
IDENTITY_GAP_TYPES = frozenset(
    {
        "exact-version-unresolved",
        "gitops-self-reference",
        "image-expression-unresolved",
        "mutable-ref",
        "oci-digest-invalid",
        "oci-platform-invalid",
        "oci-platform-multi",
        "oci-platform-unresolved",
        "oci-reference-invalid",
        "oci-tag-digest-conflict",
        "test-fixture-reference",
        "version-unobserved",
    }
)


def snapshot_axis_sets(manifest: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    """Return the accepted-available and immutable-snapshot channel_id sets."""

    accepted_available_channels: set[str] = set()
    immutable_snapshots: set[str] = set()
    for component in manifest.get("components", []):
        if not isinstance(component, Mapping):
            continue
        for channel in component.get("official_channels", []):
            if (
                isinstance(channel, Mapping)
                and channel_class_is_reviewed(channel)
                and channel_is_available(channel)
                and channel.get("channel_id")
            ):
                accepted_available_channels.add(str(channel["channel_id"]))
        for snapshot in component.get("official_channel_snapshots", []):
            if not isinstance(snapshot, Mapping):
                continue
            if (
                snapshot.get("channel_id")
                and re.fullmatch(
                    r"sha256:[0-9a-f]{64}", str(snapshot.get("content_hash") or "")
                )
                and snapshot.get("status") in SNAPSHOT_SATISFYING_STATUSES
            ):
                immutable_snapshots.add(str(snapshot["channel_id"]))
    return accepted_available_channels, immutable_snapshots


def completeness_for(manifest: Mapping[str, Any]) -> dict[str, Any]:
    input_set = manifest.get("input_set")
    entries = input_set.get("entries", []) if isinstance(input_set, Mapping) else []
    bad_inputs = [
        item
        for item in entries
        if not isinstance(item, Mapping)
        or item.get("disposition") in {"unhandled", "unreadable"}
        or item.get("error")
    ]
    input_state = (
        "complete"
        if entries and not bad_inputs
        else ("partial" if entries else "unknown")
    )
    gaps = [item for item in manifest.get("gaps", []) if isinstance(item, Mapping)]
    observation = manifest.get("observation")
    observed_at = (
        str(observation.get("observed_at") or "")
        if isinstance(observation, Mapping)
        else ""
    )
    closure_gaps, closure_exempted, closure_declarations = axis_blocking_gaps(
        gaps, CLOSURE_GAP_TYPES, "closure", observed_at
    )
    identity_gaps, identity_exempted, identity_declarations = axis_blocking_gaps(
        gaps, IDENTITY_GAP_TYPES, "identity", observed_at
    )
    coverage = coverage_manifest(manifest)
    required = int(coverage["official_channel_class_slots_total"])
    reviewed = int(coverage["official_channel_class_slots_reviewed"])
    channel_state = "complete" if reviewed == required else "gapped"

    accepted_available_channels, immutable_snapshots = snapshot_axis_sets(manifest)
    missing_snapshots = sorted(accepted_available_channels - immutable_snapshots)
    snapshot_state = (
        "complete"
        if accepted_available_channels and not missing_snapshots
        else ("gapped" if accepted_available_channels else "unknown")
    )
    axes = {
        "input": {
            "state": input_state,
            "input_count": len(entries),
            "blocking_input_ids": sorted(
                str(item.get("input_id") or "")
                for item in bad_inputs
                if isinstance(item, Mapping)
            ),
        },
        "enumeration": {"state": input_state},
        "closure": {
            "state": (
                "gapped"
                if closure_gaps
                else ("complete" if input_state == "complete" else "unknown")
            ),
            "blocking_gap_ids": closure_gaps,
        },
        "identity": {
            "state": "gapped" if identity_gaps else "complete",
            "blocking_gap_ids": identity_gaps,
        },
        "channel_review": {
            "state": channel_state,
            "required_slots": required,
            "accepted_slots": reviewed,
        },
        "snapshots": {
            "state": snapshot_state,
            "accepted_available_channels": len(accepted_available_channels),
            "immutable_verified_channels": len(immutable_snapshots),
            "missing_channel_ids": missing_snapshots,
        },
    }
    for axis, exempted, declarations in (
        ("closure", closure_exempted, closure_declarations),
        ("identity", identity_exempted, identity_declarations),
    ):
        # Absent when nothing is exempted: frozen envelopes stay reproducible.
        if exempted:
            axes[axis]["accepted_deviation_ids"] = exempted
            axes[axis]["accepted_deviations"] = declarations
    axes["all_axes_complete"] = all(
        axes[name]["state"] == "complete"
        for name in (
            "input",
            "enumeration",
            "closure",
            "identity",
            "channel_review",
            "snapshots",
        )
    )
    return axes


def manifest_hash_preimage(manifest: Mapping[str, Any]) -> dict[str, Any]:
    preimage = json.loads(canonical_json(manifest))
    preimage.pop("manifest_id", None)
    integrity = preimage.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("manifest_hash", None)
    return preimage


def digest_ids(values: Iterable[str]) -> str:
    return file_hash(canonical_json(sorted(set(values))).encode("utf-8"))


def candidate_cardinality_errors(manifest: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for field, maximum in CANDIDATE_ARRAY_BOUNDS.items():
        values = manifest.get(field)
        if isinstance(values, list) and len(values) > maximum:
            errors.append(f"{field} exceeds record bound {maximum}")
    discovery_scope = manifest.get("discovery_scope")
    if isinstance(discovery_scope, Mapping):
        inputs = discovery_scope.get("inputs")
        if isinstance(inputs, list) and len(inputs) > MAX_DISCOVERY_INPUTS:
            errors.append(
                f"discovery_scope.inputs exceeds record bound {MAX_DISCOVERY_INPUTS}"
            )
    input_set = manifest.get("input_set")
    if isinstance(input_set, Mapping):
        entries = input_set.get("entries")
        if isinstance(entries, list) and len(entries) > MAX_DISCOVERY_INPUTS:
            errors.append(
                f"input_set.entries exceeds record bound {MAX_DISCOVERY_INPUTS}"
            )
    merge_lineage = manifest.get("merge_lineage")
    if isinstance(merge_lineage, Mapping):
        identifiers = merge_lineage.get("input_manifest_ids")
        if isinstance(identifiers, list) and len(identifiers) > MAX_DISCOVERY_INPUTS:
            errors.append(
                f"merge_lineage.input_manifest_ids exceeds record bound {MAX_DISCOVERY_INPUTS}"
            )
    return errors


def candidate_shape_errors(manifest: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ARRAY_FIELDS:
        if field in manifest and not isinstance(manifest[field], list):
            errors.append(f"{field} must be an array")
    for object_field, list_fields in (
        ("input_set", ("required_source_classes", "entries")),
        ("discovery_scope", ("inputs",)),
        ("merge_lineage", ("input_manifest_ids",)),
    ):
        value = manifest.get(object_field)
        if value is None:
            continue
        if not isinstance(value, Mapping):
            errors.append(f"{object_field} must be an object")
            continue
        for list_field in list_fields:
            if list_field in value and not isinstance(value[list_field], list):
                errors.append(f"{object_field}.{list_field} must be an array")
    return errors


def seal_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    shape_errors = candidate_shape_errors(manifest)
    if shape_errors:
        raise RegistryInputError(shape_errors[0])
    cardinality_errors = candidate_cardinality_errors(manifest)
    if cardinality_errors:
        raise RegistryInputError(cardinality_errors[0])
    result = json.loads(canonical_json(manifest))
    result.pop("manifest_id", None)
    result["$schema"] = MANIFEST_SCHEMA_URI
    result["schema_version"] = MANIFEST_SCHEMA_VERSION
    result["record_kind"] = MANIFEST_RECORD_KIND
    result["manifest_version"] = MANIFEST_VERSION
    result["generation_state"] = "candidate"
    result["authority_boundary"] = {
        "review_state": "unreviewed",
        "authoritative": False,
        "compile_eligible": False,
        "promote_eligible": False,
        "source_admission": False,
        "retrieval_release": False,
        "production_mutation": False,
    }
    current_bounds = {
        "tracked_files": MAX_TRACKED_FILES,
        "discovery_files": MAX_DISCOVERY_FILES,
        "discovery_file_bytes": MAX_DISCOVERY_FILE_BYTES,
        "discovery_total_bytes": MAX_DISCOVERY_TOTAL_BYTES,
        "json_input_bytes": MAX_JSON_INPUT_BYTES,
        "json_depth": MAX_JSON_DEPTH,
        "json_nodes": MAX_JSON_NODES,
        "serialized_output_bytes": MAX_SERIALIZED_OUTPUT_BYTES,
        "sources": MAX_SOURCES,
        "components": MAX_COMPONENTS,
        "versions": MAX_VERSIONS,
        "occurrences": MAX_OCCURRENCES,
        "dependency_edges": MAX_DEPENDENCY_EDGES,
        "gaps": MAX_GAPS,
    }
    # Known-good historical bounds keep frozen manifest_ids reproducible.
    result["bounds"] = (
        result["bounds"]
        if result.get("bounds") in MANIFEST_BOUNDS_KNOWN
        else current_bounds
    )
    result.setdefault("generator", generator_identity())
    generator = result.get("generator")
    if not isinstance(generator, Mapping) or not FULL_SHA256_RE.fullmatch(
        str(generator.get("schema_hash") or "")
    ):
        raise RegistryInputError("generator.schema_hash must be a full sha256")
    result.setdefault("base_manifest_id", None)
    result.setdefault("input_set", {"required_source_classes": [], "entries": []})
    result["counts"] = counts_for(result)
    result["completeness"] = completeness_for(result)
    complete_mark = bool(
        result["completeness"]["input"]["state"] == "complete"
        and result["completeness"]["enumeration"]["state"] == "complete"
        and result["completeness"]["closure"]["state"] == "complete"
        and result["completeness"]["identity"]["state"] == "complete"
        and result["completeness"]["channel_review"]["state"] == "complete"
        and result["completeness"]["snapshots"]["state"] in {"complete", "unknown"}
    )
    existing_reconciliation = result.get("reconciliation", {})
    result["reconciliation"] = {
        "previous_manifest_id": result.get("base_manifest_id"),
        "complete_mark": complete_mark,
        # Observation-only candidate generation never authorizes deletion.
        "removal_allowed": False,
        "added": (
            list(existing_reconciliation.get("added", []))
            if isinstance(existing_reconciliation, Mapping)
            else []
        ),
        "changed": (
            list(existing_reconciliation.get("changed", []))
            if isinstance(existing_reconciliation, Mapping)
            else []
        ),
        "missing": (
            list(existing_reconciliation.get("missing", []))
            if isinstance(existing_reconciliation, Mapping)
            else []
        ),
        "removed": [],
    }
    result["integrity"] = {
        "canonicalization": CANONICALIZATION,
        "schema_hash": generator["schema_hash"],
        "deterministic_order": True,
        "exact_counts": result["counts"],
    }
    unsafe_locators = unsafe_candidate_locator_pointers(result)
    if unsafe_locators:
        raise RegistryInputError(
            f"candidate contains unsafe locator at {unsafe_locators[0]}"
        )
    preimage = canonical_json(manifest_hash_preimage(result)).encode("utf-8")
    if len(preimage) > MAX_SERIALIZED_OUTPUT_BYTES:
        raise RegistryInputError(
            f"canonical manifest exceeds byte bound {MAX_SERIALIZED_OUTPUT_BYTES}"
        )
    digest = file_hash(preimage)
    result["manifest_id"] = "mft-" + digest.removeprefix("sha256:")
    result["integrity"]["manifest_hash"] = digest
    return result


def _safe_directory_identity(path: Path, *, label: str) -> dict[str, Any]:
    absolute = Path(os.path.abspath(path))
    directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    opened = [directory_fd]
    try:
        for component in absolute.parts[1:]:
            directory_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            opened.append(directory_fd)
        metadata = os.fstat(directory_fd)
        return {
            "path": absolute.as_posix(),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
        }
    except OSError as exc:
        raise RegistryInputError(f"cannot safely bind {label}: {exc}") from exc
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _safe_metadata_file_identity(path: Path, *, label: str) -> dict[str, Any]:
    raw = read_regular_file(path, max_bytes=MAX_GIT_METADATA_BYTES, label=label)
    metadata = os.lstat(path)
    return {
        "path": Path(os.path.abspath(path)).as_posix(),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": len(raw),
        "sha256": file_hash(raw),
    }


def _optional_metadata_file_capture(
    path: Path, *, label: str
) -> tuple[dict[str, Any], bytes] | None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RegistryInputError(f"cannot inspect {label}: {exc}") from exc
    raw = read_regular_file(path, max_bytes=MAX_GIT_METADATA_BYTES, label=label)
    metadata = os.lstat(path)
    return (
        {
            "path": Path(os.path.abspath(path)).as_posix(),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": len(raw),
            "sha256": file_hash(raw),
        },
        raw,
    )


def _validate_git_ref_name(value: str) -> str:
    if (
        not value.startswith("refs/")
        or value.endswith(("/", ".", ".lock"))
        or "//" in value
        or ".." in value
        or "@{" in value
        or any(character in value for character in " ~^:?*[\\\x00\r\n")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise RegistryInputError(f"Git symbolic ref {value!r} is unsupported")
    return value


def _parse_packed_refs(raw: bytes) -> dict[str, str]:
    if raw and not raw.endswith(b"\n"):
        raise RegistryInputError("Git packed-refs is truncated")
    try:
        lines = raw.decode("ascii", errors="strict").splitlines()
    except UnicodeError as exc:
        raise RegistryInputError("Git packed-refs is not ASCII") from exc
    result: dict[str, str] = {}
    preceding_ref = False
    object_length: int | None = None
    for line in lines:
        if not line or line.startswith("#"):
            preceding_ref = False
            continue
        if line.startswith("^"):
            peeled = line[1:]
            if not preceding_ref or not re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})", peeled
            ):
                raise RegistryInputError("Git packed-refs has a malformed peeled line")
            preceding_ref = False
            continue
        try:
            object_id, ref_name = line.split(" ", 1)
        except ValueError as exc:
            raise RegistryInputError("Git packed-refs has a malformed record") from exc
        _validate_git_ref_name(ref_name)
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id):
            raise RegistryInputError("Git packed-refs has a malformed object ID")
        if object_length is None:
            object_length = len(object_id)
        elif len(object_id) != object_length:
            raise RegistryInputError("Git packed-refs mixes object formats")
        if ref_name in result:
            raise RegistryInputError(f"Git packed-refs repeats ref {ref_name!r}")
        result[ref_name] = object_id
        preceding_ref = True
    return result


def _resolve_bound_git_head(
    git_dir: Path,
    common_dir: Path,
    head_raw: bytes,
    packed_refs: Mapping[str, str],
) -> tuple[str, list[dict[str, Any]]]:
    try:
        value = head_raw.decode("ascii", errors="strict").strip()
    except UnicodeError as exc:
        raise RegistryInputError("Git HEAD is not ASCII") from exc
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _ in range(8):
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
            return value, chain
        match = re.fullmatch(r"ref: (refs/[^\r\n]+)", value)
        if not match:
            raise RegistryInputError("Git HEAD/ref target is malformed")
        ref_name = _validate_git_ref_name(match.group(1))
        if ref_name in seen:
            raise RegistryInputError("Git symbolic ref chain contains a cycle")
        seen.add(ref_name)
        loose: list[tuple[dict[str, Any], bytes]] = []
        for base in dict.fromkeys((git_dir, common_dir)):
            captured = _optional_metadata_file_capture(
                base / ref_name,
                label=f"Git loose ref {ref_name}",
            )
            if captured is not None:
                loose.append(captured)
        loose_values: set[str] = set()
        for identity, raw in loose:
            try:
                loose_value = raw.decode("ascii", errors="strict").strip()
            except UnicodeError as exc:
                raise RegistryInputError(
                    f"Git loose ref {ref_name!r} is not ASCII"
                ) from exc
            loose_values.add(loose_value)
            chain.append({"ref": ref_name, **identity})
        if len(loose_values) > 1:
            raise RegistryInputError(
                f"Git loose ref {ref_name!r} has ambiguous worktree/common values"
            )
        packed_value = packed_refs.get(ref_name)
        if loose_values:
            value = next(iter(loose_values))
        elif packed_value is not None:
            value = packed_value
            chain.append({"ref": ref_name, "storage": "packed-refs"})
        else:
            raise RegistryInputError(f"Git symbolic ref {ref_name!r} is unresolved")
    raise RegistryInputError("Git symbolic ref chain exceeds depth bound")


def _sealed_file_snapshot(
    path: Path, *, expected_hash: str, label: str
) -> tuple[int, dict[str, Any]]:
    raw = read_regular_file(path, max_bytes=MAX_GIT_METADATA_BYTES, label=label)
    if file_hash(raw) != expected_hash:
        raise RegistryInputError(f"{label} changed before it could be bound")
    descriptor = os.memfd_create(
        "knowledge-registry-git-index",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RegistryInputError(f"cannot snapshot {label}")
            view = view[written:]
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
            raise RegistryInputError(f"cannot seal {label} snapshot")
        return descriptor, {
            "sha256": file_hash(raw),
            "size": len(raw),
            "snapshot": "sealed-memfd",
        }
    except BaseException:
        os.close(descriptor)
        raise


def git_layout_identity(root: Path) -> dict[str, Any]:
    marker = root / ".git"
    try:
        marker_metadata = os.lstat(marker)
    except OSError as exc:
        raise RegistryInputError(
            "repository discovery requires a Git checkout"
        ) from exc
    if stat.S_ISLNK(marker_metadata.st_mode):
        raise RegistryInputError("Git metadata marker must not be a symlink")
    marker_identity: dict[str, Any]
    if stat.S_ISDIR(marker_metadata.st_mode):
        git_dir = marker
        marker_identity = {
            "kind": "directory",
            **_safe_directory_identity(marker, label="Git metadata directory"),
        }
    elif stat.S_ISREG(marker_metadata.st_mode):
        raw = read_regular_file(
            marker,
            max_bytes=4096,
            label="Git worktree metadata file",
        )
        try:
            line = raw.decode("utf-8", errors="strict").strip()
        except UnicodeError as exc:
            raise RegistryInputError("Git worktree metadata file is not UTF-8") from exc
        match = re.fullmatch(r"gitdir: ([^\r\n]+)", line)
        if not match:
            raise RegistryInputError("Git worktree metadata file is malformed")
        target = Path(match.group(1))
        git_dir = Path(
            os.path.abspath(target if target.is_absolute() else marker.parent / target)
        )
        marker_identity = {
            "kind": "gitfile",
            **_safe_metadata_file_identity(marker, label="Git worktree metadata file"),
        }
    else:
        raise RegistryInputError("Git metadata marker must be a directory or gitfile")
    git_dir_identity = _safe_directory_identity(git_dir, label="Git directory")
    commondir_path = git_dir / "commondir"
    try:
        commondir_metadata = os.lstat(commondir_path)
    except FileNotFoundError:
        common_dir = git_dir
        commondir_identity = None
    except OSError as exc:
        raise RegistryInputError(f"cannot inspect Git commondir: {exc}") from exc
    else:
        if stat.S_ISLNK(commondir_metadata.st_mode):
            raise RegistryInputError("Git commondir must not be a symlink")
        raw = read_regular_file(
            commondir_path,
            max_bytes=4096,
            label="Git commondir",
        )
        try:
            value = raw.decode("utf-8", errors="strict").strip()
        except UnicodeError as exc:
            raise RegistryInputError("Git commondir is not UTF-8") from exc
        if not value or "\x00" in value:
            raise RegistryInputError("Git commondir is malformed")
        candidate = Path(value)
        common_dir = Path(
            os.path.abspath(
                candidate if candidate.is_absolute() else git_dir / candidate
            )
        )
        commondir_identity = _safe_metadata_file_identity(
            commondir_path, label="Git commondir"
        )
    common_dir_identity = _safe_directory_identity(
        common_dir, label="Git common directory"
    )
    reftable_path = common_dir / "reftable"
    try:
        os.lstat(reftable_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RegistryInputError(f"cannot inspect Git ref storage: {exc}") from exc
    else:
        raise RegistryInputError("Git reftable ref storage is unsupported")
    config_capture = _optional_metadata_file_capture(
        common_dir / "config", label="Git common config"
    )
    if config_capture is None:
        raise RegistryInputError("Git common config is missing")
    config_identity, config_raw = config_capture
    if re.search(
        rb"(?im)^\s*refstorage\s*=\s*(?!files\s*$)\S+\s*$",
        config_raw,
    ):
        raise RegistryInputError("Git non-files ref storage is unsupported")
    packed_capture = _optional_metadata_file_capture(
        common_dir / "packed-refs", label="Git packed-refs"
    )
    packed_identity, packed_refs = (
        (packed_capture[0], _parse_packed_refs(packed_capture[1]))
        if packed_capture is not None
        else (None, {})
    )
    head_capture = _optional_metadata_file_capture(git_dir / "HEAD", label="Git HEAD")
    if head_capture is None:
        raise RegistryInputError("Git HEAD is missing")
    head_identity, head_raw = head_capture
    resolved_head, ref_chain = _resolve_bound_git_head(
        git_dir,
        common_dir,
        head_raw,
        packed_refs,
    )
    return {
        "marker": marker_identity,
        "git_dir": git_dir_identity,
        "common_dir": common_dir_identity,
        "commondir": commondir_identity,
        "config": config_identity,
        "packed_refs": packed_identity,
        "resolved_head": resolved_head,
        "ref_chain": ref_chain,
        "index": _safe_metadata_file_identity(git_dir / "index", label="Git index"),
        "head": head_identity,
    }


def _git_object_id(object_type: str, data: bytes, length: int) -> str:
    preimage = f"{object_type} {len(data)}\0".encode("ascii") + data
    if length == 40:
        return hashlib.sha1(preimage, usedforsecurity=False).hexdigest()
    if length == 64:
        return hashlib.sha256(preimage).hexdigest()
    raise RegistryInputError("Git repository uses an unsupported object format")


def _git_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RegistryInputError(
            f"repository discovery exceeds deadline {MAX_REPOSITORY_DISCOVERY_SECONDS}s"
        )
    return min(30.0, remaining)


def _parse_tree_inventory(raw: bytes, object_id_length: int) -> list[dict[str, Any]]:
    if raw and not raw.endswith(b"\0"):
        raise RegistryInputError("Git tree inventory is truncated")
    records = raw.split(b"\0")[:-1] if raw else []
    if len(records) > MAX_TRACKED_FILES:
        raise RegistryInputError(
            f"Git tracked inventory exceeds file bound {MAX_TRACKED_FILES}"
        )
    inventory: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_record in records:
        try:
            header, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_id, raw_size = header.decode("ascii").split()
            relative = raw_path.decode("utf-8")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as exc:
            raise RegistryInputError("Git tree inventory record is malformed") from exc
        relative_path = Path(relative)
        if (
            mode not in {"100644", "100755"}
            or object_type != "blob"
            or not re.fullmatch(rf"[0-9a-f]{{{object_id_length}}}", object_id)
            or size < 0
            or not relative
            or relative.startswith("/")
            or "\x00" in relative
            or any(part in {"", ".", ".."} for part in relative_path.parts)
        ):
            raise RegistryInputError(
                f"Git path {relative!r} has unsupported mode, identity, or shape"
            )
        if relative in seen:
            raise RegistryInputError(f"Git tree inventory repeats path {relative!r}")
        seen.add(relative)
        inventory.append(
            {
                "mode": mode,
                "object_id": object_id,
                "path": relative,
                "size": size,
            }
        )
    return sorted(inventory, key=lambda item: item["path"])


def _parse_index_inventory(raw: bytes, object_id_length: int) -> list[dict[str, str]]:
    if raw and not raw.endswith(b"\0"):
        raise RegistryInputError("Git index inventory is truncated")
    result: list[dict[str, str]] = []
    for raw_record in raw.split(b"\0")[:-1] if raw else []:
        try:
            header, raw_path = raw_record.split(b"\t", 1)
            mode, object_id, stage = header.decode("ascii").split()
            relative = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise RegistryInputError("Git index inventory record is malformed") from exc
        if stage != "0" or not re.fullmatch(
            rf"[0-9a-f]{{{object_id_length}}}", object_id
        ):
            raise RegistryInputError(
                f"Git path {relative!r} has unresolved or malformed index state"
            )
        result.append({"mode": mode, "object_id": object_id, "path": relative})
    return sorted(result, key=lambda item: item["path"])


def _read_committed_blobs(
    root: Path,
    git_prefix: Sequence[str],
    object_ids: Sequence[str],
    *,
    object_id_length: int,
    git_executable: Path,
    deadline: float,
) -> dict[str, bytes]:
    unique_ids = sorted(set(object_ids))
    if not unique_ids:
        return {}
    request = ("\n".join(unique_ids) + "\n").encode("ascii")
    raw, _ = run_trusted_executable(
        git_executable,
        (*git_prefix, "cat-file", "--batch"),
        cwd=root,
        max_stdout_bytes=MAX_DISCOVERY_TOTAL_BYTES + (len(unique_ids) * 160),
        timeout=_git_timeout(deadline),
        stdin_bytes=request,
    )
    offset = 0
    result: dict[str, bytes] = {}
    for expected_id in unique_ids:
        line_end = raw.find(b"\n", offset)
        if line_end < 0:
            raise RegistryInputError("Git blob batch output is truncated")
        try:
            object_id, object_type, raw_size = (
                raw[offset:line_end].decode("ascii").split(" ")
            )
            size = int(raw_size)
        except (UnicodeError, ValueError) as exc:
            raise RegistryInputError("Git blob batch header is malformed") from exc
        offset = line_end + 1
        end = offset + size
        if (
            object_id != expected_id
            or object_type != "blob"
            or end >= len(raw)
            or raw[end : end + 1] != b"\n"
        ):
            raise RegistryInputError("Git blob batch identity is inconsistent")
        data = raw[offset:end]
        if _git_object_id("blob", data, object_id_length) != expected_id:
            raise RegistryInputError("Git blob bytes do not match their object ID")
        result[expected_id] = data
        offset = end + 1
    if offset != len(raw):
        raise RegistryInputError("Git blob batch output has trailing data")
    return result


def repository_snapshot(
    root: Path,
    *,
    include_workingdir: bool = False,
    git_executable: Path = DEFAULT_GIT_EXECUTABLE,
    deadline: float | None = None,
) -> tuple[list[dict[str, Any]], frozenset[str], dict[str, Any]]:
    deadline = deadline or (time.monotonic() + MAX_REPOSITORY_DISCOVERY_SECONDS)
    layout_before = git_layout_identity(root)
    git_prefix = (
        f"--git-dir={layout_before['git_dir']['path']}",
        f"--work-tree={root.as_posix()}",
    )
    head = str(layout_before["resolved_head"])
    object_id_length = len(head)
    commit_raw, executable = run_trusted_executable(
        git_executable,
        (*git_prefix, "cat-file", "commit", head),
        cwd=root,
        max_stdout_bytes=MAX_GIT_METADATA_BYTES,
        timeout=_git_timeout(deadline),
    )
    if _git_object_id("commit", commit_raw, object_id_length) != head:
        raise RegistryInputError("Git commit bytes do not match HEAD identity")
    committer_matches = re.findall(
        rb"(?m)^committer .* ([0-9]+) [+-][0-9]{4}$", commit_raw
    )
    if len(committer_matches) != 1:
        raise RegistryInputError("Git HEAD has no unique committer timestamp")
    try:
        committed_epoch = int(committer_matches[0])
        head_committed_at = datetime.fromtimestamp(
            committed_epoch, timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError) as exc:
        raise RegistryInputError(
            "Git HEAD has no bounded canonical committer timestamp"
        ) from exc
    tree_raw, _ = run_trusted_executable(
        git_executable,
        (*git_prefix, "ls-tree", "-lrz", "--full-tree", head),
        cwd=root,
        max_stdout_bytes=MAX_GIT_OUTPUT_BYTES,
        timeout=_git_timeout(deadline),
    )
    inventory = _parse_tree_inventory(tree_raw, object_id_length)
    index_fd, index_snapshot = _sealed_file_snapshot(
        Path(layout_before["index"]["path"]),
        expected_hash=str(layout_before["index"]["sha256"]),
        label="Git index",
    )
    try:
        index_raw, _ = run_trusted_executable(
            git_executable,
            (*git_prefix, "ls-files", "-z", "--cached", "--stage"),
            cwd=root,
            max_stdout_bytes=MAX_GIT_OUTPUT_BYTES,
            timeout=_git_timeout(deadline),
            env_overrides={"GIT_INDEX_FILE": f"/proc/self/fd/{index_fd}"},
            pass_fds=(index_fd,),
        )
    finally:
        os.close(index_fd)
    index_inventory = _parse_index_inventory(index_raw, object_id_length)
    remote_raw, _ = run_trusted_executable(
        git_executable,
        (*git_prefix, "remote", "-v"),
        cwd=root,
        max_stdout_bytes=MAX_GIT_METADATA_BYTES,
        timeout=_git_timeout(deadline),
    )
    remote_urls = sorted(
        {
            match.group(1)
            for match in re.finditer(
                r"(?m)^\S+\t(\S+) \((?:fetch|push)\)$",
                remote_raw.decode("utf-8", errors="replace"),
            )
        }
    )
    comparable_tree = [
        {key: item[key] for key in ("mode", "object_id", "path")} for item in inventory
    ]
    if index_inventory != comparable_tree:
        raise RegistryInputError(
            "tracked index changes are not a reproducible capture input"
        )

    verified_bytes = 0
    for item in inventory:
        candidate = root / item["path"]
        try:
            metadata = os.lstat(candidate)
        except OSError as exc:
            raise RegistryInputError(
                f"tracked worktree path {item['path']!r} is unavailable: {exc}"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise RegistryInputError(
                f"tracked worktree path {item['path']!r} is not a regular file"
            )
        executable_mode = bool(metadata.st_mode & stat.S_IXUSR)
        if executable_mode != (item["mode"] == "100755"):
            raise RegistryInputError(
                f"tracked worktree mode differs from HEAD for {item['path']!r}"
            )
        data = read_regular_file(
            candidate,
            max_bytes=item["size"],
            label=f"tracked worktree path {item['path']}",
        )
        verified_bytes += len(data)
        if verified_bytes > MAX_JSON_INPUT_BYTES:
            raise RegistryInputError(
                f"tracked worktree verification exceeds byte bound {MAX_JSON_INPUT_BYTES}"
            )
        if _git_object_id("blob", data, object_id_length) != item["object_id"]:
            raise RegistryInputError(
                f"tracked worktree bytes differ from HEAD for {item['path']!r}"
            )
        if time.monotonic() >= deadline:
            raise RegistryInputError(
                f"repository discovery exceeds deadline {MAX_REPOSITORY_DISCOVERY_SECONDS}s"
            )

    authoritative = [
        item
        for item in inventory
        if is_authoritative_tracked_path(
            root,
            root / item["path"],
            include_workingdir=include_workingdir,
        )
    ]
    discovery_records = [
        item for item in authoritative if is_discovery_file(Path(item["path"]))
    ]
    if len(discovery_records) > MAX_DISCOVERY_FILES:
        raise RegistryInputError(
            f"discovery inventory exceeds file bound {MAX_DISCOVERY_FILES}"
        )
    if any(item["size"] > MAX_DISCOVERY_FILE_BYTES for item in discovery_records):
        raise RegistryInputError(
            f"discovery input exceeds file byte bound {MAX_DISCOVERY_FILE_BYTES}"
        )
    if sum(item["size"] for item in discovery_records) > MAX_DISCOVERY_TOTAL_BYTES:
        raise RegistryInputError(
            f"discovery inputs exceed total byte bound {MAX_DISCOVERY_TOTAL_BYTES}"
        )
    blob_data = _read_committed_blobs(
        root,
        git_prefix,
        [item["object_id"] for item in discovery_records],
        object_id_length=object_id_length,
        git_executable=git_executable,
        deadline=deadline,
    )
    files = [
        {**item, "data": blob_data[item["object_id"]]} for item in discovery_records
    ]
    layout_after = git_layout_identity(root)
    if layout_after != layout_before:
        raise RegistryInputError("Git metadata changed during repository capture")
    inventory_material = [
        {key: item[key] for key in ("mode", "object_id", "path", "size")}
        for item in inventory
    ]
    return (
        files,
        frozenset(item["path"] for item in inventory),
        {
            "head_commit": head,
            "head_committed_at": head_committed_at,
            "remote_urls": remote_urls,
            "tracked_file_count": len(inventory),
            "selected_file_count": len(authoritative),
            "tracked_inventory_sha256": file_hash(
                canonical_json(inventory_material).encode("utf-8")
            ),
            "git_metadata": layout_before,
            "index_snapshot": index_snapshot,
            "git_executable": {
                "path": executable["path"],
                "sha256": executable["sha256"],
                "size": executable["size"],
            },
        },
    )


def tracked_files(root: Path, include_workingdir: bool = False) -> list[Path]:
    files, _, _ = repository_snapshot(
        root,
        include_workingdir=include_workingdir,
    )
    return [root / item["path"] for item in files]


def is_authoritative_tracked_path(
    root: Path, path: Path, *, include_workingdir: bool
) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return False
    if relative == ".claude" or relative.startswith(".claude/"):
        return False
    if not include_workingdir and (
        relative == ".workingdir2" or relative.startswith(".workingdir2/")
    ):
        return False
    # These directories are versioned mirrors of upstream documentation and
    # examples. Their YAML is knowledge-source material, not evidence that the
    # example APIs or images are selected by this GitOps repository.
    return not relative.startswith(NON_AUTHORITATIVE_DISCOVERY_PREFIXES)


_COMMITTED_VIEW_TRACKED_PATHS: dict[str, frozenset[str]] = {}
_COMMITTED_VIEW_SOURCE_ROOTS: dict[str, str] = {}


class CommittedRepositoryView:
    """Private read-only materialization of bounded blobs read from exact HEAD."""

    def __init__(
        self,
        records: Sequence[Mapping[str, Any]],
        tracked_paths: frozenset[str],
        source_root: Path | None = None,
    ) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="knowledge-registry-head-")
        self.root = Path(self._temporary.name).absolute()
        self._registry_key = self.root.as_posix()
        self._source_key = (
            source_root.absolute().as_posix() if source_root is not None else None
        )
        try:
            for record in records:
                relative = str(record["path"])
                target = self.root / relative
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o500 if record["mode"] == "100755" else 0o400,
                )
                try:
                    data = record["data"]
                    if not isinstance(data, bytes):
                        raise RegistryInputError(
                            f"committed blob {relative!r} is not bytes"
                        )
                    view = memoryview(data)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise RegistryInputError(
                                f"cannot materialize committed blob {relative!r}"
                            )
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            _COMMITTED_VIEW_TRACKED_PATHS[self._registry_key] = tracked_paths
            if self._source_key is not None:
                _COMMITTED_VIEW_SOURCE_ROOTS[self._registry_key] = self._source_key
                _COMMITTED_VIEW_TRACKED_PATHS[self._source_key] = tracked_paths
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        _COMMITTED_VIEW_TRACKED_PATHS.pop(self._registry_key, None)
        _COMMITTED_VIEW_SOURCE_ROOTS.pop(self._registry_key, None)
        source_key = getattr(self, "_source_key", None)
        if source_key is not None:
            _COMMITTED_VIEW_TRACKED_PATHS.pop(source_key, None)
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            self._temporary = None
            temporary.cleanup()

    def __enter__(self) -> "CommittedRepositoryView":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


def git_path_is_tracked(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return False
    tracked = _COMMITTED_VIEW_TRACKED_PATHS.get(root.absolute().as_posix())
    return bool(tracked is not None and relative in tracked)


def committed_view_read_root(root: Path) -> Path:
    """Verified source worktree behind a committed view, else the root itself."""

    source = _COMMITTED_VIEW_SOURCE_ROOTS.get(root.absolute().as_posix())
    return Path(source) if source else root


HELM_LOCK_POLICY_HOOK = ".githooks/check-helm-dependency-versions.py"
CHART_LOCK_IGNORE_RULE = "**/Chart.lock"
LATEST_FIXTURE_HOOK = ".githooks/check-latest-image-tag.py"
LATEST_FIXTURE_HOOK_ID = "no-latest-image-tag"


def _policy_file_text(root: Path, relative: str) -> str | None:
    """HEAD-verified text of a tracked policy file, else None."""

    if not git_path_is_tracked(root, root / relative):
        return None
    candidate = committed_view_read_root(root) / relative
    try:
        metadata = os.lstat(candidate)
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    try:
        data = read_regular_file(
            candidate,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label=f"tracked policy input {relative}",
        )
    except RegistryInputError:
        return None
    return data.decode("utf-8", errors="replace")


def helm_lock_policy_proof(root: Path) -> tuple[str, ...]:
    """Evidence that Chart.lock is deliberately untracked; empty when unproven."""

    gitignore = _policy_file_text(root, ".gitignore")
    hook = _policy_file_text(root, HELM_LOCK_POLICY_HOOK)
    if gitignore is None or hook is None:
        return ()
    for line_number, line in enumerate(gitignore.splitlines(), 1):
        if line.strip() == CHART_LOCK_IGNORE_RULE:
            return (f".gitignore#L{line_number}", HELM_LOCK_POLICY_HOOK)
    return ()


def latest_image_fixture_policy(
    root: Path,
) -> tuple[re.Pattern[str], tuple[str, ...]] | None:
    """Exclusion regex + proof for the no-latest hook fixtures; None when unproven."""

    config = _policy_file_text(root, ".pre-commit-config.yaml")
    hook = _policy_file_text(root, LATEST_FIXTURE_HOOK)
    if config is None or hook is None:
        return None
    hook_indent: int | None = None
    for line_number, line in enumerate(config.splitlines(), 1):
        item = re.match(r"^(\s*)-\s+id\s*:\s*(\S+)\s*$", line)
        if item:
            hook_indent = (
                len(item.group(1)) if item.group(2) == LATEST_FIXTURE_HOOK_ID else None
            )
            continue
        if hook_indent is None:
            continue
        field = re.match(r"^(\s*)exclude\s*:\s*(.+?)\s*$", line)
        if field and len(field.group(1)) > hook_indent:
            try:
                pattern = re.compile(scalar(field.group(2)))
            except re.error:
                return None
            return pattern, (
                f".pre-commit-config.yaml#L{line_number}",
                LATEST_FIXTURE_HOOK,
            )
    return None


def is_discovery_file(path: Path) -> bool:
    name = path.name.lower()
    parts = {part.lower() for part in path.parts}
    if path.suffix.lower() in {".yaml", ".yml", ".tf", ".hcl", ".json", ".toml"}:
        return True
    if name in {"dockerfile", "go.mod", "go.sum", "chart.yaml", "chart.lock"}:
        return True
    if name in {".nvmrc", ".node-version", ".python-version", "runtime.txt"}:
        return True
    if name.startswith("dockerfile."):
        return True
    if name.startswith("requirements") and path.suffix.lower() in {"", ".in", ".txt"}:
        return True
    if name in {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    }:
        return True
    relative = path.as_posix().lower()
    if path.suffix.lower() == ".env" and "frontier-local" in parts:
        return True
    if path.suffix.lower() == ".sh" and (
        "frontier-local" in parts or "specialist-prep" in parts
    ):
        return True
    if path.suffix.lower() == ".sh" and any(
        relative == candidate or relative.endswith(f"/{candidate}")
        for candidate in TARGETED_INSTALL_SCRIPTS
    ):
        return True
    if path.suffix.lower() == ".py" and (
        "tools/voice-bakeoff/" in relative or "tools/specialist-prep/" in relative
    ):
        return True
    return False


def normalize_codex_projection_references(data: bytes) -> bytes:
    """Mask only byte spans proven to be generated MCP projection args."""

    try:
        payload = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return data
    servers = payload.get("mcp_servers") if isinstance(payload, dict) else None
    if not isinstance(servers, dict):
        return data
    canonical_projection = CODEX_CANONICAL_PROJECTION_REF.decode("ascii")
    locations: list[tuple[str, int, str]] = []
    for server_name, config in servers.items():
        if not isinstance(config, dict):
            continue
        arguments = config.get("args")
        if not isinstance(arguments, list):
            continue
        for index, argument in enumerate(arguments[:-1]):
            projection = arguments[index + 1]
            if (
                argument == "--projection"
                and isinstance(projection, str)
                and CODEX_GENERATED_PROJECTION_PATH_RE.search(projection)
                and projection != canonical_projection
            ):
                locations.append((str(server_name), index + 1, projection))
    if not locations:
        return data

    single_location_payloads: dict[tuple[str, int, str], dict[str, Any]] = {}
    for location in locations:
        server_name, argument_index, _projection = location
        candidate_payload = copy.deepcopy(payload)
        try:
            candidate_payload["mcp_servers"][server_name]["args"][
                argument_index
            ] = canonical_projection
        except (KeyError, IndexError, TypeError):
            return data
        single_location_payloads[location] = candidate_payload

    span_by_location: dict[tuple[str, int, str], tuple[int, int]] = {}
    for projection in sorted({location[2] for location in locations}):
        needle = projection.encode("utf-8")
        offset = 0
        while True:
            start = data.find(needle, offset)
            if start < 0:
                break
            end = start + len(needle)
            candidate = data[:start] + CODEX_CANONICAL_PROJECTION_REF + data[end:]
            try:
                candidate_payload = tomllib.loads(candidate.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError):
                offset = end
                continue
            matching_locations = [
                location
                for location, expected_payload in single_location_payloads.items()
                if candidate_payload == expected_payload
            ]
            if len(matching_locations) > 1:
                return data
            if matching_locations:
                location = matching_locations[0]
                if location in span_by_location:
                    return data
                span_by_location[location] = (start, end)
            offset = end

    if set(span_by_location) != set(locations):
        # Escaped or otherwise unsupported encodings fail closed to raw identity.
        return data
    spans = sorted(span_by_location.values())
    if any(
        start < previous_end for (_, previous_end), (start, _) in zip(spans, spans[1:])
    ):
        return data

    normalized = data
    for start, end in reversed(spans):
        normalized = (
            normalized[:start] + CODEX_CANONICAL_PROJECTION_REF + normalized[end:]
        )
    expected_payload = copy.deepcopy(payload)
    for server_name, argument_index, _projection in locations:
        expected_payload["mcp_servers"][server_name]["args"][
            argument_index
        ] = canonical_projection
    try:
        normalized_payload = tomllib.loads(normalized.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return data
    return normalized if normalized_payload == expected_payload else data


def source_for(
    builder: Builder, root: Path, path: Path, data: bytes, source_type: str
) -> str:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    return builder.add_source(
        relative,
        source_type,
        content_hash=file_hash(data),
        metadata={"evidence_class": evidence_class_for_path(relative)},
    )


def evidence_class_for_path(relative: str) -> str:
    parts = tuple(part.lower() for part in Path(relative).parts)
    if parts and parts[0] == ".workingdir2":
        return "scratch"
    if parts and parts[0] == ".githooks":
        return "test"
    if any(
        part in {"test", "tests", "fixtures", "fixture", "testdata"} for part in parts
    ):
        return "test"
    if parts and parts[0] == "docs":
        return "reference"
    if any(part in {"example", "examples"} for part in parts):
        return "reference"
    return "repository"


def read_text(root: Path, path: Path) -> tuple[bytes, str]:
    relative = path.relative_to(root).as_posix()
    data = read_regular_file(
        path,
        max_bytes=MAX_DISCOVERY_FILE_BYTES,
        label=f"tracked discovery input {relative}",
    )
    return data, data.decode("utf-8", errors="replace")


def add_local_root(
    builder: Builder,
    source_id: str,
    path: str,
    kind: str,
    name: str | None = None,
    version: str | None = None,
) -> tuple[str, str]:
    component_id = builder.add_component(
        kind=kind,
        ecosystem="local",
        name=name or path,
        identity=f"local:{kind}:{path}",
        official_channel_required=False,
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=version,
        source_ref=builder.sources[source_id].get("content_hash"),
        resolution_state="resolved",
        evidence=(path,),
    )
    return component_id, version_id


def discover_repo(
    root: Path,
    include_workingdir: bool = False,
    *,
    observed_at: str,
    base_manifest_id: str | None = None,
    previous_observed_at: str | None = None,
) -> dict[str, Any]:
    if not valid_live_observed_at(observed_at):
        raise RegistryInputError("observed-at must be an exact canonical UTC second")
    if (base_manifest_id is None) != (previous_observed_at is None):
        raise RegistryInputError(
            "previous manifest identity and observed-at must be supplied together"
        )
    if previous_observed_at is not None:
        if not valid_live_observed_at(previous_observed_at):
            raise RegistryInputError("previous observed-at is invalid")
        if parse_utc_second(observed_at) <= parse_utc_second(previous_observed_at):
            raise RegistryInputError(
                "observed-at must be strictly newer than the previous capture"
            )
    source_root = root.absolute()
    try:
        root_metadata = os.lstat(source_root)
    except OSError as exc:
        raise RegistryInputError(f"cannot inspect repository root: {exc}") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise RegistryInputError("repository root must be a non-symlink directory")
    deadline = time.monotonic() + MAX_REPOSITORY_DISCOVERY_SECONDS
    file_records, tracked_paths, repository = repository_snapshot(
        source_root,
        include_workingdir=include_workingdir,
        deadline=deadline,
    )
    selected_records = [
        record for record in file_records if is_discovery_file(Path(record["path"]))
    ]
    with CommittedRepositoryView(
        selected_records, tracked_paths, source_root=source_root
    ) as view:
        root = view.root
        selected_files = [root / str(record["path"]) for record in selected_records]
        builder = Builder()
        builder.self_repository_urls = frozenset(
            normalize_git_repository_url(str(item))
            for item in repository.get("remote_urls", [])
        )
        builder.helm_lock_policy_evidence = helm_lock_policy_proof(root)
        builder.latest_image_fixture_policy = latest_image_fixture_policy(root)
        repository_capture = {
            **repository,
            "observed_at": observed_at,
            "discovery_file_count": len(selected_files),
        }
        capture_hash = file_hash(canonical_json(repository_capture).encode("utf-8"))
        repository_source_id = builder.add_source(
            "git:repository:self",
            "git-repository-capture",
            content_hash=capture_hash,
            metadata={
                "evidence_class": "repository",
                "capture": repository_capture,
            },
        )
        repository_component_id = builder.add_component(
            kind="source-repository",
            ecosystem="git",
            name="self",
            identity="git:repository:self",
            lifecycles=("repository-used",),
        )
        repository_version_id = builder.add_version(
            repository_component_id,
            source_ref=repository["head_commit"],
            artifact_digest=repository["tracked_inventory_sha256"],
            resolution_state="resolved",
            evidence=("git:repository:self",),
            metadata={
                "observed_at": observed_at,
                "source_valid_at": repository["head_committed_at"],
                "source_valid_time_basis": "git-commit-committer-time",
            },
        )
        builder.add_occurrence(
            repository_component_id,
            repository_version_id,
            repository_source_id,
            locator="/capture/head_commit",
            role="repository-capture",
            raw_value=repository["head_commit"],
            directness="root",
            dependency_scope="platform",
            lifecycle="repository-used",
        )
        total_bytes = 0
        for path in selected_files:
            if time.monotonic() >= deadline:
                raise RegistryInputError(
                    f"repository discovery exceeds deadline "
                    f"{MAX_REPOSITORY_DISCOVERY_SECONDS}s"
                )
            relative = path.relative_to(root).as_posix()
            tracked = True
            try:
                data, text = read_text(root, path)
                total_bytes += len(data)
                if total_bytes > MAX_DISCOVERY_TOTAL_BYTES:
                    raise RegistryInputError(
                        "discovery inputs exceed total byte bound "
                        f"{MAX_DISCOVERY_TOTAL_BYTES}"
                    )
            except (OSError, RegistryInputError) as exc:
                source_id = builder.add_source(relative, "unreadable")
                builder.add_gap("source-unreadable", str(exc), source_id=source_id)
                builder.add_discovery_input(
                    relative,
                    content_hash=None,
                    disposition="unreadable",
                    tracked=tracked,
                    evidence_class=evidence_class_for_path(relative),
                    error=str(exc),
                )
                continue
            if relative == ".codex/config.toml":
                data = normalize_codex_projection_references(data)
                text = data.decode("utf-8", errors="replace")
            before = (
                len(builder.sources),
                len(builder.components),
                len(builder.versions),
                len(builder.occurrences),
                len(builder.edges),
                len(builder.extra_gaps),
            )
            scanners: list[str] = []

            def invoke(name: str, scanner: Any) -> None:
                scanners.append(name)
                scanner(builder, root, path, data, text)

            lower_name = path.name.lower()
            suffix = path.suffix.lower()
            if lower_name == "chart.yaml":
                invoke("helm-chart", scan_chart)
            if lower_name == "chart.lock":
                invoke("helm-lock", scan_chart_lock)
            if suffix in {".yaml", ".yml"}:
                invoke("yaml", scan_yaml)
                if "requirements" in lower_name and (
                    "ansible" in relative or lower_name == "requirements.yml"
                ):
                    invoke("ansible-requirements", scan_ansible_requirements)
                if relative.startswith(".github/workflows/"):
                    invoke("github-actions", scan_github_actions)
                if lower_name in {".pre-commit-config.yaml", ".pre-commit-config.yml"}:
                    invoke("pre-commit", scan_precommit)
                if lower_name == "pnpm-lock.yaml":
                    invoke("pnpm-lock", scan_pnpm_lock)
            if lower_name == "go.mod":
                invoke("go-mod", scan_go_mod)
            if lower_name == "go.sum":
                invoke("go-sum", scan_go_sum)
            if lower_name.startswith("requirements") and suffix in {"", ".txt", ".in"}:
                invoke("python-requirements", scan_python_requirements)
            if lower_name == "pyproject.toml":
                invoke("pyproject", scan_pyproject)
            if lower_name == "hosts.toml" and "/certs.d/" in f"/{relative}":
                invoke("containerd-hosts", scan_containerd_hosts)
            if lower_name == ".gitleaks.toml":
                invoke("gitleaks-config", scan_gitleaks_config)
            if relative == ".codex/config.toml":
                invoke("codex-config", scan_codex_config)
            if lower_name in {
                "package.json",
                "package-lock.json",
                "npm-shrinkwrap.json",
            }:
                invoke("node-manifest", scan_node_json)
            if suffix == ".json":
                invoke("mcp-command-config", scan_mcp_command_config)
            if lower_name == "yarn.lock":
                invoke("yarn-lock", scan_yarn_lock)
            if lower_name == ".terraform.lock.hcl":
                invoke("terraform-lock", scan_terraform_lock)
            elif suffix == ".tf":
                invoke("terraform-config", scan_terraform_config)
            if lower_name.endswith((".pkr.hcl", ".pkr.json", ".pkrvars.hcl")):
                invoke("packer", scan_packer)
            if lower_name == "dockerfile" or lower_name.startswith("dockerfile."):
                invoke("dockerfile", scan_dockerfile)
            if suffix in {".py", ".sh"} and (
                relative.startswith("tools/specialist-prep/")
                or relative.startswith("tools/voice-bakeoff/")
            ):
                invoke("script-dependencies", scan_script_dependencies)
            if relative in TARGETED_INSTALL_SCRIPTS:
                invoke("install-script", scan_install_script)
            if lower_name in {
                ".nvmrc",
                ".node-version",
                ".python-version",
                "runtime.txt",
            }:
                invoke("toolchain-version", scan_toolchain_version_file)
            if suffix in {".yaml", ".yml"} or re.search(
                r"huggingface(?:\.co|_hub)|snapshot_download|s3://|HF_REPO|MODEL_REPO",
                text,
                re.IGNORECASE,
            ):
                invoke("model-artifact", scan_model_artifacts)
            after = (
                len(builder.sources),
                len(builder.components),
                len(builder.versions),
                len(builder.occurrences),
                len(builder.edges),
                len(builder.extra_gaps),
            )
            if not scanners:
                disposition = "unhandled"
                source_id = source_for(builder, root, path, data, "discovery-input")
                builder.add_gap(
                    "discovery-input-unhandled",
                    f"No discovery scanner is registered for {relative}",
                    source_id=source_id,
                    evidence=(relative,),
                )
            elif after == before:
                disposition = "inspected-no-observations"
            else:
                disposition = "parsed"
            builder.add_discovery_input(
                relative,
                content_hash=file_hash(data),
                disposition=disposition,
                scanners=scanners,
                tracked=tracked,
                evidence_class=evidence_class_for_path(relative),
            )
        after_files, after_tracked_paths, after_repository = repository_snapshot(
            source_root,
            include_workingdir=include_workingdir,
            deadline=deadline,
        )
    if (
        repository != after_repository
        or tracked_paths != after_tracked_paths
        or file_records != after_files
    ):
        raise RegistryInputError("Git repository changed during discovery")
    manifest = builder.manifest(base_manifest_id=base_manifest_id)
    manifest["observation"] = {
        "observed_at": observed_at,
        "source_valid_at": repository["head_committed_at"],
        "source_valid_time_basis": "git-commit-committer-time",
    }
    manifest["discovery_scope"]["tracked_file_count"] = repository["tracked_file_count"]
    manifest["discovery_scope"]["selected_file_count"] = repository[
        "selected_file_count"
    ]
    manifest["discovery_scope"]["discovery_file_count"] = len(selected_files)
    manifest["discovery_scope"]["discovery_bytes"] = total_bytes
    manifest["discovery_scope"]["tracked_inventory_sha256"] = repository[
        "tracked_inventory_sha256"
    ]
    return seal_manifest(manifest)


def yaml_key_values(text: str, key: str) -> Iterator[tuple[int, int, str]]:
    pattern = re.compile(rf"^(\s*)(?:-\s*)?{re.escape(key)}\s*:\s*(.*?)\s*(?:#.*)?$")
    for line_number, line in enumerate(text.splitlines(), 1):
        match = pattern.match(line)
        if match and scalar(match.group(2)):
            yield line_number, len(match.group(1)), scalar(match.group(2))


HELM_TEMPLATE_SEGMENT_RE = re.compile(r"\{\{-?\s*(.*?)\s*-?\}\}")
HELM_VALUES_PATH_RE = re.compile(r"^\$?\.Values((?:\.[A-Za-z_][\w-]*)+)$")
HELM_QUOTE_FILTER_RE = re.compile(r"^(.*?)\s*\|\s*quote$")
HELM_PRINTF_RE = re.compile(r'^printf\s+"((?:%s|[^"%\\]+)*)"\s+(.+)$')
HELM_REQUIRED_RE = re.compile(r'^required\s+"(?:[^"\\]|\\.)*"\s+(.+)$')


def parse_yaml_scalar_tree(text: str) -> dict[str, Any]:
    """Nested block-mapping scalars as (line, value) leaves; lists stay opaque."""

    tree: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, tree)]
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(r"^(\s*)([A-Za-z_][\w.-]*)\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if not match:
            continue
        indent = len(match.group(1).replace("\t", "  "))
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        value = scalar(match.group(3))
        parent = stack[-1][1]
        if value:
            parent[match.group(2)] = (line_number, value)
        else:
            child: dict[str, Any] = {}
            parent[match.group(2)] = child
            stack.append((indent, child))
    return tree


def resolve_helm_values_expression(
    expression: str, tree: Mapping[str, Any]
) -> tuple[str, list[int]] | None:
    """Resolve one template body from chart values; None outside the grammar."""

    body = expression.strip()
    quoted = HELM_QUOTE_FILTER_RE.match(body)
    if quoted:
        body = quoted.group(1).strip()
    printf = HELM_PRINTF_RE.match(body)
    if printf:
        arguments = printf.group(2).split()
        pieces = printf.group(1).split("%s")
        if len(arguments) != len(pieces) - 1:
            return None
        resolved_text = pieces[0]
        lines: list[int] = []
        for argument, piece in zip(arguments, pieces[1:]):
            resolved = resolve_helm_values_expression(argument, tree)
            if resolved is None:
                return None
            resolved_text += resolved[0] + piece
            lines.extend(resolved[1])
        return resolved_text, lines
    required = HELM_REQUIRED_RE.match(body)
    if required:
        body = required.group(1).strip()
    path = HELM_VALUES_PATH_RE.match(body)
    if not path:
        return None
    node: Any = tree
    for part in path.group(1).lstrip(".").split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    if not isinstance(node, tuple) or not node[1]:
        return None
    return node[1], [node[0]]


def resolve_chart_template_image(
    root: Path, path: Path, value: str
) -> tuple[str, list[str]] | None:
    """Assemble a template image from the chart's own values; None keeps the gap."""

    chart_dir: Path | None = None
    for ancestor in path.parents:
        if (ancestor / "Chart.yaml").is_file() and (ancestor / "values.yaml").is_file():
            chart_dir = ancestor
            break
        if ancestor == root:
            break
    if chart_dir is None:
        return None
    relative_parts = path.relative_to(chart_dir).parts
    if not relative_parts or relative_parts[0] != "templates":
        return None
    values_path = chart_dir / "values.yaml"
    try:
        _, values_text = read_text(root, values_path)
    except (OSError, RegistryInputError):
        return None
    tree = parse_yaml_scalar_tree(values_text)
    values_relative = values_path.relative_to(root).as_posix()
    assembled: list[str] = []
    evidence_lines: set[int] = set()
    position = 0
    for match in HELM_TEMPLATE_SEGMENT_RE.finditer(value):
        assembled.append(value[position : match.start()])
        resolved = resolve_helm_values_expression(match.group(1), tree)
        if resolved is None:
            return None
        assembled.append(resolved[0])
        evidence_lines.update(resolved[1])
        position = match.end()
    assembled.append(value[position:])
    image = "".join(assembled)
    if TEMPLATE_EXPRESSION_RE.search(image) or oci_image_reference_error(image):
        return None
    return image, [f"{values_relative}#L{number}" for number in sorted(evidence_lines)]


def scan_yaml(builder: Builder, root: Path, path: Path, data: bytes, text: str) -> None:
    source_id = source_for(builder, root, path, data, "yaml")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "yaml-document"
    )
    fixture_policy = builder.latest_image_fixture_policy
    fixture_evidence: tuple[str, ...] = ()
    if (
        fixture_policy is not None
        and fixture_policy[0].search(relative)
        and path.parent.name.endswith("-cel")
        and git_path_is_tracked(root, path.parent / "kyverno-test.yaml")
    ):
        fixture_evidence = (
            *fixture_policy[1],
            f"{Path(relative).parent.as_posix()}/kyverno-test.yaml",
        )
    lines = text.splitlines()

    # Kubernetes GVK observations are paired by document, not guessed globally.
    document_start = 1
    document_api: tuple[int, str] | None = None
    document_kind: tuple[int, str] | None = None

    def emit_gvk() -> None:
        nonlocal document_api, document_kind
        if not document_api or not document_kind:
            return
        api_line, api_version = document_api
        kind_line, kind = document_kind
        # Group-qualified gvk mirrors import-live so repo+live merge cleanly.
        group, version = split_kubernetes_group_version(api_version)
        component_id = builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace=group,
            name=kind,
            identity=f"gvk:{group}/{version}:{kind}",
            metadata={"api_group": group, "gvk": f"{group}/{version}/{kind}"},
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version,
            evidence=(f"{relative}#L{api_line}", f"{relative}#L{kind_line}"),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"lines:{api_line},{kind_line}",
            role="kubernetes-gvk",
            raw_value=f"{api_version}/{kind}",
            root_id=root_component,
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="uses-api",
            source_occurrence_id=occurrence_id,
            scope="api",
        )

    section_stack: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, 1):
        if re.match(r"^\s*---\s*(?:#.*)?$", line):
            emit_gvk()
            document_api = None
            document_kind = None
            document_start = line_number + 1
            section_stack.clear()
            continue
        match = re.match(
            r"^(\s*)(?:-\s*)?([A-Za-z_][\w.-]*)\s*:\s*(.*?)\s*(?:#.*)?$", line
        )
        if not match:
            continue
        indent = len(match.group(1).replace("\t", "  "))
        key = match.group(2)
        value = scalar(match.group(3))
        while section_stack and section_stack[-1][0] >= indent:
            section_stack.pop()
        if not value:
            section_stack.append((indent, key))
        if key == "apiVersion" and value and document_api is None:
            document_api = (line_number, value)
        elif key == "kind" and value and document_kind is None:
            document_kind = (line_number, value)
        elif key == "image" and value:
            sections = [item[1] for item in section_stack]
            lower_sections = {item.lower() for item in sections}
            if lower_sections.intersection({"pattern", "anypattern"}):
                # Kyverno pattern values describe allowed/denied shapes; they
                # are not selected runtime image references.
                continue
            if "models" in lower_sections and not lower_sections.intersection(
                {"containers", "initcontainers", "ephemeralcontainers"}
            ):
                # A model artifact/prefix named `image` is not an OCI image.
                # scan_model_artifacts handles it with model-specific identity.
                continue
            if "initContainers" in sections:
                role = "init-container-image"
            elif "ephemeralContainers" in sections:
                role = "ephemeral-container-image"
            else:
                role = "container-image"
            occurrence_metadata: dict[str, Any] = {
                "document_start_line": document_start
            }
            if TEMPLATE_EXPRESSION_RE.search(value):
                resolved_image = resolve_chart_template_image(root, path, value)
                if resolved_image is None:
                    builder.add_gap(
                        "image-expression-unresolved",
                        f"Image expression {value!r} must be resolved by rendering",
                        source_id=source_id,
                        evidence=(f"{relative}#L{line_number}",),
                    )
                    continue
                occurrence_metadata["template_expression"] = value
                occurrence_metadata["values_evidence"] = resolved_image[1]
                value = resolved_image[0]
            if fixture_evidence:
                occurrence_metadata["test_fixture"] = True
                occurrence_metadata["test_fixture_evidence"] = list(fixture_evidence)
            _, version_id, occurrence_id = builder.add_image(
                value,
                source_id,
                f"line:{line_number}",
                role,
                root_id=root_component,
                metadata=occurrence_metadata,
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="uses-image",
                source_occurrence_id=occurrence_id,
                scope="runtime",
            )
    emit_gvk()
    scan_yaml_image_maps(
        builder, source_id, relative, text, root_component, root_version
    )
    document_start = 0
    document_index = 0
    for match in re.finditer(r"(?m)^\s*---\s*(?:#.*)?$", text):
        document = text[document_start : match.start()]
        if document.strip():
            scan_argo_app_yaml(
                builder,
                source_id,
                relative,
                document,
                root_component,
                root_version,
                document_index=document_index,
                line_offset=text.count("\n", 0, document_start),
            )
            document_index += 1
        document_start = match.end()
    document = text[document_start:]
    if document.strip():
        scan_argo_app_yaml(
            builder,
            source_id,
            relative,
            document,
            root_component,
            root_version,
            document_index=document_index,
            line_offset=text.count("\n", 0, document_start),
        )


def scan_yaml_image_maps(
    builder: Builder,
    source_id: str,
    relative: str,
    text: str,
    root_component: str,
    root_version: str,
) -> None:
    """Discover Helm-style image maps without pretending the file was rendered.

    Common charts split an image across `repository`, `tag`, `digest`, and
    sometimes `registry` below an `image:` mapping. Keeping the exact field
    coordinates makes this deterministic while rendered/live inventory remains
    the final deployment authority.
    """

    lines = text.splitlines()
    image_header = re.compile(r"^(\s*)([A-Za-z_][\w.-]*[Ii]mage|image)\s*:\s*(?:#.*)?$")
    field_re = re.compile(
        r"^(\s*)(registry|repository|tag|digest)\s*:\s*(.*?)\s*(?:#.*)?$",
        re.IGNORECASE,
    )
    for index, line in enumerate(lines):
        header = image_header.match(line)
        if not header:
            continue
        base_indent = len(header.group(1).replace("\t", "  "))
        fields: dict[str, tuple[int, str]] = {}
        for child_index in range(index + 1, len(lines)):
            child = lines[child_index]
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            child_indent = len(child) - len(child.lstrip(" \t"))
            if child_indent <= base_indent:
                break
            field = field_re.match(child)
            if field:
                value = scalar(field.group(3))
                if value:
                    fields.setdefault(field.group(2).lower(), (child_index + 1, value))
        if "repository" not in fields:
            continue
        repository_line, repository = fields["repository"]
        registry = fields.get("registry", (0, ""))[1].rstrip("/")
        tag = fields.get("tag", (0, ""))[1]
        digest = fields.get("digest", (0, ""))[1]
        if TEMPLATE_EXPRESSION_RE.search(" ".join((registry, repository, tag, digest))):
            builder.add_gap(
                "image-expression-unresolved",
                f"Structured image below line {index + 1} must be resolved by rendering",
                source_id=source_id,
                evidence=(f"{relative}#L{index + 1}",),
            )
            continue
        first_segment = repository.split("/", 1)[0]
        repository_has_registry = (
            "." in first_segment or ":" in first_segment or first_segment == "localhost"
        )
        if registry and not repository_has_registry:
            repository = f"{registry}/{repository.lstrip('/')}"
        if tag:
            image = f"{repository}:{tag}"
            if digest and "@" not in tag:
                image += f"@{digest}"
        elif digest:
            image = f"{repository}@{digest}"
        else:
            image = repository
        locator_lines = sorted(
            {line_number for line_number, _ in fields.values() if line_number}
        )
        locator = "lines:" + ",".join(str(number) for number in locator_lines)
        _, version_id, occurrence_id = builder.add_image(
            image,
            source_id,
            locator,
            "structured-image-values",
            root_id=root_component,
            metadata={
                "image_map_key": header.group(2),
                "image_map_line": index + 1,
                "repository_line": repository_line,
                "requires_render_verification": True,
            },
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="uses-image",
            source_occurrence_id=occurrence_id,
            scope="runtime",
            resolver="yaml-image-map",
        )


def scan_argo_app_yaml(
    builder: Builder,
    source_id: str,
    relative: str,
    text: str,
    root_component: str,
    root_version: str,
    *,
    document_index: int = 0,
    line_offset: int = 0,
) -> None:
    if not re.search(r"(?m)^\s*kind:\s*Application(?:Set)?\s*$", text):
        return
    kind_match = re.search(r"(?m)^\s*kind:\s*(ApplicationSet|Application)\s*$", text)
    kind = kind_match.group(1) if kind_match else "Application"
    metadata_match = re.search(r"(?ms)^metadata:\s*\n((?:[ \t]+.*(?:\n|$))*)", text)
    metadata_body = metadata_match.group(1) if metadata_match else ""
    name_match = re.search(r"(?m)^\s+name:\s*([^\s#]+)", metadata_body)
    namespace_match = re.search(r"(?m)^\s+namespace:\s*([^\s#]+)", metadata_body)
    name = scalar(name_match.group(1)) if name_match else f"{relative}#{document_index}"
    namespace = scalar(namespace_match.group(1)) if namespace_match else "argocd"
    app_component = builder.add_component(
        kind=f"argo-{kind.lower()}",
        ecosystem="argocd",
        namespace=namespace,
        name=name,
        identity=argo_application_identity(kind, namespace, name),
        metadata={"document_index": document_index},
        official_channel_required=False,
    )
    app_version = builder.add_version(
        app_component,
        source_ref=builder.sources[source_id].get("content_hash"),
        resolution_state="resolved",
        evidence=(relative,),
    )
    app_occ = builder.add_occurrence(
        app_component,
        app_version,
        source_id,
        locator=f"document:{document_index}",
        role="argo-application-root",
        raw_value=name,
        root_id=root_component,
    )
    builder.add_edge(
        root_version,
        app_version,
        relationship="declares",
        source_occurrence_id=app_occ,
        scope="deployment",
    )

    # repoURL/chart/targetRevision/path occur in both source and sources forms.
    current: dict[str, tuple[int, str]] = {}
    entries: list[dict[str, tuple[int, str]]] = []
    in_sources_indent: int | None = None
    for local_line_number, line in enumerate(text.splitlines(), 1):
        line_number = local_line_number + line_offset
        list_match = re.match(
            r"^(\s*)-\s*(repoURL|chart|targetRevision|path):\s*(.*?)\s*$", line
        )
        key_match = re.match(
            r"^(\s*)(repoURL|chart|targetRevision|path):\s*(.*?)\s*$", line
        )
        if list_match:
            indent = len(list_match.group(1))
            if (
                current
                and in_sources_indent is not None
                and indent <= in_sources_indent
            ):
                entries.append(current)
                current = {}
            in_sources_indent = indent
            current[list_match.group(2)] = (line_number, scalar(list_match.group(3)))
        elif key_match:
            indent = len(key_match.group(1))
            if (
                current
                and in_sources_indent is not None
                and indent <= in_sources_indent
            ):
                entries.append(current)
                current = {}
                in_sources_indent = None
            current[key_match.group(2)] = (line_number, scalar(key_match.group(3)))
    if current:
        entries.append(current)
    # Remove fragments that do not identify a source, then deduplicate exact sets.
    unique_entries = {
        canonical_json(entry): entry for entry in entries if "repoURL" in entry
    }
    for entry_number, entry in enumerate(unique_entries.values()):
        repo_line, repo = entry["repoURL"]
        revision = entry.get("targetRevision", (repo_line, ""))[1]
        chart = entry.get("chart", (repo_line, ""))[1]
        chart_path = entry.get("path", (repo_line, ""))[1]
        if chart:
            component_id = builder.add_component(
                kind="helm-chart",
                ecosystem="helm",
                name=chart,
                identity=f"helm:{repo}:{chart}",
                metadata={"chart_repository": repo},
            )
            version_id = builder.add_version(
                component_id,
                resolved_version=revision or None,
                constraint=revision or None,
                evidence=(f"{relative}#L{repo_line}",),
            )
            raw = f"{repo}#{chart}@{revision}"
            role = "argo-helm-source"
        else:
            name_value = chart_path or repo.rsplit("/", 1)[-1].removesuffix(".git")
            git_source_metadata: dict[str, Any] = {
                "source_repo": repo,
                "path": chart_path,
            }
            if repo and normalize_git_repository_url(repo) in (
                builder.self_repository_urls
            ):
                git_source_metadata["self_repository"] = True
            component_id = builder.add_component(
                kind="git-repository",
                ecosystem="git",
                name=name_value,
                identity=f"git:{repo}:{chart_path}",
                metadata=git_source_metadata,
            )
            version_id = builder.add_version(
                component_id,
                source_ref=revision or None,
                constraint=revision or None,
                evidence=(f"{relative}#L{repo_line}",),
            )
            raw = f"{repo}#{chart_path}@{revision}"
            role = "argo-git-source"
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{repo_line}:source:{entry_number}",
            role=role,
            raw_value=raw,
            root_id=app_component,
            dependency_scope="deployment",
        )
        builder.add_edge(
            app_version,
            version_id,
            relationship="desired-source",
            source_occurrence_id=occurrence_id,
            constraint=revision or None,
            scope="deployment",
            resolver="argocd-application",
        )


def parse_yaml_dependency_blocks(
    text: str, section_names: Sequence[str] = ("dependencies",)
) -> list[dict[str, tuple[int, str]]]:
    """Parse named list entries only from explicitly selected YAML sections.

    Helm Chart metadata commonly contains other ``- name:`` lists (notably
    maintainers). Treating those as dependencies creates convincing but false
    package identities, so this deliberately tracks the section and item
    indentation instead of scanning list names globally.
    """

    result: list[dict[str, tuple[int, str]]] = []
    section_indent: int | None = None
    item_indent: int | None = None
    current: dict[str, tuple[int, str]] | None = None
    section_pattern = "|".join(re.escape(item) for item in section_names)
    for line_number, line in enumerate(text.splitlines(), 1):
        section = re.match(rf"^(\s*)(?:{section_pattern})\s*:\s*(?:#.*)?$", line)
        if section:
            if current:
                result.append(current)
            current = None
            section_indent = len(section.group(1).replace("\t", "  "))
            item_indent = None
            continue
        if section_indent is None or not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        match = re.match(r"^(\s*)-\s*name:\s*(.*?)\s*(?:#.*)?$", line)
        if match and indent >= section_indent:
            if current:
                result.append(current)
            item_indent = len(match.group(1).replace("\t", "  "))
            name = scalar(match.group(2))
            current = {"name": (line_number, name)} if name else None
            continue
        if indent <= section_indent:
            if current:
                result.append(current)
            current = None
            section_indent = None
            item_indent = None
            continue
        if current is None or item_indent is None:
            continue
        if re.match(r"^\s*-\s*", line) and indent <= item_indent:
            current = None
            item_indent = None
            continue
        field = re.match(
            r"^(\s+)(version|repository|source|type):\s*(.*?)\s*(?:#.*)?$",
            line,
        )
        if field and len(field.group(1).replace("\t", "  ")) > item_indent:
            value = scalar(field.group(3))
            if value:
                current[field.group(2)] = (line_number, value)
    if current:
        result.append(current)
    return result


def chart_identity(text: str, relative: str) -> tuple[str, str | None]:
    name_match = re.search(r"(?m)^name\s*:\s*(.*?)\s*(?:#.*)?$", text)
    version_match = re.search(r"(?m)^version\s*:\s*(.*?)\s*(?:#.*)?$", text)
    name = scalar(name_match.group(1)) if name_match else Path(relative).parent.name
    version = scalar(version_match.group(1)) if version_match else None
    return name, version


def scan_chart(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "helm-chart-metadata")
    relative = builder.sources[source_id]["evidence_uri"]
    chart_name, chart_version = chart_identity(text, relative)
    chart_component = builder.add_component(
        kind="helm-chart",
        ecosystem="helm",
        name=chart_name,
        identity=f"local-helm:{path.parent.relative_to(root).as_posix()}:{chart_name}",
        official_channel_required=False,
    )
    chart_version_id = builder.add_version(
        chart_component,
        resolved_version=chart_version,
        source_ref=builder.sources[source_id]["content_hash"],
        resolution_state="resolved",
        evidence=(relative,),
    )
    builder.add_occurrence(
        chart_component,
        chart_version_id,
        source_id,
        locator="document",
        role="helm-chart-root",
        raw_value=chart_name,
        root_id=chart_component,
    )
    dependencies = parse_yaml_dependency_blocks(text)
    for index, dependency in enumerate(dependencies):
        name_line, name = dependency["name"]
        version = dependency.get("version", (name_line, ""))[1]
        repository = dependency.get("repository", (name_line, ""))[1]
        component_id = builder.add_component(
            kind="helm-chart",
            ecosystem="helm",
            name=name,
            identity=f"helm:{repository}:{name}",
            metadata={"chart_repository": repository} if repository else {},
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version if looks_exact(version) else None,
            constraint=version if version and not looks_exact(version) else None,
            evidence=(f"{relative}#L{name_line}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{name_line}:dependency:{index}",
            role="helm-dependency",
            raw_value=f"{name}@{version}",
            root_id=chart_component,
        )
        builder.add_edge(
            chart_version_id,
            version_id,
            relationship="depends-on",
            source_occurrence_id=occurrence_id,
            constraint=version or None,
            scope="runtime",
            resolver="helm-chart",
        )
    if dependencies and not (path.parent / "Chart.lock").exists():
        policy_evidence = builder.helm_lock_policy_evidence
        exact_pins = all(
            looks_exact(dependency.get("version", (0, ""))[1])
            for dependency in dependencies
        )
        if policy_evidence and exact_pins:
            builder.add_gap(
                "helm-lock-policy",
                f"{relative} relies on the deliberate Chart.lock-untracked policy; "
                "its exact Chart.yaml pins are the durable truth",
                component_id=chart_component,
                component_version_id=chart_version_id,
                source_id=source_id,
                evidence=(relative, *policy_evidence),
            )
        else:
            builder.add_gap(
                "helm-lock-missing",
                f"{relative} declares dependencies but Chart.lock is absent",
                component_id=chart_component,
                component_version_id=chart_version_id,
                source_id=source_id,
                evidence=(relative,),
            )


def scan_chart_lock(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "helm-chart-lock")
    relative = builder.sources[source_id]["evidence_uri"]
    chart_path = path.with_name("Chart.yaml")
    chart_text = ""
    chart_relative = ""
    declared_dependencies: dict[str, dict[str, tuple[int, str]]] = {}
    if chart_path.is_file():
        chart_data, chart_text = read_text(root, chart_path)
        chart_source = source_for(
            builder, root, chart_path, chart_data, "helm-chart-metadata"
        )
        chart_relative = builder.sources[chart_source]["evidence_uri"]
        chart_name, chart_version = chart_identity(chart_text, chart_relative)
        root_component = builder.add_component(
            kind="helm-chart",
            ecosystem="helm",
            name=chart_name,
            identity=(
                f"local-helm:{chart_path.parent.relative_to(root).as_posix()}:{chart_name}"
            ),
            official_channel_required=False,
        )
        root_version = builder.add_version(
            root_component,
            resolved_version=chart_version,
            source_ref=builder.sources[chart_source]["content_hash"],
            resolution_state="resolved",
            evidence=(chart_relative,),
        )
        declared_dependencies = {
            dependency["name"][1]: dependency
            for dependency in parse_yaml_dependency_blocks(chart_text)
        }
    else:
        root_component, root_version = add_local_root(
            builder, source_id, relative, "helm-lock"
        )
        builder.add_gap(
            "helm-chart-root-missing",
            f"{relative} has no sibling Chart.yaml to own its locked dependencies",
            component_id=root_component,
            component_version_id=root_version,
            source_id=source_id,
            evidence=(relative,),
        )
    if not git_path_is_tracked(root, path):
        builder.add_gap(
            "helm-lock-untracked",
            f"{relative} supplies exact dependency versions but is ignored/untracked",
            component_id=root_component,
            component_version_id=root_version,
            source_id=source_id,
            evidence=(relative,),
        )
    locked_names: set[str] = set()
    for index, dependency in enumerate(parse_yaml_dependency_blocks(text)):
        line, name = dependency["name"]
        locked_names.add(name)
        version = dependency.get("version", (line, ""))[1]
        repository = dependency.get("repository", (line, ""))[1]
        declared = declared_dependencies.get(name)
        declared_version = declared.get("version", (line, ""))[1] if declared else ""
        declared_repository = (
            declared.get("repository", (line, ""))[1] if declared else ""
        )
        if declared is None:
            builder.add_gap(
                "helm-lock-dependency-undeclared",
                f"{relative} locks undeclared dependency {name!r}",
                component_id=root_component,
                component_version_id=root_version,
                source_id=source_id,
                evidence=(f"{relative}#L{line}",),
            )
        elif declared_repository and repository != declared_repository:
            builder.add_gap(
                "helm-lock-repository-mismatch",
                f"{relative} locks {name!r} from {repository!r}, declared as {declared_repository!r}",
                component_id=root_component,
                component_version_id=root_version,
                source_id=source_id,
                evidence=(
                    f"{relative}#L{line}",
                    f"{chart_relative}#L{declared['name'][0]}",
                ),
            )
        if (
            declared_version
            and looks_exact(declared_version)
            and looks_exact(version)
            and declared_version.removeprefix("v") != version.removeprefix("v")
        ):
            builder.add_gap(
                "helm-lock-version-mismatch",
                f"{relative} locks {name!r} at {version!r}, but Chart.yaml declares {declared_version!r}",
                component_id=root_component,
                component_version_id=root_version,
                source_id=source_id,
                evidence=(f"{relative}#L{line}",),
            )
        component_id = builder.add_component(
            kind="helm-chart",
            ecosystem="helm",
            name=name,
            identity=f"helm:{repository}:{name}",
            metadata={"chart_repository": repository} if repository else {},
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version,
            evidence=(f"{relative}#L{line}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line}:lock:{index}",
            role="helm-locked-dependency",
            raw_value=f"{name}@{version}",
            root_id=root_component,
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="locks",
            source_occurrence_id=occurrence_id,
            constraint=declared_version or version,
            resolver="helm-lock",
        )
    for name, declared in sorted(declared_dependencies.items()):
        if name not in locked_names:
            line = declared["name"][0]
            builder.add_gap(
                "helm-lock-entry-missing",
                f"{relative} does not lock declared dependency {name!r}",
                component_id=root_component,
                component_version_id=root_version,
                source_id=source_id,
                evidence=(f"{relative}#L{line}",),
            )


def dockerfile_instructions(text: str) -> Iterator[tuple[int, str, str]]:
    """Yield logical Dockerfile instructions with their first source line."""

    start_line = 0
    logical = ""
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.rstrip()
        if not logical and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not logical:
            start_line = line_number
        continued = line.endswith("\\")
        logical += line[:-1] + " " if continued else line
        if continued:
            continue
        match = re.match(r"^\s*([A-Za-z]+)\s+(.*)$", logical, re.S)
        if match:
            yield start_line, match.group(1).upper(), match.group(2).strip()
        logical = ""
    if logical:
        match = re.match(r"^\s*([A-Za-z]+)\s+(.*)$", logical, re.S)
        if match:
            yield start_line, match.group(1).upper(), match.group(2).strip()


DOCKER_ARG_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:(?::?[-+?])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))"
)


def expand_docker_args(
    value: str, arguments: Mapping[str, str]
) -> tuple[str, set[str]]:
    unresolved: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(3) or ""
        fallback = match.group(2)
        if name in arguments and arguments[name] != "":
            return arguments[name]
        if fallback is not None:
            return fallback
        unresolved.add(name)
        return match.group(0)

    return DOCKER_ARG_RE.sub(replace, value), unresolved


SHELL_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SHELL_URL_RE = re.compile(r"https?://[^\s'\"<>|)]+")
GIT_CLONE_OPTIONS_WITH_VALUE = {
    "--branch",
    "--config",
    "--depth",
    "--filter",
    "--jobs",
    "--origin",
    "--reference",
    "--reference-if-able",
    "--separate-git-dir",
    "--shallow-exclude",
    "--shallow-since",
    "--template",
    "-b",
    "-c",
    "-j",
    "-o",
    "-u",
}


def shell_logical_commands(text: str) -> Iterator[tuple[int, str]]:
    """Yield physical shell lines joined across backslash continuations."""

    logical = ""
    start_line = 0
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.rstrip()
        if not logical:
            start_line = line_number
        continued = line.endswith("\\")
        logical += line[:-1] + " " if continued else line
        if continued:
            continue
        if logical.strip() and not logical.lstrip().startswith("#"):
            yield start_line, logical.strip()
        logical = ""
    if logical.strip() and not logical.lstrip().startswith("#"):
        yield start_line, logical.strip()


def shell_clauses(command: str) -> Iterator[str]:
    for clause in re.split(r"\s*(?:&&|\|\||;|(?<!\|)\|(?!\|))\s*", command):
        if clause.strip():
            yield clause.strip()


def shell_tokens(clause: str) -> list[str]:
    try:
        tokens = shlex.split(clause, comments=True, posix=True)
    except ValueError:
        return []
    while tokens and (
        tokens[0].startswith("--mount=") or SHELL_ASSIGNMENT_RE.match(tokens[0])
    ):
        tokens.pop(0)
    if tokens and tokens[0] == "sudo":
        tokens.pop(0)
        while tokens and tokens[0].startswith("-"):
            tokens.pop(0)
        while tokens and SHELL_ASSIGNMENT_RE.match(tokens[0]):
            tokens.pop(0)
    return tokens


def shell_install_tokens(clause: str) -> tuple[str, list[str]] | None:
    tokens = shell_tokens(clause)
    patterns = (
        ({"apt", "apt-get"}, "install", "deb"),
        ({"apk"}, "add", "apk"),
        ({"dnf", "microdnf", "yum"}, "install", "rpm"),
    )
    for commands, verb, ecosystem in patterns:
        if not tokens or tokens[0] not in commands or verb not in tokens[1:]:
            continue
        start = tokens.index(verb) + 1
        packages = [
            token
            for token in tokens[start:]
            if not token.startswith("-")
            and token not in {"\\"}
            and not re.fullmatch(r"\d*(?:>>?|<<?)", token)
        ]
        return ecosystem, packages
    return None


def shell_pip_install(clause: str) -> tuple[list[str], list[str]] | None:
    tokens = shell_tokens(clause)
    pip_index = -1
    if tokens and re.fullmatch(r"pip(?:3(?:\.\d+)?)?", tokens[0]):
        pip_index = 0
    elif tokens and tokens[0] == "pipx":
        pip_index = 0
    elif (
        len(tokens) >= 3
        and tokens[0].startswith("python")
        and tokens[1:3] == ["-m", "pip"]
    ):
        pip_index = 2
    if pip_index < 0 or "install" not in tokens[pip_index + 1 :]:
        return None
    start = tokens.index("install", pip_index + 1) + 1
    packages: list[str] = []
    requirements: list[str] = []
    skip_next = False
    requirement_next = False
    options_with_value = {
        "-c",
        "--constraint",
        "-f",
        "--find-links",
        "-i",
        "--index-url",
        "--extra-index-url",
        "--trusted-host",
        "--target",
        "--prefix",
        "--root",
        "--python",
    }
    for token in tokens[start:]:
        if requirement_next:
            requirements.append(token)
            requirement_next = False
            continue
        if skip_next:
            skip_next = False
            continue
        if token in {"-r", "--requirement"}:
            requirement_next = True
            continue
        if token.startswith("--requirement="):
            requirements.append(token.split("=", 1)[1])
            continue
        if token in options_with_value:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        packages.append(token)
    return packages, requirements


def shell_npm_install(clause: str) -> list[str] | None:
    tokens = shell_tokens(clause)
    if not tokens or tokens[0] != "npm":
        return None
    verbs = {"add", "i", "install", "pack"}
    if not any(token in verbs for token in tokens[1:]):
        return None
    start = next(index + 1 for index, token in enumerate(tokens) if token in verbs)
    result: list[str] = []
    skip_next = False
    for token in tokens[start:]:
        if skip_next:
            skip_next = False
            continue
        if token in {
            "--cache",
            "--pack-destination",
            "--prefix",
            "--registry",
            "--workspace",
        }:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        result.append(token)
    return result


def parse_git_clone(clause: str) -> tuple[str, str | None] | None:
    tokens = shell_tokens(clause)
    if len(tokens) < 3 or tokens[:2] != ["git", "clone"]:
        return None
    repository = ""
    ref: str | None = None
    index = 2
    while index < len(tokens):
        token = tokens[index]
        if token in GIT_CLONE_OPTIONS_WITH_VALUE:
            if index + 1 < len(tokens):
                if token in {"--branch", "-b"}:
                    ref = tokens[index + 1]
                index += 2
                continue
            break
        if token.startswith("--branch="):
            ref = token.split("=", 1)[1]
        elif any(
            token.startswith(f"{option}=") for option in GIT_CLONE_OPTIONS_WITH_VALUE
        ):
            pass
        elif token.startswith("-"):
            pass
        elif not repository:
            repository = token
        index += 1
    return (repository, ref) if repository else None


def literal_shell_variables(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(
            r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(?:['\"]([^'\"]*)['\"]|([^\s#]+))\s*(?:#.*)?$",
            line,
        )
        if not match:
            continue
        value = match.group(2) if match.group(2) is not None else match.group(3) or ""
        if "$(" not in value and "${" not in value and "$" not in value:
            result[match.group(1)] = value
    return result


def expand_literal_variables(value: str, variables: Mapping[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(3) or ""
        transform = match.group(2) or ""
        resolved = variables.get(name)
        if resolved is None:
            return match.group(0)
        if transform and resolved.startswith(transform):
            return resolved[len(transform) :]
        return resolved

    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:#([^}]+))?\}|\$([A-Za-z_][A-Za-z0-9_]*)",
        replace,
        value,
    )


def package_spec(
    ecosystem: str, raw_value: str
) -> tuple[str, str | None, str | None, str, str] | None:
    raw = raw_value.strip().strip("\"'")
    if not raw or raw.startswith(("$", ".", "/")):
        return None
    name = raw
    version: str | None = None
    constraint: str | None = "unversioned"
    if ecosystem in {"apk", "deb", "rpm"} and "=" in raw:
        name, requested = raw.split("=", 1)
        if looks_exact(requested):
            version, constraint = requested, None
        else:
            constraint = f"={requested}"
    elif ecosystem == "pypi":
        requirement = PYTHON_REQUIREMENT_RE.match(raw)
        if not requirement:
            return None
        name, _extras, specifier, _marker = requirement.groups()
        exact = re.fullmatch(r"={2,3}\s*([^,;\s]+)", specifier or "")
        version = exact.group(1) if exact else None
        constraint = None if version else (specifier or "unversioned")
        # Canonical spelling matches the purl and the live SBOM emitter.
        name = name.lower().replace("_", "-")
    elif ecosystem == "npm":
        separator = raw.rfind("@")
        if separator <= 0 or (raw.startswith("@") and "/" not in raw[:separator]):
            name, version, constraint = raw, None, "unversioned"
        else:
            name, requested = raw[:separator], raw[separator + 1 :]
            if looks_exact(requested):
                version, constraint = requested, None
            else:
                version, constraint = None, requested
    name = name.strip()
    if not name or name.startswith("-"):
        return None
    namespace, short_name = (
        name.rsplit("/", 1) if ecosystem == "npm" and "/" in name else ("", name)
    )
    return name, version, constraint, namespace, short_name


def add_package_observation(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    ecosystem: str,
    package: str,
    locator: str,
    role: str,
    scope: str,
    resolver: str,
    relationship: str | None = None,
    optional: bool = False,
    lifecycle: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> tuple[str, str, str] | None:
    parsed = package_spec(ecosystem, package)
    if parsed is None:
        return None
    name, version, constraint, namespace, short_name = parsed
    component_id = builder.add_component(
        kind="library",
        ecosystem=ecosystem,
        namespace=namespace,
        name=short_name,
        purl=package_purl(ecosystem, name),
    )
    evidence_uri = builder.sources[source_id]["evidence_uri"]
    version_id = builder.add_version(
        component_id,
        resolved_version=version,
        constraint=constraint,
        resolution_state="resolved" if version else "unresolved",
        evidence=(f"{evidence_uri}#{locator}",),
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=package.strip().strip("\"'"),
        root_id=root_component,
        dependency_scope=scope,
        optional=optional,
        lifecycle=lifecycle,
        metadata=metadata,
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship=relationship
        or ("installs" if "package" in role or "requirement" in role else "depends-on"),
        source_occurrence_id=occurrence_id,
        constraint=constraint or version,
        scope=scope,
        optional=optional,
        resolver=resolver,
        metadata=metadata,
    )
    return component_id, version_id, occurrence_id


def remote_input_identity(url: str) -> tuple[str, str | None, str | None]:
    parsed = urlparse(url)
    path = parsed.path
    github_release = re.search(r"/([^/]+)/([^/]+)/releases/download/([^/]+)/", path)
    if github_release:
        owner, repository, ref = github_release.groups()
        exact = looks_exact(ref) and "$" not in ref and "{" not in ref
        return f"{owner}/{repository}", ref if exact else None, ref
    github_api = re.search(r"/repos/([^/]+)/([^/]+)/releases/(latest|[^/]+)", path)
    if parsed.netloc == "api.github.com" and github_api:
        owner, repository, ref = github_api.groups()
        return f"{owner}/{repository}", None, ref
    raw_github = re.match(r"/([^/]+)/([^/]+)/([^/]+)/", path)
    if parsed.netloc == "raw.githubusercontent.com" and raw_github:
        owner, repository, ref = raw_github.groups()
        exact = looks_exact(ref) and "$" not in ref and "{" not in ref
        return f"{owner}/{repository}", ref if exact else None, ref
    if parsed.netloc == "mise.run":
        return "mise", None, "latest"
    seven_zip = re.search(r"7z(\d{2})(\d{2})-linux", path)
    if seven_zip:
        return "7zip", f"{int(seven_zip.group(1))}.{seven_zip.group(2)}", None
    intel_driver = re.search(r"gfx_win_([0-9.]+)\.exe", path)
    if intel_driver:
        return "intel-arc-driver", intel_driver.group(1), None
    if "intel-arc-graphics-windows" in path:
        return "intel-arc-driver", None, "latest"
    name = Path(path).name or parsed.netloc
    return name, None, "unversioned"


def add_cli_observation(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    name: str,
    raw_version: str,
    locator: str,
    role: str,
    scope: str,
    resolver: str,
) -> tuple[str, str, str]:
    resolved = raw_version if looks_exact(raw_version) else None
    component_id = builder.add_component(
        kind="cli",
        ecosystem="generic",
        name=name,
        purl=package_purl("generic", name),
        identity=f"cli:{name}",
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=resolved,
        constraint=None if resolved else (raw_version or "unversioned"),
        source_ref=raw_version if raw_version.lower() in MUTABLE_REFS else None,
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=f"{name}@{raw_version}",
        root_id=root_component,
        dependency_scope=scope,
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship="requires-tool",
        source_occurrence_id=occurrence_id,
        constraint=raw_version,
        scope=scope,
        resolver=resolver,
    )
    return component_id, version_id, occurrence_id


def add_remote_input(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    url: str,
    locator: str,
    role: str,
    scope: str,
    resolver: str,
    installed_version: str | None = None,
) -> tuple[str, str, str]:
    if TEMPLATE_EXPRESSION_RE.search(url) or any(
        marker in url for marker in ("$", "{", "}")
    ):
        try:
            parsed_dynamic = urlsplit(url)
        except ValueError as exc:
            raise RegistryInputError(
                "dynamic remote input has an invalid authority"
            ) from exc
        if parsed_dynamic.username is not None or parsed_dynamic.password is not None:
            raise RegistryInputError(
                "dynamic remote input must not contain URI userinfo"
            )
        filename = Path(parsed_dynamic.path).name
        name = re.sub(
            r"\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*",
            "dynamic",
            filename,
        )
        name = re.sub(r"[^A-Za-z0-9._+-]+", "-", name).strip("-")
        if not name:
            name = "dynamic-remote-input"
        evidence_uri = str(builder.sources[source_id]["evidence_uri"])
        dynamic_input_identity = f"{evidence_uri}#{locator}"
        component_id = builder.add_component(
            kind="remote-build-artifact",
            ecosystem="generic",
            name=name,
            identity=f"remote-input-dynamic:{dynamic_input_identity}",
            # Recorded, not derived: the sanitized file name cannot rebuild the id.
            metadata={
                "dynamic_input_identity": dynamic_input_identity,
                "locator_state": "dynamic-template",
            },
        )
        version_id = builder.add_version(
            component_id,
            constraint="dynamic-template",
            evidence=(f"{evidence_uri}#{locator}",),
        )
        safe_reference = "urn:archeion:dynamic-remote-input:" + stable_id(
            "ref", source_id, locator
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=locator,
            role=role,
            raw_value=safe_reference,
            root_id=root_component,
            dependency_scope=scope,
            metadata={"locator_state": "dynamic-template"},
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="downloads",
            source_occurrence_id=occurrence_id,
            constraint="dynamic-template",
            scope=scope,
            resolver=resolver,
        )
        builder.add_gap(
            "remote-download-locator-unresolved",
            "Dynamic remote input locator cannot be resolved from static evidence",
            component_id=component_id,
            component_version_id=version_id,
            source_id=source_id,
            evidence=(f"{evidence_uri}#{locator}",),
        )
        return component_id, version_id, occurrence_id

    name, resolved, ref = remote_input_identity(url)
    if installed_version:
        resolved = (
            installed_version
            if looks_exact(installed_version)
            and "$" not in installed_version
            and "{" not in installed_version
            else None
        )
        ref = installed_version
    component_id = builder.add_component(
        kind="remote-build-artifact",
        ecosystem="generic",
        name=name,
        identity=f"remote-input:{url}",
        metadata={"download_uri": url},
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=resolved,
        source_ref=ref,
        constraint=None if resolved else (ref or "unversioned"),
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=url,
        root_id=root_component,
        dependency_scope=scope,
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship="downloads",
        source_occurrence_id=occurrence_id,
        constraint=resolved or ref,
        scope=scope,
        resolver=resolver,
    )
    artifact_path = urlparse(url).path.lower()
    if (
        not artifact_path.endswith((".txt", ".json", "/latest"))
        and "api.github.com" not in url
    ):
        builder.add_gap(
            "remote-download-integrity-unresolved",
            f"Remote input {url!r} has no checksum",
            component_id=component_id,
            component_version_id=version_id,
            source_id=source_id,
            evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
        )
    return component_id, version_id, occurrence_id


def add_git_clone_observation(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    repository: str,
    ref: str | None,
    locator: str,
    role: str,
    scope: str,
    resolver: str,
) -> tuple[str, str, str]:
    selected_ref = ref or "HEAD"
    name = repository.removesuffix(".git").rstrip("/").rsplit("/", 1)[-1]
    component_id = builder.add_component(
        kind="source-repository",
        ecosystem="git",
        name=name,
        identity=f"git:{repository}",
        metadata={"source_repo": repository},
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=selected_ref if looks_exact(selected_ref) else None,
        source_ref=selected_ref,
        constraint=None if looks_exact(selected_ref) else selected_ref,
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=f"{repository}@{selected_ref}",
        root_id=root_component,
        dependency_scope=scope,
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship="clones",
        source_occurrence_id=occurrence_id,
        constraint=selected_ref,
        scope=scope,
        resolver=resolver,
    )
    return component_id, version_id, occurrence_id


def add_docker_package(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    ecosystem: str,
    package: str,
    locator: str,
    role: str,
) -> None:
    raw = package.strip().strip("\"'")
    if not raw or raw.startswith(("$", ".", "/")):
        return
    name = raw
    version: str | None = None
    constraint: str | None = "unversioned"
    if ecosystem in {"apk", "deb", "rpm"} and "=" in raw:
        name, version = raw.split("=", 1)
        constraint = None if looks_exact(version) else f"={version}"
        if constraint:
            version = None
    elif ecosystem == "pypi":
        requirement = PYTHON_REQUIREMENT_RE.match(raw)
        if not requirement:
            return
        name, _extras, specifier, _marker = requirement.groups()
        exact = re.fullmatch(r"={2,3}\s*([^,;\s]+)", specifier or "")
        version = exact.group(1) if exact else None
        constraint = None if version else (specifier or "unversioned")
        # Canonical spelling matches the purl and the live SBOM emitter.
        name = name.lower().replace("_", "-")
    elif ecosystem == "npm":
        separator = raw.rfind("@")
        if separator <= 0 or (raw.startswith("@") and "/" not in raw[:separator]):
            name, version, constraint = raw, None, "unversioned"
        else:
            name, requested = raw[:separator], raw[separator + 1 :]
            if looks_exact(requested):
                version, constraint = requested, None
            else:
                version, constraint = None, requested
    name = name.strip()
    if not name or name.startswith("-"):
        return
    namespace, short_name = (
        name.rsplit("/", 1) if ecosystem == "npm" and "/" in name else ("", name)
    )
    component_id = builder.add_component(
        kind="library",
        ecosystem=ecosystem,
        namespace=namespace,
        name=short_name,
        purl=package_purl(ecosystem, name),
    )
    evidence_uri = builder.sources[source_id]["evidence_uri"]
    version_id = builder.add_version(
        component_id,
        resolved_version=version,
        constraint=constraint,
        resolution_state="resolved" if version else "unresolved",
        evidence=(f"{evidence_uri}#{locator}",),
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=raw,
        root_id=root_component,
        dependency_scope="build",
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship="installs",
        source_occurrence_id=occurrence_id,
        constraint=constraint or version,
        scope="build",
        resolver="dockerfile-run",
    )


def docker_shell_clauses(command: str) -> Iterator[str]:
    for clause in re.split(r"\s*(?:&&|\|\||;)\s*", command):
        if clause.strip():
            yield clause.strip()


def docker_install_tokens(clause: str) -> tuple[str, list[str]] | None:
    try:
        tokens = shlex.split(clause, comments=True, posix=True)
    except ValueError:
        return None
    while tokens and (tokens[0].startswith("--mount=") or "=" in tokens[0]):
        tokens.pop(0)
    patterns = (
        ({"apt", "apt-get"}, "install", "deb"),
        ({"apk"}, "add", "apk"),
        ({"dnf", "microdnf", "yum"}, "install", "rpm"),
    )
    for commands, verb, ecosystem in patterns:
        if not tokens or tokens[0] not in commands or verb not in tokens[1:]:
            continue
        start = tokens.index(verb) + 1
        packages = [
            token
            for token in tokens[start:]
            if not token.startswith("-") and token not in {"\\"}
        ]
        return ecosystem, packages
    return None


def docker_pip_tokens(clause: str) -> list[str] | None:
    try:
        tokens = shlex.split(clause, comments=True, posix=True)
    except ValueError:
        return None
    pip_index = -1
    if tokens and re.fullmatch(r"pip(?:3(?:\.\d+)?)?", tokens[0]):
        pip_index = 0
    elif (
        len(tokens) >= 3
        and tokens[0].startswith("python")
        and tokens[1:3] == ["-m", "pip"]
    ):
        pip_index = 2
    if pip_index < 0 or "install" not in tokens[pip_index + 1 :]:
        return None
    start = tokens.index("install", pip_index + 1) + 1
    result: list[str] = []
    skip_next = False
    options_with_value = {
        "-c",
        "--constraint",
        "-f",
        "--find-links",
        "-i",
        "--index-url",
        "--extra-index-url",
        "--trusted-host",
        "--target",
        "--prefix",
        "--root",
    }
    for token in tokens[start:]:
        if skip_next:
            skip_next = False
            continue
        if token in {"-r", "--requirement"}:
            skip_next = True
            continue
        if token in options_with_value:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        result.append(token)
    return result


def docker_npm_tokens(clause: str) -> list[str] | None:
    try:
        tokens = shlex.split(clause, comments=True, posix=True)
    except ValueError:
        return None
    if (
        not tokens
        or tokens[0] != "npm"
        or not any(verb in tokens[1:] for verb in {"install", "i", "add", "pack"})
    ):
        return None
    start = next(
        index + 1
        for index, token in enumerate(tokens)
        if token in {"install", "i", "add", "pack"}
    )
    result: list[str] = []
    skip_next = False
    options_with_value = {
        "--cache",
        "--pack-destination",
        "--prefix",
        "--registry",
        "--workspace",
    }
    for token in tokens[start:]:
        if skip_next:
            skip_next = False
            continue
        if token in options_with_value:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        result.append(token)
    return result


def docker_input_digest(root: Path, path: Path) -> str | None:
    try:
        path.relative_to(root)
        metadata = os.lstat(path)
    except (OSError, ValueError):
        return None
    if stat.S_ISLNK(metadata.st_mode):
        return None
    if stat.S_ISREG(metadata.st_mode):
        if not git_path_is_tracked(root, path):
            return None
        try:
            return file_hash(
                read_regular_file(
                    path,
                    max_bytes=MAX_DISCOVERY_FILE_BYTES,
                    label=f"tracked build input {path}",
                )
            )
        except RegistryInputError:
            return None
    if stat.S_ISDIR(metadata.st_mode):
        entries: list[tuple[str, str]] = []
        total_bytes = 0
        for directory, directories, files in os.walk(path, followlinks=False):
            directories[:] = sorted(directories)
            for name in sorted(files):
                child = Path(directory) / name
                try:
                    child_metadata = os.lstat(child)
                except OSError:
                    return None
                if not stat.S_ISREG(child_metadata.st_mode) or not git_path_is_tracked(
                    root, child
                ):
                    return None
                if len(entries) >= MAX_DISCOVERY_FILES:
                    return None
                try:
                    data = read_regular_file(
                        child,
                        max_bytes=MAX_DISCOVERY_FILE_BYTES,
                        label=f"tracked build input {child}",
                    )
                except RegistryInputError:
                    return None
                total_bytes += len(data)
                if total_bytes > MAX_DISCOVERY_TOTAL_BYTES:
                    return None
                entries.append((child.relative_to(path).as_posix(), file_hash(data)))
        return file_hash(canonical_json(entries).encode("utf-8"))
    return None


def docker_input_is_tracked(root: Path, path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISREG(metadata.st_mode):
        return git_path_is_tracked(root, path)
    if stat.S_ISDIR(metadata.st_mode):
        children: list[Path] = []
        for directory, directories, files in os.walk(path, followlinks=False):
            directories[:] = sorted(directories)
            for name in sorted(files):
                child = Path(directory) / name
                try:
                    if not stat.S_ISREG(os.lstat(child).st_mode):
                        return False
                except OSError:
                    return False
                children.append(child)
                if len(children) > MAX_DISCOVERY_FILES:
                    return False
        return bool(children) and all(
            git_path_is_tracked(root, child) for child in children
        )
    return False


def docker_local_copy_sources(text: str) -> list[str]:
    """Collect local COPY/ADD sources with the same ARG expansion as the scan."""

    arguments: dict[str, str] = {}
    sources: list[str] = []
    for _line_number, instruction, value in dockerfile_instructions(text):
        if instruction == "ARG":
            declaration = value.split()[0]
            name, separator, default = declaration.partition("=")
            if separator:
                expanded_default, _ = expand_docker_args(default, arguments)
                arguments[name] = expanded_default
            else:
                arguments.setdefault(name, "")
            continue
        if instruction not in {"COPY", "ADD"}:
            continue
        expanded, _ = expand_docker_args(value, arguments)
        if re.search(r"(?:^|\s)--from(?:=|\s)", expanded):
            continue
        if instruction == "ADD" and re.search(r"https?://\S+", expanded):
            continue
        try:
            tokens = (
                json.loads(expanded)
                if expanded.lstrip().startswith("[")
                else shlex.split(expanded, comments=True, posix=True)
            )
        except (ValueError, json.JSONDecodeError):
            continue
        materialized = [str(token) for token in tokens]
        sources.extend(
            token for token in materialized[:-1] if not token.startswith("--")
        )
    return sources


def docker_source_resolves(base: Path, raw_input: str) -> bool:
    if raw_input in {"", "."}:
        return True
    if raw_input.startswith("/"):
        return False
    if any(character in raw_input for character in "*?["):
        try:
            return next(iter(base.glob(raw_input)), None) is not None
        except (OSError, ValueError):
            return False
    return os.path.lexists(os.path.normpath((base / raw_input).as_posix()))


def docker_build_context(root: Path, dockerfile: Path, text: str) -> tuple[Path, str]:
    """Dockerfile directory unless only an ancestor resolves every COPY source."""

    read_root = committed_view_read_root(root)
    declared = read_root / dockerfile.parent.relative_to(root)
    sources = [
        item for item in docker_local_copy_sources(text) if item not in {"", "."}
    ]
    if not sources:
        return declared, "declared-directory"
    for candidate in (declared, *declared.parents):
        try:
            candidate.relative_to(read_root)
        except ValueError:
            break
        if all(docker_source_resolves(candidate, item) for item in sources):
            resolution = (
                "declared-directory" if candidate == declared else "ancestor-inferred"
            )
            return candidate, resolution
    return declared, "unknown"


def docker_copy_mapping(
    dockerfile: Path, root: Path, value: str, context_relative: str = "."
) -> dict[str, Path]:
    if re.search(r"(?:^|\s)--from(?:=|\s)", value):
        return {}
    try:
        tokens = (
            json.loads(value)
            if value.lstrip().startswith("[")
            else shlex.split(value, comments=True, posix=True)
        )
    except (ValueError, json.JSONDecodeError):
        return {}
    materialized = [str(token) for token in tokens]
    values = [token for token in materialized if not token.startswith("--")]
    if len(values) < 2:
        return {}
    destination = values[-1]
    sources = values[:-1]
    result: dict[str, Path] = {}
    for raw_input in sources:
        contextual = Path(
            os.path.normpath((root / context_relative / raw_input).as_posix())
        )
        candidate = dockerfile.parent / raw_input
        if contextual.exists() or git_path_is_tracked(root, contextual):
            input_path = contextual
        else:
            input_path = candidate if candidate.exists() else root / raw_input
        target = (
            f"{destination.rstrip('/')}/{Path(raw_input).name}"
            if destination.endswith("/") or len(sources) > 1
            else destination
        )
        result[target] = input_path
        result[Path(target).name] = input_path
    return result


def scan_docker_requirements_file(
    builder: Builder,
    root: Path,
    dockerfile_source_id: str,
    root_component: str,
    root_version: str,
    requirement_path: Path,
    *,
    run_line: int,
) -> None:
    if not git_path_is_tracked(root, requirement_path):
        return
    try:
        data, text = read_text(root, requirement_path)
    except RegistryInputError:
        return
    try:
        relative = requirement_path.relative_to(root).as_posix()
    except ValueError:
        relative = requirement_path.as_posix()
    tracked = True
    requirement_source_id = source_for(
        builder, root, requirement_path, data, "python-requirements"
    )
    dockerfile_relative = builder.sources[dockerfile_source_id]["evidence_uri"]
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.split(" #", 1)[0].strip()
        if not stripped or stripped.startswith("#"):
            continue
        add_package_observation(
            builder,
            requirement_source_id,
            root_component,
            root_version,
            ecosystem="pypi",
            package=stripped,
            locator=f"line:{line_number}",
            role="docker-requirement",
            scope="build",
            resolver="dockerfile-requirements",
            metadata={
                "dockerfile": dockerfile_relative,
                "run_line": run_line,
                "tracked": tracked,
            },
        )


def scan_docker_copy(
    builder: Builder,
    root: Path,
    dockerfile: Path,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    line_number: int,
    value: str,
    context: Path | None = None,
    context_state: str = "declared-directory",
) -> None:
    if re.search(r"(?:^|\s)--from(?:=|\s)", value):
        return
    try:
        if value.lstrip().startswith("["):
            tokens = json.loads(value)
        else:
            tokens = shlex.split(value, comments=True, posix=True)
    except (ValueError, json.JSONDecodeError):
        tokens = []
    tokens = [str(token) for token in tokens]
    sources = [token for token in tokens[:-1] if not token.startswith("--")]
    relative = builder.sources[source_id]["evidence_uri"]
    read_root = committed_view_read_root(root)
    if context is None:
        context = read_root / dockerfile.parent.relative_to(root)
    for index, raw_input in enumerate(sources):
        candidates: list[Path] = []
        if any(character in raw_input for character in "*?["):
            try:
                candidates.extend(sorted(context.glob(raw_input)))
            except (OSError, ValueError):
                pass
        else:
            local = Path(os.path.normpath((context / raw_input).as_posix()))
            candidates.append(
                local if os.path.lexists(local) else read_root / raw_input
            )
        for input_path in candidates or [context / raw_input]:
            digest = docker_input_digest(read_root, input_path)
            locator = f"line:{line_number}:copy:{index}"
            if not digest:
                builder.add_gap(
                    "docker-copy-input-unresolved",
                    f"Docker COPY input {raw_input!r} cannot be hashed",
                    source_id=source_id,
                    evidence=(f"{relative}#L{line_number}",),
                    metadata={"build_context_resolution": context_state},
                )
                continue
            tracked = docker_input_is_tracked(read_root, input_path)
            try:
                input_relative = input_path.relative_to(read_root).as_posix()
            except ValueError:
                input_relative = input_path.as_posix()
            copied_source_id = builder.add_source(
                input_relative,
                "docker-copy-input",
                content_hash=digest,
                metadata={
                    "evidence_class": evidence_class_for_path(input_relative),
                    "tracked": tracked,
                },
            )
            component_id = builder.add_component(
                kind="build-input",
                ecosystem="local",
                name=input_relative,
                identity=f"docker-build-input:{input_relative}",
                official_channel_required=False,
            )
            version_id = builder.add_version(
                component_id,
                artifact_digest=digest,
                resolution_state="resolved",
                evidence=(f"{relative}#L{line_number}", input_relative),
            )
            occurrence_id = builder.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=locator,
                role="docker-copy-input",
                raw_value=raw_input,
                root_id=root_component,
                dependency_scope="build",
                metadata={
                    "copied_source_id": copied_source_id,
                    "tracked": tracked,
                },
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="copies-input",
                source_occurrence_id=occurrence_id,
                scope="build",
                resolver="dockerfile-copy",
            )
            if not tracked:
                builder.add_gap(
                    "docker-copy-input-untracked",
                    f"Docker COPY input {input_relative!r} is not reproducible from Git",
                    component_id=component_id,
                    component_version_id=version_id,
                    source_id=source_id,
                    evidence=(f"{relative}#L{line_number}", input_relative),
                )


def scan_dockerfile(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "dockerfile")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "container-build"
    )
    arguments: dict[str, str] = {}
    copied_inputs: dict[str, Path] = {}
    read_root = committed_view_read_root(root)
    copy_context, copy_context_state = docker_build_context(root, path, text)
    context_relative = copy_context.relative_to(read_root).as_posix()
    syntax = re.search(r"(?mi)^\s*#\s*syntax\s*=\s*(\S+)\s*$", text)
    if syntax:
        _, version_id, occurrence_id = builder.add_image(
            syntax.group(1),
            source_id,
            f"line:{text[:syntax.start()].count(chr(10)) + 1}",
            "dockerfile-frontend",
            root_id=root_component,
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="builds-with",
            source_occurrence_id=occurrence_id,
            scope="build",
            resolver="dockerfile-syntax",
        )
    for line_number, instruction, value in dockerfile_instructions(text):
        locator = f"line:{line_number}"
        if instruction == "ARG":
            declaration = value.split()[0]
            name, separator, default = declaration.partition("=")
            if separator:
                expanded, _ = expand_docker_args(default, arguments)
                arguments[name] = expanded
            else:
                arguments.setdefault(name, "")
            continue
        expanded, unresolved = expand_docker_args(value, arguments)
        if instruction == "FROM":
            try:
                tokens = shlex.split(expanded, comments=True, posix=True)
            except ValueError:
                tokens = []
            platform = next(
                (
                    token.split("=", 1)[1]
                    for token in tokens
                    if token.startswith("--platform=")
                ),
                None,
            )
            image_tokens = [token for token in tokens if not token.startswith("--")]
            image = image_tokens[0] if image_tokens else expanded
            stage = (
                image_tokens[2]
                if len(image_tokens) >= 3 and image_tokens[1].lower() == "as"
                else None
            )
            if "$" in image:
                builder.add_gap(
                    "docker-base-unresolved",
                    f"Docker base image expression {value!r} is unresolved",
                    source_id=source_id,
                    evidence=(f"{relative}#L{line_number}",),
                    metadata={
                        "unresolved_arguments": sorted(
                            name for name in unresolved if name in image
                        )
                    },
                )
                continue
            raw_platform = platform
            if platform and "$" in platform:
                platform = None
            _, version_id, occurrence_id = builder.add_image(
                image,
                source_id,
                locator,
                "docker-base-image",
                platform=platform,
                root_id=root_component,
                metadata={
                    key: item
                    for key, item in (
                        ("platform", raw_platform),
                        ("stage", stage),
                        ("raw_expression", value),
                    )
                    if item
                },
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="builds-from",
                source_occurrence_id=occurrence_id,
                scope="build",
                resolver="dockerfile",
            )
        elif instruction == "RUN":
            checkout_match = re.search(
                r"(?:^|[;&|]\s*)git\s+checkout\s+['\"]?([^\s'\";&|]+)",
                expanded,
            )
            checkout_ref = checkout_match.group(1) if checkout_match else None
            for clause_index, clause in enumerate(docker_shell_clauses(expanded)):
                clause_locator = f"line:{line_number}:run:{clause_index}"
                system_install = docker_install_tokens(clause)
                if system_install:
                    ecosystem, packages = system_install
                    for package in packages:
                        add_docker_package(
                            builder,
                            source_id,
                            root_component,
                            root_version,
                            ecosystem=ecosystem,
                            package=package,
                            locator=clause_locator,
                            role=f"docker-{ecosystem}-package",
                        )
                pip_install = shell_pip_install(clause)
                if pip_install:
                    packages, requirement_refs = pip_install
                    for package in packages:
                        add_docker_package(
                            builder,
                            source_id,
                            root_component,
                            root_version,
                            ecosystem="pypi",
                            package=package,
                            locator=clause_locator,
                            role="docker-pip-package",
                        )
                    for requirement_ref in requirement_refs:
                        requirement_path = copied_inputs.get(
                            requirement_ref
                        ) or copied_inputs.get(Path(requirement_ref).name)
                        if requirement_path:
                            scan_docker_requirements_file(
                                builder,
                                root,
                                source_id,
                                root_component,
                                root_version,
                                requirement_path,
                                run_line=line_number,
                            )
                for package in docker_npm_tokens(clause) or []:
                    add_docker_package(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        ecosystem="npm",
                        package=package,
                        locator=clause_locator,
                        role="docker-npm-package",
                    )
                clone = parse_git_clone(clause)
                if clone:
                    repository, clone_ref = clone
                    add_git_clone_observation(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        repository=repository,
                        ref=clone_ref or checkout_ref,
                        locator=clause_locator,
                        role="docker-git-clone",
                        scope="build",
                        resolver="dockerfile-run",
                    )
        elif instruction in {"COPY", "ADD"}:
            checksum_match = re.search(
                r"(?:^|\s)--checksum=(sha256:[0-9a-fA-F]{64})(?:\s|$)", expanded
            )
            url_match = re.search(r"https?://\S+", expanded)
            if instruction == "ADD" and url_match:
                url = url_match.group(0).strip("\"'")
                digest = checksum_match.group(1).lower() if checksum_match else None
                release = re.search(r"/releases/download/([^/]+)/", url)
                name = Path(urlparse(url).path).name
                component_id = builder.add_component(
                    kind="remote-build-artifact",
                    ecosystem="generic",
                    name=name,
                    identity=f"remote-artifact:{url}",
                    metadata={"download_uri": url},
                )
                version_id = builder.add_version(
                    component_id,
                    resolved_version=release.group(1) if release else None,
                    artifact_digest=digest,
                    constraint=None if digest else "checksum-unresolved",
                    evidence=(f"{relative}#L{line_number}",),
                )
                occurrence_id = builder.add_occurrence(
                    component_id,
                    version_id,
                    source_id,
                    locator=locator,
                    role="docker-remote-add",
                    raw_value=url,
                    root_id=root_component,
                    dependency_scope="build",
                )
                builder.add_edge(
                    root_version,
                    version_id,
                    relationship="downloads",
                    source_occurrence_id=occurrence_id,
                    scope="build",
                    resolver="dockerfile-add",
                )
                if not digest:
                    builder.add_gap(
                        "docker-remote-add-checksum-unresolved",
                        f"Remote ADD {url!r} has no checksum",
                        component_id=component_id,
                        component_version_id=version_id,
                        source_id=source_id,
                        evidence=(f"{relative}#L{line_number}",),
                    )
            else:
                scan_docker_copy(
                    builder,
                    root,
                    path,
                    source_id,
                    root_component,
                    root_version,
                    line_number=line_number,
                    value=expanded,
                    context=copy_context,
                    context_state=copy_context_state,
                )
                if instruction == "COPY":
                    copied_inputs.update(
                        docker_copy_mapping(path, root, expanded, context_relative)
                    )


def yaml_scalar_paths(text: str) -> Iterator[tuple[int, tuple[str, ...], str, str]]:
    """Yield simple YAML scalar paths without accepting them as rendered truth."""

    stack: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(
            r"^(\s*)(?:-\s*)?([A-Za-z_][\w.-]*)\s*:\s*(.*?)\s*(?:#.*)?$",
            line,
        )
        if not match:
            list_match = re.match(r"^(\s*)-\s+([^#].*?)\s*(?:#.*)?$", line)
            if list_match:
                indent = len(list_match.group(1).replace("\t", "  "))
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                value = scalar(list_match.group(2))
                if value:
                    yield line_number, tuple(item[1] for item in stack), "[]", value
            continue
        indent = len(match.group(1).replace("\t", "  "))
        key = match.group(2)
        value = scalar(match.group(3))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = tuple(item[1] for item in stack)
        if value:
            yield line_number, path, key, value
        else:
            stack.append((indent, key))


def add_model_artifact_observation(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    ecosystem: str,
    identity: str,
    name: str,
    locator: str,
    raw_value: str,
    role: str,
    revision: str | None = None,
    artifact_digest: str | None = None,
    lifecycle: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    root_relationship: str = "uses-model-artifact",
    lineage_required: bool = False,
) -> tuple[str, str, str]:
    evidence_uri = builder.sources[source_id]["evidence_uri"]
    component_metadata = dict(metadata or {})
    # Persist the declared reference the component_id was hashed from. Without
    # it recover_component_identity cannot rebuild these ids at all, because the
    # component keeps only the short display name, so derive-channels skipped
    # every model-artifact as identity-unrecoverable and no channel policy could
    # reach one. Recorded, not derived - this is the exact input string.
    component_metadata["artifact_identity"] = identity
    if lineage_required:
        component_metadata["lineage_required"] = True
        component_metadata["lineage_evidence"] = [f"{evidence_uri}#{locator}"]
    component_id = builder.add_component(
        kind="model-artifact",
        ecosystem=ecosystem,
        name=name,
        identity=f"model-artifact:{ecosystem}:{identity}",
        lifecycles=(lifecycle or builder.lifecycle_for_source(source_id),),
        metadata=component_metadata,
    )
    immutable_revision = bool(
        revision
        and (
            re.fullmatch(r"[0-9a-fA-F]{40,64}", revision)
            or (looks_exact(revision) and revision.lower() not in MUTABLE_REFS)
        )
    )
    resolution_state = (
        "resolved" if artifact_digest or immutable_revision else "unresolved"
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=revision if immutable_revision else None,
        source_ref=revision,
        artifact_digest=artifact_digest,
        constraint=(
            None
            if resolution_state == "resolved"
            else "immutable-revision-or-hash-required"
        ),
        resolution_state=resolution_state,
        evidence=(f"{evidence_uri}#{locator}",),
        metadata=component_metadata,
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=raw_value,
        root_id=root_component,
        dependency_scope="runtime",
        lifecycle=lifecycle,
        metadata=component_metadata,
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship=root_relationship,
        source_occurrence_id=occurrence_id,
        scope="runtime",
        resolver="model-artifact-discovery",
    )
    if not artifact_digest:
        builder.add_gap(
            "model-artifact-integrity-unresolved",
            f"Model artifact {identity!r} has no immutable content hash",
            component_id=component_id,
            component_version_id=version_id,
            source_id=source_id,
            evidence=(f"{evidence_uri}#{locator}",),
        )
    if ecosystem == "huggingface" and not immutable_revision:
        builder.add_gap(
            "model-artifact-revision-unresolved",
            f"Hugging Face model {identity!r} has no immutable revision",
            component_id=component_id,
            component_version_id=version_id,
            source_id=source_id,
            evidence=(f"{evidence_uri}#{locator}",),
        )
    return component_id, version_id, occurrence_id


def model_values_context(
    root: Path, path: Path, text: str
) -> tuple[dict[str, tuple[int, str]], str | None]:
    """Return scalar Helm values by dotted path and their evidence file."""

    values_path: Path | None = None
    values_text = ""
    if path.name.lower() in {"values.yaml", "values.yml"}:
        values_path = path
        values_text = text
    else:
        for parent in path.parents:
            if parent == root.parent:
                break
            for name in ("values.yaml", "values.yml"):
                candidate = parent / name
                try:
                    metadata = os.lstat(candidate)
                except OSError:
                    continue
                if stat.S_ISREG(metadata.st_mode) and git_path_is_tracked(
                    root, candidate
                ):
                    values_path = candidate
                    try:
                        values_text = read_regular_file(
                            candidate,
                            max_bytes=MAX_DISCOVERY_FILE_BYTES,
                            label=f"tracked Helm values {candidate}",
                        ).decode("utf-8", errors="replace")
                    except RegistryInputError:
                        values_path = None
                    break
            if values_path is not None:
                break
    if values_path is None:
        return {}, None
    values = {
        ".".join((*parents, key)): (line, value)
        for line, parents, key, value in yaml_scalar_paths(values_text)
    }
    try:
        evidence = values_path.relative_to(root).as_posix()
    except ValueError:
        evidence = values_path.as_posix()
    return values, evidence


def resolve_model_value(value: str, values: Mapping[str, tuple[int, str]]) -> str:
    """Resolve simple scalar .Values references without rendering a Helm chart."""

    result = scalar(value)
    pattern = re.compile(r"\{\{\s*\.Values\.([A-Za-z0-9_.-]+)\s*\}\}")
    for _ in range(4):
        updated = pattern.sub(
            lambda match: str(values.get(match.group(1), (0, match.group(0)))[1]),
            result,
        )
        if updated == result:
            break
        result = updated
    return result


def canonical_model_s3_uri(value: str) -> str | None:
    candidate = scalar(value).rstrip("/,")
    if not candidate.startswith("s3://") or TEMPLATE_EXPRESSION_RE.search(candidate):
        return None
    if "$" in candidate or "<" in candidate:
        return None
    return candidate


def yaml_env_bindings(text: str, line_offset: int = 0) -> dict[str, tuple[int, str]]:
    bindings: dict[str, tuple[int, str]] = {}
    current_name: str | None = None
    for index, line in enumerate(text.splitlines(), 1):
        name_match = re.match(r"^\s*-\s+name:\s*([^#]+?)\s*(?:#.*)?$", line)
        if name_match:
            current_name = scalar(name_match.group(1))
            continue
        value_match = re.match(r"^\s+value:\s*([^#]+?)\s*(?:#.*)?$", line)
        if current_name and value_match:
            bindings[current_name] = (line_offset + index, scalar(value_match.group(1)))
            current_name = None
    return bindings


def scan_model_artifacts(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    """Discover model files/repositories/stores without treating them as images."""

    observation_key = tuple[str, str, str, str]
    observations: dict[observation_key, dict[str, Any]] = {}
    lineages: list[tuple[observation_key, observation_key, str]] = []

    def observe(
        ecosystem: str,
        identity: str,
        name: str,
        locator: str,
        raw_value: str,
        role: str,
        *,
        revision: str | None = None,
        digest: str | None = None,
        lifecycle: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        root_relationship: str = "uses-model-artifact",
        lineage_required: bool = False,
    ) -> observation_key | None:
        value = identity.strip().rstrip("/,")
        if not value:
            return None
        key = (ecosystem, value, locator, role)
        observations[key] = {
            "ecosystem": ecosystem,
            "identity": value,
            "name": name,
            "locator": locator,
            "raw_value": raw_value,
            "role": role,
            "revision": revision,
            "artifact_digest": digest,
            "lifecycle": lifecycle,
            "metadata": dict(metadata or {}),
            "root_relationship": root_relationship,
            "lineage_required": lineage_required,
        }
        return key

    def link(
        source: observation_key | None,
        target: observation_key | None,
        relationship: str,
    ) -> None:
        if source is not None and target is not None:
            lineages.append((source, target, relationship))

    relative = path.relative_to(root).as_posix()
    yaml_values = (
        list(yaml_scalar_paths(text))
        if path.suffix.lower() in {".yaml", ".yml"}
        else []
    )
    helm_values, values_evidence = model_values_context(root, path, text)

    frontier_values = {
        match.group(1): (text[: match.start()].count("\n") + 1, scalar(match.group(2)))
        for match in re.finditer(
            r"(?m)^(FRONTIER_HF_REPO|FRONTIER_MODEL_FILE)\s*=\s*([^#\r\n]+)",
            text,
        )
    }
    if {"FRONTIER_HF_REPO", "FRONTIER_MODEL_FILE"}.issubset(frontier_values):
        repo_line, repo = frontier_values["FRONTIER_HF_REPO"]
        file_line, filename = frontier_values["FRONTIER_MODEL_FILE"]
        source_key = observe(
            "huggingface",
            repo,
            repo.rsplit("/", 1)[-1],
            f"line:{repo_line}",
            repo,
            "model-source",
            metadata={"repository": repo, "snapshot_revision": None},
        )
        file_key = observe(
            "huggingface",
            f"{repo}/{filename}",
            filename,
            f"line:{file_line}",
            filename,
            "huggingface-model-file",
            revision="main",
            metadata={
                "repository": repo,
                "filename": filename,
                "snapshot_revision": "main",
            },
        )
        link(source_key, file_key, "publishes")

    for match in re.finditer(
        r"https://huggingface\.co/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:resolve|blob)/([^/\s\"']+)/([^\s\"'?]+)",
        text,
    ):
        line = text[: match.start()].count("\n") + 1
        repo, revision, filename = match.groups()
        source_key = observe(
            "huggingface",
            repo,
            repo.rsplit("/", 1)[-1],
            f"line:{line}",
            repo,
            "model-source",
            revision=revision,
            metadata={"repository": repo, "snapshot_revision": revision},
        )
        file_key = observe(
            "huggingface",
            f"{repo}/{filename}",
            filename,
            f"line:{line}",
            match.group(0),
            "huggingface-model-file",
            revision=revision,
            metadata={
                "repository": repo,
                "filename": filename,
                "snapshot_revision": revision,
            },
        )
        link(source_key, file_key, "publishes")
    for match in re.finditer(
        r"https?://[^/\s\"']+/[^\s\"']+\.(?:gguf|onnx|safetensors|pt|pth)(?:\?[^\s\"']*)?",
        text,
        re.IGNORECASE,
    ):
        if "huggingface.co/" in match.group(0):
            continue
        line = text[: match.start()].count("\n") + 1
        url = match.group(0)
        observe(
            "model-download",
            url,
            Path(urlparse(url).path).name,
            f"line:{line}",
            url,
            "remote-model-file",
        )

    concrete_bucket = ""
    for key in (
        "detectors.s3.bucket",
        "convert.s3.bucket",
        "s3.bucket",
    ):
        candidate = helm_values.get(key, (0, ""))[1]
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", candidate):
            concrete_bucket = candidate
            break

    paired_model_values: dict[tuple[str, ...], dict[str, tuple[int, str]]] = {}
    for line, parents, key, value in yaml_values:
        lower_parents = tuple(item.lower() for item in parents)
        lower_key = key.lower()
        if "models" in lower_parents and lower_key in {
            "source",
            "image",
            "revision",
            "commit",
        }:
            paired_model_values.setdefault(lower_parents, {})[lower_key] = (line, value)
    handled_yaml_lines: set[int] = set()
    for parents, fields in sorted(paired_model_values.items()):
        source_item = fields.get("source")
        image_item = fields.get("image")
        revision_item = fields.get("revision") or fields.get("commit")
        source_key: observation_key | None = None
        output_key: observation_key | None = None
        if source_item and re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source_item[1]
        ):
            line, repo = source_item
            handled_yaml_lines.add(line)
            source_key = observe(
                "huggingface",
                repo,
                repo.rsplit("/", 1)[-1],
                f"line:{line}",
                repo,
                "model-source",
                revision=revision_item[1] if revision_item else None,
                metadata={
                    "repository": repo,
                    "model_values_path": ".".join(parents),
                    "snapshot_revision": revision_item[1] if revision_item else None,
                },
            )
        if (
            image_item
            and concrete_bucket
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", image_item[1])
        ):
            line, image = image_item
            handled_yaml_lines.add(line)
            uri = f"s3://{concrete_bucket}/{image.strip('/')}"
            output_key = observe(
                "s3-model",
                uri,
                image.rstrip("/").rsplit("/", 1)[-1],
                f"line:{line}",
                uri,
                "published-model-artifact",
                metadata={"model_values_path": ".".join(parents)},
                lineage_required=True,
            )
        link(source_key, output_key, "publishes")

    if "qwen-modelcars" in relative:
        documents: list[tuple[int, str]] = []
        document_lines: list[str] = []
        document_start = 1
        for line_number, document_line in enumerate(text.splitlines(), 1):
            if document_line.strip() == "---":
                if document_lines:
                    documents.append((document_start, "\n".join(document_lines)))
                document_lines = []
                document_start = line_number + 1
            else:
                document_lines.append(document_line)
        if document_lines:
            documents.append((document_start, "\n".join(document_lines)))
        for document_start, document in documents:
            bindings = yaml_env_bindings(document, document_start - 1)
            repo_item = bindings.get("MODEL_REPO")
            image_item = bindings.get("MODEL_IMAGE")
            tag_item = bindings.get("MODEL_TAG")
            target_match = re.search(
                r"(?:^|\s)-t\s+([A-Za-z0-9._:-]+/[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+)",
                document,
            )
            if repo_item and image_item and tag_item and target_match:
                repo_line, repo = repo_item
                image_line, image = image_item
                _tag_line, tag = tag_item
                source_key = observe(
                    "huggingface",
                    repo,
                    repo.rsplit("/", 1)[-1],
                    f"line:{repo_line}",
                    repo,
                    "modelcar-source",
                    metadata={
                        "repository": repo,
                        "snapshot_download": True,
                        "snapshot_revision": None,
                    },
                )
                target = f"oci://{target_match.group(1)}"
                output_key = observe(
                    "oci-modelcar",
                    target,
                    image,
                    f"line:{image_line}",
                    target,
                    "published-modelcar",
                    revision=tag,
                    metadata={"model_tag": tag, "source_repository": repo},
                    lineage_required=True,
                )
                link(source_key, output_key, "publishes")

    for line, parents, key, value in yaml_values:
        lower_parents = {item.lower() for item in parents}
        lower_key = key.lower()
        if (
            line not in handled_yaml_lines
            and lower_parents.intersection(
                {"models", "model", "modelartifacts", "artifacts"}
            )
            and lower_key in {"source", "repo", "repo_id", "repository", "[]"}
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value)
            and not value.startswith(("openai/", "archeion/"))
        ):
            observe(
                "huggingface",
                value,
                value.rsplit("/", 1)[-1],
                f"line:{line}",
                value,
                "huggingface-model-repository",
            )
        if lower_key == "s3prefix" and "models" in lower_parents and concrete_bucket:
            if not TEMPLATE_EXPRESSION_RE.search(value) and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._/-]*", value
            ):
                uri = f"s3://{concrete_bucket}/{value.strip('/')}"
                observe(
                    "s3-model",
                    uri,
                    value.rstrip("/").rsplit("/", 1)[-1],
                    f"line:{line}",
                    uri,
                    "served-model-artifact",
                    root_relationship="serves",
                    lineage_required=True,
                )
        if lower_key == "storageuri" and "model" in lower_parents:
            resolved = resolve_model_value(value, helm_values)
            uri = canonical_model_s3_uri(resolved)
            if uri:
                observe(
                    "s3-model",
                    uri,
                    uri.rsplit("/", 1)[-1],
                    f"line:{line}",
                    resolved,
                    "served-model-artifact",
                    lifecycle=("conditional" if "{{- if" in text[:400] else None),
                    metadata={
                        "storage_uri": resolved,
                        "values_evidence": values_evidence,
                    },
                    root_relationship="serves",
                    lineage_required=True,
                )
        if lower_key in {"asr_model", "whisper_model"} and value:
            observe(
                "logical-model",
                f"whisper:{value}",
                value,
                f"line:{line}",
                value,
                "library-resolved-model",
                metadata={"resolver": "runtime-library-cache"},
            )
    for match in re.finditer(
        r"(?:FRONTIER_HF_REPO|HF_MODEL_REPO|MODEL_REPO)\s*=\s*[\"']?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)",
        text,
    ):
        line = text[: match.start()].count("\n") + 1
        repo = match.group(1)
        if repo == frontier_values.get("FRONTIER_HF_REPO", (0, ""))[1]:
            continue
        observe(
            "huggingface",
            repo,
            repo.rsplit("/", 1)[-1],
            f"line:{line}",
            repo,
            "huggingface-model-repository",
        )
    if not observations:
        return
    source_id = source_for(builder, root, path, data, "model-artifact-config")
    root_component, root_version = add_local_root(
        builder, source_id, relative, "model-artifact-config"
    )
    materialized: dict[observation_key, tuple[str, str, str]] = {}
    for key, observation in sorted(
        observations.items(), key=lambda item: canonical_json(item[1])
    ):
        materialized[key] = add_model_artifact_observation(
            builder,
            source_id,
            root_component,
            root_version,
            **observation,
        )
    for source_key, target_key, relationship in sorted(
        set(lineages), key=canonical_json
    ):
        source = materialized.get(source_key)
        target = materialized.get(target_key)
        if source is None or target is None:
            continue
        builder.add_edge(
            source[1],
            target[1],
            relationship=relationship,
            source_occurrence_id=target[2],
            scope="build",
            resolver="model-artifact-lineage",
        )


def toolchain_version(language: str, raw_value: str) -> tuple[str | None, str | None]:
    value = raw_value.strip()
    if language == "go":
        value = value.removeprefix("go")
    elif language == "node":
        value = value.removeprefix("node-").removeprefix("v")
    elif language == "python":
        value = value.removeprefix("python-")
    exact_match = re.fullmatch(
        r"={0,2}\s*(\d+\.\d+\.\d+(?:[-+._][A-Za-z0-9.-]+)?)", value
    )
    if exact_match:
        return exact_match.group(1), None
    return None, value or raw_value.strip()


def add_toolchain_observation(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    language: str,
    raw_version: str,
    locator: str,
    role: str,
) -> tuple[str, str]:
    resolved_version, constraint = toolchain_version(language, raw_version)
    ecosystem = f"{language}-toolchain"
    source_uri = builder.sources[source_id]["evidence_uri"]
    toolchain_component = builder.add_component(
        kind="language-toolchain",
        ecosystem=ecosystem,
        name=language,
        purl=package_purl("generic", f"{language}-toolchain"),
        identity=f"toolchain:{language}",
        metadata={"language": language},
    )
    toolchain_version_id = builder.add_version(
        toolchain_component,
        resolved_version=resolved_version,
        constraint=constraint,
        resolution_state="resolved" if resolved_version else "partial",
        evidence=(f"{source_uri}#{locator}",),
        metadata={"raw_toolchain_version": raw_version},
    )
    toolchain_occurrence = builder.add_occurrence(
        toolchain_component,
        toolchain_version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=raw_version,
        root_id=root_component,
        dependency_scope="build",
    )
    builder.add_edge(
        root_version,
        toolchain_version_id,
        relationship="requires-toolchain",
        source_occurrence_id=toolchain_occurrence,
        constraint=constraint or resolved_version,
        scope="build",
        resolver="toolchain-observation",
    )
    stdlib_component = builder.add_component(
        kind="standard-library",
        ecosystem=ecosystem,
        name=f"{language}-stdlib",
        purl=package_purl("generic", f"{language}-stdlib"),
        identity=f"stdlib:{language}",
        metadata={"language": language, "coupled_to_toolchain": True},
    )
    stdlib_version_id = builder.add_version(
        stdlib_component,
        resolved_version=resolved_version,
        constraint=constraint,
        resolution_state="resolved" if resolved_version else "partial",
        evidence=(f"{source_uri}#{locator}",),
        metadata={"raw_toolchain_version": raw_version},
    )
    stdlib_occurrence = builder.add_occurrence(
        stdlib_component,
        stdlib_version_id,
        source_id,
        locator=f"{locator}:stdlib",
        role=f"{language}-standard-library",
        raw_value=raw_version,
        root_id=toolchain_component,
        dependency_scope="runtime",
    )
    builder.add_edge(
        toolchain_version_id,
        stdlib_version_id,
        relationship="provides-standard-library",
        source_occurrence_id=stdlib_occurrence,
        constraint=constraint or resolved_version,
        scope="runtime",
        resolver="toolchain-observation",
    )
    if not resolved_version:
        for component_id, version_id, surface in (
            (toolchain_component, toolchain_version_id, "toolchain"),
            (stdlib_component, stdlib_version_id, "standard library"),
        ):
            builder.add_gap(
                "toolchain-exact-version-unresolved",
                f"{language} {surface} constraint {constraint!r} lacks an exact runtime version",
                component_id=component_id,
                component_version_id=version_id,
                source_id=source_id,
                evidence=(f"{source_uri}#{locator}",),
                metadata={"language": language, "surface": surface},
            )
    return toolchain_component, stdlib_component


def scan_toolchain_version_file(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    lower_name = path.name.lower()
    language = "python" if lower_name in {".python-version", "runtime.txt"} else "node"
    source_id = source_for(builder, root, path, data, f"{language}-version")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, f"{language}-runtime-selection"
    )
    candidate = next(
        (
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ),
        "",
    )
    if not candidate:
        builder.add_gap(
            "toolchain-version-empty",
            f"{relative} contains no runtime version",
            source_id=source_id,
            evidence=(relative,),
        )
        return
    add_toolchain_observation(
        builder,
        source_id,
        root_component,
        root_version,
        language=language,
        raw_version=candidate,
        locator="line:1",
        role=f"{language}-runtime-version",
    )


def scan_go_mod(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "go-mod")
    relative = builder.sources[source_id]["evidence_uri"]
    module_match = re.search(r"(?m)^module\s+(\S+)", text)
    module_name = module_match.group(1) if module_match else path.parent.name
    go_match = re.search(r"(?m)^go\s+(\S+)", text)
    # Host-first split, as the require and go.sum sites already do.
    module_namespace, module_short_name = golang_module_namespace_name(module_name)
    root_component = builder.add_component(
        kind="go-module",
        ecosystem="golang",
        namespace=module_namespace,
        name=module_short_name,
        purl=package_purl("golang", module_name),
        identity=f"golang:{module_name}",
    )
    root_version = builder.add_version(
        root_component,
        source_ref=builder.sources[source_id]["content_hash"],
        resolution_state="resolved",
        evidence=(relative,),
        metadata={"go_version": go_match.group(1)} if go_match else {},
    )
    toolchain_match = re.search(r"(?m)^toolchain\s+(\S+)", text)
    selected_toolchain = (
        toolchain_match.group(1)
        if toolchain_match and toolchain_match.group(1) != "default"
        else (go_match.group(1) if go_match else "")
    )
    if selected_toolchain:
        selected_match = toolchain_match or go_match
        assert selected_match is not None
        line_number = text[: selected_match.start()].count("\n") + 1
        add_toolchain_observation(
            builder,
            source_id,
            root_component,
            root_version,
            language="go",
            raw_version=selected_toolchain,
            locator=f"line:{line_number}",
            role=(
                "go-toolchain-directive" if toolchain_match else "go-language-directive"
            ),
        )
    in_require = False
    dependency_count = 0
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped == "require (":
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        match = None
        if in_require:
            match = re.match(r"^(\S+)\s+(v\S+)(?:\s+//\s*(indirect))?", stripped)
        else:
            match = re.match(
                r"^require\s+(\S+)\s+(v\S+)(?:\s+//\s*(indirect))?", stripped
            )
        if not match:
            continue
        dependency_count += 1
        name, version, indirect = match.groups()
        purl = package_purl("golang", name, version)
        namespace, short_name = golang_module_namespace_name(name)
        component_id = builder.add_component(
            kind="library",
            ecosystem="golang",
            namespace=namespace,
            name=short_name,
            purl=purl,
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version,
            evidence=(f"{relative}#L{line_number}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role="go-requirement",
            raw_value=f"{name}@{version}",
            root_id=root_component,
            directness="transitive" if indirect else "direct",
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="depends-on",
            source_occurrence_id=occurrence_id,
            constraint=version,
            scope="runtime",
            resolver="go-mod",
        )
    if dependency_count and not (path.parent / "go.sum").exists():
        builder.add_gap(
            "go-sum-missing",
            f"{relative} declares dependencies but go.sum is absent",
            component_id=root_component,
            component_version_id=root_version,
            source_id=source_id,
            evidence=(relative,),
        )


def scan_go_sum(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "go-sum")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "go-checksum-lock"
    )
    seen: set[tuple[str, str]] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^(\S+)\s+(v\S+?)(?:/go\.mod)?\s+(h1:\S+)\s*$", line)
        if not match:
            continue
        name, version, checksum = match.groups()
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        namespace, short_name = golang_module_namespace_name(name)
        component_id = builder.add_component(
            kind="library",
            ecosystem="golang",
            namespace=namespace,
            name=short_name,
            purl=package_purl("golang", name, version),
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version,
            artifact_digest=checksum,
            evidence=(f"{relative}#L{line_number}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role="go-sum-module",
            raw_value=f"{name}@{version}",
            root_id=root_component,
            directness="transitive",
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="locks",
            source_occurrence_id=occurrence_id,
            constraint=version,
            resolver="go-sum",
        )


PYTHON_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)(?:\[([^]]+)\])?\s*"
    r"((?:===|==|~=|!=|<=|>=|<|>).+?)?(?:\s*;\s*(.+))?\s*$"
)


def add_python_dependency(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    name: str,
    requirement: str,
    locator: str,
    role: str,
    *,
    marker: str | None = None,
    optional: bool = False,
) -> None:
    exact_match = re.fullmatch(r"={2,3}\s*([^,;\s]+)", requirement or "")
    resolved = exact_match.group(1) if exact_match else None
    purl = package_purl("pypi", name.lower().replace("_", "-"), resolved)
    component_id = builder.add_component(
        kind="library",
        ecosystem="pypi",
        # Canonical spelling matches the purl and the live SBOM emitter.
        name=name.lower().replace("_", "-"),
        purl=purl,
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=resolved,
        constraint=requirement or None,
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
        metadata={"marker": marker} if marker else {},
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=f"{name}{requirement}",
        root_id=root_component,
        optional=optional,
        metadata={"marker": marker} if marker else {},
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship="depends-on",
        source_occurrence_id=occurrence_id,
        constraint=requirement or None,
        scope="runtime",
        optional=optional,
        resolver="python-manifest",
        metadata={"marker": marker} if marker else {},
    )


def scan_python_requirements(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "python-requirements")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "python-environment"
    )
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.split(" #", 1)[0].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("-r", "--requirement")):
            target = stripped.split(maxsplit=1)[-1]
            builder.add_gap(
                "included-manifest",
                f"Requirement file includes {target}",
                source_id=source_id,
                evidence=(f"{relative}#L{line_number}",),
            )
            continue
        direct_reference = re.fullmatch(
            r"([A-Za-z0-9_.-]+)(?:\[([^]]+)\])?\s*@\s*(\S+?)(?:\s*;\s*(.+))?",
            stripped,
        )
        if direct_reference:
            name, extras, source_reference, marker = direct_reference.groups()
            unsafe = unsafe_candidate_locator_pointers({"uri": source_reference})
            if unsafe:
                raise RegistryInputError(
                    f"candidate contains unsafe locator at {unsafe[0]}"
                )
            component_id = builder.add_component(
                kind="python-source-dependency",
                ecosystem="git",
                name=name,
                identity=f"python-source:{name}:{source_reference}",
            )
            version_id = builder.add_version(
                component_id,
                source_ref=(
                    source_reference.rsplit("@", 1)[-1]
                    if "@" in source_reference
                    else None
                ),
                constraint=source_reference,
                evidence=(f"{relative}#L{line_number}",),
                metadata={"marker": marker} if marker else {},
            )
            occurrence_id = builder.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=f"line:{line_number}",
                role="python-source-requirement",
                raw_value=source_reference,
                root_id=root_component,
                optional=bool(extras),
                metadata={"marker": marker} if marker else {},
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="depends-on",
                source_occurrence_id=occurrence_id,
                constraint=source_reference,
                resolver="python-requirements",
                optional=bool(extras),
                metadata={"marker": marker} if marker else {},
            )
            continue
        if stripped.startswith(("-e ", "git+", "http://", "https://")):
            component_id = builder.add_component(
                kind="python-source-dependency",
                ecosystem="git",
                name=stripped,
                identity=f"python-source:{stripped}",
            )
            version_id = builder.add_version(
                component_id,
                source_ref=stripped.rsplit("@", 1)[-1] if "@" in stripped else None,
                constraint=stripped,
                evidence=(f"{relative}#L{line_number}",),
            )
            occurrence_id = builder.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=f"line:{line_number}",
                role="python-source-requirement",
                raw_value=stripped,
                root_id=root_component,
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="depends-on",
                source_occurrence_id=occurrence_id,
                constraint=stripped,
                resolver="python-requirements",
            )
            continue
        match = PYTHON_REQUIREMENT_RE.match(stripped)
        if match:
            name, extras, requirement, marker = match.groups()
            add_python_dependency(
                builder,
                source_id,
                root_component,
                root_version,
                name,
                requirement or "",
                f"line:{line_number}",
                "python-requirement",
                marker=marker,
                optional=bool(extras),
            )


def scan_pyproject(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "python-pyproject")
    relative = builder.sources[source_id]["evidence_uri"]
    project_name_match = re.search(r'(?m)^name\s*=\s*["\']([^"\']+)["\']', text)
    project_version_match = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)["\']', text)
    name = project_name_match.group(1) if project_name_match else path.parent.name
    project_version = project_version_match.group(1) if project_version_match else None
    root_component = builder.add_component(
        kind="python-project",
        ecosystem="pypi",
        name=name,
        purl=package_purl("pypi", name, project_version),
        identity=f"local-pyproject:{relative}:{name}",
        official_channel_required=False,
    )
    root_version = builder.add_version(
        root_component,
        resolved_version=project_version,
        source_ref=builder.sources[source_id]["content_hash"],
        resolution_state="resolved",
        evidence=(relative,),
    )
    requires_python_match = re.search(
        r'(?m)^requires-python\s*=\s*["\']([^"\']+)["\']', text
    )
    if requires_python_match:
        line_number = text[: requires_python_match.start()].count("\n") + 1
        add_toolchain_observation(
            builder,
            source_id,
            root_component,
            root_version,
            language="python",
            raw_version=requires_python_match.group(1),
            locator=f"line:{line_number}",
            role="python-requires-version",
        )
    for line_number, line in enumerate(text.splitlines(), 1):
        for match in re.finditer(r'["\']([^"\']+)["\']', line):
            candidate = match.group(1)
            requirement = PYTHON_REQUIREMENT_RE.match(candidate)
            if not requirement:
                continue
            dep_name, extras, constraint, marker = requirement.groups()
            # Avoid treating ordinary TOML strings as dependencies.
            if not constraint and not any(token in candidate for token in (";", "[")):
                continue
            add_python_dependency(
                builder,
                source_id,
                root_component,
                root_version,
                dep_name,
                constraint or "",
                f"line:{line_number}:column:{match.start() + 1}",
                "pyproject-dependency",
                marker=marker,
                optional=bool(extras),
            )


def scan_node_json(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "node-manifest")
    relative = builder.sources[source_id]["evidence_uri"]
    try:
        payload = parse_json_bytes(data, label=f"tracked JSON input {relative}")
    except RegistryInputError as exc:
        builder.add_gap(
            "json-invalid", str(exc), source_id=source_id, evidence=(relative,)
        )
        return
    name = payload.get("name") if isinstance(payload, dict) else None
    version = payload.get("version") if isinstance(payload, dict) else None
    root_component = builder.add_component(
        kind="node-project",
        ecosystem="npm",
        name=str(name or path.parent.name),
        identity=f"local-node:{Path(relative).parent.as_posix()}:{name or path.parent.name}",
        official_channel_required=False,
    )
    root_version = builder.add_version(
        root_component,
        resolved_version=str(version) if version else None,
        source_ref=builder.sources[source_id]["content_hash"],
        resolution_state="resolved",
        evidence=(relative,),
    )
    if path.name == "package.json" and isinstance(payload, dict):
        volta = payload.get("volta") if isinstance(payload.get("volta"), dict) else {}
        engines = (
            payload.get("engines") if isinstance(payload.get("engines"), dict) else {}
        )
        node_version = volta.get("node") or engines.get("node")
        if node_version:
            locator = "/volta/node" if volta.get("node") else "/engines/node"
            add_toolchain_observation(
                builder,
                source_id,
                root_component,
                root_version,
                language="node",
                raw_version=str(node_version),
                locator=locator,
                role="node-runtime-version",
            )
    dependency_sections = {
        "dependencies": ("runtime", False),
        "devDependencies": ("development", False),
        "optionalDependencies": ("runtime", True),
        "peerDependencies": ("peer", False),
    }
    if path.name == "package.json":
        dependency_count = 0
        for section, (scope, optional) in dependency_sections.items():
            dependencies = payload.get(section, {}) if isinstance(payload, dict) else {}
            if isinstance(dependencies, dict):
                for dep_name, constraint in sorted(dependencies.items()):
                    dependency_count += 1
                    add_node_dependency(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        dep_name,
                        str(constraint),
                        f"/{section}/{json_pointer_escape(dep_name)}",
                        f"npm-{section}",
                        scope,
                        optional,
                        locked=False,
                    )
        lock_names = (
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        )
        if dependency_count and not any(
            (path.parent / name).exists() for name in lock_names
        ):
            builder.add_gap(
                "node-lock-missing",
                f"{relative} declares dependencies but no supported Node lock is present",
                component_id=root_component,
                component_version_id=root_version,
                source_id=source_id,
                evidence=(relative,),
            )
    packages = payload.get("packages", {}) if isinstance(payload, dict) else {}
    if isinstance(packages, dict):
        for package_path, metadata in sorted(packages.items()):
            if not package_path or not isinstance(metadata, dict):
                continue
            dep_name = (
                metadata.get("name") or package_path.rsplit("node_modules/", 1)[-1]
            )
            dep_version = metadata.get("version")
            if not dep_name or not dep_version:
                continue
            add_node_dependency(
                builder,
                source_id,
                root_component,
                root_version,
                str(dep_name),
                str(dep_version),
                f"/packages/{json_pointer_escape(package_path)}",
                "npm-locked-package",
                "development" if metadata.get("dev") else "runtime",
                bool(metadata.get("optional")),
                locked=True,
                directness=(
                    "transitive" if "/node_modules/" in package_path else "direct"
                ),
                metadata={
                    key: metadata[key]
                    for key in ("integrity", "resolved")
                    if key in metadata
                },
            )


def add_node_dependency(
    builder: Builder,
    source_id: str,
    root_component: str,
    root_version: str,
    name: str,
    requirement: str,
    locator: str,
    role: str,
    scope: str,
    optional: bool,
    *,
    locked: bool,
    directness: str = "direct",
    metadata: Mapping[str, Any] | None = None,
) -> None:
    resolved = requirement if locked else None
    namespace, short_name = name.rsplit("/", 1) if "/" in name else ("", name)
    purl = package_purl("npm", name, resolved)
    component_id = builder.add_component(
        kind="library",
        ecosystem="npm",
        namespace=namespace,
        name=short_name,
        purl=purl,
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=resolved,
        constraint=None if locked else requirement,
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
        metadata=metadata,
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role=role,
        raw_value=f"{name}@{requirement}",
        root_id=root_component,
        directness=directness,
        dependency_scope=scope,
        optional=optional,
        metadata=metadata,
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship="depends-on",
        source_occurrence_id=occurrence_id,
        constraint=None if locked else requirement,
        scope=scope,
        optional=optional,
        resolver="npm-lock" if locked else "package-json",
        metadata=metadata,
    )


def scan_yarn_lock(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "yarn-lock")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "node-lock"
    )
    current_name: str | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        header = re.match(r'^\s*"?(@?[^"\s:,]+(?:/[^"\s:,]+)?)@[^:]+"?:\s*$', line)
        if header:
            current_name = header.group(1)
            continue
        version = re.match(r'^\s+version\s+["\']([^"\']+)["\']', line)
        if version and current_name:
            add_node_dependency(
                builder,
                source_id,
                root_component,
                root_version,
                current_name,
                version.group(1),
                f"line:{line_number}",
                "yarn-locked-package",
                "runtime",
                False,
                locked=True,
                directness="transitive",
            )


def scan_pnpm_lock(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "pnpm-lock")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "node-lock"
    )
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.match(
            r"^\s{2,}/?(@?[^@:\s]+(?:/[^@:\s]+)?)@([^:(\s]+)(?:\([^)]*\))?:\s*$", line
        )
        if match:
            add_node_dependency(
                builder,
                source_id,
                root_component,
                root_version,
                match.group(1),
                match.group(2),
                f"line:{line_number}",
                "pnpm-locked-package",
                "runtime",
                False,
                locked=True,
                directness="transitive",
            )


def matching_hcl_brace(text: str, opening: int) -> int | None:
    depth = 0
    quote_char: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
            index += 1
            continue
        if char in {'"', "'"}:
            quote_char = char
        elif char == "#":
            line_comment = True
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def hcl_blocks(
    text: str, header_pattern: str
) -> Iterator[tuple[re.Match[str], str, int, int]]:
    pattern = re.compile(header_pattern, re.MULTILINE)
    position = 0
    while match := pattern.search(text, position):
        opening = text.find("{", match.start(), match.end())
        if opening < 0:
            position = match.end()
            continue
        closing = matching_hcl_brace(text, opening)
        if closing is None:
            break
        yield match, text[opening + 1 : closing], opening + 1, closing
        position = closing + 1


def terraform_provider_address(address: str) -> str:
    normalized = address.strip().removeprefix("registry.terraform.io/")
    if "/" not in normalized:
        normalized = f"hashicorp/{normalized}"
    return normalized


def terraform_lock_in_scope(root: Path, path: Path) -> Path | None:
    directory = path.parent
    while True:
        candidate = directory / ".terraform.lock.hcl"
        if candidate.exists():
            return candidate
        if directory == root or root not in directory.parents:
            return None
        directory = directory.parent


def scan_terraform_config(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "terraform-config")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "terraform-config"
    )
    dependency_count = 0

    required_version = re.search(r'(?m)^\s*required_version\s*=\s*"([^"]+)"', text)
    if required_version:
        constraint = required_version.group(1)
        line_number = text.count("\n", 0, required_version.start()) + 1
        component_id = builder.add_component(
            kind="cli",
            ecosystem="terraform",
            namespace="hashicorp",
            name="terraform",
            identity="terraform-cli:hashicorp/terraform",
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=constraint if looks_exact(constraint) else None,
            constraint=constraint,
            evidence=(f"{relative}#L{line_number}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role="terraform-required-version",
            raw_value=constraint,
            root_id=root_component,
            dependency_scope="automation",
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="requires-tool",
            source_occurrence_id=occurrence_id,
            constraint=constraint,
            scope="automation",
            resolver="terraform-config",
        )

    for _, body, body_offset, _ in hcl_blocks(text, r"^\s*required_providers\s*\{"):
        for entry, provider_body, _, _ in hcl_blocks(
            body, r"^\s*([A-Za-z_][\w-]*)\s*=\s*\{"
        ):
            local_name = entry.group(1)
            source_match = re.search(r'(?m)^\s*source\s*=\s*"([^"]+)"', provider_body)
            version_match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', provider_body)
            raw_address = source_match.group(1) if source_match else local_name
            address = terraform_provider_address(raw_address)
            constraint = version_match.group(1) if version_match else ""
            absolute_offset = body_offset + entry.start()
            line_number = text.count("\n", 0, absolute_offset) + 1
            namespace, name = address.rsplit("/", 1)
            component_id = builder.add_component(
                kind="terraform-provider",
                ecosystem="terraform",
                namespace=namespace,
                name=name,
                purl=package_purl("terraform", address),
                identity=f"terraform-provider:{address}",
                metadata={"source_address": address},
            )
            version_id = builder.add_version(
                component_id,
                resolved_version=constraint if looks_exact(constraint) else None,
                constraint=constraint or None,
                evidence=(f"{relative}#L{line_number}",),
            )
            occurrence_id = builder.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=f"line:{line_number}",
                role="terraform-required-provider",
                raw_value=f"{address}@{constraint}",
                root_id=root_component,
                dependency_scope="automation",
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="depends-on",
                source_occurrence_id=occurrence_id,
                constraint=constraint or None,
                scope="automation",
                resolver="terraform-config",
            )
            dependency_count += 1

    for match, body, body_offset, _ in hcl_blocks(text, r'^\s*module\s+"([^"]+)"\s*\{'):
        module_name = match.group(1)
        source_match = re.search(r'(?m)^\s*source\s*=\s*"([^"]+)"', body)
        if not source_match:
            continue
        source = source_match.group(1)
        version_match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', body)
        constraint = version_match.group(1) if version_match else ""
        source_offset = body_offset + source_match.start()
        line_number = text.count("\n", 0, source_offset) + 1
        if source.startswith(("./", "../")):
            target = (path.parent / source).absolute()
            try:
                target_name = target.relative_to(root).as_posix()
            except ValueError:
                target_name = target.as_posix()
            component_id = builder.add_component(
                kind="terraform-module",
                ecosystem="local",
                name=module_name,
                identity=f"local:terraform-module:{target_name}",
                official_channel_required=False,
                metadata={"module_path": target_name},
            )
            version_id = builder.add_version(
                component_id,
                source_ref=source,
                resolution_state="resolved" if target.exists() else "unresolved",
                evidence=(f"{relative}#L{line_number}",),
            )
            if not target.exists():
                builder.add_gap(
                    "terraform-local-module-missing",
                    f"Local Terraform module {source!r} does not exist",
                    component_id=component_id,
                    component_version_id=version_id,
                    source_id=source_id,
                    evidence=(f"{relative}#L{line_number}",),
                )
        else:
            module_source = source.split("?", 1)[0]
            component_id = builder.add_component(
                kind="terraform-module",
                ecosystem=(
                    "terraform"
                    if not source.startswith(("git::", "http://", "https://"))
                    else "git"
                ),
                name=module_name,
                purl=(
                    package_purl("terraform", module_source)
                    if not source.startswith(("git::", "http://", "https://"))
                    else None
                ),
                identity=f"terraform-module:{source}",
                metadata={"source_address": source},
            )
            source_ref_match = re.search(r"[?&]ref=([^&]+)", source)
            version_id = builder.add_version(
                component_id,
                resolved_version=constraint if looks_exact(constraint) else None,
                constraint=constraint or source,
                source_ref=source_ref_match.group(1) if source_ref_match else None,
                evidence=(f"{relative}#L{line_number}",),
            )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role="terraform-module",
            raw_value=f"{source}@{constraint}",
            root_id=root_component,
            dependency_scope="automation",
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="depends-on",
            source_occurrence_id=occurrence_id,
            constraint=constraint or source,
            scope="automation",
            resolver="terraform-config",
        )
        dependency_count += 1

    for heredoc in re.finditer(
        r"(?ms)^\s*data\s*=\s*<<-?([A-Za-z_][A-Za-z0-9_]*)\s*$\n(.*?)^\s*\1\s*$",
        text,
    ):
        body = heredoc.group(2)
        if "#cloud-config" not in body:
            continue
        packages_indent: int | None = None
        body_start_line = text.count("\n", 0, heredoc.start(2)) + 1
        for offset, line in enumerate(body.splitlines()):
            package_header = re.match(r"^(\s*)packages:\s*$", line)
            if package_header:
                packages_indent = len(package_header.group(1))
                continue
            if packages_indent is None:
                continue
            package_match = re.match(r"^(\s*)-\s*([^#\s][^#]*)\s*$", line)
            if package_match and len(package_match.group(1)) > packages_indent:
                add_package_observation(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    ecosystem="deb",
                    package=package_match.group(2).strip(),
                    locator=f"line:{body_start_line + offset}",
                    role="cloud-config-deb-package",
                    scope="deployment",
                    resolver="terraform-cloud-config",
                )
                continue
            if line.strip() and len(line) - len(line.lstrip()) <= packages_indent:
                packages_indent = None

    if dependency_count and terraform_lock_in_scope(root, path) is None:
        builder.add_gap(
            "terraform-lock-missing",
            f"{relative} declares providers/modules but no .terraform.lock.hcl is in scope",
            component_id=root_component,
            component_version_id=root_version,
            source_id=source_id,
            evidence=(relative,),
        )


def split_command_package_spec(
    command: str, value: str
) -> tuple[str, str, list[str]] | None:
    """Return package, version/constraint, and extras for npx/uvx specs."""

    candidate = value.strip()
    extras: list[str] = []
    if command == "uvx":
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)(?:\[([^\]]+)\])?(?:==|@)([^\s]+)", candidate
        )
        if not match:
            return None
        name, extra_text, version = match.groups()
        if extra_text:
            extras = sorted(
                item.strip() for item in extra_text.split(",") if item.strip()
            )
        return name, version, extras
    if command != "npx":
        return None
    separator = candidate.rfind("@")
    if separator <= 0 or (
        candidate.startswith("@") and "/" not in candidate[:separator]
    ):
        return None
    name = candidate[:separator]
    version = candidate[separator + 1 :]
    if not name or not version:
        return None
    return name, version, extras


def scan_mcp_command_config(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    """Discover exact ephemeral package executions in MCP command configs."""

    try:
        payload = parse_json_bytes(
            data,
            label=f"tracked JSON input {path.relative_to(root).as_posix()}",
        )
    except RegistryInputError:
        return
    servers = payload.get("mcpServers") if isinstance(payload, dict) else None
    if not isinstance(servers, dict):
        return
    source_id = source_for(builder, root, path, data, "mcp-command-config")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "mcp-command-config"
    )
    for server_name, config in sorted(servers.items()):
        if not isinstance(config, dict):
            continue
        command = str(config.get("command") or "").strip().lower()
        args = config.get("args")
        server_pointer = f"/mcpServers/{json_pointer_escape(str(server_name))}"
        if command not in {"npx", "uvx"} or not isinstance(args, list):
            builder.add_gap(
                "mcp-command-package-unresolved",
                f"MCP server {server_name!r} does not expose a supported npx/uvx package spec",
                source_id=source_id,
                evidence=(f"{relative}#{server_pointer}",),
            )
            continue
        candidate_indexes: list[int] = []
        if command == "uvx" and "--from" in args:
            from_index = args.index("--from")
            if from_index + 1 < len(args):
                candidate_indexes.append(from_index + 1)
        candidate_indexes.extend(
            index
            for index, argument in enumerate(args)
            if isinstance(argument, str) and not argument.startswith("-")
        )
        parsed: tuple[str, str, list[str]] | None = None
        argument_index = -1
        for index in dict.fromkeys(candidate_indexes):
            argument = args[index]
            if not isinstance(argument, str):
                continue
            parsed = split_command_package_spec(command, argument)
            if parsed:
                argument_index = index
                break
        locator = f"{server_pointer}/args/{argument_index}"
        if parsed is None:
            builder.add_gap(
                "mcp-command-package-unresolved",
                f"MCP server {server_name!r} has no parseable exact package argument",
                source_id=source_id,
                evidence=(f"{relative}#{locator}",),
            )
            continue
        package_name, version, extras = parsed
        ecosystem = "npm" if command == "npx" else "pypi"
        namespace, short_name = (
            package_name.rsplit("/", 1)
            if ecosystem == "npm" and "/" in package_name
            else ("", package_name)
        )
        component_id = builder.add_component(
            kind="library",
            ecosystem=ecosystem,
            namespace=namespace,
            name=short_name,
            purl=package_purl(ecosystem, package_name),
            metadata={"extras": extras} if extras else {},
        )
        exact = looks_exact(version)
        version_id = builder.add_version(
            component_id,
            resolved_version=version if exact else None,
            constraint=version if not exact else None,
            evidence=(f"{relative}#{locator}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=locator,
            role=f"mcp-{command}-package",
            raw_value=f"{package_name}@{version}",
            root_id=root_component,
            dependency_scope="runtime",
            metadata={"mcp_server": str(server_name), "ephemeral_fetch": True},
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="executes-package",
            source_occurrence_id=occurrence_id,
            constraint=version,
            scope="runtime",
            resolver=f"mcp-{command}",
        )
        builder.add_gap(
            "ephemeral-package-integrity-unresolved",
            f"MCP server {server_name!r} executes {package_name}@{version} without a lock artifact or integrity hash",
            component_id=component_id,
            component_version_id=version_id,
            source_id=source_id,
            evidence=(f"{relative}#{locator}",),
        )


def toml_line_for(text: str, pattern: str) -> int:
    match = re.search(pattern, text, re.MULTILINE)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def configured_endpoint_version(
    builder: Builder, component_id: str, source_id: str, evidence: str
) -> str:
    return builder.add_version(
        component_id,
        source_ref=str(builder.sources[source_id].get("content_hash") or ""),
        resolution_state="resolved",
        evidence=(evidence,),
    )


def scan_containerd_hosts(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        source_id = source_for(builder, root, path, data, "containerd-hosts")
        builder.add_gap(
            "toml-invalid", str(exc), source_id=source_id, evidence=(path.as_posix(),)
        )
        return
    server = payload.get("server") if isinstance(payload, dict) else None
    hosts = payload.get("host") if isinstance(payload, dict) else None
    if not isinstance(server, str) and not isinstance(hosts, dict):
        return
    source_id = source_for(builder, root, path, data, "containerd-hosts")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "containerd-hosts"
    )

    def add_endpoint(
        uri: str, *, line_number: int, role: str, metadata: Mapping[str, Any]
    ) -> None:
        normalized = f"https://{normalize_registry_server(uri)}"
        component_id = builder.add_component(
            kind="registry-endpoint",
            ecosystem="oci-registry",
            name=normalized,
            identity=f"registry-endpoint:{normalized}",
            official_channel_required=False,
            metadata={"endpoint": normalized},
        )
        version_id = configured_endpoint_version(
            builder, component_id, source_id, f"{relative}#L{line_number}"
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role=role,
            raw_value=uri,
            root_id=root_component,
            dependency_scope="deployment",
            metadata=metadata,
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship=(
                "configures"
                if role == "containerd-registry-server"
                else "routes-through"
            ),
            source_occurrence_id=occurrence_id,
            scope="deployment",
            resolver="containerd-hosts",
            metadata=metadata,
        )

    if isinstance(server, str):
        add_endpoint(
            server,
            line_number=toml_line_for(text, r"^server\s*="),
            role="containerd-registry-server",
            metadata={"registry_server": True},
        )
    if isinstance(hosts, dict):
        for uri, config in hosts.items():
            if not isinstance(uri, str):
                continue
            safe_config = config if isinstance(config, dict) else {}
            metadata = {
                key: safe_config[key]
                for key in ("capabilities", "override_path", "skip_verify")
                if key in safe_config
            }
            add_endpoint(
                uri,
                line_number=toml_line_for(text, rf'^\s*\[host\."{re.escape(uri)}"\]'),
                role="containerd-registry-mirror",
                metadata=metadata,
            )


def scan_gitleaks_config(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        source_id = source_for(builder, root, path, data, "gitleaks-config")
        builder.add_gap(
            "toml-invalid", str(exc), source_id=source_id, evidence=(path.as_posix(),)
        )
        return
    source_id = source_for(builder, root, path, data, "gitleaks-config")
    relative = builder.sources[source_id]["evidence_uri"]
    add_local_root(builder, source_id, relative, "gitleaks-config")
    extend = payload.get("extend") if isinstance(payload, dict) else {}
    builder.add_component(
        kind="gitleaks-config",
        ecosystem="local",
        name=relative,
        identity=f"local:gitleaks-config:{relative}",
        official_channel_required=False,
        metadata={
            "extends_default_rules": bool(
                isinstance(extend, dict) and extend.get("useDefault") is True
            )
        },
    )


def scan_codex_config(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    data = normalize_codex_projection_references(data)
    text = data.decode("utf-8", errors="replace")
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        source_id = source_for(builder, root, path, data, "codex-config")
        builder.add_gap(
            "toml-invalid", str(exc), source_id=source_id, evidence=(path.as_posix(),)
        )
        return
    servers = payload.get("mcp_servers") if isinstance(payload, dict) else None
    if not isinstance(servers, dict):
        return
    source_id = source_for(builder, root, path, data, "codex-config")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "codex-config"
    )
    for name, config in sorted(servers.items()):
        if not isinstance(config, dict) or not isinstance(config.get("url"), str):
            continue
        url = str(config["url"])
        component_id = builder.add_component(
            kind="mcp-server-endpoint",
            ecosystem="mcp",
            name=str(name),
            identity=f"mcp-endpoint:{name}:{url}",
            official_channel_required=False,
            metadata={"endpoint": url},
        )
        line_number = toml_line_for(
            text, rf"^\s*\[mcp_servers\.{re.escape(str(name))}\]"
        )
        version_id = configured_endpoint_version(
            builder, component_id, source_id, f"{relative}#L{line_number}"
        )
        enabled_tools = config.get("enabled_tools")
        metadata = {
            "enabled": bool(config.get("enabled", True)),
            "required": bool(config.get("required", False)),
            "enabled_tools": (
                sorted(str(item) for item in enabled_tools)
                if isinstance(enabled_tools, list)
                else []
            ),
        }
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role="mcp-server-endpoint",
            raw_value=url,
            root_id=root_component,
            dependency_scope="development",
            metadata=metadata,
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="configures",
            source_occurrence_id=occurrence_id,
            scope="development",
            resolver="codex-config",
            metadata=metadata,
        )


SCRIPT_DISTRIBUTION_ALIASES = {
    "chatterbox": "chatterbox-tts",
    "jsonschema": "jsonschema",
    "psycopg": "psycopg",
    "requests": "requests",
    "torchaudio": "torchaudio",
    "yaml": "PyYAML",
}


def requirement_specs_in_directory(
    root: Path, directory: Path
) -> dict[str, tuple[str, int, Path]]:
    result: dict[str, tuple[str, int, Path]] = {}
    for requirement_path in sorted(directory.glob("requirements*.txt")):
        try:
            if not stat.S_ISREG(
                os.lstat(requirement_path).st_mode
            ) or not git_path_is_tracked(root, requirement_path):
                continue
            requirement_text = read_regular_file(
                requirement_path,
                max_bytes=MAX_DISCOVERY_FILE_BYTES,
                label=f"tracked requirements input {requirement_path}",
            ).decode("utf-8", errors="replace")
        except (OSError, RegistryInputError):
            continue
        for line_number, line in enumerate(requirement_text.splitlines(), 1):
            stripped = line.split(" #", 1)[0].strip()
            parsed = package_spec("pypi", stripped)
            if parsed is None:
                continue
            normalized = re.sub(r"[-_.]+", "-", parsed[0]).lower()
            result.setdefault(normalized, (stripped, line_number, requirement_path))
    return result


def scan_script_dependencies(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    observations: list[tuple[int, str, bool]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        import_match = re.search(r"\bimport\s+([A-Za-z_][A-Za-z0-9_]*)", line)
        from_match = re.search(r"\bfrom\s+([A-Za-z_][A-Za-z0-9_]*)[.\s]", line)
        module = (
            from_match.group(1)
            if from_match
            else (import_match.group(1) if import_match else "")
        )
        if module in SCRIPT_DISTRIBUTION_ALIASES:
            distribution = SCRIPT_DISTRIBUTION_ALIASES[module]
            observations.append(
                (
                    line_number,
                    distribution,
                    distribution in {"jsonschema", "torchaudio", "chatterbox-tts"},
                )
            )
        if re.search(r"\boptimum-cli\s+export\b", line):
            observations.append((line_number, "optimum", False))
    unique_observations = list(dict.fromkeys(observations))
    if not unique_observations:
        return
    source_id = source_for(builder, root, path, data, "script-dependencies")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "automation-script"
    )
    requirements = requirement_specs_in_directory(root, path.parent)
    for line_number, distribution, optional in unique_observations:
        normalized = re.sub(r"[-_.]+", "-", distribution).lower()
        requirement = requirements.get(normalized)
        package = requirement[0] if requirement else distribution
        added = add_package_observation(
            builder,
            source_id,
            root_component,
            root_version,
            ecosystem="pypi",
            package=package,
            locator=f"line:{line_number}",
            role="script-direct-dependency",
            scope="automation",
            resolver="sibling-python-requirements",
            optional=optional,
            lifecycle="conditional" if optional else None,
            metadata={"distribution": distribution},
        )
        if not added:
            continue
        component_id, version_id, _ = added
        if requirement:
            parsed = package_spec("pypi", package)
            if parsed:
                try:
                    requirement_relative = requirement[2].relative_to(root).as_posix()
                except ValueError:
                    requirement_relative = requirement[2].as_posix()
                builder.add_version(
                    component_id,
                    resolved_version=parsed[1],
                    constraint=parsed[2],
                    resolution_state="resolved" if parsed[1] else "unresolved",
                    evidence=(
                        f"{relative}#L{line_number}",
                        f"{requirement_relative}#L{requirement[1]}",
                    ),
                )
        else:
            builder.add_gap(
                "script-dependency-pin-missing",
                f"{relative} directly uses {distribution!r} without a sibling requirement pin",
                component_id=component_id,
                component_version_id=version_id,
                source_id=source_id,
                evidence=(f"{relative}#L{line_number}",),
            )


def scan_install_script(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "install-script")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "install-script"
    )
    variables = literal_shell_variables(text)
    seen_remote: set[tuple[int, str]] = set()
    for line_number, command in shell_logical_commands(text):
        locator = f"line:{line_number}"
        for clause_index, clause in enumerate(shell_clauses(command)):
            clause_locator = f"{locator}:clause:{clause_index}"
            system_install = shell_install_tokens(clause)
            if system_install:
                ecosystem, packages = system_install
                for package in packages:
                    conditional = package in {
                        "linux-generic",
                        "linux-generic-hwe-24.04",
                    }
                    add_package_observation(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        ecosystem=ecosystem,
                        package=package,
                        locator=clause_locator,
                        role=f"shell-{ecosystem}-package",
                        scope="automation",
                        resolver="install-script",
                        optional=conditional,
                        lifecycle="conditional" if conditional else None,
                    )
            pip_install = shell_pip_install(clause)
            if pip_install:
                packages, _ = pip_install
                for package in packages:
                    add_package_observation(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        ecosystem="pypi",
                        package=package,
                        locator=clause_locator,
                        role="shell-pip-package",
                        scope="automation",
                        resolver="install-script",
                    )
            for package in shell_npm_install(clause) or []:
                add_package_observation(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    ecosystem="npm",
                    package=package,
                    locator=clause_locator,
                    role="shell-npm-package",
                    scope="automation",
                    resolver="install-script",
                )
            tokens = shell_tokens(clause)
            if len(tokens) >= 4 and tokens[:3] == ["helm", "plugin", "install"]:
                add_git_clone_observation(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    repository=tokens[3],
                    ref=None,
                    locator=clause_locator,
                    role="helm-plugin",
                    scope="automation",
                    resolver="helm-plugin-install",
                )
            clone = parse_git_clone(clause)
            if clone:
                add_git_clone_observation(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    repository=clone[0],
                    ref=clone[1],
                    locator=clause_locator,
                    role="shell-git-clone",
                    scope="automation",
                    resolver="install-script",
                )
        tokens = shell_tokens(command)
        if len(tokens) >= 3 and tokens[:2] == ["mise", "use"]:
            for index, spec in enumerate(
                token for token in tokens[2:] if not token.startswith("-")
            ):
                name, separator, raw_version = spec.rpartition("@")
                if not separator or not name or not raw_version:
                    continue
                mise_locator = f"{locator}:mise:{index}"
                if name in {"node", "python"}:
                    add_toolchain_observation(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        language=name,
                        raw_version=raw_version,
                        locator=mise_locator,
                        role="shell-mise-tool",
                    )
                else:
                    add_cli_observation(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        name=name,
                        raw_version=raw_version,
                        locator=mise_locator,
                        role="shell-mise-tool",
                        scope="automation",
                        resolver="mise",
                    )
        should_scan_urls = relative in {
            "scripts/setup/linux-apt-mise.sh",
            "apps/infra/node-gpu-firmware/files/fw-update.sh",
        } and ("curl" in command or "wget" in command)
        if should_scan_urls:
            for url_index, url_match in enumerate(SHELL_URL_RE.finditer(command)):
                url = url_match.group(0).rstrip("\\")
                if (
                    url.endswith(".gpg")
                    or url.endswith("/gpg")
                    or "\\" in url
                    or "[" in url
                ):
                    continue
                remote_key = (line_number, url)
                if remote_key in seen_remote:
                    continue
                seen_remote.add(remote_key)
                variable_match = re.search(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", url)
                installed_version = (
                    variables.get(variable_match.group(1)) if variable_match else None
                )
                add_remote_input(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    url=expand_literal_variables(url, variables),
                    locator=f"{locator}:url:{url_index}",
                    role="shell-remote-download",
                    scope="automation",
                    resolver="install-script",
                    installed_version=installed_version,
                )
        if relative == "apps/infra/node-gpu-firmware/files/fw-update.sh":
            fallback = re.match(r'^\s*DRIVER_URL="(https?://[^"\s]+)"', command)
            if fallback:
                add_remote_input(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    url=fallback.group(1),
                    locator=f"{locator}:fallback",
                    role="shell-remote-download",
                    scope="automation",
                    resolver="install-script",
                )


def scan_terraform_lock(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "terraform-lock")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "terraform-root"
    )
    provider_re = re.compile(r'^provider\s+"([^"]+)"\s*\{')
    current: tuple[int, str] | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        provider = provider_re.match(line.strip())
        if provider:
            current = (line_number, provider.group(1))
            continue
        if current:
            version = re.match(r'^\s*version\s*=\s*"([^"]+)"', line)
            if version:
                provider_line, address = current
                resolved = version.group(1)
                address = terraform_provider_address(address)
                namespace, name = address.rsplit("/", 1)
                component_id = builder.add_component(
                    kind="terraform-provider",
                    ecosystem="terraform",
                    namespace=namespace,
                    name=name,
                    purl=package_purl("terraform", address),
                    identity=f"terraform-provider:{address}",
                    metadata={"source_address": address},
                )
                version_id = builder.add_version(
                    component_id,
                    resolved_version=resolved,
                    evidence=(
                        f"{relative}#L{provider_line}",
                        f"{relative}#L{line_number}",
                    ),
                )
                occurrence_id = builder.add_occurrence(
                    component_id,
                    version_id,
                    source_id,
                    locator=f"lines:{provider_line},{line_number}",
                    role="terraform-locked-provider",
                    raw_value=f"{address}@{resolved}",
                    root_id=root_component,
                )
                builder.add_edge(
                    root_version,
                    version_id,
                    relationship="locks",
                    source_occurrence_id=occurrence_id,
                    constraint=resolved,
                    resolver="terraform-lock",
                )
                current = None


def scan_packer(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    if "required_plugins" not in text and "packer" not in text:
        return
    source_id = source_for(builder, root, path, data, "packer-template")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "packer-template"
    )
    block_re = re.compile(r"(?ms)([\w-]+)\s*=\s*\{(.*?)\}")
    for index, block in enumerate(block_re.finditer(text)):
        name, body = block.groups()
        source = re.search(r'source\s*=\s*"([^"]+)"', body)
        version = re.search(r'version\s*=\s*"([^"]+)"', body)
        if not source:
            continue
        address = source.group(1)
        constraint = version.group(1) if version else ""
        namespace, short_name = address.rsplit("/", 1) if "/" in address else ("", name)
        component_id = builder.add_component(
            kind="packer-plugin",
            ecosystem="packer",
            namespace=namespace,
            name=short_name,
            identity=f"packer:{address}",
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=constraint if looks_exact(constraint) else None,
            constraint=constraint or None,
            evidence=(f"{relative}#offset:{block.start()}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"offset:{block.start()}:plugin:{index}",
            role="packer-plugin",
            raw_value=f"{address}@{constraint}",
            root_id=root_component,
            dependency_scope="build",
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="depends-on",
            source_occurrence_id=occurrence_id,
            constraint=constraint or None,
            scope="build",
            resolver="packer-template",
        )

    for line_number, line in enumerate(text.splitlines(), 1):
        quoted = re.match(r'^\s*"((?:\\.|[^"\\])*)",?\s*$', line)
        if not quoted:
            continue
        try:
            command = json.loads(f'"{quoted.group(1)}"')
        except json.JSONDecodeError:
            command = quoted.group(1)
        for clause_index, clause in enumerate(shell_clauses(command)):
            install = shell_install_tokens(clause)
            if not install:
                continue
            ecosystem, packages = install
            for package in packages:
                add_package_observation(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    ecosystem=ecosystem,
                    package=package,
                    locator=f"line:{line_number}:clause:{clause_index}",
                    role=f"packer-{ecosystem}-package",
                    scope="build",
                    resolver="packer-shell-provisioner",
                )

    for match, body, body_offset, _ in hcl_blocks(
        text, r'^\s*provisioner\s+"file"\s*\{'
    ):
        source_match = re.search(r'(?m)^\s*source\s*=\s*"([^"]+)"', body)
        destination_match = re.search(r'(?m)^\s*destination\s*=\s*"([^"]+)"', body)
        if not source_match:
            continue
        raw_source = source_match.group(1)
        read_root = committed_view_read_root(root)
        packer_directory = read_root / path.parent.relative_to(root)
        source_value = raw_source.replace("${path.root}", packer_directory.as_posix())
        input_path = Path(os.path.normpath(Path(source_value).absolute().as_posix()))
        digest = docker_input_digest(read_root, input_path)
        line_number = text.count("\n", 0, body_offset + source_match.start()) + 1
        if not digest:
            builder.add_gap(
                "packer-file-input-unresolved",
                f"Packer file input {raw_source!r} cannot be hashed",
                source_id=source_id,
                evidence=(f"{relative}#L{line_number}",),
            )
            continue
        try:
            input_relative = input_path.relative_to(read_root).as_posix()
        except ValueError:
            input_relative = input_path.as_posix()
        tracked = docker_input_is_tracked(read_root, input_path)
        copied_source_id = builder.add_source(
            input_relative,
            "packer-file-input",
            content_hash=digest,
            metadata={
                "evidence_class": evidence_class_for_path(input_relative),
                "tracked": tracked,
            },
        )
        component_id = builder.add_component(
            kind="build-input",
            ecosystem="local",
            name=input_relative,
            identity=f"packer-build-input:{input_relative}",
            official_channel_required=False,
        )
        version_id = builder.add_version(
            component_id,
            artifact_digest=digest,
            resolution_state="resolved",
            evidence=(f"{relative}#L{line_number}", input_relative),
        )
        metadata = {
            "copied_source_id": copied_source_id,
            "destination": destination_match.group(1) if destination_match else "",
            "tracked": tracked,
        }
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role="packer-file-input",
            raw_value=raw_source,
            root_id=root_component,
            dependency_scope="build",
            metadata=metadata,
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="copies-input",
            source_occurrence_id=occurrence_id,
            scope="build",
            resolver="packer-file-provisioner",
            metadata=metadata,
        )
        if not tracked:
            builder.add_gap(
                "packer-file-input-untracked",
                f"Packer file input {input_relative!r} is not reproducible from Git",
                component_id=component_id,
                component_version_id=version_id,
                source_id=source_id,
                evidence=(f"{relative}#L{line_number}", input_relative),
            )


def scan_ansible_requirements(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "ansible-requirements")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "ansible-project"
    )
    for index, dependency in enumerate(
        parse_yaml_dependency_blocks(text, ("collections", "roles"))
    ):
        line, name = dependency["name"]
        version = dependency.get("version", (line, ""))[1]
        source = dependency.get("source", (line, ""))[1]
        kind = "ansible-collection" if "." in name else "ansible-role"
        ecosystem = "ansible"
        namespace, short_name = name.rsplit(".", 1) if "." in name else ("", name)
        component_id = builder.add_component(
            kind=kind,
            ecosystem=ecosystem,
            namespace=namespace,
            name=short_name,
            identity=f"ansible:{kind}:{name}:{source}",
            metadata={"source": source} if source else {},
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version if looks_exact(version) else None,
            constraint=version or None,
            evidence=(f"{relative}#L{line}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line}:dependency:{index}",
            role=kind,
            raw_value=f"{name}@{version}",
            root_id=root_component,
            dependency_scope="automation",
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="depends-on",
            source_occurrence_id=occurrence_id,
            constraint=version or None,
            scope="automation",
            resolver="ansible-requirements",
        )


def yaml_run_blocks(text: str) -> Iterator[tuple[int, str]]:
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*(.*?)\s*$", lines[index])
        if not match:
            index += 1
            continue
        start_line = index + 1
        indent = len(match.group(1))
        value = match.group(2)
        if value not in {"|", ">", "|-", ">-"}:
            yield start_line, scalar(value)
            index += 1
            continue
        block: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            block.append(line)
            index += 1
        nonempty_indents = [
            len(line) - len(line.lstrip()) for line in block if line.strip()
        ]
        dedent = min(nonempty_indents) if nonempty_indents else 0
        yield start_line + 1, "\n".join(
            line[dedent:] if len(line) >= dedent else "" for line in block
        )


def github_workflow_variables(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s+([A-Z][A-Z0-9_]*)\s*:\s*([^#]+?)\s*$", line)
        if not match:
            continue
        value = scalar(match.group(2))
        if value and "${{" not in value:
            result[match.group(1)] = value
    return result


def workflow_working_directory(text: str, before_line: int) -> str | None:
    result: str | None = None
    for line in text.splitlines()[:before_line]:
        match = re.match(r"^\s*working-directory:\s*(\S+)\s*$", line)
        if match:
            result = scalar(match.group(1))
    return result


def add_workflow_manifest_install(
    builder: Builder,
    root: Path,
    source_id: str,
    root_component: str,
    root_version: str,
    *,
    working_directory: str | None,
    locator: str,
) -> None:
    directory = root / (working_directory or ".")
    manifest_path = directory / "package.json"
    try:
        if not git_path_is_tracked(root, manifest_path):
            raise RegistryInputError("package.json is not tracked")
        data = read_regular_file(
            manifest_path,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label=f"workflow package manifest {manifest_path}",
        )
        payload = parse_json_bytes(
            data, label=f"workflow package manifest {manifest_path}"
        )
    except (OSError, RegistryInputError):
        builder.add_gap(
            "github-actions-install-manifest-unresolved",
            f"npm install at {locator} has no readable package.json in {working_directory or '.'}",
            source_id=source_id,
            evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
        )
        return
    name = str(payload.get("name") or manifest_path.parent.name)
    version = str(payload.get("version") or "")
    relative_directory = manifest_path.parent.relative_to(root).as_posix()
    component_id = builder.add_component(
        kind="node-project",
        ecosystem="npm",
        name=name,
        identity=f"local-node:{relative_directory}:{name}",
        official_channel_required=False,
    )
    version_id = builder.add_version(
        component_id,
        resolved_version=version or None,
        source_ref=file_hash(data),
        resolution_state="resolved",
        evidence=(manifest_path.relative_to(root).as_posix(),),
    )
    occurrence_id = builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=locator,
        role="github-actions-manifest-install",
        raw_value=f"npm install:{relative_directory}/package.json",
        root_id=root_component,
        dependency_scope="ci",
    )
    builder.add_edge(
        root_version,
        version_id,
        relationship="installs-manifest",
        source_occurrence_id=occurrence_id,
        scope="ci",
        resolver="github-actions",
    )


def scan_github_actions(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "github-actions-workflow")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "ci-workflow"
    )
    for line_number, _, value in yaml_key_values(text, "uses"):
        if value.startswith(("./", "docker://")):
            continue
        if "@" not in value:
            builder.add_gap(
                "action-ref-unresolved",
                f"GitHub Action {value!r} has no ref",
                source_id=source_id,
                evidence=(f"{relative}#L{line_number}",),
            )
            continue
        repository, ref = value.rsplit("@", 1)
        component_id = builder.add_component(
            kind="github-action",
            ecosystem="github-actions",
            name=repository,
            identity=f"github-action:{repository}",
            metadata={"source_repo": f"https://github.com/{repository}"},
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=ref,
            source_ref=ref,
            evidence=(f"{relative}#L{line_number}",),
        )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"line:{line_number}",
            role="github-action",
            raw_value=value,
            root_id=root_component,
            dependency_scope="ci",
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="invokes",
            source_occurrence_id=occurrence_id,
            constraint=ref,
            scope="ci",
            resolver="github-actions",
        )

    lines = text.splitlines()
    setup_actions = {
        "actions/setup-node": ("node", "node-version"),
        "actions/setup-python": ("python", "python-version"),
        "hashicorp/setup-terraform": ("terraform", "terraform_version"),
    }
    for index, line in enumerate(lines):
        uses_match = re.match(r"^(\s*)-?\s*uses:\s*([^\s#]+)", line)
        if not uses_match:
            continue
        repository = uses_match.group(2).split("@", 1)[0]
        setup = setup_actions.get(repository)
        if not setup:
            continue
        language, version_key = setup
        raw_version = ""
        version_line = index + 1
        for following_index in range(index + 1, min(len(lines), index + 8)):
            following = lines[following_index]
            if re.match(r"^\s*-\s+(?:uses|name|run):", following):
                break
            version_match = re.search(
                rf"\b{re.escape(version_key)}\s*:\s*['\"]?([^'\"}},\s]+)",
                following,
            )
            if version_match:
                raw_version = version_match.group(1)
                version_line = following_index + 1
                break
        if not raw_version:
            continue
        locator = f"line:{version_line}"
        if language in {"node", "python"}:
            add_toolchain_observation(
                builder,
                source_id,
                root_component,
                root_version,
                language=language,
                raw_version=raw_version,
                locator=locator,
                role="github-actions-toolchain",
            )
        else:
            add_cli_observation(
                builder,
                source_id,
                root_component,
                root_version,
                name="terraform",
                raw_version=raw_version,
                locator=locator,
                role="github-actions-toolchain",
                scope="ci",
                resolver="github-actions-setup",
            )

    variables = github_workflow_variables(text)
    for run_start, command_text in yaml_run_blocks(text):
        manifest_install_added = False
        for relative_line, command in shell_logical_commands(command_text):
            actual_line = run_start + relative_line - 1
            locator = f"line:{actual_line}"
            for clause_index, clause in enumerate(shell_clauses(command)):
                clause_locator = f"{locator}:clause:{clause_index}"
                install = shell_install_tokens(clause)
                if install:
                    ecosystem, packages = install
                    for package in packages:
                        add_package_observation(
                            builder,
                            source_id,
                            root_component,
                            root_version,
                            ecosystem=ecosystem,
                            package=package,
                            locator=clause_locator,
                            role=f"github-actions-{ecosystem}-package",
                            scope="ci",
                            resolver="github-actions-run",
                        )
                pip_install = shell_pip_install(clause)
                if pip_install:
                    for package in pip_install[0]:
                        add_package_observation(
                            builder,
                            source_id,
                            root_component,
                            root_version,
                            ecosystem="pypi",
                            package=package,
                            locator=clause_locator,
                            role="github-actions-pip-package",
                            scope="ci",
                            resolver="github-actions-run",
                        )
                npm_packages = shell_npm_install(clause)
                if npm_packages is not None:
                    if npm_packages:
                        for package in npm_packages:
                            add_package_observation(
                                builder,
                                source_id,
                                root_component,
                                root_version,
                                ecosystem="npm",
                                package=package,
                                locator=clause_locator,
                                role="github-actions-npm-package",
                                scope="ci",
                                resolver="github-actions-run",
                            )
                    elif not manifest_install_added:
                        add_workflow_manifest_install(
                            builder,
                            root,
                            source_id,
                            root_component,
                            root_version,
                            working_directory=workflow_working_directory(
                                text, actual_line
                            ),
                            locator=clause_locator,
                        )
                        manifest_install_added = True
                tokens = shell_tokens(clause)
                if len(tokens) >= 4 and tokens[:3] == ["helm", "plugin", "install"]:
                    add_git_clone_observation(
                        builder,
                        source_id,
                        root_component,
                        root_version,
                        repository=tokens[3],
                        ref=None,
                        locator=clause_locator,
                        role="github-actions-helm-plugin",
                        scope="ci",
                        resolver="github-actions-run",
                    )
            if "curl" not in command and "wget" not in command:
                continue
            for url_index, url_match in enumerate(SHELL_URL_RE.finditer(command)):
                raw_url = url_match.group(0).rstrip("\\")
                variable_match = re.search(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", raw_url)
                installed_version = (
                    variables.get(variable_match.group(1)) if variable_match else None
                )
                if installed_version is None:
                    desired = re.search(
                        r"DESIRED_VERSION=['\"]?\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
                        command,
                    )
                    installed_version = (
                        variables.get(desired.group(1)) if desired else None
                    )
                add_remote_input(
                    builder,
                    source_id,
                    root_component,
                    root_version,
                    url=expand_literal_variables(raw_url, variables),
                    locator=f"{locator}:url:{url_index}",
                    role="github-actions-download",
                    scope="ci",
                    resolver="github-actions-run",
                    installed_version=installed_version,
                )


def scan_precommit(
    builder: Builder, root: Path, path: Path, data: bytes, text: str
) -> None:
    source_id = source_for(builder, root, path, data, "pre-commit-config")
    relative = builder.sources[source_id]["evidence_uri"]
    root_component, root_version = add_local_root(
        builder, source_id, relative, "pre-commit-config"
    )
    repo: tuple[int, str] | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        repo_match = re.match(r"^\s*-\s*repo:\s*(\S+)", line)
        if repo_match:
            repo = (line_number, scalar(repo_match.group(1)))
            continue
        rev_match = re.match(r"^\s+rev:\s*(\S+)", line)
        if rev_match and repo:
            repo_line, repository = repo
            rev = scalar(rev_match.group(1))
            component_id = builder.add_component(
                kind="pre-commit-hook-repository",
                ecosystem="pre-commit",
                name=repository.rsplit("/", 1)[-1],
                identity=f"pre-commit:{repository}",
                metadata={"source_repo": repository},
            )
            version_id = builder.add_version(
                component_id,
                resolved_version=rev,
                source_ref=rev,
                evidence=(f"{relative}#L{repo_line}", f"{relative}#L{line_number}"),
            )
            occurrence_id = builder.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=f"lines:{repo_line},{line_number}",
                role="pre-commit-repository",
                raw_value=f"{repository}@{rev}",
                root_id=root_component,
                dependency_scope="development",
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="invokes",
                source_occurrence_id=occurrence_id,
                constraint=rev,
                scope="development",
                resolver="pre-commit",
            )
            repo = None

    hook_id = ""
    language = ""
    additional_indent: int | None = None

    def add_additional_dependency(line_number: int, dependency: str) -> None:
        candidate = scalar(dependency.strip().strip(","))
        if not candidate:
            return
        ecosystem = "npm" if candidate.startswith("@") else "pypi"
        if language.lower() in {"node", "nodejs"}:
            ecosystem = "npm"
        elif language.lower().startswith("python"):
            ecosystem = "pypi"
        add_package_observation(
            builder,
            source_id,
            root_component,
            root_version,
            ecosystem=ecosystem,
            package=candidate,
            locator=f"line:{line_number}:additional-dependency",
            role="pre-commit-additional-dependency",
            scope="development",
            resolver="pre-commit",
            relationship="installs",
            metadata={"hook_id": hook_id, "language": language},
        )

    for line_number, line in enumerate(text.splitlines(), 1):
        indent = len(line) - len(line.lstrip())
        if additional_indent is not None:
            item = re.match(r"^\s*-\s*(\S.*?)\s*$", line)
            if item and indent > additional_indent:
                add_additional_dependency(line_number, item.group(1))
                continue
            if line.strip() and indent <= additional_indent:
                additional_indent = None
        hook_match = re.match(r"^\s*-\s*id:\s*(\S+)", line)
        if hook_match:
            hook_id = scalar(hook_match.group(1))
            language = ""
            continue
        language_match = re.match(r"^\s*language:\s*(\S+)", line)
        if language_match and hook_id:
            language = scalar(language_match.group(1))
            continue
        additional = re.match(r"^\s*additional_dependencies:\s*(.*?)\s*$", line)
        if not additional or not hook_id:
            continue
        value = additional.group(1)
        if not value:
            additional_indent = indent
            continue
        for match in re.finditer(r"['\"]([^'\"]+)['\"]|([^,\[\]\s]+)", value):
            dependency = match.group(1) or match.group(2)
            if dependency:
                add_additional_dependency(line_number, dependency)


def load_json(path: str) -> Any:
    payload, _ = read_json_document(path)
    return payload


def json_walk(value: Any, pointer: str = "") -> Iterator[tuple[str, Any]]:
    yield pointer or "/", value
    if isinstance(value, dict):
        for key in sorted(value):
            yield from json_walk(
                value[key], f"{pointer}/{json_pointer_escape(str(key))}"
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from json_walk(item, f"{pointer}/{index}")


def read_json_document(
    path: str, *, max_bytes: int = MAX_JSON_INPUT_BYTES
) -> tuple[Any, bytes]:
    if max_bytes < 0:
        raise RegistryInputError("JSON input byte budget must not be negative")
    if path == "-":
        raw = sys.stdin.buffer.read(max_bytes + 1)
    else:
        raw = read_regular_file(
            Path(path),
            max_bytes=max_bytes,
            label=f"JSON input {path}",
        )
    return (
        parse_json_bytes(
            raw,
            label=f"JSON input {path}",
            max_bytes=max_bytes,
        ),
        raw,
    )


def preflight_regular_input_paths(
    paths: Sequence[str],
    *,
    max_files: int,
    label: str,
    max_total_bytes: int | None = None,
) -> int:
    """Reject multiplied transports/inodes before the first input byte is read."""

    if len(paths) > max_files:
        raise RegistryInputError(f"{label} exceed file bound {max_files}")
    seen_transports: set[str] = set()
    seen_files: set[tuple[int, int]] = set()
    total_regular_bytes = 0
    for raw_path in paths:
        transport = "stdin" if raw_path == "-" else Path(raw_path).absolute().as_posix()
        if transport in seen_transports:
            raise RegistryInputError(f"{label} repeat an input transport")
        seen_transports.add(transport)
        if raw_path == "-":
            continue
        try:
            metadata = os.lstat(raw_path)
        except OSError as exc:
            raise RegistryInputError(f"cannot inspect {label} path: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RegistryInputError(f"{label} must be regular non-symlink files")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen_files:
            raise RegistryInputError(f"{label} repeat an input file identity")
        seen_files.add(identity)
        total_regular_bytes += metadata.st_size
        if max_total_bytes is not None and total_regular_bytes > max_total_bytes:
            raise RegistryInputError(
                f"{label} exceed aggregate byte bound {max_total_bytes}"
            )
    return total_regular_bytes


def read_bounded_unique_json_inputs(
    paths: Sequence[str],
    *,
    max_files: int,
    max_total_bytes: int,
    label: str,
) -> list[tuple[str, Any, bytes]]:
    known_regular_bytes = preflight_regular_input_paths(
        paths,
        max_files=max_files,
        label=label,
        max_total_bytes=max_total_bytes,
    )
    result: list[tuple[str, Any, bytes]] = []
    seen_hashes: set[str] = set()
    total_bytes = 0
    for path in paths:
        path_budget = (
            max_total_bytes - known_regular_bytes
            if path == "-"
            else max_total_bytes - total_bytes
        )
        payload, raw = read_json_document(
            path,
            max_bytes=min(MAX_JSON_INPUT_BYTES, path_budget),
        )
        total_bytes += len(raw)
        if total_bytes > max_total_bytes:
            raise RegistryInputError(
                f"{label} exceed aggregate byte bound {max_total_bytes}"
            )
        raw_hash = file_hash(raw)
        if raw_hash in seen_hashes:
            raise RegistryInputError(f"{label} repeat an input content hash")
        seen_hashes.add(raw_hash)
        result.append((path, payload, raw))
    return result


def parse_utc_second(value: Any) -> datetime:
    candidate = str(value or "")
    if not CAPTURE_TIMESTAMP_RE.fullmatch(candidate):
        raise ValueError("timestamp is not a canonical UTC second")
    parsed = datetime.fromisoformat(candidate.removesuffix("Z") + "+00:00")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != candidate:
        raise ValueError("timestamp is not a canonical UTC second")
    return parsed


def valid_live_observed_at(value: Any) -> bool:
    try:
        parse_utc_second(value)
    except ValueError:
        return False
    return True


def is_openapi_v3_discovery(payload: Any) -> bool:
    if not isinstance(payload, Mapping) or payload.get("openapi"):
        return False
    paths = payload.get("paths")
    return isinstance(paths, Mapping) and all(
        isinstance(value, Mapping) and isinstance(value.get("serverRelativeURL"), str)
        for value in paths.values()
    )


def is_openapi_v3_document(payload: Any) -> bool:
    if not isinstance(payload, Mapping):
        return False
    version = str(payload.get("openapi") or "")
    components = payload.get("components")
    schemas = components.get("schemas") if isinstance(components, Mapping) else None
    return version.startswith("3.") and isinstance(schemas, Mapping)


def openapi_v3_gvk_count(payload: Any) -> int:
    return len(openapi_v3_gvks(payload))


def openapi_v3_gvks(payload: Any) -> set[tuple[str, str, str]]:
    if not is_openapi_v3_document(payload):
        return set()
    schemas = payload.get("components", {}).get("schemas", {})
    result: set[tuple[str, str, str]] = set()
    for schema in schemas.values():
        if not isinstance(schema, Mapping):
            continue
        gvks = schema.get("x-kubernetes-group-version-kind")
        if not isinstance(gvks, list):
            continue
        for gvk in gvks:
            if isinstance(gvk, Mapping) and gvk.get("version") and gvk.get("kind"):
                result.add(
                    (
                        str(gvk.get("group") or ""),
                        str(gvk["version"]),
                        str(gvk["kind"]),
                    )
                )
    return result


def live_payload_inventory(payload: Any) -> tuple[set[str], set[str], list[str]]:
    """Return recognized surfaces, resource kinds and missing CRD schemas."""

    surfaces: set[str] = set()
    resource_kinds: set[str] = set()
    missing_openapi: list[str] = []
    if not isinstance(payload, Mapping):
        return surfaces, resource_kinds, missing_openapi
    server_version = payload.get("serverVersion")
    if isinstance(server_version, Mapping) and server_version.get("gitVersion"):
        surfaces.add("server-version")
    payload_kind = str(payload.get("kind") or "")
    if payload_kind in {"APIVersions", "APIGroupList", "APIResourceList"}:
        surfaces.add("api-discovery")
        resource_kinds.add(payload_kind)
    if is_openapi_v3_discovery(payload):
        surfaces.add("builtin-openapi")
        resource_kinds.add("OpenAPIv3Discovery")
    elif is_openapi_v3_document(payload):
        surfaces.add("builtin-openapi")
        resource_kinds.add("OpenAPIv3Document")

    items = payload.get("items", [])
    if not isinstance(items, list):
        return surfaces, resource_kinds, missing_openapi
    top_level_kind = str(payload.get("kind") or "").removesuffix("List")
    if top_level_kind and top_level_kind != "List":
        resource_kinds.add(top_level_kind)
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            continue
        kind = str(item.get("kind") or top_level_kind)
        api_version = str(item.get("apiVersion") or payload.get("apiVersion") or "")
        if kind:
            resource_kinds.add(kind)
        if kind == "Node":
            surfaces.add("nodes")
        elif kind in {"Application", "ApplicationSet"}:
            surfaces.add("argo")
        elif kind in LIVE_CONTROLLER_KINDS:
            surfaces.add("controllers")
        elif kind == "Pod":
            surfaces.add("pods")
        elif kind == "CustomResourceDefinition":
            surfaces.add("crds-openapi")
            spec = item.get("spec") if isinstance(item.get("spec"), Mapping) else {}
            versions = spec.get("versions") if isinstance(spec, Mapping) else []
            if not isinstance(versions, list) or not versions:
                missing_openapi.append(f"/items/{index}/spec/versions")
                continue
            for version_index, version in enumerate(versions):
                if not isinstance(version, Mapping):
                    missing_openapi.append(
                        f"/items/{index}/spec/versions/{version_index}"
                    )
                    continue
                schema = version.get("schema")
                openapi = (
                    schema.get("openAPIV3Schema")
                    if isinstance(schema, Mapping)
                    else None
                )
                if not isinstance(openapi, Mapping) or not openapi:
                    missing_openapi.append(
                        f"/items/{index}/spec/versions/{version_index}/schema/openAPIV3Schema"
                    )
        elif kind == "ClusterSbomReport":
            surfaces.add("cluster-sboms")
        elif kind == "SbomReport" or (
            "sbomreports" in api_version.lower() and kind != "ClusterSbomReport"
        ):
            surfaces.add("workload-sboms")
        elif kind == "Namespace":
            surfaces.add("workload-sboms")

    surface_by_list_kind = {
        "Namespace": "workload-sboms",
        "Node": "nodes",
        "Application": "argo",
        "ApplicationSet": "argo",
        "Pod": "pods",
        "CustomResourceDefinition": "crds-openapi",
        "SbomReport": "workload-sboms",
        "ClusterSbomReport": "cluster-sboms",
        **{kind: "controllers" for kind in LIVE_CONTROLLER_KINDS},
    }
    if top_level_kind in surface_by_list_kind:
        # A typed empty List is still proof that the exact resource was queried.
        surfaces.add(surface_by_list_kind[top_level_kind])
    return surfaces, resource_kinds, sorted(set(missing_openapi))


def live_capture_bounds(contract_version: int) -> dict[str, int]:
    """Bounds are sealed per contract, so v3 receipts keep re-validating."""

    return dict(
        LIVE_CAPTURE_BOUNDS if contract_version >= 4 else LIVE_CAPTURE_BOUNDS_V3
    )


def live_surface_resource_kinds(surface: str, contract_version: int) -> tuple[str, ...]:
    table = (
        LIVE_SURFACE_RESOURCE_KINDS
        if contract_version >= 4
        else LIVE_SURFACE_RESOURCE_KINDS_V3
    )
    return table.get(surface, ())


def live_static_artifacts(
    surface: str, contract_version: int
) -> tuple[tuple[str, str], ...]:
    table = LIVE_STATIC_ARTIFACTS if contract_version >= 4 else LIVE_STATIC_ARTIFACTS_V3
    return table.get(surface, ())


def live_surface_is_paged(surface: str, contract_version: int) -> bool:
    return contract_version >= 4 and surface in LIVE_PAGED_SURFACES


def live_surface_has_dynamic_endpoints(surface: str, contract_version: int) -> bool:
    return surface in {"api-discovery", "builtin-openapi"} or live_surface_is_paged(
        surface, contract_version
    )


def sbom_page_endpoint(namespace: str) -> str:
    return LIVE_SBOM_PAGE_ENDPOINT_TEMPLATE.format(namespace=namespace)


def namespace_index_names(payload: Any) -> tuple[list[str], list[str]]:
    """Return the sorted namespace names a v4 paging root advertises."""

    errors: list[str] = []
    if (
        not isinstance(payload, Mapping)
        or payload.get("kind") != "NamespaceList"
        or payload.get("apiVersion") != "v1"
        or not isinstance(payload.get("items"), list)
    ):
        return [], ["namespace paging root is not a typed NamespaceList"]
    names: set[str] = set()
    for index, item in enumerate(payload["items"]):
        metadata = item.get("metadata") if isinstance(item, Mapping) else None
        name = str(metadata.get("name") or "") if isinstance(metadata, Mapping) else ""
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", name):
            errors.append(f"namespace paging root item {index} has an invalid name")
            continue
        if name in names:
            errors.append(f"namespace paging root repeats namespace {name}")
            continue
        names.add(name)
    if not names and not errors:
        errors.append("namespace paging root advertises no namespaces")
    return sorted(names), errors


def live_inventory_truncation(payload: Any) -> str | None:
    if not isinstance(payload, Mapping) or not str(payload.get("kind") or "").endswith(
        "List"
    ):
        return None
    metadata = payload.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    continuation = metadata.get("continue")
    remaining = metadata.get("remainingItemCount")
    if continuation not in {None, ""}:
        return "Kubernetes List metadata.continue is non-empty"
    if remaining not in {None, 0}:
        return "Kubernetes List metadata.remainingItemCount is non-zero"
    return None


def expected_api_discovery_endpoints(
    api_versions: Any, api_groups: Any
) -> tuple[dict[str, str], list[str]]:
    endpoints: dict[str, str] = {"/api": "APIVersions", "/apis": "APIGroupList"}
    errors: list[str] = []
    if (
        not isinstance(api_versions, Mapping)
        or api_versions.get("kind") != "APIVersions"
    ):
        errors.append("/api is not a typed APIVersions document")
    else:
        versions = api_versions.get("versions")
        if not isinstance(versions, list) or not versions:
            errors.append("/api has no versions")
        else:
            for value in versions:
                version = str(value or "")
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", version):
                    errors.append("/api contains an invalid version")
                    continue
                endpoints[f"/api/{version}"] = version
    if not isinstance(api_groups, Mapping) or api_groups.get("kind") != "APIGroupList":
        errors.append("/apis is not a typed APIGroupList document")
    else:
        groups = api_groups.get("groups")
        if not isinstance(groups, list):
            errors.append("/apis has no groups array")
        else:
            for group in groups:
                if not isinstance(group, Mapping):
                    errors.append("/apis contains a non-object group")
                    continue
                group_name = str(group.get("name") or "")
                versions = group.get("versions")
                if not group_name or not isinstance(versions, list) or not versions:
                    errors.append("/apis contains a group without versions")
                    continue
                for version_record in versions:
                    if not isinstance(version_record, Mapping):
                        errors.append(
                            f"/apis group {group_name} contains a non-object version"
                        )
                        continue
                    version = str(version_record.get("version") or "")
                    group_version = str(version_record.get("groupVersion") or "")
                    if group_version != f"{group_name}/{version}" or not version:
                        errors.append(
                            f"/apis group {group_name} contains an invalid groupVersion"
                        )
                        continue
                    endpoints[f"/apis/{group_name}/{version}"] = group_version
    return endpoints, errors


def expected_openapi_endpoints(index: Any) -> tuple[dict[str, str], list[str]]:
    endpoints = {"/openapi/v3": "OpenAPIv3Discovery"}
    errors: list[str] = []
    if not is_openapi_v3_discovery(index):
        return endpoints, ["/openapi/v3 is not an OpenAPI v3 discovery document"]
    paths = index.get("paths")
    if not isinstance(paths, Mapping) or not paths:
        return endpoints, ["/openapi/v3 has no advertised paths"]
    for key, record in paths.items():
        if not isinstance(key, str) or not (
            re.fullmatch(r"api/[^/]+", key) or re.fullmatch(r"apis/[^/]+/[^/]+", key)
        ):
            continue
        endpoint = (
            str(record.get("serverRelativeURL") or "")
            if isinstance(record, Mapping)
            else ""
        )
        parsed = urlparse(endpoint)
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not parsed.path.startswith("/openapi/v3/")
            or ".." in parsed.path.split("/")
            or len(endpoint) > 4096
        ):
            errors.append(f"/openapi/v3 contains an invalid path entry {key!r}")
            continue
        expected_path = f"/openapi/v3/{key}"
        if parsed.path != expected_path:
            errors.append("/openapi/v3 path key does not match serverRelativeURL")
            continue
        group_version = key.removeprefix("api/").removeprefix("apis/")
        endpoints[endpoint] = group_version
    if len(endpoints) == 1:
        errors.append("/openapi/v3 advertises no API group versions")
    return endpoints, errors


def validate_live_sbom_pages(
    capture: Mapping[str, Any],
    documents_by_raw_hash: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[tuple[str, str]]:
    """Close v4 namespace pages against the namespace index that rooted them."""

    surface = "workload-sboms"
    errors: list[tuple[str, str]] = []
    contract_version = capture.get("contract_version")
    if not isinstance(contract_version, int) or contract_version < 4:
        return errors
    record: Any = next(
        (
            item
            for item in capture.get("surfaces", [])
            if isinstance(item, Mapping) and item.get("surface") == surface
        ),
        {},
    )
    if record.get("state") != "captured":
        return errors
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append((surface, f"Captured {surface} has no endpoint artifacts"))
        return errors
    endpoint_payloads: dict[str, Any] = {}
    duplicate_endpoints: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            continue
        endpoint = str(artifact.get("endpoint") or "")
        documents = documents_by_raw_hash.get(str(artifact.get("raw_hash") or ""), ())
        if not endpoint or not documents:
            continue
        if endpoint in endpoint_payloads:
            duplicate_endpoints.add(endpoint)
            continue
        endpoint_payloads[endpoint] = documents[0].get("payload")
    if duplicate_endpoints:
        errors.append(
            (
                surface,
                f"Captured {surface} repeats endpoints: "
                + ", ".join(sorted(duplicate_endpoints)),
            )
        )
    if LIVE_NAMESPACE_INDEX_ENDPOINT not in endpoint_payloads:
        errors.append(
            (
                surface,
                f"Captured {surface} omits its namespace paging root "
                f"{LIVE_NAMESPACE_INDEX_ENDPOINT}",
            )
        )
        return errors
    names, name_errors = namespace_index_names(
        endpoint_payloads[LIVE_NAMESPACE_INDEX_ENDPOINT]
    )
    errors.extend((surface, message) for message in name_errors)
    expected = {sbom_page_endpoint(name) for name in names}
    actual = set(endpoint_payloads) - {LIVE_NAMESPACE_INDEX_ENDPOINT}
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        errors.append(
            (
                surface,
                f"Captured {surface} omits namespace pages: " + ", ".join(missing),
            )
        )
    if unexpected:
        errors.append(
            (
                surface,
                f"Captured {surface} contains unadvertised namespace pages: "
                + ", ".join(unexpected),
            )
        )
    for endpoint in sorted(expected & actual):
        payload = endpoint_payloads[endpoint]
        match = LIVE_SBOM_PAGE_ENDPOINT_RE.fullmatch(endpoint)
        if (
            match is None
            or not isinstance(payload, Mapping)
            or payload.get("kind") != "SbomReportList"
            or payload.get("apiVersion") != "aquasecurity.github.io/v1alpha1"
            or not isinstance(payload.get("items"), list)
        ):
            errors.append(
                (surface, f"{endpoint} is not the expected typed SbomReportList")
            )
            continue
        page_namespaces: set[str] = set()
        for item in payload["items"]:
            metadata = item.get("metadata") if isinstance(item, Mapping) else None
            page_namespaces.add(
                str(metadata.get("namespace") or "")
                if isinstance(metadata, Mapping)
                else ""
            )
        stray = sorted(page_namespaces - {match.group("namespace")})
        if stray:
            errors.append(
                (
                    surface,
                    f"{endpoint} contains reports outside its namespace: "
                    + ", ".join(stray),
                )
            )
    return errors


def validate_live_api_artifacts(
    capture: Mapping[str, Any],
    documents_by_raw_hash: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[tuple[str, str]]:
    """Cross-check captured endpoint sets against their bound discovery roots."""

    errors: list[tuple[str, str]] = validate_live_sbom_pages(
        capture, documents_by_raw_hash
    )
    records = {
        str(item.get("surface") or ""): item
        for item in capture.get("surfaces", [])
        if isinstance(item, Mapping)
    }
    captured_endpoint_sets: dict[str, set[str]] = {}
    for surface in ("api-discovery", "builtin-openapi"):
        record = records.get(surface, {})
        if record.get("state") != "captured":
            continue
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            errors.append((surface, f"Captured {surface} has no endpoint artifacts"))
            continue
        endpoint_payloads: dict[str, Any] = {}
        endpoint_document_types: dict[str, str] = {}
        duplicate_endpoints: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                continue
            endpoint = str(artifact.get("endpoint") or "")
            raw_hash = str(artifact.get("raw_hash") or "")
            documents = documents_by_raw_hash.get(raw_hash, ())
            if not endpoint or not documents:
                continue
            if endpoint in endpoint_payloads:
                duplicate_endpoints.add(endpoint)
                continue
            endpoint_payloads[endpoint] = documents[0].get("payload")
            endpoint_document_types[endpoint] = str(artifact.get("document_type") or "")
        if duplicate_endpoints:
            errors.append(
                (
                    surface,
                    f"Captured {surface} repeats endpoints: "
                    + ", ".join(sorted(duplicate_endpoints)),
                )
            )
        actual = set(endpoint_payloads)
        captured_endpoint_sets[surface] = actual
        if surface == "api-discovery":
            expected, discovery_errors = expected_api_discovery_endpoints(
                endpoint_payloads.get("/api"), endpoint_payloads.get("/apis")
            )
            for message in discovery_errors:
                errors.append((surface, message))
            missing = sorted(set(expected) - actual)
            unexpected = sorted(actual - set(expected))
            for endpoint, group_version in expected.items():
                expected_document_type = (
                    group_version
                    if endpoint in {"/api", "/apis"}
                    else "APIResourceList"
                )
                if (
                    endpoint in endpoint_document_types
                    and endpoint_document_types[endpoint] != expected_document_type
                ):
                    errors.append(
                        (
                            surface,
                            f"{endpoint} declares document type {endpoint_document_types[endpoint]!r}, expected {expected_document_type}",
                        )
                    )
                if endpoint in {"/api", "/apis"} or endpoint not in endpoint_payloads:
                    continue
                payload = endpoint_payloads[endpoint]
                if (
                    not isinstance(payload, Mapping)
                    or payload.get("kind") != "APIResourceList"
                    or payload.get("groupVersion") != group_version
                    or not isinstance(payload.get("resources"), list)
                ):
                    errors.append(
                        (
                            surface,
                            f"{endpoint} is not the expected typed APIResourceList for {group_version}",
                        )
                    )
        else:
            expected, discovery_errors = expected_openapi_endpoints(
                endpoint_payloads.get("/openapi/v3")
            )
            for message in discovery_errors:
                errors.append((surface, message))
            missing = sorted(set(expected) - actual)
            unexpected = sorted(actual - set(expected))
            for endpoint in sorted(set(expected) - {"/openapi/v3"}):
                if endpoint not in endpoint_payloads:
                    continue
                if not is_openapi_v3_document(endpoint_payloads[endpoint]):
                    errors.append(
                        (surface, f"{endpoint} is not an OpenAPI v3 schema document")
                    )
                elif not openapi_v3_gvk_count(endpoint_payloads[endpoint]):
                    errors.append(
                        (
                            surface,
                            f"{endpoint} has no Kubernetes GVK schema bindings",
                        )
                    )
                else:
                    expected_group_version = expected[endpoint]
                    if "/" in expected_group_version:
                        expected_group, expected_version = (
                            expected_group_version.rsplit("/", 1)
                        )
                    else:
                        expected_group, expected_version = "", expected_group_version
                    if not any(
                        group == expected_group and version == expected_version
                        for group, version, _kind in openapi_v3_gvks(
                            endpoint_payloads[endpoint]
                        )
                    ):
                        errors.append(
                            (
                                surface,
                                f"{endpoint} has no matching Kubernetes GVK binding",
                            )
                        )
                if endpoint_document_types.get(endpoint) != "OpenAPIv3Document":
                    errors.append(
                        (
                            surface,
                            f"{endpoint} does not declare document type OpenAPIv3Document",
                        )
                    )
            if endpoint_document_types.get("/openapi/v3") != "OpenAPIv3Discovery":
                errors.append(
                    (
                        surface,
                        "/openapi/v3 does not declare document type OpenAPIv3Discovery",
                    )
                )
        if missing:
            errors.append(
                (
                    surface,
                    f"Captured {surface} omits advertised endpoints: "
                    + ", ".join(missing),
                )
            )
        if unexpected:
            errors.append(
                (
                    surface,
                    f"Captured {surface} contains unadvertised endpoints: "
                    + ", ".join(unexpected),
                )
            )
    if all(
        records.get(surface, {}).get("state") == "captured"
        for surface in ("api-discovery", "builtin-openapi")
    ):
        api_group_versions = captured_endpoint_sets.get("api-discovery", set()) - {
            "/api",
            "/apis",
        }
        openapi_group_versions = {
            urlparse(endpoint).path.removeprefix("/openapi/v3")
            for endpoint in captured_endpoint_sets.get("builtin-openapi", set())
            if endpoint != "/openapi/v3"
        }
        missing_openapi = sorted(api_group_versions - openapi_group_versions)
        unserved_openapi = sorted(openapi_group_versions - api_group_versions)
        if missing_openapi:
            errors.append(
                (
                    "builtin-openapi",
                    "OpenAPI v3 evidence omits served API group versions: "
                    + ", ".join(missing_openapi),
                )
            )
        if unserved_openapi:
            errors.append(
                (
                    "builtin-openapi",
                    "OpenAPI v3 evidence contains unserved API group versions: "
                    + ", ".join(unserved_openapi),
                )
            )
    return errors


def normalize_live_capture_manifest(
    payload: Any, *, content_hash: str, raw_hash: str
) -> tuple[dict[str, Any], list[tuple[str, str, str | None]]]:
    errors: list[tuple[str, str, str | None]] = []
    value = payload if isinstance(payload, Mapping) else {}
    if not isinstance(payload, Mapping):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "Live capture manifest is not a JSON object",
                None,
            )
        )
    if value.get("record_kind") != LIVE_CAPTURE_RECORD_KIND:
        errors.append(
            (
                "live-capture-metadata-invalid",
                f"record_kind must equal {LIVE_CAPTURE_RECORD_KIND}",
                None,
            )
        )
    source_contract_version = value.get("contract_version")
    if source_contract_version not in LIVE_CAPTURE_SUPPORTED_CONTRACT_VERSIONS:
        errors.append(
            (
                "live-capture-metadata-invalid",
                "contract_version must be one of "
                + ", ".join(
                    str(item)
                    for item in sorted(LIVE_CAPTURE_SUPPORTED_CONTRACT_VERSIONS)
                ),
                None,
            )
        )
        source_contract_version = LIVE_CAPTURE_CONTRACT_VERSION

    normalized_bounds: dict[str, int] | None = None
    if source_contract_version >= 3:
        required_top_level = {
            "record_kind",
            "contract_version",
            "observed_at",
            "git_commit",
            "cluster_uid",
            "context",
            "required_surfaces",
            "projection",
            "kubectl",
            "capture_generator",
            "capture_window",
            "kubeconfig",
            "bounds",
            "surfaces",
        }
        allowed_top_level = {*required_top_level, "server_fingerprint"}
        if not required_top_level.issubset(value) or not set(value).issubset(
            allowed_top_level
        ):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    "v3 capture manifest has missing or unsupported top-level fields",
                    None,
                )
            )
        contract_bounds = live_capture_bounds(source_contract_version)
        declared_bounds = value.get("bounds")
        if (
            not isinstance(declared_bounds, Mapping)
            or set(declared_bounds) != set(contract_bounds)
            or any(
                not isinstance(declared_bounds.get(key), int)
                or isinstance(declared_bounds.get(key), bool)
                or declared_bounds.get(key) != maximum
                for key, maximum in contract_bounds.items()
            )
        ):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    "v3 capture bounds do not match the compiled read-only contract",
                    None,
                )
            )
        else:
            normalized_bounds = dict(contract_bounds)

    observed_at = str(value.get("observed_at") or "")
    git_commit = str(value.get("git_commit") or "").lower()
    cluster_uid = str(value.get("cluster_uid") or "")
    context = str(value.get("context") or "")
    server_fingerprint = str(value.get("server_fingerprint") or "")
    capture_tool = (
        value.get("kubectl")
        if source_contract_version >= 3
        else value.get("capture_tool")
    )
    capture_generator = value.get("capture_generator")
    capture_window = value.get("capture_window")
    kubeconfig = value.get("kubeconfig")
    projection = value.get("projection")
    if not valid_live_observed_at(observed_at):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "observed_at must be an exact UTC second",
                None,
            )
        )
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", git_commit):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "git_commit must be an exact 40- or 64-hex Git object ID",
                None,
            )
        )
    if not cluster_uid or len(cluster_uid) > 256:
        errors.append(
            (
                "live-capture-metadata-invalid",
                "cluster_uid must be a non-empty bounded Kubernetes UID",
                None,
            )
        )
    if not context and not server_fingerprint:
        errors.append(
            (
                "live-capture-metadata-invalid",
                "context or server_fingerprint is required",
                None,
            )
        )
    if server_fingerprint and not FULL_SHA256_RE.fullmatch(server_fingerprint):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "server_fingerprint must be a full sha256",
                None,
            )
        )
    normalized_capture_tool: dict[str, Any] | None = None
    if not isinstance(capture_tool, Mapping):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "capture_tool must bind the exact read-only kubectl executable",
                None,
            )
        )
    else:
        tool_path = str(capture_tool.get("path") or "")
        tool_hash = str(capture_tool.get("sha256") or "")
        tool_size = capture_tool.get("size")
        if (
            (
                source_contract_version >= 3
                and set(capture_tool) != {"path", "sha256", "size"}
            )
            or not tool_path.startswith("/")
            or not FULL_SHA256_RE.fullmatch(tool_hash)
            or not isinstance(tool_size, int)
            or isinstance(tool_size, bool)
            or tool_size <= 0
            or tool_size > MAX_EXECUTABLE_BYTES
        ):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    "capture_tool path, sha256, or size is invalid",
                    None,
                )
            )
        else:
            normalized_capture_tool = {
                "path": tool_path,
                "sha256": tool_hash,
                "size": tool_size,
            }
    normalized_capture_generator: dict[str, Any] | None = None
    if source_contract_version >= 3:
        valid_generator = isinstance(capture_generator, Mapping) and set(
            capture_generator
        ) == {"git_commit", "sources", "ruleset_hash"}
        generator_sources = (
            capture_generator.get("sources", [])
            if isinstance(capture_generator, Mapping)
            else []
        )
        normalized_sources: list[dict[str, Any]] = []
        if not isinstance(generator_sources, list):
            valid_generator = False
            generator_sources = []
        for index, source in enumerate(generator_sources):
            expected_path = (
                LIVE_CAPTURE_GENERATOR_PATHS[index]
                if index < len(LIVE_CAPTURE_GENERATOR_PATHS)
                else ""
            )
            if (
                not isinstance(source, Mapping)
                or set(source) != {"path", "sha256", "size"}
                or source.get("path") != expected_path
                or not FULL_SHA256_RE.fullmatch(str(source.get("sha256") or ""))
                or not isinstance(source.get("size"), int)
                or isinstance(source.get("size"), bool)
                or not 0 < int(source.get("size") or 0) <= MAX_DISCOVERY_FILE_BYTES
            ):
                valid_generator = False
                continue
            normalized_sources.append(dict(source))
        if (
            len(generator_sources) != len(LIVE_CAPTURE_GENERATOR_PATHS)
            or len(normalized_sources) != len(LIVE_CAPTURE_GENERATOR_PATHS)
            or not isinstance(capture_generator, Mapping)
            or capture_generator.get("git_commit") != git_commit
            or not FULL_SHA256_RE.fullmatch(
                str(capture_generator.get("ruleset_hash") or "")
            )
        ):
            valid_generator = False
        if valid_generator:
            normalized_capture_generator = {
                "git_commit": git_commit,
                "sources": normalized_sources,
                "ruleset_hash": str(capture_generator["ruleset_hash"]),
            }
        else:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    "capture_generator does not bind the exact committed redaction sources",
                    None,
                )
            )

    normalized_capture_window: dict[str, Any] | None = None
    if source_contract_version >= 3:
        valid_window = isinstance(capture_window, Mapping) and set(capture_window) == {
            "started_at",
            "completed_at",
            "observation_tolerance_seconds",
        }
        started_at = (
            str(capture_window.get("started_at") or "")
            if isinstance(capture_window, Mapping)
            else ""
        )
        completed_at = (
            str(capture_window.get("completed_at") or "")
            if isinstance(capture_window, Mapping)
            else ""
        )
        tolerance = (
            capture_window.get("observation_tolerance_seconds")
            if isinstance(capture_window, Mapping)
            else None
        )
        if (
            not valid_live_observed_at(started_at)
            or not valid_live_observed_at(completed_at)
            or not valid_live_observed_at(observed_at)
            or tolerance != LIVE_CAPTURE_TIME_TOLERANCE_SECONDS
        ):
            valid_window = False
        else:
            started_time = parse_utc_second(started_at)
            completed_time = parse_utc_second(completed_at)
            observed_time = parse_utc_second(observed_at)
            valid_window = bool(
                completed_time >= started_time
                and started_time.timestamp() - LIVE_CAPTURE_TIME_TOLERANCE_SECONDS
                <= observed_time.timestamp()
                <= completed_time.timestamp() + LIVE_CAPTURE_TIME_TOLERANCE_SECONDS
            )
        if valid_window:
            normalized_capture_window = {
                "started_at": started_at,
                "completed_at": completed_at,
                "observation_tolerance_seconds": LIVE_CAPTURE_TIME_TOLERANCE_SECONDS,
            }
        else:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    "capture_window or observation timestamp is invalid",
                    None,
                )
            )
    normalized_kubeconfig: dict[str, Any] | None = None
    if source_contract_version >= 2 and not isinstance(kubeconfig, Mapping):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "kubeconfig must bind the exact non-executable capture configuration",
                None,
            )
        )
    elif isinstance(kubeconfig, Mapping):
        if source_contract_version >= 3:
            source = kubeconfig.get("source")
            execution = kubeconfig.get("execution_snapshot")
            valid = (
                set(kubeconfig) == {"source", "execution_snapshot"}
                and isinstance(source, Mapping)
                and set(source) == {"path", "sha256", "size", "device", "inode"}
                and str(source.get("path") or "").startswith("/")
                and FULL_SHA256_RE.fullmatch(str(source.get("sha256") or ""))
                and isinstance(source.get("size"), int)
                and not isinstance(source.get("size"), bool)
                and 0 < int(source.get("size") or 0) <= MAX_JSON_INPUT_BYTES
                and isinstance(source.get("device"), int)
                and not isinstance(source.get("device"), bool)
                and int(source.get("device") or -1) >= 0
                and isinstance(source.get("inode"), int)
                and not isinstance(source.get("inode"), bool)
                and int(source.get("inode") or 0) > 0
                and isinstance(execution, Mapping)
                and set(execution) == {"policy", "sha256", "size"}
                and execution.get("policy") == "sealed-memfd"
                and execution.get("sha256") == source.get("sha256")
                and execution.get("size") == source.get("size")
            )
            if valid:
                normalized_kubeconfig = {
                    "source": dict(source),
                    "execution_snapshot": dict(execution),
                }
            else:
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        "kubeconfig source or sealed execution snapshot is invalid",
                        None,
                    )
                )
        else:
            config_path = str(kubeconfig.get("path") or "")
            config_hash = str(kubeconfig.get("sha256") or "")
            config_size = kubeconfig.get("size")
            if (
                set(kubeconfig) != {"path", "sha256", "size"}
                or not config_path.startswith("/")
                or not FULL_SHA256_RE.fullmatch(config_hash)
                or not isinstance(config_size, int)
                or isinstance(config_size, bool)
                or config_size <= 0
                or config_size > MAX_JSON_INPUT_BYTES
            ):
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        "kubeconfig path, sha256, or size is invalid",
                        None,
                    )
                )
            else:
                normalized_kubeconfig = {
                    "path": config_path,
                    "sha256": config_hash,
                    "size": config_size,
                }
    normalized_projection: dict[str, Any] | None = None
    if source_contract_version >= 3:
        if projection != LIVE_CAPTURE_PROJECTION:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    "projection must declare the fixed sensitive-field omission policy",
                    None,
                )
            )
        else:
            normalized_projection = dict(LIVE_CAPTURE_PROJECTION)

    declared_required = value.get("required_surfaces")
    required_values = (
        sorted({str(item) for item in declared_required})
        if isinstance(declared_required, list)
        else []
    )
    source_required_surfaces = (
        LIVE_CAPTURE_V1_SURFACES
        if source_contract_version == 1
        else LIVE_REQUIRED_SURFACES
    )
    if source_contract_version >= 3 and declared_required != list(
        source_required_surfaces
    ):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "required_surfaces must be the canonical fixed ordered list",
                None,
            )
        )
    omitted_required = sorted(set(source_required_surfaces) - set(required_values))
    if omitted_required:
        errors.append(
            (
                "live-capture-metadata-invalid",
                "required_surfaces omits surfaces required by its contract: "
                + ", ".join(omitted_required),
                None,
            )
        )
    unknown_required = sorted(set(required_values) - set(source_required_surfaces))
    if unknown_required:
        errors.append(
            (
                "live-capture-metadata-invalid",
                "required_surfaces contains surfaces unsupported by its contract: "
                + ", ".join(unknown_required),
                None,
            )
        )

    declared_surfaces = value.get("surfaces")
    if not isinstance(declared_surfaces, Mapping):
        declared_surfaces = {}
        errors.append(
            (
                "live-capture-metadata-invalid",
                "surfaces must be an object keyed by the fixed P0.1 surface names",
                None,
            )
        )
    unknown_surfaces = sorted(
        str(item) for item in set(declared_surfaces) - set(source_required_surfaces)
    )
    if source_contract_version >= 3 and set(declared_surfaces) != set(
        source_required_surfaces
    ):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "v3 surfaces must contain exactly the fixed surface set",
                None,
            )
        )
    if unknown_surfaces:
        errors.append(
            (
                "live-capture-metadata-invalid",
                "surfaces contains unsupported keys: " + ", ".join(unknown_surfaces),
                None,
            )
        )
    surface_records: list[dict[str, Any]] = []
    total_declared_raw_hashes = 0
    total_declared_artifacts = 0
    for surface in LIVE_REQUIRED_SURFACES:
        declared = declared_surfaces.get(surface)
        if not isinstance(declared, Mapping):
            surface_records.append(
                {
                    "surface": surface,
                    "state": "missing",
                    "raw_hashes": [],
                    "resource_kinds": [],
                }
            )
            continue
        state = str(declared.get("state") or "")
        if state not in LIVE_SURFACE_STATES:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} has unsupported state {state!r}",
                    surface,
                )
            )
            state = "missing"
        if source_contract_version >= 3:
            expected_surface_keys = {
                "state",
                "raw_hashes",
                "resource_kinds",
                "artifacts",
            }
            if state != "captured":
                expected_surface_keys.add("error")
            if set(declared) != expected_surface_keys:
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} has missing or unsupported fields",
                        surface,
                    )
                )
        declared_raw_hashes = declared.get("raw_hashes")
        if source_contract_version >= 3 and (
            not isinstance(declared_raw_hashes, list)
            or any(not isinstance(item, str) for item in declared_raw_hashes)
            or declared_raw_hashes != sorted(set(declared_raw_hashes))
        ):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} raw_hashes is not a canonical string set",
                    surface,
                )
            )
        raw_hashes = (
            sorted({str(item) for item in declared_raw_hashes})
            if isinstance(declared_raw_hashes, list)
            else []
        )
        surface_artifact_bound = len(
            live_static_artifacts(surface, source_contract_version)
        ) + (
            LIVE_CAPTURE_BOUNDS["dynamic_queries"]
            if live_surface_has_dynamic_endpoints(surface, source_contract_version)
            else 0
        )
        if source_contract_version >= 3 and len(raw_hashes) > surface_artifact_bound:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} raw_hashes exceeds compiled command coverage",
                    surface,
                )
            )
        total_declared_raw_hashes += len(raw_hashes)
        invalid_hashes = [
            item for item in raw_hashes if not FULL_SHA256_RE.fullmatch(item)
        ]
        if invalid_hashes:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} contains invalid raw sha256 hashes",
                    surface,
                )
            )
        contract_resource_kinds = live_surface_resource_kinds(
            surface, source_contract_version
        )
        declared_resource_kinds = declared.get("resource_kinds")
        if source_contract_version >= 3 and declared_resource_kinds != list(
            contract_resource_kinds
        ):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} resource_kinds is not the fixed ordered set",
                    surface,
                )
            )
        resource_kinds = (
            sorted({str(item) for item in declared.get("resource_kinds", [])})
            if isinstance(declared.get("resource_kinds"), list)
            else []
        )
        missing_kinds = sorted(set(contract_resource_kinds) - set(resource_kinds))
        if state == "captured" and missing_kinds:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} does not declare queried resource kinds: "
                    + ", ".join(missing_kinds),
                    surface,
                )
            )
        if state == "captured" and not raw_hashes:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Captured surface {surface} has no raw_hashes",
                    surface,
                )
            )
        artifacts: list[dict[str, str]] = []
        declared_artifacts = declared.get("artifacts", [])
        if not isinstance(declared_artifacts, list):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} artifacts must be an array",
                    surface,
                )
            )
            declared_artifacts = []
        if (
            source_contract_version >= 3
            and len(declared_artifacts) > surface_artifact_bound
        ):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} artifacts exceeds compiled command coverage",
                    surface,
                )
            )
        total_declared_artifacts += len(declared_artifacts)
        seen_artifacts: set[tuple[str, str, str]] = set()
        for artifact_index, artifact in enumerate(declared_artifacts):
            if not isinstance(artifact, Mapping):
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact {artifact_index} must be an object",
                        surface,
                    )
                )
                continue
            if source_contract_version >= 3 and set(artifact) != {
                "endpoint",
                "raw_hash",
                "document_type",
            }:
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact {artifact_index} has unsupported fields",
                        surface,
                    )
                )
                continue
            endpoint = str(artifact.get("endpoint") or "")
            artifact_hash = str(artifact.get("raw_hash") or "")
            document_type = str(artifact.get("document_type") or "")
            if (
                not endpoint.startswith("/")
                or len(endpoint) > 4096
                or "\n" in endpoint
                or "\r" in endpoint
            ):
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact {artifact_index} endpoint is invalid",
                        surface,
                    )
                )
                continue
            if validate_reviewed_uri_safety({"evidence_uri": endpoint}):
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact {artifact_index} endpoint is unsafe",
                        surface,
                    )
                )
                continue
            if not FULL_SHA256_RE.fullmatch(artifact_hash):
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact {artifact_index} raw_hash is invalid",
                        surface,
                    )
                )
                continue
            if artifact_hash not in raw_hashes:
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact {artifact_index} is not listed in raw_hashes",
                        surface,
                    )
                )
                continue
            if not document_type or len(document_type) > 128:
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact {artifact_index} document_type is invalid",
                        surface,
                    )
                )
                continue
            artifact_key = (endpoint, artifact_hash, document_type)
            if artifact_key in seen_artifacts:
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} contains a duplicate artifact",
                        surface,
                    )
                )
                continue
            seen_artifacts.add(artifact_key)
            artifacts.append(
                {
                    "endpoint": endpoint,
                    "raw_hash": artifact_hash,
                    "document_type": document_type,
                }
            )
        artifacts.sort(key=canonical_json)
        if source_contract_version >= 3 and declared_artifacts != artifacts:
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} artifacts is not canonical",
                    surface,
                )
            )
        if source_contract_version >= 3:
            artifact_hashes = {artifact["raw_hash"] for artifact in artifacts}
            if artifact_hashes != set(raw_hashes):
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} artifact hashes do not close raw_hashes",
                        surface,
                    )
                )
            artifact_pairs = {
                (artifact["endpoint"], artifact["document_type"])
                for artifact in artifacts
            }
            static_pairs = set(live_static_artifacts(surface, source_contract_version))
            if live_surface_is_paged(surface, source_contract_version):
                unsupported_pairs = {
                    pair
                    for pair in artifact_pairs - static_pairs
                    if pair[1] != "SbomReport"
                    or not LIVE_SBOM_PAGE_ENDPOINT_RE.fullmatch(pair[0])
                }
                if unsupported_pairs:
                    errors.append(
                        (
                            "live-capture-metadata-invalid",
                            f"Surface {surface} has an unsupported endpoint/document_type pair",
                            surface,
                        )
                    )
            elif surface not in {"api-discovery", "builtin-openapi"}:
                if not artifact_pairs.issubset(static_pairs):
                    errors.append(
                        (
                            "live-capture-metadata-invalid",
                            f"Surface {surface} has an unsupported endpoint/document_type pair",
                            surface,
                        )
                    )
            if state == "captured" and not static_pairs.issubset(artifact_pairs):
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Captured surface {surface} omits fixed endpoint/document_type coverage",
                        surface,
                    )
                )
        if (
            source_contract_version >= 2
            and state == "captured"
            and surface in {"api-discovery", "builtin-openapi"}
            and not artifacts
        ):
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Captured surface {surface} has no endpoint-bound artifacts",
                    surface,
                )
            )
        record: dict[str, Any] = {
            "surface": surface,
            "state": state,
            "raw_hashes": raw_hashes,
            "resource_kinds": resource_kinds,
        }
        if artifacts:
            record["artifacts"] = artifacts
        if declared.get("error"):
            error_message = str(declared["error"])
            if (
                source_contract_version >= 3
                and (
                    len(error_message) > 512
                    or not re.fullmatch(
                        r"[a-z0-9._-]+(?:: [a-z0-9._-]+)?(?:; [a-z0-9._-]+(?:: [a-z0-9._-]+)?)*",
                        error_message,
                    )
                )
            ) or len(error_message) > 64 * 2**10:
                errors.append(
                    (
                        "live-capture-metadata-invalid",
                        f"Surface {surface} error exceeds byte bound",
                        surface,
                    )
                )
            record["error"] = error_message
        elif source_contract_version >= 3 and state != "captured":
            errors.append(
                (
                    "live-capture-metadata-invalid",
                    f"Surface {surface} non-captured state requires a fixed safe error code",
                    surface,
                )
            )
        surface_records.append(record)

    maximum_artifacts = (
        live_capture_bounds(source_contract_version)["capture_commands"] - 2
    )
    if source_contract_version >= 3 and (
        total_declared_raw_hashes > maximum_artifacts
        or total_declared_artifacts > maximum_artifacts
    ):
        errors.append(
            (
                "live-capture-metadata-invalid",
                "v3 receipt evidence cardinality exceeds compiled command bounds",
                None,
            )
        )

    normalized: dict[str, Any] = {
        "record_kind": LIVE_CAPTURE_RECORD_KIND,
        "contract_version": source_contract_version,
        "capture_manifest_content_hash": content_hash,
        "capture_manifest_raw_hash": raw_hash,
        "git_commit": git_commit,
        "observed_at": observed_at,
        "cluster_uid": cluster_uid,
        "required_surfaces": list(LIVE_REQUIRED_SURFACES),
        "surfaces": surface_records,
    }
    if normalized_capture_tool:
        normalized["kubectl" if source_contract_version >= 3 else "capture_tool"] = (
            normalized_capture_tool
        )
    if normalized_capture_generator:
        normalized["capture_generator"] = normalized_capture_generator
    if normalized_capture_window:
        normalized["capture_window"] = normalized_capture_window
    if normalized_kubeconfig:
        normalized["kubeconfig"] = normalized_kubeconfig
    if normalized_projection:
        normalized["projection"] = normalized_projection
    if normalized_bounds:
        normalized["bounds"] = normalized_bounds
    if context:
        normalized["context"] = context
    if server_fingerprint:
        normalized["server_fingerprint"] = server_fingerprint
    normalized["capture_id"] = stable_id("cap", normalized)
    return normalized, errors


def load_live_capture_manifest(
    capture_manifest: str | Mapping[str, Any] | None,
) -> tuple[dict[str, Any] | None, list[tuple[str, str, str | None]]]:
    if capture_manifest is None:
        return None, []
    if isinstance(capture_manifest, str):
        payload, raw = read_json_document(capture_manifest)
    else:
        payload = capture_manifest
        raw = canonical_json(payload).encode("utf-8")
    normalized_raw = canonical_json(payload).encode("utf-8")
    return normalize_live_capture_manifest(
        payload,
        content_hash=file_hash(normalized_raw),
        raw_hash=file_hash(raw),
    )


def add_live_contract_gap(
    builder: Builder,
    gap_type: str,
    message: str,
    *,
    capture_id: str,
    surface: str | None = None,
    source_id: str | None = None,
    evidence: Sequence[str] = (),
) -> None:
    metadata: dict[str, Any] = {"capture_id": capture_id}
    if surface:
        metadata["surface"] = surface
    builder.add_gap(
        gap_type,
        message,
        source_id=source_id,
        evidence=evidence,
        metadata=metadata,
    )


def verify_recorded_capture_generator_binding(
    capture_generator: Mapping[str, Any], *, repository: Path | None = None
) -> dict[str, Any]:
    repository = repository or Path(__file__).resolve().parents[2]
    commit = str(capture_generator.get("git_commit") or "")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
        raise RegistryInputError("live receipt capture generator commit is invalid")
    expected_sources = capture_generator.get("sources")
    if not isinstance(expected_sources, list) or len(expected_sources) != len(
        LIVE_CAPTURE_GENERATOR_PATHS
    ):
        raise RegistryInputError("live receipt capture generator sources are missing")
    deadline = time.monotonic() + MAX_REPOSITORY_DISCOVERY_SECONDS
    layout_before = git_layout_identity(repository)
    git_prefix = (
        f"--git-dir={layout_before['git_dir']['path']}",
        f"--work-tree={repository.as_posix()}",
    )
    commit_raw, _executable = run_trusted_executable(
        DEFAULT_GIT_EXECUTABLE,
        (*git_prefix, "cat-file", "commit", commit),
        cwd=repository,
        max_stdout_bytes=MAX_GIT_METADATA_BYTES,
        timeout=_git_timeout(deadline),
    )
    if _git_object_id("commit", commit_raw, len(commit)) != commit:
        raise RegistryInputError("recorded capture commit bytes do not match identity")
    tree_raw, _executable = run_trusted_executable(
        DEFAULT_GIT_EXECUTABLE,
        (
            *git_prefix,
            "ls-tree",
            "-lrz",
            "--full-tree",
            commit,
            "--",
            *LIVE_CAPTURE_GENERATOR_PATHS,
        ),
        cwd=repository,
        max_stdout_bytes=MAX_GIT_OUTPUT_BYTES,
        timeout=_git_timeout(deadline),
    )
    inventory = _parse_tree_inventory(tree_raw, len(commit))
    inventory_by_path = {str(item["path"]): item for item in inventory}
    if set(inventory_by_path) != set(LIVE_CAPTURE_GENERATOR_PATHS):
        raise RegistryInputError("recorded capture generator sources are unavailable")
    blobs = _read_committed_blobs(
        repository,
        git_prefix,
        [inventory_by_path[path]["object_id"] for path in LIVE_CAPTURE_GENERATOR_PATHS],
        object_id_length=len(commit),
        git_executable=DEFAULT_GIT_EXECUTABLE,
        deadline=deadline,
    )
    actual_sources: list[dict[str, Any]] = []
    for expected, relative in zip(
        expected_sources, LIVE_CAPTURE_GENERATOR_PATHS, strict=True
    ):
        if not isinstance(expected, Mapping):
            raise RegistryInputError("live receipt capture generator source is unbound")
        raw = blobs[inventory_by_path[relative]["object_id"]]
        actual = {"path": relative, "sha256": file_hash(raw), "size": len(raw)}
        if dict(expected) != actual:
            raise RegistryInputError(
                "live receipt capture generator source differs from local committed bytes"
            )
        actual_sources.append(actual)
    registry_source = blobs[
        inventory_by_path["tools/knowledge-registry/knowledge_registry.py"]["object_id"]
    ]
    historical_ruleset_hash = ruleset_hash_from_registry_source(
        registry_source,
        "tools/knowledge-registry/knowledge_registry.py",
    )
    if capture_generator.get("ruleset_hash") != historical_ruleset_hash:
        raise RegistryInputError(
            "live receipt capture generator ruleset differs from committed source"
        )
    if git_layout_identity(repository) != layout_before:
        raise RegistryInputError("Git metadata changed during receipt provenance check")
    return {
        "git_commit": commit,
        "sources": actual_sources,
        "ruleset_hash": historical_ruleset_hash,
    }


def load_bound_capture_projector(capture_generator: Mapping[str, Any]) -> Any:
    verify_recorded_capture_generator_binding(capture_generator)
    current_before = registry_generator_source_binding()
    module_path = _repository_file("tools/knowledge-registry/capture_live.py")
    raw = read_regular_file(
        module_path,
        max_bytes=MAX_DISCOVERY_FILE_BYTES,
        label="current capture projection implementation",
    )
    expected_capture_source = next(
        source
        for source in current_before["sources"]
        if source["path"] == "tools/knowledge-registry/capture_live.py"
    )
    if expected_capture_source != {
        "path": "tools/knowledge-registry/capture_live.py",
        "sha256": file_hash(raw),
        "size": len(raw),
    }:
        raise RegistryInputError("capture projection source changed before loading")
    module_name = "_knowledge_registry_bound_capture_live"
    module = types.ModuleType(module_name)
    module.__file__ = module_path.as_posix()
    previous = sys.modules.get(module_name)
    previous_registry = sys.modules.get("knowledge_registry")
    sys.modules[module_name] = module
    sys.modules["knowledge_registry"] = sys.modules[__name__]
    try:
        exec(
            compile(
                raw.decode("utf-8"),
                module_path.as_posix(),
                "exec",
                dont_inherit=True,
            ),
            module.__dict__,
        )
    except Exception as exc:
        raise RegistryInputError(
            "cannot load the bound live projection implementation"
        ) from exc
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
        if previous_registry is None:
            sys.modules.pop("knowledge_registry", None)
        else:
            sys.modules["knowledge_registry"] = previous_registry
    module.kr = sys.modules[__name__]
    if current_before != registry_generator_source_binding():
        raise RegistryInputError("capture projection source changed while loading")
    return module


def enforce_exact_live_projection(
    payload: Mapping[str, Any], document_type: str, capture_runtime: Any
) -> None:
    """Re-project imported v3 evidence and require byte-equivalent safe shape."""

    safety_errors = identity_projection_safety_errors(payload)
    if safety_errors:
        raise RegistryInputError(
            f"live export violates identity-only projection at "
            f"{safety_errors[0].split(' ', 1)[0]}"
        )
    try:
        if document_type == "server-version":
            query = capture_runtime.Query(
                "server-version", "projection.json", (), response_type="server-version"
            )
        elif document_type in {"APIVersions", "APIGroupList"}:
            query = capture_runtime.Query(
                "api-discovery",
                "projection.json",
                (),
                document_type,
                "typed-object",
            )
        elif document_type == "APIResourceList":
            query = capture_runtime.Query(
                "api-discovery",
                "projection.json",
                (),
                "APIResourceList",
                "api-resource-list",
            )
        elif document_type == "OpenAPIv3Discovery":
            query = capture_runtime.Query(
                "builtin-openapi",
                "projection.json",
                (),
                document_type,
                "openapi-index",
            )
        elif document_type == "OpenAPIv3Document":
            query = capture_runtime.Query(
                "builtin-openapi",
                "projection.json",
                (),
                document_type,
                "openapi-document",
            )
        elif document_type in {
            *LIVE_CONTROLLER_KINDS,
            "Application",
            "ApplicationSet",
            "ClusterSbomReport",
            "CustomResourceDefinition",
            "Namespace",
            "Node",
            "Pod",
            "SbomReport",
        }:
            query = capture_runtime.Query(
                "projection", "projection.json", (), document_type
            )
        else:
            raise RegistryInputError("live export has an unsupported document type")
        projected = capture_runtime.project_query_payload(query, payload)
    except RegistryInputError:
        raise
    except (RuntimeError, TypeError, ValueError) as exc:
        raise RegistryInputError(
            "live export violates identity-only projection"
        ) from exc
    if canonical_json(projected) != canonical_json(payload):
        raise RegistryInputError(
            "live export is not the exact identity-only projection"
        )


def import_live(
    paths: Sequence[str],
    capture_manifest: str | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if len(paths) > LIVE_CAPTURE_BOUNDS["capture_commands"]:
        raise RegistryInputError(
            "live export inputs exceed file bound "
            f"{LIVE_CAPTURE_BOUNDS['capture_commands']}"
        )
    if isinstance(capture_manifest, str):
        capture_transport = (
            "stdin"
            if capture_manifest == "-"
            else Path(capture_manifest).absolute().as_posix()
        )
        for path in paths:
            export_transport = (
                "stdin" if path == "-" else Path(path).absolute().as_posix()
            )
            if export_transport == capture_transport:
                raise RegistryInputError(
                    "live capture manifest must not also be imported as a live export"
                )
    input_documents = read_bounded_unique_json_inputs(
        paths,
        max_files=LIVE_CAPTURE_BOUNDS["capture_commands"],
        max_total_bytes=LIVE_CAPTURE_BOUNDS["capture_bytes"],
        label="live export inputs",
    )
    builder = Builder()
    pod_inventory_observed = False
    documents: list[dict[str, Any]] = []
    for path, payload, raw in input_documents:
        normalized_raw = canonical_json(payload).encode("utf-8")
        documents.append(
            {
                "payload": payload,
                "raw_hash": file_hash(raw),
                "content_hash": file_hash(normalized_raw),
            }
        )

    node_platform_candidates: dict[str, set[str]] = {}
    for document in documents:
        payload = document["payload"]
        items = payload.get("items", []) if isinstance(payload, Mapping) else []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, Mapping):
                continue
            kind = str(item.get("kind") or payload.get("kind") or "").removesuffix(
                "List"
            )
            if kind != "Node":
                continue
            _, node_name = metadata_name(item)
            platform = node_oci_platform(item)
            if platform:
                node_platform_candidates.setdefault(node_name, set()).add(platform)
    builder.node_platforms = {
        node_name: next(iter(platforms))
        for node_name, platforms in node_platform_candidates.items()
        if len(platforms) == 1
    }

    capture, capture_errors = load_live_capture_manifest(capture_manifest)
    if (
        capture is not None
        and int(capture.get("contract_version") or 0) >= 3
        and capture_errors
    ):
        raise RegistryInputError("live capture manifest v3 is invalid")
    capture_source_id: str | None = None
    capture_id = "capture-missing"
    bound_surfaces_by_hash: dict[str, set[str]] = {}
    bound_artifacts_by_hash: dict[str, list[dict[str, str]]] = {}
    documents_by_raw_hash: dict[str, list[dict[str, Any]]] = {}
    payload_by_source_id: dict[str, Any] = {}
    for document in documents:
        documents_by_raw_hash.setdefault(str(document["raw_hash"]), []).append(document)

    if capture is None:
        builder.add_discovery_input(
            "live-capture:missing",
            content_hash=None,
            disposition="unreadable",
            scanners=("live-capture-contract",),
            evidence_class="live-capture",
            error="required live capture manifest is missing",
        )
        add_live_contract_gap(
            builder,
            "live-capture-manifest-missing",
            "Required P0.1 live capture manifest is missing",
            capture_id=capture_id,
        )
        for surface in LIVE_REQUIRED_SURFACES:
            add_live_contract_gap(
                builder,
                "live-required-surface-missing",
                f"Required live surface {surface} is not bound by a capture manifest",
                capture_id=capture_id,
                surface=surface,
            )
            builder.add_discovery_input(
                f"live-surface:{capture_id}:{surface}",
                content_hash=None,
                disposition="unreadable",
                scanners=("live-capture-contract",),
                evidence_class="live",
                error=f"required surface {surface} is missing",
            )
    else:
        capture_id = str(capture["capture_id"])
        capture_uri = f"live-capture:{capture_id}"
        capture_source_id = builder.add_source(
            capture_uri,
            "live-capture-manifest",
            content_hash=str(capture["capture_manifest_content_hash"]),
            metadata={"evidence_class": "live-capture", **capture},
        )
        contract_error = "; ".join(sorted({item[1] for item in capture_errors}))
        builder.add_discovery_input(
            capture_uri,
            content_hash=str(capture["capture_manifest_content_hash"]),
            disposition="unhandled" if capture_errors else "parsed",
            scanners=("live-capture-contract",),
            evidence_class="live-capture",
            error=contract_error or None,
        )
        for gap_type, message, surface in capture_errors:
            add_live_contract_gap(
                builder,
                gap_type,
                message,
                capture_id=capture_id,
                surface=surface,
                source_id=capture_source_id,
                evidence=(capture_uri,),
            )

        for surface_record in capture["surfaces"]:
            surface = str(surface_record["surface"])
            state = str(surface_record["state"])
            for artifact in surface_record.get("artifacts", []):
                if not isinstance(artifact, Mapping):
                    continue
                artifact_hash = str(artifact.get("raw_hash") or "")
                bound_artifacts_by_hash.setdefault(artifact_hash, []).append(
                    {
                        "surface": surface,
                        "endpoint": str(artifact.get("endpoint") or ""),
                        "document_type": str(artifact.get("document_type") or ""),
                    }
                )
            if state == "missing":
                add_live_contract_gap(
                    builder,
                    "live-required-surface-missing",
                    f"Required live surface {surface} is missing",
                    capture_id=capture_id,
                    surface=surface,
                    source_id=capture_source_id,
                    evidence=(capture_uri,),
                )
                builder.add_discovery_input(
                    f"live-surface:{capture_id}:{surface}",
                    content_hash=None,
                    disposition="unreadable",
                    scanners=("live-capture-contract",),
                    evidence_class="live",
                    error=f"required surface {surface} is missing",
                )
                continue
            if state in {"failed", "unavailable"}:
                reason = str(surface_record.get("error") or state)
                add_live_contract_gap(
                    builder,
                    "live-required-surface-unavailable",
                    f"Required live surface {surface} is {state}: {reason}",
                    capture_id=capture_id,
                    surface=surface,
                    source_id=capture_source_id,
                    evidence=(capture_uri,),
                )
                builder.add_discovery_input(
                    f"live-surface:{capture_id}:{surface}",
                    content_hash=None,
                    disposition="unreadable",
                    scanners=("live-capture-contract",),
                    evidence_class="live",
                    error=f"required surface {surface} is {state}: {reason}",
                )
                continue
            for raw_hash in surface_record["raw_hashes"]:
                bound_surfaces_by_hash.setdefault(str(raw_hash), set()).add(surface)
                matched_documents = documents_by_raw_hash.get(str(raw_hash), [])
                if not matched_documents:
                    add_live_contract_gap(
                        builder,
                        "live-surface-hash-mismatch",
                        f"Surface {surface} references unavailable raw export {raw_hash}",
                        capture_id=capture_id,
                        surface=surface,
                        source_id=capture_source_id,
                        evidence=(capture_uri,),
                    )
                    builder.add_discovery_input(
                        f"live-surface:{capture_id}:{surface}:{raw_hash}",
                        content_hash=None,
                        disposition="unreadable",
                        scanners=("live-capture-contract",),
                        evidence_class="live",
                        error=f"raw export {raw_hash} is unavailable",
                    )
                    continue
                if not any(
                    surface in live_payload_inventory(item["payload"])[0]
                    for item in matched_documents
                ):
                    add_live_contract_gap(
                        builder,
                        "live-surface-content-mismatch",
                        f"Raw export {raw_hash} does not contain surface {surface}",
                        capture_id=capture_id,
                        surface=surface,
                        source_id=capture_source_id,
                        evidence=(capture_uri,),
                    )
        if int(capture.get("contract_version") or 0) >= 3:
            capture_generator = capture.get("capture_generator")
            if not isinstance(capture_generator, Mapping):
                raise RegistryInputError("live capture generator binding is missing")
            capture_runtime = load_bound_capture_projector(capture_generator)
            for document in documents:
                raw_hash = str(document["raw_hash"])
                artifacts = bound_artifacts_by_hash.get(raw_hash, [])
                for document_type in sorted(
                    {str(artifact["document_type"]) for artifact in artifacts}
                ):
                    enforce_exact_live_projection(
                        document["payload"], document_type, capture_runtime
                    )
            verify_recorded_capture_generator_binding(capture_generator)
            registry_generator_source_binding()

        for surface, message in validate_live_api_artifacts(
            capture, documents_by_raw_hash
        ):
            add_live_contract_gap(
                builder,
                "live-surface-content-mismatch",
                message,
                capture_id=capture_id,
                surface=surface,
                source_id=capture_source_id,
                evidence=(capture_uri,),
            )

    for document in documents:
        payload = document["payload"]
        raw_hash = str(document["raw_hash"])
        content_hash = str(document["content_hash"])
        # Local fixture paths are transport details, not evidence identity.
        # Binding the logical URI to normalized content makes imports portable
        # and byte-identical across hosts and stdin/file transports.
        evidence_uri = f"live-export:{content_hash}"
        observed_surfaces, resource_kinds, missing_openapi = live_payload_inventory(
            payload
        )
        observation: dict[str, Any] = {
            "raw_content_hash": raw_hash,
            "recognized_surfaces": sorted(observed_surfaces),
            "resource_kinds": sorted(resource_kinds),
        }
        if capture is not None:
            observation.update(
                {
                    "capture_id": capture_id,
                    "observed_at": capture["observed_at"],
                    "bound_surfaces": sorted(
                        bound_surfaces_by_hash.get(raw_hash, set())
                    ),
                    "bound_artifacts": sorted(
                        bound_artifacts_by_hash.get(raw_hash, []),
                        key=canonical_json,
                    ),
                }
            )
        source_id = builder.add_source(
            evidence_uri,
            "live-export",
            content_hash=content_hash,
            metadata={
                "evidence_class": "live",
                "raw_content_hashes": [raw_hash],
                "observations": [observation],
            },
        )
        payload_by_source_id[source_id] = payload
        truncation = live_inventory_truncation(payload)
        if truncation:
            add_live_contract_gap(
                builder,
                "live-inventory-truncated",
                truncation,
                capture_id=capture_id,
                source_id=source_id,
                evidence=(evidence_uri,),
            )
        if capture is not None and raw_hash not in bound_surfaces_by_hash:
            add_live_contract_gap(
                builder,
                "live-export-unbound",
                f"Raw live export {raw_hash} is not bound to a required surface",
                capture_id=capture_id,
                source_id=source_id,
                evidence=(evidence_uri,),
            )
        if "crds-openapi" in bound_surfaces_by_hash.get(raw_hash, set()):
            for pointer in missing_openapi:
                add_live_contract_gap(
                    builder,
                    "live-crd-openapi-missing",
                    f"Captured CRD version lacks openAPIV3Schema at {pointer}",
                    capture_id=capture_id,
                    surface="crds-openapi",
                    source_id=source_id,
                    evidence=(f"{evidence_uri}#{pointer}",),
                )
        server_version = (
            payload.get("serverVersion") if isinstance(payload, dict) else None
        )
        if isinstance(server_version, dict) and server_version.get("gitVersion"):
            import_kubernetes_server_version(
                builder, source_id, server_version, "/serverVersion"
            )
            builder.add_discovery_input(
                evidence_uri,
                content_hash=content_hash,
                disposition="parsed",
                scanners=("live-kubernetes-version",),
                evidence_class="live",
            )
            continue
        payload_kind = (
            str(payload.get("kind") or "") if isinstance(payload, dict) else ""
        )
        artifact_records = bound_artifacts_by_hash.get(raw_hash, [])
        api_endpoint = next(
            (
                str(item.get("endpoint") or "")
                for item in artifact_records
                if item.get("surface") == "api-discovery"
            ),
            "",
        )
        openapi_endpoint = next(
            (
                str(item.get("endpoint") or "")
                for item in artifact_records
                if item.get("surface") == "builtin-openapi"
            ),
            "",
        )
        if payload_kind in {"APIVersions", "APIGroupList"}:
            builder.add_discovery_input(
                evidence_uri,
                content_hash=content_hash,
                disposition="parsed",
                scanners=("live-kubernetes-api-discovery",),
                evidence_class="live",
            )
            continue
        if payload_kind == "APIResourceList":
            import_api_resource_list(
                builder,
                source_id,
                payload,
                endpoint=api_endpoint or "unbound://api-discovery",
            )
            builder.add_discovery_input(
                evidence_uri,
                content_hash=content_hash,
                disposition="parsed",
                scanners=("live-kubernetes-api-discovery",),
                evidence_class="live",
            )
            continue
        if is_openapi_v3_discovery(payload):
            builder.add_discovery_input(
                evidence_uri,
                content_hash=content_hash,
                disposition="parsed",
                scanners=("live-kubernetes-openapi-v3",),
                evidence_class="live",
            )
            continue
        if is_openapi_v3_document(payload):
            imported_schemas = import_openapi_v3_document(
                builder,
                source_id,
                payload,
                endpoint=openapi_endpoint or "unbound://openapi-v3",
            )
            builder.add_discovery_input(
                evidence_uri,
                content_hash=content_hash,
                disposition="parsed" if imported_schemas else "unhandled",
                scanners=("live-kubernetes-openapi-v3",),
                evidence_class="live",
                error=(
                    None
                    if imported_schemas
                    else "OpenAPI v3 document has no Kubernetes GVK schemas"
                ),
            )
            continue
        items = payload.get("items", []) if isinstance(payload, dict) else []
        if not isinstance(items, list):
            builder.add_gap(
                "live-export-invalid",
                "Top-level items is not a list",
                source_id=source_id,
            )
            builder.add_discovery_input(
                evidence_uri,
                content_hash=content_hash,
                disposition="unhandled",
                scanners=("live-export",),
                evidence_class="live",
                error="Top-level items is not a list",
            )
            continue
        if payload_kind == "PodList":
            # An empty PodList is still an authoritative observation that no
            # running Pod image can currently satisfy a workload SBOM.
            pod_inventory_observed = True
        unsupported = False
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                unsupported = True
                continue
            kind = str(item.get("kind") or payload.get("kind", "")).removesuffix("List")
            api_version = str(item.get("apiVersion") or payload.get("apiVersion", ""))
            handled = False
            if kind in {"Application", "ApplicationSet"}:
                import_argo_item(builder, source_id, item, index)
                handled = True
            elif (
                kind in {"SbomReport", "ClusterSbomReport"}
                or "sbomreports" in api_version.lower()
            ):
                import_sbom_item(builder, source_id, item, index)
                handled = True
            elif kind in {
                "Pod",
                "Deployment",
                "StatefulSet",
                "DaemonSet",
                "Job",
                "CronJob",
                "ReplicaSet",
            }:
                import_workload_item(builder, source_id, item, index)
                pod_inventory_observed = pod_inventory_observed or kind == "Pod"
                handled = True
            elif kind == "Node":
                import_node_item(builder, source_id, item, index)
                handled = True
            elif kind == "CustomResourceDefinition":
                import_crd_item(builder, source_id, item, index)
                handled = True
            elif kind == "Namespace":
                # The namespace index is paging-closure evidence, not a component.
                handled = True
            if not handled:
                unsupported = True
                builder.add_gap(
                    "live-kind-unsupported",
                    f"Live export kind {api_version}/{kind} has no importer",
                    source_id=source_id,
                    evidence=(f"{evidence_uri}#/items/{index}",),
                )
        builder.add_discovery_input(
            evidence_uri,
            content_hash=content_hash,
            disposition="unhandled" if unsupported else "parsed",
            scanners=("live-export",),
            evidence_class="live",
        )
    if pod_inventory_observed:
        reconcile_live_sboms(builder)
    reconcile_cluster_sboms(builder)
    manifest = builder.manifest()
    validate_live_evidence_pointers(manifest, payload_by_source_id)
    return manifest


def metadata_name(item: Mapping[str, Any]) -> tuple[str, str]:
    metadata = (
        item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
    )
    return str(metadata.get("namespace", "")), str(metadata.get("name", "unknown"))


def normalize_kubernetes_version(value: str) -> str:
    normalized = value.strip()
    return normalized[1:] if normalized.lower().startswith("v") else normalized


def kubernetes_platform_component(builder: Builder) -> str:
    return builder.add_component(
        kind="platform",
        ecosystem="kubernetes",
        namespace="k8s.io",
        name="kubernetes",
        purl="pkg:k8s/k8s.io%2Fkubernetes",
        identity="kubernetes-platform:k8s.io/kubernetes",
        lifecycles=("deployed",),
        metadata={"inventory_scope": "cluster"},
        official_channel_required=True,
    )


def import_kubernetes_server_version(
    builder: Builder,
    source_id: str,
    version_info: Mapping[str, Any],
    pointer: str,
) -> None:
    git_version = str(version_info.get("gitVersion") or "")
    version = normalize_kubernetes_version(git_version)
    component_id = kubernetes_platform_component(builder)
    version_id = builder.add_version(
        component_id,
        resolved_version=version or None,
        resolution_state="resolved" if version else "unresolved",
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{pointer}",),
        metadata={
            key: version_info.get(key)
            for key in (
                "major",
                "minor",
                "gitVersion",
                "gitCommit",
                "gitTreeState",
                "buildDate",
                "goVersion",
                "compiler",
                "platform",
            )
            if version_info.get(key) not in (None, "")
        },
    )
    builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=pointer,
        role="live-kubernetes-server-version",
        raw_value=git_version or version,
        root_id=component_id,
        lifecycle="runtime-resolved",
        metadata={"inventory_scope": "control-plane"},
    )


def split_kubernetes_group_version(group_version: str) -> tuple[str, str]:
    if "/" in group_version:
        group, version = group_version.rsplit("/", 1)
        return group, version
    return "core", group_version


def import_api_resource_list(
    builder: Builder,
    source_id: str,
    payload: Mapping[str, Any],
    *,
    endpoint: str,
) -> None:
    group_version = str(payload.get("groupVersion") or "")
    group, version = split_kubernetes_group_version(group_version)
    resources = payload.get("resources")
    if not group_version or not isinstance(resources, list):
        builder.add_gap(
            "live-api-discovery-invalid",
            f"API discovery endpoint {endpoint} has no typed resources array",
            source_id=source_id,
            evidence=(f"{builder.sources[source_id]['evidence_uri']}#/resources",),
        )
        return
    platform = kubernetes_platform_component(builder)
    for index, resource in enumerate(resources):
        if not isinstance(resource, Mapping):
            builder.add_gap(
                "live-api-discovery-invalid",
                f"API discovery endpoint {endpoint} has a non-object resource",
                source_id=source_id,
                evidence=(
                    f"{builder.sources[source_id]['evidence_uri']}#/resources/{index}",
                ),
            )
            continue
        resource_name = str(resource.get("name") or "")
        resource_kind = str(resource.get("kind") or "")
        if not resource_name or not resource_kind:
            builder.add_gap(
                "live-api-discovery-invalid",
                f"API discovery endpoint {endpoint} has a resource without name or kind",
                source_id=source_id,
                evidence=(
                    f"{builder.sources[source_id]['evidence_uri']}#/resources/{index}",
                ),
            )
            continue
        component_id = builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace=group,
            name=resource_kind,
            identity=f"gvk:{group}/{version}:{resource_kind}",
            lifecycles=("deployed",),
            metadata={
                "api_group": group,
                "gvk": f"{group}/{version}/{resource_kind}",
            },
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version or None,
            resolution_state="resolved" if version else "unresolved",
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#/resources/{index}",
            ),
            metadata={
                "api_discovery_endpoint": endpoint,
                "api_resource_name": resource_name,
                "namespaced": resource.get("namespaced"),
                "singular_name": resource.get("singularName"),
                "verbs": resource.get("verbs", []),
                "short_names": resource.get("shortNames", []),
                "categories": resource.get("categories", []),
                "storage_version_hash": resource.get("storageVersionHash"),
            },
        )
        builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"/resources/{index}",
            role="live-kubernetes-api-discovery",
            raw_value=f"{group_version}/{resource_name}:{resource_kind}",
            root_id=platform,
            lifecycle="deployed",
            metadata={"endpoint": endpoint},
        )


def import_openapi_v3_document(
    builder: Builder,
    source_id: str,
    payload: Mapping[str, Any],
    *,
    endpoint: str,
) -> int:
    components = payload.get("components")
    schemas = components.get("schemas") if isinstance(components, Mapping) else None
    if not isinstance(schemas, Mapping):
        return 0
    imported = 0
    for schema_name in sorted(schemas):
        schema = schemas[schema_name]
        if not isinstance(schema, Mapping):
            continue
        gvks = schema.get("x-kubernetes-group-version-kind")
        if not isinstance(gvks, list):
            continue
        schema_digest = file_hash(canonical_json(schema).encode("utf-8"))
        schema_pointer = f"/components/schemas/{json_pointer_escape(str(schema_name))}"
        for gvk_index, gvk in enumerate(gvks):
            if not isinstance(gvk, Mapping):
                continue
            group = str(gvk.get("group") or "core")
            version = str(gvk.get("version") or "")
            resource_kind = str(gvk.get("kind") or "")
            if not version or not resource_kind:
                continue
            component_id = builder.add_component(
                kind="kubernetes-api",
                ecosystem="kubernetes",
                namespace=group,
                name=resource_kind,
                identity=f"gvk:{group}/{version}:{resource_kind}",
                lifecycles=("deployed",),
                metadata={
                    "api_group": group,
                    "gvk": f"{group}/{version}/{resource_kind}",
                },
            )
            version_id = builder.add_version(
                component_id,
                resolved_version=version,
                artifact_digest=schema_digest,
                evidence=(
                    f"{builder.sources[source_id]['evidence_uri']}#{schema_pointer}",
                ),
                metadata={
                    "openapi_endpoint": endpoint,
                    "openapi_schema_name": str(schema_name),
                    "openapi_version": payload.get("openapi"),
                },
            )
            builder.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=f"{schema_pointer}/x-kubernetes-group-version-kind/{gvk_index}",
                role="live-kubernetes-openapi-schema",
                raw_value=f"{group}/{version}/{resource_kind}",
                root_id=component_id,
                lifecycle="deployed",
                metadata={
                    "endpoint": endpoint,
                    "schema_digest": schema_digest,
                    "schema_name": str(schema_name),
                },
            )
            imported += 1
    return imported


def import_node_item(
    builder: Builder, source_id: str, item: Mapping[str, Any], index: int
) -> None:
    _, name = metadata_name(item)
    pointer = f"/items/{index}"
    status = item.get("status", {}) if isinstance(item.get("status"), dict) else {}
    node_info = (
        status.get("nodeInfo", {}) if isinstance(status.get("nodeInfo"), dict) else {}
    )
    platform = node_oci_platform(item)
    if platform:
        existing = builder.node_platforms.get(name)
        if existing and existing != platform:
            builder.node_platforms.pop(name, None)
        elif not existing:
            builder.node_platforms[name] = platform
    git_version = str(node_info.get("kubeletVersion") or "")
    version = normalize_kubernetes_version(git_version)
    component_id = kubernetes_platform_component(builder)
    version_id = builder.add_version(
        component_id,
        resolved_version=version or None,
        resolution_state="resolved" if version else "unresolved",
        evidence=(
            f"{builder.sources[source_id]['evidence_uri']}#{pointer}/status/nodeInfo/kubeletVersion",
        ),
        metadata={"inventory_scope": "node-kubelet"},
    )
    builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=f"{pointer}/status/nodeInfo/kubeletVersion",
        role="live-kubernetes-node-version",
        raw_value=f"{name}@{git_version or version}",
        root_id=component_id,
        lifecycle="runtime-resolved",
        metadata={
            "node": name,
            **{
                key: node_info.get(key)
                for key in (
                    "kubeletVersion",
                    "containerRuntimeVersion",
                    "kernelVersion",
                    "osImage",
                    "operatingSystem",
                    "architecture",
                )
                if node_info.get(key) not in (None, "")
            },
        },
    )


def normalize_runtime_image_id(image_id: str, desired_image: str) -> str | None:
    value = image_id.strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    if not value.startswith(("sha256:", "@sha256:")):
        return value
    if oci_image_reference_error(desired_image):
        return None
    repository, _, _ = split_image(desired_image)
    if not repository:
        return None
    if value.startswith("sha256:"):
        return f"{repository}@{value}"
    return f"{repository}{value}"


def node_oci_platform(item: Mapping[str, Any]) -> str | None:
    status = item.get("status", {}) if isinstance(item.get("status"), Mapping) else {}
    node_info = (
        status.get("nodeInfo", {})
        if isinstance(status.get("nodeInfo"), Mapping)
        else {}
    )
    operating_system = str(node_info.get("operatingSystem") or "")
    architecture = str(node_info.get("architecture") or "")
    return normalize_oci_platform(
        f"{operating_system}/{architecture}"
        if operating_system and architecture
        else None
    )


def workload_pod_spec_path(kind: str) -> tuple[str, ...]:
    if kind == "Pod":
        return ("spec",)
    if kind == "CronJob":
        return ("spec", "jobTemplate", "spec", "template", "spec")
    return ("spec", "template", "spec")


def workload_pod_spec(item: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    value: Any = item
    for key in workload_pod_spec_path(kind):
        if not isinstance(value, Mapping):
            return {}
        value = value.get(key, {})
    return value if isinstance(value, Mapping) else {}


def workload_pod_spec_pointer(item_pointer: str, kind: str) -> str:
    suffix = "/".join(workload_pod_spec_path(kind))
    return f"{item_pointer}/{suffix}"


def import_workload_item(
    builder: Builder, source_id: str, item: Mapping[str, Any], index: int
) -> None:
    namespace, name = metadata_name(item)
    kind = str(item.get("kind") or "Pod")
    api_version = str(item.get("apiVersion") or "v1")
    pointer = f"/items/{index}"
    metadata = (
        item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
    )
    status = item.get("status", {}) if isinstance(item.get("status"), dict) else {}
    phase = str(status.get("phase") or "")
    root_component = builder.add_component(
        kind="kubernetes-workload",
        ecosystem="kubernetes",
        namespace=namespace,
        name=name,
        identity=f"live-kubernetes:{api_version}:{kind}:{namespace}:{name}",
        lifecycles=("deployed",),
        metadata={"api_version": api_version, "resource_kind": kind},
        official_channel_required=False,
    )
    root_version = builder.add_version(
        root_component,
        source_ref=str(metadata.get("uid") or metadata.get("resourceVersion") or ""),
        resolution_state="resolved",
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{pointer}",),
        metadata={
            "generation": metadata.get("generation"),
            "observed_generation": status.get("observedGeneration"),
            "phase": phase or None,
        },
    )
    builder.add_occurrence(
        root_component,
        root_version,
        source_id,
        locator=pointer,
        role="live-kubernetes-workload",
        raw_value=f"{namespace}/{kind}/{name}",
        root_id=root_component,
        lifecycle="deployed",
        metadata={
            "uid": metadata.get("uid"),
            "resource_version": metadata.get("resourceVersion"),
            "labels": metadata.get("labels", {}),
            "phase": phase or None,
        },
    )

    pod_spec = workload_pod_spec(item, kind)
    pod_spec_pointer = workload_pod_spec_pointer(pointer, kind)
    node_name = str(pod_spec.get("nodeName") or "")
    pod_platform = builder.node_platforms.get(node_name)
    container_sections = (
        ("initContainers", "init-container"),
        ("containers", "container"),
        ("ephemeralContainers", "ephemeral-container"),
    )
    desired_by_name: dict[tuple[str, str], str] = {}
    for section, role_prefix in container_sections:
        containers = pod_spec.get(section, [])
        if not isinstance(containers, list):
            continue
        for container_index, container in enumerate(containers):
            if not isinstance(container, dict) or not container.get("image"):
                continue
            container_name = str(container.get("name") or container_index)
            image = str(container["image"])
            desired_by_name[(section, container_name)] = image
            locator = f"{pod_spec_pointer}/{section}/{container_index}/image"
            if TEMPLATE_EXPRESSION_RE.search(image):
                builder.add_gap(
                    "image-expression-unresolved",
                    f"Live desired image expression {image!r} is unresolved",
                    source_id=source_id,
                    evidence=(
                        f"{builder.sources[source_id]['evidence_uri']}#{locator}",
                    ),
                )
                continue
            _, version_id, occurrence_id = builder.add_image(
                image,
                source_id,
                locator,
                f"live-{role_prefix}-desired-image",
                platform=pod_platform,
                root_id=root_component,
                lifecycle="deployed",
                metadata={
                    "namespace": namespace,
                    "workload_kind": kind,
                    "workload": name,
                    "container": container_name,
                },
            )
            builder.add_edge(
                root_version,
                version_id,
                relationship="uses-image",
                source_occurrence_id=occurrence_id,
                scope="runtime",
                resolver="live-kubernetes-spec",
            )

    if kind == "Pod":
        status_sections = (
            ("initContainerStatuses", "initContainers"),
            ("containerStatuses", "containers"),
            ("ephemeralContainerStatuses", "ephemeralContainers"),
        )
        runtime_lifecycle = (
            "runtime-resolved"
            if phase in {"Running", "Pending", ""}
            else "historical-runtime"
        )
        for status_section, spec_section in status_sections:
            statuses = status.get(status_section, [])
            if not isinstance(statuses, list):
                continue
            for status_index, container_status in enumerate(statuses):
                if not isinstance(container_status, dict):
                    continue
                container_name = str(container_status.get("name") or status_index)
                desired_image = desired_by_name.get(
                    (spec_section, container_name),
                    str(container_status.get("image") or ""),
                )
                image_id = str(container_status.get("imageID") or "")
                status_locator = f"{pointer}/status/{status_section}/{status_index}"
                locator = f"{status_locator}/imageID"
                if not image_id:
                    builder.add_gap(
                        "live-imageid-missing",
                        f"Pod {namespace}/{name} container {container_name} has no imageID",
                        component_id=root_component,
                        component_version_id=root_version,
                        source_id=source_id,
                        evidence=(
                            f"{builder.sources[source_id]['evidence_uri']}#{status_locator}",
                        ),
                    )
                    continue
                runtime_image = normalize_runtime_image_id(image_id, desired_image)
                desired_error = oci_image_reference_error(desired_image)
                runtime_metadata = {
                    "namespace": namespace,
                    "pod": name,
                    "pod_uid": metadata.get("uid"),
                    "container": container_name,
                    "image_id": image_id,
                    "ready": container_status.get("ready"),
                    "restart_count": container_status.get("restartCount"),
                    "phase": phase or None,
                }
                if desired_image:
                    if desired_error:
                        runtime_metadata["desired_image_state"] = "invalid"
                        runtime_metadata["desired_image_sha256"] = file_hash(
                            desired_image.encode("utf-8")
                        )
                    else:
                        runtime_metadata["desired_image"] = desired_image
                _, version_id, occurrence_id = builder.add_image(
                    runtime_image or image_id,
                    source_id,
                    locator,
                    "live-container-imageid",
                    platform=pod_platform,
                    root_id=root_component,
                    lifecycle=runtime_lifecycle,
                    metadata=runtime_metadata,
                    invalid_reason=(
                        "runtime-digest-without-valid-desired-reference"
                        if runtime_image is None
                        else None
                    ),
                )
                builder.add_edge(
                    root_version,
                    version_id,
                    relationship="runs-image",
                    source_occurrence_id=occurrence_id,
                    scope="runtime",
                    resolver="live-kubernetes-status",
                )

    owners = metadata.get("ownerReferences", [])
    if isinstance(owners, list):
        for owner_index, owner in enumerate(owners):
            if not isinstance(owner, dict):
                continue
            owner_kind = str(owner.get("kind") or "unknown")
            owner_name = str(owner.get("name") or "unknown")
            owner_component = builder.add_component(
                kind="kubernetes-owner",
                ecosystem="kubernetes",
                namespace=namespace,
                name=owner_name,
                identity=f"live-owner:{owner.get('apiVersion')}:{owner_kind}:{namespace}:{owner_name}",
                lifecycles=("deployed",),
                metadata={"resource_kind": owner_kind},
                official_channel_required=False,
            )
            owner_version = builder.add_version(
                owner_component,
                source_ref=str(owner.get("uid") or ""),
                resolution_state="resolved",
                evidence=(
                    f"{builder.sources[source_id]['evidence_uri']}#{pointer}/metadata/ownerReferences/{owner_index}",
                ),
            )
            owner_occurrence = builder.add_occurrence(
                owner_component,
                owner_version,
                source_id,
                locator=f"{pointer}/metadata/ownerReferences/{owner_index}",
                role="live-owner-reference",
                raw_value=f"{owner_kind}/{owner_name}",
                root_id=root_component,
                lifecycle="deployed",
                metadata={"controller": owner.get("controller")},
            )
            builder.add_edge(
                root_version,
                owner_version,
                relationship="owned-by",
                source_occurrence_id=owner_occurrence,
                scope="deployment",
                resolver="kubernetes-owner-reference",
            )


def import_crd_item(
    builder: Builder, source_id: str, item: Mapping[str, Any], index: int
) -> None:
    namespace, name = metadata_name(item)
    pointer = f"/items/{index}"
    metadata = (
        item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
    )
    spec = item.get("spec", {}) if isinstance(item.get("spec"), dict) else {}
    group = str(spec.get("group") or "unknown")
    names = spec.get("names", {}) if isinstance(spec.get("names"), dict) else {}
    resource_kind = str(names.get("kind") or name)
    crd_component = builder.add_component(
        kind="kubernetes-crd",
        ecosystem="kubernetes",
        namespace=group,
        name=name,
        identity=f"crd:{name}",
        lifecycles=("deployed",),
        metadata={"group": group, "resource_kind": resource_kind},
        official_channel_required=True,
    )
    crd_version = builder.add_version(
        crd_component,
        source_ref=str(metadata.get("uid") or metadata.get("resourceVersion") or ""),
        resolution_state="resolved",
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{pointer}",),
    )
    versions = (
        spec.get("versions", []) if isinstance(spec.get("versions"), list) else []
    )
    for version_index, version in enumerate(versions):
        if not isinstance(version, dict) or not version.get("name"):
            continue
        version_name = str(version["name"])
        schema = (
            version.get("schema", {}) if isinstance(version.get("schema"), dict) else {}
        )
        schema_digest = (
            file_hash(canonical_json(schema).encode("utf-8")) if schema else None
        )
        api_component = builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace=group,
            name=resource_kind,
            identity=f"gvk:{group}/{version_name}:{resource_kind}",
            lifecycles=("deployed",),
            metadata={
                "api_group": group,
                "gvk": f"{group}/{version_name}/{resource_kind}",
                "crd_name": name,
            },
        )
        api_version = builder.add_version(
            api_component,
            resolved_version=version_name,
            artifact_digest=schema_digest,
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#{pointer}/spec/versions/{version_index}",
            ),
            metadata={
                "served": version.get("served"),
                "storage": version.get("storage"),
                "deprecated": version.get("deprecated"),
                "deprecation_warning": version.get("deprecationWarning"),
                "conversion": spec.get("conversion"),
            },
        )
        occurrence_id = builder.add_occurrence(
            api_component,
            api_version,
            source_id,
            locator=f"{pointer}/spec/versions/{version_index}",
            role="live-crd-api",
            raw_value=f"{group}/{version_name}/{resource_kind}",
            root_id=crd_component,
            lifecycle="deployed",
        )
        builder.add_edge(
            crd_version,
            api_version,
            relationship="defines-api",
            source_occurrence_id=occurrence_id,
            scope="api",
            resolver="live-crd",
        )


def reconcile_live_sboms(builder: Builder) -> None:
    active_occurrences: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for occurrence in builder.occurrences.values():
        if (
            occurrence.get("role") != "live-container-imageid"
            or occurrence.get("lifecycle") != "runtime-resolved"
        ):
            continue
        key = (occurrence["component_id"], occurrence["component_version_id"])
        active_occurrences.setdefault(key, []).append(occurrence)
    active = set(active_occurrences)
    active_digests = {
        (
            component_id,
            builder.versions[version_id].get("artifact_digest"),
        )
        for component_id, version_id in active
        if version_id in builder.versions
        and builder.versions[version_id].get("artifact_digest")
    }
    sbom_roots = [
        occurrence
        for occurrence in builder.occurrences.values()
        if occurrence.get("role") == "live-sbom-artifact"
        and occurrence.get("metadata", {}).get("report_kind") == "SbomReport"
        and occurrence.get("metadata", {}).get("report_namespace")
    ]
    matched_reports: set[tuple[str, str, str]] = set()
    for occurrence in sbom_roots:
        version = builder.versions.get(occurrence["component_version_id"], {})
        digest = version.get("artifact_digest")
        report = occurrence.get("metadata", {})
        report_key = (
            str(report.get("report_kind") or ""),
            str(report.get("report_namespace") or ""),
            str(report.get("report_name") or ""),
        )
        if (occurrence["component_id"], digest) in active_digests:
            occurrence["lifecycle"] = "runtime-resolved"
            matched_reports.add(report_key)
        else:
            occurrence["lifecycle"] = "orphaned"
            builder.add_gap(
                "live-sbom-stale-or-orphaned",
                f"SBOM {report_key[1]}/{report_key[2]} does not match a running image digest",
                component_id=occurrence["component_id"],
                component_version_id=occurrence["component_version_id"],
                source_id=occurrence["source_id"],
                evidence=(
                    f"{builder.sources[occurrence['source_id']]['evidence_uri']}#{occurrence['evidence_locator']}",
                ),
                metadata={"report_key": report_key, "artifact_digest": digest},
            )
    for occurrence in builder.occurrences.values():
        if occurrence.get("role") != "sbom-component":
            continue
        report = occurrence.get("metadata", {})
        if report.get("report_kind") != "SbomReport" or not report.get(
            "report_namespace"
        ):
            continue
        report_key = (
            str(report.get("report_kind") or ""),
            str(report.get("report_namespace") or ""),
            str(report.get("report_name") or ""),
        )
        occurrence["lifecycle"] = (
            "runtime-resolved" if report_key in matched_reports else "orphaned"
        )
    sbom_digest_keys = {
        (
            occurrence["component_id"],
            builder.versions.get(occurrence["component_version_id"], {}).get(
                "artifact_digest"
            ),
        )
        for occurrence in sbom_roots
    }
    for component_id, version_id in active:
        digest = builder.versions.get(version_id, {}).get("artifact_digest")
        if (component_id, digest) in sbom_digest_keys:
            continue
        occurrences = active_occurrences.get((component_id, version_id), [])
        evidence = tuple(
            f"{builder.sources[item['source_id']]['evidence_uri']}#{item['evidence_locator']}"
            for item in occurrences
        )
        builder.add_gap(
            "live-sbom-missing",
            "No current SBOM report matches a running image digest",
            component_id=component_id,
            component_version_id=version_id,
            source_id=occurrences[0]["source_id"] if occurrences else None,
            evidence=evidence,
            metadata={"artifact_digest": digest},
        )


def reconcile_cluster_sboms(builder: Builder) -> None:
    live_occurrences_by_version: dict[str, list[dict[str, Any]]] = {}
    for occurrence in builder.occurrences.values():
        if occurrence.get("role") not in {
            "live-kubernetes-server-version",
            "live-kubernetes-node-version",
        }:
            continue
        version = builder.versions.get(occurrence.get("component_version_id"), {})
        normalized = normalize_kubernetes_version(
            str(version.get("resolved_version") or "")
        )
        if normalized:
            live_occurrences_by_version.setdefault(normalized, []).append(occurrence)

    cluster_roots = [
        occurrence
        for occurrence in builder.occurrences.values()
        if occurrence.get("role") == "live-cluster-sbom-subject"
    ]
    report_versions: set[str] = set()
    report_lifecycles: dict[tuple[str, str, str], str] = {}
    for occurrence in cluster_roots:
        version = builder.versions.get(occurrence.get("component_version_id"), {})
        normalized = normalize_kubernetes_version(
            str(version.get("resolved_version") or "")
        )
        report = occurrence.get("metadata", {})
        report_key = (
            str(report.get("report_kind") or ""),
            str(report.get("report_namespace") or ""),
            str(report.get("report_name") or ""),
        )
        if normalized:
            report_versions.add(normalized)
        if not live_occurrences_by_version:
            state = "unknown"
            lifecycle = "sbom-observed"
        elif normalized in live_occurrences_by_version:
            state = "current"
            lifecycle = "runtime-resolved"
        else:
            state = "stale"
            lifecycle = "historical-runtime"
        occurrence["lifecycle"] = lifecycle
        occurrence["metadata"] = {**report, "reconciliation_state": state}
        report_lifecycles[report_key] = lifecycle
        if state == "stale":
            builder.add_gap(
                "live-cluster-sbom-stale",
                f"Cluster SBOM {report_key[2]} describes Kubernetes {normalized or 'unknown'}, which is not observed on the current server or nodes",
                component_id=occurrence["component_id"],
                component_version_id=occurrence["component_version_id"],
                source_id=occurrence["source_id"],
                evidence=(
                    f"{builder.sources[occurrence['source_id']]['evidence_uri']}#{occurrence['evidence_locator']}",
                ),
                metadata={
                    "report_key": report_key,
                    "kubernetes_version": normalized or None,
                },
            )

    for occurrence in builder.occurrences.values():
        if occurrence.get("role") != "sbom-component":
            continue
        report = occurrence.get("metadata", {})
        if report.get("report_kind") != "ClusterSbomReport":
            continue
        report_key = (
            str(report.get("report_kind") or ""),
            str(report.get("report_namespace") or ""),
            str(report.get("report_name") or ""),
        )
        if report_key in report_lifecycles:
            occurrence["lifecycle"] = report_lifecycles[report_key]

    for normalized, live_occurrences in sorted(live_occurrences_by_version.items()):
        if normalized in report_versions:
            continue
        version_ids = sorted(
            {
                str(item["component_version_id"])
                for item in live_occurrences
                if item.get("component_version_id")
            }
        )
        version_id = version_ids[0] if version_ids else None
        source_id = str(live_occurrences[0].get("source_id") or "")
        builder.add_gap(
            "live-cluster-sbom-missing",
            f"No current ClusterSbomReport matches observed Kubernetes version {normalized}",
            component_id=str(live_occurrences[0].get("component_id") or ""),
            component_version_id=version_id,
            source_id=source_id or None,
            evidence=tuple(
                f"{builder.sources[item['source_id']]['evidence_uri']}#{item['evidence_locator']}"
                for item in live_occurrences
            ),
            metadata={"kubernetes_version": normalized},
        )


def import_argo_item(
    builder: Builder, source_id: str, item: Mapping[str, Any], index: int
) -> None:
    namespace, name = metadata_name(item)
    namespace = namespace or "argocd"
    kind = str(item.get("kind", "Application"))
    pointer = f"/items/{index}"
    component_id = builder.add_component(
        kind=f"argo-{kind.lower()}",
        ecosystem="argocd",
        namespace=namespace,
        name=name,
        identity=argo_application_identity(kind, namespace, name),
        lifecycles=("deployed",),
        official_channel_required=False,
    )
    status = item.get("status", {}) if isinstance(item.get("status"), dict) else {}
    sync = status.get("sync", {}) if isinstance(status.get("sync"), dict) else {}
    revisions = sync.get("revisions")
    if not isinstance(revisions, list):
        revision = sync.get("revision")
        revisions = [revision] if revision else []
    operation_state = (
        status.get("operationState", {})
        if isinstance(status.get("operationState"), dict)
        else {}
    )
    sync_result = (
        operation_state.get("syncResult", {})
        if isinstance(operation_state.get("syncResult"), dict)
        else {}
    )
    if not revisions:
        operation_revisions = sync_result.get("revisions")
        if isinstance(operation_revisions, list):
            revisions = operation_revisions
        elif sync_result.get("revision"):
            revisions = [sync_result["revision"]]
    revisions = [str(item) for item in revisions if item]
    if len(revisions) == 1:
        revision_identity = revisions[0]
    elif revisions:
        revision_identity = (
            "revisions-sha256:"
            + hashlib.sha256(canonical_json(revisions).encode("utf-8")).hexdigest()
        )
    else:
        revision_identity = None
    version_id = builder.add_version(
        component_id,
        source_ref=revision_identity,
        constraint="live-observation" if not revision_identity else None,
        evidence=(f"{builder.sources[source_id]['evidence_uri']}#{pointer}",),
        metadata={
            "sync_status": sync.get("status"),
            "health_status": (
                (status.get("health") or {}).get("status")
                if isinstance(status.get("health"), dict)
                else None
            ),
            "reconciled_at": status.get("reconciledAt"),
            "revisions": revisions,
            "operation_phase": operation_state.get("phase"),
            "operation_started_at": operation_state.get("startedAt"),
            "operation_finished_at": operation_state.get("finishedAt"),
        },
    )
    builder.add_occurrence(
        component_id,
        version_id,
        source_id,
        locator=pointer,
        role="live-argo-application",
        raw_value=f"{namespace}/{name}",
        root_id=component_id,
        lifecycle="deployed",
        metadata={
            "uid": (
                (item.get("metadata") or {}).get("uid")
                if isinstance(item.get("metadata"), dict)
                else None
            ),
            "resource_version": (
                (item.get("metadata") or {}).get("resourceVersion")
                if isinstance(item.get("metadata"), dict)
                else None
            ),
        },
    )
    spec = item.get("spec", {}) if isinstance(item.get("spec"), dict) else {}
    sources = spec.get("sources")
    if isinstance(sources, list):
        source_pointer = f"{pointer}/spec/sources"
    else:
        sources = [spec.get("source")] if isinstance(spec.get("source"), dict) else []
        source_pointer = f"{pointer}/spec/source"
    if revisions and len(revisions) != len(sources):
        builder.add_gap(
            "argo-revision-cardinality",
            f"Argo Application {namespace}/{name} has {len(sources)} sources but {len(revisions)} observed revisions",
            component_id=component_id,
            component_version_id=version_id,
            source_id=source_id,
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#{pointer}/status/sync",
            ),
        )
    for source_index, source in enumerate(sources):
        if not isinstance(source, dict):
            continue
        repo = str(source.get("repoURL", ""))
        chart = str(source.get("chart", ""))
        source_path = str(source.get("path", ""))
        target = str(source.get("targetRevision", ""))
        observed_revision = (
            revisions[source_index] if source_index < len(revisions) else ""
        )
        locator = (
            f"{source_pointer}/{source_index}"
            if len(sources) > 1 or source_pointer.endswith("/sources")
            else source_pointer
        )
        if chart:
            target_component = builder.add_component(
                kind="helm-chart",
                ecosystem="helm",
                name=chart,
                identity=f"helm:{repo}:{chart}",
                lifecycles=("deployed",),
                metadata={"chart_repository": repo},
            )
            target_version = builder.add_version(
                target_component,
                resolved_version=observed_revision or target or None,
                constraint=target or None,
                evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
                metadata={"observed_revision": observed_revision or None},
            )
            raw_value = f"{repo}#{chart}@{target}"
            role = "live-argo-helm-source"
        else:
            target_component = builder.add_component(
                kind="git-repository",
                ecosystem="git",
                name=source_path or repo.rsplit("/", 1)[-1].removesuffix(".git"),
                identity=f"git:{repo}:{source_path}",
                lifecycles=("deployed",),
                metadata={"source_repo": repo, "path": source_path},
            )
            target_version = builder.add_version(
                target_component,
                source_ref=observed_revision or target or None,
                constraint=target or None,
                evidence=(f"{builder.sources[source_id]['evidence_uri']}#{locator}",),
                metadata={"observed_revision": observed_revision or None},
            )
            raw_value = f"{repo}#{source_path}@{target}"
            role = "live-argo-git-source"
        occurrence_id = builder.add_occurrence(
            target_component,
            target_version,
            source_id,
            locator=locator,
            role=role,
            raw_value=raw_value,
            root_id=component_id,
            lifecycle="deployed",
            dependency_scope="deployment",
        )
        builder.add_edge(
            version_id,
            target_version,
            relationship="desired-source",
            source_occurrence_id=occurrence_id,
            constraint=target or None,
            scope="deployment",
            resolver="live-argocd",
            metadata={"observed_revision": observed_revision or None},
        )

    observed_images: list[tuple[str, int, str]] = []
    for image_pointer, value in json_walk(status, f"{pointer}/status"):
        if not image_pointer.endswith("/images") or not isinstance(value, list):
            continue
        observed_images.extend(
            (image_pointer, image_index, image)
            for image_index, image in enumerate(value)
            if isinstance(image, str)
        )
    for image_pointer, image_index, image in observed_images:
        if TEMPLATE_EXPRESSION_RE.search(image):
            continue
        operation_image = "/operationState/syncResult/" in image_pointer
        _, image_version, image_occurrence = builder.add_image(
            image,
            source_id,
            f"{image_pointer}/{image_index}",
            (
                "live-argo-operation-image"
                if operation_image
                else "live-argo-observed-image"
            ),
            root_id=component_id,
            lifecycle="runtime-resolved",
            metadata={
                "application": name,
                "namespace": namespace,
                "status_path": image_pointer,
            },
        )
        builder.add_edge(
            version_id,
            image_version,
            relationship="observes-image",
            source_occurrence_id=image_occurrence,
            scope="runtime",
            resolver="live-argocd-status",
        )
    resources = (
        status.get("resources", []) if isinstance(status.get("resources"), list) else []
    )
    for resource_index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            continue
        group = str(resource.get("group") or "core")
        api_version = str(resource.get("version") or "unknown")
        resource_kind = str(resource.get("kind") or "unknown")
        target_component = builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace=group,
            name=resource_kind,
            identity=f"gvk:{group}/{api_version}:{resource_kind}",
            lifecycles=("deployed",),
            metadata={
                "api_group": group,
                "gvk": f"{group}/{api_version}/{resource_kind}",
            },
        )
        target_version = builder.add_version(
            target_component,
            resolved_version=api_version,
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#{pointer}/status/resources/{resource_index}",
            ),
        )
        occurrence_id = builder.add_occurrence(
            target_component,
            target_version,
            source_id,
            locator=f"{pointer}/status/resources/{resource_index}",
            role="live-argo-managed-resource",
            raw_value=f"{group}/{api_version}/{resource_kind}",
            root_id=component_id,
            lifecycle="deployed",
            metadata={
                key: resource.get(key)
                for key in ("namespace", "name", "status", "health", "requiresPruning")
                if key in resource
            },
        )
        builder.add_edge(
            version_id,
            target_version,
            relationship="manages-api",
            source_occurrence_id=occurrence_id,
            scope="deployment",
            resolver="live-argocd-status",
        )


def component_lists(
    value: Any, pointer: str
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    if isinstance(value, dict):
        for key in sorted(value):
            child = value[key]
            child_pointer = f"{pointer}/{json_pointer_escape(str(key))}"
            if key == "components" and isinstance(child, list):
                candidates = [
                    entry
                    for entry in child
                    if isinstance(entry, dict)
                    and (entry.get("name") or entry.get("purl"))
                ]
                if candidates:
                    yield child_pointer, candidates
                for list_index, entry in enumerate(child):
                    yield from component_lists(entry, f"{child_pointer}/{list_index}")
            else:
                yield from component_lists(child, child_pointer)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from component_lists(item, f"{pointer}/{index}")


def find_dependency_lists(
    value: Any, pointer: str = ""
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    if isinstance(value, dict):
        for key in sorted(value):
            child = value[key]
            child_pointer = f"{pointer}/{json_pointer_escape(str(key))}"
            if (
                key == "dependencies"
                and isinstance(child, list)
                and all(isinstance(x, dict) for x in child)
            ):
                yield child_pointer, child
            yield from find_dependency_lists(child, child_pointer)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from find_dependency_lists(item, f"{pointer}/{index}")


def trivy_report_subject_component(
    report: Mapping[str, Any],
) -> Mapping[str, Any]:
    components = (
        report.get("components", {})
        if isinstance(report.get("components"), dict)
        else {}
    )
    candidates = (
        (
            report.get("metadata", {}).get("component")
            if isinstance(report.get("metadata"), dict)
            else None
        ),
        (
            components.get("metadata", {}).get("component")
            if isinstance(components.get("metadata"), dict)
            else None
        ),
        components.get("component"),
    )
    return next((item for item in candidates if isinstance(item, Mapping)), {})


def trivy_repo_digest(report: Mapping[str, Any]) -> str:
    artifact = (
        report.get("artifact", {}) if isinstance(report.get("artifact"), dict) else {}
    )
    subject = trivy_report_subject_component(report)
    property_lists = (artifact.get("properties"), subject.get("properties"))
    for properties in property_lists:
        if not isinstance(properties, list):
            continue
        for item in properties:
            if not isinstance(item, Mapping):
                continue
            if str(item.get("name") or "").lower().endswith(":repodigest"):
                value = str(item.get("value") or "")
                if "@" in value:
                    return value
    return ""


def cyclonedx_oci_platform(component: Mapping[str, Any]) -> str | None:
    candidates: set[str] = set()
    purl = str(component.get("purl") or "")
    purl_platform = purl_oci_platform(purl)
    if purl_platform:
        candidates.add(purl_platform)
    properties = component.get("properties", [])
    property_values: dict[str, str] = {}
    if isinstance(properties, list):
        for item in properties:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name") or "").lower()
            value = str(item.get("value") or "")
            suffix = name.rsplit(":", 1)[-1]
            if suffix in {"platform", "os", "arch", "architecture"}:
                property_values[suffix] = value
    explicit = normalize_oci_platform(property_values.get("platform"))
    if explicit:
        candidates.add(explicit)
    operating_system = property_values.get("os", "")
    architecture = property_values.get("arch") or property_values.get(
        "architecture", ""
    )
    combined = normalize_oci_platform(
        f"{operating_system}/{architecture}"
        if operating_system and architecture
        else None
    )
    if combined:
        candidates.add(combined)
    return next(iter(candidates)) if len(candidates) == 1 else None


def cyclonedx_component_hash_identity(
    hashes: Any,
    *,
    purl: str,
    ecosystem: str,
    location: str,
) -> tuple[str | None, list[dict[str, str]], bool]:
    """Extract exact source SHA-256 evidence without synthesizing a digest."""

    if not isinstance(hashes, list):
        return None, [], False
    sha256_candidates: set[str] = set()
    evidence: list[dict[str, str]] = []
    invalid_sha256 = False
    for item in hashes:
        if not isinstance(item, Mapping):
            continue
        algorithm = str(item.get("alg") or "").strip()
        content = str(item.get("content") or "").strip()
        algorithm_key = re.sub(r"[^a-z0-9]", "", algorithm.lower())
        normalized_algorithm = (
            "SHA-256"
            if algorithm_key == "sha256"
            else (
                algorithm
                if re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", algorithm)
                else "unknown"
            )
        )
        normalized_content = content.lower().removeprefix("sha256:")
        valid_hex = bool(
            re.fullmatch(r"[0-9a-f]+", normalized_content)
            and len(normalized_content) in {32, 40, 64, 96, 128}
            and set(normalized_content) != {"0"}
        )
        record = {"alg": normalized_algorithm}
        if valid_hex:
            record["content"] = normalized_content
        else:
            record["state"] = "invalid"
        evidence.append(record)
        if algorithm_key == "sha256":
            if len(normalized_content) == 64 and valid_hex:
                sha256_candidates.add(f"sha256:{normalized_content}")
            else:
                invalid_sha256 = True

    if ecosystem == "oci":
        purl_digest_value = purl_version(purl)
        if purl_digest_value and purl_digest_value.lower().startswith("sha256:"):
            purl_digest, purl_error = normalize_oci_digest(purl_digest_value)
            if purl_error or not purl_digest:
                raise RegistryInputError(
                    f"SBOM component {location} has an invalid OCI purl digest"
                )
            sha256_candidates.add(purl_digest)
    if len(sha256_candidates) > 1:
        raise RegistryInputError(
            f"SBOM component {location} has conflicting SHA-256 identities"
        )
    digest = next(iter(sha256_candidates), None)
    return digest, sorted(evidence, key=canonical_json), invalid_sha256


def import_sbom_item(
    builder: Builder, source_id: str, item: Mapping[str, Any], index: int
) -> None:
    namespace, name = metadata_name(item)
    kind = str(item.get("kind", "SbomReport"))
    report = item.get("report", {}) if isinstance(item.get("report"), dict) else {}
    subject = trivy_report_subject_component(report)
    root_bom_ref = str(subject.get("bom-ref") or "")
    pointer = f"/items/{index}"
    artifact = (
        report.get("artifact", {}) if isinstance(report.get("artifact"), dict) else {}
    )
    root_platform_candidates = {
        platform
        for platform in (
            cyclonedx_oci_platform(subject),
            cyclonedx_oci_platform(artifact),
        )
        if platform
    }
    root_platform = (
        next(iter(root_platform_candidates))
        if len(root_platform_candidates) == 1
        else None
    )
    repository = str(artifact.get("repository") or "")
    registry = (
        report.get("registry", {}) if isinstance(report.get("registry"), dict) else {}
    )
    registry_server = normalize_registry_server(str(registry.get("server") or ""))
    if repository and registry_server and not repository_has_registry(repository):
        repository = f"{registry_server}/{repository.lstrip('/')}"
    tag = normalize_sbom_artifact_tag(str(artifact.get("tag") or ""))
    repo_digest = trivy_repo_digest(report)
    digest = str(artifact.get("digest") or "")
    if repo_digest:
        fallback_repository, fallback_digest = repo_digest.rsplit("@", 1)
        repository = repository or fallback_repository
        # Newer Trivy schemas expose artifact.digest directly.  RepoDigest is
        # only an older-schema fallback and must never override it.
        digest = digest or fallback_digest
    labels = (
        (item.get("metadata") or {}).get("labels", {})
        if isinstance(item.get("metadata"), dict)
        else {}
    )
    if not isinstance(labels, dict):
        labels = {}
    item_metadata = (
        item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
    )
    report_metadata = {
        "report_kind": kind,
        "report_namespace": namespace,
        "report_name": name,
        "report_uid": item_metadata.get("uid"),
        "resource_version": item_metadata.get("resourceVersion"),
        "creation_timestamp": item_metadata.get("creationTimestamp"),
        "update_timestamp": report.get("updateTimestamp"),
        "labels": labels,
        "registry": registry,
        "scanner": report.get("scanner"),
        "bom_format": report.get("bomFormat"),
        "spec_version": report.get("specVersion"),
        "serial_number": report.get("serialNumber"),
    }
    root_name = repository or name
    if kind == "ClusterSbomReport":
        platform_version = normalize_kubernetes_version(
            tag or str(subject.get("version") or "")
        )
        root_component = kubernetes_platform_component(builder)
        root_version = builder.add_version(
            root_component,
            resolved_version=platform_version or None,
            artifact_digest=digest or None,
            constraint=(
                "cluster-version-unidentified"
                if not (platform_version or digest)
                else None
            ),
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#{pointer}/report/artifact",
            ),
            metadata={
                "inventory_scope": "cluster",
                "subject_purl": subject.get("purl"),
                "subject_bom_ref": subject.get("bom-ref"),
            },
        )
        builder.add_occurrence(
            root_component,
            root_version,
            source_id,
            locator=f"{pointer}/report/artifact",
            role="live-cluster-sbom-subject",
            raw_value=f"kubernetes@{platform_version or tag or 'unknown'}",
            root_id=root_component,
            lifecycle="sbom-observed",
            metadata=report_metadata,
        )
    elif repository:
        image = repository
        if tag:
            image += f":{tag}"
        if digest:
            image += f"@{digest}"
        root_component, root_version, _ = builder.add_image(
            image,
            source_id,
            f"{pointer}/report/artifact",
            "live-sbom-artifact",
            platform=root_platform,
            lifecycle="sbom-observed",
            metadata=report_metadata,
        )
    else:
        root_component = builder.add_component(
            kind="sbom-subject",
            ecosystem="cyclonedx",
            namespace=namespace,
            name=root_name,
            identity=f"sbom:{kind}:{namespace}:{name}",
            lifecycles=("sbom-observed",),
            metadata=report_metadata,
            official_channel_required=False,
        )
        root_version = builder.add_version(
            root_component,
            artifact_digest=digest or None,
            resolved_version=tag or None,
            constraint="unidentified-artifact" if not (tag or digest) else None,
            evidence=(f"{builder.sources[source_id]['evidence_uri']}#{pointer}",),
        )
    if len(root_platform_candidates) > 1:
        builder.add_gap(
            "oci-platform-multi",
            "SBOM subject exposes conflicting OCI platform identities",
            component_id=root_component,
            component_version_id=root_version,
            source_id=source_id,
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#{pointer}/report",
            ),
            metadata={"platforms": sorted(root_platform_candidates)},
        )
    component_records: list[tuple[str, int, Mapping[str, Any]]] = []
    seen_locations: set[tuple[str, int]] = set()
    for list_pointer, components in component_lists(report, f"{pointer}/report"):
        for component_index, component in enumerate(components):
            marker = (list_pointer, component_index)
            if marker in seen_locations:
                continue
            seen_locations.add(marker)
            component_records.append((list_pointer, component_index, component))

    refs: dict[str, str] = {}
    if root_bom_ref:
        refs[root_bom_ref] = f"{pointer}/report/metadata/component"
    for list_pointer, component_index, component in component_records:
        bom_ref = str(component.get("bom-ref") or "")
        if not bom_ref:
            continue
        location = f"{list_pointer}/{component_index}"
        if bom_ref in refs:
            raise RegistryInputError(
                "SBOM contains duplicate CycloneDX bom-ref identities at "
                f"{refs[bom_ref]} and {location}"
            )
        refs[bom_ref] = location

    dependency_records: list[tuple[str, int, Mapping[str, Any]]] = []
    dependency_sources: dict[str, str] = {}
    adjacency: dict[str, list[str]] = {}
    for dependency_pointer, dependencies in find_dependency_lists(
        report, f"{pointer}/report"
    ):
        for dependency_index, dependency in enumerate(dependencies):
            location = f"{dependency_pointer}/{dependency_index}"
            source_ref = str(dependency.get("ref") or "")
            targets = dependency.get("dependsOn", [])
            if source_ref:
                if source_ref in dependency_sources:
                    raise RegistryInputError(
                        "SBOM contains duplicate CycloneDX dependency refs at "
                        f"{dependency_sources[source_ref]} and {location}"
                    )
                dependency_sources[source_ref] = location
            if not isinstance(targets, list) or any(
                not isinstance(target, str) for target in targets
            ):
                raise RegistryInputError(
                    f"SBOM dependency {location} has an invalid dependsOn array"
                )
            if len(targets) != len(set(targets)):
                raise RegistryInputError(
                    f"SBOM dependency {location} has duplicate target refs"
                )
            adjacency[source_ref] = list(targets)
            dependency_records.append(
                (dependency_pointer, dependency_index, dependency)
            )

    depth_by_ref: dict[str, int] = {}
    if root_bom_ref:
        depth_by_ref[root_bom_ref] = 0
        queue = [root_bom_ref]
        while queue:
            source_ref = queue.pop(0)
            for target_ref in adjacency.get(source_ref, []):
                candidate_depth = depth_by_ref[source_ref] + 1
                if (
                    target_ref not in depth_by_ref
                    or candidate_depth < depth_by_ref[target_ref]
                ):
                    depth_by_ref[target_ref] = candidate_depth
                    queue.append(target_ref)
    else:
        builder.add_gap(
            "sbom-root-bom-ref-unresolved",
            f"SBOM {namespace}/{name} has no CycloneDX metadata root bom-ref",
            component_id=root_component,
            component_version_id=root_version,
            source_id=source_id,
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#{pointer}/report",
            ),
        )

    ref_versions: dict[str, str] = {root_bom_ref: root_version} if root_bom_ref else {}
    ref_occurrences: dict[str, str] = {}
    for list_pointer, component_index, component in component_records:
        purl = str(component.get("purl") or "")
        version = str(component.get("version") or purl_version(purl) or "")
        ecosystem = (
            ecosystem_from_purl(purl)
            if purl
            else str(component.get("type") or "unknown")
        )
        component_name = str(component.get("name") or "unknown")
        namespace_value = str(component.get("group") or "")
        if purl:
            purl_namespace, purl_name = name_from_purl(purl)
            namespace_value = namespace_value or purl_namespace
            component_name = purl_name or component_name
            # Single-segment vanity Go modules carry the host as namespace.
            if ecosystem == "golang" and not namespace_value:
                namespace_value = golang_module_namespace_name(component_name)[0]
        component_kind = str(component.get("type") or "library")
        component_id = builder.add_component(
            kind=component_kind,
            ecosystem=ecosystem,
            namespace=namespace_value,
            name=component_name,
            purl=purl or None,
            identity=(
                None if purl else f"sbom:{ecosystem}:{namespace_value}:{component_name}"
            ),
            lifecycles=("sbom-observed",),
            metadata={
                key: component[key]
                for key in ("author", "publisher", "scope")
                if key in component
            },
            official_channel_required=not sbom_path_artifact_component(
                {"kind": component_kind, "ecosystem": ecosystem, "purl": purl or None}
            ),
        )
        component_location = f"{list_pointer}/{component_index}"
        artifact_digest, hash_evidence, invalid_sha256 = (
            cyclonedx_component_hash_identity(
                component.get("hashes", []),
                purl=purl,
                ecosystem=ecosystem,
                location=component_location,
            )
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version or None,
            artifact_digest=artifact_digest,
            platform=(
                cyclonedx_oci_platform(component) if ecosystem == "oci" else None
            ),
            resolution_state=(
                "resolved"
                if artifact_digest or (version and ecosystem != "oci")
                else "unresolved"
            ),
            evidence=(
                f"{builder.sources[source_id]['evidence_uri']}#{list_pointer}/{component_index}",
            ),
            metadata={
                **{
                    key: component[key]
                    for key in ("bom-ref", "licenses", "properties")
                    if key in component
                },
                **({"hash_evidence": hash_evidence} if hash_evidence else {}),
            },
        )
        if invalid_sha256:
            builder.add_gap(
                "sbom-component-sha256-invalid",
                "CycloneDX component has invalid SHA-256 evidence",
                component_id=component_id,
                component_version_id=version_id,
                source_id=source_id,
                evidence=(
                    f"{builder.sources[source_id]['evidence_uri']}#{component_location}/hashes",
                ),
            )
        occurrence_id = builder.add_occurrence(
            component_id,
            version_id,
            source_id,
            locator=f"{list_pointer}/{component_index}",
            role="sbom-component",
            raw_value=purl or f"{namespace_value}/{component_name}@{version}",
            root_id=root_component,
            directness=(
                "direct"
                if depth_by_ref.get(str(component.get("bom-ref") or "")) == 1
                else "transitive"
            ),
            lifecycle="sbom-observed",
            metadata={
                **report_metadata,
                "bom_ref": component.get("bom-ref"),
            },
        )
        builder.add_edge(
            root_version,
            version_id,
            relationship="contains",
            source_occurrence_id=occurrence_id,
            scope="runtime",
            resolver="cyclonedx-sbom",
        )
        bom_ref = component.get("bom-ref")
        if bom_ref:
            ref_versions[str(bom_ref)] = version_id
            ref_occurrences[str(bom_ref)] = occurrence_id
    for dependency_pointer, dependency_index, dependency in dependency_records:
        source_ref = str(dependency.get("ref") or "")
        source_version = ref_versions.get(source_ref)
        targets = dependency.get("dependsOn", [])
        if not source_version:
            builder.add_gap(
                "sbom-dependency-reference-unresolved",
                "CycloneDX dependency source ref is absent from the SBOM component set",
                component_id=root_component,
                component_version_id=root_version,
                source_id=source_id,
                evidence=(
                    f"{builder.sources[source_id]['evidence_uri']}#{dependency_pointer}/{dependency_index}",
                ),
            )
            continue
        for target_index, target_ref in enumerate(targets):
            target_ref_value = str(target_ref)
            target_version = ref_versions.get(target_ref_value)
            target_occurrence = ref_occurrences.get(target_ref_value)
            if not target_version or not target_occurrence:
                builder.add_gap(
                    "sbom-dependency-reference-unresolved",
                    "CycloneDX dependency target ref is absent from the SBOM component set",
                    component_id=root_component,
                    component_version_id=root_version,
                    source_id=source_id,
                    evidence=(
                        f"{builder.sources[source_id]['evidence_uri']}#{dependency_pointer}/{dependency_index}/dependsOn/{target_index}",
                    ),
                )
                continue
            builder.add_edge(
                source_version,
                target_version,
                relationship="depends-on",
                source_occurrence_id=target_occurrence,
                scope="runtime",
                resolver="cyclonedx-sbom",
                metadata={
                    "dependency_pointer": f"{dependency_pointer}/{dependency_index}/dependsOn/{target_index}"
                },
            )


def reviewed_component_kind(component: Mapping[str, Any]) -> str:
    kind = str(component.get("kind") or "component")
    ecosystem = str(component.get("ecosystem") or "unknown")
    return {
        "chart": "helm-chart",
        "image": "oci-image",
        "action": "github-action",
        "provider": "terraform-provider",
        "module": "terraform-module",
        "collection": "ansible-collection",
    }.get(kind, f"{ecosystem}-{kind}" if kind in {"package", "library"} else kind)


def reviewed_component_identity(component: Mapping[str, Any]) -> str:
    external_id = str(component.get("component_id") or "unknown")
    kind = str(component.get("kind") or "")
    if kind == "chart":
        return "helm:{repository}:{name}".format(
            repository=component.get("chart_repository") or "",
            name=component.get("chart_name") or component.get("name") or "unknown",
        )
    if kind == "image" and component.get("oci_repository"):
        return f"oci:{component['oci_repository']}"
    if component.get("purl"):
        return purl_base(str(component["purl"]))
    return f"reviewed:{external_id}"


def reviewed_component_registry_kind(component: Mapping[str, Any]) -> str:
    """Verbatim harvester kind when supplied; legacy mapping otherwise (T2)."""

    return str(component.get("registry_kind") or "") or reviewed_component_kind(
        component
    )


def reviewed_component_registry_identity(component: Mapping[str, Any]) -> str:
    return str(component.get("registry_identity") or "") or reviewed_component_identity(
        component
    )


def reviewed_lifecycle(value: Any) -> str:
    return {
        "reference": "reference-only",
        "conditional": "planned",
    }.get(str(value), str(value or "repository-used"))


def add_reviewed_root(
    builder: Builder,
    source_id: str,
    external_root_id: str,
    lifecycle: str,
) -> str:
    argo_prefix = "root:argo-application:"
    if external_root_id.startswith(argo_prefix):
        name = external_root_id.removeprefix(argo_prefix) or "unknown"
        component_id = builder.add_component(
            kind="argo-application",
            ecosystem="argocd",
            namespace="argocd",
            name=name,
            identity=argo_application_identity("Application", "argocd", name),
            lifecycles=(lifecycle,),
            metadata={"reviewed_root_id": external_root_id},
            official_channel_required=False,
        )
    else:
        component_id = builder.add_component(
            kind="reviewed-root",
            ecosystem="local",
            name=external_root_id,
            identity=f"reviewed-root:{external_root_id}",
            lifecycles=(lifecycle,),
            metadata={"reviewed_root_id": external_root_id},
            official_channel_required=False,
        )
    source = builder.sources[source_id]
    builder.add_version(
        component_id,
        source_ref=source.get("content_hash"),
        resolution_state="resolved",
        evidence=(source["evidence_uri"],),
        metadata={"reviewed_root_id": external_root_id},
    )
    return component_id


def draft202012_validator(schema_relative: str, *, label: str) -> Any:
    """Load an exact pinned Draft 2020-12 schema validator lazily."""

    try:
        installed_version = importlib.metadata.version("jsonschema")
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        raise RegistryInputError(
            "registry validation requires "
            "tools/knowledge-registry/requirements-reviewed.txt"
        ) from exc
    if installed_version != JSONSCHEMA_VERSION:
        raise RegistryInputError(
            "registry validation requires jsonschema=="
            f"{JSONSCHEMA_VERSION}, found {installed_version}"
        )
    schema_path = _repository_file(schema_relative)
    schema = parse_json_bytes(
        read_regular_file(
            schema_path,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label=label,
        ),
        label=schema_relative,
        max_bytes=MAX_DISCOVERY_FILE_BYTES,
    )
    if not isinstance(schema, Mapping):
        raise RegistryInputError(f"{label} must be a JSON object")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise RegistryInputError(f"{label} is invalid: {exc}") from exc
    checker = FormatChecker()
    checker.checks("date")(
        lambda value: not isinstance(value, str) or strict_canonical_date(value)
    )
    checker.checks("date-time")(
        lambda value: not isinstance(value, str) or strict_canonical_datetime(value)
    )
    checker.checks("uri-reference")(
        lambda value: not isinstance(value, str) or strict_uri_reference(value)
    )
    checker.checks("uri")(
        lambda value: not isinstance(value, str)
        or strict_uri_reference(value, require_scheme=True)
    )
    # Fail closed if the runtime silently ignores any format registration.
    for format_name, invalid in (
        ("date", "2026-02-30"),
        ("date-time", "2026-01-01T00:00:00+00:00"),
        ("uri-reference", "https://"),
        ("uri", "relative/path"),
    ):
        if checker.conforms(invalid, format_name):
            raise RegistryInputError(
                f"deterministic {format_name} format validation is unavailable"
            )
    return Draft202012Validator(schema, format_checker=checker)


def schema_validation_errors(validator: Any, record: Mapping[str, Any]) -> list[str]:
    errors = sorted(
        validator.iter_errors(record),
        key=lambda error: (
            tuple(str(item) for item in error.absolute_path),
            str(error.validator),
            error.message,
        ),
    )
    formatted: list[str] = []
    for error in errors[:MAX_SCHEMA_ERRORS]:
        path = "/" + "/".join(
            json_pointer_escape(str(item)) for item in error.absolute_path
        )
        formatted.append(f"{path or '/'}: {error.message}")
    if len(errors) > MAX_SCHEMA_ERRORS:
        formatted.append(
            f"... {len(errors) - MAX_SCHEMA_ERRORS} additional schema errors"
        )
    return formatted


def reviewed_record_validator() -> Any:
    return draft202012_validator(
        REVIEWED_SCHEMA_RELATIVE,
        label="reviewed component schema",
    )


def reviewed_record_schema_errors(
    validator: Any, record: Mapping[str, Any]
) -> list[str]:
    return schema_validation_errors(validator, record)


def discovery_manifest_schema_errors(manifest: Mapping[str, Any]) -> list[str]:
    validator = draft202012_validator(
        DISCOVERY_SCHEMA_RELATIVE,
        label="generated discovery manifest schema",
    )
    return schema_validation_errors(validator, manifest)


REVIEWED_URI_KEYS = {
    "$schema",
    "canonical_uri",
    "chart_repository",
    "download_uri",
    "evidence_uri",
    "endpoint",
    "lock_or_sbom_uri",
    "purl",
    "repoURL",
    "repository",
    "resolved_uri",
    "source_repo",
    "source_repository",
    "storage_uri",
    "server",
    "serverRelativeURL",
    "uri",
}
SENSITIVE_URI_QUERY_KEY_RE = re.compile(
    r"(?:^|[-_.])(?:api[-_.]?key|access[-_.]?key|auth|bearer|credential|jwt|key|password|secret|session|sig|signature|ticket|token)(?:$|[-_.])",
    re.IGNORECASE,
)
MAX_REVIEWED_URI_LENGTH = 8192
MAX_REVIEWED_URI_QUERY_PAIRS = 64
MAX_REVIEWED_URI_NESTING = 4
MAX_REVIEWED_URI_ENCODING_DEPTH = 4
REVIEWED_ID_ARRAY_FIELDS = {
    "versions": "component_version_id",
    "occurrences": "occurrence_id",
    "dependencies": "edge_id",
    "channels": "channel_id",
    "snapshots": "snapshot_id",
    "gaps": "gap_id",
}


def decode_bounded_percent_encoding(
    raw: str,
    *,
    pointer: str,
    errors: list[str],
    plus: bool = False,
    allow_decoded_literal_percent: bool = False,
) -> str | None:
    """Decode all bounded UTF-8 percent layers or return a pointer-only error."""

    current = raw
    decoder = unquote_plus if plus else unquote
    for layer in range(MAX_REVIEWED_URI_ENCODING_DEPTH):
        if re.search(r"%(?![0-9A-Fa-f]{2})", current):
            if layer == 0 and not allow_decoded_literal_percent:
                errors.append(f"{pointer} contains malformed percent encoding")
                return None
            # A valid encoded literal percent (for example %25) is data, not
            # necessarily the start of another encoding layer.
            return current
        if not re.search(r"%[0-9A-Fa-f]{2}", current):
            return current
        try:
            decoded = decoder(current, encoding="utf-8", errors="strict")
        except UnicodeError:
            errors.append(f"{pointer} contains invalid UTF-8 percent encoding")
            return None
        if decoded == current:
            return current
        current = decoded
        if len(current.encode("utf-8")) > MAX_REVIEWED_URI_LENGTH:
            errors.append(f"{pointer} exceeds URI length bound")
            return None
    if re.search(r"%[0-9A-Fa-f]{2}", current):
        errors.append(f"{pointer} exceeds percent-encoding depth bound")
        return None
    return current


def strict_uri_reference(value: Any, *, require_scheme: bool = False) -> bool:
    """Deterministic structural URI-reference validation without optional extras."""

    if not isinstance(value, str) or not value:
        return False
    if len(value.encode("utf-8")) > MAX_REVIEWED_URI_LENGTH:
        return False
    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    ):
        return False
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return False
    without_percent_triplets = re.sub(r"%[0-9A-Fa-f]{2}", "", value)
    if re.search(r"[^A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]", without_percent_triplets):
        return False
    try:
        unquote(value, encoding="utf-8", errors="strict")
        parsed = urlsplit(value)
        # Force validation of bracketed hosts and ports.
        _ = parsed.hostname
        _ = parsed.port
    except (UnicodeError, ValueError):
        return False
    if require_scheme and not parsed.scheme:
        return False
    if not parsed.scheme and "://" in value:
        return False
    if parsed.scheme:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed.scheme):
            return False
        if parsed.scheme.lower() in {"http", "https"} and not parsed.hostname:
            return False
        if parsed.scheme.lower() == "pkg" and not re.fullmatch(
            r"[A-Za-z0-9.+-]+/.+", parsed.path
        ):
            return False
        if not parsed.netloc and not parsed.path:
            return False
    elif value.startswith("//") and not parsed.netloc:
        return False
    return True


def strict_canonical_date(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value
    ):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%d") == value


def strict_canonical_datetime(value: Any) -> bool:
    return isinstance(value, str) and valid_live_observed_at(value)


CANDIDATE_LOCATOR_KEYS = {
    "artifact",
    "canonical_uri",
    "chart_repository",
    "download_uri",
    "endpoint",
    "evidence_uri",
    "image",
    "imageID",
    "lock_or_sbom_uri",
    "oci_repository",
    "registry",
    "repoURL",
    "repository",
    "resolved_uri",
    "server",
    "serverRelativeURL",
    "source_repo",
    "source_repository",
    "storage_uri",
    "uri",
}
CANDIDATE_LOCATOR_LIST_KEYS = {"images"}
RUNTIME_IMAGE_PREFIXES = (
    "docker-pullable://",
    "docker://",
    "containerd://",
    "cri-o://",
)
IDENTITY_PROJECTION_FORBIDDEN_KEYS = {
    "args",
    "command",
    "data",
    "env",
    "envFrom",
    "stringData",
}
IDENTITY_PROJECTION_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[-_.])(?:password|private[-_.]?key|secret|token)(?:$|[-_.])",
    re.IGNORECASE,
)


def unsafe_candidate_locator_pointers(value: Any, pointer: str = "") -> list[str]:
    """Return only JSON pointers for credential-bearing/unsafe persisted locators."""

    unsafe: list[str] = []

    def reject(candidate_pointer: str) -> None:
        unsafe.append(candidate_pointer or "/")

    def inspect(candidate: str, candidate_pointer: str, key: str) -> None:
        decode_errors: list[str] = []
        if not strict_uri_reference(candidate):
            reject(candidate_pointer)
            return
        decoded = decode_bounded_percent_encoding(
            candidate,
            pointer=candidate_pointer,
            errors=decode_errors,
        )
        if decoded is None or decode_errors:
            reject(candidate_pointer)
            return
        if (
            not decoded
            or len(decoded.encode("utf-8")) > MAX_REVIEWED_URI_LENGTH
            or any(
                character.isspace() or ord(character) < 32 or ord(character) == 127
                for character in decoded
            )
        ):
            reject(candidate_pointer)
            return
        if key == "serverRelativeURL":
            try:
                parsed = urlsplit(decoded)
            except ValueError:
                reject(candidate_pointer)
                return
            if (
                parsed.scheme
                or parsed.netloc
                or parsed.fragment
                or not parsed.path.startswith("/openapi/v3")
                or ".." in parsed.path.split("/")
            ):
                reject(candidate_pointer)
                return
            pairs = parsed.query.split("&") if parsed.query else []
            if len(pairs) > MAX_REVIEWED_URI_QUERY_PAIRS:
                reject(candidate_pointer)
                return
            for raw_pair in pairs:
                raw_key, _, raw_value = raw_pair.partition("=")
                query_errors: list[str] = []
                decoded_key = decode_bounded_percent_encoding(
                    raw_key,
                    pointer=candidate_pointer,
                    errors=query_errors,
                    plus=True,
                    allow_decoded_literal_percent=True,
                )
                decoded_value = decode_bounded_percent_encoding(
                    raw_value,
                    pointer=candidate_pointer,
                    errors=query_errors,
                    plus=True,
                    allow_decoded_literal_percent=True,
                )
                if (
                    query_errors
                    or decoded_key is None
                    or decoded_value is None
                    or SENSITIVE_URI_QUERY_KEY_RE.search(decoded_key)
                ):
                    reject(candidate_pointer)
                    return
            return

        normalized = decoded
        for prefix in RUNTIME_IMAGE_PREFIXES:
            if normalized.startswith(prefix):
                normalized = normalized.removeprefix(prefix)
                break
        if key in {"image", "imageID"} and normalized.count("@") > 1:
            digest_segments = normalized.split("@")[1:]
            if not all(
                FULL_SHA256_RE.fullmatch(segment) for segment in digest_segments
            ):
                reject(candidate_pointer)
                return
        try:
            parsed_locator = urlsplit(decoded)
        except ValueError:
            reject(candidate_pointer)
            return
        if parsed_locator.username is not None or parsed_locator.password is not None:
            reject(candidate_pointer)
            return
        if (
            parsed_locator.scheme
            and parsed_locator.netloc
            and parsed_locator.scheme.lower()
            in {"http", "https", "git+http", "git+https"}
        ):
            return
        if "@" in normalized:
            _base, suffix = normalized.rsplit("@", 1)
            ssh_repository = bool(
                key
                in {
                    "canonical_uri",
                    "chart_repository",
                    "evidence_uri",
                    "lock_or_sbom_uri",
                    "repoURL",
                    "repository",
                    "resolved_uri",
                    "source_repo",
                    "source_repository",
                    "uri",
                }
                and re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+", normalized)
            )
            if not FULL_SHA256_RE.fullmatch(suffix) and not ssh_repository:
                reject(candidate_pointer)

    def walk(nested_value: Any, nested_pointer: str) -> None:
        if isinstance(nested_value, Mapping):
            role = str(nested_value.get("role") or "").lower()
            for raw_key, nested in nested_value.items():
                key = str(raw_key)
                child_pointer = f"{nested_pointer}/{json_pointer_escape(key)}"
                if key in CANDIDATE_LOCATOR_KEYS and isinstance(nested, str):
                    inspect(nested, child_pointer, key)
                elif key in CANDIDATE_LOCATOR_LIST_KEYS and isinstance(nested, list):
                    for index, candidate in enumerate(nested):
                        candidate_pointer = f"{child_pointer}/{index}"
                        if not isinstance(candidate, str):
                            reject(candidate_pointer)
                        else:
                            inspect(candidate, candidate_pointer, "image")
                elif (
                    key == "raw_value"
                    and isinstance(nested, str)
                    and any(
                        locator_role in role
                        for locator_role in (
                            "endpoint",
                            "image",
                            "registry",
                            "repository",
                            "remote-add",
                            "download",
                            "source-requirement",
                            "url",
                        )
                    )
                ):
                    inspect(
                        nested,
                        child_pointer,
                        "image" if "image" in role else "endpoint",
                    )
                walk(nested, child_pointer)
        elif isinstance(nested_value, list):
            for index, nested in enumerate(nested_value):
                walk(nested, f"{nested_pointer}/{index}")

    uri_errors = validate_reviewed_uri_safety(value, pointer)
    unsafe.extend(error.split(" ", 1)[0] for error in uri_errors)
    walk(value, pointer)
    return sorted(set(unsafe))


def identity_projection_safety_errors(value: Any, pointer: str = "") -> list[str]:
    """Validate the shared no-secret projection boundary without echoing values."""

    errors: list[str] = []
    stack: list[tuple[Any, str, int]] = [(value, pointer, 0)]
    nodes = 0
    while stack:
        current, current_pointer, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            errors.append("/ exceeds projection node bound")
            break
        if depth > MAX_JSON_DEPTH:
            errors.append(f"{current_pointer or '/'} exceeds projection depth bound")
            continue
        if isinstance(current, Mapping):
            identity_keyed_map = current_pointer.endswith("/components/schemas")
            for raw_key, nested in current.items():
                key = str(raw_key)
                child_pointer = f"{current_pointer}/{json_pointer_escape(key)}"
                if not identity_keyed_map and (
                    key in IDENTITY_PROJECTION_FORBIDDEN_KEYS
                    or IDENTITY_PROJECTION_SENSITIVE_KEY_RE.search(key)
                ):
                    errors.append(f"{child_pointer} is forbidden by projection policy")
                stack.append((nested, child_pointer, depth + 1))
        elif isinstance(current, list):
            for index, nested in enumerate(current):
                stack.append((nested, f"{current_pointer}/{index}", depth + 1))
    errors.extend(
        f"{candidate_pointer} is an unsafe projected locator"
        for candidate_pointer in unsafe_candidate_locator_pointers(value, pointer)
    )
    return sorted(set(errors))


def validate_reviewed_uri_safety(value: Any, pointer: str = "") -> list[str]:
    errors: list[str] = []

    def inspect_uri(
        candidate: str,
        candidate_pointer: str,
        depth: int = 0,
        *,
        evidence_fragment: bool = False,
    ) -> None:
        if len(candidate.encode("utf-8")) > MAX_REVIEWED_URI_LENGTH:
            errors.append(f"{candidate_pointer} exceeds URI length bound")
            return
        if depth > MAX_REVIEWED_URI_NESTING:
            errors.append(f"{candidate_pointer} exceeds nested URI depth bound")
            return
        decoded_candidate = decode_bounded_percent_encoding(
            candidate,
            pointer=candidate_pointer,
            errors=errors,
        )
        if decoded_candidate is None:
            return
        if not strict_uri_reference(candidate):
            errors.append(f"{candidate_pointer} is not a safe URI")
            return
        try:
            parsed = urlparse(decoded_candidate)
        except ValueError:
            errors.append(f"{candidate_pointer} is not a safe URI")
            return
        if parsed.username is not None or parsed.password is not None:
            errors.append(f"{candidate_pointer} must not contain URI userinfo")
        json_pointer_fragment = bool(
            evidence_fragment and parsed.fragment.startswith("/")
        )
        if json_pointer_fragment and re.search(r"~(?![01])", parsed.fragment):
            errors.append(
                f"{candidate_pointer} contains an invalid JSON Pointer escape"
            )
        encoded_fields = [("query", parsed.query)]
        if not json_pointer_fragment:
            encoded_fields.append(("fragment", parsed.fragment))
        raw_pairs = [
            (location, pair)
            for location, encoded in encoded_fields
            for pair in (encoded.split("&") if encoded else [])
        ]
        if len(raw_pairs) > MAX_REVIEWED_URI_QUERY_PAIRS:
            errors.append(f"{candidate_pointer} exceeds URI query-pair bound")
            return
        for location, raw_pair in raw_pairs:
            raw_key, _, raw_value = raw_pair.partition("=")
            decoded_key = decode_bounded_percent_encoding(
                raw_key,
                pointer=candidate_pointer,
                errors=errors,
                plus=True,
                allow_decoded_literal_percent=True,
            )
            decoded_value = decode_bounded_percent_encoding(
                raw_value,
                pointer=candidate_pointer,
                errors=errors,
                plus=True,
                allow_decoded_literal_percent=True,
            )
            if decoded_key is None or decoded_value is None:
                continue
            if SENSITIVE_URI_QUERY_KEY_RE.search(decoded_key):
                errors.append(
                    f"{candidate_pointer} must not contain credential-bearing "
                    "URI fields"
                )
            if (
                decoded_key.lower()
                in {
                    "download_url",
                    "repository_url",
                    "source_url",
                    "vcs_url",
                }
                and decoded_value
            ):
                inspect_uri(
                    decoded_value,
                    f"{candidate_pointer}{'?' if location == 'query' else '#'}"
                    f"{decoded_key}",
                    depth + 1,
                )

    if isinstance(value, Mapping):
        for key, nested in value.items():
            child_pointer = f"{pointer}/{json_pointer_escape(str(key))}"
            candidates: list[str] = []
            if key in REVIEWED_URI_KEYS and isinstance(nested, str):
                candidates.append(nested)
            elif key == "evidence" and isinstance(nested, list):
                for candidate in nested:
                    if isinstance(candidate, str):
                        inspect_uri(
                            candidate,
                            child_pointer,
                            evidence_fragment=True,
                        )
            for candidate in candidates:
                inspect_uri(candidate, child_pointer)
            errors.extend(validate_reviewed_uri_safety(nested, child_pointer))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            errors.extend(validate_reviewed_uri_safety(nested, f"{pointer}/{index}"))
    return sorted(set(errors))


def preflight_reviewed_records(
    records: Sequence[tuple[str, Mapping[str, Any]]], validator: Any
) -> list[tuple[str, Mapping[str, Any]]]:
    validated: list[tuple[str, Mapping[str, Any], str]] = []
    for transport_uri, record in records:
        schema_errors = reviewed_record_schema_errors(validator, record)
        semantic_errors = validate_reviewed_record_semantics(record)
        uri_errors = validate_reviewed_uri_safety(record)
        errors = [*schema_errors, *semantic_errors, *uri_errors]
        if errors:
            raise RegistryInputError(
                f"{transport_uri} is not a safe accepted reviewed_component record: "
                + "; ".join(errors[:MAX_SCHEMA_ERRORS])
            )
        validated.append((transport_uri, record, canonical_json(record)))

    seen: dict[tuple[str, str], tuple[int, str, str]] = {}
    for record_index, (transport_uri, record, canonical) in enumerate(validated):
        identities = [
            ("record_id", str(record.get("record_id") or ""), "/record_id"),
            (
                "component_id",
                str(record.get("component", {}).get("component_id") or ""),
                "/component/component_id",
            ),
        ]
        for array_name, id_field in REVIEWED_ID_ARRAY_FIELDS.items():
            for item_index, item in enumerate(record.get(array_name, [])):
                identities.append(
                    (
                        id_field,
                        str(item.get(id_field) or ""),
                        f"/{array_name}/{item_index}/{id_field}",
                    )
                )
        for identity_kind, identity, pointer in identities:
            key = (identity_kind, identity)
            if key not in seen:
                seen[key] = (record_index, canonical, pointer)
                continue
            previous_index, previous_canonical, previous_pointer = seen[key]
            if previous_index == record_index or previous_canonical != canonical:
                raise RegistryInputError(
                    f"reviewed {identity_kind} is not unique at "
                    f"{previous_pointer} and {pointer}"
                )

    normalized_seen: dict[tuple[str, str], tuple[str, str, str]] = {}
    for _record_index, (_transport_uri, record, _canonical) in enumerate(validated):
        component = record["component"]
        external_component_id = str(component["component_id"])
        generated_component_id = stable_id(
            "cmp",
            reviewed_component_registry_kind(component),
            reviewed_component_registry_identity(component).lower(),
        )
        component_payload = canonical_json(
            {key: value for key, value in component.items() if key != "component_id"}
        )
        normalized_records = [
            (
                "component_id",
                generated_component_id,
                external_component_id,
                component_payload,
                "/component/component_id",
            )
        ]
        for version_index, version in enumerate(record.get("versions", [])):
            generated_version_id = stable_id(
                "ver",
                generated_component_id,
                version.get("resolved_version") or "",
                version.get("constraint") or "",
                version.get("source_ref") or "",
                version.get("artifact_digest") or "",
                version.get("platform") or "",
            )
            normalized_records.append(
                (
                    "component_version_id",
                    generated_version_id,
                    str(version["component_version_id"]),
                    canonical_json(
                        {
                            key: value
                            for key, value in version.items()
                            if key not in {"component_id", "component_version_id"}
                        }
                    ),
                    f"/versions/{version_index}/component_version_id",
                )
            )
        for (
            identity_kind,
            generated_id,
            external_id,
            payload,
            pointer,
        ) in normalized_records:
            key = (identity_kind, generated_id)
            previous = normalized_seen.get(key)
            if previous is None:
                normalized_seen[key] = (external_id, payload, pointer)
                continue
            previous_external_id, previous_payload, previous_pointer = previous
            if external_id != previous_external_id or payload != previous_payload:
                raise RegistryInputError(
                    f"reviewed {identity_kind} normalizes to conflicting generated "
                    f"identity {generated_id} at {previous_pointer} and {pointer}"
                )

    unique_by_content: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for transport_uri, record, canonical in validated:
        unique_by_content.setdefault(canonical, (transport_uri, record))
    return [unique_by_content[key] for key in sorted(unique_by_content)]


def reviewed_records_manifest(
    records: Sequence[tuple[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    builder = Builder()
    schema_validator = reviewed_record_validator() if records else None
    records = preflight_reviewed_records(records, schema_validator) if records else []
    source_by_record: dict[str, str] = {}
    component_by_external: dict[str, str] = {}
    lifecycle_by_external: dict[str, str] = {}
    version_by_external: dict[str, str] = {}
    component_by_version: dict[str, str] = {}
    record_by_component: dict[str, tuple[str, Mapping[str, Any]]] = {}

    for transport_uri, record in records:
        raw = canonical_json(record).encode("utf-8")
        record_id = str(record.get("record_id") or transport_uri)
        semantic_errors = validate_reviewed_record_semantics(record)
        if semantic_errors:
            raise ValueError(
                f"{transport_uri} is not an accepted reviewed_component record: "
                + "; ".join(semantic_errors)
            )
        content_hash = file_hash(raw)
        evidence_uri = f"reviewed-record:{record_id}"
        source_id = builder.add_source(
            evidence_uri,
            "reviewed-component-record",
            content_hash=content_hash,
            metadata={
                "evidence_class": "reviewed",
                "record_id": record_id,
                "review": record.get("review", {}),
            },
        )
        builder.add_discovery_input(
            evidence_uri,
            content_hash=content_hash,
            disposition="parsed",
            scanners=("reviewed-component-import",),
            evidence_class="reviewed",
        )
        source_by_record[record_id] = source_id
        component = record.get("component")
        if not isinstance(component, dict):
            builder.add_gap(
                "reviewed-record-invalid",
                f"{record_id} has no component object",
                source_id=source_id,
                evidence=(evidence_uri,),
            )
            continue
        external_id = str(component.get("component_id") or "")
        if not external_id:
            builder.add_gap(
                "reviewed-record-invalid",
                f"{record_id} component has no component_id",
                source_id=source_id,
                evidence=(evidence_uri,),
            )
            continue
        channels = []
        for channel in record.get("channels", []):
            if not isinstance(channel, dict):
                continue
            normalized = dict(channel)
            normalized["reviewed_component_id"] = external_id
            channels.append(normalized)
        lifecycle = reviewed_lifecycle(component.get("lifecycle"))
        metadata = {
            key: component.get(key)
            for key in (
                "aliases",
                "api_group",
                "authority_policy",
                "chart_name",
                "chart_repository",
                "created_at",
                "disposition",
                "gvk",
                "oci_repository",
                "owners",
                "registry_identity",
                "registry_kind",
                "source_repo",
                "topics",
            )
            if component.get(key) not in (None, "", [], {})
        }
        metadata.update(
            {
                "reviewed_component_id": external_id,
                "reviewed_record_id": record_id,
                "review": record.get("review", {}),
            }
        )
        component_id = builder.add_component(
            kind=reviewed_component_registry_kind(component),
            ecosystem=str(component.get("ecosystem") or "unknown"),
            namespace=str(component.get("namespace") or ""),
            name=str(component.get("name") or external_id),
            purl=str(component["purl"]) if component.get("purl") else None,
            identity=reviewed_component_registry_identity(component),
            lifecycles=(lifecycle,),
            metadata=metadata,
            official_channels=channels,
            official_channel_required=True,
        )
        component_by_external[external_id] = component_id
        lifecycle_by_external[external_id] = lifecycle
        record_by_component[external_id] = (record_id, record)

    for external_id, component_id in component_by_external.items():
        record_id, record = record_by_component[external_id]
        source_id = source_by_record[record_id]
        for version in record.get("versions", []):
            if not isinstance(version, dict):
                continue
            version_external_id = str(version.get("component_version_id") or "")
            if not version_external_id:
                continue
            metadata = {
                key: version.get(key)
                for key in (
                    "build_metadata",
                    "observed_at",
                    "release_time",
                    "valid_from",
                    "valid_to",
                    "purl",
                )
                if version.get(key) not in (None, "", [], {})
            }
            metadata["reviewed_component_version_id"] = version_external_id
            version_id = builder.add_version(
                component_id,
                resolved_version=(
                    str(version["resolved_version"])
                    if version.get("resolved_version")
                    else None
                ),
                constraint=(
                    str(version["constraint"]) if version.get("constraint") else None
                ),
                source_ref=(
                    str(version["source_ref"]) if version.get("source_ref") else None
                ),
                artifact_digest=(
                    str(version["artifact_digest"])
                    if version.get("artifact_digest")
                    else None
                ),
                platform=str(version["platform"]) if version.get("platform") else None,
                resolution_state=str(version.get("resolution_state") or "unresolved"),
                evidence=tuple(str(item) for item in version.get("evidence", [])),
                metadata=metadata,
            )
            version_by_external[version_external_id] = version_id
            component_by_version[version_external_id] = component_id

        snapshots = []
        for item in record.get("snapshots", []):
            if not isinstance(item, dict):
                continue
            snapshot = dict(item)
            external_version_id = str(snapshot.get("component_version_id") or "")
            snapshot["reviewed_component_version_id"] = external_version_id
            snapshot["component_version_id"] = version_by_external[external_version_id]
            snapshots.append(snapshot)
        if snapshots:
            builder.components[component_id]["official_channel_snapshots"] = snapshots

        reviewed_channels = reviewed_record_channels(
            builder.components[component_id].get("official_channels", [])
        )
        unresolved = unresolved_reviewed_channels(reviewed_channels)
        if unresolved:
            # One row per component, not per slot: the slot detail stays verbatim
            # on components[].official_channels and is re-derivable from it.
            states = Counter(
                str(channel.get("availability_state") or "unresolved")
                for channel in unresolved
            )
            builder.add_gap(
                "official-channel-state",
                f"{len(unresolved)} of {len(reviewed_channels)} reviewed official "
                f"channel classes are unresolved for {external_id}",
                component_id=component_id,
                source_id=source_id,
                evidence=(f"reviewed-record:{record_id}",),
                metadata={
                    "reviewed_channel_classes": len(reviewed_channels),
                    "unresolved_channel_classes": len(unresolved),
                    "unresolved_by_state": {key: states[key] for key in sorted(states)},
                    "unresolved_channel_types": sorted(
                        str(channel.get("channel_type") or "unknown")
                        for channel in unresolved
                    ),
                },
            )

    for external_id, component_id in component_by_external.items():
        record_id, record = record_by_component[external_id]
        source_id = source_by_record[record_id]
        lifecycle = lifecycle_by_external[external_id]
        for index, occurrence in enumerate(record.get("occurrences", [])):
            if not isinstance(occurrence, dict):
                continue
            external_version = str(occurrence.get("component_version_id") or "")
            version_id = version_by_external.get(external_version)
            if not version_id:
                builder.add_gap(
                    "reviewed-reference-unresolved",
                    f"Occurrence references unknown version {external_version!r}",
                    component_id=component_id,
                    source_id=source_id,
                    evidence=(str(occurrence.get("evidence_uri") or record_id),),
                )
                continue
            external_root_id = str(occurrence.get("root_id") or "")
            root_id = component_id
            if external_root_id:
                root_id = add_reviewed_root(
                    builder,
                    source_id,
                    external_root_id,
                    lifecycle,
                )
            builder.add_occurrence(
                component_id,
                version_id,
                source_id,
                locator=f"/occurrences/{index}",
                role=str(occurrence.get("role") or "reviewed-occurrence"),
                raw_value=str(occurrence.get("occurrence_id") or external_version),
                root_id=root_id,
                directness=str(occurrence.get("directness") or "direct"),
                dependency_scope=str(occurrence.get("dependency_scope") or "unknown"),
                optional=bool(occurrence.get("optional")),
                lifecycle=lifecycle,
                metadata={"reviewed_occurrence": occurrence},
            )

        for index, dependency in enumerate(record.get("dependencies", [])):
            if not isinstance(dependency, dict):
                continue
            from_external = str(dependency.get("from_component_version_id") or "")
            to_external = str(dependency.get("to_component_version_id") or "")
            from_version = version_by_external.get(from_external)
            to_version = version_by_external.get(to_external)
            if not from_version or not to_version:
                missing = [
                    item
                    for item, resolved in (
                        (from_external, from_version),
                        (to_external, to_version),
                    )
                    if not resolved
                ]
                builder.add_gap(
                    "reviewed-reference-unresolved",
                    "Dependency references versions outside the imported reviewed set: "
                    + ", ".join(missing),
                    component_id=component_id,
                    source_id=source_id,
                    evidence=(str(dependency.get("lock_or_sbom_uri") or record_id),),
                    metadata={"reviewed_dependency": dependency},
                )
                continue
            target_component = component_by_version[to_external]
            occurrence_id = builder.add_occurrence(
                target_component,
                to_version,
                source_id,
                locator=f"/dependencies/{index}",
                role="reviewed-dependency-evidence",
                raw_value=str(
                    dependency.get("edge_id") or f"{from_external}->{to_external}"
                ),
                root_id=component_by_version[from_external],
                directness="transitive",
                dependency_scope=str(dependency.get("scope") or "unknown"),
                optional=bool(dependency.get("optional")),
                lifecycle=lifecycle,
                metadata={"reviewed_dependency": dependency},
            )
            builder.add_edge(
                from_version,
                to_version,
                relationship=str(dependency.get("relationship") or "depends-on"),
                source_occurrence_id=occurrence_id,
                constraint=(
                    str(dependency["constraint"])
                    if dependency.get("constraint")
                    else None
                ),
                scope=str(dependency.get("scope") or "unknown"),
                optional=bool(dependency.get("optional")),
                resolver=str(dependency.get("resolver") or "reviewed-record"),
                metadata={"reviewed_dependency_id": dependency.get("edge_id")},
            )

        for gap in record.get("gaps", []):
            if not isinstance(gap, dict):
                continue
            subject_id = str(gap.get("subject_id") or "")
            subject_kind = str(gap.get("subject_kind") or "")
            gap_component = component_id
            gap_version = None
            if subject_kind == "version" and subject_id in version_by_external:
                gap_version = version_by_external[subject_id]
                gap_component = component_by_version[subject_id]
            elif subject_kind == "component" and subject_id in component_by_external:
                gap_component = component_by_external[subject_id]
            builder.add_gap(
                "reviewed-gap",
                str(gap.get("reason") or gap.get("gap_id") or "Reviewed gap"),
                component_id=gap_component,
                component_version_id=gap_version,
                source_id=source_id,
                evidence=tuple(str(item) for item in gap.get("evidence", [])),
                metadata={"reviewed_gap": gap},
            )
    return builder.manifest()


def validate_reviewed_record_semantics(record: Mapping[str, Any]) -> list[str]:
    """Validate reviewed-record invariants without I/O.

    The canonical JSON Schema remains the structural authority.  These checks
    intentionally duplicate the cross-record and review assertions that JSON
    Schema cannot express, so malformed authority is rejected at the importer
    boundary rather than converted into a plausible generated candidate.
    """

    errors: list[str] = []
    if record.get("record_kind") != "reviewed_component":
        errors.append("record_kind must equal reviewed_component")
    if not record.get("record_id"):
        errors.append("record_id is required")
    review = record.get("review")
    if not isinstance(review, Mapping) or review.get("status") != "accepted":
        errors.append("parent review.status must equal accepted")
    component = record.get("component")
    if not isinstance(component, Mapping):
        errors.append("component must be an object")
        component = {}
    for key in ("component_id", "kind", "ecosystem", "name"):
        if not component.get(key):
            errors.append(f"component.{key} is required")
    component_id = str(component.get("component_id") or "")
    component_ecosystem = str(component.get("ecosystem") or "")
    component_kind = str(component.get("kind") or "")
    registry_kind = component.get("registry_kind")
    registry_identity = component.get("registry_identity")
    if (registry_kind is None) != (registry_identity is None):
        errors.append(
            "component.registry_kind and component.registry_identity must be "
            "provided together"
        )
    for key, value in (
        ("registry_kind", registry_kind),
        ("registry_identity", registry_identity),
    ):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"component.{key} must be a non-empty string")
    is_oci_component = component_ecosystem == "oci" or component_kind in {
        "image",
        "oci-image",
    }
    arrays: dict[str, list[Any]] = {}
    for key in (
        "versions",
        "occurrences",
        "dependencies",
        "channels",
        "snapshots",
        "gaps",
    ):
        value = record.get(key)
        if not isinstance(value, list):
            errors.append(f"{key} must be an array")
            value = []
        arrays[key] = value

    version_ids: set[str] = set()
    for index, version in enumerate(arrays["versions"]):
        if not isinstance(version, Mapping):
            errors.append(f"versions[{index}] must be an object")
            continue
        version_id = str(version.get("component_version_id") or "")
        if not version_id:
            errors.append(f"versions[{index}].component_version_id is required")
        elif version_id in version_ids:
            errors.append(f"duplicate component_version_id {version_id}")
        version_ids.add(version_id)
        digest = version.get("artifact_digest")
        immutable_oci_digest, oci_digest_error = normalize_oci_digest(
            str(digest) if digest is not None else None
        )
        if version.get("resolution_state") == "resolved":
            if is_oci_component:
                if not immutable_oci_digest:
                    errors.append(
                        f"versions[{index}] resolved OCI state requires a valid non-zero manifest digest"
                    )
            elif not (
                looks_exact(str(version.get("resolved_version") or ""))
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest or ""))
                or (
                    looks_exact(str(version.get("source_ref") or ""))
                    and str(version.get("source_ref") or "").lower() not in MUTABLE_REFS
                )
            ):
                errors.append(
                    f"versions[{index}] resolved state requires an immutable version, ref, or sha256 digest"
                )
        if digest:
            if is_oci_component and oci_digest_error:
                errors.append(
                    f"versions[{index}].artifact_digest must be a valid non-zero OCI sha256 digest"
                )
            elif not is_oci_component and not re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(digest)
            ):
                errors.append(
                    f"versions[{index}].artifact_digest must be a full sha256"
                )
        platform = version.get("platform")
        if platform is not None and (
            not isinstance(platform, str)
            or normalize_oci_platform(platform) != platform
        ):
            errors.append(
                f"versions[{index}].platform must be a canonical OCI "
                "os/architecture[/variant]"
            )
        valid_from = version.get("valid_from")
        valid_to = version.get("valid_to")
        if (
            valid_from is not None
            and valid_to is not None
            and strict_canonical_datetime(valid_from)
            and strict_canonical_datetime(valid_to)
            and parse_utc_second(valid_from) > parse_utc_second(valid_to)
        ):
            errors.append(f"versions[{index}].valid_from must not be after valid_to")

    for index, occurrence in enumerate(arrays["occurrences"]):
        if not isinstance(occurrence, Mapping):
            continue
        first_seen = occurrence.get("first_seen")
        last_seen = occurrence.get("last_seen")
        if (
            strict_canonical_datetime(first_seen)
            and strict_canonical_datetime(last_seen)
            and parse_utc_second(first_seen) > parse_utc_second(last_seen)
        ):
            errors.append(
                f"occurrences[{index}].first_seen must not be after last_seen"
            )

    channel_ids: set[str] = set()
    for index, channel in enumerate(arrays["channels"]):
        if not isinstance(channel, Mapping):
            errors.append(f"channels[{index}] must be an object")
            continue
        channel_id = str(channel.get("channel_id") or "")
        if not channel_id:
            errors.append(f"channels[{index}].channel_id is required")
        elif channel_id in channel_ids:
            errors.append(f"duplicate channel_id {channel_id}")
        channel_ids.add(channel_id)
        if channel.get("component_id") not in {None, component_id}:
            errors.append(f"channels[{index}].component_id does not match component")
        if channel.get("channel_type") not in OFFICIAL_CHANNEL_TYPES:
            errors.append(f"channels[{index}].channel_type is unsupported")
        if channel.get("review_state") not in {"accepted", "needs-review"}:
            errors.append(
                f"channels[{index}].review_state must be accepted or needs-review"
            )
        state = str(channel.get("availability_state") or "")
        if state not in {"available", *EXPLICIT_CHANNEL_GAP_STATES}:
            errors.append(f"channels[{index}].availability_state is unsupported")
        if state == "available" and not channel.get("canonical_uri"):
            errors.append(f"channels[{index}] available channel lacks canonical_uri")

    snapshot_ids: set[str] = set()
    for index, snapshot in enumerate(arrays["snapshots"]):
        if not isinstance(snapshot, Mapping):
            errors.append(f"snapshots[{index}] must be an object")
            continue
        snapshot_id = str(snapshot.get("snapshot_id") or "")
        if not snapshot_id:
            errors.append(f"snapshots[{index}].snapshot_id is required")
        elif snapshot_id in snapshot_ids:
            errors.append(f"duplicate snapshot_id {snapshot_id}")
        snapshot_ids.add(snapshot_id)
        if snapshot.get("channel_id") not in channel_ids:
            errors.append(f"snapshots[{index}] references an unknown channel_id")
        if snapshot.get("component_version_id") not in version_ids:
            errors.append(
                f"snapshots[{index}] references an unknown component_version_id"
            )
        content_hash = snapshot.get("content_hash")
        if content_hash and not re.fullmatch(r"sha256:[0-9a-f]{64}", str(content_hash)):
            errors.append(f"snapshots[{index}].content_hash must be a full sha256")
        if snapshot.get("status") in {"fetched", "verified"} and not content_hash:
            errors.append(
                f"snapshots[{index}] fetched/verified status requires content_hash"
            )
    return sorted(set(errors))


def expand_reviewed_inputs(paths: Sequence[str]) -> list[str]:
    if len(paths) > MAX_DISCOVERY_FILES:
        raise RegistryInputError(
            f"reviewed inputs exceed file bound {MAX_DISCOVERY_FILES}"
        )
    expanded: list[str] = []
    for value in paths:
        path = Path(value)
        try:
            metadata = os.lstat(path)
        except OSError as exc:
            raise RegistryInputError(
                f"cannot inspect reviewed input {value}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RegistryInputError(f"reviewed input {value} must not be a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            entries = sorted(path.iterdir(), key=lambda item: item.name)
            if len(entries) > MAX_DISCOVERY_FILES:
                raise RegistryInputError(
                    f"reviewed input directory exceeds entry bound {MAX_DISCOVERY_FILES}"
                )
            for item in entries:
                item_metadata = os.lstat(item)
                if stat.S_ISLNK(item_metadata.st_mode):
                    raise RegistryInputError(
                        f"reviewed input {item} must not be a symlink"
                    )
                if item.suffix == ".json" and stat.S_ISREG(item_metadata.st_mode):
                    expanded.append(item.as_posix())
        else:
            expanded.append(value)
    if len(expanded) > MAX_DISCOVERY_FILES:
        raise RegistryInputError(
            f"reviewed inputs exceed file bound {MAX_DISCOVERY_FILES}"
        )
    preflight_regular_input_paths(
        expanded,
        max_files=MAX_DISCOVERY_FILES,
        label="reviewed inputs",
    )
    return expanded


def import_reviewed(paths: Sequence[str]) -> dict[str, Any]:
    records: list[tuple[str, Mapping[str, Any]]] = []
    expanded = expand_reviewed_inputs(paths)
    for path, payload, _raw in read_bounded_unique_json_inputs(
        expanded,
        max_files=MAX_DISCOVERY_FILES,
        max_total_bytes=MAX_JSON_INPUT_BYTES,
        label="reviewed inputs",
    ):
        if (
            not isinstance(payload, dict)
            or payload.get("record_kind") != "reviewed_component"
        ):
            raise ValueError(f"{path} is not a reviewed_component record")
        records.append(("stdin" if path == "-" else Path(path).as_posix(), payload))
    return reviewed_records_manifest(records)


REVIEWED_COMPONENT_KIND_ENUM = frozenset(
    {
        "product",
        "project",
        "runtime",
        "controller",
        "operator",
        "chart",
        "image",
        "package",
        "api",
        "cli",
        "library",
        "action",
        "provider",
        "module",
        "collection",
        "model",
        "dataset",
        "kubernetes-api",
        "kubernetes-crd",
        "git-repository",
        "helm-chart",
        "oci-image",
        "model-artifact",
    }
)


def channel_policy_validator() -> Any:
    return draft202012_validator(
        CHANNEL_POLICY_SCHEMA_RELATIVE,
        label="channel policy schema",
    )


def channel_policy_selector(policy: Mapping[str, Any]) -> str:
    scope = policy.get("scope")
    scope = scope if isinstance(scope, Mapping) else {}
    return str(scope.get("selector") or "ecosystem")


def _component_table_policy_errors(
    policy: Mapping[str, Any], tables: Mapping[str, Any]
) -> list[str]:
    """Fail-closed checks for research-corpus component-table policies."""

    errors: list[str] = []
    provenance_table = tables.get(CHANNEL_POLICY_PROVENANCE_TABLE)
    if not isinstance(provenance_table, Mapping) or not provenance_table:
        errors.append("component-table policy requires a non-empty tables.provenance")
        provenance_table = {}
    rows = policy.get("rows")
    if not isinstance(rows, Mapping) or not rows:
        errors.append("component-table policy requires non-empty rows")
        rows = {}
    for component_id in sorted(rows):
        entry = rows[component_id]
        label = f"rows.{component_id}"
        if not CHANNEL_POLICY_COMPONENT_ID_RE.fullmatch(str(component_id)):
            errors.append(f"{label} key must be a harvested component_id")
        if not isinstance(entry, Mapping):
            errors.append(f"{label} must be an object")
            continue
        channels = entry.get("channels")
        if not isinstance(channels, list):
            errors.append(f"{label}.channels must be an array")
            continue
        seen_types: list[str] = []
        for index, row in enumerate(channels):
            row_label = f"{label}.channels[{index}]"
            if not isinstance(row, Mapping):
                errors.append(f"{row_label} must be an object")
                continue
            channel_type = str(row.get("channel_type") or "")
            if channel_type not in OFFICIAL_CHANNEL_TYPES:
                errors.append(f"{row_label}.channel_type is unsupported")
            elif channel_type in seen_types:
                errors.append(f"{label} duplicate channel_type {channel_type}")
            seen_types.append(channel_type)
            disposition = str(row.get("disposition") or "")
            if disposition not in CHANNEL_POLICY_ROW_DISPOSITIONS:
                errors.append(f"{row_label}.disposition is unsupported")
            provenance = row.get("provenance")
            if not isinstance(provenance, Mapping):
                errors.append(f"{row_label} requires provenance")
                provenance = {}
            if str(provenance.get("pass") or "") not in CHANNEL_POLICY_ROW_PASSES:
                errors.append(f"{row_label}.provenance.pass is unsupported")
            refs = provenance.get("refs")
            if not isinstance(refs, list) or not refs:
                errors.append(f"{row_label}.provenance.refs must be non-empty")
                refs = []
            for ref in refs:
                if str(ref) not in provenance_table:
                    errors.append(
                        f"{row_label}.provenance references an unknown "
                        "tables.provenance entry"
                    )
            probe = row.get("probe")
            if disposition == "available":
                uri = row.get("canonical_uri")
                if (
                    not isinstance(uri, str)
                    or not uri.startswith("https://")
                    or not strict_uri_reference(uri, require_scheme=True)
                ):
                    errors.append(f"{row_label} available requires an https URI")
                if not str(row.get("publisher") or ""):
                    errors.append(f"{row_label} available requires publisher")
                if not isinstance(probe, Mapping):
                    # Fail closed: unprobed rows cannot claim availability.
                    errors.append(f"{row_label} available requires probe receipt")
                else:
                    status = probe.get("status")
                    if not isinstance(status, int) or not 200 <= status < 400:
                        errors.append(
                            f"{row_label}.probe.status must be a 2xx/3xx integer"
                        )
                    final_url = probe.get("final_url")
                    if not isinstance(final_url, str) or not strict_uri_reference(
                        final_url, require_scheme=True
                    ):
                        errors.append(f"{row_label}.probe.final_url must be a safe URI")
            elif not str(row.get("reason") or ""):
                errors.append(f"{row_label} non-available requires reason")
        missing_types = [
            channel_type
            for channel_type in OFFICIAL_CHANNEL_TYPES
            if channel_type not in seen_types
        ]
        if missing_types:
            errors.append(
                f"{label} must cover all 16 types; missing: " + ", ".join(missing_types)
            )
    return errors


def channel_policy_semantic_errors(policy: Mapping[str, Any]) -> list[str]:
    """Reject unratified or structurally dishonest channel policies (T3)."""

    errors: list[str] = []
    if policy.get("record_kind") != CHANNEL_POLICY_RECORD_KIND:
        errors.append(f"record_kind must equal {CHANNEL_POLICY_RECORD_KIND}")
    if not policy.get("record_id"):
        errors.append("record_id is required")
    review = policy.get("review")
    if not isinstance(review, Mapping):
        errors.append("review must be an object")
        review = {}
    if review.get("status") != "accepted":
        errors.append("channel policy is not ratified: review.status must be accepted")
    if not strict_canonical_date(review.get("reviewed_at")):
        errors.append("review.reviewed_at must be a canonical date")
    evidence = review.get("evidence")
    if not isinstance(evidence, list) or not any(
        isinstance(item, str) and item.startswith("sample-audit:") for item in evidence
    ):
        errors.append(
            "review.evidence must carry one sample-audit: slot (decision D-R2-1)"
        )
    scope = policy.get("scope")
    if not isinstance(scope, Mapping):
        errors.append("scope must be an object")
        scope = {}
    if not str(scope.get("ecosystem") or ""):
        errors.append("scope.ecosystem is required")
    preconditions = scope.get("preconditions")
    if not isinstance(preconditions, list) or not preconditions:
        errors.append("scope.preconditions must be a non-empty array")
        preconditions = []
    for index, precondition in enumerate(preconditions):
        if not isinstance(precondition, Mapping):
            errors.append(f"scope.preconditions[{index}] must be an object")
            continue
        if not str(precondition.get("field") or ""):
            errors.append(f"scope.preconditions[{index}].field is required")
        try:
            re.compile(str(precondition.get("pattern") or ""))
        except re.error as exc:
            errors.append(
                f"scope.preconditions[{index}].pattern is not a valid regex: {exc}"
            )
    tables = policy.get("tables")
    tables = tables if isinstance(tables, Mapping) else {}
    variables = policy.get("variables")
    if variables is not None and not isinstance(variables, Mapping):
        errors.append("variables must be an object")
        variables = {}
    for name, spec in (variables or {}).items():
        lookups = spec if isinstance(spec, list) else [spec]
        if not lookups:
            errors.append(f"variables.{name} must define table and key")
            continue
        for lookup in lookups:
            if not isinstance(lookup, Mapping) or not str(lookup.get("key") or ""):
                errors.append(f"variables.{name} must define table and key")
                continue
            if str(lookup.get("table") or "") not in tables:
                errors.append(f"variables.{name} references an unknown table")
    selector = channel_policy_selector(policy)
    if selector not in {"ecosystem", CHANNEL_POLICY_TABLE_SELECTOR}:
        errors.append("scope.selector is unsupported")
    if selector == CHANNEL_POLICY_TABLE_SELECTOR:
        if policy.get("channels"):
            errors.append("component-table policy must not define ecosystem channels")
        errors.extend(_component_table_policy_errors(policy, tables))
        return sorted(set(errors))
    if policy.get("rows"):
        errors.append("rows require scope.selector component-table")
    channels = policy.get("channels")
    if not isinstance(channels, list):
        errors.append("channels must be an array")
        channels = []
    seen_types: list[str] = []
    available_count = 0
    for index, spec in enumerate(channels):
        if not isinstance(spec, Mapping):
            errors.append(f"channels[{index}] must be an object")
            continue
        channel_type = str(spec.get("channel_type") or "")
        if channel_type not in OFFICIAL_CHANNEL_TYPES:
            errors.append(f"channels[{index}].channel_type is unsupported")
        elif channel_type in seen_types:
            errors.append(f"duplicate channel_type {channel_type}")
        seen_types.append(channel_type)
        disposition = str(spec.get("disposition") or "")
        if disposition not in CHANNEL_POLICY_DISPOSITIONS:
            errors.append(f"channels[{index}].disposition is unsupported")
        if disposition == "available":
            available_count += 1
            if not str(spec.get("uri_template") or ""):
                errors.append(f"channels[{index}] available requires uri_template")
            if not str(spec.get("publisher") or ""):
                errors.append(f"channels[{index}] available requires publisher")
            if spec.get("version_strategy") == "unresolved":
                errors.append(
                    f"channels[{index}] available forbids version_strategy unresolved"
                )
        elif not str(spec.get("gap_reason") or ""):
            errors.append(f"channels[{index}] non-available requires gap_reason")
    missing_types = [
        channel_type
        for channel_type in OFFICIAL_CHANNEL_TYPES
        if channel_type not in seen_types
    ]
    if missing_types:
        errors.append(
            "channels must cover all 16 types; missing: " + ", ".join(missing_types)
        )
    if available_count != 1:
        errors.append(
            "exactly one channel must have disposition available (decision D-R2-4)"
        )
    return sorted(set(errors))


def load_channel_policies(directory: str) -> list[dict[str, Any]]:
    """Load, validate and freeze-pin every ratified policy in a directory."""

    path = Path(directory)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RegistryInputError(f"cannot inspect policies {directory}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RegistryInputError(
            f"policies {directory} must be a non-symlink directory"
        )
    entries = sorted(item for item in path.iterdir() if item.suffix == ".json")
    if len(entries) > MAX_CHANNEL_POLICIES:
        raise RegistryInputError(
            f"channel policies exceed record bound {MAX_CHANNEL_POLICIES}"
        )
    validator = channel_policy_validator()
    policies: list[dict[str, Any]] = []
    ecosystems: dict[str, str] = {}
    record_ids: set[str] = set()
    for item in entries:
        item_metadata = os.lstat(item)
        if stat.S_ISLNK(item_metadata.st_mode) or not stat.S_ISREG(
            item_metadata.st_mode
        ):
            raise RegistryInputError(f"channel policy {item} must be a regular file")
        raw = read_regular_file(
            item,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label="channel policy",
        )
        payload = parse_json_bytes(raw, label=f"channel policy {item}")
        if not isinstance(payload, dict):
            raise RegistryInputError(f"channel policy {item} must be a JSON object")
        errors = [
            *schema_validation_errors(validator, payload),
            *channel_policy_semantic_errors(payload),
        ]
        if errors:
            raise RegistryInputError(
                f"{item} is not a ratified channel policy: "
                + "; ".join(errors[:MAX_SCHEMA_ERRORS])
            )
        ecosystem = str(payload["scope"]["ecosystem"])
        if ecosystem in ecosystems:
            raise RegistryInputError(
                f"one policy per ecosystem: {ecosystem} appears in "
                f"{ecosystems[ecosystem]} and {item}"
            )
        record_id = str(payload["record_id"])
        if record_id in record_ids:
            raise RegistryInputError(f"duplicate channel policy record_id {record_id}")
        ecosystems[ecosystem] = item.as_posix()
        record_ids.add(record_id)
        digest = file_hash(raw)
        policies.append(
            {
                "path": item.as_posix(),
                "sha256": digest,
                "citation": f"{item.as_posix()}@{digest}",
                "record": payload,
                "preconditions": [
                    (
                        str(precondition["field"]),
                        re.compile(str(precondition["pattern"])),
                    )
                    for precondition in payload["scope"]["preconditions"]
                ],
            }
        )
    return policies


def component_identity_candidates(component: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []
    purl = component.get("purl")
    if purl:
        candidates.append(str(purl))
    metadata = component.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    if metadata.get("oci_repository"):
        candidates.append(f"oci:{metadata['oci_repository']}")
    gvk = str(metadata.get("gvk") or "")
    if gvk.count("/") == 2:
        group_version, _, resource_kind = gvk.rpartition("/")
        candidates.append(f"gvk:{group_version}:{resource_kind}")
    ecosystem = str(component.get("ecosystem") or "")
    namespace = str(component.get("namespace") or "")
    name = str(component.get("name") or "")
    candidates.append(f"crd:{name}")
    candidates.append(f"{ecosystem}:{namespace}:{name}")
    candidates.append(f"sbom:{ecosystem}:{namespace}:{name}")
    source_repo = str(metadata.get("source_repo") or "")
    if source_repo:
        # Mirrors the git emitter grammars, including a None/empty path.
        candidates.append(f"git:{source_repo}:{metadata.get('path')}")
        candidates.append(f"git:{source_repo}:")
        candidates.append(f"git:{source_repo}")
        # The pre-commit emitter keys on the repository URL, not the hook name.
        candidates.append(f"pre-commit:{source_repo}")
    if name:
        # The workflow emitter keys on the owner/repo it parsed from `uses:`.
        candidates.append(f"github-action:{name}")
        # The mise/tool emitter keys a CLI on its bare name.
        candidates.append(f"cli:{name}")
        candidates.append(f"terraform-cli:hashicorp/{name}")
    artifact_identity = str(metadata.get("artifact_identity") or "")
    if artifact_identity:
        # Model artifacts hash the declared reference, not the display name.
        candidates.append(
            f"model-artifact:{component.get('ecosystem')}:{artifact_identity}"
        )
    if namespace and name:
        # Roots that hash the WHOLE path the namespace/name split came from.
        candidates.append(f"{ecosystem}:{namespace}/{name}")
    language = str(metadata.get("language") or "")
    if language:
        # Toolchains and their standard libraries key on the language alone.
        candidates.append(f"toolchain:{language}")
        candidates.append(f"stdlib:{language}")
    if ecosystem == "git" and name == "self":
        candidates.append("git:repository:self")
    download_uri = str(metadata.get("download_uri") or "")
    if download_uri:
        # Remote build inputs key on the URL, not the file name they land as.
        candidates.append(f"remote-input:{download_uri}")
        candidates.append(f"remote-artifact:{download_uri}")
    dynamic_input_identity = str(metadata.get("dynamic_input_identity") or "")
    if dynamic_input_identity:
        # Templated downloads key on the evidence locator, not the file name.
        candidates.append(f"remote-input-dynamic:{dynamic_input_identity}")
    source_address = str(metadata.get("source_address") or "")
    if source_address:
        candidates.append(f"terraform-provider:{source_address}")
    if name and str(component.get("ecosystem") or "") == "ansible":
        # Galaxy entries key on kind, the FULL namespace.name, and the source.
        kind = str(component.get("kind") or "")
        full = f"{namespace}.{name}" if namespace else name
        candidates.append(f"ansible:{kind}:{full}:{metadata.get('source') or ''}")
    if metadata.get("chart_repository"):
        candidates.append(f"helm:{metadata['chart_repository']}:{name}")
    repository = str(metadata.get("repository") or "")
    if repository:
        candidates.append(f"model-artifact:{ecosystem}:{repository}")
        filename = str(metadata.get("filename") or "")
        if filename:
            candidates.append(f"model-artifact:{ecosystem}:{repository}/{filename}")
    if metadata.get("storage_uri"):
        candidates.append(f"model-artifact:{ecosystem}:{metadata['storage_uri']}")
    asset = str(metadata.get("asset") or "")
    release_api = re.fullmatch(
        r"https://api\.github\.com/repos/([^/]+/[^/]+)/releases/tags/(.+)",
        str(metadata.get("release_api") or ""),
    )
    if asset and release_api:
        # Release assets hash the github-release:// reference, not the file name.
        candidates.append(
            f"model-artifact:{ecosystem}:github-release://"
            f"{release_api.group(1)}@{release_api.group(2)}/{asset}"
        )
    return candidates


def recover_component_identity(component: Mapping[str, Any]) -> str | None:
    """Return the identity that reproduces the harvested component_id, or None."""

    component_id = str(component.get("component_id") or "")
    kind = str(component.get("kind") or "")
    for candidate in component_identity_candidates(component):
        if stable_id("cmp", kind, candidate.lower()) == component_id:
            return candidate
    return None


class _ChannelTemplateContext(dict):
    def __missing__(self, key: str) -> str:
        raise KeyError(key)


def channel_policy_context(
    policy: Mapping[str, Any], component: Mapping[str, Any]
) -> dict[str, str]:
    purl = str(component.get("purl") or "")
    context = {
        "name": str(component.get("name") or ""),
        "namespace": str(component.get("namespace") or ""),
        "ecosystem": str(component.get("ecosystem") or ""),
        "purl": purl,
    }
    if "?" in purl:
        query = purl.split("?", 1)[1].split("#", 1)[0]
        for key, values in parse_qs(query, keep_blank_values=False).items():
            if values:
                context[f"q_{key}"] = values[0]
    metadata = component.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    for key, value in metadata.items():
        if isinstance(value, str) and value:
            context[f"m_{key}"] = value
    namespace = context["namespace"]
    name = context["name"]
    if name:
        # namespace==name is the whole-module vanity-host convention (golang v2).
        context["module"] = (
            name if not namespace or namespace == name else f"{namespace}/{name}"
        )
    tables = policy.get("tables")
    tables = tables if isinstance(tables, Mapping) else {}
    for variable, spec in (policy.get("variables") or {}).items():
        # Ordered fallback: a list of lookups resolves on the first table hit.
        for lookup in spec if isinstance(spec, list) else [spec]:
            if not isinstance(lookup, Mapping):
                continue
            table = tables.get(str(lookup.get("table") or ""))
            source = context.get(str(lookup.get("key") or ""))
            if isinstance(table, Mapping) and source is not None and source in table:
                context[str(variable)] = str(table[source])
                break
    return context


def render_channel_uri(template: str, context: Mapping[str, str]) -> str | None:
    try:
        rendered = str(template).format_map(_ChannelTemplateContext(context))
    except (IndexError, KeyError, ValueError):
        return None
    return rendered if strict_uri_reference(rendered, require_scheme=True) else None


def channel_policy_sample_ids(
    policy_hash: str,
    component_ids: Sequence[str],
    sample_size: int = CHANNEL_POLICY_SAMPLE_SIZE,
) -> list[str]:
    """Deterministic k-sample seeded from the policy hash (decision D-R2-1)."""

    ranked = sorted(
        component_ids,
        key=lambda component_id: (
            hashlib.sha256(f"{policy_hash}:{component_id}".encode("utf-8")).hexdigest(),
            component_id,
        ),
    )
    return ranked[:sample_size]


def _derived_channel(
    policy_entry: Mapping[str, Any],
    spec: Mapping[str, Any],
    component_id: str,
    context: Mapping[str, str],
    evidence_base: Sequence[str],
) -> dict[str, Any]:
    policy_record = policy_entry["record"]
    citation = str(policy_entry["citation"])
    channel_type = str(spec["channel_type"])
    disposition = str(spec["disposition"])
    template = str(spec.get("uri_template") or "")
    rendered = render_channel_uri(template, context) if template else None
    degraded = disposition == "available" and rendered is None
    channel: dict[str, Any] = {
        "channel_id": (
            f"chn:{policy_record['record_id']}:{component_id}:{channel_type}"
        ),
        "component_id": component_id,
        "channel_type": channel_type,
        "publisher": spec.get("publisher"),
        "access": str(
            spec.get("access")
            or ("public" if disposition == "available" else "unknown")
        ),
        "rights": spec.get("rights"),
        "refresh_policy": str(
            spec.get("refresh_policy")
            or ("on-version-change" if disposition == "available" else "policy-static")
        ),
        "discovery_method": str(spec.get("discovery_method") or "generated"),
        "confidence": str(
            spec.get("confidence")
            or (
                "medium"
                if disposition in {"available", "derived-unverified"}
                else "high"
            )
        ),
        "review_state": "accepted",
        "evidence": sorted(set(evidence_base)),
    }
    if disposition == "available" and not degraded:
        channel.update(
            {
                "availability_state": "available",
                "canonical_uri": rendered,
                "version_strategy": str(spec.get("version_strategy") or "per-version"),
                "gap": None,
            }
        )
        return channel
    gap_state = (
        "unresolved" if degraded or disposition == "derived-unverified" else disposition
    )
    gap_evidence = {citation}
    if rendered is not None and not degraded:
        gap_evidence.add(f"derived-uri:{rendered}")
    reason = (
        f"uri-template-unrenderable: {template}"
        if degraded
        else str(spec.get("gap_reason") or "")
    )
    next_action = spec.get("next_action")
    if next_action is None and (degraded or disposition == "derived-unverified"):
        next_action = "probe-wave"
    channel.update(
        {
            "availability_state": gap_state,
            "canonical_uri": None,
            "version_strategy": str(spec.get("version_strategy") or "unresolved"),
            "gap": {
                "state": gap_state,
                "reason": reason,
                "blocking": False,
                "evidence": sorted(gap_evidence),
                "next_action": next_action,
            },
        }
    )
    return channel


def _component_table_channel(
    policy_entry: Mapping[str, Any],
    row: Mapping[str, Any],
    component_id: str,
    evidence_base: Sequence[str],
) -> dict[str, Any]:
    """Instantiate one channel from a probe-verified research-corpus row."""

    policy_record = policy_entry["record"]
    citation = str(policy_entry["citation"])
    channel_type = str(row["channel_type"])
    disposition = str(row["disposition"])
    tables = policy_record.get("tables")
    tables = tables if isinstance(tables, Mapping) else {}
    provenance_table = tables.get(CHANNEL_POLICY_PROVENANCE_TABLE)
    provenance_table = provenance_table if isinstance(provenance_table, Mapping) else {}
    provenance = row.get("provenance")
    provenance = provenance if isinstance(provenance, Mapping) else {}
    provenance_evidence = {
        str(provenance_table[str(ref)])
        for ref in provenance.get("refs", [])
        if str(ref) in provenance_table
    }
    provenance_evidence.add(f"research-pass:{provenance.get('pass')}")
    probe = row.get("probe")
    probe = probe if isinstance(probe, Mapping) else None
    if probe is not None:
        provenance_evidence.add(f"probe:{probe.get('status')}:{probe.get('final_url')}")
    channel: dict[str, Any] = {
        "channel_id": (
            f"chn:{policy_record['record_id']}:{component_id}:{channel_type}"
        ),
        "component_id": component_id,
        "channel_type": channel_type,
        "publisher": row.get("publisher"),
        "access": str(
            row.get("access") or ("public" if disposition == "available" else "unknown")
        ),
        "rights": row.get("rights"),
        "refresh_policy": (
            "on-version-change" if disposition == "available" else "policy-static"
        ),
        "discovery_method": "inferred",
        "confidence": str(row.get("confidence") or "medium"),
        "review_state": "accepted",
        "evidence": sorted({*evidence_base, *provenance_evidence}),
    }
    if disposition == "available":
        channel.update(
            {
                "availability_state": "available",
                "canonical_uri": str(row["canonical_uri"]),
                "version_strategy": "catalog-only",
                "gap": None,
            }
        )
        return channel
    channel.update(
        {
            "availability_state": disposition,
            "canonical_uri": None,
            "version_strategy": "unresolved",
            "gap": {
                "state": disposition,
                "reason": str(row.get("reason") or ""),
                "blocking": False,
                "evidence": sorted({citation, *provenance_evidence}),
                "next_action": ("probe-wave" if disposition == "unresolved" else None),
            },
        }
    )
    return channel


def derived_component_record(
    policy_entry: Mapping[str, Any],
    component: Mapping[str, Any],
    identity: str,
    baseline_manifest_id: str,
    baseline_pointer: str | None,
    live_pointer: str | None = None,
    row_set: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    policy_record = policy_entry["record"]
    citation = str(policy_entry["citation"])
    component_id = str(component["component_id"])
    metadata = component.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    kind = str(component.get("kind") or "")
    context = channel_policy_context(policy_record, component)
    if live_pointer:
        # Live-capture binding for {evidence}/{evidence_document} templates.
        context["evidence"] = live_pointer
        context["evidence_document"] = live_pointer.partition("#")[0]
    evidence_base = {citation}
    if component.get("purl"):
        evidence_base.add(str(component["purl"]))
    if baseline_pointer:
        evidence_base.add(baseline_pointer)
    if live_pointer:
        evidence_base.add(live_pointer)
    if row_set is None:
        channels = [
            _derived_channel(
                policy_entry,
                spec,
                component_id,
                context,
                sorted(evidence_base),
            )
            for spec in policy_record["channels"]
        ]
    else:
        channels = [
            _component_table_channel(
                policy_entry,
                row,
                component_id,
                sorted(evidence_base),
            )
            for row in row_set["channels"]
        ]
    reviewed_at = str(policy_record["review"]["reviewed_at"])
    return {
        "$schema": (
            "https://github.com/cordanaLLM/knowledge/schemas/registry/"
            "component-record-v1.1.schema.json"
        ),
        "schema_version": "1.1.0",
        "record_kind": "reviewed_component",
        "record_id": f"record:{policy_record['record_id']}:{component_id}",
        "review": {
            "status": "accepted",
            "reviewed_by": (
                f"{CHANNEL_POLICY_REVIEWER_PREFIX}{policy_record['record_id']}"
                f"@{policy_entry['sha256']}"
            ),
            "reviewed_at": reviewed_at,
            "evidence": sorted({citation, f"baseline:{baseline_manifest_id}"}),
        },
        "component": {
            "component_id": component_id,
            "kind": kind if kind in REVIEWED_COMPONENT_KIND_ENUM else "package",
            "ecosystem": str(component.get("ecosystem") or "unknown"),
            "namespace": str(component.get("namespace") or "") or None,
            "name": str(component.get("name") or component_id),
            "aliases": [],
            "purl": str(component["purl"]) if component.get("purl") else None,
            "cpe": None,
            "oci_repository": (
                str(metadata["oci_repository"])
                if metadata.get("oci_repository")
                else None
            ),
            "chart_repository": None,
            "chart_name": None,
            "api_group": (
                str(metadata["api_group"]) if metadata.get("api_group") else None
            ),
            "gvk": [],
            "source_repo": None,
            "lifecycle": "deployed",
            "disposition": "selected",
            "owners": [],
            "topics": [],
            "authority_policy": "channel-policy-delegated-acceptance",
            "created_at": reviewed_at,
            "registry_kind": kind,
            "registry_identity": identity,
        },
        "versions": [],
        "occurrences": [],
        "dependencies": [],
        "channels": channels,
        "snapshots": [],
        "gaps": [],
    }


def derive_channel_records(
    manifest: Mapping[str, Any],
    policies: Sequence[Mapping[str, Any]],
) -> tuple[
    list[tuple[str, dict[str, Any]]],
    list[tuple[str, dict[str, Any]]],
    dict[str, Any],
]:
    """Deterministic offline channel-policy expansion (T3, fail-closed)."""

    errors = validate_manifest(manifest)
    if errors:
        raise RegistryInputError(
            "derive-channels baseline is invalid: " + "; ".join(errors[:20])
        )
    baseline_manifest_id = str(manifest.get("manifest_id") or "")
    policy_by_ecosystem = {
        str(policy["record"]["scope"]["ecosystem"]): policy
        for policy in policies
        if channel_policy_selector(policy["record"]) != CHANNEL_POLICY_TABLE_SELECTOR
    }
    table_policies = sorted(
        (
            policy
            for policy in policies
            if channel_policy_selector(policy["record"])
            == CHANNEL_POLICY_TABLE_SELECTOR
        ),
        key=lambda policy: str(policy["record"]["record_id"]),
    )
    evidence_by_component: dict[str, str] = {}
    live_evidence_by_component: dict[str, str] = {}
    for version in manifest.get("versions", []):
        if not isinstance(version, Mapping):
            continue
        component_id = str(version.get("component_id") or "")
        for item in version.get("evidence", []):
            if isinstance(item, str) and item:
                previous = evidence_by_component.get(component_id)
                if previous is None or item < previous:
                    evidence_by_component[component_id] = item
                if item.startswith("live-export:"):
                    live_previous = live_evidence_by_component.get(component_id)
                    if live_previous is None or item < live_previous:
                        live_evidence_by_component[component_id] = item
    validator = reviewed_record_validator()
    records: list[tuple[str, dict[str, Any]]] = []
    matched_by_policy: dict[str, list[str]] = {}
    skip_counts: Counter[str] = Counter()
    components = sorted(
        (
            component
            for component in manifest.get("components", [])
            if isinstance(component, Mapping) and component.get("component_id")
        ),
        key=lambda component: str(component["component_id"]),
    )
    for component in components:
        component_id = str(component["component_id"])
        if not component_requires_official_channels(component):
            skip_counts["not-required"] += 1
            continue
        if component_has_accepted_available_channel(component):
            skip_counts["already-closed"] += 1
            continue
        candidates: list[Mapping[str, Any]] = []
        ecosystem_entry = policy_by_ecosystem.get(str(component.get("ecosystem") or ""))
        if ecosystem_entry is not None:
            candidates.append(ecosystem_entry)
        candidates.extend(
            entry for entry in table_policies if component_id in entry["record"]["rows"]
        )
        if not candidates:
            skip_counts["no-policy"] += 1
            continue
        policy_entry = None
        for candidate in candidates:
            matched = True
            for field, pattern in candidate["preconditions"]:
                value: Any = component
                for token in str(field).split("."):
                    value = value.get(token) if isinstance(value, Mapping) else None
                if not isinstance(value, str) or not pattern.search(value):
                    matched = False
                    break
            if matched:
                policy_entry = candidate
                break
        if policy_entry is None:
            # Fail closed: nothing is emitted and the plain gap survives.
            skip_counts["precondition-mismatch"] += 1
            continue
        identity = recover_component_identity(component)
        if identity is None:
            skip_counts["identity-unrecoverable"] += 1
            continue
        row_set = (
            policy_entry["record"]["rows"][component_id]
            if channel_policy_selector(policy_entry["record"])
            == CHANNEL_POLICY_TABLE_SELECTOR
            else None
        )
        record = derived_component_record(
            policy_entry,
            component,
            identity,
            baseline_manifest_id,
            evidence_by_component.get(component_id),
            live_evidence_by_component.get(component_id),
            row_set=row_set,
        )
        record_errors = [
            *schema_validation_errors(validator, record),
            *validate_reviewed_record_semantics(record),
            *validate_reviewed_uri_safety(record),
        ]
        if record_errors:
            raise RegistryInputError(
                f"derived record for {component_id} is invalid: "
                + "; ".join(record_errors[:MAX_SCHEMA_ERRORS])
            )
        records.append((component_id, record))
        matched_by_policy.setdefault(
            str(policy_entry["record"]["record_id"]), []
        ).append(component_id)

    record_by_component = dict(records)
    samples: list[tuple[str, dict[str, Any]]] = []
    policy_summaries: list[dict[str, Any]] = []
    for policy in policies:
        ecosystem = str(policy["record"]["scope"]["ecosystem"])
        matched_ids = matched_by_policy.get(str(policy["record"]["record_id"]), [])
        sample_ids = channel_policy_sample_ids(str(policy["sha256"]), matched_ids)
        sample_name = f"sample-{ecosystem}.json"
        samples.append(
            (
                sample_name,
                {
                    "record_kind": "channel_policy_sample_audit",
                    "policy_record_id": str(policy["record"]["record_id"]),
                    "policy_sha256": str(policy["sha256"]),
                    "policy_path": str(policy["path"]),
                    "sample_size": len(sample_ids),
                    "total_matched": len(matched_ids),
                    "entries": [
                        {
                            "component_id": component_id,
                            "name": record_by_component[component_id]["component"][
                                "name"
                            ],
                            "purl": record_by_component[component_id]["component"][
                                "purl"
                            ],
                            "channels": [
                                {
                                    "channel_type": channel["channel_type"],
                                    "availability_state": channel["availability_state"],
                                    "canonical_uri": channel["canonical_uri"],
                                }
                                for channel in record_by_component[component_id][
                                    "channels"
                                ]
                            ],
                        }
                        for component_id in sample_ids
                    ],
                },
            )
        )
        policy_summaries.append(
            {
                "record_id": str(policy["record"]["record_id"]),
                "path": str(policy["path"]),
                "sha256": str(policy["sha256"]),
                "ecosystem": ecosystem,
                "matched": len(matched_ids),
                "expected_accepted_slots_delta": len(matched_ids)
                * len(OFFICIAL_CHANNEL_TYPES),
                "sample_artifact": sample_name,
                "sample_component_ids": sample_ids,
            }
        )
    summary = {
        "record_kind": "channel_policy_derivation_summary",
        "baseline_manifest_id": baseline_manifest_id,
        "policies": policy_summaries,
        "components_considered": len(components),
        "records_emitted": len(records),
        "expected_accepted_slots_delta": len(records) * len(OFFICIAL_CHANNEL_TYPES),
        "skipped": {key: skip_counts[key] for key in sorted(skip_counts)},
    }
    return records, samples, summary


def derive_channels_command(
    baseline_path: str,
    policies_dir: str,
    output_dir: str,
    snapshot_receipts: str | None = None,
) -> dict[str, Any]:
    manifest = load_json(baseline_path)
    policies = load_channel_policies(policies_dir)
    if not policies:
        raise RegistryInputError(f"no channel policies found in {policies_dir}")
    records, samples, summary = derive_channel_records(manifest, policies)
    if snapshot_receipts:
        summary["snapshot_binding"] = bind_channel_snapshot_receipts(
            records, manifest, snapshot_receipts
        )
    output = Path(output_dir)
    records_dir = output / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    for component_id, record in records:
        write_json(record, (records_dir / f"{component_id}.json").as_posix())
    for name, sample in samples:
        write_json(sample, (output / name).as_posix())
    write_json(summary, (output / "derive-channels-summary.json").as_posix())
    return summary


def _manifest_component_map(
    manifest: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    return {
        str(component["component_id"]): component
        for component in manifest.get("components", [])
        if isinstance(component, Mapping) and component.get("component_id")
    }


def _reviewed_slot_count(components: Mapping[str, Mapping[str, Any]]) -> int:
    reviewed = 0
    for component in components.values():
        if not component.get("official_channel_required", True):
            continue
        reviewed_types = {
            str(channel.get("channel_type") or "")
            for channel in component.get("official_channels", [])
            if isinstance(channel, Mapping) and channel_class_is_reviewed(channel)
        }
        reviewed += len(reviewed_types & set(OFFICIAL_CHANNEL_TYPES))
    return reviewed


def _policy_stamped_ids(components: Mapping[str, Mapping[str, Any]]) -> set[str]:
    """Components a channel policy has stamped, restricted to the denominator."""

    stamped: set[str] = set()
    for component_id, component in components.items():
        if not component.get("official_channel_required", True):
            continue
        metadata = component.get("metadata")
        review = metadata.get("review") if isinstance(metadata, Mapping) else None
        reviewed_by = (
            str(review.get("reviewed_by") or "") if isinstance(review, Mapping) else ""
        )
        if reviewed_by.startswith(CHANNEL_POLICY_REVIEWER_PREFIX):
            stamped.add(component_id)
    return stamped


def _official_channel_gap_count(manifest: Mapping[str, Any]) -> int:
    return sum(
        1
        for gap in manifest.get("gaps", [])
        if isinstance(gap, Mapping)
        and gap.get("gap_type") == "official-channel-unresolved"
    )


def channel_wave_gate(
    baseline: Mapping[str, Any],
    merged: Mapping[str, Any],
    *,
    policies: Sequence[Mapping[str, Any]],
    expected_matched: int | None = None,
) -> dict[str, Any]:
    """Mechanical per-wave gate (T4): identity closure, slot arithmetic, bindings."""

    checks: dict[str, dict[str, Any]] = {}
    merged_errors = validate_manifest(merged)
    checks["merged-valid"] = {
        "pass": not merged_errors,
        "errors": merged_errors[:20],
    }
    baseline_components = _manifest_component_map(baseline)
    merged_components = _manifest_component_map(merged)
    new_ids = sorted(set(merged_components) - set(baseline_components))
    removed_ids = sorted(set(baseline_components) - set(merged_components))
    checks["zero-new-components"] = {
        "pass": not new_ids and not removed_ids,
        "new_component_ids": new_ids[:50],
        "removed_component_ids": removed_ids[:50],
    }
    reclassified: list[str] = []
    unexplained_flag_changes: list[str] = []
    for component_id, merged_component in merged_components.items():
        baseline_component = baseline_components.get(component_id)
        if baseline_component is None:
            continue
        baseline_flag = bool(baseline_component.get("official_channel_required", True))
        merged_flag = bool(merged_component.get("official_channel_required", True))
        if baseline_flag and not merged_flag:
            if sbom_path_artifact_component(merged_component):
                reclassified.append(component_id)
            else:
                unexplained_flag_changes.append(component_id)
        elif merged_flag and not baseline_flag:
            unexplained_flag_changes.append(component_id)
    required_baseline = sum(
        1
        for component in baseline_components.values()
        if component.get("official_channel_required", True)
    ) * len(OFFICIAL_CHANNEL_TYPES)
    required_merged = sum(
        1
        for component in merged_components.values()
        if component.get("official_channel_required", True)
    ) * len(OFFICIAL_CHANNEL_TYPES)
    expected_required = required_baseline - len(reclassified) * len(
        OFFICIAL_CHANNEL_TYPES
    )
    checks["required-slots"] = {
        "pass": required_merged == expected_required and not unexplained_flag_changes,
        "baseline": required_baseline,
        "merged": required_merged,
        "expected": expected_required,
        "reclassified_components": len(reclassified),
        "reclassified_component_ids": sorted(reclassified),
        "unexplained_flag_changes": sorted(unexplained_flag_changes)[:50],
    }
    accepted_baseline = _reviewed_slot_count(baseline_components)
    accepted_merged = _reviewed_slot_count(merged_components)
    accepted_delta = accepted_merged - accepted_baseline
    policy_stamped = _policy_stamped_ids(merged_components)
    baseline_stamped = _policy_stamped_ids(baseline_components)
    # Only stamps this wave added may promise the delta; inherited ones cannot.
    wave_stamped = policy_stamped - baseline_stamped
    reclassified_accepted = _reviewed_slot_count(
        {
            component_id: baseline_components[component_id]
            for component_id in reclassified
        }
    )
    expected_delta = (
        len(wave_stamped) * len(OFFICIAL_CHANNEL_TYPES) - reclassified_accepted
    )
    checks["accepted-slots"] = {
        "pass": accepted_delta == expected_delta
        and (expected_matched is None or len(wave_stamped) == expected_matched),
        "baseline": accepted_baseline,
        "merged": accepted_merged,
        "delta": accepted_delta,
        "expected_delta": expected_delta,
        "policy_stamped_components": len(policy_stamped),
        "baseline_policy_stamped_components": len(baseline_stamped),
        "wave_policy_stamped_components": len(wave_stamped),
        "reclassified_accepted_slots": reclassified_accepted,
        "expected_matched": expected_matched,
    }
    gained_available = [
        component_id
        for component_id, component in merged_components.items()
        if component.get("official_channel_required", True)
        and component_has_accepted_available_channel(component)
        and not component_has_accepted_available_channel(
            baseline_components.get(component_id, {})
        )
    ]
    baseline_gaps = _official_channel_gap_count(baseline)
    merged_gaps = _official_channel_gap_count(merged)
    checks["gap-arithmetic"] = {
        "pass": baseline_gaps - merged_gaps
        == len(gained_available) + len(reclassified),
        "baseline_official_channel_unresolved": baseline_gaps,
        "merged_official_channel_unresolved": merged_gaps,
        "components_gained_available_channel": len(gained_available),
        "reclassified_components": len(reclassified),
    }
    unaccepted_available: list[str] = []
    for component_id, component in merged_components.items():
        for channel in component.get("official_channels", []):
            if (
                isinstance(channel, Mapping)
                and channel_is_available(channel)
                and channel.get("review_state") != "accepted"
            ):
                unaccepted_available.append(
                    str(channel.get("channel_id") or component_id)
                )
    checks["available-implies-accepted"] = {
        "pass": not unaccepted_available,
        "violations": sorted(unaccepted_available)[:50],
    }
    policy_hash_by_record_id = {
        str(policy["record"]["record_id"]): str(policy["sha256"]) for policy in policies
    }
    policy_hash_by_basename = {
        Path(str(policy["path"])).name: str(policy["sha256"]) for policy in policies
    }
    binding_violations: list[str] = []

    def check_citation(value: str, context: str) -> None:
        citation = CHANNEL_POLICY_CITATION_RE.match(value)
        if citation:
            basename = Path(citation["path"]).name
            if policy_hash_by_basename.get(basename) != citation["hash"]:
                binding_violations.append(f"{context}: {value}")
            return
        reviewer = CHANNEL_POLICY_REVIEWER_RE.match(value)
        if reviewer and (
            policy_hash_by_record_id.get(reviewer["record_id"]) != reviewer["hash"]
        ):
            binding_violations.append(f"{context}: {value}")

    for component_id, component in merged_components.items():
        metadata = component.get("metadata")
        review = metadata.get("review") if isinstance(metadata, Mapping) else None
        if isinstance(review, Mapping):
            reviewed_by = str(review.get("reviewed_by") or "")
            if reviewed_by.startswith(CHANNEL_POLICY_REVIEWER_PREFIX):
                check_citation(reviewed_by, component_id)
            for item in review.get("evidence", []):
                if isinstance(item, str):
                    check_citation(item, component_id)
        for channel in component.get("official_channels", []):
            if not isinstance(channel, Mapping):
                continue
            for item in channel.get("evidence", []):
                if isinstance(item, str):
                    check_citation(item, component_id)
    checks["policy-bindings"] = {
        "pass": not binding_violations,
        "violations": sorted(binding_violations)[:50],
    }
    return {
        "pass": all(check["pass"] for check in checks.values()),
        "checks": checks,
    }


def snapshot_receipt_validator() -> Any:
    return draft202012_validator(
        SNAPSHOT_RECEIPT_SCHEMA_RELATIVE,
        label="channel snapshot receipt schema",
    )


def _snapshot_cas_read(receipts_root: Path, cas_path: str) -> bytes:
    parts = cas_path.split("/") if cas_path else []
    if (
        not parts
        or cas_path.startswith("/")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise RegistryInputError(
            f"receipt cas_path {cas_path!r} must stay inside the receipts directory"
        )
    return read_regular_file(
        receipts_root / cas_path,
        max_bytes=SNAPSHOT_CAS_MAX_BYTES,
        label=f"snapshot CAS artifact {cas_path}",
    )


def _snapshot_receipt_cas_error(
    receipts_root: Path, row: Mapping[str, Any]
) -> str | None:
    if row.get("status") not in SNAPSHOT_SATISFYING_STATUSES:
        return None
    try:
        data = _snapshot_cas_read(receipts_root, str(row.get("cas_path") or ""))
    except RegistryInputError as exc:
        return str(exc)
    if file_hash(data) != row.get("content_hash"):
        return "CAS artifact hash does not match the receipt content_hash"
    return None


def load_snapshot_receipts(
    receipts_dir: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load JSONL receipt rows; invalid rows are rejected with reasons, not bound."""

    rows_dir = Path(receipts_dir) / "receipts"
    try:
        metadata = os.lstat(rows_dir)
    except OSError as exc:
        raise RegistryInputError(
            f"snapshot receipts directory {rows_dir} is unreadable: {exc}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RegistryInputError(
            f"snapshot receipts directory {rows_dir} must be a real directory"
        )
    files = sorted(item for item in rows_dir.iterdir() if item.suffix == ".jsonl")
    if not files:
        raise RegistryInputError(f"no .jsonl receipt files found in {rows_dir}")
    if len(files) > MAX_DISCOVERY_FILES:
        raise RegistryInputError(
            f"receipt files exceed file bound {MAX_DISCOVERY_FILES}"
        )
    validator = snapshot_receipt_validator()
    rows: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in files:
        raw = read_regular_file(
            path,
            max_bytes=MAX_DISCOVERY_FILE_BYTES,
            label=f"snapshot receipts {path.name}",
        )
        for line_number, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            if len(rows) + len(rejected) >= MAX_SNAPSHOT_RECEIPT_ROWS:
                raise RegistryInputError(
                    f"receipt rows exceed bound {MAX_SNAPSHOT_RECEIPT_ROWS}"
                )
            context = f"{path.name}:{line_number}"
            try:
                row = parse_json_bytes(
                    line,
                    label=f"snapshot receipt {context}",
                    max_bytes=MAX_DISCOVERY_FILE_BYTES,
                )
            except RegistryInputError as exc:
                rejected.append({"receipt": context, "reason": str(exc)})
                continue
            if not isinstance(row, dict):
                rejected.append(
                    {"receipt": context, "reason": "receipt row must be a JSON object"}
                )
                continue
            errors = schema_validation_errors(validator, row)
            if errors:
                rejected.append({"receipt": context, "reason": errors[0]})
                continue
            key = canonical_json(row)
            if key in seen:
                # Byte-identical rows from resumed runs collapse to one receipt.
                continue
            seen.add(key)
            rows.append({"context": context, "row": row})
    return rows, rejected


def _immutable_resolution_value(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not SNAPSHOT_MUTABLE_RESOLUTION_RE.match(value)
    )


def snapshot_reviewed_version_entry(
    component_id: str,
    baseline_versions: Sequence[Mapping[str, Any]],
    fallback_observed_at: str | None,
    *,
    ecosystem: str,
    kind: str,
) -> dict[str, Any] | None:
    """Copy one baseline version whose exact scalars the reviewed schema can express."""

    is_oci = ecosystem == "oci" or kind in {"image", "oci-image"}
    for version in sorted(
        (item for item in baseline_versions if isinstance(item, Mapping)),
        key=lambda item: str(item.get("component_version_id") or ""),
    ):
        version_id = str(version.get("component_version_id") or "")
        resolution_state = str(version.get("resolution_state") or "")
        evidence = sorted(
            {
                item
                for item in version.get("evidence", [])
                if isinstance(item, str) and item
            }
        )
        metadata = version.get("metadata")
        observed_at = (
            metadata.get("observed_at") if isinstance(metadata, Mapping) else None
        )
        if not valid_live_observed_at(observed_at):
            observed_at = fallback_observed_at
        resolved_version = version.get("resolved_version")
        source_ref = version.get("source_ref")
        artifact_digest = version.get("artifact_digest")
        platform = version.get("platform")
        if (
            not version_id
            or resolution_state
            not in {"resolved", "partial", "unresolved", "ambiguous", "unavailable"}
            or not evidence
            or not valid_live_observed_at(observed_at)
        ):
            continue
        if resolution_state == "resolved":
            if resolved_version is None:
                # Null resolved_version is legal when source_ref alone is immutable.
                if not _immutable_resolution_value(source_ref):
                    continue
            elif not _immutable_resolution_value(resolved_version):
                continue
            elif source_ref is not None and not _immutable_resolution_value(source_ref):
                continue
            if is_oci:
                digest_value, digest_error = normalize_oci_digest(
                    str(artifact_digest) if artifact_digest is not None else None
                )
                if not digest_value or digest_error:
                    continue
            elif resolved_version is not None and not (
                looks_exact(str(resolved_version))
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(artifact_digest or ""))
                or (
                    looks_exact(str(source_ref or ""))
                    and str(source_ref or "").lower() not in MUTABLE_REFS
                )
            ):
                continue
        if artifact_digest is not None and not re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(artifact_digest)
        ):
            continue
        if platform is not None and (
            not isinstance(platform, str)
            or normalize_oci_platform(platform) != platform
        ):
            continue
        return {
            "component_version_id": version_id,
            "component_id": component_id,
            "purl": None,
            "constraint": (
                str(version["constraint"]) if version.get("constraint") else None
            ),
            "resolved_version": str(resolved_version) if resolved_version else None,
            "source_ref": str(source_ref) if source_ref else None,
            "artifact_digest": str(artifact_digest) if artifact_digest else None,
            "platform": str(platform) if platform else None,
            "build_metadata": {},
            "release_time": None,
            "observed_at": str(observed_at),
            "valid_from": None,
            "valid_to": None,
            "resolution_state": resolution_state,
            "evidence": evidence,
        }
    return None


def _snapshot_record_from_receipt(
    channel_id: str, component_version_id: str, row: Mapping[str, Any]
) -> dict[str, Any]:
    content_hash = row.get("content_hash")
    suffix = (
        content_hash[7:19]
        if isinstance(content_hash, str)
        else hashlib.sha256(canonical_json(row).encode("utf-8")).hexdigest()[:12]
    )
    return {
        "snapshot_id": f"snap:{channel_id}:{suffix}",
        "channel_id": channel_id,
        "component_version_id": component_version_id,
        "resolved_uri": row.get("resolved_uri"),
        "upstream_ref": row.get("upstream_ref"),
        "fetched_at": row.get("fetched_at"),
        "observed_at": str(row["observed_at"]),
        "etag": row.get("etag"),
        "last_modified": row.get("last_modified"),
        "content_hash": content_hash,
        "media_type": row.get("media_type"),
        "language": None,
        "coordinates": dict(row.get("coordinates") or {}),
        "status": str(row["status"]),
        "supersedes": [],
        "error_state": row.get("error_state"),
    }


def bind_channel_snapshot_receipts(
    records: Sequence[tuple[str, dict[str, Any]]],
    baseline: Mapping[str, Any],
    receipts_dir: str,
) -> dict[str, Any]:
    """Populate derived-record versions/snapshots from verified receipts (T-R3-1)."""

    rows, rejected = load_snapshot_receipts(receipts_dir)
    receipts_root = Path(receipts_dir)
    versions_by_component: dict[str, list[Mapping[str, Any]]] = {}
    for version in baseline.get("versions", []):
        if isinstance(version, Mapping) and version.get("component_id"):
            versions_by_component.setdefault(str(version["component_id"]), []).append(
                version
            )
    observation = baseline.get("observation")
    fallback_observed_at = (
        str(observation["observed_at"])
        if isinstance(observation, Mapping) and observation.get("observed_at")
        else None
    )
    channel_index: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, (_component_id, record) in enumerate(records):
        for channel in record.get("channels", []):
            if (
                isinstance(channel, Mapping)
                and channel.get("availability_state") == "available"
                and channel.get("channel_id")
            ):
                channel_index[str(channel["channel_id"])] = (index, channel)
    unbound: dict[str, str] = {}
    accepted_rows: dict[str, tuple[dict[str, Any], str]] = {}
    for entry in rows:
        row, context = entry["row"], entry["context"]
        cas_error = _snapshot_receipt_cas_error(receipts_root, row)
        for raw_channel_id in row["channel_ids"]:
            channel_id = str(raw_channel_id)
            if channel_id in unbound:
                continue
            if cas_error:
                unbound[channel_id] = f"{context}: {cas_error}"
                accepted_rows.pop(channel_id, None)
                continue
            located = channel_index.get(channel_id)
            if located is None:
                unbound[channel_id] = (
                    f"{context}: receipt does not match a derived available channel"
                )
                continue
            if located[1].get("canonical_uri") != row.get("canonical_uri"):
                unbound[channel_id] = (
                    f"{context}: receipt canonical_uri does not match the channel"
                )
                accepted_rows.pop(channel_id, None)
                continue
            if channel_id in accepted_rows and accepted_rows[channel_id][0] != row:
                unbound[channel_id] = "conflicting receipts for one channel"
                accepted_rows.pop(channel_id)
                continue
            accepted_rows[channel_id] = (row, context)
    validator = reviewed_record_validator()
    by_record: dict[int, list[tuple[str, dict[str, Any]]]] = {}
    for channel_id, (row, _context) in accepted_rows.items():
        by_record.setdefault(channel_index[channel_id][0], []).append((channel_id, row))
    bound: list[str] = []
    for index in sorted(by_record):
        items = sorted(by_record[index], key=lambda item: item[0])
        component_id, record = records[index]
        component = record.get("component", {})
        version_entry = snapshot_reviewed_version_entry(
            component_id,
            versions_by_component.get(component_id, []),
            fallback_observed_at or min(str(row["observed_at"]) for _, row in items),
            ecosystem=str(component.get("ecosystem") or ""),
            kind=str(component.get("kind") or ""),
        )
        if version_entry is None:
            for channel_id, _row in items:
                unbound[channel_id] = (
                    "no baseline version is expressible as a reviewed version"
                )
            continue
        record["versions"] = [version_entry]
        record["snapshots"] = sorted(
            (
                _snapshot_record_from_receipt(
                    channel_id, version_entry["component_version_id"], row
                )
                for channel_id, row in items
            ),
            key=lambda item: str(item["snapshot_id"]),
        )
        record_errors = [
            *schema_validation_errors(validator, record),
            *validate_reviewed_record_semantics(record),
            *validate_reviewed_uri_safety(record),
        ]
        if record_errors:
            record["versions"] = []
            record["snapshots"] = []
            for channel_id, _row in items:
                unbound[channel_id] = (
                    f"bound record failed validation: {record_errors[0]}"
                )
            continue
        bound.extend(channel_id for channel_id, _row in items)
    receipted = {
        str(channel_id) for entry in rows for channel_id in entry["row"]["channel_ids"]
    }
    return {
        "receipts_dir": receipts_root.as_posix(),
        "receipt_rows": len(rows),
        "receipt_rows_rejected": len(rejected),
        "rejected_receipts": rejected[:MAX_SCHEMA_ERRORS],
        "channels_receipted": len(receipted),
        "channels_bound": len(bound),
        "bound_channel_ids_digest": digest_ids(bound),
        "channels_unbound": [
            {"channel_id": channel_id, "reason": unbound[channel_id]}
            for channel_id in sorted(unbound)
        ],
    }


def gitops_commit_receipts(
    receipts_dir: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return CAS-verified Git commit-object receipts; everything else is refused."""

    rows, rejected = load_snapshot_receipts(receipts_dir)
    receipts_root = Path(receipts_dir)
    verified: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = list(rejected)
    for entry in rows:
        row, context = entry["row"], entry["context"]
        if row.get("media_type") != GITOPS_COMMIT_MEDIA_TYPE:
            continue
        commit = str(row.get("upstream_ref") or "")
        if row.get(
            "status"
        ) not in SNAPSHOT_SATISFYING_STATUSES or not GIT_COMMIT_ID_RE.fullmatch(commit):
            refused.append(
                {"receipt": context, "reason": "not a satisfying commit-object receipt"}
            )
            continue
        cas_error = _snapshot_receipt_cas_error(receipts_root, row)
        if cas_error:
            refused.append({"receipt": context, "reason": cas_error})
            continue
        data = _snapshot_cas_read(receipts_root, str(row.get("cas_path") or ""))
        if _git_object_id("commit", data, len(commit)) != commit:
            refused.append(
                {
                    "receipt": context,
                    "reason": "CAS bytes are not the claimed commit object",
                }
            )
            continue
        verified.append({"context": context, "row": row, "commit": commit})
    return verified, refused


def bind_gitops_identity(
    baseline: Mapping[str, Any],
    receipts_dir: str,
    *,
    observed_ref: str = "main",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bind the commit a deliberate self-repository ref pointed at when observed."""

    errors = validate_manifest(baseline)
    if errors:
        raise RegistryInputError("baseline is invalid: " + "; ".join(errors[:20]))
    normalized_ref = observed_ref.lower()
    if normalized_ref not in MUTABLE_REFS and not normalized_ref.startswith(
        "refs/heads/"
    ):
        raise RegistryInputError(
            f"--observed-ref {observed_ref!r} is not a mutable ref"
        )
    components = _manifest_component_map(baseline)
    versions_by_component: dict[str, list[Mapping[str, Any]]] = {}
    for version in baseline.get("versions", []):
        if isinstance(version, Mapping) and version.get("component_id"):
            versions_by_component.setdefault(str(version["component_id"]), []).append(
                version
            )
    verified, refused = gitops_commit_receipts(receipts_dir)
    builder = Builder()
    bound_versions: list[str] = []
    bound_components: set[str] = set()
    skipped: Counter[str] = Counter()
    for receipt in verified:
        row = receipt["row"]
        observation = {
            "evidence_cas_path": str(row["cas_path"]),
            "evidence_content_hash": str(row["content_hash"]),
            "observed_at": str(row["observed_at"]),
            "observed_commit": receipt["commit"],
            "observed_ref": normalized_ref,
            "receipt_canonical_uri": str(row["canonical_uri"]),
            "resolver": "git-commit-object-receipt",
        }
        source_id = builder.add_source(
            f"gitops-observation:{row['content_hash']}",
            "gitops-source-observation",
            content_hash=str(row["content_hash"]),
            metadata={
                "evidence_class": "repository",
                "receipt": {
                    "canonical_uri": str(row["canonical_uri"]),
                    "cas_path": str(row["cas_path"]),
                    "observed_at": str(row["observed_at"]),
                    "runner_version": str(row.get("runner_version") or ""),
                    "upstream_ref": receipt["commit"],
                },
            },
        )
        for raw_channel_id in row["channel_ids"]:
            located = CHANNEL_ID_COMPONENT_RE.search(str(raw_channel_id))
            if located is None:
                skipped["channel-not-component-bound"] += 1
                continue
            component_id = located["component_id"]
            component = components.get(component_id)
            metadata = (
                component.get("metadata") if isinstance(component, Mapping) else None
            )
            if (
                component is None
                or str(component.get("ecosystem") or "") != "git"
                or not isinstance(metadata, Mapping)
                or metadata.get("self_repository") is not True
            ):
                skipped["not-a-self-repository-component"] += 1
                continue
            lifecycles = [
                str(item) for item in component.get("lifecycles", []) if str(item)
            ]
            identity = recover_component_identity(component)
            if identity is None or not lifecycles:
                skipped["identity-unrecoverable"] += 1
                continue
            lifecycle = (
                "repository-used" if "repository-used" in lifecycles else lifecycles[0]
            )
            for version in versions_by_component.get(component_id, []):
                version_ref = str(
                    version.get("source_ref") or version.get("resolved_version") or ""
                ).lower()
                if version_ref != normalized_ref or version.get("artifact_digest"):
                    continue
                bound_component_id = builder.add_component(
                    kind=str(component.get("kind") or ""),
                    ecosystem=str(component.get("ecosystem") or ""),
                    name=str(component.get("name") or ""),
                    namespace=str(component.get("namespace") or ""),
                    purl=str(component["purl"]) if component.get("purl") else None,
                    identity=identity,
                    lifecycles=tuple(lifecycles),
                    metadata=metadata,
                    official_channel_required=bool(
                        component.get("official_channel_required", True)
                    ),
                )
                version_id = builder.add_version(
                    bound_component_id,
                    resolved_version=version.get("resolved_version"),
                    constraint=version.get("constraint"),
                    source_ref=version.get("source_ref"),
                    artifact_digest=version.get("artifact_digest"),
                    platform=version.get("platform"),
                    resolution_state=str(version.get("resolution_state") or ""),
                    evidence=tuple(
                        str(item) for item in version.get("evidence", []) if item
                    ),
                    metadata={GITOPS_OBSERVATION_KEY: observation},
                )
                if bound_component_id != component_id or version_id != str(
                    version["component_version_id"]
                ):
                    # Fail closed: a re-minted identity would be a new record.
                    raise RegistryInputError(
                        f"identity binding does not reproduce {component_id} "
                        f"{version['component_version_id']}"
                    )
                builder.add_occurrence(
                    component_id,
                    version_id,
                    source_id,
                    locator=f"/receipts/{receipt['context']}",
                    role="gitops-source-observation",
                    raw_value=receipt["commit"],
                    dependency_scope="deployment",
                    lifecycle=lifecycle,
                )
                bound_versions.append(version_id)
                bound_components.add(component_id)
    fragment = builder.manifest()
    summary = {
        "record_kind": "gitops_identity_binding_summary",
        "baseline_manifest_id": str(baseline.get("manifest_id") or ""),
        "observed_ref": normalized_ref,
        "receipts_dir": Path(receipts_dir).as_posix(),
        "receipts_verified": len(verified),
        "receipts_refused": len(refused),
        "refused_receipts": refused[:MAX_SCHEMA_ERRORS],
        "commits": sorted({receipt["commit"] for receipt in verified}),
        "components_bound": len(bound_components),
        "versions_bound": len(bound_versions),
        "bound_version_ids_digest": digest_ids(bound_versions),
        "skipped": {key: skipped[key] for key in sorted(skipped)},
        "fragment_manifest_id": str(fragment.get("manifest_id") or ""),
    }
    return fragment, summary


def _oci_receipt_resolution(
    receipts_root: Path, row: Mapping[str, Any], oci: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Re-derive a registry-manifest receipt from CAS; None means a typed failure."""

    registry = str(oci.get("registry") or "")
    repository = str(oci.get("repository") or "")
    reference = str(oci.get("reference") or "")
    reference_kind = str(oci.get("reference_kind") or "")
    if not registry or not repository or not reference_kind or not reference:
        raise RegistryInputError("OCI receipt coordinates are incomplete")
    if str(row.get("canonical_uri") or "") != oci_canonical_uri(
        registry, repository, reference, reference_kind
    ):
        raise RegistryInputError(
            "OCI receipt canonical_uri contradicts its coordinates"
        )
    if row.get("status") not in SNAPSHOT_SATISFYING_STATUSES:
        return None
    cas_error = _snapshot_receipt_cas_error(receipts_root, row)
    if cas_error:
        raise RegistryInputError(cas_error)
    data = _snapshot_cas_read(receipts_root, str(row.get("cas_path") or ""))
    resolved_digest = file_hash(data)
    if str(oci.get("resolved_digest") or "") != resolved_digest:
        raise RegistryInputError("CAS bytes are not the claimed OCI manifest digest")
    if reference_kind == "digest" and reference != resolved_digest:
        raise RegistryInputError(
            "digest-addressed OCI receipt does not hash to its ref"
        )
    derived = oci_manifest_identity(data)
    if str(oci.get("kind") or "") != derived["kind"]:
        raise RegistryInputError("OCI receipt kind contradicts the manifest bytes")
    media_type = str(row.get("media_type") or "")
    if media_type not in OCI_ARTIFACT_MEDIA_TYPES or (derived["kind"] == "index") != (
        media_type in OCI_INDEX_MEDIA_TYPES
    ):
        raise RegistryInputError(
            "OCI receipt media_type contradicts the manifest bytes"
        )
    if derived["manifest_media_type"] and derived["manifest_media_type"] != media_type:
        raise RegistryInputError("OCI manifest mediaType contradicts the receipt")
    platforms = list(derived["platforms"])
    platform = ""
    if derived["kind"] == "manifest":
        config_hash = str(oci.get("config_content_hash") or "")
        if config_hash != derived["config_digest"]:
            raise RegistryInputError("OCI config digest contradicts the manifest bytes")
        config = _snapshot_cas_read(
            receipts_root, str(oci.get("config_cas_path") or "")
        )
        if file_hash(config) != config_hash:
            raise RegistryInputError("CAS bytes are not the claimed OCI config blob")
        platform = str(oci_config_platform(config) or "")
        if not platform:
            raise RegistryInputError("OCI config blob exposes no exact platform")
        platforms = [platform]
    elif not platforms:
        raise RegistryInputError("OCI index exposes no platform-bearing child")
    for key, expected in (
        ("platforms", platforms),
        ("children", derived["children"]),
        ("excluded", derived["excluded"]),
    ):
        if list(oci.get(key, [])) != expected:
            raise RegistryInputError(
                f"OCI receipt {key} contradicts the manifest bytes"
            )
    return {
        "evidence_cas_path": str(row.get("cas_path") or ""),
        "evidence_content_hash": resolved_digest,
        "manifest_kind": str(derived["kind"]),
        "manifest_media_type": media_type,
        "observed_at": str(row.get("observed_at") or ""),
        "platforms": platforms,
        "receipt_canonical_uri": str(row.get("canonical_uri") or ""),
        "reference": reference,
        "reference_kind": reference_kind,
        "registry": registry,
        "repository": repository,
        "resolved_digest": resolved_digest,
        "resolver": "oci-registry-manifest",
        **({"platform": platform} if platform else {}),
    }


def oci_artifact_receipts(
    receipts_dir: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return CAS-re-derived OCI receipts, their typed failures, and refusals."""

    rows, rejected = load_snapshot_receipts(receipts_dir)
    receipts_root = Path(receipts_dir)
    verified: list[dict[str, Any]] = []
    typed_failures: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = list(rejected)
    for entry in rows:
        row, context = entry["row"], entry["context"]
        coordinates = row.get("coordinates")
        oci = coordinates.get("oci") if isinstance(coordinates, Mapping) else None
        if not isinstance(oci, Mapping):
            continue
        try:
            resolution = _oci_receipt_resolution(receipts_root, row, oci)
        except RegistryInputError as exc:
            refused.append({"receipt": context, "reason": str(exc)})
            continue
        if resolution is None:
            typed_failures.append(
                {
                    "receipt": context,
                    "canonical_uri": str(row.get("canonical_uri") or ""),
                    "error_state": str(row.get("error_state") or ""),
                    "http_status": row.get("http_status"),
                }
            )
            continue
        verified.append({"context": context, "row": row, "observation": resolution})
    return verified, typed_failures, refused


def bind_oci_identity(
    baseline: Mapping[str, Any], receipts_dir: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Attach the receipt-verified registry manifest identity to gapped OCI versions."""

    errors = validate_manifest(baseline)
    if errors:
        raise RegistryInputError("baseline is invalid: " + "; ".join(errors[:20]))
    components = _manifest_component_map(baseline)
    versions = _manifest_version_map(baseline)
    plan, unfetchable = oci_identity_plan(baseline)
    planned = {row["canonical_uri"]: row for row in plan}
    verified, typed_failures, refused = oci_artifact_receipts(receipts_dir)
    # One ref may carry several verified receipts: the receipts tree is
    # append-only and the wave is resumable. Binding each of them would let
    # Builder DEEP-MERGE their observations -- unioning platforms and taking
    # min() on conflicting scalars -- and synthesize a record no receipt
    # produced. Collapse to one receipt per ref here: identical identity keeps
    # the newest observation, and a genuine disagreement (a tag that moved
    # between runs) is not a single identity and fails closed.
    by_ref: dict[str, list[dict[str, Any]]] = {}
    for receipt in verified:
        by_ref.setdefault(str(receipt["row"]["canonical_uri"]), []).append(receipt)
    verified = []
    for ref in sorted(by_ref):
        group = by_ref[ref]
        identities = {
            canonical_json(
                {k: v for k, v in item["observation"].items() if k != "observed_at"}
            )
            for item in group
        }
        if len(identities) > 1:
            raise RegistryInputError(
                f"OCI receipts disagree on the identity of {ref}: "
                f"{len(identities)} distinct manifests across {len(group)} receipts"
            )
        verified.append(
            max(group, key=lambda item: str(item["observation"]["observed_at"]))
        )
    builder = Builder()
    bound_versions: list[str] = []
    bound_components: set[str] = set()
    skipped: Counter[str] = Counter()
    for receipt in verified:
        row, observation = receipt["row"], receipt["observation"]
        source_id = builder.add_source(
            f"oci-observation:{row['content_hash']}",
            "oci-artifact-observation",
            content_hash=str(row["content_hash"]),
            metadata={
                "evidence_class": "reference",
                "receipt": {
                    "canonical_uri": str(row["canonical_uri"]),
                    "cas_path": str(row["cas_path"]),
                    "observed_at": str(row["observed_at"]),
                    "runner_version": str(row.get("runner_version") or ""),
                    "upstream_ref": observation["resolved_digest"],
                },
            },
        )
        for raw_version_id in row["channel_ids"]:
            version_id = str(raw_version_id)
            version = versions.get(version_id)
            component = components.get(
                str(version.get("component_id") or "") if version else ""
            )
            if version is None or component is None:
                skipped["version-not-in-baseline"] += 1
                continue
            if version_id not in planned.get(str(row["canonical_uri"]), {}).get(
                "component_version_ids", []
            ):
                skipped["version-not-in-plan"] += 1
                continue
            identity = recover_component_identity(component)
            lifecycles = [
                str(item) for item in component.get("lifecycles", []) if str(item)
            ]
            if identity is None or not lifecycles:
                skipped["identity-unrecoverable"] += 1
                continue
            bound_component_id = builder.add_component(
                kind=str(component.get("kind") or ""),
                ecosystem=str(component.get("ecosystem") or ""),
                name=str(component.get("name") or ""),
                namespace=str(component.get("namespace") or ""),
                purl=str(component["purl"]) if component.get("purl") else None,
                identity=identity,
                lifecycles=tuple(lifecycles),
                metadata=component.get("metadata"),
                official_channel_required=bool(
                    component.get("official_channel_required", True)
                ),
            )
            bound_version_id = builder.add_version(
                bound_component_id,
                resolved_version=version.get("resolved_version"),
                constraint=version.get("constraint"),
                source_ref=version.get("source_ref"),
                artifact_digest=version.get("artifact_digest"),
                platform=version.get("platform"),
                resolution_state=str(version.get("resolution_state") or ""),
                evidence=tuple(
                    str(item) for item in version.get("evidence", []) if item
                ),
                metadata={OCI_OBSERVATION_KEY: observation},
            )
            if (
                bound_component_id != str(component["component_id"])
                or bound_version_id != version_id
            ):
                # Fail closed: a re-minted identity would be a new record.
                raise RegistryInputError(
                    f"OCI identity binding does not reproduce {version_id}"
                )
            if (
                oci_artifact_observation(
                    builder.components[bound_component_id],
                    builder.versions[bound_version_id],
                )
                is None
            ):
                # Fail closed: an observation the emitter would reject is not evidence.
                raise RegistryInputError(
                    f"OCI identity binding is not readable back for {version_id}"
                )
            builder.add_occurrence(
                str(component["component_id"]),
                bound_version_id,
                source_id,
                locator=f"/receipts/{receipt['context']}",
                role="oci-artifact-observation",
                raw_value=observation["resolved_digest"],
                dependency_scope="deployment",
                lifecycle=(
                    "repository-used"
                    if "repository-used" in lifecycles
                    else lifecycles[0]
                ),
            )
            bound_versions.append(bound_version_id)
            bound_components.add(str(component["component_id"]))
    fragment = builder.manifest()
    satisfied = {str(receipt["row"]["canonical_uri"]) for receipt in verified}
    summary = {
        "record_kind": "oci_identity_binding_summary",
        "baseline_manifest_id": str(baseline.get("manifest_id") or ""),
        "receipts_dir": Path(receipts_dir).as_posix(),
        "receipts_verified": len(verified),
        "receipts_typed_failures": len(typed_failures),
        "typed_failures": typed_failures[:MAX_SCHEMA_ERRORS],
        "receipts_refused": len(refused),
        "refused_receipts": refused[:MAX_SCHEMA_ERRORS],
        "planned_refs": len(plan),
        "planned_refs_unreceipted": sorted(set(planned) - satisfied)[
            :MAX_SCHEMA_ERRORS
        ],
        "planned_versions": sum(len(row["component_version_ids"]) for row in plan),
        "unfetchable_version_ids": unfetchable[:MAX_SCHEMA_ERRORS],
        "components_bound": len(bound_components),
        "versions_bound": len(bound_versions),
        "bound_version_ids_digest": digest_ids(bound_versions),
        "skipped": {key: skipped[key] for key in sorted(skipped)},
        "fragment_manifest_id": str(fragment.get("manifest_id") or ""),
    }
    return fragment, summary


def channel_snapshot_gate(
    baseline: Mapping[str, Any],
    merged: Mapping[str, Any],
    *,
    receipts_dir: str,
) -> dict[str, Any]:
    """Snapshot-wave gate (T-R3-3): axis movement bound exactly to verified receipts."""

    checks: dict[str, dict[str, Any]] = {}
    merged_errors = validate_manifest(merged)
    checks["merged-valid"] = {
        "pass": not merged_errors,
        "errors": merged_errors[:20],
    }
    baseline_components = _manifest_component_map(baseline)
    merged_components = _manifest_component_map(merged)
    new_ids = sorted(set(merged_components) - set(baseline_components))
    removed_ids = sorted(set(baseline_components) - set(merged_components))
    checks["zero-new-components"] = {
        "pass": not new_ids and not removed_ids,
        "new_component_ids": new_ids[:50],
        "removed_component_ids": removed_ids[:50],
    }
    baseline_version_ids = {
        str(version["component_version_id"])
        for version in baseline.get("versions", [])
        if isinstance(version, Mapping) and version.get("component_version_id")
    }
    merged_version_ids = {
        str(version["component_version_id"])
        for version in merged.get("versions", [])
        if isinstance(version, Mapping) and version.get("component_version_id")
    }
    checks["zero-new-versions"] = {
        "pass": baseline_version_ids == merged_version_ids,
        "versions": len(merged_version_ids),
        "new_version_ids": sorted(merged_version_ids - baseline_version_ids)[:50],
        "removed_version_ids": sorted(baseline_version_ids - merged_version_ids)[:50],
    }
    required_baseline = sum(
        1
        for component in baseline_components.values()
        if component.get("official_channel_required", True)
    ) * len(OFFICIAL_CHANNEL_TYPES)
    required_merged = sum(
        1
        for component in merged_components.values()
        if component.get("official_channel_required", True)
    ) * len(OFFICIAL_CHANNEL_TYPES)
    accepted_baseline = _reviewed_slot_count(baseline_components)
    accepted_merged = _reviewed_slot_count(merged_components)
    checks["slots-unchanged"] = {
        "pass": required_baseline == required_merged
        and accepted_baseline == accepted_merged,
        "required_slots": required_merged,
        "required_slots_baseline": required_baseline,
        "accepted_slots": accepted_merged,
        "accepted_slots_baseline": accepted_baseline,
    }
    rows, rejected = load_snapshot_receipts(receipts_dir)
    receipts_root = Path(receipts_dir)
    cas_errors = sorted(
        f"{entry['context']}: {error}"
        for entry in rows
        if (error := _snapshot_receipt_cas_error(receipts_root, entry["row"]))
    )
    checks["receipts-verify"] = {
        "pass": not rejected and not cas_errors,
        "rows": len(rows),
        "rejected": rejected[:20],
        "cas_errors": cas_errors[:20],
    }
    baseline_accepted, baseline_immutable = snapshot_axis_sets(baseline)
    merged_accepted, merged_immutable = snapshot_axis_sets(merged)
    credit = merged_immutable - baseline_immutable
    baseline_channel_uri: dict[str, Any] = {}
    baseline_channel_component: dict[str, str] = {}
    for component_id, component in baseline_components.items():
        for channel in component.get("official_channels", []):
            if not isinstance(channel, Mapping) or not channel.get("channel_id"):
                continue
            channel_id = str(channel["channel_id"])
            if channel_id in baseline_accepted:
                baseline_channel_uri[channel_id] = channel.get("canonical_uri")
                baseline_channel_component[channel_id] = component_id
    versions_by_component: dict[str, list[Mapping[str, Any]]] = {}
    for version in baseline.get("versions", []):
        if isinstance(version, Mapping) and version.get("component_id"):
            versions_by_component.setdefault(str(version["component_id"]), []).append(
                version
            )
    observation = baseline.get("observation")
    fallback_observed_at = (
        str(observation["observed_at"])
        if isinstance(observation, Mapping) and observation.get("observed_at")
        else None
    )
    expected: set[str] = set()
    unbindable: set[str] = set()
    already_satisfied: set[str] = set()
    mismatched: list[str] = []
    failure_receipt_channels: set[str] = set()
    receipt_hash_by_channel: dict[str, set[str]] = {}
    for entry in rows:
        row, context = entry["row"], entry["context"]
        satisfying = row.get("status") in SNAPSHOT_SATISFYING_STATUSES
        for raw_channel_id in row["channel_ids"]:
            channel_id = str(raw_channel_id)
            if channel_id not in baseline_channel_uri:
                mismatched.append(f"{context}: {channel_id} is not accepted-available")
                continue
            if baseline_channel_uri[channel_id] != row.get("canonical_uri"):
                mismatched.append(f"{context}: {channel_id} canonical_uri mismatch")
                continue
            if not satisfying:
                failure_receipt_channels.add(channel_id)
                continue
            receipt_hash_by_channel.setdefault(channel_id, set()).add(
                str(row.get("content_hash"))
            )
            if channel_id in baseline_immutable:
                already_satisfied.add(channel_id)
                continue
            component_id = baseline_channel_component[channel_id]
            component = baseline_components[component_id]
            if (
                snapshot_reviewed_version_entry(
                    component_id,
                    versions_by_component.get(component_id, []),
                    fallback_observed_at or str(row["observed_at"]),
                    ecosystem=str(component.get("ecosystem") or ""),
                    kind=str(component.get("kind") or ""),
                )
                is None
            ):
                unbindable.add(channel_id)
            else:
                expected.add(channel_id)
    checks["receipt-channel-binding"] = {
        "pass": not mismatched,
        "violations": sorted(mismatched)[:50],
    }
    baseline_missing = baseline_accepted - baseline_immutable
    merged_missing = merged_accepted - merged_immutable
    checks["snapshot-arithmetic"] = {
        "pass": credit == expected
        and baseline_accepted == merged_accepted
        and merged_missing == baseline_missing - credit,
        "baseline_immutable_verified_channels": len(baseline_immutable),
        "merged_immutable_verified_channels": len(merged_immutable),
        "credited_channels": len(credit),
        "expected_channels": len(expected),
        "already_satisfied_channels": len(already_satisfied),
        "unbindable_channels": len(unbindable),
        "unbindable_channel_ids": sorted(unbindable)[:200],
        "unexplained_credit": sorted(credit - expected)[:50],
        "uncredited_expected": sorted(expected - credit)[:50],
    }
    invalid_refs: list[str] = []
    untraced: list[str] = []
    added = 0
    merged_failure_snapshot_channels: set[str] = set()
    for component_id, component in merged_components.items():
        baseline_component = baseline_components.get(component_id, {})
        baseline_snapshot_ids = {
            str(snapshot.get("snapshot_id") or "")
            for snapshot in baseline_component.get("official_channel_snapshots", [])
            if isinstance(snapshot, Mapping)
        }
        component_accepted = {
            str(channel["channel_id"])
            for channel in component.get("official_channels", [])
            if isinstance(channel, Mapping)
            and channel_class_is_reviewed(channel)
            and channel_is_available(channel)
            and channel.get("channel_id")
        }
        for snapshot in component.get("official_channel_snapshots", []):
            if not isinstance(snapshot, Mapping):
                continue
            snapshot_id = str(snapshot.get("snapshot_id") or "")
            channel_id = str(snapshot.get("channel_id") or "")
            if channel_id not in component_accepted:
                invalid_refs.append(snapshot_id)
            if snapshot.get("status") not in SNAPSHOT_SATISFYING_STATUSES:
                merged_failure_snapshot_channels.add(channel_id)
            if snapshot_id in baseline_snapshot_ids:
                continue
            added += 1
            if snapshot.get("status") in SNAPSHOT_SATISFYING_STATUSES:
                if str(snapshot.get("content_hash")) not in receipt_hash_by_channel.get(
                    channel_id, set()
                ):
                    untraced.append(f"{snapshot_id}: no verifying receipt")
            elif not snapshot.get("error_state"):
                untraced.append(f"{snapshot_id}: failure snapshot lacks error_state")
            elif channel_id not in failure_receipt_channels:
                untraced.append(f"{snapshot_id}: no failure receipt")
    checks["snapshot-channel-validity"] = {
        "pass": not invalid_refs,
        "violations": sorted(invalid_refs)[:50],
    }
    checks["added-snapshots-trace"] = {
        "pass": not untraced,
        "added_snapshots": added,
        "violations": sorted(untraced)[:50],
    }
    dropped = sorted(
        set(receipt_hash_by_channel) - credit - unbindable - already_satisfied
    )
    dropped_failures = sorted(
        failure_receipt_channels
        - merged_failure_snapshot_channels
        - unbindable
        - baseline_immutable
    )
    checks["no-silent-drop"] = {
        "pass": not dropped and not dropped_failures,
        "dropped_verified_channels": dropped[:50],
        "dropped_failure_channels": dropped_failures[:50],
    }
    return {
        "pass": all(check["pass"] for check in checks.values()),
        "checks": checks,
    }


def _manifest_version_map(
    manifest: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    return {
        str(version["component_version_id"]): version
        for version in manifest.get("versions", [])
        if isinstance(version, Mapping) and version.get("component_version_id")
    }


def _manifest_gap_map(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(gap["gap_id"]): gap
        for gap in manifest.get("gaps", [])
        if isinstance(gap, Mapping) and gap.get("gap_id")
    }


def _axis_exempted_ids(manifest: Mapping[str, Any], axis: str) -> list[str]:
    completeness = manifest.get("completeness")
    axis_state = (
        completeness.get(axis) if isinstance(completeness, Mapping) else None
    ) or {}
    return [
        str(item)
        for item in axis_state.get("accepted_deviation_ids", [])
        if isinstance(item, str)
    ]


def _version_platform_segments(version: Mapping[str, Any]) -> set[str]:
    """Every platform segment a version asserts, in its field and its observation."""

    observation = version_metadata_entry(version, OCI_OBSERVATION_KEY)
    platforms = [str(version.get("platform") or "")]
    if isinstance(observation, Mapping):
        platforms.append(str(observation.get("platform") or ""))
        platforms.extend(str(item) for item in observation.get("platforms", []))
    return {segment for item in platforms for segment in item.split("/")}


def _oci_inventory_subjects(manifest: Mapping[str, Any]) -> set[str]:
    """Components an imported CycloneDX SBOM enumerates against their own digest."""

    versions = _manifest_version_map(manifest)
    enumerated = {
        str(edge.get("from_component_version_id") or "")
        for edge in manifest.get("dependency_edges", [])
        if isinstance(edge, Mapping)
        and edge.get("relationship") == SBOM_INVENTORY_RELATIONSHIP
        and edge.get("resolver") == SBOM_INVENTORY_RESOLVER
    }
    return {
        str(occurrence.get("component_id") or "")
        for occurrence in manifest.get("occurrences", [])
        if isinstance(occurrence, Mapping)
        and occurrence.get("role") in SBOM_INVENTORY_SUBJECT_ROLES
        and str(occurrence.get("component_version_id") or "") in enumerated
        and versions.get(str(occurrence.get("component_version_id") or ""), {}).get(
            "artifact_digest"
        )
    }


def identity_gate(
    control: Mapping[str, Any],
    treatment: Mapping[str, Any],
    *,
    receipts_dir: str,
    deviations: Sequence[Mapping[str, Any]] = (),
    anchor: Mapping[str, Any] | None = None,
    expected_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Identity-wave gate: a re-derive certified against a same-generation control."""

    plan = expected_plan if isinstance(expected_plan, Mapping) else {}
    checks: dict[str, dict[str, Any]] = {}
    treatment_errors = validate_manifest(treatment)
    checks["merged-valid"] = {
        "pass": not treatment_errors,
        "errors": treatment_errors[:20],
    }
    control_axes = completeness_for(control)
    treatment_axes = completeness_for(treatment)
    treatment_observation = treatment.get("observation")
    treatment_observed_at = (
        str(treatment_observation.get("observed_at") or "")
        if isinstance(treatment_observation, Mapping)
        else ""
    )
    control_blocking = set(control_axes["identity"]["blocking_gap_ids"])
    treatment_blocking = set(treatment_axes["identity"]["blocking_gap_ids"])
    control_components = _manifest_component_map(control)
    treatment_components = _manifest_component_map(treatment)
    control_gaps = _manifest_gap_map(control)
    treatment_gaps = _manifest_gap_map(treatment)
    control_versions = _manifest_version_map(control)
    treatment_versions = _manifest_version_map(treatment)

    anchor_drift: list[str] = []
    if anchor is not None:
        anchor_blocking = set(completeness_for(anchor)["identity"]["blocking_gap_ids"])
        anchor_components = set(_manifest_component_map(anchor))
        if anchor_blocking != control_blocking:
            anchor_drift.append(
                "control identity blocking gaps differ from the anchor generation"
            )
        if anchor_components != set(control_components):
            anchor_drift.append("control components differ from the anchor generation")
    checks["generation-anchored"] = {
        "pass": not anchor_drift,
        "anchor_manifest_id": (
            str(anchor.get("manifest_id") or "") if anchor is not None else None
        ),
        "control_identity_blocking": len(control_blocking),
        "violations": anchor_drift,
    }
    new_components = sorted(set(treatment_components) - set(control_components))
    removed_components = sorted(set(control_components) - set(treatment_components))
    checks["zero-new-components"] = {
        "pass": not new_components and not removed_components,
        "new_component_ids": new_components[:50],
        "removed_component_ids": removed_components[:50],
    }
    expected_new_versions = {
        str(item) for item in plan.get("expected_new_version_ids", [])
    }
    expected_removed_versions = {
        str(item) for item in plan.get("expected_removed_version_ids", [])
    }
    new_versions = set(treatment_versions) - set(control_versions)
    removed_versions = set(control_versions) - set(treatment_versions)
    checks["version-delta-justified"] = {
        "pass": new_versions == expected_new_versions
        and removed_versions == expected_removed_versions,
        "versions": len(treatment_versions),
        "declared_new": len(expected_new_versions),
        "declared_removed": len(expected_removed_versions),
        "undeclared_new_version_ids": sorted(new_versions - expected_new_versions)[:50],
        "undeclared_removed_version_ids": sorted(
            removed_versions - expected_removed_versions
        )[:50],
    }
    stale_reviewed = sorted(
        version_id
        for version_id, version in treatment_versions.items()
        if version_metadata_entry(version, "reviewed_component_version_id")
        and version_id not in control_versions
    )
    checks["reviewed-version-generation"] = {
        "pass": not stale_reviewed,
        "stale_reviewed_version_ids": stale_reviewed[:50],
    }
    multi = {
        label: sum(
            1
            for gap in manifest.get("gaps", [])
            if isinstance(gap, Mapping) and gap.get("gap_type") == "oci-platform-multi"
        )
        for label, manifest in (("control", control), ("treatment", treatment))
    }
    checks["platform-multi-zero"] = {
        "pass": multi["control"] == 0 and multi["treatment"] == 0,
        **multi,
    }
    unknown_platforms = sorted(
        version_id
        for version_id, version in treatment_versions.items()
        if OCI_UNKNOWN_PLATFORM_SEGMENT in _version_platform_segments(version)
    )
    checks["no-unknown-platform"] = {
        "pass": not unknown_platforms,
        "violations": unknown_platforms[:50],
    }

    verified, refused = gitops_commit_receipts(receipts_dir)
    oci_verified, oci_typed, oci_refused = oci_artifact_receipts(receipts_dir)
    # Refs are many-to-one on digest and one-to-many on receipt: a resumed wave
    # re-verifies refs an earlier run wrote, differing only in fetch timestamps.
    oci_by_ref: dict[str, list[Mapping[str, Any]]] = {}
    for receipt in oci_verified:
        observation = receipt["observation"]
        oci_by_ref.setdefault(str(observation["receipt_canonical_uri"]), []).append(
            observation
        )
    commit_by_hash = {
        str(receipt["row"]["content_hash"]): receipt["commit"] for receipt in verified
    }
    closed = sorted(control_blocking - treatment_blocking)
    opened = sorted(treatment_blocking - control_blocking)
    closed_by_type: Counter[str] = Counter()
    explained_by_evidence: Counter[str] = Counter()
    unexplained: list[str] = []
    used_hashes: set[str] = set()
    used_oci_refs: set[str] = set()
    for gap_id in closed:
        gap = control_gaps.get(gap_id, {})
        gap_type = str(gap.get("gap_type") or "")
        closed_by_type[gap_type] += 1
        version = treatment_versions.get(str(gap.get("component_version_id") or ""))
        component = treatment_components.get(str(gap.get("component_id") or ""), {})
        observation = gitops_source_observation(component, version) if version else None
        if observation and commit_by_hash.get(
            str(observation["evidence_content_hash"])
        ) == str(observation["observed_commit"]):
            used_hashes.add(str(observation["evidence_content_hash"]))
            explained_by_evidence["receipt-bound-observation"] += 1
            continue
        artifact = oci_artifact_observation(component, version) if version else None
        if artifact and any(
            candidate == dict(artifact)
            for candidate in oci_by_ref.get(str(artifact["receipt_canonical_uri"]), ())
        ):
            used_oci_refs.add(str(artifact["receipt_canonical_uri"]))
            explained_by_evidence["receipt-bound-oci-manifest"] += 1
            continue
        exemption = accepted_deviation_exemption(
            treatment_gaps.get(gap_id, {}), "identity", treatment_observed_at
        )
        if exemption:
            explained_by_evidence["ratified-deviation"] += 1
            continue
        unexplained.append(gap_id)
    expected_closed = {
        str(key): int(value)
        for key, value in (plan.get("expected_closed_gap_types") or {}).items()
    }
    checks["gap-arithmetic-identity"] = {
        "pass": not unexplained
        and not opened
        and (not expected_closed or dict(closed_by_type) == expected_closed),
        "control_identity_blocking": len(control_blocking),
        "treatment_identity_blocking": len(treatment_blocking),
        "closed": len(closed),
        "closed_by_gap_type": {
            key: closed_by_type[key] for key in sorted(closed_by_type)
        },
        "expected_closed_by_gap_type": expected_closed,
        "explained_by": {
            key: explained_by_evidence[key] for key in sorted(explained_by_evidence)
        },
        "unexplained_closures": unexplained[:50],
        "opened_gap_ids": opened[:50],
    }
    control_types = {
        str(gap.get("gap_type") or "")
        for gap in control.get("gaps", [])
        if isinstance(gap, Mapping)
    }
    treatment_types = {
        str(gap.get("gap_type") or "")
        for gap in treatment.get("gaps", [])
        if isinstance(gap, Mapping)
    }
    widened = sorted((treatment_types - control_types) & IDENTITY_GAP_TYPES)
    checks["non-blocking-types-declared"] = {
        "pass": not widened
        and not (
            OBSERVED_IDENTITY_GAP_TYPES & (IDENTITY_GAP_TYPES | CLOSURE_GAP_TYPES)
        ),
        "new_gap_types": sorted(treatment_types - control_types),
        "blocking_new_gap_types": widened,
        "declared_non_blocking_types": sorted(OBSERVED_IDENTITY_GAP_TYPES),
    }
    commit_refusals = [item for item in refused if item.get("reason")]
    oci_refusals = [item for item in oci_refused if item.get("reason")]
    control_plan, _unfetchable = oci_identity_plan(control)
    planned_oci_refs = {str(row["canonical_uri"]) for row in control_plan}
    # Receipts accumulate across waves, so scope consumption to what this wave
    # planned: an OCI wave is not answerable for a gitops wave's commit receipts.
    unused_oci = sorted((set(oci_by_ref) & planned_oci_refs) - used_oci_refs)
    unused_receipts = (
        sorted(set(commit_by_hash) - used_hashes)
        if explained_by_evidence["receipt-bound-observation"]
        else []
    )
    receipted_refs = set(oci_by_ref) | {
        str(item.get("canonical_uri") or "") for item in oci_typed
    }
    unreceipted = sorted(
        row["canonical_uri"]
        for row in control_plan
        if row["canonical_uri"] not in receipted_refs
    )
    checks["receipt-coverage"] = {
        "pass": not commit_refusals
        and not oci_refusals
        and not unused_receipts
        and not unused_oci
        and not unreceipted,
        "receipts_verified": len(verified) + len(oci_verified),
        "receipts_refused": len(commit_refusals) + len(oci_refusals),
        "refused_receipts": (commit_refusals + oci_refusals)[:20],
        "unused_receipt_hashes": unused_receipts[:20],
        "oci_planned_refs": len(control_plan),
        "oci_typed_failures": len(oci_typed),
        "oci_unreceipted_refs": unreceipted[:20],
        "oci_unused_receipt_refs": unused_oci[:20],
    }
    isolation: list[str] = []
    for axis, field in (
        ("channel_review", "required_slots"),
        ("channel_review", "accepted_slots"),
        ("snapshots", "accepted_available_channels"),
        ("snapshots", "immutable_verified_channels"),
    ):
        if control_axes[axis][field] != treatment_axes[axis][field]:
            isolation.append(f"{axis}.{field}")
    checks["axis-isolation"] = {
        "pass": not isolation,
        "channel_review": treatment_axes["channel_review"],
        "snapshots_immutable_verified_channels": treatment_axes["snapshots"][
            "immutable_verified_channels"
        ],
        "violations": isolation,
    }
    deviation_violations: list[str] = []
    exempted_by_type: Counter[str] = Counter()
    for axis in sorted(ACCEPTED_DEVIATION_AXES):
        # A deviation ratified by an earlier wave belongs to the generation and
        # appears on both sides; what the wave may not do is silently drop one.
        dropped = set(_axis_exempted_ids(control, axis)) - set(
            _axis_exempted_ids(treatment, axis)
        )
        for gap_id in sorted(dropped):
            deviation_violations.append(f"treatment drops exemption {gap_id} on {axis}")
        for gap_id in _axis_exempted_ids(treatment, axis):
            gap = treatment_gaps.get(gap_id, {})
            exempted_by_type[str(gap.get("gap_type") or "")] += 1
            stamp = accepted_deviation_exemption(gap, axis, treatment_observed_at)
            expected_stamp = accepted_deviation_stamp(
                gap,
                treatment_components.get(str(gap.get("component_id") or ""), {}),
                deviations,
            )
            if stamp is None or expected_stamp != stamp:
                deviation_violations.append(
                    f"{gap_id} is not exempted by a ratified declaration"
                )
    expected_exempted = {
        str(key): int(value)
        for key, value in (plan.get("expected_exempted_gap_types") or {}).items()
    }
    checks["deviations-ratified"] = {
        "pass": not deviation_violations
        and (not expected_exempted or dict(exempted_by_type) == expected_exempted),
        "declarations": [
            {
                "declaration_id": str(item["record"]["record_id"]),
                "sha256": str(item["sha256"]),
            }
            for item in deviations
        ],
        "exempted_by_gap_type": {
            key: exempted_by_type[key] for key in sorted(exempted_by_type)
        },
        "expected_exempted_by_gap_type": expected_exempted,
        "violations": sorted(deviation_violations)[:50],
    }
    closure_reference = anchor if anchor is not None else control
    reference_closure = _manifest_gap_map(closure_reference)
    reference_blocking = set(
        completeness_for(closure_reference)["closure"]["blocking_gap_ids"]
    )
    treatment_closure_blocking = set(treatment_axes["closure"]["blocking_gap_ids"])
    inventory_subjects = _oci_inventory_subjects(treatment)
    closure_unexplained: list[str] = []
    closure_closed: Counter[str] = Counter()
    for gap_id in sorted(reference_blocking - treatment_closure_blocking):
        gap = reference_closure.get(gap_id, {})
        gap_type = str(gap.get("gap_type") or "")
        closure_closed[gap_type] += 1
        if (
            gap_type == "transitive-inventory-unavailable"
            and str(gap.get("component_id") or "") in inventory_subjects
        ):
            continue
        if accepted_deviation_exemption(
            treatment_gaps.get(gap_id, {}), "closure", treatment_observed_at
        ):
            continue
        closure_unexplained.append(gap_id)
    closure_opened = sorted(treatment_closure_blocking - reference_blocking)
    checks["closure-delta-evidenced"] = {
        "pass": not closure_unexplained and not closure_opened,
        "reference_closure_blocking": len(reference_blocking),
        "treatment_closure_blocking": len(treatment_closure_blocking),
        "closed_by_gap_type": {
            key: closure_closed[key] for key in sorted(closure_closed)
        },
        "sbom_inventory_subjects": len(inventory_subjects),
        "unexplained_closures": closure_unexplained[:50],
        "opened_gap_ids": closure_opened[:50],
    }
    checks["bounds"] = {
        "pass": len(treatment_versions) < MAX_VERSIONS,
        "versions": len(treatment_versions),
        "bound": MAX_VERSIONS,
    }
    return {
        "pass": all(check["pass"] for check in checks.values()),
        "checks": checks,
    }


def builder_from_manifest(manifest: Mapping[str, Any]) -> Builder:
    builder = Builder()
    for field, target in (
        ("sources", builder.sources),
        ("components", builder.components),
        ("versions", builder.versions),
        ("occurrences", builder.occurrences),
        ("dependency_edges", builder.edges),
        ("gaps", builder.extra_gaps),
    ):
        id_field = ID_FIELDS[field]
        for record in manifest.get(field, []):
            if isinstance(record, dict) and record.get(id_field):
                key = str(record[id_field])
                target[key] = merge_dicts(target.get(key, {}), record)
    discovery_scope = manifest.get("discovery_scope")
    if isinstance(discovery_scope, dict):
        for record in discovery_scope.get("inputs", []):
            if isinstance(record, dict) and record.get("discovery_input_id"):
                key = str(record["discovery_input_id"])
                builder.discovery_inputs[key] = merge_dicts(
                    builder.discovery_inputs.get(key, {}), record
                )
    return builder


MERGE_SELECTION_POLICY = "latest-observed-at-then-manifest-id-v1"
MERGE_SET_PATHS = {
    ("sources", "metadata", "observations"),
    ("sources", "metadata", "raw_content_hashes"),
    ("sources", "metadata", "resource_kinds"),
    ("components", "lifecycles"),
    ("components", "metadata", "aliases"),
    ("components", "metadata", "gvk"),
    ("components", "metadata", "lineage_evidence"),
    ("components", "metadata", "owners"),
    ("components", "metadata", "topics"),
    ("versions", "evidence"),
    ("gaps", "evidence"),
    ("discovery_inputs", "scanners"),
}
MERGE_KEYED_LIST_PATHS = {
    ("components", "official_channels"): "channel_id",
    ("components", "official_channel_snapshots"): "snapshot_id",
    ("components", "official_channel_proposals"): "proposal_id",
    ("components", "official_resolutions"): "resolution_id",
}
MERGE_ADDITIVE_MAP_PATHS = {
    ("sources", "metadata"),
    ("components", "metadata"),
    ("versions", "metadata"),
    ("occurrences", "metadata"),
    ("dependency_edges", "metadata"),
    ("gaps", "metadata"),
}
MERGE_OPTIONAL_PATHS = {
    *MERGE_ADDITIVE_MAP_PATHS,
    *MERGE_SET_PATHS,
    *MERGE_KEYED_LIST_PATHS,
}
MERGE_LATEST_TIME_PATHS = {("versions", "metadata", "observed_at")}


def _merge_path_allows_missing(path: tuple[str, ...]) -> bool:
    return path in MERGE_OPTIONAL_PATHS or any(
        path[: len(prefix)] == prefix for prefix in MERGE_ADDITIVE_MAP_PATHS
    )


def _merge_conflict(
    field: str, identifier: str, path: tuple[str, ...]
) -> RegistryInputError:
    pointer = "/" + "/".join(json_pointer_escape(item) for item in path[1:])
    return RegistryInputError(
        f"merge conflict for {field} record {identifier} at {pointer or '/'}"
    )


def _strict_merge_candidate_value(
    field: str,
    identifier: str,
    path: tuple[str, ...],
    left: Any,
    right: Any,
) -> Any:
    if left == right:
        return copy.deepcopy(left)
    if path in MERGE_LATEST_TIME_PATHS:
        if not valid_live_observed_at(left) or not valid_live_observed_at(right):
            raise _merge_conflict(field, identifier, path)
        return max(str(left), str(right))
    if path in MERGE_SET_PATHS:
        if not isinstance(left, list) or not isinstance(right, list):
            raise _merge_conflict(field, identifier, path)
        unique = {canonical_json(item): copy.deepcopy(item) for item in [*left, *right]}
        return [unique[key] for key in sorted(unique)]
    if path in MERGE_KEYED_LIST_PATHS:
        if not isinstance(left, list) or not isinstance(right, list):
            raise _merge_conflict(field, identifier, path)
        id_field = MERGE_KEYED_LIST_PATHS[path]
        records: dict[str, Any] = {}
        for item in [*left, *right]:
            if not isinstance(item, Mapping) or not item.get(id_field):
                raise _merge_conflict(field, identifier, path)
            item_id = str(item[id_field])
            if item_id in records and records[item_id] != item:
                raise _merge_conflict(field, identifier, (*path, item_id))
            records[item_id] = copy.deepcopy(item)
        return [records[key] for key in sorted(records)]
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(set(left) | set(right)):
            child_path = (*path, str(key))
            if key not in left or key not in right:
                if not _merge_path_allows_missing(child_path):
                    raise _merge_conflict(field, identifier, child_path)
                result[str(key)] = copy.deepcopy(
                    right[key] if key in right else left[key]
                )
                continue
            result[str(key)] = _strict_merge_candidate_value(
                field,
                identifier,
                child_path,
                left[key],
                right[key],
            )
        return result
    raise _merge_conflict(field, identifier, path)


def strict_merge_candidate_record(
    field: str,
    identifier: str,
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> dict[str, Any]:
    result = _strict_merge_candidate_value(
        field,
        identifier,
        (field,),
        left,
        right,
    )
    if not isinstance(result, dict):
        raise _merge_conflict(field, identifier, (field,))
    return result


def _manifest_temporal_identity(
    manifest: Mapping[str, Any],
) -> tuple[str, str, str] | None:
    observation = manifest.get("observation")
    if not isinstance(observation, Mapping):
        return None
    observed_at = str(observation.get("observed_at") or "")
    lineage = manifest.get("merge_lineage")
    current_manifest_id = (
        str(lineage.get("current_manifest_id") or "")
        if isinstance(lineage, Mapping)
        else ""
    ) or str(manifest.get("manifest_id") or "")
    return observed_at, current_manifest_id, str(manifest.get("manifest_id") or "")


def merge_manifests(
    manifests: Sequence[Mapping[str, Any]],
    *,
    accepted_deviations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    if not manifests:
        raise RegistryInputError("merge requires at least one candidate manifest")
    if len(manifests) > MAX_DISCOVERY_FILES:
        raise RegistryInputError(
            f"merge inputs exceed manifest bound {MAX_DISCOVERY_FILES}"
        )
    validated: list[Mapping[str, Any]] = []
    for index, manifest in enumerate(manifests):
        errors = validate_manifest(manifest)
        if errors:
            raise RegistryInputError(
                f"merge input {index} is invalid: " + "; ".join(errors[:20])
            )
        validated.append(manifest)

    lineage_ids: set[str] = set()
    for manifest in validated:
        lineage_ids.add(str(manifest["manifest_id"]))
        lineage = manifest.get("merge_lineage")
        if isinstance(lineage, Mapping):
            lineage_ids.update(
                str(item) for item in lineage.get("input_manifest_ids", [])
            )
    if len(lineage_ids) > MAX_DISCOVERY_INPUTS:
        raise RegistryInputError(
            f"merge lineage exceeds manifest bound {MAX_DISCOVERY_INPUTS}"
        )

    temporal = [
        (identity, manifest)
        for manifest in validated
        if (identity := _manifest_temporal_identity(manifest)) is not None
    ]
    current_manifest: Mapping[str, Any] | None = None
    current_manifest_id: str | None = None
    previous_manifest_id: str | None = None
    current_observation: dict[str, Any] | None = None
    if temporal:
        current_identity, current_manifest = max(temporal, key=lambda item: item[0])
        current_manifest_id = current_identity[1]
        previous_manifest_id = (
            str(current_manifest.get("base_manifest_id"))
            if current_manifest.get("base_manifest_id")
            else None
        )
        current_observation = dict(current_manifest["observation"])

    builder = Builder()
    builder.accepted_deviations = tuple(accepted_deviations)
    ordered = sorted(
        validated,
        key=lambda manifest: (
            _manifest_temporal_identity(manifest) or ("", "", ""),
            str(manifest.get("manifest_id") or ""),
        ),
    )
    for manifest in ordered:
        for field, target in (
            ("sources", builder.sources),
            ("components", builder.components),
            ("versions", builder.versions),
            ("occurrences", builder.occurrences),
            ("dependency_edges", builder.edges),
            ("gaps", builder.extra_gaps),
        ):
            id_field = ID_FIELDS[field]
            for record in manifest[field]:
                if (
                    field == "gaps"
                    and str(record.get("gap_type") or "") in MERGE_REDERIVED_GAP_TYPES
                ):
                    # Re-derived from merged state; carrying would keep stale gaps.
                    continue
                key = str(record[id_field])
                target[key] = (
                    strict_merge_candidate_record(field, key, target[key], record)
                    if key in target
                    else copy.deepcopy(record)
                )
        discovery_scope = manifest.get("discovery_scope")
        if isinstance(discovery_scope, Mapping):
            for record in discovery_scope.get("inputs", []):
                key = str(record["discovery_input_id"])
                builder.discovery_inputs[key] = (
                    strict_merge_candidate_record(
                        "discovery_inputs",
                        key,
                        builder.discovery_inputs[key],
                        record,
                    )
                    if key in builder.discovery_inputs
                    else copy.deepcopy(record)
                )

    merged = builder.manifest(base_manifest_id=previous_manifest_id)
    if current_observation is not None:
        merged["observation"] = current_observation
    merged["merge_lineage"] = {
        "selection_policy": MERGE_SELECTION_POLICY,
        "input_manifest_ids": sorted(lineage_ids),
        "current_manifest_id": current_manifest_id,
        "previous_manifest_id": previous_manifest_id,
    }
    return seal_manifest(merged)


def merge_input_files(
    paths: Sequence[str],
    *,
    accepted_deviations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    manifests: list[Mapping[str, Any]] = []
    reviewed: list[tuple[str, Mapping[str, Any]]] = []
    inputs = read_bounded_unique_json_inputs(
        paths,
        max_files=MAX_DISCOVERY_FILES,
        max_total_bytes=MAX_JSON_INPUT_BYTES,
        label="merge inputs",
    )
    for path, payload, _raw in inputs:
        if not isinstance(payload, dict):
            raise ValueError(f"{path} is not a JSON object")
        if payload.get("record_kind") == "reviewed_component":
            reviewed.append(
                ("stdin" if path == "-" else Path(path).as_posix(), payload)
            )
        else:
            manifests.append(payload)
    if reviewed:
        manifests.append(reviewed_records_manifest(reviewed))
    return merge_manifests(manifests, accepted_deviations=accepted_deviations)


def validate_manifest(manifest: Any, *, canonical_order: bool = True) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]
    shape_errors = candidate_shape_errors(manifest)
    if shape_errors:
        return shape_errors
    cardinality_errors = candidate_cardinality_errors(manifest)
    if cardinality_errors:
        # Do not hand attacker-sized arrays to the schema engine.
        return cardinality_errors
    errors.extend(
        f"schema {error}" for error in discovery_manifest_schema_errors(manifest)
    )
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        errors.append(f"schema_version must equal {MANIFEST_SCHEMA_VERSION}")
    if manifest.get("record_kind") != MANIFEST_RECORD_KIND:
        errors.append(f"record_kind must equal {MANIFEST_RECORD_KIND}")
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        errors.append(f"manifest_version must equal {MANIFEST_VERSION}")
    if manifest.get("generation_state") != "candidate":
        errors.append("generation_state must equal candidate")
    expected_authority = {
        "review_state": "unreviewed",
        "authoritative": False,
        "compile_eligible": False,
        "promote_eligible": False,
        "source_admission": False,
        "retrieval_release": False,
        "production_mutation": False,
    }
    if manifest.get("authority_boundary") != expected_authority:
        errors.append(
            "authority_boundary must remain unreviewed and deny admission, release, and mutation"
        )
    generator = manifest.get("generator")
    if not isinstance(generator, dict):
        errors.append("generator must be an object")
    else:
        for key in ("name", "version", "source_ref"):
            if not isinstance(generator.get(key), str) or not generator.get(key):
                errors.append(f"generator.{key} must be a non-empty string")
        for key in ("schema_hash", "ruleset_hash"):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(generator.get(key) or "")):
                errors.append(f"generator.{key} must be a full sha256")
    try:
        expected_envelope = seal_manifest(manifest)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        expected_envelope = {}
        errors.append(f"canonical v2 envelope cannot be evaluated: {exc}")
    for key in (
        "$schema",
        "authority_boundary",
        "bounds",
        "generator",
        "manifest_id",
        "input_set",
        "reconciliation",
        "completeness",
        "integrity",
    ):
        if manifest.get(key) != expected_envelope.get(key):
            errors.append(f"{key} does not match the canonical v2 envelope")
    input_set = manifest.get("input_set")
    if not isinstance(input_set, dict):
        errors.append("input_set must be an object")
    elif not isinstance(input_set.get("entries"), list):
        errors.append("input_set.entries must be an array")
    reconciliation = manifest.get("reconciliation")
    if isinstance(reconciliation, dict):
        if reconciliation.get("removal_allowed") is not False:
            errors.append("candidate reconciliation.removal_allowed must be false")
        if reconciliation.get("removed") not in ([],):
            errors.append("candidate reconciliation.removed must be empty")
    base_manifest_id = manifest.get("base_manifest_id")
    if base_manifest_id is not None and not MANIFEST_ID_RE.fullmatch(
        str(base_manifest_id)
    ):
        errors.append("base_manifest_id must be null or an exact manifest ID")
    observation = manifest.get("observation")
    if observation is not None:
        expected_observation_keys = {
            "observed_at",
            "source_valid_at",
            "source_valid_time_basis",
        }
        if not isinstance(observation, dict):
            errors.append("observation must be an object")
        else:
            if set(observation) != expected_observation_keys:
                errors.append("observation has unsupported fields")
            if not valid_live_observed_at(observation.get("observed_at")):
                errors.append("observation.observed_at is invalid")
            if not valid_live_observed_at(observation.get("source_valid_at")):
                errors.append("observation.source_valid_at is invalid")
            if (
                observation.get("source_valid_time_basis")
                != "git-commit-committer-time"
            ):
                errors.append("observation.source_valid_time_basis is unsupported")
    merge_lineage = manifest.get("merge_lineage")
    if merge_lineage is not None:
        expected_lineage_keys = {
            "selection_policy",
            "input_manifest_ids",
            "current_manifest_id",
            "previous_manifest_id",
        }
        if not isinstance(merge_lineage, Mapping):
            errors.append("merge_lineage must be an object")
        else:
            if set(merge_lineage) != expected_lineage_keys:
                errors.append("merge_lineage has unsupported fields")
            if merge_lineage.get("selection_policy") != MERGE_SELECTION_POLICY:
                errors.append("merge_lineage.selection_policy is unsupported")
            input_manifest_ids = merge_lineage.get("input_manifest_ids")
            if not isinstance(input_manifest_ids, list) or any(
                not isinstance(item, str) or not MANIFEST_ID_RE.fullmatch(item)
                for item in input_manifest_ids or []
            ):
                errors.append("merge_lineage.input_manifest_ids is invalid")
                input_manifest_ids = []
            elif input_manifest_ids != sorted(set(input_manifest_ids)):
                errors.append(
                    "merge_lineage.input_manifest_ids must be unique and sorted"
                )
            current_manifest_id = merge_lineage.get("current_manifest_id")
            if current_manifest_id is not None and (
                not isinstance(current_manifest_id, str)
                or not MANIFEST_ID_RE.fullmatch(current_manifest_id)
            ):
                errors.append("merge_lineage.current_manifest_id is invalid")
            elif current_manifest_id is not None and current_manifest_id not in (
                input_manifest_ids or []
            ):
                errors.append(
                    "merge_lineage.current_manifest_id is not an input manifest"
                )
            if current_manifest_id is not None and observation is None:
                errors.append(
                    "merge_lineage.current_manifest_id requires an observation"
                )
            previous_manifest_id = merge_lineage.get("previous_manifest_id")
            if previous_manifest_id is not None and (
                not isinstance(previous_manifest_id, str)
                or not MANIFEST_ID_RE.fullmatch(previous_manifest_id)
            ):
                errors.append("merge_lineage.previous_manifest_id is invalid")
            if previous_manifest_id != base_manifest_id:
                errors.append(
                    "merge_lineage.previous_manifest_id must equal base_manifest_id"
                )
    discovery_scope = manifest.get("discovery_scope")
    if discovery_scope is not None:
        if not isinstance(discovery_scope, dict):
            errors.append("discovery_scope must be an object")
        else:
            if discovery_scope.get("model_dependency") != "none":
                errors.append("discovery_scope must declare zero model dependency")
            inputs = discovery_scope.get("inputs")
            if not isinstance(inputs, list):
                errors.append("discovery_scope.inputs must be an array")
                inputs = []
            input_ids: list[str] = []
            dispositions = Counter()
            for index, record in enumerate(inputs):
                prefix = f"discovery_scope.inputs[{index}]"
                if not isinstance(record, dict):
                    errors.append(f"{prefix} must be an object")
                    continue
                evidence_uri = str(record.get("evidence_uri") or "")
                expected_id = stable_id(
                    "din", evidence_uri, str(record.get("content_hash") or "")
                )
                if record.get("discovery_input_id") != expected_id:
                    errors.append(
                        f"{prefix}.discovery_input_id does not match its stable ID"
                    )
                input_ids.append(str(record.get("discovery_input_id") or ""))
                disposition = str(record.get("disposition") or "")
                if disposition not in {
                    "parsed",
                    "inspected-no-observations",
                    "unhandled",
                    "unreadable",
                }:
                    errors.append(f"{prefix} has unsupported disposition")
                dispositions[disposition] += 1
                if not isinstance(record.get("scanners"), list):
                    errors.append(f"{prefix}.scanners must be an array")
                if not isinstance(record.get("tracked"), bool):
                    errors.append(f"{prefix}.tracked must be a boolean")
                content_hash = record.get("content_hash")
                if content_hash and not re.fullmatch(
                    r"sha256:[0-9a-f]{64}", str(content_hash)
                ):
                    errors.append(f"{prefix}.content_hash must be a full sha256")
            if canonical_order and input_ids != sorted(input_ids):
                errors.append(
                    "discovery_scope.inputs is not sorted by discovery_input_id"
                )
            if discovery_scope.get("input_count") != len(inputs):
                errors.append("discovery_scope.input_count does not match inputs")
            expected_dispositions = {
                key: dispositions[key] for key in sorted(dispositions)
            }
            if discovery_scope.get("disposition_counts") != expected_dispositions:
                errors.append(
                    "discovery_scope.disposition_counts does not match inputs"
                )
            expected_complete = not any(
                item.get("disposition") in {"unhandled", "unreadable"}
                for item in inputs
                if isinstance(item, dict)
            )
            if discovery_scope.get("complete") is not expected_complete:
                errors.append("discovery_scope.complete does not match dispositions")
            repository_capture_keys = {
                "tracked_file_count",
                "selected_file_count",
                "discovery_file_count",
                "discovery_bytes",
                "tracked_inventory_sha256",
            }
            if repository_capture_keys & set(discovery_scope):
                for key in (
                    "tracked_file_count",
                    "selected_file_count",
                    "discovery_file_count",
                    "discovery_bytes",
                ):
                    value = discovery_scope.get(key)
                    if (
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or value < 0
                    ):
                        errors.append(
                            f"discovery_scope.{key} must be a non-negative integer"
                        )
                if isinstance(discovery_scope.get("discovery_file_count"), int) and (
                    discovery_scope.get("discovery_file_count") != len(inputs)
                ):
                    errors.append(
                        "discovery_scope.discovery_file_count does not match inputs"
                    )
                if not FULL_SHA256_RE.fullmatch(
                    str(discovery_scope.get("tracked_inventory_sha256") or "")
                ):
                    errors.append(
                        "discovery_scope.tracked_inventory_sha256 must be a full sha256"
                    )
            if manifest.get("input_set") != input_set_for(
                [item for item in inputs if isinstance(item, Mapping)]
            ):
                errors.append("input_set does not match discovery_scope.inputs")
    ids: dict[str, set[str]] = {}
    for field in ARRAY_FIELDS:
        records = manifest.get(field)
        if not isinstance(records, list):
            errors.append(f"{field} must be an array")
            ids[field] = set()
            continue
        id_field = ID_FIELDS[field]
        prefix = ID_PREFIXES[field] + "-"
        seen: set[str] = set()
        ordered_ids: list[str] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                errors.append(f"{field}[{index}] must be an object")
                continue
            identifier = record.get(id_field)
            if not isinstance(identifier, str) or not identifier.startswith(prefix):
                errors.append(f"{field}[{index}].{id_field} must start with {prefix!r}")
                continue
            if identifier in seen:
                errors.append(f"duplicate {id_field}: {identifier}")
            seen.add(identifier)
            ordered_ids.append(identifier)
        if canonical_order and ordered_ids != sorted(ordered_ids):
            errors.append(f"{field} is not sorted by {id_field}")
        ids[field] = seen
    components_by_id = {
        item["component_id"]: item
        for item in manifest.get("components", [])
        if isinstance(item, dict) and item.get("component_id") in ids["components"]
    }
    versions_by_id = {
        item["component_version_id"]: item
        for item in manifest.get("versions", [])
        if isinstance(item, dict)
        and item.get("component_version_id") in ids["versions"]
    }
    occurrences_by_id = {
        item["occurrence_id"]: item
        for item in manifest.get("occurrences", [])
        if isinstance(item, dict) and item.get("occurrence_id") in ids["occurrences"]
    }
    proposal_ids_seen: set[str] = set()
    for index, source in enumerate(manifest.get("sources", [])):
        if not isinstance(source, dict):
            continue
        if source.get("content_hash") and not re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(source.get("content_hash"))
        ):
            errors.append(f"sources[{index}].content_hash must be a full sha256")
        expected_id = stable_id(
            "src",
            source.get("source_type"),
            source.get("evidence_uri"),
            source.get("content_hash") or "",
        )
        if source.get("source_id") != expected_id:
            errors.append(f"sources[{index}].source_id does not match its stable ID")
        if source.get("source_type") == "live-capture-manifest":
            prefix = f"sources[{index}].metadata"
            metadata = source.get("metadata")
            if not isinstance(metadata, dict):
                errors.append(f"{prefix} must contain the live capture receipt")
                continue
            if metadata.get("record_kind") != LIVE_CAPTURE_RECORD_KIND:
                errors.append(f"{prefix}.record_kind is invalid")
            if (
                metadata.get("contract_version")
                not in LIVE_CAPTURE_SUPPORTED_CONTRACT_VERSIONS
            ):
                errors.append(f"{prefix}.contract_version is invalid")
            if metadata.get("required_surfaces") != list(LIVE_REQUIRED_SURFACES):
                errors.append(f"{prefix}.required_surfaces is not the fixed P0.1 set")
            if not valid_live_observed_at(metadata.get("observed_at")):
                errors.append(f"{prefix}.observed_at is invalid")
            if not re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64})",
                str(metadata.get("git_commit") or ""),
            ):
                errors.append(f"{prefix}.git_commit is not exact")
            if not metadata.get("cluster_uid"):
                errors.append(f"{prefix}.cluster_uid is missing")
            if not metadata.get("context") and not metadata.get("server_fingerprint"):
                errors.append(f"{prefix} lacks context or server_fingerprint")
            if metadata.get("server_fingerprint") and not FULL_SHA256_RE.fullmatch(
                str(metadata.get("server_fingerprint"))
            ):
                errors.append(f"{prefix}.server_fingerprint is invalid")
            metadata_contract_version = metadata.get("contract_version")
            sealed_contract = (
                metadata_contract_version
                if isinstance(metadata_contract_version, int)
                and not isinstance(metadata_contract_version, bool)
                else 0
            )
            if sealed_contract >= 3 and (
                metadata.get("projection") != LIVE_CAPTURE_PROJECTION
            ):
                errors.append(f"{prefix}.projection is invalid")
            if sealed_contract >= 3 and metadata.get("bounds") != live_capture_bounds(
                sealed_contract
            ):
                errors.append(f"{prefix}.bounds is invalid")
            kubeconfig = metadata.get("kubeconfig")
            if sealed_contract >= 2 and not isinstance(kubeconfig, Mapping):
                errors.append(f"{prefix}.kubeconfig is missing")
            elif isinstance(kubeconfig, Mapping):
                if sealed_contract >= 3:
                    source_config = kubeconfig.get("source")
                    execution_snapshot = kubeconfig.get("execution_snapshot")
                    if not (
                        isinstance(source_config, Mapping)
                        and str(source_config.get("path") or "").startswith("/")
                        and FULL_SHA256_RE.fullmatch(
                            str(source_config.get("sha256") or "")
                        )
                        and isinstance(source_config.get("size"), int)
                        and int(source_config.get("size") or 0) > 0
                        and isinstance(source_config.get("device"), int)
                        and int(source_config.get("device") or -1) >= 0
                        and isinstance(source_config.get("inode"), int)
                        and int(source_config.get("inode") or 0) > 0
                        and isinstance(execution_snapshot, Mapping)
                        and execution_snapshot.get("policy") == "sealed-memfd"
                        and execution_snapshot.get("sha256")
                        == source_config.get("sha256")
                        and execution_snapshot.get("size") == source_config.get("size")
                    ):
                        errors.append(f"{prefix}.kubeconfig is invalid")
                elif (
                    not str(kubeconfig.get("path") or "").startswith("/")
                    or not FULL_SHA256_RE.fullmatch(str(kubeconfig.get("sha256") or ""))
                    or not isinstance(kubeconfig.get("size"), int)
                    or int(kubeconfig.get("size") or 0) <= 0
                ):
                    errors.append(f"{prefix}.kubeconfig is invalid")
            capture_tool = metadata.get(
                "kubectl" if sealed_contract >= 3 else "capture_tool"
            )
            if not isinstance(capture_tool, Mapping):
                errors.append(f"{prefix}.kubectl/capture_tool is missing")
            elif (
                not str(capture_tool.get("path") or "").startswith("/")
                or not FULL_SHA256_RE.fullmatch(str(capture_tool.get("sha256") or ""))
                or not isinstance(capture_tool.get("size"), int)
                or isinstance(capture_tool.get("size"), bool)
                or int(capture_tool.get("size") or 0) <= 0
            ):
                errors.append(f"{prefix}.kubectl/capture_tool is invalid")
            if sealed_contract >= 3:
                capture_generator = metadata.get("capture_generator")
                capture_window = metadata.get("capture_window")
                if not (
                    isinstance(capture_generator, Mapping)
                    and capture_generator.get("git_commit")
                    == metadata.get("git_commit")
                    and FULL_SHA256_RE.fullmatch(
                        str(capture_generator.get("ruleset_hash") or "")
                    )
                    and isinstance(capture_generator.get("sources"), list)
                    and [
                        item.get("path")
                        for item in capture_generator.get("sources", [])
                        if isinstance(item, Mapping)
                    ]
                    == list(LIVE_CAPTURE_GENERATOR_PATHS)
                ):
                    errors.append(f"{prefix}.capture_generator is invalid")
                if not (
                    isinstance(capture_window, Mapping)
                    and valid_live_observed_at(capture_window.get("started_at"))
                    and valid_live_observed_at(capture_window.get("completed_at"))
                    and capture_window.get("observation_tolerance_seconds")
                    == LIVE_CAPTURE_TIME_TOLERANCE_SECONDS
                ):
                    errors.append(f"{prefix}.capture_window is invalid")
            if source.get("content_hash") != metadata.get(
                "capture_manifest_content_hash"
            ):
                errors.append(f"{prefix} content hash is not bound to its source")
            for hash_field in (
                "capture_manifest_content_hash",
                "capture_manifest_raw_hash",
            ):
                if not FULL_SHA256_RE.fullmatch(str(metadata.get(hash_field) or "")):
                    errors.append(f"{prefix}.{hash_field} is invalid")
            surfaces = metadata.get("surfaces")
            if not isinstance(surfaces, list) or [
                item.get("surface") for item in surfaces if isinstance(item, Mapping)
            ] != list(LIVE_REQUIRED_SURFACES):
                errors.append(f"{prefix}.surfaces is not canonical")
                surfaces = []
            for surface_index, surface_record in enumerate(surfaces):
                surface_prefix = f"{prefix}.surfaces[{surface_index}]"
                if not isinstance(surface_record, Mapping):
                    errors.append(f"{surface_prefix} must be an object")
                    continue
                surface = str(surface_record.get("surface") or "")
                state = str(surface_record.get("state") or "")
                if state not in {*LIVE_SURFACE_STATES, "missing"}:
                    errors.append(f"{surface_prefix}.state is invalid")
                raw_hashes = surface_record.get("raw_hashes")
                if (
                    not isinstance(raw_hashes, list)
                    or any(not isinstance(value, str) for value in raw_hashes)
                    or raw_hashes != sorted(set(raw_hashes))
                    or any(
                        not FULL_SHA256_RE.fullmatch(str(value)) for value in raw_hashes
                    )
                ):
                    errors.append(f"{surface_prefix}.raw_hashes is invalid")
                raw_hash_values = raw_hashes if isinstance(raw_hashes, list) else []
                resource_kinds = surface_record.get("resource_kinds")
                if (
                    not isinstance(resource_kinds, list)
                    or any(not isinstance(value, str) for value in resource_kinds)
                    or resource_kinds != sorted(set(resource_kinds))
                ):
                    errors.append(f"{surface_prefix}.resource_kinds is invalid")
                    resource_kinds = []
                if state == "captured" and not set(
                    live_surface_resource_kinds(surface, sealed_contract)
                ).issubset(set(resource_kinds)):
                    errors.append(
                        f"{surface_prefix} omits required queried resource kinds"
                    )
                artifacts = surface_record.get("artifacts", [])
                if not isinstance(artifacts, list):
                    errors.append(f"{surface_prefix}.artifacts is invalid")
                    artifacts = []
                elif artifacts != sorted(artifacts, key=canonical_json):
                    errors.append(f"{surface_prefix}.artifacts is not canonical")
                for artifact_index, artifact in enumerate(artifacts):
                    artifact_prefix = f"{surface_prefix}.artifacts[{artifact_index}]"
                    if not isinstance(artifact, Mapping):
                        errors.append(f"{artifact_prefix} must be an object")
                        continue
                    if not str(artifact.get("endpoint") or "").startswith("/"):
                        errors.append(f"{artifact_prefix}.endpoint is invalid")
                    if not FULL_SHA256_RE.fullmatch(
                        str(artifact.get("raw_hash") or "")
                    ):
                        errors.append(f"{artifact_prefix}.raw_hash is invalid")
                    if artifact.get("raw_hash") not in raw_hash_values:
                        errors.append(
                            f"{artifact_prefix}.raw_hash is not bound by the surface"
                        )
                    if not artifact.get("document_type"):
                        errors.append(f"{artifact_prefix}.document_type is missing")
                if (
                    sealed_contract >= 2
                    and state == "captured"
                    and surface in {"api-discovery", "builtin-openapi"}
                    and not artifacts
                ):
                    errors.append(f"{surface_prefix} has no endpoint-bound artifacts")
            capture_material = {
                key: value
                for key, value in metadata.items()
                if key not in {"capture_id", "evidence_class"}
            }
            expected_capture_id = stable_id("cap", capture_material)
            if metadata.get("capture_id") != expected_capture_id:
                errors.append(f"{prefix}.capture_id does not match its stable ID")
            if source.get("evidence_uri") != f"live-capture:{expected_capture_id}":
                errors.append(f"sources[{index}].evidence_uri is not capture-bound")
        elif source.get("source_type") == "live-export":
            metadata = source.get("metadata")
            if not isinstance(metadata, dict):
                errors.append(f"sources[{index}].metadata is missing live provenance")
                continue
            raw_hashes = metadata.get("raw_content_hashes")
            if not isinstance(raw_hashes, list) or any(
                not FULL_SHA256_RE.fullmatch(str(value)) for value in raw_hashes
            ):
                errors.append(
                    f"sources[{index}].metadata.raw_content_hashes is invalid"
                )
            observations = metadata.get("observations")
            if not isinstance(observations, list) or not observations:
                errors.append(f"sources[{index}].metadata.observations is empty")
            elif observations != sorted(observations, key=canonical_json):
                errors.append(
                    f"sources[{index}].metadata.observations is not canonical"
                )
    for index, component in enumerate(manifest.get("components", [])):
        if not isinstance(component, dict):
            continue
        for key in ("kind", "ecosystem", "name"):
            if (
                not isinstance(component.get(key), str)
                or not component.get(key).strip()
            ):
                errors.append(f"components[{index}].{key} must be a non-empty string")
        lifecycles = component.get("lifecycles")
        if not isinstance(lifecycles, list):
            errors.append(f"components[{index}].lifecycles must be an array")
            continue
        unsupported = sorted(
            str(value) for value in lifecycles if value not in LIFECYCLE_STATES
        )
        if unsupported:
            errors.append(
                f"components[{index}] has unsupported lifecycles: {', '.join(unsupported)}"
            )
        if not isinstance(component.get("official_channel_required", True), bool):
            errors.append(
                f"components[{index}].official_channel_required must be a boolean"
            )
        official_channels = component.get("official_channels", [])
        channel_ids_for_component: set[str] = set()
        if not isinstance(official_channels, list):
            errors.append(f"components[{index}].official_channels must be an array")
        else:
            for channel_index, channel in enumerate(official_channels):
                if not isinstance(channel, dict):
                    errors.append(
                        f"components[{index}].official_channels[{channel_index}] must be an object"
                    )
                    continue
                channel_id = str(channel.get("channel_id") or "")
                if not channel_id:
                    errors.append(
                        f"components[{index}].official_channels[{channel_index}] lacks channel_id"
                    )
                elif channel_id in channel_ids_for_component:
                    errors.append(
                        f"components[{index}].official_channels has duplicate channel_id {channel_id}"
                    )
                channel_ids_for_component.add(channel_id)
                if channel.get("channel_type") not in OFFICIAL_CHANNEL_TYPES:
                    errors.append(
                        f"components[{index}].official_channels[{channel_index}] has unsupported channel_type"
                    )
                state = str(channel.get("availability_state") or "available")
                if state not in {"available", *EXPLICIT_CHANNEL_GAP_STATES}:
                    errors.append(
                        f"components[{index}].official_channels[{channel_index}] has unsupported availability_state"
                    )
                if state == "available" and not channel.get("canonical_uri"):
                    errors.append(
                        f"components[{index}].official_channels[{channel_index}] available channel lacks canonical_uri"
                    )
                if channel.get("review_state") not in {"accepted", "needs-review"}:
                    errors.append(
                        f"components[{index}].official_channels[{channel_index}] has unsupported review_state"
                    )
        snapshots = component.get("official_channel_snapshots", [])
        if not isinstance(snapshots, list):
            errors.append(
                f"components[{index}].official_channel_snapshots must be an array"
            )
            snapshots = []
        snapshot_ids: set[str] = set()
        for snapshot_index, snapshot in enumerate(snapshots):
            prefix = f"components[{index}].official_channel_snapshots[{snapshot_index}]"
            if not isinstance(snapshot, dict):
                errors.append(f"{prefix} must be an object")
                continue
            snapshot_id = str(snapshot.get("snapshot_id") or "")
            if not snapshot_id or snapshot_id in snapshot_ids:
                errors.append(f"{prefix}.snapshot_id must be non-empty and unique")
            snapshot_ids.add(snapshot_id)
            if snapshot.get("channel_id") not in channel_ids_for_component:
                errors.append(f"{prefix} references unknown channel_id")
            version = versions_by_id.get(snapshot.get("component_version_id"))
            if not version:
                errors.append(f"{prefix} references unknown component_version_id")
            elif version.get("component_id") != component.get("component_id"):
                errors.append(
                    f"{prefix}.component_version_id belongs to another component"
                )
            content_hash = snapshot.get("content_hash")
            if content_hash and not re.fullmatch(
                r"sha256:[0-9a-f]{64}", str(content_hash)
            ):
                errors.append(f"{prefix}.content_hash must be a full sha256")
            if snapshot.get("status") in {"fetched", "verified"}:
                if not content_hash:
                    errors.append(
                        f"{prefix} fetched/verified status requires content_hash"
                    )
                if not snapshot.get("fetched_at"):
                    errors.append(
                        f"{prefix} fetched/verified status requires fetched_at"
                    )
        proposals = component.get("official_channel_proposals", [])
        if not isinstance(proposals, list):
            errors.append(
                f"components[{index}].official_channel_proposals must be an array"
            )
            proposals = []
        proposal_ids_for_component: set[str] = set()
        ordered_proposal_ids: list[str] = []
        for proposal_index, proposal in enumerate(proposals):
            prefix = f"components[{index}].official_channel_proposals[{proposal_index}]"
            if not isinstance(proposal, dict):
                errors.append(f"{prefix} must be an object")
                continue
            proposal_id = str(proposal.get("proposal_id") or "")
            if not proposal_id.startswith("prp-"):
                errors.append(f"{prefix}.proposal_id must start with 'prp-'")
            if proposal_id in proposal_ids_seen:
                errors.append(f"duplicate proposal_id: {proposal_id}")
            proposal_ids_seen.add(proposal_id)
            proposal_ids_for_component.add(proposal_id)
            ordered_proposal_ids.append(proposal_id)
            if proposal.get("component_id") != component.get("component_id"):
                errors.append(f"{prefix}.component_id does not match its component")
            if proposal.get("channel_type") not in OFFICIAL_CHANNEL_TYPES:
                errors.append(f"{prefix} has unsupported channel_type")
            proposal_state = str(proposal.get("proposal_state") or "")
            if proposal_state not in OFFICIAL_PROPOSAL_STATES:
                errors.append(f"{prefix} has unsupported proposal_state")
            review_state = str(proposal.get("review_state") or "")
            if review_state not in OFFICIAL_REVIEW_STATES:
                errors.append(f"{prefix} has unsupported review_state")
            if proposal.get("confidence") not in OFFICIAL_CONFIDENCE_LEVELS:
                errors.append(f"{prefix} has unsupported confidence")
            if proposal.get("producer") == OFFICIAL_RESOLVER_PRODUCER:
                if (
                    proposal.get("model_dependency")
                    != OFFICIAL_RESOLVER_MODEL_DEPENDENCY
                ):
                    errors.append(f"{prefix} must declare zero model dependency")
                if proposal.get("evidence_method") != OFFICIAL_RESOLVER_EVIDENCE_METHOD:
                    errors.append(
                        f"{prefix} has unsupported deterministic evidence method"
                    )
            evidence = proposal.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                errors.append(f"{prefix}.evidence must be a non-empty array")
                evidence = []
            if evidence != sorted(evidence, key=canonical_json):
                errors.append(f"{prefix}.evidence must be deterministically sorted")
            for evidence_index, evidence_item in enumerate(evidence):
                if not isinstance(evidence_item, dict):
                    errors.append(
                        f"{prefix}.evidence[{evidence_index}] must be an object"
                    )
                    continue
                if not evidence_item.get("evidence_type") or not evidence_item.get(
                    "source_uri"
                ):
                    errors.append(
                        f"{prefix}.evidence[{evidence_index}] lacks evidence_type or source_uri"
                    )
                if not re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    str(evidence_item.get("content_digest") or ""),
                ):
                    errors.append(
                        f"{prefix}.evidence[{evidence_index}] has invalid content_digest"
                    )
            bindings = proposal.get("version_bindings", [])
            if not isinstance(bindings, list):
                errors.append(f"{prefix}.version_bindings must be an array")
                bindings = []
            if bindings != sorted(bindings, key=canonical_json):
                errors.append(
                    f"{prefix}.version_bindings must be deterministically sorted"
                )
            canonical_uri = str(proposal.get("canonical_uri") or "")
            if proposal_state == "proposed" and not canonical_uri:
                errors.append(f"{prefix} proposed channel lacks canonical_uri")
            if canonical_uri and urlparse(canonical_uri).scheme not in {
                "https",
                "kubernetes",
                "oci",
            }:
                errors.append(f"{prefix}.canonical_uri has an unsupported scheme")
            if proposal_state != "proposed" and not isinstance(
                proposal.get("failure"), dict
            ):
                errors.append(f"{prefix} non-proposed state lacks a typed failure")
            expected_proposal_id = stable_id(
                "prp",
                proposal.get("component_id"),
                proposal.get("channel_type"),
                canonical_uri,
                proposal.get("resolver"),
                proposal_state,
                evidence,
                bindings,
                dict(proposal.get("failure") or {}),
            )
            if proposal_id != expected_proposal_id:
                errors.append(f"{prefix}.proposal_id does not match its stable ID")
        if ordered_proposal_ids != sorted(ordered_proposal_ids):
            errors.append(
                f"components[{index}].official_channel_proposals is not sorted by proposal_id"
            )
        if "official_resolution" in component:
            errors.append(
                f"components[{index}].official_resolution is legacy singleton state; use official_resolutions"
            )
        resolutions = component.get("official_resolutions", [])
        if not isinstance(resolutions, list):
            errors.append(f"components[{index}].official_resolutions must be an array")
            resolutions = []
        ordered_resolution_ids: list[str] = []
        for resolution_index, resolution in enumerate(resolutions):
            resolution_prefix = (
                f"components[{index}].official_resolutions[{resolution_index}]"
            )
            if not isinstance(resolution, dict):
                errors.append(f"{resolution_prefix} must be an object")
                continue
            if resolution.get("producer") == OFFICIAL_RESOLVER_PRODUCER:
                if (
                    resolution.get("model_dependency")
                    != OFFICIAL_RESOLVER_MODEL_DEPENDENCY
                ):
                    errors.append(
                        f"{resolution_prefix} must declare zero model dependency"
                    )
                if (
                    resolution.get("evidence_method")
                    != OFFICIAL_RESOLVER_EVIDENCE_METHOD
                ):
                    errors.append(
                        f"{resolution_prefix} has unsupported deterministic evidence method"
                    )
            resolution_status = str(resolution.get("status") or "")
            if resolution_status not in OFFICIAL_RESOLUTION_STATES:
                errors.append(f"{resolution_prefix} has unsupported status")
            resolution_proposal_ids = resolution.get("proposal_ids", [])
            if not isinstance(resolution_proposal_ids, list) or any(
                item not in proposal_ids_for_component
                for item in resolution_proposal_ids
            ):
                errors.append(f"{resolution_prefix} references unknown proposal IDs")
                resolution_proposal_ids = []
            failures = resolution.get("failures", [])
            requested_versions = resolution.get("requested_versions", [])
            resolved_versions = resolution.get("resolved_versions", [])
            expected_resolution_id = stable_id(
                "ors",
                component.get("component_id"),
                resolution.get("dispatch"),
                resolution_status,
                requested_versions,
                resolved_versions,
                resolution_proposal_ids,
                failures,
            )
            resolution_id = str(resolution.get("resolution_id") or "")
            ordered_resolution_ids.append(resolution_id)
            if resolution_id != expected_resolution_id:
                errors.append(
                    f"{resolution_prefix}.resolution_id does not match its stable ID"
                )
        if ordered_resolution_ids != sorted(set(ordered_resolution_ids)):
            errors.append(
                f"components[{index}].official_resolutions must be unique and sorted"
            )
    for index, version in enumerate(manifest.get("versions", [])):
        if not isinstance(version, dict):
            continue
        if version.get("component_id") not in ids["components"]:
            errors.append(f"versions[{index}] references unknown component_id")
        resolution_state = version.get("resolution_state")
        if resolution_state not in RESOLUTION_STATES:
            errors.append(
                f"versions[{index}] has unsupported resolution_state {resolution_state!r}"
            )
        exact_evidence = bool(
            looks_exact(str(version.get("resolved_version") or ""))
            or looks_exact(str(version.get("source_ref") or ""))
            or FULL_SHA256_RE.fullmatch(str(version.get("artifact_digest") or ""))
        )
        if resolution_state == "resolved" and any(
            TEMPLATE_EXPRESSION_RE.search(str(version.get(key) or ""))
            for key in ("resolved_version", "source_ref")
        ):
            errors.append(
                f"versions[{index}] resolved state contains a dynamic expression"
            )
        elif resolution_state == "resolved" and not exact_evidence:
            errors.append(
                f"versions[{index}] resolved state lacks immutable version evidence"
            )
        component = components_by_id.get(version.get("component_id"))
        if component and component.get("ecosystem") == "oci":
            platform = version.get("platform")
            if platform and normalize_oci_platform(str(platform)) != platform:
                errors.append(
                    f"versions[{index}].platform must be a canonical OCI "
                    "os/architecture[/variant]"
                )
            immutable_digest, digest_error = normalize_oci_digest(
                str(version.get("artifact_digest"))
                if version.get("artifact_digest") is not None
                else None
            )
            if version.get("artifact_digest") and digest_error:
                errors.append(
                    f"versions[{index}].artifact_digest must be a valid non-zero OCI sha256 digest"
                )
            if resolution_state == "resolved" and not immutable_digest:
                errors.append(
                    f"versions[{index}] resolved OCI state requires a valid non-zero manifest digest"
                )
        expected_id = stable_id(
            "ver",
            version.get("component_id"),
            version.get("resolved_version") or "",
            version.get("constraint") or "",
            version.get("source_ref") or "",
            version.get("artifact_digest") or "",
            version.get("platform") or "",
        )
        if version.get("component_version_id") != expected_id:
            errors.append(
                f"versions[{index}].component_version_id does not match its stable ID"
            )
    for index, occurrence in enumerate(manifest.get("occurrences", [])):
        if not isinstance(occurrence, dict):
            continue
        if occurrence.get("component_id") not in ids["components"]:
            errors.append(f"occurrences[{index}] references unknown component_id")
        if occurrence.get("component_version_id") not in ids["versions"]:
            errors.append(
                f"occurrences[{index}] references unknown component_version_id"
            )
        if occurrence.get("source_id") not in ids["sources"]:
            errors.append(f"occurrences[{index}] references unknown source_id")
        version = versions_by_id.get(occurrence.get("component_version_id"))
        if version and occurrence.get("component_id") != version.get("component_id"):
            errors.append(
                f"occurrences[{index}].component_id does not match its version component_id"
            )
        root_id = occurrence.get("root_id")
        if root_id is not None and root_id not in ids["components"]:
            errors.append(f"occurrences[{index}] references unknown root_id")
        lifecycle = occurrence.get("lifecycle")
        if lifecycle not in LIFECYCLE_STATES:
            errors.append(
                f"occurrences[{index}] has unsupported lifecycle {lifecycle!r}"
            )
        directness = occurrence.get("directness")
        if directness not in DIRECTNESS_STATES:
            errors.append(
                f"occurrences[{index}] has unsupported directness {directness!r}"
            )
        dependency_scope = occurrence.get("dependency_scope")
        if dependency_scope not in DEPENDENCY_SCOPES:
            errors.append(
                f"occurrences[{index}] has unsupported dependency_scope {dependency_scope!r}"
            )
        component = components_by_id.get(occurrence.get("component_id"))
        if component and lifecycle not in component.get("lifecycles", []):
            errors.append(
                f"occurrences[{index}].lifecycle is absent from its component lifecycles"
            )
        expected_id = stable_id(
            "occ",
            occurrence.get("source_id"),
            occurrence.get("evidence_locator"),
            occurrence.get("role"),
            occurrence.get("component_version_id"),
            occurrence.get("raw_value"),
            occurrence.get("root_id") or "",
        )
        if occurrence.get("occurrence_id") != expected_id:
            errors.append(
                f"occurrences[{index}].occurrence_id does not match its stable ID"
            )
    for index, edge in enumerate(manifest.get("dependency_edges", [])):
        if not isinstance(edge, dict):
            continue
        for key in ("from_component_version_id", "to_component_version_id"):
            if edge.get(key) not in ids["versions"]:
                errors.append(f"dependency_edges[{index}] references unknown {key}")
        if edge.get("source_occurrence_id") not in ids["occurrences"]:
            errors.append(
                f"dependency_edges[{index}] references unknown source_occurrence_id"
            )
        source_occurrence = occurrences_by_id.get(edge.get("source_occurrence_id"))
        if source_occurrence and source_occurrence.get(
            "component_version_id"
        ) != edge.get("to_component_version_id"):
            errors.append(
                f"dependency_edges[{index}].to_component_version_id does not match its source occurrence"
            )
        expected_id = stable_id(
            "edge",
            edge.get("from_component_version_id"),
            edge.get("to_component_version_id"),
            edge.get("relationship"),
            edge.get("source_occurrence_id"),
            edge.get("scope"),
            edge.get("constraint") or "",
        )
        if edge.get("edge_id") != expected_id:
            errors.append(
                f"dependency_edges[{index}].edge_id does not match its stable ID"
            )
    for index, gap in enumerate(manifest.get("gaps", [])):
        if not isinstance(gap, dict):
            continue
        references = (
            ("component_id", "components"),
            ("component_version_id", "versions"),
            ("source_id", "sources"),
        )
        for key, field in references:
            if gap.get(key) is not None and gap.get(key) not in ids[field]:
                errors.append(f"gaps[{index}] references unknown {key}")
        gap_version = versions_by_id.get(gap.get("component_version_id"))
        if (
            gap_version
            and gap.get("component_id") is not None
            and gap.get("component_id") != gap_version.get("component_id")
        ):
            errors.append(
                f"gaps[{index}].component_id does not match its version component_id"
            )
        expected_id = stable_id(
            "gap",
            gap.get("gap_type"),
            gap.get("component_id") or "",
            gap.get("component_version_id") or "",
            gap.get("source_id") or "",
            gap.get("message"),
        )
        if gap.get("gap_id") != expected_id:
            errors.append(f"gaps[{index}].gap_id does not match its stable ID")
    expected_counts = counts_for(manifest)
    if manifest.get("counts") != expected_counts:
        errors.append(f"counts must equal {canonical_json(expected_counts)}")
    return sorted(set(errors))


def summarize_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    components = manifest.get("components", [])
    occurrences = manifest.get("occurrences", [])
    gaps = manifest.get("gaps", [])
    return {
        "manifest_version": manifest.get("manifest_version"),
        "generation_state": manifest.get("generation_state"),
        "counts": counts_for(manifest),
        "components_by_ecosystem": dict(
            sorted(
                Counter(
                    str(item.get("ecosystem", "unknown")) for item in components
                ).items()
            )
        ),
        "components_by_kind": dict(
            sorted(
                Counter(str(item.get("kind", "unknown")) for item in components).items()
            )
        ),
        "occurrences_by_lifecycle": dict(
            sorted(
                Counter(
                    str(item.get("lifecycle", "unknown")) for item in occurrences
                ).items()
            )
        ),
        "gaps_by_type": dict(
            sorted(
                Counter(str(item.get("gap_type", "unknown")) for item in gaps).items()
            )
        ),
    }


def coverage_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    components = [
        item for item in manifest.get("components", []) if isinstance(item, dict)
    ]
    versions = [item for item in manifest.get("versions", []) if isinstance(item, dict)]
    channel_required = {
        item["component_id"]
        for item in components
        if item.get("official_channel_required", True)
    }
    channel_components = {
        item["component_id"]
        for item in components
        if item.get("official_channel_required", True)
        and any(
            isinstance(channel, dict)
            and channel_class_is_reviewed(channel)
            and channel_is_available(channel)
            for channel in item.get("official_channels", [])
        )
    }
    channel_state_counts = Counter()
    available_type_counts = Counter()
    reviewed_components_by_type: dict[str, set[str]] = {
        channel_type: set() for channel_type in OFFICIAL_CHANNEL_TYPES
    }
    for component in components:
        component_id = str(component.get("component_id") or "")
        for channel in component.get("official_channels", []):
            if not isinstance(channel, dict):
                continue
            channel_type = str(channel.get("channel_type", "unknown"))
            state = str(channel.get("availability_state", "unknown"))
            channel_state_counts[f"{channel_type}:{state}"] += 1
            if channel_is_available(channel):
                available_type_counts[channel_type] += 1
            if (
                component_id in channel_required
                and channel_type in reviewed_components_by_type
                and channel_class_is_reviewed(channel)
            ):
                reviewed_components_by_type[channel_type].add(component_id)
    fully_reviewed_components = set(channel_required)
    for channel_type in OFFICIAL_CHANNEL_TYPES:
        fully_reviewed_components &= reviewed_components_by_type[channel_type]
    required_channel_slots = len(channel_required) * len(OFFICIAL_CHANNEL_TYPES)
    reviewed_channel_slots = sum(
        len(component_ids) for component_ids in reviewed_components_by_type.values()
    )
    class_status = {
        channel_type: {
            "required_components": len(channel_required),
            "reviewed_components": len(reviewed_components_by_type[channel_type]),
            "missing_components": len(channel_required)
            - len(reviewed_components_by_type[channel_type]),
            "coverage": (
                len(reviewed_components_by_type[channel_type]) / len(channel_required)
                if channel_required
                else 1.0
            ),
        }
        for channel_type in OFFICIAL_CHANNEL_TYPES
    }
    resolved_components = {
        item.get("component_id")
        for item in versions
        if item.get("resolution_state") == "resolved"
    }
    total = len(components)
    return {
        "components_total": total,
        "components_requiring_official_channels": len(channel_required),
        "components_with_official_channels": len(channel_components),
        "components_without_official_channels": len(channel_required)
        - len(channel_components),
        "components_with_resolved_version": len(resolved_components),
        "components_without_resolved_version": total - len(resolved_components),
        "official_channel_coverage": (
            len(channel_components) / len(channel_required) if channel_required else 1.0
        ),
        "official_channel_classes_required": list(OFFICIAL_CHANNEL_TYPES),
        "official_channel_class_status": class_status,
        "official_channel_class_slots_total": required_channel_slots,
        "official_channel_class_slots_reviewed": reviewed_channel_slots,
        "official_channel_class_slots_missing": required_channel_slots
        - reviewed_channel_slots,
        "official_channel_class_coverage": (
            reviewed_channel_slots / required_channel_slots
            if required_channel_slots
            else 1.0
        ),
        "components_with_complete_channel_matrix": len(fully_reviewed_components),
        "components_without_complete_channel_matrix": len(channel_required)
        - len(fully_reviewed_components),
        "resolved_version_coverage": (
            (len(resolved_components) / total) if total else 1.0
        ),
        "gap_count": len(manifest.get("gaps", [])),
        "available_channels_by_type": dict(sorted(available_type_counts.items())),
        "channel_states_by_type": dict(sorted(channel_state_counts.items())),
    }


def manifest_is_complete(manifest: Mapping[str, Any]) -> bool:
    reconciliation = manifest.get("reconciliation")
    return bool(
        isinstance(reconciliation, Mapping)
        and reconciliation.get("complete_mark") is True
    )


def write_json(payload: Any, output: str) -> None:
    # Canonical, not indent=2: the pretty-printed union is 831.7 MB against a
    # 768 MiB bound that MAX_JSON_INPUT_BYTES shares, so an indented manifest
    # could never be re-read by a later stage. Canonical is 637.5 MB and is
    # already the sealed hash preimage, so written bytes == hashed bytes.
    raw = (canonical_json(payload) + "\n").encode("utf-8")
    if len(raw) > MAX_SERIALIZED_OUTPUT_BYTES:
        raise RegistryInputError(
            f"serialized output exceeds byte bound {MAX_SERIALIZED_OUTPUT_BYTES}"
        )
    if output == "-":
        sys.stdout.buffer.write(raw)
        return
    target = Path(output).absolute()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        raise RegistryInputError(
            f"output must be a fresh non-symlink file: {target}: {exc}"
        ) from exc
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _previous_manifest_identity(path: str | None) -> tuple[str | None, str | None]:
    if not path:
        return None, None
    previous = load_json(path)
    errors = validate_manifest(previous)
    if errors:
        raise RegistryInputError(
            "previous manifest is invalid: " + "; ".join(errors[:20])
        )
    manifest_id = str(previous.get("manifest_id") or "")
    if not MANIFEST_ID_RE.fullmatch(manifest_id):
        raise RegistryInputError("previous manifest has no exact manifest_id")
    observation = previous.get("observation")
    observed_at = (
        str(observation.get("observed_at") or "")
        if isinstance(observation, Mapping)
        else ""
    )
    if not valid_live_observed_at(observed_at):
        raise RegistryInputError(
            "previous repository manifest has no canonical observation.observed_at"
        )
    return manifest_id, observed_at


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser(
        "discover-repo", help="capture the clean Git-tracked repository"
    )
    discover.add_argument("root", nargs="?", default=".")
    discover.add_argument(
        "--observed-at",
        required=True,
        help="caller-pinned exact UTC second",
    )
    discover.add_argument(
        "--previous",
        help="validated prior candidate whose identity is retained for reconciliation",
    )
    discover.add_argument(
        "--include-workingdir",
        action="store_true",
        help="include tracked .workingdir2 inputs as non-authoritative reference evidence",
    )
    discover.add_argument("--require-complete", action="store_true")
    discover.add_argument("-o", "--output", default="-")

    live = subparsers.add_parser(
        "import-live",
        help="import capture-bound Kubernetes, Argo, CRD, runtime and SBOM JSON",
    )
    live.add_argument("inputs", nargs="+", help="JSON files; use - once for stdin")
    live.add_argument("--capture-manifest")
    live.add_argument("--require-complete", action="store_true")
    live.add_argument("-o", "--output", default="-")

    reviewed = subparsers.add_parser(
        "import-reviewed",
        help="normalize accepted channel records into an unreviewed candidate envelope",
    )
    reviewed.add_argument("inputs", nargs="+")
    reviewed.add_argument("--require-complete", action="store_true")
    reviewed.add_argument("-o", "--output", default="-")

    merge = subparsers.add_parser(
        "merge", help="merge candidates without admission or pointer mutation"
    )
    merge.add_argument("inputs", nargs="+")
    merge.add_argument(
        "--accepted-deviations",
        help="ratified accepted-deviation directory to bind and stamp",
    )
    merge.add_argument("--require-complete", action="store_true")
    merge.add_argument("-o", "--output", default="-")

    bind_identity = subparsers.add_parser(
        "bind-identity",
        help="bind the commit a deliberate self-repository ref pointed at when observed",
    )
    bind_identity.add_argument("baseline", help="validated baseline candidate manifest")
    bind_identity.add_argument(
        "--receipts", required=True, help="snapshot receipts directory"
    )
    bind_identity.add_argument(
        "--observed-ref",
        default="main",
        help="mutable ref the commit-object receipt resolves",
    )
    bind_identity.add_argument("-o", "--output", required=True)

    bind_oci = subparsers.add_parser(
        "bind-oci-identity",
        help="bind the registry manifest identity a gapped OCI version resolves to",
    )
    bind_oci.add_argument("baseline", help="validated baseline candidate manifest")
    bind_oci.add_argument(
        "--receipts", required=True, help="snapshot receipts directory"
    )
    bind_oci.add_argument(
        "--plan-only",
        action="store_true",
        help="emit the deduped registry fetch plan without binding",
    )
    bind_oci.add_argument("-o", "--output", required=True)

    derive = subparsers.add_parser(
        "derive-channels",
        help="expand ratified channel policies into reviewed component records",
    )
    derive.add_argument("baseline", help="validated baseline candidate manifest")
    derive.add_argument("--policies", required=True, help="channel-policy directory")
    derive.add_argument(
        "--snapshot-receipts",
        help="snapshot receipts directory (receipts/*.jsonl + cas/) to bind",
    )
    derive.add_argument("-o", "--output", required=True, help="fresh output directory")

    gate = subparsers.add_parser(
        "wave-gate",
        help="assert identity closure, slot arithmetic, and policy-hash bindings",
    )
    gate.add_argument("baseline", help="pre-wave candidate manifest")
    gate.add_argument("merged", help="post-wave merged candidate manifest")
    gate.add_argument("--policies", required=True, help="channel-policy directory")
    gate.add_argument("--expected-matched", type=int)
    gate.add_argument("-o", "--output", default="-")

    snapshot_gate = subparsers.add_parser(
        "snapshot-gate",
        help="assert snapshot-only axis movement bound to verified fetch receipts",
    )
    snapshot_gate.add_argument("baseline", help="pre-wave candidate manifest")
    snapshot_gate.add_argument("merged", help="post-wave merged candidate manifest")
    snapshot_gate.add_argument(
        "--receipts", required=True, help="snapshot receipts directory"
    )
    snapshot_gate.add_argument("-o", "--output", default="-")

    identity_gate_parser = subparsers.add_parser(
        "identity-gate",
        help="assert identity-axis movement against a same-generation control",
    )
    identity_gate_parser.add_argument(
        "control", help="same-generation control candidate manifest"
    )
    identity_gate_parser.add_argument(
        "treatment", help="identity-wave candidate manifest"
    )
    identity_gate_parser.add_argument(
        "--receipts", required=True, help="snapshot receipts directory"
    )
    identity_gate_parser.add_argument(
        "--deviations", help="ratified accepted-deviation directory"
    )
    identity_gate_parser.add_argument(
        "--anchor", help="frozen generation whose identity gaps the control must match"
    )
    identity_gate_parser.add_argument(
        "--expected-plan", help="declared wave arithmetic (JSON)"
    )
    identity_gate_parser.add_argument("-o", "--output", default="-")

    validate = subparsers.add_parser(
        "validate", help="validate canonical structure, IDs, bounds and graph closure"
    )
    validate.add_argument("input")
    validate.add_argument("--allow-unsorted", action="store_true")
    validate.add_argument("--require-complete", action="store_true")
    validate.add_argument("-o", "--output", default="-")

    for name, help_text in (
        ("summarize", "summarize the exact denominator"),
        ("coverage", "report identity and channel-state coverage"),
        ("gaps", "emit every typed gap"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("input")
        command.add_argument("-o", "--output", default="-")

    capabilities = subparsers.add_parser(
        "capabilities", help="report the fixed observation-only authority boundary"
    )
    capabilities.add_argument("-o", "--output", default="-")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "capabilities":
            write_json(
                {
                    "allowed": [
                        "discover-repo",
                        "import-live",
                        "import-reviewed",
                        "merge",
                        "derive-channels",
                        "bind-identity",
                        "bind-oci-identity",
                        "wave-gate",
                        "snapshot-gate",
                        "identity-gate",
                        "validate",
                        "summarize",
                        "coverage",
                        "gaps",
                    ],
                    "network_access": False,
                    "cluster_access": "read-only capture helper only",
                    "source_acquisition": False,
                    "source_admission": False,
                    "retrieval_release": False,
                    "signing": False,
                    "pointer_mutation": False,
                    "production_mutation": False,
                },
                args.output,
            )
            return 0
        source_binding = (
            registry_generator_source_binding()
            if args.command
            in {
                "discover-repo",
                "import-live",
                "import-reviewed",
                "merge",
                "derive-channels",
                "bind-identity",
                "bind-oci-identity",
                "wave-gate",
                "snapshot-gate",
                "identity-gate",
                "validate",
                "summarize",
                "coverage",
                "gaps",
            }
            else None
        )
        if args.command == "derive-channels":
            summary = derive_channels_command(
                args.baseline,
                args.policies,
                args.output,
                snapshot_receipts=args.snapshot_receipts,
            )
            if source_binding != registry_generator_source_binding():
                raise RegistryInputError(
                    "registry generator source changed during channel derivation"
                )
            write_json(summary, "-")
            return 0
        if args.command == "wave-gate":
            report = channel_wave_gate(
                load_json(args.baseline),
                load_json(args.merged),
                policies=load_channel_policies(args.policies),
                expected_matched=args.expected_matched,
            )
            if source_binding != registry_generator_source_binding():
                raise RegistryInputError(
                    "registry generator source changed during wave gating"
                )
            write_json(report, args.output)
            return 0 if report["pass"] else 1
        if args.command == "snapshot-gate":
            report = channel_snapshot_gate(
                load_json(args.baseline),
                load_json(args.merged),
                receipts_dir=args.receipts,
            )
            if source_binding != registry_generator_source_binding():
                raise RegistryInputError(
                    "registry generator source changed during snapshot gating"
                )
            write_json(report, args.output)
            return 0 if report["pass"] else 1
        if args.command == "identity-gate":
            report = identity_gate(
                load_json(args.control),
                load_json(args.treatment),
                receipts_dir=args.receipts,
                deviations=(
                    load_accepted_deviations(args.deviations) if args.deviations else ()
                ),
                anchor=load_json(args.anchor) if args.anchor else None,
                expected_plan=(
                    load_json(args.expected_plan) if args.expected_plan else None
                ),
            )
            if source_binding != registry_generator_source_binding():
                raise RegistryInputError(
                    "registry generator source changed during identity gating"
                )
            write_json(report, args.output)
            return 0 if report["pass"] else 1
        if args.command == "bind-identity":
            fragment, summary = bind_gitops_identity(
                load_json(args.baseline),
                args.receipts,
                observed_ref=args.observed_ref,
            )
            errors = validate_manifest(fragment)
            if errors:
                raise RegistryInputError(
                    "identity binding failed validation: " + "; ".join(errors[:20])
                )
            if source_binding != registry_generator_source_binding():
                raise RegistryInputError(
                    "registry generator source changed during identity binding"
                )
            write_json(fragment, args.output)
            write_json(summary, "-")
            return 0
        if args.command == "bind-oci-identity":
            baseline = load_json(args.baseline)
            if args.plan_only:
                plan, unfetchable = oci_identity_plan(baseline)
                write_json(
                    {
                        "record_kind": "oci_identity_fetch_plan",
                        "baseline_manifest_id": str(baseline.get("manifest_id") or ""),
                        "plan": plan,
                        "unfetchable_version_ids": unfetchable,
                    },
                    args.output,
                )
                return 0
            fragment, summary = bind_oci_identity(baseline, args.receipts)
            errors = validate_manifest(fragment)
            if errors:
                raise RegistryInputError(
                    "OCI identity binding failed validation: " + "; ".join(errors[:20])
                )
            if source_binding != registry_generator_source_binding():
                raise RegistryInputError(
                    "registry generator source changed during identity binding"
                )
            write_json(fragment, args.output)
            write_json(summary, "-")
            return 0
        if args.command == "discover-repo":
            previous_manifest_id, previous_observed_at = _previous_manifest_identity(
                args.previous
            )
            manifest = discover_repo(
                Path(args.root),
                args.include_workingdir,
                observed_at=args.observed_at,
                base_manifest_id=previous_manifest_id,
                previous_observed_at=previous_observed_at,
            )
        elif args.command == "import-live":
            if args.inputs.count("-") + int(args.capture_manifest == "-") > 1:
                raise RegistryInputError("stdin may only be specified once")
            manifest = import_live(
                args.inputs,
                capture_manifest=args.capture_manifest,
            )
        elif args.command == "import-reviewed":
            if args.inputs.count("-") > 1:
                raise RegistryInputError("stdin may only be specified once")
            manifest = import_reviewed(args.inputs)
        elif args.command == "merge":
            if args.inputs.count("-") > 1:
                raise RegistryInputError("stdin may only be specified once")
            manifest = merge_input_files(
                args.inputs,
                accepted_deviations=(
                    load_accepted_deviations(args.accepted_deviations)
                    if args.accepted_deviations
                    else ()
                ),
            )
        else:
            manifest = load_json(args.input)
            if args.command == "validate":
                errors = validate_manifest(
                    manifest,
                    canonical_order=not args.allow_unsorted,
                )
                if args.require_complete and not manifest_is_complete(manifest):
                    errors.append("candidate is explicitly incomplete")
                if source_binding != registry_generator_source_binding():
                    raise RegistryInputError(
                        "registry generator source changed during validation"
                    )
                write_json(
                    {
                        "valid": not errors,
                        "complete": manifest_is_complete(manifest),
                        "errors": sorted(set(errors)),
                        "counts": counts_for(manifest),
                    },
                    args.output,
                )
                return 0 if not errors else 1
            report_errors = validate_manifest(manifest)
            if report_errors:
                raise RegistryInputError(
                    "report input is invalid: " + "; ".join(report_errors[:20])
                )
            if source_binding != registry_generator_source_binding():
                raise RegistryInputError(
                    "registry generator source changed during report generation"
                )
            if args.command == "summarize":
                payload = summarize_manifest(manifest)
                payload["manifest_id"] = manifest.get("manifest_id")
                payload["complete"] = manifest_is_complete(manifest)
                payload["authority_boundary"] = manifest.get("authority_boundary")
                write_json(payload, args.output)
                return 0
            if args.command == "coverage":
                write_json(coverage_manifest(manifest), args.output)
                return 0
            gap_items = (
                manifest.get("gaps", []) if isinstance(manifest, Mapping) else []
            )
            write_json({"count": len(gap_items), "gaps": gap_items}, args.output)
            return 0

        errors = validate_manifest(manifest)
        if errors:
            raise RegistryInputError(
                "generated candidate failed validation: " + "; ".join(errors[:20])
            )
        if source_binding != registry_generator_source_binding():
            raise RegistryInputError(
                "registry generator source changed during candidate generation"
            )
        write_json(manifest, args.output)
        return 1 if args.require_complete and not manifest_is_complete(manifest) else 0
    except (OSError, RegistryInputError, ValueError) as exc:
        sys.stderr.write(f"knowledge-registry: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
