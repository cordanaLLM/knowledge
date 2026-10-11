#!/usr/bin/env python3
"""Materialize bounded Argo reviewed-record drafts from one accepted capture.

This tool has no network, subprocess, environment, review, admission, fetch,
release, pointer, Git, Argo, or production-mutation surface.  It accepts only
the exact retained P1-SRC-01 artifacts and writes an idempotent, no-replace
scratch bundle below ``.workingdir2`` for independent review.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "1.0.0"
GENERATOR = "archeion-argo-record-set-materializer"
GENERATOR_VERSION = "1"
GENERATOR_SOURCE = "tools/knowledge-registry/materialize_argo_record_set.py"
COMPONENT_SCHEMA_SOURCE = "knowledge/registry/schemas/component-record.schema.json"
RECORD_SET_SCHEMA_SOURCE = "knowledge/registry/schemas/reviewed-record-set.schema.json"
REQUIREMENTS_SOURCE = "tools/knowledge-registry/requirements-reviewed.txt"
CANONICAL_RECORDS_PATH = "knowledge/registry/records"

EXPECTED_CANDIDATE_SHA256 = (
    "sha256:e4a84156960e86fa02ffcf01cf775a104a9d394241af626e1197678dae7b9f5c"
)
EXPECTED_CAPTURE_RESULT_SHA256 = (
    "sha256:a365aece32959068b9d30e51a2aa38285bddf61c6455d10277c8fb4352754c77"
)
EXPECTED_CAPTURE_MANIFEST_SHA256 = (
    "sha256:0090d8d89185d84da9df5117d6f5e0dcf33a5ffd52888031d06f56f06711a54f"
)
EXPECTED_CANDIDATE_MANIFEST_ID = (
    "mft-d1acd3828275b661c095ad9182bdab4d42ace24ea16bac06e1c41a3e6323f0f8"
)
EXPECTED_GENERATOR_COMMIT = "c6852c5d954c616eec960e7971a1433d493c1ba0"
EXPECTED_OBSERVED_AT = "2026-07-17T12:02:33Z"
EXPECTED_COUNTS = {
    "components": 9398,
    "dependency_edges": 153756,
    "gaps": 8878,
    "occurrences": 75954,
    "sources": 146,
    "versions": 13686,
}
REQUIRED_SURFACES = (
    "api-discovery",
    "argo",
    "builtin-openapi",
    "cluster-sboms",
    "controllers",
    "crds-openapi",
    "nodes",
    "pods",
    "server-version",
    "workload-sboms",
)
REQUIRED_TARGETS = (
    "cmp:github:argoproj/argo-cd",
    "cmp:github:argoproj/argo-events",
    "cmp:github:argoproj/argo-rollouts",
    "cmp:github:argoproj/argo-workflows",
    "cmp:helm:argoproj/argo-cd",
    "cmp:helm:argoproj/argo-rollouts",
    "cmp:helm:argoproj/argo-workflows",
)
CHART_TARGETS = {
    "argo-cd": "cmp:helm:argoproj/argo-cd",
    "argo-rollouts": "cmp:helm:argoproj/argo-rollouts",
    "argo-workflows": "cmp:helm:argoproj/argo-workflows",
}
RUNTIME_EVIDENCE = {
    "cmp:github:argoproj/argo-cd": ("quay.io/argoproj", "argocd"),
    "cmp:github:argoproj/argo-rollouts": ("quay.io/argoproj", "argo-rollouts"),
    "cmp:github:argoproj/argo-workflows": ("quay.io/argoproj", "argoexec"),
}

MAX_CANDIDATE_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_RESULT_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_CONTRACT_BYTES = 128 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 10_000_000
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 64
MAX_BINDINGS = 4096
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
REQUIRED_VALIDATOR_DISTRIBUTIONS = frozenset(
    {"attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py"}
)
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s#]+)$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?$")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def output_bytes(value: Any) -> bytes:
    raw = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("materialized output exceeds the configured byte bound")
    return raw


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def normalized_absolute(path: Path, label: str) -> Path:
    absolute = path.absolute()
    if not absolute.is_absolute() or Path(os.path.normpath(absolute)) != absolute:
        raise ValueError(f"{label} must be an absolute normalized path")
    if any(part in {"", ".", ".."} for part in absolute.parts[1:]):
        raise ValueError(f"{label} contains an ambiguous path component")
    return absolute


def open_directory_no_follow(path: Path, label: str) -> tuple[int, os.stat_result]:
    absolute = normalized_absolute(path, label)
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in absolute.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor, os.fstat(descriptor)
    except Exception:
        os.close(descriptor)
        raise


def read_descriptor(descriptor: int, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > maximum:
        raise ValueError(f"{label} exceeds the configured byte bound")
    return raw


def read_regular_capture(
    path: Path, *, maximum: int, label: str
) -> tuple[bytes, os.stat_result]:
    absolute = normalized_absolute(path, label)
    parent_fd, _ = open_directory_no_follow(absolute.parent, f"{label} parent")
    try:
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"{label} is not a regular file")
            if before.st_size > maximum:
                raise ValueError(f"{label} exceeds the configured byte bound")
            raw = read_descriptor(descriptor, maximum, label)
            after = os.fstat(descriptor)
            if stat_identity(before) != stat_identity(after):
                raise ValueError(f"{label} changed while it was read")
            entry = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
            if stat_identity(entry) != stat_identity(after):
                raise ValueError(f"{label} was replaced while it was read")
            return raw, after
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def recheck_regular(
    path: Path,
    *,
    maximum: int,
    expected_sha256: str,
    expected_identity: os.stat_result,
    label: str,
) -> None:
    raw, current = read_regular_capture(path, maximum=maximum, label=label)
    if (
        stat_identity(current) != stat_identity(expected_identity)
        or sha256_bytes(raw) != expected_sha256
    ):
        raise ValueError(f"{label} changed during materialization")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: bytes) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (UnicodeDecodeError, RecursionError) as error:
        raise ValueError(f"invalid bounded JSON input: {error}") from error
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON input exceeds the configured node bound")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON input exceeds the configured nesting bound")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value


def parse_requirement_closure(raw: bytes) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = REQUIREMENT_RE.fullmatch(stripped)
        if match is None:
            raise ValueError("reviewed validator requirements are not exact pins")
        normalized = match.group(1).lower().replace("_", "-")
        if normalized in pins:
            raise ValueError("reviewed validator requirements contain a duplicate")
        pins[normalized] = match.group(2)
    if set(pins) != REQUIRED_VALIDATOR_DISTRIBUTIONS:
        raise ValueError("reviewed validator requirements closure is incomplete")
    installed = {
        name: importlib.metadata.version(name)
        for name in sorted(REQUIRED_VALIDATOR_DISTRIBUTIONS)
    }
    if pins != installed:
        raise ValueError("installed reviewed validator closure differs from exact pins")
    return installed


def schema_validator(schema: Mapping[str, Any], label: str) -> Any:
    try:
        if importlib.metadata.version("jsonschema") != "4.26.0":
            raise ValueError("jsonschema==4.26.0 is required")
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise ValueError("exact reviewed validator closure is unavailable") from error
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        raise ValueError(f"{label} is not a valid Draft 2020-12 schema") from error
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_schema(validator: Any, value: Any, label: str) -> None:
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        pointer = "/" + "/".join(str(item) for item in first.path)
        raise ValueError(f"{label} schema failure at {pointer}: {first.message}")


def json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def leaf_pointers(value: Any, pointer: str = "") -> list[str]:
    if isinstance(value, dict) and value:
        result: list[str] = []
        for key in sorted(value):
            result.extend(
                leaf_pointers(value[key], pointer + "/" + json_pointer_escape(key))
            )
        return result
    if isinstance(value, list) and value:
        result = []
        for index, item in enumerate(value):
            result.extend(leaf_pointers(item, f"{pointer}/{index}"))
        return result
    return [pointer or "/"]


def evidence(pointer: str) -> str:
    return (
        EXPECTED_CANDIDATE_SHA256.replace("sha256:", "accepted-candidate:sha256:")
        + pointer
    )


def capture_evidence(pointer: str) -> str:
    return (
        EXPECTED_CAPTURE_MANIFEST_SHA256.replace("sha256:", "capture-manifest:sha256:")
        + pointer
    )


def stable_external_id(prefix: str, *parts: str) -> str:
    return prefix + ":" + ":".join(parts)


def exact_one(
    values: Sequence[Any], predicate: Any, label: str
) -> tuple[int, Mapping[str, Any]]:
    matches = [
        (index, value)
        for index, value in enumerate(values)
        if isinstance(value, Mapping) and predicate(value)
    ]
    if len(matches) != 1:
        raise ValueError(f"{label} must resolve exactly once, got {len(matches)}")
    return matches[0]


def draft_gap(
    chart: str,
    component_id: str,
    code: str,
    reason: str,
    observed_at: str,
    candidate_pointer: str,
    next_action: str,
    *,
    subject_kind: str = "component",
    subject_id: str | None = None,
) -> dict[str, Any]:
    return {
        "gap_id": stable_external_id("gap", "p1-src-02", chart, code),
        "subject_kind": subject_kind,
        "subject_id": subject_id or component_id,
        "state": "unresolved",
        "reason": reason,
        "blocking": True,
        "evidence": [evidence(candidate_pointer)],
        "next_action": next_action,
        "detected_at": observed_at,
        "review_state": "needs-review",
    }


def make_bindings(
    record: Mapping[str, Any],
    exact: Mapping[str, tuple[str, str]],
    derived: Mapping[str, str],
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for pointer in leaf_pointers(record):
        if pointer in exact:
            source_pointer, derivation = exact[pointer]
            binding_kind = "candidate-pointer"
        elif pointer in derived:
            source_pointer = None
            derivation = derived[pointer]
            binding_kind = "derived"
        elif pointer.endswith(
            (
                "/observed_at",
                "/first_seen",
                "/last_seen",
                "/detected_at",
                "/reviewed_at",
                "/created_at",
            )
        ):
            source_pointer = "/observed_at"
            derivation = "copied or date-projected from the exact capture observation"
            binding_kind = "capture-pointer"
        else:
            source_pointer = None
            derivation = "non-authoritative schema control value; missing semantics remain a blocking gap"
            binding_kind = "control"
        if binding_kind == "capture-pointer":
            binding_evidence = [capture_evidence(str(source_pointer))]
        else:
            binding_evidence = [
                evidence(source_pointer) if source_pointer else evidence("/manifest_id")
            ]
        bindings.append(
            {
                "record_pointer": pointer,
                "binding_kind": binding_kind,
                "source_pointer": source_pointer,
                "evidence": binding_evidence,
                "derivation": derivation,
            }
        )
    if len(bindings) > MAX_BINDINGS:
        raise ValueError("record field bindings exceed the configured bound")
    return bindings


def build_chart_record(
    candidate: Mapping[str, Any], chart: str, observed_at: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    components = candidate["components"]
    versions = candidate["versions"]
    occurrences = candidate["occurrences"]
    sources = candidate["sources"]
    component_index, component = exact_one(
        components,
        lambda item: item.get("kind") == "helm-chart"
        and item.get("ecosystem") == "helm"
        and item.get("name") == chart
        and item.get("metadata", {}).get("chart_repository")
        == "https://argoproj.github.io/argo-helm",
        f"{chart} candidate chart component",
    )
    candidate_component_id = str(component["component_id"])
    version_index, version = exact_one(
        versions,
        lambda item: item.get("component_id") == candidate_component_id
        and item.get("resolution_state") == "resolved",
        f"{chart} exact candidate chart version",
    )
    resolved_version = version.get("resolved_version")
    if (
        not isinstance(resolved_version, str)
        or SEMVER_RE.fullmatch(resolved_version) is None
    ):
        raise ValueError(f"{chart} candidate version is not exact SemVer")
    candidate_version_id = str(version["component_version_id"])
    occurrence_index, occurrence = exact_one(
        occurrences,
        lambda item: item.get("component_version_id") == candidate_version_id
        and item.get("role") == "live-argo-helm-source",
        f"{chart} deployed occurrence",
    )
    source_index, source = exact_one(
        sources,
        lambda item: item.get("source_id") == occurrence.get("source_id"),
        f"{chart} occurrence source",
    )
    root_index, root = exact_one(
        components,
        lambda item: item.get("component_id") == occurrence.get("root_id"),
        f"{chart} occurrence root",
    )
    if root.get("kind") != "argo-application" or root.get("namespace") != "argocd":
        raise ValueError(
            f"{chart} occurrence root is not the captured Argo Application"
        )

    component_id = CHART_TARGETS[chart]
    version_id = f"ver:helm:argoproj/{chart}@{resolved_version}"
    component_pointer = f"/components/{component_index}"
    version_pointer = f"/versions/{version_index}"
    occurrence_pointer = f"/occurrences/{occurrence_index}"
    source_pointer = f"/sources/{source_index}"
    root_pointer = f"/components/{root_index}"
    capture_evidence = [
        evidence(component_pointer),
        evidence(version_pointer),
        evidence(occurrence_pointer),
    ]
    capture_date = observed_at[:10]

    channels: list[dict[str, Any]] = []
    for channel_index, candidate_channel in enumerate(component["official_channels"]):
        channel_pointer = f"{component_pointer}/official_channels/{channel_index}"
        channels.append(
            {
                "channel_id": candidate_channel["channel_id"],
                "component_id": component_id,
                "channel_type": candidate_channel["channel_type"],
                "availability_state": "unresolved",
                "canonical_uri": None,
                "publisher": None,
                "version_strategy": "unresolved",
                "access": "unknown",
                "rights": None,
                "refresh_policy": "review-required",
                "discovery_method": "generated",
                "confidence": "unknown",
                "review_state": "needs-review",
                "evidence": [evidence(channel_pointer)],
                "gap": {
                    "state": "unresolved",
                    "reason": "accepted capture records this channel as unresolved and non-authoritative",
                    "blocking": True,
                    "evidence": [evidence(channel_pointer)],
                    "next_action": "resolve this channel from independently reviewed primary-source evidence",
                },
            }
        )
    if len(channels) != 16 or {item["channel_type"] for item in channels} != {
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
    }:
        raise ValueError(f"{chart} candidate channel denominator is incomplete")

    record = {
        "$schema": "https://github.com/cordanaLLM/knowledge/schemas/registry/component-record.schema.json",
        "schema_version": "1.0.0",
        "record_kind": "reviewed_component",
        "record_id": f"record:p1-src-02:argo-chart:{chart}",
        "review": {
            "status": "needs-review",
            "reviewed_by": "unassigned-materialized-draft",
            "reviewed_at": capture_date,
            "evidence": capture_evidence,
        },
        "component": {
            "component_id": component_id,
            "kind": "chart",
            "ecosystem": component["ecosystem"],
            "namespace": "argoproj",
            "name": component["name"],
            "aliases": [],
            "purl": None,
            "cpe": None,
            "oci_repository": None,
            "chart_repository": component["metadata"]["chart_repository"],
            "chart_name": component["name"],
            "api_group": None,
            "gvk": [],
            "source_repo": None,
            "lifecycle": "deployed",
            "disposition": "selected",
            "owners": [],
            "topics": [],
            "authority_policy": "needs-independent-primary-source-review",
            "created_at": capture_date,
        },
        "versions": [
            {
                "component_version_id": version_id,
                "component_id": component_id,
                "purl": None,
                "constraint": version.get("constraint"),
                "resolved_version": resolved_version,
                "source_ref": None,
                "artifact_digest": None,
                "platform": None,
                "build_metadata": {},
                "release_time": None,
                "observed_at": observed_at,
                "valid_from": None,
                "valid_to": None,
                "resolution_state": version["resolution_state"],
                "evidence": list(version["evidence"]),
            }
        ],
        "occurrences": [
            {
                "occurrence_id": occurrence["occurrence_id"],
                "component_version_id": version_id,
                "root_id": occurrence["root_id"],
                "used_by": occurrence["root_id"],
                "site": None,
                "namespace": root["namespace"],
                "workload": root["name"],
                "container": None,
                "role": occurrence["role"],
                "directness": occurrence["directness"],
                "dependency_scope": "runtime",
                "optional": occurrence["optional"],
                "evidence_uri": source["evidence_uri"]
                + "#"
                + occurrence["evidence_locator"],
                "first_seen": observed_at,
                "last_seen": observed_at,
                "status": "active",
            }
        ],
        "dependencies": [],
        "channels": channels,
        "snapshots": [],
        "gaps": [
            draft_gap(
                chart,
                component_id,
                "review-pending",
                "the deterministic projection is a draft and has not been independently accepted",
                observed_at,
                component_pointer,
                "independently verify every proposed identity and channel before acceptance",
            ),
            draft_gap(
                chart,
                component_id,
                "source-repo-unresolved",
                "the accepted candidate proves a chart repository but not a canonical source repository",
                observed_at,
                f"{component_pointer}/metadata/chart_repository",
                "bind the canonical source repository using reviewed primary-source evidence",
            ),
            draft_gap(
                chart,
                component_id,
                "source-tag-unresolved",
                "the accepted candidate proves the chart version but not its immutable source tag",
                observed_at,
                version_pointer,
                "resolve and verify the exact immutable tag without inferring tag syntax",
                subject_kind="version",
                subject_id=version_id,
            ),
            draft_gap(
                chart,
                component_id,
                "publisher-rights-unresolved",
                "publisher and per-use rights are absent from the accepted candidate",
                observed_at,
                f"{component_pointer}/official_channels",
                "review publisher and rights from the exact upstream release source",
            ),
            draft_gap(
                chart,
                component_id,
                "governance-metadata-unresolved",
                "owners, topics, and final authority policy require independent review",
                observed_at,
                component_pointer,
                "assign reviewed ownership, topic mappings, and authority policy",
            ),
        ],
    }

    exact: dict[str, tuple[str, str]] = {
        "/component/ecosystem": (
            f"{component_pointer}/ecosystem",
            "copied exactly",
        ),
        "/component/name": (f"{component_pointer}/name", "copied exactly"),
        "/component/chart_repository": (
            f"{component_pointer}/metadata/chart_repository",
            "copied exactly",
        ),
        "/component/chart_name": (
            f"{component_pointer}/name",
            "copied exactly",
        ),
        "/component/lifecycle": (
            f"{component_pointer}/lifecycles/0",
            "copied from the sole deployed lifecycle",
        ),
        "/versions/0/constraint": (
            f"{version_pointer}/constraint",
            "copied exactly",
        ),
        "/versions/0/resolved_version": (
            f"{version_pointer}/resolved_version",
            "copied exactly",
        ),
        "/versions/0/resolution_state": (
            f"{version_pointer}/resolution_state",
            "copied exactly",
        ),
        "/occurrences/0/occurrence_id": (
            f"{occurrence_pointer}/occurrence_id",
            "copied exactly",
        ),
        "/occurrences/0/root_id": (
            f"{occurrence_pointer}/root_id",
            "copied exactly",
        ),
        "/occurrences/0/used_by": (
            f"{occurrence_pointer}/root_id",
            "copied exactly",
        ),
        "/occurrences/0/namespace": (
            f"{root_pointer}/namespace",
            "copied exactly",
        ),
        "/occurrences/0/workload": (
            f"{root_pointer}/name",
            "copied exactly",
        ),
        "/occurrences/0/role": (
            f"{occurrence_pointer}/role",
            "copied exactly",
        ),
        "/occurrences/0/directness": (
            f"{occurrence_pointer}/directness",
            "copied exactly",
        ),
        "/occurrences/0/optional": (
            f"{occurrence_pointer}/optional",
            "copied exactly",
        ),
        "/occurrences/0/evidence_uri": (
            f"{source_pointer}/evidence_uri",
            "joined with the exact occurrence evidence_locator",
        ),
        "/occurrences/0/status": (
            f"{occurrence_pointer}/lifecycle",
            "mapped deployed to active",
        ),
    }
    for evidence_index, _value in enumerate(record["versions"][0]["evidence"]):
        exact[f"/versions/0/evidence/{evidence_index}"] = (
            f"{version_pointer}/evidence/{evidence_index}",
            "copied exactly",
        )
    for channel_index, _channel in enumerate(channels):
        channel_pointer = f"{component_pointer}/official_channels/{channel_index}"
        for field in (
            "channel_id",
            "channel_type",
            "availability_state",
            "review_state",
        ):
            exact[f"/channels/{channel_index}/{field}"] = (
                f"{channel_pointer}/{field}",
                "copied exactly",
            )
    derived = {
        "/component/component_id": "canonical reviewed chart identity derived from exact chart repository and chart name",
        "/component/kind": "reviewed schema maps candidate helm-chart to chart",
        "/component/namespace": "derived from the exact argoproj chart repository authority",
        "/component/disposition": "deployed candidate lifecycle maps to selected draft disposition",
        "/versions/0/component_id": "mapped to the draft canonical component identity",
        "/versions/0/component_version_id": "canonical draft identity combines component identity and exact observed version",
        "/occurrences/0/component_version_id": "mapped from the exact candidate version to the canonical draft version identity",
        "/occurrences/0/dependency_scope": "candidate deployment scope is conservatively projected to runtime",
    }
    bindings = make_bindings(record, exact, derived)
    record_raw = output_bytes(record)
    if len(record_raw) > MAX_RECORD_BYTES:
        raise ValueError(f"{chart} record exceeds the configured byte bound")
    record_entry = {
        "path": f"{CANONICAL_RECORDS_PATH}/argo-{chart}-chart.json",
        "content_sha256": sha256_bytes(record_raw),
        "bytes": len(record_raw),
        "record_id": record["record_id"],
        "component_id": component_id,
        "candidate_component_id": candidate_component_id,
        "review_status": "needs-review",
        "bindings_sha256": sha256_bytes(canonical_bytes(bindings)),
        "bindings": bindings,
    }
    return record, record_entry


def record_set_gap(
    code: str,
    target_id: str,
    state: str,
    message: str,
    pointers: Sequence[str],
    next_action: str,
) -> dict[str, Any]:
    return {
        "code": code,
        "target_id": target_id,
        "state": state,
        "message": message,
        "blocking": True,
        "candidate_pointers": sorted(set(pointers)),
        "evidence": [evidence(pointer) for pointer in sorted(set(pointers))],
        "next_action": next_action,
    }


def find_runtime_pointers(
    candidate: Mapping[str, Any], namespace: str, name: str
) -> list[str]:
    components = [
        (index, component)
        for index, component in enumerate(candidate["components"])
        if isinstance(component, Mapping)
        and component.get("kind") == "oci-image"
        and component.get("namespace") == namespace
        and component.get("name") == name
    ]
    if len(components) != 1:
        raise ValueError(
            f"runtime evidence {namespace}/{name} must resolve exactly once"
        )
    component_index, component = components[0]
    component_id = component.get("component_id")
    pointers = [f"/components/{component_index}"]
    version_ids: set[str] = set()
    for version_index, version in enumerate(candidate["versions"]):
        if (
            not isinstance(version, Mapping)
            or version.get("component_id") != component_id
        ):
            continue
        version_id = version.get("component_version_id")
        if isinstance(version_id, str):
            version_ids.add(version_id)
        pointers.append(f"/versions/{version_index}")
        if "artifact_digest" in version:
            pointers.append(f"/versions/{version_index}/artifact_digest")
    if not version_ids:
        raise ValueError(f"runtime evidence {namespace}/{name} has no versions")
    for occurrence_index, occurrence in enumerate(candidate["occurrences"]):
        if (
            isinstance(occurrence, Mapping)
            and occurrence.get("component_version_id") in version_ids
        ):
            pointers.append(f"/occurrences/{occurrence_index}")
    return pointers


def build_record_set(
    candidate_raw: bytes,
    candidate: Mapping[str, Any],
    capture_result_raw: bytes,
    capture_result: Mapping[str, Any],
    capture_manifest_raw: bytes,
    capture_manifest: Mapping[str, Any],
    generator_raw: bytes,
    component_schema_raw: bytes,
    record_set_schema_raw: bytes,
    requirements_raw: bytes,
    validator_dependencies: Mapping[str, str],
    component_validator: Any,
    record_set_validator: Any,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if candidate.get("manifest_id") != EXPECTED_CANDIDATE_MANIFEST_ID:
        raise ValueError("candidate manifest identity differs from accepted input")
    if candidate.get("generation_state") != "candidate":
        raise ValueError("accepted input is not a candidate manifest")
    if candidate.get("counts") != EXPECTED_COUNTS:
        raise ValueError("candidate count denominator differs from accepted input")
    integrity = candidate.get("integrity")
    if not isinstance(integrity, Mapping) or integrity.get("manifest_hash") != (
        "sha256:" + EXPECTED_CANDIDATE_MANIFEST_ID.removeprefix("mft-")
    ):
        raise ValueError("candidate integrity binding is invalid")
    if candidate.get("discovery_scope", {}).get("complete") is not True:
        raise ValueError("candidate discovery scope is incomplete")
    for collection, expected in EXPECTED_COUNTS.items():
        if (
            not isinstance(candidate.get(collection), list)
            or len(candidate[collection]) != expected
        ):
            raise ValueError(
                f"candidate {collection} denominator differs from exact counts"
            )

    if capture_result.get("state") != "complete":
        raise ValueError("capture result is not complete")
    if capture_result.get("unavailable_surfaces") != []:
        raise ValueError("capture result contains unavailable surfaces")
    if capture_result.get("captured_surfaces") != list(REQUIRED_SURFACES):
        raise ValueError("capture result surface denominator differs")
    if (
        not isinstance(capture_result.get("inputs"), list)
        or len(capture_result["inputs"]) != 145
    ):
        raise ValueError("capture result input denominator differs")
    if (
        Path(str(capture_result.get("capture_manifest"))).name
        != "capture-manifest.json"
    ):
        raise ValueError("capture result manifest locator is invalid")

    if capture_manifest.get("record_kind") != "live_capture_manifest":
        raise ValueError("capture manifest kind is invalid")
    if capture_manifest.get("contract_version") != 3:
        raise ValueError("capture contract version differs")
    if capture_manifest.get("git_commit") != EXPECTED_GENERATOR_COMMIT:
        raise ValueError("capture generator commit differs")
    if capture_manifest.get("observed_at") != EXPECTED_OBSERVED_AT:
        raise ValueError("capture observation time differs")
    if sorted(capture_manifest.get("required_surfaces", [])) != sorted(
        REQUIRED_SURFACES
    ):
        raise ValueError("capture manifest required surfaces differ")
    if sorted(capture_manifest.get("surfaces", {})) != sorted(REQUIRED_SURFACES):
        raise ValueError("capture manifest surface receipts differ")

    event_matches = [
        index
        for index, component in enumerate(candidate["components"])
        if isinstance(component, Mapping)
        and component.get("name") == "argo-events"
        and component.get("kind") in {"helm-chart", "argo-application", "oci-image"}
    ]
    if event_matches:
        raise ValueError("Argo Events unexpectedly exists in the accepted candidate")

    records: dict[str, bytes] = {}
    entries: list[dict[str, Any]] = []
    for chart in sorted(CHART_TARGETS):
        record, entry = build_chart_record(candidate, chart, EXPECTED_OBSERVED_AT)
        validate_schema(component_validator, record, f"{chart} draft record")
        leafs = leaf_pointers(record)
        bound = [item["record_pointer"] for item in entry["bindings"]]
        if len(bound) != len(set(bound)) or sorted(bound) != sorted(leafs):
            raise ValueError(f"{chart} field bindings do not cover every record leaf")
        raw = output_bytes(record)
        if sha256_bytes(raw) != entry["content_sha256"] or len(raw) != entry["bytes"]:
            raise ValueError(f"{chart} record entry does not bind exact bytes")
        name = Path(entry["path"]).name
        records[name] = raw
        entries.append(entry)
    if len(records) > MAX_RECORDS:
        raise ValueError("record count exceeds the configured bound")

    gaps: list[dict[str, Any]] = []
    for target_id, (namespace, name) in sorted(RUNTIME_EVIDENCE.items()):
        pointers = find_runtime_pointers(candidate, namespace, name)
        gaps.append(
            record_set_gap(
                "controller_source_identity_unresolved",
                target_id,
                "ambiguous",
                "the accepted candidate observes current, historical, tag, and digest runtime variants but does not prove one canonical controller source repository and exact source tag",
                pointers,
                "independently bind the controller repository, exact tag, publisher, and rights from primary-source evidence",
            )
        )
    gaps.append(
        record_set_gap(
            "candidate_component_absent",
            "cmp:github:argoproj/argo-events",
            "absent",
            "Argo Events has no chart, application, or OCI component in the complete accepted candidate denominator",
            [
                "/components",
                "/discovery_scope/complete",
                "/integrity/exact_counts/components",
            ],
            "keep Events absent unless a later complete accepted denominator proves a selected component",
        )
    )

    generator = {
        "name": GENERATOR,
        "version": GENERATOR_VERSION,
        "source": GENERATOR_SOURCE,
        "source_sha256": sha256_bytes(generator_raw),
        "component_schema_sha256": sha256_bytes(component_schema_raw),
        "record_set_schema_sha256": sha256_bytes(record_set_schema_raw),
        "requirements_sha256": sha256_bytes(requirements_raw),
        "validator_dependencies": dict(sorted(validator_dependencies.items())),
    }
    core = {
        "$schema": "https://github.com/cordanaLLM/knowledge/schemas/registry/reviewed-record-set.schema.json",
        "schema_version": SCHEMA_VERSION,
        "record_set_kind": "reviewed_component_record_set",
        "review": {
            "status": "needs-review",
            "reviewed_by": "unassigned-materialized-draft",
            "reviewed_at": EXPECTED_OBSERVED_AT[:10],
            "evidence": [
                EXPECTED_CANDIDATE_SHA256.replace(
                    "sha256:", "accepted-candidate:sha256:"
                ),
                EXPECTED_CAPTURE_RESULT_SHA256.replace(
                    "sha256:", "capture-result:sha256:"
                ),
                EXPECTED_CAPTURE_MANIFEST_SHA256.replace(
                    "sha256:", "capture-manifest:sha256:"
                ),
            ],
        },
        "authority_state": "non_authoritative",
        "compile_eligible": False,
        "promote_eligible": False,
        "generator": generator,
        "input_artifacts": [
            {
                "role": "accepted_candidate",
                "content_sha256": EXPECTED_CANDIDATE_SHA256,
                "bytes": len(candidate_raw),
                "identity": EXPECTED_CANDIDATE_MANIFEST_ID,
            },
            {
                "role": "capture_result",
                "content_sha256": EXPECTED_CAPTURE_RESULT_SHA256,
                "bytes": len(capture_result_raw),
                "identity": "complete-145-input-capture-result",
            },
            {
                "role": "capture_manifest",
                "content_sha256": EXPECTED_CAPTURE_MANIFEST_SHA256,
                "bytes": len(capture_manifest_raw),
                "identity": f"live-capture-manifest:{EXPECTED_GENERATOR_COMMIT}",
            },
        ],
        "scope": {
            "batch": "P1-SRC-02-argo-initial",
            "records_path": CANONICAL_RECORDS_PATH,
            "candidate_manifest_id": EXPECTED_CANDIDATE_MANIFEST_ID,
            "candidate_generator_commit": EXPECTED_GENERATOR_COMMIT,
            "observed_at": EXPECTED_OBSERVED_AT,
            "materialized_component_ids": sorted(CHART_TARGETS.values()),
            "required_targets": list(REQUIRED_TARGETS),
        },
        "records": sorted(entries, key=lambda item: item["path"]),
        "gaps": sorted(gaps, key=lambda item: (item["target_id"], item["code"])),
        "counts": {
            "records": len(entries),
            "accepted_records": 0,
            "blocking_gaps": len(gaps),
        },
    }
    payload_sha256 = sha256_bytes(canonical_bytes(core))
    record_set = {
        "record_set_id": "reviewed-record-set:" + payload_sha256,
        "payload_sha256": payload_sha256,
        **core,
    }
    validate_schema(record_set_validator, record_set, "reviewed record set")
    return records, record_set


def repository_relative(repo_root: Path, path: Path) -> str:
    try:
        return (
            normalized_absolute(path, "repository path")
            .relative_to(normalized_absolute(repo_root, "repository root"))
            .as_posix()
        )
    except ValueError as error:
        raise ValueError("output must remain inside the repository") from error


def verify_directory_path(path: Path, expected: os.stat_result, label: str) -> None:
    descriptor, current = open_directory_no_follow(path, label)
    try:
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError(f"{label} was replaced during output commit")
    finally:
        os.close(descriptor)


def open_scratch_directory(
    repo_root: Path, output_dir: Path
) -> tuple[int, os.stat_result]:
    relative = repository_relative(repo_root, output_dir)
    parts = Path(relative).parts
    if len(parts) < 2 or parts[0] != ".workingdir2":
        raise ValueError("materializer output must be below repository .workingdir2/")
    descriptor, _ = open_directory_no_follow(repo_root, "repository root")
    try:
        for component in parts:
            try:
                os.mkdir(component, 0o755, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor, os.fstat(descriptor)
    except Exception:
        os.close(descriptor)
        raise


def exact_existing(
    parent_fd: int,
    leaf: str,
    expected: bytes,
    required_inode: tuple[int, int] | None = None,
    *,
    sync: bool = False,
) -> tuple[int, int] | None:
    try:
        descriptor = os.open(
            leaf,
            (os.O_RDWR if sync else os.O_RDONLY)
            | os.O_NONBLOCK
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("existing materializer output is not a regular file")
        inode = (before.st_dev, before.st_ino)
        if required_inode is not None and inode != required_inode:
            raise ValueError("materializer output path is not the writer-owned inode")
        raw = read_descriptor(
            descriptor,
            max(len(expected), MAX_OUTPUT_BYTES),
            "existing materializer output",
        )
        after = os.fstat(descriptor)
        if stat_identity(before) != stat_identity(after):
            raise ValueError("existing materializer output changed while it was read")
        if raw != expected:
            raise ValueError("refusing to replace conflicting materializer output")
        entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat_identity(entry) != stat_identity(after):
            raise ValueError("existing materializer output was replaced after read")
        if sync:
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            durable_replay = read_descriptor(
                descriptor,
                max(len(expected), MAX_OUTPUT_BYTES),
                "existing materializer output",
            )
            durable_after = os.fstat(descriptor)
            if (
                stat_identity(durable_after) != stat_identity(after)
                or durable_replay != expected
            ):
                raise ValueError(
                    "existing materializer output changed during durability replay"
                )
            durable_entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if stat_identity(durable_entry) != stat_identity(durable_after):
                raise ValueError(
                    "existing materializer output was replaced during durability replay"
                )
        reopened = os.open(
            leaf,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            replay_before = os.fstat(reopened)
            replay = read_descriptor(
                reopened,
                max(len(expected), MAX_OUTPUT_BYTES),
                "existing materializer output",
            )
            replay_after = os.fstat(reopened)
            if (
                stat_identity(replay_before) != stat_identity(after)
                or stat_identity(replay_after) != stat_identity(after)
                or replay != expected
            ):
                raise ValueError(
                    "existing materializer output changed during replay check"
                )
            replay_entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if stat_identity(replay_entry) != stat_identity(replay_after):
                raise ValueError(
                    "existing materializer output was replaced during replay check"
                )
        finally:
            os.close(reopened)
        return inode
    finally:
        os.close(descriptor)


def write_exact(parent_fd: int, leaf: str, raw: bytes) -> None:
    if leaf in {"", ".", ".."} or "/" in leaf:
        raise ValueError("materializer output leaf is unsafe")
    existing_inode = exact_existing(parent_fd, leaf, raw, sync=True)
    if existing_inode is not None:
        os.fsync(parent_fd)
        if (
            exact_existing(parent_fd, leaf, raw, required_inode=existing_inode)
            != existing_inode
        ):
            raise ValueError("existing materializer output disappeared during replay")
        return
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o644,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            raced_inode = exact_existing(parent_fd, leaf, raw, sync=True)
            if raced_inode is None:
                raise
            os.fsync(parent_fd)
            if (
                exact_existing(parent_fd, leaf, raw, required_inode=raced_inode)
                != raced_inode
            ):
                raise ValueError(
                    "raced materializer output disappeared during final replay"
                )
            return
        created = os.fstat(descriptor)
        created_inode = (created.st_dev, created.st_ino)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while creating materializer output")
            view = view[written:]
        os.fsync(descriptor)
        written_info = os.fstat(descriptor)
        if (
            (written_info.st_dev, written_info.st_ino) != created_inode
            or not stat.S_ISREG(written_info.st_mode)
            or written_info.st_size != len(raw)
        ):
            raise ValueError("materializer output commit is incomplete")
        output_entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat_identity(output_entry) != stat_identity(written_info):
            raise ValueError("materializer output path changed during commit")
        if (
            exact_existing(parent_fd, leaf, raw, required_inode=created_inode)
            != created_inode
        ):
            raise ValueError(
                "materializer output disappeared during commit verification"
            )
        os.fsync(parent_fd)
        if (
            exact_existing(parent_fd, leaf, raw, required_inode=created_inode)
            != created_inode
        ):
            raise ValueError("materializer output disappeared during final replay")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def verify_exact_directory_entries(
    directory_fd: int, expected: set[str], label: str
) -> None:
    observed: set[str] = set()
    entries = 0
    os.lseek(directory_fd, 0, os.SEEK_SET)
    with os.scandir(directory_fd) as iterator:
        for entry in iterator:
            entries += 1
            if entries > MAX_RECORDS + 2:
                raise ValueError(f"{label} exceeds the configured entry bound")
            if entry.name in observed:
                raise ValueError(f"{label} contains a duplicate entry")
            observed.add(entry.name)
    if observed != expected:
        raise ValueError(
            f"{label} differs from the exact output set "
            f"(missing={sorted(expected - observed)}, "
            f"extra={sorted(observed - expected)})"
        )


def write_bundle(
    repo_root: Path,
    output_dir: Path,
    records: Mapping[str, bytes],
    record_set: Mapping[str, Any],
) -> None:
    output_fd, output_info = open_scratch_directory(repo_root, output_dir)
    try:
        try:
            os.mkdir("records", 0o755, dir_fd=output_fd)
        except FileExistsError:
            pass
        records_fd = os.open(
            "records",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=output_fd,
        )
        records_info = os.fstat(records_fd)
        try:
            for name, raw in sorted(records.items()):
                write_exact(records_fd, name, raw)
            verify_exact_directory_entries(
                records_fd, set(records), "materializer records directory"
            )
            verify_directory_path(
                output_dir / "records",
                records_info,
                "materializer records directory",
            )
        finally:
            os.close(records_fd)
        write_exact(output_fd, "reviewed-record-set.json", output_bytes(record_set))
        verify_exact_directory_entries(
            output_fd,
            {"records", "reviewed-record-set.json"},
            "materializer output directory",
        )
        verify_directory_path(output_dir, output_info, "materializer output directory")
    finally:
        os.close(output_fd)


def load_contracts(
    repo_root: Path,
) -> tuple[
    bytes,
    bytes,
    bytes,
    bytes,
    Any,
    Any,
    dict[str, str],
    list[tuple[Path, int, str, os.stat_result]],
]:
    paths = [
        (repo_root / COMPONENT_SCHEMA_SOURCE, MAX_CONTRACT_BYTES, "component schema"),
        (repo_root / RECORD_SET_SCHEMA_SOURCE, MAX_CONTRACT_BYTES, "record-set schema"),
        (repo_root / REQUIREMENTS_SOURCE, MAX_CONTRACT_BYTES, "validator requirements"),
        (Path(__file__), MAX_CONTRACT_BYTES, "materializer source"),
    ]
    captured: list[tuple[Path, int, str, os.stat_result]] = []
    raw_values: list[bytes] = []
    for path, maximum, label in paths:
        raw, identity = read_regular_capture(path, maximum=maximum, label=label)
        raw_values.append(raw)
        captured.append((path, maximum, sha256_bytes(raw), identity))
    component_raw, record_set_raw, requirements_raw, generator_raw = raw_values
    dependencies = parse_requirement_closure(requirements_raw)
    component_schema = strict_json_loads(component_raw)
    record_set_schema = strict_json_loads(record_set_raw)
    if not isinstance(component_schema, Mapping) or not isinstance(
        record_set_schema, Mapping
    ):
        raise ValueError("reviewed schemas must be JSON objects")
    return (
        generator_raw,
        component_raw,
        record_set_raw,
        requirements_raw,
        schema_validator(component_schema, "component schema"),
        schema_validator(record_set_schema, "record-set schema"),
        dependencies,
        captured,
    )


def materialize(
    repo_root: Path,
    candidate_path: Path,
    capture_result_path: Path,
    capture_manifest_path: Path,
) -> tuple[
    dict[str, bytes], dict[str, Any], list[tuple[Path, int, str, os.stat_result]]
]:
    inputs = [
        (
            candidate_path,
            MAX_CANDIDATE_BYTES,
            "accepted candidate",
            EXPECTED_CANDIDATE_SHA256,
        ),
        (
            capture_result_path,
            MAX_CAPTURE_RESULT_BYTES,
            "capture result",
            EXPECTED_CAPTURE_RESULT_SHA256,
        ),
        (
            capture_manifest_path,
            MAX_CAPTURE_MANIFEST_BYTES,
            "capture manifest",
            EXPECTED_CAPTURE_MANIFEST_SHA256,
        ),
    ]
    raw_values: list[bytes] = []
    captured_inputs: list[tuple[Path, int, str, os.stat_result]] = []
    for path, maximum, label, expected_sha in inputs:
        raw, identity = read_regular_capture(path, maximum=maximum, label=label)
        digest = sha256_bytes(raw)
        if digest != expected_sha:
            raise ValueError(f"{label} digest differs from the accepted artifact")
        raw_values.append(raw)
        captured_inputs.append((path, maximum, digest, identity))
    candidate, capture_result, capture_manifest = [
        strict_json_loads(raw) for raw in raw_values
    ]
    if not all(
        isinstance(value, Mapping)
        for value in (candidate, capture_result, capture_manifest)
    ):
        raise ValueError("accepted artifacts must be JSON objects")
    (
        generator_raw,
        component_schema_raw,
        record_set_schema_raw,
        requirements_raw,
        component_validator,
        record_set_validator,
        dependencies,
        captured_contracts,
    ) = load_contracts(repo_root)
    records, record_set = build_record_set(
        raw_values[0],
        candidate,
        raw_values[1],
        capture_result,
        raw_values[2],
        capture_manifest,
        generator_raw,
        component_schema_raw,
        record_set_schema_raw,
        requirements_raw,
        dependencies,
        component_validator,
        record_set_validator,
    )
    captured = [*captured_inputs, *captured_contracts]
    for path, maximum, digest, identity in captured:
        recheck_regular(
            path,
            maximum=maximum,
            expected_sha256=digest,
            expected_identity=identity,
            label=f"captured input {path.name}",
        )
    return records, record_set, captured


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("materialize",))
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--capture-result", type=Path, required=True)
    parser.add_argument("--capture-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        repo_root = Path(__file__).resolve().parents[2]
        output_dir = (
            args.output_dir
            if args.output_dir.is_absolute()
            else repo_root / args.output_dir
        )
        records, record_set, captured = materialize(
            repo_root,
            args.candidate,
            args.capture_result,
            args.capture_manifest,
        )
        write_bundle(repo_root, output_dir, records, record_set)
        for path, maximum, digest, identity in captured:
            recheck_regular(
                path,
                maximum=maximum,
                expected_sha256=digest,
                expected_identity=identity,
                label=f"captured input {path.name}",
            )
        sys.stdout.write(
            json.dumps(
                {
                    "record_set_id": record_set["record_set_id"],
                    "records": len(records),
                    "accepted_records": 0,
                    "blocking_gaps": record_set["counts"]["blocking_gaps"],
                    "output_dir": repository_relative(repo_root, output_dir),
                },
                sort_keys=True,
            )
            + "\n"
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Argo record-set materialization failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
