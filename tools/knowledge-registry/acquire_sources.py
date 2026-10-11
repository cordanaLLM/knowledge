#!/usr/bin/env python3
"""Plan bounded exact-source acquisition from reviewed records.

The planner is intentionally not a reviewer or runner.  It reads accepted
registry records and emits a non-authoritative plan.  Unsupported or
insufficient records remain visible as typed gaps.  Fetch, inventory, cache,
proposal, admission, release, pointer, Git, and production mutation surfaces
are deliberately absent until a separately reviewed exact runner lands.
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
import types
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

RECORD_SCHEMA_VERSION = "1.0.0"
PLAN_SCHEMA_VERSION = "2.0.0"
PLAN_V3_SCHEMA_VERSION = "3.0.0"
GENERATOR = "archeion-reviewed-source-acquisition"
GENERATOR_VERSION = "4"
GENERATOR_V3_VERSION = "5"
GENERATOR_SOURCE = "tools/knowledge-registry/acquire_sources.py"
REGISTRY_VALIDATOR_SOURCE = "tools/knowledge-registry/knowledge_registry.py"
REVIEWED_SCHEMA_SOURCE = "knowledge/registry/schemas/component-record.schema.json"
RECORD_SET_SCHEMA_SOURCE = "knowledge/registry/schemas/reviewed-record-set.schema.json"
REVIEWED_REQUIREMENTS_SOURCE = "tools/knowledge-registry/requirements-reviewed.txt"
DEFAULT_RECORD_SET_SOURCE = "knowledge/registry/record-sets/argo-p1-src-02.json"
DEFAULT_ARTIFACT_BUNDLE_SOURCE = (
    "knowledge/registry/acceptance/p1-src-02/" "accepted-record-artifact-bundle.json"
)
ARTIFACT_BUNDLE_RESOLVER_SOURCE = (
    "tools/knowledge-registry/materialize_record_artifact_bundle.py"
)
ARTIFACT_BUNDLE_SCHEMA_SOURCE = (
    "knowledge/registry/schemas/accepted-record-artifact-bundle.schema.json"
)
PLAN_V3_SCHEMA_SOURCE = "knowledge/registry/schemas/source-acquisition-plan.schema.json"
PLAN_V3_SCHEMA_URI = (
    "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-plan.schema.json"
)
PLAN_KIND = "reviewed_source_acquisition_plan"
RUNTIME_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?$")
CHART_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?$")
# The corrective source-resolution records bind an exact 40-hex Git commit, not
# a refs/tags value.  The tag/subtree live in build_metadata.source_resolution.
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CHART_SOURCE_PUBLISHER = "Argo Project (argoproj)"
CHART_SOURCE_RIGHTS = (
    "Apache-2.0 for Argo-authored material only; bundled and referenced "
    "third-party dependencies retain their own rights"
)
CHART_SOURCE_REFRESH_POLICY = (
    "immutable locator; re-resolve only through a new reviewed record"
)
CHART_SOURCE_LICENSE_SPDX = "Apache-2.0"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 1_000_000
MAX_RECORD_DIRECTORY_ENTRIES = 8192
MAX_RECORD_FILES = 4096
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_VERSIONS_PER_RECORD = 256
MAX_TARGETS = 8192
MAX_COMPONENT_FILTERS = 1024
MAX_PLAN_CANONICAL_BYTES = 16 * 1024 * 1024
MAX_PLAN_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_CONTRACT_FILE_BYTES = 128 * 1024 * 1024
REQUIRED_VALIDATOR_DISTRIBUTIONS = frozenset(
    {"attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py"}
)
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s#]+)$")

V3_COMPONENT_ROOTS = {
    "cmp:helm:argoproj/argo-rollouts": "charts/argo-rollouts",
    "cmp:helm:argoproj/argo-workflows": "charts/argo-workflows",
}
V3_COMPONENT_RECORD_PATHS = {
    "cmp:helm:argoproj/argo-rollouts": (
        "knowledge/registry/records/argo-argo-rollouts-chart.json"
    ),
    "cmp:helm:argoproj/argo-workflows": (
        "knowledge/registry/records/argo-argo-workflows-chart.json"
    ),
}
GITHUB_GIT_OBJECTS_CAPABILITY_CORE = {
    "api_origin": "https://api.github.com",
    "api_version": "2026-03-10",
    "capability_id": "github-git-objects-rest-v1",
    "object_format": "sha1",
    "supported_modes": ["040000", "100644", "100755"],
    "transport": "https-json",
}
GITHUB_GIT_OBJECTS_CAPABILITY_CONTRACT_SHA256 = (
    "sha256:dbc41fe166ae7672119d2655b57be528151474cad8edb4c8332a95c6f5151889"
)
V3_TARGET_FIELDS = (
    "target_id",
    "state",
    "record_sha256",
    "record_id",
    "component_id",
    "component_version_id",
    "component_kind",
    "lifecycle",
    "repository",
    "resolved_version",
    "requested_tag",
    "expected_commit",
    "content_roots",
    "target_identity",
    "source_resolution_review_state",
    "source_authorization",
    "channel_id",
    "channel_type",
    "gaps",
)
LEGACY_FETCH_FIELDS = frozenset(
    {
        "fetch_adapter",
        "fetch_argument",
        "fetch_component",
        "cache_key",
        "content_profile",
        "source_subtree",
    }
)


def compile_python_module(raw: bytes, source: Path) -> Any:
    """Compile exactly ``raw``; never consult timestamp/hash bytecode caches."""

    try:
        code = compile(raw, source.as_posix(), "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as error:
        raise ValueError(
            f"could not compile reviewed-record validator: {error}"
        ) from error
    digest = hashlib.sha256(raw).hexdigest()
    name = f"archeion_knowledge_registry_contract_{digest}"
    module = types.ModuleType(name)
    module.__file__ = source.as_posix()
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


# The fetch adapter is narrower than the registry on purpose.  A record can be
# fully reviewed and still remain a typed acquisition gap until its content
# selection adapter exists.  This avoids treating a repository-wide clone as a
# documentation snapshot or guessing a package subtree.
ARGO_SOURCE_PROFILES: dict[str, dict[str, str]] = {
    "cmp:github:argoproj/argo-cd": {
        "component_kind": "controller",
        "fetch_argument": "--argo-snapshot",
        "fetch_adapter": "docs/fetch-docs.sh:argo-snapshot-v1",
        "fetch_component": "argocd",
        "cache_key": "argocd",
        "repository": "argoproj/argo-cd",
        "content_profile": "docs-crds",
        "display_name": "Argo CD",
        "snapshot_name": "argocd",
        "source_subtree": "",
        "tag_format": "runtime",
        "version_id_prefix": "ver:github:argoproj/argo-cd@",
    },
    "cmp:github:argoproj/argo-workflows": {
        "component_kind": "controller",
        "fetch_argument": "--argo-snapshot",
        "fetch_adapter": "docs/fetch-docs.sh:argo-snapshot-v1",
        "fetch_component": "argo-workflows",
        "cache_key": "argo-workflows",
        "repository": "argoproj/argo-workflows",
        "content_profile": "docs-crds-openapi",
        "display_name": "Argo Workflows",
        "snapshot_name": "argo-workflows",
        "source_subtree": "",
        "tag_format": "runtime",
        "version_id_prefix": "ver:github:argoproj/argo-workflows@",
    },
    "cmp:github:argoproj/argo-rollouts": {
        "component_kind": "controller",
        "fetch_argument": "--argo-snapshot",
        "fetch_adapter": "docs/fetch-docs.sh:argo-snapshot-v1",
        "fetch_component": "argo-rollouts",
        "cache_key": "argo-rollouts",
        "repository": "argoproj/argo-rollouts",
        "content_profile": "docs-crds",
        "display_name": "Argo Rollouts",
        "snapshot_name": "argo-rollouts",
        "source_subtree": "",
        "tag_format": "runtime",
        "version_id_prefix": "ver:github:argoproj/argo-rollouts@",
    },
    "cmp:github:argoproj/argo-events": {
        "component_kind": "controller",
        "fetch_argument": "--argo-snapshot",
        "fetch_adapter": "docs/fetch-docs.sh:argo-snapshot-v1",
        "fetch_component": "argo-events",
        "cache_key": "argo-events",
        "repository": "argoproj/argo-events",
        "content_profile": "docs-crds-openapi",
        "display_name": "Argo Events",
        "snapshot_name": "argo-events",
        "source_subtree": "",
        "tag_format": "runtime",
        "version_id_prefix": "ver:github:argoproj/argo-events@",
    },
    "cmp:helm:argoproj/argo-cd": {
        "component_kind": "chart",
        "fetch_argument": "--argo-chart-snapshot",
        "fetch_adapter": "docs/fetch-docs.sh:argo-chart-snapshot-v1",
        "fetch_component": "argo-cd",
        "cache_key": "argo-helm-argo-cd",
        "repository": "argoproj/argo-helm",
        "content_profile": "helm-chart-subtree",
        "display_name": "Argo CD Helm chart",
        "snapshot_name": "argo-helm-argo-cd",
        "source_subtree": "charts/argo-cd",
        "tag_format": "argo-cd-chart",
        "version_id_prefix": "ver:helm:argoproj/argo-cd@",
    },
    "cmp:helm:argoproj/argo-rollouts": {
        "component_kind": "chart",
        "fetch_argument": "--argo-chart-snapshot",
        "fetch_adapter": "docs/fetch-docs.sh:argo-chart-snapshot-v1",
        "fetch_component": "argo-rollouts",
        "cache_key": "argo-helm-argo-rollouts",
        "repository": "argoproj/argo-helm",
        "content_profile": "helm-chart-subtree",
        "display_name": "Argo Rollouts Helm chart",
        "snapshot_name": "argo-helm-argo-rollouts",
        "source_subtree": "charts/argo-rollouts",
        "tag_format": "argo-rollouts-chart",
        "version_id_prefix": "ver:helm:argoproj/argo-rollouts@",
    },
    "cmp:helm:argoproj/argo-workflows": {
        "component_kind": "chart",
        "fetch_argument": "--argo-chart-snapshot",
        "fetch_adapter": "docs/fetch-docs.sh:argo-chart-snapshot-v1",
        "fetch_component": "argo-workflows",
        "cache_key": "argo-helm-argo-workflows",
        "repository": "argoproj/argo-helm",
        "content_profile": "helm-chart-subtree",
        "display_name": "Argo Workflows Helm chart",
        "snapshot_name": "argo-helm-argo-workflows",
        "source_subtree": "charts/argo-workflows",
        "tag_format": "argo-workflows-chart",
        "version_id_prefix": "ver:helm:argoproj/argo-workflows@",
    },
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
        raise ValueError(f"{label} must not contain ambiguous path components")
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
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"{label} is not a directory")
        return descriptor, info
    except Exception:
        os.close(descriptor)
        raise


def read_regular_at(
    directory_fd: int, name: str, *, max_bytes: int, label: str
) -> tuple[bytes, os.stat_result]:
    if not name or name in {".", ".."} or "/" in name:
        raise ValueError(f"{label} has an unsafe leaf name")
    # O_NONBLOCK is immaterial for regular files and prevents a named pipe or
    # device leaf from hanging the planner before fstat can reject its type.
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if before.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        if len(raw) != before.st_size or stat_identity(before) != stat_identity(after):
            raise ValueError(f"{label} changed while it was read")
        reopened = os.open(name, flags, dir_fd=directory_fd)
        try:
            if stat_identity(os.fstat(reopened)) != stat_identity(after):
                raise ValueError(f"{label} was replaced after it was read")
        finally:
            os.close(reopened)
        return raw, after
    finally:
        os.close(descriptor)


def read_regular_capture(
    path: Path, *, max_bytes: int, label: str
) -> tuple[bytes, os.stat_result]:
    absolute = normalized_absolute(path, label)
    if len(absolute.parts) < 2:
        raise ValueError(f"{label} does not name a file")
    parent_fd, _ = open_directory_no_follow(absolute.parent, f"{label} parent")
    try:
        return read_regular_at(
            parent_fd, absolute.name, max_bytes=max_bytes, label=label
        )
    finally:
        os.close(parent_fd)


def file_sha256(path: Path, max_bytes: int = MAX_CONTRACT_FILE_BYTES) -> str:
    raw, _ = read_regular_capture(path, max_bytes=max_bytes, label=str(path))
    return sha256_bytes(raw)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(data: bytes | str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number is forbidden: {value}")

    value = json.loads(
        data,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON input exceeds the configured node bound")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON input exceeds the configured nesting bound")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def read_regular_json_with_size(
    path: Path, max_bytes: int = MAX_JSON_BYTES
) -> tuple[Any, int, str]:
    data, _ = read_regular_capture(path, max_bytes=max_bytes, label=f"JSON file {path}")
    return strict_json_loads(data), len(data), sha256_bytes(data)


def read_regular_json(path: Path, max_bytes: int = MAX_JSON_BYTES) -> Any:
    value, _, _ = read_regular_json_with_size(path, max_bytes)
    return value


def repository_relative(repo_root: Path, path: Path) -> str:
    root = normalized_absolute(repo_root, "repository root")
    candidate = normalized_absolute(path, "repository path")
    return candidate.relative_to(root).as_posix()


def parse_requirement_closure(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("reviewed validator requirements are not UTF-8") from error
    pins: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_RE.fullmatch(line)
        if match is None:
            raise ValueError(
                f"reviewed validator requirement line {line_number} is not an exact pin"
            )
        name, version = match.groups()
        normalized = name.lower().replace("_", "-")
        if normalized in pins:
            raise ValueError(f"duplicate reviewed validator requirement: {normalized}")
        pins[normalized] = version
    if set(pins) != REQUIRED_VALIDATOR_DISTRIBUTIONS:
        raise ValueError(
            "reviewed validator requirements do not name the exact closure"
        )
    installed: dict[str, str] = {}
    for name in sorted(pins):
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as error:
            raise ValueError(
                f"reviewed validator dependency is not installed: {name}"
            ) from error
        if actual != pins[name]:
            raise ValueError(
                f"reviewed validator requires {name}=={pins[name]}, found {actual}"
            )
        installed[name] = actual
    return installed


def reviewed_contract_paths() -> tuple[Path, Path, Path, Path]:
    repo_root = Path(__file__).resolve().parents[2]
    return (
        repo_root / REGISTRY_VALIDATOR_SOURCE,
        repo_root / REVIEWED_SCHEMA_SOURCE,
        repo_root / RECORD_SET_SCHEMA_SOURCE,
        repo_root / REVIEWED_REQUIREMENTS_SOURCE,
    )


def load_artifact_bundle_resolver(
    repo_root: Path,
) -> tuple[Any, str, dict[Path, str]]:
    """Load the exact no-copy resolver source without consulting bytecode."""

    resolver_path = repo_root / ARTIFACT_BUNDLE_RESOLVER_SOURCE
    resolver_raw, _ = read_regular_capture(
        resolver_path,
        max_bytes=MAX_CONTRACT_FILE_BYTES,
        label="accepted-record artifact-bundle resolver source",
    )
    resolver_sha256 = sha256_bytes(resolver_raw)
    resolver = compile_python_module(resolver_raw, resolver_path)
    return resolver, resolver_sha256, {resolver_path: resolver_sha256}


def fixed_github_git_objects_capability() -> dict[str, Any]:
    digest = sha256_bytes(canonical_bytes(GITHUB_GIT_OBJECTS_CAPABILITY_CORE))
    if digest != GITHUB_GIT_OBJECTS_CAPABILITY_CONTRACT_SHA256:
        raise ValueError("fixed Git-object capability contract digest drifted")
    return {
        "capability_id": GITHUB_GIT_OBJECTS_CAPABILITY_CORE["capability_id"],
        "capability_contract_sha256": digest,
        "transport": GITHUB_GIT_OBJECTS_CAPABILITY_CORE["transport"],
        "api_origin": GITHUB_GIT_OBJECTS_CAPABILITY_CORE["api_origin"],
        "api_version": GITHUB_GIT_OBJECTS_CAPABILITY_CORE["api_version"],
        "object_format": GITHUB_GIT_OBJECTS_CAPABILITY_CORE["object_format"],
        "supported_modes": list(GITHUB_GIT_OBJECTS_CAPABILITY_CORE["supported_modes"]),
    }


def load_reviewed_contract() -> tuple[Any, Any, Any, dict[str, Any], dict[Path, str]]:
    (
        validator_path,
        schema_path,
        record_set_schema_path,
        requirements_path,
    ) = reviewed_contract_paths()
    validator_raw, _ = read_regular_capture(
        validator_path,
        max_bytes=MAX_CONTRACT_FILE_BYTES,
        label="reviewed-record validator source",
    )
    schema_raw, _ = read_regular_capture(
        schema_path,
        max_bytes=MAX_JSON_BYTES,
        label="reviewed component schema",
    )
    record_set_schema_raw, _ = read_regular_capture(
        record_set_schema_path,
        max_bytes=MAX_JSON_BYTES,
        label="reviewed record-set schema",
    )
    requirements_raw, _ = read_regular_capture(
        requirements_path,
        max_bytes=MAX_JSON_BYTES,
        label="reviewed validator requirements",
    )
    validator_sha256 = sha256_bytes(validator_raw)
    schema_sha256 = sha256_bytes(schema_raw)
    record_set_schema_sha256 = sha256_bytes(record_set_schema_raw)
    requirements_sha256 = sha256_bytes(requirements_raw)
    dependencies = parse_requirement_closure(requirements_raw)
    registry = compile_python_module(validator_raw, validator_path)
    original_reader = registry.read_regular_file
    schema_absolute = normalized_absolute(schema_path, "reviewed component schema")
    record_set_schema_absolute = normalized_absolute(
        record_set_schema_path, "reviewed record-set schema"
    )

    def bound_schema_reader(path: Path, *, max_bytes: int, label: str) -> bytes:
        candidate = normalized_absolute(Path(path), label)
        if candidate == schema_absolute:
            if len(schema_raw) > max_bytes:
                raise ValueError(f"{label} exceeds byte bound {max_bytes}")
            return schema_raw
        if candidate == record_set_schema_absolute:
            if len(record_set_schema_raw) > max_bytes:
                raise ValueError(f"{label} exceeds byte bound {max_bytes}")
            return record_set_schema_raw
        return original_reader(path, max_bytes=max_bytes, label=label)

    registry.read_regular_file = bound_schema_reader
    # The acquisition contract stays pinned to the frozen v1.0 reviewed schema.
    registry.REVIEWED_SCHEMA_RELATIVE = REVIEWED_SCHEMA_SOURCE
    schema_validator = registry.reviewed_record_validator()
    record_set_validator = registry.draft202012_validator(
        RECORD_SET_SCHEMA_SOURCE,
        label="reviewed record-set schema",
    )
    binding = {
        "reviewed_record_validator_source": REGISTRY_VALIDATOR_SOURCE,
        "reviewed_record_validator_sha256": validator_sha256,
        "reviewed_record_schema_source": REVIEWED_SCHEMA_SOURCE,
        "reviewed_record_schema_sha256": schema_sha256,
        "reviewed_record_set_schema_source": RECORD_SET_SCHEMA_SOURCE,
        "reviewed_record_set_schema_sha256": record_set_schema_sha256,
        "reviewed_validator_requirements_source": REVIEWED_REQUIREMENTS_SOURCE,
        "reviewed_validator_requirements_sha256": requirements_sha256,
        "reviewed_validator_dependencies": dependencies,
    }
    expected = {
        validator_path: validator_sha256,
        schema_path: schema_sha256,
        record_set_schema_path: record_set_schema_sha256,
        requirements_path: requirements_sha256,
    }
    return registry, schema_validator, record_set_validator, binding, expected


def recheck_contract_files(expected: Mapping[Path, str]) -> None:
    for path, digest in expected.items():
        maximum = (
            MAX_JSON_BYTES
            if path.suffix in {".json", ".txt"}
            else MAX_CONTRACT_FILE_BYTES
        )
        raw, _ = read_regular_capture(
            path,
            max_bytes=maximum,
            label=f"reviewed contract file {path}",
        )
        if sha256_bytes(raw) != digest:
            raise ValueError(
                f"reviewed contract file changed during plan generation: {path}"
            )
        if path.name == Path(REVIEWED_REQUIREMENTS_SOURCE).name:
            parse_requirement_closure(raw)


def gap(code: str, message: str, *, blocking: bool = True) -> dict[str, Any]:
    return {"code": code, "message": message, "blocking": blocking}


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


def binding_evidence_prefixes(record_set: Mapping[str, Any]) -> dict[str, str]:
    artifacts = record_set.get("input_artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("normalized binding ledger input artifacts are invalid")
    by_role: dict[str, Mapping[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            raise ValueError("normalized binding ledger input artifact is invalid")
        role = str(artifact.get("role") or "")
        if role in by_role:
            raise ValueError("normalized binding ledger input roles are not unique")
        by_role[role] = artifact
    if set(by_role) != {"accepted_candidate", "capture_result", "capture_manifest"}:
        raise ValueError("normalized binding ledger input roles are incomplete")

    def prefix(role: str, label: str) -> str:
        digest = by_role[role].get("content_sha256")
        if not isinstance(digest, str) or not re.fullmatch(
            r"sha256:[a-f0-9]{64}", digest
        ):
            raise ValueError("normalized binding ledger input digest is invalid")
        return digest.replace("sha256:", f"{label}:sha256:", 1)

    return {
        "candidate-pointer": prefix("accepted_candidate", "accepted-candidate"),
        "capture-pointer": prefix("capture_manifest", "capture-manifest"),
    }


def normalized_binding_atom_core(atom: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in atom.items() if key != "atom_id"}


def normalized_logical_binding(
    pointer: str,
    atom: Mapping[str, Any],
    source_pointer: str | None,
) -> dict[str, Any]:
    kind = str(atom["binding_kind"])
    source_uri = atom.get("source_uri") if kind == "primary-source" else None
    if kind in {"candidate-pointer", "capture-pointer"}:
        evidence = [str(atom["evidence_identity_prefix"]) + str(source_pointer)]
    elif kind == "primary-source":
        evidence = [source_uri]
    else:
        evidence = atom["evidence"]
    return {
        "record_pointer": pointer,
        "binding_kind": kind,
        "source_pointer": source_pointer,
        "source_uri": source_uri,
        "evidence": evidence,
        "derivation": atom["derivation"],
    }


def validate_normalized_atom(
    atom: Mapping[str, Any],
    prefixes: Mapping[str, str],
    registry: Any,
) -> None:
    kind = atom.get("binding_kind")
    if kind in {"candidate-pointer", "capture-pointer"}:
        expected_keys = {
            "atom_id",
            "binding_kind",
            "evidence_identity_prefix",
            "derivation",
        }
        if set(atom) != expected_keys:
            raise ValueError("normalized pointer atom fields are invalid")
        if atom.get("evidence_identity_prefix") != prefixes[kind]:
            raise ValueError("normalized pointer atom evidence identity is invalid")
    elif kind == "primary-source":
        expected_keys = {"atom_id", "binding_kind", "source_uri", "derivation"}
        if set(atom) != expected_keys:
            raise ValueError("normalized primary atom fields are invalid")
        source_uri = atom.get("source_uri")
        if not isinstance(source_uri, str) or not source_uri.startswith("https://"):
            raise ValueError("normalized primary atom requires an HTTPS source URI")
        uri_errors = registry.validate_reviewed_uri_safety({"uri": source_uri})
        if uri_errors:
            raise ValueError(
                "normalized primary atom URI is unsafe: " + "; ".join(uri_errors[:4])
            )
    elif kind in {"derived", "control"}:
        expected_keys = {"atom_id", "binding_kind", "evidence", "derivation"}
        if set(atom) != expected_keys:
            raise ValueError("normalized static atom fields are invalid")
        evidence = atom.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("normalized static atom evidence is invalid")
        uri_errors = registry.validate_reviewed_uri_safety({"evidence": evidence})
        if uri_errors:
            raise ValueError(
                "normalized static atom evidence is unsafe: "
                + "; ".join(uri_errors[:4])
            )
    else:
        raise ValueError("normalized binding atom kind is invalid")
    derivation = atom.get("derivation")
    if not isinstance(derivation, str) or not derivation:
        raise ValueError("normalized binding atom derivation is invalid")
    atom_id = atom.get("atom_id")
    expected_id = "binding-atom:" + sha256_bytes(
        canonical_bytes(normalized_binding_atom_core(atom))
    )
    if atom_id != expected_id:
        raise ValueError("normalized binding atom content identity is invalid")


def validate_source_resolution_binding_semantics(
    record: Mapping[str, Any],
    bindings: Sequence[Mapping[str, Any]],
    relative: str,
) -> None:
    versions = record.get("versions")
    if not isinstance(versions, list) or not versions:
        return
    first = versions[0]
    if not isinstance(first, Mapping):
        return
    metadata = first.get("build_metadata")
    if not isinstance(metadata, Mapping) or "source_resolution" not in metadata:
        return
    by_pointer = {str(binding["record_pointer"]): binding for binding in bindings}
    root = "/versions/0/build_metadata/source_resolution/runtime_mapping/components"
    resolution = metadata["source_resolution"]
    runtime_mapping = (
        resolution.get("runtime_mapping") if isinstance(resolution, Mapping) else None
    )
    components = (
        runtime_mapping.get("components")
        if isinstance(runtime_mapping, Mapping)
        else None
    )
    if not isinstance(components, list):
        raise ValueError(
            f"normalized source-resolution runtime mapping is invalid: {relative}"
        )
    for index, _component in enumerate(components):
        canonical_pointer = f"{root}/{index}/canonical_runtime_id"
        canonical = by_pointer.get(canonical_pointer)
        if canonical is None or canonical.get("binding_kind") != "derived":
            raise ValueError(
                f"normalized canonical runtime identity must be derived: {relative}"
            )
        for field in ("upstream_tag", "upstream_commit"):
            pointer = f"{root}/{index}/source_admission/{field}"
            admission = by_pointer.get(pointer)
            if (
                admission is None
                or admission.get("binding_kind") != "primary-source"
                or not admission.get("source_uri")
            ):
                raise ValueError(
                    f"normalized runtime source admission must be primary-bound: {relative}"
                )


def validate_v2_binding_ledger(
    record_set: Mapping[str, Any],
    records_by_path: Mapping[str, Mapping[str, Any]],
    registry: Any,
) -> dict[str, list[dict[str, Any]]]:
    ledger = record_set.get("binding_ledger")
    if not isinstance(ledger, Mapping):
        raise ValueError("normalized binding ledger is missing")
    if ledger.get("version") != 2:
        raise ValueError("normalized binding ledger version is invalid")
    if ledger.get("atom_order_algorithm") != "binding-atom-id-lexicographic-v1":
        raise ValueError("normalized binding atom-order algorithm is invalid")
    if ledger.get("leaf_order_algorithm") != "canonical-json-leaf-pointers-v1":
        raise ValueError("normalized binding leaf-order algorithm is invalid")
    atoms = ledger.get("atoms")
    if not isinstance(atoms, list) or not atoms:
        raise ValueError("normalized binding atoms are missing")
    if ledger.get("atom_count") != len(atoms):
        raise ValueError("normalized binding atom count is invalid")
    prefixes = binding_evidence_prefixes(record_set)
    atom_ids: list[str] = []
    for atom in atoms:
        if not isinstance(atom, Mapping):
            raise ValueError("normalized binding atom is invalid")
        validate_normalized_atom(atom, prefixes, registry)
        atom_ids.append(str(atom["atom_id"]))
    if atom_ids != sorted(atom_ids) or len(atom_ids) != len(set(atom_ids)):
        raise ValueError("normalized binding atoms are not uniquely sorted")
    entries = record_set.get("records")
    if not isinstance(entries, list):
        raise ValueError("normalized binding record entries are invalid")
    used_atoms: set[int] = set()
    logical_ledger: list[dict[str, Any]] = []
    by_path: dict[str, list[dict[str, Any]]] = {}
    for entry in sorted(entries, key=lambda item: str(item.get("path") or "")):
        if not isinstance(entry, Mapping):
            raise ValueError("normalized binding record entry is invalid")
        relative = str(entry.get("path") or "")
        record = records_by_path.get(relative)
        if record is None:
            raise ValueError(
                f"normalized binding record has no denominator: {relative}"
            )
        record_ledger = entry.get("binding_ledger")
        if not isinstance(record_ledger, Mapping):
            raise ValueError(f"normalized record binding ledger is missing: {relative}")
        if (
            record_ledger.get("leaf_order_algorithm")
            != "canonical-json-leaf-pointers-v1"
        ):
            raise ValueError(
                f"normalized record leaf-order algorithm is invalid: {relative}"
            )
        leafs = leaf_pointers(record)
        tuples = record_ledger.get("tuples")
        if not isinstance(tuples, list):
            raise ValueError(f"normalized binding tuples are missing: {relative}")
        if record_ledger.get("leaf_count") != len(leafs):
            raise ValueError(f"normalized binding leaf count is invalid: {relative}")
        if record_ledger.get("tuple_count") != len(tuples) or len(tuples) != len(leafs):
            raise ValueError(f"normalized binding tuple count is invalid: {relative}")
        if record_ledger.get("leaf_pointers_sha256") != sha256_bytes(
            canonical_bytes(leafs)
        ):
            raise ValueError(
                f"normalized binding leaf enumeration is invalid: {relative}"
            )
        bindings: list[dict[str, Any]] = []
        for pointer, item in zip(leafs, tuples, strict=True):
            if not isinstance(item, list) or len(item) not in {1, 2}:
                raise ValueError(
                    f"normalized binding tuple shape is invalid: {relative}"
                )
            index = item[0]
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < len(atoms)
            ):
                raise ValueError(
                    f"normalized binding atom index is invalid: {relative}"
                )
            used_atoms.add(index)
            atom = atoms[index]
            kind = atom["binding_kind"]
            if kind in {"candidate-pointer", "capture-pointer"}:
                if (
                    len(item) != 2
                    or not isinstance(item[1], str)
                    or not item[1].startswith("/")
                ):
                    raise ValueError(
                        f"normalized pointer tuple payload is invalid: {relative}"
                    )
                source_pointer = item[1]
            else:
                if len(item) != 1:
                    raise ValueError(
                        f"normalized non-pointer tuple payload is invalid: {relative}"
                    )
                source_pointer = None
            bindings.append(normalized_logical_binding(pointer, atom, source_pointer))
        if record_ledger.get("logical_bindings_sha256") != sha256_bytes(
            canonical_bytes(bindings)
        ):
            raise ValueError(
                f"normalized logical binding digest is invalid: {relative}"
            )
        validate_source_resolution_binding_semantics(record, bindings, relative)
        by_path[relative] = bindings
        logical_ledger.append({"path": relative, "bindings": bindings})
    if used_atoms != set(range(len(atoms))):
        raise ValueError("normalized binding ledger contains an unused atom")
    if ledger.get("logical_ledger_sha256") != sha256_bytes(
        canonical_bytes(logical_ledger)
    ):
        raise ValueError("normalized full logical ledger digest is invalid")
    return by_path


def schema_errors(validator: Any, value: Any) -> list[str]:
    errors: list[str] = []
    for error in sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        pointer = "/" + "/".join(str(part) for part in error.path)
        errors.append(f"{pointer}: {error.message}")
    return errors


def read_record_set(
    record_set_path: Path,
    validator: Any,
) -> tuple[Mapping[str, Any], str, os.stat_result]:
    raw, identity = read_regular_capture(
        record_set_path,
        max_bytes=MAX_JSON_BYTES,
        label="reviewed record-set manifest",
    )
    value = strict_json_loads(raw)
    if not isinstance(value, dict):
        raise ValueError("reviewed record-set manifest must be an object")
    errors = schema_errors(validator, value)
    if errors:
        raise ValueError(
            "reviewed record-set schema failure: " + "; ".join(errors[:32])
        )
    core = {
        key: item
        for key, item in value.items()
        if key not in {"record_set_id", "payload_sha256"}
    }
    payload_sha256 = sha256_bytes(canonical_bytes(core))
    if value.get("payload_sha256") != payload_sha256:
        raise ValueError("reviewed record-set payload digest is invalid")
    if value.get("record_set_id") != "reviewed-record-set:" + payload_sha256:
        raise ValueError("reviewed record-set identity is invalid")
    return value, sha256_bytes(raw), identity


def record_set_denominator_accepted(record_set: Mapping[str, Any]) -> bool:
    """The exact denominator/binding-ledger is independently accepted.

    This is deliberately separate from per-record and per-channel network
    authorization.  Partial explicit coverage is required: a set may be an
    accepted, reviewed denominator while individual records remain proposed and
    while unrelated Events/runtime/OCI lanes keep blocking set-level gaps.  A
    selected chart target is authorized only when this denominator is accepted
    *and* its own record/channel/rights/identity independently pass; the set's
    unrelated gaps must never revoke that authorization.  Whole-set acceptance
    (`review.status`) plus the reviewed authority state gate the denominator;
    the per-target readiness in :func:`plan_target` gates the rest.
    """

    review = record_set.get("review")
    return (
        isinstance(review, Mapping)
        and review.get("status") == "accepted"
        and record_set.get("authority_state") == "reviewed"
    )


def validate_record_set_denominator(
    repo_root: Path,
    records_dir: Path,
    record_set: Mapping[str, Any],
    denominator_records: Sequence[tuple[Path, str, Mapping[str, Any], os.stat_result]],
    registry: Any,
    schema_validator: Any,
) -> None:
    scope = record_set.get("scope")
    if not isinstance(scope, Mapping) or scope.get(
        "records_path"
    ) != repository_relative(repo_root, records_dir):
        raise ValueError(
            "reviewed record-set records_path differs from the denominator"
        )
    manifest_records = record_set.get("records")
    if not isinstance(manifest_records, list):
        raise ValueError("reviewed record-set records must be an array")
    by_path: dict[str, Mapping[str, Any]] = {}
    for entry in manifest_records:
        if not isinstance(entry, Mapping):
            raise ValueError("reviewed record-set entry must be an object")
        path = str(entry.get("path") or "")
        if path in by_path:
            raise ValueError("reviewed record-set contains a duplicate record path")
        by_path[path] = entry
    actual_paths = {
        repository_relative(repo_root, path)
        for path, _digest, _record, _identity in denominator_records
    }
    if set(by_path) != actual_paths:
        missing = sorted(set(by_path) - actual_paths)
        extra = sorted(actual_paths - set(by_path))
        raise ValueError(
            "reviewed record-set directory equality failed "
            f"(missing={missing}, extra={extra})"
        )
    records_by_path = {
        repository_relative(repo_root, path): record
        for path, _digest, record, _identity in denominator_records
    }
    generator = record_set.get("generator")
    generator_name = generator.get("name") if isinstance(generator, Mapping) else None
    v2_bindings: dict[str, list[dict[str, Any]]] | None = None
    if generator_name == "archeion-argo-source-resolution-materializer":
        v2_bindings = validate_v2_binding_ledger(record_set, records_by_path, registry)
    elif record_set.get("binding_ledger") is not None:
        raise ValueError("legacy record set must not carry a normalized binding ledger")
    accepted_records: list[tuple[str, Mapping[str, Any]]] = []
    seen_record_ids: set[str] = set()
    seen_component_ids: set[str] = set()
    for path, digest, record, identity in denominator_records:
        relative = repository_relative(repo_root, path)
        entry = by_path[relative]
        raw_size = identity.st_size
        if entry.get("content_sha256") != digest or entry.get("bytes") != raw_size:
            raise ValueError(f"reviewed record-set digest/size mismatch: {relative}")
        if entry.get("record_id") != record.get("record_id"):
            raise ValueError(
                f"reviewed record-set record identity mismatch: {relative}"
            )
        component = record.get("component")
        component_id = (
            component.get("component_id") if isinstance(component, Mapping) else None
        )
        review = record.get("review")
        review_status = review.get("status") if isinstance(review, Mapping) else None
        if entry.get("component_id") != component_id:
            raise ValueError(
                f"reviewed record-set component identity mismatch: {relative}"
            )
        if entry.get("review_status") != review_status:
            raise ValueError(f"reviewed record-set review status mismatch: {relative}")
        if v2_bindings is None:
            bindings = entry.get("bindings")
            if not isinstance(bindings, list):
                raise ValueError(f"reviewed record-set bindings missing: {relative}")
            if entry.get("bindings_sha256") != sha256_bytes(canonical_bytes(bindings)):
                raise ValueError(
                    f"reviewed record-set binding digest mismatch: {relative}"
                )
            bound = [
                item.get("record_pointer")
                for item in bindings
                if isinstance(item, Mapping)
            ]
            leafs = leaf_pointers(record)
            if (
                len(bound) != len(bindings)
                or len(bound) != len(set(bound))
                or sorted(bound) != sorted(leafs)
            ):
                raise ValueError(
                    f"reviewed record-set bindings are incomplete: {relative}"
                )
        elif relative not in v2_bindings:
            raise ValueError(f"normalized record bindings are missing: {relative}")
        structural_errors = registry.reviewed_record_schema_errors(
            schema_validator, record
        )
        uri_errors = registry.validate_reviewed_uri_safety(record)
        if structural_errors or uri_errors:
            raise ValueError(
                f"reviewed record-set record is invalid: {relative}: "
                + "; ".join([*structural_errors, *uri_errors][:32])
            )
        record_id = str(record.get("record_id") or "")
        component_key = str(component_id or "")
        if record_id in seen_record_ids or component_key in seen_component_ids:
            raise ValueError(
                "reviewed record-set record/component identities are not unique"
            )
        seen_record_ids.add(record_id)
        seen_component_ids.add(component_key)
        if review_status == "accepted":
            accepted_records.append((relative, record))
    counts = record_set.get("counts")
    gaps = record_set.get("gaps")
    if not isinstance(counts, Mapping) or not isinstance(gaps, list):
        raise ValueError("reviewed record-set counts/gaps are invalid")
    if (
        counts.get("records") != len(denominator_records)
        or counts.get("accepted_records") != len(accepted_records)
        or counts.get("blocking_gaps")
        != sum(bool(item.get("blocking")) for item in gaps if isinstance(item, Mapping))
    ):
        raise ValueError("reviewed record-set exact counts are invalid")
    if accepted_records:
        registry.preflight_reviewed_records(accepted_records, schema_validator)
    # A reviewed, accepted denominator may legitimately carry proposed records
    # and unrelated blocking set-level gaps (partial explicit coverage).
    # Per-record authorization is enforced target by target, never by revoking
    # the whole denominator, so no all-or-nothing acceptance is asserted here.


def github_repository(uri: Any) -> str | None:
    if not isinstance(uri, str):
        return None
    parsed = urlparse(uri)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or any(
        re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None for part in parts
    ):
        return None
    if parsed.params or parsed.query or parsed.fragment:
        return None
    if parsed.path != "/" + "/".join(parts):
        return None
    return "/".join(parts)


def source_channel(
    record: Mapping[str, Any],
) -> tuple[Mapping[str, Any] | None, list[dict[str, Any]]]:
    channels = record.get("channels")
    if not isinstance(channels, list):
        return None, [gap("source_channels_invalid", "channels must be an array")]
    sources = [
        item
        for item in channels
        if isinstance(item, dict) and item.get("channel_type") == "source"
    ]
    accepted = [
        item
        for item in sources
        if item.get("review_state") == "accepted"
        and item.get("availability_state") == "available"
    ]
    if len(accepted) == 1:
        return accepted[0], []
    if not accepted:
        return None, [
            gap(
                "accepted_source_channel_missing",
                "no accepted available source channel exists",
            )
        ]
    return None, [
        gap(
            "accepted_source_channel_ambiguous",
            "multiple accepted available source channels exist",
        )
    ]


def expected_tag(profile: Mapping[str, str], resolved_version: Any) -> str | None:
    if not isinstance(resolved_version, str):
        return None
    tag_format = profile["tag_format"]
    if tag_format == "runtime":
        return resolved_version if RUNTIME_TAG_RE.fullmatch(resolved_version) else None
    if (
        not tag_format.endswith("-chart")
        or CHART_VERSION_RE.fullmatch(resolved_version) is None
    ):
        return None
    return tag_format.removesuffix("-chart") + "-" + resolved_version


def target_scoped_record_gaps(
    record: Mapping[str, Any], subject_ids: set[str]
) -> list[dict[str, Any]]:
    """Project only blocking gaps that name this exact target denominator.

    Record sets may retain unrelated runtime, OCI, dependency, or absent-product
    gaps without revoking a chart-source target.  A blocking record gap that
    names the selected component, version, source channel, selected-version
    dependency, or bound snapshot is different: it is part of that target's own
    authorization state and must fail closed.
    """

    projected: list[dict[str, Any]] = []
    record_gaps = record.get("gaps")
    if not isinstance(record_gaps, list):
        return projected
    for item in record_gaps:
        if (
            not isinstance(item, Mapping)
            or item.get("blocking") is not True
            or item.get("subject_id") not in subject_ids
        ):
            continue
        projected.append(
            {
                "code": "target_scoped_record_gap",
                "message": "the reviewed record retains a blocking gap for this target",
                "blocking": True,
                "source_gap_id": item.get("gap_id"),
                "source_subject_kind": item.get("subject_kind"),
                "source_subject_id": item.get("subject_id"),
                "source_review_state": item.get("review_state"),
            }
        )
    return projected


def plan_target(
    repo_root: Path,
    record_path: Path,
    record_sha256: str,
    record: Mapping[str, Any],
    version: Mapping[str, Any] | None,
) -> dict[str, Any]:
    component = (
        record.get("component") if isinstance(record.get("component"), dict) else {}
    )
    review = record.get("review") if isinstance(record.get("review"), dict) else {}
    component_id = component.get("component_id")
    version_id = version.get("component_version_id") if version else None
    gaps: list[dict[str, Any]] = []

    if record.get("schema_version") != RECORD_SCHEMA_VERSION:
        gaps.append(
            gap("record_schema_unsupported", "component record schema must be 1.0.0")
        )
    if record.get("record_kind") != "reviewed_component":
        gaps.append(
            gap("record_kind_unsupported", "record_kind must be reviewed_component")
        )
    if review.get("status") != "accepted":
        gaps.append(
            gap("record_review_not_accepted", "component record review is not accepted")
        )
    if not isinstance(component_id, str) or not component_id:
        gaps.append(gap("component_id_missing", "component_id is required"))
    if component.get("disposition") != "selected":
        gaps.append(
            gap(
                "component_disposition_not_selected",
                "component disposition must be selected before acquisition planning",
            )
        )

    resolved_version = version.get("resolved_version") if version else None
    version_component_id = version.get("component_id") if version else None
    source_ref = version.get("source_ref") if version else None
    resolution_state = version.get("resolution_state") if version else None
    build_metadata = version.get("build_metadata") if version else None
    if (
        resolution_state != "resolved"
        or not isinstance(resolved_version, str)
        or not resolved_version
    ):
        gaps.append(
            gap("version_unresolved", "component version is not exactly resolved")
        )
    if version is not None and version_component_id != component_id:
        gaps.append(
            gap(
                "version_component_mismatch",
                "component version does not belong to the reviewed component",
            )
        )

    # Identity is the tuple {repository, requested_tag, expected_commit,
    # content_roots[]}.  The corrective records bind source_ref to an exact
    # 40-hex commit; the tag/subtree/tree URI live in
    # build_metadata.source_resolution.chart and every bound leaf must agree
    # with that commit before a target can be authorized.
    expected_commit = (
        source_ref
        if isinstance(source_ref, str) and COMMIT_RE.fullmatch(source_ref)
        else None
    )
    if expected_commit is None:
        gaps.append(
            gap(
                "exact_commit_missing",
                "resolved version has no exact 40-hex commit source_ref",
            )
        )

    repository = github_repository(component.get("source_repo"))
    if repository is None:
        gaps.append(
            gap(
                "github_source_repo_invalid",
                "source_repo is not a canonical GitHub repository URI",
            )
        )

    profile = ARGO_SOURCE_PROFILES.get(str(component_id))
    requested_tag: str | None = None
    content_roots: list[str] = []
    chart: Mapping[str, Any] | None = None
    source_resolution_review_state: Any = None
    chart_publisher: Any = None
    license_spdx: Any = None
    license_uri: Any = None
    if profile is None:
        gaps.append(
            gap(
                "fetch_profile_unsupported",
                "no bounded exact-content fetch profile exists for this component",
            )
        )
    elif profile["component_kind"] != "chart":
        # Only the accepted Argo Helm-chart lanes have a reviewed exact-source
        # shape (source_resolution.chart).  Standalone controller source records
        # are not yet specified, so controller acquisition stays fail-closed.
        gaps.append(
            gap(
                "controller_acquisition_deferred",
                "controller exact-source acquisition awaits a reviewed record shape",
            )
        )
    elif repository != profile["repository"]:
        gaps.append(
            gap(
                "fetch_profile_repository_mismatch",
                "fetch profile and reviewed repository differ",
            )
        )
    else:
        if component.get("kind") != profile["component_kind"]:
            gaps.append(
                gap(
                    "fetch_profile_kind_mismatch",
                    "fetch profile and reviewed component kind differ",
                )
            )
        resolution = (
            build_metadata.get("source_resolution")
            if isinstance(build_metadata, Mapping)
            else None
        )
        source_resolution_review_state = (
            resolution.get("review_state") if isinstance(resolution, Mapping) else None
        )
        if source_resolution_review_state != "accepted":
            gaps.append(
                gap(
                    "source_resolution_not_accepted",
                    "version source_resolution review_state must be accepted",
                )
            )
        candidate_chart = (
            resolution.get("chart") if isinstance(resolution, Mapping) else None
        )
        if not isinstance(candidate_chart, Mapping):
            gaps.append(
                gap(
                    "chart_source_resolution_missing",
                    "chart version has no source_resolution.chart evidence",
                )
            )
        else:
            chart = candidate_chart
            chart_tag = chart.get("tag")
            chart_commit = chart.get("commit")
            chart_subtree = chart.get("subtree")
            chart_subtree_uri = chart.get("subtree_uri")
            chart_publisher = chart.get("publisher")
            chart_license = chart.get("license")
            license_spdx = (
                chart_license.get("spdx")
                if isinstance(chart_license, Mapping)
                else None
            )
            license_uri = (
                chart_license.get("uri") if isinstance(chart_license, Mapping) else None
            )
            profile_tag = expected_tag(profile, resolved_version)
            if (
                not isinstance(chart_tag, str)
                or profile_tag is None
                or chart_tag != profile_tag
            ):
                gaps.append(
                    gap(
                        "resolved_version_tag_mismatch",
                        "chart tag differs from its profile-bound exact source tag",
                    )
                )
            else:
                requested_tag = chart_tag
            if (
                not isinstance(chart_commit, str)
                or COMMIT_RE.fullmatch(chart_commit) is None
                or (expected_commit is not None and chart_commit != expected_commit)
            ):
                gaps.append(
                    gap(
                        "chart_commit_mismatch",
                        "chart commit differs from the exact resolved commit",
                    )
                )
            if (
                not isinstance(chart_subtree, str)
                or not chart_subtree
                or chart_subtree != profile["source_subtree"]
            ):
                gaps.append(
                    gap(
                        "chart_subtree_mismatch",
                        "chart subtree differs from the bounded fetch profile subtree",
                    )
                )
            else:
                content_roots = [chart_subtree]
            expected_subtree_uri = None
            if (
                repository is not None
                and isinstance(chart_commit, str)
                and isinstance(chart_subtree, str)
                and chart_subtree
            ):
                expected_subtree_uri = f"https://github.com/{repository}/tree/{chart_commit}/{chart_subtree}"
            if (
                expected_subtree_uri is None
                or chart_subtree_uri != expected_subtree_uri
            ):
                gaps.append(
                    gap(
                        "chart_subtree_uri_mismatch",
                        "chart subtree_uri is not the exact commit/subtree tree URI",
                    )
                )
            expected_license_uri = None
            if repository is not None and isinstance(chart_commit, str):
                expected_license_uri = (
                    f"https://github.com/{repository}/blob/{chart_commit}/LICENSE"
                )
            if (
                chart_publisher != CHART_SOURCE_PUBLISHER
                or not isinstance(chart_license, Mapping)
                or set(chart_license) != {"spdx", "uri"}
                or license_spdx != CHART_SOURCE_LICENSE_SPDX
                or license_uri != expected_license_uri
            ):
                gaps.append(
                    gap(
                        "chart_license_profile_unsupported",
                        "chart publisher/license must equal the reviewed exact-commit profile",
                    )
                )
        expected_version_id = profile["version_id_prefix"] + str(resolved_version)
        if version_id != expected_version_id:
            gaps.append(
                gap(
                    "component_version_identity_mismatch",
                    "component version identity differs from repository and version",
                )
            )

    channel, channel_gaps = source_channel(record)
    gaps.extend(channel_gaps)
    channel_id = channel.get("channel_id") if channel else None
    if channel is not None:
        if channel.get("component_id") != component_id:
            gaps.append(
                gap(
                    "channel_component_mismatch",
                    "source channel does not belong to the reviewed component",
                )
            )
        if channel.get("version_strategy") != "exact-commit":
            gaps.append(
                gap(
                    "source_channel_not_exact",
                    "source channel is not exact-commit bound",
                )
            )
        if channel.get("access") != "public":
            gaps.append(
                gap(
                    "source_channel_not_public",
                    "source channel access must be explicitly public",
                )
            )
        refresh = channel.get("refresh_policy")
        if refresh != CHART_SOURCE_REFRESH_POLICY:
            gaps.append(
                gap(
                    "source_channel_not_immutable",
                    "source channel refresh policy must equal the reviewed immutable-locator rule",
                )
            )
        if channel.get("discovery_method") not in {"manual", "reviewed"} or channel.get(
            "confidence"
        ) not in {"high", "reviewed"}:
            gaps.append(
                gap(
                    "source_channel_not_reviewed_exact",
                    "source channel must be reviewed evidence, not inferred discovery",
                )
            )
        rights = channel.get("rights")
        if (
            rights != CHART_SOURCE_RIGHTS
            or channel.get("publisher") != CHART_SOURCE_PUBLISHER
        ):
            gaps.append(
                gap(
                    "rights_profile_unsupported",
                    "source publisher/rights must equal the reviewed acquisition profile",
                )
            )
        # Bind the channel to the same exact commit/subtree tree URI as the
        # chart resolution, so the channel and resolution cannot name different
        # leaves of the repository.
        if chart is not None:
            channel_uri = channel.get("canonical_uri")
            if not isinstance(channel_uri, str) or channel_uri != chart.get(
                "subtree_uri"
            ):
                gaps.append(
                    gap(
                        "fetch_profile_channel_mismatch",
                        "bounded fetch profile requires its exact commit and subtree tree URI",
                    )
                )

    target_subject_ids = {
        value
        for value in (component_id, version_id, channel_id)
        if isinstance(value, str) and value
    }
    dependencies = record.get("dependencies")
    if isinstance(dependencies, list):
        target_subject_ids.update(
            str(item["edge_id"])
            for item in dependencies
            if isinstance(item, Mapping)
            and item.get("from_component_version_id") == version_id
            and isinstance(item.get("edge_id"), str)
            and item.get("edge_id")
        )
    snapshots = record.get("snapshots")
    if isinstance(snapshots, list):
        target_subject_ids.update(
            str(item["snapshot_id"])
            for item in snapshots
            if isinstance(item, Mapping)
            and (
                item.get("component_version_id") == version_id
                or item.get("channel_id") == channel_id
            )
            and isinstance(item.get("snapshot_id"), str)
            and item.get("snapshot_id")
        )
    gaps.extend(target_scoped_record_gaps(record, target_subject_ids))

    stable_identity = {
        "repository": repository,
        "requested_tag": requested_tag,
        "expected_commit": expected_commit,
        "content_roots": content_roots,
    }
    target_id = (
        "source-acquisition-target:"
        + hashlib.sha256(canonical_bytes(stable_identity)).hexdigest()
    )
    return {
        "target_id": target_id,
        "state": "ready" if not gaps else "blocked",
        "record_path": repository_relative(repo_root, record_path),
        "record_sha256": record_sha256,
        "record_id": record.get("record_id"),
        "component_id": component_id,
        "component_version_id": version_id,
        "component_kind": component.get("kind"),
        "lifecycle": component.get("lifecycle"),
        "repository": repository,
        "resolved_version": resolved_version,
        "requested_tag": requested_tag,
        "expected_commit": expected_commit,
        "content_roots": content_roots,
        "target_identity": stable_identity,
        "source_resolution_review_state": source_resolution_review_state,
        "source_authorization": {
            "channel": {
                "publisher": channel.get("publisher") if channel else None,
                "rights": channel.get("rights") if channel else None,
                "refresh_policy": channel.get("refresh_policy") if channel else None,
            },
            "chart": {
                "publisher": chart_publisher,
                "license": {
                    "spdx": license_spdx,
                    "uri": license_uri,
                },
            },
        },
        "channel_id": channel_id,
        "channel_type": channel.get("channel_type") if channel else None,
        "fetch_adapter": profile.get("fetch_adapter") if profile else None,
        "fetch_argument": profile.get("fetch_argument") if profile else None,
        "fetch_component": profile.get("fetch_component") if profile else None,
        "cache_key": profile.get("cache_key") if profile else None,
        "content_profile": profile.get("content_profile") if profile else None,
        "source_subtree": profile.get("source_subtree") if profile else None,
        "gaps": gaps,
    }


def open_record_denominator(
    records_dir: Path,
    lifecycles: set[str],
    component_ids: set[str],
) -> tuple[
    int,
    os.stat_result,
    list[tuple[Path, str, Mapping[str, Any], os.stat_result]],
    list[tuple[Path, str, Mapping[str, Any], os.stat_result]],
    set[str],
]:
    directory_fd, directory_before = open_directory_no_follow(
        records_dir, "record denominator"
    )
    try:
        names: list[str] = []
        directory_entries = 0
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                directory_entries += 1
                if directory_entries > MAX_RECORD_DIRECTORY_ENTRIES:
                    raise ValueError(
                        "record directory exceeds the configured entry bound"
                    )
                if not entry.name.endswith(".json"):
                    raise ValueError(
                        "record denominator contains a non-record directory entry: "
                        f"{entry.name!r}"
                    )
                names.append(entry.name)
                if len(names) > MAX_RECORD_FILES:
                    raise ValueError(
                        "record denominator exceeds the configured file bound"
                    )
        selected: list[tuple[Path, str, Mapping[str, Any], os.stat_result]] = []
        denominator: list[tuple[Path, str, Mapping[str, Any], os.stat_result]] = []
        seen_component_ids: set[str] = set()
        record_bytes = 0
        for name in sorted(names):
            raw, identity = read_regular_at(
                directory_fd,
                name,
                max_bytes=MAX_JSON_BYTES,
                label=f"reviewed record {name}",
            )
            record_bytes += len(raw)
            if record_bytes > MAX_RECORD_BYTES:
                raise ValueError("record denominator exceeds the configured byte bound")
            record = strict_json_loads(raw)
            record_path = records_dir / name
            record_sha256 = sha256_bytes(raw)
            if not isinstance(record, dict):
                raise ValueError(f"record is not an object: {record_path}")
            denominator.append((record_path, record_sha256, record, identity))
            component = (
                record.get("component")
                if isinstance(record.get("component"), dict)
                else {}
            )
            if component.get("lifecycle") not in lifecycles:
                continue
            review = (
                record.get("review") if isinstance(record.get("review"), dict) else {}
            )
            if review.get("status") != "accepted":
                continue
            component_id = component.get("component_id")
            if component_ids and component_id not in component_ids:
                continue
            versions = record.get("versions")
            if isinstance(versions, list) and len(versions) > MAX_VERSIONS_PER_RECORD:
                raise ValueError(
                    "component record exceeds the configured version-entry bound: "
                    f"{record_path}"
                )
            if isinstance(component_id, str):
                seen_component_ids.add(component_id)
            selected.append((record_path, record_sha256, record, identity))
        return (
            directory_fd,
            directory_before,
            denominator,
            selected,
            seen_component_ids,
        )
    except Exception:
        os.close(directory_fd)
        raise


def verify_record_denominator(
    records_dir: Path,
    directory_fd: int,
    directory_before: os.stat_result,
    denominator_records: Sequence[tuple[Path, str, Mapping[str, Any], os.stat_result]],
) -> None:
    if stat_identity(os.fstat(directory_fd)) != stat_identity(directory_before):
        raise ValueError("record denominator changed during plan generation")
    reopened, path_info = open_directory_no_follow(records_dir, "record denominator")
    try:
        if stat_identity(path_info) != stat_identity(directory_before):
            raise ValueError(
                "record denominator path was replaced during plan generation"
            )
    finally:
        os.close(reopened)
    for record_path, digest, _record, identity in denominator_records:
        raw, current = read_regular_at(
            directory_fd,
            record_path.name,
            max_bytes=MAX_JSON_BYTES,
            label=f"reviewed record {record_path.name}",
        )
        if (
            stat_identity(current) != stat_identity(identity)
            or sha256_bytes(raw) != digest
        ):
            raise ValueError(
                f"reviewed record changed during plan generation: {record_path}"
            )


def build_plan(
    repo_root: Path,
    records_dir: Path,
    lifecycles: set[str],
    component_ids: set[str],
    record_set_path: Path | None = None,
) -> dict[str, Any]:
    if len(component_ids) > MAX_COMPONENT_FILTERS:
        raise ValueError(
            f"component filter exceeds the {MAX_COMPONENT_FILTERS} item bound"
        )
    generator_path = normalized_absolute(Path(__file__), "acquisition planner source")
    generator_raw, _ = read_regular_capture(
        generator_path,
        max_bytes=MAX_CONTRACT_FILE_BYTES,
        label="acquisition planner source",
    )
    generator_sha256 = sha256_bytes(generator_raw)
    record_set_path = record_set_path or repo_root / DEFAULT_RECORD_SET_SOURCE
    (
        directory_fd,
        directory_before,
        denominator_records,
        selected_records,
        seen_component_ids,
    ) = open_record_denominator(records_dir, lifecycles, component_ids)
    try:
        (
            registry,
            schema_validator,
            record_set_validator,
            contract_binding,
            expected_contract,
        ) = load_reviewed_contract()
        record_set, record_set_sha256, record_set_identity = read_record_set(
            record_set_path, record_set_validator
        )
        validate_record_set_denominator(
            repo_root,
            records_dir,
            record_set,
            denominator_records,
            registry,
            schema_validator,
        )
        denominator_accepted = record_set_denominator_accepted(record_set)
        registry.preflight_reviewed_records(
            [
                (path.as_posix(), record)
                for path, _digest, record, _info in selected_records
            ],
            schema_validator,
        )

        targets: list[dict[str, Any]] = []
        for record_path, record_sha256, record, _identity in selected_records:
            versions = record.get("versions")
            if not isinstance(versions, list) or not versions:
                if len(targets) >= MAX_TARGETS:
                    raise ValueError(
                        "acquisition plan exceeds the configured target bound"
                    )
                targets.append(
                    plan_target(repo_root, record_path, record_sha256, record, None)
                )
                continue
            for version in versions:
                if len(targets) >= MAX_TARGETS:
                    raise ValueError(
                        "acquisition plan exceeds the configured target bound"
                    )
                targets.append(
                    plan_target(
                        repo_root,
                        record_path,
                        record_sha256,
                        record,
                        version if isinstance(version, dict) else None,
                    )
                )
        if not denominator_accepted:
            for target in targets:
                target["gaps"].append(
                    gap(
                        "reviewed_record_set_not_accepted",
                        "the exact reviewed record-set manifest is not independently accepted",
                    )
                )
                target["state"] = "blocked"
        targets.sort(
            key=lambda item: (
                str(item.get("component_id")),
                str(item.get("component_version_id")),
            )
        )
        plan_gaps: list[dict[str, Any]] = []
        if not denominator_accepted:
            plan_gaps.append(
                gap(
                    "reviewed_record_set_not_accepted",
                    "the exact reviewed record-set manifest is not independently accepted",
                )
            )
        for missing in sorted(component_ids - seen_component_ids):
            plan_gaps.append(
                gap(
                    "requested_component_missing",
                    "requested component is absent from the selected record "
                    f"denominator: {missing}",
                )
            )
        if not targets and not component_ids:
            plan_gaps.append(
                gap(
                    "record_denominator_empty",
                    "the selected deployed/planned record denominator is empty",
                )
            )
        target_ids = [item["target_id"] for item in targets]
        if len(target_ids) != len(set(target_ids)):
            plan_gaps.append(
                gap(
                    "target_identity_duplicate",
                    "multiple selected records resolve to the same acquisition "
                    "target identity",
                )
            )
        verify_record_denominator(
            records_dir, directory_fd, directory_before, denominator_records
        )
        recheck_contract_files(expected_contract)
        core = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "record_schema_version": RECORD_SCHEMA_VERSION,
            "plan_kind": PLAN_KIND,
            "authority_state": "non_authoritative",
            "review_state": "not_applicable",
            "compile_eligible": False,
            "promote_eligible": False,
            "authority_boundary": {
                "source_admission": False,
                "retrieval_release": False,
                "signing": False,
                "pointer_mutation": False,
                "git_mutation": False,
                "production_mutation": False,
            },
            "generator": {
                "name": GENERATOR,
                "version": GENERATOR_VERSION,
                "source": GENERATOR_SOURCE,
                "source_sha256": generator_sha256,
                **contract_binding,
            },
            "bounds": {
                "component_filters": MAX_COMPONENT_FILTERS,
                "record_directory_entries": MAX_RECORD_DIRECTORY_ENTRIES,
                "record_files": MAX_RECORD_FILES,
                "record_bytes": MAX_RECORD_BYTES,
                "versions_per_record": MAX_VERSIONS_PER_RECORD,
                "targets": MAX_TARGETS,
                "json_bytes": MAX_JSON_BYTES,
                "json_depth": MAX_JSON_DEPTH,
                "json_nodes": MAX_JSON_NODES,
                "canonical_plan_bytes": MAX_PLAN_CANONICAL_BYTES,
                "serialized_output_bytes": MAX_PLAN_OUTPUT_BYTES,
            },
            "scope": {
                "lifecycles": sorted(lifecycles),
                "component_ids": sorted(component_ids),
                "records_path": repository_relative(repo_root, records_dir),
                "record_set_path": repository_relative(repo_root, record_set_path),
                "record_set_id": record_set.get("record_set_id"),
                "record_set_sha256": record_set_sha256,
                "record_set_review_status": record_set.get("review", {}).get("status"),
            },
            "gaps": plan_gaps,
            "targets": targets,
            "counts": {
                "total": len(targets),
                "ready": sum(item["state"] == "ready" for item in targets),
                "blocked": sum(item["state"] == "blocked" for item in targets),
                "blocking_gaps": sum(
                    issue["blocking"] for item in targets for issue in item["gaps"]
                )
                + sum(issue["blocking"] for issue in plan_gaps),
            },
        }
        payload = canonical_bytes(core)
        if len(payload) > MAX_PLAN_CANONICAL_BYTES:
            raise ValueError("acquisition plan exceeds the configured serialized bound")
        payload_sha256 = sha256_bytes(payload)
        plan = {
            "plan_id": "source-acquisition-plan:"
            + payload_sha256.removeprefix("sha256:"),
            "plan_payload_sha256": payload_sha256,
            **core,
        }
        if len(canonical_bytes(plan)) > MAX_PLAN_OUTPUT_BYTES:
            raise ValueError("acquisition plan output exceeds the configured bound")
        recheck_contract_files(expected_contract)
        current_record_set_raw, current_record_set_identity = read_regular_capture(
            record_set_path,
            max_bytes=MAX_JSON_BYTES,
            label="reviewed record-set manifest",
        )
        if (
            stat_identity(current_record_set_identity)
            != stat_identity(record_set_identity)
            or sha256_bytes(current_record_set_raw) != record_set_sha256
        ):
            raise ValueError(
                "reviewed record-set manifest changed during plan generation"
            )
        if file_sha256(generator_path) != generator_sha256:
            raise ValueError(
                "acquisition planner source changed during plan generation"
            )
        verify_record_denominator(
            records_dir, directory_fd, directory_before, denominator_records
        )
        return plan
    finally:
        os.close(directory_fd)


def validate_plan_v3(
    resolver: Any,
    validator: Any,
    value: Mapping[str, Any],
) -> None:
    resolver.validate_schema(validator, value, "source acquisition plan v3")
    core = {
        key: item
        for key, item in value.items()
        if key not in {"plan_id", "plan_payload_sha256"}
    }
    payload = sha256_bytes(canonical_bytes(core))
    if value.get("plan_payload_sha256") != payload:
        raise ValueError("source acquisition plan v3 payload digest is invalid")
    if value.get("plan_id") != "source-acquisition-plan:" + payload:
        raise ValueError("source acquisition plan v3 identity is invalid")
    selection = value.get("selection")
    targets = value.get("targets")
    counts = value.get("counts")
    artifact_bundle = value.get("artifact_bundle")
    execution_boundary = value.get("execution_boundary")
    if (
        not isinstance(selection, Mapping)
        or not isinstance(targets, list)
        or not isinstance(counts, Mapping)
    ):
        raise ValueError("source acquisition plan v3 semantic projection is invalid")
    expected_execution_boundary = {
        "execution_authorized": False,
        "network_access": False,
        "cache_mutation": False,
        "inventory_emission": False,
    }
    if execution_boundary != expected_execution_boundary:
        raise ValueError("source acquisition plan v3 execution boundary is invalid")
    if not isinstance(artifact_bundle, Mapping) or not isinstance(
        artifact_bundle.get("bundle_id"), str
    ):
        raise ValueError("source acquisition plan v3 artifact bundle is invalid")
    selected_components = selection.get("component_ids")
    if not isinstance(selected_components, list) or not all(
        isinstance(item, str) for item in selected_components
    ):
        raise ValueError("source acquisition plan v3 selection is invalid")
    if selected_components != sorted(selected_components):
        raise ValueError("source acquisition plan v3 selection is not canonical")
    target_components: list[str] = []
    target_ids: set[str] = set()
    for target in targets:
        if not isinstance(target, Mapping):
            raise ValueError("source acquisition plan v3 target is invalid")
        if LEGACY_FETCH_FIELDS.intersection(target):
            raise ValueError("source acquisition plan v3 contains a legacy adapter")
        component_id = target.get("component_id")
        if not isinstance(component_id, str) or component_id not in V3_COMPONENT_ROOTS:
            raise ValueError("source acquisition plan v3 target component is invalid")
        target_components.append(component_id)
        expected_root = V3_COMPONENT_ROOTS[component_id]
        if target.get("content_roots") != [expected_root]:
            raise ValueError(
                "source acquisition plan v3 target content root differs from component"
            )
        expected_logical = V3_COMPONENT_RECORD_PATHS[component_id]
        if target.get("record_logical_path") != expected_logical:
            raise ValueError(
                "source acquisition plan v3 logical record path differs from component"
            )
        record_artifact = target.get("record_artifact")
        expected_artifact_path = f"accepted-records/{Path(expected_logical).name}"
        if (
            not isinstance(record_artifact, Mapping)
            or record_artifact.get("base") != "bundle"
            or record_artifact.get("path") != expected_artifact_path
            or record_artifact.get("content_sha256") != target.get("record_sha256")
            or target.get("artifact_bundle_id") != artifact_bundle.get("bundle_id")
        ):
            raise ValueError(
                "source acquisition plan v3 typed record artifact is invalid"
            )
        expected_identity = {
            "repository": target.get("repository"),
            "requested_tag": target.get("requested_tag"),
            "expected_commit": target.get("expected_commit"),
            "content_roots": [expected_root],
        }
        if target.get("target_identity") != expected_identity:
            raise ValueError(
                "source acquisition plan v3 target identity projection is invalid"
            )
        expected_target_id = (
            "source-acquisition-target:"
            + hashlib.sha256(canonical_bytes(expected_identity)).hexdigest()
        )
        if target.get("target_id") != expected_target_id:
            raise ValueError("source acquisition plan v3 target identity is invalid")
        if expected_target_id in target_ids:
            raise ValueError("source acquisition plan v3 target identity is duplicated")
        target_ids.add(expected_target_id)
    if target_components != sorted(target_components):
        raise ValueError("source acquisition plan v3 targets are not canonical")
    if target_components != selected_components:
        raise ValueError(
            "source acquisition plan v3 selection differs from target components"
        )
    expected_counts = {
        "total": len(targets),
        "ready": len(targets),
        "blocked": 0,
        "blocking_gaps": 0,
    }
    if dict(counts) != expected_counts:
        raise ValueError("source acquisition plan v3 counts differ from targets")


def build_plan_v3(
    repo_root: Path,
    artifact_bundle_path: Path,
    component_ids: Sequence[str],
) -> dict[str, Any]:
    """Build the explicit no-copy plan without authorizing execution.

    Unlike v2, v3 has no implicit denominator selection.  Every requested
    component must name one accepted artifact in the exact successor bundle,
    must be ready under the existing target checks, and must use the single
    fixed Git-object capability contract.  The legacy docs/fetch-docs.sh
    adapters are intentionally absent from the v3 schema and output.
    """

    if not component_ids:
        raise ValueError("plan v3 requires an explicit non-empty component selection")
    if len(component_ids) > MAX_COMPONENT_FILTERS:
        raise ValueError(
            f"component filter exceeds the {MAX_COMPONENT_FILTERS} item bound"
        )
    if any(not isinstance(item, str) or not item for item in component_ids):
        raise ValueError("plan v3 component selection contains an empty identity")
    if len(component_ids) != len(set(component_ids)):
        raise ValueError("plan v3 component selection contains a duplicate identity")

    repo_root = normalized_absolute(repo_root, "repository root")
    artifact_bundle_path = (
        artifact_bundle_path
        if artifact_bundle_path.is_absolute()
        else repo_root / artifact_bundle_path
    )
    artifact_bundle_path = normalized_absolute(
        artifact_bundle_path, "accepted-record artifact bundle"
    )
    artifact_bundle_path.relative_to(repo_root)
    resolver, resolver_sha256, resolver_expected = load_artifact_bundle_resolver(
        repo_root
    )
    resolved = resolver.resolve_bundle(repo_root, artifact_bundle_path)
    record_set = resolved.record_set
    manifest = resolved.manifest
    by_component: dict[str, tuple[str, Mapping[str, Any], bytes]] = {}
    for logical, record in resolved.records_by_logical_path.items():
        component = record.get("component")
        component_id = (
            component.get("component_id") if isinstance(component, Mapping) else None
        )
        if not isinstance(component_id, str) or component_id in by_component:
            raise ValueError("artifact bundle component denominator is ambiguous")
        by_component[component_id] = (
            logical,
            record,
            resolved.record_bytes_by_logical_path[logical],
        )
    manifest_records = manifest.get("records")
    if not isinstance(manifest_records, list):
        raise ValueError("artifact bundle record projection is absent")
    artifact_by_logical: dict[str, Mapping[str, Any]] = {}
    for item in manifest_records:
        if not isinstance(item, Mapping) or not isinstance(
            item.get("logical_path"), str
        ):
            raise ValueError("artifact bundle record projection is invalid")
        artifact_by_logical[str(item["logical_path"])] = item
    if set(artifact_by_logical) != set(resolved.records_by_logical_path):
        raise ValueError("artifact bundle record projection is incomplete")

    selected: list[tuple[str, Mapping[str, Any], bytes]] = []
    for component_id in component_ids:
        item = by_component.get(component_id)
        if item is None:
            raise ValueError(f"requested component is absent: {component_id}")
        record = item[1]
        if record.get("review", {}).get("status") != "accepted":
            raise ValueError(f"requested component is not accepted: {component_id}")
        if component_id not in V3_COMPONENT_ROOTS:
            raise ValueError(
                f"requested component is outside the exact v3 selection: {component_id}"
            )
        selected.append(item)

    (
        registry,
        schema_validator,
        _record_set_validator,
        contract_binding,
        expected_contract,
    ) = load_reviewed_contract()
    registry.preflight_reviewed_records(
        [(logical, record) for logical, record, _raw in selected],
        schema_validator,
    )
    generator_path = normalized_absolute(Path(__file__), "acquisition planner source")
    generator_raw, _ = read_regular_capture(
        generator_path,
        max_bytes=MAX_CONTRACT_FILE_BYTES,
        label="acquisition planner source",
    )
    generator_sha256 = sha256_bytes(generator_raw)
    plan_schema_path = repo_root / PLAN_V3_SCHEMA_SOURCE
    plan_schema_raw, _ = read_regular_capture(
        plan_schema_path,
        max_bytes=MAX_JSON_BYTES,
        label="source acquisition plan v3 schema",
    )
    plan_schema = strict_json_loads(plan_schema_raw)
    if not isinstance(plan_schema, dict):
        raise ValueError("source acquisition plan v3 schema is not an object")
    resolver.Draft202012Validator.check_schema(plan_schema)
    plan_validator = resolver.Draft202012Validator(plan_schema)
    bundle_schema_path = repo_root / ARTIFACT_BUNDLE_SCHEMA_SOURCE
    bundle_schema_raw, _ = read_regular_capture(
        bundle_schema_path,
        max_bytes=MAX_JSON_BYTES,
        label="accepted-record artifact-bundle schema",
    )

    targets: list[dict[str, Any]] = []
    for logical, record, raw in selected:
        versions = record.get("versions")
        if not isinstance(versions, list) or len(versions) != 1:
            raise ValueError(
                f"plan v3 requires exactly one resolved version: {logical}"
            )
        target = plan_target(
            repo_root,
            repo_root / logical,
            sha256_bytes(raw),
            record,
            versions[0] if isinstance(versions[0], dict) else None,
        )
        if target["state"] != "ready":
            codes = sorted(
                str(issue.get("code"))
                for issue in target["gaps"]
                if isinstance(issue, Mapping)
            )
            raise ValueError(
                "requested component is blocked: "
                f"{target.get('component_id')} ({', '.join(codes)})"
            )
        component_id = str(target["component_id"])
        if target["content_roots"] != [V3_COMPONENT_ROOTS[component_id]]:
            raise ValueError(
                f"requested component has an unexpected content root: {component_id}"
            )
        unexpected = (
            set(target) - set(V3_TARGET_FIELDS) - LEGACY_FETCH_FIELDS - {"record_path"}
        )
        if unexpected:
            raise ValueError(
                "legacy target projection gained unreviewed fields: "
                + ", ".join(sorted(unexpected))
            )
        projected = {field: target[field] for field in V3_TARGET_FIELDS}
        artifact_entry = artifact_by_logical[logical]
        artifact = artifact_entry.get("artifact")
        if (
            not isinstance(artifact, Mapping)
            or artifact.get("base") != "bundle"
            or artifact.get("content_sha256") != target["record_sha256"]
        ):
            raise ValueError(
                f"selected record has no exact bundle artifact: {component_id}"
            )
        projected["record_logical_path"] = target["record_path"]
        projected["record_artifact"] = dict(artifact)
        projected["artifact_bundle_id"] = manifest["bundle_id"]
        projected["acquisition_capability"] = "github-git-objects-rest-v1"
        targets.append(projected)

    targets.sort(key=lambda item: str(item["component_id"]))
    target_ids = [str(item["target_id"]) for item in targets]
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("plan v3 target identity is duplicated")
    capability = fixed_github_git_objects_capability()
    core = {
        "$schema": PLAN_V3_SCHEMA_URI,
        "schema_version": PLAN_V3_SCHEMA_VERSION,
        "record_schema_version": RECORD_SCHEMA_VERSION,
        "plan_kind": PLAN_KIND,
        "authority_state": "non_authoritative",
        "review_state": "not_applicable",
        "compile_eligible": False,
        "promote_eligible": False,
        "authority_boundary": {
            "source_admission": False,
            "retrieval_release": False,
            "signing": False,
            "pointer_mutation": False,
            "git_mutation": False,
            "production_mutation": False,
        },
        "execution_boundary": {
            "execution_authorized": False,
            "network_access": False,
            "cache_mutation": False,
            "inventory_emission": False,
        },
        "generator": {
            "name": GENERATOR,
            "version": GENERATOR_V3_VERSION,
            "source": GENERATOR_SOURCE,
            "source_sha256": generator_sha256,
            "artifact_bundle_resolver_source": ARTIFACT_BUNDLE_RESOLVER_SOURCE,
            "artifact_bundle_resolver_sha256": resolver_sha256,
            "artifact_bundle_schema_source": ARTIFACT_BUNDLE_SCHEMA_SOURCE,
            "artifact_bundle_schema_sha256": sha256_bytes(bundle_schema_raw),
            "plan_schema_source": PLAN_V3_SCHEMA_SOURCE,
            "plan_schema_sha256": sha256_bytes(plan_schema_raw),
            **contract_binding,
        },
        "bounds": {
            "component_filters": MAX_COMPONENT_FILTERS,
            "targets": MAX_TARGETS,
            "canonical_plan_bytes": MAX_PLAN_CANONICAL_BYTES,
        },
        "artifact_bundle": {
            "path": repository_relative(repo_root, artifact_bundle_path),
            "bundle_id": manifest["bundle_id"],
            "payload_sha256": manifest["payload_sha256"],
            "successor_record_set_id": record_set["record_set_id"],
            "successor_record_set_payload_sha256": record_set["payload_sha256"],
            "acceptance_outcome_id": resolved.acceptance_outcome["outcome_id"],
            "acceptance_outcome_payload_sha256": resolved.acceptance_outcome[
                "payload_sha256"
            ],
        },
        "selection": {
            "mode": "explicit_exact",
            "component_ids": sorted(component_ids),
        },
        "acquisition_capability": capability,
        "targets": targets,
        "counts": {
            "total": len(targets),
            "ready": len(targets),
            "blocked": 0,
            "blocking_gaps": 0,
        },
    }
    payload_raw = canonical_bytes(core)
    if len(payload_raw) > MAX_PLAN_CANONICAL_BYTES:
        raise ValueError("source acquisition plan v3 exceeds the serialized bound")
    payload_sha256 = sha256_bytes(payload_raw)
    plan = {
        "plan_id": "source-acquisition-plan:" + payload_sha256,
        "plan_payload_sha256": payload_sha256,
        **core,
    }
    validate_plan_v3(resolver, plan_validator, plan)
    recheck_contract_files(expected_contract)
    expected_files = {
        **resolver_expected,
        plan_schema_path: sha256_bytes(plan_schema_raw),
        bundle_schema_path: sha256_bytes(bundle_schema_raw),
        generator_path: generator_sha256,
    }
    recheck_contract_files(expected_files)
    # Re-resolve after construction so path swaps and input replacement cannot
    # race the final plan binding.
    final = resolver.resolve_bundle(repo_root, artifact_bundle_path)
    if final != resolved:
        raise ValueError(
            "accepted-record artifact bundle projection changed during planning"
        )
    validate_plan_v3(resolver, plan_validator, plan)
    return plan


def json_output_bytes(value: Any) -> bytes:
    raw = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(raw) > MAX_PLAN_OUTPUT_BYTES:
        raise ValueError("acquisition plan output exceeds the configured bound")
    return raw


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
        raise ValueError(f"{label} exceeds the configured output bound")
    return raw


def verify_directory_path(path: Path, expected: os.stat_result, label: str) -> None:
    descriptor, current = open_directory_no_follow(path, label)
    try:
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError(f"{label} was replaced during output commit")
    finally:
        os.close(descriptor)


def open_scratch_output_parent(
    repo_root: Path, output: Path
) -> tuple[int, os.stat_result]:
    relative = repository_relative(repo_root, output)
    parts = Path(relative).parts
    if len(parts) < 2 or parts[0] != ".workingdir2":
        raise ValueError("plan output must be below repository .workingdir2/")
    directory_fd, _ = open_directory_no_follow(repo_root, "repository root")
    try:
        for component in parts[:-1]:
            try:
                os.mkdir(component, 0o755, dir_fd=directory_fd)
            except FileExistsError:
                pass
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = child
        return directory_fd, os.fstat(directory_fd)
    except Exception:
        os.close(directory_fd)
        raise


def exact_existing_output(
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
            raise ValueError("existing plan output is not a regular file")
        inode = (before.st_dev, before.st_ino)
        if required_inode is not None and inode != required_inode:
            raise ValueError("plan output path is not the writer-owned inode")
        existing = read_descriptor(
            descriptor,
            max(len(expected), MAX_PLAN_OUTPUT_BYTES),
            "existing plan output",
        )
        after = os.fstat(descriptor)
        if stat_identity(before) != stat_identity(after):
            raise ValueError("existing plan output changed while it was read")
        if existing != expected:
            raise ValueError("refusing to replace conflicting plan output")
        entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat_identity(entry) != stat_identity(after):
            raise ValueError("existing plan output was replaced after it was read")
        if sync:
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            durable_replay = read_descriptor(
                descriptor,
                max(len(expected), MAX_PLAN_OUTPUT_BYTES),
                "existing plan output",
            )
            durable_after = os.fstat(descriptor)
            if (
                stat_identity(durable_after) != stat_identity(after)
                or durable_replay != expected
            ):
                raise ValueError(
                    "existing plan output changed during durability replay"
                )
            durable_entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if stat_identity(durable_entry) != stat_identity(durable_after):
                raise ValueError(
                    "existing plan output was replaced during durability replay"
                )
        reopened = os.open(
            leaf,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            reopened_before = os.fstat(reopened)
            replay = read_descriptor(
                reopened,
                max(len(expected), MAX_PLAN_OUTPUT_BYTES),
                "existing plan output",
            )
            reopened_after = os.fstat(reopened)
            if (
                stat_identity(reopened_before) != stat_identity(after)
                or stat_identity(reopened_after) != stat_identity(after)
                or replay != expected
            ):
                raise ValueError("existing plan output changed during replay check")
            replay_entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if stat_identity(replay_entry) != stat_identity(reopened_after):
                raise ValueError(
                    "existing plan output was replaced during replay check"
                )
        finally:
            os.close(reopened)
        return inode
    finally:
        os.close(descriptor)


def write_plan_output(repo_root: Path, output: Path, value: Any) -> None:
    raw = json_output_bytes(value)
    relative = repository_relative(repo_root, output)
    leaf = Path(relative).name
    if leaf in {"", ".", ".."}:
        raise ValueError("plan output has an unsafe leaf name")
    parent_fd, parent_info = open_scratch_output_parent(repo_root, output)
    descriptor: int | None = None
    try:
        verify_directory_path(output.parent, parent_info, "plan output parent")
        existing_inode = exact_existing_output(parent_fd, leaf, raw, sync=True)
        if existing_inode is not None:
            verify_directory_path(output.parent, parent_info, "plan output parent")
            os.fsync(parent_fd)
            if (
                exact_existing_output(
                    parent_fd, leaf, raw, required_inode=existing_inode
                )
                != existing_inode
            ):
                raise ValueError("existing plan output disappeared during final replay")
            verify_directory_path(output.parent, parent_info, "plan output parent")
            return
        try:
            descriptor = os.open(
                leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o644,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            raced_inode = exact_existing_output(parent_fd, leaf, raw, sync=True)
            if raced_inode is None:
                raise
            verify_directory_path(output.parent, parent_info, "plan output parent")
            os.fsync(parent_fd)
            if (
                exact_existing_output(parent_fd, leaf, raw, required_inode=raced_inode)
                != raced_inode
            ):
                raise ValueError("raced plan output disappeared during final replay")
            verify_directory_path(output.parent, parent_info, "plan output parent")
            return
        created = os.fstat(descriptor)
        created_inode = (created.st_dev, created.st_ino)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while creating plan output")
            view = view[written:]
        os.fsync(descriptor)
        written_info = os.fstat(descriptor)
        if (
            (written_info.st_dev, written_info.st_ino) != created_inode
            or not stat.S_ISREG(written_info.st_mode)
            or written_info.st_size != len(raw)
        ):
            raise ValueError("plan output commit is incomplete")
        output_entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat_identity(output_entry) != stat_identity(written_info):
            raise ValueError("plan output path changed during commit")
        if (
            exact_existing_output(parent_fd, leaf, raw, required_inode=created_inode)
            != created_inode
        ):
            raise ValueError("plan output disappeared during commit verification")
        verify_directory_path(output.parent, parent_info, "plan output parent")
        os.fsync(parent_fd)
        if (
            exact_existing_output(parent_fd, leaf, raw, required_inode=created_inode)
            != created_inode
        ):
            raise ValueError("plan output disappeared during final replay")
        verify_directory_path(output.parent, parent_info, "plan output parent")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def verify_plan_generator(value: Mapping[str, Any]) -> None:
    if value.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise ValueError("acquisition plan schema version is unsupported")
    if value.get("record_schema_version") != RECORD_SCHEMA_VERSION:
        raise ValueError("acquisition plan record schema binding is unsupported")
    generator = value.get("generator")
    expected = generator.get("source_sha256") if isinstance(generator, dict) else None
    if (
        not isinstance(generator, dict)
        or generator.get("name") != GENERATOR
        or generator.get("version") != GENERATOR_VERSION
    ):
        raise ValueError("acquisition plan generator contract is unsupported")
    if (
        not isinstance(expected, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is None
    ):
        raise ValueError("acquisition plan has no exact generator source binding")
    if file_sha256(Path(__file__)) != expected:
        raise ValueError("acquisition planner source differs from the plan binding")


def verify_plan_v3_generator(repo_root: Path, value: Mapping[str, Any]) -> None:
    if value.get("schema_version") != PLAN_V3_SCHEMA_VERSION:
        raise ValueError("source acquisition plan v3 schema version is unsupported")
    generator = value.get("generator")
    if (
        not isinstance(generator, Mapping)
        or generator.get("name") != GENERATOR
        or generator.get("version") != GENERATOR_V3_VERSION
    ):
        raise ValueError("source acquisition plan v3 generator is unsupported")
    bindings = {
        Path(__file__): generator.get("source_sha256"),
        repo_root
        / ARTIFACT_BUNDLE_RESOLVER_SOURCE: generator.get(
            "artifact_bundle_resolver_sha256"
        ),
        repo_root
        / ARTIFACT_BUNDLE_SCHEMA_SOURCE: generator.get("artifact_bundle_schema_sha256"),
        repo_root / PLAN_V3_SCHEMA_SOURCE: generator.get("plan_schema_sha256"),
    }
    for path, expected in bindings.items():
        if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
            raise ValueError("source acquisition plan v3 has an invalid source binding")
        if file_sha256(path) != expected:
            raise ValueError(
                f"source acquisition plan v3 binding differs from disk: {path}"
            )
    resolver, _resolver_sha256, _expected = load_artifact_bundle_resolver(repo_root)
    schema_raw, _ = read_regular_capture(
        repo_root / PLAN_V3_SCHEMA_SOURCE,
        max_bytes=MAX_JSON_BYTES,
        label="source acquisition plan v3 schema",
    )
    schema = strict_json_loads(schema_raw)
    if not isinstance(schema, dict):
        raise ValueError("source acquisition plan v3 schema is not an object")
    validator = resolver.Draft202012Validator(schema)
    validate_plan_v3(resolver, validator, value)
    artifact_bundle = value.get("artifact_bundle")
    selection = value.get("selection")
    if not isinstance(artifact_bundle, Mapping) or not isinstance(selection, Mapping):
        raise ValueError("source acquisition plan v3 has no deterministic projection")
    bundle_path = artifact_bundle.get("path")
    component_ids = selection.get("component_ids")
    if not isinstance(bundle_path, str) or not isinstance(component_ids, list):
        raise ValueError("source acquisition plan v3 has no deterministic projection")
    expected = build_plan_v3(
        repo_root,
        below(repo_root, Path(bundle_path)),
        component_ids,
    )
    if canonical_bytes(value) != canonical_bytes(expected):
        raise ValueError(
            "source acquisition plan v3 differs from deterministic "
            "artifact-bundle projection"
        )


def write_output(
    repo_root: Path, value: Mapping[str, Any], output: Path | None
) -> None:
    verify_plan_generator(value)
    if output is not None:
        write_plan_output(repo_root, output, value)
    verify_plan_generator(value)
    sys.stdout.buffer.write(json_output_bytes(value))


def write_output_v3(
    repo_root: Path, value: Mapping[str, Any], output: Path | None
) -> None:
    verify_plan_v3_generator(repo_root, value)
    if output is not None:
        write_plan_output(repo_root, output, value)
    verify_plan_v3_generator(repo_root, value)
    sys.stdout.buffer.write(json_output_bytes(value))


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "plan-v3"))
    parser.add_argument("--records", type=Path)
    parser.add_argument("--record-set", type=Path)
    parser.add_argument("--lifecycle", action="append", choices=("deployed", "planned"))
    parser.add_argument("--component-id", action="append", default=[])
    parser.add_argument("--artifact-bundle", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def below(repo_root: Path, path: Path) -> Path:
    root = normalized_absolute(repo_root, "repository root")
    candidate = path if path.is_absolute() else root / path
    candidate = normalized_absolute(candidate, "repository path")
    candidate.relative_to(root)
    return candidate


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        repo_root = Path(__file__).resolve().parents[2]
        output = below(repo_root, args.output) if args.output else None
        if args.command == "plan-v3":
            if args.artifact_bundle is None:
                raise ValueError("plan-v3 requires --artifact-bundle")
            if args.lifecycle:
                raise ValueError("plan-v3 does not accept lifecycle projection")
            if args.records is not None:
                raise ValueError("plan-v3 does not accept --records")
            if args.record_set is not None:
                raise ValueError("plan-v3 does not accept --record-set")
            if args.require_complete:
                raise ValueError("plan-v3 does not accept --require-complete")
            plan = build_plan_v3(
                repo_root,
                below(repo_root, args.artifact_bundle),
                args.component_id,
            )
            write_output_v3(repo_root, plan, output)
        else:
            if args.artifact_bundle is not None:
                raise ValueError("legacy plan does not accept --artifact-bundle")
            records_dir = below(
                repo_root, args.records or Path("knowledge/registry/records")
            )
            record_set_path = below(
                repo_root, args.record_set or Path(DEFAULT_RECORD_SET_SOURCE)
            )
            lifecycles = set(args.lifecycle or ["deployed", "planned"])
            plan = build_plan(
                repo_root,
                records_dir,
                lifecycles,
                set(args.component_id),
                record_set_path,
            )
            write_output(repo_root, plan, output)
            if args.require_complete and plan["counts"]["blocking_gaps"]:
                return 1
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"source acquisition planning failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
