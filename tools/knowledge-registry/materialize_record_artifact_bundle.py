#!/usr/bin/env python3
"""Materialize and resolve an accepted record overlay without copying records.

The accepted P1-SRC-02 successor retains the predecessor's logical record paths,
while accepted records physically live in an evidence bundle and unchanged
proposed records remain in the repository.  This module binds that split
explicitly.  Every logical set entry maps to exactly one typed, relative
``repository`` or ``bundle`` locator with an exact byte count and SHA-256.

The materializer and resolver are offline and non-authoritative.  They perform
no network, subprocess, cache, acquisition, inventory, admission, signing,
pointer, Git, or production mutation.  All input traversal is relative to held
directory descriptors with no-follow opens.  The resolver returns captured
bytes and identities to its caller; it never creates a repo-shaped copy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, NamedTuple, Sequence

from jsonschema import Draft202012Validator

SCHEMA_VERSION = "1.0.0"
GENERATOR = "archeion-accepted-record-artifact-bundle"
GENERATOR_VERSION = "1"
GENERATOR_SOURCE = "tools/knowledge-registry/materialize_record_artifact_bundle.py"
BUNDLE_SCHEMA_SOURCE = (
    "knowledge/registry/schemas/accepted-record-artifact-bundle.schema.json"
)
COMPONENT_SCHEMA_SOURCE = "knowledge/registry/schemas/component-record.schema.json"
RECORD_SET_SCHEMA_SOURCE = "knowledge/registry/schemas/reviewed-record-set.schema.json"
OUTCOME_SCHEMA_SOURCE = (
    "knowledge/registry/schemas/source-acceptance-outcome.schema.json"
)
BUNDLE_SCHEMA_URI = (
    "https://github.com/cordanaLLM/knowledge/schemas/registry/"
    "accepted-record-artifact-bundle.schema.json"
)
BUNDLE_KIND = "accepted_record_artifact_bundle"

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 1_000_000
MAX_RECORDS = 4096
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
LOGICAL_RECORD_RE = re.compile(r"^knowledge/registry/records/[A-Za-z0-9._-]+\.json$")
BUNDLE_RECORD_RE = re.compile(r"^accepted-records/[A-Za-z0-9._-]+\.json$")


class CapturedArtifact(NamedTuple):
    raw: bytes
    content_sha256: str
    size: int
    identity: tuple[int, int]


class ResolvedArtifactBundle(NamedTuple):
    manifest: Mapping[str, Any]
    record_set: Mapping[str, Any]
    acceptance_outcome: Mapping[str, Any]
    records_by_logical_path: Mapping[str, Mapping[str, Any]]
    record_bytes_by_logical_path: Mapping[str, bytes]


class DerivedArtifactBundle(NamedTuple):
    manifest: dict[str, Any]
    record_set: Mapping[str, Any]
    acceptance_outcome: Mapping[str, Any]
    records_by_logical_path: dict[str, Mapping[str, Any]]
    record_bytes_by_logical_path: dict[str, bytes]
    record_set_capture: CapturedArtifact
    acceptance_outcome_capture: CapturedArtifact


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def output_bytes(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def strict_json_loads(raw: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number is forbidden: {value}")

    value = json.loads(
        raw,
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


def normalized_absolute(path: Path, label: str) -> Path:
    original = Path(path)
    if any(part in {"", ".", ".."} for part in original.parts[1:]):
        raise ValueError(f"{label} contains an ambiguous path component")
    absolute = Path(os.path.abspath(os.fspath(original)))
    if not absolute.is_absolute() or Path(os.path.normpath(absolute)) != absolute:
        raise ValueError(f"{label} must be an absolute normalized path")
    return absolute


def safe_relative(value: str, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty relative path")
    if "\\" in value or "\x00" in value:
        raise ValueError(f"{label} contains an unsafe separator")
    pure = PurePosixPath(value)
    parts = pure.parts
    if (
        pure.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"{label} must be a normalized relative path")
    if pure.as_posix() != value:
        raise ValueError(f"{label} is not canonical")
    return parts


def stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def open_directory_no_follow(path: Path, label: str) -> tuple[int, os.stat_result]:
    absolute = normalized_absolute(path, label)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"{label} is not a directory")
        return descriptor, info
    except Exception:
        os.close(descriptor)
        raise


def verify_directory_path(path: Path, expected: os.stat_result, label: str) -> None:
    reopened, current = open_directory_no_follow(path, label)
    try:
        if (current.st_dev, current.st_ino, current.st_mode) != (
            expected.st_dev,
            expected.st_ino,
            expected.st_mode,
        ):
            raise ValueError(f"{label} path changed during resolution")
    finally:
        os.close(reopened)


def read_relative_regular(
    root: Path,
    relative: str,
    *,
    maximum: int,
    label: str,
) -> CapturedArtifact:
    parts = safe_relative(relative, label)
    root_fd, root_info = open_directory_no_follow(root, f"{label} base")
    descriptors = [root_fd]
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for component in parts[:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptors[-1])
            descriptors.append(child)
        leaf_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        leaf = os.open(parts[-1], leaf_flags, dir_fd=descriptors[-1])
        try:
            before = os.fstat(leaf)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"{label} is not a regular file")
            if before.st_size < 1 or before.st_size > maximum:
                raise ValueError(f"{label} has an invalid byte size")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(leaf, min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError(f"{label} ended during capture")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(leaf, 1):
                raise ValueError(f"{label} grew during capture")
            after = os.fstat(leaf)
            if stat_identity(after) != stat_identity(before):
                raise ValueError(f"{label} changed during capture")
            path_info = os.stat(
                parts[-1], dir_fd=descriptors[-1], follow_symlinks=False
            )
            if stat_identity(path_info) != stat_identity(before):
                raise ValueError(f"{label} path changed during capture")
            raw = b"".join(chunks)
        finally:
            os.close(leaf)
        verify_directory_path(root, root_info, f"{label} base")
        return CapturedArtifact(
            raw=raw,
            content_sha256=sha256_bytes(raw),
            size=len(raw),
            identity=(before.st_dev, before.st_ino),
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def exact_directory_entries(
    root: Path, relative: str, label: str
) -> tuple[set[str], os.stat_result]:
    parts = safe_relative(relative, label)
    root_fd, root_info = open_directory_no_follow(root, f"{label} base")
    descriptors = [root_fd]
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for component in parts:
            child = os.open(component, flags, dir_fd=descriptors[-1])
            descriptors.append(child)
        before = os.fstat(descriptors[-1])
        with os.scandir(descriptors[-1]) as entries:
            names = {entry.name for entry in entries}
            if len(names) > MAX_RECORDS:
                raise ValueError(f"{label} exceeds the configured entry bound")
        after = os.fstat(descriptors[-1])
        if stat_identity(after) != stat_identity(before):
            raise ValueError(f"{label} changed during enumeration")
        verify_directory_path(root, root_info, f"{label} base")
        return names, before
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def validate_schema(validator: Draft202012Validator, value: Any, label: str) -> None:
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if not errors:
        return
    rendered = []
    for error in errors[:32]:
        pointer = "/" + "/".join(str(part) for part in error.path)
        rendered.append(f"{pointer}: {error.message}")
    raise ValueError(f"{label} schema failure: " + "; ".join(rendered))


def content_address_valid(
    value: Mapping[str, Any], *, id_field: str, id_prefix: str, label: str
) -> None:
    core = {
        key: item
        for key, item in value.items()
        if key not in {id_field, "payload_sha256"}
    }
    payload = sha256_bytes(canonical_bytes(core))
    if value.get("payload_sha256") != payload:
        raise ValueError(f"{label} payload digest is invalid")
    if value.get(id_field) != id_prefix + payload:
        raise ValueError(f"{label} identity is invalid")


def load_contracts(repo_root: Path) -> dict[str, Any]:
    sources = {
        "bundle": BUNDLE_SCHEMA_SOURCE,
        "component": COMPONENT_SCHEMA_SOURCE,
        "record_set": RECORD_SET_SCHEMA_SOURCE,
        "outcome": OUTCOME_SCHEMA_SOURCE,
    }
    raw: dict[str, bytes] = {}
    validators: dict[str, Draft202012Validator] = {}
    for name, source in sources.items():
        artifact = read_relative_regular(
            repo_root,
            source,
            maximum=MAX_JSON_BYTES,
            label=f"{name} schema",
        )
        schema = strict_json_loads(artifact.raw)
        if not isinstance(schema, dict):
            raise ValueError(f"{name} schema is not an object")
        Draft202012Validator.check_schema(schema)
        raw[name] = artifact.raw
        validators[name] = Draft202012Validator(schema)
    return {
        "raw": raw,
        "validators": validators,
        "hashes": {name: sha256_bytes(value) for name, value in raw.items()},
    }


def validate_artifact_binding(
    artifact: Mapping[str, Any], captured: CapturedArtifact, label: str
) -> None:
    if artifact.get("content_sha256") != captured.content_sha256:
        raise ValueError(f"{label} hash mismatch")
    if artifact.get("bytes") != captured.size:
        raise ValueError(f"{label} size mismatch")


def artifact_descriptor(
    *, base: str, path: str, captured: CapturedArtifact
) -> dict[str, Any]:
    return {
        "base": base,
        "path": path,
        "content_sha256": captured.content_sha256,
        "bytes": captured.size,
    }


def capture_json_artifact(
    root: Path, relative: str, *, maximum: int, label: str
) -> tuple[Mapping[str, Any], CapturedArtifact]:
    captured = read_relative_regular(root, relative, maximum=maximum, label=label)
    value = strict_json_loads(captured.raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value, captured


def _validated_inputs(
    repo_root: Path,
    bundle_root: Path,
    contracts: Mapping[str, Any],
) -> tuple[
    Mapping[str, Any],
    CapturedArtifact,
    Mapping[str, Any],
    CapturedArtifact,
]:
    record_set, set_artifact = capture_json_artifact(
        bundle_root,
        "accepted-reviewed-record-set.json",
        maximum=MAX_JSON_BYTES,
        label="accepted successor record set",
    )
    outcome, outcome_artifact = capture_json_artifact(
        bundle_root,
        "source-acceptance-outcome.json",
        maximum=MAX_JSON_BYTES,
        label="source acceptance outcome",
    )
    validators = contracts["validators"]
    validate_schema(validators["record_set"], record_set, "record set")
    validate_schema(validators["outcome"], outcome, "acceptance outcome")
    content_address_valid(
        record_set,
        id_field="record_set_id",
        id_prefix="reviewed-record-set:",
        label="record set",
    )
    content_address_valid(
        outcome,
        id_field="outcome_id",
        id_prefix="source-acceptance-outcome:",
        label="acceptance outcome",
    )
    if record_set.get("review", {}).get("status") != "accepted":
        raise ValueError("successor record set is not accepted")
    if record_set.get("authority_state") != "reviewed":
        raise ValueError("successor record set denominator is not reviewed")
    if (
        record_set.get("compile_eligible") is not False
        or record_set.get("promote_eligible") is not False
    ):
        raise ValueError("successor record set exceeds the authority boundary")
    successor = outcome.get("successor")
    if not isinstance(successor, Mapping):
        raise ValueError("acceptance outcome has no successor")
    if successor.get("record_set_id") != record_set.get(
        "record_set_id"
    ) or successor.get("payload_sha256") != record_set.get("payload_sha256"):
        raise ValueError("acceptance outcome and successor record set differ")
    authority = outcome.get("authority")
    if not isinstance(authority, Mapping) or any(
        authority.get(field) is not False
        for field in (
            "authoritative",
            "admits_retrieval",
            "mutates_pointers",
            "signs_production",
            "compile_eligible",
            "promote_eligible",
        )
    ):
        raise ValueError("acceptance outcome exceeds the authority boundary")
    return record_set, set_artifact, outcome, outcome_artifact


def derive_bundle(
    repo_root: Path,
    bundle_root: Path,
) -> DerivedArtifactBundle:
    repo_root = normalized_absolute(repo_root, "repository root")
    bundle_root = normalized_absolute(bundle_root, "acceptance bundle root")
    contracts = load_contracts(repo_root)
    record_set, set_capture, outcome, outcome_capture = _validated_inputs(
        repo_root, bundle_root, contracts
    )
    entries = record_set.get("records")
    successor = outcome["successor"]
    accepted_entries = successor.get("records")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_RECORDS:
        raise ValueError("successor record set has an invalid record denominator")
    if not isinstance(accepted_entries, list) or not accepted_entries:
        raise ValueError("acceptance outcome contains no accepted record")

    set_by_path: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("successor record set entry is invalid")
        logical = entry.get("path")
        if not isinstance(logical, str) or LOGICAL_RECORD_RE.fullmatch(logical) is None:
            raise ValueError("successor record set contains an unsafe logical path")
        if logical in set_by_path:
            raise ValueError("successor record set contains a duplicate logical path")
        set_by_path[logical] = entry

    outcome_by_path: dict[str, Mapping[str, Any]] = {}
    for entry in accepted_entries:
        if not isinstance(entry, Mapping):
            raise ValueError("acceptance outcome successor entry is invalid")
        logical = entry.get("path")
        if not isinstance(logical, str) or logical in outcome_by_path:
            raise ValueError("acceptance outcome has a duplicate logical path")
        outcome_by_path[logical] = entry

    status_accepted = {
        path
        for path, entry in set_by_path.items()
        if entry.get("review_status") == "accepted"
    }
    if set(outcome_by_path) != status_accepted:
        raise ValueError(
            "acceptance outcome does not cover the exact accepted successor set"
        )
    if any(
        entry.get("review_status") not in {"accepted", "proposed"}
        for entry in set_by_path.values()
    ):
        raise ValueError("successor record set has an unsupported review status")

    expected_bundle_names = {Path(path).name for path in status_accepted}
    actual_bundle_names, accepted_directory_before = exact_directory_entries(
        bundle_root, "accepted-records", "accepted records directory"
    )
    if actual_bundle_names != expected_bundle_names:
        raise ValueError(
            "accepted records directory differs from the exact successor coverage "
            f"(missing={sorted(expected_bundle_names - actual_bundle_names)}, "
            f"extra={sorted(actual_bundle_names - expected_bundle_names)})"
        )

    source_capture = read_relative_regular(
        repo_root,
        GENERATOR_SOURCE,
        maximum=MAX_JSON_BYTES,
        label="artifact bundle generator source",
    )
    records: list[dict[str, Any]] = []
    records_by_path: dict[str, Mapping[str, Any]] = {}
    bytes_by_path: dict[str, bytes] = {}
    physical_identities = {set_capture.identity, outcome_capture.identity}
    record_ids: set[str] = set()
    component_ids: set[str] = set()
    locators: set[tuple[str, str]] = set()

    for logical in sorted(set_by_path):
        entry = set_by_path[logical]
        accepted = logical in status_accepted
        base = "bundle" if accepted else "repository"
        artifact_path = (
            f"accepted-records/{Path(logical).name}" if accepted else logical
        )
        if accepted and BUNDLE_RECORD_RE.fullmatch(artifact_path) is None:
            raise ValueError("accepted record bundle path is unsafe")
        root = bundle_root if accepted else repo_root
        captured = read_relative_regular(
            root,
            artifact_path,
            maximum=MAX_RECORD_BYTES,
            label=f"record artifact {logical}",
        )
        if captured.identity in physical_identities:
            raise ValueError("record artifact aliases or overlaps another artifact")
        physical_identities.add(captured.identity)
        locator = (base, artifact_path)
        if locator in locators:
            raise ValueError("record artifact locator is duplicated or aliased")
        locators.add(locator)
        if captured.content_sha256 != entry.get("content_sha256"):
            raise ValueError(f"record artifact hash mismatch: {logical}")
        if captured.size != entry.get("bytes"):
            raise ValueError(f"record artifact size mismatch: {logical}")
        record = strict_json_loads(captured.raw)
        if not isinstance(record, dict):
            raise ValueError(f"record artifact is not an object: {logical}")
        validate_schema(
            contracts["validators"]["component"], record, f"record {logical}"
        )
        record_id = entry.get("record_id")
        component_id = entry.get("component_id")
        if (
            record.get("record_id") != record_id
            or record.get("component", {}).get("component_id") != component_id
            or record.get("review", {}).get("status") != entry.get("review_status")
        ):
            raise ValueError(
                f"record artifact path swap or identity mismatch: {logical}"
            )
        if record_id in record_ids or component_id in component_ids:
            raise ValueError("record/component identity is duplicated")
        record_ids.add(str(record_id))
        component_ids.add(str(component_id))
        if accepted:
            outcome_entry = outcome_by_path[logical]
            if any(
                outcome_entry.get(field) != entry.get(field)
                for field in ("record_id", "component_id", "content_sha256", "bytes")
            ):
                raise ValueError(f"accepted outcome binding mismatch: {logical}")
        records.append(
            {
                "logical_path": logical,
                "record_id": record_id,
                "component_id": component_id,
                "review_status": entry.get("review_status"),
                "artifact": artifact_descriptor(
                    base=base, path=artifact_path, captured=captured
                ),
            }
        )
        records_by_path[logical] = record
        bytes_by_path[logical] = captured.raw

    final_bundle_names, accepted_directory_after = exact_directory_entries(
        bundle_root, "accepted-records", "accepted records directory final check"
    )
    if final_bundle_names != expected_bundle_names or stat_identity(
        accepted_directory_after
    ) != stat_identity(accepted_directory_before):
        raise ValueError(
            "accepted records directory changed during bundle materialization"
        )

    core = {
        "$schema": BUNDLE_SCHEMA_URI,
        "schema_version": SCHEMA_VERSION,
        "bundle_kind": BUNDLE_KIND,
        "authority": {
            "authoritative": False,
            "admits_sources": False,
            "admits_retrieval": False,
            "mutates_pointers": False,
            "compile_eligible": False,
            "promote_eligible": False,
        },
        "generator": {
            "name": GENERATOR,
            "version": GENERATOR_VERSION,
            "source": GENERATOR_SOURCE,
            "source_sha256": source_capture.content_sha256,
            "bundle_schema_source": BUNDLE_SCHEMA_SOURCE,
            "bundle_schema_sha256": contracts["hashes"]["bundle"],
            "component_schema_sha256": contracts["hashes"]["component"],
            "record_set_schema_sha256": contracts["hashes"]["record_set"],
            "acceptance_outcome_schema_sha256": contracts["hashes"]["outcome"],
        },
        "acceptance_outcome": {
            "outcome_id": outcome["outcome_id"],
            "payload_sha256": outcome["payload_sha256"],
            "artifact": artifact_descriptor(
                base="bundle",
                path="source-acceptance-outcome.json",
                captured=outcome_capture,
            ),
        },
        "successor_record_set": {
            "record_set_id": record_set["record_set_id"],
            "payload_sha256": record_set["payload_sha256"],
            "artifact": artifact_descriptor(
                base="bundle",
                path="accepted-reviewed-record-set.json",
                captured=set_capture,
            ),
        },
        "records": records,
        "counts": {
            "records": len(records),
            "accepted_records": len(status_accepted),
            "retained_records": len(records) - len(status_accepted),
        },
    }
    payload = sha256_bytes(canonical_bytes(core))
    manifest = {
        "bundle_id": "accepted-record-artifact-bundle:" + payload,
        "payload_sha256": payload,
        **core,
    }
    validate_schema(contracts["validators"]["bundle"], manifest, "artifact bundle")
    content_address_valid(
        manifest,
        id_field="bundle_id",
        id_prefix="accepted-record-artifact-bundle:",
        label="artifact bundle",
    )
    return DerivedArtifactBundle(
        manifest=manifest,
        record_set=record_set,
        acceptance_outcome=outcome,
        records_by_logical_path=records_by_path,
        record_bytes_by_logical_path=bytes_by_path,
        record_set_capture=set_capture,
        acceptance_outcome_capture=outcome_capture,
    )


def require_capture_unchanged(
    root: Path,
    relative: str,
    expected: CapturedArtifact,
    *,
    maximum: int,
    label: str,
) -> None:
    current = read_relative_regular(root, relative, maximum=maximum, label=label)
    if current.identity != expected.identity or current.raw != expected.raw:
        raise ValueError(f"{label} changed during bundle resolution")


def resolve_bundle(repo_root: Path, manifest_path: Path) -> ResolvedArtifactBundle:
    repo_root = normalized_absolute(repo_root, "repository root")
    manifest_path = (
        manifest_path if manifest_path.is_absolute() else repo_root / manifest_path
    )
    manifest_path = normalized_absolute(manifest_path, "artifact bundle manifest")
    manifest_path.relative_to(repo_root)
    bundle_root = manifest_path.parent
    relative_manifest = manifest_path.name
    if relative_manifest != "accepted-record-artifact-bundle.json":
        raise ValueError("artifact bundle manifest has a non-canonical filename")
    manifest_value, manifest_capture = capture_json_artifact(
        bundle_root,
        relative_manifest,
        maximum=MAX_JSON_BYTES,
        label="accepted record artifact bundle",
    )
    contracts = load_contracts(repo_root)
    validate_schema(
        contracts["validators"]["bundle"], manifest_value, "artifact bundle"
    )
    content_address_valid(
        manifest_value,
        id_field="bundle_id",
        id_prefix="accepted-record-artifact-bundle:",
        label="artifact bundle",
    )
    derived = derive_bundle(repo_root, bundle_root)
    if canonical_bytes(manifest_value) != canonical_bytes(derived.manifest):
        raise ValueError("artifact bundle differs from deterministic materialization")
    if manifest_capture.content_sha256 != sha256_bytes(output_bytes(derived.manifest)):
        raise ValueError("artifact bundle serialized bytes are not canonical")
    require_capture_unchanged(
        bundle_root,
        relative_manifest,
        manifest_capture,
        maximum=MAX_JSON_BYTES,
        label="accepted record artifact bundle",
    )
    require_capture_unchanged(
        bundle_root,
        "accepted-reviewed-record-set.json",
        derived.record_set_capture,
        maximum=MAX_JSON_BYTES,
        label="accepted successor record set",
    )
    require_capture_unchanged(
        bundle_root,
        "source-acceptance-outcome.json",
        derived.acceptance_outcome_capture,
        maximum=MAX_JSON_BYTES,
        label="source acceptance outcome",
    )
    return ResolvedArtifactBundle(
        manifest=manifest_value,
        record_set=derived.record_set,
        acceptance_outcome=derived.acceptance_outcome,
        records_by_logical_path=derived.records_by_logical_path,
        record_bytes_by_logical_path=derived.record_bytes_by_logical_path,
    )


def below(repo_root: Path, value: Path, label: str) -> Path:
    root = normalized_absolute(repo_root, "repository root")
    candidate = value if value.is_absolute() else root / value
    candidate = normalized_absolute(candidate, label)
    candidate.relative_to(root)
    return candidate


def write_exclusive_scratch(repo_root: Path, output: Path, raw: bytes) -> None:
    output = below(repo_root, output, "artifact bundle output")
    scratch = normalized_absolute(repo_root / ".workingdir2", "scratch root")
    output.relative_to(scratch)
    parent_fd, parent_info = open_directory_no_follow(
        output.parent, "artifact bundle output parent"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            output.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644,
            dir_fd=parent_fd,
        )
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise OSError("short write while creating artifact bundle output")
            written += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or after.st_size != len(raw):
            raise ValueError("artifact bundle output commit is incomplete")
        path_after = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat_identity(path_after) != stat_identity(after):
            raise ValueError("artifact bundle output path changed during commit")
        verify_directory_path(
            output.parent, parent_info, "artifact bundle output parent"
        )
        captured = read_relative_regular(
            output.parent,
            output.name,
            maximum=max(1, len(raw)),
            label="artifact bundle output",
        )
        if captured.identity != created_identity or captured.raw != raw:
            raise ValueError("artifact bundle output changed during commit replay")
        verify_directory_path(
            output.parent, parent_info, "artifact bundle output parent"
        )
        os.fsync(parent_fd)
        captured = read_relative_regular(
            output.parent,
            output.name,
            maximum=max(1, len(raw)),
            label="artifact bundle output",
        )
        if captured.identity != created_identity or captured.raw != raw:
            raise ValueError("artifact bundle output changed during final replay")
        verify_directory_path(
            output.parent, parent_info, "artifact bundle output parent"
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("materialize", "verify"))
    parser.add_argument(
        "--bundle-root",
        type=Path,
        default=Path("knowledge/registry/acceptance/p1-src-02"),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(
            "knowledge/registry/acceptance/p1-src-02/"
            "accepted-record-artifact-bundle.json"
        ),
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        repo_root = Path(__file__).resolve().parents[2]
        if args.command == "verify":
            if args.output is not None:
                raise ValueError("verify does not accept --output")
            resolved = resolve_bundle(repo_root, args.manifest)
            sys.stdout.write(
                json.dumps(
                    {
                        "bundle_id": resolved.manifest["bundle_id"],
                        "records": len(resolved.records_by_logical_path),
                        "accepted_records": resolved.manifest["counts"][
                            "accepted_records"
                        ],
                    },
                    sort_keys=True,
                )
                + "\n"
            )
            return 0
        bundle_root = below(repo_root, args.bundle_root, "acceptance bundle root")
        derived = derive_bundle(repo_root, bundle_root)
        raw = output_bytes(derived.manifest)
        if args.output is not None:
            write_exclusive_scratch(repo_root, args.output, raw)
        sys.stdout.buffer.write(raw)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"artifact bundle operation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
