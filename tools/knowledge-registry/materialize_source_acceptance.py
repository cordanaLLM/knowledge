#!/usr/bin/env python3
"""Materialize an offline P1-SRC-02 review and acceptance decision.

This tool is the review/acceptance control plane the acquisition planner has
always assumed but that never existed.  It consumes an exact *proposed*
reviewed-record set, one independent review manifest per record, and a
hash-bound standing acceptance policy, then deterministically decides which
routine exact-official-source records may become *accepted* successors.

It performs no network, subprocess, Git, signing, admission, retrieval,
release, pointer, Argo, or Kubernetes action.  It never mutates the proposed
record set or its records; every output is a fresh content-addressed successor
written below ``.workingdir2/``.  A record is accepted only when policy,
reviewer independence, source-resolution state, rights, immutable locator,
evidence hashes, target-scoped gaps, freshness, and the complete denominator
all pass.  Every other condition fails closed into a typed exception queue for
later UI/human resolution.  The accepted successor set/records are emitted only
when at least one record passes and the denominator itself is accepted; a
zero-accepted run emits only the exception outcome.

Acceptance never invents a source fact: transitions are restricted to review
disposition, channel availability, and the immutable-locator handling class,
each verified against its exact prior value and the policy's authorized
constants, and the resulting record is re-validated against the component
schema.  Primary-source locators, commits, tags, licences, and evidence hashes
are read and checked, never written.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import stat
import sys
import types
from pathlib import Path
from typing import Any, Mapping, Sequence

BASE_MAX_BYTES = 128 * 1024 * 1024


def pre_exec_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def pre_exec_directory_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode)


def pre_exec_absolute(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute() or Path(os.path.normpath(absolute)) != absolute:
        raise ValueError("base materializer path is not absolute and normalized")
    if any(part in {"", ".", ".."} for part in absolute.parts[1:]):
        raise ValueError("base materializer path has an ambiguous component")
    return absolute


def capture_base_source_before_exec(path: Path, maximum: int) -> bytes:
    """Capture one bounded regular source through a held root-to-leaf chain."""

    if maximum < 1:
        raise ValueError("base materializer byte bound must be positive")
    absolute = pre_exec_absolute(path)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    leaf_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_fds: list[int] = []
    directory_names: list[str] = []
    directory_before: list[os.stat_result] = []
    leaf_fd: int | None = None
    try:
        root_fd = os.open(os.sep, directory_flags)
        directory_fds.append(root_fd)
        root_before = os.fstat(root_fd)
        if not stat.S_ISDIR(root_before.st_mode):
            raise OSError("base materializer root is not a directory")
        directory_before.append(root_before)
        for component in absolute.parent.parts[1:]:
            child_fd = os.open(component, directory_flags, dir_fd=directory_fds[-1])
            child_before = os.fstat(child_fd)
            if not stat.S_ISDIR(child_before.st_mode):
                os.close(child_fd)
                raise OSError("base materializer ancestor is not a directory")
            directory_fds.append(child_fd)
            directory_names.append(component)
            directory_before.append(child_before)

        leaf_fd = os.open(absolute.name, leaf_flags, dir_fd=directory_fds[-1])
        before = os.fstat(leaf_fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("base materializer source is not a regular file")
        if before.st_size < 1:
            raise ValueError("base materializer source is empty")
        if before.st_size > maximum:
            raise ValueError(
                "base materializer source exceeds byte bound "
                f"{maximum} ({before.st_size} bytes)"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(leaf_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("short read while capturing base materializer")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(leaf_fd, 1):
            raise ValueError("base materializer source grew during capture")
        after = os.fstat(leaf_fd)
        if pre_exec_identity(after) != pre_exec_identity(before):
            raise ValueError("base materializer source changed during capture")

        for index, (descriptor, expected) in enumerate(
            zip(directory_fds, directory_before, strict=True)
        ):
            current = os.fstat(descriptor)
            if pre_exec_directory_identity(current) != pre_exec_directory_identity(
                expected
            ):
                raise ValueError("base materializer directory chain changed")
            linked = (
                os.stat(os.sep, follow_symlinks=False)
                if index == 0
                else os.stat(
                    directory_names[index - 1],
                    dir_fd=directory_fds[index - 1],
                    follow_symlinks=False,
                )
            )
            if pre_exec_directory_identity(linked) != pre_exec_directory_identity(
                expected
            ):
                raise ValueError("base materializer directory chain path changed")

        leaf_path = os.stat(
            absolute.name, dir_fd=directory_fds[-1], follow_symlinks=False
        )
        final = os.fstat(leaf_fd)
        if pre_exec_identity(final) != pre_exec_identity(before):
            raise ValueError("base materializer source changed during capture")
        if pre_exec_identity(leaf_path) != pre_exec_identity(before):
            raise ValueError("base materializer path changed during capture")
        return b"".join(chunks)
    finally:
        if leaf_fd is not None:
            os.close(leaf_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)


BASE_PATH = Path(os.path.abspath(__file__)).with_name("materialize_argo_record_set.py")
BASE_RAW = capture_base_source_before_exec(BASE_PATH, BASE_MAX_BYTES)
base = types.ModuleType("_archeion_argo_record_base")
base.__file__ = str(BASE_PATH)
exec(compile(BASE_RAW, str(BASE_PATH), "exec"), base.__dict__)

SCHEMA_VERSION = "1.0.0"
GENERATOR = "archeion-source-acceptance-materializer"
GENERATOR_VERSION = "1"
GENERATOR_SOURCE = "tools/knowledge-registry/materialize_source_acceptance.py"
COMPONENT_SCHEMA_SOURCE = base.COMPONENT_SCHEMA_SOURCE
RECORD_SET_SCHEMA_SOURCE = base.RECORD_SET_SCHEMA_SOURCE
POLICY_SCHEMA_SOURCE = "knowledge/registry/schemas/source-acceptance-policy.schema.json"
REVIEW_SCHEMA_SOURCE = (
    "knowledge/registry/schemas/independent-review-manifest.schema.json"
)
OUTCOME_SCHEMA_SOURCE = (
    "knowledge/registry/schemas/source-acceptance-outcome.schema.json"
)
REQUIREMENTS_SOURCE = base.REQUIREMENTS_SOURCE

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_CONTRACT_BYTES = base.MAX_CONTRACT_BYTES
MAX_REVIEW_MANIFESTS = 64

ACCEPTANCE_EVIDENCE = "source-monorepo-review:source-acceptance"
CONTROL_DERIVATION_ACCEPTED = (
    "conservative null retained after independent acceptance; not a source fact"
)

# Defence in depth beyond the policy schema: the transition applier only ever
# touches these leaves and only sets these exact values.
CHANNEL_TRANSITION_FIELDS = frozenset(
    {"availability_state", "review_state", "version_strategy", "refresh_policy", "gap"}
)
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
TREE_URI_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/tree/[a-f0-9]{40}/.+$"
)


# --------------------------------------------------------------------------
# Bounded, no-follow input capture
# --------------------------------------------------------------------------
def resolve_under_root(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def capture_json(
    path: Path, *, maximum: int, label: str
) -> tuple[Any, str, os.stat_result]:
    raw, identity = base.read_regular_capture(path, maximum=maximum, label=label)
    if not raw:
        raise ValueError(f"{label} is empty")
    value = base.strict_json_loads(raw)
    return value, base.sha256_bytes(raw), identity


def parse_date(value: Any, label: str) -> datetime.date:
    if not isinstance(value, str):
        raise ValueError(f"{label} is not a date string")
    try:
        return datetime.date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} is not an ISO date: {value}") from error


def parse_datetime(value: Any, label: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is not a date-time string")
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError(f"{label} is not a UTC date-time: {value}") from error


# --------------------------------------------------------------------------
# Typed exception accumulation
# --------------------------------------------------------------------------
class Decisions:
    """Collects per-record decisions and the shared typed exception queue."""

    def __init__(self) -> None:
        self.exceptions: list[dict[str, Any]] = []
        self.records: dict[str, dict[str, Any]] = {}

    def decision(self, record_id: str, component_id: str) -> dict[str, Any]:
        entry = self.records.get(record_id)
        if entry is None:
            entry = {
                "record_id": record_id,
                "component_id": component_id,
                "accepted": False,
                "gates": {},
                "exception_codes": [],
            }
            self.records[record_id] = entry
        return entry

    def gate(self, record_id: str, name: str, result: str) -> None:
        self.records[record_id]["gates"][name] = result

    def fail(
        self,
        *,
        code: str,
        scope: str,
        subject_kind: str,
        subject_id: str,
        message: str,
        next_action: str,
        evidence: Sequence[str],
        requires_human: bool,
        state: str = "unresolved",
        record_id: str | None = None,
    ) -> None:
        exception: dict[str, Any] = {
            "code": code,
            "scope": scope,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "state": state,
            "message": message,
            "evidence": list(dict.fromkeys(evidence)) or ["source-acceptance"],
            "next_action": next_action,
            "requires_human": requires_human,
        }
        if record_id is not None:
            exception["record_id"] = record_id
            entry = self.records.get(record_id)
            if entry is not None:
                entry["accepted"] = False
                if code not in entry["exception_codes"]:
                    entry["exception_codes"].append(code)
        self.exceptions.append(exception)


# --------------------------------------------------------------------------
# Binding-ledger reconstruction and recomputation (v2, generic)
# --------------------------------------------------------------------------
POINTER_KINDS = frozenset({"candidate-pointer", "capture-pointer"})


def normalized_binding_atom_core(atom: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in atom.items() if key != "atom_id"}


def atom_identity(core: Mapping[str, Any]) -> str:
    return "binding-atom:" + base.sha256_bytes(base.canonical_bytes(core))


def logical_binding(
    pointer: str, core: Mapping[str, Any], source_pointer: str | None
) -> dict[str, Any]:
    kind = str(core["binding_kind"])
    source_uri = core.get("source_uri") if kind == "primary-source" else None
    if kind in POINTER_KINDS:
        evidence = [str(core["evidence_identity_prefix"]) + str(source_pointer)]
    elif kind == "primary-source":
        evidence = [source_uri]
    else:
        evidence = core["evidence"]
    return {
        "record_pointer": pointer,
        "binding_kind": kind,
        "source_pointer": source_pointer,
        "source_uri": source_uri,
        "evidence": evidence,
        "derivation": core["derivation"],
    }


def reconstruct_record_items(
    record: Mapping[str, Any],
    record_entry: Mapping[str, Any],
    atoms: Sequence[Mapping[str, Any]],
) -> list[tuple[str, dict[str, Any], str | None]]:
    """Rebuild (pointer, atom_core, source_pointer) triples for one record.

    Mirrors the acquisition planner's ``validate_v2_binding_ledger`` so a
    zero-change reconstruction is byte-identical to the committed ledger.
    """

    ledger = record_entry.get("binding_ledger")
    if not isinstance(ledger, Mapping):
        raise ValueError("record entry has no binding ledger")
    leafs = base.leaf_pointers(record)
    tuples = ledger.get("tuples")
    if not isinstance(tuples, list) or len(tuples) != len(leafs):
        raise ValueError("record binding ledger tuples do not match record leaves")
    items: list[tuple[str, dict[str, Any], str | None]] = []
    for pointer, entry_tuple in zip(leafs, tuples, strict=True):
        if not isinstance(entry_tuple, list) or len(entry_tuple) not in {1, 2}:
            raise ValueError("record binding tuple shape is invalid")
        index = entry_tuple[0]
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < len(atoms)
        ):
            raise ValueError("record binding atom index is invalid")
        atom = atoms[index]
        kind = atom.get("binding_kind")
        if kind in POINTER_KINDS:
            if len(entry_tuple) != 2 or not isinstance(entry_tuple[1], str):
                raise ValueError("record binding pointer tuple is invalid")
            source_pointer: str | None = entry_tuple[1]
        else:
            if len(entry_tuple) != 1:
                raise ValueError("record binding non-pointer tuple is invalid")
            source_pointer = None
        items.append((pointer, normalized_binding_atom_core(atom), source_pointer))
    return items


def accepted_record_items(
    original_items: Sequence[tuple[str, dict[str, Any], str | None]],
    accepted_record: Mapping[str, Any],
) -> list[tuple[str, dict[str, Any], str | None]]:
    """Project binding triples onto the accepted record's leaf set.

    Value-only transitions keep their leaf pointer and reuse the original
    binding.  Leaves removed by acceptance (a resolved channel gap object) drop
    out.  Genuinely new leaves (the ``null`` channel gap) receive a
    conservative control binding — never a source fact.
    """

    by_pointer = {
        pointer: (core, source_pointer)
        for pointer, core, source_pointer in original_items
    }
    control_core = {
        "binding_kind": "control",
        "evidence": [ACCEPTANCE_EVIDENCE],
        "derivation": CONTROL_DERIVATION_ACCEPTED,
    }
    projected: list[tuple[str, dict[str, Any], str | None]] = []
    for pointer in base.leaf_pointers(accepted_record):
        if pointer in by_pointer:
            core, source_pointer = by_pointer[pointer]
            projected.append((pointer, core, source_pointer))
        else:
            projected.append((pointer, dict(control_core), None))
    return projected


def recompute_binding_ledgers(
    items_by_path: Mapping[str, Sequence[tuple[str, dict[str, Any], str | None]]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Rebuild the shared atom pool, per-record ledgers and the set ledger."""

    core_by_id: dict[str, dict[str, Any]] = {}
    for items in items_by_path.values():
        for _pointer, core, _source_pointer in items:
            core_by_id[atom_identity(core)] = core
    ordered_ids = sorted(core_by_id)
    atoms = [{"atom_id": atom_id, **core_by_id[atom_id]} for atom_id in ordered_ids]
    index_of = {atom_id: index for index, atom_id in enumerate(ordered_ids)}

    record_ledgers: dict[str, dict[str, Any]] = {}
    logical_ledger: list[dict[str, Any]] = []
    for path in sorted(items_by_path):
        items = items_by_path[path]
        leafs = [pointer for pointer, _core, _source_pointer in items]
        bindings = [
            logical_binding(pointer, core, source_pointer)
            for pointer, core, source_pointer in items
        ]
        tuples: list[list[Any]] = []
        for _pointer, core, source_pointer in items:
            index = index_of[atom_identity(core)]
            if core["binding_kind"] in POINTER_KINDS:
                tuples.append([index, source_pointer])
            else:
                tuples.append([index])
        record_ledgers[path] = {
            "leaf_order_algorithm": "canonical-json-leaf-pointers-v1",
            "leaf_count": len(leafs),
            "tuple_count": len(tuples),
            "leaf_pointers_sha256": base.sha256_bytes(base.canonical_bytes(leafs)),
            "logical_bindings_sha256": base.sha256_bytes(
                base.canonical_bytes(bindings)
            ),
            "tuples": tuples,
        }
        logical_ledger.append({"path": path, "bindings": bindings})
    set_ledger = {
        "version": 2,
        "atom_order_algorithm": "binding-atom-id-lexicographic-v1",
        "leaf_order_algorithm": "canonical-json-leaf-pointers-v1",
        "atom_count": len(atoms),
        "atoms": atoms,
        "logical_ledger_sha256": base.sha256_bytes(
            base.canonical_bytes(logical_ledger)
        ),
    }
    return set_ledger, record_ledgers


# --------------------------------------------------------------------------
# Record acceptance transformation (leaf-preserving except channel gap null)
# --------------------------------------------------------------------------
def json_pointer_parts(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ValueError(f"JSON pointer is not absolute: {pointer}")
    return [
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer.removeprefix("/").split("/")
    ]


def pointer_get(value: Any, pointer: str) -> Any:
    current = value
    for part in json_pointer_parts(pointer):
        if isinstance(current, Mapping):
            if part not in current:
                raise KeyError(pointer)
            current = current[part]
        elif isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                raise KeyError(pointer)
            current = current[int(part)]
        else:
            raise KeyError(pointer)
    return current


def pointer_set(value: Any, pointer: str, new_value: Any) -> None:
    parts = json_pointer_parts(pointer)
    current = value
    for part in parts[:-1]:
        if isinstance(current, Mapping):
            current = current[part]
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            raise KeyError(pointer)
    leaf = parts[-1]
    if isinstance(current, Mapping):
        current[leaf] = new_value
    elif isinstance(current, list):
        current[int(leaf)] = new_value
    else:
        raise KeyError(pointer)


def authorized_transition_target(pointer: str, authorization: Mapping[str, Any]) -> Any:
    """Return the only value a given leaf may transition to, or raise."""

    if pointer == "/review/status":
        return "accepted"
    if pointer == "/versions/0/build_metadata/source_resolution/review_state":
        return "accepted"
    match = re.fullmatch(r"/channels/[0-9]+/([a-z_]+)", pointer)
    if match is None:
        raise ValueError(f"transition pointer is out of policy: {pointer}")
    field = match.group(1)
    if field not in CHANNEL_TRANSITION_FIELDS:
        raise ValueError(f"transition pointer is out of policy: {pointer}")
    if field == "availability_state":
        return authorization["channel_availability_state"]
    if field == "review_state":
        return "accepted"
    if field == "version_strategy":
        return authorization["version_strategy"]
    if field == "refresh_policy":
        return authorization["refresh_policy"]
    if field == "gap":
        return None
    raise ValueError(f"transition pointer is out of policy: {pointer}")


def channel_index_for_id(record: Mapping[str, Any], channel_id: str) -> int:
    channels = record.get("channels")
    if not isinstance(channels, list):
        raise ValueError("record channels are invalid")
    matches = [
        index
        for index, channel in enumerate(channels)
        if isinstance(channel, Mapping) and channel.get("channel_id") == channel_id
    ]
    if len(matches) != 1:
        raise ValueError(
            "policy source channel does not resolve to exactly one channel"
        )
    return matches[0]


# --------------------------------------------------------------------------
# Contract loading (schemas, validators, hashes) via no-follow capture
# --------------------------------------------------------------------------
def load_contracts(repo_root: Path) -> dict[str, Any]:
    paths = {
        "component_schema": (repo_root / COMPONENT_SCHEMA_SOURCE, MAX_CONTRACT_BYTES),
        "record_set_schema": (repo_root / RECORD_SET_SCHEMA_SOURCE, MAX_CONTRACT_BYTES),
        "policy_schema": (repo_root / POLICY_SCHEMA_SOURCE, MAX_CONTRACT_BYTES),
        "review_schema": (repo_root / REVIEW_SCHEMA_SOURCE, MAX_CONTRACT_BYTES),
        "outcome_schema": (repo_root / OUTCOME_SCHEMA_SOURCE, MAX_CONTRACT_BYTES),
        "requirements": (repo_root / REQUIREMENTS_SOURCE, MAX_CONTRACT_BYTES),
        "generator": (Path(os.path.abspath(__file__)), MAX_CONTRACT_BYTES),
    }
    raw: dict[str, bytes] = {}
    captured: list[tuple[Path, int, str, os.stat_result]] = []
    for key, (path, maximum) in paths.items():
        data, identity = base.read_regular_capture(
            path, maximum=maximum, label=f"acceptance contract {key}"
        )
        raw[key] = data
        captured.append((path, maximum, base.sha256_bytes(data), identity))
    dependencies = base.parse_requirement_closure(raw["requirements"])
    contracts = {
        "component_validator": base.schema_validator(
            base.strict_json_loads(raw["component_schema"]), "component schema"
        ),
        "record_set_validator": base.schema_validator(
            base.strict_json_loads(raw["record_set_schema"]), "record-set schema"
        ),
        "policy_validator": base.schema_validator(
            base.strict_json_loads(raw["policy_schema"]), "acceptance policy schema"
        ),
        "review_validator": base.schema_validator(
            base.strict_json_loads(raw["review_schema"]), "review manifest schema"
        ),
        "outcome_validator": base.schema_validator(
            base.strict_json_loads(raw["outcome_schema"]), "acceptance outcome schema"
        ),
        "dependencies": dependencies,
        "hashes": {
            "source_sha256": base.sha256_bytes(raw["generator"]),
            "base_materializer_sha256": base.sha256_bytes(BASE_RAW),
            "component_schema_sha256": base.sha256_bytes(raw["component_schema"]),
            "record_set_schema_sha256": base.sha256_bytes(raw["record_set_schema"]),
            "policy_schema_sha256": base.sha256_bytes(raw["policy_schema"]),
            "review_manifest_schema_sha256": base.sha256_bytes(raw["review_schema"]),
            "outcome_schema_sha256": base.sha256_bytes(raw["outcome_schema"]),
            "requirements_sha256": base.sha256_bytes(raw["requirements"]),
        },
        "captured": captured,
    }
    return contracts


# --------------------------------------------------------------------------
# Selected-target subject set (for target-scoped gap partitioning)
# --------------------------------------------------------------------------
def selected_subject_ids(record: Mapping[str, Any], channel_id: str) -> set[str]:
    subjects: set[str] = {channel_id}
    component = record.get("component")
    if isinstance(component, Mapping) and isinstance(
        component.get("component_id"), str
    ):
        subjects.add(component["component_id"])
    versions = record.get("versions")
    if isinstance(versions, list) and versions and isinstance(versions[0], Mapping):
        version_id = versions[0].get("component_version_id")
        if isinstance(version_id, str):
            subjects.add(version_id)
    return subjects


# --------------------------------------------------------------------------
# Per-record acceptance evaluation
# --------------------------------------------------------------------------
def evaluate_record(
    *,
    record: Mapping[str, Any],
    record_entry: Mapping[str, Any],
    record_content_sha256: str,
    record_policy: Mapping[str, Any],
    review_manifest: Mapping[str, Any] | None,
    reviewer_load: Mapping[str, int],
    policy: Mapping[str, Any],
    observed_at: datetime.datetime,
    contracts: Mapping[str, Any],
    decisions: Decisions,
) -> Mapping[str, Any] | None:
    """Run every acceptance gate for one record.

    Returns the accepted successor record when all gates pass, otherwise
    ``None`` after appending the relevant typed exceptions.
    """

    record_id = str(record.get("record_id"))
    component = (
        record.get("component") if isinstance(record.get("component"), Mapping) else {}
    )
    component_id = str(component.get("component_id"))
    decision = decisions.decision(record_id, component_id)
    authorization = policy["authorization"]

    def gate(name: str, ok: bool) -> None:
        decisions.gate(record_id, name, "pass" if ok else "fail")

    failed = False

    def fail(
        code: str,
        message: str,
        next_action: str,
        *,
        subject_kind: str = "component",
        subject_id: str | None = None,
        requires_human: bool = True,
        evidence: Sequence[str] | None = None,
    ) -> None:
        nonlocal failed
        failed = True
        decisions.fail(
            code=code,
            scope="record",
            subject_kind=subject_kind,
            subject_id=subject_id or component_id,
            message=message,
            next_action=next_action,
            evidence=evidence or [record_id],
            requires_human=requires_human,
            record_id=record_id,
        )

    # Gate: policy record binding
    if record_policy.get("bound_record_content_sha256") != record_content_sha256:
        gate("policy_binding", False)
        fail(
            "policy_record_binding_mismatch",
            "policy record binding does not match the exact reviewed record bytes",
            "reissue the acceptance policy against the exact reviewed record content",
            requires_human=True,
        )
    else:
        gate("policy_binding", True)

    # Gate: independent review manifest present, bound, and an accept decision
    if review_manifest is None:
        gate("review_present", False)
        fail(
            "missing_review_artifact",
            "no independent review manifest exists for this record",
            "supply exactly one independent review manifest bound to the record",
            requires_human=True,
        )
    else:
        gate("review_present", True)
        binding_ok = (
            review_manifest.get("bound_record_content_sha256") == record_content_sha256
            and review_manifest.get("component_id") == component_id
        )
        if not binding_ok:
            gate("review_binding", False)
            fail(
                "review_binding_mismatch",
                "review manifest is not bound to the exact reviewed record",
                "rebind the review manifest to the exact record content hash",
                subject_kind="review",
                subject_id=str(review_manifest.get("review_id")),
            )
        else:
            gate("review_binding", True)
        if review_manifest.get("decision") != "accept":
            gate("review_decision", False)
            fail(
                "review_decision_not_accept",
                "independent review decision is not accept",
                "resolve the record through the reviewer's non-accept decision",
                subject_kind="review",
                subject_id=str(review_manifest.get("review_id")),
            )
        else:
            gate("review_decision", True)
        # Gate: reviewer authorisation and independence
        reviewer = (
            review_manifest.get("reviewer")
            if isinstance(review_manifest.get("reviewer"), Mapping)
            else {}
        )
        reviewer_id = str(reviewer.get("identity"))
        proposer = (
            record.get("review", {}).get("reviewed_by")
            if isinstance(record.get("review"), Mapping)
            else None
        )
        authorized = set(policy["reviewers"]["authorized_reviewers"])
        denied = set(policy["reviewers"]["denied_reviewers"])
        excluded = set(policy["reviewers"]["excluded_proposer_identities"])
        if reviewer_id not in authorized or reviewer_id in denied:
            gate("reviewer_authorized", False)
            fail(
                "reviewer_unauthorized",
                "reviewer is not on the standing authorized reviewer list",
                "authorize the reviewer in the standing policy or reassign review",
                subject_kind="reviewer",
                subject_id=reviewer_id,
            )
        else:
            gate("reviewer_authorized", True)
        if reviewer_id == proposer or reviewer_id in excluded:
            gate("reviewer_independent", False)
            fail(
                "reviewer_not_independent",
                "reviewer identity overlaps the proposing identity",
                "assign an independent reviewer distinct from the proposer",
                subject_kind="reviewer",
                subject_id=reviewer_id,
            )
        else:
            gate("reviewer_independent", True)
        if reviewer_load.get(reviewer_id, 0) > int(
            policy["reviewers"]["max_records_per_reviewer"]
        ):
            gate("reviewer_reuse", False)
            fail(
                "reviewer_reuse",
                "reviewer accepts more records than the standing reuse cap allows",
                "spread acceptance across independent reviewers within the cap",
                subject_kind="reviewer",
                subject_id=reviewer_id,
            )
        else:
            gate("reviewer_reuse", True)
        # Gate: freshness (review recency vs the observation, and ordering)
        reviewed_at = parse_date(
            review_manifest.get("reviewed_at"), f"{record_id} reviewed_at"
        )
        proposal_reviewed_at = None
        if isinstance(record.get("review"), Mapping):
            try:
                proposal_reviewed_at = parse_date(
                    record["review"].get("reviewed_at"),
                    f"{record_id} proposal reviewed_at",
                )
            except ValueError:
                proposal_reviewed_at = None
        if reviewed_at > observed_at.date() or (
            proposal_reviewed_at is not None and reviewed_at < proposal_reviewed_at
        ):
            gate("review_order", False)
            fail(
                "out_of_order_review",
                "review predates the proposal or postdates the observation",
                "align the independent review timestamp with the observed proposal",
                subject_kind="review",
                subject_id=str(review_manifest.get("review_id")),
            )
        else:
            gate("review_order", True)
        age_days = (observed_at.date() - reviewed_at).days
        if age_days > int(policy["freshness"]["max_review_age_days"]):
            gate("review_fresh", False)
            fail(
                "evidence_stale",
                "the independent review is older than the standing freshness window",
                "obtain a fresh independent review within the freshness window",
                subject_kind="review",
                subject_id=str(review_manifest.get("review_id")),
            )
        else:
            gate("review_fresh", True)
        # Gate: risk and rights findings
        if review_manifest.get("risk_finding") == "high-risk":
            gate("risk", False)
            fail(
                "high_risk_subject",
                "the reviewer flagged the subject as high risk",
                "route the high-risk subject to human resolution",
                requires_human=True,
            )
        else:
            gate("risk", True)
        if review_manifest.get("rights_finding") == "ambiguous":
            gate("rights_finding", False)
            fail(
                "ambiguous_rights",
                "the reviewer flagged the rights position as ambiguous",
                "resolve the ambiguous rights position before acceptance",
                subject_kind="rights",
            )
        else:
            gate("rights_finding", True)
        # Gate: reproduced evidence hashes match the record's source facts
        evaluate_evidence_gate(record, review_manifest, gate, fail)

    # Gate: high-risk subject denylist (independent of the reviewer's opinion)
    subjects_text = [component_id]
    if isinstance(component.get("topics"), list):
        subjects_text.extend(str(topic) for topic in component["topics"])
    denylist = policy.get("high_risk_subjects", [])
    hit = next(
        (term for term in denylist for text in subjects_text if term == text), None
    )
    if hit is not None:
        gate("risk_denylist", False)
        fail(
            "high_risk_subject",
            f"subject matches the standing high-risk denylist entry {hit}",
            "route the high-risk subject to human resolution",
            requires_human=True,
        )
    else:
        gate("risk_denylist", True)

    # Gate: source-resolution state, immutable locator, structured rights
    evaluate_state_locator_rights(record, record_policy, authorization, gate, fail)

    # Gate: target-scoped and residual gap partitioning
    retained = evaluate_gap_partitioning(
        record, record_policy, review_manifest, gate, fail
    )

    if failed:
        return None

    # All gates passed: build the accepted successor record.
    try:
        accepted = build_accepted_record(record, record_policy, authorization)
        schema_errors = list(contracts["component_validator"].iter_errors(accepted))
    except (ValueError, KeyError) as error:
        fail(
            "transition_precondition_failed",
            f"acceptance transition failed: {error}",
            "reconcile the policy transitions with the exact reviewed record",
        )
        return None
    if schema_errors:
        first = sorted(schema_errors, key=lambda item: list(item.path))[0]
        pointer = "/" + "/".join(str(part) for part in first.path)
        fail(
            "accepted_record_schema_invalid",
            f"accepted record fails the component schema at {pointer}: {first.message}",
            "correct the acceptance transitions so the record stays schema-valid",
        )
        return None
    decision["accepted"] = True
    decision["retained_residual_gaps"] = retained
    return accepted


def evaluate_evidence_gate(
    record: Mapping[str, Any], review: Mapping[str, Any], gate, fail
) -> None:
    try:
        chart = record["versions"][0]["build_metadata"]["source_resolution"]["chart"]
    except (KeyError, IndexError, TypeError):
        gate("evidence_hashes", False)
        fail(
            "source_resolution_state_invalid",
            "record has no source_resolution.chart to reproduce",
            "materialize a chart source_resolution before acceptance",
        )
        return
    expected = {
        "chart-package": {
            "locator": _get(chart, "package", "uri"),
            "content_sha256": _get(chart, "package", "content_sha256"),
        },
        "chart-provenance": {
            "locator": _get(chart, "provenance", "uri"),
            "content_sha256": _get(chart, "provenance", "content_sha256"),
        },
        "chart-commit": {
            "locator": chart.get("subtree_uri"),
            "content_sha256": chart.get("commit"),
        },
    }
    reproduced = review.get("reproduced_primary_sources", [])
    by_kind: dict[str, list[Mapping[str, Any]]] = {}
    for item in reproduced if isinstance(reproduced, list) else []:
        if isinstance(item, Mapping):
            by_kind.setdefault(str(item.get("kind")), []).append(item)
    missing = sorted(kind for kind in expected if len(by_kind.get(kind, [])) != 1)
    mismatched = sorted(
        kind
        for kind, wanted in expected.items()
        if len(by_kind.get(kind, [])) == 1
        and (
            by_kind[kind][0].get("locator") != wanted["locator"]
            or by_kind[kind][0].get("content_sha256") != wanted["content_sha256"]
        )
    )
    if missing or mismatched:
        gate("evidence_hashes", False)
        details = []
        if missing:
            details.append("missing-or-duplicate=" + ",".join(missing))
        if mismatched:
            details.append("locator-or-hash-mismatch=" + ",".join(mismatched))
        fail(
            "evidence_tamper",
            "reproduced evidence does not exactly cover the record source facts: "
            + "; ".join(details),
            "reconcile the reproduced evidence with the immutable source record",
        )
    else:
        gate("evidence_hashes", True)


def _get(mapping: Any, *path: str) -> Any:
    current = mapping
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


def evaluate_state_locator_rights(
    record: Mapping[str, Any],
    record_policy: Mapping[str, Any],
    authorization: Mapping[str, Any],
    gate,
    fail,
) -> None:
    component = (
        record.get("component") if isinstance(record.get("component"), Mapping) else {}
    )
    versions = record.get("versions")
    version = versions[0] if isinstance(versions, list) and versions else {}
    resolution = _get(version, "build_metadata", "source_resolution")
    chart = resolution.get("chart") if isinstance(resolution, Mapping) else None
    state_ok = (
        component.get("disposition") == "selected"
        and version.get("resolution_state") == "resolved"
        and isinstance(version.get("source_ref"), str)
        and COMMIT_RE.fullmatch(version.get("source_ref") or "") is not None
        and isinstance(chart, Mapping)
        and chart.get("commit") == version.get("source_ref")
        and resolution.get("review_state") == "proposed"
    )
    if not state_ok:
        gate("source_resolution_state", False)
        fail(
            "source_resolution_state_invalid",
            "record is not a resolved, selected, still-proposed exact-commit chart",
            "resolve the version and disposition before submitting for acceptance",
        )
        return
    gate("source_resolution_state", True)

    try:
        channel_index = channel_index_for_id(
            record, str(record_policy["source_channel_id"])
        )
        channel = record["channels"][channel_index]
    except (ValueError, KeyError, IndexError):
        gate("immutable_locator", False)
        fail(
            "immutable_locator_invalid",
            "policy source channel does not resolve to a single record channel",
            "bind the policy to the exact immutable source channel id",
        )
        return
    canonical_uri = channel.get("canonical_uri")
    subtree_uri = chart.get("subtree_uri")
    locator_ok = (
        channel.get("channel_type") == "source"
        and isinstance(canonical_uri, str)
        and TREE_URI_RE.fullmatch(canonical_uri) is not None
        and canonical_uri == subtree_uri
        and channel.get("access") == authorization["channel_access"]
    )
    if not locator_ok:
        gate("immutable_locator", False)
        fail(
            "immutable_locator_invalid",
            "source channel is not the exact immutable commit-bound tree locator",
            "bind the channel to the exact github tree/<commit>/<subtree> locator",
        )
        return
    gate("immutable_locator", True)

    license_block = _get(chart, "license")
    rights_ok = (
        channel.get("publisher") == authorization["publisher"]
        and chart.get("publisher") == authorization["publisher"]
        and channel.get("rights") == authorization["rights_statement"]
        and isinstance(license_block, Mapping)
        and license_block.get("spdx") == authorization["license_spdx"]
    )
    if not rights_ok:
        gate("structured_rights", False)
        fail(
            "ambiguous_rights",
            "publisher, rights statement, or SPDX licence differ from the policy",
            "reconcile the chart rights with the authorized Argo Apache statement",
            subject_kind="rights",
        )
    else:
        gate("structured_rights", True)


def evaluate_gap_partitioning(
    record: Mapping[str, Any],
    record_policy: Mapping[str, Any],
    review: Mapping[str, Any] | None,
    gate,
    fail,
) -> int:
    channel_id = str(record_policy["source_channel_id"])
    subjects = selected_subject_ids(record, channel_id)
    resolve_gaps = set(record_policy.get("resolve_gaps", []))
    residual = {
        (subject["subject_kind"], subject["subject_id"])
        for subject in record_policy.get("authorized_residual_gap_subjects", [])
    }
    reviewed = {
        gap.get("gap_id"): gap.get("disposition")
        for gap in (
            review.get("gaps_reviewed", []) if isinstance(review, Mapping) else []
        )
    }
    retained = 0
    ok = True
    for gap in record.get("gaps", []) if isinstance(record.get("gaps"), list) else []:
        if not isinstance(gap, Mapping) or gap.get("blocking") is not True:
            continue
        gap_id = gap.get("gap_id")
        subject_kind = gap.get("subject_kind")
        subject_id = gap.get("subject_id")
        if gap_id in resolve_gaps:
            # Acceptance resolves this gap; the reviewer must corroborate it.
            if reviewed.get(gap_id) != "resolved":
                ok = False
                fail(
                    "unresolved_target_gap",
                    f"policy resolves gap {gap_id} but the reviewer did not",
                    "obtain a reviewer resolution for the gap before acceptance",
                    subject_kind=str(subject_kind),
                    subject_id=str(subject_id),
                )
            if subject_id not in subjects and subject_kind != "component":
                ok = False
                fail(
                    "conflict",
                    f"policy resolves an unrelated-subject gap {gap_id}",
                    "only the target's own review gap may be resolved by acceptance",
                    subject_kind=str(subject_kind),
                    subject_id=str(subject_id),
                )
            continue
        if subject_kind == "dependency":
            ok = False
            fail(
                "unresolved_dependency_rights",
                f"selected-version dependency gap {gap_id} is unresolved",
                "resolve third-party dependency rights through human review",
                subject_kind="dependency",
                subject_id=str(subject_id),
                requires_human=True,
            )
            continue
        if subject_id in subjects:
            ok = False
            fail(
                "unresolved_target_gap",
                f"the record retains an unresolved blocking gap {gap_id} for this target",
                "resolve the target's own blocking gap before acceptance",
                subject_kind=str(subject_kind),
                subject_id=str(subject_id),
            )
            continue
        if (subject_kind, subject_id) in residual:
            retained += 1
            continue
        ok = False
        fail(
            "partial_acceptance_unauthorized",
            f"blocking gap {gap_id} is not authorized as a residual unrelated lane",
            "authorize the unrelated residual lane in policy or resolve the gap",
            subject_kind=str(subject_kind),
            subject_id=str(subject_id),
        )
    gate("gap_partitioning", ok)
    return retained


def build_accepted_record(
    record: Mapping[str, Any],
    record_policy: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    accepted = json.loads(json.dumps(record))
    channel_index = channel_index_for_id(
        accepted, str(record_policy["source_channel_id"])
    )
    for transition in record_policy["transitions"]:
        pointer = str(transition["pointer"])
        expected_to = authorized_transition_target(pointer, authorization)
        if transition["to"] != expected_to:
            raise ValueError(f"transition target is out of policy: {pointer}")
        channel_match = re.fullmatch(r"/channels/([0-9]+)/[a-z_]+", pointer)
        if channel_match is not None and int(channel_match.group(1)) != channel_index:
            raise ValueError(
                "transition targets a channel other than the policy channel"
            )
        current = pointer_get(accepted, pointer)
        if current != transition["from"]:
            raise ValueError(f"transition precondition failed at {pointer}")
        pointer_set(accepted, pointer, transition["to"])
    # Leaf-preserving resolution of the target's own review gap(s).
    for gap in accepted.get("gaps", []):
        if isinstance(gap, Mapping) and gap.get("gap_id") in set(
            record_policy.get("resolve_gaps", [])
        ):
            if gap.get("blocking") is not True or gap.get("review_state") != "proposed":
                raise ValueError("resolvable gap is not a blocking proposed gap")
            gap["blocking"] = False
            gap["review_state"] = "accepted"
    # An accepted reviewed_component record may not retain a proposed channel
    # review_state (registry preflight).  The exact source channel is accepted
    # by the policy transitions above; every ancillary channel that was not
    # independently accepted is marked non-authoritative needs-review.  This is
    # a value-only change that never alters a source locator or fact.
    for channel in accepted.get("channels", []):
        if isinstance(channel, Mapping) and channel.get("review_state") == "proposed":
            channel["review_state"] = "needs-review"
    if accepted.get("review", {}).get("status") != "accepted":
        raise ValueError("acceptance did not flip the record review status")
    return accepted


# --------------------------------------------------------------------------
# Denominator and policy gates (whole-run)
# --------------------------------------------------------------------------
def evaluate_denominator(
    record_set: Mapping[str, Any],
    policy: Mapping[str, Any],
    decisions: Decisions,
) -> bool:
    ok = True
    scope = (
        record_set.get("scope") if isinstance(record_set.get("scope"), Mapping) else {}
    )
    required = set(scope.get("required_targets", []))
    materialized = set(scope.get("materialized_component_ids", []))
    authorized_codes = set(policy["denominator"]["authorized_residual_set_gap_codes"])
    for gap in (
        record_set.get("gaps", []) if isinstance(record_set.get("gaps"), list) else []
    ):
        if not isinstance(gap, Mapping) or gap.get("blocking") is not True:
            continue
        target = gap.get("target_id")
        code = gap.get("code")
        if (
            target in required
            and target not in materialized
            and str(target).startswith("cmp:helm:")
        ):
            ok = False
            decisions.fail(
                code="denominator_incomplete",
                scope="set",
                subject_kind="target",
                subject_id=str(target),
                message=f"required denominator target {target} is absent and blocking",
                next_action="materialize the missing denominator target before acceptance",
                evidence=[str(gap.get("gap_id") or code or target)],
                requires_human=True,
            )
        elif code not in authorized_codes:
            ok = False
            decisions.fail(
                code="denominator_gap_unauthorized",
                scope="set",
                subject_kind="target",
                subject_id=str(target),
                message=f"blocking set gap {code} is not an authorized residual lane",
                next_action="authorize the residual set lane in policy or resolve the gap",
                evidence=[str(gap.get("gap_id") or code or target)],
                requires_human=True,
            )
    if policy["denominator"]["require_all_targets"]:
        # Chart (helm) targets must be materialized as reviewed records; the
        # github/oci source lanes are represented inside each chart record's
        # source_resolution rather than as separate records, so they are not
        # required to appear as materialized component ids.
        for target in sorted(required):
            if str(target).startswith("cmp:helm:") and target not in materialized:
                ok = False
                decisions.fail(
                    code="denominator_incomplete",
                    scope="set",
                    subject_kind="target",
                    subject_id=str(target),
                    message=f"required chart target {target} is not materialized",
                    next_action="materialize the required chart record before acceptance",
                    evidence=[str(target)],
                    requires_human=True,
                )
    return ok


def evaluate_policy_binding(
    record_set: Mapping[str, Any],
    policy: Mapping[str, Any],
    policy_payload_sha256: str,
    observed_at: datetime.datetime,
    contracts: Mapping[str, Any],
    decisions: Decisions,
) -> bool:
    ok = True
    bindings = policy["bindings"]
    generator = (
        record_set.get("generator")
        if isinstance(record_set.get("generator"), Mapping)
        else {}
    )
    hashes = contracts["hashes"]
    expected = {
        "record_set_id": record_set.get("record_set_id"),
        "record_set_payload_sha256": record_set.get("payload_sha256"),
        "generator_source_sha256": generator.get("source_sha256"),
        "component_schema_sha256": hashes["component_schema_sha256"],
        "record_set_schema_sha256": hashes["record_set_schema_sha256"],
        "requirements_sha256": hashes["requirements_sha256"],
    }
    for key, value in expected.items():
        if bindings.get(key) != value:
            ok = False
            decisions.fail(
                code="policy_binding_mismatch",
                scope="policy",
                subject_kind="policy-binding",
                subject_id=key,
                message=f"standing policy binding {key} does not match the exact inputs",
                next_action="reissue the standing policy against the exact input hashes",
                evidence=[str(bindings.get(key)), str(value)],
                requires_human=True,
            )
    not_valid_after = parse_datetime(
        policy.get("not_valid_after"), "policy not_valid_after"
    )
    if not_valid_after < observed_at:
        ok = False
        decisions.fail(
            code="policy_stale",
            scope="policy",
            subject_kind="policy",
            subject_id=str(policy.get("policy_id")),
            message="standing policy expired before the observation time",
            next_action="renew the standing acceptance policy",
            evidence=[
                str(policy.get("not_valid_after")),
                str(record_set.get("scope", {}).get("observed_at")),
            ],
            requires_human=True,
        )
    return ok


# --------------------------------------------------------------------------
# Successor set assembly
# --------------------------------------------------------------------------
def content_addressed(
    document: Mapping[str, Any], prefix: str, id_field: str
) -> dict[str, Any]:
    core = {
        key: value
        for key, value in document.items()
        if key not in {id_field, "payload_sha256"}
    }
    payload_sha256 = base.sha256_bytes(base.canonical_bytes(core))
    result = dict(document)
    result[id_field] = prefix + payload_sha256
    result["payload_sha256"] = payload_sha256
    return result


def build_successor_set(
    record_set: Mapping[str, Any],
    accepted_records: Mapping[str, Mapping[str, Any]],
    accepted_bytes: Mapping[str, bytes],
    accepted_sha: Mapping[str, str],
) -> dict[str, Any]:
    successor = json.loads(json.dumps(record_set))
    successor["review"] = dict(successor["review"])
    successor["review"]["status"] = "accepted"
    successor["review"]["reviewed_by"] = "independent-source-acceptance"
    successor["review"]["reviewed_at"] = str(successor["scope"]["observed_at"]).split(
        "T", 1
    )[0]
    successor["authority_state"] = "reviewed"

    # Recompute the shared binding ledger from the accepted + retained records.
    atoms = record_set["binding_ledger"]["atoms"]
    items_by_path: dict[str, list[tuple[str, dict[str, Any], str | None]]] = {}
    records_by_path: dict[str, Mapping[str, Any]] = {}
    for entry in record_set["records"]:
        path = entry["path"]
        record_id = entry["record_id"]
        if record_id in accepted_records:
            record_obj = accepted_records[record_id]
        else:
            record_obj = _load_predecessor_record(record_set, entry)
        records_by_path[path] = record_obj
        original_items = reconstruct_record_items(
            _predecessor_record(record_set, entry), entry, atoms
        )
        if record_id in accepted_records:
            items_by_path[path] = accepted_record_items(original_items, record_obj)
        else:
            items_by_path[path] = original_items
    set_ledger, record_ledgers = recompute_binding_ledgers(items_by_path)
    successor["binding_ledger"] = set_ledger

    accepted_count = 0
    for entry in successor["records"]:
        path = entry["path"]
        record_id = entry["record_id"]
        entry["binding_ledger"] = record_ledgers[path]
        if record_id in accepted_records:
            entry["content_sha256"] = accepted_sha[record_id]
            entry["bytes"] = len(accepted_bytes[record_id])
            entry["review_status"] = "accepted"
            accepted_count += 1
    successor["counts"] = dict(successor["counts"])
    successor["counts"]["accepted_records"] = accepted_count
    return content_addressed(successor, "reviewed-record-set:", "record_set_id")


# Predecessor records are supplied by the caller; these thin accessors keep the
# assembly readable while the caller owns the exact captured bytes.
_PREDECESSOR_RECORDS: dict[str, Mapping[str, Any]] = {}


def _predecessor_record(
    record_set: Mapping[str, Any], entry: Mapping[str, Any]
) -> Mapping[str, Any]:
    return _PREDECESSOR_RECORDS[entry["record_id"]]


def _load_predecessor_record(
    record_set: Mapping[str, Any], entry: Mapping[str, Any]
) -> Mapping[str, Any]:
    return _PREDECESSOR_RECORDS[entry["record_id"]]


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def materialize(
    repo_root: Path,
    record_set_path: Path,
    records_dir: Path,
    policy_path: Path,
    review_paths: Sequence[Path],
) -> tuple[
    dict[str, Any],
    dict[str, bytes],
    dict[str, Any] | None,
    list[tuple[Path, int, str, os.stat_result]],
]:
    contracts = load_contracts(repo_root)
    captured = list(contracts["captured"])
    decisions = Decisions()

    record_set, record_set_sha, record_set_identity = capture_json(
        record_set_path, maximum=MAX_INPUT_BYTES, label="proposed reviewed record set"
    )
    captured.append(
        (record_set_path, MAX_INPUT_BYTES, record_set_sha, record_set_identity)
    )
    if not isinstance(record_set, Mapping):
        raise ValueError("proposed reviewed record set must be an object")
    base.validate_schema(
        contracts["record_set_validator"], record_set, "proposed record set"
    )
    if record_set.get("review", {}).get("status") != "proposed":
        raise ValueError("input record set is not in the proposed state")
    if not isinstance(record_set.get("binding_ledger"), Mapping):
        raise ValueError("acceptance requires a normalized v2 binding ledger")

    policy, policy_sha, policy_identity = capture_json(
        policy_path, maximum=MAX_INPUT_BYTES, label="standing acceptance policy"
    )
    captured.append((policy_path, MAX_INPUT_BYTES, policy_sha, policy_identity))
    base.validate_schema(contracts["policy_validator"], policy, "acceptance policy")
    expected_policy = content_addressed(
        policy, "source-acceptance-policy:", "policy_id"
    )
    if expected_policy["policy_id"] != policy.get("policy_id") or expected_policy[
        "payload_sha256"
    ] != policy.get("payload_sha256"):
        raise ValueError("acceptance policy is not correctly content-addressed")

    reviews: dict[str, list[dict[str, Any]]] = {}
    review_index: list[dict[str, Any]] = []
    for review_path in review_paths:
        manifest, manifest_sha, manifest_identity = capture_json(
            review_path,
            maximum=MAX_INPUT_BYTES,
            label=f"review manifest {review_path.name}",
        )
        captured.append((review_path, MAX_INPUT_BYTES, manifest_sha, manifest_identity))
        base.validate_schema(contracts["review_validator"], manifest, "review manifest")
        expected_manifest = content_addressed(
            manifest, "independent-source-review:", "review_id"
        )
        if expected_manifest["review_id"] != manifest.get("review_id"):
            raise ValueError("review manifest is not correctly content-addressed")
        if manifest.get("bound_record_set_payload_sha256") != record_set.get(
            "payload_sha256"
        ):
            raise ValueError("review manifest is not bound to the proposed record set")
        review_id = str(manifest["review_id"])
        # Repeated or conflicting manifests for the same record are not a hard
        # error; they fail closed as a typed duplicate_review exception below.
        reviews.setdefault(str(manifest["record_id"]), []).append(manifest)
        review_index.append(
            {
                "review_id": review_id,
                "record_id": str(manifest["record_id"]),
                "content_sha256": manifest_sha,
            }
        )

    observed_at = parse_datetime(
        record_set["scope"]["observed_at"], "record set observed_at"
    )

    # Phase A: denominator and policy gates.
    denominator_ok = evaluate_denominator(record_set, policy, decisions)
    policy_ok = evaluate_policy_binding(
        record_set, policy, policy_sha, observed_at, contracts, decisions
    )

    # Capture exact predecessor record bytes for successor assembly.
    global _PREDECESSOR_RECORDS
    _PREDECESSOR_RECORDS = {}
    record_by_id: dict[str, Mapping[str, Any]] = {}
    record_content_sha: dict[str, str] = {}
    expected_names = {
        entry["path"].rsplit("/", 1)[-1] for entry in record_set["records"]
    }
    resolved_records_dir = resolve_under_root(repo_root, records_dir)
    _verify_records_directory(resolved_records_dir, expected_names, decisions)
    for entry in record_set["records"]:
        name = entry["path"].rsplit("/", 1)[-1]
        record_path = resolved_records_dir / name
        record_obj, content_sha, identity = capture_json(
            record_path, maximum=MAX_INPUT_BYTES, label=f"reviewed record {name}"
        )
        captured.append((record_path, MAX_INPUT_BYTES, content_sha, identity))
        record_id = str(entry["record_id"])
        record_by_id[record_id] = record_obj
        record_content_sha[record_id] = content_sha
        _PREDECESSOR_RECORDS[record_id] = record_obj
        if content_sha != entry.get("content_sha256") or identity.st_size != entry.get(
            "bytes"
        ):
            decisions.fail(
                code="record_tamper",
                scope="record",
                subject_kind="record",
                subject_id=record_id,
                message=f"record {name} content/size differs from the set manifest",
                next_action="restore the exact reviewed record bytes named by the set",
                evidence=[name, content_sha],
                requires_human=True,
                record_id=record_id,
            )

    policy_records = {str(item["record_id"]): item for item in policy["records"]}

    # Reviewer load (for reuse cap) across all accept manifests.
    reviewer_load: dict[str, int] = {}
    for manifests in reviews.values():
        for manifest in manifests:
            if manifest.get("decision") == "accept":
                identity = str(manifest.get("reviewer", {}).get("identity"))
                reviewer_load[identity] = reviewer_load.get(identity, 0) + 1

    accepted_records: dict[str, dict[str, Any]] = {}
    accepted_bytes: dict[str, bytes] = {}
    accepted_sha: dict[str, str] = {}
    # A tampered or path-swapped denominator is compromised: no successor may be
    # emitted from it, even for records that would otherwise pass.
    compromised = any(
        exception["code"] in {"record_tamper", "path_swap"}
        for exception in decisions.exceptions
    )
    denominator_acceptable = denominator_ok and policy_ok and not compromised

    for entry in record_set["records"]:
        record_id = str(entry["record_id"])
        record_obj = record_by_id[record_id]
        component = (
            record_obj.get("component")
            if isinstance(record_obj.get("component"), Mapping)
            else {}
        )
        decision = decisions.decision(record_id, str(component.get("component_id")))
        record_policy = policy_records.get(record_id)
        if record_policy is None:
            decisions.gate(record_id, "submitted", "skip")
            continue
        decisions.gate(record_id, "submitted", "pass")
        manifests = reviews.get(record_id, [])
        review_manifest: dict[str, Any] | None
        if len(manifests) > 1:
            decisions.gate(record_id, "review_unique", "fail")
            decisions.fail(
                code="duplicate_review",
                scope="review",
                subject_kind="record",
                subject_id=record_id,
                message="more than one independent review manifest names this record",
                next_action="supply exactly one independent review manifest per record",
                evidence=[record_id],
                requires_human=True,
                record_id=record_id,
            )
            review_manifest = None
        else:
            decisions.gate(record_id, "review_unique", "pass")
            review_manifest = manifests[0] if manifests else None
        if record_content_sha[record_id] != entry.get("content_sha256"):
            # A tampered record cannot be accepted regardless of other gates.
            continue
        accepted = evaluate_record(
            record=record_obj,
            record_entry=entry,
            record_content_sha256=record_content_sha[record_id],
            record_policy=record_policy,
            review_manifest=review_manifest,
            reviewer_load=reviewer_load,
            policy=policy,
            observed_at=observed_at,
            contracts=contracts,
            decisions=decisions,
        )
        if accepted is not None and denominator_acceptable:
            accepted_records[record_id] = accepted
            accepted_bytes[record_id] = base.output_bytes(accepted)
            accepted_sha[record_id] = base.sha256_bytes(accepted_bytes[record_id])
        elif accepted is not None and not denominator_acceptable:
            decisions.decision(record_id, str(component.get("component_id")))[
                "accepted"
            ] = False
            decisions.fail(
                code="denominator_incomplete",
                scope="record",
                subject_kind="record",
                subject_id=record_id,
                message="record passes but the denominator is not accepted",
                next_action="accept the complete denominator before any record",
                evidence=[record_id],
                requires_human=True,
                record_id=record_id,
            )

    successor_set: dict[str, Any] | None = None
    if accepted_records and denominator_acceptable:
        successor_set = build_successor_set(
            record_set, accepted_records, accepted_bytes, accepted_sha
        )

    outcome = build_outcome(
        record_set=record_set,
        policy=policy,
        review_index=review_index,
        decisions=decisions,
        successor_set=successor_set,
        accepted_bytes=accepted_bytes,
        accepted_sha=accepted_sha,
        accepted_records=accepted_records,
        contracts=contracts,
    )
    base.validate_schema(contracts["outcome_validator"], outcome, "acceptance outcome")

    outputs = {record_id: accepted_bytes[record_id] for record_id in accepted_records}
    return outcome, outputs, successor_set, captured


def _verify_records_directory(
    records_dir: Path, expected: set[str], decisions: Decisions
) -> None:
    directory_fd, _ = base.open_directory_no_follow(
        records_dir, "reviewed records directory"
    )
    observed: set[str] = set()
    try:
        with os.scandir(directory_fd) as iterator:
            for item in iterator:
                observed.add(item.name)
    finally:
        os.close(directory_fd)
    if observed != expected:
        decisions.fail(
            code="path_swap",
            scope="set",
            subject_kind="records-directory",
            subject_id="knowledge/registry/records",
            message="records directory differs from the exact set denominator "
            f"(missing={sorted(expected - observed)}, extra={sorted(observed - expected)})",
            next_action="restore the exact set-referenced record files",
            evidence=[",".join(sorted(observed)) or "empty"],
            requires_human=True,
        )


def build_outcome(
    *,
    record_set: Mapping[str, Any],
    policy: Mapping[str, Any],
    review_index: Sequence[Mapping[str, Any]],
    decisions: Decisions,
    successor_set: Mapping[str, Any] | None,
    accepted_bytes: Mapping[str, bytes],
    accepted_sha: Mapping[str, str],
    accepted_records: Mapping[str, Mapping[str, Any]],
    contracts: Mapping[str, Any],
) -> dict[str, Any]:
    hashes = contracts["hashes"]
    entry_by_id = {entry["record_id"]: entry for entry in record_set["records"]}
    successor_records = []
    successor_id = None
    successor_payload = None
    if successor_set is not None:
        successor_id = successor_set["record_set_id"]
        successor_payload = successor_set["payload_sha256"]
        for record_id in sorted(accepted_records):
            entry = entry_by_id[record_id]
            successor_records.append(
                {
                    "record_id": record_id,
                    "component_id": entry["component_id"],
                    "path": entry["path"],
                    "content_sha256": accepted_sha[record_id],
                    "bytes": len(accepted_bytes[record_id]),
                }
            )
    decisions_list = [
        {
            "record_id": item["record_id"],
            "component_id": item["component_id"],
            "accepted": item["accepted"],
            "gates": item["gates"],
            "exception_codes": item["exception_codes"],
        }
        for item in sorted(
            decisions.records.values(), key=lambda entry: entry["record_id"]
        )
    ]
    retained = sum(
        item.get("retained_residual_gaps", 0) for item in decisions.records.values()
    )
    document = {
        "$schema": "./schemas/source-acceptance-outcome.schema.json",
        "schema_version": SCHEMA_VERSION,
        "outcome_kind": "source_acceptance_outcome",
        "outcome_id": "source-acceptance-outcome:" + "0" * 64,
        "payload_sha256": "sha256:" + "0" * 64,
        "authority": {
            "authoritative": False,
            "admits_retrieval": False,
            "mutates_pointers": False,
            "signs_production": False,
            "compile_eligible": False,
            "promote_eligible": False,
        },
        "generator": {
            "name": GENERATOR,
            "version": GENERATOR_VERSION,
            "source": GENERATOR_SOURCE,
            "source_sha256": hashes["source_sha256"],
            "base_materializer_sha256": hashes["base_materializer_sha256"],
            "component_schema_sha256": hashes["component_schema_sha256"],
            "record_set_schema_sha256": hashes["record_set_schema_sha256"],
            "policy_schema_sha256": hashes["policy_schema_sha256"],
            "review_manifest_schema_sha256": hashes["review_manifest_schema_sha256"],
            "outcome_schema_sha256": hashes["outcome_schema_sha256"],
            "requirements_sha256": hashes["requirements_sha256"],
            "validator_dependencies": contracts["dependencies"],
        },
        "inputs": {
            "record_set_id": record_set["record_set_id"],
            "record_set_payload_sha256": record_set["payload_sha256"],
            "policy_id": policy["policy_id"],
            "policy_payload_sha256": policy["payload_sha256"],
            "review_manifests": sorted(
                (dict(item) for item in review_index),
                key=lambda item: (item["record_id"], item["review_id"]),
            ),
        },
        "predecessor": {
            "record_set_id": record_set["record_set_id"],
            "payload_sha256": record_set["payload_sha256"],
        },
        "successor": {
            "record_set_id": successor_id,
            "payload_sha256": successor_payload,
            "records": successor_records,
        },
        "decisions": decisions_list,
        "exception_queue": decisions.exceptions,
        "counts": {
            "records": len(record_set["records"]),
            "accepted_records": len(accepted_records),
            "exceptions": len(decisions.exceptions),
            "blocking_gaps_retained": retained,
        },
    }
    return content_addressed(document, "source-acceptance-outcome:", "outcome_id")


# --------------------------------------------------------------------------
# Bounded, no-follow output commit (below .workingdir2/)
# --------------------------------------------------------------------------
def validate_output_separation(output_dir: Path, protected: Sequence[Path]) -> None:
    if not protected:
        raise ValueError("acceptance output requires exact protected inputs")
    output = base.normalized_absolute(output_dir, "acceptance output")
    for index, path in enumerate(protected):
        candidate = base.normalized_absolute(path, f"protected input {index}")
        if (
            output == candidate
            or output in candidate.parents
            or candidate in output.parents
        ):
            raise ValueError("acceptance output overlaps a retained input/source path")


def write_bundle(
    repo_root: Path,
    output_dir: Path,
    outcome: Mapping[str, Any],
    accepted_bytes: Mapping[str, bytes],
    successor_set: Mapping[str, Any] | None,
    record_names: Mapping[str, str],
    protected: Sequence[Path],
) -> None:
    validate_output_separation(output_dir, protected)
    outcome_raw = base.output_bytes(outcome)
    output_fd, output_info = base.open_scratch_directory(repo_root, output_dir)
    try:
        base.write_exact(output_fd, "source-acceptance-outcome.json", outcome_raw)
        top_entries = {"source-acceptance-outcome.json"}
        if successor_set is not None:
            try:
                os.mkdir("accepted-records", 0o755, dir_fd=output_fd)
            except FileExistsError:
                pass
            records_fd = os.open(
                "accepted-records",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=output_fd,
            )
            records_info = os.fstat(records_fd)
            try:
                names = set()
                for record_id, raw in sorted(accepted_bytes.items()):
                    name = record_names[record_id]
                    base.write_exact(records_fd, name, raw)
                    names.add(name)
                base.verify_exact_directory_entries(
                    records_fd, names, "acceptance records directory"
                )
                base.verify_directory_path(
                    output_dir / "accepted-records",
                    records_info,
                    "acceptance records directory",
                )
            finally:
                os.close(records_fd)
            base.write_exact(
                output_fd,
                "accepted-reviewed-record-set.json",
                base.output_bytes(successor_set),
            )
            top_entries |= {"accepted-records", "accepted-reviewed-record-set.json"}
        base.verify_exact_directory_entries(
            output_fd, top_entries, "acceptance output directory"
        )
        base.verify_directory_path(
            output_dir, output_info, "acceptance output directory"
        )
    finally:
        os.close(output_fd)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("materialize",))
    parser.add_argument("--record-set", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--review", type=Path, action="append", default=[])
    parser.add_argument("--reviews-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def collect_review_paths(repo_root: Path, args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = [resolve_under_root(repo_root, path) for path in args.review]
    if args.reviews_dir is not None:
        directory = resolve_under_root(repo_root, args.reviews_dir)
        directory_fd, _ = base.open_directory_no_follow(directory, "reviews directory")
        names: list[str] = []
        try:
            with os.scandir(directory_fd) as iterator:
                for item in iterator:
                    if item.name.endswith(".json"):
                        names.append(item.name)
        finally:
            os.close(directory_fd)
        paths.extend(directory / name for name in sorted(names))
    if len(paths) > MAX_REVIEW_MANIFESTS:
        raise ValueError("too many review manifests supplied")
    # De-duplicate identical absolute paths deterministically.
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = os.path.abspath(os.fspath(path))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        repo_root = Path(__file__).resolve().parents[2]
        output_dir = resolve_under_root(repo_root, args.output_dir)
        review_paths = collect_review_paths(repo_root, args)
        outcome, accepted_bytes, successor_set, captured = materialize(
            repo_root,
            resolve_under_root(repo_root, args.record_set),
            resolve_under_root(repo_root, args.records),
            resolve_under_root(repo_root, args.policy),
            review_paths,
        )
        record_names = {
            record["record_id"]: record["path"].rsplit("/", 1)[-1]
            for record in outcome["successor"]["records"]
        }
        write_bundle(
            repo_root,
            output_dir,
            outcome,
            accepted_bytes,
            successor_set,
            record_names,
            [path for path, _maximum, _digest, _identity in captured],
        )
        for path, maximum, digest, identity in captured:
            base.recheck_regular(
                path,
                maximum=maximum,
                expected_sha256=digest,
                expected_identity=identity,
                label=f"captured input {path.name}",
            )
        sys.stdout.write(
            json.dumps(
                {
                    "outcome_id": outcome["outcome_id"],
                    "records": outcome["counts"]["records"],
                    "accepted_records": outcome["counts"]["accepted_records"],
                    "exceptions": outcome["counts"]["exceptions"],
                    "successor_record_set_id": outcome["successor"]["record_set_id"],
                    "output_dir": base.repository_relative(repo_root, output_dir),
                },
                sort_keys=True,
            )
            + "\n"
        )
        if args.require_complete and (
            outcome["counts"]["exceptions"] > 0
            or outcome["counts"]["accepted_records"] != outcome["counts"]["records"]
        ):
            return 1
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"Source acceptance materialization failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
