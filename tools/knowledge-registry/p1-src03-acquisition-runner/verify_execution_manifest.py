#!/usr/bin/env python3
"""Independently verify the P1-SRC-03 expected execution-byte manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

TREE_FORMAT = "type-nul-path-nul-mode-nul-size-nul-content-nul-v1"
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
MAX_MANIFEST_BYTES = 128 * 1024
MAX_GOROOT_ENTRY_BYTES = 64 * 1024 * 1024
MAX_GO_BINARY_BYTES = 32 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 10_000_000
SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
EXPECTED_ARTIFACTS = {
    "knowledge/registry/schemas/source-acquisition-contract-v2.schema.json": "schema",
    "knowledge/registry/schemas/source-acquisition-execution-manifest-v1.schema.json": "schema",
    "knowledge/registry/schemas/source-acquisition-output-common-v2.schema.json": "schema",
    "knowledge/registry/schemas/source-acquisition-receipt-v2.schema.json": "schema",
    "knowledge/registry/schemas/source-inventory-proposal-v2.schema.json": "schema",
    "testdata/canonical-json/v1/vectors.json": "canonical_vectors",
    "tools/knowledge-registry/p1-src03-acquisition-runner/contract.go": "runner_source",
    "tools/knowledge-registry/p1-src03-acquisition-runner/execution_manifest.go": "runner_source",
    "tools/knowledge-registry/p1-src03-acquisition-runner/go.mod": "module_definition",
    "tools/knowledge-registry/p1-src03-acquisition-runner/main.go": "runner_source",
    "tools/knowledge-registry/p1-src03-acquisition-runner/runner.go": "runner_source",
    "tools/knowledge-registry/p1-src03-acquisition-runner/store.go": "runner_source",
    "tools/knowledge-registry/p1-src03-acquisition-runner/verify_execution_manifest.py": "execution_verifier",
}
EXPECTED_TOOLCHAIN = {
    "go_version": "go1.26.5-X:nodwarf5",
    "goos": "linux",
    "goarch": "amd64",
    "goamd64": "v1",
    "binary_path": "/usr/lib/go/bin/go",
    "binary_sha256": "sha256:24ede1c93e3882e0b105ff45228e7258d36a4ab3ebabf39580e28668de683696",
}
EXPECTED_DEPENDENCIES = {
    "module_mode": "go_mod_no_external_modules",
    "external_modules": [],
    "standard_library": "go1.26.5-X:nodwarf5",
    "goroot_path": "/usr/lib/go",
    "goroot_tree_format": TREE_FORMAT,
    "goroot_tree_sha256": "sha256:843de40ce8db6950451b47ebcf080317e400be1be18a99ef23c4b5512117db8b",
    "goroot_tree_entries": 16671,
    "goroot_logical_bytes": 225627376,
}


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON token: {value}")


def validate_json(value: Any) -> None:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON exceeds maximum node count")
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON exceeds maximum depth")
        if isinstance(current, dict):
            for key in current:
                key.encode("utf-8")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            current.encode("utf-8")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite JSON number")
        elif (
            isinstance(current, int)
            and not isinstance(current, bool)
            and not INT64_MIN <= current <= INT64_MAX
        ):
            raise ValueError("JSON integer is outside signed 64-bit range")


def load_strict(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = read_stable_regular(path, MAX_MANIFEST_BYTES, "execution manifest")
    if not raw:
        raise ValueError("execution manifest is empty or exceeds its byte bound")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )
    validate_json(value)
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value, raw


def canonical(value: Any) -> bytes:
    validate_json(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def stat_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_stable_regular(path: Path, maximum: int, label: str) -> bytes:
    path_before = path.lstat()
    if (
        not stat.S_ISREG(path_before.st_mode)
        or stat.S_ISLNK(path_before.st_mode)
        or path_before.st_nlink != 1
        or path_before.st_size > maximum
    ):
        raise ValueError(f"{label} is not a bounded single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        held_before = os.fstat(descriptor)
        if stat_fingerprint(path_before) != stat_fingerprint(held_before):
            raise ValueError(f"{label} changed while it was opened")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError(f"{label} exceeds its byte bound")
        held_after = os.fstat(descriptor)
        path_after = path.lstat()
        if stat_fingerprint(held_before) != stat_fingerprint(
            held_after
        ) or stat_fingerprint(held_after) != stat_fingerprint(path_after):
            raise ValueError(f"{label} changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def validate_manifest_semantics(manifest: dict[str, Any]) -> None:
    expected_keys = {
        "$schema",
        "artifacts",
        "authority_state",
        "canonicalization",
        "dependencies",
        "execution_eligible",
        "manifest_id",
        "manifest_kind",
        "manifest_payload_sha256",
        "schema_version",
        "toolchain",
        "verification_state",
    }
    if set(manifest) != expected_keys:
        raise ValueError("execution manifest fields differ from the exact contract")
    expected_scalars = {
        "$schema": "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-execution-manifest-v1.schema.json",
        "authority_state": "non_authoritative",
        "canonicalization": "registry_compact_utf8",
        "execution_eligible": False,
        "manifest_kind": "p1_src03_runner_execution_byte_manifest",
        "schema_version": "1.0.0",
        "verification_state": "expected_bytes_unverified",
    }
    for key, expected in expected_scalars.items():
        if manifest[key] != expected or type(manifest[key]) is not type(expected):
            raise ValueError(
                f"execution manifest {key} differs from the exact contract"
            )
    if manifest["toolchain"] != EXPECTED_TOOLCHAIN:
        raise ValueError("execution manifest toolchain tuple differs")
    if manifest["dependencies"] != EXPECTED_DEPENDENCIES:
        raise ValueError("execution manifest dependency closure differs")
    if not isinstance(manifest["manifest_id"], str) or not re.fullmatch(
        r"source-acquisition-execution-manifest:sha256:[a-f0-9]{64}",
        manifest["manifest_id"],
    ):
        raise ValueError("execution manifest ID is malformed")
    if not isinstance(
        manifest["manifest_payload_sha256"], str
    ) or not SHA256_PATTERN.fullmatch(manifest["manifest_payload_sha256"]):
        raise ValueError("execution manifest payload hash is malformed")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(EXPECTED_ARTIFACTS):
        raise ValueError("execution manifest artifact denominator differs")
    expected = sorted(EXPECTED_ARTIFACTS.items())
    for artifact, (path, role) in zip(artifacts, expected, strict=True):
        if not isinstance(artifact, dict) or set(artifact) != {
            "logical_path",
            "role",
            "sha256",
            "bytes",
        }:
            raise ValueError("execution manifest artifact fields differ")
        if artifact["logical_path"] != path or artifact["role"] != role:
            raise ValueError("execution manifest artifact path or role differs")
        if not isinstance(artifact["sha256"], str) or not SHA256_PATTERN.fullmatch(
            artifact["sha256"]
        ):
            raise ValueError("execution manifest artifact hash is malformed")
        if (
            type(artifact["bytes"]) is not int
            or artifact["bytes"] < 1
            or artifact["bytes"] > 1024 * 1024
        ):
            raise ValueError("execution manifest artifact byte count is invalid")


def verify_manifest_identity(manifest: dict[str, Any], raw: bytes) -> None:
    validate_manifest_semantics(manifest)
    if canonical(manifest) + b"\n" != raw:
        raise ValueError("execution manifest bytes are not canonical")
    core = {
        key: value
        for key, value in manifest.items()
        if key not in {"manifest_id", "manifest_payload_sha256"}
    }
    payload_sha = sha256(canonical(core))
    if manifest.get("manifest_payload_sha256") != payload_sha:
        raise ValueError("execution manifest payload hash is invalid")
    if (
        manifest.get("manifest_id")
        != "source-acquisition-execution-manifest:" + payload_sha
    ):
        raise ValueError("execution manifest ID is invalid")


def verify_repository_artifacts(root: Path, manifest: dict[str, Any]) -> None:
    for artifact in manifest["artifacts"]:
        relative = artifact["logical_path"]
        path = root / relative
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"unsafe artifact path: {relative}")
        raw = read_stable_regular(path, 1024 * 1024, f"artifact {relative}")
        if artifact["bytes"] != len(raw) or artifact["sha256"] != sha256(raw):
            raise ValueError(f"artifact bytes differ from manifest: {relative}")


def goroot_tree(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    entries = 0
    logical_bytes = 0
    root_before = root.lstat()
    paths = sorted(
        root.rglob("*"),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    for path in paths:
        before = path.lstat()
        relative = path.relative_to(root).as_posix().encode("utf-8")
        mode = stat.S_IMODE(before.st_mode)
        if stat.S_ISDIR(before.st_mode):
            kind, body = b"d", b""
        elif stat.S_ISREG(before.st_mode):
            kind = b"f"
            body = read_stable_regular(
                path, MAX_GOROOT_ENTRY_BYTES, f"GOROOT file {relative!r}"
            )
        elif stat.S_ISLNK(before.st_mode):
            kind, body = b"l", os.readlink(path).encode("utf-8")
        else:
            raise ValueError(f"unsupported GOROOT object: {path}")
        after = path.lstat()
        if stat_fingerprint(before) != stat_fingerprint(after):
            raise ValueError(f"GOROOT object changed while read: {path}")
        digest.update(
            kind
            + b"\0"
            + relative
            + b"\0"
            + format(mode, "04o").encode()
            + b"\0"
            + str(len(body)).encode()
            + b"\0"
            + body
            + b"\0"
        )
        entries += 1
        logical_bytes += len(body)
    replayed = sorted(
        root.rglob("*"),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    if [path.relative_to(root).as_posix() for path in paths] != [
        path.relative_to(root).as_posix() for path in replayed
    ] or stat_fingerprint(root_before) != stat_fingerprint(root.lstat()):
        raise ValueError("GOROOT tree changed while it was enumerated")
    return "sha256:" + digest.hexdigest(), entries, logical_bytes


def verify_toolchain(manifest: dict[str, Any], go_binary: Path) -> None:
    toolchain = manifest["toolchain"]
    dependencies = manifest["dependencies"]
    if go_binary != Path(toolchain["binary_path"]):
        raise ValueError("Go launcher path differs from manifest")
    descriptor = os.open(
        go_binary,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Go launcher is not a regular non-symlink file")
        if before.st_nlink != 1 or before.st_size > MAX_GO_BINARY_BYTES:
            raise ValueError("Go launcher is not a bounded single-link file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(MAX_GO_BINARY_BYTES + 1)
        if len(raw) > MAX_GO_BINARY_BYTES:
            raise ValueError("Go launcher exceeds its byte bound")
        if sha256(raw) != toolchain["binary_sha256"]:
            raise ValueError("Go launcher bytes differ from manifest")
        environment = {
            "CGO_ENABLED": "0",
            "GOENV": "off",
            "GOTOOLCHAIN": "local",
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "PATH": "/usr/bin:/bin",
        }
        completed = subprocess.run(
            [
                f"/proc/self/fd/{descriptor}",
                "env",
                "GOVERSION",
                "GOOS",
                "GOARCH",
                "GOAMD64",
                "GOROOT",
            ],
            check=True,
            env=environment,
            pass_fds=(descriptor,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        actual = completed.stdout.splitlines()
        expected = [
            toolchain["go_version"],
            toolchain["goos"],
            toolchain["goarch"],
            toolchain["goamd64"],
            dependencies["goroot_path"],
        ]
        if actual != expected:
            raise ValueError(f"Go toolchain tuple differs: {actual!r}")
        if dependencies["goroot_tree_format"] != TREE_FORMAT:
            raise ValueError("unknown GOROOT tree digest format")
        tree = goroot_tree(Path(dependencies["goroot_path"]))
        wanted = (
            dependencies["goroot_tree_sha256"],
            dependencies["goroot_tree_entries"],
            dependencies["goroot_logical_bytes"],
        )
        if tree != wanted:
            raise ValueError(f"GOROOT byte tree differs: {tree!r}")
        after = os.fstat(descriptor)
        if stat_fingerprint(before) != stat_fingerprint(after):
            raise ValueError("Go launcher changed during exact verification")
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--go-binary", type=Path, default=Path("/usr/lib/go/bin/go"))
    parser.add_argument("--repository-only", action="store_true")
    arguments = parser.parse_args()

    root = arguments.repository_root.resolve(strict=True)
    manifest, raw = load_strict(arguments.manifest)
    verify_manifest_identity(manifest, raw)
    verify_repository_artifacts(root, manifest)
    if not arguments.repository_only:
        verify_toolchain(manifest, arguments.go_binary)
    result = {
        "execution_manifest_id": manifest["manifest_id"],
        "external_exact_byte_verification": not arguments.repository_only,
        "predecessor_eligible": False,
        "repository_bytes_verified": True,
        "toolchain_bytes_verified": not arguments.repository_only,
    }
    print(canonical(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
