#!/usr/bin/env python3
"""Capture the fixed read-only live surface for knowledge-registry import."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

import knowledge_registry as kr

_LOADED_MODULE_CODE = sys._getframe().f_code

MAX_LIVE_ARTIFACT_BYTES = kr.LIVE_CAPTURE_BOUNDS["artifact_bytes"]
MAX_LIVE_CAPTURE_BYTES = kr.LIVE_CAPTURE_BOUNDS["capture_bytes"]
MAX_LIVE_LIST_ITEMS = kr.LIVE_CAPTURE_BOUNDS["list_items"]
MAX_DYNAMIC_QUERIES = kr.LIVE_CAPTURE_BOUNDS["dynamic_queries"]
MAX_KUBECONFIG_BYTES = 4 * 2**20
MAX_LIVE_STDERR_BYTES = 64 * 2**10
MAX_LIVE_CAPTURE_SECONDS = kr.LIVE_CAPTURE_BOUNDS["capture_seconds"]
FIXED_KUBECTL_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
}


@dataclass(frozen=True)
class Query:
    surface: str
    filename: str
    args: tuple[str, ...]
    expected_kind: str | None = None
    response_type: str = "typed-list"


QUERIES = (
    Query(
        "server-version",
        "server-version.json",
        ("version", "-o", "json"),
        response_type="server-version",
    ),
    Query("nodes", "nodes.json", ("get", "--raw", "/api/v1/nodes"), "Node"),
    Query(
        "argo",
        "applications.json",
        ("get", "--raw", "/apis/argoproj.io/v1alpha1/applications"),
        "Application",
    ),
    Query(
        "argo",
        "applicationsets.json",
        ("get", "--raw", "/apis/argoproj.io/v1alpha1/applicationsets"),
        "ApplicationSet",
    ),
    Query(
        "controllers",
        "cronjobs.json",
        ("get", "--raw", "/apis/batch/v1/cronjobs"),
        "CronJob",
    ),
    Query(
        "controllers",
        "daemonsets.json",
        ("get", "--raw", "/apis/apps/v1/daemonsets"),
        "DaemonSet",
    ),
    Query(
        "controllers",
        "deployments.json",
        ("get", "--raw", "/apis/apps/v1/deployments"),
        "Deployment",
    ),
    Query(
        "controllers",
        "jobs.json",
        ("get", "--raw", "/apis/batch/v1/jobs"),
        "Job",
    ),
    Query(
        "controllers",
        "replicasets.json",
        ("get", "--raw", "/apis/apps/v1/replicasets"),
        "ReplicaSet",
    ),
    Query(
        "controllers",
        "statefulsets.json",
        ("get", "--raw", "/apis/apps/v1/statefulsets"),
        "StatefulSet",
    ),
    Query("pods", "pods.json", ("get", "--raw", "/api/v1/pods"), "Pod"),
    Query(
        "crds-openapi",
        "crds.json",
        ("get", "--raw", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"),
        "CustomResourceDefinition",
    ),
    Query(
        "workload-sboms",
        "namespaces.json",
        ("get", "--raw", kr.LIVE_NAMESPACE_INDEX_ENDPOINT),
        "Namespace",
    ),
    Query(
        "cluster-sboms",
        "clustersbomreports.json",
        (
            "get",
            "--raw",
            "/apis/aquasecurity.github.io/v1alpha1/clustersbomreports",
        ),
        "ClusterSbomReport",
    ),
    Query(
        "api-discovery",
        "api-versions.json",
        ("get", "--raw", "/api"),
        "APIVersions",
        "typed-object",
    ),
    Query(
        "api-discovery",
        "api-groups.json",
        ("get", "--raw", "/apis"),
        "APIGroupList",
        "typed-object",
    ),
    Query(
        "builtin-openapi",
        "openapi-v3-index.json",
        ("get", "--raw", "/openapi/v3"),
        "OpenAPIv3Discovery",
        "openapi-index",
    ),
)

Runner = Callable[..., subprocess.Popen[bytes]]
# api-discovery, builtin-openapi and the namespace-paged workload-sboms surface.
MAX_LIVE_CAPTURE_COMMANDS = len(QUERIES) + (3 * MAX_DYNAMIC_QUERIES) + 2
if MAX_LIVE_CAPTURE_COMMANDS != kr.LIVE_CAPTURE_BOUNDS["capture_commands"]:
    raise RuntimeError("live capture command contract is out of sync")

FORBIDDEN_KUBECONFIG_KEYS = {
    "auth-provider",
    "certificate-authority",
    "client-certificate",
    "client-key",
    "exec",
    "insecure-skip-tls-verify",
    "proxy-url",
    "token-file",
    "tokenfile",
}
REQUIRED_KUBECONFIG_KEYS = {
    "apiVersion",
    "kind",
    "clusters",
    "contexts",
    "current-context",
    "users",
}
FORBIDDEN_PERSISTED_KEYS = {
    "args",
    "command",
    "data",
    "env",
    "envFrom",
    "stringData",
}
SENSITIVE_PERSISTED_KEY_RE = re.compile(
    r"(?:^|[-_.])(?:password|private[-_.]?key|secret|token)(?:$|[-_.])",
    re.IGNORECASE,
)
MAX_OPENAPI_GVKS_PER_SCHEMA = 256
KUBECONFIG_MAPPING_LINE_RE = re.compile(
    r"^(?P<indent> *)(?P<item>- )?(?P<key>[A-Za-z][A-Za-z0-9-]*):"
    r"(?: (?P<value>.*))?$"
)


def utc_second(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def capture_generator_identity(
    expected_commit: str,
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    """Bind the exact clean committed redaction/generation implementation."""

    repository = (root or Path(__file__).resolve().parents[2]).absolute()
    _files, tracked, snapshot = kr.repository_snapshot(repository)
    head_commit = str(snapshot["head_commit"])
    if head_commit != expected_commit.lower():
        raise RuntimeError("claimed git commit does not match the clean capture source")
    sources: list[dict[str, Any]] = []
    source_bytes: dict[str, bytes] = {}
    for relative in kr.LIVE_CAPTURE_GENERATOR_PATHS:
        if relative not in tracked:
            raise RuntimeError("capture generator source is not committed")
        raw = kr.read_regular_file(
            repository / relative,
            max_bytes=kr.MAX_DISCOVERY_FILE_BYTES,
            label=f"capture generator source {relative}",
        )
        source_bytes[relative] = raw
        sources.append(
            {
                "path": relative,
                "sha256": kr.file_hash(raw),
                "size": len(raw),
            }
        )
    kr.verify_loaded_python_module_source(
        source_bytes["tools/knowledge-registry/capture_live.py"],
        Path(__file__).as_posix(),
        globals(),
        __name__,
        constant_evaluation_globals={"kr": kr, "Query": Query, "len": len},
        require_all_constants=True,
    )
    kr.verify_loaded_registry_source(
        source_bytes["tools/knowledge-registry/knowledge_registry.py"],
        Path(kr.__file__).as_posix(),
    )
    return {
        "git_commit": head_commit,
        "sources": sources,
        "ruleset_hash": kr.ruleset_hash_from_registry_source(
            source_bytes["tools/knowledge-registry/knowledge_registry.py"],
            "tools/knowledge-registry/knowledge_registry.py",
        ),
    }


def bounded_error(value: bytes | str, limit: int = 4096) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = value
    return " ".join(text.strip().split())[:limit] or "command failed"


def invoke(
    runner: Runner,
    command: Sequence[str],
    *,
    timeout: float,
    max_stdout_bytes: int = MAX_LIVE_ARTIFACT_BYTES,
    max_stderr_bytes: int = MAX_LIVE_STDERR_BYTES,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[bytes]:
    if timeout <= 0:
        raise RuntimeError("command timeout must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise RuntimeError("command stream bounds must be positive")
    try:
        process = runner(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=FIXED_KUBECTL_ENV,
            pass_fds=tuple(pass_fds),
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeError(f"command could not start: {exc}") from exc
    if process.stdout is None or process.stderr is None:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise RuntimeError("command runner did not expose bounded output pipes")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    limits = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"command timed out after {timeout:g}s")
            events = selector.select(remaining)
            if not events:
                raise RuntimeError(f"command timed out after {timeout:g}s")
            for key, _ in events:
                stream_name = str(key.data)
                chunk = os.read(key.fileobj.fileno(), 64 * 2**10)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffers[stream_name].extend(chunk)
                if len(buffers[stream_name]) > limits[stream_name]:
                    raise RuntimeError(
                        f"command {stream_name} exceeds byte bound "
                        f"{limits[stream_name]}"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"command timed out after {timeout:g}s")
        returncode = process.wait(timeout=remaining)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                process.kill()
        process.wait()
        if isinstance(exc, subprocess.TimeoutExpired):
            raise RuntimeError(f"command timed out after {timeout:g}s") from exc
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        list(command),
        returncode,
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
    )


def kubectl_command(
    kubectl: str,
    kubeconfig: str,
    context: str,
    args: Sequence[str],
) -> list[str]:
    command = [kubectl, "--kubeconfig", kubeconfig]
    if context:
        command.extend(("--context", context))
    command.extend(args)
    return command


def _reject_kubeconfig_external_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_KUBECONFIG_KEYS:
                raise ValueError(
                    "kubeconfig must use inline credentials and must not invoke "
                    "credential plugins"
                )
            _reject_kubeconfig_external_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_kubeconfig_external_keys(nested)


def _validate_kubeconfig_root(value: Mapping[str, Any]) -> None:
    missing = sorted(REQUIRED_KUBECONFIG_KEYS - set(value))
    if missing:
        raise ValueError(
            "kubeconfig omits required structural keys: " + ", ".join(missing)
        )
    if value.get("apiVersion") != "v1" or value.get("kind") != "Config":
        raise ValueError("kubeconfig must be a Kubernetes v1 Config")
    for key in ("clusters", "contexts", "users"):
        if not isinstance(value.get(key), list):
            raise ValueError(f"kubeconfig {key} must be an array")
    if not isinstance(value.get("current-context"), str) or not value.get(
        "current-context"
    ):
        raise ValueError("kubeconfig current-context must be a non-empty string")
    for cluster_entry in value.get("clusters", []):
        cluster = (
            cluster_entry.get("cluster") if isinstance(cluster_entry, Mapping) else None
        )
        server = (
            str(cluster.get("server") or "") if isinstance(cluster, Mapping) else ""
        )
        try:
            parsed = urlsplit(server)
        except ValueError as exc:
            raise ValueError(
                "kubeconfig cluster server must be a valid HTTPS URL"
            ) from exc
        if (
            not kr.strict_uri_reference(server, require_scheme=True)
            or parsed.scheme.lower() != "https"
            or not parsed.hostname
        ):
            raise ValueError("kubeconfig cluster server must be a valid HTTPS URL")


def validate_kubeconfig_structure(raw: bytes, text: str) -> None:
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            value = kr.parse_json_bytes(
                raw,
                label="kubeconfig JSON",
                max_bytes=MAX_KUBECONFIG_BYTES,
            )
        except kr.RegistryInputError as exc:
            raise ValueError(f"unsupported kubeconfig flow syntax: {exc}") from exc
        if not isinstance(value, Mapping):
            raise ValueError("kubeconfig JSON must be an object")
        _reject_kubeconfig_external_keys(value)
        _validate_kubeconfig_root(value)
        return

    top_level: dict[str, str] = {}
    current_top_level: str | None = None
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        if stripped_line == "---":
            continue
        if "\t" in line:
            raise ValueError("kubeconfig block YAML must not contain tabs")
        match = KUBECONFIG_MAPPING_LINE_RE.fullmatch(line)
        if not match:
            raise ValueError(
                f"unsupported kubeconfig YAML syntax at line {line_number}"
            )
        key = match.group("key")
        normalized_key = key.lower()
        if normalized_key in FORBIDDEN_KUBECONFIG_KEYS:
            raise ValueError(
                "kubeconfig must use inline credentials and must not invoke "
                "credential plugins"
            )
        value = (match.group("value") or "").strip()
        if value not in {"{}", "[]"} and any(
            marker in value for marker in ("{", "}", "[", "]")
        ):
            raise ValueError(
                f"unsupported kubeconfig flow syntax at line {line_number}"
            )
        if value.startswith(("|", ">", "&", "*", "!")):
            raise ValueError(
                f"unsupported kubeconfig YAML feature at line {line_number}"
            )
        if normalized_key == "server":
            server = kr.scalar(value)
            try:
                parsed = urlsplit(server)
            except ValueError as exc:
                raise ValueError(
                    "kubeconfig cluster server must be a valid HTTPS URL"
                ) from exc
            if (
                not kr.strict_uri_reference(server, require_scheme=True)
                or parsed.scheme.lower() != "https"
                or not parsed.hostname
            ):
                raise ValueError("kubeconfig cluster server must be a valid HTTPS URL")
        indent = len(match.group("indent"))
        if indent == 0:
            if match.group("item"):
                if current_top_level not in {"clusters", "contexts", "users"}:
                    raise ValueError("kubeconfig root must be a mapping")
                if top_level.get(current_top_level) not in {"", "[]"}:
                    raise ValueError(
                        f"kubeconfig {current_top_level} must be a block array"
                    )
                continue
            if key in top_level:
                raise ValueError(f"duplicate kubeconfig root key {key}")
            top_level[key] = kr.scalar(value)
            current_top_level = key
        elif indent > 0 and current_top_level is None:
            raise ValueError(
                f"kubeconfig has nested content without a root key at line {line_number}"
            )
    missing = sorted(REQUIRED_KUBECONFIG_KEYS - set(top_level))
    if missing:
        raise ValueError(
            "kubeconfig omits required structural keys: " + ", ".join(missing)
        )
    if top_level.get("apiVersion") != "v1" or top_level.get("kind") != "Config":
        raise ValueError("kubeconfig must be a Kubernetes v1 Config")
    for key in ("clusters", "contexts", "users"):
        if top_level.get(key) not in {"", "[]"}:
            raise ValueError(f"kubeconfig {key} must be a block array")
    if not top_level.get("current-context"):
        raise ValueError("kubeconfig current-context must be a non-empty string")


def read_validated_kubeconfig(path: Path) -> tuple[dict[str, Any], bytes]:
    absolute = path.absolute()
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise ValueError(f"cannot inspect kubeconfig {absolute}: {exc}") from exc
    if os.path.islink(absolute) or not os.path.isfile(absolute):
        raise ValueError("kubeconfig must be a regular non-symlink file")
    if metadata.st_uid not in {0, os.getuid()}:
        raise ValueError("kubeconfig must be owned by root or the capture user")
    if metadata.st_mode & 0o077:
        raise ValueError("kubeconfig must not grant group or other access")
    try:
        raw, bound_metadata = kr.read_regular_file_capture(
            absolute,
            max_bytes=MAX_KUBECONFIG_BYTES,
            label=f"kubeconfig {absolute}",
        )
        text = raw.decode("utf-8", errors="strict")
    except (UnicodeError, kr.RegistryInputError) as exc:
        raise ValueError(f"cannot safely bind kubeconfig {absolute}: {exc}") from exc
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ) != (
        bound_metadata.st_dev,
        bound_metadata.st_ino,
        bound_metadata.st_size,
        bound_metadata.st_mtime_ns,
        bound_metadata.st_ctime_ns,
    ):
        raise ValueError("kubeconfig changed before it could be bound")
    validate_kubeconfig_structure(raw, text)
    return (
        {
            "path": absolute.as_posix(),
            "sha256": kr.file_hash(raw),
            "size": len(raw),
            "device": bound_metadata.st_dev,
            "inode": bound_metadata.st_ino,
        },
        raw,
    )


def kubeconfig_identity(path: Path) -> dict[str, Any]:
    identity, _ = read_validated_kubeconfig(path)
    return identity


def sealed_kubeconfig_snapshot(path: Path) -> tuple[int, dict[str, Any]]:
    source_identity, raw = read_validated_kubeconfig(path)
    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    descriptor = os.memfd_create("knowledge-registry-kubeconfig", flags)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        observed_seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        if observed_seals & seals != seals:
            raise ValueError("cannot seal private kubeconfig snapshot")
        metadata = os.fstat(descriptor)
        snapshot_raw = os.pread(descriptor, len(raw) + 1, 0)
        if snapshot_raw != raw:
            raise ValueError("private kubeconfig snapshot identity mismatch")
        validate_kubeconfig_structure(snapshot_raw, snapshot_raw.decode("utf-8"))
        return descriptor, {
            "source": source_identity,
            "execution": {
                "path": f"/proc/self/fd/{descriptor}",
                "sha256": kr.file_hash(snapshot_raw),
                "size": len(snapshot_raw),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "policy": "sealed-memfd",
            },
        }
    except Exception:
        os.close(descriptor)
        raise


def verify_sealed_kubeconfig_snapshot(
    descriptor: int, expected: Mapping[str, Any]
) -> None:
    execution = expected.get("execution")
    if not isinstance(execution, Mapping):
        raise RuntimeError("sealed kubeconfig execution identity is missing")
    metadata = os.fstat(descriptor)
    raw = os.pread(descriptor, int(execution["size"]) + 1, 0)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    required_seals = (
        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    )
    if (
        len(raw) != execution.get("size")
        or kr.file_hash(raw) != execution.get("sha256")
        or metadata.st_dev != execution.get("device")
        or metadata.st_ino != execution.get("inode")
        or execution.get("policy") != "sealed-memfd"
        or seals & required_seals != required_seals
    ):
        raise RuntimeError("sealed kubeconfig snapshot changed during capture")


def command_json(
    runner: Runner,
    command: Sequence[str],
    *,
    timeout: float,
    pass_fds: Sequence[int] = (),
) -> tuple[Mapping[str, Any], bytes]:
    completed = invoke(runner, command, timeout=timeout, pass_fds=pass_fds)
    if completed.returncode != 0:
        raise RuntimeError("kubectl-command-failed")
    try:
        payload = kr.parse_json_bytes(
            completed.stdout,
            label="kubectl response",
            max_bytes=MAX_LIVE_ARTIFACT_BYTES,
        )
    except kr.RegistryInputError as exc:
        raise RuntimeError("kubectl-response-invalid-json") from exc
    if not isinstance(payload, Mapping):
        raise RuntimeError("command returned JSON but not an object")
    return payload, completed.stdout


TYPED_ITEM_API_VERSIONS = {
    "Application": "argoproj.io/v1alpha1",
    "ApplicationSet": "argoproj.io/v1alpha1",
    "ClusterSbomReport": "aquasecurity.github.io/v1alpha1",
    "CronJob": "batch/v1",
    "DaemonSet": "apps/v1",
    "Deployment": "apps/v1",
    "Job": "batch/v1",
    "Namespace": "v1",
    "Node": "v1",
    "Pod": "v1",
    "ReplicaSet": "apps/v1",
    "SbomReport": "aquasecurity.github.io/v1alpha1",
    "StatefulSet": "apps/v1",
    "CustomResourceDefinition": "apiextensions.k8s.io/v1",
}


def validate_query_payload(query: Query, payload: Mapping[str, Any]) -> None:
    truncation = kr.live_inventory_truncation(payload)
    if truncation:
        raise RuntimeError(f"truncated inventory: {truncation}")
    items = payload.get("items")
    if isinstance(items, list) and len(items) > MAX_LIVE_LIST_ITEMS:
        raise RuntimeError(f"inventory exceeds item bound {MAX_LIVE_LIST_ITEMS}")
    if query.response_type == "server-version":
        server = payload.get("serverVersion")
        if not isinstance(server, Mapping) or not server.get("gitVersion"):
            raise RuntimeError(
                "server version response has no serverVersion.gitVersion"
            )
        return
    if query.response_type == "typed-object":
        if payload.get("kind") != query.expected_kind:
            raise RuntimeError(f"expected a typed {query.expected_kind} response")
        return
    if query.response_type == "openapi-index":
        if not kr.is_openapi_v3_discovery(payload):
            raise RuntimeError("expected an OpenAPI v3 discovery response")
        paths = payload.get("paths")
        if not isinstance(paths, Mapping) or not paths:
            raise RuntimeError("OpenAPI v3 discovery response has no paths")
        return
    if query.response_type == "openapi-document":
        if not kr.is_openapi_v3_document(payload):
            raise RuntimeError("expected an OpenAPI v3 schema document")
        schemas = payload.get("components", {}).get("schemas", {})
        if not isinstance(schemas, Mapping) or not schemas:
            raise RuntimeError("OpenAPI v3 document has no component schemas")
        return
    if query.response_type == "api-resource-list":
        if payload.get("kind") != "APIResourceList" or not isinstance(
            payload.get("resources"), list
        ):
            raise RuntimeError("expected a typed APIResourceList response")
        return
    expected = f"{query.expected_kind}List"
    if payload.get("kind") != expected or not isinstance(payload.get("items"), list):
        raise RuntimeError(f"expected a typed {expected} response")
    expected_api_version = TYPED_ITEM_API_VERSIONS.get(str(query.expected_kind))
    if payload.get("apiVersion") != expected_api_version:
        raise RuntimeError(f"{expected} has a mismatched apiVersion")
    for item in payload["items"]:
        kind_present = isinstance(item, Mapping) and "kind" in item
        api_version_present = isinstance(item, Mapping) and "apiVersion" in item
        if (
            not isinstance(item, Mapping)
            or kind_present != api_version_present
            or (
                kind_present
                and (
                    item.get("kind") != query.expected_kind
                    or item.get("apiVersion") != expected_api_version
                )
            )
        ):
            raise RuntimeError(f"{expected} contains a mismatched typed item")


def safe_metadata(value: Any) -> dict[str, Any]:
    metadata = value if isinstance(value, Mapping) else {}
    result = {
        key: metadata[key]
        for key in (
            "name",
            "namespace",
            "uid",
            "resourceVersion",
            "generation",
            "creationTimestamp",
        )
        if key in metadata
    }
    owners = metadata.get("ownerReferences")
    if isinstance(owners, list):
        result["ownerReferences"] = [
            {
                key: owner[key]
                for key in (
                    "apiVersion",
                    "kind",
                    "name",
                    "uid",
                    "controller",
                    "blockOwnerDeletion",
                )
                if key in owner
            }
            for owner in owners
            if isinstance(owner, Mapping)
        ]
    return result


def safe_containers(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        {
            key: container[key]
            for key in ("name", "image", "imagePullPolicy")
            if key in container
        }
        for container in value
        if isinstance(container, Mapping) and container.get("image")
    ]


def safe_pod_spec(value: Any) -> dict[str, Any]:
    spec = value if isinstance(value, Mapping) else {}
    result: dict[str, Any] = {}
    for key in ("initContainers", "containers", "ephemeralContainers"):
        containers = safe_containers(spec.get(key))
        if containers:
            result[key] = containers
    for key in ("nodeName", "runtimeClassName", "serviceAccountName"):
        if key in spec:
            result[key] = spec[key]
    return result


def safe_container_statuses(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for status in value:
        if not isinstance(status, Mapping):
            continue
        projected: dict[str, Any] = {}
        for key in ("name", "image", "imageID", "ready", "restartCount"):
            if key not in status:
                continue
            field = status[key]
            if key in {"image", "imageID"}:
                if not isinstance(field, str):
                    raise RuntimeError(f"container status {key} must be a string")
                if field == "":
                    continue
            projected[key] = field
        result.append(projected)
    return result


def project_workload(item: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(item.get("kind") or "")
    result: dict[str, Any] = {
        "apiVersion": item.get("apiVersion"),
        "kind": kind,
        "metadata": safe_metadata(item.get("metadata")),
    }
    spec = item.get("spec") if isinstance(item.get("spec"), Mapping) else {}
    if kind == "Pod":
        result["spec"] = safe_pod_spec(spec)
    elif kind == "CronJob":
        job_template = (
            spec.get("jobTemplate")
            if isinstance(spec.get("jobTemplate"), Mapping)
            else {}
        )
        job_spec = (
            job_template.get("spec")
            if isinstance(job_template.get("spec"), Mapping)
            else {}
        )
        template = (
            job_spec.get("template")
            if isinstance(job_spec.get("template"), Mapping)
            else {}
        )
        result["spec"] = {
            "jobTemplate": {
                "spec": {"template": {"spec": safe_pod_spec(template.get("spec"))}}
            }
        }
    else:
        template = (
            spec.get("template") if isinstance(spec.get("template"), Mapping) else {}
        )
        result["spec"] = {"template": {"spec": safe_pod_spec(template.get("spec"))}}
    status = item.get("status") if isinstance(item.get("status"), Mapping) else {}
    safe_status = {
        key: status[key] for key in ("phase", "observedGeneration") if key in status
    }
    if kind == "Pod":
        for key in (
            "initContainerStatuses",
            "containerStatuses",
            "ephemeralContainerStatuses",
        ):
            statuses = safe_container_statuses(status.get(key))
            if statuses:
                safe_status[key] = statuses
    if safe_status:
        result["status"] = safe_status
    return result


def project_node(item: Mapping[str, Any]) -> dict[str, Any]:
    status = item.get("status") if isinstance(item.get("status"), Mapping) else {}
    node_info = (
        status.get("nodeInfo") if isinstance(status.get("nodeInfo"), Mapping) else {}
    )
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": safe_metadata(item.get("metadata")),
        "status": {
            "nodeInfo": {
                key: node_info[key]
                for key in (
                    "kubeletVersion",
                    "containerRuntimeVersion",
                    "kernelVersion",
                    "osImage",
                    "operatingSystem",
                    "architecture",
                )
                if key in node_info
            }
        },
    }


def safe_argo_resources(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result = []
    for resource in value:
        if not isinstance(resource, Mapping):
            continue
        projected = {
            key: resource[key]
            for key in (
                "group",
                "version",
                "kind",
                "namespace",
                "name",
                "status",
                "requiresPruning",
            )
            if key in resource
        }
        health = resource.get("health")
        if isinstance(health, Mapping) and health.get("status") is not None:
            projected["health"] = {"status": health["status"]}
        result.append(projected)
    return result


def project_argo(item: Mapping[str, Any]) -> dict[str, Any]:
    spec = item.get("spec") if isinstance(item.get("spec"), Mapping) else {}

    def source(value: Any) -> dict[str, Any]:
        candidate = value if isinstance(value, Mapping) else {}
        return {
            key: candidate[key]
            for key in ("repoURL", "chart", "path", "targetRevision")
            if key in candidate
        }

    safe_spec: dict[str, Any] = {}
    if isinstance(spec.get("sources"), list):
        safe_spec["sources"] = [source(item) for item in spec["sources"]]
    elif isinstance(spec.get("source"), Mapping):
        safe_spec["source"] = source(spec["source"])
    status = item.get("status") if isinstance(item.get("status"), Mapping) else {}
    safe_status: dict[str, Any] = {}
    sync = status.get("sync") if isinstance(status.get("sync"), Mapping) else {}
    if sync:
        safe_status["sync"] = {
            key: sync[key] for key in ("status", "revision", "revisions") if key in sync
        }
    health = status.get("health")
    if isinstance(health, Mapping) and health.get("status") is not None:
        safe_status["health"] = {"status": health["status"]}
    if status.get("reconciledAt") is not None:
        safe_status["reconciledAt"] = status["reconciledAt"]
    resources = safe_argo_resources(status.get("resources"))
    if resources:
        safe_status["resources"] = resources
    summary = status.get("summary")
    if isinstance(summary, Mapping) and isinstance(summary.get("images"), list):
        safe_status["summary"] = {
            "images": [item for item in summary["images"] if isinstance(item, str)]
        }
    operation = (
        status.get("operationState")
        if isinstance(status.get("operationState"), Mapping)
        else {}
    )
    if operation:
        safe_operation = {
            key: operation[key]
            for key in ("phase", "startedAt", "finishedAt")
            if key in operation
        }
        sync_result = (
            operation.get("syncResult")
            if isinstance(operation.get("syncResult"), Mapping)
            else {}
        )
        if sync_result:
            safe_operation["syncResult"] = {
                key: sync_result[key]
                for key in ("revision", "revisions", "images")
                if key in sync_result
            }
        safe_status["operationState"] = safe_operation
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": safe_metadata(item.get("metadata")),
        "spec": safe_spec,
        "status": safe_status,
    }


def project_crd(item: Mapping[str, Any]) -> dict[str, Any]:
    spec = item.get("spec") if isinstance(item.get("spec"), Mapping) else {}
    names = spec.get("names") if isinstance(spec.get("names"), Mapping) else {}
    versions = []
    for version in spec.get("versions", []):
        if not isinstance(version, Mapping):
            continue
        schema = (
            version.get("schema") if isinstance(version.get("schema"), Mapping) else {}
        )
        openapi = (
            schema.get("openAPIV3Schema")
            if isinstance(schema.get("openAPIV3Schema"), Mapping)
            else {}
        )
        projected_openapi = {
            key: openapi[key]
            for key in ("type", "x-kubernetes-preserve-unknown-fields")
            if key in openapi
        }
        if openapi and not projected_openapi:
            projected_openapi = {"type": "object"}
        versions.append(
            {
                **{
                    key: version[key]
                    for key in ("name", "served", "storage", "deprecated")
                    if key in version
                },
                "schema": {"openAPIV3Schema": projected_openapi},
            }
        )
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": safe_metadata(item.get("metadata")),
        "spec": {
            "group": spec.get("group"),
            "scope": spec.get("scope"),
            "names": {
                key: names[key]
                for key in ("kind", "listKind", "plural", "singular", "shortNames")
                if key in names
            },
            "versions": versions,
        },
    }


SBOM_SAFE_KEYS = {
    "alg",
    "apiVersion",
    "artifact",
    "author",
    "bom-ref",
    "bomFormat",
    "component",
    "components",
    "dependencies",
    "dependsOn",
    "digest",
    "group",
    "hashes",
    "kind",
    "metadata",
    "name",
    "publisher",
    "purl",
    "ref",
    "registry",
    "repository",
    "scanner",
    "scope",
    "serialNumber",
    "server",
    "specVersion",
    "tag",
    "type",
    "updateTimestamp",
    "vendor",
    "version",
}


def project_sbom_value(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if key == "content":
                digest = value[key]
                if (
                    parent_key == "hashes"
                    and isinstance(digest, str)
                    and re.fullmatch(r"[0-9A-Fa-f]{32,128}", digest)
                ):
                    result[key] = digest
                continue
            if key == "properties":
                properties = value[key]
                if isinstance(properties, list):
                    safe_properties = []
                    for item in properties:
                        if not isinstance(item, Mapping):
                            continue
                        name = str(item.get("name") or "")
                        property_value = str(item.get("value") or "")
                        suffix = name.lower().rsplit(":", 1)[-1]
                        if suffix == "repodigest" and re.fullmatch(
                            r"[A-Za-z0-9._:/+-]+@sha256:[0-9a-f]{64}",
                            property_value,
                        ):
                            safe_properties.append(
                                {"name": name, "value": property_value}
                            )
                        elif suffix == "platform" and re.fullmatch(
                            r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+" r"(?:/[A-Za-z0-9._-]+)?",
                            property_value,
                        ):
                            safe_properties.append(
                                {"name": name, "value": property_value}
                            )
                        elif suffix in {"os", "arch", "architecture"} and re.fullmatch(
                            r"[A-Za-z0-9._-]+", property_value
                        ):
                            safe_properties.append(
                                {"name": name, "value": property_value}
                            )
                    if safe_properties:
                        result[key] = safe_properties
                continue
            if key in SBOM_SAFE_KEYS:
                result[key] = project_sbom_value(value[key], key)
        return result
    if isinstance(value, list):
        return [project_sbom_value(item, parent_key) for item in value]
    return value


def project_sbom(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": safe_metadata(item.get("metadata")),
        "report": project_sbom_value(item.get("report", {})),
    }


def project_namespace(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": item.get("apiVersion"),
        "kind": item.get("kind"),
        "metadata": safe_metadata(item.get("metadata")),
    }


def project_openapi_document(payload: Mapping[str, Any]) -> dict[str, Any]:
    components = payload.get("components")
    schemas = components.get("schemas") if isinstance(components, Mapping) else {}
    safe_schemas: dict[str, Any] = {}
    if isinstance(schemas, Mapping):
        for name in sorted(schemas):
            schema = schemas[name]
            if not isinstance(schema, Mapping):
                continue
            safe_schema = {"type": schema["type"]} if "type" in schema else {}
            raw_gvks = schema.get("x-kubernetes-group-version-kind")
            if raw_gvks is not None:
                if (
                    not isinstance(raw_gvks, list)
                    or len(raw_gvks) > MAX_OPENAPI_GVKS_PER_SCHEMA
                ):
                    raise RuntimeError(
                        f"OpenAPI schema {name!r} has an invalid or oversized GVK list"
                    )
                safe_gvks: list[dict[str, str]] = []
                for gvk in raw_gvks:
                    if not isinstance(gvk, Mapping):
                        raise RuntimeError(
                            f"OpenAPI schema {name!r} has a non-object GVK"
                        )
                    projected_gvk = {
                        key: str(gvk.get(key) or "")
                        for key in ("group", "version", "kind")
                    }
                    if (
                        not projected_gvk["version"]
                        or not projected_gvk["kind"]
                        or any(len(value) > 512 for value in projected_gvk.values())
                        or any(
                            not re.fullmatch(r"[A-Za-z0-9._-]*", value)
                            for value in projected_gvk.values()
                        )
                    ):
                        raise RuntimeError(
                            f"OpenAPI schema {name!r} has invalid GVK scalars"
                        )
                    safe_gvks.append(projected_gvk)
                safe_schema["x-kubernetes-group-version-kind"] = safe_gvks
            if safe_schema:
                safe_schemas[str(name)] = safe_schema
    return {
        "openapi": payload.get("openapi"),
        "components": {"schemas": safe_schemas},
    }


def assert_safe_projection(value: Any, pointer: str = "") -> None:
    errors = kr.identity_projection_safety_errors(value, pointer)
    if errors:
        raise RuntimeError(errors[0])


def validate_persisted_locators(value: Any, pointer: str = "") -> None:
    unsafe = kr.unsafe_candidate_locator_pointers(value, pointer)
    if unsafe:
        raise RuntimeError(f"persisted locator is unsafe at {unsafe[0]}")


def project_query_payload(
    query: Query, payload: Mapping[str, Any]
) -> Mapping[str, Any]:
    validate_query_payload(query, payload)
    if query.response_type == "server-version":
        server = payload.get("serverVersion")
        server = server if isinstance(server, Mapping) else {}
        projected: Mapping[str, Any] = {
            "serverVersion": {
                key: server[key]
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
                if key in server
            }
        }
    elif query.response_type == "openapi-index":
        paths = (
            payload.get("paths") if isinstance(payload.get("paths"), Mapping) else {}
        )
        projected = {
            "paths": {
                str(key): {"serverRelativeURL": value.get("serverRelativeURL")}
                for key, value in paths.items()
                if isinstance(value, Mapping)
            }
        }
    elif query.response_type == "openapi-document":
        projected = project_openapi_document(payload)
    elif query.response_type == "api-resource-list":
        resources = (
            payload.get("resources")
            if isinstance(payload.get("resources"), list)
            else []
        )
        projected = {
            "apiVersion": payload.get("apiVersion"),
            "kind": payload.get("kind"),
            "groupVersion": payload.get("groupVersion"),
            "resources": [
                {
                    key: resource[key]
                    for key in (
                        "name",
                        "singularName",
                        "namespaced",
                        "kind",
                        "verbs",
                        "shortNames",
                        "categories",
                        "storageVersionHash",
                    )
                    if key in resource
                }
                for resource in resources
                if isinstance(resource, Mapping)
            ],
        }
    elif payload.get("kind") == "APIVersions":
        projected = {
            "apiVersion": payload.get("apiVersion"),
            "kind": payload.get("kind"),
            "versions": payload.get("versions", []),
        }
    elif payload.get("kind") == "APIGroupList":
        groups = (
            payload.get("groups") if isinstance(payload.get("groups"), list) else []
        )
        projected = {
            "apiVersion": payload.get("apiVersion"),
            "kind": payload.get("kind"),
            "groups": [
                {
                    "name": group.get("name"),
                    "versions": [
                        {
                            key: version[key]
                            for key in ("groupVersion", "version")
                            if key in version
                        }
                        for version in group.get("versions", [])
                        if isinstance(version, Mapping)
                    ],
                }
                for group in groups
                if isinstance(group, Mapping)
            ],
        }
    else:
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        kind = str(query.expected_kind or "")
        api_version = str(TYPED_ITEM_API_VERSIONS.get(kind) or "")
        projected_items = []
        for item in items:
            if not isinstance(item, Mapping):
                continue
            typed_item = dict(item)
            typed_item["apiVersion"] = api_version
            typed_item["kind"] = kind
            if kind in {"Application", "ApplicationSet"}:
                projected_items.append(project_argo(typed_item))
            elif kind in {"SbomReport", "ClusterSbomReport"}:
                projected_items.append(project_sbom(typed_item))
            elif kind == "Namespace":
                projected_items.append(project_namespace(typed_item))
            elif kind == "Node":
                projected_items.append(project_node(typed_item))
            elif kind == "CustomResourceDefinition":
                projected_items.append(project_crd(typed_item))
            else:
                projected_items.append(project_workload(typed_item))
        list_metadata = (
            payload.get("metadata")
            if isinstance(payload.get("metadata"), Mapping)
            else {}
        )
        projected = {
            "apiVersion": payload.get("apiVersion"),
            "kind": payload.get("kind"),
            "metadata": {
                key: list_metadata[key]
                for key in ("continue", "remainingItemCount", "resourceVersion")
                if key in list_metadata
            },
            "items": projected_items,
        }
    assert_safe_projection(projected)
    uri_errors = kr.validate_reviewed_uri_safety(projected)
    if uri_errors:
        raise RuntimeError(
            "safe capture projection contains an unsafe URI: "
            + "; ".join(uri_errors[:8])
        )
    validate_persisted_locators(projected)
    validate_query_payload(query, projected)
    return projected


def artifact_endpoint(query: Query) -> str:
    if query.response_type == "server-version":
        return "/version"
    try:
        raw_index = query.args.index("--raw")
    except ValueError as exc:
        raise ValueError(f"Query {query.filename} has no --raw endpoint") from exc
    endpoint = query.args[raw_index + 1]
    if not endpoint.startswith("/"):
        raise ValueError(f"Query {query.filename} endpoint is not absolute")
    return endpoint


def endpoint_filename(prefix: str, endpoint: str) -> str:
    digest = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest}.json"


def api_resource_queries(
    api_versions: Mapping[str, Any], api_groups: Mapping[str, Any]
) -> list[Query]:
    endpoints: set[tuple[str, str]] = set()
    versions = api_versions.get("versions")
    if not isinstance(versions, list) or not versions:
        raise RuntimeError("APIVersions response has no versions")
    for item in versions:
        version = str(item or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", version):
            raise RuntimeError("APIVersions response contains an invalid version")
        endpoints.add((f"/api/{version}", version))

    groups = api_groups.get("groups")
    if not isinstance(groups, list):
        raise RuntimeError("APIGroupList response has no groups array")
    for group in groups:
        if not isinstance(group, Mapping):
            raise RuntimeError("APIGroupList contains a non-object group")
        group_name = str(group.get("name") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", group_name):
            raise RuntimeError("APIGroupList contains an invalid group name")
        group_versions = group.get("versions")
        if not isinstance(group_versions, list) or not group_versions:
            raise RuntimeError(f"API group {group_name} has no versions")
        for group_version_record in group_versions:
            if not isinstance(group_version_record, Mapping):
                raise RuntimeError(
                    f"API group {group_name} contains a non-object version"
                )
            group_version = str(group_version_record.get("groupVersion") or "")
            version = str(group_version_record.get("version") or "")
            if group_version != f"{group_name}/{version}" or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", version
            ):
                raise RuntimeError(
                    f"API group {group_name} contains an invalid groupVersion"
                )
            endpoints.add((f"/apis/{group_name}/{version}", group_version))
            if len(endpoints) > MAX_DYNAMIC_QUERIES:
                raise RuntimeError(
                    f"API discovery exceeds endpoint bound {MAX_DYNAMIC_QUERIES}"
                )
    return [
        Query(
            "api-discovery",
            endpoint_filename("api-resources", endpoint),
            ("get", "--raw", endpoint),
            "APIResourceList",
            "api-resource-list",
        )
        for endpoint, _ in sorted(endpoints)
    ]


def sbom_page_queries(namespace_index: Mapping[str, Any]) -> list[Query]:
    """One SbomReport page per advertised namespace, ordered by namespace name."""

    namespaces, errors = kr.namespace_index_names(namespace_index)
    if errors:
        raise RuntimeError(errors[0])
    if len(namespaces) > MAX_DYNAMIC_QUERIES:
        raise RuntimeError(
            f"namespace paging exceeds endpoint bound {MAX_DYNAMIC_QUERIES}"
        )
    return [
        Query(
            "workload-sboms",
            endpoint_filename("sbomreports", kr.sbom_page_endpoint(namespace)),
            ("get", "--raw", kr.sbom_page_endpoint(namespace)),
            "SbomReport",
        )
        for namespace in namespaces
    ]


def openapi_document_queries(index: Mapping[str, Any]) -> list[Query]:
    paths = index.get("paths")
    if not isinstance(paths, Mapping) or not paths:
        raise RuntimeError("OpenAPI v3 discovery response has no paths")
    endpoints: set[str] = set()
    for path_key, record in paths.items():
        if not isinstance(path_key, str) or not path_key:
            raise RuntimeError("OpenAPI v3 discovery contains an invalid path key")
        if not (
            re.fullmatch(r"api/[^/]+", path_key)
            or re.fullmatch(r"apis/[^/]+/[^/]+", path_key)
        ):
            continue
        if not isinstance(record, Mapping):
            raise RuntimeError(f"OpenAPI v3 discovery path {path_key} is not an object")
        endpoint = str(record.get("serverRelativeURL") or "")
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not parsed.path.startswith("/openapi/v3/")
            or ".." in parsed.path.split("/")
            or len(endpoint) > 4096
        ):
            raise RuntimeError(
                f"OpenAPI v3 discovery path {path_key} has an invalid serverRelativeURL"
            )
        if parsed.path != f"/openapi/v3/{path_key}":
            raise RuntimeError(
                "OpenAPI v3 discovery path key does not match serverRelativeURL"
            )
        endpoints.add(endpoint)
        if len(endpoints) > MAX_DYNAMIC_QUERIES:
            raise RuntimeError(
                f"OpenAPI discovery exceeds endpoint bound {MAX_DYNAMIC_QUERIES}"
            )
    if not endpoints:
        raise RuntimeError("OpenAPI v3 discovery advertises no API group versions")
    return [
        Query(
            "builtin-openapi",
            endpoint_filename("openapi-v3", endpoint),
            ("get", "--raw", endpoint),
            "OpenAPIv3Document",
            "openapi-document",
        )
        for endpoint in sorted(endpoints)
    ]


def write_new(directory_fd: int, filename: str, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(filename, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("capture artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        try:
            os.unlink(filename, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)


def cleanup_failed_capture(directory_fd: int, created_names: Sequence[str]) -> None:
    """Remove only artifacts created by this failed capture invocation."""

    failures: list[str] = []
    for filename in reversed(tuple(created_names)):
        try:
            os.unlink(filename, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        except OSError:
            failures.append(filename)
    try:
        os.fsync(directory_fd)
    except OSError:
        failures.append("directory-fsync")
    if failures:
        raise RuntimeError("failed capture cleanup could not remove all artifacts")


def materialize_unique_projected_artifact(
    directory_fd: int,
    output_dir: Path,
    filename: str,
    raw: bytes,
    captured_hash_inputs: dict[str, str],
    inputs: list[str],
    created_names: list[str] | None = None,
) -> str:
    raw_hash = kr.file_hash(raw)
    if raw_hash not in captured_hash_inputs:
        if created_names is not None:
            created_names.append(filename)
        write_new(directory_fd, filename, raw)
        capture_path = str((output_dir / filename).resolve())
        captured_hash_inputs[raw_hash] = capture_path
        inputs.append(capture_path)
    return raw_hash


def create_capture_directory(path: Path) -> Path:
    absolute = path.absolute()
    if absolute == Path("/"):
        raise ValueError("output directory cannot be filesystem root")
    current = Path("/")
    for component in absolute.parts[1:-1]:
        current /= component
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise ValueError(
                f"output parent {current} must already exist: {exc}"
            ) from exc
        if os.path.islink(current) or not os.path.isdir(current):
            raise ValueError(f"output parent {current} must be a non-symlink directory")
        if not (metadata.st_mode & 0o400):
            raise ValueError(f"output parent {current} is not accessible")
    try:
        os.mkdir(absolute, 0o700)
    except OSError as exc:
        raise ValueError(
            f"cannot create fresh output directory {absolute}: {exc}"
        ) from exc
    return absolute


def resolve_context(
    runner: Runner,
    kubectl: str,
    kubeconfig: str,
    requested: str,
    *,
    timeout: float,
    pass_fds: Sequence[int] = (),
) -> str:
    if requested:
        return requested
    completed = invoke(
        runner,
        kubectl_command(kubectl, kubeconfig, "", ("config", "current-context")),
        timeout=timeout,
        max_stdout_bytes=513,
        pass_fds=pass_fds,
    )
    if completed.returncode != 0:
        raise RuntimeError("cannot resolve kubectl context: command failed")
    context = completed.stdout.decode("utf-8", errors="strict").strip()
    if not context or len(context) > 512:
        raise RuntimeError("kubectl current context is empty or oversized")
    return context


def resolve_cluster_uid(
    runner: Runner,
    kubectl: str,
    kubeconfig: str,
    context: str,
    *,
    timeout: float,
    pass_fds: Sequence[int] = (),
) -> str:
    payload, _ = command_json(
        runner,
        kubectl_command(
            kubectl,
            kubeconfig,
            context,
            ("get", "namespace", "kube-system", "-o", "json"),
        ),
        timeout=timeout,
        pass_fds=pass_fds,
    )
    metadata = payload.get("metadata")
    uid = str(metadata.get("uid") if isinstance(metadata, Mapping) else "")
    if not uid or len(uid) > 256:
        raise RuntimeError("kube-system namespace has no bounded metadata.uid")
    return uid


def _capture_with_bound_kubeconfig(
    output_dir: Path,
    *,
    kubectl: str,
    kubeconfig: str,
    context: str,
    git_commit: str,
    observed_at: str,
    timeout: float,
    kubeconfig_snapshot: Mapping[str, Any],
    kubeconfig_fd: int,
    capture_generator: Mapping[str, Any],
    capture_started_at: str,
    wall_clock: Callable[[], float],
    runner: Runner = subprocess.Popen,
    verify_executable: bool = True,
) -> dict[str, Any]:
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", git_commit.lower()):
        raise ValueError("git commit must be an exact 40- or 64-hex object ID")
    if not kr.valid_live_observed_at(observed_at):
        raise ValueError("observed-at must be an exact UTC second")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not kr.valid_live_observed_at(capture_started_at):
        raise ValueError("capture start must be an exact UTC second")

    capture_deadline = time.monotonic() + MAX_LIVE_CAPTURE_SECONDS
    command_count = 0

    def next_command_timeout() -> float:
        nonlocal command_count
        command_count += 1
        if command_count > MAX_LIVE_CAPTURE_COMMANDS:
            raise RuntimeError(
                f"capture exceeds command bound {MAX_LIVE_CAPTURE_COMMANDS}"
            )
        remaining = capture_deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"capture exceeds deadline {MAX_LIVE_CAPTURE_SECONDS}s")
        return min(timeout, remaining)

    executable_before: dict[str, Any] | None = None
    kubeconfig_before = dict(kubeconfig_snapshot)
    kubeconfig_source = kubeconfig_before.get("source")
    kubeconfig_execution = kubeconfig_before.get("execution")
    if not isinstance(kubeconfig_source, Mapping) or not isinstance(
        kubeconfig_execution, Mapping
    ):
        raise ValueError("kubeconfig snapshot lacks source or execution identity")
    if verify_executable:
        executable_before = kr.trusted_executable_identity(Path(kubectl))
    resolved_context = context
    if not resolved_context:
        resolved_context = resolve_context(
            runner,
            kubectl,
            str(kubeconfig_execution["path"]),
            "",
            timeout=next_command_timeout(),
            pass_fds=(kubeconfig_fd,),
        )
    cluster_uid = resolve_cluster_uid(
        runner,
        kubectl,
        str(kubeconfig_execution["path"]),
        resolved_context,
        timeout=next_command_timeout(),
        pass_fds=(kubeconfig_fd,),
    )

    output_dir = create_capture_directory(output_dir)
    directory_fd = os.open(output_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    inputs: list[str] = []
    surface_hashes: dict[str, list[str]] = {
        surface: [] for surface in kr.LIVE_REQUIRED_SURFACES
    }
    surface_artifacts: dict[str, list[dict[str, str]]] = {
        surface: [] for surface in kr.LIVE_REQUIRED_SURFACES
    }
    surface_errors: dict[str, list[str]] = {
        surface: [] for surface in kr.LIVE_REQUIRED_SURFACES
    }
    captured_payloads: dict[str, Mapping[str, Any]] = {}
    captured_hash_inputs: dict[str, str] = {}
    captured_documents_by_hash: dict[str, list[dict[str, Any]]] = {}
    created_names: list[str] = []
    total_capture_bytes = 0
    try:

        def run_query(query: Query) -> None:
            nonlocal total_capture_bytes
            try:
                payload, _ = command_json(
                    runner,
                    kubectl_command(
                        kubectl,
                        str(kubeconfig_execution["path"]),
                        resolved_context,
                        query.args,
                    ),
                    timeout=next_command_timeout(),
                    pass_fds=(kubeconfig_fd,),
                )
                validate_query_payload(query, payload)
                payload = project_query_payload(query, payload)
                raw = (
                    json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
                    + "\n"
                ).encode("utf-8")
                if len(raw) > MAX_LIVE_ARTIFACT_BYTES:
                    raise RuntimeError(
                        "projected command output exceeds byte bound "
                        f"{MAX_LIVE_ARTIFACT_BYTES}"
                    )
                total_capture_bytes += len(raw)
                if total_capture_bytes > MAX_LIVE_CAPTURE_BYTES:
                    raise RuntimeError(
                        f"capture exceeds total byte bound {MAX_LIVE_CAPTURE_BYTES}"
                    )
                raw_hash = materialize_unique_projected_artifact(
                    directory_fd,
                    output_dir,
                    query.filename,
                    raw,
                    captured_hash_inputs,
                    inputs,
                    created_names,
                )
                surface_hashes[query.surface].append(raw_hash)
                captured_documents_by_hash.setdefault(raw_hash, []).append(
                    {"payload": payload}
                )
                surface_artifacts[query.surface].append(
                    {
                        "endpoint": artifact_endpoint(query),
                        "raw_hash": raw_hash,
                        "document_type": (query.expected_kind or query.response_type),
                    }
                )
                captured_payloads[query.filename] = payload
            except RuntimeError as exc:
                if (
                    command_count > MAX_LIVE_CAPTURE_COMMANDS
                    or time.monotonic() >= capture_deadline
                ):
                    raise
                surface_errors[query.surface].append(f"{query.filename}: query-failed")

        for query in QUERIES:
            run_query(query)

        namespace_index = captured_payloads.get("namespaces.json")
        if isinstance(namespace_index, Mapping):
            try:
                page_queries = sbom_page_queries(namespace_index)
            except RuntimeError:
                surface_errors["workload-sboms"].append(
                    "namespace-paging-validation-failed"
                )
            else:
                page_errors_before = len(surface_errors["workload-sboms"])
                for query in page_queries:
                    run_query(query)
                # One stable code keeps a wide page failure inside the error bound.
                if len(surface_errors["workload-sboms"]) > page_errors_before:
                    del surface_errors["workload-sboms"][page_errors_before:]
                    surface_errors["workload-sboms"].append(
                        "namespace-page-query-failed"
                    )
        elif not surface_errors["workload-sboms"]:
            surface_errors["workload-sboms"].append("namespace-index-unavailable")

        dynamic_api_queries: list[Query] = []
        api_versions = captured_payloads.get("api-versions.json")
        api_groups = captured_payloads.get("api-groups.json")
        if isinstance(api_versions, Mapping) and isinstance(api_groups, Mapping):
            try:
                dynamic_api_queries = api_resource_queries(api_versions, api_groups)
            except RuntimeError as exc:
                surface_errors["api-discovery"].append(
                    "api-discovery-validation-failed"
                )
            else:
                for query in dynamic_api_queries:
                    run_query(query)

        openapi_index = captured_payloads.get("openapi-v3-index.json")
        dynamic_openapi_queries: list[Query] = []
        if isinstance(openapi_index, Mapping):
            try:
                dynamic_openapi_queries = openapi_document_queries(openapi_index)
            except RuntimeError as exc:
                surface_errors["builtin-openapi"].append(
                    "openapi-discovery-validation-failed"
                )
            else:
                for query in dynamic_openapi_queries:
                    run_query(query)

        api_endpoints = {artifact_endpoint(query) for query in dynamic_api_queries}
        openapi_api_endpoints = {
            urlsplit(artifact_endpoint(query)).path.removeprefix("/openapi/v3")
            for query in dynamic_openapi_queries
        }
        missing_openapi = sorted(api_endpoints - openapi_api_endpoints)
        unserved_openapi = sorted(openapi_api_endpoints - api_endpoints)
        if missing_openapi:
            surface_errors["builtin-openapi"].append(
                "openapi-served-group-coverage-missing"
            )
        if unserved_openapi:
            surface_errors["builtin-openapi"].append(
                "openapi-unserved-group-coverage-present"
            )

        if verify_executable:
            executable_after = kr.trusted_executable_identity(Path(kubectl))
            if executable_before != executable_after:
                raise RuntimeError("kubectl executable changed during capture")
        verify_sealed_kubeconfig_snapshot(kubeconfig_fd, kubeconfig_before)
        generator_after = capture_generator_identity(git_commit)
        if dict(capture_generator) != generator_after:
            raise RuntimeError("capture generator changed during capture")
        capture_completed_at = utc_second(wall_clock())
        started = kr.parse_utc_second(capture_started_at)
        completed = kr.parse_utc_second(capture_completed_at)
        observed = kr.parse_utc_second(observed_at)
        tolerance = kr.LIVE_CAPTURE_TIME_TOLERANCE_SECONDS
        if completed < started or not (
            started.timestamp() - tolerance
            <= observed.timestamp()
            <= completed.timestamp() + tolerance
        ):
            raise RuntimeError(
                "caller observation timestamp is outside the measured capture window"
            )

        surfaces: dict[str, dict[str, Any]] = {}
        for surface in kr.LIVE_REQUIRED_SURFACES:
            errors = surface_errors[surface]
            record: dict[str, Any] = {
                "state": "unavailable" if errors else "captured",
                "raw_hashes": sorted(set(surface_hashes[surface])),
                "resource_kinds": list(kr.LIVE_SURFACE_RESOURCE_KINDS[surface]),
                "artifacts": sorted(
                    surface_artifacts[surface],
                    key=kr.canonical_json,
                ),
            }
            if errors:
                record["error"] = "; ".join(errors)
            surfaces[surface] = record

        manifest = {
            "record_kind": kr.LIVE_CAPTURE_RECORD_KIND,
            "contract_version": kr.LIVE_CAPTURE_CONTRACT_VERSION,
            "observed_at": observed_at,
            "git_commit": git_commit.lower(),
            "cluster_uid": cluster_uid,
            "context": resolved_context,
            "capture_window": {
                "started_at": capture_started_at,
                "completed_at": capture_completed_at,
                "observation_tolerance_seconds": tolerance,
            },
            "required_surfaces": list(kr.LIVE_REQUIRED_SURFACES),
            "projection": dict(kr.LIVE_CAPTURE_PROJECTION),
            "kubectl": (
                {
                    "path": executable_before["path"],
                    "sha256": executable_before["sha256"],
                    "size": executable_before["size"],
                }
                if executable_before
                else {"state": "test-runner"}
            ),
            "capture_generator": dict(capture_generator),
            "kubeconfig": {
                "source": {
                    key: kubeconfig_source[key]
                    for key in ("path", "sha256", "size", "device", "inode")
                },
                "execution_snapshot": {
                    "policy": kubeconfig_execution["policy"],
                    "sha256": kubeconfig_execution["sha256"],
                    "size": kubeconfig_execution["size"],
                },
            },
            "bounds": {
                "artifact_bytes": MAX_LIVE_ARTIFACT_BYTES,
                "capture_bytes": MAX_LIVE_CAPTURE_BYTES,
                "list_items": MAX_LIVE_LIST_ITEMS,
                "dynamic_queries": MAX_DYNAMIC_QUERIES,
                "capture_commands": MAX_LIVE_CAPTURE_COMMANDS,
                "capture_seconds": MAX_LIVE_CAPTURE_SECONDS,
            },
            "surfaces": surfaces,
        }
        if verify_executable:
            normalized_raw = kr.canonical_json(manifest).encode("utf-8")
            normalized, receipt_errors = kr.normalize_live_capture_manifest(
                manifest,
                content_hash=kr.file_hash(normalized_raw),
                raw_hash=kr.file_hash(normalized_raw),
            )
            closure_errors = kr.validate_live_api_artifacts(
                normalized, captured_documents_by_hash
            )
            if receipt_errors or closure_errors:
                raise RuntimeError(
                    "generated capture receipt failed the shared live evidence contract"
                )
        manifest_raw = (
            json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        created_names.append("capture-manifest.json")
        write_new(directory_fd, "capture-manifest.json", manifest_raw)
        os.fsync(directory_fd)
    except BaseException:
        cleanup_failed_capture(directory_fd, created_names)
        failed_directory_fd = directory_fd
        directory_fd = -1
        os.close(failed_directory_fd)
        try:
            os.rmdir(output_dir)
        except OSError as exc:
            raise RuntimeError(
                "failed capture cleanup could not remove output directory"
            ) from exc
        raise
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)

    unavailable = sorted(
        surface for surface, errors in surface_errors.items() if errors
    )
    return {
        "state": "partial" if unavailable else "complete",
        "capture_manifest": str((output_dir / "capture-manifest.json").resolve()),
        "inputs": sorted(inputs),
        "captured_surfaces": sorted(set(kr.LIVE_REQUIRED_SURFACES) - set(unavailable)),
        "unavailable_surfaces": unavailable,
    }


def capture(
    output_dir: Path,
    *,
    kubectl: str,
    kubeconfig: str,
    context: str,
    git_commit: str,
    observed_at: str,
    timeout: float,
    runner: Runner = subprocess.Popen,
    verify_executable: bool = True,
    wall_clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    capture_started_epoch = wall_clock()
    capture_started_at = utc_second(capture_started_epoch)
    if not kr.valid_live_observed_at(observed_at):
        raise ValueError("observed-at must be an exact UTC second")
    if (
        abs(kr.parse_utc_second(observed_at).timestamp() - capture_started_epoch)
        > kr.LIVE_CAPTURE_TIME_TOLERANCE_SECONDS
    ):
        raise ValueError("observed-at is outside the measured capture start tolerance")
    generator = capture_generator_identity(git_commit)
    kubeconfig_fd, snapshot = sealed_kubeconfig_snapshot(Path(kubeconfig))
    try:
        return _capture_with_bound_kubeconfig(
            output_dir,
            kubectl=kubectl,
            kubeconfig=str(snapshot["execution"]["path"]),
            context=context,
            git_commit=git_commit,
            observed_at=observed_at,
            timeout=timeout,
            kubeconfig_snapshot=snapshot,
            kubeconfig_fd=kubeconfig_fd,
            capture_generator=generator,
            capture_started_at=capture_started_at,
            wall_clock=wall_clock,
            runner=runner,
            verify_executable=verify_executable,
        )
    finally:
        os.close(kubeconfig_fd)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--output-dir", required=True)
    result.add_argument("--kubectl", default="/usr/bin/kubectl")
    result.add_argument("--kubeconfig", required=True)
    result.add_argument("--context", default="")
    result.add_argument("--git-commit", required=True)
    result.add_argument(
        "--observed-at",
        required=True,
        help="caller-pinned exact UTC second",
    )
    result.add_argument("--timeout", type=float, default=60.0)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = capture(
            Path(args.output_dir),
            kubectl=args.kubectl,
            kubeconfig=args.kubeconfig,
            context=args.context,
            git_commit=args.git_commit,
            observed_at=args.observed_at,
            timeout=args.timeout,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        sys.stderr.write(f"capture failed: {exc}\n")
        return 2
    json.dump(result, sys.stdout, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return 0 if result["state"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
