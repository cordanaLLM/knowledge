#!/usr/bin/env python3
"""Materialize a proposed, non-authoritative Argo source-resolution set.

The materializer performs no network, subprocess, Git, signing, admission,
release, pointer, Argo, or Kubernetes action.  It combines the exact retained
P1-SRC-01 denominator with a source-hash-bound table of primary-source facts.
The result is deliberately ``proposed``: independent review is still required
before the acquisition planner can select any target.
"""

from __future__ import annotations

import argparse
import json
import os
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
GENERATOR = "archeion-argo-source-resolution-materializer"
GENERATOR_VERSION = "1"
GENERATOR_SOURCE = "tools/knowledge-registry/materialize_argo_source_resolution.py"
REVIEW_EVIDENCE = "source-monorepo-review:source-acceptance#argo-source-resolution"
PUBLISHER = "Argo Project (argoproj)"
CHART_REPOSITORY = "https://argoproj.github.io/argo-helm"
CHART_SOURCE_REPOSITORY = "https://github.com/argoproj/argo-helm"
GOVERNANCE_URI = (
    "https://raw.githubusercontent.com/argoproj/argoproj/main/community/GOVERNANCE.md"
)
MEMBERSHIP_URI = (
    "https://raw.githubusercontent.com/argoproj/argoproj/main/community/membership.md"
)
CHART_INDEX_URI = "https://argoproj.github.io/argo-helm/index.yaml"
PGP_KEY_URI = "https://argoproj.github.io/argo-helm/pgp_keys.asc"
PGP_FINGERPRINT = "2B8F22F57260EFA67BE1C5824B11F800CD9D2252"
RIGHTS = (
    "Apache-2.0 for Argo-authored material only; bundled and referenced "
    "third-party dependencies retain their own rights"
)

CHART_FACTS: dict[str, dict[str, Any]] = {
    "argo-cd": {
        "chart_version": "10.1.4",
        "chart_tag": "argo-cd-10.1.4",
        "chart_commit": "465fffbbfb42693e1254073d9573153789bc7d1c",
        "package_sha256": "sha256:142d2eaaa2adf9051c109c396c5fe3af742674011a5837df262bd6f8f2991d2c",
        "provenance_sha256": "sha256:13a7132d984acc830d023440d0cf6c1787e257f8d67a885f25dae911aa10f24e",
        "app_version": "v3.4.5",
        "upstream_repo": "argo-cd",
        "upstream_commit": "564b94973b284b8de98da7cee6eeade2cb941e46",
        "docs_path": "docs",
        "reference_path": "docs/user-guide/commands",
        "api_path": "docs/developer-guide",
        "schema_path": "manifests/crds",
        "config_path": "docs/operator-manual",
        "migration_path": "docs/operator-manual/upgrading",
        "deprecation_path": "docs/operator-manual/upgrading",
        "security_path": "docs/operator-manual/signed-release-assets.md",
        "runtime_names": ("argocd",),
        "runtime_assurance": {
            "release_assets_documented": True,
            "signed_release_documentation": "release-3.4",
            "cosign_verified_by_this_materializer": False,
            "slsa_verified_by_this_materializer": False,
        },
    },
    "argo-rollouts": {
        "chart_version": "2.41.0",
        "chart_tag": "argo-rollouts-2.41.0",
        "chart_commit": "8796aeaa82428f96c3a20293f75a1a805f99d32b",
        "package_sha256": "sha256:ff53d617efb369cd07acc595309e7fa73a602576375e0a52a78dab1e2d970df5",
        "provenance_sha256": "sha256:b26b21ee43e09374a2bb08698d7e07a3c5352696243ce0303d3c66d7f773d9c8",
        "app_version": "v1.9.0",
        "upstream_repo": "argo-rollouts",
        "upstream_commit": "838d4e792be666ec11bd0c80331e0c5511b5010e",
        "docs_path": "docs",
        "reference_path": "docs/features/specification.md",
        "api_path": "docs/features/specification.md",
        "schema_path": "manifests/crds",
        "config_path": "docs/features",
        "migration_path": "docs/migrating.md",
        "deprecation_path": "docs/migrating.md",
        "security_path": "docs/security/signed-release-assets.md",
        "runtime_names": ("argo-rollouts", "kubectl-argo-rollouts"),
        "runtime_assurance": {
            "provenance_asset": "argo-rollouts.intoto.jsonl",
            "provenance_asset_verified_by_this_materializer": False,
            "cosign_verified_by_this_materializer": False,
            "slsa_verified_by_this_materializer": False,
        },
    },
    "argo-workflows": {
        "chart_version": "1.0.20",
        "chart_tag": "argo-workflows-1.0.20",
        "chart_commit": "f5030f65031287ae00222bfc2bf47004dff5dc5b",
        "package_sha256": "sha256:2d4bd422507b44ecb39f8f654c16b26e122b41faf867f0f53eca523a607a440d",
        "provenance_sha256": "sha256:2433b8f75214e79c1ba426515eb7c021f129c4582d8ed15a057872899a00fc84",
        "app_version": "v4.0.7",
        "upstream_repo": "argo-workflows",
        "upstream_commit": "9aeb47ce10339f4a14819335c6a00027353ba0df",
        "docs_path": "docs",
        "reference_path": "docs/fields.md",
        "api_path": "api/openapi-spec/swagger.json",
        "schema_path": "manifests/base/crds",
        "schema_variants": ("full", "minimal"),
        "config_path": "docs/workflow-controller-configmap.md",
        "migration_path": "docs/upgrading.md",
        "deprecation_path": "docs/deprecations.md",
        "security_path": "docs/security.md",
        "runtime_names": ("workflow-controller", "argoexec", "argocli"),
        "runtime_assurance": {
            "release_sbom_documented": True,
            "images_documented_as_signed": True,
            "release_workflow_provenance": False,
            "cosign_verified_by_this_materializer": False,
            "slsa_verified_by_this_materializer": False,
        },
    },
}

RUNTIME_COMPONENTS = {
    "argocd": "cmp:oci:quay.io/argoproj/argocd",
    "argo-rollouts": "cmp:oci:quay.io/argoproj/argo-rollouts",
    "kubectl-argo-rollouts": "cmp:oci:quay.io/argoproj/kubectl-argo-rollouts",
    "workflow-controller": "cmp:oci:quay.io/argoproj/workflow-controller",
    "argoexec": "cmp:oci:quay.io/argoproj/argoexec",
    "argocli": "cmp:oci:quay.io/argoproj/argocli",
}


def github_at(repo: str, commit: str, path: str = "") -> str:
    suffix = f"/{path}" if path else ""
    return f"https://github.com/argoproj/{repo}/tree/{commit}{suffix}"


def github_blob(repo: str, commit: str, path: str) -> str:
    return f"https://github.com/argoproj/{repo}/blob/{commit}/{path}"


def github_path(repo: str, commit: str, path: str) -> str:
    """Use GitHub's file or directory route without guessing at retrieval time."""

    name = path.rstrip("/").rsplit("/", 1)[-1]
    return (
        github_blob(repo, commit, path)
        if "." in name
        else github_at(repo, commit, path)
    )


def chart_uris(chart: str, facts: Mapping[str, Any]) -> dict[str, str]:
    tag = str(facts["chart_tag"])
    commit = str(facts["chart_commit"])
    release = f"{CHART_SOURCE_REPOSITORY}/releases/tag/{tag}"
    package = f"{CHART_SOURCE_REPOSITORY}/releases/download/{tag}/{chart}-{facts['chart_version']}.tgz"
    upstream_repo = str(facts["upstream_repo"])
    upstream_commit = str(facts["upstream_commit"])
    upstream_release = f"https://github.com/argoproj/{upstream_repo}/releases/tag/{facts['app_version']}"
    result = {
        "subtree": github_at("argo-helm", commit, f"charts/{chart}"),
        "release": release,
        "package": package,
        "provenance": package + ".prov",
        "license": github_blob("argo-helm", commit, "LICENSE"),
        "chart_lock": github_blob("argo-helm", commit, f"charts/{chart}/Chart.lock"),
        "publish_workflow": github_blob(
            "argo-helm", commit, ".github/workflows/publish.yml"
        ),
        "upstream_source": github_at(upstream_repo, upstream_commit),
        "upstream_release": upstream_release,
        "upstream_license": github_blob(upstream_repo, upstream_commit, "LICENSE"),
        "upstream_reference": github_path(
            upstream_repo, upstream_commit, str(facts["reference_path"])
        ),
        "upstream_docs": github_path(
            upstream_repo, upstream_commit, str(facts["docs_path"])
        ),
        "upstream_api": github_path(
            upstream_repo, upstream_commit, str(facts["api_path"])
        ),
        "upstream_schema": github_path(
            upstream_repo, upstream_commit, str(facts["schema_path"])
        ),
        "upstream_config": github_path(
            upstream_repo, upstream_commit, str(facts["config_path"])
        ),
        "upstream_migration": github_path(
            upstream_repo, upstream_commit, str(facts["migration_path"])
        ),
        "upstream_deprecation": github_path(
            upstream_repo, upstream_commit, str(facts["deprecation_path"])
        ),
        "upstream_security": github_path(
            upstream_repo, upstream_commit, str(facts["security_path"])
        ),
        "upstream_changelog": github_blob(
            upstream_repo, upstream_commit, "CHANGELOG.md"
        ),
        "advisory": f"https://github.com/argoproj/{upstream_repo}/security/advisories",
    }
    for variant in facts.get("schema_variants", ()):
        result[f"upstream_schema_{variant}"] = github_at(
            upstream_repo,
            upstream_commit,
            f"{facts['schema_path']}/{variant}",
        )
    return result


def channel_spec(
    chart: str, channel_type: str, facts: Mapping[str, Any], uris: Mapping[str, str]
) -> tuple[str, str, str]:
    immutable = {
        "docs": (uris["upstream_docs"], "exact-commit"),
        "reference": (uris["upstream_reference"], "exact-commit"),
        "api": (uris["upstream_api"], "exact-commit"),
        "schema": (uris["upstream_schema"], "exact-commit"),
        "config": (uris["upstream_config"], "exact-commit"),
        "release": (uris["release"], "exact-tag"),
        "changelog": (uris["upstream_changelog"], "exact-commit"),
        "migration": (uris["upstream_migration"], "exact-commit"),
        "deprecation": (uris["upstream_deprecation"], "exact-commit"),
        "source": (uris["subtree"], "exact-commit"),
        "license": (uris["license"], "exact-commit"),
        "package": (uris["package"], "exact-artifact"),
        "artifact": (uris["package"], "exact-artifact"),
        "provenance": (uris["provenance"], "exact-artifact"),
        "sbom": (uris["upstream_release"], "exact-tag"),
    }
    if channel_type == "advisory":
        return (
            uris["advisory"],
            "mutable-resolve-ref",
            (
                "resolve live and content-hash every use; never substitute it for an immutable release"
            ),
        )
    uri, strategy = immutable[channel_type]
    return (
        uri,
        strategy,
        "immutable locator; re-resolve only through a new reviewed record",
    )


def candidate_runtime_mapping(
    candidate: Mapping[str, Any], chart: str, facts: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, tuple[str, str]]]:
    mapped: list[dict[str, Any]] = []
    exact: dict[str, tuple[str, str]] = {}
    expected_tag = str(facts["app_version"])
    for output_index, name in enumerate(facts["runtime_names"]):
        component_index, component = base.exact_one(
            candidate["components"],
            lambda item, runtime_name=name: item.get("kind") == "oci-image"
            and item.get("namespace") == "quay.io/argoproj"
            and item.get("name") == runtime_name,
            f"{chart} runtime component {name}",
        )
        component_id = component["component_id"]
        versions = [
            (index, value)
            for index, value in enumerate(candidate["versions"])
            if isinstance(value, Mapping) and value.get("component_id") == component_id
        ]
        if not versions:
            raise ValueError(f"{chart} runtime component {name} has no versions")
        version_ids = {str(value["component_version_id"]) for _, value in versions}
        occurrences = [
            (index, value)
            for index, value in enumerate(candidate["occurrences"])
            if isinstance(value, Mapping)
            and value.get("component_version_id") in version_ids
        ]
        if not occurrences:
            raise ValueError(f"{chart} runtime component {name} has no occurrences")
        tagged = [
            value
            for _, value in versions
            if value.get("resolved_version") == expected_tag
        ]
        if not tagged:
            raise ValueError(f"{chart} runtime component {name} lacks {expected_tag}")
        if not any("artifact_digest" in value for _, value in versions):
            raise ValueError(f"{chart} runtime component {name} lacks observed digests")
        item = {
            "canonical_runtime_id": RUNTIME_COMPONENTS[name],
            "candidate_component_index": component_index,
            "candidate_component": component,
            "candidate_versions": [
                {"candidate_index": index, "record": value} for index, value in versions
            ],
            "candidate_occurrences": [
                {"candidate_index": index, "record": value}
                for index, value in occurrences
            ],
            "source_admission": {
                "upstream_tag": expected_tag,
                "upstream_commit": facts["upstream_commit"],
                "oci_manifest_digest": None,
                "digest_to_source_verified": False,
                "sbom_verified": False,
                "cosign_verified": False,
                "slsa_verified": False,
                "state": "blocked",
            },
        }
        prefix = f"/versions/0/build_metadata/source_resolution/runtime_mapping/components/{output_index}"
        for leaf in base.leaf_pointers(component):
            exact[f"{prefix}/candidate_component{leaf}"] = (
                f"/components/{component_index}{leaf}",
                "copied exactly from the accepted candidate runtime component",
            )
        for local_index, (candidate_index, value) in enumerate(versions):
            exact[f"{prefix}/candidate_versions/{local_index}/candidate_index"] = (
                f"/versions/{candidate_index}",
                "candidate array index retained as a locator",
            )
            for leaf in base.leaf_pointers(value):
                exact[f"{prefix}/candidate_versions/{local_index}/record{leaf}"] = (
                    f"/versions/{candidate_index}{leaf}",
                    "copied exactly from the accepted candidate runtime version",
                )
        for local_index, (candidate_index, value) in enumerate(occurrences):
            exact[f"{prefix}/candidate_occurrences/{local_index}/candidate_index"] = (
                f"/occurrences/{candidate_index}",
                "candidate array index retained as a locator",
            )
            for leaf in base.leaf_pointers(value):
                exact[f"{prefix}/candidate_occurrences/{local_index}/record{leaf}"] = (
                    f"/occurrences/{candidate_index}{leaf}",
                    "copied exactly from the accepted candidate runtime occurrence",
                )
        mapped.append(item)
    return {
        "upstream_repository": f"https://github.com/argoproj/{facts['upstream_repo']}",
        "upstream_tag": expected_tag,
        "upstream_commit": facts["upstream_commit"],
        "components": mapped,
        "admission_state": "blocked_runtime_identity_verification",
    }, exact


def make_channels(
    draft: Mapping[str, Any],
    chart: str,
    facts: Mapping[str, Any],
    uris: Mapping[str, str],
) -> list[dict[str, Any]]:
    channels: list[dict[str, Any]] = []
    for candidate_channel in draft["channels"]:
        channel_type = str(candidate_channel["channel_type"])
        uri, strategy, refresh = channel_spec(chart, channel_type, facts, uris)
        channel = {
            "channel_id": candidate_channel["channel_id"],
            "component_id": draft["component"]["component_id"],
            "channel_type": channel_type,
            "availability_state": "unresolved",
            "canonical_uri": uri,
            "publisher": PUBLISHER,
            "version_strategy": strategy,
            "access": "public",
            "rights": RIGHTS,
            "refresh_policy": refresh,
            "discovery_method": "manual",
            "confidence": "high",
            "review_state": "proposed",
            "evidence": [uri, REVIEW_EVIDENCE],
            "gap": {
                "state": "unresolved",
                "reason": "primary-source locator is materialized but has not been independently accepted",
                "blocking": True,
                "evidence": [uri, REVIEW_EVIDENCE],
                "next_action": "independently verify the locator, version strategy, publisher, and rights",
            },
        }
        channels.append(channel)
    return channels


CANDIDATE_EVIDENCE_PREFIX = base.EXPECTED_CANDIDATE_SHA256.replace(
    "sha256:", "accepted-candidate:sha256:"
)
CAPTURE_EVIDENCE_PREFIX = base.EXPECTED_CAPTURE_MANIFEST_SHA256.replace(
    "sha256:", "capture-manifest:sha256:"
)
PRIMARY_DERIVATION = (
    "materialized from this exact primary-source locator; independent acceptance "
    "remains pending"
)
CONTROL_DERIVATION = (
    "non-authoritative control or conservative null; independent review remains "
    "blocking"
)


def json_pointer_parts(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ValueError(f"JSON pointer is not absolute: {pointer}")
    return [
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer.removeprefix("/").split("/")
    ]


def json_pointer_value(value: Any, pointer: str) -> Any:
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


def leaf_values(value: Any, pointer: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, Mapping) and value:
        result: list[tuple[str, Any]] = []
        for key in sorted(value):
            result.extend(
                leaf_values(
                    value[key], pointer + "/" + base.json_pointer_escape(str(key))
                )
            )
        return result
    if isinstance(value, list) and value:
        result = []
        for index, item in enumerate(value):
            result.extend(leaf_values(item, f"{pointer}/{index}"))
        return result
    return [(pointer or "/", value)]


def retained_candidate_bindings(
    draft: Mapping[str, Any], record: Mapping[str, Any], draft_entry: Mapping[str, Any]
) -> dict[str, tuple[str, str]]:
    """Retain only bindings whose record leaf is byte-for-byte unchanged."""

    original_evidence_count = len(draft["versions"][0]["evidence"])

    def allowed(pointer: str) -> bool:
        excluded = (
            "/review",
            "/component/source_repo",
            "/component/owners",
            "/component/topics",
            "/component/authority_policy",
            "/versions/0/source_ref",
            "/versions/0/artifact_digest",
            "/versions/0/build_metadata",
            "/snapshots",
            "/dependencies",
            "/gaps",
        )
        if any(
            pointer == prefix or pointer.startswith(prefix + "/") for prefix in excluded
        ):
            return False
        if pointer.startswith("/versions/0/evidence/"):
            index = pointer.rsplit("/", 1)[-1]
            return index.isdigit() and int(index) < original_evidence_count
        if pointer.startswith("/channels/"):
            return pointer.rsplit("/", 1)[-1] in {
                "channel_id",
                "channel_type",
                "component_id",
            }
        return True

    retained: dict[str, tuple[str, str]] = {}
    for item in draft_entry["bindings"]:
        if item["binding_kind"] != "candidate-pointer":
            continue
        pointer = str(item["record_pointer"])
        if not allowed(pointer):
            continue
        try:
            unchanged = json_pointer_value(draft, pointer) == json_pointer_value(
                record, pointer
            )
        except KeyError:
            unchanged = False
        if not unchanged:
            raise ValueError(f"candidate-bound leaf changed unexpectedly: {pointer}")
        retained[pointer] = (
            str(item["source_pointer"]),
            str(item["derivation"]),
        )
    return retained


def exact_primary_sources(
    record: Mapping[str, Any],
    chart: str,
    facts: Mapping[str, Any],
    uris: Mapping[str, str],
) -> dict[str, str]:
    """Assign each source fact to one exact leaf and one exact official locator."""

    official_literal_uris = {
        CHART_SOURCE_REPOSITORY,
        GOVERNANCE_URI,
        MEMBERSHIP_URI,
        CHART_INDEX_URI,
        PGP_KEY_URI,
        *uris.values(),
    }
    primary = {
        pointer: value
        for pointer, value in leaf_values(record)
        if isinstance(value, str) and value in official_literal_uris
    }

    def bind(pointer: str, uri: str) -> None:
        if pointer not in base.leaf_pointers(record):
            raise ValueError(f"primary binding targets no record leaf: {pointer}")
        existing = primary.get(pointer)
        if existing is not None and existing != uri:
            raise ValueError(f"conflicting primary source for {pointer}")
        primary[pointer] = uri

    bind("/component/owners/0", GOVERNANCE_URI)
    bind("/component/owners/1", MEMBERSHIP_URI)
    bind("/versions/0/source_ref", uris["subtree"])
    bind("/versions/0/artifact_digest", uris["package"])
    root = "/versions/0/build_metadata/source_resolution"
    scalar_sources = {
        f"{root}/chart/publisher": GOVERNANCE_URI,
        f"{root}/chart/source_repository": CHART_SOURCE_REPOSITORY,
        f"{root}/chart/tag": uris["release"],
        f"{root}/chart/commit": uris["subtree"],
        f"{root}/chart/subtree": uris["subtree"],
        f"{root}/chart/package/content_sha256": uris["package"],
        f"{root}/chart/provenance/content_sha256": uris["provenance"],
        f"{root}/chart/provenance/pgp_fingerprint": PGP_KEY_URI,
        f"{root}/chart/license/spdx": uris["license"],
        f"{root}/upstream/repository": uris["upstream_source"],
        f"{root}/upstream/tag": uris["upstream_release"],
        f"{root}/upstream/commit": uris["upstream_source"],
        f"{root}/upstream/license/spdx": uris["upstream_license"],
        f"{root}/runtime_mapping/upstream_repository": uris["upstream_source"],
        f"{root}/runtime_mapping/upstream_tag": uris["upstream_release"],
        f"{root}/runtime_mapping/upstream_commit": uris["upstream_source"],
    }
    for pointer, uri in scalar_sources.items():
        bind(pointer, uri)
    runtime_assurance = record["versions"][0]["build_metadata"]["source_resolution"][
        "upstream"
    ]["runtime_assurance"]
    for key, value in runtime_assurance.items():
        if value not in {False, None}:
            bind(
                f"{root}/upstream/runtime_assurance/{base.json_pointer_escape(key)}",
                (
                    uris["upstream_security"]
                    if "signed" in key or "document" in key
                    else uris["upstream_release"]
                ),
            )
    for index, _runtime_name in enumerate(facts["runtime_names"]):
        prefix = f"{root}/runtime_mapping/components/{index}/source_admission"
        bind(f"{prefix}/upstream_tag", uris["upstream_release"])
        bind(f"{prefix}/upstream_commit", uris["upstream_source"])
    for index, snapshot in enumerate(record["snapshots"]):
        source_uri = uris["package"] if index == 0 else uris["provenance"]
        for field in (
            "resolved_uri",
            "upstream_ref",
            "content_hash",
            "media_type",
        ):
            bind(f"/snapshots/{index}/{field}", source_uri)
        for pointer in base.leaf_pointers(snapshot["coordinates"]):
            bind(f"/snapshots/{index}/coordinates{pointer}", source_uri)
    for index, dependency in enumerate(record["dependencies"]):
        for pointer in base.leaf_pointers(dependency):
            absolute = f"/dependencies/{index}{pointer}"
            if not absolute.endswith("/observed_at"):
                bind(absolute, uris["chart_lock"])
    third_party = record["versions"][0]["build_metadata"]["source_resolution"][
        "chart"
    ].get("third_party_dependencies", [])
    for index, dependency in enumerate(third_party):
        for pointer in base.leaf_pointers(dependency):
            bind(
                f"{root}/chart/third_party_dependencies/{index}{pointer}",
                uris["chart_lock"],
            )
    for index, channel in enumerate(record["channels"]):
        channel_uri = str(channel["canonical_uri"])
        bind(f"/channels/{index}/access", channel_uri)
        bind(f"/channels/{index}/publisher", GOVERNANCE_URI)
        bind(f"/channels/{index}/rights", uris["license"])
    return primary


def exact_derived_bindings(
    record: Mapping[str, Any], facts: Mapping[str, Any]
) -> dict[str, str]:
    root = "/versions/0/build_metadata/source_resolution"
    derived = {
        "/component/authority_policy": "review policy selected by this proposed resolution",
        f"{root}/review_state": "fixed proposed state prevents self-acceptance",
    }
    for index in range(len(record["component"]["topics"])):
        derived[f"/component/topics/{index}"] = (
            "topic assignment is a local routing projection, not source authority"
        )
    for index, _runtime_name in enumerate(facts["runtime_names"]):
        derived[f"{root}/runtime_mapping/components/{index}/canonical_runtime_id"] = (
            "canonical runtime identity is deterministically mapped from the exact "
            "candidate component"
        )
    for index, _channel in enumerate(record["channels"]):
        for field in (
            "version_strategy",
            "refresh_policy",
            "discovery_method",
            "confidence",
        ):
            derived[f"/channels/{index}/{field}"] = (
                "channel handling policy is derived from the immutable or mutable "
                "locator class"
            )
    return derived


def logical_binding(
    pointer: str,
    kind: str,
    derivation: str,
    *,
    source_pointer: str | None = None,
    source_uri: str | None = None,
    evidence: list[str] | None = None,
) -> dict[str, Any]:
    if kind == "candidate-pointer":
        effective_evidence = [CANDIDATE_EVIDENCE_PREFIX + str(source_pointer)]
    elif kind == "capture-pointer":
        effective_evidence = [CAPTURE_EVIDENCE_PREFIX + str(source_pointer)]
    elif kind == "primary-source":
        effective_evidence = [str(source_uri)]
    else:
        effective_evidence = evidence or [REVIEW_EVIDENCE]
    return {
        "record_pointer": pointer,
        "binding_kind": kind,
        "source_pointer": source_pointer,
        "source_uri": source_uri,
        "evidence": effective_evidence,
        "derivation": derivation,
    }


def binding_atom_core(binding: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(binding["binding_kind"])
    if kind in {"candidate-pointer", "capture-pointer"}:
        prefix = (
            CANDIDATE_EVIDENCE_PREFIX
            if kind == "candidate-pointer"
            else CAPTURE_EVIDENCE_PREFIX
        )
        return {
            "binding_kind": kind,
            "evidence_identity_prefix": prefix,
            "derivation": binding["derivation"],
        }
    if kind == "primary-source":
        return {
            "binding_kind": kind,
            "source_uri": binding["source_uri"],
            "derivation": binding["derivation"],
        }
    return {
        "binding_kind": kind,
        "evidence": binding["evidence"],
        "derivation": binding["derivation"],
    }


def binding_atom(core: Mapping[str, Any]) -> dict[str, Any]:
    atom_id = "binding-atom:" + base.sha256_bytes(base.canonical_bytes(core))
    return {"atom_id": atom_id, **core}


def validate_logical_bindings(
    record: Mapping[str, Any], bindings: Sequence[Mapping[str, Any]], chart: str
) -> None:
    leafs = base.leaf_pointers(record)
    pointers = [str(item.get("record_pointer")) for item in bindings]
    if pointers != leafs or len(pointers) != len(set(pointers)):
        raise ValueError(f"{chart} logical bindings do not enumerate exact leaves")
    for item in bindings:
        kind = item.get("binding_kind")
        source_pointer = item.get("source_pointer")
        source_uri = item.get("source_uri")
        evidence = item.get("evidence")
        if kind in {"candidate-pointer", "capture-pointer"}:
            if not isinstance(source_pointer, str) or not source_pointer.startswith(
                "/"
            ):
                raise ValueError(
                    f"{chart} pointer binding lacks an exact source pointer"
                )
            if source_uri is not None:
                raise ValueError(f"{chart} pointer binding carries a source URI")
            prefix = (
                CANDIDATE_EVIDENCE_PREFIX
                if kind == "candidate-pointer"
                else CAPTURE_EVIDENCE_PREFIX
            )
            if evidence != [prefix + source_pointer]:
                raise ValueError(f"{chart} pointer evidence identity is invalid")
        elif kind == "primary-source":
            if source_pointer is not None or not isinstance(source_uri, str):
                raise ValueError(f"{chart} primary binding source fields are invalid")
            if not source_uri.startswith("https://") or evidence != [source_uri]:
                raise ValueError(f"{chart} primary binding evidence is invalid")
        elif kind in {"derived", "control"}:
            if source_pointer is not None or source_uri is not None:
                raise ValueError(f"{chart} static binding carries a source locator")
            if not isinstance(evidence, list) or not evidence:
                raise ValueError(f"{chart} static binding lacks evidence")
        else:
            raise ValueError(f"{chart} has an unsupported binding kind")
    by_pointer = {str(item["record_pointer"]): item for item in bindings}
    root = "/versions/0/build_metadata/source_resolution/runtime_mapping/components"
    for index, _runtime_name in enumerate(CHART_FACTS[chart]["runtime_names"]):
        canonical = by_pointer[f"{root}/{index}/canonical_runtime_id"]
        if canonical["binding_kind"] != "derived":
            raise ValueError(f"{chart} canonical runtime identity is not derived")
        for field in ("upstream_tag", "upstream_commit"):
            admission = by_pointer[f"{root}/{index}/source_admission/{field}"]
            if admission["binding_kind"] != "primary-source":
                raise ValueError(
                    f"{chart} runtime source admission is not primary-bound"
                )


def reconstruct_normalized_bindings(
    record: Mapping[str, Any], entry: Mapping[str, Any], ledger: Mapping[str, Any]
) -> list[dict[str, Any]]:
    leafs = base.leaf_pointers(record)
    record_ledger = entry["binding_ledger"]
    tuples = record_ledger["tuples"]
    atoms = ledger["atoms"]
    if record_ledger["leaf_count"] != len(leafs):
        raise ValueError("normalized binding leaf count is invalid")
    if record_ledger["tuple_count"] != len(tuples) or len(tuples) != len(leafs):
        raise ValueError("normalized binding tuple count is invalid")
    if record_ledger["leaf_pointers_sha256"] != base.sha256_bytes(
        base.canonical_bytes(leafs)
    ):
        raise ValueError("normalized binding leaf enumeration is invalid")
    result: list[dict[str, Any]] = []
    for pointer, item in zip(leafs, tuples, strict=True):
        if not isinstance(item, list) or len(item) not in {1, 2}:
            raise ValueError("normalized binding tuple shape is invalid")
        index = item[0]
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < len(atoms)
        ):
            raise ValueError("normalized binding atom index is out of range")
        atom = atoms[index]
        kind = atom["binding_kind"]
        if kind in {"candidate-pointer", "capture-pointer"}:
            if len(item) != 2:
                raise ValueError("normalized pointer binding lacks its pointer payload")
            source_pointer = item[1]
            source_uri = None
            evidence = [atom["evidence_identity_prefix"] + source_pointer]
        else:
            if len(item) != 1:
                raise ValueError(
                    "normalized non-pointer binding carries a pointer payload"
                )
            source_pointer = None
            source_uri = atom.get("source_uri")
            evidence = [source_uri] if kind == "primary-source" else atom["evidence"]
        result.append(
            logical_binding(
                pointer,
                kind,
                str(atom["derivation"]),
                source_pointer=source_pointer,
                source_uri=source_uri,
                evidence=list(evidence),
            )
        )
    if record_ledger["logical_bindings_sha256"] != base.sha256_bytes(
        base.canonical_bytes(result)
    ):
        raise ValueError("normalized logical binding digest is invalid")
    return result


def normalize_binding_ledger(
    records: Mapping[str, bytes],
    entries: Sequence[dict[str, Any]],
    logical_by_path: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    cores: dict[str, dict[str, Any]] = {}
    for bindings in logical_by_path.values():
        for binding in bindings:
            atom = binding_atom(binding_atom_core(binding))
            atom_id = str(atom["atom_id"])
            if atom_id in cores and cores[atom_id] != atom:
                raise ValueError("binding atom hash collision")
            cores[atom_id] = atom
    atoms = [cores[atom_id] for atom_id in sorted(cores)]
    atom_indices = {atom["atom_id"]: index for index, atom in enumerate(atoms)}
    used: set[int] = set()
    logical_ledger: list[dict[str, Any]] = []
    for entry in sorted(entries, key=lambda item: item["path"]):
        path = str(entry["path"])
        bindings = list(logical_by_path[path])
        tuples: list[list[Any]] = []
        for binding in bindings:
            atom = binding_atom(binding_atom_core(binding))
            index = atom_indices[atom["atom_id"]]
            used.add(index)
            if binding["binding_kind"] in {"candidate-pointer", "capture-pointer"}:
                tuples.append([index, binding["source_pointer"]])
            else:
                tuples.append([index])
        record = base.strict_json_loads(records[Path(path).name])
        leafs = base.leaf_pointers(record)
        entry["binding_ledger"] = {
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
    if used != set(range(len(atoms))):
        raise ValueError("normalized binding ledger contains an unused atom")
    ledger = {
        "version": 2,
        "atom_order_algorithm": "binding-atom-id-lexicographic-v1",
        "leaf_order_algorithm": "canonical-json-leaf-pointers-v1",
        "atom_count": len(atoms),
        "atoms": atoms,
        "logical_ledger_sha256": base.sha256_bytes(
            base.canonical_bytes(logical_ledger)
        ),
    }
    for entry in entries:
        record = base.strict_json_loads(records[Path(entry["path"]).name])
        reconstructed = reconstruct_normalized_bindings(record, entry, ledger)
        if reconstructed != list(logical_by_path[entry["path"]]):
            raise ValueError("normalized binding reconstruction changed logical data")
    return ledger


def build_resolution_record(
    candidate: Mapping[str, Any],
    chart: str,
    draft_raw: bytes,
    draft_entry: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    draft = base.strict_json_loads(draft_raw)
    if not isinstance(draft, Mapping):
        raise ValueError(f"{chart} draft record is invalid")
    facts = CHART_FACTS[chart]
    if draft["versions"][0]["resolved_version"] != facts["chart_version"]:
        raise ValueError(f"{chart} researched version differs from accepted candidate")
    uris = chart_uris(chart, facts)
    runtime_mapping, runtime_exact = candidate_runtime_mapping(candidate, chart, facts)
    channels = make_channels(draft, chart, facts, uris)
    version_id = draft["versions"][0]["component_version_id"]
    source_resolution = {
        "review_state": "proposed",
        "chart": {
            "publisher": PUBLISHER,
            "source_repository": CHART_SOURCE_REPOSITORY,
            "tag": facts["chart_tag"],
            "commit": facts["chart_commit"],
            "subtree": f"charts/{chart}",
            "subtree_uri": uris["subtree"],
            "release_uri": uris["release"],
            "package": {
                "uri": uris["package"],
                "content_sha256": facts["package_sha256"],
                "materializer_fetch_state": "not-fetched",
            },
            "provenance": {
                "uri": uris["provenance"],
                "content_sha256": facts["provenance_sha256"],
                "pgp_fingerprint": PGP_FINGERPRINT,
                "key_uri": PGP_KEY_URI,
                "signature_verified_by_this_materializer": False,
            },
            "license": {"spdx": "Apache-2.0", "uri": uris["license"]},
            "governance": {
                "governance_uri": GOVERNANCE_URI,
                "membership_uri": MEMBERSHIP_URI,
                "strategy": "mutable-resolve-ref",
            },
            "mutable_channels": {
                "index_uri": CHART_INDEX_URI,
                "pgp_key_uri": PGP_KEY_URI,
                "strategy": "mutable-resolve-ref-and-content-hash",
                "may_replace_immutable_release": False,
            },
            "oci_publication": {
                "workflow_uri": uris["publish_workflow"],
                "manifest_digest": None,
                "state": "unresolved",
            },
        },
        "upstream": {
            "repository": f"https://github.com/argoproj/{facts['upstream_repo']}",
            "tag": facts["app_version"],
            "commit": facts["upstream_commit"],
            "source_uri": uris["upstream_source"],
            "release_uri": uris["upstream_release"],
            "license": {"spdx": "Apache-2.0", "uri": uris["upstream_license"]},
            "security_uri": uris["upstream_security"],
            "runtime_assurance": facts["runtime_assurance"],
            **(
                {
                    "schema_variants": {
                        "root_uri": uris["upstream_schema"],
                        "full_uri": uris["upstream_schema_full"],
                        "minimal_uri": uris["upstream_schema_minimal"],
                        "selected_variant": None,
                        "state": "catalogued_unselected",
                    }
                }
                if facts.get("schema_variants")
                else {}
            ),
        },
        "runtime_mapping": runtime_mapping,
    }
    record = dict(draft)
    record["review"] = {
        "status": "proposed",
        "reviewed_by": "unassigned-independent-reviewer",
        "reviewed_at": base.EXPECTED_OBSERVED_AT[:10],
        "evidence": [uris["subtree"], uris["release"], REVIEW_EVIDENCE],
    }
    record["component"] = {
        **draft["component"],
        "source_repo": CHART_SOURCE_REPOSITORY,
        "owners": ["Argo Project", "argoproj/argo-helm maintainers"],
        "topics": ["TOP-K8S-GITOPS", "TOP-K8S-OPERATORS", "TOP-X-PROVENANCE"],
        "authority_policy": "official-primary-source-plus-independent-review",
    }
    record["versions"] = [
        {
            **draft["versions"][0],
            "source_ref": facts["chart_commit"],
            "artifact_digest": facts["package_sha256"],
            "build_metadata": {"source_resolution": source_resolution},
            "evidence": list(
                dict.fromkeys(
                    [
                        *draft["versions"][0]["evidence"],
                        uris["subtree"],
                        uris["release"],
                        uris["package"],
                        uris["provenance"],
                    ]
                )
            ),
        }
    ]
    record["channels"] = channels
    channel_ids = {item["channel_type"]: item["channel_id"] for item in channels}
    record["snapshots"] = [
        {
            "snapshot_id": f"snapshot:p1-src-02:{chart}:package",
            "channel_id": channel_ids["package"],
            "component_version_id": version_id,
            "resolved_uri": uris["package"],
            "upstream_ref": facts["chart_tag"],
            "fetched_at": None,
            "observed_at": base.EXPECTED_OBSERVED_AT,
            "etag": None,
            "last_modified": None,
            "content_hash": facts["package_sha256"],
            "media_type": "application/gzip",
            "language": None,
            "coordinates": {"kind": "github-release-asset"},
            "status": "catalogued",
            "supersedes": [],
            "error_state": "independent hash verification pending",
        },
        {
            "snapshot_id": f"snapshot:p1-src-02:{chart}:provenance",
            "channel_id": channel_ids["provenance"],
            "component_version_id": version_id,
            "resolved_uri": uris["provenance"],
            "upstream_ref": facts["chart_tag"],
            "fetched_at": None,
            "observed_at": base.EXPECTED_OBSERVED_AT,
            "etag": None,
            "last_modified": None,
            "content_hash": facts["provenance_sha256"],
            "media_type": "application/pgp-signature",
            "language": None,
            "coordinates": {"pgp_fingerprint": PGP_FINGERPRINT},
            "status": "catalogued",
            "supersedes": [],
            "error_state": "independent PGP verification pending",
        },
    ]
    record["dependencies"] = []
    record["gaps"] = [
        {
            "gap_id": f"gap:p1-src-02:{chart}:independent-review-pending",
            "subject_kind": "component",
            "subject_id": record["component"]["component_id"],
            "state": "unresolved",
            "reason": "the source resolution is proposed and cannot accept itself",
            "blocking": True,
            "evidence": [uris["subtree"], uris["release"], REVIEW_EVIDENCE],
            "next_action": "an independent reviewer must reproduce the facts and create a distinct accepted identity",
            "detected_at": base.EXPECTED_OBSERVED_AT,
            "review_state": "proposed",
        }
    ]
    for runtime_name in facts["runtime_names"]:
        record["gaps"].extend(
            [
                {
                    "gap_id": f"gap:p1-src-02:{chart}:{runtime_name}:oci-manifest-digest-unresolved",
                    "subject_kind": "component",
                    "subject_id": RUNTIME_COMPONENTS[runtime_name],
                    "state": "unresolved",
                    "reason": "observed imageID digests are preserved but no canonical upstream OCI manifest digest was independently resolved",
                    "blocking": True,
                    "evidence": [uris["upstream_release"], REVIEW_EVIDENCE],
                    "next_action": "resolve the exact OCI manifest digest without treating a platform imageID as a source proof",
                    "detected_at": base.EXPECTED_OBSERVED_AT,
                    "review_state": "proposed",
                },
                {
                    "gap_id": f"gap:p1-src-02:{chart}:{runtime_name}:digest-source-admission-unverified",
                    "subject_kind": "component",
                    "subject_id": RUNTIME_COMPONENTS[runtime_name],
                    "state": "unresolved",
                    "reason": "digest-to-source, SBOM, cosign, and SLSA verification were not performed",
                    "blocking": True,
                    "evidence": [uris["upstream_source"], uris["upstream_release"]],
                    "next_action": "verify the runtime artifact through a separately governed admission path",
                    "detected_at": base.EXPECTED_OBSERVED_AT,
                    "review_state": "proposed",
                },
            ]
        )
    if chart == "argo-cd":
        dependency_id = "dep:p1-src-02:argo-cd:redis-ha"
        record["dependencies"] = [
            {
                "edge_id": dependency_id,
                "from_component_version_id": version_id,
                "to_component_version_id": "ver:helm:dandydeveloper/redis-ha@4.38.0",
                "relationship": "depends-on",
                "constraint": "4.38.0",
                "selected_version": "4.38.0",
                "scope": "runtime",
                "optional": True,
                "marker": "condition:redis-ha.enabled",
                "platform": None,
                "resolver": "Helm Chart.lock",
                "lock_or_sbom_uri": uris["chart_lock"],
                "observed_at": base.EXPECTED_OBSERVED_AT,
            }
        ]
        record["versions"][0]["build_metadata"]["source_resolution"]["chart"][
            "third_party_dependencies"
        ] = [
            {
                "name": "redis-ha",
                "version": "4.38.0",
                "repository": "https://dandydeveloper.github.io/charts/",
                "chart_lock_digest": "sha256:0d8b0161248c5ab2c77d62fc77d5ca28393f73f7b7a8abd5474b78bc969cab39",
                "rights": None,
                "rights_state": "unresolved",
                "inherit_argo_apache_license": False,
            }
        ]
        record["gaps"].append(
            {
                "gap_id": "gap:p1-src-02:argo-cd:redis-ha-rights-unresolved",
                "subject_kind": "dependency",
                "subject_id": dependency_id,
                "state": "unresolved",
                "reason": "the Argo chart license does not relicense bundled redis-ha",
                "blocking": True,
                "evidence": [uris["chart_lock"], REVIEW_EVIDENCE],
                "next_action": "resolve and review redis-ha rights independently",
                "detected_at": base.EXPECTED_OBSERVED_AT,
                "review_state": "proposed",
            }
        )

    candidate_bindings = retained_candidate_bindings(draft, record, draft_entry)
    candidate_bindings.update(runtime_exact)
    primary = exact_primary_sources(record, chart, facts, uris)
    derived = exact_derived_bindings(record, facts)
    bindings: list[dict[str, Any]] = []
    for pointer in base.leaf_pointers(record):
        candidate_match = candidate_bindings.get(pointer)
        if candidate_match is not None:
            source_pointer, derivation = candidate_match
            binding = logical_binding(
                pointer,
                "candidate-pointer",
                derivation,
                source_pointer=source_pointer,
            )
        elif pointer.endswith(("/observed_at", "/detected_at", "/reviewed_at")):
            binding = logical_binding(
                pointer,
                "capture-pointer",
                "copied or projected from the exact capture observation",
                source_pointer="/observed_at",
            )
        elif pointer in primary:
            binding = logical_binding(
                pointer,
                "primary-source",
                PRIMARY_DERIVATION,
                source_uri=primary[pointer],
            )
        elif pointer in derived:
            binding = logical_binding(pointer, "derived", derived[pointer])
        else:
            binding = logical_binding(pointer, "control", CONTROL_DERIVATION)
        bindings.append(binding)
    if len(bindings) > base.MAX_BINDINGS:
        raise ValueError(f"{chart} bindings exceed the configured bound")
    validate_logical_bindings(record, bindings, chart)
    raw = base.output_bytes(record)
    if len(raw) > base.MAX_RECORD_BYTES:
        raise ValueError(f"{chart} resolution record exceeds the configured bound")
    entry = {
        "path": f"{base.CANONICAL_RECORDS_PATH}/argo-{chart}-chart.json",
        "content_sha256": base.sha256_bytes(raw),
        "bytes": len(raw),
        "record_id": record["record_id"],
        "component_id": record["component"]["component_id"],
        "candidate_component_id": draft_entry["candidate_component_id"],
        "review_status": "proposed",
    }
    return record, entry, bindings


def build_resolution_set(
    candidate_raw: bytes,
    candidate: Mapping[str, Any],
    capture_result_raw: bytes,
    capture_result: Mapping[str, Any],
    capture_manifest_raw: bytes,
    capture_manifest: Mapping[str, Any],
    generator_raw: bytes,
    base_generator_raw: bytes,
    component_schema_raw: bytes,
    record_set_schema_raw: bytes,
    requirements_raw: bytes,
    validator_dependencies: Mapping[str, str],
    component_validator: Any,
    record_set_validator: Any,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    if base.sha256_bytes(base_generator_raw) != base.sha256_bytes(BASE_RAW):
        raise ValueError("captured base materializer differs from executed bytes")
    draft_records, draft_set = base.build_record_set(
        candidate_raw,
        candidate,
        capture_result_raw,
        capture_result,
        capture_manifest_raw,
        capture_manifest,
        base_generator_raw,
        component_schema_raw,
        record_set_schema_raw,
        requirements_raw,
        validator_dependencies,
        component_validator,
        record_set_validator,
    )
    draft_entries = {Path(item["path"]).name: item for item in draft_set["records"]}
    records: dict[str, bytes] = {}
    entries: list[dict[str, Any]] = []
    logical_by_path: dict[str, list[dict[str, Any]]] = {}
    for chart in sorted(CHART_FACTS):
        name = f"argo-{chart}-chart.json"
        record, entry, bindings = build_resolution_record(
            candidate, chart, draft_records[name], draft_entries[name]
        )
        base.validate_schema(component_validator, record, f"{chart} resolution record")
        raw = base.output_bytes(record)
        records[name] = raw
        entries.append(entry)
        logical_by_path[entry["path"]] = bindings
    binding_ledger = normalize_binding_ledger(records, entries, logical_by_path)
    gaps: list[dict[str, Any]] = []
    for chart, facts in sorted(CHART_FACTS.items()):
        uris = chart_uris(chart, facts)
        for runtime_name in facts["runtime_names"]:
            pointers = base.find_runtime_pointers(
                candidate, "quay.io/argoproj", runtime_name
            )
            gaps.extend(
                [
                    base.record_set_gap(
                        "oci_manifest_digest_unresolved",
                        RUNTIME_COMPONENTS[runtime_name],
                        "unresolved",
                        "observed imageID digests are retained but no canonical OCI manifest digest is accepted",
                        pointers,
                        "resolve the manifest digest in a separate immutable acquisition/admission step",
                    ),
                    base.record_set_gap(
                        "runtime_digest_source_verification_unresolved",
                        RUNTIME_COMPONENTS[runtime_name],
                        "unresolved",
                        "digest-to-source, SBOM, cosign, and SLSA verification were not performed",
                        pointers,
                        f"verify against {uris['upstream_release']} without inferring identity from the tag",
                    ),
                ]
            )
    gaps.append(
        base.record_set_gap(
            "candidate_component_absent",
            "cmp:github:argoproj/argo-events",
            "absent",
            "Argo Events is absent and unselected in the complete accepted candidate denominator",
            [
                "/components",
                "/discovery_scope/complete",
                "/integrity/exact_counts/components",
            ],
            "keep Events absent unless a later complete accepted denominator proves selection",
        )
    )
    generator = {
        "name": GENERATOR,
        "version": GENERATOR_VERSION,
        "source": GENERATOR_SOURCE,
        "source_sha256": base.sha256_bytes(generator_raw),
        "base_materializer_sha256": base.sha256_bytes(base_generator_raw),
        "component_schema_sha256": base.sha256_bytes(component_schema_raw),
        "record_set_schema_sha256": base.sha256_bytes(record_set_schema_raw),
        "requirements_sha256": base.sha256_bytes(requirements_raw),
        "validator_dependencies": dict(sorted(validator_dependencies.items())),
    }
    core = {
        "$schema": "https://github.com/cordanaLLM/knowledge/schemas/registry/reviewed-record-set.schema.json",
        "schema_version": SCHEMA_VERSION,
        "record_set_kind": "reviewed_component_record_set",
        "review": {
            "status": "proposed",
            "reviewed_by": "unassigned-independent-reviewer",
            "reviewed_at": base.EXPECTED_OBSERVED_AT[:10],
            "evidence": sorted(
                {
                    REVIEW_EVIDENCE,
                    GOVERNANCE_URI,
                    MEMBERSHIP_URI,
                    *(
                        chart_uris(chart, facts)["release"]
                        for chart, facts in CHART_FACTS.items()
                    ),
                }
            ),
        },
        "authority_state": "non_authoritative",
        "compile_eligible": False,
        "promote_eligible": False,
        "generator": generator,
        "input_artifacts": draft_set["input_artifacts"],
        "scope": draft_set["scope"],
        "binding_ledger": binding_ledger,
        "records": sorted(entries, key=lambda item: item["path"]),
        "gaps": sorted(gaps, key=lambda item: (item["target_id"], item["code"])),
        "counts": {
            "records": len(entries),
            "accepted_records": 0,
            "blocking_gaps": len(gaps),
        },
    }
    payload_sha256 = base.sha256_bytes(base.canonical_bytes(core))
    record_set = {
        "record_set_id": "reviewed-record-set:" + payload_sha256,
        "payload_sha256": payload_sha256,
        **core,
    }
    base.validate_schema(record_set_validator, record_set, "source-resolution set")
    return records, record_set


def materialize(
    repo_root: Path,
    candidate_path: Path,
    capture_result_path: Path,
    capture_manifest_path: Path,
) -> tuple[dict[str, bytes], dict[str, Any], list[tuple[Path, int, str, Any]]]:
    inputs = [
        (
            candidate_path,
            base.MAX_CANDIDATE_BYTES,
            "accepted candidate",
            base.EXPECTED_CANDIDATE_SHA256,
        ),
        (
            capture_result_path,
            base.MAX_CAPTURE_RESULT_BYTES,
            "capture result",
            base.EXPECTED_CAPTURE_RESULT_SHA256,
        ),
        (
            capture_manifest_path,
            base.MAX_CAPTURE_MANIFEST_BYTES,
            "capture manifest",
            base.EXPECTED_CAPTURE_MANIFEST_SHA256,
        ),
    ]
    captured: list[tuple[Path, int, str, Any]] = []
    raw_values: list[bytes] = []
    for path, maximum, label, expected in inputs:
        raw, identity = base.read_regular_capture(path, maximum=maximum, label=label)
        digest = base.sha256_bytes(raw)
        if digest != expected:
            raise ValueError(f"{label} digest differs from the accepted artifact")
        raw_values.append(raw)
        captured.append((path, maximum, digest, identity))
    values = [base.strict_json_loads(raw) for raw in raw_values]
    if not all(isinstance(value, Mapping) for value in values):
        raise ValueError("accepted artifacts must be JSON objects")
    contract_paths = [
        (
            repo_root / base.COMPONENT_SCHEMA_SOURCE,
            base.MAX_CONTRACT_BYTES,
            "component schema",
        ),
        (
            repo_root / base.RECORD_SET_SCHEMA_SOURCE,
            base.MAX_CONTRACT_BYTES,
            "record-set schema",
        ),
        (
            repo_root / base.REQUIREMENTS_SOURCE,
            base.MAX_CONTRACT_BYTES,
            "validator requirements",
        ),
        (BASE_PATH, base.MAX_CONTRACT_BYTES, "bounded base materializer"),
        (Path(__file__), base.MAX_CONTRACT_BYTES, "source-resolution materializer"),
    ]
    contract_raw: list[bytes] = []
    for path, maximum, label in contract_paths:
        raw, identity = base.read_regular_capture(path, maximum=maximum, label=label)
        contract_raw.append(raw)
        captured.append((path, maximum, base.sha256_bytes(raw), identity))
    dependencies = base.parse_requirement_closure(contract_raw[2])
    component_schema = base.strict_json_loads(contract_raw[0])
    record_set_schema = base.strict_json_loads(contract_raw[1])
    records, record_set = build_resolution_set(
        raw_values[0],
        values[0],
        raw_values[1],
        values[1],
        raw_values[2],
        values[2],
        contract_raw[4],
        contract_raw[3],
        contract_raw[0],
        contract_raw[1],
        contract_raw[2],
        dependencies,
        base.schema_validator(component_schema, "component schema"),
        base.schema_validator(record_set_schema, "record-set schema"),
    )
    for path, maximum, digest, identity in captured:
        base.recheck_regular(
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


def compact_record_set_bytes(record_set: Mapping[str, Any]) -> bytes:
    raw = base.canonical_bytes(record_set) + b"\n"
    if len(raw) > base.MAX_OUTPUT_BYTES:
        raise ValueError("materialized record set exceeds the configured byte bound")
    return raw


def validate_output_separation(
    output_dir: Path, protected_paths: Sequence[Path]
) -> None:
    """Reject any lexical same/ancestor/descendant output-input overlap."""

    if not protected_paths:
        raise ValueError("materializer output requires exact protected inputs")
    output = base.normalized_absolute(output_dir, "materializer output")
    for index, path in enumerate(protected_paths):
        protected = base.normalized_absolute(path, f"protected input {index}")
        if (
            output == protected
            or output in protected.parents
            or protected in output.parents
        ):
            raise ValueError(
                "materializer output overlaps an exact retained input/source path"
            )


def write_resolution_bundle(
    repo_root: Path,
    output_dir: Path,
    records: Mapping[str, bytes],
    record_set: Mapping[str, Any],
    protected_paths: Sequence[Path],
) -> None:
    """Write records normally and the normalized ledger without whitespace bloat."""

    validate_output_separation(output_dir, protected_paths)
    output_fd, output_info = base.open_scratch_directory(repo_root, output_dir)
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
                base.write_exact(records_fd, name, raw)
            base.verify_exact_directory_entries(
                records_fd, set(records), "materializer records directory"
            )
            base.verify_directory_path(
                output_dir / "records",
                records_info,
                "materializer records directory",
            )
        finally:
            os.close(records_fd)
        base.write_exact(
            output_fd, "reviewed-record-set.json", compact_record_set_bytes(record_set)
        )
        base.verify_exact_directory_entries(
            output_fd,
            {"records", "reviewed-record-set.json"},
            "materializer output directory",
        )
        base.verify_directory_path(
            output_dir, output_info, "materializer output directory"
        )
    finally:
        os.close(output_fd)


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
            repo_root, args.candidate, args.capture_result, args.capture_manifest
        )
        write_resolution_bundle(
            repo_root,
            output_dir,
            records,
            record_set,
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
                    "record_set_id": record_set["record_set_id"],
                    "records": len(records),
                    "accepted_records": 0,
                    "blocking_gaps": record_set["counts"]["blocking_gaps"],
                    "output_dir": base.repository_relative(repo_root, output_dir),
                },
                sort_keys=True,
            )
            + "\n"
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(
            f"Argo source-resolution materialization failed: {error}", file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
