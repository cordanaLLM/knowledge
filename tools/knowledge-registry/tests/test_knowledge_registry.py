from __future__ import annotations

import contextlib
import copy
import errno
import fcntl
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Mapping, Sequence
from unittest import mock
from urllib.parse import quote

TOOL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOL_ROOT.parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import capture_live as live
import knowledge_registry as kr

OBSERVED_AT = "2026-07-17T12:00:00Z"
NEXT_OBSERVED_AT = "2026-07-17T12:00:01Z"


def run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        env={
            "HOME": str(root),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "GIT_AUTHOR_DATE": "2026-07-16T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-07-16T00:00:00Z",
        },
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class RegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def repository(self, files: dict[str, str] | None = None) -> Path:
        root = self.base / f"repo-{len(list(self.base.iterdir()))}"
        root.mkdir()
        run_git(root, "init", "-q")
        run_git(root, "config", "user.name", "Registry Test")
        run_git(root, "config", "user.email", "registry@example.invalid")
        for relative, content in (files or {"README.md": "fixture\n"}).items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        run_git(root, "add", ".")
        run_git(root, "commit", "-q", "-m", "test: fixture")
        return root

    @staticmethod
    def fixture_files() -> dict[str, str]:
        return {
            "argocd-apps/demo.yaml": """apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: demo
  namespace: argocd
spec:
  source:
    repoURL: https://charts.example.invalid
    chart: demo
    targetRevision: 1.2.3
""",
            "apps/demo/Chart.yaml": """apiVersion: v2
name: demo
version: 1.2.3
appVersion: 4.5.6
dependencies:
  - name: child
    version: 2.0.0
    repository: https://charts.example.invalid
""",
            "apps/demo/values.yaml": """image:
  repository: ghcr.io/example/demo
  tag: v4.5.6
  digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
            "go.mod": """module example.invalid/demo

go 1.26

require github.com/google/uuid v1.6.0
""",
            "go.sum": """github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8dnRX8Qei2G4MR4zcDLoC8ZQYQzi2Gk=
golang.org/x/sys v0.34.0 h1:BJP2sWEmIv4KKHMmCGoC7nPD6L2F1JXfQN09RDMr4Ts=
""",
            "package.json": json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "dependencies": {"left-pad": "1.3.0"},
                }
            ),
            "requirements.txt": "requests==2.32.4\n",
            "main.tf": """terraform {
  required_version = "= 1.13.5"
  required_providers {
    random = {
      source = "hashicorp/random"
      version = "3.7.2"
    }
  }
}
""",
            "Dockerfile": """FROM docker.io/library/alpine:3.24@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
COPY requirements.txt /requirements.txt
RUN python3 -m pip install -r /requirements.txt
RUN apk add --no-cache ca-certificates=20250619-r0
""",
            ".github/workflows/ci.yml": """name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
""",
        }

    def minimal_builder(self) -> tuple[kr.Builder, str, str, str]:
        builder = kr.Builder()
        source = builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "1" * 64,
            metadata={"evidence_class": "test"},
        )
        component = builder.add_component(
            kind="library",
            ecosystem="pypi",
            name="demo",
            purl="pkg:pypi/demo",
        )
        version = builder.add_version(
            component,
            resolved_version="1.2.3",
            evidence=("fixture.json",),
        )
        builder.add_occurrence(
            component,
            version,
            source,
            locator="/demo",
            role="test",
            raw_value="demo==1.2.3",
        )
        return builder, source, component, version

    @staticmethod
    def popen_runner(
        stdout: bytes,
        *,
        stderr: bytes = b"",
        returncode: int = 0,
        delay: float = 0,
    ):
        script = (
            "import os,time;"
            f"time.sleep({delay!r});"
            f"os.write(1,{stdout!r});"
            f"os.write(2,{stderr!r});"
            f"raise SystemExit({returncode})"
        )

        def runner(_command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            # capture_live deliberately replaces the child environment with
            # FIXED_KUBECTL_ENV. setup-python's toolcache interpreter depends
            # on an LD_LIBRARY_PATH that this boundary must not inherit, while
            # the distro interpreter is self-contained under the fixed PATH.
            return subprocess.Popen(["/usr/bin/python3", "-c", script], **kwargs)

        return runner

    @staticmethod
    def reviewed_record(
        *,
        record_id: str = "record-demo",
        component_id: str = "component-demo",
        version_id: str = "version-demo",
        name: str = "demo",
        purl: str = "pkg:pypi/demo",
    ) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "record_kind": "reviewed_component",
            "record_id": record_id,
            "review": {
                "status": "accepted",
                "reviewed_by": "registry-test",
                "reviewed_at": "2026-07-17",
                "evidence": ["https://example.invalid/review"],
            },
            "component": {
                "component_id": component_id,
                "kind": "library",
                "ecosystem": "pypi",
                "namespace": None,
                "name": name,
                "aliases": [],
                "purl": purl,
                "cpe": None,
                "oci_repository": None,
                "chart_repository": None,
                "chart_name": None,
                "api_group": None,
                "gvk": [],
                "source_repo": "https://example.invalid/source",
                "lifecycle": "repository-used",
                "disposition": "selected",
                "owners": [],
                "topics": [],
                "authority_policy": "reviewed",
                "created_at": "2026-07-17",
            },
            "versions": [
                {
                    "component_version_id": version_id,
                    "component_id": component_id,
                    "purl": f"{purl}@1.2.3",
                    "constraint": None,
                    "resolved_version": "1.2.3",
                    "source_ref": None,
                    "artifact_digest": None,
                    "platform": None,
                    "build_metadata": {},
                    "release_time": None,
                    "observed_at": "2026-07-17T12:00:00Z",
                    "valid_from": None,
                    "valid_to": None,
                    "resolution_state": "resolved",
                    "evidence": ["https://example.invalid/release/1.2.3"],
                }
            ],
            "occurrences": [],
            "dependencies": [],
            "channels": [],
            "snapshots": [],
            "gaps": [],
        }

    @staticmethod
    def current_capture_generator() -> dict[str, object]:
        commit = (
            subprocess.run(
                ["/usr/bin/git", "rev-parse", "HEAD"],
                cwd=REPO_ROOT,
                check=True,
                stdout=subprocess.PIPE,
            )
            .stdout.decode()
            .strip()
        )
        sources = []
        for relative in kr.LIVE_CAPTURE_GENERATOR_PATHS:
            raw = (REPO_ROOT / relative).read_bytes()
            sources.append(
                {"path": relative, "sha256": kr.file_hash(raw), "size": len(raw)}
            )
        return {
            "git_commit": commit,
            "sources": sources,
            "ruleset_hash": kr.generator_identity()["ruleset_hash"],
        }

    @classmethod
    def v3_capture_receipt(cls, contract_version: int = 3) -> dict[str, object]:
        generator = cls.current_capture_generator()
        return {
            "record_kind": kr.LIVE_CAPTURE_RECORD_KIND,
            "contract_version": contract_version,
            "observed_at": OBSERVED_AT,
            "git_commit": generator["git_commit"],
            "cluster_uid": "cluster-uid",
            "context": "test-context",
            "capture_window": {
                "started_at": OBSERVED_AT,
                "completed_at": NEXT_OBSERVED_AT,
                "observation_tolerance_seconds": kr.LIVE_CAPTURE_TIME_TOLERANCE_SECONDS,
            },
            "required_surfaces": list(kr.LIVE_REQUIRED_SURFACES),
            "projection": dict(kr.LIVE_CAPTURE_PROJECTION),
            "kubectl": {
                "path": "/usr/bin/kubectl",
                "sha256": "sha256:" + "1" * 64,
                "size": 1,
            },
            "capture_generator": generator,
            "kubeconfig": {
                "source": {
                    "path": "/tmp/test-kubeconfig",
                    "sha256": "sha256:" + "2" * 64,
                    "size": 1,
                    "device": 1,
                    "inode": 1,
                },
                "execution_snapshot": {
                    "policy": "sealed-memfd",
                    "sha256": "sha256:" + "2" * 64,
                    "size": 1,
                },
            },
            "bounds": kr.live_capture_bounds(contract_version),
            "surfaces": {
                surface: {
                    "state": "unavailable",
                    "raw_hashes": [],
                    "resource_kinds": list(
                        kr.live_surface_resource_kinds(surface, contract_version)
                    ),
                    "artifacts": [],
                    "error": "query-failed",
                }
                for surface in kr.LIVE_REQUIRED_SURFACES
            },
        }

    def test_discovery_is_byte_deterministic_for_same_explicit_observation(
        self,
    ) -> None:
        root = self.repository(self.fixture_files())
        first = kr.discover_repo(root, observed_at=OBSERVED_AT)
        second = kr.discover_repo(root, observed_at=OBSERVED_AT)
        first_bytes = json.dumps(first, sort_keys=True, indent=2).encode()
        second_bytes = json.dumps(second, sort_keys=True, indent=2).encode()
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual([], kr.validate_manifest(first))
        self.assertFalse(kr.manifest_is_complete(first))
        self.assertFalse(first["authority_boundary"]["compile_eligible"])
        self.assertFalse(first["authority_boundary"]["promote_eligible"])

    def test_observation_time_changes_capture_and_preserves_previous_identity(
        self,
    ) -> None:
        root = self.repository(self.fixture_files())
        first = kr.discover_repo(root, observed_at=OBSERVED_AT)
        second = kr.discover_repo(
            root,
            observed_at=NEXT_OBSERVED_AT,
            base_manifest_id=first["manifest_id"],
            previous_observed_at=first["observation"]["observed_at"],
        )
        self.assertNotEqual(first["manifest_id"], second["manifest_id"])
        self.assertEqual(
            first["manifest_id"], second["reconciliation"]["previous_manifest_id"]
        )
        self.assertNotEqual(
            second["observation"]["observed_at"],
            second["observation"]["source_valid_at"],
        )
        self.assertEqual(
            "2026-07-16T00:00:00Z",
            second["observation"]["source_valid_at"],
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "strictly newer"):
            kr.discover_repo(
                root,
                observed_at=OBSERVED_AT,
                base_manifest_id=first["manifest_id"],
                previous_observed_at=first["observation"]["observed_at"],
            )

    def test_untracked_review_input_is_not_in_denominator(self) -> None:
        root = self.repository(self.fixture_files())
        first = kr.discover_repo(root, observed_at=OBSERVED_AT)
        prototype = root / "tools/knowledge-registry/prototype.json"
        prototype.parent.mkdir(parents=True, exist_ok=True)
        prototype.write_text('{"image":"evil.invalid/latest"}', encoding="utf-8")
        second = kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertEqual(first, second)

    def test_tracked_dirty_input_fails_before_capture(self) -> None:
        root = self.repository({"package.json": '{"name":"demo"}\n'})
        (root / "package.json").write_text('{"name":"changed"}\n', encoding="utf-8")
        with self.assertRaisesRegex(kr.RegistryInputError, "tracked worktree"):
            kr.discover_repo(root, observed_at=OBSERVED_AT)

    def test_tracked_symlink_fails_closed(self) -> None:
        root = self.repository()
        os.symlink("README.md", root / "package.json")
        run_git(root, "add", "package.json")
        run_git(root, "commit", "-q", "-m", "test: symlink")
        with self.assertRaisesRegex(kr.RegistryInputError, "unsupported mode"):
            kr.discover_repo(root, observed_at=OBSERVED_AT)

    def test_symlink_repository_root_fails_closed(self) -> None:
        root = self.repository(self.fixture_files())
        link = self.base / "repo-link"
        link.symlink_to(root, target_is_directory=True)
        with self.assertRaisesRegex(kr.RegistryInputError, "non-symlink"):
            kr.discover_repo(link, observed_at=OBSERVED_AT)

    def test_git_inventory_requires_terminating_nul(self) -> None:
        with self.assertRaisesRegex(kr.RegistryInputError, "truncated"):
            kr._parse_tree_inventory(
                b"100644 blob " + b"b" * 40 + b" 2\tpackage.json", 40
            )

    def test_tracked_file_count_bound_fails_closed(self) -> None:
        root = self.repository({"a.json": "{}", "b.json": "{}"})
        with mock.patch.object(kr, "MAX_TRACKED_FILES", 1):
            with self.assertRaisesRegex(kr.RegistryInputError, "file bound"):
                kr.repository_snapshot(root)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(kr.RegistryInputError, "duplicate JSON object key"):
            kr.parse_json_bytes(b'{"a":1,"a":2}', label="duplicate")

    def test_json_depth_and_size_are_bounded(self) -> None:
        nested: object = 0
        for _ in range(kr.MAX_JSON_DEPTH + 1):
            nested = [nested]
        with self.assertRaisesRegex(kr.RegistryInputError, "depth bound"):
            kr.parse_json_bytes(json.dumps(nested).encode(), label="nested")
        with self.assertRaisesRegex(kr.RegistryInputError, "byte bound"):
            kr.parse_json_bytes(b"{}", label="small", max_bytes=1)
        with mock.patch.object(kr, "MAX_JSON_NODES", 3):
            with self.assertRaisesRegex(kr.RegistryInputError, "structural nodes"):
                kr.parse_json_bytes(b"[1,2,3]", label="wide")

    def test_builder_record_bounds_are_enforced(self) -> None:
        builder = kr.Builder()
        with mock.patch.object(kr, "MAX_COMPONENTS", 1):
            builder.add_component(kind="library", ecosystem="pypi", name="one")
            with self.assertRaisesRegex(kr.RegistryInputError, "components"):
                builder.add_component(kind="library", ecosystem="pypi", name="two")

    def test_read_revalidates_file_identity(self) -> None:
        target = self.base / "identity.txt"
        target.write_text("identity", encoding="utf-8")
        with mock.patch.object(
            kr,
            "_identity_from_stat",
            side_effect=[(1, 1, 8, 1, 1), (1, 2, 8, 1, 1)],
        ):
            with self.assertRaisesRegex(kr.RegistryInputError, "changed"):
                kr.read_regular_file(target, max_bytes=64, label="identity")

    def test_symlink_json_input_is_rejected(self) -> None:
        real = self.base / "real.json"
        real.write_text("{}", encoding="utf-8")
        link = self.base / "link.json"
        link.symlink_to(real)
        with self.assertRaises(kr.RegistryInputError):
            kr.load_json(str(link))

    def test_untrusted_executable_is_rejected(self) -> None:
        executable = self.base / "git"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o777)
        with self.assertRaisesRegex(kr.RegistryInputError, "writable|owned by root"):
            kr.trusted_executable_identity(executable)

    def test_executable_replacement_is_detected_after_subprocess(self) -> None:
        before = {
            "path": "/usr/bin/true",
            "sha256": "sha256:" + "1" * 64,
            "size": 1,
            "device": 1,
            "inode": 1,
        }
        after = {**before, "sha256": "sha256:" + "2" * 64}
        with mock.patch.object(
            kr, "trusted_executable_identity", side_effect=[before, after]
        ):
            with self.assertRaisesRegex(kr.RegistryInputError, "changed"):
                kr.run_trusted_executable(Path("/usr/bin/true"), (), cwd=self.base)

    def test_output_refuses_overwrite_and_symlink(self) -> None:
        target = self.base / "output.json"
        target.write_text("existing", encoding="utf-8")
        with self.assertRaisesRegex(kr.RegistryInputError, "fresh non-symlink"):
            kr.write_json({}, str(target))
        target.unlink()
        target.symlink_to(self.base / "elsewhere")
        with self.assertRaisesRegex(kr.RegistryInputError, "fresh non-symlink"):
            kr.write_json({}, str(target))

    def test_output_size_is_bounded(self) -> None:
        with mock.patch.object(kr, "MAX_SERIALIZED_OUTPUT_BYTES", 8):
            with self.assertRaisesRegex(kr.RegistryInputError, "byte bound"):
                kr.write_json({"long": "value"}, "-")

    def test_candidate_ids_and_duplicate_ids_fail_validation(self) -> None:
        builder, _, _, _ = self.minimal_builder()
        manifest = builder.manifest()
        tampered = json.loads(json.dumps(manifest))
        tampered["components"][0]["component_id"] = "cmp-" + "f" * 24
        self.assertTrue(kr.validate_manifest(tampered))
        duplicate = json.loads(json.dumps(manifest))
        duplicate["components"].append(dict(duplicate["components"][0]))
        duplicate = kr.seal_manifest(duplicate)
        self.assertTrue(
            any(
                "duplicate component_id" in item
                for item in kr.validate_manifest(duplicate)
            )
        )

    def test_every_required_channel_class_has_explicit_state(self) -> None:
        builder, _, component, _ = self.minimal_builder()
        manifest = builder.manifest()
        record = next(
            item for item in manifest["components"] if item["component_id"] == component
        )
        self.assertEqual(
            sorted(kr.OFFICIAL_CHANNEL_TYPES),
            sorted(item["channel_type"] for item in record["official_channels"]),
        )
        self.assertEqual(
            {"unresolved"},
            {item["availability_state"] for item in record["official_channels"]},
        )
        self.assertTrue(
            all(
                item["review_state"] == "needs-review"
                for item in record["official_channels"]
            )
        )

    def test_all_supported_channel_states_validate_and_unknown_state_fails(
        self,
    ) -> None:
        states = ["available", "absent", "ambiguous", "unresolved", "unavailable"]
        channels = []
        for index, channel_type in enumerate(kr.OFFICIAL_CHANNEL_TYPES):
            state = states[index % len(states)]
            channel = {
                "channel_id": f"channel-{index}",
                "channel_type": channel_type,
                "availability_state": state,
                "review_state": "accepted",
            }
            if state == "available":
                channel["canonical_uri"] = f"https://example.invalid/{channel_type}"
            channels.append(channel)
        builder = kr.Builder()
        source = builder.add_source(
            "channels", "test", content_hash="sha256:" + "3" * 64
        )
        component = builder.add_component(
            kind="library",
            ecosystem="pypi",
            name="channels",
            official_channels=channels,
        )
        version = builder.add_version(component, resolved_version="1.0.0")
        builder.add_occurrence(
            component, version, source, locator="/", role="test", raw_value="channels"
        )
        manifest = builder.manifest()
        self.assertEqual([], kr.validate_manifest(manifest))
        self.assertEqual(
            set(states),
            {
                item["availability_state"]
                for item in next(
                    value
                    for value in manifest["components"]
                    if value["component_id"] == component
                )["official_channels"]
            },
        )
        broken = json.loads(json.dumps(manifest))
        broken["components"][0]["official_channels"][0][
            "availability_state"
        ] = "unknown"
        broken = kr.seal_manifest(broken)
        self.assertTrue(
            any(
                "unsupported availability_state" in item
                for item in kr.validate_manifest(broken)
            )
        )

    def test_mutable_latest_and_zero_digest_are_typed_gaps(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "images.yaml", "yaml", content_hash="sha256:" + "4" * 64
        )
        builder.add_image("docker.io/library/nginx:latest", source, "line:1", "image")
        builder.add_image(
            "docker.io/library/alpine:3.24@sha256:" + "0" * 64,
            source,
            "line:2",
            "image",
        )
        git_component = builder.add_component(
            kind="git-repository",
            ecosystem="git",
            name="example.invalid/demo",
        )
        builder.add_version(
            git_component,
            source_ref="refs/heads/main",
            resolution_state="resolved",
        )
        manifest = builder.manifest()
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertIn("mutable-ref", gap_types)
        self.assertIn("exact-version-unresolved", gap_types)
        self.assertIn("oci-digest-invalid", gap_types)
        self.assertIn("transitive-inventory-unavailable", gap_types)
        self.assertTrue(
            any(
                item["gap_type"] == "mutable-ref"
                and item.get("component_id") == git_component
                for item in manifest["gaps"]
            )
        )

    def test_malformed_oci_references_are_opaque_gapped_placeholders(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "images.yaml", "yaml", content_hash="sha256:" + "4" * 64
        )
        root = builder.add_component(kind="workload", ecosystem="local", name="root")
        root_version = builder.add_version(root, resolved_version="1")
        digest = "sha256:" + "a" * 64
        valid = f"ghcr.io/example/valid:v1@{digest}"
        valid_component, _, _ = builder.add_image(
            valid, source, "line:0", "container-image", root_id=root
        )
        malformed = (
            f"ghcr.io/example/duplicate:v1@{digest}@{digest}",
            f"https://user:credential@example.invalid/repo@{digest}",
            "ghcr.io/example/wrong@sha512:" + "b" * 128,
        )
        placeholder_ids = []
        for index, reference in enumerate(malformed, start=1):
            component_id, version_id, occurrence_id = builder.add_image(
                reference,
                source,
                f"line:{index}",
                "container-image",
                root_id=root,
                metadata={"untrusted_reference": reference},
            )
            placeholder_ids.append((component_id, version_id, occurrence_id))
            builder.add_edge(
                root_version,
                version_id,
                relationship="uses-image",
                source_occurrence_id=occurrence_id,
            )

        self.assertEqual(
            placeholder_ids[0],
            builder.add_image(
                malformed[0],
                source,
                "line:1",
                "container-image",
                root_id=root,
                metadata={"untrusted_reference": malformed[0]},
            ),
        )
        different_locator, _, _ = builder.add_image(
            malformed[0], source, "line:4", "container-image", root_id=root
        )
        self.assertNotEqual(placeholder_ids[0][0], different_locator)

        manifest = builder.manifest()
        serialized = json.dumps(manifest, sort_keys=True)
        for reference in malformed:
            self.assertNotIn(reference, serialized)
        self.assertNotIn("credential", serialized)
        placeholders = [
            item
            for item in manifest["components"]
            if item["kind"] == "invalid-oci-image-reference"
        ]
        self.assertEqual(4, len(placeholders))
        for component in placeholders:
            self.assertFalse(component["official_channel_required"])
            self.assertNotIn("purl", component)
            self.assertNotIn("oci_repository", component.get("metadata", {}))
            self.assertEqual(
                {"invalid_reference_reason", "observed_reference_sha256"},
                set(component["metadata"]),
            )
        valid_record = next(
            item
            for item in manifest["components"]
            if item["component_id"] == valid_component
        )
        self.assertEqual(
            "ghcr.io/example/valid", valid_record["metadata"]["oci_repository"]
        )
        placeholder_occurrences = [
            item
            for item in manifest["occurrences"]
            if item["component_id"]
            in {component["component_id"] for component in placeholders}
        ]
        self.assertTrue(placeholder_occurrences)
        self.assertTrue(
            all(
                item["raw_value"].startswith("invalid-image-reference:sha256:")
                for item in placeholder_occurrences
            )
        )
        self.assertTrue(
            all(
                set(item.get("metadata", {}))
                == {"invalid_reference_reason", "observed_reference_sha256"}
                for item in placeholder_occurrences
            )
        )
        invalid_gaps = [
            item
            for item in manifest["gaps"]
            if item["gap_type"] == "oci-reference-invalid"
        ]
        self.assertEqual(4, len(invalid_gaps))
        self.assertEqual("gapped", manifest["completeness"]["identity"]["state"])
        self.assertEqual([], kr.unsafe_candidate_locator_pointers(manifest))
        self.assertEqual([], kr.validate_manifest(manifest))

    def test_live_malformed_desired_image_never_infers_runtime_repository(self) -> None:
        digest = "sha256:" + "c" * 64
        malformed = f"ghcr.io/example/demo:v1@{digest}@{digest}"
        payload = {
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {},
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "namespace": "demo",
                        "name": "malformed-image",
                        "uid": "pod-uid",
                    },
                    "spec": {"containers": [{"name": "main", "image": malformed}]},
                    "status": {
                        "phase": "Pending",
                        "containerStatuses": [
                            {
                                "name": "main",
                                "image": malformed,
                                "imageID": "containerd://" + digest,
                                "ready": False,
                                "restartCount": 0,
                            }
                        ],
                    },
                }
            ],
        }
        export = self.base / "malformed-live-image.json"
        export.write_text(json.dumps(payload), encoding="utf-8")
        manifest = kr.import_live([str(export)])
        serialized = json.dumps(manifest, sort_keys=True)
        self.assertNotIn(malformed, serialized)
        placeholders = [
            item
            for item in manifest["components"]
            if item["kind"] == "invalid-oci-image-reference"
        ]
        self.assertEqual(2, len(placeholders))
        placeholder_components = {item["component_id"] for item in placeholders}
        placeholder_versions = {
            item["component_version_id"]
            for item in manifest["versions"]
            if item["component_id"] in placeholder_components
        }
        relationships = {
            edge["relationship"]
            for edge in manifest["dependency_edges"]
            if edge["to_component_version_id"] in placeholder_versions
        }
        self.assertEqual({"runs-image", "uses-image"}, relationships)
        reasons = {
            gap.get("metadata", {}).get("invalid_reference_reason")
            for gap in manifest["gaps"]
            if gap["gap_type"] == "oci-reference-invalid"
        }
        self.assertEqual(
            {
                "multiple-digest-separators",
                "runtime-digest-without-valid-desired-reference",
            },
            reasons,
        )
        self.assertFalse(
            any(
                component.get("metadata", {}).get("oci_repository")
                for component in placeholders
            )
        )
        self.assertEqual([], kr.unsafe_candidate_locator_pointers(manifest))
        self.assertEqual([], kr.validate_manifest(manifest))

    def test_live_desired_image_evidence_resolves_for_every_workload_kind(
        self,
    ) -> None:
        image = "ghcr.io/example/demo@sha256:" + "a" * 64
        pod_spec = {
            "initContainers": [{"name": "init", "image": image}],
            "containers": [{"name": "main", "image": image}],
            "ephemeralContainers": [{"name": "debug", "image": image}],
        }
        expected_prefixes = {
            "Pod": "/items/0/spec",
            "Deployment": "/items/0/spec/template/spec",
            "StatefulSet": "/items/0/spec/template/spec",
            "DaemonSet": "/items/0/spec/template/spec",
            "ReplicaSet": "/items/0/spec/template/spec",
            "Job": "/items/0/spec/template/spec",
            "CronJob": "/items/0/spec/jobTemplate/spec/template/spec",
        }

        for kind, expected_prefix in expected_prefixes.items():
            with self.subTest(kind=kind):
                if kind == "Pod":
                    spec = copy.deepcopy(pod_spec)
                elif kind == "CronJob":
                    spec = {
                        "jobTemplate": {
                            "spec": {"template": {"spec": copy.deepcopy(pod_spec)}}
                        }
                    }
                else:
                    spec = {"template": {"spec": copy.deepcopy(pod_spec)}}
                item = {
                    "apiVersion": (
                        "batch/v1" if kind in {"Job", "CronJob"} else "apps/v1"
                    ),
                    "kind": kind,
                    "metadata": {
                        "namespace": "demo",
                        "name": kind.lower(),
                        "uid": f"{kind.lower()}-uid",
                    },
                    "spec": spec,
                }
                builder = kr.Builder()
                source = builder.add_source(
                    f"{kind.lower()}.json",
                    "test",
                    content_hash="sha256:" + "b" * 64,
                )
                kr.import_workload_item(builder, source, item, 0)
                manifest = builder.manifest()
                occurrences = [
                    occurrence
                    for occurrence in manifest["occurrences"]
                    if occurrence["role"].endswith("-desired-image")
                ]
                self.assertEqual(3, len(occurrences))
                payload: Any = {"items": [item]}
                for occurrence in occurrences:
                    locator = occurrence["evidence_locator"]
                    self.assertTrue(locator.startswith(expected_prefix + "/"))
                    resolved = payload
                    for token in locator.lstrip("/").split("/"):
                        token = token.replace("~1", "/").replace("~0", "~")
                        resolved = (
                            resolved[int(token)]
                            if isinstance(resolved, list)
                            else resolved[token]
                        )
                    self.assertEqual(image, resolved)

                self.assertEqual([], kr.unsafe_candidate_locator_pointers(manifest))
                self.assertEqual([], kr.validate_manifest(manifest))

    def test_live_import_rejects_an_unresolved_occurrence_evidence_pointer(
        self,
    ) -> None:
        image = "ghcr.io/example/demo@sha256:" + "a" * 64
        export = self.base / "replicaset.json"
        export.write_text(
            json.dumps(
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSetList",
                    "items": [
                        {
                            "apiVersion": "apps/v1",
                            "kind": "ReplicaSet",
                            "metadata": {
                                "namespace": "demo",
                                "name": "demo",
                                "uid": "replicaset-uid",
                            },
                            "spec": {
                                "template": {
                                    "spec": {
                                        "containers": [{"name": "main", "image": image}]
                                    }
                                }
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(
            kr,
            "workload_pod_spec_pointer",
            return_value="/items/0/spec",
        ):
            with self.assertRaisesRegex(
                kr.RegistryInputError,
                "live occurrence evidence pointer is unresolved",
            ):
                kr.import_live([str(export)])

    def test_live_missing_image_id_binds_gap_to_existing_status_object(self) -> None:
        image = "ghcr.io/example/demo@sha256:" + "a" * 64
        payload = {
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "namespace": "demo",
                        "name": "pending",
                        "uid": "pod-uid",
                    },
                    "spec": {"containers": [{"name": "main", "image": image}]},
                    "status": {
                        "phase": "Pending",
                        "containerStatuses": [
                            {"name": "main", "ready": False, "restartCount": 0}
                        ],
                    },
                }
            ],
        }
        export = self.base / "missing-image-id.json"
        export.write_text(json.dumps(payload), encoding="utf-8")
        manifest = kr.import_live([str(export)])
        gap = next(
            item
            for item in manifest["gaps"]
            if item["gap_type"] == "live-imageid-missing"
        )
        self.assertTrue(
            gap["evidence"][0].endswith("#/items/0/status/containerStatuses/0")
        )
        source_payloads = {
            gap["source_id"]: payload,
        }
        self.assertGreater(
            kr.validate_live_evidence_pointers(manifest, source_payloads),
            0,
        )

    def test_live_import_rejects_an_unresolved_gap_evidence_pointer(self) -> None:
        export = self.base / "empty-pods.json"
        export.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "PodList",
                    "items": [],
                }
            ),
            encoding="utf-8",
        )

        def add_bad_gap(builder: kr.Builder) -> None:
            source_id = next(
                source_id
                for source_id, source in builder.sources.items()
                if source["source_type"] == "live-export"
            )
            builder.add_gap(
                "live-test-evidence-unresolved",
                "fixture",
                source_id=source_id,
                evidence=(f"{builder.sources[source_id]['evidence_uri']}#/missing",),
            )

        with mock.patch.object(kr, "reconcile_cluster_sboms", add_bad_gap):
            with self.assertRaisesRegex(
                kr.RegistryInputError,
                "live gap evidence pointer is unresolved",
            ):
                kr.import_live([str(export)])

    def test_conflicting_exact_tag_digests_fail_closed(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "images.yaml", "yaml", content_hash="sha256:" + "5" * 64
        )
        builder.add_image(
            "ghcr.io/example/demo:v1@sha256:" + "a" * 64,
            source,
            "line:1",
            "image",
        )
        builder.add_image(
            "ghcr.io/example/demo:v1@sha256:" + "b" * 64,
            source,
            "line:2",
            "image",
        )
        manifest = builder.manifest()
        self.assertTrue(
            any(
                item["gap_type"] == "oci-tag-digest-conflict"
                for item in manifest["gaps"]
            )
        )
        self.assertEqual("gapped", manifest["completeness"]["identity"]["state"])

    def test_tag_digest_conflict_gap_merges_across_candidates(self) -> None:
        def candidate(digest_letters: str) -> dict[str, Any]:
            builder = kr.Builder()
            source = builder.add_source(
                "images.yaml", "yaml", content_hash="sha256:" + "5" * 64
            )
            for index, letter in enumerate(digest_letters, 1):
                builder.add_image(
                    "ghcr.io/example/demo:v1@sha256:" + letter * 64,
                    source,
                    f"line:{index}",
                    "image",
                )
            return builder.manifest()

        merged = kr.merge_manifests([candidate("ab"), candidate("abcd")])
        self.assertEqual([], kr.validate_manifest(merged))
        gap = next(
            item
            for item in merged["gaps"]
            if item["gap_type"] == "oci-tag-digest-conflict"
        )
        self.assertEqual({"tag": "v1"}, gap["metadata"])
        self.assertEqual(
            ["sha256:" + letter * 64 for letter in "abcd"], gap["evidence"]
        )

    def test_lockfile_absence_and_transitive_go_checksums_are_visible(self) -> None:
        root = self.repository(self.fixture_files())
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertIn("helm-lock-missing", gap_types)
        self.assertIn("node-lock-missing", gap_types)
        self.assertIn("terraform-lock-missing", gap_types)
        self.assertTrue(
            any(
                item["directness"] == "transitive" and item["role"] == "go-sum-module"
                for item in manifest["occurrences"]
            )
        )

    def test_tracked_docker_and_helm_lock_inputs_are_read_safely(self) -> None:
        root = self.repository(
            {
                "Dockerfile": """FROM docker.io/library/python:3.14@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
COPY requirements.txt /requirements.txt
RUN python3 -m pip install -r /requirements.txt
""",
                "requirements.txt": "requests==2.32.4\n",
                "chart/Chart.yaml": """apiVersion: v2
name: root
version: 1.0.0
dependencies:
  - name: child
    version: 2.0.0
    repository: https://charts.example.invalid
""",
                "chart/Chart.lock": """dependencies:
  - name: child
    repository: https://charts.example.invalid
    version: 2.0.0
digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
generated: 2026-07-16T00:00:00Z
""",
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertEqual([], kr.validate_manifest(manifest))
        self.assertTrue(
            any(
                item["role"] == "docker-requirement"
                and item["raw_value"] == "requests==2.32.4"
                for item in manifest["occurrences"]
            )
        )
        self.assertTrue(
            any(
                item["role"] == "helm-locked-dependency"
                for item in manifest["occurrences"]
            )
        )

    def test_pypi_dependency_names_are_canonical(self) -> None:
        root = self.repository(
            {
                "Dockerfile": """FROM docker.io/library/python:3.14@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
COPY requirements.txt /requirements.txt
RUN python3 -m pip install -r /requirements.txt
""",
                "requirements.txt": "PyYAML==6.0.3\ntyping_extensions==4.12.2\n",
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertEqual([], kr.validate_manifest(manifest))
        names = {
            item["name"]
            for item in manifest["components"]
            if item["ecosystem"] == "pypi"
        }
        self.assertIn("pyyaml", names)
        self.assertIn("typing-extensions", names)
        self.assertNotIn("PyYAML", names)
        self.assertNotIn("typing_extensions", names)

    def test_docker_copy_inputs_resolve_outside_the_materialized_view(self) -> None:
        # .py inputs are not discovery files; only HEAD-verified worktree bytes hash them.
        root = self.repository(
            {
                "apps/demo/Dockerfile": (
                    "FROM docker.io/library/python:3.14@sha256:" + "b" * 64 + "\n"
                    "COPY patch_one.py /app/patch_one.py\n"
                ),
                "apps/demo/patch_one.py": "print('one')\n",
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertNotIn("docker-copy-input-unresolved", gap_types)
        occurrence = next(
            item
            for item in manifest["occurrences"]
            if item["role"] == "docker-copy-input"
        )
        self.assertEqual("patch_one.py", occurrence["raw_value"])
        version = next(
            item
            for item in manifest["versions"]
            if item["component_version_id"] == occurrence["component_version_id"]
        )
        self.assertEqual(kr.file_hash(b"print('one')\n"), version["artifact_digest"])

    def test_docker_copy_context_directory_and_glob_expansion(self) -> None:
        root = self.repository(
            {
                "apps/infra/exporter/Dockerfile": (
                    "FROM docker.io/library/golang:1.27@sha256:" + "b" * 64 + "\n"
                    "COPY sibling /src/sibling\n"
                    "COPY exporter/go.mod exporter/go.sum ./\n"
                    "COPY exporter/*.go /src/\n"
                ),
                "apps/infra/sibling/go.mod": "module example.invalid/sibling\n",
                "apps/infra/sibling/pkg/parser.go": "package pkg\n",
                "apps/infra/exporter/go.mod": "module example.invalid/exporter\n",
                "apps/infra/exporter/go.sum": "\n",
                "apps/infra/exporter/main.go": "package main\n",
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertNotIn("docker-copy-input-unresolved", gap_types)
        copies = {
            item["raw_value"]: item
            for item in manifest["occurrences"]
            if item["role"] == "docker-copy-input"
        }
        self.assertEqual(
            {"sibling", "exporter/go.mod", "exporter/go.sum", "exporter/*.go"},
            set(copies),
        )
        components = {item["component_id"]: item for item in manifest["components"]}
        self.assertEqual(
            "apps/infra/sibling",
            components[copies["sibling"]["component_id"]]["name"],
        )
        self.assertEqual(
            "apps/infra/exporter/main.go",
            components[copies["exporter/*.go"]["component_id"]]["name"],
        )
        tree_entries = [
            ["go.mod", kr.file_hash(b"module example.invalid/sibling\n")],
            ["pkg/parser.go", kr.file_hash(b"package pkg\n")],
        ]
        tree_digest = kr.file_hash(kr.canonical_json(tree_entries).encode("utf-8"))
        version = next(
            item
            for item in manifest["versions"]
            if item["component_version_id"] == copies["sibling"]["component_version_id"]
        )
        self.assertEqual(tree_digest, version["artifact_digest"])

    def test_untracked_docker_copy_input_is_still_a_typed_gap(self) -> None:
        root = self.repository(
            {
                "Dockerfile": (
                    "FROM docker.io/library/alpine:3.24@sha256:" + "b" * 64 + "\n"
                    "COPY loose.txt /srv/\n"
                )
            }
        )
        (root / "loose.txt").write_text("untracked\n", encoding="utf-8")
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        gap = next(
            item
            for item in manifest["gaps"]
            if item["gap_type"] == "docker-copy-input-unresolved"
        )
        self.assertEqual(
            "declared-directory", gap["metadata"]["build_context_resolution"]
        )

    def test_from_platform_flag_keeps_digest_pinned_base_resolved(self) -> None:
        digest = "sha256:" + "c" * 64
        root = self.repository(
            {
                "Dockerfile": (
                    "ARG BASE_IMAGE\n"
                    "FROM --platform=$BUILDPLATFORM "
                    f"docker.io/library/golang:1.27-alpine@{digest} AS build\n"
                    "FROM ${BASE_IMAGE}\n"
                )
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        base_gaps = [
            item
            for item in manifest["gaps"]
            if item["gap_type"] == "docker-base-unresolved"
        ]
        self.assertEqual(1, len(base_gaps))
        self.assertEqual(
            ["BASE_IMAGE"], base_gaps[0]["metadata"]["unresolved_arguments"]
        )
        self.assertNotIn(
            "oci-platform-invalid", {item["gap_type"] for item in manifest["gaps"]}
        )
        occurrence = next(
            item
            for item in manifest["occurrences"]
            if item["role"] == "docker-base-image"
            and item["raw_value"].endswith(digest)
        )
        version = next(
            item
            for item in manifest["versions"]
            if item["component_version_id"] == occurrence["component_version_id"]
        )
        self.assertEqual(digest, version["artifact_digest"])

    def test_packer_path_root_relative_file_input_resolves(self) -> None:
        root = self.repository(
            {
                "packer/template.pkr.hcl": (
                    "packer {\n  required_plugins {\n  }\n}\n"
                    'source "null" "demo" {}\n'
                    "build {\n"
                    '  provisioner "file" {\n'
                    '    source      = "${path.root}/../ansible/files/ptb.sources"\n'
                    '    destination = "/etc/chrony/ptb.sources"\n'
                    "  }\n"
                    "}\n"
                ),
                "ansible/files/ptb.sources": "server ptbtime1.ptb.de iburst\n",
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertNotIn(
            "packer-file-input-unresolved",
            {item["gap_type"] for item in manifest["gaps"]},
        )
        occurrence = next(
            item
            for item in manifest["occurrences"]
            if item["role"] == "packer-file-input"
        )
        version = next(
            item
            for item in manifest["versions"]
            if item["component_version_id"] == occurrence["component_version_id"]
        )
        self.assertEqual(
            kr.file_hash(b"server ptbtime1.ptb.de iburst\n"),
            version["artifact_digest"],
        )

    def test_digest_pinned_tag_and_git_ref_are_not_mutable_gaps(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "images.yaml", "yaml", content_hash="sha256:" + "4" * 64
        )
        digest = "sha256:" + "a" * 64
        pinned, _, _ = builder.add_image(
            f"ghcr.io/example/app:main@{digest}", source, "line:1", "image"
        )
        floating, _, _ = builder.add_image(
            "ghcr.io/example/app2:main", source, "line:2", "image"
        )
        git_component = builder.add_component(
            kind="git-repository", ecosystem="git", name="example.invalid/demo"
        )
        builder.add_version(
            git_component,
            source_ref="refs/heads/main",
            artifact_digest="sha256:" + "d" * 64,
            resolution_state="resolved",
        )
        manifest = builder.manifest()
        mutable = {
            item.get("component_id")
            for item in manifest["gaps"]
            if item["gap_type"] == "mutable-ref"
        }
        self.assertIn(floating, mutable)
        self.assertNotIn(pinned, mutable)
        self.assertNotIn(git_component, mutable)

    def test_self_repository_gitops_refs_are_typed_not_mutable(self) -> None:
        root = self.repository(
            {
                "argocd-apps/self.yaml": """apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: self-app
  namespace: argocd
spec:
  source:
    repoURL: git@github.com:example-org/k8s.git
    targetRevision: main
    path: apps/demo
""",
                "argocd-apps/foreign.yaml": """apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: foreign-app
  namespace: argocd
spec:
  source:
    repoURL: https://github.com/other/elsewhere.git
    targetRevision: main
    path: charts/demo
""",
            }
        )
        run_git(root, "remote", "add", "origin", "https://github.com/example-org/k8s.git")
        manifest = kr.merge_manifests([kr.discover_repo(root, observed_at=OBSERVED_AT)])
        gap_components: dict[str, set[str]] = {}
        for item in manifest["gaps"]:
            gap_components.setdefault(item["gap_type"], set()).add(
                item.get("component_id")
            )
        components = {item["component_id"]: item for item in manifest["components"]}
        self_ids = {
            component_id
            for component_id, component in components.items()
            if component.get("metadata", {}).get("source_repo")
            == "git@github.com:example-org/k8s.git"
        }
        foreign_ids = {
            component_id
            for component_id, component in components.items()
            if component.get("metadata", {}).get("source_repo")
            == "https://github.com/other/elsewhere.git"
        }
        self.assertTrue(self_ids)
        self.assertTrue(foreign_ids)
        self.assertTrue(self_ids <= gap_components.get("gitops-self-reference", set()))
        self.assertTrue(foreign_ids <= gap_components.get("mutable-ref", set()))
        self.assertFalse(self_ids & gap_components.get("mutable-ref", set()))

    @staticmethod
    def helm_lock_policy_files() -> dict[str, str]:
        return {
            ".gitignore": "# Helm dependency artifacts\n**/charts/\n**/Chart.lock\n",
            ".githooks/check-helm-dependency-versions.py": "print('guard')\n",
            "apps/demo/Chart.yaml": """apiVersion: v2
name: demo
version: 1.2.3
dependencies:
  - name: child
    version: 2.0.0
    repository: https://charts.example.invalid
""",
        }

    def test_helm_lock_policy_is_typed_when_the_repo_proves_it(self) -> None:
        root = self.repository(self.helm_lock_policy_files())
        manifest = kr.merge_manifests([kr.discover_repo(root, observed_at=OBSERVED_AT)])
        self.assertEqual([], kr.validate_manifest(manifest))
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertNotIn("helm-lock-missing", gap_types)
        gap = next(
            item for item in manifest["gaps"] if item["gap_type"] == "helm-lock-policy"
        )
        self.assertEqual(
            [
                ".githooks/check-helm-dependency-versions.py",
                ".gitignore#L3",
                "apps/demo/Chart.yaml",
            ],
            gap["evidence"],
        )

    def test_helm_lock_policy_leg_missing_returns_the_plain_gap(self) -> None:
        no_hook = self.helm_lock_policy_files()
        del no_hook[".githooks/check-helm-dependency-versions.py"]
        manifest = kr.discover_repo(self.repository(no_hook), observed_at=OBSERVED_AT)
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertIn("helm-lock-missing", gap_types)
        self.assertNotIn("helm-lock-policy", gap_types)

        unpinned = self.helm_lock_policy_files()
        unpinned["apps/demo/Chart.yaml"] = """apiVersion: v2
name: demo
version: 1.2.3
dependencies:
  - name: child
    repository: https://charts.example.invalid
"""
        manifest = kr.discover_repo(self.repository(unpinned), observed_at=OBSERVED_AT)
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertIn("helm-lock-missing", gap_types)
        self.assertNotIn("helm-lock-policy", gap_types)

    @staticmethod
    def latest_fixture_files() -> dict[str, str]:
        return {
            ".pre-commit-config.yaml": """repos:
  - repo: local
    hooks:
      - id: no-latest-image-tag
        name: ban latest tags
        entry: python3 .githooks/check-latest-image-tag.py
        language: system
        files: ^(apps|cluster)/.*\\.ya?ml$
        exclude: ^cluster/kyverno/test/demo-cel/
""",
            ".githooks/check-latest-image-tag.py": "print('guard')\n",
            "cluster/kyverno/test/demo-cel/kyverno-test.yaml": (
                "name: demo\npolicies:\n  - ../../demo-cel.yaml\n"
            ),
            "cluster/kyverno/test/demo-cel/resource.yaml": """apiVersion: v1
kind: Pod
metadata:
  name: latest-pod
spec:
  containers:
    - name: app
      image: nginx:latest
""",
        }

    def gaps_for_component(
        self, manifest: dict[str, Any], name: str
    ) -> dict[str, list[dict[str, Any]]]:
        component_ids = {
            item["component_id"]
            for item in manifest["components"]
            if item.get("name") == name
        }
        gaps: dict[str, list[dict[str, Any]]] = {}
        for item in manifest["gaps"]:
            if item.get("component_id") in component_ids:
                gaps.setdefault(item["gap_type"], []).append(item)
        return gaps

    def test_kyverno_latest_fixture_is_typed_not_mutable(self) -> None:
        root = self.repository(self.latest_fixture_files())
        manifest = kr.merge_manifests([kr.discover_repo(root, observed_at=OBSERVED_AT)])
        self.assertEqual([], kr.validate_manifest(manifest))
        nginx_gaps = self.gaps_for_component(manifest, "nginx")
        self.assertNotIn("mutable-ref", nginx_gaps)
        gap = nginx_gaps["test-fixture-reference"][0]
        for evidence in (
            ".pre-commit-config.yaml#L9",
            ".githooks/check-latest-image-tag.py",
            "cluster/kyverno/test/demo-cel/kyverno-test.yaml",
            "cluster/kyverno/test/demo-cel/resource.yaml#line:8",
        ):
            self.assertIn(evidence, gap["evidence"])

    def test_identity_provenance_does_not_downgrade_a_test_fixture_ref(self) -> None:
        """A receipt-bound observation is evidence about a version, not another
        use site, so it must not break the all-occurrences-carry-proof quorum."""

        root = self.repository(self.latest_fixture_files())
        base = kr.merge_manifests([kr.discover_repo(root, observed_at=OBSERVED_AT)])
        self.assertIn("test-fixture-reference", self.gaps_for_component(base, "nginx"))

        component = next(c for c in base["components"] if c.get("name") == "nginx")
        version = next(
            v
            for v in base["versions"]
            if v["component_id"] == component["component_id"]
        )
        builder = kr.Builder()
        source = builder.add_source(
            "oci-observation:sha256:" + "9" * 64,
            "oci-artifact-observation",
            content_hash="sha256:" + "9" * 64,
            metadata={"evidence_class": "reference"},
        )
        component_id = builder.add_component(
            kind=component["kind"],
            ecosystem=component["ecosystem"],
            name=component["name"],
            namespace=component.get("namespace", ""),
            purl=component.get("purl"),
            identity=kr.recover_component_identity(component),
            lifecycles=tuple(component.get("lifecycles", [])),
            metadata=component.get("metadata"),
            official_channel_required=bool(
                component.get("official_channel_required", True)
            ),
        )
        version_id = builder.add_version(
            component_id,
            resolved_version=version.get("resolved_version"),
            constraint=version.get("constraint"),
            source_ref=version.get("source_ref"),
            artifact_digest=version.get("artifact_digest"),
            platform=version.get("platform"),
        )
        builder.add_occurrence(
            component_id,
            version_id,
            source,
            locator="/receipts/receipts-test.jsonl:1",
            role="oci-artifact-observation",
            raw_value="sha256:" + "9" * 64,
            dependency_scope="deployment",
            lifecycle=(component.get("lifecycles") or ["repository-used"])[0],
        )
        fragment = builder.manifest()
        # Seen alone the fragment holds only the provenance occurrence, so it
        # types the ref mutable. That is what must not survive the merge.
        self.assertIn("mutable-ref", {g["gap_type"] for g in fragment["gaps"]})

        merged = kr.merge_manifests([base, fragment])
        gaps = self.gaps_for_component(merged, "nginx")
        self.assertNotIn("mutable-ref", gaps)
        self.assertIn("test-fixture-reference", gaps)

    def test_fixture_reference_fails_closed_without_full_proof(self) -> None:
        mixed = self.latest_fixture_files()
        mixed["apps/demo/pod.yaml"] = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\nspec:\n"
            "  containers:\n    - name: app\n      image: nginx:latest\n"
        )
        manifest = kr.discover_repo(self.repository(mixed), observed_at=OBSERVED_AT)
        nginx_gaps = self.gaps_for_component(manifest, "nginx")
        self.assertIn("mutable-ref", nginx_gaps)
        self.assertNotIn("test-fixture-reference", nginx_gaps)

        no_hook = self.latest_fixture_files()
        del no_hook[".githooks/check-latest-image-tag.py"]
        manifest = kr.discover_repo(self.repository(no_hook), observed_at=OBSERVED_AT)
        nginx_gaps = self.gaps_for_component(manifest, "nginx")
        self.assertIn("mutable-ref", nginx_gaps)
        self.assertNotIn("test-fixture-reference", nginx_gaps)

    def test_chart_template_images_resolve_from_the_charts_own_values(self) -> None:
        digest = "sha256:" + "a" * 64
        root = self.repository(
            {
                "apps/demo/Chart.yaml": "apiVersion: v2\nname: demo\nversion: 1.2.3\n",
                "apps/demo/values.yaml": f"""image:
  repository: ghcr.io/example/demo
  tag: v4.5.6
  digest: {digest}
sidecar:
  image: docker.io/library/busybox:1.36.1@{digest}
""",
                "apps/demo/templates/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: app
          image: {{ .Values.image.repository }}:{{ .Values.image.tag }}@{{ required "pin the digest" .Values.image.digest }}
        - name: side
          image: {{ .Values.sidecar.image | quote }}
        - name: audit
          image: '{{ printf "%s@%s" .Values.image.repository .Values.image.digest | quote }}'
""",
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertEqual([], kr.validate_manifest(manifest))
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertNotIn("image-expression-unresolved", gap_types)
        resolved = {
            item["raw_value"]: item
            for item in manifest["occurrences"]
            if item.get("metadata", {}).get("template_expression")
        }
        self.assertEqual(
            {
                f"ghcr.io/example/demo:v4.5.6@{digest}",
                f"docker.io/library/busybox:1.36.1@{digest}",
                f"ghcr.io/example/demo@{digest}",
            },
            set(resolved),
        )
        app = resolved[f"ghcr.io/example/demo:v4.5.6@{digest}"]
        self.assertEqual(
            [
                "apps/demo/values.yaml#L2",
                "apps/demo/values.yaml#L3",
                "apps/demo/values.yaml#L4",
            ],
            app["metadata"]["values_evidence"],
        )
        version = next(
            item
            for item in manifest["versions"]
            if item["component_version_id"] == app["component_version_id"]
        )
        self.assertEqual(digest, version["artifact_digest"])
        self.assertEqual("resolved", version["resolution_state"])

    def test_unresolvable_template_expressions_keep_the_typed_gap(self) -> None:
        root = self.repository(
            {
                "apps/demo/Chart.yaml": "apiVersion: v2\nname: demo\nversion: 1.2.3\n",
                "apps/demo/values.yaml": (
                    'image:\n  repository: ghcr.io/example/demo\n  digest: ""\n'
                ),
                "apps/demo/templates/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: helper
          image: {{ include "demo.image" . | quote }}
        - name: variable
          image: {{ $img | quote }}
        - name: empty
          image: {{ .Values.image.repository }}@{{ required "pin" .Values.image.digest }}
""",
                "playbook.yml": (
                    "- hosts: all\n  tasks:\n    - name: run\n"
                    "      docker_container:\n"
                    "        image: ghcr.io/example/tool:{{ tool_version }}\n"
                ),
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        messages = [
            item["message"]
            for item in manifest["gaps"]
            if item["gap_type"] == "image-expression-unresolved"
        ]
        for expression in (
            '{{ include "demo.image" . | quote }}',
            "{{ $img | quote }}",
            '{{ .Values.image.repository }}@{{ required "pin" .Values.image.digest }}',
            "ghcr.io/example/tool:{{ tool_version }}",
        ):
            self.assertTrue(
                any(repr(expression) in message for message in messages), expression
            )
        self.assertFalse(
            [
                item
                for item in manifest["occurrences"]
                if item.get("metadata", {}).get("template_expression")
            ]
        )

    def test_merge_is_order_independent(self) -> None:
        first, _, _, _ = self.minimal_builder()
        second = kr.Builder()
        source = second.add_source("other", "test", content_hash="sha256:" + "6" * 64)
        component = second.add_component(kind="library", ecosystem="npm", name="other")
        version = second.add_version(component, resolved_version="2.0.0")
        second.add_occurrence(
            component, version, source, locator="/", role="test", raw_value="other"
        )
        left = kr.merge_manifests([first.manifest(), second.manifest()])
        right = kr.merge_manifests([second.manifest(), first.manifest()])
        self.assertEqual(left, right)

    def test_merge_rejects_invalid_duplicate_and_conflicting_candidates(self) -> None:
        builder, _, _, _ = self.minimal_builder()
        manifest = builder.manifest()
        tampered = copy.deepcopy(manifest)
        tampered["components"][0]["component_id"] = "cmp-" + "f" * 24
        tampered = kr.seal_manifest(tampered)
        with self.assertRaisesRegex(kr.RegistryInputError, "merge input 0 is invalid"):
            kr.merge_manifests([tampered])

        duplicate = copy.deepcopy(manifest)
        duplicate["components"].append(copy.deepcopy(duplicate["components"][0]))
        duplicate = kr.seal_manifest(duplicate)
        with self.assertRaisesRegex(kr.RegistryInputError, "duplicate component_id"):
            kr.merge_manifests([duplicate])

        conflicting_builder = kr.Builder()
        source = conflicting_builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "1" * 64,
            metadata={"evidence_class": "test"},
        )
        component = conflicting_builder.add_component(
            kind="library",
            ecosystem="pypi",
            name="conflicting-name",
            purl="pkg:pypi/demo",
        )
        version = conflicting_builder.add_version(
            component, resolved_version="1.2.3", evidence=("fixture.json",)
        )
        conflicting_builder.add_occurrence(
            component,
            version,
            source,
            locator="/demo",
            role="test",
            raw_value="demo==1.2.3",
        )
        conflicting = conflicting_builder.manifest()
        self.assertEqual([], kr.validate_manifest(conflicting))
        with self.assertRaisesRegex(kr.RegistryInputError, "merge conflict"):
            kr.merge_manifests([manifest, conflicting])

    def test_merge_preserves_latest_observation_base_and_lineage(self) -> None:
        root = self.repository({"package.json": '{"name":"demo","version":"1.0.0"}'})
        first = kr.discover_repo(root, observed_at=OBSERVED_AT)
        second = kr.discover_repo(
            root,
            observed_at=NEXT_OBSERVED_AT,
            base_manifest_id=first["manifest_id"],
            previous_observed_at=OBSERVED_AT,
        )
        merged = kr.merge_manifests([first, second])
        self.assertEqual(second["observation"], merged["observation"])
        self.assertEqual(first["manifest_id"], merged["base_manifest_id"])
        self.assertEqual(
            first["manifest_id"], merged["merge_lineage"]["previous_manifest_id"]
        )
        self.assertEqual(
            sorted([first["manifest_id"], second["manifest_id"]]),
            merged["merge_lineage"]["input_manifest_ids"],
        )
        self.assertEqual([], kr.validate_manifest(merged))

    def test_repo_gvk_metadata_is_group_qualified_and_merges_with_live(self) -> None:
        root = self.repository(
            {
                "manifests/demo.yaml": (
                    "apiVersion: v1\n"
                    "kind: ServiceAccount\n"
                    "metadata:\n"
                    "  name: demo\n"
                    "---\n"
                    "apiVersion: apps/v1\n"
                    "kind: Deployment\n"
                    "metadata:\n"
                    "  name: demo\n"
                ),
            }
        )
        repo_manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertEqual([], kr.validate_manifest(repo_manifest))
        gvks = {
            item["metadata"]["gvk"]: item["component_id"]
            for item in repo_manifest["components"]
            if item["kind"] == "kubernetes-api"
        }
        self.assertEqual({"core/v1/ServiceAccount", "apps/v1/Deployment"}, set(gvks))

        live_builder = kr.Builder()
        source = live_builder.add_source(
            "live/api-discovery-core-v1.json",
            "live-cluster",
            content_hash="sha256:" + "7" * 64,
            metadata={"evidence_class": "test"},
        )
        component = live_builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace="core",
            name="ServiceAccount",
            identity="gvk:core/v1:ServiceAccount",
            lifecycles=("deployed",),
            metadata={"api_group": "core", "gvk": "core/v1/ServiceAccount"},
        )
        self.assertEqual(gvks["core/v1/ServiceAccount"], component)
        version = live_builder.add_version(
            component,
            resolved_version="v1",
            resolution_state="resolved",
            evidence=("live/api-discovery-core-v1.json#/resources/0",),
        )
        live_builder.add_occurrence(
            component,
            version,
            source,
            locator="/resources/0",
            role="live-kubernetes-api-discovery",
            raw_value="v1/serviceaccounts:ServiceAccount",
            lifecycle="deployed",
        )
        live_manifest = live_builder.manifest()
        self.assertEqual([], kr.validate_manifest(live_manifest))
        merged = kr.merge_manifests([repo_manifest, live_manifest])
        self.assertEqual([], kr.validate_manifest(merged))
        merged_component = next(
            item for item in merged["components"] if item["component_id"] == component
        )
        self.assertEqual("core/v1/ServiceAccount", merged_component["metadata"]["gvk"])
        self.assertIn("deployed", merged_component["lifecycles"])

    def test_dynamic_refs_are_never_exact_versions(self) -> None:
        for value in ("${VERSION}", "v${VERSION}", "$VERSION", "%VERSION%"):
            self.assertFalse(kr.looks_exact(value), value)
        builder = kr.Builder()
        component = builder.add_component(
            kind="git-repository", ecosystem="git", name="dynamic"
        )
        builder.add_version(component, source_ref="v${VERSION}")
        manifest = builder.manifest()
        self.assertTrue(
            any(
                item["gap_type"] == "dynamic-ref-unresolved"
                for item in manifest["gaps"]
            )
        )

    def test_generated_schema_rejects_extra_and_wrongly_typed_fields(self) -> None:
        builder, _, _, _ = self.minimal_builder()
        manifest = builder.manifest()
        mutations = []
        top_level = copy.deepcopy(manifest)
        top_level["unexpected"] = True
        mutations.append(top_level)
        nested_extra = copy.deepcopy(manifest)
        nested_extra["components"][0]["unexpected"] = True
        mutations.append(nested_extra)
        nested_type = copy.deepcopy(manifest)
        nested_type["components"][0]["kind"] = 7
        mutations.append(nested_type)
        for mutation in mutations:
            errors = kr.validate_manifest(kr.seal_manifest(mutation))
            self.assertTrue(
                any(error.startswith("schema ") for error in errors), errors
            )

    def test_reviewed_schema_cross_file_and_normalized_identities_fail_closed(
        self,
    ) -> None:
        valid = self.reviewed_record()
        malformed = copy.deepcopy(valid)
        malformed["component"]["unexpected"] = True
        with self.assertRaisesRegex(kr.RegistryInputError, "Additional properties"):
            kr.reviewed_records_manifest([("bad.json", malformed)])

        other = self.reviewed_record(
            record_id="record-other",
            component_id="component-other",
            version_id="version-demo",
            name="other",
            purl="pkg:pypi/other",
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "not unique"):
            kr.reviewed_records_manifest([("one.json", valid), ("two.json", other)])

        normalized = self.reviewed_record(
            record_id="record-normalized",
            component_id="component-normalized",
            version_id="version-normalized",
            name="conflicting-name",
            purl="pkg:pypi/demo",
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "normalizes to conflicting"):
            kr.reviewed_records_manifest(
                [("one.json", valid), ("two.json", normalized)]
            )

    def test_reviewed_uri_safety_rejects_encoded_credentials_and_is_bounded(
        self,
    ) -> None:
        cases = []
        userinfo = self.reviewed_record()
        userinfo["component"]["source_repo"] = "https://user:pass@example.invalid/repo"
        cases.append(userinfo)
        encoded_key = self.reviewed_record()
        encoded_key["review"]["evidence"] = [
            "https://example.invalid/review?%2574oken=value"
        ]
        cases.append(encoded_key)
        nested_purl = self.reviewed_record()
        nested_purl["component"]["purl"] = "pkg:oci/demo?repository_url=" + quote(
            quote("https://user:pass@example.invalid/repo", safe=""), safe=""
        )
        cases.append(nested_purl)
        for record in cases:
            with self.assertRaisesRegex(
                kr.RegistryInputError, "userinfo|credential-bearing"
            ):
                kr.reviewed_records_manifest([("unsafe.json", record)])

        malformed = self.reviewed_record()
        malformed["review"]["evidence"] = ["https://example.invalid/?token=%ZZ"]
        with self.assertRaisesRegex(
            kr.RegistryInputError, "malformed percent encoding"
        ):
            kr.reviewed_records_manifest([("malformed.json", malformed)])

        for unsafe in (
            "https://x.invalid/?key=DO-NOT-PERSIST-SECRET",
            "https://x.invalid/#access_token=DO-NOT-PERSIST-SECRET",
            "https://x.invalid/?session=value",
            "https://x.invalid/#jwt=value",
        ):
            self.assertTrue(
                kr.validate_reviewed_uri_safety({"evidence_uri": unsafe}), unsafe
            )
        self.assertEqual(
            [],
            kr.validate_reviewed_uri_safety(
                {"evidence_uri": "https://x.invalid/?q=100%25#section"}
            ),
        )

        pointer_evidence = (
            "live-export:sha256:"
            + "a" * 64
            + "#/components/schemas/io.k8s.api.core.v1.Secret"
        )
        self.assertEqual(
            [], kr.validate_reviewed_uri_safety({"evidence": [pointer_evidence]})
        )
        encoded_pointer = pointer_evidence.replace(
            "#/components/schemas/io.k8s.api.core.v1.Secret",
            "#%2Fcomponents%2Fschemas%2Fio.k8s.api.core.v1.Secret~1field~0name",
        )
        self.assertEqual(
            [], kr.validate_reviewed_uri_safety({"evidence": [encoded_pointer]})
        )
        invalid_pointer = pointer_evidence.replace(".Secret", ".Secret~2field")
        self.assertTrue(
            any(
                "invalid JSON Pointer escape" in error
                for error in kr.validate_reviewed_uri_safety(
                    {"evidence": [invalid_pointer]}
                )
            )
        )
        for malformed_pointer in (
            pointer_evidence + "%ZZ",
            pointer_evidence + "%FF",
        ):
            self.assertTrue(
                kr.validate_reviewed_uri_safety({"evidence": [malformed_pointer]})
            )
        for unsafe_evidence in (
            "https://user:pass@example.invalid/export#/components/schemas/Secret",
            "https://example.invalid/export?token=value#/components/schemas/Secret",
        ):
            self.assertTrue(
                kr.validate_reviewed_uri_safety({"evidence": [unsafe_evidence]})
            )
        self.assertTrue(
            kr.validate_reviewed_uri_safety(
                {"evidence_uri": "https://example.invalid/export#token=value"}
            )
        )

        nested = "https://example.invalid/repo"
        for _ in range(kr.MAX_REVIEWED_URI_NESTING + 2):
            nested = "pkg:generic/demo?repository_url=" + quote(nested, safe="")
        too_deep = self.reviewed_record(purl=nested)
        with self.assertRaisesRegex(kr.RegistryInputError, "depth bound"):
            kr.reviewed_records_manifest([("deep.json", too_deep)])

    def test_reviewed_formats_uri_repertoire_and_temporal_intervals_are_strict(
        self,
    ) -> None:
        for field, invalid in (
            ("reviewed_at", "2026-02-30"),
            ("reviewed_at", "2026-7-1"),
        ):
            record = self.reviewed_record()
            record["review"][field] = invalid
            with self.assertRaisesRegex(kr.RegistryInputError, "not a 'date'"):
                kr.reviewed_records_manifest([("invalid-date.json", record)])

        for invalid in (
            "2026-07-17T12:00:00+00:00",
            "2026-07-17T12:00:00.000Z",
            "2026-02-30T12:00:00Z",
        ):
            record = self.reviewed_record()
            record["versions"][0]["observed_at"] = invalid
            with self.assertRaisesRegex(kr.RegistryInputError, "not a 'date-time'"):
                kr.reviewed_records_manifest([("invalid-time.json", record)])

        for invalid in (
            "foo\\bar",
            "https://example.invalid/{x}",
            "/|x",
            "https://example.invalid/ä",
            "https://",
            "://",
            "pkg:",
        ):
            self.assertFalse(kr.strict_uri_reference(invalid), invalid)
        self.assertTrue(kr.strict_uri_reference("https://example.invalid/100%25"))
        self.assertEqual(
            [],
            kr.validate_reviewed_uri_safety(
                {"evidence_uri": "https://example.invalid/?value=100%25"}
            ),
        )
        self.assertEqual(
            [],
            kr.validate_reviewed_uri_safety(
                {"evidence_uri": "https://example.invalid/?value=100%2525"}
            ),
        )
        percent = self.reviewed_record()
        percent["review"]["evidence"] = ["https://example.invalid/100%25"]
        self.assertEqual(
            [],
            kr.validate_manifest(kr.reviewed_records_manifest([("ok.json", percent)])),
        )

        reversed_version = self.reviewed_record()
        reversed_version["versions"][0]["valid_from"] = NEXT_OBSERVED_AT
        reversed_version["versions"][0]["valid_to"] = OBSERVED_AT
        with self.assertRaisesRegex(kr.RegistryInputError, "valid_from"):
            kr.reviewed_records_manifest([("reversed-version.json", reversed_version)])

        reversed_occurrence = self.reviewed_record()
        reversed_occurrence["occurrences"] = [
            {
                "occurrence_id": "occurrence-demo",
                "component_version_id": "version-demo",
                "root_id": "root-demo",
                "used_by": "component-demo",
                "site": None,
                "namespace": None,
                "workload": None,
                "container": None,
                "role": "runtime",
                "directness": "direct",
                "dependency_scope": "runtime",
                "optional": False,
                "evidence_uri": "https://example.invalid/runtime",
                "first_seen": NEXT_OBSERVED_AT,
                "last_seen": OBSERVED_AT,
                "status": "active",
            }
        ]
        with self.assertRaisesRegex(kr.RegistryInputError, "first_seen"):
            kr.reviewed_records_manifest(
                [("reversed-occurrence.json", reversed_occurrence)]
            )

    def test_candidate_locator_safety_covers_typed_keys_and_endpoint_roles(
        self,
    ) -> None:
        invalid = "https://user:pass@example.invalid/repo?token=value"
        for key in (
            "canonical_uri",
            "chart_repository",
            "evidence_uri",
            "endpoint",
            "repoURL",
            "repository",
            "source_repo",
            "uri",
        ):
            builder, source_id, _component, _version = self.minimal_builder()
            builder.sources[source_id].setdefault("metadata", {})[key] = invalid
            with self.assertRaisesRegex(kr.RegistryInputError, "unsafe locator at /"):
                builder.manifest()

        for key in ("repoURL", "repository", "source_repo", "evidence_uri"):
            builder, source_id, _component, _version = self.minimal_builder()
            builder.sources[source_id].setdefault("metadata", {})[
                key
            ] = "user:pass@github.example:org/repo"
            with self.assertRaisesRegex(kr.RegistryInputError, "unsafe locator at /"):
                builder.manifest()
            builder, source_id, _component, _version = self.minimal_builder()
            builder.sources[source_id].setdefault("metadata", {})[
                key
            ] = "git@github.example:org/repo"
            self.assertEqual([], kr.validate_manifest(builder.manifest()))
        self.assertEqual(
            [],
            kr.unsafe_candidate_locator_pointers(
                {"evidence_uri": "https://www.npmjs.com/package/@scope/name"}
            ),
        )

        builder, source_id, component, version = self.minimal_builder()
        builder.add_occurrence(
            component,
            version,
            source_id,
            locator="/endpoint",
            role="mcp-server-endpoint",
            raw_value=invalid,
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "unsafe locator at /"):
            builder.manifest()

        files = self.fixture_files()
        files["apps/demo/Chart.yaml"] = files["apps/demo/Chart.yaml"].replace(
            "https://charts.example.invalid",
            "https://user:pass@charts.example.invalid",
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "unsafe locator at /"):
            kr.discover_repo(self.repository(files), observed_at=OBSERVED_AT)

        docker_files = self.fixture_files()
        docker_files[
            "Dockerfile"
        ] += "ADD https://user:pass@downloads.example.invalid/archive.tgz /tmp/\n"
        with self.assertRaisesRegex(kr.RegistryInputError, "unsafe locator at /"):
            kr.discover_repo(self.repository(docker_files), observed_at=OBSERVED_AT)

        requirement_files = self.fixture_files()
        requirement_files["requirements.txt"] = (
            "demo @ git+https://user:pass@git.example.invalid/org/repo@v1.0.0\n"
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "unsafe locator at /"):
            kr.discover_repo(
                self.repository(requirement_files), observed_at=OBSERVED_AT
            )

        dynamic_files = self.fixture_files()
        dynamic_files["scripts/setup/linux-apt-mise.sh"] = """#!/usr/bin/env bash
K9S_VER="$(curl -s https://api.github.com/repos/derailed/k9s/releases/latest | jq -r .tag_name)"
curl -fsSL "https://github.com/derailed/k9s/releases/download/${K9S_VER}/k9s_Linux_amd64.tar.gz" -o /tmp/k9s.tgz
"""
        dynamic_manifest = kr.discover_repo(
            self.repository(dynamic_files), observed_at=OBSERVED_AT
        )
        serialized_dynamic = kr.canonical_json(dynamic_manifest)
        self.assertNotIn("${K9S_VER}", serialized_dynamic)
        dynamic_components = [
            component
            for component in dynamic_manifest["components"]
            if component.get("metadata", {}).get("locator_state") == "dynamic-template"
        ]
        self.assertEqual(1, len(dynamic_components))
        dynamic_occurrences = [
            occurrence
            for occurrence in dynamic_manifest["occurrences"]
            if occurrence.get("metadata", {}).get("locator_state") == "dynamic-template"
        ]
        self.assertEqual(1, len(dynamic_occurrences))
        self.assertTrue(
            dynamic_occurrences[0]["raw_value"].startswith(
                "urn:archeion:dynamic-remote-input:ref-"
            )
        )
        self.assertIn(
            "remote-download-locator-unresolved",
            {gap["gap_type"] for gap in dynamic_manifest["gaps"]},
        )

    def test_live_sbom_preserves_transitive_dependency_edges(self) -> None:
        payload = {
            "apiVersion": "aquasecurity.github.io/v1alpha1",
            "kind": "SbomReportList",
            "metadata": {},
            "items": [
                {
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "SbomReport",
                    "metadata": {"namespace": "demo", "name": "pod-main"},
                    "report": {
                        "artifact": {
                            "repository": "ghcr.io/example/main",
                            "tag": "1.0.0",
                            "digest": "sha256:" + "d" * 64,
                        },
                        "components": {
                            "components": [
                                {
                                    "bom-ref": "pkg:pypi/requests@2.32.4",
                                    "type": "library",
                                    "name": "requests",
                                    "version": "2.32.4",
                                    "purl": "pkg:pypi/requests@2.32.4",
                                },
                                {
                                    "bom-ref": "pkg:pypi/urllib3@2.5.0",
                                    "type": "library",
                                    "name": "urllib3",
                                    "version": "2.5.0",
                                    "purl": "pkg:pypi/urllib3@2.5.0",
                                },
                            ],
                            "dependencies": [
                                {
                                    "ref": "pkg:pypi/requests@2.32.4",
                                    "dependsOn": ["pkg:pypi/urllib3@2.5.0"],
                                }
                            ],
                        },
                    },
                }
            ],
        }
        fixture = self.base / "sbom.json"
        fixture.write_text(json.dumps(payload), encoding="utf-8")
        manifest = kr.import_live([str(fixture)])
        self.assertEqual([], kr.validate_manifest(manifest))
        self.assertTrue(
            any(
                item["resolver"] == "cyclonedx-sbom"
                for item in manifest["dependency_edges"]
            )
        )
        self.assertTrue(
            any(
                item["role"] == "sbom-component" and item["directness"] == "transitive"
                for item in manifest["occurrences"]
            )
        )

    def test_sbom_root_topology_and_duplicate_refs_fail_closed(self) -> None:
        root_ref = "pkg:oci/main@sha256:" + "a" * 64
        direct_ref = "pkg:pypi/requests@2.32.4"
        transitive_ref = "pkg:pypi/urllib3@2.5.0"
        report = {
            "apiVersion": "aquasecurity.github.io/v1alpha1",
            "kind": "SbomReportList",
            "metadata": {},
            "items": [
                {
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "SbomReport",
                    "metadata": {"namespace": "demo", "name": "main"},
                    "report": {
                        "artifact": {
                            "repository": "ghcr.io/example/main",
                            "digest": "sha256:" + "a" * 64,
                        },
                        "metadata": {
                            "component": {
                                "bom-ref": root_ref,
                                "purl": "pkg:oci/main?os=linux&arch=amd64",
                            }
                        },
                        "components": {
                            "components": [
                                {
                                    "bom-ref": direct_ref,
                                    "type": "library",
                                    "name": "requests",
                                    "version": "2.32.4",
                                    "purl": direct_ref,
                                },
                                {
                                    "bom-ref": transitive_ref,
                                    "type": "library",
                                    "name": "urllib3",
                                    "version": "2.5.0",
                                    "purl": transitive_ref,
                                },
                            ],
                            "dependencies": [
                                {"ref": root_ref, "dependsOn": [direct_ref]},
                                {"ref": direct_ref, "dependsOn": [transitive_ref]},
                            ],
                        },
                    },
                }
            ],
        }
        fixture = self.base / "root-sbom.json"
        fixture.write_text(json.dumps(report), encoding="utf-8")
        manifest = kr.import_live([str(fixture)])
        direct_occurrence = next(
            item
            for item in manifest["occurrences"]
            if item.get("metadata", {}).get("bom_ref") == direct_ref
        )
        transitive_occurrence = next(
            item
            for item in manifest["occurrences"]
            if item.get("metadata", {}).get("bom_ref") == transitive_ref
        )
        self.assertEqual("direct", direct_occurrence["directness"])
        self.assertEqual("transitive", transitive_occurrence["directness"])
        root_version = next(
            edge["from_component_version_id"]
            for edge in manifest["dependency_edges"]
            if edge["to_component_version_id"]
            == direct_occurrence["component_version_id"]
            and edge["relationship"] == "depends-on"
        )
        self.assertNotEqual(direct_occurrence["component_version_id"], root_version)

        duplicate_bom = copy.deepcopy(report)
        duplicate_bom["items"][0]["report"]["components"]["components"][1][
            "bom-ref"
        ] = direct_ref
        fixture.write_text(json.dumps(duplicate_bom), encoding="utf-8")
        with self.assertRaisesRegex(
            kr.RegistryInputError, "duplicate CycloneDX bom-ref"
        ):
            kr.import_live([str(fixture)])

        duplicate_dependency = copy.deepcopy(report)
        duplicate_dependency["items"][0]["report"]["components"]["dependencies"].append(
            {"ref": direct_ref, "dependsOn": []}
        )
        fixture.write_text(json.dumps(duplicate_dependency), encoding="utf-8")
        with self.assertRaisesRegex(
            kr.RegistryInputError, "duplicate CycloneDX dependency refs"
        ):
            kr.import_live([str(fixture)])

    def test_sbom_hash_identity_uses_exact_source_sha256_and_rejects_conflict(
        self,
    ) -> None:
        oci_digest = "sha256:" + "a" * 64
        payload = {
            "apiVersion": "aquasecurity.github.io/v1alpha1",
            "kind": "SbomReportList",
            "metadata": {},
            "items": [
                {
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "SbomReport",
                    "metadata": {"namespace": "demo", "name": "hashes"},
                    "report": {
                        "artifact": {
                            "repository": "ghcr.io/example/root",
                            "digest": "sha256:" + "c" * 64,
                            "properties": [
                                {"name": "platform", "value": "linux/amd64"}
                            ],
                        },
                        "metadata": {"component": {"bom-ref": "root"}},
                        "components": {
                            "components": [
                                {
                                    "bom-ref": "python",
                                    "type": "library",
                                    "name": "demo",
                                    "version": "1.0.0",
                                    "purl": "pkg:pypi/demo@1.0.0",
                                    "hashes": [{"alg": "SHA-256", "content": "d" * 64}],
                                },
                                {
                                    "bom-ref": "image",
                                    "type": "container",
                                    "name": "child",
                                    "purl": (
                                        "pkg:oci/child@"
                                        + oci_digest
                                        + "?os=linux&arch=amd64"
                                    ),
                                    "hashes": [
                                        {"alg": "SHA-256", "content": "a" * 64},
                                        {"alg": "sha256", "content": "a" * 64},
                                    ],
                                },
                                {
                                    "bom-ref": "unresolved-image",
                                    "type": "container",
                                    "name": "unresolved",
                                    "version": "1.2.3",
                                    "purl": (
                                        "pkg:oci/unresolved@1.2.3"
                                        "?os=linux&arch=amd64"
                                    ),
                                    "hashes": [{"alg": "MD5", "content": "e" * 32}],
                                },
                            ]
                        },
                    },
                }
            ],
        }
        fixture = self.base / "hash-identity.json"
        fixture.write_text(json.dumps(payload), encoding="utf-8")
        manifest = kr.import_live([str(fixture)])
        components_by_id = {
            component["component_id"]: component for component in manifest["components"]
        }
        versions_by_purl = {
            components_by_id[version["component_id"]].get("purl"): version
            for version in manifest["versions"]
            if version["component_id"] in components_by_id
        }
        self.assertEqual(
            "sha256:" + "d" * 64,
            versions_by_purl["pkg:pypi/demo"]["artifact_digest"],
        )
        image_purl = "pkg:oci/child?os=linux&arch=amd64"
        self.assertEqual(oci_digest, versions_by_purl[image_purl]["artifact_digest"])
        unresolved_purl = "pkg:oci/unresolved?os=linux&arch=amd64"
        self.assertIsNone(versions_by_purl[unresolved_purl].get("artifact_digest"))
        self.assertEqual(
            "unresolved", versions_by_purl[unresolved_purl]["resolution_state"]
        )
        self.assertEqual([], kr.validate_manifest(manifest))

        conflict = copy.deepcopy(payload)
        conflict["items"][0]["report"]["components"]["components"][1]["hashes"] = [
            {"alg": "SHA-256", "content": "b" * 64}
        ]
        conflict_file = self.base / "hash-conflict.json"
        conflict_file.write_text(json.dumps(conflict), encoding="utf-8")
        with self.assertRaisesRegex(kr.RegistryInputError, "conflicting SHA-256"):
            kr.import_live([str(conflict_file)])

    def test_truncated_live_inventory_is_a_blocking_typed_gap(self) -> None:
        fixture = self.base / "truncated.json"
        fixture.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "PodList",
                    "metadata": {"continue": "next"},
                    "items": [],
                }
            ),
            encoding="utf-8",
        )
        manifest = kr.import_live([str(fixture)])
        self.assertTrue(
            any(
                item["gap_type"] == "live-inventory-truncated"
                for item in manifest["gaps"]
            )
        )
        self.assertEqual("gapped", manifest["completeness"]["closure"]["state"])

    def test_duplicate_live_json_is_rejected(self) -> None:
        fixture = self.base / "duplicate.json"
        fixture.write_text(
            '{"kind":"PodList","kind":"NodeList","items":[]}', encoding="utf-8"
        )
        with self.assertRaisesRegex(kr.RegistryInputError, "duplicate JSON object key"):
            kr.import_live([str(fixture)])

    def test_capture_query_rejects_truncated_and_duplicate_payloads(self) -> None:
        query = live.Query("pods", "pods.json", ("get", "pods"), "Pod")
        with self.assertRaisesRegex(RuntimeError, "truncated inventory"):
            live.validate_query_payload(
                query,
                {
                    "apiVersion": "v1",
                    "kind": "PodList",
                    "metadata": {"remainingItemCount": 1},
                    "items": [],
                },
            )

        with self.assertRaisesRegex(RuntimeError, "kubectl-response-invalid-json"):
            live.command_json(
                self.popen_runner(b'{"a":1,"a":2}'),
                ["/usr/bin/kubectl", "version"],
                timeout=1,
            )

    def test_capture_subprocess_gets_fixed_environment(self) -> None:
        observed: dict[str, object] = {}

        underlying = self.popen_runner(b"context\n")

        def runner(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            observed.update(kwargs)
            return underlying(command, **kwargs)

        completed = live.invoke(
            runner, ["/usr/bin/kubectl", "config", "current-context"], timeout=1
        )
        self.assertEqual(0, completed.returncode)
        self.assertEqual(live.FIXED_KUBECTL_ENV, observed["env"])

        sentinel = "DO-NOT-PERSIST-STDERR-SECRET"
        with self.assertRaisesRegex(RuntimeError, "kubectl-command-failed") as failure:
            live.command_json(
                self.popen_runner(b"", stderr=sentinel.encode(), returncode=1),
                ["/usr/bin/kubectl", "version"],
                timeout=1,
            )
        self.assertNotIn(sentinel, str(failure.exception))

    def test_kubeconfig_is_bound_and_rejects_plugins_or_symlinks(self) -> None:
        config = self.base / "config"
        config.write_text(
            """apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: local
contexts:
- context:
    cluster: local
    user: local
  name: local
current-context: local
users:
- name: local
  user:
    token: static
""",
            encoding="utf-8",
        )
        config.chmod(0o600)
        identity = live.kubeconfig_identity(config)
        self.assertEqual(config.as_posix(), identity["path"])
        self.assertEqual(
            [
                "/usr/bin/kubectl",
                "--kubeconfig",
                config.as_posix(),
                "--context",
                "local",
                "get",
                "--raw",
                "/api",
            ],
            live.kubectl_command(
                "/usr/bin/kubectl",
                config.as_posix(),
                "local",
                ("get", "--raw", "/api"),
            ),
        )
        link = self.base / "config-link"
        link.symlink_to(config)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            live.kubeconfig_identity(link)
        config.write_text(
            """apiVersion: v1
kind: Config
users:
  - name: local
    user:
      exec:
        command: arbitrary-helper
""",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "credential plugins"):
            live.kubeconfig_identity(config)
        http_config = {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [
                {"name": "local", "cluster": {"server": "http://127.0.0.1:6443"}}
            ],
            "contexts": [
                {
                    "name": "local",
                    "context": {"cluster": "local", "user": "local"},
                }
            ],
            "current-context": "local",
            "users": [{"name": "local", "user": {"token": "inline"}}],
        }
        config.write_text(json.dumps(http_config), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "valid HTTPS URL"):
            live.kubeconfig_identity(config)
        http_config["clusters"][0]["cluster"] = {
            "server": "https://127.0.0.1:6443",
            "insecure-skip-tls-verify": True,
        }
        config.write_text(json.dumps(http_config), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "credential plugins"):
            live.kubeconfig_identity(config)
        http_config["clusters"][0]["cluster"] = {
            "server": "https://127.0.0.1:6443",
            "certificate-authority-data": "aW5saW5lLWNh",
        }
        config.write_text(json.dumps(http_config), encoding="utf-8")
        self.assertEqual(config.as_posix(), live.kubeconfig_identity(config)["path"])

    def test_capture_output_rejects_symlink_parent_and_requires_time(self) -> None:
        real = self.base / "real"
        real.mkdir()
        link = self.base / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            live.create_capture_directory(link / "capture")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                live.parser().parse_args(
                    [
                        "--output-dir",
                        str(self.base / "capture"),
                        "--git-commit",
                        "a" * 40,
                        "--kubeconfig",
                        str(self.base / "config"),
                    ]
                )

    def test_capture_subprocess_streams_and_dynamic_queries_are_bounded(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "stdout exceeds byte bound"):
            live.invoke(
                self.popen_runner(b"x" * 64),
                ["/usr/bin/kubectl", "version"],
                timeout=1,
                max_stdout_bytes=8,
            )
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            live.invoke(
                self.popen_runner(b"{}", delay=0.5),
                ["/usr/bin/kubectl", "version"],
                timeout=0.02,
            )
        self.assertLess(time.monotonic() - started, 1)
        api_versions = {"versions": ["v1"]}
        api_groups = {
            "groups": [
                {
                    "name": "apps",
                    "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                }
            ]
        }
        with mock.patch.object(live, "MAX_DYNAMIC_QUERIES", 1):
            with self.assertRaisesRegex(RuntimeError, "endpoint bound"):
                live.api_resource_queries(api_versions, api_groups)

    def test_v3_receipt_is_exact_bounded_temporal_and_static_surface_closed(
        self,
    ) -> None:
        receipt = self.v3_capture_receipt()

        def normalize(
            candidate: dict[str, object],
        ) -> list[tuple[str, str, str | None]]:
            raw = kr.canonical_json(candidate).encode()
            _normalized, errors = kr.normalize_live_capture_manifest(
                candidate,
                content_hash=kr.file_hash(raw),
                raw_hash=kr.file_hash(raw),
            )
            return errors

        self.assertEqual([], normalize(copy.deepcopy(receipt)))
        mutations: list[dict[str, object]] = []
        extra = copy.deepcopy(receipt)
        extra["unexpected"] = True
        mutations.append(extra)
        bounds = copy.deepcopy(receipt)
        bounds["bounds"]["capture_commands"] += 1
        mutations.append(bounds)
        required = copy.deepcopy(receipt)
        required["required_surfaces"].append("pods")
        mutations.append(required)
        surface_extra = copy.deepcopy(receipt)
        surface_extra["surfaces"]["pods"]["unexpected"] = True
        mutations.append(surface_extra)
        window = copy.deepcopy(receipt)
        window["capture_window"]["started_at"] = "2026-07-18T12:00:00Z"
        mutations.append(window)
        cardinality = copy.deepcopy(receipt)
        hashes = ["sha256:" + character * 64 for character in ("3", "4")]
        cardinality["surfaces"]["pods"] = {
            "state": "unavailable",
            "raw_hashes": hashes,
            "resource_kinds": ["Pod"],
            "artifacts": [
                {
                    "endpoint": "/api/v1/pods",
                    "raw_hash": raw_hash,
                    "document_type": "Pod",
                }
                for raw_hash in hashes
            ],
            "error": "query-failed",
        }
        mutations.append(cardinality)
        controllers = copy.deepcopy(receipt)
        deployment_hash = "sha256:" + "5" * 64
        controllers["surfaces"]["controllers"] = {
            "state": "captured",
            "raw_hashes": [deployment_hash],
            "resource_kinds": list(kr.LIVE_CONTROLLER_KINDS),
            "artifacts": [
                {
                    "endpoint": "/apis/apps/v1/deployments",
                    "raw_hash": deployment_hash,
                    "document_type": "Deployment",
                }
            ],
        }
        mutations.append(controllers)
        endpoint_secret = copy.deepcopy(receipt)
        endpoint_hash = "sha256:" + "6" * 64
        endpoint_secret["surfaces"]["builtin-openapi"] = {
            "state": "unavailable",
            "raw_hashes": [endpoint_hash],
            "resource_kinds": list(kr.LIVE_SURFACE_RESOURCE_KINDS["builtin-openapi"]),
            "artifacts": [
                {
                    "endpoint": "/openapi/v3?%2574oken=sentinel",
                    "raw_hash": endpoint_hash,
                    "document_type": "OpenAPIv3Discovery",
                }
            ],
            "error": "query-failed",
        }
        mutations.append(endpoint_secret)
        for mutation in mutations:
            errors = normalize(mutation)
            self.assertTrue(
                any(error[0] == "live-capture-metadata-invalid" for error in errors),
                errors,
            )

    def test_capture_openapi_path_keys_bind_exact_server_relative_urls(self) -> None:
        valid = live.openapi_document_queries(
            {
                "paths": {
                    "api/v1": {"serverRelativeURL": "/openapi/v3/api/v1?hash=100%25"}
                }
            }
        )
        self.assertEqual(
            ("get", "--raw", "/openapi/v3/api/v1?hash=100%25"),
            valid[0].args,
        )
        with self.assertRaisesRegex(RuntimeError, "path key does not match"):
            live.openapi_document_queries(
                {"paths": {"api/v1": {"serverRelativeURL": "/openapi/v3/apis/apps/v1"}}}
            )

    def test_malformed_v3_capture_receipts_fail_closed_in_library_and_cli(self) -> None:
        exported = self.base / "export.json"
        exported.write_text("{}\n", encoding="utf-8")
        for index, malformed in enumerate(({"contract_version": 3}, [])):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(
                    kr.RegistryInputError, "live capture manifest v3 is invalid"
                ):
                    kr.import_live([str(exported)], capture_manifest=malformed)
                receipt = self.base / f"bad-receipt-{index}.json"
                receipt.write_text(json.dumps(malformed), encoding="utf-8")
                output = self.base / f"bad-output-{index}.json"
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    status = kr.main(
                        [
                            "import-live",
                            str(exported),
                            "--capture-manifest",
                            str(receipt),
                            "--output",
                            str(output),
                        ]
                    )
                self.assertEqual(2, status)
                self.assertFalse(output.exists())
                self.assertIn("live capture manifest v3 is invalid", stderr.getvalue())

    def test_openapi_endpoint_gvk_binding_rejects_swaps_and_allows_shared_valid_doc(
        self,
    ) -> None:
        index = {
            "paths": {
                "api/v1": {"serverRelativeURL": "/openapi/v3/api/v1?hash=core"},
                "apis/apps/v1": {
                    "serverRelativeURL": "/openapi/v3/apis/apps/v1?hash=apps"
                },
            }
        }
        apps_only = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "io.k8s.apps.v1.Deployment": {
                        "type": "object",
                        "x-kubernetes-group-version-kind": [
                            {"group": "apps", "version": "v1", "kind": "Deployment"}
                        ],
                    }
                }
            },
        }
        capture = {
            "surfaces": [
                {
                    "surface": "builtin-openapi",
                    "state": "captured",
                    "artifacts": [
                        {
                            "endpoint": "/openapi/v3",
                            "raw_hash": "index",
                            "document_type": "OpenAPIv3Discovery",
                        },
                        {
                            "endpoint": "/openapi/v3/api/v1?hash=core",
                            "raw_hash": "shared",
                            "document_type": "OpenAPIv3Document",
                        },
                        {
                            "endpoint": "/openapi/v3/apis/apps/v1?hash=apps",
                            "raw_hash": "shared",
                            "document_type": "OpenAPIv3Document",
                        },
                    ],
                }
            ]
        }
        documents = {
            "index": [{"payload": index}],
            "shared": [{"payload": apps_only}],
        }
        errors = kr.validate_live_api_artifacts(capture, documents)
        self.assertTrue(
            any("no matching Kubernetes GVK" in error for _, error in errors)
        )

        shared_valid = copy.deepcopy(apps_only)
        shared_valid["components"]["schemas"]["io.k8s.api.core.v1.Pod"] = {
            "type": "object",
            "x-kubernetes-group-version-kind": [
                {"group": "", "version": "v1", "kind": "Pod"}
            ],
        }
        documents["shared"] = [{"payload": shared_valid}]
        self.assertEqual([], kr.validate_live_api_artifacts(capture, documents))

        swapped = copy.deepcopy(index)
        swapped["paths"]["api/v1"][
            "serverRelativeURL"
        ] = "/openapi/v3/apis/apps/v1?hash=core"
        _endpoints, index_errors = kr.expected_openapi_endpoints(swapped)
        self.assertTrue(any("does not match" in error for error in index_errors))

    def test_identical_endpoint_projections_share_one_input_and_keep_all_mappings(
        self,
    ) -> None:
        output = self.base / "capture"
        output.mkdir()
        descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        inputs: list[str] = []
        hashes: dict[str, str] = {}
        shared_document = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "io.k8s.api.core.v1.Pod": {
                        "type": "object",
                        "x-kubernetes-group-version-kind": [
                            {"group": "", "version": "v1", "kind": "Pod"}
                        ],
                    },
                    "io.k8s.apps.v1.Deployment": {
                        "type": "object",
                        "x-kubernetes-group-version-kind": [
                            {"group": "apps", "version": "v1", "kind": "Deployment"}
                        ],
                    },
                }
            },
        }
        shared_raw = json.dumps(shared_document, sort_keys=True).encode()
        try:
            first_hash = live.materialize_unique_projected_artifact(
                descriptor,
                output,
                "core.json",
                shared_raw,
                hashes,
                inputs,
            )
            second_hash = live.materialize_unique_projected_artifact(
                descriptor,
                output,
                "apps.json",
                shared_raw,
                hashes,
                inputs,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(first_hash, second_hash)
        self.assertEqual(1, len(inputs))
        self.assertTrue((output / "core.json").exists())
        self.assertFalse((output / "apps.json").exists())

        index = {
            "paths": {
                "api/v1": {"serverRelativeURL": "/openapi/v3/api/v1?hash=core"},
                "apis/apps/v1": {
                    "serverRelativeURL": "/openapi/v3/apis/apps/v1?hash=apps"
                },
            }
        }
        index_path = output / "index.json"
        index_path.write_text(json.dumps(index, sort_keys=True), encoding="utf-8")
        index_hash = kr.file_hash(index_path.read_bytes())
        receipt = self.v3_capture_receipt()
        artifacts = [
            {
                "endpoint": "/openapi/v3",
                "raw_hash": index_hash,
                "document_type": "OpenAPIv3Discovery",
            },
            {
                "endpoint": "/openapi/v3/api/v1?hash=core",
                "raw_hash": first_hash,
                "document_type": "OpenAPIv3Document",
            },
            {
                "endpoint": "/openapi/v3/apis/apps/v1?hash=apps",
                "raw_hash": first_hash,
                "document_type": "OpenAPIv3Document",
            },
        ]
        receipt["surfaces"]["builtin-openapi"] = {
            "state": "captured",
            "raw_hashes": sorted({index_hash, first_hash}),
            "resource_kinds": list(kr.LIVE_SURFACE_RESOURCE_KINDS["builtin-openapi"]),
            "artifacts": sorted(artifacts, key=kr.canonical_json),
        }
        imported = kr.import_live(
            [str(index_path), inputs[0]], capture_manifest=receipt
        )
        forbidden_gaps = {
            "live-export-invalid",
            "live-export-unbound",
            "live-surface-content-mismatch",
        }
        self.assertFalse(forbidden_gaps & {gap["gap_type"] for gap in imported["gaps"]})

    def test_fatal_capture_failure_removes_unreceipted_artifacts(self) -> None:
        output = self.base / "failed-capture"
        queries = (
            live.Query(
                "server-version",
                "first.json",
                ("version", "-o", "json"),
                response_type="server-version",
            ),
            live.Query(
                "server-version",
                "second.json",
                ("version", "-o", "json"),
                response_type="server-version",
            ),
        )
        payload = {"serverVersion": {"gitVersion": "v1.36.0"}}
        kubeconfig_fd = os.open("/dev/null", os.O_RDONLY)
        self.addCleanup(os.close, kubeconfig_fd)
        with (
            mock.patch.object(live, "QUERIES", queries),
            mock.patch.object(live, "resolve_cluster_uid", return_value="cluster-uid"),
            mock.patch.object(
                live,
                "command_json",
                return_value=(payload, json.dumps(payload).encode()),
            ),
            mock.patch.object(
                live,
                "project_query_payload",
                side_effect=[{"first": "safe"}, TypeError("projection failed")],
            ),
        ):
            with self.assertRaisesRegex(TypeError, "projection failed"):
                live._capture_with_bound_kubeconfig(
                    output,
                    kubectl="/usr/bin/kubectl",
                    kubeconfig="/dev/null",
                    context="fixture",
                    git_commit="0" * 40,
                    observed_at=OBSERVED_AT,
                    timeout=1.0,
                    kubeconfig_snapshot={
                        "source": {
                            "path": "/dev/null",
                            "sha256": "sha256:" + "a" * 64,
                            "size": 0,
                            "device": 0,
                            "inode": 0,
                        },
                        "execution": {
                            "path": "/dev/null",
                            "policy": "test",
                            "sha256": "sha256:" + "a" * 64,
                            "size": 0,
                        },
                    },
                    kubeconfig_fd=kubeconfig_fd,
                    capture_generator={},
                    capture_started_at=OBSERVED_AT,
                    wall_clock=lambda: kr.parse_utc_second(OBSERVED_AT).timestamp(),
                    verify_executable=False,
                )
        self.assertFalse(output.exists())

    def test_input_preflight_rejects_multiplication_and_aggregate_before_reads(
        self,
    ) -> None:
        first = self.base / "first.json"
        second = self.base / "second.json"
        first.write_text('{"one":1}', encoding="utf-8")
        second.write_text('{"two":2}', encoding="utf-8")
        with mock.patch.object(kr, "read_json_document") as reader:
            with self.assertRaisesRegex(kr.RegistryInputError, "file bound"):
                kr.read_bounded_unique_json_inputs(
                    [str(first), str(second)],
                    max_files=1,
                    max_total_bytes=100,
                    label="test inputs",
                )
            reader.assert_not_called()
        with mock.patch.object(kr, "read_json_document") as reader:
            with self.assertRaisesRegex(kr.RegistryInputError, "aggregate byte bound"):
                kr.read_bounded_unique_json_inputs(
                    [str(first), str(second)],
                    max_files=2,
                    max_total_bytes=first.stat().st_size + second.stat().st_size - 1,
                    label="test inputs",
                )
            reader.assert_not_called()
        hardlink = self.base / "hardlink.json"
        os.link(first, hardlink)
        with mock.patch.object(kr, "read_json_document") as reader:
            with self.assertRaisesRegex(kr.RegistryInputError, "file identity"):
                kr.read_bounded_unique_json_inputs(
                    [str(first), str(hardlink)],
                    max_files=2,
                    max_total_bytes=100,
                    label="test inputs",
                )
            reader.assert_not_called()
        same = self.base / "same.json"
        same.write_bytes(first.read_bytes())
        with self.assertRaisesRegex(kr.RegistryInputError, "content hash"):
            kr.read_bounded_unique_json_inputs(
                [str(first), str(same)],
                max_files=2,
                max_total_bytes=100,
                label="test inputs",
            )
        with self.assertRaisesRegex(kr.RegistryInputError, "must not also"):
            kr.import_live([str(first)], capture_manifest=str(first))
        budgets: list[tuple[str, int]] = []

        def bounded_reader(path: str, *, max_bytes: int = kr.MAX_JSON_INPUT_BYTES):
            budgets.append((path, max_bytes))
            return ({"path": path}, b"{}" if path == "-" else first.read_bytes())

        with mock.patch.object(kr, "read_json_document", side_effect=bounded_reader):
            kr.read_bounded_unique_json_inputs(
                ["-", str(first)],
                max_files=2,
                max_total_bytes=first.stat().st_size + 5,
                label="test inputs",
            )
        self.assertEqual(("-", 5), budgets[0])

    def test_candidate_shape_and_cardinality_gates_precede_schema_iteration(
        self,
    ) -> None:
        for field in kr.ARRAY_FIELDS:
            self.assertEqual(
                [f"{field} must be an array"], kr.validate_manifest({field: 1})
            )
        for candidate, expected in (
            ({"input_set": {"entries": 1}}, "input_set.entries must be an array"),
            (
                {"discovery_scope": {"inputs": 1}},
                "discovery_scope.inputs must be an array",
            ),
            (
                {"merge_lineage": {"input_manifest_ids": 1}},
                "merge_lineage.input_manifest_ids must be an array",
            ),
        ):
            self.assertEqual([expected], kr.validate_manifest(candidate))

        malformed = (
            {"generator": {}},
            {"generator": {"schema_hash": None}},
            {"input_set": {"entries": [None]}},
            {"discovery_scope": {"inputs": [None]}},
            {"components": [{}], "generator": {}},
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                errors = kr.validate_manifest(candidate)
                self.assertTrue(errors)

        manifest = self.minimal_builder()[0].manifest()
        field_targets = {
            **{field: kr.CANDIDATE_ARRAY_BOUNDS for field in kr.ARRAY_FIELDS},
        }
        for field, target in field_targets.items():
            candidate = copy.deepcopy(manifest)
            candidate[field] = [{}, {}]
            with mock.patch.dict(target, {field: 1}):
                errors = kr.validate_manifest(candidate)
            self.assertEqual([f"{field} exceeds record bound 1"], errors)
        for parent, child in (
            ("input_set", "entries"),
            ("discovery_scope", "inputs"),
            ("merge_lineage", "input_manifest_ids"),
        ):
            candidate = copy.deepcopy(manifest)
            candidate.setdefault(parent, {})[child] = ["a", "b"]
            with mock.patch.object(kr, "MAX_DISCOVERY_INPUTS", 1):
                errors = kr.validate_manifest(candidate)
            self.assertTrue(any("exceeds record bound 1" in error for error in errors))

    def test_kubeconfig_json_plugins_flow_yaml_and_sealed_source_races_fail_closed(
        self,
    ) -> None:
        json_config = self.base / "config.json"
        json_config.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "clusters": [
                        {"name": "local", "cluster": {"server": "https://localhost"}}
                    ],
                    "contexts": [
                        {
                            "name": "local",
                            "context": {"cluster": "local", "user": "local"},
                        }
                    ],
                    "current-context": "local",
                    "users": [
                        {
                            "name": "local",
                            "user": {"exec": {"command": "credential-helper"}},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        json_config.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "credential plugins"):
            live.kubeconfig_identity(json_config)

        flow = self.base / "flow-config"
        flow.write_text(
            "apiVersion: v1\nkind: Config\nclusters: [{name: local}]\n"
            "contexts: []\ncurrent-context: local\nusers: []\n",
            encoding="utf-8",
        )
        flow.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "flow syntax"):
            live.kubeconfig_identity(flow)

        source = self.base / "sealed-config"
        original = (
            "apiVersion: v1\nkind: Config\nclusters:\n"
            "- cluster:\n    server: https://127.0.0.1:6443\n  name: local\n"
            "contexts:\n- context:\n    cluster: local\n    user: local\n  name: local\n"
            "current-context: local\nusers:\n- name: local\n  user:\n    token: static\n"
        )
        source.write_text(original, encoding="utf-8")
        source.chmod(0o600)
        descriptor, snapshot = live.sealed_kubeconfig_snapshot(source)
        self.addCleanup(os.close, descriptor)
        self.assertEqual(source.as_posix(), snapshot["source"]["path"])
        self.assertEqual("sealed-memfd", snapshot["execution"]["policy"])
        source.write_text(original.replace("static", "changed"), encoding="utf-8")
        self.assertEqual(
            original.encode(),
            os.pread(descriptor, snapshot["execution"]["size"] + 1, 0),
        )
        self.assertEqual(
            snapshot["execution"]["path"],
            live.kubectl_command(
                "/usr/bin/kubectl",
                snapshot["execution"]["path"],
                "local",
                ("get", "--raw", "/api"),
            )[2],
        )
        with self.assertRaises(OSError) as sealed_error:
            os.write(descriptor, b"x")
        self.assertIn(sealed_error.exception.errno, {errno.EPERM, errno.EBADF})
        live.verify_sealed_kubeconfig_snapshot(descriptor, snapshot)

    def test_safe_projection_omits_literals_rejects_unsafe_uris_and_bounds_gvks(
        self,
    ) -> None:
        sentinel = "DO-NOT-PERSIST-SECRET"
        pod_query = live.Query("pods", "pods.json", ("get", "pods"), "Pod")
        projected = live.project_query_payload(
            pod_query,
            {
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": {},
                "items": [
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"namespace": "demo", "name": "demo"},
                        "spec": {
                            "nodeName": "node-a",
                            "containers": [
                                {
                                    "name": "main",
                                    "image": "ghcr.io/example/demo@sha256:" + "a" * 64,
                                    "env": [{"name": "PASSWORD", "value": sentinel}],
                                    "command": [sentinel],
                                    "args": [sentinel],
                                }
                            ],
                        },
                        "status": {},
                    }
                ],
            },
        )
        persisted = json.dumps(projected, sort_keys=True).encode()
        self.assertNotIn(sentinel.encode(), persisted)
        for forbidden in (b'"env"', b'"command"', b'"args"'):
            self.assertNotIn(forbidden, persisted)

        digest = "sha256:" + "a" * 64
        duplicate_digest = f"ghcr.io/example/demo:v1@{digest}@{digest}"
        duplicate_payload = copy.deepcopy(projected)
        duplicate_payload["items"][0]["spec"]["containers"][0][
            "image"
        ] = duplicate_digest
        duplicate_projected = live.project_query_payload(pod_query, duplicate_payload)
        self.assertEqual(
            duplicate_digest,
            duplicate_projected["items"][0]["spec"]["containers"][0]["image"],
        )

        credential_shaped = f"user:password@registry/x@{digest}"
        credential_payload = copy.deepcopy(projected)
        credential_payload["items"][0]["spec"]["containers"][0][
            "image"
        ] = credential_shaped
        with self.assertRaisesRegex(RuntimeError, "unsafe projected locator") as error:
            live.project_query_payload(pod_query, credential_payload)
        self.assertNotIn(credential_shaped, str(error.exception))
        self.assertTrue(
            kr.unsafe_candidate_locator_pointers({"image": credential_shaped})
        )

        argo_query = live.Query("argo", "argo.json", ("get", "argo"), "Application")
        with self.assertRaisesRegex(RuntimeError, "unsafe projected locator"):
            live.project_query_payload(
                argo_query,
                {
                    "apiVersion": "argoproj.io/v1alpha1",
                    "kind": "ApplicationList",
                    "metadata": {},
                    "items": [
                        {
                            "apiVersion": "argoproj.io/v1alpha1",
                            "kind": "Application",
                            "metadata": {"name": "bad"},
                            "spec": {
                                "source": {
                                    "repoURL": "https://user:token@example.invalid/repo"
                                }
                            },
                        }
                    ],
                },
            )

        sbom_query = live.Query(
            "workload-sboms", "sbom.json", ("get", "sbom"), "SbomReport"
        )
        safe_sbom = live.project_query_payload(
            sbom_query,
            {
                "apiVersion": "aquasecurity.github.io/v1alpha1",
                "kind": "SbomReportList",
                "metadata": {},
                "items": [
                    {
                        "apiVersion": "aquasecurity.github.io/v1alpha1",
                        "kind": "SbomReport",
                        "metadata": {"name": "safe"},
                        "report": {
                            "content": sentinel,
                            "properties": [
                                {"name": "platform", "value": "linux/amd64"},
                                "permitted-non-object-list-member",
                            ],
                            "scanner": {"name": "Trivy", "version": "1.2.3"},
                            "components": {
                                "components": [
                                    {
                                        "type": "library",
                                        "name": "safe-component",
                                        "version": "1.0.0",
                                        "hashes": [
                                            {
                                                "alg": "SHA-256",
                                                "content": "a" * 64,
                                            }
                                        ],
                                    }
                                ]
                            },
                        },
                    }
                ],
            },
        )
        serialized_sbom = json.dumps(safe_sbom, sort_keys=True)
        self.assertNotIn(sentinel, serialized_sbom)
        self.assertIn("a" * 64, serialized_sbom)
        self.assertEqual(
            {"name": "Trivy", "version": "1.2.3"},
            safe_sbom["items"][0]["report"]["scanner"],
        )
        self.assertEqual(
            [{"name": "platform", "value": "linux/amd64"}],
            safe_sbom["items"][0]["report"]["properties"],
        )
        with self.assertRaisesRegex(RuntimeError, "unsafe projected locator"):
            live.project_query_payload(
                sbom_query,
                {
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "SbomReportList",
                    "metadata": {},
                    "items": [
                        {
                            "apiVersion": "aquasecurity.github.io/v1alpha1",
                            "kind": "SbomReport",
                            "metadata": {"name": "bad"},
                            "report": {
                                "artifact": {
                                    "repository": "https://user:token@example.invalid/image"
                                },
                                "components": {"components": []},
                            },
                        }
                    ],
                },
            )

        openapi_query = live.Query(
            "builtin-openapi",
            "openapi.json",
            ("get", "--raw", "/openapi/v3/apis/apps/v1"),
            "OpenAPIv3Document",
            "openapi-document",
        )
        openapi = live.project_query_payload(
            openapi_query,
            {
                "openapi": "3.0.0",
                "components": {
                    "schemas": {
                        "io.k8s.apps.v1.Deployment": {
                            "type": "object",
                            "x-kubernetes-group-version-kind": [
                                {
                                    "group": "apps",
                                    "version": "v1",
                                    "kind": "Deployment",
                                    "env": [{"value": sentinel}],
                                }
                            ],
                        },
                        "io.k8s.api.core.v1.Secret": {
                            "type": "object",
                            "x-kubernetes-group-version-kind": [
                                {"group": "", "version": "v1", "kind": "Secret"}
                            ],
                        },
                    }
                },
            },
        )
        gvk = openapi["components"]["schemas"]["io.k8s.apps.v1.Deployment"][
            "x-kubernetes-group-version-kind"
        ][0]
        self.assertEqual({"group": "apps", "version": "v1", "kind": "Deployment"}, gvk)
        self.assertIn("io.k8s.api.core.v1.Secret", openapi["components"]["schemas"])
        with self.assertRaisesRegex(RuntimeError, "forbidden by projection policy"):
            live.assert_safe_projection({"password": sentinel})
        for forbidden in (
            {"data": {"x": sentinel}},
            {"stringData": {}},
            {"token": sentinel},
        ):
            with self.assertRaisesRegex(RuntimeError, "forbidden by projection policy"):
                live.assert_safe_projection(forbidden)

        openapi_index_query = live.Query(
            "builtin-openapi",
            "openapi-index.json",
            ("get", "--raw", "/openapi/v3"),
            "OpenAPIv3Discovery",
            "openapi-index",
        )
        with self.assertRaisesRegex(RuntimeError, "unsafe projected locator"):
            live.project_query_payload(
                openapi_index_query,
                {
                    "paths": {
                        "apis/apps/v1": {
                            "serverRelativeURL": "/openapi/v3/apis/apps/v1?%2574oken=x"
                        }
                    }
                },
            )

        wrong_items = {
            "apiVersion": "apps/v1",
            "kind": "DaemonSetList",
            "metadata": {},
            "items": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "wrong"},
                    "spec": {},
                    "status": {},
                }
            ],
        }
        with self.assertRaisesRegex(RuntimeError, "mismatched typed item"):
            live.project_query_payload(
                live.Query(
                    "controllers",
                    "daemonsets.json",
                    ("get", "--raw", "/apis/apps/v1/daemonsets"),
                    "DaemonSet",
                ),
                wrong_items,
            )

        untyped_items = {
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {},
            "items": [
                {
                    "metadata": {"namespace": "demo", "name": "untyped"},
                    "spec": {"containers": []},
                    "status": {},
                }
            ],
        }
        pod_query = live.Query(
            "pods", "pods.json", ("get", "--raw", "/api/v1/pods"), "Pod"
        )
        normalized_items = live.project_query_payload(pod_query, untyped_items)["items"]
        self.assertEqual("v1", normalized_items[0]["apiVersion"])
        self.assertEqual("Pod", normalized_items[0]["kind"])
        self.assertNotIn("apiVersion", untyped_items["items"][0])
        self.assertNotIn("kind", untyped_items["items"][0])

        for partial_item in (
            {"kind": "Pod", "metadata": {}},
            {"apiVersion": "v1", "metadata": {}},
            {"kind": "Deployment", "apiVersion": "v1", "metadata": {}},
            {"kind": "Pod", "apiVersion": "apps/v1", "metadata": {}},
            "not-an-object",
        ):
            invalid_items = copy.deepcopy(untyped_items)
            invalid_items["items"] = [partial_item]
            with self.assertRaisesRegex(RuntimeError, "mismatched typed item"):
                live.project_query_payload(pod_query, invalid_items)

        wrong_envelope = copy.deepcopy(untyped_items)
        wrong_envelope["apiVersion"] = "apps/v1"
        with self.assertRaisesRegex(RuntimeError, "mismatched apiVersion"):
            live.project_query_payload(pod_query, wrong_envelope)

    def test_container_status_projection_omits_only_empty_locators(self) -> None:
        image = "ghcr.io/example/demo@sha256:" + "a" * 64
        image_id = "containerd://" + image
        normal = live.safe_container_statuses(
            [
                {
                    "name": "main",
                    "image": image,
                    "imageID": image_id,
                    "ready": True,
                    "restartCount": 0,
                }
            ]
        )
        self.assertEqual(image, normal[0]["image"])
        self.assertEqual(image_id, normal[0]["imageID"])

        empty = live.safe_container_statuses(
            [{"name": "pending", "image": "", "imageID": "", "ready": False}]
        )
        self.assertEqual({"name": "pending", "ready": False}, empty[0])

        with self.assertRaisesRegex(RuntimeError, "must be a string"):
            live.safe_container_statuses([{"imageID": {}}])

        def pod_payload(runtime_image_id: str) -> dict[str, Any]:
            return {
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": {},
                "items": [
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"namespace": "demo", "name": "demo"},
                        "spec": {"containers": [{"name": "main", "image": image}]},
                        "status": {
                            "containerStatuses": [
                                {
                                    "name": "main",
                                    "image": image,
                                    "imageID": runtime_image_id,
                                }
                            ]
                        },
                    }
                ],
            }

        query = live.Query("pods", "pods.json", ("get", "pods"), "Pod")
        projected_empty = live.project_query_payload(query, pod_payload(""))
        projected_status = projected_empty["items"][0]["status"]["containerStatuses"][0]
        self.assertNotIn("imageID", projected_status)
        empty_export = self.base / "empty-runtime-image.json"
        empty_export.write_text(json.dumps(projected_empty), encoding="utf-8")
        empty_manifest = kr.import_live([str(empty_export)])
        self.assertTrue(
            any(
                gap["gap_type"] == "live-imageid-missing"
                for gap in empty_manifest["gaps"]
            )
        )

        for unsafe in (" ", "containerd://ghcr.io/example/demo@not-a-digest"):
            with self.assertRaisesRegex(RuntimeError, "unsafe projected locator"):
                live.project_query_payload(query, pod_payload(unsafe))

    def test_hash_bound_v3_import_rejects_unsanitized_exact_projection(self) -> None:
        sentinel = "DO-NOT-PERSIST-SECRET"
        payload = {
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {},
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"namespace": "demo", "name": "demo"},
                    "spec": {
                        "containers": [
                            {
                                "name": "main",
                                "image": "ghcr.io/example/demo@sha256:" + "a" * 64,
                                "env": [{"name": "TOKEN", "value": sentinel}],
                            }
                        ]
                    },
                    "status": {},
                }
            ],
        }
        path = self.base / "pods.json"
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        raw_hash = kr.file_hash(path.read_bytes())
        receipt = self.v3_capture_receipt()
        receipt["surfaces"]["pods"] = {
            "state": "captured",
            "raw_hashes": [raw_hash],
            "resource_kinds": ["Pod"],
            "artifacts": [
                {
                    "endpoint": "/api/v1/pods",
                    "raw_hash": raw_hash,
                    "document_type": "Pod",
                }
            ],
        }
        with self.assertRaisesRegex(
            kr.RegistryInputError, "violates identity-only projection"
        ):
            kr.import_live([str(path)], capture_manifest=receipt)
        self.assertNotIn(sentinel, json.dumps(receipt, sort_keys=True))

    @staticmethod
    def namespace_index_payload(namespaces: Sequence[str]) -> dict[str, object]:
        payload = {
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "metadata": {"resourceVersion": "1"},
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": namespace,
                        "uid": f"uid-{namespace}",
                        "resourceVersion": "1",
                    },
                }
                for namespace in namespaces
            ],
        }
        return dict(
            live.project_query_payload(
                live.Query(
                    "workload-sboms",
                    "namespaces.json",
                    ("get", "--raw", kr.LIVE_NAMESPACE_INDEX_ENDPOINT),
                    "Namespace",
                ),
                payload,
            )
        )

    @staticmethod
    def sbom_page_payload(
        namespace: str, repositories: Sequence[str]
    ) -> dict[str, object]:
        items = []
        for index, repository in enumerate(repositories):
            digest = f"sha256:{index:064d}"
            items.append(
                {
                    "apiVersion": "aquasecurity.github.io/v1alpha1",
                    "kind": "SbomReport",
                    "metadata": {
                        "namespace": namespace,
                        "name": f"replicaset-{repository.rsplit('/', 1)[-1]}",
                        "uid": f"uid-{namespace}-{index}",
                        "resourceVersion": "1",
                    },
                    "report": {
                        "artifact": {
                            "digest": digest,
                            "repository": repository,
                            "tag": "v1.0.0",
                        },
                        "registry": {"server": "index.docker.io"},
                        "scanner": {"name": "Trivy", "vendor": "Aqua", "version": "1"},
                        "components": {
                            "bomFormat": "CycloneDX",
                            "specVersion": "1.6",
                            "metadata": {
                                "component": {
                                    "bom-ref": f"pkg:oci/demo@{digest}",
                                    "name": f"{repository}@{digest}",
                                    "type": "container",
                                }
                            },
                            "components": [
                                {
                                    "bom-ref": "pkg:deb/debian/zlib1g@1.3-1?arch=amd64",
                                    "name": "zlib1g",
                                    "purl": "pkg:deb/debian/zlib1g@1.3-1?arch=amd64",
                                    "type": "library",
                                    "version": "1.3-1",
                                }
                            ],
                        },
                    },
                }
            )
        payload = {
            "apiVersion": "aquasecurity.github.io/v1alpha1",
            "kind": "SbomReportList",
            "metadata": {"resourceVersion": "1"},
            "items": items,
        }
        return dict(
            live.project_query_payload(
                live.Query(
                    "workload-sboms",
                    "page.json",
                    ("get", "--raw", kr.sbom_page_endpoint(namespace)),
                    "SbomReport",
                ),
                payload,
            )
        )

    def paged_sbom_capture(
        self, pages: Mapping[str, Sequence[str]]
    ) -> tuple[dict[str, object], list[str]]:
        """Write a v4 namespace-paged workload-sboms capture to disk."""

        namespaces = sorted(pages)
        documents = {
            kr.LIVE_NAMESPACE_INDEX_ENDPOINT: (
                "namespaces.json",
                self.namespace_index_payload(namespaces),
                "Namespace",
            )
        }
        for namespace in namespaces:
            documents[kr.sbom_page_endpoint(namespace)] = (
                f"sbomreports-{namespace}.json",
                self.sbom_page_payload(namespace, pages[namespace]),
                "SbomReport",
            )
        artifacts: list[dict[str, str]] = []
        raw_hashes: list[str] = []
        paths: list[str] = []
        for endpoint, (filename, payload, document_type) in documents.items():
            path = self.base / filename
            path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            raw_hash = kr.file_hash(path.read_bytes())
            raw_hashes.append(raw_hash)
            paths.append(str(path))
            artifacts.append(
                {
                    "endpoint": endpoint,
                    "raw_hash": raw_hash,
                    "document_type": document_type,
                }
            )
        receipt = self.v3_capture_receipt(4)
        receipt["surfaces"]["workload-sboms"] = {
            "state": "captured",
            "raw_hashes": sorted(set(raw_hashes)),
            "resource_kinds": list(kr.live_surface_resource_kinds("workload-sboms", 4)),
            "artifacts": sorted(artifacts, key=kr.canonical_json),
        }
        return receipt, sorted(paths)

    def test_v4_namespace_paged_sboms_import_without_contract_gaps(self) -> None:
        receipt, paths = self.paged_sbom_capture(
            {"demo": ["example/api"], "empty": [], "other": ["example/worker"]}
        )
        imported = kr.import_live(paths, capture_manifest=receipt)
        gap_types = {gap["gap_type"] for gap in imported["gaps"]}
        self.assertFalse(
            {
                "live-capture-metadata-invalid",
                "live-export-invalid",
                "live-export-unbound",
                "live-inventory-truncated",
                "live-kind-unsupported",
                "live-surface-content-mismatch",
                "live-surface-hash-mismatch",
            }
            & gap_types
        )
        self.assertNotIn(
            "workload-sboms",
            {
                gap.get("metadata", {}).get("surface")
                for gap in imported["gaps"]
                if gap["gap_type"] == "live-required-surface-unavailable"
            },
        )
        sbom_roles = {
            occurrence["role"]
            for occurrence in imported["occurrences"]
            if occurrence["role"] in {"live-sbom-artifact", "sbom-component"}
        }
        self.assertEqual({"live-sbom-artifact", "sbom-component"}, sbom_roles)

    def test_v4_page_closure_fails_on_missing_extra_and_misfiled_pages(self) -> None:
        documents = {
            "index": [{"payload": self.namespace_index_payload(["demo", "other"])}],
            "demo": [{"payload": self.sbom_page_payload("demo", ["example/api"])}],
            "other": [{"payload": self.sbom_page_payload("other", ["example/worker"])}],
            "misfiled": [{"payload": self.sbom_page_payload("demo", ["example/api"])}],
        }

        def capture(artifacts: Sequence[Mapping[str, str]]) -> dict[str, object]:
            return {
                "contract_version": 4,
                "surfaces": [
                    {
                        "surface": "workload-sboms",
                        "state": "captured",
                        "artifacts": list(artifacts),
                    }
                ],
            }

        root = {
            "endpoint": kr.LIVE_NAMESPACE_INDEX_ENDPOINT,
            "raw_hash": "index",
            "document_type": "Namespace",
        }
        demo_page = {
            "endpoint": kr.sbom_page_endpoint("demo"),
            "raw_hash": "demo",
            "document_type": "SbomReport",
        }
        other_page = {
            "endpoint": kr.sbom_page_endpoint("other"),
            "raw_hash": "other",
            "document_type": "SbomReport",
        }
        self.assertEqual(
            [],
            kr.validate_live_sbom_pages(
                capture([root, demo_page, other_page]), documents
            ),
        )
        for artifacts, expected in (
            ([root, demo_page], "omits namespace pages"),
            (
                [
                    root,
                    demo_page,
                    other_page,
                    {
                        "endpoint": kr.sbom_page_endpoint("stray"),
                        "raw_hash": "demo",
                        "document_type": "SbomReport",
                    },
                ],
                "contains unadvertised namespace pages",
            ),
            (
                [root, demo_page, {**other_page, "raw_hash": "misfiled"}],
                "contains reports outside its namespace",
            ),
            ([demo_page, other_page], "omits its namespace paging root"),
        ):
            with self.subTest(expected=expected):
                messages = [
                    message
                    for _surface, message in kr.validate_live_sbom_pages(
                        capture(artifacts), documents
                    )
                ]
                self.assertTrue(
                    any(expected in message for message in messages), messages
                )

    def test_v3_capture_receipts_still_normalize_after_the_v4_paging_bump(self) -> None:
        receipt = self.v3_capture_receipt(3)
        receipt["surfaces"]["workload-sboms"] = {
            "state": "captured",
            "raw_hashes": ["sha256:" + "a" * 64],
            "resource_kinds": ["SbomReport"],
            "artifacts": [
                {
                    "endpoint": "/apis/aquasecurity.github.io/v1alpha1/sbomreports",
                    "raw_hash": "sha256:" + "a" * 64,
                    "document_type": "SbomReport",
                }
            ],
        }
        raw = kr.canonical_json(receipt).encode("utf-8")
        normalized, errors = kr.normalize_live_capture_manifest(
            receipt, content_hash=kr.file_hash(raw), raw_hash=kr.file_hash(raw)
        )
        self.assertEqual(
            [], [error for error in errors if error[2] == "workload-sboms"]
        )
        self.assertEqual(3, normalized["contract_version"])
        self.assertEqual(kr.LIVE_CAPTURE_BOUNDS_V3, normalized["bounds"])
        self.assertNotEqual(
            kr.LIVE_CAPTURE_BOUNDS_V3["capture_commands"],
            kr.LIVE_CAPTURE_BOUNDS["capture_commands"],
        )

    def test_sbom_page_queries_are_ordered_bounded_and_root_validated(self) -> None:
        index = self.namespace_index_payload(["zeta", "alpha", "mid"])
        queries = live.sbom_page_queries(index)
        ordered = ("alpha", "mid", "zeta")
        self.assertEqual(
            [kr.sbom_page_endpoint(name) for name in ordered],
            [live.artifact_endpoint(query) for query in queries],
        )
        self.assertEqual(
            [
                live.endpoint_filename("sbomreports", kr.sbom_page_endpoint(name))
                for name in ordered
            ],
            [query.filename for query in queries],
        )
        self.assertEqual({"workload-sboms"}, {query.surface for query in queries})
        self.assertEqual(queries, live.sbom_page_queries(index))
        with self.assertRaisesRegex(RuntimeError, "typed NamespaceList"):
            live.sbom_page_queries({"kind": "PodList", "apiVersion": "v1", "items": []})
        with mock.patch.object(live, "MAX_DYNAMIC_QUERIES", 2):
            with self.assertRaisesRegex(RuntimeError, "endpoint bound"):
                live.sbom_page_queries(index)

    def test_workingdir_is_excluded_by_default_and_reference_only_when_requested(
        self,
    ) -> None:
        files = self.fixture_files()
        files[".workingdir2/review.yaml"] = "image: ghcr.io/example/review:v1\n"
        root = self.repository(files)
        default = kr.discover_repo(root, observed_at=OBSERVED_AT)
        included = kr.discover_repo(
            root,
            include_workingdir=True,
            observed_at=OBSERVED_AT,
        )
        self.assertNotEqual(default["manifest_id"], included["manifest_id"])
        review_occurrences = [
            item
            for item in included["occurrences"]
            if item.get("raw_value") == "ghcr.io/example/review:v1"
        ]
        self.assertTrue(review_occurrences)
        self.assertEqual(
            {"reference-only"}, {item["lifecycle"] for item in review_occurrences}
        )

    def test_git_metadata_filters_refs_and_modify_restore_races_fail_closed(
        self,
    ) -> None:
        root = self.repository({"package.json": '{"name":"safe","version":"1.0.0"}'})
        marker = self.base / "git-hook-ran"
        helper = self.base / "git-helper.sh"
        helper.write_text(
            f"#!/bin/sh\ntouch {marker.as_posix()}\ncat\n", encoding="utf-8"
        )
        helper.chmod(0o700)
        run_git(root, "config", "core.fsmonitor", helper.as_posix())
        run_git(root, "config", "filter.poison.clean", helper.as_posix())
        run_git(root, "config", "filter.poison.required", "true")
        info_attributes = root / ".git/info/attributes"
        info_attributes.write_text("* filter=poison\n", encoding="utf-8")
        kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertFalse(marker.exists())

        packed = self.repository({"x.yaml": "image: ghcr.io/example/a:v1\n"})
        run_git(packed, "pack-refs", "--all")
        (packed / "x.yaml").write_text(
            "image: ghcr.io/example/b:v2\n", encoding="utf-8"
        )
        run_git(packed, "add", "x.yaml")
        run_git(packed, "commit", "-q", "-m", "test: loose ref after packing")
        self.assertEqual(
            [], kr.validate_manifest(kr.discover_repo(packed, observed_at=OBSERVED_AT))
        )

        index_repo = self.repository({"x.yaml": "kind: ConfigMap\n"})
        index = index_repo / ".git/index"
        index_copy = index_repo / ".git/index-copy"
        index_copy.write_bytes(index.read_bytes())
        index.unlink()
        index.symlink_to(index_copy.name)
        with self.assertRaisesRegex(kr.RegistryInputError, "Git index"):
            kr.repository_snapshot(index_repo)

        marker_repo = self.repository({"x.yaml": "kind: ConfigMap\n"})
        git_directory = marker_repo / ".git"
        real_git_directory = marker_repo / ".git-real"
        git_directory.rename(real_git_directory)
        git_directory.symlink_to(real_git_directory.name, target_is_directory=True)
        with self.assertRaisesRegex(kr.RegistryInputError, "must not be a symlink"):
            kr.repository_snapshot(marker_repo)

    def test_discovery_reads_exact_head_blobs_despite_modify_read_restore(self) -> None:
        root = self.repository({"package.json": '{"name":"safe","version":"1.0.0"}'})
        baseline = kr.discover_repo(root, observed_at=OBSERVED_AT)
        original_read = kr.read_text

        def raced_read(view_root: Path, path: Path) -> tuple[bytes, str]:
            source = root / path.relative_to(view_root)
            before = source.read_bytes()
            source.write_text('{"name":"poisoned","version":"9.9.9"}', encoding="utf-8")
            try:
                return original_read(view_root, path)
            finally:
                source.write_bytes(before)

        with mock.patch.object(kr, "read_text", side_effect=raced_read):
            raced = kr.discover_repo(root, observed_at=OBSERVED_AT)
        self.assertEqual(baseline, raced)
        self.assertNotIn("poisoned", json.dumps(raced))

    def test_bound_head_and_index_reject_a_to_b_to_a_git_race(self) -> None:
        root = self.repository({"x.yaml": "image: ghcr.io/example/a:v1\n"})
        commit_a = run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        (root / "x.yaml").write_text("image: ghcr.io/example/b:v2\n", encoding="utf-8")
        run_git(root, "add", "x.yaml")
        run_git(root, "commit", "-q", "-m", "test: commit b")
        commit_b = run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        run_git(root, "reset", "--hard", commit_a)
        original_layout = kr.git_layout_identity
        calls = 0

        def swap_after_bound(path: Path) -> dict[str, object]:
            nonlocal calls
            calls += 1
            layout = original_layout(path)
            if calls == 1:
                run_git(root, "reset", "--hard", commit_b)
            return layout

        try:
            with mock.patch.object(
                kr, "git_layout_identity", side_effect=swap_after_bound
            ):
                with self.assertRaisesRegex(
                    kr.RegistryInputError, "changed before it could be bound"
                ):
                    kr.repository_snapshot(root)
        finally:
            run_git(root, "reset", "--hard", commit_a)
        self.assertEqual(
            commit_a, run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        )
        self.assertIn("example/a", (root / "x.yaml").read_text(encoding="utf-8"))

    def test_partial_clone_missing_object_never_invokes_promisor_remote(self) -> None:
        self.assertEqual("1", kr.FIXED_SUBPROCESS_ENV["GIT_NO_LAZY_FETCH"])
        root = self.repository({"data.json": '{"safe":true}\n'})
        blob = run_git(root, "rev-parse", "HEAD:data.json").stdout.decode().strip()
        marker = self.base / "promisor-invoked"
        helper = self.base / "promisor-helper"
        helper.write_text(
            f"#!/bin/sh\ntouch {marker.as_posix()}\nexit 1\n", encoding="utf-8"
        )
        helper.chmod(0o700)
        run_git(root, "config", "remote.origin.url", f"ext::{helper.as_posix()}")
        run_git(root, "config", "remote.origin.promisor", "true")
        run_git(root, "config", "remote.origin.partialclonefilter", "blob:none")
        run_git(root, "config", "extensions.partialClone", "origin")
        object_path = root / ".git/objects" / blob[:2] / blob[2:]
        object_path.unlink()
        with self.assertRaises(kr.RegistryInputError):
            kr.repository_snapshot(root)
        self.assertFalse(marker.exists())

    def test_capture_generator_requires_exact_clean_claimed_commit(self) -> None:
        root = self.repository(
            {
                relative: (REPO_ROOT / relative).read_text(encoding="utf-8")
                for relative in kr.LIVE_CAPTURE_GENERATOR_PATHS
            }
        )
        commit = run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        identity = live.capture_generator_identity(commit, root=root)
        self.assertEqual(commit, identity["git_commit"])
        self.assertEqual(
            list(kr.LIVE_CAPTURE_GENERATOR_PATHS),
            [source["path"] for source in identity["sources"]],
        )
        with self.assertRaisesRegex(RuntimeError, "claimed git commit"):
            live.capture_generator_identity("0" * len(commit), root=root)
        with mock.patch.object(
            live, "project_query_payload", lambda query, payload: payload
        ):
            with self.assertRaisesRegex(kr.RegistryInputError, "does not match"):
                live.capture_generator_identity(commit, root=root)
        with mock.patch.object(live, "QUERIES", ()):
            with self.assertRaisesRegex(kr.RegistryInputError, "does not match"):
                live.capture_generator_identity(commit, root=root)
        with mock.patch.object(live, "MAX_DYNAMIC_QUERIES", 0):
            with self.assertRaisesRegex(kr.RegistryInputError, "does not match"):
                live.capture_generator_identity(commit, root=root)
        with mock.patch.object(kr, "IDENTITY_PROJECTION_FORBIDDEN_KEYS", set()):
            with self.assertRaisesRegex(kr.RegistryInputError, "does not match"):
                live.capture_generator_identity(commit, root=root)
        source = root / kr.LIVE_CAPTURE_GENERATOR_PATHS[0]
        source.write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(kr.RegistryInputError):
            live.capture_generator_identity(commit, root=root)

    def test_recorded_capture_generator_replays_after_head_advance(self) -> None:
        root = self.repository(
            {
                relative: (REPO_ROOT / relative).read_text(encoding="utf-8")
                for relative in (
                    *kr.LIVE_CAPTURE_GENERATOR_PATHS,
                    kr.REVIEWED_SCHEMA_RELATIVE,
                    kr.SNAPSHOT_RECEIPT_SCHEMA_RELATIVE,
                )
            }
        )
        historical_commit = run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        sources = []
        for relative in kr.LIVE_CAPTURE_GENERATOR_PATHS:
            raw = (root / relative).read_bytes()
            sources.append(
                {"path": relative, "sha256": kr.file_hash(raw), "size": len(raw)}
            )
        capture_generator = {
            "git_commit": historical_commit,
            "sources": sources,
            "ruleset_hash": kr.ruleset_hash_from_registry_source(
                (root / "tools/knowledge-registry/knowledge_registry.py").read_bytes(),
                "tools/knowledge-registry/knowledge_registry.py",
            ),
        }
        (root / "unrelated.txt").write_text("new head\n", encoding="utf-8")
        run_git(root, "add", "unrelated.txt")
        run_git(root, "commit", "-q", "-m", "test: advance head")
        self.assertEqual(
            historical_commit,
            kr.verify_recorded_capture_generator_binding(
                capture_generator, repository=root
            )["git_commit"],
        )
        receipt = self.v3_capture_receipt()
        receipt["git_commit"] = historical_commit
        receipt["capture_generator"] = copy.deepcopy(capture_generator)
        exported = self.base / "historical-export.json"
        exported.write_text("{}\n", encoding="utf-8")
        with (
            mock.patch.object(
                kr,
                "__file__",
                str(root / "tools/knowledge-registry/knowledge_registry.py"),
            ),
            mock.patch.object(kr, "verify_loaded_registry_source"),
        ):
            imported = kr.import_live([str(exported)], capture_manifest=receipt)
        self.assertEqual("candidate", imported["generation_state"])

        bad_hash = copy.deepcopy(capture_generator)
        bad_hash["sources"][0]["sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(kr.RegistryInputError, "source differs"):
            kr.verify_recorded_capture_generator_binding(bad_hash, repository=root)
        bad_ruleset = copy.deepcopy(capture_generator)
        bad_ruleset["ruleset_hash"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(kr.RegistryInputError, "ruleset differs"):
            kr.verify_recorded_capture_generator_binding(bad_ruleset, repository=root)

        capture_source = root / "tools/knowledge-registry/capture_live.py"
        capture_source.write_text("# changed generator\n", encoding="utf-8")
        run_git(root, "add", capture_source.relative_to(root).as_posix())
        run_git(root, "commit", "-q", "-m", "test: change generator")
        changed_commit = run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
        bad_commit = copy.deepcopy(capture_generator)
        bad_commit["git_commit"] = changed_commit
        with self.assertRaisesRegex(kr.RegistryInputError, "source differs"):
            kr.verify_recorded_capture_generator_binding(bad_commit, repository=root)

    def test_loaded_registry_and_capture_projector_bind_exact_code(self) -> None:
        registry_path = Path(kr.__file__)
        registry_raw = registry_path.read_bytes()
        kr.verify_loaded_registry_source(registry_raw, registry_path.as_posix())
        tampered = registry_raw.replace(b"return result\n", b"return dict(result)\n", 1)
        self.assertNotEqual(registry_raw, tampered)
        with self.assertRaisesRegex(kr.RegistryInputError, "does not match"):
            kr.verify_loaded_registry_source(tampered, registry_path.as_posix())

        capture_path = REPO_ROOT / "tools/knowledge-registry/capture_live.py"
        capture_raw = capture_path.read_bytes()
        capture_source = {
            "path": "tools/knowledge-registry/capture_live.py",
            "sha256": kr.file_hash(capture_raw),
            "size": len(capture_raw),
        }
        binding = {"sources": [capture_source]}
        changed_binding = copy.deepcopy(binding)
        changed_binding["sources"][0]["sha256"] = "sha256:" + "0" * 64
        with (
            mock.patch.object(kr, "verify_recorded_capture_generator_binding"),
            mock.patch.object(
                kr,
                "registry_generator_source_binding",
                side_effect=[binding, changed_binding],
            ),
        ):
            with self.assertRaisesRegex(kr.RegistryInputError, "changed while loading"):
                kr.load_bound_capture_projector({})

        altered_capture = capture_raw.replace(
            b"MAX_KUBECONFIG_BYTES = 4 * 2**20",
            b"MAX_KUBECONFIG_BYTES = 5 * 2**20",
            1,
        )
        self.assertNotEqual(capture_raw, altered_capture)
        with (
            mock.patch.object(kr, "verify_recorded_capture_generator_binding"),
            mock.patch.object(
                kr, "registry_generator_source_binding", return_value=binding
            ),
            mock.patch.object(kr, "read_regular_file", return_value=altered_capture),
        ):
            with self.assertRaisesRegex(
                kr.RegistryInputError, "changed before loading"
            ):
                kr.load_bound_capture_projector({})

    def test_oci_platform_is_preserved_or_a_typed_identity_gap(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "images.yaml", "yaml", content_hash="sha256:" + "7" * 64
        )
        _, explicit_version, _ = builder.add_image(
            "ghcr.io/example/demo:v1@sha256:" + "a" * 64,
            source,
            "line:1",
            "image",
            platform="linux/amd64",
        )
        builder.add_image(
            "ghcr.io/example/demo:v2@sha256:" + "b" * 64,
            source,
            "line:2",
            "image",
        )
        builder.add_image(
            "ghcr.io/example/demo:v1@sha256:" + "a" * 64,
            source,
            "line:3",
            "image",
            platform="linux/arm64",
        )
        manifest = builder.manifest()
        explicit = next(
            item
            for item in manifest["versions"]
            if item["component_version_id"] == explicit_version
        )
        self.assertEqual("linux/amd64", explicit["platform"])
        gap_types = {item["gap_type"] for item in manifest["gaps"]}
        self.assertIn("oci-platform-unresolved", gap_types)
        self.assertIn("oci-platform-multi", gap_types)
        self.assertEqual("gapped", manifest["completeness"]["identity"]["state"])

        node = self.base / "node.json"
        node.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "NodeList",
                    "metadata": {},
                    "items": [
                        {
                            "apiVersion": "v1",
                            "kind": "Node",
                            "metadata": {"name": "node-a"},
                            "status": {
                                "nodeInfo": {
                                    "kubeletVersion": "v1.35.0",
                                    "operatingSystem": "linux",
                                    "architecture": "amd64",
                                }
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        pod = self.base / "pod.json"
        pod.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "PodList",
                    "metadata": {},
                    "items": [
                        {
                            "apiVersion": "v1",
                            "kind": "Pod",
                            "metadata": {
                                "namespace": "demo",
                                "name": "pod-a",
                                "uid": "u1",
                            },
                            "spec": {
                                "nodeName": "node-a",
                                "containers": [
                                    {
                                        "name": "main",
                                        "image": "ghcr.io/example/demo@sha256:"
                                        + "c" * 64,
                                    }
                                ],
                            },
                            "status": {"phase": "Running"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        live_manifest = kr.import_live([str(pod), str(node)])
        image_versions = [
            version
            for version in live_manifest["versions"]
            if next(
                component
                for component in live_manifest["components"]
                if component["component_id"] == version["component_id"]
            ).get("ecosystem")
            == "oci"
        ]
        self.assertTrue(image_versions)
        self.assertEqual(
            {"linux/amd64"}, {item.get("platform") for item in image_versions}
        )

    def test_containerd_registry_endpoints_are_not_oci_artifacts(self) -> None:
        root = self.repository({"etc/containerd/certs.d/docker.io/hosts.toml": """
server = "https://registry-1.docker.io"

[host."https://mirror.example.invalid/v2"]
  capabilities = ["pull", "resolve"]
  override_path = true
"""})
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        endpoints = [
            component
            for component in manifest["components"]
            if component.get("kind") == "registry-endpoint"
        ]
        self.assertEqual(2, len(endpoints))
        self.assertEqual({"oci-registry"}, {item["ecosystem"] for item in endpoints})
        endpoint_ids = {item["component_id"] for item in endpoints}
        endpoint_gaps = [
            gap
            for gap in manifest["gaps"]
            if gap.get("component_id") in endpoint_ids
            and gap["gap_type"]
            in {
                "oci-platform-invalid",
                "oci-platform-multi",
                "oci-platform-unresolved",
                "transitive-inventory-unavailable",
            }
        ]
        self.assertEqual([], endpoint_gaps)
        endpoint_versions = [
            version
            for version in manifest["versions"]
            if version["component_id"] in endpoint_ids
        ]
        self.assertEqual(2, len(endpoint_versions))
        self.assertTrue(
            all(
                version["resolution_state"] == "resolved"
                for version in endpoint_versions
            )
        )
        self.assertEqual([], kr.validate_manifest(manifest))

    def test_precommit_secret_named_hook_does_not_poison_dependency_locator(
        self,
    ) -> None:
        root = self.repository({".pre-commit-config.yaml": """repos:
  - repo: local
    hooks:
      - id: reports-server-secret-env
        language: python
        additional_dependencies: [PyYAML==6.0.3]
"""})
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        component = next(
            item
            for item in manifest["components"]
            if item.get("ecosystem") == "pypi" and item.get("name") == "pyyaml"
        )
        version = next(
            item
            for item in manifest["versions"]
            if item["component_id"] == component["component_id"]
        )
        occurrence = next(
            item
            for item in manifest["occurrences"]
            if item["component_id"] == component["component_id"]
        )
        self.assertEqual(
            [".pre-commit-config.yaml#line:6:additional-dependency"],
            version["evidence"],
        )
        self.assertEqual("line:6:additional-dependency", occurrence["evidence_locator"])
        self.assertEqual("reports-server-secret-env", occurrence["metadata"]["hook_id"])
        self.assertEqual([], kr.unsafe_candidate_locator_pointers(manifest))
        self.assertEqual([], kr.validate_manifest(manifest))

    def test_no_acquisition_release_or_mutation_surface_is_importable(self) -> None:
        for name in (
            "OfficialHTTPClient",
            "OfficialChannelResolver",
            "resolve_official_manifest",
            "prepare_generation_promotion",
            "apply_generation_transition",
            "generation_status",
        ):
            self.assertFalse(hasattr(kr, name), name)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                kr.parser().parse_args(["resolve-official"])

    def test_reporting_commands_reject_invalid_candidates(self) -> None:
        forged = self.base / "forged.json"
        forged.write_text(
            json.dumps(
                {
                    "manifest_id": "mft-" + "0" * 64,
                    "sources": [],
                    "components": [],
                    "versions": [],
                    "occurrences": [],
                    "dependency_edges": [],
                    "gaps": [],
                }
            ),
            encoding="utf-8",
        )
        for command in ("summarize", "coverage", "gaps"):
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = kr.main([command, str(forged)])
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertIn("report input is invalid", stderr.getvalue())

    def test_schema_files_are_strict_json(self) -> None:
        for relative in (
            "knowledge/registry/schemas/discovery-manifest.schema.json",
            "knowledge/registry/schemas/component-record.schema.json",
            "knowledge/registry/schemas/component-record-v1.1.schema.json",
            "knowledge/registry/schemas/channel-policy.schema.json",
        ):
            payload = kr.parse_json_bytes(
                (REPO_ROOT / relative).read_bytes(),
                label=relative,
            )
            self.assertIsInstance(payload, dict)


class ChannelClosureW0Test(unittest.TestCase):
    FIXTURE_POLICY = TOOL_ROOT / "tests" / "fixtures" / "channel-policies" / "pypi.json"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def minimal_builder(self) -> tuple[kr.Builder, str, str, str]:
        return RegistryTest.minimal_builder(self)

    @staticmethod
    def reviewed_record(**kwargs: Any) -> dict[str, object]:
        return RegistryTest.reviewed_record(**kwargs)

    def fixture_policy_payload(self) -> dict[str, Any]:
        return json.loads(self.FIXTURE_POLICY.read_text(encoding="utf-8"))

    def policy_dir(self, *payloads: dict[str, Any]) -> str:
        directory = self.base / f"policies-{len(list(self.base.iterdir()))}"
        directory.mkdir()
        for index, payload in enumerate(payloads):
            target = directory / f"policy-{index}.json"
            target.write_text(
                json.dumps(payload, sort_keys=True, indent=1) + "\n",
                encoding="utf-8",
            )
        return directory.as_posix()

    def pypi_baseline(self) -> tuple[dict[str, Any], str, str, str]:
        builder = kr.Builder()
        source = builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "1" * 64,
            metadata={"evidence_class": "test"},
        )
        demo = builder.add_component(
            kind="library", ecosystem="pypi", name="demo", purl="pkg:pypi/demo"
        )
        version = builder.add_version(
            demo, resolved_version="1.2.3", evidence=("fixture.json",)
        )
        builder.add_occurrence(
            demo, version, source, locator="/demo", role="test", raw_value="demo"
        )
        mismatched = builder.add_component(
            kind="library", ecosystem="pypi", name="Bad", purl="pkg:pypi/Bad"
        )
        bad_version = builder.add_version(
            mismatched, resolved_version="2.0.0", evidence=("fixture.json",)
        )
        builder.add_occurrence(
            mismatched, bad_version, source, locator="/bad", role="test", raw_value="b"
        )
        noise = builder.add_component(
            kind="application",
            ecosystem="application",
            name="usr/local/bin/kustomize",
            identity="sbom:application::usr/local/bin/kustomize",
        )
        noise_version = builder.add_version(
            noise, resolved_version="0", evidence=("fixture.json",)
        )
        builder.add_occurrence(
            noise, noise_version, source, locator="/noise", role="test", raw_value="n"
        )
        return builder.manifest(), demo, mismatched, noise

    def test_sbom_path_artifact_classifier(self) -> None:
        self.assertTrue(
            kr.sbom_path_artifact_component(
                {"kind": "application", "ecosystem": "application"}
            )
        )
        self.assertTrue(
            kr.sbom_path_artifact_component({"kind": "library", "ecosystem": "library"})
        )
        self.assertFalse(
            kr.sbom_path_artifact_component(
                {"kind": "library", "ecosystem": "library", "purl": "pkg:pypi/x"}
            )
        )
        self.assertFalse(
            kr.sbom_path_artifact_component({"kind": "library", "ecosystem": "pypi"})
        )
        self.assertFalse(
            kr.sbom_path_artifact_component({"kind": "chart", "ecosystem": "chart"})
        )

    def test_cyclonedx_emission_reclassifies_path_artifacts(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "live-export:sboms", "test", content_hash="sha256:" + "9" * 64
        )
        item = {
            "kind": "SbomReport",
            "metadata": {"name": "demo", "namespace": "ns"},
            "report": {
                "artifact": {
                    "repository": "docker.io/library/demo",
                    "tag": "1.0",
                    "digest": "sha256:" + "a" * 64,
                },
                "components": {
                    "components": [
                        {"type": "application", "name": "usr/local/bin/kustomize"},
                        {"type": "library", "name": "../client/v3"},
                        {
                            "type": "library",
                            "name": "requests",
                            "version": "2.32.4",
                            "purl": "pkg:pypi/requests@2.32.4",
                        },
                    ]
                },
            },
        }
        kr.import_sbom_item(builder, source, item, 0)
        manifest = builder.manifest()
        by_name = {component["name"]: component for component in manifest["components"]}
        self.assertFalse(
            by_name["usr/local/bin/kustomize"]["official_channel_required"]
        )
        self.assertFalse(by_name["../client/v3"]["official_channel_required"])
        self.assertTrue(by_name["requests"]["official_channel_required"])
        gap_components = {
            gap.get("component_id")
            for gap in manifest["gaps"]
            if gap["gap_type"] == "official-channel-unresolved"
        }
        self.assertNotIn(
            by_name["usr/local/bin/kustomize"]["component_id"], gap_components
        )
        self.assertIn(by_name["requests"]["component_id"], gap_components)

    def test_merge_recomputes_stale_official_channel_gap(self) -> None:
        open_builder, _, component, _ = self.minimal_builder()
        open_manifest = open_builder.manifest()
        stale_gap = kr.make_gap(
            "official-channel-unresolved",
            f"No reviewed official channel is registered for {component}",
            component_id=component,
        )
        self.assertIn(
            stale_gap["gap_id"],
            {gap["gap_id"] for gap in open_manifest["gaps"]},
        )

        closed_builder, _, closed_component, _ = self.minimal_builder()
        self.assertEqual(component, closed_component)
        closed_builder.components[closed_component]["official_channels"] = [
            {
                "channel_id": "chn:test:package",
                "channel_type": "package",
                "availability_state": "available",
                "canonical_uri": "https://pypi.org/project/demo/",
                "review_state": "accepted",
            }
        ]
        closed_manifest = closed_builder.manifest()
        merged = kr.merge_manifests([open_manifest, closed_manifest])
        merged_gap_ids = {gap["gap_id"] for gap in merged["gaps"]}
        self.assertNotIn(stale_gap["gap_id"], merged_gap_ids)
        self.assertEqual(
            merged,
            kr.merge_manifests([closed_manifest, open_manifest]),
        )

        still_open = kr.merge_manifests([open_manifest, open_manifest])
        self.assertIn(
            stale_gap["gap_id"], {gap["gap_id"] for gap in still_open["gaps"]}
        )

    def test_merge_keeps_import_time_gap_carriage(self) -> None:
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, _, _ = kr.derive_channel_records(baseline, policies)
        reviewed = kr.reviewed_records_manifest(
            [(f"{component_id}.json", record) for component_id, record in records]
        )
        state_rows = [
            gap
            for gap in reviewed["gaps"]
            if gap["gap_type"] == "official-channel-state"
        ]
        # One row for the one matched component, counting 15 of its 16 classes.
        self.assertEqual(1, len(state_rows))
        self.assertEqual(demo, state_rows[0]["component_id"])
        self.assertEqual(15, state_rows[0]["metadata"]["unresolved_channel_classes"])
        self.assertEqual(16, state_rows[0]["metadata"]["reviewed_channel_classes"])
        reviewed_state_gaps = {gap["gap_id"] for gap in state_rows}
        version_unobserved = {
            gap["gap_id"]
            for gap in reviewed["gaps"]
            if gap["gap_type"] == "version-unobserved"
        }
        self.assertEqual(1, len(version_unobserved))
        merged = kr.merge_manifests([baseline, reviewed])
        merged_gap_ids = {gap["gap_id"] for gap in merged["gaps"]}
        self.assertTrue(reviewed_state_gaps <= merged_gap_ids)
        self.assertFalse(version_unobserved & merged_gap_ids)
        self.assertNotIn(
            demo,
            {
                gap.get("component_id")
                for gap in merged["gaps"]
                if gap["gap_type"] == "official-channel-unresolved"
            },
        )

    @staticmethod
    def multi_state_record(**kwargs: Any) -> dict[str, Any]:
        """A reviewed record whose 16 classes span every supported channel state."""

        record = RegistryTest.reviewed_record(**kwargs)
        component_id = str(record["component"]["component_id"])
        states = ["available", "absent", "ambiguous", "unresolved", "unavailable"]
        channels: list[dict[str, Any]] = []
        for index, channel_type in enumerate(kr.OFFICIAL_CHANNEL_TYPES):
            state = states[index % len(states)]
            available = state == "available"
            channels.append(
                {
                    "channel_id": f"chn:test:{component_id}:{channel_type}",
                    "component_id": component_id,
                    "channel_type": channel_type,
                    "availability_state": state,
                    "canonical_uri": (
                        f"https://example.invalid/{channel_type}" if available else None
                    ),
                    "publisher": "example" if available else None,
                    "version_strategy": "catalog-only" if available else "unresolved",
                    "access": "public",
                    "rights": None,
                    "refresh_policy": "on-version-change",
                    "discovery_method": "inferred",
                    "confidence": "medium",
                    "review_state": "accepted",
                    "evidence": [f"probe:{channel_type}", "policy:test"],
                    "gap": (
                        None
                        if available
                        else {
                            "state": state,
                            "reason": f"{channel_type} is {state}",
                            "blocking": False,
                            "evidence": [f"probe:{channel_type}"],
                            "next_action": f"probe-{channel_type}",
                        }
                    ),
                }
            )
        record["channels"] = channels
        return record

    def test_official_channel_state_is_emitted_at_component_grain(self) -> None:
        manifest = kr.reviewed_records_manifest(
            [
                ("a.json", self.multi_state_record()),
                (
                    "b.json",
                    self.multi_state_record(
                        record_id="record-widget",
                        component_id="component-widget",
                        version_id="version-widget",
                        name="widget",
                        purl="pkg:pypi/widget",
                    ),
                ),
            ]
        )
        self.assertEqual([], kr.validate_manifest(manifest))
        rows = [
            gap
            for gap in manifest["gaps"]
            if gap["gap_type"] == "official-channel-state"
        ]
        # Two components, 12 unresolved classes each: two rows, not twenty-four.
        self.assertEqual(2, len(rows))
        self.assertEqual(
            {component["component_id"] for component in manifest["components"]},
            {gap["component_id"] for gap in rows},
        )
        for gap in rows:
            self.assertEqual(16, gap["metadata"]["reviewed_channel_classes"])
            self.assertEqual(12, gap["metadata"]["unresolved_channel_classes"])
            self.assertEqual(
                {"absent": 3, "ambiguous": 3, "unavailable": 3, "unresolved": 3},
                gap["metadata"]["unresolved_by_state"],
            )
            self.assertEqual(12, len(gap["metadata"]["unresolved_channel_types"]))
            self.assertIn(
                "12 of 16 reviewed official channel classes are unresolved",
                gap["message"],
            )

    def test_official_channel_state_slot_detail_stays_derivable(self) -> None:
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, _, _ = kr.derive_channel_records(baseline, policies)
        merged = kr.merge_manifests(
            [baseline, kr.reviewed_records_manifest([("demo.json", records[0][1])])]
        )
        component = next(
            item for item in merged["components"] if item["component_id"] == demo
        )
        row = next(
            gap
            for gap in merged["gaps"]
            if gap["gap_type"] == "official-channel-state"
            and gap["component_id"] == demo
        )
        # The retained channel records reproduce the retired per-slot rows exactly.
        derived = kr.unresolved_reviewed_channels(component["official_channels"])
        self.assertEqual(row["metadata"]["unresolved_channel_classes"], len(derived))
        # Merge also carries the 16 seeded needs-review rows; the reviewed slots
        # are the ones the record bound, and only those are in the denominator.
        self.assertEqual(32, len(component["official_channels"]))
        self.assertEqual(
            row["metadata"]["reviewed_channel_classes"],
            len(kr.reviewed_record_channels(component["official_channels"])),
        )
        self.assertEqual(
            sorted(row["metadata"]["unresolved_channel_types"]),
            sorted(channel["channel_type"] for channel in derived),
        )
        source_channels = {
            channel["channel_id"]: channel for channel in records[0][1]["channels"]
        }
        for channel in derived:
            original = source_channels[channel["channel_id"]]
            self.assertEqual(
                original["availability_state"], channel["availability_state"]
            )
            self.assertEqual(original["evidence"], channel["evidence"])
            self.assertEqual(original["gap"]["reason"], channel["gap"]["reason"])
            self.assertEqual(
                original["gap"]["next_action"], channel["gap"]["next_action"]
            )
        self.assertEqual(
            {channel["channel_id"] for channel in derived},
            {
                channel["channel_id"]
                for channel in records[0][1]["channels"]
                if channel["availability_state"] != "available"
            },
        )

    def test_official_channel_state_never_enters_a_blocking_axis(self) -> None:
        self.assertNotIn("official-channel-state", kr.IDENTITY_GAP_TYPES)
        self.assertNotIn("official-channel-state", kr.CLOSURE_GAP_TYPES)
        manifest = kr.reviewed_records_manifest([("a.json", self.multi_state_record())])
        axes = kr.completeness_for(manifest)
        state_ids = {
            gap["gap_id"]
            for gap in manifest["gaps"]
            if gap["gap_type"] == "official-channel-state"
        }
        self.assertTrue(state_ids)
        self.assertFalse(state_ids & set(axes["identity"]["blocking_gap_ids"]))
        self.assertFalse(state_ids & set(axes["closure"]["blocking_gap_ids"]))

    def test_wave_gate_arithmetic_is_unmoved_by_the_collapsed_grain(self) -> None:
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, _, _ = kr.derive_channel_records(baseline, policies)
        merged = kr.merge_manifests(
            [baseline, kr.reviewed_records_manifest([("demo.json", records[0][1])])]
        )
        report = kr.channel_wave_gate(
            baseline, merged, policies=policies, expected_matched=1
        )
        self.assertTrue(report["pass"], report)
        arithmetic = report["checks"]["gap-arithmetic"]
        self.assertTrue(arithmetic["pass"], arithmetic)
        # The wave gate reconciles official-channel-unresolved, one row per
        # component either way, so the collapsed class cannot perturb it.
        self.assertEqual(
            arithmetic["baseline_official_channel_unresolved"]
            - arithmetic["merged_official_channel_unresolved"],
            arithmetic["components_gained_available_channel"]
            + arithmetic["reclassified_components"],
        )
        legacy = ChannelClosureW0Test.per_slot_manifest(merged)
        legacy_report = kr.channel_wave_gate(
            baseline, legacy, policies=policies, expected_matched=1
        )
        self.assertEqual(legacy_report["checks"]["gap-arithmetic"], arithmetic)
        self.assertEqual(
            kr.completeness_for(legacy)["channel_review"],
            kr.completeness_for(merged)["channel_review"],
        )

    @staticmethod
    def per_slot_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
        """Re-expand collapsed rows into the retired one-row-per-slot grain."""

        legacy = json.loads(json.dumps(manifest))
        components = {item["component_id"]: item for item in legacy["components"]}
        rows: list[dict[str, Any]] = []
        for gap in legacy["gaps"]:
            if gap["gap_type"] != "official-channel-state":
                rows.append(gap)
                continue
            component = components[gap["component_id"]]
            for channel in kr.unresolved_reviewed_channels(
                component["official_channels"]
            ):
                channel_type = str(channel.get("channel_type") or "unknown")
                state = str(channel.get("availability_state") or "unresolved")
                nested = channel.get("gap")
                nested = nested if isinstance(nested, dict) else {}
                row = kr.make_gap(
                    "official-channel-state",
                    f"Reviewed {channel_type} channel is {state} for "
                    f"{gap['component_id']}",
                    component_id=gap["component_id"],
                    source_id=gap.get("source_id"),
                    evidence=tuple(str(item) for item in channel.get("evidence", [])),
                )
                row["metadata"] = {
                    "channel_id": channel.get("channel_id"),
                    "channel_type": channel_type,
                    "state": state,
                    "reason": nested.get("reason"),
                    "next_action": nested.get("next_action"),
                }
                rows.append(row)
        legacy["gaps"] = sorted(rows, key=lambda item: item["gap_id"])
        return kr.seal_manifest(legacy)

    def test_reviewed_registry_passthrough_round_trip(self) -> None:
        _, _, harvested, _ = self.minimal_builder()
        record = self.reviewed_record()
        record["component"]["registry_kind"] = "library"
        record["component"]["registry_identity"] = "pkg:pypi/demo"
        manifest = kr.reviewed_records_manifest([("demo.json", record)])
        self.assertIn(
            harvested,
            {component["component_id"] for component in manifest["components"]},
        )
        imported = next(
            component
            for component in manifest["components"]
            if component["component_id"] == harvested
        )
        self.assertEqual("library", imported["metadata"]["registry_kind"])
        self.assertEqual("pkg:pypi/demo", imported["metadata"]["registry_identity"])

        legacy = kr.reviewed_records_manifest([("demo.json", self.reviewed_record())])
        legacy_ids = {component["component_id"] for component in legacy["components"]}
        self.assertNotIn(harvested, legacy_ids)
        self.assertIn(kr.stable_id("cmp", "pypi-library", "pkg:pypi/demo"), legacy_ids)

    def test_reviewed_registry_passthrough_requires_pair(self) -> None:
        record = self.reviewed_record()
        record["component"]["registry_kind"] = "library"
        with self.assertRaisesRegex(kr.RegistryInputError, "provided together"):
            kr.reviewed_records_manifest([("demo.json", record)])

    def test_derive_channels_end_to_end_with_wave_gate(self) -> None:
        baseline, demo, mismatched, noise = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, samples, summary = kr.derive_channel_records(baseline, policies)
        self.assertEqual([demo], [component_id for component_id, _ in records])
        self.assertEqual(
            {"not-required": 1, "precondition-mismatch": 1}, summary["skipped"]
        )
        self.assertEqual(16, summary["expected_accepted_slots_delta"])
        record = records[0][1]
        self.assertEqual("accepted", record["review"]["status"])
        self.assertTrue(record["review"]["reviewed_by"].startswith("channel-policy:"))
        channels = {channel["channel_type"]: channel for channel in record["channels"]}
        self.assertEqual(set(kr.OFFICIAL_CHANNEL_TYPES), set(channels))
        self.assertEqual("available", channels["package"]["availability_state"])
        self.assertEqual(
            "https://pypi.org/project/demo/", channels["package"]["canonical_uri"]
        )
        self.assertEqual("unresolved", channels["api"]["availability_state"])
        self.assertEqual("probe-wave", channels["api"]["gap"]["next_action"])
        self.assertIn(
            "derived-uri:https://pypi.org/pypi/demo/json",
            channels["api"]["gap"]["evidence"],
        )
        self.assertEqual("absent", channels["sbom"]["availability_state"])
        self.assertEqual("absent", channels["sbom"]["gap"]["state"])
        self.assertEqual(
            [demo], [entry["component_id"] for entry in samples[0][1]["entries"]]
        )

        merged = kr.merge_manifests(
            [baseline, kr.reviewed_records_manifest([("demo.json", record)])]
        )
        unresolved = {
            gap.get("component_id")
            for gap in merged["gaps"]
            if gap["gap_type"] == "official-channel-unresolved"
        }
        self.assertNotIn(demo, unresolved)
        self.assertIn(mismatched, unresolved)
        self.assertNotIn(noise, unresolved)

        report = kr.channel_wave_gate(
            baseline, merged, policies=policies, expected_matched=1
        )
        self.assertTrue(report["pass"], report)
        self.assertEqual(16, report["checks"]["accepted-slots"]["delta"])

    def test_derive_channels_is_deterministic(self) -> None:
        baseline, _, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        first = kr.derive_channel_records(baseline, policies)
        second = kr.derive_channel_records(baseline, policies)
        self.assertEqual(kr.canonical_json(first), kr.canonical_json(second))

    def test_derive_channels_refuses_unratified_policy(self) -> None:
        payload = self.fixture_policy_payload()
        payload["review"]["status"] = "proposed"
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(payload))

    def test_derive_channels_policy_validation_fails_closed(self) -> None:
        incomplete = self.fixture_policy_payload()
        incomplete["channels"] = incomplete["channels"][:-1]
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(incomplete))

        double_available = self.fixture_policy_payload()
        double_available["channels"][1] = {
            "channel_type": "api",
            "disposition": "available",
            "uri_template": "https://pypi.org/pypi/{name}/json",
            "publisher": "Python Package Index",
        }
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(double_available))

        no_sample_slot = self.fixture_policy_payload()
        no_sample_slot["review"]["evidence"] = ["https://docs.pypi.org/api/"]
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(no_sample_slot))

        duplicate_ecosystem = self.fixture_policy_payload()
        duplicate_ecosystem["record_id"] = "policy:channel:pypi:v0-test-duplicate"
        with self.assertRaisesRegex(kr.RegistryInputError, "one policy per ecosystem"):
            kr.load_channel_policies(
                self.policy_dir(self.fixture_policy_payload(), duplicate_ecosystem)
            )

    def test_derive_channels_authenticated_derived_unverified(self) -> None:
        payload = self.fixture_policy_payload()
        payload["channels"][1]["access"] = "authenticated"
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(self.policy_dir(payload))
        records, _, _ = kr.derive_channel_records(baseline, policies)
        channels = {
            channel["channel_type"]: channel for channel in records[0][1]["channels"]
        }
        self.assertEqual("authenticated", channels["api"]["access"])
        self.assertEqual("unresolved", channels["api"]["availability_state"])
        self.assertEqual("accepted", channels["api"]["review_state"])

    def test_derive_channels_unrenderable_template_stays_unresolved(self) -> None:
        payload = self.fixture_policy_payload()
        payload["channels"][0]["uri_template"] = "https://pypi.org/project/{missing}/"
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(self.policy_dir(payload))
        records, _, _ = kr.derive_channel_records(baseline, policies)
        channels = {
            channel["channel_type"]: channel for channel in records[0][1]["channels"]
        }
        self.assertEqual("unresolved", channels["package"]["availability_state"])
        self.assertTrue(
            channels["package"]["gap"]["reason"].startswith("uri-template-unrenderable")
        )
        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest([("demo.json", records[0][1])]),
            ]
        )
        unresolved = {
            gap.get("component_id")
            for gap in merged["gaps"]
            if gap["gap_type"] == "official-channel-unresolved"
        }
        self.assertIn(demo, unresolved)
        report = kr.channel_wave_gate(baseline, merged, policies=policies)
        self.assertTrue(report["pass"], report)

    def test_channel_policy_sample_is_policy_hash_seeded(self) -> None:
        component_ids = [f"cmp-{index:024d}" for index in range(30)]
        first = kr.channel_policy_sample_ids("sha256:" + "a" * 64, component_ids)
        second = kr.channel_policy_sample_ids("sha256:" + "a" * 64, component_ids)
        self.assertEqual(first, second)
        self.assertEqual(20, len(first))
        self.assertTrue(set(first) <= set(component_ids))
        expected = sorted(
            component_ids,
            key=lambda component_id: (
                hashlib.sha256(
                    f"sha256:{'a' * 64}:{component_id}".encode("utf-8")
                ).hexdigest(),
                component_id,
            ),
        )[:20]
        self.assertEqual(expected, first)

    def test_wave_gate_detects_minted_component(self) -> None:
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, _, _ = kr.derive_channel_records(baseline, policies)
        minted = copy.deepcopy(records[0][1])
        minted["component"]["registry_identity"] = "pkg:pypi/notdemo"
        merged = kr.merge_manifests(
            [baseline, kr.reviewed_records_manifest([("demo.json", minted)])]
        )
        report = kr.channel_wave_gate(baseline, merged, policies=policies)
        self.assertFalse(report["pass"])
        self.assertFalse(report["checks"]["zero-new-components"]["pass"])
        self.assertFalse(report["checks"]["required-slots"]["pass"])

    def test_wave_gate_detects_policy_hash_drift(self) -> None:
        baseline, _, _, _ = self.pypi_baseline()
        directory = self.policy_dir(self.fixture_policy_payload())
        policies = kr.load_channel_policies(directory)
        records, _, _ = kr.derive_channel_records(baseline, policies)
        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest([("demo.json", records[0][1])]),
            ]
        )
        drifted = self.fixture_policy_payload()
        drifted["channels"][5]["gap_reason"] = "drifted reason"
        (Path(directory) / "policy-0.json").write_text(
            json.dumps(drifted, sort_keys=True, indent=1) + "\n", encoding="utf-8"
        )
        report = kr.channel_wave_gate(
            baseline, merged, policies=kr.load_channel_policies(directory)
        )
        self.assertFalse(report["pass"])
        self.assertFalse(report["checks"]["policy-bindings"]["pass"])

    def test_wave_gate_accounts_for_reclassified_population(self) -> None:
        baseline, demo, mismatched, noise = self.pypi_baseline()
        old = copy.deepcopy(baseline)
        for component in old["components"]:
            if component["component_id"] != noise:
                continue
            component["official_channel_required"] = True
            component["official_channels"] = sorted(
                (
                    {
                        "channel_id": kr.stable_id(
                            "chn", noise, channel_type, "unresolved"
                        ),
                        "channel_type": channel_type,
                        "availability_state": "unresolved",
                        "review_state": "needs-review",
                        "authority_state": "non-authoritative",
                    }
                    for channel_type in kr.OFFICIAL_CHANNEL_TYPES
                ),
                key=lambda item: (item["channel_type"], item["channel_id"]),
            )
        stale_gap = kr.make_gap(
            "official-channel-unresolved",
            f"No reviewed official channel is registered for {noise}",
            component_id=noise,
        )
        old["gaps"] = kr.sorted_records([*old["gaps"], stale_gap], "gap_id")
        old = kr.seal_manifest(old)
        self.assertEqual([], kr.validate_manifest(old))
        self.assertEqual(
            3 * 16, old["completeness"]["channel_review"]["required_slots"]
        )

        merged = kr.merge_manifests([old])
        merged_noise = next(
            component
            for component in merged["components"]
            if component["component_id"] == noise
        )
        self.assertFalse(merged_noise["official_channel_required"])
        self.assertEqual(
            2 * 16, merged["completeness"]["channel_review"]["required_slots"]
        )
        self.assertNotIn(stale_gap["gap_id"], {gap["gap_id"] for gap in merged["gaps"]})

        report = kr.channel_wave_gate(old, merged, policies=[])
        self.assertTrue(report["pass"], report)
        self.assertEqual(
            [noise],
            report["checks"]["required-slots"]["reclassified_component_ids"],
        )

    NPM_URI_TEMPLATES = {
        "package": "https://www.npmjs.com/package/{name}",
        "api": "https://registry.npmjs.org/{name}",
        "docs": "https://www.npmjs.com/package/{name}",
        "advisory": "https://osv.dev/list?ecosystem=npm&q={name}",
        "release": "https://www.npmjs.com/package/{name}?activeTab=versions",
    }

    def npm_policy_payload(self) -> dict[str, Any]:
        """A second ratified ecosystem policy, so waves can land one at a time."""

        payload = self.fixture_policy_payload()
        payload["record_id"] = "policy:channel:npm:v0-test"
        payload["scope"] = {
            "ecosystem": "npm",
            "preconditions": [
                {
                    "field": "purl",
                    "pattern": "^pkg:npm/[a-z0-9]([a-z0-9._-]*[a-z0-9])?$",
                }
            ],
        }
        for channel in payload["channels"]:
            template = self.NPM_URI_TEMPLATES.get(str(channel["channel_type"]))
            if template is not None:
                channel["uri_template"] = template
                channel["publisher"] = "npm registry"
        return payload

    def two_ecosystem_baseline(self) -> tuple[dict[str, Any], str, str]:
        builder = kr.Builder()
        source = builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "1" * 64,
            metadata={"evidence_class": "test"},
        )
        component_ids: list[str] = []
        for label, ecosystem, purl in (
            ("demo", "pypi", "pkg:pypi/demo"),
            ("widget", "npm", "pkg:npm/widget"),
        ):
            component_id = builder.add_component(
                kind="library", ecosystem=ecosystem, name=label, purl=purl
            )
            version = builder.add_version(
                component_id, resolved_version="1.2.3", evidence=("fixture.json",)
            )
            builder.add_occurrence(
                component_id,
                version,
                source,
                locator=f"/{label}",
                role="test",
                raw_value=label,
            )
            component_ids.append(component_id)
        demo, widget = component_ids
        return builder.manifest(), demo, widget

    def landed_first_wave(
        self,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], str, str]:
        """Baseline state after one channel wave already stamped a population."""

        baseline, demo, widget = self.two_ecosystem_baseline()
        both = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload(), self.npm_policy_payload())
        )
        pypi_only = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, _, _ = kr.derive_channel_records(baseline, pypi_only)
        self.assertEqual([demo], [component_id for component_id, _ in records])
        merged = kr.merge_manifests(
            [baseline, kr.reviewed_records_manifest([("demo.json", records[0][1])])]
        )
        report = kr.channel_wave_gate(
            baseline, merged, policies=pypi_only, expected_matched=1
        )
        self.assertTrue(report["pass"], report)
        return merged, both, demo, widget

    def second_wave_record(
        self, merged: Mapping[str, Any], policies: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        records, _, summary = kr.derive_channel_records(merged, policies)
        self.assertEqual({"already-closed": 1}, summary["skipped"])
        self.assertEqual(1, len(records))
        return copy.deepcopy(records[0][1])

    def failed_checks(self, report: Mapping[str, Any]) -> list[str]:
        return sorted(
            name for name, check in report["checks"].items() if not check["pass"]
        )

    def test_wave_gate_null_change_on_stamped_baseline_passes(self) -> None:
        merged, policies, _, _ = self.landed_first_wave()
        report = kr.channel_wave_gate(
            merged, merged, policies=policies, expected_matched=0
        )
        accepted = report["checks"]["accepted-slots"]
        self.assertEqual(1, accepted["baseline_policy_stamped_components"])
        self.assertEqual(0, accepted["wave_policy_stamped_components"])
        self.assertEqual(0, accepted["delta"])
        self.assertEqual(0, accepted["expected_delta"])
        self.assertTrue(report["pass"], report)

    def test_wave_gate_incremental_wave_on_stamped_baseline_passes(self) -> None:
        merged, policies, _, widget = self.landed_first_wave()
        record = self.second_wave_record(merged, policies)
        self.assertEqual(widget, record["component"]["component_id"])
        second = kr.merge_manifests(
            [merged, kr.reviewed_records_manifest([("widget.json", record)])]
        )
        report = kr.channel_wave_gate(
            merged, second, policies=policies, expected_matched=1
        )
        accepted = report["checks"]["accepted-slots"]
        self.assertEqual(2, accepted["policy_stamped_components"])
        self.assertEqual(1, accepted["baseline_policy_stamped_components"])
        self.assertEqual(1, accepted["wave_policy_stamped_components"])
        self.assertEqual(16, accepted["delta"])
        self.assertEqual(16, accepted["expected_delta"])
        self.assertTrue(report["pass"], report)

    def test_wave_gate_detects_stamp_without_emitted_slots(self) -> None:
        merged, policies, _, _ = self.landed_first_wave()
        record = self.second_wave_record(merged, policies)
        record["channels"] = [
            channel
            for channel in record["channels"]
            if channel["channel_type"] not in {"release", "changelog"}
        ]
        second = kr.merge_manifests(
            [merged, kr.reviewed_records_manifest([("widget.json", record)])]
        )
        report = kr.channel_wave_gate(
            merged, second, policies=policies, expected_matched=1
        )
        accepted = report["checks"]["accepted-slots"]
        self.assertEqual(1, accepted["wave_policy_stamped_components"])
        self.assertEqual(14, accepted["delta"])
        self.assertEqual(16, accepted["expected_delta"])
        self.assertFalse(report["pass"], report)
        self.assertEqual(["accepted-slots"], self.failed_checks(report))

    def test_wave_gate_detects_stamp_with_unreviewed_slots(self) -> None:
        merged, policies, _, _ = self.landed_first_wave()
        record = self.second_wave_record(merged, policies)
        for channel in record["channels"]:
            if channel["channel_type"] in {"release", "changelog"}:
                channel["review_state"] = "needs-review"
        second = kr.merge_manifests(
            [merged, kr.reviewed_records_manifest([("widget.json", record)])]
        )
        report = kr.channel_wave_gate(
            merged, second, policies=policies, expected_matched=1
        )
        accepted = report["checks"]["accepted-slots"]
        self.assertEqual(14, accepted["delta"])
        self.assertEqual(16, accepted["expected_delta"])
        self.assertFalse(report["pass"], report)
        self.assertEqual(["accepted-slots"], self.failed_checks(report))

    def test_wave_gate_credits_reclassified_stamped_population(self) -> None:
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        policy = policies[0]
        baseline, _, _, noise = self.pypi_baseline()
        for component in baseline["components"]:
            if component["component_id"] != noise:
                continue
            component["official_channel_required"] = True
            component["official_channels"] = sorted(
                (
                    {
                        "channel_id": kr.stable_id(
                            "chn", noise, channel_type, "absent"
                        ),
                        "channel_type": channel_type,
                        "availability_state": "absent",
                        "review_state": "accepted",
                        "authority_state": "non-authoritative",
                    }
                    for channel_type in kr.OFFICIAL_CHANNEL_TYPES
                ),
                key=lambda item: (item["channel_type"], item["channel_id"]),
            )
            metadata = dict(component.get("metadata") or {})
            metadata["review"] = {
                "status": "accepted",
                "reviewed_by": (
                    f"{kr.CHANNEL_POLICY_REVIEWER_PREFIX}"
                    f"{policy['record']['record_id']}@{policy['sha256']}"
                ),
                "reviewed_at": "2026-08-22",
                "evidence": ["baseline:test"],
            }
            component["metadata"] = metadata
        stale_gap = kr.make_gap(
            "official-channel-unresolved",
            f"No reviewed official channel is registered for {noise}",
            component_id=noise,
        )
        baseline["gaps"] = kr.sorted_records([*baseline["gaps"], stale_gap], "gap_id")
        baseline = kr.seal_manifest(baseline)
        self.assertEqual([], kr.validate_manifest(baseline))

        merged = kr.merge_manifests([baseline])
        report = kr.channel_wave_gate(
            baseline, merged, policies=policies, expected_matched=0
        )
        accepted = report["checks"]["accepted-slots"]
        self.assertEqual(1, accepted["baseline_policy_stamped_components"])
        self.assertEqual(0, accepted["wave_policy_stamped_components"])
        self.assertEqual(16, accepted["reclassified_accepted_slots"])
        self.assertEqual(-16, accepted["delta"])
        self.assertEqual(-16, accepted["expected_delta"])
        self.assertTrue(report["pass"], report)

    def test_derive_channels_command_writes_deterministic_artifacts(self) -> None:
        baseline, demo, _, _ = self.pypi_baseline()
        baseline_path = self.base / "baseline.json"
        baseline_path.write_text(json.dumps(baseline, sort_keys=True), encoding="utf-8")
        directory = self.policy_dir(self.fixture_policy_payload())
        first_out = self.base / "out-1"
        second_out = self.base / "out-2"
        for target in (first_out, second_out):
            summary = kr.derive_channels_command(
                baseline_path.as_posix(), directory, target.as_posix()
            )
            self.assertEqual(1, summary["records_emitted"])
        first_record = (first_out / "records" / f"{demo}.json").read_bytes()
        second_record = (second_out / "records" / f"{demo}.json").read_bytes()
        self.assertEqual(first_record, second_record)
        self.assertEqual(
            (first_out / "sample-pypi.json").read_bytes(),
            (second_out / "sample-pypi.json").read_bytes(),
        )
        self.assertEqual(
            (first_out / "derive-channels-summary.json").read_bytes(),
            (second_out / "derive-channels-summary.json").read_bytes(),
        )

    def research_policy_payload(self, *component_ids: str) -> dict[str, Any]:
        pin = "sha256:" + "0" * 64
        rows: dict[str, Any] = {}
        for component_id in component_ids:
            channels: list[dict[str, Any]] = []
            for channel_type in kr.OFFICIAL_CHANNEL_TYPES:
                if channel_type == "docs":
                    channels.append(
                        {
                            "channel_type": channel_type,
                            "disposition": "available",
                            "canonical_uri": "https://example.org/bad/docs",
                            "publisher": "Example Project",
                            "access": "public",
                            "rights": None,
                            "confidence": "high",
                            "reason": None,
                            "probe": {
                                "status": 200,
                                "final_url": "https://example.org/bad/docs",
                            },
                            "provenance": {
                                "pass": "1",
                                "refs": ["engine", "gate", "corpus"],
                            },
                        }
                    )
                    continue
                agy_row = channel_type == "source"
                channels.append(
                    {
                        "channel_type": channel_type,
                        "disposition": "absent",
                        "canonical_uri": None,
                        "publisher": None,
                        "rights": None,
                        "reason": "research verdict: no official channel of this type",
                        "probe": None,
                        "provenance": {
                            "pass": "3" if agy_row else "1",
                            "refs": (
                                ["engine", "corpus", "agy"]
                                if agy_row
                                else ["engine", "corpus"]
                            ),
                        },
                    }
                )
            rows[component_id] = {
                "name": "bad",
                "ecosystem": "pypi",
                "channels": channels,
            }
        return {
            "$schema": (
                "https://github.com/cordanaLLM/knowledge/schemas/registry/"
                "channel-policy.schema.json"
            ),
            "schema_version": "1.1.0",
            "record_kind": "channel_policy",
            "record_id": "policy:channel:research:test:v1",
            "review": {
                "status": "accepted",
                "reviewed_by": "operator",
                "reviewed_at": "2026-08-23",
                "evidence": [
                    "sample-audit:test-fixture-slice",
                    "source-monorepo-review:acceptance-suite",
                ],
            },
            "scope": {
                "ecosystem": "research-test",
                "selector": "component-table",
                "preconditions": [{"field": "component_id", "pattern": "^cmp-"}],
            },
            "tables": {
                "provenance": {
                    "engine": "engine:ollama:test-model:UD-Q4_K_M",
                    "gate": f"gate:build-test/w4_scale.py@{pin}",
                    "corpus": f"research-corpus:build-test/corpus-state.json@{pin}#w4",
                    "agy": f"agy:build-test/agy-outcomes.json@{pin}#outcomes",
                }
            },
            "rows": rows,
        }

    def test_component_table_policy_end_to_end(self) -> None:
        baseline, demo, mismatched, _ = self.pypi_baseline()
        directory = self.policy_dir(
            self.fixture_policy_payload(), self.research_policy_payload(mismatched)
        )
        policies = kr.load_channel_policies(directory)
        records, samples, summary = kr.derive_channel_records(baseline, policies)
        self.assertEqual(
            {demo, mismatched}, {component_id for component_id, _ in records}
        )
        research = next(
            record for component_id, record in records if component_id == mismatched
        )
        self.assertTrue(
            research["review"]["reviewed_by"].startswith(
                "channel-policy:policy:channel:research:test:v1@sha256:"
            )
        )
        channels = {
            channel["channel_type"]: channel for channel in research["channels"]
        }
        self.assertEqual(set(kr.OFFICIAL_CHANNEL_TYPES), set(channels))
        docs = channels["docs"]
        self.assertEqual("available", docs["availability_state"])
        self.assertEqual("https://example.org/bad/docs", docs["canonical_uri"])
        self.assertEqual("catalog-only", docs["version_strategy"])
        self.assertIn("probe:200:https://example.org/bad/docs", docs["evidence"])
        self.assertIn("engine:ollama:test-model:UD-Q4_K_M", docs["evidence"])
        self.assertIn("research-pass:1", docs["evidence"])
        self.assertTrue(
            any(item.startswith("gate:build-test/") for item in docs["evidence"])
        )
        source = channels["source"]
        self.assertEqual("absent", source["availability_state"])
        self.assertEqual("absent", source["gap"]["state"])
        self.assertIn("research-pass:3", source["evidence"])
        self.assertTrue(
            any(item.startswith("agy:build-test/") for item in source["evidence"])
        )
        research_sample = next(
            sample for name, sample in samples if name == "sample-research-test.json"
        )
        self.assertEqual(
            [mismatched],
            [entry["component_id"] for entry in research_sample["entries"]],
        )
        by_policy = {
            entry["record_id"]: entry["matched"] for entry in summary["policies"]
        }
        self.assertEqual(1, by_policy["policy:channel:research:test:v1"])
        self.assertEqual(1, by_policy["policy:channel:pypi:v0-test"])

        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest(
                    [
                        (f"{component_id}.json", record)
                        for component_id, record in records
                    ]
                ),
            ]
        )
        unresolved = {
            gap.get("component_id")
            for gap in merged["gaps"]
            if gap["gap_type"] == "official-channel-unresolved"
        }
        self.assertNotIn(mismatched, unresolved)
        report = kr.channel_wave_gate(
            baseline, merged, policies=policies, expected_matched=2
        )
        self.assertTrue(report["pass"], report)
        self.assertEqual(32, report["checks"]["accepted-slots"]["delta"])

    def test_component_table_policy_fails_closed(self) -> None:
        _, _, mismatched, _ = self.pypi_baseline()

        unprobed = self.research_policy_payload(mismatched)
        docs_row = unprobed["rows"][mismatched]["channels"][0]
        docs_row["probe"] = None
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(unprobed))

        failed_probe = self.research_policy_payload(mismatched)
        failed_probe["rows"][mismatched]["channels"][0]["probe"] = {
            "status": 404,
            "final_url": "https://example.org/bad/docs",
        }
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(failed_probe))

        unreasoned = self.research_policy_payload(mismatched)
        unreasoned["rows"][mismatched]["channels"][1]["reason"] = None
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(unreasoned))

        unknown_ref = self.research_policy_payload(mismatched)
        unknown_ref["rows"][mismatched]["channels"][0]["provenance"]["refs"] = [
            "missing-ref"
        ]
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(unknown_ref))

        short_form = self.research_policy_payload(mismatched)
        short_form["rows"][mismatched]["channels"] = short_form["rows"][mismatched][
            "channels"
        ][:15]
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(short_form))

        mixed = self.research_policy_payload(mismatched)
        mixed["channels"] = self.fixture_policy_payload()["channels"]
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(mixed))

        rows_without_selector = self.fixture_policy_payload()
        rows_without_selector["rows"] = self.research_policy_payload(mismatched)["rows"]
        with self.assertRaisesRegex(kr.RegistryInputError, "not a ratified"):
            kr.load_channel_policies(self.policy_dir(rows_without_selector))

    def test_component_table_identity_unrecoverable_skips_typed(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "1" * 64,
            metadata={"evidence_class": "test"},
        )
        opaque = builder.add_component(
            kind="cli",
            ecosystem="generic",
            name="tool",
            identity="custom:opaque-identity",
        )
        version = builder.add_version(
            opaque, resolved_version="1.0.0", evidence=("fixture.json",)
        )
        builder.add_occurrence(
            opaque, version, source, locator="/tool", role="test", raw_value="tool"
        )
        baseline = builder.manifest()
        policies = kr.load_channel_policies(
            self.policy_dir(self.research_policy_payload(opaque))
        )
        records, _, summary = kr.derive_channel_records(baseline, policies)
        self.assertEqual([], records)
        self.assertEqual(1, summary["skipped"]["identity-unrecoverable"])

    def test_component_table_defers_to_ecosystem_policy(self) -> None:
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(
                self.fixture_policy_payload(), self.research_policy_payload(demo)
            )
        )
        records, _, summary = kr.derive_channel_records(baseline, policies)
        record = next(
            record for component_id, record in records if component_id == demo
        )
        self.assertTrue(
            record["review"]["reviewed_by"].startswith(
                "channel-policy:policy:channel:pypi:v0-test@sha256:"
            )
        )
        by_policy = {
            entry["record_id"]: entry["matched"] for entry in summary["policies"]
        }
        self.assertEqual(0, by_policy["policy:channel:research:test:v1"])


class ChannelClosureW2Test(unittest.TestCase):
    POLICY_DIR = REPO_ROOT / "knowledge" / "registry" / "channel-policies"
    LIVE_URI = "live-export:sha256:" + "a" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def repository(self, files: dict[str, str]) -> Path:
        return RegistryTest.repository(self, files)

    def kubernetes_policy(self) -> dict[str, Any]:
        policies = kr.load_channel_policies(self.POLICY_DIR.as_posix())
        return next(
            policy
            for policy in policies
            if policy["record"]["scope"]["ecosystem"] == "kubernetes"
        )

    def kubernetes_baseline(self) -> tuple[dict[str, Any], dict[str, str]]:
        builder = kr.Builder()
        source = builder.add_source(
            self.LIVE_URI,
            "test",
            content_hash="sha256:" + "a" * 64,
            metadata={"evidence_class": "test"},
        )
        api = builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace="longhorn.io",
            name="Volume",
            identity="gvk:longhorn.io/v1beta2:Volume",
            lifecycles=("deployed",),
            metadata={
                "api_group": "longhorn.io",
                "gvk": "longhorn.io/v1beta2/Volume",
            },
        )
        api_version = builder.add_version(
            api,
            resolved_version="v1beta2",
            evidence=(
                f"{self.LIVE_URI}#/components/schemas/io.longhorn.v1beta2.Volume",
            ),
        )
        builder.add_occurrence(
            api, api_version, source, locator="/a", role="test", raw_value="a"
        )
        crd = builder.add_component(
            kind="kubernetes-crd",
            ecosystem="kubernetes",
            namespace="longhorn.io",
            name="volumes.longhorn.io",
            identity="crd:volumes.longhorn.io",
            lifecycles=("deployed",),
            metadata={"group": "longhorn.io", "resource_kind": "Volume"},
        )
        crd_version = builder.add_version(
            crd,
            source_ref="c" * 40,
            resolution_state="resolved",
            evidence=(f"{self.LIVE_URI}#/items/1",),
        )
        builder.add_occurrence(
            crd, crd_version, source, locator="/b", role="test", raw_value="b"
        )
        repo_only = builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace="cilium.io",
            name="CiliumNetworkPolicy",
            identity="gvk:cilium.io/v2:CiliumNetworkPolicy",
            lifecycles=("deployed",),
            metadata={
                "api_group": "cilium.io",
                "gvk": "cilium.io/v2/CiliumNetworkPolicy",
            },
        )
        repo_version = builder.add_version(
            repo_only,
            resolved_version="v2",
            evidence=("apps/demo/policy.yaml#L1",),
        )
        builder.add_occurrence(
            repo_only, repo_version, source, locator="/c", role="test", raw_value="c"
        )
        unmapped = builder.add_component(
            kind="kubernetes-api",
            ecosystem="kubernetes",
            namespace="unmapped.example.io",
            name="Widget",
            identity="gvk:unmapped.example.io/v1:Widget",
            lifecycles=("deployed",),
            metadata={
                "api_group": "unmapped.example.io",
                "gvk": "unmapped.example.io/v1/Widget",
            },
        )
        unmapped_version = builder.add_version(
            unmapped,
            resolved_version="v1",
            evidence=(f"{self.LIVE_URI}#/components/schemas/io.example.Widget",),
        )
        builder.add_occurrence(
            unmapped,
            unmapped_version,
            source,
            locator="/d",
            role="test",
            raw_value="d",
        )
        manifest = builder.manifest()
        self.assertEqual([], kr.validate_manifest(manifest))
        return manifest, {
            "api": api,
            "crd": crd,
            "repo_only": repo_only,
            "unmapped": unmapped,
        }

    def test_kubernetes_policy_closes_gvk_and_crd_identities(self) -> None:
        baseline, ids = self.kubernetes_baseline()
        policy = self.kubernetes_policy()
        records, samples, summary = kr.derive_channel_records(baseline, [policy])
        by_component = dict(records)
        self.assertEqual(
            sorted([ids["api"], ids["crd"], ids["repo_only"]]),
            sorted(by_component),
        )
        self.assertEqual({"precondition-mismatch": 1}, summary["skipped"])

        api_record = by_component[ids["api"]]
        self.assertEqual("kubernetes-api", api_record["component"]["kind"])
        self.assertEqual("kubernetes-api", api_record["component"]["registry_kind"])
        self.assertEqual(
            "gvk:longhorn.io/v1beta2:Volume",
            api_record["component"]["registry_identity"],
        )
        channels = {
            channel["channel_type"]: channel for channel in api_record["channels"]
        }
        self.assertEqual("available", channels["schema"]["availability_state"])
        self.assertEqual(self.LIVE_URI, channels["schema"]["canonical_uri"])
        self.assertIn(
            f"{self.LIVE_URI}#/components/schemas/io.longhorn.v1beta2.Volume",
            channels["schema"]["evidence"],
        )
        self.assertEqual("unresolved", channels["docs"]["availability_state"])
        self.assertIn(
            "derived-uri:https://longhorn.io/docs/",
            channels["docs"]["gap"]["evidence"],
        )
        self.assertEqual("unresolved", channels["deprecation"]["availability_state"])
        self.assertFalse(
            any(
                item.startswith("derived-uri:")
                for item in channels["deprecation"]["gap"]["evidence"]
            )
        )
        self.assertEqual("absent", channels["package"]["availability_state"])

        crd_record = by_component[ids["crd"]]
        self.assertEqual("kubernetes-crd", crd_record["component"]["kind"])
        self.assertEqual(
            "crd:volumes.longhorn.io",
            crd_record["component"]["registry_identity"],
        )

        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest(
                    [(f"{cid}.json", record) for cid, record in records]
                ),
            ]
        )
        report = kr.channel_wave_gate(
            baseline, merged, policies=[policy], expected_matched=3
        )
        self.assertTrue(report["pass"], report)
        unresolved = {
            gap.get("component_id")
            for gap in merged["gaps"]
            if gap["gap_type"] == "official-channel-unresolved"
        }
        self.assertNotIn(ids["api"], unresolved)
        self.assertNotIn(ids["crd"], unresolved)
        self.assertIn(ids["unmapped"], unresolved)

    def test_kubernetes_schema_fails_closed_without_live_capture(self) -> None:
        baseline, ids = self.kubernetes_baseline()
        policy = self.kubernetes_policy()
        records, _, _ = kr.derive_channel_records(baseline, [policy])
        record = dict(records)[ids["repo_only"]]
        channels = {channel["channel_type"]: channel for channel in record["channels"]}
        self.assertEqual("unresolved", channels["schema"]["availability_state"])
        self.assertTrue(
            channels["schema"]["gap"]["reason"].startswith("uri-template-unrenderable")
        )
        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest(
                    [(f"{cid}.json", item) for cid, item in records]
                ),
            ]
        )
        unresolved = {
            gap.get("component_id")
            for gap in merged["gaps"]
            if gap["gap_type"] == "official-channel-unresolved"
        }
        self.assertIn(ids["repo_only"], unresolved)
        report = kr.channel_wave_gate(baseline, merged, policies=[policy])
        self.assertTrue(report["pass"], report)

    def kubernetes_context(self, namespace: str, name: str) -> dict[str, str]:
        policy = self.kubernetes_policy()
        component = {
            "name": name,
            "namespace": namespace,
            "ecosystem": "kubernetes",
            "purl": None,
        }
        return kr.channel_policy_context(policy["record"], component)

    def test_argoproj_release_advisory_resolve_per_owning_project(self) -> None:
        for name, project in (
            ("Rollout", "argo-rollouts"),
            ("applications.argoproj.io", "argo-cd"),
            ("Workflow", "argo-workflows"),
            ("workflowtemplates.argoproj.io", "argo-workflows"),
            ("AppProject", "argo-cd"),
        ):
            context = self.kubernetes_context("argoproj.io", name)
            self.assertEqual(
                f"https://github.com/argoproj/{project}/releases",
                context.get("group_release"),
                name,
            )
            self.assertEqual(
                f"https://github.com/argoproj/{project}/security/advisories",
                context.get("group_advisory"),
                name,
            )
        scale = self.kubernetes_context("argoproj.io", "Scale")
        self.assertNotIn("group_release", scale)
        self.assertNotIn("group_advisory", scale)

    def test_variable_fallback_first_hit_wins(self) -> None:
        context = self.kubernetes_context("longhorn.io", "Rollout")
        self.assertEqual(
            "https://github.com/longhorn/longhorn/releases",
            context.get("group_release"),
        )

    def test_grafana_release_advisory_point_at_alloy_source_stays_agent(
        self,
    ) -> None:
        context = self.kubernetes_context("monitoring.grafana.com", "PodLogs")
        self.assertEqual(
            "https://github.com/grafana/agent", context.get("group_source")
        )
        self.assertEqual(
            "https://github.com/grafana/alloy/releases",
            context.get("group_release"),
        )
        self.assertEqual(
            "https://github.com/grafana/alloy/security/advisories",
            context.get("group_advisory"),
        )

    def test_valkey_conservative_columns_fail_closed(self) -> None:
        context = self.kubernetes_context("valkey.io", "ValkeyCluster")
        self.assertEqual(
            "https://github.com/valkey-io/valkey-operator",
            context.get("group_source"),
        )
        self.assertEqual("https://valkey.io/", context.get("group_docs"))
        self.assertNotIn("group_reference", context)
        self.assertNotIn("group_release", context)
        self.assertNotIn("group_advisory", context)

    def test_variable_fallback_semantic_validation(self) -> None:
        policy = copy.deepcopy(self.kubernetes_policy()["record"])
        policy["variables"]["group_release"] = [
            {"table": "api_group_release", "key": "namespace"},
            {"table": "missing_table", "key": "argo_project"},
        ]
        policy["variables"]["group_advisory"] = []
        errors = kr.channel_policy_semantic_errors(policy)
        self.assertIn("variables.group_release references an unknown table", errors)
        self.assertIn("variables.group_advisory must define table and key", errors)

    def test_golang_vanity_single_segment_namespace(self) -> None:
        self.assertEqual(
            ("go.opencensus.io", "go.opencensus.io"),
            kr.golang_module_namespace_name("go.opencensus.io"),
        )
        self.assertEqual(
            ("github.com/gorilla", "mux"),
            kr.golang_module_namespace_name("github.com/gorilla/mux"),
        )
        self.assertEqual(("", "stdlib"), kr.golang_module_namespace_name("stdlib"))
        self.assertEqual(
            ("", "github.com%2Fcontainerd%2Fcontainerd"),
            kr.golang_module_namespace_name("github.com%2Fcontainerd%2Fcontainerd"),
        )

    def test_path_root_toolchain_and_self_repo_identities_recover(self) -> None:
        """Grammars found by reproduction against stable_id."""

        cases = [
            # go.mod module root hashes the WHOLE path the split came from.
            (
                "go-module",
                "golang",
                "github.com/example-org/k8s/apps/media",
                "romm-curator",
                {},
                "golang:github.com/example-org/k8s/apps/media/romm-curator",
            ),
            # packer plugins hash namespace/name under the bare ecosystem.
            (
                "packer-plugin",
                "packer",
                "github.com/hashicorp",
                "proxmox",
                {},
                "packer:github.com/hashicorp/proxmox",
            ),
            # toolchains and stdlibs key on the language alone.
            (
                "language-toolchain",
                "go-toolchain",
                "",
                "go",
                {"language": "go"},
                "toolchain:go",
            ),
            (
                "standard-library",
                "go-toolchain",
                "",
                "go-stdlib",
                {"language": "go"},
                "stdlib:go",
            ),
            # the self-repository root is a literal.
            ("source-repository", "git", "", "self", {}, "git:repository:self"),
        ]
        for kind, ecosystem, namespace, name, metadata, identity in cases:
            component = {
                "component_id": kr.stable_id("cmp", kind, identity.lower()),
                "kind": kind,
                "ecosystem": ecosystem,
                "namespace": namespace,
                "name": name,
                "metadata": metadata,
            }
            self.assertEqual(identity, kr.recover_component_identity(component), kind)

    def test_model_artifact_identity_is_recoverable_from_metadata(self) -> None:
        """Model artifacts hash the declared ref, not the display name."""

        declared = "OpenVINO/Qwen3-Embedding-0.6B-int8-ov"
        component = {
            # add_component hashes identity.lower(), so the fixture must too.
            "component_id": kr.stable_id(
                "cmp",
                "model-artifact",
                f"model-artifact:huggingface:{declared}".lower(),
            ),
            "kind": "model-artifact",
            "ecosystem": "huggingface",
            "name": "qwen3-embed",
            "metadata": {"artifact_identity": declared},
        }
        self.assertEqual(
            f"model-artifact:huggingface:{declared}",
            kr.recover_component_identity(component),
        )
        # Without the recorded reference the short name cannot rebuild the id.
        stripped = dict(component)
        stripped["metadata"] = {}
        self.assertIsNone(kr.recover_component_identity(stripped))

    def test_identity_candidates_mirror_action_and_precommit_grammars(self) -> None:
        """Both emitters were unrecoverable, so no policy could reach them."""

        action = {
            "component_id": kr.stable_id(
                "cmp", "github-action", "github-action:actions/checkout"
            ),
            "kind": "github-action",
            "ecosystem": "github-actions",
            "name": "actions/checkout",
            "metadata": {"source_repo": "https://github.com/actions/checkout"},
        }
        self.assertEqual(
            "github-action:actions/checkout",
            kr.recover_component_identity(action),
        )
        hook = {
            "component_id": kr.stable_id(
                "cmp",
                "pre-commit-hook-repository",
                "pre-commit:https://github.com/gitleaks/gitleaks",
            ),
            "kind": "pre-commit-hook-repository",
            "ecosystem": "pre-commit",
            "name": "gitleaks",
            "metadata": {"source_repo": "https://github.com/gitleaks/gitleaks"},
        }
        self.assertEqual(
            "pre-commit:https://github.com/gitleaks/gitleaks",
            kr.recover_component_identity(hook),
        )

    def test_github_release_asset_identity_recovers_from_release_api(self) -> None:
        """The release job's asset kept only its file name, never the reference."""

        component = {
            # The id a harvest gives this asset; the channel derivation
            # once skipped such a component.
            "component_id": "cmp-a7cd63169df20ba622da6553",
            "kind": "model-artifact",
            "ecosystem": "github-release-asset",
            "name": "model.onnx",
            "metadata": {
                "asset": "model.onnx",
                "release_api": (
                    "https://api.github.com/repos/example-org/example-weights"
                    "/releases/tags/v1.0-weights"
                ),
            },
        }
        identity = (
            "model-artifact:github-release-asset:"
            "github-release://example-org/example-weights@v1.0-weights/model.onnx"
        )
        self.assertEqual(identity, kr.recover_component_identity(component))
        self.assertEqual(
            component["component_id"],
            kr.stable_id("cmp", "model-artifact", identity.lower()),
        )
        # A release URL that is not a tag reference must not guess a reference.
        untagged = copy.deepcopy(component)
        untagged["metadata"][
            "release_api"
        ] = "https://api.github.com/repos/example-org/example-weights/releases/latest"
        self.assertIsNone(kr.recover_component_identity(untagged))

    def test_dynamic_remote_input_records_the_locator_it_was_hashed_from(self) -> None:
        """The sanitized file name alone could never rebuild the id."""

        files = RegistryTest.fixture_files()
        files["scripts/setup/linux-apt-mise.sh"] = """#!/usr/bin/env bash
K9S_VER="$(curl -s https://api.github.com/repos/derailed/k9s/releases/latest | jq -r .tag_name)"
curl -fsSL "https://github.com/derailed/k9s/releases/download/${K9S_VER}/k9s_Linux_amd64.tar.gz" -o /tmp/k9s.tgz
"""
        manifest = kr.discover_repo(self.repository(files), observed_at=OBSERVED_AT)
        dynamic = [
            component
            for component in manifest["components"]
            if component.get("metadata", {}).get("locator_state") == "dynamic-template"
        ]
        self.assertEqual(1, len(dynamic))
        component = dynamic[0]
        identity = kr.recover_component_identity(component)
        self.assertEqual(
            f"remote-input-dynamic:{component['metadata']['dynamic_input_identity']}",
            identity,
        )
        self.assertEqual(
            component["component_id"],
            kr.stable_id("cmp", component["kind"], str(identity).lower()),
        )
        # The recorded locator is the version evidence, not a rebuilt guess.
        versions = [
            version
            for version in manifest["versions"]
            if version["component_id"] == component["component_id"]
        ]
        self.assertEqual(1, len(versions))
        self.assertEqual(
            [component["metadata"]["dynamic_input_identity"]],
            list(versions[0]["evidence"]),
        )
        # Without the recorded locator the component is unrecoverable again.
        stripped = copy.deepcopy(component)
        del stripped["metadata"]["dynamic_input_identity"]
        self.assertIsNone(kr.recover_component_identity(stripped))

    def test_toolchain_w8_policy_covers_the_no_policy_residue(self) -> None:
        """These six language-toolchain rows were the last no-policy skips."""

        policy = next(
            entry
            for entry in kr.load_channel_policies(self.POLICY_DIR.as_posix())
            if entry["record"]["record_id"] == "policy:channel:toolchain:w8:v1"
        )
        record = policy["record"]
        self.assertEqual(
            kr.CHANNEL_POLICY_TABLE_SELECTOR,
            kr.channel_policy_selector(record),
        )
        self.assertEqual(
            {
                "cmp-16057b6621f6bbc3107663e7",
                "cmp-1e03905819fd9621b9f25d23",
                "cmp-356174090414ad9e7efaed00",
                "cmp-3b610d576cae0def35a7cb37",
                "cmp-5edd3a0e1a07d1fde1afca44",
                "cmp-9214f30225aaf54e843f396a",
            },
            set(record["rows"]),
        )
        available = 0
        for row_set in record["rows"].values():
            self.assertEqual(
                set(kr.OFFICIAL_CHANNEL_TYPES),
                {row["channel_type"] for row in row_set["channels"]},
            )
            for row in row_set["channels"]:
                if row["disposition"] != "available":
                    self.assertTrue(row.get("reason"))
                    continue
                available += 1
                # Each asserted availability carries its own liveness receipt.
                self.assertEqual(row["canonical_uri"], row["probe"]["final_url"])
                self.assertTrue(200 <= row["probe"]["status"] < 400)
        self.assertEqual(40, available)

    def test_go_mod_module_root_splits_namespace_like_require_and_gosum(self) -> None:
        """The module root was the only golang site left unsplit."""

        root = self.repository(
            {
                "go.mod": (
                    "module github.com/example-org/k8s/apps/media/romm-curator\n"
                    "\ngo 1.26\n"
                )
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        roots = [
            component
            for component in manifest["components"]
            if component.get("kind") == "go-module"
        ]
        self.assertEqual(1, len(roots))
        component = roots[0]
        # A namespace is what every ecosystem channel policy preconditions on.
        self.assertEqual("github.com/example-org/k8s/apps/media", component["namespace"])
        self.assertEqual("romm-curator", component["name"])
        # purl and identity keep the whole module path, as the other sites do.
        self.assertEqual(
            "pkg:golang/github.com/example-org/k8s/apps/media/romm-curator",
            component["purl"],
        )

        root = self.repository(
            {
                "go.mod": """module example.invalid/demo

go 1.26

require go4.org v0.0.0-20200411211856-f5505b9728dd
""",
                "go.sum": (
                    "go.opencensus.io v0.24.0 "
                    "h1:y73uSU6J157QMP2kn2r66baCQFAYz1JCPhCNKp9NfMY=\n"
                ),
            }
        )
        manifest = kr.discover_repo(root, observed_at=OBSERVED_AT)
        by_purl = {
            component.get("purl"): component
            for component in manifest["components"]
            if component.get("ecosystem") == "golang"
        }
        vanity_mod = by_purl["pkg:golang/go4.org"]
        self.assertEqual("go4.org", vanity_mod["namespace"])
        self.assertEqual("go4.org", vanity_mod["name"])
        self.assertEqual(
            kr.stable_id("cmp", "library", "pkg:golang/go4.org"),
            vanity_mod["component_id"],
        )
        vanity_sum = by_purl["pkg:golang/go.opencensus.io"]
        self.assertEqual("go.opencensus.io", vanity_sum["namespace"])
        self.assertEqual("go.opencensus.io", vanity_sum["name"])

    def test_golang_sbom_vanity_namespace(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "live-export:sboms", "test", content_hash="sha256:" + "9" * 64
        )
        item = {
            "kind": "SbomReport",
            "metadata": {"name": "demo", "namespace": "ns"},
            "report": {
                "artifact": {
                    "repository": "docker.io/library/demo",
                    "tag": "1.0",
                    "digest": "sha256:" + "a" * 64,
                },
                "components": {
                    "components": [
                        {
                            "type": "library",
                            "name": "goauthentik.io",
                            "version": "v1.0.0",
                            "purl": "pkg:golang/goauthentik.io@v1.0.0",
                        },
                        {
                            "type": "library",
                            "name": "stdlib",
                            "version": "1.24.4",
                            "purl": "pkg:golang/stdlib@1.24.4",
                        },
                    ]
                },
            },
        }
        kr.import_sbom_item(builder, source, item, 0)
        manifest = builder.manifest()
        by_name = {
            component["name"]: component
            for component in manifest["components"]
            if component.get("ecosystem") == "golang"
        }
        self.assertEqual("goauthentik.io", by_name["goauthentik.io"]["namespace"])
        self.assertEqual(
            kr.stable_id("cmp", "library", "pkg:golang/goauthentik.io"),
            by_name["goauthentik.io"]["component_id"],
        )
        self.assertEqual("", by_name["stdlib"]["namespace"])


class ChannelClosureW3Test(unittest.TestCase):
    POLICY_DIR = REPO_ROOT / "knowledge" / "registry" / "channel-policies"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def policy(self, ecosystem: str) -> dict[str, Any]:
        policies = kr.load_channel_policies(self.POLICY_DIR.as_posix())
        return next(
            policy
            for policy in policies
            if policy["record"]["scope"]["ecosystem"] == ecosystem
        )

    def test_manifest_bounds_v1_reseals_byte_identically(self) -> None:
        builder, _, _, _ = RegistryTest.minimal_builder(self)
        manifest = builder.manifest()
        self.assertEqual(768 * 2**20, manifest["bounds"]["serialized_output_bytes"])
        self.assertEqual(768 * 2**20, manifest["bounds"]["json_input_bytes"])
        self.assertEqual([], kr.validate_manifest(manifest))

        frozen = copy.deepcopy(manifest)
        frozen["bounds"] = dict(kr.MANIFEST_BOUNDS_V1)
        frozen = kr.seal_manifest(frozen)
        self.assertEqual(kr.MANIFEST_BOUNDS_V1, frozen["bounds"])
        self.assertNotEqual(manifest["manifest_id"], frozen["manifest_id"])
        self.assertEqual([], kr.validate_manifest(frozen))
        self.assertEqual(frozen, kr.seal_manifest(copy.deepcopy(frozen)))

        tampered = copy.deepcopy(frozen)
        tampered["bounds"] = {**kr.MANIFEST_BOUNDS_V1, "gaps": 1}
        self.assertTrue(
            any("envelope" in error for error in kr.validate_manifest(tampered))
        )

    def test_manifest_bounds_v2_reseals_byte_identically(self) -> None:
        builder, _, _, _ = RegistryTest.minimal_builder(self)
        manifest = builder.manifest()
        self.assertEqual(700_000, manifest["bounds"]["dependency_edges"])
        self.assertEqual(20_000_000, manifest["bounds"]["json_nodes"])

        self.assertEqual(400_000, kr.MANIFEST_BOUNDS_V2["dependency_edges"])
        self.assertEqual(10_000_000, kr.MANIFEST_BOUNDS_V2["json_nodes"])
        self.assertEqual(768 * 2**20, kr.MANIFEST_BOUNDS_V2["json_input_bytes"])
        self.assertNotEqual(kr.MANIFEST_BOUNDS_V1, kr.MANIFEST_BOUNDS_V2)

        frozen = copy.deepcopy(manifest)
        frozen["bounds"] = dict(kr.MANIFEST_BOUNDS_V2)
        frozen = kr.seal_manifest(frozen)
        self.assertEqual(kr.MANIFEST_BOUNDS_V2, frozen["bounds"])
        self.assertNotEqual(manifest["manifest_id"], frozen["manifest_id"])
        self.assertEqual([], kr.validate_manifest(frozen))
        self.assertEqual(frozen, kr.seal_manifest(copy.deepcopy(frozen)))

        tampered = copy.deepcopy(frozen)
        tampered["bounds"] = {**kr.MANIFEST_BOUNDS_V2, "occurrences": 1}
        self.assertTrue(
            any("envelope" in error for error in kr.validate_manifest(tampered))
        )

    def test_module_context_collapses_vanity_host(self) -> None:
        policy: dict[str, Any] = {"tables": {}, "variables": {}}
        vanity = kr.channel_policy_context(
            policy,
            {
                "name": "go.opencensus.io",
                "namespace": "go.opencensus.io",
                "ecosystem": "golang",
                "purl": "pkg:golang/go.opencensus.io",
            },
        )
        self.assertEqual("go.opencensus.io", vanity["module"])
        regular = kr.channel_policy_context(
            policy,
            {
                "name": "mux",
                "namespace": "github.com/gorilla",
                "ecosystem": "golang",
                "purl": "pkg:golang/github.com/gorilla/mux",
            },
        )
        self.assertEqual("github.com/gorilla/mux", regular["module"])
        bare = kr.channel_policy_context(
            policy,
            {"name": "stdlib", "namespace": "", "ecosystem": "golang", "purl": None},
        )
        self.assertEqual("stdlib", bare["module"])

    def test_metadata_scalars_enter_template_context(self) -> None:
        context = kr.channel_policy_context(
            {"tables": {}, "variables": {}},
            {
                "name": "demo",
                "namespace": "",
                "ecosystem": "helm",
                "purl": None,
                "metadata": {
                    "chart_repository": "https://charts.demo.io",
                    "storage_uri": "s3://bucket/demo",
                    "self_repository": True,
                    "count": 3,
                },
            },
        )
        self.assertEqual("https://charts.demo.io", context["m_chart_repository"])
        self.assertEqual("s3://bucket/demo", context["m_storage_uri"])
        self.assertNotIn("m_self_repository", context)
        self.assertNotIn("m_count", context)

    def test_identity_candidates_recover_w3_grammars(self) -> None:
        builder = kr.Builder()
        fixtures = (
            (
                "git-repository",
                "git",
                "apps/demo",
                "git:git@github.com:example-org/k8s.git:apps/demo",
                {
                    "source_repo": "git@github.com:example-org/k8s.git",
                    "path": "apps/demo",
                    "self_repository": True,
                },
            ),
            (
                "source-repository",
                "git",
                "helm-diff",
                "git:https://github.com/databus23/helm-diff",
                {"source_repo": "https://github.com/databus23/helm-diff"},
            ),
            (
                "helm-chart",
                "helm",
                "demo-chart",
                "helm:https://charts.demo.io:demo-chart",
                {"chart_repository": "https://charts.demo.io"},
            ),
            (
                "model-artifact",
                "huggingface",
                "Demo-Model",
                "model-artifact:huggingface:Org/Demo-Model",
                {"repository": "Org/Demo-Model"},
            ),
            (
                "model-artifact",
                "huggingface",
                "demo.gguf",
                "model-artifact:huggingface:Org/Demo-Model/demo.gguf",
                {"repository": "Org/Demo-Model", "filename": "demo.gguf"},
            ),
            (
                "model-artifact",
                "s3-model",
                "demo",
                "model-artifact:s3-model:s3://models/demo",
                {"storage_uri": "s3://models/demo"},
            ),
        )
        for kind, ecosystem, name, identity, metadata in fixtures:
            component_id = builder.add_component(
                kind=kind,
                ecosystem=ecosystem,
                name=name,
                identity=identity,
                metadata=metadata,
            )
            self.assertEqual(
                identity,
                kr.recover_component_identity(builder.components[component_id]),
                identity,
            )

    def w3_baseline(self) -> tuple[dict[str, Any], dict[str, str]]:
        builder = kr.Builder()
        source = builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "2" * 64,
            metadata={"evidence_class": "test"},
        )
        ids: dict[str, str] = {}
        fixtures = (
            (
                "git_self",
                "git-repository",
                "git",
                "apps/demo",
                "git:git@github.com:example-org/k8s.git:apps/demo",
                None,
                {
                    "source_repo": "git@github.com:example-org/k8s.git",
                    "path": "apps/demo",
                    "self_repository": True,
                },
            ),
            (
                "git_external",
                "source-repository",
                "git",
                "helm-diff",
                "git:https://github.com/databus23/helm-diff",
                None,
                {"source_repo": "https://github.com/databus23/helm-diff"},
            ),
            (
                "helm_http",
                "helm-chart",
                "helm",
                "argo-rollouts",
                "helm:https://argoproj.github.io/argo-helm:argo-rollouts",
                None,
                {"chart_repository": "https://argoproj.github.io/argo-helm"},
            ),
            (
                "helm_oci",
                "helm-chart",
                "helm",
                "kserve-resources",
                "helm:ghcr.io/kserve/charts:kserve-resources",
                None,
                {"chart_repository": "ghcr.io/kserve/charts"},
            ),
            (
                "oci_internal",
                "oci-image",
                "oci",
                "kb-mcp",
                None,
                "pkg:oci/kb-mcp?repository_url=registry.example.com/library/kb-mcp",
                {"oci_repository": "registry.example.com/library/kb-mcp"},
            ),
            (
                "oci_proxy",
                "oci-image",
                "oci",
                "presidio-analyzer",
                None,
                "pkg:oci/presidio-analyzer?repository_url=registry.example.com/proxy-mcr/presidio-analyzer",
                {
                    "oci_repository": (
                        "registry.example.com/proxy-mcr/presidio-analyzer"
                    )
                },
            ),
            (
                "hf_repo",
                "model-artifact",
                "huggingface",
                "Qwen3-8B-int4-ov",
                "model-artifact:huggingface:OpenVINO/Qwen3-8B-int4-ov",
                None,
                {"repository": "OpenVINO/Qwen3-8B-int4-ov"},
            ),
            (
                "hf_bare",
                "model-artifact",
                "huggingface",
                "auto",
                "model-artifact:huggingface:auto",
                None,
                {},
            ),
            (
                "s3_uri",
                "model-artifact",
                "s3-model",
                "demo-detector",
                "model-artifact:s3-model:s3://example-models/demo-detector",
                None,
                {"storage_uri": "s3://example-models/demo-detector"},
            ),
            (
                "s3_bare",
                "model-artifact",
                "s3-model",
                "calib.zip",
                "model-artifact:s3-model:calib.zip",
                None,
                {},
            ),
        )
        for index, (label, kind, ecosystem, name, identity, purl, meta) in enumerate(
            fixtures
        ):
            namespace = (
                "registry.example.com/library"
                if label == "oci_internal"
                else "registry.example.com/proxy-mcr" if label == "oci_proxy" else ""
            )
            component_id = builder.add_component(
                kind=kind,
                ecosystem=ecosystem,
                namespace=namespace,
                name=name,
                identity=identity,
                purl=purl,
                metadata=meta,
            )
            version_id = builder.add_version(
                component_id,
                resolved_version="1.0.0",
                artifact_digest=("sha256:" + "b" * 64 if ecosystem == "oci" else None),
                evidence=("fixture.json",),
            )
            builder.add_occurrence(
                component_id,
                version_id,
                source,
                locator=f"/{index}",
                role="test",
                raw_value=label,
            )
            ids[label] = component_id
        manifest = builder.manifest()
        self.assertEqual([], kr.validate_manifest(manifest))
        return manifest, ids

    def test_w3_policies_close_populations_and_fail_closed(self) -> None:
        baseline, ids = self.w3_baseline()
        policies = [
            self.policy("git"),
            self.policy("helm"),
            self.policy("oci"),
            self.policy("huggingface"),
            self.policy("s3-model"),
        ]
        records, _, summary = kr.derive_channel_records(baseline, policies)
        by_component = dict(records)
        self.assertEqual(
            sorted(
                [
                    ids["git_self"],
                    ids["helm_http"],
                    ids["oci_internal"],
                    ids["hf_repo"],
                    ids["s3_uri"],
                ]
            ),
            sorted(by_component),
        )
        self.assertEqual({"precondition-mismatch": 5}, summary["skipped"])

        available = {
            record["component"]["ecosystem"]: next(
                channel
                for channel in record["channels"]
                if channel["availability_state"] == "available"
            )
            for record in by_component.values()
        }
        self.assertEqual(
            "https://github.com/example-org/k8s", available["git"]["canonical_uri"]
        )
        self.assertEqual("restricted", available["git"]["access"])
        self.assertEqual(
            "https://argoproj.github.io/argo-helm/index.yaml",
            available["helm"]["canonical_uri"],
        )
        self.assertEqual(
            "https://registry.example.com/api/v2.0/projects/library/"
            "repositories/kb-mcp",
            available["oci"]["canonical_uri"],
        )
        self.assertEqual("restricted", available["oci"]["access"])
        self.assertEqual(
            "https://huggingface.co/OpenVINO/Qwen3-8B-int4-ov",
            available["huggingface"]["canonical_uri"],
        )
        self.assertEqual(
            "s3://example-models/demo-detector",
            available["s3-model"]["canonical_uri"],
        )
        self.assertEqual("restricted", available["s3-model"]["access"])
        for label, kind in (
            ("git_self", "git-repository"),
            ("helm_http", "helm-chart"),
            ("oci_internal", "oci-image"),
            ("hf_repo", "model-artifact"),
        ):
            self.assertEqual(kind, by_component[ids[label]]["component"]["kind"])
            self.assertEqual(
                kind, by_component[ids[label]]["component"]["registry_kind"]
            )

        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest(
                    [(f"{cid}.json", record) for cid, record in records]
                ),
            ]
        )
        report = kr.channel_wave_gate(
            baseline, merged, policies=policies, expected_matched=5
        )
        self.assertTrue(report["pass"], report)
        unresolved = {
            gap.get("component_id")
            for gap in merged["gaps"]
            if gap["gap_type"] == "official-channel-unresolved"
        }
        for label in ("git_self", "helm_http", "oci_internal", "hf_repo", "s3_uri"):
            self.assertNotIn(ids[label], unresolved)
        for label in ("git_external", "helm_oci", "oci_proxy", "hf_bare", "s3_bare"):
            self.assertIn(ids[label], unresolved)

    def test_golang_v2_renders_whole_module_vanity_once(self) -> None:
        policy = self.policy("golang")
        self.assertEqual("policy:channel:golang:v2", policy["record"]["record_id"])
        builder = kr.Builder()
        source = builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "3" * 64,
            metadata={"evidence_class": "test"},
        )
        regular = builder.add_component(
            kind="library",
            ecosystem="golang",
            namespace="github.com/gorilla",
            name="mux",
            purl="pkg:golang/github.com/gorilla/mux",
        )
        vanity = builder.add_component(
            kind="library",
            ecosystem="golang",
            namespace="go.opencensus.io",
            name="go.opencensus.io",
            purl="pkg:golang/go.opencensus.io",
        )
        frozen_vanity = builder.add_component(
            kind="library",
            ecosystem="golang",
            namespace="",
            name="go4.org",
            purl="pkg:golang/go4.org",
        )
        for index, component_id in enumerate((regular, vanity, frozen_vanity)):
            version_id = builder.add_version(
                component_id,
                resolved_version="v1.0.0",
                evidence=("fixture.json",),
            )
            builder.add_occurrence(
                component_id,
                version_id,
                source,
                locator=f"/{index}",
                role="test",
                raw_value="go",
            )
        baseline = builder.manifest()
        records, _, summary = kr.derive_channel_records(baseline, [policy])
        by_component = dict(records)
        self.assertEqual(sorted([regular, vanity]), sorted(by_component))
        self.assertEqual({"precondition-mismatch": 1}, summary["skipped"])

        def package_uri(component_id: str) -> str:
            return next(
                channel["canonical_uri"]
                for channel in by_component[component_id]["channels"]
                if channel["channel_type"] == "package"
            )

        self.assertEqual(
            "https://proxy.golang.org/github.com/gorilla/mux/@v/list",
            package_uri(regular),
        )
        self.assertEqual(
            "https://proxy.golang.org/go.opencensus.io/@v/list",
            package_uri(vanity),
        )


class ChannelSnapshotR3Test(unittest.TestCase):
    FIXTURE_POLICY = TOOL_ROOT / "tests" / "fixtures" / "channel-policies" / "pypi.json"
    PACKAGE_URI = "https://pypi.org/project/demo/"

    fixture_policy_payload = ChannelClosureW0Test.fixture_policy_payload
    policy_dir = ChannelClosureW0Test.policy_dir
    pypi_baseline = ChannelClosureW0Test.pypi_baseline

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def write_receipts(
        self, rows: list[dict[str, Any]], blobs: dict[str, bytes]
    ) -> str:
        root = self.base / f"snapshots-{len(list(self.base.iterdir()))}"
        (root / "receipts").mkdir(parents=True)
        (root / "cas").mkdir()
        for digest, data in blobs.items():
            target = root / "cas" / "sha256" / digest[:2] / digest
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (root / "receipts" / "receipts-test.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        return root.as_posix()

    @staticmethod
    def receipt_row(
        channel_ids: list[str],
        canonical_uri: str,
        content: bytes,
        **overrides: Any,
    ) -> tuple[dict[str, Any], str]:
        digest = hashlib.sha256(content).hexdigest()
        row: dict[str, Any] = {
            "channel_ids": channel_ids,
            "canonical_uri": canonical_uri,
            "resolved_uri": canonical_uri,
            "fetched_at": "2026-08-22T12:00:00Z",
            "observed_at": "2026-08-22T12:00:00Z",
            "etag": None,
            "last_modified": None,
            "content_hash": f"sha256:{digest}",
            "media_type": "text/html",
            "bytes": len(content),
            "status": "fetched",
            "error_state": None,
            "http_status": 200,
            "attempt": 1,
            "runner_version": "test-0",
            "cas_path": f"cas/sha256/{digest[:2]}/{digest}",
        }
        row.update(overrides)
        return row, digest

    def derived_records(
        self,
    ) -> tuple[dict[str, Any], str, list[tuple[str, dict[str, Any]]], str]:
        baseline, demo, _, _ = self.pypi_baseline()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, _, _ = kr.derive_channel_records(baseline, policies)
        channel_id = next(
            str(channel["channel_id"])
            for channel in records[0][1]["channels"]
            if channel["channel_type"] == "package"
        )
        return baseline, demo, records, channel_id

    def test_snapshot_binding_end_to_end_with_snapshot_gate(self) -> None:
        baseline, demo, records, channel_id = self.derived_records()
        head = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest(
                    [("demo.json", copy.deepcopy(records[0][1]))]
                ),
            ]
        )
        content = b"<html>demo</html>"
        row, digest = self.receipt_row([channel_id], self.PACKAGE_URI, content)
        receipts = self.write_receipts([row], {digest: content})
        summary = kr.bind_channel_snapshot_receipts(records, baseline, receipts)
        self.assertEqual(1, summary["channels_bound"])
        self.assertEqual([], summary["channels_unbound"])
        record = records[0][1]
        baseline_version_id = next(
            version["component_version_id"]
            for version in baseline["versions"]
            if version["component_id"] == demo
        )
        self.assertEqual(
            [baseline_version_id],
            [version["component_version_id"] for version in record["versions"]],
        )
        snapshot = record["snapshots"][0]
        self.assertEqual(channel_id, snapshot["channel_id"])
        self.assertEqual(f"sha256:{digest}", snapshot["content_hash"])
        self.assertEqual(f"snap:{channel_id}:{digest[:12]}", snapshot["snapshot_id"])
        merged = kr.merge_manifests(
            [baseline, kr.reviewed_records_manifest([("demo.json", record)])]
        )
        axis = merged["completeness"]["snapshots"]
        self.assertEqual(1, axis["immutable_verified_channels"])
        self.assertEqual("complete", axis["state"])
        report = kr.channel_snapshot_gate(head, merged, receipts_dir=receipts)
        self.assertTrue(report["pass"], report)
        self.assertTrue(report["checks"]["zero-new-versions"]["pass"])
        self.assertEqual(
            1, report["checks"]["snapshot-arithmetic"]["credited_channels"]
        )
        self.assertEqual(
            0, report["checks"]["snapshot-arithmetic"]["unbindable_channels"]
        )

    def test_snapshot_binding_command_is_deterministic(self) -> None:
        baseline, _, records, channel_id = self.derived_records()
        baseline_path = self.base / "baseline.json"
        baseline_path.write_text(json.dumps(baseline, sort_keys=True), encoding="utf-8")
        directory = self.policy_dir(self.fixture_policy_payload())
        content = b"payload"
        row, digest = self.receipt_row([channel_id], self.PACKAGE_URI, content)
        receipts = self.write_receipts([row], {digest: content})
        first_out = self.base / "out-1"
        second_out = self.base / "out-2"
        for target in (first_out, second_out):
            summary = kr.derive_channels_command(
                baseline_path.as_posix(),
                directory,
                target.as_posix(),
                snapshot_receipts=receipts,
            )
            self.assertEqual(1, summary["snapshot_binding"]["channels_bound"])
        component_id = records[0][0]
        self.assertEqual(
            (first_out / "records" / f"{component_id}.json").read_bytes(),
            (second_out / "records" / f"{component_id}.json").read_bytes(),
        )
        self.assertEqual(
            (first_out / "derive-channels-summary.json").read_bytes(),
            (second_out / "derive-channels-summary.json").read_bytes(),
        )

    def test_snapshot_receipt_hash_mismatch_fails_closed(self) -> None:
        baseline, _, records, channel_id = self.derived_records()
        row, digest = self.receipt_row([channel_id], self.PACKAGE_URI, b"real")
        receipts = self.write_receipts([row], {digest: b"tampered"})
        summary = kr.bind_channel_snapshot_receipts(records, baseline, receipts)
        self.assertEqual(0, summary["channels_bound"])
        self.assertEqual([], records[0][1]["snapshots"])
        self.assertEqual([], records[0][1]["versions"])
        self.assertIn("content_hash", summary["channels_unbound"][0]["reason"])

    def test_snapshot_receipt_channel_mismatch_fails_closed(self) -> None:
        baseline, _, records, channel_id = self.derived_records()
        content = b"payload"
        wrong_uri, digest = self.receipt_row(
            [channel_id], "https://pypi.org/project/other/", content
        )
        unknown, _ = self.receipt_row(
            ["chn:policy:channel:pypi:v0-test:cmp-missing:package"],
            self.PACKAGE_URI,
            content,
        )
        receipts = self.write_receipts([wrong_uri, unknown], {digest: content})
        summary = kr.bind_channel_snapshot_receipts(records, baseline, receipts)
        self.assertEqual(0, summary["channels_bound"])
        self.assertEqual([], records[0][1]["snapshots"])
        reasons = {
            item["channel_id"]: item["reason"] for item in summary["channels_unbound"]
        }
        self.assertIn("canonical_uri", reasons[channel_id])
        self.assertIn(
            "derived available channel",
            reasons["chn:policy:channel:pypi:v0-test:cmp-missing:package"],
        )

    def test_snapshot_failure_receipt_stays_in_band(self) -> None:
        baseline, _, records, channel_id = self.derived_records()
        row = {
            "channel_ids": [channel_id],
            "canonical_uri": self.PACKAGE_URI,
            "resolved_uri": self.PACKAGE_URI,
            "fetched_at": None,
            "observed_at": "2026-08-22T12:00:00Z",
            "etag": None,
            "last_modified": None,
            "content_hash": None,
            "media_type": None,
            "bytes": None,
            "status": "fetch-failed",
            "error_state": "http-500",
            "http_status": 500,
            "attempt": 5,
            "runner_version": "test-0",
            "cas_path": None,
        }
        receipts = self.write_receipts([row], {})
        summary = kr.bind_channel_snapshot_receipts(records, baseline, receipts)
        self.assertEqual(1, summary["channels_bound"])
        snapshot = records[0][1]["snapshots"][0]
        self.assertEqual("fetch-failed", snapshot["status"])
        self.assertEqual("http-500", snapshot["error_state"])
        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest([("demo.json", records[0][1])]),
            ]
        )
        self.assertEqual(
            0,
            merged["completeness"]["snapshots"]["immutable_verified_channels"],
        )

    def test_snapshot_gate_rejects_unreceipted_credit(self) -> None:
        baseline, _, records, channel_id = self.derived_records()
        head = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest(
                    [("demo.json", copy.deepcopy(records[0][1]))]
                ),
            ]
        )
        content = b"<html>demo</html>"
        row, digest = self.receipt_row([channel_id], self.PACKAGE_URI, content)
        receipts = self.write_receipts([row], {digest: content})
        kr.bind_channel_snapshot_receipts(records, baseline, receipts)
        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest([("demo.json", records[0][1])]),
            ]
        )
        empty = self.write_receipts([], {})
        report = kr.channel_snapshot_gate(head, merged, receipts_dir=empty)
        self.assertFalse(report["pass"])
        self.assertFalse(report["checks"]["snapshot-arithmetic"]["pass"])
        self.assertFalse(report["checks"]["added-snapshots-trace"]["pass"])

    def test_snapshot_gate_explains_unbindable_versions(self) -> None:
        builder = kr.Builder()
        source = builder.add_source(
            "fixture.json",
            "test",
            content_hash="sha256:" + "1" * 64,
            metadata={"evidence_class": "test"},
        )
        demo = builder.add_component(
            kind="library", ecosystem="pypi", name="demo", purl="pkg:pypi/demo"
        )
        # Evidence-less versions stay genuinely unbindable (the UID-source_ref
        # shape binds since the resolved-via-source_ref fix).
        version = builder.add_version(
            demo,
            resolved_version="1.0.0",
            resolution_state="resolved",
        )
        builder.add_occurrence(
            demo, version, source, locator="/demo", role="test", raw_value="demo"
        )
        baseline = builder.manifest()
        policies = kr.load_channel_policies(
            self.policy_dir(self.fixture_policy_payload())
        )
        records, _, _ = kr.derive_channel_records(baseline, policies)
        channel_id = next(
            str(channel["channel_id"])
            for channel in records[0][1]["channels"]
            if channel["channel_type"] == "package"
        )
        head = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest(
                    [("demo.json", copy.deepcopy(records[0][1]))]
                ),
            ]
        )
        content = b"payload"
        row, digest = self.receipt_row([channel_id], self.PACKAGE_URI, content)
        receipts = self.write_receipts([row], {digest: content})
        summary = kr.bind_channel_snapshot_receipts(records, baseline, receipts)
        self.assertEqual(0, summary["channels_bound"])
        self.assertIn("expressible", summary["channels_unbound"][0]["reason"])
        merged = kr.merge_manifests(
            [
                baseline,
                kr.reviewed_records_manifest([("demo.json", records[0][1])]),
            ]
        )
        report = kr.channel_snapshot_gate(head, merged, receipts_dir=receipts)
        self.assertTrue(report["pass"], report)
        arithmetic = report["checks"]["snapshot-arithmetic"]
        self.assertEqual(0, arithmetic["credited_channels"])
        self.assertEqual(1, arithmetic["unbindable_channels"])
        self.assertEqual([channel_id], arithmetic["unbindable_channel_ids"])

    def test_snapshot_receipt_schema_conformance(self) -> None:
        validator = kr.snapshot_receipt_validator()
        row, _ = self.receipt_row(
            ["chn:policy:channel:pypi:v0-test:cmp-demo:package"],
            self.PACKAGE_URI,
            b"payload",
        )
        self.assertEqual([], kr.schema_validation_errors(validator, row))
        for tamper in (
            {"status": "downloaded"},
            {"cas_path": None},
            {"content_hash": None},
            {"channel_ids": []},
            {"unexpected": True},
        ):
            self.assertNotEqual(
                [],
                kr.schema_validation_errors(validator, {**row, **tamper}),
                tamper,
            )


class IdentityWaveR4Test(unittest.TestCase):
    REPO_URI = "https://github.com/example-org/k8s"
    SOURCE_REPO = "git@github.com:example-org/k8s.git"
    OBSERVATION = {
        "observed_at": "2026-08-22T13:15:08Z",
        "source_valid_at": "2026-08-22T13:14:54Z",
        "source_valid_time_basis": "git-commit-committer-time",
    }

    write_receipts = ChannelSnapshotR3Test.write_receipts
    receipt_row = staticmethod(ChannelSnapshotR3Test.receipt_row)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    @staticmethod
    def commit_object(message: str = "identity fixture") -> tuple[str, bytes]:
        data = (
            f"tree {'0' * 40}\n"
            "author Fixture <fixture@example.invalid> 0 +0000\n"
            "committer Fixture <fixture@example.invalid> 0 +0000\n"
            f"\n{message}\n"
        ).encode("utf-8")
        preimage = b"commit " + str(len(data)).encode("ascii") + b"\0" + data
        return hashlib.sha1(preimage, usedforsecurity=False).hexdigest(), data

    def observation(self, commit: str, digest: str, **overrides: Any) -> dict[str, Any]:
        observation = {
            "evidence_cas_path": f"cas/sha256/{digest[:2]}/{digest}",
            "evidence_content_hash": f"sha256:{digest}",
            "observed_at": "2026-08-22T19:48:32Z",
            "observed_commit": commit,
            "observed_ref": "main",
            "receipt_canonical_uri": self.REPO_URI,
            "resolver": "git-commit-object-receipt",
        }
        observation.update(overrides)
        return observation

    def gitops_builder(
        self, observation: dict[str, Any] | None = None, *, ref: str = "main"
    ) -> tuple[kr.Builder, str, str]:
        builder = kr.Builder()
        source = builder.add_source(
            "argocd-apps/demo.yaml",
            "argocd-application",
            content_hash="sha256:" + "2" * 64,
        )
        component = builder.add_component(
            kind="git-repository",
            ecosystem="git",
            name="apps/demo",
            identity=f"git:{self.SOURCE_REPO}:apps/demo",
            metadata={
                "path": "apps/demo",
                "self_repository": True,
                "source_repo": self.SOURCE_REPO,
            },
        )
        version = builder.add_version(
            component,
            source_ref=ref,
            constraint=ref,
            evidence=("argocd-apps/demo.yaml#L11",),
            metadata=(
                {kr.GITOPS_OBSERVATION_KEY: observation} if observation else None
            ),
        )
        builder.add_occurrence(
            component,
            version,
            source,
            locator="line:11:source:0",
            role="argo-git-source",
            raw_value=f"{self.SOURCE_REPO}#apps/demo@{ref}",
            dependency_scope="deployment",
        )
        return builder, component, version

    def helm_lock_gap(self, builder: kr.Builder) -> str:
        chart = builder.add_component(
            kind="helm-chart", ecosystem="helm", name="wikijs", identity="helm::wikijs"
        )
        chart_version = builder.add_version(
            chart, resolved_version="2.4.1", evidence=("apps/demo/Chart.yaml",)
        )
        gap = builder.add_gap(
            "helm-lock-policy",
            "apps/demo/Chart.yaml relies on the deliberate Chart.lock-untracked "
            "policy; its exact Chart.yaml pins are the durable truth",
            component_id=chart,
            component_version_id=chart_version,
            evidence=(
                "apps/demo/Chart.yaml",
                ".githooks/check-helm-dependency-versions.py",
                ".gitignore#L91",
            ),
        )
        return gap

    def sealed(self, builder: kr.Builder) -> dict[str, Any]:
        manifest = builder.manifest()
        manifest["observation"] = dict(self.OBSERVATION)
        return kr.seal_manifest(manifest)

    def deviation_dir(self, **overrides: Any) -> str:
        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "record_kind": "accepted_deviation",
            "record_id": "deviation:closure:helm-lock-policy:test",
            "review": {
                "status": "accepted",
                "reviewed_by": "operator",
                "reviewed_at": "2026-08-23",
                "evidence": ["deviation-audit:census.md#L332"],
            },
            "scope": {
                "axis": "closure",
                "gap_type": "helm-lock-policy",
                "preconditions": [
                    {
                        "field": "gap.evidence",
                        "pattern": "(?m)^\\.githooks/check-helm-dependency-versions\\.py$",
                    },
                    {"field": "component.ecosystem", "pattern": "^helm$"},
                ],
            },
            "reason": "Chart.lock is deliberately untracked; the pins are the truth.",
            "expires_at": "2027-08-23",
        }
        payload.update(overrides)
        directory = self.base / f"deviations-{len(list(self.base.iterdir()))}"
        directory.mkdir()
        (directory / "helm-lock-policy.json").write_text(
            json.dumps(payload, sort_keys=True, indent=1) + "\n", encoding="utf-8"
        )
        return directory.as_posix()

    def commit_receipts(
        self, component_id: str, **overrides: Any
    ) -> tuple[str, str, str]:
        commit, content = self.commit_object()
        row, digest = self.receipt_row(
            [f"chn:policy:channel:git-self:v1:{component_id}:source"],
            self.REPO_URI,
            content,
            media_type="application/x-git-commit",
            status="verified",
            http_status=None,
            upstream_ref=commit,
        )
        blobs = {digest: content}
        row.update(overrides.pop("row", {}))
        if overrides.pop("corrupt_cas", False):
            blobs = {digest: content + b"tampered"}
        return self.write_receipts([row], blobs), commit, digest

    def test_self_reference_typing_requires_a_bound_capture_time_commit(self) -> None:
        self.assertNotIn("gitops-self-reference-observed", kr.IDENTITY_GAP_TYPES)
        self.assertIn("gitops-self-reference", kr.IDENTITY_GAP_TYPES)
        builder, _component, version = self.gitops_builder()
        blocked = builder.manifest()
        self.assertEqual(
            {"exact-version-unresolved", "gitops-self-reference"},
            {
                gap["gap_type"]
                for gap in blocked["gaps"]
                if gap.get("component_version_id") == version
            },
        )
        commit, content = self.commit_object()
        digest = hashlib.sha256(content).hexdigest()
        builder, _component, version = self.gitops_builder(
            self.observation(commit, digest)
        )
        resolved = builder.manifest()
        self.assertEqual(
            {"gitops-self-reference-observed"},
            {
                gap["gap_type"]
                for gap in resolved["gaps"]
                if gap.get("component_version_id") == version
            },
        )
        self.assertEqual([], resolved["completeness"]["identity"]["blocking_gap_ids"])
        observed = next(
            gap
            for gap in resolved["gaps"]
            if gap["gap_type"] == "gitops-self-reference-observed"
        )
        self.assertIn(commit, observed["message"])
        self.assertIn(f"sha256:{digest}", observed["evidence"])
        for tamper in (
            {"observed_commit": "z" * 40},
            {"observed_commit": commit[:39]},
            {"observed_ref": "master"},
            {"resolver": "operator-assertion"},
            {"evidence_content_hash": "sha256:not-a-hash"},
            {"observed_at": "2026-08-22"},
        ):
            builder, _component, version = self.gitops_builder(
                self.observation(commit, digest, **tamper)
            )
            self.assertEqual(
                {"exact-version-unresolved", "gitops-self-reference"},
                {
                    gap["gap_type"]
                    for gap in builder.manifest()["gaps"]
                    if gap.get("component_version_id") == version
                },
                tamper,
            )

    def test_bind_identity_closes_the_self_reference_pair_without_new_ids(self) -> None:
        builder, component, version = self.gitops_builder()
        baseline = self.sealed(builder)
        receipts, commit, digest = self.commit_receipts(component)
        fragment, summary = kr.bind_gitops_identity(baseline, receipts)
        self.assertEqual(1, summary["versions_bound"])
        self.assertEqual(1, summary["components_bound"])
        self.assertEqual([commit], summary["commits"])
        self.assertEqual([], summary["refused_receipts"])
        merged = kr.merge_manifests([baseline, fragment])
        self.assertEqual([], kr.validate_manifest(merged))
        self.assertEqual(
            {item["component_version_id"] for item in baseline["versions"]},
            {item["component_version_id"] for item in merged["versions"]},
        )
        self.assertEqual(
            {"gitops-self-reference-observed"},
            {
                gap["gap_type"]
                for gap in merged["gaps"]
                if gap.get("component_version_id") == version
            },
        )
        self.assertEqual([], merged["completeness"]["identity"]["blocking_gap_ids"])
        bound = next(
            item
            for item in merged["versions"]
            if item["component_version_id"] == version
        )
        self.assertEqual("unresolved", bound["resolution_state"])
        self.assertEqual(
            commit, bound["metadata"][kr.GITOPS_OBSERVATION_KEY]["observed_commit"]
        )

    def test_bind_identity_fails_closed_on_unverifiable_evidence(self) -> None:
        builder, component, _version = self.gitops_builder()
        baseline = self.sealed(builder)
        corrupted, _commit, _digest = self.commit_receipts(component, corrupt_cas=True)
        _fragment, summary = kr.bind_gitops_identity(baseline, corrupted)
        self.assertEqual(0, summary["versions_bound"])
        self.assertEqual(1, summary["receipts_refused"])
        forged, _commit, _digest = self.commit_receipts(
            component, row={"upstream_ref": "a" * 40}
        )
        _fragment, summary = kr.bind_gitops_identity(baseline, forged)
        self.assertEqual(0, summary["versions_bound"])
        self.assertIn(
            "CAS bytes are not the claimed commit object",
            summary["refused_receipts"][0]["reason"],
        )
        failed, _commit, _digest = self.commit_receipts(
            component, row={"status": "fetch-failed", "error_state": "http-404"}
        )
        _fragment, summary = kr.bind_gitops_identity(baseline, failed)
        self.assertEqual(0, summary["versions_bound"])
        receipts, _commit, _digest = self.commit_receipts(component)
        _fragment, summary = kr.bind_gitops_identity(
            baseline, receipts, observed_ref="develop"
        )
        self.assertEqual(0, summary["versions_bound"])
        with self.assertRaisesRegex(kr.RegistryInputError, "not a mutable ref"):
            kr.bind_gitops_identity(baseline, receipts, observed_ref="v1.2.3")

    def test_ratified_deviation_subtracts_while_the_row_stays_visible(self) -> None:
        builder, _component, _version = self.gitops_builder()
        gap_id = self.helm_lock_gap(builder)
        baseline = self.sealed(builder)
        self.assertIn(gap_id, baseline["completeness"]["closure"]["blocking_gap_ids"])
        deviations = kr.load_accepted_deviations(self.deviation_dir())
        merged = kr.merge_manifests([baseline], accepted_deviations=deviations)
        self.assertEqual([], kr.validate_manifest(merged))
        closure = merged["completeness"]["closure"]
        self.assertIn(gap_id, {gap["gap_id"] for gap in merged["gaps"]})
        self.assertNotIn(gap_id, closure["blocking_gap_ids"])
        self.assertEqual([gap_id], closure["accepted_deviation_ids"])
        self.assertEqual(
            [
                {
                    "declaration_id": "deviation:closure:helm-lock-policy:test",
                    "declaration_sha256": deviations[0]["sha256"],
                    "exempted_gaps": 1,
                }
            ],
            closure["accepted_deviations"],
        )
        self.assertEqual([], closure["blocking_gap_ids"])
        stamp = next(gap for gap in merged["gaps"] if gap["gap_id"] == gap_id)[
            "metadata"
        ][kr.ACCEPTED_DEVIATION_KEY]
        self.assertEqual(deviations[0]["citation"], stamp["citation"])

    def test_unratified_or_lapsed_deviations_keep_blocking(self) -> None:
        builder, _component, _version = self.gitops_builder()
        gap_id = self.helm_lock_gap(builder)
        baseline = self.sealed(builder)
        for overrides in (
            {
                "review": {
                    "status": "proposed",
                    "reviewed_by": "operator",
                    "reviewed_at": "2026-08-23",
                    "evidence": ["deviation-audit:census.md#L332"],
                }
            },
            {"record_kind": "channel_policy"},
            {"expires_at": "not-a-date"},
        ):
            with self.assertRaises(kr.RegistryInputError):
                kr.load_accepted_deviations(self.deviation_dir(**overrides))
        mismatched = kr.load_accepted_deviations(
            self.deviation_dir(
                scope={
                    "axis": "closure",
                    "gap_type": "helm-lock-policy",
                    "preconditions": [
                        {"field": "gap.evidence", "pattern": "^Chart\\.lock$"}
                    ],
                }
            )
        )
        merged = kr.merge_manifests([baseline], accepted_deviations=mismatched)
        self.assertIn(gap_id, merged["completeness"]["closure"]["blocking_gap_ids"])
        self.assertNotIn("accepted_deviation_ids", merged["completeness"]["closure"])
        lapsed = kr.load_accepted_deviations(
            self.deviation_dir(expires_at="2026-08-22")
        )
        merged = kr.merge_manifests([baseline], accepted_deviations=lapsed)
        self.assertIn(gap_id, merged["completeness"]["closure"]["blocking_gap_ids"])
        undated = copy.deepcopy(baseline)
        undated.pop("observation")
        undated = kr.seal_manifest(undated)
        merged = kr.merge_manifests(
            [undated],
            accepted_deviations=kr.load_accepted_deviations(self.deviation_dir()),
        )
        self.assertIn(gap_id, merged["completeness"]["closure"]["blocking_gap_ids"])

    def test_repository_accepted_deviations_are_ratified_and_bound(self) -> None:
        deviations = kr.load_accepted_deviations(
            (REPO_ROOT / "knowledge" / "registry" / "accepted-deviations").as_posix()
        )
        self.assertTrue(deviations)
        for deviation in deviations:
            self.assertEqual("accepted", deviation["record"]["review"]["status"])
            self.assertIn(
                deviation["record"]["scope"]["axis"], kr.ACCEPTED_DEVIATION_AXES
            )
            self.assertTrue(
                kr.ACCEPTED_DEVIATION_CITATION_RE.fullmatch(deviation["citation"])
            )

    def identity_wave(self) -> tuple[dict[str, Any], dict[str, Any], str, str]:
        builder, component, _version = self.gitops_builder()
        self.helm_lock_gap(builder)
        baseline = self.sealed(builder)
        receipts, _commit, _digest = self.commit_receipts(component)
        deviations = self.deviation_dir()
        fragment, _summary = kr.bind_gitops_identity(baseline, receipts)
        control = kr.merge_manifests([baseline])
        treatment = kr.merge_manifests(
            [baseline, fragment],
            accepted_deviations=kr.load_accepted_deviations(deviations),
        )
        return control, treatment, receipts, deviations

    def test_identity_gate_allows_a_deviation_ratified_before_the_wave(self) -> None:
        """A deviation ratified earlier belongs to the generation, not the wave."""

        control, treatment, receipts, deviations = self.identity_wave()
        builder, component, _version = self.gitops_builder()
        self.helm_lock_gap(builder)
        baseline = self.sealed(builder)
        both = kr.merge_manifests(
            [baseline], accepted_deviations=kr.load_accepted_deviations(deviations)
        )
        self.assertTrue(
            kr._axis_exempted_ids(both, "closure"),
            "control must carry the ratified exemption for this test to mean anything",
        )
        report = kr.identity_gate(
            both,
            treatment,
            receipts_dir=receipts,
            deviations=kr.load_accepted_deviations(deviations),
        )
        self.assertTrue(report["checks"]["deviations-ratified"]["pass"], report)
        self.assertEqual(component, component)

    def test_identity_gate_rejects_a_wave_that_drops_a_ratified_exemption(self) -> None:
        _control, treatment, receipts, deviations = self.identity_wave()
        self.assertTrue(kr._axis_exempted_ids(treatment, "closure"))
        stripped = copy.deepcopy(treatment)
        for gap in stripped["gaps"]:
            metadata = gap.get("metadata")
            if isinstance(metadata, dict):
                metadata.pop("accepted_deviation", None)
        stripped = kr.seal_manifest(stripped)
        self.assertEqual([], kr._axis_exempted_ids(stripped, "closure"))
        report = kr.identity_gate(
            treatment,
            stripped,
            receipts_dir=receipts,
            deviations=kr.load_accepted_deviations(deviations),
        )
        check = report["checks"]["deviations-ratified"]
        self.assertFalse(check["pass"])
        self.assertTrue(
            any(v.startswith("treatment drops exemption") for v in check["violations"]),
            check["violations"][:5],
        )

    def test_identity_gate_certifies_receipt_bound_and_ratified_movement(self) -> None:
        control, treatment, receipts, deviations = self.identity_wave()
        report = kr.identity_gate(
            control,
            treatment,
            receipts_dir=receipts,
            deviations=kr.load_accepted_deviations(deviations),
            anchor=control,
            expected_plan={
                "expected_closed_gap_types": {
                    "exact-version-unresolved": 1,
                    "gitops-self-reference": 1,
                },
                "expected_exempted_gap_types": {"helm-lock-policy": 1},
            },
        )
        self.assertTrue(report["pass"], report["checks"])
        checks = report["checks"]
        self.assertEqual(2, checks["gap-arithmetic-identity"]["closed"])
        self.assertEqual(
            {"receipt-bound-observation": 2},
            checks["gap-arithmetic-identity"]["explained_by"],
        )
        self.assertEqual(
            {"helm-lock-policy": 1},
            checks["deviations-ratified"]["exempted_by_gap_type"],
        )
        self.assertEqual(
            ["gitops-self-reference-observed"],
            checks["non-blocking-types-declared"]["new_gap_types"],
        )

    def test_identity_gate_rejects_closures_without_receipt_or_ratification(
        self,
    ) -> None:
        control, treatment, receipts, deviations = self.identity_wave()
        loaded = kr.load_accepted_deviations(deviations)
        forged = copy.deepcopy(control)
        closed = set(control["completeness"]["identity"]["blocking_gap_ids"])
        forged["gaps"] = [gap for gap in forged["gaps"] if gap["gap_id"] not in closed]
        forged = kr.seal_manifest(forged)
        report = kr.identity_gate(
            control, forged, receipts_dir=receipts, deviations=loaded
        )
        self.assertFalse(report["pass"])
        arithmetic = report["checks"]["gap-arithmetic-identity"]
        self.assertFalse(arithmetic["pass"])
        self.assertEqual(sorted(closed), sorted(arithmetic["unexplained_closures"]))

        unratified = copy.deepcopy(treatment)
        exempted = unratified["completeness"]["closure"]["accepted_deviation_ids"][0]
        for gap in unratified["gaps"]:
            if gap["gap_id"] == exempted:
                gap["metadata"][kr.ACCEPTED_DEVIATION_KEY]["declaration_sha256"] = (
                    "sha256:" + "0" * 64
                )
                gap["metadata"][kr.ACCEPTED_DEVIATION_KEY]["citation"] = (
                    "knowledge/registry/accepted-deviations/forged.json@sha256:"
                    + "0" * 64
                )
        unratified = kr.seal_manifest(unratified)
        report = kr.identity_gate(
            control, unratified, receipts_dir=receipts, deviations=loaded
        )
        self.assertFalse(report["pass"])
        self.assertFalse(report["checks"]["deviations-ratified"]["pass"])
        report = kr.identity_gate(control, treatment, receipts_dir=receipts)
        self.assertFalse(report["pass"])
        self.assertFalse(report["checks"]["deviations-ratified"]["pass"])

    def test_identity_gate_rejects_stale_reviewed_version_injection(self) -> None:
        stale = RegistryTest.reviewed_record()
        platformed = copy.deepcopy(stale)
        # Same record identity; only the re-derived version six-tuple moved.
        platformed["versions"][0]["platform"] = "linux/amd64"
        control = kr.reviewed_records_manifest([("platform.json", platformed)])
        treatment = kr.merge_manifests(
            [control, kr.reviewed_records_manifest([("stale.json", stale)])]
        )
        content = b"<html>unrelated</html>"
        row, digest = self.receipt_row(
            ["chn:policy:channel:pypi:v1:cmp-demo:package"],
            "https://pypi.org/project/demo/",
            content,
        )
        receipts = self.write_receipts([row], {digest: content})
        report = kr.identity_gate(control, treatment, receipts_dir=receipts)
        self.assertFalse(report["pass"])
        stale_check = report["checks"]["reviewed-version-generation"]
        self.assertFalse(stale_check["pass"])
        self.assertEqual(
            sorted(
                {item["component_version_id"] for item in treatment["versions"]}
                - {item["component_version_id"] for item in control["versions"]}
            ),
            stale_check["stale_reviewed_version_ids"],
        )
        self.assertTrue(
            kr.identity_gate(control, control, receipts_dir=receipts)["checks"][
                "reviewed-version-generation"
            ]["pass"]
        )

    def test_official_channel_state_grain_change_closes_no_identity_gap(self) -> None:
        treatment = kr.reviewed_records_manifest(
            [("demo.json", ChannelClosureW0Test.multi_state_record())]
        )
        # The control is the same generation at the retired one-row-per-slot grain.
        control = ChannelClosureW0Test.per_slot_manifest(treatment)
        control_rows = [
            gap
            for gap in control["gaps"]
            if gap["gap_type"] == "official-channel-state"
        ]
        treatment_rows = [
            gap
            for gap in treatment["gaps"]
            if gap["gap_type"] == "official-channel-state"
        ]
        self.assertEqual(12, len(control_rows))
        self.assertEqual(1, len(treatment_rows))
        receipts = self.write_receipts([], {})
        report = kr.identity_gate(control, treatment, receipts_dir=receipts)
        arithmetic = report["checks"]["gap-arithmetic-identity"]
        self.assertEqual([], arithmetic["unexplained_closures"])
        self.assertEqual([], arithmetic["opened_gap_ids"])
        self.assertEqual(0, arithmetic["closed"])
        self.assertNotIn("official-channel-state", arithmetic["closed_by_gap_type"])
        self.assertTrue(arithmetic["pass"], arithmetic)
        declared = report["checks"]["non-blocking-types-declared"]
        # Same gap_type string on both sides: the wave declares no new type.
        self.assertEqual([], declared["new_gap_types"])
        self.assertTrue(declared["pass"], declared)
        self.assertEqual(
            report["checks"]["closure-delta-evidenced"]["unexplained_closures"], []
        )
        self.assertTrue(report["checks"]["axis-isolation"]["pass"])
        self.assertTrue(report["pass"], report)


class OciIdentityWaveR4Test(unittest.TestCase):
    REPOSITORY = "ghcr.io/example-org/demo"
    TAG = "v1.2.3"
    OBSERVATION = {
        "observed_at": "2026-08-23T13:15:08Z",
        "source_valid_at": "2026-08-23T13:14:54Z",
        "source_valid_time_basis": "git-commit-committer-time",
    }
    CHILD_AMD64 = "sha256:" + "a" * 64
    CHILD_ARM64 = "sha256:" + "b" * 64
    CHILD_ARM64_ALT = "sha256:" + "c" * 64
    ATTESTATION = "sha256:" + "d" * 64
    UNKNOWN = "sha256:" + "e" * 64

    write_receipts = ChannelSnapshotR3Test.write_receipts
    receipt_row = staticmethod(ChannelSnapshotR3Test.receipt_row)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    @classmethod
    def index_bytes(cls) -> bytes:
        entry = "application/vnd.oci.image.manifest.v1+json"
        return json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": entry,
                        "digest": cls.CHILD_AMD64,
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "mediaType": entry,
                        "digest": cls.ATTESTATION,
                        "platform": {"os": "unknown", "architecture": "unknown"},
                        "annotations": {
                            "vnd.docker.reference.type": "attestation-manifest"
                        },
                    },
                    {
                        "mediaType": entry,
                        "digest": cls.CHILD_ARM64,
                        "platform": {
                            "os": "linux",
                            "architecture": "arm64",
                            "variant": "v8",
                        },
                    },
                    {
                        "mediaType": entry,
                        "digest": cls.UNKNOWN,
                        "platform": {"os": "unknown", "architecture": "unknown"},
                    },
                    {
                        "mediaType": entry,
                        "digest": cls.CHILD_ARM64_ALT,
                        "platform": {
                            "os": "linux",
                            "architecture": "arm64",
                            "variant": "v8",
                        },
                    },
                ],
            },
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def image_bytes(config_digest: str) -> bytes:
        return json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest,
                    "size": 42,
                },
                "layers": [],
            },
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def config_bytes(**overrides: Any) -> bytes:
        payload: dict[str, Any] = {"os": "linux", "architecture": "amd64"}
        payload.update(overrides)
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def oci_builder(
        self, *, observation: dict[str, Any] | None = None, digest: str | None = None
    ) -> tuple[kr.Builder, str, str]:
        builder = kr.Builder()
        source = builder.add_source(
            "apps/demo/values.yaml", "helm-values", content_hash="sha256:" + "3" * 64
        )
        image = (
            f"{self.REPOSITORY}@{digest}" if digest else f"{self.REPOSITORY}:{self.TAG}"
        )
        component, version, _occurrence = builder.add_image(
            image, source, "line:4:image", "container-image"
        )
        if observation is not None:
            builder.versions[version]["metadata"] = {
                kr.OCI_OBSERVATION_KEY: observation
            }
        return builder, component, version

    def observation(
        self, data: bytes, *, digest: str | None = None, **overrides: Any
    ) -> dict[str, Any]:
        identity = kr.oci_manifest_identity(data)
        content_hash = kr.file_hash(data)
        reference = digest or self.TAG
        observation: dict[str, Any] = {
            "evidence_cas_path": (
                f"cas/sha256/{content_hash[7:9]}/{content_hash.removeprefix('sha256:')}"
            ),
            "evidence_content_hash": content_hash,
            "manifest_kind": identity["kind"],
            "manifest_media_type": identity["manifest_media_type"],
            "observed_at": "2026-08-23T15:54:14Z",
            "platforms": identity["platforms"] or ["linux/amd64"],
            "receipt_canonical_uri": kr.oci_canonical_uri(
                "ghcr.io", "example-org/demo", reference, "digest" if digest else "tag"
            ),
            "reference": reference,
            "reference_kind": "digest" if digest else "tag",
            "registry": "ghcr.io",
            "repository": "example-org/demo",
            "resolved_digest": content_hash,
            "resolver": "oci-registry-manifest",
        }
        if identity["kind"] == "manifest":
            observation["platform"] = "linux/amd64"
        observation.update(overrides)
        return observation

    def sealed(self, builder: kr.Builder) -> dict[str, Any]:
        manifest = builder.manifest()
        manifest["observation"] = dict(self.OBSERVATION)
        return kr.seal_manifest(manifest)

    def oci_receipts(
        self, *, image: bool = False, corrupt_cas: bool = False, **row_overrides: Any
    ) -> tuple[str, str, str]:
        """Write one registry-manifest receipt for the tag-addressed demo image."""

        builder, _component, version = self.oci_builder()
        config = self.config_bytes()
        config_digest = kr.file_hash(config)
        data = self.image_bytes(config_digest) if image else self.index_bytes()
        identity = kr.oci_manifest_identity(data)
        content_hash = kr.file_hash(data)
        blobs = {content_hash.removeprefix("sha256:"): data}
        coordinates: dict[str, Any] = {
            "registry": "ghcr.io",
            "repository": "example-org/demo",
            "reference": self.TAG,
            "reference_kind": "tag",
            "resolved_digest": content_hash,
            "kind": identity["kind"],
            "children": identity["children"],
            "excluded": identity["excluded"],
            "platforms": identity["platforms"],
            "component_version_ids": [version],
        }
        if image:
            coordinates["platforms"] = ["linux/amd64"]
            coordinates["config_content_hash"] = config_digest
            coordinates["config_cas_path"] = (
                f"cas/sha256/{config_digest[7:9]}/"
                f"{config_digest.removeprefix('sha256:')}"
            )
            blobs[config_digest.removeprefix("sha256:")] = config
        row, _digest = self.receipt_row(
            [version],
            kr.oci_canonical_uri("ghcr.io", "example-org/demo", self.TAG, "tag"),
            data,
            media_type=identity["manifest_media_type"],
            status="verified",
            upstream_ref=content_hash,
            coordinates={"oci": coordinates},
        )
        row.update(row_overrides)
        if corrupt_cas:
            blobs[content_hash.removeprefix("sha256:")] = data + b"tampered"
        return self.write_receipts([row], blobs), version, content_hash

    def test_index_identity_excludes_attestation_and_unknown_entries(self) -> None:
        identity = kr.oci_manifest_identity(self.index_bytes())
        self.assertEqual("index", identity["kind"])
        self.assertEqual(["linux/amd64", "linux/arm64/v8"], identity["platforms"])
        self.assertEqual(
            [
                (self.CHILD_AMD64, "linux/amd64"),
                (self.CHILD_ARM64, "linux/arm64/v8"),
                (self.CHILD_ARM64_ALT, "linux/arm64/v8"),
            ],
            [(item["digest"], item["platform"]) for item in identity["children"]],
        )
        self.assertEqual(
            [
                {"digest": self.ATTESTATION, "reason": "attestation"},
                {"digest": self.UNKNOWN, "reason": "unknown-platform"},
            ],
            identity["excluded"],
        )
        self.assertIsNone(kr.oci_config_platform(self.config_bytes(os="unknown")))
        self.assertEqual(
            "linux/amd64/v3",
            kr.oci_config_platform(self.config_bytes(variant="v3")),
        )

    def test_new_observation_types_stay_out_of_both_axes(self) -> None:
        for gap_type in (
            "oci-artifact-version-observed",
            "oci-platform-index",
            "oci-platform-observed",
        ):
            self.assertIn(gap_type, kr.OBSERVED_IDENTITY_GAP_TYPES)
            self.assertIn(gap_type, kr.MERGE_REDERIVED_GAP_TYPES)
            self.assertNotIn(gap_type, kr.IDENTITY_GAP_TYPES)
            self.assertNotIn(gap_type, kr.CLOSURE_GAP_TYPES)
        self.assertIn("oci-platform-unresolved", kr.IDENTITY_GAP_TYPES)
        self.assertIn("exact-version-unresolved", kr.IDENTITY_GAP_TYPES)
        self.assertNotIn("oci-platform-multi", kr.MERGE_REDERIVED_GAP_TYPES)

    def test_index_observation_types_the_platform_without_a_multi_platform_gap(
        self,
    ) -> None:
        builder, _component, version = self.oci_builder()
        blocked = builder.manifest()
        self.assertEqual(
            {"exact-version-unresolved", "oci-platform-unresolved"},
            {
                gap["gap_type"]
                for gap in blocked["gaps"]
                if gap.get("component_version_id") == version
            },
        )
        data = self.index_bytes()
        builder, _component, version = self.oci_builder(
            observation=self.observation(data)
        )
        resolved = builder.manifest()
        self.assertEqual(
            {"oci-artifact-version-observed", "oci-platform-index"},
            {
                gap["gap_type"]
                for gap in resolved["gaps"]
                if gap.get("component_version_id") == version
            },
        )
        self.assertEqual([], resolved["completeness"]["identity"]["blocking_gap_ids"])
        self.assertEqual(
            [],
            [
                gap
                for gap in resolved["gaps"]
                if gap["gap_type"] in {"oci-platform-multi", "oci-tag-digest-conflict"}
            ],
        )
        indexed = next(
            gap for gap in resolved["gaps"] if gap["gap_type"] == "oci-platform-index"
        )
        self.assertIn("linux/arm64/v8", indexed["message"])
        self.assertIn(kr.file_hash(data), indexed["evidence"])
        self.assertEqual(
            "unresolved",
            next(
                item
                for item in resolved["versions"]
                if item["component_version_id"] == version
            )["resolution_state"],
        )

    def test_single_manifest_observation_carries_the_exact_config_platform(
        self,
    ) -> None:
        config_digest = kr.file_hash(self.config_bytes())
        data = self.image_bytes(config_digest)
        builder, _component, version = self.oci_builder(
            observation=self.observation(data)
        )
        resolved = builder.manifest()
        self.assertEqual(
            {"oci-artifact-version-observed", "oci-platform-observed"},
            {
                gap["gap_type"]
                for gap in resolved["gaps"]
                if gap.get("component_version_id") == version
            },
        )
        self.assertEqual([], resolved["completeness"]["identity"]["blocking_gap_ids"])
        observed = next(
            gap
            for gap in resolved["gaps"]
            if gap["gap_type"] == "oci-platform-observed"
        )
        self.assertIn("linux/amd64", observed["message"])

    def test_tampered_observations_restore_both_blocking_gaps(self) -> None:
        data = self.index_bytes()
        blocking = {"exact-version-unresolved", "oci-platform-unresolved"}
        for tamper in (
            {"resolver": "operator-assertion"},
            {"registry": "docker.io"},
            {"repository": "example-org/other"},
            {"reference": "v9.9.9"},
            {"reference_kind": "digest"},
            {"manifest_kind": "manifest"},
            {"manifest_media_type": "text/html"},
            {"platforms": ["unknown/unknown"]},
            {"platforms": []},
            {"platforms": ["linux/arm64/v8", "linux/amd64"]},
            {"platform": "linux/amd64"},
            {"observed_at": "2026-08-23"},
            {"resolved_digest": "sha256:" + "f" * 64},
            {"evidence_content_hash": "sha256:not-a-hash"},
        ):
            builder, _component, version = self.oci_builder(
                observation=self.observation(data, **tamper)
            )
            self.assertEqual(
                blocking,
                {
                    gap["gap_type"]
                    for gap in builder.manifest()["gaps"]
                    if gap.get("component_version_id") == version
                },
                tamper,
            )

    def test_bind_oci_identity_reproduces_ids_and_survives_merge(self) -> None:
        builder, component, version = self.oci_builder()
        baseline = self.sealed(builder)
        plan, unfetchable = kr.oci_identity_plan(baseline)
        self.assertEqual([], unfetchable)
        self.assertEqual(
            [
                {
                    "canonical_uri": "oci://ghcr.io/example-org/demo:v1.2.3",
                    "component_version_ids": [version],
                    "reference": self.TAG,
                    "reference_kind": "tag",
                    "registry": "ghcr.io",
                    "repository": "example-org/demo",
                }
            ],
            plan,
        )
        receipts, _version, content_hash = self.oci_receipts()
        fragment, summary = kr.bind_oci_identity(baseline, receipts)
        self.assertEqual(1, summary["versions_bound"])
        self.assertEqual(1, summary["components_bound"])
        self.assertEqual(0, summary["receipts_refused"])
        self.assertEqual(0, summary["receipts_typed_failures"])
        self.assertEqual([], summary["planned_refs_unreceipted"])
        merged = kr.merge_manifests([baseline, fragment])
        self.assertEqual([], kr.validate_manifest(merged))
        self.assertEqual(
            {item["component_version_id"] for item in baseline["versions"]},
            {item["component_version_id"] for item in merged["versions"]},
        )
        self.assertEqual(
            {item["component_id"] for item in baseline["components"]},
            {item["component_id"] for item in merged["components"]},
        )
        self.assertEqual(
            {"oci-artifact-version-observed", "oci-platform-index"},
            {
                gap["gap_type"]
                for gap in merged["gaps"]
                if gap.get("component_version_id") == version
            },
        )
        self.assertEqual([], merged["completeness"]["identity"]["blocking_gap_ids"])
        bound = next(
            item
            for item in merged["versions"]
            if item["component_version_id"] == version
        )
        self.assertEqual("unresolved", bound["resolution_state"])
        self.assertEqual(
            content_hash,
            bound["metadata"][kr.OCI_OBSERVATION_KEY]["evidence_content_hash"],
        )
        self.assertEqual(component, bound["component_id"])

    def test_bind_oci_identity_fails_closed_on_unverifiable_receipts(self) -> None:
        builder, _component, _version = self.oci_builder()
        baseline = self.sealed(builder)
        corrupted, _version, _hash = self.oci_receipts(corrupt_cas=True)
        _fragment, summary = kr.bind_oci_identity(baseline, corrupted)
        self.assertEqual(0, summary["versions_bound"])
        self.assertEqual(1, summary["receipts_refused"])
        self.assertIn(
            "CAS artifact hash does not match",
            summary["refused_receipts"][0]["reason"],
        )
        forged, _version, _hash = self.oci_receipts(
            coordinates={
                "oci": {
                    "registry": "ghcr.io",
                    "repository": "example-org/demo",
                    "reference": self.TAG,
                    "reference_kind": "tag",
                    "resolved_digest": "sha256:" + "9" * 64,
                    "kind": "index",
                    "children": [],
                    "excluded": [],
                    "platforms": ["linux/amd64"],
                    "component_version_ids": [],
                }
            }
        )
        _fragment, summary = kr.bind_oci_identity(baseline, forged)
        self.assertEqual(0, summary["versions_bound"])
        self.assertIn(
            "CAS bytes are not the claimed OCI manifest digest",
            summary["refused_receipts"][0]["reason"],
        )
        withdrawn, _version, _hash = self.oci_receipts(
            status="fetch-failed",
            error_state="manifest-unknown",
            http_status=404,
            content_hash=None,
            cas_path=None,
            media_type=None,
        )
        fragment, summary = kr.bind_oci_identity(baseline, withdrawn)
        self.assertEqual(0, summary["versions_bound"])
        self.assertEqual(1, summary["receipts_typed_failures"])
        self.assertEqual(0, summary["receipts_refused"])
        self.assertEqual(
            "manifest-unknown", summary["typed_failures"][0]["error_state"]
        )
        merged = kr.merge_manifests([baseline, fragment])
        self.assertEqual(2, len(merged["completeness"]["identity"]["blocking_gap_ids"]))

    def test_reviewed_resolution_state_still_hard_conflicts_on_merge(self) -> None:
        builder, _component, version = self.oci_builder()
        baseline = self.sealed(builder)
        receipts, _version, _hash = self.oci_receipts()
        fragment, _summary = kr.bind_oci_identity(baseline, receipts)
        # G4: versions.metadata is additive, so the observation merges in.
        self.assertEqual(
            [], kr.validate_manifest(kr.merge_manifests([baseline, fragment]))
        )
        conflicting = copy.deepcopy(fragment)
        for item in conflicting["versions"]:
            if item["component_version_id"] == version:
                item["resolution_state"] = "ambiguous"
        conflicting = kr.seal_manifest(conflicting)
        # G3: a differing bare scalar on the same version id stays a hard conflict.
        with self.assertRaisesRegex(kr.RegistryInputError, "merge conflict"):
            kr.merge_manifests([baseline, conflicting])

    def sbom_builder(
        self, *, edges: bool = True, digest: str | None = None
    ) -> tuple[kr.Builder, str]:
        builder = kr.Builder()
        source = builder.add_source(
            "live/sboms.json", "sbom-report", content_hash="sha256:" + "4" * 64
        )
        subject = digest or "sha256:" + "7" * 64
        component, version, _occurrence = builder.add_image(
            f"{self.REPOSITORY}@{subject}" if digest is not False else self.REPOSITORY,
            source,
            "/items/0/report/artifact",
            "live-sbom-artifact",
            platform="linux/amd64",
            lifecycle="sbom-observed",
            metadata={"report_kind": "SbomReport", "report_namespace": "demo"},
        )
        library = builder.add_component(
            kind="library", ecosystem="deb", name="zlib1g", purl="pkg:deb/debian/zlib1g"
        )
        library_version = builder.add_version(library, resolved_version="1.3.dfsg-3")
        occurrence = builder.add_occurrence(
            library,
            library_version,
            source,
            locator="/items/0/report/components/0",
            role="sbom-component",
            raw_value="pkg:deb/debian/zlib1g@1.3.dfsg-3",
            root_id=component,
            directness="direct",
            lifecycle="runtime-resolved",
        )
        if edges:
            builder.add_edge(
                version,
                library_version,
                relationship="contains",
                source_occurrence_id=occurrence,
                resolver="cyclonedx-sbom",
            )
        for item in builder.occurrences.values():
            if item["role"] == "live-sbom-artifact":
                # reconcile_live_sboms erases sbom-observed on every live capture.
                item["lifecycle"] = "orphaned"
        return builder, component

    def test_imported_sbom_subject_clears_its_own_transitive_inventory(self) -> None:
        builder, component = self.sbom_builder()
        manifest = builder.manifest()
        self.assertEqual(
            [],
            [
                gap
                for gap in manifest["gaps"]
                if gap["gap_type"] == "transitive-inventory-unavailable"
            ],
        )
        self.assertEqual([], manifest["completeness"]["closure"]["blocking_gap_ids"])
        self.assertEqual({component}, builder.sbom_inventory_subjects())

    def test_transitive_inventory_needs_a_digest_and_enumerated_contents(self) -> None:
        builder, component = self.sbom_builder(edges=False)
        manifest = builder.manifest()
        self.assertEqual(
            [component],
            [
                gap["component_id"]
                for gap in manifest["gaps"]
                if gap["gap_type"] == "transitive-inventory-unavailable"
            ],
        )
        builder, component = self.sbom_builder(digest=False)
        manifest = builder.manifest()
        self.assertIn(
            component,
            {
                gap["component_id"]
                for gap in manifest["gaps"]
                if gap["gap_type"] == "transitive-inventory-unavailable"
            },
        )

    def oci_wave(self) -> tuple[dict[str, Any], dict[str, Any], str]:
        builder, _component, _version = self.oci_builder()
        baseline = self.sealed(builder)
        receipts, _version, _hash = self.oci_receipts()
        fragment, _summary = kr.bind_oci_identity(baseline, receipts)
        return (
            kr.merge_manifests([baseline]),
            kr.merge_manifests([baseline, fragment]),
            receipts,
        )

    def test_identity_gate_certifies_the_receipt_bound_oci_wave(self) -> None:
        control, treatment, receipts = self.oci_wave()
        report = kr.identity_gate(
            control,
            treatment,
            receipts_dir=receipts,
            anchor=control,
            expected_plan={
                "expected_closed_gap_types": {
                    "exact-version-unresolved": 1,
                    "oci-platform-unresolved": 1,
                }
            },
        )
        self.assertTrue(report["pass"], report["checks"])
        checks = report["checks"]
        self.assertEqual(
            {"receipt-bound-oci-manifest": 2},
            checks["gap-arithmetic-identity"]["explained_by"],
        )
        self.assertEqual(
            0, checks["gap-arithmetic-identity"]["treatment_identity_blocking"]
        )
        self.assertEqual(1, checks["receipt-coverage"]["oci_planned_refs"])
        self.assertEqual([], checks["receipt-coverage"]["oci_unreceipted_refs"])
        self.assertEqual([], checks["receipt-coverage"]["oci_unused_receipt_refs"])
        self.assertEqual(
            ["oci-artifact-version-observed", "oci-platform-index"],
            checks["non-blocking-types-declared"]["new_gap_types"],
        )
        self.assertEqual(0, checks["platform-multi-zero"]["treatment"])
        self.assertTrue(checks["no-unknown-platform"]["pass"])
        self.assertEqual(
            [], checks["version-delta-justified"]["undeclared_new_version_ids"]
        )

    def test_identity_gate_ignores_receipts_another_wave_planned(self) -> None:
        """Receipts accumulate across waves; scope consumption to this one."""

        control, treatment, receipts = self.oci_wave()
        foreign = Path(receipts) / "receipts" / "receipts-foreign.jsonl"
        commit, content = IdentityWaveR4Test.commit_object("another wave")
        row, digest = self.receipt_row(
            ["chn:policy:channel:git-self:v1:cmp-other:source"],
            "https://github.com/example-org/k8s",
            content,
            media_type="application/x-git-commit",
            status="verified",
            http_status=None,
            upstream_ref=commit,
        )
        foreign.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        cas = Path(receipts) / "cas" / "sha256" / digest[:2] / digest
        cas.parent.mkdir(parents=True, exist_ok=True)
        cas.write_bytes(content)
        report = kr.identity_gate(
            control,
            treatment,
            receipts_dir=receipts,
            anchor=control,
            expected_plan={
                "expected_closed_gap_types": {
                    "exact-version-unresolved": 1,
                    "oci-platform-unresolved": 1,
                }
            },
        )
        self.assertTrue(report["pass"], report["checks"])
        self.assertEqual(
            [], report["checks"]["receipt-coverage"]["unused_receipt_hashes"]
        )

    def _append_oci_receipt(
        self, receipts: str, data: bytes, *, filename: str, observed_at: str
    ) -> None:
        """Write one more verified receipt for the demo tag into an existing tree."""

        identity = kr.oci_manifest_identity(data)
        content_hash = kr.file_hash(data)
        row, digest = self.receipt_row(
            [self.oci_builder()[2]],
            kr.oci_canonical_uri("ghcr.io", "example-org/demo", self.TAG, "tag"),
            data,
            media_type=identity["manifest_media_type"],
            status="verified",
            upstream_ref=content_hash,
            coordinates={
                "oci": {
                    "registry": "ghcr.io",
                    "repository": "example-org/demo",
                    "reference": self.TAG,
                    "reference_kind": "tag",
                    "resolved_digest": content_hash,
                    "kind": identity["kind"],
                    "children": identity["children"],
                    "excluded": identity["excluded"],
                    "platforms": identity["platforms"],
                    "component_version_ids": [self.oci_builder()[2]],
                }
            },
        )
        row["fetched_at"] = observed_at
        row["observed_at"] = observed_at
        root = Path(receipts)
        (root / "receipts" / filename).write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
        cas = root / "cas" / "sha256" / digest[:2] / digest
        cas.parent.mkdir(parents=True, exist_ok=True)
        cas.write_bytes(data)

    def _narrow_index_bytes(self) -> bytes:
        """The demo index with only its amd64 child - a different manifest."""

        document = json.loads(self.index_bytes())
        document["manifests"] = [
            m for m in document["manifests"] if m["digest"] == self.CHILD_AMD64
        ]
        return json.dumps(document, sort_keys=True).encode()

    def test_bind_oci_identity_refuses_receipts_that_disagree_on_identity(self) -> None:
        """A tag that moved between runs is not one identity."""

        builder, _component, _version = self.oci_builder()
        baseline = self.sealed(builder)
        receipts, _v, _h = self.oci_receipts()
        self._append_oci_receipt(
            receipts,
            self._narrow_index_bytes(),
            filename="receipts-test2.jsonl",
            observed_at="2026-08-22T13:00:00Z",
        )
        verified, _typed, refused = kr.oci_artifact_receipts(receipts)
        self.assertEqual([], refused)
        self.assertEqual(2, len(verified), "both rows must verify on their own bytes")
        with self.assertRaises(kr.RegistryInputError) as caught:
            kr.bind_oci_identity(baseline, receipts)
        self.assertIn("disagree on the identity", str(caught.exception))

    def test_bind_oci_identity_never_fuses_two_receipts_into_one_record(self) -> None:
        """Identical identity, two timestamps: bind one receipt, invent nothing."""

        builder, _component, _version = self.oci_builder()
        baseline = self.sealed(builder)
        receipts, _v, _h = self.oci_receipts()
        self._append_oci_receipt(
            receipts,
            self.index_bytes(),
            filename="receipts-test2.jsonl",
            observed_at="2026-08-22T13:00:00Z",
        )
        verified, _typed, _refused = kr.oci_artifact_receipts(receipts)
        self.assertEqual(2, len(verified))
        fragment, summary = kr.bind_oci_identity(baseline, receipts)
        self.assertEqual([], kr.validate_manifest(fragment))
        bound = [
            kr.version_metadata_entry(item, kr.OCI_OBSERVATION_KEY)
            for item in fragment["versions"]
        ]
        bound = [b for b in bound if b]
        self.assertEqual(1, len(bound))
        observation = dict(bound[0])
        # The record must BE a receipt, not a merge of several.
        self.assertTrue(
            any(observation == dict(r["observation"]) for r in verified),
            observation,
        )
        # Newest evidence wins, deliberately - not min() by accident.
        self.assertEqual("2026-08-22T13:00:00Z", observation["observed_at"])
        self.assertEqual(1, summary["versions_bound"])

    def test_oci_platform_segments_never_slide_into_earlier_positions(self) -> None:
        """os and architecture are required; a gap must not promote variant."""

        self.assertEqual(
            "linux/amd64",
            kr.oci_config_platform(b'{"os":"linux","architecture":"amd64"}'),
        )
        self.assertEqual(
            "linux/arm64/v8",
            kr.oci_config_platform(
                b'{"os":"linux","architecture":"arm64","variant":"v8"}'
            ),
        )
        for document in (
            {"os": "linux", "variant": "amd64"},
            {"os": "linux", "architecture": "", "variant": "v8"},
            {"architecture": "amd64", "variant": "v3"},
        ):
            self.assertIsNone(
                kr.oci_config_platform(json.dumps(document).encode()), document
            )

    def test_oci_index_child_without_os_is_excluded_not_slid(self) -> None:
        document = json.loads(self.index_bytes())
        document["manifests"] = [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": self.CHILD_AMD64,
                "platform": {"architecture": "amd64", "variant": "v3"},
            }
        ]
        identity = kr.oci_manifest_identity(json.dumps(document).encode())
        self.assertEqual([], identity["platforms"])
        self.assertEqual([], identity["children"])
        self.assertEqual(
            [{"digest": self.CHILD_AMD64, "reason": "platform-unexpressible"}],
            identity["excluded"],
        )

    def test_single_manifest_receipt_binds_through_the_config_blob(self) -> None:
        """The image path derives its platform from the config blob, not an index."""

        builder, _component, _version = self.oci_builder()
        baseline = self.sealed(builder)
        receipts, _v, _h = self.oci_receipts(image=True)
        verified, typed, refused = kr.oci_artifact_receipts(receipts)
        self.assertEqual(([], []), (typed, refused))
        self.assertEqual(1, len(verified))
        observation = verified[0]["observation"]
        self.assertEqual("manifest", observation["manifest_kind"])
        self.assertEqual(["linux/amd64"], observation["platforms"])
        self.assertEqual("linux/amd64", observation.get("platform"))
        fragment, summary = kr.bind_oci_identity(baseline, receipts)
        self.assertEqual([], kr.validate_manifest(fragment))
        self.assertEqual(1, summary["versions_bound"])

    def test_single_manifest_receipt_refuses_a_tampered_config_blob(self) -> None:
        """CAS bytes that are not the config the manifest names bind nothing."""

        receipts, _v, _h = self.oci_receipts(image=True)
        config = self.config_bytes()
        digest = kr.file_hash(config).removeprefix("sha256:")
        blob = Path(receipts) / "cas" / "sha256" / digest[:2] / digest
        self.assertTrue(blob.exists(), "image receipts must store a config blob")
        blob.write_bytes(config + b"tampered")
        verified, _typed, refused = kr.oci_artifact_receipts(receipts)
        self.assertEqual([], verified)
        self.assertEqual(1, len(refused))
        self.assertIn("config", refused[0]["reason"].lower())

    def test_identity_gate_certifies_a_resumed_wave_reverifying_one_ref(
        self,
    ) -> None:
        """A resumed run re-verifies refs an earlier run already wrote."""

        control, treatment, receipts = self.oci_wave()
        source = Path(receipts) / "receipts" / "receipts-test.jsonl"
        resumed = []
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            row = json.loads(line)
            row["fetched_at"] = "2026-08-22T12:01:00Z"
            row["observed_at"] = "2026-08-22T12:01:00Z"
            resumed.append(row)
        self.assertTrue(resumed)
        later = source.parent / "receipts-test2.jsonl"
        later.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in resumed),
            encoding="utf-8",
        )
        # Receipts load in sorted filename order; the resumed row must sort last
        # or a one-per-ref map keeps the bound row and this test goes vacuous.
        self.assertEqual(
            [source.name, later.name],
            sorted(item.name for item in source.parent.iterdir()),
        )
        report = kr.identity_gate(
            control,
            treatment,
            receipts_dir=receipts,
            anchor=control,
            expected_plan={
                "expected_closed_gap_types": {
                    "exact-version-unresolved": 1,
                    "oci-platform-unresolved": 1,
                }
            },
        )
        self.assertTrue(report["pass"], report["checks"])
        checks = report["checks"]
        self.assertEqual([], checks["gap-arithmetic-identity"]["unexplained_closures"])
        self.assertEqual(
            {"receipt-bound-oci-manifest": 2},
            checks["gap-arithmetic-identity"]["explained_by"],
        )
        self.assertEqual([], checks["receipt-coverage"]["oci_unused_receipt_refs"])

    def test_identity_gate_rejects_oci_closures_without_a_verified_receipt(
        self,
    ) -> None:
        control, treatment, receipts = self.oci_wave()
        forged = copy.deepcopy(control)
        closed = set(control["completeness"]["identity"]["blocking_gap_ids"])
        forged["gaps"] = [gap for gap in forged["gaps"] if gap["gap_id"] not in closed]
        forged = kr.seal_manifest(forged)
        report = kr.identity_gate(control, forged, receipts_dir=receipts)
        self.assertFalse(report["pass"])
        self.assertEqual(
            sorted(closed),
            sorted(report["checks"]["gap-arithmetic-identity"]["unexplained_closures"]),
        )
        self.assertFalse(report["checks"]["receipt-coverage"]["pass"])
        self.assertEqual(
            ["oci://ghcr.io/example-org/demo:v1.2.3"],
            report["checks"]["receipt-coverage"]["oci_unused_receipt_refs"],
        )
        tampered = copy.deepcopy(treatment)
        for item in tampered["versions"]:
            observation = (item.get("metadata") or {}).get(kr.OCI_OBSERVATION_KEY)
            if observation:
                observation["platforms"] = [
                    "unknown/unknown",
                    *observation["platforms"],
                ]
        tampered = kr.seal_manifest(tampered)
        report = kr.identity_gate(control, tampered, receipts_dir=receipts)
        self.assertFalse(report["pass"])
        self.assertFalse(report["checks"]["no-unknown-platform"]["pass"])

    def test_identity_gate_requires_evidence_for_a_closed_transitive_gap(self) -> None:
        builder, component = self.sbom_builder(edges=False)
        control = kr.merge_manifests([self.sealed(builder)])
        builder, _component = self.sbom_builder()
        treatment = kr.merge_manifests([self.sealed(builder)])
        receipts, _version, _hash = self.oci_receipts()
        report = kr.identity_gate(control, treatment, receipts_dir=receipts)
        closure = report["checks"]["closure-delta-evidenced"]
        self.assertTrue(closure["pass"], closure)
        self.assertEqual(
            {"transitive-inventory-unavailable": 1}, closure["closed_by_gap_type"]
        )
        self.assertEqual(1, closure["sbom_inventory_subjects"])
        stripped = copy.deepcopy(treatment)
        stripped["dependency_edges"] = []
        stripped["gaps"] = [
            gap
            for gap in stripped["gaps"]
            if gap["gap_type"] != "transitive-inventory-unavailable"
        ]
        stripped["completeness"]["closure"]["blocking_gap_ids"] = []
        stripped = kr.seal_manifest(stripped)
        report = kr.identity_gate(control, stripped, receipts_dir=receipts)
        self.assertFalse(report["checks"]["closure-delta-evidenced"]["pass"])
        self.assertEqual(
            [
                gap["gap_id"]
                for gap in control["gaps"]
                if gap["gap_type"] == "transitive-inventory-unavailable"
                and gap["component_id"] == component
            ],
            report["checks"]["closure-delta-evidenced"]["unexplained_closures"],
        )


class KillProcessGroupTest(unittest.TestCase):
    """kill_process_group never sends a group signal to 1 or less or to its own group (cordanaLLM/knowledge#2)."""

    def _run(self, pid: object, killpg_error: BaseException | None = None) -> tuple[list[tuple[object, int]], mock.Mock]:
        sent: list[tuple[object, int]] = []

        def killpg(group: object, number: int) -> None:
            sent.append((group, number))
            if killpg_error is not None:
                raise killpg_error

        process = mock.Mock(pid=pid)
        with mock.patch.object(kr.os, "killpg", side_effect=killpg):
            kr.kill_process_group(process)
        return sent, process

    def test_refused_groups_are_never_signalled_and_the_child_is_killed_alone(self) -> None:
        for pid in (-1, 0, 1, True, "7", os.getpgrp(), mock.MagicMock().pid):
            with self.subTest(pid=pid):
                sent, process = self._run(pid)
                self.assertEqual(sent, [])
                process.kill.assert_called_once_with()

    def test_a_child_group_above_one_is_killed_as_a_group(self) -> None:
        group = os.getpgrp() + 1 if os.getpgrp() > 1 else 2
        sent, process = self._run(group)
        self.assertEqual(sent, [(group, kr.signal.SIGKILL)])
        process.kill.assert_not_called()

    def test_a_vanished_group_is_fine_and_a_refused_one_kills_the_child(self) -> None:
        group = os.getpgrp() + 1 if os.getpgrp() > 1 else 2
        _sent, process = self._run(group, ProcessLookupError())
        process.kill.assert_not_called()
        _sent, process = self._run(group, PermissionError())
        process.kill.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
