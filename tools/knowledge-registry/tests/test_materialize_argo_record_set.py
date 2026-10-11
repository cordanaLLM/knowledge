from __future__ import annotations

import importlib.util
import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools/knowledge-registry/materialize_argo_record_set.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "materialize_argo_record_set", MODULE_PATH
)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError("could not load Argo record-set materializer")
materializer = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(materializer)


CHANNEL_TYPES = (
    "advisory",
    "api",
    "artifact",
    "changelog",
    "config",
    "deprecation",
    "docs",
    "license",
    "migration",
    "package",
    "provenance",
    "reference",
    "release",
    "sbom",
    "schema",
    "source",
)


def candidate_channel(chart: str, channel_type: str) -> dict[str, object]:
    return {
        "authority_state": "non-authoritative",
        "availability_state": "unresolved",
        "channel_id": f"chn-test-{chart}-{channel_type}",
        "channel_type": channel_type,
        "review_state": "needs-review",
    }


def synthetic_candidate() -> dict[str, object]:
    components: list[dict[str, object]] = []
    versions: list[dict[str, object]] = []
    occurrences: list[dict[str, object]] = []
    sources = [
        {
            "source_id": "src-test-argo",
            "evidence_uri": "live-export:sha256:" + "a" * 64,
        }
    ]
    chart_versions = {
        "argo-cd": "10.1.4",
        "argo-rollouts": "2.41.0",
        "argo-workflows": "1.0.20",
    }
    for chart, version in chart_versions.items():
        component_id = f"cmp-test-chart-{chart}"
        version_id = f"ver-test-chart-{chart}"
        root_id = f"cmp-test-app-{chart}"
        components.extend(
            [
                {
                    "component_id": component_id,
                    "kind": "helm-chart",
                    "ecosystem": "helm",
                    "name": chart,
                    "lifecycles": ["deployed"],
                    "metadata": {
                        "chart_repository": "https://argoproj.github.io/argo-helm"
                    },
                    "official_channels": [
                        candidate_channel(chart, channel_type)
                        for channel_type in CHANNEL_TYPES
                    ],
                },
                {
                    "component_id": root_id,
                    "kind": "argo-application",
                    "namespace": "argocd",
                    "name": chart,
                },
            ]
        )
        versions.append(
            {
                "component_id": component_id,
                "component_version_id": version_id,
                "constraint": version,
                "resolved_version": version,
                "resolution_state": "resolved",
                "evidence": [f"candidate:{chart}:{version}"],
            }
        )
        occurrences.append(
            {
                "component_version_id": version_id,
                "occurrence_id": f"occ-test-chart-{chart}",
                "root_id": root_id,
                "role": "live-argo-helm-source",
                "directness": "direct",
                "optional": False,
                "lifecycle": "deployed",
                "source_id": "src-test-argo",
                "evidence_locator": f"/applications/{chart}",
            }
        )

    runtime_components = {
        "argocd": "cmp-test-runtime-argocd",
        "argo-rollouts": "cmp-test-runtime-rollouts",
        "argoexec": "cmp-test-runtime-workflows",
    }
    for name, component_id in runtime_components.items():
        components.append(
            {
                "component_id": component_id,
                "kind": "oci-image",
                "namespace": "quay.io/argoproj",
                "name": name,
            }
        )
        tag_version_id = f"ver-test-runtime-{name}-tag"
        digest_version_id = f"ver-test-runtime-{name}-digest"
        versions.extend(
            [
                {
                    "component_id": component_id,
                    "component_version_id": tag_version_id,
                    "resolved_version": "v1.0.0",
                    "resolution_state": "unresolved",
                    "evidence": [f"candidate:{name}:tag"],
                },
                {
                    "component_id": component_id,
                    "component_version_id": digest_version_id,
                    "artifact_digest": "sha256:" + "b" * 64,
                    "resolution_state": "resolved",
                    "evidence": [f"candidate:{name}:digest"],
                },
            ]
        )
        occurrences.extend(
            [
                {
                    "component_version_id": tag_version_id,
                    "occurrence_id": f"occ-test-runtime-{name}-tag",
                    "role": "live-container-desired-image",
                },
                {
                    "component_version_id": digest_version_id,
                    "occurrence_id": f"occ-test-runtime-{name}-digest",
                    "role": "live-container-imageid",
                },
            ]
        )

    collections: dict[str, object] = {
        "components": components,
        "dependency_edges": [],
        "gaps": [],
        "occurrences": occurrences,
        "sources": sources,
        "versions": versions,
    }
    counts = {name: len(value) for name, value in collections.items()}
    return {
        "manifest_id": materializer.EXPECTED_CANDIDATE_MANIFEST_ID,
        "generation_state": "candidate",
        "counts": counts,
        "integrity": {
            "manifest_hash": "sha256:"
            + materializer.EXPECTED_CANDIDATE_MANIFEST_ID.removeprefix("mft-"),
            "exact_counts": counts,
        },
        "discovery_scope": {"complete": True},
        **collections,
    }


# Hang guard, not the assertion: the assertion is the child's exit code. A
# blocked open never returns, so this is sized to stop a regression wedging
# the CI job -- never to bound how fast a loaded runner completes the call.
BLOCKING_GUARD_SECONDS = 120.0


class MaterializeArgoRecordSetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / ".workingdir2").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected_without_blocking(
        self, callback: Callable[[], object], message: str
    ) -> None:
        """Assert the call returns with its rejection instead of blocking."""

        context = multiprocessing.get_context("fork")
        entered = context.Event()

        def invoke() -> None:
            # Signalled immediately before the call so the guard below bounds
            # the call under test, not fork and interpreter startup.
            entered.set()
            try:
                callback()
            except (OSError, ValueError) as error:
                os._exit(0 if message in str(error) else 2)
            os._exit(1)

        process = context.Process(target=invoke)
        process.start()
        try:
            if not entered.wait(timeout=BLOCKING_GUARD_SECONDS):
                self.fail(
                    "child never reached the call under test within "
                    f"{BLOCKING_GUARD_SECONDS:.0f}s; that is runner scheduling "
                    "latency, not a materializer regression"
                )
            process.join(timeout=BLOCKING_GUARD_SECONDS)
            if process.is_alive():
                self.fail(
                    "the materializer did not return within "
                    f"{BLOCKING_GUARD_SECONDS:.0f}s of entering the call on a "
                    "non-regular leaf: it blocked in open, or a heavily loaded "
                    "runner starved the child past the hang guard"
                )
        finally:
            if process.is_alive():
                process.terminate()
                process.join(timeout=BLOCKING_GUARD_SECONDS)
                if process.is_alive():
                    process.kill()
                    process.join()
        self.assertEqual(0, process.exitcode)

    def build(self) -> tuple[dict[str, bytes], dict[str, object]]:
        candidate = synthetic_candidate()
        candidate_raw = materializer.output_bytes(candidate)
        capture_result = {
            "state": "complete",
            "unavailable_surfaces": [],
            "captured_surfaces": list(materializer.REQUIRED_SURFACES),
            "inputs": [{} for _ in range(145)],
            "capture_manifest": "capture-manifest.json",
        }
        capture_manifest = {
            "record_kind": "live_capture_manifest",
            "contract_version": 3,
            "git_commit": materializer.EXPECTED_GENERATOR_COMMIT,
            "observed_at": materializer.EXPECTED_OBSERVED_AT,
            "required_surfaces": list(materializer.REQUIRED_SURFACES),
            "surfaces": {
                name: {"state": "captured"} for name in materializer.REQUIRED_SURFACES
            },
        }
        component_schema_raw = (
            REPO_ROOT / materializer.COMPONENT_SCHEMA_SOURCE
        ).read_bytes()
        record_set_schema_raw = (
            REPO_ROOT / materializer.RECORD_SET_SCHEMA_SOURCE
        ).read_bytes()
        component_schema = materializer.strict_json_loads(component_schema_raw)
        record_set_schema = materializer.strict_json_loads(record_set_schema_raw)
        counts = candidate["counts"]
        with mock.patch.object(materializer, "EXPECTED_COUNTS", counts):
            return materializer.build_record_set(
                candidate_raw,
                candidate,
                materializer.output_bytes(capture_result),
                capture_result,
                materializer.output_bytes(capture_manifest),
                capture_manifest,
                MODULE_PATH.read_bytes(),
                component_schema_raw,
                record_set_schema_raw,
                b"test requirements",
                {
                    "attrs": "test",
                    "jsonschema": "test",
                    "jsonschema-specifications": "test",
                    "referencing": "test",
                    "rpds-py": "test",
                },
                materializer.schema_validator(component_schema, "component schema"),
                materializer.schema_validator(record_set_schema, "record-set schema"),
            )

    def test_projection_is_deterministic_complete_and_non_authoritative(self) -> None:
        first_records, first_set = self.build()
        second_records, second_set = self.build()
        self.assertEqual(first_records, second_records)
        self.assertEqual(first_set, second_set)
        self.assertEqual(
            {
                "argo-argo-cd-chart.json",
                "argo-argo-rollouts-chart.json",
                "argo-argo-workflows-chart.json",
            },
            set(first_records),
        )
        self.assertEqual("needs-review", first_set["review"]["status"])
        self.assertEqual("non_authoritative", first_set["authority_state"])
        self.assertEqual(0, first_set["counts"]["accepted_records"])
        self.assertFalse(first_set["compile_eligible"])
        self.assertFalse(first_set["promote_eligible"])
        self.assertEqual(
            "reviewed-record-set:" + first_set["payload_sha256"],
            first_set["record_set_id"],
        )

        for entry in first_set["records"]:
            record = json.loads(first_records[Path(entry["path"]).name])
            bound = [binding["record_pointer"] for binding in entry["bindings"]]
            self.assertEqual(sorted(materializer.leaf_pointers(record)), sorted(bound))
            self.assertEqual(len(bound), len(set(bound)))
            capture_bindings = [
                binding
                for binding in entry["bindings"]
                if binding["binding_kind"] == "capture-pointer"
            ]
            self.assertTrue(capture_bindings)
            self.assertTrue(
                all(
                    binding["evidence"][0].startswith(
                        "capture-manifest:sha256:0090d8d89185d84d"
                    )
                    and binding["evidence"][0].endswith("/observed_at")
                    for binding in capture_bindings
                )
            )

        gaps = {gap["target_id"]: gap for gap in first_set["gaps"]}
        events = gaps["cmp:github:argoproj/argo-events"]
        self.assertEqual("absent", events["state"])
        for target_id in materializer.RUNTIME_EVIDENCE:
            runtime = gaps[target_id]
            self.assertEqual("ambiguous", runtime["state"])
            pointers = runtime["candidate_pointers"]
            self.assertTrue(
                any(pointer.startswith("/components/") for pointer in pointers)
            )
            self.assertTrue(
                any(pointer.startswith("/versions/") for pointer in pointers)
            )
            self.assertTrue(
                any(pointer.startswith("/occurrences/") for pointer in pointers)
            )
            self.assertTrue(
                any(pointer.endswith("/artifact_digest") for pointer in pointers)
            )

    def test_duplicate_keys_and_structural_bounds_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            materializer.strict_json_loads(b'{"key":1,"key":2}')
        with mock.patch.object(materializer, "MAX_JSON_DEPTH", 1):
            with self.assertRaisesRegex(ValueError, "nesting bound"):
                materializer.strict_json_loads(b'{"nested":{"deeper":{}}}')
        with mock.patch.object(materializer, "MAX_JSON_NODES", 1):
            with self.assertRaisesRegex(ValueError, "node bound"):
                materializer.strict_json_loads(b"[1]")

    def test_non_regular_inputs_are_rejected_without_blocking(self) -> None:
        pipe = self.root / "candidate.json"
        os.mkfifo(pipe)
        self.assert_rejected_without_blocking(
            lambda: materializer.read_regular_capture(
                pipe, maximum=1024, label="candidate"
            ),
            "not a regular file",
        )
        pipe.unlink()
        target = self.root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        pipe.symlink_to(target)
        with self.assertRaises(OSError):
            materializer.read_regular_capture(pipe, maximum=1024, label="candidate")

    def test_captured_input_replacement_and_wrong_digest_fail_closed(self) -> None:
        path = self.root / "captured.json"
        path.write_text("{}\n", encoding="utf-8")
        raw, identity = materializer.read_regular_capture(
            path, maximum=1024, label="captured"
        )
        path.write_text('{"changed":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed during materialization"):
            materializer.recheck_regular(
                path,
                maximum=1024,
                expected_sha256=materializer.sha256_bytes(raw),
                expected_identity=identity,
                label="captured",
            )

        capture_result = self.root / "capture-result.json"
        capture_manifest = self.root / "capture-manifest.json"
        capture_result.write_text("{}\n", encoding="utf-8")
        capture_manifest.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            materializer.materialize(REPO_ROOT, path, capture_result, capture_manifest)

    def test_output_is_scratch_only_exclusive_and_swap_detected(self) -> None:
        records, record_set = self.build()
        outside = self.root / "bundle"
        with self.assertRaisesRegex(ValueError, "below repository .workingdir2"):
            materializer.write_bundle(self.root, outside, records, record_set)

        output = self.root / ".workingdir2/bundle"
        materializer.write_bundle(self.root, output, records, record_set)
        first = {
            path.relative_to(output).as_posix(): path.read_bytes()
            for path in output.rglob("*")
            if path.is_file()
        }
        materializer.write_bundle(self.root, output, records, record_set)
        second = {
            path.relative_to(output).as_posix(): path.read_bytes()
            for path in output.rglob("*")
            if path.is_file()
        }
        self.assertEqual(first, second)
        (output / "reviewed-record-set.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "conflicting materializer output"):
            materializer.write_bundle(self.root, output, records, record_set)

        exact_set_output = self.root / ".workingdir2/exact-set"
        (exact_set_output / "records").mkdir(parents=True)
        (exact_set_output / "records/extra.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "differs from the exact output set"):
            materializer.write_bundle(self.root, exact_set_output, records, record_set)

        fifo_output = self.root / ".workingdir2/fifo"
        (fifo_output / "records").mkdir(parents=True)
        os.mkfifo(fifo_output / "reviewed-record-set.json")
        self.assert_rejected_without_blocking(
            lambda: materializer.write_bundle(
                self.root, fifo_output, records, record_set
            ),
            "not a regular file",
        )

        swap_output = self.root / ".workingdir2/swap"
        moved = self.root / ".workingdir2/swap-moved"
        original_verify = materializer.verify_directory_path
        swapped = False

        def swap_then_verify(path: Path, expected: os.stat_result, label: str) -> None:
            nonlocal swapped
            if label == "materializer output directory" and not swapped:
                swapped = True
                swap_output.rename(moved)
                swap_output.mkdir()
            original_verify(path, expected, label)

        with mock.patch.object(
            materializer, "verify_directory_path", side_effect=swap_then_verify
        ):
            with self.assertRaisesRegex(ValueError, "replaced during output commit"):
                materializer.write_bundle(self.root, swap_output, records, record_set)

    def test_exact_output_replacement_is_preserved_without_unlink(self) -> None:
        parent = self.root / ".workingdir2/direct"
        parent.mkdir()
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, parent_fd)

        for replacement_call in (2, 3):
            with self.subTest(replacement_call=replacement_call):
                leaf = f"record-{replacement_call}.json"
                output = parent / leaf
                original_verify = materializer.exact_existing
                original_unlink = os.unlink
                calls = 0

                def replace_before_reopen(
                    directory_fd: int,
                    name: str,
                    expected: bytes,
                    required_inode: tuple[int, int] | None = None,
                    *,
                    sync: bool = False,
                ) -> tuple[int, int] | None:
                    nonlocal calls
                    calls += 1
                    if calls == replacement_call:
                        original_unlink(output)
                        output.write_bytes(b"KEEP")
                    return original_verify(
                        directory_fd,
                        name,
                        expected,
                        required_inode,
                        sync=sync,
                    )

                with mock.patch.object(materializer.os, "unlink") as unsafe_unlink:
                    with mock.patch.object(
                        materializer,
                        "exact_existing",
                        side_effect=replace_before_reopen,
                    ):
                        with self.assertRaisesRegex(ValueError, "writer-owned inode"):
                            materializer.write_exact(parent_fd, leaf, b"new")
                    unsafe_unlink.assert_not_called()
                self.assertEqual(b"KEEP", output.read_bytes())

        self.assertEqual(
            {"record-2.json", "record-3.json"},
            {path.name for path in parent.iterdir()},
        )

    def test_exact_output_write_failure_retains_leaf_without_temp_or_unlink(
        self,
    ) -> None:
        parent = self.root / ".workingdir2/direct-partial"
        parent.mkdir()
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, parent_fd)
        output = parent / "record.json"
        original_write = os.write
        calls = 0

        def fail_after_partial_write(descriptor: int, raw: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(descriptor, raw[:1])
            raise OSError("injected write failure")

        with mock.patch.object(materializer.os, "unlink") as unsafe_unlink:
            with mock.patch.object(
                materializer.os, "write", side_effect=fail_after_partial_write
            ):
                with self.assertRaisesRegex(OSError, "injected write failure"):
                    materializer.write_exact(parent_fd, output.name, b"new")
            unsafe_unlink.assert_not_called()
        self.assertEqual(b"n", output.read_bytes())
        self.assertEqual([output], list(parent.iterdir()))

    def test_full_output_after_fsync_failure_is_durably_rehabilitated(self) -> None:
        parent = self.root / ".workingdir2/direct-fsync"
        parent.mkdir()
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, parent_fd)
        output = parent / "record.json"
        original_fsync = os.fsync
        failed = False

        def fail_first_fsync(descriptor: int) -> None:
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("injected fsync failure")
            original_fsync(descriptor)

        with mock.patch.object(materializer.os, "fsync", side_effect=fail_first_fsync):
            with self.assertRaisesRegex(OSError, "injected fsync failure"):
                materializer.write_exact(parent_fd, output.name, b"new")

        calls: list[str] = []

        def observe_fsync(descriptor: int) -> None:
            calls.append("fsync")
            original_fsync(descriptor)

        with mock.patch.object(materializer.os, "fsync", side_effect=observe_fsync):
            materializer.write_exact(parent_fd, output.name, b"new")

        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(b"new", output.read_bytes())


if __name__ == "__main__":
    unittest.main()
