from __future__ import annotations

import hashlib
import importlib.util
import json
import multiprocessing
import os
import py_compile
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools/knowledge-registry/acquire_sources.py"
MODULE_SPEC = importlib.util.spec_from_file_location("acquire_sources", MODULE_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError("could not load acquire_sources module")
acquire = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(acquire)

# Hang guard, not the assertion: the assertion is the child's exit code. A
# blocked open never returns, so this is sized to stop a regression wedging
# the CI job -- never to bound how fast a loaded runner completes the call.
BLOCKING_GUARD_SECONDS = 120.0


def runtime_record(
    *,
    component_id: str = "cmp:github:argoproj/argo-workflows",
    repository: str = "argoproj/argo-workflows",
    version: str | None = "v4.0.7",
    lifecycle: str = "deployed",
) -> dict[str, object]:
    tag = version
    component_version = (
        f"ver:github:{repository}@{version}"
        if version is not None
        else f"ver:github:{repository}@unresolved"
    )
    return {
        "schema_version": "1.0.0",
        "record_kind": "reviewed_component",
        "record_id": "record:test-runtime",
        "review": {
            "status": "accepted",
            "reviewed_by": "acquisition-test",
            "reviewed_at": "2026-07-17",
            "evidence": ["https://github.com/argoproj/argo-workflows"],
        },
        "component": {
            "component_id": component_id,
            "kind": "controller",
            "ecosystem": "github",
            "namespace": repository.split("/", 1)[0],
            "name": repository.split("/", 1)[1],
            "aliases": [],
            "purl": f"pkg:github/{repository}",
            "cpe": None,
            "oci_repository": None,
            "chart_repository": None,
            "chart_name": None,
            "api_group": None,
            "gvk": [],
            "lifecycle": lifecycle,
            "disposition": "selected",
            "owners": ["platform"],
            "topics": ["TOP-K8S-WORKFLOW"],
            "authority_policy": "official-exact-source",
            "created_at": "2026-07-17",
            "source_repo": f"https://github.com/{repository}",
        },
        "versions": [
            {
                "component_version_id": component_version,
                "component_id": component_id,
                "purl": f"pkg:github/{repository}@{version}" if version else None,
                "constraint": version,
                "resolved_version": version,
                "source_ref": f"refs/tags/{tag}" if tag else None,
                "artifact_digest": None,
                "platform": None,
                "build_metadata": {},
                "release_time": None,
                "observed_at": "2026-07-17T00:00:00Z",
                "valid_from": None,
                "valid_to": None,
                "resolution_state": "resolved" if tag else "unresolved",
                "evidence": [f"https://github.com/{repository}"],
            }
        ],
        "occurrences": [],
        "dependencies": [],
        "channels": [
            {
                "channel_id": f"chn:test:{repository.replace('/', '-')}:source",
                "channel_type": "source",
                "component_id": component_id,
                "availability_state": "available",
                "canonical_uri": (
                    f"https://github.com/{repository}/tree/{tag}"
                    if tag
                    else f"https://github.com/{repository}"
                ),
                "publisher": "Argo Project",
                "rights": "Apache-2.0",
                "version_strategy": "exact-tag" if tag else "mutable-resolve-ref",
                "access": "public",
                "refresh_policy": "immutable" if tag else "on-version-selection",
                "discovery_method": "reviewed",
                "confidence": "reviewed",
                "review_state": "accepted",
                "evidence": [f"https://github.com/{repository}"],
                "gap": None,
            }
        ],
        "snapshots": [],
        "gaps": [],
    }


def chart_record(
    *,
    chart: str = "argo-workflows",
    version: str | None = "1.0.20",
    lifecycle: str = "deployed",
) -> dict[str, object]:
    component_id = f"cmp:helm:argoproj/{chart}"
    tag = f"{chart}-{version}" if version is not None else None
    # The corrective records bind an exact 40-hex commit; derive a deterministic
    # synthetic commit from the tag so offline fixtures stay byte-stable.
    commit = hashlib.sha1(tag.encode()).hexdigest() if tag else None
    subtree = f"charts/{chart}"
    subtree_uri = (
        f"https://github.com/argoproj/argo-helm/tree/{commit}/{subtree}"
        if commit
        else None
    )
    version_id = (
        f"ver:helm:argoproj/{chart}@{version}"
        if version is not None
        else f"ver:helm:argoproj/{chart}@unresolved"
    )
    return {
        "schema_version": "1.0.0",
        "record_kind": "reviewed_component",
        "record_id": f"record:test-chart:{chart}",
        "review": {
            "status": "accepted",
            "reviewed_by": "acquisition-test",
            "reviewed_at": "2026-07-17",
            "evidence": ["https://github.com/argoproj/argo-helm"],
        },
        "component": {
            "component_id": component_id,
            "kind": "chart",
            "ecosystem": "helm",
            "namespace": "argoproj",
            "name": chart,
            "aliases": [],
            "purl": f"pkg:helm/{chart}",
            "cpe": None,
            "oci_repository": None,
            "chart_repository": "https://argoproj.github.io/argo-helm",
            "chart_name": chart,
            "api_group": None,
            "gvk": [],
            "lifecycle": lifecycle,
            "disposition": "selected",
            "owners": ["platform"],
            "topics": ["TOP-K8S-WORKFLOW"],
            "authority_policy": "official-exact-chart-source",
            "created_at": "2026-07-17",
            "source_repo": "https://github.com/argoproj/argo-helm",
        },
        "versions": [
            {
                "component_version_id": version_id,
                "component_id": component_id,
                "purl": f"pkg:helm/{chart}@{version}" if version else None,
                "constraint": version,
                "resolved_version": version,
                "source_ref": commit if tag else None,
                "artifact_digest": None,
                "platform": None,
                "build_metadata": (
                    {
                        "source_resolution": {
                            "review_state": "accepted",
                            "chart": {
                                "tag": tag,
                                "commit": commit,
                                "subtree": subtree,
                                "subtree_uri": subtree_uri,
                                "publisher": "Argo Project (argoproj)",
                                "license": {
                                    "spdx": "Apache-2.0",
                                    "uri": (
                                        "https://github.com/argoproj/argo-helm/blob/"
                                        f"{commit}/LICENSE"
                                    ),
                                },
                            },
                        }
                    }
                    if tag
                    else {}
                ),
                "release_time": None,
                "observed_at": "2026-07-17T00:00:00Z",
                "valid_from": None,
                "valid_to": None,
                "resolution_state": "resolved" if tag else "unresolved",
                "evidence": ["https://github.com/argoproj/argo-helm"],
            }
        ],
        "occurrences": [],
        "dependencies": [],
        "channels": [
            {
                "channel_id": f"chn:test:{chart}:source",
                "channel_type": "source",
                "component_id": component_id,
                "availability_state": "available",
                "canonical_uri": (
                    subtree_uri
                    if tag
                    else f"https://github.com/argoproj/argo-helm/tree/main/charts/{chart}"
                ),
                "publisher": "Argo Project (argoproj)",
                "rights": (
                    "Apache-2.0 for Argo-authored material only; bundled and "
                    "referenced third-party dependencies retain their own rights"
                ),
                "version_strategy": "exact-commit" if tag else "mutable-resolve-ref",
                "access": "public",
                "refresh_policy": (
                    "immutable locator; re-resolve only through a new reviewed record"
                    if tag
                    else "on-version-selection"
                ),
                "discovery_method": "manual",
                "confidence": "high",
                "review_state": "accepted",
                "evidence": ["https://github.com/argoproj/argo-helm"],
                "gap": None,
            }
        ],
        "snapshots": [],
        "gaps": [],
    }


class AcquireSourcesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.records = self.root / "knowledge/registry/records"
        self.records.mkdir(parents=True)
        self.record_set = (
            self.root / "knowledge/registry/record-sets/argo-p1-src-02.json"
        )
        self.record_set.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_record(self, name: str, record: dict[str, object]) -> Path:
        path = self.records / name
        path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def write_record_set(self) -> Path:
        entries: list[dict[str, object]] = []
        for path in sorted(self.records.iterdir()):
            identity = path.lstat()
            if not path.name.endswith(".json") or not stat.S_ISREG(identity.st_mode):
                continue
            raw = path.read_bytes()
            record = json.loads(raw)
            component = record.get("component", {})
            review = record.get("review", {})
            bindings = [
                {
                    "record_pointer": pointer,
                    "binding_kind": "control",
                    "source_pointer": None,
                    "evidence": ["test-fixture:accepted-record"],
                    "derivation": "test fixture binds the exact record leaf",
                }
                for pointer in acquire.leaf_pointers(record)
            ]
            entries.append(
                {
                    "path": acquire.repository_relative(self.root, path),
                    "content_sha256": acquire.sha256_bytes(raw),
                    "bytes": identity.st_size,
                    "record_id": str(record.get("record_id") or "missing-record-id"),
                    "component_id": str(
                        component.get("component_id") or "missing-component-id"
                    ),
                    "candidate_component_id": "cmp-test-candidate",
                    "review_status": str(review.get("status") or "needs-review"),
                    "bindings_sha256": acquire.sha256_bytes(
                        acquire.canonical_bytes(bindings)
                    ),
                    "bindings": bindings,
                }
            )
        if not entries:
            self.record_set.write_text("{}\n", encoding="utf-8")
            return self.record_set
        all_accepted = all(item["review_status"] == "accepted" for item in entries)
        generator_dependencies = {
            name: "test" for name in sorted(acquire.REQUIRED_VALIDATOR_DISTRIBUTIONS)
        }
        core = {
            "$schema": "https://github.com/cordanaLLM/knowledge/schemas/registry/reviewed-record-set.schema.json",
            "schema_version": "1.0.0",
            "record_set_kind": "reviewed_component_record_set",
            "review": {
                "status": "accepted" if all_accepted else "needs-review",
                "reviewed_by": "acquisition-test",
                "reviewed_at": "2026-07-17",
                "evidence": ["test-fixture:record-set"],
            },
            "authority_state": "reviewed" if all_accepted else "non_authoritative",
            "compile_eligible": False,
            "promote_eligible": False,
            "generator": {
                "name": "archeion-argo-record-set-materializer",
                "version": "test",
                "source": "tools/knowledge-registry/materialize_argo_record_set.py",
                "source_sha256": "sha256:" + "0" * 64,
                "component_schema_sha256": "sha256:" + "1" * 64,
                "record_set_schema_sha256": "sha256:" + "2" * 64,
                "requirements_sha256": "sha256:" + "3" * 64,
                "validator_dependencies": generator_dependencies,
            },
            "input_artifacts": [
                {
                    "role": role,
                    "content_sha256": "sha256:" + digit * 64,
                    "bytes": 1,
                    "identity": "test-fixture",
                }
                for role, digit in (
                    ("accepted_candidate", "4"),
                    ("capture_result", "5"),
                    ("capture_manifest", "6"),
                )
            ],
            "scope": {
                "batch": "P1-SRC-02-argo-initial",
                "records_path": "knowledge/registry/records",
                "candidate_manifest_id": "mft-" + "7" * 64,
                "candidate_generator_commit": "8" * 40,
                "observed_at": "2026-07-17T00:00:00Z",
                "materialized_component_ids": sorted(
                    {str(item["component_id"]) for item in entries}
                ),
                "required_targets": [
                    "cmp:github:argoproj/argo-cd",
                    "cmp:github:argoproj/argo-events",
                    "cmp:github:argoproj/argo-rollouts",
                    "cmp:github:argoproj/argo-workflows",
                    "cmp:helm:argoproj/argo-cd",
                    "cmp:helm:argoproj/argo-rollouts",
                    "cmp:helm:argoproj/argo-workflows",
                ],
            },
            "records": entries,
            "gaps": [],
            "counts": {
                "records": len(entries),
                "accepted_records": sum(
                    item["review_status"] == "accepted" for item in entries
                ),
                "blocking_gaps": 0,
            },
        }
        payload_sha256 = acquire.sha256_bytes(acquire.canonical_bytes(core))
        manifest = {
            "record_set_id": "reviewed-record-set:" + payload_sha256,
            "payload_sha256": payload_sha256,
            **core,
        }
        self.record_set.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        return self.record_set

    def build(self, component_ids: set[str] | None = None) -> dict[str, object]:
        self.write_record_set()
        return acquire.build_plan(
            self.root,
            self.records,
            {"deployed", "planned"},
            component_ids or set(),
            self.record_set,
        )

    def rewrite_record_set(
        self,
        callback: Callable[[dict[str, object]], None],
        *,
        rebind: bool = True,
    ) -> dict[str, object]:
        manifest = json.loads(self.record_set.read_text(encoding="utf-8"))
        callback(manifest)
        if rebind:
            core = {
                key: value
                for key, value in manifest.items()
                if key not in {"record_set_id", "payload_sha256"}
            }
            payload_sha256 = acquire.sha256_bytes(acquire.canonical_bytes(core))
            manifest["payload_sha256"] = payload_sha256
            manifest["record_set_id"] = "reviewed-record-set:" + payload_sha256
        self.record_set.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        return manifest

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
                    "latency, not a planner regression"
                )
            process.join(timeout=BLOCKING_GUARD_SECONDS)
            if process.is_alive():
                self.fail(
                    "the planner did not return within "
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

    def test_exact_reviewed_chart_is_ready_and_plan_is_reproducible(self) -> None:
        self.write_record("workflows.json", chart_record())
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)
        self.assertEqual(
            acquire.json_output_bytes(first), acquire.json_output_bytes(second)
        )
        output_bytes = acquire.json_output_bytes(first)
        self.assertTrue(output_bytes.endswith(b"\n"))
        self.assertFalse(output_bytes.endswith(b"\\n"))

        self.assertFalse(output_bytes.endswith(b"\n\n"))
        self.assertEqual(
            acquire.file_sha256(REPO_ROOT / acquire.REGISTRY_VALIDATOR_SOURCE),
            first["generator"]["reviewed_record_validator_sha256"],
        )
        self.assertEqual(
            acquire.file_sha256(REPO_ROOT / acquire.REVIEWED_SCHEMA_SOURCE),
            first["generator"]["reviewed_record_schema_sha256"],
        )
        self.assertEqual(
            acquire.file_sha256(REPO_ROOT / acquire.REVIEWED_REQUIREMENTS_SOURCE),
            first["generator"]["reviewed_validator_requirements_sha256"],
        )
        self.assertEqual(
            sorted(acquire.REQUIRED_VALIDATOR_DISTRIBUTIONS),
            list(first["generator"]["reviewed_validator_dependencies"]),
        )
        self.assertFalse(first["compile_eligible"])
        self.assertFalse(first["promote_eligible"])
        self.assertEqual(acquire.PLAN_SCHEMA_VERSION, first["schema_version"])
        self.assertEqual(acquire.RECORD_SCHEMA_VERSION, first["record_schema_version"])
        self.assertEqual(acquire.GENERATOR_VERSION, first["generator"]["version"])
        self.assertTrue(
            all(value is False for value in first["authority_boundary"].values())
        )
        self.assertEqual(1, first["counts"]["ready"])
        self.assertEqual(0, first["counts"]["blocked"])
        target = first["targets"][0]
        self.assertEqual("argo-workflows-1.0.20", target["requested_tag"])
        self.assertEqual(40, len(target["expected_commit"]))
        self.assertEqual(["charts/argo-workflows"], target["content_roots"])
        self.assertEqual(
            {
                "repository": "argoproj/argo-helm",
                "requested_tag": "argo-workflows-1.0.20",
                "expected_commit": target["expected_commit"],
                "content_roots": ["charts/argo-workflows"],
            },
            target["target_identity"],
        )
        self.assertEqual("accepted", target["source_resolution_review_state"])
        self.assertEqual(
            "Apache-2.0",
            target["source_authorization"]["chart"]["license"]["spdx"],
        )
        self.assertEqual("argo-workflows", target["fetch_component"])
        self.assertEqual([], target["gaps"])

    def test_named_pipe_record_is_rejected_without_blocking(self) -> None:
        os.mkfifo(self.records / "blocked.json")
        self.assert_rejected_without_blocking(self.build, "not a regular file")

    def test_non_json_record_entry_reports_the_offending_name(self) -> None:
        (self.records / "README.txt").write_text("not a record\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValueError,
            r"non-record directory entry: 'README\.txt'",
        ):
            self.build()

    def test_named_pipe_output_is_rejected_without_blocking(self) -> None:
        self.write_record("workflows.json", runtime_record())
        plan = self.build()
        output = self.root / ".workingdir2/plans/plan.json"
        output.parent.mkdir(parents=True)
        os.mkfifo(output)
        self.assert_rejected_without_blocking(
            lambda: acquire.write_plan_output(self.root, output, plan),
            "not a regular file",
        )

    def test_deployed_exact_chart_profiles_are_ready(self) -> None:
        self.write_record("cd.json", chart_record(chart="argo-cd", version="10.1.3"))
        self.write_record(
            "rollouts.json", chart_record(chart="argo-rollouts", version="2.41.0")
        )
        self.write_record("workflows.json", chart_record())
        plan = self.build()
        self.assertEqual(3, plan["counts"]["ready"])
        self.assertEqual(0, plan["counts"]["blocked"])
        targets = {target["component_id"]: target for target in plan["targets"]}
        workflows = targets["cmp:helm:argoproj/argo-workflows"]
        self.assertEqual("argo-workflows-1.0.20", workflows["requested_tag"])
        self.assertEqual("--argo-chart-snapshot", workflows["fetch_argument"])
        self.assertEqual("argo-helm-argo-workflows", workflows["cache_key"])
        self.assertEqual("charts/argo-workflows", workflows["source_subtree"])
        self.assertEqual("helm-chart-subtree", workflows["content_profile"])

    def test_record_replacement_after_capture_fails_closed(self) -> None:
        record_path = self.write_record("workflows.json", runtime_record())
        original_reader = acquire.read_regular_at
        replaced = False

        def replace_after_read(*args: object, **kwargs: object) -> object:
            nonlocal replaced
            value = original_reader(*args, **kwargs)
            if kwargs.get("label") == "reviewed record workflows.json" and not replaced:
                replaced = True
                changed = runtime_record()
                changed["record_id"] = "record:changed-after-read"
                record_path.write_text(
                    json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8"
                )
            return value

        with mock.patch.object(
            acquire, "read_regular_at", side_effect=replace_after_read
        ):
            with self.assertRaisesRegex(ValueError, "changed during plan generation"):
                self.build()

    def test_pathname_replacement_is_checked_against_captured_fstat(self) -> None:
        record_path = self.write_record("workflows.json", runtime_record())
        self.write_record_set()
        original_reader = acquire.read_record_set

        def replace_after_denominator_capture(
            *args: object, **kwargs: object
        ) -> object:
            result = original_reader(*args, **kwargs)
            changed = runtime_record()
            changed["review"]["reviewed_by"] = "replacement-with-a-different-size"
            record_path.write_text(
                json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8"
            )
            return result

        with mock.patch.object(
            acquire,
            "read_record_set",
            side_effect=replace_after_denominator_capture,
        ):
            with self.assertRaisesRegex(
                ValueError, "reviewed record changed during plan generation"
            ):
                acquire.build_plan(
                    self.root,
                    self.records,
                    {"deployed", "planned"},
                    set(),
                    self.record_set,
                )

    def test_excluded_record_cannot_mutate_into_the_selected_denominator(self) -> None:
        self.write_record("workflows.json", runtime_record())
        excluded = runtime_record(
            component_id="cmp:github:argoproj/argo-rollouts",
            repository="argoproj/argo-rollouts",
            version="v1.9.0",
        )
        excluded["record_id"] = "record:test-runtime:excluded"
        excluded["review"]["status"] = "rejected"
        excluded_path = self.write_record("excluded.json", excluded)
        original_loader = acquire.load_reviewed_contract

        def select_after_capture() -> object:
            result = original_loader()
            excluded["review"]["status"] = "accepted"
            excluded_path.write_text(
                json.dumps(excluded, sort_keys=True) + "\n", encoding="utf-8"
            )
            return result

        with mock.patch.object(
            acquire, "load_reviewed_contract", side_effect=select_after_capture
        ):
            with self.assertRaisesRegex(
                ValueError, "reviewed record changed during plan generation"
            ):
                self.build()

    def test_only_accepted_deployed_or_planned_records_enter_denominator(self) -> None:
        self.write_record("accepted.json", runtime_record())
        rejected = runtime_record(
            component_id="cmp:github:argoproj/argo-rollouts",
            repository="argoproj/argo-rollouts",
            version="v1.9.0",
        )
        rejected["record_id"] = "record:test-runtime:rejected"
        rejected["review"]["status"] = "rejected"
        self.write_record("rejected.json", rejected)
        retired = runtime_record(
            component_id="cmp:github:argoproj/argo-cd",
            repository="argoproj/argo-cd",
            version="v3.4.5",
        )
        retired["record_id"] = "record:test-runtime:retired"
        retired["component"]["lifecycle"] = "retired"
        self.write_record("retired.json", retired)
        plan = self.build()
        self.assertEqual(1, plan["counts"]["total"])
        self.assertEqual(
            ["cmp:github:argoproj/argo-workflows"],
            [target["component_id"] for target in plan["targets"]],
        )
        self.assertEqual(0, plan["counts"]["ready"])
        self.assertIn(
            "reviewed_record_set_not_accepted",
            {gap["code"] for gap in plan["targets"][0]["gaps"]},
        )

    def test_draft_record_set_blocks_an_otherwise_ready_target(self) -> None:
        self.write_record("workflows.json", runtime_record())
        self.write_record_set()

        def make_draft(manifest: dict[str, object]) -> None:
            manifest["review"]["status"] = "needs-review"
            manifest["authority_state"] = "non_authoritative"

        self.rewrite_record_set(make_draft)
        plan = acquire.build_plan(
            self.root,
            self.records,
            {"deployed", "planned"},
            set(),
            self.record_set,
        )
        self.assertEqual(0, plan["counts"]["ready"])
        self.assertEqual("blocked", plan["targets"][0]["state"])
        self.assertEqual("reviewed_record_set_not_accepted", plan["gaps"][0]["code"])

    def test_record_set_requires_exact_directory_and_content_binding(self) -> None:
        first = self.write_record("workflows.json", runtime_record())
        second_record = runtime_record(
            component_id="cmp:github:argoproj/argo-rollouts",
            repository="argoproj/argo-rollouts",
            version="v1.9.0",
        )
        second_record["record_id"] = "record:test-runtime:rollouts"
        second = self.write_record("rollouts.json", second_record)
        self.write_record_set()

        second.unlink()
        with self.assertRaisesRegex(ValueError, "directory equality failed"):
            acquire.build_plan(
                self.root,
                self.records,
                {"deployed", "planned"},
                set(),
                self.record_set,
            )
        self.write_record("rollouts.json", second_record)

        extra_record = runtime_record(
            component_id="cmp:github:argoproj/argo-cd",
            repository="argoproj/argo-cd",
            version="v3.4.5",
        )
        extra_record["record_id"] = "record:test-runtime:argocd"
        extra = self.write_record("extra.json", extra_record)
        with self.assertRaisesRegex(ValueError, "directory equality failed"):
            acquire.build_plan(
                self.root,
                self.records,
                {"deployed", "planned"},
                set(),
                self.record_set,
            )
        extra.unlink()

        def swap_digest(manifest: dict[str, object]) -> None:
            manifest["records"][0]["content_sha256"] = manifest["records"][1][
                "content_sha256"
            ]

        self.rewrite_record_set(swap_digest)
        with self.assertRaisesRegex(ValueError, "digest/size mismatch"):
            acquire.build_plan(
                self.root,
                self.records,
                {"deployed", "planned"},
                set(),
                self.record_set,
            )

        self.write_record_set()
        self.rewrite_record_set(
            lambda manifest: manifest["scope"].update(
                {"observed_at": "2026-07-17T00:00:01Z"}
            ),
            rebind=False,
        )
        with self.assertRaisesRegex(ValueError, "payload digest is invalid"):
            acquire.build_plan(
                self.root,
                self.records,
                {"deployed", "planned"},
                set(),
                self.record_set,
            )
        self.assertTrue(first.exists())

    def test_record_set_fifo_symlink_and_replacement_fail_closed(self) -> None:
        self.write_record("workflows.json", runtime_record())
        self.write_record_set()
        original_manifest = self.record_set.read_bytes()
        self.record_set.unlink()
        os.mkfifo(self.record_set)
        self.assert_rejected_without_blocking(
            lambda: acquire.build_plan(
                self.root,
                self.records,
                {"deployed", "planned"},
                set(),
                self.record_set,
            ),
            "not a regular file",
        )
        self.record_set.unlink()
        target = self.record_set.parent / "manifest-target.json"
        target.write_bytes(original_manifest)
        self.record_set.symlink_to(target)
        with self.assertRaises(OSError):
            acquire.build_plan(
                self.root,
                self.records,
                {"deployed", "planned"},
                set(),
                self.record_set,
            )
        self.record_set.unlink()
        self.record_set.write_bytes(original_manifest)
        original_reader = acquire.read_record_set

        def mutate_after_read(*args: object, **kwargs: object) -> object:
            result = original_reader(*args, **kwargs)
            self.record_set.write_bytes(original_manifest + b" ")
            return result

        with mock.patch.object(
            acquire, "read_record_set", side_effect=mutate_after_read
        ):
            with self.assertRaisesRegex(ValueError, "changed during plan generation"):
                acquire.build_plan(
                    self.root,
                    self.records,
                    {"deployed", "planned"},
                    set(),
                    self.record_set,
                )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        path = self.records / "duplicate.json"
        path.write_text('{"review":{"status":"accepted","status":"rejected"}}\n')
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key: status"):
            self.build()

    def test_selected_records_must_pass_the_shared_registry_contract(self) -> None:
        malformed = runtime_record()
        del malformed["snapshots"]
        self.write_record("malformed.json", malformed)
        with self.assertRaisesRegex(ValueError, "snapshots.*required property"):
            self.build()

    def test_selected_record_uris_use_the_shared_credential_safety_gate(self) -> None:
        unsafe = runtime_record()
        unsafe["channels"][0]["canonical_uri"] += "?token=not-a-secret-value"
        self.write_record("unsafe.json", unsafe)
        with self.assertRaisesRegex(ValueError, "credential-bearing URI fields"):
            self.build()

    def test_conflicting_reviewed_component_identity_is_rejected(self) -> None:
        first = runtime_record()
        second = runtime_record(version="v4.0.6")
        second["record_id"] = "record:test-runtime:older"
        self.write_record("first.json", first)
        self.write_record("second.json", second)
        with self.assertRaisesRegex(
            ValueError, "record/component identities are not unique"
        ):
            self.build()

    def test_record_and_version_denominators_are_hard_bounded(self) -> None:
        self.write_record("first.json", runtime_record())
        self.write_record(
            "second.json",
            runtime_record(
                component_id="cmp:github:argoproj/argo-rollouts",
                repository="argoproj/argo-rollouts",
                version="v1.9.0",
            ),
        )
        with mock.patch.object(acquire, "MAX_RECORD_FILES", 1):
            with self.assertRaisesRegex(ValueError, "file bound"):
                self.build()

        (self.records / "second.json").unlink()
        record = runtime_record()
        record["versions"].append(dict(record["versions"][0]))
        self.write_record("first.json", record)
        with mock.patch.object(acquire, "MAX_VERSIONS_PER_RECORD", 1):
            with self.assertRaisesRegex(ValueError, "version-entry bound"):
                self.build()

    def test_plan_serialization_is_hard_bounded(self) -> None:
        self.write_record("workflows.json", runtime_record())
        with mock.patch.object(acquire, "MAX_PLAN_CANONICAL_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "serialized bound"):
                self.build()

    def test_missing_requested_component_is_a_plan_gap(self) -> None:
        self.write_record("workflows.json", runtime_record())
        plan = self.build({"cmp:github:example/missing"})
        self.assertEqual(0, plan["counts"]["total"])
        self.assertEqual(1, plan["counts"]["blocking_gaps"])
        self.assertEqual("requested_component_missing", plan["gaps"][0]["code"])

    def test_invalid_source_repository_is_a_typed_gap(self) -> None:
        record = runtime_record()
        record["component"]["source_repo"] = "https://example.invalid/not-github"
        self.write_record("workflows.json", record)
        plan = self.build()
        self.assertEqual("blocked", plan["targets"][0]["state"])
        self.assertIn(
            "github_source_repo_invalid",
            {item["code"] for item in plan["targets"][0]["gaps"]},
        )

    def test_unresolved_events_chart_stays_blocked_without_invented_version(
        self,
    ) -> None:
        self.write_record(
            "events.json",
            chart_record(
                chart="argo-events",
                version=None,
                lifecycle="planned",
            ),
        )
        plan = self.build()
        self.assertEqual(0, plan["counts"]["ready"])
        self.assertEqual(1, plan["counts"]["blocked"])
        target = plan["targets"][0]
        self.assertIsNone(target["resolved_version"])
        self.assertIsNone(target["requested_tag"])
        self.assertIsNone(target["fetch_adapter"])
        codes = {
            issue["code"] for target in plan["targets"] for issue in target["gaps"]
        }
        self.assertIn("version_unresolved", codes)
        self.assertIn("source_channel_not_exact", codes)
        self.assertIn("fetch_profile_unsupported", codes)

    def test_chart_tag_version_subtree_and_kind_mismatches_fail_closed(self) -> None:
        wrong_tag = chart_record()
        wrong_tag["versions"][0]["build_metadata"]["source_resolution"]["chart"][
            "tag"
        ] = "argo-workflows-1.0.19"
        self.write_record("wrong-tag.json", wrong_tag)
        # A wrong commit and a wrong channel subtree URI on the same record both
        # fail closed: source_ref must equal chart.commit, and the channel must
        # name the exact commit/subtree tree URI.
        wrong_bindings = chart_record(chart="argo-rollouts", version="2.41.0")
        wrong_bindings["versions"][0]["source_ref"] = "1" * 40
        wrong_bindings["channels"][0]["canonical_uri"] = (
            "https://github.com/argoproj/argo-helm/tree/"
            + "0" * 40
            + "/charts/argo-workflows"
        )
        self.write_record("wrong-bindings.json", wrong_bindings)
        wrong_kind = chart_record(chart="argo-cd", version="10.1.3")
        wrong_kind["component"]["kind"] = "controller"
        self.write_record("wrong-kind.json", wrong_kind)
        plan = self.build()
        self.assertEqual(0, plan["counts"]["ready"])
        self.assertEqual(3, plan["counts"]["blocked"])
        codes = {
            issue["code"] for target in plan["targets"] for issue in target["gaps"]
        }
        self.assertIn("resolved_version_tag_mismatch", codes)
        self.assertIn("fetch_profile_channel_mismatch", codes)
        self.assertIn("chart_commit_mismatch", codes)
        self.assertIn("fetch_profile_kind_mismatch", codes)

    def test_ready_target_requires_selected_public_immutable_reviewed_channel(
        self,
    ) -> None:
        mutations = {
            "disposition": ("component", "disposition", "rejected"),
            "access": ("channel", "access", "restricted"),
            "refresh": ("channel", "refresh_policy", "on-demand"),
            "confidence": ("channel", "confidence", "low"),
            "discovery": ("channel", "discovery_method", "inferred"),
        }
        expected = {
            "component_disposition_not_selected",
            "source_channel_not_public",
            "source_channel_not_immutable",
            "source_channel_not_reviewed_exact",
        }
        seen: set[str] = set()
        for name, (location, field, value) in mutations.items():
            record = chart_record()
            target = (
                record["component"]
                if location == "component"
                else record["channels"][0]
            )
            target[field] = value
            self.write_record(f"{name}.json", record)
            plan = self.build()
            self.assertEqual("blocked", plan["targets"][0]["state"])
            seen.update(issue["code"] for issue in plan["targets"][0]["gaps"])
            (self.records / f"{name}.json").unlink()
        self.assertTrue(expected.issubset(seen))

    def test_real_workflows_authorization_gates_fail_closed_independently(self) -> None:
        """Exercise the exact proposed Workflows record, not a reduced facsimile."""

        source = REPO_ROOT / "knowledge/registry/records/argo-argo-workflows-chart.json"
        record = json.loads(source.read_text(encoding="utf-8"))
        record["review"] = {
            "status": "accepted",
            "reviewed_by": "independent-acquisition-test",
            "reviewed_at": "2026-07-17",
            "evidence": list(record["review"]["evidence"]),
        }
        for channel in record["channels"]:
            if channel["review_state"] == "proposed":
                channel["review_state"] = "needs-review"
        source_channel = next(
            item for item in record["channels"] if item["channel_type"] == "source"
        )
        record_path = self.write_record("workflows.json", record)

        plan = self.build()
        target = plan["targets"][0]
        issues = {item["code"]: item for item in target["gaps"]}
        self.assertEqual("blocked", target["state"])
        self.assertIn("source_resolution_not_accepted", issues)
        self.assertIn("accepted_source_channel_missing", issues)
        self.assertEqual(
            "gap:p1-src-02:argo-workflows:independent-review-pending",
            issues["target_scoped_record_gap"]["source_gap_id"],
        )

        record["versions"][0]["build_metadata"]["source_resolution"][
            "review_state"
        ] = "accepted"
        record["gaps"] = [
            item
            for item in record["gaps"]
            if item["gap_id"]
            != "gap:p1-src-02:argo-workflows:independent-review-pending"
        ]
        record_path.write_text(
            json.dumps(record, sort_keys=True) + "\n", encoding="utf-8"
        )
        plan = self.build()
        self.assertEqual("blocked", plan["targets"][0]["state"])
        self.assertEqual(
            ["accepted_source_channel_missing"],
            [
                item["code"]
                for item in plan["targets"][0]["gaps"]
                if item["code"] == "accepted_source_channel_missing"
            ],
        )

        source_channel["review_state"] = "accepted"
        source_channel["availability_state"] = "available"
        source_channel["gap"] = None
        record_path.write_text(
            json.dumps(record, sort_keys=True) + "\n", encoding="utf-8"
        )
        plan = self.build()
        self.assertEqual(1, plan["counts"]["ready"])
        self.assertEqual([], plan["targets"][0]["gaps"])

    def test_unrelated_runtime_record_gap_does_not_revoke_chart_target(self) -> None:
        record = chart_record()
        record["gaps"] = [
            {
                "gap_id": "gap:p1-src-02:argo-workflows:argoexec:oci-unresolved",
                "subject_kind": "component",
                "subject_id": "cmp:oci:quay.io/argoproj/argoexec",
                "state": "unresolved",
                "reason": "runtime OCI source admission remains unresolved",
                "blocking": True,
                "evidence": ["https://quay.io/argoproj/argoexec"],
                "next_action": "resolve the runtime OCI source independently",
                "detected_at": "2026-07-17T00:00:00Z",
                "review_state": "proposed",
            }
        ]
        self.write_record("workflows.json", record)
        plan = self.build()
        self.assertEqual(1, plan["counts"]["ready"])
        self.assertEqual([], plan["targets"][0]["gaps"])

    def test_version_and_channel_scoped_record_gaps_fail_closed(self) -> None:
        record = chart_record()
        scoped = (
            (
                "version",
                record["versions"][0]["component_version_id"],
                "gap:test:workflows:version",
            ),
            (
                "channel",
                record["channels"][0]["channel_id"],
                "gap:test:workflows:channel",
            ),
        )
        record["gaps"] = [
            {
                "gap_id": gap_id,
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "state": "unresolved",
                "reason": f"{subject_kind} authorization remains unresolved",
                "blocking": True,
                "evidence": ["https://github.com/argoproj/argo-helm"],
                "next_action": f"review the exact {subject_kind} authorization",
                "detected_at": "2026-07-17T00:00:00Z",
                "review_state": "proposed",
            }
            for subject_kind, subject_id, gap_id in scoped
        ]
        self.write_record("workflows.json", record)
        plan = self.build()
        projected = [
            item
            for item in plan["targets"][0]["gaps"]
            if item["code"] == "target_scoped_record_gap"
        ]
        self.assertEqual("blocked", plan["targets"][0]["state"])
        self.assertEqual(
            {"gap:test:workflows:version", "gap:test:workflows:channel"},
            {item["source_gap_id"] for item in projected},
        )

    def test_selected_version_dependency_gap_fails_closed(self) -> None:
        record = chart_record(chart="argo-cd", version="10.1.3")
        version_id = record["versions"][0]["component_version_id"]
        dependency_id = "dep:test:argo-cd:redis-ha"
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
                "lock_or_sbom_uri": (
                    "https://github.com/argoproj/argo-helm/blob/"
                    f"{record['versions'][0]['source_ref']}/charts/argo-cd/Chart.lock"
                ),
                "observed_at": "2026-07-17T00:00:00Z",
            }
        ]
        record["gaps"] = [
            {
                "gap_id": "gap:test:argo-cd:redis-ha-rights",
                "subject_kind": "dependency",
                "subject_id": dependency_id,
                "state": "unresolved",
                "reason": "the chart license does not relicense the dependency",
                "blocking": True,
                "evidence": [
                    "https://github.com/argoproj/argo-helm/tree/"
                    f"{record['versions'][0]['source_ref']}/charts/argo-cd"
                ],
                "next_action": "review the dependency rights independently",
                "detected_at": "2026-07-17T00:00:00Z",
                "review_state": "proposed",
            }
        ]
        self.write_record("cd.json", record)
        plan = self.build()
        projected = [
            item
            for item in plan["targets"][0]["gaps"]
            if item["code"] == "target_scoped_record_gap"
        ]
        self.assertEqual("blocked", plan["targets"][0]["state"])
        self.assertEqual(
            ["gap:test:argo-cd:redis-ha-rights"],
            [item["source_gap_id"] for item in projected],
        )

    def test_source_policy_text_and_structured_license_are_exact(self) -> None:
        mutations = {
            "mutable-refresh-prefix": (
                "channel",
                "refresh_policy",
                "immutable-looking but mutable",
                "source_channel_not_immutable",
            ),
            "forbidden-rights-suffix": (
                "channel",
                "rights",
                "Apache-2.0 except acquisition is forbidden",
                "rights_profile_unsupported",
            ),
            "spoofed-channel-publisher": (
                "channel",
                "publisher",
                "Argo Project (argoproj) mirror",
                "rights_profile_unsupported",
            ),
            "spoofed-chart-publisher": (
                "chart",
                "publisher",
                "Argo Project (argoproj) mirror",
                "chart_license_profile_unsupported",
            ),
            "invalid-license-expression": (
                "license",
                "spdx",
                "Apache-2.0 except acquisition is forbidden",
                "chart_license_profile_unsupported",
            ),
            "mutable-license-uri": (
                "license",
                "uri",
                "https://github.com/argoproj/argo-helm/blob/main/LICENSE",
                "chart_license_profile_unsupported",
            ),
        }
        for name, (location, field, value, expected_code) in mutations.items():
            with self.subTest(name=name):
                record = chart_record()
                if location == "channel":
                    record["channels"][0][field] = value
                elif location == "chart":
                    record["versions"][0]["build_metadata"]["source_resolution"][
                        "chart"
                    ][field] = value
                else:
                    record["versions"][0]["build_metadata"]["source_resolution"][
                        "chart"
                    ]["license"][field] = value
                self.write_record(f"{name}.json", record)
                plan = self.build()
                self.assertEqual("blocked", plan["targets"][0]["state"])
                self.assertIn(
                    expected_code,
                    {item["code"] for item in plan["targets"][0]["gaps"]},
                )
                (self.records / f"{name}.json").unlink()

        record = chart_record()
        record["versions"][0]["build_metadata"]["source_resolution"]["chart"][
            "license"
        ]["acquisition"] = "forbidden"
        self.write_record("extra-license-policy.json", record)
        plan = self.build()
        self.assertEqual("blocked", plan["targets"][0]["state"])
        self.assertIn(
            "chart_license_profile_unsupported",
            {item["code"] for item in plan["targets"][0]["gaps"]},
        )

    def test_latest_is_rejected_by_the_shared_reviewed_record_contract(self) -> None:
        self.write_record("latest.json", runtime_record(version="latest"))
        with self.assertRaisesRegex(ValueError, "latest"):
            self.build()

    def test_exact_source_compile_ignores_crafted_bytecode_cache(self) -> None:
        source = self.root / "contract.py"
        source.write_text("VALUE = 'cached'\n", encoding="utf-8")
        cache = Path(importlib.util.cache_from_source(str(source)))
        cache.parent.mkdir()
        py_compile.compile(str(source), cfile=str(cache), doraise=True)
        source.write_text("VALUE = 'exact-source'\n", encoding="utf-8")
        module = acquire.compile_python_module(source.read_bytes(), source)
        self.assertEqual("exact-source", module.VALUE)

    def test_contract_schema_and_requirements_replacement_fail_closed(self) -> None:
        self.write_record("workflows.json", runtime_record())
        contract_root = self.root / "contract"
        validator = contract_root / acquire.REGISTRY_VALIDATOR_SOURCE
        schema = contract_root / acquire.REVIEWED_SCHEMA_SOURCE
        record_set_schema = contract_root / acquire.RECORD_SET_SCHEMA_SOURCE
        requirements = contract_root / acquire.REVIEWED_REQUIREMENTS_SOURCE
        validator.parent.mkdir(parents=True)
        schema.parent.mkdir(parents=True)
        shutil.copy2(REPO_ROOT / acquire.REGISTRY_VALIDATOR_SOURCE, validator)
        shutil.copy2(REPO_ROOT / acquire.REVIEWED_SCHEMA_SOURCE, schema)
        shutil.copy2(REPO_ROOT / acquire.RECORD_SET_SCHEMA_SOURCE, record_set_schema)
        shutil.copy2(REPO_ROOT / acquire.REVIEWED_REQUIREMENTS_SOURCE, requirements)
        original_loader = acquire.load_reviewed_contract

        for changed in (schema, record_set_schema, requirements):
            shutil.copy2(REPO_ROOT / acquire.REVIEWED_SCHEMA_SOURCE, schema)
            shutil.copy2(
                REPO_ROOT / acquire.RECORD_SET_SCHEMA_SOURCE, record_set_schema
            )
            shutil.copy2(REPO_ROOT / acquire.REVIEWED_REQUIREMENTS_SOURCE, requirements)

            def load_then_replace(path: Path = changed) -> object:
                result = original_loader()
                suffix = (
                    b"\n " if path.suffix == ".json" else b"\n# changed after capture\n"
                )
                path.write_bytes(path.read_bytes() + suffix)
                return result

            with self.subTest(path=changed.name):
                with mock.patch.object(
                    acquire,
                    "reviewed_contract_paths",
                    return_value=(
                        validator,
                        schema,
                        record_set_schema,
                        requirements,
                    ),
                ), mock.patch.object(
                    acquire, "load_reviewed_contract", side_effect=load_then_replace
                ):
                    with self.assertRaisesRegex(
                        ValueError, "contract file changed during plan generation"
                    ):
                        self.build()

    def test_planner_source_replacement_fails_generation_and_write_checks(
        self,
    ) -> None:
        self.write_record("workflows.json", runtime_record())
        original_hash = acquire.file_sha256

        def changed_generator(path: Path, *args: object, **kwargs: object) -> str:
            digest = original_hash(path, *args, **kwargs)
            if Path(path).absolute() == Path(acquire.__file__).absolute():
                return "sha256:" + "0" * 64
            return digest

        with mock.patch.object(acquire, "file_sha256", side_effect=changed_generator):
            with self.assertRaisesRegex(ValueError, "planner source changed"):
                self.build()

        plan = self.build()
        plan["generator"]["source_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "differs from the plan binding"):
            acquire.verify_plan_generator(plan)

        for field, value, message in (
            ("schema_version", "1.0.0", "schema version"),
            ("record_schema_version", "0.0.0", "record schema binding"),
        ):
            stale = self.build()
            stale[field] = value
            with self.assertRaisesRegex(ValueError, message):
                acquire.verify_plan_generator(stale)
        stale = self.build()
        stale["generator"]["version"] = "3"
        with self.assertRaisesRegex(ValueError, "generator contract"):
            acquire.verify_plan_generator(stale)

    def test_record_directory_replacement_and_symlink_fail_closed(self) -> None:
        self.write_record("workflows.json", runtime_record())
        original_verify = acquire.verify_record_denominator
        moved = self.root / "records-moved"
        swapped = False

        def swap_before_verify(*args: object, **kwargs: object) -> object:
            nonlocal swapped
            if not swapped:
                swapped = True
                self.records.rename(moved)
                self.records.mkdir()
            return original_verify(*args, **kwargs)

        with mock.patch.object(
            acquire, "verify_record_denominator", side_effect=swap_before_verify
        ):
            with self.assertRaisesRegex(ValueError, "changed|path was replaced"):
                self.build()

        self.records.rmdir()
        self.records.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            self.build()

    def test_fixed_filter_target_json_and_output_bounds_fail_closed(self) -> None:
        self.write_record("workflows.json", runtime_record())
        with mock.patch.object(acquire, "MAX_COMPONENT_FILTERS", 1):
            with self.assertRaisesRegex(ValueError, "component filter"):
                acquire.build_plan(
                    self.root,
                    self.records,
                    {"deployed"},
                    {"cmp:first", "cmp:second"},
                    self.write_record_set(),
                )
        with mock.patch.object(acquire, "MAX_TARGETS", 0):
            with self.assertRaisesRegex(ValueError, "target bound"):
                self.build()
        with mock.patch.object(acquire, "MAX_JSON_DEPTH", 1):
            with self.assertRaisesRegex(ValueError, "nesting bound"):
                acquire.strict_json_loads('{"nested": {}}')
        with mock.patch.object(acquire, "MAX_JSON_NODES", 1):
            with self.assertRaisesRegex(ValueError, "node bound"):
                acquire.strict_json_loads("[1]")
        with mock.patch.object(acquire, "MAX_PLAN_OUTPUT_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "output exceeds"):
                acquire.json_output_bytes({"value": 1})

    def test_output_is_scratch_only_exclusive_and_large_replay_safe(self) -> None:
        outside = self.root / "plan.json"
        with self.assertRaisesRegex(ValueError, "below repository .workingdir2"):
            acquire.write_plan_output(self.root, outside, {"value": 1})

        output = self.root / ".workingdir2/plans/plan.json"
        value = {"blob": "x" * (9 * 1024 * 1024)}
        acquire.write_plan_output(self.root, output, value)
        first = output.read_bytes()
        acquire.write_plan_output(self.root, output, value)
        self.assertEqual(first, output.read_bytes())
        self.assertEqual(0o644, output.stat().st_mode & 0o777)
        with self.assertRaisesRegex(ValueError, "conflicting plan output"):
            acquire.write_plan_output(self.root, output, {"blob": "different"})

    def test_output_parent_swap_is_detected_and_owned_leaf_is_retained(self) -> None:
        parent = self.root / ".workingdir2/plans"
        parent.mkdir(parents=True)
        output = parent / "plan.json"
        moved = self.root / "moved-output-parent"
        original_verify = acquire.verify_directory_path
        calls = 0

        def swap_parent(path: Path, expected: os.stat_result, label: str) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                parent.rename(moved)
                parent.mkdir()
            original_verify(path, expected, label)

        with mock.patch.object(
            acquire, "verify_directory_path", side_effect=swap_parent
        ):
            with self.assertRaisesRegex(ValueError, "replaced during output commit"):
                acquire.write_plan_output(self.root, output, {"value": 1})
        self.assertFalse(output.exists())
        retained = moved / "plan.json"
        self.assertEqual(acquire.json_output_bytes({"value": 1}), retained.read_bytes())
        self.assertEqual([retained], list(moved.iterdir()))

    def test_output_replacement_during_replay_is_rejected_and_preserved(self) -> None:
        for replacement_call in (2, 3):
            with self.subTest(replacement_call=replacement_call):
                output = self.root / f".workingdir2/plans-{replacement_call}/plan.json"
                output.parent.mkdir(parents=True)
                original_verify = acquire.exact_existing_output
                original_unlink = os.unlink
                calls = 0

                def replace_before_reopen(
                    parent_fd: int,
                    leaf: str,
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
                        parent_fd,
                        leaf,
                        expected,
                        required_inode,
                        sync=sync,
                    )

                with mock.patch.object(acquire.os, "unlink") as unsafe_unlink:
                    with mock.patch.object(
                        acquire,
                        "exact_existing_output",
                        side_effect=replace_before_reopen,
                    ):
                        with self.assertRaisesRegex(ValueError, "writer-owned inode"):
                            acquire.write_plan_output(self.root, output, {"value": 1})
                    unsafe_unlink.assert_not_called()
                self.assertEqual(b"KEEP", output.read_bytes())
                self.assertEqual([output], list(output.parent.iterdir()))

    def test_output_write_failure_has_no_temp_or_conditional_unlink_window(
        self,
    ) -> None:
        output = self.root / ".workingdir2/plans/plan.json"
        output.parent.mkdir(parents=True)
        original_write = os.write
        calls = 0

        def fail_after_partial_write(descriptor: int, raw: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(descriptor, raw[:4])
            raise OSError("injected write failure")

        with mock.patch.object(acquire.os, "unlink") as unsafe_unlink:
            with mock.patch.object(
                acquire.os, "write", side_effect=fail_after_partial_write
            ):
                with self.assertRaisesRegex(OSError, "injected write failure"):
                    acquire.write_plan_output(self.root, output, {"value": 1})
            unsafe_unlink.assert_not_called()
        self.assertEqual(
            acquire.json_output_bytes({"value": 1})[:4], output.read_bytes()
        )
        self.assertEqual([output], list(output.parent.iterdir()))

    def test_full_output_after_fsync_failure_is_durably_rehabilitated(self) -> None:
        output = self.root / ".workingdir2/plans/plan.json"
        value = {"value": 1}
        original_fsync = os.fsync
        failed = False

        def fail_first_fsync(descriptor: int) -> None:
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("injected fsync failure")
            original_fsync(descriptor)

        with mock.patch.object(acquire.os, "fsync", side_effect=fail_first_fsync):
            with self.assertRaisesRegex(OSError, "injected fsync failure"):
                acquire.write_plan_output(self.root, output, value)

        calls: list[str] = []

        def observe_fsync(descriptor: int) -> None:
            calls.append("fsync")
            original_fsync(descriptor)

        with mock.patch.object(acquire.os, "fsync", side_effect=observe_fsync):
            acquire.write_plan_output(self.root, output, value)

        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(acquire.json_output_bytes(value), output.read_bytes())

    def test_public_cli_is_plan_only_and_repo_root_is_not_overridable(self) -> None:
        for name in (
            "execute_plan",
            "execute_target",
            "run_command",
            "cached_snapshots",
            "validate_cached_snapshot",
            "source_tree_inventory",
        ):
            self.assertFalse(hasattr(acquire, name), name)
        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                acquire.parse_args(["run"])
            with self.assertRaises(SystemExit):
                acquire.parse_args(["plan", "--repo-root", str(self.root)])

    def test_accepted_denominator_allows_partial_record_acceptance(self) -> None:
        # Partial explicit coverage: a reviewed, accepted denominator may
        # carry a still-proposed record without hard-failing, and the accepted
        # record's target is authorized while the proposed record contributes no
        # target.
        self.write_record("cd.json", chart_record(chart="argo-cd", version="10.1.3"))
        proposed = chart_record(chart="argo-rollouts", version="2.41.0")
        proposed["review"]["status"] = "proposed"
        self.write_record("rollouts.json", proposed)
        self.write_record_set()

        def accept_denominator(manifest: dict[str, object]) -> None:
            manifest["review"]["status"] = "accepted"
            manifest["authority_state"] = "reviewed"

        self.rewrite_record_set(accept_denominator)
        plan = acquire.build_plan(
            self.root,
            self.records,
            {"deployed", "planned"},
            set(),
            self.record_set,
        )
        self.assertEqual(1, plan["counts"]["total"])
        self.assertEqual(1, plan["counts"]["ready"])
        self.assertEqual(0, plan["counts"]["blocked"])
        self.assertEqual(
            ["cmp:helm:argoproj/argo-cd"],
            [target["component_id"] for target in plan["targets"]],
        )
        self.assertEqual([], plan["gaps"])

    def test_unrelated_blocking_set_gap_does_not_revoke_accepted_target(self) -> None:
        # A set-level gap for an unrelated lane must not block an otherwise ready
        # chart target once the denominator is accepted.
        self.write_record("workflows.json", chart_record())
        self.write_record_set()

        def add_unrelated_gap(manifest: dict[str, object]) -> None:
            manifest["gaps"] = [
                {
                    "code": "argo-events-source-absent",
                    "target_id": "cmp:github:argoproj/argo-events",
                    "state": "absent",
                    "message": "Argo Events source lane is not represented",
                    "blocking": True,
                    "candidate_pointers": ["/scope/required_targets/1"],
                    "evidence": ["test-fixture:events-absent"],
                    "next_action": "materialize the Argo Events source lane",
                }
            ]
            manifest["counts"]["blocking_gaps"] = 1

        self.rewrite_record_set(add_unrelated_gap)
        plan = acquire.build_plan(
            self.root,
            self.records,
            {"deployed", "planned"},
            set(),
            self.record_set,
        )
        self.assertEqual(1, plan["counts"]["ready"])
        self.assertEqual([], plan["gaps"])

    def test_controller_record_is_deferred_not_authorized(self) -> None:
        self.write_record("workflows.json", runtime_record())
        plan = self.build()
        target = plan["targets"][0]
        self.assertEqual("blocked", target["state"])
        self.assertIn(
            "controller_acquisition_deferred",
            {issue["code"] for issue in target["gaps"]},
        )

    def test_non_commit_source_ref_fails_closed(self) -> None:
        record = chart_record()
        record["versions"][0]["source_ref"] = "refs/tags/argo-workflows-1.0.20"
        self.write_record("workflows.json", record)
        plan = self.build()
        self.assertEqual("blocked", plan["targets"][0]["state"])
        self.assertIn(
            "exact_commit_missing",
            {issue["code"] for issue in plan["targets"][0]["gaps"]},
        )

    def test_target_identity_is_repository_tag_commit_and_roots(self) -> None:
        record = chart_record()
        self.write_record("workflows.json", record)
        plan = self.build()
        target = plan["targets"][0]
        self.assertEqual("argoproj/argo-helm", target["repository"])
        self.assertEqual("argo-workflows-1.0.20", target["requested_tag"])
        self.assertEqual(record["versions"][0]["source_ref"], target["expected_commit"])
        self.assertEqual(["charts/argo-workflows"], target["content_roots"])
        self.assertEqual(
            {
                "repository": "argoproj/argo-helm",
                "requested_tag": "argo-workflows-1.0.20",
                "expected_commit": record["versions"][0]["source_ref"],
                "content_roots": ["charts/argo-workflows"],
            },
            target["target_identity"],
        )
        expected_id = (
            "source-acquisition-target:"
            + hashlib.sha256(
                acquire.canonical_bytes(
                    {
                        "repository": "argoproj/argo-helm",
                        "requested_tag": "argo-workflows-1.0.20",
                        "expected_commit": record["versions"][0]["source_ref"],
                        "content_roots": ["charts/argo-workflows"],
                    }
                )
            ).hexdigest()
        )
        self.assertEqual(expected_id, target["target_id"])

    def test_below_preserves_path_components_for_no_follow_open(self) -> None:
        directory = self.root / "directory"
        directory.mkdir()
        self.assertEqual(directory, acquire.below(self.root, Path("directory")))
        outside = self.root.parent / "outside"
        with self.assertRaises(ValueError):
            acquire.below(self.root, outside)


if __name__ == "__main__":
    unittest.main()
