from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
BUNDLE_MODULE_PATH = (
    REPO_ROOT / "tools/knowledge-registry/materialize_record_artifact_bundle.py"
)
ACQUIRE_MODULE_PATH = REPO_ROOT / "tools/knowledge-registry/acquire_sources.py"
ACCEPTANCE_RELATIVE = Path("knowledge/registry/acceptance/p1-src-02")
MANIFEST_RELATIVE = ACCEPTANCE_RELATIVE / "accepted-record-artifact-bundle.json"


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bundle = load_module("record_artifact_bundle", BUNDLE_MODULE_PATH)
acquire = load_module("acquire_sources_v3", ACQUIRE_MODULE_PATH)


class ArtifactBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.acceptance = self.root / ACCEPTANCE_RELATIVE
        self.copy_required_tree()
        self.write_fresh_manifest()

    def copy_required_tree(self) -> None:
        files = [
            "tools/knowledge-registry/materialize_record_artifact_bundle.py",
            "knowledge/registry/schemas/accepted-record-artifact-bundle.schema.json",
            "knowledge/registry/schemas/component-record.schema.json",
            "knowledge/registry/schemas/reviewed-record-set.schema.json",
            "knowledge/registry/schemas/source-acceptance-outcome.schema.json",
            "knowledge/registry/records/argo-argo-cd-chart.json",
            "knowledge/registry/records/argo-argo-rollouts-chart.json",
            "knowledge/registry/records/argo-argo-workflows-chart.json",
            "knowledge/registry/acceptance/p1-src-02/accepted-reviewed-record-set.json",
            "knowledge/registry/acceptance/p1-src-02/source-acceptance-outcome.json",
            "knowledge/registry/acceptance/p1-src-02/accepted-records/argo-argo-rollouts-chart.json",
            "knowledge/registry/acceptance/p1-src-02/accepted-records/argo-argo-workflows-chart.json",
        ]
        for relative in files:
            source = REPO_ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    @property
    def manifest_path(self) -> Path:
        return self.root / MANIFEST_RELATIVE

    def write_fresh_manifest(self) -> dict[str, Any]:
        derived = bundle.derive_bundle(self.root, self.acceptance)
        self.manifest_path.write_bytes(bundle.output_bytes(derived.manifest))
        return derived.manifest

    def rewrite_manifest(self, callback: Callable[[dict[str, Any]], None]) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        callback(manifest)
        core = {
            key: value
            for key, value in manifest.items()
            if key not in {"bundle_id", "payload_sha256"}
        }
        payload = bundle.sha256_bytes(bundle.canonical_bytes(core))
        manifest["payload_sha256"] = payload
        manifest["bundle_id"] = "accepted-record-artifact-bundle:" + payload
        self.manifest_path.write_bytes(bundle.output_bytes(manifest))

    def assert_manifest_rejected(
        self, callback: Callable[[dict[str, Any]], None], pattern: str
    ) -> None:
        self.rewrite_manifest(callback)
        with self.assertRaisesRegex((OSError, ValueError), pattern):
            bundle.resolve_bundle(self.root, self.manifest_path)

    def test_committed_bundle_is_exact_and_resolves_without_copy(self) -> None:
        derived = bundle.derive_bundle(REPO_ROOT, REPO_ROOT / ACCEPTANCE_RELATIVE)
        committed = (REPO_ROOT / MANIFEST_RELATIVE).read_bytes()
        self.assertEqual(bundle.output_bytes(derived.manifest), committed)
        resolved = bundle.resolve_bundle(REPO_ROOT, REPO_ROOT / MANIFEST_RELATIVE)
        self.assertEqual(derived.manifest, resolved.manifest)
        self.assertEqual(
            set(derived.records_by_logical_path),
            set(resolved.records_by_logical_path),
        )
        self.assertEqual(
            derived.record_bytes_by_logical_path,
            resolved.record_bytes_by_logical_path,
        )
        self.assertEqual(2, resolved.manifest["counts"]["accepted_records"])
        self.assertEqual(1, resolved.manifest["counts"]["retained_records"])

    def test_missing_and_extra_bundle_artifacts_fail_closed(self) -> None:
        accepted = self.acceptance / "accepted-records"
        (accepted / "argo-argo-workflows-chart.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing=.*workflows"):
            bundle.derive_bundle(self.root, self.acceptance)
        shutil.copyfile(
            REPO_ROOT
            / "knowledge/registry/acceptance/p1-src-02/accepted-records/argo-argo-workflows-chart.json",
            accepted / "argo-argo-workflows-chart.json",
        )
        (accepted / "extra.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "extra=.*extra.json"):
            bundle.derive_bundle(self.root, self.acceptance)

    def test_duplicate_manifest_mapping_is_rejected(self) -> None:
        def duplicate(value: dict[str, Any]) -> None:
            value["records"].append(copy.deepcopy(value["records"][1]))
            value["counts"]["records"] += 1
            value["counts"]["accepted_records"] += 1

        self.assert_manifest_rejected(duplicate, "deterministic materialization")

    def test_physical_alias_is_rejected_before_hash_trust(self) -> None:
        accepted = self.acceptance / "accepted-records"
        workflows = accepted / "argo-argo-workflows-chart.json"
        workflows.unlink()
        os.link(accepted / "argo-argo-rollouts-chart.json", workflows)
        with self.assertRaisesRegex(ValueError, "aliases or overlaps"):
            bundle.derive_bundle(self.root, self.acceptance)

    def test_swapped_manifest_locators_are_rejected(self) -> None:
        def swap(value: dict[str, Any]) -> None:
            first = value["records"][1]["artifact"]
            second = value["records"][2]["artifact"]
            value["records"][1]["artifact"] = copy.deepcopy(second)
            value["records"][2]["artifact"] = copy.deepcopy(first)

        self.assert_manifest_rejected(swap, "deterministic materialization")

    def test_symlink_artifact_is_never_followed(self) -> None:
        accepted = self.acceptance / "accepted-records"
        target = accepted / "argo-argo-workflows-chart.json"
        target.unlink()
        target.symlink_to(
            self.root / "knowledge/registry/records/argo-argo-workflows-chart.json"
        )
        with self.assertRaises(OSError):
            bundle.derive_bundle(self.root, self.acceptance)

    def test_typed_base_overlap_is_rejected(self) -> None:
        def overlap(value: dict[str, Any]) -> None:
            entry = value["records"][1]
            entry["artifact"]["base"] = "repository"
            entry["artifact"]["path"] = entry["logical_path"]

        self.assert_manifest_rejected(overlap, "deterministic materialization")

    def test_manifest_hash_and_size_tampering_are_rejected(self) -> None:
        self.assert_manifest_rejected(
            lambda value: value["records"][1]["artifact"].__setitem__(
                "content_sha256", "sha256:" + "0" * 64
            ),
            "deterministic materialization",
        )
        self.write_fresh_manifest()
        self.assert_manifest_rejected(
            lambda value: value["records"][1]["artifact"].__setitem__(
                "bytes", value["records"][1]["artifact"]["bytes"] + 1
            ),
            "deterministic materialization",
        )

    def test_physical_content_tamper_fails_the_set_hash(self) -> None:
        retained = self.root / "knowledge/registry/records/argo-argo-cd-chart.json"
        retained.write_bytes(retained.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "record artifact hash mismatch"):
            bundle.derive_bundle(self.root, self.acceptance)

    def test_noncanonical_manifest_serialization_is_rejected(self) -> None:
        value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.manifest_path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "serialized bytes are not canonical"):
            bundle.resolve_bundle(self.root, self.manifest_path)

    def test_resolver_rejects_control_artifact_swaps_after_validation(self) -> None:
        original_derive = bundle.derive_bundle
        for relative in (
            "accepted-reviewed-record-set.json",
            "source-acceptance-outcome.json",
        ):
            with self.subTest(relative=relative):
                target = self.acceptance / relative
                original_raw = target.read_bytes()

                def swap_after_validation(*args: Any, **kwargs: Any) -> Any:
                    derived = original_derive(*args, **kwargs)
                    target.write_bytes(b"{}\n")
                    return derived

                try:
                    with mock.patch.object(
                        bundle, "derive_bundle", side_effect=swap_after_validation
                    ):
                        with self.assertRaisesRegex(ValueError, "changed during"):
                            bundle.resolve_bundle(self.root, self.manifest_path)
                finally:
                    target.write_bytes(original_raw)

    def test_accepted_directory_swap_with_extra_entry_is_rejected(self) -> None:
        accepted = self.acceptance / "accepted-records"
        replacement = self.acceptance / "replacement-records"
        backup = self.acceptance / "accepted-records-original"
        shutil.copytree(accepted, replacement)
        (replacement / "extra.json").write_text("{}\n", encoding="utf-8")
        original_reader = bundle.read_relative_regular
        swapped = False

        def swap_directory(*args: Any, **kwargs: Any) -> Any:
            nonlocal swapped
            captured = original_reader(*args, **kwargs)
            if not swapped and kwargs.get("label", "").endswith(
                "argo-argo-rollouts-chart.json"
            ):
                accepted.rename(backup)
                replacement.rename(accepted)
                swapped = True
            return captured

        with mock.patch.object(
            bundle, "read_relative_regular", side_effect=swap_directory
        ):
            with self.assertRaisesRegex(ValueError, "directory changed"):
                bundle.derive_bundle(self.root, self.acceptance)
        self.assertTrue(swapped)

    def test_exclusive_output_preserves_preexisting_bytes(self) -> None:
        output = self.root / ".workingdir2/cache/bundle.json"
        output.parent.mkdir(parents=True)
        output.write_bytes(b"KEEP")
        with self.assertRaises(FileExistsError):
            bundle.write_exclusive_scratch(self.root, output, b"new")
        self.assertEqual(b"KEEP", output.read_bytes())

    def test_exclusive_output_preserves_replacement_inode_on_failure(self) -> None:
        output = self.root / ".workingdir2/cache/bundle.json"
        output.parent.mkdir(parents=True)
        original_unlink = os.unlink

        def replace_and_fail(*args: Any, **kwargs: Any) -> None:
            original_unlink(output)
            output.write_bytes(b"KEEP")
            raise ValueError("injected parent verification failure")

        with mock.patch.object(bundle.os, "unlink") as unsafe_unlink:
            with mock.patch.object(
                bundle, "verify_directory_path", side_effect=replace_and_fail
            ):
                with self.assertRaisesRegex(ValueError, "injected"):
                    bundle.write_exclusive_scratch(self.root, output, b"new")
            unsafe_unlink.assert_not_called()
        self.assertEqual(b"KEEP", output.read_bytes())

    def test_exclusive_output_write_failure_retains_leaf_without_unlink(self) -> None:
        output = self.root / ".workingdir2/cache/bundle.json"
        output.parent.mkdir(parents=True)
        original_write = os.write
        calls = 0

        def fail_after_partial_write(descriptor: int, raw: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(descriptor, raw[:1])
            raise OSError("injected write failure")

        with mock.patch.object(bundle.os, "unlink") as unsafe_unlink:
            with mock.patch.object(
                bundle.os, "write", side_effect=fail_after_partial_write
            ):
                with self.assertRaisesRegex(OSError, "injected write failure"):
                    bundle.write_exclusive_scratch(self.root, output, b"new")
            unsafe_unlink.assert_not_called()
        self.assertEqual(b"n", output.read_bytes())
        self.assertEqual([output], list(output.parent.iterdir()))

    def test_exclusive_output_replays_before_and_after_parent_fsync(self) -> None:
        output = self.root / ".workingdir2/cache/bundle.json"
        output.parent.mkdir(parents=True)
        events: list[str] = []
        original_fsync = os.fsync
        original_reader = bundle.read_relative_regular

        def observe_fsync(descriptor: int) -> None:
            events.append("fsync")
            original_fsync(descriptor)

        def observe_replay(*args: Any, **kwargs: Any) -> Any:
            events.append("replay")
            return original_reader(*args, **kwargs)

        with mock.patch.object(bundle.os, "fsync", side_effect=observe_fsync):
            with mock.patch.object(
                bundle, "read_relative_regular", side_effect=observe_replay
            ):
                bundle.write_exclusive_scratch(self.root, output, b"new")

        self.assertEqual(["fsync", "replay", "fsync", "replay"], events)
        self.assertEqual(b"new", output.read_bytes())


class PlanV3Test(unittest.TestCase):
    def build(self, components: list[str] | None = None) -> dict[str, Any]:
        return acquire.build_plan_v3(
            REPO_ROOT,
            REPO_ROOT / MANIFEST_RELATIVE,
            components
            or [
                "cmp:helm:argoproj/argo-rollouts",
                "cmp:helm:argoproj/argo-workflows",
            ],
        )

    def validator(self) -> tuple[Any, Any]:
        resolver, _digest, _expected = acquire.load_artifact_bundle_resolver(REPO_ROOT)
        schema = json.loads(
            (REPO_ROOT / acquire.PLAN_V3_SCHEMA_SOURCE).read_text(encoding="utf-8")
        )
        return resolver, resolver.Draft202012Validator(schema)

    def readdress(self, plan: dict[str, Any]) -> None:
        core = {
            key: value
            for key, value in plan.items()
            if key not in {"plan_id", "plan_payload_sha256"}
        }
        payload = acquire.sha256_bytes(acquire.canonical_bytes(core))
        plan["plan_payload_sha256"] = payload
        plan["plan_id"] = "source-acquisition-plan:" + payload

    def test_v3_is_reproducible_explicit_and_legacy_v2_is_unchanged(self) -> None:
        first = self.build()
        second = self.build(
            [
                "cmp:helm:argoproj/argo-workflows",
                "cmp:helm:argoproj/argo-rollouts",
            ]
        )
        self.assertEqual(first, second)
        self.assertEqual("3.0.0", first["schema_version"])
        self.assertEqual("5", first["generator"]["version"])
        self.assertEqual(2, first["counts"]["ready"])
        self.assertEqual(
            "sha256:dbc41fe166ae7672119d2655b57be528151474cad8edb4c8332a95c6f5151889",
            first["acquisition_capability"]["capability_contract_sha256"],
        )
        self.assertTrue(
            all(
                not acquire.LEGACY_FETCH_FIELDS.intersection(target)
                for target in first["targets"]
            )
        )
        self.assertEqual("2.0.0", acquire.PLAN_SCHEMA_VERSION)
        self.assertEqual("4", acquire.GENERATOR_VERSION)
        self.assertEqual(
            {
                "execution_authorized": False,
                "network_access": False,
                "cache_mutation": False,
                "inventory_emission": False,
            },
            first["execution_boundary"],
        )
        manifest = json.loads((REPO_ROOT / MANIFEST_RELATIVE).read_text("utf-8"))
        artifacts = {
            item["component_id"]: item["artifact"] for item in manifest["records"]
        }
        for target in first["targets"]:
            artifact = artifacts[target["component_id"]]
            self.assertEqual(artifact, target["record_artifact"])
            self.assertEqual(artifact["content_sha256"], target["record_sha256"])
            self.assertEqual(
                first["artifact_bundle"]["bundle_id"], target["artifact_bundle_id"]
            )
            self.assertNotEqual(
                acquire.file_sha256(REPO_ROOT / target["record_logical_path"]),
                target["record_sha256"],
            )

    def test_v3_rejects_implicit_empty_and_duplicate_selection(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit non-empty"):
            acquire.build_plan_v3(REPO_ROOT, REPO_ROOT / MANIFEST_RELATIVE, [])
        with self.assertRaisesRegex(ValueError, "empty identity"):
            acquire.build_plan_v3(REPO_ROOT, REPO_ROOT / MANIFEST_RELATIVE, [""])
        with self.assertRaisesRegex(ValueError, "duplicate identity"):
            acquire.build_plan_v3(
                REPO_ROOT,
                REPO_ROOT / MANIFEST_RELATIVE,
                [
                    "cmp:helm:argoproj/argo-rollouts",
                    "cmp:helm:argoproj/argo-rollouts",
                ],
            )

    def test_v3_rejects_proposed_and_unknown_selection(self) -> None:
        with self.assertRaisesRegex(ValueError, "not accepted"):
            acquire.build_plan_v3(
                REPO_ROOT,
                REPO_ROOT / MANIFEST_RELATIVE,
                ["cmp:helm:argoproj/argo-cd"],
            )
        with self.assertRaisesRegex(ValueError, "absent"):
            acquire.build_plan_v3(
                REPO_ROOT,
                REPO_ROOT / MANIFEST_RELATIVE,
                ["cmp:helm:argoproj/not-present"],
            )

    def test_v3_rejects_a_blocked_selected_target(self) -> None:
        original = acquire.plan_target

        def blocked(*args: Any, **kwargs: Any) -> dict[str, Any]:
            target = original(*args, **kwargs)
            target["state"] = "blocked"
            target["gaps"] = [
                {"code": "test_block", "blocking": True, "message": "blocked"}
            ]
            return target

        with mock.patch.object(acquire, "plan_target", side_effect=blocked):
            with self.assertRaisesRegex(ValueError, "requested component is blocked"):
                self.build(["cmp:helm:argoproj/argo-rollouts"])

    def test_v3_schema_rejects_legacy_adapter_fields(self) -> None:
        plan = self.build(["cmp:helm:argoproj/argo-rollouts"])
        plan["targets"][0][
            "fetch_adapter"
        ] = "docs/fetch-docs.sh:argo-chart-snapshot-v1"
        self.readdress(plan)
        resolver, validator = self.validator()
        with self.assertRaisesRegex(ValueError, "legacy adapter|schema failure"):
            acquire.validate_plan_v3(resolver, validator, plan)

    def test_v3_validator_rejects_readdressed_semantic_tampering(self) -> None:
        resolver, validator = self.validator()

        def wrong_count(plan: dict[str, Any]) -> None:
            plan["counts"]["total"] = 2

        def wrong_selection(plan: dict[str, Any]) -> None:
            plan["selection"]["component_ids"] = ["cmp:helm:argoproj/argo-workflows"]

        def wrong_root(plan: dict[str, Any]) -> None:
            target = plan["targets"][0]
            target["content_roots"] = ["charts/argo-workflows"]
            target["target_identity"]["content_roots"] = ["charts/argo-workflows"]
            target["target_id"] = (
                "source-acquisition-target:"
                + hashlib.sha256(
                    acquire.canonical_bytes(target["target_identity"])
                ).hexdigest()
            )

        def wrong_record_path(plan: dict[str, Any]) -> None:
            plan["targets"][0][
                "record_logical_path"
            ] = "knowledge/registry/records/argo-argo-workflows-chart.json"

        def wrong_artifact(plan: dict[str, Any]) -> None:
            plan["targets"][0]["record_artifact"][
                "path"
            ] = "accepted-records/argo-argo-workflows-chart.json"

        cases = (
            (wrong_count, "counts differ"),
            (wrong_selection, "selection differs"),
            (wrong_root, "content root differs"),
            (wrong_record_path, "logical record path differs"),
            (wrong_artifact, "typed record artifact"),
        )
        for mutate, pattern in cases:
            with self.subTest(pattern=pattern):
                plan = self.build(["cmp:helm:argoproj/argo-rollouts"])
                mutate(plan)
                self.readdress(plan)
                with self.assertRaisesRegex(ValueError, pattern):
                    acquire.validate_plan_v3(resolver, validator, plan)

    def test_v3_generator_rederives_the_bundle_byte_projection(self) -> None:
        plan = self.build(["cmp:helm:argoproj/argo-rollouts"])
        plan["targets"][0]["record_sha256"] = "sha256:" + "0" * 64
        plan["targets"][0]["record_artifact"]["content_sha256"] = "sha256:" + "0" * 64
        self.readdress(plan)
        with self.assertRaisesRegex(ValueError, "artifact-bundle projection"):
            acquire.verify_plan_v3_generator(REPO_ROOT, plan)

    def test_v3_schema_rejects_execution_authorization(self) -> None:
        plan = self.build(["cmp:helm:argoproj/argo-rollouts"])
        plan["execution_boundary"]["execution_authorized"] = True
        self.readdress(plan)
        resolver, validator = self.validator()
        with self.assertRaisesRegex(ValueError, "schema failure"):
            acquire.validate_plan_v3(resolver, validator, plan)

    def test_cli_requires_bundle_and_explicit_components(self) -> None:
        with mock.patch("sys.stderr"):
            self.assertEqual(2, acquire.main(["plan-v3"]))
            self.assertEqual(
                2,
                acquire.main(
                    [
                        "plan-v3",
                        "--artifact-bundle",
                        MANIFEST_RELATIVE.as_posix(),
                    ]
                ),
            )

    def test_plan_v3_rejects_every_legacy_projection_flag(self) -> None:
        prefix = [
            "plan-v3",
            "--artifact-bundle",
            MANIFEST_RELATIVE.as_posix(),
        ]
        legacy_flags = (
            ["--records", "knowledge/registry/records"],
            ["--record-set", "knowledge/registry/record-sets/argo-p1-src-02.json"],
            ["--require-complete"],
        )
        with mock.patch("sys.stderr"):
            for legacy_flag in legacy_flags:
                with self.subTest(legacy_flag=legacy_flag):
                    self.assertEqual(2, acquire.main([*prefix, *legacy_flag]))


if __name__ == "__main__":
    unittest.main()
