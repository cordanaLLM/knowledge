from __future__ import annotations

import ast
import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = (
    REPO_ROOT / "tools/knowledge-registry/materialize_argo_source_resolution.py"
)
BASE_TEST_PATH = (
    REPO_ROOT / "tools/knowledge-registry/tests/test_materialize_argo_record_set.py"
)
PLANNER_PATH = REPO_ROOT / "tools/knowledge-registry/acquire_sources.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


materializer = load_module("materialize_argo_source_resolution", MODULE_PATH)
base_test = load_module("materialize_argo_record_set_test_fixture", BASE_TEST_PATH)
planner = load_module("acquire_sources_for_proposed_resolution_test", PLANNER_PATH)

EXPECTED_TAGS = {
    "argocd": "v3.4.5",
    "argo-rollouts": "v1.9.0",
    "kubectl-argo-rollouts": "v1.9.0",
    "workflow-controller": "v4.0.7",
    "argoexec": "v4.0.7",
    "argocli": "v4.0.7",
}


def resolution_candidate() -> dict[str, object]:
    candidate = base_test.synthetic_candidate()
    components = candidate["components"]
    versions = candidate["versions"]
    occurrences = candidate["occurrences"]
    assert isinstance(components, list)
    assert isinstance(versions, list)
    assert isinstance(occurrences, list)

    existing: set[str] = set()
    for component in components:
        if not isinstance(component, dict) or component.get("kind") != "oci-image":
            continue
        name = str(component["name"])
        if name not in EXPECTED_TAGS:
            continue
        existing.add(name)
        component_id = component["component_id"]
        for version in versions:
            if (
                isinstance(version, dict)
                and version.get("component_id") == component_id
                and "resolved_version" in version
            ):
                version["resolved_version"] = EXPECTED_TAGS[name]

    for name in sorted(set(EXPECTED_TAGS) - existing):
        component_id = f"cmp-test-runtime-{name}"
        tag_id = f"ver-test-runtime-{name}-tag"
        digest_id = f"ver-test-runtime-{name}-digest"
        components.append(
            {
                "component_id": component_id,
                "kind": "oci-image",
                "namespace": "quay.io/argoproj",
                "name": name,
            }
        )
        versions.extend(
            [
                {
                    "component_id": component_id,
                    "component_version_id": tag_id,
                    "resolved_version": EXPECTED_TAGS[name],
                    "resolution_state": "unresolved",
                    "evidence": [f"candidate:{name}:tag"],
                },
                {
                    "component_id": component_id,
                    "component_version_id": digest_id,
                    "artifact_digest": "sha256:" + "c" * 64,
                    "resolution_state": "resolved",
                    "evidence": [f"candidate:{name}:digest"],
                },
            ]
        )
        occurrences.extend(
            [
                {
                    "component_version_id": tag_id,
                    "occurrence_id": f"occ-test-runtime-{name}-tag",
                    "role": "live-container-desired-image",
                },
                {
                    "component_version_id": digest_id,
                    "occurrence_id": f"occ-test-runtime-{name}-digest",
                    "role": "live-container-imageid",
                },
            ]
        )

    collections = (
        "components",
        "dependency_edges",
        "gaps",
        "occurrences",
        "sources",
        "versions",
    )
    counts = {name: len(candidate[name]) for name in collections}
    candidate["counts"] = counts
    candidate["integrity"]["exact_counts"] = counts
    return candidate


def capture_inputs() -> tuple[dict[str, object], dict[str, object]]:
    capture_result = {
        "state": "complete",
        "unavailable_surfaces": [],
        "captured_surfaces": list(materializer.base.REQUIRED_SURFACES),
        "inputs": [{} for _ in range(145)],
        "capture_manifest": "capture-manifest.json",
    }
    capture_manifest = {
        "record_kind": "live_capture_manifest",
        "contract_version": 3,
        "git_commit": materializer.base.EXPECTED_GENERATOR_COMMIT,
        "observed_at": materializer.base.EXPECTED_OBSERVED_AT,
        "required_surfaces": list(materializer.base.REQUIRED_SURFACES),
        "surfaces": {
            name: {"state": "captured"} for name in materializer.base.REQUIRED_SURFACES
        },
    }
    return capture_result, capture_manifest


class MaterializeArgoSourceResolutionTest(unittest.TestCase):
    def build(
        self, candidate: dict[str, object] | None = None
    ) -> tuple[dict[str, bytes], dict[str, object]]:
        candidate = candidate or resolution_candidate()
        capture_result, capture_manifest = capture_inputs()
        component_schema_raw = (
            REPO_ROOT / materializer.base.COMPONENT_SCHEMA_SOURCE
        ).read_bytes()
        record_set_schema_raw = (
            REPO_ROOT / materializer.base.RECORD_SET_SCHEMA_SOURCE
        ).read_bytes()
        component_schema = materializer.base.strict_json_loads(component_schema_raw)
        record_set_schema = materializer.base.strict_json_loads(record_set_schema_raw)
        with mock.patch.object(
            materializer.base, "EXPECTED_COUNTS", candidate["counts"]
        ):
            return materializer.build_resolution_set(
                materializer.base.output_bytes(candidate),
                candidate,
                materializer.base.output_bytes(capture_result),
                capture_result,
                materializer.base.output_bytes(capture_manifest),
                capture_manifest,
                MODULE_PATH.read_bytes(),
                materializer.BASE_PATH.read_bytes(),
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
                materializer.base.schema_validator(
                    component_schema, "component schema"
                ),
                materializer.base.schema_validator(
                    record_set_schema, "record-set schema"
                ),
            )

    @staticmethod
    def bindings_for(
        records: dict[str, bytes],
        record_set: dict[str, object],
        entry: dict[str, object],
    ) -> list[dict[str, object]]:
        record = json.loads(records[Path(entry["path"]).name])
        return materializer.reconstruct_normalized_bindings(
            record, entry, record_set["binding_ledger"]
        )

    def test_output_is_deterministic_proposed_and_fully_bound(self) -> None:
        first_records, first_set = self.build()
        second_records, second_set = self.build()
        self.assertEqual(first_records, second_records)
        self.assertEqual(first_set, second_set)
        self.assertEqual("proposed", first_set["review"]["status"])
        self.assertEqual("non_authoritative", first_set["authority_state"])
        self.assertEqual(0, first_set["counts"]["accepted_records"])
        self.assertFalse(first_set["compile_eligible"])
        self.assertFalse(first_set["promote_eligible"])
        self.assertEqual(
            materializer.base.sha256_bytes(materializer.BASE_PATH.read_bytes()),
            first_set["generator"]["base_materializer_sha256"],
        )
        self.assertEqual(2, first_set["binding_ledger"]["version"])
        self.assertEqual(
            sorted(atom["atom_id"] for atom in first_set["binding_ledger"]["atoms"]),
            [atom["atom_id"] for atom in first_set["binding_ledger"]["atoms"]],
        )

        for entry in first_set["records"]:
            record = json.loads(first_records[Path(entry["path"]).name])
            bindings = self.bindings_for(first_records, first_set, entry)
            pointers = [binding["record_pointer"] for binding in bindings]
            self.assertEqual(materializer.base.leaf_pointers(record), pointers)
            self.assertEqual(len(pointers), len(set(pointers)))
            self.assertEqual(len(pointers), entry["binding_ledger"]["tuple_count"])
            self.assertTrue(
                any(
                    binding["binding_kind"] == "primary-source"
                    and binding["source_uri"]
                    for binding in bindings
                )
            )
            self.assertEqual("proposed", record["review"]["status"])
            self.assertTrue(all(gap["blocking"] for gap in record["gaps"]))
            self.assertTrue(
                all(
                    channel["availability_state"] == "unresolved"
                    and channel["review_state"] == "proposed"
                    for channel in record["channels"]
                )
            )

        expanded = copy.deepcopy(first_set)
        ledger = expanded.pop("binding_ledger")
        for entry in expanded["records"]:
            record = json.loads(first_records[Path(entry["path"]).name])
            bindings = materializer.reconstruct_normalized_bindings(
                record, entry, ledger
            )
            entry.pop("binding_ledger")
            entry["bindings"] = bindings
            entry["bindings_sha256"] = materializer.base.sha256_bytes(
                materializer.base.canonical_bytes(bindings)
            )
        compact_size = len(materializer.compact_record_set_bytes(first_set))
        expanded_size = len(materializer.base.output_bytes(expanded))
        self.assertLessEqual(compact_size, expanded_size * 0.08)
        self.assertLess(compact_size, planner.MAX_JSON_BYTES)

    def test_generator_name_source_pairing_fails_closed(self) -> None:
        _records, record_set = self.build()
        schema = materializer.base.strict_json_loads(
            (REPO_ROOT / materializer.base.RECORD_SET_SCHEMA_SOURCE).read_bytes()
        )
        validator = materializer.base.schema_validator(schema, "record-set schema")
        mismatched = copy.deepcopy(record_set)
        mismatched["generator"][
            "source"
        ] = "tools/knowledge-registry/materialize_argo_record_set.py"
        self.assertTrue(list(validator.iter_errors(mismatched)))

    def test_exact_chart_and_runtime_resolution_facts_are_preserved(self) -> None:
        records, record_set = self.build()
        entries = {Path(item["path"]).name: item for item in record_set["records"]}
        expected_runtimes = {
            "argo-cd": {"argocd"},
            "argo-rollouts": {"argo-rollouts", "kubectl-argo-rollouts"},
            "argo-workflows": {"workflow-controller", "argoexec", "argocli"},
        }
        for chart, facts in materializer.CHART_FACTS.items():
            record = json.loads(records[f"argo-{chart}-chart.json"])
            source = record["versions"][0]["build_metadata"]["source_resolution"]
            self.assertEqual(facts["chart_tag"], source["chart"]["tag"])
            self.assertEqual(facts["chart_commit"], source["chart"]["commit"])
            self.assertEqual(
                facts["package_sha256"],
                source["chart"]["package"]["content_sha256"],
            )
            self.assertEqual(
                facts["provenance_sha256"],
                source["chart"]["provenance"]["content_sha256"],
            )
            self.assertEqual(
                materializer.PGP_FINGERPRINT,
                source["chart"]["provenance"]["pgp_fingerprint"],
            )
            self.assertFalse(
                source["chart"]["provenance"]["signature_verified_by_this_materializer"]
            )
            self.assertEqual(facts["app_version"], source["upstream"]["tag"])
            self.assertEqual(facts["upstream_commit"], source["upstream"]["commit"])
            channels = {
                channel["channel_type"]: channel for channel in record["channels"]
            }
            self.assertNotIn("readthedocs", channels["docs"]["canonical_uri"])
            self.assertEqual(
                materializer.github_at(
                    facts["upstream_repo"], facts["upstream_commit"], "docs"
                ),
                channels["docs"]["canonical_uri"],
            )
            self.assertEqual(
                expected_runtimes[chart],
                {
                    item["candidate_component"]["name"]
                    for item in source["runtime_mapping"]["components"]
                },
            )
            for item in source["runtime_mapping"]["components"]:
                admission = item["source_admission"]
                self.assertIsNone(admission["oci_manifest_digest"])
                self.assertFalse(admission["digest_to_source_verified"])
                self.assertFalse(admission["sbom_verified"])
                self.assertFalse(admission["cosign_verified"])
                self.assertFalse(admission["slsa_verified"])
                self.assertEqual("blocked", admission["state"])
            bindings = self.bindings_for(
                records, record_set, entries[f"argo-{chart}-chart.json"]
            )
            by_pointer = {item["record_pointer"]: item for item in bindings}
            root = "/versions/0/build_metadata/source_resolution/runtime_mapping/components"
            for index, _item in enumerate(source["runtime_mapping"]["components"]):
                self.assertEqual(
                    "derived",
                    by_pointer[f"{root}/{index}/canonical_runtime_id"]["binding_kind"],
                )
                for field in ("upstream_tag", "upstream_commit"):
                    binding = by_pointer[f"{root}/{index}/source_admission/{field}"]
                    self.assertEqual("primary-source", binding["binding_kind"])
                    self.assertIsNotNone(binding["source_uri"])
            for binding in bindings:
                if binding["binding_kind"] in {
                    "candidate-pointer",
                    "capture-pointer",
                }:
                    self.assertIsNotNone(binding["source_pointer"])
                    self.assertIsNone(binding["source_uri"])
                elif binding["binding_kind"] == "primary-source":
                    self.assertIsNone(binding["source_pointer"])
                    self.assertIsNotNone(binding["source_uri"])
                elif binding["binding_kind"] == "control":
                    self.assertIsNone(binding["source_pointer"])
                    self.assertIsNone(binding["source_uri"])

        rollouts = json.loads(records["argo-argo-rollouts-chart.json"])
        rollouts_channels = {
            item["channel_type"]: item for item in rollouts["channels"]
        }
        self.assertTrue(
            rollouts_channels["schema"]["canonical_uri"].endswith("/manifests/crds")
        )
        workflows = json.loads(records["argo-argo-workflows-chart.json"])
        workflows_channels = {
            item["channel_type"]: item for item in workflows["channels"]
        }
        self.assertTrue(
            workflows_channels["api"]["canonical_uri"].endswith(
                "/api/openapi-spec/swagger.json"
            )
        )
        self.assertIn("/blob/", workflows_channels["api"]["canonical_uri"])
        self.assertTrue(
            workflows_channels["schema"]["canonical_uri"].endswith(
                "/manifests/base/crds"
            )
        )
        schema_variants = workflows["versions"][0]["build_metadata"][
            "source_resolution"
        ]["upstream"]["schema_variants"]
        self.assertTrue(
            schema_variants["full_uri"].endswith("/manifests/base/crds/full")
        )
        self.assertTrue(
            schema_variants["minimal_uri"].endswith("/manifests/base/crds/minimal")
        )
        self.assertIsNone(schema_variants["selected_variant"])
        cd_record = json.loads(records["argo-argo-cd-chart.json"])
        redis = cd_record["versions"][0]["build_metadata"]["source_resolution"][
            "chart"
        ]["third_party_dependencies"][0]
        self.assertEqual("redis-ha", redis["name"])
        self.assertEqual("4.38.0", redis["version"])
        self.assertEqual(
            "sha256:0d8b0161248c5ab2c77d62fc77d5ca28393f73f7b7a8abd5474b78bc969cab39",
            redis["chart_lock_digest"],
        )
        self.assertIsNone(redis["rights"])
        self.assertEqual("unresolved", redis["rights_state"])
        self.assertFalse(redis["inherit_argo_apache_license"])
        self.assertEqual(13, record_set["counts"]["blocking_gaps"])
        runtime_gap_counts = {
            runtime_id: sum(
                gap["target_id"] == runtime_id and gap["blocking"]
                for gap in record_set["gaps"]
            )
            for runtime_id in materializer.RUNTIME_COMPONENTS.values()
        }
        self.assertEqual(
            {runtime_id: 2 for runtime_id in materializer.RUNTIME_COMPONENTS.values()},
            runtime_gap_counts,
        )
        self.assertTrue(
            any(
                gap["target_id"] == "cmp:github:argoproj/argo-events"
                and gap["state"] == "absent"
                for gap in record_set["gaps"]
            )
        )

    def test_missing_runtime_tag_or_digest_fails_closed(self) -> None:
        missing_tag = resolution_candidate()
        for version in missing_tag["versions"]:
            if (
                version.get("component_id") == "cmp-test-runtime-argocd"
                and "resolved_version" in version
            ):
                version["resolved_version"] = "v0.0.0"
        with self.assertRaisesRegex(ValueError, "lacks v3.4.5"):
            self.build(missing_tag)

        missing_digest = resolution_candidate()
        component = next(
            item
            for item in missing_digest["components"]
            if item.get("kind") == "oci-image"
            and item.get("name") == "workflow-controller"
        )
        for version in missing_digest["versions"]:
            if version.get("component_id") == component["component_id"]:
                version.pop("artifact_digest", None)
        with self.assertRaisesRegex(ValueError, "lacks observed digests"):
            self.build(missing_digest)

    def test_events_presence_fails_closed(self) -> None:
        candidate = resolution_candidate()
        candidate["components"].append(
            {
                "component_id": "cmp-test-argo-events",
                "kind": "helm-chart",
                "name": "argo-events",
            }
        )
        counts = copy.deepcopy(candidate["counts"])
        counts["components"] += 1
        candidate["counts"] = counts
        candidate["integrity"]["exact_counts"] = counts
        with self.assertRaisesRegex(ValueError, "Argo Events unexpectedly exists"):
            self.build(candidate)

    def test_planner_reconstructs_and_adversarially_validates_v2_ledger(self) -> None:
        records, record_set = self.build()
        records_by_path = {
            entry["path"]: json.loads(records[Path(entry["path"]).name])
            for entry in record_set["records"]
        }
        registry = planner.load_reviewed_contract()[0]
        reconstructed = planner.validate_v2_binding_ledger(
            record_set, records_by_path, registry
        )
        self.assertEqual(set(records_by_path), set(reconstructed))

        def reject(value: dict[str, object], message: str) -> None:
            with self.assertRaisesRegex(ValueError, message):
                planner.validate_v2_binding_ledger(value, records_by_path, registry)

        def rehash(value: dict[str, object]) -> None:
            ledger = value["binding_ledger"]
            atoms = ledger["atoms"]
            logical_ledger: list[dict[str, object]] = []
            for entry in sorted(value["records"], key=lambda item: item["path"]):
                record = records_by_path[entry["path"]]
                leafs = planner.leaf_pointers(record)
                bindings = []
                for pointer, item in zip(
                    leafs, entry["binding_ledger"]["tuples"], strict=True
                ):
                    atom = atoms[item[0]]
                    source_pointer = item[1] if len(item) == 2 else None
                    bindings.append(
                        planner.normalized_logical_binding(
                            pointer, atom, source_pointer
                        )
                    )
                entry["binding_ledger"]["logical_bindings_sha256"] = (
                    planner.sha256_bytes(planner.canonical_bytes(bindings))
                )
                logical_ledger.append({"path": entry["path"], "bindings": bindings})
            ledger["logical_ledger_sha256"] = planner.sha256_bytes(
                planner.canonical_bytes(logical_ledger)
            )

        changed = copy.deepcopy(record_set)
        changed["binding_ledger"]["atoms"][0]["atom_id"] = (
            "binding-atom:sha256:" + "0" * 64
        )
        reject(changed, "content identity")

        changed = copy.deepcopy(record_set)
        changed["binding_ledger"]["atoms"].reverse()
        reject(changed, "uniquely sorted")

        changed = copy.deepcopy(record_set)
        changed["binding_ledger"]["atom_count"] += 1
        reject(changed, "atom count")

        changed = copy.deepcopy(record_set)
        changed["records"][0]["binding_ledger"]["tuples"][0][0] = len(
            changed["binding_ledger"]["atoms"]
        )
        reject(changed, "atom index")

        changed = copy.deepcopy(record_set)
        changed["records"][0]["binding_ledger"]["leaf_count"] += 1
        reject(changed, "leaf count")

        changed = copy.deepcopy(record_set)
        changed["records"][0]["binding_ledger"]["leaf_pointers_sha256"] = (
            "sha256:" + "0" * 64
        )
        reject(changed, "leaf enumeration")

        changed = copy.deepcopy(record_set)
        changed["records"][0]["binding_ledger"]["logical_bindings_sha256"] = (
            "sha256:" + "0" * 64
        )
        reject(changed, "logical binding digest")

        changed = copy.deepcopy(record_set)
        changed["binding_ledger"]["logical_ledger_sha256"] = "sha256:" + "0" * 64
        reject(changed, "full logical ledger digest")

        changed = copy.deepcopy(record_set)
        pointer_atom = next(
            atom
            for atom in changed["binding_ledger"]["atoms"]
            if atom["binding_kind"] == "candidate-pointer"
        )
        pointer_atom["evidence_identity_prefix"] = (
            "accepted-candidate:sha256:" + "0" * 64
        )
        reject(changed, "evidence identity")

        changed = copy.deepcopy(record_set)
        primary_atom = next(
            atom
            for atom in changed["binding_ledger"]["atoms"]
            if atom["binding_kind"] == "primary-source"
        )
        primary_atom.pop("source_uri")
        reject(changed, "primary atom fields")

        changed = copy.deepcopy(record_set)
        primary_atom = next(
            atom
            for atom in changed["binding_ledger"]["atoms"]
            if atom["binding_kind"] == "primary-source"
        )
        primary_atom["source_uri"] += "?token=not-a-secret"
        reject(changed, "URI is unsafe")

        changed = copy.deepcopy(record_set)
        candidate_index = next(
            index
            for index, atom in enumerate(changed["binding_ledger"]["atoms"])
            if atom["binding_kind"] == "candidate-pointer"
        )
        candidate_tuple = next(
            item
            for entry in changed["records"]
            for item in entry["binding_ledger"]["tuples"]
            if item[0] == candidate_index
        )
        candidate_tuple.pop()
        reject(changed, "pointer tuple payload")

        changed = copy.deepcopy(record_set)
        primary_index = next(
            index
            for index, atom in enumerate(changed["binding_ledger"]["atoms"])
            if atom["binding_kind"] == "primary-source"
        )
        primary_tuple = next(
            item
            for entry in changed["records"]
            for item in entry["binding_ledger"]["tuples"]
            if item[0] == primary_index
        )
        primary_tuple.append("/forbidden")
        reject(changed, "non-pointer tuple payload")

        changed = copy.deepcopy(record_set)
        control_index = next(
            index
            for index, atom in enumerate(changed["binding_ledger"]["atoms"])
            if atom["binding_kind"] == "control"
        )
        first_entry = changed["records"][0]
        first_leafs = planner.leaf_pointers(records_by_path[first_entry["path"]])
        canonical_index = next(
            index
            for index, pointer in enumerate(first_leafs)
            if pointer.endswith("/canonical_runtime_id")
        )
        first_entry["binding_ledger"]["tuples"][canonical_index] = [control_index]
        rehash(changed)
        reject(changed, "canonical runtime identity must be derived")

        changed = copy.deepcopy(record_set)
        control_index = next(
            index
            for index, atom in enumerate(changed["binding_ledger"]["atoms"])
            if atom["binding_kind"] == "control"
        )
        first_entry = changed["records"][0]
        first_leafs = planner.leaf_pointers(records_by_path[first_entry["path"]])
        admission_index = next(
            index
            for index, pointer in enumerate(first_leafs)
            if pointer.endswith("/source_admission/upstream_tag")
        )
        first_entry["binding_ledger"]["tuples"][admission_index] = [control_index]
        rehash(changed)
        reject(changed, "runtime source admission must be primary-bound")

        changed = copy.deepcopy(record_set)
        old_atoms = changed["binding_ledger"]["atoms"]
        unused_core = {
            "binding_kind": "control",
            "evidence": ["test:unused-atom"],
            "derivation": "adversarial unused atom",
        }
        unused = {
            "atom_id": "binding-atom:"
            + planner.sha256_bytes(planner.canonical_bytes(unused_core)),
            **unused_core,
        }
        new_atoms = sorted([*old_atoms, unused], key=lambda atom: atom["atom_id"])
        new_indices = {atom["atom_id"]: index for index, atom in enumerate(new_atoms)}
        for entry in changed["records"]:
            for item in entry["binding_ledger"]["tuples"]:
                item[0] = new_indices[old_atoms[item[0]]["atom_id"]]
        changed["binding_ledger"]["atoms"] = new_atoms
        changed["binding_ledger"]["atom_count"] = len(new_atoms)
        rehash(changed)
        reject(changed, "unused atom")

    def test_base_source_capture_rejects_nonregular_oversize_and_swaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "base.py"
            regular.write_text("VALUE = 1\n", encoding="utf-8")
            self.assertEqual(
                regular.read_bytes(),
                materializer.capture_base_source_before_exec(regular, 1024),
            )
            with self.assertRaisesRegex(ValueError, "exceeds byte bound"):
                materializer.capture_base_source_before_exec(regular, 1)

            target = root / "target.py"
            target.write_text("VALUE = 2\n", encoding="utf-8")
            link = root / "link.py"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                materializer.capture_base_source_before_exec(link, 1024)

            real_ancestor = root / "real-ancestor"
            (real_ancestor / "parent").mkdir(parents=True)
            ancestor_source = real_ancestor / "parent/base.py"
            ancestor_source.write_text("VALUE = 3\n", encoding="utf-8")
            linked_ancestor = root / "linked-ancestor"
            linked_ancestor.symlink_to(real_ancestor, target_is_directory=True)
            with self.assertRaises(OSError):
                materializer.capture_base_source_before_exec(
                    linked_ancestor / "parent/base.py", 1024
                )

            fifo = root / "fifo.py"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(OSError, "not a regular file"):
                materializer.capture_base_source_before_exec(fifo, 1024)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "base.py"
            source.write_bytes(b"x" * 32)
            moved = root / "old.py"
            original_read = materializer.os.read
            swapped = False

            def swap_leaf(fd: int, count: int) -> bytes:
                nonlocal swapped
                data = original_read(fd, count)
                if not swapped:
                    swapped = True
                    source.rename(moved)
                    source.write_bytes(b"y" * 32)
                return data

            with mock.patch.object(materializer.os, "read", side_effect=swap_leaf):
                with self.assertRaisesRegex(ValueError, "source changed|path changed"):
                    materializer.capture_base_source_before_exec(source, 1024)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent"
            parent.mkdir()
            source = parent / "base.py"
            source.write_bytes(b"x" * 32)
            moved_parent = root / "moved-parent"
            original_read = materializer.os.read
            swapped = False

            def swap_parent(fd: int, count: int) -> bytes:
                nonlocal swapped
                data = original_read(fd, count)
                if not swapped:
                    swapped = True
                    parent.rename(moved_parent)
                    parent.mkdir()
                return data

            with mock.patch.object(materializer.os, "read", side_effect=swap_parent):
                with self.assertRaisesRegex(ValueError, "directory chain.*changed"):
                    materializer.capture_base_source_before_exec(source, 1024)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ancestor = root / "ancestor"
            parent = ancestor / "parent"
            parent.mkdir(parents=True)
            source = parent / "base.py"
            source.write_bytes(b"x" * 32)
            moved_ancestor = root / "moved-ancestor"
            original_read = materializer.os.read
            swapped = False

            def swap_ancestor_to_symlink(fd: int, count: int) -> bytes:
                nonlocal swapped
                data = original_read(fd, count)
                if not swapped:
                    swapped = True
                    ancestor.rename(moved_ancestor)
                    ancestor.symlink_to(moved_ancestor, target_is_directory=True)
                return data

            with mock.patch.object(
                materializer.os, "read", side_effect=swap_ancestor_to_symlink
            ):
                with self.assertRaisesRegex(ValueError, "directory chain path changed"):
                    materializer.capture_base_source_before_exec(source, 1024)

    def test_output_overlap_fails_before_every_write_in_all_directions(self) -> None:
        root = REPO_ROOT
        overlap_root = root / ".workingdir2/tests/source-resolution-overlap"
        cases = {
            "same": (overlap_root / "same", overlap_root / "same"),
            "output-ancestor": (
                overlap_root / "output-ancestor",
                overlap_root / "output-ancestor/input.json",
            ),
            "input-ancestor": (
                overlap_root / "input-ancestor/output",
                overlap_root / "input-ancestor",
            ),
        }
        for name, (output, protected) in cases.items():
            with self.subTest(name=name):
                with mock.patch.object(
                    materializer.base, "open_scratch_directory"
                ) as open_output, mock.patch.object(
                    materializer.base, "write_exact"
                ) as write_exact:
                    with self.assertRaisesRegex(ValueError, "output overlaps"):
                        materializer.write_resolution_bundle(
                            root,
                            output,
                            {},
                            {},
                            [protected],
                        )
                open_output.assert_not_called()
                write_exact.assert_not_called()

    def test_materializer_has_no_acquisition_or_process_api(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imported.isdisjoint(
                {"asyncio", "http", "requests", "socket", "subprocess", "urllib"}
            )
        )

    def test_proposed_tracked_set_cannot_select_an_acquisition_target(self) -> None:
        plan = planner.build_plan(
            REPO_ROOT,
            REPO_ROOT / "knowledge/registry/records",
            {"deployed", "planned"},
            set(),
            REPO_ROOT / "knowledge/registry/record-sets/argo-p1-src-02.json",
        )
        self.assertEqual([], plan["targets"])
        self.assertEqual(0, plan["counts"]["ready"])
        self.assertGreater(plan["counts"]["blocking_gaps"], 0)
        self.assertTrue(
            any(
                gap["code"] == "reviewed_record_set_not_accepted"
                for gap in plan["gaps"]
            )
        )


if __name__ == "__main__":
    unittest.main()
