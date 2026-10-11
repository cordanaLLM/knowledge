from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools/knowledge-registry/materialize_p1_src03_crosswalk.py"
CROSSWALK_PATH = REPO_ROOT / "knowledge/registry/acceptance/p1-src-03/crosswalk.json"
FREEZE_CORE_PATH = (
    REPO_ROOT
    / "tools/knowledge-retrieval/testdata/scorer-blind-multidomain-v1"
    / "suite-freeze.core.json"
)


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crosswalk = load_module("p1_src03_crosswalk", MODULE_PATH)


class CrosswalkMaterializerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.inputs = crosswalk.load_inputs(REPO_ROOT)
        self.freeze = json.loads(FREEZE_CORE_PATH.read_bytes())
        self.spans_by_id = {span["span_id"]: span for span in self.freeze["spans"]}
        self.sources_by_key = {
            source["source_key"]: source for source in self.freeze["sources"]
        }

    def build(self, **overrides: Any) -> dict[str, Any]:
        args = {
            "freeze": self.inputs["freeze"],
            "freeze_core_document_sha256": self.inputs["freeze_core_document_sha256"],
            "materialized_freeze": self.inputs["materialized_freeze"],
            "manifests": self.inputs["manifests"],
            "source_blobs": self.inputs["source_blobs"],
        }
        for key, value in overrides.items():
            args[key] = value
        return crosswalk.build_crosswalk(**args)

    def deep(self, key: str) -> Any:
        return copy.deepcopy(self.inputs[key])

    # ------------------------------------------------------------------
    # Positive invariants
    # ------------------------------------------------------------------
    def test_matches_committed_crosswalk_byte_identical(self) -> None:
        produced = crosswalk.output_bytes(self.build())
        self.assertEqual(produced, CROSSWALK_PATH.read_bytes())

    def test_deterministic_on_repeat(self) -> None:
        self.assertEqual(
            crosswalk.output_bytes(self.build()),
            crosswalk.output_bytes(self.build()),
        )

    def test_content_addressed_id(self) -> None:
        document = self.build()
        core = {
            key: value
            for key, value in document.items()
            if key not in {"crosswalk_id", "payload_sha256"}
        }
        expected = crosswalk.sha256_bytes(crosswalk.canonical_bytes(core))
        self.assertEqual(document["payload_sha256"], expected)
        self.assertEqual(
            document["crosswalk_id"],
            crosswalk.CROSSWALK_ID_PREFIX + expected,
        )

    def test_eleven_mappings_and_authority_counts(self) -> None:
        document = self.build()
        self.assertEqual(document["judgment_count"], 11)
        self.assertEqual(len(document["mappings"]), 11)
        self.assertEqual(
            document["authority_counts"],
            {"cilium": 4, "go": 4, "kubernetes": 3},
        )

    def test_every_frozen_span_resolves_exactly_once(self) -> None:
        document = self.build()
        mapped = [mapping["frozen"]["span_id"] for mapping in document["mappings"]]
        self.assertEqual(len(mapped), len(set(mapped)))
        self.assertEqual(set(mapped), set(self.spans_by_id))

    def test_per_authority_scoping(self) -> None:
        document = self.build()
        by_manifest = {
            authority["class"]: authority["evidence_manifest_id"]
            for authority in document["authorities"]
        }
        for mapping in document["mappings"]:
            component = mapping["class"]
            source = self.sources_by_key[mapping["frozen"]["source_key"]]
            self.assertEqual(source["component_id"], component)
            self.assertTrue(
                mapping["authority"].startswith(
                    f"retrieval-source-authority:{component}:"
                )
            )
            self.assertEqual(
                mapping["admitted"]["evidence_manifest_id"], by_manifest[component]
            )

    def test_byte_identity_frozen_equals_admitted(self) -> None:
        document = self.build()
        for mapping in document["mappings"]:
            frozen = mapping["frozen"]
            admitted = mapping["admitted"]
            span = self.spans_by_id[frozen["span_id"]]
            self.assertEqual(frozen["payload_sha256"], admitted["payload_sha256"])
            self.assertEqual(frozen["payload_sha256"], span["payload_sha256"])
            # admitted chunk encloses the frozen window
            self.assertLessEqual(
                admitted["admitted_span_raw_byte_start"], admitted["raw_byte_start"]
            )
            self.assertGreaterEqual(
                admitted["admitted_span_raw_byte_end"], admitted["raw_byte_end"]
            )

    def test_frozen_values_pass_through_unchanged(self) -> None:
        document = self.build()
        cases = {case["case_id"]: case for case in self.freeze["cases"]}
        thresholds_by_class: dict[str, list[dict[str, Any]]] = {}
        for threshold in self.freeze["thresholds"]:
            thresholds_by_class.setdefault(threshold["class"], []).append(
                dict(threshold)
            )
        for entries in thresholds_by_class.values():
            entries.sort(key=lambda entry: entry["profile"])

        for mapping in document["mappings"]:
            case = cases[mapping["case_id"]]
            judgment = case["relevance_judgments"][0]
            span = self.spans_by_id[judgment["span_id"]]
            frozen = mapping["frozen"]
            # question preserved by content address, never altered
            self.assertEqual(mapping["query_sha256"], case["query_sha256"])
            # judgment + grade + span id unchanged
            self.assertEqual(frozen["span_id"], judgment["span_id"])
            self.assertEqual(frozen["grade"], judgment["grade"])
            # source range unchanged
            for field in (
                "source_key",
                "raw_byte_start",
                "raw_byte_end",
                "raw_line_start",
                "raw_line_end",
                "payload_sha256",
                "payload_byte_size",
            ):
                self.assertEqual(frozen[field], span[field])

        for authority in document["authorities"]:
            self.assertEqual(
                authority["frozen_thresholds"],
                thresholds_by_class[authority["class"]],
            )

    def test_freeze_identity_preserved(self) -> None:
        document = self.build()
        self.assertEqual(
            document["freeze"]["freeze_id"],
            self.inputs["materialized_freeze"]["freeze_id"],
        )
        self.assertEqual(
            document["freeze"]["freeze_payload_sha256"],
            self.inputs["materialized_freeze"]["freeze_payload_sha256"],
        )
        self.assertEqual(
            document["freeze"]["freeze_core_document_sha256"],
            "sha256:" + hashlib.sha256(FREEZE_CORE_PATH.read_bytes()).hexdigest(),
        )

    def test_non_serving_non_quality(self) -> None:
        document = self.build()
        self.assertFalse(document["serving"])
        self.assertFalse(document["quality_claim_made"])
        self.assertFalse(document["retrieval_authority"])
        self.assertFalse(document["join"]["span_id_identity_join"])

    # ------------------------------------------------------------------
    # Fail-closed negative invariants
    # ------------------------------------------------------------------
    def test_rejects_mis_scoped_judgment(self) -> None:
        freeze = self.deep("freeze")
        # relabel the first cilium case as a go authority case
        freeze["cases"][0]["class"] = "go"
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(freeze=freeze)

    def test_rejects_unmatched_span(self) -> None:
        freeze = self.deep("freeze")
        freeze["cases"][0]["relevance_judgments"][0]["span_id"] = (
            "evidence-span:sha256:" + "0" * 64
        )
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(freeze=freeze)

    def test_rejects_duplicate_judgment(self) -> None:
        freeze = self.deep("freeze")
        duplicate = copy.deepcopy(freeze["cases"][0]["relevance_judgments"][0])
        freeze["cases"][0]["relevance_judgments"].append(duplicate)
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(freeze=freeze)

    def test_rejects_payload_sha_mismatch(self) -> None:
        freeze = self.deep("freeze")
        freeze["spans"][0]["payload_sha256"] = "sha256:" + "1" * 64
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(freeze=freeze)

    def test_rejects_tampered_source_blob(self) -> None:
        blobs = self.deep("source_blobs")
        key = self.freeze["spans"][1]["source_key"]
        mutated = bytearray(blobs[key])
        window = self.freeze["spans"][1]["raw_byte_start"]
        mutated[window] ^= 0x01
        blobs[key] = bytes(mutated)
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(source_blobs=blobs)

    def test_rejects_cross_authority_aliasing(self) -> None:
        manifests = self.deep("manifests")
        by_class = {}
        for manifest in manifests:
            snap = manifest["input_snapshot_id"]
            if "cilium" in snap:
                by_class["cilium"] = manifest
            elif "golang" in snap:
                by_class["go"] = manifest
        aliased = copy.deepcopy(by_class["cilium"]["files"][0])
        by_class["go"]["files"].append(aliased)
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(manifests=manifests)

    def test_rejects_missing_admitted_file(self) -> None:
        manifests = self.deep("manifests")
        for manifest in manifests:
            if "cilium" in manifest["input_snapshot_id"]:
                manifest["files"] = [
                    file
                    for file in manifest["files"]
                    if "cluster-pool" not in file["relative_path"]
                ]
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(manifests=manifests)

    def test_rejects_dropped_case_count(self) -> None:
        freeze = self.deep("freeze")
        freeze["cases"] = freeze["cases"][:-1]
        with self.assertRaises(crosswalk.CrosswalkError):
            self.build(freeze=freeze)


if __name__ == "__main__":
    unittest.main()
