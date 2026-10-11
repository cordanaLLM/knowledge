from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOL_ROOT.parents[1]
VECTOR_PATH = REPO_ROOT / "testdata/canonical-json/v1/vectors.json"
PROFILE = "registry_compact_utf8"
sys.path.insert(0, str(TOOL_ROOT))

import knowledge_registry as registry


class CanonicalJSONConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    def test_registry_profile_matches_shared_canonical_vectors(self) -> None:
        for vector in self.vectors["values"]:
            with self.subTest(vector=vector["id"]):
                self.assertEqual(
                    vector["canonical"][PROFILE],
                    registry.canonical_json(vector["value"]),
                )

    def test_registry_parser_rejects_every_shared_unsafe_vector(self) -> None:
        for vector in self.vectors["reject_raw"]:
            raw = (
                base64.b64decode(vector["raw_base64"], validate=True)
                if "raw_base64" in vector
                else vector["raw_utf8"].encode("utf-8")
            )
            with self.subTest(vector=vector["id"]):
                with self.assertRaises(registry.RegistryInputError):
                    registry.parse_json_bytes(raw, label=vector["id"])

    def test_registry_recanonicalizes_every_noncanonical_vector(self) -> None:
        for vector in self.vectors["reject_noncanonical"]:
            raw = vector["raw_utf8"].encode("utf-8")
            with self.subTest(vector=vector["id"]):
                value = registry.parse_json_bytes(raw, label=vector["id"])
                canonical = registry.canonical_json(value).encode()
                self.assertNotEqual(raw, canonical)
                if PROFILE in vector.get("canonical", {}):
                    self.assertEqual(vector["canonical"][PROFILE].encode(), canonical)

    def test_registry_shared_depth_and_byte_bounds(self) -> None:
        for vector in self.vectors["bounds"]["nested_arrays"]:
            raw = ("[" * vector["levels"] + "0" + "]" * vector["levels"]).encode()
            with self.subTest(vector=vector["id"]):
                if vector["expected"][PROFILE] == "accept":
                    registry.parse_json_bytes(raw, label=vector["id"])
                else:
                    with self.assertRaises(registry.RegistryInputError):
                        registry.parse_json_bytes(raw, label=vector["id"])

        vector = self.vectors["bounds"]["byte_limit"]
        with self.assertRaises(registry.RegistryInputError):
            registry.parse_json_bytes(
                vector["raw_utf8"].encode(),
                label="byte-limit",
                max_bytes=vector["maximum"],
            )


if __name__ == "__main__":
    unittest.main()
