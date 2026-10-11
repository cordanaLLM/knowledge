from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any, Mapping

TOOL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOL_ROOT.parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import acquire_sources as acq
import knowledge_registry as kr

MANIFEST_SCHEMA = json.loads(
    (REPO_ROOT / kr.DISCOVERY_SCHEMA_RELATIVE).read_text(encoding="utf-8")
)
PLAN_SCHEMA = json.loads(
    (REPO_ROOT / acq.PLAN_V3_SCHEMA_SOURCE).read_text(encoding="utf-8")
)

# Cardinality stated four times: the live constant, the schema maxItems,
# CANDIDATE_ARRAY_BOUNDS and the table seal_manifest stamps onto every candidate.
LIVE_ARRAY_BOUNDS = {
    "sources": kr.MAX_SOURCES,
    "components": kr.MAX_COMPONENTS,
    "versions": kr.MAX_VERSIONS,
    "occurrences": kr.MAX_OCCURRENCES,
    "dependency_edges": kr.MAX_DEPENDENCY_EDGES,
    "gaps": kr.MAX_GAPS,
}

# The full stamp seal_manifest writes for a current-generation candidate.
LIVE_MANIFEST_BOUNDS = {
    "tracked_files": kr.MAX_TRACKED_FILES,
    "discovery_files": kr.MAX_DISCOVERY_FILES,
    "discovery_file_bytes": kr.MAX_DISCOVERY_FILE_BYTES,
    "discovery_total_bytes": kr.MAX_DISCOVERY_TOTAL_BYTES,
    "json_input_bytes": kr.MAX_JSON_INPUT_BYTES,
    "json_depth": kr.MAX_JSON_DEPTH,
    "json_nodes": kr.MAX_JSON_NODES,
    "serialized_output_bytes": kr.MAX_SERIALIZED_OUTPUT_BYTES,
    **LIVE_ARRAY_BOUNDS,
}

# Every schema array whose maxItems restates MAX_DISCOVERY_INPUTS.
DISCOVERY_INPUT_SCHEMA_PATHS = (
    ("$defs", "inputSet", "properties", "entries"),
    ("$defs", "discoveryScope", "properties", "inputs"),
    ("$defs", "mergeLineage", "properties", "input_manifest_ids"),
)

# Frozen envelopes, pinned here as literals so no edit to a live constant can
# reach them unnoticed.  17 sealed manifests re-seal byte-identically from these
# tables, so a value below is not a bound to keep current: changing one changes
# sealed manifest_ids.  The 512 MiB byte pair was frozen when the live envelope
# moved to 768 MiB; json_nodes and dependency_edges were frozen when the paged
# SBOM surface raised the live constants.  A newer bound belongs in a new
# generation, never in one of these.
FROZEN_BOUNDS_V1 = {
    "tracked_files": 20_000,
    "discovery_files": 10_000,
    "discovery_file_bytes": 8 * 2**20,
    "discovery_total_bytes": 128 * 2**20,
    "json_input_bytes": 512 * 2**20,
    "json_depth": 128,
    "json_nodes": 10_000_000,
    "serialized_output_bytes": 512 * 2**20,
    "sources": 100_000,
    "components": 100_000,
    "versions": 200_000,
    "occurrences": 400_000,
    "dependency_edges": 400_000,
    "gaps": 400_000,
}
FROZEN_BOUNDS_V2 = {
    **FROZEN_BOUNDS_V1,
    "json_input_bytes": 768 * 2**20,
    "serialized_output_bytes": 768 * 2**20,
}
FROZEN_BOUNDS_V3 = {
    **FROZEN_BOUNDS_V2,
    "json_nodes": 20_000_000,
    "dependency_edges": 700_000,
}
# Keys each generation deliberately holds BELOW the live constants.  Asserting
# the gap is what proves the freeze is real rather than an alias that happens to
# read the same today.  Keys absent here are only required to be <= live, never
# equal, so freezing one more of them later stays a passing change.
FROZEN_BELOW_LIVE = {
    "v1": ("json_input_bytes", "serialized_output_bytes", "json_nodes", "dependency_edges"),
    "v2": ("json_nodes", "dependency_edges"),
    # v3 IS the current generation, so no key sits below live yet. The freeze is
    # still real: FROZEN_BOUNDS_V3 is written out of literals, never kr.MAX_*,
    # so a later raise moves live and leaves this table where it is.
    "v3": (),
}
PINNED_FROZEN_BOUNDS = {
    "v1": (kr.MANIFEST_BOUNDS_V1, FROZEN_BOUNDS_V1),
    "v2": (kr.MANIFEST_BOUNDS_V2, FROZEN_BOUNDS_V2),
    "v3": (kr.MANIFEST_BOUNDS_V3, FROZEN_BOUNDS_V3),
}

# Bounds acquire_sources stamps and source-acquisition-plan.schema.json pins.
LIVE_PLAN_BOUNDS = {
    "component_filters": acq.MAX_COMPONENT_FILTERS,
    "targets": acq.MAX_TARGETS,
    "canonical_plan_bytes": acq.MAX_PLAN_CANONICAL_BYTES,
}


def schema_node(schema: Mapping[str, Any], *path: str) -> Mapping[str, Any]:
    node: Any = schema
    for key in path:
        node = node[key]
    return node


class ManifestBoundsCrossCheckTest(unittest.TestCase):
    """Every duplicated record bound must agree with its other definitions."""

    def stamped_bounds(self) -> dict[str, int]:
        # seal_manifest builds the current-generation table inline; sealing is
        # the only way to read it, and an empty candidate is enough to stamp it.
        return kr.seal_manifest({})["bounds"]

    def test_stamped_bounds_match_the_live_constants(self) -> None:
        self.assertEqual(LIVE_MANIFEST_BOUNDS, self.stamped_bounds())

    def test_candidate_array_bounds_match_the_live_constants(self) -> None:
        self.assertEqual(LIVE_ARRAY_BOUNDS, dict(kr.CANDIDATE_ARRAY_BOUNDS))

    def test_schema_max_items_match_the_live_array_constants(self) -> None:
        stamped = self.stamped_bounds()
        for field, bound in LIVE_ARRAY_BOUNDS.items():
            with self.subTest(field=field):
                # The copy that only a failing import discovered.
                self.assertEqual(
                    bound,
                    schema_node(MANIFEST_SCHEMA, "properties", field)["maxItems"],
                )
                self.assertEqual(bound, kr.CANDIDATE_ARRAY_BOUNDS[field])
                self.assertEqual(bound, stamped[field])

    def test_schema_discovery_input_max_items_match_the_live_constant(self) -> None:
        for path in DISCOVERY_INPUT_SCHEMA_PATHS:
            with self.subTest(path="/".join(path)):
                self.assertEqual(
                    kr.MAX_DISCOVERY_INPUTS,
                    schema_node(MANIFEST_SCHEMA, *path)["maxItems"],
                )

    def test_schema_accepted_deviation_max_items_matches_the_live_constant(
        self,
    ) -> None:
        self.assertEqual(
            kr.MAX_ACCEPTED_DEVIATIONS,
            schema_node(MANIFEST_SCHEMA, "$defs", "acceptedDeviations")["maxItems"],
        )

    def test_every_bounds_table_carries_the_schema_key_set(self) -> None:
        # The schema closes bounds with additionalProperties false, so a key
        # added to one table and not the others cannot validate anywhere.
        schema_bounds = schema_node(MANIFEST_SCHEMA, "$defs", "bounds")
        keys = sorted(schema_bounds["required"])
        self.assertEqual(keys, sorted(schema_bounds["properties"]))
        self.assertEqual(keys, sorted(LIVE_MANIFEST_BOUNDS))
        self.assertEqual(keys, sorted(self.stamped_bounds()))
        for generation, (table, _) in PINNED_FROZEN_BOUNDS.items():
            with self.subTest(generation=generation):
                self.assertEqual(keys, sorted(table))

    def test_frozen_bounds_never_track_the_live_constants(self) -> None:
        for generation, (table, pinned) in PINNED_FROZEN_BOUNDS.items():
            with self.subTest(generation=generation):
                # Re-sealing 17 manifests byte-identically depends on this.
                self.assertEqual(pinned, dict(table))
                for key in FROZEN_BELOW_LIVE[generation]:
                    self.assertLess(table[key], LIVE_MANIFEST_BOUNDS[key])

    def test_frozen_bounds_never_exceed_the_live_constants(self) -> None:
        # Bounds only relax, so no sealed envelope may sit above today's.
        for generation, (table, _) in PINNED_FROZEN_BOUNDS.items():
            for key, bound in table.items():
                with self.subTest(generation=generation, key=key):
                    self.assertLessEqual(bound, LIVE_MANIFEST_BOUNDS[key])

    def test_schema_still_admits_every_frozen_generation(self) -> None:
        # A relaxation keeps sealed manifests valid; a tightening would not.
        for generation, (table, _) in PINNED_FROZEN_BOUNDS.items():
            for field in LIVE_ARRAY_BOUNDS:
                with self.subTest(generation=generation, field=field):
                    self.assertLessEqual(
                        table[field],
                        schema_node(MANIFEST_SCHEMA, "properties", field)["maxItems"],
                    )

    def test_every_known_generation_is_pinned_here(self) -> None:
        known = list(kr.MANIFEST_BOUNDS_KNOWN)
        self.assertEqual(len(known), len(PINNED_FROZEN_BOUNDS))
        for generation, (table, _) in PINNED_FROZEN_BOUNDS.items():
            with self.subTest(generation=generation):
                self.assertIn(table, known)

    def test_acquisition_plan_schema_pins_the_live_plan_constants(self) -> None:
        schema_bounds = schema_node(PLAN_SCHEMA, "properties", "bounds")
        self.assertEqual(sorted(LIVE_PLAN_BOUNDS), sorted(schema_bounds["required"]))
        for key, bound in LIVE_PLAN_BOUNDS.items():
            with self.subTest(key=key):
                self.assertEqual(bound, schema_bounds["properties"][key]["const"])


if __name__ == "__main__":
    unittest.main()
