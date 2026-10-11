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

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools/knowledge-registry/materialize_source_acceptance.py"
ACQUIRE_PATH = REPO_ROOT / "tools/knowledge-registry/acquire_sources.py"
SET_PATH = REPO_ROOT / "knowledge/registry/record-sets/argo-p1-src-02.json"
RECORDS_DIR = REPO_ROOT / "knowledge/registry/records"
ACCEPTANCE_DIR = REPO_ROOT / "knowledge/registry/acceptance/p1-src-02"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


accept = _load("materialize_source_acceptance", MODULE_PATH)
acquire = _load("acquire_sources_for_acceptance_tests", ACQUIRE_PATH)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def content_address(
    document: dict[str, Any], prefix: str, id_field: str
) -> dict[str, Any]:
    core = {k: v for k, v in document.items() if k not in {id_field, "payload_sha256"}}
    payload = sha(canonical(core))
    document[id_field] = prefix + payload
    document["payload_sha256"] = payload
    return document


def load_real_records() -> dict[str, dict[str, Any]]:
    record_set = json.loads(SET_PATH.read_text(encoding="utf-8"))
    records: dict[str, dict[str, Any]] = {}
    for entry in record_set["records"]:
        name = entry["path"].rsplit("/", 1)[-1]
        records[entry["record_id"]] = json.loads(
            (RECORDS_DIR / name).read_text(encoding="utf-8")
        )
    return records


def source_channel_id(record: dict[str, Any]) -> str:
    for channel in record["channels"]:
        if channel.get("channel_type") == "source":
            return channel["channel_id"]
    raise AssertionError("no source channel")


def source_channel_index(record: dict[str, Any]) -> int:
    for index, channel in enumerate(record["channels"]):
        if channel.get("channel_type") == "source":
            return index
    raise AssertionError("no source channel")


def review_gap_id(record: dict[str, Any]) -> str:
    for gap in record["gaps"]:
        if gap["gap_id"].endswith("independent-review-pending"):
            return gap["gap_id"]
    raise AssertionError("no independent-review gap")


def residual_subjects(record: dict[str, Any]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    subjects: list[dict[str, str]] = []
    for gap in record["gaps"]:
        if (
            gap.get("blocking")
            and gap.get("subject_kind") == "component"
            and str(gap.get("subject_id")).startswith("cmp:oci:")
        ):
            key = (gap["subject_kind"], gap["subject_id"])
            if key not in seen:
                seen.add(key)
                subjects.append(
                    {
                        "subject_kind": gap["subject_kind"],
                        "subject_id": gap["subject_id"],
                    }
                )
    return subjects


CONTRACT_HASHES = {
    "generator_source_sha256": None,  # filled from the set
    "component_schema_sha256": sha(
        (
            REPO_ROOT / "knowledge/registry/schemas/component-record.schema.json"
        ).read_bytes()
    ),
    "record_set_schema_sha256": sha(
        (
            REPO_ROOT / "knowledge/registry/schemas/reviewed-record-set.schema.json"
        ).read_bytes()
    ),
    "requirements_sha256": sha(
        (REPO_ROOT / "tools/knowledge-registry/requirements-reviewed.txt").read_bytes()
    ),
}


def build_policy(
    record_set: dict[str, Any], records: dict[str, dict[str, Any]], **overrides: Any
) -> dict[str, Any]:
    record_policies = []
    for entry in record_set["records"]:
        record_id = entry["record_id"]
        record = records[record_id]
        index = source_channel_index(record)
        channel = record["channels"][index]
        record_policies.append(
            {
                "record_id": record_id,
                "path": entry["path"],
                "component_id": entry["component_id"],
                "bound_record_content_sha256": entry["content_sha256"],
                "subject_class": "routine-exact-official-source",
                "source_channel_id": source_channel_id(record),
                "transitions": [
                    {"pointer": "/review/status", "from": "proposed", "to": "accepted"},
                    {
                        "pointer": "/versions/0/build_metadata/source_resolution/review_state",
                        "from": "proposed",
                        "to": "accepted",
                    },
                    {
                        "pointer": f"/channels/{index}/availability_state",
                        "from": "unresolved",
                        "to": "available",
                    },
                    {
                        "pointer": f"/channels/{index}/review_state",
                        "from": "proposed",
                        "to": "accepted",
                    },
                    {
                        "pointer": f"/channels/{index}/gap",
                        "from": channel["gap"],
                        "to": None,
                    },
                ],
                "resolve_gaps": [review_gap_id(record)],
                "authorized_residual_gap_subjects": residual_subjects(record),
            }
        )
    policy = {
        "$schema": "./schemas/source-acceptance-policy.schema.json",
        "schema_version": "1.0.0",
        "policy_kind": "source_acceptance_policy",
        "policy_id": "source-acceptance-policy:" + "0" * 64,
        "payload_sha256": "sha256:" + "0" * 64,
        "policy_version": "test-1",
        "not_valid_after": "2027-01-01T00:00:00Z",
        "bindings": {
            "record_set_id": record_set["record_set_id"],
            "record_set_payload_sha256": record_set["payload_sha256"],
            "generator_source_sha256": record_set["generator"]["source_sha256"],
            "component_schema_sha256": CONTRACT_HASHES["component_schema_sha256"],
            "record_set_schema_sha256": CONTRACT_HASHES["record_set_schema_sha256"],
            "requirements_sha256": CONTRACT_HASHES["requirements_sha256"],
        },
        "freshness": {"max_review_age_days": 90, "max_evidence_age_days": 365},
        "reviewers": {
            "authorized_reviewers": ["independent-reviewer-a"],
            "denied_reviewers": [],
            "excluded_proposer_identities": [
                "unassigned-independent-reviewer",
                "archeion-argo-source-resolution-materializer",
            ],
            "max_records_per_reviewer": 3,
        },
        "authorization": {
            "publisher": "Argo Project (argoproj)",
            "rights_statement": (
                "Apache-2.0 for Argo-authored material only; bundled and referenced "
                "third-party dependencies retain their own rights"
            ),
            "refresh_policy": "immutable locator; re-resolve only through a new reviewed record",
            "license_spdx": "Apache-2.0",
            "version_strategy": "exact-commit",
            "channel_access": "public",
            "channel_availability_state": "available",
        },
        "high_risk_subjects": [],
        "denominator": {
            "require_all_targets": True,
            "authorized_residual_set_gap_codes": [
                "candidate_component_absent",
                "oci_manifest_digest_unresolved",
                "runtime_digest_source_verification_unresolved",
            ],
        },
        "records": record_policies,
    }
    for key, value in overrides.items():
        policy[key] = value
    return content_address(policy, "source-acceptance-policy:", "policy_id")


def build_review(
    record_set: dict[str, Any],
    entry: dict[str, Any],
    record: dict[str, Any],
    **overrides: Any,
) -> dict[str, Any]:
    chart = record["versions"][0]["build_metadata"]["source_resolution"]["chart"]
    manifest = {
        "$schema": "./schemas/independent-review-manifest.schema.json",
        "schema_version": "1.0.0",
        "manifest_kind": "independent_source_review",
        "review_id": "independent-source-review:" + "0" * 64,
        "payload_sha256": "sha256:" + "0" * 64,
        "record_id": entry["record_id"],
        "component_id": entry["component_id"],
        "bound_record_content_sha256": entry["content_sha256"],
        "bound_record_set_payload_sha256": record_set["payload_sha256"],
        "reviewer": {
            "identity": "independent-reviewer-a",
            "independent_of": ["unassigned-independent-reviewer"],
            "attestation": "reproduced the primary sources independently",
        },
        "reviewed_at": "2026-07-17",
        "subject_class": "routine-exact-official-source",
        "decision": "accept",
        "reproduced_primary_sources": [
            {
                "kind": "chart-package",
                "locator": chart["package"]["uri"],
                "content_sha256": chart["package"]["content_sha256"],
            },
            {
                "kind": "chart-provenance",
                "locator": chart["provenance"]["uri"],
                "content_sha256": chart["provenance"]["content_sha256"],
            },
            {
                "kind": "chart-commit",
                "locator": chart["subtree_uri"],
                "content_sha256": chart["commit"],
            },
        ],
        "gaps_reviewed": [{"gap_id": review_gap_id(record), "disposition": "resolved"}],
        "rights_finding": "clear",
        "risk_finding": "routine",
    }
    for key, value in overrides.items():
        manifest[key] = value
    return content_address(manifest, "independent-source-review:", "review_id")


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.records_dir = self.dir / "records"
        self.records_dir.mkdir()
        self.reviews_dir = self.dir / "reviews"
        self.reviews_dir.mkdir()
        self.real_records = load_real_records()
        # Copy the real record files verbatim so their content hashes match.
        for entry in json.loads(SET_PATH.read_text())["records"]:
            name = entry["path"].rsplit("/", 1)[-1]
            shutil.copyfile(RECORDS_DIR / name, self.records_dir / name)

    def write(self, name: str, value: Any) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def write_review(self, name: str, value: Any) -> Path:
        path = self.reviews_dir / name
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def run_accept(
        self,
        record_set: dict[str, Any],
        policy: dict[str, Any],
        reviews: list[dict[str, Any]],
        *,
        records_dir: Path | None = None,
    ) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any] | None]:
        set_path = self.write("record-set.json", record_set)
        policy_path = self.write("policy.json", policy)
        review_paths = []
        for index, review in enumerate(reviews):
            review_paths.append(self.write_review(f"review-{index}.json", review))
        outcome, accepted_bytes, successor, _captured = accept.materialize(
            REPO_ROOT,
            set_path,
            records_dir or self.records_dir,
            policy_path,
            review_paths,
        )
        return outcome, accepted_bytes, successor

    def full_happy_inputs(
        self,
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        record_set = json.loads(SET_PATH.read_text(encoding="utf-8"))
        policy = build_policy(record_set, self.real_records)
        reviews = [
            build_review(record_set, entry, self.real_records[entry["record_id"]])
            for entry in record_set["records"]
            if not entry["record_id"].endswith("argo-cd")
        ]
        return record_set, policy, reviews

    def codes(self, outcome: dict[str, Any]) -> set[str]:
        return {exc["code"] for exc in outcome["exception_queue"]}


class RoundTripTests(Harness):
    def test_binding_ledger_reconstruct_is_byte_identical_with_no_change(self) -> None:
        record_set = json.loads(SET_PATH.read_text())
        atoms = record_set["binding_ledger"]["atoms"]
        items_by_path: dict[str, Any] = {}
        for entry in record_set["records"]:
            record = self.real_records[entry["record_id"]]
            items_by_path[entry["path"]] = accept.reconstruct_record_items(
                record, entry, atoms
            )
        set_ledger, record_ledgers = accept.recompute_binding_ledgers(items_by_path)
        self.assertEqual(record_set["binding_ledger"], set_ledger)
        for entry in record_set["records"]:
            self.assertEqual(entry["binding_ledger"], record_ledgers[entry["path"]])


class CommittedAcceptanceTests(Harness):
    def test_committed_partial_acceptance_replays_byte_identically(self) -> None:
        policy_path = ACCEPTANCE_DIR / "policy.json"
        review_paths = sorted((ACCEPTANCE_DIR / "reviews").glob("*.json"))
        outcome, accepted_bytes, successor, _captured = accept.materialize(
            REPO_ROOT,
            SET_PATH,
            RECORDS_DIR,
            policy_path,
            review_paths,
        )
        assert successor is not None
        self.assertEqual(
            accept.base.output_bytes(outcome),
            (ACCEPTANCE_DIR / "source-acceptance-outcome.json").read_bytes(),
        )
        self.assertEqual(
            accept.base.output_bytes(successor),
            (ACCEPTANCE_DIR / "accepted-reviewed-record-set.json").read_bytes(),
        )
        expected_ids = {
            "record:p1-src-02:argo-chart:argo-rollouts",
            "record:p1-src-02:argo-chart:argo-workflows",
        }
        self.assertEqual(expected_ids, set(accepted_bytes))
        for record_id, raw in accepted_bytes.items():
            name = record_id.rsplit(":", 1)[-1]
            self.assertEqual(
                raw,
                (
                    ACCEPTANCE_DIR / "accepted-records" / f"argo-{name}-chart.json"
                ).read_bytes(),
            )
        self.assertEqual(13, successor["counts"]["blocking_gaps"])
        self.assertEqual(2, successor["counts"]["accepted_records"])
        self.assertEqual(
            [
                "missing_review_artifact",
                "unresolved_target_gap",
                "unresolved_dependency_rights",
            ],
            [item["code"] for item in outcome["exception_queue"]],
        )
        # The default planner inputs remain the untouched proposed set and
        # records. This committed bundle is evidence, not a pointer promotion.
        self.assertEqual(
            "proposed", json.loads(SET_PATH.read_text())["review"]["status"]
        )
        self.assertTrue(
            all(
                record["review"]["status"] == "proposed"
                for record in self.real_records.values()
            )
        )


class FailClosedTests(Harness):
    def test_real_proposed_set_never_accepts_without_reviews(self) -> None:
        # Staged against the exact committed proposal with a bound policy but no
        # independent review artifacts: nothing may be accepted.
        record_set = json.loads(SET_PATH.read_text())
        policy = build_policy(record_set, self.real_records)
        outcome, accepted_bytes, successor = self.run_accept(record_set, policy, [])
        self.assertEqual(0, outcome["counts"]["accepted_records"])
        self.assertIsNone(successor)
        self.assertEqual({}, accepted_bytes)
        self.assertNotIn("denominator_incomplete", self.codes(outcome))
        self.assertIn("missing_review_artifact", self.codes(outcome))
        self.assertIn("unresolved_dependency_rights", self.codes(outcome))
        # Authority is always non-authoritative and never admits or promotes.
        self.assertFalse(outcome["authority"]["authoritative"])
        self.assertFalse(outcome["authority"]["admits_retrieval"])
        self.assertFalse(outcome["authority"]["promote_eligible"])


class HappyPathTests(Harness):
    def test_partial_acceptance_accepts_workflows_and_rollouts(self) -> None:
        record_set, policy, reviews = self.full_happy_inputs()
        outcome, accepted_bytes, successor = self.run_accept(
            record_set, policy, reviews
        )
        accepted_ids = {d["record_id"] for d in outcome["decisions"] if d["accepted"]}
        self.assertEqual(
            {
                "record:p1-src-02:argo-chart:argo-workflows",
                "record:p1-src-02:argo-chart:argo-rollouts",
            },
            accepted_ids,
        )
        # Argo CD fails closed on the bundled redis-ha third-party rights.
        cd = next(d for d in outcome["decisions"] if d["record_id"].endswith("argo-cd"))
        self.assertFalse(cd["accepted"])
        self.assertIn("unresolved_dependency_rights", cd["exception_codes"])
        self.assertIsNotNone(successor)
        self.assertEqual("accepted", successor["review"]["status"])
        self.assertEqual("reviewed", successor["authority_state"])
        self.assertEqual(2, successor["counts"]["accepted_records"])
        self.assertNotEqual(successor["record_set_id"], record_set["record_set_id"])
        # Acceptance preserves, rather than erases, the explicitly authorized
        # Events absence and every runtime verification blocker.
        self.assertEqual(record_set["gaps"], successor["gaps"])
        self.assertEqual(13, successor["counts"]["blocking_gaps"])
        cd_entry = next(
            entry
            for entry in successor["records"]
            if entry["record_id"].endswith("argo-cd")
        )
        predecessor_cd = next(
            entry
            for entry in record_set["records"]
            if entry["record_id"].endswith("argo-cd")
        )
        for field in ("record_id", "component_id", "path", "content_sha256", "bytes"):
            self.assertEqual(predecessor_cd[field], cd_entry[field])
        self.assertEqual("proposed", cd_entry["review_status"])
        cd_record = self.real_records[cd_entry["record_id"]]
        self.assertTrue(
            any(
                gap["gap_id"].endswith("redis-ha-rights-unresolved")
                and gap["blocking"] is True
                for gap in cd_record["gaps"]
            )
        )

    def test_successor_is_internally_consistent(self) -> None:
        record_set, policy, reviews = self.full_happy_inputs()
        _outcome, accepted_bytes, successor = self.run_accept(
            record_set, policy, reviews
        )
        assert successor is not None
        # Reconstruct the successor ledger from the accepted/proposed records and
        # confirm it equals what the tool emitted (planner will do the same).
        records: dict[str, dict[str, Any]] = {}
        for entry in successor["records"]:
            record_id = entry["record_id"]
            if record_id in accepted_bytes:
                records[entry["path"]] = json.loads(accepted_bytes[record_id])
            else:
                records[entry["path"]] = self.real_records[record_id]
        atoms = successor["binding_ledger"]["atoms"]
        items = {
            entry["path"]: accept.reconstruct_record_items(
                records[entry["path"]], entry, atoms
            )
            for entry in successor["records"]
        }
        set_ledger, record_ledgers = accept.recompute_binding_ledgers(items)
        self.assertEqual(successor["binding_ledger"], set_ledger)
        for entry in successor["records"]:
            self.assertEqual(entry["binding_ledger"], record_ledgers[entry["path"]])

    def test_successor_authorizes_accepted_targets_in_planner(self) -> None:
        record_set, policy, reviews = self.full_happy_inputs()
        _outcome, accepted_bytes, successor = self.run_accept(
            record_set, policy, reviews
        )
        assert successor is not None
        # Stage a promotion: write the accepted + proposed records and successor
        # set into a repo-shaped tree, then run the real acquisition planner.
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        records_out = root / "knowledge/registry/records"
        records_out.mkdir(parents=True)
        sets_out = root / "knowledge/registry/record-sets"
        sets_out.mkdir(parents=True)
        for entry in successor["records"]:
            name = entry["path"].rsplit("/", 1)[-1]
            record_id = entry["record_id"]
            if record_id in accepted_bytes:
                (records_out / name).write_bytes(accepted_bytes[record_id])
            else:
                shutil.copyfile(RECORDS_DIR / name, records_out / name)
        set_path = sets_out / "successor.json"
        set_path.write_text(json.dumps(successor, indent=2) + "\n", encoding="utf-8")
        plan = acquire.build_plan(
            root, records_out, {"deployed", "planned"}, set(), set_path
        )
        ready = {t["component_id"] for t in plan["targets"] if t["state"] == "ready"}
        self.assertEqual(
            {"cmp:helm:argoproj/argo-workflows", "cmp:helm:argoproj/argo-rollouts"},
            ready,
        )
        # The still-proposed Argo CD chart contributes no ready target.
        self.assertNotIn("cmp:helm:argoproj/argo-cd", ready)


class AdversarialTests(Harness):
    def accept_one(
        self,
        *,
        policy_mut: Callable[[dict[str, Any]], None] | None = None,
        review_mut: Callable[[list[dict[str, Any]]], None] | None = None,
        records_dir: Path | None = None,
    ) -> dict[str, Any]:
        record_set, policy, reviews = self.full_happy_inputs()
        if policy_mut is not None:
            policy_mut(policy)
            content_address(policy, "source-acceptance-policy:", "policy_id")
        if review_mut is not None:
            review_mut(reviews)
        outcome, _accepted, _successor = self.run_accept(
            record_set, policy, reviews, records_dir=records_dir
        )
        return outcome

    def wf_decision(self, outcome: dict[str, Any]) -> dict[str, Any]:
        return next(
            d for d in outcome["decisions"] if d["record_id"].endswith("argo-workflows")
        )

    def test_policy_binding_mismatch(self) -> None:
        def mutate(policy: dict[str, Any]) -> None:
            policy["bindings"]["record_set_payload_sha256"] = "sha256:" + "b" * 64

        outcome = self.accept_one(policy_mut=mutate)
        self.assertIn("policy_binding_mismatch", self.codes(outcome))
        self.assertEqual(0, outcome["counts"]["accepted_records"])

    def test_stale_policy(self) -> None:
        def mutate(policy: dict[str, Any]) -> None:
            policy["not_valid_after"] = "2026-01-01T00:00:00Z"

        outcome = self.accept_one(policy_mut=mutate)
        self.assertIn("policy_stale", self.codes(outcome))
        self.assertEqual(0, outcome["counts"]["accepted_records"])

    def test_reviewer_unauthorized(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            for review in reviews:
                review["reviewer"]["identity"] = "rogue-reviewer"
                content_address(review, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn(
            "reviewer_unauthorized", self.wf_decision(outcome)["exception_codes"]
        )

    def test_reviewer_not_independent(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            for review in reviews:
                review["reviewer"]["identity"] = "unassigned-independent-reviewer"
                content_address(review, "independent-source-review:", "review_id")

        def policy(pol: dict[str, Any]) -> None:
            pol["reviewers"]["authorized_reviewers"] = [
                "unassigned-independent-reviewer"
            ]

        outcome = self.accept_one(policy_mut=policy, review_mut=mutate)
        self.assertIn(
            "reviewer_not_independent", self.wf_decision(outcome)["exception_codes"]
        )

    def test_reviewer_reuse(self) -> None:
        def policy(pol: dict[str, Any]) -> None:
            pol["reviewers"]["max_records_per_reviewer"] = 1

        outcome = self.accept_one(policy_mut=policy)
        self.assertIn("reviewer_reuse", self.wf_decision(outcome)["exception_codes"])

    def test_duplicate_review(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            reviews.append(copy.deepcopy(workflow))

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn("duplicate_review", self.wf_decision(outcome)["exception_codes"])

    def test_out_of_order_review(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            for review in reviews:
                review["reviewed_at"] = "2026-08-01"
                content_address(review, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn(
            "out_of_order_review", self.wf_decision(outcome)["exception_codes"]
        )

    def test_stale_evidence(self) -> None:
        def policy(pol: dict[str, Any]) -> None:
            pol["freshness"]["max_review_age_days"] = 0

        def mutate(reviews: list[dict[str, Any]]) -> None:
            for review in reviews:
                review["reviewed_at"] = "2026-01-01"
                content_address(review, "independent-source-review:", "review_id")

        outcome = self.accept_one(policy_mut=policy, review_mut=mutate)
        self.assertIn("evidence_stale", self.wf_decision(outcome)["exception_codes"])

    def test_evidence_tamper(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["reproduced_primary_sources"][0]["content_sha256"] = (
                "sha256:" + "d" * 64
            )
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn("evidence_tamper", self.wf_decision(outcome)["exception_codes"])

    def test_evidence_kind_missing(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["reproduced_primary_sources"] = [
                item
                for item in workflow["reproduced_primary_sources"]
                if item["kind"] != "chart-provenance"
            ]
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn("evidence_tamper", self.wf_decision(outcome)["exception_codes"])

    def test_evidence_kind_duplicate(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["reproduced_primary_sources"].append(
                copy.deepcopy(workflow["reproduced_primary_sources"][0])
            )
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn("evidence_tamper", self.wf_decision(outcome)["exception_codes"])

    def test_evidence_locator_mismatch(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["reproduced_primary_sources"][0][
                "locator"
            ] = "https://github.com/argoproj/argo-helm/releases/download/other.tgz"
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn("evidence_tamper", self.wf_decision(outcome)["exception_codes"])

    def test_events_absence_requires_explicit_residual_authorization(self) -> None:
        def policy(pol: dict[str, Any]) -> None:
            pol["denominator"]["authorized_residual_set_gap_codes"].remove(
                "candidate_component_absent"
            )

        outcome = self.accept_one(policy_mut=policy)
        self.assertIn("denominator_gap_unauthorized", self.codes(outcome))
        self.assertEqual(0, outcome["counts"]["accepted_records"])

    def test_review_decision_not_accept(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["decision"] = "needs-review"
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn(
            "review_decision_not_accept", self.wf_decision(outcome)["exception_codes"]
        )

    def test_ambiguous_rights(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["rights_finding"] = "ambiguous"
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn("ambiguous_rights", self.wf_decision(outcome)["exception_codes"])

    def test_high_risk_subject_denylist(self) -> None:
        def policy(pol: dict[str, Any]) -> None:
            pol["high_risk_subjects"] = ["cmp:helm:argoproj/argo-workflows"]

        outcome = self.accept_one(policy_mut=policy)
        exception = next(
            e for e in outcome["exception_queue"] if e["code"] == "high_risk_subject"
        )
        self.assertTrue(exception["requires_human"])
        self.assertIn("high_risk_subject", self.wf_decision(outcome)["exception_codes"])

    def test_high_risk_finding_from_reviewer(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["risk_finding"] = "high-risk"
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn("high_risk_subject", self.wf_decision(outcome)["exception_codes"])

    def test_missing_review_artifact(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            reviews[:] = [
                r for r in reviews if not r["record_id"].endswith("argo-workflows")
            ]

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn(
            "missing_review_artifact", self.wf_decision(outcome)["exception_codes"]
        )

    def test_review_binding_mismatch(self) -> None:
        def mutate(reviews: list[dict[str, Any]]) -> None:
            workflow = next(
                r for r in reviews if r["record_id"].endswith("argo-workflows")
            )
            workflow["bound_record_content_sha256"] = "sha256:" + "e" * 64
            content_address(workflow, "independent-source-review:", "review_id")

        outcome = self.accept_one(review_mut=mutate)
        self.assertIn(
            "review_binding_mismatch", self.wf_decision(outcome)["exception_codes"]
        )

    def test_partial_acceptance_unauthorized(self) -> None:
        def policy(pol: dict[str, Any]) -> None:
            for record in pol["records"]:
                if record["record_id"].endswith("argo-workflows"):
                    record["authorized_residual_gap_subjects"] = []

        outcome = self.accept_one(policy_mut=policy)
        self.assertIn(
            "partial_acceptance_unauthorized",
            self.wf_decision(outcome)["exception_codes"],
        )

    def test_transition_precondition_failed(self) -> None:
        def policy(pol: dict[str, Any]) -> None:
            for record in pol["records"]:
                if record["record_id"].endswith("argo-workflows"):
                    for transition in record["transitions"]:
                        if transition["pointer"] == "/review/status":
                            transition["from"] = "needs-review"

        outcome = self.accept_one(policy_mut=policy)
        self.assertIn(
            "transition_precondition_failed",
            self.wf_decision(outcome)["exception_codes"],
        )

    def test_record_tamper(self) -> None:
        # Mutate a record file so its content no longer matches the set manifest.
        name = "argo-argo-workflows-chart.json"
        record = json.loads((self.records_dir / name).read_text())
        record["component"]["owners"].append("tamper")
        (self.records_dir / name).write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
        record_set, policy, reviews = self.full_happy_inputs()
        outcome, _accepted, successor = self.run_accept(record_set, policy, reviews)
        self.assertIn("record_tamper", self.codes(outcome))
        accepted_ids = {d["record_id"] for d in outcome["decisions"] if d["accepted"]}
        self.assertNotIn("record:p1-src-02:argo-chart:argo-workflows", accepted_ids)

    def test_path_swap(self) -> None:
        # An extra record file in the directory breaks exact denominator equality.
        (self.records_dir / "extra.json").write_text("{}\n", encoding="utf-8")
        record_set, policy, reviews = self.full_happy_inputs()
        outcome, _accepted, _successor = self.run_accept(record_set, policy, reviews)
        self.assertIn("path_swap", self.codes(outcome))


class ContractTests(Harness):
    def test_cli_exposes_only_materialize(self) -> None:
        for forbidden in ("fetch", "sign", "admit", "promote", "execute_plan"):
            self.assertFalse(hasattr(accept, forbidden))
        import argparse

        with self.assertRaises(SystemExit):
            accept.parse_args(
                [
                    "fetch",
                    "--record-set",
                    "x",
                    "--records",
                    "y",
                    "--policy",
                    "z",
                    "--output-dir",
                    "o",
                ]
            )

    def test_transition_targets_are_constrained(self) -> None:
        authorization = {
            "channel_availability_state": "available",
            "version_strategy": "exact-commit",
            "refresh_policy": "immutable locator; re-resolve only through a new reviewed record",
        }
        self.assertEqual(
            "accepted",
            accept.authorized_transition_target("/review/status", authorization),
        )
        self.assertIsNone(
            accept.authorized_transition_target("/channels/3/gap", authorization)
        )
        with self.assertRaises(ValueError):
            accept.authorized_transition_target("/versions/0/source_ref", authorization)
        with self.assertRaises(ValueError):
            accept.authorized_transition_target(
                "/channels/3/canonical_uri", authorization
            )


if __name__ == "__main__":
    unittest.main()
