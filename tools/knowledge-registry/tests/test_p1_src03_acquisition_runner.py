from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).resolve().parents[3]
RUNNER_ROOT = REPO_ROOT / "tools/knowledge-registry/p1-src03-acquisition-runner"
EXECUTION_VERIFIER = RUNNER_ROOT / "verify_execution_manifest.py"
SCHEMA_ROOT = REPO_ROOT / "knowledge/registry/schemas"
TOOL_ROOT = REPO_ROOT / "tools/knowledge-registry"
sys.path.insert(0, str(TOOL_ROOT))

import knowledge_registry as registry

SCHEMA_NAMES = (
    "source-acquisition-output-common-v2.schema.json",
    "source-acquisition-contract-v2.schema.json",
    "source-acquisition-execution-manifest-v1.schema.json",
    "source-acquisition-receipt-v2.schema.json",
    "source-inventory-proposal-v2.schema.json",
)


def load_strict(raw: bytes) -> dict[str, object]:
    value = registry.parse_json_bytes(raw, label="P1-SRC-03 JSON document")
    if not isinstance(value, dict):
        raise TypeError("JSON root must be an object")
    return value


def assert_content_address(
    test: unittest.TestCase,
    value: dict[str, object],
    *,
    id_key: str,
    payload_key: str,
    prefix: str,
) -> None:
    core = {
        key: item for key, item in value.items() if key not in {id_key, payload_key}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(registry.canonical_json(core).encode("utf-8")).hexdigest()
    )
    test.assertEqual(digest, value[payload_key])
    test.assertEqual(prefix + digest, value[id_key])


def assert_target_content_addresses(
    test: unittest.TestCase, targets: list[dict[str, object]]
) -> None:
    for target in targets:
        core = {key: value for key, value in target.items() if key != "target_id"}
        digest = hashlib.sha256(
            registry.canonical_json(core).encode("utf-8")
        ).hexdigest()
        test.assertEqual(
            "source-acquisition-target:sha256:" + digest,
            target["target_id"],
        )


class P1SRC03AcquisitionSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            name: load_strict((SCHEMA_ROOT / name).read_bytes())
            for name in SCHEMA_NAMES
        }
        for schema in cls.schemas.values():
            Draft202012Validator.check_schema(schema)
        cls.registry = Registry().with_resources(
            (
                str(schema["$id"]),
                Resource.from_contents(schema),
            )
            for schema in cls.schemas.values()
        )

    def validator(self, name: str) -> Draft202012Validator:
        return Draft202012Validator(
            self.schemas[name],
            registry=self.registry,
            format_checker=FormatChecker(),
        )

    def test_runner_contract_receipt_and_proposal_validate_v2(self) -> None:
        contract = load_strict(
            subprocess.run(
                ["go", "run", ".", "--print-contract"],
                cwd=RUNNER_ROOT,
                check=True,
                capture_output=True,
            ).stdout
        )
        self.validator("source-acquisition-contract-v2.schema.json").validate(contract)
        assert_content_address(
            self,
            contract,
            id_key="contract_id",
            payload_key="contract_payload_sha256",
            prefix="source-acquisition-contract:",
        )
        assert_target_content_addresses(self, contract["targets"])
        manifest = load_strict((RUNNER_ROOT / "execution-manifest.json").read_bytes())
        self.validator("source-acquisition-execution-manifest-v1.schema.json").validate(
            manifest
        )
        assert_content_address(
            self,
            manifest,
            id_key="manifest_id",
            payload_key="manifest_payload_sha256",
            prefix="source-acquisition-execution-manifest:",
        )

        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary) / "run"
            environment = os.environ.copy()
            environment["P1_SRC03_TEST_OUTPUT_ROOT"] = str(output_root)
            subprocess.run(
                ["go", "test", "-run", "^TestEmitSchemaValidationFixtures$", "."],
                cwd=RUNNER_ROOT,
                env=environment,
                check=True,
                capture_output=True,
            )
            receipt_paths = list((output_root / "receipts").glob("*.json"))
            proposal_paths = list((output_root / "inventory-proposals").glob("*.json"))
            self.assertEqual(1, len(receipt_paths))
            self.assertEqual(1, len(proposal_paths))
            receipt = load_strict(receipt_paths[0].read_bytes())
            proposal = load_strict(proposal_paths[0].read_bytes())
            self.validator("source-acquisition-receipt-v2.schema.json").validate(
                receipt
            )
            self.validator("source-inventory-proposal-v2.schema.json").validate(
                proposal
            )
            assert_content_address(
                self,
                receipt,
                id_key="receipt_id",
                payload_key="receipt_payload_sha256",
                prefix="source-acquisition-receipt:",
            )
            assert_content_address(
                self,
                proposal,
                id_key="proposal_id",
                payload_key="proposal_payload_sha256",
                prefix="source-inventory-proposal:",
            )
            self.assertEqual(
                [target["target_id"] for target in contract["targets"]],
                [target["target_id"] for target in receipt["targets"]],
            )

            widened = copy.deepcopy(receipt)
            widened["targets"][0]["files"].append(
                copy.deepcopy(widened["targets"][0]["files"][0])
            )
            self.assertTrue(
                list(
                    self.validator(
                        "source-acquisition-receipt-v2.schema.json"
                    ).iter_errors(widened)
                )
            )
            authority = copy.deepcopy(proposal)
            authority["authority_state"] = "accepted"
            self.assertTrue(
                list(
                    self.validator(
                        "source-inventory-proposal-v2.schema.json"
                    ).iter_errors(authority)
                )
            )
            aliased = copy.deepcopy(proposal)
            aliased["targets"][1]["source_set_id"] = aliased["targets"][0][
                "source_set_id"
            ]
            self.assertTrue(
                list(
                    self.validator(
                        "source-inventory-proposal-v2.schema.json"
                    ).iter_errors(aliased)
                )
            )
            wrong_publisher = copy.deepcopy(receipt)
            wrong_publisher["targets"][2]["publisher"] = copy.deepcopy(
                wrong_publisher["targets"][0]["publisher"]
            )
            self.assertTrue(
                list(
                    self.validator(
                        "source-acquisition-receipt-v2.schema.json"
                    ).iter_errors(wrong_publisher)
                )
            )
            wrong_cas = copy.deepcopy(receipt)
            wrong_cas["targets"][0]["files"][0]["cas_path"] = wrong_cas["targets"][0][
                "files"
            ][1]["cas_path"]
            self.assertTrue(
                list(
                    self.validator(
                        "source-acquisition-receipt-v2.schema.json"
                    ).iter_errors(wrong_cas)
                )
            )
            broken_path = copy.deepcopy(receipt)
            broken_path["targets"][0]["files"][0]["path_resolution"][0][
                "object_sha1"
            ] = ("0" * 40)
            self.assertTrue(
                list(
                    self.validator(
                        "source-acquisition-receipt-v2.schema.json"
                    ).iter_errors(broken_path)
                )
            )
            mixed_contract = copy.deepcopy(contract)
            mixed_contract["targets"][0]["files"][0] = copy.deepcopy(
                mixed_contract["targets"][1]["files"][0]
            )
            self.assertTrue(
                list(
                    self.validator(
                        "source-acquisition-contract-v2.schema.json"
                    ).iter_errors(mixed_contract)
                )
            )

    def test_external_execution_verifier_rejects_readdressed_scope_drift(
        self,
    ) -> None:
        manifest = load_strict((RUNNER_ROOT / "execution-manifest.json").read_bytes())
        for name, mutate, wanted in (
            (
                "artifact-denominator",
                lambda value: value.__setitem__("artifacts", []),
                "artifact denominator differs",
            ),
            (
                "toolchain-tuple",
                lambda value: value["toolchain"].__setitem__("goos", "forged"),
                "toolchain tuple differs",
            ),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                forged = copy.deepcopy(manifest)
                mutate(forged)
                core = {
                    key: item
                    for key, item in forged.items()
                    if key not in {"manifest_id", "manifest_payload_sha256"}
                }
                payload_sha = (
                    "sha256:"
                    + hashlib.sha256(registry.canonical_json(core).encode()).hexdigest()
                )
                forged["manifest_id"] = (
                    "source-acquisition-execution-manifest:" + payload_sha
                )
                forged["manifest_payload_sha256"] = payload_sha
                path = Path(temporary) / "forged.json"
                path.write_text(
                    registry.canonical_json(forged) + "\n", encoding="utf-8"
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(EXECUTION_VERIFIER),
                        "--repository-root",
                        str(REPO_ROOT),
                        "--manifest",
                        str(path),
                        "--repository-only",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn(wanted, completed.stderr)


if __name__ == "__main__":
    unittest.main()
