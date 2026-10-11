#!/usr/bin/env python3
"""Materialize the P1-SRC-03 relevance-judgment -> admitted-evidence crosswalk.

This tool is a deterministic, offline lineage-preservation materializer.  It
binds each frozen relevance judgment of the ``scorer-blind-multidomain-v1``
evaluation freeze to the admitted P1-SRC-03 evidence span it refers to, under
the correct per-authority scope, without altering any question, judgment,
grade, threshold, source range, or span id.

It is not a scorer, evaluator, or quality artifact.  It performs no network,
subprocess, Git, signing, admission, retrieval, release, pointer, Argo, or
Kubernetes action, and it never mutates the frozen freeze, the evidence
manifests, or any source blob.  The single output is a fresh content-addressed
crosswalk object; the crosswalk stays non-serving and makes no quality claim.

The frozen judgments use ``official-source-line-span@1.0.0`` fine byte/line
windows, while the admitted evidence spans are coarse
``exact-coordinate-line-window@1.0.0`` document chunks, so the frozen and
admitted span ids do not share an identity namespace.  The join is therefore by
shared raw-document identity: the frozen source ``raw_document_sha256`` equals
the admitted file ``raw_sha256``, and byte identity is asserted by re-deriving
the frozen byte window from the raw blob (whose digest equals both) and
matching the frozen ``payload_sha256``.  Every failure is fail-closed.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "1.0.0"
CROSSWALK_KIND = "retrieval_judgment_evidence_crosswalk"
CROSSWALK_ID_PREFIX = "retrieval-judgment-crosswalk:"
JOIN_METHOD = "source-document-identity-byte-window"
JOIN_VERSION = "1.0.0"
GENERATOR = "archeion-p1-src03-judgment-crosswalk"
GENERATOR_VERSION = "1"
GENERATOR_SOURCE = "tools/knowledge-registry/materialize_p1_src03_crosswalk.py"

TESTDATA_DIR = "tools/knowledge-retrieval/testdata/scorer-blind-multidomain-v1"
FREEZE_CORE_RELATIVE = f"{TESTDATA_DIR}/suite-freeze.core.json"
FREEZE_MATERIALIZED_GLOB = (
    f"{TESTDATA_DIR}/materialized/evaluation-freezes/sha256/*/*.json"
)
EVIDENCE_GLOB = "knowledge/registry/acceptance/p1-src-03/evidence/sha256/*.json"
OUTPUT_RELATIVE = "knowledge/registry/acceptance/p1-src-03/crosswalk.json"

EXPECTED_AUTHORITY_COUNTS = {"cilium": 4, "go": 4, "kubernetes": 3}


class CrosswalkError(Exception):
    """A fail-closed crosswalk materialization or verification failure."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def output_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def content_addressed(document: Mapping[str, Any]) -> dict[str, Any]:
    core = {
        key: value
        for key, value in document.items()
        if key not in {"crosswalk_id", "payload_sha256"}
    }
    payload_sha256 = sha256_bytes(canonical_bytes(core))
    result = dict(document)
    result["crosswalk_id"] = CROSSWALK_ID_PREFIX + payload_sha256
    result["payload_sha256"] = payload_sha256
    return result


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise CrosswalkError(f"cannot read JSON input {path}: {exc}") from exc


def load_inputs(repo_root: Path) -> dict[str, Any]:
    """Load every read-only crosswalk input relative to ``repo_root``."""

    testdata = repo_root / TESTDATA_DIR
    freeze_path = repo_root / FREEZE_CORE_RELATIVE
    freeze_raw = freeze_path.read_bytes()
    freeze = json.loads(freeze_raw)

    freeze_files = sorted(glob.glob(str(repo_root / FREEZE_MATERIALIZED_GLOB)))
    if len(freeze_files) != 1:
        raise CrosswalkError(
            "expected exactly one materialized evaluation freeze, "
            f"found {len(freeze_files)}"
        )
    materialized_freeze = _load_json(Path(freeze_files[0]))

    manifest_files = sorted(glob.glob(str(repo_root / EVIDENCE_GLOB)))
    manifests = [_load_json(Path(path)) for path in manifest_files]

    source_blobs: dict[str, bytes] = {}
    for source in freeze.get("sources", []):
        blob_path = testdata / source["source_object_path"]
        try:
            source_blobs[source["source_key"]] = blob_path.read_bytes()
        except OSError as exc:
            raise CrosswalkError(f"cannot read source blob {blob_path}: {exc}") from exc

    return {
        "freeze": freeze,
        "freeze_core_document_sha256": sha256_bytes(freeze_raw),
        "materialized_freeze": materialized_freeze,
        "manifests": manifests,
        "source_blobs": source_blobs,
    }


def _authority_id(component_id: str, component_version: str) -> str:
    return f"retrieval-source-authority:{component_id}:{component_version}"


def _resolve_manifest_by_class(
    freeze: Mapping[str, Any], manifests: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, str], dict[str, Mapping[str, Any]]]:
    class_version: dict[str, str] = {}
    for source in freeze["sources"]:
        component = source["component_id"]
        version = source["component_version"]
        prior = class_version.setdefault(component, version)
        if prior != version:
            raise CrosswalkError(
                f"authority {component} has inconsistent frozen versions"
            )

    manifest_by_class: dict[str, Mapping[str, Any]] = {}
    for component, version in class_version.items():
        hits = [
            manifest
            for manifest in manifests
            if str(manifest.get("input_snapshot_id", "")).endswith("@" + version)
        ]
        if len(hits) != 1:
            raise CrosswalkError(
                f"expected exactly one evidence manifest for authority "
                f"{component}:{version}, found {len(hits)}"
            )
        manifest_by_class[component] = hits[0]

    distinct = {manifest["manifest_id"] for manifest in manifest_by_class.values()}
    if len(distinct) != len(manifest_by_class):
        raise CrosswalkError("authorities must not share an evidence manifest")
    return class_version, manifest_by_class


def _admitted_parser_version(manifests: Sequence[Mapping[str, Any]]) -> str:
    versions = {
        file["parser_version"] for manifest in manifests for file in manifest["files"]
    }
    if len(versions) != 1:
        raise CrosswalkError("admitted evidence uses more than one parser version")
    return next(iter(versions))


def build_crosswalk(
    freeze: Mapping[str, Any],
    freeze_core_document_sha256: str,
    materialized_freeze: Mapping[str, Any],
    manifests: Sequence[Mapping[str, Any]],
    source_blobs: Mapping[str, bytes],
) -> dict[str, Any]:
    """Build and fully verify the content-addressed judgment crosswalk."""

    freeze_body = {
        key: value
        for key, value in materialized_freeze.items()
        if key not in {"freeze_id", "freeze_payload_sha256"}
    }
    if freeze_body != freeze:
        raise CrosswalkError(
            "materialized freeze body does not equal the frozen suite core"
        )

    spans_by_id: dict[str, Mapping[str, Any]] = {}
    for span in freeze["spans"]:
        if span["span_id"] in spans_by_id:
            raise CrosswalkError(f"duplicate frozen span {span['span_id']}")
        spans_by_id[span["span_id"]] = span
    sources_by_key = {source["source_key"]: source for source in freeze["sources"]}

    class_version, manifest_by_class = _resolve_manifest_by_class(freeze, manifests)
    admitted_parser_version = _admitted_parser_version(manifests)

    thresholds_by_class: dict[str, list[dict[str, Any]]] = {}
    for threshold in freeze["thresholds"]:
        thresholds_by_class.setdefault(threshold["class"], []).append(dict(threshold))
    for entries in thresholds_by_class.values():
        entries.sort(key=lambda entry: entry["profile"])

    mappings: list[dict[str, Any]] = []
    used_span_ids: set[str] = set()

    for case in freeze["cases"]:
        component = case["class"]
        if component not in manifest_by_class:
            raise CrosswalkError(f"case {case['case_id']} has unknown authority")
        authority = _authority_id(component, class_version[component])
        manifest = manifest_by_class[component]

        for judgment in case["relevance_judgments"]:
            span_id = judgment["span_id"]
            if span_id in used_span_ids:
                raise CrosswalkError(f"frozen span {span_id} judged more than once")
            used_span_ids.add(span_id)

            span = spans_by_id.get(span_id)
            if span is None:
                raise CrosswalkError(f"judgment span {span_id} is unmatched")
            source = sources_by_key.get(span["source_key"])
            if source is None:
                raise CrosswalkError(
                    f"span {span_id} names unknown source {span['source_key']}"
                )

            if source["component_id"] != component:
                raise CrosswalkError(
                    f"case {case['case_id']} ({component}) is mis-scoped to a "
                    f"{source['component_id']} span"
                )

            raw = source["raw_document_sha256"]
            file_matches = [
                file
                for file in manifest["files"]
                if file["raw_sha256"] == raw
                and file["relative_path"] == source["source_path"]
            ]
            if len(file_matches) != 1:
                raise CrosswalkError(
                    f"span {span_id} resolves to {len(file_matches)} admitted "
                    f"files in authority {component}"
                )
            admitted_file = file_matches[0]

            for other_class, other_manifest in manifest_by_class.items():
                if other_class == component:
                    continue
                if any(file["raw_sha256"] == raw for file in other_manifest["files"]):
                    raise CrosswalkError(
                        f"span {span_id} payload is cross-authority aliased into "
                        f"{other_class}"
                    )

            blob = source_blobs.get(span["source_key"])
            if blob is None:
                raise CrosswalkError(f"missing source blob for {span['source_key']}")
            if sha256_bytes(blob) != raw:
                raise CrosswalkError(f"source blob for {span_id} fails raw identity")
            if admitted_file["raw_byte_size"] != source[
                "raw_document_byte_size"
            ] or admitted_file["raw_byte_size"] != len(blob):
                raise CrosswalkError(f"raw byte size disagreement for {span_id}")

            start = span["raw_byte_start"]
            end = span["raw_byte_end"]
            if not 0 <= start < end <= len(blob):
                raise CrosswalkError(f"span {span_id} byte window is out of bounds")
            segment = blob[start:end]
            segment_sha = sha256_bytes(segment)
            if segment_sha != span["payload_sha256"]:
                raise CrosswalkError(
                    f"span {span_id} payload sha256 mismatch (byte identity)"
                )
            if len(segment) != span["payload_byte_size"]:
                raise CrosswalkError(f"span {span_id} payload byte size mismatch")

            containing = [
                admitted_span
                for admitted_span in admitted_file["spans"]
                if admitted_span["raw_byte_start"] <= start
                and admitted_span["raw_byte_end"] >= end
            ]
            if len(containing) != 1:
                raise CrosswalkError(
                    f"span {span_id} resolves to {len(containing)} admitted spans"
                )
            chunk = containing[0]

            mappings.append(
                {
                    "case_id": case["case_id"],
                    "class": component,
                    "authority": authority,
                    "query_sha256": case["query_sha256"],
                    "frozen": {
                        "span_id": span["span_id"],
                        "grade": judgment["grade"],
                        "source_key": span["source_key"],
                        "heading_breadcrumb": span["heading_breadcrumb"],
                        "raw_byte_start": span["raw_byte_start"],
                        "raw_byte_end": span["raw_byte_end"],
                        "raw_line_start": span["raw_line_start"],
                        "raw_line_end": span["raw_line_end"],
                        "payload_sha256": span["payload_sha256"],
                        "payload_byte_size": span["payload_byte_size"],
                        "payload_object_path": span["payload_object_path"],
                    },
                    "admitted": {
                        "evidence_manifest_id": manifest["manifest_id"],
                        "snapshot_manifest_id": manifest["input_manifest_id"],
                        "input_snapshot_id": manifest["input_snapshot_id"],
                        "relative_path": admitted_file["relative_path"],
                        "occurrence_id": admitted_file["occurrence_id"],
                        "raw_sha256": admitted_file["raw_sha256"],
                        "admitted_span_id": chunk["span_id"],
                        "admitted_span_kind": chunk["kind"],
                        "admitted_span_raw_byte_start": chunk["raw_byte_start"],
                        "admitted_span_raw_byte_end": chunk["raw_byte_end"],
                        "raw_byte_start": start,
                        "raw_byte_end": end,
                        "raw_line_start": span["raw_line_start"],
                        "raw_line_end": span["raw_line_end"],
                        "payload_sha256": segment_sha,
                        "payload_byte_size": len(segment),
                    },
                }
            )

    if len(mappings) != len(freeze["spans"]):
        raise CrosswalkError(
            f"mapped {len(mappings)} judgments, expected {len(freeze['spans'])}"
        )
    if used_span_ids != set(spans_by_id):
        raise CrosswalkError("frozen spans and mapped judgments are not a bijection")

    counts = dict(Counter(mapping["class"] for mapping in mappings))
    if counts != EXPECTED_AUTHORITY_COUNTS:
        raise CrosswalkError(
            f"authority counts {counts} != {EXPECTED_AUTHORITY_COUNTS}"
        )

    mappings.sort(key=lambda mapping: mapping["case_id"])

    authorities = []
    for component in sorted(manifest_by_class):
        manifest = manifest_by_class[component]
        authorities.append(
            {
                "authority": _authority_id(component, class_version[component]),
                "class": component,
                "component_id": component,
                "component_version": class_version[component],
                "evidence_manifest_id": manifest["manifest_id"],
                "snapshot_manifest_id": manifest["input_manifest_id"],
                "input_snapshot_id": manifest["input_snapshot_id"],
                "judgment_count": counts[component],
                "frozen_thresholds": thresholds_by_class.get(component, []),
                "serving": False,
            }
        )

    document = {
        "schema_version": SCHEMA_VERSION,
        "crosswalk_kind": CROSSWALK_KIND,
        "state": "materialized",
        "serving": False,
        "quality_claim_made": False,
        "retrieval_authority": False,
        "span_identity_algorithm": freeze["span_identity_algorithm"],
        "join": {
            "method": JOIN_METHOD,
            "version": JOIN_VERSION,
            "span_id_identity_join": False,
            "admitted_span_identity_algorithm": admitted_parser_version,
            "rationale": (
                "Frozen judgments use official-source-line-span@1.0.0 fine byte/"
                "line windows; admitted evidence spans are coarse document chunks. "
                "The join is by shared raw-document identity (frozen source "
                "raw_document_sha256 == admitted file raw_sha256), and byte "
                "identity is asserted by re-deriving the frozen byte window from "
                "the raw blob and matching the frozen payload_sha256."
            ),
        },
        "freeze": {
            "freeze_id": materialized_freeze["freeze_id"],
            "freeze_payload_sha256": materialized_freeze["freeze_payload_sha256"],
            "freeze_core_document_sha256": freeze_core_document_sha256,
            "freeze_kind": freeze["freeze_kind"],
            "name": freeze["name"],
            "revision": freeze["revision"],
            "frozen_at": freeze["frozen_at"],
            "span_identity_algorithm": freeze["span_identity_algorithm"],
        },
        "generator": GENERATOR,
        "generator_version": GENERATOR_VERSION,
        "generator_source": GENERATOR_SOURCE,
        "judgment_count": len(mappings),
        "authority_counts": dict(counts),
        "authorities": authorities,
        "mappings": mappings,
    }
    return content_addressed(document)


def materialize(repo_root: Path) -> dict[str, Any]:
    inputs = load_inputs(repo_root)
    return build_crosswalk(
        inputs["freeze"],
        inputs["freeze_core_document_sha256"],
        inputs["materialized_freeze"],
        inputs["manifests"],
        inputs["source_blobs"],
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="repository root that holds the frozen and admitted inputs",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="output path (defaults to the committed crosswalk.json)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the on-disk crosswalk is byte-identical without writing",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    out_path = Path(args.out) if args.out else repo_root / OUTPUT_RELATIVE

    try:
        crosswalk = materialize(repo_root)
    except CrosswalkError as exc:
        print(f"crosswalk materialization failed: {exc}", file=sys.stderr)
        return 1

    raw = output_bytes(crosswalk)
    if args.check:
        current = out_path.read_bytes() if out_path.exists() else b""
        if current != raw:
            print(
                "crosswalk.json is not byte-identical to materialization",
                file=sys.stderr,
            )
            return 1
        print(crosswalk["crosswalk_id"])
        return 0

    out_path.write_bytes(raw)
    print(crosswalk["crosswalk_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
