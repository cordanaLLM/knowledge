"""Synthesize zero-network channel-snapshot receipts (R3-W1).

Two offline populations are receipted from a validated baseline census:
live-export ``schema`` channels whose canonical_uri already carries the exact
content-addressed sha256 (re-hashed from the on-disk live capture inputs), and
``git-self`` ``source`` channels bound to the raw commit object bytes of a
local Git ref. Everything is read-only and local; the WAN runner
(``snapshot_channels.py``) is a separate, later deliverable.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

TOOL_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_ROOT))

import knowledge_registry as kr

RUNNER_VERSION = "archeion-offline-snapshot-synthesizer/1"
GIT_SELF_CHANNEL_PREFIX = "chn:policy:channel:git-self:"
LIVE_URI_PREFIX = "live-export:sha256:"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--baseline", required=True, help="validated census candidate manifest"
    )
    result.add_argument(
        "--live-dir",
        action="append",
        default=[],
        help="directory of captured live JSON inputs (repeatable)",
    )
    result.add_argument(
        "--repository", help="local Git repository for the git-self population"
    )
    result.add_argument(
        "--git-ref", default="origin/main", help="commit ref to bind (exact object)"
    )
    result.add_argument(
        "--observed-at", required=True, help="caller-pinned exact UTC second"
    )
    result.add_argument(
        "--output", required=True, help="snapshots directory (cas/ + receipts/)"
    )
    return result


def missing_channels(baseline: dict[str, Any]) -> dict[str, tuple[str, str]]:
    accepted, immutable = kr.snapshot_axis_sets(baseline)
    missing = accepted - immutable
    located: dict[str, tuple[str, str]] = {}
    for component in baseline.get("components", []):
        for channel in component.get("official_channels", []):
            if not isinstance(channel, dict):
                continue
            channel_id = str(channel.get("channel_id") or "")
            if channel_id in missing and channel.get("canonical_uri"):
                located[channel_id] = (
                    str(component.get("component_id") or ""),
                    str(channel["canonical_uri"]),
                )
    return located


def live_observed_at_by_sha(baseline: dict[str, Any]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for source in baseline.get("sources", []):
        evidence_uri = str(source.get("evidence_uri") or "")
        if not evidence_uri.startswith(LIVE_URI_PREFIX):
            continue
        metadata = source.get("metadata")
        observations = (
            metadata.get("observations", []) if isinstance(metadata, dict) else []
        )
        stamps = sorted(
            str(item["observed_at"])
            for item in observations
            if isinstance(item, dict) and item.get("observed_at")
        )
        if stamps:
            observed[evidence_uri.removeprefix(LIVE_URI_PREFIX)] = stamps[-1]
    return observed


def index_live_content(live_dirs: list[str], wanted: set[str]) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    for live_dir in live_dirs:
        for path in sorted(Path(live_dir).rglob("*.json")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                payload = kr.load_json(path.as_posix())
            except (kr.RegistryInputError, ValueError):
                # Fail closed per file: non-canonical inputs simply never match.
                continue
            canonical = kr.canonical_json(payload).encode("utf-8")
            digest = kr.file_hash(canonical).removeprefix("sha256:")
            if digest in wanted and digest not in found:
                found[digest] = canonical
    return found


def cas_write(root: Path, digest: str, data: bytes) -> str:
    relative = f"cas/sha256/{digest[:2]}/{digest}"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_bytes(data)
    return relative


def receipt_row(
    channel_ids: list[str],
    canonical_uri: str,
    *,
    observed_at: str,
    content: bytes,
    cas_path: str,
    media_type: str,
    upstream_ref: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "channel_ids": sorted(channel_ids),
        "canonical_uri": canonical_uri,
        "resolved_uri": canonical_uri,
        "fetched_at": observed_at,
        "observed_at": observed_at,
        "etag": None,
        "last_modified": None,
        "content_hash": kr.file_hash(content),
        "media_type": media_type,
        "bytes": len(content),
        "status": "verified",
        "error_state": None,
        "http_status": None,
        "attempt": 1,
        "runner_version": RUNNER_VERSION,
        "cas_path": cas_path,
    }
    if upstream_ref is not None:
        row["upstream_ref"] = upstream_ref
    return row


def git_commit_object(repository: str, ref: str) -> tuple[str, bytes]:
    def run(*arguments: str) -> bytes:
        return subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

    commit = run("rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    return commit, run("cat-file", "commit", commit)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not kr.valid_live_observed_at(args.observed_at):
        raise SystemExit("--observed-at must be an exact UTC second")
    baseline = kr.load_json(args.baseline)
    located = missing_channels(baseline)
    live_groups: dict[str, list[str]] = {}
    git_channels: dict[str, str] = {}
    for channel_id, (_component_id, canonical_uri) in located.items():
        if canonical_uri.startswith(LIVE_URI_PREFIX):
            digest = canonical_uri.removeprefix(LIVE_URI_PREFIX)
            live_groups.setdefault(digest, []).append(channel_id)
        elif channel_id.startswith(GIT_SELF_CHANNEL_PREFIX):
            git_channels[channel_id] = canonical_uri
    observed_by_sha = live_observed_at_by_sha(baseline)
    content_by_sha = index_live_content(args.live_dir, set(live_groups))
    root = Path(args.output)
    (root / "receipts").mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    live_missing: list[str] = []
    for digest in sorted(live_groups):
        content = content_by_sha.get(digest)
        observed_at = observed_by_sha.get(digest)
        if content is None or observed_at is None:
            # Fail closed: no on-disk proof means no receipt for those channels.
            live_missing.append(digest)
            continue
        rows.append(
            receipt_row(
                live_groups[digest],
                f"{LIVE_URI_PREFIX}{digest}",
                observed_at=observed_at,
                content=content,
                cas_path=cas_write(root, digest, content),
                media_type="application/json",
            )
        )
    git_summary: dict[str, Any] = {"channels": 0}
    if git_channels:
        if not args.repository:
            raise SystemExit("--repository is required for git-self channels")
        uris = sorted(set(git_channels.values()))
        if len(uris) != 1:
            raise SystemExit(f"git-self channels disagree on canonical_uri: {uris}")
        commit, content = git_commit_object(args.repository, args.git_ref)
        digest = kr.file_hash(content).removeprefix("sha256:")
        rows.append(
            receipt_row(
                sorted(git_channels),
                uris[0],
                observed_at=args.observed_at,
                content=content,
                cas_path=cas_write(root, digest, content),
                media_type="application/x-git-commit",
                upstream_ref=commit,
            )
        )
        git_summary = {"channels": len(git_channels), "commit": commit}
    validator = kr.snapshot_receipt_validator()
    for row in rows:
        errors = kr.schema_validation_errors(validator, row)
        if errors:
            raise SystemExit(f"synthesized receipt is invalid: {errors[0]}")
    run_id = args.observed_at.replace("-", "").replace(":", "")
    receipt_path = root / "receipts" / f"receipts-{run_id}.jsonl"
    receipt_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    json.dump(
        {
            "receipt_path": receipt_path.as_posix(),
            "rows": len(rows),
            "live_docs_receipted": len(rows) - (1 if git_channels else 0),
            "live_docs_missing": live_missing,
            "live_channels_receipted": sum(
                len(live_groups[digest])
                for digest in live_groups
                if digest not in live_missing
            ),
            "git_self": git_summary,
        },
        sys.stdout,
        indent=1,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
