"""Fetch channel snapshots into CAS + receipts (R3 W2-W4 runner).

The registry tool is intentionally incapable of source acquisition, so this
sibling runner (capture_live.py mold) performs the bounded, resumable fetch
loop of design r3-snapshot-design-20260822.md section E: it reads a validated
census-head manifest, selects accepted-available channels still lacking
snapshots, fetches each canonical_uri with per-host token buckets and a pinned
honest User-Agent, content-addresses verified bodies into ``cas/sha256/`` and
appends schema-conforming JSONL receipt rows. Failures are typed in-band
receipt rows, never silence; already-receipted URIs are skipped on resume.
"""

from __future__ import annotations

import argparse
import base64
import collections
import http.client
import json
import os
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

TOOL_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_ROOT))

import knowledge_registry as kr

RUNNER_VERSION = "archeion-channel-snapshot-runner/1"
USER_AGENT = (
    "archeion-channel-snapshot-runner/1"
    " (+https://github.com/cordanaLLM/knowledge; knowledge-registry R3)"
)
DEFAULT_RATE_PER_SECOND = 2.0
DEFAULT_MAX_BYTES = kr.SNAPSHOT_CAS_MAX_BYTES
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_ATTEMPTS = 5
DEFAULT_CIRCUIT_BREAK = 10
BACKOFF_BASE_SECONDS = 2.0
BACKOFF_CAP_SECONDS = 120.0
RECEIPT_FILE_ROTATE_BYTES = 6 * 2**20
NPM_ABBREVIATED_HOSTS = frozenset({"registry.npmjs.org"})
NPM_ABBREVIATED_ACCEPT = "application/vnd.npm.install-v1+json"
RETRYABLE_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--baseline", required=True, help="validated census candidate manifest"
    )
    result.add_argument(
        "--policy",
        action="append",
        required=True,
        help="channel policy name to fetch (repeatable; the wave scope)",
    )
    result.add_argument(
        "--output", required=True, help="snapshots directory (cas/ + receipts/)"
    )
    result.add_argument(
        "--default-rate",
        type=float,
        default=DEFAULT_RATE_PER_SECOND,
        help="request-per-second ceiling per host (jitter keeps it below)",
    )
    result.add_argument(
        "--rate",
        action="append",
        default=[],
        metavar="HOST=RPS",
        help="per-host rate override (repeatable)",
    )
    result.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="response size bound; oversize is a typed artifact-bound-exceeded",
    )
    result.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="per-request"
    )
    result.add_argument(
        "--attempts", type=int, default=DEFAULT_ATTEMPTS, help="bounded retry budget"
    )
    result.add_argument(
        "--circuit-break",
        type=int,
        default=DEFAULT_CIRCUIT_BREAK,
        help="consecutive host failures before the remaining URIs are typed open",
    )
    result.add_argument(
        "--docker-config-auth",
        action="append",
        default=[],
        metavar="HOST",
        help="send Basic auth for HOST from the workstation docker config",
    )
    result.add_argument(
        "--allow-insecure-host",
        action="append",
        default=[],
        metavar="HOST",
        help="allow plain http for HOST (offline test fixtures only)",
    )
    result.add_argument(
        "--plan-only",
        action="store_true",
        help="print the deduped fetch plan summary and exit without fetching",
    )
    return result


def utc_now_second() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def channel_policy_name(channel_id: str) -> str:
    parts = channel_id.split(":")
    return parts[3] if len(parts) > 4 else ""


def fetch_plan(
    baseline: dict[str, Any], policies: set[str]
) -> list[tuple[str, list[str]]]:
    accepted, immutable = kr.snapshot_axis_sets(baseline)
    missing = accepted - immutable
    by_uri: dict[str, set[str]] = {}
    for component in baseline.get("components", []):
        for channel in component.get("official_channels", []):
            if not isinstance(channel, dict):
                continue
            channel_id = str(channel.get("channel_id") or "")
            canonical_uri = channel.get("canonical_uri")
            if (
                channel_id in missing
                and canonical_uri
                and channel_policy_name(channel_id) in policies
            ):
                by_uri.setdefault(str(canonical_uri), set()).add(channel_id)
    return [(uri, sorted(by_uri[uri])) for uri in sorted(by_uri)]


def docker_config_basic_auth(hosts: list[str]) -> dict[str, str]:
    if not hosts:
        return {}
    config_path = (
        Path(os.environ.get("DOCKER_CONFIG", Path.home() / ".docker")) / "config.json"
    )
    try:
        auths = json.loads(config_path.read_text(encoding="utf-8")).get("auths", {})
    except (OSError, ValueError) as exc:
        raise SystemExit(f"docker config {config_path} is unreadable: {exc}") from exc
    headers: dict[str, str] = {}
    for host in hosts:
        token = (auths.get(host) or {}).get("auth")
        if not token:
            raise SystemExit(f"docker config has no auth entry for {host}")
        base64.b64decode(token, validate=True)
        headers[host] = f"Basic {token}"
    return headers


def existing_receipt_state(
    receipts_dir: Path,
) -> tuple[set[str], dict[str, list[Path]], int]:
    satisfied: set[str] = set()
    rows_by_uri: dict[str, list[Path]] = {}
    total_rows = 0
    if not receipts_dir.is_dir():
        return satisfied, rows_by_uri, total_rows
    for path in sorted(receipts_dir.iterdir()):
        if path.suffix != ".jsonl" or not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict) or not row.get("canonical_uri"):
                continue
            total_rows += 1
            uri = str(row["canonical_uri"])
            rows_by_uri.setdefault(uri, []).append(path)
            if row.get("status") in kr.SNAPSHOT_SATISFYING_STATUSES:
                satisfied.add(uri)
    return satisfied, rows_by_uri, total_rows


def drop_superseded_failure_rows(uris: set[str], files: set[Path]) -> int:
    """Retried URIs keep exactly one receipt row: rewrite their old failures out."""

    dropped = 0
    for path in sorted(files):
        kept: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line) if line.strip() else None
            except ValueError:
                row = None
            if isinstance(row, dict) and str(row.get("canonical_uri")) in uris:
                if row.get("status") in kr.SNAPSHOT_SATISFYING_STATUSES:
                    raise SystemExit(f"refusing to drop a satisfying receipt in {path}")
                dropped += 1
                continue
            if line.strip():
                kept.append(line)
        stage = path.with_name(path.name + ".tmp")
        stage.write_text("".join(item + "\n" for item in kept), encoding="utf-8")
        os.replace(stage, path)
    return dropped


class ReceiptWriter:
    def __init__(self, root: Path, run_id: str, validator: Any) -> None:
        self.root = root
        self.run_id = run_id
        self.validator = validator
        self.lock = threading.Lock()
        self.rows_written = 0
        self.file_index = 0
        self.current: Path | None = None

    def _target(self) -> Path:
        suffix = "" if self.file_index == 0 else f"-{self.file_index}"
        return self.root / "receipts" / f"receipts-{self.run_id}{suffix}.jsonl"

    def append(self, row: dict[str, Any]) -> None:
        errors = kr.schema_validation_errors(self.validator, row)
        if errors:
            raise SystemExit(f"runner produced an invalid receipt: {errors[0]}")
        line = json.dumps(row, sort_keys=True) + "\n"
        with self.lock:
            target = self._target()
            if (
                target.exists()
                and target.stat().st_size + len(line) > RECEIPT_FILE_ROTATE_BYTES
            ):
                self.file_index += 1
                target = self._target()
            with open(target, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            self.rows_written += 1


def cas_store(root: Path, data: bytes) -> tuple[str, str]:
    digest = kr.file_hash(data).removeprefix("sha256:")
    relative = f"cas/sha256/{digest[:2]}/{digest}"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        stage = target.with_name(f"{digest}.tmp-{os.getpid()}-{threading.get_ident()}")
        stage.write_bytes(data)
        os.replace(stage, target)
    if kr.file_hash(target.read_bytes()) != f"sha256:{digest}":
        raise SystemExit(f"CAS verification failed for {relative}")
    return f"sha256:{digest}", relative


def network_error_state(exc: BaseException) -> str:
    """Type a transport failure. A name that does not resolve is permanent.

    Measured 2026-08-25 on the OCI residue: a mistyped registry host (no such
    host) was recorded as the generic
    `network-URLError`, which reads as a transient blip worth retrying forever.
    urllib wraps the resolver failure in `URLError.reason`, so the class name
    alone cannot tell the two apart.
    """

    reason = getattr(exc, "reason", None)
    if isinstance(exc, socket.gaierror) or isinstance(reason, socket.gaierror):
        return "network-dns-unresolvable"
    return f"network-{type(exc).__name__}"


def receipt_row(
    channel_ids: list[str],
    canonical_uri: str,
    *,
    status: str,
    attempt: int,
    resolved_uri: str | None = None,
    fetched_at: str | None = None,
    etag: str | None = None,
    last_modified: str | None = None,
    content_hash: str | None = None,
    media_type: str | None = None,
    size: int | None = None,
    error_state: str | None = None,
    http_status: int | None = None,
    cas_path: str | None = None,
    coordinates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "channel_ids": channel_ids,
        "canonical_uri": canonical_uri,
        "resolved_uri": resolved_uri,
        "fetched_at": fetched_at,
        "observed_at": utc_now_second(),
        "etag": etag,
        "last_modified": last_modified,
        "content_hash": content_hash,
        "media_type": media_type,
        "bytes": size,
        "status": status,
        "error_state": error_state,
        "http_status": http_status,
        "attempt": attempt,
        "runner_version": RUNNER_VERSION,
        "cas_path": cas_path,
    }
    if coordinates:
        row["coordinates"] = coordinates
    return row


class Oversize(Exception):
    pass


class HostWorker(threading.Thread):
    def __init__(
        self,
        host: str,
        queue: list[tuple[str, list[str]]],
        *,
        args: argparse.Namespace,
        rate: float,
        auth_header: str | None,
        writer: ReceiptWriter,
        root: Path,
        stats: collections.Counter,
        reasons: collections.Counter,
        stats_lock: threading.Lock,
    ) -> None:
        super().__init__(name=f"fetch-{host}", daemon=True)
        self.host = host
        self.queue = queue
        self.args = args
        self.interval = 1.0 / max(rate, 0.001)
        self.auth_header = auth_header
        self.writer = writer
        self.root = root
        self.stats = stats
        self.reasons = reasons
        self.stats_lock = stats_lock
        self.consecutive_failures = 0
        self.fatal: BaseException | None = None

    def record(self, row: dict[str, Any]) -> None:
        self.writer.append(row)
        with self.stats_lock:
            if row["status"] in kr.SNAPSHOT_SATISFYING_STATUSES:
                self.stats["fetched"] += 1
            else:
                self.stats["failed"] += 1
                self.reasons[str(row["error_state"])] += 1

    def read_bounded(self, response: Any) -> bytes:
        chunks: list[bytes] = []
        remaining = self.args.max_bytes + 1
        while remaining > 0:
            chunk = response.read(min(remaining, 2**20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > self.args.max_bytes:
            raise Oversize()
        return data

    def request_once(self, uri: str, accept: str | None) -> tuple[bytes, Any, str, int]:
        headers = {"User-Agent": USER_AGENT}
        if accept:
            headers["Accept"] = accept
        if self.auth_header:
            headers["Authorization"] = self.auth_header
        request = urllib.request.Request(uri, headers=headers)
        with urllib.request.urlopen(request, timeout=self.args.timeout) as response:
            data = self.read_bounded(response)
            return data, response.headers, response.geturl(), response.status

    def fetch(self, uri: str, channel_ids: list[str]) -> dict[str, Any]:
        accept: str | None = None
        coordinates: dict[str, Any] | None = None
        attempt = 0
        while attempt < self.args.attempts:
            attempt += 1
            retry_after: float | None = None
            try:
                fetched_at = utc_now_second()
                data, headers, final_uri, http_status = self.request_once(uri, accept)
                content_hash, cas_path = cas_store(self.root, data)
                media_type = (
                    (headers.get("Content-Type") or "application/octet-stream")
                    .split(";")[0]
                    .strip()
                )
                return receipt_row(
                    channel_ids,
                    uri,
                    status="fetched",
                    attempt=attempt,
                    resolved_uri=final_uri,
                    fetched_at=fetched_at,
                    etag=headers.get("ETag"),
                    last_modified=headers.get("Last-Modified"),
                    content_hash=content_hash,
                    media_type=media_type,
                    size=len(data),
                    http_status=http_status,
                    cas_path=cas_path,
                    coordinates=coordinates,
                )
            except Oversize:
                if self.host in NPM_ABBREVIATED_HOSTS and accept is None:
                    # D-R3-2: abbreviated packument is the typed oversize fallback.
                    accept = NPM_ABBREVIATED_ACCEPT
                    coordinates = {"packument": "abbreviated"}
                    attempt -= 1
                    continue
                return receipt_row(
                    channel_ids,
                    uri,
                    status="fetch-failed",
                    attempt=attempt,
                    error_state="artifact-bound-exceeded",
                )
            except urllib.error.HTTPError as exc:
                error_state, http_status = f"http-{exc.code}", exc.code
                if exc.code not in RETRYABLE_HTTP_STATUSES:
                    return receipt_row(
                        channel_ids,
                        uri,
                        status="fetch-failed",
                        attempt=attempt,
                        error_state=error_state,
                        http_status=http_status,
                    )
                header = exc.headers.get("Retry-After") if exc.headers else None
                if header and str(header).isdigit():
                    retry_after = float(header)
            except (
                urllib.error.URLError,
                http.client.HTTPException,
                OSError,
                TimeoutError,
            ) as exc:
                error_state = network_error_state(exc)
                http_status = None
            if attempt >= self.args.attempts:
                return receipt_row(
                    channel_ids,
                    uri,
                    status="fetch-failed",
                    attempt=attempt,
                    error_state=error_state,
                    http_status=http_status,
                )
            backoff = min(
                BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)) + random.random(),
                BACKOFF_CAP_SECONDS,
            )
            time.sleep(max(backoff, retry_after or 0.0))
        raise AssertionError("retry loop must return a receipt row")

    def run(self) -> None:
        try:
            self.drain()
        except BaseException as exc:  # surfaced by main; a dead thread is silence
            self.fatal = exc

    def drain(self) -> None:
        for index, (uri, channel_ids) in enumerate(self.queue):
            if self.consecutive_failures >= self.args.circuit_break:
                # In-band circuit break: the remaining obligations stay typed.
                for open_uri, open_channels in self.queue[index:]:
                    self.record(
                        receipt_row(
                            open_channels,
                            open_uri,
                            status="fetch-failed",
                            attempt=1,
                            error_state="host-circuit-open",
                        )
                    )
                return
            try:
                row = self.fetch(uri, channel_ids)
            except Exception as exc:  # in-band: a silently lost row is worse
                row = receipt_row(
                    channel_ids,
                    uri,
                    status="fetch-failed",
                    attempt=1,
                    error_state=f"runner-{type(exc).__name__}",
                )
            self.record(row)
            if row["status"] in kr.SNAPSHOT_SATISFYING_STATUSES:
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1
            time.sleep(self.interval * (1.0 + random.random() * 0.5))


def parse_rates(overrides: list[str], default_rate: float) -> dict[str, float]:
    rates: dict[str, float] = {"": default_rate}
    for item in overrides:
        host, _, value = item.partition("=")
        if not host or not value:
            raise SystemExit(f"--rate must be HOST=RPS, got {item!r}")
        rates[host] = float(value)
    return rates


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    started = time.monotonic()
    policies = {item for item in args.policy if item}
    baseline = kr.load_json(args.baseline)
    plan = fetch_plan(baseline, policies)
    root = Path(args.output)
    receipts_dir = root / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    satisfied, rows_by_uri, existing_rows = existing_receipt_state(receipts_dir)
    pending = [(uri, channels) for uri, channels in plan if uri not in satisfied]
    skipped = len(plan) - len(pending)
    if args.plan_only:
        by_host = collections.Counter(
            urlsplit(uri).hostname or urlsplit(uri).scheme for uri, _ in pending
        )
        json.dump(
            {
                "plan_uris": len(plan),
                "pending_uris": len(pending),
                "skipped_uris": skipped,
                "pending_channels": sum(len(channels) for _, channels in pending),
                "hosts": dict(sorted(by_host.items())),
            },
            sys.stdout,
            indent=1,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0
    if existing_rows + len(pending) > kr.MAX_SNAPSHOT_RECEIPT_ROWS:
        raise SystemExit(
            f"receipt rows would exceed bound {kr.MAX_SNAPSHOT_RECEIPT_ROWS}"
        )
    retried_uris = {uri for uri, _ in pending if uri in rows_by_uri}
    superseded = drop_superseded_failure_rows(
        retried_uris,
        {path for uri in retried_uris for path in rows_by_uri[uri]},
    )
    auth_headers = docker_config_basic_auth(args.docker_config_auth)
    rates = parse_rates(args.rate, args.default_rate)
    insecure_hosts = set(args.allow_insecure_host)
    writer = ReceiptWriter(
        root,
        utc_now_second().replace("-", "").replace(":", ""),
        kr.snapshot_receipt_validator(),
    )
    stats: collections.Counter = collections.Counter()
    reasons: collections.Counter = collections.Counter()
    stats_lock = threading.Lock()
    queues: dict[str, list[tuple[str, list[str]]]] = {}
    for uri, channel_ids in pending:
        parts = urlsplit(uri)
        if parts.scheme == "s3":
            # D-R3-5: without workstation credentials this stays a typed failure.
            row = receipt_row(
                channel_ids,
                uri,
                status="fetch-failed",
                attempt=1,
                error_state="s3-credentials-unavailable",
            )
            writer.append(row)
            stats["failed"] += 1
            reasons[str(row["error_state"])] += 1
            continue
        host = parts.hostname or ""
        if parts.scheme == "https" or (
            parts.scheme == "http" and host in insecure_hosts
        ):
            queues.setdefault(host, []).append((uri, channel_ids))
            continue
        row = receipt_row(
            channel_ids,
            uri,
            status="fetch-failed",
            attempt=1,
            error_state="scheme-not-allowed",
        )
        writer.append(row)
        stats["failed"] += 1
        reasons[str(row["error_state"])] += 1
    workers = [
        HostWorker(
            host,
            queue,
            args=args,
            rate=rates.get(host, rates[""]),
            auth_header=auth_headers.get(host),
            writer=writer,
            root=root,
            stats=stats,
            reasons=reasons,
            stats_lock=stats_lock,
        )
        for host, queue in sorted(queues.items())
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    for worker in workers:
        if worker.fatal is not None:
            raise SystemExit(f"worker {worker.name} failed: {worker.fatal}")
    json.dump(
        {
            "plan_uris": len(plan),
            "skipped_uris": skipped,
            "superseded_failure_rows": superseded,
            "fetched_uris": stats["fetched"],
            "failed_uris": stats["failed"],
            "failure_reasons": dict(sorted(reasons.items())),
            "receipt_rows_written": writer.rows_written,
            "receipts_dir": receipts_dir.as_posix(),
            "wall_seconds": round(time.monotonic() - started, 1),
        },
        sys.stdout,
        indent=1,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
