"""Resolve OCI registry manifest identity into CAS + receipts (R4 W6).

The registry tool is intentionally incapable of source acquisition, so this
sibling runner reuses the proven snapshot_channels fetch stack (per-host token
buckets, CAS + JSONL receipts, typed in-band failures, resume-by-skip) and adds
only what a registry needs: the Bearer token dance, a two-phase manifest/config
fetch, and coordinates that re-derive from the stored bytes alone. Attestation
and unknown/unknown index entries are excluded before they can ever become a
platform identity.
"""

from __future__ import annotations

import argparse
import collections
import http.client
import json
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

TOOL_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_ROOT))

import knowledge_registry as kr
import snapshot_channels as sc

RUNNER_VERSION = "archeion-oci-artifact-runner/1"
USER_AGENT = (
    "archeion-oci-artifact-runner/1"
    " (+https://github.com/cordanaLLM/knowledge; knowledge-registry R4)"
)
MANIFEST_ACCEPT = ", ".join(sorted(kr.OCI_ARTIFACT_MEDIA_TYPES))
BLOB_ACCEPT = "application/octet-stream"
# Measured live 2026-08-23: ratelimit-limit 100;w=3600 per docker-ratelimit-source,
# decremented by every manifest GET including 404s; config blob GETs are free.
DOCKER_HUB_RATE_PER_SECOND = 0.025
REGISTRY_API_HOSTS = {kr.OCI_DEFAULT_REGISTRY: "registry-1.docker.io"}
CHALLENGE_PARAMETER_RE = re.compile(r'(?P<key>[a-zA-Z0-9_-]+)="(?P<value>[^"]*)"')
TOKEN_EXPIRY_MARGIN_SECONDS = 30.0
DEFAULT_TOKEN_LIFETIME_SECONDS = 300.0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--baseline", required=True, help="validated census candidate manifest"
    )
    result.add_argument(
        "--output", required=True, help="snapshots directory (cas/ + receipts/)"
    )
    result.add_argument(
        "--default-rate",
        type=float,
        default=sc.DEFAULT_RATE_PER_SECOND,
        help="request-per-second ceiling per registry (jitter keeps it below)",
    )
    result.add_argument(
        "--rate",
        action="append",
        default=[],
        metavar="REGISTRY=RPS",
        help="per-registry rate override (repeatable)",
    )
    result.add_argument(
        "--max-bytes",
        type=int,
        default=sc.DEFAULT_MAX_BYTES,
        help="response size bound; oversize is a typed artifact-bound-exceeded",
    )
    result.add_argument(
        "--timeout", type=float, default=sc.DEFAULT_TIMEOUT_SECONDS, help="per-request"
    )
    result.add_argument(
        "--attempts", type=int, default=sc.DEFAULT_ATTEMPTS, help="bounded retry budget"
    )
    result.add_argument(
        "--circuit-break",
        type=int,
        default=sc.DEFAULT_CIRCUIT_BREAK,
        help="consecutive registry failures before the remaining refs are typed open",
    )
    result.add_argument(
        "--docker-config-auth",
        action="append",
        default=[],
        metavar="REGISTRY",
        help="use the workstation docker config credential for REGISTRY",
    )
    result.add_argument(
        "--only-registry",
        action="append",
        default=[],
        metavar="REGISTRY",
        help="restrict the wave to these registries (repeatable)",
    )
    result.add_argument(
        "--plan-only",
        action="store_true",
        help="print the deduped fetch plan summary and exit without fetching",
    )
    return result


class _AuthStrippingRedirect(urllib.request.HTTPRedirectHandler):
    """Signed blob redirects reject a second credential; drop it cross-host."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if request is not None and (
            urllib.parse.urlsplit(newurl).hostname
            != urllib.parse.urlsplit(req.full_url).hostname
        ):
            request.headers.pop("Authorization", None)
        return request


OPENER = urllib.request.build_opener(_AuthStrippingRedirect())


class RegistryAuth:
    """Bearer tokens per (realm, service, scope), with an optional Basic fallback."""

    def __init__(self, basic: str | None) -> None:
        self.basic = basic
        self.lock = threading.Lock()
        self.realm: tuple[str, str] | None = None
        self.tokens: dict[tuple[str, str, str], tuple[str, float]] = {}

    @staticmethod
    def challenge(header: str) -> dict[str, str] | None:
        if not header or not header.strip().lower().startswith("bearer "):
            return None
        return {
            match["key"].lower(): match["value"]
            for match in CHALLENGE_PARAMETER_RE.finditer(header)
        }

    def learn(self, header: str) -> None:
        parameters = self.challenge(header) or {}
        if parameters.get("realm"):
            with self.lock:
                self.realm = (parameters["realm"], parameters.get("service", ""))

    def bearer(self, scope: str) -> str | None:
        with self.lock:
            realm = self.realm
        if realm is None:
            return None
        key = (realm[0], realm[1], scope)
        now = time.monotonic()
        with self.lock:
            cached = self.tokens.get(key)
            if cached and cached[1] > now:
                return cached[0]
        query = {"scope": scope}
        if realm[1]:
            query["service"] = realm[1]
        url = f"{realm[0]}?{urllib.parse.urlencode(query)}"
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.basic:
            headers["Authorization"] = self.basic
        request = urllib.request.Request(url, headers=headers)
        with OPENER.open(request, timeout=sc.DEFAULT_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read(2**20).decode("utf-8"))
        token = str(payload.get("token") or payload.get("access_token") or "")
        if not token:
            return None
        lifetime = float(payload.get("expires_in") or DEFAULT_TOKEN_LIFETIME_SECONDS)
        with self.lock:
            self.tokens[key] = (
                f"Bearer {token}",
                now + max(lifetime - TOKEN_EXPIRY_MARGIN_SECONDS, 1.0),
            )
        return f"Bearer {token}"


class RegistryWorker(sc.HostWorker):
    """One registry: token bucket, bearer negotiation, manifest then config blob."""

    def __init__(
        self,
        registry: str,
        rows: list[dict[str, Any]],
        *,
        args: argparse.Namespace,
        rate: float,
        auth: RegistryAuth,
        writer: sc.ReceiptWriter,
        root: Path,
        stats: collections.Counter,
        reasons: collections.Counter,
        stats_lock: threading.Lock,
    ) -> None:
        super().__init__(
            registry,
            [(row["canonical_uri"], row["component_version_ids"]) for row in rows],
            args=args,
            rate=rate,
            auth_header=None,
            writer=writer,
            root=root,
            stats=stats,
            reasons=reasons,
            stats_lock=stats_lock,
        )
        self.registry = registry
        self.api_host = REGISTRY_API_HOSTS.get(registry, registry)
        self.auth = auth
        self.rows = {row["canonical_uri"]: row for row in rows}

    def open_path(self, path: str, accept: str, scope: str) -> tuple[bytes, Any, int]:
        url = f"https://{self.api_host}/v2/{path}"
        headers = {"User-Agent": USER_AGENT, "Accept": accept}
        authorization = self.auth.bearer(scope) or self.auth.basic
        if authorization:
            headers["Authorization"] = authorization
        try:
            with OPENER.open(
                urllib.request.Request(url, headers=headers),
                timeout=self.args.timeout,
            ) as response:
                return self.read_bounded(response), response.headers, response.status
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            self.auth.learn(exc.headers.get("WWW-Authenticate") or "")
            token = self.auth.bearer(scope)
            if not token:
                raise
            headers["Authorization"] = token
        with OPENER.open(
            urllib.request.Request(url, headers=headers), timeout=self.args.timeout
        ) as response:
            return self.read_bounded(response), response.headers, response.status

    def resolve(self, row: dict[str, Any]) -> tuple[dict[str, Any], bytes, str]:
        repository, reference = row["repository"], row["reference"]
        scope = f"repository:{repository}:pull"
        data, headers, status = self.open_path(
            f"{repository}/manifests/{reference}", MANIFEST_ACCEPT, scope
        )
        resolved_digest = kr.file_hash(data)
        advertised = str(headers.get("docker-content-digest") or "")
        if advertised and advertised != resolved_digest:
            raise ValueError("digest-mismatch")
        if row["reference_kind"] == "digest" and reference != resolved_digest:
            raise ValueError("digest-mismatch")
        identity = kr.oci_manifest_identity(data)
        media_type = (
            (headers.get("Content-Type") or identity["manifest_media_type"] or "")
            .split(";")[0]
            .strip()
        )
        coordinates: dict[str, Any] = {
            "registry": self.registry,
            "repository": repository,
            "reference": reference,
            "reference_kind": row["reference_kind"],
            "resolved_digest": resolved_digest,
            "kind": identity["kind"],
            "children": identity["children"],
            "excluded": identity["excluded"],
            "platforms": identity["platforms"],
            "component_version_ids": row["component_version_ids"],
        }
        if identity["kind"] == "manifest":
            config_digest = str(identity["config_digest"])
            blob, _blob_headers, _status = self.open_path(
                f"{repository}/blobs/{config_digest}", BLOB_ACCEPT, scope
            )
            if kr.file_hash(blob) != config_digest:
                raise ValueError("digest-mismatch")
            platform = kr.oci_config_platform(blob)
            if not platform:
                raise ValueError("config-platform-unresolved")
            _config_hash, config_path = sc.cas_store(self.root, blob)
            coordinates["config_content_hash"] = config_digest
            coordinates["config_cas_path"] = config_path
            coordinates["platforms"] = [platform]
        elif not identity["platforms"]:
            raise ValueError("index-without-platform-children")
        return coordinates, data, media_type or "application/octet-stream"

    def fetch(self, uri: str, channel_ids: list[str]) -> dict[str, Any]:
        row = self.rows[uri]
        attempt = 0
        while attempt < self.args.attempts:
            attempt += 1
            retry_after: float | None = None
            try:
                fetched_at = sc.utc_now_second()
                coordinates, data, media_type = self.resolve(row)
                content_hash, cas_path = sc.cas_store(self.root, data)
                return sc.receipt_row(
                    channel_ids,
                    uri,
                    status="verified",
                    attempt=attempt,
                    resolved_uri=(
                        f"https://{self.api_host}/v2/{row['repository']}"
                        f"/manifests/{row['reference']}"
                    ),
                    fetched_at=fetched_at,
                    content_hash=content_hash,
                    media_type=media_type,
                    size=len(data),
                    http_status=200,
                    cas_path=cas_path,
                    coordinates={"oci": coordinates},
                ) | {
                    "runner_version": RUNNER_VERSION,
                    "upstream_ref": coordinates["resolved_digest"],
                }
            except sc.Oversize:
                return self.typed_failure(
                    channel_ids, uri, attempt, "artifact-bound-exceeded"
                )
            except (ValueError, kr.RegistryInputError) as exc:
                return self.typed_failure(
                    channel_ids, uri, attempt, f"manifest-{exc}"[:120]
                )
            except urllib.error.HTTPError as exc:
                error_state, http_status = f"http-{exc.code}", exc.code
                if exc.code == 404:
                    error_state = "manifest-unknown"
                elif exc.code in {401, 403}:
                    error_state = "registry-auth-required"
                if exc.code not in sc.RETRYABLE_HTTP_STATUSES:
                    return self.typed_failure(
                        channel_ids, uri, attempt, error_state, http_status
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
                error_state, http_status = sc.network_error_state(exc), None
            if attempt >= self.args.attempts:
                return self.typed_failure(
                    channel_ids, uri, attempt, error_state, http_status
                )
            backoff = min(
                sc.BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)) + random.random(),
                sc.BACKOFF_CAP_SECONDS,
            )
            time.sleep(max(backoff, retry_after or 0.0))
        raise AssertionError("retry loop must return a receipt row")

    def typed_failure(
        self,
        channel_ids: list[str],
        uri: str,
        attempt: int,
        error_state: str,
        http_status: int | None = None,
    ) -> dict[str, Any]:
        row = self.rows[uri]
        return sc.receipt_row(
            channel_ids,
            uri,
            status="fetch-failed",
            attempt=attempt,
            error_state=error_state,
            http_status=http_status,
            coordinates={
                # A typed failure keeps its ref bound to its obligations in-band.
                "oci": {
                    "registry": self.registry,
                    "repository": row["repository"],
                    "reference": row["reference"],
                    "reference_kind": row["reference_kind"],
                    "component_version_ids": row["component_version_ids"],
                }
            },
        ) | {"runner_version": RUNNER_VERSION}


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    started = time.monotonic()
    baseline = kr.load_json(args.baseline)
    plan, unfetchable = kr.oci_identity_plan(baseline)
    only = set(args.only_registry)
    if only:
        plan = [row for row in plan if row["registry"] in only]
    root = Path(args.output)
    receipts_dir = root / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    satisfied, rows_by_uri, existing_rows = sc.existing_receipt_state(receipts_dir)
    pending = [row for row in plan if row["canonical_uri"] not in satisfied]
    by_registry: dict[str, list[dict[str, Any]]] = {}
    for row in pending:
        by_registry.setdefault(row["registry"], []).append(row)
    if args.plan_only:
        json.dump(
            {
                "plan_refs": len(plan),
                "pending_refs": len(pending),
                "skipped_refs": len(plan) - len(pending),
                "pending_versions": sum(
                    len(row["component_version_ids"]) for row in pending
                ),
                "unfetchable_versions": len(unfetchable),
                "registries": {
                    registry: len(rows)
                    for registry, rows in sorted(by_registry.items())
                },
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
    retried = {
        row["canonical_uri"] for row in pending if row["canonical_uri"] in rows_by_uri
    }
    superseded = sc.drop_superseded_failure_rows(
        retried, {path for uri in retried for path in rows_by_uri[uri]}
    )
    basic = sc.docker_config_basic_auth(args.docker_config_auth)
    rates = sc.parse_rates(args.rate, args.default_rate)
    writer = sc.ReceiptWriter(
        root,
        sc.utc_now_second().replace("-", "").replace(":", ""),
        kr.snapshot_receipt_validator(),
    )
    stats: collections.Counter = collections.Counter()
    reasons: collections.Counter = collections.Counter()
    stats_lock = threading.Lock()
    workers = [
        RegistryWorker(
            registry,
            rows,
            args=args,
            rate=rates.get(
                registry,
                (
                    DOCKER_HUB_RATE_PER_SECOND
                    if registry == kr.OCI_DEFAULT_REGISTRY
                    else rates[""]
                ),
            ),
            auth=RegistryAuth(basic.get(registry)),
            writer=writer,
            root=root,
            stats=stats,
            reasons=reasons,
            stats_lock=stats_lock,
        )
        for registry, rows in sorted(by_registry.items())
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
            "plan_refs": len(plan),
            "skipped_refs": len(plan) - len(pending),
            "superseded_failure_rows": superseded,
            "resolved_refs": stats["fetched"],
            "failed_refs": stats["failed"],
            "failure_reasons": dict(sorted(reasons.items())),
            "receipt_rows_written": writer.rows_written,
            "receipts_dir": receipts_dir.as_posix(),
            "unfetchable_versions": len(unfetchable),
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
