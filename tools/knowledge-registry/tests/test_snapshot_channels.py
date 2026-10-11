from __future__ import annotations

import hashlib
import http.server
import io
import json
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import knowledge_registry as kr
import snapshot_channels as sc


class Handler(http.server.BaseHTTPRequestHandler):
    responses: dict[str, tuple[int, dict[str, str], bytes]] = {}
    abbreviated_body: bytes | None = None
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - http.server API name
        type(self).hits.append(self.path)
        if (
            self.abbreviated_body is not None
            and self.headers.get("Accept") == sc.NPM_ABBREVIATED_ACCEPT
        ):
            status, headers, body = (
                200,
                {"Content-Type": "application/json"},
                (self.abbreviated_body),
            )
        else:
            status, headers, body = self.responses.get(
                self.path, (404, {"Content-Type": "text/plain"}, b"missing")
            )
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *arguments: Any) -> None:
        return


class SnapshotChannelsRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        Handler.responses = {}
        Handler.abbreviated_body = None
        Handler.hits = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def uri(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def baseline_path(self, channels: list[tuple[str, str]]) -> str:
        manifest = {
            "components": [
                {
                    "component_id": "cmp-demo",
                    "official_channels": [
                        {
                            "channel_id": channel_id,
                            "channel_type": "package",
                            "review_state": "accepted",
                            "availability_state": "available",
                            "canonical_uri": canonical_uri,
                        }
                        for channel_id, canonical_uri in channels
                    ],
                }
            ]
        }
        target = self.base / f"baseline-{len(list(self.base.iterdir()))}.json"
        target.write_text(json.dumps(manifest), encoding="utf-8")
        return target.as_posix()

    def run_main(self, baseline: str, *extra: str) -> dict[str, Any]:
        output = io.StringIO()
        with redirect_stdout(output):
            status = sc.main(
                [
                    "--baseline",
                    baseline,
                    "--policy",
                    "pypi",
                    "--output",
                    (self.base / "snapshots").as_posix(),
                    "--default-rate",
                    "1000",
                    "--allow-insecure-host",
                    "127.0.0.1",
                    *extra,
                ]
            )
        self.assertEqual(0, status)
        return json.loads(output.getvalue())

    def receipt_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        receipts = self.base / "snapshots" / "receipts"
        for path in sorted(receipts.glob("*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        return rows

    def test_fetched_receipt_conforms_and_content_addresses(self) -> None:
        body = b'{"releases": {"1.0.0": []}}'
        Handler.responses["/project/demo/"] = (
            200,
            {"Content-Type": "application/json; charset=utf-8", "ETag": '"e1"'},
            body,
        )
        channels = [
            ("chn:policy:channel:pypi:v1:cmp-demo:package", self.uri("/project/demo/")),
            ("chn:policy:channel:pypi:v1:cmp-demo:release", self.uri("/project/demo/")),
        ]
        summary = self.run_main(self.baseline_path(channels))
        self.assertEqual(1, summary["fetched_uris"])
        self.assertEqual(0, summary["failed_uris"])
        rows = self.receipt_rows()
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual(
            [], kr.schema_validation_errors(kr.snapshot_receipt_validator(), row)
        )
        digest = hashlib.sha256(body).hexdigest()
        self.assertEqual([channel for channel, _ in channels], row["channel_ids"])
        self.assertEqual("fetched", row["status"])
        self.assertEqual(f"sha256:{digest}", row["content_hash"])
        self.assertEqual("application/json", row["media_type"])
        self.assertEqual(200, row["http_status"])
        self.assertEqual('"e1"', row["etag"])
        self.assertEqual(len(body), row["bytes"])
        self.assertEqual(sc.RUNNER_VERSION, row["runner_version"])
        blob = self.base / "snapshots" / row["cas_path"]
        self.assertEqual(body, blob.read_bytes())

    def test_resume_skips_satisfied_uris(self) -> None:
        Handler.responses["/project/demo/"] = (
            200,
            {"Content-Type": "application/json"},
            b"{}",
        )
        channels = [
            ("chn:policy:channel:pypi:v1:cmp-demo:package", self.uri("/project/demo/"))
        ]
        baseline = self.baseline_path(channels)
        first = self.run_main(baseline)
        self.assertEqual(1, first["fetched_uris"])
        second = self.run_main(baseline)
        self.assertEqual(1, second["skipped_uris"])
        self.assertEqual(0, second["fetched_uris"] + second["failed_uris"])
        self.assertEqual(1, len(self.receipt_rows()))
        self.assertEqual(1, len(Handler.hits))

    def test_size_cap_refusal_is_typed(self) -> None:
        Handler.responses["/big"] = (
            200,
            {"Content-Type": "application/octet-stream"},
            b"x" * 256,
        )
        channels = [("chn:policy:channel:pypi:v1:cmp-demo:package", self.uri("/big"))]
        summary = self.run_main(self.baseline_path(channels), "--max-bytes", "64")
        self.assertEqual({"artifact-bound-exceeded": 1}, summary["failure_reasons"])
        row = self.receipt_rows()[0]
        self.assertEqual("fetch-failed", row["status"])
        self.assertEqual("artifact-bound-exceeded", row["error_state"])
        self.assertIsNone(row["content_hash"])
        self.assertIsNone(row["cas_path"])
        self.assertFalse((self.base / "snapshots" / "cas").exists())

    def test_http_failure_row_is_in_band(self) -> None:
        channels = [("chn:policy:channel:pypi:v1:cmp-demo:package", self.uri("/gone"))]
        summary = self.run_main(self.baseline_path(channels))
        self.assertEqual({"http-404": 1}, summary["failure_reasons"])
        row = self.receipt_rows()[0]
        self.assertEqual(
            [], kr.schema_validation_errors(kr.snapshot_receipt_validator(), row)
        )
        self.assertEqual("fetch-failed", row["status"])
        self.assertEqual("http-404", row["error_state"])
        self.assertEqual(404, row["http_status"])
        self.assertEqual(1, row["attempt"])

    def test_retry_success_supersedes_prior_failure(self) -> None:
        channels = [("chn:policy:channel:pypi:v1:cmp-demo:package", self.uri("/flaky"))]
        baseline = self.baseline_path(channels)
        first = self.run_main(baseline)
        self.assertEqual(1, first["failed_uris"])
        Handler.responses["/flaky"] = (
            200,
            {"Content-Type": "application/json"},
            b"{}",
        )
        second = self.run_main(baseline)
        self.assertEqual(1, second["fetched_uris"])
        self.assertEqual(1, second["superseded_failure_rows"])
        rows = self.receipt_rows()
        self.assertEqual(1, len(rows))
        self.assertEqual("fetched", rows[0]["status"])

    def test_s3_uri_without_credentials_is_typed_failure(self) -> None:
        channels = [
            (
                "chn:policy:channel:pypi:v1:cmp-demo:package",
                "s3://example-models/demo",
            )
        ]
        summary = self.run_main(self.baseline_path(channels))
        self.assertEqual({"s3-credentials-unavailable": 1}, summary["failure_reasons"])
        row = self.receipt_rows()[0]
        self.assertEqual("fetch-failed", row["status"])
        self.assertIsNone(row["http_status"])
        self.assertEqual([], Handler.hits)

    def test_npm_abbreviated_fallback_is_typed_in_coordinates(self) -> None:
        Handler.responses["/packument"] = (
            200,
            {"Content-Type": "application/json"},
            b"y" * 256,
        )
        Handler.abbreviated_body = b'{"abbrev": true}'
        channels = [
            ("chn:policy:channel:pypi:v1:cmp-demo:package", self.uri("/packument"))
        ]
        with mock.patch.object(sc, "NPM_ABBREVIATED_HOSTS", frozenset({"127.0.0.1"})):
            summary = self.run_main(self.baseline_path(channels), "--max-bytes", "64")
        self.assertEqual(1, summary["fetched_uris"])
        row = self.receipt_rows()[0]
        self.assertEqual("fetched", row["status"])
        self.assertEqual({"packument": "abbreviated"}, row.get("coordinates"))
        digest = hashlib.sha256(Handler.abbreviated_body).hexdigest()
        self.assertEqual(f"sha256:{digest}", row["content_hash"])

    def test_unresolvable_host_is_typed_apart_from_a_transient_network_error(
        self,
    ) -> None:
        # Without the wrapped-reason check both cases collapse to
        # network-URLError, so asserting the generic case is what keeps this
        # test from passing vacuously.
        transient = urllib.error.URLError(ConnectionResetError("reset by peer"))
        self.assertEqual("network-URLError", sc.network_error_state(transient))
        self.assertEqual(
            "network-dns-unresolvable",
            sc.network_error_state(socket.gaierror(-2, "Name or service not known")),
        )

        wrapped = urllib.error.URLError(
            socket.gaierror(-2, "Name or service not known")
        )
        channels = [("chn:policy:channel:pypi:v1:cmp-demo:package", self.uri("/gone"))]
        with mock.patch.object(
            sc.HostWorker, "request_once", side_effect=wrapped
        ) as request_once:
            summary = self.run_main(self.baseline_path(channels), "--attempts", "1")
        self.assertEqual(1, request_once.call_count)
        self.assertEqual({"network-dns-unresolvable": 1}, summary["failure_reasons"])
        row = self.receipt_rows()[0]
        self.assertEqual("fetch-failed", row["status"])
        self.assertEqual("network-dns-unresolvable", row["error_state"])


if __name__ == "__main__":
    unittest.main()
