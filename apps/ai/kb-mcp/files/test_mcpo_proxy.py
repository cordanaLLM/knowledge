"""Unit tests for the bounded mcpo proxy layer."""

from __future__ import annotations

import importlib
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).parent))
proxy = importlib.import_module("mcpo_proxy")


def public_resolver(host: str, port: int, *, type: int) -> list:
    del host, port
    return [(socket.AF_INET, type, 6, "", ("93.184.216.34", 443))]


def private_resolver(host: str, port: int, *, type: int) -> list:
    del host, port
    return [(socket.AF_INET, type, 6, "", ("10.1.2.3", 443))]


class PublicUrlTests(unittest.TestCase):
    def test_public_url_is_accepted_and_fragment_removed(self) -> None:
        self.assertEqual(
            proxy._validate_public_url(
                "https://example.com/article?q=1#section", resolver=public_resolver
            ),
            "https://example.com/article?q=1",
        )

    def test_private_resolution_is_rejected(self) -> None:
        with self.assertRaisesRegex(proxy.InputError, "non-public"):
            proxy._validate_public_url(
                "https://example.test/article", resolver=private_resolver
            )

    def test_cluster_service_and_credentials_are_rejected(self) -> None:
        for url in (
            "http://mcpo.example.svc.cluster.local:8000/docs",
            "https://user:password@example.com/",
            "http://127.0.0.1/",
            "http://[::ffff:127.0.0.1]/",
        ):
            with self.subTest(url=url), self.assertRaises(proxy.InputError):
                proxy._validate_public_url(url, resolver=public_resolver)


class McpoCallTests(unittest.TestCase):
    def test_success_is_marked_as_external_content(self) -> None:
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"results": [{"title": "Example"}]}, request=request
            )
        )
        with httpx.Client(transport=transport) as client:
            result = proxy._call_mcpo(
                "duckduckgo", "search", {"query": "example"}, client=client
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["external_content"])
        self.assertFalse(result["truncated"])
        self.assertEqual(result["data"]["results"][0]["title"], "Example")

    def test_timeout_degrades_to_a_bounded_error(self) -> None:
        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timeout", request=request)

        with httpx.Client(transport=httpx.MockTransport(timeout)) as client:
            result = proxy._call_mcpo(
                "arxiv", "search_papers", {"query": "example"}, client=client
            )
        self.assertEqual(
            result,
            {
                "ok": False,
                "tool": "search_papers",
                "error": "research service timed out",
            },
        )

    def test_upstream_error_does_not_echo_response_body(self) -> None:
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                503, text="sensitive upstream detail", request=request
            )
        )
        with httpx.Client(transport=transport) as client:
            result = proxy._call_mcpo(
                "openalex", "search_works", {"query": "example"}, client=client
            )
        self.assertEqual(result["upstream_status"], 503)
        self.assertNotIn("sensitive", str(result))

    def test_large_response_is_truncated(self) -> None:
        transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json="x" * 100, request=request)
        )
        with (
            mock.patch.object(proxy, "MAX_RESPONSE_CHARS", 20),
            httpx.Client(transport=transport) as client,
        ):
            result = proxy._call_mcpo(
                "duckduckgo", "search", {"query": "example"}, client=client
            )
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["data"]), 20)


class ToolMappingTests(unittest.TestCase):
    @mock.patch.object(proxy, "_call_mcpo")
    def test_web_search_uses_global_region_by_default(self, call: mock.Mock) -> None:
        call.return_value = {"ok": True}
        result = proxy.search_web("history of technology")
        self.assertEqual(result, {"ok": True})
        call.assert_called_once_with(
            "duckduckgo",
            "search",
            {
                "query": "history of technology",
                "max_results": 8,
                "region": "wt-wt",
            },
            result_tool="search_web",
        )

    @mock.patch.object(proxy, "_call_mcpo")
    def test_arxiv_filters_are_forwarded(self, call: mock.Mock) -> None:
        call.return_value = {"ok": True}
        proxy.search_arxiv(
            'ti:"history of technology"',
            max_results=5,
            date_from="2000-01-01",
            categories=["physics.hist-ph"],
            sort_by="date",
        )
        call.assert_called_once_with(
            "arxiv",
            "search_papers",
            {
                "query": 'ti:"history of technology"',
                "max_results": 5,
                "sort_by": "date",
                "date_from": "2000-01-01",
                "categories": ["physics.hist-ph"],
            },
            result_tool="search_arxiv",
        )

    @mock.patch.object(proxy, "_call_mcpo")
    @mock.patch.object(proxy, "_validate_public_url")
    def test_fetch_forces_safe_httpx_backend(
        self, validate_url: mock.Mock, call: mock.Mock
    ) -> None:
        validate_url.return_value = "https://example.com/article"
        call.return_value = {"ok": True}
        proxy.fetch_web_page("https://example.com/article", 50, 1000)
        call.assert_called_once_with(
            "duckduckgo",
            "fetch_content",
            {
                "url": "https://example.com/article",
                "start_index": 50,
                "max_length": 1000,
                "backend": "httpx",
            },
            result_tool="fetch_web_page",
        )

    def test_invalid_ranges_do_not_reach_mcpo(self) -> None:
        cases = (
            proxy.search_web("query", max_results=21),
            proxy.search_arxiv("query", date_from="2026-02-30"),
            proxy.search_semantic_scholar("query", offset=1001),
            proxy.search_openalex("query", from_year=2020, to_year=1900),
        )
        self.assertTrue(all(result["ok"] is False for result in cases))


if __name__ == "__main__":
    unittest.main()
