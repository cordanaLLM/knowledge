"""Verify the FastMCP server exports the intended Paperclip tool surface."""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
import unittest
from importlib.metadata import version
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).parent))


class DependencyContractTests(unittest.TestCase):
    def test_transport_dependency_versions_match_the_image_contract(self) -> None:
        self.assertEqual(
            {
                package: version(package)
                for package in ("fastmcp", "httpx", "mcp", "starlette")
            },
            {
                "fastmcp": "3.4.2",
                "httpx": "0.28.1",
                "mcp": "1.28.1",
                "starlette": "1.3.1",
            },
        )


class ServerToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ["OPENWEBUI_API_KEY"] = "unit-test"
        response = mock.Mock()
        response.json.return_value = [{"name": "cluster-knowledge", "id": "test-kb"}]
        with mock.patch("httpx.Client.get", return_value=response):
            cls.server = importlib.import_module("server")

    def test_exact_tool_surface_is_registered(self) -> None:
        tools = asyncio.run(self.server.mcp.list_tools())
        self.assertEqual(
            {tool.name for tool in tools},
            {
                "search_knowledge",
                "search_web",
                "fetch_web_page",
                "search_arxiv",
                "search_semantic_scholar",
                "search_openalex",
            },
        )

    def test_http_transport_uses_stateless_json_responses(self) -> None:
        with (
            mock.patch.object(self.server, "MCP_TRANSPORT", "http"),
            mock.patch.object(self.server, "MCP_PORT", 8001),
            mock.patch.object(self.server.mcp, "run") as run,
        ):
            self.server.serve()

        run.assert_called_once_with(
            transport="http",
            host="0.0.0.0",
            port=8001,
            json_response=True,
            stateless_http=True,
        )

    def test_http_initialize_is_json_not_sse(self) -> None:
        app = self.server.mcp.http_app(json_response=True, stateless_http=True)

        async def initialize() -> httpx.Response:
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://testserver",
                ) as client:
                    return await client.post(
                        "/mcp",
                        headers={
                            "Accept": "application/json, text/event-stream",
                            "Content-Type": "application/json",
                        },
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-03-26",
                                "capabilities": {},
                                "clientInfo": {
                                    "name": "unit-test",
                                    "version": "1.0",
                                },
                            },
                        },
                    )

        response = asyncio.run(initialize())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertNotIn("mcp-session-id", response.headers)
        self.assertEqual(response.json()["result"]["serverInfo"]["name"], "archeion-kb")


if __name__ == "__main__":
    unittest.main()
