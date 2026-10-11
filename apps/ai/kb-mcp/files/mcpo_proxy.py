"""Bounded, read-only proxies for the mcpo web and research routes."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from datetime import date
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

import httpx

MCPO_BASE = os.environ.get(
    "MCPO_BASE_URL", "http://mcpo:8000"
).rstrip("/")
MCPO_TIMEOUT = float(os.environ.get("MCPO_API_TIMEOUT_SECONDS", "90"))
MAX_RESPONSE_CHARS = int(os.environ.get("MCPO_MAX_RESPONSE_CHARS", "65536"))

_REGION_RE = re.compile(r"^(?:wt-wt|[a-z]{2}-[a-z]{2})$")
_CATEGORY_RE = re.compile(r"^[A-Za-z0-9.-]{2,32}$")
_BLOCKED_HOST_SUFFIXES = (
    ".cluster.local",
    ".internal",
    ".local",
    ".localhost",
    ".svc",
)


class InputError(ValueError):
    """A caller-supplied tool argument failed validation."""


def _failure(tool: str, message: str, *, upstream_status: int | None = None) -> dict:
    result: dict[str, Any] = {"ok": False, "tool": tool, "error": message}
    if upstream_status is not None:
        result["upstream_status"] = upstream_status
    return result


def _required_text(value: str, name: str, *, max_length: int = 500) -> str:
    text = value.strip()
    if not text:
        raise InputError(f"{name} must not be empty")
    if len(text) > max_length:
        raise InputError(f"{name} must be at most {max_length} characters")
    return text


def _bounded_int(value: int, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise InputError(f"{name} must be between {minimum} and {maximum}")
    return value


def _optional_year(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    return _bounded_int(value, name, 1000, date.today().year + 1)


def _optional_date(value: str, name: str) -> str | None:
    text = value.strip()
    if not text:
        return None
    try:
        date.fromisoformat(text)
    except ValueError as exc:
        raise InputError(f"{name} must use YYYY-MM-DD format") from exc
    return text


def _short_string_list(
    values: list[str] | None,
    name: str,
    *,
    maximum_items: int = 8,
    item_max_length: int = 64,
) -> list[str] | None:
    if values is None:
        return None
    if not isinstance(values, list):
        raise InputError(f"{name} must be a list")
    if len(values) > maximum_items:
        raise InputError(f"{name} accepts at most {maximum_items} values")
    cleaned: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise InputError(f"{name} values must be strings")
        item = _required_text(value, f"{name} value", max_length=item_max_length)
        cleaned.append(item)
    return cleaned or None


def _validate_public_url(
    value: str,
    *,
    resolver: Callable[..., list] = socket.getaddrinfo,
) -> str:
    url = _required_text(value, "url", max_length=2048)
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise InputError("url must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise InputError("url must not contain credentials")
    if not parsed.hostname:
        raise InputError("url must include a hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputError("url contains an invalid port") from exc
    if port not in {None, 80, 443}:
        raise InputError("url may only use port 80 or 443")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(_BLOCKED_HOST_SUFFIXES):
        raise InputError("url hostname is not public")

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname:
            raise InputError("url hostname must be a public fully-qualified name")
        try:
            addresses = resolver(
                hostname,
                port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise InputError("url hostname could not be resolved") from exc
        resolved_ips = {entry[4][0] for entry in addresses}
        if not resolved_ips:
            raise InputError("url hostname did not resolve to an address")
        try:
            ips = [ipaddress.ip_address(address) for address in resolved_ips]
        except ValueError as exc:
            raise InputError("url hostname resolved to an invalid address") from exc
    else:
        ips = [literal_ip]

    normalized_ips = [
        (
            ip.ipv4_mapped
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None
            else ip
        )
        for ip in ips
    ]
    if any(not ip.is_global for ip in normalized_ips):
        raise InputError("url hostname resolves to a non-public address")

    # Fragments are browser-local and should not be sent to the upstream fetcher.
    normalized_host = f"[{hostname}]" if ":" in hostname else hostname
    normalized_netloc = (
        f"{normalized_host}:{port}" if port is not None else normalized_host
    )
    return urlunsplit(
        (parsed.scheme.lower(), normalized_netloc, parsed.path, parsed.query, "")
    )


def _call_mcpo(
    route: str,
    endpoint_tool: str,
    body: dict[str, Any],
    *,
    result_tool: str | None = None,
    client: httpx.Client | None = None,
) -> dict:
    endpoint = f"{MCPO_BASE}/{route}/{endpoint_tool}"
    tool = result_tool or endpoint_tool
    owns_client = client is None
    active_client = client or httpx.Client(timeout=MCPO_TIMEOUT)
    try:
        response = active_client.post(endpoint, json=body)
    except httpx.TimeoutException:
        return _failure(tool, "research service timed out")
    except httpx.RequestError:
        return _failure(tool, "research service is unavailable")
    finally:
        if owns_client:
            active_client.close()

    if not response.is_success:
        return _failure(
            tool,
            "research service rejected the request",
            upstream_status=response.status_code,
        )
    try:
        payload = response.json()
    except ValueError:
        return _failure(tool, "research service returned an invalid response")

    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    truncated = len(serialized) > MAX_RESPONSE_CHARS
    if truncated:
        payload = serialized[:MAX_RESPONSE_CHARS]
    return {
        "ok": True,
        "tool": tool,
        "external_content": True,
        "truncated": truncated,
        "data": payload,
    }


def search_web(query: str, max_results: int = 8, region: str = "wt-wt") -> dict:
    """Search the public web through the keyless DuckDuckGo mcpo route."""
    try:
        body = {
            "query": _required_text(query, "query"),
            "max_results": _bounded_int(max_results, "max_results", 1, 20),
            "region": region.strip().lower(),
        }
        if not _REGION_RE.fullmatch(body["region"]):
            raise InputError("region must look like wt-wt, us-en, or uk-en")
    except InputError as exc:
        return _failure("search_web", str(exc))
    return _call_mcpo("duckduckgo", "search", body, result_tool="search_web")


def fetch_web_page(
    url: str,
    start_index: int = 0,
    max_length: int = 8000,
) -> dict:
    """Fetch readable text from a public HTTP(S) page through mcpo."""
    try:
        body = {
            "url": _validate_public_url(url),
            "start_index": _bounded_int(start_index, "start_index", 0, 500_000),
            "max_length": _bounded_int(max_length, "max_length", 500, 20_000),
            "backend": "httpx",
        }
    except InputError as exc:
        return _failure("fetch_web_page", str(exc))
    return _call_mcpo("duckduckgo", "fetch_content", body, result_tool="fetch_web_page")


def search_arxiv(
    query: str,
    max_results: int = 8,
    date_from: str = "",
    date_to: str = "",
    categories: list[str] | None = None,
    sort_by: str = "relevance",
) -> dict:
    """Search arXiv metadata and abstracts through mcpo."""
    try:
        cleaned_categories = _short_string_list(
            categories, "categories", item_max_length=32
        )
        if cleaned_categories and any(
            not _CATEGORY_RE.fullmatch(category) for category in cleaned_categories
        ):
            raise InputError("categories contains an invalid arXiv category")
        cleaned_sort = sort_by.strip().lower()
        if cleaned_sort not in {"relevance", "date"}:
            raise InputError("sort_by must be relevance or date")
        body: dict[str, Any] = {
            "query": _required_text(query, "query"),
            "max_results": _bounded_int(max_results, "max_results", 1, 20),
            "sort_by": cleaned_sort,
        }
        for key, value in (
            ("date_from", _optional_date(date_from, "date_from")),
            ("date_to", _optional_date(date_to, "date_to")),
            ("categories", cleaned_categories),
        ):
            if value is not None:
                body[key] = value
        if body.get("date_from") and body.get("date_to"):
            if body["date_from"] > body["date_to"]:
                raise InputError("date_from must not be after date_to")
    except InputError as exc:
        return _failure("search_arxiv", str(exc))
    return _call_mcpo("arxiv", "search_papers", body, result_tool="search_arxiv")


def search_semantic_scholar(
    query: str,
    limit: int = 8,
    offset: int = 0,
    year: int | None = None,
    fields_of_study: list[str] | None = None,
    sort: str = "relevance",
) -> dict:
    """Search Semantic Scholar papers and citation metadata through mcpo."""
    try:
        cleaned_sort = sort.strip()
        if cleaned_sort not in {"relevance", "citationCount", "year"}:
            raise InputError("sort must be relevance, citationCount, or year")
        body: dict[str, Any] = {
            "query": _required_text(query, "query"),
            "limit": _bounded_int(limit, "limit", 1, 20),
            "offset": _bounded_int(offset, "offset", 0, 1000),
            "sort": cleaned_sort,
        }
        cleaned_year = _optional_year(year, "year")
        cleaned_fields = _short_string_list(fields_of_study, "fields_of_study")
        if cleaned_year is not None:
            body["year"] = cleaned_year
        if cleaned_fields is not None:
            body["fields_of_study"] = cleaned_fields
    except InputError as exc:
        return _failure("search_semantic_scholar", str(exc))
    return _call_mcpo(
        "semantic-scholar",
        "search_papers",
        body,
        result_tool="search_semantic_scholar",
    )


def search_openalex(
    query: str,
    per_page: int = 8,
    page: int = 1,
    from_year: int | None = None,
    to_year: int | None = None,
    min_citations: int = 0,
    sort: str = "relevance_score",
    open_access_only: bool = False,
) -> dict:
    """Search OpenAlex scholarly works through mcpo."""
    try:
        cleaned_sort = sort.strip().lower()
        if cleaned_sort not in {
            "relevance_score",
            "cited_by_count:desc",
            "publication_year:desc",
        }:
            raise InputError(
                "sort must be relevance_score, cited_by_count:desc, "
                "or publication_year:desc"
            )
        cleaned_from = _optional_year(from_year, "from_year")
        cleaned_to = _optional_year(to_year, "to_year")
        if cleaned_from is not None and cleaned_to is not None:
            if cleaned_from > cleaned_to:
                raise InputError("from_year must not be after to_year")
        if not isinstance(open_access_only, bool):
            raise InputError("open_access_only must be a boolean")
        body: dict[str, Any] = {
            "query": _required_text(query, "query"),
            "per_page": _bounded_int(per_page, "per_page", 1, 20),
            "page": _bounded_int(page, "page", 1, 100),
            "min_citations": _bounded_int(
                min_citations, "min_citations", 0, 10_000_000
            ),
            "sort": cleaned_sort,
            "is_oa": open_access_only,
        }
        if cleaned_from is not None:
            body["from_year"] = cleaned_from
        if cleaned_to is not None:
            body["to_year"] = cleaned_to
    except InputError as exc:
        return _failure("search_openalex", str(exc))
    return _call_mcpo("openalex", "search_works", body, result_tool="search_openalex")
