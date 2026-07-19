"""JavaScript analysis: sourcemaps, endpoint extraction, secret and leakage scanning."""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin

import httpx

from .models import Finding, ScanResult, Severity
from .secrets import scan_body

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\'> ]+)["\']', re.IGNORECASE)
_SOURCEMAP_RE = re.compile(r'//[#@] sourceMappingURL=(\S+)', re.IGNORECASE)

# Endpoint extraction — 3 tiers ordered by specificity
_ENDPOINT_PATTERNS = [
    # Tier 1: paths starting with a known API prefix
    re.compile(r'["\']/((?:api|v\d+|rest|graphql|auth|oauth|admin|internal)/[^\s"\'<>]{2,80})["\']'),
    # Tier 2: at least two path segments, letters/digits only
    re.compile(r'"(/[a-zA-Z][a-zA-Z0-9_-]*/[a-zA-Z][a-zA-Z0-9_/-]{1,60})"'),
]

# RFC1918 and common internal DNS patterns
_INTERNAL_RE = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|[\w-]+\.(?:svc\.cluster\.local|internal|corp|lan|intranet))\b',
    re.IGNORECASE,
)

MAX_SCRIPTS = 8
MAX_SCRIPT_BYTES = 50_000
MAX_SOURCEMAP_BYTES = 300_000


async def analyze_javascript(
    base_url: str,
    html: str,
    root: str,
    result: ScanResult,
    client: httpx.AsyncClient,
) -> None:
    """Fetch and analyze JavaScript files referenced from an HTML page."""
    srcs = _SCRIPT_SRC_RE.findall(html)
    external = [s for s in srcs if not s.startswith("data:")][:MAX_SCRIPTS]
    if not external:
        return
    await asyncio.gather(
        *(_analyze_one(src, base_url, root, result, client) for src in external),
        return_exceptions=True,
    )


async def _analyze_one(
    src: str,
    base_url: str,
    root: str,
    result: ScanResult,
    client: httpx.AsyncClient,
) -> None:
    script_url = urljoin(base_url, src)
    if not script_url.startswith(("http://", "https://")):
        return

    try:
        resp = await client.get(script_url)
        if resp.status_code != 200:
            return
        body = resp.text[:MAX_SCRIPT_BYTES]
    except httpx.HTTPError:
        return

    # Secret scanning on the script body
    scan_body(script_url, body, root, result)

    # Internal host leakage detection
    internal_hits = set(_INTERNAL_RE.findall(body))
    if internal_hits:
        result.findings.append(
            Finding(
                script_url,
                "Internal host references in JavaScript",
                Severity.MEDIUM,
                "info-disclosure",
                f"Leaked: {', '.join(sorted(internal_hits)[:8])}",
                "Remove internal hostnames and IP addresses from client-side code before deployment.",
                "http",
            )
        )

    # Sourcemap analysis
    sm_match = _SOURCEMAP_RE.search(body)
    if sm_match:
        sm_ref = sm_match.group(1).strip()
        if not sm_ref.startswith("data:"):
            sm_url = urljoin(script_url, sm_ref)
            await _analyze_sourcemap(script_url, sm_url, root, result, client)

    # Endpoint extraction
    _extract_endpoints(script_url, body, root, result)


async def _analyze_sourcemap(
    script_url: str,
    sm_url: str,
    root: str,
    result: ScanResult,
    client: httpx.AsyncClient,
) -> None:
    try:
        resp = await client.get(sm_url)
        if resp.status_code != 200:
            return
        raw = resp.text[:MAX_SOURCEMAP_BYTES]
    except httpx.HTTPError:
        return

    result.findings.append(
        Finding(
            sm_url,
            "JavaScript source map is publicly accessible",
            Severity.HIGH,
            "source-map",
            f"Fetched {len(raw):,} chars from {sm_url}; original source may be reconstructable.",
            "Remove source maps from production builds, or serve them only to authenticated internal users.",
            "http",
        )
    )

    try:
        sm_data = json.loads(raw)
        sources_content = sm_data.get("sourcesContent") or []
        if not isinstance(sources_content, list):
            return
        combined = "\n".join(str(s) for s in sources_content if s)[:MAX_SCRIPT_BYTES * 4]
        if combined:
            scan_body(sm_url, combined, root, result)
            _extract_endpoints(sm_url, combined, root, result)
    except (json.JSONDecodeError, TypeError):
        pass


def _extract_endpoints(source_url: str, body: str, root: str, result: ScanResult) -> None:
    found: set[str] = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(body):
            path = match.group(1)
            if path and 3 < len(path) < 120:
                found.add(path)

    if len(found) < 3:
        return

    sample = sorted(found)[:10]
    result.findings.append(
        Finding(
            source_url,
            f"API endpoint paths extracted from JavaScript ({len(found)} paths)",
            Severity.INFO,
            "js-endpoints",
            f"Sample: {', '.join(sample[:6])}",
            "Review extracted paths for undocumented, administrative, or internal-only endpoints "
            "that may be accessible without authentication.",
            "http",
        )
    )
