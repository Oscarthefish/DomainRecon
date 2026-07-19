"""Cloud storage bucket enumeration via candidate permutation."""

from __future__ import annotations

import asyncio
import re

import httpx

from .models import Asset, Edge, Finding, ScanResult, Severity


_PREFIXES = ("", "dev-", "staging-", "prod-", "backup-", "data-", "static-")
_SUFFIXES = ("", "-dev", "-staging", "-prod", "-backup", "-data", "-static", "-assets")

# Bucket listing response markers
_S3_LIST_RE = re.compile(r"<ListBucketResult", re.IGNORECASE)
_S3_DENIED_RE = re.compile(r"<Code>AccessDenied|<Code>AllAccessDisabled", re.IGNORECASE)
_S3_MISSING_RE = re.compile(r"<Code>NoSuchBucket", re.IGNORECASE)
_GCS_LIST_RE = re.compile(r'"kind":\s*"storage#objects"|<ListBucketResult', re.IGNORECASE)


def _candidates(root: str) -> set[str]:
    """Generate bucket name candidates from a root domain."""
    stem = root.split(".")[0]
    names: set[str] = set()
    for prefix in _PREFIXES:
        for suffix in _SUFFIXES:
            names.add(f"{prefix}{stem}{suffix}")
    names.add(root.replace(".", "-"))
    return names


async def enumerate_buckets(root: str, result: ScanResult, timeout: float = 8.0) -> None:
    """Probe S3 and GCS bucket name candidates derived from the root domain."""
    candidates = _candidates(root)
    semaphore = asyncio.Semaphore(15)
    headers = {"User-Agent": "DomainRecon/0.1 (+authorized-security-assessment)"}

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, headers=headers, verify=True
    ) as client:
        await asyncio.gather(
            *(_probe_candidate(client, name, root, result, semaphore) for name in sorted(candidates))
        )


async def _probe_candidate(
    client: httpx.AsyncClient,
    name: str,
    root: str,
    result: ScanResult,
    semaphore: asyncio.Semaphore,
) -> None:
    async with semaphore:
        await asyncio.gather(
            _probe_s3(client, name, root, result),
            _probe_gcs(client, name, root, result),
        )


async def _probe_s3(
    client: httpx.AsyncClient, name: str, root: str, result: ScanResult
) -> None:
    url = f"https://{name}.s3.amazonaws.com/?max-keys=1"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return

    body = resp.text[:8_000]

    if resp.status_code == 200 and _S3_LIST_RE.search(body):
        _record(
            result, root, name, "AWS S3", url,
            f"S3 bucket {name!r} is publicly listable — HTTP 200 with ListBucketResult",
            Severity.HIGH,
            "Remove public access block or apply a restrictive bucket policy. "
            "Audit bucket contents for sensitive data immediately.",
        )
    elif resp.status_code == 403 and not _S3_MISSING_RE.search(body):
        _record(
            result, root, name, "AWS S3", f"https://{name}.s3.amazonaws.com/",
            f"S3 bucket {name!r} exists (HTTP 403 — access denied)",
            Severity.LOW,
            "Confirm this bucket is intentional and that its ACL/policy is correctly restricted.",
        )
    # 404 + NoSuchBucket → bucket does not exist, skip silently


async def _probe_gcs(
    client: httpx.AsyncClient, name: str, root: str, result: ScanResult
) -> None:
    url = f"https://storage.googleapis.com/{name}/?max-results=1"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return

    body = resp.text[:8_000]

    if resp.status_code == 200 and _GCS_LIST_RE.search(body):
        _record(
            result, root, name, "Google Cloud Storage", url,
            f"GCS bucket {name!r} is publicly listable — HTTP 200",
            Severity.HIGH,
            "Set the bucket's IAM policy to deny allUsers and allAuthenticatedUsers. "
            "Audit bucket contents for sensitive data immediately.",
        )
    elif resp.status_code == 403:
        _record(
            result, root, name, "Google Cloud Storage", f"https://storage.googleapis.com/{name}/",
            f"GCS bucket {name!r} exists (HTTP 403 — access denied)",
            Severity.LOW,
            "Confirm this bucket is intentional and that its IAM policy is correctly restricted.",
        )
    # 404 → bucket does not exist, skip silently


def _record(
    result: ScanResult,
    root: str,
    name: str,
    provider: str,
    url: str,
    evidence: str,
    severity: Severity,
    remediation: str,
) -> None:
    asset = Asset(
        "bucket", url, root, "cloud-enum",
        attributes={"provider": provider, "bucket_name": name},
    )
    result.add_asset(asset)
    result.add_edge(Edge(f"domain:{root}", asset.key, "cloud-asset", provider))
    result.findings.append(
        Finding(url, f"{provider} bucket discovered: {name}", severity, "cloud-storage", evidence, remediation, "http")
    )
