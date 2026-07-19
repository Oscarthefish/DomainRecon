"""Subdomain takeover detection via CNAME fingerprinting."""

from __future__ import annotations

import asyncio
import re

import httpx

from .models import Asset, Edge, Finding, ScanResult, Severity


# CNAME target pattern → (provider_name, takeover_signature_regex)
# Signature is matched against the response body of the CNAME target.
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, str]] = {
    "github.io":           ("GitHub Pages",          r"There isn't a GitHub Pages site here"),
    "herokuapp.com":       ("Heroku",                r"No such app"),
    "s3.amazonaws.com":    ("AWS S3",                r"NoSuchBucket|The specified bucket"),
    "cloudfront.net":      ("AWS CloudFront",        r"The request could not be satisfied"),
    "azurewebsites.net":   ("Azure Web Apps",        r"404 Web Site not found|Microsoft Azure App"),
    "azure-api.net":       ("Azure API Management",  r"ResourceNotFound"),
    "trafficmanager.net":  ("Azure Traffic Manager", r"404 - File or directory not found"),
    "shopify.com":         ("Shopify",               r"Sorry, this shop is currently unavailable"),
    "wordpress.com":       ("WordPress",             r"Do you want to register"),
    "fastly.net":          ("Fastly",                r"Fastly error: unknown domain"),
    "pantheon.io":         ("Pantheon",              r"The gods are wise"),
    "surge.sh":            ("Surge.sh",              r"project not found"),
    "ngrok.io":            ("ngrok",                 r"Tunnel .* not found"),
    "zendesk.com":         ("Zendesk",               r"Help Center Closed"),
    "helpscoutdocs.com":   ("HelpScout",             r"No settings were found"),
    "ghost.io":            ("Ghost",                 r"Used internally by Ghost"),
    "myshopify.com":       ("Shopify",               r"Sorry, this shop is currently unavailable"),
    "readthedocs.io":      ("Read the Docs",         r"unknown to Read the Docs"),
    "readme.io":           ("ReadMe",                r"Project doesnt exist"),
    "feedpress.me":        ("FeedPress",             r"The feed has not been found"),
    "statuspage.io":       ("Atlassian Statuspage",  r"You are being"),
    "bitbucket.io":        ("Bitbucket",             r"Repository not found"),
    "cloudapp.net":        ("Azure Cloud App",       r"404 - File or directory not found"),
    "tumblr.com":          ("Tumblr",                r"There's nothing here"),
    "unbounce.com":        ("Unbounce",              r"The requested URL was not found"),
    "hubspot.net":         ("HubSpot",               r"This page cannot be found"),
    "webflow.io":          ("Webflow",               r"The page you are looking for doesn't exist"),
}


async def check_takeovers(result: ScanResult, timeout: float = 8.0) -> None:
    """Inspect all discovered CNAME edges for potential subdomain takeover vulnerabilities."""
    # Collect (subdomain, cname_target) pairs from the scan result edges
    cname_pairs: list[tuple[str, str]] = []
    for edge in result.edges:
        if edge.relation != "cname":
            continue
        subdomain = edge.source.removeprefix("domain:")
        cname_target = edge.target.removeprefix("dns_record:").rstrip(".")
        cname_pairs.append((subdomain, cname_target))

    if not cname_pairs:
        return

    semaphore = asyncio.Semaphore(10)

    async def _check_pair(subdomain: str, cname_target: str) -> None:
        provider, signature_pattern = _match_fingerprint(cname_target)
        if not provider:
            return
        async with semaphore:
            await _probe_takeover(subdomain, cname_target, provider, signature_pattern, result, timeout)

    await asyncio.gather(*(_check_pair(sub, cname) for sub, cname in cname_pairs))


def _match_fingerprint(cname_target: str) -> tuple[str, str] | tuple[None, None]:
    lowered = cname_target.lower()
    for suffix, (provider, signature) in TAKEOVER_FINGERPRINTS.items():
        if lowered.endswith(f".{suffix}") or lowered == suffix:
            return provider, signature
    return None, None


async def _probe_takeover(
    subdomain: str,
    cname_target: str,
    provider: str,
    signature_pattern: str,
    result: ScanResult,
    timeout: float,
) -> None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}/"
        try:
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=True, verify=False
            ) as client:
                response = await client.get(url)
                body = response.text[:20_000]
        except httpx.HTTPError:
            continue

        if re.search(signature_pattern, body, re.IGNORECASE):
            root = next(
                (t for t in result.targets if subdomain == t or subdomain.endswith(f".{t}")),
                subdomain,
            )
            asset_url = url
            result.add_asset(
                Asset(
                    "url",
                    asset_url,
                    root,
                    "takeover-probe",
                    attributes={"cname_target": cname_target, "provider": provider},
                )
            )
            result.add_edge(
                Edge(f"domain:{subdomain}", f"url:{asset_url}", "takeover-candidate", provider)
            )
            result.findings.append(
                Finding(
                    asset_url,
                    f"Subdomain takeover candidate — {provider}",
                    Severity.HIGH,
                    "takeover",
                    f"CNAME {subdomain} → {cname_target}; {provider} signature matched in response body",
                    f"Claim or remove the dangling {provider} resource, then delete the CNAME record.",
                    "http",
                )
            )
            return  # one finding per subdomain is enough
