from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlparse


WEB_TOP_10 = {
    "A01:2021": (
        "Broken Access Control",
        "manual",
        "Requires authenticated roles and object-level authorization tests.",
    ),
    "A02:2021": (
        "Cryptographic Failures",
        "tested",
        "TLS, HTTPS and session-cookie signals are checked.",
    ),
    "A03:2021": (
        "Injection",
        "manual",
        "Parameter mutation is intentionally excluded from safe reconnaissance.",
    ),
    "A04:2021": (
        "Insecure Design",
        "manual",
        "Requires threat modelling and business-logic context.",
    ),
    "A05:2021": (
        "Security Misconfiguration",
        "tested",
        "Headers, CORS, methods, debug paths and exposed files are checked.",
    ),
    "A06:2021": (
        "Vulnerable and Outdated Components",
        "manual",
        "Technology fingerprints are collected; reliable version validation is still required.",
    ),
    "A07:2021": (
        "Identification and Authentication Failures",
        "tested",
        "Authentication surfaces and session-cookie controls are inspected.",
    ),
    "A08:2021": (
        "Software and Data Integrity Failures",
        "tested",
        "Git metadata, source maps and exposed configuration are checked.",
    ),
    "A09:2021": (
        "Security Logging and Monitoring Failures",
        "manual",
        "External reconnaissance cannot verify server-side logging coverage.",
    ),
    "A10:2021": (
        "Server-Side Request Forgery",
        "manual",
        "Safe validation requires a controlled callback service and explicit authorization.",
    ),
}

API_TOP_10 = {
    "API1:2023": (
        "Broken Object Level Authorization",
        "manual",
        "Requires authenticated object-level comparisons.",
    ),
    "API2:2023": (
        "Broken Authentication",
        "tested",
        "Authentication declarations and exposed authentication surfaces are inspected.",
    ),
    "API3:2023": (
        "Broken Object Property Level Authorization",
        "manual",
        "Requires authenticated response and property comparisons.",
    ),
    "API4:2023": (
        "Unrestricted Resource Consumption",
        "manual",
        "Rate and resource-limit tests are intentionally excluded.",
    ),
    "API5:2023": (
        "Broken Function Level Authorization",
        "manual",
        "Schemas generate leads; role-based validation remains manual.",
    ),
    "API6:2023": (
        "Unrestricted Access to Sensitive Business Flows",
        "manual",
        "Requires business-flow and abuse-case context.",
    ),
    "API7:2023": (
        "Server Side Request Forgery",
        "manual",
        "Requires a controlled callback service.",
    ),
    "API8:2023": (
        "Security Misconfiguration",
        "tested",
        "CORS, methods, schemas, GraphQL and exposed files are checked.",
    ),
    "API9:2023": (
        "Improper Inventory Management",
        "tested",
        "Public schemas and discovered API endpoints are inventoried.",
    ),
    "API10:2023": (
        "Unsafe Consumption of APIs",
        "manual",
        "Requires trust-boundary and downstream integration analysis.",
    ),
}

CATEGORY_MAP = {
    "http-headers": ("A02:2021", "A05:2021"),
    "cors": ("A01:2021", "A05:2021", "API8:2023"),
    "authentication": ("A07:2021", "API2:2023"),
    "session": ("A02:2021", "A07:2021", "API2:2023"),
    "api": ("A01:2021", "API5:2023", "API9:2023"),
    "api-auth": ("A01:2021", "API2:2023", "API5:2023"),
    "exposure": ("A05:2021", "A08:2021", "API8:2023"),
    "data-store": ("A01:2021", "A05:2021"),
    "http-methods": ("A05:2021", "API8:2023"),
    "source-map": ("A05:2021", "A08:2021"),
    "technology": ("A06:2021",),
    "tls": ("A02:2021",),
}


def mappings_for(category: str) -> list[str]:
    return list(CATEGORY_MAP.get(category, ()))


def coverage(findings: Iterable[dict[str, Any]], has_api: bool = False) -> dict[str, Any]:
    finding_rows = list(findings)
    signalled = {item for row in finding_rows for item in row.get("owasp", [])}

    def rows(catalog: dict[str, tuple[str, str, str]]) -> list[dict[str, Any]]:
        output = []
        for identifier, (name, default, note) in catalog.items():
            state = "signal" if identifier in signalled else default
            matched = [row for row in finding_rows if identifier in row.get("owasp", [])]
            assets = sorted({str(row.get("asset", "")) for row in matched if row.get("asset")})
            domains = sorted(
                {urlparse(asset).hostname or asset.split("/", 1)[0] for asset in assets if asset}
            )
            output.append(
                {
                    "id": identifier,
                    "name": name,
                    "state": state,
                    "note": note,
                    "finding_count": len(matched),
                    "assets": assets,
                    "domains": domains,
                }
            )
        return output

    return {
        "web": rows(WEB_TOP_10),
        "api": rows(API_TOP_10) if has_api else [],
        "disclaimer": "Coverage describes checks performed and investigation signals; it is not a compliance result or proof that a category is secure.",
    }


def hydrate_result(data: dict[str, Any]) -> dict[str, Any]:
    """Add OWASP metadata to reports created before coverage support existed."""
    findings = data.get("findings", [])
    for finding in findings:
        finding.setdefault("owasp", mappings_for(str(finding.get("category", ""))))
    has_api = any(item.get("category") in {"api", "api-auth"} for item in findings)
    data["owasp_coverage"] = coverage(findings, has_api)
    return data
