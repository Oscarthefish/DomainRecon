"""HudsonRock Cavalier breach corpus integration with SSO exposure correlation."""

from __future__ import annotations

import httpx

from .models import Finding, ScanResult, Severity

_CAVALIER_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
_USER_AGENT = "DomainRecon/0.1 (+authorized-security-assessment)"


async def check_breach_exposure(root: str, result: ScanResult, timeout: float = 8.0) -> None:
    """Query HudsonRock Cavalier for infostealer breach exposure and emit findings."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        ) as client:
            resp = await client.get(_CAVALIER_URL, params={"domain": root})
        if not resp.is_success:
            return
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return

    total = data.get("total") or {}
    employees: int = total.get("employees") or 0
    users: int = total.get("users") or 0

    if employees == 0 and users == 0:
        return

    inner = data.get("data") or {}
    stealer_fams = sorted((inner.get("stealer_families") or {}).keys())
    source_url = f"https://www.hudsonrock.com/search?domain={root}"

    # Severity: employee credentials are more dangerous than end-user credentials
    if employees >= 10:
        severity = Severity.HIGH
    elif employees >= 1:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM

    evidence_parts: list[str] = []
    if employees:
        evidence_parts.append(f"{employees} employee account(s)")
    if users:
        evidence_parts.append(f"{users} customer/user account(s)")
    if stealer_fams:
        evidence_parts.append(f"malware families: {', '.join(stealer_fams[:6])}")

    result.findings.append(
        Finding(
            source_url,
            f"Infostealer breach exposure — {root}",
            severity,
            "breach-exposure",
            "; ".join(evidence_parts),
            "Require immediate password resets for all potentially affected accounts. "
            "Enforce MFA across the organization. Audit authentication logs for signs of "
            "credential stuffing or unauthorized access.",
            "hudsonrock",
        )
    )

    # SSO exposure compound finding: employee breach + discovered IdP = privileged access at risk
    if employees >= 1:
        idp_assets = [
            a for a in result.assets.values()
            if a.kind == "url" and any(
                marker in a.value.lower()
                for marker in ("openid-configuration", "saml", "okta.com", "microsoftonline.com")
            )
        ]
        if idp_assets:
            idp_endpoints = ", ".join(a.value for a in idp_assets[:3])
            result.findings.append(
                Finding(
                    source_url,
                    f"SSO exposure risk: employee credential(s) compromised + IdP discovered",
                    Severity.HIGH,
                    "sso-exposure",
                    f"{employees} employee account(s) in infostealer corpus; "
                    f"identity provider endpoint(s) found: {idp_endpoints}",
                    "Immediately review SSO audit logs for suspicious authentication events. "
                    "Force re-authentication for all employees and consider temporary "
                    "conditional access policy enforcement.",
                    "hudsonrock",
                )
            )
