"""Credential and secret pattern scanning for HTTP response bodies."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, ScanResult, Severity


@dataclass(frozen=True)
class SecretPattern:
    name: str
    severity: Severity
    category: str
    pattern: re.Pattern[str]


def _p(name: str, severity: Severity, category: str, regex: str) -> SecretPattern:
    return SecretPattern(name, severity, category, re.compile(regex))


_H = Severity.HIGH
_M = Severity.MEDIUM

PATTERNS: list[SecretPattern] = [
    _p("AWS_ACCESS_KEY",       _H, "cloud",   r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    _p("AWS_SECRET_KEY",       _H, "cloud",   r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]"),
    _p("GCP_SERVICE_ACCOUNT",  _H, "cloud",   r'"type":\s*"service_account"'),
    _p("GH_PAT_CLASSIC",       _H, "vcs",     r"\bghp_[A-Za-z0-9]{36}\b"),
    _p("GH_PAT_FINE",          _H, "vcs",     r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    _p("GH_OAUTH",             _H, "vcs",     r"\bgho_[A-Za-z0-9]{36}\b"),
    _p("GH_ACTIONS",           _H, "vcs",     r"\bghs_[A-Za-z0-9]{36}\b"),
    _p("GH_REFRESH",           _H, "vcs",     r"\bghr_[A-Za-z0-9]{76}\b"),
    _p("GITLAB_PAT",           _H, "vcs",     r"\bglpat-[A-Za-z0-9\-_]{20}\b"),
    _p("ANTHROPIC_API",        _H, "ai_api",  r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b"),
    _p("OPENAI_LEGACY",        _H, "ai_api",  r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    _p("OPENAI_NEW",           _H, "ai_api",  r"\bsk-proj-[A-Za-z0-9_\-]{48}\b"),
    _p("HUGGINGFACE",          _H, "ai_api",  r"\bhf_[A-Za-z0-9]{37}\b"),
    _p("STRIPE_SECRET",        _H, "payment", r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    _p("STRIPE_RESTRICTED",    _H, "payment", r"\brk_live_[A-Za-z0-9]{24,}\b"),
    _p("TWILIO_SID",           _H, "comms",   r"\bAC[a-f0-9]{32}\b"),
    _p("TWILIO_TOKEN",         _H, "comms",   r"(?i)twilio.{0,20}['\"]([a-f0-9]{32})['\"]"),
    _p("SLACK_BOT",            _H, "comms",   r"\bxoxb-[0-9]{11,12}-[0-9]{11,12}-[A-Za-z0-9]{24}\b"),
    _p("SLACK_APP",            _H, "comms",   r"\bxapp-[A-Za-z0-9\-_]{93,}\b"),
    _p("SLACK_LEGACY",         _H, "comms",   r"\bxoxp-[0-9]{11,12}-[0-9]{11,12}-[0-9]{11,12}-[a-f0-9]{32}\b"),
    _p("CLOUDFLARE_KEY",       _H, "cloud",   r"\b[A-Za-z0-9_\-]{37}CLOUDFLARE[A-Za-z0-9_\-]{37}\b"),
    _p("CLOUDFLARE_TOKEN",     _H, "cloud",   r"(?i)cloudflare.{0,20}['\"]([A-Za-z0-9_\-]{40})['\"]"),
    _p("DIGITALOCEAN",         _H, "cloud",   r"\bdop_v1_[A-Za-z0-9]{64}\b"),
    _p("NPM_TOKEN",            _H, "registry",r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("PYPI_TOKEN",           _H, "registry",r"\bpypi-[A-Za-z0-9_\-]{160,}\b"),
    _p("DOCKER_HUB",           _H, "registry",r"(?i)dockerhub.{0,20}['\"]([a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12})['\"]"),
    _p("ATLASSIAN_TOKEN",      _H, "collab",  r"\bATATT[A-Za-z0-9_\-]{216}\b"),
    _p("DATADOG_KEY",          _H, "observ",  r"\b[a-f0-9]{32}(?=[^a-f0-9]|$)"),  # broad, needs context
    _p("SENTRY_DSN",           _M, "observ",  r"\bhttps://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+\b"),
    _p("NGROK_TOKEN",          _M, "tunnel",  r"\b[A-Za-z0-9_\-]{48}_[A-Za-z0-9_\-]{10}\b"),
    _p("POSTMAN_PMAK",         _H, "api",     r"\bPMAK-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{24}\b"),
    _p("PRIVATE_KEY",          _H, "crypto",  r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    _p("JWT",                  _M, "auth",    r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    _p("GENERIC_SECRET",       _M, "generic", r"(?i)(?:secret|api_key|access_token|auth_token)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"),
]

# Max body size scanned to keep latency bounded
MAX_SCAN_BYTES = 100_000


def scan_body(url: str, body: str, root: str, result: ScanResult) -> None:
    """Scan an HTTP response body for credential patterns and append findings."""
    text = body[:MAX_SCAN_BYTES]
    hits_by_category: dict[str, list[str]] = {}

    for sp in PATTERNS:
        match = sp.pattern.search(text)
        if not match:
            continue
        category = sp.category
        if category not in hits_by_category:
            hits_by_category[category] = []
        hits_by_category[category].append(sp.name)

    if not hits_by_category:
        return

    all_hit_names = [name for names in hits_by_category.values() for name in names]
    categories = sorted(hits_by_category.keys())

    # Use HIGH severity if any HIGH pattern matched
    high_names = {sp.name for sp in PATTERNS if sp.severity == _H}
    severity = Severity.HIGH if any(n in high_names for n in all_hit_names) else Severity.MEDIUM

    result.findings.append(
        Finding(
            url,
            "Credential pattern(s) detected in HTTP response",
            severity,
            "secret-leak",
            f"Pattern(s): {', '.join(all_hit_names[:10])}; categories: {', '.join(categories)}",
            "Rotate any exposed credentials immediately. Remove secrets from public responses and "
            "audit git history, logs, and cached CDN responses for further leakage.",
            "http",
        )
    )
