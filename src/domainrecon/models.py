from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Asset:
    kind: str
    value: str
    root_domain: str
    source: str
    first_seen: str = field(default_factory=now)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value.lower()}"


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: str
    evidence: str
    confidence: float = 1.0


@dataclass(frozen=True)
class Finding:
    asset: str
    title: str
    severity: Severity
    category: str
    evidence: str
    remediation: str
    source: str
    observed_at: str = field(default_factory=now)

    def as_dict(self) -> dict[str, Any]:
        from .owasp import mappings_for

        data = asdict(self)
        data["severity"] = self.severity.value
        data["owasp"] = mappings_for(self.category)
        return data


@dataclass
class ScanResult:
    scan_id: str
    targets: list[str]
    assets: dict[str, Asset] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    comparison: dict[str, Any] = field(default_factory=dict)

    def add_asset(self, asset: Asset) -> None:
        old = self.assets.get(asset.key)
        if old is None or len(asset.attributes) > len(old.attributes):
            self.assets[asset.key] = asset

    def add_edge(self, edge: Edge) -> None:
        if edge not in self.edges:
            self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        from .owasp import coverage

        severities = {"info": 1, "low": 8, "medium": 18, "high": 35}
        finding_risk: dict[str, int] = {}
        for finding in self.findings:
            finding_risk[finding.asset.lower()] = (
                finding_risk.get(finding.asset.lower(), 0) + severities[finding.severity.value]
            )

        def asset_dict(asset: Asset) -> dict[str, Any]:
            data = asdict(asset)
            score = finding_risk.get(asset.value.lower(), 0)
            if asset.kind == "url":
                score += 10
            if any(
                word in asset.value.lower()
                for word in ("admin", "login", "auth", "dev", "stage", "api")
            ):
                score += 15
            if asset.attributes.get("status") in range(200, 400):
                score += 5
            data["risk_score"] = min(score, 100)
            return data

        findings = [x.as_dict() for x in self.findings]
        has_api = any(x.category in {"api", "api-auth"} for x in self.findings)
        return {
            "scan_id": self.scan_id,
            "targets": self.targets,
            "assets": [asset_dict(x) for x in self.assets.values()],
            "edges": [asdict(x) for x in self.edges],
            "findings": findings,
            "errors": self.errors,
            "comparison": self.comparison,
            "owasp_coverage": coverage(findings, has_api),
        }
