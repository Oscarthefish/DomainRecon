from __future__ import annotations

import os
from typing import Any

import httpx

from . import config as _config  # noqa: F401 - loads local .env before status checks
from .collectors import ProbeOptions, is_public_ip
from .models import Asset, Edge, ScanResult


def integration_status() -> list[dict[str, Any]]:
    return [
        {"name": "RDAP", "configured": True, "credential": None, "mode": "passive"},
        {
            "name": "Shodan",
            "configured": bool(os.getenv("SHODAN_API_KEY")),
            "credential": "SHODAN_API_KEY",
            "mode": "passive database lookup",
        },
        {
            "name": "Censys",
            "configured": bool(os.getenv("CENSYS_PAT")),
            "credential": "CENSYS_PAT",
            "mode": "passive database lookup",
        },
    ]


class EnrichmentCollector:
    """Read-only third-party enrichment; never requests an on-demand provider scan."""

    def __init__(self, options: ProbeOptions):
        self.options = options

    async def collect(self, result: ScanResult) -> None:
        async with httpx.AsyncClient(
            timeout=self.options.timeout,
            headers={"User-Agent": self.options.user_agent},
        ) as client:
            for root in result.targets:
                await self._rdap(client, root, result)
            ips = sorted(
                {
                    asset.value
                    for asset in result.assets.values()
                    if asset.kind == "ip" and is_public_ip(asset.value)
                }
            )[:25]
            for ip in ips:
                if key := os.getenv("SHODAN_API_KEY"):
                    await self._shodan(client, ip, key, result)
                if token := os.getenv("CENSYS_PAT"):
                    await self._censys(client, ip, token, result)

    async def _rdap(self, client: httpx.AsyncClient, root: str, result: ScanResult) -> None:
        try:
            response = await client.get(f"https://rdap.org/domain/{root}")
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            result.errors.append(f"rdap:{root}: {type(exc).__name__}")
            return
        registrar = self._registrar(payload)
        attrs = {
            "handle": payload.get("handle"),
            "status": payload.get("status", []),
            "registrar": registrar,
            "nameservers": sorted(
                {
                    str(item.get("ldhName", "")).lower().rstrip(".")
                    for item in payload.get("nameservers", [])
                    if item.get("ldhName")
                }
            ),
            "dnssec": payload.get("secureDNS", {}).get("delegationSigned"),
            "port43": payload.get("port43"),
            "entities": self._public_entities(payload),
            "events": {
                item.get("eventAction"): item.get("eventDate")
                for item in payload.get("events", [])
                if item.get("eventAction") and item.get("eventDate")
            },
        }
        ownership = Asset(
            "registration",
            root,
            root,
            "rdap",
            attributes={
                key: value for key, value in attrs.items() if value not in (None, [], {}, "")
            },
        )
        result.add_asset(ownership)
        result.add_edge(Edge(f"domain:{root}", ownership.key, "registered_as", registrar or root))
        for nameserver in attrs["nameservers"]:
            result.add_edge(
                Edge(f"domain:{root}", f"dns_record:{nameserver}", "registration_ns", nameserver)
            )

    @staticmethod
    def _registrar(payload: dict[str, Any]) -> str | None:
        for entity in payload.get("entities", []):
            if "registrar" not in entity.get("roles", []):
                continue
            card = entity.get("vcardArray", [])
            rows = card[1] if len(card) > 1 and isinstance(card[1], list) else []
            for row in rows:
                if isinstance(row, list) and len(row) > 3 and row[0] == "fn":
                    return str(row[3])[:200]
        return None

    @staticmethod
    def _public_entities(payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Return public organization labels and roles, excluding contact details."""
        output = []
        for entity in payload.get("entities", [])[:20]:
            card = entity.get("vcardArray", [])
            rows = card[1] if len(card) > 1 and isinstance(card[1], list) else []
            labels = {
                row[0]: str(row[3])[:200]
                for row in rows
                if isinstance(row, list) and len(row) > 3 and row[0] in {"fn", "org"}
            }
            if labels or entity.get("roles"):
                output.append(
                    {
                        "roles": entity.get("roles", []),
                        "name": labels.get("fn"),
                        "organization": labels.get("org"),
                    }
                )
        return output

    async def _shodan(
        self, client: httpx.AsyncClient, ip: str, key: str, result: ScanResult
    ) -> None:
        try:
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": key, "minify": "true"},
            )
            if response.status_code == 404:
                return
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            result.errors.append(f"shodan:{ip}: {type(exc).__name__}")
            return
        asset = Asset(
            "internet_intelligence",
            f"shodan:{ip}",
            self._root_for_ip(ip, result),
            "shodan",
            attributes={
                "ports": payload.get("ports", []),
                "org": payload.get("org"),
                "asn": payload.get("asn"),
                "hostnames": payload.get("hostnames", []),
                "last_update": payload.get("last_update"),
            },
        )
        result.add_asset(asset)
        result.add_edge(Edge(f"ip:{ip}", asset.key, "observed_by", "Shodan", 0.85))

    async def _censys(
        self, client: httpx.AsyncClient, ip: str, token: str, result: ScanResult
    ) -> None:
        try:
            response = await client.get(
                f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.censys.api.v3.host.v1+json",
                },
            )
            if response.status_code == 404:
                return
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            result.errors.append(f"censys:{ip}: {type(exc).__name__}")
            return
        resource = payload.get("result", payload)
        asset = Asset(
            "internet_intelligence",
            f"censys:{ip}",
            self._root_for_ip(ip, result),
            "censys",
            attributes={
                "observed_at": resource.get("last_updated_at") or resource.get("observed_at"),
                "service_count": len(resource.get("services", [])),
                "location": resource.get("location", {}).get("country"),
            },
        )
        result.add_asset(asset)
        result.add_edge(Edge(f"ip:{ip}", asset.key, "observed_by", "Censys", 0.85))

    @staticmethod
    def _root_for_ip(ip: str, result: ScanResult) -> str:
        for edge in result.edges:
            if edge.target == f"ip:{ip}" and edge.source.startswith("domain:"):
                domain = edge.source.removeprefix("domain:")
                return next(
                    (
                        root
                        for root in result.targets
                        if domain == root or domain.endswith("." + root)
                    ),
                    result.targets[0],
                )
        return result.targets[0]
