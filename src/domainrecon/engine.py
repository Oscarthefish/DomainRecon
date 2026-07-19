from __future__ import annotations

import asyncio
import shutil
import uuid
from collections import defaultdict

from .collectors import CTCollector, DNSCollector, ProbeOptions, TLSCollector, WebCollector
from .enrichment import EnrichmentCollector
from .models import Asset, Edge, ScanResult
from .scope import Scope


class ReconEngine:
    def __init__(self, scope: Scope, options: ProbeOptions | None = None):
        self.scope = scope
        self.options = options or ProbeOptions()
        self.dns = DNSCollector(scope, self.options)
        self.ct = CTCollector(scope, self.options)
        self.web = WebCollector(scope, self.options)
        self.tls = TLSCollector(scope, self.options)
        self.enrichment = EnrichmentCollector(self.options)

    async def run(self, *, passive_only: bool = False, max_hosts: int = 250) -> ScanResult:
        result = ScanResult(uuid.uuid4().hex[:12], list(self.scope.roots))
        hosts = set(self.scope.roots)
        subfinder = await asyncio.gather(
            *(self._subfinder(root, result) for root in self.scope.roots)
        )
        for names in subfinder:
            hosts.update(names)
        discovered = await asyncio.gather(
            *(self.ct.collect(root, result) for root in self.scope.roots)
        )
        for names in discovered:
            hosts.update(names)
        # Root targets are never displaced by alphabetically earlier CT discoveries.
        roots = list(self.scope.roots)
        remaining = sorted(hosts.difference(roots))
        hosts = set((roots + remaining)[:max_hosts])
        semaphore = asyncio.Semaphore(self.options.concurrency)

        async def inspect(host: str) -> None:
            async with semaphore:
                await self.dns.collect(host, result)
                if not passive_only:
                    await asyncio.gather(
                        self.web.collect(host, result), self.tls.collect(host, result)
                    )

        await asyncio.gather(*(inspect(host) for host in hosts))
        if self.options.enrich_external:
            await self.enrichment.collect(result)
        self._correlate(result)
        return result

    async def _subfinder(self, root: str, result: ScanResult) -> set[str]:
        binary = shutil.which("subfinder")
        if not binary:
            return set()
        try:
            process = await asyncio.create_subprocess_exec(
                binary,
                "-silent",
                "-d",
                root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=90)
        except (OSError, TimeoutError, asyncio.TimeoutError) as exc:
            result.errors.append(f"subfinder:{root}: {type(exc).__name__}: {exc}")
            return set()
        if process.returncode:
            result.errors.append(
                f"subfinder:{root}: exit {process.returncode}: {stderr.decode()[:200]}"
            )
            return set()
        hosts = {
            name
            for line in stdout.decode(errors="replace").splitlines()
            if (name := line.strip().lower().rstrip(".")) and self.scope.contains(name)
        }
        for host in hosts:
            result.add_asset(Asset("domain", host, root, "subfinder"))
            result.add_edge(Edge(f"domain:{root}", f"domain:{host}", "contains", "subfinder"))
        return hosts

    @staticmethod
    def _correlate(result: ScanResult) -> None:
        """Connect roots sharing infrastructure; evidence is always retained."""
        owners: dict[tuple[str, str], set[str]] = defaultdict(set)
        for edge in result.edges:
            if edge.relation in {"a", "aaaa", "cname", "ns", "mx"} and edge.source.startswith(
                "domain:"
            ):
                domain = edge.source.removeprefix("domain:")
                root = next(
                    (r for r in result.targets if domain == r or domain.endswith("." + r)), None
                )
                if root:
                    owners[(edge.relation, edge.target)].add(root)
        for (relation, target), roots in owners.items():
            roots = sorted(roots)
            for index, left in enumerate(roots):
                for right in roots[index + 1 :]:
                    result.add_edge(
                        Edge(f"domain:{left}", f"domain:{right}", f"shared_{relation}", target, 0.8)
                    )

        # A certificate spanning separate declared roots is a high-confidence relationship.
        certificate_roots: dict[str, set[str]] = defaultdict(set)
        for edge in result.edges:
            if edge.relation != "covers" or not edge.source.startswith("certificate:"):
                continue
            domain = edge.target.removeprefix("domain:")
            root = next(
                (r for r in result.targets if domain == r or domain.endswith("." + r)), None
            )
            if root:
                certificate_roots[edge.source].add(root)
        for certificate, roots in certificate_roots.items():
            roots = sorted(roots)
            for index, left in enumerate(roots):
                for right in roots[index + 1 :]:
                    result.add_edge(
                        Edge(
                            f"domain:{left}",
                            f"domain:{right}",
                            "shared_certificate",
                            certificate,
                            0.95,
                        )
                    )
