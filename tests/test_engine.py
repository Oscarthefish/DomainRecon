import httpx

from domainrecon.collectors import CTCollector, ProbeOptions, WebCollector
from domainrecon.engine import ReconEngine
from domainrecon.models import Asset, Edge, ScanResult
from domainrecon.scope import Scope


def test_classifies_login_and_api_surfaces():
    result = ScanResult("id", ["example.com"])
    response = httpx.Response(
        200,
        headers={"content-type": "application/json"},
        text='<html><title>Admin Login</title><input type="password"></html>',
    )
    WebCollector._classify_surface("https://example.com/", response, result)
    assert {finding.category for finding in result.findings} == {"authentication", "api"}


def test_technology_fingerprints_are_conservative():
    response = httpx.Response(
        200,
        headers={"server": "cloudflare", "x-powered-by": "Express"},
        text='<script src="/_next/static/app.js"></script>',
    )
    assert WebCollector._technologies(response) == ["Cloudflare", "Express", "Next.js"]


async def test_exposure_probe_detects_git_without_retaining_secrets():
    collector = WebCollector(Scope.build(["example.com"]), ProbeOptions())
    result = ScanResult("id", ["example.com"])

    class Client:
        async def get(self, url):
            if url.endswith("/.git/HEAD"):
                return httpx.Response(200, text="ref: refs/heads/main\n")
            return httpx.Response(404)

    await collector._probe_exposures(Client(), "https", "example.com", "example.com", result)
    finding = next(item for item in result.findings if "Git" in item.title)
    assert finding.severity.value == "high"
    assert any(edge.relation == "exposes" for edge in result.edges)


def test_api_schema_generates_inventory_and_authentication_lead():
    result = ScanResult("id", ["example.com"])
    body = """{"openapi":"3.0.0","paths":{"/admin/users":{"get":{}},"/health":{"get":{"security":[]}}}}"""
    WebCollector._analyze_api_schema("https://api.example.com/openapi.json", body, result)
    # /admin/users is also flagged as a high-interest operation by the endpoint scorer.
    assert {finding.category for finding in result.findings} == {"api", "api-auth", "api-scoring"}
    serialized = result.to_dict()
    auth = next(item for item in serialized["findings"] if item["category"] == "api-auth")
    assert "API5:2023" in auth["owasp"]
    api5 = next(item for item in serialized["owasp_coverage"]["api"] if item["id"] == "API5:2023")
    assert api5["domains"] == ["api.example.com"]
    assert api5["finding_count"] == 2


def test_cookie_attributes_are_reported_without_retaining_cookie_value():
    result = ScanResult("id", ["example.com"])
    headers = httpx.Headers({"set-cookie": "session=secret-value; Path=/"})
    WebCollector._cookies("https://example.com/", headers, result)
    finding = result.findings[0]
    assert finding.category == "session"
    assert "secret-value" not in finding.evidence
    assert "Secure" in finding.evidence


async def test_cors_reflection_is_validated_with_synthetic_origin():
    result = ScanResult("id", ["example.com"])

    class Client:
        async def get(self, url, headers=None):
            return httpx.Response(
                200,
                headers={
                    "access-control-allow-origin": headers["Origin"],
                    "access-control-allow-credentials": "true",
                },
            )

        async def request(self, method, url):
            return httpx.Response(204)

    await WebCollector._probe_cors_and_methods(Client(), "https://example.com/", result)
    finding = result.findings[0]
    assert finding.category == "cors"
    assert finding.severity.value == "high"


def test_correlates_shared_infrastructure_between_roots():
    result = ScanResult("id", ["one.test", "two.test"])
    result.add_edge(Edge("domain:www.one.test", "ip:203.0.113.4", "a", "203.0.113.4"))
    result.add_edge(Edge("domain:two.test", "ip:203.0.113.4", "a", "203.0.113.4"))
    ReconEngine._correlate(result)
    assert any(e.relation == "shared_a" and e.source == "domain:one.test" for e in result.edges)


def test_correlates_certificate_spanning_multiple_roots():
    result = ScanResult("id", ["one.test", "two.test"])
    result.add_edge(Edge("certificate:shared", "domain:api.one.test", "covers", "api.one.test"))
    result.add_edge(Edge("certificate:shared", "domain:login.two.test", "covers", "login.two.test"))
    ReconEngine._correlate(result)
    relationship = next(e for e in result.edges if e.relation == "shared_certificate")
    assert relationship.confidence == 0.95
    assert relationship.evidence == "certificate:shared"


def test_asset_deduplicates_and_keeps_richer_attributes():
    result = ScanResult("id", ["example.com"])
    result.add_asset(Asset("domain", "www.example.com", "example.com", "ct"))
    result.add_asset(
        Asset("domain", "www.example.com", "example.com", "dns", attributes={"live": True})
    )
    assert len(result.assets) == 1
    assert result.assets["domain:www.example.com"].attributes["live"] is True


def test_asset_risk_prioritizes_authentication_surfaces():
    result = ScanResult("id", ["example.com"])
    result.add_asset(Asset("domain", "admin.example.com", "example.com", "ct"))
    serialized = result.to_dict()
    assert serialized["assets"][0]["risk_score"] == 15


async def test_ct_falls_back_and_does_not_report_primary_failure(monkeypatch):
    collector = CTCollector(Scope.build(["example.com"]), ProbeOptions())
    calls = 0

    async def fail_crt(_root):
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("timed out")

    async def certspotter(_root):
        return [{"dns_names": ["api.example.com", "*.example.com"]}]

    monkeypatch.setattr(collector, "_fetch_crt", fail_crt)
    monkeypatch.setattr(collector, "_fetch_certspotter", certspotter)
    result = ScanResult("id", ["example.com"])
    hosts = await collector.collect("example.com", result)
    assert calls == 2
    assert hosts == {"api.example.com", "example.com"}
    assert result.errors == []
    assert all(edge.evidence == "Cert Spotter" for edge in result.edges)


async def test_ct_errors_name_both_providers(monkeypatch):
    collector = CTCollector(Scope.build(["example.com"]), ProbeOptions())

    async def fail_crt(_root):
        raise httpx.ReadTimeout("")

    async def fail_fallback(_root):
        request = httpx.Request("GET", "https://api.certspotter.com")
        response = httpx.Response(429, request=request)
        raise httpx.HTTPStatusError("rate limited", request=request, response=response)

    monkeypatch.setattr(collector, "_fetch_crt", fail_crt)
    monkeypatch.setattr(collector, "_fetch_certspotter", fail_fallback)
    result = ScanResult("id", ["example.com"])
    await collector.collect("example.com", result)
    assert result.errors == ["ct:example.com: crt.sh ReadTimeout | Cert Spotter HTTP 429"]
