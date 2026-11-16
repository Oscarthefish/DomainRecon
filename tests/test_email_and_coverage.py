import asyncio

from domainrecon.collectors import DNSCollector, ProbeOptions, dkim_key_status
from domainrecon.models import ScanResult
from domainrecon.scope import Scope


def test_dkim_key_status():
    assert dkim_key_status("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB") == "active"
    assert dkim_key_status("v=DKIM1; p=") == "revoked"
    assert dkim_key_status("v=DKIM1; k=rsa; p= ") == "revoked"
    assert dkim_key_status("v=spf1 -all") is None


class _Rdata:
    def __init__(self, text):
        self.strings = [text.encode()]


class _Answer(list):
    @property
    def rrset(self):
        return bool(self)


class _Resolver:
    """Answers TXT lookups from a {name: text} map; a "*" key acts as a wildcard."""

    def __init__(self, records):
        self.records = records

    async def resolve(self, name, rdtype, raise_on_no_answer=False):
        if name.startswith("_dmarc."):
            return _Answer()
        selector = name.split("._domainkey.")[0]
        text = self.records.get(selector, self.records.get("*"))
        return _Answer([_Rdata(text)] if text else [])


def _dkim_findings(records):
    collector = DNSCollector(Scope.build(["example.com"]), ProbeOptions())
    collector.resolver = _Resolver(records)
    result = ScanResult("id", ["example.com"])
    asyncio.run(collector._audit_email_security("example.com", result))
    return [f for f in result.findings if "DKIM" in f.title]


def test_real_regression_revoked_wildcard_is_not_reported_as_active_selectors():
    # example.com publishes "v=DKIM1; p=" for every selector: a revoked wildcard.
    (finding,) = _dkim_findings({"*": "v=DKIM1; p="})
    assert finding.title == "Wildcard DKIM record"
    assert "revoked" in finding.evidence
    assert "Active selectors" not in finding.evidence


def test_active_and_revoked_selectors_are_separated():
    (finding,) = _dkim_findings({"selector1": "v=DKIM1; k=rsa; p=MIIBIjANBg", "s1": "v=DKIM1; p="})
    assert finding.title == "DKIM selectors discovered"
    assert finding.evidence == "Active selectors: selector1. Revoked (empty key): s1"


def test_only_revoked_and_none_found():
    assert _dkim_findings({"google": "v=DKIM1; p="})[0].title == "Only revoked DKIM selectors found"
    assert _dkim_findings({})[0].title == "No DKIM selectors found"


def test_passive_scans_do_not_claim_web_checks_were_run():
    from domainrecon.owasp import coverage
    states = {row["id"]: row["state"] for row in coverage([], passive_only=True)["web"]}
    assert states["A02:2021"] == "not run" and states["A01:2021"] == "manual"
    assert "tested" not in states.values()
    active = {row["id"]: row["state"] for row in coverage([])["web"]}
    assert active["A02:2021"] == "tested"
