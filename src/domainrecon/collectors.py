from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Any

import dns.asyncresolver
import dns.exception
import httpx

from .models import Asset, Edge, Finding, ScanResult, Severity
from .scope import Scope
from .javascript import analyze_javascript
from .scoring import score_schema_operations
from .secrets import scan_body


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_global


@dataclass(frozen=True)
class ProbeOptions:
    timeout: float = 8.0
    concurrency: int = 20
    allow_private: bool = False
    user_agent: str = "DomainRecon/0.1 (+authorized-security-assessment)"
    enrich_external: bool = True
    enumerate_buckets: bool = False
    deep_js: bool = False


class DNSCollector:
    RECORDS = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA")

    def __init__(self, scope: Scope, options: ProbeOptions):
        self.scope, self.options = scope, options
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = options.timeout

    # Common DKIM selectors to probe during email security audit
    _DKIM_SELECTORS = (
        "default", "google", "selector1", "selector2", "amazonses",
        "mandrill", "sendgrid", "s1", "s2", "k1", "k2", "mail",
        "email", "dkim", "proofpoint", "mimecast",
    )

    async def collect(self, host: str, result: ScanResult) -> None:
        root = self.scope.root_for(host)
        if not root:
            return
        result.add_asset(Asset("domain", host, root, "target"))
        for record_type in self.RECORDS:
            try:
                answers = await self.resolver.resolve(host, record_type, raise_on_no_answer=False)
            except (dns.exception.DNSException, OSError) as exc:
                if record_type in ("A", "AAAA"):
                    result.errors.append(f"dns:{host}:{record_type}: {exc}")
                continue
            if answers.rrset is None:
                continue
            for answer in answers:
                value = answer.to_text().strip('"').rstrip(".")
                attrs: dict[str, Any] = {"record_type": record_type}
                kind = "dns_record"
                if record_type in ("A", "AAAA"):
                    kind = "ip"
                    attrs["public"] = is_public_ip(value)
                elif record_type == "MX":
                    parts = value.split()
                    value = parts[-1].rstrip(".")
                    attrs["priority"] = int(parts[0])
                asset = Asset(kind, value, root, "dns", attributes=attrs)
                result.add_asset(asset)
                result.add_edge(Edge(f"domain:{host}", asset.key, record_type.lower(), value))
                if record_type == "TXT":
                    self._spf_findings(host, value, result)
        # Full email security audit for root domains only (avoids redundant checks on subdomains)
        if host == root:
            await self._audit_email_security(host, result)

    @staticmethod
    def _spf_findings(host: str, value: str, result: ScanResult) -> None:
        lowered = value.lower()
        if not lowered.startswith("v=spf1"):
            return
        if "+all" in lowered:
            result.findings.append(
                Finding(
                    host,
                    "Permissive SPF policy (+all)",
                    Severity.HIGH,
                    "email-security",
                    value,
                    "Replace +all with -all to hard-fail unauthorized senders.",
                    "dns",
                )
            )
        elif "~all" in lowered:
            result.findings.append(
                Finding(
                    host,
                    "SPF soft-fail policy (~all)",
                    Severity.MEDIUM,
                    "email-security",
                    value,
                    "Replace ~all with -all; soft-fail still permits spoofed mail delivery.",
                    "dns",
                )
            )

    async def _audit_email_security(self, host: str, result: ScanResult) -> None:
        """Query DMARC and common DKIM selectors; emit findings for missing or weak controls."""
        # --- DMARC ---
        dmarc_record: str | None = None
        try:
            answers = await self.resolver.resolve(f"_dmarc.{host}", "TXT", raise_on_no_answer=False)
            if answers.rrset:
                for answer in answers:
                    val = answer.to_text().strip('"')
                    if "v=dmarc1" in val.lower():
                        dmarc_record = val
                        break
        except (dns.exception.DNSException, OSError):
            pass

        if dmarc_record is None:
            result.findings.append(
                Finding(
                    host,
                    "DMARC record absent",
                    Severity.MEDIUM,
                    "email-security",
                    f"No _dmarc.{host} TXT record found",
                    "Publish a DMARC record starting with v=DMARC1; p=reject to prevent domain spoofing.",
                    "dns",
                )
            )
        else:
            lowered = dmarc_record.lower()
            if "p=none" in lowered:
                result.findings.append(
                    Finding(
                        host,
                        "DMARC policy is monitoring only (p=none)",
                        Severity.MEDIUM,
                        "email-security",
                        dmarc_record,
                        "After reviewing RUA reports, move to p=quarantine then p=reject.",
                        "dns",
                    )
                )
            elif "p=quarantine" in lowered:
                result.findings.append(
                    Finding(
                        host,
                        "DMARC policy is quarantine — not yet enforcing",
                        Severity.LOW,
                        "email-security",
                        dmarc_record,
                        "Consider moving to p=reject once you have confirmed legitimate mail sources.",
                        "dns",
                    )
                )

        # --- DKIM selectors ---
        found_selectors: list[str] = []
        async def _probe_selector(sel: str) -> str | None:
            try:
                answers = await self.resolver.resolve(
                    f"{sel}._domainkey.{host}", "TXT", raise_on_no_answer=False
                )
                if answers.rrset:
                    for answer in answers:
                        val = answer.to_text().strip('"')
                        if "v=dkim1" in val.lower() or "p=" in val.lower():
                            return sel
            except (dns.exception.DNSException, OSError):
                pass
            return None

        selector_results = await asyncio.gather(
            *(_probe_selector(s) for s in self._DKIM_SELECTORS)
        )
        found_selectors = [s for s in selector_results if s]

        if found_selectors:
            result.findings.append(
                Finding(
                    host,
                    "DKIM selectors discovered",
                    Severity.INFO,
                    "email-security",
                    f"Active selectors: {', '.join(found_selectors)}",
                    "Rotate DKIM keys periodically and retire unused selectors.",
                    "dns",
                )
            )
        else:
            result.findings.append(
                Finding(
                    host,
                    "No DKIM selectors found",
                    Severity.LOW,
                    "email-security",
                    f"Probed selectors: {', '.join(self._DKIM_SELECTORS)}",
                    "Publish DKIM records for all mail-sending services to enable receiver authentication.",
                    "dns",
                )
            )


class CTCollector:
    """Passive CT discovery with redundant providers and bounded retries."""

    def __init__(self, scope: Scope, options: ProbeOptions):
        self.scope, self.options = scope, options

    async def collect(self, root: str, result: ScanResult) -> set[str]:
        failures: list[str] = []
        rows: list[dict[str, Any]] = []
        source = "crt.sh"
        for attempt in range(2):
            try:
                rows = await self._fetch_crt(root)
                break
            except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
                failures.append(self._error("crt.sh", exc))
                if attempt == 0:
                    await asyncio.sleep(0.5)
        if not rows:
            source = "Cert Spotter"
            try:
                rows = await self._fetch_certspotter(root)
            except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
                failures.append(self._error("Cert Spotter", exc))
        if not rows:
            # De-duplicate repeated retry messages while retaining both provider outcomes.
            result.errors.append(f"ct:{root}: " + " | ".join(dict.fromkeys(failures)))
            return set()

        hosts: set[str] = set()
        for row in rows:
            names = row.get("dns_names", [])
            if isinstance(names, str):
                names = names.splitlines()
            for name in names:
                name = str(name).lower().strip().removeprefix("*.").rstrip(".")
                if self.scope.contains(name):
                    hosts.add(name)
                    result.add_asset(Asset("domain", name, root, "certificate-transparency"))
                    result.add_edge(Edge(f"domain:{root}", f"domain:{name}", "contains", source))
        return hosts

    async def _fetch_crt(self, root: str) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(
                timeout=self.options.timeout, headers={"User-Agent": self.options.user_agent}
            ) as client:
                response = await client.get(
                    "https://crt.sh/", params={"q": f"%.{root}", "output": "json"}
                )
                response.raise_for_status()
                payload = response.json()
        except json.JSONDecodeError:
            raise
        if not isinstance(payload, list):
            raise ValueError("unexpected JSON response")
        return [{"dns_names": str(row.get("name_value", "")).splitlines()} for row in payload]

    async def _fetch_certspotter(self, root: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(
            timeout=self.options.timeout, headers={"User-Agent": self.options.user_agent}
        ) as client:
            response = await client.get(
                "https://api.certspotter.com/v1/issuances",
                params={"domain": root, "include_subdomains": "true", "expand": "dns_names"},
            )
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("unexpected JSON response")
        return payload

    @staticmethod
    def _error(source: str, exc: Exception) -> str:
        if isinstance(exc, httpx.HTTPStatusError):
            return f"{source} HTTP {exc.response.status_code}"
        message = str(exc).strip()
        return f"{source} {type(exc).__name__}" + (f": {message}" if message else "")


class WebCollector:
    EXPOSURE_PATHS = (
        "/.well-known/security.txt",
        "/robots.txt",
        "/openapi.json",
        "/swagger.json",
        "/graphql",
        "/.git/HEAD",
        "/.env",
        "/.well-known/openid-configuration",
        "/actuator/health",
        "/actuator/env",
        "/debug",
        "/server-status",
        "/metrics",
    )

    # Vendor-specific paths: path → (product_name, cve_hint | None)
    # HIGH if there is a known exploited CVE; MEDIUM for exposed admin panels with no CVE.
    VENDOR_PATHS: dict[str, tuple[str, str | None]] = {
        "/vpn/index.html":                        ("Citrix NetScaler",            "CVE-2023-3519"),
        "/tmui/login.jsp":                        ("F5 BIG-IP Management",        "CVE-2022-1388"),
        "/tmui/tmui/login/welcome.jsp":           ("F5 BIG-IP Management",        "CVE-2022-1388"),
        "/remote/login":                          ("Fortinet SSL VPN",             "CVE-2023-27997"),
        "/dana-na/auth/url_default/welcome.cgi":  ("Pulse Secure VPN",            "CVE-2019-11510"),
        "/global-protect/login.esp":              ("Palo Alto GlobalProtect",      "CVE-2024-3400"),
        "/+CSCOE+/logon.html":                   ("Cisco ASA WebVPN",             "CVE-2020-3452"),
        "/broker/xml":                            ("VMware Horizon",               "CVE-2021-22005"),
        "/ui/":                                   ("VMware vSphere Web Client",    "CVE-2021-21985"),
        "/ecp/":                                  ("Microsoft Exchange ECP",       "CVE-2021-26855"),
        "/owa/auth/logon.aspx":                   ("Microsoft OWA",                None),
        "/autodiscover/autodiscover.xml":         ("Microsoft Exchange Autodiscover", None),
        "/Telerik.Web.UI.WebResource.axd":        ("Telerik UI",                  "CVE-2019-18935"),
        "/manager/html":                          ("Apache Tomcat Manager",        None),
        "/phpmyadmin/":                           ("phpMyAdmin",                   None),
        "/solr/admin/":                           ("Apache Solr Admin",            None),
        "/jenkins/":                              ("Jenkins CI",                   None),
        "/kibana/":                               ("Kibana",                       None),
    }

    def __init__(self, scope: Scope, options: ProbeOptions):
        self.scope, self.options = scope, options

    async def _safe(self, host: str) -> bool:
        try:
            infos = await asyncio.get_running_loop().run_in_executor(
                None, socket.getaddrinfo, host, 443
            )
            ips = {x[4][0] for x in infos}
            return self.options.allow_private or bool(ips) and all(is_public_ip(x) for x in ips)
        except OSError:
            return False

    async def collect(self, host: str, result: ScanResult) -> None:
        root = self.scope.root_for(host)
        if not root or not await self._safe(host):
            return
        headers = {
            "User-Agent": self.options.user_agent,
            "Accept": "text/html,application/xhtml+xml",
        }
        async with httpx.AsyncClient(
            timeout=self.options.timeout, follow_redirects=False, headers=headers, verify=True
        ) as client:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}/"
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
                attrs = {
                    "status": response.status_code,
                    "server": response.headers.get("server"),
                    "content_type": response.headers.get("content-type"),
                    "title": self._title(response.text[:100_000]),
                    "location": response.headers.get("location"),
                    "technologies": self._technologies(response),
                }
                endpoint = Asset(
                    "url", url, root, "http", attributes={k: v for k, v in attrs.items() if v}
                )
                result.add_asset(endpoint)
                result.add_edge(
                    Edge(f"domain:{host}", endpoint.key, "serves", str(response.status_code))
                )
                for technology in attrs["technologies"]:
                    tech = Asset("technology", technology, root, "http-fingerprint")
                    result.add_asset(tech)
                    result.add_edge(Edge(endpoint.key, tech.key, "uses", technology, 0.75))
                self._headers(url, scheme, response.headers, result)
                self._classify_surface(url, response, result)
                await self._probe_exposures(client, scheme, host, root, result)
                await self._probe_cors_and_methods(client, url, result)
                if self.options.deep_js and "html" in response.headers.get("content-type", "").lower():
                    await analyze_javascript(url, response.text[:100_000], root, result, client)
                break

    async def _probe_exposures(self, client, scheme, host, root, result) -> None:
        """Perform bounded, read-only exposure checks during authorized scans."""
        for path in self.EXPOSURE_PATHS:
            url = f"{scheme}://{host}{path}"
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue
            if response.status_code not in range(200, 400):
                continue
            body = response.text[:50_000]
            content_type = response.headers.get("content-type", "").lower()
            scan_body(url, body, root, result)
            evidence = None
            if path == "/.git/HEAD" and re.match(r"ref:\s+refs/heads/", body):
                evidence = (
                    "Exposed Git repository metadata",
                    Severity.HIGH,
                    body.strip()[:160],
                    "Block access to .git, rotate secrets found in repository history, and review logs.",
                )
            elif path == "/.env" and re.search(
                r"(?im)^(?:APP_KEY|API_KEY|DB_(?:HOST|PASSWORD|USERNAME)|AWS_ACCESS_KEY_ID)=", body
            ):
                evidence = (
                    "Exposed environment configuration",
                    Severity.HIGH,
                    "Configuration variable names were returned (values intentionally not retained).",
                    "Remove the file from the web root and rotate every potentially exposed credential.",
                )
            elif path in {"/openapi.json", "/swagger.json"} and (
                '"openapi"' in body[:2000] or '"swagger"' in body[:2000]
            ):
                evidence = (
                    "Public API schema",
                    Severity.MEDIUM,
                    f"HTTP {response.status_code}; API schema marker at {path}",
                    "Confirm intended exposure, enumerate documented operations, and test authorization boundaries.",
                )
                self._analyze_api_schema(url, body, result)
            elif path == "/graphql" and (
                "application/json" in content_type or "graphql" in body.lower()
            ):
                evidence = (
                    "GraphQL endpoint candidate",
                    Severity.LOW,
                    f"HTTP {response.status_code}; content-type={content_type or 'unknown'}",
                    "Validate endpoint behavior and, if authorized, assess introspection and object-level authorization.",
                )
            elif path == "/robots.txt" and "disallow:" in body.lower():
                evidence = (
                    "Robots.txt reveals candidate paths",
                    Severity.INFO,
                    f"HTTP {response.status_code}; {body.lower().count('disallow:')} disallow entries",
                    "Review disclosed paths for unintended administrative, backup, or pre-production exposure.",
                )
            elif path == "/.well-known/security.txt" and "contact:" in body.lower():
                evidence = (
                    "Published security contact",
                    Severity.INFO,
                    f"HTTP {response.status_code}; security.txt contact present",
                    "Use the published disclosure channel if a vulnerability is validated.",
                )
            elif path == "/.well-known/openid-configuration" and "issuer" in body:
                evidence = (
                    "OpenID Connect configuration exposed",
                    Severity.INFO,
                    f"HTTP {response.status_code}; public identity-provider metadata",
                    "Review advertised flows, redirect URI controls, token endpoints, and supported algorithms.",
                )
            elif path in {"/actuator/env", "/debug", "/server-status", "/metrics"}:
                markers = ("propertySources", "server version", "process_", "go_gc_", "debug")
                if any(marker.lower() in body.lower() for marker in markers):
                    evidence = (
                        "Operational or debug endpoint exposed",
                        Severity.HIGH if path == "/actuator/env" else Severity.MEDIUM,
                        f"HTTP {response.status_code}; recognizable response at {path}",
                        "Restrict operational endpoints to trusted management networks and remove sensitive output.",
                    )
            if not evidence:
                continue
            name, severity, observed, remediation = evidence
            result.add_asset(
                Asset(
                    "url",
                    url,
                    root,
                    "http-exposure",
                    attributes={"status": response.status_code, "content_type": content_type},
                )
            )
            result.add_edge(Edge(f"domain:{host}", f"url:{url}", "exposes", name))
            result.findings.append(
                Finding(url, name, severity, "exposure", observed, remediation, "http")
            )

        # Vendor product fingerprinting — probes known admin/appliance paths
        for vpath, (product, cve) in self.VENDOR_PATHS.items():
            vurl = f"{scheme}://{host}{vpath}"
            try:
                vresponse = await client.get(vurl)
            except httpx.HTTPError:
                continue
            if vresponse.status_code not in range(200, 400):
                continue
            vcontent_type = vresponse.headers.get("content-type", "").lower()
            if cve:
                vseverity = Severity.HIGH
                vremediation = (
                    f"Patch immediately — {cve} is a known critical vulnerability for {product}. "
                    "Restrict management access to trusted networks and apply vendor mitigations."
                )
                vname = f"{product} exposed ({cve})"
            else:
                vseverity = Severity.MEDIUM
                vremediation = (
                    f"Restrict {product} admin panel access to internal or VPN-only networks. "
                    "Confirm default credentials have been changed and patch to latest version."
                )
                vname = f"{product} admin panel exposed"
            result.add_asset(
                Asset(
                    "url",
                    vurl,
                    root,
                    "vendor-fingerprint",
                    attributes={"status": vresponse.status_code, "content_type": vcontent_type, "product": product},
                )
            )
            result.add_edge(Edge(f"domain:{host}", f"url:{vurl}", "exposes", vname))
            result.findings.append(
                Finding(
                    vurl,
                    vname,
                    vseverity,
                    "vendor-exposure",
                    f"HTTP {vresponse.status_code}; {product} path {vpath} accessible",
                    vremediation,
                    "http",
                )
            )

    @staticmethod
    def _analyze_api_schema(url: str, body: str, result: ScanResult) -> None:
        import json as _json
        try:
            schema = _json.loads(body)
        except (ValueError, TypeError):
            return
        paths = schema.get("paths") if isinstance(schema, dict) else None
        if not isinstance(paths, dict):
            return
        operations = 0
        unsecured = 0
        sensitive = []
        global_security = schema.get("security")
        methods = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
        for path, definition in list(paths.items())[:1000]:
            if not isinstance(definition, dict):
                continue
            for method, operation in definition.items():
                if method.lower() not in methods or not isinstance(operation, dict):
                    continue
                operations += 1
                security = operation.get("security", global_security)
                if security == [] or security is None:
                    unsecured += 1
                if any(
                    word in str(path).lower()
                    for word in ("admin", "export", "token", "upload", "user", "debug")
                ):
                    sensitive.append(f"{method.upper()} {path}")
        result.findings.append(
            Finding(
                url,
                "API operation inventory generated",
                Severity.INFO,
                "api",
                f"{operations} operations; {unsecured} without a declared security requirement; {len(sensitive)} sensitive-name candidates",
                "Validate schema declarations against runtime enforcement, prioritizing sensitive operations and object identifiers.",
                "openapi",
            )
        )
        if unsecured:
            result.findings.append(
                Finding(
                    url,
                    "API operations lack declared authentication",
                    Severity.MEDIUM,
                    "api-auth",
                    f"{unsecured} of {operations} operations have no effective schema security requirement",
                    "Determine whether each operation is intentionally public, then validate function- and object-level authorization.",
                    "openapi",
                )
            )
        root = next(iter({a.root_domain for a in result.assets.values() if a.kind == "domain"}), "")
        score_schema_operations(url, schema, root, result)

    @staticmethod
    async def _probe_cors_and_methods(client, url: str, result: ScanResult) -> None:
        origin = "https://domainrecon.invalid"
        try:
            cors = await client.get(url, headers={"Origin": origin})
            allow_origin = cors.headers.get("access-control-allow-origin", "")
            if allow_origin == origin:
                result.findings.append(
                    Finding(
                        url,
                        "Arbitrary Origin reflected by CORS",
                        Severity.HIGH
                        if cors.headers.get("access-control-allow-credentials", "").lower()
                        == "true"
                        else Severity.MEDIUM,
                        "cors",
                        f"Synthetic Origin reflected; credentials={cors.headers.get('access-control-allow-credentials', 'false')}",
                        "Use an explicit trusted-origin allowlist and reject unrecognized origins.",
                        "http",
                    )
                )
            options = await client.request("OPTIONS", url)
            allow = options.headers.get("allow", "")
            dangerous = sorted(set(allow.upper().replace(",", " ").split()) & {"TRACE", "CONNECT"})
            if dangerous:
                result.findings.append(
                    Finding(
                        url,
                        "Dangerous HTTP methods advertised",
                        Severity.MEDIUM,
                        "http-methods",
                        f"Allow: {allow[:300]}",
                        "Disable TRACE and CONNECT unless explicitly required.",
                        "http",
                    )
                )
        except (httpx.HTTPError, AttributeError):
            return

    @staticmethod
    def _classify_surface(url: str, response: httpx.Response, result: ScanResult) -> None:
        text = response.text[:100_000]
        lowered = text.lower()
        title = WebCollector._title(text) or ""
        content_type = response.headers.get("content-type", "").lower()
        WebCollector._cookies(url, response.headers, result)
        if re.search(r"(?i)(?:sourceMappingURL=|\.js\.map(?:[\"']))", text):
            result.findings.append(
                Finding(
                    url,
                    "JavaScript source map reference discovered",
                    Severity.LOW,
                    "source-map",
                    "Public response references a source map",
                    "Remove production source maps or ensure they contain no proprietary source, internal endpoints, or secrets.",
                    "http",
                )
            )
        signals = []
        if re.search(r"<input[^>]+type=[\"']password[\"']", lowered):
            signals.append("password field")
        if any(term in title.lower() for term in ("sign in", "log in", "login", "admin")):
            signals.append(f"title={title}")
        if signals:
            result.findings.append(
                Finding(
                    url,
                    "Authentication surface discovered",
                    Severity.INFO,
                    "authentication",
                    "; ".join(signals),
                    "Confirm ownership, MFA, rate limiting, account recovery controls, and default credentials policy.",
                    "http",
                )
            )
        if "application/json" in content_type:
            result.findings.append(
                Finding(
                    url,
                    "JSON/API surface discovered",
                    Severity.INFO,
                    "api",
                    f"HTTP {response.status_code}; content-type={content_type}",
                    "Map operations and test authentication and object-level authorization within program scope.",
                    "http",
                )
            )
        storage_markers = {
            "amazons3": "Amazon S3",
            "blobnotfound": "Azure Blob Storage",
            "google cloud storage": "Google Cloud Storage",
        }
        for marker, provider in storage_markers.items():
            if marker in lowered:
                result.findings.append(
                    Finding(
                        url,
                        f"{provider} endpoint discovered",
                        Severity.LOW,
                        "data-store",
                        f"Service fingerprint: {provider}; HTTP {response.status_code}",
                        "Verify listing, read, write, CORS, and signed-URL policy without accessing unrelated data.",
                        "http",
                    )
                )
                break

    @staticmethod
    def _cookies(url: str, headers: httpx.Headers, result: ScanResult) -> None:
        try:
            values = headers.get_list("set-cookie")
        except AttributeError:
            value = headers.get("set-cookie")
            values = [value] if value else []
        for value in values[:20]:
            name = value.split("=", 1)[0].strip()[:80] or "cookie"
            lowered = value.lower()
            missing = []
            if url.startswith("https://") and "secure" not in lowered:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite=" not in lowered:
                missing.append("SameSite")
            if missing:
                result.findings.append(
                    Finding(
                        url,
                        f"Cookie {name} lacks security attributes",
                        Severity.MEDIUM if "Secure" in missing else Severity.LOW,
                        "session",
                        f"Missing {', '.join(missing)}",
                        "Set Secure, HttpOnly, and an appropriate SameSite policy on session cookies.",
                        "http",
                    )
                )

    @staticmethod
    def _title(body: str) -> str | None:
        low = body.lower()
        start, end = low.find("<title"), low.find("</title>")
        if start < 0 or end < 0:
            return None
        start = body.find(">", start) + 1
        return " ".join(body[start:end].split())[:200]

    @staticmethod
    def _technologies(response: httpx.Response) -> list[str]:
        """Conservative header/markup fingerprints; avoids version guessing."""
        body = response.text[:100_000].lower()
        headers = {key.lower(): value.lower() for key, value in response.headers.items()}
        found: set[str] = set()
        signatures = {
            "WordPress": ("/wp-content/", "wp-json"),
            "Next.js": ("/_next/", "__next_data__"),
            "React": ("data-reactroot", "react-dom"),
            "Angular": ("ng-version=", "ng-app"),
            "Vue.js": ("data-v-", "__vue__"),
            "Drupal": ("drupal-settings-json", "/sites/default/files/"),
            "Joomla": ("/media/system/js/", "option=com_"),
            "Grafana": ("grafana_boot_data", "public/build/grafana"),
        }
        for name, markers in signatures.items():
            if any(marker in body for marker in markers):
                found.add(name)
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        for name, marker in {
            "Cloudflare": "cloudflare",
            "nginx": "nginx",
            "Apache HTTP Server": "apache",
            "Microsoft IIS": "microsoft-iis",
        }.items():
            if marker in server:
                found.add(name)
        for name, marker in {
            "ASP.NET": "asp.net",
            "Express": "express",
            "PHP": "php",
        }.items():
            if marker in powered:
                found.add(name)
        if "cf-ray" in headers:
            found.add("Cloudflare")
        return sorted(found)

    @staticmethod
    def _headers(url: str, scheme: str, headers: httpx.Headers, result: ScanResult) -> None:
        checks = {
            "strict-transport-security": (
                Severity.MEDIUM,
                "Missing HSTS",
                "Enable HSTS after confirming HTTPS coverage.",
            ),
            "content-security-policy": (
                Severity.LOW,
                "Missing Content-Security-Policy",
                "Deploy a restrictive CSP.",
            ),
            "x-content-type-options": (
                Severity.LOW,
                "Missing X-Content-Type-Options",
                "Set X-Content-Type-Options: nosniff.",
            ),
            "referrer-policy": (
                Severity.LOW,
                "Missing Referrer-Policy",
                "Set a restrictive Referrer-Policy appropriate for the application.",
            ),
            "permissions-policy": (
                Severity.INFO,
                "Missing Permissions-Policy",
                "Disable unneeded browser capabilities with Permissions-Policy.",
            ),
        }
        for header, (severity, title, fix) in checks.items():
            if header not in headers and (
                scheme == "https" or header != "strict-transport-security"
            ):
                result.findings.append(
                    Finding(url, title, severity, "http-headers", f"{header} absent", fix, "http")
                )
        if (
            headers.get("access-control-allow-origin") == "*"
            and headers.get("access-control-allow-credentials", "").lower() == "true"
        ):
            result.findings.append(
                Finding(
                    url,
                    "Invalid permissive CORS combination",
                    Severity.MEDIUM,
                    "cors",
                    "ACAO=* with credentials=true",
                    "Use an explicit origin allowlist.",
                    "http",
                )
            )


class TLSCollector:
    def __init__(self, scope: Scope, options: ProbeOptions):
        self.scope, self.options = scope, options

    async def collect(self, host: str, result: ScanResult) -> None:
        root = self.scope.root_for(host)
        if not root:
            return
        try:
            cert, cipher, version = await asyncio.wait_for(
                asyncio.to_thread(self._fetch, host), self.options.timeout + 1
            )
        except (OSError, ssl.SSLError, TimeoutError, asyncio.TimeoutError):
            return
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        asset = Asset(
            "certificate",
            f"{host}:{cert.get('serialNumber', 'unknown')}",
            root,
            "tls",
            attributes={
                "subject": subject,
                "issuer": issuer,
                "sans": sans,
                "not_after": cert.get("notAfter"),
                "cipher": cipher[0] if cipher else None,
                "tls_version": version,
            },
        )
        result.add_asset(asset)
        result.add_edge(Edge(f"domain:{host}", asset.key, "presents", str(issuer)))
        for san in sans:
            clean = san.lower().removeprefix("*.")
            if self.scope.contains(clean):
                result.add_edge(Edge(asset.key, f"domain:{clean}", "covers", san))

    @staticmethod
    def _fetch(host: str) -> tuple[dict, tuple | None, str | None]:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                return sock.getpeercert(), sock.cipher(), sock.version()
