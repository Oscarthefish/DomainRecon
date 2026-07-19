# DomainRecon enrichment integrations

DomainRecon works without third-party accounts. Optional connectors should be read-only,
disabled by default, bounded by provider rate limits, and record source plus observation time.

## Recommended order

1. **Censys Platform API** — enrich discovered IPs, certificates, web properties, software,
   ports and historical observations. Free accounts currently support lookup endpoints.
2. **Shodan REST API** — retrieve indexed host services, ports, banners, TLS and known
   vulnerability metadata. Prefer `minify=true`; do not trigger on-demand scans.
3. **SecurityTrails** — passive DNS history, associated domains, subdomains and historical
   records. Useful for shadow IT and ownership pivots; requires a commercial API plan.
4. **RDAP** — registration and registrar data using standards-based registry endpoints.
   Cache results aggressively and treat privacy-redacted records as unknown, not unrelated.
5. **GitHub REST search** — organization/domain-scoped public-code discovery. Store repository,
   path and redacted match classification; never persist discovered credential values.
6. **urlscan.io** — historical page captures, contacted domains, certificates and technologies.
   Use existing public results by default; submitting a new scan transmits the target to urlscan.

## Useful local tools

- `subfinder` and `amass` for subdomain aggregation.
- `dnsx` for bulk resolution and wildcard handling.
- `httpx` for high-volume HTTP metadata and technology fingerprints.
- `katana` for authorized endpoint extraction.
- `nuclei` with an explicitly allowlisted, non-destructive template set.
- `gitleaks` for repositories the analyst owns or has downloaded with authorization.
- `naabu` or `nmap` only in an explicit active profile and approved port range.

## Connector contract

Every connector should return assets, relationships, findings and errors through the existing
models. It must declare whether it contacts the target, a third party, or neither; required
credentials; rate-limit state; confidence; and the exact evidence source. API keys belong in
environment variables or an OS keychain and must never be included in reports.
