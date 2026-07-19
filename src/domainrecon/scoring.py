"""API endpoint interest scoring — prioritizes operations for manual review."""

from __future__ import annotations

from .models import Finding, ScanResult, Severity


_SENSITIVE_PATH_TERMS = frozenset(
    {"admin", "token", "export", "upload", "import", "debug", "internal",
     "secret", "key", "password", "credential", "config", "backup", "dump",
     "superuser", "root", "sudo", "impersonate", "reset", "execute", "rce"}
)

_DANGEROUS_METHODS = frozenset({"delete", "put", "patch"})


def score_endpoint(
    path: str,
    method: str,
    has_security_requirement: bool,
    cors_wildcard: bool = False,
    cors_with_credentials: bool = False,
) -> int:
    """Return 0-100 interest score for a single API operation."""
    score = 0

    path_lower = path.lower()
    if any(term in path_lower for term in _SENSITIVE_PATH_TERMS):
        score += 25

    if not has_security_requirement:
        score += 20

    if method.lower() in _DANGEROUS_METHODS:
        score += 15

    if cors_wildcard and cors_with_credentials:
        score += 20
    elif cors_wildcard:
        score += 8

    # Path depth heuristic: deeply nested paths are more likely to be business logic
    depth = path.count("/")
    if depth >= 4:
        score += 5

    return min(score, 100)


def score_schema_operations(
    url: str,
    schema: dict,
    root: str,
    result: ScanResult,
    cors_wildcard: bool = False,
    cors_with_credentials: bool = False,
) -> None:
    """Score all operations in an OpenAPI schema and emit high-priority findings."""
    paths = schema.get("paths") if isinstance(schema, dict) else None
    if not isinstance(paths, dict):
        return

    global_security = schema.get("security")
    methods = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}

    high_interest: list[tuple[int, str, str]] = []  # (score, method, path)

    for path, definition in list(paths.items())[:1000]:
        if not isinstance(definition, dict):
            continue
        for method, operation in definition.items():
            if method.lower() not in methods or not isinstance(operation, dict):
                continue
            security = operation.get("security", global_security)
            has_security = not (security == [] or security is None)

            interest = score_endpoint(
                path=path,
                method=method,
                has_security_requirement=has_security,
                cors_wildcard=cors_wildcard,
                cors_with_credentials=cors_with_credentials,
            )
            if interest >= 40:
                high_interest.append((interest, method.upper(), path))

    if not high_interest:
        return

    high_interest.sort(reverse=True)
    top = high_interest[:20]

    severity = Severity.HIGH if any(s >= 60 for s, _, _ in top) else Severity.MEDIUM
    top_summary = "; ".join(f"{m} {p} (score={s})" for s, m, p in top[:5])

    result.findings.append(
        Finding(
            url,
            f"High-interest API operations identified ({len(high_interest)} endpoint(s))",
            severity,
            "api-scoring",
            f"Top candidates: {top_summary}",
            "Manually test authentication, authorization, input validation, and rate limiting "
            "on the highest-scored operations before deploying to production.",
            "openapi",
        )
    )
