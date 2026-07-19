from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = (urlsplit(value).hostname or "").rstrip(".")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not accepted as root domain targets")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain: {value!r}")
    return value


@dataclass(frozen=True)
class Scope:
    roots: tuple[str, ...]
    excludes: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def build(cls, roots: list[str], excludes: list[str] | None = None) -> "Scope":
        return cls(
            tuple(dict.fromkeys(normalize_domain(x) for x in roots)),
            tuple(normalize_domain(x) for x in (excludes or [])),
        )

    def root_for(self, host: str) -> str | None:
        host = host.lower().rstrip(".")
        if any(host == x or host.endswith("." + x) for x in self.excludes):
            return None
        return next((r for r in self.roots if host == r or host.endswith("." + r)), None)

    def contains(self, host: str) -> bool:
        return self.root_for(host) is not None
