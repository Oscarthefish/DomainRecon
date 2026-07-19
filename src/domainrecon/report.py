from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanResult


STYLE = """
body{font:15px system-ui;margin:0;background:#0b1020;color:#e8edf7}main{max-width:1200px;margin:auto;padding:32px}
h1,h2{color:#fff}.cards{display:flex;gap:12px;flex-wrap:wrap}.card,table{background:#151d32;border:1px solid #2a3657;border-radius:8px}
.card{padding:14px 20px}.n{font-size:28px;font-weight:700}table{width:100%;border-collapse:collapse;overflow:hidden}th,td{padding:10px;text-align:left;border-bottom:1px solid #2a3657;vertical-align:top}
th{background:#1c2742}.high{color:#ff6b6b}.medium{color:#ffbf69}.low{color:#79c0ff}.info{color:#aaa}code{overflow-wrap:anywhere}
"""


def write_reports(result: ScanResult, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    data = result.to_dict()
    (output / "report.json").write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
    )
    (output / "graph.graphml").write_text(_graphml(result), encoding="utf-8")
    (output / "report.html").write_text(_html(result), encoding="utf-8")


def _graphml(result: ScanResult) -> str:
    nodes = set(result.assets)
    for edge in result.edges:
        nodes.update((edge.source, edge.target))
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '<graph edgedefault="directed">',
    ]
    parts.extend(f'<node id="{html.escape(node, quote=True)}"/>' for node in sorted(nodes))
    parts.extend(
        f'<edge source="{html.escape(e.source, quote=True)}" target="{html.escape(e.target, quote=True)}"><data key="relation">{html.escape(e.relation)}</data><data key="evidence">{html.escape(e.evidence)}</data></edge>'
        for e in result.edges
    )
    return "\n".join(parts + ["</graph>", "</graphml>"])


def _html(result: ScanResult) -> str:
    data = result.to_dict()
    findings = (
        "".join(
            f'<tr><td class="{f.severity.value}">{f.severity.value.upper()}</td><td>{html.escape(", ".join(f.as_dict()["owasp"]))}</td><td>{html.escape(f.asset)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.evidence)}</td><td>{html.escape(f.remediation)}</td></tr>'
            for f in sorted(result.findings, key=lambda x: x.severity.value)
        )
        or '<tr><td colspan="6">No findings</td></tr>'
    )
    coverage = "".join(
        f"<tr><td>{html.escape(row['id'])}</td><td>{html.escape(row['name'])}</td><td>{html.escape(row['state'].upper())}</td><td>{html.escape(row['note'])}</td></tr>"
        for group in ("web", "api")
        for row in data["owasp_coverage"].get(group, [])
    )
    assets = "".join(
        f"<tr><td>{html.escape(a.kind)}</td><td><code>{html.escape(a.value)}</code></td><td>{html.escape(a.root_domain)}</td><td>{html.escape(a.source)}</td></tr>"
        for a in sorted(result.assets.values(), key=lambda x: (x.kind, x.value))
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>DomainRecon {result.scan_id}</title><style>{STYLE}</style></head><body><main><h1>DomainRecon report</h1><p>Scan <code>{result.scan_id}</code> · {html.escape(", ".join(result.targets))}</p><div class="cards"><div class="card"><div class="n">{len(result.assets)}</div>assets</div><div class="card"><div class="n">{len(result.edges)}</div>connections</div><div class="card"><div class="n">{len(result.findings)}</div>findings</div></div><h2>OWASP coverage</h2><p>{html.escape(data["owasp_coverage"]["disclaimer"])}</p><table><tr><th>Category</th><th>Name</th><th>Status</th><th>Scope note</th></tr>{coverage}</table><h2>Findings</h2><table><tr><th>Severity</th><th>OWASP</th><th>Asset</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr>{findings}</table><h2>Assets</h2><table><tr><th>Type</th><th>Value</th><th>Root</th><th>Source</th></tr>{assets}</table></main></body></html>"""
