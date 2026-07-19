from domainrecon.models import Asset, Finding, ScanResult, Severity
from domainrecon.report import write_reports


def test_writes_all_report_formats_and_escapes_html(tmp_path):
    result = ScanResult("scan", ["example.com"])
    result.add_asset(Asset("domain", "<example.com>", "example.com", "test"))
    result.findings.append(
        Finding("example.com", "<unsafe>", Severity.LOW, "test", "x", "fix", "test")
    )
    write_reports(result, tmp_path)
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "graph.graphml").exists()
    body = (tmp_path / "report.html").read_text()
    assert "&lt;unsafe&gt;" in body
    assert "<unsafe>" not in body
    assert "OWASP coverage" in body
    assert "A05:2021" in body
