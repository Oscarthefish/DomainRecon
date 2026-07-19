from fastapi.testclient import TestClient

import domainrecon.web as web
from domainrecon.web import ScanRequest, app


client = TestClient(app)


def test_home_page_contains_scan_interface():
    response = client.get("/")
    assert response.status_code == 200
    assert "New reconnaissance scan" in response.text
    assert "DOMAIN<span>RECON" in response.text
    assert "Explain scan profiles" in response.text
    assert "connectionsPane" in response.text
    assert "ENUMERATING SURFACE" in response.text
    assert "PROACTIVE ATTACK-SURFACE INTELLIGENCE" in response.text
    assert "RELATIONSHIP MAP" in response.text
    assert "CROSS-DOMAIN PIVOTS" in response.text
    assert "CONNECTED DOMAIN GROUPS" in response.text
    assert "connected only" in response.text
    assert "renderClusters" in response.text
    assert "NEW SINCE BASELINE" in response.text
    assert "Scan history" in response.text
    assert "risk_score" in response.text
    assert "RECOMMENDED NEXT ACTIONS" in response.text
    assert "Interactive domain relationship graph" in response.text
    assert "ANALYST NEXT STEP" in response.text
    assert "exposed Git or environment files" in response.text
    assert "Reset graph view" in response.text
    assert "results-mode" in response.text
    assert "reconnecting automatically" in response.text
    assert "requestScan" in response.text
    assert "enrich_external" in response.text
    assert "External integrations" in response.text
    assert "Save integration settings" in response.text
    assert "Run deep inspection" in response.text
    assert "Deep inspect elevated assets" in response.text
    assert "deepAuthorized" in response.text
    assert "OWASP COVERAGE" in response.text
    assert "WEB TOP 10 · API TOP 10" in response.text
    assert "renderOwasp" in response.text
    assert "RESEARCHER CONTEXT" in response.text
    assert "Click a node to isolate its connected component" in response.text
    assert "focusGraphNode" in response.text
    assert "data-owasp-filter" in response.text


def test_integrations_endpoint_reports_readiness_without_keys():
    response = client.get("/api/integrations")
    assert response.status_code == 200
    assert {item["name"] for item in response.json()} == {"RDAP", "Shodan", "Censys"}


def test_active_scan_requires_authorization():
    response = client.post(
        "/api/scans",
        json={"targets": ["example.com"], "mode": "active", "authorized": False},
    )
    assert response.status_code == 400
    assert "authorization" in response.json()["detail"].lower()


def test_accepts_large_domain_lists():
    request = ScanRequest(targets=[f"domain{i}.example" for i in range(50)])
    assert len(request.targets) == 50


def test_rejects_invalid_domain():
    response = client.post(
        "/api/scans",
        json={"targets": ["localhost"], "mode": "passive"},
    )
    assert response.status_code == 422


def test_saved_html_report_opens_inline_after_restart(tmp_path, monkeypatch):
    scan_id = "abcdef123456"
    output = tmp_path / scan_id
    output.mkdir()
    (output / "report.json").write_text(
        '{"scan_id":"abcdef123456","targets":[],"assets":[],"edges":[],"findings":[],"errors":[]}'
    )
    (output / "report.html").write_text("<html><title>Saved report</title></html>")
    monkeypatch.setattr(web, "OUTPUT_ROOT", tmp_path)
    web.jobs.clear()

    response = client.get(f"/api/scans/{scan_id}/download/html")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "content-disposition" not in response.headers
    assert "Saved report" in response.text


def test_saved_report_path_rejects_invalid_scan_id(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "OUTPUT_ROOT", tmp_path)
    response = client.get("/api/scans/../../etc/download/html")
    assert response.status_code == 404
