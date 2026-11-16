from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field, field_validator

from .collectors import ProbeOptions
from .compare import compare_results
from .config import save_secrets
from .engine import ReconEngine
from .enrichment import integration_status
from .owasp import hydrate_result
from .report import write_reports
from .scope import Scope
from .screenshots import capture_screenshots
from .store import Store

OUTPUT_ROOT = Path("recon-output")


class ScanRequest(BaseModel):
    request_id: str = Field(
        default_factory=lambda: __import__("uuid").uuid4().hex,
        pattern=r"^[a-f0-9-]{16,64}$",
    )
    targets: list[str] = Field(min_length=1, max_length=100)
    excludes: list[str] = Field(default_factory=list, max_length=200)
    mode: Literal["passive", "active"] = "passive"
    authorized: bool = False
    max_hosts: int = Field(default=250, ge=1, le=5000)
    concurrency: int = Field(default=20, ge=1, le=100)
    timeout: float = Field(default=8, ge=1, le=60)
    enrich_external: bool = True

    @field_validator("targets", "excludes")
    @classmethod
    def no_empty_values(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("domain entries cannot be empty")
        return values


class IntegrationConfig(BaseModel):
    shodan_api_key: str | None = Field(default=None, max_length=1000)
    censys_pat: str | None = Field(default=None, max_length=1000)


@dataclass
class Job:
    id: str
    status: str = "queued"
    message: str = "Waiting to start"
    result: dict[str, Any] | None = None
    error: str | None = None
    output: Path | None = None
    task: asyncio.Task[None] | None = field(default=None, repr=False)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "message": self.message,
            "result": self.result,
            "error": self.error,
        }


app = FastAPI(title="DomainRecon", docs_url=None, redoc_url=None)
jobs: dict[str, Job] = {}
request_jobs: dict[str, Job] = {}
SCAN_ID_RE = re.compile(r"^[a-f0-9]{12}$")


def _load_saved_job(scan_id: str) -> Job | None:
    if not SCAN_ID_RE.fullmatch(scan_id):
        return None
    output = OUTPUT_ROOT / scan_id
    report = output / "report.json"
    if not report.is_file():
        return None
    try:
        result = hydrate_result(json.loads(report.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None
    job = Job(
        id=scan_id,
        status="complete",
        message="Loaded saved scan",
        result=result,
        output=output,
    )
    jobs[scan_id] = job
    return job


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return INDEX_HTML


@app.get("/api/integrations")
async def integrations() -> list[dict[str, Any]]:
    return integration_status()


@app.post("/api/integrations/config")
async def configure_integrations(config: IntegrationConfig) -> dict[str, Any]:
    try:
        save_secrets(
            {
                "SHODAN_API_KEY": config.shodan_api_key,
                "CENSYS_PAT": config.censys_pat,
            }
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"saved": True, "providers": integration_status()}


@app.post("/api/scans", status_code=202)
async def create_scan(request: ScanRequest) -> dict[str, Any]:
    if existing := request_jobs.get(request.request_id):
        return existing.public()
    if request.mode == "active" and not request.authorized:
        raise HTTPException(400, "Active scanning requires authorization confirmation")
    try:
        scope = Scope.build(request.targets, request.excludes)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    options = ProbeOptions(
        timeout=request.timeout,
        concurrency=request.concurrency,
        allow_private=False,
        enrich_external=request.enrich_external,
    )
    engine = ReconEngine(scope, options)
    job = Job(id=__import__("uuid").uuid4().hex[:12])
    jobs[job.id] = job
    request_jobs[request.request_id] = job
    job.task = asyncio.create_task(_run(job, engine, request))
    return job.public()


async def _run(job: Job, engine: ReconEngine, request: ScanRequest) -> None:
    job.status = "running"
    job.message = "Discovering and fingerprinting in-scope assets"
    try:
        result = await engine.run(
            passive_only=request.mode == "passive", max_hosts=request.max_hosts
        )
        output = OUTPUT_ROOT / result.scan_id
        if request.mode == "active":
            try:
                await asyncio.wait_for(capture_screenshots(result, output), timeout=60)
            except asyncio.TimeoutError:
                result.errors.append("screenshots: timed out after 60 seconds")
        with Store(OUTPUT_ROOT / "domainrecon.sqlite3") as store:
            baseline = store.previous_for_targets(result.targets)
            result.comparison = compare_results(result.to_dict(), baseline)
            store.save(result)
        write_reports(result, output)
        job.id = result.scan_id
        job.output = output
        job.result = result.to_dict()
        job.status = "complete"
        job.message = "Scan complete"
    except Exception as exc:  # job boundary: surface failures without crashing the server
        job.status = "failed"
        job.error = str(exc)
        job.message = "Scan failed"


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    job = jobs.get(scan_id)
    if not job:
        # The engine creates its own result ID; completed jobs may have moved IDs.
        job = next((item for item in jobs.values() if item.id == scan_id), None)
    if not job:
        job = _load_saved_job(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    return job.public()


@app.get("/api/history/latest")
async def latest_scan() -> dict[str, Any]:
    database = OUTPUT_ROOT / "domainrecon.sqlite3"
    if not database.exists():
        raise HTTPException(404, "No saved scans")
    with Store(database) as store:
        result = store.latest()
    if not result:
        raise HTTPException(404, "No saved scans")
    result = hydrate_result(result)
    scan_id = str(result["scan_id"])
    job = next((item for item in jobs.values() if item.id == scan_id), None)
    if not job:
        job = Job(
            id=scan_id,
            status="complete",
            message="Loaded most recent saved scan",
            result=result,
            output=OUTPUT_ROOT / scan_id,
        )
        jobs[scan_id] = job
    return job.public()


@app.get("/api/history")
async def scan_history(limit: int = 25) -> list[dict[str, Any]]:
    database = OUTPUT_ROOT / "domainrecon.sqlite3"
    if not database.exists():
        return []
    with Store(database) as store:
        return store.history(max(1, min(limit, 100)))


@app.get("/api/scans/{scan_id}/download/{kind}")
async def download(scan_id: str, kind: Literal["json", "html", "graphml"]):
    job = next((item for item in jobs.values() if item.id == scan_id), None)
    if not job:
        job = _load_saved_job(scan_id)
    if not job or job.status != "complete" or not job.output:
        raise HTTPException(404, "Completed scan not found")
    names = {"json": "report.json", "html": "report.html", "graphml": "graph.graphml"}
    path = job.output / names[kind]
    if not path.is_file():
        raise HTTPException(404, "Report file not found")
    if kind == "html":
        return HTMLResponse(path.read_text(encoding="utf-8"))
    return FileResponse(path, filename=f"domainrecon-{scan_id}.{kind}")


def main() -> None:
    import uvicorn

    uvicorn.run("domainrecon.web:app", host="127.0.0.1", port=8765)


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DomainRecon</title><style>
:root{--bg:#081017;--panel:#101c26;--line:#263847;--text:#edf5f7;--muted:#93a8b1;--cyan:#3ddbd9;--amber:#ffbf69;--red:#ff6b6b}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#123344 0,transparent 35%),var(--bg);color:var(--text);font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;min-height:100vh}
header,main{max-width:1500px;margin:auto;padding:28px 34px}header{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
.brand{font-size:20px;font-weight:750;letter-spacing:.08em}.brand span{color:var(--cyan)}.tag{color:var(--muted);font:12px ui-monospace,monospace}
.grid{display:grid;grid-template-columns:350px minmax(0,1fr);gap:24px;align-items:start}.grid.results-mode{display:block}.grid.results-mode #scanForm{display:none}.panel{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:14px;padding:24px;box-shadow:0 16px 40px #0005}
h1{font-size:34px;line-height:1.1;margin:6px 0 9px}h2{font-size:16px;margin:0 0 18px}p{color:var(--muted);line-height:1.55}label{display:block;color:#c9d8dd;font-size:12px;font-weight:650;margin:15px 0 7px}
textarea,input,select{width:100%;border:1px solid var(--line);background:#09131b;color:var(--text);padding:11px 12px;border-radius:8px;outline:none}textarea:focus,input:focus,select:focus{border-color:var(--cyan)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.check{display:flex;align-items:flex-start;gap:9px;margin:15px 0;color:var(--muted);font-weight:400;line-height:1.4}.check input{width:auto;margin-top:3px}.labelrow{display:flex;align-items:center;gap:7px;margin-top:15px}.labelrow label{margin:0}
button{width:100%;border:0;border-radius:8px;padding:12px;background:var(--cyan);color:#032323;font-weight:750;cursor:pointer}button:disabled{opacity:.45;cursor:wait}.help{width:19px;height:19px;padding:0;border:1px solid #45606c;border-radius:50%;background:transparent;color:var(--cyan);font:700 11px ui-monospace;line-height:17px}
.hero{margin-bottom:22px}.empty{min-height:360px;display:grid;place-content:center;text-align:center;color:var(--muted)}.radar{width:120px;height:120px;border:1px solid #315363;border-radius:50%;margin:auto;position:relative;background:repeating-radial-gradient(circle,transparent 0 24px,#223b46 25px)}.radar:after{content:"";position:absolute;inset:50% 0 0 50%;border-left:1px solid var(--cyan);transform-origin:0 0;animation:scan 3s linear infinite}@keyframes scan{to{transform:rotate(360deg)}}
.status{display:none}.status.show{display:block}.statusline{display:flex;justify-content:space-between;align-items:center;gap:12px}.statusactions{display:flex;align-items:center;gap:8px}.secondary{width:auto;padding:7px 10px;background:transparent;border:1px solid var(--line);color:var(--text);font-size:12px}.pill{font:11px ui-monospace;padding:5px 9px;border-radius:99px;background:#18333e;color:var(--cyan)}
.activity{display:none;align-items:center;gap:16px;margin:18px 0;padding:14px;border:1px solid #284958;border-radius:10px;background:#0b1922;overflow:hidden;position:relative}.activity.running{display:flex}.activity:after{content:"";position:absolute;bottom:0;left:-45%;width:45%;height:2px;background:linear-gradient(90deg,transparent,var(--cyan));animation:sweep 1.5s ease-in-out infinite}.orbit{width:42px;height:42px;border:1px solid #315563;border-radius:50%;position:relative;flex:0 0 auto}.orbit:before{content:"";position:absolute;width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px var(--cyan);left:17px;top:-4px;transform-origin:4px 25px;animation:spin 1.2s linear infinite}.pulse{color:var(--cyan);font:12px ui-monospace}.pulse small{display:block;color:var(--muted);margin-top:5px}@keyframes spin{to{transform:rotate(360deg)}}@keyframes sweep{50%,100%{left:100%}}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:18px 0}.metric{padding:15px;background:#0b161f;border:1px solid var(--line);border-radius:9px}.metric b{display:block;font-size:25px}.metric span{color:var(--muted);font-size:11px}
table{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto}th,td{text-align:left;border-bottom:1px solid var(--line);padding:11px 9px;vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);position:sticky;top:0;background:var(--panel);z-index:1}.sev-high{color:var(--red)}.sev-medium{color:var(--amber)}.sev-low{color:#79c0ff}.downloads{display:flex;gap:8px;margin-top:16px}.downloads a{color:var(--cyan);border:1px solid var(--line);border-radius:7px;padding:8px 10px;text-decoration:none}.error{color:var(--red);margin-top:12px}.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-top:22px;overflow-x:auto}.tab{width:auto;background:transparent;color:var(--muted);padding:10px 13px;border-radius:6px 6px 0 0;font-size:12px;white-space:nowrap}.tab.active{color:var(--cyan);background:#162732}.tabpane{display:none;max-height:520px;overflow:auto}.tabpane.active{display:block}.emptyrow{color:var(--muted);padding:18px 7px}.code{font-family:ui-monospace,monospace;color:#c7d7dc}.badge{font:10px ui-monospace;color:var(--cyan);background:#17313a;padding:3px 6px;border-radius:4px}.errline{color:#ff9b9b;font-family:ui-monospace,monospace}
.clusterbar{border:1px solid var(--line);background:#0a151d;border-radius:10px;padding:16px;margin:18px 0}.clusters{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}.cluster{border:1px solid #344d59;border-top:3px solid var(--amber);border-radius:7px;padding:13px;background:#101e27}.clusterhead{display:flex;justify-content:space-between;gap:8px}.clusterhead b{font-size:13px}.score{color:var(--amber);font:11px ui-monospace}.domains{display:flex;gap:7px;flex-wrap:wrap;margin-top:11px}.domainchip{font:600 13px -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;color:#f0f7f8;background:#1b3440;padding:6px 9px;border-radius:5px;line-height:1.3}.cluster small{display:block;color:var(--muted);font-size:12px;margin-top:10px}.cluster.isolates{border-top-color:#405b67}
.guidance{border:1px solid #3a5260;background:linear-gradient(135deg,#0d2029,#101a23);border-radius:10px;padding:16px;margin:16px 0}.actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:9px}.action{padding:13px;background:#14242d;border-left:3px solid var(--cyan);border-radius:5px;display:flex;flex-direction:column}.action.urgent{border-color:var(--red)}.action.review{border-color:var(--amber)}.action b{display:block;font-size:13px;margin-bottom:5px}.action span{color:var(--muted);font-size:12px;line-height:1.45}.actiongo{width:auto;align-self:flex-start;margin-top:auto;padding:7px 10px;background:#1a3a45;color:var(--cyan);border:1px solid #315865;font-size:11px}.actiongo:hover{background:#204b57}.step{display:inline-block;color:#061216;background:var(--cyan);border-radius:50%;width:20px;height:20px;line-height:20px;text-align:center;margin-right:7px;font-size:11px}
.owaspbar,.researchbar{border:1px solid var(--line);background:#0a151d;border-radius:10px;padding:16px;margin:16px 0}.owaspgrid,.researchgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:7px}.owaspcard{border-left:3px solid #546c76;background:#111f28;padding:9px 10px;border-radius:4px}.owaspcard.signal{border-color:var(--red)}.owaspcard.tested{border-color:var(--cyan)}.owaspcard.manual{border-color:var(--amber)}.owaspcard b,.researchcard b{display:block;font-size:12px}.owaspcard span,.researchcard span{display:block;color:var(--muted);font-size:11px;margin-top:4px}.owaspcard button{width:auto;padding:5px 8px;margin-top:8px;background:#1a3a45;color:var(--cyan);border:1px solid #315865;font-size:10px}.owaspdomains{color:#d9e7ea!important}.owaspnote{font-size:11px;margin:10px 0 0}.researchcard{background:#111f28;border-top:2px solid #4b7180;border-radius:5px;padding:11px}.researchcard .domainname{color:#fff;font-size:13px}.researchcard .fact{color:#c8d9dd}.filterbar{display:none;align-items:center;justify-content:space-between;gap:10px;padding:9px 11px;background:#122731;border:1px solid #315865;color:var(--cyan);font-size:12px}.filterbar.show{display:flex}.filterbar button{width:auto;padding:5px 8px;background:transparent;color:var(--cyan);border:1px solid #315865}
.changes{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:12px 0}.change{padding:11px;border-radius:7px;background:#0b171f;border:1px solid var(--line)}.change b{font-size:20px;display:block}.change.new b{color:var(--cyan)}.change.removed b{color:var(--red)}.change.changed b{color:var(--amber)}.change span{font-size:10px;color:var(--muted)}.risk{font-weight:800}.risk.high{color:var(--red)}.risk.medium{color:var(--amber)}.risk.low{color:var(--cyan)}
.intel{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(300px,.65fr);gap:14px;margin:18px 0}.graphbox,.pivotbox{border:1px solid var(--line);background:#0a151d;border-radius:10px;padding:14px}.sectionhead{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;gap:10px}.sectionhead h3{font-size:12px;letter-spacing:.08em;margin:0}.sectionhead span{font:10px ui-monospace;color:var(--muted)}#relationshipGraph{width:100%;height:500px;display:block;cursor:grab;touch-action:none;border-radius:7px;background:#071118}#relationshipGraph.dragging{cursor:grabbing}.graph-edge{stroke:#3a5663;stroke-width:1.3;transition:opacity .18s,stroke .18s,stroke-width .18s}.graph-edge.strong{stroke:var(--amber);stroke-width:2.4}.graph-item{transition:opacity .18s}.graph-item.dim,.graph-edge.dim{opacity:.1}.graph-item.focus .graph-node{stroke:#fff;stroke-width:3;filter:drop-shadow(0 0 5px var(--cyan))}.graph-edge.focus{opacity:1;stroke:var(--cyan);stroke-width:3}.graph-node{fill:#132a35;stroke:#4d7180;stroke-width:1.2}.graph-node.root{fill:#123c44;stroke:var(--cyan);stroke-width:2}.graph-node.pivotnode{fill:#5b421d;stroke:var(--amber);stroke-width:2}.graph-label{fill:#f2f7f8;font:600 12px -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;paint-order:stroke;stroke:#071118;stroke-width:3px;stroke-linejoin:round}.pivots{display:grid;gap:8px;max-height:500px;overflow:auto}.pivot{border-left:3px solid var(--amber);background:#111f28;padding:10px 11px;border-radius:4px}.pivot b{display:block;font-size:13px;color:#fff}.pivot span{display:block;color:var(--muted);font:12px -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;margin-top:5px;overflow-wrap:anywhere}.pivot.none{border-color:#48606b}.legend{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:11px;flex-wrap:wrap}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--cyan);margin-right:4px}.dot.shared{background:var(--amber)}.graphfilter{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--muted)}.graphfilter input{width:auto}.graphcontrols{display:flex;gap:4px}.graphcontrols button{width:28px;height:28px;padding:0;background:#132a35;color:var(--text);border:1px solid var(--line);font-size:15px}.graphhint{color:var(--cyan)!important}
.modal{display:none;position:fixed;inset:0;background:#02080dcc;z-index:20;place-items:center;padding:20px}.modal.open{display:grid}.modalcard{width:min(620px,100%);max-height:90vh;overflow:auto;background:#111f29;border:1px solid #345363;border-radius:14px;padding:24px;box-shadow:0 24px 80px #000}.modalhead{display:flex;align-items:center;justify-content:space-between}.modalhead h2{margin:0}.close{width:auto;background:transparent;color:var(--muted);font-size:20px;padding:4px 8px}.profilecard{padding:13px;border:1px solid var(--line);border-radius:8px;margin-top:12px}.profilecard b{color:var(--cyan)}.headeractions{display:flex;align-items:center;gap:12px}.providergrid{display:grid;gap:10px;margin:16px 0}.provider{display:flex;justify-content:space-between;gap:12px;padding:11px;border:1px solid var(--line);border-radius:7px}.provider .ready{color:var(--cyan)}.provider .missing{color:var(--amber)}.secretrow{position:relative}.secretrow input{padding-right:70px}.secretrow button{position:absolute;right:5px;top:5px;width:auto;padding:6px 9px;background:#17313a;color:var(--cyan);font-size:10px}.savehint{min-height:20px;color:var(--cyan);font-size:12px}.checklist{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:15px 0}.checkitem{padding:9px;border:1px solid var(--line);border-radius:6px;color:#c9d8dd;font-size:12px}.targetlist{max-height:150px;overflow:auto;padding:10px;background:#09131b;border:1px solid var(--line);border-radius:7px;font:12px ui-monospace;line-height:1.6}
@media(max-width:850px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:1fr 1fr}header{padding:20px}main{padding:20px}}
</style></head><body>
<header><div class="brand">DOMAIN<span>RECON</span></div><div class="headeractions"><div class="tag">PROACTIVE ATTACK-SURFACE INTELLIGENCE // AUTHORIZED</div><button class="secondary" id="integrationsButton" type="button">Integrations</button></div></header>
<main><section class="hero"><h1>Map the surface.<br>Expose the relationships.</h1><p>Discover external assets, pivot across shared infrastructure, and prioritize exposure signals before they become an incident.</p></section>
<div class="grid"><form class="panel" id="scanForm"><h2>New reconnaissance scan</h2>
<label for="targets">TARGET DOMAINS · ONE PER LINE</label><textarea id="targets" rows="4" placeholder="example.com&#10;example.org" required></textarea>
<label for="excludes">EXCLUSIONS · OPTIONAL</label><textarea id="excludes" rows="2" placeholder="dev.example.com"></textarea>
<div class="row"><div><div class="labelrow"><label for="mode">SCAN PROFILE</label><button class="help" id="profileHelp" type="button" aria-label="Explain scan profiles">?</button></div><select id="mode"><option value="passive">Passive + DNS</option><option value="active">Authorized HTTP/TLS</option></select></div><div><label for="maxHosts">HOST LIMIT</label><input id="maxHosts" type="number" value="250" min="1" max="5000"></div></div>
<div class="row"><div><label for="concurrency">CONCURRENCY</label><input id="concurrency" type="number" value="20" min="1" max="100"></div><div><label for="timeout">TIMEOUT (SEC)</label><input id="timeout" type="number" value="8" min="1" max="60"></div></div>
<label class="check"><input id="enrichExternal" type="checkbox" checked><span>Enrich with read-only third-party intelligence (RDAP and configured providers).</span></label>
<div class="hint" id="integrationStatus">Checking enrichment providers…</div>
<label class="check"><input id="authorized" type="checkbox"><span>I confirm I own or have explicit permission to assess these domains. Required for active probes.</span></label>
<button id="run" type="submit">Run reconnaissance</button><div class="error" id="error"></div></form>
<section class="panel"><div class="empty" id="empty"><div><div class="radar"></div><h2>Awaiting target scope</h2><p>Results, connections, and exposure findings will appear here.</p></div></div>
<div class="status" id="status"><div class="statusline"><h2 id="statusText">Scan queued</h2><div class="statusactions"><button class="secondary" id="newScan" type="button">New scan</button><span class="pill" id="statusPill">QUEUED</span></div></div><p id="message"></p><div class="activity" id="activity"><div class="orbit"></div><div class="pulse">ENUMERATING SURFACE<small id="activityText">Querying public sources and resolving DNS records…</small></div></div><div class="metrics"><div class="metric"><b id="assetCount">0</b><span>ASSETS</span></div><div class="metric"><b id="edgeCount">0</b><span>RELATIONSHIPS</span></div><div class="metric"><b id="findingCount">0</b><span>FINDINGS</span></div><div class="metric"><b id="errorCount">0</b><span>ERRORS</span></div></div>
<div class="changes"><div class="change new"><b id="newCount">0</b><span>NEW SINCE BASELINE</span></div><div class="change removed"><b id="removedCount">0</b><span>REMOVED</span></div><div class="change changed"><b id="changedCount">0</b><span>CHANGED</span></div></div>
<div class="guidance"><div class="sectionhead"><h3>RECOMMENDED NEXT ACTIONS</h3><span>ANALYST WORKFLOW</span></div><div class="actions" id="nextActions"></div></div>
<div class="researchbar"><div class="sectionhead"><h3>RESEARCHER CONTEXT</h3><span>RDAP · WHOIS · DNS · INTERNET INTELLIGENCE</span></div><div class="researchgrid" id="researchContext"></div></div>
<div class="owaspbar"><div class="sectionhead"><h3>OWASP COVERAGE</h3><span>WEB TOP 10 · API TOP 10</span></div><div class="owaspgrid" id="owaspCoverage"></div><p class="owaspnote" id="owaspDisclaimer"></p></div>
<div class="clusterbar"><div class="sectionhead"><h3>CONNECTED DOMAIN GROUPS</h3><span id="clusterCount">0 GROUPS</span></div><div class="clusters" id="clusters"></div></div>
<div class="intel"><div class="graphbox"><div class="sectionhead"><h3>RELATIONSHIP MAP</h3><div class="legend"><span id="graphFocus" class="graphhint">Click a node to isolate its connected component</span><span><i class="dot"></i>root domain</span><span><i class="dot shared"></i>shared pivot</span><label class="graphfilter"><input id="connectedOnly" type="checkbox" checked> connected only</label><div class="graphcontrols"><button id="zoomOut" type="button" aria-label="Zoom out">−</button><button id="zoomReset" type="button" aria-label="Reset graph view">⌂</button><button id="zoomIn" type="button" aria-label="Zoom in">+</button></div></div></div><svg id="relationshipGraph" viewBox="0 0 900 420" role="img" aria-label="Interactive domain relationship graph"></svg></div><div class="pivotbox"><div class="sectionhead"><h3>RANKED CROSS-DOMAIN PIVOTS</h3><span id="pivotCount">0 DETECTED</span></div><div class="pivots" id="pivots"></div></div></div>
<div class="tabs" role="tablist"><button class="tab active" type="button" data-tab="findingsPane">Findings <span id="findingTabCount">0</span></button><button class="tab" type="button" data-tab="assetsPane">Assets <span id="assetTabCount">0</span></button><button class="tab" type="button" data-tab="connectionsPane">Connections <span id="edgeTabCount">0</span></button><button class="tab" type="button" data-tab="historyPane">Scan history</button><button class="tab" type="button" data-tab="errorsPane">Errors <span id="errorTabCount">0</span></button></div>
<div class="tabpane active" id="findingsPane"><div class="filterbar" id="findingFilter"><span id="findingFilterText"></span><button id="clearFindingFilter" type="button">Clear filter</button></div><table><thead><tr><th>SEVERITY</th><th>CATEGORY</th><th>OWASP</th><th>ASSET</th><th>FINDING</th><th>EVIDENCE</th><th>ANALYST NEXT STEP</th></tr></thead><tbody id="findings"></tbody></table></div>
<div class="tabpane" id="assetsPane"><table><thead><tr><th>RISK</th><th>TYPE</th><th>VALUE</th><th>SOURCE</th><th>DETAILS</th></tr></thead><tbody id="assets"></tbody></table></div>
<div class="tabpane" id="connectionsPane"><table><thead><tr><th>FROM</th><th>RELATION</th><th>TO</th><th>EVIDENCE</th></tr></thead><tbody id="connections"></tbody></table></div>
<div class="tabpane" id="historyPane"><table><thead><tr><th>SCAN</th><th>DATE</th><th>TARGETS</th><th>ASSETS</th><th>FINDINGS</th></tr></thead><tbody id="history"></tbody></table></div>
<div class="tabpane" id="errorsPane"><table><thead><tr><th>COLLECTOR ERROR</th></tr></thead><tbody id="errors"></tbody></table></div><div class="downloads" id="downloads"></div></div></section></div></main>
<div class="modal" id="profileModal" role="dialog" aria-modal="true" aria-labelledby="profileTitle"><div class="modalcard"><div class="modalhead"><h2 id="profileTitle">Scan profiles</h2><button class="close" id="closeProfile" type="button" aria-label="Close scan profile help">×</button></div><div class="profilecard"><b>Passive + DNS</b><p>Queries certificate-transparency records and standard DNS records. It does not connect directly to discovered websites. Best for initial inventory, ownership correlation, and low-impact mapping.</p></div><div class="profilecard"><b>Authorized HTTP/TLS</b><p>Includes passive discovery, then performs bounded read-only checks for login surfaces, API schemas, GraphQL, storage fingerprints, robots/security metadata, and exposed Git or environment files. It records fingerprints rather than secret values. Use only with explicit permission.</p></div><p>Both profiles obey exclusions, host limits, concurrency, and timeout settings. Neither exploits vulnerabilities, submits credentials, modifies targets, or retrieves breach dumps.</p></div></div>
<div class="modal" id="integrationsModal" role="dialog" aria-modal="true" aria-labelledby="integrationsTitle"><form class="modalcard" id="integrationsForm"><div class="modalhead"><h2 id="integrationsTitle">External integrations</h2><button class="close" id="closeIntegrations" type="button" aria-label="Close integrations">×</button></div><p>Credentials are stored only in the local <span class="code">.env</span> file with owner-only permissions. Existing values are never returned to this page.</p><div class="providergrid" id="providerGrid"></div><label for="shodanKey">SHODAN API KEY</label><div class="secretrow"><input id="shodanKey" type="password" autocomplete="off" placeholder="Leave blank to preserve existing value"><button type="button" data-reveal="shodanKey">SHOW</button></div><label for="censysPat">CENSYS PERSONAL ACCESS TOKEN</label><div class="secretrow"><input id="censysPat" type="password" autocomplete="off" placeholder="Leave blank to preserve existing value"><button type="button" data-reveal="censysPat">SHOW</button></div><label class="check"><input id="clearCredentials" type="checkbox"><span>Remove both saved API credentials</span></label><button type="submit">Save integration settings</button><p class="savehint" id="integrationSaveStatus"></p></form></div>
<div class="modal" id="deepModal" role="dialog" aria-modal="true" aria-labelledby="deepTitle"><form class="modalcard" id="deepForm"><div class="modalhead"><h2 id="deepTitle">Deep inspect elevated assets</h2><button class="close" id="closeDeep" type="button" aria-label="Close deep inspection">×</button></div><p>Launch a bounded, non-destructive active assessment against the selected elevated-risk hosts.</p><div class="checklist"><div class="checkitem">✓ HTTP, cookies and security headers</div><div class="checkitem">✓ Login and identity-provider surfaces</div><div class="checkitem">✓ API schema and authentication analysis</div><div class="checkitem">✓ CORS and HTTP method validation</div><div class="checkitem">✓ Git, source maps, debug and storage exposure</div><div class="checkitem">✓ OWASP Web and API coverage mapping</div><div class="checkitem">✓ TLS and technology fingerprints</div><div class="checkitem">✓ Screenshots of responding websites</div></div><label>SELECTED HOSTS</label><div class="targetlist" id="deepTargets"></div><label class="check"><input id="deepAuthorized" type="checkbox" required><span>I confirm I own or have explicit permission to actively assess these hosts.</span></label><button type="submit" id="runDeep">Run deep inspection</button><p class="error" id="deepError"></p></form></div>
<script>
const $=id=>document.getElementById(id), lines=id=>$(id).value.split(/\n|,/).map(x=>x.trim()).filter(Boolean);let timer,lastResult,deepHostList=[],graphState={x:0,y:0,scale:1},dragStart=null,selectedGraphNode=null;
$('mode').onchange=()=>{$('authorized').required=$('mode').value==='active'};
$('profileHelp').onclick=()=>{$('profileModal').classList.add('open');$('closeProfile').focus()};$('closeProfile').onclick=()=>$('profileModal').classList.remove('open');$('profileModal').onclick=e=>{if(e.target===$('profileModal'))$('profileModal').classList.remove('open')};
$('integrationsButton').onclick=()=>{$('integrationsModal').classList.add('open');loadIntegrations();$('closeIntegrations').focus()};$('closeIntegrations').onclick=()=>$('integrationsModal').classList.remove('open');$('integrationsModal').onclick=e=>{if(e.target===$('integrationsModal'))$('integrationsModal').classList.remove('open')};document.querySelectorAll('[data-reveal]').forEach(button=>button.onclick=()=>{const input=$(button.dataset.reveal);input.type=input.type==='password'?'text':'password';button.textContent=input.type==='password'?'SHOW':'HIDE'});
$('closeDeep').onclick=()=>$('deepModal').classList.remove('open');$('deepModal').onclick=e=>{if(e.target===$('deepModal'))$('deepModal').classList.remove('open')};
$('deepForm').onsubmit=async e=>{e.preventDefault();if(!$('deepAuthorized').checked)return;$('runDeep').disabled=true;$('deepError').textContent='';try{const body={request_id:crypto.randomUUID(),targets:deepHostList,excludes:[],mode:'active',authorized:true,enrich_external:$('enrichExternal').checked,max_hosts:Math.min(250,Math.max(20,deepHostList.length*10)),concurrency:10,timeout:12};const {response,data}=await requestScan(body);if(!response.ok)throw Error(apiError(data));$('deepModal').classList.remove('open');$('empty').style.display='none';$('status').classList.add('show');render(data);poll(data.id)}catch(error){$('deepError').textContent=error.message||'Unable to start deep inspection';$('runDeep').disabled=false}};
$('integrationsForm').onsubmit=async e=>{e.preventDefault();$('integrationSaveStatus').textContent='Saving locally…';const clear=$('clearCredentials').checked,payload={shodan_api_key:clear?'':($('shodanKey').value||null),censys_pat:clear?'':($('censysPat').value||null)};try{const response=await fetch('/api/integrations/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await response.json();if(!response.ok)throw Error(apiError(data));$('shodanKey').value='';$('censysPat').value='';$('clearCredentials').checked=false;$('integrationSaveStatus').textContent='Saved. New scans will use connected providers.';renderIntegrationStatus(data.providers)}catch(error){$('integrationSaveStatus').textContent=error.message||'Unable to save integration settings'}};
document.querySelectorAll('.tab').forEach(button=>button.onclick=()=>{document.querySelectorAll('.tab,.tabpane').forEach(x=>x.classList.remove('active'));button.classList.add('active');$(button.dataset.tab).classList.add('active')});
$('connectedOnly').onchange=()=>{if(lastResult)drawGraph(lastResult)};
$('nextActions').onclick=e=>{const button=e.target.closest('[data-workflow]');if(button)runWorkflow(button.dataset.workflow)};
$('owaspCoverage').onclick=e=>{const button=e.target.closest('[data-owasp-filter]');if(button)filterOwasp(button.dataset.owaspFilter)};
$('clearFindingFilter').onclick=()=>filterOwasp(null);
$('newScan').onclick=()=>{document.querySelector('.grid').classList.remove('results-mode');$('scanForm').scrollIntoView({behavior:'smooth'});$('targets').focus()};
$('zoomIn').onclick=()=>setGraphZoom(graphState.scale*1.2);$('zoomOut').onclick=()=>setGraphZoom(graphState.scale/1.2);$('zoomReset').onclick=()=>{graphState={x:0,y:0,scale:1};applyGraphTransform()};
const graph=$('relationshipGraph');graph.addEventListener('wheel',e=>{e.preventDefault();setGraphZoom(graphState.scale*(e.deltaY<0?1.12:.89))},{passive:false});graph.addEventListener('pointerdown',e=>{dragStart={x:e.clientX-graphState.x,y:e.clientY-graphState.y,moved:false};graph.setPointerCapture(e.pointerId);graph.classList.add('dragging')});graph.addEventListener('pointermove',e=>{if(!dragStart)return;const x=e.clientX-dragStart.x,y=e.clientY-dragStart.y;if(Math.abs(x-graphState.x)>3||Math.abs(y-graphState.y)>3)dragStart.moved=true;graphState.x=x;graphState.y=y;applyGraphTransform()});graph.addEventListener('pointerup',e=>{const moved=dragStart?.moved;dragStart=null;graph.classList.remove('dragging');if(moved)return;const node=e.target.closest('[data-node-id]');focusGraphNode(node?.dataset.nodeId||null)});
$('scanForm').onsubmit=async e=>{e.preventDefault();$('error').textContent='';if($('mode').value==='active'&&!$('authorized').checked){$('error').textContent='Confirm authorization before an active scan.';return}$('run').disabled=true;
const body={request_id:crypto.randomUUID(),targets:lines('targets'),excludes:lines('excludes'),mode:$('mode').value,authorized:$('authorized').checked,enrich_external:$('enrichExternal').checked,max_hosts:+$('maxHosts').value,concurrency:+$('concurrency').value,timeout:+$('timeout').value};
try{const {response:r,data:d}=await requestScan(body);if(!r.ok)throw Error(apiError(d));$('empty').style.display='none';$('status').classList.add('show');render(d);poll(d.id)}catch(err){$('error').textContent=err.message||'Unable to start scan';$('run').disabled=false}};
async function requestScan(body){let failure;for(let attempt=0;attempt<3;attempt++){try{const response=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return {response,data:await response.json()}}catch(error){failure=error;if(attempt<2)await delay(500*(attempt+1))}}throw Error(`Unable to reach the local scanner after 3 attempts. The server may still be processing; reload to recover the latest completed scan. (${failure?.message||'connection error'})`)}
function poll(id){clearInterval(timer);let misses=0;timer=setInterval(async()=>{try{const r=await fetch('/api/scans/'+id);if(!r.ok)throw Error(`HTTP ${r.status}`);const d=await r.json();misses=0;render(d);if(['complete','failed'].includes(d.status)){clearInterval(timer);$('run').disabled=false}}catch{misses++;$('message').textContent=`Connection interrupted — reconnecting automatically (${misses})…`}},1200)}
function delay(ms){return new Promise(resolve=>setTimeout(resolve,ms))}
function render(d){$('statusText').textContent=d.status==='complete'?'Reconnaissance complete':d.status==='failed'?'Scan failed':'Reconnaissance in progress';$('statusPill').textContent=d.status.toUpperCase();$('message').textContent=d.error||d.message;$('activity').classList.toggle('running',['queued','running'].includes(d.status));document.querySelector('.grid').classList.toggle('results-mode',d.status==='complete');const r=d.result||{targets:[],assets:[],edges:[],findings:[],errors:[],comparison:{}};const counts={asset:r.assets.length,edge:r.edges.length,finding:r.findings.length,error:r.errors.length};Object.entries(counts).forEach(([k,v])=>{$(k+'Count').textContent=v;$(k+'TabCount').textContent=v});const c=r.comparison||{};$('newCount').textContent=(c.new_assets||[]).length;$('removedCount').textContent=(c.removed_assets||[]).length;$('changedCount').textContent=(c.changed_assets||[]).length;renderGuidance(r);renderResearch(r);renderOwasp(r);renderRelationships(r);$('findings').innerHTML=r.findings.map(f=>`<tr><td class="sev-${esc(f.severity)}">${esc(f.severity).toUpperCase()}</td><td class="code">${esc(f.asset)}</td><td>${esc(f.title)}</td></tr>`).join('')||'<tr><td class="emptyrow" colspan="3">No exposure findings recorded.</td></tr>';$('assets').innerHTML=[...r.assets].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).map(a=>`<tr><td><span class="risk ${a.risk_score>=40?'high':a.risk_score>=20?'medium':'low'}">${a.risk_score||0}</span></td><td><span class="badge">${esc(a.kind)}</span></td><td class="code">${esc(a.value)}</td><td>${esc(a.source)}</td><td>${esc(details(a.attributes))}</td></tr>`).join('')||'<tr><td class="emptyrow" colspan="5">Assets appear when the scan completes.</td></tr>';$('connections').innerHTML=r.edges.map(e=>`<tr><td class="code">${esc(e.source)}</td><td><span class="badge">${esc(e.relation)}</span></td><td class="code">${esc(e.target)}</td><td>${esc(e.evidence)}</td></tr>`).join('')||'<tr><td class="emptyrow" colspan="4">Connections appear when the scan completes.</td></tr>';$('errors').innerHTML=r.errors.map(x=>`<tr><td class="errline">${esc(x)}</td></tr>`).join('')||'<tr><td class="emptyrow">No collector errors.</td></tr>';if(d.status==='complete'){$('downloads').innerHTML=['json','html','graphml'].map(x=>`<a href="/api/scans/${d.id}/download/${x}"${x==='html'?' target="_blank" rel="noopener"':''}>${x==='html'?'OPEN REPORT':x.toUpperCase()}</a>`).join('');loadHistory()}}
function renderOwasp(r){const coverage=r.owasp_coverage||{web:[],api:[],disclaimer:''},rows=[...(coverage.web||[]),...(coverage.api||[])];$('owaspCoverage').innerHTML=rows.map(x=>{const domains=x.domains||[],count=x.finding_count||0;return `<div class="owaspcard ${esc(x.state)}"><b>${esc(x.id)} · ${esc(x.name)}</b><span>${x.state==='signal'?'SIGNAL FOUND':x.state==='tested'?'AUTOMATED CHECKS RUN':x.state==='not run'?'NOT RUN (PASSIVE SCAN)':'MANUAL VALIDATION REQUIRED'}</span>${domains.length?`<span class="owaspdomains">Affected: ${domains.slice(0,4).map(esc).join(', ')}${domains.length>4?` +${domains.length-4} more`:''}</span>`:''}<span>${esc(x.note)}</span>${count?`<button type="button" data-owasp-filter="${esc(x.id)}">View ${count} mapped finding${count===1?'':'s'}</button>`:''}</div>`}).join('')||'<div class="owaspcard manual"><b>Run an authorized active scan</b><span>OWASP coverage is produced from scan evidence.</span></div>';$('owaspDisclaimer').textContent=coverage.disclaimer||''}
function renderResearch(r){const roots=r.targets||[],registrations=new Map(r.assets.filter(x=>x.kind==='registration').map(x=>[x.root_domain,x])),intel=r.assets.filter(x=>x.kind==='internet_intelligence'),edges=r.edges||[];$('researchContext').innerHTML=roots.map(root=>{const reg=registrations.get(root),a=reg?.attributes||{},events=a.events||{},ips=[...new Set(edges.filter(e=>e.source.startsWith('domain:')&&(clean(e.source)===root||clean(e.source).endsWith('.'+root))&&(e.relation==='a'||e.relation==='aaaa')).map(e=>clean(e.target)))],ns=[...new Set(edges.filter(e=>e.source.startsWith('domain:')&&(clean(e.source)===root||clean(e.source).endsWith('.'+root))&&e.relation==='ns').map(e=>clean(e.target)))],providers=intel.filter(x=>x.root_domain===root).map(x=>x.attributes?.org||x.attributes?.asn||x.source).filter(Boolean);const entity=(a.entities||[]).find(x=>x.organization||x.name);return `<div class="researchcard"><b class="domainname">${esc(root)}</b><span class="fact">Registrar: ${esc(a.registrar||'not returned')}</span>${entity?`<span class="fact">Public entity: ${esc(entity.organization||entity.name)} (${esc((entity.roles||[]).join(', ')||'role unspecified')})</span>`:''}<span>Created: ${esc(events.registration||events.registered||'unknown')} · Expires: ${esc(events.expiration||'unknown')}</span><span>DNSSEC: ${a.dnssec===true?'signed':a.dnssec===false?'not signed':'unknown'} · Status: ${esc((a.status||[]).slice(0,3).join(', ')||'unknown')}</span><span>${ips.length} public IP${ips.length===1?'':'s'} · NS: ${esc((a.nameservers||ns).slice(0,3).join(', ')||'not observed')}</span>${providers.length?`<span>Network intelligence: ${providers.map(esc).join(', ')}</span>`:''}</div>`}).join('')||'<div class="researchcard"><b>No ownership context available</b><span>Enable external enrichment to query RDAP and configured providers.</span></div>'}
function filterOwasp(id){const rows=document.querySelectorAll('#findings tr[data-owasp]');rows.forEach(row=>row.hidden=!!id&&!row.dataset.owasp.split(' ').includes(id));$('findingFilter').classList.toggle('show',!!id);$('findingFilterText').textContent=id?`Showing findings mapped to ${id}`:'';if(id)openTab('findingsPane')}
function renderGuidance(r){const actions=[],high=r.findings.filter(x=>x.severity==='high'||x.severity==='medium'),newAssets=r.comparison?.new_assets||[],risky=[...r.assets].filter(x=>(x.risk_score||0)>=20).sort((a,b)=>b.risk_score-a.risk_score),shared=r.edges.filter(x=>x.relation.startsWith('shared_'));if(high.length)actions.push(['urgent',`Validate ${high.length} priority finding${high.length===1?'':'s'}`,`Open Findings, confirm the evidence, then reproduce the highest-severity items manually before reporting.`,'findings','Open findings']);if(newAssets.length)actions.push(['review',`Triage ${newAssets.length} new asset${newAssets.length===1?'':'s'}`,`New attack surface is often the best lead. Check ownership, authentication, technology, and whether it was intentionally exposed.`,'assets','Open asset triage']);if(risky.length)actions.push(['review',`Deep inspect ${risky.length} elevated-risk asset${risky.length===1?'':'s'}`,`Automatically collect screenshots, headers, login surfaces, API exposure, TLS and technology evidence for the highest-risk hosts.`,'deep','Run deep inspection']);if(shared.length)actions.push(['',`Pivot through ${shared.length} shared relationship${shared.length===1?'':'s'}`,`Use the relationship map to test whether trust boundaries, shared hosting, certificates, or administrative ownership connect the domains.`,'pivots','Open pivot map']);if(r.errors.length)actions.push(['',`Resolve ${r.errors.length} collection gap${r.errors.length===1?'':'s'}`,`Review Errors before assuming coverage is complete; failed sources can hide subdomains or services.`,'errors','Open collection errors']);actions.push(['',`Build the next hypothesis`,`If no clear finding exists, run an authorized active profile, inspect high-risk assets, then compare the next scan for changes.`,'active','Configure active scan']);$('nextActions').innerHTML=actions.slice(0,5).map((a,i)=>`<div class="action ${a[0]}"><b><span class="step">${i+1}</span>${esc(a[1])}</b><span>${esc(a[2])}</span><button class="actiongo" type="button" data-workflow="${a[3]}">${esc(a[4])} →</button></div>`).join('')}
function assetHost(asset){try{if(asset.kind==='url')return new URL(asset.value).hostname;if(asset.kind==='domain')return asset.value}catch{}return null}
function runWorkflow(action){if(action==='findings')return openTab('findingsPane');if(action==='assets')return openTab('assetsPane');if(action==='errors')return openTab('errorsPane');if(action==='deep'){const risky=[...(lastResult?.assets||[])].filter(x=>(x.risk_score||0)>=20).sort((a,b)=>b.risk_score-a.risk_score);deepHostList=[...new Set(risky.map(assetHost).filter(Boolean))].slice(0,20);if(!deepHostList.length)deepHostList=(lastResult?.targets||[]).slice(0,20);$('deepTargets').innerHTML=deepHostList.map(x=>`<div>${esc(x)}</div>`).join('');$('deepAuthorized').checked=false;$('runDeep').disabled=false;$('deepError').textContent='';$('deepModal').classList.add('open');$('closeDeep').focus();return}if(action==='pivots'){$('connectedOnly').checked=true;if(lastResult)drawGraph(lastResult);document.querySelector('.intel').scrollIntoView({behavior:'smooth',block:'start'});document.querySelector('.graphbox').animate([{boxShadow:'0 0 0 0 rgba(61,219,217,.7)'},{boxShadow:'0 0 0 8px rgba(61,219,217,0)'}],{duration:900});return}if(action==='active'){document.querySelector('.grid').classList.remove('results-mode');$('mode').value='active';$('authorized').required=true;if(lastResult?.targets)$('targets').value=lastResult.targets.join('\n');$('scanForm').scrollIntoView({behavior:'smooth'});$('authorized').focus()}}
function openTab(id){document.querySelectorAll('.tab,.tabpane').forEach(x=>x.classList.remove('active'));const button=document.querySelector(`[data-tab="${id}"]`);if(button)button.classList.add('active');$(id).classList.add('active');$(id).scrollIntoView({behavior:'smooth',block:'start'})}
function renderRelationships(r){lastResult=r;const weight={shared_certificate:100,shared_a:80,shared_aaaa:80,shared_cname:70,shared_mx:45,shared_ns:30};const shared=r.edges.filter(e=>e.relation.startsWith('shared_')).sort((a,b)=>(weight[b.relation]||10)-(weight[a.relation]||10));$('pivotCount').textContent=`${shared.length} DETECTED`;$('pivots').innerHTML=shared.map(e=>`<div class="pivot"><b>${esc(clean(e.source))} ↔ ${esc(clean(e.target))}</b><span>${esc(e.relation.replaceAll('_',' ').toUpperCase())}</span><span>Evidence: ${esc(e.evidence)} · confidence ${Math.round((e.confidence||0)*100)}%</span></div>`).join('')||'<div class="pivot none"><b>No cross-domain pivot detected</b><span>No IP, nameserver, mail exchanger, CNAME, or certificate is currently shared by two supplied roots.</span></div>';renderClusters(r,shared,weight);drawGraph(r)}
function renderClusters(r,shared,weight){const roots=r.targets||[],parent=new Map(roots.map(x=>[x,x]));const find=x=>{while(parent.get(x)!==x){parent.set(x,parent.get(parent.get(x)));x=parent.get(x)}return x};const union=(a,b)=>{a=find(a);b=find(b);if(a!==b)parent.set(b,a)};shared.forEach(e=>union(clean(e.source),clean(e.target)));const groups=new Map();roots.forEach(x=>{const key=find(x);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(x)});const connected=[...groups.values()].filter(x=>x.length>1).map(domains=>({domains,edges:shared.filter(e=>domains.includes(clean(e.source))&&domains.includes(clean(e.target)))})).sort((a,b)=>b.domains.length-a.domains.length);const isolates=roots.filter(x=>!connected.some(g=>g.domains.includes(x)));$('clusterCount').textContent=`${connected.length} GROUPS · ${isolates.length} ISOLATED`;$('clusters').innerHTML=connected.map((g,i)=>{const score=g.edges.reduce((n,e)=>n+(weight[e.relation]||10),0);return `<div class="cluster"><div class="clusterhead"><b>GROUP ${i+1} · ${g.domains.length} DOMAINS</b><span class="score">PIVOT SCORE ${score}</span></div><div class="domains">${g.domains.map(x=>`<span class="domainchip">${esc(x)}</span>`).join('')}</div><small>${g.edges.length} shared infrastructure relationship${g.edges.length===1?'':'s'}</small></div>`}).join('')+(isolates.length?`<div class="cluster isolates"><div class="clusterhead"><b>ISOLATED ROOTS</b><span class="score">${isolates.length}</span></div><div class="domains">${isolates.slice(0,12).map(x=>`<span class="domainchip">${esc(x)}</span>`).join('')}${isolates.length>12?`<span class="domainchip">+${isolates.length-12} more</span>`:''}</div><small>No cross-domain pivot found in this scan.</small></div>`:'')||'<div class="cluster isolates"><b>No roots available</b></div>'}
function drawGraph(r){const allRoots=new Set((r.targets||[]).map(x=>'domain:'+x)),shared=r.edges.filter(e=>e.relation.startsWith('shared_'));let graphEdges=[],rootIds=new Set(),pivotIds=new Set();if($('connectedOnly').checked&&shared.length){shared.forEach((e,i)=>{const pivot=`pivot:${e.relation}:${e.evidence}`,key=pivotIds.has(pivot)?`${pivot}:${i}`:pivot;pivotIds.add(key);rootIds.add(e.source);rootIds.add(e.target);graphEdges.push({source:e.source,target:key,relation:e.relation,evidence:e.evidence,strong:true},{source:key,target:e.target,relation:e.relation,evidence:e.evidence,strong:true})})}else{rootIds=allRoots;graphEdges=r.edges.slice(0,70)}const nodes=[...rootIds,...pivotIds];if(!$('connectedOnly').checked||!shared.length){const seen=new Set(nodes),limit=rootIds.size+18;for(const e of graphEdges)for(const id of[e.source,e.target])if(!seen.has(id)&&nodes.length<limit){seen.add(id);nodes.push(id)}}const positions=new Map(),roots=[...rootIds],inner=nodes.filter(x=>!rootIds.has(x));roots.forEach((id,i)=>{const a=(Math.PI*2*i/Math.max(1,roots.length))-Math.PI/2;positions.set(id,{x:450+350*Math.cos(a),y:210+160*Math.sin(a)})});inner.forEach((id,i)=>{const a=(Math.PI*2*i/Math.max(1,inner.length))-Math.PI/2;positions.set(id,{x:450+165*Math.cos(a),y:210+75*Math.sin(a)})});const edgeSvg=graphEdges.filter(e=>positions.has(e.source)&&positions.has(e.target)).map(e=>{const a=positions.get(e.source),b=positions.get(e.target);return `<line class="graph-edge${e.strong||e.relation.startsWith('shared_')?' strong':''}" data-source="${esc(e.source)}" data-target="${esc(e.target)}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"><title>${esc(e.relation)}: ${esc(e.evidence)}</title></line>`}).join('');const nodeSvg=nodes.map(id=>{const p=positions.get(id),root=rootIds.has(id),pivot=pivotIds.has(id),label=pivot?clean(id).replace(/^shared_/,''):clean(id),short=label.length>35?label.slice(0,32)+'…':label;return `<g class="graph-item" data-node-id="${esc(id)}" role="button" tabindex="0"><circle class="graph-node${root?' root':''}${pivot?' pivotnode':''}" cx="${p.x}" cy="${p.y}" r="${root?11:pivot?10:8}"><title>${esc(id)}</title></circle><text class="graph-label" x="${p.x}" y="${p.y+23}" text-anchor="middle">${esc(short)}</text></g>`}).join('');$('relationshipGraph').innerHTML=`<g id="graphViewport">${edgeSvg}${nodeSvg}</g>`;selectedGraphNode=null;$('graphFocus').textContent='Click a node to isolate its connected component';graphState={x:0,y:0,scale:1};applyGraphTransform()}
function focusGraphNode(id){if(id===selectedGraphNode)id=null;selectedGraphNode=id;const nodes=[...document.querySelectorAll('#relationshipGraph [data-node-id]')],edges=[...document.querySelectorAll('#relationshipGraph [data-source]')];nodes.forEach(x=>x.classList.remove('dim','focus'));edges.forEach(x=>x.classList.remove('dim','focus'));if(!id){$('graphFocus').textContent='Click a node to isolate its connected component';return}const connected=new Set([id]);let changed=true;while(changed){changed=false;for(const edge of edges){const a=edge.dataset.source,b=edge.dataset.target;if(connected.has(a)&&!connected.has(b)){connected.add(b);changed=true}if(connected.has(b)&&!connected.has(a)){connected.add(a);changed=true}}}nodes.forEach(x=>x.classList.add(connected.has(x.dataset.nodeId)?'focus':'dim'));edges.forEach(x=>x.classList.add(connected.has(x.dataset.source)&&connected.has(x.dataset.target)?'focus':'dim'));$('graphFocus').textContent=`Focused: ${clean(id)} · ${connected.size} connected nodes · click again to clear`}
function setGraphZoom(scale){graphState.scale=Math.max(.45,Math.min(3.5,scale));applyGraphTransform()}
function applyGraphTransform(){const viewport=$('graphViewport');if(viewport)viewport.setAttribute('transform',`translate(${graphState.x} ${graphState.y}) scale(${graphState.scale})`)}
function clean(value){return String(value).replace(/^[^:]+:/,'')}
function apiError(data){const detail=data?.detail;if(typeof detail==='string')return detail;if(Array.isArray(detail))return detail.map(item=>{const where=Array.isArray(item.loc)?item.loc.filter(x=>x!=='body').join(' → '):'';return `${where?where+': ':''}${item.msg||JSON.stringify(item)}`}).join(' · ');if(detail&&typeof detail==='object')return detail.message||JSON.stringify(detail);return 'Unable to start scan'}
function details(value){if(!value||!Object.keys(value).length)return '—';return Object.entries(value).map(([k,v])=>`${k}: ${typeof v==='object'?JSON.stringify(v):v}`).join(' · ')}
function esc(s){return String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
async function loadLatest(){try{const response=await fetch('/api/history/latest');if(!response.ok)return;const data=await response.json();$('empty').style.display='none';$('status').classList.add('show');render(data)}catch{}}loadLatest();
async function loadHistory(){try{const response=await fetch('/api/history');if(!response.ok)return;const rows=await response.json();$('history').innerHTML=rows.map(x=>`<tr><td class="code">${esc(x.scan_id)}</td><td>${esc(x.created_at)}</td><td>${x.targets.map(esc).join('<br>')}</td><td>${x.summary.assets}</td><td>${x.summary.findings}</td></tr>`).join('')||'<tr><td colspan="5">No saved scans.</td></tr>'}catch{}}
function renderIntegrationStatus(providers){$('integrationStatus').textContent=providers.map(x=>`${x.name}: ${x.configured?'ready':`set ${x.credential}`}`).join(' · ');$('providerGrid').innerHTML=providers.map(x=>`<div class="provider"><span><b>${esc(x.name)}</b><small> · ${esc(x.mode)}</small></span><strong class="${x.configured?'ready':'missing'}">${x.configured?'CONNECTED':'NOT CONFIGURED'}</strong></div>`).join('')}
async function loadIntegrations(){try{const response=await fetch('/api/integrations');if(!response.ok)return;renderIntegrationStatus(await response.json())}catch{$('integrationStatus').textContent='Provider status unavailable'}}loadIntegrations();
const findingObserver=new MutationObserver(()=>{if(!lastResult?.findings)return;const signature=lastResult.findings.map(f=>`${f.asset}|${f.title}|${f.observed_at}`).join(';');if($('findings').dataset.signature===signature)return;$('findings').dataset.signature=signature;$('findings').innerHTML=lastResult.findings.map(f=>`<tr data-owasp="${esc((f.owasp||[]).join(' '))}"><td class="sev-${esc(f.severity)}">${esc(f.severity).toUpperCase()}</td><td><span class="badge">${esc(f.category)}</span></td><td class="code">${(f.owasp||[]).map(esc).join('<br>')||'—'}</td><td class="code">${esc(f.asset)}</td><td>${esc(f.title)}</td><td>${esc(f.evidence)}</td><td>${esc(f.remediation)}</td></tr>`).join('')||'<tr><td class="emptyrow" colspan="7">No exposure findings recorded.</td></tr>'});findingObserver.observe($('findings'),{childList:true});
</script></body></html>"""
