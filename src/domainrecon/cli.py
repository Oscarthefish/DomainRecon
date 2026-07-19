from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .collectors import ProbeOptions
from .engine import ReconEngine
from .report import write_reports
from .scope import Scope
from .store import Store

app = typer.Typer(
    no_args_is_help=True, help="Scope-aware domain reconnaissance and relationship mapping."
)
console = Console()


@app.command()
def scan(
    targets: Annotated[list[str], typer.Argument(help="One or more root domains")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("recon-output"),
    exclude: Annotated[list[str] | None, typer.Option("--exclude")] = None,
    passive: Annotated[
        bool, typer.Option("--passive", help="Use public data and DNS only")
    ] = False,
    authorized: Annotated[
        bool, typer.Option("--authorized", help="Confirm authorization for direct HTTP/TLS probes")
    ] = False,
    max_hosts: Annotated[int, typer.Option(min=1, max=5000)] = 250,
    concurrency: Annotated[int, typer.Option(min=1, max=100)] = 20,
    timeout: Annotated[float, typer.Option(min=1, max=60)] = 8.0,
    allow_private: Annotated[
        bool, typer.Option(help="Permit RFC1918/internal targets (requires --authorized)")
    ] = False,
    enumerate_buckets: Annotated[
        bool, typer.Option("--enumerate-buckets", help="Probe cloud storage bucket name candidates (requires --authorized)")
    ] = False,
    deep_js: Annotated[
        bool, typer.Option("--deep-js", help="Fetch and analyze JavaScript files for endpoints and secrets (requires --authorized)")
    ] = False,
) -> None:
    """Discover and map assets. Direct probes require --authorized."""
    if not passive and not authorized:
        raise typer.BadParameter("active mode requires --authorized; otherwise use --passive")
    if allow_private and not authorized:
        raise typer.BadParameter("--allow-private requires --authorized")
    if enumerate_buckets and not authorized:
        raise typer.BadParameter("--enumerate-buckets requires --authorized")
    if deep_js and not authorized:
        raise typer.BadParameter("--deep-js requires --authorized")
    try:
        scope = Scope.build(targets, exclude)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    options = ProbeOptions(timeout=timeout, concurrency=concurrency, allow_private=allow_private, enumerate_buckets=enumerate_buckets, deep_js=deep_js)
    result = asyncio.run(ReconEngine(scope, options).run(passive_only=passive, max_hosts=max_hosts))
    write_reports(result, output)
    with Store(output / "domainrecon.sqlite3") as store:
        store.save(result)
    table = Table(title=f"Scan {result.scan_id}")
    table.add_column("Assets")
    table.add_column("Connections")
    table.add_column("Findings")
    table.add_column("Errors")
    table.add_row(
        str(len(result.assets)),
        str(len(result.edges)),
        str(len(result.findings)),
        str(len(result.errors)),
    )
    console.print(table)
    console.print(f"Reports: [bold]{output.resolve()}[/bold]")


@app.command()
def latest(
    database: Annotated[Path, typer.Argument()] = Path("recon-output/domainrecon.sqlite3"),
) -> None:
    """Print the most recently persisted scan as JSON."""
    with Store(database) as store:
        data = store.latest()
    if data is None:
        raise typer.Exit(1)
    console.print_json(json.dumps(data))


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Listening address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8765,
) -> None:
    """Start the local HTML interface."""
    import uvicorn

    console.print(f"DomainRecon UI: [bold]http://{host}:{port}[/bold]")
    uvicorn.run("domainrecon.web:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
