from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hackon.backend.core.orchestrator import Orchestrator
from hackon.backend.utils.logging import setup_root_logging
from hackon.backend.utils.net import normalize_target


def _severity_color(sev: str) -> str:
    return {
        "SAFE": "green",
        "LOW": "cyan",
        "MEDIUM": "yellow",
        "HIGH": "orange3",
        "EXTREME": "red",
    }.get(sev, "white")


def render_cli_summary(result: Dict[str, Any]) -> None:
    console = Console()
    target = result.get("target", "")
    overall = int(result.get("overall_risk") or 0)

    console.print(Panel.fit(f"[bold]HackOn Recon[/bold]\nTarget: [bold]{target}[/bold]\nOverall risk: [bold]{overall}[/bold]/100"))

    # Ports
    ports = result.get("ports", []) or []
    t_ports = Table(title="Open Ports")
    t_ports.add_column("Port", justify="right")
    t_ports.add_column("Service")
    for p in ports:
        t_ports.add_row(str(p.get("port")), str(p.get("service_guess") or ""))
    console.print(t_ports)

    # HTTP
    http = result.get("http", []) or []
    t_http = Table(title="HTTP Probes")
    t_http.add_column("URL")
    t_http.add_column("Status", justify="right")
    t_http.add_column("Title")
    t_http.add_column("Server")
    for h in http[:20]:
        t_http.add_row(
            str(h.get("url")),
            str(h.get("status_code")),
            str(h.get("title") or ""),
            str(h.get("server") or ""),
        )
    console.print(t_http)

    # Directories
    dirs = result.get("directories", []) or []
    t_dirs = Table(title="Discovered Endpoints")
    t_dirs.add_column("Path")
    t_dirs.add_column("Status", justify="right")
    t_dirs.add_column("URL")
    for d in dirs[:30]:
        t_dirs.add_row(str(d.get("path")), str(d.get("status_code")), str(d.get("url")))
    console.print(t_dirs)

    # Subdomains
    subs = result.get("subdomains", []) or []
    t_subs = Table(title="Subdomains")
    t_subs.add_column("Subdomain")
    t_subs.add_column("Resolved")
    t_subs.add_column("IP")
    for s in subs:
        t_subs.add_row(str(s.get("subdomain")), str(bool(s.get("resolved"))), str(s.get("ip") or ""))
    console.print(t_subs)

    # Findings
    findings = result.get("findings", []) or []
    t_find = Table(title="Risk Findings")
    t_find.add_column("Severity")
    t_find.add_column("Score", justify="right")
    t_find.add_column("Type")
    t_find.add_column("Value")
    t_find.add_column("Reason")
    for f in findings[:30]:
        sev = str(f.get("severity"))
        score = str(f.get("risk_score"))
        sev_txt = Text(sev, style=_severity_color(sev))
        t_find.add_row(sev_txt, score, str(f.get("type")), str(f.get("value")), str(f.get("reason")))
    console.print(t_find)

    # Artifacts
    artifacts = result.get("artifacts") or {}
    if artifacts:
        console.print(Panel.fit(f"JSON: [bold]{artifacts.get('json','')}[/bold]\nMarkdown: [bold]{artifacts.get('markdown','')}[/bold]"))

    # Module errors (if any)
    if result.get("module_errors"):
        console.print(Panel.fit(json.dumps(result["module_errors"], indent=2), title="Module errors", style="yellow"))


def main(argv: Any = None) -> int:
    p = argparse.ArgumentParser(prog="hackon-recon", description="HackOn Recon — authorized recon & insight")
    p.add_argument("target", help="Domain or IP (no scheme required), e.g. example.com or 1.2.3.4")
    p.add_argument("--max-workers", type=int, default=6, help="Maximum parallel workers")
    p.add_argument("--timeout", type=float, default=12.0, help="Default timeout per module (seconds)")
    p.add_argument("--log-level", default="INFO", help="Logging level (INFO, DEBUG, ...)")
    args = p.parse_args(argv)

    setup_root_logging(args.log_level)
    target = normalize_target(args.target)

    orch = Orchestrator(max_workers=args.max_workers, default_timeout_s=args.timeout)
    result = orch.run(target)
    render_cli_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

