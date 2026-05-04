from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _md_list(items: List[str]) -> str:
    if not items:
        return "_None_"
    return "\n".join([f"- {x}" for x in items])


class ReportGenerator:
    def generate_markdown(self, normalized: Dict[str, Any], overall_risk: int) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        target = normalized.get("target", "")

        ports = normalized.get("ports", []) or []
        http = normalized.get("http", []) or []
        dirs = normalized.get("directories", []) or []
        subs = normalized.get("subdomains", []) or []
        findings = normalized.get("findings", []) or []

        open_ports = [f'{p.get("port")} ({p.get("service_guess")})' for p in ports]
        endpoints = [f'{d.get("path")} — {d.get("status_code")} ({d.get("url")})' for d in dirs]
        sublines = []
        for s in subs:
            sd = s.get("subdomain")
            if s.get("resolved"):
                sublines.append(f'{sd} → {s.get("ip")}')
            else:
                sublines.append(f"{sd} (unresolved)")

        risk_lines = [
            f'**{f.get("severity")}** — score `{f.get("risk_score")}` — `{f.get("type")}` `{f.get("value")}` — {f.get("reason")}'
            for f in findings
        ]

        high_priority = [
            f'`{f.get("type")}` `{f.get("value")}` ({f.get("severity")} / {f.get("risk_score")})'
            for f in findings
            if f.get("severity") in ("HIGH", "EXTREME")
        ]

        recommendations = [
            "Restrict or remove public access to administrative endpoints (`/admin`, `/login`) where possible.",
            "Harden access controls and validate authorization logic for endpoints returning `403`.",
            "Close or firewall uncommon service ports (e.g. 3306/MySQL, 6379/Redis) from the public internet.",
            "Reduce fingerprinting by minimizing unnecessary server banner exposure (where feasible).",
            "Review subdomain inventory and apply consistent TLS, auth, and monitoring across environments (dev/test/api).",
        ]

        # NOTE: Keep headings exactly as required.
        return "\n".join(
            [
                "# HackOn Recon Report",
                "",
                f"_Generated: {ts}_",
                "",
                "## Target",
                "",
                f"- `{target}`",
                "",
                "## Open Ports",
                "",
                _md_list(open_ports),
                "",
                "## Discovered Endpoints",
                "",
                _md_list(endpoints),
                "",
                "## Subdomains",
                "",
                _md_list(sublines),
                "",
                "## Risk Analysis",
                "",
                f"- **Overall risk score**: `{overall_risk}` / `100`",
                "",
                _md_list(risk_lines),
                "",
                "## High Priority Targets",
                "",
                _md_list(high_priority),
                "",
                "## Recommendations",
                "",
                _md_list(recommendations),
                "",
            ]
        )

