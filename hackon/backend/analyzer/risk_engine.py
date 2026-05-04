from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


def severity_label(score: int) -> str:
    if score <= 20:
        return "SAFE"
    if score <= 40:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 80:
        return "HIGH"
    return "EXTREME"


@dataclass(frozen=True)
class FindingTrigger:
    points: int
    ftype: str
    value: str
    reason: str


class RiskEngine:
    """
    Implements the strict scoring rules from the prompt.

    Rules (additive; cap at 100):
    +30 → /admin or /login exposed
    +25 → status 403 (possible bypass)
    +20 → uncommon open port (3306, 6379)
    +15 → multiple subdomains
    +10 → HTTP server header exposed
    +20 → sensitive keyword in URL (api, dev, test)
    """

    ADMIN_PATHS = {"/admin", "/login"}
    SENSITIVE_KEYWORDS = ("api", "dev", "test")
    UNCOMMON_PORTS = {3306, 6379}

    def analyze(self, normalized: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
        triggers: List[FindingTrigger] = []

        # Directories / endpoints
        for d in normalized.get("directories", []) or []:
            path = (d.get("path") or "").strip()
            url = (d.get("url") or "").strip()
            status = d.get("status_code")

            if path in self.ADMIN_PATHS:
                triggers.append(
                    FindingTrigger(
                        points=30,
                        ftype="endpoint",
                        value=path,
                        reason=f"Sensitive endpoint exposed: {path}",
                    )
                )

            if status == 403:
                triggers.append(
                    FindingTrigger(
                        points=25,
                        ftype="endpoint",
                        value=url or path or "unknown",
                        reason="Received 403 (possible access control bypass potential)",
                    )
                )

            low = (url or path).lower()
            if any(k in low for k in self.SENSITIVE_KEYWORDS):
                triggers.append(
                    FindingTrigger(
                        points=20,
                        ftype="endpoint",
                        value=url or path,
                        reason="Sensitive keyword detected in URL/path (api/dev/test)",
                    )
                )

        # Open ports
        for p in normalized.get("ports", []) or []:
            port = p.get("port")
            if port in self.UNCOMMON_PORTS:
                triggers.append(
                    FindingTrigger(
                        points=20,
                        ftype="port",
                        value=str(port),
                        reason=f"Uncommon service port open: {port}",
                    )
                )

        # Subdomains (count)
        subs = normalized.get("subdomains", []) or []
        resolved = [s for s in subs if s.get("resolved")]
        if len(resolved) >= 2:
            triggers.append(
                FindingTrigger(
                    points=15,
                    ftype="subdomain",
                    value=str(len(resolved)),
                    reason=f"Multiple subdomains resolved ({len(resolved)}) increases attack surface",
                )
            )

        # HTTP headers
        for h in normalized.get("http", []) or []:
            server = h.get("server")
            if server:
                triggers.append(
                    FindingTrigger(
                        points=10,
                        ftype="header",
                        value=str(server),
                        reason="HTTP Server header exposed (fingerprinting signal)",
                    )
                )

            url = (h.get("url") or "").lower()
            if any(k in url for k in self.SENSITIVE_KEYWORDS):
                triggers.append(
                    FindingTrigger(
                        points=20,
                        ftype="endpoint",
                        value=h.get("url") or "",
                        reason="Sensitive keyword detected in URL (api/dev/test)",
                    )
                )

        # Convert triggers -> findings while keeping a running total (cap 100)
        findings: List[Dict[str, Any]] = []
        total = 0
        for t in triggers:
            total = min(100, total + int(t.points))
            findings.append(
                {
                    "type": t.ftype,
                    "value": t.value,
                    "risk_score": int(total),
                    "severity": severity_label(int(total)),
                    "reason": t.reason,
                }
            )

        return int(total), findings

