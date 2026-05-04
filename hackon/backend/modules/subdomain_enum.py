from __future__ import annotations

import socket
from typing import Any, Dict, List

from hackon.backend.modules.base import BaseModule


class SubdomainEnumModule(BaseModule):
    name = "subdomain_enum"
    description = "Passive subdomain enumeration using common prefixes"
    timeout = 8.0

    PREFIXES = ["www", "dev", "api", "test"]

    def _resolve(self, fqdn: str) -> Dict[str, Any]:
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "resolved": True, "ip": ip}
        except OSError:
            return {"subdomain": fqdn, "resolved": False, "ip": None}

    def run(self, target: str) -> Dict[str, Any]:
        logger = self.ctx.logger if self.ctx else None
        subs: List[Dict[str, Any]] = []

        # Passive "generate likely names" (no brute force / wordlist).
        for p in self.PREFIXES:
            fqdn = f"{p}.{target}"
            subs.append(self._resolve(fqdn))

        resolved = [s for s in subs if s.get("resolved")]
        if logger:
            logger.info("Generated subdomains: %s", [s["subdomain"] for s in subs])
            logger.info("DNS-resolved: %s", [s["subdomain"] for s in resolved])

        return {"subdomains": subs}

