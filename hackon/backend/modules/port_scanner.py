from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from typing import Any, Dict, List

from hackon.backend.modules.base import BaseModule
from hackon.backend.utils.net import guess_service


class PortScannerModule(BaseModule):
    name = "port_scanner"
    description = "TCP connect scan on common ports"
    timeout = 8.0

    PORTS = [21, 22, 80, 443, 8080, 3306, 6379]

    def _check_port(self, host: str, port: int, per_port_timeout: float) -> Dict[str, Any]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(per_port_timeout)
        try:
            result = s.connect_ex((host, port))
            if result == 0:
                return {"port": port, "status": "open", "service_guess": guess_service(port)}
            return {"port": port, "status": "closed", "service_guess": guess_service(port)}
        except OSError as e:
            return {"port": port, "status": "error", "service_guess": guess_service(port), "error": str(e)}
        finally:
            try:
                s.close()
            except Exception:
                pass

    def run(self, target: str) -> Dict[str, Any]:
        logger = self.ctx.logger if self.ctx else None
        timeout_s = float(self.ctx.timeout_s if self.ctx else self.timeout)
        per_port_timeout = max(0.5, min(2.0, timeout_s / 4))

        max_workers = min(32, max(1, int(self.ctx.max_workers if self.ctx else 10)))
        ports: List[Dict[str, Any]] = []

        if logger:
            logger.info("Scanning %d ports (per_port_timeout=%.2fs)", len(self.PORTS), per_port_timeout)

        with ThreadPoolExecutor(max_workers=min(max_workers, len(self.PORTS))) as ex:
            futures = {ex.submit(self._check_port, target, p, per_port_timeout): p for p in self.PORTS}
            try:
                for fut in as_completed(futures, timeout=timeout_s):
                    ports.append(fut.result())
            except TimeoutError:
                if logger:
                    logger.warning("Port scan exceeded timeout; returning partial results")

        open_ports = [p for p in ports if p.get("status") == "open"]
        if logger:
            logger.info("Open ports: %s", [p["port"] for p in open_ports])

        return {"ports": open_ports}

