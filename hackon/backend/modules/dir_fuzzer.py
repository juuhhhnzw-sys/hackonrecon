from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from hackon.backend.modules.base import BaseModule


class DirectoryFuzzerModule(BaseModule):
    name = "dir_fuzzer"
    description = "Small path discovery against HTTP(S) hosts"
    timeout = 12.0

    DEFAULT_WORDLIST = ["/admin", "/login", "/dashboard", "/api", "/test"]
    ALLOWED_CODES = {200, 301, 302, 403}

    def _check(self, base_url: str, path: str, timeout_s: float) -> Optional[Dict[str, Any]]:
        url = f"{base_url}{path}"
        try:
            r = requests.get(url, timeout=timeout_s, allow_redirects=False, headers={"User-Agent": "HackOnRecon/1.0"})
            if int(r.status_code) in self.ALLOWED_CODES:
                return {"url": url, "path": path, "status_code": int(r.status_code)}
            return None
        except requests.RequestException:
            return None

    def _base_urls(self) -> List[str]:
        hosts = []
        if self.ctx:
            hosts.append(self.ctx.data.get("target"))
            # Fuzz every generated host (same rationale as http_probe).
            subs = self.ctx.data.get("subdomains_all") or self.ctx.data.get("subdomains_resolved") or []
            for s in subs:
                sd = s.get("subdomain")
                if sd:
                    hosts.append(sd)
        else:
            return []

        seen = set()
        base_urls: List[str] = []
        for h in hosts:
            if not h or h in seen:
                continue
            seen.add(h)
            base_urls.append(f"http://{h}")
            base_urls.append(f"https://{h}")
        return base_urls

    def run(self, target: str) -> Dict[str, Any]:
        logger = self.ctx.logger if self.ctx else None
        timeout_s = float(self.ctx.timeout_s if self.ctx else self.timeout)
        per_request_timeout = max(2.0, min(6.0, timeout_s / 2))
        wordlist = self.DEFAULT_WORDLIST

        base_urls = self._base_urls() or [f"http://{target}", f"https://{target}"]
        jobs: List[Tuple[str, str]] = [(b, p) for b in base_urls for p in wordlist]

        max_workers = min(32, max(1, int(self.ctx.max_workers if self.ctx else 10)))
        results: List[Dict[str, Any]] = []

        if logger:
            logger.info("Fuzzing %d paths across %d base URLs", len(wordlist), len(base_urls))

        with ThreadPoolExecutor(max_workers=min(max_workers, len(jobs) or 1)) as ex:
            futures = {ex.submit(self._check, b, p, per_request_timeout): (b, p) for (b, p) in jobs}
            try:
                for fut in as_completed(futures, timeout=timeout_s):
                    item = fut.result()
                    if item:
                        results.append(item)
            except Exception as e:
                if logger:
                    logger.warning("Dir fuzzer timed/errored: %s", e)

        if logger:
            logger.info("Directory hits: %d", len(results))
        return {"directories": results}

