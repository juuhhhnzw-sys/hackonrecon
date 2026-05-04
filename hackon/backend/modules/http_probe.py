from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests

from hackon.backend.modules.base import BaseModule


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", flags=re.IGNORECASE | re.DOTALL)


class HttpProbeModule(BaseModule):
    name = "http_probe"
    description = "HTTP GET probe to capture status/title/headers/server"
    timeout = 12.0

    def _probe_one(self, url: str, timeout_s: float) -> Optional[Dict[str, Any]]:
        try:
            r = requests.get(url, timeout=timeout_s, allow_redirects=True, headers={"User-Agent": "HackOnRecon/1.0"})
            body = r.text or ""
            title = None
            m = _TITLE_RE.search(body)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None
            headers = dict(r.headers)
            server = headers.get("Server") or headers.get("server")
            return {
                "url": url,
                "status_code": int(r.status_code),
                "title": title,
                "headers": headers,
                "server": server,
            }
        except requests.RequestException:
            return None

    def _candidate_urls(self, host: str) -> List[str]:
        # Probe both http and https.
        return [f"http://{host}", f"https://{host}"]

    def run(self, target: str) -> Dict[str, Any]:
        logger = self.ctx.logger if self.ctx else None
        timeout_s = float(self.ctx.timeout_s if self.ctx else self.timeout)
        per_request_timeout = max(2.0, min(6.0, timeout_s / 2))

        hosts = [target]
        # Use ALL generated subdomains (passive list), not only DNS-resolved ones.
        # Many hosts answer on HTTP even when A-record check failed from this resolver;
        # skipping non-resolved hosts incorrectly limited scans to e.g. only www.*.
        if self.ctx:
            subs = self.ctx.data.get("subdomains_all") or self.ctx.data.get("subdomains_resolved") or []
            for s in subs:
                sd = s.get("subdomain")
                if sd and sd not in hosts:
                    hosts.append(sd)

        urls: List[str] = []
        for h in hosts:
            urls.extend(self._candidate_urls(h))

        max_workers = min(32, max(1, int(self.ctx.max_workers if self.ctx else 10)))
        results: List[Dict[str, Any]] = []

        if logger:
            logger.info("Probing %d URLs (timeout=%.2fs)", len(urls), per_request_timeout)

        with ThreadPoolExecutor(max_workers=min(max_workers, len(urls) or 1)) as ex:
            futures = {ex.submit(self._probe_one, u, per_request_timeout): u for u in urls}
            try:
                for fut in as_completed(futures, timeout=timeout_s):
                    item = fut.result()
                    if item:
                        results.append(item)
            except Exception as e:
                if logger:
                    logger.warning("HTTP probe timed/errored: %s", e)

        if logger:
            logger.info("HTTP results: %d", len(results))
        return {"http": results}

