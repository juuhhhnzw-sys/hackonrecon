from __future__ import annotations

import re
import socket
from typing import Optional


_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_ip(target: str) -> bool:
    if not _IPV4_RE.match(target.strip()):
        return False
    try:
        socket.inet_aton(target.strip())
        return True
    except OSError:
        return False


def normalize_target(target: str) -> str:
    t = target.strip()
    t = re.sub(r"^https?://", "", t, flags=re.IGNORECASE)
    t = t.strip().strip("/")
    return t


def try_resolve(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def guess_service(port: int) -> str:
    return {
        21: "ftp",
        22: "ssh",
        80: "http",
        443: "https",
        8080: "http-alt",
        3306: "mysql",
        6379: "redis",
    }.get(port, "unknown")

