from __future__ import annotations

from typing import Any, Dict, List


def empty_normalized(target: str) -> Dict[str, Any]:
    return {
        "target": target,
        "ports": [],
        "http": [],
        "directories": [],
        "subdomains": [],
        "findings": [],
    }


def ensure_list(obj: Any) -> List[Any]:
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    return [obj]

