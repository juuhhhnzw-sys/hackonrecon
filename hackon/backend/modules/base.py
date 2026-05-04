from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Dict, Optional

import logging


@dataclass
class ModuleContext:
    timeout_s: float
    logger: logging.Logger
    max_workers: int
    data: Dict[str, Any]


class BaseModule(abc.ABC):
    """
    Strict contract:
    - subclass must be a class
    - must define: name, description, timeout
    - must implement run(target: str) -> dict returning structured JSON only
    """

    name: str = "base"
    description: str = "Base module"
    timeout: float = 10.0

    def __init__(self, ctx: Optional[ModuleContext] = None) -> None:
        self.ctx = ctx

    @abc.abstractmethod
    def run(self, target: str) -> Dict[str, Any]:
        raise NotImplementedError

