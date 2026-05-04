from __future__ import annotations

import logging
import os
from datetime import datetime, timezone


def setup_root_logging(level: str = "INFO") -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def module_logger(module_name: str, logs_dir: str = "scans") -> logging.Logger:
    """
    Creates a per-module logger that logs to console (root handler) and to a dedicated file.
    """
    logger = logging.getLogger(f"hackon.module.{module_name}")
    logger.propagate = True

    os.makedirs(logs_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filepath = os.path.join(logs_dir, f"{ts}.{module_name}.log")

    # Avoid duplicate handlers if called multiple times
    for h in list(logger.handlers):
        if isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == os.path.abspath(filepath):
            return logger

    file_handler = logging.FileHandler(filepath, encoding="utf-8")
    file_handler.setLevel(logger.level or logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s :: %(message)s"))
    logger.addHandler(file_handler)
    return logger

