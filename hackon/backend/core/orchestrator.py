from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Type

from hackon.backend.analyzer.risk_engine import RiskEngine
from hackon.backend.modules.base import BaseModule, ModuleContext
from hackon.backend.modules.dir_fuzzer import DirectoryFuzzerModule
from hackon.backend.modules.http_probe import HttpProbeModule
from hackon.backend.modules.port_scanner import PortScannerModule
from hackon.backend.modules.subdomain_enum import SubdomainEnumModule
from hackon.backend.report.generator import ReportGenerator
from hackon.backend.utils.logging import module_logger
from hackon.backend.utils.schema import empty_normalized
from hackon.backend.utils.time import Timer


class Orchestrator:
    def __init__(
        self,
        max_workers: int = 6,
        default_timeout_s: float = 12.0,
        scans_dir: str = "scans",
        reports_dir: str = "reports",
    ) -> None:
        self.max_workers = max(1, int(max_workers))
        self.default_timeout_s = float(default_timeout_s)
        self.scans_dir = scans_dir
        self.reports_dir = reports_dir

    def _run_module(
        self,
        module_cls: Type[BaseModule],
        target: str,
        shared: Dict[str, Any],
        timeout_override: Optional[float] = None,
    ) -> Tuple[str, Dict[str, Any], Optional[str], int]:
        """
        Returns: (module_name, output_dict, error_string, elapsed_ms)
        """
        logger = module_logger(module_cls.name, logs_dir=self.scans_dir)
        timeout_s = float(timeout_override if timeout_override is not None else getattr(module_cls, "timeout", self.default_timeout_s))
        ctx = ModuleContext(timeout_s=timeout_s, logger=logger, max_workers=self.max_workers, data=shared)
        module = module_cls(ctx=ctx)

        t = Timer.start_now()
        try:
            logger.info("Starting module (timeout=%.2fs)", timeout_s)
            out = module.run(target)
            if not isinstance(out, dict):
                raise TypeError("Module returned non-dict output")
            logger.info("Completed module in %dms", t.elapsed_ms())
            return module_cls.name, out, None, t.elapsed_ms()
        except Exception as e:
            logger.exception("Module failed: %s", e)
            return module_cls.name, {}, str(e), t.elapsed_ms()

    def _merge(self, normalized: Dict[str, Any], module_out: Dict[str, Any]) -> None:
        for key in ("ports", "http", "directories", "subdomains"):
            if key in module_out and isinstance(module_out[key], list):
                normalized[key].extend(module_out[key])

    def run(self, target: str) -> Dict[str, Any]:
        os.makedirs(self.scans_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        normalized = empty_normalized(target)

        # Shared data passed between phases (to satisfy "http probe for target and discovered subdomains")
        shared: Dict[str, Any] = {"target": target}

        # Phase 1: run independent discovery in parallel
        phase1: List[Type[BaseModule]] = [PortScannerModule, SubdomainEnumModule]

        results: Dict[str, Dict[str, Any]] = {}
        errors: Dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(phase1))) as ex:
            futs: Dict[Any, Tuple[str, float]] = {}
            for m in phase1:
                tmo = float(getattr(m, "timeout", self.default_timeout_s))
                futs[ex.submit(self._run_module, m, target, shared, None)] = (m.name, tmo)
            for f, (mname, tmo) in futs.items():
                try:
                    name, out, err, _ms = f.result(timeout=tmo)
                    results[name] = out
                    if err:
                        errors[name] = err
                except TimeoutError:
                    errors[mname] = f"Timed out after {tmo:.2f}s"

        for out in results.values():
            self._merge(normalized, out)

        # Update shared with subdomain results for Phase 2 consumption
        sub_all = results.get(SubdomainEnumModule.name, {}).get("subdomains", []) if results else []
        sub_resolved = [s for s in (sub_all or []) if s.get("resolved")]
        shared["subdomains_all"] = sub_all or []
        shared["subdomains_resolved"] = sub_resolved or []

        # Phase 2: probe/fuzz in parallel (consumes shared subdomain list)
        phase2: List[Type[BaseModule]] = [HttpProbeModule, DirectoryFuzzerModule]
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(phase2))) as ex:
            futs: Dict[Any, Tuple[str, float]] = {}
            for m in phase2:
                tmo = float(getattr(m, "timeout", self.default_timeout_s))
                futs[ex.submit(self._run_module, m, target, shared, None)] = (m.name, tmo)
            for f, (mname, tmo) in futs.items():
                try:
                    name, out, err, _ms = f.result(timeout=tmo)
                    results[name] = out
                    if err:
                        errors[name] = err
                except TimeoutError:
                    errors[mname] = f"Timed out after {tmo:.2f}s"

        for out in (results.get(HttpProbeModule.name, {}), results.get(DirectoryFuzzerModule.name, {})):
            self._merge(normalized, out)

        # Risk analysis
        engine = RiskEngine()
        overall, findings = engine.analyze(normalized)
        normalized["findings"] = findings
        normalized["overall_risk"] = overall

        if errors:
            normalized["module_errors"] = errors

        # Persist outputs
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        json_path = os.path.join(self.scans_dir, f"{ts}.{target}.json".replace(":", "_"))
        md_path = os.path.join(self.reports_dir, f"{ts}.{target}.md".replace(":", "_"))

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2, ensure_ascii=False)

        md = ReportGenerator().generate_markdown(normalized, overall_risk=overall)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)

        normalized["artifacts"] = {"json": json_path, "markdown": md_path}
        return normalized

