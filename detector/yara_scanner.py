from __future__ import annotations

"""
Educational use only disclaimer:
YARA signatures and matches are heuristic indicators and may produce false positives
or false negatives. Use for defensive/educational purposes only.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None  # type: ignore


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_RULES_DIR = os.path.join(PROJECT_ROOT, "rules")


def _discover_rule_files(rules_dir: str = DEFAULT_RULES_DIR) -> List[str]:
    if not os.path.isdir(rules_dir):
        return []
    files: List[str] = []
    for name in os.listdir(rules_dir):
        if name.lower().endswith(".yar"):
            files.append(os.path.join(rules_dir, name))
    files.sort()
    return files


def _severity_from_meta(meta: Dict[str, Any]) -> Optional[str]:
    sev = meta.get("severity")
    if not sev:
        return None
    sev_s = str(sev).upper()
    if sev_s in {"HIGH", "MEDIUM"}:
        return sev_s
    return None


@dataclass
class YaraScanner:
    """
    Loads and runs YARA rules from `rules/`.
    """

    rules_dir: str = DEFAULT_RULES_DIR
    timeout_s: int = 10

    def __post_init__(self) -> None:
        self._rulesets: List[Any] = []
        self._rule_files = _discover_rule_files(self.rules_dir)
        if yara is None:
            return

        if not self._rule_files:
            return

        # `yara-python` expects `filepath=` for a single source. We compile each
        # rule file separately and aggregate matches at scan-time.
        for rule_file in self._rule_files:
            try:
                rs = yara.compile(filepath=rule_file)
                self._rulesets.append(rs)
            except Exception:
                continue

    def is_ready(self) -> bool:
        return len(self._rulesets) > 0

    def scan_path(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file path and return:
          - yara_severity: "HIGH"/"MEDIUM"/None
          - yara_matches: list[str] rule names
        """
        if not file_path or not os.path.isfile(file_path) or not self._rulesets:
            return {"yara_severity": None, "yara_matches": []}

        try:
            matches = []
            for rs in self._rulesets:
                try:
                    matches.extend(rs.match(file_path, timeout=self.timeout_s))
                except Exception:
                    continue
        except Exception:
            return {"yara_severity": None, "yara_matches": []}

        matched_names: List[str] = []
        severities: List[str] = []

        for m in matches:
            try:
                rule_name = getattr(m, "rule", None) or ""
                if rule_name:
                    matched_names.append(str(rule_name))
                sev = getattr(m, "meta", {}) or {}
                sev_s = _severity_from_meta(sev)  # type: ignore[arg-type]
                if sev_s:
                    severities.append(sev_s)
            except Exception:
                continue

        if any(s == "HIGH" for s in severities):
            return {"yara_severity": "HIGH", "yara_matches": matched_names}
        if any(s == "MEDIUM" for s in severities):
            return {"yara_severity": "MEDIUM", "yara_matches": matched_names}
        return {"yara_severity": None, "yara_matches": matched_names}


def scan_paths(paths: List[str], scanner: Optional[YaraScanner] = None) -> Dict[str, Dict[str, Any]]:
    """
    Convenience function: scan many paths, returning a mapping by path.
    """
    sc = scanner or YaraScanner()
    results: Dict[str, Dict[str, Any]] = {}
    for p in paths:
        results[p] = sc.scan_path(p)
    return results

