from __future__ import annotations

"""
Educational use only disclaimer:
This project is for defensive/educational use. It does not provide guarantees and
should not be used as the sole basis for security decisions.
"""

import fnmatch
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_WHITELIST_PATH = os.path.join(PROJECT_ROOT, "whitelist.json")
DISCLAIMER_NOTE = "Educational use only"


@dataclass(frozen=True)
class WhitelistMatch:
    """Represents a whitelist match for debugging/UI display."""

    matched_by: str  # "name" or "path"
    pattern: str


def _normalize(s: str) -> str:
    return (s or "").strip()


def _load_whitelist_file(path: str = DEFAULT_WHITELIST_PATH) -> Dict[str, List[str]]:
    """
    Load whitelist JSON.

    Expected shape:
      - trusted_processes: list[str]
      - trusted_paths: list[str]
    """
    try:
        if not os.path.exists(path):
            return {"trusted_processes": [], "trusted_paths": []}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "trusted_processes": list(data.get("trusted_processes") or []),
            "trusted_paths": list(data.get("trusted_paths") or []),
        }
    except Exception:
        # Keep defensive scanning robust; whitelist failures shouldn't crash scans.
        return {"trusted_processes": [], "trusted_paths": []}


def _save_whitelist_file(data: Dict[str, List[str]], path: str = DEFAULT_WHITELIST_PATH) -> None:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        # Do not raise; GUI/CLI should keep running.
        pass


def is_whitelisted(name: str, path: Optional[str] = None, whitelist_path: str = DEFAULT_WHITELIST_PATH) -> Tuple[bool, Optional[WhitelistMatch]]:
    """
    Check whether an item is whitelisted based on trusted_processes and trusted_paths.

    Wildcards are supported in both lists using `fnmatch`.
    """
    data = _load_whitelist_file(whitelist_path)
    name_n = _normalize(name).lower()
    path_n = _normalize(path or "").lower()

    for pat in data.get("trusted_processes") or []:
        pat_n = _normalize(pat).lower()
        if pat_n and fnmatch.fnmatchcase(name_n, pat_n):
            return True, WhitelistMatch(matched_by="name", pattern=pat)

    if path_n:
        for pat in data.get("trusted_paths") or []:
            pat_n = _normalize(pat).lower()
            if pat_n and fnmatch.fnmatchcase(path_n, pat_n):
                return True, WhitelistMatch(matched_by="path", pattern=pat)

    return False, None


def add_to_whitelist(
    *,
    process_name: Optional[str] = None,
    path_pattern: Optional[str] = None,
    whitelist_path: str = DEFAULT_WHITELIST_PATH,
) -> Tuple[bool, str]:
    """
    Add user-supplied patterns to the whitelist.

    Args:
      process_name: a process executable filename pattern (supports wildcards)
      path_pattern: a full path or glob pattern (supports wildcards)

    Returns:
      (added, message)
    """
    process_name_n = _normalize(process_name or "")
    path_pattern_n = _normalize(path_pattern or "")

    if not process_name_n and not path_pattern_n:
        return False, "No whitelist value provided."

    data = _load_whitelist_file(whitelist_path)
    changed = False

    if process_name_n:
        if process_name_n not in data.get("trusted_processes") or []:
            data.setdefault("trusted_processes", []).append(process_name_n)
            changed = True

    if path_pattern_n:
        if path_pattern_n not in data.get("trusted_paths") or []:
            data.setdefault("trusted_paths", []).append(path_pattern_n)
            changed = True

    if changed:
        _save_whitelist_file(data, whitelist_path)
        return True, "Whitelist updated."

    return False, "Whitelist already contained these patterns."

