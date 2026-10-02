from __future__ import annotations

"""
Educational use only disclaimer:
This project is for defensive/educational use only. The scoring logic is heuristic
and may produce false positives/false negatives.
"""

from typing import Any, Dict, List, Tuple

from detector.whitelist import is_whitelisted


_KEYLOGGER_NAME_PATTERNS = [
    "keylogger",
    "keylog",
    "keyboardhook",
    "keyboard_hook",
    "inputlogger",
    "hooklogger",
    "keystroke",
    "setwindowshookex",
    "journal",
]


def _is_temp_or_appdata_path(path: str, full_reason: str = "") -> bool:
    if not path:
        # Unknown/empty paths can come from registry parsing; treat as "unknown startup path"
        # but for scoring rules we only award the temp/appdata bucket when we can see markers.
        return False

    p = (path or "").lower()
    r = (full_reason or "").lower()

    markers = [
        r"\temp",
        r"\tmp",
        r"%temp%",
        r"\appdata",
        r"\local\appdata",
        r"\roaming\appdata",
        r"%appdata%",
        r"%localappdata%",
    ]

    return any(m in p for m in markers) or any(m in r for m in markers)


def _score_item(item: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Score an individual flagged item based on its available fields.

    Rules:
    - +2 for keyboard hook
    - +2 for temp/appdata path
    - +1 for no visible window
    - +1 for suspicious name
    """

    score = 0
    reasons: List[str] = []

    name = str(item.get("name") or "")
    path = str(item.get("path") or "")
    reason_text = str(item.get("reason") or "")

    # Keyboard hook: hook_detect returns hook_type; some future items may use status/type.
    if "hook_type" in item or str(item.get("type") or "") in {"keyboard_hook", "keyboardhook"}:
        score += 2
        reasons.append("keyboard hook indicator (+2)")

    # Temp/appdata path:
    # - process_scan includes markers in its "reason"
    # - registry_scan sets `suspicious=True` for temp/appdata/unknown locations
    if bool(item.get("suspicious")) or _is_temp_or_appdata_path(path, reason_text):
        score += 2
        reasons.append("temp/appdata/unknown startup path (+2)")

    # No visible window heuristic from process_scan.
    if "no visible window" in reason_text.lower() or "top-level windows" in reason_text.lower():
        score += 1
        reasons.append("no visible window (+1)")

    # Suspicious name heuristic: process_scan reason includes keylogger patterns,
    # but we also match name directly as a fallback.
    name_l = name.lower()
    if any(pat in name_l for pat in _KEYLOGGER_NAME_PATTERNS) or "keylogger pattern" in reason_text.lower():
        score += 1
        reasons.append("suspicious name (+1)")

    # VirusTotal scoring: +3 for MALICIOUS, +1 for SUSPICIOUS.
    vt_verdict = str(item.get("vt_verdict") or "").upper()
    if vt_verdict == "MALICIOUS":
        score += 3
        reasons.append("VT verdict MALICIOUS (+3)")
    elif vt_verdict == "SUSPICIOUS":
        score += 1
        reasons.append("VT verdict SUSPICIOUS (+1)")

    # YARA scoring: +3 for HIGH, +1 for MEDIUM.
    yara_sev = str(item.get("yara_severity") or "").upper()
    if yara_sev == "HIGH":
        score += 3
        reasons.append("YARA match HIGH (+3)")
    elif yara_sev == "MEDIUM":
        score += 1
        reasons.append("YARA match MEDIUM (+1)")

    return score, reasons


def _level_for_score(score: int) -> str:
    if score >= 4:
        return "HIGH"
    if 2 <= score <= 3:
        return "MEDIUM"
    return "LOW"


def score_threats(flagged_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Accept a list of flagged items (merged from process_scan/registry_scan/hook_detect),
    score them, classify by risk, and return a list sorted by risk descending.

    Output dict keys:
      - name
      - score
      - level
      - reasons
    """

    threats: List[Dict[str, Any]] = []

    for item in flagged_items:
        if not isinstance(item, dict):
            continue

        # Skip scoring for whitelisted items.
        try:
            whitelisted, _match = is_whitelisted(
                str(item.get("name") or ""),
                str(item.get("path") or "") if item.get("path") is not None else None,
            )
        except Exception:
            whitelisted = False
        if whitelisted:
            continue

        score, reasons = _score_item(item)
        if score <= 0:
            continue

        threats.append(
            {
                "name": str(item.get("name") or ""),
                "score": score,
                "level": _level_for_score(score),
                "reasons": reasons,
                # Extra fields for GUI columns/context.
                "pid": item.get("pid"),
                "path": item.get("path") or "",
                "vt_verdict": item.get("vt_verdict"),
                "yara_severity": item.get("yara_severity"),
            }
        )

    threats.sort(key=lambda t: (-t["score"], t["name"].lower()))
    return threats

