from __future__ import annotations

from typing import Any, Dict, List

import psutil


def detect_process_keylogging_signals() -> List[Dict[str, Any]]:
    """
    Heuristic process-level detection.

    Educational idea:
    - Look for suspicious process names / command lines that mention keyloggers,
      keyboard hooks, or input interception.
    - This is not reliable malware detection; it's a starting point.
    """

    suspicious_names = [
        "keylogger",
        "keylog",
        "keyboardhook",
        "keyboard_hook",
        "inputlogger",
        "hooklogger",
        "rat",  # generic, low confidence placeholder
    ]
    suspicious_terms = [
        "keylog",
        "key logger",
        "keystroke",
        "keyboardhook",
        "setwindowshookex",
        "getasynckeystate",
        "input monitor",
        "inputlogger",
        "windowshook",
        "journal",  # WinAPI patterns often mention journal hooks
    ]

    findings: List[Dict[str, Any]] = []

    # psutil can raise AccessDenied for some processes; we skip those.
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            pid = proc.info.get("pid")
            name = proc.info.get("name") or ""
            cmdline = proc.info.get("cmdline") or []
            cmd = " ".join(cmdline).lower()
            name_l = name.lower()

            confidence = 0.0
            reason_parts: List[str] = []

            if any(sn in name_l for sn in suspicious_names):
                confidence = max(confidence, 0.7)
                reason_parts.append(f"suspicious process name: {name}")

            for term in suspicious_terms:
                if term in cmd or term in name_l:
                    # More specific API/function names count more.
                    delta = 0.5 if term in {"setwindowshookex", "getasynckeystate"} else 0.35
                    confidence = max(confidence, delta)
                    reason_parts.append(f"suspicious term found: {term}")

            if confidence > 0.0:
                findings.append(
                    {
                        "type": "process",
                        "pid": pid,
                        "name": name,
                        "confidence": confidence,
                        "reason": "; ".join(reason_parts) if reason_parts else "Suspicious process signals found.",
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            # Keep the scan robust; detailed logging can be added later.
            continue

    return findings

