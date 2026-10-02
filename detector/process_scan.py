from __future__ import annotations

"""
Educational use only disclaimer:
This project is for defensive/educational purposes and may produce false positives
or false negatives. It must not be used as a substitute for professional security tools.
"""

import os
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil


def _collect_visible_window_pids() -> Set[int]:
    """
    Collect PIDs that own at least one visible top-level window.

    This is Windows-only and intentionally best-effort: if Win32 calls fail,
    we fall back to returning an empty set (so we won't flag by this criterion).
    """

    if sys.platform != "win32":
        return set()

    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)

        EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        visible_pids: Set[int] = set()

        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL

        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD

        def callback(hwnd: wintypes.HWND, lparam: wintypes.LPARAM) -> bool:
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True

                pid = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    visible_pids.add(int(pid.value))

            except Exception:
                # Never let an enumeration callback crash the scan.
                pass

            return True

        enum_windows = EnumWindowsProc(callback)
        user32.EnumWindows(enum_windows, 0)
        return visible_pids
    except Exception:
        # If we can't enumerate windows, don't apply the "no visible window" heuristic.
        return set()


def _flag_reason_join(reasons: List[str]) -> str:
    # Keep it stable and readable for GUI/JSON output.
    return "; ".join(reasons) if reasons else "Suspicious process signals found."


def _exe_in_temp_or_appdata(exe_path: str) -> Optional[str]:
    """
    Return a string explaining which marker matched, otherwise None.
    """

    p = exe_path.lower()

    markers: List[Tuple[str, str]] = [
        (r"\\temp\\", "located under TEMP"),
        (r"\\local\\temp\\", "located under LOCAL\\TEMP"),
        (r"\\appdata\\", "located under APPDATA"),
        (r"\\local\\appdata\\", "located under LOCAL\\APPDATA"),
        (r"\\roaming\\appdata\\", "located under ROAMING\\APPDATA"),
    ]
    for marker, msg in markers:
        if marker in p:
            return msg

    # Fallback: if path includes temp/appdata without backslashes (rare),
    # still catch it.
    if "temp" in p:
        return "path contains TEMP"
    if "appdata" in p:
        return "path contains APPDATA"
    return None


def scan_processes() -> List[Dict[str, Any]]:
    """
    Scan running processes and return a list of suspicious ones.

    Flag a process if it matches any of:
    - It has no visible window (Windows: no visible top-level window owned by PID)
    - Its executable path is in TEMP or APPDATA folders
    - It has unusually high CPU usage with low memory (heuristic)
    - Its name matches common keylogger patterns

    Returns:
        List[Dict[str, Any]] with keys: name, pid, path, reason
    """

    # Keylogger-like patterns (name/command heuristics).
    keylogger_name_patterns = [
        "keylogger",
        "keylog",
        "keyboardhook",
        "keyboard_hook",
        "inputlogger",
        "hooklogger",
        "keystroke",
        "input hook",
        "setwindowshookex",
        "journal",  # sometimes appears in hook-related tooling names
    ]

    # Heuristic thresholds.
    # Note: these are intentionally conservative for an educational scaffold.
    cpu_high_pct = 30.0
    rss_low_bytes = 200 * 1024 * 1024  # 200 MB
    cpu_sample_interval_s = 0.5

    visible_pids: Set[int] = _collect_visible_window_pids()
    should_apply_window_heuristic = bool(visible_pids)

    procs: List[psutil.Process] = []
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            procs.append(proc)
        except Exception:
            continue

    # Initialize per-process cpu_percent measurements.
    for proc in procs:
        try:
            proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    time.sleep(cpu_sample_interval_s)

    findings: List[Dict[str, Any]] = []
    for proc in procs:
        pid = getattr(proc, "pid", None)
        name = ""
        path = ""
        reasons: List[str] = []

        try:
            info = proc.as_dict(attrs=["name"])
            name = (info.get("name") or "") if isinstance(info, dict) else ""
            name_l = name.lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            name_l = ""

        # 1) No visible window heuristic (Windows).
        if should_apply_window_heuristic and isinstance(pid, int):
            if pid not in visible_pids:
                reasons.append("no visible window (PID has no visible top-level windows)")

        # 2) Executable path heuristic.
        try:
            path = proc.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.Error):
            path = ""
        except Exception:
            path = ""

        if path:
            marker_msg = _exe_in_temp_or_appdata(path)
            if marker_msg:
                reasons.append(marker_msg + f": {path}")

        # 3) High CPU + low memory heuristic.
        try:
            cpu_pct = float(proc.cpu_percent(None))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            cpu_pct = 0.0
        except Exception:
            cpu_pct = 0.0

        try:
            mem = proc.memory_info()
            rss = int(getattr(mem, "rss", 0))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            rss = 0
        except Exception:
            rss = 0

        if cpu_pct >= cpu_high_pct and rss > 0 and rss <= rss_low_bytes:
            # Keep reason concise; include CPU/RSS values for triage.
            rss_mb = rss / (1024 * 1024)
            reasons.append(f"high CPU usage ({cpu_pct:.1f}%) with low memory (RSS={rss_mb:.1f} MB)")

        # 4) Name pattern heuristic.
        if name_l:
            matched = [p for p in keylogger_name_patterns if p in name_l]
            if matched:
                reasons.append("name matches keylogger pattern(s): " + ", ".join(matched))

        if reasons:
            findings.append(
                {
                    "name": name,
                    "pid": pid,
                    "path": path,
                    "reason": _flag_reason_join(reasons),
                }
            )

    return findings

