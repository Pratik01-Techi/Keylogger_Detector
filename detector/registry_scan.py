from __future__ import annotations

"""
Educational use only disclaimer:
This project is for defensive/educational purposes and may produce false positives
or false negatives. It must not be used as a substitute for professional security tools.
"""

from typing import Any, Dict, List, Optional


def _to_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    if isinstance(value, str):
        return value
    return str(value)


def _extract_candidate_path(command: str) -> str:
    """
    Extract a likely executable/path from a Run-key command line.

    Examples:
      "C:\\Temp\\x.exe" --flag -> C:\\Temp\\x.exe
      C:\\Program Files\\a.exe -arg -> C:\\Program Files\\a.exe
      powershell -nop -> powershell
    """

    cmd = (command or "").strip()
    if not cmd:
        return ""

    if cmd[0] == '"':
        end = cmd.find('"', 1)
        if end > 1:
            return cmd[1:end]
        # Unbalanced quotes; fall back to token split.
    return cmd.split()[0]


def _is_absolute_path(p: str) -> bool:
    if not p:
        return False
    pl = p.lower()
    if pl.startswith("\\\\"):
        return True  # UNC path
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():
        return True  # Drive letter path: C:\...
    return False


def _suspicious_path(candidate_path: str, full_command: str) -> bool:
    """
    Suspicious if candidate is under TEMP/APPDATA or if location is unknown.

    "Unknown locations" is handled conservatively as "not an absolute path"
    (e.g., just `notepad.exe`, `powershell`, or env-variable-based paths).
    """

    p = (candidate_path or "").strip()
    pl = p.lower()
    cmdl = (full_command or "").lower()

    temp_markers = [
        r"\temp",
        r"\tmp",
        r"%temp%",
    ]
    appdata_markers = [
        r"\appdata",
        r"\local\appdata",
        r"\roaming\appdata",
        r"%appdata%",
        r"%localappdata%",
    ]

    if any(m in pl or m in cmdl for m in temp_markers):
        return True
    if any(m in pl or m in cmdl for m in appdata_markers):
        return True

    # Unknown location heuristic: if it's not an absolute path, mark suspicious.
    # (This intentionally trades off some false positives for educational value.)
    return not _is_absolute_path(p)


def scan_startup_run_keys() -> List[Dict[str, Any]]:
    """
    Scan Windows Run keys for suspicious startup entries.

    Keys scanned:
      - HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
      - HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

    Returns:
        List[Dict] with keys:
          - name: registry value name
          - path: extracted command/exe path (best-effort)
          - suspicious: bool
    """

    try:
        import winreg  # type: ignore
    except Exception:
        # Keep the module importable on non-Windows systems.
        return []

    key_specs = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    results: List[Dict[str, Any]] = []

    for root, key_path in key_specs:
        try:
            k = winreg.OpenKey(root, key_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue
        except PermissionError:
            # Access denied: skip this key.
            continue
        except Exception:
            continue

        try:
            i = 0
            while True:
                try:
                    value_name, value_data, _value_type = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1

                command = _to_str(value_data)
                candidate = _extract_candidate_path(command)
                suspicious = _suspicious_path(candidate, command)

                results.append(
                    {
                        "name": value_name,
                        "path": candidate,
                        "suspicious": suspicious,
                    }
                )
        finally:
            try:
                winreg.CloseKey(k)
            except Exception:
                pass

    return results

