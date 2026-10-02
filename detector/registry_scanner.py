from __future__ import annotations

from typing import Any, Dict, List


def _try_get_registry_value_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    if isinstance(value, str):
        return value
    # Many values are numeric; stringify as a last resort.
    return str(value)


def scan_registry_for_keylogger_indicators() -> List[Dict[str, Any]]:
    """
    Heuristic registry scanning for suspicious persistence.

    Educational approach:
    - Check common autorun keys (`Run` / `RunOnce`).
    - Search value names/data for keylogging / keyboard hook related terms.
    """

    try:
        import winreg  # type: ignore
    except Exception:
        # Keeps the module importable on non-Windows platforms.
        return [
            {
                "type": "registry",
                "confidence": 0.0,
                "reason": "winreg unavailable; registry scanning is Windows-only in this scaffold.",
                "status": "unavailable",
            }
        ]

    root_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    suspicious_terms = [
        "keylog",
        "keyboard",
        "hook",
        "keystroke",
        "inputlogger",
        "input log",
        "windowshook",
        "setwindowshookex",
        "journal",
    ]

    findings: List[Dict[str, Any]] = []

    for root, key_path in root_keys:
        try:
            key = winreg.OpenKey(root, key_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue
        except Exception:
            continue

        try:
            i = 0
            while True:
                try:
                    value_name, value_data, _value_type = winreg.EnumValue(key, i)
                except OSError:
                    break

                i += 1

                data_str = _try_get_registry_value_str(value_data)
                data_l = data_str.lower()
                name_l = str(value_name).lower()

                matched_terms = [t for t in suspicious_terms if t in data_l or t in name_l]
                if matched_terms:
                    confidence = min(0.85, 0.35 + 0.1 * len(matched_terms))
                    findings.append(
                        {
                            "type": "registry",
                            "key_root": getattr(root, "name", str(root)),
                            "key_path": key_path,
                            "value_name": value_name,
                            "value_data": data_str,
                            "confidence": confidence,
                            "reason": f"suspicious registry term(s) found: {', '.join(matched_terms)}",
                        }
                    )
        finally:
            try:
                winreg.CloseKey(key)
            except Exception:
                pass

    return findings

