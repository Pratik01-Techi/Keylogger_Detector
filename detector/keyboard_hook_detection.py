from __future__ import annotations

from typing import Any, Dict, List


def detect_keyboard_hook_indicators() -> List[Dict[str, Any]]:
    """
    Keyboard-hook detection (Windows).

    Real keyboard-hook detection typically involves:
    - Enumerating installed hooks / observing SetWindowsHookEx usage at runtime
    - Monitoring DLL injections / module loads related to hooking
    - Heuristics on loaded modules and suspicious API usage in target processes

    This scaffold returns a structured placeholder so you can extend it safely.
    """

    return [
        {
            "type": "keyboard_hook",
            "confidence": 0.0,
            "status": "not_implemented",
            "reason": "Keyboard-hook detection is scaffolded for extension (Windows API hooking telemetry needed).",
        }
    ]

