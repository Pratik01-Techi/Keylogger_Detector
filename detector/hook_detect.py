from __future__ import annotations

"""
Educational use only disclaimer:
This project is for defensive/educational purposes and may produce false positives
or false negatives. Hook probing is best-effort and must not be treated as a
definitive security outcome.
"""

import os
import sys
import time
from typing import Any, Dict, List, Optional


def detect_active_low_level_keyboard_hooks(duration_s: float = 1.0) -> List[Dict[str, Any]]:
    """
    Best-effort detection of low-level keyboard hooks using WH_KEYBOARD_LL.

    Important limitation:
    Windows does not expose a simple public API to enumerate which *other* processes
    installed hooks and return their PIDs. With ctypes we can reliably install a
    temporary WH_KEYBOARD_LL hook ourselves to confirm hooking capability.

    This function therefore returns the current process as an "active hook"
    when the hook is successfully installed, and returns [] on permission errors.
    The callback does NOT record keystrokes (educational scaffold).
    """

    # Keep this module Windows-oriented.
    if os.name != "nt":
        return []

    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return []

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    WH_KEYBOARD_LL = 13
    WM_QUIT = 0x0012
    PM_REMOVE = 0x0001

    # BOOL PeekMessage(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
    user32.PeekMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG),
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
        wintypes.UINT,
    ]
    user32.PeekMessageW.restype = wintypes.BOOL

    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.TranslateMessage.restype = wintypes.BOOL

    # LONG_PTR / LRESULT is platform-dependent; ctypes.wintypes doesn't provide LRESULT here.
    LRESULT = ctypes.c_ssize_t

    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = LRESULT

    # LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
    user32.CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
    user32.CallNextHookEx.restype = LRESULT

    # HOOKPROC signature
    LowLevelKeyboardProc = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

    callback_invocations = {"count": 0}

    @LowLevelKeyboardProc
    def _hook_proc(nCode: int, wParam: wintypes.WPARAM, lParam: wintypes.LPARAM) -> wintypes.LRESULT:
        # Educational/no-op: do not log or store keystrokes.
        if nCode >= 0:
            callback_invocations["count"] += 1
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    # HHOOK SetWindowsHookEx(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
    user32.SetWindowsHookExW.argtypes = [ctypes.c_int, LowLevelKeyboardProc, wintypes.HINSTANCE, wintypes.DWORD]
    user32.SetWindowsHookExW.restype = wintypes.HHOOK

    # BOOL UnhookWindowsHookEx(HHOOK hhk);
    user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
    user32.UnhookWindowsHookEx.restype = wintypes.BOOL

    # HINSTANCE GetModuleHandleW(LPCWSTR lpModuleName);
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE

    h_instance = kernel32.GetModuleHandleW(None)
    h_hook = None
    try:
        h_hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, _hook_proc, h_instance, 0)
        if not h_hook:
            last_err = ctypes.get_last_error()
            # ERROR_ACCESS_DENIED = 5
            if last_err == 5:
                return []
            return []

        # Pump messages for a short duration so the hook can run.
        end = time.time() + max(0.0, float(duration_s))
        msg = wintypes.MSG()
        while time.time() < end:
            got_msg = user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, PM_REMOVE)
            if got_msg:
                if msg.message == WM_QUIT:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            else:
                time.sleep(0.01)

    finally:
        try:
            if h_hook:
                user32.UnhookWindowsHookEx(h_hook)
        except Exception:
            pass

    # If we successfully installed our hook, we can confirm *at least* one hook is active
    # (ours). We cannot enumerate other processes' hooks with public APIs.
    pid = os.getpid()
    try:
        name = os.path.basename(sys.executable) or "unknown"
    except Exception:
        name = "unknown"

    return [
        {
            "pid": pid,
            "name": name,
            "hook_type": "WH_KEYBOARD_LL",
        }
    ]

