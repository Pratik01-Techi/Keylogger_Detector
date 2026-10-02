rule keylogger_strings {
  meta:
    description = "Keylogger-related WinAPI strings"
    severity = "HIGH"
  strings:
    $getasync = "GetAsyncKeyState" ascii wide
    $sethook  = "SetWindowsHookEx" ascii wide
    $whll     = "WH_KEYBOARD_LL" ascii wide
  condition:
    ($getasync and $sethook) or ($getasync and $whll) or ($sethook and $whll)
}

