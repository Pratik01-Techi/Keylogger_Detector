rule suspicious_imports {
  meta:
    description = "Keyboard hook + file write indicators"
    severity = "MEDIUM"
  strings:
    $hook1 = "SetWindowsHookEx" ascii wide
    $ll    = "WH_KEYBOARD_LL" ascii wide
    $write = "WriteFile" ascii wide
    $create = "CreateFileW" ascii wide
    $open = "OpenFile" ascii wide
  condition:
    (($hook1 and $write) or ($hook1 and $create) or ($ll and $write) or ($ll and $create) or ($hook1 and $open))
}

