rule hidden_process {
  meta:
    description = "PE binaries that appear to be missing version-info strings"
    severity = "MEDIUM"
  strings:
    $vs = "VS_VERSION_INFO" ascii wide
  condition:
    uint16(0) == 0x5A4D and not $vs
}

