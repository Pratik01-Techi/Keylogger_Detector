"""
Keylogger Detector - educational anti-malware scaffold.

Ties together process scanning, registry scanning, hook capability probing,
YARA signature scanning, and VirusTotal verdict checks.

Educational use only disclaimer: heuristic detection may produce false positives
or false negatives and should not be treated as definitive security guidance.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import psutil

from detector import hook_detect, process_scan, registry_scan, scorer, virustotal_check, yara_scanner
from detector.whitelist import is_whitelisted


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_scan() -> Dict[str, Any]:
    """
    Backwards-compatible scan runner used by the older `gui/main_window.py`.

    Returns a dict with keys:
      - process_analysis
      - registry_scanning
      - keyboard_hook_detection
    """
    scanned_at = _utc_now_iso()
    process_findings = process_scan.scan_processes()
    registry_findings = registry_scan.scan_startup_run_keys()
    hook_findings = hook_detect.detect_active_low_level_keyboard_hooks()

    # Convert to the field names expected by gui/main_window.py.
    process_analysis = [
        {
            "confidence": 1.0,
            "reason": item.get("reason", ""),
            "pid": item.get("pid"),
            "name": item.get("name", ""),
        }
        for item in process_findings
    ]

    registry_scanning = []
    for item in registry_findings:
        suspicious = bool(item.get("suspicious"))
        registry_scanning.append(
            {
                "confidence": 0.9 if suspicious else 0.3,
                "reason": f"suspicious startup registry entry: {item.get('path')}" if suspicious else f"startup entry: {item.get('path')}",
                "key_path": "",
                "value_name": item.get("name"),
            }
        )

    keyboard_hook_detection = [
        {
            "reason": f"{item.get('hook_type')} hook detected (best-effort)",
            "status": "active",
        }
        for item in hook_findings
    ]

    return {
        "scanned_at": scanned_at,
        "process_analysis": process_analysis,
        "registry_scanning": registry_scanning,
        "keyboard_hook_detection": keyboard_hook_detection,
    }


def _merged_flagged_items() -> Tuple[Dict[str, Any], List[Dict[str, Any]], float]:
    """
    Run process/registry/hook scans, then apply YARA + VirusTotal enrichment.

    Returns:
        (raw_results, flagged_items, accuracy_estimate)
    """
    scanned_at = _utc_now_iso()

    # Step 1-3: base heuristics.
    proc_findings = process_scan.scan_processes()
    reg_findings = registry_scan.scan_startup_run_keys()
    hook_findings = hook_detect.detect_active_low_level_keyboard_hooks()

    # Best-effort: resolve executable paths for hook items (optional for YARA/VT).
    for hi in hook_findings:
        if (hi.get("path") or "").strip():
            continue
        pid = hi.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            continue
        try:
            hi["path"] = psutil.Process(pid).exe()
        except Exception:
            # Access denied / process exited / etc.
            hi["path"] = hi.get("path") or ""

    raw_results: Dict[str, Any] = {
        "scanned_at": scanned_at,
        "process_scan": proc_findings,
        "registry_scan": reg_findings,
        "hook_detect": hook_findings,
    }

    flagged_items: List[Dict[str, Any]] = []

    # Process scan findings already match the scorer's expected schema.
    for item in proc_findings:
        if isinstance(item, dict):
            flagged_items.append(item)

    # Convert registry entries into the shape scorer understands.
    for item in reg_findings:
        if not isinstance(item, dict):
            continue
        suspicious = bool(item.get("suspicious"))
        path = item.get("path") or ""
        flagged_items.append(
            {
                "name": str(item.get("name") or ""),
                "pid": None,
                "path": path,
                "suspicious": suspicious,
                "reason": (
                    f"suspicious registry startup path: {path}"
                    if suspicious
                    else f"registry startup path: {path}"
                ),
            }
        )

    # Hook items already match scorer's hook indicators (pid/name/hook_type).
    for item in hook_findings:
        if isinstance(item, dict):
            flagged_items.append(item)

    # Step 4: YARA enrichment.
    yara_scanner_obj = yara_scanner.YaraScanner()
    yara_ready = yara_scanner_obj.is_ready()

    def _candidate_for_yara(it: Dict[str, Any]) -> bool:
        path = str(it.get("path") or "")
        if not path or not os.path.isfile(path):
            return False

        name_l = str(it.get("name") or "").lower()
        path_l = path.lower()
        suspicious = bool(it.get("suspicious"))
        hook_type_present = bool(it.get("hook_type"))

        keylogger_name_patterns = [
            "keylogger",
            "keylog",
            "keyboardhook",
            "keyboard_hook",
            "inputlogger",
            "hooklogger",
            "keystroke",
        ]
        name_hits = any(p in name_l for p in keylogger_name_patterns)
        path_hits = ("\\temp\\" in path_l) or ("\\appdata\\" in path_l) or ("\\local\\appdata\\" in path_l)
        return suspicious or hook_type_present or name_hits or path_hits

    candidate_paths: List[str] = []
    for it in flagged_items:
        if _candidate_for_yara(it):
            candidate_paths.append(str(it.get("path") or ""))

    # De-duplicate and limit.
    candidate_paths = list(dict.fromkeys([p for p in candidate_paths if p]))[:50]

    yara_results: Dict[str, Dict[str, Any]] = {}
    if yara_ready and candidate_paths:
        try:
            yara_results = yara_scanner.scan_paths(candidate_paths, scanner=yara_scanner_obj)
        except Exception:
            yara_results = {}

    # Attach YARA outcomes to flagged items.
    for it in flagged_items:
        path = str(it.get("path") or "")
        if not path:
            continue
        yres = yara_results.get(path) or {}
        if yres:
            it["yara_severity"] = yres.get("yara_severity")
            it["yara_matches"] = yres.get("yara_matches") or []

    raw_results["yara_ready"] = yara_ready
    raw_results["yara_candidates"] = candidate_paths
    raw_results["yara_results"] = yara_results

    # Step 5: VirusTotal enrichment (SHA-256 lookup).
    vt_client = virustotal_check.VirusTotalClient()
    vt_configured = vt_client.is_configured()

    def _candidate_for_vt(it: Dict[str, Any]) -> bool:
        path = str(it.get("path") or "")
        if not path or not os.path.isfile(path):
            return False

        if bool(it.get("hook_type")):
            return True
        if bool(it.get("suspicious")):
            return True

        name_l = str(it.get("name") or "").lower()
        if any(p in name_l for p in ["keylogger", "keylog", "inputlogger", "keystroke"]):
            return True

        yara_sev = str(it.get("yara_severity") or "").upper()
        if yara_sev in {"HIGH", "MEDIUM"}:
            return True

        path_l = path.lower()
        if "\\temp\\" in path_l or "\\appdata\\" in path_l:
            return True

        return False

    # Skip VT work for whitelisted items to reduce false alarms and costs.
    vt_shas_to_items: Dict[str, List[Dict[str, Any]]] = {}
    seen_shas: set[str] = set()

    vt_max_shas = 20
    for it in flagged_items:
        if not _candidate_for_vt(it):
            continue

        if is_whitelisted(str(it.get("name") or ""), str(it.get("path") or ""))[0]:
            continue

        path = str(it.get("path") or "")
        sha = virustotal_check.sha256_of_file(path)
        if not sha:
            continue
        if sha in seen_shas:
            vt_shas_to_items[sha].append(it)
            continue

        seen_shas.add(sha)
        vt_shas_to_items[sha] = [it]
        if len(seen_shas) >= vt_max_shas:
            break

    vt_verdicts_by_sha: Dict[str, str] = {}
    if vt_configured and vt_shas_to_items:
        for sha in list(vt_shas_to_items.keys()):
            verdict = vt_client.get_verdict_for_sha256(sha)
            vt_verdicts_by_sha[sha] = verdict
            for it in vt_shas_to_items.get(sha) or []:
                it["vt_verdict"] = verdict
    else:
        # Ensure field exists for dashboard consistency.
        for it in flagged_items:
            it.setdefault("vt_verdict", None)

    raw_results["vt_configured"] = vt_configured
    raw_results["vt_shas"] = list(vt_shas_to_items.keys())
    raw_results["vt_verdicts_by_sha"] = vt_verdicts_by_sha

    # Accuracy estimate (heuristic): potential uplift from added enrichment layers.
    # - YARA is fully applied when rules compile.
    # - VT verdicts are only applied when an API key is configured.
    accuracy_estimate = 0.65
    if yara_ready:
        accuracy_estimate += 0.05

    vt_possible = bool(getattr(vt_client, "_session", None))
    if vt_possible:
        accuracy_estimate += 0.10

    accuracy_estimate = min(0.80, accuracy_estimate)
    if not vt_configured and vt_possible:
        raw_results["accuracy_note"] = "VT_API_KEY not configured; VT verdicts will be UNKNOWN/unapplied."

    raw_results["accuracy_estimate"] = accuracy_estimate
    return raw_results, flagged_items, accuracy_estimate


def _print_summary(threats: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        lvl = str(t.get("level") or "LOW").upper()
        if lvl in counts:
            counts[lvl] += 1
        else:
            counts["LOW"] += 1

    print(f"Total threats: {len(threats)}")
    print(f"Threat count by level: HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
    return counts


def _export_json_report(
    raw_results: Dict[str, Any],
    threats: List[Dict[str, Any]],
    counts: Dict[str, int],
    output_path: str,
) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    payload = {
        "scanned_at": raw_results.get("scanned_at"),
        "raw_results": raw_results,
        "threats": threats,
        "counts_by_level": counts,
        "accuracy_estimate": raw_results.get("accuracy_estimate"),
        "note": "Educational purposes only; heuristic detection scaffold.",
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return output_path


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Educational Keylogger Detector (heuristic).")
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run terminal-only scan and export a JSON report (no GUI).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional JSON output path (CLI mode). Default: reports/keylogger_detection_json_report_*.json",
    )
    args = parser.parse_args(argv)

    raw_results, flagged_items, accuracy_estimate = _merged_flagged_items()
    threats = scorer.score_threats(flagged_items)
    counts = _print_summary(threats)
    print(f"Estimated detection accuracy (heuristic): {accuracy_estimate * 100:.0f}%")
    note = raw_results.get("accuracy_note")
    if note:
        print(f"Note: {note}")

    if args.cli:
        dt = datetime.now()
        ts = dt.strftime("%Y%m%d_%H%M%S")
        output_path = args.output or os.path.join(
            "reports", f"keylogger_detection_json_report_{ts}.json"
        )
        out = _export_json_report(raw_results, threats, counts, output_path)
        print(f"JSON report saved to: {out}")
        return 0

    # GUI mode
    from gui.dashboard import launch_gui

    launch_gui(raw_results=raw_results, threats=threats, counts_by_level=counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

