from __future__ import annotations

from typing import Any, Dict, List


def generate_pdf_report(results: Dict[str, Any], output_path: str) -> None:
    """
    Generate a simple PDF summary using `fpdf2`.

    The PDF is intentionally minimal; it's meant for educational demonstration.
    """

    try:
        from fpdf import FPDF  # fpdf2 uses the same import name
    except Exception as e:
        raise RuntimeError("fpdf2 is required for PDF reporting. Install with pip.") from e

    def add_findings(title: str, findings: List[Dict[str, Any]]) -> None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, title, ln=True)
        pdf.set_font("Helvetica", "", 10)

        if not findings:
            pdf.multi_cell(0, 5, "- None found by heuristics.")
            pdf.ln(2)
            return

        for item in findings:
            conf = item.get("confidence", "n/a")
            reason = str(item.get("reason", ""))
            extra = ""
            if "pid" in item:
                extra = f" (pid={item.get('pid')}, name={item.get('name')})"
            if "key_path" in item:
                extra = f" (path={item.get('key_path')}, value={item.get('value_name')})"
            if "status" in item:
                extra = f" (status={item.get('status')})"
            pdf.multi_cell(0, 5, f"- [confidence={conf}] {reason}{extra}")
        pdf.ln(2)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Keylogger Detector - Educational Report", ln=True, align="C")
    pdf.ln(6)

    scanned_at = results.get("scanned_at", "")
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(0, 6, f"Scanned at (UTC): {scanned_at}")
    pdf.ln(4)

    add_findings("Process Analysis", results.get("process_analysis") or [])
    add_findings("Registry Scanning", results.get("registry_scanning") or [])
    add_findings("Keyboard Hook Detection", results.get("keyboard_hook_detection") or [])

    pdf.output(output_path)

