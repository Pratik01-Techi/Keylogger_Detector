from __future__ import annotations

"""
Educational use only disclaimer:
PDF generation and report content are for defensive/educational visualization.
Always validate findings safely and responsibly.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fpdf import FPDF
from fpdf.enums import MethodReturnValue


def _level_color(level: str) -> tuple[int, int, int]:
    lvl = (level or "").upper()
    if lvl == "HIGH":
        return (220, 20, 60)  # crimson/red
    if lvl == "MEDIUM":
        return (255, 165, 0)  # orange
    return (46, 204, 113)  # green-ish for LOW


def _set_level_style(pdf: FPDF, level: str) -> None:
    r, g, b = _level_color(level)
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)


def generate_pdf_report(
    threats: List[Dict[str, Any]],
    output_dir: str = "reports",
    filename_prefix: str = "keylogger_detection_report",
    scan_datetime: Optional[datetime] = None,
) -> str:
    """
    Generate a PDF report from a list of threat dicts.

    Each threat dict should include:
      - name
      - score
      - level ("HIGH" / "MEDIUM" / "LOW")
      - reasons (list[str])

    Returns:
        The saved PDF path.
    """

    os.makedirs(output_dir, exist_ok=True)

    dt = scan_datetime or datetime.now()
    ts = dt.strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(output_dir, f"{filename_prefix}_{ts}.pdf")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Keylogger Detection Report", ln=True, align="C")
    pdf.ln(2)

    # Scan datetime
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Scan date/time: {dt.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(3)

    # Summary table layout
    # Columns: Level | Threat Name | Score | Reasons
    epw = pdf.w - pdf.l_margin - pdf.r_margin
    level_w = 22
    name_w = 55
    score_w = 16
    reasons_w = epw - level_w - name_w - score_w
    assert reasons_w > 30, "Page width too small for the table layout."

    # Header
    header_h = 8
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(230, 230, 230)
    pdf.set_text_color(0, 0, 0)

    x0 = pdf.l_margin
    y0 = pdf.get_y()

    pdf.set_xy(x0, y0)
    pdf.cell(level_w, header_h, "Level", border=1, fill=True, align="C")
    pdf.cell(name_w, header_h, "Threat", border=1, fill=True)
    pdf.cell(score_w, header_h, "Score", border=1, fill=True, align="C")
    pdf.cell(reasons_w, header_h, "Reasons", border=1, fill=True)
    pdf.ln(header_h)

    # Rows
    pdf.set_font("Helvetica", "", 9)
    cell_h = 5
    for threat in threats:
        name = str(threat.get("name") or "")
        score = threat.get("score", "")
        level = str(threat.get("level") or "LOW").upper()
        reasons_list = threat.get("reasons") or []
        if isinstance(reasons_list, str):
            reasons_list = [reasons_list]
        reasons_text = "; ".join(str(r) for r in reasons_list if r)
        if not reasons_text:
            reasons_text = "-"

        # Compute how many wrapped lines the reasons will occupy
        # using a dry-run pass so we can align the row borders.
        pdf.set_font("Helvetica", "", 9)
        lines = pdf.multi_cell(
            reasons_w,
            cell_h,
            reasons_text,
            border=0,
            dry_run=True,
            output=MethodReturnValue.LINES,
        )
        # Ensure at least one visual line.
        line_count = max(1, len(lines))
        row_h = line_count * cell_h

        y_start = pdf.get_y()
        x_level = x0
        x_name = x0 + level_w
        x_score = x_name + name_w
        x_reasons = x_score + score_w

        # Level cell with color fill
        _set_level_style(pdf, level)
        pdf.set_xy(x_level, y_start)
        pdf.cell(level_w, row_h, level, border=1, fill=True, align="C")
        # Reset to normal text color for the rest of the row
        pdf.set_text_color(0, 0, 0)

        # Threat name cell
        pdf.set_xy(x_name, y_start)
        pdf.cell(name_w, row_h, name, border=1)

        # Score cell
        pdf.set_xy(x_score, y_start)
        pdf.cell(score_w, row_h, str(score), border=1, align="C")

        # Reasons cell (multi_cell draws the bordered multi-line cell)
        pdf.set_xy(x_reasons, y_start)
        pdf.multi_cell(
            reasons_w,
            cell_h,
            reasons_text,
            border=1,
        )

        # fpdf2 advances y after multi_cell. Ensure next row starts at the row end.
        # (We leave as-is; multi_cell sets the cursor to the correct y.)

    if not threats:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, "No threats matched the heuristics.", ln=True)

    # Footer
    pdf.ln(3)
    pdf.set_y(-12)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Educational purposes only", align="C")

    pdf.output(out_path)
    return out_path

