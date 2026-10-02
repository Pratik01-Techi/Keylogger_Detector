from __future__ import annotations

"""
Educational use only disclaimer:
This GUI is for defensive/educational use only. The displayed results are heuristic
and may include false positives/false negatives.
"""

from typing import Any, Dict, List


def launch_gui(*, raw_results: Dict[str, Any], threats: List[Dict[str, Any]], counts_by_level: Dict[str, int]) -> None:
    """
    Tkinter dashboard to display scan findings and allow user whitelisting.
    """

    try:
        import tkinter as tk
        from tkinter import scrolledtext, ttk, messagebox
    except Exception as e:  # pragma: no cover
        print("Tkinter GUI is not available:", e)
        return

    from detector.whitelist import add_to_whitelist

    root = tk.Tk()
    root.title("Keylogger Detector - Educational")
    root.geometry("1100x700")

    LEVEL_TAGS = {
        "HIGH": {"bg": "#ffe6ea", "fg": "#b00020"},
        "MEDIUM": {"bg": "#fff0d6", "fg": "#a15a00"},
        "LOW": {"bg": "#e7fff1", "fg": "#0b5f2a"},
    }

    state_frame = tk.Frame(root)
    state_frame.pack(fill="x", padx=10, pady=10)

    status = tk.StringVar(value="Scan complete.")
    tk.Label(state_frame, textvariable=status, font=("Arial", 11, "bold")).pack(side="left")

    false_positive_var = tk.StringVar(value="False positives whitelisted: 0")
    tk.Label(state_frame, textvariable=false_positive_var, font=("Arial", 10)).pack(side="left", padx=20)

    tk.Button(state_frame, text="Quit", width=10, command=root.destroy).pack(side="right")

    # Table + details layout.
    table_frame = tk.Frame(root)
    table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    columns = ("level", "name", "score", "vt_verdict", "yara_severity")
    tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse", height=12)
    tree.heading("level", text="Level")
    tree.heading("name", text="Threat")
    tree.heading("score", text="Score")
    tree.heading("vt_verdict", text="VT verdict")
    tree.heading("yara_severity", text="YARA severity")

    tree.column("level", width=80, anchor="center")
    tree.column("name", width=340, anchor="w")
    tree.column("score", width=80, anchor="center")
    tree.column("vt_verdict", width=120, anchor="center")
    tree.column("yara_severity", width=140, anchor="center")

    tree.pack(side="top", fill="x")

    details = scrolledtext.ScrolledText(table_frame, wrap=tk.WORD, font=("Consolas", 10), height=12)
    details.pack(side="top", fill="both", expand=True, pady=(8, 0))

    scanned_at = raw_results.get("scanned_at", "")
    details.insert(tk.END, "Keylogger Detection Report\n")
    details.insert(tk.END, f"Scan time (UTC): {scanned_at}\n")
    details.insert(
        tk.END,
        f"Threat count by level: HIGH={counts_by_level.get('HIGH', 0)}  MEDIUM={counts_by_level.get('MEDIUM', 0)}  LOW={counts_by_level.get('LOW', 0)}\n\n",
    )
    details.insert(tk.END, "Select a threat row to view reasons.\n")
    details.config(state="disabled")

    # Configure row colors via tags.
    for lvl, cfg in LEVEL_TAGS.items():
        tree.tag_configure(lvl, background=cfg["bg"], foreground=cfg["fg"])

    threat_by_item_id: Dict[str, Dict[str, Any]] = {}
    false_positive_count = 0

    # Insert threats.
    for t in threats:
        lvl = str(t.get("level") or "LOW").upper()
        name = str(t.get("name") or "")
        score = t.get("score")
        vt_verdict = t.get("vt_verdict") or ""
        yara_sev = t.get("yara_severity") or ""
        reasons = t.get("reasons") or []

        item_id = tree.insert(
            "",
            "end",
            values=(lvl, name, score, vt_verdict, yara_sev),
            tags=(lvl,),
        )
        threat_by_item_id[item_id] = {
            "name": name,
            "pid": t.get("pid"),
            "path": t.get("path") or "",
            "reasons": reasons,
            "vt_verdict": vt_verdict,
            "yara_severity": yara_sev,
            "level": lvl,
        }

    def _show_reasons_for_selected() -> None:
        selection = tree.selection()
        if not selection:
            return
        item_id = selection[0]
        t = threat_by_item_id.get(item_id) or {}
        reasons = t.get("reasons") or []
        if isinstance(reasons, str):
            reasons = [reasons]

        details.config(state="normal")
        details.delete("1.0", tk.END)
        details.insert(
            tk.END,
            "Keylogger Detection Report\n",
        )
        details.insert(tk.END, f"Scan time (UTC): {scanned_at}\n")
        details.insert(
            tk.END,
            f"Threat count by level: HIGH={counts_by_level.get('HIGH', 0)}  MEDIUM={counts_by_level.get('MEDIUM', 0)}  LOW={counts_by_level.get('LOW', 0)}\n\n",
        )
        details.insert(tk.END, f"Selected threat: {t.get('name')}\n\n")
        details.insert(tk.END, "Reasons:\n")
        if not reasons:
            details.insert(tk.END, "- (no reasons provided)\n")
        else:
            for r in reasons:
                details.insert(tk.END, f"- {r}\n")

        details.config(state="disabled")

    tree.bind("<<TreeviewSelect>>", lambda _evt: _show_reasons_for_selected())

    # Context menu for whitelisting.
    menu = tk.Menu(root, tearoff=0)

    def on_whitelist_selected() -> None:
        nonlocal false_positive_count
        selection = tree.selection()
        if not selection:
            return
        item_id = selection[0]
        t = threat_by_item_id.get(item_id) or {}
        name = str(t.get("name") or "")
        path = str(t.get("path") or "")

        if not name and not path:
            messagebox.showinfo("Whitelist", "Selected item has no name/path to whitelist.")
            return

        # Best-effort: store name pattern and full path pattern (if available).
        added, msg = add_to_whitelist(process_name=name, path_pattern=path or None)
        if added:
            false_positive_count += 1
            false_positive_var.set(f"False positives whitelisted: {false_positive_count}")
            # Remove from view since it should be skipped in future scans.
            tree.delete(item_id)
            threat_by_item_id.pop(item_id, None)
            details.config(state="normal")
            details.delete("1.0", tk.END)
            details.config(state="disabled")
            _show_reasons_for_selected()
        else:
            messagebox.showinfo("Whitelist", msg)

    menu.add_command(label="Add to whitelist (false positive)", command=on_whitelist_selected)

    def on_tree_right_click(evt: Any) -> None:
        try:
            # Select the row under the cursor.
            row_id = tree.identify_row(evt.y)
            if row_id:
                tree.selection_set(row_id)
                menu.tk_popup(evt.x_root, evt.y_root)
        finally:
            # Ensure popup closes correctly.
            try:
                menu.grab_release()
            except Exception:
                pass

    tree.bind("<Button-3>", on_tree_right_click)
    tree.bind("<Button-2>", on_tree_right_click)  # some systems use middle-button for context

    root.mainloop()

