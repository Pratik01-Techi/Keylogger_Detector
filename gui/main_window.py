from __future__ import annotations

from typing import Any, Dict


def launch_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import scrolledtext
    except Exception as e:
        print("Tkinter GUI is not available in this Python environment:", e)
        return

    from main import run_scan

    root = tk.Tk()
    root.title("Keylogger Detector (Educational)")
    root.geometry("900x600")

    top = tk.Frame(root)
    top.pack(fill="x", padx=10, pady=10)

    status_var = tk.StringVar(value="Idle.")
    status_label = tk.Label(top, textvariable=status_var)
    status_label.pack(side="left")

    btn = tk.Button(top, text="Run Scan", width=12)
    btn.pack(side="right")

    output = scrolledtext.ScrolledText(root, wrap=tk.WORD)
    output.pack(fill="both", expand=True, padx=10, pady=10)

    def format_results(results: Dict[str, Any]) -> str:
        # Keep formatting simple for readability.
        parts = [f"Scanned at: {results.get('scanned_at')}\n"]

        parts.append("Process analysis findings:\n")
        pa = results.get("process_analysis") or []
        if not pa:
            parts.append("- None found by heuristics.\n")
        else:
            for item in pa:
                parts.append(
                    f"- [confidence={item.get('confidence')}] {item.get('reason')} (pid={item.get('pid')}, name={item.get('name')})\n"
                )

        parts.append("\nRegistry scanning findings:\n")
        rs = results.get("registry_scanning") or []
        if not rs:
            parts.append("- None found by heuristics.\n")
        else:
            for item in rs:
                parts.append(
                    f"- [confidence={item.get('confidence')}] {item.get('reason')} (path={item.get('key_path')}, value={item.get('value_name')})\n"
                )

        parts.append("\nKeyboard hook detection findings:\n")
        hk = results.get("keyboard_hook_detection") or []
        if not hk:
            parts.append("- No keyboard-hook indicators returned.\n")
        else:
            for item in hk:
                parts.append(f"- {item.get('reason')} (status={item.get('status')})\n")

        return "".join(parts)

    def on_scan() -> None:
        status_var.set("Scanning...")
        output.delete("1.0", tk.END)
        try:
            results = run_scan()
            output.insert(tk.END, format_results(results))
        except Exception as e:
            output.insert(tk.END, f"Scan failed: {e}\n")
        finally:
            status_var.set("Done.")

    btn.config(command=on_scan)
    root.mainloop()

