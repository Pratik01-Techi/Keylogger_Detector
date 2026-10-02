<div align="center">

# 🛡️ Keylogger Detector

**An educational anti-malware tool for Windows** — combining process analysis, registry scanning, hook detection, YARA rules, and VirusTotal lookups into a unified animated dashboard.

<br/>


> ⚠️ **For educational and defensive research use only.** Not a replacement for professional security software.

</div>

---

## 📸 Screenshots

### Threat Detection Dashboard
> Scan results showing HIGH / MEDIUM / LOW threats with VT verdict and YARA severity columns.

---

### Right-Click Whitelist Action
> Right-clicking a flagged process reveals the *"Add to whitelist (false positive)"* option to suppress known-good processes from future scans.



## 🧠 How Keyloggers Work

Keyloggers capture user input by:

| Technique | Description |
|-----------|-------------|
| 🎣 **API Hooking** | Intercept `WH_KEYBOARD_LL` via `SetWindowsHookEx` |
| 🌑 **Background Execution** | Run silently with no visible window |
| 🔁 **Persistence** | Register in Windows startup (Registry `Run` keys) |
| 📁 **Hiding in TEMP/APPDATA** | Executables buried in user directories |

This tool detects **suspicious combinations** of these behaviors using layered heuristics.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔬 **Process Analysis** | Heuristic scan of all running processes via `psutil` |
| 🗂️ **Registry Scanning** | Checks `HKCU/HKLM` startup keys for suspicious entries |
| 🪝 **Hook Detection** | Probes for active `WH_KEYBOARD_LL` hooks via `ctypes` |
| ⚡ **Parallel Scanning** | `ThreadPoolExecutor` with 25s per-module timeout |
| 🧬 **YARA Rules** | Matches keylogger API strings and suspicious PE imports |
| 🌐 **VirusTotal v3** | Async SHA-256 lookups + 24h SQLite cache |
| 📋 **Whitelist Engine** | JSON-based false-positive suppression with wildcards |
| 📊 **Animated Dashboard** | Tkinter GUI with live progress bars and threat table |
| 📄 **PDF Reports** | Color-coded, severity-tagged export with timestamp |

---

## 🗂️ Project Structure

```
Keylogger-Detector/
│
├── 📂 detector/
│   ├── process_scan.py        # psutil-based process heuristics
│   ├── registry_scan.py       # winreg startup key scanner
│   ├── hook_detect.py         # WH_KEYBOARD_LL probe via ctypes
│   ├── scan_coordinator.py    # Parallel scan orchestrator
│   ├── yara_scanner.py        # YARA rule loader & matcher
│   ├── virustotal_check.py    # Async VT v3 client with caching
│   ├── whitelist.py           # JSON whitelist engine
│   └── scorer.py              # Risk scoring & threat ranking
│
├── 📂 rules/
│   ├── keylogger_strings.yar  # HIGH severity — keyboard API strings
│   ├── suspicious_imports.yar # MEDIUM — hook + file write imports
│   └── hidden_process.yar     # MEDIUM — missing PE version info
│
├── 📂 gui/
│   └── dashboard.py           # Animated Tkinter dashboard
│
├── 📂 reports/
│   └── report_gen.py          # PDF report generator
│
├── whitelist.json             # Trusted process/path patterns
├── vt_cache.db                # SQLite VT response cache (auto-created)
├── .env.example               # API key template
├── requirements.txt
└── main.py                    # Entry point (GUI + CLI)
```

---

## ⚙️ Installation

### Prerequisites

- 🐍 Python 3.10+ (Windows)
- A free [VirusTotal API key](https://virustotal.com) *(optional but recommended)*

### Setup

```bash
# Clone the repository
git clone https://github.com/<your-username>/Keylogger-Detector.git
cd Keylogger-Detector

# Install dependencies
pip install -r requirements.txt
```

### Configure VirusTotal *(optional)*

```bash
# Copy the example and add your key
cp .env.example .env
```

Edit `.env`:

```env
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY_HERE
```

> **No key?** Scans still run — VT verdicts will show as `UNKNOWN` and won't affect scoring.

---

## 🚀 Usage

### GUI Mode *(Animated Dashboard)*

```bash
python main.py
```

**What happens:**
- 🔄 Scans run in a background thread
- 📊 5 live progress bars animate in real time
- 🧾 Threat table populates as results arrive (new rows flash ~500ms)
- 🖱️ Right-click any row → *"Add to Whitelist (false positive)"*
- ⏱️ Enforced 30-second scan limit
- ✅ Banner: `Scan complete in Xs — N threats found`

### CLI Mode *(Terminal + JSON Export)*

```bash
# Basic scan
python main.py --cli

# Save results to JSON
python main.py --cli --output reports/out.json
```

---

## 🔍 Detection Modules

### 🔬 `process_scan.py` — Process Behavior Analysis

Uses `psutil` to iterate over all running processes and applies heuristics:

```
Flags if ANY of:
  ✗ No visible window detected
  ✗ Executable in TEMP or APPDATA
  ✗ High CPU + unusually low memory usage
  ✗ Process name matches keylogger-like patterns
```

Returns: `{ name, pid, path, reason }`

---

### 🗂️ `registry_scan.py` — Startup Persistence Scanner

Scans Windows autorun locations via `winreg`:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
```

Marks entries suspicious if they point to **TEMP/APPDATA** or non-absolute paths.

Returns: `{ name, path, suspicious }`

---

### 🪝 `hook_detect.py` — Keyboard Hook Probe

Uses `ctypes` to probe `WH_KEYBOARD_LL` hook installation via `SetWindowsHookExW`.

> **Note:** Windows does not expose a public API to enumerate which processes hold active low-level hooks. This module acts as a **capability scaffold** and returns conservative hook context.

---

### ⚡ `scan_coordinator.py` — Parallel Orchestrator

```python
ThreadPoolExecutor(max_workers=4)
```

| Module | Timeout |
|--------|---------|
| Process Scan | 25 seconds |
| Registry Scan | 25 seconds |
| Hook Detection | 25 seconds |
| YARA Scanning | 25 seconds |

Returns a `ScanResult` dataclass:

```
ScanResult
  ├── process_findings
  ├── registry_findings
  ├── hook_findings
  ├── yara_ready / yara_candidates / yara_results
  └── module_status (per module)
```

---

### 🧬 `yara_scanner.py` — YARA Rule Engine

| Rule File | Severity | Matches |
|-----------|----------|---------|
| `keylogger_strings.yar` | 🔴 HIGH | `GetAsyncKeyState`, `SetWindowsHookEx`, `WH_KEYBOARD_LL` |
| `suspicious_imports.yar` | 🟡 MEDIUM | Keyboard hook + file write/create imports |
| `hidden_process.yar` | 🟡 MEDIUM | PE files missing version-info strings |

Returns: `yara_severity`, `yara_matches[]`

---

### 🌐 `virustotal_check.py` — Async VT v3 Client

```
SHA-256 → VT API v3
  ├── SQLite cache (vt_cache.db) — 24h TTL
  ├── Rate limiting: 4 req/min (free tier)
  ├── asyncio.Semaphore(4) + aiohttp
  ├── Hard timeout: 15 seconds
  └── Max hashes per scan: 20 (by threat score priority)
```

Verdicts: `CLEAN` · `SUSPICIOUS` · `MALICIOUS` · `UNKNOWN`

---

### 📋 `whitelist.py` — False Positive Suppression

`whitelist.json` schema:

```json
{
  "trusted_processes": ["explorer.exe", "chrome.exe"],
  "trusted_paths":    ["C:\\Program Files\\*", "C:\\Windows\\*"]
}
```

- Pattern matching via `fnmatch` (supports `*` wildcards)
- GUI right-click → auto-appends to `whitelist.json`
- Whitelisted items are **excluded from scoring**

---

### 🎯 `scorer.py` — Risk Scoring Engine

| Indicator | Score |
|-----------|-------|
| ⌨️ Keyboard hook detected | `+2` |
| 📁 Path in TEMP/APPDATA or suspicious startup | `+2` |
| 🌑 No visible window | `+1` |
| 🏷️ Suspicious name pattern | `+1` |

**Classification:**

```
Score ≥ 4  →  🔴 HIGH
Score 2–3  →  🟡 MEDIUM
Score ≤ 1  →  🟢 LOW
```

Returns per-item: `name`, `pid`, `path`, `vt_verdict`, `yara_severity`, `reasons[]`

---

### 📊 `gui/dashboard.py` — Animated Dashboard

- 5 animated progress bars (process / registry / hook / YARA / VirusTotal)
- Scan button shows live countdown: `Scanning... (Xs remaining)`
- Threat rows flash on arrival (~500ms highlight)
- Right-click context menu → whitelist action
- Completion banner: `✅ Scan complete in Xs — N threats found`

---

### 📄 `reports/report_gen.py` — PDF Report Generator

Generates a color-coded PDF including:
- Title + scan timestamp
- Summary threat table (HIGH / MEDIUM / LOW color indicators)
- Per-threat reasons and verdicts
- Footer: *"Educational purposes only"*

---

## 🛡️ Scoring Summary

```
┌─────────────────────────────────────────────────────┐
│                  THREAT SCORE MATRIX                │
├────────────────────────────┬────────┬───────────────┤
│ Indicator                  │ Points │ Severity      │
├────────────────────────────┼────────┼───────────────┤
│ Keyboard hook detected     │  +2    │ Critical      │
│ Path in TEMP / APPDATA     │  +2    │ High          │
│ No visible window          │  +1    │ Medium        │
│ Suspicious name pattern    │  +1    │ Low           │
├────────────────────────────┼────────┼───────────────┤
│ Total ≥ 4                  │  —     │ 🔴 HIGH       │
│ Total 2–3                  │  —     │ 🟡 MEDIUM     │
│ Total ≤ 1                  │  —     │ 🟢 LOW        │
└────────────────────────────┴────────┴───────────────┘
```

---

## 🧰 Tech Stack

| Component | Library |
|-----------|---------|
| Process scanning | `psutil` |
| Registry access | `winreg` (stdlib) |
| Hook detection | `ctypes` (stdlib) |
| YARA rules | `yara-python` |
| VT API client | `aiohttp` + `aiosqlite` |
| GUI | `tkinter` (stdlib) |
| PDF generation | `reportlab` |
| Concurrency | `ThreadPoolExecutor`, `asyncio` |
| Environment vars | `python-dotenv` |

---

## 🔐 Security & Ethics

- ✅ **Defensive use only** — no offensive or keylogging code included
- ✅ **Heuristic-based** — may produce false positives/negatives
- ✅ **Local analysis** — only SHA-256 hashes sent to VirusTotal (never file contents)
- ✅ **Cached lookups** — respects VT free-tier rate limits
- ❌ **Not a SIEM** — complement with enterprise security tooling in production

---

## ⚠️ Disclaimer

This project is for **educational and defensive research purposes only**. Detection logic is heuristic and intentionally simplified to illustrate concepts. It is **not a substitute** for professional endpoint security products, antivirus software, or incident response. Always validate findings responsibly and ethically.

---

<div align="center">

Made with 🛡️ for defensive security learning


</div>
