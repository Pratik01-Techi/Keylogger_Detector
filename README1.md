<!-- Badges -->
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D7.svg)

## Keylogger Detector

**Keylogger Detector** is an **educational anti-malware** project for Windows that demonstrates how to combine multiple defensive heuristics into a practical keylogger-detection pipeline. It uses:

- Parallel **process / registry / hook** scanning
- **YARA** signatures
- **VirusTotal** lookups (with local caching)
- A **whitelist** engine
- An animated **Tkinter dashboard**

This repository is intended for learning, safe experimentation, and defensive tooling concepts — **not** as a replacement for professional security products.

## How Keyloggers Work (Brief)

Keyloggers are malware (or unwanted software) that capture user input—often keyboard events—by hooking input APIs, running in the background, and persisting across reboots (for example via Windows Registry startup entries). Defensive detection typically looks for suspicious combinations of **process behavior**, **persistence artifacts**, and **hook-related indicators**.

## Features

- **Process behavior analysis** (`detector/process_scan.py`)
- **Registry scanning** for Windows startup persistence (`detector/registry_scan.py`)
- **Hook detection probe (Windows)** (`detector/hook_detect.py`)
- **Parallel scan coordinator** (`detector/scan_coordinator.py`)
- **YARA rule scanning** (`detector/yara_scanner.py`, `rules/*.yar`)
- **VirusTotal v3 integration** with async I/O + SQLite cache (`detector/virustotal_check.py`, `vt_cache.db`)
- **JSON whitelist engine** for legitimate apps (`detector/whitelist.py`, `whitelist.json`)
- **Risk scoring** and threat ranking (`detector/scorer.py`)
- **Animated GUI dashboard** (`gui/dashboard.py`)
- **PDF reports** from JSON results (`reports/report_gen.py`)

## Installation

```bash
git clone https://github.com/<your-username>/Keylogger-Detector.git
cd Keylogger-Detector
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Configure VirusTotal (optional but recommended)

1. Get a free API key from `virustotal.com`.
2. Create a `.env` file (you can copy from `.env.example`):

   ```env
   VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY_HERE
   ```

If no key is provided, scans still run, but VT verdicts will be `UNKNOWN` and won’t contribute to scoring.

### 2. Run the GUI (animated dashboard)

```bash
python main.py
```

The GUI will:

- Start scans in a background thread
- Show 5 animated progress bars (process / registry / hook / YARA / VirusTotal)
- Display a live threat table with VT verdicts and YARA severity
- Let you right-click rows to add them to the whitelist
- Enforce a 30-second scan limit and show:  
  **“Scan complete in Xs — N threats found”**

### 3. Run terminal-only scan and export JSON

```bash
python main.py --cli
```

Optional: specify a JSON output path:

```bash
python main.py --cli --output reports/out.json
```

## Detection Modules (How They Work)

## Detection Modules (How They Work)

### `detector/process_scan.py`

Uses `psutil` to iterate over running processes and applies educational heuristics to flag suspicious candidates, including:

- **No visible window** (Windows best-effort top-level window visibility check)
- **Executable path located in TEMP / APPDATA** (best-effort via `proc.exe()`)
- **Unusually high CPU usage with relatively low memory** (heuristic sampling)
- **Process name matches keylogger-like patterns**

Returns flagged processes as dicts containing `name`, `pid`, `path`, and `reason`.

### `detector/registry_scan.py`

Uses Python’s built-in `winreg` to scan Windows startup locations for automatic execution:

- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`

It extracts value commands (best-effort) and marks entries as suspicious when they point to **TEMP / APPDATA** or appear to be in **unknown / non-absolute** locations.

Returns entries as dicts containing `name`, `path`, and `suspicious`.

### `detector/hook_detect.py`

Uses `ctypes` to call the Windows API for a **best-effort** probe of `WH_KEYBOARD_LL` hook installation using `SetWindowsHookExW`.

Important: Windows does not provide a simple public mechanism to enumerate *which other processes* installed low-level keyboard hooks. This module therefore acts as a scaffold/capability probe and returns detected hook context in a conservative way.

### `detector/scan_coordinator.py`

Uses `ThreadPoolExecutor(max_workers=4)` to launch:

- `process_scan.scan_processes()`
- `registry_scan.scan_startup_run_keys()`
- `hook_detect.detect_active_low_level_keyboard_hooks()`
- a YARA scanning task

Key behaviors:

- **25-second per-module timeout**
- Uses `queue.Queue` to report module status back to the caller
- Returns a `ScanResult` dataclass with:
  - `process_findings`, `registry_findings`, `hook_findings`
  - `yara_ready`, `yara_candidates`, `yara_results`
  - `module_status` per module

### `detector/yara_scanner.py`

Loads YARA rules from the `rules/` folder:

- `rules/keylogger_strings.yar` — matches keylogger-related API strings (e.g. `GetAsyncKeyState`, `SetWindowsHookEx`, `WH_KEYBOARD_LL`) — **HIGH** severity
- `rules/suspicious_imports.yar` — keyboard hook + file write / create imports — **MEDIUM** severity
- `rules/hidden_process.yar` — PE files missing common version-info strings — **MEDIUM** severity

Aggregates matches across all rule files and returns:

- `yara_severity`: `HIGH` / `MEDIUM` / `None`
- `yara_matches`: list of matched rule names

### `detector/virustotal_check.py`

Implements an **async** VirusTotal v3 client using `aiohttp` + `aiosqlite`:

- Computes SHA-256 for candidate executables
- Uses SQLite cache (`vt_cache.db`) with **24h TTL** to avoid repeated lookups
- Enforces **4 requests/min** (API free-tier limit) via a sliding-window rate limiter and `asyncio.Semaphore(4)`
- Hard timeout of **15 seconds** for the entire VT phase
- Returns verdicts: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN`

Only up to **20** hashes are queried per scan, **prioritized by baseline threat score**.

### `detector/whitelist.py`

JSON-based whitelist:

- `whitelist.json` holds:
  - `trusted_processes` (executable name patterns, with wildcards)
  - `trusted_paths` (path patterns, with wildcards)
- `is_whitelisted()` checks both process name and path (using `fnmatch`)
- `add_to_whitelist()` lets the user add new process/path patterns (used by the GUI right-click menu)

Whitelisted items are **excluded from scoring** to reduce false positives.

### `detector/scorer.py`

Assigns risk scores to flagged items using simple rules:

- `+2` for keyboard hook indicators
- `+2` for TEMP/APPDATA (or suspicious startup locations)
- `+1` for no visible window
- `+1` for suspicious name patterns  

Then it classifies each item as **HIGH**, **MEDIUM**, or **LOW**, sorts threats by score, and preserves:

- `name`, `pid`, `path`
- `vt_verdict`, `yara_severity`
- `reasons` explaining why it was scored

### `gui/dashboard.py`

Animated Tkinter dashboard:

- **5 progress bars** (process, registry, hook, YARA, VirusTotal)
- Scan button shows a **countdown**: `Scanning... (Xs remaining)`
- Populates the threat table as results come in; new rows flash for ~500ms
- Right-click on a row → “Add to whitelist (false positive)”
- Displays a banner: **“Scan complete in Xs — N threats found”**

### `reports/report_gen.py`

Generates a color-coded PDF report containing:

- Title
- Scan date/time
- Summary table of threats (with HIGH/MEDIUM/LOW indicators)
- Footer: “Educational purposes only”

## Disclaimer

This project is for **educational and defensive use only**. The detection logic is **heuristic** and may produce **false positives** or **false negatives**. It is not a substitute for professional security tools or incident response. Always validate findings safely and responsibly.
