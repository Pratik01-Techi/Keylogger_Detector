from __future__ import annotations

"""
Educational use only disclaimer:
This project is for defensive/educational use. VirusTotal lookups and scoring are
heuristic aids and should not be treated as definitive malware identification.
"""

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_ENV_PATH = os.path.join(PROJECT_ROOT, ".env")

DISCLAIMER_NOTE = "Educational use only"


def sha256_of_file(file_path: str, chunk_size: int = 1024 * 1024) -> Optional[str]:
    """
    Compute SHA-256 for a local file.

    Returns None if the file cannot be read.
    """
    if not file_path or not os.path.isfile(file_path):
        return None

    try:
        digest = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def _load_vt_api_key(env_path: str = DEFAULT_ENV_PATH, env_var: str = "VT_API_KEY") -> Optional[str]:
    if load_dotenv is None:
        return os.getenv(env_var)

    try:
        load_dotenv(env_path)
    except Exception:
        # Fall back to environment variables.
        pass

    return os.getenv(env_var)


def _verdict_from_vt_stats(stats: Dict[str, Any]) -> str:
    """
    Map VirusTotal's `last_analysis_stats` into CLEAN/SUSPICIOUS/MALICIOUS.
    """
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)

    if malicious > 0:
        return "MALICIOUS"
    if suspicious > 0:
        return "SUSPICIOUS"
    if harmless > 0 or undetected > 0:
        return "CLEAN"
    return "CLEAN"


@dataclass
class VirusTotalClient:
    """
    Minimal VirusTotal v3 client with caching and rate limiting.
    """

    api_key: Optional[str] = None
    min_interval_s: float = 15.0  # 4 requests/min => 60/4 seconds

    def __post_init__(self) -> None:
        self._cache: Dict[str, str] = {}
        self._last_request_ts: float = 0.0
        self._session = requests.Session() if requests is not None else None

        if self.api_key is None:
            self.api_key = _load_vt_api_key()

    def is_configured(self) -> bool:
        return bool(self.api_key) and self._session is not None

    def _respect_rate_limit(self) -> None:
        if not self._last_request_ts:
            return
        elapsed = time.time() - self._last_request_ts
        if elapsed < self.min_interval_s:
            time.sleep(self.min_interval_s - elapsed)

    def get_verdict_for_sha256(self, sha256: str) -> str:
        """
        Query VirusTotal for a SHA-256 and return CLEAN/SUSPICIOUS/MALICIOUS/UNKNOWN.
        """
        sha = (sha256 or "").strip().lower()
        if not sha:
            return "UNKNOWN"

        if sha in self._cache:
            return self._cache[sha]

        if not self.is_configured():
            return "UNKNOWN"

        self._respect_rate_limit()
        headers = {"x-apikey": self.api_key}  # type: ignore[arg-type]
        url = f"https://www.virustotal.com/api/v3/files/{sha}"

        try:
            resp = self._session.get(url, headers=headers, timeout=20)  # type: ignore[union-attr]
            self._last_request_ts = time.time()
        except Exception:
            self._last_request_ts = time.time()
            return "UNKNOWN"

        # Handle rate-limiting responses.
        if resp.status_code == 429:
            try:
                retry_after = int(resp.headers.get("Retry-After") or "0")
                if retry_after > 0:
                    time.sleep(retry_after)
            except Exception:
                pass
            self._last_request_ts = time.time()
            verdict = "UNKNOWN"
            self._cache[sha] = verdict
            return verdict

        if resp.status_code < 200 or resp.status_code >= 300:
            verdict = "UNKNOWN"
            self._cache[sha] = verdict
            return verdict

        try:
            data = resp.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            verdict = _verdict_from_vt_stats(stats)
        except Exception:
            verdict = "UNKNOWN"

        self._cache[sha] = verdict
        return verdict

