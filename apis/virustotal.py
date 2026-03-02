"""apis/virustotal.py

Minimal VirusTotal v3 integration used by the project.

This module submits a URL to VirusTotal, polls the analysis until
completion (within a short timeout), then computes a normalized
score between 1 and 100 where 100 = fully safe and 1 = fully
malicious (conservative fallback on errors).

Notes
-----
- Requires `VIRUSTOTAL_API_KEY` defined in the project's `config.py`.
- Uses the public v3 API: POST /urls then GET /analyses/{id}.
"""

import time
from typing import Dict

import requests

from config import VIRUSTOTAL_API_KEY


VT_BASE = "https://www.virustotal.com/api/v3"


def _post_url(url: str) -> str:
    """Submit a URL for analysis and return the analysis id.

    Raises requests.HTTPError on non-2xx responses.
    """
    endpoint = f"{VT_BASE}/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    resp = requests.post(endpoint, headers=headers, data={"url": url}, timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return data.get("id")


def _get_analysis(analysis_id: str) -> Dict:
    endpoint = f"{VT_BASE}/analyses/{analysis_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    resp = requests.get(endpoint, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _normalize_score(malicious: int, total: int) -> int:
    """Return a score 1..100 where more malicious -> lower score.

    If total is zero, return a conservative neutral score (50).
    """
    if total <= 0:
        return 50
    ratio_malicious = malicious / total
    score = int(round((1.0 - ratio_malicious) * 100))
    # Clamp to 1..100
    score = max(1, min(100, score))
    return score


def check(url: str) -> dict:
    """Check `url` using VirusTotal and return standardized dict.

    Returns
    -------
    {"score": int(1-100), "source": "VirusTotal"}

    On errors we return a conservative score of 1.
    """
    fallback = {"score": 1, "source": "VirusTotal"}

    if not VIRUSTOTAL_API_KEY:
        return fallback

    try:
        analysis_id = _post_url(url)
        if not analysis_id:
            return fallback

        # Poll until status == 'completed' or timeout reached
        timeout = 30
        interval = 1
        elapsed = 0
        while elapsed < timeout:
            analysis = _get_analysis(analysis_id)
            attrs = analysis.get("data", {}).get("attributes", {})
            status = attrs.get("status")
            if status == "completed":
                stats = attrs.get("stats", {}) or {}
                # stats typically contains counts for harmless/malicious/etc.
                total = sum(v for v in stats.values() if isinstance(v, int))
                malicious = int(stats.get("malicious", 0))
                score = _normalize_score(malicious, total)
                return {"score": score, "source": "VirusTotal"}

            time.sleep(interval)
            elapsed += interval

        # If polling timed out, attempt to compute from whatever we have
        analysis = _get_analysis(analysis_id)
        attrs = analysis.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {}) or {}
        total = sum(v for v in stats.values() if isinstance(v, int))
        malicious = int(stats.get("malicious", 0))
        score = _normalize_score(malicious, total)
        return {"score": score, "source": "VirusTotal"}

    except Exception:
        return fallback

