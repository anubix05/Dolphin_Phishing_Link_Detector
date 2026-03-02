"""
apis/urlscan.py

TODO: Replace the stub below with real URLScan.io API logic.

Real implementation steps:
1. Submit the URL for scanning via POST /api/v1/scan/.
2. Wait for the scan to complete (poll GET /api/v1/result/{uuid}/).
3. Parse the 'verdicts.overall.score' or malicious/suspicious flags.
4. Normalize to 0–100 (100 = fully safe).

API Docs: https://urlscan.io/docs/api/
"""

import time
import requests

from config import URLSCAN_API_KEY  # noqa: F401  (will be used in real impl)


def check(url: str) -> dict:
    """
    Check a URL against URLScan.io.

    Parameters
    ----------
    url : str  –  the URL to analyse

    Returns
    -------
    dict with keys:
        'score'  : int  0-100  (100 = safe, 0 = malicious)
        'source' : str  always "URLScan"

    TODO: Replace stub body with real API call.
    """
    # ── REAL IMPLEMENTATION ──────────────────────────────────────────────────
    # Submit the URL for scanning.
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {"url": url, "visibility": "public"}

    try:
        post_resp = requests.post(
            "https://urlscan.io/api/v1/scan/", headers=headers, json=payload, timeout=15
        )
        post_resp.raise_for_status()
        post_data = post_resp.json()
        uuid = post_data.get("uuid")

        # poll for result
        result = None
        for _ in range(15):  # try for up to ~15 seconds
            get_resp = requests.get(
                f"https://urlscan.io/api/v1/result/{uuid}/", headers=headers, timeout=15
            )
            if get_resp.status_code == 200:
                result = get_resp.json()
                break
            time.sleep(1)

        if not result:
            # couldn't fetch result in time
            return {"score": 0, "source": "URLScan"}

        # extract score if available
        score_val = (
            result.get("verdicts", {})
            .get("overall", {})
            .get("score")
        )

        score = 50
        if isinstance(score_val, (int, float)):
            # most likely a 0..1 float or 0..100 int
            if 0 <= score_val <= 1:
                score = int(score_val * 100)
            else:
                score = int(score_val)
        # clamp
        score = max(0, min(100, score))
        return {"score": score, "source": "URLScan"}

    except Exception:
        # on any failure treat as malicious/unknown
        return {"score": 0, "source": "URLScan"}
    # ─────────────────────────────────────────────────────────────────────────
