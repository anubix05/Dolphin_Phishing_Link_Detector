"""
apis/urlscan.py

URLScan.io integration for the phishing-link detection bot.

Implementation:
1. Submit the URL for scanning via POST /api/v1/scan/.
2. Wait for the scan to complete (poll GET /api/v1/result/{uuid}/).
3. Parse 'verdicts.overall' – score (0-100 maliciousness) and malicious flag.
4. Invert to a safety score 0–100 (100 = fully safe).

API Docs: https://urlscan.io/docs/api/
"""

import time
import requests

from config import URLSCAN_API_KEY


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
    """
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {"url": url, "visibility": "public"}

    try:
        # ── Submit the URL for scanning ──────────────────────────────────────
        post_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers, json=payload, timeout=15,
        )

        # Some URLs (e.g. google.com) are blocked from scanning → treat as neutral
        if post_resp.status_code == 400:
            return {"score": 50, "source": "URLScan"}

        post_resp.raise_for_status()
        uuid = post_resp.json().get("uuid")
        if not uuid:
            return {"score": 50, "source": "URLScan"}

        # ── Poll for the result (up to ~40 seconds) ─────────────────────────
        result = None
        for _ in range(20):
            time.sleep(2)
            get_resp = requests.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                headers=headers, timeout=15,
            )
            if get_resp.status_code == 200:
                result = get_resp.json()
                break

        if not result:
            # Scan didn't finish in time – return neutral
            return {"score": 50, "source": "URLScan"}

        # ── Interpret the verdict ───────────────────────────────────────────
        overall = result.get("verdicts", {}).get("overall", {})
        malicious_flag = overall.get("malicious", False)

        # URLScan's 'score' is a MALICIOUSNESS score (0 = benign, 100 = bad).
        # We invert it:  safety_score = 100 - maliciousness_score
        maliciousness = overall.get("score", 0)
        if not isinstance(maliciousness, (int, float)):
            maliciousness = 0

        safety_score = 100 - int(maliciousness)

        # If the explicit malicious flag is set, cap at 10
        if malicious_flag:
            safety_score = min(safety_score, 10)

        # Clamp 0–100
        safety_score = max(0, min(100, safety_score))
        return {"score": safety_score, "source": "URLScan"}

    except Exception:
        # On network / unexpected errors → neutral fallback
        return {"score": 50, "source": "URLScan"}
