"""
apis/checkphish.py – CheckPhish (by Bolster) API integration.

Submits a URL for scanning, polls for the result, then maps the
verdict to a normalized safety score (0–100, where 100 = safe).

API Docs: https://checkphish.bolster.ai/docs
"""

import time
import requests

from config import CHECKPHISH_API_KEY

CHECKPHISH_SCAN_URL = "https://developers.checkphish.ai/api/neo/scan"
CHECKPHISH_STATUS_URL = "https://developers.checkphish.ai/api/neo/scan/status"

# ── Verdict → safety score mapping ───────────────────────────────────────────
# CheckPhish returns a disposition string.  We map each known verdict
# to a safety score on the 0-100 scale (100 = fully safe).
VERDICT_SCORES = {
    "clean":                100,
    "no_phishing":          100,
    "benign":               100,
    "likely_phish":          15,
    "phish":                  0,
    "phishing":               0,
    "suspicious":            30,
    "adult":                 50,
    "cryptojacking":         10,
    "drug_spam":             20,
    "gambling":              50,
    "hacked_website":        10,
    "malware":                0,
    "scam":                   5,
    "spam":                  30,
    "streaming":             60,
    "tech_support_scam":      5,
}


def check(url: str) -> dict:
    """
    Check *url* against the CheckPhish API.

    Returns
    -------
    {
        "score"  : int   0–100  (100 = safe),
        "source" : "CheckPhish"
    }
    """
    fallback = {"score": 50, "source": "CheckPhish"}

    if not CHECKPHISH_API_KEY:
        return fallback

    headers = {"Content-Type": "application/json"}

    # ── Step 1: Submit URL for scanning ──────────────────────────────────────
    try:
        scan_payload = {
            "apiKey": CHECKPHISH_API_KEY,
            "urlInfo": {"url": url},
            "scanType": "full",
        }
        post_resp = requests.post(
            CHECKPHISH_SCAN_URL, json=scan_payload, headers=headers, timeout=15
        )
        post_resp.raise_for_status()
        job_id = post_resp.json().get("jobID")
        if not job_id:
            return fallback
    except Exception:
        return fallback

    # ── Step 2: Poll for results (up to ~40 seconds) ─────────────────────────
    status_payload = {
        "apiKey": CHECKPHISH_API_KEY,
        "jobID": job_id,
        "insights": True,
    }

    try:
        for _ in range(20):
            time.sleep(2)
            status_resp = requests.post(
                CHECKPHISH_STATUS_URL, json=status_payload, headers=headers, timeout=15
            )
            status_resp.raise_for_status()
            data = status_resp.json()
            job_status = data.get("status", "").lower()

            if job_status == "done":
                disposition = (data.get("disposition") or "").lower().strip()
                score = VERDICT_SCORES.get(disposition, 50)
                return {"score": score, "source": "CheckPhish"}

        # Polling timed out
        return fallback

    except Exception:
        return fallback
