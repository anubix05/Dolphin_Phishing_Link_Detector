"""
apis/google_safe_browsing.py

TODO: Replace the stub below with real Google Safe Browsing API logic.

Real implementation steps:
1. POST to https://safebrowsing.googleapis.com/v4/threatMatches:find
2. Include threatTypes: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, etc.
3. If any threat matches are returned → threat detected (score = 0).
4. If no matches → clean (score = 100).
   Optionally interpolate a mid-range score based on threat type severity.

API Docs: https://developers.google.com/safe-browsing/v4/lookup-api
"""

import requests

from config import GOOGLE_SAFE_BROWSING_API_KEY  # noqa: F401  (used below)


def check(url: str) -> dict:
    """
    Check a URL against Google Safe Browsing.

    Parameters
    ----------
    url : str  –  the URL to analyse

    Returns
    -------
    dict with keys:
        'score'  : int  0-100  (100 = safe, 0 = malicious)
        'source' : str  always "Google Safe Browsing"

    TODO: Replace stub body with real API call.
    """
    # ── REAL IMPLEMENTATION ─────────────────────────────────────────────────
    # Build request payload according to Google Safe Browsing API documentation.
    api_url = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "dolphin-phishing-bot",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(api_url, json=payload, timeout=10)
        resp.raise_for_status()
    except requests.RequestException:
        # In case of network or API errors we fall back to conservative score of 50
        return {"score": 50, "source": "Google Safe Browsing"}

    data = resp.json()
    # If any matches are returned, treat URL as malicious.
    if data.get("matches"):
        score = 0
    else:
        score = 100

    return {"score": score, "source": "Google Safe Browsing"}
    # ─────────────────────────────────────────────────────────────────────────
