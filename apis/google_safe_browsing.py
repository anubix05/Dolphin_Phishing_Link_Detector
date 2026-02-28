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

# TODO: Remove this stub import once real logic is implemented
import random

from config import GOOGLE_SAFE_BROWSING_API_KEY  # noqa: F401  (will be used in real impl)


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
    # ── STUB – returns a random score for development/testing ─────────────────
    # Remove the two lines below and add real API logic here.
    stub_score = random.randint(0, 100)
    return {"score": stub_score, "source": "Google Safe Browsing"}
    # ─────────────────────────────────────────────────────────────────────────
