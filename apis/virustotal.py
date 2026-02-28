"""
apis/virustotal.py

TODO: Replace the stub below with real VirusTotal API logic.

Real implementation steps:
1. Submit the URL to VirusTotal using the /urls endpoint.
2. Poll or retrieve the analysis report.
3. Calculate score from malicious/total engine votes.
4. Normalize to 0–100 (100 = fully safe).

API Docs: https://developers.virustotal.com/reference/overview
"""

# TODO: Remove this stub import once real logic is implemented
import random

from config import VIRUSTOTAL_API_KEY  # noqa: F401  (will be used in real impl)


def check(url: str) -> dict:
    """
    Check a URL against VirusTotal.

    Parameters
    ----------
    url : str  –  the URL to analyse

    Returns
    -------
    dict with keys:
        'score'  : int  0-100  (100 = safe, 0 = malicious)
        'source' : str  always "VirusTotal"

    TODO: Replace stub body with real API call.
    """
    # ── STUB – returns a random score for development/testing ─────────────────
    # Remove the two lines below and add real API logic here.
    stub_score = random.randint(0, 100)
    return {"score": stub_score, "source": "VirusTotal"}
    # ─────────────────────────────────────────────────────────────────────────

# virustotal 