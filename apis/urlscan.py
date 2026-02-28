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

# TODO: Remove this stub import once real logic is implemented
import random

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
    # ── STUB – returns a random score for development/testing ─────────────────
    # Remove the two lines below and add real API logic here.
    stub_score = random.randint(0, 100)
    return {"score": stub_score, "source": "URLScan"}
    # ─────────────────────────────────────────────────────────────────────────
