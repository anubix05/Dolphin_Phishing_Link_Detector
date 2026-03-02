"""
apis/heuristics.py – Local Heuristic Analysis Engine

Analyses URL structure and lexical signals to produce a normalized
safety score (1–100) without making any external API calls.

Each check returns a HeuristicFlag with:
  - name        : short label
  - description : human-readable explanation
  - penalty     : 0–100 severity weight

The final score uses exponential decay over the accumulated penalty so
that a handful of serious flags strongly reduces the score while a
cluster of minor flags doesn't trivially reach 1.

No API key required.
"""

import math
import re
from typing import NamedTuple
from urllib.parse import urlparse


# ── Known brand names to watch for subdomain / lookalike abuse ────────────────
BRAND_KEYWORDS = {
    "paypal", "google", "facebook", "microsoft", "apple", "amazon",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
    "wellsfargo", "bankofamerica", "citibank", "ebay", "steam",
    "spotify", "discord", "whatsapp", "telegram", "yahoo", "outlook",
    "office365", "onedrive", "icloud", "coinbase", "binance",
}

# ── TLDs heavily abused in phishing / spam campaigns ─────────────────────────
SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "top",
    "work", "click", "link", "zip", "review", "country", "kim",
    "science", "party", "gdn", "stream", "download", "racing",
    "win", "loan", "date", "faith", "trade", "accountant", "icu",
    "buzz", "vip", "club", "live",
}

# ── Known URL-shortener hostnames ─────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bc.vc", "j.mp", "tiny.cc", "lnkd.in",
    "db.tt", "qr.ae", "po.st", "1url.com", "hyperurl.co", "rb.gy",
    "shorturl.at", "cutt.ly", "rebrand.ly", "snip.ly",
}

# ── Social-engineering / credential-harvesting keywords ──────────────────────
PHISHING_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm",
    "password", "credential", "banking", "wallet", "recover",
    "unlock", "suspended", "unusual", "validate", "authenticate",
    "invoice", "receipt", "billing", "payment", "refund",
    "webscr", "cmd=", "dispatch=", "token=",
}

# ── Executable / archive extensions commonly delivered via phishing links ─────
SUSPICIOUS_EXTS = {
    ".exe", ".bat", ".scr", ".cmd", ".vbs", ".js", ".jar",
    ".msi", ".pif", ".reg", ".ps1", ".hta", ".wsf",
}

# ── Path segments used in open-redirect / click-tracking chains ──────────────
REDIRECT_PATTERNS = [
    "/redirect", "/click", "/go/", "/out/", "/track/", "/r/",
    "url=http", "return=http", "next=http", "redir=",
]


# ── Data type ─────────────────────────────────────────────────────────────────
class HeuristicFlag(NamedTuple):
    name: str
    description: str
    penalty: int  # severity weight (cumulative total drives score)


# ── Individual checks ─────────────────────────────────────────────────────────
def _run_checks(url: str) -> list[HeuristicFlag]:
    flags: list[HeuristicFlag] = []

    # Ensure the URL has a scheme so urlparse works correctly
    normalised = url if url.startswith(("http://", "https://")) else "http://" + url
    parsed = urlparse(normalised)

    host       = (parsed.hostname or "").lower()
    path       = (parsed.path    or "").lower()
    query      = (parsed.query   or "").lower()
    netloc     = (parsed.netloc  or "").lower()
    full_lower = normalised.lower()
    parts      = host.split(".")

    # 1 ── IP address used as host ─────────────────────────────────────────────
    ip_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ip_re.match(host):
        flags.append(HeuristicFlag(
            "IP address as host",
            "A raw IP is used instead of a domain name. Legitimate services "
            "almost never use bare IPs in public-facing URLs.",
            40,
        ))

    # 2 ── URL length ──────────────────────────────────────────────────────────
    url_len = len(url)
    if url_len > 150:
        flags.append(HeuristicFlag(
            "Excessive URL length",
            f"URL is {url_len} characters long. Phishing links are often "
            "padded with noise to confuse filters.",
            18,
        ))
    elif url_len > 100:
        flags.append(HeuristicFlag(
            "Long URL",
            f"URL is {url_len} characters long (moderately suspicious).",
            8,
        ))

    # 3 ── '@' symbol in URL ───────────────────────────────────────────────────
    if "@" in normalised:
        flags.append(HeuristicFlag(
            "'@' symbol in URL",
            "Browsers ignore everything before '@' in a URL. Attackers use "
            "this to disguise the real destination.",
            45,
        ))

    # 4 ── Double slash in path ────────────────────────────────────────────────
    if "//" in path:
        flags.append(HeuristicFlag(
            "Double slash in path",
            "Extra slash sequences in the path can bypass naive pattern matching.",
            10,
        ))

    # 5 ── Percent-encoding in the hostname ────────────────────────────────────
    if "%" in netloc:
        flags.append(HeuristicFlag(
            "Hex/percent-encoding in hostname",
            "Percent-encoded characters in the hostname obfuscate the real domain.",
            35,
        ))

    # 6 ── Punycode / IDN homograph attack ────────────────────────────────────
    if "xn--" in host:
        flags.append(HeuristicFlag(
            "IDN / Punycode domain",
            "Internationalised domain names (e.g. xn--pypal-4ve.com ≈ 'pȧypal') "
            "are used in homograph spoofing attacks.",
            30,
        ))

    # 7 ── Excessive subdomain depth ──────────────────────────────────────────
    subdomain_depth = len(parts) - 2  # e.g. a.b.c.com → depth 2
    if subdomain_depth >= 3:
        flags.append(HeuristicFlag(
            "Excessive subdomain depth",
            f"Domain has {subdomain_depth} subdomain levels. Attackers nest "
            "brand names deep in the hierarchy to simulate legitimacy.",
            20,
        ))

    # 8 ── Hyphen count in domain ──────────────────────────────────────────────
    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        flags.append(HeuristicFlag(
            "Many hyphens in domain",
            f"Domain contains {hyphen_count} hyphens — a common trait of "
            "algorithmically generated phishing domains.",
            18,
        ))

    # 9 ── Suspicious TLD ──────────────────────────────────────────────────────
    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(HeuristicFlag(
            f"Suspicious TLD (.{tld})",
            f"'.{tld}' is disproportionately used in phishing and spam.",
            22,
        ))

    # 10 ── Known URL-shortener service ───────────────────────────────────────
    if host in URL_SHORTENERS:
        flags.append(HeuristicFlag(
            "URL shortener service",
            "The real destination is hidden behind a shortening service, a "
            "frequent phishing delivery technique.",
            22,
        ))

    # 11 ── Brand name abused in subdomain ────────────────────────────────────
    subdomains_str = ".".join(parts[:-2]) if len(parts) > 2 else ""
    found_brands = [b for b in BRAND_KEYWORDS if b in subdomains_str]
    if found_brands:
        flags.append(HeuristicFlag(
            "Brand name in subdomain",
            f"'{', '.join(found_brands[:3])}' appears in the subdomain, not "
            "the registered domain — a classic impersonation trick.",
            35,
        ))

    # 12 ── Phishing keywords in path / query ─────────────────────────────────
    combined = path + " " + query
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in combined]
    if found_kw:
        penalty = min(30, 8 * len(found_kw))
        flags.append(HeuristicFlag(
            "Phishing keywords in URL",
            f"Suspicious terms detected: {', '.join(found_kw[:6])}.",
            penalty,
        ))

    # 13 ── Non-standard port ─────────────────────────────────────────────────
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        flags.append(HeuristicFlag(
            "Non-standard port",
            f"Port {parsed.port} is unusual for a web service. Legitimate "
            "sites almost always use 80 or 443.",
            18,
        ))

    # 14 ── Suspicious file extension in path ─────────────────────────────────
    path_no_qs = path.split("?")[0]
    matched_ext = next((e for e in SUSPICIOUS_EXTS if path_no_qs.endswith(e)), None)
    if matched_ext:
        flags.append(HeuristicFlag(
            f"Suspicious file extension ({matched_ext})",
            "URL points directly to an executable or script — a hallmark of "
            "malware delivery links.",
            40,
        ))

    # 15 ── Digit–letter mixing in registered domain (l33t-speak / typosquat) ─
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    rd_alphanum = registered_domain.replace(".", "").replace("-", "")
    leet_hits = len(re.findall(r"(?<=[a-z])\d|\d(?=[a-z])", rd_alphanum))
    if leet_hits >= 2:
        flags.append(HeuristicFlag(
            "Digit–letter mixing in domain",
            "Digits mixed into domain letters suggest typosquatting or "
            "l33t-speak impersonation (e.g. g00gle, paypа1).",
            18,
        ))

    # 16 ── Open-redirect / click-tracking patterns ───────────────────────────
    if any(p in full_lower for p in REDIRECT_PATTERNS):
        flags.append(HeuristicFlag(
            "Redirect/tracking pattern",
            "URL contains path segments commonly used in open-redirect or "
            "click-tracking chains that conceal the final destination.",
            18,
        ))

    # 17 ── Scheme is plain HTTP (not HTTPS) ──────────────────────────────────
    if parsed.scheme == "http":
        flags.append(HeuristicFlag(
            "Unencrypted HTTP scheme",
            "Connection is not encrypted. Almost all legitimate modern sites "
            "use HTTPS.",
            10,
        ))

    # 18 ── Counts of dots in the full path (many = obfuscation) ──────────────
    dot_count_path = path.count(".")
    if dot_count_path >= 5:
        flags.append(HeuristicFlag(
            "Excessive dots in path",
            f"Path contains {dot_count_path} dots, which may indicate "
            "directory traversal obfuscation or a heavily disguised file name.",
            12,
        ))

    return flags


# ── Score calculation ─────────────────────────────────────────────────────────
def _compute_score(flags: list[HeuristicFlag]) -> int:
    """
    Convert accumulated penalty points to a 1–100 safety score using
    exponential decay.  Chosen constant k so that:
      - penalty = 0   → score ≈ 100  (clean)
      - penalty = 50  → score ≈ 32   (suspicious)
      - penalty = 100 → score ≈ 10   (highly suspicious)
    """
    total_penalty = sum(f.penalty for f in flags)
    k = 0.023
    score = 100.0 * math.exp(-k * total_penalty)
    return max(1, min(100, int(round(score))))


# ── Public interface ──────────────────────────────────────────────────────────
def check(url: str) -> dict:
    """
    Run all heuristic checks on *url*.

    Returns
    -------
    {
        "score"  : int   1–100 (100 = no red flags detected),
        "source" : "Heuristics",
        "flags"  : [{"name": str, "description": str, "penalty": int}, ...]
    }
    """
    flags = _run_checks(url)
    score = _compute_score(flags)
    return {
        "score": score,
        "source": "Heuristics",
        "flags": [
            {"name": f.name, "description": f.description, "penalty": f.penalty}
            for f in flags
        ],
    }
