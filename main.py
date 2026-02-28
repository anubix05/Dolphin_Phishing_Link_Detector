"""
main.py – Twilio WhatsApp webhook entry point.

Responsibilities
----------------
1. Receive incoming WhatsApp messages via Twilio webhook (POST /webhook).
2. Extract the URL from the message body.
3. Call all API modules concurrently.
4. Collect and average the normalized scores.
5. Classify the result and send a WhatsApp reply.
"""

import re
import concurrent.futures

from flask import Flask, request, Response
from twilio.twiml.messaging_response import MessagingResponse  # type: ignore[import-untyped]

# ── API modules ────────────────────────────────────────────────────────────────
from apis.virustotal           import check as vt_check
from apis.urlscan              import check as us_check
from apis.google_safe_browsing import check as gsb_check

# ── Internal modules ───────────────────────────────────────────────────────────
from scoring import build_report

app = Flask(__name__)

# ── Helpers ────────────────────────────────────────────────────────────────────
URL_REGEX = re.compile(
    r"https?://[^\s]+"          # http / https URLs
    r"|www\.[^\s]+"             # bare www. URLs
    , re.IGNORECASE
)

API_CHECKS = [vt_check, us_check, gsb_check]


def extract_url(text: str) -> str | None:
    """Return the first URL found in *text*, or None."""
    match = URL_REGEX.search(text)
    return match.group(0) if match else None


def run_all_checks(url: str) -> list[dict]:
    """
    Run every API check concurrently and return the list of results.
    Failed checks are excluded (logged to stderr).
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(fn, url): fn.__module__ for fn in API_CHECKS}
        for future in concurrent.futures.as_completed(futures):
            module_name = futures[future]
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as exc:
                print(f"[ERROR] {module_name} raised an exception: {exc}")
    return results


# ── Webhook ────────────────────────────────────────────────────────────────────
@app.route("/webhook", methods=["POST"])
def webhook():
    incoming_msg = request.form.get("Body", "").strip()
    sender       = request.form.get("From", "")

    resp = MessagingResponse()
    msg  = resp.message()

    url = extract_url(incoming_msg)
    if not url:
        msg.body(
            "⚠️ I couldn't find a URL in your message.\n"
            "Please send a link starting with http:// or https://"
        )
        return Response(str(resp), mimetype="application/xml")

    results = run_all_checks(url)

    if not results:
        msg.body(
            "❌ All safety checks failed. Please try again later."
        )
        return Response(str(resp), mimetype="application/xml")

    report = build_report(url, results)
    msg.body(report)
    return Response(str(resp), mimetype="application/xml")


# ── Dev server ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
