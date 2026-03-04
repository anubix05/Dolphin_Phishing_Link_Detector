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
import threading
import concurrent.futures

from flask import Flask, request, Response, render_template, jsonify
from twilio.twiml.messaging_response import MessagingResponse  # type: ignore[import-untyped]
from twilio.rest import Client as TwilioClient                 # type: ignore[import-untyped]

# ── API modules ────────────────────────────────────────────────────────────────
from apis.virustotal           import check as vt_check
from apis.urlscan              import check as us_check
from apis.google_safe_browsing import check as gsb_check
from apis.heuristics           import check as heuristics_check
from apis.checkphish           import check as cp_check

# ── Internal modules ───────────────────────────────────────────────────────────
from scoring import build_report
from config import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER

app = Flask(__name__)

# ── Twilio REST client (used to send replies asynchronously) ───────────────────
twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# ── Helpers ────────────────────────────────────────────────────────────────────
URL_REGEX = re.compile(
    r"https?://[^\s]+"          # http / https URLs
    r"|www\.[^\s]+"             # bare www. URLs
    , re.IGNORECASE
)

API_CHECKS = [vt_check, us_check, gsb_check, cp_check]


def extract_url(text: str) -> str | None:
    """Return the first URL found in *text*, or None."""
    match = URL_REGEX.search(text)
    return match.group(0) if match else None


def run_all_checks(url: str) -> list[dict]:
    """
    Run heuristic analysis first (instant, local), then fire the
    external API checks concurrently.  Returns the combined list of results.
    Failed checks are excluded (logged to stderr).
    """
    results: list[dict] = []

    # ── Step 1: Heuristic analysis (runs locally, no network) ────────────────
    try:
        heuristic_result = heuristics_check(url)
        if heuristic_result is not None:
            results.append(heuristic_result)
    except Exception as exc:
        print(f"[ERROR] heuristics raised an exception: {exc}")

    # ── Step 2: External API checks (concurrent) ────────────────────────────
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


# ── Web UI ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    """Serve the chatbot-style web interface."""
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    """
    JSON API for the web UI (no Twilio involved).

    Expects: { "url": "https://example.com" }
    Returns: { "report": "..." } or { "error": "..." }
    """
    data = request.get_json(silent=True) or {}
    raw  = data.get("url", "").strip()

    url = extract_url(raw)
    if not url:
        return jsonify({"error": "I couldn't find a valid URL. Please send a link starting with http:// or https://"})

    results = run_all_checks(url)

    if not results:
        return jsonify({"error": "All safety checks failed. Please try again later."})

    report = build_report(url, results)
    return jsonify({"report": report})


# ── Webhook ────────────────────────────────────────────────────────────────────

def _process_and_reply(url: str, sender: str) -> None:
    """Run all checks in a background thread and send the result via Twilio REST API."""
    results = run_all_checks(url)

    if not results:
        body = "❌ All safety checks failed. Please try again later."
    else:
        body = build_report(url, results)

    try:
        twilio_client.messages.create(
            body=body,
            from_=TWILIO_WHATSAPP_NUMBER,
            to=sender,
        )
    except Exception as exc:
        print(f"[ERROR] Failed to send WhatsApp reply: {exc}")


@app.route("/webhook", methods=["POST"])
def webhook():
    incoming_msg = request.form.get("Body", "").strip()
    sender       = request.form.get("From", "")

    resp = MessagingResponse()

    url = extract_url(incoming_msg)
    if not url:
        # No URL found – reply inline (instant, no API calls needed)
        msg = resp.message()
        msg.body(
            "⚠️ I couldn't find a URL in your message.\n"
            "Please send a link starting with http:// or https://"
        )
        return Response(str(resp), mimetype="application/xml")

    # Acknowledge immediately so Twilio doesn't time out,
    # then run the heavy API checks in a background thread.
    thread = threading.Thread(target=_process_and_reply, args=(url, sender))
    thread.start()

    # Return empty TwiML so Twilio gets a 200 within its timeout window
    return Response(str(resp), mimetype="application/xml")


# ── Dev server ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
