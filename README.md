# 🐬 Dolphin – Phishing Link Detection WhatsApp Chatbot

A modular phishing link detection system that analyses URLs using multiple security APIs and a built-in heuristic engine. Available as a **WhatsApp chatbot** (via Twilio) and a **web chat UI**.

---

## ✨ Features

- **Multi-API Detection** – Queries 5 independent sources for every URL: VirusTotal, URLScan.io, Google Safe Browsing, CheckPhish, and a local heuristic engine.
- **Weighted Scoring** – Each source has a priority weight so that higher-trust databases (e.g. Google Safe Browsing) influence the final score more.
- **18-Check Heuristic Engine** – Instant, offline structural analysis that catches IP-as-host, brand impersonation, suspicious TLDs, phishing keywords, URL shorteners, and more.
- **Async WhatsApp Replies** – Background threading ensures Twilio's 15-second webhook timeout is never exceeded.
- **Concurrent API Calls** – External checks run in parallel via `ThreadPoolExecutor` to minimize response time.
- **Web Chat Interface** – Browser-based dark/light theme chat UI at the root URL.
- **Graceful Degradation** – Failed APIs are excluded from scoring; users are notified if all checks fail.
- **Easy Extensibility** – Add a new detection API by creating one file and registering it.

---

## 📁 Project Structure

```
project/
├── main.py                        # Flask app, webhook, web API
├── config.py                      # API keys, weights, thresholds
├── scoring.py                     # Score calculation, classification, report
├── requirements.txt               # Python dependencies
├── AGENTS.md                      # Agent instructions / project spec
├── DOCUMENTATION.txt              # Full project documentation
├── README.md                      # This file
│
├── apis/
│   ├── virustotal.py              # VirusTotal v3 integration
│   ├── urlscan.py                 # URLScan.io integration
│   ├── google_safe_browsing.py    # Google Safe Browsing v4 integration
│   ├── checkphish.py              # CheckPhish (Bolster) integration
│   └── heuristics.py              # Local heuristic analysis (18 checks)
│
├── templates/
│   └── index.html                 # Web chat UI
│
└── static/                        # Static assets
```

---

## 🚀 Setup & Running

### Prerequisites

- Python 3.10+
- API keys for: Twilio, VirusTotal, URLScan, Google Safe Browsing, CheckPhish
- [ngrok](https://ngrok.com/) (for WhatsApp webhook)

### Installation

```bash
pip install -r requirements.txt
```

### Configuration

Set API keys either as **environment variables** or edit the defaults in `config.py`:

| Variable | Service |
|---|---|
| `TWILIO_ACCOUNT_SID` | Twilio |
| `TWILIO_AUTH_TOKEN` | Twilio |
| `TWILIO_WHATSAPP_NUMBER` | Twilio |
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `URLSCAN_API_KEY` | URLScan.io |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing |
| `CHECKPHISH_API_KEY` | CheckPhish |

### Run the Server

```bash
python main.py
```

Server starts on `http://localhost:5000`.

### WhatsApp Setup

1. Expose port 5000 via ngrok:
   ```bash
   ngrok http 5000
   ```
2. Copy the HTTPS URL from ngrok.
3. In the Twilio Console → Messaging → WhatsApp Sandbox, set the webhook to:
   ```
   https://<ngrok-id>.ngrok.io/webhook
   ```

### Web UI

Open `http://localhost:5000` in a browser.

---

## 🔌 API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web chat UI |
| `POST` | `/check` | JSON API for the web UI. Accepts `{"url": "..."}`, returns `{"report": "..."}` |
| `POST` | `/webhook` | Twilio WhatsApp webhook (form-encoded) |

---

## 📊 Scoring System

### Source Weights

| Source | Weight | Priority |
|---|---|---|
| Google Safe Browsing | 5 | Highest |
| VirusTotal | 4 | |
| CheckPhish | 3 | |
| URLScan | 2 | |
| Heuristics | 1 | Lowest |

### Final Score

```
Final Score = Σ(score_i × weight_i) / Σ(weight_i)
```

### Classification

| Score | Classification |
|---|---|
| 0 – 33 | ❌ UNSAFE |
| 34 – 66 | ⚠️ AVERAGE / USE CAUTION |
| 67 – 100 | ✅ SAFE |

---

## 🧠 Heuristic Checks

The built-in heuristic engine runs 18 checks on the URL structure — no API key or network required:

| # | Check | Penalty |
|---|---|---|
| 1 | IP address as host | 40 |
| 2 | Excessive URL length (>150 chars) | 18 |
| 3 | `@` symbol in URL | 45 |
| 4 | Double slash in path | 10 |
| 5 | Percent-encoding in hostname | 35 |
| 6 | IDN / Punycode domain | 30 |
| 7 | Excessive subdomain depth (≥3) | 20 |
| 8 | Many hyphens in domain (≥3) | 18 |
| 9 | Suspicious TLD | 22 |
| 10 | Known URL shortener | 22 |
| 11 | Brand name in subdomain | 35 |
| 12 | Phishing keywords in path | 8–30 |
| 13 | Non-standard port | 18 |
| 14 | Suspicious file extension | 40 |
| 15 | Digit-letter mixing (l33tspeak) | 18 |
| 16 | Redirect/tracking pattern | 18 |
| 17 | Unencrypted HTTP | 10 |
| 18 | Excessive dots in path (≥5) | 12 |

Score uses exponential decay: `score = 100 × e^(−0.023 × total_penalty)`

---

## 📩 Sample Report

```
🔍 Safety Report

URL: https://example.com

Final Safety Score: 78.5%

Classification: SAFE ✅

Score by source:
  - Google Safe Browsing: 100%
  - VirusTotal: 95%
  - CheckPhish: 100%
  - URLScan: 80%
  - Heuristics: 72%

🧠 Heuristic Red Flags (2 detected):
  ⚑ Long URL: URL is 105 characters long (moderately suspicious).
  ⚑ Phishing keywords in URL: Suspicious terms detected: login.
```

> If Google Safe Browsing returns 0%, the line is annotated:
> `- Google Safe Browsing: 0%  ⛔ UNSAFE – threat detected by Google`

---

## ➕ Adding a New API

1. Create `apis/new_api.py` with a `check(url: str) -> dict` function returning:
   ```python
   {"score": <0-100>, "source": "<API Name>"}
   ```
2. Add the API key to `config.py`.
3. Add a weight to `SOURCE_WEIGHTS` in `config.py`.
4. Import and add to `API_CHECKS` in `main.py`.

The scoring, classification, and report generation will automatically include the new source.

---

## 🛡️ Error Handling

| Source | Fallback Score | Trigger |
|---|---|---|
| VirusTotal | 1 (conservative) | Any error or missing key |
| URLScan | 50 (neutral) | Network error, timeout, blocked URL |
| Google Safe Browsing | 50 (neutral) | Network/API error |
| CheckPhish | 50 (neutral) | Error, missing key, timeout |
| Heuristics | Always succeeds | Local analysis, no network |

If **all** APIs fail, the user receives: *"❌ All safety checks failed. Please try again later."*

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `flask` ≥ 3.0.0 | Web framework |
| `twilio` ≥ 9.0.0 | WhatsApp messaging (TwiML + REST API) |
| `requests` ≥ 2.31.0 | HTTP requests to external APIs |
| `python-dotenv` ≥ 1.0.0 | Environment variable loading |

---

## 🏗️ Architecture

```
User sends URL
     │
     ▼
 Extract URL
     │
     ├── Heuristic Check (local, instant)
     │
     └── ThreadPoolExecutor (concurrent)
              ├── VirusTotal
              ├── URLScan
              ├── Google Safe Browsing
              └── CheckPhish
                    │
     Collect all results
              │
     Calculate weighted score
              │
     Classify (Safe / Caution / Unsafe)
              │
     Build & send report
```

---

*For detailed documentation, see [DOCUMENTATION.txt](DOCUMENTATION.txt).*
