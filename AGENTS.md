# 🛡️ Phishing Link Detection WhatsApp Chatbot

A modular WhatsApp chatbot that detects phishing or unsafe links using multiple security APIs and returns a unified safety score.

Built using:

* Twilio WhatsApp API
* VirusTotal API
* URLScan API
* Google Safe Browsing API

---

## 🎯 Project Overview

This chatbot allows a user to forward a link via WhatsApp. The system:

1. Receives the link using Twilio webhook.
2. Sends the link to multiple phishing detection APIs.
3. Converts each API result into a normalized score (0–100).
4. Averages the scores.
5. Classifies the link’s safety.
6. Replies on WhatsApp with a safety report.

---

## 📊 Scoring System

All APIs must return a normalized safety score between **0 and 100**.

### Final Score Calculation

```
Final Score = Average of all API scores
```

### Safety Classification

| Score Range | Classification           |
| ----------- | ------------------------ |
| 0 – 33      | ❌ Unsafe                 |
| 34 – 66     | ⚠️ Average / Use Caution |
| 67 – 100    | ✅ Safe                   |

---

## 🏗️ Project Structure

The system must remain modular and scalable.

```
project/
│
├── main.py
├── apis/
│   ├── virustotal.py
│   ├── urlscan.py
│   ├── google_safe_browsing.py
│
├── scoring.py
├── config.py
└── requirements.txt
```

---

## 🔌 API Module Rules

Each API must:

* Be implemented in its own file inside `/apis`
* Contain only logic related to that API
* Return data in this format:

```python
{
    "score": <number between 0-100>,
    "source": "<api_name>"
}
```

No API logic should be written inside `main.py`.

---

## 🧠 Main Program Responsibilities

`main.py` should only:

* Handle Twilio webhook
* Extract the forwarded link
* Call all API modules
* Collect scores
* Calculate average score
* Determine classification
* Send WhatsApp response

---

## ➕ Adding a New API

To integrate a new phishing detection API:

1. Create a new file inside `/apis`
2. Implement API logic
3. Normalize its output to 0–100
4. Follow the standard return format
5. Import and call it in `main.py`

Use the format:
- from config import VIRUSTOTAL_API_KEY, for VirusTotal
- from config import GOOGLE_SAFE_BROWSING_API_KEY, for Google Safe Browsing
- from config import URLSCAN_API_KEY, for URLScan
to import the API keys

Do NOT modify existing API modules unnecessarily.

---

## ⚙️ Code Change & Integration Rules

Whenever modifying code:

* Verify integration with all modules
* Ensure return formats remain consistent
* Fix any errors immediately
* Confirm scoring and classification still work
* Do not leave broken or partial code

---

## 🚫 Git Rules

* Do NOT auto-commit
* Do NOT auto-push
* Only make changes and save files
* Manual commit process only

---

## 📩 WhatsApp Response Format

Example response:

```
🔍 Safety Report for the Link:

Final Safety Score: 78%

Classification: SAFE ✅

Checked using:
- VirusTotal
- URLScan
- Google Safe Browsing
```

---

## 🚀 Design Principles

* Modular architecture
* Clean and readable code
* Scalable structure
* Proper error handling
* Parallel/async API calls where possible
* Easy future expansion

---

## 📌 Summary

This project is a modular, scalable phishing detection WhatsApp bot that:

* Uses multiple security APIs
* Normalizes results to a 0–100 safety scale
* Classifies links clearly
* Is easy to extend with new APIs
* Maintains clean separation of responsibilities

---
