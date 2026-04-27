# 🛡️ WebGuard v2.0 — Advanced Web Security Scanner

A professional web application security scanner with a cybersecurity-themed UI.

## Features
- **HTTP Header Analysis** — Checks for 7 critical security headers + info leaks
- **SSL/TLS Inspection** — Certificate validity, expiry, cipher strength, TLS version
- **XSS Detection** — Reflected & DOM-based XSS with 8 payloads
- **SQL Injection** — Error-based detection with 8 payloads across common params
- **CSP Evaluation** — Unsafe directives, wildcard sources, missing directives
- **Technology Fingerprinting** — CMS, frameworks, server stack detection
- **Port Scanner** — 12 common ports with risk flagging
- **Site Crawler** — Discovers all internal links and assets
- **Risk Scoring** — 0–100 score with CRITICAL / HIGH / MEDIUM / LOW rating

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Then open: http://localhost:5000

## ⚠️ Disclaimer
For authorized penetration testing and educational use only.
Never scan targets you do not own or have explicit written permission to test.
