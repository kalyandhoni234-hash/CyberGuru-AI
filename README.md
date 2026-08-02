<div align="center">

<img src="https://img.shields.io/badge/CyberGuru_AI-v2.0-4F6EF7?style=for-the-badge&logo=shield&logoColor=white" alt="CyberGuru AI"/>

# 🛡️ CyberGuru AI — SOC Investigation Center

**A standalone AI-powered SOC investigation workspace**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat&logo=google&logoColor=white)](https://ai.google.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-336791?style=flat&logo=postgresql&logoColor=white)](https://neon.tech)
[![Redis](https://img.shields.io/badge/Rate_Limit-Upstash-DC382D?style=flat&logo=redis&logoColor=white)](https://upstash.com)
[![Render](https://img.shields.io/badge/Deployed_on-Render-46E3B7?style=flat&logo=render&logoColor=white)](https://render.com)
[![CI](https://github.com/kalyandhoni234-hash/CyberGuru-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/kalyandhoni234-hash/CyberGuru-AI/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)](LICENSE)

[**Live App**](https://cyberguru-ai.onrender.com) · [**Report Bug**](https://github.com/kalyandhoni234-hash/CyberGuru-AI/issues) · [**Request Feature**](https://github.com/kalyandhoni234-hash/CyberGuru-AI/issues)

</div>

---

## Overview

CyberGuru AI is a dedicated **SOC Investigation Center**. Analysts paste or upload evidence — an IP, domain, URL, file hash, malware report, phishing email, or security log — and the app runs a full investigation pipeline:

- **IOC extraction** (IPs, domains, URLs, hashes, emails) with defanging
- **Threat-intelligence lookups** (AbuseIPDB, VirusTotal) with TTL caching
- **MITRE ATT&CK mapping** to technique IDs and tactic names
- **Risk scoring** with a severity gauge and a *separate* evidence-based **confidence score**
- **Traceable AI output** — every claim maps to an evidence ID (E-01, E-02, …) rendered in an Evidence legend
- **Analyst triage workflow** — status (New / In Review / Resolved / False Positive / Escalated) + notes per investigation
- **Detection rule export** — one-click **Sigma / YARA** rules generated from the investigation's IOCs and MITRE technique
- **Evidence-specific recommendations** — deterministic next steps grounded in threat-intel scores, IOCs, and technique
- A **structured incident report** you can export (Markdown/JSON) or print
- An **investigation-grounded AI copilot** to ask follow-up questions about the artifact, IOCs, report, or next steps

Built with Flask, powered by **Gemini 2.5 Flash**, and deployed on Render with PostgreSQL (Neon) and Redis (Upstash).

---

## ✨ Features

### 🧬 Investigation Pipeline
Every analysis runs a deterministic pipeline before the AI verdict:
1. **Extracting Indicators** — regex-based IOC extraction
2. **Parsing Evidence** — type-aware parsing (URLs, phishing emails, logs, malware reports, hashes)
3. **Threat Intelligence Lookup** — AbuseIPDB + VirusTotal reputation, RFC-1918/private IPs skipped before external calls
4. **MITRE ATT&CK Mapping** — keyword → T-ID / tactic lookup
5. **Risk Assessment** — severity gauge + separate evidence-based confidence score
6. **AI Analysis** — Gemini verdict and summary (grounded in cited evidence)
7. **Report Generation** — full incident report with evidence-specific recommendations

### 🤖 Investigation-Grounded Copilot
A panel beside the results lets you ask questions *scoped to the current investigation*:
- Grounded in the artifact, extracted IOCs, threat-intel results, MITRE mapping, and generated report
- The prompt includes the full **EVIDENCE REGISTRY** (E-01, E-02, …) and the model must cite these IDs when it makes claims
- SSE streaming responses, CSRF + rate-limited, `@login_required`
- `POST /api/investigate/ask` with `{ "investigation_id": <id>, "question": "<text>" }`

### 📊 Analyst Triage Workflow
Each investigation carries analyst-owned state, kept visually distinct from the pipeline's severity scale:
- `analyst_status`: **New → In Review → Resolved / False Positive / Escalated** (dedicated blue/teal/violet badge palette)
- `analyst_notes`: free-text notes per case
- Status dropdown + notes editor on the dashboard, status chips in the history list
- `PATCH /api/investigate/<id>` with `{ "status": "In Review", "notes": "…" }`

### 🎯 Evidence, Confidence & Recommendations
- **Confidence** is a deterministic 0–100 score derived from AbuseIPDB/VirusTotal results, MITRE matches and IOC corroboration — independent of severity, and unit-tested (`utils/confidence.py`)
- **Evidence legend** lists every source behind the AI's claims with stable E-IDs
- **Recommendations** are generated deterministically (`utils/recommendations.py`) — e.g. block an IP with ≥75% abuse confidence, DNS-sinkhole a domain, hunt a hash in the EDR, or apply the T1110 lockout/MFA playbook

### 🛡️ Detection Rule Export
- `GET /api/investigate/<id>/export/rule/sigma` — Sigma YAML mapping IPs → `net.source.ip`, domains → `dns.query.name`, URLs → `http.request.url`, hashes → `file.sha256`, with `attack.*` tags and severity-derived level
- `GET /api/investigate/<id>/export/rule/yara` — one YARA string per raw indicator
- Deterministic: same investigation always yields the same rule (stable rule IDs); no LLM involved

### 🏠 Smart Root
- Anonymous visitors get a lightweight **landing page** with a sign-in CTA
- Authenticated users land directly on the **Investigation Center**
- `/investigate` always serves the tool (redirects anonymous users to `/`)

### 📁 File Analysis
Upload files for AI-powered security review. Supported: `.txt`, `.log`, `.pdf`, `.py`, `.js`, `.json`, `.yaml`, `.conf`, `.sh`, `.csv`, `.md` — up to 5 MB. Magic-byte validation blocks disguised executables, archives, and images.

### 🗂️ Investigation History & Exports
- Per-user history (scoped to `user_id` in every query), with analyst-status chips
- One-click Markdown / JSON export and print
- Detection rule export: Sigma / YARA (see above)

### 🔒 Security-First Backend
- Rate limiting on all API routes (Flask-Limiter, per-user keys; Redis/Upstash in production)
- CSRF protection on all state-changing endpoints (double-submit cookie pattern)
- `@login_required` guards on sensitive routes; **auth is checked before CSRF**
- Nonce-based CSP (`'unsafe-inline'` removed) with a CSP violation report endpoint
- Sanitized error responses — no stack traces leak to clients
- `MAX_CONTENT_LENGTH` enforced at the Flask layer
- Neon PostgreSQL connection pool with `SELECT 1` ping-on-checkout (prevents stale-connection 500s on Render)

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask, Gunicorn |
| AI | Gemini 2.5 Flash (Google GenAI SDK), SSE streaming |
| Database | PostgreSQL (Neon) |
| Rate Limiting | Flask-Limiter + Redis (Upstash) |
| Auth | Authlib (Google OAuth 2.0) |
| Threat Intel | AbuseIPDB API, VirusTotal API |
| Frontend | HTML5, CSS3 (custom design system), Vanilla JS |
| Deployment | Render + Gunicorn |

---

## 📁 Project Structure

```
CyberGuru-AI/
├── app.py                    # Entry point — initialises DB, registers routes
├── config.py                 # API config, system prompts, generation settings, length caps
├── extensions.py             # Flask app, limiter, CSRF, login helpers, CSP headers
├── requirements.txt
├── requirements-dev.txt      # pytest
│
├── routes/
│   ├── auth.py               # Google OAuth login / logout / /auth/me / CSRF token
│   ├── analyze.py            # /analyze-file + investigation-scoped copilot (/api/investigate/ask)
│   ├── investigate_center.py # Smart root, /investigate, analyze/history/detail/delete/export
│   ├── triage.py             # Artifact triage endpoints (analyze, analyze-log/email/malware)
│   ├── misc.py               # /health, /csp-report, /favicon.ico
│   └── seo.py                # /sitemap.xml, /robots.txt
│
├── services/
│   ├── gemini_service.py     # Gemini API client + SSE error handling
│   ├── db_service.py         # PostgreSQL pool + users + investigation CRUD
│   ├── file_service.py       # File extraction (PDF, log, text)
│   ├── triage_service.py     # Triage agent with Gemini function calling
│   └── cyberguru_agent.py    # Investigation orchestration layer
│
├── utils/
│   ├── ioc_extractor.py      # Regex IOC extraction (IPs, domains, hashes, URLs)
│   ├── mitre_mapper.py       # Keyword → MITRE ATT&CK T-ID lookup
│   ├── abuseipdb_tool.py     # AbuseIPDB reputation check
│   ├── virustotal_tool.py    # VirusTotal IP / domain lookup
│   ├── defang.py             # IOC defanging for safe display
│   ├── sanitize.py           # Input / output sanitisation helpers
│   ├── grounding.py          # Detects queries needing Google Search grounding
│   ├── report_generator.py   # Incident report generation
│   └── cache.py              # Generic TTL cache utility
│
├── templates/
│   ├── index.html            # Landing page (anonymous visitors)
│   └── investigate.html      # SOC Investigation Center (authenticated users)
│
├── static/
│   ├── css/main.css          # Design system — tokens, themes, components
│   ├── manifest.json         # PWA manifest
│   ├── robots.txt
│   └── js/
│       ├── csp-bindings.js   # CSP-compliant event delegation + theme init
│       ├── auth.js           # Login state, CSRF-token fetch interceptor
│       └── investigate.js    # Investigation Center UI + copilot SSE handler
│
└── tests/
    ├── conftest.py           # Route/db stubs, fixtures
    ├── test_auth_routes.py
    ├── test_security.py      # Auth, CSRF, rate limiting
    ├── test_file_upload_limits.py
    ├── test_ioc_extractor.py
    └── test_triage_parsing.py
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL database ([Neon](https://neon.tech) free tier works)
- [Google Gemini API key](https://ai.google.dev/)
- Optional: [AbuseIPDB](https://www.abuseipdb.com/api) and [VirusTotal](https://www.virustotal.com/gui/join-us) keys for reputation lookups

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/kalyandhoni234-hash/CyberGuru-AI.git
   cd CyberGuru-AI
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate       # Linux / macOS
   venv\Scripts\activate          # Windows (PowerShell)
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**

   Create a `.env` file in the project root:
   ```env
   # AI
   GEMINI_API_KEY=your_gemini_api_key

   # Database
   DATABASE_URL=postgresql://user:password@host/dbname

   # Auth
   GOOGLE_CLIENT_ID=your_google_oauth_client_id
   GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret
   FLASK_SECRET_KEY=generate_with_python_-c_import_secrets_print(secrets.token_hex(32))

   # Threat Intel (optional)
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   VIRUSTOTAL_API_KEY=your_virustotal_key

   # Rate limiting (optional — falls back to in-memory)
   REDIS_URL=redis://...

   # App
   APP_ENV=production              # sets Secure cookies + HSTS
   ALLOWED_ORIGINS=http://localhost:5000
   ```

5. **Run the application**
   ```bash
   flask run
   ```
   Open [http://localhost:5000](http://localhost:5000).

---

## ☁️ Deployment (Render)

1. Push to GitHub.
2. Create a **Web Service** on Render, connect the repository.
3. Add all `.env` variables under **Environment** in the Render dashboard.
4. Set the start command:
   ```bash
   gunicorn app:app
   ```

PostgreSQL (Neon) and Redis (Upstash) both have free tiers compatible with Render's free plan. The connection pool uses `SELECT 1` ping-on-checkout to prevent stale-connection errors after idle periods.

---

## 🧪 Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/
```

Coverage includes: auth routes, the smart root, CSRF + auth ordering on every protected endpoint, file upload validation, IOC extraction, and triage response parsing.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: describe your change"`
4. Push and open a Pull Request

---

## 📄 License

[MIT](LICENSE)

---

## 👤 Author

**Guru Sharan Kalyan**  
B.Tech CSE (Cybersecurity) — Government Engineering College, Ajmer

[![GitHub](https://img.shields.io/badge/GitHub-kalyandhoni234--hash-181717?style=flat&logo=github)](https://github.com/kalyandhoni234-hash)
[![Live](https://img.shields.io/badge/Live_App-cyberguru--ai.onrender.com-46E3B7?style=flat&logo=render&logoColor=white)](https://cyberguru-ai.onrender.com)

---

<div align="center">
<sub>Built for investigators. Powered by AI. Secured by design.</sub>
</div>
