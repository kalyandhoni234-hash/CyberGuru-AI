<div align="center">

# 🛡️ CyberGuru AI

**A cybersecurity-focused AI assistant for students, analysts, and learners**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Gemini API](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat&logo=google&logoColor=white)](https://ai.google.dev)
[![Render](https://img.shields.io/badge/Deployed_on-Render-46E3B7?style=flat&logo=render&logoColor=white)](https://render.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

[Live Demo](https://cyberguru-ai.onrender.com) · [Report Bug](https://github.com/GuruSharanKalyan/CyberGuru-AI/issues) · [Request Feature](https://github.com/GuruSharanKalyan/CyberGuru-AI/issues)

</div>

---

## Overview

CyberGuru AI is a cybersecurity assistant web application built for learners and analysts who want a domain-focused AI chat experience. It goes beyond generic AI chat — triage artifacts, extract IOCs, map findings to MITRE ATT&CK, and stay current with live threat news, all from one interface.

Built with Flask, powered by Gemini 2.5 Flash, and deployed on Render.

---

## Features

### 🤖 AI Chat — Cybersecurity-Tuned
Context-aware multi-turn conversations with system-level prompting scoped to security topics. Streaming responses via Server-Sent Events (SSE) so answers appear in real time.

### 🔍 Security Triage Agent
Paste a log, email, or malware report and get a structured analysis back:
- Auto-detects artifact type (log, phishing email, malware, URL) or accepts manual input
- Extracts Indicators of Compromise (IPs, domains, hashes, URLs)
- Maps findings to [MITRE ATT&CK](https://attack.mitre.org/) techniques (T-IDs + names)
- Queries [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/) for IP/domain reputation
- Returns a severity verdict with a structured JSON summary

### 📁 File Analysis
Upload files for AI-powered security review. Supported types: `.txt`, `.log`, `.pdf`, `.py`, `.js`, `.json`, `.yaml`, `.conf`, `.sh`, `.csv`, `.md`. Max 5 MB.

### 🌐 CyberNews Feed
Live cybersecurity headlines pulled from [The Hacker News](https://thehackernews.com/) and [BleepingComputer](https://www.bleepingcomputer.com/) RSS feeds, with:
- 10-minute server-side cache (stale fallback if feeds are down)
- Relative timestamps
- Client-side topic filters: malware, phishing, vulnerabilities, data breach

### 🔊 Voice Input
Hands-free chat via the Web Speech API.

### 💬 Persistent Chat History
Login-gated sessions with conversation history stored in PostgreSQL. Sidebar with full conversation management and deletion.

### 🔒 Security-First Backend
- Rate limiting on all API routes (Flask-Limiter + Redis/Upstash)
- CSRF protection on state-changing endpoints
- Login-required guards on sensitive routes
- Error responses sanitized — no stack traces or internal paths leak to clients
- IOC extraction skips private/RFC-1918 IP ranges before external API calls

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask |
| AI | Gemini 2.5 Flash (Google GenAI SDK) |
| Database | PostgreSQL (Neon) |
| Rate Limiting | Flask-Limiter + Redis (Upstash) |
| Auth | Authlib (Google OAuth) |
| News | feedparser + TTL cache |
| Threat Intel | AbuseIPDB API, VirusTotal API |
| Frontend | HTML5, CSS3, Vanilla JS |
| Voice | Web Speech API |
| Deployment | Render + Gunicorn |

---

## Project Structure

```
CyberGuru-AI/
├── app.py                    # Entry point — initialises DB and registers routes
├── config.py                 # API config, system prompt, generation settings
├── extensions.py             # Flask app, limiter, CSRF, login helpers
├── requirements.txt
│
├── routes/
│   ├── auth.py               # Google OAuth login/logout
│   ├── chat.py               # Main AI chat (SSE streaming)
│   ├── analyze.py            # File upload and analysis
│   ├── triage.py             # Security triage agent endpoints
│   ├── news.py               # CyberNews RSS feed with caching
│   └── misc.py               # Health check, static helpers
│
├── services/
│   ├── gemini_service.py     # Gemini API client + error handling
│   ├── db_service.py         # PostgreSQL session/history management
│   ├── file_service.py       # File extraction (PDF, log, text)
│   ├── triage_service.py     # Triage agent with function calling
│   └── cyberguru_agent.py    # Agent orchestration layer
│
├── utils/
│   ├── ioc_extractor.py      # Regex-based IOC extraction (IPs, domains, hashes, URLs)
│   ├── mitre_mapper.py       # Keyword → MITRE ATT&CK T-ID lookup
│   ├── abuseipdb_tool.py     # AbuseIPDB reputation check
│   ├── virustotal_tool.py    # VirusTotal IP/domain lookup
│   ├── defang.py             # IOC defanging for safe display
│   ├── sanitize.py           # Input/output sanitisation helpers
│   ├── grounding.py          # Detects queries needing Google Search grounding
│   ├── report_generator.py   # Structured triage report formatter
│   ├── quiz.py               # Security quiz generation
│   └── cache.py              # Generic TTL cache utility
│
├── templates/
│   └── index.html            # Main chat UI
│
├── static/
│   ├── css/style.css
│   └── js/main.js            # SSE, voice input, chat history, news feed
│
└── tests/
    ├── test_auth_routes.py
    ├── test_chat_persistence.py
    ├── test_file_upload_limits.py
    ├── test_ioc_extractor.py
    └── test_triage_parsing.py
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL database (or a [Neon](https://neon.tech) free-tier connection string)
- [Google Gemini API key](https://ai.google.dev/)
- Optional: [AbuseIPDB](https://www.abuseipdb.com/api) and [VirusTotal](https://www.virustotal.com/gui/join-us) API keys for triage reputation lookups

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/GuruSharanKalyan/CyberGuru-AI.git
   cd CyberGuru-AI
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate       # Linux/macOS
   venv\Scripts\activate          # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**

   Create a `.env` file in the project root:
   ```env
   GEMINI_API_KEY=your_gemini_api_key
   DATABASE_URL=postgresql://user:password@host/dbname
   GOOGLE_CLIENT_ID=your_google_oauth_client_id
   GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret
   SECRET_KEY=a_random_secret_key_for_flask_sessions
   ABUSEIPDB_API_KEY=your_abuseipdb_key        # optional, for triage
   VIRUSTOTAL_API_KEY=your_virustotal_key       # optional, for triage
   REDIS_URL=redis://...                        # optional, for rate limiting
   ALLOWED_ORIGINS=http://localhost:5000
   ```

5. **Run the application**
   ```bash
   flask run
   ```
   Open [http://localhost:5000](http://localhost:5000).

---

## Deployment (Render)

1. Push to GitHub.
2. Create a **Web Service** on Render, connect the repository.
3. Add all `.env` variables in the Render dashboard under **Environment**.
4. Set the start command:
   ```bash
   gunicorn app:app
   ```

The app uses PostgreSQL (Neon) and Redis (Upstash) — both have free tiers that work with Render's free plan.

---

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/
```

Test coverage includes: auth routes, chat persistence, file upload validation, IOC extraction, and triage response parsing.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: describe your change"`
4. Push and open a Pull Request

---

## License

[MIT](LICENSE)

---

## Author

**Guru Sharan Kalyan**  
B.Tech CSE (Cybersecurity) — Government Engineering College, Ajmer

[![GitHub](https://img.shields.io/badge/GitHub-GuruSharanKalyan-181717?style=flat&logo=github)](https://github.com/GuruSharanKalyan)3