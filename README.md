<div align="center">

<img src="https://img.shields.io/badge/CyberGuru_AI-v1.1-4F6EF7?style=for-the-badge&logo=shield&logoColor=white" alt="CyberGuru AI"/>

# 🛡️ CyberGuru AI

**A cybersecurity-focused AI assistant for students, analysts, and learners**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat&logo=google&logoColor=white)](https://ai.google.dev)
[![Groq](https://img.shields.io/badge/Groq-Gemma_2_9B-F55036?style=flat&logo=groq&logoColor=white)](https://groq.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-336791?style=flat&logo=postgresql&logoColor=white)](https://neon.tech)
[![Redis](https://img.shields.io/badge/Redis-Upstash-DC382D?style=flat&logo=redis&logoColor=white)](https://upstash.com)
[![Render](https://img.shields.io/badge/Deployed_on-Render-46E3B7?style=flat&logo=render&logoColor=white)](https://render.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)](LICENSE)

[**Live Demo**](https://cyberguru-ai.onrender.com) · [**Report Bug**](https://github.com/GuruSharanKalyan/CyberGuru-AI/issues) · [**Request Feature**](https://github.com/GuruSharanKalyan/CyberGuru-AI/issues)

</div>

---

## Overview

CyberGuru AI is a full-stack cybersecurity assistant web application built for students and analysts who want a domain-focused AI experience beyond generic chat. Analyze logs, triage phishing emails, extract IOCs, map findings to MITRE ATT&CK, track live threats, and learn via structured roadmaps — all from a single polished interface.

Built with Flask, powered by **Gemini 2.5 Flash** and **Groq (Gemma 2 9B)**, and deployed live on Render with PostgreSQL and Redis.

---

## ✨ Features

### 🤖 Multi-Model AI Chat
Context-aware, multi-turn cybersecurity conversations with real-time streaming via Server-Sent Events (SSE). Choose from three models per session:

| Model | Provider | Best for |
|---|---|---|
| Gemini 2.5 Flash | Google | Deep analysis, long context |
| Gemini Flash Lite | Google | Faster, lightweight queries |
| Gemma 2 9B | Groq (LPU) | Ultra-low latency responses |

Sessions are auto-titled by Gemini on first message and persisted to PostgreSQL with full history management.

---

### 🔍 Security Triage Agent
Paste any artifact and get a structured threat report in seconds:
- Auto-detects artifact type: log, phishing email, malware report, or URL
- Extracts Indicators of Compromise — IPs, domains, hashes, URLs — with defanging for safe display
- Maps findings to [MITRE ATT&CK](https://attack.mitre.org/) techniques (T-IDs + tactic names)
- Queries [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/) for live reputation scores
- Returns a severity verdict with structured JSON summary
- Skips RFC-1918 / private IP ranges before external API calls
- **PDF Export** — one-click investigation report download (dark-themed, WeasyPrint)

---

### 📚 Cyber Mentor Mode
A dedicated learning environment at `/cyber-mentor` with three structured roadmaps:

| Track | Target |
|---|---|
| SOC Analyst L1 | Blue team fundamentals, SIEM, log analysis |
| Ethical Hacker | Recon, exploitation, post-exploitation methodology |
| Cybersecurity Fundamentals | Networking, OS, cryptography basics |

Features phased lessons, progress tracking (DB-persisted quiz scores), a collapsible history sidebar, and deep-link integration back to the main chat via `?ask=` params.

---

### 🚩 CTF Challenge Mode
Gemini-backed CTF generation with:
- Dynamic challenge creation across difficulty tiers (Easy / Medium / Hard)
- Server-side answer storage in Flask session (no client-side spoilers)
- Streamed hints on request
- Scoring and session persistence

---

### 🌐 Live Threat Landscape Dashboard
Aggregates real-time threat intelligence from four sources with 10-minute server-side caching:

| Source | Data |
|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities |
| [ransomware.live](https://ransomware.live) | Active ransomware group activity |
| [AbuseIPDB](https://www.abuseipdb.com/) | Top reported malicious IPs |
| [CyberNews](https://cybernews.com/) | Breaking security headlines |

---

### 📰 CyberNews Feed
Live headlines from [The Hacker News](https://thehackernews.com/) and [BleepingComputer](https://www.bleepingcomputer.com/) RSS feeds:
- 10-minute server-side TTL cache with stale fallback
- Relative timestamps
- Client-side topic filters: malware, phishing, vulnerabilities, data breach

---

### 📁 File Analysis
Upload files for AI-powered security review. Supported: `.txt`, `.log`, `.pdf`, `.py`, `.js`, `.json`, `.yaml`, `.conf`, `.sh`, `.csv`, `.md` — up to 5 MB.

---

### 🔒 Security-First Backend
- Rate limiting on all API routes (Flask-Limiter + Redis/Upstash)
- CSRF protection on all state-changing endpoints
- Login-required guards on sensitive routes
- Sanitized error responses — no stack traces or internal paths leak to clients
- `MAX_CONTENT_LENGTH` enforced at the Flask layer
- SRI hashes on all CDN assets
- Neon PostgreSQL connection pool with `SELECT 1` ping-on-checkout (prevents stale connection 500s on Render)

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask, Gunicorn |
| AI — Primary | Gemini 2.5 Flash, Gemini Flash Lite (Google GenAI SDK) |
| AI — Speed | Gemma 2 9B via Groq LPU |
| PDF Export | WeasyPrint + Jinja2 |
| Database | PostgreSQL (Neon) |
| Rate Limiting | Flask-Limiter + Redis (Upstash) |
| Auth | Authlib (Google OAuth 2.0) |
| Threat Intel | AbuseIPDB API, VirusTotal API, CISA KEV, ransomware.live |
| News | feedparser + TTL cache |
| Frontend | HTML5, CSS3 (custom design system), Vanilla JS |
| Voice | Web Speech API |
| Deployment | Render + Gunicorn |

---

## 📁 Project Structure

```
CyberGuru-AI/
├── app.py                    # Entry point — initialises DB, registers blueprints
├── config.py                 # API config, system prompts, generation settings
├── extensions.py             # Flask app factory, limiter, CSRF, login helpers
├── requirements.txt
│
├── routes/
│   ├── auth.py               # Google OAuth login / logout
│   ├── chat.py               # Main AI chat (SSE streaming, auto-title)
│   ├── analyze.py            # File upload and analysis
│   ├── triage.py             # Security triage agent endpoints
│   ├── news.py               # CyberNews RSS feed with caching
│   ├── threat.py             # Threat Landscape dashboard aggregator
│   ├── mentor.py             # Cyber Mentor mode — lessons, quiz, history
│   ├── ctf.py                # CTF Challenge mode
│   ├── export.py             # Investigation report PDF export
│   └── misc.py               # Health check, static helpers
│
├── services/
│   ├── gemini_service.py     # Gemini API client + SSE error handling
│   ├── groq_service.py       # Groq API client (Gemma 2 9B)
│   ├── db_service.py         # PostgreSQL session / history management
│   ├── file_service.py       # File extraction (PDF, log, text)
│   ├── triage_service.py     # Triage agent with Gemini function calling
│   └── cyberguru_agent.py    # Agent orchestration layer
│
├── utils/
│   ├── ioc_extractor.py      # Regex IOC extraction (IPs, domains, hashes, URLs)
│   ├── mitre_mapper.py       # Keyword → MITRE ATT&CK T-ID lookup
│   ├── abuseipdb_tool.py     # AbuseIPDB reputation check
│   ├── virustotal_tool.py    # VirusTotal IP / domain lookup
│   ├── defang.py             # IOC defanging for safe display
│   ├── sanitize.py           # Input / output sanitisation helpers
│   ├── grounding.py          # Detects queries needing Google Search grounding
│   ├── report_generator.py   # Triage report → PDF formatter
│   ├── quiz.py               # Security quiz generation
│   └── cache.py              # Generic TTL cache utility
│
├── templates/
│   ├── index.html            # Main chat UI
│   ├── cyber_mentor.html     # Mentor mode landing + lesson view
│   └── report.html           # PDF export template (dark-themed)
│
├── static/
│   ├── css/main.css          # Design system — tokens, themes, components
│   └── js/
│       ├── chat.js           # SSE, model switcher, chat history
│       ├── mentor.js         # Mentor mode UI, progress, deep-links
│       └── threat.js         # Threat dashboard polling + render
│
└── tests/
    ├── test_auth_routes.py
    ├── test_chat_persistence.py
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
- [Groq API key](https://console.groq.com/) — for Gemma 2 9B
- Optional: [AbuseIPDB](https://www.abuseipdb.com/api) and [VirusTotal](https://www.virustotal.com/gui/join-us) keys for triage reputation lookups

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/GuruSharanKalyan/CyberGuru-AI.git
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
   GROQ_API_KEY=your_groq_api_key

   # Database & Cache
   DATABASE_URL=postgresql://user:password@host/dbname
   REDIS_URL=redis://...

   # Auth
   GOOGLE_CLIENT_ID=your_google_oauth_client_id
   GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret
   SECRET_KEY=a_random_secret_key_for_flask_sessions

   # Threat Intel (optional)
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   VIRUSTOTAL_API_KEY=your_virustotal_key

   # App
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

PostgreSQL (Neon) and Redis (Upstash) both have free tiers compatible with Render's free plan. The connection pool uses `SELECT 1` ping-on-checkout to prevent stale connection errors after idle periods.

---

## 🧪 Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/
```

Coverage includes: auth routes, chat persistence, file upload validation, IOC extraction, and triage response parsing.

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

[![GitHub](https://img.shields.io/badge/GitHub-GuruSharanKalyan-181717?style=flat&logo=github)](https://github.com/GuruSharanKalyan)
[![Live](https://img.shields.io/badge/Live_App-cyberguru--ai.onrender.com-46E3B7?style=flat&logo=render&logoColor=white)](https://cyberguru-ai.onrender.com)

---

<div align="center">
<sub>Built for learning. Powered by AI. Secured by design.</sub>
</div>
