<div align="center">

# 🛡️ CyberGuru AI

**An intelligent cybersecurity assistant powered by Gemini AI**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Gemini API](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat&logo=google&logoColor=white)](https://ai.google.dev)
[![Render](https://img.shields.io/badge/Deployed_on-Render-46E3B7?style=flat&logo=render&logoColor=white)](https://render.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

[Live Demo](https://cyberguru_ai.onrender.com) • [Report Bug](https://github.com/kalyandhoni234-hash/CyberGuru-AI/issues) • [Request Feature](https://github.com/GuruSharanKalyan/CyberGuru-AI/issues)

</div>

---

## 📖 Overview

CyberGuru AI is a cybersecurity-focused AI chatbot web application designed to assist users with security concepts, threat analysis, vulnerability explanations, and best practices. Built with a Flask backend and powered by the Gemini 2.5 Flash API, it delivers accurate, domain-specific responses through a sleek, terminal-inspired dark UI.

---

## ✨ Features

- 🤖 **Cybersecurity-Focused AI** — Responses tuned specifically for security topics using system-level prompting
- 📁 **File Analysis** — Upload and analyze files for potential threats or vulnerabilities
- 🔊 **Voice Input** — Hands-free interaction via the Web Speech API
- 💬 **Conversation Memory** — Context-aware multi-turn conversations with history management
- ⚡ **Streaming Responses** — Real-time response streaming via Server-Sent Events (SSE)
- 🗂️ **Chat History** — Persistent sidebar with conversation management and deletion support
- 🌐 **Animated Network Background** — Cybersecurity-themed canvas animation
- 📱 **Responsive Design** — Works seamlessly across desktop and mobile

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python, Flask |
| **AI Model** | Gemini 2.5 Flash API |
| **Frontend** | HTML5, CSS3, JavaScript (Vanilla) |
| **Voice** | Web Speech API |
| **Deployment** | Render |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- A [Google Gemini API key](https://ai.google.dev/)

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

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   Fill in your `.env`:
   ```env
   GEMINI_API_KEY=your_api_key_here
   ```

5. **Run the application**
   ```bash
   flask run
   ```
   Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 📸 Screenshots

> *Screenshots coming soon*

---

## 📁 Project Structure

```
CyberGuru-AI/
├── app.py                 # Flask application entry point
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variable template
├── static/
│   ├── css/
│   │   └── style.css      # Application styles
│   └── js/
│       └── main.js        # Frontend logic (SSE, voice, history)
└── templates/
    └── index.html         # Main chat interface
```

---

## 🌐 Deployment

This project is configured for deployment on [Render](https://render.com).

1. Push your code to GitHub.
2. Create a new **Web Service** on Render and connect your repository.
3. Add `GEMINI_API_KEY` as an environment variable in the Render dashboard.
4. Set the start command to:
   ```bash
   gunicorn app:app
   ```

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Commit your changes (`git commit -m "feat: add your feature"`)
4. Push to the branch (`git push origin feat/your-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Guru Sharan Kalyan**  
CSE (Cybersecurity) | Government Engineering College, Ajmer  

[![GitHub](https://img.shields.io/badge/GitHub-GuruSharanKalyan-181717?style=flat&logo=github)](https://github.com/GuruSharanKalyan)

---

<div align="center">
  <sub>Built with ❤️ and a passion for cybersecurity</sub>
</div>