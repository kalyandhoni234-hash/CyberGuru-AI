"""
services/ctf_service.py
───────────────────────
CTF / Challenge Mode for CyberGuru AI.

Uses Groq API (free) directly instead of Gemini.
Everything else in the project (chat, analyze, etc.) is untouched.

Get a free Groq key at: https://console.groq.com
Add to your .env:  GROQ_API_KEY=your_key_here

Public API:
    get_ctf_challenge(category=None)  → dict (challenge)
    score_ctf_answer(challenge, user_answer) → dict (score, feedback, correct_answer)
"""

import json
import logging
import os
import re
import time
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Groq config (free tier, no changes to your main config.py needed) ─────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"
MAX_RETRIES  = 3
BASE_BACKOFF = 5

# ── Categories ────────────────────────────────────────────────────────────────
CTF_CATEGORIES = [
    "Log Analysis",
    "Phishing Email",
    "Malware Artifact",
    "Network Traffic",
    "Web Vulnerability",
    "Misconfiguration",
    "Forensics",
]

def _weekly_category(override=None):
    if override and override in CTF_CATEGORIES:
        return override
    week_num = datetime.now(timezone.utc).isocalendar()[1]
    return CTF_CATEGORIES[week_num % len(CTF_CATEGORIES)]


# ── Prompts ───────────────────────────────────────────────────────────────────
_CHALLENGE_SYSTEM = """You are a cybersecurity CTF challenge designer for CyberGuru AI.
Generate realistic, educational security challenges at SOC analyst difficulty.
Always respond with valid JSON only — no markdown fences, no preamble."""

_CHALLENGE_USER = """Generate a CTF challenge for category: {category}

Return ONLY a JSON object with these exact keys:
{{
  "category": "{category}",
  "title": "Short challenge title (max 8 words)",
  "difficulty": "Easy | Medium | Hard",
  "scenario": "2-3 sentence context setting the scene",
  "artifact": "The raw artifact — a log snippet (8-12 lines), email headers+body, config excerpt, network capture summary, or code snippet. Make it realistic with real-looking IPs, hostnames, timestamps. Keep it concise.",
  "question": "Specific question the analyst must answer",
  "hints": ["Hint 1 — subtle clue", "Hint 2 — stronger clue"],
  "correct_answer": "The definitive correct answer (2-4 sentences)",
  "mitre_id": "T#### or null",
  "mitre_name": "Technique name or null",
  "key_indicators": ["indicator1", "indicator2", "indicator3"]
}}"""

_SCORING_SYSTEM = """You are a cybersecurity instructor grading a CTF challenge answer.
Be fair, specific, and educational. Always respond with valid JSON only."""

_SCORING_USER = """CTF Challenge:
Category: {category}
Title: {title}
Artifact:
{artifact}

Question: {question}
Correct answer (hidden from student): {correct_answer}
Key indicators to look for: {key_indicators}

Student's answer: {user_answer}

Score the student's answer. Return ONLY this JSON:
{{
  "score": <integer 0-100>,
  "grade": "S | A | B | C | D | F",
  "correct": <true if score >= 70>,
  "summary": "One sentence verdict on the student's answer",
  "strengths": ["What they got right (be specific)"],
  "missed": ["Key things they missed or got wrong"],
  "correct_answer_reveal": "Full explanation of the correct answer with reasoning",
  "pro_tip": "One actionable tip to spot this faster next time",
  "mitre_callout": "If applicable: the MITRE ATT&CK technique and why it maps here"
}}"""


# ── Groq call helper ──────────────────────────────────────────────────────────
def _groq_json(system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> dict:
    """Call Groq API and return parsed JSON response."""
    if not GROQ_API_KEY:
        raise ValueError("GROQ_API_KEY not set in environment. Get a free key at console.groq.com")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GROQ_API_KEY}",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.8,
    }

    last_status = None
    for attempt in range(MAX_RETRIES):
        resp = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=45)
        last_status = resp.status_code

        if resp.status_code == 200:
            raw = resp.json()["choices"][0]["message"]["content"]
            raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
            return json.loads(raw)

        if resp.status_code == 429:
            wait = BASE_BACKOFF * (2 ** attempt)
            logger.warning("Groq rate limit (attempt %d), waiting %ds", attempt + 1, wait)
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise RuntimeError("Groq rate limit reached. Please wait a moment.")

        elif resp.status_code == 503:
            wait = BASE_BACKOFF * (2 ** attempt)
            logger.warning("Groq 503 (attempt %d), waiting %ds", attempt + 1, wait)
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise RuntimeError(f"Groq service unavailable ({last_status}).")
        else:
            raise RuntimeError(f"Groq API error {last_status}: {resp.text[:200]}")

    raise RuntimeError(f"Groq API failed after {MAX_RETRIES} attempts.")


# ── Public API ────────────────────────────────────────────────────────────────
def get_ctf_challenge(category: str = None) -> dict:
    """
    Generate a CTF challenge. category is optional; defaults to this week's category.
    Returns the challenge dict (caller should store it in session/DB for scoring).
    """
    cat    = _weekly_category(category)
    prompt = _CHALLENGE_USER.format(category=cat)

    try:
        challenge = _groq_json(_CHALLENGE_SYSTEM, prompt, max_tokens=4096)
        challenge["generated_at"] = datetime.now(timezone.utc).isoformat()
        return {"ok": True, "challenge": challenge}
    except RuntimeError as e:
        rate_limited = "rate limit" in str(e).lower()
        return {"ok": False, "error": str(e), "rate_limited": rate_limited}
    except (json.JSONDecodeError, KeyError) as e:
        logger.exception("CTF challenge — bad JSON from Groq")
        return {"ok": False, "error": "Could not parse challenge response. Please try again."}


def score_ctf_answer(challenge: dict, user_answer: str) -> dict:
    """
    Score a user's answer against the challenge.
    `challenge` is the dict from get_ctf_challenge()["challenge"].
    Returns scoring dict with score, grade, feedback, reveal.
    """
    if not user_answer or not user_answer.strip():
        return {"ok": False, "error": "Please provide an answer before submitting."}

    prompt = _SCORING_USER.format(
        category       = challenge.get("category", ""),
        title          = challenge.get("title", ""),
        artifact       = challenge.get("artifact", ""),
        question       = challenge.get("question", ""),
        correct_answer = challenge.get("correct_answer", ""),
        key_indicators = ", ".join(challenge.get("key_indicators", [])),
        user_answer    = user_answer[:2000],
    )

    try:
        result = _groq_json(_SCORING_SYSTEM, prompt, max_tokens=1024)
        return {"ok": True, "result": result}
    except RuntimeError as e:
        rate_limited = "rate limit" in str(e).lower()
        return {"ok": False, "error": str(e), "rate_limited": rate_limited}
    except (json.JSONDecodeError, KeyError) as e:
        logger.exception("CTF scoring — bad JSON from Groq")
        return {"ok": False, "error": "Could not parse scoring result. Please try again."}