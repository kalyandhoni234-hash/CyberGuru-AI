"""
services/quiz_service.py
─────────────────────────
Interactive Quiz Mode for CyberGuru AI.

Mirrors the architecture of services/ctf_service.py (same Groq call
pattern, same self-contained style) but for short multiple-choice
quizzes instead of freeform CTF challenges.

Key difference from CTF: grading needs no second LLM call. The model
returns the correct answer + explanation up front, so scoring is just
local comparison once the quiz is submitted. This keeps quiz mode fast
and free of extra Groq quota usage.

Get a free Groq key at: https://console.groq.com
Add to your .env:  GROQ_API_KEY=your_key_here

Public API:
    get_quiz(topic=None)                 → dict (quiz)
    grade_quiz(quiz, answers)            → dict (result) — pure local scoring
"""

import json
import logging
import os
import random
import re
import time
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Groq config (same free tier used by CTF mode) ──────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"
MAX_RETRIES  = 3
BASE_BACKOFF = 5

QUESTIONS_PER_QUIZ = 5

# ── Topics ───────────────────────────────────────────────────────────────────
QUIZ_TOPICS = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Malware",
    "Phishing",
    "Network Security",
    "Cryptography",
    "Social Engineering",
    "OWASP Top 10",
]


def _pick_topic(override=None):
    if override and override in QUIZ_TOPICS:
        return override
    return random.choice(QUIZ_TOPICS)


# ── Prompts ───────────────────────────────────────────────────────────────────
_QUIZ_SYSTEM = """You are a cybersecurity quiz designer for CyberGuru AI.
Generate clear, accurate, unambiguous multiple-choice quiz questions for
students learning cybersecurity. Always respond with valid JSON only —
no markdown fences, no preamble."""

_QUIZ_USER = """Generate a {n}-question multiple-choice quiz on: {topic}

Return ONLY a JSON object with these exact keys:
{{
  "topic": "{topic}",
  "title": "Short quiz title (max 6 words)",
  "questions": [
    {{
      "id": "q1",
      "question": "Question text",
      "options": {{"A": "Option A text", "B": "Option B text", "C": "Option C text", "D": "Option D text"}},
      "correct": "A",
      "explanation": "1-2 sentence explanation of why this is correct"
    }}
  ]
}}

Rules:
- Exactly {n} question objects, with ids q1 through q{n} in order.
- Exactly 4 options per question (A-D), only one correct.
- "correct" must be exactly one of "A", "B", "C", "D".
- Vary difficulty slightly across the {n} questions, easiest first.
- Keep each question and option concise (one sentence each)."""


# ── Groq call helper (mirrors ctf_service._groq_json) ──────────────────────
def _groq_json(system_prompt: str, user_prompt: str, max_tokens: int = 2048) -> dict:
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
        "temperature": 0.7,
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


def _validate_quiz(quiz: dict) -> bool:
    questions = quiz.get("questions")
    if not isinstance(questions, list) or len(questions) != QUESTIONS_PER_QUIZ:
        return False
    for q in questions:
        if not isinstance(q, dict):
            return False
        if not q.get("id") or not q.get("question") or not q.get("explanation"):
            return False
        opts = q.get("options")
        if not isinstance(opts, dict) or set(opts.keys()) != {"A", "B", "C", "D"}:
            return False
        if q.get("correct") not in ("A", "B", "C", "D"):
            return False
    return True


# ── Grading helpers ─────────────────────────────────────────────────────────
def _grade_letter(score: int) -> str:
    if score >= 100:
        return "S"
    if score >= 80:
        return "A"
    if score >= 60:
        return "B"
    if score >= 40:
        return "C"
    if score >= 20:
        return "D"
    return "F"


_SUMMARIES = {
    "S": "Flawless run — you nailed every question.",
    "A": "Strong showing — you clearly know this topic well.",
    "B": "Solid effort — a couple of gaps to close.",
    "C": "Decent start — worth a re-read before round two.",
    "D": "Rough round — review the explanations below and try again.",
    "F": "That one didn't land — but the breakdown below has you covered.",
}


# ── Public API ────────────────────────────────────────────────────────────────
def get_quiz(topic: str = None) -> dict:
    """
    Generate a quiz. topic is optional; a random topic is picked if omitted
    or not recognized. Returns the quiz dict (caller should cache it
    server-side, keyed per user, for grading).
    """
    chosen_topic = _pick_topic(topic)
    prompt = _QUIZ_USER.format(topic=chosen_topic, n=QUESTIONS_PER_QUIZ)

    try:
        quiz = _groq_json(_QUIZ_SYSTEM, prompt, max_tokens=2560)
        if not _validate_quiz(quiz):
            logger.error("Quiz — Groq returned malformed quiz JSON: %s", quiz)
            return {"ok": False, "error": "Could not generate a valid quiz. Please try again."}
        quiz["topic"] = chosen_topic
        quiz["generated_at"] = datetime.now(timezone.utc).isoformat()
        return {"ok": True, "quiz": quiz}
    except RuntimeError as e:
        rate_limited = "rate limit" in str(e).lower()
        return {"ok": False, "error": str(e), "rate_limited": rate_limited}
    except (json.JSONDecodeError, KeyError, TypeError):
        logger.exception("Quiz — bad JSON from Groq")
        return {"ok": False, "error": "Could not parse quiz response. Please try again."}


def grade_quiz(quiz: dict, answers: dict) -> dict:
    """
    Score a submitted quiz locally — no LLM call needed since the
    correct answers are already known from generation.

    `quiz` is the full dict from get_quiz()["quiz"] (includes correct
    answers + explanations, which were withheld from the client until now).
    `answers` is {question_id: "A"|"B"|"C"|"D", ...} from the player.
    """
    questions = quiz.get("questions", [])
    total = len(questions)
    breakdown = []
    correct_count = 0

    for q in questions:
        qid = q.get("id")
        player_choice = (answers.get(qid) or "").strip().upper()
        correct_choice = q.get("correct")
        is_correct = player_choice == correct_choice
        if is_correct:
            correct_count += 1

        options = q.get("options", {})
        breakdown.append({
            "id": qid,
            "question": q.get("question"),
            "your_answer": player_choice or None,
            "your_answer_text": options.get(player_choice),
            "correct_answer": correct_choice,
            "correct_answer_text": options.get(correct_choice),
            "is_correct": is_correct,
            "explanation": q.get("explanation"),
        })

    score = round((correct_count / total) * 100) if total else 0
    grade = _grade_letter(score)
    passed = score >= 60

    return {
        "ok": True,
        "result": {
            "score": score,
            "grade": grade,
            "correct_count": correct_count,
            "total": total,
            "passed": passed,
            "summary": _SUMMARIES.get(grade, ""),
            "breakdown": breakdown,
        },
    }
