"""
Groq service — llama3-8b-8192
Drop-in alongside Gemini. Uses the official groq Python SDK.
"""

import os
import logging
from groq import Groq

logger = logging.getLogger(__name__)

_client = Groq(api_key=os.environ.get("GROQ_API_KEY", ""))
MODEL = "llama-3.1-8b-instant"
GEMMA_MODEL = "gemma2-9b-it"


# ── Message builder ────────────────────────────────────────────────────────────

def build_groq_messages(system_prompt: str, history: list[dict], user_message: str) -> list[dict]:
    """
    Convert CyberGuru history format → OpenAI-style messages list for Groq.
    history entries are expected as {"role": "user"|"bot", "content": "..."}
    """
    msgs = [{"role": "system", "content": system_prompt}]
    for h in history:
        role = "assistant" if h.get("role") == "bot" else "user"
        msgs.append({"role": role, "content": h.get("content", "")})
    msgs.append({"role": "user", "content": user_message})
    return msgs


# ── Non-streaming ──────────────────────────────────────────────────────────────

def groq_chat(messages: list[dict], model: str = MODEL) -> str:
    """Blocking Groq completion. Returns full reply string."""
    try:
        response = _client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=1024,
            temperature=0.7,
        )
        return response.choices[0].message.content
    except Exception:
        logger.exception("Groq non-streaming error")
        raise


# ── Streaming ──────────────────────────────────────────────────────────────────

def groq_stream(messages: list[dict], model: str = MODEL):
    """Generator that yields text chunks from Groq SSE stream."""
    try:
        stream = _client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=1024,
            temperature=0.7,
            stream=True,
        )
        for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta
    except Exception:
        logger.exception("Groq streaming error")
        raise