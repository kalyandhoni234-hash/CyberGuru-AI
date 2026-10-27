import time
import random
import logging
import requests
from config import (
    get_gemini_headers,
    BASE_BACKOFF,
    MAX_BACKOFF,
    MAX_JITTER,
    MAX_RETRIES,
)
logger = logging.getLogger(__name__)


class GeminiRateLimitError(Exception):
    pass


class GeminiServiceError(Exception):
    def __init__(self, status_code=None):
        self.status_code = status_code
        super().__init__(f"Gemini API error {status_code}")


def _backoff(attempt, retry_after=None):
    """Bounded exponential back-off with jitter (seconds)."""
    if retry_after is not None:
        try:
            seconds = int(retry_after)
        except (TypeError, ValueError):
            seconds = 0
        if seconds > 0:
            return min(seconds, MAX_BACKOFF)
    base = min(BASE_BACKOFF * (2 ** attempt), MAX_BACKOFF)
    return base + random.uniform(0, MAX_JITTER)


def gemini_post(url, payload, stream=False, timeout=60):
    """POST to Gemini with a bounded exponential back-off and jitter.

    Retries 429, 500, 502, 503 and 504.  Returns the response on success,
    or raises GeminiRateLimitError / GeminiServiceError.  Only the HTTP status
    is retained; response bodies are not exposed to callers.
    """
    last_status = None
    for attempt in range(MAX_RETRIES):
        resp = requests.post(
            url,
            json=payload,
            headers=get_gemini_headers(),
            timeout=timeout,
            stream=stream,
        )
        last_status = resp.status_code

        if resp.status_code == 200:
            return resp

        if resp.status_code == 429:
            wait = _backoff(attempt, resp.headers.get("Retry-After"))
            logger.warning("[Retry %d/%d] 429 rate limit — waiting %.1fs", attempt + 1, MAX_RETRIES, wait)
            resp.close()
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise GeminiRateLimitError()

        elif resp.status_code in (500, 502, 503, 504):
            wait = _backoff(attempt)
            logger.warning(
                "[Retry %d/%d] %d unavailable — waiting %.1fs",
                attempt + 1, MAX_RETRIES, resp.status_code, wait,
            )
            resp.close()
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise GeminiServiceError(last_status)

        else:
            resp.close()
            raise GeminiServiceError(last_status)

    raise GeminiServiceError(last_status)


def build_contents(history, new_message):
    """
    Convert frontend history format to Gemini contents array.
    history = [{"role": "user"|"bot", "text": "..."}]
    Gemini expects role = "user" | "model"
    Keeps last MAX_HISTORY_TURNS pairs (user+bot = 1 turn).
    """
    from config import MAX_HISTORY_TURNS, MAX_HISTORY_BYTES
    from utils.sanitize import sanitize_input

    contents = []

    max_msgs = MAX_HISTORY_TURNS * 2
    trimmed = history[-max_msgs:] if len(history) > max_msgs else history

    while trimmed:
        total = sum(len(m.get("text", "")) for m in trimmed)
        if total <= MAX_HISTORY_BYTES:
            break
        trimmed = trimmed[2:]  # drop oldest turn (user + bot pair)

    for msg in trimmed:
        role = msg.get("role", "")
        text = msg.get("text", "")
        if not role or not isinstance(text, str):
            continue
        text = sanitize_input(text)
        gemini_role = "model" if role == "bot" else "user"
        contents.append({
            "role": gemini_role,
            "parts": [{"text": text}]
        })

    contents.append({
        "role": "user",
        "parts": [{"text": new_message}]
    })

    return contents
