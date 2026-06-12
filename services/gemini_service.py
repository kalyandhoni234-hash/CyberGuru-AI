import time
import requests
from config import GEMINI_HEADERS, MAX_RETRIES, BASE_BACKOFF


class GeminiRateLimitError(Exception):
    pass


class GeminiServiceError(Exception):
    def __init__(self, status_code=None):
        self.status_code = status_code
        super().__init__(f"Gemini API error {status_code}")


def gemini_post(url, payload, stream=False, timeout=60):
    """
    POST to Gemini with exponential backoff on 429 (rate limit) and 503 (unavailable).
    Returns the requests.Response object on success, or raises on final failure.
    Raises GeminiRateLimitError or GeminiServiceError for callers to handle cleanly.
    """
    last_status = None
    for attempt in range(MAX_RETRIES):
        resp = requests.post(
            url,
            json=payload,
            headers=GEMINI_HEADERS,
            timeout=timeout,
            stream=stream,
        )
        last_status = resp.status_code

        if resp.status_code == 200:
            return resp

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 0))
            wait = retry_after if retry_after > 0 else BASE_BACKOFF * (2 ** attempt)
            print(f"[Retry {attempt+1}/{MAX_RETRIES}] 429 rate limit — waiting {wait}s")
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise GeminiRateLimitError()

        elif resp.status_code == 503:
            wait = BASE_BACKOFF * (2 ** attempt)
            print(f"[Retry {attempt+1}/{MAX_RETRIES}] 503 unavailable — waiting {wait}s")
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            else:
                raise GeminiServiceError(last_status)

        else:
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
