import re
from config import MAX_INPUT_CHARS, MAX_HISTORY_MSG_CHARS

ALLOWED_HISTORY_ROLES = {"user", "bot"}


def sanitize_input(text: str) -> str:
    """
    Strip null bytes and non-printable control characters,
    then hard-cap length to MAX_INPUT_CHARS.
    """
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
    if len(cleaned) > MAX_INPUT_CHARS:
        cleaned = cleaned[:MAX_INPUT_CHARS]
    return cleaned.strip()


def sanitize_filename(filename: str) -> str:
    """Strip path separators and special chars from a filename before prompt inclusion."""
    import os
    name = os.path.basename(filename)
    name = re.sub(r'[^\w.\-\s]', '_', name)
    return name[:120].strip()


def validate_history(raw_history) -> list:
    """
    Sanitize client-supplied history before it reaches Gemini.
    - Rejects non-list input entirely.
    - Drops entries with invalid/missing roles.
    - Drops entries with non-string or empty text.
    - Truncates each entry's text to MAX_HISTORY_MSG_CHARS.
    """
    if not isinstance(raw_history, list):
        return []

    clean = []
    for entry in raw_history:
        if not isinstance(entry, dict):
            continue
        role = entry.get("role", "")
        text = entry.get("text", "")
        if role not in ALLOWED_HISTORY_ROLES:
            continue
        if not isinstance(text, str) or not text.strip():
            continue
        clean.append({
            "role": role,
            "text": sanitize_input(text[:MAX_HISTORY_MSG_CHARS]),
        })

    return clean
