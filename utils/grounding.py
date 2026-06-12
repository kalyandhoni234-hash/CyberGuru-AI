from config import GROUNDING_KEYWORDS


def needs_grounding(message: str) -> bool:
    """Check if a user message likely needs live web search grounding."""
    lower = message.lower()
    return any(kw in lower for kw in GROUNDING_KEYWORDS)
