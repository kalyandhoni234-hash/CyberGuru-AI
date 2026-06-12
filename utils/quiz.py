import re

QUIZ_TOPIC_ALLOWLIST = {
    "sql injection", "xss", "cross-site scripting", "malware", "phishing",
    "network security", "cryptography", "encryption", "ransomware", "firewall",
    "penetration testing", "owasp", "owasp top 10", "buffer overflow",
    "social engineering", "zero-day", "zero day", "ddos", "man in the middle",
    "mitm", "authentication", "authorization", "csrf", "cross-site request forgery",
    "idor", "ssrf", "xxe", "command injection", "path traversal", "jwt",
    "vpn", "ids", "ips", "siem", "threat modelling", "threat modeling",
    "incident response", "forensics", "reverse engineering", "web security",
    "cloud security", "iot security", "mobile security", "apt", "rootkit",
    "keylogger", "botnet", "spyware", "trojan", "worm", "virus",
}

MAX_QUIZ_TOPIC_LEN = 60


def sanitize_quiz_topic(raw_topic: str) -> str | None:
    """
    Validate and normalize a quiz topic against the allowlist.
    Returns the cleaned topic string on success, or None if not recognized.
    """
    topic = raw_topic.strip()[:MAX_QUIZ_TOPIC_LEN]
    topic = re.sub(r'[^\w\s\-]', '', topic).strip()
    if not topic:
        return None
    lower = topic.lower()
    if lower in QUIZ_TOPIC_ALLOWLIST:
        return topic
    if any(lower in allowed or allowed in lower for allowed in QUIZ_TOPIC_ALLOWLIST):
        return topic
    return None


def build_quiz_prompt(topic: str) -> str:
    return f"""
Generate a professional cybersecurity quiz.

Topic: {topic}

Rules:
- Create exactly 5 multiple-choice questions.
- Each question must have 4 options (A, B, C, D).
- Show the correct answer.
- Give a short explanation.
- Use markdown formatting.

Format:

# {topic.title()} Quiz

## Question 1

Question text

A) Option A
B) Option B
C) Option C
D) Option D

**Answer:** B

**Explanation:** Short explanation.

Repeat for 5 questions.
"""
