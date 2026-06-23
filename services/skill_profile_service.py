"""
Skill Profile Service — Adaptive Intelligence Layer.

Responsibilities:
  - Load/sync user profile and learning progress from PostgreSQL.
  - Build dynamic adaptive prompts based on skill level and progress.
  - Centralised single source of truth for all profile-aware decisions.

Every route that needs profile context MUST go through this service.
Never hardcode adaptive logic inside route handlers.
"""

import logging

from services.db_service import (
    get_or_create_profile,
    update_profile,
    get_or_create_learning_progress,
    update_learning_progress,
)

logger = logging.getLogger(__name__)

SKILL_LEVELS = ("beginner", "intermediate", "advanced")

# ── Adaptive instruction blocks ───────────────────────────────────────────────

_ADAPTIVE_INSTRUCTIONS = {
    "beginner": (
        "## USER PROFILE: Beginner Cybersecurity Learner\n"
        "The user is NEW to cybersecurity concepts.\n"
        "\n"
        "### Teaching Guidelines\n"
        "- Explain ALL terminology before using it — define every acronym and technical term.\n"
        "- Use real-world analogies (e.g. 'a firewall is like a security guard at a building entrance').\n"
        "- Teach step-by-step. Never skip intermediate reasoning.\n"
        "- Avoid overwhelming the user with jargon. If a technical term is necessary, explain it simply first.\n"
        "- Focus on understanding CORE CONCEPTS before diving into tools or commands.\n"
        "- When showing commands or code, explain EVERY line and flag.\n"
        "- Encourage questions. Check for understanding.\n"
        "- Be patient and supportive. Mistakes are learning opportunities.\n"
        "- Suggest beginner-friendly labs and reading materials.\n"
        "- Keep responses focused and practical. Avoid theoretical tangents.\n"
    ),
    "intermediate": (
        "## USER PROFILE: Intermediate Cybersecurity Learner\n"
        "The user has FOUNDATIONAL knowledge of cybersecurity concepts.\n"
        "\n"
        "### Teaching Guidelines\n"
        "- Assume the user knows basic terminology (firewall, encryption, VPN, IDS/IPS, etc.).\n"
        "- Include security TOOLS in explanations (Wireshark, Nmap, Burp Suite, Metasploit, etc.).\n"
        "- Describe PRACTICAL WORKFLOWS — how things are done in real security operations.\n"
        "- Increase technical DEPTH. Explain configuration options, attack variants, detection methods.\n"
        "- Provide command-line examples with explanation of switches (but don't explain basic flags).\n"
        "- Connect concepts to real-world attack scenarios and defensive strategies.\n"
        "- Encourage hands-on practice with specific tool-based exercises.\n"
        "- Introduce relevant frameworks (MITRE ATT&CK, NIST, OWASP) and explain how to use them.\n"
        "- Balance breadth and depth — cover multiple angles of a topic.\n"
    ),
    "advanced": (
        "## USER PROFILE: Advanced Cybersecurity Learner\n"
        "The user has SOLID cybersecurity experience and technical background.\n"
        "\n"
        "### Teaching Guidelines\n"
        "- Assume strong cybersecurity fundamentals. Do NOT explain basic concepts.\n"
        "- Focus on IMPLEMENTATION details — how to deploy, configure, and tune defenses.\n"
        "- Discuss ARCHITECTURE — how systems are designed, where weaknesses emerge.\n"
        "- Cover ATTACK/DEFENSE TRADEOFFS — cost, complexity, detection evasion, false positives.\n"
        "- Include advanced evasion techniques, detection bypass methods, and how to counter them.\n"
        "- Reference CVEs, exploit code, and real-world APT techniques where relevant.\n"
        "- Discuss tool internals, protocol-level details, and performance considerations.\n"
        "- Provide deep-dive scenarios: red team / blue team / purple team exercises.\n"
        "- Challenge the user with edge cases, corner cases, and non-obvious attack paths.\n"
        "- Use precise technical language. Avoid unnecessary introductory fluff.\n"
        "- Be direct. Assume the user wants depth over breadth.\n"
    ),
}


class SkillProfileService:
    """Central service for user profile intelligence."""

    def __init__(self, user_id: int):
        if not user_id:
            raise ValueError("user_id is required")
        self.user_id = user_id
        self._profile = None
        self._progress = None

    # ── Profile loading ───────────────────────────────────────────────────────

    def get_profile(self) -> dict:
        if self._profile is None:
            self._profile = dict(get_or_create_profile(self.user_id))
        return self._profile

    def get_progress(self) -> dict:
        if self._progress is None:
            self._progress = dict(get_or_create_learning_progress(self.user_id))
        return self._progress

    def sync(self):
        """Reload both profile and progress from the database."""
        self._profile = dict(get_or_create_profile(self.user_id))
        self._progress = dict(get_or_create_learning_progress(self.user_id))

    # ── Profile mutations ────────────────────────────────────────────────────

    def set_skill_level(self, level: str) -> dict:
        if level not in SKILL_LEVELS:
            raise ValueError(f"Invalid skill level: {level}. Must be one of {SKILL_LEVELS}")
        self._profile = dict(update_profile(self.user_id, skill_level=level))
        return self._profile

    def complete_onboarding(self, level: str) -> dict:
        if level not in SKILL_LEVELS:
            raise ValueError(f"Invalid skill level: {level}")
        self._profile = dict(update_profile(
            self.user_id,
            skill_level=level,
            onboarding_completed=True,
        ))
        self._progress = dict(get_or_create_learning_progress(self.user_id))
        return self._profile

    # ── Progress mutations ───────────────────────────────────────────────────

    def increment_lessons(self, n: int = 1) -> dict:
        p = self.get_progress()
        new_val = (p.get("completed_lessons") or 0) + n
        self._progress = dict(update_learning_progress(
            self.user_id, completed_lessons=new_val
        ))
        return self._progress

    def increment_quizzes(self, n: int = 1) -> dict:
        p = self.get_progress()
        new_val = (p.get("completed_quizzes") or 0) + n
        self._progress = dict(update_learning_progress(
            self.user_id, completed_quizzes=new_val
        ))
        return self._progress

    def increment_labs(self, n: int = 1) -> dict:
        p = self.get_progress()
        new_val = (p.get("completed_labs") or 0) + n
        self._progress = dict(update_learning_progress(
            self.user_id, completed_labs=new_val
        ))
        return self._progress

    def set_current_topic(self, topic: str) -> dict:
        self._progress = dict(update_learning_progress(
            self.user_id, current_topic=topic
        ))
        return self._progress

    def set_progress_percentage(self, pct: float) -> dict:
        clamped = max(0.0, min(100.0, float(pct)))
        self._progress = dict(update_learning_progress(
            self.user_id, progress_percentage=round(clamped, 2)
        ))
        return self._progress

    # ── Adaptive prompt builder ──────────────────────────────────────────────

    def build_adaptive_system_prompt(self, base_prompt: str = "") -> str:
        """Build a dynamic system prompt incorporating the user's skill level.

        Args:
            base_prompt: The default system instruction to augment.

        Returns:
            A complete system prompt string with adaptive instructions appended.
        """
        profile = self.get_profile()
        progress = self.get_progress()

        level = (profile.get("skill_level") or "beginner").lower()
        current_topic = progress.get("current_topic") or ""

        parts = [base_prompt] if base_prompt else []

        # Adaptive instruction block
        level_instruction = _ADAPTIVE_INSTRUCTIONS.get(level, _ADAPTIVE_INSTRUCTIONS["beginner"])
        parts.append(level_instruction)

        # Topic context block
        if current_topic:
            parts.append(
                f"The user is currently studying: {current_topic}. "
                f"Tailor explanations to help them master this topic."
            )

        # Progress context block
        lessons = progress.get("completed_lessons") or 0
        quizzes = progress.get("completed_quizzes") or 0
        labs = progress.get("completed_labs") or 0
        pct = progress.get("progress_percentage") or 0
        parts.append(
            f"## USER PROGRESS\n"
            f"Lessons completed: {lessons}  |  Quizzes completed: {quizzes}  |  "
            f"Labs completed: {labs}  |  Overall progress: {pct}%"
        )

        return "\n\n".join(parts)

    # ── Summary helper ────────────────────────────────────────────────────────

    def get_profile_summary(self) -> dict:
        """Return a concise JSON-serialisable profile summary for the frontend."""
        profile = self.get_profile()
        progress = self.get_progress()

        return {
            "skill_level": profile.get("skill_level"),
            "onboarding_completed": profile.get("onboarding_completed", False),
            "completed_lessons": progress.get("completed_lessons") or 0,
            "completed_quizzes": progress.get("completed_quizzes") or 0,
            "completed_labs": progress.get("completed_labs") or 0,
            "current_topic": progress.get("current_topic"),
            "progress_percentage": float(progress.get("progress_percentage") or 0),
        }
