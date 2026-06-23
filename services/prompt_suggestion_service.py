"""
Prompt Suggestion Service — Dynamic personalised prompt pools.

Responsibilities:
  - Serve context-aware prompt suggestions based on user skill level and module.
  - Rotate randomly so users never see the same set every time.
  - Easily extensible: add entries to a pool dict, no template changes needed.

Every route that needs prompt suggestions MUST go through this service.
Never hardcode suggestions inside route handlers or templates.
"""

import random
import logging

from services.skill_profile_service import SkillProfileService

logger = logging.getLogger(__name__)

# ── Suggestion pools ──────────────────────────────────────────────────────────
# Structure: { module: { skill_level: [list of prompts] } }
# Add new modules or levels here without touching templates.

_SUGGESTION_POOLS = {

    # ── Main Chat ──────────────────────────────────────────────────────────
    "chat": {
        "beginner": [
            "What is phishing and how can I spot it?",
            "What is a firewall and how does it work?",
            "What is malware and what types exist?",
            "What is a VPN and how does it protect privacy?",
            "How does a DDoS attack work?",
            "What is the difference between a virus and a worm?",
            "What is a strong password policy?",
            "How does two-factor authentication work?",
            "What is ransomware and how can I stay safe?",
            "What is social engineering in cybersecurity?",
            "How do I secure my home Wi-Fi network?",
            "What is encryption and why is it important?",
            "What is an IP address and how can it be traced?",
            "Explain what a botnet is in simple terms.",
            "What is a zero-day vulnerability?",
        ],
        "intermediate": [
            "Explain DNS cache poisoning and how to prevent it.",
            "How does ARP spoofing work in a local network?",
            "Analyze a suspicious PowerShell script for malware.",
            "What is MITRE ATT&CK and how do SOC teams use it?",
            "Compare IDS vs IPS — which should you deploy?",
            "How does SSL/TLS handshake work step by step?",
            "What is Kerberos and how does it authenticate users?",
            "Explain SQL injection mitigation techniques.",
            "How do you detect lateral movement in a network?",
            "What is the Cyber Kill Chain framework?",
            "How does OAuth 2.0 flow work and what are its risks?",
            "Describe how to harden a Linux web server.",
            "What are common Active Directory attack vectors?",
            "How does a reverse shell work and how can you detect it?",
            "Explain the difference between symmetric and asymmetric encryption.",
        ],
        "advanced": [
            "Map this attack chain to MITRE ATT&CK techniques and sub-techniques.",
            "Create Sigma rules to detect this malicious behavior pattern.",
            "Explain EDR evasion techniques — process injection, API unhooking, ETW patching.",
            "Design a detection pipeline for fileless malware using Sysmon and EDR telemetry.",
            "Analyze the tradeoffs between signature-based and behavioral detection at scale.",
            "How would you bypass AMSI in a modern Windows environment?",
            "Describe the internals of a kernel-mode rootkit and detection strategies.",
            "What are the latest CVE-based exploitation chains for enterprise VPN appliances?",
            "Build a YARA rule set for APT32 (OceanLotus) malware families.",
            "Explain how to implement a SOAR playbook for automated incident triage.",
            "Compare Sysmon vs ETW for advanced threat detection on Windows.",
            "How does Kerberoasting work and what are the best defenses?",
            "Design an architecture for a zero-trust network with micro-segmentation.",
            "What are the forensic artifacts left by a successful Pass-the-Hash attack?",
            "Analyze the detection gaps in current EDR solutions for living-off-the-land binaries.",
        ],
    },

    # ── Investigation Center ──────────────────────────────────────────────
    "investigate": {
        "beginner": [
            "Check this IP address: 185.220.101.45 — is it malicious?",
            "Analyze this suspicious link: http://bit.ly/3xExample",
            "Is this email header suspicious? From: security@paypa1.com",
            "Look up this domain: malwaresite.tk",
            "Analyze this log entry: Failed password for root from 10.0.0.5",
            "Is this file hash known malware? d41d8cd98f00b204e9800998ecf8427e",
            "Check if 192.168.1.1 shows any suspicious activity.",
            "Analyze this URL for phishing indicators: http://free-iphone.fake.com",
            "Scan this IP: 45.33.32.156 — what threat feeds report it?",
            "What can you tell me about this domain: examplemalware.com?",
        ],
        "intermediate": [
            "Analyze this phishing email: 'Urgent: Verify your account now' with headers.",
            "Investigate this C2 beacon traffic pattern in the PCAP summary.",
            "Correlate these IOCs: IP 5.188.62.18, domain evilcorp.xyz, hash a1b2c3d4.",
            "Parse this Windows Event ID 4625 log for brute force indicators.",
            "Analyze this suspicious macro embedded in a Word document.",
            "Check if 203.0.113.5 appears in any known threat intelligence feeds.",
            "Map these network connections to MITRE ATT&CK techniques.",
            "Investigate this potential data exfiltration pattern in the logs.",
            "Analyze this email with headers showing SPF/DKIM/DMARC failures.",
            "Is this domain generated by a DGA algorithm? xyzabc123.xyz",
        ],
        "advanced": [
            "Perform full threat intel enrichment and map the entire attack chain to MITRE ATT&CK.",
            "Correlate these IOCs across VirusTotal, AbuseIPDB, and ThreatFox — what's the overlap?",
            "Analyze this encrypted C2 traffic pattern and suggest detection rules.",
            "Reverse-engineer this PowerShell payload and map it to MITRE techniques.",
            "Build a complete timeline of this multi-stage attack from the provided evidence.",
            "Identify the root cause and suggest remediation for this Active Directory compromise.",
            "Create a detection rule set for this APT group's TTPs based on the evidence.",
            "Perform a deep-dive analysis of this Lazarus Group artifact.",
            "Analyze this memory dump excerpt for process injection indicators.",
            "Correlate the Diamond Model with the evidence and identify the adversary.",
        ],
    },

    # ── CTF Challenge Mode ──────────────────────────────────────────────
    "ctf": {
        "beginner": [
            "Help me understand this CTF challenge scenario.",
            "What are common CTF techniques for beginners?",
            "Walk me through a basic buffer overflow CTF.",
            "How do I approach a web exploitation CTF challenge?",
            "What tools should I have ready for CTF competitions?",
        ],
        "intermediate": [
            "Analyze this CTF challenge and suggest an approach.",
            "What's the best strategy for binary exploitation CTFs?",
            "How do I chain multiple vulnerabilities in a CTF?",
            "Explain the methodology for solving reverse engineering CTFs.",
            "What are common pitfalls in CTF cryptography challenges?",
        ],
        "advanced": [
            "Develop an exploit strategy for this multi-stage CTF challenge.",
            "Analyze the anti-debugging techniques in this CTF binary.",
            "How would you approach a kernel exploitation CTF?",
            "Explain advanced heap exploitation techniques for CTF challenges.",
            "Design a custom payload for this CTF shellcode challenge.",
        ],
    },

    # ── Mentor Mode ───────────────────────────────────────────────────────
    "mentor": {
        "beginner": [
            "What learning path should I follow to start in cybersecurity?",
            "What certifications should a beginner aim for?",
            "Explain the CIA triad with examples.",
            "What tools should I learn first as a beginner?",
            "How do I set up a home lab for practice?",
            "What is ethical hacking and is it legal?",
            "Where can I find beginner Capture The Flag challenges?",
            "How do I start learning about network security?",
            "What are the best YouTube channels for cybersecurity beginners?",
            "What is the difference between white hat, black hat, and grey hat hackers?",
        ],
        "intermediate": [
            "Design a study plan to prepare for CompTIA Security+ in 3 months.",
            "What are the most common mistakes in penetration testing reports?",
            "How do I transition from IT support to a SOC analyst role?",
            "Explain how to conduct a proper risk assessment for a small business.",
            "What labs should I build to practice Active Directory attacks?",
            "Compare Blue Team vs Red Team career paths and required skills.",
            "How do you explain technical vulnerabilities to non-technical stakeholders?",
            "What is the OSCP exam format and how should I prepare?",
            "How do I build a custom CTF challenge for my team?",
            "What are the key metrics for measuring SOC performance?",
        ],
        "advanced": [
            "Design a purple team exercise from scratch — what scenarios and metrics?",
            "How do you architect a detection engineering program for a Fortune 500?",
            "What are the biggest gaps in current EDR/XDR platforms and how would you fix them?",
            "Explain how to build and train a phishing simulation campaign at enterprise scale.",
            "How do you conduct a red team engagement with no known TTP signatures?",
            "What is the optimal SIEM architecture for ingesting 50TB+ of logs daily?",
            "Design a threat hunting hypothesis based on the latest CISA advisory.",
            "How would you build a threat intelligence team from the ground up?",
            "Explain the challenges of attribution in APT investigations.",
            "What are the most effective methods for measuring detection coverage across MITRE ATT&CK?",
        ],
    },
}

# ── Number of suggestions to return per call ──────────────────────────────────
_DEFAULT_COUNT = 4


class PromptSuggestionService:
    """Central service for dynamic, personalised prompt suggestions."""

    def __init__(self, user_id: int):
        self.user_id = user_id
        self._profile_service = SkillProfileService(user_id)

    def get_suggestions(self, module: str, count: int = None, q: str = None) -> list:
        """Return a randomly rotated list of prompt suggestions.

        Args:
            module: One of 'chat', 'investigate', 'mentor', 'ctf'.
            count:  Number of suggestions to return (default: 4).
            q:      Optional query string to filter suggestions (case-insensitive).

        Returns:
            List of suggestion strings.
        """
        if count is None:
            count = _DEFAULT_COUNT

        pool = _SUGGESTION_POOLS.get(module)
        if not pool:
            logger.warning("Unknown module '%s' requested suggestions", module)
            return []

        # Load the user's skill level (fresh from DB each call)
        try:
            self._profile_service.sync()
            profile = self._profile_service.get_profile()
            level = (profile.get("skill_level") or "beginner").lower()
            logger.debug("Suggestions for user=%s module=%s skill=%s", self.user_id, module, level)
        except Exception:
            logger.exception("Failed to load profile for suggestion service, falling back to beginner")
            level = "beginner"

        # Get the pool for this level (fall back to beginner if level missing)
        suggestions = pool.get(level) or pool.get("beginner", [])

        if not suggestions:
            return []

        # Filter by query if provided
        if q:
            q_lower = q.lower()
            suggestions = [s for s in suggestions if q_lower in s.lower()]

        if not suggestions:
            return []

        # Random rotation: shuffle and take requested count
        selected = random.sample(suggestions, min(count, len(suggestions)))
        return selected
