import re
from utils.sanitize import sanitize_filename


def extract_pdf_text(file_bytes):
    try:
        import io
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(file_bytes))
            pages = []
            for i, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                if text.strip():
                    pages.append(f"[Page {i+1}]\n{text.strip()}")
            return "\n\n".join(pages) if pages else None
        except ImportError:
            pass
        raw = file_bytes.decode("latin-1", errors="replace")
        chunks = re.findall(r'\((.*?)\)', raw)
        text = " ".join(c for c in chunks if len(c) > 2 and c.isprintable())
        return text[:8000] if len(text) > 50 else None
    except Exception:
        return None


def parse_log_file(content, filename):
    lines = content.splitlines()
    total_lines = len(lines)
    SUSPICIOUS = [
        "error", "fail", "denied", "unauthorized", "forbidden",
        "attack", "inject", "overflow", "exploit", "malware",
        "backdoor", "root", "sudo", "privilege", "brute",
        "invalid user", "authentication failure", "connection refused",
        "segfault", "killed", "timeout", "404", "500", "403", "401",
        "xss", "sql", "traversal", "payload", "shell", "exec",
    ]
    flagged = []
    for i, line in enumerate(lines, 1):
        if any(kw in line.lower() for kw in SUSPICIOUS):
            flagged.append(f"  Line {i}: {line.strip()}")
    sample_lines = lines[:100]
    if len(lines) > 100:
        sample_lines += ["", f"  ... [{total_lines - 100} more lines truncated] ...", ""]
        sample_lines += lines[-20:]
    summary = f"File: {filename}\nTotal lines: {total_lines}\n\n"
    summary += "=== FULL LOG SAMPLE ===\n"
    summary += "\n".join(sample_lines[:120])
    if flagged:
        summary += f"\n\n=== ⚠️ SUSPICIOUS LINES DETECTED ({len(flagged)}) ===\n"
        summary += "\n".join(flagged[:50])
        if len(flagged) > 50:
            summary += f"\n  ... and {len(flagged) - 50} more suspicious lines."
    return summary


def build_analysis_prompt(filename, content_summary, file_type):
    filename = sanitize_filename(filename)     # prevent prompt injection via filename
    ext = file_type.lower()
    if ext == "pdf":
        context = (
            "This is extracted text from a PDF document. "
            "Analyze it for: sensitive data exposure, embedded links or scripts, "
            "social engineering indicators, phishing content, or policy violations."
        )
    elif ext == "log":
        context = (
            "This is a system/application log file. "
            "Analyze it for: brute force attempts, unauthorized access, injection attacks, "
            "privilege escalation, suspicious IPs or commands, error patterns indicating exploitation."
        )
    else:
        context = (
            "Analyze this text file for: hardcoded credentials, API keys, suspicious commands, "
            "malicious scripts, vulnerabilities, or any cybersecurity concerns."
        )
    return (
        f"{context}\n\n"
        f"File name: {filename}\n\n"
        f"Content:\n{content_summary}"
    )
