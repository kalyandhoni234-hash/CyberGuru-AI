import re

def extract_iocs(text):
    ips = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    urls = re.findall(
        r'https?://[^\s]+',
        text
    )

    emails = re.findall(
        r'[\w\.-]+@[\w\.-]+\.\w+',
        text
    )

    return {
        "ips": list(set(ips)),
        "urls": list(set(urls)),
        "emails": list(set(emails))
    }