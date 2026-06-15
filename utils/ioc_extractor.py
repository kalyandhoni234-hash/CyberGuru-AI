import re
import ipaddress


def is_private_ip(ip_str):
    """
    Return True if the IP is private, loopback, link-local, multicast,
    or otherwise non-globally-routable — i.e. not worth querying
    AbuseIPDB / VirusTotal for.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        # Malformed address — treat as non-routable
        return True


def extract_iocs(text):
    raw_ips = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    # Keep only globally routable IPs
    ips = [ip for ip in set(raw_ips) if not is_private_ip(ip)]

    urls = re.findall(
        r'https?://[^\s]+',
        text
    )

    emails = re.findall(
        r'[\w\.-]+@[\w\.-]+\.\w+',
        text
    )

    return {
        "ips": list(ips),
        "urls": list(set(urls)),
        "emails": list(set(emails))
    }