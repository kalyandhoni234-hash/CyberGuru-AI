import re
import ipaddress


# RFC 5737 TEST-NET ranges used in documentation/examples. Python's
# ipaddress marks these is_private=True (they overlap the IANA special-use
# registry) but they are NOT globally routable either, so classify them
# explicitly so they can be labelled accurately and skipped by threat-intel
# lookups.
_TESTNET_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

# Why an IP is not worth a threat-intel lookup, keyed by ip_scope() result.
SCOPE_REASONS = {
    "documentation": "Reserved/Documentation Range (RFC 5737 TEST-NET)",
    "private":       "Private Network Range (RFC 1918)",
    "link_local":    "Link-Local Range (RFC 3927)",
    "loopback":      "Loopback Range",
    "reserved":      "Reserved/Multicast Range",
    "unspecified":   "Unspecified Address",
    "invalid":       "Not a Valid IP Address",
}

# Scopes that should never be sent to AbuseIPDB / VirusTotal.
NON_ROUTABLE_SCOPES = {
    "private",
    "documentation",
    "link_local",
    "loopback",
    "reserved",
    "unspecified",
    "invalid",
}


def ip_scope(ip_str):
    """
    Classify an IP address by routability scope.

    Returns one of: "global", "private" (RFC 1918), "documentation"
    (RFC 5737 TEST-NET), "link_local", "loopback", "reserved",
    "unspecified", or "invalid".
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_link_local:
        return "link_local"
    if any(addr in net for net in _TESTNET_NETS):
        return "documentation"
    if addr.is_multicast or addr.is_reserved:
        return "reserved"
    if addr.is_private:
        return "private"
    return "global"


def is_private_ip(ip_str):
    """
    Return True if the IP is private, loopback, link-local, multicast,
    documentation (TEST-NET), reserved, or otherwise non-globally-routable
    — i.e. not worth querying AbuseIPDB / VirusTotal for.
    """
    return ip_scope(ip_str) in NON_ROUTABLE_SCOPES


def _unique(items):
    """Deduplicate a sequence preserving first-seen order."""
    return list(dict.fromkeys(items))


def extract_all_ips(text):
    """
    Return every IP-like token in the text that parses as a valid IPv4/IPv6
    address, in first-seen order. Unlike extract_iocs(), private and
    documentation addresses are NOT filtered out — the caller decides how to
    classify them.
    """
    out = []
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        out.append(token)
    return _unique(out)


_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_domains(text):
    """Return distinct domain names (lowercased) in first-seen order."""
    return _unique([d.lower() for d in _DOMAIN_RE.findall(text)])


def extract_hashes(text):
    """Return distinct file hashes (MD5/SHA1/SHA256, lowercased hex) in
    first-seen order."""
    out = []
    for pattern in (_SHA256_RE, _SHA1_RE, _MD5_RE):
        for h in pattern.findall(text):
            out.append(h.lower())
    return _unique(out)


def extract_iocs(text, include_private_ips=False):
    """
    Extract indicators of compromise from free text.

    Returns a dict with the keys ips, domains, urls, hashes, emails.
    Globally-routable IPs are kept by default; set include_private_ips=True
    to retain private/documentation/etc. addresses (used when the caller
    wants every IP classified, e.g. to attach a verification status).
    """
    raw_ips = extract_all_ips(text)
    if include_private_ips:
        ips = raw_ips
    else:
        ips = [ip for ip in raw_ips if not is_private_ip(ip)]

    urls = re.findall(r'https?://[^\s]+', text)
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)

    return {
        "ips": _unique(ips),
        "domains": extract_domains(text),
        "urls": _unique(urls),
        "hashes": extract_hashes(text),
        "emails": _unique(emails),
    }
