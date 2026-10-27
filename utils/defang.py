"""
IOC defanging utilities.

Defanging neutralizes IPs, URLs, and domains so they don't render as
clickable links or trigger automated scanners/link-preview bots when
pasted into Slack, email, or tickets.

Standard conventions:
  192.168.1.1        -> 192[.]168[.]1[.]1
  http://evil.com    -> hxxp[://]evil[.]com
  https://evil.com   -> hxxps[://]evil[.]com
  user@evil.com      -> user[@]evil[.]com
"""
import re


def defang_ip(ip):
    return ip.replace(".", "[.]")


def defang_url(url):
    defanged = re.sub(r"^https?", lambda m: "hxxp" + m.group(0)[4:], url, flags=re.IGNORECASE)
    defanged = defanged.replace("://", "[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged


def defang_email(email):
    defanged = email.replace("@", "[@]")
    defanged = defanged.replace(".", "[.]")
    return defanged


def defang_domain(domain):
    return domain.replace(".", "[.]")


def defang_hash(h):
    # Hashes carry no clickable scheme or host — nothing to neutralise.
    return h


def defang_iocs(iocs):
    """
    Given an iocs dict ({"ips": [...], "domains": [...], "urls": [...],
    "hashes": [...], "emails": [...]}), return a new dict with all values
    defanged. Original dict is left untouched. Malformed/missing keys are
    treated as empty so export rendering cannot crash on a legacy row.
    """
    if not isinstance(iocs, dict):
        iocs = {}

    def values(key):
        raw = iocs.get(key)
        if not isinstance(raw, list):
            return []
        return [str(item) for item in raw if isinstance(item, (str, int, float))]

    return {
        "ips": [defang_ip(ip) for ip in values("ips")],
        "domains": [defang_domain(domain) for domain in values("domains")],
        "urls": [defang_url(url) for url in values("urls")],
        "hashes": [defang_hash(h) for h in values("hashes")],
        "emails": [defang_email(email) for email in values("emails")],
    }