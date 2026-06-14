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


def defang_iocs(iocs):
    """
    Given an iocs dict ({"ips": [...], "urls": [...], "emails": [...]}),
    return a new dict with all values defanged. Original dict is left
    untouched.
    """
    return {
        "ips": [defang_ip(ip) for ip in iocs.get("ips", [])],
        "urls": [defang_url(url) for url in iocs.get("urls", [])],
        "emails": [defang_email(email) for email in iocs.get("emails", [])],
    }