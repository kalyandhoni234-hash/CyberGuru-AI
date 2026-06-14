import os
import requests

from utils.cache import get_virustotal_cached, set_virustotal_cached


def check_virustotal_ip(ip, timeout=10):

    cached = get_virustotal_cached(ip)
    if cached is not None:
        return cached

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        raise RuntimeError("VT_API_KEY environment variable is not set")

    headers = {
        "x-apikey": api_key
    }

    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers=headers,
        timeout=timeout
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"VirusTotal request failed for {ip}: "
            f"HTTP {response.status_code} - {response.text[:200]}"
        )

    result = response.json()
    set_virustotal_cached(ip, result)
    return result