import os
import requests

from utils.ioc_extractor import is_private_ip


def check_abuseipdb(ip, timeout=10):

    if is_private_ip(ip):
        return {"info": f"{ip} is a private/non-routable address — skipped lookup"}

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        raise RuntimeError("ABUSEIPDB_API_KEY environment variable is not set")

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params=params,
        timeout=timeout
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"AbuseIPDB request failed for {ip}: "
            f"HTTP {response.status_code} - {response.text[:200]}"
        )

    return response.json()