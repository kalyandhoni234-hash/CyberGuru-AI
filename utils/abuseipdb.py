import os
import requests

def check_abuseipdb(ip):

    headers = {
        "Key": os.getenv("ABUSEIPDB_API_KEY"),
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params=params
    )

    return response.json()