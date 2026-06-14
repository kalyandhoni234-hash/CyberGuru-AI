import os
import requests

def check_virustotal_ip(ip):

    headers = {
        "x-apikey": os.getenv("VT_API_KEY")
    }

    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers=headers
    )

    return response.json()