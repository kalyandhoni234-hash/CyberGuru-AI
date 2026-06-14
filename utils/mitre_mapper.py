
MITRE_MAP = {
    "brute force": {
        "id": "T1110",
        "name": "Brute Force"
    },

    "phishing": {
        "id": "T1566",
        "name": "Phishing"
    },

    "powershell": {
        "id": "T1059.001",
        "name": "PowerShell"
    },

    "dns tunneling": {
        "id": "T1071.004",
        "name": "DNS Tunneling"
    }
}
def lookup_mitre(technique):

    return MITRE_MAP.get(
        technique.lower(),
        {
            "id": "Unknown",
            "name": technique
        }
    )