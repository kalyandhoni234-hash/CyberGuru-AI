"""AbuseIPDB IP reputation lookup.

All failures are returned as structured errors with a small, sanitized
``error_code``. Provider response bodies and API keys are never returned to
callers and never logged. A failed lookup is not a clean result.
"""

import ipaddress
import logging
import os

import requests

from config import THREAT_INTEL_TIMEOUT_SECONDS
from utils.cache import get_abuseipdb_cached, set_abuseipdb_cached
from utils.ioc_extractor import is_private_ip, ip_scope, SCOPE_REASONS

logger = logging.getLogger(__name__)

_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


def _not_applicable(ip):
    return {
        "status": "not_applicable",
        "ip": ip,
        "reason": SCOPE_REASONS.get(ip_scope(ip), "Not a routable address"),
    }


def _error(ip, code, message):
    return {
        "status": "error",
        "ip": ip,
        "error_code": code,
        "error": message,
    }


def _normalise_ip(ip):
    """Return a canonical IP string, or None when the value is not an IP."""
    if not isinstance(ip, str) or not ip.strip():
        return None
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None


def _http_error(ip, status_code):
    """Map an HTTP status to a sanitized error without echoing the body."""
    if status_code in (401, 403):
        return _error(ip, "authentication", "Threat-intel provider rejected the credentials.")
    if status_code == 429:
        return _error(ip, "rate_limited", "Threat-intel provider rate limit reached.")
    if status_code >= 500:
        return _error(ip, "unavailable", "Threat-intel provider is unavailable.")
    return _error(ip, "http_error", f"Threat-intel provider returned HTTP {status_code}.")


def check_abuseipdb(ip, timeout=THREAT_INTEL_TIMEOUT_SECONDS):
    """Look up an IP on AbuseIPDB.

    Returns a dict with a ``status`` of:
      - ``not_applicable`` for private/documentation/etc. IPs (never called)
      - ``ok`` with the provider payload under ``data`` (and ``cached`` when
        served from the TTL cache)
      - ``not_found`` when AbuseIPDB has no record (HTTP 404)
      - ``error`` with a sanitized ``error_code`` for config/network/HTTP
        failures or malformed JSON
    """
    canonical = _normalise_ip(ip)
    if canonical is None:
        return _not_applicable(ip if isinstance(ip, str) else "unknown")

    ip = canonical
    if is_private_ip(ip):
        return _not_applicable(ip)

    cached = get_abuseipdb_cached(ip)
    if isinstance(cached, dict):
        return {"status": "ok", "ip": ip, "cached": True, **cached}

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return _error(ip, "configuration", "Threat-intel provider is not configured.")

    try:
        response = requests.get(
            _ENDPOINT,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return _error(ip, "timeout", "Threat-intel lookup timed out.")
    except requests.exceptions.RequestException as exc:
        logger.warning("AbuseIPDB request failed: %s", type(exc).__name__)
        return _error(ip, "unavailable", "Threat-intel provider is unavailable.")

    if response.status_code == 404:
        return {"status": "not_found", "ip": ip, "message": "No results found for this IP"}
    if response.status_code != 200:
        logger.warning("AbuseIPDB HTTP %s", response.status_code)
        return _http_error(ip, response.status_code)

    try:
        payload = response.json()
    except ValueError:
        return _error(ip, "malformed_response", "Threat-intel provider returned an invalid response.")
    if not isinstance(payload, dict):
        return _error(ip, "malformed_response", "Threat-intel provider returned an invalid response.")

    set_abuseipdb_cached(ip, payload)
    return {"status": "ok", "ip": ip, **payload}
