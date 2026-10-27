"""VirusTotal IP reputation lookup.

All failures are returned as structured errors with a small, sanitized
``error_code``. Provider response bodies and API keys are never returned to
callers and never logged. A failed lookup is not a clean result.

Configuration accepts either ``VT_API_KEY`` or the documented
``VIRUSTOTAL_API_KEY`` name; the former wins if both are set.
"""

import ipaddress
import logging
import os

import requests

from config import THREAT_INTEL_TIMEOUT_SECONDS
from utils.cache import get_virustotal_cached, set_virustotal_cached
from utils.ioc_extractor import is_private_ip, ip_scope, SCOPE_REASONS

logger = logging.getLogger(__name__)

_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


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
    if not isinstance(ip, str) or not ip.strip():
        return None
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None


def _http_error(ip, status_code):
    if status_code in (401, 403):
        return _error(ip, "authentication", "Threat-intel provider rejected the credentials.")
    if status_code == 429:
        return _error(ip, "rate_limited", "Threat-intel provider rate limit reached.")
    if status_code >= 500:
        return _error(ip, "unavailable", "Threat-intel provider is unavailable.")
    return _error(ip, "http_error", f"Threat-intel provider returned HTTP {status_code}.")


def _api_key():
    return os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")


def check_virustotal_ip(ip, timeout=THREAT_INTEL_TIMEOUT_SECONDS):
    """Look up an IP on VirusTotal.

    Returns a dict with a ``status`` of:
      - ``not_applicable`` for private/documentation/etc. IPs (never called)
      - ``ok`` with the provider payload under ``data`` (and ``cached`` when
        served from the TTL cache)
      - ``not_found`` when VirusTotal has no record (HTTP 404)
      - ``error`` with a sanitized ``error_code`` for config/network/HTTP
        failures or malformed JSON
    """
    canonical = _normalise_ip(ip)
    if canonical is None:
        return _not_applicable(ip if isinstance(ip, str) else "unknown")

    ip = canonical
    if is_private_ip(ip):
        return _not_applicable(ip)

    cached = get_virustotal_cached(ip)
    if isinstance(cached, dict):
        return {"status": "ok", "ip": ip, "cached": True, **cached}

    api_key = _api_key()
    if not api_key:
        return _error(ip, "configuration", "Threat-intel provider is not configured.")

    try:
        response = requests.get(
            _ENDPOINT.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
    except requests.exceptions.Timeout:
        return _error(ip, "timeout", "Threat-intel lookup timed out.")
    except requests.exceptions.RequestException as exc:
        logger.warning("VirusTotal request failed: %s", type(exc).__name__)
        return _error(ip, "unavailable", "Threat-intel provider is unavailable.")

    if response.status_code == 404:
        return {"status": "not_found", "ip": ip, "message": "No results found for this IP"}
    if response.status_code != 200:
        logger.warning("VirusTotal HTTP %s", response.status_code)
        return _http_error(ip, response.status_code)

    try:
        payload = response.json()
    except ValueError:
        return _error(ip, "malformed_response", "Threat-intel provider returned an invalid response.")
    if not isinstance(payload, dict):
        return _error(ip, "malformed_response", "Threat-intel provider returned an invalid response.")

    set_virustotal_cached(ip, payload)
    return {"status": "ok", "ip": ip, **payload}
