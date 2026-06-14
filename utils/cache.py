"""
Redis-based cache for threat-intel lookups (AbuseIPDB, VirusTotal).

Keeps repeat /investigate calls from burning API quota on IPs that
were already checked recently.
"""
import os
import json
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# Matches AbuseIPDB's maxAgeInDays=90 window used in abuseipdb_tool.py
ABUSEIPDB_TTL_SECONDS = 90 * 24 * 60 * 60

# VT data changes more often (new scans, detections) - shorter TTL
VIRUSTOTAL_TTL_SECONDS = 6 * 60 * 60


def _key(prefix, ip):
    return f"threatintel:{prefix}:{ip}"


def get_cached(prefix, ip):
    """Return cached result dict for (prefix, ip), or None if not cached."""
    try:
        raw = _redis_client.get(_key(prefix, ip))
    except redis.RedisError:
        return None

    if raw is None:
        return None

    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def set_cached(prefix, ip, value, ttl_seconds):
    """Store result dict for (prefix, ip) with the given TTL."""
    try:
        _redis_client.set(_key(prefix, ip), json.dumps(value), ex=ttl_seconds)
    except redis.RedisError:
        # Cache failures should never break the investigation
        pass


def get_abuseipdb_cached(ip):
    return get_cached("abuseipdb", ip)


def set_abuseipdb_cached(ip, value):
    set_cached("abuseipdb", ip, value, ABUSEIPDB_TTL_SECONDS)


def get_virustotal_cached(ip):
    return get_cached("virustotal", ip)


def set_virustotal_cached(ip, value):
    set_cached("virustotal", ip, value, VIRUSTOTAL_TTL_SECONDS)