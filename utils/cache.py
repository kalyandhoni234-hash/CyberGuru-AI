"""
Cache for threat-intel lookups (AbuseIPDB, VirusTotal).

Keeps repeat /investigate calls from burning API quota on IPs that
were already checked recently.

Uses Redis if available, otherwise falls back to in-memory cache.
"""
import os
import json
from datetime import datetime, timedelta

# Try to import Redis, but don't fail if it's not installed
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

REDIS_URL = os.getenv("REDIS_URL")

# Initialize Redis client only if REDIS_URL is set and redis is available
_redis_client = None
if REDIS_AVAILABLE and REDIS_URL:
    try:
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        _redis_client.ping()  # Test connection
    except Exception:
        _redis_client = None  # Fall back to in-memory if connection fails

# In-memory cache fallback (simple dict with expiry times)
_memory_cache = {}

# Matches AbuseIPDB's maxAgeInDays=90 window used in abuseipdb_tool.py
ABUSEIPDB_TTL_SECONDS = 90 * 24 * 60 * 60

# VT data changes more often (new scans, detections) - shorter TTL
VIRUSTOTAL_TTL_SECONDS = 6 * 60 * 60


def _key(prefix, ip):
    return f"threatintel:{prefix}:{ip}"


def get_cached(prefix, ip):
    """Return cached result dict for (prefix, ip), or None if not cached."""
    key = _key(prefix, ip)
    
    # Try Redis first
    if _redis_client:
        try:
            raw = _redis_client.get(key)
            if raw:
                return json.loads(raw)
        except Exception:
            pass  # Fall through to memory cache
    
    # Fall back to in-memory cache
    if key in _memory_cache:
        entry = _memory_cache[key]
        # Check if expired
        if datetime.now() < entry["expires_at"]:
            return entry["value"]
        else:
            del _memory_cache[key]
    
    return None


def set_cached(prefix, ip, value, ttl_seconds):
    """Store result dict for (prefix, ip) with the given TTL."""
    key = _key(prefix, ip)
    
    # Try Redis first
    if _redis_client:
        try:
            _redis_client.set(key, json.dumps(value), ex=ttl_seconds)
            return
        except Exception:
            pass  # Fall through to memory cache
    
    # Fall back to in-memory cache
    _memory_cache[key] = {
        "value": value,
        "expires_at": datetime.now() + timedelta(seconds=ttl_seconds)
    }


def get_abuseipdb_cached(ip):
    return get_cached("abuseipdb", ip)


def set_abuseipdb_cached(ip, value):
    set_cached("abuseipdb", ip, value, ABUSEIPDB_TTL_SECONDS)


def get_virustotal_cached(ip):
    return get_cached("virustotal", ip)


def set_virustotal_cached(ip, value):
    set_cached("virustotal", ip, value, VIRUSTOTAL_TTL_SECONDS)