"""
routes/threat_pulse.py
──────────────────────
Threat Pulse dashboard — aggregates four live cyber-threat data sources
into a single JSON response served at  GET /api/threat-pulse.

Sources:
  1. News headlines  — RSS feeds already used by news.py, no key needed
                       (The Hacker News + BleepingComputer)
  2. Recent CVEs     — NVD NIST REST API v2, no key needed (5 req / 30 s limit)
  3. CISA KEV        — CISA Known Exploited Vulnerabilities JSON feed, no key needed
  4. Malware URLs    — URLhaus abuse.ch API. Requires a free Auth-Key
                       (https://auth.abuse.ch/) set as URLHAUS_AUTH_KEY in .env —
                       abuse.ch started rejecting unauthenticated requests with
                       HTTP 401 in 2025.

Each source is cached independently so a single slow / failing source
never blocks the whole response.  Stale data is returned with a flag so
the UI can show "last updated X min ago" instead of an error.
"""

import os
import time
import logging
import threading
import concurrent.futures

import feedparser
import requests
from flask import jsonify

from extensions import app, limiter, get_user_id

logger = logging.getLogger(__name__)

# ── Per-source TTL cache ───────────────────────────────────────────────────────
# Each entry: { "data": <payload|None>, "expires_at": float, "fetched_at": float|None }

_LOCK   = threading.Lock()
_CACHES: dict[str, dict] = {
    "news":    {"data": None, "expires_at": 0.0, "fetched_at": None},
    "cves":    {"data": None, "expires_at": 0.0, "fetched_at": None},
    "kev":     {"data": None, "expires_at": 0.0, "fetched_at": None},
    "malware": {"data": None, "expires_at": 0.0, "fetched_at": None},
}

_TTL = {
    "news":    5  * 60,   # 5 min  — headlines refresh quickly
    "cves":    15 * 60,   # 15 min — NVD rate limit is strict
    "kev":     60 * 60,   # 1 hr   — CISA feed changes infrequently
    "malware": 5  * 60,   # 5 min  — URLhaus is fast and permissive
}

NEWS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
}

REQUEST_TIMEOUT = 8  # seconds per external call


# ── Helpers ────────────────────────────────────────────────────────────────────

def _cached(key: str):
    """Return (data, fetched_at) from cache if fresh, else (None, None)."""
    with _LOCK:
        c = _CACHES[key]
        if c["data"] is not None and time.monotonic() < c["expires_at"]:
            return c["data"], c["fetched_at"]
    return None, None


def _store(key: str, data):
    now = time.monotonic()
    with _LOCK:
        _CACHES[key]["data"]       = data
        _CACHES[key]["expires_at"] = now + _TTL[key]
        _CACHES[key]["fetched_at"] = time.time()   # wall-clock for the UI


def _stale(key: str):
    """Return stale (data, fetched_at) regardless of TTL — fallback on fetch error."""
    with _LOCK:
        c = _CACHES[key]
        return c["data"], c["fetched_at"]


# ── Source fetchers ────────────────────────────────────────────────────────────

def _fetch_news():
    import re

    def strip_html(t):
        return re.sub(r"<[^>]+>", "", t or "").strip()

    def truncate(t, n=180):
        if len(t) <= n:
            return t
        cut = t[:n].rfind(" ")
        return (t[:cut] if cut > 0 else t[:n]) + "…"

    items = []
    for source, url in NEWS_FEEDS.items():
        try:
            feed = feedparser.parse(url)
            for e in feed.entries[:4]:
                items.append({
                    "title":     e.get("title", "Untitled"),
                    "link":      e.get("link", "#"),
                    "published": e.get("published", ""),
                    "summary":   truncate(strip_html(e.get("summary", ""))),
                    "source":    source,
                })
        except Exception:
            logger.exception("ThreatPulse: news feed error for %s", source)

    # interleave sources, cap at 6
    from_thn = [i for i in items if i["source"] == "The Hacker News"][:3]
    from_bc  = [i for i in items if i["source"] == "BleepingComputer"][:3]
    merged   = []
    for pair in zip(from_thn, from_bc):
        merged.extend(pair)
    merged += from_thn[len(from_bc):] + from_bc[len(from_thn):]
    return merged[:6]


def _fetch_cves():
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        "?resultsPerPage=6&startIndex=0"
    )
    resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                        headers={"User-Agent": "CyberGuru-AI/1.0"})
    resp.raise_for_status()
    raw = resp.json().get("vulnerabilities", [])
    out = []
    for v in raw:
        cve  = v.get("cve", {})
        cid  = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        # CVSS v3.1 preferred, fall back to v3.0 then v2
        metrics = cve.get("metrics", {})
        score, severity = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            bucket = metrics.get(key, [])
            if bucket:
                cvss_data = bucket[0].get("cvssData", {})
                score     = cvss_data.get("baseScore")
                severity  = cvss_data.get("baseSeverity") or bucket[0].get("baseSeverity")
                break
        published = cve.get("published", "")[:10]   # YYYY-MM-DD
        refs = cve.get("references", [])
        link = refs[0].get("url", "") if refs else ""
        out.append({
            "id":        cid,
            "desc":      desc[:200] + ("…" if len(desc) > 200 else ""),
            "score":     score,
            "severity":  (severity or "").upper(),
            "published": published,
            "link":      link,
        })
    return out


def _fetch_kev():
    url  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                        headers={"User-Agent": "CyberGuru-AI/1.0"})
    resp.raise_for_status()
    data  = resp.json()
    vulns = data.get("vulnerabilities", [])
    # Sort newest-first by dateAdded, take 6
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    out = []
    for v in vulns[:6]:
        out.append({
            "cve_id":      v.get("cveID", ""),
            "vendor":      v.get("vendorProject", ""),
            "product":     v.get("product", ""),
            "name":        v.get("vulnerabilityName", ""),
            "date_added":  v.get("dateAdded", ""),
            "due_date":    v.get("dueDate", ""),
            "action":      v.get("requiredAction", ""),
        })
    return out


def _fetch_malware():
    # abuse.ch now requires an Auth-Key on every URLhaus API call (free, see
    # https://urlhaus-api.abuse.ch/#auth_key). Without it every request gets
    # HTTP 401 and this panel silently shows "Source unavailable" forever.
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key:
        raise RuntimeError(
            "URLHAUS_AUTH_KEY environment variable is not set. "
            "Get a free key at https://auth.abuse.ch/"
        )
    resp = requests.post(
        "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        data={"limit": "8"},
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": "CyberGuru-AI/1.0", "Auth-Key": auth_key},
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("query_status") != "ok":
        raise RuntimeError(f"URLhaus status: {data.get('query_status')}")
    out = []
    for u in (data.get("urls") or [])[:8]:
        out.append({
            "url":       u.get("url", ""),
            "host":      u.get("host", ""),
            "threat":    u.get("threat", ""),
            "status":    u.get("url_status", ""),
            "tags":      u.get("tags") or [],
            "date_added": (u.get("date_added") or "")[:10],
        })
    return out


# ── Generic "get-or-fetch-or-stale" wrapper ───────────────────────────────────

def _get_source(key: str, fetcher):
    data, fetched_at = _cached(key)
    if data is not None:
        return {"ok": True, "data": data, "fetched_at": fetched_at, "stale": False}
    try:
        fresh = fetcher()
        _store(key, fresh)
        _, fetched_at = _cached(key)
        return {"ok": True, "data": fresh, "fetched_at": fetched_at, "stale": False}
    except Exception:
        logger.exception("ThreatPulse: fetch error for source '%s'", key)
        stale, fetched_at = _stale(key)
        if stale:
            return {"ok": True, "data": stale, "fetched_at": fetched_at, "stale": True}
        return {"ok": False, "data": None, "fetched_at": None, "stale": False}


# ── Route ─────────────────────────────────────────────────────────────────────

@app.route("/api/threat-pulse", methods=["GET"])
@limiter.limit("30 per minute", key_func=get_user_id)
def threat_pulse():
    """
    Return aggregated threat-intelligence data from four sources.
    All fetches run in parallel; each source degrades independently.
    No authentication required — data is public.
    """
    sources = {
        "news":    _fetch_news,
        "cves":    _fetch_cves,
        "kev":     _fetch_kev,
        "malware": _fetch_malware,
    }

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(_get_source, k, fn): k for k, fn in sources.items()}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception:
                logger.exception("ThreatPulse: unexpected error for '%s'", key)
                results[key] = {"ok": False, "data": None, "fetched_at": None, "stale": False}

    return jsonify({"status": "ok", "sources": results})