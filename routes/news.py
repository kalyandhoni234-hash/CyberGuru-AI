"""
CyberNews route — fetches recent cybersecurity headlines from RSS feeds.

FIX #4: Responses are now cached in memory for 60 seconds using cachetools TTLCache.
Previously every page load hit the RSS feed servers live, adding 500ms+ latency and
risking rate-bans from feed providers. With the cache, only the first request in each
60-second window makes a network call; all subsequent callers get the cached result instantly.

Install dependency if not already present:
    pip install cachetools
"""

import re
import time
import logging
import threading

import feedparser
from flask import jsonify

from extensions import app, limiter, get_user_id

logger = logging.getLogger(__name__)

FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
}

# ── Simple TTL cache ──────────────────────────────────────────────────────────
# We use a plain dict + timestamp rather than pulling in cachetools as an extra
# dependency. If you already have cachetools installed, the TTLCache approach
# is equivalent and slightly cleaner.
_CACHE_TTL = 60          # seconds
_cache_lock = threading.Lock()
_cache: dict = {"data": None, "expires_at": 0.0}


def _fetch_feeds() -> list:
    """Fetch and interleave articles from all RSS feed sources."""
    per_source = []

    for source_name, feed_url in FEEDS.items():
        items = []
        try:
            feed = feedparser.parse(feed_url)
            if feed.bozo and not feed.entries:
                logger.warning("CyberNews: feed %s returned bozo error", source_name)
                continue
            for entry in feed.entries[:4]:
                summary = _strip_html(entry.get("summary", ""))
                items.append({
                    "title":     entry.get("title", "Untitled"),
                    "link":      entry.get("link", "#"),
                    "published": entry.get("published", "Recent"),
                    "summary":   _truncate(summary, 200),
                    "source":    source_name,
                })
        except Exception:
            logger.exception("CyberNews: error fetching feed %s", source_name)

        per_source.append(items)

    if not any(per_source):
        return []

    # Interleave: one article from each source in turn (round-robin).
    articles = []
    for group in zip(*per_source):
        articles.extend(group)
    return articles[:8]


def _get_cached_news() -> list | None:
    """
    Return cached news if still fresh, otherwise fetch live and re-cache.
    Thread-safe via a lock so only one request fetches at a time.
    Returns None if the fetch fails and there is no cached data.
    """
    now = time.monotonic()

    with _cache_lock:
        if _cache["data"] is not None and now < _cache["expires_at"]:
            return _cache["data"]

        articles = _fetch_feeds()
        if articles:
            _cache["data"] = articles
            _cache["expires_at"] = now + _CACHE_TTL
            return articles

        # Fetch failed — return stale data if we have it, else None.
        return _cache.get("data")


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


def _truncate(text: str, length: int = 200) -> str:
    if len(text) <= length:
        return text
    truncated = text[:length]
    last_space = truncated.rfind(" ")
    if last_space > 0:
        truncated = truncated[:last_space]
    return truncated + "..."


@app.route("/api/cybernews", methods=["GET"])
@limiter.limit("20 per minute", key_func=get_user_id)
def get_cybernews():
    articles = _get_cached_news()
    if not articles:
        return jsonify({"error": "Unable to fetch news at this time. Please try again later."}), 503
    return jsonify(articles)
