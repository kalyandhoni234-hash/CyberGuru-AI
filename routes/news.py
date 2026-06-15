"""
CyberNews route — fetches recent cybersecurity headlines from RSS feeds.
No AI calls, no quota usage, 100% free.
"""
import re
import feedparser
from flask import jsonify

from extensions import app, limiter, get_user_id

FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
}


def _strip_html(text):
    return re.sub(r"<[^>]+>", "", text or "").strip()


def _truncate(text, length=200):
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
    per_source = []

    for source_name, feed_url in FEEDS.items():
        items = []
        try:
            feed = feedparser.parse(feed_url)
            if feed.bozo and not feed.entries:
                continue

            for entry in feed.entries[:4]:
                summary = _strip_html(entry.get("summary", ""))
                items.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", "#"),
                    "published": entry.get("published", "Recent"),
                    "summary": _truncate(summary, 200),
                    "source": source_name,
                })
        except Exception as e:
            print(f"CYBERNEWS FEED ERROR [{source_name}]: {e}")

        per_source.append(items)

    if not any(per_source):
        return jsonify({"error": "Unable to fetch news at this time. Please try again later."}), 503

    articles = []
    for group in zip(*per_source):
        articles.extend(group)

    return jsonify(articles[:8])