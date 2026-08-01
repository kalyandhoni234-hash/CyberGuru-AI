"""
SEO routes: /sitemap.xml and /robots.txt

sitemap.xml is generated dynamically so new public pages are automatically
included. robots.txt is served from static/ but also reachable here as a
fallback in case Render's static-file serving is misconfigured.
"""

from datetime import datetime, timezone
from flask import Response, send_from_directory

from extensions import app


# ── Public pages included in the sitemap ──────────────────────
# Add any new indexable route here; the sitemap rebuilds on each request.
_PUBLIC_PAGES = [
    {"loc": "/",            "priority": "1.0", "changefreq": "daily"},
    {"loc": "/investigate", "priority": "0.8", "changefreq": "weekly"},
]

_BASE_URL = "https://cyberguru-ai.onrender.com"


@app.route("/sitemap.xml", methods=["GET"])
def sitemap():
    """Return a dynamically generated sitemap.xml."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    urls = []
    for page in _PUBLIC_PAGES:
        urls.append(
            f"""  <url>
    <loc>{_BASE_URL}{page['loc']}</loc>
    <lastmod>{today}</lastmod>
    <changefreq>{page['changefreq']}</changefreq>
    <priority>{page['priority']}</priority>
  </url>"""
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + "\n</urlset>"
    )

    return Response(xml, mimetype="application/xml")


@app.route("/robots.txt", methods=["GET"])
def robots():
    """Serve robots.txt from the static folder."""
    return send_from_directory(app.static_folder, "robots.txt", mimetype="text/plain")
