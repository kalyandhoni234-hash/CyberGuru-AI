/* ─────────────────────────────────────────────────────────────
   Threat Pulse  —  threat_pulse.js
   Opens a full-width dashboard modal with four live data panels:
     · Latest cybersecurity news headlines
     · Recent CVEs from NVD NIST
     · CISA Known Exploited Vulnerabilities
     · Live malicious URLs from URLhaus
   Fetches  GET /api/threat-pulse  (routes/threat_pulse.py).
   ───────────────────────────────────────────────────────────── */

'use strict';

// ── Open / close ──────────────────────────────────────────────

function openThreatPulse() {
  document.getElementById('tp-modal').classList.add('show');
  _tpLoad();
}

function closeThreatPulse() {
  document.getElementById('tp-modal').classList.remove('show');
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('tp-modal')
    ?.addEventListener('click', e => {
      if (e.target.id === 'tp-modal') closeThreatPulse();
    });
});

// ── Fetch ─────────────────────────────────────────────────────

async function _tpLoad() {
  _tpSetContent(_tpTmplLoading());
  try {
    const res  = await fetch('/api/threat-pulse');
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.status !== 'ok') {
      _tpSetContent(_tpTmplError('Could not load threat data. Try again shortly.'));
      return;
    }
    _tpRender(data.sources);
  } catch {
    _tpSetContent(_tpTmplError('Network error — check your connection.'));
  }
}

function _tpSetContent(html) {
  document.getElementById('tp-content').innerHTML = html;
}

// ── Main render ───────────────────────────────────────────────

function _tpRender(src) {
  _tpSetContent(`
    <div class="tp-grid">
      ${_tpPanelNews(src.news)}
      ${_tpPanelCVE(src.cves)}
      ${_tpPanelKEV(src.kev)}
      ${_tpPanelMalware(src.malware)}
    </div>
  `);
}

// ── Shared helpers ────────────────────────────────────────────

function _tpTimestamp(fetchedAt) {
  if (!fetchedAt) return '';
  const d   = new Date(fetchedAt * 1000);
  const now = new Date();
  const diffMin = Math.round((now - d) / 60000);
  const label   = diffMin < 1 ? 'just now'
                : diffMin < 60 ? `${diffMin}m ago`
                : `${Math.round(diffMin / 60)}h ago`;
  return `<span class="tp-stamp">Updated ${label}</span>`;
}

function _tpStaleTag(stale) {
  return stale ? '<span class="tp-stale-tag">cached</span>' : '';
}

function _tpPanelShell(icon, title, srcObj, bodyHtml) {
  const ok    = srcObj?.ok !== false;
  const stamp = _tpTimestamp(srcObj?.fetched_at);
  const stale = _tpStaleTag(srcObj?.stale);
  return `
    <div class="tp-panel">
      <div class="tp-panel-hdr">
        <span class="tp-panel-icon">${icon}</span>
        <span class="tp-panel-title">${title}</span>
        <span class="tp-panel-meta">${stale}${stamp}</span>
      </div>
      <div class="tp-panel-body">
        ${ok && srcObj?.data?.length ? bodyHtml : _tpTmplPanelEmpty(ok)}
      </div>
    </div>`;
}

function _tpTmplPanelEmpty(ok) {
  return ok
    ? '<div class="tp-empty">No data available right now.</div>'
    : '<div class="tp-empty tp-empty--err">⚠️ Source unavailable — try refreshing.</div>';
}

// ── Panel: News ───────────────────────────────────────────────

function _tpPanelNews(src) {
  const items = (src?.data || []).map(a => `
    <a class="tp-news-item" href="${escapeHtml(a.link)}" target="_blank" rel="noopener noreferrer">
      <div class="tp-news-source">${escapeHtml(a.source)}</div>
      <div class="tp-news-title">${escapeHtml(a.title)}</div>
      <div class="tp-news-summary">${escapeHtml(a.summary)}</div>
    </a>`).join('');
  return _tpPanelShell('📰', 'Latest Headlines', src, items);
}

// ── Panel: CVEs ───────────────────────────────────────────────

const _CVE_SEV_CLASS = { CRITICAL:'tp-sev--crit', HIGH:'tp-sev--high', MEDIUM:'tp-sev--med', LOW:'tp-sev--low' };

function _tpPanelCVE(src) {
  const items = (src?.data || []).map(c => {
    const sevClass = _CVE_SEV_CLASS[c.severity] || 'tp-sev--none';
    const score    = c.score != null ? c.score.toFixed(1) : '—';
    const link     = c.link ? `href="${escapeHtml(c.link)}" target="_blank" rel="noopener noreferrer"` : '';
    return `
      <div class="tp-cve-item">
        <div class="tp-cve-top">
          <a class="tp-cve-id" ${link}>${escapeHtml(c.id)}</a>
          <span class="tp-sev ${sevClass}">${escapeHtml(c.severity || 'N/A')} ${score}</span>
          <span class="tp-cve-date">${escapeHtml(c.published)}</span>
        </div>
        <div class="tp-cve-desc">${escapeHtml(c.desc)}</div>
      </div>`;
  }).join('');
  return _tpPanelShell('🛡️', 'Recent CVEs  <span class="tp-source-badge">NVD NIST</span>', src, items);
}

// ── Panel: CISA KEV ───────────────────────────────────────────

function _tpPanelKEV(src) {
  const items = (src?.data || []).map(v => `
    <div class="tp-kev-item">
      <div class="tp-kev-top">
        <span class="tp-kev-id">${escapeHtml(v.cve_id)}</span>
        <span class="tp-kev-vendor">${escapeHtml(v.vendor)} · ${escapeHtml(v.product)}</span>
        <span class="tp-kev-date">Added ${escapeHtml(v.date_added)}</span>
      </div>
      <div class="tp-kev-name">${escapeHtml(v.name)}</div>
      <div class="tp-kev-action">⚡ ${escapeHtml(v.action)}</div>
    </div>`).join('');
  return _tpPanelShell('⚠️', 'Active Exploits  <span class="tp-source-badge">CISA KEV</span>', src, items);
}

// ── Panel: Malware URLs ───────────────────────────────────────

const _URL_STATUS_CLASS = { online:'tp-url-status--online', offline:'tp-url-status--offline' };

function _tpPanelMalware(src) {
  const items = (src?.data || []).map(u => {
    const stCls  = _URL_STATUS_CLASS[(u.status || '').toLowerCase()] || '';
    const tags   = (u.tags || []).map(t => `<span class="tp-tag">${escapeHtml(t)}</span>`).join('');
    const threat = u.threat ? `<span class="tp-threat-label">${escapeHtml(u.threat)}</span>` : '';
    return `
      <div class="tp-url-item">
        <div class="tp-url-top">
          <span class="tp-url-host">${escapeHtml(u.host)}</span>
          ${threat}
          <span class="tp-url-status ${stCls}">${escapeHtml(u.status || '—')}</span>
          <span class="tp-url-date">${escapeHtml(u.date_added)}</span>
        </div>
        <div class="tp-url-raw">${escapeHtml(u.url.length > 80 ? u.url.slice(0, 80) + '…' : u.url)}</div>
        ${tags ? `<div class="tp-url-tags">${tags}</div>` : ''}
      </div>`;
  }).join('');
  return _tpPanelShell('🦠', 'Live Malware URLs  <span class="tp-source-badge">URLhaus</span>', src, items);
}

// ── Loading / error ───────────────────────────────────────────

function _tpTmplLoading() {
  return `
    <div class="tp-loading">
      <div class="tp-spinner"></div>
      Pulling live threat data…
      <span class="tp-loading-sub">Fetching CVEs, KEV, malware feeds & headlines in parallel</span>
    </div>`;
}

function _tpTmplError(msg) {
  return `
    <div class="tp-loading tp-loading--err">
      ⚠️ ${escapeHtml(msg)}
      <button class="start-btn" style="margin-top:16px" data-action="_tpLoad">Retry</button>
    </div>`;
}
