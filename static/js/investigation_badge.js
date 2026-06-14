/**
 * Severity/verdict badge rendering for CyberGuru investigations.
 *
 * Usage in your SSE handler for /chat-stream:
 *
 *   const evt = JSON.parse(jsonStr);
 *   if (evt.investigation) {
 *     renderInvestigationBadge(evt.investigation, chatContainer);
 *   }
 *   if (evt.token) {
 *     appendReplyText(evt.token);
 *   }
 *
 * For the non-streaming /chat response, the same shape is available at
 * response.investigation.
 */

// Severity -> color (severity takes priority for color, since it answers
// "how bad is this" more directly than verdict alone)
const SEVERITY_COLORS = {
  low:      { bg: "#1f7a3f", fg: "#ffffff", label: "LOW" },       // green
  medium:   { bg: "#b8860b", fg: "#ffffff", label: "MEDIUM" },    // yellow/amber
  high:     { bg: "#cc6600", fg: "#ffffff", label: "HIGH" },      // orange
  critical: { bg: "#b3261e", fg: "#ffffff", label: "CRITICAL" },  // red
  unknown:  { bg: "#6b7280", fg: "#ffffff", label: "UNKNOWN" },   // gray
};

// Verdict -> color, used for benign (which has no "severity" connotation
// but should still read as clearly safe/green)
const VERDICT_COLORS = {
  benign:           { bg: "#1f7a3f", fg: "#ffffff", label: "BENIGN" },
  suspicious:       { bg: "#b8860b", fg: "#ffffff", label: "SUSPICIOUS" },
  likely_malicious: null, // color comes from severity instead
  inconclusive:     { bg: "#6b7280", fg: "#ffffff", label: "INCONCLUSIVE" },
  unknown:          { bg: "#6b7280", fg: "#ffffff", label: "UNKNOWN" },
};

const MITRE_BADGE = { bg: "#2d3748", fg: "#e2e8f0" };

/**
 * Pick a color/label for the combined verdict+severity.
 * - benign / suspicious / inconclusive / unknown -> color from verdict
 * - likely_malicious -> color from severity (low/medium/high/critical)
 */
function getBadgeStyle(verdict, severity) {
  const verdictStyle = VERDICT_COLORS[verdict];

  if (verdictStyle) {
    return verdictStyle;
  }

  // likely_malicious (or unrecognized verdict) -> use severity color
  const sevStyle = SEVERITY_COLORS[severity] || SEVERITY_COLORS.unknown;
  const verdictLabel = (verdict || "unknown").replace(/_/g, " ").toUpperCase();

  return {
    bg: sevStyle.bg,
    fg: sevStyle.fg,
    label: `${verdictLabel} · ${sevStyle.label}`,
  };
}

/**
 * Render the investigation badge into the given container element.
 * Returns the created element so callers can further style/position it.
 *
 * @param {{verdict: string, severity: string, mitre: object|null, from_cache: boolean}} investigation
 * @param {HTMLElement} container
 */
function renderInvestigationBadge(investigation, container) {
  const { verdict, severity, mitre, from_cache } = investigation;

  const wrapper = document.createElement("div");
  wrapper.className = "cyberguru-investigation-badge";
  wrapper.style.display = "flex";
  wrapper.style.alignItems = "center";
  wrapper.style.gap = "8px";
  wrapper.style.flexWrap = "wrap";
  wrapper.style.margin = "8px 0";
  wrapper.style.fontFamily = "system-ui, sans-serif";
  wrapper.style.fontSize = "13px";

  // Main verdict/severity pill
  const style = getBadgeStyle(verdict, severity);
  const pill = document.createElement("span");
  pill.textContent = `🛡️ ${style.label}`;
  pill.style.background = style.bg;
  pill.style.color = style.fg;
  pill.style.padding = "4px 10px";
  pill.style.borderRadius = "999px";
  pill.style.fontWeight = "600";
  pill.style.letterSpacing = "0.03em";
  wrapper.appendChild(pill);

  // MITRE pill, if present
  if (mitre && mitre.id) {
    const mitrePill = document.createElement("span");
    mitrePill.textContent = `${mitre.id} - ${mitre.name || "Unknown"}`;
    mitrePill.style.background = MITRE_BADGE.bg;
    mitrePill.style.color = MITRE_BADGE.fg;
    mitrePill.style.padding = "4px 10px";
    mitrePill.style.borderRadius = "999px";
    mitrePill.style.fontWeight = "500";
    wrapper.appendChild(mitrePill);
  }

  // "From cache" pill, if applicable
  if (from_cache) {
    const cachePill = document.createElement("span");
    cachePill.textContent = "cached";
    cachePill.style.background = "transparent";
    cachePill.style.color = "#6b7280";
    cachePill.style.border = "1px solid #6b7280";
    cachePill.style.padding = "3px 9px";
    cachePill.style.borderRadius = "999px";
    cachePill.style.fontWeight = "500";
    wrapper.appendChild(cachePill);
  }

  container.appendChild(wrapper);
  return wrapper;
}

// Export for module-based bundlers; falls back to global for plain <script> use
if (typeof module !== "undefined" && module.exports) {
  module.exports = { renderInvestigationBadge, getBadgeStyle };
} else {
  window.renderInvestigationBadge = renderInvestigationBadge;
  window.getBadgeStyle = getBadgeStyle;
}
