// ── CSP-compliant event delegation ──────────────────────────────
// Loaded in <head> so the theme-init block runs before first paint.
// All data-action / data-keydown / data-input / data-change wiring
// is deferred to DOMContentLoaded.

// ── Theme Init (synchronous, prevents FOUC) ────────────────────
(function () {
  var t = localStorage.getItem('cyberguru_theme') || 'hacker';
  if (t === 'cyber') t = 'hacker';
  if (t === 'hacker') document.documentElement.classList.add('theme-hacker');
  else if (t === 'light') document.documentElement.classList.add('theme-light');
  else if (t === 'oled') document.documentElement.classList.add('theme-oled');
})();

// ── Delegation (deferred) ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {

  /* ── CLICK delegation ──────────────────────────────────────── */
  document.addEventListener('click', function (e) {
    var el = e.target.closest('[data-action]');
    if (!el) return;
    var action = el.dataset.action;

    switch (action) {

      // ── Login ────────────────────────────────────────────────
      case 'goLogin':
        window.location.href = '/auth/login'; break;

      // ── Investigate ──────────────────────────────────────────
      case 'selectType':
        e.preventDefault();
        selectType(el.dataset.typeId || el.dataset.type, el);
        break;
      case 'clearEditor':        clearEditor(); break;
      case 'runInvestigation':   runInvestigation(); break;
      case 'newAnalysis':        newAnalysis(); break;
      case 'toggleEvidence':     toggleEvidence(); break;
      case 'toggleRawFindings':  toggleRawFindings(); break;
      case 'printReport':        printReport(); break;
      case 'copyToClipboard':    copyToClipboard(el.dataset.encoded); break;
      case 'loadInvestigation':  loadInvestigation(parseInt(el.dataset.invId, 10)); break;
      case 'deleteInvestigation':
        e.stopPropagation();
        deleteInvestigation(parseInt(el.dataset.invId, 10));
        break;
      case 'loadInvestigateSuggestion':
        loadInvestigateSuggestion(el.dataset.text); break;

      // ── Mobile investigate ───────────────────────────────────
      case 'mobSelectType':      mobSelectType(el.dataset.typeId || el.dataset.type, el); break;
      case 'mobClear':           mobClear(); break;
      case 'mobRunInvestigation': mobRunInvestigation(); break;
      case 'mobBackToInput':     mobBackToInput(); break;
      case 'mobNewAnalysis':     mobNewAnalysis(); break;
      case 'mobToggleEvidence':  mobToggleEvidence(); break;
      case 'mobToggleRaw':       mobToggleRaw(); break;
      case 'mobUseSuggestion':   mobUseSuggestion(el.dataset.text); break;

      default:
        // Fallback: try calling window[action] with no args
        if (typeof window[action] === 'function') window[action]();
    }
  });

  /* ── KEYDOWN delegation ────────────────────────────────────── */
  document.addEventListener('keydown', function (e) {
    var el = e.target.closest('[data-keydown]');
    if (!el) return;
    var action = el.dataset.keydown;
    if ((action === 'toggleEvidence' || action === 'toggleRawFindings') && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      if (action === 'toggleEvidence') toggleEvidence();
      else toggleRawFindings();
    }
  });

  /* ── INPUT delegation ──────────────────────────────────────── */
  document.addEventListener('input', function (e) {
    var el = e.target.closest('[data-input]');
    if (!el) return;
    var action = el.dataset.input;
    if (action === 'onEditorInput') onEditorInput();
    else if (action === 'mobOnInput') mobOnInput();
  });

  /* ── CHANGE delegation ─────────────────────────────────────── */
  document.addEventListener('change', function (e) {
    var el = e.target.closest('[data-change]');
    if (!el) return;
    var action = el.dataset.change;
    if (action === 'mobFileLoad') mobFileLoad(e);
  });
});
