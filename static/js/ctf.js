/* ─────────────────────────────────────────────────────────────
   CTF Challenge Mode — frontend
   Talks to /api/ctf/challenge and /api/ctf/submit (routes/ctf.py).
   Self-contained modal: doesn't touch the chat pipeline.
   ───────────────────────────────────────────────────────────── */

let _ctfCurrentChallenge = null; // last challenge shown (safe fields only)
let _ctfSelectedCategory = '';   // currently selected category value on picker

const CTF_CATEGORY_OPTIONS = [
  { value: '',                  label: "This Week's Pick", icon: '🎲' },
  { value: 'Log Analysis',      label: 'Log Analysis',      icon: '📊' },
  { value: 'Phishing Email',    label: 'Phishing Email',    icon: '🎣' },
  { value: 'Malware Artifact',  label: 'Malware Artifact',  icon: '🦠' },
  { value: 'Network Traffic',   label: 'Network Traffic',   icon: '🌐' },
  { value: 'Web Vulnerability', label: 'Web Vulnerability', icon: '🛡️' },
  { value: 'Misconfiguration',  label: 'Misconfiguration',  icon: '⚙️' },
  { value: 'Forensics',         label: 'Forensics',         icon: '🔍' },
];

function openCtfModal() {
  document.getElementById('ctf-modal').classList.add('show');
  _ctfSelectedCategory = '';
  _ctfRenderCategoryPicker();
  if (typeof loadChatSuggestions === 'function') {
    loadChatSuggestions('ctf');
  }
}

function closeCtfModal() {
  document.getElementById('ctf-modal').classList.remove('show');
  if (typeof loadChatSuggestions === 'function') {
    loadChatSuggestions('chat');
  }
}

function _ctfBody() {
  return document.getElementById('ctf-modal-body');
}

function _ctfStepDots(activeIdx) {
  const steps = [0, 1, 2]; // pick -> challenge -> result
  return `
    <div class="ctf-step-dots">
      ${steps.map(i => `<span class="${i === activeIdx ? 'active' : ''}"></span>`).join('')}
    </div>
  `;
}

function _ctfHeader(title, activeStepIdx) {
  return `
    <div class="ctf-header-row">
      <div class="ctf-header-title">
        <span class="ctf-flag-badge">🚩</span>
        ${escapeHtml(title)}
      </div>
      ${_ctfStepDots(activeStepIdx)}
    </div>
  `;
}

function _ctfRenderCategoryPicker() {
  const cards = CTF_CATEGORY_OPTIONS.map((opt, i) => {
    const isChecked = (i === 0 && _ctfSelectedCategory === '') || _ctfSelectedCategory === opt.value;
    return `
      <label class="ctf-cat-card ${isChecked ? 'selected' : ''}" data-value="${escapeHtml(opt.value)}" onclick="_ctfSelectCategory(this, '${escapeHtml(opt.value)}')">
        <input type="radio" name="ctf-category" value="${escapeHtml(opt.value)}" ${isChecked ? 'checked' : ''}>
        <span class="ctf-cat-icon">${opt.icon}</span>
        <span>${escapeHtml(opt.label)}</span>
        <span class="ctf-cat-check"></span>
      </label>
    `;
  }).join('');

  _ctfBody().innerHTML = `
    ${_ctfHeader('CTF Challenge Mode', 0)}
    <div class="ctf-subtitle">Pick a focus area. Gemini will generate a realistic scenario for you to investigate and answer like a real SOC analyst.</div>
    <div class="ctf-category-options">
      ${cards}
    </div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeCtfModal()">Cancel</button>
      <button class="start-btn" onclick="_ctfStartFromPicker()">Start Challenge →</button>
    </div>
  `;
}

function _ctfSelectCategory(el, value) {
  _ctfSelectedCategory = value;
  document.querySelectorAll('.ctf-cat-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  const input = el.querySelector('input');
  if (input) input.checked = true;
}

function _ctfStartFromPicker() {
  const checked = document.querySelector('input[name="ctf-category"]:checked');
  const category = checked ? checked.value : '';
  _ctfLoadChallenge(true, category);
}

function _ctfRenderLoading(msg, sub) {
  _ctfBody().innerHTML = `
    ${_ctfHeader('CTF Challenge Mode', 1)}
    <div class="ctf-loading-wrap">
      <div class="ctf-ring-spinner"></div>
      <div class="ctf-spinner-row">
        <div>${escapeHtml(msg || 'Generating your challenge...')}</div>
        ${sub ? `<div class="ctf-loading-sub">${escapeHtml(sub)}</div>` : ''}
      </div>
    </div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeCtfModal()">Cancel</button>
    </div>
  `;
}

function _ctfRenderError(message, allowRetry) {
  _ctfBody().innerHTML = `
    ${_ctfHeader('CTF Challenge Mode', 0)}
    <div class="ctf-error">⚠️ ${escapeHtml(message || 'Something went wrong.')}</div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeCtfModal()">Close</button>
      ${allowRetry ? '<button class="start-btn" onclick="_ctfRenderCategoryPicker()">Choose Category</button>' : ''}
    </div>
  `;
}

async function _ctfLoadChallenge(forceNew, category) {
  _ctfRenderLoading('Generating your challenge...', 'Gemini is building a realistic scenario');
  try {
    const params = new URLSearchParams();
    if (forceNew) params.set('new', '1');
    if (category) params.set('category', category);
    const qs = params.toString();
    const url = '/api/ctf/challenge' + (qs ? `?${qs}` : '');

    const res = await fetch(url, { credentials: 'include' });
    const data = await res.json().catch(() => ({}));

    if (res.status === 401) return; // global fetch interceptor already shows login overlay

    if (!res.ok || data.status !== 'ok') {
      _ctfRenderError(data.message, true);
      return;
    }

    _ctfCurrentChallenge = data.challenge;
    _ctfRenderChallenge(data.challenge);
  } catch (e) {
    console.error('CTF challenge load error:', e);
    _ctfRenderError('Could not reach the server. Check your connection and try again.', true);
  }
}

function _ctfDiffClass(diff) {
  const d = (diff || '').toLowerCase();
  if (d === 'easy') return 'diff-easy';
  if (d === 'hard') return 'diff-hard';
  return 'diff-medium';
}

function _ctfDiffIcon(diff) {
  const d = (diff || '').toLowerCase();
  if (d === 'easy') return '●';
  if (d === 'hard') return '●●●';
  return '●●';
}

function _ctfRenderChallenge(c) {
  const hints = (c.hints || []).map(h => `<li>${escapeHtml(h)}</li>`).join('');

  _ctfBody().innerHTML = `
    ${_ctfHeader(c.title || 'CTF Challenge', 1)}
    <div class="ctf-meta-row">
      <span class="ctf-badge cat">📁 ${escapeHtml(c.category || '')}</span>
      <span class="ctf-badge ${_ctfDiffClass(c.difficulty)}">${_ctfDiffIcon(c.difficulty)} ${escapeHtml(c.difficulty || '')}</span>
    </div>
    <div class="ctf-scenario">${escapeHtml(c.scenario || '')}</div>
    ${c.artifact ? `
    <div class="ctf-artifact-wrap">
      <div class="ctf-artifact-titlebar">
        <span class="dot"></span><span class="dot"></span><span class="dot"></span>
        <span class="ctf-artifact-label">Evidence</span>
        <button class="ctf-artifact-copy" onclick="_ctfCopyArtifact(this)">Copy</button>
      </div>
      <pre class="ctf-artifact" id="ctf-artifact-text">${escapeHtml(c.artifact)}</pre>
    </div>` : ''}
    <div class="ctf-question">${escapeHtml(c.question || '')}</div>
    ${hints ? `<details class="ctf-hints"><summary>Need a hint?</summary><ul>${hints}</ul></details>` : ''}
    <textarea id="ctf-answer-input" class="ctf-answer-box" placeholder="Write your analysis and answer here..."></textarea>
    <div class="ctf-answer-hint">Explain your reasoning — partial credit is given for sound analysis even if your conclusion is off.</div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeCtfModal()">Cancel</button>
      <button class="quiz-cancel" onclick="_ctfRenderCategoryPicker()">↻ New Challenge</button>
      <button class="start-btn" onclick="_ctfSubmitAnswer()">Submit Answer</button>
    </div>
  `;

  setTimeout(() => {
    const ta = document.getElementById('ctf-answer-input');
    if (ta) ta.focus();
  }, 0);
}

function _ctfCopyArtifact(btn) {
  const el = document.getElementById('ctf-artifact-text');
  if (!el) return;
  navigator.clipboard?.writeText(el.textContent || '').then(() => {
    const original = btn.textContent;
    btn.textContent = 'Copied ✓';
    setTimeout(() => { btn.textContent = original; }, 1500);
  }).catch(() => {});
}

async function _ctfSubmitAnswer() {
  const ta = document.getElementById('ctf-answer-input');
  const answer = ta ? ta.value.trim() : '';

  if (!answer) {
    ta && ta.focus();
    return;
  }

  _ctfRenderLoading('Grading your answer...', 'Comparing against the analyst-level rubric');

  try {
    const res = await fetch('/api/ctf/submit', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ answer }),
    });
    const data = await res.json().catch(() => ({}));

    if (res.status === 401) return;

    if (!res.ok || data.status !== 'ok') {
      if (data.expired) {
        _ctfRenderError(data.message, true);
      } else {
        _ctfRenderError(data.message, false);
      }
      return;
    }

    _ctfRenderResult(data.result, data.challenge_title, data.challenge_category);
  } catch (e) {
    console.error('CTF submit error:', e);
    _ctfRenderError('Could not reach the server. Check your connection and try again.', false);
  }
}

function _ctfRenderResult(r, title, category) {
  const pass = !!r.correct || (r.score >= 70);
  const score = Number(r.score) || 0;
  const strengths = (r.strengths || []).map(s => `<li>${escapeHtml(s)}</li>`).join('');
  const missed = (r.missed || []).map(s => `<li>${escapeHtml(s)}</li>`).join('');

  _ctfBody().innerHTML = `
    ${_ctfHeader(title || 'Challenge Result', 2)}
    <div class="ctf-meta-row"><span class="ctf-badge cat">📁 ${escapeHtml(category || '')}</span></div>

    <div class="ctf-result-header">
      <div class="ctf-grade-circle ${pass ? 'pass' : 'fail'}">${escapeHtml(r.grade || '?')}</div>
      <div class="ctf-result-score-row" style="flex:1;">
        <div class="ctf-result-score">Score: ${escapeHtml(String(r.score ?? '—'))}/100</div>
        <div class="ctf-result-pill ${pass ? 'pass' : 'fail'}">${pass ? '✅ Passed' : '🔁 Needs work'}</div>
        <div class="ctf-score-bar-track">
          <div class="ctf-score-bar-fill ${pass ? '' : 'fail'}" id="ctf-score-bar" style="width:0%"></div>
        </div>
      </div>
    </div>

    <div class="ctf-result-summary">${escapeHtml(r.summary || '')}</div>

    ${strengths ? `<div class="ctf-section-label">✓ What you got right</div><ul class="ctf-list good">${strengths}</ul>` : ''}
    ${missed ? `<div class="ctf-section-label">○ What you missed</div><ul class="ctf-list bad">${missed}</ul>` : ''}

    <div class="ctf-section-label">📖 Full Explanation</div>
    <div class="ctf-reveal">${escapeHtml(r.correct_answer_reveal || '')}</div>

    ${r.pro_tip ? `<div class="ctf-section-label">💡 Pro Tip</div><div class="ctf-reveal">${escapeHtml(r.pro_tip)}</div>` : ''}
    ${r.mitre_callout ? `<div class="ctf-section-label">🧭 MITRE ATT&CK</div><div class="ctf-reveal mitre">${escapeHtml(r.mitre_callout)}</div>` : ''}

    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeCtfModal()">Close</button>
      <button class="start-btn" onclick="_ctfRenderCategoryPicker()">New Challenge</button>
    </div>
  `;

  // animate score bar fill in next frame
  requestAnimationFrame(() => {
    const bar = document.getElementById('ctf-score-bar');
    if (bar) bar.style.width = Math.max(0, Math.min(100, score)) + '%';
  });
}