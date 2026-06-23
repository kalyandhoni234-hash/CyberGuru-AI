// ── Global declarations (must be first — referenced before their original positions) ──

let currentModel = 'gemini';

const WELCOME_CAPS = [
  '🎯 Quiz Mode',
  '🚩 CTF Challenges',
  '🛡️ Threat Pulse',
  '🎓 Cyber Mentor',
];

const WELCOME_CARD_ICONS = {
  database: '<svg viewBox="0 0 24 24" aria-hidden="true"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></svg>',
  code: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8 4 12l4 4"/><path d="m16 8 4 4-4 4"/><path d="m14 5-4 14"/></svg>',
  pulse: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13h4l2-6 4 10 2-4h4"/><path d="M4 6h16"/></svg>',
  shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5c0 4.6 2.9 8.9 7 10 4.1-1.1 7-5.4 7-10V6l-7-3Z"/><path d="M9 12l2 2 4-4"/></svg>',
};

const WELCOME_CARDS = [
  { icon: 'database', label: 'Attack Vector',       text: 'What is SQL Injection and how does it work?', action: () => fillAndSend('What is SQL Injection and how does it work?') },
  { icon: 'code',     label: 'Client-side Exploit', text: 'Explain XSS Attacks',                         action: () => fillAndSend('Explain Cross-Site Scripting (XSS) attacks') },
  { icon: 'pulse',    label: 'Threat Intel',        text: 'Types of Malware',                             action: () => fillAndSend('What are the different types of malware?') },
  { icon: 'shield',   label: 'Framework',           text: 'OWASP Top 10 Guide',                           action: () => fillAndSend('What is OWASP Top 10 and why does it matter?') },
];

/* ─── Dynamic Prompt Suggestions ──────────────────────────────────
   Fetched from backend API every time; no hardcoded prompts here. */

/* ─── THEME ──────────────────────────────────────────────────── */
function setTheme(theme) {
  document.body.classList.remove('theme-cyber','theme-light','theme-oled');
  document.querySelectorAll('.theme-btn').forEach(b => b.classList.remove('active'));
 
  if(theme === 'light') document.body.classList.add('theme-light');
  else if(theme === 'oled') document.body.classList.add('theme-oled');
  const btn = document.getElementById('btn-' + theme);
  if(btn) btn.classList.add('active');
  localStorage.setItem('cyberguru_theme', theme);
}

function loadTheme() {
  const saved = localStorage.getItem('cyberguru_theme') || 'cyber';
  const valid = ['cyber', 'light', 'oled'];
  setTheme(valid.includes(saved) ? saved : 'cyber');
}

/* ─── GLOBALS ────────────────────────────────────────────────── */
let STORAGE_KEY = 'cybguru_chats_v1';     // re-namespaced after login
let ACTIVE_KEY  = 'cybguru_active_v1';
const API_BASE    = '';  // ← change to deployed URL

let chats        = {};
let activeChatId = null;
let isThinking   = false;
let suggestionTimer = null;

// ── Stop generation ──
let activeReader  = null;   // holds current stream reader so we can cancel it
let abortCtrl     = null;   // AbortController for fetch

// ── Stream retry ──
const MAX_STREAM_RETRIES = 2;   // attempts after first failure

// ── Rate limit banner ──
let _rateBannerTimer = null;

function showRateBanner(retryAfterSecs) {
  const banner    = document.getElementById('rate-limit-banner');
  const countdown = document.getElementById('rate-limit-countdown');
  if(!banner || !countdown) return;

  let remaining = retryAfterSecs || 60;
  countdown.textContent = remaining;
  banner.classList.add('show');

  // disable send while throttled
  document.getElementById('send-btn').disabled = true;

  clearInterval(_rateBannerTimer);
  _rateBannerTimer = setInterval(() => {
    remaining--;
    countdown.textContent = Math.max(0, remaining);
    if(remaining <= 0) {
      dismissRateBanner();
    }
  }, 1000);
}

function dismissRateBanner() {
  clearInterval(_rateBannerTimer);
  const banner = document.getElementById('rate-limit-banner');
  if(banner) banner.classList.remove('show');
  if(typeof updateSendBtn === 'function') updateSendBtn();
}

function stopGeneration() {
  if(abortCtrl) { abortCtrl.abort(); abortCtrl = null; }
  if(activeReader) { try { activeReader.cancel(); } catch(e){} activeReader = null; }
  setThinkingUI(false);
}

function setThinkingUI(on) {
  const sendBtn = document.getElementById('send-btn');
  const stopBtn = document.getElementById('stop-btn');
  const typer   = document.getElementById('typing-indicator');
  if(on) {
    sendBtn.style.display = 'none';
    stopBtn.style.display = 'flex';
    typer.style.display   = 'block';
    setTypingState('thinking');   // always reset to base state on show
  } else {
    sendBtn.style.display = 'flex';
    stopBtn.style.display = 'none';
    typer.style.display   = 'none';
    if(typeof updateSendBtn === 'function') updateSendBtn();
    hideTPS();
  }
  document.getElementById('chat-box').scrollTo({ top: 99999, behavior: 'auto' });
}

// ── Typing state machine ──────────────────────────────────────────
// States: 'thinking' | 'searching' | 'generating' | 'reconnecting'
const TYPING_STATES = {
  thinking: {
    label: 'Thinking',
    // CPU/chip icon
    icon: `<rect x="7" y="7" width="10" height="10" rx="1" stroke-linecap="round"/>
           <path stroke-linecap="round" d="M7 9H5M7 12H4M7 15H5M17 9h2M17 12h3M17 15h2M9 7V5M12 7V4M15 7V5M9 17v2M12 17v3M15 17v2"/>`,
  },
  analyzing: {
    label: 'Analyzing file',
    // Document + magnifying glass
    icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>`,
  },
  searching: {
    label: 'Searching',
    // Magnifying glass
    icon: `<circle cx="11" cy="11" r="7"/><path stroke-linecap="round" d="M21 21l-4.35-4.35"/>`,
  },
  generating: {
    label: 'Generating',
    // Zap / lightning bolt
    icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>`,
  },
  reconnecting: {
    label: 'Reconnecting',
    // Refresh / rotate arrows
    icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h5"/>
           <path stroke-linecap="round" stroke-linejoin="round" d="M20 20v-5h-5"/>
           <path stroke-linecap="round" stroke-linejoin="round" d="M20.49 9A9 9 0 005.64 5.64L4 9M3.51 15a9 9 0 0014.85 3.36L20 15"/>`,
  },
};

function setTypingState(state) {
  const typer    = document.getElementById('typing-indicator');
  const labelEl  = document.getElementById('typing-label');
  const iconEl   = document.getElementById('typing-state-icon');
  if(!typer || !labelEl || !iconEl) return;

  const cfg = TYPING_STATES[state] || TYPING_STATES.thinking;
  typer.setAttribute('data-state', state);
  labelEl.textContent = cfg.label;
  iconEl.innerHTML = cfg.icon;
}
function toggleSidebarCollapse() {
  const sidebar = document.getElementById('sidebar');
  const isCollapsed = sidebar.classList.toggle('collapsed');
  document.body.classList.toggle('sidebar-collapsed', isCollapsed);
  localStorage.setItem('sidebar_collapsed', isCollapsed);
}

// In your init/loadTheme area, add:
function loadSidebarState() {
  if (localStorage.getItem('sidebar_collapsed') === 'true') {
    document.getElementById('sidebar').classList.add('collapsed');
    document.body.classList.add('sidebar-collapsed');
  }
}

// ── Tokens/sec counter ──
let tpsStartTime  = 0;
let tpsTokenCount = 0;

function startTPS() {
  tpsStartTime  = Date.now();
  tpsTokenCount = 0;
  document.getElementById('tps-badge').style.display = 'flex';
}

function tickTPS(tokens) {
  tpsTokenCount += tokens;
  const secs = (Date.now() - tpsStartTime) / 1000 || 0.001;
  document.getElementById('tps-value').textContent = Math.round(tpsTokenCount / secs);
}

function hideTPS() {
  setTimeout(() => { document.getElementById('tps-badge').style.display = 'none'; }, 2000);
}

// ── Copy message ──
function copyMessage(msgId) {
  const el = document.getElementById(msgId);
  if(!el) return;
  const text = el.innerText || el.textContent || '';
  navigator.clipboard.writeText(text).then(() => {
    const btn = el.closest('.msg-body')?.querySelector('.msg-action-btn');
    if(!btn) return;
    const orig = btn.innerHTML;
    btn.innerHTML = '<svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M20 6L9 17l-5-5"/></svg> Copied';
    btn.style.borderColor = 'var(--green)';
    btn.style.color = 'var(--green)';
    setTimeout(() => { btn.innerHTML = orig; btn.style.borderColor = ''; btn.style.color = ''; }, 2000);
  }).catch(() => {});
}

// ── Thumbs up / down ──
function thumbs(msgId, dir) {
  const upBtn = document.getElementById(msgId + '-up');
  const dnBtn = document.getElementById(msgId + '-dn');
  if(!upBtn || !dnBtn) return;
  upBtn.classList.toggle('active-up', dir === 'up');
  dnBtn.classList.toggle('active-dn', dir === 'down');
  upBtn.classList.toggle('active-dn', false);
  dnBtn.classList.toggle('active-up', false);
  // Could POST feedback to backend here in future
}

// ── Smart title — local, no API call ──
// Strips common filler words, takes the first 5 meaningful words,
// title-cases them. Fast, free, zero Gemini requests.
const TITLE_STOPWORDS = new Set([
  'a','an','the','is','are','was','were','be','been','being',
  'i','me','my','we','our','you','your','it','its',
  'what','how','why','when','where','who','which','can','could',
  'do','does','did','will','would','should','please','tell','explain',
  'give','show','help','about','and','or','but','for','with',
  'in','on','at','to','of','from','by','up','if','so',
]);

function generateSmartTitle(message) {
  const words = message
    .replace(/[^\w\s]/g, ' ')   // strip punctuation
    .split(/\s+/)
    .filter(w => w.length > 1 && !TITLE_STOPWORDS.has(w.toLowerCase()));

  const titleWords = words.slice(0, 5);
  if(!titleWords.length) return message.slice(0, 42);

  return titleWords
    .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');
}

// ── Export chat ──
function exportChat() {
  if(!activeChatId || !chats[activeChatId]) return;
  const chat = chats[activeChatId];
  const lines = [`# ${chat.title}\n`, `*Exported from CyberGuru AI — ${new Date().toLocaleString()}*\n`, '---\n'];
  chat.msgs.forEach(m => {
    const who = m.role === 'user' ? '**You**' : '**CyberGuru**';
    lines.push(`${who}\n\n${m.text}\n\n---\n`);
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = (chat.title || 'conversation').replace(/[^a-z0-9]/gi, '_').toLowerCase() + '.md';
  a.click();
  URL.revokeObjectURL(url);
}

/* ─── INIT ───────────────────────────────────────────────────── */
(function init() {
  loadTheme();
  loadSidebarState(); 
  loadAppearanceSettings(); 
  initScrollTracking();
  _initStaticWelcome();

  // File input: show indicator when file chosen
  document.getElementById('fileInput').addEventListener('change', function() {
    const label = document.getElementById('upload-label');
    const indicator = document.getElementById('file-indicator');
    const nameEl = document.getElementById('file-name');
    if(this.files[0]) {
      label.classList.add('has-file');
      nameEl.textContent = this.files[0].name;
      indicator.classList.add('show');
    } else {
      label.classList.remove('has-file');
      indicator.classList.remove('show');
    }
    updateSendBtn();
  });
})();
// ── TTS ──────────────────────────────────────────────────────────────────────

let currentAudio  = null;
let currentTTSBtn = null;
let ttsLoading    = false;  // lock: true while fetch is in-flight

// Strip markdown syntax so gTTS doesn't read asterisks, backticks, etc. aloud
function stripMarkdown(text) {
  return text
    .replace(/```[\s\S]*?```/g, 'code block.')   // fenced code → spoken label
    .replace(/`[^`]+`/g, '')                      // inline code → silence
    .replace(/#{1,6}\s/g, '')                     // headings
    .replace(/\*\*\*(.+?)\*\*\*/g, '$1')          // bold+italic
    .replace(/\*\*(.+?)\*\*/g, '$1')              // bold
    .replace(/\*(.+?)\*/g, '$1')                  // italic
    .replace(/^[-*]\s/gm, '')                     // list bullets
    .replace(/^\d+\.\s/gm, '')                    // numbered list
    .replace(/^>\s/gm, '')                        // blockquotes
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')      // links → link text
    .replace(/\n{2,}/g, '. ')                     // double newlines → pause
    .replace(/\n/g, ' ')
    .trim();
}

function _ttsReset(btn) {
  if (btn) {
    btn.innerHTML = btn._listenHTML || '🔊';
    btn.disabled  = false;
    btn.classList.remove('playing');
  }
}

async function speakText(text, btn) {
  // ── Case 1: fetch already in-flight — block all clicks until it resolves ──
  if (ttsLoading) return;

  // ── Case 2: audio is playing ──
  if (currentAudio) {
    // Stop playback and reset whichever button was playing
    currentAudio.pause();
    currentAudio.onended = null;   // prevent onended firing after manual stop
    URL.revokeObjectURL(currentAudio.src);
    currentAudio = null;
    _ttsReset(currentTTSBtn);
    const wasBtn = currentTTSBtn;
    currentTTSBtn = null;
    // Same button = toggle off, different button = fall through to play new one
    if (wasBtn === btn) return;
  }

  // ── Start new TTS request ──
  btn._listenHTML = btn.innerHTML;
  ttsLoading      = true;
  currentTTSBtn   = btn;

  btn.innerHTML = `<svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite">
    <path stroke-linecap="round" d="M12 2a10 10 0 0 1 10 10"/>
  </svg> Loading…`;
  btn.disabled = true;

  // Disable ALL other listen buttons while loading so only one can queue
  document.querySelectorAll('.tts-btn').forEach(b => { if (b !== btn) b.disabled = true; });

  try {
    const res = await fetch('/api/tts', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ text: stripMarkdown(text) })
    });

    if (!res.ok) throw new Error(`TTS ${res.status}`);

    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const audio = new Audio(url);

    // If user managed to click stop while we were fetching, abort playback
    if (currentTTSBtn !== btn) {
      URL.revokeObjectURL(url);
      return;
    }

    currentAudio = audio;
    ttsLoading   = false;

    btn.innerHTML = `<svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
      <rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>
    </svg> Stop`;
    btn.disabled = false;
    btn.classList.add('playing');

    // Re-enable all other listen buttons now that fetch is done
    document.querySelectorAll('.tts-btn').forEach(b => { if (b !== btn) b.disabled = false; });

    audio.play().catch(e => {
      console.error('Audio play() rejected:', e);
      _ttsReset(btn);
      currentAudio  = null;
      currentTTSBtn = null;
    });

    audio.onended = () => {
      _ttsReset(btn);
      currentAudio  = null;
      currentTTSBtn = null;
      URL.revokeObjectURL(url);
    };

  } catch (err) {
    console.error('TTS error:', err);
    ttsLoading = false;
    _ttsReset(btn);
    currentTTSBtn = null;
    // Re-enable all buttons on failure
    document.querySelectorAll('.tts-btn').forEach(b => { b.disabled = false; });
  }
}

// Attach a speaker button to a bot message's .msg-actions bar (or .msg-body as fallback)
function addTTSButton(msgBodyEl, rawText) {
  const btn = document.createElement('button');
  btn.className   = 'msg-action-btn tts-btn';
  btn.title       = 'Read aloud';
  btn.innerHTML   = `<svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
    <path stroke-linecap="round" stroke-linejoin="round" d="M11 5L6 9H2v6h4l5 4V5z"/>
    <path stroke-linecap="round" stroke-linejoin="round" d="M15.54 8.46a5 5 0 010 7.07"/>
    <path stroke-linecap="round" stroke-linejoin="round" d="M19.07 4.93a10 10 0 010 14.14"/>
  </svg> Listen`;
  btn.onclick = () => speakText(rawText, btn);

  const actionsBar = msgBodyEl.querySelector('.msg-actions');
  if (actionsBar) actionsBar.appendChild(btn);
  else msgBodyEl.appendChild(btn);
}
function clearFile() {
  const fi = document.getElementById('fileInput');
  fi.value = '';
  document.getElementById('upload-label').classList.remove('has-file');
  document.getElementById('file-indicator').classList.remove('show');
  document.getElementById('file-name').textContent = '';
  updateSendBtn();
}

/* ─── STORAGE ────────────────────────────────────────────────── */
const STORAGE_WARN_BYTES = 4 * 1024 * 1024; // warn at 4 MB (limit ~5 MB)

function saveToStorage() {
  try {
    const serialised = JSON.stringify(chats);
    if(serialised.length > STORAGE_WARN_BYTES) {
      // Trim oldest chats until we're under the threshold
      const ids = Object.keys(chats).sort((a, b) => {
        return parseInt(a.replace('chat_',''),10) - parseInt(b.replace('chat_',''),10);
      });
      while(ids.length > 1 && JSON.stringify(chats).length > STORAGE_WARN_BYTES) {
        const oldest = ids.shift();
        if(oldest !== activeChatId) delete chats[oldest];
      }
      console.warn('[CyberGuru] Storage near limit — oldest chats pruned.');
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(chats));
  } catch(e) {
    if(e && (e.name === 'QuotaExceededError' || e.code === 22)) {
      // Surface a non-blocking toast instead of silently dropping data
      showStorageWarning();
    }
  }
}

function showStorageWarning() {
  let toast = document.getElementById('storage-toast');
  if(!toast) {
    toast = document.createElement('div');
    toast.id = 'storage-toast';
    toast.style.cssText = [
      'position:fixed','bottom:80px','left:50%','transform:translateX(-50%)',
      'background:var(--bg-card)','border:1px solid var(--red)',
      'color:var(--red)','font-size:12px','font-family:var(--font-ui)',
      'padding:8px 16px','border-radius:var(--r-md)','z-index:9998',
      'box-shadow:var(--shadow-md)','pointer-events:none'
    ].join(';');
    document.body.appendChild(toast);
  }
  toast.textContent = '⚠️ Storage full — oldest chats may not be saved. Export important conversations.';
  toast.style.display = 'block';
  setTimeout(() => { toast.style.display = 'none'; }, 5000);
}

function loadFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if(raw) chats = JSON.parse(raw);
  } catch(e) { chats = {}; }
}

/* ─── NEW CHAT ───────────────────────────────────────────────── */
function newChat() {
  activeChatId = null;
  localStorage.removeItem(ACTIVE_KEY);
  showWelcome();
  renderHistoryList();
  document.getElementById('topbar-title').textContent = 'New Conversation';
  const exportBtn = document.getElementById('export-btn');
  if(exportBtn) exportBtn.classList.remove('visible');
  document.getElementById('user-input').focus();
  if(window.innerWidth <= 768) closeSidebar();
  // suggestionTimer is declared globally; do not redeclare here.
}
// ── Local suggestion bank — no API call, no rate limit impact ──
const SUGGESTION_BANK = [
  // Attacks & exploits
  "What is SQL Injection and how does it work?",
  "Explain Cross-Site Scripting (XSS) attacks",
  "What is a buffer overflow attack?",
  "How does a man-in-the-middle attack work?",
  "What is Cross-Site Request Forgery (CSRF)?",
  "Explain command injection vulnerabilities",
  "What is an XML External Entity (XXE) attack?",
  "How does Server-Side Request Forgery (SSRF) work?",
  "What is a race condition vulnerability?",
  "Explain path traversal attacks",
  // Malware & threats
  "What are the different types of malware?",
  "How does ransomware work?",
  "What is a rootkit and how does it hide?",
  "Explain how keyloggers capture data",
  "What is a trojan horse in cybersecurity?",
  "How do botnets work?",
  "What is a zero-day vulnerability?",
  "Explain Advanced Persistent Threats (APT)",
  "What is spyware and how to detect it?",
  "How does a worm spread through networks?",
  // Network security
  "What is a firewall and how does it work?",
  "Explain the difference between IDS and IPS",
  "What is a VPN and how does it protect privacy?",
  "How does a DDoS attack work?",
  "What is DNS spoofing?",
  "Explain ARP poisoning attacks",
  "What is port scanning and why is it used?",
  "How does SSL/TLS encryption work?",
  "What is network segmentation?",
  "Explain the OSI model in security context",
  // Web security
  "What is OWASP Top 10 and why does it matter?",
  "How does Content Security Policy (CSP) work?",
  "What is clickjacking and how to prevent it?",
  "Explain HTTP security headers",
  "What is CORS and how can it be misconfigured?",
  "How does OAuth 2.0 work securely?",
  "What is JWT and what are its security risks?",
  "Explain insecure direct object references (IDOR)",
  // Cryptography
  "What is the difference between symmetric and asymmetric encryption?",
  "How does public key infrastructure (PKI) work?",
  "What is hashing and why is it used in security?",
  "Explain salting passwords",
  "What is certificate pinning?",
  "How does end-to-end encryption work?",
  // Defence & tools
  "What is penetration testing?",
  "How does multi-factor authentication work?",
  "What is the principle of least privilege?",
  "Explain threat modelling",
  "What is a security audit?",
  "How does SIEM work?",
  "What is vulnerability scanning?",
  "Explain the kill chain framework",
  "What is MITRE ATT&CK?",
  "How to implement a secure SDLC?",
  // Social engineering
  "What is phishing and how to spot it?",
  "Explain spear phishing vs regular phishing",
  "What is social engineering in cybersecurity?",
  "How does vishing work?",
  "What is pretexting?",
];

async function getContextualSuggestions(query) {
  if(!query || query.length < 2) return [];
  try {
    const res = await fetch(`/api/prompt-suggestions?module=chat&count=5&q=${encodeURIComponent(query)}`, { credentials: 'include' });
    if (res.ok) {
      const data = await res.json();
      if (data.suggestions && data.suggestions.length) return data.suggestions;
    }
  } catch (_) {}
  // Fallback to local bank if API fails
  const q = query.toLowerCase();
  return SUGGESTION_BANK
    .map(s => ({ s, score: s.toLowerCase().startsWith(q) ? 2 : s.toLowerCase().includes(q) ? 1 : 0 }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map(x => x.s);
}

const userInput = document.getElementById('user-input');

userInput.addEventListener("input", () => {
  clearTimeout(suggestionTimer);
  const text = userInput.value.trim();
  if(text.length < 2) {
    document.getElementById("suggestions-box").style.display = "none";
    return;
  }
  suggestionTimer = setTimeout(async () => {
    renderSuggestions(await getContextualSuggestions(text));
  }, 180);
});

userInput.addEventListener("blur", () => {
  setTimeout(() => {
    document.getElementById("suggestions-box").style.display = "none";
  }, 200);
});

function renderSuggestions(suggestions) {
  const box = document.getElementById("suggestions-box");
  if(!suggestions || suggestions.length === 0) {
    box.style.display = "none";
    return;
  }
  box.innerHTML = "";
  suggestions.forEach(item => {
    const div = document.createElement("div");
    div.className = "suggestion-item";
    div.textContent = item;
    div.onclick = () => {
      userInput.value = item;
      box.style.display = "none";
      userInput.focus();
    };
    box.appendChild(div);
  });
  box.style.display = "block";
}
// ── Welcome screen config ──────────────────────────────────────────────────
// Suggestions loaded dynamically from backend API based on user skill level.

function _buildWelcomeHTML() {
  const caps = WELCOME_CAPS
    .map(c => `<span>${c.replace(/^.*?(Quiz|CTF|Threat Pulse|Cyber Mentor).*$/, '$1')}</span>`)
    .join('');
  const cards = WELCOME_CARDS
    .map(c => `
      <div class="suggest-card" onclick="(${c.action.toString()})()">
        <span class="sc-icon" aria-hidden="true">${WELCOME_CARD_ICONS[c.icon]}</span>
        <span class="sc-copy"><span class="sc-label">${c.label}</span>${c.text}</span>
      </div>`)
    .join('');
  const mentorCard = `
    <div class="mentor-welcome-card" onclick="openMentorOverlay()" style="opacity:0;animation:cardFadeUp .4s ease .4s forwards">
      <div class="mentor-wc-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25"/>
        </svg>
      </div>
      <div class="mentor-wc-body">
        <div class="mentor-wc-label">New — Beginner Mode</div>
        <div class="mentor-wc-title">Cyber Mentor</div>
        <div class="mentor-wc-desc">Structured learning path, interactive roadmap, AI mentor chat and quizzes — built for complete beginners.</div>
        <div class="mentor-wc-pills">
          <span class="mentor-wc-pill">Roadmap</span>
          <span class="mentor-wc-pill">AI Mentor</span>
          <span class="mentor-wc-pill">Quizzes</span>
          <span class="mentor-wc-pill">Resources</span>
          <span class="mentor-wc-pill">Progress Tracker</span>
        </div>
      </div>
      <svg class="mentor-wc-arrow" width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
      </svg>
    </div>`;
  return `
    <div id="welcome">
      <div class="welcome-shield">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none">
          <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" fill="rgba(255,255,255,.12)" stroke="rgba(255,255,255,.55)" stroke-width="1.5" stroke-linejoin="round"/>
          <path d="M9 12l2 2 4-4" stroke="rgba(255,255,255,.85)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="welcome-text-group">
        <div class="welcome-heading">CyberGuru AI</div>
        <div class="welcome-sub">Your AI-powered cybersecurity learning assistant. Ask about threats, attacks, defenses, and security best practices.</div>
      </div>
      <div class="welcome-caps"><span class="new-dot" aria-hidden="true"></span><span class="new-label">New:</span>${caps}</div>

      <div class="suggest-grid">${mentorCard}${cards}</div>

    </div>`;
}
// Mark a tool item active while its panel is open
function setActiveToolItem(id) {
  document.querySelectorAll('.tools-menu-item').forEach(el => el.classList.remove('active'));
  if (id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('active');
  }
}

// Call setActiveToolItem('tool-quiz') inside openQuizModal(), etc.
// Call setActiveToolItem(null) when a modal/panel closes.

// Keyboard navigation for the tools dropdown
document.getElementById('tools-menu-dropdown')?.addEventListener('keydown', e => {
  const items = [...document.querySelectorAll('#tools-menu-dropdown .tools-menu-item')];
  const idx = items.indexOf(document.activeElement);
  if (e.key === 'ArrowDown') { e.preventDefault(); items[(idx + 1) % items.length]?.focus(); }
  if (e.key === 'ArrowUp')   { e.preventDefault(); items[(idx - 1 + items.length) % items.length]?.focus(); }
  if (e.key === 'Home')      { e.preventDefault(); items[0]?.focus(); }
  if (e.key === 'End')       { e.preventDefault(); items[items.length - 1]?.focus(); }
  if (e.key === 'Escape')    { closeToolsMenu(); document.getElementById('tools-menu-trigger')?.focus(); }
});
async function _initStaticWelcome() {
  const caps = document.getElementById('welcome-caps');
  if (caps) caps.innerHTML = `<span class="new-dot" aria-hidden="true"></span><span class="new-label">New:</span>${WELCOME_CAPS.map(c => `<span>${c.replace(/^.*?(Quiz|CTF|Threat Pulse|Cyber Mentor).*$/, '$1')}</span>`).join('')}`;
  const grid = document.getElementById('suggest-grid');
  if (grid) {
    const cards = WELCOME_CARDS
      .map(c => `
        <div class="suggest-card" onclick="(${c.action.toString()})()">
          <span class="sc-icon" aria-hidden="true">${WELCOME_CARD_ICONS[c.icon]}</span>
          <span class="sc-copy"><span class="sc-label">${c.label}</span>${c.text}</span>
        </div>`)
      .join('');
    const mentorCard = `
      <div class="mentor-welcome-card" onclick="openMentorOverlay()" style="opacity:0;animation:cardFadeUp .4s ease .4s forwards">
        <div class="mentor-wc-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25"/>
          </svg>
        </div>
        <div class="mentor-wc-body">
          <div class="mentor-wc-label">New — Beginner Mode</div>
          <div class="mentor-wc-title">Cyber Mentor</div>
          <div class="mentor-wc-desc">Structured learning path, interactive roadmap, AI mentor chat and quizzes — built for complete beginners.</div>
          <div class="mentor-wc-pills">
            <span class="mentor-wc-pill">Roadmap</span>
            <span class="mentor-wc-pill">AI Mentor</span>
            <span class="mentor-wc-pill">Quizzes</span>
            <span class="mentor-wc-pill">Resources</span>
            <span class="mentor-wc-pill">Progress Tracker</span>
          </div>
        </div>
        <svg class="mentor-wc-arrow" width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
        </svg>
      </div>`;
    grid.innerHTML = mentorCard + cards;
  }
}

async function showWelcome() {
  const box = document.getElementById('chat-box');
  box.innerHTML = _buildWelcomeHTML();
}


function loadChat(id, closeMenu = true) {
  activeChatId = id;
  localStorage.setItem(ACTIVE_KEY, id);
  renderHistoryList();

  const box = document.getElementById('chat-box');
  box.innerHTML = '<div class="chat-content" id="chat-content"></div>';

  const chat = chats[id];
  if(!chat) return;

  document.getElementById('topbar-title').textContent = chat.title;
  chat.msgs.forEach(m => appendMessage(m.role, m.text, false));
  scrollToBottom(false);
  const exportBtn = document.getElementById('export-btn');
  if(exportBtn && chat.msgs.length) exportBtn.classList.add('visible');
  if(closeMenu && window.innerWidth <= 768) closeSidebar();
}

/* ─── APPEND MESSAGE ─────────────────────────────────────────── */
function appendMessage(role, text, scroll = true) {
  const welcome = document.getElementById('welcome');
  if(welcome) {
    const box = document.getElementById('chat-box');
    box.innerHTML = '<div class="chat-content" id="chat-content"></div>';
    if(typeof syncRadar === 'function') syncRadar();
  }

  let content = document.getElementById('chat-content');
  if(!content) {
    const box = document.getElementById('chat-box');
    content = document.createElement('div');
    content.id = 'chat-content';
    content.className = 'chat-content';
    box.appendChild(content);
  }

  const time    = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  const name    = role === 'user' ? 'You' : 'CyberGuru';
  let rendered;
  if(role === 'bot') {
    // If the server or other code returned raw HTML, sanitize and render it directly.
    const hasHtml = /<\/?\w+[^>]*>/.test(text);
    if(hasHtml) {
      rendered = (typeof DOMPurify !== 'undefined') ? DOMPurify.sanitize(text) : text;
    } else {
      rendered = (typeof DOMPurify !== 'undefined') ? DOMPurify.sanitize(renderMarkdown(text)) : renderMarkdown(text);
    }
  } else {
    rendered = `<p>${escapeHtml(text)}</p>`;
  }

  const userAvatar = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.8)" stroke-width="2">
    <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/>
  </svg>`;
  const botAvatar = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none">
    <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" fill="rgba(255,255,255,.1)" stroke="rgba(255,255,255,.55)" stroke-width="1.5" stroke-linejoin="round"/>
    <path d="M9 12l2 2 4-4" stroke="rgba(255,255,255,.85)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;

  const msgId = 'msg-' + Date.now() + '-' + Math.random().toString(36).slice(2,6);
  const botActions = role === 'bot' ? `
    <div class="msg-actions">
      <button class="msg-action-btn" onclick="copyMessage('${msgId}')" title="Copy response">
        <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
        Copy
      </button>
      <button class="msg-action-btn" id="${msgId}-up" onclick="thumbs('${msgId}','up')" title="Good response">
        <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3H14zM7 22H4a2 2 0 01-2-2v-7a2 2 0 012-2h3"/></svg>
      </button>
      <button class="msg-action-btn" id="${msgId}-dn" onclick="thumbs('${msgId}','down')" title="Bad response">
        <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 15v4a3 3 0 003 3l4-9V2H5.72a2 2 0 00-2 1.7l-1.38 9a2 2 0 002 2.3H10zM17 2h2.67A2.31 2.31 0 0122 4v7a2.31 2.31 0 01-2.33 2H17"/></svg>
      </button>
    </div>` : '';

  const row = document.createElement('div');
  row.className = `msg-row ${role}`;
  row.innerHTML = `
    <div class="msg-inner">
      <div class="msg-avatar">${role === 'user' ? userAvatar : botAvatar}</div>
      <div class="msg-body">
        <div class="msg-meta">
          <span class="msg-name">${name}</span>
          <span class="msg-time">${time}</span>
        </div>
        <div class="msg-content" id="${msgId}">${rendered}</div>
        ${botActions}
      </div>
    </div>`;

  content.appendChild(row);

  // Attach TTS button to bot messages
  if(role === 'bot') {
    const msgBody = row.querySelector('.msg-body');
    if(msgBody) addTTSButton(msgBody, text);
  }

  // Show export button once there are messages
  const exportBtn = document.getElementById('export-btn');
  if(exportBtn) exportBtn.classList.add('visible');

  if(scroll) {
    requestAnimationFrame(() => { autoScrollIfNeeded(); });
  }
}

/* Quiz Mode is now a self-contained interactive flow — see static/js/quiz.js
   for openQuizModal/closeQuizModal and the full picker→play→result UI. */

/* ─── MARKDOWN RENDERER ──────────────────────────────────────── */
function renderMarkdown(text) {
  // Step 1: Extract and protect code blocks BEFORE any escaping
  // so code content is escaped but markdown syntax outside is not
  const codeBlocks = [];
  let s = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
    const id = 'code-' + Math.random().toString(36).slice(2,8);
    const display = lang || 'text';
    const trimmed = code.trim();
    // Use hljs to highlight if available and language is known
    let highlighted;
    if(typeof hljs !== 'undefined' && lang && hljs.getLanguage(lang)) {
      try {
        highlighted = hljs.highlight(trimmed, { language: lang, ignoreIllegals: true }).value;
      } catch(e) {
        highlighted = trimmed.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      }
    } else if(typeof hljs !== 'undefined' && !lang) {
      // Auto-detect language
      try {
        highlighted = hljs.highlightAuto(trimmed).value;
      } catch(e) {
        highlighted = trimmed.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      }
    } else {
      highlighted = trimmed.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }
    const html = `<div class="code-block-wrap">
      <div class="code-block-header">
        <span class="code-lang">${display}</span>
        <button class="copy-btn" id="${id}" onclick="copyCode('${id}')">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
          </svg>
          Copy
        </button>
      </div>
      <pre><code class="hljs lang-${display}">${highlighted}</code></pre>
    </div>`;
    const placeholder = `\x00CODE${codeBlocks.length}\x00`;
    codeBlocks.push(html);
    return placeholder;
  });

  // Step 2: Escape only < and > (not & — that would corrupt emojis/special chars)
  // Emojis are Unicode codepoints and don't need HTML escaping
  s = s.replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Step 3: Inline code (escape content inside backticks)
  s = s.replace(/`([^`]+)`/g, (_, code) => {
    const esc = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return `<code>${esc}</code>`;
  });

  // Step 4: Headings
  s = s.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  s = s.replace(/^## (.+)$/gm,  '<h2>$1</h2>');
  s = s.replace(/^# (.+)$/gm,   '<h1>$1</h1>');

  // Step 5: Bold & italic
  s = s.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  s = s.replace(/\*\*(.+?)\*\*/g,     '<strong>$1</strong>');
  s = s.replace(/\*(.+?)\*/g,         '<em>$1</em>');

  // Step 6: Blockquote
  s = s.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>');

  // Step 7: Unordered lists
  s = s.replace(/((?:^[-*] .+\n?)+)/gm, match => {
    const items = match.trim().split('\n').map(l => `<li>${l.replace(/^[-*] /,'')}</li>`).join('');
    return `<ul>${items}</ul>`;
  });

  // Step 8: Ordered lists
  s = s.replace(/((?:^\d+\. .+\n?)+)/gm, match => {
    const items = match.trim().split('\n').map(l => `<li>${l.replace(/^\d+\. /,'')}</li>`).join('');
    return `<ol>${items}</ol>`;
  });

  // Step 9: Paragraphs
  s = s.split(/\n{2,}/).map(block => {
    if(/^<(h[1-3]|ul|ol|pre|div|blockquote|\x00CODE)/.test(block.trim())) return block;
    return `<p>${block.replace(/\n/g,'<br>')}</p>`;
  }).join('\n');

  // Step 10: Restore code blocks
  codeBlocks.forEach((html, i) => {
    s = s.replace(`\x00CODE${i}\x00`, html);
  });

  return s;
}

function escapeHtml(t) {
  return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
          .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/* ─── COPY CODE ──────────────────────────────────────────────── */
function copyCode(btnId) {
  const btn = document.getElementById(btnId);
  if(!btn) return;
  const pre = btn.closest('.code-block-wrap').querySelector('pre code');
  if(!pre) return;
  navigator.clipboard.writeText(pre.textContent).then(() => {
    btn.classList.add('copied');
    btn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M20 6L9 17l-5-5"/></svg> Copied`;
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg> Copy`;
    }, 2000);
  }).catch(() => {});
}

/* ─── HISTORY ────────────────────────────────────────────────── */
function getChatTimestamp(id) {
  // IDs are 'chat_<timestamp>' — extract ms for grouping
  const ts = parseInt(id.replace('chat_', ''), 10);
  return isNaN(ts) ? 0 : ts;
}

function getGroupLabel(ts) {
  if(!ts) return 'Older';
  const now   = new Date();
  const date  = new Date(ts);
  const diffMs   = now - date;
  const diffDays = Math.floor(diffMs / 86400000);
  const todayStr = now.toDateString();
  const dateStr  = date.toDateString();
  if(dateStr === todayStr)               return 'Today';
  if(diffDays === 1)                     return 'Yesterday';
  if(diffDays <= 6)                      return 'This Week';
  if(diffDays <= 29)                     return 'This Month';
  return 'Older';
}

function renderHistoryList() {
  const list = document.getElementById('history-list');
  list.innerHTML = '';

  const ids = Object.keys(chats).reverse();
  if(ids.length === 0) {
    const e = document.createElement('div');
    e.id = 'history-empty';
    e.className = 'history-empty';
    e.innerHTML = 'No conversations yet.<br>Start by asking a question.';
    list.appendChild(e);
    return;
  }

  const chatIcon = `<svg class="hi-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
    <path stroke-linecap="round" stroke-linejoin="round" d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
  </svg>`;
  const deleteIcon = `<svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"></path></svg>`;

  // Group by time
  const groups = {};
  const ORDER  = ['Today','Yesterday','This Week','This Month','Older'];
  ids.forEach(id => {
    const label = getGroupLabel(getChatTimestamp(id));
    if(!groups[label]) groups[label] = [];
    groups[label].push(id);
  });

  ORDER.forEach(label => {
    if(!groups[label]) return;
    // Group header
    const hdr = document.createElement('div');
    hdr.className = 'history-group-label';
    hdr.textContent = label;
    list.appendChild(hdr);

    groups[label].forEach(id => {
      const chat = chats[id];
      const div  = document.createElement('div');
      div.className = 'history-item' + (id === activeChatId ? ' active' : '');
      div.innerHTML = `
        ${chatIcon}
        <span class="hi-title">${escapeHtml(chat.title)}</span>
        <button class="delete-chat-btn" aria-label="Delete chat" title="Delete conversation" onclick="deleteChat('${id}', event)">
          ${deleteIcon}
        </button>`;
      div.onclick = () => loadChat(id);
      list.appendChild(div);
    });
  });
}

/* ─── DELETE CHAT ────────────────────────────────────────────── */
let _confirmResolve = null;

function showConfirm() {
  document.getElementById('confirm-modal').classList.add('show');
  return new Promise(resolve => { _confirmResolve = resolve; });
}

function resolveConfirm(result) {
  document.getElementById('confirm-modal').classList.remove('show');
  if(_confirmResolve) { _confirmResolve(result); _confirmResolve = null; }
}

async function deleteChat(id, event) {
  event.stopPropagation();
  const ok = await showConfirm();
  if(!ok) return;
  delete chats[id];
  saveToStorage();
  renderHistoryList();
  if(activeChatId === id) newChat();
}

/* ─── FILL AND SEND ──────────────────────────────────────────── */
// Named fillAndSend() to avoid collision with the /suggest autocomplete route.
// All suggest-card onclick handlers and quiz mode call this.
function fillAndSend(text) {
  const inputEl = document.getElementById('user-input');
  inputEl.value = text;
  autoResize(inputEl);
  updateCharCount(inputEl.value.length);
  updateSendBtn();
  sendToBackend();
}

/* ─── SEND ───────────────────────────────────────────────────── */
async function sendToBackend() {
  if(isThinking) return;

  const inputEl   = document.getElementById('user-input');
  const message   = inputEl.value.trim();
  const fileInput = document.getElementById('fileInput');
  const file      = fileInput.files[0];

  if(!message && !file) return;
  if(inputEl.value.length > INPUT_MAX_CHARS) {
    updateCharCount(inputEl.value.length);
    updateSendBtn();
    inputEl.focus();
    return;
  }

  inputEl.value = '';
  autoResize(inputEl);
  updateCharCount(0);
  updateSendBtn();
  document.getElementById("suggestions-box").style.display = "none";
  isThinking = true;

  /* ── FILE UPLOAD PATH (streaming) ── */
  if(file) {
    const userLabel = `📎 Analyzing file: ${file.name}`;
    if(!activeChatId) {
      activeChatId = 'chat_' + Date.now();
      chats[activeChatId] = { title: file.name.slice(0,40), msgs:[] };
      localStorage.setItem(ACTIVE_KEY, activeChatId);
      document.getElementById('topbar-title').textContent = chats[activeChatId].title;
    }
    chats[activeChatId].msgs.push({ role:'user', text:userLabel });
    saveToStorage();
    renderHistoryList();
    appendMessage('user', userLabel);

    setThinkingUI(true);
    setTypingState('analyzing');

    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch(`${API_BASE}/analyze-file`, { method:'POST', body:formData });

      // Keep the indicator up — hide it only once the streaming row is in the DOM
      if(!res.ok || !res.body) {
        setThinkingUI(false);
        throw new Error(`HTTP ${res.status}`);
      }

      const streamId = 'stream-' + Date.now();
      appendStreamingMessage(streamId);
      setThinkingUI(false);   // now safe to hide — message row already exists

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let   fullText = '';
      let   buffer   = '';
      let   firstToken = true;

      while(true) {
        const { done, value } = await reader.read();
        if(done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for(const line of lines) {
          if(!line.startsWith('data:')) continue;
          const jsonStr = line.slice(5).trim();
          if(!jsonStr) continue;
          try {
            const payload = JSON.parse(jsonStr);
            if(payload.error) { fullText = payload.error; updateStreamingMessage(streamId, fullText, true); break; }
            if(payload.token) {
              if(firstToken) { firstToken = false; }
              fullText += payload.token; updateStreamingMessage(streamId, fullText, false);
            }
            if(payload.done)  { updateStreamingMessage(streamId, fullText, true); }
          } catch(e) {}
        }
      }

      if(fullText) {
        updateStreamingMessage(streamId, fullText, true);
        chats[activeChatId].msgs.push({ role:'bot', text:fullText });
        saveToStorage();
      } else {
        const errMsg = '⚠️ The response stream ended unexpectedly. Please try again.';
        updateStreamingMessage(streamId, errMsg, true);
        chats[activeChatId].msgs.push({ role:'bot', text:errMsg });
        saveToStorage();
      }

    } catch(err) {
      setThinkingUI(false);
      const errMsg = '⚠️ Could not reach the server. Please check your connection and try again.';
      chats[activeChatId].msgs.push({ role:'bot', text:errMsg });
      saveToStorage();
      appendMessage('bot', errMsg);
    }

    clearFile();
    isThinking = false;
    return;
  }

  /* ── TEXT CHAT PATH — STREAMING + HISTORY ── */
  if(!activeChatId) {
    activeChatId = 'chat_' + Date.now();
    // Generate title locally — no API call, no rate limit impact
    const title = generateSmartTitle(message) || message.slice(0, 42);
    chats[activeChatId] = { title, msgs:[] };
    localStorage.setItem(ACTIVE_KEY, activeChatId);
    document.getElementById('topbar-title').textContent = title;
    renderHistoryList();
  }

  // Build history array from stored messages (exclude current message)
  const history = chats[activeChatId].msgs.map(m => ({ role: m.role, text: m.text }));

  chats[activeChatId].msgs.push({ role:'user', text:message });
  saveToStorage();
  renderHistoryList();
  appendMessage('user', message);

  setThinkingUI(true);
  startTPS();

  // ── Retry-aware stream reader ──
  // Attempts the fetch up to MAX_STREAM_RETRIES+1 times when the stream
  // drops unexpectedly (network hiccup, server restart, etc.).
  // Each retry resumes from the already-accumulated fullText so the user
  // sees a "Reconnecting…" notice rather than a blank error.

  const streamId = 'stream-' + Date.now();
  let   streamCreated   = false;
  let   fullText        = '';
  let   pendingGrounding = null;
  let   streamDone      = false;   // set when server sends {"done":true}
  let   wasRateLimited  = false;

  for(let attempt = 0; attempt <= MAX_STREAM_RETRIES; attempt++) {
    // Show reconnect notice on retry attempts (not the first)
    if(attempt > 0 && streamCreated) {
      setTypingState('reconnecting');
      showReconnectNotice(streamId, attempt);
      // Brief back-off before retry (1s, then 2s)
      await new Promise(r => setTimeout(r, attempt * 1000));
    }

    try {
      abortCtrl = new AbortController();

      const res = await fetch(`${API_BASE}/chat-stream`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ message, history, model: currentModel }),
        signal:  abortCtrl.signal
      });

      setThinkingUI(false);

      // ── HTTP-level 429 (Flask limiter fired before SSE started) ──
      if(res.status === 429) {
        let retryAfter = 60;
        try { const j = await res.json(); retryAfter = j.retry_after || 60; } catch(e){}
        showRateBanner(retryAfter);
        wasRateLimited = true;
        break;
      }

      if(!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);

      // Create the streaming message row on first successful connect only
      if(!streamCreated) {
        appendStreamingMessage(streamId);
        streamCreated = true;
      } else {
        clearReconnectNotice(streamId);
      }

      activeReader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let gotDoneEvent = false;

      while(true) {
        const { done, value } = await activeReader.read();
        if(done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for(const line of lines) {
          if(!line.startsWith('data:')) continue;
          const jsonStr = line.slice(5).trim();
          if(!jsonStr) continue;

          try {
            const payload = JSON.parse(jsonStr);

            // ── SSE-level rate limit event ──
            if(payload.rate_limited) {
              showRateBanner(payload.retry_after || 60);
              wasRateLimited = true;
              if(fullText) updateStreamingMessage(streamId, fullText, true);
              gotDoneEvent = true;
              break;
            }

            // ── Model state transitions ──
            if(payload.status === 'searching') {
              setTypingState('searching');
            }

            // ── Model auto-switch (rate-limit fallback) ──
            if(payload.model_switch) {
              const labels = { gemini:'Gemini Flash', groq:'Groq Llama3', lite:'Flash Lite' };
              const labelEl = document.getElementById('typing-label');
              if(labelEl) labelEl.textContent = `⚡ Switching to ${labels[payload.model_switch] || payload.model_switch}...`;
            }

            if(payload.error) {
              updateStreamingMessage(streamId, payload.error, true);
              fullText = payload.error;
              gotDoneEvent = true;
              break;
            }

            if(payload.token) {
              if(fullText === '') setTypingState('generating'); // first token → switch state
              fullText += payload.token;
              tickTPS(payload.token.length);
              updateStreamingMessage(streamId, fullText, false);
            }

            if(payload.grounding) {
              pendingGrounding = payload.grounding;
            }

            if(payload.done) {
              updateStreamingMessage(streamId, fullText, true);
              gotDoneEvent = true;
              streamDone = true;
            }
          } catch(e) { /* malformed chunk, skip */ }
        }

        if(gotDoneEvent) break;
      }

      // Clean exit — no retry needed
      if(streamDone || wasRateLimited || fullText.startsWith('⚠️')) break;

      // Stream ended without a done event — retry if we have attempts left
      if(attempt < MAX_STREAM_RETRIES) continue;

      // Exhausted retries — treat as complete with whatever we got
      if(fullText) {
        updateStreamingMessage(streamId, fullText + '\n\n*[Response may be incomplete — stream dropped]*', true);
      } else {
        const errMsg = '⚠️ The response stream dropped and could not be recovered. Please try again.';
        if(streamCreated) updateStreamingMessage(streamId, errMsg, true);
        else appendMessage('bot', errMsg);
        fullText = errMsg;
      }

    } catch(err) {
      if(err.name === 'AbortError') {
        // User hit stop — exit cleanly, no retry
        break;
      }

      // Network error — retry if attempts remain
      if(attempt < MAX_STREAM_RETRIES) {
        setThinkingUI(true); // re-show thinking while we retry (resets to 'thinking' state)
        continue;
      }

      // Final failure
      setThinkingUI(false);
      const errMsg = '⚠️ Could not reach the server. Please check your connection and try again.';
      if(streamCreated) updateStreamingMessage(streamId, errMsg, true);
      else appendMessage('bot', errMsg);
      fullText = errMsg;
    }

    break; // success path exits here
  }

  // Finalize storage
  if(fullText && !chats[activeChatId]?.msgs.find(m => m.role === 'bot' && m.text === fullText)) {
    chats[activeChatId].msgs.push({ role:'bot', text:fullText });
    saveToStorage();
  }
  if(pendingGrounding && streamCreated) appendGroundingBlock(streamId, pendingGrounding);

  activeReader = null;
  abortCtrl    = null;
  setThinkingUI(false);
  isThinking = false;
}

/* ─── STREAMING MESSAGE HELPERS ─────────────────────────────── */
function appendStreamingMessage(streamId) {
  // Remove welcome screen if present
  const welcome = document.getElementById('welcome');
  if(welcome) {
    document.getElementById('chat-box').innerHTML = '<div class="chat-content" id="chat-content"></div>';
    if(typeof syncRadar === 'function') syncRadar();
  }

  let content = document.getElementById('chat-content');
  if(!content) {
    const box = document.createElement('div');
    box.id = 'chat-content';
    box.className = 'chat-content';
    document.getElementById('chat-box').appendChild(box);
    content = box;
  }

  const time = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  const botAvatar = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none">
    <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" fill="rgba(255,255,255,.1)" stroke="rgba(255,255,255,.55)" stroke-width="1.5" stroke-linejoin="round"/>
    <path d="M9 12l2 2 4-4" stroke="rgba(255,255,255,.85)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;

  const row = document.createElement('div');
  row.className = 'msg-row bot';
  row.id = streamId;
  row.innerHTML = `
    <div class="msg-inner">
      <div class="msg-avatar">${botAvatar}</div>
      <div class="msg-body">
        <div class="msg-meta">
          <span class="msg-name" style="color:var(--cyan)">CyberGuru</span>
          <span class="msg-time">${time}</span>
        </div>
        <div class="msg-content" id="${streamId}-content"><span class="typing-cursor"></span></div>
      </div>
    </div>`;

  content.appendChild(row);
  requestAnimationFrame(() => { autoScrollIfNeeded(); });
}

function updateStreamingMessage(streamId, fullText, isFinal) {
  const contentEl = document.getElementById(`${streamId}-content`);
  if(!contentEl) return;

  if(isFinal) {
    // Full markdown render on completion
    const renderedHtml = renderMarkdown(fullText);
    contentEl.innerHTML = (typeof DOMPurify !== 'undefined') ? DOMPurify.sanitize(renderedHtml) : renderedHtml;

    // Attach TTS button to the actions bar (or msg-body) once text is final
    const msgBody = contentEl.closest('.msg-body');
    if(msgBody && !msgBody.querySelector('.tts-btn')) {
      addTTSButton(msgBody, fullText);
    }
  } else {
    // Plain text during streaming (fast, no markdown flicker)
    contentEl.textContent = fullText;
    // Keep cursor blinking at end
    const cursor = document.createElement('span');
    cursor.className = 'typing-cursor';
    contentEl.appendChild(cursor);
  }

  requestAnimationFrame(() => { autoScrollIfNeeded(); });
}

function showReconnectNotice(streamId, attempt) {
  // Remove any existing notice first
  clearReconnectNotice(streamId);
  const row = document.getElementById(streamId);
  if(!row) return;
  const body = row.querySelector('.msg-body');
  if(!body) return;
  const notice = document.createElement('div');
  notice.className = 'reconnect-notice';
  notice.id = `${streamId}-reconnect`;
  notice.innerHTML = `
    <div class="reconnect-spinner"></div>
    Reconnecting… (attempt ${attempt} of ${MAX_STREAM_RETRIES})`;
  body.appendChild(notice);
  requestAnimationFrame(() => { autoScrollIfNeeded(); });
}

function clearReconnectNotice(streamId) {
  const el = document.getElementById(`${streamId}-reconnect`);
  if(el) el.remove();
}

/* ─── GROUNDING SOURCES RENDERER ────────────────────────────── */
function appendGroundingBlock(streamId, grounding) {
  const row = document.getElementById(streamId);
  if(!row) return;
  const body = row.querySelector('.msg-body');
  if(!body) return;

  const block = document.createElement('div');
  block.className = 'grounding-block';
  block.innerHTML = `
    <div class="grounding-label">
      <svg width="11" height="11" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-4.35-4.35"/>
      </svg>
      Live search results
    </div>`;

  if(grounding.sources && grounding.sources.length) {
    const sourcesDiv = document.createElement('div');
    sourcesDiv.className = 'grounding-sources';
    grounding.sources.forEach(s => {
      const a = document.createElement('a');
      a.className = 'grounding-source';
      a.href = s.uri;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.innerHTML = `<span class="grounding-dot"></span>${escapeHtml(s.title)}`;
      sourcesDiv.appendChild(a);
    });
    block.appendChild(sourcesDiv);
  }

  if(grounding.rendered) {
    const w = document.createElement('div');
    w.className = 'grounding-widget';
    w.innerHTML = DOMPurify.sanitize(grounding.rendered);
    block.appendChild(w);
  }

  const actions = body.querySelector('.msg-actions');
  if(actions) body.insertBefore(block, actions);
  else body.appendChild(block);
}

/* ─── VOICE INPUT ────────────────────────────────────────────── */
(function initVoice() {
  console.log('[Voice] Script Loaded');
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const micBtn = document.getElementById('mic-btn');

  // Expose a default toggle so inline onclick won't throw even if not supported
  window.toggleVoice = function() { console.log('[Voice] toggleVoice() called before init'); };

  if (!SpeechRecognition) {
    console.warn('[Voice] SpeechRecognition not available in this browser. Hiding mic button.');
    if (micBtn) micBtn.style.display = 'none';
    console.log('[Voice] Browser Supported: false');
    return;
  }

  console.log('[Voice] Browser Supported: true');

  // Create recognition safely
  let recognition;
  try {
    recognition = new SpeechRecognition();
  } catch (err) {
    console.error('[Voice] Failed to create SpeechRecognition:', err);
    if (micBtn) micBtn.style.display = 'none';
    return;
  }

  recognition.lang = 'en-US';
  recognition.continuous = false;
  recognition.interimResults = true;

  let isListening = false;
  let isStarting = false;
  let silenceTimer = null;
  let pendingSend = false;
  let finalTranscript = '';
  let watchdogTimer = null;
  let isStopping = false;
  let isSending = false;
  

  const DEFAULT_PLACEHOLDER = 'Ask about phishing, malware, SQL injection, zero-days…';

  function setVoiceUI(active) {
    if (micBtn) {
      micBtn.classList.toggle('listening', active);
      micBtn.setAttribute('aria-label', active ? 'Stop recording' : 'Start voice input');
      micBtn.title = active ? 'Stop recording' : 'Voice input';
      const idle = document.getElementById('mic-icon-idle');
      const stop = document.getElementById('mic-icon-stop');
      if (idle) idle.style.display = active ? 'none' : '';
      if (stop) stop.style.display = active ? '' : 'none';
    }
    if (micBtn) micBtn.title = active ? 'Listening… (click to stop)' : 'Voice input';
    const inputEl = document.getElementById('user-input');
    if (inputEl) inputEl.placeholder = active ? '🎤 Listening…' : DEFAULT_PLACEHOLDER;
    const vis = document.getElementById('voice-visualizer');
    if (vis) vis.classList.toggle('active', active);
  }

  function showPlaceholderMsg(msg, durationMs = 3500) {
    const inputEl = document.getElementById('user-input');
    if (!inputEl) return;
    inputEl.placeholder = msg;
    setTimeout(() => { if (inputEl) inputEl.placeholder = DEFAULT_PLACEHOLDER; }, durationMs);
  }

  function clearSilenceTimer() {
    if (silenceTimer) { clearTimeout(silenceTimer); silenceTimer = null; }
  }

  function clearWatchdog() {
    if (watchdogTimer) { clearTimeout(watchdogTimer); watchdogTimer = null; }
  }

  function startWatchdog() {
    clearWatchdog();
    // Force-stop recognition after 30s to avoid stuck state
    watchdogTimer = setTimeout(() => {
      console.warn('[Voice] Watchdog timeout — forcing recognition.stop()');
      try { recognition.stop(); } catch (e) {}
      isStarting = false; isListening = false; setVoiceUI(false);
    }, 30000);
  }

  function startListening() {
    console.log('[Voice] startListening() called — isListening=', isListening, 'isStarting=', isStarting);
    if (isListening || isStarting) return;
    isStarting = true;
    finalTranscript = '';
    pendingSend = false;
    try {
      recognition.start();
      console.log('[Voice] recognition.start() called');
      startWatchdog();
    } catch (err) {
      isStarting = false;
      console.warn('[Voice] recognition.start() failed:', err && err.name ? err.name : err);
      showPlaceholderMsg('⚠️ Could not start microphone. Try clicking again.');
    }
  }

  function stopListening() {
    console.log('[Voice] stopListening() called');
    // If user manually stops, ensure we will submit any final transcript
    clearSilenceTimer();
    clearWatchdog();
    if (finalTranscript && finalTranscript.trim()) {
      pendingSend = true;
      console.log('[Voice] Manual stop requested — pendingSend set to true');
    }
    if (isStopping) {
      console.log('[Voice] stop already in progress — ignoring duplicate stop');
      return;
    }
    isStopping = true;
    try { recognition.stop(); console.log('[Voice] recognition.stop() called'); } catch (err) { isStopping = false; /* ignore */ }
  }

  // Attach toggle on window so HTML onclick works; keep behavior same
  window.toggleVoice = function() {
    console.log('[Voice] toggleVoice()');
    if (isListening) stopListening(); else startListening();
  };

  // Add a click listener for diagnostic logging (doesn't replace onclick)
  if (micBtn) micBtn.addEventListener('click', () => console.log('[Voice] mic button clicked'));

  recognition.onstart = () => {
    console.log('[Voice] onstart');
    isListening = true; isStarting = false; isStopping = false; setVoiceUI(true);
    console.log('[Voice] Started Listening');
  };

  recognition.onresult = (e) => {
    console.log('[Voice] onresult, resultIndex=', e.resultIndex, 'resultsLen=', e.results.length);
    let interim = '';
    let newFinal = '';
    for (let i = e.resultIndex; i < e.results.length; i++) {
      const t = e.results[i][0].transcript;
      if (e.results[i].isFinal) {
        newFinal += t;
        console.log('[Voice] Final Transcript:', t);
      } else {
        interim += t;
        console.log('[Voice] Interim Transcript:', t);
      }
    }
    if (newFinal) finalTranscript += newFinal;
    const inputEl = document.getElementById('user-input');
    if (inputEl) { inputEl.value = (finalTranscript || interim); autoResize(inputEl); }

    clearSilenceTimer();
    // Start 1s silence timer after last detected final transcript
    if (finalTranscript && finalTranscript.trim()) {
      silenceTimer = setTimeout(() => {
        pendingSend = !!finalTranscript.trim();
        console.log('[Voice] Silence Detected — pendingSend=', pendingSend);
        // Guard against multiple stop() calls
        if (isStopping) {
          console.log('[Voice] recognition.stop() already in progress from another action');
          return;
        }
        isStopping = true;
        try { recognition.stop(); console.log('[Voice] recognition.stop() called (silence timer)'); } catch (e) { isStopping = false; console.warn('[Voice] recognition.stop() failed in silenceTimer', e); }
      }, 1000);
    }
  };

  recognition.onend = () => {
    console.log('[Voice] onend — isListening=', isListening, 'pendingSend=', pendingSend);
    isListening = false; isStarting = false; setVoiceUI(false); clearSilenceTimer(); clearWatchdog(); isStopping = false;
    console.log('[Voice] Recognition Stopped');
    if (pendingSend && finalTranscript && finalTranscript.trim()) {
      pendingSend = false;
      if (isSending) {
        console.log('[Voice] send already in progress — skipping duplicate');
        return;
      }
      console.log('[Voice] Auto Send Triggered');
      isSending = true;
      // Ensure the input contains the final transcript before sending
      const inputEl = document.getElementById('user-input');
      if (inputEl) inputEl.value = finalTranscript.trim();
      sendToBackend().then(() => {
        console.log('[Voice] Message Submitted');
        isSending = false;
        // Clear final transcript buffer to prevent re-sends
        finalTranscript = '';
      }).catch((err) => {
        console.warn('[Voice] sendToBackend failed', err);
        isSending = false;
      });
    }
  };

  recognition.onerror = (e) => {
    console.warn('[Voice] onerror', e && e.error ? e.error : e);
    isListening = false; isStarting = false; pendingSend = false; clearSilenceTimer(); clearWatchdog(); setVoiceUI(false);

    const errorMessages = {
      'not-allowed':   '⚠️ Microphone access denied. Check browser permissions.',
      'audio-capture': '⚠️ No microphone found. Plug one in and try again.',
      'network':       '⚠️ Network error during voice recognition. Try again.',
      'aborted':       null,
      'no-speech':     '⚠️ No speech detected. Try speaking closer to your mic.',
      'service-not-allowed': '⚠️ Voice input requires HTTPS.',
    };
    const msg = e && e.error ? errorMessages[e.error] : null;
    if (msg) showPlaceholderMsg(msg, 4000);
  };

  // Diagnostic helper: prints browser / mic / recognition state
  window.voiceDebug = async function() {
    console.log('--- Voice Debug ---');
    try {
      const ua = navigator.userAgent;
      console.log('Browser UA:', ua);
      console.log('SpeechRecognition available:', !!SpeechRecognition);
      if (navigator.permissions && navigator.permissions.query) {
        try {
          const p = await navigator.permissions.query({ name: 'microphone' });
          console.log('Microphone permission state:', p.state);
        } catch (permErr) {
          console.log('Permission API error:', permErr);
        }
      } else {
        console.log('Permissions API not available in this browser.');
      }
      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        try {
          const devs = await navigator.mediaDevices.enumerateDevices();
          const mics = devs.filter(d => d.kind === 'audioinput');
          console.log('Microphone devices found:', mics.length, mics.map(m => ({ label: m.label, id: m.deviceId }))); 
        } catch (mdErr) { console.log('enumerateDevices error:', mdErr); }
      } else {
        console.log('mediaDevices.enumerateDevices not supported');
      }
      console.log('Mic button exists:', !!micBtn);
      console.log('Event listeners attached: onstart/onresult/onend/onerror:', !!recognition.onstart, !!recognition.onresult, !!recognition.onend, !!recognition.onerror);
      console.log('Current recognition state: isListening=', isListening, 'isStarting=', isStarting, 'pendingSend=', pendingSend);
      console.log('-------------------');
    } catch (err) { console.error('[Voice] voiceDebug failed', err); }
  };

  // Expose some internals for debugging in console
  window._voice = { recognition, isListening: () => isListening };

  // Startup self-test logs
  console.log('[Voice] Mic Button Found:', !!micBtn);
  console.log('[Voice] Ready');
})();
async function fetchCyberNews() {
  // Push a user-style message into chat so it feels like a real query
  if(!activeChatId) {
    activeChatId = 'chat_' + Date.now();
    chats[activeChatId] = { title: 'Cybersecurity News', msgs: [] };
    localStorage.setItem(ACTIVE_KEY, activeChatId);
    document.getElementById('topbar-title').textContent = chats[activeChatId].title;
  }

  const userLabel = '📰 Show me the latest cybersecurity news';
  chats[activeChatId].msgs.push({ role: 'user', text: userLabel });
  saveToStorage();
  renderHistoryList();

  appendMessage('user', userLabel);   // clears welcome screen, adds user bubble

  setThinkingUI(true);
  setTypingState('searching');

  try {
    const res = await fetch('/api/cybernews');
    const articles = await res.json();
    setThinkingUI(false);

    let html = `<h3>📰 Latest Cybersecurity News</h3><ul>`;
    articles.forEach(art => {
      html += `<li><strong><a href="${art.link}" target="_blank" rel="noopener noreferrer">${escapeHtml(art.title)}</a></strong><br><small>${escapeHtml(art.source)} · ${escapeHtml(art.published)}</small><br>${escapeHtml(art.summary)}</li><br>`;
    });
    html += `</ul>`;

    appendMessage('bot', html);
    chats[activeChatId].msgs.push({ role: 'bot', text: html });
    saveToStorage();

  } catch (err) {
    setThinkingUI(false);
    const errMsg = '⚠️ Failed to fetch cybersecurity news.';
    appendMessage('bot', errMsg);
    chats[activeChatId].msgs.push({ role: 'bot', text: errMsg });
    saveToStorage();
  }
}
/* ─── TEXTAREA AUTO-RESIZE + CHAR COUNT ─────────────────────── */
var ta = document.getElementById('user-input');
var sendBtn = document.getElementById('send-btn');
const INPUT_MAX_CHARS = 4000;

function updateSendBtn() {
  const hasText = ta.value.trim().length > 0;
  const hasFile = document.getElementById('fileInput').files.length > 0;
  const isOverLimit = ta.value.length > INPUT_MAX_CHARS;
  sendBtn.disabled = !(hasText || hasFile) || isOverLimit;
  const wrapper = document.querySelector('.input-wrapper');
  if(wrapper) {
    wrapper.classList.toggle('is-ready', (hasText || hasFile) && !isOverLimit);
    wrapper.classList.toggle('is-over-limit', isOverLimit);
  }
}

// Initial state — disabled on page load
sendBtn.disabled = true;

ta.addEventListener('input', function() {
  autoResize(this);
  updateCharCount(this.value.length);
  updateSendBtn();
});
ta.addEventListener('keydown', function(e) {
  if(e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if(ta.value.trim().length > 0 || document.getElementById('fileInput').files.length > 0) {
      sendToBackend();
    }
  }
});

function updateCharCount(len) {
  const el = document.getElementById('char-count');
  if(!el) return;
  if(len === 0) { el.classList.remove('visible','warn','over'); return; }
  el.textContent = len >= INPUT_MAX_CHARS * 0.8 ? `${len}/${INPUT_MAX_CHARS}` : len;
  el.classList.toggle('visible', len > 0);
  el.classList.toggle('warn', len > INPUT_MAX_CHARS * 0.8 && len <= INPUT_MAX_CHARS);
  el.classList.toggle('over', len > INPUT_MAX_CHARS);
}

function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 160) + 'px';
}

/* ─── SCROLL HELPERS ─────────────────────────────────────────── */
let _userScrolled = false;

function initScrollTracking() {
  const box = document.getElementById('chat-box');
  const btn = document.getElementById('scroll-btn');
  box.addEventListener('scroll', () => {
    const dist = box.scrollHeight - box.scrollTop - box.clientHeight;
    _userScrolled = dist > 80;
    if(btn) btn.classList.toggle('show', _userScrolled);
  });
}

function scrollToBottom(smooth) {
  const box = document.getElementById('chat-box');
  const btn = document.getElementById('scroll-btn');
  _userScrolled = false;
  if(btn) btn.classList.remove('show');
  box.scrollTo({ top: box.scrollHeight, behavior: smooth === false ? 'auto' : 'smooth' });
}

function autoScrollIfNeeded() {
  if(!_userScrolled) {
    const box = document.getElementById('chat-box');
    box.scrollTo({ top: box.scrollHeight, behavior: 'smooth' });
  }
}

/* ─── SIDEBAR TOGGLE (mobile) ────────────────────────────────── */
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('show');
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('show');
}

/* ─────────────────────────────────────────────────────────────────
   NETWORK TOPOLOGY BACKGROUND
   Renders a minimal threat-map style graph:
   - Nodes pulse gently (heartbeat opacity)
   - Edges fade in/out to simulate live traffic
   - One "alert" node flickers red occasionally
   Performance: requestAnimationFrame, ~30 nodes, lightweight
   ───────────────────────────────────────────────────────────────── */
(function initNetwork() {
  const canvas = document.getElementById('network-canvas');
  const ctx    = canvas.getContext('2d');

  let W, H, nodes, edges, packets;
  let frame = 0;
  let swCache = 264;

  // ── Accent colour per theme ──
  function accent() {
    const b = document.body;
    if (b.classList.contains('theme-light'))  return [67, 56, 202];
    if (b.classList.contains('theme-oled'))   return [124, 110, 247];
    return [79, 110, 247];
  }

  function resize() {
    swCache = document.getElementById('sidebar')?.offsetWidth || 264;
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    build();
  }

  function build() {
    // More nodes than before — denser graph, covers the full screen
    const count = Math.min(55, Math.max(30, Math.floor(W * H / 16000)));

    // Scatter nodes across full screen including sidebar area for depth
    nodes = Array.from({ length: count }, (_, i) => ({
      x:     Math.random() * W,
      y:     Math.random() * H,
      // Three tiers: hub (large), relay (medium), leaf (small)
      tier:  i < 4 ? 'hub' : i < count * 0.3 ? 'relay' : 'leaf',
      vx:    (Math.random() - 0.5) * 0.18,
      vy:    (Math.random() - 0.5) * 0.18,
      // alert node — one per session, flickers red periodically
      alert: i === 1,
      alertTimer: Math.floor(Math.random() * 400),
    }));

    rebuildEdges();
    spawnPackets();
  }

  function rebuildEdges() {
    edges = [];
    // Connection distance: hubs connect farther, leaves connect closer
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const maxDist =
          (a.tier === 'hub' || b.tier === 'hub')   ? W * 0.28 :
          (a.tier === 'relay' || b.tier === 'relay') ? W * 0.18 :
                                                        W * 0.12;
        if (dist < maxDist) {
          edges.push({ a: i, b: j, dist });
        }
      }
    }
  }

  // ── Data packets travelling along edges ──
  function spawnPackets() {
    packets = [];
    // Seed some initial packets
    for (let k = 0; k < 12; k++) spawnPacket();
  }

  function spawnPacket() {
    if (!edges.length) return;
    const e = edges[Math.floor(Math.random() * edges.length)];
    // Randomly pick direction along the edge
    const forward = Math.random() > 0.5;
    packets.push({
      edgeIdx: edges.indexOf(e),
      t:       0,                          // 0 → 1 travel progress
      speed:   0.004 + Math.random() * 0.006,
      forward,
    });
  }

  function draw() {
    frame++;
    ctx.clearRect(0, 0, W, H);

    const [r, g, b] = accent();

    // ── Move nodes (slow drift, bounce off walls) ──
    for (const n of nodes) {
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > W) { n.vx *= -1; n.x = Math.max(0, Math.min(W, n.x)); }
      if (n.y < 0 || n.y > H) { n.vy *= -1; n.y = Math.max(0, Math.min(H, n.y)); }
    }

    // Rebuild edges every 90 frames so new connections form as nodes drift
    if (frame % 90 === 0) rebuildEdges();

    // ── Draw edges — sharp, minimal ──
    for (const e of edges) {
      const a = nodes[e.a], b = nodes[e.b];
      // Closer edges are slightly more visible
      const proximity = 1 - e.dist / (W * 0.3);
      const alpha = proximity * 0.13;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = `rgba(${r},${g},${b},${alpha})`;
      ctx.lineWidth = 0.5;
      ctx.stroke();
    }

    // ── Draw packets ──
    for (let i = packets.length - 1; i >= 0; i--) {
      const p = packets[i];
      const e = edges[p.edgeIdx];
      if (!e) { packets.splice(i, 1); continue; }

      p.t += p.speed;
      if (p.t >= 1) {
        packets.splice(i, 1);
        // Spawn a new one to keep density constant
        if (Math.random() > 0.3) spawnPacket();
        continue;
      }

      const na = nodes[e.a], nb = nodes[e.b];
      const t  = p.forward ? p.t : 1 - p.t;
      const px = na.x + (nb.x - na.x) * t;
      const py = na.y + (nb.y - na.y) * t;

      // Packet: small sharp square dot
      ctx.fillStyle = `rgba(${r},${g},${b},0.7)`;
      ctx.fillRect(px - 1.5, py - 1.5, 3, 3);
    }

    // ── Draw nodes — clean dots, no glow halos ──
    for (const n of nodes) {
      n.alertTimer++;
      const isAlerting = n.alert && (n.alertTimer % 320) < 30;

      let nr = r, ng = g, nb2 = b;
      if (isAlerting) { nr = 248; ng = 113; nb2 = 113; }

      const dotR =
        n.tier === 'hub'   ? 3.5 :
        n.tier === 'relay' ? 2.2 :
                              1.4;

      const alpha =
        n.tier === 'hub'   ? 0.7 :
        n.tier === 'relay' ? 0.5 :
                              0.35;

      // Sharp filled circle — no glow, no radial gradient
      ctx.beginPath();
      ctx.arc(n.x, n.y, dotR, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${nr},${ng},${nb2},${alpha})`;
      ctx.fill();

      // Hub nodes get a crisp ring instead of glow
      if (n.tier === 'hub') {
        ctx.beginPath();
        ctx.arc(n.x, n.y, dotR + 3, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${nr},${ng},${nb2},0.18)`;
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      // Alert: sharp blinking ring only
      if (isAlerting) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, dotR + 6, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(248,113,113,0.35)`;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }

    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', resize);
  resize();
  draw();
})();
/* ── Sidebar Tools Dropdown ── */
function toggleToolsMenu(e) {
  e.stopPropagation();
  const dropdown = document.getElementById('tools-menu-dropdown');
  const trigger  = document.getElementById('tools-menu-trigger');
  const isOpen   = dropdown.classList.contains('open');
  if (isOpen) {
    dropdown.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
  } else {
    dropdown.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
  }
}

function closeToolsMenu() {
  const dropdown = document.getElementById('tools-menu-dropdown');
  const trigger  = document.getElementById('tools-menu-trigger');
  if (dropdown) dropdown.classList.remove('open');
  if (trigger)  trigger.setAttribute('aria-expanded', 'false');
}

document.addEventListener('click', function(e) {
  const wrap = document.getElementById('tools-menu-wrap');
  if (wrap && !wrap.contains(e.target)) closeToolsMenu();
});

/* ── User Menu Dropdown ── */
function toggleUserMenu(e) {
  e.stopPropagation();
  const dropdown = document.getElementById('user-menu-dropdown');
  const trigger  = document.getElementById('user-menu-trigger');
  const isOpen   = dropdown.classList.contains('open');
  if (isOpen) {
    dropdown.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
  } else {
    dropdown.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
  }
}

function closeUserMenu() {
  const dropdown = document.getElementById('user-menu-dropdown');
  const trigger  = document.getElementById('user-menu-trigger');
  if (dropdown) dropdown.classList.remove('open');
  if (trigger)  trigger.setAttribute('aria-expanded', 'false');
}

document.addEventListener('click', function(e) {
  const wrap = document.getElementById('user-menu-wrap');
  if (wrap && !wrap.contains(e.target)) closeUserMenu();
});

/* ── Settings Panel ── */
function openSettings() {
  // Populate user info
  const avatar = document.getElementById('user-avatar');
  const name   = document.getElementById('user-name');
  const email  = document.getElementById('user-email');
  if (avatar) document.getElementById('sp-avatar').src = avatar.src;
  if (name)   document.getElementById('sp-name').textContent  = name.textContent;
  if (email)  document.getElementById('sp-email').textContent = email.textContent;

  document.getElementById('settings-panel').classList.add('show');
  document.getElementById('settings-overlay').classList.add('show');
  document.body.style.overflow = 'hidden';
  updateThemeCards();
  updateFontButtons();
}

function closeSettings() {
  document.getElementById('settings-panel').classList.remove('show');
  document.getElementById('settings-overlay').classList.remove('show');
  document.body.style.overflow = '';
}

function switchTab(tab) {
  document.querySelectorAll('.sp-tab').forEach((t,i) => {
    t.classList.toggle('active', ['account','appearance','about'][i] === tab);
  });
  document.querySelectorAll('.sp-body').forEach(b => b.classList.add('hidden'));
  document.getElementById('tab-' + tab).classList.remove('hidden');
}

function updateThemeCards() {
  const saved = localStorage.getItem('cyberguru_theme') || 'cyber';
  document.querySelectorAll('.sp-theme-card').forEach(c => c.classList.remove('active'));
  const el = document.getElementById('tc-' + saved);
  if (el) el.classList.add('active');
}

function setFontSize(size) {
  document.documentElement.style.setProperty('--msg-font-size',
    size === 'compact' ? '13px' : size === 'large' ? '16px' : '14px'
  );
  document.querySelectorAll('.sp-font-btn').forEach(b => b.classList.remove('active'));
  const el = document.getElementById('fs-' + size);
  if (el) el.classList.add('active');
  localStorage.setItem('font_size', size);
}

function updateFontButtons() {
  const saved = localStorage.getItem('font_size') || 'default';
  document.querySelectorAll('.sp-font-btn').forEach(b => b.classList.remove('active'));
  const el = document.getElementById('fs-' + saved);
  if (el) el.classList.add('active');
}

function toggleCompactSidebar(on) {
  document.documentElement.style.setProperty('--sidebar-w', on ? '200px' : '264px');
  localStorage.setItem('compact_sidebar', on);
}

// Load saved font size and sidebar on init
function loadAppearanceSettings() {
  const fs = localStorage.getItem('font_size') || 'default';
  setFontSize(fs);
  const compact = localStorage.getItem('compact_sidebar') === 'true';
  if (compact) {
    document.getElementById('compact-sidebar-toggle').checked = true;
    toggleCompactSidebar(true);
  }
}
function setModel(m) {
  currentModel = m;
  document.querySelectorAll('.model-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.model === m);
  });
  const label = document.getElementById('model-active-label');
  const topbar = document.getElementById('topbar-model-text');
  const version = document.getElementById('sidebar-version');
  if (m === 'groq') {
    if (label)   label.textContent   = 'Groq Llama3.1 8B · Ultra Fast';
    if (topbar)  topbar.textContent  = 'Groq Llama3.1 8B';
    if (version) version.textContent = 'v1.1 | Groq Llama 3.1 8B';
  } else if (m === 'lite') {
    if (label)   label.textContent   = 'Flash Lite · Fastest';
    if (topbar)  topbar.textContent  = 'Gemini 3.1 Flash Lite';
    if (version) version.textContent = 'v1.1 | Gemini 3.1 Flash Lite';
  } else {
    if (label)   label.textContent   = 'Gemini 2.5 Flash · Smart';
    if (topbar)  topbar.textContent  = 'Gemini 2.5 Flash';
    if (version) version.textContent = 'v1.1 | Gemini 2.5 Flash';
  }
}
// ── Plus menu ──
function togglePlusMenu() {
  const btn = document.getElementById('plus-btn');
  const menu = document.getElementById('plus-menu-dropdown');
  const open = menu.classList.toggle('open');
  btn.setAttribute('aria-expanded', open);
  if (open) {
    prefetchInvestigatePage();
    document.addEventListener('click', closePlusOnOutside, { once: true, capture: true });
  }
}
function closePlusMenu() {
  document.getElementById('plus-menu-dropdown')?.classList.remove('open');
  document.getElementById('plus-btn')?.setAttribute('aria-expanded', 'false');
  // close submenu too
  document.getElementById('models-submenu')?.classList.remove('open');
  document.querySelector('.plus-menu-item.submenu-open')?.classList.remove('submenu-open');
}
function closePlusOnOutside(e) {
  if (!document.getElementById('plus-menu-wrap')?.contains(e.target)) closePlusMenu();
}
function toggleModelsSubmenu(e) {
  e.stopPropagation();
  const sub = document.getElementById('models-submenu');
  const btn = e.currentTarget;
  const isOpen = sub.classList.toggle('open');
  btn.classList.toggle('submenu-open', isOpen);
}
function updatePlusModelLabel(label) {
  const el = document.getElementById('plus-active-model');
  if (el) el.textContent = label;
}

let investigatePrefetchStarted = false;
function prefetchInvestigatePage() {
  if (investigatePrefetchStarted) return;
  investigatePrefetchStarted = true;

  if (!document.querySelector('link[data-prefetch-investigate="true"]')) {
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.as = 'document';
    link.href = '/investigate';
    link.setAttribute('data-prefetch-investigate', 'true');
    document.head.appendChild(link);
  }

  if (!document.querySelector('link[data-prefetch-investigate-js="true"]')) {
    const script = document.createElement('link');
    script.rel = 'prefetch';
    script.as = 'script';
    script.href = '/static/js/investigate.js';
    script.setAttribute('data-prefetch-investigate-js', 'true');
    document.head.appendChild(script);
  }

  fetch('/investigate', { credentials: 'include', cache: 'force-cache' }).catch(() => {});
}

/* Investigation Center is now a dedicated page at /investigate */
function openInvestigatePanel() {
  window.location.href = '/investigate';
}

document.addEventListener('DOMContentLoaded', function () {
  prefetchInvestigatePage();
});
