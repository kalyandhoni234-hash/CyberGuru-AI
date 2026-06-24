/* ═══════════════════════════════════════════════════════════════════
   CYBER MENTOR — Domain-Based Roadmap
   ═══════════════════════════════════════════════════════════════════ */

function escapeHtml(t) { if (typeof t !== 'string') return ''; return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function generateChatTitle(text) {
  let t = text.trim().replace(/[?。！？.!]+$/, '').trim();
  const prefixes = [
    /^tell me about\s+/i, /^tell me more about\s+/i,
    /^what is\s+/i, /^what are\s+/i, /^what's\s+/i,
    /^explain\s+/i, /^how do i\s+/i, /^how to\s+/i,
    /^where do i\s+/i, /^can you\s+/i, /^could you\s+/i,
    /^i want to learn\s+/i, /^i want to know\s+/i,
    /^define\s+/i, /^describe\s+/i,
  ];
  for (const p of prefixes) {
    t = t.replace(p, '');
  }
  t = t.trim();
  t = t.replace(/\s+(for|in|of|on|about|with|and|the|a|an)\s*$/i, '');
  t = t.trim();
  if (!t) {
    const words = text.trim().split(/\s+/).slice(0, 3);
    return words.map(w => w[0].toUpperCase() + w.slice(1).toLowerCase()).join(' ');
  }
  const words = t.split(/\s+/);
  const n = Math.min(words.length, Math.max(2, Math.min(words.length, 4)));
  return words.slice(0, n).map(w => w[0].toUpperCase() + w.slice(1).toLowerCase()).join(' ');
}

// ── Three-dot menu helpers ──
let _openMenuId = null;
document.addEventListener('click', function _closeMenus() {
  if (_openMenuId) {
    const menu = document.getElementById('mchat-menu-' + _openMenuId);
    if (menu) menu.classList.remove('open');
    _openMenuId = null;
  }
});
function toggleMentorMenu(id, event) {
  event.stopPropagation();
  const menu = document.getElementById('mchat-menu-' + id);
  if (!menu) return;
  if (_openMenuId === id) {
    menu.classList.remove('open');
    _openMenuId = null;
    return;
  }
  if (_openMenuId) {
    const old = document.getElementById('mchat-menu-' + _openMenuId);
    if (old) old.classList.remove('open');
  }
  menu.classList.add('open');
  _openMenuId = id;
}

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) return meta.getAttribute('content');
  const name = 'csrf_token';
  const cookies = document.cookie.split(';');
  for (let c of cookies) {
    c = c.trim();
    if (c.startsWith(name + '=')) return decodeURIComponent(c.substring(name.length + 1));
  }
  return null;
}

const MENTOR_KEY = 'cyberguru_mentor_v1';

const FALLBACK_DATA = {
  shared_core: {
    title: 'Core Foundations',
    topics: [
      { id:'core_ip','name':'How the Internet Works (IP, DNS, HTTP)','tag':'Core','details':'' },
      { id:'core_osi','name':'OSI & TCP/IP Models','tag':'Core','details':'' },
      { id:'core_net','name':'Networking Basics (Ports, Protocols, Subnets)','tag':'Core','details':'' },
    ],
    resources: []
  },
  domains: [
    { id:'soc-analyst',name:'SOC Analyst',icon:'🛡️',desc:'Monitor, detect, and respond to threats',color:'#4f6ef7',roles:['SOC Analyst','Incident Responder'],phases:[] },
  ]
};

const QUIZ_QUESTIONS = {
  'networking-basics': {
    icon: '🌐', name: 'Networking Basics', desc: 'IP, DNS, ports & protocols',
    questions: [
      { q: 'What does IP stand for?', opts: ['Internet Protocol', 'Internal Process', 'Integrated Platform', 'Interface Protocol'], correct: 0 },
      { q: 'Which port does HTTP use?', opts: ['21', '80', '443', '22'], correct: 1 },
      { q: 'What is DNS used for?', opts: ['Routing packets', 'Domain name resolution', 'Encrypting data', 'Firewall rules'], correct: 1 },
      { q: 'What is a subnet mask?', opts: ['A network boundary identifier', 'A type of firewall', 'A routing protocol', 'An encryption key'], correct: 0 },
      { q: 'What is the OSI model?', opts: ['A networking reference model', 'A programming language', 'An operating system', 'A security standard'], correct: 0 },
    ]
  },
  'linux-basics': {
    icon: '🐧', name: 'Linux Basics', desc: 'Commands, filesystem, permissions',
    questions: [
      { q: 'What command lists files?', opts: ['dir', 'ls', 'list', 'show'], correct: 1 },
      { q: 'What does chmod 755 do?', opts: ['Changes ownership', 'Changes permissions', 'Deletes a file', 'Renames a file'], correct: 1 },
      { q: 'Which dir has system binaries?', opts: ['/home', '/etc', '/usr/bin', '/var'], correct: 2 },
      { q: 'How to view running processes?', opts: ['ps', 'ls', 'cat', 'echo'], correct: 0 },
      { q: 'What is the root user?', opts: ['A regular user', 'The superuser admin', 'A system service', 'A network daemon'], correct: 1 },
    ]
  },
  'cybersecurity-fundamentals': {
    icon: '🔐', name: 'Cyber Security Basics', desc: 'CIA triad, threats, defenses',
    questions: [
      { q: 'What does CIA stand for?', opts: ['Confidentiality Integrity Availability', 'Code Identity Access', 'Central Intelligence Agency', 'Control Integration Auth'], correct: 0 },
      { q: 'What is phishing?', opts: ['A network scan', 'A social engineering attack', 'Password brute force', 'A DDoS attack'], correct: 1 },
      { q: 'What is a firewall?', opts: ['A network security filter', 'A type of virus', 'A programming tool', 'A database'], correct: 0 },
      { q: 'What is encryption?', opts: ['Encoding data to hide it', 'Deleting data', 'Copying data', 'Indexing data'], correct: 0 },
      { q: 'What is MFA?', opts: ['Multiple passwords', '2+ verification factors', 'One password', 'Biometrics only'], correct: 1 },
    ]
  },
  'ethical-hacking': {
    icon: '🛡️', name: 'Ethical Hacking', desc: 'Pentesting methodology',
    questions: [
      { q: 'What is a pentest?', opts: ['A security assessment', 'A software update', 'A network diagram', 'A backup'], correct: 0 },
      { q: 'Which tool for network scanning?', opts: ['Photoshop', 'Nmap', 'Excel', 'Word'], correct: 1 },
      { q: 'What is a vulnerability?', opts: ['A security weakness', 'A strong password', 'A firewall rule', 'An encryption key'], correct: 0 },
      { q: 'First phase of pentesting?', opts: ['Exploitation', 'Reconnaissance', 'Reporting', 'Escalation'], correct: 1 },
      { q: 'What is a zero-day?', opts: ['A known patched bug', 'An unknown unpatched vuln', 'A firewall type', 'A daily backup'], correct: 1 },
    ]
  },
  'web-security': {
    icon: '🌍', name: 'Web Security', desc: 'OWASP Top 10, SQLi, XSS',
    questions: [
      { q: 'What is SQL Injection?', opts: ['Injecting SQL into queries', 'A database backup', 'A type of firewall', 'A programming language'], correct: 0 },
      { q: 'What does XSS stand for?', opts: ['Cross-Site Scripting', 'XML Security Standard', 'Extended Security', 'Cross-Site Scanning'], correct: 0 },
      { q: 'What is CSRF?', opts: ['Cross-Site Request Forgery', 'A secure protocol', 'A firewall type', 'An encryption method'], correct: 0 },
      { q: 'What is OWASP?', opts: ['Open Web Application Security Project', 'A framework', 'An OS', 'A protocol'], correct: 0 },
      { q: 'How to prevent SQLi?', opts: ['Parameterized queries', 'Disable JavaScript', 'Use GET requests', 'Weak passwords'], correct: 0 },
    ]
  },
};

const BADGES = [
  { id:'first-topic',icon:'⭐',name:'First Step',desc:'Complete your first topic',check:s => { const c = getAllCompleted(); return c.length >= 1; } },
  { id:'domain-started',icon:'🚀',name:'Path Starter',desc:'Start a domain path',check:s => !!s.selectedDomain },
  { id:'domain-done',icon:'🏆',name:'Domain Complete',desc:'Complete all topics in a domain',check:s => { if(!s.selectedDomain || !mentorData) return false; const d = getSelectedDomain(); if(!d) return false; const all = d.phases.flatMap(p=>p.topics).map(t=>t.id); const done = all.filter(id=>s.domainCompleted[id]); return all.length>0 && done.length>=all.length; } },
  { id:'core-done',icon:'📚',name:'Core Complete',desc:'Complete all core topics',check:s => { if(!mentorData) return false; const core = mentorData.shared_core.topics.map(t=>t.id); const done = core.filter(id=>s.sharedCompleted[id]); return core.length>0 && done.length>=core.length; } },
  { id:'quiz-first',icon:'🎯',name:'Quiz Rookie',desc:'Complete your first quiz',check:s => s.quizScore !== undefined },
  { id:'quiz-perfect',icon:'💯',name:'Perfect Score',desc:'Score 100% on any quiz',check:s => s.quizPerfect !== undefined },
  { id:'streak-3',icon:'🔥',name:'On Fire',desc:'3 days in a row',check:s => (s.streak||0) >= 3 },
  { id:'terminal',icon:'💻',name:'Terminal Ace',desc:'Use terminal 10 times',check:s => (s.terminalCmds||0) >= 10 },
];

const TERMINAL_COMMANDS = {
  help:{desc:'Show commands',run:()=>Object.entries(TERMINAL_COMMANDS).map(([k,v])=>`  ${k.padEnd(12)} ${v.desc}`).join('\n')},
  ls:{desc:'List directory',run:()=>'Desktop  Documents  Downloads  projects\nnotes.txt  .bashrc'},
  pwd:{desc:'Print working dir',run:()=>'/home/mentor/cyberguru'},
  whoami:{desc:'Show user',run:()=>'mentor'},
  ifconfig:{desc:'Network interfaces',run:()=>'eth0: flags=4163<UP,BROADCAST,RUNNING>  mtu 1500\n  inet 10.0.0.42  netmask 255.255.255.0\nlo: flags=73<UP,LOOPBACK>  mtu 65536\n  inet 127.0.0.1'},
  ping:{desc:'Ping host (ping <host>)',run:args=>{if(!args.length)return 'usage: ping <host>';return `PING ${args[0]} 56 bytes.\n64 bytes from ${args[0]}: icmp_seq=1 ttl=64 time=12.3ms\n--- stats ---\n3 transmitted, 3 received, 0% loss`;}},
  nmap:{desc:'Scan ports (nmap <target>)',run:args=>{if(!args.length)return 'usage: nmap <target>';return `Starting Nmap 7.94\nHost: ${args[0]}\n22/tcp open ssh\n80/tcp open http\n443/tcp open https`;}},
  netstat:{desc:'Show connections',run:()=>'Proto Local Address          State\ntcp   0.0.0.0:22             LISTEN\ntcp   10.0.0.42:22            ESTABLISHED'},
  cat:{desc:'Show file (cat <file>)',run:args=>{if(!args.length)return 'usage: cat <file>';const f={'notes.txt':'# Cyber Security Notes\n- Use HTTPS\n- Enable 2FA','flag.txt':'CTF{cyb3r_m3nt0r}'};return f[args[0]]||`cat: ${args[0]}: No such file`;}},
  echo:{desc:'Print text',run:args=>args.join(' ')||''},
  clear:{desc:'Clear screen',run:()=>null},
  date:{desc:'Show date/time',run:()=>new Date().toString()},
  uname:{desc:'System info',run:()=>'Linux cyberguru-mentor 6.2.0 x86_64 GNU/Linux'},
};

// ── State ──
let mentorData = null;
let mentorState = {
  selectedDomain: null,
  sharedCompleted: {},
  domainCompleted: {},
  chatHistory: [],
  mentorChats: {},
  activeMentorChatId: null,
  streak: 0,
  quizScore: undefined,
  quizPerfect: undefined,
  terminalCmds: 0,
  learningActivity: {},
};
let quizState = { topic: null, questions: [], current: 0, score: 0, answered: false };
let _pendingSwitchDomain = null;

// ══ ACTIVITY TRACKING ══
function trackActivity(type) {
  const today = new Date().toISOString().slice(0, 10);
  if (!mentorState.learningActivity) mentorState.learningActivity = {};
  if (!mentorState.learningActivity[today]) mentorState.learningActivity[today] = {};
  if (!mentorState.learningActivity[today][type]) mentorState.learningActivity[today][type] = 0;
  mentorState.learningActivity[today][type]++;
  mentorSave();
}
function getActivityTotal(dateStr) {
  const day = mentorState.learningActivity?.[dateStr];
  if (!day) return 0;
  return Object.values(day).reduce((a, b) => a + b, 0);
}
function getActivityLevel(dateStr) {
  const total = getActivityTotal(dateStr);
  if (total === 0) return 0;
  if (total <= 2) return 1;
  if (total <= 5) return 2;
  if (total <= 10) return 3;
  return 4;
}

function mentorSave() {
  if (mentorState.activeMentorChatId && mentorState.mentorChats[mentorState.activeMentorChatId]) {
    mentorState.mentorChats[mentorState.activeMentorChatId].msgs = mentorState.chatHistory;
  }
  localStorage.setItem(MENTOR_KEY, JSON.stringify(mentorState));
}
function mentorLoad() {
  try {
    const raw = localStorage.getItem(MENTOR_KEY);
    if (raw) {
      const p = JSON.parse(raw);
      mentorState.selectedDomain = p.selectedDomain || null;
      mentorState.sharedCompleted = p.sharedCompleted || {};
      mentorState.domainCompleted = p.domainCompleted || {};
      mentorState.streak = p.streak || 0;
      mentorState.quizScore = p.quizScore;
      mentorState.quizPerfect = p.quizPerfect;
      mentorState.terminalCmds = p.terminalCmds || 0;
      mentorState.learningActivity = p.learningActivity || {};

      // Migrate old single chatHistory → session
      if (p.chatHistory && p.chatHistory.length > 0 && (!p.mentorChats || Object.keys(p.mentorChats).length === 0)) {
        const id = 'mchat_' + Date.now();
        mentorState.mentorChats = { [id]: { title: 'Previous Chat', msgs: p.chatHistory, createdAt: Date.now() } };
        mentorState.activeMentorChatId = id;
        mentorState.chatHistory = p.chatHistory;
      } else {
        mentorState.mentorChats = p.mentorChats || {};
        // Migrate: ensure every chat has createdAt and upgrade old titles
        for (const cId of Object.keys(mentorState.mentorChats)) {
          const c = mentorState.mentorChats[cId];
          if (!c.createdAt) c.createdAt = Date.now();
          if (c.title === 'Previous conversation') c.title = 'Previous Chat';
          if (c.title === 'New conversation') c.title = 'New Chat';
        }
        mentorState.activeMentorChatId = p.activeMentorChatId || null;
      }

      // Sync chatHistory from active session
      if (mentorState.activeMentorChatId && mentorState.mentorChats[mentorState.activeMentorChatId]) {
        mentorState.chatHistory = mentorState.mentorChats[mentorState.activeMentorChatId].msgs;
      } else if (!mentorState.chatHistory || mentorState.chatHistory.length === 0) {
        mentorState.chatHistory = [];
      }
    }
  } catch (_) {}
}

async function loadRoadmap() {
  try {
    const res = await fetch('/static/data/roadmap.json');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    mentorData = data;
  } catch (e) {
    console.warn('Roadmap JSON failed, using fallback:', e);
    mentorData = FALLBACK_DATA;
  }
}

function getSelectedDomain() {
  if (!mentorData || !mentorState.selectedDomain) return null;
  return mentorData.domains.find(d => d.id === mentorState.selectedDomain);
}

function getAllCompleted() {
  const shared = Object.keys(mentorState.sharedCompleted);
  const domain = Object.keys(mentorState.domainCompleted);
  return [...shared, ...domain];
}

function computeProgress() {
  if (!mentorData) return { done: 0, total: 0, pct: 0, allTopics: [] };
  const coreTopics = mentorData.shared_core.topics.map(t => ({ id: t.id, source:'core' }));
  const domain = getSelectedDomain();
  const domainTopics = domain ? domain.phases.flatMap(p => p.topics).map(t => ({ id: t.id, source:'domain' })) : [];
  const allTopics = [...coreTopics, ...domainTopics];
  const done = allTopics.filter(t => {
    if (t.source === 'core') return mentorState.sharedCompleted[t.id];
    return mentorState.domainCompleted[t.id];
  }).length;
  const total = allTopics.length;
  return { done, total, pct: total ? Math.round((done / total) * 100) : 0, allTopics };
}

function getEarnedBadges() {
  return BADGES.filter(b => b.check(mentorState)).map(b => b.id);
}

async function openMentorOverlay() {
  mentorLoad();
  if (!mentorData) await loadRoadmap();
  document.getElementById('mentor-overlay').classList.add('show');
  document.body.style.overflow = 'hidden';
  initLanding();
  if (typeof loadChatSuggestions === 'function') loadChatSuggestions('mentor');
}

function closeMentorOverlay() {
  document.getElementById('mentor-overlay').classList.remove('show');
  document.body.style.overflow = '';
  if (_mlAnimId) { cancelAnimationFrame(_mlAnimId); _mlAnimId = null; }
  if (typeof loadChatSuggestions === 'function') loadChatSuggestions('chat');
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const o = document.getElementById('mentor-overlay');
    if (o && o.classList.contains('show')) closeMentorOverlay();
  }
});

// ══ LANDING PAGE ══

const ML_DOMAIN_COLORS = {
  'soc-analyst': '#4f6ef7', 'penetration-tester': '#e74c3c', 'ethical-hacker': '#e74c3c',
  'grc-analyst': '#00e5ff', 'cloud-security-engineer': '#ff9800',
  'dfir-analyst': '#00ff88', 'network-security-engineer': '#ab47bc',
  'ai-cybersecurity': '#f06292',
};
const ML_DOMAIN_ICONS = {
  'soc-analyst': '🛡️', 'penetration-tester': '💉', 'ethical-hacker': '🐱‍💻',
  'grc-analyst': '📋', 'cloud-security-engineer': '☁️',
  'dfir-analyst': '🔍', 'network-security-engineer': '🌐',
  'ai-cybersecurity': '🤖',
};

let _mlAnimId = null;

function dismissLanding(tab) {
  const landing = document.getElementById('mentor-landing');
  if (!landing) return;
  landing.classList.add('ml-hidden');
  if (_mlAnimId) { cancelAnimationFrame(_mlAnimId); _mlAnimId = null; }
  document.querySelector('.mentor-topbar').style.display = 'flex';
  document.querySelector('.mentor-body').style.display = 'flex';
  switchMentorTab(tab || 'dashboard');
}

function handleLandingAction(action, el) {
  if (action === 'roadmap') {
    dismissLanding('roadmap');
    return;
  }
  if (action === 'domain') {
    const domainId = el.dataset.domainId;
    if (!domainId) return;
    dismissLanding('roadmap');
    setTimeout(function () {
      mentorState.selectedDomain = domainId;
      mentorSave();
      renderRoadmap();
    }, 50);
    return;
  }
  dismissLanding();
}

document.addEventListener('click', function (e) {
  const el = e.target.closest('[data-landing-action]');
  if (!el) return;
  e.preventDefault();
  handleLandingAction(el.dataset.landingAction, el);
});

function initLanding() {
  document.querySelector('.mentor-topbar').style.display = 'none';
  document.querySelector('.mentor-body').style.display = 'none';
  const landing = document.getElementById('mentor-landing');
  if (!landing) return;
  landing.classList.remove('ml-hidden');
  setupLandingCanvas();
  renderLandingPaths();
  renderLandingTimeline();
  renderLandingBadges();
  updateContinueCard();
}

function setupLandingCanvas() {
  const canvas = document.getElementById('ml-bg-canvas');
  if (!canvas) return;
  if (_mlAnimId) { cancelAnimationFrame(_mlAnimId); _mlAnimId = null; }
  const ctx = canvas.getContext('2d');
  let w, h, nodes = [], packets = [];
  const NODE_COUNT = 28;
  const PACKET_COUNT = 5;

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    w = canvas.width = rect.width;
    h = canvas.height = rect.height;
  }
  resize();
  window.addEventListener('resize', resize);

  // Create nodes
  nodes = [];
  for (let i = 0; i < NODE_COUNT; i++) {
    nodes.push({
      x: Math.random() * w, y: Math.random() * h,
      r: 1.5 + Math.random() * 2.5,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
    });
  }

  // Create packets
  packets = [];
  for (let i = 0; i < PACKET_COUNT; i++) {
    const src = nodes[Math.floor(Math.random() * nodes.length)];
    let dst;
    do { dst = nodes[Math.floor(Math.random() * nodes.length)]; } while (dst === src);
    packets.push({
      src, dst, t: Math.random(),
      speed: 0.002 + Math.random() * 0.004,
      size: 1.5 + Math.random() * 1,
    });
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);

    // Update nodes
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > w) n.vx *= -1;
      if (n.y < 0 || n.y > h) n.vy *= -1;
    }

    // Draw connections (lines between nearby nodes)
    ctx.strokeStyle = 'rgba(79,110,247,0.08)';
    ctx.lineWidth = 0.5;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 150) {
          ctx.globalAlpha = 1 - dist / 150;
          ctx.beginPath(); ctx.moveTo(nodes[i].x, nodes[i].y); ctx.lineTo(nodes[j].x, nodes[j].y); ctx.stroke();
        }
      }
    }
    ctx.globalAlpha = 1;

    // Draw nodes
    for (const n of nodes) {
      const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 2);
      grad.addColorStop(0, 'rgba(79,110,247,0.25)');
      grad.addColorStop(1, 'rgba(79,110,247,0)');
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r * 2, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = 'rgba(79,110,247,0.3)';
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill();
    }

    // Update and draw packets
    for (const p of packets) {
      p.t += p.speed;
      if (p.t >= 1) { p.t = 0;
        const src = nodes[Math.floor(Math.random() * nodes.length)];
        let dst;
        do { dst = nodes[Math.floor(Math.random() * nodes.length)]; } while (dst === src);
        p.src = src; p.dst = dst;
      }
      const x = p.src.x + (p.dst.x - p.src.x) * p.t;
      const y = p.src.y + (p.dst.y - p.src.y) * p.t;
      const grad = ctx.createRadialGradient(x, y, 0, x, y, p.size * 4);
      grad.addColorStop(0, 'rgba(0,229,255,0.6)');
      grad.addColorStop(1, 'rgba(0,229,255,0)');
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.arc(x, y, p.size * 4, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = 'rgba(0,229,255,0.8)';
      ctx.beginPath(); ctx.arc(x, y, p.size, 0, Math.PI * 2); ctx.fill();
    }

    _mlAnimId = requestAnimationFrame(draw);
  }
  draw();
}

function renderLandingPaths() {
  const grid = document.getElementById('ml-paths-grid');
  if (!grid || !mentorData) return;
  let html = '';
  for (const d of mentorData.domains) {
    const color = ML_DOMAIN_COLORS[d.id] || '#4f6ef7';
    const icon = ML_DOMAIN_ICONS[d.id] || '📘';
    const allTopics = d.phases.flatMap(p => p.topics);
    const total = allTopics.length;
    const done = allTopics.filter(t => mentorState.domainCompleted[t.id]).length;
    const pct = total ? Math.round(done / total * 100) : 0;
    html += `<div class="ml-path-card" style="--path-color:${color}" data-landing-action="domain" data-domain-id="${d.id}">
      <div class="ml-path-header">
        <span class="ml-path-icon">${icon}</span>
        <span class="ml-path-name">${escapeHtml(d.name)}</span>
      </div>
      <div class="ml-path-desc">${escapeHtml(d.desc || '')}</div>
      <div class="ml-path-bar-wrap"><div class="ml-path-bar-fill" style="width:${pct}%"></div></div>
      <div class="ml-path-pct">${done}/${total} topics (${pct}%)</div>
      <span class="ml-path-tag">${d.roles ? d.roles.join(', ') : ''}</span>
    </div>`;
  }
  grid.innerHTML = html;
}

function renderLandingTimeline() {
  const el = document.getElementById('ml-timeline');
  if (!el) return;
  const phases = [
    { phase: 'Foundation', topics: 'Networking, OSI Model, Linux, Windows', icon: '📚' },
    { phase: 'Core Concepts', topics: 'Security Fundamentals, Cryptography, IAM', icon: '🔐' },
    { phase: 'Domain Specialization', topics: 'SOC, Pentest, Cloud, GRC, DFIR, Network, AI', icon: '🎯' },
    { phase: 'Advanced Practice', topics: 'Hands-on labs, Quizzes, Real-world scenarios', icon: '⚡' },
    { phase: 'Mastery', topics: 'Certification prep, Expert-level challenges', icon: '🏆' },
  ];
  let html = '';
  for (let i = 0; i < phases.length; i++) {
    const isActive = i <= 1;
    html += `<div class="ml-timeline-item">
      <div class="ml-timeline-dot${isActive ? ' active-dot' : ''}">${phases[i].icon}</div>
      <div class="ml-timeline-phase">${phases[i].phase}</div>
      <div class="ml-timeline-topics">${phases[i].topics}</div>
    </div>`;
  }
  el.innerHTML = html;
}

function renderLandingBadges() {
  const el = document.getElementById('ml-badges-grid');
  if (!el) return;
  const preview = BADGES.slice(0, 8);
  const earned = getEarnedBadges();
  let html = '';
  for (const b of preview) {
    const isEarned = earned.includes(b.id);
    html += `<div class="ml-badge-card${isEarned ? ' ml-badge-earned' : ''}">
      <span class="ml-badge-icon">${b.icon || '🏅'}</span>
      ${escapeHtml(b.name)}
    </div>`;
  }
  el.innerHTML = html;
}

function updateContinueCard() {
  const section = document.getElementById('ml-continue-section');
  if (!section || !mentorState.selectedDomain) { section.style.display = 'none'; return; }
  const domain = getSelectedDomain();
  if (!domain) { section.style.display = 'none'; return; }
  const allTopics = domain.phases.flatMap(p => p.topics);
  const total = allTopics.length;
  if (total === 0) { section.style.display = 'none'; return; }
  const done = allTopics.filter(t => mentorState.domainCompleted[t.id]).length;
  const pct = Math.round(done / total * 100);
  const icon = ML_DOMAIN_ICONS[domain.id] || '📘';
  document.getElementById('ml-continue-icon').textContent = icon;
  document.getElementById('ml-continue-greeting').textContent = done > 0 ? 'Welcome Back, Learner!' : 'Ready to Start Learning?';
  document.getElementById('ml-continue-track').textContent = domain.name;
  // Find current incomplete topic
  let currentTopic = '—';
  for (const t of allTopics) {
    if (!mentorState.domainCompleted[t.id]) { currentTopic = t.name; break; }
  }
  document.getElementById('ml-continue-lesson').textContent = done > 0 ? currentTopic : 'Start your first lesson';
  document.getElementById('ml-continue-bar-fill').style.width = pct + '%';
  document.getElementById('ml-continue-pct').textContent = pct + '% complete';
  section.style.display = 'block';
}

// ── Tab switching ──
function _initMentorChatView() {
  const ids = Object.keys(mentorState.mentorChats);
  if (ids.length === 0) {
    createNewConversation();
    return;
  }
  if (!mentorState.activeMentorChatId || !mentorState.mentorChats[mentorState.activeMentorChatId]) {
    switchMentorChat(ids[ids.length - 1]);
    return;
  }
  const msgs = document.getElementById('mentor-chat-msgs');
  if (msgs && mentorState.chatHistory.length > 0) {
    msgs.innerHTML = '';
    mentorState.chatHistory.forEach(m => appendMentorMessage(m.role, m.text));
  }
  renderMentorHistoryList();
}

function switchMentorTab(tabId) {
  document.querySelectorAll('.mentor-nav-item').forEach(t => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  document.querySelectorAll('.mentor-panel').forEach(p => p.classList.remove('active'));
  const tab = document.getElementById('tab-' + tabId);
  const panel = document.getElementById('panel-' + tabId);
  if (tab) { tab.classList.add('active'); tab.setAttribute('aria-selected', 'true'); }
  if (panel) panel.classList.add('active');
  if (tabId === 'dashboard') renderDashboard();
  if (tabId === 'roadmap') renderRoadmap();
  if (tabId === 'quiz') renderQuizTopics();
  if (tabId === 'badges') renderBadges();
  if (tabId === 'terminal') setTimeout(() => { const i = document.getElementById('mterm-input'); if (i) i.focus(); }, 100);
  if (tabId === 'chat') {
    _initMentorChatView();
    setTimeout(() => scrollMentorChat(), 50);
  }
  updateTopbarStats();
}

function updateTopbarStats() {
  const prog = computeProgress();
  const badges = getEarnedBadges();
  document.getElementById('mts-dashboard-done').textContent = prog.done;
  document.getElementById('mts-dashboard-streak').textContent = mentorState.streak || 0;
  document.getElementById('mts-dashboard-score').textContent = mentorState.quizScore !== undefined ? mentorState.quizScore + '/5' : '--';
}

// ══ DASHBOARD ══
function renderDashboard() {
  const prog = computeProgress();
  const badges = getEarnedBadges();
  const nextBadge = BADGES.find(b => !badges.includes(b.id));
  document.getElementById('mdash-progress-pct').textContent = prog.pct + '%';
  document.getElementById('mdash-progress-fill').style.width = prog.pct + '%';
  document.getElementById('mdash-topics-done').textContent = prog.done;
  document.getElementById('mdash-topics-total').textContent = prog.total;
  document.getElementById('mdash-streak').textContent = mentorState.streak || 0;
  document.getElementById('mdash-badges').textContent = badges.length;
  document.getElementById('mdash-badges-next').textContent = nextBadge ? nextBadge.name : 'All badges earned!';
  updateTopbarStats();
  renderActivityChart();
  renderHeatmap();
  renderDomainBars();
}

// ── Activity Chart ──
function renderActivityChart() {
  const svg = document.getElementById('mdash-chart-svg');
  const tooltip = document.getElementById('mdash-chart-tooltip');
  const legend = document.getElementById('mdash-chart-legend');
  if (!svg) return;
  const W = 400, H = 160;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  // Build 4 weeks of daily data
  const days = [];
  const today = new Date();
  for (let i = 27; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    days.push({ date: key, total: getActivityTotal(key) });
  }
  // Aggregate into 4 weeks
  const weeks = [];
  for (let w = 0; w < 4; w++) {
    let sum = 0;
    for (let d = w * 7; d < (w + 1) * 7 && d < days.length; d++) {
      sum += days[d].total;
    }
    weeks.push(sum);
  }
  const maxVal = Math.max(...weeks, 1);
  const pad = { top: 12, bottom: 20, left: 28, right: 10 };
  const cw = W - pad.left - pad.right;
  const ch = H - pad.top - pad.bottom;

  // Grid lines
  let gridHtml = '';
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + ch - (ch * i) / 4;
    const val = Math.round((maxVal * i) / 4);
    gridHtml += `<line x1="${pad.left}" y1="${y}" x2="${W - pad.right}" y2="${y}" stroke="rgba(255,255,255,.04)" stroke-width="1"/>`;
    gridHtml += `<text x="${pad.left - 6}" y="${y + 3}" fill="var(--text-muted)" font-size="7" text-anchor="end">${val}</text>`;
  }

  // Area path
  const stepX = cw / (weeks.length - 1 || 1);
  let pathD = `M ${pad.left} ${pad.top + ch} L ${pad.left} ${pad.top + ch - (weeks[0] / maxVal) * ch}`;
  for (let i = 1; i < weeks.length; i++) {
    const x = pad.left + i * stepX;
    const y = pad.top + ch - (weeks[i] / maxVal) * ch;
    pathD += ` L ${x} ${y}`;
  }
  pathD += ` L ${pad.left + (weeks.length - 1) * stepX} ${pad.top + ch} Z`;

  const linePts = [];
  for (let i = 0; i < weeks.length; i++) {
    const x = pad.left + i * stepX;
    const y = pad.top + ch - (weeks[i] / maxVal) * ch;
    linePts.push(`${x},${y}`);
  }

  // Labels
  const labels = ['4 weeks ago', '3 weeks ago', '2 weeks ago', 'Last week', 'This week'].slice(-weeks.length);

  svg.innerHTML = gridHtml + `
    <defs>
      <linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#8B5CF6" stop-opacity=".35"/>
        <stop offset="100%" stop-color="#8B5CF6" stop-opacity=".02"/>
      </linearGradient>
    </defs>
    <path d="${pathD}" fill="url(#chartGrad)" opacity="0.8"/>
    <polyline points="${linePts.join(' ')}" fill="none" stroke="#8B5CF6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    ${weeks.map((v, i) => {
      const x = pad.left + i * stepX;
      const y = pad.top + ch - (v / maxVal) * ch;
      return `<circle cx="${x}" cy="${y}" r="3" fill="#8B5CF6" stroke="#0d1117" stroke-width="1.2" class="mdash-chart-dot" data-week="${i}" data-val="${v}" style="cursor:pointer"/>`;
    }).join('')}
    ${labels.map((l, i) => {
      const x = pad.left + i * stepX;
      return `<text x="${x}" y="${H - 3}" fill="var(--text-muted)" font-size="6.5" text-anchor="middle">${l}</text>`;
    }).join('')}
  `;

  // Legend
  legend.innerHTML = weeks.map((v, i) =>
    `<span class="mdash-legend-item"><span class="mdash-legend-dot" style="background:#8B5CF6"></span>Week ${i+1}: <strong>${v}</strong> activities</span>`
  ).join('');

  // Hover tooltips
  svg.querySelectorAll('.mdash-chart-dot').forEach(dot => {
    dot.addEventListener('mouseenter', () => {
      const week = parseInt(dot.dataset.week);
      const val = parseInt(dot.dataset.val);
      const label = labels[week] || `Week ${week + 1}`;
      tooltip.textContent = `${label}: ${val} activities`;
      tooltip.style.display = 'block';
      const rect = dot.getBoundingClientRect();
      const parent = document.getElementById('activity-chart-card').getBoundingClientRect();
      tooltip.style.left = (rect.left - parent.left - 40) + 'px';
      tooltip.style.top = (rect.top - parent.top - 28) + 'px';
    });
    dot.addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });
  });
}

// ── Heatmap ──
function renderHeatmap() {
  const wrap = document.getElementById('mdash-heatmap-wrap');
  const legend = document.getElementById('mdash-heatmap-legend');
  if (!wrap) return;
  const today = new Date();
  const days = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const total = getActivityTotal(key);
    const level = getActivityLevel(key);
    const dayName = d.toLocaleDateString('en', { weekday: 'short' });
    const dateStr = d.toLocaleDateString('en', { month: 'short', day: 'numeric' });
    days.push({ date: key, total, level, dayName, label: dateStr });
  }
  const levels = ['#161b22', '#0e4429', '#006d32', '#26a641', '#39d353'];
  wrap.innerHTML = `<div class="mdash-heatmap-grid">${days.map((d, i) => `
    <div class="mdash-heatmap-cell" data-level="${d.level}" data-date="${d.date}" data-total="${d.total}" data-label="${d.label}"
         style="background:${levels[d.level]}; width:14px; height:14px; border-radius:3px; cursor:pointer"
         title="${d.label} — ${d.total} activity${d.total !== 1 ? 's' : ''}"></div>
  `).join('')}</div>`;
  // Tooltip via title attr already set above
  // Legend
  legend.innerHTML = `
    <span style="font-size:10px;color:var(--text-muted);margin-right:4px">Less</span>
    ${levels.map((c, i) => `<span style="display:inline-block;width:12px;height:12px;border-radius:2px;background:${c};margin:0 1px" title="Level ${i}"></span>`).join('')}
    <span style="font-size:10px;color:var(--text-muted);margin-left:4px">More</span>
  `;
}

// ── Domain Bars ──
function renderDomainBars() {
  const bars = document.getElementById('mdash-domains-bars');
  if (!bars || !mentorData) return;
  const domains = mentorData.domains.map(d => {
    const total = d.phases.reduce((s, p) => s + p.topics.length, 0);
    const done = d.phases.reduce((s, p) => s + p.topics.filter(t => mentorState.domainCompleted[t.id]).length, 0);
    return { name: d.name, icon: d.icon, pct: total ? Math.round((done / total) * 100) : 0, color: d.color || '#8B5CF6' };
  }).sort((a, b) => b.pct - a.pct);
  bars.innerHTML = domains.map(d => `
    <div class="mdash-domain-bar-row">
      <span class="mdash-domain-bar-label">${d.icon} <span>${d.name}</span></span>
      <div class="mdash-domain-bar-track">
        <div class="mdash-domain-bar-fill" style="width:${d.pct}%;background:${d.color}"></div>
      </div>
      <span class="mdash-domain-bar-pct">${d.pct}%</span>
    </div>
  `).join('');
}

// ══ ROADMAP ══
function renderRoadmap() {
  if (!mentorData) return;
  const selector = document.getElementById('domain-selector');
  const view = document.getElementById('domain-roadmap-view');
  if (!selector || !view) return;

  if (!mentorState.selectedDomain) {
    selector.style.display = 'block';
    view.style.display = 'none';
    renderDomainSelector();
  } else {
    selector.style.display = 'none';
    view.style.display = 'block';
    renderDomainRoadmap();
  }
}

// ── Domain Selector ──
function renderDomainSelector() {
  const grid = document.getElementById('domain-grid');
  if (!grid || !mentorData) return;
  grid.innerHTML = mentorData.domains.map(d => `
    <div class="domain-card" data-action="selectDomain" data-domain-id="${d.id}" style="--domain-color:${d.color}">
      <div class="domain-card-icon">${d.icon}</div>
      <div class="domain-card-name">${d.name}</div>
      <div class="domain-card-desc">${d.desc}</div>
      <div class="domain-card-roles">${d.roles.slice(0,2).map(r => `<span>${r}</span>`).join('')}</div>
    </div>
  `).join('');
}

function openDomainAI() {
  const w = document.getElementById('domain-ai-widget');
  if (w) w.style.display = 'block';
}

function closeDomainAI() {
  const w = document.getElementById('domain-ai-widget');
  if (w) w.style.display = 'none';
}

async function askAIRoadmap() {
  const input = document.getElementById('domain-ai-input');
  const result = document.getElementById('domain-ai-result');
  const text = input.value.trim();
  if (!text) { result.textContent = 'Please describe your background first.'; return; }
  result.innerHTML = 'Thinking...';
  const domainNames = mentorData.domains.map(d => d.name).join(', ');
  const systemMsg = `You are a cybersecurity career advisor. Based on the user's background, recommend ONE of these paths: ${domainNames}. Respond with just the path name and a brief 2-sentence explanation why.`;
  try {
    const csrfToken = getCsrfToken();
    const headers = { 'Content-Type': 'application/json' };
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    const res = await fetch('/chat', {
      method: 'POST', headers, body: JSON.stringify({ message: text, history: [{ role:'bot', text:systemMsg }], model:'gemini' }),
    });
    const data = await res.json();
    const reply = data.reply || data.text || '';
    const matched = mentorData.domains.find(d => reply.toLowerCase().includes(d.name.toLowerCase()));
    if (matched) {
      result.innerHTML = `🤖 AI recommends: <strong>${matched.name}</strong> — ${reply}<br><br><button class="domain-ai-pick" data-action="selectDomain" data-domain-id="${matched.id}">Select This Path →</button>`;
    } else {
      result.innerHTML = `🤖 ${reply}`;
    }
  } catch (e) {
    result.textContent = 'Sorry, AI recommendation failed. Please try again or pick manually.';
  }
  // Scroll the roadmap panel to bring the AI result into view
  const panel = document.getElementById('panel-roadmap');
  const resultEl = document.getElementById('domain-ai-result');
  if (panel && resultEl) {
    resultEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    resultEl.focus({ preventScroll: true });
  }
}

// ── Domain Selection ──
function selectDomain(domainId) {
  if (mentorState.selectedDomain && mentorState.selectedDomain !== domainId) {
    _pendingSwitchDomain = domainId;
    const target = mentorData.domains.find(d => d.id === domainId);
    document.getElementById('switch-modal-title').textContent = 'Change Learning Path?';
    document.getElementById('switch-modal-body').innerHTML = 'Switch to <strong>' + (target ? target.name : domainId) + '</strong>? This will reset domain-specific progress.';
    document.getElementById('switch-confirm-btn').textContent = 'Switch Path';
    document.getElementById('switch-modal').style.display = 'flex';
    return;
  }
  _applyDomain(domainId);
}

function _applyDomain(domainId) {
  mentorState.selectedDomain = domainId;
  if (!mentorState.domainCompleted) mentorState.domainCompleted = {};
  mentorSave();
  renderRoadmap();
  renderDashboard();
}

function confirmSwitchDomain() {
  if (_pendingSwitchDomain === '__clear__') {
    mentorState.domainCompleted = {};
    mentorState.selectedDomain = null;
    mentorSave();
    renderRoadmap();
    renderDashboard();
  } else if (_pendingSwitchDomain) {
    mentorState.domainCompleted = {};
    _applyDomain(_pendingSwitchDomain);
  }
  _pendingSwitchDomain = null;
  document.getElementById('switch-modal').style.display = 'none';
}

function cancelSwitchDomain() {
  _pendingSwitchDomain = null;
  document.getElementById('switch-modal').style.display = 'none';
}

// ── Domain Roadmap View ──
function renderDomainRoadmap() {
  const domain = getSelectedDomain();
  if (!domain) { mentorState.selectedDomain = null; renderRoadmap(); return; }

  document.getElementById('domain-header-icon').textContent = domain.icon;
  document.getElementById('domain-header-name').textContent = domain.name;
  document.getElementById('domain-header-desc').textContent = domain.desc;

  renderCoreSection();
  renderDomainPhases(domain);
}

function renderCoreSection() {
  if (!mentorData) return;
  const core = mentorData.shared_core;
  const total = core.topics.length;
  const done = core.topics.filter(t => mentorState.sharedCompleted[t.id]).length;
  document.getElementById('domain-core-count').textContent = `${done}/${total}`;
  const body = document.getElementById('domain-core-body');
  body.innerHTML = core.topics.map(t => {
    const d = !!mentorState.sharedCompleted[t.id];
    return `<label class="roadmap-topic ${d?'done':''}">
      <input type="checkbox" ${d?'checked':''} data-change="toggleSharedTopic" data-topic-id="${t.id}">
      <span class="roadmap-topic-name">${t.name}</span>
      <span class="roadmap-topic-tag">${t.tag}</span>
      ${(t.badges||[]).map(b => `<span class="roadmap-topic-badge">${b}</span>`).join('')}
      <button class="roadmap-topic-detail-toggle" data-action="toggleTopicDetails" data-topic-id="${t.id}" aria-expanded="false">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 9l-7 7-7-7"/></svg>
      </button>
      <div class="roadmap-topic-details" id="topic-details-${t.id}" style="display:none">${t.details||'<p><em>No content yet.</em></p>'}</div>
    </label>`;
  }).join('');
}

function toggleCoreSection() {
  const body = document.getElementById('domain-core-body');
  const chevron = document.querySelector('.domain-core-toggle .domain-chevron');
  if (!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  if (chevron) chevron.style.transform = open ? '' : 'rotate(180deg)';
}

function renderDomainPhases(domain) {
  const container = document.getElementById('roadmap-phases');
  if (!container) return;

  function phasePercent(phase) {
    const d = phase.topics.filter(t => mentorState.domainCompleted[t.id]).length;
    return d / phase.topics.length;
  }

  let html = '';
  domain.phases.forEach((phase, idx) => {
    const phaseDone = phase.topics.filter(t => mentorState.domainCompleted[t.id]).length;
    const phaseTotal = phase.topics.length;

    let isUnlocked = idx === 0;
    if (idx > 0) {
      const prevPct = phasePercent(domain.phases[idx - 1]);
      isUnlocked = prevPct >= 0.5;
    }
    const isComplete = phaseDone === phaseTotal;
    const inProgress = phaseDone > 0 && !isComplete;

    let dotClass = 'locked';
    if (isComplete) dotClass = 'completed';
    else if (inProgress) dotClass = 'in-progress';
    else if (isUnlocked) dotClass = 'unlocked';

    let badgeClass = 'locked-badge', badgeLabel = 'Locked';
    if (isComplete) { badgeClass = 'green'; badgeLabel = 'Completed'; }
    else if (inProgress) { badgeClass = 'amber'; badgeLabel = 'In Progress'; }
    else if (isUnlocked) { badgeClass = ''; badgeLabel = 'Start'; }

    let dotIcon = '🔒';
    if (isComplete) dotIcon = '✓';
    else if (inProgress) dotIcon = '▶';
    else if (isUnlocked) dotIcon = idx + 1;

    const lineClass = isComplete ? 'done' : '';
    const isOpen = (inProgress || (isUnlocked && phaseDone === 0 && idx === _firstUnlockedIdx(domain))) ? ' open active-phase' : '';

    html += `
      <div class="roadmap-phase">
        <div class="roadmap-spine">
          <div class="roadmap-dot ${dotClass}" data-action="toggleRoadmapCard" data-phase-id="${phase.id}">${dotIcon}</div>
          ${idx < domain.phases.length - 1 ? `<div class="roadmap-line ${lineClass}"></div>` : ''}
        </div>
        <div class="roadmap-card${isOpen}" id="roadmap-card-${phase.id}">
          <div class="roadmap-card-header" data-action="toggleRoadmapCard" data-phase-id="${phase.id}">
            <span class="roadmap-phase-badge ${badgeClass}">${badgeLabel}</span>
            <span class="roadmap-phase-title">${phase.phase} — ${phase.title}</span>
            <span class="roadmap-progress-mini">${phaseDone}/${phaseTotal}</span>
            <svg class="roadmap-chevron" width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M19 9l-7 7-7-7"/></svg>
          </div>
          <div class="roadmap-card-body">
            <div class="roadmap-topics">
              ${phase.topics.map(t => {
                const done = !!mentorState.domainCompleted[t.id];
                const disabled = (!isUnlocked && !isComplete) ? 'style="opacity:.45;pointer-events:none"' : '';
                return `<label class="roadmap-topic ${done?'done':''}" ${disabled}>
                  <input type="checkbox" ${done?'checked':''} data-change="toggleDomainTopic" data-topic-id="${t.id}">
                  <span class="roadmap-topic-name">${t.name}</span>
                  <span class="roadmap-topic-tag">${t.tag}</span>
                  ${(t.badges||[]).map(b => `<span class="roadmap-topic-badge">${b}</span>`).join('')}
                  <button class="roadmap-topic-detail-toggle" data-action="toggleTopicDetails" data-topic-id="${t.id}" aria-expanded="false">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 9l-7 7-7-7"/></svg>
                  </button>
                  <div class="roadmap-topic-details" id="topic-details-${t.id}" style="display:none">${t.details||'<p><em>No content yet.</em></p>'}</div>
                </label>`;
              }).join('')}
            </div>
            <div class="roadmap-resources">
              ${(phase.resources||[]).map(r => `
                <a class="resource-link ${r.free?'free-badge':''}" href="${r.url}" target="_blank" rel="noopener">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
                  ${r.name}
                </a>`).join('')}
            </div>
          </div>
        </div>
      </div>`;
  });
  container.innerHTML = html;
}

function _firstUnlockedIdx(domain) {
  for (let i = 0; i < domain.phases.length; i++) {
    const d = domain.phases[i].topics.filter(t => mentorState.domainCompleted[t.id]).length;
    if (d < domain.phases[i].topics.length) return i;
  }
  return 0;
}

function toggleRoadmapCard(phaseId) {
  const card = document.getElementById('roadmap-card-' + phaseId);
  if (card) card.classList.toggle('open');
}

function toggleTopicDetails(topicId) {
  const el = document.getElementById('topic-details-' + topicId);
  if (!el) return;
  const vis = el.style.display !== 'none';
  el.style.display = vis ? 'none' : 'block';
  const btn = el.closest('.roadmap-topic')?.querySelector('.roadmap-topic-detail-toggle');
  if (btn) btn.setAttribute('aria-expanded', !vis);
}

function toggleSharedTopic(topicId, checked) {
  if (checked) mentorState.sharedCompleted[topicId] = true;
  else delete mentorState.sharedCompleted[topicId];
  if (checked) trackActivity('topic');
  mentorSave();
  renderCoreSection();
  renderDashboard();
}

function toggleDomainTopic(topicId, checked) {
  if (checked) mentorState.domainCompleted[topicId] = true;
  else delete mentorState.domainCompleted[topicId];
  if (checked) trackActivity('topic');
  mentorSave();
  renderDomainPhases(getSelectedDomain());
  renderDashboard();
}

function showSwitchWarning() {
  _pendingSwitchDomain = '__clear__';
  document.getElementById('switch-modal-title').textContent = 'Clear Learning Path?';
  document.getElementById('switch-modal-body').innerHTML = 'Go back to path selection? This will reset domain-specific progress.';
  document.getElementById('switch-confirm-btn').textContent = 'Clear Path';
  document.getElementById('switch-modal').style.display = 'flex';
}

function appendMentorMessage(role, text) {
  const msgs = document.getElementById('mentor-chat-msgs');
  if (!msgs) return;
  const div = document.createElement('div');
  div.className = `mentor-msg ${role}`;
  const avatar = role === 'user' ? '<div class="mentor-msg-avatar">👤</div>' : '<div class="mentor-msg-avatar">🛡️</div>';
  div.innerHTML = `${avatar}<div class="mentor-msg-bubble">${_mentorFormatText(text)}</div>`;
  msgs.appendChild(div);
  scrollMentorChat();
}

function _mentorFormatText(text) {
  // Handle code blocks first
  let html = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, function(_, lang, code) {
    return '<pre style="background:var(--bg-code);border:1px solid var(--border-subtle);border-radius:8px;padding:12px 14px;font-family:var(--font-mono);font-size:12px;line-height:1.5;overflow-x:auto;margin:8px 0"><code>' + code.trim() + '</code></pre>';
  });
  html = html.replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code>$1</code>');
  html = html.replace(/\n\n/g,'<br><br>').replace(/\n/g,'<br>');
  return html;
}

// ══ CHAT SESSIONS (history sidebar) ══
function getChatIcon(title) {
  const t = (title || '').toLowerCase();
  if (/\bnetworking?\b|\bdns\b|\btcp\b|\bip\b|\bosi\b|\brouting?\b/.test(t)) return '🌐';
  if (/\bethical hacking?\b|\bpentest|\bpenetration|\bbug bounty\b/.test(t)) return '💉';
  if (/\blinux\b|\bunix\b|\bterminal\b|\bcommand\b|\bbash\b/.test(t)) return '🐧';
  if (/\bsql\b|\binjection\b|\bxss\b/.test(t)) return '⚡';
  if (/\bfirewall\b|\bids\b|\bips\b|\bdetect|\bmonitor/.test(t)) return '🛡️';
  if (/\bcrypt|\bencrypt|\bhash\b|\bssl\b|\btls\b/.test(t)) return '🔐';
  if (/\bcloud\b|\baws\b|\bazure\b|\bgcp\b/.test(t)) return '☁️';
  if (/\bmalware|\bvirus|\bransom|\btrojan/.test(t)) return '🦠';
  if (/\bwifi\b|\bwireless|\bbluetooth/.test(t)) return '📡';
  if (/\bforensic|\bdfir|\binvestigat/.test(t)) return '🔍';
  if (/\bgrc\b|\bcomplianc|\bpolicy\b|\biso\b|\bsoc 2\b/.test(t)) return '📋';
  if (/\bai\b|\bml\b|\bmachine learn|\bneural/.test(t)) return '🤖';
  return '💬';
}

function renderMentorHistoryList() {
  const list = document.getElementById('mchat-history-list');
  if (!list) return;
  const query = document.getElementById('mchat-search-input');
  const q = query ? query.value.trim().toLowerCase() : '';
  const ids = Object.keys(mentorState.mentorChats).reverse();
  const filtered = q ? ids.filter(id => (mentorState.mentorChats[id].title || '').toLowerCase().includes(q)) : ids;
  if (filtered.length === 0) {
    list.innerHTML = '<div class="mchat-history-empty">' + (q ? 'No matching conversations.' : 'No conversations yet.') + '</div>';
    return;
  }
  list.innerHTML = filtered.map(id => {
    const chat = mentorState.mentorChats[id];
    const active = id === mentorState.activeMentorChatId ? ' active' : '';
    const title = chat.title || 'New Chat';
    const icon = getChatIcon(title);
    const dateStr = chat.createdAt ? new Date(chat.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
    return `<div class="mchat-history-item${active}" data-id="${id}" data-action="switchMentorChat" data-chat-id="${id}" title="${escapeHtml(dateStr ? 'Created: ' + dateStr : title)}">
      <span class="mchat-hi-icon">${icon}</span>
      <span class="mhi-title" ondblclick="renameMentorChat('${id}', event)">${escapeHtml(title)}</span>
      <div class="mchat-menu-wrap">
        <button class="mchat-dots-btn" data-action="toggleMentorMenu" data-chat-id="${id}" title="More">⋮</button>
        <div class="mchat-menu-dropdown" id="mchat-menu-${id}">
          <button class="mchat-menu-item" data-action="renameMentorChat" data-chat-id="${id}">✏️ Rename</button>
          <button class="mchat-menu-item mchat-menu-danger" data-action="deleteMentorChat" data-chat-id="${id}">🗑️ Delete</button>
        </div>
      </div>
    </div>`;
  }).join('');
}

function filterMentorHistory() {
  renderMentorHistoryList();
}

function scrollMentorChat() {
  const msgs = document.getElementById('mentor-chat-msgs');
  if (msgs) msgs.scrollTop = msgs.scrollHeight;
}

function createNewConversation() {
  const id = 'mchat_' + Date.now();
  mentorState.mentorChats[id] = { title: 'New Chat', msgs: [], createdAt: Date.now() };
  mentorState.activeMentorChatId = id;
  mentorState.chatHistory = [];
  const msgs = document.getElementById('mentor-chat-msgs');
  if (msgs) {
    msgs.innerHTML = '<div class="mentor-msg"><div class="mentor-msg-avatar">🛡️</div><div class="mentor-msg-bubble">Hey! I\'m your Cyber Mentor. Ask me anything about cybersecurity.</div></div>';
  }
  mentorSave();
  renderMentorHistoryList();
  const inp = document.getElementById('mentor-chat-input');
  if (inp) { inp.value = ''; inp.focus(); }
}

function switchMentorChat(id) {
  if (!mentorState.mentorChats[id]) return;
  if (mentorState.activeMentorChatId && mentorState.mentorChats[mentorState.activeMentorChatId]) {
    mentorState.mentorChats[mentorState.activeMentorChatId].msgs = mentorState.chatHistory;
  }
  mentorState.activeMentorChatId = id;
  mentorState.chatHistory = mentorState.mentorChats[id].msgs;
  const msgs = document.getElementById('mentor-chat-msgs');
  if (msgs) {
    msgs.innerHTML = '';
    if (mentorState.chatHistory.length === 0) {
      msgs.innerHTML = '<div class="mentor-msg"><div class="mentor-msg-avatar">🛡️</div><div class="mentor-msg-bubble">Hey! I\'m your Cyber Mentor. Ask me anything about cybersecurity.</div></div>';
    } else {
      mentorState.chatHistory.forEach(m => appendMentorMessage(m.role, m.text));
    }
  }
  mentorSave();
  renderMentorHistoryList();
}

function deleteMentorChat(id, event) {
  if (event) event.stopPropagation();
  if (!mentorState.mentorChats[id]) return;
  // Close menu if open
  const menu = document.getElementById('mchat-menu-' + id);
  if (menu) menu.classList.remove('open');
  if (_openMenuId === id) _openMenuId = null;
  delete mentorState.mentorChats[id];
  if (mentorState.activeMentorChatId === id) {
    const remaining = Object.keys(mentorState.mentorChats);
    if (remaining.length > 0) {
      switchMentorChat(remaining[0]);
    } else {
      mentorState.activeMentorChatId = null;
      mentorState.chatHistory = [];
      const msgs = document.getElementById('mentor-chat-msgs');
      if (msgs) {
        msgs.innerHTML = '<div class="mentor-msg"><div class="mentor-msg-avatar">🛡️</div><div class="mentor-msg-bubble">Hey! I\'m your Cyber Mentor. Ask me anything about cybersecurity.</div></div>';
      }
    }
  }
  mentorSave();
  renderMentorHistoryList();
}

function renameMentorChat(id, event) {
  if (event) event.stopPropagation();
  // Close menu if open
  const menu = document.getElementById('mchat-menu-' + id);
  if (menu) menu.classList.remove('open');
  if (_openMenuId === id) _openMenuId = null;
  // Find the title span — either from double-click or menu click
  let span = event && event.currentTarget && event.currentTarget.classList.contains('mhi-title') ? event.currentTarget : null;
  if (!span) {
    const item = document.querySelector(`.mchat-history-item[data-id="${id}"]`);
    if (item) span = item.querySelector('.mhi-title');
  }
  if (!span || span.getAttribute('contenteditable') === 'true') return;
  const original = span.textContent;
  span.setAttribute('contenteditable', 'true');
  span.focus();
  // Select all text
  const range = document.createRange();
  range.selectNodeContents(span);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
  const finish = () => {
    span.removeAttribute('contenteditable');
    const newTitle = span.textContent.trim() || original;
    span.textContent = newTitle;
    if (mentorState.mentorChats[id]) {
      mentorState.mentorChats[id].title = newTitle;
      mentorSave();
    }
  };
  span.addEventListener('blur', finish, { once: true });
  span.addEventListener('keydown', function handler(e) {
    if (e.key === 'Enter') { e.preventDefault(); span.blur(); }
    if (e.key === 'Escape') { span.textContent = original; span.blur(); }
  });
}

function showMentorTyping() {
  const msgs = document.getElementById('mentor-chat-msgs');
  if (!msgs) return;
  const e = document.getElementById('mentor-typing-indicator');
  if (e) e.remove();
  const div = document.createElement('div');
  div.className = 'mentor-msg'; div.id = 'mentor-typing-indicator';
  div.innerHTML = '<div class="mentor-msg-avatar">🛡️</div><div class="mentor-typing"><span></span><span></span><span></span></div>';
  msgs.appendChild(div); scrollMentorChat();
}

function hideMentorTyping() {
  const el = document.getElementById('mentor-typing-indicator');
  if (el) el.remove();
}

let mentorThinking = false;

async function mentorSendMessage() {
  if (mentorThinking) return;
  // Auto-create session if none active
  if (!mentorState.activeMentorChatId || !mentorState.mentorChats[mentorState.activeMentorChatId]) {
    const id = 'mchat_' + Date.now();
    mentorState.mentorChats[id] = { title: 'New Chat', msgs: [], createdAt: Date.now() };
    mentorState.activeMentorChatId = id;
    mentorState.chatHistory = [];
  }
  const input = document.getElementById('mentor-chat-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = ''; input.style.height = '';
  appendMentorMessage('user', text);
  mentorState.chatHistory.push({ role:'user', text });
  trackActivity('chat');
  // Auto-title from first user message
  const chat = mentorState.mentorChats[mentorState.activeMentorChatId];
  if (chat && (chat.title === 'New conversation' || chat.title === 'New Chat')) {
    chat.title = generateChatTitle(text);
    if (!chat.createdAt) chat.createdAt = Date.now();
  }
  mentorSave();
  renderMentorHistoryList();
  mentorThinking = true;
  document.getElementById('mentor-send-btn').disabled = true;
  showMentorTyping();
  const csrfToken = getCsrfToken();
  const headers = { 'Content-Type':'application/json' };
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  try {
    const history = mentorState.chatHistory.slice(0,-1).map(m => ({ role: m.role === 'bot' ? 'bot' : 'user', text: m.text }));
    const payload = { message: text, history, model: typeof currentModel !== 'undefined' ? currentModel : 'gemini' };
    let response = await fetch('/chat-stream', { method:'POST', headers, body: JSON.stringify(payload) });
    if (!response.ok) {
      const errText = await response.text();
      response = await fetch('/chat', { method:'POST', headers, body: JSON.stringify(payload) });
      if (!response.ok) throw new Error(`Server error ${response.status}`);
      const data = await response.json();
      hideMentorTyping();
      const reply = data.reply || data.text || 'No response.';
      appendMentorMessage('bot', reply);
      mentorState.chatHistory.push({ role:'bot', text: reply });
      mentorSave();
      mentorThinking = false;
      document.getElementById('mentor-send-btn').disabled = false;
      return;
    }
    hideMentorTyping();
    if (!response.body) throw new Error('No body');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let fullReply = '', assistantBubble = null;
    const msgs = document.getElementById('mentor-chat-msgs');
    const adiv = document.createElement('div');
    adiv.className = 'mentor-msg';
    const av = document.createElement('div');
    av.className = 'mentor-msg-avatar'; av.textContent = '🛡️';
    assistantBubble = document.createElement('div');
    assistantBubble.className = 'mentor-msg-bubble';
    adiv.appendChild(av); adiv.appendChild(assistantBubble);
    msgs.appendChild(adiv);
    let buffer = '', streamError = null;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6).trim();
        if (data === '[DONE]') continue;
        try {
          const chunk = JSON.parse(data);
          if (chunk.error) { streamError = chunk.error; break; }
          if (chunk.rate_limited) { streamError = '⚠️ Rate limit reached.'; break; }
          if (chunk.model_switch) {
            const labels = { gemini:'Gemini Flash', groq:'Groq Llama3', lite:'Flash Lite' };
            const typing = document.getElementById('mentor-typing');
            if (typing) typing.textContent = `⚡ Switching to ${labels[chunk.model_switch] || chunk.model_switch}...`;
          }
          const token = chunk.token || chunk.choices?.[0]?.delta?.content || chunk.candidates?.[0]?.content?.parts?.[0]?.text || chunk.text || chunk.content || '';
          if (token) { fullReply += token; assistantBubble.innerHTML = _mentorFormatText(fullReply); scrollMentorChat(); }
          if (chunk.done) break;
        } catch(_) {}
      }
    }
    if (streamError) {
      assistantBubble.innerHTML = _mentorFormatText(streamError);
      mentorState.chatHistory.push({ role:'bot', text: streamError });
    } else if (fullReply) {
      mentorState.chatHistory.push({ role:'bot', text: fullReply });
    } else {
      const fb = 'No response generated. Please try again.';
      assistantBubble.innerHTML = _mentorFormatText(fb);
      mentorState.chatHistory.push({ role:'bot', text: fb });
    }
    mentorSave();
  } catch (err) {
    hideMentorTyping();
    console.error('Chat error:', err);
    appendMentorMessage('bot', `⚠️ Connection error. Please try again.`);
    mentorState.chatHistory.push({ role:'bot', text: '⚠️ Connection error.' });
    mentorSave();
  } finally {
    mentorThinking = false;
    document.getElementById('mentor-send-btn').disabled = false;
    loadMentorSuggestions();
  }
}

function mentorSendQuick(btn) {
  const input = document.getElementById('mentor-chat-input');
  if (input) { input.value = btn.textContent.trim(); }
  mentorSendMessage();
}

function _findTopic(name) {
  const normal = name.trim().toLowerCase();
  for (const t of mentorData.shared_core.topics) { if (t.name.toLowerCase().includes(normal) || normal.includes(t.name.toLowerCase())) return t; }
  for (const d of mentorData.domains) { for (const p of d.phases) { for (const t of p.topics) { if (t.name.toLowerCase().includes(normal) || normal.includes(t.name.toLowerCase())) return t; } } }
  return null;
}

function mentorChatKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); mentorSendMessage(); }
  const ta = e.target;
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
}

// ══ QUIZ ══
function renderQuizTopics() {
  const grid = document.getElementById('quiz-topic-grid');
  if (!grid) return;
  const keys = Object.keys(QUIZ_QUESTIONS);
  grid.innerHTML = keys.map(k => {
    const t = QUIZ_QUESTIONS[k];
    return `<div class="quiz-topic-card" data-id="${k}" data-action="selectQuizTopic" data-topic-id="${k}">
      <div class="quiz-topic-icon">${t.icon}</div>
      <div class="quiz-topic-name">${t.name}</div>
      <div class="quiz-topic-count">${t.questions.length} questions</div>
    </div>`;
  }).join('');
  document.getElementById('start-quiz-btn').disabled = true;
  document.getElementById('quiz-question-area').classList.remove('active');
  document.getElementById('quiz-selector').style.display = 'block';
  document.getElementById('quiz-result-card').classList.remove('show');
  quizState.topic = null;
}

function selectQuizTopic(topicId) {
  document.querySelectorAll('.quiz-topic-card').forEach(c => c.classList.remove('selected'));
  const card = document.querySelector(`.quiz-topic-card[data-id="${topicId}"]`);
  if (card) card.classList.add('selected');
  quizState.topic = topicId;
  document.getElementById('start-quiz-btn').disabled = false;
}

function startMentorQuiz() {
  if (!quizState.topic || !QUIZ_QUESTIONS[quizState.topic]) return;
  trackActivity('quiz_attempt');
  quizState.questions = QUIZ_QUESTIONS[quizState.topic].questions;
  quizState.current = 0; quizState.score = 0; quizState.answered = false;
  document.getElementById('quiz-selector').style.display = 'none';
  document.getElementById('quiz-question-area').classList.add('active');
  document.getElementById('quiz-result-card').classList.remove('show');
  renderQuizQuestion();
}

function renderQuizQuestion() {
  const q = quizState.questions[quizState.current];
  if (!q) return;
  const letters = ['A','B','C','D'];
  document.getElementById('quiz-q-num').textContent = `Q ${quizState.current+1} / ${quizState.questions.length}`;
  document.getElementById('quiz-q-score').textContent = `Score: ${quizState.score}`;
  document.getElementById('quiz-q-text').textContent = q.q;
  document.getElementById('quiz-q-options').innerHTML = q.opts.map((o,i) =>
    `<button class="quiz-q-option" data-idx="${i}" data-action="answerQuiz" data-idx-value="${i}">
      <span class="quiz-opt-letter">${letters[i]}</span>${o}
    </button>`
  ).join('');
  document.getElementById('quiz-feedback').className = 'quiz-feedback';
  document.getElementById('quiz-feedback').textContent = '';
  document.getElementById('quiz-next-btn').style.display = 'none';
  quizState.answered = false;
  document.querySelectorAll('.quiz-q-option').forEach(b => b.disabled = false);
}

function answerQuiz(idx) {
  if (quizState.answered) return;
  quizState.answered = true;
  const q = quizState.questions[quizState.current];
  const correct = idx === q.correct;
  if (correct) quizState.score++;
  document.querySelectorAll('.quiz-q-option').forEach((b,i) => {
    b.disabled = true;
    if (i === q.correct) b.classList.add('correct');
    if (i === idx && !correct) b.classList.add('wrong');
  });
  const fb = document.getElementById('quiz-feedback');
  if (correct) { fb.className = 'quiz-feedback correct show'; fb.textContent = '✓ Correct!'; }
  else { fb.className = 'quiz-feedback wrong show'; fb.textContent = `✗ Incorrect. Answer: ${q.opts[q.correct]}`; }
  document.getElementById('quiz-q-score').textContent = `Score: ${quizState.score}`;
  if (quizState.current < quizState.questions.length - 1) {
    document.getElementById('quiz-next-btn').style.display = 'inline-flex';
  } else {
    setTimeout(mentorQuizFinish, 800);
  }
}

function mentorQuizNext() { quizState.current++; renderQuizQuestion(); }

function mentorQuizFinish() {
  trackActivity('quiz_complete');
  const total = quizState.questions.length, score = quizState.score, pct = Math.round(score/total*100);
  document.getElementById('quiz-question-area').classList.remove('active');
  const rc = document.getElementById('quiz-result-card');
  rc.classList.add('show');
  let emoji='😢',msg='Keep studying!';
  if (pct===100) { emoji='🏆'; msg='Perfect! Genius!'; }
  else if (pct>=80) { emoji='🎉'; msg='Great job!'; }
  else if (pct>=60) { emoji='👍'; msg='Good effort!'; }
  else { emoji='📚'; msg='Review fundamentals.'; }
  document.getElementById('quiz-result-emoji').textContent = emoji;
  document.getElementById('quiz-result-score').textContent = `${score}/${total}`;
  document.getElementById('quiz-result-msg').textContent = msg;
  mentorState.quizScore = score;
  if (pct===100) mentorState.quizPerfect = true;
  mentorSave(); updateTopbarStats();
}

function resetMentorQuiz() {
  quizState = { topic:null, questions:[], current:0, score:0, answered:false };
  document.getElementById('quiz-result-card').classList.remove('show');
  renderQuizTopics();
}

// ══ TERMINAL ══
function mtermKeydown(e) {
  if (e.key === 'Enter') {
    e.preventDefault();
    const inp = document.getElementById('mterm-input');
    const cmd = inp.value.trim();
    inp.value = '';
    if (cmd) mtermExecute(cmd);
  }
}

function mtermExecute(cmd) {
  const screen = document.getElementById('mterm-screen');
  if (!screen) return;
  const parts = cmd.split(/\s+/);
  const base = parts[0].toLowerCase();
  const args = parts.slice(1);
  screen.innerHTML += `<div class="mterm-line"><span class="mterm-prompt">mentor@cyberguru:~$</span> <span class="mterm-cmd">${_mtermEscape(cmd)}</span></div>`;
  if (base === 'clear') { screen.innerHTML = ''; return; }
  if (TERMINAL_COMMANDS[base]) {
    const result = TERMINAL_COMMANDS[base].run(args);
    if (result !== null) result.split('\n').forEach(l => { screen.innerHTML += `<div class="mterm-line mterm-output">${_mtermEscape(l)}</div>`; });
    mentorState.terminalCmds = (mentorState.terminalCmds||0) + 1;
    trackActivity('terminal');
    mentorSave();
  } else {
    screen.innerHTML += `<div class="mterm-line mterm-error">bash: ${_mtermEscape(base)}: command not found</div>`;
    screen.innerHTML += `<div class="mterm-line mterm-output">Try 'help' for available commands</div>`;
  }
  screen.scrollTop = screen.scrollHeight;
}

function _mtermEscape(str) { return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ══ BADGES ══
function renderBadges() {
  const grid = document.getElementById('mbadge-grid');
  if (!grid) return;
  const earned = getEarnedBadges();
  grid.innerHTML = BADGES.map(b => {
    const has = earned.includes(b.id);
    return `<div class="mbadge-card ${has?'':'locked'}">
      <div class="mbadge-icon">${b.icon}</div>
      <div class="mbadge-name">${b.name}</div>
      <div class="mbadge-desc">${has ? b.desc : '🔒 Locked — '+b.desc}</div>
    </div>`;
  }).join('');
}

// ══ PROFILE & ONBOARDING ══

function showOnboarding() {
  const overlay = document.getElementById('onboarding-overlay');
  if (!overlay) return;
  overlay.classList.add('active');
  overlay.style.display = 'flex';
  // Reset
  document.getElementById('ob-view-select').style.display = '';
  document.getElementById('ob-view-processing').style.display = 'none';
  document.getElementById('ob-save-btn').disabled = true;
  document.querySelectorAll('.ob-card').forEach(c => c.classList.remove('selected'));
  document.querySelector('input[name="skill_level"]:checked') && (document.querySelector('input[name="skill_level"]:checked').checked = false);
}

function closeOnboarding() {
  const overlay = document.getElementById('onboarding-overlay');
  if (overlay) { overlay.classList.remove('active'); overlay.style.display = 'none'; }
}

function skipOnboarding() {
  closeOnboarding();
}

// Card selection via click
document.addEventListener('click', function (e) {
  const card = e.target.closest('.ob-card');
  if (!card) return;
  document.querySelectorAll('.ob-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  const radio = card.querySelector('input[type="radio"]');
  if (radio) radio.checked = true;
  const btn = document.getElementById('ob-save-btn');
  if (btn) btn.disabled = false;
});

async function saveOnboarding() {
  const level = document.querySelector('input[name="skill_level"]:checked')?.value;
  if (!level) return;

  // Show processing view
  document.getElementById('ob-view-select').style.display = 'none';
  document.getElementById('ob-view-processing').style.display = '';

  const step1 = document.getElementById('ob-step-1');
  const step2 = document.getElementById('ob-step-2');
  const step3 = document.getElementById('ob-step-3');

  // Animate steps
  step1.classList.add('active');
  await sleep(600);

  try {
    const csrf = window._csrfToken || '';
    const res = await fetch('/api/profile/onboard', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      credentials: 'include',
      body: JSON.stringify({ skill_level: level }),
    });

    step1.classList.remove('active');
    step1.classList.add('done');

    step2.classList.add('active');
    await sleep(500);

    if (!res.ok) {
      step2.classList.remove('active');
      step2.querySelector('.ob-step-dot').style.background = '#ef4444';
      step2.style.color = '#ef4444';
      return;
    }

    step2.classList.remove('active');
    step2.classList.add('done');

    step3.classList.add('active');
    await sleep(400);

    const data = await res.json();
    window.__userData = window.__userData || {};
    window.__userData.profile = data.profile || {};

    step3.classList.remove('active');
    step3.classList.add('done');

    await sleep(400);
    closeOnboarding();
    await refreshProfileWidget(true);
    if (typeof loadChatSuggestions === 'function') loadChatSuggestions('chat');

  } catch (e) {
    console.error('Onboarding error:', e);
    const active = document.querySelector('.ob-step-row.active');
    if (active) { active.querySelector('.ob-step-dot').style.background = '#ef4444'; active.style.color = '#ef4444'; }
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function refreshProfileWidget(force = false) {
  window.__userData = window.__userData || {};
  if (force || !window.__userData.profile) {
    try {
      const res = await fetch('/api/profile', { credentials: 'include' });
      if (res.ok) {
        const profileData = await res.json();
        window.__userData.profile = profileData.profile || profileData;
      }
    } catch (err) {
      console.warn('Could not refresh profile widget:', err);
    }
  }
  loadProfileWidget();
}

function loadProfileWidget() {
  const profile = window.__userData?.profile;
  const cont = document.getElementById('settings-profile-widget');
  if (!cont) return;
  if (!profile) {
    cont.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-muted);font-size:13px;">Complete onboarding to personalise your experience.</div>';
    return;
  }
  const level = profile.skill_level || 'beginner';
  const pct = profile.progress_percentage || 0;
  const lessons = profile.completed_lessons || 0;
  const quizzes = profile.completed_quizzes || 0;
  const labs = profile.completed_labs || 0;
  const topic = profile.current_topic || '—';
  cont.innerHTML = `
    <div class="prof-widget">
      <div class="prof-row"><span class="prof-label">Skill Level</span><span class="prof-badge ${level}">${level.charAt(0).toUpperCase() + level.slice(1)}</span></div>
      <div class="prof-row"><span class="prof-label">Progress</span><span class="prof-value">${pct}%</span></div>
      <div class="prof-bar"><div class="prof-bar-fill" style="width:${pct}%"></div></div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:4px;">
        <div class="prof-stat"><div class="prof-stat-val">${lessons}</div><div class="prof-stat-lbl">Lessons</div></div>
        <div class="prof-stat"><div class="prof-stat-val">${quizzes}</div><div class="prof-stat-lbl">Quizzes</div></div>
        <div class="prof-stat"><div class="prof-stat-val">${labs}</div><div class="prof-stat-lbl">Labs</div></div>
      </div>
      <div class="prof-row"><span class="prof-label">Current Topic</span><span class="prof-value" style="font-size:12px;max-width:160px;text-align:right;">${topic}</span></div>
    </div>
  `;
}

function loadSettingsProfile() {
  refreshProfileWidget(true);
}

/* ── Dynamic Prompt Suggestions ─────────────────────────────────── */

async function loadMentorSuggestions() {
  var wrap = document.getElementById('mentor-suggest-chips');
  if (!wrap) return;
  try {
    var res = await fetch('/api/prompt-suggestions?module=mentor&count=4', { credentials: 'include' });
    if (!res.ok) { wrap.innerHTML = ''; return; }
    var data = await res.json();
    var items = data.suggestions || [];
    if (!items.length) { wrap.innerHTML = ''; return; }
    wrap.innerHTML = items.map(function (text, i) {
      return '<span class="dyn-suggest-chip dsc-d' + (i + 1) + '" data-action="mentorFillSuggestion" data-text=' + JSON.stringify(text) + ' title="' + escapeHtml(text) + '"><span class="dsc-icon">🎓</span>' + escapeHtml(text) + '</span>';
    }).join('');
  } catch (_) { wrap.innerHTML = ''; }
}

function mentorFillSuggestion(text) {
  var input = document.getElementById('mentor-chat-input');
  if (input) { input.value = text; input.focus(); }
}

// ══ INIT ══
(async function mentorInit() {
  mentorLoad();
  await loadRoadmap();
  setTimeout(loadMentorSuggestions, 300);
})();
