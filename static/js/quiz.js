/* ─────────────────────────────────────────────────────────────
   Quiz Mode — frontend
   Talks to /api/quiz/start and /api/quiz/submit (routes/quiz.py).
   Self-contained modal: doesn't touch the chat pipeline.
   Deliberately reuses the .ctf-* CSS classes from ctf.js so Quiz
   Mode looks and feels like CTF Challenge Mode — same header,
   step dots, badges, and result screen. Only the in-between
   "answer" step differs: multiple-choice cards instead of a
   freeform textarea, since quiz answers are objective.
   ───────────────────────────────────────────────────────────── */

let _quizCurrent = null;       // public quiz (no answers) currently shown
let _quizAnswers = {};         // { questionId: "A" | "B" | "C" | "D" }
let _quizIndex = 0;            // index of question currently on screen
let _quizSelectedTopic = '';   // currently selected topic value on picker

const QUIZ_TOPIC_OPTIONS = [
  { value: '',                          label: 'Random Topic',       icon: '🎲' },
  { value: 'SQL Injection',             label: 'SQL Injection',      icon: '💉' },
  { value: 'Cross-Site Scripting (XSS)',label: 'XSS',                icon: '🕸️' },
  { value: 'Malware',                   label: 'Malware',            icon: '🦠' },
  { value: 'Phishing',                  label: 'Phishing',           icon: '🎣' },
  { value: 'Network Security',          label: 'Network Security',   icon: '🌐' },
  { value: 'Cryptography',              label: 'Cryptography',       icon: '🔐' },
  { value: 'Social Engineering',        label: 'Social Engineering', icon: '🎭' },
  { value: 'OWASP Top 10',              label: 'OWASP Top 10',       icon: '📋' },
];

function openQuizModal() {
  document.getElementById('quiz-modal').classList.add('show');
  _quizSelectedTopic = '';
  _quizAnswers = {};
  _quizIndex = 0;
  _quizRenderTopicPicker();
}

function closeQuizModal() {
  document.getElementById('quiz-modal').classList.remove('show');
}

function _quizBody() {
  return document.getElementById('quiz-modal-body');
}

function _quizHeader(title, activeStepIdx) {
  const steps = [0, 1, 2]; // pick -> play -> result
  return `
    <div class="ctf-header-row">
      <div class="ctf-header-title">
        <span class="ctf-flag-badge">🎯</span>
        ${escapeHtml(title)}
      </div>
      <div class="ctf-step-dots">
        ${steps.map(i => `<span class="${i === activeStepIdx ? 'active' : ''}"></span>`).join('')}
      </div>
    </div>
  `;
}

function _quizRenderTopicPicker() {
  const cards = QUIZ_TOPIC_OPTIONS.map((opt, i) => {
    const isChecked = (i === 0 && _quizSelectedTopic === '') || _quizSelectedTopic === opt.value;
    return `
      <label class="ctf-cat-card ${isChecked ? 'selected' : ''}" data-value="${escapeHtml(opt.value)}" onclick="_quizSelectTopic(this, '${escapeHtml(opt.value)}')">
        <input type="radio" name="quiz-topic-pick" value="${escapeHtml(opt.value)}" ${isChecked ? 'checked' : ''}>
        <span class="ctf-cat-icon">${opt.icon}</span>
        <span>${escapeHtml(opt.label)}</span>
        <span class="ctf-cat-check"></span>
      </label>
    `;
  }).join('');

  _quizBody().innerHTML = `
    ${_quizHeader('Quiz Mode', 0)}
    <div class="ctf-subtitle">Pick a topic. CyberGuru will generate 5 multiple-choice questions for you to work through.</div>
    <div class="ctf-category-options">
      ${cards}
    </div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeQuizModal()">Cancel</button>
      <button class="start-btn" onclick="_quizStartFromPicker()">Start Quiz →</button>
    </div>
  `;
}

function _quizSelectTopic(el, value) {
  _quizSelectedTopic = value;
  document.querySelectorAll('#quiz-modal-body .ctf-cat-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  const input = el.querySelector('input');
  if (input) input.checked = true;
}

function _quizStartFromPicker() {
  const checked = document.querySelector('input[name="quiz-topic-pick"]:checked');
  const topic = checked ? checked.value : '';
  _quizLoadQuiz(true, topic);
}

function _quizRenderLoading(msg, sub) {
  _quizBody().innerHTML = `
    ${_quizHeader('Quiz Mode', 1)}
    <div class="ctf-loading-wrap">
      <div class="ctf-ring-spinner"></div>
      <div class="ctf-spinner-row">
        <div>${escapeHtml(msg || 'Generating your quiz...')}</div>
        ${sub ? `<div class="ctf-loading-sub">${escapeHtml(sub)}</div>` : ''}
      </div>
    </div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeQuizModal()">Cancel</button>
    </div>
  `;
}

function _quizRenderError(message, allowRetry) {
  _quizBody().innerHTML = `
    ${_quizHeader('Quiz Mode', 0)}
    <div class="ctf-error">⚠️ ${escapeHtml(message || 'Something went wrong.')}</div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeQuizModal()">Close</button>
      ${allowRetry ? '<button class="start-btn" onclick="_quizRenderTopicPicker()">Choose Topic</button>' : ''}
    </div>
  `;
}

async function _quizLoadQuiz(forceNew, topic) {
  _quizRenderLoading('Generating your quiz...', 'CyberGuru is writing 5 questions');
  try {
    const params = new URLSearchParams();
    if (forceNew) params.set('new', '1');
    if (topic) params.set('topic', topic);
    const qs = params.toString();
    const url = '/api/quiz/start' + (qs ? `?${qs}` : '');

    const res = await fetch(url, { credentials: 'include' });
    const data = await res.json().catch(() => ({}));

    if (res.status === 401) return; // global fetch interceptor already shows login overlay

    if (!res.ok || data.status !== 'ok') {
      _quizRenderError(data.message, true);
      return;
    }

    _quizCurrent = data.quiz;
    _quizAnswers = {};
    _quizIndex = 0;
    _quizRenderQuestion();
  } catch (e) {
    console.error('Quiz load error:', e);
    _quizRenderError('Could not reach the server. Check your connection and try again.', true);
  }
}

function _quizRenderQuestion() {
  const total = _quizCurrent.questions.length;
  const q = _quizCurrent.questions[_quizIndex];
  const selected = _quizAnswers[q.id];
  const letters = ['A', 'B', 'C', 'D'];

  const options = letters.map(letter => {
    const text = q.options[letter];
    if (text === undefined) return '';
    const isSelected = selected === letter;
    return `
      <label class="quiz-mcq-option ${isSelected ? 'selected' : ''}" onclick="_quizSelectAnswer('${q.id}', '${letter}')">
        <input type="radio" name="quiz-answer-${escapeHtml(q.id)}" value="${letter}" ${isSelected ? 'checked' : ''}>
        <span class="quiz-mcq-letter">${letter}</span>
        <span class="quiz-mcq-text">${escapeHtml(text)}</span>
      </label>
    `;
  }).join('');

  const isLast = _quizIndex === total - 1;
  const nextLabel = isLast ? 'Finish Quiz' : 'Next Question →';
  const pct = Math.round(((_quizIndex) / total) * 100);

  _quizBody().innerHTML = `
    ${_quizHeader(_quizCurrent.title || 'Quiz Mode', 1)}
    <div class="ctf-meta-row">
      <span class="ctf-badge cat">📁 ${escapeHtml(_quizCurrent.topic || '')}</span>
    </div>
    <div class="quiz-progress-row">
      <span class="quiz-progress-text">Question ${_quizIndex + 1} of ${total}</span>
      <div class="quiz-progress-bar"><div class="quiz-progress-fill" style="width:${pct}%"></div></div>
    </div>
    <div class="ctf-question">${escapeHtml(q.question || '')}</div>
    <div class="quiz-mcq-list">
      ${options}
    </div>
    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeQuizModal()">Cancel</button>
      ${_quizIndex > 0 ? '<button class="quiz-cancel" onclick="_quizPrevQuestion()">← Back</button>' : ''}
      <button class="start-btn" id="quiz-next-btn" onclick="_quizNextOrSubmit()" ${selected ? '' : 'disabled'}>${nextLabel}</button>
    </div>
  `;
}

function _quizSelectAnswer(qid, letter) {
  _quizAnswers[qid] = letter;
  _quizRenderQuestion();
}

function _quizPrevQuestion() {
  if (_quizIndex > 0) {
    _quizIndex -= 1;
    _quizRenderQuestion();
  }
}

function _quizNextOrSubmit() {
  const total = _quizCurrent.questions.length;
  if (_quizIndex < total - 1) {
    _quizIndex += 1;
    _quizRenderQuestion();
  } else {
    _quizSubmitAnswers();
  }
}

async function _quizSubmitAnswers() {
  _quizRenderLoading('Grading your quiz...', 'Checking your answers');

  try {
    const res = await fetch('/api/quiz/submit', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ answers: _quizAnswers }),
    });
    const data = await res.json().catch(() => ({}));

    if (res.status === 401) return;

    if (!res.ok || data.status !== 'ok') {
      if (data.expired) {
        _quizRenderError(data.message, true);
      } else {
        _quizRenderError(data.message, false);
      }
      return;
    }

    _quizRenderResult(data.result, data.quiz_title, data.quiz_topic);
  } catch (e) {
    console.error('Quiz submit error:', e);
    _quizRenderError('Could not reach the server. Check your connection and try again.', false);
  }
}

function _quizRenderResult(r, title, topic) {
  const pass = !!r.passed;
  const score = Number(r.score) || 0;

  const breakdownItems = (r.breakdown || []).map((b, i) => {
    const icon = b.is_correct ? '✓' : '○';
    const cls = b.is_correct ? 'good' : 'bad';
    const yourAnswer = b.your_answer ? `${b.your_answer}) ${escapeHtml(b.your_answer_text || '')}` : '— no answer —';
    const correctAnswer = `${b.correct_answer}) ${escapeHtml(b.correct_answer_text || '')}`;
    return `
      <div class="quiz-review-item ${cls}">
        <div class="quiz-review-q"><span class="quiz-review-icon">${icon}</span>Q${i + 1}. ${escapeHtml(b.question || '')}</div>
        <div class="quiz-review-answer">Your answer: <strong>${yourAnswer}</strong></div>
        ${!b.is_correct ? `<div class="quiz-review-answer">Correct answer: <strong>${correctAnswer}</strong></div>` : ''}
        <div class="quiz-review-explain">${escapeHtml(b.explanation || '')}</div>
      </div>
    `;
  }).join('');

  _quizBody().innerHTML = `
    ${_quizHeader(title || 'Quiz Result', 2)}
    <div class="ctf-meta-row"><span class="ctf-badge cat">📁 ${escapeHtml(topic || '')}</span></div>

    <div class="ctf-result-header">
      <div class="ctf-grade-circle ${pass ? 'pass' : 'fail'}">${escapeHtml(r.grade || '?')}</div>
      <div class="ctf-result-score-row" style="flex:1;">
        <div class="ctf-result-score">Score: ${r.correct_count}/${r.total} correct (${score}%)</div>
        <div class="ctf-result-pill ${pass ? 'pass' : 'fail'}">${pass ? '✅ Passed' : '🔁 Needs work'}</div>
        <div class="ctf-score-bar-track">
          <div class="ctf-score-bar-fill ${pass ? '' : 'fail'}" id="quiz-score-bar" style="width:0%"></div>
        </div>
      </div>
    </div>

    <div class="ctf-result-summary">${escapeHtml(r.summary || '')}</div>

    <div class="ctf-section-label">📖 Question Review</div>
    <div class="quiz-review-list">${breakdownItems}</div>

    <div class="quiz-actions">
      <button class="quiz-cancel" onclick="closeQuizModal()">Close</button>
      <button class="start-btn" onclick="_quizRenderTopicPicker()">New Quiz</button>
    </div>
  `;

  requestAnimationFrame(() => {
    const bar = document.getElementById('quiz-score-bar');
    if (bar) bar.style.width = Math.max(0, Math.min(100, score)) + '%';
  });
}
