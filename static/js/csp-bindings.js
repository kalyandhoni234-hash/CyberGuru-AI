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

      // ── Sidebar ──────────────────────────────────────────────
      case 'closeSidebar':       closeSidebar(); break;
      case 'newChat':            newChat(); break;
      case 'toggleSidebar':      toggleSidebar(); break;
      case 'toggleSidebarCollapse': toggleSidebarCollapse(); break;

      // ── Confirm modal ────────────────────────────────────────
      case 'resolveConfirm':
        resolveConfirm(el.dataset.result === 'true'); break;

      // ── Tools menu ───────────────────────────────────────────
      case 'toggleToolsMenu':    toggleToolsMenu(e); break;
      case 'openQuiz':           openQuizModal(); closeToolsMenu(); break;
      case 'openCtf':            openCtfModal(); closeToolsMenu(); break;
      case 'openNews':           fetchCyberNews(); closeToolsMenu(); break;
      case 'openThreat':         openThreatPulse(); closeToolsMenu(); break;

      // ── Mentor sidebar button ────────────────────────────────
      case 'openMentorOverlay':  openMentorOverlay(); break;

      // ── User menu ────────────────────────────────────────────
      case 'toggleUserMenu':     toggleUserMenu(e); break;
      case 'openSettingsMenu':   openSettings(); closeUserMenu(); break;
      case 'logoutUser':         logout(); closeUserMenu(); break;

      // ── Rate-limit banner ────────────────────────────────────
      case 'dismissRateBanner':  dismissRateBanner(); break;

      // ── Export / Scroll ──────────────────────────────────────
      case 'exportChat':         exportChat(); break;
      case 'scrollToBottom':     scrollToBottom(); break;

      // ── Plus menu ────────────────────────────────────────────
      case 'togglePlusMenu':     togglePlusMenu(); break;
      case 'closePlusMenu':      closePlusMenu(); break;
      case 'toggleModelsSubmenu': toggleModelsSubmenu(e); break;
      case 'setModel':
        setModel(el.dataset.model);
        updatePlusModelLabel(el.dataset.label);
        closePlusMenu();
        break;
      case 'openInvestigate':    openInvestigatePanel(); closePlusMenu(); break;

      // ── Voice / Send / Stop ──────────────────────────────────
      case 'toggleVoice':
        if (typeof window.toggleVoice === 'function') window.toggleVoice();
        break;
      case 'stopGeneration':     stopGeneration(); break;
      case 'sendToBackend':      sendToBackend(); break;

      // ── Settings ─────────────────────────────────────────────
      case 'closeSettings':      closeSettings(); break;
      case 'switchTab':          switchTab(el.dataset.tab); break;
      case 'setTheme':
        setTheme(el.dataset.theme);
        updateThemeCards();
        break;
      case 'setFontSize':        setFontSize(el.dataset.size); break;

      // ── Onboarding ───────────────────────────────────────────
      case 'closeOnboarding':    closeOnboarding(); break;
      case 'saveOnboarding':     saveOnboarding(); break;
      case 'skipOnboarding':     skipOnboarding(); break;

      // ── Login ────────────────────────────────────────────────
      case 'goLogin':
        window.location.href = '/auth/login'; break;

      // ── Threat Pulse ─────────────────────────────────────────
      case '_tpLoad':            _tpLoad(); break;
      case 'closeThreatPulse':   closeThreatPulse(); break;

      // ── Mentor overlay ───────────────────────────────────────
      case 'closeMentorOverlay': closeMentorOverlay(); break;
      case 'switchMentorTab':    switchMentorTab(el.dataset.tab); break;
      case 'dismissLanding':     dismissLanding(el.dataset.tab || undefined); break;
      case 'selectLandingDomain':
        dismissLanding('roadmap');
        setTimeout(function () {
          mentorState.selectedDomain = el.dataset.domainId;
          mentorSave();
          renderRoadmap();
        }, 50);
        break;
      case 'openDomainAI':       openDomainAI(); break;
      case 'closeDomainAI':      closeDomainAI(); break;
      case 'askAIRoadmap':       askAIRoadmap(); break;
      case 'showSwitchWarning':  showSwitchWarning(); break;
      case 'confirmSwitchDomain': confirmSwitchDomain(); break;
      case 'cancelSwitchDomain': cancelSwitchDomain(); break;
      case 'toggleCoreSection':  toggleCoreSection(); break;
      case 'toggleRoadmapCard':  toggleRoadmapCard(el.dataset.phaseId || el.dataset.phaseIdValue || el.dataset.phase); break;
      case 'selectDomain':       selectDomain(el.dataset.domainId || el.dataset.domain); break;
      case 'toggleTopicDetails': toggleTopicDetails(el.dataset.topicId || el.dataset.topic); break;

      // ── Mentor chat ──────────────────────────────────────────
      case 'createNewConversation': createNewConversation(); break;
      case 'mentorSendMessage':  mentorSendMessage(); break;
      case 'switchMentorChat':   switchMentorChat(el.dataset.chatId || el.dataset.id); break;
      case 'toggleMentorMenu':   toggleMentorMenu(el.dataset.chatId || el.dataset.id, e); break;
      case 'renameMentorChat':   renameMentorChat(el.dataset.chatId || el.dataset.id, e); break;
      case 'deleteMentorChat':   deleteMentorChat(el.dataset.chatId || el.dataset.id, e); break;
      case 'mentorFillSuggestion': mentorFillSuggestion(el.dataset.text); break;
      case 'mentorSendQuick':    mentorSendQuick(el); break;

      // ── Mentor quiz ──────────────────────────────────────────
      case 'selectQuizTopic':    selectQuizTopic(el.dataset.topicId || el.dataset.id); break;
      case 'startMentorQuiz':    startMentorQuiz(); break;
      case 'answerQuiz':         answerQuiz(parseInt(el.dataset.idxValue || el.dataset.idx, 10)); break;
      case 'mentorQuizNext':     mentorQuizNext(); break;
      case 'resetMentorQuiz':    resetMentorQuiz(); break;

      // ── Topic toggles ────────────────────────────────────────
      case 'toggleDomainTopic':
        toggleDomainTopic(el.dataset.topicId || el.dataset.topic, el.checked); break;
      case 'toggleSharedTopic':
        toggleSharedTopic(el.dataset.topicId || el.dataset.topic, el.checked); break;

      // ── Chat message actions ─────────────────────────────────
      case 'copyMessage':        copyMessage(el.dataset.msgId); break;
      case 'thumbs':             thumbs(el.dataset.msgId, el.dataset.dir); break;
      case 'copyCode':           copyCode(el.dataset.codeId); break;
      case 'fillAndSend':        fillAndSend(el.dataset.text || el.textContent.trim()); break;

      // ── Welcome card actions ─────────────────────────────────
      case 'fillAndSendSQL':     fillAndSend('What is SQL Injection and how does it work?'); break;
      case 'fillAndSendXSS':     fillAndSend('Explain Cross-Site Scripting (XSS) attacks'); break;
      case 'fillAndSendMalware': fillAndSend('What are the different types of malware?'); break;
      case 'fillAndSendOWASP':   fillAndSend('What is OWASP Top 10 and why does it matter?'); break;

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

      // ── CTF modal ────────────────────────────────────────────
      case 'closeCtfModal':      closeCtfModal(); break;
      case '_ctfSelectCategory': _ctfSelectCategory(el, el.dataset.valueId || el.dataset.value); break;
      case '_ctfStartFromPicker': _ctfStartFromPicker(); break;
      case '_ctfCopyArtifact':   _ctfCopyArtifact(el); break;
      case '_ctfSubmitAnswer':   _ctfSubmitAnswer(); break;
      case '_ctfRenderCategoryPicker': _ctfRenderCategoryPicker(); break;

      // ── Quiz modal ───────────────────────────────────────────
      case 'closeQuizModal':     closeQuizModal(); break;
      case '_quizSelectTopic':   _quizSelectTopic(el, el.dataset.valueId || el.dataset.value); break;
      case '_quizStartFromPicker': _quizStartFromPicker(); break;
      case '_quizSelectAnswer':
        _quizSelectAnswer(el.dataset.qId || el.dataset.qid, el.dataset.letter);
        break;
      case '_quizNextOrSubmit':  _quizNextOrSubmit(); break;
      case '_quizPrevQuestion':  _quizPrevQuestion(); break;
      case '_quizRenderTopicPicker': _quizRenderTopicPicker(); break;

      // ── Mobile investigate ───────────────────────────────────
      case 'mobSelectType':      mobSelectType(el.dataset.typeId || el.dataset.type, el); break;
      case 'mobClear':           mobClear(); break;
      case 'mobRunInvestigation': mobRunInvestigation(); break;
      case 'mobBackToInput':     mobBackToInput(); break;
      case 'mobNewAnalysis':     mobNewAnalysis(); break;
      case 'mobToggleEvidence':  mobToggleEvidence(); break;
      case 'mobToggleRaw':       mobToggleRaw(); break;

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
    if (action === 'mentorChatKeydown') mentorChatKeydown(e);
    else if (action === 'mtermKeydown') mtermKeydown(e);
    else if ((action === 'toggleEvidence' || action === 'toggleRawFindings') && (e.key === 'Enter' || e.key === ' ')) {
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
    if (action === 'filterMentorHistory') filterMentorHistory();
    else if (action === 'onEditorInput') onEditorInput();
    else if (action === 'mobOnInput') mobOnInput();
  });

  /* ── CHANGE delegation ─────────────────────────────────────── */
  document.addEventListener('change', function (e) {
    var el = e.target.closest('[data-change]');
    if (!el) return;
    var action = el.dataset.change;
    if (action === 'toggleCompactSidebar') toggleCompactSidebar(el.checked);
    else if (action === 'mobFileLoad') mobFileLoad(e);
    else if (action === 'toggleSharedTopic') toggleSharedTopic(el.dataset.topicId || el.dataset.topic, el.checked);
    else if (action === 'toggleDomainTopic') toggleDomainTopic(el.dataset.topicId || el.dataset.topic, el.checked);
  });
});
