(function () {
  'use strict';

  var activeType = 'auto';
  var currentInvestigationId = null;
  var _evidenceText = '';

  var PIPELINE_STEPS = [
    { step: 1, label: 'Extracting Indicators' },
    { step: 2, label: 'Parsing Evidence' },
    { step: 3, label: 'Threat Intelligence Lookup' },
    { step: 4, label: 'MITRE ATT&CK Mapping' },
    { step: 5, label: 'Risk Assessment' },
    { step: 6, label: 'AI Analysis' },
    { step: 7, label: 'Report Generation' },
  ];

  // ── Type selection ──

  window.selectType = function (type, el) {
    activeType = type;
    document.querySelectorAll('.ic-type-item').forEach(function (i) { i.classList.remove('active'); i.setAttribute('aria-selected', 'false'); });
    if (el) { el.classList.add('active'); el.setAttribute('aria-selected', 'true'); }
    var editor = document.getElementById('ic-editor');
    var placeholders = {
      auto: 'Paste a URL, IP address, domain, email headers, security log, malware report, hash, or any security indicator here...',
      url: 'Paste a suspicious URL to analyze...',
      phishing_email: 'Paste email headers or the full phishing email content...',
      log: 'Paste security log entries (firewall, IDS, auth logs)...',
      malware: 'Paste a malware analysis report or describe the malware behavior...',
      ioc: 'Paste a list of hashes, IPs, domains, or URLs to investigate...',
      domain: 'Enter a domain name to investigate...',
      ip: 'Enter an IP address to check reputation...',
    };
    editor.placeholder = placeholders[type] || placeholders.auto;
    editor.focus();
  };

  // ── Editor actions ──

  window.clearEditor = function () {
    document.getElementById('ic-editor').value = '';
    document.getElementById('ic-editor').focus();
    updateCharCount();
  };

  window.onEditorInput = function () {
    updateCharCount();
    autoExpandTextarea();
    if (window.innerWidth < 768) {
      var es = document.getElementById('ic-empty-state');
      var ed = document.getElementById('ic-editor');
      if (es && ed) es.style.display = ed.value.trim() ? 'none' : '';
      var mh = document.getElementById('ic-mobile-hint');
      if (mh && ed) mh.style.display = ed.value.trim() ? 'none' : '';
    }
  };

  function autoExpandTextarea() {
    var el = document.getElementById('ic-editor');
    if (!el) return;
    el.style.height = 'auto';
    var isMobile = window.innerWidth < 768;
    var minHeight = isMobile ? 120 : 160;
    var maxHeight = isMobile ? 250 : window.innerHeight * 0.5;
    el.style.height = Math.max(minHeight, Math.min(el.scrollHeight, maxHeight)) + 'px';
  }

  function updateCharCount() {
    var el = document.getElementById('ic-char-count');
    if (!el) return;
    var len = (document.getElementById('ic-editor').value || '').length;
    el.textContent = len > 0 ? len + ' chars' : '';
  }

  // ── Init ──

  document.addEventListener('DOMContentLoaded', function () {
    var fileInput = document.getElementById('ic-file-input');
    if (fileInput) {
      fileInput.addEventListener('change', function (e) {
        var file = e.target.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function (ev) {
          var editor = document.getElementById('ic-editor');
          editor.value += (ev.target.result || '');
          updateCharCount();
          showToast('File loaded: ' + file.name, 'success');
        };
        reader.onerror = function () { showToast('Could not read file.', 'error'); };
        reader.readAsText(file);
        fileInput.value = '';
      });
    }

    var editorWrap = document.getElementById('ic-editor-wrap');
    var dropzone = document.getElementById('ic-dropzone');
    if (editorWrap && dropzone) {
      editorWrap.addEventListener('dragenter', function (e) { e.preventDefault(); dropzone.classList.add('active'); });
      editorWrap.addEventListener('dragover', function (e) { e.preventDefault(); });
      editorWrap.addEventListener('dragleave', function (e) { e.preventDefault(); dropzone.classList.remove('active'); });
      editorWrap.addEventListener('drop', function (e) {
        e.preventDefault();
        dropzone.classList.remove('active');
        var file = e.dataTransfer.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function (ev) {
          document.getElementById('ic-editor').value += (ev.target.result || '');
          updateCharCount();
          showToast('File loaded: ' + file.name, 'success');
        };
        reader.readAsText(file);
      });
    }

    if (window.innerWidth < 768) {
      var ed = document.getElementById('ic-editor');
      var mobPlaceholder = ed.getAttribute('data-mob-placeholder');
      if (mobPlaceholder) {
        ed.placeholder = mobPlaceholder;
        ed.addEventListener('focus', function () { if (window.innerWidth < 768) this.placeholder = ''; });
        ed.addEventListener('blur', function () { if (window.innerWidth < 768 && !this.value.trim()) this.placeholder = mobPlaceholder; });
      }
    }
    loadHistory();
    loadInvestigateSuggestions();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && e.ctrlKey) {
      e.preventDefault();
      runInvestigation();
    }
  });

  // ── Dashboard show/hide ──

  function showDashboard() {
    document.getElementById('ic-work-area').style.display = 'none';
    document.getElementById('ic-dashboard').style.display = 'flex';
    document.getElementById('ic-center-title').textContent = 'Investigation Report Dashboard';
    document.getElementById('ic-center-subtitle').textContent = 'Analysis complete. Review findings below.';
    document.getElementById('ic-empty-state').style.display = 'none';
    document.getElementById('ic-pipeline').style.display = '';
    document.getElementById('ic-new-analysis').style.display = '';
    var mt = document.getElementById('ic-mobile-types');
    if (mt) mt.style.display = 'none';
    if (window.innerWidth < 768) {
      var ew = document.getElementById('ic-editor-wrap');
      if (ew) ew.classList.add('ic-hidden-mobile');
      var sc = document.getElementById('ic-suggest-chips');
      if (sc) sc.style.display = 'none';
      var mh = document.getElementById('ic-mobile-hint');
      if (mh) mh.style.display = 'none';
    }
  }

  function hideDashboard() {
    document.getElementById('ic-work-area').style.display = 'flex';
    document.getElementById('ic-dashboard').style.display = 'none';
    document.getElementById('ic-center-title').textContent = 'Evidence Workspace';
    document.getElementById('ic-center-subtitle').textContent = 'Paste an artifact, upload a file, or drag & drop evidence for analysis.';
    document.getElementById('ic-new-analysis').style.display = 'none';
    var mt = document.getElementById('ic-mobile-types');
    if (mt) mt.style.display = '';
    var ew = document.getElementById('ic-editor-wrap');
    if (ew) ew.classList.remove('ic-hidden-mobile');
    var sc = document.getElementById('ic-suggest-chips');
    if (sc) sc.style.display = '';
    var es = document.getElementById('ic-empty-state');
    if (es) es.style.display = '';
    var mh = document.getElementById('ic-mobile-hint');
    if (mh) mh.style.display = '';
  }

  // ── Pipeline ──

  function renderPipeline() {
    var container = document.getElementById('ic-pipeline-steps');
    if (!container) return;
    container.innerHTML = PIPELINE_STEPS.map(function (s) {
      return '<div class="ic-step" id="ic-step-' + s.step + '"><div class="ic-step-icon">●</div><span>' + s.label + '</span></div>';
    }).join('');
  }

  function setPipelineStep(step, status) {
    var el = document.getElementById('ic-step-' + step);
    if (!el) return;
    el.className = 'ic-step';
    if (status === 'running') { el.classList.add('running'); el.querySelector('.ic-step-icon').textContent = '◌'; }
    if (status === 'done') { el.classList.add('done'); el.querySelector('.ic-step-icon').textContent = '✓'; }
  }

  function animatePipeline() {
    renderPipeline();
    var steps = PIPELINE_STEPS.length;
    var i = 0;
    var bar = document.querySelector('.ic-btn-bar');
    return new Promise(function (resolve) {
      function next() {
        if (i > 0) setPipelineStep(i, 'done');
        if (i < steps) {
          setPipelineStep(i + 1, 'running');
          i++;
          if (bar) bar.style.width = Math.round((i / steps) * 100) + '%';
          setTimeout(next, i === 1 ? 500 : i <= 4 ? 350 : 250);
        } else { resolve(); }
      }
      next();
    });
  }

  function completePipeline() {
    PIPELINE_STEPS.forEach(function (_, idx) { setPipelineStep(idx + 1, 'done'); });
  }

  function resetPipeline() {
    PIPELINE_STEPS.forEach(function (_, idx) {
      var el = document.getElementById('ic-step-' + (idx + 1));
      if (el) { el.className = 'ic-step'; el.querySelector('.ic-step-icon').textContent = '●'; }
    });
    var st = document.getElementById('ic-pipeline-status');
    if (st) st.textContent = 'Running…';
  }

  // ── Main investigation flow ──

  window.runInvestigation = async function () {
    var editor = document.getElementById('ic-editor');
    var artifact = editor.value.trim();
    if (!artifact) {
      showToast('Please enter evidence to analyze.', 'error');
      editor.focus();
      return;
    }
    _evidenceText = artifact;

    var btn = document.getElementById('ic-analyze-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="ic-btn-loading">Analyzing<span class="ic-dots"></span></span><span class="ic-btn-progress"><span class="ic-btn-bar"></span></span>';

    document.getElementById('ic-empty-state').style.display = 'none';
    document.getElementById('ic-pipeline').style.display = '';
    document.getElementById('ic-dashboard').setAttribute('aria-busy', 'true');
    currentInvestigationId = null;
    syncCopilotVisibility();
    resetPipeline();
    showDashboard();

    var pipelinePromise = animatePipeline();

    try {
      var res = await fetch('/api/investigate/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ artifact: artifact, type: activeType }),
      });

      await pipelinePromise;

      if (!res.ok) {
        var errData;
        try { errData = await res.json(); } catch (_) { errData = { error: 'Analysis failed (' + res.status + ')' }; }
        completePipeline();
        var st = document.getElementById('ic-pipeline-status');
        if (st) st.textContent = 'Failed';
        showToast(errData.error || 'Analysis failed.', 'error');
        btn.disabled = false;
        btn.innerHTML = ' Analyze';
        return;
      }

      var data = await res.json();
      completePipeline();
      var bar = document.querySelector('.ic-btn-bar');
      if (bar) bar.style.width = '100%';
      var st = document.getElementById('ic-pipeline-status');
      if (st) st.textContent = 'Completed';

      await sleep(400);

      currentInvestigationId = data.investigation_id;
      document.getElementById('ic-dashboard').setAttribute('aria-busy', 'false');
      syncCopilotVisibility();

      populateEvidenceBar(artifact);
      populateVerdictBanner(data);
      populateExecutiveSummary(data);
      populateDashboardRecs(data);
      populateDashboardIOC(data);
      populateDashboardMITRE(data);
      populateDashboardTI(data);
      populateEvidenceLegend(data);
      populateDashboardTimeline(data);
      populateDashboardRaw(data);
      renderRiskAssessment(data);
      populateAnalystState(data);

      loadHistory();
      loadInvestigateSuggestions();
      showToast('Investigation complete.', 'success');

    } catch (e) {
      console.error('Investigation error:', e);
      completePipeline();
      var st2 = document.getElementById('ic-pipeline-status');
      if (st2) st2.textContent = 'Error';
      showToast('Network error. Please try again.', 'error');
    }

    btn.disabled = false;
    btn.innerHTML = ' Analyze';
  };

  // ── Evidence toggle / New Analysis ──

  window.toggleEvidence = function () {
    var expanded = document.getElementById('ic-evidence-expanded');
    var toggle = document.getElementById('ic-evidence-toggle');
    var bar = document.getElementById('ic-evidence-bar');
    if (!expanded) return;
    var isHidden = expanded.style.display === 'none';
    expanded.style.display = isHidden ? '' : 'none';
    if (toggle) toggle.textContent = isHidden ? '▼' : '▶';
    if (bar) bar.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
  };

  window.toggleRawFindings = function () {
    var wrap = document.getElementById('ic-dash-raw-body-wrap');
    var toggle = document.getElementById('ic-raw-toggle');
    var hdr = document.querySelector('#ic-dash-raw .ic-dash-hdr');
    if (!wrap) return;
    var isHidden = wrap.style.display === 'none';
    wrap.style.display = isHidden ? '' : 'none';
    if (toggle) toggle.textContent = isHidden ? '▼' : '▶';
    if (hdr) hdr.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
  };

  window.newAnalysis = function () {
    currentInvestigationId = null;
    syncCopilotVisibility();
    _evidenceText = '';
    hideDashboard();
    var firstType = document.querySelector('.ic-type-item');
    if (firstType) {
      document.querySelectorAll('.ic-type-item').forEach(function (i) { i.classList.remove('active'); });
      firstType.classList.add('active');
      activeType = firstType.getAttribute('data-type') || 'auto';
    }
    document.getElementById('ic-empty-state').style.display = '';
    document.getElementById('ic-pipeline').style.display = 'none';
    document.getElementById('ic-editor').value = '';
    updateCharCount();
    autoExpandTextarea();
    if (window.innerWidth < 768) {
      var mh = document.getElementById('ic-mobile-hint');
      if (mh) mh.style.display = '';
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
    var mt = document.getElementById('ic-mobile-types');
    if (mt) mt.scrollLeft = 0;
    setTimeout(function () { document.getElementById('ic-editor').focus(); }, 300);
  };

  // ── Dashboard population ──

  function populateEvidenceBar(text) {
    var preview = document.getElementById('ic-evidence-preview');
    var content = document.getElementById('ic-evidence-content');
    if (preview) preview.textContent = (text || '').slice(0, 80) + ((text || '').length > 80 ? '…' : '');
    if (content) content.textContent = text || '';
    var expanded = document.getElementById('ic-evidence-expanded');
    var toggle = document.getElementById('ic-evidence-toggle');
    if (expanded) expanded.style.display = 'none';
    if (toggle) toggle.textContent = '▶';
  }

  function populateVerdictBanner(data) {
    var risk = data.risk || {};
    var analysis = data.analysis || {};
    var severity = (risk.severity || analysis.severity || 'unknown').toLowerCase();
    var confidence = risk.confidence || 0;
    var category = risk.threat_category || analysis.verdict || 'Inconclusive';
    var verdict = analysis.verdict || 'Analyzed';
    var iocCount = risk.ioc_count || data.ioc_count || 0;

    var badgeEl = document.getElementById('ic-vb-severity');
    var verdictEl = document.getElementById('ic-vb-verdict');
    var confEl = document.getElementById('ic-vb-confidence');
    var threatEl = document.getElementById('ic-vb-threat');
    var iocEl = document.getElementById('ic-vb-ioc-count');

    var severityColor = severity === 'critical' ? '#FF4757' : severity === 'high' ? '#FF6348' : severity === 'medium' ? '#FFA502' : severity === 'low' ? '#00FF88' : '#555570';

    if (badgeEl) {
      badgeEl.textContent = severity.toUpperCase();
      badgeEl.className = 'ic-vb-badge severity-' + severity;
    }
    if (verdictEl) {
      verdictEl.textContent = typeof verdict === 'string' ? verdict.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); }) : '—';
      verdictEl.style.color = severityColor;
    }
    if (confEl) confEl.textContent = (typeof confidence === 'number' ? confidence : 0) + '%';
    if (threatEl) threatEl.textContent = typeof category === 'string' ? category : 'Inconclusive';
    if (iocEl) iocEl.textContent = iocCount;
  }

  function populateExecutiveSummary(data) {
    var body = document.getElementById('ic-dash-exec-body');
    if (!body) return;
    var analysis = data.analysis || {};
    var text = analysis.summary || data.report || '';
    body.innerHTML = text ? '<p>' + escapeHtml(text) + '</p>' : '<p style="color:var(--ic-text-muted);font-style:italic;">No executive summary available.</p>';
  }

  function populateDashboardIOC(data) {
    var iocs = data.iocs || {};
    var iocsDefanged = data.iocs_defanged || {};
    var summaryEl = document.getElementById('ic-dash-ioc-summary');
    var chipsEl = document.getElementById('ic-dash-ioc-chips');
    var badgeEl = document.getElementById('ic-dash-ioc-badge');
    if (!summaryEl) return;

    var sections = [
      { key: 'ips', icon: '🌐', label: 'IPs' },
      { key: 'domains', icon: '🌍', label: 'Domains' },
      { key: 'urls', icon: '🔗', label: 'URLs' },
      { key: 'hashes', icon: '🔑', label: 'Hashes' },
      { key: 'emails', icon: '📧', label: 'Emails' },
    ];

    var total = 0;
    var sumHtml = '';
    sections.forEach(function (s) {
      var items = iocs[s.key] || [];
      total += items.length;
      sumHtml += '<div class="ic-ioc-summary-card"><div class="isc-icon">' + s.icon + '</div><div class="isc-count">' + items.length + '</div><div class="isc-label">' + s.label + '</div></div>';
    });
    summaryEl.innerHTML = sumHtml;
    if (badgeEl) badgeEl.textContent = total;

    if (total === 0) {
      chipsEl.innerHTML = '<div class="ic-ioc-empty">No indicators extracted.</div>';
      return;
    }

    var chipHtml = '';
    sections.forEach(function (s) {
      var items = iocs[s.key] || [];
      var defanged = iocsDefanged[s.key] || [];
      if (items.length === 0) return;
      chipHtml += '<div class="ic-ioc-group"><div class="ic-ioc-hdr">' + s.icon + ' ' + s.label + ' <span class="cnt">(' + items.length + ')</span></div>';
      items.forEach(function (item, idx) {
        var display = defanged[idx] || item;
        chipHtml += '<span class="ic-ioc-chip" data-action="copyToClipboard" data-encoded="' + encodeURIComponent(display) + '" title="Click to copy">' + escapeHtml(display) + '<span class="copy-icon">📋</span></span>';
      });
      chipHtml += '</div>';
    });
    chipsEl.innerHTML = chipHtml;
  }

  function populateDashboardMITRE(data) {
    var techniques = data.mitre_techniques || [];
    var grid = document.getElementById('ic-dash-mitre-grid');
    var badge = document.getElementById('ic-dash-mitre-badge');
    if (!grid) return;

    if (techniques.length === 0) {
      grid.innerHTML = '<div style="text-align:center;padding:12px;color:var(--ic-text-muted);font-size:12px;grid-column:1/-1;">No MITRE ATT&CK techniques identified.</div>';
      if (badge) badge.textContent = '0';
      return;
    }

    var tacticMap = { 'T1566':'Initial Access','T1110':'Credential Access','T1059':'Execution','T1071':'Command & Control','T1003':'Credential Access','T1486':'Impact','T1190':'Initial Access','T1204':'Execution','T1021':'Lateral Movement','T1046':'Discovery','T1053':'Execution','T1068':'Privilege Escalation','T1090':'Command & Control','T1105':'Command & Control','T1134':'Privilege Escalation','T1203':'Execution','T1210':'Lateral Movement','T1498':'Impact','T1055':'Defense Evasion','T1036':'Defense Evasion','T1202':'Defense Evasion','T1562':'Defense Evasion','T1001':'Command & Control','T1573':'Command & Control','T1568':'Command & Control','T1095':'Command & Control' };

    var html = '';
    techniques.forEach(function (t) {
      var tid = t.id || '';
      var name = t.name || 'Unknown';
      var tactic = tacticMap[tid] || (tid ? 'Unknown Tactic' : '');
      html += '<div class="ic-dash-mitre-card"><div><div class="dmt-tactic">' + (tactic ? escapeHtml(tactic) : '&nbsp;') + '</div><div class="dmt-tech">' + escapeHtml(name) + '</div></div>' + (tid ? '<div class="dmt-id">' + escapeHtml(tid) + '</div>' : '') + '</div>';
    });
    grid.innerHTML = html;
    if (badge) badge.textContent = techniques.length;
  }

  function populateDashboardTI(data) {
    var ti = data.threat_intel || {};
    var body = document.getElementById('ic-dash-ti-body');
    var badge = document.getElementById('ic-dash-ti-badge');
    if (!body) return;

    var abuse = ti.abuseipdb || [];
    var vt = ti.virustotal || [];
    var total = abuse.length + vt.length;

    if (total === 0) {
      body.innerHTML = '<div style="text-align:center;padding:12px;color:var(--ic-text-muted);font-size:12px;">No threat intelligence data available.</div>';
      if (badge) badge.textContent = '0';
      return;
    }

    var html = '';
    abuse.forEach(function (entry) {
      var ip = entry.ip || 'unknown';
      var result = entry.result || {};
      var d2 = result.data || {};
      var score = d2.abuseConfidenceScore || 0;
      var reports = d2.totalReports || 0;
      var country = d2.countryCode || '--';
      var color = score > 80 ? '#FF4757' : score > 50 ? '#FFA502' : score > 0 ? '#00FF88' : '#555570';
      html += '<div class="ic-ti-entry"><div class="ic-ti-source">' + escapeHtml(ip) + '</div><div class="ic-ti-stats"><span class="ic-ti-stat" style="color:' + color + '">⚠ Score: ' + score + '</span><span class="ic-ti-stat">📊 Reports: ' + reports + '</span><span class="ic-ti-stat">🌍 ' + country + '</span></div></div>';
    });
    vt.forEach(function (entry) {
      var ip = entry.ip || 'unknown';
      var result = entry.result || {};
      var d2 = result.data || {};
      var attrs = d2.attributes || {};
      var stats = attrs.last_analysis_stats || {};
      var malicious = stats.malicious || 0;
      var suspicious = stats.suspicious || 0;
      var harmless = stats.harmless || 0;
      var total2 = malicious + suspicious + harmless + (stats.undetected || 0);
      var vcolor = malicious > 0 ? '#FF4757' : suspicious > 0 ? '#FFA502' : '#00FF88';
      html += '<div class="ic-ti-entry"><div class="ic-ti-source">' + escapeHtml(ip) + ' <span style="font-weight:400;font-size:10px;color:var(--ic-text-muted)">[VirusTotal]</span></div><div class="ic-ti-stats"><span class="ic-ti-stat" style="color:' + vcolor + '">🛡️ ' + malicious + '/' + total2 + ' malicious</span><span class="ic-ti-stat" style="color:#FFA502">⚠ ' + suspicious + ' suspicious</span></div></div>';
    });

    body.innerHTML = html;
    if (badge) badge.textContent = total;
  }

  function populateEvidenceLegend(data) {
    var body = document.getElementById('ic-dash-evidence-body');
    var badge = document.getElementById('ic-dash-evidence-badge');
    if (!body) return;

    var evidence = data.evidence || [];
    if (evidence.length === 0) {
      body.innerHTML = '<p style="color:var(--ic-text-muted);font-style:italic;margin:0;">No structured evidence was collected for this investigation.</p>';
      if (badge) badge.textContent = '0';
      return;
    }

    body.innerHTML = evidence.map(function (item) {
      var id = item.id || 'E-??';
      var type = item.type || 'Evidence';
      var detail = item.detail || '';
      return '<div class="ic-evidence-item">'
        + '<span class="ic-evidence-id">' + escapeHtml(id) + '</span>'
        + '<span class="ic-evidence-type">' + escapeHtml(type) + '</span>'
        + '<span class="ic-evidence-detail">' + escapeHtml(detail) + '</span>'
        + '</div>';
    }).join('');
    if (badge) badge.textContent = evidence.length;
  }

  function statusChipClass(status) {
    return 'ic-status-chip--' + String(status || 'New').toLowerCase().replace(/\s+/g, '-');
  }

  function populateAnalystState(data) {
    var chip = document.getElementById('ic-analyst-status-chip');
    var select = document.getElementById('ic-analyst-status');
    var notes = document.getElementById('ic-analyst-notes');
    var saveBtn = document.getElementById('ic-analyst-save');
    var status = data.analyst_status || 'New';
    if (chip) {
      chip.textContent = status;
      chip.className = 'ic-dash-status-chip ' + statusChipClass(status);
    }
    if (select && select.value !== status) select.value = status;
    if (notes) notes.value = data.analyst_notes || '';
    if (saveBtn) saveBtn.disabled = false;
  }

  window.analystStatusChange = function () {
    var select = document.getElementById('ic-analyst-status');
    var chip = document.getElementById('ic-analyst-status-chip');
    if (!select || !chip) return;
    chip.textContent = select.value;
    chip.className = 'ic-dash-status-chip ' + statusChipClass(select.value);
  };

  window.saveAnalystState = async function () {
    if (!currentInvestigationId) { showToast('No investigation to update.', 'error'); return; }
    var select = document.getElementById('ic-analyst-status');
    var notes = document.getElementById('ic-analyst-notes');
    var saveBtn = document.getElementById('ic-analyst-save');
    var status = select ? select.value : 'New';
    if (saveBtn) saveBtn.disabled = true;
    try {
      var res = await fetch('/api/investigate/' + currentInvestigationId, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ status: status, notes: notes ? notes.value : '' }),
      });
      if (!res.ok) throw new Error('save failed with ' + res.status);
      var data = await res.json();
      populateAnalystState({ analyst_status: data.analyst_status, analyst_notes: data.analyst_notes });
      showToast('Analyst status saved.', 'success');
      loadHistory();
    } catch (e) {
      console.error('Analyst save error:', e);
      showToast('Could not save analyst state.', 'error');
    } finally {
      if (saveBtn) saveBtn.disabled = false;
    }
  };

  function populateDashboardRecs(data) {
    var body = document.getElementById('ic-dash-recs-body');
    if (!body) return;

    var recs = [];
    var analysis = data.analysis || {};
    var summary = analysis.summary || '';

    if (summary) {
      var lines = summary.split('\n');
      lines.forEach(function (line) {
        var t = line.trim();
        if (t.match(/^\d+[\.\)]/) || t.match(/^[-*]/) || t.match(/^(recommend|suggest|ensure|implement|use|enable|configure|review|investigate|block|monitor|patch|update|restrict)/i)) {
          recs.push(t.replace(/^[\d\.\-\*\s]+/, '').trim());
        }
      });
    }

    if (recs.length === 0) {
      var verdict = analysis.verdict || 'inconclusive';
      var sev = analysis.severity || 'low';
      recs.push('Review the investigation report for full details.');
      if (sev !== 'low') recs.push('Block any identified malicious indicators.');
      recs.push('Monitor affected systems for suspicious activity.');
      if (verdict === 'likely_malicious') recs.push('Escalate to incident response team if not already engaged.');
    }

    body.innerHTML = recs.slice(0, 8).map(function (r, i) {
      return '<div class="ic-dash-rec"><div class="ic-dash-rec-num">' + (i + 1) + '</div><div class="ic-dash-rec-text">' + escapeHtml(r) + '</div></div>';
    }).join('') || '<div style="text-align:center;padding:12px;color:var(--ic-text-muted);font-size:12px;">No recommendations available.</div>';
  }

  function populateDashboardTimeline(data) {
    var body = document.getElementById('ic-dash-timeline');
    if (!body) return;

    var analysis = data.analysis || {};
    var summary = analysis.summary || '';
    var verdict = analysis.verdict || 'inconclusive';
    var severity = analysis.severity || 'low';
    var now = new Date();

    var events = [
      { time: toTimeStr(new Date(now - 7000)), text: 'Evidence submitted for investigation', cls: '' },
    ];

    if (summary) {
      var lines = summary.split('\n').filter(function (l) { return l.trim().length > 0; });
      lines.forEach(function (line, i) {
        var t = line.trim();
        if (t.length > 10 && i < 5) {
          var ts = new Date(now - (lines.length - i) * 2000);
          var cls = '';
          if (/fail|block|malicious|attack|breach|comprom/i.test(t)) cls = ' malicious';
          else if (/suspicious|anomal|unusual|warning/i.test(t)) cls = ' suspicious';
          else if (/success|clean|benign|resolved|mitigat/i.test(t)) cls = ' benign';
          events.push({ time: toTimeStr(ts), text: t.slice(0, 120) + (t.length > 120 ? '…' : ''), cls: cls });
        }
      });
    }

    events.push({ time: toTimeStr(now), text: 'Investigation completed — Verdict: ' + verdict + ', Severity: ' + severity, cls: verdict === 'likely_malicious' ? ' malicious' : verdict === 'benign' ? ' benign' : '' });

    body.innerHTML = events.map(function (e) {
      return '<div class="ic-dash-tl-item' + e.cls + '"><div class="ic-dash-tl-time">' + e.time + '</div><div class="ic-dash-tl-text">' + escapeHtml(e.text) + '</div></div>';
    }).join('');
  }

  function populateDashboardRaw(data) {
    var report = data.report || '';
    var analysis = data.analysis || {};
    var verdict = analysis.verdict || 'inconclusive';
    var severity = analysis.severity || 'low';
    var summary = analysis.summary || '';

    var body = document.getElementById('ic-dash-raw-body');
    var badge = document.getElementById('ic-dash-verdict-badge');
    if (!body || !badge) return;

    badge.textContent = verdict + ' · ' + severity;
    badge.className = 'badge ' + severity;

    body.textContent = report || summary || 'No report generated.';

    var exportBar = document.getElementById('ic-dash-export-bar');
    if (currentInvestigationId) {
      var mdEl = document.getElementById('ic-dash-export-md');
      var jsonEl = document.getElementById('ic-dash-export-json');
      if (mdEl) mdEl.href = '/api/investigate/' + currentInvestigationId + '/export/md';
      if (jsonEl) jsonEl.href = '/api/investigate/' + currentInvestigationId + '/export/json';
      if (exportBar) exportBar.style.display = '';
    } else {
      if (exportBar) exportBar.style.display = 'none';
    }
  }

  // ── Risk Assessment (right panel) ──

  function renderRiskAssessment(data) {
    var risk = data.risk || {};
    var score = risk.score || 0;
    var severity = risk.severity || 'unknown';
    var confidence = risk.confidence || 0;
    var category = risk.threat_category || 'Inconclusive';
    var iocCount = risk.ioc_count || 0;

    var body = document.getElementById('ic-risk-body');
    var badge = document.getElementById('ic-risk-badge');
    if (!body) return;
    if (badge) { badge.textContent = severity.toUpperCase(); badge.className = 'badge ' + severity; }

    var circumference = 2 * Math.PI * 28;
    var offset = circumference - (score / 100) * circumference;
    var severityColor = severity === 'critical' ? '#FF4757' : severity === 'high' ? '#FF6348' : severity === 'medium' ? '#FFA502' : severity === 'low' ? '#00FF88' : '#555570';

    // Confidence is a separate evidence-strength metric, so it uses its own
    // blue/indigo scale rather than the red→green severity palette.
    var confColor = confidence >= 70 ? '#4DA3FF' : confidence >= 40 ? '#8B7CF6' : '#5A5A75';
    var confLabel = confidence >= 70 ? 'High' : confidence >= 40 ? 'Medium' : 'Low';

    body.innerHTML = '<div class="ic-risk-score">'
      + '<div class="ic-risk-ring">'
      + '<svg width="72" height="72" viewBox="0 0 72 72">'
      + '<circle class="rbg" cx="36" cy="36" r="28"/>'
      + '<circle class="rfg" cx="36" cy="36" r="28" style="stroke:' + severityColor + ';stroke-dasharray:' + circumference + ';stroke-dashoffset:' + offset + '"/>'
      + '</svg>'
      + '<div class="ic-risk-num" style="color:' + severityColor + '">' + score + '</div>'
      + '</div>'
      + '<div class="ic-risk-label" style="color:' + severityColor + '">' + severity.toUpperCase() + '</div>'
      + '</div>'
      + '<div class="ic-risk-conf">'
      + '<div class="ic-risk-conf-hdr"><span class="ic-risk-conf-lbl">Confidence</span><span class="ic-risk-conf-val" style="color:' + confColor + '">' + confidence + '% · ' + confLabel + '</span></div>'
      + '<div class="ic-risk-conf-track"><div class="ic-risk-conf-fill" style="width:' + Math.max(4, Math.min(100, confidence)) + '%;background:' + confColor + ';"></div></div>'
      + '</div>'
      + '<div class="ic-risk-grid">'
      + '<div class="ic-risk-cell"><div class="lbl">IOCs</div><div class="val">' + iocCount + '</div></div>'
      + '<div class="ic-risk-cell"><div class="lbl">Category</div><div class="val" style="font-size:11px">' + escapeHtml(category) + '</div></div>'
      + '<div class="ic-risk-cell"><div class="lbl">Source</div><div class="val" style="font-size:11px">' + (data.from_cache ? 'Cached' : 'Fresh') + '</div></div>'
      + '<div class="ic-risk-cell"><div class="lbl">Evidence</div><div class="val">' + confidence + '%</div></div>'
      + '</div>';
  }

  // ── Print ──

  window.printReport = function () {
    var report = document.getElementById('ic-dash-raw-body');
    if (!report || !report.textContent) return;
    var win = window.open('', '_blank');
    if (!win) { showToast('Please allow popups for printing.', 'error'); return; }
    win.document.write('<html><head><title>Investigation Report</title>');
    win.document.write('<style>body{font-family:monospace;font-size:13px;line-height:1.7;padding:40px;white-space:pre-wrap;max-width:800px;margin:0 auto;color:#222;}</style>');
    win.document.write('</head><body>');
    win.document.write('<pre style="white-space:pre-wrap;word-wrap:break-word;">' + escapeHtml(report.textContent) + '</pre>');
    win.document.write('</body></html>');
    win.document.close();
    win.print();
  };

  // ── History ──

  async function loadHistory() {
    var container = document.getElementById('ic-hist-list');
    if (!container) return;
    try {
      var res = await fetch('/api/investigate/history', { credentials: 'include' });
      if (!res.ok) return;
      var data = await res.json();
      var items = data.history || [];
      if (items.length === 0) {
        container.innerHTML = '<div class="ic-hist-empty">No investigations yet.<br>Run your first analysis above.</div>';
        return;
      }
      container.innerHTML = items.slice(0, 25).map(function (h) {
        var time = formatHistTime(h.created_at);
        var sev = (h.severity || 'low').toLowerCase();
        var d = new Date(h.created_at);
        var dateStr = d.toLocaleDateString();
        var iocCount = h.ioc_count || 0;
        var status = h.analyst_status || 'New';
        return '<div class="ic-hist-item" data-action="loadInvestigation" data-inv-id="' + h.id + '">'
          + '<div class="h-sev ' + sev + '"></div>'
          + '<div class="h-info"><div class="h-verdict">' + escapeHtml(h.verdict || '—')
          + ' <span class="ic-status-chip ' + statusChipClass(status) + '">' + escapeHtml(status) + '</span></div>'
          + '<div class="h-meta"><span>' + dateStr + '</span><span>' + time + '</span><span>' + iocCount + ' IOCs</span></div></div>'
          + '<button class="ic-hist-delete" data-action="deleteInvestigation" data-inv-id="' + h.id + '" title="Delete">✕</button>'
          + '</div>';
      }).join('');
    } catch (e) { console.warn('Could not load history:', e); }
  }

  function formatHistTime(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
  }

  window.loadInvestigation = async function (id) {
    try {
      var res = await fetch('/api/investigate/' + id, { credentials: 'include' });
      if (!res.ok) { showToast('Investigation not found.', 'error'); return; }
      var data = await res.json();
      currentInvestigationId = id;
      syncCopilotVisibility();

      document.getElementById('ic-empty-state').style.display = 'none';
      document.getElementById('ic-pipeline').style.display = 'none';
      showDashboard();

      var sev = data.severity || 'low';
      var verdict = data.verdict || 'inconclusive';
      var scoreMap = { critical: 90, high: 70, medium: 50, low: 20 };
      var catMap = { likely_malicious: 'Suspicious Activity', suspicious: 'Anomalous Behavior', benign: 'Benign' };
      var iocCount = data.ioc_count || 0;

      var riskData = {
        risk: { score: scoreMap[sev] || 0, severity: sev, confidence: data.confidence || 0, threat_category: catMap[verdict] || 'Inconclusive', ioc_count: iocCount },
        from_cache: false,
      };
      var reportText = data.report || '';

      populateEvidenceBar(reportText.slice(0, 300));
      populateVerdictBanner(riskData);
      populateExecutiveSummary({ analysis: { summary: reportText.slice(0, 500) } });
      populateDashboardRecs({ analysis: { summary: reportText.slice(0, 500), verdict: verdict, severity: sev } });
      populateDashboardIOC(data);
      populateDashboardMITRE(data);
      populateDashboardTI(data);
      populateEvidenceLegend(data);
      populateDashboardTimeline({ analysis: { summary: reportText.slice(0, 300), verdict: verdict, severity: sev }, from_cache: true });
      populateDashboardRaw({ report: reportText, analysis: { verdict: verdict, severity: sev, summary: '' } });
      renderRiskAssessment(riskData);
      populateAnalystState(data);

    } catch (e) { console.error('Error loading investigation:', e); showToast('Error loading investigation.', 'error'); }
  };

  window.deleteInvestigation = async function (id) {
    if (!confirm('Delete this investigation?')) return;
    try {
      var res = await fetch('/api/investigate/' + id, { method: 'DELETE', credentials: 'include' });
      if (!res.ok) { showToast('Could not delete.', 'error'); return; }
      showToast('Investigation deleted.', 'success');
      loadHistory();
      if (currentInvestigationId === id) {
        currentInvestigationId = null;
        syncCopilotVisibility();
        _evidenceText = '';
        hideDashboard();
        document.getElementById('ic-pipeline').style.display = 'none';
        document.getElementById('ic-empty-state').style.display = '';
      }
    } catch (e) { showToast('Error deleting.', 'error'); }
  };

  // ── Clipboard ──

  window.copyToClipboard = function (encoded) {
    var text = decodeURIComponent(encoded);
    navigator.clipboard.writeText(text).then(function () {
      showToast('Copied to clipboard', 'success');
    }).catch(function () {
      var ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('Copied to clipboard', 'success');
    });
  };

  // ── Toast ──

  function showToast(msg, type) {
    var toast = document.getElementById('ic-toast');
    if (!toast) return;
    toast.textContent = msg;
    toast.className = 'ic-toast ' + (type || '') + ' show';
    clearTimeout(toast._hide);
    toast._hide = setTimeout(function () { toast.classList.remove('show'); }, 3000);
  }
  window.showToast = showToast;

  // ── Helpers ──

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function escapeHtml(str) {
    if (typeof str !== 'string') return String(str || '');
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function toTimeStr(d) {
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  // ── Dynamic Prompt Suggestions ──

  var SUGGESTION_BANK = window.SUGGESTION_BANK || [
    'Check if 45.77.65.211 is known to be malicious',
    'Analyze this phishing email: "Your account will be suspended..."',
    'Review firewall log for SQL injection attempts',
    'Look up the domain example-evil.com reputation',
    'Analyze malware behavior in this report',
    'Investigate this suspicious URL for credential harvesting',
    'Triage this auth log for brute-force activity',
    'Scan this log for data exfiltration indicators',
    'Check this PowerShell command line for abuse',
    'Analyze this suspicious file hash',
  ];
  window.SUGGESTION_BANK = SUGGESTION_BANK;

  window.loadInvestigateSuggestions = async function () {
    var wrap = document.getElementById('ic-suggest-chips');
    if (!wrap) return;
    var items = SUGGESTION_BANK.slice(0, 4);
    if (!items.length) { wrap.innerHTML = ''; return; }
    wrap.innerHTML = items.map(function (text, i) {
      var encoded = encodeURIComponent(text);
      return '<span class="dyn-suggest-chip dsc-d' + (i + 1) + '" data-action="loadInvestigateSuggestion" data-text="' + encoded + '" title="' + escapeHtml(text) + '"><span class="dsc-icon">🔎</span>' + escapeHtml(text) + '</span>';
    }).join('');
  };

  window.loadInvestigateSuggestion = function (text) {
    var editor = document.getElementById('ic-editor');
    var decoded = typeof text === 'string' && text.indexOf('%') !== -1 ? decodeURIComponent(text) : text;
    if (editor) { editor.value = decoded; editor.focus(); updateCharCount(); }
  };

  // ── Investigation-grounded AI Copilot ──

  function syncCopilotVisibility() {
    var card = document.getElementById('ic-copilot-card');
    if (!card) return;
    card.style.display = currentInvestigationId ? '' : 'none';
  }
  window.syncCopilotVisibility = syncCopilotVisibility;

  function copilotAddMsg(role, text) {
    var box = document.getElementById('ic-copilot-msgs');
    if (!box) return null;
    var wrap = document.createElement('div');
    wrap.className = 'ic-copilot-msg ' + role;
    var avatar = document.createElement('span');
    avatar.className = 'cp-avatar';
    avatar.textContent = role === 'user' ? '👤' : '🤖';
    var bubble = document.createElement('div');
    bubble.className = 'cp-bubble';
    bubble.textContent = text;
    wrap.appendChild(avatar);
    wrap.appendChild(bubble);
    box.appendChild(wrap);
    box.scrollTop = box.scrollHeight;
    return bubble;
  }

  function copilotSetBusy(busy) {
    var btn = document.querySelector('.ic-copilot-send');
    if (btn) btn.disabled = busy;
  }

  window.sendCopilotQuestion = async function (question) {
    question = (question || '').trim();
    if (!question || !currentInvestigationId) return;
    var input = document.getElementById('ic-copilot-input');
    if (input) input.value = '';
    copilotAddMsg('user', question);
    var thinking = copilotAddMsg('thinking', 'Thinking');
    if (thinking) thinking.classList.add('thinking');
    copilotSetBusy(true);

    var res;
    try {
      res = await fetch('/api/investigate/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ investigation_id: currentInvestigationId, question: question }),
      });
    } catch (e) {
      if (thinking) { thinking.classList.remove('thinking'); thinking.textContent = 'Network error. Please try again.'; thinking.parentElement.classList.add('error'); }
      copilotSetBusy(false);
      return;
    }

    if (!res.ok || !res.headers.get('content-type') || res.headers.get('content-type').indexOf('text/event-stream') === -1) {
      var errData = {};
      try { errData = await res.json(); } catch (_) {}
      if (thinking) { thinking.classList.remove('thinking'); thinking.textContent = errData.error || ('Request failed (' + res.status + ').'); thinking.parentElement.classList.add('error'); }
      copilotSetBusy(false);
      return;
    }

    var reader = res.body.getReader();
    var decoder = new TextDecoder();
    var buffer = '';
    var done = false;
    try {
      while (!done) {
        var r = await reader.read();
        if (r.done) { done = true; break; }
        buffer += decoder.decode(r.value, { stream: true });
        var parts = buffer.split('\n\n');
        buffer = parts.pop();
        for (var i = 0; i < parts.length; i++) {
          var line = parts[i];
          if (line.indexOf('data:') !== 0) continue;
          var jsonStr = line.slice(5).trim();
          if (!jsonStr) continue;
          var evt;
          try { evt = JSON.parse(jsonStr); } catch (_) { continue; }
          if (evt.error) {
            if (thinking) { thinking.classList.remove('thinking'); thinking.textContent = evt.error; thinking.parentElement.classList.add('error'); }
            done = true; break;
          }
          if (evt.done) { done = true; break; }
          if (evt.token && thinking) {
            thinking.classList.remove('thinking');
            thinking.textContent += evt.token;
          }
        }
      }
    } catch (e) {
      if (thinking) { thinking.classList.remove('thinking'); thinking.textContent = 'Connection interrupted. Please try again.'; thinking.parentElement.classList.add('error'); }
    }
    copilotSetBusy(false);
    var box = document.getElementById('ic-copilot-msgs');
    if (box) box.scrollTop = box.scrollHeight;
  };

  document.addEventListener('DOMContentLoaded', function () {
    var form = document.getElementById('ic-copilot-form');
    var input = document.getElementById('ic-copilot-input');
    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (input && input.value.trim()) sendCopilotQuestion(input.value);
      });
    }
    if (input) {
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          if (input.value.trim()) sendCopilotQuestion(input.value);
        }
      });
      input.addEventListener('input', function () {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 84) + 'px';
      });
    }
  });

})();
(function () {
  'use strict';

  var IS_MOBILE = window.innerWidth < 768;
  if (!IS_MOBILE) return;

  /* ── shared state (mirrors desktop) ── */
  var activeType = 'auto';
  var _evidenceText = '';
  var currentInvestigationId = null;

  var PIPELINE_STEPS = [
    { id: 'mob-ps-1', label: 'Extracting Indicators' },
    { id: 'mob-ps-2', label: 'Parsing Evidence' },
    { id: 'mob-ps-3', label: 'Threat Intel Lookup' },
    { id: 'mob-ps-4', label: 'MITRE Mapping' },
    { id: 'mob-ps-5', label: 'Risk Assessment' },
    { id: 'mob-ps-6', label: 'AI Analysis' },
    { id: 'mob-ps-7', label: 'Report Generation' },
  ];

  var PLACEHOLDERS = {
    auto:           'Paste a URL, IP, domain, email headers, log, hash…',
    url:            'Paste a suspicious URL to analyze…',
    phishing_email: 'Paste email headers or full phishing content…',
    log:            'Paste firewall, IDS, or auth log entries…',
    malware:        'Paste malware report or describe behavior…',
    ioc:            'Paste hashes, IPs, domains, or URLs…',
    domain:         'Enter a domain name to investigate…',
    ip:             'Enter an IP address to check…',
  };

  /* ── helpers ── */
  function $(id) { return document.getElementById(id); }
  function escHtml(s) {
    if (typeof s !== 'string') return String(s || '');
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function sleep(ms) { return new Promise(function(r){ setTimeout(r, ms); }); }

  /* ── screen transitions ── */
  function showReportScreen() {
    var inp = $('mob-input-screen');
    var rep = $('mob-report-screen');
    if (!inp || !rep) return;
    inp.setAttribute('aria-hidden', 'true');
    rep.setAttribute('aria-hidden', 'false');
    rep.classList.add('mob-screen--visible');
    inp.classList.remove('mob-screen--visible');
    /* scroll report to top */
    var scroll = $('mob-report-scroll');
    if (scroll) scroll.scrollTop = 0;
  }

  function showInputScreen() {
    var inp = $('mob-input-screen');
    var rep = $('mob-report-screen');
    if (!inp || !rep) return;
    inp.setAttribute('aria-hidden', 'false');
    rep.setAttribute('aria-hidden', 'true');
    inp.classList.add('mob-screen--visible');
    rep.classList.remove('mob-screen--visible');
  }

  /* ── type tabs ── */
  window.mobSelectType = function (type, el) {
    activeType = type;
    document.querySelectorAll('#mob-input-screen .mob-tab').forEach(function(t) {
      t.classList.remove('mob-tab--active');
      t.setAttribute('aria-selected', 'false');
    });
    if (el) {
      el.classList.add('mob-tab--active');
      el.setAttribute('aria-selected', 'true');
    }
    var ta = $('mob-textarea');
    if (ta) {
      ta.placeholder = PLACEHOLDERS[type] || PLACEHOLDERS.auto;
      ta.focus();
    }
  };

  /* ── textarea auto-expand ── */
  function mobAutoExpand() {
    var ta = $('mob-textarea');
    if (!ta) return;
    ta.style.height = 'auto';
    var next = Math.max(120, Math.min(ta.scrollHeight, 220));
    ta.style.height = next + 'px';
  }

  function mobUpdateCharCount() {
    var ta = $('mob-textarea');
    var cc = $('mob-char-count');
    if (!ta || !cc) return;
    var len = (ta.value || '').length;
    cc.textContent = len > 0 ? len + ' chars' : '';
  }

  window.mobOnInput = function () {
    mobAutoExpand();
    mobUpdateCharCount();
  };

  /* ── clear ── */
  window.mobClear = function () {
    var ta = $('mob-textarea');
    if (ta) { ta.value = ''; ta.focus(); }
    mobUpdateCharCount();
    mobAutoExpand();
  };

  /* ── file upload ── */
  window.mobFileLoad = function (e) {
    var file = e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function (ev) {
      var ta = $('mob-textarea');
      if (ta) { ta.value += (ev.target.result || ''); mobUpdateCharCount(); mobAutoExpand(); }
      showToast('File loaded: ' + file.name, 'success');
    };
    reader.onerror = function () { showToast('Could not read file.', 'error'); };
    reader.readAsText(file);
    e.target.value = '';
  };

  /* ── pipeline ── */
  function mobRenderPipeline() {
    var strip = $('mob-pipeline-strip');
    if (!strip) return;
    strip.innerHTML = PIPELINE_STEPS.map(function(s, i) {
      var sep = i > 0 ? '<span class="mob-pipe-sep" aria-hidden="true">›</span>' : '';
      return sep + '<span class="mob-pipe-step" id="' + s.id + '">'
        + '<span class="mob-pipe-dot">●</span>'
        + '<span class="mob-pipe-label">' + escHtml(s.label) + '</span>'
        + '</span>';
    }).join('');
  }

  function mobSetStep(id, status) {
    var el = $(id);
    if (!el) return;
    el.className = 'mob-pipe-step';
    var dot = el.querySelector('.mob-pipe-dot');
    if (status === 'running') {
      el.classList.add('mob-pipe-step--running');
      if (dot) dot.textContent = '◌';
      /* scroll it into view */
      el.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'smooth' });
    } else if (status === 'done') {
      el.classList.add('mob-pipe-step--done');
      if (dot) dot.textContent = '✓';
    }
  }

  function mobAnimatePipeline() {
    mobRenderPipeline();
    var bar = $('mob-analyze-btn');
    return new Promise(function(resolve) {
      var i = 0;
      function next() {
        if (i > 0) mobSetStep(PIPELINE_STEPS[i-1].id, 'done');
        if (i < PIPELINE_STEPS.length) {
          mobSetStep(PIPELINE_STEPS[i].id, 'running');
          i++;
          setTimeout(next, i === 1 ? 500 : i <= 4 ? 350 : 250);
        } else {
          resolve();
        }
      }
      next();
    });
  }

  function mobCompletePipeline() {
    PIPELINE_STEPS.forEach(function(s) { mobSetStep(s.id, 'done'); });
  }

  /* ── main analyze ── */
  window.mobRunInvestigation = async function () {
    var ta = $('mob-textarea');
    var artifact = ta ? ta.value.trim() : '';
    if (!artifact) {
      showToast('Paste evidence before analyzing.', 'error');
      if (ta) ta.focus();
      return;
    }
    _evidenceText = artifact;

    /* disable button */
    var btn = $('mob-analyze-btn');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span class="mob-btn-dots">Analyzing<span class="mob-dots"></span></span>';
    }

    /* show report screen immediately so pipeline is visible */
    mobRenderPipeline();
    showReportScreen();

    /* show verdict as pending */
    mobResetVerdict();

    var pipelinePromise = mobAnimatePipeline();

    try {
      var res = await fetch('/api/investigate/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ artifact: artifact, type: activeType }),
      });

      await pipelinePromise;
      mobCompletePipeline();

      if (!res.ok) {
        var errData;
        try { errData = await res.json(); } catch(_) { errData = { error: 'Analysis failed (' + res.status + ')' }; }
        showToast(errData.error || 'Analysis failed.', 'error');
        if (btn) { btn.disabled = false; btn.innerHTML = '🔍 Analyze'; }
        showInputScreen();
        return;
      }

      var data = await res.json();
      await sleep(300);

      currentInvestigationId = data.investigation_id;

      mobPopulateEvidence(artifact);
      mobPopulateVerdict(data);
      mobPopulateExecSummary(data);
      mobPopulateRecs(data);
      mobPopulateIOC(data);
      mobPopulateMITRE(data);
      mobPopulateTimeline(data);
      mobPopulateTI(data);
      mobPopulateRaw(data);

      showToast('Investigation complete.', 'success');

    } catch(err) {
      console.error('mob investigate error:', err);
      mobCompletePipeline();
      showToast('Network error. Please try again.', 'error');
      showInputScreen();
    }

    if (btn) { btn.disabled = false; btn.innerHTML = '🔍 Analyze'; }
  };

  /* ── back / new ── */
  window.mobBackToInput = function () {
    showInputScreen();
  };

  window.mobNewAnalysis = function () {
    currentInvestigationId = null;
    _evidenceText = '';
    var ta = $('mob-textarea');
    if (ta) { ta.value = ''; mobAutoExpand(); }
    mobUpdateCharCount();
    mobResetReport();
    showInputScreen();
    setTimeout(function() { if (ta) ta.focus(); }, 350);
  };

  /* ── evidence toggle ── */
  window.mobToggleEvidence = function () {
    var full = $('mob-evidence-full');
    var tog  = $('mob-evidence-toggle');
    var bar  = $('mob-evidence-bar');
    if (!full) return;
    var isOpen = full.classList.contains('mob-evidence-full--open');
    if (isOpen) {
      full.classList.remove('mob-evidence-full--open');
      if (tog) tog.textContent = '▶';
      if (bar) bar.setAttribute('aria-expanded', 'false');
    } else {
      full.classList.add('mob-evidence-full--open');
      if (tog) tog.textContent = '▼';
      if (bar) bar.setAttribute('aria-expanded', 'true');
    }
  };

  /* ── raw toggle ── */
  window.mobToggleRaw = function () {
    var wrap = $('mob-raw-wrap');
    var hdr  = $('mob-raw-hdr');
    var tog  = $('mob-raw-toggle');
    if (!wrap) return;
    var open = wrap.style.display !== 'none';
    wrap.style.display = open ? 'none' : '';
    if (tog) tog.textContent = open ? '▶' : '▼';
    if (hdr) hdr.setAttribute('aria-expanded', String(!open));
  };

  /* ── population helpers ── */
  function mobResetVerdict() {
    var sev = $('mob-vb-sev'); if (sev) { sev.textContent = '—'; sev.className = 'mob-vb-badge'; }
    var vrd = $('mob-vb-verdict'); if (vrd) { vrd.textContent = 'Analyzing…'; vrd.removeAttribute('style'); }
    var conf = $('mob-vb-conf'); if (conf) conf.textContent = '—';
    var thr  = $('mob-vb-threat'); if (thr) thr.textContent = '—';
    var iocs = $('mob-vb-iocs'); if (iocs) iocs.textContent = '0';
  }

  function mobResetReport() {
    mobResetVerdict();
    var exec = $('mob-exec-body'); if (exec) exec.innerHTML = '<p style="color:var(--ic-text-muted);font-style:italic;">Analysis results will appear here.</p>';
    var recs = $('mob-recs-body'); if (recs) recs.innerHTML = '';
    var isum = $('mob-ioc-summary'); if (isum) isum.innerHTML = '';
    var ioc  = $('mob-ioc-chips');  if (ioc) ioc.innerHTML = '';
    var mit  = $('mob-mitre-body'); if (mit) mit.innerHTML = '';
    var tl   = $('mob-timeline');   if (tl) tl.innerHTML = '';
    var ti   = $('mob-ti-body');    if (ti) ti.innerHTML = '';
    var raw  = $('mob-raw-body');   if (raw) raw.textContent = '';
    var rw   = $('mob-raw-wrap');   if (rw) rw.style.display = 'none';
    var rtog = $('mob-raw-toggle'); if (rtog) rtog.textContent = '▶';
  }

  function mobPopulateEvidence(text) {
    var prev = $('mob-evidence-preview'); if (prev) prev.textContent = (text || '').slice(0, 70) + ((text||'').length > 70 ? '…' : '');
    var cont = $('mob-evidence-content'); if (cont) cont.textContent = text || '';
    var full = $('mob-evidence-full'); if (full) full.classList.remove('mob-evidence-full--open');
    var tog  = $('mob-evidence-toggle'); if (tog) tog.textContent = '▶';
    var bar  = $('mob-evidence-bar'); if (bar) bar.setAttribute('aria-expanded', 'false');
  }

  function mobPopulateVerdict(data) {
    var risk     = data.risk || {};
    var analysis = data.analysis || {};
    var severity = (risk.severity || analysis.severity || 'unknown').toLowerCase();
    var confidence = risk.confidence || 0;
    var category   = risk.threat_category || analysis.verdict || 'Inconclusive';
    var verdict    = analysis.verdict || 'Analyzed';
    var iocCount   = risk.ioc_count || data.ioc_count || 0;

    var colorMap = { critical:'#FF4757', high:'#FF6348', medium:'#FFA502', low:'#00FF88' };
    var color = colorMap[severity] || '#888899';

    var sev = $('mob-vb-sev');
    if (sev) { sev.textContent = severity.toUpperCase(); sev.className = 'mob-vb-badge mob-vb-badge--' + severity; }

    var vrd = $('mob-vb-verdict');
    if (vrd) {
      vrd.textContent = typeof verdict === 'string'
        ? verdict.replace(/_/g,' ').replace(/\b\w/g, function(l){ return l.toUpperCase(); })
        : '—';
      vrd.style.color = color;
    }

    var conf = $('mob-vb-conf'); if (conf) conf.textContent = confidence + '%';
    var thr  = $('mob-vb-threat'); if (thr) thr.textContent = typeof category === 'string' ? category : 'Inconclusive';
    var iocs = $('mob-vb-iocs'); if (iocs) iocs.textContent = iocCount;
  }

  function mobPopulateExecSummary(data) {
    var body = $('mob-exec-body');
    if (!body) return;
    var analysis = data.analysis || {};
    var text = analysis.summary || data.report || '';
    body.innerHTML = text
      ? '<p>' + escHtml(text) + '</p>'
      : '<p style="color:var(--ic-text-muted);font-style:italic;">No summary available.</p>';
  }

  function mobPopulateRecs(data) {
    var body = $('mob-recs-body');
    if (!body) return;
    var analysis = data.analysis || {};
    var summary  = analysis.summary || '';
    var recs = [];

    summary.split('\n').forEach(function(line) {
      var t = line.trim();
      if (t.match(/^\d+[\.\)]/) || t.match(/^[-*]/) ||
          t.match(/^(recommend|suggest|ensure|implement|use|enable|configure|review|investigate|block|monitor|patch|update|restrict)/i)) {
        recs.push(t.replace(/^[\d\.\-\*\s]+/, '').trim());
      }
    });

    if (recs.length === 0) {
      recs.push('Review the investigation report for full details.');
      if ((analysis.severity || 'low') !== 'low') recs.push('Block identified malicious indicators immediately.');
      recs.push('Monitor affected systems for suspicious activity.');
    }

    body.innerHTML = recs.slice(0, 6).map(function(r, i) {
      return '<div class="mob-rec">'
        + '<div class="mob-rec-num">' + (i+1) + '</div>'
        + '<div class="mob-rec-text">' + escHtml(r) + '</div>'
        + '</div>';
    }).join('');
  }

  function mobPopulateIOC(data) {
    var iocs     = data.iocs || {};
    var defanged = data.iocs_defanged || {};
    var summEl   = $('mob-ioc-summary');
    var chipsEl  = $('mob-ioc-chips');
    var badgeEl  = $('mob-ioc-badge');

    var sections = [
      { key:'ips',     icon:'🌐', label:'IPs' },
      { key:'domains', icon:'🌍', label:'Domains' },
      { key:'urls',    icon:'🔗', label:'URLs' },
      { key:'hashes',  icon:'🔑', label:'Hashes' },
      { key:'emails',  icon:'📧', label:'Emails' },
    ];

    var total = 0;
    var sumHtml = '';
    sections.forEach(function(s) {
      var items = iocs[s.key] || [];
      total += items.length;
      sumHtml += '<div class="mob-ioc-cell">'
        + '<div class="mob-ioc-cell-icon">' + s.icon + '</div>'
        + '<div class="mob-ioc-cell-count">' + items.length + '</div>'
        + '<div class="mob-ioc-cell-label">' + s.label + '</div>'
        + '</div>';
    });
    if (summEl) summEl.innerHTML = sumHtml;
    if (badgeEl) badgeEl.textContent = total;

    if (!chipsEl) return;
    if (total === 0) {
      chipsEl.innerHTML = '<div style="font-size:11px;color:var(--ic-text-muted);padding:4px 0;">No indicators extracted.</div>';
      return;
    }

    var chipHtml = '';
    sections.forEach(function(s) {
      var items = iocs[s.key] || [];
      var def   = defanged[s.key] || [];
      if (!items.length) return;
      chipHtml += '<div class="mob-ioc-group">'
        + '<div class="mob-ioc-group-hdr">' + s.icon + ' ' + s.label + ' <span class="mob-ioc-cnt">(' + items.length + ')</span></div>';
      items.forEach(function(item, idx) {
        var display = def[idx] || item;
        chipHtml += '<span class="mob-ioc-chip" data-action="copyToClipboard" data-encoded="' + encodeURIComponent(display) + '" title="Tap to copy">'
          + escHtml(display) + '</span>';
      });
      chipHtml += '</div>';
    });
    chipsEl.innerHTML = chipHtml;
  }

  var TACTIC_MAP = {'T1566':'Initial Access','T1110':'Credential Access','T1059':'Execution','T1071':'C2','T1003':'Credential Access','T1486':'Impact','T1190':'Initial Access','T1204':'Execution','T1021':'Lateral Movement','T1046':'Discovery','T1053':'Execution','T1068':'Priv Escalation','T1090':'C2','T1105':'C2','T1134':'Priv Escalation','T1203':'Execution','T1210':'Lateral Movement','T1498':'Impact','T1055':'Defense Evasion','T1036':'Defense Evasion','T1562':'Defense Evasion'};

  function mobPopulateMITRE(data) {
    var techniques = data.mitre_techniques || [];
    var body  = $('mob-mitre-body');
    var badge = $('mob-mitre-badge');
    if (!body) return;
    if (!techniques.length) {
      body.innerHTML = '<div style="font-size:11px;color:var(--ic-text-muted);padding:4px 0;">No MITRE techniques identified.</div>';
      if (badge) badge.textContent = '0';
      return;
    }
    body.innerHTML = techniques.map(function(t) {
      var tid    = t.id || '';
      var name   = t.name || 'Unknown';
      var tactic = TACTIC_MAP[tid] || (tid ? 'Unknown' : '');
      return '<div class="mob-mitre-row">'
        + '<div class="mob-mitre-info">'
        + (tactic ? '<div class="mob-mitre-tactic">' + escHtml(tactic) + '</div>' : '')
        + '<div class="mob-mitre-tech">' + escHtml(name) + '</div>'
        + '</div>'
        + (tid ? '<div class="mob-mitre-id">' + escHtml(tid) + '</div>' : '')
        + '</div>';
    }).join('');
    if (badge) badge.textContent = techniques.length;
  }

  function mobPopulateTimeline(data) {
    var body = $('mob-timeline');
    if (!body) return;
    var analysis = data.analysis || {};
    var verdict  = analysis.verdict || 'inconclusive';
    var severity = analysis.severity || 'low';
    var now = new Date();
    var fmt = function(d) { return d.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',hour12:false}); };

    var sevClass = { likely_malicious:'malicious', suspicious:'suspicious', benign:'benign' }[verdict] || 'info';
    var items = [
      { time: fmt(new Date(now - 180000)), cls:'', text:'Evidence received for analysis' },
      { time: fmt(new Date(now - 120000)), cls:'', text:'Indicators extracted' },
      { time: fmt(new Date(now - 60000)),  cls:sevClass, text: 'Verdict: ' + verdict.replace(/_/g,' ').replace(/\b\w/g,function(l){return l.toUpperCase();}) },
      { time: fmt(now), cls:'', text:'Report generated' },
    ];
    body.innerHTML = items.map(function(item) {
      return '<div class="mob-tl-item' + (item.cls ? ' mob-tl-item--' + item.cls : '') + '">'
        + '<div class="mob-tl-time">' + item.time + '</div>'
        + '<div class="mob-tl-text">' + escHtml(item.text) + '</div>'
        + '</div>';
    }).join('');
  }

  function mobPopulateTI(data) {
    var ti    = data.threat_intel || {};
    var body  = $('mob-ti-body');
    var badge = $('mob-ti-badge');
    if (!body) return;
    var abuse = ti.abuseipdb || [];
    var vt    = ti.virustotal || [];
    var total = abuse.length + vt.length;
    if (badge) badge.textContent = total;
    if (total === 0) {
      body.innerHTML = '<div style="font-size:11px;color:var(--ic-text-muted);padding:4px 0;">No threat intelligence data.</div>';
      return;
    }
    var html = '';
    abuse.forEach(function(entry) {
      var ip   = entry.ip || 'unknown';
      var d2   = (entry.result || {}).data || {};
      var score   = d2.abuseConfidenceScore || 0;
      var reports = d2.totalReports || 0;
      var country = d2.countryCode || '--';
      var col  = score > 80 ? '#FF4757' : score > 50 ? '#FFA502' : '#00FF88';
      html += '<div class="mob-ti-entry">'
        + '<div class="mob-ti-source">' + escHtml(ip) + '</div>'
        + '<div class="mob-ti-row">'
        + '<span style="color:' + col + '">⚠ ' + score + '</span>'
        + '<span>📊 ' + reports + ' reports</span>'
        + '<span>🌍 ' + country + '</span>'
        + '</div></div>';
    });
    vt.forEach(function(entry) {
      var ip    = entry.ip || 'unknown';
      var attrs = ((entry.result || {}).data || {}).attributes || {};
      var stats = attrs.last_analysis_stats || {};
      var mal   = stats.malicious || 0;
      var sus   = stats.suspicious || 0;
      var tot   = mal + sus + (stats.harmless||0) + (stats.undetected||0);
      var col   = mal > 0 ? '#FF4757' : sus > 0 ? '#FFA502' : '#00FF88';
      html += '<div class="mob-ti-entry">'
        + '<div class="mob-ti-source">' + escHtml(ip) + ' <span style="font-size:9px;color:var(--ic-text-muted)">[VT]</span></div>'
        + '<div class="mob-ti-row">'
        + '<span style="color:' + col + '">🛡 ' + mal + '/' + tot + ' malicious</span>'
        + '<span>⚠ ' + sus + ' suspicious</span>'
        + '</div></div>';
    });
    body.innerHTML = html;
  }

  function mobPopulateRaw(data) {
    var body = $('mob-raw-body');
    if (!body) return;
    var text = data.report || '';
    body.textContent = text;
    /* keep collapsed by default */
    var wrap = $('mob-raw-wrap');
    if (wrap) wrap.style.display = 'none';
  }

  /* ── suggestions ── */
  function mobLoadSuggestions() {
    var wrap = $('mob-chips');
    if (!wrap) return;
    var items = (window.SUGGESTION_BANK || []).slice(0, 3);
    if (!items.length) { wrap.innerHTML = ''; return; }
    wrap.innerHTML = items.map(function(text) {
      var enc = encodeURIComponent(text);
      return '<button class="mob-chip" data-action="mobUseSuggestion" data-text="' + enc + '">'
        + '🔎 ' + escHtml(text.length > 40 ? text.slice(0,38)+'…' : text) + '</button>';
    }).join('');
  }

  window.mobUseSuggestion = function(enc) {
    var ta = $('mob-textarea');
    if (!ta) return;
    ta.value = decodeURIComponent(enc);
    ta.focus();
    mobUpdateCharCount();
    mobAutoExpand();
  };

  /* ── init ── */
  document.addEventListener('DOMContentLoaded', function() {
    /* initial auto-expand */
    mobAutoExpand();
    mobLoadSuggestions();
    /* show input screen */
    showInputScreen();
  });

})();
