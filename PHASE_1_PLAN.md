# Phase 1 Plan — CyberGuru AI: Investigation Analytics & Analyst Workflow

## Executive Summary

Phase 0 established a trustworthy core: the investigation pipeline now reports real outcomes, verdicts and severity are validated against supported values, artifact types are correctly propagated, confidence scoring is deterministic and documented, evidence provenance is traceable, cached results obey a consistent contract, and threat-intelligence errors are distinguishable from clean results.

**Phase 1 objective**: Build on the trustworthy core to deliver analyst-facing productivity features, improved threat-intelligence reliability, and operational observability — without compromising the Phase 0 correctness foundations.

**Success criteria** (by end of Phase 1):
- 100% of existing 193 pytest tests continue passing (no regressions).
- New targeted tests cover all Phase 1 deliverables with 100% branch coverage on modified functions.
- No new High/Critical Bandit findings; any Medium findings documented with technical justification.
- All new API endpoints include input validation, ownership scoping, and error sanitization matching Phase 0 standards.
- Frontend UI reflects truthful pipeline status and evidence provenance markers.

## Repository Baseline (CONFIRMED)

- **Branch**: `fix/phase-0-trustworthy-core` (29 files modified, 2732 insertions, 867 deletions vs `main`)
- **193 pytest tests pass** with 0 failures
- **Bandit**: 0 High, 0 Medium (392 Low pre-existing, unrelated)
- **Phase 0 changes**: uncommitted, unpushed, on feature branch only
- **Architecture**: Flask backend, Gemini AI, PostgreSQL, AbuseIPDB/VirusTotal threat intel, Flask-Limiter, CSRF protection, Jinja2 templates, Vanilla JS frontend

## Highest-Value Next Improvements (Ranked)

### 1. Threat-Intelligence Integration Reliability
- **User problem**: External provider lookups (AbuseIPDB/VirusTotal) occasionally fail or return malformed data; the pipeline currently handles this but without rich user-visible status detail.
- **Expected benefit**: Analysts see clear, categorized threat-intel status (ok/error/not_applicable/not_found) per indicator in the UI; rate-limit and auth-error handling is surfaced gracefully.
- **Files likely affected**: `services/cyberguru_agent.py` (pipeline status), `utils/abuseipdb_tool.py`, `utils/virustotal_tool.py`, `static/js/investigate.js` (UI rendering), `routes/investigate_center.py` (API responses).
- **Dependencies**: API keys must be configured in `.env`; existing `_threat_intel_stage_state()` and `_usable_provider_data()` foundations already in place.
- **Security/privacy**: No new data collection; existing indicator validation and private IP safeguards preserved. Error messages sanitized per Phase 0 standards.
- **Test requirements**: Mocked provider success/error/timeout/malformed-response scenarios; UI renders status badges correctly; rate-limit backoff respected.

### 2. Investigation History & Case Management
- **User problem**: No persistent history across sessions; analysts cannot revisit prior investigations, filter, or export comprehensive reports. History exists in DB but is not user-friendlyly accessible.
- **Expected benefit**: Authentication-scoped history list with filtering (by verdict, severity, artifact type); export as Markdown/JSON with full contract; delete individual cases; analytics-ready summaries.
- **Files likely affected**: `routes/investigate_center.py` (history/list/export endpoints), `services/db_service.py` (history queries), `templates/investigate.html` (history UI), `utils/report_generator.py` (export enrichment).
- **Dependencies**: Existing `get_investigation_history()`, `get_investigation_by_id()`, `delete_investigation()` foundations already in Place. Export endpoints partially built in Phase 0.
- **Security/privacy**: All history scoped by `user_id` via `@login_required`; ownership checked in DB queries; export endpoints already have `@login_required` and sanitization; no new sensitive data exposed.
- **Test requirements**: Authenticated user sees only own history; anonymous gets 401; filter by verdict/severity works; export produces valid Markdown/JSON matching Phase 0 contract; delete requires CSRF token and ownership.

### 3. Evidence Explainability & UI Grounding
- **User problem**: The E-ID registry exists but the UI does not surface verified/unverified markers or provenance details. The copilot can cite E-IDs but the analyst cannot easily see them in the investigation view.
- **Expected benefit**: Investigation page shows a "Evidence legend" panel with E-ID, type, detail, verified/unverified badge, and provenance (provider/heuristic/extraction). Clicking an E-ID highlights the corresponding indicator. The copilot prompt includes the full evidence block.
- **Files likely affected**: `templates/investigate.html` (evidence legend panel), `static/js/investigate.js` (UI rendering of evidence, click-to-highlight), `utils/evidence.py` (format_evidence_block detail enrichment), `services/cyberguru_agent.py` (evidence included in investigate() response).
- **Dependencies**: `build_evidence()` and `format_evidence_block()` already produce the registry; `investigate()` already returns `evidence` field; template already loads data from API.
- **Security/privacy**: E-IDs are deterministic and read-only; provenance markers prevent unverified data from being presented as externally confirmed. No new data collection.
- **Test requirements**: Evidence legend rendered on investigation page; verified badges shown for provider lookups, unverified for MITRE/IOCs; copilot prompt includes evidence block; clicking E-ID highlights indicator (DOM interaction test).

### 4. Confidence Scoring Transparency & UI Feedback
- **User problem**: Confidence score (0-100) is returned but not explained in the UI; analysts cannot understand why a score is high/low. The factors are computed but not displayed.
- **Expected benefit**: UI shows confidence factors as a human-readable list; score distribution explained (floor at 5, clean sources cap at 60, conflicting evidence caps at 25, inconclusive at 40). Hover/tooltip explains each factor.
- **Files likely affected**: `static/js/investigate.js` (confidence display, factor tooltips), `routes/investigate_center.py` (risk score computation already present), `utils/confidence.py` (factors already computed, just need UI integration).
- **Dependencies**: `compute_confidence_detail()` already returns `factors` list; `_risk_score()` in routes already uses severity + IOC count; Phase 0 already computes confidence correctly.
- **Security/privacy**: No new data; factors are derived from existing threat-intel and IOC data. Display explains rather than reinterprets the score.
- **Test requirements**: Confidence score displayed on investigation result page; factors listed with explanatory text; score floor at 5 confirmed when no corroborating evidence; conflicting evidence cap at 25 confirmed when verdict differs from provider malice.

### 5. Error Handling & Observability Reinforcement
- **User problem**: API errors are sanitized but generic; internal logs contain useful detail but are not accessible to analysts. No structured error codes returned to API consumers beyond generic messages.
- **Expected benefit**: API returns machine-readable error codes (consistent with Phase 0 error_code conventions); dashboard/ logging captures categorized errors; rate-limit and auth-error handling observable.
- **Files likely affected**: `services/triage_service.py` (_error_result, _classify_ai_exception), `routes/investigate_center.py` (error response format), `services/cyberguru_agent.py` (error propagation through pipeline).
- **Dependencies**: Phase 0 already established error_code taxonomy (timeout, blocked, authentication, provider_error, invalid_output, too_many_assessment_blocks, malformed_assessment_json, empty_response, internal_error, tool_iteration_limit).
- **Test requirements**: Mocked AI failures return correct error_code; API returns error_code in response; rate-limit backoff respected; no stack traces leaked to client.

## Prioritized Deliverables (MAX 5)

| # | Deliverable | Primary Files | Estimated Effort | Dependencies |
|---|-------------|--------------|-----------------|--------------|
| 1 | Threat-intel status UI | `static/js/investigate.js`, `routes/investigate_center.py` | Medium | Phase 0 error handling |
| 2 | History & case management | `routes/investigate_center.py`, `services/db_service.py`, `templates/investigate.html` | Medium | `@login_required`, existing DB functions |
| 3 | Evidence legend panel | `templates/investigate.html`, `static/js/investigate.js`, `utils/evidence.py` | Low-Medium | `build_evidence()`, `format_evidence_block()` |
| 4 | Confidence factor display | `static/js/investigate.js`, `utils/confidence.py` | Low | `compute_confidence_detail()`, already computed |
| 5 | Error code transparency | `services/triage_service.py`, `routes/investigate_center.py` | Low | Phase 0 error_code taxonomy |

**Selected Phase 1 scope** (4 deliverables, fitting within reasonable effort):
1. Threat-intelligence status in UI
2. Investigation history & case management
3. Evidence explainability panel
4. Confidence factor display

(Excluded: error code transparency — Phase 0 already solid; evidence explainability partially overlaps with #3.)

## Milestones & Test Criteria

**Milestone 1 — Threat-intel UI status** (acceptance: new test + manual verification)
- UI renders threat-intel entries with status badges (ok/error/not_applicable/not_found)
- Private IPs show "not applicable" with reason
- Provider errors show "error" badge without exposing raw details
- Test: `tests/test_investigation_pipeline.py` extended with mocked provider rendering test

**Milestone 2 — Investigation history & case management** (acceptance: all new tests pass)
- Authenticated GET /api/investigate/history returns user's investigations with verdict/severity/artifact_type filters
- GET /api/investigate/<id>/export/md and /export/json produce valid output matching Phase 0 contract
- PATCH /api/investigate/<id> updates analyst status; response reflects persisted state
- DELETE removes investigation; 404 if not owned; CSRF-protected
- Test: new test file `tests/test_investigation_history.py` (or equivalent test additions)

**Milestone 3 — Evidence explainability panel** (acceptance: new test + manual verification)
- Evidence legend panel appears on investigation result page
- Verified badge shown for AbuseIPDB/VirusTotal provider entries
- Unverified badge shown for MITRE mappings and extracted IOCs
- Detail tooltip shows source and value
- Test: manual verification on running instance; snapshot test of evidence block rendering

**Milestone 4 — Confidence factor display** (acceptance: new test + manual verification)
- Confidence score (0-100) displayed on investigation result page
- Factors listed as tooltips/bullet list with explanatory text
- Score floor at 5 when no corroborating evidence
- Conflicting evidence capped at 25 when verdict conflicts with provider malice
- Test: manual verification on running instance; compute_confidence_detail() factors verified against known inputs

## Scope Exclusions (Explicit)

The following are intentionally out of Phase 1 scope:
- Real AI model integration with live Gemini API (requires user credentials; deferred to Phase 2 or user-initiated)
- External AbuseIPDB/VirusTotal API key provisioning (user-owns keys; Phase 1 uses mocked providers only)
- Full SOC case management workflow (beyond investigation center scope; could be Phase 2)
- Database schema migration or performance optimization (Phase 0 schema is adequate)
- Browser automation or end-to-end UI testing framework setup (existing pytest + manual checks suffice)
- Multi-user collaboration or shared investigation features (single-user auth model from Phase 0)

## Risks and Dependencies

| Risk | Mitigation |
|------|-----------|
| API key absence breaks mocked provider tests | Tests use monkeypatched `analyze_artifact`; no real API calls required |
| Frontend changes conflict with existing template structure | Incremental edits to `investigate.html` + `investigate.js`; existing UI conventions preserved |
| Confidence factor display misleads as calibrated probability | Documentation included: "This is a transparent heuristic, not a statistically calibrated probability" (per Phase 0 docstring) |
| History export format drift from Phase 0 contract | Export endpoints reuse `result_from_db_row()` and `build_specific_recommendations()` — same contract as fresh/cached investigations |
| Bandit new findings from JS template changes | `escHtml()` already used consistently; only adding new DOM elements with proper escaping |

## Final Recommendation

**Phase 1 scope of 4 deliverables** is technically grounded, incremental on Phase 0 foundations, and provides tangible analyst productivity improvements without introducing risk. Each deliverable has clear test criteria and can be validated without production deployment or API keys.

**Proposed sequence**: Start with Milestone 3 (evidence explainability — lowest effort, highest impact for trust), then Milestone 4 (confidence display), then Milestone 1 (threat-intel UI), then Milestone 2 (history/case management).

**Acceptance gate**: All 193 existing pytest tests must remain passing. New behavior has targeted tests. Security-sensitive changes include negative tests. No secrets or production data exposed. No deployment without explicit approval.

---
*Plan derived from Phase 0 audit of branch `fix/phase-0-trustworthy-core`. All Phase 0 changes preserved intact. No code modifications made in this planning step.*