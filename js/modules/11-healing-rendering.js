function renderHealingChanges(changes = []) {
  if (!Array.isArray(changes) || !changes.length) {
    return `<div class="healing-empty-copy">No structural changes were flagged in the latest snapshot.</div>`;
  }
  return `
    <ul class="healing-change-list">
      ${changes.slice(0, 6).map(change => `<li>${escapeHtml(change)}</li>`).join("")}
    </ul>
  `;
}

function renderHealingCollectorCard(item) {
  return `
    <article class="mini-card healing-collector-card">
      <div class="healing-collector-head">
        <strong>${escapeHtml(item.collector_name || "collector")}</strong>
        <span class="healing-collector-total">${escapeHtml(String(item.total_scripts ?? 0))} scripts</span>
      </div>
      <div class="healing-collector-metrics">
        <span>Monitorable ${escapeHtml(String(item.monitorable_scripts ?? 0))}</span>
        <span>Healthy ${escapeHtml(String(item.healthy_count ?? 0))}</span>
        <span>Failing ${escapeHtml(String(item.failing_count ?? 0))}</span>
        <span>Skipped ${escapeHtml(String(item.skipped_count ?? 0))}</span>
      </div>
    </article>
  `;
}

function renderHealingEventCard(item) {
  const message = cleanHealingMessage(item.message || item.last_event_message || "");
  return `
    <article class="result-card healing-event-card">
      <div class="result-card-header">
        <div class="result-card-headline">
          <span class="result-card-eyebrow">${escapeHtml(item.collector_type || "collector")}</span>
          <h3 class="result-card-title">${escapeHtml(item.script_name || item.target_key || "Healing event")}</h3>
        </div>
        ${renderHealingPrimaryPill(item)}
      </div>
      <p class="result-card-desc">${escapeHtml(item.target_url || "No target URL")}</p>
      <div class="result-card-grid">
        <div class="result-card-field">
          <span class="result-card-field-label">Event Time</span>
          <span class="result-card-field-value">${escapeHtml(item.created_at ? formatDate(item.created_at) : "-")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Live</span>
          <span class="result-card-field-value">${escapeHtml(formatHealingLiveStatus(item.live_status || ""))}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Drift</span>
          <span class="result-card-field-value">${escapeHtml(formatHealingDriftStatus(item.html_change_status || ""))}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Repair Confidence</span>
          <span class="result-card-field-value">${renderHealingMetric(item.repair_confidence, "")}</span>
        </div>
      </div>
      <div class="result-card-note">
        <span class="result-card-note-label">Message</span>
        <p class="result-card-note-copy">${escapeHtml(message || "No event detail available.")}</p>
      </div>
      <div class="healing-subsection">
        <span class="healing-pill-label">Change Summary</span>
        ${renderHealingChanges(item.summary_changes || [])}
      </div>
      <div class="healing-subsection">
        <span class="healing-pill-label">Fix Suggestions</span>
        ${renderHealingSuggestions(item.selector_suggestions || [])}
      </div>
    </article>
  `;
}

function renderHealingScriptRows(items = []) {
  if (!Array.isArray(items) || !items.length) {
    return `<div class="healing-empty-copy">No healing targets match the current filters.</div>`;
  }

  return items.map(item => {
    const scriptId = item.script_id || item.target_key || "";
    const selectors = item.selector_health_score === null || item.selector_health_score === undefined
      ? "n/a"
      : `${Number(item.selector_health_score).toFixed(1)}%`;
    const domain = item.target_domain || hostFromValue(item.target_url) || "No target URL";
    const reason = cleanHealingMessage(item.last_event_message || item.message || item.skip_reason || item.last_error || "");
    const secondaryBadges = healingSecondaryBadges(item)
      .map(([label, type]) => `<span class="healing-secondary-badge badge-${escapeHtml(type)}">${escapeHtml(label)}</span>`)
      .join("");
    const isSelected = state.healingMonitor.selectedScriptId === scriptId;
    const selectedDetail = isSelected && (state.healingMonitor.scriptDetail?.script?.script_id || "") === scriptId
      ? state.healingMonitor.scriptDetail
      : null;
    const inlineDetail = selectedDetail?.status === "ok"
      ? `<div class="healing-inline-detail">${renderHealingDetailPanel(selectedDetail)}</div>`
      : (isSelected
        ? `<div class="healing-inline-detail">${selectedDetail?.error_message ? `<div class="healing-empty-copy">${escapeHtml(selectedDetail.error_message)}</div>` : renderLoadingSkeleton("compact", 2)}</div>`
        : "");
    const primaryStatus = healingPrimaryStatus(item);
    const canApplyRepair = primaryStatus === "repair_ready" || primaryStatus === "repaired" || Number(item.repair_confidence || 0) > 0;
    return `
      <article class="healing-target-card ${isSelected ? "is-selected" : ""}" data-healing-card="${escapeHtml(scriptId)}">
        <div class="healing-target-main">
          <div class="healing-target-title-row">
            <div>
              <span class="section-kicker">${escapeHtml(item.collector_name || "collector")}</span>
              <h3 class="healing-target-title">${escapeHtml(domain)}</h3>
              <p class="healing-target-script">${escapeHtml(item.script_file || item.script_name || scriptId || "-")}</p>
            </div>
            <div class="healing-header-stack">
              ${renderHealingPrimaryPill(item)}
              ${secondaryBadges}
            </div>
          </div>
          <div class="healing-target-facts">
            <span><strong>Data</strong>${escapeHtml(String(item.last_data_count ?? 0))}</span>
            <span><strong>Selectors</strong>${escapeHtml(selectors)}</span>
            <span><strong>Drift</strong>${escapeHtml(formatHealingDriftStatus(item.html_change_status))}</span>
            <span><strong>Last Check</strong>${escapeHtml(item.last_checked_at ? formatDate(item.last_checked_at) : "Not checked")}</span>
          </div>
          <p class="healing-target-reason">${escapeHtml(reason || "Ready for target validation.")}</p>
        </div>
        <div class="healing-action-stack">
          <button class="healing-inline-btn primary" data-healing-check="${escapeHtml(scriptId)}">Run Check</button>
          <button class="healing-inline-btn" data-healing-detail="${escapeHtml(scriptId)}">${isSelected ? "Refresh Details" : "View Details"}</button>
          <button class="healing-inline-btn" data-healing-repair="${escapeHtml(scriptId)}">Generate Repair</button>
          <button class="healing-inline-btn" data-healing-apply="${escapeHtml(scriptId)}" ${canApplyRepair ? "" : "disabled title=\"Generate a repair first\""}>Apply Repair</button>
          <button class="healing-inline-btn" data-healing-check="${escapeHtml(scriptId)}">Re-Test</button>
        </div>
        ${inlineDetail}
      </article>
    `;
  }).join("");
}

function renderHealingAiReport(report = {}) {
  const safeReport = report && typeof report === "object" ? report : {};
  const issues = Array.isArray(safeReport.issues) ? safeReport.issues.filter(Boolean) : [];
  const actions = Array.isArray(safeReport.actions) ? safeReport.actions.filter(Boolean) : [];
  const mappings = Array.isArray(safeReport.selector_mappings) ? safeReport.selector_mappings.filter(Boolean) : [];
  const recovery = safeReport.data_recovery && typeof safeReport.data_recovery === "object" ? safeReport.data_recovery : {};
  const summary = sanitizeAiBranding(safeReport.summary || "DARKPULSE AI has not generated a healing report for this target yet.");

  const listMarkup = (items, emptyText) => items.length
    ? `<ul class="healing-ai-list">${items.slice(0, 8).map(item => `<li>${escapeHtml(sanitizeAiBranding(item))}</li>`).join("")}</ul>`
    : `<div class="healing-empty-copy">${escapeHtml(emptyText)}</div>`;

  const mappingRows = mappings.length
    ? mappings.slice(0, 12).map(item => `
        <tr>
          <td><code>${escapeHtml(item.old_selector || "-")}</code></td>
          <td><code>${escapeHtml(item.new_selector || "No replacement yet")}</code></td>
          <td>${escapeHtml(item.confidence !== undefined && item.confidence !== null ? String(item.confidence) : "-")}</td>
          <td>${escapeHtml(sanitizeAiBranding(item.reason || "Selector comparison recorded."))}</td>
        </tr>
      `).join("")
    : `<tr><td colspan="4">No old/new selector mappings are available yet. Run Check, then Generate Repair.</td></tr>`;

  return `
    <section class="healing-ai-report-card">
      <div class="healing-ai-report-head">
        <span class="ai-pulse-mini"></span>
        <div>
          <h4>DARKPULSE AI Healing Report</h4>
          <p>${escapeHtml(summary)}</p>
        </div>
      </div>
      <div class="healing-ai-status-grid">
        <span><strong>Recovered Data</strong>${escapeHtml(String(recovery.latest_data_count ?? 0))}</span>
        <span><strong>Mongo Docs</strong>${escapeHtml(String(recovery.mongo_document_count ?? 0))}</span>
        <span><strong>Injection Status</strong>${escapeHtml(sanitizeAiBranding(recovery.injection_status || "Not verified yet"))}</span>
      </div>
      ${recovery.message ? `<p class="healing-ai-recovery-copy">${escapeHtml(sanitizeAiBranding(recovery.message))}</p>` : ""}
      <div class="healing-ai-report-grid">
        <article class="healing-ai-section">
          <h5>Issues Found</h5>
          ${listMarkup(issues, "No issues were listed for this target.")}
        </article>
        <article class="healing-ai-section">
          <h5>Repair Actions</h5>
          ${listMarkup(actions, "No repair actions are available yet.")}
        </article>
      </div>
      <article class="healing-ai-section">
        <h5>Old Selectors vs DARKPULSE AI Suggested Selectors</h5>
        <div class="healing-ai-table-wrap">
          <table class="healing-ai-selector-table">
            <thead>
              <tr>
                <th>Previous Selector</th>
                <th>Suggested Selector</th>
                <th>Confidence</th>
                <th>Why</th>
              </tr>
            </thead>
            <tbody>${mappingRows}</tbody>
          </table>
        </div>
      </article>
    </section>
  `;
}

function renderHealingDetailPanel(detail) {
  if (!detail || detail.status !== "ok") {
    return `<div class="healing-empty-copy">Select a script to inspect baseline snapshots, latest HTML drift, failed selectors, and repair suggestions.</div>`;
  }

  const script = detail.script || {};
  const baseline = detail.baseline_snapshot || {};
  const latest = detail.latest_snapshot || {};
  const repair = detail.latest_repair || {};
  const recentEvents = Array.isArray(detail.recent_events) ? detail.recent_events : [];
  const failedSelectors = latest.failed_selectors || script.failed_selectors || [];
  const suggestedSelectors = repair.suggested_selectors || script.suggested_selectors || [];
  const explanation = cleanHealingMessage(script.last_event_message || latest.message || repair.message || "");

  return `
    <div class="healing-detail-head">
      <div>
        <span class="section-kicker">${escapeHtml(script.collector_name || "collector")}</span>
        <h3 class="healing-detail-title">${escapeHtml(script.script_file || script.script_name || "Script detail")}</h3>
        <p class="result-card-desc">${escapeHtml(script.target_url || "No target URL")}</p>
      </div>
      <div class="healing-header-stack">
        ${renderHealingPrimaryPill(script)}
        ${healingSecondaryBadges(script).map(([label, type]) => `<span class="healing-secondary-badge badge-${escapeHtml(type)}">${escapeHtml(label)}</span>`).join("")}
      </div>
    </div>
    <div class="result-card-grid">
      <div class="result-card-field">
        <span class="result-card-field-label">Last Data Count</span>
        <span class="result-card-field-value">${escapeHtml(String(script.last_data_count ?? 0))}</span>
      </div>
      <div class="result-card-field">
        <span class="result-card-field-label">Mongo Docs</span>
        <span class="result-card-field-value">${escapeHtml(String(script.mongo_document_count ?? 0))}</span>
      </div>
      <div class="result-card-field">
        <span class="result-card-field-label">Selector Health</span>
        <span class="result-card-field-value">${script.selector_health_score === null || script.selector_health_score === undefined ? "n/a" : `${escapeHtml(String(script.selector_health_score))}%`}</span>
      </div>
      <div class="result-card-field">
        <span class="result-card-field-label">Repair Confidence</span>
        <span class="result-card-field-value">${renderHealingMetric(script.repair_confidence)}</span>
      </div>
      <div class="result-card-field">
        <span class="result-card-field-label">Response Code</span>
        <span class="result-card-field-value">${renderHealingMetric(script.last_response_code)}</span>
      </div>
      <div class="result-card-field">
        <span class="result-card-field-label">Response Time</span>
        <span class="result-card-field-value">${renderHealingMetric(script.last_response_time_ms, " ms")}</span>
      </div>
      <div class="result-card-field">
        <span class="result-card-field-label">Baseline Snapshot</span>
        <span class="result-card-field-value">${escapeHtml(baseline.snapshot_path || script.baseline_snapshot_path || "-")}</span>
      </div>
      <div class="result-card-field">
        <span class="result-card-field-label">Latest Snapshot</span>
        <span class="result-card-field-value">${escapeHtml(latest.snapshot_path || script.latest_snapshot_path || "-")}</span>
      </div>
    </div>
    <div class="healing-subsection">
      <span class="healing-pill-label">Human Explanation</span>
      <div class="result-card-note-copy">${escapeHtml(explanation || "No latest explanation available.")}</div>
    </div>
    ${renderHealingAiReport(detail.ai_report || repair.ai_report || {})}
    <div class="healing-subsection" id="healingDetailDiff">
      <span class="healing-pill-label">DOM Drift Summary</span>
      ${renderHealingChanges(script.diff_summary || latest.diff_summary || [])}
      <pre class="healing-code-block">${escapeHtml(latest.diff_excerpt || "")}</pre>
    </div>
    <div class="healing-subsection" id="healingDetailSelectors">
      <span class="healing-pill-label">Failed Selectors</span>
      ${failedSelectors.length ? `
        <ul class="healing-suggestion-list">
          ${failedSelectors.slice(0, 8).map(item => `<li><strong>${escapeHtml(item.selector || "selector")}</strong><span> -> ${escapeHtml(item.reason || "no match")}</span></li>`).join("")}
        </ul>
      ` : `<div class="healing-empty-copy">No failed selectors were recorded in the latest check.</div>`}
    </div>
    <div class="healing-subsection">
      <span class="healing-pill-label">Suggested Selectors</span>
      ${renderHealingSuggestions(suggestedSelectors)}
    </div>
    <div class="healing-subsection">
      <span class="healing-pill-label">Recent Events</span>
      ${recentEvents.length ? `
        <ul class="healing-change-list">
          ${recentEvents.slice(0, 5).map(item => `<li>${escapeHtml(item.created_at ? formatDate(item.created_at) : "-")} - ${escapeHtml(item.message || item.status || "event")}</li>`).join("")}
        </ul>
      ` : `<div class="healing-empty-copy">No recent events are available for this script.</div>`}
    </div>
  `;
}

function formatLeakSourceStatus(status) {
  const normalized = String(status || "not_run").toLowerCase();
  switch (normalized) {
    case "ingested":
      return "Ingested";
    case "unreachable":
      return "Unreachable";
    case "import_error":
      return "Import Error";
    case "not_run":
      return "Not Run";
    default:
      return normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase()) : "Unknown";
  }
}

function renderLeakSourceStatusRows(items = []) {
  if (!Array.isArray(items) || !items.length) {
    return `<tr><td colspan="7">No leak script status records are available yet.</td></tr>`;
  }

  return items.map(item => {
    const status = String(item.status || "not_run").toLowerCase();
    const error = String(item.last_error || "").trim();
    const displayError = error.length > 140 ? `${error.slice(0, 137)}...` : error;
    return `
      <tr>
        <td><strong>${escapeHtml(item.script_file || item.module_stem || "-")}</strong></td>
        <td>${escapeHtml(item.source_name || "-")}</td>
        <td><span class="status-badge status-${escapeHtml(status)}">${escapeHtml(formatLeakSourceStatus(status))}</span></td>
        <td>${escapeHtml(String(item.mongo_document_count ?? 0))}</td>
        <td>${escapeHtml(item.last_run_at ? formatDate(item.last_run_at) : "-")}</td>
        <td>${escapeHtml(item.target_host || "-")}</td>
        <td title="${escapeHtml(error || "")}">${escapeHtml(displayError || "-")}</td>
      </tr>
    `;
  }).join("");
}

function renderHealingExplainer(summary = {}) {
  const breakdown = summary.discovery_breakdown || {};
  const totalFiles = Number(breakdown.total_python_files || 0);
  const skippedFiles = Number(breakdown.skipped_file_count || 0);
  const utilityFiles = Number(breakdown.utility_file_count || 0);
  const discoveredTargets = Number(breakdown.discovered_target_count || 0);
  const runLimit = Number(breakdown.default_run_limit || 0);
  const roots = Array.isArray(breakdown.roots) ? breakdown.roots : [];
  const utilityList = Array.isArray(breakdown.utility_files) ? breakdown.utility_files : [];

  $("healingExplainFiles").textContent = String(totalFiles);
  $("healingExplainSkipped").textContent = String(skippedFiles);
  $("healingExplainUtility").textContent = String(utilityFiles);
  $("healingExplainTargets").textContent = String(discoveredTargets);
  $("healingExplainLimit").textContent = String(runLimit);
  $("healingExplainerBadge").textContent = `${discoveredTargets} target${discoveredTargets === 1 ? "" : "s"}`;

  $("healingExplainerIntro").textContent = totalFiles
    ? `Healing discovery found ${discoveredTargets} real monitor targets from ${totalFiles} Python files. It does not count every backend file as a target.`
    : "Healing discovery scans collector folders, skips framework files, and keeps only real monitor targets.";

  $("healingExplainRoots").textContent = roots.length
    ? `The monitor scans ${roots.length} collector roots: ${roots.join(", ")}.`
    : "The monitor scans the configured collector roots for targetable scraper files.";

  $("healingExplainFiltering").textContent = `Skipped infra files: ${skippedFiles}. Utility/no-target files: ${utilityFiles}. Only files with a usable target URL become healing targets.`;

  $("healingExplainMonitor").textContent = runLimit
    ? `A full registry may have ${discoveredTargets} targets, but the default bulk scan checks ${runLimit} targets per run unless you run a single target manually.`
    : `A full registry may have ${discoveredTargets} targets, but monitor runs can be limited instead of checking everything at once.`;

  $("healingExplainerNote").textContent = utilityList.length
    ? `Utility files excluded from target discovery: ${utilityList.join(", ")}.`
    : "Utility files without a target URL will appear here once discovery stats load.";
}

function writeHealingCache(payload) {
  try {
    window.localStorage.setItem(HEALING_CACHE_KEY, JSON.stringify({ cachedAt: Date.now(), payload }));
  } catch (error) {
    console.debug("Could not cache healing payload", error);
  }
}

function readHealingCache() {
  try {
    const raw = window.localStorage.getItem(HEALING_CACHE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

function populateHealingCollectorFilter(collectors = []) {
  const select = $("healingCollectorFilter");
  const current = select.value;
  const options = [
    `<option value="">All Collectors</option>`,
    ...collectors.map(item => `<option value="${escapeHtml(item.collector_name || "")}">${escapeHtml(item.collector_name || "")}</option>`)
  ];
  select.innerHTML = options.join("");
  select.value = current && collectors.some(item => item.collector_name === current) ? current : "";
}

function healingScriptSearchBlob(item = {}) {
  return [
    item.script_id,
    item.target_key,
    item.script_file,
    item.script_name,
    item.collector_name,
    item.target_domain,
    item.target_url,
    item.last_event_message,
    item.message,
    item.status,
    item.live_status,
  ].map(value => String(value || "").toLowerCase()).join(" ");
}

function getFilteredHealingScripts() {
  const filters = state.healingMonitor.filters;
  const collectorFilter = $("healingCollectorFilter")?.value?.trim?.() || filters.collector || "";
  const statusFilter = $("healingStatusFilter")?.value?.trim?.() || filters.status || "";
  const issueFilter = $("healingIssueFilter")?.value?.trim?.() || filters.issue || "";
  const query = ($("healingSearchInput")?.value || filters.query || "").trim().toLowerCase();
  return (state.healingMonitor.scripts || []).filter(item => {
    if (collectorFilter && item.collector_name !== collectorFilter) {
      return false;
    }
    const primaryStatus = healingPrimaryStatus(item);
    const issue = healingIssueType(item);
    if (statusFilter === "no_url" && issue !== "no_url") {
      return false;
    }
    if (statusFilter && statusFilter !== "no_url" && primaryStatus !== statusFilter) {
      return false;
    }
    if (issueFilter && issue !== issueFilter) {
      return false;
    }
    if (query && !healingScriptSearchBlob(item).includes(query)) {
      return false;
    }
    return true;
  });
}

function renderHealingScriptList() {
  const filteredScripts = getFilteredHealingScripts();
  const filters = state.healingMonitor.filters;
  const totalPages = Math.max(1, Math.ceil(filteredScripts.length / filters.pageSize));
  filters.page = Math.min(Math.max(filters.page, 1), totalPages);
  const start = (filters.page - 1) * filters.pageSize;
  const pageItems = filteredScripts.slice(start, start + filters.pageSize);
  const totalTargets = state.healingMonitor.scripts.length;
  const discoveredTargets = Number(state.healingMonitor.summary?.discovery_breakdown?.discovered_target_count || totalTargets || 0);
  const defaultLimit = Number(state.healingMonitor.summary?.discovery_breakdown?.default_run_limit || 0);

  $("healingScriptsSummary").textContent = `${filteredScripts.length} target(s) in current view`;
  $("healingScriptsTableBody").innerHTML = renderHealingScriptRows(pageItems);
  $("healingPageLabel").textContent = `Page ${filters.page} of ${totalPages}`;
  $("healingPrevPageBtn").disabled = filters.page <= 1;
  $("healingNextPageBtn").disabled = filters.page >= totalPages;
  $("healingLimitNotice").textContent = defaultLimit && discoveredTargets
    ? `Showing ${pageItems.length} of ${filteredScripts.length} filtered targets. Bulk scan checks ${defaultLimit} of ${discoveredTargets} targets by default.`
    : `Showing ${pageItems.length} of ${filteredScripts.length} filtered targets.`;
}

function resetHealingListPage() {
  state.healingMonitor.filters.page = 1;
  renderHealingScriptList();
}

