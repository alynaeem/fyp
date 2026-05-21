export function createHealingMonitorModule({
  state,
  $,
  apiFetch,
  formatDate,
  hostFromValue,
  escapeHtml,
  HEALING_CACHE_KEY,
  maybeApplyActiveTranslation,
  showToast
}) {
  const applyTranslation = typeof maybeApplyActiveTranslation === "function"
    ? maybeApplyActiveTranslation
    : async () => {};
  const notify = typeof showToast === "function" ? showToast : () => {};

  function setActionButtonBusy(buttonId, isBusy, busyLabel, readyLabel = busyLabel) {
    const button = $(buttonId);
    if (!button) return;

    if (isBusy) {
      if (!button.dataset.defaultLabel) {
        button.dataset.defaultLabel = button.textContent || readyLabel || busyLabel || "";
      }
      button.disabled = true;
      button.textContent = busyLabel;
      return;
    }

    button.disabled = false;
    button.textContent = button.dataset.defaultLabel || readyLabel || button.textContent || "";
  }

  function setScanStatusLoading(elementId, message) {
    const element = $(elementId);
    if (!element) return;
    element.innerHTML = `
      <span class="scan-status-loading">
        <span class="scan-status-pulse"></span>
        ${escapeHtml(message)}
      </span>
    `;
  }

  function renderLoadingSkeleton(kind = "compact", count = 3) {
    return Array.from({ length: count }, (_, index) => `
      <div class="mini-card healing-loading-card healing-loading-card-${escapeHtml(kind)}" aria-busy="true" data-loading-index="${index}">
        <div class="healing-empty-copy">Loading...</div>
      </div>
    `).join("");
  }

  function formatHealingStatus(status) {
    const normalized = String(status || "unknown").toLowerCase();
    switch (normalized) {
      case "healthy":
        return "Healthy";
      case "no_data":
        return "No Data";
      case "target_unreachable":
      case "unreachable":
        return "Unreachable";
      case "html_changed":
      case "changed":
        return "HTML Changed";
      case "repair_ready":
      case "auto_fixed":
        return "Repair Ready";
      case "needs_review":
        return "Needs Review";
      case "skipped":
        return "Skipped";
      case "error":
        return "Error";
      case "discovered":
        return "Discovered";
      default:
        return normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase()) : "Unknown";
    }
  }

  function renderHealingPill(status) {
    const normalized = String(status || "unknown").toLowerCase();
    return `<span class="healing-status-pill status-${escapeHtml(normalized)}">${escapeHtml(formatHealingStatus(normalized))}</span>`;
  }

  function formatHealingLiveStatus(status) {
    const normalized = String(status || "not_checked").toLowerCase();
    switch (normalized) {
      case "live":
        return "Live";
      case "redirect":
        return "Redirect";
      case "blocked":
        return "Blocked";
      case "server_error":
        return "Server Error";
      case "client_error":
        return "Client Error";
      case "timeout":
        return "Timeout";
      case "dns_failure":
        return "DNS Failure";
      case "connection_error":
        return "Connection Error";
      case "not_checked":
        return "Not Checked";
      default:
        return normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase()) : "Unknown";
    }
  }

  function formatHealingDriftStatus(status) {
    const normalized = String(status || "not_checked").toLowerCase();
    switch (normalized) {
      case "no_change":
        return "No Change";
      case "minor_change":
        return "Minor Change";
      case "major_change":
        return "Major Change";
      case "not_checked":
        return "Not Checked";
      default:
        return normalized ? normalized.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase()) : "Unknown";
    }
  }

  function renderHealingMetric(value, suffix = "") {
    if (value === null || value === undefined || value === "") {
      return "n/a";
    }
    return `${escapeHtml(String(value))}${suffix}`;
  }

  function renderHealingSuggestions(suggestions = []) {
    if (!Array.isArray(suggestions) || !suggestions.length) {
      return `<div class="healing-empty-copy">No selector repair suggestions were needed in the latest check.</div>`;
    }
    return `
      <ul class="healing-suggestion-list">
        ${suggestions.slice(0, 5).map(item => `
          <li>
            <strong>${escapeHtml(item.old_selector || "selector")}</strong>
            <span> -> ${escapeHtml(item.suggested_selector || item.new_selector || "manual review")}</span>
          </li>
        `).join("")}
      </ul>
    `;
  }

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
    return `
      <article class="result-card healing-event-card">
        <div class="result-card-header">
          <div class="result-card-headline">
            <span class="result-card-eyebrow">${escapeHtml(item.collector_type || "collector")}</span>
            <h3 class="result-card-title">${escapeHtml(item.script_name || item.target_key || "Healing event")}</h3>
          </div>
          ${renderHealingPill(item.status)}
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
          <p class="result-card-note-copy">${escapeHtml(item.message || "No event detail available.")}</p>
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
      return `<tr><td colspan="10">No healing scripts match the current filters.</td></tr>`;
    }

    return items.map(item => {
      const scriptId = item.script_id || item.target_key || "";
      const selectors = item.selector_health_score === null || item.selector_health_score === undefined
        ? "n/a"
        : `${Number(item.selector_health_score).toFixed(1)}%`;
      return `
        <tr class="${state.healingMonitor.selectedScriptId === scriptId ? "is-selected" : ""}">
          <td>
            <strong>${escapeHtml(item.script_file || item.script_name || "-")}</strong>
            <div class="table-meta">${escapeHtml(item.skip_reason ? `Skip: ${item.skip_reason}` : (item.fetch_strategy || "requests"))}</div>
          </td>
          <td>${escapeHtml(item.collector_name || "-")}</td>
          <td>${escapeHtml(item.target_domain || hostFromValue(item.target_url) || "-")}</td>
          <td>${escapeHtml(String(item.last_data_count ?? 0))}</td>
          <td>${renderHealingPill(item.status)}</td>
          <td><span class="status-badge status-${escapeHtml(String(item.live_status || "not_checked").toLowerCase())}">${escapeHtml(formatHealingLiveStatus(item.live_status))}</span></td>
          <td>${escapeHtml(formatHealingDriftStatus(item.html_change_status))}</td>
          <td>${escapeHtml(selectors)}</td>
          <td>${escapeHtml(item.last_checked_at ? formatDate(item.last_checked_at) : "Not checked")}</td>
          <td>
            <div class="healing-action-stack">
              <button class="healing-inline-btn" data-healing-check="${escapeHtml(scriptId)}">Run Check</button>
              <button class="healing-inline-btn" data-healing-check="${escapeHtml(scriptId)}">Re-Test</button>
              <button class="healing-inline-btn" data-healing-detail="${escapeHtml(scriptId)}" data-healing-focus="diff">View Diff</button>
              <button class="healing-inline-btn" data-healing-detail="${escapeHtml(scriptId)}" data-healing-focus="selectors">View Selectors</button>
              <button class="healing-inline-btn" data-healing-repair="${escapeHtml(scriptId)}">Generate Repair</button>
              <button class="healing-inline-btn" data-healing-apply="${escapeHtml(scriptId)}">Apply Repair</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
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

    return `
      <div class="healing-detail-head">
        <div>
          <span class="section-kicker">${escapeHtml(script.collector_name || "collector")}</span>
          <h3 class="healing-detail-title">${escapeHtml(script.script_file || script.script_name || "Script detail")}</h3>
          <p class="result-card-desc">${escapeHtml(script.target_url || "No target URL")}</p>
        </div>
        <div class="healing-header-stack">
          ${renderHealingPill(script.status)}
          <span class="status-badge status-${escapeHtml(String(script.live_status || "not_checked").toLowerCase())}">${escapeHtml(formatHealingLiveStatus(script.live_status))}</span>
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
        <div class="result-card-note-copy">${escapeHtml(script.last_event_message || "No latest explanation available.")}</div>
      </div>
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
    if (!select) return;
    const current = select.value;
    const options = [
      `<option value="">All Collectors</option>`,
      ...collectors.map(item => `<option value="${escapeHtml(item.collector_name || "")}">${escapeHtml(item.collector_name || "")}</option>`)
    ];
    select.innerHTML = options.join("");
    select.value = current && collectors.some(item => item.collector_name === current) ? current : "";
  }

  function getFilteredHealingScripts() {
    const collectorFilter = $("healingCollectorFilter")?.value?.trim?.() || "";
    const statusFilter = $("healingStatusFilter")?.value?.trim?.() || "";
    return (state.healingMonitor.scripts || []).filter(item => {
      if (collectorFilter && item.collector_name !== collectorFilter) {
        return false;
      }
      if (statusFilter && String(item.status || "").toLowerCase() !== statusFilter.toLowerCase()) {
        return false;
      }
      return true;
    });
  }

  function applyHealingMonitorPayload(payload, { preserveStatus = false, fromCache = false, errorMessage = "" } = {}) {
    const summary = payload.summary || {};
    const collectors = Array.isArray(payload.collectors) ? payload.collectors : [];
    const scripts = Array.isArray(payload.scripts) ? payload.scripts : [];
    const events = Array.isArray(payload.events) ? payload.events : [];

    state.healingMonitor.summary = summary;
    state.healingMonitor.collectors = collectors;
    state.healingMonitor.scripts = scripts;
    state.healingMonitor.events = events;

    $("healingStatTotalScripts").textContent = String(summary.total_scripts ?? 0);
    $("healingStatHealthy").textContent = String(summary.healthy ?? 0);
    $("healingStatNoData").textContent = String(summary.no_data ?? 0);
    $("healingStatUnreachable").textContent = String(summary.target_unreachable ?? 0);
    $("healingStatChanged").textContent = String(summary.html_changed ?? 0);
    $("healingStatRepairReady").textContent = String(summary.repair_ready ?? 0);
    $("healingStatNeedsReview").textContent = String(summary.needs_review ?? 0);
    renderHealingExplainer(summary);

    $("healingCollectorsSummary").textContent = `${collectors.length} collectors`;
    $("healingCollectorsGrid").innerHTML = collectors.length
      ? collectors.map(renderHealingCollectorCard).join("")
      : `<div class="healing-empty-copy">Collector discovery has not returned any monitored collectors yet.</div>`;

    populateHealingCollectorFilter(collectors);
    const filteredScripts = getFilteredHealingScripts();
    $("healingScriptsSummary").textContent = `${filteredScripts.length} script(s) in current view`;
    $("healingScriptsTableBody").innerHTML = renderHealingScriptRows(filteredScripts);

    $("healingEventsSummary").textContent = `${events.length} recent healing events`;
    $("healingEventsList").innerHTML = events.length
      ? events.map(renderHealingEventCard).join("")
      : `<div class="healing-empty-copy">No healing events have been recorded yet.</div>`;

    if (!preserveStatus) {
      const lastRun = summary.last_run_at ? formatDate(summary.last_run_at) : "not run yet";
      $("healingStatus").textContent = fromCache
        ? `Showing cached healing monitor data. Backend error: ${errorMessage || "unavailable"}.`
        : `Healing monitor ready. Last run ${lastRun}.`;
    }

    const detailId = state.healingMonitor.selectedScriptId || (filteredScripts[0] && filteredScripts[0].script_id) || "";
    if (detailId) {
      loadHealingScriptDetail(detailId);
    } else {
      $("healingDetailSummary").textContent = "Select a script to inspect";
      $("healingDetailPanel").innerHTML = `<div class="healing-empty-copy">Select a script to inspect baseline snapshots, latest HTML drift, failed selectors, and repair suggestions.</div>`;
    }
  }

  async function loadLeakSourceStatus(preserveStatus = false) {
    if (!preserveStatus) {
      setScanStatusLoading("leakSourceStatusNotice", "Loading leak script status...");
    }
    $("leakSourceStatusTableBody").innerHTML = `<tr><td colspan="7">Loading leak source status...</td></tr>`;

    try {
      const data = await apiFetch("/leaks/source-status");
      const summary = data.summary || {};
      const items = Array.isArray(data.items) ? data.items : [];
      const statusCounts = summary.status_counts || {};

      state.leakSourceStatus = { summary, items };

      $("leakSourceStatTotal").textContent = String(summary.total_scripts ?? items.length ?? 0);
      $("leakSourceStatWithData").textContent = String(summary.with_data ?? 0);
      $("leakSourceStatMongoDocs").textContent = String(summary.total_mongo_documents ?? 0);
      $("leakSourceStatIngested").textContent = String(statusCounts.ingested ?? 0);
      $("leakSourceStatUnreachable").textContent = String(statusCounts.unreachable ?? 0);
      $("leakSourceStatNeedsWork").textContent = String(
        (statusCounts.error ?? 0)
        + (statusCounts.import_error ?? 0)
        + (statusCounts.empty ?? 0)
        + (statusCounts.not_run ?? 0)
      );

      $("leakSourceStatusTableBody").innerHTML = renderLeakSourceStatusRows(items);
      if (!preserveStatus) {
        $("leakSourceStatusNotice").textContent = `${summary.with_data ?? 0} script(s) already have Mongo-backed leak data. ${summary.without_data ?? 0} still need successful ingestion.`;
      }
      await applyTranslation("view");
    } catch (error) {
      $("leakSourceStatusNotice").textContent = `Leak source status failed to load: ${error.message}`;
      $("leakSourceStatusTableBody").innerHTML = `<tr><td colspan="7">${escapeHtml(error.message)}</td></tr>`;
      $("leakSourceStatTotal").textContent = "0";
      $("leakSourceStatWithData").textContent = "0";
      $("leakSourceStatMongoDocs").textContent = "0";
      $("leakSourceStatIngested").textContent = "0";
      $("leakSourceStatUnreachable").textContent = "0";
      $("leakSourceStatNeedsWork").textContent = "0";
    }
  }

  async function loadHealingMonitor(preserveStatus = false) {
    if (!preserveStatus) {
      setScanStatusLoading("healingStatus", "Loading healing monitor state...");
    }
    $("healingCollectorsSummary").textContent = "Loading collectors...";
    $("healingScriptsSummary").textContent = "Loading scripts...";
    $("healingEventsSummary").textContent = "Loading events...";
    $("healingCollectorsGrid").innerHTML = renderLoadingSkeleton("compact", 3);
    $("healingScriptsTableBody").innerHTML = `<tr><td colspan="10">Loading healing monitor...</td></tr>`;
    $("healingEventsList").innerHTML = renderLoadingSkeleton("compact", 3);

    try {
      const [summaryData, collectorsData, scriptsData, eventsData] = await Promise.all([
        apiFetch("/api/healing/summary"),
        apiFetch("/api/healing/collectors"),
        apiFetch("/api/healing/scripts?limit=240"),
        apiFetch("/api/healing/events?limit=40")
      ]);
      const payload = {
        summary: summaryData.summary || {},
        collectors: collectorsData.items || [],
        scripts: scriptsData.items || [],
        events: eventsData.items || []
      };
      writeHealingCache(payload);
      applyHealingMonitorPayload(payload, { preserveStatus });
      await applyTranslation("view");
    } catch (error) {
      const cached = readHealingCache();
      if (cached && cached.payload) {
        applyHealingMonitorPayload(cached.payload, {
          preserveStatus,
          fromCache: true,
          errorMessage: error.message
        });
      } else {
        $("healingStatus").textContent = `Healing monitor failed to load: ${error.message}`;
        $("healingCollectorsSummary").textContent = "Unavailable";
        $("healingScriptsSummary").textContent = "Unavailable";
        $("healingEventsSummary").textContent = "Unavailable";
        $("healingCollectorsGrid").innerHTML = "";
        $("healingScriptsTableBody").innerHTML = `<tr><td colspan="10">${escapeHtml(error.message)}</td></tr>`;
        $("healingEventsList").innerHTML = "";
        $("healingExplainerBadge").textContent = "Unavailable";
        $("healingExplainerIntro").textContent = "Healing discovery details could not be loaded right now.";
        $("healingExplainerNote").textContent = "Try refreshing the monitor after the backend becomes reachable again.";
        $("healingDetailSummary").textContent = "Unavailable";
        $("healingDetailPanel").innerHTML = `<div class="healing-empty-copy">${escapeHtml(error.message)}</div>`;
      }
    }
  }

  async function loadHealingScriptDetail(scriptId, focus = "") {
    if (!scriptId) return;
    state.healingMonitor.selectedScriptId = scriptId;
    $("healingDetailSummary").textContent = "Loading script detail...";
    $("healingDetailPanel").innerHTML = renderLoadingSkeleton("compact", 2);
    $("healingScriptsTableBody").innerHTML = renderHealingScriptRows(getFilteredHealingScripts());
    try {
      const detail = await apiFetch(`/api/healing/script/${encodeURIComponent(scriptId)}`);
      state.healingMonitor.scriptDetail = detail;
      $("healingDetailSummary").textContent = detail.script
        ? `${detail.script.script_name || detail.script.script_file || scriptId}`
        : "Script detail";
      $("healingDetailPanel").innerHTML = renderHealingDetailPanel(detail);
      if (focus === "diff") {
        $("healingDetailDiff")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      } else if (focus === "selectors") {
        $("healingDetailSelectors")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
      await applyTranslation("view");
    } catch (error) {
      $("healingDetailSummary").textContent = "Detail unavailable";
      $("healingDetailPanel").innerHTML = `<div class="healing-empty-copy">${escapeHtml(error.message)}</div>`;
    }
  }

  async function runHealingDiscover() {
    setActionButtonBusy("healingDiscoverBtn", true, "Discovering...");
    setScanStatusLoading("healingStatus", "Discovering HTML monitor targets from collector scripts...");
    try {
      const data = await apiFetch("/healing/discover", false, { method: "POST" });
      $("healingStatus").textContent = data.message || "Healing targets discovered.";
      await loadHealingMonitor(true);
      notify(data.message || "Healing targets discovered.", "success");
    } catch (error) {
      $("healingStatus").textContent = `Discovery failed: ${error.message}`;
      notify(`Healing discovery failed: ${error.message}`, "error");
    } finally {
      setActionButtonBusy("healingDiscoverBtn", false, "Discovering...");
    }
  }

  async function runHealingMonitor(targetKey = "", inlineButton = null) {
    const isSingleTarget = !!targetKey;
    const collectorName = $("healingCollectorFilter")?.value?.trim?.() || "";
    setActionButtonBusy("healingRunBtn", !isSingleTarget, "Scanning...");
    const originalInlineLabel = inlineButton ? (inlineButton.dataset.defaultLabel || inlineButton.textContent) : "";
    if (inlineButton) {
      inlineButton.dataset.defaultLabel = originalInlineLabel;
      inlineButton.disabled = true;
      inlineButton.textContent = "Checking...";
    }
    setScanStatusLoading(
      "healingStatus",
      isSingleTarget
        ? `Checking HTML drift for ${targetKey}...`
        : "Running healing checks across monitored scripts..."
    );

    try {
      const path = targetKey ? `/api/healing/check/${encodeURIComponent(targetKey)}` : "/api/healing/run";
      const data = await apiFetch(path, false, {
        method: "POST",
        body: targetKey ? {} : {
          collector_name: collectorName,
          mode: collectorName ? "collector" : "default",
          limit: collectorName ? 80 : 20,
          dry_run_repair: true
        }
      });
      const statusCounts = data.status_counts || (data.check_result && data.check_result.status_counts) || {};
      const statusLine = Object.entries(statusCounts)
        .map(([key, value]) => `${formatHealingStatus(key)} ${value}`)
        .join(", ");
      $("healingStatus").textContent = statusLine
        ? `${data.message} ${statusLine}.`
        : (data.message || "Healing scan complete.");
      await loadHealingMonitor(true);
      notify(data.message || "Healing scan complete.", "success");
    } catch (error) {
      $("healingStatus").textContent = `Healing scan failed: ${error.message}`;
      notify(`Healing scan failed: ${error.message}`, "error");
    } finally {
      setActionButtonBusy("healingRunBtn", false, "Scanning...");
      if (inlineButton) {
        inlineButton.disabled = false;
        inlineButton.textContent = originalInlineLabel || "Run Check";
      }
    }
  }

  async function generateHealingRepair(scriptId, button = null) {
    if (!scriptId) return;
    if (button) {
      button.disabled = true;
      button.textContent = "Generating...";
    }
    try {
      const data = await apiFetch(`/api/healing/repair/${encodeURIComponent(scriptId)}`, false, { method: "POST" });
      notify(data.repair?.message || "Repair preview generated.", "success");
      await loadHealingScriptDetail(scriptId);
      await loadHealingMonitor(true);
    } catch (error) {
      notify(`Repair preview failed: ${error.message}`, "error");
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = "Generate Repair";
      }
    }
  }

  async function applyHealingRepair(scriptId, button = null) {
    if (!scriptId) return;
    if (button) {
      button.disabled = true;
      button.textContent = "Applying...";
    }
    try {
      const data = await apiFetch(`/api/healing/apply-repair/${encodeURIComponent(scriptId)}`, false, { method: "POST" });
      notify(data.message || "Repair apply complete.", data.status === "ok" ? "success" : "warning");
      await loadHealingMonitor(true);
      await loadHealingScriptDetail(scriptId);
    } catch (error) {
      notify(`Repair apply failed: ${error.message}`, "error");
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = "Apply Repair";
      }
    }
  }

  return {
    loadLeakSourceStatus,
    loadHealingMonitor,
    loadHealingScriptDetail,
    runHealingDiscover,
    runHealingMonitor,
    generateHealingRepair,
    applyHealingRepair
  };
}
