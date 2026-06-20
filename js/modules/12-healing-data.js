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
  renderHealingScriptList();

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

  const filteredScripts = getFilteredHealingScripts();
  const selectedStillVisible = filteredScripts.some(item => item.script_id === state.healingMonitor.selectedScriptId);
  if (!selectedStillVisible) {
    state.healingMonitor.selectedScriptId = "";
    state.healingMonitor.scriptDetail = null;
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
    await maybeApplyActiveTranslation("view");
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
  $("healingScriptsTableBody").innerHTML = `<div class="healing-empty-copy">Loading healing monitor...</div>`;
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
    await maybeApplyActiveTranslation("view");
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
      $("healingScriptsTableBody").innerHTML = `<div class="healing-empty-copy">${escapeHtml(error.message)}</div>`;
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
  state.healingMonitor.scriptDetail = null;
  renderHealingScriptList();
  try {
    const detail = await apiFetch(`/api/healing/script/${encodeURIComponent(scriptId)}`);
    state.healingMonitor.scriptDetail = detail;
    renderHealingScriptList();
    document.querySelector(`[data-healing-card="${CSS.escape(scriptId)}"]`)?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    if (focus === "diff") {
      $("healingDetailDiff")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } else if (focus === "selectors") {
      $("healingDetailSelectors")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    state.healingMonitor.scriptDetail = {
      status: "error",
      script: { script_id: scriptId },
      ai_report: null,
      error_message: error.message
    };
    renderHealingScriptList();
  }
}

async function runHealingDiscover() {
  setActionButtonBusy("healingDiscoverBtn", true, "Discovering...");
  setScanStatusLoading("healingStatus", "Discovering HTML monitor targets from collector scripts...");
  try {
    const data = await apiFetch("/healing/discover", false, { method: "POST" });
    $("healingStatus").textContent = data.message || "Healing targets discovered.";
    await loadHealingMonitor(true);
    showToast(data.message || "Healing targets discovered.", "success");
  } catch (error) {
    $("healingStatus").textContent = `Discovery failed: ${error.message}`;
    showToast(`Healing discovery failed: ${error.message}`, "error");
  } finally {
    setActionButtonBusy("healingDiscoverBtn", false, "Discovering...");
  }
}

const HEALING_CHECK_STAGES = [
  "Preparing check",
  "Launching browser/request",
  "Reaching target",
  "Capturing HTML",
  "Validating selectors",
  "Comparing baseline",
  "Generating DARKPULSE AI diagnosis",
  "Preparing repair preview",
  "Refreshing recovered records",
];

function healingScriptById(scriptId) {
  return (state.healingMonitor.scripts || []).find(item => (item.script_id || item.target_key || "") === scriptId) || {};
}

function closeHealingCheckModal() {
  $("healingCheckBackdrop")?.classList.add("hidden");
  if (state.healingMonitor.checkModal.timer) {
    window.clearInterval(state.healingMonitor.checkModal.timer);
  }
  state.healingMonitor.checkModal.timer = null;
  state.healingMonitor.checkModal.outcome = "idle";
}

function renderHealingCheckProgress(outcome = "running") {
  const stageIndex = state.healingMonitor.checkModal.stageIndex;
  const finalLabel = outcome === "failed" ? "Failed" : "Completed";
  const stages = outcome === "running" ? HEALING_CHECK_STAGES : [...HEALING_CHECK_STAGES, finalLabel];
  $("healingCheckProgress").innerHTML = stages.map((stage, index) => {
    let statusClass = "pending";
    if (outcome !== "running" && index === stages.length - 1) {
      statusClass = outcome === "failed" ? "failed" : "done";
    } else if (index < stageIndex || outcome !== "running") {
      statusClass = "done";
    } else if (index === stageIndex) {
      statusClass = "active";
    }
    return `
      <div class="healing-progress-step ${statusClass}">
        <span>${index + 1}</span>
        <strong>${escapeHtml(stage)}</strong>
      </div>
    `;
  }).join("");
}

function openHealingCheckModal(scriptId) {
  const item = healingScriptById(scriptId);
  const domain = item.target_domain || hostFromValue(item.target_url) || "No target URL";
  state.healingMonitor.checkModal.scriptId = scriptId;
  state.healingMonitor.checkModal.stageIndex = 0;
  state.healingMonitor.checkModal.outcome = "running";

  $("healingCheckTitle").textContent = item.script_file || item.script_name || scriptId || "Target Check";
  $("healingCheckSubtitle").textContent = domain;
  $("healingCheckMeta").innerHTML = `
    <div><span>Collector</span><strong>${escapeHtml(item.collector_name || "-")}</strong></div>
    <div><span>Target Domain</span><strong>${escapeHtml(domain)}</strong></div>
    <div><span>Target URL</span><strong>${escapeHtml(item.target_url || "No URL")}</strong></div>
    <div><span>Current Status</span><strong>${escapeHtml(formatHealingStatus(healingPrimaryStatus(item)))}</strong></div>
    <div><span>Last Checked</span><strong>${escapeHtml(item.last_checked_at ? formatDate(item.last_checked_at) : "Not checked")}</strong></div>
    <div><span>Reachability</span><strong>${escapeHtml(formatHealingLiveStatus(item.live_status))}</strong></div>
    <div><span>Selector Health</span><strong>${escapeHtml(item.selector_health_score === null || item.selector_health_score === undefined ? "n/a" : `${item.selector_health_score}%`)}</strong></div>
    <div><span>HTML Drift</span><strong>${escapeHtml(formatHealingDriftStatus(item.html_change_status))}</strong></div>
  `;
  $("healingCheckDiagnosis").textContent = "Running target validation. Results will appear here when the check finishes.";
  renderHealingCheckProgress("running");
  $("healingCheckBackdrop").classList.remove("hidden");

  if (state.healingMonitor.checkModal.timer) {
    window.clearInterval(state.healingMonitor.checkModal.timer);
  }
  state.healingMonitor.checkModal.timer = window.setInterval(() => {
    const modal = state.healingMonitor.checkModal;
    if (modal.outcome !== "running") return;
    modal.stageIndex = Math.min(modal.stageIndex + 1, HEALING_CHECK_STAGES.length - 1);
    renderHealingCheckProgress("running");
    renderHealingScriptList();
  }, 700);
  renderHealingScriptList();
}

function finishHealingCheckModal({ success = true, message = "" } = {}) {
  if (state.healingMonitor.checkModal.timer) {
    window.clearInterval(state.healingMonitor.checkModal.timer);
  }
  state.healingMonitor.checkModal.timer = null;
  state.healingMonitor.checkModal.stageIndex = HEALING_CHECK_STAGES.length;
  state.healingMonitor.checkModal.outcome = success ? "complete" : "failed";
  renderHealingCheckProgress(success ? "complete" : "failed");
  $("healingCheckDiagnosis").textContent = cleanHealingMessage(message) || (success
    ? "Check completed. Review the inline target card for latest data, selector mappings, drift, and repair report."
    : "Check failed. Review the error and run the suggested next action.");
  renderHealingScriptList();
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
  if (isSingleTarget) {
    state.healingMonitor.selectedScriptId = targetKey;
    state.healingMonitor.scriptDetail = null;
    state.healingMonitor.checkModal.scriptId = targetKey;
    state.healingMonitor.checkModal.stageIndex = 0;
    state.healingMonitor.checkModal.outcome = "running";
    renderHealingScriptList();
  }

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
    let repairMessage = "";
    if (isSingleTarget) {
      state.healingMonitor.checkModal.stageIndex = HEALING_CHECK_STAGES.length - 2;
      renderHealingScriptList();
      try {
        const repairData = await apiFetch(`/api/healing/repair/${encodeURIComponent(targetKey)}`, false, { method: "POST" });
        repairMessage = repairData.repair?.message || "DARKPULSE AI repair report generated.";
      } catch (repairError) {
        repairMessage = `DARKPULSE AI repair report could not be generated: ${repairError.message}`;
      }
      finishHealingCheckModal({
        success: true,
        message: `${data.message || statusLine || "Target check complete."} ${repairMessage} Opened inline details on this card.`
      });
    }
    await loadHealingMonitor(true);
    if (isSingleTarget) {
      await loadHealingScriptDetail(targetKey);
    }
    showToast(data.message || "Healing scan complete.", "success");
  } catch (error) {
    $("healingStatus").textContent = `Healing scan failed: ${error.message}`;
    if (isSingleTarget) {
      finishHealingCheckModal({ success: false, message: error.message });
    }
    showToast(`Healing scan failed: ${error.message}`, "error");
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
    showToast(data.repair?.message || "Repair preview generated.", "success");
    await loadHealingMonitor(true);
    await loadHealingScriptDetail(scriptId);
  } catch (error) {
    showToast(`Repair preview failed: ${error.message}`, "error");
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
    showToast(data.message || "Repair apply complete.", data.status === "ok" ? "success" : "warning");
    await loadHealingMonitor(true);
    await loadHealingScriptDetail(scriptId);
  } catch (error) {
    showToast(`Repair apply failed: ${error.message}`, "error");
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "Apply Repair";
    }
  }
}

async function refreshUserList() {
  try {
    const data = await apiFetch("/admin/users");
    const currentUsername = (localStorage.getItem(USER_NAME_KEY) || "").trim().toLowerCase();
    $("userTableBody").innerHTML = data.users.map(user => `
      <tr>
        <td>${escapeHtml(user.name || user.username)}</td>
        <td>${escapeHtml(user.username)}</td>
        <td>${escapeHtml(user.email || "")}</td>
        <td>${escapeHtml(user.role || "user")}</td>
        <td><span class="status-badge status-${escapeHtml(user.status)}">${escapeHtml(user.status)}</span></td>
        <td>
          ${user.status === "pending" ? `<button class="btn-secondary compact-btn" type="button" onclick="approveUser('${escapeHtml(user.username)}')">Approve</button>` : ""}
          ${String(user.username || "").trim().toLowerCase() === currentUsername
            ? `<span class="status-inline-note">Current admin</span>`
            : `<button class="btn-secondary compact-btn" type="button" onclick="deleteUser('${escapeHtml(user.username)}')">Reject</button>`}
        </td>
      </tr>
    `).join("");
  } catch (error) {
    $("userTableBody").innerHTML = `<tr><td colspan="6">${escapeHtml(error.message)}</td></tr>`;
  }
}

async function refreshPasswordResetRequests() {
  try {
    const data = await apiFetch("/admin/password-reset-requests");
    const rows = data.requests || [];
    $("resetRequestTableBody").innerHTML = rows.length
      ? rows.map(item => `
        <tr>
          <td>${escapeHtml(item.name || item.username || "Unknown")}</td>
          <td>${escapeHtml(item.identity || item.email || item.username || "-")}</td>
          <td>${escapeHtml(item.message || "No note provided")}</td>
          <td><span class="status-badge status-${escapeHtml(item.status || "pending")}">${escapeHtml(item.status || "pending")}</span></td>
          <td>${escapeHtml(formatDate(item.created_at))}</td>
          <td>
            ${item.status === "pending" ? `<button class="btn-secondary" onclick="resolvePasswordResetRequest('${escapeHtml(item._id)}')">Mark Reviewed</button>` : `<span class="status-inline-note">Handled</span>`}
          </td>
        </tr>
      `).join("")
      : `<tr><td colspan="6">No password recovery requests yet.</td></tr>`;
  } catch (error) {
    $("resetRequestTableBody").innerHTML = `<tr><td colspan="6">${escapeHtml(error.message)}</td></tr>`;
  }
}

window.approveUser = async username => {
  try {
    await apiFetch(`/admin/users/${username}/approve`, false, { method: "POST" });
    showToast(`${username} approved.`, "success");
    refreshUserList();
  } catch (error) {
    showToast(error.message || "Could not approve user.", "error");
  }
};

