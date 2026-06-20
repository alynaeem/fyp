function renderConfidentialResults() {
  const allItems = state.confidentialFindings || [];
  const items = getConfidentialFilteredFindings();
  const tbody = $("confidentialResultsBody");
  renderConfidentialTypeOptions(allItems);

  if (!allItems.length) {
    tbody.innerHTML = `<tr><td colspan="10">Upload a local file to begin masked defensive analysis.</td></tr>`;
    setExportToolbarState("confidentialExportBar", false);
    return;
  }

  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="10">No masked findings match the selected filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = items.map(item => `
    <tr>
      <td>${escapeHtml(item.record_id || "-")}</td>
      <td>${escapeHtml(item.detected_type || "-")}</td>
      <td><code>${escapeHtml(item.masked_value || "-")}</code></td>
      <td>${escapeHtml(item.card_brand_guess || "N/A")}</td>
      <td>${escapeHtml(getConfidentialParsedField(item, "expiry_date"))}</td>
      <td>${escapeHtml(item.detection_confidence || "-")}</td>
      <td><span class="status-badge ${riskBadgeClass(item.risk_level)}">${escapeHtml(item.risk_level || "-")}</span></td>
      <td>
        <select class="confidential-status-select" data-confidential-status="${escapeHtml(item.record_id || "")}">
          ${["New", "Reviewed", "False Positive", "Confirmed"].map(status => `<option value="${escapeHtml(status)}" ${status === item.status ? "selected" : ""}>${escapeHtml(status)}</option>`).join("")}
        </select>
      </td>
      <td>${escapeHtml(formatConfidentialTimestamp(item.timestamp_of_analysis))}</td>
      <td><button class="btn-secondary compact-btn" type="button" data-confidential-detail="${escapeHtml(item.record_id || "")}">Inspect</button></td>
    </tr>
  `).join("");
  setExportToolbarState("confidentialExportBar", true, `${allItems.length} masked finding(s) ready for export.`);
}

function updateConfidentialStats(data) {
  const items = Array.isArray(data.results) ? data.results : [];
  $("confidentialStats").classList.remove("hidden");
  $("confidentialElapsed").textContent = `${Number(data.elapsed_ms || 0)} ms`;
  $("confidentialCount").textContent = String(items.length);
  $("confidentialHighRisk").textContent = String((data.risk_counts && data.risk_counts.High) || items.filter(item => item.risk_level === "High").length);
}

async function runConfidentialAnalysis() {
  const input = $("confidentialFileInput");
  const file = input.files && input.files[0];
  if (!file) {
    $("confidentialStatus").textContent = "Choose a .txt, .csv, .json, or .log file first.";
    return;
  }

  setActionButtonBusy("confidentialAnalyzeBtn", true, "Analysing...");
  $("confidentialStatus").textContent = "Analysing local file with masking controls...";
  $("confidentialStats").classList.add("hidden");
  setExportToolbarState("confidentialExportBar", false);
  $("confidentialResultsBody").innerHTML = `<tr><td colspan="10">Processing file locally. Raw secrets will not be returned to the browser.</td></tr>`;

  try {
    const headers = {};
    const token = getToken();
    const apiKey = localStorage.getItem(STORAGE_KEY) || "";
    if (token) headers.Authorization = `Bearer ${token}`;
    if (apiKey) headers["X-API-Key"] = apiKey;

    const formData = new FormData();
    formData.append("file", file);
    const response = await fetch(`${getBase()}/confidential/analyze`, {
      method: "POST",
      headers,
      body: formData
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || data.message || `HTTP ${response.status}`);
    }

    state.confidentialFindings = Array.isArray(data.results) ? data.results : [];
    state.scanExports.confidential = data;
    $("confidentialStatus").textContent = data.message || "Analysis complete. Review masked findings below.";
    updateConfidentialStats(data);
    renderConfidentialResults();
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    state.confidentialFindings = [];
    state.scanExports.confidential = null;
    $("confidentialStatus").textContent = `Analysis failed: ${error.message}`;
    $("confidentialResultsBody").innerHTML = `<tr><td colspan="10">${escapeHtml(error.message)}</td></tr>`;
    $("confidentialStats").classList.add("hidden");
    setExportToolbarState("confidentialExportBar", false);
  } finally {
    setActionButtonBusy("confidentialAnalyzeBtn", false, "Analysing...", "Analyse File");
    input.value = "";
  }
}

function showConfidentialDetail(recordId) {
  const item = state.confidentialFindings.find(entry => entry.record_id === recordId);
  if (!item) return;
  state.confidentialSelectedRecordId = recordId;
  $("confidentialDetailTopTag").textContent = `${item.detected_type || "Finding"} • ${item.risk_level || "Risk"}`;
  $("confidentialDetailTitle").textContent = item.masked_value || "Masked Finding";
  $("confidentialDetailMeta").innerHTML = `
    <span>Record ID: ${escapeHtml(item.record_id || "-")}</span>
    <span>Location: ${escapeHtml(item.location || "-")}</span>
  `;
  $("confidentialDetailFacts").innerHTML = [
    ["Detected Type", item.detected_type || "-"],
    ["Card Brand Guess", item.card_brand_guess || "N/A"],
    ["Confidence", item.detection_confidence || "-"],
    ["Risk Level", item.risk_level || "-"],
    ["Status", item.status || "New"],
    ["Analysis Timestamp", item.timestamp_of_analysis || "-"]
  ].map(([label, value]) => `
    <div class="fact-item">
      <span class="fact-label">${escapeHtml(label)}</span>
      <span class="fact-value">${escapeHtml(value)}</span>
    </div>
  `).join("");
  $("confidentialParsedFields").innerHTML = getConfidentialParsedFieldRows(item).map(([label, value]) => `
    <div class="confidential-field-item">
      <span class="confidential-field-label">${escapeHtml(label)}</span>
      <span class="confidential-field-value">${escapeHtml(value)}</span>
    </div>
  `).join("");
  $("confidentialDetailReason").textContent = item.reason_for_detection || "-";
  $("confidentialDetailContext").textContent = item.context_snippet || "-";
  $("confidentialDetailNotes").textContent = item.analyst_notes || "No analyst notes recorded.";
  $("confidentialDetailBackdrop").classList.remove("hidden");
}

function closeConfidentialDetailModal() {
  $("confidentialDetailBackdrop").classList.add("hidden");
  state.confidentialSelectedRecordId = "";
}

async function checkHealth() {
  try {
    const data = await apiFetch("/health", true);
    const statusDot = $("statusDot");
    const statusText = $("statusText");
    if (statusDot) statusDot.className = `status-dot ${data.status === "ok" ? "ok" : "error"}`;
    if (statusText) statusText.textContent = data.status === "ok" ? "Connected" : "Degraded";
  } catch (error) {
    const statusDot = $("statusDot");
    const statusText = $("statusText");
    if (statusDot) statusDot.className = "status-dot error";
    if (statusText) statusText.textContent = "Offline";
  }
}

async function switchView(target, options = {}) {
  const skipFeedLoad = Boolean(options.skipFeedLoad);
  state.currentView = target;
  clearTimeout(state.mapRefreshTimer);
  clearTimeout(state.mapSpotlightTimer);
  updateHeader(target);
  setActiveNavigation(target);
  renderSearchInsight();
  renderFeedFilterState();

  document.querySelectorAll(".view-panel").forEach(panel => panel.classList.add("hidden"));

  if (target === "homepage") {
    $("viewHomepage").classList.remove("hidden");
    const heatmapTask = initHeatmap();
    await Promise.all([fetchStats(), fetchRecentIntel()]);
    warmFeedSnapshots().catch(error => console.error(error));
    await maybeApplyActiveTranslation("view");
    heatmapTask.catch(error => console.error(error));
    return;
  }

  if (target === "admin-users") {
    $("viewAdminUsers").classList.remove("hidden");
    await Promise.all([refreshUserList(), refreshPasswordResetRequests()]);
    await maybeApplyActiveTranslation("view");
    return;
  }

  if (target === "pakdb") {
    $("viewPakdb").classList.remove("hidden");
    maybeApplyActiveTranslation("view");
    return;
  }

  if (target === "credential-checker") {
    $("viewCredentialChecker").classList.remove("hidden");
    await refreshCredentialDatasets();
    maybeApplyActiveTranslation("view");
    return;
  }

  if (target === "confidential-data") {
    $("viewConfidentialData").classList.remove("hidden");
    maybeApplyActiveTranslation("view");
    return;
  }

  if (target === "seo") {
    $("viewSeo").classList.remove("hidden");
    maybeApplyActiveTranslation("view");
    return;
  }
  if (target === "playstore") {
    $("viewPlaystore").classList.remove("hidden");
    maybeApplyActiveTranslation("view");
    return;
  }
  if (target === "software") {
    $("viewSoftware").classList.remove("hidden");
    maybeApplyActiveTranslation("view");
    return;
  }
  if (target === "repo-scan") {
    $("viewRepoScan").classList.remove("hidden");
    maybeApplyActiveTranslation("view");
    return;
  }
  if (target === "healing") {
    $("viewHealing").classList.remove("hidden");
    await loadHealingMonitor();
    maybeApplyActiveTranslation("view");
    return;
  }
  if (target === "leak-source-status") {
    $("viewLeakSourceStatus").classList.remove("hidden");
    await loadLeakSourceStatus();
    maybeApplyActiveTranslation("view");
    return;
  }
  if (target === "docs") {
    $("viewDocs").classList.remove("hidden");
    maybeApplyActiveTranslation("view");
    return;
  }
  if (target === "account") {
    $("viewAccount").classList.remove("hidden");
    await initAccountSettings();
    maybeApplyActiveTranslation("view");
    return;
  }
  state.activeTab = target;
  $("viewFeed").classList.remove("hidden");
  if (skipFeedLoad) {
    await maybeApplyActiveTranslation("view");
    return;
  }
  await loadArticles(true, 1);
}

function scheduleRefresh() {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = setTimeout(async () => {
    try {
      await checkHealth();
      await fetchStats();
      if (state.currentView === "homepage") {
        await Promise.all([initHeatmap(), fetchRecentIntel()]);
      } else if (state.currentView === "admin-users") {
        await Promise.all([refreshUserList(), refreshPasswordResetRequests()]);
      } else if (state.currentView === "healing") {
        await loadHealingMonitor(true);
      } else if (state.currentView === "leak-source-status") {
        await loadLeakSourceStatus(true);
      } else if (!TOOL_VIEWS.includes(state.currentView)) {
        await loadArticles(true, state.feedPage || 1);
      }
      setLastUpdated();
    } catch (error) {
      console.error(error);
    } finally {
      scheduleRefresh();
    }
  }, REFRESH_MS);
}

