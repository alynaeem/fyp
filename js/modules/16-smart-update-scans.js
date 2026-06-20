async function triggerSmartUpdate() {
  if (isSmartUpdateRunning(state.smartUpdateStatus)) return;

  syncSmartUpdateButton(true);
  showToast("Launching hidden fast background sync...", "info");

  try {
    const data = await apiFetch("/api/trigger-smart-update", false, { method: "POST" });
    if (data.status === "busy") {
      showToast("A scan is already running. Live status has been refreshed.", "info");
      await pollSmartUpdateStatus(true);
      return;
    }

    if (data.status !== "ok") {
      syncSmartUpdateButton(false);
      showToast("Trigger failed: " + (data.message || "Unknown error"), "error");
      return;
    }

    state.smartUpdateJobId = data.job?.job_id || "";
    state.smartUpdateStatus = data.job?.status || "queued";
    renderSmartUpdateBanner({
      active_run: data.job,
      latest_run: data.job,
      latest_notification: data.notification
    });
    showToast(data.message || "Fast headless sync started.", "success");
    scheduleSmartUpdateMonitor(1000);
  } catch (error) {
    syncSmartUpdateButton(false);
    showToast("Server error triggering scan: " + error.message, "error");
  }
}

async function stopSmartUpdate() {
  if (!isSmartUpdateRunning(state.smartUpdateStatus)) return;

  state.smartUpdateStatus = "cancelling";
  syncSmartUpdateButton(true);
  showToast("Stopping the active scan...", "info");

  try {
    const data = await apiFetch("/api/intelligence/stop", false, { method: "POST" });
    if (data.status === "idle") {
      showToast(data.message || "No active scan is running.", "info");
      state.smartUpdateStatus = "idle";
      state.smartUpdateJobId = "";
      syncSmartUpdateButton(false);
      await pollSmartUpdateStatus(true);
      return;
    }

    if (data.job) {
      state.smartUpdateJobId = data.job.job_id || state.smartUpdateJobId;
      state.smartUpdateStatus = data.job.status || "cancelling";
    }
    renderSmartUpdateBanner({
      active_run: data.job,
      latest_run: data.job,
      latest_notification: data.notification
    });
    showToast(data.message || "Stop requested.", "info");
    scheduleSmartUpdateMonitor(1000);
  } catch (error) {
    showToast("Failed to stop scan: " + error.message, "error");
    await pollSmartUpdateStatus(true);
  }
}

function showAlertSummary() {
  const summaryData = buildAlertSummaryData(state.smartUpdatePayload);
  const completeSources = completeAlertSummarySources(summaryData.sourceResults);
  const totalRecords = completeSources.reduce((sum, item) => {
    const total = item.current_count ?? item.after_count ?? item.before_count ?? 0;
    return sum + Number(total || 0);
  }, 0);

  if (!summaryData.jobId && summaryData.sourceResults.length === 0 && !completeSources.length) {
    showToast("No scan summary is available yet.", "info");
    return;
  }

  $("alertSummaryStatusTag").textContent = summaryData.heading;
  $("alertSummaryTitle").textContent = summaryData.title;
  $("alertSummaryMeta").innerHTML = [
    `Job: ${escapeHtml(summaryData.jobId || "Unavailable")}`,
    `Triggered by: ${escapeHtml(summaryData.triggeredBy)}`,
    `Channel: ${escapeHtml(summaryData.channel)}`,
    summaryData.startedAt ? `Started: ${escapeHtml(formatDate(summaryData.startedAt))}` : "",
    summaryData.completedAt ? `Completed: ${escapeHtml(formatDate(summaryData.completedAt))}` : ""
  ].filter(Boolean).map(item => `<span>${item}</span>`).join("");

  $("alertSummaryFactGrid").innerHTML = [
    ["Status", formatSmartUpdateStatus(summaryData.status)],
    ["New Records", String(summaryData.totalNew || 0)],
    ["Total Records", String(totalRecords || 0)],
    ["Sources", String(completeSources.length || 0)]
  ].map(([label, value]) => `
    <div class="fact-item">
      <span class="fact-label">${escapeHtml(label)}</span>
      <span class="fact-value">${escapeHtml(value)}</span>
    </div>
  `).join("");

  if (completeSources.length) {
    $("alertSummarySources").innerHTML = completeSources.map(item => {
      const label = item.label || SMART_UPDATE_SOURCE_LABELS[item.source] || item.source || "Source";
      const total = item.current_count ?? item.after_count ?? item.before_count ?? 0;
      const highlights = Array.isArray(item.highlights) ? item.highlights : [];
      return `
        <div class="summary-source-card">
          <div class="summary-source-header">
            <span class="summary-source-title">${escapeHtml(label)}</span>
            <span class="summary-source-status">${escapeHtml(formatSourceRunStatus(item.status || "idle"))}</span>
          </div>
          <div class="summary-source-meta">
            <span>New: ${escapeHtml(String(Number(item.new_records || 0)))}</span>
            <span>Total: ${escapeHtml(String(total))}</span>
            ${(item.error && String(item.error).trim()) ? `<span>Error: ${escapeHtml(item.error)}</span>` : ""}
          </div>
          ${highlights.length ? `
            <div class="summary-highlight-list">
              ${highlights.map(highlight => `
                <div class="summary-highlight-item">
                  <div class="summary-highlight-title">${escapeHtml(highlight.title || "Untitled")}</div>
                  <div class="summary-highlight-source">
                    ${escapeHtml(highlight.source_name || label)}
                    ${(highlight.url && String(highlight.url).trim()) ? `<span class="summary-highlight-link">${escapeHtml(highlight.url)}</span>` : ""}
                  </div>
                </div>
              `).join("")}
            </div>
          ` : `<div class="summary-source-empty neutral">No new items were added in this source during this run.</div>`}
        </div>
      `;
    }).join("");
  } else {
    $("alertSummarySources").innerHTML = `<div class="summary-empty">No source breakdown is available for this scan yet.</div>`;
  }

  $("alertSummaryBackdrop").classList.remove("hidden");
  setTimeout(() => {
    maybeApplyActiveTranslation("alert");
  }, 0);
}

// --- Playstore Scanner ---
async function runPlaystoreScan() {
  const url = $("playstoreInput").value.trim();
  if (!url) return;
  setActionButtonBusy("playstoreSearchBtn", true, "Scanning...");
  $("playstoreResultsHeader").classList.add("hidden");
  clearPagination("playstorePagination");
  setExportToolbarState("playstoreExportBar", false);
  showListScanLoading("playstoreStatus", "playstoreResults", "Queued: hunting for cracked or modded APK mirrors...", "cards", 2);

  try {
    const data = await apiFetch("/apk/scan", false, {
      method: "POST",
      body: { playstore_url: url }
    });
    if (data.status === "error") {
      state.scanExports.playstore = { query: url, items: [] };
      $("playstoreStatus").textContent = `Error: ${data.message}`;
      setExportToolbarState("playstoreExportBar", false);
      return;
    }
    const items = data.results || [];
    state.scanExports.playstore = { query: url, items };
    $("playstoreStatus").textContent = items.length ? `${items.length} result(s) returned.` : "No cracked versions found.";
    if (items.length) {
      $("playstoreResultsHeader").classList.remove("hidden");
      $("playstoreQueryLabel").textContent = url.length > 30 ? url.substring(0, 27) + "..." : url;
      $("playstoreCount").textContent = items.length;
      setClientPaginatedItems("playstore", items);
      setExportToolbarState("playstoreExportBar", true, `${items.length} Playstore result(s) ready for export.`);
      await renderClientPaginatedResults("playstore", 1);
    } else {
      $("playstoreResults").innerHTML = "";
      clearPagination("playstorePagination");
      setExportToolbarState("playstoreExportBar", false);
    }
  } catch (error) {
    state.scanExports.playstore = { query: url, items: [] };
    $("playstoreStatus").textContent = `Scan failed: ${error.message}`;
    $("playstoreResults").innerHTML = "";
    clearPagination("playstorePagination");
    setExportToolbarState("playstoreExportBar", false);
  } finally {
    setActionButtonBusy("playstoreSearchBtn", false, "Scanning...");
  }
}

function renderPlaystoreCard(item) {
  return `
    <article class="result-card">
      <div class="result-card-header">
        <div class="result-card-headline">
          <span class="result-card-eyebrow">${escapeHtml(item.source || item.network || "clearnet")}</span>
          <h3 class="result-card-title">${escapeHtml(normalizePreviewText(item.app_name || "Unknown Application", "Unknown Application"))}</h3>
        </div>
        <span class="result-status-pill ${item.version ? "is-good" : "is-muted"}">${escapeHtml(item.version || "Unknown Version")}</span>
      </div>
      <p class="result-card-desc">${escapeHtml(normalizePreviewText((item.description || "").trim() || "Description not available from the source page.", "Description not available from the source page."))}</p>
      <div class="result-card-grid">
        <div class="result-card-field">
          <span class="result-card-field-label">Package</span>
          <span class="result-card-field-value">${escapeHtml(item.package_id || "N/A")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Updated</span>
          <span class="result-card-field-value">${escapeHtml(item.latest_date || "N/A")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Size</span>
          <span class="result-card-field-value">${escapeHtml(item.apk_size || "N/A")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Type</span>
          <span class="result-card-field-value">${escapeHtml(item.content_type || "apk")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Publisher</span>
          <span class="result-card-field-value">${escapeHtml(item.publisher || "N/A")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Network</span>
          <span class="result-card-field-value">${escapeHtml(item.network || "clearnet")}</span>
        </div>
      </div>
      <div class="result-card-note">
        <span class="result-card-note-label">Mod Features</span>
        <p class="result-card-note-copy">${escapeHtml(normalizePreviewText(item.mod_features || "Standard features info not provided.", "Standard features info not provided."))}</p>
      </div>
      <div class="result-card-actions">
        <a href="${escapeHtml(item.url || "#")}" target="_blank" rel="noopener noreferrer" class="btn-action">View Page</a>
        ${item.download_link ? `<a href="${escapeHtml(item.download_link)}" target="_blank" rel="noopener noreferrer" class="btn-action btn-action-primary">Download APK</a>` : ""}
      </div>
    </article>
  `;
}

// --- PC Game Scanner ---
async function runSoftwareScan() {
  const query = $("softwareInput").value.trim();
  if (!query) return;
  setActionButtonBusy("softwareSearchBtn", true, "Scanning...");
  $("softwareResultsHeader").classList.add("hidden");
  clearPagination("softwarePagination");
  setExportToolbarState("softwareExportBar", false);
  showListScanLoading("softwareStatus", "softwareResults", "Queued: checking matching PC game/software sources...", "accordion", 3);

  try {
    const data = await apiFetch("/pcgame/scan", false, {
      method: "POST",
      body: { game_name: query }
    });
    if (data.status === "error" || data.detail) {
      state.scanExports.software = { query, items: [] };
      $("softwareStatus").textContent = `Error: ${data.message || data.detail}`;
      setExportToolbarState("softwareExportBar", false);
      return;
    }
    const items = data.results || [];
    state.scanExports.software = { query, items };
    $("softwareStatus").textContent = items.length ? `${items.length} result(s) returned.` : "No matches found.";
    if (items.length) {
      $("softwareResultsHeader").classList.remove("hidden");
      $("softwareCount").textContent = items.length;
      $("softwareQueryLabel").textContent = query.length > 30 ? query.substring(0, 27) + "..." : query;
      setClientPaginatedItems("software", items);
      setExportToolbarState("softwareExportBar", true, `${items.length} PC game result(s) ready for export.`);
      await renderClientPaginatedResults("software", 1);
    } else {
      $("softwareResults").innerHTML = "";
      clearPagination("softwarePagination");
      setExportToolbarState("softwareExportBar", false);
    }
  } catch (error) {
    state.scanExports.software = { query, items: [] };
    $("softwareStatus").textContent = `Scan failed: ${error.message}`;
    $("softwareResults").innerHTML = "";
    clearPagination("softwarePagination");
    setExportToolbarState("softwareExportBar", false);
  } finally {
    setActionButtonBusy("softwareSearchBtn", false, "Scanning...");
  }
}

function renderSoftwareAccordion(item) {
  const fields = [
    { label: "App Name", value: item.app_name || item.name || "not available" },
    { label: "Package Id", value: item.package_id || "not available" },
    { label: "App Url", value: item.app_url || item.url || "not available" },
    { label: "Source", value: item.source || "not available" },
    { label: "Network", value: item.network || "clearnet" },
    { label: "Version", value: item.version || "not available" },
    { label: "Content Type", value: item.content_type || "pc_game" },
    { label: "Download Link", value: item.download_link || "[]" },
    { label: "Apk Size", value: item.apk_size || "not available" },
    { label: "Latest Date", value: item.latest_date || "not available" },
    { label: "Mod Features", value: item.mod_features || "not available" }
  ];
  const gridHtml = fields.map(f => `
    <div class="software-field-box">
      <span class="field-label">${escapeHtml(f.label)}</span>
      <span class="field-value">${escapeHtml(f.value)}</span>
    </div>
  `).join("");
  return `
    <details class="software-accordion">
      <summary>
        <div class="software-summary-title">
          <strong>${escapeHtml(normalizePreviewText(item.app_name || item.name || "Untitled", "Untitled"))}</strong>
          <small>${fields.length} Fields</small>
        </div>
      </summary>
      <div class="software-details-grid">${gridHtml}</div>
    </details>
  `;
}

// --- Repository Scanner ---
async function runRepoScan() {
  const url = $("repoScanInput").value.trim();
  if (!url) return;
  setActionButtonBusy("repoScanSearchBtn", true, "Scanning...");
  setExportToolbarState("repoExportBar", false);
  showReportScanLoading("repoScanStatus", "repoScanReport", "repo", "Queued: analyzing repository posture and dependency coverage...");

  try {
    const data = await apiFetch("/scan/repo", false, {
      method: "POST",
      body: { url: url }
    });
    if (data.status === "error") {
      state.scanExports.repo = null;
      restoreReportTemplate("repoScanReport", "repo");
      $("repoScanReport").classList.add("hidden");
      $("repoScanStatus").textContent = `Scan Error: ${data.message}`;
      setExportToolbarState("repoExportBar", false);
      return;
    }
    restoreReportTemplate("repoScanReport", "repo");
    $("repoScanReport").classList.remove("hidden");
    state.scanExports.repo = data;
    renderRepoReport(data);
    const summary = data.summary || {};
    $("repoScanStatus").textContent = `Scan complete. Grade ${summary.grade || "A"} - ${summary.posture_label || "Repository posture ready"}.`;
    setExportToolbarState("repoExportBar", true, `Repository report ready. Grade ${summary.grade || "A"} with ${((data.misconfigs?.length || 0) + (data.secrets?.length || 0) + (data.vulnerabilities?.length || 0))} finding(s).`);
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    state.scanExports.repo = null;
    restoreReportTemplate("repoScanReport", "repo");
    $("repoScanReport").classList.add("hidden");
    $("repoScanStatus").textContent = `Scan failed: ${error.message}`;
    setExportToolbarState("repoExportBar", false);
  } finally {
    setActionButtonBusy("repoScanSearchBtn", false, "Scanning...");
  }
}

