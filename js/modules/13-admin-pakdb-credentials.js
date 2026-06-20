window.deleteUser = async username => {
  if ((username || "").trim().toLowerCase() === (localStorage.getItem(USER_NAME_KEY) || "").trim().toLowerCase()) {
    showToast("You cannot reject your own admin account.", "error");
    return;
  }
  try {
    await apiFetch(`/admin/users/${username}/reject`, false, { method: "POST" });
    showToast(`${username} rejected.`, "success");
    refreshUserList();
  } catch (error) {
    showToast(error.message || "Could not reject user.", "error");
  }
};

window.resolvePasswordResetRequest = async requestId => {
  await apiFetch(`/admin/password-reset-requests/${requestId}/resolve`, false, { method: "POST" });
  refreshPasswordResetRequests();
  showToast("Password recovery request marked as reviewed.", "success");
};

async function runPakdbLookup() {
  const number = $("pakdbInput").value.trim();
  if (!number) return;

  setActionButtonBusy("pakdbSearchBtn", true, "Opening Tor...");
  clearPagination("pakdbPagination");
  setExportToolbarState("pakdbExportBar", false);
  $("pakdbHistoryList").innerHTML = "";
  $("pakdbStatus").innerHTML = `
    <span class="scan-status-loading">
      <span class="scan-status-pulse"></span>
      Opening configured lookup site in Tor Browser...
    </span>
  `;

  try {
    const data = await apiFetch("/pakdb/launch-tor", false, {
      method: "POST",
      body: { number }
    });

    $("pakdbImportPanel").classList.remove("hidden");
    $("pakdbStatus").textContent = data.message || "Tor Browser opened. Complete the lookup manually, then paste the result and click Import Result.";
    showToast("Tor Browser opened for manual lookup.", "success");
  } catch (error) {
    state.scanExports.pakdb = { query: number, items: [] };
    $("pakdbStatus").textContent = error.message;
    $("pakdbHistoryList").innerHTML = "";
    clearPagination("pakdbPagination");
    setExportToolbarState("pakdbExportBar", false);
  } finally {
    setActionButtonBusy("pakdbSearchBtn", false, "Opening Tor...");
  }
}

async function importPakdbManualResult() {
  const number = $("pakdbInput").value.trim();
  const rawResult = $("pakdbImportInput").value.trim();
  if (!rawResult) {
    $("pakdbStatus").textContent = "Paste result text, HTML, or JSON before importing.";
    return;
  }

  setActionButtonBusy("pakdbImportBtn", true, "Importing...");
  clearPagination("pakdbPagination");
  setExportToolbarState("pakdbExportBar", false);
  showListScanLoading("pakdbStatus", "pakdbHistoryList", "Parsing pasted manual result...", "compact", 3);

  try {
    const data = await apiFetch("/pakdb/import", false, {
      method: "POST",
      body: { number, raw_result: rawResult }
    });

    const items = data.results || [];
    state.scanExports.pakdb = { query: data.query || number, items };
    $("pakdbStatus").textContent = data.message || `${items.length} imported result(s).`;
    setClientPaginatedItems("pakdb", items);
    setExportToolbarState("pakdbExportBar", items.length > 0, `${items.length} imported national identity result(s) ready for export.`);
    await renderClientPaginatedResults("pakdb", 1);
    showToast("Manual result imported.", "success");
  } catch (error) {
    state.scanExports.pakdb = { query: number, items: [] };
    $("pakdbStatus").textContent = error.message;
    $("pakdbHistoryList").innerHTML = "";
    clearPagination("pakdbPagination");
    setExportToolbarState("pakdbExportBar", false);
  } finally {
    setActionButtonBusy("pakdbImportBtn", false, "Importing...");
  }
}

async function runCredentialCheck(page = 1) {
  const fallbackQuery = state.credentialPager.query || "";
  const query = page > 1 ? fallbackQuery : $("credentialInput").value.trim();
  if (!query) return;

  state.credentialPager.query = query;
  setActionButtonBusy("credentialSearchBtn", true, "Searching...");
  $("credentialStats").classList.add("hidden");
  $("credentialDatasetMeta").classList.add("hidden");
  clearPagination("credentialPagination");
  setExportToolbarState("credentialExportBar", false);
  showListScanLoading("credentialStatus", "credentialResults", "Syncing saved JSON files into Mongo and searching exposure records...", "accordion", 4);

  try {
    const data = await apiFetch("/credentials/search", false, {
      method: "POST",
      body: {
        query,
        page,
        limit: PAGE_SIZE
      }
    });

    if (data.status === "error") {
      state.scanExports.credential = null;
      $("credentialStatus").textContent = `Error: ${data.message}`;
      $("credentialResults").innerHTML = "";
      clearPagination("credentialPagination");
      setExportToolbarState("credentialExportBar", false);
      return;
    }

    state.credentialPager = {
      query,
      page: Number(data.page || page || 1),
      totalPages: Number(data.total_pages || 0),
      totalItems: Number(data.count || 0)
    };
    state.scanExports.credential = data;

    renderCredentialResults(data);
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    state.scanExports.credential = null;
    $("credentialStatus").textContent = `Scan failed: ${error.message}`;
    $("credentialResults").innerHTML = "";
    $("credentialStats").classList.add("hidden");
    $("credentialDatasetMeta").classList.add("hidden");
    clearPagination("credentialPagination");
  } finally {
    setActionButtonBusy("credentialSearchBtn", false, "Searching...");
  }
}

function renderCredentialResults(data) {
  const items = Array.isArray(data.results) ? data.results : [];
  const datasets = Array.isArray(data.datasets) ? data.datasets : [];
  const pageSize = Number(data.per_page || PAGE_SIZE);
  const currentPage = Number(data.page || 1);
  const totalCount = Number(data.count || items.length || 0);
  const metrics = getPaginationMetrics(totalCount, currentPage, pageSize);

  $("credentialStatus").textContent = data.message || (items.length
    ? `${items.length} redacted credential exposure result(s) found.`
    : "No matching exposure records were found.");

  $("credentialElapsed").textContent = `${Number(data.elapsed_ms || 0)} ms`;
  $("credentialCount").textContent = String(Number(data.count || items.length || 0));
  $("credentialHosts").textContent = String(Number(data.hosts_count || 0));
  $("credentialFiles").textContent = String(Number(data.aggregated_count || 0));
  $("credentialStats").classList.toggle("hidden", !datasets.length);

  const datasetMeta = $("credentialDatasetMeta");
  if (datasets.length) {
    datasetMeta.classList.remove("hidden");
    datasetMeta.innerHTML = `
      <span class="credential-meta-pill">Mongo Files: ${escapeHtml(String(data.files_loaded || datasets.length))}</span>
      ${datasets.map(name => `<span class="credential-meta-pill">${escapeHtml(name)}</span>`).join("")}
    `;
  } else {
    datasetMeta.classList.add("hidden");
    datasetMeta.innerHTML = "";
  }

  if (!items.length) {
    $("credentialResults").innerHTML = `
      <div class="credential-empty-state">
        <h3 class="credential-section-title">No Results</h3>
        <p class="credential-empty-copy">${escapeHtml(data.message || "No matching records were found in the currently loaded datasets.")}</p>
      </div>
    `;
    clearPagination("credentialPagination");
    setExportToolbarState("credentialExportBar", false);
    return;
  }

  $("credentialResults").innerHTML = items.map((item, index) => renderCredentialResultItem(item, metrics.startIndex + index + 1)).join("");
  setExportToolbarState("credentialExportBar", true, `${totalCount} redacted result(s) available across ${Math.max(metrics.totalPages, 1)} page(s).`);
  renderPagination("credentialPagination", "credential", {
    ...metrics,
    endLabel: Math.min(metrics.startIndex + items.length, totalCount)
  });
}

function renderCredentialResultItem(item, index) {
  const tags = Array.isArray(item.metadata_tags) ? item.metadata_tags : [];
  const maskedPassword = String(item.password ?? "").trim() || "-";
  const maskedTrace = String(item.raw_trace ?? "").trim() || "No trace available.";
  return `
    <details class="credential-log-card"${index === 1 ? " open" : ""}>
      <summary class="credential-log-summary">
        <span class="credential-col credential-col-index">${index}</span>
        <span class="credential-col credential-col-host">${escapeHtml(item.domain_host || "-")}</span>
        <span class="credential-col credential-col-identifier">${escapeHtml(item.credential_identifier || "-")}</span>
        <span class="credential-col credential-col-date">${escapeHtml(item.date || "-")}</span>
        <span class="credential-toggle-icon" aria-hidden="true"></span>
      </summary>

      <div class="credential-log-body">
        <div class="credential-pill-row">
          <span class="badge-outline">Stealer Log</span>
          <span class="credential-source-pill">Source File: ${escapeHtml(item.source_file || "-")}</span>
        </div>

        <div class="credential-detail-grid credential-detail-grid-top">
          <div class="credential-detail-card">
            <span class="credential-detail-label">Source Domain</span>
            <span class="credential-detail-value">${escapeHtml(item.source_domain || "-")}</span>
          </div>
          <div class="credential-detail-card">
            <span class="credential-detail-label">Channel</span>
            <span class="credential-detail-value">${escapeHtml(item.channel || "-")}</span>
          </div>
          <div class="credential-detail-card">
            <span class="credential-detail-label">Year</span>
            <span class="credential-detail-value">${escapeHtml(item.year || "-")}</span>
          </div>
          <div class="credential-detail-card">
            <span class="credential-detail-label">File Type</span>
            <span class="credential-detail-value">${escapeHtml(item.file_type || "-")}</span>
          </div>
        </div>

        <div class="credential-section-block">
          <h4 class="credential-section-title">Identity Intelligence</h4>
          <div class="credential-detail-grid credential-detail-grid-main">
            <div class="credential-detail-card credential-detail-highlight">
              <span class="credential-detail-label">Email / Username</span>
              <span class="credential-detail-value">${escapeHtml(item.email_username || item.credential_identifier || "-")}</span>
            </div>
            <div class="credential-detail-card credential-detail-highlight">
              <span class="credential-detail-label">Domain</span>
              <span class="credential-detail-value">${escapeHtml(item.domain || "-")}</span>
            </div>
            <div class="credential-detail-card">
              <span class="credential-detail-label">IP</span>
              <span class="credential-detail-value">${escapeHtml(item.ip || "-")}</span>
            </div>
            <div class="credential-detail-card">
              <span class="credential-detail-label">Password</span>
              <span class="credential-detail-value">${escapeHtml(maskedPassword)}</span>
            </div>
          </div>
        </div>

        <div class="credential-section-block">
          <h4 class="credential-section-title">Metadata Telemetry Array</h4>
          <div class="credential-tag-row">
            ${tags.length
              ? tags.map(tag => `<span class="credential-tag-chip">${escapeHtml(tag.label || "Tag")} <strong>${escapeHtml(String(tag.count ?? 1))}</strong></span>`).join("")
              : `<span class="credential-tag-chip">No metadata tags</span>`}
          </div>
        </div>

        <div class="credential-section-block">
          <h4 class="credential-section-title">Raw Trace Buffer</h4>
          <pre class="credential-trace">${escapeHtml(maskedTrace)}</pre>
        </div>
      </div>
    </details>
  `;
}

function renderCredentialDatasetMeta(datasets) {
  const datasetMeta = $("credentialDatasetMeta");
  const items = Array.isArray(datasets) ? datasets : [];

  if (!items.length) {
    datasetMeta.classList.add("hidden");
    datasetMeta.innerHTML = "";
    return;
  }

  datasetMeta.classList.remove("hidden");
  datasetMeta.innerHTML = items.map(item => {
    const label = typeof item === "string"
      ? item
      : `${item.name || "dataset"}${item.records_count != null ? ` (${item.records_count})` : ""}`;
    return `<span class="credential-meta-pill">${escapeHtml(label)}</span>`;
  }).join("");
}

async function refreshCredentialDatasets(showStatus = true) {
  try {
    const data = await apiFetch("/credentials/datasets", false);
    renderCredentialDatasetMeta(data.datasets || []);
    $("credentialStats").classList.add("hidden");

    if (showStatus) {
      $("credentialStatus").textContent = data.message || "Saved backend datasets are already synced into Mongo and ready.";
    }

    if (!Array.isArray(data.datasets) || !data.datasets.length) {
      state.scanExports.credential = null;
      $("credentialResults").innerHTML = `
        <div class="credential-empty-state">
          <h3 class="credential-section-title">No Datasets</h3>
          <p class="credential-empty-copy">No JSON files are saved in <code>data/credential_checker</code> yet. Once the backend folder has files, search will use them automatically. Upload is optional.</p>
        </div>
      `;
      clearPagination("credentialPagination");
      setExportToolbarState("credentialExportBar", false);
    }
  } catch (error) {
    state.scanExports.credential = null;
    $("credentialStatus").textContent = `Dataset sync failed: ${error.message}`;
    clearPagination("credentialPagination");
    setExportToolbarState("credentialExportBar", false);
  }
}

async function uploadCredentialDatasets(fileList) {
  const files = Array.from(fileList || []);
  if (!files.length) return;

  setActionButtonBusy("credentialUploadBtn", true, "Uploading...", "Optional Upload");
  $("credentialStatus").textContent = "Saving files to disk and syncing them into Mongo...";

  try {
    const headers = {};
    const token = getToken();
    const apiKey = localStorage.getItem(STORAGE_KEY) || "";
    if (token) headers.Authorization = `Bearer ${token}`;
    if (apiKey) headers["X-API-Key"] = apiKey;

    const formData = new FormData();
    files.forEach(file => formData.append("files", file));

    const response = await fetch(`${getBase()}/credentials/upload`, {
      method: "POST",
      headers,
      body: formData
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || data.message || `HTTP ${response.status}`);
    }

    renderCredentialDatasetMeta(data.datasets || []);
    $("credentialStatus").textContent = data.message || "Datasets were saved on disk and synced into Mongo.";

    const query = $("credentialInput").value.trim();
    if (query) {
      await runCredentialCheck();
    } else {
      state.scanExports.credential = null;
      $("credentialResults").innerHTML = `
        <div class="credential-empty-state">
          <h3 class="credential-section-title">Datasets Ready</h3>
          <p class="credential-empty-copy">Your JSON files are saved on disk and loaded into Mongo. Enter a domain like <code>ucp.edu.pk</code> or <code>bahria.edu.pk</code> to search.</p>
        </div>
      `;
      clearPagination("credentialPagination");
      setExportToolbarState("credentialExportBar", false);
    }
  } catch (error) {
    state.scanExports.credential = null;
    $("credentialStatus").textContent = `Upload failed: ${error.message}`;
    clearPagination("credentialPagination");
    setExportToolbarState("credentialExportBar", false);
  } finally {
    setActionButtonBusy("credentialUploadBtn", false, "Uploading...", "Optional Upload");
    $("credentialFileInput").value = "";
  }
}

function getConfidentialFilteredFindings() {
  const typeFilter = $("confidentialTypeFilter").value;
  const riskFilter = $("confidentialRiskFilter").value;
  const confidenceFilter = $("confidentialConfidenceFilter").value;
  const statusFilter = $("confidentialStatusFilter").value;
  return state.confidentialFindings.filter(item => {
    if (typeFilter && item.detected_type !== typeFilter) return false;
    if (riskFilter && item.risk_level !== riskFilter) return false;
    if (confidenceFilter && item.detection_confidence !== confidenceFilter) return false;
    if (statusFilter && item.status !== statusFilter) return false;
    return true;
  });
}

function renderConfidentialTypeOptions(items) {
  const select = $("confidentialTypeFilter");
  const current = select.value;
  const types = [...new Set((items || []).map(item => item.detected_type).filter(Boolean))].sort();
  select.innerHTML = `<option value="">All Types</option>${types.map(type => `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`).join("")}`;
  if (types.includes(current)) select.value = current;
}

function riskBadgeClass(value) {
  const risk = String(value || "").toLowerCase();
  if (risk === "high") return "status-error";
  if (risk === "medium") return "status-running";
  return "status-ok";
}

const CONFIDENTIAL_PARSED_FIELD_LABELS = [
  ["masked_card_number", "Masked Card Number"],
  ["expiry_date", "Expiry Date"],
  ["cvv", "CVV"],
  ["cardholder_name", "Cardholder Name"],
  ["address_line_1", "Address Line 1"],
  ["address_line_2", "Address Line 2"],
  ["city", "City"],
  ["state_region", "State / Region"],
  ["postal_code", "Postal Code"],
  ["country", "Country"],
  ["masked_phone", "Masked Phone"],
  ["masked_email", "Masked Email"],
  ["extra_field", "Extra Field"],
  ["masked_ip_address", "Masked IP Address"],
  ["masked_user_agent", "Masked User Agent"]
];

function getConfidentialParsedField(item, key) {
  const value = item?.parsed_fields?.[key];
  return value && String(value).trim() ? String(value) : "N/A";
}

function getConfidentialParsedFieldRows(item) {
  return CONFIDENTIAL_PARSED_FIELD_LABELS.map(([key, label]) => [label, getConfidentialParsedField(item, key)]);
}

function formatConfidentialTimestamp(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

