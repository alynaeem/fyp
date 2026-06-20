function setupEventListeners() {
  initSidebarAutomationCollapse();

  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      const target = item.dataset.view || item.dataset.tab;
      if (target) switchView(target);
    });
  });

  document.querySelectorAll(".stat-pill[data-tab]").forEach(item => {
    item.addEventListener("click", () => {
      const target = item.dataset.tab;
      if (target) switchView(target);
    });
  });

  $("detailClose").addEventListener("click", closeDetailModal);
  $("detailBackdrop").addEventListener("click", event => {
    if (event.target === $("detailBackdrop")) closeDetailModal();
  });
  $("cardsGrid").addEventListener("click", async event => {
    const actionButton = event.target.closest("[data-card-action]");
    if (!actionButton) return;
    event.stopPropagation();
    const card = actionButton.closest(".intel-card");
    const aid = card?.dataset.aid;
    if (!aid) return;
    if (actionButton.dataset.cardAction === "summary") {
      toggleCardSummary(card);
      return;
    }
    if (actionButton.dataset.cardAction === "detail") {
      await showDetail(aid);
      return;
    }
    if (actionButton.dataset.cardAction === "translate") {
      await showDetail(aid);
      openTranslateModal("detail");
    }
  });
  $("modalMediaGallery").addEventListener("click", event => {
    const card = event.target.closest(".modal-media-card");
    if (!card) return;
    openMediaLightbox(card.dataset.mediaSrc || "", card.dataset.mediaTitle || "Evidence image");
  });
  $("mediaLightboxClose").addEventListener("click", closeMediaLightbox);
  $("leakSourceRefreshBtn").addEventListener("click", () => loadLeakSourceStatus(false));
  $("mediaLightboxBackdrop").addEventListener("click", event => {
    if (event.target === $("mediaLightboxBackdrop")) closeMediaLightbox();
  });

  $("settingsBtn").addEventListener("click", () => {
    $("apiBaseInput").value = getBase();
    $("apiKeyInput").value = localStorage.getItem(STORAGE_KEY) || "";
    $("settingsBackdrop").classList.remove("hidden");
  });

  $("settingsClose").onclick = () => $("settingsBackdrop").classList.add("hidden");
  $("alertSummaryClose").onclick = closeAlertSummaryModal;
  $("alertSummaryDone").onclick = closeAlertSummaryModal;
  $("logoutBtn").onclick = () => handleLogout();
  $("smartUpdateBtn").onclick = triggerSmartUpdate;
  $("stopSmartUpdateBtn").onclick = stopSmartUpdate;
  $("alertSummaryBtn").onclick = showAlertSummary;
  $("translateViewBtn").onclick = () => openTranslateModal("view");
  $("detailTranslateBtn").onclick = () => openTranslateModal("detail");
  $("translateClose").onclick = closeTranslateModal;
  $("translateApplyBtn").onclick = applySelectedTranslation;
  $("translateResetModalBtn").onclick = resetTranslationToEnglish;
  $("resetLanguageBtn").onclick = resetTranslationToEnglish;
  $("feedFilterBtn").onclick = openFeedFiltersModal;
  $("feedFiltersClose").onclick = closeFeedFiltersModal;
  $("feedFiltersApplyBtn").onclick = () => applyFeedFilters({ closeModal: true });
  $("feedFiltersResetBtn").onclick = resetFeedFilters;
  ["feedFilterStartDate", "feedFilterEndDate", "feedFilterNetwork", "feedFilterTopic"].forEach(id => {
    const input = $(id);
    if (input) input.addEventListener("change", () => applyFeedFilters({ closeModal: false }));
  });
  $("aiChatLaunchBtn").onclick = dpChatShow;
  $("dpChatFab").onclick = dpChatShow;
  $("dpChatCloseBtn").onclick = dpChatHide;
  $("dpChatMinBtn").onclick = dpChatMinimize;
  $("dpChatSendBtn").onclick = runAiChatQuery;
  $("dpChatClearBtn").onclick = dpChatClear;
  $("dpChatInput").addEventListener("keydown", event => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      runAiChatQuery();
    }
  });

  // Show FAB after auth
  dpChatShowFab();

  window.onclick = e => {
    if (e.target === $("settingsBackdrop")) $("settingsBackdrop").classList.add("hidden");
    if (e.target === $("alertSummaryBackdrop")) closeAlertSummaryModal();
    if (e.target === $("mediaLightboxBackdrop")) closeMediaLightbox();
    if (e.target === $("translateBackdrop")) closeTranslateModal();
    if (e.target === $("feedFiltersBackdrop")) closeFeedFiltersModal();
  };

  $("saveSettingsBtn").addEventListener("click", () => {
    localStorage.setItem(API_BASE_KEY, $("apiBaseInput").value.trim() || DEFAULT_API_BASE);
    localStorage.setItem(STORAGE_KEY, $("apiKeyInput").value.trim());
    window.location.reload();
  });

  $("testConnBtn").addEventListener("click", async () => {
    const base = $("apiBaseInput").value.trim() || DEFAULT_API_BASE;
    const result = $("testResult");
    result.textContent = "Testing connection...";
    try {
      const response = await fetch(`${base}/health`);
      const data = await response.json();
      result.textContent = data.status === "ok" ? "Connection successful." : "Connection reachable but degraded.";
    } catch {
      result.textContent = "Connection failed.";
    }
  });

  $("authSubmitBtn").addEventListener("click", handleAuthSubmit);
  $("showRegisterLink").addEventListener("click", event => {
    event.preventDefault();
    toggleAuthMode();
  });
  $("showApprovalLink").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    clearAuthChallenge();
    setAuthStage("approval");
  });
  $("showForgotLink").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    clearAuthChallenge();
    setAuthStage("forgot");
  });
  $("showLoginLink").addEventListener("click", event => {
    event.preventDefault();
    toggleAuthMode();
  });
  $("forgotBackToLogin").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    setAuthStage("login");
  });
  $("approvalBackToLogin").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    setAuthStage("login");
  });
  $("approvalOpenRegister").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    setAuthStage("register");
  });
  $("mfaBackToLogin").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    clearAuthChallenge();
    setAuthStage("login");
  });
  ["loginUsername", "loginPassword", "mfaOtpInput", "regName", "regEmail", "regUsername", "regPassword", "forgotIdentity", "forgotMessage"].forEach(id => {
    $(id).addEventListener("keydown", event => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      handleAuthSubmit();
    });
  });

  $("searchInput").addEventListener("input", debounce(() => {
    const query = $("searchInput").value.trim();
    if (!query) {
      handleHeaderSearch(false);
      return;
    }
    if (state.currentView === "homepage" || state.currentView === "docs") return;
    if (!TOOL_VIEWS.includes(state.currentView)) {
      handleHeaderSearch(false);
    }
  }, SEARCH_DEBOUNCE_MS));

  $("searchInput").addEventListener("keydown", event => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    handleHeaderSearch(true);
  });

  document.addEventListener("click", async event => {
    const button = event.target.closest("[data-pagination-target]");
    if (!button) return;
    event.preventDefault();
    if (button.disabled) return;
    await handlePaginationChange(button.dataset.paginationTarget || "", button.dataset.paginationPage || "1");
  });

  document.addEventListener("click", async event => {
    const button = event.target.closest("[data-export-target]");
    if (!button) return;
    event.preventDefault();
    if (button.disabled) return;
    await handleExportAction(button.dataset.exportTarget || "", button.dataset.exportFormat || "json", button);
  });

  $("pakdbSearchBtn").addEventListener("click", runPakdbLookup);
  $("pakdbInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runPakdbLookup();
  });
  $("pakdbImportBtn").addEventListener("click", importPakdbManualResult);
  $("pakdbImportClearBtn").addEventListener("click", () => {
    $("pakdbImportInput").value = "";
    $("pakdbStatus").textContent = "Paste result text, HTML, or JSON after completing the lookup in Tor Browser.";
  });
  $("credentialSearchBtn").addEventListener("click", runCredentialCheck);
  $("credentialInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runCredentialCheck();
  });
  $("credentialUploadBtn").addEventListener("click", () => $("credentialFileInput").click());
  $("credentialRefreshBtn").addEventListener("click", () => refreshCredentialDatasets(true));
  $("credentialFileInput").addEventListener("change", event => {
    uploadCredentialDatasets(event.target.files);
  });
  $("confidentialAnalyzeBtn").addEventListener("click", runConfidentialAnalysis);
  ["confidentialTypeFilter", "confidentialRiskFilter", "confidentialConfidenceFilter", "confidentialStatusFilter"].forEach(id => {
    $(id).addEventListener("change", renderConfidentialResults);
  });
  $("confidentialResultsBody").addEventListener("click", event => {
    const button = event.target.closest("[data-confidential-detail]");
    if (!button) return;
    showConfidentialDetail(button.dataset.confidentialDetail || "");
  });
  $("confidentialResultsBody").addEventListener("change", event => {
    const select = event.target.closest("[data-confidential-status]");
    if (!select) return;
    const recordId = select.dataset.confidentialStatus || "";
    const item = state.confidentialFindings.find(entry => entry.record_id === recordId);
    if (!item) return;
    item.status = select.value;
    if (state.scanExports.confidential && Array.isArray(state.scanExports.confidential.results)) {
      const exported = state.scanExports.confidential.results.find(entry => entry.record_id === recordId);
      if (exported) exported.status = select.value;
    }
  });
  $("confidentialDetailClose").addEventListener("click", closeConfidentialDetailModal);
  $("confidentialDetailDismiss").addEventListener("click", closeConfidentialDetailModal);
  $("confidentialDetailBackdrop").addEventListener("click", event => {
    if (event.target === $("confidentialDetailBackdrop")) closeConfidentialDetailModal();
  });
  $("playstoreSearchBtn").addEventListener("click", runPlaystoreScan);
  $("playstoreInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runPlaystoreScan();
  });
  $("softwareSearchBtn").addEventListener("click", runSoftwareScan);
  $("softwareInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runSoftwareScan();
  });
  $("seoSearchBtn").addEventListener("click", runSeoScan);
  $("seoInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runSeoScan();
  });
  $("repoScanSearchBtn").addEventListener("click", runRepoScan);
  $("repoScanInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runRepoScan();
  });
  $("healingDiscoverBtn").addEventListener("click", runHealingDiscover);
  $("healingRunBtn").addEventListener("click", () => runHealingMonitor());
  $("healingRefreshBtn").addEventListener("click", () => loadHealingMonitor());
  $("healingSearchInput").addEventListener("input", () => {
    state.healingMonitor.filters.query = $("healingSearchInput").value.trim();
    resetHealingListPage();
  });
  $("healingCollectorFilter").addEventListener("change", () => {
    state.healingMonitor.filters.collector = $("healingCollectorFilter").value.trim();
    resetHealingListPage();
  });
  $("healingStatusFilter").addEventListener("change", () => {
    state.healingMonitor.filters.status = $("healingStatusFilter").value.trim();
    resetHealingListPage();
  });
  $("healingIssueFilter").addEventListener("change", () => {
    state.healingMonitor.filters.issue = $("healingIssueFilter").value.trim();
    resetHealingListPage();
  });
  $("healingPrevPageBtn").addEventListener("click", () => {
    state.healingMonitor.filters.page = Math.max(1, state.healingMonitor.filters.page - 1);
    renderHealingScriptList();
  });
  $("healingNextPageBtn").addEventListener("click", () => {
    state.healingMonitor.filters.page += 1;
    renderHealingScriptList();
  });
  $("healingCheckClose").addEventListener("click", closeHealingCheckModal);
  $("healingCheckBackdrop").addEventListener("click", event => {
    if (event.target === $("healingCheckBackdrop")) closeHealingCheckModal();
  });
  $("healingStatsGrid").addEventListener("click", event => {
    const card = event.target.closest("[data-healing-stat-filter]");
    if (!card) return;
    const filter = card.dataset.healingStatFilter || "";
    $("healingStatusFilter").value = filter;
    $("healingIssueFilter").value = "";
    state.healingMonitor.filters.status = filter;
    state.healingMonitor.filters.issue = "";
    resetHealingListPage();
  });
  $("healingScriptsTableBody").addEventListener("click", event => {
    const checkButton = event.target.closest("[data-healing-check]");
    if (checkButton) {
      runHealingMonitor(checkButton.dataset.healingCheck || "", checkButton);
      return;
    }
    const detailButton = event.target.closest("[data-healing-detail]");
    if (detailButton) {
      loadHealingScriptDetail(detailButton.dataset.healingDetail || "", detailButton.dataset.healingFocus || "");
      return;
    }
    const repairButton = event.target.closest("[data-healing-repair]");
    if (repairButton) {
      generateHealingRepair(repairButton.dataset.healingRepair || "", repairButton);
      return;
    }
    const applyButton = event.target.closest("[data-healing-apply]");
    if (applyButton) {
      applyHealingRepair(applyButton.dataset.healingApply || "", applyButton);
      return;
    }
    if (event.target.closest(".healing-inline-detail")) {
      return;
    }
    const card = event.target.closest("[data-healing-card]");
    if (card) {
      loadHealingScriptDetail(card.dataset.healingCard || "");
    }
  });

  // Account Preferences Bindings
  $("saveBrandBtn").addEventListener("click", saveAppBrand);
  $("toggleTheme").addEventListener("change", (e) => applyTheme(e.target.checked ? "light" : "dark"));
  $("toggle2fa").addEventListener("change", (e) => save2FA(e.target.checked));
}

// --- Account Settings Logic ---
async function initAccountSettings() {
  const currentTheme = localStorage.getItem("app_theme") || "dark";
  const currentBrand = localStorage.getItem("app_name") || "DarkPulse Intelligence";

  $("toggleTheme").checked = currentTheme === "light";
  $("labelThemeState").textContent = currentTheme === "light" ? "Light Mode" : "Dark Mode";

  $("projectBrandInput").value = currentBrand;
  $("profileDisplayUsername").value = localStorage.getItem(USER_NAME_KEY) || "admin";
  $("profileDisplayRole").value = (localStorage.getItem(USER_ROLE_KEY) || "user") === "admin" ? "Administrator" : "Researcher";

  $("toggle2fa").disabled = true;
  $("label2faState").textContent = "Checking status...";
  try {
    const data = await apiFetch("/auth/2fa/status");
    $("toggle2fa").checked = !!data.enabled;
    $("label2faState").textContent = data.enabled ? "Enabled" : data.setup_pending ? "Setup Pending" : "Disabled";
  } catch (error) {
    $("toggle2fa").checked = false;
    $("label2faState").textContent = "Unavailable";
  } finally {
    $("toggle2fa").disabled = false;
  }
}

function saveAppBrand() {
  const newVal = $("projectBrandInput").value.trim();
  if (!newVal) return;
  localStorage.setItem("app_name", newVal);
  const brandContainer = document.getElementById("appBrandName");
  if (brandContainer) brandContainer.textContent = newVal;
  showToast("Project name updated successfully", "success");
}

function applyTheme(theme) {
  localStorage.setItem("app_theme", theme);
  const isLight = theme === "light";
  document.body.classList.toggle("light-theme", isLight);
  document.body.dataset.theme = theme;
  document.documentElement.style.colorScheme = isLight ? "light" : "dark";

  const themeLabel = $("labelThemeState");
  if (themeLabel) {
    themeLabel.textContent = isLight ? "Light Mode" : "Dark Mode";
  }

  const toggle = $("toggleTheme");
  if (toggle) {
    toggle.checked = isLight;
  }
}

async function save2FA(isEnabled) {
  const toggle = $("toggle2fa");
  toggle.disabled = true;
  try {
    if (isEnabled) {
      const data = await apiFetch("/auth/2fa/enable", false, { method: "POST" });
      $("label2faState").textContent = "Setup Pending";
      handleLogout(data.message || "2FA setup started. Sign in again to scan the QR code and verify your OTP.");
      return;
    }

    const data = await apiFetch("/auth/2fa/disable", false, { method: "POST" });
    $("label2faState").textContent = "Disabled";
    $("toggle2fa").checked = false;
    showToast(data.message || "2FA disabled", "success");
  } catch (error) {
    $("toggle2fa").checked = !isEnabled;
    $("label2faState").textContent = $("toggle2fa").checked ? "Enabled" : "Disabled";
    showToast(error.message || "2FA update failed", "error");
  } finally {
    toggle.disabled = false;
  }
}

async function initApp() {
  // Bootstrapping App Theme & Brand
  const savedTheme = localStorage.getItem("app_theme") || "dark";
  applyTheme(savedTheme);

  const savedBrand = localStorage.getItem("app_name");
  if (savedBrand) {
    const brandContainer = document.getElementById("appBrandName");
    if (brandContainer) brandContainer.textContent = savedBrand;
  }

  cacheScanTemplates();
  refreshLanguageIndicator();
  setupEventListeners();
  renderFeedFilterState();
  if (!await checkAuth()) return;
  await checkHealth();
  await pollSmartUpdateStatus(true);
  await switchView("homepage");
  setLastUpdated();
  scheduleRefresh();
}


// --- Smart Update Orchestration ---
