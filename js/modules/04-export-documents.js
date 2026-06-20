function completeAlertSummarySources(sourceResults = []) {
  const stats = state.latestStats || {};
  const totalsBySource = {
    news: stats.news,
    leaks: stats.leak,
    social: stats.social,
    defacement: stats.defacement,
    exploit: stats.exploit,
    api: stats.api
  };
  const order = ["news", "leaks", "social", "defacement", "exploit", "api"];
  const bySource = new Map();

  (Array.isArray(sourceResults) ? sourceResults : []).forEach(item => {
    const source = item.source || item.collector || "";
    if (source) bySource.set(source, { ...item, source });
  });

  order.forEach(source => {
    if (!bySource.has(source)) {
      bySource.set(source, {
        source,
        label: SMART_UPDATE_SOURCE_LABELS[source],
        status: "not_run",
        new_records: 0,
        current_count: Number(totalsBySource[source] || 0),
        highlights: []
      });
      return;
    }
    const item = bySource.get(source);
    if (item.current_count === undefined && item.after_count === undefined && item.before_count === undefined) {
      item.current_count = Number(totalsBySource[source] || 0);
    }
  });

  return order.map(source => bySource.get(source)).filter(Boolean);
}

function formatSourceRunStatus(status) {
  switch ((status || "").toLowerCase()) {
    case "cancelled":
      return "Stopped";
    case "cancelling":
      return "Stopping";
    case "completed":
      return "Synced";
    case "failed":
      return "Failed";
    case "running":
      return "Running";
    case "queued":
      return "Queued";
    case "not_run":
      return "Not Run";
    default:
      return formatSmartUpdateStatus(status || "idle");
  }
}

function renderSmartUpdateMeta(chips) {
  $("intelNotificationMeta").innerHTML = chips.map(chip => `
    <span class="intel-meta-chip">${escapeHtml(chip)}</span>
  `).join("");
}

function renderSmartUpdateBanner(payload = {}) {
  state.smartUpdatePayload = payload;
  const bar = $("intelNotificationBar");
  const dot = $("intelNotificationDot");
  const label = $("intelNotificationLabel");
  const title = $("intelNotificationTitle");
  const message = $("intelNotificationMessage");

  const activeRun = payload.active_run;
  const latestRun = payload.latest_run;
  const rawLatestNotification = payload.latest_notification;
  const latestNotification = rawLatestNotification && !activeRun && isSmartUpdateRunning(rawLatestNotification.status)
    ? {
        ...rawLatestNotification,
        status: latestRun?.status && !isSmartUpdateRunning(latestRun.status) ? latestRun.status : "completed_no_new",
        title: latestRun?.completed_at ? "No intelligence update is running" : "No active scan is running",
        message: latestRun?.completed_at
          ? "The previous scan has finished. Press Scan Now to start a fresh hidden background sync."
          : "Press Scan Now to start a hidden background sync.",
        completed_at: latestRun?.completed_at || rawLatestNotification.completed_at,
      }
    : rawLatestNotification;
  const activeSourceResults = Array.isArray(activeRun?.source_results) ? activeRun.source_results : [];

  let status = "idle";
  let chips = ["MongoDB ready", "Arya Dashboard Alert"];

  if (activeRun && isSmartUpdateRunning(activeRun.status)) {
    status = activeRun.status;
    const liveNewTotal = activeSourceResults.reduce((sum, item) => sum + Number(item.new_records || 0), 0);
    label.textContent = formatSmartUpdateStatus(activeRun.status);
    title.textContent = activeRun.status === "cancelling"
      ? "Fast background sync is shutting down"
      : "Fast headless sync is checking for new records";
    message.textContent = activeRun.status === "cancelling"
      ? "Stop requested. DarkPulse is finalizing the latest counts from the active sources."
      : "Cached dashboard records stay visible while hidden collectors upsert new dated intelligence into MongoDB.";
    chips = [
      "Headless mode",
      "Incremental upsert",
      `New so far ${liveNewTotal}`,
      ...activeSourceResults.map(item => formatSourceProgressChip(item, true)).slice(0, 6),
      `Triggered by ${activeRun.triggered_by || "operator"}`
    ];
  } else if (latestNotification) {
    status = latestNotification.status || "idle";
    label.textContent = formatSmartUpdateStatus(status);
    title.textContent = latestNotification.title || "Intelligence update status";
    message.textContent = latestNotification.message || "Press Scan Now to refresh the intelligence database.";

    const resultChips = Array.isArray(latestNotification.source_results)
      ? latestNotification.source_results
          .filter(item => item.new_records || item.status === "failed" || item.status === "cancelled")
          .slice(0, 4)
          .map(item => formatSourceProgressChip(item, false))
      : [];

    chips = [
      `New ${latestNotification.new_records_total || 0}`,
      `Arya ${(latestNotification.delivery && latestNotification.delivery.channel_label) || "Dashboard Alert"}`,
      ...(latestNotification.completed_at ? [`Completed ${formatDate(latestNotification.completed_at)}`] : []),
      ...resultChips
    ];
  } else if (latestRun) {
    status = latestRun.status || "idle";
    label.textContent = formatSmartUpdateStatus(status);
    title.textContent = "No intelligence update is running";
    message.textContent = "Press Scan Now to run a hidden background sync. Old results stay cached while new unique records are added.";
    chips = [
      ...(latestRun.completed_at ? [`Last run ${formatDate(latestRun.completed_at)}`] : ["MongoDB ready"]),
      ...(Array.isArray(latestRun.source_results)
        ? latestRun.source_results.filter(item => item.new_records).slice(0, 4).map(item => formatSourceProgressChip(item, false))
        : [])
    ];
  } else {
    label.textContent = "Automation Idle";
    title.textContent = "No intelligence update is running";
    message.textContent = "Press Scan Now to run a hidden background sync. Old results stay cached while new unique records are added.";
    chips = ["MongoDB cache ready", "Headless collectors", "Arya Dashboard Alert"];
  }

  state.smartUpdateStatus = status;
  if (activeRun?.job_id) {
    state.smartUpdateJobId = activeRun.job_id;
  } else if (!isSmartUpdateRunning(status)) {
    state.smartUpdateJobId = "";
  }

  if (!activeRun && status === "cancelled") {
    bar.classList.add("hidden");
    renderSmartUpdateMeta([]);
    syncSmartUpdateButton(false);
    return;
  }

  bar.classList.remove("hidden");

  const visualStatus = status === "queued"
    ? "running"
    : (status === "completed" || status === "completed_no_new"
        ? "success"
        : (status === "completed_with_errors" || status === "cancelling" || status === "cancelled")
          ? "warning"
          : status === "failed"
            ? "error"
            : status);

  bar.className = `intel-notification-bar status-${visualStatus}`;
  dot.className = `intel-notification-dot dot-${visualStatus}`;
  renderSmartUpdateMeta(chips.filter(Boolean));
  syncSmartUpdateButton(isSmartUpdateRunning(status));
}

async function refreshAfterSmartUpdate() {
  await checkHealth();
  await fetchStats();

  if (state.currentView === "homepage") {
    await Promise.all([initHeatmap(), fetchRecentIntel()]);
  } else if (state.currentView === "admin-users") {
    await refreshUserList();
  } else if (state.currentView === "healing") {
    await loadHealingMonitor(true);
  } else if (!TOOL_VIEWS.includes(state.currentView)) {
    await loadArticles(true, state.feedPage || 1);
  }

  setLastUpdated();
}

function scheduleSmartUpdateMonitor(delay = SMART_UPDATE_POLL_MS) {
  clearTimeout(state.smartUpdateTimer);
  if (!getToken()) return;
  state.smartUpdateTimer = setTimeout(() => {
    pollSmartUpdateStatus();
  }, delay);
}

async function pollSmartUpdateStatus(silent = false) {
  let nextDelay = SMART_UPDATE_POLL_MS;

  try {
    const previousJobId = state.smartUpdateJobId;
    const previousStatus = state.smartUpdateStatus;
    const data = await apiFetch("/api/intelligence/status");
    renderSmartUpdateBanner(data);

    const latestRunIsActive = data.latest_run && isSmartUpdateRunning(data.latest_run.status);
    const observedRun = data.active_run || (latestRunIsActive ? null : data.latest_run);
    if (observedRun) {
      const currentStatus = observedRun.status || "idle";

      if (
        previousJobId &&
        previousJobId === observedRun.job_id &&
        isSmartUpdateRunning(previousStatus) &&
        !isSmartUpdateRunning(currentStatus)
      ) {
        await refreshAfterSmartUpdate();
        if (!silent) {
          if (currentStatus === "completed_no_new") {
            showToast("Scan complete. No new intelligence was found.", "info");
          } else if (currentStatus === "completed_with_errors") {
            showToast("Scan complete with partial source errors.", "info");
          } else if (currentStatus === "cancelled") {
            showToast(`Scan stopped. ${observedRun.new_records_total || 0} new records were kept.`, "info");
          } else if (currentStatus === "failed") {
            showToast("Automated intelligence update failed.", "error");
          } else {
            showToast(`Scan complete. ${observedRun.new_records_total || 0} new records synced.`, "success");
          }
        }
      }

      state.smartUpdateJobId = observedRun.job_id || "";
      state.smartUpdateStatus = currentStatus;
      syncSmartUpdateButton(isSmartUpdateRunning(currentStatus));
      nextDelay = isSmartUpdateRunning(currentStatus) ? 2000 : SMART_UPDATE_POLL_MS;
    } else {
      state.smartUpdateJobId = "";
      state.smartUpdateStatus = "idle";
      syncSmartUpdateButton(false);
    }
  } catch (error) {
    console.error(error);
  } finally {
    scheduleSmartUpdateMonitor(nextDelay);
  }
}

async function apiFetch(path, noAuth = false, options = {}) {
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json"
  };

  const token = getToken();
  const apiKey = localStorage.getItem(STORAGE_KEY) || "";
  if (!noAuth && token) headers.Authorization = `Bearer ${token}`;
  if (apiKey) headers["X-API-Key"] = apiKey;

  const response = await fetch(getBase() + path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: options.signal
  });

  if (response.status === 401 && !noAuth) {
    handleLogout();
    throw new Error("Session expired");
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}

function clearAuthLoadingTimer() {
  clearInterval(state.authLoadingTimer);
  state.authLoadingTimer = null;
}

function renderAuthLoading(progress = state.authLoadingProgress) {
  const safeProgress = Math.max(0, Math.min(100, Math.round(progress)));
  state.authLoadingProgress = safeProgress;
  $("authLoadingRing").style.setProperty("--auth-progress", `${safeProgress}%`);
  $("authLoadingPercent").textContent = `${safeProgress}%`;
}

function setAuthLoadingText({
  kicker = "",
  title = "",
  copy = "",
  stage = ""
} = {}) {
  if (kicker) $("authLoadingKicker").textContent = kicker;
  if (title) $("authLoadingTitle").textContent = title;
  if (copy) $("authLoadingCopy").textContent = copy;
  if (stage) $("authLoadingStage").textContent = stage;
}

function showAuthLoading({
  kicker = "Authenticating",
  title = "Signing in to DarkPulse",
  copy = "Verifying your credentials and preparing the live console.",
  stage = "Checking username and password...",
  progress = 8,
  cap = 72
} = {}) {
  state.authLoadingActive = true;
  state.authLoadingCap = Math.max(progress, cap);
  $("authLoadingOverlay").classList.remove("hidden");
  $("authShell").classList.add("auth-shell-loading");
  setAuthLoadingText({ kicker, title, copy, stage });
  renderAuthLoading(progress);
  clearAuthLoadingTimer();
  state.authLoadingTimer = setInterval(() => {
    if (!state.authLoadingActive || state.authLoadingProgress >= state.authLoadingCap) return;
    const current = state.authLoadingProgress;
    const step = current < 36 ? 4 : current < 64 ? 3 : current < 82 ? 2 : 1;
    renderAuthLoading(Math.min(state.authLoadingCap, current + step));
  }, AUTH_PROGRESS_TICK_MS);
}

async function advanceAuthLoading(target, stage = "", options = {}) {
  if (!state.authLoadingActive) return;
  state.authLoadingCap = Math.max(state.authLoadingCap, target);
  setAuthLoadingText({
    kicker: options.kicker || "",
    title: options.title || "",
    copy: options.copy || "",
    stage
  });
  renderAuthLoading(Math.max(state.authLoadingProgress, target));
  await sleep(options.delay ?? 140);
}

function hideAuthLoading() {
  state.authLoadingActive = false;
  state.authLoadingCap = 0;
  clearAuthLoadingTimer();
  $("authLoadingOverlay").classList.add("hidden");
  $("authShell").classList.remove("auth-shell-loading");
  renderAuthLoading(0);
  setAuthLoadingText({
    kicker: "Authenticating",
    title: "Signing in to DarkPulse",
    copy: "Verifying your credentials and preparing the live console.",
    stage: "Checking username and password..."
  });
}

function applyAuthenticatedIdentity(role, username, options = {}) {
  $("currentUserName").textContent = username || localStorage.getItem(USER_NAME_KEY) || "User";
  $("currentUserRole").textContent = role === "admin" ? "Administrator" : "Researcher";
  $("sidebarNavItemUsers").style.display = role === "admin" ? "flex" : "none";
  $("appWrapper").classList.remove("hidden");
  if (!options.keepBackdrop) {
    $("loginBackdrop").classList.add("hidden");
  }
  setChatAvailability(true);
}

async function warmAuthenticatedWorkspace() {
  const bootWarnings = [];

  const healthTask = checkHealth();
  const smartUpdateTask = pollSmartUpdateStatus(true);
  const homepageTask = switchView("homepage");

  const [healthResult, smartUpdateResult, homepageResult] = await Promise.allSettled([
    healthTask,
    smartUpdateTask,
    homepageTask
  ]);

  if (healthResult.status === "rejected") {
    console.error(healthResult.reason);
    bootWarnings.push("health");
  }

  if (smartUpdateResult.status === "rejected") {
    console.error(smartUpdateResult.reason);
    bootWarnings.push("automation");
  }

  if (homepageResult.status === "rejected") {
    console.error(homepageResult.reason);
    bootWarnings.push("homepage");
  }

  setLastUpdated();
  scheduleRefresh();

  if (bootWarnings.length) {
    showToast("Signed in. Some dashboard panels are still warming up in the background.", "info");
  }
}

async function bootstrapAuthenticatedSession({ username, role }) {
  applyAuthenticatedIdentity(role, username, { keepBackdrop: true });
  await advanceAuthLoading(78, "Session accepted. Opening your console...", {
    copy: "DarkPulse has verified your access. The dashboard will keep loading in the background.",
    delay: 120
  });
  await advanceAuthLoading(100, "Access granted. Entering DarkPulse now.", {
    copy: "You are signed in. Live cards, heatmap, and automation status are warming up.",
    delay: 180
  });

  $("loginBackdrop").classList.add("hidden");
  setChatAvailability(true);
  hideAuthLoading();
  void warmAuthenticatedWorkspace().catch(error => {
    console.error(error);
    showToast("Signed in, but some dashboard sections are still loading.", "info");
  });
}

async function checkAuth() {
  const token = getToken();
  const role = localStorage.getItem(USER_ROLE_KEY);
  if (!token) {
    setAuthStage("login");
    restoreAuthNotice();
    $("loginBackdrop").classList.remove("hidden");
    $("appWrapper").classList.add("hidden");
    setChatAvailability(false);
    return false;
  }

  applyAuthenticatedIdentity(role, localStorage.getItem(USER_NAME_KEY) || "User");
  return true;
}

function handleLogout(notice = "") {
  if (notice && typeof notice === "object") {
    notice = "";
  }
  hideAuthLoading();
  clearTimeout(state.smartUpdateTimer);
  clearTimeout(state.mapRefreshTimer);
  clearTimeout(state.mapSpotlightTimer);
  if (notice) {
    sessionStorage.setItem(AUTH_NOTICE_KEY, notice);
  } else {
    sessionStorage.removeItem(AUTH_NOTICE_KEY);
  }
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_ROLE_KEY);
  setChatAvailability(false);
  localStorage.removeItem(USER_NAME_KEY);
  $("appWrapper").classList.add("hidden");
  $("loginBackdrop").classList.remove("hidden");
  setAuthStage("login");
  restoreAuthNotice();
}

