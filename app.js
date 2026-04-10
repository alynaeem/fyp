const DEFAULT_API_BASE = window.location.origin && window.location.origin !== "null"
  ? window.location.origin
  : "http://localhost:8200";

const STORAGE_KEY = "darkpulse_api_key";
const TOKEN_KEY = "darkpulse_token";
const USER_ROLE_KEY = "darkpulse_role";
const USER_NAME_KEY = "darkpulse_name";
const API_BASE_KEY = "darkpulse_base";
const AUTH_NOTICE_KEY = "darkpulse_auth_notice";
const PAGE_SIZE = 36;
const REFRESH_MS = 2 * 60 * 1000;
const SMART_UPDATE_POLL_MS = 5 * 1000;
const MAP_LIVE_REFRESH_MS = 15 * 1000;
const MAP_SPOTLIGHT_MS = 2200;
const SEARCH_DEBOUNCE_MS = 550;
const MIN_GLOBAL_SEARCH_LENGTH = 2;
const FEED_SNAPSHOT_TTL_MS = 90 * 1000;
const TRANSLATION_LANGUAGE_KEY = "darkpulse_translation_language";
const TRANSLATION_LABEL_KEY = "darkpulse_translation_label";

const TRANSLATION_OPTIONS = [
  { code: "en", label: "English" },
  { code: "ur", label: "Urdu" },
  { code: "ar", label: "Arabic" },
  { code: "es", label: "Spanish" },
  { code: "fr", label: "French" },
  { code: "de", label: "German" },
  { code: "tr", label: "Turkish" },
  { code: "ru", label: "Russian" },
  { code: "hi", label: "Hindi" },
  { code: "pt", label: "Portuguese" },
  { code: "it", label: "Italian" },
  { code: "ja", label: "Japanese" },
  { code: "zh-CN", label: "Chinese (Simplified)" }
];

const TRANSLATABLE_SELECTORS = [
  ".view-title",
  ".view-subtitle",
  ".section-title",
  ".section-copy",
  ".feed-summary",
  ".badge-outline",
  ".grade-label",
  ".intel-notification-title",
  ".intel-notification-message",
  ".country-name",
  ".compact-title",
  ".compact-meta",
  ".card-title",
  ".card-desc",
  ".identity-pill",
  ".identity-field-label",
  ".identity-name",
  ".identity-meta-line",
  ".identity-address",
  ".mini-card-label",
  ".result-card-title",
  ".result-card-desc",
  ".result-card-field-label",
  ".result-card-field-value",
  ".result-card-note-label",
  ".result-card-note-copy",
  ".software-summary-title strong",
  ".field-label",
  ".field-value",
  ".seo-report-subtitle",
  ".suggestions-title",
  ".suggestions-note",
  ".suggestions-body li",
  ".repo-clean-title",
  ".repo-clean-copy",
  ".repo-finding-title",
  ".repo-finding-desc",
  ".modal-title",
  ".modal-section label",
  ".fact-label",
  ".modal-summary",
  ".entity-tag",
  ".summary-source-title",
  ".summary-source-empty",
  ".summary-empty",
  ".summary-highlight-title"
  ,
  ".healing-toolbar-title",
  ".healing-toolbar-note",
  ".healing-pill-label",
  ".healing-change-list li",
  ".healing-suggestion-list li",
  ".healing-empty-copy"
].join(",");

const TAB_SOURCE_MAP = {
  all: "all",
  news: "news",
  leak: "leak",
  defacement: "defacement",
  social: "social",
  exploit: "exploit",
  api: "api",
  forums: "social",
  marketplaces: "leak",
  github: "api",
  apk: "api"
};

const VIEW_META = {
  homepage: {
    title: "Command Center",
    subtitle: "Leaks and defacement activity are highlighted in red with restored MongoDB data behind the feed."
  },
  all: {
    title: "Live Feed",
    subtitle: "Every restored DarkPulse record across news, leaks, defacement, exploits, social, and API outputs."
  },
  news: {
    title: "News Feed",
    subtitle: "Security reporting and advisories with author data and raw JSON preserved."
  },
  leak: {
    title: "Leak Feed",
    subtitle: "Breach tracking, dumps, and disclosure activity with full record details."
  },
  defacement: {
    title: "Defacement Feed",
    subtitle: "Affected targets, attacker context, infrastructure hints, and raw record payloads."
  },
  exploit: {
    title: "Exploit Feed",
    subtitle: "Exploit publications, weaponization notes, and supporting metadata."
  },
  social: {
    title: "Social Monitoring",
    subtitle: "Forum and channel collection with actor, team, and linked source context."
  },
  api: {
    title: "API and Scanner Output",
    subtitle: "Collected API records and scanner artifacts from the restored database."
  },
  playstore: {
    title: "Playstore Scanner",
    subtitle: "Search for cracked/modded versions of Android apps."
  },
  software: {
    title: "PC Game Scan",
    subtitle: "Search for PC games and mods"
  },
  "repo-scan": {
    title: "Repository Scan",
    subtitle: "GitHub vulnerability analysis"
  },
  healing: {
    title: "Healing Monitor",
    subtitle: "HTML drift detection, selector health checks, and self-healing visibility across collector scripts."
  },
  pakdb: {
    title: "PakDB Lookup",
    subtitle: "Search entity and phone data live from the connected backend."
  },
  "admin-users": {
    title: "User Management",
    subtitle: "Approve, reject, and review dashboard access."
  }
};

const TOOL_VIEWS = ["admin-users", "pakdb", "seo", "playstore", "software", "repo-scan", "healing", "account"];

const SMART_UPDATE_SOURCE_LABELS = {
  news: "Security Feeds",
  leaks: "Ransomware Leaks",
  social: "Social Monitoring",
  defacement: "Defacement Tracking"
};

const state = {
  activeTab: "all",
  currentView: "homepage",
  offset: 0,
  total: 0,
  feedSnapshots: new Map(),
  feedAbortController: null,
  isRegistering: false,
  authStage: "login",
  authChallengeToken: "",
  authChallengeType: "",
  authPendingUsername: "",
  authPendingRole: "",
  authQrCodeUrl: "",
  authManualSecret: "",
  refreshTimer: null,
  smartUpdateTimer: null,
  mapRefreshTimer: null,
  mapSpotlightTimer: null,
  mapSpotlightIndex: 0,
  mapSpotlightCode: "",
  mapSpotlightCountries: [],
  mapInstance: null,
  detailCache: new Map(),
  countryStatsByCode: {},
  smartUpdatePayload: null,
  smartUpdateJobId: "",
  smartUpdateStatus: "idle",
  mediaLightboxSrc: "",
  mediaLightboxTitle: "",
  translationLanguage: localStorage.getItem(TRANSLATION_LANGUAGE_KEY) || "en",
  translationLabel: localStorage.getItem(TRANSLATION_LABEL_KEY) || "English",
  translationScope: "view",
  translationCache: new Map()
};

const scanReportTemplates = {};

const $ = id => document.getElementById(id);

function debounce(fn, wait) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), wait);
  };
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
}

function normalizePreviewText(value, fallback = "") {
  const raw = String(value ?? fallback ?? "").replace(/\r/g, "\n");
  if (!raw.trim()) return String(fallback || "").trim();
  const lines = raw
    .split("\n")
    .map(line => line.replace(/\s+/g, " ").trim())
    .filter(Boolean)
    .filter(line => {
      const compact = line.replace(/\s+/g, "");
      if (!compact) return false;
      const alphaCount = (compact.match(/[A-Za-z0-9]/g) || []).length;
      return compact.length < 12 || alphaCount / compact.length > 0.28;
    });
  return (lines.join(" ").replace(/\s+/g, " ").trim() || String(fallback || "").trim());
}

function buildFeedSnapshotKey() {
  const query = $("searchInput")?.value.trim().toLowerCase() || "";
  return `${currentSourceType()}::${query}`;
}

function getTranslationLabel(code) {
  return TRANSLATION_OPTIONS.find(option => option.code === code)?.label || code.toUpperCase();
}

function refreshLanguageIndicator() {
  const indicator = $("languageIndicator");
  const resetButton = $("resetLanguageBtn");
  if (indicator) {
    indicator.textContent = state.translationLanguage === "en"
      ? "Original intelligence text"
      : `Translated to ${state.translationLabel}`;
  }
  if (resetButton) {
    resetButton.disabled = state.translationLanguage === "en";
  }
}

function shouldTranslateText(text) {
  const value = String(text || "").replace(/\s+/g, " ").trim();
  if (!value || value.length < 2 || value.length > 1400) return false;
  if (/^(https?:\/\/|www\.)/i.test(value)) return false;
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(value)) return false;
  if (/^[\d\s:./\-]+$/.test(value)) return false;
  if (/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(value)) return false;
  if (/\b[a-f0-9]{24,}\b/i.test(value)) return false;
  if (/^(json endpoint|open source)$/i.test(value)) return false;
  const alphaChars = (value.match(/[A-Za-z\u00C0-\u024F\u0400-\u04FF\u0600-\u06FF\u0900-\u097F\u4E00-\u9FFF]/g) || []).length;
  if (!alphaChars) return false;
  if (value.length > 50 && alphaChars / value.length < 0.2) return false;
  return true;
}

function getTranslateScopeRoot(scope = "view") {
  if (scope === "detail" && !$("detailBackdrop").classList.contains("hidden")) {
    return $("detailBackdrop");
  }
  if (scope === "alert" && !$("alertSummaryBackdrop").classList.contains("hidden")) {
    return $("alertSummaryBackdrop");
  }
  return document.querySelector(".app-content");
}

function collectTranslatableNodes(scope = "view") {
  const root = getTranslateScopeRoot(scope);
  if (!root) return [];

  const roots = scope === "view"
    ? [
        document.querySelector(".content-header"),
        $("intelNotificationBar"),
        document.querySelector(".view-panel:not(.hidden)")
      ].filter(Boolean)
    : [root];

  return roots.flatMap(scopeRoot => Array.from(scopeRoot.querySelectorAll(TRANSLATABLE_SELECTORS)))
    .filter(node => node && !node.closest("[data-no-translate]"))
    .map(node => {
      if (!node.dataset.originalText) {
        node.dataset.originalText = node.textContent || "";
      }
      return {
        node,
        original: node.dataset.originalText.trim()
      };
    })
    .filter(entry => shouldTranslateText(entry.original));
}

function restoreOriginalText(scope = "view") {
  const root = getTranslateScopeRoot(scope);
  if (!root) return;
  const roots = scope === "view"
    ? [
        document.querySelector(".content-header"),
        $("intelNotificationBar"),
        document.querySelector(".view-panel:not(.hidden)")
      ].filter(Boolean)
    : [root];
  roots.flatMap(scopeRoot => Array.from(scopeRoot.querySelectorAll("[data-original-text]"))).forEach(node => {
    node.textContent = node.dataset.originalText || "";
  });
}

async function applyTranslationToScope(scope = "view", targetLanguage = state.translationLanguage) {
  if (!targetLanguage || targetLanguage === "en") {
    restoreOriginalText(scope);
    return;
  }

  const entries = collectTranslatableNodes(scope);
  if (!entries.length) return;

  const uniqueTexts = [...new Set(entries.map(entry => entry.original))];
  const uncachedTexts = uniqueTexts.filter(text => !state.translationCache.has(`${targetLanguage}::${text}`));

  if (uncachedTexts.length) {
    const data = await apiFetch("/translate/text", false, {
      method: "POST",
      body: {
        target_language: targetLanguage,
        texts: uncachedTexts
      }
    });
    (data.translations || []).forEach((translated, index) => {
      const original = uncachedTexts[index];
      state.translationCache.set(`${targetLanguage}::${original}`, translated || original);
    });
  }

  entries.forEach(entry => {
    const translated = state.translationCache.get(`${targetLanguage}::${entry.original}`);
    if (translated) {
      entry.node.textContent = translated;
    }
  });
}

async function maybeApplyActiveTranslation(scope = "view") {
  if (state.translationLanguage === "en") {
    restoreOriginalText(scope);
    return;
  }
  try {
    await applyTranslationToScope(scope, state.translationLanguage);
  } catch (error) {
    console.error(error);
    showToast(`Translation failed: ${error.message}`, "error");
  }
}

function openTranslateModal(scope = "view") {
  state.translationScope = scope;
  $("translateScopeTag").textContent = scope === "detail" ? "Translate Open Record" : "Translate Current View";
  $("translateLanguageSelect").value = state.translationLanguage || "en";
  $("translateStatus").textContent = state.translationLanguage === "en"
    ? "Choose a language for the visible intelligence content."
    : `Current language: ${state.translationLabel}`;
  $("translateBackdrop").classList.remove("hidden");
}

function closeTranslateModal() {
  $("translateBackdrop").classList.add("hidden");
}

async function applySelectedTranslation() {
  const select = $("translateLanguageSelect");
  const targetLanguage = select?.value || "en";
  const targetLabel = getTranslationLabel(targetLanguage);

  $("translateApplyBtn").disabled = true;
  $("translateStatus").innerHTML = `
    <span class="scan-status-loading">
      <span class="scan-status-pulse"></span>
      Translating visible intelligence into ${escapeHtml(targetLabel)}...
    </span>
  `;

  try {
    if (targetLanguage === "en") {
      resetTranslationToEnglish();
      return;
    }
    await applyTranslationToScope(state.translationScope, targetLanguage);
    state.translationLanguage = targetLanguage;
    state.translationLabel = targetLabel;
    localStorage.setItem(TRANSLATION_LANGUAGE_KEY, targetLanguage);
    localStorage.setItem(TRANSLATION_LABEL_KEY, targetLabel);
    refreshLanguageIndicator();
    $("translateStatus").textContent = `Translated to ${targetLabel}.`;
    closeTranslateModal();
    showToast(`Translated to ${targetLabel}`, "success");
  } catch (error) {
    console.error(error);
    $("translateStatus").textContent = `Translation failed: ${error.message}`;
  } finally {
    $("translateApplyBtn").disabled = false;
  }
}

function resetTranslationToEnglish() {
  state.translationLanguage = "en";
  state.translationLabel = "English";
  localStorage.setItem(TRANSLATION_LANGUAGE_KEY, "en");
  localStorage.setItem(TRANSLATION_LABEL_KEY, "English");
  restoreOriginalText("view");
  restoreOriginalText("detail");
  restoreOriginalText("alert");
  refreshLanguageIndicator();
  $("translateStatus").textContent = "Original English content restored.";
  closeTranslateModal();
  showToast("Restored original content", "info");
}

function cacheScanTemplates() {
  if (!scanReportTemplates.seo && $("seoReport")) {
    scanReportTemplates.seo = $("seoReport").innerHTML;
  }
  if (!scanReportTemplates.repo && $("repoScanReport")) {
    scanReportTemplates.repo = $("repoScanReport").innerHTML;
  }
}

function setActionButtonBusy(buttonId, isBusy, busyLabel, idleLabel) {
  const button = $(buttonId);
  if (!button) return;
  if (!button.dataset.defaultLabel) {
    button.dataset.defaultLabel = idleLabel || button.textContent || "Search";
  }
  button.disabled = isBusy;
  button.textContent = isBusy ? busyLabel : (idleLabel || button.dataset.defaultLabel || "Search");
}

function setScanStatusLoading(statusId, message) {
  const node = $(statusId);
  if (!node) return;
  node.innerHTML = `
    <span class="scan-status-loading">
      <span class="scan-status-pulse"></span>
      ${escapeHtml(message)}
    </span>
  `;
}

function renderLoadingSkeleton(variant = "cards", count = 3) {
  if (variant === "report") {
    return `
      <div class="scan-loading-shell">
        <div class="scan-loading-progress-copy">Queued: preparing structured scan output...</div>
        <div class="scan-loading-progress-track"><span></span></div>
        <div class="scan-loading-report-head">
          <div class="scan-line w-18"></div>
          <div class="scan-line w-42"></div>
          <div class="scan-line w-28"></div>
        </div>
        <div class="scan-loading-report-top">
          <div class="scan-loading-card scan-loading-card-wide">
            <div class="scan-line w-22"></div>
            <div class="scan-line w-65"></div>
            <div class="scan-line w-48"></div>
          </div>
          <div class="scan-loading-grade">
            <div class="scan-square"></div>
            <div class="scan-line w-16 centered"></div>
          </div>
        </div>
        <div class="scan-loading-mini-grid">
          ${Array.from({ length: 6 }).map(() => `
            <div class="scan-loading-stat">
              <div class="scan-line w-28"></div>
              <div class="scan-line w-55"></div>
            </div>
          `).join("")}
        </div>
        <div class="scan-loading-card scan-loading-card-full">
          <div class="scan-line w-18"></div>
          <div class="scan-line w-90"></div>
          <div class="scan-line w-80"></div>
          <div class="scan-line w-72"></div>
        </div>
        <div class="scan-loading-card scan-loading-card-full">
          <div class="scan-line w-20"></div>
          <div class="scan-line w-94"></div>
          <div class="scan-line w-89"></div>
          <div class="scan-line w-76"></div>
        </div>
      </div>
    `;
  }

  if (variant === "feed") {
    return Array.from({ length: count }).map(() => `
      <div class="scan-loading-card scan-loading-card-feed">
        <div class="scan-line w-18"></div>
        <div class="scan-line w-62"></div>
        <div class="scan-line w-84"></div>
        <div class="scan-line w-72"></div>
        <div class="scan-line w-46"></div>
        <div class="scan-line w-28"></div>
      </div>
    `).join("");
  }

  const cardClass = variant === "compact"
    ? "scan-loading-card scan-loading-card-compact"
    : variant === "accordion"
      ? "scan-loading-card scan-loading-card-accordion"
      : "scan-loading-card";

  return `
    <div class="scan-loading-shell scan-loading-shell-list">
      <div class="scan-loading-progress-copy">Queued: waiting for scanner availability...</div>
      <div class="scan-loading-progress-track"><span></span></div>
      <div class="scan-loading-list">
        ${Array.from({ length: count }).map(() => `
          <div class="${cardClass}">
            <div class="scan-line w-18"></div>
            <div class="scan-line w-62"></div>
            <div class="scan-line w-84"></div>
            <div class="scan-line w-46"></div>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function showListScanLoading(statusId, containerId, message, variant = "cards", count = 3) {
  setScanStatusLoading(statusId, message);
  const container = $(containerId);
  if (container) container.innerHTML = renderLoadingSkeleton(variant, count);
}

function showReportScanLoading(statusId, reportId, templateKey, message) {
  cacheScanTemplates();
  setScanStatusLoading(statusId, message);
  const container = $(reportId);
  if (!container) return;
  container.classList.remove("hidden");
  container.innerHTML = renderLoadingSkeleton("report");
}

function restoreReportTemplate(reportId, templateKey) {
  cacheScanTemplates();
  const container = $(reportId);
  if (!container) return;
  if (scanReportTemplates[templateKey]) {
    container.innerHTML = scanReportTemplates[templateKey];
  }
}

function getBase() {
  return localStorage.getItem(API_BASE_KEY) || DEFAULT_API_BASE;
}

function getToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

function currentSourceType() {
  return TAB_SOURCE_MAP[state.activeTab] || state.activeTab || "all";
}

function formatDate(value) {
  if (!value) return "Unknown";
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isNaN(numeric) && String(value).trim() !== "") {
    const millis = numeric > 1_000_000_000_000 ? numeric : numeric * 1000;
    const asDate = new Date(millis);
    if (!Number.isNaN(asDate.getTime()) && asDate.getFullYear() > 2000) {
      return asDate.toLocaleString();
    }
  }
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) return parsed.toLocaleString();
  return String(value);
}

function humanViewName(viewName) {
  const meta = VIEW_META[viewName];
  return meta ? meta.title : "DarkPulse Feed";
}

function firstNonEmpty(...values) {
  return values.find(value => String(value ?? "").trim()) || "";
}

function hostFromValue(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  try {
    return new URL(text).hostname || text;
  } catch {
    return text;
  }
}

function formatShortDate(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) return text;
  const parsed = new Date(text);
  if (!Number.isNaN(parsed.getTime())) return parsed.toLocaleDateString();
  return text;
}

function updateHeader(viewName) {
  const meta = VIEW_META[viewName] || VIEW_META.all;
  $("viewTitle").textContent = meta.title;
  $("viewSubtitle").textContent = meta.subtitle;
}

function setLastUpdated() {
  $("lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

function isSmartUpdateRunning(status) {
  return status === "queued" || status === "running" || status === "cancelling";
}

function syncSmartUpdateButton(isRunning = false) {
  const startButton = $("smartUpdateBtn");
  const stopButton = $("stopSmartUpdateBtn");
  const alertButton = $("alertSummaryBtn");
  const isCancelling = state.smartUpdateStatus === "cancelling";

  if (startButton) {
    if (!startButton.dataset.originalText) {
      startButton.dataset.originalText = startButton.textContent || "Scan Now";
    }
    startButton.classList.toggle("scanning", isRunning && !isCancelling);
    startButton.disabled = isRunning;
    startButton.textContent = isRunning
      ? (isCancelling ? "Stopping..." : "Scanning...")
      : (startButton.dataset.originalText || "Scan Now");
  }

  if (stopButton) {
    stopButton.disabled = !isRunning || isCancelling;
    stopButton.textContent = isCancelling ? "Stopping..." : "Stop Scan";
  }

  if (alertButton) {
    const hasSummary = Boolean(
      state.smartUpdatePayload &&
      (state.smartUpdatePayload.active_run || state.smartUpdatePayload.latest_run || state.smartUpdatePayload.latest_notification)
    );
    alertButton.disabled = !hasSummary;
  }
}

function formatSmartUpdateStatus(status) {
  switch (status) {
    case "running":
    case "queued":
      return "Automation Running";
    case "cancelling":
      return "Stopping Scan";
    case "completed":
      return "New Intel Synced";
    case "completed_no_new":
      return "No New Intel";
    case "completed_with_errors":
      return "Partial Source Error";
    case "cancelled":
      return "Scan Stopped";
    case "failed":
      return "Automation Failed";
    default:
      return "Automation Idle";
  }
}

function formatSourceProgressChip(item, active = false) {
  const label = item.label || SMART_UPDATE_SOURCE_LABELS[item.source] || item.source || "Source";
  const newRecords = Number(item.new_records || 0);
  const liveCount = item.current_count ?? item.after_count ?? item.before_count ?? 0;

  if (item.status === "failed") {
    return `${label} failed`;
  }
  if (item.status === "cancelled") {
    return `${label} stopped (+${newRecords})`;
  }
  if (item.status === "cancelling") {
    return `${label} stopping (+${newRecords})`;
  }
  if (active) {
    return `${label} +${newRecords} live (${liveCount})`;
  }
  return `${label} +${newRecords}`;
}

function buildAlertSummary(payload) {
  const activeRun = payload?.active_run;
  const latestRun = payload?.latest_run;
  const latestNotification = payload?.latest_notification;
  const run = activeRun || latestRun;
  const sourceResults = Array.isArray(run?.source_results)
    ? run.source_results
    : Array.isArray(latestNotification?.source_results)
      ? latestNotification.source_results
      : [];

  if (!run && sourceResults.length === 0) {
    return "No scan summary is available yet.";
  }

  const heading = activeRun && isSmartUpdateRunning(activeRun.status)
    ? "Live scan summary"
    : "Latest scan summary";
  const statusLine = `Status: ${formatSmartUpdateStatus(run?.status || latestNotification?.status || "idle")}`;
  const liveTotal = sourceResults.reduce((sum, item) => sum + Number(item.new_records || 0), 0);
  const summaryTotal = activeRun && isSmartUpdateRunning(activeRun.status)
    ? liveTotal
    : (run?.new_records_total ?? latestNotification?.new_records_total ?? liveTotal);
  const totalLine = `New records: ${summaryTotal || 0}`;

  const lines = sourceResults.map(item => {
    const label = item.label || SMART_UPDATE_SOURCE_LABELS[item.source] || item.source || "Source";
    const newRecords = Number(item.new_records || 0);
    const total = item.current_count ?? item.after_count ?? item.before_count ?? 0;
    const sourceStatus = item.status || "idle";
    return `${label}: ${newRecords} new, total ${total}, status ${sourceStatus}`;
  });

  return [heading, statusLine, totalLine, "", ...lines].join("\n");
}

function buildAlertSummaryData(payload) {
  const activeRun = payload?.active_run;
  const latestRun = payload?.latest_run;
  const latestNotification = payload?.latest_notification;
  const run = activeRun || latestRun;
  const sourceResults = Array.isArray(run?.source_results)
    ? run.source_results
    : Array.isArray(latestNotification?.source_results)
      ? latestNotification.source_results
      : [];
  const status = run?.status || latestNotification?.status || "idle";
  const totalNew = activeRun && isSmartUpdateRunning(activeRun.status)
    ? sourceResults.reduce((sum, item) => sum + Number(item.new_records || 0), 0)
    : Number(run?.new_records_total ?? latestNotification?.new_records_total ?? 0);

  return {
    heading: activeRun && isSmartUpdateRunning(activeRun.status) ? "Live Scan Summary" : "Latest Scan Summary",
    title: formatSmartUpdateStatus(status),
    status,
    triggeredBy: run?.triggered_by || latestNotification?.triggered_by || "operator",
    startedAt: run?.started_at || latestNotification?.started_at || "",
    completedAt: run?.completed_at || latestNotification?.completed_at || "",
    totalNew,
    sourceResults,
    channel: run?.delivery?.channel_label || latestNotification?.delivery?.channel_label || "Dashboard Alert",
    jobId: run?.job_id || latestNotification?.job_id || ""
  };
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
  const latestNotification = payload.latest_notification;
  const activeSourceResults = Array.isArray(activeRun?.source_results) ? activeRun.source_results : [];

  let status = "idle";
  let chips = ["MongoDB ready", "Arya Dashboard Alert"];

  if (activeRun && isSmartUpdateRunning(activeRun.status)) {
    status = activeRun.status;
    const liveNewTotal = activeSourceResults.reduce((sum, item) => sum + Number(item.new_records || 0), 0);
    label.textContent = formatSmartUpdateStatus(activeRun.status);
    title.textContent = activeRun.status === "cancelling"
      ? "One-click intelligence update is shutting down"
      : "One-click intelligence update is scanning live sources";
    message.textContent = activeRun.status === "cancelling"
      ? "Stop requested. DarkPulse is finalizing the latest counts from the active sources."
      : "Security feeds, ransomware leaks, social monitoring, and defacement trackers are syncing into MongoDB now.";
    chips = [
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
    message.textContent = "Press Scan Now to refresh MongoDB and check for new intelligence across the dashboard sources.";
    chips = [
      ...(latestRun.completed_at ? [`Last run ${formatDate(latestRun.completed_at)}`] : ["MongoDB ready"]),
      ...(Array.isArray(latestRun.source_results)
        ? latestRun.source_results.filter(item => item.new_records).slice(0, 4).map(item => formatSourceProgressChip(item, false))
        : [])
    ];
  } else {
    label.textContent = "Automation Idle";
    title.textContent = "No intelligence update is running";
    message.textContent = "Press Scan Now to refresh MongoDB and check for new intelligence across the dashboard sources.";
    chips = ["MongoDB ready", "Arya Dashboard Alert"];
  }

  state.smartUpdateStatus = status;
  if (activeRun?.job_id) {
    state.smartUpdateJobId = activeRun.job_id;
  }

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
    await initHeatmap();
    await fetchRecentIntel();
  } else if (state.currentView === "admin-users") {
    await refreshUserList();
  } else if (state.currentView === "healing") {
    await loadHealingMonitor(true);
  } else if (!TOOL_VIEWS.includes(state.currentView)) {
    await loadArticles(true);
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

    const observedRun = data.active_run || data.latest_run;
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

async function checkAuth() {
  const token = getToken();
  const role = localStorage.getItem(USER_ROLE_KEY);
  if (!token) {
    setAuthStage("login");
    restoreAuthNotice();
    $("loginBackdrop").classList.remove("hidden");
    $("appWrapper").classList.add("hidden");
    return false;
  }

  $("appWrapper").classList.remove("hidden");
  $("loginBackdrop").classList.add("hidden");
  $("currentUserName").textContent = localStorage.getItem(USER_NAME_KEY) || "User";
  $("currentUserRole").textContent = role === "admin" ? "Administrator" : "Researcher";
  $("sidebarNavItemUsers").style.display = role === "admin" ? "flex" : "none";
  return true;
}

function handleLogout(notice = "") {
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
  localStorage.removeItem(USER_NAME_KEY);
  window.location.reload();
}

function setAuthStage(stage) {
  state.authStage = stage;
  state.isRegistering = stage === "register";
  $("loginForm").classList.toggle("hidden", stage !== "login");
  $("registerForm").classList.toggle("hidden", stage !== "register");
  $("mfaForm").classList.toggle("hidden", stage !== "mfa");
  $("authSubmitBtn").classList.toggle("hidden", false);
  $("authSubmitBtn").textContent = stage === "register" ? "Request Access" : stage === "mfa" ? "Verify OTP" : "Sign In";
}

function clearAuthChallenge() {
  state.authChallengeToken = "";
  state.authChallengeType = "";
  state.authPendingUsername = "";
  state.authPendingRole = "";
  state.authQrCodeUrl = "";
  state.authManualSecret = "";
  $("mfaOtpInput").value = "";
  $("mfaQrImage").src = "";
  $("mfaManualSecret").textContent = "-";
  $("mfaQrSection").classList.add("hidden");
}

function toggleAuthMode() {
  clearErrors();
  clearAuthChallenge();
  setAuthStage(state.isRegistering ? "login" : "register");
}

function restoreAuthNotice() {
  const notice = sessionStorage.getItem(AUTH_NOTICE_KEY);
  if (!notice) return;
  sessionStorage.removeItem(AUTH_NOTICE_KEY);
  $("loginInfo").textContent = notice;
  $("loginInfo").classList.remove("hidden");
}

function prepareTwoFactorStage(payload, username) {
  clearErrors();
  clearAuthChallenge();
  state.authChallengeToken = payload.challenge_token || "";
  state.authChallengeType = payload.challenge_type || (payload.setup_required ? "setup" : "otp");
  state.authPendingUsername = username || payload.username || "";
  state.authPendingRole = payload.role || "";
  state.authQrCodeUrl = payload.qr_code_url || "";
  state.authManualSecret = payload.manual_secret || "";

  $("mfaTitle").textContent = payload.setup_required ? "Set up your authenticator" : "Enter your verification code";
  $("mfaCopy").textContent = payload.setup_required
    ? "Scan this QR code once in Google Authenticator, Authy, or another app, then enter the 6-digit code to finish signing in."
    : "2FA is enabled for this account. Enter the current 6-digit code from your authenticator app to continue.";
  $("mfaSecretHint").textContent = payload.setup_required
    ? "If the QR code does not load, type this key manually into your authenticator app."
    : "This setup has already been completed before, so only the OTP is required now.";
  $("mfaManualSecret").textContent = state.authManualSecret || "-";
  $("mfaQrSection").classList.toggle("hidden", !payload.setup_required);
  $("mfaQrImage").src = state.authQrCodeUrl || "";
  $("mfaOtpInput").value = "";
  setAuthStage("mfa");
}

function showError(id, message) {
  const element = $(id);
  element.textContent = message;
  element.classList.remove("hidden");
}

function clearErrors() {
  ["loginError", "registerError", "mfaError"].forEach(id => {
    $(id).textContent = "";
    $(id).classList.add("hidden");
  });
  $("loginInfo").textContent = "";
  $("loginInfo").classList.add("hidden");
}

async function handleAuthSubmit() {
  clearErrors();
  const button = $("authSubmitBtn");
  const originalLabel = button.textContent;
  button.disabled = true;

  try {
    if (state.authStage === "register") {
      await apiFetch("/auth/register", true, {
        method: "POST",
        body: {
          username: $("regUsername").value.trim(),
          password: $("regPassword").value,
          email: $("regEmail").value.trim(),
          name: $("regName").value.trim()
        }
      });
      $("registerForm").innerHTML = "<div class='test-result'>Registration submitted. Wait for admin approval before signing in.</div>";
      button.classList.add("hidden");
      return;
    }

    if (state.authStage === "mfa") {
      const data = await apiFetch("/auth/login/verify-otp", true, {
        method: "POST",
        body: {
          challenge_token: state.authChallengeToken,
          otp: $("mfaOtpInput").value.trim()
        }
      });

      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_ROLE_KEY, data.role);
      localStorage.setItem(USER_NAME_KEY, state.authPendingUsername || $("loginUsername").value.trim());
      sessionStorage.removeItem(AUTH_NOTICE_KEY);
      window.location.reload();
      return;
    }

    const username = $("loginUsername").value.trim();
    const data = await apiFetch("/auth/login", true, {
      method: "POST",
      body: {
        username,
        password: $("loginPassword").value
      }
    });

    if (data.mfa_required) {
      prepareTwoFactorStage(data, username);
      return;
    }

    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USER_ROLE_KEY, data.role);
    localStorage.setItem(USER_NAME_KEY, username);
    sessionStorage.removeItem(AUTH_NOTICE_KEY);
    window.location.reload();
  } catch (error) {
    showError(state.authStage === "register" ? "registerError" : state.authStage === "mfa" ? "mfaError" : "loginError", error.message);
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
    if (state.authStage === "login") {
      button.textContent = "Sign In";
    } else if (state.authStage === "register") {
      button.textContent = "Request Access";
    } else if (state.authStage === "mfa") {
      button.textContent = "Verify OTP";
    }
  }
}

function setActiveNavigation(target) {
  document.querySelectorAll(".nav-item").forEach(item => {
    const itemTarget = item.dataset.view || item.dataset.tab;
    item.classList.toggle("active", itemTarget === target);
  });
}

function buildFeedPath(limit = PAGE_SIZE, offset = state.offset, includeRaw = false) {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset)
  });

  const sourceType = currentSourceType();
  if (sourceType && sourceType !== "all") params.set("source_type", sourceType);

  const query = $("searchInput").value.trim();
  if (query) params.set("q", query);
  if (includeRaw) params.set("include_raw", "true");

  return `/feed?${params.toString()}`;
}

function normalizeEntities(entities) {
  if (Array.isArray(entities)) return entities;
  if (!entities || typeof entities !== "object") return [];
  return Object.entries(entities).flatMap(([label, value]) => {
    if (Array.isArray(value)) return value.map(text => ({ label, text: String(text) }));
    return [{ label, text: String(value) }];
  });
}

function renderCountryImpactList(countries) {
  const list = $("countryImpactList");
  list.innerHTML = "";
  if (!countries || countries.length === 0) {
    list.innerHTML = "<div class='compact-item'><div class='compact-title'>No mapped countries found yet.</div></div>";
    return;
  }

  countries.forEach(country => {
    const row = document.createElement("div");
    row.className = "country-row";
    row.style.cursor = "pointer";
    row.addEventListener("click", () => {
      $("searchInput").value = country.name;
      switchView("all");
    });
    row.innerHTML = `
      <div class="country-topline">
        <span class="country-name">${escapeHtml(country.name)}</span>
        <span class="country-total">${country.total}</span>
      </div>
      <div class="country-breakdown">
        <span class="count-chip">Leak <strong>${country.leak_count}</strong></span>
        <span class="count-chip">Defacement <strong>${country.defacement_count}</strong></span>
      </div>
    `;
    list.appendChild(row);
  });
}

function buildCountryTooltip(stats) {
  if (!stats) {
    return "<div class='map-tooltip-card'><div class='map-tooltip-title'>No mapped activity</div></div>";
  }

  return `
    <div class="map-tooltip-card">
      <div class="map-tooltip-title">${escapeHtml(stats.name || "Unknown Country")}</div>
      <div class="map-tooltip-inline">Leaks: ${escapeHtml(String(stats.leak_count || 0))}</div>
    </div>
  `;
}

function updateMapFocusCard(country) {
  $("mapFocusCountry").textContent = country?.name || "No affected country";
  $("mapFocusLeaks").textContent = String(country?.leak_count || 0);
}

function hideMapSpotlightTag() {
  const tag = $("mapSpotlightTag");
  if (!tag) return;
  tag.classList.add("hidden");
}

function updateMapSpotlightTag(code, country) {
  const tag = $("mapSpotlightTag");
  const shell = document.querySelector(".map-shell");
  const map = $("worldMap");
  const region = getMapRegionElement(code);

  if (!tag || !shell || !map || !region || !country) {
    hideMapSpotlightTag();
    return;
  }

  tag.innerHTML = `
    <div class="map-spotlight-tag-title">${escapeHtml(country.name || "Unknown Country")}</div>
    <div class="map-spotlight-tag-meta">Leaks: ${escapeHtml(String(country.leak_count || 0))}</div>
  `;
  tag.classList.remove("hidden");

  const shellRect = shell.getBoundingClientRect();
  const regionRect = region.getBoundingClientRect();
  const tagRect = tag.getBoundingClientRect();

  if (!regionRect.width && !regionRect.height) {
    hideMapSpotlightTag();
    return;
  }

  const centerX = (regionRect.left - shellRect.left) + (regionRect.width / 2);
  const topY = regionRect.top - shellRect.top;
  const bottomY = regionRect.bottom - shellRect.top;

  const minLeft = 18 + (tagRect.width / 2);
  const maxLeft = shellRect.width - 18 - (tagRect.width / 2);
  const clampedLeft = Math.min(Math.max(centerX, minLeft), maxLeft);

  let top = topY - 10;
  let transform = "translate(-50%, -100%)";

  if (top - tagRect.height < 8) {
    top = bottomY + 10;
    transform = "translate(-50%, 0)";
  }

  tag.style.left = `${clampedLeft}px`;
  tag.style.top = `${top}px`;
  tag.style.transform = transform;
}

function getMapRegionElement(code) {
  if (!code) return null;
  return (
    state.mapInstance?.regions?.[code]?.element
    || state.mapInstance?.regions?.[code]?.shape
    || document.querySelector(`#worldMap [data-code="${code}"]`)
    || document.querySelector(`#worldMap .jvm-region[data-code="${code}"]`)
    || null
  );
}

function syncAffectedRegions(countries) {
  (countries || []).forEach(country => {
    const element = getMapRegionElement(country.code);
    if (element) element.classList.add("map-region-affected");
  });
}

function setMapSpotlight(code) {
  if (!code) return;
  const country = state.countryStatsByCode[code];
  if (!country) return;

  if (state.mapSpotlightCode && state.mapSpotlightCode !== code) {
    const previous = getMapRegionElement(state.mapSpotlightCode);
    if (previous) previous.classList.remove("map-region-spotlight");
  }

  const next = getMapRegionElement(code);
  if (next) {
    next.classList.add("map-region-affected", "map-region-spotlight");
  }

  state.mapSpotlightCode = code;
  updateMapFocusCard(country);
  updateMapSpotlightTag(code, country);
}

function scheduleMapSpotlight() {
  clearTimeout(state.mapSpotlightTimer);
  if (!getToken() || state.currentView !== "homepage") return;

  const countries = state.mapSpotlightCountries || [];
  if (!countries.length) {
    updateMapFocusCard(null);
    hideMapSpotlightTag();
    return;
  }

  state.mapSpotlightTimer = setTimeout(() => {
    const nextCountry = countries[state.mapSpotlightIndex % countries.length];
    state.mapSpotlightIndex = (state.mapSpotlightIndex + 1) % countries.length;
    if (nextCountry) {
      setMapSpotlight(nextCountry.code);
    }
    scheduleMapSpotlight();
  }, MAP_SPOTLIGHT_MS);
}

function scheduleLiveMapRefresh() {
  clearTimeout(state.mapRefreshTimer);
  if (!getToken() || state.currentView !== "homepage") return;

  state.mapRefreshTimer = setTimeout(async () => {
    try {
      if (state.currentView === "homepage") {
        await initHeatmap();
      }
    } catch (error) {
      console.error(error);
    } finally {
      scheduleLiveMapRefresh();
    }
  }, MAP_LIVE_REFRESH_MS);
}

async function initHeatmap() {
  const payload = await apiFetch("/stats/map");
  const countries = payload.countries || [];
  const spotlightCountries = countries
    .filter(country => Number(country.leak_count || 0) > 0)
    .sort((left, right) => {
      const leakDelta = Number(right.leak_count || 0) - Number(left.leak_count || 0);
      if (leakDelta !== 0) return leakDelta;
      const totalDelta = Number(right.total || 0) - Number(left.total || 0);
      if (totalDelta !== 0) return totalDelta;
      return String(left.name || "").localeCompare(String(right.name || ""));
    });
  const fallbackCountries = countries
    .slice()
    .sort((left, right) => Number(right.total || 0) - Number(left.total || 0));
  const rotatingCountries = spotlightCountries.length ? spotlightCountries : fallbackCountries;
  const intensityEntries = countries.map(country => {
    const leakCount = Number(country.leak_count || 0);
    const defacementCount = Number(country.defacement_count || 0);
    const totalCount = Number(country.total || 0);
    const intensity = leakCount > 0
      ? leakCount + (defacementCount * 0.35)
      : Math.max(totalCount, defacementCount * 0.9);
    return [country.code, intensity];
  });
  const highestImpact = intensityEntries.length
    ? Math.max(...intensityEntries.map(([, value]) => Number(value || 0)))
    : 0;

  $("impactCountriesCount").textContent = String(payload.summary?.affected_countries || countries.length || 0);
  $("impactLeakCoverage").textContent = String(payload.summary?.leak_items_with_country || 0);
  $("impactDefaceCoverage").textContent = String(payload.summary?.defacement_items_with_country || 0);

  renderCountryImpactList(countries);
  state.countryStatsByCode = Object.fromEntries(countries.map(country => [country.code, country]));
  state.mapSpotlightCountries = rotatingCountries;
  state.mapSpotlightCode = "";
  if (state.mapSpotlightIndex >= state.mapSpotlightCountries.length) {
    state.mapSpotlightIndex = 0;
  }
  updateMapFocusCard(state.mapSpotlightCountries[0] || countries[0] || null);

  const mapValues = Object.fromEntries(
    intensityEntries.map(([code, intensity]) => {
      const numericIntensity = Number(intensity || 0);
      if (!numericIntensity) return [code, 0];
      return [code, highestImpact > 0 ? Math.max(numericIntensity, Math.ceil(highestImpact * 0.32)) : numericIntensity];
    })
  );
  const container = $("worldMap");
  container.innerHTML = "";

  if (state.mapInstance && typeof state.mapInstance.destroy === "function") {
    state.mapInstance.destroy();
  }

  state.mapInstance = new jsVectorMap({
    selector: "#worldMap",
    map: "world",
    backgroundColor: "transparent",
    regionStyle: {
      initial: {
        fill: "#121a28",
        stroke: "#242f44",
        strokeWidth: 0.5
      },
      hover: {
        fill: "#ff7390",
        cursor: "pointer"
      }
    },
    series: {
      regions: [{
        values: mapValues,
        scale: ["#92253a", "#e43d61", "#ff5f82"],
        normalizeFunction: "polynomial"
      }]
    },
    onRegionTooltipShow(event, tooltip, code) {
      const stats = state.countryStatsByCode[code];
      if (!stats) {
        tooltip.html(buildCountryTooltip({
          name: tooltip.text(),
          leak_count: 0,
          defacement_count: 0,
          total: 0,
          examples: []
        }));
        return;
      }
      setMapSpotlight(code);
      tooltip.html(buildCountryTooltip(stats));
    },
    onRegionClick(event, code) {
      const stats = state.countryStatsByCode[code];
      if (!stats) return;
      $("searchInput").value = stats.name;
      switchView("all");
    }
  });

  window.setTimeout(() => {
    syncAffectedRegions(countries);
    if (state.mapSpotlightCountries.length) {
      setMapSpotlight(state.mapSpotlightCountries[state.mapSpotlightIndex % state.mapSpotlightCountries.length].code);
    } else if (countries.length) {
      setMapSpotlight(countries[0].code);
    } else {
      updateMapFocusCard(null);
      hideMapSpotlightTag();
    }
    scheduleMapSpotlight();
  }, 120);
  scheduleLiveMapRefresh();
}

function createCompactItem(item) {
  const element = document.createElement("div");
  element.className = "compact-item";
  element.addEventListener("click", () => showDetail(item.aid));
  const compactSource = firstNonEmpty(item.source_label, hostFromValue(item.source_site || item.seed_url || item.source), item.source, "Unknown source");
  const compactTitle = normalizePreviewText(item.title || "Untitled", "Untitled");
  element.innerHTML = `
    <div class="compact-item-header">
      <span class="compact-badge">${escapeHtml(item.source_type || "intel")}</span>
      <span class="compact-meta">${escapeHtml(formatDate(item.scraped_at || item.date))}</span>
    </div>
    <div class="compact-title">${escapeHtml(compactTitle)}</div>
    <div class="compact-item-footer">
      <span class="compact-meta">${escapeHtml(compactSource)}</span>
      <span class="compact-meta">${escapeHtml((item.country_names || []).join(", ") || item.ip_addresses || "")}</span>
    </div>
  `;
  return element;
}

async function fetchRecentIntel() {
  const data = await apiFetch("/feed?limit=8&offset=0");
  const items = data.items || [];
  const list = $("recentIntelList");
  list.innerHTML = "";

  items.forEach(item => {
    state.detailCache.set(item.aid, item);
    list.appendChild(createCompactItem(item));
  });
}

function buildCardChip(label, value) {
  if (!value) return "";
  return `<span class="card-chip">${escapeHtml(label)} <strong>${escapeHtml(value)}</strong></span>`;
}

function renderCard(item) {
  const card = document.createElement("article");
  card.className = "intel-card";
  card.dataset.aid = item.aid || "";
  card.addEventListener("click", event => {
    if (event.target.closest("[data-card-action]")) return;
    showDetail(item.aid);
  });

  const countryText = (item.country_names || []).join(", ");
  const websiteHost = hostFromValue(item.website_host || item.website);
  const sourceSite = hostFromValue(item.source_site || item.seed_url || item.source);
  const sourceLabel = firstNonEmpty(item.source_label, sourceSite, item.source, item.source_type, "active");
  const metaChips = [
    buildCardChip("Source", sourceLabel),
    buildCardChip("Author", item.author),
    buildCardChip("Website", websiteHost),
    buildCardChip("Country", countryText),
    buildCardChip("Attack", formatShortDate(item.attack_date)),
    buildCardChip("Discovered", formatShortDate(item.discovered_at)),
    buildCardChip("IPs", item.ip_addresses),
    buildCardChip("Attacker", item.attacker),
    buildCardChip("Team", item.team),
    buildCardChip("Server", item.web_server)
  ].filter(Boolean).join("");

  const categories = Array.isArray(item.categories)
    ? item.categories.slice(0, 3).map(category => escapeHtml(category.label || "intel")).join(", ")
    : "";
  const statusLabel = sourceLabel;
  const footerSource = firstNonEmpty(sourceLabel, sourceSite, websiteHost, item.source_type, "Unknown source");
  const title = normalizePreviewText(item.title || "Untitled", "Untitled");
  const description = normalizePreviewText(firstNonEmpty(item.description, item.summary, "No description available."), "No description available.");
  const collectedAt = formatDate(item.scraped_at || item.date);

  card.innerHTML = `
    <div class="card-orbit" aria-hidden="true"></div>
    <div class="card-header">
      <span class="card-source">${escapeHtml(item.source_type || "intel")}</span>
      <span class="card-status">${escapeHtml(statusLabel)}</span>
    </div>
    <h3 class="card-title">${escapeHtml(title)}</h3>
    <p class="card-desc">${escapeHtml(description)}</p>
    <div class="card-chip-row">${metaChips || "<span class='card-chip'>Details <strong>Open full record</strong></span>"}</div>
    <div class="card-actions">
      <button class="card-action-btn" type="button" data-card-action="detail">Inspect</button>
      <button class="card-action-btn ghost" type="button" data-card-action="translate">Translate</button>
      ${categories ? `<span class="card-category-inline">${categories}</span>` : ""}
    </div>
    <div class="card-footer">
      <span>${escapeHtml(footerSource)}</span>
      <span>${escapeHtml(collectedAt)}</span>
    </div>
  `;
  return card;
}

function setFeedState(title, message = "", mode = "idle") {
  const emptyState = $("emptyState");
  const titleEl = emptyState.querySelector(".empty-state-title");
  const bodyEl = emptyState.querySelector("p");
  titleEl.textContent = title;
  bodyEl.textContent = message;
  emptyState.dataset.mode = mode;
}

async function loadArticles(reset = false) {
  if (state.feedAbortController) {
    state.feedAbortController.abort();
  }
  const controller = new AbortController();
  state.feedAbortController = controller;

  if (reset) {
    state.offset = 0;
    state.total = 0;
  }

  $("feedSummary").textContent = `Loading ${humanViewName(state.activeTab)}...`;
  $("loadMoreWrap").classList.add("hidden");
  if (reset) {
    const snapshot = state.feedSnapshots.get(buildFeedSnapshotKey());
    const hasFreshSnapshot = snapshot && (Date.now() - snapshot.cachedAt) < FEED_SNAPSHOT_TTL_MS && Array.isArray(snapshot.items) && snapshot.items.length;
    if (hasFreshSnapshot) {
      $("cardsGrid").innerHTML = "";
      snapshot.items.forEach(item => {
        state.detailCache.set(item.aid, item);
        $("cardsGrid").appendChild(renderCard(item));
      });
      $("feedSummary").textContent = `Showing cached ${humanViewName(state.activeTab)} while refreshing live data...`;
      $("emptyState").classList.add("hidden");
      maybeApplyActiveTranslation("view");
    } else {
      $("cardsGrid").innerHTML = renderLoadingSkeleton("feed", 6);
      setFeedState("Loading records", "DarkPulse is fetching the latest results for this stream.", "loading");
      $("emptyState").classList.add("hidden");
    }
  }

  try {
    const data = await apiFetch(buildFeedPath(PAGE_SIZE, state.offset), false, { signal: controller.signal });
    if (state.feedAbortController !== controller) return;

    const items = data.items || [];
    const grid = $("cardsGrid");

    if (reset && items.length === 0) {
      grid.innerHTML = "";
      setFeedState("No matching records", "Try a different search term or switch to another intelligence stream.", "empty");
      $("emptyState").classList.remove("hidden");
      $("loadMoreWrap").classList.add("hidden");
      $("feedSummary").textContent = "0 results loaded";
      return;
    }

    $("emptyState").classList.add("hidden");
    if (reset) {
      grid.innerHTML = "";
    }
    items.forEach(item => {
      state.detailCache.set(item.aid, item);
      grid.appendChild(renderCard(item));
    });

    state.offset += items.length;
    state.total = data.total || state.offset;
    if (reset) {
      state.feedSnapshots.set(buildFeedSnapshotKey(), {
        cachedAt: Date.now(),
        items: items.slice(),
        total: state.total
      });
    }
    $("feedSummary").textContent = `${Math.min(state.offset, state.total)} of ${state.total} records loaded for ${humanViewName(state.activeTab)}`;
    $("loadMoreWrap").classList.toggle("hidden", state.offset >= state.total);
    setLastUpdated();
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    if (error.name === "AbortError") return;
    console.error(error);
    $("cardsGrid").innerHTML = "";
    setFeedState("Feed unavailable", error.message || "The feed request failed. Please try again.", "error");
    $("emptyState").classList.remove("hidden");
    $("loadMoreWrap").classList.add("hidden");
    $("feedSummary").textContent = "Feed request failed";
  } finally {
    if (state.feedAbortController === controller) {
      state.feedAbortController = null;
    }
  }
}

async function fetchStats() {
  const data = await apiFetch("/stats");
  const counts = data.counts || data;

  $("statTotalCount").textContent = String(counts.total || 0);
  $("statNewsCount").textContent = String(counts.news || 0);
  $("statLeakCount").textContent = String(counts.leak || 0);
  $("statDefaceCount").textContent = String(counts.defacement || 0);
  $("statExploitCount").textContent = String(counts.exploit || 0);
  $("statSocialCount").textContent = String(counts.social || 0);
  $("statVulnCount").textContent = String(counts.api || 0);
}

function normalizeStringList(value) {
  if (Array.isArray(value)) {
    return value.flatMap(entry => normalizeStringList(entry));
  }
  if (value === null || value === undefined || value === "") {
    return [];
  }
  return [String(value)];
}

function dedupeText(values) {
  const seen = new Set();
  return values.filter(value => {
    const text = String(value || "").trim();
    if (!text || seen.has(text)) return false;
    seen.add(text);
    return true;
  });
}

function looksLikeBase64Image(value) {
  const compact = String(value || "").replace(/\s+/g, "");
  return compact.length > 120 && /^[A-Za-z0-9+/=]+$/.test(compact);
}

function toMediaSource(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (text.startsWith("data:image/")) return text;
  if (text.startsWith("http://") || text.startsWith("https://")) return text;
  if (looksLikeBase64Image(text)) {
    return `data:image/jpeg;base64,${text.replace(/\s+/g, "")}`;
  }
  return "";
}

function collectDetailMedia(item) {
  const raw = item && typeof item.raw === "object" ? item.raw : {};
  const refs = [
    ...normalizeStringList(item.screenshot),
    ...normalizeStringList(item.screenshot_links),
    ...normalizeStringList(item.hero_image),
    ...normalizeStringList(item.og_image),
    ...normalizeStringList(item.original_screenshot_url),
    ...normalizeStringList(raw.m_screenshot),
    ...normalizeStringList(raw.screenshot),
    ...normalizeStringList(raw.m_screenshot_links),
    ...normalizeStringList(raw.screenshot_links),
    ...normalizeStringList(raw.hero_image),
    ...normalizeStringList(raw.og_image),
    ...normalizeStringList(raw.original_screenshot_url),
    ...normalizeStringList(raw.extra && raw.extra.original_screenshot_url),
    ...normalizeStringList(raw.extra && raw.extra.hero_image),
    ...normalizeStringList(raw.extra && raw.extra.og_image),
    ...normalizeStringList(raw.m_extra && raw.m_extra.original_screenshot_url),
    ...normalizeStringList(raw.m_extra && raw.m_extra.hero_image),
    ...normalizeStringList(raw.m_extra && raw.m_extra.og_image)
  ];
  return dedupeText(refs.map(toMediaSource).filter(Boolean));
}

function collectEvidenceLinks(item) {
  const raw = item && typeof item.raw === "object" ? item.raw : {};
  const refs = [
    ...normalizeStringList(item.evidence_links),
    ...normalizeStringList(item.mirror_links),
    ...normalizeStringList(item.url),
    ...normalizeStringList(item.seed_url),
    ...normalizeStringList(item.website),
    ...normalizeStringList(raw.m_source_url),
    ...normalizeStringList(raw.source_url),
    ...normalizeStringList(raw.m_mirror_links),
    ...normalizeStringList(raw.m_weblink),
    ...normalizeStringList(raw.weblink),
    ...normalizeStringList(raw.website),
    ...normalizeStringList(raw.m_external_scanners),
    ...normalizeStringList(raw.external_scanners),
    ...normalizeStringList(raw.m_social_media_profiles),
    ...normalizeStringList(raw.social_media_profiles),
    ...normalizeStringList(raw.extra && raw.extra.website),
    ...normalizeStringList(raw.m_extra && raw.m_extra.website)
  ];
  return dedupeText(refs).filter(link => /^https?:\/\//i.test(link));
}

function renderFacts(item) {
  const sourceLabel = firstNonEmpty(item.source_label, item.source, "Unknown");
  const sourceSite = hostFromValue(item.source_site || item.seed_url || item.source);
  const website = firstNonEmpty(hostFromValue(item.website_host || item.website), item.website, "Unavailable");
  const country = (item.country_names || []).join(", ") || "Unmapped";
  const discovered = formatShortDate(item.discovered_at) || "Unavailable";
  const attackDate = formatShortDate(item.attack_date) || "Unavailable";
  const collectedAt = item.collected_at ? formatDate(item.collected_at) : "Unavailable";
  const facts = [
    ["Author", item.author || "Unavailable"],
    ["Source", sourceLabel],
    ["Source Site", sourceSite || "Unavailable"],
    ["Country", country],
    ["Network", item.network || "Unknown"],
    ["IPs", item.ip_addresses || "None"],
    ["Attacker", item.attacker || "Unknown"],
    ["Team / User", item.team || "Unknown"],
    ["Website", website],
    ["Industry", item.industry || "Unavailable"],
    ["Web Server", item.web_server || "Unknown"],
    ["Discovered", discovered],
    ["Attack Date", attackDate],
    ["Published", formatDate(item.date || item.scraped_at)],
    ["Collected", collectedAt],
    ["Seed URL", item.seed_url || "Unavailable"]
  ];

  $("modalFactGrid").innerHTML = facts.map(([label, value]) => `
    <div class="fact-item">
      <span class="fact-label">${escapeHtml(label)}</span>
      <span class="fact-value">${escapeHtml(value)}</span>
    </div>
  `).join("");
}

function renderDetail(item) {
  $("modalSource").textContent = (item.source_type || "intel").toUpperCase();
  $("modalTopTag").textContent = item.source_label || item.top_tag || (item.country_names || []).join(", ") || "Live Record";
  $("modalTitle").textContent = normalizePreviewText(item.title || "Untitled", "Untitled");
  $("modalMeta").innerHTML = `
    <span>AID: ${escapeHtml(item.aid || "")}</span>
    <span>Date: ${escapeHtml(formatDate(item.scraped_at || item.date))}</span>
    <span>Source URL: ${escapeHtml(item.url || item.website || item.seed_url || "Unavailable")}</span>
  `;

  renderFacts(item);
  $("modalSummary").textContent = normalizePreviewText(item.description || item.summary || "No description available.", "No description available.");

  const media = collectDetailMedia(item);
  $("modalMediaSection").classList.toggle("hidden", media.length === 0);
  $("modalMediaGallery").innerHTML = media.map((src, index) => `
    <button type="button" class="modal-media-card" data-media-src="${escapeHtml(src)}" data-media-title="${escapeHtml(item.title || "Evidence image")}">
      <img src="${escapeHtml(src)}" alt="${escapeHtml((item.title || "intel-record") + ` screenshot ${index + 1}`)}" loading="lazy" />
      <span class="modal-media-hint">Open inside DarkPulse</span>
    </button>
  `).join("");

  const evidenceLinks = collectEvidenceLinks(item);
  $("modalEvidenceSection").classList.toggle("hidden", evidenceLinks.length === 0);
  $("modalEvidenceLinks").innerHTML = evidenceLinks.map(link => `
    <a class="modal-evidence-link" href="${escapeHtml(link)}" target="_blank" rel="noopener noreferrer">${escapeHtml(link)}</a>
  `).join("");

  const entities = normalizeEntities(item.entities);
  $("modalEntitiesSection").classList.toggle("hidden", entities.length === 0);
  $("modalEntities").innerHTML = entities.map(entity => `
    <span class="entity-tag">${escapeHtml(entity.label || "entity")}: ${escapeHtml(entity.text || "")}</span>
  `).join("");

  const categories = Array.isArray(item.categories) ? item.categories : [];
  $("modalCategories").innerHTML = categories.map(category => {
    const score = typeof category.score === "number" ? ` (${Math.round(category.score * 100)}%)` : "";
    return `<span class="entity-tag">${escapeHtml(category.label || "intel")}${escapeHtml(score)}</span>`;
  }).join("");

  $("modalRawJson").textContent = JSON.stringify(item.raw || item, null, 2);

  const readButton = $("modalReadBtn");
  const readTarget = item.url || item.website || item.seed_url || "";
  readButton.href = readTarget || "#";
  readButton.style.pointerEvents = readTarget ? "auto" : "none";
  readButton.style.opacity = readTarget ? "1" : "0.55";

  $("modalJsonLink").href = `${getBase()}/feed/${encodeURIComponent(item.aid)}`;
  $("detailBackdrop").classList.remove("hidden");
  setTimeout(() => {
    maybeApplyActiveTranslation("detail");
  }, 0);
}

function openMediaLightbox(src, title = "Evidence image") {
  state.mediaLightboxSrc = src;
  state.mediaLightboxTitle = title;
  $("mediaLightboxImage").src = src;
  $("mediaLightboxImage").alt = title;
  $("mediaLightboxTitle").textContent = title;
  $("mediaLightboxOpen").href = src;
  $("mediaLightboxBackdrop").classList.remove("hidden");
}

async function showDetail(aid) {
  try {
    let item = state.detailCache.get(aid);
    if (!item || !item.raw) {
      item = await apiFetch(`/feed/${encodeURIComponent(aid)}`);
    }
    state.detailCache.set(aid, item);
    renderDetail(item);
  } catch (error) {
    showToast(`Failed to load detail: ${error.message}`, "error");
  }
}

function closeDetailModal() {
  $("detailBackdrop").classList.add("hidden");
}

function closeMediaLightbox() {
  state.mediaLightboxSrc = "";
  state.mediaLightboxTitle = "";
  $("mediaLightboxBackdrop").classList.add("hidden");
  $("mediaLightboxImage").src = "";
  $("mediaLightboxOpen").href = "#";
}

function closeAlertSummaryModal() {
  $("alertSummaryBackdrop").classList.add("hidden");
}

function renderPakdbResultCard(item) {
  return `
    <article class="identity-card">
      <div class="identity-header">
        <div>
          <h3 class="identity-name">${escapeHtml(normalizePreviewText(item.name || "Unknown Record", "Unknown Record"))}</h3>
          <p class="identity-address">${escapeHtml(normalizePreviewText(item.address || "Address unavailable", "Address unavailable"))}</p>
        </div>
        <span class="identity-pill">National Identity</span>
      </div>
      <div class="identity-grid">
        <div class="identity-field">
          <span class="identity-field-label">CNIC</span>
          <span class="identity-field-value">${escapeHtml(item.cnic || "-")}</span>
        </div>
        <div class="identity-field">
          <span class="identity-field-label">Mobile</span>
          <span class="identity-field-value">${escapeHtml(item.mobile || "-")}</span>
        </div>
      </div>
      <div class="identity-meta-line">Matched from the connected national identity lookup backend.</div>
    </article>
  `;
}

function formatHealingStatus(status) {
  const normalized = String(status || "unknown").toLowerCase();
  switch (normalized) {
    case "healthy":
      return "Healthy";
    case "changed":
      return "Changed";
    case "auto_fixed":
      return "Repair Ready";
    case "needs_review":
      return "Needs Review";
    case "unreachable":
      return "Unreachable";
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

function renderHealingSuggestions(suggestions = []) {
  if (!Array.isArray(suggestions) || !suggestions.length) {
    return `<div class="healing-empty-copy">No selector repair suggestions were needed in the latest check.</div>`;
  }
  return `
    <ul class="healing-suggestion-list">
      ${suggestions.slice(0, 2).map(item => `
        <li>
          <strong>${escapeHtml(item.old_selector || "selector")}</strong>
          <span> -> ${escapeHtml(item.suggested_selector || "manual review")}</span>
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
      ${changes.slice(0, 3).map(change => `<li>${escapeHtml(change)}</li>`).join("")}
    </ul>
  `;
}

function renderHealingTargetCard(item) {
  return `
    <article class="result-card healing-target-card">
      <div class="result-card-header">
        <div class="result-card-headline">
          <span class="result-card-eyebrow">${escapeHtml(item.collector_type || "collector")}</span>
          <h3 class="result-card-title">${escapeHtml(item.script_name || item.target_key || "Unnamed target")}</h3>
        </div>
        <div class="healing-header-stack">
          ${renderHealingPill(item.status)}
          <button class="healing-inline-btn" data-healing-run="${escapeHtml(item.target_key || "")}">Run Check</button>
        </div>
      </div>
      <p class="result-card-desc">${escapeHtml(item.target_url || "No target URL")}</p>
      <div class="result-card-grid">
        <div class="result-card-field">
          <span class="result-card-field-label">Domain</span>
          <span class="result-card-field-value">${escapeHtml(item.target_domain || hostFromValue(item.target_url) || "-")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Fetcher</span>
          <span class="result-card-field-value">${escapeHtml(item.fetch_strategy || "requests")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Broken Selectors</span>
          <span class="result-card-field-value">${escapeHtml(item.selector_broken_count ?? 0)}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Repair Ready</span>
          <span class="result-card-field-value">${escapeHtml(item.selector_fix_count ?? 0)}</span>
        </div>
      </div>
      <div class="result-card-note">
        <span class="result-card-note-label">Latest Check</span>
        <p class="result-card-note-copy">${escapeHtml(item.last_checked_at ? formatDate(item.last_checked_at) : "Not checked yet")}</p>
      </div>
      <div class="healing-subsection">
        <span class="healing-pill-label">Detected Changes</span>
        ${renderHealingChanges(item.last_summary_changes || [])}
      </div>
      <div class="healing-subsection">
        <span class="healing-pill-label">Selector Suggestions</span>
        ${renderHealingSuggestions(item.last_selector_suggestions || [])}
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
          <span class="result-card-field-label">Similarity</span>
          <span class="result-card-field-value">${escapeHtml(item.structure_similarity ?? "-")}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Broken</span>
          <span class="result-card-field-value">${escapeHtml((item.broken_selectors || []).length)}</span>
        </div>
        <div class="result-card-field">
          <span class="result-card-field-label">Repair Ready</span>
          <span class="result-card-field-value">${escapeHtml(item.auto_fix_count ?? 0)}</span>
        </div>
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

async function loadHealingMonitor(preserveStatus = false) {
  if (!preserveStatus) {
    setScanStatusLoading("healingStatus", "Loading healing monitor state...");
  }
  $("healingTargetsSummary").textContent = "Loading targets...";
  $("healingEventsSummary").textContent = "Loading events...";
  $("healingTargetsList").innerHTML = renderLoadingSkeleton("compact", 4);
  $("healingEventsList").innerHTML = renderLoadingSkeleton("compact", 3);

  try {
    const [statsData, targetsData, eventsData] = await Promise.all([
      apiFetch("/healing/stats"),
      apiFetch("/healing/targets?limit=80"),
      apiFetch("/healing/events?limit=40")
    ]);

    const stats = statsData.stats || {};
    const targets = targetsData.items || [];
    const events = eventsData.items || [];

    $("healingStatTargets").textContent = stats.total_targets ?? 0;
    $("healingStatChanged").textContent = stats.html_changed ?? 0;
    $("healingStatAutoFixed").textContent = stats.auto_fixed ?? 0;
    $("healingStatNeedsReview").textContent = stats.needs_review ?? 0;
    $("healingStatHealthy").textContent = stats.healthy ?? 0;
    $("healingStatUnreachable").textContent = stats.unreachable ?? 0;

    $("healingTargetsSummary").textContent = `${targets.length} monitored scripts`;
    $("healingEventsSummary").textContent = `${events.length} recent healing events`;
    $("healingTargetsList").innerHTML = targets.length
      ? targets.map(renderHealingTargetCard).join("")
      : `<div class="healing-empty-copy">No healing targets have been discovered yet.</div>`;
    $("healingEventsList").innerHTML = events.length
      ? events.map(renderHealingEventCard).join("")
      : `<div class="healing-empty-copy">No healing events have been recorded yet.</div>`;

    if (!preserveStatus) {
      const lastRun = stats.last_run_at ? formatDate(stats.last_run_at) : "not run yet";
      $("healingStatus").textContent = `Monitor ready. Last run ${lastRun}.`;
    }
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    $("healingStatus").textContent = `Healing monitor failed to load: ${error.message}`;
    $("healingTargetsSummary").textContent = "Unavailable";
    $("healingEventsSummary").textContent = "Unavailable";
    $("healingTargetsList").innerHTML = "";
    $("healingEventsList").innerHTML = "";
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

async function runHealingMonitor(targetKey = "", inlineButton = null) {
  const isSingleTarget = !!targetKey;
  setActionButtonBusy("healingRunBtn", !isSingleTarget, "Scanning...");
  if (inlineButton) {
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
    const path = targetKey ? `/healing/run/${encodeURIComponent(targetKey)}` : "/healing/run";
    const data = await apiFetch(path, false, {
      method: "POST",
      body: targetKey ? {} : { limit: 12 }
    });
    const statusCounts = data.status_counts || {};
    const statusLine = Object.entries(statusCounts)
      .map(([key, value]) => `${formatHealingStatus(key)} ${value}`)
      .join(", ");
    $("healingStatus").textContent = statusLine
      ? `${data.message} ${statusLine}.`
      : (data.message || "Healing scan complete.");
    await loadHealingMonitor(true);
    showToast(data.message || "Healing scan complete.", "success");
  } catch (error) {
    $("healingStatus").textContent = `Healing scan failed: ${error.message}`;
    showToast(`Healing scan failed: ${error.message}`, "error");
  } finally {
    setActionButtonBusy("healingRunBtn", false, "Scanning...");
    if (inlineButton) {
      inlineButton.disabled = false;
      inlineButton.textContent = "Run Check";
    }
  }
}

async function refreshUserList() {
  try {
    const data = await apiFetch("/admin/users");
    $("userTableBody").innerHTML = data.users.map(user => `
      <tr>
        <td>${escapeHtml(user.name || user.username)}</td>
        <td>${escapeHtml(user.username)}</td>
        <td>${escapeHtml(user.email || "")}</td>
        <td>${escapeHtml(user.role || "user")}</td>
        <td><span class="status-badge status-${escapeHtml(user.status)}">${escapeHtml(user.status)}</span></td>
        <td>
          ${user.status === "pending" ? `<button class="btn-secondary" onclick="approveUser('${escapeHtml(user.username)}')">Approve</button>` : ""}
          <button class="btn-secondary" onclick="deleteUser('${escapeHtml(user.username)}')">Reject</button>
        </td>
      </tr>
    `).join("");
  } catch (error) {
    $("userTableBody").innerHTML = `<tr><td colspan="6">${escapeHtml(error.message)}</td></tr>`;
  }
}

window.approveUser = async username => {
  await apiFetch(`/admin/users/${username}/approve`, false, { method: "POST" });
  refreshUserList();
};

window.deleteUser = async username => {
  await apiFetch(`/admin/users/${username}/reject`, false, { method: "POST" });
  refreshUserList();
};

async function runPakdbLookup() {
  const number = $("pakdbInput").value.trim();
  if (!number) return;

  setActionButtonBusy("pakdbSearchBtn", true, "Searching...");
  showListScanLoading("pakdbStatus", "pakdbHistoryList", "Searching national identity records...", "compact", 3);

  try {
    const data = await apiFetch("/pakdb/lookup", false, {
      method: "POST",
      body: { number }
    });

    const items = data.results || [];
    $("pakdbStatus").textContent = items.length ? `${items.length} result(s) returned.` : "No PakDB results found.";
    $("pakdbHistoryList").innerHTML = items.map(renderPakdbResultCard).join("");
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    $("pakdbStatus").textContent = error.message;
    $("pakdbHistoryList").innerHTML = "";
  } finally {
    setActionButtonBusy("pakdbSearchBtn", false, "Searching...");
  }
}

async function checkHealth() {
  try {
    const data = await apiFetch("/health", true);
    $("statusDot").className = `status-dot ${data.status === "ok" ? "ok" : "error"}`;
    $("statusText").textContent = data.status === "ok" ? "Connected" : "Degraded";
  } catch (error) {
    $("statusDot").className = "status-dot error";
    $("statusText").textContent = "Offline";
  }
}

async function switchView(target) {
  state.currentView = target;
  clearTimeout(state.mapRefreshTimer);
  clearTimeout(state.mapSpotlightTimer);
  updateHeader(target);
  setActiveNavigation(target);

  document.querySelectorAll(".view-panel").forEach(panel => panel.classList.add("hidden"));

  if (target === "homepage") {
    $("viewHomepage").classList.remove("hidden");
    await fetchStats();
    await initHeatmap();
    await fetchRecentIntel();
    scheduleLiveMapRefresh();
    await maybeApplyActiveTranslation("view");
    return;
  }

  if (target === "admin-users") {
    $("viewAdminUsers").classList.remove("hidden");
    refreshUserList();
    maybeApplyActiveTranslation("view");
    return;
  }

  if (target === "pakdb") {
    $("viewPakdb").classList.remove("hidden");
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
  if (target === "account") {
    $("viewAccount").classList.remove("hidden");
    await initAccountSettings();
    maybeApplyActiveTranslation("view");
    return;
  }
  state.activeTab = target;
  $("viewFeed").classList.remove("hidden");
  await loadArticles(true);
}

function scheduleRefresh() {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = setTimeout(async () => {
    try {
      await checkHealth();
      await fetchStats();
      if (state.currentView === "homepage") {
        await initHeatmap();
        await fetchRecentIntel();
      } else if (state.currentView === "admin-users") {
        await refreshUserList();
      } else if (state.currentView === "healing") {
        await loadHealingMonitor(true);
      } else if (!TOOL_VIEWS.includes(state.currentView)) {
        await loadArticles(true);
      }
      setLastUpdated();
    } catch (error) {
      console.error(error);
    } finally {
      scheduleRefresh();
    }
  }, REFRESH_MS);
}

function setupEventListeners() {
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

  $("logoutBtn").addEventListener("click", handleLogout);
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
  $("logoutBtn").onclick = handleLogout;
  $("smartUpdateBtn").onclick = triggerSmartUpdate;
  $("stopSmartUpdateBtn").onclick = stopSmartUpdate;
  $("alertSummaryBtn").onclick = showAlertSummary;
  $("translateViewBtn").onclick = () => openTranslateModal("view");
  $("detailTranslateBtn").onclick = () => openTranslateModal("detail");
  $("translateClose").onclick = closeTranslateModal;
  $("translateApplyBtn").onclick = applySelectedTranslation;
  $("translateResetModalBtn").onclick = resetTranslationToEnglish;
  $("resetLanguageBtn").onclick = resetTranslationToEnglish;

  window.onclick = e => {
    if (e.target === $("settingsBackdrop")) $("settingsBackdrop").classList.add("hidden");
    if (e.target === $("alertSummaryBackdrop")) closeAlertSummaryModal();
    if (e.target === $("mediaLightboxBackdrop")) closeMediaLightbox();
    if (e.target === $("translateBackdrop")) closeTranslateModal();
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
  $("showLoginLink").addEventListener("click", event => {
    event.preventDefault();
    toggleAuthMode();
  });
  $("mfaBackToLogin").addEventListener("click", event => {
    event.preventDefault();
    clearErrors();
    clearAuthChallenge();
    setAuthStage("login");
  });
  ["loginUsername", "loginPassword", "mfaOtpInput", "regName", "regEmail", "regUsername", "regPassword"].forEach(id => {
    $(id).addEventListener("keydown", event => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      handleAuthSubmit();
    });
  });

  $("searchInput").addEventListener("input", debounce(() => {
    if (TOOL_VIEWS.includes(state.currentView)) return;

    const query = $("searchInput").value.trim();
    if (query && query.length < MIN_GLOBAL_SEARCH_LENGTH) return;
    loadArticles(true);
  }, SEARCH_DEBOUNCE_MS));

  $("searchInput").addEventListener("keydown", event => {
    if (event.key !== "Enter" || TOOL_VIEWS.includes(state.currentView)) return;
    event.preventDefault();
    loadArticles(true);
  });

  $("loadMoreBtn").addEventListener("click", () => loadArticles(false));
  $("pakdbSearchBtn").addEventListener("click", runPakdbLookup);
  $("pakdbInput").addEventListener("keydown", event => {
    if (event.key === "Enter") runPakdbLookup();
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
  $("healingTargetsList").addEventListener("click", event => {
    const button = event.target.closest("[data-healing-run]");
    if (!button) return;
    runHealingMonitor(button.dataset.healingRun || "", button);
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
  if (theme === "light") {
    document.body.classList.add("light-theme");
    $("labelThemeState").textContent = "Light Mode";
  } else {
    document.body.classList.remove("light-theme");
    $("labelThemeState").textContent = "Dark Mode";
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
  const savedTheme = localStorage.getItem("app_theme");
  if (savedTheme === "light") {
    document.body.classList.add("light-theme");
  }

  const savedBrand = localStorage.getItem("app_name");
  if (savedBrand) {
    const brandContainer = document.getElementById("appBrandName");
    if (brandContainer) brandContainer.textContent = savedBrand;
  }

  cacheScanTemplates();
  refreshLanguageIndicator();
  setupEventListeners();
  if (!await checkAuth()) return;
  await checkHealth();
  await pollSmartUpdateStatus(true);
  await switchView("homepage");
  setLastUpdated();
  scheduleRefresh();
}

initApp().catch(error => {
  console.error(error);
});

// --- Smart Update Orchestration ---
async function triggerSmartUpdate() {
  if (isSmartUpdateRunning(state.smartUpdateStatus)) return;

  syncSmartUpdateButton(true);
  showToast("Launching automated intelligence update...", "info");

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
    showToast(data.message || "Automated intelligence update started.", "success");
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

  if (!summaryData.jobId && summaryData.sourceResults.length === 0) {
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
    ["Sources", String(summaryData.sourceResults.length || 0)]
  ].map(([label, value]) => `
    <div class="fact-item">
      <span class="fact-label">${escapeHtml(label)}</span>
      <span class="fact-value">${escapeHtml(value)}</span>
    </div>
  `).join("");

  if (summaryData.sourceResults.length) {
    $("alertSummarySources").innerHTML = summaryData.sourceResults.map(item => {
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
          ` : `<div class="summary-source-empty">No new items were added in this source during this run.</div>`}
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
  showListScanLoading("playstoreStatus", "playstoreResults", "Queued: hunting for cracked or modded APK mirrors...", "cards", 2);

  try {
    const data = await apiFetch("/apk/scan", false, {
      method: "POST",
      body: { playstore_url: url }
    });
    if (data.status === "error") {
      $("playstoreStatus").textContent = `Error: ${data.message}`;
      return;
    }
    const items = data.results || [];
    $("playstoreStatus").textContent = items.length ? `${items.length} result(s) returned.` : "No cracked versions found.";
    if (items.length) {
      $("playstoreResultsHeader").classList.remove("hidden");
      $("playstoreQueryLabel").textContent = url.length > 30 ? url.substring(0, 27) + "..." : url;
      $("playstoreCount").textContent = items.length;
      $("playstoreResults").innerHTML = items.map(renderPlaystoreCard).join("");
      await maybeApplyActiveTranslation("view");
    } else {
      $("playstoreResults").innerHTML = "";
    }
  } catch (error) {
    $("playstoreStatus").textContent = `Scan failed: ${error.message}`;
    $("playstoreResults").innerHTML = "";
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
  showListScanLoading("softwareStatus", "softwareResults", "Queued: checking cracked PC game sources...", "accordion", 3);

  try {
    const data = await apiFetch("/pcgame/scan", false, {
      method: "POST",
      body: { game_name: query }
    });
    if (data.status === "error" || data.detail) {
      $("softwareStatus").textContent = `Error: ${data.message || data.detail}`;
      return;
    }
    const items = data.results || [];
    $("softwareStatus").textContent = items.length ? `${items.length} result(s) returned.` : "No matches found.";
    if (items.length) {
      $("softwareResultsHeader").classList.remove("hidden");
      $("softwareCount").textContent = items.length;
      $("softwareQueryLabel").textContent = query.length > 30 ? query.substring(0, 27) + "..." : query;
      $("softwareResults").innerHTML = items.map(renderSoftwareAccordion).join("");
      await maybeApplyActiveTranslation("view");
    } else {
      $("softwareResults").innerHTML = "";
    }
  } catch (error) {
    $("softwareStatus").textContent = `Scan failed: ${error.message}`;
    $("softwareResults").innerHTML = "";
  } finally {
    setActionButtonBusy("softwareSearchBtn", false, "Scanning...");
  }
}

function renderSoftwareAccordion(item) {
  const fields = [
    { label: "App Name", value: item.app_name || item.name || "not available" },
    { label: "Package Id", value: item.package_id || "not available" },
    { label: "App Url", value: item.app_url || item.url || "not available" },
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
          <small>10 Fields</small>
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
  showReportScanLoading("repoScanStatus", "repoScanReport", "repo", "Queued: analyzing repository posture and dependency coverage...");

  try {
    const data = await apiFetch("/scan/repo", false, {
      method: "POST",
      body: { url: url }
    });
    if (data.status === "error") {
      restoreReportTemplate("repoScanReport", "repo");
      $("repoScanReport").classList.add("hidden");
      $("repoScanStatus").textContent = `Scan Error: ${data.message}`;
      return;
    }
    restoreReportTemplate("repoScanReport", "repo");
    $("repoScanReport").classList.remove("hidden");
    renderRepoReport(data);
    const summary = data.summary || {};
    $("repoScanStatus").textContent = `Scan complete. Grade ${summary.grade || "A"} - ${summary.posture_label || "Repository posture ready"}.`;
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    restoreReportTemplate("repoScanReport", "repo");
    $("repoScanReport").classList.add("hidden");
    $("repoScanStatus").textContent = `Scan failed: ${error.message}`;
  } finally {
    setActionButtonBusy("repoScanSearchBtn", false, "Scanning...");
  }
}

function renderRepoReport(data) {
  const summary = data.summary || {};
  const grade = String(summary.grade || "A").toUpperCase();
  const isDanger = grade === "F" || grade === "E";
  const container = $("repoScanReport");
  const totalFindings = (data.misconfigs?.length || 0) + (data.secrets?.length || 0) + (data.vulnerabilities?.length || 0);
  const postureLabel = summary.posture_label || (isDanger ? "High Risk" : totalFindings ? "Needs Review" : "Healthy");
  const reportNote = summary.note || (totalFindings ? "Security issues were detected in this repository." : "No critical findings detected for this repository.");
  const coverage = summary.coverage || {};
  const recommendations = Array.isArray(summary.recommendations) ? summary.recommendations.filter(Boolean) : [];
  
  // Apply danger theme if needed
  container.className = `seo-report-container ${isDanger ? 'report-danger' : ''}`;
  
  // Header Info
  $("repoReportTitle").textContent = `Report for ${summary.repo_name || summary.host || "github.com"}`;
  container.querySelector(".seo-report-subtitle").textContent = reportNote;
  $("repoGradeLetter").textContent = grade;
  $("repoGradeLabel").textContent = postureLabel;
  $("repoGradeCircle").className = `grade-circle grade-${grade.toLowerCase()}`;
  $("repoFindingsCount").textContent = String(totalFindings);

  // Meta Grid
  const metaGrid = container.querySelector(".seo-meta-grid");
  metaGrid.innerHTML = `
    <div class="mini-card">
      <span class="mini-card-label">TARGET URL</span>
      <span class="mini-card-value">${escapeHtml(data.query)}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">HOST</span>
      <span class="mini-card-value">${escapeHtml(summary.host || "github.com")}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">RISK SCORE</span>
      <span class="mini-card-value">${escapeHtml(String(summary.risk_score ?? 0))}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">FINDINGS</span>
      <span class="mini-card-value">${escapeHtml(String(totalFindings))}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">COVERAGE</span>
      <span class="mini-card-value">${escapeHtml(String(coverage.supported_target_count ?? 0))} supported targets</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">SCANNED ON</span>
      <span class="mini-card-value">${new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}</span>
    </div>
    <div class="mini-card">
      <span class="mini-card-label">SCANNED BY</span>
      <span class="mini-card-value">${escapeHtml(summary.scanned_by || "Orion Intelligence")}</span>
    </div>
  `;

  const repoRecommendationsBox = $("repoRecommendationsBox");
  const repoRecommendationsContent = $("repoRecommendationsContent");
  const repoRecommendationsTitle = $("repoRecommendationsTitle");
  if (repoRecommendationsBox && repoRecommendationsContent && repoRecommendationsTitle) {
    if (recommendations.length) {
      repoRecommendationsBox.classList.remove("hidden");
      repoRecommendationsTitle.textContent = grade === "A" ? "Maintain Grade A" : "How to Reach A";
      const intro = grade === "A"
        ? "This repository is in a strong state right now. These practices help keep it there."
        : `DarkPulse graded this repository ${grade}. These improvements would strengthen the posture and move it closer to A.`;
      repoRecommendationsContent.innerHTML = `
        <p class="suggestions-note">${escapeHtml(intro)}</p>
        <ul>${recommendations.map(point => `<li>${escapeHtml(point)}</li>`).join("")}</ul>
      `;
    } else {
      repoRecommendationsBox.classList.add("hidden");
      repoRecommendationsContent.innerHTML = "";
    }
  }

  // Render Category Function
  const renderCategory = (title, items) => {
    if (!items || items.length === 0) return "";
    const severityClass = severity => {
      const normalized = String(severity || "UNKNOWN").toLowerCase();
      if (normalized === "critical") return "severity-critical";
      if (normalized === "high") return "severity-high";
      if (normalized === "medium") return "severity-medium";
      if (normalized === "low") return "severity-low";
      return "severity-unknown";
    };

    return `
      <section class="repo-findings-group">
        <h3 class="repo-section-title">${escapeHtml(title)} <span>${items.length}</span></h3>
      ${items.map(f => `
        <article class="repo-finding-card">
          <div class="repo-finding-body">
            <div class="repo-finding-head">
            <div class="finding-dot ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'dot-critical' : 'dot-medium'}"></div>
              <div class="repo-finding-copy">
                <span class="repo-finding-id">${escapeHtml(f.id)}</span>
                <span class="repo-finding-title">${escapeHtml(f.title)}</span>
                <span class="repo-finding-desc">${escapeHtml(f.description)}</span>
              </div>
            </div>
            <div class="repo-finding-tags">
              <span class="repo-severity-pill ${severityClass(f.severity)}">${escapeHtml(f.severity)} Risk</span>
              <span class="repo-confidence-badge">${escapeHtml(f.confidence)}</span>
            </div>
          </div>
          <div class="repo-snippet-box">
            <div class="snippet-header">
              <span class="snippet-label">Code snippet ⓘ</span>
            </div>
            <pre class="repo-snippet-desc">${escapeHtml(f.snippet || "No snippet available")}</pre>
          </div>
        </article>
      `).join("")}
      </section>
    `;
  };

  // Main Findings List
  let html = "";
  html += renderCategory("Security Findings", data.misconfigs);
  html += renderCategory("Secrets Findings", data.secrets);
  html += renderCategory("Vulnerability Findings", data.vulnerabilities);

  if (!html) {
    const manifestExamples = Array.isArray(coverage.manifest_examples) ? coverage.manifest_examples.slice(0, 4) : [];
    html = `
      <div class="repo-clean-state">
        <h3 class="repo-clean-title">${escapeHtml(postureLabel)}</h3>
        <p class="repo-clean-copy">${escapeHtml(reportNote)}</p>
        <div class="repo-clean-stats">
          <span>Manifests: ${escapeHtml(String(coverage.manifest_count ?? 0))}</span>
          <span>Configs: ${escapeHtml(String(coverage.config_count ?? 0))}</span>
          <span>Code Files: ${escapeHtml(String(coverage.code_file_count ?? 0))}</span>
        </div>
        ${manifestExamples.length ? `<div class="repo-clean-examples">${manifestExamples.map(example => `<span>${escapeHtml(example)}</span>`).join("")}</div>` : ""}
      </div>
    `;
  }

  $("repoFindingsList").innerHTML = html;
}




// --- SEO Analysis ---
async function runSeoScan() {
  const urlArg = $("seoInput").value.trim();
  if (!urlArg) return;
  setActionButtonBusy("seoSearchBtn", true, "Analyzing...");
  showReportScanLoading("seoStatus", "seoReport", "seo", "Queued: building live SEO posture and recommendations...");

  try {
    const data = await apiFetch(`/seo/analyze?url=${encodeURIComponent(urlArg)}`);
    if (data.status === "error") {
      restoreReportTemplate("seoReport", "seo");
      $("seoReport").classList.add("hidden");
      $("seoStatus").textContent = `Error: ${data.message}`;
      return;
    }
    restoreReportTemplate("seoReport", "seo");
    $("seoStatus").textContent = data.scan_message || "Analysis complete.";
    $("seoReport").classList.remove("hidden");
    renderSeoReport(data);
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    restoreReportTemplate("seoReport", "seo");
    $("seoReport").classList.add("hidden");
    $("seoStatus").textContent = `Scan failed: ${error.message}`;
  } finally {
    setActionButtonBusy("seoSearchBtn", false, "Analyzing...");
  }
}

function renderSeoReport(data) {
  $("seoReportTitle").textContent = `Report for ${escapeHtml(data.url)}`;
  $("seoMetaUrl").textContent = data.url;
  $("seoMetaHost").textContent = new URL(data.url).hostname;
  $("seoMetaDate").textContent = data.timestamp;
  $("seoGradeLetter").textContent = data.grade;
  $("seoGradeCircle").className = `grade-circle grade-${data.grade.toLowerCase()}`;

  const audits = data.audits || {};
  const auditItems = Object.keys(audits).map(id => audits[id]);
  $("seoFindingsCount").textContent = auditItems.length;
  $("seoFindingsList").innerHTML = auditItems.map(a => `
    <div class="compact-item">
      <div class="compact-title">${escapeHtml(a.title)}</div>
      <div class="compact-item-footer">
        <span class="compact-meta">Score: ${a.score}</span>
      </div>
      <div class="compact-meta">${escapeHtml(a.description)}</div>
    </div>
  `).join("");

  const aiBox = $("seoAiSuggestionsBox");
  const aiContent = $("seoAiSuggestionsContent");
  const rawSuggestions = String(data.ai_suggestions || "").trim();
  const aiMessage = String(data.ai_message || "").trim();
  const normalizedPoints = rawSuggestions
    .split(/\n+/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => line.replace(/^[-*•]\s*/, "").replace(/^\d+[.)]\s*/, "").trim())
    .filter(Boolean);

  if (rawSuggestions || aiMessage) {
    aiBox.classList.remove("hidden");
    const messageHtml = aiMessage
      ? `<p class="suggestions-note">${escapeHtml(aiMessage)}</p>`
      : "";

    if (normalizedPoints.length) {
      aiContent.innerHTML = `${messageHtml}<ul>${normalizedPoints.map(point => `<li>${escapeHtml(point)}</li>`).join("")}</ul>`;
    } else {
      aiContent.innerHTML = `${messageHtml}<p class="suggestions-note">${escapeHtml(rawSuggestions || "No AI recommendations were returned for this scan.")}</p>`;
    }
  } else {
    aiBox.classList.add("hidden");
    aiContent.innerHTML = "";
  }
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.classList.add("show"), 100);
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => document.body.removeChild(toast), 300);
  }, 3000);
}
