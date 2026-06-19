const DEFAULT_API_BASE = window.location.origin && window.location.origin !== "null"
  ? window.location.origin
  : "http://localhost:8200";

const STORAGE_KEY = "darkpulse_api_key";
const TOKEN_KEY = "darkpulse_token";
const USER_ROLE_KEY = "darkpulse_role";
const USER_NAME_KEY = "darkpulse_name";
const API_BASE_KEY = "darkpulse_base";
const AUTH_NOTICE_KEY = "darkpulse_auth_notice";
const PAGE_SIZE = 30;
const PAGINATION_WINDOW = 5;
const REFRESH_MS = 2 * 60 * 1000;
const SMART_UPDATE_POLL_MS = 5 * 1000;
const MAP_LIVE_REFRESH_MS = 15 * 1000;
const MAP_SPOTLIGHT_MS = 2200;
const SEARCH_DEBOUNCE_MS = 550;
const AUTH_PROGRESS_TICK_MS = 140;
const MIN_GLOBAL_SEARCH_LENGTH = 2;
const FEED_SNAPSHOT_TTL_MS = 90 * 1000;
const FEED_PREFETCH_DELAY_MS = 120;
const SEMANTIC_CACHE_TTL_MS = 60 * 1000;
const TRANSLATION_LANGUAGE_KEY = "darkpulse_translation_language";
const TRANSLATION_LABEL_KEY = "darkpulse_translation_label";
const HEALING_CACHE_KEY = "darkpulse_healing_cache";

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
  ".card-summary-title",
  ".card-summary-text",
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
  ".credential-section-title",
  ".credential-detail-label",
  ".credential-detail-value",
  ".credential-tag-chip",
  ".credential-empty-copy",
  ".modal-title",
  ".modal-section label",
  ".fact-label",
  ".modal-summary",
  ".modal-ai-summary",
  ".entity-tag",
  ".summary-source-title",
  ".summary-source-empty",
  ".summary-empty",
  ".summary-highlight-title"
  ,
  ".healing-toolbar-title",
  ".healing-toolbar-note",
  ".healing-explainer-title",
  ".healing-explainer-copy",
  ".healing-step-title",
  ".healing-step-copy",
  ".healing-explainer-note",
  ".healing-pill-label",
  ".healing-change-list li",
  ".healing-suggestion-list li",
  ".healing-empty-copy",
  ".docs-title",
  ".docs-copy",
  ".docs-card strong",
  ".docs-card p",
  ".docs-list li",
  ".docs-note",
  ".auth-panel-copy",
  ".auth-guide-step p"
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
    subtitle: "Leaks and compromised monitoring activity are highlighted in red with restored MongoDB data behind the feed."
  },
  all: {
    title: "Live Feed",
    subtitle: "Every restored DarkPulse record across news, leaks, compromised monitoring, exploits, social, and API outputs."
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
    title: "Compromised Monitoring Feed",
    subtitle: "Compromised targets, attacker context, infrastructure hints, and raw record payloads."
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
  "leak-source-status": {
    title: "Leak Source Status",
    subtitle: "Track every leak script, its MongoDB footprint, and what is already visible on localhost."
  },
  docs: {
    title: "Documentation",
    subtitle: "Feature guides, operator workflows, search behavior, auth flows, and system notes."
  },
  pakdb: {
    title: "PakDB Lookup",
    subtitle: "Search entity and phone data live from the connected backend."
  },
  "credential-checker": {
    title: "Credential Checker",
    subtitle: "Review redacted exposure matches from locally saved stealer-log JSON files."
  },
  "confidential-data": {
    title: "Confidential Data",
    subtitle: "Guarded review for sensitive document evidence with a withheld in-app preview."
  },
  "admin-users": {
    title: "User Management",
    subtitle: "Approve, reject, and review dashboard access."
  },
  account: {
    title: "Account",
    subtitle: "Profile, appearance, and security preferences."
  }
};

const TOOL_VIEWS = ["admin-users", "pakdb", "credential-checker", "confidential-data", "seo", "playstore", "software", "repo-scan", "healing", "leak-source-status", "docs", "account"];
const FEED_PREFETCH_VIEWS = ["all", "news", "leak", "defacement", "exploit", "social", "api"];

const SMART_UPDATE_SOURCE_LABELS = {
  news: "Security Feeds",
  leaks: "Ransomware Leaks",
  social: "Social Monitoring",
  defacement: "Compromised Monitoring",
  exploit: "Exploit Intelligence",
  api: "API Outputs"
};

const state = {
  activeTab: "all",
  currentView: "homepage",
  offset: 0,
  total: 0,
  feedPage: 1,
  feedSnapshots: new Map(),
  feedPrefetchPromises: new Map(),
  feedWarmupPromise: null,
  semanticGuideCache: new Map(),
  paginatedResults: {
    pakdb: { items: [], page: 1 },
    playstore: { items: [], page: 1 },
    software: { items: [], page: 1 }
  },
  credentialPager: {
    query: "",
    page: 1,
    totalPages: 0,
    totalItems: 0
  },
  leakSourceStatus: {
    items: [],
    summary: {}
  },
  healingMonitor: {
    summary: {},
    collectors: [],
    scripts: [],
    events: [],
    selectedScriptId: "",
    scriptDetail: null,
    filters: {
      query: "",
      status: "",
      issue: "",
      collector: "",
      page: 1,
      pageSize: 18
    },
    checkModal: {
      scriptId: "",
      stageIndex: 0,
      timer: null,
      outcome: "idle"
    }
  },
  feedFilters: {
    startDate: "",
    endDate: "",
    network: "",
    topic: ""
  },
  feedAbortController: null,
  isRegistering: false,
  authStage: "login",
  authChallengeToken: "",
  authChallengeType: "",
  authPendingUsername: "",
  authPendingRole: "",
  authQrCodeUrl: "",
  authManualSecret: "",
  authLoadingActive: false,
  authLoadingProgress: 0,
  authLoadingCap: 0,
  authLoadingTimer: null,
  semanticSearch: null,
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
  latestStats: null,
  headerSearchBusy: false,
  mediaLightboxSrc: "",
  mediaLightboxTitle: "",
  currentDetailItem: null,
  scanExports: {
    pakdb: { query: "", items: [] },
    credential: null,
    confidential: null,
    playstore: { query: "", items: [] },
    software: { query: "", items: [] },
    seo: null,
    repo: null
  },
  confidentialFindings: [],
  confidentialSelectedRecordId: "",
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

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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

function sanitizeAiBranding(value = "") {
  const hiddenAiName = "qw" + "en";
  const hiddenRouterName = "open" + "router";
  const hiddenConfigWords = `(?:${"mo" + "del"}|${"pro" + "vider"})`;
  return String(value ?? "")
    .replace(new RegExp(`\\b${hiddenAiName}3?\\b`, "gi"), "DARKPULSE AI")
    .replace(new RegExp(`\\b${hiddenRouterName}(?:\\s+${hiddenAiName}3?)?\\b`, "gi"), "DARKPULSE AI")
    .replace(/\b(gemini|gpt-?4o?|claude|llama)\b/gi, "DARKPULSE AI")
    .replace(new RegExp(`\\b${hiddenConfigWords}\\s*:\\s*[^\\n.]+[.]?`, "gi"), "")
    .replace(new RegExp(`\\b(${hiddenRouterName}|${hiddenAiName}\\/[^\\s,.)]+|OPENROUTER_[A-Z_]+)\\b`, "g"), "DARKPULSE AI")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function normalizeRecommendationContent(content) {
  const fallback = "No DARKPULSE AI recommendations available for this result.";
  const sections = [];
  const pushSection = (title, lines) => {
    const cleanTitle = sanitizeAiBranding(title || "Recommendations") || "Recommendations";
    const cleanLines = (Array.isArray(lines) ? lines : [lines])
      .map(line => sanitizeAiBranding(String(line || "").replace(/^[-*•]\s*/, "").replace(/^\d+[.)]\s*/, "").trim()))
      .filter(Boolean);
    if (cleanLines.length) sections.push({ title: cleanTitle, items: cleanLines });
  };

  if (Array.isArray(content)) {
    pushSection("Actions", content);
    return sections.length ? sections : [{ title: "Recommendations", items: [fallback] }];
  }

  if (content && typeof content === "object") {
    const preferred = ["summary", "key_findings", "findings", "relevant_records", "missing_values", "risks", "actions", "recommendations"];
    preferred.forEach(key => {
      if (content[key] === undefined || content[key] === null) return;
      const title = key.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase());
      pushSection(title, Array.isArray(content[key]) ? content[key] : String(content[key]).split(/\n+/));
    });
    if (!sections.length) {
      Object.entries(content).forEach(([key, value]) => pushSection(key, Array.isArray(value) ? value : String(value).split(/\n+/)));
    }
    return sections.length ? sections : [{ title: "Recommendations", items: [fallback] }];
  }

  let raw = sanitizeAiBranding(String(content || "").trim());
  if (!raw) return [{ title: "Recommendations", items: [fallback] }];

  try {
    const parsed = JSON.parse(raw);
    return normalizeRecommendationContent(parsed);
  } catch (_) {}

  raw = raw
    .replace(/\*\*/g, "")
    .replace(/^#+\s*/gm, "")
    .replace(/\r/g, "\n");
  const sectionNames = ["Summary", "Key Findings", "Relevant Records", "Missing Values", "Risks", "Actions", "Recommendations"];
  const sectionPattern = new RegExp(`(?:^|\\n)\\s*(${sectionNames.join("|")})\\s*:?\\s*\\n?`, "gi");
  const matches = [...raw.matchAll(sectionPattern)];
  if (matches.length) {
    matches.forEach((match, index) => {
      const start = (match.index || 0) + match[0].length;
      const end = matches[index + 1]?.index ?? raw.length;
      const lines = raw.slice(start, end).split(/\n+/).map(line => line.trim()).filter(Boolean);
      pushSection(match[1], lines);
    });
    if (sections.length) return sections;
  }

  const lines = raw
    .replace(/\s+(?=\d+[.)]\s+)/g, "\n")
    .replace(/\s+-\s+/g, "\n- ")
    .split(/\n+/)
    .map(line => line.trim())
    .filter(Boolean);
  pushSection("Recommendations", lines.length ? lines : [raw]);
  return sections.length ? sections : [{ title: "Recommendations", items: [fallback] }];
}

function renderDarkpulseRecommendationCard(content, options = {}) {
  const sections = normalizeRecommendationContent(content);
  let note = sanitizeAiBranding(options.note || "");
  if (/^recommendations generated by darkpulse ai\.?$/i.test(note)) {
    note = "";
  }
  const hasUsefulContent = sections.some(section =>
    section.items.some(item => item !== "No DARKPULSE AI recommendations available for this result.")
  );
  const body = hasUsefulContent
    ? sections.map(section => `
        <section class="darkpulse-ai-recommendation-section">
          <h5 class="darkpulse-ai-recommendation-title">${escapeHtml(section.title)}</h5>
          <ul class="darkpulse-ai-recommendation-list">
            ${section.items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}
          </ul>
        </section>
      `).join("")
    : `<div class="darkpulse-ai-empty-state">No DARKPULSE AI recommendations available for this result.</div>`;

  return `
    <article class="darkpulse-ai-recommendation-card">
      <div class="darkpulse-ai-recommendation-header">
        <span class="ai-pulse-mini"></span>
        <h4>AI Recommendations by DARKPULSE AI</h4>
      </div>
      ${note ? `<p class="darkpulse-ai-recommendation-note">${escapeHtml(note)}</p>` : ""}
      ${body}
    </article>
  `;
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

function getBlankFeedFilters() {
  return {
    startDate: "",
    endDate: "",
    network: "",
    topic: ""
  };
}

function normalizeFeedFilters(filters = {}) {
  return {
    startDate: String(filters.startDate || "").trim(),
    endDate: String(filters.endDate || "").trim(),
    network: String(filters.network || "").trim().toLowerCase(),
    topic: String(filters.topic || "").trim()
  };
}

function buildFeedSnapshotKeyFor(sourceType = currentSourceType(), query = "", filters = getBlankFeedFilters(), page = state.feedPage || 1) {
  const normalizedFilters = normalizeFeedFilters(filters);
  const filterKey = [
    normalizedFilters.startDate,
    normalizedFilters.endDate,
    normalizedFilters.network,
    normalizedFilters.topic
  ].join("|");
  return `${String(sourceType || "all").trim().toLowerCase()}::${String(query || "").trim().toLowerCase()}::filters:${filterKey}::page:${page}`;
}

function buildFeedSnapshotKey(page = state.feedPage || 1) {
  const query = $("searchInput")?.value.trim().toLowerCase() || "";
  return buildFeedSnapshotKeyFor(currentSourceType(), query, state.feedFilters, page);
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

function setInlineButtonBusy(button, isBusy, busyLabel) {
  if (!button) return;
  if (!button.dataset.defaultLabel) {
    button.dataset.defaultLabel = button.textContent || "Action";
  }
  button.disabled = isBusy;
  button.textContent = isBusy ? busyLabel : button.dataset.defaultLabel;
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

function getPaginationMetrics(totalItems, page, pageSize = PAGE_SIZE) {
  const total = Math.max(0, Number(totalItems) || 0);
  const totalPages = total ? Math.ceil(total / pageSize) : 0;
  const safePage = totalPages ? Math.min(Math.max(1, Number(page) || 1), totalPages) : 1;
  const startIndex = total ? (safePage - 1) * pageSize : 0;
  const endIndex = total ? Math.min(startIndex + pageSize, total) : 0;

  return {
    page: safePage,
    totalItems: total,
    totalPages,
    startIndex,
    endIndex,
    startLabel: total ? startIndex + 1 : 0,
    endLabel: endIndex
  };
}

function buildPaginationPageList(page, totalPages) {
  if (totalPages <= 1) return [1];

  let start = Math.max(1, page - Math.floor(PAGINATION_WINDOW / 2));
  let end = Math.min(totalPages, start + PAGINATION_WINDOW - 1);
  start = Math.max(1, end - PAGINATION_WINDOW + 1);

  const pages = [];
  if (start > 1) {
    pages.push(1);
    if (start > 2) pages.push("ellipsis-start");
  }

  for (let current = start; current <= end; current += 1) {
    pages.push(current);
  }

  if (end < totalPages) {
    if (end < totalPages - 1) pages.push("ellipsis-end");
    pages.push(totalPages);
  }

  return pages;
}

function buildPaginationMarkup(target, metrics) {
  const pageItems = buildPaginationPageList(metrics.page, metrics.totalPages);
  return `
    <div class="pagination-meta">
      <span>Page ${escapeHtml(String(metrics.page))} of ${escapeHtml(String(metrics.totalPages))}</span>
      <span>Showing ${escapeHtml(String(metrics.startLabel))}-${escapeHtml(String(metrics.endLabel))} of ${escapeHtml(String(metrics.totalItems))}</span>
    </div>
    <div class="pagination-controls">
      <button class="pagination-btn pagination-nav" type="button" data-pagination-target="${escapeHtml(target)}" data-pagination-page="${escapeHtml(String(metrics.page - 1))}" ${metrics.page <= 1 ? "disabled" : ""}>Previous</button>
      ${pageItems.map(item => {
        if (typeof item !== "number") {
          return `<span class="pagination-ellipsis">...</span>`;
        }
        return `<button class="pagination-btn ${item === metrics.page ? "is-active" : ""}" type="button" data-pagination-target="${escapeHtml(target)}" data-pagination-page="${escapeHtml(String(item))}">${escapeHtml(String(item))}</button>`;
      }).join("")}
      <button class="pagination-btn pagination-nav" type="button" data-pagination-target="${escapeHtml(target)}" data-pagination-page="${escapeHtml(String(metrics.page + 1))}" ${metrics.page >= metrics.totalPages ? "disabled" : ""}>Next</button>
    </div>
  `;
}

function renderPagination(containerId, target, metrics) {
  const container = $(containerId);
  if (!container) return;
  if (!metrics.totalPages || metrics.totalPages <= 1) {
    container.classList.add("hidden");
    container.innerHTML = "";
    return;
  }
  container.classList.remove("hidden");
  container.innerHTML = buildPaginationMarkup(target, metrics);
}

function clearPagination(containerId) {
  const container = $(containerId);
  if (!container) return;
  container.classList.add("hidden");
  container.innerHTML = "";
}

function setExportToolbarState(toolbarId, visible, note = "") {
  const toolbar = $(toolbarId);
  if (!toolbar) return;
  toolbar.classList.toggle("hidden", !visible);
  const noteNode = toolbar.querySelector(".export-toolbar-note");
  if (noteNode && note) {
    noteNode.textContent = note;
  }
}

function getClientPaginationConfig(target) {
  switch (target) {
    case "pakdb":
      return {
        containerId: "pakdbHistoryList",
        paginationId: "pakdbPagination",
        renderItem: renderPakdbResultCard
      };
    case "playstore":
      return {
        containerId: "playstoreResults",
        paginationId: "playstorePagination",
        renderItem: renderPlaystoreCard
      };
    case "software":
      return {
        containerId: "softwareResults",
        paginationId: "softwarePagination",
        renderItem: renderSoftwareAccordion
      };
    default:
      return null;
  }
}

function getPaginationAnchorId(target) {
  switch (target) {
    case "feed":
      return "cardsGrid";
    case "credential":
      return "credentialResults";
    case "pakdb":
      return "pakdbHistoryList";
    case "playstore":
      return "playstoreResults";
    case "software":
      return "softwareResults";
    default:
      return "";
  }
}

function scrollPaginationAnchor(target) {
  const anchorId = getPaginationAnchorId(target);
  const anchor = anchorId ? $(anchorId) : null;
  if (!anchor) return;
  const top = anchor.getBoundingClientRect().top + window.scrollY - 120;
  window.scrollTo({
    top: Math.max(0, top),
    behavior: "smooth"
  });
}

function setClientPaginatedItems(target, items) {
  state.paginatedResults[target] = {
    items: Array.isArray(items) ? items.slice() : [],
    page: 1
  };
}

async function renderClientPaginatedResults(target, page = 1) {
  const config = getClientPaginationConfig(target);
  if (!config) return;

  const entry = state.paginatedResults[target] || { items: [], page: 1 };
  const metrics = getPaginationMetrics(entry.items.length, page);
  const pageItems = entry.items.slice(metrics.startIndex, metrics.endIndex);

  state.paginatedResults[target] = {
    items: entry.items,
    page: metrics.page
  };

  const container = $(config.containerId);
  if (container) {
    container.innerHTML = pageItems.map((item, index) => config.renderItem(item, metrics.startIndex + index + 1)).join("");
  }

  renderPagination(config.paginationId, target, metrics);
  await maybeApplyActiveTranslation("view");
}

async function handlePaginationChange(target, page) {
  const nextPage = Math.max(1, Number(page) || 1);
  if (target === "feed") {
    await loadArticles(true, nextPage);
    scrollPaginationAnchor(target);
    return;
  }
  if (target === "credential") {
    await runCredentialCheck(nextPage);
    scrollPaginationAnchor(target);
    return;
  }
  if (state.paginatedResults[target]) {
    await renderClientPaginatedResults(target, nextPage);
    scrollPaginationAnchor(target);
  }
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

function slugifyFilename(value, fallback = "darkpulse-export") {
  const normalized = String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || fallback;
}

function formatExportTimestamp(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  return `${year}${month}${day}-${hours}${minutes}${seconds}`;
}

function triggerFileDownload(filename, content, mimeType = "application/octet-stream") {
  const blob = new Blob([content], { type: mimeType });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

function formatExportValue(value) {
  if (Array.isArray(value)) {
    return value.map(item => formatExportValue(item)).filter(Boolean).join(", ");
  }
  if (value && typeof value === "object") {
    if ("label" in value || "name" in value || "count" in value) {
      const label = value.label || value.name || "Item";
      const count = value.count ?? value.value ?? "";
      return String(count).trim() ? `${label} ${count}` : String(label);
    }
    try {
      return Object.entries(value)
        .map(([key, itemValue]) => `${key}: ${formatExportValue(itemValue)}`)
        .join(", ");
    } catch {
      return "-";
    }
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  const text = String(value ?? "").trim();
  return text || "-";
}

function maskCredentialSecret(value) {
  return String(value ?? "").trim() || "-";
}

function maskCredentialRawTrace(trace, password) {
  return String(trace ?? "").trim() || "";
}

function formatCredentialTags(tags) {
  return (Array.isArray(tags) ? tags : [])
    .map(tag => formatExportValue(tag))
    .filter(Boolean);
}

function renderExportFields(fields) {
  const rows = (Array.isArray(fields) ? fields : Object.entries(fields || {}))
    .filter(([_, value]) => String(formatExportValue(value)).trim() && String(formatExportValue(value)).trim() !== "-");

  if (!rows.length) return "";

  return `
    <div class="export-field-grid">
      ${rows.map(([label, value]) => `
        <div class="export-field-item">
          <span class="export-field-label">${escapeHtml(label)}</span>
          <span class="export-field-value">${escapeHtml(formatExportValue(value))}</span>
        </div>
      `).join("")}
    </div>
  `;
}

function renderExportCards(cards = []) {
  if (!Array.isArray(cards) || !cards.length) return "";

  return `
    <div class="export-card-grid">
      ${cards.map(card => `
        <article class="export-card">
          <div class="export-card-head">
            <div>
              <h4>${escapeHtml(card.title || "Record")}</h4>
              ${card.subtitle ? `<p>${escapeHtml(card.subtitle)}</p>` : ""}
            </div>
            ${Array.isArray(card.tags) && card.tags.length ? `
              <div class="export-card-tags">
                ${card.tags.map(tag => `<span>${escapeHtml(tag)}</span>`).join("")}
              </div>
            ` : ""}
          </div>
          ${card.text ? `<p class="export-card-text">${escapeHtml(card.text)}</p>` : ""}
          ${renderExportFields(card.fields)}
        </article>
      `).join("")}
    </div>
  `;
}

function renderExportSection(section) {
  if (!section) return "";

  let body = "";
  if (Array.isArray(section.images) && section.images.length) {
    body += `
      <div class="export-image-grid">
        ${section.images.map((image, index) => {
          const src = typeof image === "string" ? image : image.src;
          const label = typeof image === "string" ? `Screenshot ${index + 1}` : (image.label || `Screenshot ${index + 1}`);
          return `
            <figure class="export-image-card">
              <img src="${escapeHtml(absoluteAssetUrl(src))}" alt="${escapeHtml(label)}" />
              <figcaption>${escapeHtml(label)}</figcaption>
            </figure>
          `;
        }).join("")}
      </div>
    `;
  }
  if (section.text) {
    body += `<p class="export-section-text">${escapeHtml(section.text)}</p>`;
  }
  if (section.list && section.list.length) {
    body += `<ul class="export-list">${section.list.map(item => `<li>${escapeHtml(formatExportValue(item))}</li>`).join("")}</ul>`;
  }
  if (section.fields) {
    body += renderExportFields(section.fields);
  }
  if (section.cards) {
    body += renderExportCards(section.cards);
  }
  if (section.pre) {
    body += `<pre class="export-pre">${escapeHtml(section.pre)}</pre>`;
  }

  if (!body) return "";

  return `
    <section class="export-section">
      <h3>${escapeHtml(section.title || "Section")}</h3>
      ${body}
    </section>
  `;
}

function buildExportDocumentHtml(payload, options = {}) {
  const autoPrint = options.autoPrint !== false;
  const metadata = Array.isArray(payload.metadata) ? payload.metadata : Object.entries(payload.metadata || {});
  const metadataRows = metadata.filter(([_, value]) => String(formatExportValue(value)).trim());
  const sectionsHtml = (payload.sections || []).map(section => renderExportSection(section)).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(payload.title || "DarkPulse Export")}</title>
  <style>
    :root {
      color-scheme: light;
    }
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      font-family: "Outfit", Arial, sans-serif;
      background: #edf2f7;
      color: #0f172a;
      padding: 32px;
    }
    .export-shell {
      max-width: 1040px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #dbe4ee;
      border-radius: 28px;
      padding: 32px;
      box-shadow: 0 24px 60px rgba(15, 23, 42, 0.08);
    }
    .export-kicker {
      margin: 0 0 8px;
      color: #ff5a3d;
      text-transform: uppercase;
      letter-spacing: 0.16em;
      font-size: 12px;
      font-weight: 800;
    }
    .export-shell h1 {
      margin: 0;
      font-size: 32px;
      line-height: 1.15;
    }
    .export-subtitle {
      margin: 10px 0 0;
      color: #475569;
      font-size: 15px;
      line-height: 1.6;
    }
    .export-meta {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0 0;
    }
    .export-meta-item,
    .export-field-item {
      border: 1px solid #e2e8f0;
      border-radius: 18px;
      padding: 14px 16px;
      background: #f8fafc;
    }
    .export-meta-label,
    .export-field-label {
      display: block;
      color: #64748b;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      margin-bottom: 8px;
    }
    .export-meta-value,
    .export-field-value {
      display: block;
      color: #0f172a;
      font-size: 15px;
      line-height: 1.55;
      word-break: break-word;
    }
    .export-section {
      margin-top: 28px;
      padding-top: 24px;
      border-top: 1px solid #e2e8f0;
    }
    .export-print-note {
      margin: 18px 0 0;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid #dbe4ee;
      background: #f8fafc;
      color: #475569;
      font-size: 13px;
      line-height: 1.6;
    }
    .export-section h3 {
      margin: 0 0 14px;
      font-size: 18px;
    }
    .export-section-text,
    .export-card-text {
      color: #334155;
      line-height: 1.7;
      white-space: pre-wrap;
    }
    .export-list {
      margin: 0;
      padding-left: 20px;
      color: #334155;
      line-height: 1.7;
    }
    .export-image-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }
    .export-image-card {
      margin: 0;
      border: 1px solid #dbe4ee;
      border-radius: 20px;
      overflow: hidden;
      background: #f8fafc;
      break-inside: avoid;
    }
    .export-image-card img {
      display: block;
      width: 100%;
      max-height: 360px;
      object-fit: cover;
      background: #e2e8f0;
    }
    .export-image-card figcaption {
      padding: 10px 14px;
      color: #475569;
      font-size: 12px;
      font-weight: 700;
    }
    .export-field-grid,
    .export-card-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
    }
    .export-card {
      border: 1px solid #dbe4ee;
      border-radius: 20px;
      padding: 18px;
      background: #fff;
      break-inside: avoid;
    }
    .export-card-head {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 12px;
    }
    .export-card h4 {
      margin: 0;
      font-size: 17px;
    }
    .export-card-head p {
      margin: 6px 0 0;
      color: #64748b;
      font-size: 13px;
    }
    .export-card-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: flex-end;
    }
    .export-card-tags span {
      border: 1px solid #dbe4ee;
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 12px;
      color: #334155;
      background: #f8fafc;
    }
    .export-pre {
      margin: 0;
      padding: 18px;
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 20px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12px;
      line-height: 1.6;
    }
    @media print {
      body {
        background: #fff;
        padding: 0;
      }
      .export-shell {
        max-width: none;
        border: none;
        border-radius: 0;
        box-shadow: none;
        padding: 0;
      }
      .export-section,
      .export-card,
      .export-meta-item,
      .export-field-item {
        break-inside: avoid;
      }
    }
  </style>
</head>
<body>
  <article class="export-shell">
    <p class="export-kicker">${escapeHtml(payload.kicker || "DarkPulse Export")}</p>
    <h1>${escapeHtml(payload.title || "DarkPulse Export")}</h1>
    ${payload.subtitle ? `<p class="export-subtitle">${escapeHtml(payload.subtitle)}</p>` : ""}
    ${metadataRows.length ? `
      <div class="export-meta">
        ${metadataRows.map(([label, value]) => `
          <div class="export-meta-item">
            <span class="export-meta-label">${escapeHtml(label)}</span>
            <span class="export-meta-value">${escapeHtml(formatExportValue(value))}</span>
          </div>
        `).join("")}
      </div>
    ` : ""}
    <div class="export-print-note">DarkPulse prepared this printable export for PDF saving. If the print dialog does not open automatically, use <strong>Ctrl+P</strong> or your browser Print action.</div>
    ${sectionsHtml}
  </article>
  ${autoPrint ? `
  <script>
    window.addEventListener("load", function () {
      var images = Array.prototype.slice.call(document.images || []);
      var waits = images.map(function (img) {
        if (img.complete) return Promise.resolve();
        return new Promise(function (resolve) {
          img.addEventListener("load", resolve, { once: true });
          img.addEventListener("error", resolve, { once: true });
        });
      });
      Promise.race([
        Promise.all(waits),
        new Promise(function (resolve) { setTimeout(resolve, 4200); })
      ]).then(function () {
        window.focus();
        window.print();
      });
    });
  </script>
  ` : ""}
</body>
</html>`;
}

function createPrintWindowShell() {
  const printWindow = window.open("", "_blank");
  if (!printWindow) return null;
  printWindow.document.write(`<!DOCTYPE html><html><head><title>Preparing PDF export</title></head><body style="font-family: Arial, sans-serif; padding: 24px; color: #0f172a; background: #f8fafc;">Preparing DarkPulse PDF export...</body></html>`);
  printWindow.document.close();
  return printWindow;
}

function exportPayloadAsJson(payload) {
  const fileBase = slugifyFilename(payload.filenameBase || payload.title || "darkpulse-export");
  triggerFileDownload(
    `${fileBase}-${formatExportTimestamp()}.json`,
    JSON.stringify(payload.data, null, 2),
    "application/json"
  );
}

function exportPayloadAsPdf(payload, printWindow = null) {
  const exportWindow = printWindow || createPrintWindowShell();
  if (!exportWindow) {
    throw new Error("Popup was blocked. Allow popups to save PDF exports.");
  }

  const html = buildExportDocumentHtml(payload, { autoPrint: true });
  const blob = new Blob([html], { type: "text/html" });
  const objectUrl = URL.createObjectURL(blob);
  exportWindow.location.replace(objectUrl);
  setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
}

function updateHeader(viewName) {
  const meta = VIEW_META[viewName] || VIEW_META.all;
  $("viewTitle").textContent = meta.title;
  $("viewSubtitle").textContent = meta.subtitle;
}

function setLastUpdated() {
  const lastUpdated = $("lastUpdated");
  if (lastUpdated) {
    lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  }
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
    if (!startButton.dataset.originalText || /scanning|stopping/i.test(startButton.dataset.originalText)) {
      startButton.dataset.originalText = startButton.textContent || "Scan Now";
    }
    startButton.classList.toggle("scanning", isRunning && !isCancelling);
    startButton.disabled = isRunning;
    startButton.textContent = isRunning
      ? (isCancelling ? "Stopping..." : "Scanning...")
      : "Scan Now";
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

function initSidebarAutomationCollapse() {
  const sidebar = document.querySelector(".app-sidebar");
  const nav = document.querySelector(".sidebar-nav");
  if (!sidebar || !nav || sidebar.dataset.automationScrollReady === "1") return;

  sidebar.dataset.automationScrollReady = "1";
  let lastScrollTop = nav.scrollTop;
  nav.addEventListener("scroll", () => {
    const currentScrollTop = nav.scrollTop;
    const delta = currentScrollTop - lastScrollTop;

    if (currentScrollTop <= 12 || delta < -8) {
      sidebar.classList.remove("sidebar-automation-collapsed");
    } else if (delta > 8 && currentScrollTop > 24) {
      sidebar.classList.add("sidebar-automation-collapsed");
    }

    lastScrollTop = currentScrollTop;
  }, { passive: true });
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

function setAuthStage(stage) {
  state.authStage = stage;
  state.isRegistering = stage === "register";
  $("loginForm").classList.toggle("hidden", stage !== "login");
  $("registerForm").classList.toggle("hidden", stage !== "register");
  $("forgotForm").classList.toggle("hidden", stage !== "forgot");
  $("approvalForm").classList.toggle("hidden", stage !== "approval");
  $("mfaForm").classList.toggle("hidden", stage !== "mfa");
  $("authSubmitBtn").classList.toggle("hidden", stage === "approval");
  $("authSubmitBtn").textContent = stage === "register"
    ? "Request Access"
    : stage === "mfa"
      ? "Verify OTP"
      : stage === "forgot"
        ? "Request Reset"
        : "Sign In";
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
  ["loginError", "registerError", "forgotError", "mfaError"].forEach(id => {
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
      const requestedUsername = $("regUsername").value.trim();
      await apiFetch("/auth/register", true, {
        method: "POST",
        body: {
          username: requestedUsername,
          password: $("regPassword").value,
          email: $("regEmail").value.trim(),
          name: $("regName").value.trim()
        }
      });
      $("regName").value = "";
      $("regEmail").value = "";
      $("regUsername").value = "";
      $("regPassword").value = "";
      setAuthStage("login");
      $("loginUsername").value = requestedUsername;
      $("loginPassword").value = "";
      $("loginInfo").textContent = "Registration submitted. Wait for admin approval before signing in.";
      $("loginInfo").classList.remove("hidden");
      return;
    }

    if (state.authStage === "forgot") {
      const data = await apiFetch("/auth/password-reset-request", true, {
        method: "POST",
        body: {
          identity: $("forgotIdentity").value.trim(),
          message: $("forgotMessage").value.trim()
        }
      });
      clearErrors();
      setAuthStage("login");
      $("forgotIdentity").value = "";
      $("forgotMessage").value = "";
      $("loginInfo").textContent = data.message || "Reset request submitted for review.";
      $("loginInfo").classList.remove("hidden");
      return;
    }

    if (state.authStage === "mfa") {
      button.textContent = "Verifying OTP...";
      showAuthLoading({
        kicker: "Two-Factor Verification",
        title: "Confirming your one-time password",
        copy: "DarkPulse is validating your OTP and restoring your approved analyst session.",
        stage: "Checking the 6-digit code from your authenticator...",
        progress: 18,
        cap: 86
      });
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
      await bootstrapAuthenticatedSession({
        username: state.authPendingUsername || $("loginUsername").value.trim(),
        role: data.role
      });
      return;
    }

    const username = $("loginUsername").value.trim();
    button.textContent = "Signing In...";
    showAuthLoading({
      kicker: "Authenticating",
      title: "Signing in to DarkPulse",
      copy: "We are verifying your credentials and preparing the local threat intelligence console.",
      stage: "Checking username and password...",
      progress: 12,
      cap: 84
    });
    const data = await apiFetch("/auth/login", true, {
      method: "POST",
      body: {
        username,
        password: $("loginPassword").value
      }
    });

    if (data.mfa_required) {
      await advanceAuthLoading(100, "Two-factor verification required. Opening OTP step...", {
        copy: "Your account needs an authenticator code before DarkPulse can finish signing you in.",
        delay: 220
      });
      hideAuthLoading();
      prepareTwoFactorStage(data, username);
      return;
    }

    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USER_ROLE_KEY, data.role);
    localStorage.setItem(USER_NAME_KEY, username);
    sessionStorage.removeItem(AUTH_NOTICE_KEY);
    await bootstrapAuthenticatedSession({ username, role: data.role });
  } catch (error) {
    hideAuthLoading();
    const errorTarget = state.authStage === "register"
      ? "registerError"
      : state.authStage === "mfa"
        ? "mfaError"
        : state.authStage === "forgot"
          ? "forgotError"
          : "loginError";
    showError(errorTarget, error.message);
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
    if (state.authStage === "login") {
      button.textContent = "Sign In";
    } else if (state.authStage === "register") {
      button.textContent = "Request Access";
    } else if (state.authStage === "forgot") {
      button.textContent = "Request Reset";
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

function getActiveFeedFilters() {
  return normalizeFeedFilters(state.feedFilters);
}

function countActiveFeedFilters() {
  const filters = getActiveFeedFilters();
  return [filters.startDate, filters.endDate, filters.network, filters.topic].filter(Boolean).length;
}

function buildFeedFilterSummary(filters = getActiveFeedFilters()) {
  const parts = [];
  if (filters.startDate) parts.push(`From ${filters.startDate}`);
  if (filters.endDate) parts.push(`To ${filters.endDate}`);
  if (filters.network) parts.push(filters.network === "onion" ? "Onion / Tor" : "Clearnet");
  if (filters.topic) parts.push(`Topic ${filters.topic}`);
  return parts.length ? parts.join(" • ") : "No feed filters applied.";
}

function renderFeedFilterState() {
  const filters = getActiveFeedFilters();
  const activeCount = countActiveFeedFilters();
  const button = $("feedFilterBtn");
  const bar = $("feedFilterBar");
  const note = $("feedFilterNote");
  const chips = $("feedFilterChips");
  const status = $("feedFilterStatus");

  if (button) {
    button.textContent = activeCount ? `Filters (${activeCount})` : "Filters";
  }

  if (status) {
    status.textContent = buildFeedFilterSummary(filters);
  }

  if (!bar || !note || !chips) return;

  if (!activeCount) {
    bar.classList.add("hidden");
    note.textContent = "No feed filters applied.";
    chips.innerHTML = "";
    return;
  }

  note.textContent = buildFeedFilterSummary(filters);
  chips.innerHTML = [
    filters.startDate ? `<span class="feed-filter-chip">Start ${escapeHtml(filters.startDate)}</span>` : "",
    filters.endDate ? `<span class="feed-filter-chip">End ${escapeHtml(filters.endDate)}</span>` : "",
    filters.network ? `<span class="feed-filter-chip">${escapeHtml(filters.network === "onion" ? "Onion / Tor" : "Clearnet")}</span>` : "",
    filters.topic ? `<span class="feed-filter-chip">Topic ${escapeHtml(filters.topic)}</span>` : ""
  ].filter(Boolean).join("");
  bar.classList.remove("hidden");
}

function setHeaderSearchBusy(isBusy, label = "Searching local intelligence...") {
  state.headerSearchBusy = isBusy;
  const bar = $("headerSearchBar");
  const status = $("searchBarStatus");
  const icon = $("headerSearchIcon");

  if (bar) {
    bar.classList.toggle("is-busy", isBusy);
    bar.setAttribute("aria-busy", isBusy ? "true" : "false");
  }
  if (status) {
    status.textContent = label;
    status.classList.toggle("hidden", !isBusy);
  }
  if (icon) {
    icon.textContent = isBusy ? "..." : "/";
  }
}

function openFeedFiltersModal() {
  $("feedFilterStartDate").value = state.feedFilters.startDate || "";
  $("feedFilterEndDate").value = state.feedFilters.endDate || "";
  $("feedFilterNetwork").value = state.feedFilters.network || "";
  $("feedFilterTopic").value = state.feedFilters.topic || "";
  renderFeedFilterState();
  $("feedFiltersBackdrop").classList.remove("hidden");
}

function closeFeedFiltersModal() {
  $("feedFiltersBackdrop").classList.add("hidden");
}

/* ── Floating Chatbot Widget ────────────────────────────────────────── */
let _dpChatBusy = false;

function isAuthRouteOrLoginVisible() {
  const path = `${window.location.pathname || ""} ${window.location.hash || ""}`.toLowerCase();
  return path.includes("/login")
    || path.includes("/auth")
    || path.includes("/signin")
    || !$("loginBackdrop")?.classList.contains("hidden")
    || $("appWrapper")?.classList.contains("hidden");
}

function setChatAvailability(enabled) {
  const shouldEnable = Boolean(enabled) && !isAuthRouteOrLoginVisible();
  const headerButton = $("aiChatLaunchBtn");
  const fab = $("dpChatFab");
  const widget = $("dpChatWidget");
  if (headerButton) {
    headerButton.classList.toggle("hidden", !shouldEnable);
    headerButton.style.display = shouldEnable ? "" : "none";
  }
  if (!shouldEnable) {
    fab?.classList.add("hidden");
    widget?.classList.add("hidden");
    return;
  }
  if (widget?.classList.contains("hidden")) {
    fab?.classList.remove("hidden");
  }
}

function dpChatShow() {
  if (isAuthRouteOrLoginVisible()) return;
  $("dpChatWidget").classList.remove("hidden");
  $("dpChatFab").classList.add("hidden");
  setTimeout(() => $("dpChatInput").focus(), 60);
}

function dpChatHide() {
  $("dpChatWidget").classList.add("hidden");
  if (!isAuthRouteOrLoginVisible()) $("dpChatFab").classList.remove("hidden");
}

function dpChatMinimize() {
  $("dpChatWidget").classList.add("hidden");
  if (!isAuthRouteOrLoginVisible()) $("dpChatFab").classList.remove("hidden");
}

function dpChatClear() {
  $("dpChatMessages").innerHTML = `
    <div class="dp-chat-welcome">
      <div class="dp-chat-welcome-icon">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
      </div>
      <p class="dp-chat-welcome-title">DARKPULSE Chatbot</p>
      <p class="dp-chat-welcome-text">Ask about threat actors, leaks, CVEs, ransomware campaigns, or any topic in the local MongoDB.</p>
    </div>
  `;
}

function dpChatShowFab() {
  if (!isAuthRouteOrLoginVisible() && $("dpChatWidget").classList.contains("hidden")) {
    $("dpChatFab").classList.remove("hidden");
  }
}

function _dpScrollToBottom() {
  const el = $("dpChatMessages");
  el.scrollTop = el.scrollHeight;
}

function _dpAddUserMessage(text) {
  const welcome = $("dpChatMessages").querySelector(".dp-chat-welcome");
  if (welcome) welcome.remove();

  const now = new Date();
  const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  const msg = document.createElement("div");
  msg.className = "dp-msg dp-msg-user";
  msg.innerHTML = `
    <div class="dp-msg-bubble">${escapeHtml(sanitizeAiBranding(text))}</div>
    <div class="dp-msg-meta">${time}</div>
  `;
  $("dpChatMessages").appendChild(msg);
  _dpScrollToBottom();
}

function _dpAddThinking() {
  const el = document.createElement("div");
  el.className = "dp-msg dp-msg-ai";
  el.id = "dpMsgThinking";
  el.innerHTML = `
    <div class="dp-msg-bubble dp-msg-thinking">
      <div class="dp-msg-thinking-dots"><span></span><span></span><span></span></div>
      Searching intelligence...
    </div>
  `;
  $("dpChatMessages").appendChild(el);
  _dpScrollToBottom();
}

function _dpRemoveThinking() {
  const el = $("dpMsgThinking");
  if (el) el.remove();
}

function _dpSourceLabel(doc) {
  // Build a human-readable label from the document reference
  const aid = doc.aid || doc._id || "";
  const field = doc.field || "";

  // Try to extract a meaningful title from the preview
  const preview = doc.preview || "";
  const titleMatch = preview.match(/Title:\s*(.+?)(?:\n|$)/i);
  const summaryMatch = preview.match(/Summary:\s*(.+?)(?:\n|$)/i);
  const sourceMatch = preview.match(/Source(?:\sName)?:\s*(.+?)(?:\n|$)/i);

  if (titleMatch && titleMatch[1].trim().length > 5) {
    return titleMatch[1].trim().slice(0, 65);
  }
  if (summaryMatch && summaryMatch[1].trim().length > 5) {
    return summaryMatch[1].trim().slice(0, 65);
  }
  if (sourceMatch && sourceMatch[1].trim().length > 3) {
    return sourceMatch[1].trim().slice(0, 65);
  }

  // Fallback: use the aid/field combo but make it readable
  if (aid && field && field !== "record" && field !== "content") {
    return `${field.charAt(0).toUpperCase() + field.slice(1)} · ${aid.slice(0, 20)}`;
  }
  if (aid) {
    // Try to extract source from the aid pattern like "LEAK_ITEMS:raw:xxxx"
    const aidParts = aid.split(":");
    if (aidParts.length >= 2) {
      const type = aidParts[0].replace(/_ITEMS$/i, "").replace(/_/g, " ");
      return `${type.charAt(0).toUpperCase() + type.slice(1).toLowerCase()} record · ${aidParts.slice(-1)[0].slice(0, 12)}`;
    }
    return `Intelligence record · ${aid.slice(0, 20)}`;
  }
  return `Source document #${Math.random().toString(36).slice(2, 6)}`;
}

function _dpRenderSources(docs, container) {
  if (!docs || !docs.length) return;

  const sourcesEl = document.createElement("div");
  sourcesEl.className = "dp-msg-sources";
  sourcesEl.innerHTML = `<div class="dp-msg-sources-label">References (${docs.length})</div>`;

  docs.slice(0, 5).forEach((doc, i) => {
    const btn = document.createElement("button");
    btn.className = "dp-msg-source-chip";
    if (doc.aid) {
      btn.setAttribute("data-ai-source-aid", doc.aid);
    } else {
      btn.disabled = true;
    }
    btn.innerHTML = `
      <span class="dp-msg-source-num">${i + 1}</span>
      <span class="dp-msg-source-text">${escapeHtml(_dpSourceLabel(doc))}</span>
      <span class="dp-msg-source-arrow">${doc.aid ? "→" : ""}</span>
    `;
    if (doc.aid) {
      btn.addEventListener("click", () => {
        dpChatMinimize();
        showDetail(doc.aid);
      });
    }
    sourcesEl.appendChild(btn);
  });

  container.appendChild(sourcesEl);
}

function splitAiSectionLines(content = "", forceList = false) {
  const normalized = String(content || "")
    .replace(/\s+(?=\d+\.\s+)/g, "\n")
    .replace(/\s+-\s+/g, "\n")
    .trim();
  const lines = normalized
    .split(/\n+/)
    .map(line => line.replace(/^[-*•\d.)\s]+/, "").trim())
    .filter(Boolean);
  return forceList ? lines : (lines.length > 1 ? lines : [normalized]);
}

function _dpRenderStructuredAnswer(rawText, bubble) {
  // Clean and parse the structured sections
  const bodyText = sanitizeAiBranding(rawText)
    .replace(/\*\*\s*(Summary|Key Findings|Relevant Records|Missing Values)\s*:?\s*\*\*/g, "$1:")
    .replace(/^#+\s*(Summary|Key Findings|Relevant Records|Missing Values):?/gm, "$1:")
    .replace(/\s*(Summary|Key Findings|Relevant Records|Missing Values):\s*/g, "\n$1:\n")
    .replace(/\*\*/g, "")
    .trim();

  const sectionNames = ["Summary", "Key Findings", "Relevant Records", "Missing Values"];
  const sectionPattern = new RegExp(`^(${sectionNames.join("|")}):?\\s*`, "gm");
  const matches = [...bodyText.matchAll(sectionPattern)];

  if (!matches.length) {
    bubble.innerHTML = `<p style="margin:0">${escapeHtml(bodyText)}</p>`;
    return;
  }

  const sections = matches.map((match, index) => {
    const start = match.index + match[0].length;
    const end = matches[index + 1]?.index ?? bodyText.length;
    return { title: match[1], content: bodyText.slice(start, end).trim() };
  }).filter(s => s.content);

  bubble.innerHTML = sections.map(section => {
    const forceList = section.title !== "Summary";
    const lines = splitAiSectionLines(section.content, forceList);
    const markup = forceList || lines.length > 1
      ? `<ul>${lines.map(l => `<li>${escapeHtml(l)}</li>`).join("")}</ul>`
      : `<p>${escapeHtml(lines[0] || section.content)}</p>`;
    return `<section class="ai-chat-section"><h3>${escapeHtml(section.title)}</h3>${markup}</section>`;
  }).join("");
}

function _dpChatMetaLabel(metaInfo) {
  if (!metaInfo) return "response";
  const count = Number(metaInfo.count || 0);
  if (metaInfo.status === "general_chat") return "general chat";
  if (metaInfo.status === "empty") return "no matching records";
  if (metaInfo.status === "success") {
    return count === 1 ? "1 source record" : `top ${count} source records`;
  }
  return count === 1 ? "1 record" : `${count} records`;
}

async function runAiChatQuery() {
  const input = $("dpChatInput");
  const query = input.value.trim();
  if (!query || _dpChatBusy) return;

  _dpChatBusy = true;
  input.value = "";
  $("dpChatSendBtn").disabled = true;

  _dpAddUserMessage(query);
  _dpAddThinking();

  try {
    const headers = {
      "Content-Type": "application/json",
      Accept: "text/event-stream"
    };
    const token = getToken();
    const apiKey = localStorage.getItem(STORAGE_KEY) || "";
    if (token) headers.Authorization = `Bearer ${token}`;
    if (apiKey) headers["X-API-Key"] = apiKey;

    const response = await fetch(getBase() + "/api/ai/stream", {
      method: "POST",
      headers,
      body: JSON.stringify({ query, collection: "redis_kv_store", limit: 8, max_context_words: 1800 })
    });

    if (response.status === 401) { handleLogout(); throw new Error("Session expired"); }
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }

    _dpRemoveThinking();

    // Create AI message bubble
    const aiMsg = document.createElement("div");
    aiMsg.className = "dp-msg dp-msg-ai";
    const bubble = document.createElement("div");
    bubble.className = "dp-msg-bubble";
    const streamEl = document.createElement("div");
    streamEl.className = "dp-msg-stream";
    bubble.appendChild(streamEl);
    aiMsg.appendChild(bubble);
    $("dpChatMessages").appendChild(aiMsg);

    let fullAnswer = "";
    let metaDocs = [];
    let metaInfo = null;

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      sseBuffer += decoder.decode(value, { stream: true });
      const parts = sseBuffer.split("\n\n");
      sseBuffer = parts.pop() || "";

      for (const part of parts) {
        if (!part.trim()) continue;
        let eventType = "message", eventData = "";
        for (const line of part.split("\n")) {
          if (line.startsWith("event: ")) eventType = line.slice(7).trim();
          else if (line.startsWith("data: ")) eventData = line.slice(6);
        }

        if (eventType === "meta") {
          try {
            const meta = JSON.parse(eventData);
            metaInfo = meta;
            if (meta.status === "error" || meta.status === "empty") {
              streamEl.textContent = meta.message || "No data found.";
              break;
            }
            metaDocs = meta.documents || [];
          } catch(_) {}
        } else if (eventType === "chunk") {
          try {
            const text = JSON.parse(eventData);
            fullAnswer += text;
    streamEl.textContent = sanitizeAiBranding(fullAnswer);
            _dpScrollToBottom();
          } catch(_) {}
        } else if (eventType === "done") {
          break;
        }
      }
    }

    // Final structured render
    if (fullAnswer.trim()) {
      streamEl.remove();
      _dpRenderStructuredAnswer(sanitizeAiBranding(fullAnswer), bubble);
    }

    // Add source references
    if (metaDocs.length > 0) {
      _dpRenderSources(metaDocs, bubble);
    }

    // Add timestamp
    const now = new Date();
    const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const meta = document.createElement("div");
    meta.className = "dp-msg-meta";
    meta.innerHTML = `<span class="dp-msg-meta-dot"></span> ${time} · ${escapeHtml(_dpChatMetaLabel(metaInfo))}`;
    aiMsg.appendChild(meta);

    _dpScrollToBottom();

  } catch (error) {
    _dpRemoveThinking();
    const errMsg = document.createElement("div");
    errMsg.className = "dp-msg dp-msg-ai";
    errMsg.innerHTML = `<div class="dp-msg-bubble" style="border-color:rgba(255,80,80,0.3)">Warning: ${escapeHtml(sanitizeAiBranding(error.message))}</div>`;
    $("dpChatMessages").appendChild(errMsg);
    _dpScrollToBottom();
  } finally {
    _dpChatBusy = false;
    $("dpChatSendBtn").disabled = false;
    $("dpChatInput").focus();
  }
}

// Legacy aliases — keep these so old code referencing them doesn't crash
function openAiChatModal() { dpChatShow(); }
function closeAiChatModal() { dpChatMinimize(); }
function clearAiChat() { dpChatClear(); }

async function applyFeedFilters(options = {}) {
  const closeModal = options.closeModal !== false;
  const startDate = $("feedFilterStartDate").value.trim();
  const endDate = $("feedFilterEndDate").value.trim();
  const network = $("feedFilterNetwork").value.trim();
  const topic = $("feedFilterTopic").value.trim();

  if (startDate && endDate && startDate > endDate) {
    $("feedFilterStatus").textContent = "Start date cannot be later than end date.";
    return;
  }

  state.feedFilters = { startDate, endDate, network, topic };
  renderFeedFilterState();
  if (closeModal) closeFeedFiltersModal();

  if (!TOOL_VIEWS.includes(state.currentView) && state.currentView !== "homepage") {
    await loadArticles(true, 1);
  }
}

async function resetFeedFilters() {
  state.feedFilters = { startDate: "", endDate: "", network: "", topic: "" };
  $("feedFilterStartDate").value = "";
  $("feedFilterEndDate").value = "";
  $("feedFilterNetwork").value = "";
  $("feedFilterTopic").value = "";
  renderFeedFilterState();

  if (!TOOL_VIEWS.includes(state.currentView) && state.currentView !== "homepage") {
    await loadArticles(true, 1);
  }
}

function buildFeedPath(limit = PAGE_SIZE, page = state.feedPage || 1, includeRaw = false) {
  return buildFeedRequestPath({
    limit,
    page,
    includeRaw,
    sourceType: currentSourceType(),
    query: $("searchInput").value.trim(),
    filters: getActiveFeedFilters()
  });
}

function buildFeedRequestPath({
  limit = PAGE_SIZE,
  page = 1,
  includeRaw = false,
  sourceType = currentSourceType(),
  query = "",
  filters = getBlankFeedFilters()
} = {}) {
  const safePage = Math.max(1, Number(page) || 1);
  const safeFilters = normalizeFeedFilters(filters);
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String((safePage - 1) * limit)
  });

  if (sourceType && sourceType !== "all") params.set("source_type", sourceType);
  if (query) params.set("q", query);
  if (safeFilters.startDate) params.set("start_date", safeFilters.startDate);
  if (safeFilters.endDate) params.set("end_date", safeFilters.endDate);
  if (safeFilters.network) params.set("network", safeFilters.network);
  if (safeFilters.topic) params.set("topic", safeFilters.topic);
  if (includeRaw) params.set("include_raw", "true");

  return `/feed?${params.toString()}`;
}

function isFeedSnapshotFresh(snapshot) {
  return Boolean(
    snapshot &&
    typeof snapshot.cachedAt === "number" &&
    (Date.now() - snapshot.cachedAt) < FEED_SNAPSHOT_TTL_MS &&
    Array.isArray(snapshot.items)
  );
}

function storeFeedSnapshot(sourceType, query, filters, page, items, total) {
  const snapshotKey = buildFeedSnapshotKeyFor(sourceType, query, filters, page);
  state.feedSnapshots.set(snapshotKey, {
    cachedAt: Date.now(),
    items: Array.isArray(items) ? items.slice() : [],
    total: Number(total || 0)
  });
}

async function prefetchFeedSnapshot(viewName, page = 1) {
  const sourceType = TAB_SOURCE_MAP[viewName] || viewName || "all";
  const filters = getBlankFeedFilters();
  const snapshotKey = buildFeedSnapshotKeyFor(sourceType, "", filters, page);
  const existing = state.feedSnapshots.get(snapshotKey);
  if (isFeedSnapshotFresh(existing)) {
    return existing;
  }
  if (state.feedPrefetchPromises.has(snapshotKey)) {
    return state.feedPrefetchPromises.get(snapshotKey);
  }

  const promise = (async () => {
    try {
      const data = await apiFetch(buildFeedRequestPath({
        sourceType,
        page,
        limit: PAGE_SIZE,
        query: "",
        filters
      }));
      const items = Array.isArray(data.items) ? data.items : [];
      storeFeedSnapshot(sourceType, "", filters, page, items, data.total || items.length);
      items.forEach(item => {
        state.detailCache.set(item.aid, item);
      });
      return data;
    } catch (error) {
      console.error(`Feed prefetch failed for ${viewName}`, error);
      return null;
    } finally {
      state.feedPrefetchPromises.delete(snapshotKey);
    }
  })();

  state.feedPrefetchPromises.set(snapshotKey, promise);
  return promise;
}

function warmFeedSnapshots(force = false) {
  if (!getToken()) return Promise.resolve();
  if (state.feedWarmupPromise && !force) {
    return state.feedWarmupPromise;
  }

  const promise = (async () => {
    for (const viewName of FEED_PREFETCH_VIEWS) {
      if (!getToken()) break;
      await prefetchFeedSnapshot(viewName, 1);
      await new Promise(resolve => setTimeout(resolve, FEED_PREFETCH_DELAY_MS));
    }
  })();

  state.feedWarmupPromise = promise;
  promise.finally(() => {
    if (state.feedWarmupPromise === promise) {
      state.feedWarmupPromise = null;
    }
  });
  return promise;
}

function renderSearchInsight() {
  const bar = $("searchInsight");
  if (!bar) return;

  const query = $("searchInput").value.trim();
  if (state.currentView === "homepage" || TOOL_VIEWS.includes(state.currentView) || !query || query.length < MIN_GLOBAL_SEARCH_LENGTH) {
    bar.classList.add("hidden");
    $("searchInsightMeta").innerHTML = "";
    return;
  }

  const insight = state.semanticSearch;
  const title = $("searchInsightTitle");
  const message = $("searchInsightMessage");
  const meta = $("searchInsightMeta");

  bar.classList.remove("hidden");

  if (!insight || String(insight.query || "").toLowerCase() !== query.toLowerCase() || insight.pending) {
    title.textContent = `Analyzing "${query}"`;
    message.textContent = "DarkPulse is checking the restored feeds, entities, and summaries to find the best route for this query.";
    meta.innerHTML = `<span class="search-chip loading">Semantic route pending</span>`;
    return;
  }

  if (!insight.total) {
    title.textContent = `No results for "${query}"`;
    message.textContent = "No matching intelligence was found in the local restored records for this search. Try another actor, topic, domain, or keyword.";
    meta.innerHTML = `<span class="search-chip muted">0 matches</span>`;
    return;
  }

  const routeLabel = humanViewName(insight.suggested_view || "all");
  title.textContent = `${insight.total} matches for "${query}"`;
  message.textContent = `DarkPulse routed this query toward ${routeLabel} based on semantic matches across restored titles, descriptions, entities, actors, IPs, and related source text.`;
  meta.innerHTML = Object.entries(insight.source_counts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([source, count]) => `<span class="search-chip">${escapeHtml(humanViewName(source))} <strong>${escapeHtml(String(count))}</strong></span>`)
    .join("");
}

async function fetchSemanticGuide(query) {
  const cleanQuery = String(query || "").trim();
  if (!cleanQuery || cleanQuery.length < MIN_GLOBAL_SEARCH_LENGTH) {
    state.semanticSearch = null;
    renderSearchInsight();
    return null;
  }

  const cacheKey = cleanQuery.toLowerCase();
  const cached = state.semanticGuideCache.get(cacheKey);
  if (cached && (Date.now() - cached.cachedAt) < SEMANTIC_CACHE_TTL_MS) {
    state.semanticSearch = cached.data;
    renderSearchInsight();
    return cached.data;
  }

  state.semanticSearch = {
    query: cleanQuery,
    pending: true,
    total: 0,
    source_counts: {},
    suggested_view: "all"
  };
  renderSearchInsight();

  const data = await apiFetch(`/search/semantic?q=${encodeURIComponent(cleanQuery)}&limit=8`);
  state.semanticSearch = data;
  state.semanticGuideCache.set(cacheKey, {
    cachedAt: Date.now(),
    data
  });
  renderSearchInsight();
  return data;
}

async function routeHomepageSearch(query) {
  await switchView("all", { skipFeedLoad: true });
  $("cardsGrid").innerHTML = renderLoadingSkeleton("feed", 6);
  setFeedState("Routing intelligence", `DarkPulse is mapping "${query}" into the best stream and loading local matches.`, "loading");
  $("emptyState").classList.add("hidden");
  $("feedSummary").textContent = `Routing "${query}" into the live feed...`;
  clearPagination("feedPagination");
  renderSearchInsight();

  const semanticPromise = fetchSemanticGuide(query);
  const feedPromise = loadArticles(true, 1).catch(error => {
    console.error(error);
    return null;
  });
  const semantic = await semanticPromise;
  const targetView = semantic && semantic.total > 0
    ? (semantic.suggested_view || "all")
    : "all";

  if (targetView !== state.currentView) {
    await switchView(targetView);
    return;
  }

  updateHeader(targetView);
  setActiveNavigation(targetView);
  renderSearchInsight();
  await feedPromise;
}

async function handleHeaderSearch(force = false) {
  const query = $("searchInput").value.trim();
  if (!query) {
    state.semanticSearch = null;
    renderSearchInsight();
    setHeaderSearchBusy(false);
    if (!TOOL_VIEWS.includes(state.currentView) && state.currentView !== "homepage") {
      await loadArticles(true, 1);
    }
    return;
  }

  if (query.length < MIN_GLOBAL_SEARCH_LENGTH) {
    if (force) showToast(`Enter at least ${MIN_GLOBAL_SEARCH_LENGTH} characters to search intelligence.`, "info");
    return;
  }

  if (TOOL_VIEWS.includes(state.currentView) && state.currentView !== "docs") {
    return;
  }

  try {
    setHeaderSearchBusy(true, state.currentView === "homepage" || state.currentView === "docs"
      ? "Routing semantic search..."
      : "Searching restored intelligence...");

    if (state.currentView === "homepage" || state.currentView === "docs") {
      await routeHomepageSearch(query);
      return;
    }

    await fetchSemanticGuide(query);
    if (!TOOL_VIEWS.includes(state.currentView)) {
      await loadArticles(true, 1);
    }
  } catch (error) {
    console.error(error);
    state.semanticSearch = null;
    renderSearchInsight();
    if (state.currentView === "homepage" || state.currentView === "docs") {
      await switchView("all");
      return;
    }
    if (!TOOL_VIEWS.includes(state.currentView)) {
      await loadArticles(true, 1);
    }
  } finally {
    setHeaderSearchBusy(false);
  }
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
        <span class="count-chip">Compromised <strong>${country.defacement_count}</strong></span>
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
      <div class="map-tooltip-stat-grid">
        <span class="map-tooltip-stat">Leaks <strong>${escapeHtml(String(stats.leak_count || 0))}</strong></span>
        <span class="map-tooltip-stat">Total <strong>${escapeHtml(String(stats.total || 0))}</strong></span>
      </div>
    </div>
  `;
}

function getCountryDisplayName(code, tooltip) {
  const normalizedCode = String(code || "").toUpperCase();
  const tooltipText = typeof tooltip?.text === "function" ? String(tooltip.text() || "").trim() : "";
  if (tooltipText) return tooltipText;
  try {
    const displayNames = new Intl.DisplayNames(["en"], { type: "region" });
    return displayNames.of(normalizedCode) || normalizedCode;
  } catch (_) {
    return normalizedCode || "Unknown Country";
  }
}

function syncMapRegionTitles() {
  const displayNames = (() => {
    try {
      return new Intl.DisplayNames(["en"], { type: "region" });
    } catch (_) {
      return null;
    }
  })();
  document.querySelectorAll("#worldMap [data-code], #worldMap .jvm-region").forEach(region => {
    const code = String(region.getAttribute("data-code") || region.dataset?.code || "").toUpperCase();
    if (!code) return;
    const stats = state.countryStatsByCode[code];
    let displayName = "";
    try {
      displayName = displayNames?.of(code) || "";
    } catch (_) {
      displayName = "";
    }
    const countryName = stats?.name || displayName || code;
    const total = Number(stats?.total || 0);
    const titleText = total
      ? `${countryName} - ${total} tracked activity item${total === 1 ? "" : "s"}`
      : countryName;

    region.setAttribute("aria-label", titleText);
    region.setAttribute("title", titleText);
    let titleNode = Array.from(region.children || []).find(child => child.tagName?.toLowerCase() === "title");
    if (!titleNode) {
      titleNode = document.createElementNS("http://www.w3.org/2000/svg", "title");
      region.insertBefore(titleNode, region.firstChild || null);
    }
    titleNode.textContent = titleText;
  });
}

function getMapRegionFromTarget(target) {
  const region = target?.closest?.("[data-code], .jvm-region");
  if (!region || !$("worldMap")?.contains(region)) return null;
  return region;
}

function getMapRegionCode(region) {
  return String(
    region?.getAttribute?.("data-code")
    || region?.dataset?.code
    || region?.getAttribute?.("id")
    || ""
  ).replace(/^.*-/, "").toUpperCase();
}

function mapTooltipTextForCode(code) {
  const stats = state.countryStatsByCode?.[code];
  const name = stats?.name || getCountryDisplayName(code);
  const total = Number(stats?.total || 0);
  if (!total) return { name, meta: "No mapped activity" };
  return {
    name,
    meta: `Total ${total} | Leaks ${Number(stats?.leak_count || 0)} | Compromised ${Number(stats?.defacement_count || 0)}`
  };
}

function showMapHoverTooltip(event, code) {
  const shell = document.querySelector(".map-shell");
  if (!shell || !code) return;

  let tooltip = $("mapHoverTooltip");
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.id = "mapHoverTooltip";
    tooltip.className = "map-hover-tooltip";
    shell.appendChild(tooltip);
  }

  const payload = mapTooltipTextForCode(code);
  tooltip.innerHTML = `
    <div class="map-hover-tooltip-title">${escapeHtml(payload.name || code)}</div>
    <div class="map-hover-tooltip-meta">${escapeHtml(payload.meta)}</div>
  `;

  const shellRect = shell.getBoundingClientRect();
  const tooltipRect = tooltip.getBoundingClientRect();
  const nextLeft = event.clientX - shellRect.left + 16;
  const nextTop = event.clientY - shellRect.top + 16;
  const clampedLeft = Math.min(Math.max(12, nextLeft), Math.max(12, shellRect.width - tooltipRect.width - 12));
  const clampedTop = Math.min(Math.max(12, nextTop), Math.max(12, shellRect.height - tooltipRect.height - 12));

  tooltip.style.left = `${clampedLeft}px`;
  tooltip.style.top = `${clampedTop}px`;
  tooltip.classList.add("is-visible");
}

function hideMapHoverTooltip() {
  $("mapHoverTooltip")?.classList.remove("is-visible");
}

function initMapHoverTooltip() {
  const container = $("worldMap");
  if (!container || container.dataset.hoverTooltipReady === "1") return;
  container.dataset.hoverTooltipReady = "1";

  container.addEventListener("mousemove", event => {
    const region = getMapRegionFromTarget(event.target);
    const code = getMapRegionCode(region);
    if (!code) {
      hideMapHoverTooltip();
      return;
    }
    showMapHoverTooltip(event, code);
  });

  container.addEventListener("mouseleave", hideMapHoverTooltip);
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
  const shell = document.querySelector(".globe-shell") || document.querySelector(".map-shell");

  if (!tag || !shell || !country) {
    hideMapSpotlightTag();
    return;
  }

  tag.innerHTML = `
    <div class="map-spotlight-tag-label">Active Country</div>
    <div class="map-spotlight-tag-title">${escapeHtml(country.name || "Unknown Country")}</div>
    <div class="map-spotlight-stat-grid">
      <span class="map-spotlight-stat">Leaks <strong>${escapeHtml(String(country.leak_count || 0))}</strong></span>
      <span class="map-spotlight-stat">Compromised <strong>${escapeHtml(String(country.defacement_count || 0))}</strong></span>
    </div>
    <div class="map-spotlight-tag-meta">Total tracked activity: ${escapeHtml(String(country.total || 0))}</div>
  `;
  tag.classList.remove("hidden");
  tag.style.left = "";
  tag.style.top = "";
  tag.style.right = "1rem";
  tag.style.bottom = "1rem";
  tag.style.transform = "none";
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

function getMapRegionStyle(country, spotlight = false) {
  const leakCount = Number(country?.leak_count || 0);
  const defacementCount = Number(country?.defacement_count || 0);
  const total = Number(country?.total || 0);

  if (spotlight) {
    return {
      fill: "#ff4f73",
      stroke: "#ffe7ed",
      strokeWidth: "1.4",
      filter: "drop-shadow(0 0 18px rgba(255, 79, 115, 0.95))"
    };
  }

  if (leakCount > 0 || defacementCount > 0 || total > 0) {
    const fill = leakCount >= 200
      ? "#ff5f82"
      : leakCount >= 80
        ? "#df3f61"
        : leakCount > 0
          ? "#b32d46"
          : "#8d2337";

    return {
      fill,
      stroke: "rgba(255, 145, 168, 0.44)",
      strokeWidth: "0.95",
      filter: "drop-shadow(0 0 10px rgba(255, 79, 115, 0.22))"
    };
  }

  return {
    fill: "#121a28",
    stroke: "#242f44",
    strokeWidth: "0.5",
    filter: ""
  };
}

function applyMapRegionVisual(code, country, spotlight = false) {
  const element = getMapRegionElement(code);
  if (!element || !element.style || typeof element.style.setProperty !== "function") return;
  const style = getMapRegionStyle(country, spotlight);
  if (element.classList) {
    element.classList.toggle("map-region-affected", !spotlight && Number(country?.total || 0) > 0);
    element.classList.toggle("map-region-spotlight", spotlight);
  }
  element.style.setProperty("fill", style.fill, "important");
  element.style.setProperty("stroke", style.stroke, "important");
  element.style.setProperty("stroke-width", style.strokeWidth, "important");
  if (style.filter) {
    element.style.setProperty("filter", style.filter, "important");
  } else {
    element.style.removeProperty("filter");
  }
  element.style.setProperty("opacity", "1", "important");
}

function syncAffectedRegions(countries) {
  (countries || []).forEach(country => {
    applyMapRegionVisual(country.code, country, false);
  });
}

function setMapSpotlight(code) {
  if (!code) return;
  const country = state.countryStatsByCode[code];
  if (!country) return;

  if (state.mapSpotlightCode && state.mapSpotlightCode !== code) {
    const previousCountry = state.countryStatsByCode[state.mapSpotlightCode];
    applyMapRegionVisual(state.mapSpotlightCode, previousCountry, false);
  }

  applyMapRegionVisual(code, country, true);

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

function setHeatmapShellState(mode = "loading", message = "Loading live impact map...") {
  const container = $("worldMap");
  if (!container) return;
  if (mode === "ready") {
    return;
  }

  const safeMessage = escapeHtml(message);
  container.innerHTML = `
    <div class="hm-map-loading hm-map-loading-inline" data-mode="${escapeHtml(mode)}">
      <div class="hm-spinner"></div>
      <div>${safeMessage}</div>
    </div>
  `;
}

async function initHeatmap() {
  setHeatmapShellState("loading", "Loading live impact map...");
  try {
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
    if ($("statCountryCount")) $("statCountryCount").textContent = String(payload.summary?.affected_countries || countries.length || 0);
    if ($("statLeakCoverageCount")) $("statLeakCoverageCount").textContent = String(payload.summary?.leak_items_with_country || 0);
    if ($("statDefaceCoverageCount")) $("statDefaceCoverageCount").textContent = String(payload.summary?.defacement_items_with_country || 0);

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
    initMapHoverTooltip();

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
            name: getCountryDisplayName(code, tooltip),
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
      syncMapRegionTitles();
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
  } catch (error) {
    console.error(error);
    setHeatmapShellState("error", "Impact map could not be loaded.");
  }
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

function mediaSourcesAttribute(sources) {
  return escapeHtml(JSON.stringify(Array.isArray(sources) ? sources : []));
}

function readMediaSourcesFromImage(img) {
  if (!img) return [];
  try {
    const sources = JSON.parse(img.getAttribute("data-media-sources") || "[]");
    return Array.isArray(sources) ? sources.filter(Boolean) : [];
  } catch {
    return [];
  }
}

function markCardMediaLoaded(img) {
  img?.closest(".card-media")?.classList.remove("image-failed");
}

function advanceCardMedia(img) {
  if (!img) return;
  const sources = readMediaSourcesFromImage(img);
  const currentIndex = Number(img.getAttribute("data-media-index") || "0");
  const nextIndex = Number.isFinite(currentIndex) ? currentIndex + 1 : 1;
  if (sources[nextIndex]) {
    img.setAttribute("data-media-index", String(nextIndex));
    img.src = sources[nextIndex];
    return;
  }
  img.closest(".card-media")?.classList.add("image-failed");
}

window.advanceCardMedia = advanceCardMedia;
window.markCardMediaLoaded = markCardMediaLoaded;

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
  const aiSummary = normalizePreviewText(item.ai_summary || buildLocalAiSummary(item), buildLocalAiSummary(item));
  const collectedAt = formatDate(item.scraped_at || item.date);
  const media = collectDetailMedia(item);
  const thumbnail = media[0];
  if (thumbnail) {
    card.classList.add("has-media");
  }

  card.innerHTML = `
    <div class="card-media ${thumbnail ? "" : "image-failed"}">
      ${thumbnail
        ? `<img src="${escapeHtml(thumbnail)}" data-media-sources="${mediaSourcesAttribute(media)}" data-media-index="0" alt="${escapeHtml(title)} evidence screenshot" loading="lazy" referrerpolicy="no-referrer" onerror="advanceCardMedia(this)" onload="markCardMediaLoaded(this)" />`
        : ""}
      <div class="card-media-fallback">
        <span>${escapeHtml((item.source_type || "intel").toUpperCase())}</span>
        <strong>${escapeHtml(sourceSite || sourceLabel || "Source preview")}</strong>
      </div>
    </div>
    <div class="card-header">
      <span class="card-source">${escapeHtml(item.source_type || "intel")}</span>
      <span class="card-status">${escapeHtml(statusLabel)}</span>
    </div>
    <h3 class="card-title">${escapeHtml(title)}</h3>
    <p class="card-desc">${escapeHtml(description)}</p>
    <div class="card-chip-row">${metaChips || "<span class='card-chip'>Details <strong>Open full record</strong></span>"}</div>
    <div class="card-actions">
      <button class="card-action-btn" type="button" data-card-action="detail">Inspect</button>
      <button class="card-action-btn ghost" type="button" data-card-action="summary" aria-expanded="false">AI Summary</button>
      <button class="card-action-btn ghost" type="button" data-card-action="translate">Translate</button>
      ${categories ? `<span class="card-category-inline">${categories}</span>` : ""}
    </div>
    <div class="card-summary-panel hidden" aria-hidden="true">
      <div class="card-summary-title">AI Summary</div>
      <p class="card-summary-text">${escapeHtml(aiSummary)}</p>
    </div>
    <div class="card-footer">
      <span>${escapeHtml(footerSource)}</span>
      <span>${escapeHtml(collectedAt)}</span>
    </div>
  `;
  return card;
}

function setCardSummaryExpanded(card, expanded) {
  if (!card) return;
  const panel = card.querySelector(".card-summary-panel");
  const button = card.querySelector('[data-card-action="summary"]');
  if (!panel || !button) return;
  card.classList.toggle("summary-open", expanded);
  panel.classList.toggle("hidden", !expanded);
  panel.setAttribute("aria-hidden", expanded ? "false" : "true");
  button.setAttribute("aria-expanded", expanded ? "true" : "false");
  button.textContent = expanded ? "Hide Summary" : "AI Summary";
}

function toggleCardSummary(card) {
  if (!card) return;
  const shouldExpand = !card.classList.contains("summary-open");
  document.querySelectorAll(".intel-card.summary-open").forEach(otherCard => {
    if (otherCard !== card) {
      setCardSummaryExpanded(otherCard, false);
    }
  });
  setCardSummaryExpanded(card, shouldExpand);
}

function setFeedState(title, message = "", mode = "idle") {
  const emptyState = $("emptyState");
  const titleEl = emptyState.querySelector(".empty-state-title");
  const bodyEl = emptyState.querySelector("p");
  titleEl.textContent = title;
  bodyEl.textContent = message;
  emptyState.dataset.mode = mode;
}

async function loadArticles(reset = false, targetPage = 1) {
  renderSearchInsight();
  if (state.feedAbortController) {
    state.feedAbortController.abort();
  }
  const controller = new AbortController();
  state.feedAbortController = controller;
  const requestedPage = Math.max(1, Number(targetPage) || 1);
  const snapshotKey = buildFeedSnapshotKey(requestedPage);

  if (reset) {
    state.feedPage = requestedPage;
  }

  $("feedSummary").textContent = `Loading ${humanViewName(state.activeTab)}...`;
  clearPagination("feedPagination");
  if (reset) {
    const snapshot = state.feedSnapshots.get(snapshotKey);
    const hasFreshSnapshot = isFeedSnapshotFresh(snapshot) && Array.isArray(snapshot.items) && snapshot.items.length;
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
    const data = await apiFetch(buildFeedPath(PAGE_SIZE, requestedPage), false, { signal: controller.signal });
    if (state.feedAbortController !== controller) return;

    const items = data.items || [];
    const grid = $("cardsGrid");
    const totalItems = Number(data.total || 0);
    const metrics = getPaginationMetrics(totalItems, requestedPage);

    if (requestedPage > 1 && totalItems > 0 && items.length === 0 && metrics.totalPages && requestedPage > metrics.totalPages) {
      await loadArticles(true, metrics.totalPages);
      return;
    }

    if (reset && items.length === 0) {
      grid.innerHTML = "";
      const noResultsMessage = countActiveFeedFilters()
        ? "No records matched the current search and feed filters. Try widening the date range or changing the topic."
        : "Try a different search term or switch to another intelligence stream.";
      setFeedState("No matching records", noResultsMessage, "empty");
      $("emptyState").classList.remove("hidden");
      clearPagination("feedPagination");
      $("feedSummary").textContent = "0 results loaded";
      state.feedPage = 1;
      state.offset = 0;
      state.total = 0;
      renderSearchInsight();
      return;
    }

    $("emptyState").classList.add("hidden");
    grid.innerHTML = "";
    items.forEach(item => {
      state.detailCache.set(item.aid, item);
      grid.appendChild(renderCard(item));
    });

    state.feedPage = requestedPage;
    state.offset = metrics.startIndex;
    state.total = totalItems || items.length;
    storeFeedSnapshot(currentSourceType(), $("searchInput").value.trim(), getActiveFeedFilters(), requestedPage, items, state.total);

    const visibleEnd = items.length ? Math.min(metrics.startIndex + items.length, state.total) : metrics.endLabel;
    const filterPrefix = countActiveFeedFilters() ? "Filtered • " : "";
    $("feedSummary").textContent = `${filterPrefix}Page ${metrics.page} of ${Math.max(metrics.totalPages, 1)} • Showing ${metrics.startLabel}-${visibleEnd} of ${state.total} records for ${humanViewName(state.activeTab)}`;
    renderPagination("feedPagination", "feed", {
      ...metrics,
      endLabel: visibleEnd
    });
    renderSearchInsight();
    setLastUpdated();
    await maybeApplyActiveTranslation("view");
    if (!$("searchInput").value.trim() && countActiveFeedFilters() === 0 && requestedPage === 1) {
      warmFeedSnapshots().catch(error => console.error(error));
    }
  } catch (error) {
    if (error.name === "AbortError") return;
    console.error(error);
    $("cardsGrid").innerHTML = "";
    setFeedState("Feed unavailable", error.message || "The feed request failed. Please try again.", "error");
    $("emptyState").classList.remove("hidden");
    clearPagination("feedPagination");
    $("feedSummary").textContent = "Feed request failed";
    renderSearchInsight();
  } finally {
    if (state.feedAbortController === controller) {
      state.feedAbortController = null;
    }
  }
}

async function fetchStats() {
  const statBindings = {
    statTotalCount: "display_total",
    statNewsCount: "news",
    statLeakCount: "leak",
    statDefaceCount: "defacement",
    statExploitCount: "exploit",
    statSocialCount: "social",
    statVulnCount: "api",
    statCountryCount: "affected_countries",
    statLeakCoverageCount: "leak_coverage",
    statDefaceCoverageCount: "defacement_coverage",
    statCredentialCount: "credentials",
    statCredentialDatasetCount: "credential_datasets",
    statConfidentialCount: "confidential"
  };

  Object.keys(statBindings).forEach(id => {
    const el = $(id);
    if (el) {
      el.closest(".stat-pill")?.setAttribute("data-state", "loading");
    }
  });

  try {
    const data = await apiFetch("/stats");
    const counts = data.counts || data || {};
    state.latestStats = counts;

    Object.entries(statBindings).forEach(([id, key]) => {
      const el = $(id);
      if (!el) return;
      const rawValue = key === "display_total" ? (counts.display_total ?? counts.total) : counts[key];
      const value = Number(rawValue || 0);
      el.textContent = Number.isFinite(value) ? String(value) : "0";
      const card = el.closest(".stat-pill");
      if (card) {
        card.setAttribute("data-state", value > 0 ? "ready" : "empty");
      }
    });
  } catch (error) {
    Object.keys(statBindings).forEach(id => {
      const el = $(id);
      if (!el) return;
      el.textContent = "0";
      el.closest(".stat-pill")?.setAttribute("data-state", "error");
    });
    throw error;
  }
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
  if (text.startsWith("/")) return text;
  if (text.startsWith("http://") || text.startsWith("https://")) return text;
  if (looksLikeBase64Image(text)) {
    return `data:image/jpeg;base64,${text.replace(/\s+/g, "")}`;
  }
  return "";
}

function absoluteAssetUrl(src) {
  const text = String(src || "").trim();
  if (!text || text.startsWith("data:")) return text;
  try {
    return new URL(text, window.location.origin).href;
  } catch {
    return text;
  }
}

function generatedScreenshotSource(item) {
  const aid = String(item?.aid || "").trim();
  return aid ? `/feed-screenshot?aid=${encodeURIComponent(aid)}&capture=real&v=2` : "";
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
    ...normalizeStringList(raw.m_extra && raw.m_extra.og_image),
    generatedScreenshotSource(item)
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

function getDetailFacts(item) {
  const sourceLabel = firstNonEmpty(item.source_label, item.source, "Unknown");
  const sourceSite = hostFromValue(item.source_site || item.seed_url || item.source);
  const website = firstNonEmpty(hostFromValue(item.website_host || item.website), item.website, "Unavailable");
  const country = (item.country_names || []).join(", ") || "Unmapped";
  const discovered = formatShortDate(item.discovered_at) || "Unavailable";
  const attackDate = formatShortDate(item.attack_date) || "Unavailable";
  const collectedAt = item.collected_at ? formatDate(item.collected_at) : "Unavailable";
  return [
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
}

function renderFacts(item) {
  const facts = getDetailFacts(item);
  $("modalFactGrid").innerHTML = facts.map(([label, value]) => `
    <div class="fact-item">
      <span class="fact-label">${escapeHtml(label)}</span>
      <span class="fact-value">${escapeHtml(value)}</span>
    </div>
  `).join("");
}

function buildLocalAiSummary(item) {
  const sourceLabel = firstNonEmpty(item.source_label, item.source_site, item.source, item.source_type || "source");
  const tagText = Array.isArray(item.categories)
    ? item.categories
        .map(category => String(category?.label || "").trim())
        .filter(Boolean)
        .slice(0, 3)
        .join(", ")
    : "";
  const entities = normalizeEntities(item.entities)
    .map(entity => String(entity?.text || "").trim())
    .filter(Boolean)
    .slice(0, 3);
  const countries = Array.isArray(item.country_names) ? item.country_names.slice(0, 2).join(", ") : "";
  const base = normalizePreviewText(item.summary || item.description || "No summary available.", "No summary available.");
  const summaryLine = base.endsWith(".") ? base : `${base}.`;
  const contextParts = [];
  if (tagText) contextParts.push(`Themes: ${tagText}`);
  if (entities.length) contextParts.push(`Key entities: ${entities.join(", ")}`);
  if (countries) contextParts.push(`Geography: ${countries}`);
  const contextLine = contextParts.length ? ` ${contextParts.join(" | ")}.` : "";
  return `DarkPulse AI summary: this ${item.source_type || "intelligence"} item from ${sourceLabel} highlights ${summaryLine}${contextLine}`;
}

function renderDetail(item) {
  state.currentDetailItem = item;
  $("modalSource").textContent = (item.source_type || "intel").toUpperCase();
  $("modalTopTag").textContent = item.source_label || item.top_tag || (item.country_names || []).join(", ") || "Live Record";
  $("modalTitle").textContent = normalizePreviewText(item.title || "Untitled", "Untitled");
  $("modalMeta").innerHTML = `
    <span>AID: ${escapeHtml(item.aid || "")}</span>
    <span>Date: ${escapeHtml(formatDate(item.scraped_at || item.date))}</span>
    <span>Source URL: ${escapeHtml(item.url || item.website || item.seed_url || "Unavailable")}</span>
  `;

  renderFacts(item);
  $("modalAiSummary").textContent = normalizePreviewText(item.ai_summary || buildLocalAiSummary(item), buildLocalAiSummary(item));
  $("modalSummary").textContent = normalizePreviewText(item.description || item.summary || "No description available.", "No description available.");

  const media = collectDetailMedia(item);
  $("modalMediaSection").classList.toggle("hidden", media.length === 0);
  $("modalMediaGallery").innerHTML = media.map((src, index) => `
    <button type="button" class="modal-media-card" data-media-src="${escapeHtml(src)}" data-media-title="${escapeHtml(item.title || "Evidence image")}">
      <img src="${escapeHtml(src)}" alt="${escapeHtml((item.title || "intel-record") + ` screenshot ${index + 1}`)}" loading="lazy" referrerpolicy="no-referrer" onerror="this.closest('.modal-media-card')?.classList.add('image-failed')" />
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

function buildDetailExportPayload(item) {
  const evidenceLinks = collectEvidenceLinks(item);
  const media = collectDetailMedia(item);
  const entities = normalizeEntities(item.entities).map(entity => `${entity.label || "entity"}: ${entity.text || ""}`);
  const categories = (Array.isArray(item.categories) ? item.categories : []).map(category => {
    const score = typeof category.score === "number" ? ` (${Math.round(category.score * 100)}%)` : "";
    return `${category.label || "intel"}${score}`;
  });
  const title = normalizePreviewText(item.title || "Untitled", "Untitled");

  return {
    filenameBase: `${item.source_type || "intel"}-${item.aid || title}`,
    kicker: "DarkPulse Article Export",
    title,
    subtitle: normalizePreviewText(item.description || item.summary || "No description available.", "No description available."),
    metadata: [
      ["AID", item.aid || "-"],
      ["Source Type", item.source_type || "intel"],
      ["Source", firstNonEmpty(item.source_label, item.source, "Unavailable")],
      ["Date", formatDate(item.scraped_at || item.date)],
      ["Source URL", item.url || item.website || item.seed_url || "Unavailable"]
    ],
    sections: [
      media.length ? {
        title: "Evidence Screenshots",
        images: media.slice(0, 4).map((src, index) => ({
          src,
          label: `${title} screenshot ${index + 1}`
        }))
      } : null,
      { title: "Key Facts", fields: getDetailFacts(item) },
      { title: "AI Summary", text: normalizePreviewText(item.ai_summary || buildLocalAiSummary(item), buildLocalAiSummary(item)) },
      evidenceLinks.length ? { title: "Evidence Links", list: evidenceLinks } : null,
      entities.length ? { title: "Entities", list: entities } : null,
      categories.length ? { title: "Categories", list: categories } : null,
      { title: "Raw JSON", pre: JSON.stringify(item.raw || item, null, 2) }
    ].filter(Boolean),
    data: item.raw || item
  };
}

function buildPakdbExportPayload() {
  const entry = state.scanExports.pakdb || { query: "", items: [] };
  if (!entry.items.length) throw new Error("Run a national identity search before exporting.");

  return {
    filenameBase: `national-identity-${entry.query || "lookup"}`,
    kicker: "DarkPulse Scan Export",
    title: "National Identity Search",
    subtitle: `Query: ${entry.query || "-"}`,
    metadata: [
      ["Query", entry.query || "-"],
      ["Results", entry.items.length],
      ["Exported", formatDate(new Date().toISOString())]
    ],
    sections: [
      {
        title: "Result Set",
        cards: entry.items.map((item, index) => ({
          title: item.name || `Record ${index + 1}`,
          subtitle: item.mobile || item.cnic || "National identity result",
          text: item.address || "Address unavailable",
          fields: [
            ["CNIC", item.cnic || "-"],
            ["Mobile", item.mobile || "-"]
          ]
        }))
      }
    ],
    data: {
      query: entry.query || "",
      count: entry.items.length,
      results: entry.items
    }
  };
}

async function fetchAllCredentialResultsForExport() {
  const base = state.scanExports.credential;
  const query = state.credentialPager.query || base?.query || "";
  if (!query) throw new Error("Run a credential search before exporting.");

  const totalPages = Math.max(1, Number(state.credentialPager.totalPages || base?.total_pages || 1));
  const pages = [];
  for (let page = 1; page <= totalPages; page += 1) {
    if (base && Number(base.page || 1) === page && Array.isArray(base.results)) {
      pages.push(base);
      continue;
    }
    const pageData = await apiFetch("/credentials/search", false, {
      method: "POST",
      body: {
        query,
        page,
        limit: PAGE_SIZE
      }
    });
    pages.push(pageData);
  }

  const allResults = pages.flatMap(page => Array.isArray(page.results) ? page.results : []);
  const sample = pages.find(Boolean) || {};
  return {
    ...sample,
    query,
    page: 1,
    per_page: PAGE_SIZE,
    total_pages: totalPages,
    count: Number(sample.count || allResults.length || 0),
    results: allResults
  };
}

async function buildCredentialExportPayload() {
  const data = await fetchAllCredentialResultsForExport();
  const results = Array.isArray(data.results) ? data.results : [];
  if (!results.length) throw new Error("No credential results are available for export.");
  const exportedAt = new Date().toISOString();

  return {
    filenameBase: `credential-checker-${data.query || "results"}`,
    kicker: "DarkPulse Exposure Export",
    title: "Credential Checker",
    subtitle: `Redacted exposure review for ${data.query || "-"}`,
    metadata: [
      ["Query", data.query || "-"],
      ["Results", data.count || results.length],
      ["Hosts", data.hosts_count || 0],
      ["Matched Files", data.aggregated_count || 0],
      ["Exported", formatDate(exportedAt)],
      ["Sensitive Values", "Passwords are masked by default"]
    ],
    sections: [
      {
        title: "Exposure Matches",
        cards: results.map((item, index) => ({
          title: item.credential_identifier || `Match ${index + 1}`,
          subtitle: item.domain_host || item.source_domain || "Exposure record",
          text: maskCredentialRawTrace(item.raw_trace, item.password),
          tags: formatCredentialTags(item.metadata_tags),
          fields: [
            ["Username / Email", item.email_username || item.credential_identifier || "-"],
            ["Domain", item.domain || "-"],
            ["Date", item.date || "-"],
            ["Source Domain", item.source_domain || "-"],
            ["Channel", item.channel || "-"],
            ["Year", item.year || "-"],
            ["File Type", item.file_type || "-"],
            ["IP", item.ip || "-"],
            ["Password", maskCredentialSecret(item.password)],
            ["Raw Trace", maskCredentialRawTrace(item.raw_trace, item.password) || "-"],
            ["Source File", item.source_file || "-"]
          ]
        }))
      }
    ],
    data
  };
}

function buildConfidentialExportPayload() {
  const data = state.scanExports.confidential;
  const results = Array.isArray(data?.results) ? data.results : [];
  if (!results.length) throw new Error("Run a confidential data analysis before exporting.");

  return {
    filenameBase: `confidential-masked-analysis-${data.analysis_id || "results"}`,
    kicker: "DarkPulse Defensive Export",
    title: "Confidential Data Analysis",
    subtitle: "Masked local file analysis for potential exposed payment-card-like and credential indicators.",
    metadata: [
      ["Analysis ID", data.analysis_id || "-"],
      ["Findings", results.length],
      ["Elapsed", `${Number(data.elapsed_ms || 0)} ms`],
      ["Disclaimer", data.disclaimer || "Sensitive values are masked and raw secrets are never displayed or stored."]
    ],
    sections: [
      {
        title: "Masked Findings",
        cards: results.map(item => ({
          title: `${item.detected_type || "Finding"} • ${item.record_id || "-"}`,
          subtitle: `${item.risk_level || "Risk"} • ${item.detection_confidence || "Confidence"} confidence`,
          text: item.context_snippet || "",
          tags: [item.status || "New", item.card_brand_guess || "N/A"].filter(Boolean),
          fields: [
            ["Record ID", item.record_id || "-"],
            ["Detected Type", item.detected_type || "-"],
            ["Masked Value", item.masked_value || "-"],
            ["Card Brand Guess", item.card_brand_guess || "N/A"],
            ["Expiry Date", getConfidentialParsedField(item, "expiry_date")],
            ["Reason", item.reason_for_detection || "-"],
            ["Timestamp", item.timestamp_of_analysis || "-"],
            ["Analyst Notes", item.analyst_notes || "-"],
            ...getConfidentialParsedFieldRows(item)
          ]
        }))
      }
    ],
    data: {
      ...data,
      results
    }
  };
}

function buildPlaystoreExportPayload() {
  const entry = state.scanExports.playstore || { query: "", items: [] };
  const items = Array.isArray(entry.items) ? entry.items : [];
  if (!items.length) throw new Error("Run a Playstore scan before exporting.");

  return {
    filenameBase: `playstore-scan-${entry.query || "results"}`,
    kicker: "DarkPulse Scan Export",
    title: "Playstore Scanner",
    subtitle: `Query: ${entry.query || "-"}`,
    metadata: [
      ["Query", entry.query || "-"],
      ["Results", items.length],
      ["Exported", formatDate(new Date().toISOString())]
    ],
    sections: [
      {
        title: "Result Set",
        cards: items.map(item => ({
          title: item.app_name || "Unknown Application",
          subtitle: item.source || item.network || "clearnet",
          text: normalizePreviewText((item.description || "").trim() || "Description not available from the source page.", "Description not available from the source page."),
          fields: [
            ["Package", item.package_id || "N/A"],
            ["Updated", item.latest_date || "N/A"],
            ["Size", item.apk_size || "N/A"],
            ["Type", item.content_type || "apk"],
            ["Publisher", item.publisher || "N/A"],
            ["Network", item.network || "clearnet"],
            ["Version", item.version || "Unknown Version"],
            ["Download Link", item.download_link || "-"],
            ["Page URL", item.url || "-"]
          ]
        }))
      }
    ],
    data: {
      query: entry.query || "",
      count: items.length,
      results: items
    }
  };
}

function buildSoftwareExportPayload() {
  const entry = state.scanExports.software || { query: "", items: [] };
  const items = Array.isArray(entry.items) ? entry.items : [];
  if (!items.length) throw new Error("Run a PC game scan before exporting.");

  return {
    filenameBase: `pc-game-scan-${entry.query || "results"}`,
    kicker: "DarkPulse Scan Export",
    title: "PC Game Scan",
    subtitle: `Query: ${entry.query || "-"}`,
    metadata: [
      ["Query", entry.query || "-"],
      ["Results", items.length],
      ["Exported", formatDate(new Date().toISOString())]
    ],
    sections: [
      {
        title: "Result Set",
        cards: items.map(item => ({
          title: item.app_name || item.name || "Software result",
          subtitle: item.network || "clearnet",
          text: item.mod_features || "No additional feature notes.",
          fields: [
            ["Package Id", item.package_id || "-"],
            ["App URL", item.app_url || item.url || "-"],
            ["Version", item.version || "-"],
            ["Content Type", item.content_type || "pc_game"],
            ["Download Link", item.download_link || "-"],
            ["Size", item.apk_size || "-"],
            ["Latest Date", item.latest_date || "-"]
          ]
        }))
      }
    ],
    data: {
      query: entry.query || "",
      count: items.length,
      results: items
    }
  };
}

function buildSeoExportPayload() {
  const data = state.scanExports.seo;
  if (!data) throw new Error("Run an SEO scan before exporting.");

  const audits = Object.keys(data.audits || {}).map(key => data.audits[key]);
  const aiSuggestions = String(data.ai_suggestions || "")
    .split(/\n+/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => line.replace(/^[-*•]\s*/, "").replace(/^\d+[.)]\s*/, "").trim())
    .filter(Boolean);

  return {
    filenameBase: `seo-report-${data.url || "report"}`,
    kicker: "DarkPulse Scan Export",
    title: "SEO Analysis Report",
    subtitle: data.url || "Website posture report",
    metadata: [
      ["Target URL", data.url || "-"],
      ["Host", (() => { try { return new URL(data.url).hostname; } catch { return "-"; } })()],
      ["SEO Health Grade", data.seoHealthGrade || data.grade || "-"],
      ["Scan Confidence", data.scanConfidenceGrade || "-"],
      ["Scan Mode", data.scanModeUsed || "-"],
      ["Raw Scan Available", data.rawScanAvailable ? "Yes" : "No"],
      ["Rendered Scan Available", data.renderedScanAvailable ? "Yes" : "No"],
      ["Findings", audits.length],
      ["Scanned On", data.timestamp || "-"]
    ],
    sections: [
      data.crawlerVisibility ? {
        title: "Crawler Visibility",
        text: data.crawlerVisibility.reason || "",
        fields: [
          ["Level", data.crawlerVisibility.level || "-"],
          ["Raw Body Text", data.crawlerVisibility.signals?.bodyTextLength ?? "-"],
          ["Raw Scripts", data.crawlerVisibility.signals?.scriptCount ?? "-"],
          ["Rendered Body Text", data.crawlerVisibility.signals?.renderedBodyTextLength ?? "-"],
          ["JS Heavy Likely", data.crawlerVisibility.signals?.jsHeavyLikely ? "Yes" : "No"],
          ["Access Limited", data.crawlerVisibility.signals?.accessLimitedSignals ? "Yes" : "No"],
          ["Bot Protection Likely", data.crawlerVisibility.signals?.botProtectionLikely ? "Yes" : "No"]
        ]
      } : null,
      data.ai_message || aiSuggestions.length ? {
        title: "Recommendations",
        text: data.ai_message || "",
        list: aiSuggestions
      } : null,
      {
        title: "Audit Findings",
        cards: audits.map((audit, index) => ({
          title: audit.title || `Audit ${index + 1}`,
          subtitle: `Score ${audit.score ?? "-"} | ${audit.status || "-"}`,
          text: [audit.description, audit.note].filter(Boolean).join(" "),
          fields: [
            ["Audit Id", audit.id || index + 1],
            ["Confidence", audit.confidence || "-"],
            ["Evidence Source", audit.evidenceSource || "-"],
            ["Evidence", audit.evidence || "-"],
            ["Recommendation", audit.recommendation || "-"]
          ]
        }))
      }
    ].filter(Boolean),
    data
  };
}

function buildRepoExportPayload() {
  const data = state.scanExports.repo;
  if (!data) throw new Error("Run a repository scan before exporting.");

  const summary = data.summary || {};
  const vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities.map(item => ({ ...item, finding_type: "Vulnerability" })) : [];
  const secrets = Array.isArray(data.secrets) ? data.secrets.map(item => ({ ...item, finding_type: "Secret" })) : [];
  const misconfigs = Array.isArray(data.misconfigs) ? data.misconfigs.map(item => ({ ...item, finding_type: "Misconfiguration" })) : [];
  const findings = [...misconfigs, ...secrets, ...vulnerabilities];

  return {
    filenameBase: `repository-scan-${data.query || summary.repo_name || "report"}`,
    kicker: "DarkPulse Scan Export",
    title: "Repository Scan Report",
    subtitle: data.query || summary.repo_name || "Repository posture summary",
    metadata: [
      ["Target URL", data.query || "-"],
      ["Host", summary.host || "github.com"],
      ["Grade", summary.grade || "-"],
      ["Risk Score", summary.risk_score ?? 0],
      ["Findings", findings.length],
      ["Scanned By", summary.scanned_by || "DarkPulse / Trivy"]
    ],
    sections: [
      Array.isArray(summary.recommendations) && summary.recommendations.length
        ? { title: "Recommendations", list: summary.recommendations }
        : null,
      {
        title: "Findings",
        cards: findings.map((finding, index) => ({
          title: finding.title || `Finding ${index + 1}`,
          subtitle: `${finding.finding_type || "Finding"} • ${finding.severity || "UNKNOWN"}`,
          text: finding.description || finding.snippet || "",
          fields: [
            ["ID", finding.id || "-"],
            ["Severity", finding.severity || "UNKNOWN"],
            ["Confidence", finding.confidence || "-"],
            ["Snippet", finding.snippet || "-"]
          ]
        }))
      }
    ].filter(Boolean),
    data
  };
}

async function resolveExportPayload(target) {
  switch (target) {
    case "detail":
      if (!state.currentDetailItem) throw new Error("Open an article before exporting.");
      return buildDetailExportPayload(state.currentDetailItem);
    case "pakdb":
      return buildPakdbExportPayload();
    case "credential":
      return buildCredentialExportPayload();
    case "confidential":
      return buildConfidentialExportPayload();
    case "playstore":
      return buildPlaystoreExportPayload();
    case "software":
      return buildSoftwareExportPayload();
    case "seo":
      return buildSeoExportPayload();
    case "repo":
      return buildRepoExportPayload();
    default:
      throw new Error("Unsupported export target.");
  }
}

async function handleExportAction(target, format, button) {
  const normalizedFormat = format === "pdf" ? "pdf" : "json";
  const printWindow = normalizedFormat === "pdf" ? createPrintWindowShell() : null;
  setInlineButtonBusy(button, true, normalizedFormat === "pdf" ? "Preparing PDF..." : "Preparing JSON...");

  try {
    const payload = await resolveExportPayload(target);
    if (normalizedFormat === "pdf") {
      exportPayloadAsPdf(payload, printWindow);
      showToast("PDF export opened. Use your browser's save-to-PDF option.", "success");
    } else {
      exportPayloadAsJson(payload);
      showToast("JSON export downloaded.", "success");
    }
  } catch (error) {
    if (printWindow && !printWindow.closed) {
      printWindow.close();
    }
    showToast(error.message || "Export failed.", "error");
  } finally {
    setInlineButtonBusy(button, false, normalizedFormat === "pdf" ? "Preparing PDF..." : "Preparing JSON...");
  }
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
    case "checking":
      return "Checking";
    case "healthy":
      return "Healthy";
    case "blocked":
      return "Blocked";
    case "failed":
      return "Failed";
    case "repaired":
      return "Repaired";
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

function cleanHealingMessage(value = "") {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  if (/BrowserType\.launch: Executable doesn't exist|playwright install|headless_shell/i.test(text)) {
    return "Playwright browser is not installed. Run: playwright install";
  }
  if (/cloudflare|cf-ray|checking your browser|access denied|forbidden|blocked/i.test(text)) {
    return "Target is reachable but appears blocked by Cloudflare or an access-control page.";
  }
  if (/timeout|timed out/i.test(text)) {
    return "Target check timed out. Re-test later or verify network/proxy access.";
  }
  if (text.length > 260) {
    return `${text.slice(0, 257)}...`;
  }
  return text;
}

function healingIssueType(item = {}) {
  const blob = [
    item.status,
    item.live_status,
    item.last_event_message,
    item.message,
    item.skip_reason,
    item.last_error,
    item.target_url,
    item.target_domain,
  ].map(value => String(value || "").toLowerCase()).join(" ");

  if (!item.target_url && !item.target_domain) return "no_url";
  if (/playwright|headless_shell|browser executable|chromium/i.test(blob)) return "playwright";
  if (/cloudflare|blocked|access denied|forbidden/i.test(blob)) return "blocked";
  if (/timeout|timed out/i.test(blob)) return "timeout";
  if (/selector|no match|failed selector/i.test(blob)) return "selector";
  return "";
}

function healingPrimaryStatus(item = {}) {
  const rawStatus = String(item.status || "discovered").toLowerCase();
  const liveStatus = String(item.live_status || "").toLowerCase();
  const issue = healingIssueType(item);

  if (state.healingMonitor.checkModal.scriptId === (item.script_id || item.target_key || "") && state.healingMonitor.checkModal.outcome === "running") {
    return "checking";
  }
  if (issue === "playwright" || rawStatus === "error") return "failed";
  if (issue === "blocked" || liveStatus === "blocked") return "blocked";
  if (rawStatus === "auto_fixed") return "repaired";
  if (rawStatus === "target_unreachable" || rawStatus === "unreachable") return "failed";
  if (rawStatus === "html_changed" || rawStatus === "changed") return "html_changed";
  if (rawStatus === "repair_ready") return "repair_ready";
  if (rawStatus === "no_data") return "needs_review";
  if (rawStatus === "skipped") return "skipped";
  if (rawStatus === "healthy") return "healthy";
  if (rawStatus === "needs_review") return "needs_review";
  return rawStatus || "discovered";
}

function healingSecondaryBadges(item = {}) {
  const badges = [];
  const issue = healingIssueType(item);
  const live = String(item.live_status || "not_checked").toLowerCase();
  const drift = String(item.html_change_status || "not_checked").toLowerCase();
  const selectorScore = item.selector_health_score;

  if (!item.target_url && !item.target_domain) badges.push(["No URL", "no_url"]);
  if (live && live !== "not_checked") badges.push([formatHealingLiveStatus(live), live]);
  if (issue === "playwright") badges.push(["Playwright Missing", "playwright"]);
  if (issue === "blocked") badges.push(["Cloudflare / Blocked", "blocked"]);
  if (issue === "timeout") badges.push(["Timeout", "timeout"]);
  if (selectorScore !== null && selectorScore !== undefined && Number(selectorScore) < 100) {
    badges.push(["Selector Failed", "selector"]);
  }
  if (drift && drift !== "not_checked" && drift !== "no_change") {
    badges.push([formatHealingDriftStatus(drift), drift]);
  }
  return badges.slice(0, 4);
}

function renderHealingPill(status) {
  const normalized = String(status || "unknown").toLowerCase();
  return `<span class="healing-status-pill status-${escapeHtml(normalized)}">${escapeHtml(formatHealingStatus(normalized))}</span>`;
}

function renderHealingPrimaryPill(item = {}) {
  return renderHealingPill(healingPrimaryStatus(item));
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

  setActionButtonBusy("pakdbSearchBtn", true, "Searching...");
  clearPagination("pakdbPagination");
  setExportToolbarState("pakdbExportBar", false);
  showListScanLoading("pakdbStatus", "pakdbHistoryList", "Searching national identity records...", "compact", 3);

  try {
    const data = await apiFetch("/pakdb/lookup", false, {
      method: "POST",
      body: { number }
    });

    const items = data.results || [];
    state.scanExports.pakdb = { query: number, items };
    $("pakdbStatus").textContent = items.length ? `${items.length} result(s) returned.` : "No PakDB results found.";
    setClientPaginatedItems("pakdb", items);
    setExportToolbarState("pakdbExportBar", items.length > 0, `${items.length} national identity result(s) ready for export.`);
    await renderClientPaginatedResults("pakdb", 1);
  } catch (error) {
    state.scanExports.pakdb = { query: number, items: [] };
    $("pakdbStatus").textContent = error.message;
    $("pakdbHistoryList").innerHTML = "";
    clearPagination("pakdbPagination");
    setExportToolbarState("pakdbExportBar", false);
  } finally {
    setActionButtonBusy("pakdbSearchBtn", false, "Searching...");
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

initApp().catch(error => {
  console.error(error);
});

// --- Smart Update Orchestration ---
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
    repoRecommendationsBox.classList.remove("hidden");
    repoRecommendationsTitle.textContent = "AI Recommendations by DARKPULSE AI";
    const intro = grade === "A"
      ? "This repository is in a strong state right now. These practices help keep it there."
      : `DarkPulse graded this repository ${grade}. These improvements would strengthen the posture and move it closer to A.`;
    repoRecommendationsContent.innerHTML = renderDarkpulseRecommendationCard(
      recommendations.length ? { Actions: recommendations } : "",
      { note: intro }
    );
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
  setExportToolbarState("seoExportBar", false);
  showReportScanLoading("seoStatus", "seoReport", "seo", "Queued: building live SEO posture and recommendations...");

  try {
    const data = await apiFetch(`/seo/analyze?url=${encodeURIComponent(urlArg)}`);
    if (data.status === "error") {
      state.scanExports.seo = null;
      restoreReportTemplate("seoReport", "seo");
      $("seoReport").classList.add("hidden");
      $("seoStatus").textContent = `Error: ${data.message}`;
      setExportToolbarState("seoExportBar", false);
      return;
    }
    restoreReportTemplate("seoReport", "seo");
    $("seoStatus").textContent = data.scan_message || "Analysis complete.";
    $("seoReport").classList.remove("hidden");
    state.scanExports.seo = data;
    renderSeoReport(data);
    setExportToolbarState("seoExportBar", true, `SEO report ready. Grade ${data.grade || "-"} with ${Object.keys(data.audits || {}).length} finding(s).`);
    await maybeApplyActiveTranslation("view");
  } catch (error) {
    state.scanExports.seo = null;
    restoreReportTemplate("seoReport", "seo");
    $("seoReport").classList.add("hidden");
    $("seoStatus").textContent = `Scan failed: ${error.message}`;
    setExportToolbarState("seoExportBar", false);
  } finally {
    setActionButtonBusy("seoSearchBtn", false, "Analyzing...");
  }
}

function renderSeoReport(data) {
  const seoHealthGrade = data.seoHealthGrade || data.grade || "-";
  const scanConfidenceGrade = data.scanConfidenceGrade || "-";
  const crawlerVisibility = data.crawlerVisibility || {};
  const visibilityLevel = String(crawlerVisibility.level || "").toLowerCase();
  $("seoReportTitle").textContent = `Report for ${escapeHtml(data.url)}`;
  $("seoMetaUrl").textContent = data.url;
  $("seoMetaHost").textContent = new URL(data.url).hostname;
  $("seoMetaDate").textContent = data.timestamp;
  $("seoGradeLetter").textContent = seoHealthGrade;
  $("seoGradeLabel").textContent = "SEO Health";
  $("seoGradeCircle").className = `grade-circle grade-${String(seoHealthGrade).toLowerCase()}`;
  if ($("seoHealthGradeValue")) $("seoHealthGradeValue").textContent = seoHealthGrade;
  if ($("seoScanConfidenceValue")) $("seoScanConfidenceValue").textContent = scanConfidenceGrade;
  if ($("seoScanModeValue")) $("seoScanModeValue").textContent = data.scanModeUsed || "-";
  const warningBox = $("seoCrawlerWarning");
  const warningText = $("seoCrawlerWarningText");
  if (warningBox && warningText) {
    if (visibilityLevel === "low") {
      warningBox.classList.remove("hidden");
      warningText.textContent = "This page appears JavaScript-heavy, login-gated, or bot-protected. Some SEO findings are based only on limited crawler-visible HTML and should be treated as approximate.";
    } else if (visibilityLevel === "medium") {
      warningBox.classList.remove("hidden");
      warningText.textContent = crawlerVisibility.reason || "Rendered scan returned partial evidence, so some findings may need manual verification.";
    } else {
      warningBox.classList.add("hidden");
      warningText.textContent = "";
    }
  }

  const audits = data.audits || {};
  const auditItems = Object.keys(audits).map(id => audits[id]);
  $("seoFindingsCount").textContent = auditItems.length;
  $("seoFindingsList").innerHTML = auditItems.map(a => {
    const status = String(a.status || (Number(a.score) >= 0.85 ? "pass" : Number(a.score) >= 0.55 ? "warning" : "fail"));
    const evidence = String(a.evidence || "").trim();
    const recommendation = String(a.recommendation || "").trim();
    const confidence = String(a.confidence || "-");
    const evidenceSource = String(a.evidenceSource || "-");
    const note = String(a.note || "").trim();
    return `
    <div class="compact-item">
      <div class="compact-title">${escapeHtml(a.title)}</div>
      <div class="compact-item-footer">
        <span class="compact-meta">Score: ${a.score}</span>
        <span class="compact-meta">Status: ${escapeHtml(status)}</span>
        <span class="compact-meta">Confidence: ${escapeHtml(confidence)}</span>
        <span class="compact-meta">${escapeHtml(evidenceSource.replace(/_/g, " "))}</span>
      </div>
      <div class="compact-meta">${escapeHtml(a.description)}</div>
      ${evidence ? `<div class="compact-meta">Evidence: ${escapeHtml(evidence)}</div>` : ""}
      ${note ? `<div class="compact-meta">Note: ${escapeHtml(note)}</div>` : ""}
      ${recommendation ? `<div class="compact-meta">Fix: ${escapeHtml(recommendation)}</div>` : ""}
    </div>
  `;
  }).join("");

  const aiBox = $("seoAiSuggestionsBox");
  const aiContent = $("seoAiSuggestionsContent");
  const rawSuggestions = sanitizeAiBranding(String(data.ai_suggestions || "").trim());
  const aiMessage = sanitizeAiBranding(String(data.ai_message || "").trim());
  aiBox.classList.remove("hidden");
  aiContent.innerHTML = renderDarkpulseRecommendationCard(rawSuggestions, { note: aiMessage });
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
