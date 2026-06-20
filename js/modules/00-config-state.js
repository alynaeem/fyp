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

