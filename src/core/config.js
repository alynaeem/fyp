export const DEFAULT_API_BASE = window.location.origin && window.location.origin !== "null"
  ? window.location.origin
  : "http://localhost:8200";

export const STORAGE_KEY = "darkpulse_api_key";
export const TOKEN_KEY = "darkpulse_token";
export const USER_ROLE_KEY = "darkpulse_role";
export const USER_NAME_KEY = "darkpulse_name";
export const API_BASE_KEY = "darkpulse_base";
export const AUTH_NOTICE_KEY = "darkpulse_auth_notice";
export const PAGE_SIZE = 30;
export const PAGINATION_WINDOW = 5;
export const REFRESH_MS = 2 * 60 * 1000;
export const SMART_UPDATE_POLL_MS = 5 * 1000;
export const MAP_LIVE_REFRESH_MS = 15 * 1000;
export const MAP_SPOTLIGHT_MS = 2200;
export const SEARCH_DEBOUNCE_MS = 550;
export const AUTH_PROGRESS_TICK_MS = 140;
export const MIN_GLOBAL_SEARCH_LENGTH = 2;
export const FEED_SNAPSHOT_TTL_MS = 90 * 1000;
export const FEED_PREFETCH_DELAY_MS = 120;
export const SEMANTIC_CACHE_TTL_MS = 60 * 1000;
export const TRANSLATION_LANGUAGE_KEY = "darkpulse_translation_language";
export const TRANSLATION_LABEL_KEY = "darkpulse_translation_label";
export const HEALING_CACHE_KEY = "darkpulse_healing_cache";

export const TRANSLATION_OPTIONS = [
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

export const TRANSLATABLE_SELECTORS = [
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
  ".summary-highlight-title",
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

export const TAB_SOURCE_MAP = {
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

export const VIEW_META = {
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
  }
};

export const TOOL_VIEWS = ["admin-users", "pakdb", "credential-checker", "confidential-data", "seo", "playstore", "software", "repo-scan", "healing", "leak-source-status", "docs", "account"];
export const FEED_PREFETCH_VIEWS = [];

export const SMART_UPDATE_SOURCE_LABELS = {
  news: "Security Feeds",
  leaks: "Ransomware Leaks",
  social: "Social Monitoring",
  defacement: "Defacement Tracking"
};
